//! `/api/fail2ban` - not in the Python: the Fail2ban addon's page.
//!
//! Administrators only, and only while the addon is installed - a 409
//! otherwise, like the Application addon's, which says the feature is not
//! there rather than that the caller may not use it.

use std::net::IpAddr;

use axum::extract::State;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_core::IpOrCidr;
use snpanel_ipc::{Fail2banConfig, Fail2banJail};

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, not_enough_permissions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/fail2ban", get(read).fallback(crate::fallback))
        .route(
            "/fail2ban/settings",
            put(save_settings).fallback(crate::fallback),
        )
        .route("/fail2ban/ban", post(ban).fallback(crate::fallback))
        .route("/fail2ban/unban", post(unban).fallback(crate::fallback))
}

/// The caller, when it is an administrator and the addon is installed.
async fn admit(state: &AppState, parts: &mut Parts) -> Result<CurrentUser, Response> {
    let current = CurrentUser::from_parts(parts, state).await?;
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return Err(not_enough_permissions());
    }
    if !super::addons::fail2ban_installed() {
        return Err(crate::errors::conflict(
            "The Fail2ban addon is not installed. Install it on the Addons page first.",
        ));
    }
    Ok(current)
}

/// The address this request came from, as fail2ban would see it.
fn your_address(parts: &Parts) -> Option<IpAddr> {
    crate::client::client_host(parts)
        .and_then(|host| host.parse::<IpAddr>().ok())
        .map(|a| a.to_canonical())
}

fn settings_json(config: &Fail2banConfig) -> Value {
    json!({
        "ignoreip": config.ignoreip.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "bantime": config.bantime,
        "findtime": config.findtime,
        "maxretry": config.maxretry,
        "jails": config.jails.iter().map(|j| j.name()).collect::<Vec<_>>(),
    })
}

/// One row of the jail list: what the panel decided, and what fail2ban
/// reports for it when it is running.
fn jail_entry(name: &str, managed: bool, enabled: bool, live: Option<&Value>) -> Value {
    let count = |key: &str| live.and_then(|l| l[key].as_u64()).unwrap_or(0);
    json!({
        "name": name,
        "managed": managed,
        "enabled": enabled,
        "running": live.is_some(),
        "currently_failed": count("currently_failed"),
        "total_failed": count("total_failed"),
        "currently_banned": count("currently_banned"),
        "total_banned": count("total_banned"),
        "banned": live.map_or_else(|| json!([]), |l| l["banned"].clone()),
    })
}

/// The panel's jails in their fixed order, then any jail fail2ban runs that
/// an administrator added by hand - its bans are as real as the panel's.
fn jails_json(config: &Fail2banConfig, running: &[Value]) -> Vec<Value> {
    let live = |name: &str| running.iter().find(|j| j["name"] == name);
    let mut jails: Vec<Value> = Fail2banJail::ALL
        .iter()
        .map(|jail| jail_entry(jail.name(), true, config.enables(*jail), live(jail.name())))
        .collect();
    for other in running {
        let name = other["name"].as_str().unwrap_or_default();
        if !name.is_empty() && Fail2banJail::parse(name).is_none() {
            jails.push(jail_entry(name, false, true, Some(other)));
        }
    }
    jails
}

/// Everything the page shows.
async fn page(state: &AppState, parts: &Parts) -> Value {
    let config = crate::fail2ban::stored().unwrap_or_else(|| Fail2banConfig::defaults(None));
    let service = crate::fail2ban::service_status(state).await;
    let running = service["jails"].as_array().cloned().unwrap_or_default();
    let you = your_address(parts);
    json!({
        "service": {
            "installed": service["installed"],
            "running": service["running"],
            "version": service["version"],
        },
        "settings": settings_json(&config),
        "jails": jails_json(&config, &running),
        "your_address": you.map(|a| a.to_string()),
        "your_address_exempt": you.is_some_and(|a| config.exempts(a)),
    })
}

/// The page's settings, each value checked and the first problem named.
fn parse_settings(body: &Value) -> Result<Fail2banConfig, String> {
    let number = |key: &str| -> Result<u32, String> {
        body.get(key)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| format!("{key} must be a whole number"))
    };
    let mut ignoreip: Vec<IpOrCidr> = Vec::new();
    let entries = body
        .get("ignoreip")
        .and_then(Value::as_array)
        .ok_or("ignoreip must be a list")?;
    for entry in entries {
        let text = entry
            .as_str()
            .ok_or("every exempt address must be text")?
            .trim();
        if text.is_empty() {
            continue;
        }
        let parsed =
            IpOrCidr::parse(text).map_err(|_| format!("Not an address or a network: {text}"))?;
        if !ignoreip
            .iter()
            .any(|e| e.normalized() == parsed.normalized())
        {
            ignoreip.push(parsed);
        }
    }
    let mut jails: Vec<Fail2banJail> = Vec::new();
    let names = body
        .get("jails")
        .and_then(Value::as_array)
        .ok_or("jails must be a list")?;
    for name in names {
        let name = name.as_str().unwrap_or_default();
        let jail = Fail2banJail::parse(name).ok_or_else(|| format!("Unknown jail: {name}"))?;
        if !jails.contains(&jail) {
            jails.push(jail);
        }
    }
    jails.sort();
    let config = Fail2banConfig {
        ignoreip,
        bantime: number("bantime")?,
        findtime: number("findtime")?,
        maxretry: number("maxretry")?,
        jails,
    };
    config.validate()?;
    Ok(config)
}

/// `GET /api/fail2ban`.
async fn read(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, _) = req.into_parts();
    if let Err(r) = admit(&state, &mut parts).await {
        return r;
    }
    axum::Json(page(&state, &parts).await).into_response()
}

/// `PUT /api/fail2ban/settings`: checked by fail2ban before it is kept.
async fn save_settings(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let config = match parse_settings(&body) {
        Ok(c) => c,
        Err(message) => return error(StatusCode::UNPROCESSABLE_ENTITY, &message),
    };
    if let Err(message) = crate::fail2ban::configure(&state, &config).await {
        return bad_request(&message);
    }
    if let Err(e) = crate::fail2ban::save(&config) {
        tracing::error!("writing fail2ban.json failed: {e}");
        return crate::errors::internal_error();
    }
    let jails: Vec<&str> = config.jails.iter().map(|j| j.name()).collect();
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "fail2ban_settings",
        "fail2ban",
        &format!(
            "jails={} bantime={} findtime={} maxretry={} exempt={}",
            jails.join(","),
            config.bantime,
            config.findtime,
            config.maxretry,
            config.ignoreip.len()
        ),
    )
    .await;
    axum::Json(page(&state, &parts).await).into_response()
}

fn address_in(body: &Value) -> Result<IpAddr, Response> {
    let raw = body
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    raw.parse::<IpAddr>()
        .map(|a| a.to_canonical())
        .map_err(|_| {
            error(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("Not an address: {raw}"),
            )
        })
}

/// `POST /api/fail2ban/ban` `{jail, address}`.
///
/// Refuses the caller's own address and an exempt one. fail2ban would carry
/// out the first and lock the administrator out of the panel mid-sentence;
/// the second it may carry out regardless of `ignoreip`, which applies to
/// what its filters find rather than to a ban asked for by name.
async fn ban(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(jail) = body
        .get("jail")
        .and_then(Value::as_str)
        .and_then(Fail2banJail::parse)
    else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "Unknown jail");
    };
    let address = match address_in(&body) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let config = crate::fail2ban::stored().unwrap_or_else(|| Fail2banConfig::defaults(None));
    if your_address(&parts) == Some(address) {
        return bad_request(
            "That is your own address: banning it would lock you out of the panel.",
        );
    }
    if config.exempts(address) {
        return bad_request(
            "That address is exempt from bans. Remove it from the exempt list first.",
        );
    }
    if !config.enables(jail) {
        return bad_request("That jail is switched off.");
    }
    if let Err(message) = crate::fail2ban::ban(&state, jail, address).await {
        return bad_request(&message);
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "fail2ban_ban",
        &address.to_string(),
        &format!("jail={}", jail.name()),
    )
    .await;
    axum::Json(page(&state, &parts).await).into_response()
}

/// `POST /api/fail2ban/unban` `{address}`: out of every jail.
async fn unban(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let address = match address_in(&body) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(message) = crate::fail2ban::unban(&state, address).await {
        return bad_request(&message);
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "fail2ban_unban",
        &address.to_string(),
    )
    .await;
    axum::Json(page(&state, &parts).await).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> Value {
        json!({
            "ignoreip": ["203.0.113.7", " 198.51.100.0/24 ", "", "203.0.113.7/32"],
            "bantime": 3600,
            "findtime": 600,
            "maxretry": 5,
            "jails": ["recidive", "sshd", "sshd"],
        })
    }

    #[test]
    fn the_settings_are_read_the_way_the_page_sends_them() {
        let config = parse_settings(&body()).unwrap();
        // Blank lines dropped, surrounding space trimmed, and an entry that
        // repeats another network in a different spelling kept once.
        let ignore: Vec<String> = config.ignoreip.iter().map(ToString::to_string).collect();
        assert_eq!(ignore, ["203.0.113.7", "198.51.100.0/24"]);
        // In the page's order, each once.
        assert_eq!(config.jails, [Fail2banJail::Sshd, Fail2banJail::Recidive]);
        assert_eq!(
            (config.bantime, config.findtime, config.maxretry),
            (3600, 600, 5)
        );
    }

    #[test]
    fn each_problem_is_named() {
        for (patch, expected) in [
            (
                json!({"ignoreip": ["203.0.113.300"]}),
                "Not an address or a network: 203.0.113.300",
            ),
            (
                json!({"ignoreip": "203.0.113.7"}),
                "ignoreip must be a list",
            ),
            (json!({"jails": ["sshd-ddos"]}), "Unknown jail: sshd-ddos"),
            (json!({"bantime": "600"}), "bantime must be a whole number"),
            (json!({"maxretry": -1}), "maxretry must be a whole number"),
            (
                json!({"findtime": 30}),
                "findtime must be between 60 and 604800, not 30",
            ),
            (
                json!({"bantime": 5_000_000_000u64}),
                "bantime must be a whole number",
            ),
        ] {
            let mut b = body();
            for (k, v) in patch.as_object().unwrap() {
                b[k] = v.clone();
            }
            assert_eq!(parse_settings(&b).unwrap_err(), expected);
        }
    }

    #[test]
    fn a_jail_row_says_what_was_decided_and_what_runs() {
        let config = Fail2banConfig {
            jails: vec![Fail2banJail::Sshd, Fail2banJail::PanelLogin],
            ..Fail2banConfig::defaults(None)
        };
        let running = vec![
            json!({"name": "sshd", "currently_failed": 1, "total_failed": 9,
                   "currently_banned": 2, "total_banned": 4, "banned": ["198.51.100.7", "198.51.100.8"]}),
            json!({"name": "postfix", "currently_failed": 0, "total_failed": 0,
                   "currently_banned": 1, "total_banned": 1, "banned": ["192.0.2.1"]}),
        ];
        let jails = jails_json(&config, &running);
        let names: Vec<&str> = jails.iter().map(|j| j["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "sshd",
                "snpanel-login",
                "snpanel-wordpress",
                "nginx-http-auth",
                "recidive",
                "postfix"
            ]
        );
        assert_eq!(jails[0]["running"], json!(true));
        assert_eq!(jails[0]["currently_banned"], json!(2));
        assert_eq!(jails[0]["banned"], json!(["198.51.100.7", "198.51.100.8"]));
        // Switched on but not (yet) running: zero, not missing.
        assert_eq!(jails[1]["enabled"], json!(true));
        assert_eq!(jails[1]["running"], json!(false));
        assert_eq!(jails[1]["currently_banned"], json!(0));
        assert_eq!(jails[1]["banned"], json!([]));
        assert_eq!(jails[3]["enabled"], json!(false));
        // Somebody else's jail is listed, and marked as not the panel's.
        assert_eq!(jails[5]["managed"], json!(false));
        assert_eq!(jails[5]["banned"], json!(["192.0.2.1"]));
    }
}
