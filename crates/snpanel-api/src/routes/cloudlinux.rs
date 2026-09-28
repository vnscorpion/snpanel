//! `/api/hosting/cloudlinux` - not in the Python: opening CloudLinux
//! Manager's own UI (LVE Manager, Resource Usage, PHP Selector) inside the
//! panel. See `crate::cloudlinux_ui` for the model.
//!
//! - `POST /hosting/cloudlinux/session` - a signed-in user asks to open a
//!   plugin; the answer is the URL to put in the iframe.
//! - `GET /hosting/cloudlinux/identity/{token}` - CloudLinux's `ui_user_info`
//!   asks who a token belongs to. Loopback only.

use std::net::SocketAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};

use crate::auth::CurrentUser;
use crate::cloudlinux_ui;
use crate::errors::{error, not_enough_permissions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/hosting/cloudlinux",
            get(available).fallback(crate::fallback),
        )
        .route(
            "/hosting/cloudlinux/session",
            post(session).fallback(crate::fallback),
        )
        .route(
            "/hosting/cloudlinux/identity/{token}",
            get(identity).fallback(crate::fallback),
        )
}

fn not_cloudlinux() -> Response {
    crate::errors::conflict(
        "CloudLinux Manager needs CloudLinux. Run `snpanel upgrade cloudlinux` on this server first.",
    )
}

/// Whether this server runs CloudLinux, for any signed-in user: the panel
/// shows the CloudLinux pages only where they exist.
async fn available(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, _) = req.into_parts();
    if let Err(r) = CurrentUser::from_parts(&mut parts, &state).await {
        return r;
    }
    match snpanel_osabi::hosting::cloudlinux() {
        Some(cl) => axum::Json(json!({ "available": true, "lve": cl.lve_loaded })).into_response(),
        None => not_cloudlinux(),
    }
}

async fn session(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if snpanel_osabi::hosting::cloudlinux().is_none() {
        return not_cloudlinux();
    }
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let plugin = body.get("plugin").and_then(Value::as_str).unwrap_or("");
    let admin = current.user.is_admin();
    if !cloudlinux_ui::plugin_allowed(plugin, admin) {
        return if cloudlinux_ui::plugin_allowed(plugin, true) {
            not_enough_permissions()
        } else {
            error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unknown CloudLinux plugin",
            )
        };
    }
    let token = cloudlinux_ui::issue(current.user.id, current.user.token_version);
    axum::Json(json!({ "url": cloudlinux_ui::open_url(plugin, &token) })).into_response()
}

/// The uid of a system account, from /etc/passwd.
fn uid_of(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
    })
}

/// What CloudLinux's `ui_user_info` must print (integration guide).
pub fn user_info(username: &str, uid: Option<u32>, admin: bool, domain: &str) -> Value {
    json!({
        "userName": username,
        "userId": uid.unwrap_or(0),
        "userType": if admin { "admin" } else { "user" },
        "baseUri": "/cloudlinux/",
        // LveManager.php appends "/assets/..." itself; base_path/assets is
        // where CloudLinux copies the SPA, so the prefix is the base.
        "assetsUri": "/cloudlinux",
        "lang": "en",
        "userDomain": domain,
    })
}

async fn identity(
    State(state): State<AppState>,
    Path(token): Path<String>,
    req: axum::extract::Request,
) -> Response {
    // Loopback only: this answers "who is this token", which only CloudLinux's
    // ui_user_info on this machine has any business asking.
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    if !peer.is_some_and(|ip| ip.is_loopback()) {
        return crate::errors::not_found("Not Found");
    }
    let invalid = || error(StatusCode::UNAUTHORIZED, "invalid token");
    let Some(session) = cloudlinux_ui::resolve(&token) else {
        return invalid();
    };
    let user = match state.db.users().by_id(session.user_id).await {
        Ok(Some(u)) => u,
        _ => {
            cloudlinux_ui::revoke(&token);
            return invalid();
        }
    };
    if !user.is_active || user.token_version != session.token_version {
        cloudlinux_ui::revoke(&token);
        return invalid();
    }
    let admin = user.is_admin();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let uid = if admin {
        None
    } else {
        uid_of(&passwd, &user.username)
    };
    if !admin && uid.is_none() {
        // A customer with no Linux account has no LVE to show.
        return invalid();
    }
    let domain = state
        .db
        .websites()
        .list(Some(user.id), "")
        .await
        .ok()
        .and_then(|sites| sites.into_iter().next().map(|w| w.domain))
        .unwrap_or_default();
    axum::Json(user_info(&user.username, uid, admin, &domain)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_info_is_cloudlinuxs_contract() {
        let v = user_info("alice", Some(1001), false, "wp1.alice.test");
        for key in [
            "userName",
            "userId",
            "userType",
            "baseUri",
            "assetsUri",
            "lang",
            "userDomain",
        ] {
            assert!(v.get(key).is_some(), "{key}");
        }
        assert_eq!(v["userType"], "user");
        assert_eq!(v["userId"], 1001);
        assert_eq!(user_info("admin", None, true, "")["userType"], "admin");
        // "/cloudlinux" + LveManager's own "/assets/static/..." = the files.
        assert_eq!(v["assetsUri"], "/cloudlinux");
    }

    #[test]
    fn uids_come_from_passwd_by_exact_name() {
        let passwd = "root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/sbin/nologin\nalice2:x:1002:1002::/h:/s\n";
        assert_eq!(uid_of(passwd, "alice"), Some(1001));
        assert_eq!(uid_of(passwd, "alice2"), Some(1002));
        assert_eq!(uid_of(passwd, "ali"), None);
    }
}
