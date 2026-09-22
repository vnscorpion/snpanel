//! `/api/panel-settings` - ported from `api/panel_settings.py`.
//!
//! The reads, the settings write, all three certificate paths and the IPv6
//! toggle, the administrator's own account and the branding uploads.
//!
//! **Whole.** Every endpoint of `api/panel_settings.py` is answered here.
//!
//! `POST /ssl` was proxied until Stage D: it needs `panel-ssl-install`, and
//! that verb was still bash. `PATCH /admin-account` was proxied for the
//! step-up check, which `users::set_password` already carried - the two share
//! it now rather than holding a copy each.
//!
//! **`/public` is the only unauthenticated endpoint in the panel.** The login
//! page needs the panel's name and its artwork; what certificate the panel
//! runs on, and which domains live on this server, are for people who have
//! signed in.
//!
//! How that is achieved is worth stating precisely, because I got it wrong
//! first. The handler returns a dict of three keys - and FastAPI's
//! `response_model=PanelSettingsOut` then **fills every other field in with
//! its schema default**. So the reply has fifteen keys, not three: the
//! projection controls which values are *real*, and the response model
//! controls the *shape*. Returning only three keys, as this did at first, is
//! a different response body - the shadow diff reported twelve fields as "only
//! python has it".
//!
//! The security boundary is still the projection. `panel_url`, `server_ipv4`
//! and the malware state come back as `""`, `[]` and `false` rather than as
//! what they actually are.

use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::config::Settings;
use snpanel_core::permissions::{self, Role};

use axum::extract::FromRequest;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, not_enough_permissions};
use crate::shell;
use crate::state::AppState;

/// Source: `PUBLIC_SETTING_FIELDS`.
const PUBLIC_SETTING_FIELDS: &[&str] = &["app_name", "logo_url", "favicon_url"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/panel-settings/public",
            get(public).fallback(crate::fallback),
        )
        .route(
            "/panel-settings",
            get(full).patch(update_settings).fallback(crate::fallback),
        )
        .route(
            "/panel-settings/logo",
            post(upload_logo).fallback(crate::fallback),
        )
        .route(
            "/panel-settings/favicon",
            post(upload_favicon).fallback(crate::fallback),
        )
        .route(
            "/panel-settings/admin-account",
            patch(update_admin_account).fallback(crate::fallback),
        )
        .route(
            "/panel-settings/ssl",
            post(install_panel_ssl).fallback(crate::fallback),
        )
        .route(
            "/panel-settings/ssl/use-domain",
            post(use_domain_certificate).fallback(crate::fallback),
        )
        .route(
            "/panel-settings/ssl/self-signed",
            post(regenerate_self_signed).fallback(crate::fallback),
        )
        .route(
            "/panel-settings/ipv6",
            post(toggle_ipv6).fallback(crate::fallback),
        )
}

fn data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()),
    )
}

pub(super) fn raw_settings() -> Value {
    std::fs::read_to_string(data_dir().join("panel-settings.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn string_field(raw: &Value, key: &str) -> String {
    raw.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Source: `_asset_url` - a stored filename becomes a URL, and nothing stored
/// becomes an empty string.
fn asset_url(filename: &str) -> String {
    if filename.is_empty() {
        String::new()
    } else {
        format!("/api/panel-settings/assets/{filename}")
    }
}

/// Source: `parse_panel_url`, as `current_settings` uses it - a URL that will
/// not parse leaves the hostname empty and the port at the configured one.
/// Is this a hostname the panel will report?
///
/// The same rule Python applies in `normalize_panel_hostname`: a domain whose
/// top level is letters only, an IPv4 address, or `localhost`. Anything else
/// is reported as no hostname at all rather than as itself.
///
/// It matters because the panel offers to request a certificate for the
/// hostname it reports. A host Python considers unusable, echoed back by this
/// side, is an offer that cannot be honoured - which is how the Debian test
/// machine `snpanel.deb13` came to be reported by one implementation and not
/// the other: its top level has digits in it.
fn is_reportable_host(host: &str) -> bool {
    if host.is_empty() || host.contains('/') || host.contains(':') {
        return false;
    }
    if host == "localhost" {
        return true;
    }
    // IPv4: four dot-separated runs of one to three digits. Python's IPV4_RE
    // is no stricter than this, so neither is this.
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() == 4
        && octets
            .iter()
            .all(|o| !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit()))
    {
        return true;
    }
    is_panel_domain(host)
}

/// Source: `panel_settings.is_domain`, which is
/// `^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,}$`.
///
/// **Not** `snpanel_core::Domain::parse`. There are two domain predicates in
/// the Python and they disagree exactly where it matters here: this one's
/// last label is letters only, so `192.0.2.1` is refused, while the other -
/// used by `site_users` and the bash helper, and mirrored by `Domain` - allows
/// all-digit labels and accepts an address.
///
/// The panel offers to request a certificate for this hostname, and Let's
/// Encrypt will not sign an address. Using the wrong predicate sends certbot
/// to the CA for something it cannot have, and those attempts are spent from
/// a rate-limited account whether or not they succeed.
///
/// `(?!-)` guards only the very first character, not each label, so
/// `a.-b.com` matches in Python and matches here.
fn is_panel_domain(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.starts_with('-') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let (tld, rest) = labels.split_last().expect("checked len >= 2");
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    rest.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn parse_panel_url(url: &str, fallback_port: i64) -> (String, i64) {
    let Some((_scheme, rest)) = url.split_once("://") else {
        return (String::new(), fallback_port);
    };
    let authority = rest.split('/').next().unwrap_or("");

    // An IPv6 literal is bracketed, and `rsplit_once(':')` would split inside
    // it and hand back `[::1` as a host. Take the brackets off first; the
    // result is then rejected by is_reportable_host, which is what Python does
    // with it too.
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        match after.split_once(']') {
            Some((literal, tail)) => (
                literal.to_string(),
                tail.strip_prefix(':').and_then(|p| p.parse::<i64>().ok()),
            ),
            None => (String::new(), None),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => (h.to_lowercase(), p.parse::<i64>().ok()),
            // No port in the URL: the scheme's default is not assumed, the
            // configured port is kept.
            _ => (authority.to_lowercase(), None),
        }
    };

    // Python normalises the port through the same 1..=65535 range and falls
    // back to the configured one when it is outside it.
    let port = match port {
        Some(p) if (1..=65535).contains(&p) => p,
        Some(_) => return (String::new(), fallback_port),
        None => fallback_port,
    };

    if is_reportable_host(&host) {
        (host, port)
    } else {
        (String::new(), fallback_port)
    }
}

/// Source: `panel_ipv6.status()`.
async fn ipv6_status(settings: &Settings) -> Value {
    let result = shell::privileged(
        settings.command_dry_run,
        "ipv6-status",
        &[],
        None,
        Some(&["bash", "-lc", "echo dry-run-ipv6-status"]),
    )
    .await;

    let marker = std::path::Path::new(
        &std::env::var("SNPANEL_IPV6_MARKER")
            .unwrap_or_else(|_| "/etc/snpanel/ipv6-enabled".into()),
    )
    .exists();

    if !result.ok() {
        // Never fail the settings page over this.
        let detail = [result.stderr.trim(), result.stdout.trim()]
            .into_iter()
            .find(|s| !s.is_empty())
            .map(tail_300)
            .unwrap_or_else(|| "Không đọc được trạng thái IPv6 của máy chủ.".to_string());
        return json!({
            "available": false,
            "enabled": marker,
            "addresses": [],
            "detail": detail,
        });
    }

    let (available, enabled, addresses) = parse_ipv6_status(&result.stdout);
    let detail = if !available {
        "VPS của bạn không có địa chỉ IPv6 nên không thể dùng tính năng này. \
         Liên hệ nhà cung cấp để được cấp IPv6, sau đó bật lại."
            .to_string()
    } else if enabled {
        "Website và panel đang nhận kết nối qua cả IPv4 và IPv6.".to_string()
    } else {
        "VPS có IPv6. Bật để website và panel nhận thêm kết nối IPv6.".to_string()
    };

    json!({
        "available": available,
        "enabled": enabled,
        "addresses": addresses,
        "detail": detail,
    })
}

/// Python slices the last 300 *characters*.
fn tail_300(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 300 {
        return text.to_string();
    }
    chars[chars.len() - 300..].iter().collect()
}

/// Source: `panel_ipv6._parse_status`.
fn parse_ipv6_status(output: &str) -> (bool, bool, Vec<String>) {
    let mut values = std::collections::BTreeMap::new();
    for line in output.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    let addresses: Vec<String> = values
        .get("addresses")
        .map(|a| {
            a.split(',')
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    (
        values.get("available").map(String::as_str) == Some("yes"),
        values.get("enabled").map(String::as_str) == Some("yes"),
        addresses,
    )
}

/// Source: `server_network.ipv4_addresses` - `ip -o -4 addr show scope global`,
/// which needs no privileges at all.
///
/// **Global addresses only.** Loopback and link-local are real addresses that
/// nothing outside the machine can reach, and listing them on the settings
/// page would only invite somebody to hand one to a customer.
fn ipv4_addresses() -> Vec<String> {
    let Ok(out) = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (index, token) in parts.iter().enumerate() {
            if *token != "inet" || index + 1 >= parts.len() {
                continue;
            }
            let candidate = parts[index + 1]
                .split('/')
                .next()
                .unwrap_or("")
                .split('%')
                .next()
                .unwrap_or("");
            if let Ok(address) = candidate.parse::<std::net::IpAddr>() {
                if address.is_loopback() || is_link_local(&address) {
                    break;
                }
                let text = address.to_string();
                if !found.contains(&text) {
                    found.push(text);
                }
            }
            break;
        }
    }
    found
}

fn is_link_local(address: &std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        // 169.254/16's IPv6 equivalent is fe80::/10.
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Source: `current_settings`.
async fn current_settings(state: &AppState) -> Value {
    let raw = raw_settings();
    let settings = &state.settings;

    let app_name = {
        let stored = string_field(&raw, "app_name");
        let name = if stored.trim().is_empty() {
            settings.app_name.clone()
        } else {
            stored
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            "SNPanel".to_string()
        } else {
            name
        }
    };

    let panel_url = {
        let stored = string_field(&raw, "panel_url");
        if stored.is_empty() {
            settings.panel_url.clone()
        } else {
            stored
        }
    };

    let configured_port = settings.panel_port.get() as i64;
    let (panel_hostname, panel_port) = if panel_url.is_empty() {
        (String::new(), configured_port)
    } else {
        parse_panel_url(&panel_url, configured_port)
    };

    let ssl_enabled =
        panel_url.starts_with("https://") && crate::panel_urls::has_panel_certificate(settings);

    let malware = crate::malware::refresh_status(
        settings.command_dry_run,
        &settings.clamav_socket_path,
        settings.malware_scan_enabled,
    )
    .await;

    // The only field with a default that is not empty: a panel with no
    // favicon still has one.
    let favicon_url = {
        let url = asset_url(&string_field(&raw, "favicon_filename"));
        if url.is_empty() {
            "/favicon.png".to_string()
        } else {
            url
        }
    };
    let ipv6 = ipv6_status(settings).await;

    json!({
        "app_name": app_name,
        "panel_url": panel_url,
        "panel_hostname": panel_hostname,
        "panel_port": panel_port,
        "logo_url": asset_url(&string_field(&raw, "logo_filename")),
        "favicon_url": favicon_url,
        "ssl_enabled": ssl_enabled,
        "ssl_mode": settings.panel_ssl_mode,
        "ipv6": ipv6,
        "server_ipv4": ipv4_addresses(),
        "malware_scan_enabled": malware["enabled"],
        "malware_scan_installed": malware["installed"],
        "malware_scan_active": malware["active"],
        "malware_scan_detail": malware["detail"],
    })
}

/// Source: `PanelSettingsOut`'s field defaults.
///
/// These are what a field the handler did not set comes back as. They are not
/// placeholders: `/public` returns this object with three values replaced, so
/// every default here is part of that endpoint's real response.
fn schema_defaults() -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("app_name".into(), json!("SNPanel"));
    m.insert("panel_url".into(), json!(""));
    m.insert("panel_hostname".into(), json!(""));
    m.insert("panel_port".into(), json!(2222));
    m.insert("logo_url".into(), json!(""));
    m.insert("favicon_url".into(), json!("/favicon.png"));
    m.insert("ssl_enabled".into(), json!(false));
    m.insert("ssl_mode".into(), json!("none"));
    m.insert("ipv6".into(), json!({}));
    m.insert("server_ipv4".into(), json!([]));
    // Set by the endpoints that report the result of a change; null on a read.
    m.insert("message".into(), Value::Null);
    m.insert("malware_scan_enabled".into(), json!(false));
    m.insert("malware_scan_installed".into(), json!(false));
    m.insert("malware_scan_active".into(), json!(false));
    m.insert("malware_scan_detail".into(), Value::Null);
    m
}

/// Fill a handler's dict out to the full response model, as FastAPI does.
/// `current_settings()` through the response model, which is what every
/// endpoint answering with the whole settings object returns.
pub(super) async fn settings_model(state: &AppState) -> Value {
    to_response_model(&current_settings(state).await)
}

fn to_response_model(values: &Value) -> Value {
    let mut out = schema_defaults();
    if let Some(map) = values.as_object() {
        for (key, value) in map {
            // A key the schema does not declare is dropped by the response
            // model, so it is dropped here too.
            if out.contains_key(key) {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(out)
}

/// No authentication: this is what the login page reads before anyone has
/// signed in.
async fn public(State(state): State<AppState>) -> Response {
    let all = current_settings(&state).await;
    let mut projected = serde_json::Map::new();
    for field in PUBLIC_SETTING_FIELDS {
        if let Some(value) = all.get(*field) {
            projected.insert((*field).to_string(), value.clone());
        }
    }
    axum::Json(to_response_model(&Value::Object(projected))).into_response()
}

async fn full(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    // Through the response model too: `current_settings` never sets `message`,
    // so the reply carries it as null.
    axum::Json(to_response_model(&current_settings(&state).await)).into_response()
}

// ---------------------------------------------------------------------------
// the settings an administrator can change
// ---------------------------------------------------------------------------

/// Source: `panel_settings._write_raw` - a temporary file beside the real one,
/// then a rename. Every page on the panel reads this file.
pub(crate) fn write_raw(data: &Value) -> std::io::Result<()> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    let mut text = serde_json::to_string_pretty(data)?;
    text.push('\n');
    let temp = dir.join(format!(".panel-settings.json.{}", std::process::id()));
    std::fs::write(&temp, text)?;
    std::fs::rename(&temp, dir.join("panel-settings.json"))
}

/// Source: `normalize_panel_hostname`.
///
/// A scheme, a port or a path in the hostname box is refused rather than
/// stripped: this name goes into the URL the panel tells people to use, and
/// quietly discarding half of what was typed produces a link that does not
/// work for a reason nobody can see.
fn normalize_panel_hostname(value: &str) -> Result<String, String> {
    let host = value
        .trim()
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();
    if host.is_empty() {
        return Err("Panel hostname is required".to_string());
    }
    if host.contains("://") || host.contains('/') || host.contains(':') {
        return Err("Panel hostname must not include a scheme, port, or path".to_string());
    }
    if !is_reportable_host(&host) && host != "localhost" {
        return Err("Panel hostname must be a domain name or IPv4 address".to_string());
    }
    Ok(host)
}

/// Source: `normalize_panel_port`.
fn normalize_panel_port(value: Option<i64>, fallback: i64) -> Result<i64, String> {
    // `int(value or settings.panel_port or 2222)` - **zero is falsy**, so a
    // port of 0 falls back rather than being refused as out of range. Kept.
    let port = match value {
        Some(0) | None => fallback,
        Some(v) => v,
    };
    if !(1..=65535).contains(&port) {
        return Err("Panel port is out of range".to_string());
    }
    Ok(port)
}

/// Source: `has_panel_certificate`.
fn has_panel_certificate(settings: &Settings) -> bool {
    let pairs = [
        (
            settings.panel_ssl_cert.clone(),
            settings.panel_ssl_key.clone(),
        ),
        (
            "/etc/snpanel/panel-fullchain.pem".to_string(),
            "/etc/snpanel/panel-privkey.pem".to_string(),
        ),
    ];
    pairs.iter().any(|(cert, key)| {
        !cert.is_empty()
            && !key.is_empty()
            && std::path::Path::new(cert).exists()
            && std::path::Path::new(key).exists()
    })
}

/// Source: `update_panel_settings` and `panel_settings.update_settings`.
///
/// `panel_port` is accepted and **discarded** - `del panel_port` with the
/// comment "the panel port is install-time only; settings can change
/// hostname/branding". Changing the port here would leave the running service
/// listening on the old one while the stored URL pointed at the new.
async fn update_settings(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let mut data = raw_settings();
    let map = data
        .as_object_mut()
        .expect("raw_settings returns an object");

    if let Some(raw) = payload.get("app_name").filter(|v| !v.is_null()) {
        let Some(name) = raw.as_str() else {
            return crate::errors::string_type("app_name", raw);
        };
        let value = name.trim();
        // `if not 2 <= len(value) <= 80` - characters, not bytes.
        let length = value.chars().count();
        if !(2..=80).contains(&length) {
            return bad_request("Panel name must be 2-80 characters");
        }
        map.insert("app_name".to_string(), json!(value));
    }

    let hostname = payload
        .get("panel_hostname")
        .and_then(Value::as_str)
        .unwrap_or("");
    let url_field = payload
        .get("panel_url")
        .and_then(Value::as_str)
        .unwrap_or("");

    if !hostname.trim().is_empty() || !url_field.trim().is_empty() {
        let existing_url = map
            .get("panel_url")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&state.settings.panel_url)
            .to_string();
        let (existing_host, existing_port) =
            parse_panel_url(&existing_url, state.settings.panel_port.get() as i64);
        let existing_scheme = if existing_url.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        // `existing_normalized` is "" when there is no stored URL, and the
        // comparison below is against that - so a first-time save always runs
        // the helper.
        let existing_normalized = if existing_host.is_empty() {
            String::new()
        } else {
            format!("{existing_scheme}://{existing_host}:{existing_port}")
        };

        let (scheme, host) = if !hostname.trim().is_empty() {
            (existing_scheme.to_string(), hostname.to_string())
        } else {
            let (requested_host, _) =
                parse_panel_url(url_field, state.settings.panel_port.get() as i64);
            let requested_scheme = if url_field.trim().starts_with("https://") {
                "https"
            } else {
                "http"
            };
            (requested_scheme.to_string(), requested_host)
        };
        let host = match normalize_panel_hostname(&host) {
            Ok(h) => h,
            Err(e) => return bad_request(&e),
        };
        let port =
            match normalize_panel_port(Some(existing_port), state.settings.panel_port.get() as i64)
            {
                Ok(p) => p,
                Err(e) => return bad_request(&e),
            };
        let normalized = format!("{scheme}://{host}:{port}");

        if scheme == "https" && !has_panel_certificate(&state.settings) {
            return bad_request("Use Install SSL before saving an HTTPS panel URL");
        }
        if normalized != existing_normalized {
            let port_text = port.to_string();
            let result = shell::privileged(
                state.settings.command_dry_run,
                "panel-url-set",
                &[&scheme, &host, &port_text],
                None,
                Some(&["bash", "-lc", "true"]),
            )
            .await;
            if !result.ok() {
                // Source: `raise RuntimeError(...)`, which the router turns
                // into a **500**, not a 400 - this is the machine refusing,
                // not the input being wrong.
                tracing::error!(
                    "setting the panel URL failed: {}",
                    result.failure_detail("Could not update panel URL")
                );
                return crate::errors::internal_error();
            }
        }
        map.insert("panel_url".to_string(), json!(normalized));
    }

    if let Err(e) = write_raw(&data) {
        tracing::error!("writing panel-settings.json failed: {e}");
        return crate::errors::internal_error();
    }

    let settings = current_settings(&state).await;
    let target = settings["panel_url"].as_str().unwrap_or("");
    let target = if target.is_empty() { "panel" } else { target };
    audit_panel(
        &state,
        &parts,
        current.user.id,
        "update_panel_settings",
        target,
    )
    .await;
    axum::Json(to_response_model(&settings)).into_response()
}

/// `log_action(..., request=request)` - ip and user agent, no detail, which is
/// how every write in this router calls it.
async fn audit_panel(
    state: &AppState,
    parts: &axum::http::request::Parts,
    actor_id: i64,
    action: &str,
    target: &str,
) {
    super::packages::audit_action(state, parts, actor_id, action, target).await;
}

/// Source: `panel_settings.domains_with_certificate`.
///
/// Asked through the helper: "/etc/letsencrypt/live is root-only, so the panel
/// reading it directly finds nothing and reports, wrongly, that there is
/// nothing to borrow."
async fn domains_with_certificate(state: &AppState) -> Vec<String> {
    let result = shell::privileged(
        state.settings.command_dry_run,
        "panel-ssl-domains",
        &[],
        None,
        Some(&["bash", "-lc", "echo ''"]),
    )
    .await;
    if !result.ok() {
        return Vec::new();
    }
    let mut found: Vec<String> = Vec::new();
    for line in result.stdout.lines() {
        let name = line.trim().trim_matches('/');
        if name.is_empty() || name == "README" || !is_reportable_host(name) {
            continue;
        }
        if !found.iter().any(|f| f == name) {
            found.push(name.to_string());
        }
    }
    found.sort();
    found
}

/// Source: `use_domain_certificate` - "serve the panel with a certificate a
/// website here already has".
///
/// Better than asking a certificate authority for a second certificate
/// covering a name it has already signed, and it renews with the website.
async fn use_domain_certificate(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let domain = payload.get("domain").and_then(Value::as_str).unwrap_or("");
    let host = match normalize_panel_hostname(domain) {
        Ok(h) => h,
        Err(e) => return bad_request(&e),
    };
    let port = match normalize_panel_port(
        payload.get("panel_port").and_then(Value::as_i64),
        state.settings.panel_port.get() as i64,
    ) {
        Ok(p) => p,
        Err(e) => return bad_request(&e),
    };

    if !domains_with_certificate(&state).await.contains(&host) {
        return bad_request(&format!(
            "{host} chưa có chứng chỉ trên máy này. Cài SSL cho website đó trước."
        ));
    }
    let port_text = port.to_string();
    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        "panel-ssl-use-domain",
        &[&host, &port_text],
        None,
        Some(&["bash", "-lc", "echo dry-run-panel-ssl-use-domain"]),
        Some(300),
    )
    .await;
    if !result.ok() {
        return bad_request(&tail_500(
            &result.failure_detail("Could not switch the panel certificate"),
        ));
    }

    audit_panel(
        &state,
        &parts,
        current.user.id,
        "panel_ssl_use_domain",
        &host,
    )
    .await;
    axum::Json(json!({
        "message": format!(
            "Panel dùng chứng chỉ của {host} làm mặc định. \
             Các domain khác có SSL trên máy vẫn mở panel được bằng chứng chỉ riêng."
        ),
        "panel_url": format!("https://{host}:{port}"),
    }))
    .into_response()
}

/// Source: `regenerate_self_signed` - "go back to a certificate the panel
/// signs for itself".
async fn regenerate_self_signed(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return crate::errors::not_enough_permissions();
    }

    let data = raw_settings();
    let stored = data
        .get("panel_url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(&state.settings.panel_url)
        .to_string();
    let mut host = if stored.is_empty() {
        String::new()
    } else {
        parse_panel_url(&stored, state.settings.panel_port.get() as i64).0
    };
    if host.is_empty() {
        host = std::env::var("PANEL_DOMAIN")
            .unwrap_or_default()
            .trim()
            .to_string();
    }
    if host.is_empty() {
        host = "127.0.0.1".to_string();
    }
    let port = state.settings.panel_port.get() as i64;

    let port_text = port.to_string();
    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        "panel-ssl-selfsigned",
        &[&host, &port_text],
        None,
        Some(&["bash", "-lc", "echo dry-run-panel-ssl-selfsigned"]),
        Some(300),
    )
    .await;
    if !result.ok() {
        return bad_request(&tail_500(
            &result.failure_detail("Could not generate a certificate"),
        ));
    }

    audit_panel(
        &state,
        &parts,
        current.user.id,
        "panel_ssl_self_signed",
        "panel",
    )
    .await;
    axum::Json(json!({
        "message": "Panel dùng chứng chỉ tự ký.",
        "panel_url": format!("https://{host}:{port}"),
    }))
    .into_response()
}

/// Source: `panel_ipv6.NO_IPV6_MESSAGE`.
const NO_IPV6_MESSAGE: &str =
    "VPS của bạn không có địa chỉ IPv6 nên không thể dùng tính năng này. \
     Liên hệ nhà cung cấp để được cấp IPv6, sau đó bật lại.";

/// `(...).strip()[-500:]` - the **last** 500 characters, so the end of a long
/// error survives rather than its beginning. Sliced by character.
fn tail_500(value: &str) -> String {
    let trimmed = value.trim();
    let count = trimmed.chars().count();
    if count <= 500 {
        return trimmed.to_string();
    }
    trimmed.chars().skip(count - 500).collect()
}

/// Source: `toggle_ipv6` and `panel_ipv6.set_enabled`.
///
/// "Turning it on is refused when the server has no IPv6 address: nginx cannot
/// bind an address family that is not there, and it would refuse to start."
async fn toggle_ipv6(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `bool(payload.enabled)` on a pydantic `bool` field: absent is the
    // model's default, which is false.
    let enabled = payload
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let before = ipv6_status(&state.settings).await;
    if enabled && !before["available"].as_bool().unwrap_or(false) {
        return bad_request(NO_IPV6_MESSAGE);
    }

    let verb = if enabled {
        "ipv6-enable"
    } else {
        "ipv6-disable"
    };
    let probe = format!("echo dry-run-{verb}");
    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        verb,
        &[],
        None,
        Some(&["bash", "-lc", &probe]),
        Some(300),
    )
    .await;
    if !result.ok() {
        let mut detail = tail_500(&result.failure_detail(""));
        if detail.contains("no global IPv6 address") {
            detail = NO_IPV6_MESSAGE.to_string();
        }
        if detail.is_empty() {
            detail = "Không thay đổi được cấu hình IPv6.".to_string();
        }
        return bad_request(&detail);
    }

    audit_panel(
        &state,
        &parts,
        current.user.id,
        "toggle_ipv6",
        if enabled { "on" } else { "off" },
    )
    .await;

    let mut settings = current_settings(&state).await;
    settings["message"] = json!(if enabled {
        "Đã bật IPv6 cho toàn bộ website và panel."
    } else {
        "Đã tắt IPv6. Website và panel chỉ nhận kết nối IPv4."
    });
    axum::Json(to_response_model(&settings)).into_response()
}

/// Source: `default_ssl_email` - `admin@<host>`, and empty for an address.
///
/// A certificate authority will not register an account against an IP, and
/// an empty string is what makes the helper pass
/// `--register-unsafely-without-email` instead of an address it would refuse.
fn default_ssl_email(host: &str) -> String {
    if is_panel_domain(host) {
        format!("admin@{}", host.to_lowercase())
    } else {
        String::new()
    }
}

/// Source: `(email or settings.ssl_email or default_ssl_email(host)).strip()`.
///
/// The administrator's own address first, then the server-wide one, then a
/// constructed `admin@<host>`. All three may be empty, and empty is not an
/// error: the helper then registers the ACME account without an address
/// instead of handing the CA one it would refuse.
///
/// Named rather than written inline so the test drives this and not a copy.
fn certbot_email(user_email: &str, configured: &str, host: &str) -> String {
    [user_email, configured, &default_ssl_email(host)]
        .into_iter()
        .map(str::trim)
        .find(|candidate| !candidate.is_empty())
        .unwrap_or_default()
        .to_string()
}

/// `POST /panel-settings/ssl` - issue a certificate for the panel's own name.
///
/// Source: `install_panel_ssl`. Proxied until now because the helper verb it
/// needs, `panel-ssl-install`, was still bash.
///
/// The refusal that matters is the domain check. Let's Encrypt will not sign
/// an IP address, so asking certbot for one fails after it has already talked
/// to the CA - and on a rate-limited account that failure is expensive. The
/// panel says no before any of that happens.
async fn install_panel_ssl(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    // `if panel_hostname: ... elif panel_url: ... else: raise` - the hostname
    // wins when both are sent, which is the order the Python tries them in.
    let hostname = payload
        .get("panel_hostname")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let url = payload
        .get("panel_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();

    let fallback_port = state.settings.panel_port.get() as i64;
    let (host, port) = if !hostname.is_empty() {
        let host = match normalize_panel_hostname(hostname) {
            Ok(h) => h,
            Err(e) => return bad_request(&e),
        };
        let port = match normalize_panel_port(
            payload.get("panel_port").and_then(Value::as_i64),
            fallback_port,
        ) {
            Ok(p) => p,
            Err(e) => return bad_request(&e),
        };
        (host, port)
    } else if !url.is_empty() {
        let (host, port) = parse_panel_url(url, fallback_port);
        match normalize_panel_hostname(&host) {
            Ok(h) => (h, port),
            Err(e) => return bad_request(&e),
        }
    } else {
        return bad_request("Panel hostname is required");
    };

    if !is_panel_domain(&host) {
        return bad_request("Panel SSL requires a domain name, not an IP address");
    }

    let email = certbot_email(&current.user.email, &state.settings.ssl_email, &host);

    let port_text = port.to_string();
    let mut args: Vec<&str> = vec![&host, &port_text];
    if !email.is_empty() {
        args.push(&email);
    }
    // Minutes, not seconds: certbot answers an HTTP-01 challenge over the
    // network. The same 300s the sibling switch uses.
    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        "panel-ssl-install",
        &args,
        None,
        Some(&["bash", "-lc", "true"]),
        Some(300),
    )
    .await;
    if !result.ok() {
        return internal_error_with(&tail_500(
            &result.failure_detail("Could not install panel SSL"),
        ));
    }

    // `data["panel_url"] = f"https://{host}:{port}"` - written to the settings
    // file, not merely returned, because the panel reads it back on restart to
    // know what it is reachable as.
    let mut raw = raw_settings();
    if let Some(map) = raw.as_object_mut() {
        map.insert(
            "panel_url".to_string(),
            Value::String(format!("https://{host}:{port}")),
        );
    }
    if let Err(e) = write_raw(&raw) {
        tracing::error!("writing the panel settings failed: {e}");
        return crate::errors::internal_error();
    }

    audit_panel(
        &state,
        &parts,
        current.user.id,
        "install_panel_ssl",
        &format!("https://{host}:{port}"),
    )
    .await;

    let mut out = current_settings(&state).await;
    if let Some(map) = out.as_object_mut() {
        let message = result.stdout.trim();
        map.insert(
            "message".to_string(),
            Value::String(if message.is_empty() {
                format!("Panel SSL enabled for {host}")
            } else {
                message.to_string()
            }),
        );
    }
    axum::Json(out).into_response()
}

/// A 500 carrying the reason, which is what `RuntimeError` becomes in
/// FastAPI's handler here - not a 400.
///
/// The distinction is not cosmetic: a 400 tells the administrator they asked
/// for something wrong, and certbot failing to reach the CA is not that.
fn internal_error_with(detail: &str) -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({ "detail": detail })),
    )
        .into_response()
}

/// `PATCH /panel-settings/admin-account` - the signed-in administrator's own
/// email and password.
///
/// Source: `update_admin_account`. Proxied until now for the step-up check,
/// which `users::set_password` already carries: changing your own password
/// takes the current one, and the TOTP code as well when 2FA is on. Being an
/// administrator is not enough on its own, because a stolen admin session
/// would otherwise be able to change that admin's own password and lock the
/// owner out.
///
/// The order is the Python's and it matters at one point: the email
/// uniqueness check runs **before** the password is set. The other way round
/// leaves a request that changed the password, failed on the email, and
/// reported failure - so the administrator does not know their password moved.
async fn update_admin_account(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    // Pydantic validates the model before the handler runs, so the field
    // checks come before the role check. That is not only a status code: the
    // other order would tell a caller whether they are an administrator
    // before looking at what they sent.
    let password = match payload.get("password") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => return crate::errors::string_type("password", other),
    };
    if let Some(password) = password.as_deref() {
        if let Err(r) = crate::errors::check_length("password", password, 12, 72) {
            return r;
        }
        if let Err(r) = super::users::check_linux_login_password(password) {
            return r;
        }
    }
    let email = match payload.get("email") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => return crate::errors::string_type("email", other),
    };
    if let Some(email) = email.as_deref() {
        if snpanel_core::Email::parse(email).is_err() {
            return crate::errors::value_error(
                "email",
                "value is not a valid email address",
                &Value::String(email.to_string()),
            );
        }
    }

    if !permissions::has_role(&current.user.role, Role::Admin) {
        return crate::errors::not_enough_permissions();
    }

    // `password_changed = bool(payload.password)` - an empty string is
    // falsy, so sending `""` changes nothing rather than setting an empty
    // password. The length check above has already refused it anyway.
    let password_changed = password.as_deref().is_some_and(|p| !p.is_empty());
    if password_changed {
        if let Err(r) = super::users::require_step_up(&state, &current, &payload) {
            return r;
        }
    }

    // Before anything is written.
    let email_changed = email
        .as_deref()
        .is_some_and(|e| e != current.user.email.as_str());
    if email_changed {
        let candidate = email.as_deref().unwrap_or_default();
        match state
            .db
            .users()
            .email_taken_by_other(candidate, current.user.id)
            .await
        {
            Ok(true) => {
                return crate::errors::error(
                    axum::http::StatusCode::CONFLICT,
                    "Email already in use",
                )
            }
            Ok(false) => {}
            Err(e) => {
                tracing::error!("checking the email failed: {e}");
                return crate::errors::internal_error();
            }
        }
    }

    if password_changed {
        let password = password.clone().unwrap_or_default();
        // The system account first, as `set_panel_user_password` does: a
        // panel password that changed while SFTP kept the old one is the
        // confusing half.
        let linux_user = match snpanel_core::types::PanelUsername::parse(
            current.user.username.trim().to_lowercase().as_str(),
        ) {
            Ok(u) => u,
            Err(e) => return bad_request(&format!("invalid username: {e}")),
        };
        let result = crate::shell::privileged(
            state.settings.command_dry_run,
            "panel-user-password",
            &[linux_user.as_str()],
            Some(&format!("{password}\n")),
            Some(&["true"]),
        )
        .await;
        if !result.ok() {
            tracing::error!(
                "setting the system password failed: {}",
                result.failure_detail("panel-user-password")
            );
            return crate::errors::internal_error();
        }

        let hashed = match snpanel_core::crypto::password::hash_password(&password) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("hashing failed: {e}");
                return crate::errors::internal_error();
            }
        };
        if let Err(e) = state
            .db
            .users()
            .set_hashed_password(current.user.id, &hashed)
            .await
        {
            tracing::error!("storing the password failed: {e}");
            return crate::errors::internal_error();
        }
        // `token_version += 1` - every session issued before this one ends,
        // which is the point of changing a password you think was stolen.
        if let Err(e) = state.db.users().bump_token_version(current.user.id).await {
            tracing::error!("bumping the token version failed: {e}");
            return crate::errors::internal_error();
        }
    }

    if email_changed {
        let fields = snpanel_db::UserFields {
            email: email.clone(),
            ..Default::default()
        };
        if let Err(e) = state
            .db
            .users()
            .update(current.user.id, &fields, false)
            .await
        {
            tracing::error!("updating the admin email failed: {e}");
            return crate::errors::internal_error();
        }
    }

    audit_panel(
        &state,
        &parts,
        current.user.id,
        "update_admin_account",
        &current.user.username,
    )
    .await;

    axum::Json(json!({
        "message": "Admin account updated",
        "password_changed": password_changed,
    }))
    .into_response()
}

/// Source: `MAX_ASSET_SIZE`.
const MAX_ASSET_SIZE: usize = 1024 * 1024;

/// Source: `detect_asset_type`.
///
/// The type comes from the **content**, not the filename. A file named
/// `logo.png` that is actually HTML would otherwise be written to the assets
/// directory and served back with `Content-Type: image/png` - which is a
/// stored file the panel vouches for, under a name the panel chose, to every
/// administrator who loads the login page.
///
/// The two error messages are different on purpose and the Python has both:
/// a file whose *extension* is one of the four allowed types is told its
/// content does not match, and anything else is told which types are
/// supported. The first is nearly always a renamed file; the second is
/// nearly always the wrong file.
pub(crate) fn detect_asset_type(content: &[u8], filename: &str) -> Result<&'static str, String> {
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Ok("png");
    }
    if content.starts_with(b"\xff\xd8\xff") {
        return Ok("jpg");
    }
    // `RIFF....WEBP` - the four bytes at offset 8, after the chunk size.
    if content.starts_with(b"RIFF") && content.len() >= 12 && &content[8..12] == b"WEBP" {
        return Ok("webp");
    }
    if content.starts_with(b"\x00\x00\x01\x00") {
        return Ok("ico");
    }
    let suffix = filename
        .rsplit_once('.')
        .map(|(_, s)| s.to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(suffix.as_str(), "png" | "jpg" | "jpeg" | "webp" | "ico") {
        return Err("Uploaded file content does not match its image type".to_string());
    }
    Err("Only PNG, JPG, WEBP, and ICO images are supported".to_string())
}

/// `POST /panel-settings/logo` and `POST /panel-settings/favicon`.
///
/// Source: `upload_logo` / `upload_favicon`, both of which are
/// `save_asset(kind, file)`.
async fn upload_logo(State(state): State<AppState>, req: Request) -> Response {
    save_asset(state, req, "logo").await
}

async fn upload_favicon(State(state): State<AppState>, req: Request) -> Response {
    save_asset(state, req, "favicon").await
}

async fn save_asset(state: AppState, req: Request, kind: &str) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return crate::errors::not_enough_permissions();
    }

    let request = Request::from_parts(parts.clone(), body);
    let mut multipart = match axum::extract::Multipart::from_request(request, &state).await {
        Ok(m) => m,
        Err(e) => return crate::errors::bad_request(&e.body_text()),
    };

    let mut content: Option<Vec<u8>> = None;
    let mut filename = String::new();
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                // `file: UploadFile = File(...)` - the part is named `file`,
                // and a form carrying other parts is not an error.
                if field.name() != Some("file") {
                    continue;
                }
                filename = field.file_name().unwrap_or_default().to_string();
                match field.bytes().await {
                    Ok(bytes) => content = Some(bytes.to_vec()),
                    Err(e) => return crate::errors::bad_request(&e.body_text()),
                }
            }
            Ok(None) => break,
            Err(e) => return crate::errors::bad_request(&e.body_text()),
        }
    }

    let Some(content) = content else {
        return crate::errors::missing_field("file", Value::Null);
    };
    // `upload.read(MAX_ASSET_SIZE + 1)` then `len > MAX_ASSET_SIZE` - reading
    // one byte more than the limit is how the Python tells "exactly at the
    // limit" from "over it" without holding the whole upload.
    if content.len() > MAX_ASSET_SIZE {
        return crate::errors::bad_request("Image must be 1 MB or smaller");
    }
    let ext = match detect_asset_type(&content, &filename) {
        Ok(ext) => ext,
        Err(message) => return crate::errors::bad_request(&message),
    };

    let dir = data_dir().join("assets");
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        tracing::error!("creating {} failed: {e}", dir.display());
        return crate::errors::internal_error();
    }

    // The previous file goes first, and its failure is ignored: an asset that
    // is already gone is not a reason to refuse the new one. It matters
    // because the extension may change - a PNG replaced by an ICO leaves
    // `logo.png` behind, still served by the URL in the settings file until
    // that file is rewritten below.
    let mut raw = raw_settings();
    let key = format!("{kind}_filename");
    if let Some(previous) = raw.get(&key).and_then(Value::as_str) {
        if !previous.is_empty() && previous != format!("{kind}.{ext}") {
            let _ = tokio::fs::remove_file(dir.join(previous)).await;
        }
    }

    let name = format!("{kind}.{ext}");
    if let Err(e) = tokio::fs::write(dir.join(&name), &content).await {
        tracing::error!("writing {name} failed: {e}");
        return crate::errors::internal_error();
    }
    if let Some(map) = raw.as_object_mut() {
        map.insert(key, Value::String(name));
    }
    if let Err(e) = write_raw(&raw) {
        tracing::error!("writing the panel settings failed: {e}");
        return crate::errors::internal_error();
    }

    let action = if kind == "logo" {
        "upload_panel_logo"
    } else {
        "upload_panel_favicon"
    };
    audit_panel(&state, &parts, current.user.id, action, "panel").await;

    axum::Json(to_response_model(&current_settings(&state).await)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_reply_has_every_field_with_three_of_them_real() {
        // FastAPI's response_model fills the rest in from the schema. Sending
        // only the three projected keys is a different response body, and the
        // shadow diff reported twelve fields as missing when it did.
        let projected = json!({
            "app_name": "My Panel",
            "logo_url": "/api/panel-settings/assets/logo.png",
            "favicon_url": "/api/panel-settings/assets/icon.png",
        });
        let body = to_response_model(&projected);

        assert_eq!(body.as_object().unwrap().len(), 15);
        assert_eq!(body["app_name"], json!("My Panel"));
        assert_eq!(
            body["logo_url"],
            json!("/api/panel-settings/assets/logo.png")
        );

        // Everything else is the schema default, not the real value - which is
        // what keeps the server's addresses off an unauthenticated page.
        assert_eq!(body["panel_url"], json!(""));
        assert_eq!(body["server_ipv4"], json!([]));
        assert_eq!(body["ipv6"], json!({}));
        assert_eq!(body["message"], Value::Null);
        assert_eq!(body["malware_scan_installed"], json!(false));
        assert_eq!(body["malware_scan_detail"], Value::Null);
    }

    #[test]
    fn a_field_the_schema_does_not_declare_is_dropped() {
        let body = to_response_model(&json!({"app_name": "x", "invented": 1}));
        assert!(body.get("invented").is_none(), "{body}");
    }

    #[test]
    fn the_public_projection_is_three_fields() {
        // This list is a security boundary, not a convenience: everything else
        // in the settings tells an anonymous visitor about the server and its
        // customers.
        assert_eq!(
            PUBLIC_SETTING_FIELDS,
            &["app_name", "logo_url", "favicon_url"]
        );
        for leaked in [
            "panel_url",
            "panel_hostname",
            "server_ipv4",
            "ipv6",
            "ssl_mode",
            "malware_scan_installed",
        ] {
            assert!(
                !PUBLIC_SETTING_FIELDS.contains(&leaked),
                "{leaked} must not be public"
            );
        }
    }

    #[test]
    fn a_panel_url_yields_its_host_and_port() {
        assert_eq!(
            parse_panel_url("https://panel.example.com:2222", 2222),
            ("panel.example.com".to_string(), 2222)
        );
        assert_eq!(
            parse_panel_url("https://panel.example.com:9443/", 2222),
            ("panel.example.com".to_string(), 9443)
        );
        // No port: the configured one stands rather than the scheme's default.
        assert_eq!(
            parse_panel_url("https://panel.example.com", 2222),
            ("panel.example.com".to_string(), 2222)
        );
    }

    #[test]
    fn an_unparsable_url_leaves_the_hostname_empty() {
        for bad in ["", "not a url", "panel.example.com:2222"] {
            let (host, port) = parse_panel_url(bad, 2222);
            assert!(host.is_empty(), "{bad:?} -> {host}");
            assert_eq!(port, 2222);
        }
    }

    #[test]
    fn an_asset_url_is_empty_when_nothing_is_stored() {
        assert_eq!(asset_url(""), "");
        assert_eq!(
            asset_url("logo-abc.png"),
            "/api/panel-settings/assets/logo-abc.png"
        );
    }

    #[test]
    fn the_ipv6_status_lines_are_parsed_as_key_values() {
        let (available, enabled, addresses) =
            parse_ipv6_status("available=yes\nenabled=no\naddresses=2001:db8::1,2001:db8::2\n");
        assert!(available);
        assert!(!enabled);
        assert_eq!(addresses, vec!["2001:db8::1", "2001:db8::2"]);

        // Anything but the literal "yes" is false.
        let (available, enabled, addresses) = parse_ipv6_status("available=1\nenabled=true\n");
        assert!(!available);
        assert!(!enabled);
        assert!(addresses.is_empty());
    }

    #[test]
    fn an_empty_address_list_yields_no_addresses() {
        // "addresses=" splits to [""], which must not become one empty entry.
        let (_, _, addresses) = parse_ipv6_status("available=yes\naddresses=\n");
        assert!(addresses.is_empty());
    }

    #[test]
    fn only_global_addresses_are_reported() {
        assert!(is_link_local(&"169.254.1.1".parse().unwrap()));
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(!is_link_local(&"203.0.113.4".parse().unwrap()));
        assert!(!is_link_local(&"2001:db8::1".parse().unwrap()));
        assert!("127.0.0.1"
            .parse::<std::net::IpAddr>()
            .unwrap()
            .is_loopback());
    }

    #[test]
    fn a_long_error_is_trimmed_from_the_end() {
        // The tail is what says why it failed; the head is usually a banner.
        let long = "x".repeat(400);
        let trimmed = tail_300(&long);
        assert_eq!(trimmed.chars().count(), 300);
        assert_eq!(tail_300("short"), "short");
    }

    #[test]
    fn a_host_python_will_not_call_a_hostname_is_reported_as_none() {
        // Found by the shadow diff on Debian 13: `snpanel.deb13` has digits in
        // its top level, so Python's DOMAIN_RE refuses it and reports an empty
        // hostname. Echoing it back here would have the panel offer to request
        // a certificate for a name the other half considers unusable.
        assert_eq!(
            parse_panel_url("http://snpanel.deb13:2222", 2222),
            (String::new(), 2222)
        );
    }

    #[test]
    fn ordinary_hosts_are_still_reported() {
        assert_eq!(
            parse_panel_url("https://claude.sgd.ovh:2222", 8080),
            ("claude.sgd.ovh".to_string(), 2222)
        );
        assert_eq!(
            parse_panel_url("http://192.0.2.10:2222", 8080),
            ("192.0.2.10".to_string(), 2222)
        );
        assert_eq!(
            parse_panel_url("http://localhost:2222", 8080),
            ("localhost".to_string(), 2222)
        );
    }

    #[test]
    fn an_ipv6_literal_does_not_get_split_in_half() {
        // `rsplit_once(':')` on "[::1]:2222" hands back "[::1" as a host.
        // Python's urlparse reads the literal correctly and then rejects it,
        // so both sides answer the same - now for the same reason.
        assert_eq!(
            parse_panel_url("http://[::1]:2222", 8080),
            (String::new(), 8080)
        );
    }

    #[test]
    fn a_port_outside_the_range_falls_back() {
        assert_eq!(
            parse_panel_url("http://example.com:99999", 2222),
            (String::new(), 2222)
        );
    }

    #[test]
    fn a_url_without_a_port_keeps_the_configured_one() {
        assert_eq!(
            parse_panel_url("https://example.com", 2222),
            ("example.com".to_string(), 2222)
        );
    }

    /// The address certbot registers with, and why empty is allowed.
    ///
    /// Source: `(email or settings.ssl_email or default_ssl_email(host)).strip()`.
    /// An empty result is not a failure - it makes the helper pass
    /// `--register-unsafely-without-email`, which is the right answer when
    /// there is no address to give and better than handing a CA one it will
    /// refuse.
    #[test]
    fn the_certbot_address_falls_back_in_the_pythons_order() {
        // The administrator's own, first.
        assert_eq!(
            certbot_email("admin@example.com", "ops@example.net", "panel.example.org"),
            "admin@example.com"
        );
        // Then the server-wide one.
        assert_eq!(
            certbot_email("", "ops@example.net", "panel.example.org"),
            "ops@example.net"
        );
        // Then one built from the host.
        assert_eq!(
            certbot_email("", "", "panel.example.org"),
            "admin@panel.example.org"
        );
        // Whitespace is not an address: `.strip()` runs before the test for
        // emptiness, so a settings file with a stray space falls through
        // rather than sending certbot a blank.
        assert_eq!(
            certbot_email("   ", "  ", "panel.example.org"),
            "admin@panel.example.org"
        );
        assert_eq!(
            certbot_email("  admin@example.com  ", "", "panel.example.org"),
            "admin@example.com"
        );

        // An IP address gets no constructed address, so the whole chain can
        // come back empty - and that is the case the helper handles by
        // registering without one.
        assert_eq!(certbot_email("", "", "192.0.2.1"), "");
        assert_eq!(default_ssl_email("192.0.2.1"), "");
        assert_eq!(default_ssl_email("localhost"), "");
        assert_eq!(
            default_ssl_email("PANEL.Example.ORG"),
            "admin@panel.example.org"
        );
    }

    /// Let's Encrypt will not sign an IP address.
    ///
    /// The refusal has to happen before certbot is called, not after: by the
    /// time certbot fails it has already talked to the CA, and on a
    /// rate-limited account those attempts are spent.
    ///
    /// This is the same check the handler makes, on the same type.
    #[test]
    fn panel_ssl_refuses_an_address_before_certbot_is_reached() {
        for host in ["panel.example.org", "xn--bcher-kva.example", "a.io"] {
            assert!(is_panel_domain(host), "{host} should be accepted");
        }
        // An address, a bare name, and the case that made this fail first:
        // `Domain::parse` - the *other* domain predicate in the Python -
        // accepts every one of these, which is why using it here let
        // `192.0.2.1` through to certbot.
        for host in ["192.0.2.1", "10.0.0.1", "localhost", "", "::1", "a.b"] {
            assert!(!is_panel_domain(host), "{host} must not reach certbot");
        }
        assert!(
            snpanel_core::Domain::parse("192.0.2.1").is_ok(),
            "the other predicate accepts an address - that is the trap"
        );
        // The top level is letters only: the Debian test machine
        // `snpanel.deb13` is a real host and is not one certbot can serve.
        assert!(!is_panel_domain("snpanel.deb13"));
    }

    /// `detect_asset_type` - the type comes from the content, not the name.
    ///
    /// This is the security-relevant half of the upload. A file called
    /// `logo.png` that is actually HTML would otherwise be written into the
    /// assets directory and served back as `image/png` from a path the panel
    /// chose, to every administrator who loads the login page. Sniffing the
    /// magic bytes is what stops the panel vouching for a file it has not
    /// looked at.
    #[test]
    fn an_asset_is_identified_by_its_bytes_not_its_name() {
        // The four the Python accepts, each by its signature.
        assert_eq!(
            detect_asset_type(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0d", "anything.txt"),
            Ok("png")
        );
        assert_eq!(detect_asset_type(b"\xff\xd8\xff\xe0JFIF", "x"), Ok("jpg"));
        assert_eq!(
            detect_asset_type(b"RIFF\x24\x00\x00\x00WEBPVP8 ", "x"),
            Ok("webp")
        );
        assert_eq!(
            detect_asset_type(b"\x00\x00\x01\x00\x01\x00", "x"),
            Ok("ico")
        );

        // A name that claims one of the four, over content that is not: the
        // Python says the content does not match, and so does this.
        for name in ["evil.png", "evil.JPG", "evil.jpeg", "evil.webp", "evil.ico"] {
            assert_eq!(
                detect_asset_type(b"<!DOCTYPE html><script>alert(1)</script>", name),
                Err("Uploaded file content does not match its image type".to_string()),
                "{name}"
            );
        }

        // Anything else is told which types are supported.
        for name in ["notes.txt", "payload.svg", "archive.zip", "", "noextension"] {
            assert_eq!(
                detect_asset_type(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>", name),
                Err("Only PNG, JPG, WEBP, and ICO images are supported".to_string()),
                "{name}"
            );
        }

        // An SVG named `.png` is the case worth naming: SVG can carry script,
        // and serving one as `image/png` is not a defence if a browser
        // sniffs. It is refused on content.
        assert!(detect_asset_type(b"<svg onload=alert(1)>", "logo.png").is_err());

        // `RIFF` alone is not WEBP - the marker is at offset 8, and a short
        // file must not be read past its end.
        assert!(detect_asset_type(b"RIFF", "x.webp").is_err());
        assert!(detect_asset_type(b"RIFF\x00\x00\x00\x00AVI ", "x.webp").is_err());
        assert!(detect_asset_type(b"", "x.png").is_err());

        // A truncated PNG signature is not a PNG.
        assert!(detect_asset_type(b"\x89PNG", "x.png").is_err());

        // The limit, checked here because a typo in it is silent: the Python
        // reads `MAX_ASSET_SIZE + 1` bytes and refuses `len > MAX`, so a file
        // of exactly one megabyte is accepted and one byte more is not.
        assert_eq!(MAX_ASSET_SIZE, 1024 * 1024);
    }
}
