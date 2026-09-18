//! `/api/panel-settings` - ported from `api/panel_settings.py`, the two reads.
//!
//! Changing the settings, the admin account, or uploading branding all write
//! and stay with Python. What is here is `/public` and the full read.
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

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::config::Settings;
use snpanel_core::permissions::{self, Role};

use crate::auth::CurrentUser;
use crate::errors::not_enough_permissions;
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
        .route("/panel-settings", get(full).fallback(crate::fallback))
}

fn data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()),
    )
}

fn raw_settings() -> Value {
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
    // A domain: at least two labels, the last all letters and at least two of
    // them, no label empty or longer than 63, and none starting with a hyphen.
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
}
