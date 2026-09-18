//! Building links back into the panel - `services/panel_urls.py`.
//!
//! Two URLs, and they deliberately differ:
//!
//! - **the panel's own** (`panel_base_url`) carries `PANEL_PORT`, because that
//!   is the only port the panel listens on;
//! - **the tools URL** (`tools_base_url`) carries no port at all, because
//!   phpMyAdmin is served by nginx on 80/443. Putting :2222 on it would send
//!   the browser to a port where phpMyAdmin does not exist.
//!
//! The interesting rule is in `panel_base_url`: it follows the hostname the
//! request arrived on, **but only if the panel can actually serve that name**.
//! A login link should open on the domain the customer already uses rather
//! than on whichever single domain `PANEL_URL` happens to name - and honouring
//! an arbitrary `Host` header would put an attacker's domain into a link the
//! panel sends to a user. `serves_hostname` is what separates the two, and it
//! answers from the same SNI store that chooses the certificate.

use std::path::Path;

use snpanel_core::config::Settings;

use crate::tls::normalize_hostname;

/// Source: `panel_settings.SETTINGS_FILE`.
fn settings_file() -> std::path::PathBuf {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".to_string());
    Path::new(&dir).join("panel-settings.json")
}

/// Source: `panel_settings.configured_panel_url` - what an administrator set,
/// falling back to the `.env` value.
pub fn configured_panel_url(settings: &Settings) -> String {
    let stored = std::fs::read_to_string(settings_file())
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| {
            v.get("panel_url")
                .and_then(|u| u.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    if !stored.trim().is_empty() {
        return stored.trim().to_string();
    }
    settings.panel_url.trim().to_string()
}

/// Source: `has_panel_certificate`.
pub fn has_panel_certificate(settings: &Settings) -> bool {
    !settings.panel_ssl_cert.is_empty()
        && !settings.panel_ssl_key.is_empty()
        && Path::new(&settings.panel_ssl_cert).is_file()
        && Path::new(&settings.panel_ssl_key).is_file()
}

/// Source: `configured_panel_host` - the hostname in `PANEL_URL`, or
/// `PANEL_DOMAIN` when no URL has been set.
pub fn configured_panel_host(settings: &Settings) -> String {
    let url = configured_panel_url(settings);
    let host = if url.contains("://") {
        url.split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };
    let host = if host.is_empty() {
        settings.panel_domain.clone()
    } else {
        host
    };
    normalize_hostname(&host)
}

/// Source: `_request_host_without_port`.
pub fn request_host(headers: &axum::http::HeaderMap) -> String {
    let raw = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(axum::http::header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let first = raw.split(',').next().unwrap_or("").trim();
    normalize_hostname(first)
}

/// Source: `tools_base_url` - **no port**, because nginx serves phpMyAdmin on
/// the ordinary web ports.
pub fn tools_base_url(settings: &Settings, headers: &axum::http::HeaderMap) -> String {
    let host = if !settings.panel_domain.is_empty() {
        settings.panel_domain.clone()
    } else {
        let configured = configured_panel_host(settings);
        if configured.is_empty() {
            request_host(headers)
        } else {
            configured
        }
    };
    let scheme = if has_panel_certificate(settings) {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with(domain: &str, url: &str) -> Settings {
        Settings {
            panel_domain: domain.to_string(),
            panel_url: url.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_tools_url_never_carries_the_panel_port() {
        // phpMyAdmin is served by nginx on 80/443. A :2222 here sends the
        // browser to a port where it does not exist.
        let s = settings_with("panel.example.com", "https://panel.example.com:2222");
        let url = tools_base_url(&s, &axum::http::HeaderMap::new());
        assert!(!url.contains("2222"), "{url}");
        assert!(url.ends_with("panel.example.com"), "{url}");
    }

    #[test]
    fn the_configured_host_comes_out_of_the_panel_url() {
        let s = settings_with("", "https://panel.example.com:2222/");
        assert_eq!(configured_panel_host(&s), "panel.example.com");
    }

    #[test]
    fn the_domain_is_the_fallback_when_no_url_is_set() {
        let s = settings_with("fallback.example.com", "");
        assert_eq!(configured_panel_host(&s), "fallback.example.com");
    }

    #[test]
    fn the_request_host_loses_its_port_and_its_proxy_chain() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::HOST,
            axum::http::HeaderValue::from_static("Panel.Example.COM:2222"),
        );
        assert_eq!(request_host(&h), "panel.example.com");

        // A forwarded list: the first entry is the browser's.
        h.insert(
            "x-forwarded-host",
            axum::http::HeaderValue::from_static("first.example.com, second.example.com"),
        );
        assert_eq!(request_host(&h), "first.example.com");
    }

    #[test]
    fn no_certificate_means_an_http_link() {
        let mut s = settings_with("panel.example.com", "");
        s.panel_ssl_cert = "/nonexistent/cert.pem".into();
        s.panel_ssl_key = "/nonexistent/key.pem".into();
        assert!(!has_panel_certificate(&s));
        assert!(tools_base_url(&s, &axum::http::HeaderMap::new()).starts_with("http://"));
    }
}
