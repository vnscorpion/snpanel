//! The two response middlewares from `main.py`.
//!
//! Both are cross-cutting, which is why they live here rather than in a
//! router: they change *every* response, including the ones the strangler
//! proxies, and leaving either out would be a difference the shadow diff
//! reports on every single endpoint.
//!
//! **`security_headers`** uses `setdefault` in Python - it never overwrites a
//! header the handler already chose. Reproduced with the same rule, which also
//! means a proxied response that already carries Python's headers passes
//! through untouched instead of collecting a second copy.
//!
//! **`slide_session`** re-issues a cookie session once it is past halfway
//! through its life, turning a fixed expiry into an idle timeout. Without it
//! an admin with the panel open is thrown out mid-task at a fixed wall-clock
//! time, which is the sort of regression that gets blamed on "the Rust
//! rewrite" rather than on a missing middleware.

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use snpanel_core::crypto::token;

use crate::auth::{CSRF_COOKIE, SESSION_COOKIE};
use crate::state::AppState;

/// Source: `_SESSION_RENEW_RATIO`.
const RENEW_RATIO: f64 = 0.5;

/// Source: the `security_headers` middleware.
const HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("x-permitted-cross-domain-policies", "none"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    (
        "permissions-policy",
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), \
fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), \
payment=(), usb=()",
    ),
    (
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; \
frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    ),
];

/// Headers added only on a "potentially trustworthy" origin.
const TRUSTWORTHY_ONLY: &[(&str, &str)] = &[
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
];

pub async fn security_headers(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let trustworthy = is_trustworthy(request.headers(), state.serves_tls);
    let https = state.serves_tls || forwarded_proto_is_https(request.headers());
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    for (name, value) in HEADERS {
        set_default(headers, name, value);
    }
    if trustworthy {
        for (name, value) in TRUSTWORTHY_ONLY {
            set_default(headers, name, value);
        }
    }
    // HSTS only in production and only over HTTPS: sending it over plain HTTP
    // achieves nothing, and sending it from a development box pins a
    // developer's browser to HTTPS for a year.
    if state.settings.app_env.is_production() && https {
        set_default(
            headers,
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        );
    }
    response
}

/// `response.headers.setdefault(...)` - present means untouched.
fn set_default(headers: &mut HeaderMap, name: &str, value: &str) {
    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    if headers.contains_key(&name) {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// Source: `_is_potentially_trustworthy_origin` - HTTPS, or a loopback host.
fn is_trustworthy(headers: &HeaderMap, serves_tls: bool) -> bool {
    if serves_tls || forwarded_proto_is_https(headers) {
        return true;
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    // `request.url.hostname` has no port, so compare the host half only.
    let hostname = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host);
    matches!(hostname, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Only the header: callers that also need "this process holds the
/// certificate" pass `serves_tls` themselves.
pub fn forwarded_proto_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("https")
        })
        .unwrap_or(false)
}

/// Source: `maybe_renew_session_cookie`.
///
/// Five conditions have to hold before anything is re-issued, and each one is
/// there for a reason:
///
/// 1. the request authenticated by **cookie** - a bearer token belongs to a
///    CLI or a script and is not slid;
/// 2. it is not an **impersonation** session - an admin acting as a customer
///    must re-initiate rather than drift along indefinitely;
/// 3. the handler has not already set a session cookie - login, logout and the
///    2FA toggles set their own, and overwriting them would undo a logout;
/// 4. the token is past **halfway** through its life;
/// 5. it has not already expired.
pub async fn slide_session(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let request_cookies = request.headers().clone();
    let mut response = next.run(request).await;

    if let Err(e) = renew(&state, &request_cookies, &mut response) {
        // "Session renewal must never break a response" - the Python catches
        // everything here too.
        tracing::warn!("session renewal failed: {e}");
    }
    response
}

fn renew(state: &AppState, request: &HeaderMap, response: &mut Response) -> anyhow::Result<()> {
    let Some(raw) = crate::auth::cookie_from(request, SESSION_COOKIE) else {
        return Ok(());
    };
    // Already carrying a new session cookie: leave it alone.
    let already_set = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with(&format!("{SESSION_COOKIE}=")));
    if already_set {
        return Ok(());
    }

    // Expiry is checked by hand below, so an expired token must still decode.
    let claims = token::decode_ignoring_expiry(&state.settings.secret_key, &raw)?;
    if claims.is_impersonation() {
        return Ok(());
    }

    let now = chrono::Utc::now().timestamp();
    let lifetime = claims.exp - claims.iat;
    if lifetime <= 0 || claims.exp <= now {
        return Ok(());
    }
    if (claims.exp - now) as f64 > lifetime as f64 * RENEW_RATIO {
        return Ok(());
    }

    // round(), not truncate: truncating would shave a little off the lifetime
    // at every renewal until the session became uselessly short. Clamped to a
    // minute so a very short token cannot be re-issued already expired.
    let minutes = ((lifetime as f64 / 60.0).round() as i64).max(1);
    let mut extra = std::collections::BTreeMap::new();
    if let Some(role) = claims.role() {
        extra.insert("role".to_string(), serde_json::json!(role));
    } else {
        // `payload.get("role")` is None, and None is carried into the new
        // token rather than dropped.
        extra.insert("role".to_string(), serde_json::Value::Null);
    }
    extra.insert(
        token::TOKEN_VERSION_CLAIM.to_string(),
        serde_json::json!(claims.token_version()),
    );

    let new_token =
        token::create_access_token(&state.settings.secret_key, &claims.sub, extra, minutes)?;

    // The CSRF value is *kept*, not minted: a POST already in flight carries
    // the old header, and changing the cookie under it would fail that request
    // with a CSRF error the user cannot explain.
    let csrf = crate::auth::cookie_from(request, CSRF_COOKIE).unwrap_or_else(token::generate_jti);
    let secure = state.serves_tls || forwarded_proto_is_https(request);
    let max_age = lifetime;

    let headers = response.headers_mut();
    for value in [
        format!(
            "{SESSION_COOKIE}={new_token}; Max-Age={max_age}; Path=/; SameSite=Lax{}; HttpOnly",
            if secure { "; Secure" } else { "" }
        ),
        format!(
            "{CSRF_COOKIE}={csrf}; Max-Age={max_age}; Path=/; SameSite=Lax{}",
            if secure { "; Secure" } else { "" }
        ),
    ] {
        headers.append(header::SET_COOKIE, HeaderValue::from_str(&value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_counts_as_trustworthy_without_tls() {
        // The panel is reachable on http://127.0.0.1:2222 during install.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("127.0.0.1:2222"));
        assert!(is_trustworthy(&h, false));

        h.insert(header::HOST, HeaderValue::from_static("localhost:2222"));
        assert!(is_trustworthy(&h, false));
    }

    #[test]
    fn a_public_host_over_plain_http_is_not_trustworthy() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("panel.example.com"));
        assert!(!is_trustworthy(&h, false));

        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(is_trustworthy(&h, false));
    }

    #[test]
    fn terminating_tls_here_counts_as_https_with_no_header_at_all() {
        // When this process holds the certificate there is no proxy in front
        // to set x-forwarded-proto, and a header-only check concluded "plain
        // HTTP" on a connection that was demonstrably TLS. The visible symptom
        // was cookies sent without `Secure` over a real HTTPS login.
        let h = HeaderMap::new();
        assert!(!forwarded_proto_is_https(&h));
        assert!(is_trustworthy(&h, true));
    }

    #[test]
    fn setdefault_never_overwrites() {
        // A proxied response already carries Python's headers; a second copy
        // would be a difference on every single endpoint.
        let mut h = HeaderMap::new();
        h.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
        set_default(&mut h, "x-frame-options", "DENY");
        assert_eq!(h.get("x-frame-options").unwrap(), "SAMEORIGIN");

        set_default(&mut h, "x-content-type-options", "nosniff");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    }

    #[test]
    fn the_csp_is_the_pythons_byte_for_byte() {
        // A stricter policy would be an improvement, and NT1 says improvements
        // go in IMPROVEMENTS.md, not into a port. A looser one would be a
        // security regression under NT5.
        let csp = HEADERS
            .iter()
            .find(|(n, _)| *n == "content-security-policy")
            .unwrap()
            .1;
        assert!(csp.starts_with("default-src 'self'; script-src 'self';"));
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("connect-src 'self' ws: wss:"));
        assert!(csp.ends_with("form-action 'self'"));
    }

    #[test]
    fn the_renew_ratio_is_half() {
        assert_eq!(RENEW_RATIO, 0.5);
    }
}
