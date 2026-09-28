//! CloudLinux Manager's own UI, embedded in the panel (Hosting Edition).
//!
//! CloudLinux ships the LVE Manager / Selectors / Resource Usage SPA as PHP
//! pages for custom panels ("Web UI integration" in the control panel
//! integration guide). SNPanel serves them from Apache on a loopback-only
//! vhost (127.0.0.1:2224, PHP as the unprivileged `snpanel-lvem`) and this
//! module puts them on the panel's own origin at `/cloudlinux/`: same TLS, and
//! an iframe the panel page is allowed to show.
//!
//! Identity is the panel's, never the OS's (CloudLinux F-37 / CLOS-5551): the
//! panel mints a random token per opened view, the SPA stores it in its
//! `CLSIDTOKEN` cookie, and CloudLinux's `ui_user_info <token>` asks the
//! panel - on loopback only - who that token belongs to. A token dies with
//! the panel session it came from (token_version) and after idling.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::state::AppState;

/// Where Apache serves CloudLinux's PHP. Loopback only.
pub const UPSTREAM: &str = "http://127.0.0.1:2224";

/// The plugins CloudLinux's `LveManager.php` knows, and who may open each.
/// Administrators get everything; a hosting customer gets their own usage and
/// their PHP version.
pub fn plugin_allowed(plugin: &str, admin: bool) -> bool {
    match plugin {
        "resource_usage" | "php_selector" => true,
        "lvemanager" | "nodejs_selector" | "python_selector" | "xray" | "wpos" => admin,
        _ => false,
    }
}

/// The URL that opens `plugin` with `token` - CloudLinux reads the token from
/// the query once, moves it into a cookie and redirects the token away.
pub fn open_url(plugin: &str, token: &str) -> String {
    if plugin == "lvemanager" {
        format!("/cloudlinux/index.php?token={token}")
    } else {
        format!("/cloudlinux/open.php?plugin={plugin}&token={token}")
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// A token is unused for this long and it is gone.
const IDLE: Duration = Duration::from_secs(2 * 3600);
/// And gone this long after it was issued, whatever happens.
const LIFETIME: Duration = Duration::from_secs(12 * 3600);
/// A ceiling on live tokens, so a caller minting in a loop cannot grow the
/// map without bound. Each view opened is one token.
const MAX_TOKENS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: i64,
    /// The user's token_version when the token was issued: a panel logout or
    /// password change bumps it and so revokes every CloudLinux view as well.
    pub token_version: i64,
    issued: Instant,
    last_used: Instant,
}

fn store() -> &'static Mutex<HashMap<String, Session>> {
    static STORE: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn live(s: &Session, now: Instant) -> bool {
    now.duration_since(s.last_used) < IDLE && now.duration_since(s.issued) < LIFETIME
}

/// 256 random bits, hex: inside CloudLinux's accepted `[a-zA-Z0-9._-]{1,256}`.
fn new_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mint a token for this user.
pub fn issue(user_id: i64, token_version: i64) -> String {
    let now = Instant::now();
    let token = new_token();
    let mut map = store().lock().unwrap_or_else(|p| p.into_inner());
    map.retain(|_, s| live(s, now));
    if map.len() >= MAX_TOKENS {
        // Drop the least recently used rather than refuse the caller.
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, s)| s.last_used)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }
    map.insert(
        token.clone(),
        Session {
            user_id,
            token_version,
            issued: now,
            last_used: now,
        },
    );
    token
}

/// The session behind a token, touched, or `None` when unknown or expired.
pub fn resolve(token: &str) -> Option<Session> {
    let now = Instant::now();
    let mut map = store().lock().unwrap_or_else(|p| p.into_inner());
    let s = map.get_mut(token)?;
    if !live(s, now) {
        map.remove(token);
        return None;
    }
    s.last_used = now;
    Some(s.clone())
}

/// Forget a token (its user is gone or its panel session was revoked).
pub fn revoke(token: &str) {
    let mut map = store().lock().unwrap_or_else(|p| p.into_inner());
    map.remove(token);
}

// ---------------------------------------------------------------------------
// Reverse proxy for /cloudlinux/
// ---------------------------------------------------------------------------

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The only cookies CloudLinux's pages use. The panel's own session and CSRF
/// cookies are never handed to PHP.
const FORWARDED_COOKIES: &[&str] = &["CLSIDTOKEN", "csrftoken"];

/// The embedded pages' policy. CloudLinux's pages carry inline scripts and
/// styles, and its SPA is an Angular build that compiles its templates in the
/// browser (JIT, via `eval`) - under `script-src 'self'` it dies at start-up
/// and the page spins forever. So this relaxed policy applies to
/// `/cloudlinux/` only; the rest of the panel keeps its own, and nothing but
/// the panel may frame these pages. Its icons and fonts come from Google Fonts,
/// so those two hosts are allowed for styles and fonts - here only.
pub const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; \
font-src 'self' data: https://fonts.gstatic.com; \
connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'";

/// `Cookie` with only the pairs CloudLinux needs, or `None` when none remain.
pub fn filter_cookies(header: &str) -> Option<String> {
    let kept: Vec<&str> = header
        .split(';')
        .map(str::trim)
        .filter(|pair| {
            pair.split_once('=')
                .is_some_and(|(name, _)| FORWARDED_COOKIES.contains(&name.trim()))
        })
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

fn client() -> &'static Client<HttpConnector, Body> {
    static CLIENT: OnceLock<Client<HttpConnector, Body>> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        connector.set_nodelay(true);
        Client::builder(TokioExecutor::new()).build(connector)
    })
}

fn gateway(detail: &str) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        axum::Json(serde_json::json!({ "detail": detail })),
    )
        .into_response()
}

/// `GET /cloudlinux` - the SPA's base is the directory.
pub async fn redirect_to_dir() -> Response {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(axum::http::header::LOCATION, "/cloudlinux/")],
    )
        .into_response()
}

/// `/cloudlinux/*` -> Apache on loopback, only on a CloudLinux server.
pub async fn proxy(State(state): State<AppState>, req: Request) -> Response {
    if snpanel_osabi::hosting::cloudlinux().is_none() {
        return crate::errors::not_found("Not Found");
    }
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let target: Uri = match format!("{UPSTREAM}{path_and_query}").parse() {
        Ok(u) => u,
        Err(_) => return crate::errors::bad_request("bad path"),
    };
    let (parts, body) = req.into_parts();
    let mut builder = Request::builder().method(parts.method.clone()).uri(target);
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &parts.headers {
            let n = name.as_str();
            if HOP_BY_HOP.contains(&n) || n == "cookie" || n.starts_with("x-forwarded-") {
                continue;
            }
            // Host is kept as the browser sent it: CloudLinux checks that a
            // token arrives from its own origin (scheme + Host).
            headers.append(name.clone(), value.clone());
        }
        if let Some(cookie) = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(filter_cookies)
        {
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                headers.insert(axum::http::header::COOKIE, v);
            }
        }
        let proto = if state.serves_tls { "https" } else { "http" };
        headers.insert("x-forwarded-proto", HeaderValue::from_static(proto));
        if let Some(peer) = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        {
            if let Ok(v) = HeaderValue::from_str(&peer.0.ip().to_string()) {
                headers.insert("x-forwarded-for", v);
            }
        }
    }
    let forwarded = match builder.body(body) {
        Ok(r) => r,
        Err(_) => return gateway("could not forward the request"),
    };
    match client().request(forwarded).await {
        Ok(response) => {
            let (up, body) = response.into_parts();
            let mut out = Response::builder().status(up.status);
            if let Some(headers) = out.headers_mut() {
                copy_response_headers(&up.headers, headers);
            }
            out.body(Body::new(body))
                .unwrap_or_else(|_| gateway("the reply could not be relayed"))
        }
        Err(e) => {
            tracing::error!("CloudLinux UI upstream failed: {e}");
            gateway("CloudLinux Manager is not responding. Is Apache running?")
        }
    }
}

fn copy_response_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for (name, value) in from {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        to.append(name.clone(), value.clone());
    }
    // Set, not "if absent": these replace anything the page or the panel's
    // own middleware would otherwise put there.
    to.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    to.insert(
        axum::http::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    to.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customers_get_usage_and_php_only() {
        assert!(plugin_allowed("resource_usage", false));
        assert!(plugin_allowed("php_selector", false));
        assert!(!plugin_allowed("lvemanager", false));
        assert!(!plugin_allowed("xray", false));
        assert!(plugin_allowed("lvemanager", true));
        assert!(!plugin_allowed("../etc/passwd", true));
        assert!(!plugin_allowed("", true));
    }

    #[test]
    fn tokens_are_long_hex_and_resolve_until_revoked() {
        let t = issue(7, 3);
        assert_eq!(t.len(), 64);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        let s = resolve(&t).unwrap();
        assert_eq!((s.user_id, s.token_version), (7, 3));
        assert_ne!(issue(7, 3), t, "every view gets its own token");
        revoke(&t);
        assert!(resolve(&t).is_none());
        assert!(resolve("not-a-token").is_none());
    }

    #[test]
    fn only_cloudlinux_cookies_reach_php() {
        assert_eq!(
            filter_cookies("snpanel_session=abc; CLSIDTOKEN=t1; snpanel_csrf=x; csrftoken=c2"),
            Some("CLSIDTOKEN=t1; csrftoken=c2".to_string())
        );
        assert_eq!(filter_cookies("snpanel_session=abc; snpanel_csrf=x"), None);
        assert_eq!(filter_cookies("xCLSIDTOKEN=1"), None);
    }

    #[test]
    fn urls_open_the_plugin_with_the_token() {
        assert_eq!(
            open_url("lvemanager", "ab"),
            "/cloudlinux/index.php?token=ab"
        );
        assert_eq!(
            open_url("php_selector", "ab"),
            "/cloudlinux/open.php?plugin=php_selector&token=ab"
        );
    }

    #[test]
    fn the_embedded_policy_still_frames_only_from_the_panel() {
        assert!(CSP.contains("frame-ancestors 'self'"));
        // CloudLinux's Angular SPA compiles at runtime; without eval it spins.
        assert!(CSP.contains("'unsafe-eval'"));
    }
}
