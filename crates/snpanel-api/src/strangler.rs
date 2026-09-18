//! The strangler proxy.
//!
//! Plan §9. This is the mechanism that makes Phase 3 possible at all: 211
//! endpoints cannot move in one cutover, so Rust sits in front and forwards
//! anything it has not ported to the Python process still listening on
//! localhost.
//!
//! ```text
//!   browser :2222
//!        |
//!   snpanel-api (Rust)
//!        |-- /api/services/*  -> handled here            ported
//!        |-- /api/health      -> handled here            ported
//!        `-- everything else  -> uvicorn 127.0.0.1:8000  not yet
//! ```
//!
//! What makes it safe is that both sides share the SQLite file, Redis, and
//! `SECRET_KEY` - so a session started through one is valid through the other.
//! That is what C4 is for, and why the `tv` claim being right mattered so much.
//!
//! **The frontend does not know.** NT7: no route is renamed and no response
//! shape changes, so `App.jsx` cannot tell which side answered. Any difference
//! is a bug in the Rust side, not a new API.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Headers that describe *this* connection rather than the request, and so
/// must not be forwarded to the upstream or copied back from it.
///
/// `Connection`, `Keep-Alive`, `Transfer-Encoding` and friends are hop-by-hop
/// per RFC 9110 §7.6.1. Copying `Transfer-Encoding: chunked` onto a response
/// whose body has already been buffered produces a reply the browser cannot
/// parse, which is the kind of failure that looks like a mysterious blank page.
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

#[derive(Clone)]
pub struct Upstream {
    /// `http://127.0.0.1:8000`, with no trailing slash.
    base: String,
    client: Client<HttpConnector, Body>,
}

impl Upstream {
    pub fn new(base: &str) -> Self {
        let mut connector = HttpConnector::new();
        // The upstream is on loopback; a slow connect means it is not there.
        connector.set_connect_timeout(Some(std::time::Duration::from_secs(5)));
        connector.set_nodelay(true);

        Self {
            base: base.trim_end_matches('/').to_string(),
            client: Client::builder(TokioExecutor::new()).build(connector),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// Is the Python side actually up?
    ///
    /// Used by the readiness check, so "the panel is broken" and "the part of
    /// the panel that has not been ported yet is down" are distinguishable.
    pub async fn is_reachable(&self) -> bool {
        let uri: Uri = match format!("{}/api/health", self.base).parse() {
            Ok(u) => u,
            Err(_) => return false,
        };
        let req = match Request::builder().uri(uri).body(Body::empty()) {
            Ok(r) => r,
            Err(_) => return false,
        };
        matches!(
            tokio::time::timeout(std::time::Duration::from_secs(3), self.client.request(req)).await,
            Ok(Ok(_))
        )
    }
}

/// Forward a request to the Python implementation and return its answer.
pub async fn proxy(State(upstream): State<Upstream>, req: Request) -> Response {
    let method = req.method().clone();
    // **`OriginalUri`, not `req.uri()`.** `Router::nest` rewrites the URI of a
    // request it passes inward, stripping the prefix it matched - so a handler
    // reached through `.nest("/api", ...)` sees `/users/7`, not
    // `/api/users/7`. Forwarding that truncated path sends the upstream to a
    // route that does not exist.
    //
    // It cost a real bug to find: a `DELETE /api/users/{id}` falling through a
    // method-level fallback arrived at Python as `/users/{id}`, matched the
    // SPA's GET-only catch-all, and came back 405 where Python alone answers
    // 404. axum records the untouched URI in this extension precisely for
    // proxies, and the top-level fallback happens to work without it only
    // because nothing has stripped anything by the time it runs.
    let uri = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|o| o.0.clone())
        .unwrap_or_else(|| req.uri().clone());
    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());

    let target: Uri = match format!("{}{}", upstream.base, path_and_query).parse() {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("cannot build an upstream URI for {path_and_query}: {e}");
            return unavailable("the upstream address is not usable");
        }
    };

    tracing::debug!(method = %method, path = %path_and_query, "proxying to the upstream");

    let (parts, body) = req.into_parts();
    let mut builder = Request::builder().method(method.clone()).uri(target);

    // Copy the request headers, minus the hop-by-hop ones, and keep Host as
    // the upstream's own - uvicorn does not care, but a mismatched Host is the
    // sort of thing that breaks a redirect later.
    if let Some(headers) = builder.headers_mut() {
        copy_headers(&parts.headers, headers);
        headers.remove(axum::http::header::HOST);
        // The Python side builds absolute SSO URLs from the request it sees
        // (C26), so it has to be told what the browser actually asked for.
        if let Some(host) = parts.headers.get(axum::http::header::HOST) {
            headers.insert("x-forwarded-host", host.clone());
        }
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        // The peer is **appended**, exactly as nginx's
        // `proxy_add_x_forwarded_for` does. uvicorn behind us reads the list
        // from the right and stops at the first entry that is not a trusted
        // proxy, so appending here is what makes a client-supplied header
        // harmless: whatever the caller wrote, the address we observed is to
        // its right and wins. Without this the Python sees every request as
        // coming from 127.0.0.1 - one rate-limit key for the whole Internet,
        // and an audit log that records the proxy instead of the user.
        if let Some(peer) = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
        {
            let chain = match parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            {
                Some(existing) => format!("{existing}, {peer}"),
                None => peer,
            };
            if let Ok(v) = HeaderValue::from_str(&chain) {
                headers.insert("x-forwarded-for", v);
            }
        }
    }

    let forwarded = match builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("cannot build the upstream request: {e}");
            return unavailable("could not forward the request");
        }
    };

    match upstream.client.request(forwarded).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let mut out = Response::builder().status(parts.status);
            if let Some(headers) = out.headers_mut() {
                copy_headers(&parts.headers, headers);
            }
            out.body(Body::new(body))
                .unwrap_or_else(|_| unavailable("the upstream reply could not be relayed"))
        }
        Err(e) => {
            // Distinguish this clearly in the log: the Rust side is fine and
            // the Python side is not, which is a different page of the runbook.
            tracing::error!(
                method = %method,
                path = %path_and_query,
                "upstream request failed: {e}"
            );
            unavailable("the part of the panel that serves this route is not responding")
        }
    }
}

fn copy_headers(from: &HeaderMap, to: &mut HeaderMap) {
    for (name, value) in from {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        to.append(name.clone(), value.clone());
    }
}

/// 502 with a shape the frontend already understands.
///
/// FastAPI puts its error text in `detail`, and `App.jsx` reads that, so a
/// proxy failure has to look the same rather than inventing a field the
/// frontend will render as "undefined".
fn unavailable(detail: &str) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        axum::Json(serde_json::json!({ "detail": detail })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base_url_loses_a_trailing_slash() {
        // Otherwise every proxied path becomes a double slash, which some
        // routers treat as a different route.
        assert_eq!(
            Upstream::new("http://127.0.0.1:8000/").base(),
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            Upstream::new("http://127.0.0.1:8000").base(),
            "http://127.0.0.1:8000"
        );
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        let mut from = HeaderMap::new();
        from.insert("connection", HeaderValue::from_static("keep-alive"));
        from.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        from.insert("upgrade", HeaderValue::from_static("websocket"));
        from.insert("cookie", HeaderValue::from_static("snpanel_session=abc"));
        from.insert("authorization", HeaderValue::from_static("Bearer xyz"));

        let mut to = HeaderMap::new();
        copy_headers(&from, &mut to);

        // Copying transfer-encoding onto an already-buffered body produces a
        // reply the browser cannot parse.
        assert!(!to.contains_key("transfer-encoding"));
        assert!(!to.contains_key("connection"));
        assert!(!to.contains_key("upgrade"));
        // Everything that carries the session must survive.
        assert_eq!(to.get("cookie").unwrap(), "snpanel_session=abc");
        assert_eq!(to.get("authorization").unwrap(), "Bearer xyz");
    }

    #[test]
    fn multiple_values_for_one_header_all_survive() {
        // Set-Cookie is the one that matters: the login response sets both
        // snpanel_session and snpanel_csrf, and dropping either breaks auth.
        let mut from = HeaderMap::new();
        from.append("set-cookie", HeaderValue::from_static("snpanel_session=a"));
        from.append("set-cookie", HeaderValue::from_static("snpanel_csrf=b"));

        let mut to = HeaderMap::new();
        copy_headers(&from, &mut to);
        assert_eq!(to.get_all("set-cookie").iter().count(), 2);
    }

    #[tokio::test]
    async fn a_nested_route_is_proxied_under_its_original_path() {
        // The regression: `nest("/api", ...)` strips the prefix before a
        // handler inside it runs, so a proxy reading `req.uri()` forwards
        // `/users/7` for a request to `/api/users/7`.
        use axum::routing::get;
        use tower::ServiceExt;

        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let recorder = seen.clone();

        let inner: axum::Router = axum::Router::new().route(
            "/users/{id}",
            get(|| async { "ported" }).fallback(move |req: Request| {
                let recorder = recorder.clone();
                async move {
                    let uri = req
                        .extensions()
                        .get::<axum::extract::OriginalUri>()
                        .map(|o| o.0.to_string())
                        .unwrap_or_else(|| req.uri().to_string());
                    *recorder.lock().unwrap() = uri;
                    "fell through"
                }
            }),
        );
        let app = axum::Router::new().nest("/api", inner);

        let request = Request::builder()
            .method("DELETE")
            .uri("/api/users/7")
            .body(Body::empty())
            .unwrap();
        let _ = app.oneshot(request).await.unwrap();

        assert_eq!(
            seen.lock().unwrap().as_str(),
            "/api/users/7",
            "the upstream has to be given the path the client actually asked for"
        );
    }

    #[test]
    fn a_client_supplied_forwarded_for_is_appended_to_not_replaced() {
        // The rule uvicorn applies is "read from the right, stop at the first
        // untrusted entry". Appending therefore makes a forged prefix
        // harmless; *replacing* the header would work too, but appending is
        // what nginx does and what the Python was tuned against.
        let existing = "1.2.3.4";
        let peer = "203.0.113.9";
        assert_eq!(format!("{existing}, {peer}"), "1.2.3.4, 203.0.113.9");
    }

    #[test]
    fn an_upstream_failure_looks_like_a_fastapi_error() {
        // App.jsx reads `detail`; inventing another field renders as
        // "undefined" in the UI.
        let resp = unavailable("upstream is down");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn an_absent_upstream_is_reported_as_unreachable_not_a_hang() {
        // Port 1 has nothing on it. This must come back quickly rather than
        // waiting on a connect that will never complete.
        let upstream = Upstream::new("http://127.0.0.1:1");
        let started = std::time::Instant::now();
        assert!(!upstream.is_reachable().await);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}
