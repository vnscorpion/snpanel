//! Authenticating a request, exactly as `api/deps.py` does.
//!
//! Every check below exists in the Python and is reproduced in the same order,
//! because a request that Python accepts and Rust refuses is a customer locked
//! out of a page that worked yesterday - and the reverse is worse.
//!
//! `_user_from_token` in order:
//!
//! 1. decode the JWT with `SECRET_KEY`, HS256;
//! 2. `sub` is the **username**; no `sub` is a 401;
//! 3. look the user up by username; not found is a 401;
//! 4. `is_active` false is a 401 **unless** the `imp` claim is set, because an
//!    admin's "log in as" session may legitimately target a suspended user;
//! 5. the user's `token_version` must equal the token's `tv`;
//! 6. a `jti` present in `revoked_tokens` is a 401.
//!
//! Then, separately, `_enforce_cookie_csrf`: when the request authenticated by
//! **cookie** and the method mutates, `snpanel_csrf` must equal the
//! `X-CSRF-Token` header, compared in constant time. Bearer auth is exempt,
//! and deliberately so - a browser will not attach an `Authorization` header
//! cross-origin on its own, so there is nothing to forge.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use snpanel_core::crypto::token;
use snpanel_db::User;

use crate::state::AppState;

/// Source: `_set_session_cookies` / the `snpanel_session` cookie alias.
pub const SESSION_COOKIE: &str = "snpanel_session";
/// Source: `_enforce_cookie_csrf`.
pub const CSRF_COOKIE: &str = "snpanel_csrf";
pub const CSRF_HEADER: &str = "x-csrf-token";

/// An authenticated request.
pub struct CurrentUser {
    pub user: User,
    pub claims: token::Claims,
    /// True when the token arrived in a cookie rather than a header. CSRF
    /// enforcement depends on it.
    pub via_cookie: bool,
}

impl CurrentUser {
    pub fn is_admin(&self) -> bool {
        self.user.is_admin()
    }
}

/// The 401 body FastAPI produces, so the frontend's error handling is
/// unchanged. `App.jsx` reads `detail`.
fn unauthorised() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", "Bearer")],
        axum::Json(serde_json::json!({ "detail": "Could not validate credentials" })),
    )
        .into_response()
}

fn csrf_failure() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "detail": "CSRF token missing or invalid" })),
    )
        .into_response()
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Self::from_parts(parts, state).await
    }
}

impl CurrentUser {
    /// The same six checks, callable from a handler that has already taken the
    /// request apart.
    ///
    /// `/auth/session` and `/auth/csrf` need this: `session` answers 200 with
    /// `authenticated: false` rather than 401, so it has to *see* the failure
    /// instead of having the extractor turn it into a response.
    pub async fn from_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let bearer = bearer_token(parts);
        let cookie = cookie_value(parts, SESSION_COOKIE);

        // Source: `_resolve_token` - the header wins over the cookie.
        let (raw, via_cookie) = match (bearer.as_deref(), cookie.as_deref()) {
            (Some(t), _) => (t.to_string(), false),
            (None, Some(t)) => (t.to_string(), true),
            (None, None) => return Err(unauthorised()),
        };

        let claims = token::decode_access_token(&state.settings.secret_key, &raw)
            .map_err(|_| unauthorised())?;
        if claims.sub.is_empty() {
            return Err(unauthorised());
        }

        let user = state
            .db
            .users()
            .by_username(&claims.sub)
            .await
            .map_err(|e| {
                tracing::error!("user lookup failed: {e}");
                unauthorised()
            })?
            .ok_or_else(unauthorised)?;

        // An impersonated session may target a suspended user; the `imp` claim
        // is only ever set by the impersonate endpoint, which has already
        // checked the caller is an admin.
        if !user.is_active && !claims.is_impersonation() {
            return Err(unauthorised());
        }

        if user.token_version != claims.token_version() {
            return Err(unauthorised());
        }

        if !claims.jti.is_empty()
            && state
                .db
                .revoked_tokens()
                .is_revoked(&claims.jti)
                .await
                .map_err(|e| {
                    tracing::error!("revocation lookup failed: {e}");
                    unauthorised()
                })?
        {
            return Err(unauthorised());
        }

        if via_cookie && mutates(&parts.method) {
            let cookie_csrf = cookie_value(parts, CSRF_COOKIE);
            let header_csrf = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            match (cookie_csrf, header_csrf) {
                (Some(a), Some(b)) if constant_time_eq(a.as_bytes(), b.as_bytes()) => {}
                _ => return Err(csrf_failure()),
            }
        }

        Ok(CurrentUser {
            user,
            claims,
            via_cookie,
        })
    }
}

/// Source: the method set in `_enforce_cookie_csrf`.
fn mutates(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn bearer_token(parts: &Parts) -> Option<String> {
    let value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    // OAuth2PasswordBearer accepts exactly "Bearer <token>", case-insensitively
    // on the scheme.
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Pull one cookie out of the `Cookie` header.
///
/// Hand-rolled rather than pulled in as a dependency because the parsing is
/// four lines and a cookie jar is not needed to read two names.
fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    cookie_from(&parts.headers, name)
}

/// The same, for a handler that holds the headers rather than the parts.
pub fn cookie_from(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    for header in headers.get_all(axum::http::header::COOKIE) {
        let Ok(text) = header.to_str() else { continue };
        for pair in text.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    let v = v.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Constant-time comparison, matching Python's `compare_digest`.
///
/// A byte-by-byte early return would leak the CSRF cookie through
/// response-time differences, which is the reason the Python uses
/// `compare_digest` and not `==`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Request};

    fn parts_with(headers: &[(&str, &str)], method: Method) -> Parts {
        let mut builder = Request::builder().method(method).uri("/api/x");
        for (k, v) in headers {
            builder = builder.header(*k, HeaderValue::from_str(v).unwrap());
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn the_bearer_header_wins_over_the_cookie() {
        // _resolve_token checks the header first.
        let p = parts_with(
            &[
                ("authorization", "Bearer header-token"),
                ("cookie", "snpanel_session=cookie-token"),
            ],
            Method::GET,
        );
        assert_eq!(bearer_token(&p).as_deref(), Some("header-token"));
        assert_eq!(
            cookie_value(&p, SESSION_COOKIE).as_deref(),
            Some("cookie-token")
        );
    }

    #[test]
    fn a_malformed_authorization_header_is_no_token_rather_than_an_error() {
        for bad in ["", "Bearer", "Bearer ", "Basic abc", "abc"] {
            let p = parts_with(&[("authorization", bad)], Method::GET);
            assert!(bearer_token(&p).is_none(), "{bad:?}");
        }
        // The scheme is case-insensitive.
        let p = parts_with(&[("authorization", "bearer tok")], Method::GET);
        assert_eq!(bearer_token(&p).as_deref(), Some("tok"));
    }

    #[test]
    fn cookies_are_picked_out_of_a_crowded_header() {
        let p = parts_with(
            &[(
                "cookie",
                "other=1; snpanel_session=sess; snpanel_csrf=csrf; last=2",
            )],
            Method::GET,
        );
        assert_eq!(cookie_value(&p, SESSION_COOKIE).as_deref(), Some("sess"));
        assert_eq!(cookie_value(&p, CSRF_COOKIE).as_deref(), Some("csrf"));
        assert!(cookie_value(&p, "absent").is_none());
    }

    #[test]
    fn a_cookie_name_is_matched_whole_not_as_a_prefix() {
        // `snpanel_session_old` must not satisfy a request for
        // `snpanel_session`.
        let p = parts_with(&[("cookie", "snpanel_session_old=stale")], Method::GET);
        assert!(cookie_value(&p, SESSION_COOKIE).is_none());
    }

    #[test]
    fn an_empty_cookie_value_counts_as_absent() {
        // A cleared cookie arrives as `name=`; treating that as a token would
        // send an empty string to the JWT decoder every time somebody logs out.
        let p = parts_with(&[("cookie", "snpanel_session=")], Method::GET);
        assert!(cookie_value(&p, SESSION_COOKIE).is_none());
    }

    #[test]
    fn only_mutating_methods_need_csrf() {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(mutates(&m), "{m}");
        }
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!mutates(&m), "{m}");
        }
    }

    #[test]
    fn constant_time_compare_is_still_correct() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
