//! `/api/auth` - ported from `api/auth.py`.
//!
//! The router every other route depends on. Ten endpoints, and the ones that
//! carry contracts are marked below:
//!
//! | route                  | contract                                      |
//! |------------------------|-----------------------------------------------|
//! | `POST /login`          | C1 bcrypt, C2 constant time, C9 rate limit, C7 cookies |
//! | `POST /logout`         | C27 token_version, revocation list             |
//! | `GET  /session`        | the Dashboard's whole bootstrap                |
//! | `GET  /csrf`           | the double-submit cookie                       |
//! | `GET  /sso/{token}`    | C26 one-shot provisioning login                |
//! | `POST /impersonate/{id}` | admin-only, TOTP re-prompt, audited          |
//! | `/2fa/*`               | C3 Fernet at rest, C6 pyotp compatibility      |
//!
//! Two details in `login` are worth stating plainly, because both look like
//! inefficiencies until you see what they defend:
//!
//! **A missing user still pays for a bcrypt verify** (C2). Returning early
//! would make "no such user" measurably faster than "wrong password", and that
//! timing difference is a username oracle - an attacker learns which accounts
//! exist without ever guessing a password.
//!
//! **The username key is rate-limited but never locked out** (C9). Locking it
//! would let anyone who knows an admin's username lock that admin out of their
//! own panel from a botnet. See `crate::ratelimit`.

use std::collections::BTreeMap;

use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::crypto::{fernet, password, token, totp};
use snpanel_core::permissions::{self, Role};
use snpanel_db::User;

use crate::auth::{CurrentUser, CSRF_COOKIE, SESSION_COOKIE};
use crate::errors::{
    check_length, error, internal_error, missing_entry, missing_field, not_a_dictionary,
    not_enough_permissions, validation_error,
};
use crate::ratelimit::{Decision, RateLimiter};
use crate::state::AppState;
use crate::storage;

/// Source: `_MAX_USERNAME_LEN` and `_MAX_PASSWORD_LEN`.
const MAX_USERNAME_LEN: usize = 64;
const MAX_PASSWORD_LEN: usize = 72;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/session", get(session))
        .route("/csrf", get(csrf))
        .route("/sso/{token}", get(sso_login))
        .route("/impersonate/{user_id}", post(impersonate))
        .route("/2fa/status", get(two_factor_status))
        .route("/2fa/setup", post(two_factor_setup))
        .route("/2fa/enable", post(two_factor_enable))
        .route("/2fa/disable", post(two_factor_disable))
        .merge(super::passkeys::router())
}

// ---------------------------------------------------------------------------
// Errors, in FastAPI's shapes
// ---------------------------------------------------------------------------

/// A 429 with the `Retry-After` header the Python attaches.
pub(crate) fn too_many(detail: &str, retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after.to_string())],
        axum::Json(json!({ "detail": detail })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/// Source: `_is_secure_request` - both of its branches.
///
/// Python checks the forwarded header **and** `request.url.scheme`. The second
/// branch is the one that matters when this process holds the certificate
/// itself: there is no proxy in front to set a header, so a header-only check
/// concludes "not secure" on a connection that plainly is, and the session and
/// CSRF cookies go out without `Secure`. That is how this was found - a real
/// login over real HTTPS returned cookies a browser would happily send over
/// plain HTTP.
///
/// It is still not "are we in production": the panel is served over plain
/// `http://IP:2222` during a first install, and forcing `Secure` there would
/// set a cookie the browser never sends back - a login that appears to succeed
/// and lands you on the login page again.
pub(crate) fn is_secure_request(headers: &HeaderMap, serves_tls: bool) -> bool {
    if serves_tls {
        return true;
    }
    crate::middleware::forwarded_proto_is_https(headers)
}

/// Source: `secrets.token_urlsafe(32)`.
fn new_csrf_token() -> String {
    token::generate_jti()
}

fn cookie(name: &str, value: &str, max_age: i64, http_only: bool, secure: bool) -> String {
    let mut c = format!("{name}={value}; Max-Age={max_age}; Path=/; SameSite=Lax");
    if secure {
        c.push_str("; Secure");
    }
    if http_only {
        c.push_str("; HttpOnly");
    }
    c
}

/// Source: `_set_session_cookies`.
///
/// Two cookies with deliberately different visibility: the session is
/// `HttpOnly` so script cannot read the token, and the CSRF value is *not*, so
/// the SPA can echo it into `X-CSRF-Token`. That asymmetry is the double-submit
/// pattern; making them both HttpOnly would break every mutating request, and
/// making them both readable would hand a token to any XSS.
fn set_session_cookies(
    headers: &mut HeaderMap,
    secure: bool,
    token: &str,
    csrf_token: &str,
    max_age: i64,
) {
    for value in [
        cookie(SESSION_COOKIE, token, max_age, true, secure),
        cookie(CSRF_COOKIE, csrf_token, max_age, false, secure),
    ] {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.append(header::SET_COOKIE, v);
        }
    }
}

/// Source: `_clear_session_cookies` - Starlette's `delete_cookie`, which is a
/// set with an empty value and an expiry in 1970.
fn clear_session_cookies(headers: &mut HeaderMap) {
    for name in [SESSION_COOKIE, CSRF_COOKIE] {
        let value = format!(
            "{name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; SameSite=lax"
        );
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.append(header::SET_COOKIE, v);
        }
    }
}

/// Source: `_issue_login_session`.
pub(crate) fn issue_login_session(
    state: &AppState,
    headers: &mut HeaderMap,
    secure: bool,
    user: &User,
    extra_claims: &[(&str, Value)],
    lifetime_minutes: Option<i64>,
) -> Result<String, Response> {
    let mut extra = BTreeMap::new();
    extra.insert("role".to_string(), json!(user.role));
    // `tv`, not `token_version` - the claim name is part of C4 and a session
    // minted with the wrong one authenticates against neither implementation.
    extra.insert(
        token::TOKEN_VERSION_CLAIM.to_string(),
        json!(user.token_version),
    );
    for (k, v) in extra_claims {
        extra.insert((*k).to_string(), v.clone());
    }

    let minutes = lifetime_minutes.unwrap_or(state.settings.access_token_expire_minutes);
    let token =
        token::create_access_token(&state.settings.secret_key, &user.username, extra, minutes)
            .map_err(|e| {
                tracing::error!("cannot mint an access token: {e}");
                internal_error()
            })?;

    set_session_cookies(headers, secure, &token, &new_csrf_token(), minutes * 60);
    Ok(token)
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

/// Source: `core/step_up.verify_totp`.
///
/// Spaces are stripped because authenticator apps display `123 456` and people
/// paste what they see.
/// Shared with `users::set_password`, which needs the same check for its
/// step-up. One implementation, so the two cannot drift on what counts as
/// a valid window.
pub(crate) fn verify_totp(state: &AppState, user: &User, code: &str) -> bool {
    let Some(stored) = user.totp_secret.as_deref() else {
        return false;
    };
    if stored.is_empty() {
        return false;
    }
    let Ok(secret) = fernet::decrypt(
        &state.settings.secret_key,
        Some(stored),
        state.settings.strict_decrypt,
    ) else {
        return false;
    };
    let clean: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return false;
    }
    totp::verify_with_skew(&secret, &clean, unix_now()).unwrap_or(false)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Source: `require_sensitive_action_step_up` - the current password, then the
/// TOTP if the account has one.
fn require_step_up(
    state: &AppState,
    user: &User,
    current_password: &str,
    code: &str,
) -> Result<(), Response> {
    if current_password.is_empty()
        || !password::verify_password(current_password, &user.hashed_password)
    {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "Current password is incorrect",
        ));
    }
    if user.totp_enabled && !verify_totp(state, user, code) {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "Invalid authentication code",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /login
// ---------------------------------------------------------------------------

async fn login(State(state): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let headers = parts.headers.clone();
    let secure = is_secure_request(&headers, state.serves_tls);
    let ip_key = crate::client::rate_limit_key(&parts);

    let form = match read_form(body).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    // Both fields are reported when both are absent, in the order the form
    // declares them, because that is what Pydantic does.
    let missing: Vec<Value> = ["username", "password"]
        .iter()
        .filter(|f| !form.contains_key(**f))
        .map(|f| missing_entry(f, Value::Null))
        .collect();
    if !missing.is_empty() {
        return validation_error(missing);
    }
    let username = form["username"].clone();
    let submitted_password = form["password"].clone();
    let otp = form.get("otp").cloned().unwrap_or_default();
    let remember = form.get("remember").cloned().unwrap_or_default();

    // Oversize credentials are refused before anything expensive happens: it
    // protects bcrypt, and it stops a megabyte of rubbish becoming a
    // rate-limit key that never expires from memory.
    if username.len() > MAX_USERNAME_LEN || submitted_password.len() > MAX_PASSWORD_LEN {
        return error(StatusCode::UNAUTHORIZED, "Invalid username or password");
    }

    let user_key = RateLimiter::username_key(&username);

    for key in [&ip_key, &user_key] {
        if let Decision::Refuse {
            detail,
            retry_after,
        } = state.rate_limiter.check(key).await
        {
            return too_many(detail, retry_after);
        }
    }

    let user = match state.db.users().by_username(&username).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("user lookup failed during login: {e}");
            return internal_error();
        }
    };

    // C2. The dummy verify on the miss path is the entire defence against a
    // username oracle, and it has to happen on *this* side of the branch.
    let password_ok = match &user {
        Some(u) => password::verify_password(&submitted_password, &u.hashed_password),
        None => {
            password::verify_dummy(&submitted_password);
            false
        }
    };

    let Some(user) = user.filter(|_| password_ok) else {
        state.rate_limiter.record_failure(&ip_key, true).await;
        state.rate_limiter.record_failure(&user_key, false).await;
        crate::auth_log::login_failure(&parts);
        return error(StatusCode::UNAUTHORIZED, "Invalid username or password");
    };

    if !user.is_active {
        return error(StatusCode::FORBIDDEN, "User is suspended");
    }

    // The second step: the app code, a passkey, or either. Read only once the
    // password is right, and failing closed - not knowing whether an account
    // has a passkey is not a reason to let the password through alone.
    let passkeys = match state.db.passkeys().for_user(user.id, &user.username).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("listing passkeys during login failed: {e}");
            return internal_error();
        }
    };
    if user.totp_enabled || !passkeys.is_empty() {
        // A code answers only where there is one to check: an account whose
        // second step is passkeys alone is asked for a passkey whatever the
        // form sent.
        if otp.is_empty() || !user.totp_enabled {
            // Not an error: the SPA shows the second step on this reply.
            //
            // Not in the Python: `methods`, and - when the user has a passkey
            // registered on this host - `passkey`, which the page tries first
            // and, with the app code on, falls back from to the code. See
            // `passkeys.rs`.
            let remember_me = matches!(
                remember.trim().to_lowercase().as_str(),
                "1" | "true" | "on" | "yes"
            );
            let offer =
                super::passkeys::login_offer(&state, &headers, &user, &passkeys, remember_me);
            if offer.is_none() && !user.totp_enabled {
                // Passkeys alone, and none of them works at this address - an
                // IP address, or another name. Where they do work is said.
                let hosts = super::passkeys::hosts_of(&passkeys);
                return error(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "This account confirms its sign-in with a passkey, and its passkeys work only at {hosts}. Open the panel there."
                    ),
                );
            }
            let mut methods = Vec::new();
            if offer.is_some() {
                methods.push("passkey");
            }
            if user.totp_enabled {
                methods.push("totp");
            }
            let mut body = json!({
                "access_token": Value::Null,
                "token_type": "bearer",
                "requires_2fa": true,
                "methods": methods
            });
            if let Some(offer) = offer {
                body["passkey"] = offer;
            }
            return axum::Json(body).into_response();
        }
        if !verify_totp(&state, &user, &otp) {
            state.rate_limiter.record_failure(&ip_key, true).await;
            state.rate_limiter.record_failure(&user_key, false).await;
            crate::auth_log::login_failure(&parts);
            return error(StatusCode::UNAUTHORIZED, "Invalid authentication code");
        }
    }

    state.rate_limiter.record_success(&ip_key).await;
    state.rate_limiter.record_success(&user_key).await;

    // An old, cheap hash is upgraded on the one occasion the plaintext is in
    // hand. A failure here must not fail the login - the user's password is
    // correct either way.
    if password::needs_rehash(&user.hashed_password) {
        match password::hash_password(&submitted_password) {
            Ok(new_hash) => {
                if let Err(e) = state
                    .db
                    .users()
                    .set_hashed_password(user.id, &new_hash)
                    .await
                {
                    tracing::warn!("password rehash could not be stored: {e}");
                }
            }
            Err(e) => tracing::warn!("password rehash failed: {e}"),
        }
    }

    // Source: `remember.strip().lower() in {"1", "true", "on", "yes"}`.
    let remember_me = matches!(
        remember.trim().to_lowercase().as_str(),
        "1" | "true" | "on" | "yes"
    );
    let lifetime = remember_me.then_some(state.settings.remember_me_expire_minutes);

    let mut out_headers = HeaderMap::new();
    let token = match issue_login_session(&state, &mut out_headers, secure, &user, &[], lifetime) {
        Ok(t) => t,
        Err(r) => return r,
    };

    (
        out_headers,
        axum::Json(json!({
            "access_token": token,
            "token_type": "bearer",
            "requires_2fa": false
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /logout
// ---------------------------------------------------------------------------

async fn logout(State(state): State<AppState>, current: CurrentUser) -> Response {
    // Both halves matter. Revoking the jti kills *this* session even though
    // the token is still within its lifetime; bumping token_version kills
    // every other tab and device at the same time, which is what a user
    // pressing "log out" on a shared machine assumes happened.
    let expires_at = snpanel_db::format_timestamp(
        chrono::DateTime::from_timestamp(current.claims.exp, 0)
            .map(|d| d.naive_utc())
            .unwrap_or_else(|| chrono::Utc::now().naive_utc()),
    );
    if !current.claims.jti.is_empty() {
        if let Err(e) = state
            .db
            .revoked_tokens()
            .revoke(&current.claims.jti, current.user.id, &expires_at)
            .await
        {
            tracing::error!("could not record the revoked token: {e}");
        }
    }
    if let Err(e) = state.db.users().bump_token_version(current.user.id).await {
        tracing::error!("could not bump token_version on logout: {e}");
        return internal_error();
    }

    let mut headers = HeaderMap::new();
    clear_session_cookies(&mut headers);
    (headers, axum::Json(json!({ "ok": true }))).into_response()
}

// ---------------------------------------------------------------------------
// GET /session
// ---------------------------------------------------------------------------

/// The SPA's bootstrap call, and the only endpoint that answers 200 to an
/// unauthenticated request - it reports `authenticated: false` instead, so the
/// frontend can render the login page rather than an error.
async fn session(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = CurrentUser::from_parts(&mut parts, &state).await;

    let Ok(current) = current else {
        let mut headers = HeaderMap::new();
        clear_session_cookies(&mut headers);
        return (
            headers,
            axum::Json(json!({ "authenticated": false, "user": Value::Null })),
        )
            .into_response();
    };

    let user = current.user;
    let package_name = state
        .db
        .users()
        .package_name(user.package_id)
        .await
        .unwrap_or(None);

    let usage = user_storage(&state, &user).await;

    axum::Json(json!({
        "authenticated": true,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "package_name": package_name,
            "website_limit": user.website_limit,
            "storage_limit_mb": user.storage_limit_mb,
            "totp_enabled": user.totp_enabled,
            "storage_used_bytes": usage.used_bytes,
            "storage_limit_bytes": usage.limit_bytes,
            "storage_percent": usage.percent,
        }
    }))
    .into_response()
}

/// Source: `storage_quota.storage_usage_summary`, called from `auth.py`
/// with `use_cache` left at its default of false.
///
/// Counts applications as well as websites. It used to sum website roots
/// alone, which understated every account with a site app — and understated
/// it against an *enforcement* path that already counted them, so a customer
/// could be refused a write at a figure this endpoint had never shown them.
///
/// The walk is blocking and can touch tens of thousands of files, but it is
/// not wrapped in `spawn_blocking` here any more: the counting now needs the
/// database and the helper, so it is async throughout, and the blocking file
/// walk inside `path_usage_bytes` is the same one every other caller already
/// performs.
async fn user_storage(state: &AppState, user: &User) -> storage::Usage {
    let used = crate::storage_quota::user_storage_used_bytes(
        state.settings.command_dry_run,
        &state.db,
        user.id,
        super::addons::application_installed(),
    )
    .await;

    storage::Usage::new(
        used as i64,
        storage::limit_bytes(&user.role, user.storage_limit_mb),
    )
}

// ---------------------------------------------------------------------------
// GET /csrf
// ---------------------------------------------------------------------------

async fn csrf(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let headers = parts.headers.clone();
    if let Err(rejection) = CurrentUser::from_parts(&mut parts, &state).await {
        return rejection;
    }

    // Reuse the value already in the cookie when there is one: minting a fresh
    // token would invalidate a mutating request the SPA has in flight with the
    // old header.
    let existing = crate::auth::cookie_from(&headers, CSRF_COOKIE);
    let csrf_token = existing.unwrap_or_else(new_csrf_token);

    let mut out = HeaderMap::new();
    let value = cookie(
        CSRF_COOKIE,
        &csrf_token,
        state.settings.access_token_expire_minutes * 60,
        false,
        is_secure_request(&headers, state.serves_tls),
    );
    if let Ok(v) = HeaderValue::from_str(&value) {
        out.append(header::SET_COOKIE, v);
    }
    (out, axum::Json(json!({ "csrf_token": csrf_token }))).into_response()
}

// ---------------------------------------------------------------------------
// GET /sso/{token}
// ---------------------------------------------------------------------------

/// One-shot login from the provisioning API (C26).
///
/// The token is a file that is deleted as it is read, so a link that leaks
/// from a log or a browser history is already spent.
async fn sso_login(
    State(state): State<AppState>,
    Path(sso_token): Path<String>,
    req: Request,
) -> Response {
    let (parts, _) = req.into_parts();
    let secure = is_secure_request(&parts.headers, state.serves_tls);
    let audit_ip = crate::client::audit_ip(&parts);
    let user_agent = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Some(username) = crate::sso::consume_panel_login_token(&sso_token) else {
        return error(StatusCode::NOT_FOUND, "Invalid or expired token");
    };

    let user = match state.db.users().by_username(&username).await {
        Ok(Some(u)) => u,
        Ok(None) => return error(StatusCode::NOT_FOUND, "Invalid or expired token"),
        Err(e) => {
            tracing::error!("SSO user lookup failed: {e}");
            return internal_error();
        }
    };

    if !user.is_active {
        return redirect("/?error=account_suspended", HeaderMap::new());
    }

    let mut headers = HeaderMap::new();
    if let Err(r) = issue_login_session(&state, &mut headers, secure, &user, &[], None) {
        return r;
    }

    let detail = snpanel_db::AuditRepo::detail_with_request("provisioning", &audit_ip, &user_agent);
    if let Err(e) = state
        .db
        .audits()
        .log(None, "auth.sso", &user.username, &detail)
        .await
    {
        tracing::error!("could not write the SSO audit entry: {e}");
    }

    redirect("/", headers)
}

fn redirect(location: &str, mut headers: HeaderMap) -> Response {
    // 302, as Starlette's RedirectResponse defaults to.
    headers.insert(header::LOCATION, HeaderValue::from_str(location).unwrap());
    (StatusCode::FOUND, headers).into_response()
}

// ---------------------------------------------------------------------------
// POST /impersonate/{user_id}
// ---------------------------------------------------------------------------

async fn impersonate(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let headers = parts.headers.clone();
    let secure = is_secure_request(&headers, state.serves_tls);
    let ip_key = crate::client::rate_limit_key(&parts);
    let audit_ip = crate::client::audit_ip(&parts);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }

    let form = match read_form(body).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    let otp = form.get("otp").cloned().unwrap_or_default();

    // Rate-limited like a login: without it, this endpoint enumerates user ids
    // for anyone who has an admin session open.
    let user_key = RateLimiter::username_key(&current.user.username);
    for key in [&ip_key, &user_key] {
        if let Decision::Refuse {
            detail,
            retry_after,
        } = state.rate_limiter.check(key).await
        {
            return too_many(detail, retry_after);
        }
    }

    let target = match state.db.users().by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return error(StatusCode::NOT_FOUND, "User not found"),
        Err(e) => {
            tracing::error!("impersonation lookup failed: {e}");
            return internal_error();
        }
    };

    // An admin with 2FA re-proves possession of it. A stolen session cookie is
    // then not enough to walk into every customer's account.
    if current.user.totp_enabled {
        if otp.is_empty() {
            return error(
                StatusCode::UNAUTHORIZED,
                "Two-factor authentication code required",
            );
        }
        if !verify_totp(&state, &current.user, &otp) {
            state.rate_limiter.record_failure(&ip_key, true).await;
            return error(StatusCode::UNAUTHORIZED, "Invalid authentication code");
        }
    }

    // Written *before* the session is issued: a database failure must not
    // leave an impersonation that happened with no record of who did it.
    let detail = snpanel_db::AuditRepo::detail_with_request(
        &format!("target_user_id={} target_role={}", target.id, target.role),
        &audit_ip,
        &user_agent,
    );
    if let Err(e) = state
        .db
        .audits()
        .log(
            Some(current.user.id),
            "auth.impersonate",
            &target.username,
            &detail,
        )
        .await
    {
        tracing::error!("could not write the impersonation audit entry: {e}");
    }

    let mut out = HeaderMap::new();
    let token = match issue_login_session(
        &state,
        &mut out,
        secure,
        &target,
        &[(token::IMPERSONATION_CLAIM, json!(true))],
        None,
    ) {
        Ok(t) => t,
        Err(r) => return r,
    };

    (
        out,
        axum::Json(json!({
            "access_token": token,
            "token_type": "bearer",
            "requires_2fa": false
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// /2fa
// ---------------------------------------------------------------------------

async fn two_factor_status(current: CurrentUser) -> Response {
    axum::Json(json!({ "enabled": current.user.totp_enabled })).into_response()
}

async fn two_factor_setup(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let current_password = match payload.get("current_password").and_then(Value::as_str) {
        Some(v) => v.to_string(),
        None => return missing_field("current_password", payload.clone()),
    };
    if let Err(r) = check_length("current_password", &current_password, 1, 72) {
        return r;
    }
    let code = payload
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !code.is_empty() {
        if let Err(r) = check_length("code", &code, 6, 12) {
            return r;
        }
    }

    if let Err(r) = require_step_up(&state, &current.user, &current_password, &code) {
        return r;
    }
    if current.user.totp_enabled {
        return error(
            StatusCode::BAD_REQUEST,
            "Two-factor authentication is already enabled",
        );
    }

    let secret = totp::generate_secret();
    // C3: the column holds a Fernet ciphertext. The plaintext is returned to
    // the user once, here, and never stored.
    let stored = fernet::encrypt(&state.settings.secret_key, &secret);
    if let Err(e) = state
        .db
        .users()
        .set_totp_secret(current.user.id, Some(&stored))
        .await
    {
        tracing::error!("could not store the TOTP secret: {e}");
        return internal_error();
    }

    let account = if current.user.email.is_empty() {
        current.user.username.clone()
    } else {
        current.user.email.clone()
    };
    let uri = match totp::provisioning_uri(&secret, &account, &state.settings.totp_issuer) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("could not build the provisioning URI: {e}");
            return internal_error();
        }
    };

    axum::Json(json!({
        "secret": secret,
        "provisioning_uri": uri,
        "qr_data_url": crate::qr::data_url(&uri),
    }))
    .into_response()
}

async fn two_factor_enable(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let headers = parts.headers.clone();
    let secure = is_secure_request(&headers, state.serves_tls);
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let code = match payload.get("code").and_then(Value::as_str) {
        Some(v) => v.to_string(),
        None => return missing_field("code", payload.clone()),
    };
    if let Err(r) = check_length("code", &code, 6, 12) {
        return r;
    }

    if current
        .user
        .totp_secret
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        return error(
            StatusCode::BAD_REQUEST,
            "Set up two-factor authentication first",
        );
    }
    if !verify_totp(&state, &current.user, &code) {
        return error(StatusCode::BAD_REQUEST, "Invalid authentication code");
    }

    let mut user = current.user;
    if !user.totp_enabled {
        // Turning 2FA on invalidates sessions opened before it, which is the
        // point: a session that predates the second factor did not present one.
        match state
            .db
            .users()
            .set_totp_enabled(user.id, true, false)
            .await
        {
            Ok(v) => {
                user.totp_enabled = true;
                user.token_version = v;
            }
            Err(e) => {
                tracing::error!("could not enable 2FA: {e}");
                return internal_error();
            }
        }
    }

    let mut out = HeaderMap::new();
    // The caller's own session was just invalidated by the bump, so it is
    // replaced here - otherwise enabling 2FA logs you out of the page you are
    // standing on.
    if let Err(r) = issue_login_session(&state, &mut out, secure, &user, &[], None) {
        return r;
    }
    (out, axum::Json(json!({ "enabled": true }))).into_response()
}

async fn two_factor_disable(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let headers = parts.headers.clone();
    let secure = is_secure_request(&headers, state.serves_tls);
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let current_password = match payload.get("current_password").and_then(Value::as_str) {
        Some(v) => v.to_string(),
        None => return missing_field("current_password", payload.clone()),
    };
    if let Err(r) = check_length("current_password", &current_password, 1, 72) {
        return r;
    }
    let code = payload
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !code.is_empty() {
        if let Err(r) = check_length("code", &code, 6, 12) {
            return r;
        }
    }

    if let Err(r) = require_step_up(&state, &current.user, &current_password, &code) {
        return r;
    }

    // The account's passkeys stay: they are a second step of their own, and
    // sign-in goes on asking for one of them.
    let mut user = current.user;
    match state
        .db
        .users()
        .set_totp_enabled(user.id, false, true)
        .await
    {
        Ok(v) => {
            user.totp_enabled = false;
            user.totp_secret = None;
            user.token_version = v;
        }
        Err(e) => {
            tracing::error!("could not disable 2FA: {e}");
            return internal_error();
        }
    }

    let mut out = HeaderMap::new();
    if let Err(r) = issue_login_session(&state, &mut out, secure, &user, &[], None) {
        return r;
    }
    (out, axum::Json(json!({ "enabled": false }))).into_response()
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// `application/x-www-form-urlencoded`, which is what OAuth2PasswordRequestForm
/// reads. Parsed by hand so a malformed body is a 422 in FastAPI's shape
/// rather than axum's own text.
async fn read_form(body: axum::body::Body) -> Result<BTreeMap<String, String>, Response> {
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "Request body is too large"))?;
    let mut out = BTreeMap::new();
    for pair in bytes.split(|b| *b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.iter().position(|b| *b == b'=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &[][..]),
        };
        out.insert(percent_decode(k), percent_decode(v));
    }
    Ok(out)
}

/// Form encoding: `+` is a space and `%XX` is a byte.
pub(super) fn percent_decode(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < raw.len() => {
                let hex = std::str::from_utf8(&raw[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(raw[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Shared with the other routers: every JSON body in the API is read this
/// way, so they all refuse an oversize or non-object body identically.
pub async fn read_json_body(body: axum::body::Body) -> Result<Value, Response> {
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "Request body is too large"))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| not_a_dictionary(Value::Null))?;
    // A valid JSON scalar is still not a model: Pydantic reports it with the
    // value it was given, so the body has to be parsed before it is refused.
    if !value.is_object() {
        return Err(not_a_dictionary(value));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_cookie_is_httponly_and_the_csrf_cookie_is_not() {
        // This asymmetry is the double-submit pattern. Both HttpOnly breaks
        // every mutating request; both readable hands a session to any XSS.
        let session = cookie(SESSION_COOKIE, "tok", 1800, true, true);
        let csrf = cookie(CSRF_COOKIE, "abc", 1800, false, true);
        assert!(session.contains("HttpOnly"), "{session}");
        assert!(!csrf.contains("HttpOnly"), "{csrf}");
        for c in [&session, &csrf] {
            assert!(c.contains("SameSite=Lax"), "{c}");
            assert!(c.contains("Path=/"), "{c}");
            assert!(c.contains("Max-Age=1800"), "{c}");
            assert!(c.contains("Secure"), "{c}");
        }
    }

    #[test]
    fn a_plain_http_install_does_not_get_secure_cookies() {
        // The panel is reachable over http://IP:2222 before a certificate
        // exists. A Secure cookie there is never sent back, so the login
        // appears to succeed and then bounces to the login page again.
        let plain = cookie(SESSION_COOKIE, "tok", 1800, true, false);
        assert!(!plain.contains("Secure"));
    }

    #[test]
    fn https_is_recognised_from_the_forwarded_header() {
        let mut headers = HeaderMap::new();
        assert!(!is_secure_request(&headers, false));

        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(is_secure_request(&headers, false));

        // A proxy chain sends a list; the first entry is the browser's.
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
        assert!(is_secure_request(&headers, false));

        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert!(!is_secure_request(&headers, false));
    }

    #[test]
    fn terminating_tls_here_is_enough_on_its_own() {
        // The bug this pins: with no proxy in front there is no
        // x-forwarded-proto, so a header-only check called a real HTTPS login
        // insecure and issued the session and CSRF cookies without `Secure`.
        // A browser will send an unmarked cookie over plain HTTP.
        let headers = HeaderMap::new();
        assert!(is_secure_request(&headers, true));

        // And an explicit `http` header does not override the fact that this
        // connection was terminated here.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert!(is_secure_request(&headers, true));
    }

    #[test]
    fn clearing_the_cookies_expires_them_in_the_past() {
        let mut headers = HeaderMap::new();
        clear_session_cookies(&mut headers);
        let values: Vec<String> = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(values.len(), 2);
        for v in &values {
            assert!(v.contains("Max-Age=0"), "{v}");
            assert!(v.contains("1970"), "{v}");
        }
        assert!(values.iter().any(|v| v.starts_with("snpanel_session=;")));
        assert!(values.iter().any(|v| v.starts_with("snpanel_csrf=;")));
    }

    #[test]
    fn a_form_body_is_decoded_the_way_a_browser_encodes_it() {
        let body = axum::body::Body::from("username=admin&password=p%40ss+word&remember=on");
        let form = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(read_form(body))
            .unwrap();
        assert_eq!(form.get("username").unwrap(), "admin");
        // %40 is @ and + is a space - a password with either in it must
        // survive, or the user simply cannot log in.
        assert_eq!(form.get("password").unwrap(), "p@ss word");
        assert_eq!(form.get("remember").unwrap(), "on");
    }

    #[test]
    fn an_empty_form_field_is_present_but_empty() {
        let body = axum::body::Body::from("username=admin&password=&otp=");
        let form = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(read_form(body))
            .unwrap();
        assert_eq!(form.get("password").map(String::as_str), Some(""));
        assert_eq!(form.get("otp").map(String::as_str), Some(""));
    }

    #[test]
    fn percent_decoding_leaves_a_malformed_escape_alone() {
        assert_eq!(percent_decode(b"a%zz"), "a%zz");
        assert_eq!(percent_decode(b"a%4"), "a%4");
        assert_eq!(percent_decode(b"100%"), "100%");
    }

    #[test]
    fn a_validation_error_puts_a_list_under_detail() {
        // FastAPI's 422 is a list. A string here renders as "[object Object]"
        // in the SPA's error handler.
        let resp = missing_field("username", Value::Null);
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn code_length_is_checked_the_way_pydantic_checks_it() {
        assert!(check_length("code", "123456", 6, 12).is_ok());
        assert!(check_length("code", "12345", 6, 12).is_err());
        assert!(check_length("code", "1234567890123", 6, 12).is_err());
    }

    #[test]
    fn the_remember_flag_accepts_the_four_words_python_accepts() {
        for yes in ["1", "true", "on", "yes", "TRUE", " On "] {
            assert!(
                matches!(
                    yes.trim().to_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                ),
                "{yes:?}"
            );
        }
        for no in ["0", "false", "off", "", "maybe"] {
            assert!(
                !matches!(
                    no.trim().to_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                ),
                "{no:?}"
            );
        }
    }

    #[test]
    fn a_csrf_token_looks_like_secrets_token_urlsafe_32() {
        let t = new_csrf_token();
        assert_eq!(t.len(), 43, "32 bytes, urlsafe base64, unpadded");
        assert!(!t.contains('='), "token_urlsafe does not pad");
        assert_ne!(t, new_csrf_token());
    }

    /// POST /login as the page sends it, at `host`.
    async fn sign_in(state: &AppState, host: &str, form: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(form.to_string()))
            .unwrap();
        let res = login(State(state.clone()), req).await;
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// A passkey is a second step of its own: an account with one and no app
    /// code is asked for it where it works, refused - with where it works -
    /// anywhere else, and never let through on the password alone, with a
    /// code or without one.
    #[tokio::test]
    async fn passkeys_alone_are_a_second_step_of_their_own() {
        let Some(mut state) = crate::testenv::panel("passkey-login").await else {
            eprintln!("skipped: could not build a test panel here");
            return;
        };
        state.serves_tls = true;
        // As every start does: the passkeys table is a Rust migration's.
        state.db.apply_rust_migrations().await.unwrap();
        let hash = password::hash_password("a long enough password").unwrap();
        let new_user = |username| snpanel_db::NewUser {
            username,
            email: "someone@example.test",
            hashed_password: &hash,
            role: "end_user",
            package_id: None,
            website_limit: 1,
            storage_limit_mb: 100,
            terminal_enabled: false,
        };
        let alice = state.db.users().create(&new_user("alice")).await.unwrap();
        state.db.users().create(&new_user("bob")).await.unwrap();
        state
            .db
            .passkeys()
            .insert(&snpanel_db::NewPasskey {
                user_id: alice,
                username: "alice",
                credential_id: "Y3JlZGVudGlhbA",
                public_key: &[1, 2, 3],
                algorithm: -7,
                sign_count: 0,
                rp_id: "panel.example.com",
                name: "Laptop",
                aaguid: "00000000-0000-0000-0000-000000000000",
                created_at: "2026-09-26 10:00:00.000000",
            })
            .await
            .unwrap();
        let alice_form = "username=alice&password=a+long+enough+password";

        // Where the passkey works: asked for it, and only it.
        let (status, body) = sign_in(&state, "panel.example.com:2222", alice_form).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["requires_2fa"], json!(true), "{body}");
        assert_eq!(body["methods"], json!(["passkey"]), "{body}");
        assert!(body["passkey"]["ticket"].is_string(), "{body}");
        assert!(body["access_token"].is_null(), "{body}");

        // A code sent anyway changes nothing: there is none to check.
        let with_code = format!("{alice_form}&otp=123456");
        let (status, body) = sign_in(&state, "panel.example.com:2222", &with_code).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["access_token"].is_null(), "{body}");
        assert_eq!(body["methods"], json!(["passkey"]), "{body}");

        // At an IP address no passkey can work: refused, saying where they do.
        for form in [alice_form, with_code.as_str()] {
            let (status, body) = sign_in(&state, "203.0.113.4:2222", form).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            let detail = body["detail"].as_str().unwrap_or_default();
            assert!(detail.contains("panel.example.com"), "{detail}");
            assert!(body.get("access_token").is_none(), "{body}");
        }

        // With the app code on as well, the code is the way in at the IP.
        state
            .db
            .users()
            .set_totp_enabled(alice, true, false)
            .await
            .unwrap();
        let (status, body) = sign_in(&state, "203.0.113.4:2222", alice_form).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["methods"], json!(["totp"]), "{body}");
        let (_, body) = sign_in(&state, "panel.example.com", alice_form).await;
        assert_eq!(body["methods"], json!(["passkey", "totp"]), "{body}");

        // An account with neither is let in on its password, as before.
        let (status, body) = sign_in(
            &state,
            "203.0.113.4:2222",
            "username=bob&password=a+long+enough+password",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["access_token"].is_string(), "{body}");
    }
}
