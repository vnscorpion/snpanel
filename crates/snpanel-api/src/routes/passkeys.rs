//! Passkeys: `/api/auth/passkeys*` and `/api/auth/login/passkey`.
//!
//! Not in the Python. A passkey is the second step of a sign-in, after the
//! password - on its own, or beside the authenticator-app code:
//!
//! - Anyone can add one, with their current password - and the app code as
//!   well when that is on. A session on its own cannot enrol a factor.
//!   Asking for the app code first read as a riddle ("turn on the
//!   authenticator app first"), and a passkey is the stronger factor of the
//!   two anyway.
//! - At sign-in, once the password is right, an account with a passkey or
//!   the app code is asked for one of them. The page tries a passkey
//!   registered on the host in use first, and falls back to the code, when
//!   there is one, if the passkey does not work - no authenticator at hand,
//!   the prompt cancelled, the signature refused.
//! - An account whose second step is passkeys alone, opened at an address
//!   none of them was made for (by IP address, say), is told where they
//!   work rather than let in on the password. A lost device is an
//!   administrator's 2FA reset, or `snpanel reset-admin-2fa` for the admin.
//! - Removing a passkey takes the current password, since it can be what
//!   stands between the account and a password-only sign-in. Turning the app
//!   code off leaves the passkeys; deleting the account removes them by
//!   foreign key.
//!
//! The checking itself is `snpanel_core::crypto::webauthn`. What lives here
//! is the challenge: 32 random bytes, kept in this process for three
//! minutes and used once, keyed by the user for an enrolment and by a random
//! ticket for a sign-in. A restart forgets them; the person starts again.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use rand::RngCore;
use serde_json::{json, Value};
use snpanel_core::crypto::{password, token, webauthn};
use snpanel_db::{NewPasskey, Passkey, User};

use crate::auth::CurrentUser;
use crate::errors::{error, internal_error, not_found};
use crate::ratelimit::{Decision, RateLimiter};
use crate::state::AppState;

/// How long a challenge stays good.
const CHALLENGE_TTL: Duration = Duration::from_secs(180);
/// What the browser is told to wait for the person, in milliseconds.
const PROMPT_TIMEOUT_MS: u64 = 120_000;
/// Pending challenges kept at once; the oldest goes first. Only a correct
/// password or a signed-in session makes one, so this bounds memory, not
/// abuse.
const MAX_PENDING: usize = 1024;
/// Enough for every device someone owns, and a bound on the list.
pub const MAX_PASSKEYS_PER_USER: usize = 10;
const MAX_NAME_CHARS: usize = 64;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/passkeys", get(list))
        .route("/passkeys/register/options", post(register_options))
        .route("/passkeys/register", post(register))
        .route("/passkeys/{passkey_id}", delete(remove))
        .route("/login/passkey", post(login))
}

// ---------------------------------------------------------------------------
// challenges in waiting
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Pending {
    user_id: i64,
    username: String,
    challenge: [u8; 32],
    origin: String,
    rp_id: String,
    remember: bool,
    created: Instant,
}

static PENDING: Mutex<Vec<(String, Pending)>> = Mutex::new(Vec::new());

fn keep(key: String, pending: Pending) {
    let mut all = PENDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    all.retain(|(k, p)| p.created.elapsed() < CHALLENGE_TTL && *k != key);
    if all.len() >= MAX_PENDING {
        all.remove(0);
    }
    all.push((key, pending));
}

/// Take a challenge out: it is used once, whatever the outcome.
fn take(key: &str) -> Option<Pending> {
    let mut all = PENDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let index = all.iter().position(|(k, _)| k == key)?;
    let (_, pending) = all.remove(index);
    (pending.created.elapsed() < CHALLENGE_TTL).then_some(pending)
}

fn new_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    challenge
}

// ---------------------------------------------------------------------------
// where the page is
// ---------------------------------------------------------------------------

/// The origin the browser will report in `clientDataJSON`, and the relying
/// party id - the host without its port.
///
/// `None` where a passkey cannot work: WebAuthn wants a secure context and a
/// domain name for the relying party, so an IP address, or plain HTTP to
/// anything but `localhost`, gets nothing. The page says so rather than
/// offering a button that fails.
pub(crate) fn web_origin(headers: &HeaderMap, serves_tls: bool) -> Option<(String, String)> {
    let host = headers
        .get(header::HOST)?
        .to_str()
        .ok()?
        .trim()
        .to_ascii_lowercase();
    // An IPv6 literal is `[...]`; an IP is never a relying party id.
    if host.is_empty() || host.starts_with('[') {
        return None;
    }
    let (hostname, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host.as_str(), None),
    };
    if let Some(port) = port {
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    if hostname.parse::<std::net::Ipv4Addr>().is_ok()
        || hostname.is_empty()
        || hostname.starts_with('.')
        || hostname.ends_with('.')
        || !hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    let scheme = if super::auth::is_secure_request(headers, serves_tls) {
        "https"
    } else if hostname == "localhost" {
        "http"
    } else {
        return None;
    };
    Some((format!("{scheme}://{host}"), hostname.to_string()))
}

fn item(passkey: &Passkey, here: Option<&str>) -> Value {
    json!({
        "id": passkey.id,
        "name": passkey.name,
        "rp_id": passkey.rp_id,
        "created_at": passkey.created_at,
        "last_used_at": passkey.last_used_at,
        "usable_here": here == Some(passkey.rp_id.as_str()),
    })
}

/// A base64url field somewhere inside the credential the page sent.
fn b64_field(value: &Value, path: &[&str]) -> Option<Vec<u8>> {
    let mut v = value;
    for key in path {
        v = v.get(*key)?;
    }
    webauthn::from_base64url(v.as_str()?)
}

fn aaguid_text(aaguid: &[u8; 16]) -> String {
    let hex: String = aaguid.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ---------------------------------------------------------------------------
// the list, and taking one away
// ---------------------------------------------------------------------------

async fn list(State(state): State<AppState>, headers: HeaderMap, current: CurrentUser) -> Response {
    let passkeys = match state
        .db
        .passkeys()
        .for_user(current.user.id, &current.user.username)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("listing passkeys failed: {e}");
            return internal_error();
        }
    };
    let here = web_origin(&headers, state.serves_tls).map(|(_, rp_id)| rp_id);
    axum::Json(json!({
        "totp_enabled": current.user.totp_enabled,
        // Whether a passkey can be added or used at the address in use.
        "available": here.is_some(),
        "rp_id": here,
        "limit": MAX_PASSKEYS_PER_USER,
        "items": passkeys.iter().map(|p| item(p, here.as_deref())).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Takes the current password: a passkey can be the only thing standing
/// between the account and a sign-in on the password alone, and a session on
/// its own should not be able to take that away. Not the app code as well -
/// with the code on, the account keeps a second step whatever goes.
async fn remove(
    State(state): State<AppState>,
    Path(passkey_id): Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let limit_key = RateLimiter::username_key(&current.user.username);
    if let Decision::Refuse {
        detail,
        retry_after,
    } = state.rate_limiter.check(&limit_key).await
    {
        return super::auth::too_many(detail, retry_after);
    }
    let given = payload
        .get("current_password")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if given.is_empty() || !password::verify_password(given, &current.user.hashed_password) {
        state.rate_limiter.record_failure(&limit_key, false).await;
        return error(StatusCode::UNAUTHORIZED, "Current password is incorrect");
    }
    match state
        .db
        .passkeys()
        .delete(passkey_id, current.user.id)
        .await
    {
        Ok(true) => {
            let _ = state
                .db
                .audits()
                .log(
                    Some(current.user.id),
                    "passkey_remove",
                    &current.user.username,
                    &passkey_id.to_string(),
                )
                .await;
            axum::Json(json!({ "deleted": true })).into_response()
        }
        Ok(false) => not_found("Passkey not found"),
        Err(e) => {
            tracing::error!("deleting a passkey failed: {e}");
            internal_error()
        }
    }
}

// ---------------------------------------------------------------------------
// adding one
// ---------------------------------------------------------------------------

async fn register_options(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let user = &current.user;
    // Where the page is comes first: at an IP address no proof would help.
    let Some((origin, rp_id)) = web_origin(&parts.headers, state.serves_tls) else {
        return error(
            StatusCode::BAD_REQUEST,
            "Passkeys need the panel to be opened by its hostname over HTTPS, not by an IP address",
        );
    };
    // The current password - and the app code, when it is on - is the proof,
    // so guessing it is limited the way a sign-in is: on the same key, so
    // guesses here count there too.
    let limit_key = RateLimiter::username_key(&user.username);
    if let Decision::Refuse {
        detail,
        retry_after,
    } = state.rate_limiter.check(&limit_key).await
    {
        return super::auth::too_many(detail, retry_after);
    }
    if let Err(refused) = super::users::require_step_up(&state, &current, &payload) {
        state.rate_limiter.record_failure(&limit_key, false).await;
        return refused;
    }
    let existing = match state.db.passkeys().for_user(user.id, &user.username).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("listing passkeys failed: {e}");
            return internal_error();
        }
    };
    if existing.len() >= MAX_PASSKEYS_PER_USER {
        return error(
            StatusCode::BAD_REQUEST,
            &format!("An account can have at most {MAX_PASSKEYS_PER_USER} passkeys"),
        );
    }

    let challenge = new_challenge();
    keep(
        format!("register:{}", user.id),
        Pending {
            user_id: user.id,
            username: user.username.clone(),
            challenge,
            origin,
            rp_id: rp_id.clone(),
            remember: false,
            created: Instant::now(),
        },
    );
    let exclude: Vec<Value> = existing
        .iter()
        .filter(|p| p.rp_id == rp_id)
        .map(|p| json!({ "type": "public-key", "id": p.credential_id }))
        .collect();
    axum::Json(json!({
        "publicKey": {
            "rp": { "id": rp_id, "name": state.settings.totp_issuer },
            "user": {
                "id": webauthn::base64url(&webauthn::user_handle(user.id, &user.username)),
                "name": user.username,
                "displayName": user.username,
            },
            "challenge": webauthn::base64url(&challenge),
            "pubKeyCredParams": webauthn::SUPPORTED_ALGORITHMS
                .iter()
                .map(|alg| json!({ "type": "public-key", "alg": alg }))
                .collect::<Vec<_>>(),
            "timeout": PROMPT_TIMEOUT_MS,
            "excludeCredentials": exclude,
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "userVerification": "preferred",
            },
            "attestation": "none",
        }
    }))
    .into_response()
}

async fn register(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let user = &current.user;
    let Some(pending) = take(&format!("register:{}", user.id)) else {
        return error(
            StatusCode::BAD_REQUEST,
            "The passkey request has expired. Start again.",
        );
    };

    let name = payload
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or("Passkey")
        .to_string();
    if name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return error(
            StatusCode::BAD_REQUEST,
            &format!("A passkey name is at most {MAX_NAME_CHARS} characters"),
        );
    }

    let credential = payload.get("credential").cloned().unwrap_or(Value::Null);
    let (Some(client_data), Some(attestation)) = (
        b64_field(&credential, &["response", "clientDataJSON"]),
        b64_field(&credential, &["response", "attestationObject"]),
    ) else {
        return error(
            StatusCode::BAD_REQUEST,
            "The passkey response is incomplete",
        );
    };
    let expected = webauthn::Expected {
        challenge: &pending.challenge,
        origin: &pending.origin,
        rp_id: &pending.rp_id,
    };
    let registration = match webauthn::verify_registration(&client_data, &attestation, &expected) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(user = %user.username, "passkey registration refused: {e}");
            return error(StatusCode::BAD_REQUEST, "The passkey could not be verified");
        }
    };
    let credential_id = webauthn::base64url(&registration.credential_id);
    // The id the browser reported has to be the one the authenticator signed.
    let reported = credential
        .get("id")
        .and_then(Value::as_str)
        .and_then(webauthn::from_base64url);
    if reported.as_deref() != Some(registration.credential_id.as_slice()) {
        return error(
            StatusCode::BAD_REQUEST,
            "The passkey response is inconsistent",
        );
    }

    let repo = state.db.passkeys();
    match repo.credential_exists(&credential_id).await {
        Ok(false) => {}
        Ok(true) => return error(StatusCode::CONFLICT, "This passkey is already registered"),
        Err(e) => {
            tracing::error!("checking a passkey failed: {e}");
            return internal_error();
        }
    }
    let stored = match repo
        .insert(&NewPasskey {
            user_id: user.id,
            username: &user.username,
            credential_id: &credential_id,
            public_key: &registration.public_key,
            algorithm: registration.algorithm,
            sign_count: i64::from(registration.sign_count),
            rp_id: &pending.rp_id,
            name: &name,
            aaguid: &aaguid_text(&registration.aaguid),
            created_at: &snpanel_db::sqlalchemy_now(),
        })
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("storing a passkey failed: {e}");
            return internal_error();
        }
    };
    let _ = state
        .db
        .audits()
        .log(Some(user.id), "passkey_add", &user.username, &name)
        .await;
    let here = Some(pending.rp_id.as_str());
    axum::Json(item(&stored, here)).into_response()
}

// ---------------------------------------------------------------------------
// signing in with one
// ---------------------------------------------------------------------------

/// What the password step adds to its `requires_2fa` answer when the user
/// has a passkey for this host: a ticket, and the options for
/// `navigator.credentials.get`. `None` when there is nothing to offer here -
/// the page at an IP address, or every passkey made for another host.
pub(crate) fn login_offer(
    state: &AppState,
    headers: &HeaderMap,
    user: &User,
    passkeys: &[Passkey],
    remember: bool,
) -> Option<Value> {
    let (origin, rp_id) = web_origin(headers, state.serves_tls)?;
    let allow: Vec<Value> = passkeys
        .iter()
        .filter(|p| p.rp_id == rp_id)
        .map(|p| json!({ "type": "public-key", "id": p.credential_id }))
        .collect();
    if allow.is_empty() {
        return None;
    }
    let challenge = new_challenge();
    let ticket = token::generate_jti();
    keep(
        format!("login:{ticket}"),
        Pending {
            user_id: user.id,
            username: user.username.clone(),
            challenge,
            origin,
            rp_id: rp_id.clone(),
            remember,
            created: Instant::now(),
        },
    );
    Some(json!({
        "ticket": ticket,
        "publicKey": {
            "challenge": webauthn::base64url(&challenge),
            "rpId": rp_id,
            "timeout": PROMPT_TIMEOUT_MS,
            "userVerification": "preferred",
            "allowCredentials": allow,
        }
    }))
}

/// The hosts an account's passkeys were made for, named for a sign-in that
/// can use none of them where it is.
pub(crate) fn hosts_of(passkeys: &[Passkey]) -> String {
    let mut hosts: Vec<&str> = passkeys.iter().map(|p| p.rp_id.as_str()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    hosts.join(", ")
}

async fn login(State(state): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let secure = super::auth::is_secure_request(&parts.headers, state.serves_tls);
    let ip_key = crate::client::rate_limit_key(&parts);
    if let Decision::Refuse {
        detail,
        retry_after,
    } = state.rate_limiter.check(&ip_key).await
    {
        return super::auth::too_many(detail, retry_after);
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ticket = payload
        .get("ticket")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(pending) = take(&format!("login:{ticket}")) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "The sign-in has expired. Enter your password again.",
        );
    };
    let user_key = RateLimiter::username_key(&pending.username);
    if let Decision::Refuse {
        detail,
        retry_after,
    } = state.rate_limiter.check(&user_key).await
    {
        return super::auth::too_many(detail, retry_after);
    }

    match verify_login(&state, &pending, &payload).await {
        Ok(user) => {
            state.rate_limiter.record_success(&ip_key).await;
            state.rate_limiter.record_success(&user_key).await;
            let lifetime = pending
                .remember
                .then_some(state.settings.remember_me_expire_minutes);
            let mut out = HeaderMap::new();
            let token = match super::auth::issue_login_session(
                &state,
                &mut out,
                secure,
                &user,
                &[],
                lifetime,
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
        Err(why) => {
            tracing::warn!(user = %pending.username, "passkey sign-in refused: {why}");
            state.rate_limiter.record_failure(&ip_key, true).await;
            state.rate_limiter.record_failure(&user_key, false).await;
            error(
                StatusCode::UNAUTHORIZED,
                "The passkey could not be verified",
            )
        }
    }
}

/// Everything a passkey sign-in has to get right, in order. The error is for
/// the log; the person is told only that it did not verify.
async fn verify_login(
    state: &AppState,
    pending: &Pending,
    payload: &Value,
) -> Result<User, String> {
    let user = state
        .db
        .users()
        .by_id(pending.user_id)
        .await
        .map_err(|e| format!("user lookup: {e}"))?
        .ok_or("the user is gone")?;
    // The same account the password was checked for, and still able to sign
    // in. The passkey itself is looked up again below: one removed since the
    // password step is not found.
    if user.username != pending.username {
        return Err("the user id now belongs to someone else".into());
    }
    if !user.is_active {
        return Err("the user is suspended".into());
    }

    let credential = payload.get("credential").cloned().unwrap_or(Value::Null);
    let id = credential
        .get("id")
        .and_then(Value::as_str)
        .ok_or("no credential id")?;
    let passkeys = state
        .db
        .passkeys()
        .for_user(user.id, &user.username)
        .await
        .map_err(|e| format!("listing passkeys: {e}"))?;
    let passkey = passkeys
        .into_iter()
        .find(|p| p.credential_id == id && p.rp_id == pending.rp_id)
        .ok_or("not one of this user's passkeys for this host")?;

    let (Some(client_data), Some(authenticator_data), Some(signature)) = (
        b64_field(&credential, &["response", "clientDataJSON"]),
        b64_field(&credential, &["response", "authenticatorData"]),
        b64_field(&credential, &["response", "signature"]),
    ) else {
        return Err("the response is incomplete".into());
    };
    let expected = webauthn::Expected {
        challenge: &pending.challenge,
        origin: &pending.origin,
        rp_id: &pending.rp_id,
    };
    let stored_count = u32::try_from(passkey.sign_count).unwrap_or(0);
    let new_count = webauthn::verify_assertion(
        &webauthn::Assertion {
            client_data_json: &client_data,
            authenticator_data: &authenticator_data,
            signature: &signature,
        },
        &passkey.public_key,
        stored_count,
        &expected,
    )
    .map_err(|e| e.to_string())?;

    // Conditional on the counter just checked: of two sign-ins racing with
    // one assertion, only one gets to record it.
    let recorded = state
        .db
        .passkeys()
        .record_use(
            passkey.id,
            passkey.sign_count,
            i64::from(new_count),
            &snpanel_db::sqlalchemy_now(),
        )
        .await
        .map_err(|e| format!("recording the use: {e}"))?;
    if !recorded {
        return Err("the passkey was used at the same moment elsewhere".into());
    }
    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(host: &str, forwarded_https: bool) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, host.parse().unwrap());
        if forwarded_https {
            h.insert("x-forwarded-proto", "https".parse().unwrap());
        }
        h
    }

    #[test]
    fn a_passkey_needs_a_hostname_and_a_secure_page() {
        assert_eq!(
            web_origin(&headers("Panel.Example.com:2222", false), true),
            Some((
                "https://panel.example.com:2222".into(),
                "panel.example.com".into()
            ))
        );
        assert_eq!(
            web_origin(&headers("panel.example.com", false), true),
            Some((
                "https://panel.example.com".into(),
                "panel.example.com".into()
            ))
        );
        // Plain HTTP only for localhost, which browsers treat as secure.
        assert_eq!(
            web_origin(&headers("localhost:8080", false), false),
            Some(("http://localhost:8080".into(), "localhost".into()))
        );
        assert_eq!(
            web_origin(&headers("panel.example.com", false), false),
            None
        );
        // An IP address is never a relying party.
        assert_eq!(web_origin(&headers("203.0.113.4:2222", false), true), None);
        assert_eq!(
            web_origin(&headers("[2001:db8::1]:2222", false), true),
            None
        );
        // Junk in the Host header.
        for junk in [
            "",
            "panel.example.com:",
            "panel.example.com:22x",
            "pa nel.com",
            ".example.com",
            "example.com.",
        ] {
            assert_eq!(web_origin(&headers(junk, false), true), None, "{junk:?}");
        }
    }

    #[test]
    fn a_challenge_is_used_once_and_not_after_its_time() {
        let pending = |created| Pending {
            user_id: 1,
            username: "alice".into(),
            challenge: [1; 32],
            origin: "https://panel.example.com".into(),
            rp_id: "panel.example.com".into(),
            remember: false,
            created,
        };
        keep("test:once".into(), pending(Instant::now()));
        assert!(take("test:once").is_some());
        assert!(take("test:once").is_none(), "used once");

        let old = Instant::now().checked_sub(CHALLENGE_TTL + Duration::from_secs(1));
        if let Some(old) = old {
            keep("test:old".into(), pending(old));
            assert!(take("test:old").is_none(), "expired");
        }

        // A second enrolment replaces the first rather than queueing.
        keep("test:again".into(), pending(Instant::now()));
        keep("test:again".into(), pending(Instant::now()));
        assert!(take("test:again").is_some());
        assert!(take("test:again").is_none());
    }
}
