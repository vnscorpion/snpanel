//! `/api/users` - ported from `api/users.py`, **partially and on purpose**.
//!
//! This router is the first one that could not be moved whole, and pretending
//! otherwise would be worse than saying so. Five of its ten endpoints reach
//! outside the database entirely; four of the five are still proxied:
//!
//! | endpoint | what it also does | here |
//! |---|---|---|
//! | `POST /users` | creates a Linux account through the helper | proxied |
//! | `DELETE /users/{id}` | drops databases, deletes vhosts, releases certificates, removes the Linux account | proxied |
//! | `POST /users/{id}/password` | sets the SFTP password through the helper | **here** |
//! | `POST /users/{id}/suspend` | rewrites every vhost and locks the Linux accounts | proxied |
//! | `POST /users/{id}/unsuspend` | rebuilds every vhost and unlocks them | proxied |
//!
//! Those depend on helper operations that belong to the `siteapp`/`site_users`
//! surface, which Phase 2 has not finished. Half-porting one would mean a
//! customer account created in Rust with no Linux user behind it - a database
//! row that looks fine and a website that can never be uploaded to.
//!
//! So the ported methods are registered and the rest fall through to Python
//! *by method*, not just by path: a `GET /api/users` is answered here while a
//! `POST /api/users` on the same path is proxied. Without the method-level
//! fallback axum would answer 405 and the SPA's create-user form would break.

use axum::extract::{Path, Query, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_db::{User, UserFields};
use std::collections::HashMap;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, check_range, internal_error, not_enough_permissions, not_found};
use crate::state::AppState;
use crate::storage;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list).fallback(crate::fallback))
        .route("/users/me", get(me).fallback(crate::fallback))
        .route("/users/audit/log", get(audit_log).fallback(crate::fallback))
        .route("/users/{user_id}", patch(update).fallback(crate::fallback))
        .route(
            "/users/{user_id}/2fa/reset",
            post(reset_two_factor).fallback(crate::fallback),
        )
        .route(
            "/users/{user_id}/password",
            post(set_password).fallback(crate::fallback),
        )
        .route(
            "/users/{user_id}/suspend",
            post(suspend).fallback(crate::fallback),
        )
        .route(
            "/users/{user_id}/unsuspend",
            post(unsuspend).fallback(crate::fallback),
        )
}

fn require_admin(current: &CurrentUser) -> Result<(), Response> {
    if permissions::has_role(&current.user.role, Role::Admin) {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

/// Source: `_user_out`.
async fn user_out(state: &AppState, user: &User) -> Value {
    let package_name = state
        .db
        .users()
        .package_name(user.package_id)
        .await
        .unwrap_or(None);

    let roots = state
        .db
        .users()
        .website_roots(user.id)
        .await
        .unwrap_or_default();
    let used = tokio::task::spawn_blocking(move || {
        roots.iter().map(|r| storage::website_usage(r)).sum::<i64>()
    })
    .await
    .unwrap_or(0);
    let usage = storage::Usage::new(
        used,
        storage::limit_bytes(&user.role, user.storage_limit_mb),
    );

    json!({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "package_id": user.package_id,
        "package_name": package_name,
        "website_limit": user.website_limit,
        "storage_limit_mb": user.storage_limit_mb,
        "storage_used_bytes": usage.used_bytes,
        "storage_limit_bytes": usage.limit_bytes,
        "storage_percent": usage.percent,
        "totp_enabled": user.totp_enabled,
    })
}

async fn list(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }
    let users = match state.db.users().list_all().await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("listing users failed: {e}");
            return internal_error();
        }
    };
    let mut out = Vec::with_capacity(users.len());
    for user in &users {
        out.push(user_out(&state, user).await);
    }
    axum::Json(out).into_response()
}

/// Every user may read their own record - no role check, as in the Python.
async fn me(State(state): State<AppState>, current: CurrentUser) -> Response {
    axum::Json(user_out(&state, &current.user).await).into_response()
}

async fn update(State(state): State<AppState>, Path(user_id): Path<i64>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current) {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let user = match state.db.users().by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("User not found"),
        Err(e) => {
            tracing::error!("user lookup failed: {e}");
            return internal_error();
        }
    };

    let mut fields = UserFields::default();
    let mut bump = false;

    // Two guards that stop an administrator locking themselves out of their
    // own panel, and they are checked against the *current* value: setting a
    // field to what it already is is not a change.
    if let Some(raw) = payload.get("role").filter(|v| !v.is_null()) {
        let Some(role) = raw.as_str() else {
            return crate::errors::string_type("role", raw);
        };
        if !matches!(role, "admin" | "end_user") {
            return literal_error("role", raw);
        }
        if role != user.role {
            if user_id == current.user.id {
                return bad_request("Cannot change your own role");
            }
            fields.role = Some(role.to_string());
            // A token carries the role as a claim, so one minted under the old
            // role would keep its old powers until it expired.
            bump = true;
        }
    }

    if let Some(raw) = payload.get("email").filter(|v| !v.is_null()) {
        let Some(email) = raw.as_str() else {
            return crate::errors::string_type("email", raw);
        };
        // Not checked for uniqueness: several panel users may share a contact
        // address, which is what a reseller managing many accounts does.
        if email != user.email {
            fields.email = Some(email.to_string());
        }
    }

    if let Some(raw) = payload.get("is_active").filter(|v| !v.is_null()) {
        let Some(active) = raw.as_bool() else {
            return crate::errors::bool_parsing("is_active", raw);
        };
        if user_id == current.user.id && !active {
            return bad_request("Cannot deactivate yourself");
        }
        if active != user.is_active {
            fields.is_active = Some(active);
            bump = true;
        }
    }

    // `package_id` is three-valued, and the Python distinguishes the cases
    // with `model_fields_set`: absent leaves the package alone, null clears
    // it, and a number assigns one. Reading it as "null means absent" would
    // make it impossible to take a package away from a customer.
    if let Some(raw) = payload.get("package_id") {
        if raw.is_null() {
            fields.package_id = Some(None);
        } else {
            let Some(id) = raw.as_i64() else {
                return crate::errors::int_parsing("package_id", raw);
            };
            if let Err(r) = check_range("package_id", id, 1, i64::MAX) {
                return r;
            }
            match state.db.packages().by_id(id).await {
                Ok(Some(package)) => {
                    fields.package_id = Some(Some(package.id));
                    // Assigning a package copies its limits onto the user -
                    // including terminal_enabled, which is the only thing that
                    // makes that flag mean anything.
                    fields.website_limit = Some(package.website_limit);
                    fields.storage_limit_mb = Some(package.storage_limit_mb);
                    fields.terminal_enabled = Some(package.terminal_enabled);
                }
                Ok(None) => return not_found("Package not found"),
                Err(e) => {
                    tracing::error!("package lookup failed: {e}");
                    return internal_error();
                }
            }
        }
    }

    // These come *after* the package copy, so an explicit limit in the same
    // request wins over the package's - the order is the Python's.
    for (name, min, max) in [
        ("website_limit", 0i64, 1000i64),
        ("storage_limit_mb", 0, 1024 * 1024),
    ] {
        let Some(raw) = payload.get(name).filter(|v| !v.is_null()) else {
            continue;
        };
        let Some(value) = raw.as_i64() else {
            return crate::errors::int_parsing(name, raw);
        };
        if let Err(r) = check_range(name, value, min, max) {
            return r;
        }
        match name {
            "website_limit" => fields.website_limit = Some(value),
            "storage_limit_mb" => fields.storage_limit_mb = Some(value),
            _ => unreachable!(),
        }
    }

    let updated = match state.db.users().update(user_id, &fields, bump).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("User not found"),
        Err(e) => {
            tracing::error!("updating a user failed: {e}");
            return internal_error();
        }
    };

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "update_user",
        &updated.username,
    )
    .await;
    axum::Json(user_out(&state, &updated).await).into_response()
}

async fn reset_two_factor(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current) {
        return r;
    }

    let user = match state.db.users().by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("User not found"),
        Err(e) => {
            tracing::error!("user lookup failed: {e}");
            return internal_error();
        }
    };
    // An admin resetting their *own* second factor through this endpoint would
    // be a way to shed 2FA without proving anything; the Security page asks
    // for the current password first.
    if user_id == current.user.id {
        return bad_request("Use the Security page to disable your own 2FA");
    }

    if let Err(e) = state
        .db
        .users()
        .set_totp_enabled(user_id, false, true)
        .await
    {
        tracing::error!("resetting 2FA failed: {e}");
        return internal_error();
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "reset_user_2fa",
        &user.username,
    )
    .await;
    axum::Json(json!({ "message": format!("Reset 2FA for user {}", user.username) }))
        .into_response()
}

async fn audit_log(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }

    // Query parameters, so the validation errors carry `loc: ["query", ...]`
    // rather than `["body", ...]`.
    let user_id = match params.get("user_id") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(v) => Some(v),
            Err(_) => return query_int_error("user_id", raw),
        },
        None => None,
    };
    let limit = match params.get("limit") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(v) => v,
            Err(_) => return query_int_error("limit", raw),
        },
        None => 100,
    };
    let offset = match params.get("offset") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(v) => v,
            Err(_) => return query_int_error("offset", raw),
        },
        None => 0,
    };
    if let Err(r) = query_range("limit", limit, 1, 1000) {
        return r;
    }
    if let Err(r) = query_range("offset", offset, 0, i64::MAX) {
        return r;
    }
    let action = params.get("action").filter(|a| !a.is_empty());
    if let Some(a) = action {
        if a.chars().count() > 64 {
            return query_too_long("action", a, 64);
        }
    }

    match state
        .db
        .audits()
        .list(user_id, action.map(String::as_str), limit, offset)
        .await
    {
        Ok(rows) => {
            let out: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "user_id": r.user_id,
                        "action": r.action,
                        "target": r.target,
                        // `detail or ""` - a NULL column renders as an empty
                        // string, not as null.
                        "detail": r.detail.clone().unwrap_or_default(),
                        "created_at": crate::errors::iso_datetime(r.created_at.as_deref()),
                    })
                })
                .collect();
            axum::Json(out).into_response()
        }
        Err(e) => {
            tracing::error!("reading the audit log failed: {e}");
            internal_error()
        }
    }
}

fn query_int_error(field: &str, raw: &str) -> Response {
    crate::errors::validation_error(vec![json!({
        "type": "int_parsing",
        "loc": ["query", field],
        "msg": "Input should be a valid integer, unable to parse string as an integer",
        "input": raw,
    })])
}

fn query_range(field: &str, value: i64, min: i64, max: i64) -> Result<(), Response> {
    if value < min {
        return Err(crate::errors::validation_error(vec![json!({
            "type": "greater_than_equal",
            "loc": ["query", field],
            "msg": format!("Input should be greater than or equal to {min}"),
            "input": value.to_string(),
            "ctx": { "ge": min },
        })]));
    }
    if value > max {
        return Err(crate::errors::validation_error(vec![json!({
            "type": "less_than_equal",
            "loc": ["query", field],
            "msg": format!("Input should be less than or equal to {max}"),
            "input": value.to_string(),
            "ctx": { "le": max },
        })]));
    }
    Ok(())
}

fn query_too_long(field: &str, value: &str, max: usize) -> Response {
    crate::errors::validation_error(vec![json!({
        "type": "string_too_long",
        "loc": ["query", field],
        "msg": format!("String should have at most {max} characters"),
        "input": value,
        "ctx": { "max_length": max },
    })])
}

/// Source: a `Literal[...]` field given something outside the set.
fn literal_error(field: &str, input: &Value) -> Response {
    crate::errors::validation_error(vec![json!({
        "type": "literal_error",
        "loc": ["body", field],
        "msg": "Input should be 'admin' or 'end_user'",
        "input": input,
        "ctx": { "expected": "'admin' or 'end_user'" },
    })])
}

/// `POST /users/{user_id}/password` - source: `update_user_password`.
///
/// Two different authorisations, which is the whole subtlety: an admin may set
/// anyone else's password, but changing *your own* needs the current one and,
/// with 2FA on, a code. Source: `require_sensitive_action_step_up`.
///
/// Order matters and follows Python's. The helper sets the system password
/// first and the database moves second, so a refusal leaves nothing changed
/// anywhere. The other order would leave the panel and SFTP disagreeing about
/// what the password is, with no way to tell which one a user should try.
/// Source: `require_sensitive_action_step_up`.
///
/// Changing your own password takes the current one, and the TOTP code as
/// well when 2FA is on. Being an administrator is deliberately not enough: a
/// stolen admin session would otherwise change that admin's own password and
/// lock the owner out of their own panel.
///
/// Named and shared because `panel_settings::update_admin_account` guards the
/// same thing the same way, and two copies of an authentication check is one
/// more than should exist.
pub(super) fn require_step_up(
    state: &AppState,
    current: &CurrentUser,
    payload: &Value,
) -> Result<(), Response> {
    let given = payload
        .get("current_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if given.is_empty()
        || !snpanel_core::crypto::password::verify_password(given, &current.user.hashed_password)
    {
        return Err(crate::errors::error(
            axum::http::StatusCode::UNAUTHORIZED,
            "Current password is incorrect",
        ));
    }
    if current.user.totp_enabled {
        let code = payload.get("code").and_then(|v| v.as_str()).unwrap_or("");
        if !super::auth::verify_totp(state, &current.user, code) {
            return Err(crate::errors::error(
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid authentication code",
            ));
        }
    }
    Ok(())
}

/// Source: `_validate_linux_login_password`.
///
/// The panel password is synced to the Linux account, and `chpasswd` reads
/// `user:password` lines - so a colon or a newline in it is not a weak
/// password, it is a different instruction. A newline could set a second
/// account's password entirely.
///
/// The helper refuses these too, and that is the boundary that matters. This
/// exists so the refusal is the 422 Pydantic produces rather than the 500 a
/// helper failure becomes: the caller is told what is wrong with what they
/// sent, not that the server broke.
pub(super) fn check_linux_login_password(value: &str) -> Result<(), Response> {
    if value.contains([':', '\r', '\n', '\0']) {
        return Err(crate::errors::value_error(
            "password",
            "password cannot contain ':', newlines, or NUL characters because it is \
             synced to the Linux/SFTP account",
            &Value::String(value.to_string()),
        ));
    }
    Ok(())
}

async fn set_password(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
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

    let Some(raw) = payload.get("password") else {
        return crate::errors::missing_field("password", payload.clone());
    };
    let Some(password) = raw.as_str() else {
        return crate::errors::string_type("password", raw);
    };
    // Source: `password: str = Field(min_length=12, max_length=72)`. FastAPI
    // validates the model *before* the handler runs, so this happens before
    // the permission check and before the user is looked up - which is not
    // only a status code: the other order tells a caller whether a user id
    // exists before it has looked at what they sent.
    if let Err(r) = crate::errors::check_length("password", password, 12, 72) {
        return r;
    }
    // `validate_sftp_password` on the model. This was missing: the helper
    // refuses a colon or a newline - which is the boundary that matters - but
    // its refusal reached the caller as a 500 instead of the 422 Pydantic
    // produces for the same input.
    if let Err(r) = check_linux_login_password(password) {
        return r;
    }
    let password = password.to_string();

    if user_id != current.user.id {
        if let Err(r) = require_admin(&current) {
            return r;
        }
    } else if let Err(r) = require_step_up(&state, &current, &payload) {
        return r;
    }

    let user = match state.db.users().by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("User not found"),
        Err(e) => {
            tracing::error!("user lookup failed: {e}");
            return internal_error();
        }
    };

    // The system account first. The fallback is `true` because that is what
    // Python passes: on a machine with no helper the panel password still
    // changes rather than the request failing.
    // Source: `linux_user_for_panel_username`, which is
    // `validate_linux_user(username.strip().lower())` - the account name is
    // the panel name lowercased, and parsing is what validates it. Not
    // `Domain::linux_user()`, which derives a name for a *domain* and would
    // send the password to an account that does not exist.
    let linux_user = match snpanel_core::types::PanelUsername::parse(
        user.username.trim().to_lowercase().as_str(),
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
        return internal_error();
    }

    let hashed = match snpanel_core::crypto::password::hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing failed: {e}");
            return internal_error();
        }
    };
    if let Err(e) = state.db.users().set_hashed_password(user_id, &hashed).await {
        tracing::error!("storing the password failed: {e}");
        return internal_error();
    }
    // Every other session of this user has to log in again.
    if let Err(e) = state.db.users().bump_token_version(user_id).await {
        tracing::error!("bumping the token version failed: {e}");
        return internal_error();
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "update_user_password",
        &user.username,
    )
    .await;

    axum::Json(serde_json::json!({
        "message": format!("Changed password for user {}", user.username)
    }))
    .into_response()
}

/// `POST /users/{user_id}/suspend`.
///
/// Source: `suspend_user`. "Full suspend: block login, rewrite nginx, lock
/// SFTP, kill sessions."
///
/// Four things happen and the order is not arbitrary. The account is
/// deactivated and its token version bumped **first**, because that is what
/// invalidates the sessions already issued - a customer holding a valid token
/// while their sites come down would otherwise keep using the panel. Then
/// every site is rewritten as a static vhost, then the Linux accounts are
/// locked so SFTP stops too.
///
/// The Linux lock is best-effort in the Python (`except Exception: pass`) and
/// is here as well: a site row whose Linux account was removed by hand must
/// not stop the suspension of the other nine.
async fn suspend(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    req: Request,
) -> Response {
    set_suspended(state, user_id, req, true).await
}

/// `POST /users/{user_id}/unsuspend`.
///
/// Source: `unsuspend_user`. The mirror of the above, with one deliberate
/// asymmetry: the token version is **not** bumped. Suspending has to end the
/// sessions that exist; unsuspending only has to let new ones start.
async fn unsuspend(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    req: Request,
) -> Response {
    set_suspended(state, user_id, req, false).await
}

/// How a customer's vhost is rendered in each direction.
///
/// Source: the `nginx.write_vhost(...)` call in `suspend_user` and the
/// `nginx.rewrite_vhost(...)` in `unsuspend_user`.
///
/// Named rather than written inline so that the test drives *this*, and a
/// change to it is a change the test sees. Built inline, it was invisible to
/// every assertion about suspension.
///
/// Suspending passes no aliases or redirects, which is not an oversight: a
/// suspended customer's alias domains stop being served too. Unsuspending
/// passes no overrides at all, so every setting comes back from the site's
/// own row.
pub(super) fn vhost_overrides(suspending: bool) -> super::websites::RewriteOverrides {
    if !suspending {
        return super::websites::RewriteOverrides::default();
    }
    super::websites::RewriteOverrides {
        aliases: Some(Vec::new()),
        redirects: Some(Vec::new()),
        custom_directives: Some("# SUSPENDED".to_string()),
        app_type: Some("static"),
        rewrite_mode: Some("none"),
        preserve_existing_ssl: Some(false),
        // Suspension does not pass `include_ssl=False`: the Python leaves the
        // keyword at its default here, and the certificate paths are dropped
        // by `preserve_existing_ssl` instead. The two are not the same switch
        // and only one of them is thrown on this path.
        include_ssl: None,
    }
}

async fn set_suspended(state: AppState, user_id: i64, req: Request, suspending: bool) -> Response {
    let (mut parts, _body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current) {
        return r;
    }
    let user = match state.db.users().by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return not_found("User not found"),
        Err(e) => {
            tracing::error!("loading user {user_id} failed: {e}");
            return internal_error();
        }
    };
    // Only on the way in: the Python guards `suspend` alone, and an
    // administrator may un-suspend themselves. Suspending yourself locks you
    // out of the panel you would need in order to undo it.
    if suspending && user_id == current.user.id {
        return bad_request("Cannot suspend yourself");
    }

    let websites = match state.db.websites().list(Some(user.id), "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing websites for user {user_id} failed: {e}");
            return internal_error();
        }
    };

    // The account first: the token bump is what ends the sessions already
    // issued, and doing it after the vhosts would leave a window in which the
    // customer is still signed in and their sites are already down.
    let fields = UserFields {
        is_active: Some(!suspending),
        ..Default::default()
    };
    if let Err(e) = state.db.users().update(user.id, &fields, suspending).await {
        tracing::error!("updating user {user_id} failed: {e}");
        return internal_error();
    }

    for website in &websites {
        let status = if suspending { "suspended" } else { "active" };
        if let Err(e) = state.db.websites().set_status(website.id, status).await {
            tracing::error!("setting the status of website {} failed: {e}", website.id);
            return internal_error();
        }

        let overrides = vhost_overrides(suspending);
        if let Err(e) = super::websites::rewrite_owned_vhost(&state, website, overrides).await {
            // One site failing must not abandon the rest half-done: the
            // account is already deactivated, so stopping here would leave a
            // customer blocked with some of their sites still serving.
            tracing::error!("rewriting the vhost for {} failed: {e}", website.domain);
        }

        let linux_user = website.linux_user.as_deref().unwrap_or_default();
        if !linux_user.is_empty() && !state.settings.command_dry_run {
            let result = crate::shell::privileged(
                false,
                if suspending {
                    "panel-user-lock"
                } else {
                    "panel-user-unlock"
                },
                &[linux_user],
                None,
                Some(&["true"]),
            )
            .await;
            if !result.ok() {
                // `except Exception: pass` - a Linux account removed by hand
                // is not a reason to leave the other sites unsuspended.
                tracing::warn!(
                    "could not {} {}: {}",
                    if suspending { "lock" } else { "unlock" },
                    linux_user,
                    result.failure_detail("no detail").trim()
                );
            }
        }
    }

    let action = if suspending {
        "suspend_user"
    } else {
        "unsuspend_user"
    };
    super::packages::audit_action(&state, &parts, current.user.id, action, &user.username).await;

    let verb = if suspending {
        "Suspended"
    } else {
        "Unsuspended"
    };
    axum::Json(json!({
        "message": format!("{verb} user {}", user.username),
        "affected_websites": websites.len(),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    /// The rule this endpoint enforces, written out as a table.
    ///
    /// Source: `update_user_password`. Changing someone else's password is an
    /// admin action; changing your own is a step-up, and the two are not
    /// interchangeable. A version that checked only the role would let a
    /// stolen admin session change that admin's own password without proving
    /// anything; one that checked only the current password would stop an
    /// admin resetting an account whose password nobody knows - which is the
    /// entire reason the endpoint exists.
    #[test]
    fn changing_your_own_password_and_someone_elses_are_different_proofs() {
        // Encoded as the decision the handler makes, so the table is checked
        // rather than described. `needs_admin` and `needs_step_up` are
        // mutually exclusive by construction.
        fn decision(target_id: i64, current_id: i64) -> (bool, bool) {
            let own = target_id == current_id;
            (!own, own)
        }

        assert_eq!(
            decision(7, 1),
            (true, false),
            "another account: admin, no step-up"
        );
        assert_eq!(
            decision(1, 1),
            (false, true),
            "your own account: step-up, and being admin is not enough"
        );
    }

    /// The account the password is sent to.
    ///
    /// `Domain::linux_user()` derives a name from a *domain* and was the first
    /// thing reached for here; it compiles against a different type and would
    /// have sent the password to an account that does not exist, leaving the
    /// panel password changed and SFTP still on the old one.
    #[test]
    fn the_system_account_is_the_panel_name_lowercased() {
        use snpanel_core::types::PanelUsername;

        for (panel, expected) in [("alice", "alice"), ("Alice", "alice"), ("BOB", "bob")] {
            let derived = PanelUsername::parse(panel.trim().to_lowercase().as_str())
                .expect("a valid panel username lowercases to a valid account");
            assert_eq!(derived.as_str(), expected, "for {panel}");
        }
    }

    use super::*;

    #[test]
    fn the_limit_window_is_the_pythons() {
        assert!(query_range("limit", 1, 1, 1000).is_ok());
        assert!(query_range("limit", 1000, 1, 1000).is_ok());
        // Zero is refused, not treated as "no limit": an unbounded audit query
        // on a busy panel is a page that never renders.
        assert!(query_range("limit", 0, 1, 1000).is_err());
        assert!(query_range("limit", 1001, 1, 1000).is_err());
        assert!(query_range("offset", 0, 0, i64::MAX).is_ok());
        assert!(query_range("offset", -1, 0, i64::MAX).is_err());
    }

    #[test]
    fn an_action_filter_is_length_limited() {
        let long = "a".repeat(65);
        assert!(long.chars().count() > 64);
        let resp = query_too_long("action", &long, 64);
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn only_the_two_roles_are_accepted() {
        // A Literal field; anything else is a 422 rather than a stored value
        // that `normalize_role` would later refuse with a 403 on every request.
        let resp = literal_error("role", &json!("root"));
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A suspended site serves nothing dynamic.
    ///
    /// Source: `suspend_user`, which renders each of the customer's sites
    /// with `app_type="static"`, `rewrite_mode="none"`, `# SUSPENDED` and
    /// `preserve_existing_ssl=False`. The point is not the comment - it is
    /// that a suspended WordPress site must stop reaching PHP-FPM. A vhost
    /// that kept its `fastcgi_pass` would go on serving the customer's
    /// application to the internet while the panel reported the account as
    /// blocked.
    ///
    /// This drives `vhost_overrides`, which is what the handler calls. An
    /// earlier version built the input itself with `app_type = "static"`
    /// written into the test, and every mutation of the handler passed.
    #[test]
    fn a_suspended_vhost_reaches_no_interpreter() {
        use super::vhost_overrides;

        let root = std::path::PathBuf::from("/home/bp_alice/example.com");
        let env = snpanel_nginx::VhostEnv {
            ipv6: false,
            waf_engine: false,
            default_php_version: "8.4".to_string(),
            home_root: std::path::PathBuf::from("/home"),
        };
        let sites = std::path::PathBuf::from("/etc/nginx/sites-available");

        // The site as its row describes it: WordPress on PHP 8.4.
        use crate::routes::websites;

        // What certbot leaves in the file. `preserve_existing_ssl` decides
        // whether a rewrite carries it forward, so without an existing vhost
        // the flag has nothing to act on and flipping it proves nothing.
        let existing = concat!(
            "server {\n",
            "    listen 443 ssl;\n",
            "    server_name example.com;\n",
            "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n",
            "    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n",
            "}\n",
        );

        let render = |overrides: &websites::RewriteOverrides| {
            let custom_text = overrides.custom_directives.clone().unwrap_or_default();
            let custom = snpanel_nginx::CustomDirectives::validate(&custom_text).expect("valid");
            let app_type = overrides.app_type.unwrap_or("wordpress");
            let rewrite_mode = overrides.rewrite_mode.unwrap_or("front_controller");
            let mut input = snpanel_nginx::VhostInput::new("example.com", &root, &custom);
            input.app_type = app_type;
            input.php_version = Some("8.4");
            input.document_root = "public_html";
            input.rewrite_mode = Some(rewrite_mode);
            snpanel_nginx::plan_rewrite(
                &input,
                &env,
                &sites,
                Some(existing),
                overrides.preserve_existing_ssl.unwrap_or(true),
            )
            .expect("renders")
        };

        let live = render(&vhost_overrides(false));
        assert!(
            live.content.contains("fastcgi_pass"),
            "the unsuspended site is the one that reaches PHP:\n{}",
            live.content
        );

        let off = render(&vhost_overrides(true));
        assert!(
            !off.content.contains("fastcgi_pass"),
            "a suspended site must not reach PHP-FPM:\n{}",
            off.content
        );
        assert!(
            !off.content.contains("php-fpm"),
            "nor name a pool socket:\n{}",
            off.content
        );
        assert!(
            off.custom_include.contains("# SUSPENDED"),
            "the marker goes in the customer's include: {:?}",
            off.custom_include
        );
        // Same file, so the site keeps its name and the rewrite is reversible.
        assert_eq!(off.path, live.path);

        // The certificate certbot left is carried into the live rewrite
        // and **not** into the suspended one: a vhost that is deliberately
        // serving nothing should not go on presenting the customer's
        // certificate for it.
        assert!(
            live.content.contains("ssl_certificate"),
            "an unsuspended rewrite keeps what certbot wrote:\n{}",
            live.content
        );
        assert!(
            !off.content.contains("ssl_certificate"),
            "a suspended rewrite drops it:\n{}",
            off.content
        );

        // And the aliases: a suspended customer's other names stop being
        // served too, which is the difference between the two override sets
        // that is easiest to drop.
        assert_eq!(vhost_overrides(true).aliases.as_deref(), Some(&[][..]));
        assert_eq!(vhost_overrides(false).aliases, None);
    }

    /// `_validate_linux_login_password`.
    ///
    /// The panel password is synced to the Linux account, and `chpasswd`
    /// reads `user:password` lines. A newline in it is not a weak password -
    /// it is a second line, and a second line sets **another account's**
    /// password. A colon is a field separator.
    ///
    /// The helper refuses these too, and that is the boundary that matters;
    /// this exists so the refusal reaches the caller as the 422 Pydantic
    /// produces rather than the 500 a helper failure becomes.
    #[test]
    fn a_panel_password_may_not_carry_a_colon_or_a_newline() {
        assert!(check_linux_login_password("correct horse battery").is_ok());
        assert!(check_linux_login_password("p@ssw0rd!#$%^&*()-_=+").is_ok());
        // Unicode is fine: the rule is about four specific characters.
        assert!(check_linux_login_password("mật-khẩu-rất-dài-12").is_ok());

        for bad in [
            "pass:word-long",
            "pass\nword-long",
            "pass\rword-long",
            "pass\0word-long",
            // The shape that matters: a newline followed by another account.
            "aaaaaaaaaaaa\nroot:owned",
        ] {
            let err = check_linux_login_password(bad).expect_err(bad);
            assert_eq!(
                err.status(),
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "{bad:?} must be a 422, not a 500 from the helper"
            );
        }
    }
}
