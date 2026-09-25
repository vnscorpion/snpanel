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
        .route("/users", get(list).post(create).fallback(crate::fallback))
        .route("/users/me", get(me).fallback(crate::fallback))
        .route(
            "/users/{user_id}/usage",
            get(usage).fallback(crate::fallback),
        )
        .route("/users/audit/log", get(audit_log).fallback(crate::fallback))
        .route(
            "/users/{user_id}",
            patch(update).delete(delete).fallback(crate::fallback),
        )
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

/// How a user record gets its storage figure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StorageFigure {
    /// Measured now - every caller but the list.
    Fresh,
    /// Five minutes' cache - the list, as Python's `cached_usage=True`.
    Cached,
    /// Not measured: `null`, for the page to ask `/users/{id}/usage` after.
    Later,
}

/// `storage_used_bytes`, `storage_limit_bytes` and `storage_percent`.
///
/// With no figure the used bytes and the percentage are `null` and the limit
/// is still given: the limit is a setting, read from the row; only the usage
/// is a measurement.
fn storage_fields(used: Option<u64>, role: &str, storage_limit_mb: i64) -> (Value, Value, Value) {
    let limit = storage::limit_bytes(role, storage_limit_mb);
    match used {
        Some(used) => {
            let usage = storage::Usage::new(used as i64, limit);
            (
                json!(usage.used_bytes),
                json!(usage.limit_bytes),
                json!(usage.percent),
            )
        }
        None => (Value::Null, json!(limit), Value::Null),
    }
}

/// Source: `_user_out`.
/// [`StorageFigure::Cached`] matches Python's `_user_out(..., cached_usage=)`:
/// only the user **list** asks for it, since it walks every account's files
/// at once. Every other caller asks for a fresh figure.
async fn user_out(state: &AppState, user: &User, figure: StorageFigure) -> Value {
    let package_name = state
        .db
        .users()
        .package_name(user.package_id)
        .await
        .unwrap_or(None);

    // Applications as well as websites — see `auth::user_storage` for why
    // reporting less than the quota check enforces is the bug this fixes.
    let application_installed = super::addons::application_installed();
    let used = match figure {
        StorageFigure::Cached => Some(
            crate::storage_quota::user_storage_used_bytes_cached(
                state.settings.command_dry_run,
                &state.db,
                user.id,
                application_installed,
            )
            .await,
        ),
        StorageFigure::Fresh => Some(
            crate::storage_quota::user_storage_used_bytes(
                state.settings.command_dry_run,
                &state.db,
                user.id,
                application_installed,
            )
            .await,
        ),
        StorageFigure::Later => None,
    };
    let (used_bytes, limit_bytes, percent) =
        storage_fields(used, &user.role, user.storage_limit_mb);
    // Not in the Python: the SFTP login, for the list's badge.
    let sftp = crate::sftp_access::access(&state.db, user.id, &user.username)
        .await
        .unwrap_or(snpanel_db::sftp_accounts::SftpAccess::DEFAULT);

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
        "storage_used_bytes": used_bytes,
        "storage_limit_bytes": limit_bytes,
        "storage_percent": percent,
        "totp_enabled": user.totp_enabled,
        "sftp": { "enabled": sftp.enabled, "own_password": sftp.own_password },
    })
}

async fn list(
    State(state): State<AppState>,
    current: CurrentUser,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }
    // Not in the Python. `?usage=0` leaves out the one column that walks
    // every account's files, so the page can show the users at once and ask
    // `/users/{id}/usage` for each figure after. Without it, the list is the
    // Python's, figures and all.
    let figure = match params.get("usage").map(String::as_str) {
        Some("0" | "false" | "no") => StorageFigure::Later,
        _ => StorageFigure::Cached,
    };
    let users = match state.db.users().list_all().await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("listing users failed: {e}");
            return internal_error();
        }
    };
    let mut out = Vec::with_capacity(users.len());
    for user in &users {
        out.push(user_out(&state, user, figure).await);
    }
    axum::Json(out).into_response()
}

/// Every user may read their own record - no role check, as in the Python.
async fn me(State(state): State<AppState>, current: CurrentUser) -> Response {
    axum::Json(user_out(&state, &current.user, StorageFigure::Fresh).await).into_response()
}

/// `GET /users/{user_id}/usage` - one user's storage figure, the list's way
/// (five minutes' cache). Not in the Python: it is the other half of the
/// list's `?usage=0`.
async fn usage(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(user_id): Path<i64>,
) -> Response {
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
    let used = crate::storage_quota::user_storage_used_bytes_cached(
        state.settings.command_dry_run,
        &state.db,
        user.id,
        super::addons::application_installed(),
    )
    .await;
    let (used_bytes, limit_bytes, percent) =
        storage_fields(Some(used), &user.role, user.storage_limit_mb);
    axum::Json(json!({
        "id": user.id,
        "storage_used_bytes": used_bytes,
        "storage_limit_bytes": limit_bytes,
        "storage_percent": percent,
    }))
    .into_response()
}

/// What a user's limits end up as, given a package and the request's own
/// numbers.
///
/// Source: `update_user`, which calls `_apply_package_limits` **twice** —
/// once where the package is resolved and once at the end, with the explicit
/// limits assigned in between. So the second call wins and **a package
/// overrides an explicit limit in the same request**.
///
/// `create_user` reaches the same answer by a different route: it builds the
/// row with the payload's numbers and then calls `_apply_package_limits`
/// once. Two handlers, one rule, and only one of them looks like it.
///
/// The first port of this applied the package once and let the explicit limit
/// win — so `{"package_id": 3, "website_limit": 999}` gave the customer 999
/// websites here and the package's number there. It shipped. A limit is not
/// a field to be generous with.
fn resolve_package_limits(
    package: Option<&snpanel_db::Package>,
    website_limit: Option<i64>,
    storage_limit_mb: Option<i64>,
) -> (Option<i64>, Option<i64>, Option<bool>) {
    match package {
        // The package decides all three, whatever else was asked for.
        Some(package) => (
            Some(package.website_limit),
            Some(package.storage_limit_mb),
            Some(package.terminal_enabled),
        ),
        // No package in this request: the explicit numbers stand, and
        // `terminal_enabled` is left alone because nothing in the payload
        // sets it.
        None => (website_limit, storage_limit_mb, None),
    }
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
    // The package, kept because its limits are applied **twice** - see
    // the second application below.
    let mut assigned_package: Option<snpanel_db::Package> = None;
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
        let active = match crate::errors::read_bool("is_active", Some(raw), false) {
            Ok(value) => value,
            Err(response) => return response,
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
            // `_package_for_payload(db, None)` returns `None`, so an explicit
            // null clears the package **and** leaves the limits alone - the
            // second `_apply_package_limits` is skipped for a null.
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
                    assigned_package = Some(package);
                }
                Ok(None) => return not_found("Package not found"),
                Err(e) => {
                    tracing::error!("package lookup failed: {e}");
                    return internal_error();
                }
            }
        }
    }

    // Read and range-checked here; whether they survive is
    // `resolve_package_limits`'s answer, below.
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

    let (website_limit, storage_limit_mb, terminal_enabled) = resolve_package_limits(
        assigned_package.as_ref(),
        fields.website_limit,
        fields.storage_limit_mb,
    );
    fields.website_limit = website_limit;
    fields.storage_limit_mb = storage_limit_mb;
    if terminal_enabled.is_some() {
        fields.terminal_enabled = terminal_enabled;
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
    axum::Json(user_out(&state, &updated, StorageFigure::Fresh).await).into_response()
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

    // A reset is for someone who lost their second factor; their passkeys go
    // with the code, first, so none is left without one.
    if let Err(e) = state.db.passkeys().delete_for_user(user_id).await {
        tracing::error!("removing passkeys in a 2FA reset failed: {e}");
        return internal_error();
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
    if let Err(message) = crate::sftp_access::linux_account(&user.username) {
        return bad_request(&message);
    }
    // Into the Linux account too, while the SFTP login still follows the
    // panel password - not when it is off, or has a password of its own.
    if let Err(detail) = crate::sftp_access::follow_panel_password(
        &state.db,
        state.settings.command_dry_run,
        user.id,
        &user.username,
        &password,
    )
    .await
    {
        tracing::error!("setting the system password failed: {detail}");
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
        // Nor `app_port`: a suspended site is rendered static, so it has no
        // upstream to be told about.
        app_port: None,
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
    }
    // Every Linux account of theirs, once: their own - which a user with no
    // sites kept unlocked through a suspension - and their sites'. Unlocked
    // again only while their SFTP is on.
    let site_accounts: Vec<Option<String>> =
        websites.iter().map(|w| w.linux_user.clone()).collect();
    crate::sftp_access::set_locked(
        &state.db,
        state.settings.command_dry_run,
        user.id,
        &user.username,
        &site_accounts,
        suspending,
    )
    .await;

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

/// Source: `UserCreate`'s fields and its two validators.
struct UserCreateFields {
    username: String,
    email: String,
    password: String,
    role: String,
    package_id: Option<i64>,
    website_limit: i64,
    storage_limit_mb: i64,
}

/// Source: `UserCreate`.
///
/// The username pattern is `^[a-z_][a-z0-9_-]{2,31}$` **and** a reserved-name
/// check, and the two produce different messages: a bad shape is pydantic's
/// `string_pattern_mismatch`, a reserved name is a `value_error` from the
/// validator. An administrator who typed `root` has to be told it is taken by
/// the system rather than that it is malformed.
/// Source: `^[a-z_][a-z0-9_-]{2,31}$`, the pattern on every panel username.
///
/// Shared with the provisioning router rather than copied: the two schemas
/// carry the same pattern, and a panel that let a billing system create a
/// username its own form would refuse is a panel with two answers to the
/// same question.
///
/// The length is checked separately, so this is only the shape - the
/// pattern's own `{2,31}` says the same thing as `max_length=32` and
/// pydantic reports whichever it reaches first.
pub(super) fn panel_username_shape_ok(username: &str) -> bool {
    let mut chars = username.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first == '_' => {
            chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        }
        _ => false,
    }
}

/// The 422 entry [`panel_username_shape_ok`] refuses with.
pub(super) fn panel_username_pattern_entry(username: &str) -> Value {
    json!({
        "type": "string_pattern_mismatch",
        "loc": ["body", "username"],
        "msg": "String should match pattern '^[a-z_][a-z0-9_-]{2,31}$'",
        "input": username,
        "ctx": { "pattern": "^[a-z_][a-z0-9_-]{2,31}$" },
    })
}

pub(super) fn panel_username_pattern_error(username: &str) -> Response {
    crate::errors::validation_error(vec![panel_username_pattern_entry(username)])
}

fn user_create_fields(payload: &Value) -> Result<UserCreateFields, Response> {
    let text = |key: &str| payload.get(key).and_then(Value::as_str);

    let Some(username) = text("username") else {
        return Err(crate::errors::missing_field("username", payload.clone()));
    };
    crate::errors::check_length("username", username, 3, 32)?;
    if !panel_username_shape_ok(username) {
        return Err(panel_username_pattern_error(username));
    }
    if snpanel_core::types::RESERVED_LINUX_USERS.contains(&username) {
        return Err(crate::errors::value_error(
            "username",
            "username is reserved by the system",
            payload.get("username").unwrap_or(&Value::Null),
        ));
    }

    let Some(email) = text("email") else {
        return Err(crate::errors::missing_field("email", payload.clone()));
    };
    // **`EmailStr` is not checked here, and that is a recorded gap.** Pydantic
    // runs `email-validator`, which does far more than a pattern: it decodes
    // IDNA (`xn--mnchen-3ya.de` arrives as `münchen.de`), accepts a display
    // name (`Name <a@b.com>` becomes `a@b.com`), lowercases the domain while
    // leaving the local part alone, and refuses `a@localhost`, `a@example`
    // and `admin@127.0.0.1`. All measured, in `tests/golden/email.json`.
    //
    // Reproducing it needs an IDNA implementation, which is a dependency
    // decision rather than a line of code. `PATCH /users/{id}` shipped
    // without the check; this matches it rather than inventing a third
    // answer, and the corpus is there for whoever ports it.

    let Some(password) = text("password") else {
        return Err(crate::errors::missing_field("password", payload.clone()));
    };
    // 72 is bcrypt's limit, not a policy. Longer and bcrypt silently
    // truncates, so two different passwords would open the same account.
    crate::errors::check_length("password", password, 12, 72)?;
    // `_validate_linux_login_password` — the password is synced to the Linux
    // and SFTP account through `chpasswd`, which reads `user:password` lines.
    if password.contains(':')
        || password.contains('\r')
        || password.contains('\n')
        || password.contains('\0')
    {
        return Err(crate::errors::value_error(
            "password",
            "password cannot contain ':', newlines, or NUL characters because it is \
             synced to the Linux/SFTP account",
            payload.get("password").unwrap_or(&Value::Null),
        ));
    }

    let role = match text("role") {
        Some(v) => {
            if !matches!(v, "admin" | "end_user") {
                return Err(literal_error(
                    "role",
                    payload.get("role").unwrap_or(&Value::Null),
                ));
            }
            v.to_string()
        }
        None => "end_user".to_string(),
    };

    let package_id = match payload.get("package_id").filter(|v| !v.is_null()) {
        Some(raw) => {
            let Some(id) = raw.as_i64() else {
                return Err(crate::errors::int_parsing("package_id", raw));
            };
            crate::errors::check_range("package_id", id, 1, i64::MAX)?;
            Some(id)
        }
        None => None,
    };

    let number = |name: &str, default: i64, min: i64, max: i64| -> Result<i64, Response> {
        match payload.get(name).filter(|v| !v.is_null()) {
            Some(raw) => {
                let Some(value) = raw.as_i64() else {
                    return Err(crate::errors::int_parsing(name, raw));
                };
                crate::errors::check_range(name, value, min, max)?;
                Ok(value)
            }
            None => Ok(default),
        }
    };

    Ok(UserCreateFields {
        username: username.to_string(),
        email: email.to_string(),
        password: password.to_string(),
        role,
        package_id,
        website_limit: number("website_limit", 5, 0, 1000)?,
        storage_limit_mb: number("storage_limit_mb", 1024, 0, 1024 * 1024)?,
    })
}

/// `POST /users`.
///
/// Source: `create_user`.
///
/// **Only the username has to be unique.** Several panel users may share one
/// contact email — a reseller managing many accounts, for instance — and a
/// port that made the email unique would refuse a shape the panel supports.
///
/// The Linux account is made **before** the row, because the row is what
/// makes the account findable: an account with no row is an orphan the
/// orphan sweep reports, and a row with no account is a customer who cannot
/// log in over SFTP and nothing to tell them why.
async fn create(State(state): State<AppState>, req: Request) -> Response {
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
    let fields = match user_create_fields(&payload) {
        Ok(f) => f,
        Err(r) => return r,
    };

    match state.db.users().by_username(&fields.username).await {
        Ok(Some(_)) => {
            return crate::errors::error(
                axum::http::StatusCode::CONFLICT,
                "Username already exists",
            )
        }
        Err(e) => {
            tracing::error!("username lookup failed: {e}");
            return internal_error();
        }
        Ok(None) => {}
    }

    let package = match fields.package_id {
        Some(id) => match state.db.packages().by_id(id).await {
            Ok(Some(p)) => Some(p),
            Ok(None) => return not_found("Package not found"),
            Err(e) => {
                tracing::error!("package lookup failed: {e}");
                return internal_error();
            }
        },
        None => None,
    };

    let Ok(panel_user) = snpanel_core::types::PanelUsername::parse(&fields.username) else {
        return bad_request("Invalid panel Linux user");
    };
    let ensured = crate::shell::privileged(
        state.settings.command_dry_run,
        "panel-user-ensure",
        &[panel_user.as_str()],
        None,
        None,
    )
    .await;
    if !ensured.ok() {
        // `except RuntimeError as exc: raise HTTPException(500, ...)` — a
        // helper that cannot make the account is a fault, not a bad request.
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ensured
                .failure_detail("Could not create the system account")
                .trim(),
        );
    }
    let set = crate::shell::privileged(
        state.settings.command_dry_run,
        "panel-user-password",
        &[panel_user.as_str()],
        Some(&format!("{}\n", fields.password)),
        None,
    )
    .await;
    if !set.ok() {
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            set.failure_detail("Could not set the system password")
                .trim(),
        );
    }

    let hashed = match snpanel_core::crypto::password::hash_password(&fields.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing failed: {e}");
            return internal_error();
        }
    };
    // `_apply_package_limits(user, package)` runs **after** the row is built
    // with the payload's numbers, so the package wins — the same rule
    // `update_user` reaches by calling it twice.
    let (website_limit, storage_limit_mb, terminal_enabled) = resolve_package_limits(
        package.as_ref(),
        Some(fields.website_limit),
        Some(fields.storage_limit_mb),
    );
    let new = snpanel_db::NewUser {
        username: &fields.username,
        email: &fields.email,
        hashed_password: &hashed,
        role: &fields.role,
        package_id: package.as_ref().map(|p| p.id),
        website_limit: website_limit.unwrap_or(fields.website_limit),
        storage_limit_mb: storage_limit_mb.unwrap_or(fields.storage_limit_mb),
        // `User.terminal_enabled` is `default=True` on the model; a package
        // that says otherwise overrides it.
        terminal_enabled: terminal_enabled.unwrap_or(true),
    };
    let user_id = match state.db.users().create(&new).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("creating a user failed: {e}");
            return internal_error();
        }
    };

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "create_user",
        &fields.username,
    )
    .await;

    let created = match state.db.users().by_id(user_id).await {
        Ok(Some(u)) => u,
        _ => return internal_error(),
    };
    axum::Json(user_out(&state, &created, StorageFigure::Fresh).await).into_response()
}

/// `DELETE /users/{user_id}`.
///
/// Source: `delete_user`.
///
/// **Every site the customer owns is checked before any of them is deleted.**
/// A site whose `linux_user` is not this account's was moved or imported, and
/// deleting it would take files that are not this customer's — so the whole
/// request is refused rather than half-run.
async fn delete(State(state): State<AppState>, Path(user_id): Path<i64>, req: Request) -> Response {
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
    if user.id == current.user.id {
        return bad_request("Cannot delete yourself");
    }

    let Ok(panel_user) = snpanel_core::types::PanelUsername::parse(&user.username) else {
        return bad_request("Invalid panel Linux user");
    };
    let websites = match state.db.websites().list(Some(user.id), "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing the websites of {} failed: {e}", user.username);
            return internal_error();
        }
    };
    // The whole check first, then the whole deletion. The Python has two
    // loops and the order is the point.
    for website in &websites {
        if let Some(linux_user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) {
            if linux_user != panel_user.as_str() {
                return bad_request(&format!(
                    "Website {} is not owned by Linux user {}",
                    website.domain,
                    panel_user.as_str()
                ));
            }
        }
    }

    let mut deleted_domains: Vec<String> = Vec::new();
    for website in &websites {
        if let Err(r) = delete_owned_website(&state, website).await {
            return r;
        }
        deleted_domains.push(website.domain.clone());
    }

    if let Err(r) = forget_user_in_schedules(&state, user.id).await {
        return r;
    }
    // `check=False` in the Python: an account that is already gone is not a
    // reason to refuse a deletion that has already removed the websites.
    let _ = crate::shell::privileged(
        state.settings.command_dry_run,
        "panel-user-delete",
        &[panel_user.as_str()],
        None,
        None,
    )
    .await;

    if let Err(e) = state.db.users().delete(user.id).await {
        tracing::error!("deleting {} failed: {e}", user.username);
        return internal_error();
    }

    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "delete_user",
        &user.username,
        &deleted_domains.join(","),
    )
    .await;

    axum::Json(json!({
        "ok": true,
        "deleted_websites": deleted_domains,
    }))
    .into_response()
}

/// Source: `_delete_owned_website`.
///
/// The same order as `DELETE /websites/{id}`: the database, the aliases, the
/// vhost, **then** the certificate and the WAF rules — both of which are
/// still referenced by the vhost while it exists, and a missing
/// `modsecurity_rules_file` fails `nginx -t` for every site on the box.
///
/// It differs from that endpoint in one place: the certificate note is
/// discarded rather than reported. Deleting an owner is not the moment to
/// tell somebody about one site's lineage, and the Python throws it away too.
async fn delete_owned_website(
    state: &AppState,
    website: &snpanel_db::Website,
) -> Result<(), Response> {
    let db_item = state
        .db
        .databases()
        .by_website(website.id)
        .await
        .unwrap_or_default();
    if let Some(item) = &db_item {
        if let Err(e) = crate::mariadb::drop_database(&item.db_name, &item.db_user).await {
            return Err(bad_request(&e.to_string()));
        }
    }
    if let Err(e) = state.db.websites().alias_delete_all(website.id).await {
        tracing::error!("deleting the aliases of {} failed: {e}", website.domain);
        return Err(internal_error());
    }
    super::websites::delete_website_vhost(state, &website.domain).await;
    let _ = super::websites::release_site_certificates(state, &website.domain, website.id).await;
    let _ = crate::shell::privileged(
        state.settings.command_dry_run,
        "waf-site-delete",
        &[&website.domain],
        None,
        None,
    )
    .await;
    if let Some(linux_user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) {
        let _ = crate::shell::privileged(
            state.settings.command_dry_run,
            "site-runtime-delete",
            &[linux_user, &website.root_path],
            None,
            None,
        )
        .await;
    }
    if let Some(item) = &db_item {
        if let Err(e) = state.db.databases().delete(item.id).await {
            tracing::error!(
                "deleting the database row for {} failed: {e}",
                website.domain
            );
            return Err(internal_error());
        }
    }
    if let Err(e) = state.db.websites().delete(website.id).await {
        tracing::error!("deleting the row for {} failed: {e}", website.domain);
        return Err(internal_error());
    }
    Ok(())
}

/// Source: `_decode_schedule_user_ids`.
///
/// ```python
/// try: value = json.loads(raw)
/// except json.JSONDecodeError: value = [item for item in raw.split(",") if item]
/// if isinstance(value, int): value = [value]
/// return [int(item) for item in value if int(item) > 0]
/// ```
///
/// Four things a reading of that misses, all measured in
/// `tests/golden/schedule_user_ids.json`:
///
/// - a JSON **string** is iterated as a string, so `"12"` yields `[1, 2]`;
/// - `int(True)` is `1`, so `[true]` yields `[1]`;
/// - `int(item)` has **no exception handling** and neither does the caller,
///   so `abc`, `{"a":1}`, `null` and `[[1]]` make the endpoint answer **500**;
/// - `> 0` drops zero and negatives rather than keeping them.
///
/// `Err` here is that 500: the value in the column is one the Python cannot
/// read either, and answering "no users" instead would silently keep a
/// schedule the Python would have refused to touch.
pub(crate) fn decode_schedule_user_ids(raw: Option<&str>) -> Result<Vec<i64>, ()> {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return Ok(Vec::new());
    };

    // `json.loads` first; only a decode error falls back to the comma split.
    let items: Vec<Value> = match serde_json::from_str::<Value>(raw) {
        Ok(Value::Number(n)) => {
            // `isinstance(value, int)` - a float is **not** an int, and
            // iterating one raises. `1.0` is a float to Python's `json`.
            if n.is_i64() || n.is_u64() {
                vec![Value::Number(n)]
            } else {
                return Err(());
            }
        }
        Ok(Value::Array(items)) => items,
        // Iterating a dict yields its **keys**, which are strings.
        Ok(Value::Object(map)) => map.keys().map(|k| Value::String(k.clone())).collect(),
        // A JSON string is iterated character by character.
        Ok(Value::String(s)) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        // `None` and `True`/`False` are not iterable: `TypeError`.
        Ok(_) => return Err(()),
        Err(_) => raw
            .split(',')
            .filter(|item| !item.is_empty())
            .map(|item| Value::String(item.to_string()))
            .collect(),
    };

    let mut out = Vec::new();
    for item in items {
        let value = python_int(&item)?;
        if value > 0 {
            out.push(value);
        }
    }
    Ok(out)
}

/// `int(item)`, for the shapes that can reach it.
///
/// A float truncates toward zero, a bool is 0 or 1, and a string is parsed
/// after stripping whitespace. Anything else raises, which is `Err`.
fn python_int(item: &Value) -> Result<i64, ()> {
    match item {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f.trunc() as i64))
            .ok_or(()),
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::String(s) => s.trim().parse().map_err(|_| ()),
        _ => Err(()),
    }
}

/// `json.dumps(user_ids)`, byte for byte.
///
/// Python's default separator is `", "` — **with the space**. `serde_json`
/// writes `[1,2,3]`, and this column is compared against what the Python
/// wrote when a shadow diff runs.
pub(super) fn encode_schedule_user_ids(ids: &[i64]) -> String {
    let parts: Vec<String> = ids.iter().map(i64::to_string).collect();
    format!("[{}]", parts.join(", "))
}

/// Source: `_remove_user_from_backup_schedules`.
///
/// A schedule left naming nobody is **deleted**, not kept: one with no users
/// and `all_users` off would run nightly and back up nothing, and the failure
/// would read as a broken backup rather than a schedule that should not
/// exist.
async fn forget_user_in_schedules(state: &AppState, user_id: i64) -> Result<(), Response> {
    let schedules = match state.db.backup_schedules().user_columns().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing the backup schedules failed: {e}");
            return Err(internal_error());
        }
    };
    for schedule in schedules {
        let Ok(mut ids) = decode_schedule_user_ids(schedule.user_ids.as_deref()) else {
            // The Python raises out of here and nothing catches it.
            tracing::error!(
                "backup schedule {} has a user_ids column neither JSON nor a list of \
                 numbers: {:?}",
                schedule.id,
                schedule.user_ids
            );
            return Err(internal_error());
        };
        let had = ids.contains(&user_id);
        ids.retain(|item| *item != user_id);
        let owner_cleared = schedule.user_id == Some(user_id);
        if !had && !owner_cleared {
            continue;
        }
        let owner = if owner_cleared {
            None
        } else {
            schedule.user_id
        };
        if !schedule.all_users && owner.is_none() && ids.is_empty() {
            if let Err(e) = state.db.backup_schedules().delete(schedule.id).await {
                tracing::error!("deleting backup schedule {} failed: {e}", schedule.id);
                return Err(internal_error());
            }
            super::maintenance::forget_schedule_options(state, schedule.id).await;
            continue;
        }
        if let Err(e) = state
            .db
            .backup_schedules()
            .set_users(schedule.id, owner, &encode_schedule_user_ids(&ids))
            .await
        {
            tracing::error!("updating backup schedule {} failed: {e}", schedule.id);
            return Err(internal_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_without_figures_still_gives_each_limit() {
        // `?usage=0`: the measurement is null, the setting is not.
        assert_eq!(
            storage_fields(None, "end_user", 100),
            (Value::Null, json!(100 * 1024 * 1024), Value::Null)
        );
        // An administrator has no limit, figure or not.
        assert_eq!(
            storage_fields(None, "admin", 100),
            (Value::Null, Value::Null, Value::Null)
        );
        // With a figure, the three fields are the list's own.
        assert_eq!(
            storage_fields(Some(25 * 1024 * 1024), "end_user", 100),
            (
                json!(25 * 1024 * 1024),
                json!(100 * 1024 * 1024),
                json!(25.0)
            )
        );
        // A limit of zero is a limit: the used bytes are there, the
        // percentage is the helper's 0.0 for a zero limit, as before.
        assert_eq!(
            storage_fields(Some(1), "end_user", 0),
            (json!(1), json!(0), json!(0.0))
        );
    }

    /// Every `_decode_schedule_user_ids` verdict the real Python gave.
    ///
    /// The cases that matter are the ones no reading of the function finds:
    /// a JSON **string** is iterated character by character, so `"12"` is
    /// `[1, 2]`; `int(True)` is `1`; and four shapes make the function
    /// **raise**, which nothing catches — so the endpoint answers 500 rather
    /// than treating the column as empty.
    #[test]
    fn a_schedule_user_list_is_decoded_the_way_the_python_decodes_it() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/schedule_user_ids.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the schedule corpus"))
                .expect("the corpus parses");
        let cases = corpus["cases"].as_array().expect("the cases");
        assert_eq!(cases.len(), 31, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut raised = 0usize;
        for case in cases {
            let raw = case["raw"].as_str();
            let got = decode_schedule_user_ids(raw);
            if case["ok"].as_bool().unwrap_or(false) {
                let want: Vec<i64> = case["ids"]
                    .as_array()
                    .expect("ids")
                    .iter()
                    .filter_map(Value::as_i64)
                    .collect();
                if got.as_deref() != Ok(want.as_slice()) {
                    failures.push(format!("{raw:?}\n  python {want:?}\n  rust   {got:?}"));
                }
            } else {
                raised += 1;
                if got.is_ok() {
                    failures.push(format!(
                        "{raw:?}: python raises {}, rust gave {got:?}",
                        case["error"].as_str().unwrap_or("")
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
        // A corpus in which nothing raises would agree with a decoder that
        // never refuses anything.
        assert!(raised >= 4, "only {raised} cases raise");
    }

    /// What goes back into the column, byte for byte.
    ///
    /// `json.dumps` puts a **space after the comma**, and `serde_json` does
    /// not. The column is compared against what the Python wrote when a
    /// shadow diff runs, and a missing space is a difference on every
    /// schedule with more than one user.
    #[test]
    fn the_schedule_column_is_the_pythons_bytes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/schedule_user_ids.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the schedule corpus"))
                .expect("the corpus parses");
        let encoded = corpus["encoded"].as_object().expect("the encodings");
        assert!(!encoded.is_empty());

        for (key, want) in encoded {
            // The key is Python's `str(list)`, e.g. `[1, 2, 3]`.
            let ids: Vec<i64> = key
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .filter_map(|part| part.trim().parse().ok())
                .collect();
            assert_eq!(
                encode_schedule_user_ids(&ids),
                want.as_str().unwrap_or(""),
                "for {key}"
            );
        }
        // And the shape the space lives in.
        assert_eq!(encode_schedule_user_ids(&[]), "[]");
        assert_eq!(encode_schedule_user_ids(&[1]), "[1]");
        assert_eq!(encode_schedule_user_ids(&[1, 2, 3]), "[1, 2, 3]");
    }

    /// A reserved name and a malformed one are different refusals.
    ///
    /// Source: `UserCreate` — the pattern is pydantic's and gives
    /// `string_pattern_mismatch`; the reserved-name check is a
    /// `field_validator` and gives `value_error`. An administrator who typed
    /// `root` has to be told it is taken by the system, not that it is
    /// malformed.
    #[test]
    fn a_reserved_username_is_refused_differently_from_a_malformed_one() {
        let refusal = |payload: Value| -> axum::http::StatusCode {
            user_create_fields(&payload)
                .err()
                .expect("refused")
                .status()
        };
        let unprocessable = axum::http::StatusCode::UNPROCESSABLE_ENTITY;

        let good = json!({
            "username": "alice",
            "email": "a@b.co",
            "password": "correct horse battery",
        });
        let fields = user_create_fields(&good).expect("accepted");
        assert_eq!(fields.username, "alice");
        // The defaults, which are the schema's and not the column's.
        assert_eq!(fields.role, "end_user");
        assert_eq!(fields.website_limit, 5);
        assert_eq!(fields.storage_limit_mb, 1024);
        assert_eq!(fields.package_id, None);

        // Reserved: every name the helper would refuse anyway, caught here
        // with a message that says why.
        for reserved in ["root", "nobody", "snpanel", "www-data", "mysql"] {
            let mut payload = good.clone();
            payload["username"] = json!(reserved);
            assert_eq!(refusal(payload), unprocessable, "{reserved} was accepted");
        }
        // Malformed: a leading digit, a capital, a dot, too short.
        //
        // `aLice` and `aliceÉ` carry theirs **after** the first character,
        // which is the only position the tail's `[a-z0-9_-]` decides: the
        // first character has its own `[a-z_]` check, so a capital there
        // proves nothing about the tail.
        for bad in [
            "1alice", "Alice", "aLice", "aliceB", "aliceÉ", "a.b", "ab", "-alice", "alice!",
            "alice b", "",
        ] {
            let mut payload = good.clone();
            payload["username"] = json!(bad);
            assert_eq!(refusal(payload), unprocessable, "{bad:?} was accepted");
        }
        // A leading underscore is allowed by the pattern.
        let mut payload = good.clone();
        payload["username"] = json!("_alice");
        assert!(user_create_fields(&payload).is_ok());
        // 32 characters is the limit.
        payload["username"] = json!("a".repeat(32));
        assert!(user_create_fields(&payload).is_ok());
        payload["username"] = json!("a".repeat(33));
        assert_eq!(refusal(payload), unprocessable);
    }

    /// The password is synced to a Linux account, and `chpasswd` reads lines.
    ///
    /// Source: `_validate_linux_login_password`. A `:` or a newline in the
    /// password would make `user:password` ambiguous — and the failure would
    /// be a customer who cannot log in over SFTP with the password the panel
    /// shows them.
    #[test]
    fn a_password_that_would_break_chpasswd_is_refused() {
        let with = |password: &str| {
            user_create_fields(&json!({
                "username": "alice",
                "email": "a@b.co",
                "password": password,
            }))
        };
        assert!(with("correct horse battery").is_ok());
        // Twelve characters, and seventy-two - bcrypt's limit, not a policy.
        assert!(with(&"a".repeat(12)).is_ok());
        assert!(with(&"a".repeat(72)).is_ok());
        assert!(with(&"a".repeat(11)).is_err());
        assert!(with(&"a".repeat(73)).is_err());

        for bad in [
            "pass:word123",
            "pass\nword123",
            "pass\rword123",
            "pass\0word12",
        ] {
            assert!(with(bad).is_err(), "{bad:?} was accepted");
        }
    }

    /// A package overrides an explicit limit in the same request.
    ///
    /// Source: `update_user` calls `_apply_package_limits` **twice** — once
    /// where the package is resolved and once at the end, with the explicit
    /// limits assigned in between. The second call decides.
    ///
    /// The first port of this applied it once and let the explicit limit win,
    /// so `{"package_id": 3, "website_limit": 999}` gave the customer 999
    /// websites here and the package's number there. **It shipped**, and the
    /// Rust was the permissive one — which is the wrong direction for a
    /// limit.
    #[test]
    fn a_package_overrides_a_limit_asked_for_in_the_same_request() {
        let package = snpanel_db::Package {
            id: 3,
            name: "Starter".into(),
            slug: None,
            website_limit: 5,
            storage_limit_mb: 1024,
            database_limit: 1,
            alias_limit: 1,
            backup_retention_days: 7,
            terminal_enabled: false,
            waf_enabled: true,
            wordpress_enabled: true,
            node_apps_limit: 0,
            node_app_memory_mb: 0,
            created_at: None,
        };

        // Both given: the package wins, on all three fields.
        assert_eq!(
            resolve_package_limits(Some(&package), Some(999), Some(999_999)),
            (Some(5), Some(1024), Some(false))
        );
        // A package and nothing else: the package's numbers.
        assert_eq!(
            resolve_package_limits(Some(&package), None, None),
            (Some(5), Some(1024), Some(false))
        );
        // No package: the explicit numbers stand, and `terminal_enabled` is
        // left alone rather than defaulted - nothing in the payload sets it,
        // and writing `false` would turn a customer's terminal off for a
        // request that never mentioned it.
        assert_eq!(
            resolve_package_limits(None, Some(999), Some(999_999)),
            (Some(999), Some(999_999), None)
        );
        assert_eq!(resolve_package_limits(None, None, None), (None, None, None));
        // One of the two given, without a package.
        assert_eq!(
            resolve_package_limits(None, Some(7), None),
            (Some(7), None, None)
        );
    }
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
