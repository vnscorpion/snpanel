//! `/api/users` - ported from `api/users.py`, **partially and on purpose**.
//!
//! This router is the first one that could not be moved whole, and pretending
//! otherwise would be worse than saying so. Five of its ten endpoints reach
//! outside the database entirely:
//!
//! | endpoint | what it also does | here |
//! |---|---|---|
//! | `POST /users` | creates a Linux account through the helper | proxied |
//! | `DELETE /users/{id}` | drops databases, deletes vhosts, releases certificates, removes the Linux account | proxied |
//! | `POST /users/{id}/password` | sets the SFTP password through the helper | proxied |
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

#[cfg(test)]
mod tests {
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
}
