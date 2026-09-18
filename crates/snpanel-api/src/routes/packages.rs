//! `/api/packages` - ported from `api/packages.py`.
//!
//! Four admin-only endpoints over `user_packages`. Small, and worth reading
//! closely for two rules that are not obvious from the route list:
//!
//! **A patch cascades.** Changing a package's `website_limit` or
//! `storage_limit_mb` rewrites those columns on every user holding it, because
//! the columns on `users` are copies rather than references. See
//! `snpanel_db::packages`.
//!
//! **A package in use cannot be deleted** - 400, not a cascade. Deleting it
//! would set `package_id` to NULL on its members (the foreign key says
//! `ON DELETE SET NULL`) and leave them with limits that came from a package
//! nobody can find any more.

use axum::extract::{Path, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_db::PackageFields;

use crate::auth::CurrentUser;
use crate::errors::{
    bad_request, check_length, check_range, conflict, internal_error, iso_datetime, missing_field,
    not_enough_permissions, not_found,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    // Registered with their full paths rather than nested, so `/api/packages`
    // is matched exactly - a nested empty path would answer on
    // `/api/packages/` instead, and the frontend asks for the former.
    Router::new()
        .route("/packages", get(list).post(create))
        .route("/packages/{package_id}", patch(update).delete(remove))
}

/// Source: `UserPackageOut`.
fn to_json(p: &snpanel_db::Package) -> Value {
    json!({
        "id": p.id,
        "name": p.name,
        "slug": p.slug,
        "website_limit": p.website_limit,
        "storage_limit_mb": p.storage_limit_mb,
        "database_limit": p.database_limit,
        "alias_limit": p.alias_limit,
        "backup_retention_days": p.backup_retention_days,
        "terminal_enabled": p.terminal_enabled,
        "waf_enabled": p.waf_enabled,
        "wordpress_enabled": p.wordpress_enabled,
        "node_apps_limit": p.node_apps_limit,
        "node_app_memory_mb": p.node_app_memory_mb,
        "created_at": iso_datetime(p.created_at.as_deref()),
    })
}

/// Source: `ensure_role(current_user.role, Role.admin)`.
fn require_admin(current: &CurrentUser) -> Result<(), Response> {
    if permissions::has_role(&current.user.role, Role::Admin) {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

async fn list(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }
    match state.db.packages().list().await {
        Ok(rows) => {
            let out: Vec<Value> = rows.iter().map(to_json).collect();
            axum::Json(out).into_response()
        }
        Err(e) => {
            tracing::error!("listing packages failed: {e}");
            internal_error()
        }
    }
}

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

    let name = match payload.get("name").and_then(Value::as_str) {
        Some(v) => v,
        None => return missing_field("name", payload.clone()),
    };
    let name = match normalise_name(name) {
        Ok(n) => n,
        Err(r) => return r,
    };
    if let Err(r) = check_length("name", &name, 1, 100) {
        return r;
    }

    let mut fields = PackageFields {
        name: Some(name.clone()),
        ..Default::default()
    };
    if let Err(r) = read_common_fields(&payload, &mut fields) {
        return r;
    }
    // A create fills in the schema defaults for anything absent; a patch
    // leaves it alone. `PackageFields` carries `None` for both, so the create
    // path resolves it here rather than in the repository.
    fields.slug = Some(match payload.get("slug") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    });

    match state.db.packages().name_taken(&name, None).await {
        Ok(true) => return conflict("Package name already exists"),
        Ok(false) => {}
        Err(e) => {
            tracing::error!("package name check failed: {e}");
            return internal_error();
        }
    }

    let package = match state.db.packages().create(&fields).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("creating a package failed: {e}");
            return internal_error();
        }
    };

    audit_action(
        &state,
        &parts,
        current.user.id,
        "create_package",
        &package.name,
    )
    .await;
    axum::Json(to_json(&package)).into_response()
}

async fn update(
    State(state): State<AppState>,
    Path(package_id): Path<i64>,
    req: Request,
) -> Response {
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

    let existing = match state.db.packages().by_id(package_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("Package not found"),
        Err(e) => {
            tracing::error!("package lookup failed: {e}");
            return internal_error();
        }
    };

    let mut fields = PackageFields::default();
    if let Err(r) = read_common_fields(&payload, &mut fields) {
        return r;
    }
    // `slug` is three-valued on a patch: absent leaves it, a string sets it,
    // and an explicit null... does nothing, because the Python guards with
    // `if payload.slug is not None`. Reproduced rather than improved (NT1).
    if let Some(Value::String(s)) = payload.get("slug") {
        fields.slug = Some(Some(s.clone()));
    }

    if let Some(raw) = payload.get("name") {
        let Some(text) = raw.as_str() else {
            return crate::errors::string_type("name", raw);
        };
        let name = match normalise_name(text) {
            Ok(n) => n,
            Err(r) => return r,
        };
        if let Err(r) = check_length("name", &name, 1, 100) {
            return r;
        }
        // Only checked when it actually changes, as the Python does: renaming
        // a package to the name it already has is not a conflict.
        if name != existing.name {
            match state
                .db
                .packages()
                .name_taken(&name, Some(package_id))
                .await
            {
                Ok(true) => return conflict("Package name already exists"),
                Ok(false) => fields.name = Some(name),
                Err(e) => {
                    tracing::error!("package name check failed: {e}");
                    return internal_error();
                }
            }
        }
    }

    let package = match state.db.packages().update(package_id, &fields).await {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("Package not found"),
        Err(e) => {
            tracing::error!("updating a package failed: {e}");
            return internal_error();
        }
    };

    audit_action(
        &state,
        &parts,
        current.user.id,
        "update_package",
        &package.name,
    )
    .await;
    axum::Json(to_json(&package)).into_response()
}

async fn remove(
    State(state): State<AppState>,
    Path(package_id): Path<i64>,
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

    let package = match state.db.packages().by_id(package_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("Package not found"),
        Err(e) => {
            tracing::error!("package lookup failed: {e}");
            return internal_error();
        }
    };

    // Refused rather than cascaded: the foreign key would set `package_id` to
    // NULL on its members and leave them with limits copied from a package
    // nobody can look up any more.
    match state.db.packages().user_count(package_id).await {
        Ok(0) => {}
        Ok(_) => return bad_request("Package is in use"),
        Err(e) => {
            tracing::error!("package user count failed: {e}");
            return internal_error();
        }
    }

    // The name is captured before the delete, because the audit entry names it
    // and the row is gone by the time the entry is written.
    let name = package.name.clone();
    if let Err(e) = state.db.packages().delete(package_id).await {
        tracing::error!("deleting a package failed: {e}");
        return internal_error();
    }

    audit_action(&state, &parts, current.user.id, "delete_package", &name).await;
    axum::Json(json!({ "ok": true })).into_response()
}

/// Every numeric and boolean field, with the bounds from the Pydantic schema.
///
/// The bounds are not decoration: `storage_limit_mb` is multiplied by 1024²
/// when it is turned into bytes, so an unbounded value overflows into a
/// nonsensical quota.
fn read_common_fields(payload: &Value, fields: &mut PackageFields) -> Result<(), Response> {
    const INTS: &[(&str, i64, i64)] = &[
        ("website_limit", 0, 1000),
        ("storage_limit_mb", 0, 1024 * 1024),
        ("database_limit", 0, 10000),
        ("alias_limit", 0, 1000),
        ("backup_retention_days", 0, 365),
        ("node_apps_limit", 0, 100),
        ("node_app_memory_mb", 64, 16384),
    ];

    for (name, min, max) in INTS {
        let Some(raw) = payload.get(*name) else {
            continue;
        };
        if raw.is_null() {
            continue;
        }
        let Some(value) = raw.as_i64() else {
            return Err(crate::errors::int_parsing(name, raw));
        };
        check_range(name, value, *min, *max)?;
        match *name {
            "website_limit" => fields.website_limit = Some(value),
            "storage_limit_mb" => fields.storage_limit_mb = Some(value),
            "database_limit" => fields.database_limit = Some(value),
            "alias_limit" => fields.alias_limit = Some(value),
            "backup_retention_days" => fields.backup_retention_days = Some(value),
            "node_apps_limit" => fields.node_apps_limit = Some(value),
            "node_app_memory_mb" => fields.node_app_memory_mb = Some(value),
            _ => unreachable!("the list above is exhaustive"),
        }
    }

    for name in ["terminal_enabled", "waf_enabled", "wordpress_enabled"] {
        let Some(raw) = payload.get(name) else {
            continue;
        };
        if raw.is_null() {
            continue;
        }
        let Some(value) = raw.as_bool() else {
            return Err(crate::errors::bool_parsing(name, raw));
        };
        match name {
            "terminal_enabled" => fields.terminal_enabled = Some(value),
            "waf_enabled" => fields.waf_enabled = Some(value),
            "wordpress_enabled" => fields.wordpress_enabled = Some(value),
            _ => unreachable!(),
        }
    }
    Ok(())
}

/// Source: the `validate_name` field validator - collapse runs of whitespace,
/// trim, and refuse what is left if it is empty.
fn normalise_name(raw: &str) -> Result<String, Response> {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return Err(crate::errors::value_error(
            "name",
            "name is required",
            &json!(raw),
        ));
    }
    Ok(collapsed)
}

pub(super) async fn audit_action(
    state: &AppState,
    parts: &axum::http::request::Parts,
    actor_id: i64,
    action: &str,
    target: &str,
) {
    let ip = crate::client::audit_ip(parts);
    let ua = parts
        .headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let detail = snpanel_db::AuditRepo::detail_with_request("", &ip, ua);
    if let Err(e) = state
        .db
        .audits()
        .log(Some(actor_id), action, target, &detail)
        .await
    {
        // The Python logs and carries on: an audit write that fails must not
        // turn a completed operation into a 500 the administrator retries.
        tracing::error!("could not write the {action} audit entry: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_has_its_whitespace_collapsed() {
        assert_eq!(normalise_name("  Gói   cơ  bản ").unwrap(), "Gói cơ bản");
        assert_eq!(normalise_name("Basic").unwrap(), "Basic");
        // A tab or a newline counts as whitespace, as Python's \s+ does.
        assert_eq!(normalise_name("a\t\nb").unwrap(), "a b");
    }

    #[test]
    fn a_name_of_nothing_but_whitespace_is_refused() {
        for bad in ["", "   ", "\t", "\n "] {
            assert!(normalise_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_numeric_bounds_are_the_schemas() {
        let mut f = PackageFields::default();
        // The upper bound on storage matters: the value is multiplied by
        // 1024² to make bytes, so an unbounded one overflows into nonsense.
        assert!(read_common_fields(&json!({"storage_limit_mb": 1024 * 1024}), &mut f).is_ok());
        assert!(read_common_fields(&json!({"storage_limit_mb": 1024 * 1024 + 1}), &mut f).is_err());
        assert!(read_common_fields(&json!({"website_limit": 1000}), &mut f).is_ok());
        assert!(read_common_fields(&json!({"website_limit": 1001}), &mut f).is_err());
        assert!(read_common_fields(&json!({"website_limit": -1}), &mut f).is_err());
        // node_app_memory_mb has a *lower* bound of 64, not 0.
        assert!(read_common_fields(&json!({"node_app_memory_mb": 63}), &mut f).is_err());
        assert!(read_common_fields(&json!({"node_app_memory_mb": 64}), &mut f).is_ok());
    }

    #[test]
    fn a_field_that_is_absent_is_left_alone() {
        let mut f = PackageFields::default();
        read_common_fields(&json!({"website_limit": 20}), &mut f).unwrap();
        assert_eq!(f.website_limit, Some(20));
        assert_eq!(f.database_limit, None, "not mentioned, so not set");
        assert_eq!(f.terminal_enabled, None);
    }

    #[test]
    fn a_wrong_type_is_a_validation_error_not_a_silent_zero() {
        let mut f = PackageFields::default();
        assert!(read_common_fields(&json!({"website_limit": "abc"}), &mut f).is_err());
        assert!(read_common_fields(&json!({"terminal_enabled": "yes"}), &mut f).is_err());
        // A float is not an integer either.
        assert!(read_common_fields(&json!({"website_limit": 1.5}), &mut f).is_err());
    }

    #[test]
    fn booleans_are_read_where_they_are_given() {
        let mut f = PackageFields::default();
        read_common_fields(
            &json!({"terminal_enabled": true, "waf_enabled": false}),
            &mut f,
        )
        .unwrap();
        assert_eq!(f.terminal_enabled, Some(true));
        assert_eq!(f.waf_enabled, Some(false));
        assert_eq!(f.wordpress_enabled, None);
    }

    #[test]
    fn a_package_serialises_with_every_field_the_schema_declares() {
        let p = snpanel_db::Package {
            id: 1,
            name: "Basic".into(),
            slug: None,
            website_limit: 5,
            storage_limit_mb: 1024,
            database_limit: 5,
            alias_limit: 0,
            backup_retention_days: 7,
            terminal_enabled: false,
            waf_enabled: true,
            wordpress_enabled: true,
            node_apps_limit: 0,
            node_app_memory_mb: 512,
            created_at: Some("2026-09-17 17:07:20.000000".into()),
        };
        let v = to_json(&p);
        for key in [
            "id",
            "name",
            "slug",
            "website_limit",
            "storage_limit_mb",
            "database_limit",
            "alias_limit",
            "backup_retention_days",
            "terminal_enabled",
            "waf_enabled",
            "wordpress_enabled",
            "node_apps_limit",
            "node_app_memory_mb",
            "created_at",
        ] {
            assert!(v.get(key).is_some(), "{key} is missing");
        }
        // A whole second serialises without microseconds, as isoformat() does.
        assert_eq!(v["created_at"], json!("2026-09-17T17:07:20"));
        assert_eq!(v["slug"], Value::Null);
    }
}
