//! `/api/databases` - ported from `api/databases.py`, in part.
//!
//! Deleting and re-passwording a database drive MariaDB, and downloading one
//! runs a `mysqldump`. That note used to say they were waiting on "the
//! helper's MariaDB surface"; they were not. `mariadb._run_sql` calls
//! `shell.run`, not `shell.privileged` - the panel runs `mysql` itself with
//! the credentials the installer put in its `~/.my.cnf`. No helper is
//! involved and none needs to be, so they are here. Creating a database
//! still is not: it also provisions a user and a package quota.
//!
//! Two things in the ported half are worth reading twice.
//!
//! **The ownership check is not a filter.** `get_accessible_database` looks the
//! row up by id and *then* demands admin if it belongs to somebody else. That
//! is a 403, not a 404, and the difference is deliberate in the original: it
//! tells a customer the id exists. Reproduced as it stands (NT1) rather than
//! "improved" into a 404, because the frontend distinguishes them.
//!
//! **The phpMyAdmin hand-off is loopback-only.** The signon script always
//! curls `127.0.0.1`, so a legitimate consume never has a remote peer. With
//! `--forwarded-allow-ips 127.0.0.1` the client address cannot be spoofed by a
//! header, which is what makes the check worth anything - see `crate::client`.
//! Refusing with 404 rather than 403 is also deliberate: it says nothing about
//! whether the token existed.

use axum::extract::{Path, Query, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::crypto::fernet;
use snpanel_core::permissions;
use std::collections::HashMap;

use crate::auth::CurrentUser;
use crate::errors::{internal_error, not_enough_permissions, not_found};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/databases", get(list).fallback(crate::fallback))
        .route(
            "/databases/{database_id}",
            axum::routing::delete(delete_database).fallback(crate::fallback),
        )
        .route(
            "/databases/{database_id}/password",
            post(change_password).fallback(crate::fallback),
        )
        .route(
            "/databases/{database_id}/download",
            get(download_database).fallback(crate::fallback),
        )
        .route(
            "/databases/phpmyadmin-sso/{token}",
            get(consume_sso).fallback(crate::fallback),
        )
        .route(
            "/databases/{database_id}/phpmyadmin-sso",
            post(create_sso).fallback(crate::fallback),
        )
}

/// Source: `DatabaseOut` - note that `db_password` is **not** in it. The
/// password is returned exactly once, by the create endpoint, and never again.
fn to_json(d: &snpanel_db::DatabaseAccount) -> Value {
    json!({
        "id": d.id,
        "owner_id": d.owner_id,
        "website_id": d.website_id,
        "db_name": d.db_name,
        "db_user": d.db_user,
    })
}

async fn list(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let q = params.get("q").cloned().unwrap_or_default();
    if q.chars().count() > 255 {
        return crate::errors::validation_error(vec![json!({
            "type": "string_too_long",
            "loc": ["query", "q"],
            "msg": "String should have at most 255 characters",
            "input": q,
            "ctx": { "max_length": 255 },
        })]);
    }
    let search = q.trim().to_lowercase();

    // An administrator sees every database; anyone else sees their own.
    let owner = if permissions::is_admin_role(&current.user.role) {
        None
    } else {
        Some(current.user.id)
    };

    match state.db.databases().list(owner, &search).await {
        Ok(rows) => axum::Json(rows.iter().map(to_json).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!("listing databases failed: {e}");
            internal_error()
        }
    }
}

/// Source: `get_accessible_database`.
async fn accessible(
    state: &AppState,
    current: &CurrentUser,
    id: i64,
) -> Result<snpanel_db::DatabaseAccount, Response> {
    let item = state
        .db
        .databases()
        .by_id(id)
        .await
        .map_err(|e| {
            tracing::error!("database lookup failed: {e}");
            internal_error()
        })?
        .ok_or_else(|| not_found("Database not found"))?;

    if item.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return Err(not_enough_permissions());
    }
    Ok(item)
}

/// Mint a one-shot phpMyAdmin login.
///
/// This is the endpoint that decrypts a stored database password, so it is
/// where C3 is exercised against real production ciphertext: a key derivation
/// that disagreed with Python's by a single byte fails here and nowhere else.
async fn create_sso(
    State(state): State<AppState>,
    Path(database_id): Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let item = match accessible(&state, &current, database_id).await {
        Ok(i) => i,
        Err(r) => return r,
    };

    let password = match fernet::decrypt(
        &state.settings.secret_key,
        Some(&item.db_password),
        state.settings.strict_decrypt,
    ) {
        Ok(p) => p,
        Err(e) => {
            // The Python's message, which tells the user what to do rather
            // than what went wrong.
            tracing::error!("could not decrypt a stored database password: {e}");
            return crate::errors::error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to access stored database password; please re-save the password in panel settings",
            );
        }
    };

    let token = match crate::sso::create_phpmyadmin_token(&item.db_user, &password, &item.db_name) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("could not write the phpMyAdmin token: {e}");
            return internal_error();
        }
    };

    let detail = snpanel_db::AuditRepo::detail_with_request(
        "",
        &crate::client::audit_ip(&parts),
        parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );
    if let Err(e) = state
        .db
        .audits()
        .log(
            Some(current.user.id),
            "phpmyadmin_sso",
            &format!("db={}", item.db_name),
            &detail,
        )
        .await
    {
        tracing::error!("could not write the phpMyAdmin audit entry: {e}");
    }

    let base = crate::panel_urls::tools_base_url(&state.settings, &parts.headers);
    axum::Json(json!({
        "url": format!("{base}/phpmyadmin/snpanel-signon.php?snpanel_sso={token}")
    }))
    .into_response()
}

/// Consume one. No authentication - the token *is* the credential - so the
/// loopback check is the entire access control.
async fn consume_sso(Path(token): Path<String>, req: Request) -> Response {
    let (parts, _) = req.into_parts();

    let peer_is_loopback = crate::client::client_host(&parts)
        .and_then(|h| h.parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);
    if !peer_is_loopback {
        tracing::warn!(
            peer = crate::client::audit_ip(&parts),
            "phpmyadmin-sso non-loopback access attempt"
        );
        return not_found("Invalid or expired token");
    }

    let Some(data) = crate::sso::consume_phpmyadmin_token(&token) else {
        return not_found("Invalid or expired token");
    };

    // `Cache-Control: no-store`: this body carries a database password, and a
    // proxy or a browser keeping a copy of it is the one thing that must not
    // happen to a one-shot credential.
    ([("cache-control", "no-store")], axum::Json(data)).into_response()
}

// ---------------------------------------------------------------------------
// the three that drive MariaDB
// ---------------------------------------------------------------------------

/// Source: `change_database_password`.
///
/// The new password is stored encrypted with the panel's key, the same way
/// the create path stores it: the panel has to be able to hand it to
/// phpMyAdmin later, so it is reversible by design and the key is what keeps
/// it safe.
async fn change_password(
    State(state): State<AppState>,
    Path(database_id): Path<i64>,
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
    let item = match accessible(&state, &current, database_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(raw) = payload.get("password") else {
        return crate::errors::missing_field("password", payload.clone());
    };
    let Some(password) = raw.as_str() else {
        return crate::errors::string_type("password", raw);
    };

    if let Err(e) = crate::mariadb::change_database_password(&item.db_user, password).await {
        return match e {
            crate::mariadb::SqlError::Invalid(m) => crate::errors::bad_request(&m),
            crate::mariadb::SqlError::Failed(m) => {
                tracing::error!("changing a database password failed: {m}");
                internal_error()
            }
        };
    }
    let encrypted = snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, password);
    if let Err(e) = state.db.databases().set_password(item.id, &encrypted).await {
        tracing::error!("storing the database password failed: {e}");
        return internal_error();
    }
    axum::Json(json!({ "ok": true, "db_user": item.db_user })).into_response()
}

/// Source: `delete_database_record`.
///
/// MariaDB first, the row second, and the order is the Python's. A row
/// removed while the database still exists leaves storage nobody can see; a
/// database dropped while the row remains shows the customer something that
/// is not there, and the next create can collide with the name.
async fn delete_database(
    State(state): State<AppState>,
    Path(database_id): Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let item = match accessible(&state, &current, database_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(e) = crate::mariadb::drop_database(&item.db_name, &item.db_user).await {
        tracing::error!("deleting a MariaDB database or user failed: {e}");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({ "detail": format!("MariaDB error: {e}") })),
        )
            .into_response();
    }
    if let Err(e) = state.db.databases().delete(item.id).await {
        tracing::error!("deleting the database record failed: {e}");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({ "detail": "Panel database error" })),
        )
            .into_response();
    }
    axum::Json(json!({ "ok": true })).into_response()
}

/// Source: `download_database` - a `mysqldump` to a temporary file, sent as
/// an attachment and removed afterwards.
async fn download_database(
    State(state): State<AppState>,
    Path(database_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let item = match accessible(&state, &current, database_id).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let temp = std::env::temp_dir().join(format!(
        "{}-{}-{}.sql",
        item.db_name,
        std::process::id(),
        item.id
    ));
    let temp_str = temp.to_string_lossy().into_owned();
    if let Err(e) = crate::mariadb::export_database(&item.db_name, &temp_str).await {
        let _ = tokio::fs::remove_file(&temp).await;
        return match e {
            crate::mariadb::SqlError::Invalid(m) => crate::errors::bad_request(&m),
            crate::mariadb::SqlError::Failed(m) => {
                tracing::error!("exporting a database failed: {m}");
                internal_error()
            }
        };
    }
    let bytes = match tokio::fs::read(&temp).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("reading the export failed: {e}");
            let _ = tokio::fs::remove_file(&temp).await;
            return internal_error();
        }
    };
    // The Python removes it in a background task after the response is sent.
    // Reading it into memory first and removing it now reaches the same end
    // with no window where a temp file survives a crash.
    let _ = tokio::fs::remove_file(&temp).await;

    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/sql".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}.sql\"", item.db_name),
            ),
        ],
        axum::body::Body::from(bytes),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listing_never_carries_a_password() {
        // DatabaseOut has no `db_password`. Adding one would put every
        // customer's database password in a list every page load fetches.
        let d = snpanel_db::DatabaseAccount {
            id: 1,
            owner_id: 2,
            website_id: Some(3),
            db_name: "shop".into(),
            db_user: "shop_user".into(),
            db_password: "fernet:secret".into(),
        };
        let v = to_json(&d);
        assert!(v.get("db_password").is_none(), "{v}");
        assert_eq!(v["id"], json!(1));
        assert_eq!(v["owner_id"], json!(2));
        assert_eq!(v["website_id"], json!(3));
        assert_eq!(v["db_name"], json!("shop"));
        assert_eq!(v["db_user"], json!("shop_user"));
    }

    #[test]
    fn a_null_website_stays_null() {
        let d = snpanel_db::DatabaseAccount {
            id: 1,
            owner_id: 2,
            website_id: None,
            db_name: "x".into(),
            db_user: "y".into(),
            db_password: "fernet:z".into(),
        };
        assert_eq!(to_json(&d)["website_id"], Value::Null);
    }
}
