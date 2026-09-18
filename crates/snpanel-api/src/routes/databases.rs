//! `/api/databases` - ported from `api/databases.py`, in part.
//!
//! Creating, deleting and re-passwording a database all drive MariaDB through
//! the helper, and downloading one streams a `mysqldump`. Those stay with
//! Python until the helper's MariaDB surface is finished; the rest is here.
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
