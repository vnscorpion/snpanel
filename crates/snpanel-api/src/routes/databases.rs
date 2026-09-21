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
        .route(
            "/databases",
            get(list).post(create_database).fallback(crate::fallback),
        )
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

/// Source: `mariadb.user_exists`.
///
/// Asked of **MariaDB**, not of the panel's own table: the whole point is to
/// notice accounts the panel does not know about, which is exactly what the
/// table cannot tell you. A restore or a DirectAdmin import can leave one
/// behind, and taking it over would reset its password.
async fn mariadb_user_exists(db_user: &str) -> Result<bool, crate::mariadb::SqlError> {
    let safe = crate::mariadb::validate_identifier(db_user)?.to_string();
    let sql = format!(
        "SELECT 1 FROM mysql.user WHERE user = {} LIMIT 1;\n",
        crate::mariadb::quote_sql_string(&safe)
    );
    // `check=False` - a MariaDB that will not answer is not a reason to say
    // the account is free.
    Ok(crate::mariadb::run_sql(&sql)
        .await
        .map(|out| out.contains('1'))
        .unwrap_or(false))
}

/// Source: `mariadb.create_database_credentials`.
///
/// **`CREATE USER IF NOT EXISTS` with no `ALTER USER` behind it.** The pair
/// used to mean "create it, or take it over" - and since the panel
/// authenticates with ALL PRIVILEGES ON *.*, any caller who asked for
/// `db_user=root` got root's password reset to a value of their choosing,
/// handed back in the response. On a stock Ubuntu box root is `IDENTIFIED VIA
/// mysql_native_password USING 'invalid' OR unix_socket`, so the `ALTER` also
/// dropped the socket clause and locked the system's own root out of MariaDB.
///
/// Creating now refuses an account that already exists. The restore paths
/// legitimately recreate an account their archive owned; they are not this
/// one.
async fn create_database_credentials(
    db_name: &str,
    db_user: &str,
    db_password: &str,
) -> Result<(), crate::mariadb::SqlError> {
    let db_name = crate::mariadb::validate_identifier(db_name)?.to_string();
    let db_user = crate::mariadb::validate_identifier(db_user)?.to_string();
    crate::mariadb::reject_reserved_user(&db_user)?;

    if mariadb_user_exists(&db_user).await? {
        return Err(crate::mariadb::SqlError::Invalid(format!(
            "MariaDB account '{db_user}' already exists. Choose another database user name."
        )));
    }

    let quoted_user = crate::mariadb::quote_sql_string(&db_user);
    let sql = format!(
        "CREATE DATABASE IF NOT EXISTS {} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n\
         CREATE USER IF NOT EXISTS {quoted_user}@'localhost' IDENTIFIED BY {};\n\
         GRANT ALL PRIVILEGES ON {}.* TO {quoted_user}@'localhost';\n\
         FLUSH PRIVILEGES;\n",
        crate::mariadb::quote_identifier(&db_name)?,
        crate::mariadb::quote_sql_string(db_password),
        crate::mariadb::quote_identifier(&db_name)?,
    );
    crate::mariadb::run_sql(&sql).await.map(|_| ())
}

/// Source: `DatabaseCreate`'s three fields and their validators.
///
/// The validators run in `mode="before"`, so `db_name` and `db_user` are
/// **trimmed and lowered before the pattern sees them**: `  MyDB ` is accepted
/// and stored as `mydb`, not refused for its capitals. A port that checked the
/// pattern first would refuse a name the panel takes today.
///
/// `""` maps to `None` for the two optional fields, which is why an empty
/// `db_password` means "generate one" rather than "a password of length zero"
/// - the `min_length=12` never sees it.
fn database_create_fields(payload: &Value) -> Result<(String, String, Option<String>), Value> {
    let field = |key: &str| payload.get(key).and_then(Value::as_str);
    let pattern = |name: &str, value: &str| {
        json!({
            "type": "string_pattern_mismatch",
            "loc": ["body", name],
            "msg": "String should match pattern '^[a-z0-9_]+$'",
            "input": value,
            "ctx": { "pattern": "^[a-z0-9_]+$" },
        })
    };
    // `Field(min_length=..., max_length=...)`, as the entry rather than a
    // response - see the note on this function's return type.
    let length = |name: &str, value: &str, min: usize, max: usize| -> Result<(), Value> {
        let chars = value.chars().count();
        if chars < min {
            return Err(json!({
                "type": "string_too_short",
                "loc": ["body", name],
                "msg": format!("String should have at least {min} characters"),
                "input": value,
                "ctx": { "min_length": min },
            }));
        }
        if chars > max {
            return Err(json!({
                "type": "string_too_long",
                "loc": ["body", name],
                "msg": format!("String should have at most {max} characters"),
                "input": value,
                "ctx": { "max_length": max },
            }));
        }
        Ok(())
    };
    let ok_identifier = |v: &str| {
        !v.is_empty()
            && v.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };

    let raw_name = field("db_name").unwrap_or("").trim().to_lowercase();
    if raw_name.is_empty() {
        // `raise ValueError("db_name is required")` from a `field_validator`,
        // which pydantic renders as a **`value_error`** - not the
        // `string_too_short` the length bound below would give for the same
        // empty string. Both are 422 and they are not the same answer.
        return Err(json!({
            "type": "value_error",
            "loc": ["body", "db_name"],
            "msg": "Value error, db_name is required",
            "input": payload.get("db_name").unwrap_or(&Value::Null),
            "ctx": { "error": {} },
        }));
    }
    length("db_name", &raw_name, 1, 64)?;
    if !ok_identifier(&raw_name) {
        return Err(pattern("db_name", &raw_name));
    }

    // `db_user: Optional[str]` with `"" -> None`, then `db_user or db_name`.
    let raw_user = match field("db_user").map(|v| v.trim().to_lowercase()) {
        Some(v) if !v.is_empty() => v,
        _ => raw_name.clone(),
    };
    length("db_user", &raw_user, 1, 64)?;
    if !ok_identifier(&raw_user) {
        return Err(pattern("db_user", &raw_user));
    }

    // `db_password: Optional[str]` with `min_length=12, max_length=128`. The
    // validator maps `""` to `None`, so an empty string means "generate one"
    // rather than "a password of length zero".
    let password = match field("db_password") {
        Some(v) if !v.is_empty() => {
            length("db_password", v, 12, 128)?;
            Some(v.to_string())
        }
        _ => None,
    };
    Ok((raw_name, raw_user, password))
}

/// `POST /databases`.
///
/// Source: `create_database`. A database the customer asked for by name,
/// rather than one a website install created.
///
/// **The plain password is in the response and nowhere else.** The column
/// holds Fernet ciphertext (C3); this is the only moment the caller can read
/// it, which is why a generated one is worth 24 characters.
async fn create_database(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (db_name, db_user, given_password) = match database_create_fields(&payload) {
        Ok(v) => v,
        Err(entry) => return crate::errors::validation_error(vec![entry]),
    };
    let db_password = given_password.unwrap_or_else(|| crate::mariadb::random_password(24));

    // Two separate 409s, because the caller has to know which name to change.
    match state.db.databases().by_name(&db_name).await {
        Ok(Some(_)) => {
            return crate::errors::error(
                axum::http::StatusCode::CONFLICT,
                "Database name already exists",
            )
        }
        Err(e) => {
            tracing::error!("database name lookup failed: {e}");
            return internal_error();
        }
        Ok(None) => {}
    }
    match state.db.databases().by_user(&db_user).await {
        Ok(Some(_)) => {
            return crate::errors::error(
                axum::http::StatusCode::CONFLICT,
                "Database user already exists",
            )
        }
        Err(e) => {
            tracing::error!("database user lookup failed: {e}");
            return internal_error();
        }
        Ok(None) => {}
    }

    if let Err(e) = create_database_credentials(&db_name, &db_user, &db_password).await {
        // `except ValueError -> 409`, everything else -> 500. A reserved
        // account, or one MariaDB already has without the panel knowing, is
        // the caller's mistake and not a fault.
        return match e {
            crate::mariadb::SqlError::Invalid(message) => {
                crate::errors::error(axum::http::StatusCode::CONFLICT, &message)
            }
            other => {
                tracing::error!("creating the MariaDB database or user failed: {other}");
                crate::errors::error(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("MariaDB error: {other}"),
                )
            }
        };
    }

    let encrypted = snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, &db_password);
    let id = match state
        .db
        .databases()
        .create(current.user.id, None, &db_name, &db_user, &encrypted)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("storing the database row failed: {e}");
            return internal_error();
        }
    };

    axum::Json(json!({
        "id": id,
        "owner_id": current.user.id,
        "website_id": Value::Null,
        "db_name": db_name,
        "db_user": db_user,
        "db_password": db_password,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The validators run **before** the pattern, not after.
    ///
    /// Source: `DatabaseCreate`'s three `field_validator(mode="before")`. So
    /// `  MyDB ` is trimmed and lowered and then matches `^[a-z0-9_]+$` - it
    /// is accepted and stored as `mydb`. A port that checked the pattern on
    /// what arrived would refuse a name the panel takes today, and the caller
    /// would see a 422 for a name that looks fine to them.
    #[test]
    fn a_database_name_is_folded_before_the_pattern_sees_it() {
        let fields = |payload: Value| database_create_fields(&payload);

        let (name, user, password) = fields(json!({ "db_name": "  MyDB " })).expect("accepted");
        assert_eq!(name, "mydb");
        // `db_user or db_name` - the account is named after the database when
        // nothing else was asked for.
        assert_eq!(user, "mydb");
        // No password given means one is generated, not one of length zero.
        assert_eq!(password, None);

        let (_, user, _) = fields(json!({ "db_name": "a", "db_user": " B_2 " })).expect("ok");
        assert_eq!(user, "b_2");

        // An empty string is `None` to the validator, so it falls back rather
        // than failing the pattern.
        let (_, user, password) =
            fields(json!({ "db_name": "a", "db_user": "", "db_password": "" })).expect("ok");
        assert_eq!(user, "a");
        assert_eq!(password, None);

        // A given password is carried through, not regenerated.
        let (_, _, password) =
            fields(json!({ "db_name": "a", "db_password": "correcthorsebattery" })).expect("ok");
        assert_eq!(password.as_deref(), Some("correcthorsebattery"));
    }

    /// The names a database may not have, and **which** check refuses them.
    ///
    /// The entry rather than the status, because every refusal here is 422
    /// and the shapes are what differ: a `field_validator` that raised gives
    /// pydantic's `value_error`, a length bound gives `string_too_short` or
    /// `string_too_long`, and the pattern gives `string_pattern_mismatch`.
    /// A test that read only the status could not tell one from another, and
    /// two mutations survived on exactly that.
    #[test]
    fn a_database_name_that_would_need_quoting_is_refused() {
        let refusal = |payload: Value| -> (String, String) {
            let entry = database_create_fields(&payload).expect_err("refused");
            (
                entry["type"].as_str().unwrap_or("").to_string(),
                entry["loc"][1].as_str().unwrap_or("").to_string(),
            )
        };

        // Missing, empty or whitespace: the validator raising, **not** the
        // length bound - which would refuse the same empty string with a
        // different answer.
        for missing in [
            json!({}),
            json!({ "db_name": "" }),
            json!({ "db_name": "   " }),
        ] {
            assert_eq!(
                refusal(missing.clone()),
                ("value_error".to_string(), "db_name".to_string()),
                "{missing}"
            );
        }

        // Anything outside `[a-z0-9_]` after folding.
        for bad in ["a-b", "a.b", "a b", "a;b", "a`b", "a'b", "café", "a/b"] {
            assert_eq!(
                refusal(json!({ "db_name": bad })),
                ("string_pattern_mismatch".to_string(), "db_name".to_string()),
                "{bad:?} was accepted"
            );
        }

        // 64 characters is the limit, counted after folding.
        //
        // The user name is given explicitly on the long case: it falls back
        // to the database name, so *its* 64-character bound would refuse the
        // row whatever `db_name`'s bound said, and the thing under test would
        // never be the thing doing the refusing.
        assert!(database_create_fields(&json!({ "db_name": "a".repeat(64) })).is_ok());
        assert_eq!(
            refusal(json!({ "db_name": "a".repeat(65), "db_user": "ok" })),
            ("string_too_long".to_string(), "db_name".to_string())
        );
        // And the user name is held to both rules in its own right.
        assert_eq!(
            refusal(json!({ "db_name": "ok", "db_user": "root-user" })),
            ("string_pattern_mismatch".to_string(), "db_user".to_string())
        );
        assert_eq!(
            refusal(json!({ "db_name": "ok", "db_user": "a".repeat(65) })),
            ("string_too_long".to_string(), "db_user".to_string())
        );

        // The password bounds. Eleven characters, counted rather than
        // eyeballed: the first version of this used `"eleven_chr"`, which is
        // ten, so a mutation moving the bound to eleven survived.
        let eleven = "abcdefghijk";
        assert_eq!(eleven.chars().count(), 11);
        assert_eq!(
            refusal(json!({ "db_name": "ok", "db_password": eleven })),
            ("string_too_short".to_string(), "db_password".to_string())
        );
        assert!(
            database_create_fields(&json!({ "db_name": "ok", "db_password": "twelve_chars" }))
                .is_ok()
        );
        assert_eq!(
            refusal(json!({ "db_name": "ok", "db_password": "x".repeat(129) })),
            ("string_too_long".to_string(), "db_password".to_string())
        );
    }

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
