//! `/api/maintenance/s3-targets` - not in the Python: S3 backup destinations.
//!
//! Beside the SFTP targets, for administrators only. The secret key is
//! encrypted with the panel's key before it reaches the database and never
//! comes back out - an edit that leaves it blank keeps it. A destination a
//! schedule uploads to cannot be deleted: the schedule would go on backing
//! up to this server alone, and nobody would know until this server was the
//! thing that failed.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_db::s3_targets::{S3Target, S3TargetFields};

use crate::auth::CurrentUser;
use crate::errors::{conflict, error, internal_error, not_enough_permissions, not_found};
use crate::s3::Endpoint;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/maintenance/s3-targets",
            get(list).post(create).fallback(crate::fallback),
        )
        .route(
            "/maintenance/s3-targets/{target_id}",
            put(update).delete(remove).fallback(crate::fallback),
        )
        .route(
            "/maintenance/s3-targets/{target_id}/test",
            post(test).fallback(crate::fallback),
        )
}

fn is_admin(current: &CurrentUser) -> bool {
    permissions::has_role(&current.user.role, Role::Admin)
}

fn unprocessable(message: &str) -> Response {
    error(StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// Everything but the secret, which is never sent back.
fn s3_json(row: &S3Target) -> Value {
    json!({
        "id": row.id,
        "name": row.name,
        "endpoint": row.endpoint,
        "region": row.region,
        "bucket": row.bucket,
        "prefix": row.prefix,
        "access_key": row.access_key,
        "path_style": row.path_style,
        "is_active": row.is_active,
    })
}

/// A destination's settings as sent, checked and normalised.
struct Fields {
    name: String,
    endpoint: Endpoint,
    region: String,
    bucket: String,
    prefix: String,
    access_key: String,
    path_style: bool,
}

fn text<'a>(body: &'a Value, field: &str) -> &'a str {
    body.get(field).and_then(Value::as_str).unwrap_or("").trim()
}

fn read_fields(body: &Value) -> Result<Fields, Response> {
    let name = text(body, "name");
    let name_ok = (2..=64).contains(&name.chars().count())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b' ' | b'-'));
    if !name_ok {
        return Err(unprocessable(
            "The name is 2 to 64 letters, digits, spaces, dots, dashes or underscores.",
        ));
    }
    let endpoint =
        crate::s3::parse_endpoint(text(body, "endpoint")).map_err(|m| unprocessable(&m))?;
    let region = match text(body, "region") {
        "" => "us-east-1",
        region => region,
    };
    if !crate::s3::valid_region(region) {
        return Err(unprocessable(
            "The region is letters, digits, dashes and underscores - us-east-1, or auto for R2.",
        ));
    }
    let bucket = text(body, "bucket");
    if !crate::s3::valid_bucket(bucket) {
        return Err(unprocessable(
            "The bucket name is 3 to 63 lower-case letters, digits, dots and dashes.",
        ));
    }
    let prefix = crate::s3::normalise_prefix(text(body, "prefix")).ok_or_else(|| {
        unprocessable("The folder is letters, digits, dots, dashes and underscores, split by /.")
    })?;
    let access_key = text(body, "access_key");
    if !crate::s3::valid_key(access_key, 128) {
        return Err(unprocessable(
            "The access key is required, and has no spaces.",
        ));
    }
    let path_style = match body.get("path_style") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(unprocessable("path_style must be true or false")),
    };
    if let Some(problem) = crate::s3::addressing_problem(&endpoint, bucket, path_style) {
        return Err(unprocessable(problem));
    }
    Ok(Fields {
        name: name.to_string(),
        endpoint,
        region: region.to_string(),
        bucket: bucket.to_string(),
        prefix,
        access_key: access_key.to_string(),
        path_style,
    })
}

/// The secret key as sent, encrypted; `None` when it was left blank.
fn read_secret(state: &AppState, body: &Value) -> Result<Option<String>, Response> {
    match text(body, "secret_key") {
        "" => Ok(None),
        secret if crate::s3::valid_key(secret, 256) => Ok(Some(
            snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, secret),
        )),
        _ => Err(unprocessable("The secret key has no spaces.")),
    }
}

async fn by_id(state: &AppState, target_id: i64) -> Result<S3Target, Response> {
    match state.db.s3_targets().by_id(target_id).await {
        Ok(Some(row)) => Ok(row),
        Ok(None) => Err(not_found("S3 destination not found")),
        Err(e) => {
            tracing::error!("reading S3 destination {target_id} failed: {e}");
            Err(internal_error())
        }
    }
}

async fn name_free(state: &AppState, name: &str, except: Option<i64>) -> Result<(), Response> {
    match state.db.s3_targets().name_taken(name, except).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(conflict("An S3 destination with this name already exists")),
        Err(e) => {
            tracing::error!("S3 destination lookup failed: {e}");
            Err(internal_error())
        }
    }
}

/// The caller, when an administrator, and the JSON body.
async fn admin_request(
    state: &AppState,
    req: axum::extract::Request,
) -> Result<(axum::http::request::Parts, CurrentUser, Value), Response> {
    let (mut parts, body) = req.into_parts();
    let current = CurrentUser::from_parts(&mut parts, state).await?;
    if !is_admin(&current) {
        return Err(not_enough_permissions());
    }
    let body = super::auth::read_json_body(body).await?;
    Ok((parts, current, body))
}

async fn list(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !is_admin(&current) {
        return not_enough_permissions();
    }
    match state.db.s3_targets().list().await {
        Ok(rows) => axum::Json(rows.iter().map(s3_json).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!("listing S3 destinations failed: {e}");
            internal_error()
        }
    }
}

async fn create(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (parts, current, body) = match admin_request(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fields = match read_fields(&body) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let secret = match read_secret(&state, &body) {
        Ok(Some(secret)) => secret,
        Ok(None) => return unprocessable("The secret key is required."),
        Err(r) => return r,
    };
    if let Err(r) = name_free(&state, &fields.name, None).await {
        return r;
    }
    let endpoint = fields.endpoint.url();
    let row = S3TargetFields {
        name: &fields.name,
        endpoint: &endpoint,
        region: &fields.region,
        bucket: &fields.bucket,
        prefix: &fields.prefix,
        access_key: &fields.access_key,
        path_style: fields.path_style,
    };
    let id = match state
        .db
        .s3_targets()
        .create(&row, &secret, &snpanel_db::sqlalchemy_now())
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("creating an S3 destination failed: {e}");
            return internal_error();
        }
    };
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "create_s3_target",
        &fields.name,
    )
    .await;
    match by_id(&state, id).await {
        Ok(row) => axum::Json(s3_json(&row)).into_response(),
        Err(r) => r,
    }
}

async fn update(
    State(state): State<AppState>,
    Path(target_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (parts, current, body) = match admin_request(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = by_id(&state, target_id).await {
        return r;
    }
    let fields = match read_fields(&body) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let secret = match read_secret(&state, &body) {
        Ok(secret) => secret,
        Err(r) => return r,
    };
    if let Err(r) = name_free(&state, &fields.name, Some(target_id)).await {
        return r;
    }
    let endpoint = fields.endpoint.url();
    let row = S3TargetFields {
        name: &fields.name,
        endpoint: &endpoint,
        region: &fields.region,
        bucket: &fields.bucket,
        prefix: &fields.prefix,
        access_key: &fields.access_key,
        path_style: fields.path_style,
    };
    if let Err(e) = state
        .db
        .s3_targets()
        .update(target_id, &row, secret.as_deref())
        .await
    {
        tracing::error!("updating S3 destination {target_id} failed: {e}");
        return internal_error();
    }
    let detail = if secret.is_some() {
        "new secret key"
    } else {
        ""
    };
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "update_s3_target",
        &fields.name,
        detail,
    )
    .await;
    match by_id(&state, target_id).await {
        Ok(row) => axum::Json(s3_json(&row)).into_response(),
        Err(r) => r,
    }
}

async fn remove(
    State(state): State<AppState>,
    Path(target_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !is_admin(&current) {
        return not_enough_permissions();
    }
    let row = match by_id(&state, target_id).await {
        Ok(row) => row,
        Err(r) => return r,
    };
    match state.db.s3_targets().schedules_using(target_id).await {
        Ok(ids) if ids.is_empty() => {}
        Ok(ids) => {
            let ids: Vec<String> = ids.iter().map(|id| format!("#{id}")).collect();
            return conflict(&format!(
                "Backup schedule {} uploads here. Delete the schedule first.",
                ids.join(", ")
            ));
        }
        Err(e) => {
            tracing::error!("reading the schedules of S3 destination {target_id} failed: {e}");
            return internal_error();
        }
    }
    if let Err(e) = state.db.s3_targets().delete(target_id).await {
        tracing::error!("deleting S3 destination {target_id} failed: {e}");
        return internal_error();
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "delete_s3_target",
        &row.name,
    )
    .await;
    axum::Json(json!({ "ok": true })).into_response()
}

/// Writes one small object and removes it: whether backups will get there.
async fn test(
    State(state): State<AppState>,
    Path(target_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    if !is_admin(&current) {
        return not_enough_permissions();
    }
    let row = match by_id(&state, target_id).await {
        Ok(row) => row,
        Err(r) => return r,
    };
    let secret = match secret_of(&state, target_id).await {
        Ok(secret) => secret,
        Err(message) => return error(StatusCode::BAD_GATEWAY, &message),
    };
    let endpoint = match crate::s3::parse_endpoint(&row.endpoint) {
        Ok(endpoint) => endpoint,
        Err(message) => return unprocessable(&message),
    };
    let target = crate::s3::Target {
        endpoint: &endpoint,
        region: &row.region,
        bucket: &row.bucket,
        prefix: &row.prefix,
        access_key: &row.access_key,
        secret_key: &secret,
        path_style: row.path_style,
    };
    match crate::s3::check(&target).await {
        Ok(removed) => {
            let message = if removed {
                format!("{} accepts backups.", row.name)
            } else {
                format!(
                    "{} accepts backups. The key may not delete, so the test file {} is still there.",
                    row.name,
                    crate::s3::object_key(&row.prefix, crate::s3::CHECK_OBJECT)
                )
            };
            axum::Json(json!({ "ok": true, "removed": removed, "message": message }))
                .into_response()
        }
        Err(e) => error(StatusCode::BAD_GATEWAY, &e.0),
    }
}

/// The secret key, decrypted - for the upload and the test, nothing else.
async fn secret_of(state: &AppState, target_id: i64) -> Result<String, String> {
    let stored = state
        .db
        .s3_targets()
        .secret(target_id)
        .await
        .map_err(|e| format!("Could not read the S3 destination: {e}"))?
        .ok_or_else(|| "S3 destination not found".to_string())?;
    snpanel_core::crypto::fernet::decrypt(
        &state.settings.secret_key,
        Some(&stored),
        state.settings.strict_decrypt,
    )
    .ok()
    .filter(|secret| !secret.is_empty())
    .ok_or_else(|| {
        "Failed to decrypt the S3 secret key; please enter it again on the destination".to_string()
    })
}

/// An archive to an S3 destination: the destination's name, and where the
/// object went (`s3://bucket/key`).
pub(crate) async fn upload_archive(
    state: &AppState,
    target_id: i64,
    archive: &str,
) -> Result<(String, String), String> {
    let (row, secret, endpoint) = open(state, target_id).await?;
    let target = target_of(&row, &secret, &endpoint);
    let uploaded = crate::s3::upload(archive, &target).await.map_err(|e| e.0)?;
    Ok((row.name, uploaded.location))
}

/// The bucket kept to a schedule's retention, as the local folder is: of the
/// archives `style` names for `username`, the newest `keep` stay. How many
/// went. The styles whose names repeat replace their object instead.
pub(crate) async fn prune_archives(
    state: &AppState,
    target_id: i64,
    username: &str,
    style: snpanel_db::s3_targets::NameStyle,
    keep: i64,
) -> Result<usize, String> {
    let Some(start) = crate::backups::family_start(username, style) else {
        return Ok(0);
    };
    let (row, secret, endpoint) = open(state, target_id).await?;
    let target = target_of(&row, &secret, &endpoint);
    let listed = crate::s3::list_keys(&target, &crate::s3::object_key(&row.prefix, &start))
        .await
        .map_err(|e| e.0)?;
    let old = crate::backups::past_retention(&listed, &row.prefix, username, style, keep);
    for key in &old {
        crate::s3::delete_key(&target, key).await.map_err(|e| e.0)?;
    }
    Ok(old.len())
}

/// A destination that may be used: its row, its secret, its endpoint.
async fn open(state: &AppState, target_id: i64) -> Result<(S3Target, String, Endpoint), String> {
    let row = match state.db.s3_targets().by_id(target_id).await {
        Ok(Some(row)) if row.is_active => row,
        Ok(_) => return Err("S3 destination not found".to_string()),
        Err(e) => return Err(format!("Could not read the S3 destination: {e}")),
    };
    let secret = secret_of(state, target_id).await?;
    let endpoint = crate::s3::parse_endpoint(&row.endpoint)?;
    Ok((row, secret, endpoint))
}

fn target_of<'a>(
    row: &'a S3Target,
    secret: &'a str,
    endpoint: &'a Endpoint,
) -> crate::s3::Target<'a> {
    crate::s3::Target {
        endpoint,
        region: &row.region,
        bucket: &row.bucket,
        prefix: &row.prefix,
        access_key: &row.access_key,
        secret_key: secret,
        path_style: row.path_style,
    }
}

/// Whether a destination a request names is there to upload to.
pub(crate) async fn usable(state: &AppState, target_id: i64) -> Result<(), Response> {
    match state.db.s3_targets().by_id(target_id).await {
        Ok(Some(row)) if row.is_active => Ok(()),
        Ok(_) => Err(not_found("S3 destination not found")),
        Err(e) => {
            tracing::error!("reading S3 destination {target_id} failed: {e}");
            Err(internal_error())
        }
    }
}
