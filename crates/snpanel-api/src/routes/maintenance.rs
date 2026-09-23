//! `/api/maintenance` - the file manager, for now.
//!
//! The module is 67 endpoints across five unrelated areas: backups, restore,
//! PHP, cron and the file manager. Plan §8 Stage C says to take it by
//! sub-area rather than whole, and this is the first: browsing, reading and
//! downloading a customer's files.
//!
//! | endpoint | notes |
//! | --- | --- |
//! | `GET /files/{id}` | a listing; symlinks are hidden, not followed |
//! | `GET /files/{id}/read` | text only, 2MB ceiling |
//! | `GET /files/{id}/download` | the bytes, as an attachment |
//!
//! Everything here resolves paths through [`crate::files::safe_path`], which
//! refuses a symlink anywhere along the way. That is the check the whole
//! screen rests on.

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;
use std::collections::HashMap;

use crate::auth::CurrentUser;
use crate::backups;
use crate::errors::{bad_request, conflict, internal_error, not_found};
use crate::files;
use crate::php;
use crate::shell;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/maintenance/files/{website_id}",
            get(list_files)
                .delete(delete_file)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/{website_id}/upload",
            post(upload_file).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/{website_id}/read",
            get(read_file).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/{website_id}/download",
            get(download_file).fallback(crate::fallback),
        )
        // A separate prefix on purpose: under `/files` these would be
        // shadowed by `/files/{website_id}` and answer 422 instead of
        // dispatching here.
        .route(
            "/maintenance/app-files/{app_id}",
            get(list_app_files).fallback(crate::fallback),
        )
        .route(
            "/maintenance/app-files/{app_id}/read",
            get(read_app_file).fallback(crate::fallback),
        )
        .route(
            "/maintenance/app-files/{app_id}/download",
            get(download_app_file).fallback(crate::fallback),
        )
        .route(
            "/maintenance/app-files/{app_id}/upload",
            post(upload_app_file).fallback(crate::fallback),
        )
        .route(
            "/maintenance/backup",
            post(queue_site_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/backup-jobs",
            get(list_backup_jobs).fallback(crate::fallback),
        )
        .route(
            "/maintenance/backup-jobs/{job_id}",
            get(get_backup_job).fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-backup",
            post(queue_user_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/backup-sftp",
            post(queue_sftp_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-restore",
            post(restore_user_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/mkdir",
            post(make_directory).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/rename",
            post(rename_entry).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/chmod",
            post(chmod_entry).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/delete",
            post(delete_entries).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/move",
            post(move_entries).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/copy",
            post(copy_entries).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/create",
            post(create_file).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/write",
            post(write_file).fallback(crate::fallback),
        )
        // These three move together on purpose: the registry they share is
        // process-local, so the endpoint that creates a job and the two
        // that read it have to be on the same side of the proxy.
        .route(
            "/maintenance/files/archive",
            post(archive_entries).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/extract",
            post(extract_archive).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/jobs",
            get(list_file_jobs).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/jobs/{job_id}",
            get(get_file_job).fallback(crate::fallback),
        )
        .route(
            "/maintenance/da-import/upload",
            post(upload_da_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/da-import/backups",
            get(list_da_backups)
                .delete(delete_da_backup)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/da-import/scan",
            post(scan_da_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/da-import/import",
            post(start_da_import).fallback(crate::fallback),
        )
        .route(
            "/maintenance/da-import/jobs/{job_id}",
            get(get_da_import_job).fallback(crate::fallback),
        )
        .route(
            "/maintenance/da-import/bulk-import",
            post(start_da_bulk_import).fallback(crate::fallback),
        )
        .route(
            "/maintenance/da-import/bulk-jobs/{job_id}",
            get(get_da_bulk_import_job).fallback(crate::fallback),
        )
        .route(
            "/maintenance/wordpress",
            post(wordpress_action).fallback(crate::fallback),
        )
        .route(
            "/maintenance/wordpress/{website_id}/fix-permissions",
            post(fix_wordpress_permissions).fallback(crate::fallback),
        )
        .route(
            "/maintenance/cron",
            post(add_cron).delete(delete_cron).fallback(crate::fallback),
        )
        .route(
            "/maintenance/cron/{website_id}",
            get(list_cron).fallback(crate::fallback),
        )
        .route(
            "/maintenance/backups/{website_id}",
            get(list_site_backups)
                .delete(delete_site_backup)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/backups/{website_id}/download",
            get(download_site_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/backups/{website_id}/upload",
            post(upload_site_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/restore",
            post(restore_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-backups/upload",
            post(upload_user_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-backups/{user_id}",
            get(list_account_backups).fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-backups-download",
            get(download_account_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-backups",
            axum::routing::delete(delete_account_backup).fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-restore-backups",
            get(list_restore_backups)
                .delete(delete_restore_backup)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/user-restore-backups/upload",
            post(upload_restore_backups).fallback(crate::fallback),
        )
        .route(
            "/maintenance/backup-schedules",
            get(list_backup_schedules)
                .post(create_backup_schedule)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/backup-schedules/{schedule_id}",
            axum::routing::delete(delete_backup_schedule).fallback(crate::fallback),
        )
        .route(
            "/maintenance/sftp-targets",
            get(list_sftp_targets)
                .post(create_sftp_target)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/sftp-targets/{target_id}",
            axum::routing::delete(delete_sftp_target).fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-config",
            get(get_php_config)
                .post(update_php_config)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-config/defaults",
            post(restore_php_defaults).fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-tune",
            get(get_php_tune)
                .post(apply_php_tune)
                .fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-tune/pools",
            post(retune_php_pools).fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-opcache",
            post(toggle_php_opcache).fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-versions",
            get(get_php_versions).fallback(crate::fallback),
        )
        .route(
            "/maintenance/php-versions/{php_version}/install",
            post(install_php_version).fallback(crate::fallback),
        )
}

/// Source: `get_owned_website` - the site, if this caller may see it.
///
/// Not owner-or-admin as a single test: the Python looks the site up first,
/// so an id that does not exist is a 404 for an administrator and for a
/// customer alike, and only then checks ownership.
async fn owned(
    state: &AppState,
    current: &CurrentUser,
    website_id: i64,
) -> Result<snpanel_db::Website, Response> {
    let website = state
        .db
        .websites()
        .by_id(website_id)
        .await
        .map_err(|e| {
            tracing::error!("website lookup failed: {e}");
            internal_error()
        })?
        .ok_or_else(|| not_found("Website not found"))?;
    if website.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return Err(crate::errors::not_enough_permissions());
    }
    Ok(website)
}

/// The tree a file operation runs in: a website root or an application root.
///
/// Source: `get_file_target` and the `AppFileTarget` adapter beside it.
/// `file_manager` reads `root_path` and `linux_user` and nothing else, so an
/// application can be handed to it directly rather than duplicating the whole
/// module.
pub(crate) struct FileTarget {
    pub root_path: String,
    pub linux_user: Option<String>,
    /// What the audit log names. An application has no domain of its own, so
    /// it is labelled `app:<name>`.
    pub label: String,
    /// The storage quota is charged to whoever owns the tree.
    pub owner_id: i64,
    /// An application's own files are code: a `.js` entry point or a build
    /// script has to be allowed to arrive executable, which for a website is
    /// an administrator-only thing to do.
    pub allow_executable: Option<bool>,
}

impl FileTarget {
    fn website(site: &snpanel_db::Website) -> FileTarget {
        FileTarget {
            root_path: site.root_path.clone(),
            linux_user: site.linux_user.clone(),
            label: site.domain.clone(),
            owner_id: site.owner_id,
            // `is_admin_role(current_user.role)` decides for a website, so
            // this is left for the caller to fill in.
            allow_executable: None,
        }
    }
}

/// Source: `get_file_target(db, user, app_id=...)`.
///
/// The addon guard first, then the app, then the self-heal: an app created
/// before the directory was made at creation time, or by a release that left
/// it unreadable by the panel user, gets it made now.
async fn app_target(
    state: &AppState,
    current: &CurrentUser,
    app_id: i64,
) -> Result<FileTarget, Response> {
    super::addons::require_application()?;
    let app = match state.db.site_apps().full_by_id(app_id).await {
        Ok(Some(app)) => app,
        Ok(None) => return Err(not_found("Application not found")),
        Err(e) => {
            tracing::error!("reading application {app_id} failed: {e}");
            return Err(internal_error());
        }
    };
    if app.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return Err(crate::errors::not_enough_permissions());
    }
    let root_path = match crate::site_apps::directory_for(&app) {
        Ok(path) => path,
        Err(why) => return Err(bad_request(&why)),
    };
    // `os.access(root, os.R_OK)` — readable by *this* process, not merely
    // present.
    if std::fs::read_dir(&root_path).is_err() {
        let _ = crate::site_apps::ensure_directory(state.settings.command_dry_run, &app).await;
    }
    Ok(FileTarget {
        root_path,
        linux_user: crate::site_apps::owner_linux_user(&app).ok(),
        label: format!("app:{}", app.name),
        owner_id: app.owner_id,
        allow_executable: Some(true),
    })
}

/// Source: `list_files`.
async fn list_files(
    State(state): State<AppState>,
    AxumPath(website_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    list_in(&FileTarget::website(&website), &params)
}

/// Source: `list_app_files`. A separate prefix on purpose: under `/files`
/// this would be shadowed by `/files/{website_id}` and answer 422 instead of
/// dispatching here.
async fn list_app_files(
    State(state): State<AppState>,
    AxumPath(app_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let target = match app_target(&state, &current, app_id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    list_in(&target, &params)
}

fn list_in(target: &FileTarget, params: &HashMap<String, String>) -> Response {
    let path = params.get("path").cloned().unwrap_or_default();
    match files::list_files(&target.root_path, &path) {
        Ok(items) => axum::Json(json!({ "items": items })).into_response(),
        // The Python lets the ValueError out of `list_files` unhandled, and
        // FastAPI turns that into a 500. Matching it rather than improving
        // it: a 400 here would be a different answer to the same request.
        Err(e) => {
            tracing::warn!("listing files failed: {e}");
            internal_error()
        }
    }
}

/// Source: `read_file` -> `file_manager.read_text_file`.
async fn read_file(
    State(state): State<AppState>,
    AxumPath(website_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    read_in(&state, &current, &FileTarget::website(&website), &params).await
}

/// Source: `read_app_file`.
async fn read_app_file(
    State(state): State<AppState>,
    AxumPath(app_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let target = match app_target(&state, &current, app_id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    read_in(&state, &current, &target, &params).await
}

async fn read_in(
    state: &AppState,
    current: &CurrentUser,
    site: &FileTarget,
    params: &HashMap<String, String>,
) -> Response {
    let Some(path) = params.get("path") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "path"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    let allow_sensitive = permissions::is_admin_role(&current.user.role);
    let target = match files::readable_text_file(&site.root_path, path, allow_sensitive) {
        Ok(t) => t,
        Err(e) => return bad_request(&e.to_string()),
    };

    // A site with a Linux user owns its files, and the panel account cannot
    // read into them - so the read happens as that user, through the helper.
    match site.linux_user.as_deref().filter(|u| !u.is_empty()) {
        Some(user) => {
            let root = std::fs::canonicalize(&site.root_path)
                .unwrap_or_else(|_| std::path::PathBuf::from(&site.root_path));
            let root_str = root.to_string_lossy().into_owned();
            let relative = files::helper_relative_path(&site.root_path, &target);
            let full = target.to_string_lossy().into_owned();
            let result = shell::privileged(
                state.settings.command_dry_run,
                "terminal-exec",
                &[user, &root_str, "cat", &relative],
                None,
                Some(&["cat", &full]),
            )
            .await;
            if !result.ok() {
                return bad_request(result.failure_detail("Cannot read the file").trim());
            }
            axum::Json(json!({ "content": result.stdout })).into_response()
        }
        None => match std::fs::read_to_string(&target) {
            Ok(content) => axum::Json(json!({ "content": content })).into_response(),
            Err(e) => {
                tracing::warn!("reading {} failed: {e}", target.display());
                internal_error()
            }
        },
    }
}

/// Source: `download_file` - FastAPI's `FileResponse(path, filename=name)`.
async fn download_file(
    State(state): State<AppState>,
    AxumPath(website_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    download_in(&current, &FileTarget::website(&website), &params).await
}

/// Source: `download_app_file`.
async fn download_app_file(
    State(state): State<AppState>,
    AxumPath(app_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let target = match app_target(&state, &current, app_id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    download_in(&current, &target, &params).await
}

async fn download_in(
    current: &CurrentUser,
    site: &FileTarget,
    params: &HashMap<String, String>,
) -> Response {
    let Some(path) = params.get("path") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "path"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    let allow_sensitive = permissions::is_admin_role(&current.user.role);
    let target = match files::download_file_path(&site.root_path, path, allow_sensitive) {
        Ok(t) => t,
        Err(e) => return bad_request(&e.to_string()),
    };

    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let bytes = match tokio::fs::read(&target).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("reading {} failed: {e}", target.display());
            return internal_error();
        }
    };

    // Source: Starlette's `FileResponse`, which guesses the type from the
    // suffix and falls back to octet-stream, and quotes the filename.
    let media = mime_for(&name);
    (
        [
            (axum::http::header::CONTENT_TYPE, media.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        Body::from(bytes),
    )
        .into_response()
}

/// The handful of types Starlette's `mimetypes` guesses for files a customer
/// downloads from a web root. Anything else is `application/octet-stream`,
/// which is also what Starlette falls back to.
fn mime_for(name: &str) -> &'static str {
    let suffix = name.rsplit_once('.').map(|(_, s)| s.to_lowercase());
    match suffix.as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("txt" | "log" | "md") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz") => "application/gzip",
        Some("tar") => "application/x-tar",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// the file manager's write operations
// ---------------------------------------------------------------------------

/// Source: `get_file_target`.
///
/// The screens pass either a website or an application. Applications need
/// `site_apps`, which is not ported, so those requests are handed back to
/// Python with their body intact rather than answered wrongly here.
enum Target {
    // Boxed because the other variant carries nothing, and a `Website` is
    // half a kilobyte: without it every `Target` on the stack is that big.
    Website(Box<snpanel_db::Website>),
    /// `app_id` was given: Python's job for now.
    Upstream,
}

async fn file_target(
    state: &AppState,
    current: &CurrentUser,
    payload: &serde_json::Value,
) -> Result<Target, Response> {
    let app_id = payload.get("app_id").and_then(Value::as_i64).unwrap_or(0);
    if app_id != 0 {
        return Ok(Target::Upstream);
    }
    match payload.get("website_id").and_then(Value::as_i64) {
        Some(id) if id != 0 => owned(state, current, id)
            .await
            .map(|w| Target::Website(Box::new(w))),
        _ => Err(bad_request("Pick a website or an application to browse")),
    }
}

/// Hand the request back to Python, body and all.
///
/// The body was already consumed to read `app_id`, so it is put back rather
/// than proxied from a stream that has been drained.
async fn to_upstream(
    state: &AppState,
    parts: axum::http::request::Parts,
    body: axum::body::Bytes,
) -> Response {
    let req = axum::http::Request::from_parts(parts, Body::from(body));
    crate::fallback(State(state.clone()), req).await
}

/// Read the body once, keep the bytes, and parse them.
async fn body_and_json(body: Body) -> Result<(axum::body::Bytes, serde_json::Value), Response> {
    let bytes = match axum::body::to_bytes(body, 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Err(bad_request("Invalid request body")),
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return Err(crate::errors::validation_error(vec![json!({
                "type": "json_invalid",
                "loc": ["body", 0],
                "msg": "JSON decode error",
                "input": {},
            })]))
        }
    };
    Ok((bytes, value))
}

/// A `list[str]` body field, with pydantic's two refusals.
///
/// A missing field and a field that is not a list are different errors, and
/// so is a list with a non-string in it — the panel shows the message, and
/// "Field required" for a typo in a list is not the same help as "Input
/// should be a valid string".
fn string_list_field(payload: &Value, name: &str) -> Result<Vec<String>, Response> {
    let Some(items) = payload.get(name) else {
        return Err(crate::errors::missing_field(name, payload.clone()));
    };
    let Some(items) = items.as_array() else {
        return Err(crate::errors::list_type(name, items));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::String(s) => out.push(s.clone()),
            other => return Err(crate::errors::string_type(name, other)),
        }
    }
    Ok(out)
}

fn string_field(payload: &Value, name: &str) -> Result<String, Response> {
    match payload.get(name) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(crate::errors::string_type(name, other)),
        None => Err(crate::errors::missing_field(name, payload.clone())),
    }
}

/// `site-path-fix` after a write, so the file belongs to the site's user.
async fn fix_site_path(state: &AppState, path: &str, linux_user: Option<&str>) {
    let Some(user) = linux_user.filter(|u| !u.is_empty()) else {
        return;
    };
    let owner = format!("{user}:{user}");
    let _ = shell::privileged(
        state.settings.command_dry_run,
        "site-path-fix",
        &[path, user],
        None,
        Some(&["chown", "-R", &owner, path]),
    )
    .await;
}

/// Source: `_clear_fastcgi_cache` - best effort, and the Python swallows a
/// missing helper because development boxes do not install one.
async fn clear_fastcgi_cache(state: &AppState) {
    let _ = shell::privileged(
        state.settings.command_dry_run,
        "fastcgi-cache-clear",
        &[],
        None,
        None,
    )
    .await;
}

/// Run a command inside the site, as the site's own user.
///
/// Source: `_run_as_site_user`. The verb is `terminal-exec`, which the Rust
/// helper does not implement - so it reaches the bash one through the
/// fallthrough, which is exactly what that fallthrough is for.
async fn run_as_site_user(
    state: &AppState,
    website: &snpanel_db::Website,
    command: &str,
    args: &[&str],
    fallback: &[&str],
) -> Result<(), Response> {
    let root = std::fs::canonicalize(&website.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
    run_in_site_dir(
        state,
        website,
        &root.to_string_lossy(),
        command,
        args,
        fallback,
    )
    .await
}

/// [`run_as_site_user`] with the working directory named.
///
/// The Python's `_run_as_site_user` has always taken a `cwd`; every caller
/// ported so far passed the site root, so the port folded it in. The
/// archive endpoint is the first that does not — `zip -r name -- items` has
/// to run **inside the folder being archived**, because that is what makes
/// the names inside the archive relative to it rather than to the root.
async fn run_in_site_dir(
    state: &AppState,
    website: &snpanel_db::Website,
    cwd: &str,
    command: &str,
    args: &[&str],
    fallback: &[&str],
) -> Result<(), Response> {
    let Some(user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) else {
        return Err(bad_request("Website has no runtime user configured"));
    };
    let root_str = cwd.to_string();
    let mut argv: Vec<&str> = vec![user, &root_str, command];
    argv.extend_from_slice(args);
    let result = shell::privileged(
        state.settings.command_dry_run,
        "terminal-exec",
        &argv,
        None,
        Some(fallback),
    )
    .await;
    if result.ok() {
        Ok(())
    } else {
        Err(bad_request(
            result.failure_detail("The command failed").trim(),
        ))
    }
}

/// `log_action` with a **detail** and no request.
///
/// `packages::audit_action` is the other shape: an empty detail plus `ip=`
/// and `ua=`. Both exist in the Python and they are not interchangeable - the
/// file-manager endpoints call `log_action(db, user.id, action, target,
/// detail)` with no `request=`, so an entry that carries ip/ua instead of the
/// paths is not the entry an administrator goes looking for after an
/// incident.
async fn audit_detail(state: &AppState, actor_id: i64, action: &str, target: &str, detail: &str) {
    if let Err(e) = state
        .db
        .audits()
        .log(Some(actor_id), action, target, detail)
        .await
    {
        // The Python logs and carries on: a failed audit write must not turn a
        // completed operation into a 500 the customer retries.
        tracing::error!("could not write the {action} audit entry: {e}");
    }
}

/// Source: `make_directory`.
async fn make_directory(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    // `path` defaults to the public directory, the way the model does.
    let parent_rel = payload
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("public_html")
        .to_string();
    let name = match string_field(&payload, "name") {
        Ok(v) => v,
        Err(r) => return r,
    };

    let parent = match files::safe_path(&website.root_path, &parent_rel, false) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !parent.is_dir() {
        return bad_request("Parent directory not found");
    }
    let safe_name = match files::safe_entry_name(&name) {
        Ok(n) => n,
        Err(e) => return bad_request(&e.to_string()),
    };
    let target = parent.join(&safe_name);
    if target.exists() {
        return bad_request("File or folder already exists");
    }

    let target_str = target.to_string_lossy().into_owned();
    if website.linux_user.as_deref().is_some_and(|u| !u.is_empty()) {
        let relative = files::helper_relative_path(&website.root_path, &target);
        if let Err(r) = run_as_site_user(
            &state,
            &website,
            "mkdir",
            &["--", &relative],
            &["mkdir", "--", &target_str],
        )
        .await
        {
            return r;
        }
    } else if let Err(e) = std::fs::create_dir(&target) {
        tracing::warn!("mkdir {} failed: {e}", target.display());
        return bad_request("Parent directory not found");
    }
    fix_site_path(&state, &target_str, website.linux_user.as_deref()).await;
    clear_fastcgi_cache(&state).await;

    super::packages::audit_action(&state, &parts, current.user.id, "mkdir", &website.domain).await;
    axum::Json(json!({ "target": target_str })).into_response()
}

/// Source: `rename_entry`.
async fn rename_entry(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let path = match string_field(&payload, "path") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let new_name = match string_field(&payload, "new_name") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let allow_executable = permissions::is_admin_role(&current.user.role);

    let source = match files::safe_path(&website.root_path, &path, false) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !source.exists() {
        return bad_request("File or folder not found");
    }
    let root = std::fs::canonicalize(&website.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
    if source == root {
        return bad_request("Cannot rename website root");
    }
    let safe_name = match files::safe_entry_name(&new_name) {
        Ok(n) => n,
        Err(e) => return bad_request(&e.to_string()),
    };
    let target = match source.parent() {
        Some(p) => p.join(&safe_name),
        None => return bad_request("Cannot rename website root"),
    };
    if target.exists() {
        return bad_request("Target already exists");
    }
    if let Err(e) = files::assert_tree_write_allowed(&source, "Renaming", allow_executable, false) {
        return bad_request(&e.to_string());
    }
    if let Err(e) = files::assert_write_allowed(&target, "Renaming", allow_executable) {
        return bad_request(&e.to_string());
    }

    let source_str = source.to_string_lossy().into_owned();
    let target_str = target.to_string_lossy().into_owned();
    if website.linux_user.as_deref().is_some_and(|u| !u.is_empty()) {
        let from = files::helper_relative_path(&website.root_path, &source);
        let to = files::helper_relative_path(&website.root_path, &target);
        if let Err(r) = run_as_site_user(
            &state,
            &website,
            "mv",
            &["--", &from, &to],
            &["mv", "--", &source_str, &target_str],
        )
        .await
        {
            return r;
        }
    } else if let Err(e) = std::fs::rename(&source, &target) {
        tracing::warn!("rename failed: {e}");
        return bad_request("File or folder not found");
    }
    fix_site_path(&state, &target_str, website.linux_user.as_deref()).await;
    clear_fastcgi_cache(&state).await;

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "rename_file",
        &website.domain,
    )
    .await;
    axum::Json(json!({ "target": target_str })).into_response()
}

/// Source: `chmod_entry`.
///
/// Deliberately **not** run as the site user: that account is outside the
/// site group, so the kernel would strip setgid from directories and break
/// group inheritance under `public_html`.
async fn chmod_entry(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let path = match string_field(&payload, "path") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mode = match string_field(&payload, "mode") {
        Ok(v) => v,
        Err(r) => return r,
    };

    let target = match files::safe_path(&website.root_path, &path, false) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !target.exists() {
        return bad_request("File or folder not found");
    }
    if std::fs::symlink_metadata(&target)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return bad_request("Symlinks are not allowed");
    }
    let numeric = match files::parse_chmod_mode(&mode, target.is_dir()) {
        Ok(n) => n,
        Err(e) => return bad_request(&e.to_string()),
    };
    // chmod keeps a directory's special bits for an ordinary numeric mode and
    // only honours the special digit given an extra leading zero, so the fully
    // explicit form goes across: what the caller asked for is what is applied.
    let explicit = format!("0{numeric:04o}");
    let target_str = target.to_string_lossy().into_owned();

    if website.linux_user.as_deref().is_some_and(|u| !u.is_empty()) {
        let root = std::fs::canonicalize(&website.root_path)
            .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
        let root_str = root.to_string_lossy().into_owned();
        let user = website.linux_user.as_deref().unwrap_or("");
        let result = shell::privileged(
            state.settings.command_dry_run,
            "site-chmod",
            &[user, &root_str, &target_str, &explicit],
            None,
            Some(&["chmod", &explicit, &target_str]),
        )
        .await;
        if !result.ok() {
            return bad_request(result.failure_detail("Cannot change the mode").trim());
        }
    } else {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(numeric))
        {
            tracing::warn!("chmod failed: {e}");
            return bad_request("File or folder not found");
        }
    }
    clear_fastcgi_cache(&state).await;

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "chmod_file",
        &website.domain,
    )
    .await;
    axum::Json(json!({ "target": target_str, "mode": mode })).into_response()
}

/// Source: `delete_entries`.
///
/// Every path is checked before anything is removed. A half-finished delete
/// is worse than a refused one: the customer cannot tell which of their
/// selection went.
async fn delete_entries(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let Some(paths) = payload.get("paths").and_then(Value::as_array) else {
        return crate::errors::missing_field("paths", payload.clone());
    };
    let allow_executable = permissions::is_admin_role(&current.user.role);
    let root = std::fs::canonicalize(&website.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));

    let mut targets: Vec<std::path::PathBuf> = Vec::new();
    for value in paths {
        let Some(relative) = value.as_str() else {
            return crate::errors::string_type("paths", value);
        };
        let target = match files::safe_path(&website.root_path, relative, true) {
            Ok(t) => t,
            Err(e) => return bad_request(&e.to_string()),
        };
        let is_link = std::fs::symlink_metadata(&target)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if !target.exists() && !is_link {
            return bad_request("File or folder not found");
        }
        if target == root {
            return bad_request("Cannot delete website root");
        }
        if let Err(e) =
            files::assert_tree_write_allowed(&target, "Deleting", allow_executable, true)
        {
            return bad_request(&e.to_string());
        }
        targets.push(target);
    }

    let root_str = root.to_string_lossy().into_owned();
    let user = website.linux_user.clone().unwrap_or_default();
    let mut deleted: Vec<String> = Vec::new();
    let mut deleted_dirs: Vec<std::path::PathBuf> = Vec::new();
    for target in targets {
        // Anything already inside a directory this loop removed is skipped,
        // the way the Python skips it.
        if deleted_dirs.iter().any(|d| target.starts_with(d)) {
            continue;
        }
        let target_str = target.to_string_lossy().into_owned();
        let is_link = std::fs::symlink_metadata(&target)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let is_dir = target.is_dir() && !is_link;
        if !user.is_empty() {
            let fallback: [&str; 4] = if is_dir {
                ["rm", "-rf", "--", &target_str]
            } else {
                ["rm", "-f", "--", &target_str]
            };
            let result = shell::privileged(
                state.settings.command_dry_run,
                "rm-site",
                &[&user, &root_str, &target_str],
                None,
                Some(&fallback),
            )
            .await;
            if !result.ok() {
                return bad_request(result.failure_detail("Cannot delete").trim());
            }
        } else if is_dir {
            let _ = std::fs::remove_dir_all(&target);
        } else {
            let _ = std::fs::remove_file(&target);
        }
        if is_dir {
            deleted_dirs.push(target.clone());
        }
        deleted.push(target_str);
    }
    clear_fastcgi_cache(&state).await;

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "delete_files",
        &website.domain,
    )
    .await;
    axum::Json(json!({ "deleted": deleted })).into_response()
}

// ---------------------------------------------------------------------------
// backups: finding, downloading and removing archives
// ---------------------------------------------------------------------------

/// A file as an attachment, the way Starlette's `FileResponse` sends one.
async fn attachment(path: &std::path::Path, media_type: Option<&str>) -> Response {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("reading {} failed: {e}", path.display());
            return internal_error();
        }
    };
    let media = media_type.unwrap_or_else(|| mime_for(&name));
    (
        [
            (axum::http::header::CONTENT_TYPE, media.to_string()),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        Body::from(bytes),
    )
        .into_response()
}

/// Source: `get_backup_user` - the account whose backups these are.
async fn backup_user(
    state: &AppState,
    current: &CurrentUser,
    user_id: i64,
) -> Result<snpanel_db::User, Response> {
    let user = state
        .db
        .users()
        .by_id(user_id)
        .await
        .map_err(|e| {
            tracing::error!("user lookup failed: {e}");
            internal_error()
        })?
        .ok_or_else(|| not_found("User not found"))?;
    if user.id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return Err(crate::errors::not_enough_permissions());
    }
    Ok(user)
}

/// Source: `list_backups`.
async fn list_site_backups(
    State(state): State<AppState>,
    AxumPath(website_id): AxumPath<i64>,
    current: CurrentUser,
) -> Response {
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let items = backups::list_backups(
        &state.settings.backup_root,
        &website.domain,
        state.settings.command_dry_run,
    );
    axum::Json(json!({ "items": items })).into_response()
}

/// Source: `download_backup`.
async fn download_site_backup(
    State(state): State<AppState>,
    AxumPath(website_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let Some(file) = params.get("backup_file") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "backup_file"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    match backups::backup_path(&state.settings.backup_root, &website.domain, file) {
        Ok(path) => attachment(&path, Some("application/gzip")).await,
        Err(_) => not_found("Backup not found"),
    }
}

/// Source: `delete_backup`.
async fn delete_site_backup(
    State(state): State<AppState>,
    AxumPath(website_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let Some(file) = params.get("backup_file") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "backup_file"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    match backups::delete_backup(&state.settings.backup_root, &website.domain, file) {
        Ok(deleted) => {
            super::packages::audit_action(
                &state,
                &parts,
                current.user.id,
                "delete_backup",
                &website.domain,
            )
            .await;
            axum::Json(json!({ "deleted": deleted })).into_response()
        }
        Err(_) => not_found("Backup not found"),
    }
}

/// Source: `list_user_backups` - the account's own archives, plus the
/// uploaded ones when an administrator is asking.
async fn list_account_backups(
    State(state): State<AppState>,
    AxumPath(user_id): AxumPath<i64>,
    current: CurrentUser,
) -> Response {
    let user = match backup_user(&state, &current, user_id).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let mut items = match backups::list_user_backups(
        &state.settings.backup_root,
        &user.username,
        state.settings.command_dry_run,
    ) {
        Ok(v) => v,
        Err(e) => return bad_request(&e.to_string()),
    };
    if permissions::is_admin_role(&current.user.role) {
        let root = state.settings.backup_root.clone();
        let username = user.username.clone();
        let dry_run = state.settings.command_dry_run;
        // Reading a manifest out of each archive is blocking work, and there
        // may be a lot of them.
        let uploaded = tokio::task::spawn_blocking(move || {
            backups::list_uploaded_user_backups(&root, Some(&username), dry_run)
        })
        .await
        .unwrap_or_default();
        for item in uploaded {
            if !items.contains(&item) {
                items.push(item);
            }
        }
    }
    axum::Json(json!({ "items": items })).into_response()
}

/// Source: `download_user_backup`.
async fn download_account_backup(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    if !permissions::is_admin_role(&current.user.role) {
        return crate::errors::not_enough_permissions();
    }
    let Some(file) = params.get("backup_file") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "backup_file"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    match backups::user_backup_path(&state.settings.backup_root, file) {
        Ok(path) => attachment(&path, Some("application/gzip")).await,
        Err(_) => not_found("Backup not found"),
    }
}

/// Source: `delete_user_backup`.
async fn delete_account_backup(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::is_admin_role(&current.user.role) {
        return crate::errors::not_enough_permissions();
    }
    let Some(file) = params.get("backup_file") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "backup_file"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    match backups::delete_user_backup(&state.settings.backup_root, file) {
        Ok(deleted) => {
            super::packages::audit_action(
                &state,
                &parts,
                current.user.id,
                "delete_user_backup",
                "user",
            )
            .await;
            axum::Json(json!({ "deleted": deleted })).into_response()
        }
        Err(_) => not_found("Backup not found"),
    }
}

/// `POST /maintenance/restore`.
///
/// Source: `restore_backup` the endpoint and `backup.restore_backup`.
///
/// The archive was written by this panel, but it is a file on disk that an
/// administrator can replace, so **every member goes through the filter**
/// before it is written — and the filter rewrites as well as refuses, so a
/// restore cannot land a setuid binary owned by root inside a directory the
/// customer controls.
///
/// The extraction happens in this process rather than through the helper,
/// which is what the Python does: the site root is writable by the panel
/// user, and the ownership is corrected afterwards by `fix-permissions`.
async fn restore_backup(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (_, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website_id = match payload.get("website_id").and_then(Value::as_i64) {
        Some(id) => id,
        None => match payload.get("website_id") {
            Some(other) => return crate::errors::int_type("website_id", other),
            None => return crate::errors::missing_field("website_id", payload.clone()),
        },
    };
    let backup_file = match string_field(&payload, "backup_file") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    // `backup_path` confines the archive to this site's own backup folder,
    // so one customer cannot restore another's.
    let archive = match crate::backups::backup_path(
        &state.settings.backup_root,
        &website.domain,
        &backup_file,
    ) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    let destination = std::fs::canonicalize(&website.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));

    let archive_for_task = archive.clone();
    let destination_for_task = destination.clone();
    // Reading and writing a whole site is blocking and can take minutes, so
    // it does not run on a tokio worker other requests are waiting on.
    let extracted = tokio::task::spawn_blocking(move || {
        extract_site_backup(&archive_for_task, &destination_for_task)
    })
    .await;
    match extracted {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return bad_request(&e),
        Err(e) => {
            tracing::error!("the restore task failed: {e}");
            return crate::errors::internal_error();
        }
    }

    // Source: `site_users.ensure_site_runtime` — the PHP pool and the home
    // directory may have been removed while the site was broken.
    if let Some(user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) {
        let runtime_php = if matches!(website.app_type.as_str(), "" | "wordpress" | "php") {
            let v = website.php_version.clone();
            if v.is_empty() {
                "none".to_string()
            } else {
                v
            }
        } else {
            "none".to_string()
        };
        let fallback_dir = document_root_of(&website);
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "site-runtime-ensure",
            &[user, &website.root_path, &runtime_php],
            None,
            Some(&["mkdir", "-p", &fallback_dir]),
        )
        .await;
    }
    // Source: `wordpress.fix_permissions` — everything just written belongs
    // to whoever ran the extraction until this puts it back.
    let user = website.linux_user.clone().unwrap_or_default();
    if user.is_empty() {
        let owner = format!("{}:{}", web_user(), web_group());
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "fix-permissions",
            &[&website.root_path],
            None,
            Some(&["chown", "-R", &owner, &website.root_path]),
        )
        .await;
    } else if let Ok(safe_user) = snpanel_core::types::PanelUsername::parse(&user) {
        let owner = format!("{}:{}", safe_user.as_str(), safe_user.as_str());
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "fix-permissions",
            &[&website.root_path, safe_user.as_str()],
            None,
            Some(&["chown", "-R", &owner, &website.root_path]),
        )
        .await;
    }

    audit_detail(
        &state,
        current.user.id,
        "restore",
        &website.domain,
        &backup_file,
    )
    .await;
    axum::Json(json!({ "restored_to": destination.to_string_lossy() })).into_response()
}

/// A member's name, as **Python's** reader reports it.
///
/// Source: the last line of `tarfile.TarInfo.frombuf` —
/// `if obj.isdir(): obj.name = obj.name.rstrip("/")`. The writer adds the
/// slash back when it stores a directory, so a member that went in as
/// `site` comes out of Python as `site` and out of the `tar` crate as
/// `site/`. Every rule downstream compares this name against a literal —
/// `== "site"`, `starts_with("site/")`, `starts_with("database/")` — so a
/// trailing slash the Python does not have changes which branch fires.
fn member_name<R: std::io::Read>(entry: &tar::Entry<'_, R>) -> std::io::Result<String> {
    let raw = entry.path()?.to_string_lossy().into_owned();
    if entry.header().entry_type().is_dir() {
        Ok(raw.trim_end_matches('/').to_string())
    } else {
        Ok(raw)
    }
}

/// Unpack one site backup, member by member, through the filter.
///
/// Source: `tar.extractall(path=destination, filter=safe_filter)`.
///
/// The archive is read **twice**: once to find out whether its members
/// carry the panel's `site/` prefix, and once to unpack. That is what the
/// Python does — `getmembers()` then `extractall` — and the alternative,
/// guessing from the first member, is wrong for an archive whose first
/// entry is the database dump.
fn extract_site_backup(
    archive: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), String> {
    use std::io::Read;

    let names = {
        let file = std::fs::File::open(archive).map_err(|_| "Backup not found".to_string())?;
        let reader = flate2::read::GzDecoder::new(file);
        let mut tar = tar::Archive::new(reader);
        let mut names: Vec<String> = Vec::new();
        for entry in tar.entries().map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            names.push(member_name(&entry).map_err(|e| e.to_string())?);
        }
        names
    };
    let prefixed = crate::tarfilter::has_site_prefix(names.iter().map(String::as_str));

    let file = std::fs::File::open(archive).map_err(|_| "Backup not found".to_string())?;
    let reader = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let header = entry.header().clone();
        let kind = header.entry_type();
        let member = crate::tarfilter::Member {
            name: member_name(&entry).map_err(|e| e.to_string())?,
            kind: if kind.is_dir() {
                crate::tarfilter::MemberKind::Directory
            } else if kind.is_symlink() {
                crate::tarfilter::MemberKind::Symlink
            } else if kind.is_hard_link() {
                crate::tarfilter::MemberKind::Hardlink
            } else if kind.is_file() {
                crate::tarfilter::MemberKind::Regular
            } else {
                crate::tarfilter::MemberKind::Special
            },
            mode: header.mode().ok(),
            linkname: header
                .link_name()
                .ok()
                .flatten()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        };

        let filtered = match crate::tarfilter::safe_filter(&member, destination, prefixed) {
            Ok(Some(m)) => m,
            // Skipped on purpose: the database dump, the `site` directory
            // entry itself, and anything outside the prefix.
            Ok(None) => continue,
            Err(e) => {
                return Err(format!(
                    "Backup archive contains unsafe paths: {}",
                    e.as_str()
                ))
            }
        };

        let target = destination.join(&filtered.name);
        match filtered.kind {
            crate::tarfilter::MemberKind::Directory => {
                std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
            }
            crate::tarfilter::MemberKind::Symlink => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                // A link already there is replaced, which is what an
                // extraction over an existing tree has to do.
                let _ = std::fs::remove_file(&target);
                std::os::unix::fs::symlink(&filtered.linkname, &target)
                    .map_err(|e| e.to_string())?;
            }
            crate::tarfilter::MemberKind::Regular => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let mut bytes: Vec<u8> = Vec::new();
                entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                std::fs::write(&target, &bytes).map_err(|e| e.to_string())?;
                if let Some(mode) = filtered.mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode));
                }
            }
            // The filter has already refused these.
            crate::tarfilter::MemberKind::Hardlink | crate::tarfilter::MemberKind::Special => {}
        }
    }
    Ok(())
}

/// Every file part of a multipart body, by name.
///
/// `file: UploadFile = File(...)` and `files: list[UploadFile] = File(...)`
/// differ only in how many parts they take, and FastAPI matches on the part
/// name — so a form carrying other parts is not an error, and a form
/// carrying several parts named `files` is one list.
async fn upload_parts(
    state: &AppState,
    parts: axum::http::request::Parts,
    body: Body,
    field: &str,
) -> Result<Vec<(String, Vec<u8>)>, Response> {
    use axum::extract::FromRequest;

    let request = axum::extract::Request::from_parts(parts, body);
    let mut multipart = match axum::extract::Multipart::from_request(request, state).await {
        Ok(m) => m,
        Err(e) => return Err(bad_request(&e.body_text())),
    };
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    loop {
        match multipart.next_field().await {
            Ok(Some(part)) => {
                if part.name() != Some(field) {
                    continue;
                }
                let filename = part.file_name().unwrap_or_default().to_string();
                match part.bytes().await {
                    Ok(bytes) => out.push((filename, bytes.to_vec())),
                    Err(e) => return Err(bad_request(&e.body_text())),
                }
            }
            Ok(None) => break,
            Err(e) => return Err(bad_request(&e.body_text())),
        }
    }
    Ok(out)
}

/// A timestamp and a nonce for a restore upload whose name is taken.
///
/// Source: `datetime.utcnow().strftime("%Y%m%d%H%M%S")` and
/// `secrets.token_hex(3)` — six hex characters, not eight: the timestamp
/// already separates uploads a second apart, and this only has to separate
/// two in the same second.
fn restore_upload_suffix() -> (String, String) {
    use rand::RngCore;

    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let mut buf = [0u8; 3];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let nonce: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    (stamp, nonce)
}

/// `POST /maintenance/backups/{website_id}/upload`.
///
/// Source: `upload_backup`.
async fn upload_site_backup(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    use axum::extract::FromRequestParts;

    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let website_id = match AxumPath::<i64>::from_request_parts(&mut parts, &state).await {
        Ok(AxumPath(id)) => id,
        Err(e) => return bad_request(&e.body_text()),
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let files = match upload_parts(&state, parts.clone(), body, "file").await {
        Ok(f) => f,
        Err(r) => return r,
    };
    let Some((filename, data)) = files.into_iter().next() else {
        return crate::errors::missing_field("file", Value::Null);
    };
    // `file.filename or "backup.tar.gz"` — a part with no filename still
    // lands, under a name the operator can find.
    let filename = if filename.is_empty() {
        "backup.tar.gz".to_string()
    } else {
        filename
    };
    let target = match crate::backups::save_uploaded_backup(
        &state.settings.backup_root,
        &website.domain,
        &filename,
        &data,
    ) {
        Ok(t) => t,
        Err(e) => return bad_request(&e.to_string()),
    };
    audit_detail(
        &state,
        current.user.id,
        "upload_backup",
        &website.domain,
        &target,
    )
    .await;
    axum::Json(json!({ "backup_file": target })).into_response()
}

/// One uploaded user backup, saved and then **read back**.
///
/// Source: `_save_user_restore_upload`. The manifest check is the point:
/// an archive that is not a full user backup is deleted again rather than
/// left in the restore folder, where the next administrator would find it
/// and try to restore a customer from a website backup.
async fn save_restore_upload(
    state: &AppState,
    filename: &str,
    data: &[u8],
) -> Result<Value, Response> {
    let filename = if filename.is_empty() {
        "user-backup.tar.gz"
    } else {
        filename
    };
    let (stamp, nonce) = restore_upload_suffix();
    let target = crate::backups::save_uploaded_user_backup(
        &state.settings.backup_root,
        filename,
        data,
        &stamp,
        &nonce,
    )
    .map_err(|e| bad_request(&e.to_string()))?;

    let manifest = match crate::backups::read_backup_manifest(&state.settings.backup_root, &target)
    {
        Ok(m) if m.get("kind").and_then(Value::as_str) == Some("snpanel_user") => m,
        other => {
            // Both the unreadable and the wrong-kind archive go, and the
            // message is the Python's for each.
            let _ = crate::backups::delete_user_backup(&state.settings.backup_root, &target);
            return Err(bad_request(&match other {
                Ok(_) => "This is not a full user backup".to_string(),
                Err(e) => e.to_string(),
            }));
        }
    };
    let path = std::path::Path::new(&target);
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    Ok(json!({
        "backup_file": target,
        "filename": path.file_name().map(|n| n.to_string_lossy().into_owned()),
        "username": manifest["user"]["username"],
        "generated_at": manifest["generated_at"],
        "websites": manifest["websites"].as_array().map(Vec::len).unwrap_or(0),
        "size": size,
        "valid": true,
    }))
}

/// `POST /maintenance/user-restore-backups/upload`.
///
/// Source: `upload_user_restore_backups` — several archives at once, and
/// the audit line names the customers rather than the filenames, because
/// that is what an administrator is looking for afterwards.
async fn upload_restore_backups(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let files = match upload_parts(&state, parts.clone(), body, "files").await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if files.is_empty() {
        return bad_request("No backup files uploaded");
    }
    let mut items: Vec<Value> = Vec::with_capacity(files.len());
    for (filename, data) in files {
        match save_restore_upload(&state, &filename, &data).await {
            Ok(item) => items.push(item),
            Err(r) => return r,
        }
    }
    // `item.get("username") or item.get("filename") or "user"`.
    let users: Vec<String> = items
        .iter()
        .map(|item| {
            item["username"]
                .as_str()
                .filter(|s| !s.is_empty())
                .or_else(|| item["filename"].as_str().filter(|s| !s.is_empty()))
                .unwrap_or("user")
                .to_string()
        })
        .collect();
    audit_detail(
        &state,
        current.user.id,
        "upload_user_restore_backups",
        "restore_folder",
        &users.join(", "),
    )
    .await;
    axum::Json(json!({
        "directory": crate::backups::user_restore_dir(&state.settings.backup_root)
            .to_string_lossy(),
        "items": items,
    }))
    .into_response()
}

/// `POST /maintenance/user-backups/upload`.
///
/// Source: `upload_user_backup` — the same saver, one archive, and a
/// narrower answer.
async fn upload_user_backup(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let files = match upload_parts(&state, parts.clone(), body, "file").await {
        Ok(f) => f,
        Err(r) => return r,
    };
    let Some((filename, data)) = files.into_iter().next() else {
        return crate::errors::missing_field("file", Value::Null);
    };
    let item = match save_restore_upload(&state, &filename, &data).await {
        Ok(item) => item,
        Err(r) => return r,
    };
    let username = item["username"].as_str().unwrap_or("user").to_string();
    let backup_file = item["backup_file"].as_str().unwrap_or("").to_string();
    audit_detail(
        &state,
        current.user.id,
        "upload_user_backup",
        &username,
        &backup_file,
    )
    .await;
    axum::Json(json!({
        "backup_file": item["backup_file"],
        "username": item["username"],
    }))
    .into_response()
}

/// `DELETE /maintenance/user-restore-backups`.
///
/// Source: `delete_user_restore_backup`.
async fn delete_restore_backup(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
    req: axum::extract::Request,
) -> Response {
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let Some(backup_file) = params.get("backup_file") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "backup_file"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    let deleted = match crate::backups::delete_user_restore_backup(
        &state.settings.backup_root,
        backup_file,
    ) {
        Ok(d) => d,
        // Every failure here is "Backup not found": a path outside the
        // restore folder is not a refusal to explain, it is simply not
        // one of the files this endpoint knows about.
        Err(_) => return not_found("Backup not found"),
    };
    let (parts, _) = req.into_parts();
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "delete_user_restore_backup",
        "restore_folder",
        &deleted,
    )
    .await;
    axum::Json(json!({ "deleted": deleted })).into_response()
}

/// Source: `list_user_restore_backups` - the uploads waiting to be restored,
/// each described from its own manifest.
async fn list_restore_backups(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::is_admin_role(&current.user.role) {
        return crate::errors::not_enough_permissions();
    }
    let root = state.settings.backup_root.clone();
    let dry_run = state.settings.command_dry_run;
    let directory = backups::user_restore_dir(&root)
        .to_string_lossy()
        .into_owned();
    let items = tokio::task::spawn_blocking(move || {
        if dry_run {
            return Vec::new();
        }
        let dir = backups::user_restore_dir(&root);
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let mut paths: Vec<String> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.to_string_lossy().ends_with(".tar.gz"))
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            paths.sort();
            paths.reverse();
            for path in paths {
                out.push(backups::describe_user_backup(&root, &path));
            }
        }
        out
    })
    .await
    .unwrap_or_default();
    axum::Json(json!({ "directory": directory, "items": items })).into_response()
}

// ---------------------------------------------------------------------------
// backup schedules and SFTP targets
// ---------------------------------------------------------------------------

/// Source: `BackupScheduleOut`, whose `user_ids` validator decodes the JSON
/// the column holds. A column that will not parse becomes an empty list
/// rather than an error, the same way the Python's `before` validator does.
fn schedule_json(row: &snpanel_db::BackupSchedule) -> Value {
    let user_ids: Vec<i64> = serde_json::from_str(&row.user_ids).unwrap_or_default();
    json!({
        "id": row.id,
        "user_id": row.user_id,
        "user_ids": user_ids,
        "all_users": row.all_users,
        "target_id": row.target_id,
        "schedule": row.schedule,
        "retention": row.retention,
        "is_active": row.is_active,
        "last_run_at": row.last_run_at,
        "last_status": row.last_status,
        "last_message": row.last_message,
    })
}

/// Source: `SftpBackupTargetOut` - note what is *not* in it. The password and
/// the private key are stored encrypted and never leave the server.
fn sftp_json(row: &snpanel_db::SftpTarget) -> Value {
    json!({
        "id": row.id,
        "name": row.name,
        "host": row.host,
        "port": row.port,
        "username": row.username,
        "remote_path": row.remote_path,
        "is_active": row.is_active,
        "host_key_type": row.host_key_type,
        "host_key_fingerprint": row.host_key_fingerprint,
    })
}

/// Source: `_validate_backup_schedule` - five fields, each `*` or one or two
/// digits, optionally joined by `-`, `/` or `,`.
fn validate_cron(value: &str) -> Option<String> {
    let fields: Vec<&str> = value.split_whitespace().collect();
    if fields.len() != 5 {
        return None;
    }
    for field in &fields {
        let mut terms = Vec::new();
        let mut current = String::new();
        for c in field.chars() {
            if matches!(c, '-' | '/' | ',') {
                terms.push(std::mem::take(&mut current));
            } else {
                current.push(c);
            }
        }
        terms.push(current);
        // The pattern needs at least one term, and a separator may not end
        // the field: `1-` splits to ["1", ""], and "" matches nothing.
        if terms.is_empty() {
            return None;
        }
        for term in &terms {
            let ok = term == "*"
                || ((1..=2).contains(&term.len()) && term.bytes().all(|b| b.is_ascii_digit()));
            if !ok {
                return None;
            }
        }
    }
    Some(fields.join(" "))
}

async fn require_admin(current: &CurrentUser) -> Result<(), Response> {
    if permissions::is_admin_role(&current.user.role) {
        Ok(())
    } else {
        Err(crate::errors::not_enough_permissions())
    }
}

/// Source: `list_backup_schedules`.
async fn list_backup_schedules(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    match state.db.backup_schedules().list().await {
        Ok(rows) => axum::Json(rows.iter().map(schedule_json).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!("listing backup schedules failed: {e}");
            internal_error()
        }
    }
}

/// Source: `create_backup_schedule`.
async fn create_backup_schedule(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let (_, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let all_users = payload
        .get("all_users")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // `payload.user_ids or ([payload.user_id] if payload.user_id else [])`
    let mut user_ids: Vec<i64> = if all_users {
        Vec::new()
    } else {
        let listed: Vec<i64> = payload
            .get("user_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default();
        if listed.is_empty() {
            payload
                .get("user_id")
                .and_then(Value::as_i64)
                .filter(|id| *id != 0)
                .map(|id| vec![id])
                .unwrap_or_default()
        } else {
            listed
        }
    };
    user_ids.retain(|id| *id > 0);
    user_ids.sort_unstable();
    user_ids.dedup();

    let mut usernames: Vec<String> = Vec::new();
    if !all_users {
        if user_ids.is_empty() {
            return bad_request("Select at least one user");
        }
        let mut missing: Vec<String> = Vec::new();
        for id in &user_ids {
            match state.db.users().by_id(*id).await {
                Ok(Some(u)) => usernames.push(u.username),
                Ok(None) => missing.push(id.to_string()),
                Err(e) => {
                    tracing::error!("user lookup failed: {e}");
                    return internal_error();
                }
            }
        }
        if !missing.is_empty() {
            return not_found(&format!("User not found: {}", missing.join(", ")));
        }
    }

    let target_id = payload
        .get("target_id")
        .and_then(Value::as_i64)
        .filter(|id| *id != 0);
    if let Some(id) = target_id {
        match state.db.sftp_targets().active_exists(id).await {
            Ok(true) => {}
            Ok(false) => return not_found("SFTP target not found"),
            Err(e) => {
                tracing::error!("SFTP target lookup failed: {e}");
                return internal_error();
            }
        }
    }

    let schedule_raw = payload
        .get("schedule")
        .and_then(Value::as_str)
        .unwrap_or("0 2 * * *");
    let Some(schedule) = validate_cron(schedule_raw) else {
        return crate::errors::validation_error(vec![json!({
            "type": "value_error",
            "loc": ["body", "schedule"],
            "msg": "Value error, Invalid cron schedule",
            "input": schedule_raw,
        })]);
    };
    let retention = payload
        .get("retention")
        .and_then(Value::as_i64)
        .unwrap_or(7);
    if !(1..=365).contains(&retention) {
        let (kind, msg, ctx) = if retention < 1 {
            (
                "greater_than_equal",
                "Input should be greater than or equal to 1",
                json!({"ge": 1}),
            )
        } else {
            (
                "less_than_equal",
                "Input should be less than or equal to 365",
                json!({"le": 365}),
            )
        };
        return crate::errors::validation_error(vec![json!({
            "type": kind,
            "loc": ["body", "retention"],
            "msg": msg,
            "input": retention,
            "ctx": ctx,
        })]);
    }
    let is_active = payload
        .get("is_active")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let user_ids_json = serde_json::to_string(&user_ids).unwrap_or_else(|_| "[]".into());
    let created = match state
        .db
        .backup_schedules()
        .create(
            user_ids.first().copied(),
            &user_ids_json,
            all_users,
            target_id,
            &schedule,
            retention,
            is_active,
        )
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!("creating a backup schedule failed: {e}");
            return internal_error();
        }
    };

    let target = if all_users {
        "all_users".to_string()
    } else {
        usernames.join(",")
    };
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "create_backup_schedule",
        &target,
    )
    .await;
    axum::Json(schedule_json(&created)).into_response()
}

/// Source: `delete_backup_schedule`.
async fn delete_backup_schedule(
    State(state): State<AppState>,
    AxumPath(schedule_id): AxumPath<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    match state.db.backup_schedules().delete(schedule_id).await {
        Ok(true) => {
            super::packages::audit_action(
                &state,
                &parts,
                current.user.id,
                "delete_backup_schedule",
                &schedule_id.to_string(),
            )
            .await;
            axum::Json(json!({ "ok": true })).into_response()
        }
        Ok(false) => not_found("Backup schedule not found"),
        Err(e) => {
            tracing::error!("deleting a backup schedule failed: {e}");
            internal_error()
        }
    }
}

/// Source: `list_sftp_targets`.
async fn list_sftp_targets(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    match state.db.sftp_targets().list().await {
        Ok(rows) => axum::Json(rows.iter().map(sftp_json).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!("listing SFTP targets failed: {e}");
            internal_error()
        }
    }
}

/// Source: `create_sftp_target`.
///
/// The password and the private key are encrypted here, with the panel's own
/// key, before they reach the database layer - which does not hold that key
/// and therefore cannot be called in a way that stores them in the clear.
async fn create_sftp_target(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let (_, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let name = match string_field(&payload, "name") {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !(2..=100).contains(&name.chars().count())
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b' ' | b'-'))
    {
        return crate::errors::validation_error(vec![json!({
            "type": "string_pattern_mismatch",
            "loc": ["body", "name"],
            "msg": "String should match pattern '^[A-Za-z0-9._ -]+$'",
            "input": name,
            "ctx": { "pattern": "^[A-Za-z0-9._ -]+$" },
        })]);
    }
    let host = match string_field(&payload, "host") {
        Ok(v) => v.trim().to_string(),
        Err(r) => return r,
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return crate::errors::validation_error(vec![json!({
            "type": "value_error",
            "loc": ["body", "host"],
            "msg": "Value error, Invalid SFTP host",
            "input": host,
        })]);
    }
    let username = match string_field(&payload, "username") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let port = payload.get("port").and_then(Value::as_i64).unwrap_or(22);
    if !(1..=65535).contains(&port) {
        return crate::errors::validation_error(vec![json!({
            "type": "less_than_equal",
            "loc": ["body", "port"],
            "msg": "Input should be less than or equal to 65535",
            "input": port,
            "ctx": { "le": 65535 },
        })]);
    }
    let remote_path = payload
        .get("remote_path")
        .and_then(Value::as_str)
        .unwrap_or("/backups/snpanel")
        .to_string();
    let password = payload
        .get("password")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let private_key = payload
        .get("private_key")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if password.is_none() && private_key.is_none() {
        return bad_request("SFTP password or private key is required");
    }

    match state.db.sftp_targets().name_taken(&name).await {
        Ok(true) => return conflict("SFTP target name already exists"),
        Ok(false) => {}
        Err(e) => {
            tracing::error!("SFTP target lookup failed: {e}");
            return internal_error();
        }
    }

    let key = &state.settings.secret_key;
    let encrypted_password = password.map(|p| snpanel_core::crypto::fernet::encrypt(key, p));
    let encrypted_key = private_key.map(|p| snpanel_core::crypto::fernet::encrypt(key, p));

    match state
        .db
        .sftp_targets()
        .create(
            &name,
            &host,
            port,
            &username,
            encrypted_password.as_deref(),
            encrypted_key.as_deref(),
            &remote_path,
        )
        .await
    {
        Ok(row) => {
            super::packages::audit_action(
                &state,
                &parts,
                current.user.id,
                "create_sftp_target",
                &row.name,
            )
            .await;
            axum::Json(sftp_json(&row)).into_response()
        }
        Err(e) => {
            tracing::error!("creating an SFTP target failed: {e}");
            internal_error()
        }
    }
}

/// Source: `delete_sftp_target`.
async fn delete_sftp_target(
    State(state): State<AppState>,
    AxumPath(target_id): AxumPath<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    match state.db.sftp_targets().delete(target_id).await {
        Ok(Some(name)) => {
            super::packages::audit_action(
                &state,
                &parts,
                current.user.id,
                "delete_sftp_target",
                &name,
            )
            .await;
            axum::Json(json!({ "ok": true })).into_response()
        }
        Ok(None) => not_found("SFTP target not found"),
        Err(e) => {
            tracing::error!("deleting an SFTP target failed: {e}");
            internal_error()
        }
    }
}

// ---------------------------------------------------------------------------
// PHP versions and the panel's ini file
// ---------------------------------------------------------------------------

/// The `php_version` a body carries, with the model's default and its
/// validator: anything the panel does not support falls back to `8.4` rather
/// than being refused, which is what `_validate_php_version(...) or "8.4"`
/// does.
fn body_php_version(payload: &Value) -> String {
    let raw = payload
        .get("php_version")
        .and_then(Value::as_str)
        .unwrap_or("8.4")
        .trim();
    if php::SUPPORTED_PHP_VERSIONS.contains(&raw) {
        raw.to_string()
    } else {
        "8.4".to_string()
    }
}

/// Write the panel's ini and restart FPM, through the helper.
async fn write_php_ini(state: &AppState, version: &str, content: &str) -> Result<String, Response> {
    let target = php::config_target(version);
    if state.settings.command_dry_run {
        // Source: `update_php_ini` returns the *content* in dry-run mode, not
        // the path. Faithful, because a caller that printed it would show the
        // operator what would be written.
        return Ok(content.to_string());
    }
    let script = "cat > /etc/php/$1/fpm/conf.d/99-snpanel.ini && systemctl restart php$1-fpm";
    let result = shell::privileged(
        false,
        "php-config-write",
        &[version],
        Some(content),
        Some(&["bash", "-lc", script, "snpanel-php-config-write", version]),
    )
    .await;
    if !result.ok() {
        return Err(internal_error());
    }
    Ok(target)
}

/// Source: `get_php_config`.
async fn get_php_config(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let requested = params.get("php_version").map(String::as_str);
    match php::read_php_ini(requested, &state.settings.default_php_version) {
        Ok(values) => axum::Json(values).into_response(),
        Err(e) => bad_request(&e),
    }
}

/// Source: `update_php_config`.
async fn update_php_config(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let (_, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let version = body_php_version(&payload);

    let text = |name: &str, default: &str| -> String {
        payload
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_string()
    };
    let number = |name: &str, default: i64| -> i64 {
        payload.get(name).and_then(Value::as_i64).unwrap_or(default)
    };
    let update = php::IniUpdate {
        display_errors: text("display_errors", "Off"),
        memory_limit: text("memory_limit", "1024M"),
        upload_max_filesize: text("upload_max_filesize", "1024M"),
        post_max_size: text("post_max_size", "1024M"),
        max_execution_time: number("max_execution_time", 300),
        max_input_time: number("max_input_time", 600),
        max_input_vars: number("max_input_vars", 10000),
    };
    for (name, value, lo, hi) in [
        ("max_execution_time", update.max_execution_time, 1, 3600),
        ("max_input_time", update.max_input_time, 1, 3600),
        ("max_input_vars", update.max_input_vars, 100, 1_000_000),
    ] {
        if !(lo..=hi).contains(&value) {
            let (kind, msg, ctx) = if value < lo {
                (
                    "greater_than_equal",
                    format!("Input should be greater than or equal to {lo}"),
                    json!({ "ge": lo }),
                )
            } else {
                (
                    "less_than_equal",
                    format!("Input should be less than or equal to {hi}"),
                    json!({ "le": hi }),
                )
            };
            return crate::errors::validation_error(vec![json!({
                "type": kind,
                "loc": ["body", name],
                "msg": msg,
                "input": value,
                "ctx": ctx,
            })]);
        }
    }

    let content = match update.render() {
        Ok(c) => c,
        Err(e) => return bad_request(&e),
    };
    match write_php_ini(&state, &version, &content).await {
        Ok(target) => axum::Json(json!({ "target": target })).into_response(),
        Err(r) => r,
    }
}

/// Source: `restore_php_config_defaults`.
async fn restore_php_defaults(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let (_, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let version = body_php_version(&payload);
    let values = match php::default_php_config(&version) {
        Ok(v) => v,
        Err(e) => return bad_request(&e),
    };
    let update = php::IniUpdate {
        display_errors: "Off".into(),
        memory_limit: "1024M".into(),
        upload_max_filesize: "1024M".into(),
        post_max_size: "1024M".into(),
        max_execution_time: 300,
        max_input_time: 600,
        max_input_vars: 10000,
    };
    let content = match update.render() {
        Ok(c) => c,
        Err(e) => return bad_request(&e),
    };
    match write_php_ini(&state, &version, &content).await {
        Ok(target) => axum::Json(json!({ "target": target, "values": values })).into_response(),
        Err(r) => r,
    }
}

/// Everything `plan` needs from this machine, gathered once.
///
/// The two PHP subprocesses are the slow part and neither depends on the
/// other, so they run together: a cold `php -i` is most of a second and the
/// JIT probe starts an opcache.
async fn php_tune_plan(state: &AppState, requested: Option<&str>) -> Result<Value, Response> {
    let version = match php::resolve_version(requested, &state.settings.default_php_version) {
        Ok(v) => v,
        Err(e) => return Err(bad_request(&e)),
    };
    let (live, jit) = tokio::join!(
        crate::php_tune::current_values(&version),
        crate::php_tune::jit_status(&version),
    );
    let pools = crate::php_tune::pool_settings(
        std::path::Path::new("/etc/php")
            .join(&version)
            .join("fpm")
            .join("pool.d")
            .as_path(),
    );
    Ok(crate::php_tune::plan_payload(
        &version,
        &crate::php_tune::server_facts(),
        &live,
        &crate::php_tune::pinned_by_php_config(&version),
        &jit,
        pools,
    ))
}

/// `GET /maintenance/php-tune`.
///
/// Source: `get_php_tune`. Read-only: the numbers and the reasoning, so an
/// administrator can see what would change before anything does.
async fn get_php_tune(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    // `php_version: str | None = Query(default=None)` — no pattern, so an
    // unsupported value reaches `resolve_version` and is refused there with
    // the list of what is allowed.
    match php_tune_plan(&state, params.get("php_version").map(String::as_str)).await {
        Ok(payload) => axum::Json(payload).into_response(),
        Err(r) => r,
    }
}

/// `POST /maintenance/php-tune`.
///
/// Source: `apply_php_tune`. **One button, both halves**: the settings PHP
/// reads and the pool sizes FPM runs with, which are otherwise only
/// recalculated when a site is touched.
async fn apply_php_tune(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let (_, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let requested = body_php_version(&payload);
    let version = match php::resolve_version(Some(&requested), &state.settings.default_php_version)
    {
        Ok(v) => v,
        Err(e) => return bad_request(&e),
    };

    let jit = crate::php_tune::jit_status(&version).await;
    let content = crate::php_tune::render_ini(&crate::php_tune::server_facts(), &jit);
    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        "php-tune-write",
        &[&version],
        Some(&content),
        Some(&["bash", "-lc", "echo dry-run-php-tune"]),
        Some(120),
    )
    .await;
    if !result.ok() {
        // `RuntimeError` from the service, which this endpoint answers as a
        // 500 rather than a 400: the request was well formed and the machine
        // failed to carry it out.
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            snpanel_core::pyunicode::tail(
                result
                    .failure_detail("Could not write the PHP tuning file")
                    .trim(),
                2000,
            ),
        );
    }

    let message = {
        let stdout = result.stdout.trim();
        if stdout.is_empty() {
            format!("PHP {version} đã tune.")
        } else {
            stdout.to_string()
        }
    };
    let plan = match php_tune_plan(&state, Some(&version)).await {
        Ok(plan) => plan,
        Err(r) => return r,
    };
    let mut body = json!({ "message": message, "plan": plan });

    // The pool retune is reported, not enforced: a tuning file that landed
    // is worth keeping even if the pools could not be recalculated, and the
    // page shows the error beside the success rather than instead of it.
    let pools = shell::privileged_timed(
        state.settings.command_dry_run,
        "php-pools-retune",
        &[],
        None,
        Some(&["bash", "-lc", "echo dry-run-retune"]),
        Some(600),
    )
    .await;
    if pools.ok() {
        body["pools"] = json!(pools.stdout.trim());
    } else {
        body["pools"] = json!("");
        body["pools_error"] = json!(snpanel_core::pyunicode::tail(
            pools.failure_detail("Could not retune the pools").trim(),
            500
        ));
    }

    super::packages::audit_action(&state, &parts, current.user.id, "php_tune", &requested).await;
    axum::Json(body).into_response()
}

/// `POST /maintenance/php-opcache`.
///
/// Source: `toggle_php_opcache`. Kept out of the tuning file so that running
/// Auto tune afterwards does not switch it back on behind the
/// administrator's back.
async fn toggle_php_opcache(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let (_, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `PhpOpcacheToggle` has **no** validator on `php_version`, unlike
    // `PhpConfigRestore`: an unsupported value is not quietly replaced with
    // 8.4 here, it reaches `set_opcache` and is refused.
    let version = match payload.get("php_version") {
        Some(Value::String(s)) => s.clone(),
        None => "8.4".to_string(),
        Some(other) => return crate::errors::string_type("php_version", other),
    };
    let enabled = match crate::errors::read_bool("enabled", payload.get("enabled"), true) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !php::SUPPORTED_PHP_VERSIONS.contains(&version.as_str()) {
        return bad_request(&format!("Unsupported PHP version: {version}"));
    }

    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        "php-opcache-set",
        &[&version, if enabled { "1" } else { "0" }],
        None,
        Some(&["bash", "-lc", "echo dry-run-opcache"]),
        Some(120),
    )
    .await;
    if !result.ok() {
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            snpanel_core::pyunicode::tail(
                result.failure_detail("Could not change opcache").trim(),
                2000,
            ),
        );
    }

    let target = format!("{version}={}", i32::from(enabled));
    super::packages::audit_action(&state, &parts, current.user.id, "php_opcache", &target).await;
    axum::Json(json!({
        "php_version": version,
        "enabled": enabled,
        "message": format!(
            "OPcache PHP {version}: {}.",
            if enabled { "bật" } else { "tắt" }
        ),
    }))
    .into_response()
}

/// `POST /maintenance/php-tune/pools`.
///
/// Source: `retune_php_pools`. Pool sizing is decided when a pool is
/// written, so a server that gained RAM keeps the old numbers until each
/// site is touched; this asks for all of them at once.
async fn retune_php_pools(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        "php-pools-retune",
        &[],
        None,
        Some(&["bash", "-lc", "echo dry-run-retune"]),
        Some(600),
    )
    .await;
    if !result.ok() {
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            snpanel_core::pyunicode::tail(
                result.failure_detail("Could not retune the pools").trim(),
                2000,
            ),
        );
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "php_retune_pools",
        "php-fpm",
    )
    .await;
    axum::Json(json!({
        "message": "Đã tính lại các pool PHP-FPM.",
        "output": snpanel_core::pyunicode::tail(result.stdout.trim(), 4000),
    }))
    .into_response()
}

/// `POST /maintenance/files/archive`.
///
/// Source: `archive_entries`.
///
/// Everything is validated before anything is written, and in the Python's
/// order: the folder, then every selection, then the output name, then the
/// two ways the output could sit inside its own input, then the quota. The
/// order is the product — an operator who picked twenty folders and one bad
/// one is told which rule they broke, not handed a half-written archive.
async fn archive_entries(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let admin = permissions::is_admin_role(&current.user.role);

    // `base_path: str = site_users.PUBLIC_DIR`, `paths: list[str]`,
    // `output_name: str = ""`, `format: str = "zip"`.
    let base_rel = payload
        .get("base_path")
        .and_then(Value::as_str)
        .unwrap_or("public_html")
        .to_string();
    let format = payload
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("zip")
        .to_string();
    let output_name = payload
        .get("output_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let paths = match string_list_field(&payload, "paths") {
        Ok(v) => v,
        Err(r) => return r,
    };

    let base = match files::safe_path(&website.root_path, &base_rel, false) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !base.is_dir() {
        return bad_request("Archive directory not found");
    }
    let mut selected: Vec<std::path::PathBuf> = Vec::with_capacity(paths.len());
    for path in &paths {
        match files::safe_path(&website.root_path, path, false) {
            Ok(p) => selected.push(p),
            Err(e) => return bad_request(&e.to_string()),
        }
    }
    if selected.is_empty() {
        return bad_request("Select files or folders to archive");
    }
    for path in &selected {
        if !path.exists() {
            return bad_request("File or folder not found");
        }
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return bad_request("Symlinks are not allowed");
        }
        if let Err(e) = assert_tree_read_allowed(path, "Archiving", admin) {
            return bad_request(&e);
        }
        // Not for its answer: this is where a selection from outside the
        // folder is caught, before the output name is even built.
        if let Err(e) = crate::archive::archive_arcname(&base, path) {
            return bad_request(&e);
        }
    }

    let now_unix = chrono::Utc::now().timestamp();
    let name = match crate::archive::archive_output_name(&output_name, &format, now_unix) {
        Ok(n) => n,
        Err(e) => return bad_request(&e),
    };
    let output_path = base.join(&name);
    if output_path.exists() {
        return bad_request("Archive output already exists");
    }
    for path in &selected {
        // Two ways the output ends up inside its own input: it *is* a
        // selected path, or it is under a selected folder. Either one makes
        // the archive grow while it is being written.
        if *path == output_path || (path.is_dir() && output_path.starts_with(path)) {
            return bad_request("Archive output cannot be inside a selected folder");
        }
    }
    if let Err(r) = quota_check(&state, website.owner_id, total_size(&selected), 0).await {
        return r;
    }

    let output_str = output_path.to_string_lossy().into_owned();
    // The Python has an in-process branch for a site with no runtime user,
    // which is a development box with no helper. `run_in_site_dir` refuses
    // with the message `_run_as_site_user` raises, and this process does not
    // write into a customer's tree itself.
    let mut items: Vec<String> = Vec::with_capacity(selected.len());
    for path in &selected {
        match crate::archive::archive_arcname(&base, path) {
            Ok(item) => items.push(item),
            Err(e) => return bad_request(&e),
        }
    }
    // `zip -r <name> -- <items>` and `tar -czf <name> -- <items>`, both run
    // as the site's user with the archive folder as the working directory,
    // which is what makes the arcnames relative to it.
    let mut args: Vec<&str> = if format == "zip" {
        vec!["-r", &name, "--"]
    } else {
        vec!["-czf", &name, "--"]
    };
    args.extend(items.iter().map(String::as_str));
    let base_str = base.to_string_lossy().into_owned();
    let tool = if format == "zip" { "zip" } else { "tar" };
    let mut fallback: Vec<String> = vec![tool.to_string()];
    fallback.extend(args.iter().map(|a| (*a).to_string()));
    let fallback_refs: Vec<&str> = fallback.iter().map(String::as_str).collect();
    if let Err(r) = run_in_site_dir(&state, &website, &base_str, tool, &args, &fallback_refs).await
    {
        return r;
    }

    fix_site_path(&state, &output_str, website.linux_user.as_deref()).await;
    clear_fastcgi_cache(&state).await;
    audit_detail(
        &state,
        current.user.id,
        "archive_files",
        &website.domain,
        &output_str,
    )
    .await;
    axum::Json(json!({ "target": output_str })).into_response()
}

/// Source: `_assert_tree_read_allowed`.
///
/// A symlink **anywhere** under a selected folder stops the archive, not
/// just at the top: `zip -r` would follow it and write whatever it points
/// at into a file the customer can then download. The sensitive-name half
/// of the Python's check is a no-op here for the same reason it is there —
/// `SENSITIVE_READ_NAMES` is empty — and a permission error while walking
/// is not a refusal, because a directory this process cannot read is one
/// `zip` will not read either.
fn assert_tree_read_allowed(
    path: &std::path::Path,
    _action: &str,
    _allow_sensitive: bool,
) -> Result<(), String> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("Symlinks are not allowed".to_string());
    }
    if !path.is_dir() {
        return Ok(());
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let child = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return Err("Symlinks are not allowed".to_string());
            }
            if meta.is_dir() {
                stack.push(child);
            }
        }
    }
    Ok(())
}

/// `POST /maintenance/files/{website_id}/upload`.
///
/// Source: `upload_file`.
///
/// The bytes are **staged outside the site** and scanned before they are
/// installed. A file written into the customer's tree and scanned there is
/// a file that was briefly servable by nginx; the staging directory is not
/// under any vhost, so a detection means nothing was ever reachable.
///
/// The quota is charged for what arrives *minus* what it replaces: an
/// upload overwriting a 10 MB file with a 12 MB one costs 2 MB, not 12.
async fn upload_file(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    use axum::extract::FromRequestParts;

    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // The body is needed whole for the multipart reader, so the path and
    // query are taken from the parts rather than through the extractors.
    let website_id = match AxumPath::<i64>::from_request_parts(&mut parts, &state).await {
        Ok(AxumPath(id)) => id,
        Err(e) => return bad_request(&e.body_text()),
    };
    // `path: str = Query(default=site_users.PUBLIC_DIR)`.
    let directory = Query::<HashMap<String, String>>::try_from_uri(&parts.uri)
        .ok()
        .and_then(|Query(q)| q.get("path").cloned())
        .unwrap_or_else(|| "public_html".to_string());

    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    upload_into(
        state,
        current,
        FileTarget::website(&website),
        directory,
        parts,
        body,
    )
    .await
}

/// `POST /maintenance/app-files/{app_id}/upload`.
///
/// Source: `upload_app_file`. Two things differ from a website's: the
/// directory defaults to the application root rather than to `public_html`,
/// and an executable is always allowed — an application's own files are
/// code.
async fn upload_app_file(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    use axum::extract::FromRequestParts;

    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let app_id = match AxumPath::<i64>::from_request_parts(&mut parts, &state).await {
        Ok(AxumPath(id)) => id,
        Err(e) => return bad_request(&e.body_text()),
    };
    // `path: str = Query(default="")` — the application's own root.
    let directory = Query::<HashMap<String, String>>::try_from_uri(&parts.uri)
        .ok()
        .and_then(|Query(q)| q.get("path").cloned())
        .unwrap_or_default();

    let target = match app_target(&state, &current, app_id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    upload_into(state, current, target, directory, parts, body).await
}

async fn upload_into(
    state: AppState,
    current: CurrentUser,
    site: FileTarget,
    directory: String,
    parts: axum::http::request::Parts,
    body: Body,
) -> Response {
    use axum::extract::FromRequest;

    let request = axum::extract::Request::from_parts(parts.clone(), body);
    let mut multipart = match axum::extract::Multipart::from_request(request, &state).await {
        Ok(m) => m,
        Err(e) => return bad_request(&e.body_text()),
    };
    let mut content: Option<Vec<u8>> = None;
    let mut filename = String::new();
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                if field.name() != Some("file") {
                    continue;
                }
                filename = field.file_name().unwrap_or_default().to_string();
                match field.bytes().await {
                    Ok(bytes) => content = Some(bytes.to_vec()),
                    Err(e) => return bad_request(&e.body_text()),
                }
            }
            Ok(None) => break,
            Err(e) => return bad_request(&e.body_text()),
        }
    }
    let Some(content) = content else {
        return crate::errors::missing_field("file", Value::Null);
    };
    // `file.filename or "upload.bin"` — a part with no filename still lands,
    // under a name the customer can find.
    if filename.is_empty() {
        filename = "upload.bin".to_string();
    }

    let target_dir = match files::safe_path(&site.root_path, &directory, false) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if target_dir.exists() && !target_dir.is_dir() {
        return bad_request("Upload target is not a directory");
    }
    if std::fs::symlink_metadata(&target_dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return bad_request("Symlinks are not allowed");
    }
    let safe_name = match files::safe_upload_name(&filename) {
        Ok(n) => n,
        Err(e) => return bad_request(&e.to_string()),
    };
    let target = target_dir.join(&safe_name);
    if std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
        return bad_request("Refusing to overwrite a symlink");
    }
    // `allow_executable` is `is_admin_role(...)` for a website and a plain
    // `True` for an application.
    let allow_executable = site
        .allow_executable
        .unwrap_or_else(|| permissions::is_admin_role(&current.user.role));
    if let Err(e) = files::assert_write_allowed(&target, "Uploading", allow_executable) {
        return bad_request(&e.to_string());
    }

    // `_existing_file_size` — zero for a path that is not a plain file, so
    // uploading over a directory does not earn a refund.
    let replaced = std::fs::metadata(&target)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|m| m.len())
        .unwrap_or(0);
    if let Err(r) = quota_check(&state, site.owner_id, content.len() as u64, replaced).await {
        return r;
    }

    if let Err(e) = crate::clamav::scan_before_install(
        state.settings.malware_scan_enabled,
        &state.settings.clamav_socket_path,
        &content,
        &filename,
    ) {
        return bad_request(&e);
    }

    let Some(linux_user) = site.linux_user.as_deref().filter(|u| !u.is_empty()) else {
        return bad_request("Website has no runtime user configured");
    };
    let staged = std::env::temp_dir().join(format!(
        "snpanel-upload-{}-{}",
        std::process::id(),
        crate::file_jobs::new_job_id()
    ));
    if let Err(e) = std::fs::write(&staged, &content) {
        return bad_request(&format!("Cannot stage the upload: {e}"));
    }
    let staged_str = staged.to_string_lossy().into_owned();
    let target_str = target.to_string_lossy().into_owned();
    let root = std::fs::canonicalize(&site.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&site.root_path));
    let root_str = root.to_string_lossy().into_owned();
    let target_rel = files::helper_relative_path(&site.root_path, &target);
    let result = shell::privileged(
        state.settings.command_dry_run,
        "site-file-install",
        &[linux_user, &root_str, &target_rel, &staged_str],
        None,
        Some(&["cp", "--", &staged_str, &target_str]),
    )
    .await;
    // `finally: staged_path.unlink(missing_ok=True)` — the staged copy goes
    // whether or not the install worked, because it is a full copy of a
    // customer's file sitting in a world-readable directory.
    let _ = std::fs::remove_file(&staged);
    if !result.ok() {
        return bad_request(result.failure_detail("Cannot install the upload").trim());
    }

    fix_site_path(&state, &target_str, site.linux_user.as_deref()).await;
    clear_fastcgi_cache(&state).await;
    // The two answers differ, and so do the two actions: an application's
    // upload is logged as `upload_app_file` against `app:<name>` and reports
    // what it `stored`, which is what the Applications page reads.
    let app = site.allow_executable.is_some();
    audit_detail(
        &state,
        current.user.id,
        if app {
            "upload_app_file"
        } else {
            "upload_file"
        },
        &site.label,
        &target_str,
    )
    .await;
    if app {
        axum::Json(json!({ "stored": target_str })).into_response()
    } else {
        axum::Json(json!({ "target": target_str })).into_response()
    }
}

/// `DELETE /maintenance/files/{website_id}`.
///
/// Source: `delete_file`.
///
/// **A symlink may be the final component here**, and only here: a
/// Laravel-style `public/storage` has to be unlinkable without being
/// followed. A directory is refused outright — the bulk endpoint is what
/// deletes trees — but a symlink *to* a directory is not a directory for
/// this purpose, which is the distinction that lets `public/storage` go.
async fn delete_file(
    State(state): State<AppState>,
    AxumPath(website_id): AxumPath<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let Some(path) = params.get("path") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "path"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let target = match files::safe_path(&website.root_path, path, true) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    let is_symlink = std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink());
    if target.is_dir() && !is_symlink {
        return bad_request("Cannot delete directory");
    }
    let admin = permissions::is_admin_role(&current.user.role);
    if let Err(e) = files::assert_write_allowed(&target, "Deleting", admin) {
        return bad_request(&e.to_string());
    }

    let target_str = target.to_string_lossy().into_owned();
    if let Some(linux_user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) {
        let root = std::fs::canonicalize(&website.root_path)
            .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
        let root_str = root.to_string_lossy().into_owned();
        let result = shell::privileged(
            state.settings.command_dry_run,
            "rm-site",
            &[linux_user, &root_str, &target_str],
            None,
            Some(&["rm", "-f", "--", &target_str]),
        )
        .await;
        if !result.ok() {
            return bad_request(result.failure_detail("Cannot delete").trim());
        }
    } else {
        // `unlink(missing_ok=True)` — a file that is already gone is not an
        // error, because the page that asked may be showing a stale listing.
        let _ = std::fs::remove_file(&target);
    }
    clear_fastcgi_cache(&state).await;
    axum::Json(json!({ "deleted": target_str })).into_response()
}

/// `POST /maintenance/files/extract`.
///
/// Source: `extract_archive`.
///
/// The archive is **opened** before the job is queued, not just named: a
/// corrupt upload is a 400 the customer sees immediately rather than a job
/// card that fails ten seconds later with nothing to act on. The scan that
/// decides what may be unpacked runs in the worker, because on a large
/// archive it is the slow part.
async fn extract_archive(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let archive_path = match string_field(&payload, "archive_path") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let destination_path = payload
        .get("destination_path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let archive_file = match files::safe_path(&website.root_path, &archive_path, false) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !archive_file.is_file() {
        return bad_request("Archive not found");
    }
    if std::fs::symlink_metadata(&archive_file).is_ok_and(|m| m.file_type().is_symlink()) {
        return bad_request("Symlinks are not allowed");
    }
    let name = archive_file
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let is_zip = name.ends_with(".zip");
    let is_tar = name.ends_with(".tar.gz") || name.ends_with(".tgz");
    if !is_zip && !is_tar {
        return bad_request("Only .zip, .tar.gz, and .tgz archives are supported");
    }
    // Opened and closed again: this only asks whether the container is
    // readable, which is what `with zipfile.ZipFile(...) as _: pass` does.
    if is_zip {
        if crate::archive::read_zip_entries(&archive_file).is_err() {
            return bad_request("Invalid or corrupted ZIP archive");
        }
    } else if crate::archive::read_tar_entries(&archive_file).is_err() {
        return bad_request("Invalid or corrupted tar archive");
    }

    let job_id = crate::file_jobs::new_job_id();
    let target_key = crate::file_jobs::target_key(Some(website.id), None);
    let public = crate::file_jobs::remember(crate::file_jobs::FileJob {
        sequence: 0,
        job_id: job_id.clone(),
        kind: "extract_archive".to_string(),
        status: "queued".to_string(),
        user_id: current.user.id,
        website_id: Some(website.id),
        target_key: target_key.clone(),
        archive_path: archive_path.clone(),
        destination_path: destination_path.clone(),
        target: String::new(),
        message: "Extraction queued".to_string(),
        error: String::new(),
        created_at: crate::file_jobs::now_iso(),
        started_at: String::new(),
        finished_at: String::new(),
    });

    let worker_state = state.clone();
    let worker_user = current.user.id;
    let worker_job = job_id.clone();
    let worker_key = target_key.clone();
    let worker_archive = archive_path.clone();
    let worker_destination = destination_path.clone();
    tokio::spawn(async move {
        // Two at a time, as the Python's `ThreadPoolExecutor(max_workers=2)`
        // allows. On a shared box this is the ceiling on how much disk an
        // extraction storm can move at once, not an accident.
        let permit = crate::file_jobs::worker_permit().await;
        crate::file_jobs::update(&worker_job, |job| {
            job.status = "running".to_string();
            job.started_at = crate::file_jobs::now_iso();
            job.message = "Extracting archive".to_string();
        });
        let outcome = run_extract_job(
            &worker_state,
            worker_user,
            &worker_key,
            &worker_archive,
            &worker_destination,
        )
        .await;
        match outcome {
            Ok(target) => crate::file_jobs::update(&worker_job, |job| {
                job.status = "done".to_string();
                job.target = target;
                job.message = "Extraction completed".to_string();
                job.finished_at = crate::file_jobs::now_iso();
            }),
            Err(error) => crate::file_jobs::update(&worker_job, |job| {
                job.status = "error".to_string();
                job.error = error;
                job.message = "Extraction failed".to_string();
                job.finished_at = crate::file_jobs::now_iso();
            }),
        }
        drop(permit);
    });

    audit_detail(
        &state,
        current.user.id,
        "extract_archive_queued",
        &website.domain,
        &archive_path,
    )
    .await;
    let mut body = public;
    body["message"] = json!("Extraction started in the background");
    axum::Json(body).into_response()
}

/// `GET /maintenance/files/jobs`.
async fn list_file_jobs(
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let website_id = match params.get("website_id") {
        Some(raw) => match raw.trim().parse::<i64>() {
            Ok(id) => Some(id),
            Err(_) => {
                return crate::errors::validation_error(vec![json!({
                    "type": "int_parsing",
                    "loc": ["query", "website_id"],
                    "msg": "Input should be a valid integer, unable to parse string as an integer",
                    "input": raw,
                })])
            }
        },
        None => None,
    };
    let is_admin = permissions::has_role(&current.user.role, permissions::Role::Admin);
    axum::Json(json!({
        "jobs": crate::file_jobs::list(current.user.id, is_admin, website_id),
    }))
    .into_response()
}

/// `GET /maintenance/files/jobs/{job_id}`.
///
/// Source: `get_file_job`. A job that is not there is a 404 and a job that
/// belongs to somebody else is a 403 — **not** both answered as 404. The
/// ids are random, so the difference tells a caller nothing they could not
/// already tell by whether they made the job.
async fn get_file_job(AxumPath(job_id): AxumPath<String>, current: CurrentUser) -> Response {
    let Some(job) = crate::file_jobs::get(&job_id) else {
        return not_found("File job not found");
    };
    if job.user_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return crate::errors::error(axum::http::StatusCode::FORBIDDEN, "Access denied");
    }
    axum::Json(job.public()).into_response()
}

/// Source: `_run_extract_job` and `file_manager.extract_archive`.
///
/// **The ownership check runs again here.** The job carries only a key, and
/// by the time the worker picks it up the request that queued it is long
/// gone — a site that changed hands, or a user that was deactivated, must
/// not have work done on its behalf because a queue entry outlived the
/// decision.
async fn run_extract_job(
    state: &AppState,
    user_id: i64,
    target_key: &str,
    archive_path: &str,
    destination_path: &str,
) -> Result<String, String> {
    let user = match state.db.users().by_id(user_id).await {
        Ok(Some(user)) if user.is_active => user,
        Ok(_) => return Err("User not found".to_string()),
        Err(e) => return Err(e.to_string()),
    };
    let website_id: i64 = target_key
        .strip_prefix("site:")
        .and_then(|raw| raw.parse().ok())
        .ok_or_else(|| "Website not found".to_string())?;
    let website = match state.db.websites().by_id(website_id).await {
        Ok(Some(w)) => w,
        Ok(None) => return Err("Website not found".to_string()),
        Err(e) => return Err(e.to_string()),
    };
    if website.owner_id != user.id && !permissions::has_role(&user.role, permissions::Role::Admin) {
        return Err("Access denied".to_string());
    }

    let archive_file =
        files::safe_path(&website.root_path, archive_path, false).map_err(|e| e.to_string())?;
    if !archive_file.is_file() {
        return Err("Archive not found".to_string());
    }
    if std::fs::symlink_metadata(&archive_file).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("Symlinks are not allowed".to_string());
    }
    // `destination_path or str(Path(archive_path).parent)` — an empty
    // destination unpacks beside the archive, not at the site root.
    let destination_rel = if destination_path.is_empty() {
        std::path::Path::new(archive_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        destination_path.to_string()
    };
    let destination =
        files::safe_path(&website.root_path, &destination_rel, false).map_err(|e| e.to_string())?;
    if !destination.is_dir() {
        return Err("Extract destination not found".to_string());
    }

    let name = archive_file
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let archive_kind = if name.ends_with(".zip") {
        let entries = crate::archive::read_zip_entries(&archive_file)
            .map_err(|_| "Invalid or corrupted ZIP archive".to_string())?;
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        let implied = crate::archive::implied_dirs(&names);
        crate::archive::zip_uncompressed_size(&entries, &destination, &archive_file, &implied)?;
        "zip"
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let entries = crate::archive::read_tar_entries(&archive_file)
            .map_err(|_| "Invalid or corrupted tar archive".to_string())?;
        crate::archive::tar_uncompressed_size(&entries, &destination, &archive_file)?;
        "tar.gz"
    } else {
        return Err("Only .zip, .tar.gz, and .tgz archives can be extracted".to_string());
    };

    let Some(linux_user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) else {
        // No runtime user means a development box with no helper; the
        // Python unpacks in-process there, which is not a path this serves.
        return Err("Website has no runtime user configured".to_string());
    };
    let root = std::fs::canonicalize(&website.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
    let root_str = root.to_string_lossy().into_owned();
    let archive_rel = files::helper_relative_path(&website.root_path, &archive_file);
    let destination_rel_helper = files::helper_relative_path(&website.root_path, &destination);
    let max_items = crate::archive::max_archive_items().to_string();
    let max_bytes = crate::archive::max_archive_uncompressed_bytes().to_string();
    let result = shell::privileged(
        state.settings.command_dry_run,
        "site-archive-extract",
        &[
            linux_user,
            &root_str,
            &archive_rel,
            &destination_rel_helper,
            archive_kind,
            &max_items,
            &max_bytes,
        ],
        None,
        None,
    )
    .await;
    if !result.ok() {
        return Err(result
            .failure_detail("Could not extract the archive")
            .trim()
            .to_string());
    }

    let destination_str = destination.to_string_lossy().into_owned();
    // Everything the helper just wrote belongs to the site's runtime user,
    // and nginx is still serving whatever the old files rendered to.
    fix_site_path(state, &destination_str, website.linux_user.as_deref()).await;
    clear_fastcgi_cache(state).await;
    // `log_action(db, user.id, "extract_archive", ...)` — distinct from the
    // `extract_archive_queued` line the request wrote. One says somebody
    // asked; only this one says it happened.
    audit_detail(
        state,
        user.id,
        "extract_archive",
        &website.domain,
        archive_path,
    )
    .await;
    Ok(destination_str)
}

/// Source: `get_php_versions`.
async fn get_php_versions(current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    axum::Json(json!({
        "installed": php::list_installed_php(),
        "supported": php::SUPPORTED_PHP_VERSIONS,
    }))
    .into_response()
}

/// Source: `install_php_version`.
async fn install_php_version(
    State(state): State<AppState>,
    AxumPath(php_version): AxumPath<String>,
    current: CurrentUser,
) -> Response {
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    if !php::SUPPORTED_PHP_VERSIONS.contains(&php_version.as_str()) {
        let mut allowed: Vec<&str> = php::SUPPORTED_PHP_VERSIONS.to_vec();
        allowed.sort_unstable();
        return bad_request(&format!(
            "Unsupported PHP version. Allowed: {}",
            allowed.join(", ")
        ));
    }
    let already =
        std::path::Path::new(&format!("/etc/php/{php_version}/fpm/php-fpm.conf")).exists();
    if state.settings.command_dry_run {
        let action = if already { "repair" } else { "install" };
        return axum::Json(json!({
            "status": "dry_run",
            "message": format!("Would {action} php{php_version} and SNPanel extensions"),
        }))
        .into_response();
    }

    let packages = php::install_packages(&php_version);
    let mut fallback: Vec<&str> = vec!["apt-get", "install", "-y"];
    fallback.extend(packages.iter().map(String::as_str));
    let result =
        shell::privileged(false, "php-install", &[&php_version], None, Some(&fallback)).await;
    if !result.ok() {
        return internal_error();
    }
    axum::Json(json!({
        "status": if already { "ensured" } else { "installed" },
        "version": php_version,
        "output": result.stdout,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// the file manager's writes: moving, copying, creating and saving
// ---------------------------------------------------------------------------

/// Source: `_quota_check_for_website` - the closure the file manager calls
/// before it writes anything.
///
/// The quota belongs to the website's **owner**, not to whoever is making the
/// request. An administrator writing into a customer's site spends the
/// customer's allowance, which is the only reading that makes sense: the bytes
/// land under the customer's home.
async fn quota_check(
    state: &AppState,
    owner_id: i64,
    incoming_bytes: u64,
    replaced_bytes: u64,
) -> Result<(), Response> {
    let owner = match state.db.users().by_id(owner_id).await {
        Ok(Some(u)) => u,
        // Source: `website.owner` being `None`. The Python would raise
        // `AttributeError` reading `.role` off it, which is a 500 - not a
        // silently unlimited write.
        Ok(None) => {
            tracing::error!("no owner row for user {owner_id}");
            return Err(internal_error());
        }
        Err(e) => {
            tracing::error!("owner lookup failed: {e}");
            return Err(internal_error());
        }
    };
    let subject = crate::storage_quota::QuotaSubject {
        dry_run: state.settings.command_dry_run,
        user_id: owner.id,
        role: &owner.role,
        storage_limit_mb: owner.storage_limit_mb,
        application_installed: super::addons::application_installed(),
    };
    match crate::storage_quota::enforce_user_storage_quota(
        &state.db,
        &subject,
        incoming_bytes,
        replaced_bytes,
    )
    .await
    {
        Ok(()) => Ok(()),
        // Source: `except storage_quota.StorageQuotaExceeded` -> **413**, not
        // the 400 every other `ValueError` here becomes. The frontend tells
        // the two apart, and so does a customer: one means "fix your input",
        // the other means "buy more disk".
        Err(e) => Err(crate::errors::error(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            &e.to_string(),
        )),
    }
}

/// Source: `_existing_file_size` - what a write is about to replace. Zero for
/// a directory or anything that is not there.
fn existing_file_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.size()
        })
        .unwrap_or(0)
}

/// Source: `_total_size` - directories walked, files stat'ed.
fn total_size(paths: &[std::path::PathBuf]) -> u64 {
    paths
        .iter()
        .map(|p| {
            if p.is_dir() {
                crate::storage_quota::path_usage_bytes(p)
            } else if p.is_file() {
                existing_file_size(p)
            } else {
                0
            }
        })
        .sum()
}

/// Source: `_transfer_sources`.
///
/// The last loop is the one worth reading twice. Having resolved every path,
/// it drops any source that already sits under another selected **directory**,
/// so selecting a folder and a file inside it copies the folder once rather
/// than copying the folder and then dropping the file into the destination's
/// top level. The sort is by path depth, so a parent is always seen before its
/// children; Python's sort is stable, so two paths of equal depth keep the
/// order they were sent in.
fn transfer_sources(
    root_path: &str,
    paths: &[&str],
    action: &str,
    allow_executable: bool,
    allow_sensitive: bool,
) -> Result<Vec<std::path::PathBuf>, String> {
    let root =
        std::fs::canonicalize(root_path).unwrap_or_else(|_| std::path::PathBuf::from(root_path));

    let mut sources: Vec<std::path::PathBuf> = Vec::new();
    for relative in paths {
        let source = files::safe_path(root_path, relative, true).map_err(|e| e.to_string())?;
        if !source.exists() {
            return Err("File or folder not found".to_string());
        }
        if source == root {
            return Err(format!("Cannot {} website root", action.to_lowercase()));
        }
        if std::fs::symlink_metadata(&source)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err("Symlinks are not allowed".to_string());
        }
        if action == "Copying" {
            files::assert_tree_read_allowed(&source, action, allow_sensitive)
                .map_err(|e| e.to_string())?;
        }
        // `allow_symlinks` is **false** here, which is the Python's default and
        // how `_transfer_sources` calls it. The delete path passes true on
        // purpose - a symlink has to be deletable - but a copy or a move must
        // not walk one.
        files::assert_tree_write_allowed(&source, action, allow_executable, false)
            .map_err(|e| e.to_string())?;
        sources.push(source);
    }
    if sources.is_empty() {
        return Err("Select files or folders first".to_string());
    }

    // Source: `dict.fromkeys(sources)` - duplicates removed, first occurrence
    // kept, then sorted by how many components the path has.
    let mut unique: Vec<std::path::PathBuf> = Vec::new();
    for source in sources {
        if !unique.contains(&source) {
            unique.push(source);
        }
    }
    unique.sort_by_key(|p| p.components().count());

    let mut top_level: Vec<std::path::PathBuf> = Vec::new();
    for source in unique {
        // `parent in source.parents` in the Python, and `source.parents`
        // never contains the path itself - which is what the `source !=
        // *parent` clause is here for, because `Path::starts_with` does count
        // a path as starting with itself. Breaking that clause on purpose does
        // not fail the corpus, and cannot: the dedup above means `top_level`
        // can never hold a path equal to the one being tested. It is the
        // faithful translation rather than a live guard, and is kept as one.
        //
        // `starts_with` is component-wise, so `/a/bcd` does not start with
        // `/a/bc`. A string prefix test here would filter out a sibling whose
        // name happens to begin with another's.
        if top_level
            .iter()
            .any(|parent| parent.is_dir() && source.starts_with(parent) && source != *parent)
        {
            continue;
        }
        top_level.push(source);
    }
    Ok(top_level)
}

/// Source: `_transfer_destination`.
fn transfer_destination(
    root_path: &str,
    destination_path: &str,
) -> Result<std::path::PathBuf, String> {
    let destination =
        files::safe_path(root_path, destination_path, true).map_err(|e| e.to_string())?;
    if !destination.is_dir() {
        return Err("Destination folder not found".to_string());
    }
    if std::fs::symlink_metadata(&destination)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err("Symlinks are not allowed".to_string());
    }
    Ok(destination)
}

/// Source: `_assert_transfer_target`.
fn assert_transfer_target(
    source: &std::path::Path,
    destination: &std::path::Path,
    target: &std::path::Path,
    action: &str,
) -> Result<(), String> {
    // Moving a folder into itself, or into anything under itself, would move
    // the destination out from under the operation half way through.
    if source.is_dir() && (destination == source || destination.starts_with(source)) {
        return Err(format!(
            "Cannot {} a folder into itself",
            action.to_lowercase()
        ));
    }
    let exists_or_link = target.exists()
        || std::fs::symlink_metadata(target)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
    if exists_or_link {
        return Err(format!(
            "Target already exists: {}",
            target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
    }
    Ok(())
}

/// The part `copy` and `move` share: resolve the sources, resolve the
/// destination, and check every target before touching any of them.
///
/// Checking all of them first is the Python's order and it matters: a
/// half-finished transfer that stopped on the third of five files leaves the
/// customer to work out which two moved.
fn plan_transfer(
    website: &snpanel_db::Website,
    payload: &Value,
    action: &str,
    allow_executable: bool,
    allow_sensitive: bool,
) -> Result<Vec<(std::path::PathBuf, std::path::PathBuf)>, Response> {
    let Some(paths) = payload.get("paths").and_then(Value::as_array) else {
        return Err(crate::errors::missing_field("paths", payload.clone()));
    };
    let destination_path = payload
        .get("destination_path")
        .and_then(Value::as_str)
        .unwrap_or("");

    let mut relatives: Vec<&str> = Vec::new();
    for value in paths {
        let Some(text) = value.as_str() else {
            return Err(crate::errors::string_type("paths", value));
        };
        relatives.push(text);
    }

    let plan = (|| -> Result<Vec<(std::path::PathBuf, std::path::PathBuf)>, String> {
        let sources = transfer_sources(
            &website.root_path,
            &relatives,
            action,
            allow_executable,
            allow_sensitive,
        )?;
        let destination = transfer_destination(&website.root_path, destination_path)?;

        let verb = if action == "Copying" { "copy" } else { "move" };
        let mut pairs = Vec::new();
        for source in sources {
            let Some(name) = source.file_name() else {
                return Err("File or folder not found".to_string());
            };
            let target = destination.join(name);
            assert_transfer_target(&source, &destination, &target, verb)?;
            files::assert_write_allowed(&target, action, allow_executable)
                .map_err(|e| e.to_string())?;
            pairs.push((source, target));
        }
        Ok(pairs)
    })();
    // Source: the router's `except ValueError as exc: raise HTTPException(400,
    // detail=str(exc))` - one place, so every message above reaches the
    // customer unchanged.
    plan.map_err(|message| bad_request(&message))
}

/// Source: `move_entries` / `move_entries` the endpoint.
///
/// No quota check: the bytes do not leave the customer's home, so moving
/// cannot take them over their limit.
async fn move_entries(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let allow_executable = permissions::is_admin_role(&current.user.role);

    // `move_entries` passes `allow_sensitive` nowhere, so it keeps its default
    // of false - but `_transfer_sources` only reads it for "Copying", so it
    // makes no difference here. Passed explicitly rather than left implied.
    let pairs = match plan_transfer(&website, &payload, "Moving", allow_executable, false) {
        Ok(p) => p,
        Err(r) => return r,
    };

    let mut moved: Vec<String> = Vec::new();
    for (source, target) in pairs {
        let source_str = source.to_string_lossy().into_owned();
        let target_str = target.to_string_lossy().into_owned();
        if website.linux_user.as_deref().is_some_and(|u| !u.is_empty()) {
            let source_rel = files::helper_relative_path(&website.root_path, &source);
            let target_rel = files::helper_relative_path(&website.root_path, &target);
            if let Err(r) = run_as_site_user(
                &state,
                &website,
                "mv",
                &["--", &source_rel, &target_rel],
                &["mv", "--", &source_str, &target_str],
            )
            .await
            {
                return r;
            }
        } else if let Err(e) = std::fs::rename(&source, &target) {
            return bad_request(&format!("Cannot move: {e}"));
        }
        fix_site_path(&state, &target_str, website.linux_user.as_deref()).await;
        moved.push(target_str);
    }
    clear_fastcgi_cache(&state).await;

    let detail = format!(
        "{} -> {}",
        payload
            .get("paths")
            .and_then(Value::as_array)
            .map(|a| a
                .iter()
                .take(20)
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","))
            .unwrap_or_default(),
        payload
            .get("destination_path")
            .and_then(Value::as_str)
            .unwrap_or("")
    );
    audit_detail(
        &state,
        current.user.id,
        "move_files",
        &website.domain,
        &detail,
    )
    .await;
    axum::Json(json!({ "moved": moved })).into_response()
}

/// Source: `copy_entries` / `copy_entries` the endpoint.
async fn copy_entries(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let admin = permissions::is_admin_role(&current.user.role);

    let pairs = match plan_transfer(&website, &payload, "Copying", admin, admin) {
        Ok(p) => p,
        Err(r) => return r,
    };

    // The quota is checked once, for the whole selection, **after** every
    // target has been validated and before anything is written. `replaced` is
    // zero: a copy cannot overwrite, because `_assert_transfer_target` has
    // already refused every target that exists.
    let sources: Vec<std::path::PathBuf> = pairs.iter().map(|(s, _)| s.clone()).collect();
    if let Err(r) = quota_check(&state, website.owner_id, total_size(&sources), 0).await {
        return r;
    }

    let mut copied: Vec<String> = Vec::new();
    for (source, target) in pairs {
        let source_str = source.to_string_lossy().into_owned();
        let target_str = target.to_string_lossy().into_owned();
        if website.linux_user.as_deref().is_some_and(|u| !u.is_empty()) {
            let source_rel = files::helper_relative_path(&website.root_path, &source);
            let target_rel = files::helper_relative_path(&website.root_path, &target);
            if let Err(r) = run_as_site_user(
                &state,
                &website,
                "cp",
                &["-R", "--", &source_rel, &target_rel],
                &["cp", "-R", "--", &source_str, &target_str],
            )
            .await
            {
                return r;
            }
        } else if let Err(e) = copy_tree(&source, &target) {
            return bad_request(&format!("Cannot copy: {e}"));
        }
        fix_site_path(&state, &target_str, website.linux_user.as_deref()).await;
        copied.push(target_str);
    }
    clear_fastcgi_cache(&state).await;

    let detail = format!(
        "{} -> {}",
        payload
            .get("paths")
            .and_then(Value::as_array)
            .map(|a| a
                .iter()
                .take(20)
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","))
            .unwrap_or_default(),
        payload
            .get("destination_path")
            .and_then(Value::as_str)
            .unwrap_or("")
    );
    audit_detail(
        &state,
        current.user.id,
        "copy_files",
        &website.domain,
        &detail,
    )
    .await;
    axum::Json(json!({ "copied": copied })).into_response()
}

/// Source: `shutil.copytree(..., copy_function=shutil.copy2)` for a directory
/// and `shutil.copy2` for a file - the local path, used only when the website
/// has no runtime user of its own.
fn copy_tree(source: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
    if source.is_dir() {
        std::fs::create_dir_all(target)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(source, target).map(|_| ())
    }
}

/// Source: `create_file` / `create_text_file` - an empty file.
async fn create_file(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let name = match string_field(&payload, "name") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let parent_path = payload.get("path").and_then(Value::as_str).unwrap_or("");

    let parent = match files::safe_path(&website.root_path, parent_path, true) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if parent.exists() && !parent.is_dir() {
        return bad_request("Parent path is not a directory");
    }
    if std::fs::symlink_metadata(&parent)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return bad_request("Symlinks are not allowed");
    }
    let safe_name = match files::safe_entry_name(&name) {
        Ok(n) => n,
        Err(e) => return bad_request(&e.to_string()),
    };
    let target = parent.join(&safe_name);
    if target.exists() {
        return bad_request("File or folder already exists");
    }
    if let Err(e) = files::assert_write_allowed(
        &target,
        "Creating",
        permissions::is_admin_role(&current.user.role),
    ) {
        return bad_request(&e.to_string());
    }
    // `quota_check(0, 0)`: zero incoming bytes, so this refuses only a
    // customer who is *already* over their limit. That is deliberate in the
    // Python - an account over quota should not be able to keep adding files,
    // even empty ones.
    if let Err(r) = quota_check(&state, website.owner_id, 0, 0).await {
        return r;
    }

    let target_str = target.to_string_lossy().into_owned();
    if let Err(r) = write_as_site_user(&state, &website, &target, "").await {
        return r;
    }
    fix_site_path(&state, &target_str, website.linux_user.as_deref()).await;
    clear_fastcgi_cache(&state).await;

    audit_detail(
        &state,
        current.user.id,
        "create_file",
        &website.domain,
        &target_str,
    )
    .await;
    axum::Json(json!({ "target": target_str })).into_response()
}

/// Source: `write_file` / `write_text_file`.
async fn write_file(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let (raw, payload) = match body_and_json(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match file_target(&state, &current, &payload).await {
        Ok(Target::Website(w)) => *w,
        Ok(Target::Upstream) => return to_upstream(&state, parts, raw).await,
        Err(r) => return r,
    };
    let relative = match string_field(&payload, "path") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = payload
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let target = match files::safe_path(&website.root_path, &relative, true) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    if let Err(e) = files::assert_write_allowed(
        &target,
        "Writing",
        permissions::is_admin_role(&current.user.role),
    ) {
        return bad_request(&e.to_string());
    }
    // The Python measures the encoded length, not the character count.
    let content_size = content.len() as u64;
    if content_size > files::MAX_TEXT_FILE_BYTES {
        return bad_request("File content is too large");
    }
    if std::fs::symlink_metadata(&target)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        // C36: never act through a symlink. A file the customer can edit that
        // points at `/etc/nginx` is a file the customer can edit in
        // `/etc/nginx`.
        return bad_request("Refusing to write through a symlink");
    }
    if let Err(r) = quota_check(
        &state,
        website.owner_id,
        content_size,
        existing_file_size(&target),
    )
    .await
    {
        return r;
    }

    let target_str = target.to_string_lossy().into_owned();
    if let Err(r) = write_as_site_user(&state, &website, &target, &content).await {
        return r;
    }
    fix_site_path(&state, &target_str, website.linux_user.as_deref()).await;
    clear_fastcgi_cache(&state).await;

    audit_detail(
        &state,
        current.user.id,
        "write_file",
        &website.domain,
        &target_str,
    )
    .await;
    axum::Json(json!({ "target": target_str })).into_response()
}

/// Source: `_write_text_as_site_user`.
///
/// The content goes in on **stdin**, never in argv. C37: a file a customer is
/// editing can hold anything, and a command line is visible in `ps` to every
/// account on the machine.
async fn write_as_site_user(
    state: &AppState,
    website: &snpanel_db::Website,
    target: &std::path::Path,
    content: &str,
) -> Result<(), Response> {
    let Some(user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) else {
        // Source: the `if not website.linux_user` branch - a plain local
        // write, used on a development box with no site accounts.
        if let Some(parent) = target.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        return std::fs::write(target, content)
            .map_err(|e| bad_request(&format!("Cannot write the file: {e}")));
    };
    let root = std::fs::canonicalize(&website.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
    let root_str = root.to_string_lossy().into_owned();
    let relative = files::helper_relative_path(&website.root_path, target);
    let target_str = target.to_string_lossy().into_owned();

    let result = shell::privileged(
        state.settings.command_dry_run,
        "site-file-write",
        &[user, &root_str, &relative],
        Some(content),
        Some(&["tee", &target_str]),
    )
    .await;
    if result.ok() {
        Ok(())
    } else {
        Err(bad_request(
            result.failure_detail("Cannot write the file").trim(),
        ))
    }
}

// ---------------------------------------------------------------------------
// cron
// ---------------------------------------------------------------------------

/// Source: `platform.web_user()` - "`www-data` on Ubuntu, `nginx` on EL".
///
/// Shared with `websites::retarget_website_cron`, which has to install a
/// retargeted job under the same account the original was installed under.
///
/// A job installed under the wrong name does not run at all, which is the
/// quietest way for a backup or a WordPress cron to stop happening.
pub(super) fn web_user() -> String {
    snpanel_osabi::detect()
        .map(|p| p.web_user().to_string())
        .unwrap_or_else(|_| "www-data".to_string())
}

/// Source: `cron.list_cron_all`.
pub(super) async fn list_cron_all(state: &AppState, cron_user: &str) -> String {
    let result = shell::privileged(
        state.settings.command_dry_run,
        "cron-list",
        &[cron_user],
        None,
        Some(&["bash", "-lc", "crontab -l 2>/dev/null || true"]),
    )
    .await;
    result.stdout
}

/// Source: `cron.list_cron` - the lines carrying this site's marker.
fn lines_for_domain(all: &str, domain: &str) -> Vec<String> {
    let marker = format!("snpanel:{domain}");
    all.lines()
        .filter(|line| line.contains(&marker))
        .map(str::to_string)
        .collect()
}

/// Source: `cron-write` - the whole crontab, replaced.
///
/// The helper takes the entire file on stdin because a crontab has no
/// line-addressed edit: the panel reads it, changes it, and writes it back.
pub(super) async fn write_crontab(
    state: &AppState,
    cron_user: &str,
    content: &str,
) -> Result<(), Response> {
    let result = shell::privileged(
        state.settings.command_dry_run,
        "cron-write",
        &[cron_user],
        Some(content),
        Some(&["bash", "-lc", "crontab -"]),
    )
    .await;
    if result.ok() {
        Ok(())
    } else {
        Err(bad_request(
            result.failure_detail("Cannot write the crontab").trim(),
        ))
    }
}

/// Source: `list_cron` the endpoint.
async fn list_cron(
    State(state): State<AppState>,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let cron_user = crate::cron::cron_user_for_website(
        website.linux_user.as_deref(),
        &website.root_path,
        &web_user(),
    );
    let Ok(domain) = crate::cron::validate_domain(&website.domain) else {
        return bad_request("Invalid domain");
    };

    let all = list_cron_all(&state, &cron_user).await;
    let items: Vec<Value> = lines_for_domain(&all, &domain)
        .iter()
        .enumerate()
        .map(|(index, line)| crate::cron::parse_cron_line(index, line))
        .collect();

    axum::Json(json!({
        "items": items,
        "cron_user": cron_user,
        "php_version": website.php_version,
        // Shown in the add-cron help so it is obvious which interpreter a job
        // runs on.
        "php_binary": crate::cron::php_binary(&website.php_version),
        "document_root": document_root_of(&website),
    }))
    .into_response()
}

/// Source: `site_users.document_root(website.root_path)` - the default
/// `public_html`, resolved.
fn document_root_of(website: &snpanel_db::Website) -> String {
    let root = crate::files::resolve(std::path::Path::new(&website.root_path));
    root.join("public_html").to_string_lossy().into_owned()
}

/// Source: `add_cron` the endpoint and `cron.add_cron`.
async fn add_cron(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(website_id) = payload.get("website_id").and_then(Value::as_i64) else {
        return crate::errors::missing_field("website_id", payload.clone());
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let schedule = match string_field(&payload, "schedule") {
        Ok(v) => v,
        Err(r) => return r,
    };
    let command = match string_field(&payload, "command") {
        Ok(v) => v,
        Err(r) => return r,
    };

    let cron_user = crate::cron::cron_user_for_website(
        website.linux_user.as_deref(),
        &website.root_path,
        &web_user(),
    );
    // Source: `if not website.linux_user and cron_user != "www-data"` - note
    // the **literal**, not `WEB_USER`. On EL the web user is `nginx`, so a
    // site with no runtime user of its own gets `linux_user` recorded there
    // and not on Debian. Reproduced rather than tidied: changing it would
    // start writing a column on one distribution that the Python leaves
    // empty.
    let adopt_user =
        website.linux_user.as_deref().unwrap_or("").is_empty() && cron_user != "www-data";

    let document_root = std::path::PathBuf::from(document_root_of(&website));
    let site_root = crate::files::resolve(std::path::Path::new(&website.root_path));
    let php_bin = crate::cron::php_binary(&website.php_version);
    let wp_cli = std::path::Path::new(crate::cron::WP_CLI_PATH).exists();

    let safe_schedule = match crate::cron::validate_schedule(&schedule) {
        Ok(v) => v,
        Err(e) => return bad_request(&e.to_string()),
    };
    let safe_command =
        match crate::cron::validate_command(&command, &document_root, &site_root, &php_bin, wp_cli)
        {
            Ok(v) => v,
            Err(e) => return bad_request(&e.to_string()),
        };
    let safe_domain = match crate::cron::validate_domain(&website.domain) {
        Ok(v) => v,
        Err(e) => return bad_request(&e.to_string()),
    };

    let line = format!(
        "{safe_schedule} cd {} && {} # snpanel:{safe_domain}",
        shell::shlex_quote(&document_root.to_string_lossy()),
        crate::cron::escape_percent(&safe_command)
    );

    // A site whose jobs run as its own account needs that account's home and
    // runtime to exist before cron tries to `cd` into it.
    if cron_user != web_user() {
        let runtime_php = if matches!(website.app_type.as_str(), "" | "wordpress" | "php") {
            website.php_version.clone()
        } else {
            "none".to_string()
        };
        let runtime_php = if runtime_php.is_empty() {
            "none".to_string()
        } else {
            runtime_php
        };
        let fallback_dir = document_root.to_string_lossy().into_owned();
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "site-runtime-ensure",
            &[&cron_user, &website.root_path, &runtime_php],
            None,
            Some(&["mkdir", "-p", &fallback_dir]),
        )
        .await;
    }

    let existing = list_cron_all(&state, &cron_user).await;
    let trimmed = existing.trim_end();
    let new_content = if trimmed.trim().is_empty() {
        format!("{line}\n")
    } else {
        format!("{trimmed}\n{line}\n")
    };
    if let Err(r) = write_crontab(&state, &cron_user, &new_content).await {
        return r;
    }

    if adopt_user {
        if let Err(e) = state
            .db
            .websites()
            .set_linux_user(website.id, &cron_user)
            .await
        {
            tracing::error!("recording the cron runtime user failed: {e}");
            return internal_error();
        }
    }

    audit_detail(&state, current.user.id, "add_cron", &website.domain, &line).await;
    axum::Json(json!({ "line": line, "cron_user": cron_user })).into_response()
}

/// Source: `delete_cron` the endpoint and `cron.delete_cron`.
///
/// The index is into **this site's** lines, not the whole crontab, and the
/// removal matches by text: two identical lines would both go, which is the
/// Python's behaviour and is the safe direction for a duplicate.
async fn delete_cron(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(website_id) = payload.get("website_id").and_then(Value::as_i64) else {
        return crate::errors::missing_field("website_id", payload.clone());
    };
    let Some(raw_index) = payload.get("index") else {
        return crate::errors::missing_field("index", payload.clone());
    };
    let Some(index) = raw_index.as_i64() else {
        return crate::errors::int_parsing("index", raw_index);
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let cron_user = crate::cron::cron_user_for_website(
        website.linux_user.as_deref(),
        &website.root_path,
        &web_user(),
    );
    let Ok(domain) = crate::cron::validate_domain(&website.domain) else {
        return bad_request("Invalid domain");
    };

    let all = list_cron_all(&state, &cron_user).await;
    let matching = lines_for_domain(&all, &domain);
    if index < 0 || index as usize >= matching.len() {
        return bad_request("Cron not found");
    }
    let target = matching[index as usize].clone();

    let kept: Vec<&str> = all
        .lines()
        .filter(|line| line.trim() != target.trim())
        .collect();
    let new_content = if kept.is_empty() {
        String::new()
    } else {
        kept.join("\n") + "\n"
    };
    if let Err(r) = write_crontab(&state, &cron_user, &new_content).await {
        return r;
    }

    audit_detail(
        &state,
        current.user.id,
        "delete_cron",
        &website.domain,
        &target,
    )
    .await;
    axum::Json(json!({ "deleted": target, "cron_user": cron_user })).into_response()
}

// ---------------------------------------------------------------------------
// WordPress
// ---------------------------------------------------------------------------

/// Source: `wordpress._wp_php_flag`.
///
/// "WP-CLI must run under the site's PHP. Left to the default `php`, a site on
/// one version gets updated by another version's CLI, which may not have the
/// extensions WordPress needs - mysqli in particular."
fn wp_php_flag(php_version: &str) -> Option<String> {
    let version = php_version.trim();
    (!version.is_empty()).then(|| format!("--php-version={version}"))
}

/// Source: `wordpress_action` and `wordpress.wp_update`.
async fn wordpress_action(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(website_id) = payload.get("website_id").and_then(Value::as_i64) else {
        return crate::errors::missing_field("website_id", payload.clone());
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let action = match string_field(&payload, "action") {
        Ok(v) => v,
        Err(r) => return r,
    };

    // The document root here is the website's **configured** one, unlike the
    // terminal's start directory which always uses `public_html`. WP-CLI is
    // pointed at where WordPress actually lives.
    let relative = if website.document_root.is_empty() {
        "public_html"
    } else {
        &website.document_root
    };
    let path = match files::safe_path(&website.root_path, relative, true) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => return bad_request(&e.to_string()),
    };

    let path_flag = format!("--path={path}");
    let args: Vec<&str> = match action.as_str() {
        "core" => vec!["core", "update", &path_flag, "--allow-root"],
        "plugins" => vec!["plugin", "update", "--all", &path_flag, "--allow-root"],
        "themes" => vec!["theme", "update", "--all", &path_flag, "--allow-root"],
        _ => return bad_request("Unsupported WordPress action"),
    };

    let user = website.linux_user.as_deref().unwrap_or("");
    let result = if user.is_empty() {
        // No runtime account: the helper runs WP-CLI itself.
        let mut fallback: Vec<&str> = vec!["wp"];
        fallback.extend_from_slice(&args);
        shell::privileged(
            state.settings.command_dry_run,
            "wp",
            &args,
            None,
            Some(&fallback),
        )
        .await
    } else {
        let flag = wp_php_flag(&website.php_version);
        let mut helper_args: Vec<&str> = vec![user];
        if let Some(flag) = flag.as_deref() {
            helper_args.push(flag);
        }
        helper_args.extend_from_slice(&args);
        let mut fallback: Vec<&str> = vec!["wp"];
        fallback.extend_from_slice(&args);
        shell::privileged(
            state.settings.command_dry_run,
            "wp-site",
            &helper_args,
            None,
            Some(&fallback),
        )
        .await
    };

    // Source: `return result.__dict__` - the command result itself, so the
    // page can show WP-CLI's output whether it worked or not.
    axum::Json(result.to_json()).into_response()
}

/// Source: `fix_wordpress_permissions`.
///
/// The runtime is ensured first when the site has its own account: fixing
/// ownership on a tree whose home does not exist yet would leave the files
/// owned by an account cron and PHP-FPM cannot use.
async fn fix_wordpress_permissions(
    State(state): State<AppState>,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let user = website.linux_user.clone().unwrap_or_default();
    if !user.is_empty() {
        let runtime_php = if matches!(website.app_type.as_str(), "" | "wordpress" | "php") {
            let v = website.php_version.clone();
            if v.is_empty() {
                "none".to_string()
            } else {
                v
            }
        } else {
            "none".to_string()
        };
        let fallback_dir = document_root_of(&website);
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "site-runtime-ensure",
            &[&user, &website.root_path, &runtime_php],
            None,
            Some(&["mkdir", "-p", &fallback_dir]),
        )
        .await;
    }

    // Source: `site_users.fix_site_permissions` - two shapes, because the
    // helper derives different ownership from one argument than from two.
    if user.is_empty() {
        let owner = format!("{}:{}", web_user(), web_group());
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "fix-permissions",
            &[&website.root_path],
            None,
            Some(&["chown", "-R", &owner, &website.root_path]),
        )
        .await;
    } else {
        let Ok(safe_user) = snpanel_core::types::PanelUsername::parse(&user) else {
            return bad_request("Invalid panel Linux user");
        };
        let owner = format!("{}:{}", safe_user.as_str(), safe_user.as_str());
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "fix-permissions",
            &[&website.root_path, safe_user.as_str()],
            None,
            Some(&["chown", "-R", &owner, &website.root_path]),
        )
        .await;
    }

    audit_detail(
        &state,
        current.user.id,
        "fix_permissions",
        &website.domain,
        &website.root_path,
    )
    .await;
    axum::Json(json!({
        "message": format!("Fixed permissions for {}", website.domain),
        "root_path": website.root_path,
    }))
    .into_response()
}

/// Source: `platform.web_group()`.
pub(super) fn web_group() -> String {
    snpanel_osabi::detect()
        .map(|p| p.web_group().to_string())
        .unwrap_or_else(|_| "www-data".to_string())
}

// ---------------------------------------------------------------------------
// the DirectAdmin backup archives waiting to be imported
// ---------------------------------------------------------------------------

/// Source: `da_import.ARCHIVE_SUFFIXES`.
pub(crate) const ARCHIVE_SUFFIXES: &[&str] = &[
    ".tar.zst", ".tzst", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar",
];

/// Source: `da_import.DA_BACKUP_DIR`.
fn da_backup_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("SNPANEL_DA_BACKUP_DIR")
            .unwrap_or_else(|_| "/home/admin/snpanel_backups/da".to_string()),
    )
}

/// Source: `da_import._is_archive` - a **file**, with one of the suffixes,
/// matched case-insensitively on the name.
fn is_archive(path: &std::path::Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    ARCHIVE_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Source: `da_import.safe_upload_name`.
///
/// The uploaded name comes straight from the browser, so every directory
/// component goes before it is joined onto the backup directory. A **dot
/// leader is refused** as well as `.` and `..`: a file called
/// `.bashrc.tar.gz` in a directory somebody later globs is a surprise
/// nobody needs, and no DirectAdmin backup is named that way.
fn da_safe_upload_name(filename: &str) -> Result<String, String> {
    let normalized = filename.replace('\\', "/");
    let name = std::path::Path::new(&normalized)
        .file_name()
        .map(|n| n.to_string_lossy().trim().to_string())
        .unwrap_or_default();
    if name.is_empty() || name == "." || name == ".." || name.starts_with('.') {
        return Err("Invalid backup filename".to_string());
    }
    let lower = name.to_lowercase();
    if !ARCHIVE_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return Err(format!(
            "Unsupported archive type. Expected one of: {}",
            ARCHIVE_SUFFIXES.join(", ")
        ));
    }
    Ok(name)
}

/// `POST /maintenance/da-import/upload`.
///
/// Source: `upload_da_backup`.
///
/// A name that is already taken is a **409**, not an overwrite. These are
/// other people's account backups waiting to be imported, and replacing one
/// with another of the same name would import the wrong customer — the same
/// reasoning as the restore folder, and the opposite of a site's own backup
/// folder where a collision means a re-upload.
async fn upload_da_backup(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let files = match upload_parts(&state, parts.clone(), body, "file").await {
        Ok(f) => f,
        Err(r) => return r,
    };
    let Some((filename, data)) = files.into_iter().next() else {
        return crate::errors::missing_field("file", Value::Null);
    };
    // `file.filename or ""` — and an empty name is refused rather than
    // given a default, because a DirectAdmin backup's name is what says
    // whose account it is.
    let name = match da_safe_upload_name(&filename) {
        Ok(n) => n,
        Err(e) => return bad_request(&e),
    };

    let dir = da_backup_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!("creating the DA backup directory failed: {e}");
        return crate::errors::internal_error();
    }
    let destination = dir.join(&name);
    if destination.exists() {
        return conflict("A backup with this name already exists");
    }
    if let Err(e) = std::fs::write(&destination, &data) {
        // `except Exception: destination.unlink(missing_ok=True); raise` —
        // a half-written archive left behind would be listed as importable.
        let _ = std::fs::remove_file(&destination);
        tracing::error!("writing the DA backup failed: {e}");
        return crate::errors::internal_error();
    }
    let size = std::fs::metadata(&destination)
        .map(|m| m.len())
        .unwrap_or(0);

    audit_detail(&state, current.user.id, "da_backup_upload", &name, "").await;
    axum::Json(json!({
        "filename": name,
        "path": destination.to_string_lossy(),
        "size": size,
    }))
    .into_response()
}

/// Source: `da_import.resolve_backup_path` - "confining it to the upload
/// directory keeps the endpoints from reading or deleting arbitrary files on
/// the host".
///
/// Scan, import and delete all take this path from the request body, so this
/// is the boundary. An absolute path is allowed *through* the check rather
/// than refused outright, because the listing hands absolute paths back and
/// the page sends one of them straight back - but it still has to resolve
/// inside the directory.
fn resolve_backup_path(archive_path: &str) -> Result<std::path::PathBuf, String> {
    let raw = archive_path.trim();
    if raw.is_empty() {
        return Err("archive_path is required".to_string());
    }
    let root = crate::files::resolve(&da_backup_dir());
    let candidate = std::path::Path::new(raw);
    let resolved = crate::files::resolve(&if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    });
    if !resolved.starts_with(&root) {
        return Err(format!("Backup must be inside {}", root.display()));
    }
    Ok(resolved)
}

/// Source: `list_da_backups`.
async fn list_da_backups(State(state): State<AppState>, current: CurrentUser) -> Response {
    let _ = &state;
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let dir = da_backup_dir();
    // `DA_BACKUP_DIR.mkdir(parents=True, exist_ok=True)` - the Python creates
    // it, so an operator opening the page before anything has been uploaded
    // sees an empty list rather than an error.
    let _ = std::fs::create_dir_all(&dir);

    let mut paths: Vec<std::path::PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.flatten().map(|e| e.path()).collect(),
        Err(_) => Vec::new(),
    };
    // `sorted(DA_BACKUP_DIR.iterdir())` sorts the whole path, which for one
    // directory is the same as sorting by name.
    paths.sort();

    let items: Vec<Value> = paths
        .iter()
        .filter(|p| is_archive(p))
        .map(|p| {
            let size = std::fs::metadata(p).map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.size()
            });
            json!({
                "filename": p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                "path": p.to_string_lossy(),
                "size": size.unwrap_or(0),
            })
        })
        .collect();
    axum::Json(items).into_response()
}

/// Source: `delete_da_backup`.
/// `POST /maintenance/da-import/scan`.
///
/// Source: `scan_da_backup` - "extract a DA backup into a staging dir,
/// discover users/domains/databases".
///
/// **Nothing is created and nothing is changed.** This is what an operator
/// looks at before deciding to import, so an archive that cannot be read
/// answers with the reason in `errors` rather than a status code: a scan
/// that found half an account is more use than one that refused to say
/// anything.
///
/// The work is entirely filesystem - unpacking tens of gigabytes and
/// walking it - so it runs on the blocking pool rather than holding a
/// worker thread for minutes.
async fn scan_da_backup(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `body.get("archive_path", "")` - the endpoint takes a bare dict, so
    // a field of the wrong type is `""` rather than a 422.
    let archive_path = payload
        .get("archive_path")
        .and_then(Value::as_str)
        .unwrap_or("");
    if archive_path.is_empty() {
        return bad_request("archive_path is required");
    }
    let path = match resolve_backup_path(archive_path) {
        Ok(p) => p,
        Err(e) => return bad_request(&e),
    };
    if !path.exists() {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        return not_found(&format!("Backup not found: {name}"));
    }
    if !is_archive(&path) {
        return bad_request("Not a supported archive format");
    }

    match tokio::task::spawn_blocking(move || scan_backup_archive(&path)).await {
        Ok(result) => axum::Json(result).into_response(),
        Err(e) => {
            tracing::error!("the DA scan task failed: {e}");
            internal_error()
        }
    }
}

/// The body of the scan, off the async runtime.
///
/// Source: everything inside `scan_da_backup`'s
/// `with tempfile.TemporaryDirectory(...)`.
fn scan_backup_archive(path: &std::path::Path) -> Value {
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut result = serde_json::json!({
        "filename": filename,
        "size": size,
        "archive_path": path.to_string_lossy(),
        "users": [],
        "errors": [],
    });

    // `STAGE_BASE.mkdir(...)` then a temporary directory **inside** it,
    // removed however this returns.
    let stage = crate::da_import::stage_base();
    if let Err(e) = std::fs::create_dir_all(&stage) {
        result["errors"] = serde_json::json!([format!("Extraction failed: {e}")]);
        return result;
    }
    let Some(temp) = crate::da_import::make_stage_dir(&stage, "snpanel-da-scan-") else {
        result["errors"] = serde_json::json!(["Extraction failed: could not stage the archive"]);
        return result;
    };
    let extracted = temp.join("extracted");

    if let Err(message) = crate::da_import::safe_extract_tar(path, &extracted) {
        // `result["errors"].append(...)` then `return result` - a scan
        // that cannot open the archive says so and answers 200, because
        // the page shows the reason beside the file.
        result["errors"] = serde_json::json!([format!("Extraction failed: {message}")]);
        let _ = std::fs::remove_dir_all(&temp);
        return result;
    }

    let root = crate::da_import::find_backup_root(&extracted);
    crate::da_import::extract_nested_domain_archives(&root);
    result["users"] = serde_json::json!([crate::da_import::scan_extracted(&root, &filename)]);

    let _ = std::fs::remove_dir_all(&temp);
    result
}

/// Source: `import_da_backup` (the service).
///
/// One archive becomes a panel user, its websites, their files, their
/// vhosts and their databases. The shape is the Python's throughout, and
/// three of its decisions are the ones that matter:
///
/// - **Delete before create, and only with `force`.** The conflict check
///   runs first and refuses without it, because a re-run of a finished
///   import would otherwise wipe a site that has been live for a month.
/// - **A failure inside one domain is a warning, not an abort.** An
///   account with eight sites and one broken config should import seven
///   sites, not none.
/// - **The staging tree is removed however this returns.** It holds a
///   full copy of the customer's files.
async fn run_da_import(
    state: &AppState,
    archive: &std::path::Path,
    force: bool,
) -> Result<Value, String> {
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !is_archive(archive) {
        return Err("Not a supported archive format".to_string());
    }
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let Some(stage_dir) = crate::da_import::make_import_stage() else {
        return Err("Could not create the import staging directory".to_string());
    };

    let outcome = import_into(state, archive, &name, &stamp, &stage_dir, force).await;
    // `finally: shutil.rmtree(stage_dir, ignore_errors=True)` - the tree
    // holds a full copy of the customer's files and must not outlive the
    // import, however it ended.
    let _ = std::fs::remove_dir_all(&stage_dir);
    outcome
}

/// The body of [`run_da_import`], so the staging cleanup is written once.
async fn import_into(
    state: &AppState,
    archive: &std::path::Path,
    archive_name: &str,
    stamp: &str,
    stage_dir: &std::path::Path,
    force: bool,
) -> Result<Value, String> {
    let mut credentials = crate::da_import::credentials_header(stamp, archive_name);
    let extracted = stage_dir.join("extracted");

    let extract_archive = archive.to_path_buf();
    let extract_target = extracted.clone();
    tokio::task::spawn_blocking(move || {
        crate::da_import::safe_extract_tar(&extract_archive, &extract_target)
    })
    .await
    .map_err(|e| e.to_string())??;

    let root = crate::da_import::find_backup_root(&extracted);
    crate::da_import::extract_nested_domain_archives(&root);
    let domains = crate::da_import::discover_domains(&root);
    let (username, email) = crate::da_import::discover_username(&root, archive_name);
    let subdomains = crate::da_import::relocate_subdomain_sources(&root, &domains);
    let all = crate::da_import::all_domains(&domains, &subdomains);

    let mut warnings: Vec<String> = Vec::new();
    let mut imported: Vec<String> = Vec::new();
    let mut databases: Vec<Value> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();

    if all.is_empty() {
        warnings.push("No domains found".to_string());
        return Ok(import_summary(
            archive_name,
            &username,
            &all,
            &imported,
            &databases,
            &aliases,
            &warnings,
            &credentials,
        ));
    }

    // `if not force:` - the conflict check, before anything is touched.
    if !force {
        let user_exists = matches!(state.db.users().by_username(&username).await, Ok(Some(_)));
        let mut taken: Vec<String> = Vec::new();
        for domain in &all {
            if matches!(state.db.websites().by_domain(domain).await, Ok(Some(_))) {
                taken.push(domain.clone());
            }
        }
        if let Some(message) = crate::da_import::conflict_message(user_exists, &username, &taken) {
            warnings.push(message);
            return Ok(import_summary(
                archive_name,
                &username,
                &all,
                &imported,
                &databases,
                &aliases,
                &warnings,
                &credentials,
            ));
        }
    }

    for domain in &all {
        delete_existing_domain(state, domain).await;
    }
    delete_existing_user(state, &username).await;

    let password = crate::mariadb::random_password(24);
    let panel_user = match snpanel_core::types::PanelUsername::parse(&username) {
        Ok(user) => user,
        Err(_) => return Err(format!("Invalid panel Linux user: {username}")),
    };
    let dry = state.settings.command_dry_run;
    let ensured =
        shell::privileged(dry, "panel-user-ensure", &[panel_user.as_str()], None, None).await;
    if !ensured.ok() {
        return Err(ensured
            .failure_detail("Could not create the system account")
            .trim()
            .to_string());
    }
    let set = shell::privileged(
        dry,
        "panel-user-password",
        &[panel_user.as_str()],
        // On stdin, never in argv.
        Some(&format!("{password}\n")),
        None,
    )
    .await;
    if !set.ok() {
        return Err(set
            .failure_detail("Could not set the system password")
            .trim()
            .to_string());
    }

    let taken_emails = state.db.users().all_emails().await.unwrap_or_default();
    let account_email = crate::da_import::unique_email(&username, &email, &all, &taken_emails);
    let hashed = snpanel_core::crypto::password::hash_password(&password)
        .map_err(|e| format!("hashing failed: {e}"))?;
    let user_id = state
        .db
        .users()
        .create(&snpanel_db::NewUser {
            username: &username,
            email: &account_email,
            hashed_password: &hashed,
            role: "end_user",
            package_id: None,
            // `max(5, len(domains) + 5)` - room for what came in plus a
            // few, so the first site a customer adds does not refuse.
            website_limit: std::cmp::max(5, all.len() as i64 + 5),
            storage_limit_mb: crate::da_import::default_storage_mb(),
            terminal_enabled: false,
        })
        .await
        .map_err(|e| format!("creating the panel user failed: {e}"))?;
    credentials.push(format!(
        "panel_user username={username} password={password}"
    ));

    let sql_files = crate::da_import::discover_sql_files(&root);
    let mut imported_sql: Vec<String> = Vec::new();
    let targets = crate::da_import::import_targets(&root, &domains, &subdomains);
    let single_site = targets.len() == 1;

    for target in &targets {
        match import_one_domain(
            state,
            &root,
            stage_dir,
            &panel_user,
            user_id,
            target,
            &sql_files,
            single_site,
            &mut credentials,
            &mut databases,
            &mut aliases,
            &mut imported_sql,
        )
        .await
        {
            Ok(extra) => {
                imported.push(target.domain.clone());
                warnings.extend(extra);
            }
            // One domain's failure is a warning: an account with eight
            // sites and one broken config should import seven.
            Err(message) => warnings.push(format!("{}: import failed: {message}", target.domain)),
        }
    }

    Ok(import_summary(
        archive_name,
        &username,
        &all,
        &imported,
        &databases,
        &aliases,
        &warnings,
        &credentials,
    ))
}

/// Source: the `item_summary` dict plus the `{"summary", "credentials",
/// "errors"}` the endpoint answers with.
#[allow(clippy::too_many_arguments)]
fn import_summary(
    archive: &str,
    username: &str,
    domains: &[String],
    imported: &[String],
    databases: &[Value],
    aliases: &[String],
    warnings: &[String],
    credentials: &[String],
) -> Value {
    json!({
        "summary": [{
            "archive": archive,
            "username": username,
            "domains": domains,
            "imported_domains": imported,
            "databases": databases,
            "aliases": aliases,
            "ssl_enabled_domains": [],
            "warnings": warnings,
        }],
        "credentials": credentials,
        "errors": crate::da_import::errors_from_warnings(warnings),
    })
}

/// Source: the body of `import_da_backup`'s per-domain loop.
///
/// Returns the warnings this domain produced; anything that stops the
/// domain being importable at all is an error, which the caller records
/// as a warning against the account rather than letting it end the run.
#[allow(clippy::too_many_arguments)]
async fn import_one_domain(
    state: &AppState,
    root: &std::path::Path,
    stage_dir: &std::path::Path,
    panel_user: &snpanel_core::types::PanelUsername,
    user_id: i64,
    target: &crate::da_import::ImportTarget,
    sql_files: &std::collections::BTreeMap<String, std::path::PathBuf>,
    single_site: bool,
    credentials: &mut Vec<String>,
    databases: &mut Vec<Value>,
    aliases: &mut Vec<String>,
    imported_sql: &mut Vec<String>,
) -> Result<Vec<String>, String> {
    let mut warnings: Vec<String> = Vec::new();
    let dry = state.settings.command_dry_run;
    let domain = &target.domain;
    let php = crate::da_import::default_php_version();

    let app_type = crate::da_import::detect_app_type(target.source.as_deref());
    let app_config = match &target.source {
        Some(source) => crate::da_import::parse_app_db_config(source),
        None => std::collections::BTreeMap::new(),
    };
    // A static site gets no PHP pool at all, which is the point of
    // calling it static: no interpreter is started and none can be
    // reached.
    let runtime_php = matches!(app_type, "wordpress" | "php").then(|| php.clone());

    let root_path = format!("/home/{}/{}", panel_user.as_str(), domain);
    let ensured = shell::privileged(
        dry,
        "site-runtime-ensure",
        &[
            panel_user.as_str(),
            &root_path,
            runtime_php.as_deref().unwrap_or("none"),
        ],
        None,
        None,
    )
    .await;
    if !ensured.ok() {
        return Err(ensured
            .failure_detail("Could not prepare the website directory")
            .trim()
            .to_string());
    }

    // The site directory belongs to its Linux user, so this process
    // cannot write into it. The files are copied into a panel-owned
    // staging tree laid out like the site root, and the helper moves them
    // in as root.
    if let Some(source) = &target.source {
        let staged = stage_dir.join("payload").join(domain);
        let public = staged.join("public_html");
        let copy_source = source.clone();
        tokio::task::spawn_blocking(move || {
            crate::da_import::copy_site_files(Some(&copy_source), &public)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("could not stage the site files: {e}"))?;

        let populated = shell::privileged(
            dry,
            "site-populate",
            &[panel_user.as_str(), &root_path, &staged.to_string_lossy()],
            None,
            None,
        )
        .await;
        if !populated.ok() {
            return Err(populated
                .failure_detail("Could not import the site files")
                .trim()
                .to_string());
        }
    }

    // Imported sites arrive with the default rules and CRS **off**, like
    // any new site: a rule set the customer never chose, turned on during
    // an import they did not watch, is how a site comes back broken.
    let rule_ids: Vec<String> = crate::waf::DEFAULT_RULES
        .iter()
        .map(|rule| rule.id.to_string())
        .collect();
    let mut waf_enabled = true;
    match crate::waf::sync_site_rules(dry, domain, &rule_ids, "", "off").await {
        Ok(result) if result.ok() => {}
        _ => {
            waf_enabled = false;
            warnings.push(format!("WAF rules failed for {domain}"));
        }
    }

    // Write the vhost, and retry without the WAF if nginx refuses it: a
    // site that serves with no rule file beats a site that does not serve.
    let mut wrote = write_import_vhost(
        state,
        domain,
        &root_path,
        panel_user,
        app_type,
        runtime_php.as_deref(),
        waf_enabled,
        &[],
        &[],
    )
    .await;
    if wrote.is_err() && waf_enabled {
        waf_enabled = false;
        warnings.push(format!(
            "nginx rejected WAF for {domain}; retrying with WAF disabled"
        ));
        wrote = write_import_vhost(
            state,
            domain,
            &root_path,
            panel_user,
            app_type,
            runtime_php.as_deref(),
            false,
            &[],
            &[],
        )
        .await;
    }
    wrote?;

    let rewrite_mode = if app_type == "wordpress" {
        "front_controller"
    } else {
        "none"
    };
    let created_at = snpanel_db::sqlalchemy_now();
    let website_id = state
        .db
        .websites()
        .create(&snpanel_db::NewWebsite {
            domain,
            owner_id: user_id,
            root_path: &root_path,
            document_root: "public_html",
            linux_user: Some(panel_user.as_str()),
            php_version: &php,
            app_type,
            nginx_rewrite_mode: rewrite_mode,
            app_id: None,
            status: "active",
            waf_enabled,
            created_at: &created_at,
        })
        .await
        .map_err(|e| format!("creating the website row failed: {e}"))?;

    // DirectAdmin domain pointers become this panel's website aliases.
    // An alias domain is globally unique, so one already owned elsewhere
    // is recorded as a warning rather than stolen.
    let pointers = crate::da_import::discover_domain_pointers(root, domain);
    let mut applied: Vec<(String, String)> = Vec::new();
    for (pointer, mode) in pointers {
        match state.db.websites().by_domain(&pointer).await {
            Ok(Some(_)) => {
                warnings.push(format!("Pointer {pointer} is already a website; skipped"));
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                warnings.push(format!("Could not check pointer {pointer}: {e}"));
                continue;
            }
        }
        match state
            .db
            .websites()
            .alias_create(website_id, &pointer, &mode)
            .await
        {
            Ok(_) => {
                aliases.push(format!("{pointer} ({mode})"));
                applied.push((pointer, mode));
            }
            Err(e) => warnings.push(format!("Pointer {pointer} not added: {e}")),
        }
    }
    if !applied.is_empty() {
        let alias_domains: Vec<String> = applied
            .iter()
            .filter(|(_, mode)| mode == "alias")
            .map(|(name, _)| name.clone())
            .collect();
        let redirect_domains: Vec<String> = applied
            .iter()
            .filter(|(_, mode)| mode == "redirect")
            .map(|(name, _)| name.clone())
            .collect();
        if let Err(message) = write_import_vhost(
            state,
            domain,
            &root_path,
            panel_user,
            app_type,
            runtime_php.as_deref(),
            waf_enabled,
            &alias_domains,
            &redirect_domains,
        )
        .await
        {
            warnings.push(format!(
                "Pointers for {domain} not applied to Nginx: {message}"
            ));
        }
    }

    let _ = shell::privileged(
        dry,
        "fix-permissions",
        &[&root_path, panel_user.as_str()],
        None,
        None,
    )
    .await;

    // --- the database -----------------------------------------------------
    let (matched_key, matched_sql) =
        crate::da_import::matched_sql_for_config(&app_config, sql_files, single_site);
    if let Some(sql_path) = matched_sql {
        let da_credentials = crate::da_import::da_db_credentials(sql_path, root);
        let old_db = app_config
            .get("DB_NAME")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or(matched_key.clone());
        let old_user = app_config.get("DB_USER").filter(|v| !v.is_empty()).cloned();

        match create_imported_database(
            state,
            user_id,
            Some(website_id),
            domain,
            &old_db,
            old_user.as_deref(),
            Some(sql_path),
            &app_config,
            &da_credentials,
            credentials,
        )
        .await
        {
            Ok((db_name, db_user, db_password, reused)) => {
                imported_sql.push(matched_key.clone());
                // When the site's own config already carries the working
                // secret, leave it alone; only rewrite when the panel
                // changed the password.
                if !reused {
                    let public = std::path::PathBuf::from(&root_path).join("public_html");
                    let staged = stage_dir.join("payload").join(domain).join("public_html");
                    // The live tree belongs to the site's user, so the
                    // rewrite happens in the staging copy and is moved
                    // back in through the helper.
                    if staged.is_dir() {
                        let name = db_name.clone();
                        let user = db_user.clone();
                        let pass = db_password.clone();
                        let target_dir = staged.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::da_import::update_config_dir(&target_dir, &name, &user, &pass)
                        })
                        .await;
                        let repopulated = shell::privileged(
                            dry,
                            "site-populate",
                            &[
                                panel_user.as_str(),
                                &root_path,
                                &stage_dir.join("payload").join(domain).to_string_lossy(),
                            ],
                            None,
                            None,
                        )
                        .await;
                        if !repopulated.ok() {
                            warnings.push(format!(
                                "Could not rewrite the database config for {domain}"
                            ));
                        }
                    }
                    let _ = public;
                }
                let _ = shell::privileged(
                    dry,
                    "fix-permissions",
                    &[&root_path, panel_user.as_str()],
                    None,
                    None,
                )
                .await;
                databases.push(json!({
                    "domain": domain,
                    "source": sql_path.to_string_lossy(),
                    "db_name": db_name,
                }));
            }
            Err(message) => warnings.push(format!("Database for {domain} not imported: {message}")),
        }
    }

    Ok(warnings)
}

/// Source: `_create_panel_database`.
#[allow(clippy::too_many_arguments)]
async fn create_imported_database(
    state: &AppState,
    owner_id: i64,
    website_id: Option<i64>,
    target: &str,
    old_db: &str,
    old_user: Option<&str>,
    sql_file: Option<&std::path::Path>,
    app_config: &std::collections::BTreeMap<String, String>,
    da_credentials: &crate::da_import::DaPassword,
    credentials: &mut Vec<String>,
) -> Result<(String, String, String, bool), String> {
    let existing = state
        .db
        .databases()
        .list(None, "")
        .await
        .unwrap_or_default();
    let used_names: Vec<String> = existing.iter().map(|d| d.db_name.clone()).collect();
    let used_users: Vec<String> = existing.iter().map(|d| d.db_user.clone()).collect();

    let fallback = crate::mariadb::safe_db_identifier(target, "da");
    let db_name = crate::da_import::normalize_db_identifier(old_db, &fallback, &used_names);
    let user_fallback: String = format!("u_{db_name}").chars().take(64).collect();
    let db_user = crate::da_import::normalize_db_identifier(
        old_user.unwrap_or(&db_name),
        &user_fallback,
        &used_users,
    );

    let generated = crate::mariadb::random_password(24);
    let mut chosen = crate::da_import::import_db_password(app_config, da_credentials, &generated);
    // A reused secret only helps if the config still points at this
    // database and this user.
    if chosen.reused
        && crate::da_import::rename_invalidates_reuse(old_db, &db_name, old_user, &db_user)
    {
        chosen = crate::da_import::ImportPassword {
            password: crate::mariadb::random_password(24),
            password_hash: String::new(),
            reused: false,
        };
    }

    crate::mariadb::create_database_credentials(
        &db_name,
        &db_user,
        &chosen.password,
        Some(&chosen.password_hash)
            .filter(|h| !h.is_empty())
            .map(String::as_str),
        true,
    )
    .await
    .map_err(|e| e.to_string())?;

    if let Some(sql_file) = sql_file {
        match import_sql_dump(state, &db_name, sql_file).await {
            Ok(()) => {}
            Err(message) => {
                // The half-made database goes with the failure: one left
                // behind is invisible to the panel and nothing would ever
                // clean it up.
                let _ = crate::mariadb::drop_database(&db_name, &db_user).await;
                return Err(message);
            }
        }
    }

    // The panel cannot recover the plaintext behind a reused hash, so it
    // stores what it can: an empty secret the operator resets if needed.
    let encrypted = if chosen.password.is_empty() {
        String::new()
    } else {
        snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, &chosen.password)
    };
    state
        .db
        .databases()
        .create(owner_id, website_id, &db_name, &db_user, &encrypted)
        .await
        .map_err(|e| e.to_string())?;

    credentials.push(crate::da_import::database_credential_line(
        target,
        &db_name,
        &db_user,
        &chosen.password,
    ));
    Ok((db_name, db_user, chosen.password, chosen.reused))
}

/// Source: `_temporary_sql_file` then `mariadb.import_database`.
///
/// The dump may be compressed four ways; it is decompressed into the
/// staging area first, because `mysql` reads a plain stream.
async fn import_sql_dump(
    state: &AppState,
    db_name: &str,
    sql_file: &std::path::Path,
) -> Result<(), String> {
    let source = sql_file.to_path_buf();
    let plain = tokio::task::spawn_blocking(move || crate::da_import::decompress_sql(&source))
        .await
        .map_err(|e| e.to_string())??;
    let result = crate::mariadb::import_database(
        state.settings.command_dry_run,
        db_name,
        &plain.to_string_lossy(),
    )
    .await;
    let _ = std::fs::remove_file(&plain);
    result.map_err(|e| e.to_string())
}

/// Write an imported site's vhost.
#[allow(clippy::too_many_arguments)]
async fn write_import_vhost(
    state: &AppState,
    domain: &str,
    root_path: &str,
    panel_user: &snpanel_core::types::PanelUsername,
    app_type: &str,
    runtime_php: Option<&str>,
    waf_enabled: bool,
    aliases: &[String],
    redirects: &[String],
) -> Result<(), String> {
    let custom = snpanel_nginx::CustomDirectives::validate("").map_err(|e| e.to_string())?;
    let root = std::path::PathBuf::from(root_path);
    let socket = runtime_php.map(|version| {
        let resolved = std::fs::canonicalize(root_path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| root_path.to_string());
        let hash = snpanel_core::types::site_hash(&resolved);
        format!(
            "/run/php/snpanel-{}-{hash}-{}.sock",
            panel_user.as_str(),
            version.replace('.', "_")
        )
    });
    let mut input = snpanel_nginx::VhostInput::new(domain, &root, &custom);
    input.app_type = app_type;
    input.php_version = runtime_php;
    input.php_fpm_socket_override = socket.as_deref();
    input.document_root = "public_html";
    input.rewrite_mode = Some(if app_type == "wordpress" {
        "front_controller"
    } else {
        "none"
    });
    input.waf_enabled = waf_enabled;
    input.aliases = aliases;
    input.redirects = redirects;

    let env = snpanel_nginx::VhostEnv {
        ipv6: crate::system::ipv6_enabled(),
        waf_engine: crate::system::waf_engine_available(),
        default_php_version: state.settings.default_php_version.clone(),
        home_root: std::path::PathBuf::from("/home"),
    };
    let sites = std::path::PathBuf::from(&state.settings.nginx_sites_available);
    let plan =
        snpanel_nginx::plan_rewrite(&input, &env, &sites, None, true).map_err(|e| e.to_string())?;

    if !state.settings.command_dry_run {
        let write = shell::privileged(
            false,
            "nginx-custom-write",
            &[domain],
            Some(plan.custom_include.as_str()),
            None,
        )
        .await;
        if !write.ok() {
            return Err(write
                .failure_detail("Cannot write Nginx config")
                .trim()
                .to_string());
        }
    }
    super::websites::apply_vhost_plan(state, plan).await
}

/// Source: `_delete_existing_domain`.
async fn delete_existing_domain(state: &AppState, domain: &str) {
    let Ok(Some(website)) = state.db.websites().by_domain(domain).await else {
        return;
    };
    for item in state
        .db
        .databases()
        .for_website(website.id)
        .await
        .unwrap_or_default()
    {
        let _ = crate::mariadb::drop_database(&item.db_name, &item.db_user).await;
        let _ = state.db.databases().delete(item.id).await;
    }
    let _ = shell::privileged(
        state.settings.command_dry_run,
        "nginx-vhost-delete",
        &[domain],
        None,
        None,
    )
    .await;
    let _ = state.db.websites().delete(website.id).await;
}

/// Source: `_delete_existing_user`.
async fn delete_existing_user(state: &AppState, username: &str) {
    let Ok(Some(user)) = state.db.users().by_username(username).await else {
        return;
    };
    for website in state
        .db
        .websites()
        .list(Some(user.id), "")
        .await
        .unwrap_or_default()
    {
        delete_existing_domain(state, &website.domain).await;
    }
    for item in state
        .db
        .databases()
        .for_owner(user.id)
        .await
        .unwrap_or_default()
    {
        let _ = crate::mariadb::drop_database(&item.db_name, &item.db_user).await;
        let _ = state.db.databases().delete(item.id).await;
    }
    if let Ok(panel_user) = snpanel_core::types::PanelUsername::parse(username) {
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "panel-user-delete",
            &[panel_user.as_str()],
            None,
            None,
        )
        .await;
    }
    let _ = state.db.users().delete(user.id).await;
}

/// `POST /maintenance/da-import/import`.
///
/// Source: `import_da_backup` (the endpoint). Starts a background job and
/// answers immediately: a real account backup takes minutes to hours, and
/// a request held open for that would time out in the browser while the
/// import carried on invisibly.
///
/// **A 429 when an import is already running**, of either kind. The work
/// deletes and recreates panel users, sites, files and databases; two of
/// them at once would race over the same rows and the same directories.
async fn start_da_import(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `body.get("archive_path", "")` - a bare dict, so a field of the
    // wrong type reads as empty rather than as a 422.
    let archive_path = payload
        .get("archive_path")
        .and_then(Value::as_str)
        .unwrap_or("");
    // `bool(body.get("force", False))` - Python truthiness, not pydantic:
    // this endpoint takes a `dict`, so `"yes"` and `1` are both true and
    // `""` and `0` are both false.
    let force = python_truthy(payload.get("force"));

    let path = match resolve_backup_path(archive_path) {
        Ok(p) => p,
        Err(e) => return bad_request(&e),
    };
    if !path.exists() {
        return not_found("Backup file not found");
    }
    if crate::da_jobs::any_running() {
        return crate::errors::error(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "An import is already running. Please wait.",
        );
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let job = crate::da_jobs::new_single_job(&name, &path.to_string_lossy());
    let job_id = job["id"].as_str().unwrap_or("").to_string();
    crate::da_jobs::remember(crate::da_jobs::Kind::Single, &job);

    let worker_state = state.clone();
    let worker_id = job_id.clone();
    let worker_path = path.clone();
    tokio::spawn(async move {
        crate::da_jobs::update(
            crate::da_jobs::Kind::Single,
            &worker_id,
            vec![("status", json!("running"))],
        );
        match run_da_import(&worker_state, &worker_path, force).await {
            Ok(result) => crate::da_jobs::update(
                crate::da_jobs::Kind::Single,
                &worker_id,
                vec![("status", json!("completed")), ("result", result)],
            ),
            // `logger.exception(...)` then the job carries the reason: the
            // request that started this returned long ago, so the job is
            // the only place left to report it.
            Err(message) => {
                tracing::error!("DA import failed for {}: {message}", worker_path.display());
                crate::da_jobs::update(
                    crate::da_jobs::Kind::Single,
                    &worker_id,
                    vec![("status", json!("failed")), ("error", json!(message))],
                )
            }
        }
    });

    audit_detail(
        &state,
        current.user.id,
        "da_backup_import_start",
        &format!("{job_id} archive={name}"),
        "",
    )
    .await;
    axum::Json(json!({ "job_id": job_id, "status": "pending" })).into_response()
}

/// `GET /maintenance/da-import/jobs/{job_id}`.
///
/// Source: `get_da_import_job`. The registry is **only in memory**, so a
/// restart loses every record - which is why these four endpoints could
/// not be split across two processes for even one release.
async fn get_da_import_job(
    State(state): State<AppState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
    current: CurrentUser,
) -> Response {
    let _ = &state;
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    match crate::da_jobs::get(crate::da_jobs::Kind::Single, &job_id) {
        Some(job) => axum::Json(job).into_response(),
        None => not_found("Job not found"),
    }
}

/// `POST /maintenance/da-import/bulk-import`.
///
/// Source: `bulk_import_da_backups`. **Sequential, not parallel**: the
/// archives are imported one after another by a single worker, because
/// each one takes the same locks as a single import would.
///
/// Every path is resolved and checked **before** anything starts, so a
/// typo in the tenth archive is a 400 rather than nine finished imports
/// and a surprise.
async fn start_da_bulk_import(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `DaBulkImportRequest` is a pydantic model here, unlike the single
    // import's bare dict.
    let raw_paths = match payload.get("archive_paths") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                match item.as_str() {
                    Some(text) => out.push(text.to_string()),
                    None => return crate::errors::string_type("archive_paths", item),
                }
            }
            out
        }
        Some(other) => return crate::errors::list_type("archive_paths", other),
    };
    let force = crate::errors::read_bool("force", payload.get("force"), false);
    let force = match force {
        Ok(v) => v,
        Err(r) => return r,
    };
    if raw_paths.is_empty() {
        return bad_request("archive_paths is required");
    }

    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for raw in &raw_paths {
        let path = match resolve_backup_path(raw) {
            Ok(p) => p,
            Err(e) => return bad_request(&e),
        };
        if !path.exists() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            return not_found(&format!("Backup file not found: {name}"));
        }
        paths.push(path);
    }

    if crate::da_jobs::any_running() {
        return crate::errors::error(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "A bulk import is already running. Please wait.",
        );
    }

    let path_strings: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let job = crate::da_jobs::new_bulk_job(&path_strings);
    let job_id = job["id"].as_str().unwrap_or("").to_string();
    let total = paths.len();
    crate::da_jobs::remember(crate::da_jobs::Kind::Bulk, &job);

    let worker_state = state.clone();
    let worker_id = job_id.clone();
    tokio::spawn(async move {
        crate::da_jobs::update(
            crate::da_jobs::Kind::Bulk,
            &worker_id,
            vec![("status", json!("running"))],
        );
        let mut results: Vec<Value> = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            crate::da_jobs::update(
                crate::da_jobs::Kind::Bulk,
                &worker_id,
                vec![
                    ("current", json!(index)),
                    ("current_archive", json!(name.clone())),
                ],
            );
            // **One archive's failure does not stop the rest.** A bulk
            // import of twenty accounts that stopped on the third would
            // leave seventeen customers waiting on a retry.
            match run_da_import(&worker_state, path, force).await {
                Ok(result) => results.push(json!({
                    "archive": name,
                    "status": "completed",
                    "result": result,
                })),
                Err(message) => {
                    tracing::error!("DA bulk import failed for {}: {message}", path.display());
                    results.push(json!({
                        "archive": name,
                        "status": "failed",
                        "error": message,
                    }))
                }
            }
        }
        crate::da_jobs::update(
            crate::da_jobs::Kind::Bulk,
            &worker_id,
            vec![
                ("status", json!("completed")),
                ("results", json!(results)),
                ("current", json!(total)),
            ],
        );
    });

    audit_detail(
        &state,
        current.user.id,
        "da_bulk_import_start",
        &format!("{job_id} archives={total}"),
        "",
    )
    .await;
    axum::Json(json!({ "job_id": job_id, "status": "pending", "total": total })).into_response()
}

/// `GET /maintenance/da-import/bulk-jobs/{job_id}`.
async fn get_da_bulk_import_job(
    State(state): State<AppState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
    current: CurrentUser,
) -> Response {
    let _ = &state;
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    match crate::da_jobs::get(crate::da_jobs::Kind::Bulk, &job_id) {
        Some(job) => axum::Json(job).into_response(),
        None => not_found("Job not found"),
    }
}

/// Python's `bool(value)` for a field read out of a bare `dict`.
fn python_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

async fn delete_da_backup(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current).await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let archive_path = payload
        .get("archive_path")
        .and_then(Value::as_str)
        .unwrap_or("");
    // Source: the endpoint's own `if not archive_path` check, which runs
    // before `resolve_backup_path` would raise the same thing.
    if archive_path.is_empty() {
        return bad_request("archive_path is required");
    }
    let path = match resolve_backup_path(archive_path) {
        Ok(p) => p,
        Err(e) => return bad_request(&e),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Source: `FileNotFoundError` -> **404**, `ValueError` -> 400. The order
    // matters: a path that is not there is reported as missing rather than as
    // the wrong format.
    if !path.exists() {
        return not_found(&format!("Backup not found: {name}"));
    }
    if !is_archive(&path) {
        return bad_request("Not a supported archive format");
    }
    let _ = std::fs::remove_file(&path);

    audit_detail(&state, current.user.id, "da_backup_delete", &name, "").await;
    axum::Json(json!({ "deleted": name })).into_response()
}

#[cfg(test)]
mod da_import_tests {
    use super::*;
    use serde_json::Value;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/da_import.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the da import corpus"))
            .expect("the corpus parses")
    }

    /// What a browser may name an uploaded backup.
    ///
    /// The name arrives from the browser and is joined onto the backup
    /// directory, so every directory component has to go - including a
    /// Windows one, because the browser may be Windows.
    #[test]
    fn an_uploaded_backup_name_is_the_pythons() {
        let corpus = corpus();
        let cases = corpus["safe_upload_name"].as_array().expect("the cases");
        assert_eq!(cases.len(), 25, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let raw = case["filename"].as_str().unwrap_or("");
            let got = da_safe_upload_name(raw);
            match case["name"].as_str() {
                Some(want) => {
                    if got.as_deref() != Ok(want) {
                        failures.push(format!("{raw:?}: python {want:?}, rust {got:?}"));
                    }
                }
                None => {
                    if got.is_ok() {
                        failures.push(format!("{raw:?}: python refused it, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // The three that matter on their own.
        assert_eq!(
            da_safe_upload_name("C:\\Users\\me\\user.bob.tar.gz").unwrap(),
            "user.bob.tar.gz"
        );
        assert_eq!(
            da_safe_upload_name("../../etc/x.tar.gz").unwrap(),
            "x.tar.gz"
        );
        // A hidden name is refused rather than un-hidden: a file called
        // `.bashrc.tar.gz` in a directory somebody later globs is a
        // surprise nobody needs.
        assert!(da_safe_upload_name(".hidden.tar.gz").is_err());
    }

    /// Which suffixes the extractor will actually accept.
    ///
    /// **There is no `.zip`**, and that is not an oversight: a
    /// DirectAdmin account backup is a tar, and accepting a zip at upload
    /// would mean an archive the extractor cannot read being taken and
    /// then failing at import, hours later.
    #[test]
    fn the_accepted_archive_suffixes_are_the_pythons() {
        for good in [
            "a.tar.zst",
            "a.tzst",
            "a.tar.gz",
            "a.tgz",
            "a.tar.bz2",
            "a.tbz2",
            "a.tar.xz",
            "a.txz",
            "a.tar",
        ] {
            assert!(
                da_safe_upload_name(good).is_ok(),
                "{good} should be accepted"
            );
        }
        for bad in ["a.zip", "a.gz", "a.rar", "a.tar.gz.exe", "noext"] {
            assert!(da_safe_upload_name(bad).is_err(), "{bad} should be refused");
        }
        // The compound suffixes come first, so `.tar.gz` is matched whole
        // rather than as the `.tar` it is not.
        assert!(
            ARCHIVE_SUFFIXES
                .iter()
                .position(|s| *s == ".tar.gz")
                .unwrap()
                < ARCHIVE_SUFFIXES.iter().position(|s| *s == ".tar").unwrap()
        );
    }

    /// A path from the request body cannot leave the backup directory.
    ///
    /// Scan, import and delete all take this path from a JSON body, so it
    /// is the guard between a malformed request and reading - or deleting
    /// - an arbitrary file on the host.
    #[test]
    fn a_backup_path_cannot_escape_its_directory() {
        for escape in [
            "../../etc/passwd",
            "/etc/passwd",
            "..",
            "a/../../../etc/shadow",
            "/",
        ] {
            assert!(
                resolve_backup_path(escape).is_err(),
                "{escape:?} escaped the backup directory"
            );
        }
        // An empty path is a missing argument, not an escape.
        assert!(resolve_backup_path("").is_err());
        assert!(resolve_backup_path("   ").is_err());

        // A name inside it resolves to a path under the root.
        let inside = resolve_backup_path("user.bob.tar.gz").expect("a path inside");
        assert!(inside.starts_with(crate::files::resolve(&da_backup_dir())));
        // And so does a relative path that stays inside after `..`.
        let winding = resolve_backup_path("sub/../user.bob.tar.gz").expect("a path inside");
        assert_eq!(winding, inside);
    }
}

#[cfg(test)]
mod app_file_tests {
    use super::*;

    /// The two file targets are not interchangeable, and the differences are
    /// the ones the Python spells out rather than any I chose.
    #[test]
    fn an_application_target_differs_from_a_websites_in_three_ways() {
        let site = snpanel_db::Website {
            id: 1,
            domain: "example.test".into(),
            owner_id: 7,
            root_path: "/home/alice/example.test".into(),
            document_root: "public_html".into(),
            linux_user: Some("alice".into()),
            php_version: "8.3".into(),
            app_type: "wordpress".into(),
            ssl_enabled: false,
            ssl_mode: "none".into(),
            ssl_cert_path: None,
            ssl_key_path: None,
            ssl_ca_path: None,
            ssl_updated_at: None,
            ssl_source_domain: None,
            status: "active".into(),
            nginx_custom: String::new(),
            nginx_config_mode: "managed".into(),
            nginx_rewrite_mode: "none".into(),
            waf_enabled: true,
            waf_default_rules: String::new(),
            waf_custom_rules: String::new(),
            crs_enabled: false,
            http_flood_enabled: false,
            http_flood_config: String::new(),
            blocked_bots: String::new(),
            app_id: None,
        };
        let target = FileTarget::website(&site);
        assert_eq!(target.label, "example.test");
        assert_eq!(target.owner_id, 7);
        assert_eq!(target.root_path, "/home/alice/example.test");
        // A website leaves the executable question to the caller's role.
        assert_eq!(target.allow_executable, None);

        // An application's is `app:<name>`, and an executable always lands:
        // a `.js` entry point or a build script is what the tree is *for*.
        let app = FileTarget {
            root_path: "/home/alice/apps/api".into(),
            linux_user: Some("alice".into()),
            label: "app:api".into(),
            owner_id: 7,
            allow_executable: Some(true),
        };
        assert_eq!(app.label, "app:api");
        assert_eq!(app.allow_executable, Some(true));
    }

    /// Which of the two answers an upload gives is decided by the same field,
    /// so a target cannot end up logged as one and answered as the other.
    #[test]
    fn an_upload_answers_stored_for_an_application_and_target_for_a_site() {
        for (allow_executable, action, key) in [
            (None, "upload_file", "target"),
            (Some(true), "upload_app_file", "stored"),
        ] {
            let app = allow_executable.is_some();
            assert_eq!(
                if app {
                    "upload_app_file"
                } else {
                    "upload_file"
                },
                action
            );
            assert_eq!(if app { "stored" } else { "target" }, key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tree the corpus was generated over, rebuilt locally.
    ///
    /// Rebuilt rather than shipped, because what is being compared is what the
    /// selection logic *picks*, and that needs real directories to walk.
    fn build_transfer_tree(corpus: &Value, label: &str) -> std::path::PathBuf {
        let site_root =
            std::env::temp_dir().join(format!("transfer-test-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&site_root);
        std::fs::create_dir_all(&site_root).expect("the site root");
        let bytes = corpus["file_bytes"].as_u64().unwrap_or(100) as usize;
        for entry in corpus["tree"].as_array().expect("the tree") {
            let entry = entry.as_str().unwrap_or("");
            let target = site_root.join(entry.trim_end_matches('/'));
            if entry.ends_with('/') {
                std::fs::create_dir_all(&target).expect("a directory");
            } else {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).expect("a parent");
                }
                std::fs::write(&target, vec![b'x'; bytes]).expect("a file");
            }
        }
        site_root
    }

    fn transfer_corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/file_transfer.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the transfer corpus"))
            .expect("the corpus parses")
    }

    /// What `_transfer_sources` selects, and in what order.
    ///
    /// The order is not cosmetic: it is the order the copies happen in. And
    /// the filtering is the part a hand-written version gets wrong - selecting
    /// a folder *and* a file inside it has to copy the folder once, not copy
    /// the folder and then drop the file into the destination's top level.
    #[test]
    fn a_selection_is_reduced_the_way_python_reduces_it() {
        let corpus = transfer_corpus();
        let site_root = build_transfer_tree(&corpus, "select");
        let root_path = site_root.to_string_lossy().into_owned();

        let mut failures: Vec<String> = Vec::new();
        for case in corpus["selections"].as_array().expect("the selections") {
            let owned: Vec<String> = case["paths"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|v| v.as_str().unwrap_or("").to_string())
                        .collect()
                })
                .unwrap_or_default();
            let paths: Vec<&str> = owned.iter().map(String::as_str).collect();
            let got = transfer_sources(&root_path, &paths, "Copying", false, false);
            let label = format!("{:?}", case["paths"]);

            match (got, case.get("selected")) {
                (Ok(picked), Some(want)) => {
                    let want: Vec<String> = want
                        .as_array()
                        .expect("a list")
                        .iter()
                        .map(|v| v.as_str().unwrap_or("").to_string())
                        .collect();
                    let have: Vec<String> = picked
                        .iter()
                        .map(|p| {
                            p.strip_prefix(&site_root)
                                .unwrap_or(p)
                                .to_string_lossy()
                                .into_owned()
                        })
                        .collect();
                    if have != want {
                        failures.push(format!("{label}: python {want:?}, rust {have:?}"));
                    }
                    // Only selections made entirely of files are compared by
                    // size. A directory's own inode size is filesystem
                    // dependent - an empty one is 40 bytes on the box the
                    // corpus came from and 4096 on plenty of others - so a
                    // recorded total that includes one is not a number about
                    // this code.
                    if picked.iter().all(|p| p.is_file()) {
                        let want_size = case["total_size"].as_u64().unwrap_or(0);
                        let have_size = total_size(&picked);
                        if have_size != want_size {
                            failures.push(format!(
                                "{label}: size python {want_size}, rust {have_size}"
                            ));
                        }
                    }
                }
                (Err(detail), None) => {
                    // The message matters: it is what the file manager shows.
                    let want = case["error"].as_str().unwrap_or("");
                    if detail != want {
                        failures.push(format!("{label}: python {want:?}, rust {detail:?}"));
                    }
                }
                (Ok(picked), None) => failures.push(format!(
                    "{label}: python refused with {:?}, rust selected {} item(s)",
                    case["error"],
                    picked.len()
                )),
                (Err(detail), Some(want)) => {
                    failures.push(format!("{label}: python {want:?}, rust refused {detail:?}"))
                }
            }
        }

        let _ = std::fs::remove_dir_all(&site_root);
        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// `path_usage_bytes` over the same tree.
    ///
    /// The absolute totals are deliberately not compared - see above - so what
    /// is asserted is what does not depend on the filesystem: a single file is
    /// its own size, a missing path is zero, and a tree is bigger than the
    /// subtree inside it.
    #[test]
    fn a_tree_is_measured_file_by_file() {
        let corpus = transfer_corpus();
        let site_root = build_transfer_tree(&corpus, "usage");
        let bytes = corpus["file_bytes"].as_u64().unwrap_or(100);

        use crate::storage_quota::path_usage_bytes;
        assert_eq!(
            path_usage_bytes(site_root.join("public_html/readme.txt")),
            bytes
        );
        assert_eq!(path_usage_bytes(site_root.join("nope")), 0);

        let whole = path_usage_bytes(&site_root);
        let part = path_usage_bytes(site_root.join("public_html"));
        // public_html holds four files of `bytes` each, plus directory inodes.
        assert!(part >= 4 * bytes, "public_html measured {part}");
        assert!(
            whole > part,
            "the whole tree {whole} is not bigger than {part}"
        );

        let _ = std::fs::remove_dir_all(&site_root);
    }

    /// The limit, and the message a customer reads when a write does not fit.
    #[test]
    fn the_quota_arithmetic_and_its_message_are_pythons() {
        let corpus = transfer_corpus();
        let mut failures: Vec<String> = Vec::new();

        for case in corpus["limits"].as_array().expect("the limits") {
            let role = case["role"].as_str().unwrap_or("");
            // Python's `int(user.storage_limit_mb or 0)` turns None into 0,
            // and the Rust column is NOT NULL, so the None case is 0 here too.
            let limit_mb = case["limit_mb"].as_i64().unwrap_or(0);
            let want = case["limit_bytes"].as_u64();
            let got = crate::storage_quota::user_storage_limit_bytes(role, limit_mb);
            if got != want {
                failures.push(format!("{role} {limit_mb}: python {want:?}, rust {got:?}"));
            }
        }

        let mb = crate::storage_quota::BYTES_PER_MB;
        for case in corpus["messages"].as_array().expect("the quota cases") {
            let used = case["used"].as_u64().unwrap_or(0);
            let limit = case["limit"].as_u64().unwrap_or(0);
            let incoming = case["incoming"].as_u64().unwrap_or(0);
            let replaced = case["replaced"].as_u64().unwrap_or(0);
            let label = format!("{used}/{limit} +{incoming} -{replaced}");

            let projected = used.saturating_sub(replaced) + incoming;
            let want_projected = case["projected"].as_u64().unwrap_or(0);
            if projected != want_projected {
                failures.push(format!(
                    "{label}: projected python {want_projected}, rust {projected}"
                ));
            }
            let over = projected > limit;
            if over != case["over"].as_bool().unwrap_or(false) {
                failures.push(format!(
                    "{label}: over python {}, rust {over}",
                    case["over"]
                ));
            }
            if over {
                let message = format!(
                    "Storage quota exceeded: {} MB used/projected, limit {} MB",
                    projected / mb,
                    limit / mb
                );
                let want = case["message"].as_str().unwrap_or("");
                if message != want {
                    failures.push(format!("{label}: python {want:?}, rust {message:?}"));
                }
            }
        }

        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// `validate_cron` is a hand-written port of a regular expression, which
    /// is where this stage has already been wrong once. The answers come from
    /// the real `_validate_backup_schedule` rather than from re-reading the
    /// pattern that produced the port.
    #[test]
    fn the_cron_validator_agrees_with_python() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/cron_schedule.json");
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the cron corpus"))
                .expect("the corpus parses");
        assert!(cases.len() > 100, "the corpus shrank to {}", cases.len());
        let accepted = cases
            .iter()
            .filter(|c| c["ok"].as_bool().unwrap_or(false))
            .count();
        assert!(
            accepted > 20,
            "only {accepted} accepted; a corpus that refuses everything would \
             pass a validator that refuses everything"
        );

        let mut failures: Vec<String> = Vec::new();
        for case in &cases {
            let input = case["input"].as_str().expect("an input");
            let python_ok = case["ok"].as_bool().expect("a verdict");
            match (validate_cron(input), python_ok) {
                (Some(got), true) => {
                    let want = case["value"].as_str().unwrap_or("");
                    if got != want {
                        failures.push(format!("{input:?}: python {want:?}, rust {got:?}"));
                    }
                }
                (None, false) => {}
                (Some(got), false) => failures.push(format!(
                    "{input:?}: rust ACCEPTED as {got:?}, python refused"
                )),
                (None, true) => failures.push(format!("{input:?}: rust refused, python accepted")),
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    /// What a DirectAdmin backup upload may be called.
    ///
    /// Stricter than the panel's other uploads in one way and looser in
    /// another. Stricter: a **dot leader is refused** outright, so
    /// `.hidden.tar.gz` never lands in a directory the import endpoints
    /// later read and delete from. Looser: the suffix is matched
    /// case-insensitively, so `user.TAR.GZ` is accepted and keeps its own
    /// spelling — where the backup savers demand an exact `.tar.gz`.
    ///
    /// The name is trimmed *after* the directory components go, which is
    /// why `" .tar.gz"` is refused (it becomes `.tar.gz`) and
    /// `"user.tar.gz "` is not.
    #[test]
    fn a_da_backup_upload_is_named_the_way_python_names_it() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/da_upload.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the da corpus"))
                .expect("the corpus parses");

        let suffixes: Vec<&str> = corpus["archive_suffixes"]
            .as_array()
            .expect("the suffixes")
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect();
        assert_eq!(suffixes, ARCHIVE_SUFFIXES.to_vec());

        let cases = corpus["safe_upload_name"].as_array().expect("the cases");
        assert_eq!(cases.len(), 31, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut accepted = 0usize;
        let mut invalid = 0usize;
        let mut unsupported = 0usize;
        for case in cases {
            let filename = case["filename"].as_str().unwrap_or("");
            let got = da_safe_upload_name(filename);
            match (case.get("name").and_then(Value::as_str), case.get("error")) {
                (Some(want), _) => {
                    accepted += 1;
                    match got {
                        Ok(ref name) if name == want => {}
                        other => {
                            failures.push(format!("{filename:?}: python {want:?}, rust {other:?}"))
                        }
                    }
                }
                (None, Some(error)) => {
                    let want = error.as_str().unwrap_or("");
                    if want == "Invalid backup filename" {
                        invalid += 1;
                    } else {
                        unsupported += 1;
                    }
                    match got {
                        Err(ref e) if e == want => {}
                        other => {
                            failures.push(format!("{filename:?}: python {want:?}, rust {other:?}"))
                        }
                    }
                }
                _ => failures.push(format!("{filename:?}: the corpus says neither")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(accepted >= 15, "only {accepted} names accepted");
        assert!(invalid >= 7, "only {invalid} were invalid names");
        assert!(
            unsupported >= 3,
            "only {unsupported} were unsupported types"
        );

        // The three that separate this from the other upload paths.
        assert_eq!(
            da_safe_upload_name("user.TAR.GZ").ok(),
            Some("user.TAR.GZ".to_string()),
            "the suffix match folds case and the name keeps its own"
        );
        assert!(da_safe_upload_name(".hidden.tar.gz").is_err());
        assert!(da_safe_upload_name("a/.hidden.tar.gz").is_err());
        // Every directory component goes, including one that escapes.
        assert_eq!(
            da_safe_upload_name("../../etc/x.tar.gz").ok(),
            Some("x.tar.gz".to_string())
        );
    }

    /// A whole site backup, unpacked, with the members that must not land.
    ///
    /// The corpus in `tarfilter` proves the *decisions*; this proves that
    /// the extraction acts on them. Both archives were built by Python,
    /// because the `tar` crate's writer refuses to put `..` in a member
    /// name — the right default for a writer, and useless for a test whose
    /// point is that the reader refuses it.
    #[test]
    fn a_site_backup_unpacks_only_what_the_filter_allows() {
        use base64::Engine;

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/data_filter.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the filter corpus"))
                .expect("the corpus parses");
        let decode = |key: &str| -> Vec<u8> {
            base64::engine::general_purpose::STANDARD
                .decode(corpus["archives"][key].as_str().expect("the archive"))
                .expect("valid base64")
        };

        let base = std::env::temp_dir().join(format!(
            "restore-extract-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&base);
        let dest = base.join("site");
        std::fs::create_dir_all(&dest).expect("the destination");

        // The hostile archive carries `site/../escape.txt`, a symlink to
        // `/etc/passwd` and a FIFO. Any one of them stops the restore.
        let hostile = base.join("hostile.tar.gz");
        std::fs::write(&hostile, decode("hostile")).expect("the fixture");
        let result = extract_site_backup(&hostile, &dest);
        assert!(
            result.is_err(),
            "an unsafe archive was unpacked: {result:?}"
        );
        assert!(
            !base.join("escape.txt").exists(),
            "a member escaped the destination"
        );
        assert!(
            !dest.join("evil").exists(),
            "a link to /etc/passwd was written"
        );

        // The same archive without those three unpacks cleanly.
        let clean = base.join("clean.tar.gz");
        std::fs::write(&clean, decode("clean")).expect("the fixture");
        extract_site_backup(&clean, &dest).expect("the clean archive unpacks");

        // The `site/` prefix is gone.
        assert!(
            dest.join("index.php").is_file(),
            "the prefix was not stripped"
        );
        assert!(dest.join("sub").is_dir());
        assert!(
            !dest.join("site").exists(),
            "the prefix was kept as a folder"
        );
        // The database dump is not in the document root, where nginx could
        // serve it to anybody who guessed the name.
        assert!(
            !dest.join("dump.sql").exists() && !dest.join("database").exists(),
            "the database dump landed in the site"
        );
        // The setuid bit is gone, and the file is still executable.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dest.join("tool"))
            .expect("the tool")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o755, "setuid survived: {mode:o}");
        // A plain file keeps a sensible mode too.
        let mode = std::fs::metadata(dest.join("index.php"))
            .expect("the index")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o644, "{mode:o}");
        // The symlink landed as a link, pointing where it said.
        let link = dest.join("sub/link");
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("the link")
                .file_type()
                .is_symlink(),
            "the symlink was written as a file"
        );
        assert_eq!(
            std::fs::read_link(&link).expect("the target"),
            std::path::Path::new("../index.php")
        );

        // The names the reader hands the filter are Python's, without the
        // trailing slash a tar writer puts on a directory — every rule
        // downstream compares them against a literal, so one extra
        // character changes which branch fires.
        assert!(dest.join("sub").is_dir(), "the directory member landed");

        // An archive whose only `site` marker is the bare directory entry
        // still counts as prefixed: a backup of an empty site has nothing
        // else in it, and treating it as unprefixed would restore a folder
        // called `site` into the document root.
        let bare = base.join("bare.tar.gz");
        std::fs::write(&bare, decode("bare_prefix")).expect("the fixture");
        let empty = base.join("empty");
        std::fs::create_dir_all(&empty).expect("the second destination");
        extract_site_backup(&bare, &empty).expect("the bare archive unpacks");
        assert!(
            !empty.join("site").exists(),
            "the prefix was restored as a folder"
        );
        assert!(
            !empty.join("database").exists() && !empty.join("dump.sql").exists(),
            "the dump landed"
        );
        assert_eq!(
            std::fs::read_dir(&empty).expect("the destination").count(),
            0,
            "something was restored that should not have been"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}

// ---------------------------------------------------------------------------
// reading a user backup back in
// ---------------------------------------------------------------------------

/// `POST /maintenance/user-restore`.
///
/// Source: `restore_user_backup`. Administrator only: it writes into another
/// account's home, recreates their databases and can overwrite a site that is
/// serving right now.
async fn restore_user_backup(
    State(state): State<AppState>,
    req: axum::extract::Request,
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
    // `UserRestoreBackup.backup_file: str` — required, and a string.
    let backup_file = match payload.get("backup_file") {
        Some(Value::String(text)) => text.clone(),
        None => return crate::errors::missing_field("backup_file", payload.clone()),
        Some(other) => return crate::errors::string_type("backup_file", other),
    };
    if !permissions::is_admin_role(&current.user.role) {
        return crate::errors::not_enough_permissions();
    }

    let result = match run_user_restore(&state, &backup_file).await {
        Ok(result) => result,
        // `except (FileNotFoundError, ValueError, RuntimeError)` — every way
        // this can fail is the caller's to see, because every one of them
        // names something in the archive or on the machine.
        Err(why) => return bad_request(&why),
    };
    let username = result
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or("user")
        .to_string();
    let detail = snpanel_db::AuditRepo::detail_with_request(
        &backup_file,
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
        .log(Some(current.user.id), "restore_user", &username, &detail)
        .await
    {
        tracing::error!("Failed to write audit log: action=restore_user target={username}: {e}");
    }
    axum::Json(result).into_response()
}

/// `^[A-Za-z0-9._-]{3,64}$` — `PANEL_USERNAME_RE`, which is **looser** than
/// the Linux account pattern: a backup may name an account this installation
/// would not create, and the name is still what its files are filed under.
fn backup_username_ok(name: &str) -> bool {
    let count = name.chars().count();
    (3..=64).contains(&count)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

async fn run_user_restore(state: &AppState, backup_file: &str) -> Result<Value, String> {
    let root = &state.settings.backup_root;
    let archive = crate::backups::user_backup_path(root, backup_file).map_err(|e| e.to_string())?;
    let manifest =
        crate::backups::read_backup_manifest(root, backup_file).map_err(|e| e.to_string())?;

    let kind = manifest
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !crate::restore::RESTORABLE_KINDS.contains(&kind) {
        return Err("This is not a snpanel or opanel user backup".to_string());
    }
    let user_info = manifest.get("user").cloned().unwrap_or(Value::Null);
    let username = user_info
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !backup_username_ok(&username) {
        return Err("Invalid user in backup".to_string());
    }

    let (user_id, created_user) = ensure_restored_user(state, &username, &user_info).await?;

    // `site_users.ensure_panel_user(user.username)`.
    let panel_user = snpanel_core::types::PanelUsername::parse(&username.to_lowercase())
        .map_err(|_| format!("Invalid panel Linux user: {username}"))?;
    let dry = state.settings.command_dry_run;
    let home = format!("/home/{}", panel_user.as_str());
    let ensured = shell::privileged(
        dry,
        "panel-user-ensure",
        &[panel_user.as_str()],
        None,
        Some(&["mkdir", "-p", &home]),
    )
    .await;
    if !ensured.ok() {
        return Err(ensured
            .failure_detail("Could not create the system account")
            .trim()
            .to_string());
    }

    // Stage under the panel-owned import area: the helper only copies site
    // files into place from there, because the site directory belongs to its
    // Linux user and not to the panel.
    let stage = crate::da_import::make_import_stage()
        .ok_or_else(|| "Could not make the staging directory".to_string())?;
    let outcome = restore_everything(
        state,
        &archive,
        &manifest,
        &username,
        user_id,
        &panel_user,
        &stage,
    )
    .await;
    // The staging tree is a full copy of a customer's files; it goes whether
    // or not the restore worked.
    let _ = std::fs::remove_dir_all(&stage);
    let (websites, applications) = outcome?;

    Ok(json!({
        "created_user": created_user,
        "username": username,
        "websites": websites,
        "applications": applications,
    }))
}

/// The account the archive belongs to, made if this installation has none.
async fn ensure_restored_user(
    state: &AppState,
    username: &str,
    info: &Value,
) -> Result<(i64, bool), String> {
    if let Ok(Some(existing)) = state.db.users().by_username(username).await {
        return Ok((existing.id, false));
    }
    let mut email = info
        .get("email")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{username}@users.snpanel.invalid"));
    if crate::restore::is_placeholder_email(&email) {
        email = format!("{username}@users.snpanel.invalid");
    }
    let taken = state.db.users().all_emails().await.unwrap_or_default();
    if taken.iter().any(|known| known == &email) {
        email = format!(
            "{username}-{}@users.snpanel.invalid",
            crate::ratelimit::random_hex(4)
        );
    }
    // `normalize_role(...)` with everything else falling back — a backup from
    // a release with a role this one does not have restores as a customer
    // rather than refusing the whole archive.
    let role = info
        .get("role")
        .and_then(Value::as_str)
        .and_then(snpanel_core::permissions::normalize_role)
        .map(|role| role.as_str().to_string())
        .unwrap_or_else(|| "end_user".to_string());
    let hashed = match info
        .get("hashed_password")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        Some(hash) => hash.to_string(),
        // No password in the archive: one nobody knows, so the account has to
        // be given a new one rather than being open.
        None => snpanel_core::crypto::password::hash_password(&crate::mariadb::random_password(24))
            .map_err(|e| format!("hashing failed: {e}"))?,
    };
    let website_limit = info
        .get("website_limit")
        .and_then(Value::as_i64)
        .filter(|value| *value != 0)
        .unwrap_or(5);
    let storage_limit_mb = info
        .get("storage_limit_mb")
        .and_then(Value::as_i64)
        .filter(|value| *value != 0)
        .unwrap_or(1024);

    let id = state
        .db
        .users()
        .create(&snpanel_db::NewUser {
            username,
            email: &email,
            hashed_password: &hashed,
            role: &role,
            package_id: None,
            website_limit,
            storage_limit_mb,
            // `User.terminal_enabled` is not in the manifest — a backup
            // written before the column existed has nothing to say about it,
            // and the model's default is off.
            terminal_enabled: false,
        })
        .await
        .map_err(|e| format!("Could not create the account: {e}"))?;
    Ok((id, true))
}

/// Every site, then every application.
async fn restore_everything(
    state: &AppState,
    archive: &std::path::Path,
    manifest: &Value,
    username: &str,
    user_id: i64,
    panel_user: &snpanel_core::types::PanelUsername,
    stage: &std::path::Path,
) -> Result<(Vec<Value>, Vec<Value>), String> {
    let mut restored = Vec::new();
    let empty: Vec<Value> = Vec::new();
    let sites = manifest
        .get("websites")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .clone();
    for site in &sites {
        restored.push(restore_one_site(state, archive, site, user_id, panel_user, stage).await?);
    }
    let applications =
        restore_applications(state, archive, manifest, username, user_id, stage).await;
    Ok((restored, applications))
}

async fn restore_one_site(
    state: &AppState,
    archive: &std::path::Path,
    site: &Value,
    user_id: i64,
    panel_user: &snpanel_core::types::PanelUsername,
    stage: &std::path::Path,
) -> Result<Value, String> {
    let dry = state.settings.command_dry_run;
    let domain = site
        .get("domain")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    // `site_users.DOMAIN_RE`, which is the **whole** name and not one label:
    // two labels at least, so `localhost` out of a hand-edited archive is
    // refused rather than turned into a site root.
    if snpanel_core::types::Domain::parse(&domain).is_err() {
        return Err(format!("Invalid domain in backup: {domain}"));
    }
    let php_version = site
        .get("php_version")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| state.settings.default_php_version.clone());
    let app_type = crate::restore::app_type_for(site.get("app_type").and_then(Value::as_str));
    let rewrite_mode = crate::restore::rewrite_mode_for(
        site.get("nginx_rewrite_mode").and_then(Value::as_str),
        &app_type,
    );
    let document_root = match site
        .get("document_root")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        Some(text) => snpanel_core::types::DocumentRoot::parse(text)
            .map_err(|_| {
                "document_root must be a safe relative path such as public_html/public".to_string()
            })?
            .as_str()
            .to_string(),
        None => "public_html".to_string(),
    };
    let raw_aliases: Vec<String> = site
        .get("aliases")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(json_text).collect())
        .unwrap_or_default();
    let aliases = crate::restore::alias_domains(&raw_aliases, &domain);

    let root_path = format!("/home/{}/{domain}", panel_user.as_str());
    let runtime_php = matches!(app_type.as_str(), "wordpress" | "php").then(|| php_version.clone());

    // The runtime first: the directory and the PHP pool have to exist before
    // anything is copied into them.
    ensure_site_runtime(state, panel_user, &root_path, runtime_php.as_deref()).await?;
    let site_stage = stage.join("site").join(&domain);
    crate::restore::extract_prefix(archive, &format!("sites/{domain}/site"), &site_stage)?;
    let populate = shell::privileged(
        dry,
        "site-populate",
        &[
            panel_user.as_str(),
            &root_path,
            &site_stage.to_string_lossy(),
        ],
        None,
        Some(&["true"]),
    )
    .await;
    if !populate.ok() {
        return Err(populate
            .failure_detail("Could not copy the site files into place")
            .trim()
            .to_string());
    }
    // Backups from older releases may contain `public/`. Normalise the
    // document root after extraction, before the vhost is rewritten.
    ensure_site_runtime(state, panel_user, &root_path, runtime_php.as_deref()).await?;
    let document = shell::privileged(
        dry,
        "site-document-root-ensure",
        &[panel_user.as_str(), &root_path, &document_root],
        None,
        Some(&["true"]),
    )
    .await;
    if !document.ok() {
        return Err(document
            .failure_detail("Could not create the document root")
            .trim()
            .to_string());
    }

    let waf_enabled = site
        .get("waf_enabled")
        .map(crate::compose::json_truthy)
        .unwrap_or(true);
    let http_flood_enabled = site
        .get("http_flood_enabled")
        .map(crate::compose::json_truthy)
        .unwrap_or(false);
    let row = snpanel_db::RestoredWebsite {
        domain: &domain,
        owner_id: user_id,
        root_path: &root_path,
        document_root: &document_root,
        linux_user: panel_user.as_str(),
        php_version: &php_version,
        app_type: &app_type,
        status: &text_or(site.get("status"), "active"),
        nginx_custom: &text_or(site.get("nginx_custom"), ""),
        nginx_rewrite_mode: &rewrite_mode,
        waf_enabled,
        waf_default_rules: &text_or(site.get("waf_default_rules"), ""),
        waf_custom_rules: &text_or(site.get("waf_custom_rules"), ""),
        http_flood_enabled,
        http_flood_config: &text_or(site.get("http_flood_config"), ""),
        created_at: &snpanel_db::sqlalchemy_now(),
    };
    let (website_id, created) = state
        .db
        .websites()
        .restore_write(&row)
        .await
        .map_err(|e| format!("Could not write the row for {domain}: {e}"))?;

    restore_aliases(state, website_id, &aliases).await?;

    if let Some(info) = site.get("database").filter(|value| !value.is_null()) {
        restore_database(state, archive, stage, &domain, website_id, user_id, info).await?;
    }

    let website = state
        .db
        .websites()
        .by_id(website_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| format!("The row for {domain} vanished mid-restore"))?;
    let waf = crate::waf::sync_website_rules(dry, &website, &super::waf::server_crs_mode())
        .await
        .map_err(|e| e.to_string())?;
    if !waf.ok() {
        return Err(waf
            .failure_detail("Could not write WAF rules")
            .trim()
            .to_string());
    }
    // The zones are synced before the vhost when the site wants them and
    // after when it does not, which is the Python's order and not an
    // accident: a vhost naming a zone that has not been written yet fails
    // `nginx -t`, and one that has stopped using a zone has to be rewritten
    // before the zone goes.
    if http_flood_enabled {
        sync_flood_zones(state).await?;
    }
    write_import_vhost(
        state,
        &domain,
        &root_path,
        panel_user,
        &app_type,
        runtime_php.as_deref(),
        waf_enabled,
        &aliases,
        &[],
    )
    .await?;
    if !http_flood_enabled {
        sync_flood_zones(state).await?;
    }
    // `wordpress.fix_permissions` — two arguments, so the helper files the
    // tree under the site's own account.
    let owner = format!("{0}:{0}", panel_user.as_str());
    let _ = shell::privileged(
        dry,
        "fix-permissions",
        &[&root_path, panel_user.as_str()],
        None,
        Some(&["chown", "-R", &owner, &root_path]),
    )
    .await;

    Ok(json!({ "domain": domain, "created": created }))
}

/// `str(value)` for a name read out of a manifest. A list of aliases is
/// written by the panel and holds strings, but a hand-edited archive can
/// hold anything, and the Python stringifies before it looks.
fn json_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        other => other.to_string(),
    }
}

/// `text[-n:]` — **characters**, not bytes.
fn last_chars(text: &str, n: usize) -> String {
    let count = text.chars().count();
    text.chars().skip(count.saturating_sub(n)).collect()
}

fn text_or(value: Option<&Value>, fallback: &str) -> String {
    match value.and_then(Value::as_str) {
        Some(text) if !text.is_empty() => text.to_string(),
        _ => fallback.to_string(),
    }
}

async fn ensure_site_runtime(
    state: &AppState,
    panel_user: &snpanel_core::types::PanelUsername,
    root_path: &str,
    runtime_php: Option<&str>,
) -> Result<(), String> {
    let php = runtime_php.unwrap_or("");
    let result = shell::privileged(
        state.settings.command_dry_run,
        "site-runtime-ensure",
        &[panel_user.as_str(), root_path, php],
        None,
        Some(&["mkdir", "-p", root_path]),
    )
    .await;
    if result.ok() {
        return Ok(());
    }
    Err(result
        .failure_detail("Could not prepare the site directory")
        .trim()
        .to_string())
}

/// Source: `nginx.sync_http_flood_zones(db.query(Website).all())`.
///
/// The same zones the websites router writes, under the same helper verb.
/// The message differs because the Python's does: this call site names
/// writing them and the other names saving them, and an operator reading a
/// failed restore should find the sentence the restore printed.
async fn sync_flood_zones(state: &AppState) -> Result<(), String> {
    let websites = state
        .db
        .websites()
        .list(None, "")
        .await
        .map_err(|e| format!("Could not read the websites: {e}"))?;
    let configs: Vec<(String, bool, snpanel_nginx::HttpFloodConfig)> = websites
        .iter()
        .map(|site| {
            (
                site.domain.clone(),
                site.http_flood_enabled,
                crate::waf::http_flood_config(site),
            )
        })
        .collect();
    let sites: Vec<snpanel_nginx::FloodSite<'_>> = configs
        .iter()
        .map(|(domain, enabled, config)| snpanel_nginx::FloodSite {
            domain,
            enabled: *enabled,
            config: *config,
        })
        .collect();
    let content = snpanel_nginx::render_http_flood_zones(&sites).map_err(|e| e.to_string())?;
    let result = shell::privileged(
        state.settings.command_dry_run,
        "http-flood-zones-save",
        &[],
        Some(&content),
        Some(&[
            "bash",
            "-lc",
            "cat >/tmp/snpanel-http-flood-zones.conf && echo HTTP flood zones saved",
        ]),
    )
    .await;
    if result.ok() {
        return Ok(());
    }
    Err(result
        .failure_detail("Could not write HTTP flood zones")
        .trim()
        .to_string())
}

/// The aliases the archive names, and only those.
///
/// Source: the two loops — an alias in the backup that is not in the table is
/// added, and one in the table that is not in the backup is removed.
async fn restore_aliases(
    state: &AppState,
    website_id: i64,
    wanted: &[String],
) -> Result<(), String> {
    let websites = state.db.websites().all_domains().await.unwrap_or_default();
    let all_aliases = state.db.websites().all_aliases().await.unwrap_or_default();
    let existing = state
        .db
        .websites()
        .aliases(website_id)
        .await
        .unwrap_or_default();

    for alias in wanted {
        if crate::restore::hostname_conflicts(alias, &websites, &all_aliases, Some(website_id)) {
            return Err(format!(
                "Alias domain already belongs to another website: {alias}"
            ));
        }
        if !existing.iter().any(|known| &known.domain == alias) {
            state
                .db
                .websites()
                .alias_create(website_id, alias, "alias")
                .await
                .map_err(|e| format!("Could not add the alias {alias}: {e}"))?;
        }
    }
    for alias in &existing {
        if !wanted.contains(&alias.domain) {
            let _ = state.db.websites().alias_delete(website_id, alias.id).await;
        }
    }
    Ok(())
}

/// Recreate the account this archive already owned, and load its dump.
async fn restore_database(
    state: &AppState,
    archive: &std::path::Path,
    stage: &std::path::Path,
    domain: &str,
    website_id: i64,
    owner_id: i64,
    info: &Value,
) -> Result<(), String> {
    let db_name = text_or(info.get("db_name"), "");
    let db_user = text_or(info.get("db_user"), "");
    let db_password = match info
        .get("db_password")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        Some(text) => text.to_string(),
        None => crate::mariadb::random_password(16),
    };
    if let Ok(Some(conflict)) = state.db.databases().by_name(&db_name).await {
        if conflict.website_id != Some(website_id) {
            return Err(format!(
                "Database name already belongs to another website: {db_name}"
            ));
        }
    }
    let dry = state.settings.command_dry_run;
    // `allow_existing_user=True`: a restore recreates the account this
    // archive already owned, and the MariaDB user may still be there from
    // before the row was deleted.
    let _ = dry;
    crate::mariadb::create_database_credentials(&db_name, &db_user, &db_password, None, true)
        .await
        .map_err(|e| e.to_string())?;

    let member = match info
        .get("sql_member")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        Some(text) => text.to_string(),
        None => format!("databases/{domain}.sql"),
    };
    if let Some(dump) = crate::restore::extract_member_to_file(archive, &member, stage)? {
        crate::mariadb::import_database(dry, &db_name, &dump.to_string_lossy())
            .await
            .map_err(|e| e.to_string())?;
    }

    let encrypted = snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, &db_password);
    // `.first()` — the Python takes the first row for this site and leaves
    // any others alone, which is what a site with two database accounts on
    // it already means.
    let existing = state
        .db
        .databases()
        .for_website(website_id)
        .await
        .unwrap_or_default();
    match existing.first() {
        Some(row) => state
            .db
            .databases()
            .restore_write(row.id, owner_id, &db_name, &db_user, &encrypted)
            .await
            .map_err(|e| format!("Could not update the database row: {e}"))?,
        None => {
            state
                .db
                .databases()
                .create(owner_id, Some(website_id), &db_name, &db_user, &encrypted)
                .await
                .map(|_| ())
                .map_err(|e| format!("Could not write the database row: {e}"))?;
        }
    }
    Ok(())
}

/// Bring back a user's applications, **stopped**.
///
/// Deliberately not started: the images may not be pulled yet, and a customer
/// should look at what came back before it starts answering on their domain.
/// The panel's Deploy button does the rest.
async fn restore_applications(
    state: &AppState,
    archive: &std::path::Path,
    manifest: &Value,
    username: &str,
    user_id: i64,
    stage: &std::path::Path,
) -> Vec<Value> {
    let empty: Vec<Value> = Vec::new();
    let entries = manifest
        .get("applications")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    if entries.is_empty() {
        return Vec::new();
    }
    if !super::addons::application_installed() {
        // Recorded rather than dropped, so the operator knows what this
        // backup holds and can install the addon and restore again.
        return entries
            .iter()
            .map(|entry| {
                json!({
                    "name": entry.get("name").cloned().unwrap_or(Value::Null),
                    "skipped": "Addon Application chưa được cài",
                })
            })
            .collect();
    }

    let dry = state.settings.command_dry_run;
    let mut results = Vec::new();
    for entry in entries {
        let raw_name = text_or(entry.get("name"), "");
        let name = match crate::site_apps::validate_name(&raw_name) {
            Ok(name) => name,
            Err(why) => {
                results.push(json!({ "name": raw_name, "error": why }));
                continue;
            }
        };
        let kind = match entry.get("kind").and_then(Value::as_str) {
            Some(kind) if crate::site_apps::APP_KINDS.contains(&kind) => kind.to_string(),
            _ => "node".to_string(),
        };
        let mut record = json!({ "name": name, "created": false, "data_restored": false });
        match write_restored_app(state, user_id, &name, &kind, entry).await {
            Ok((app_id, created)) => {
                record["created"] = json!(created);
                if let Some(member) = entry
                    .get("payload_member")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                {
                    match restore_app_payload(state, archive, stage, username, app_id, member).await
                    {
                        Ok(true) => record["data_restored"] = json!(true),
                        Ok(false) => {}
                        Err(why) => {
                            tracing::warn!("Could not restore application {name}: {why}");
                            record["error"] = json!(last_chars(&why, 500));
                        }
                    }
                } else if let Some(problem) = entry
                    .get("payload_error")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                {
                    record["error"] = json!(format!("Backup này không có dữ liệu: {problem}"));
                }
            }
            Err(why) => {
                record["error"] = json!(last_chars(&why, 500));
            }
        }
        let _ = dry;
        results.push(record);
    }
    results
}

async fn write_restored_app(
    state: &AppState,
    user_id: i64,
    name: &str,
    kind: &str,
    entry: &Value,
) -> Result<(i64, bool), String> {
    let dry = state.settings.command_dry_run;
    let existing = state
        .db
        .site_apps()
        .full_list(Some(user_id))
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|app| app.name == name);

    let container_port = entry
        .get("container_port")
        .and_then(Value::as_i64)
        .filter(|value| *value != 0)
        .unwrap_or(3000);
    let memory_limit_mb = entry
        .get("memory_limit_mb")
        .and_then(Value::as_i64)
        .filter(|value| *value != 0)
        .unwrap_or(512);
    let autostart = entry
        .get("autostart")
        .map(crate::compose::json_truthy)
        .unwrap_or(true);

    let created = existing.is_none();
    let mut app = match existing {
        Some(app) => app,
        None => {
            // The port it had, or any free one: a backup restored onto a
            // machine that already uses that port still has to come back.
            let asked = crate::site_apps::PortInput::from_json(entry.get("port"));
            let port = match crate::site_apps::allocate_port(dry, &state.db, &asked, None).await {
                Ok(port) => port,
                Err(_) => {
                    crate::site_apps::allocate_port(
                        dry,
                        &state.db,
                        &crate::site_apps::PortInput::Missing,
                        None,
                    )
                    .await?
                }
            };
            let row = snpanel_db::NewSiteApp {
                owner_id: user_id,
                name: name.to_string(),
                kind: kind.to_string(),
                container_port: 3000,
                cpu_limit: "1".to_string(),
                port,
                memory_limit_mb: 512,
                autostart: true,
                created_at: snpanel_db::sqlalchemy_now(),
                ..snpanel_db::NewSiteApp::default()
            };
            let id = match state.db.site_apps().create(&row).await {
                Ok(Ok(id)) => id,
                Ok(Err(snpanel_db::Duplicate)) => {
                    return Err(format!("An application named {name} already exists"))
                }
                Err(e) => return Err(format!("Could not write the application row: {e}")),
            };
            let mut made = state
                .db
                .site_apps()
                .full_by_id(id)
                .await
                .ok()
                .flatten()
                .ok_or_else(|| "The application row vanished mid-restore".to_string())?;
            made.status = "stopped".to_string();
            made
        }
    };
    app.kind = kind.to_string();
    app.start_kind = entry
        .get("start_kind")
        .and_then(Value::as_str)
        .map(str::to_string);
    app.start_arg = entry
        .get("start_arg")
        .and_then(Value::as_str)
        .map(str::to_string);
    app.node_major = entry
        .get("node_major")
        .and_then(Value::as_str)
        .map(str::to_string);
    app.image = entry
        .get("image")
        .and_then(Value::as_str)
        .map(str::to_string);
    app.container_port = container_port;
    app.cpu_limit = text_or(entry.get("cpu_limit"), "1");
    app.env = text_or(entry.get("env"), "");
    app.compose_source = text_or(entry.get("compose_source"), "");
    app.web_service = entry
        .get("web_service")
        .and_then(Value::as_str)
        .map(str::to_string);
    app.memory_limit_mb = memory_limit_mb;
    app.autostart = autostart;
    app.status = "stopped".to_string();
    state
        .db
        .site_apps()
        .save(&app)
        .await
        .map_err(|e| format!("Could not write the application row: {e}"))?
        .map_err(|_| format!("An application named {name} already exists"))?;
    Ok((app.id, created))
}

/// Put a backed-up application's directory and volumes back.
async fn restore_app_payload(
    state: &AppState,
    archive: &std::path::Path,
    stage: &std::path::Path,
    username: &str,
    app_id: i64,
    member: &str,
) -> Result<bool, String> {
    let Some(payload) = crate::restore::extract_member_to_file(archive, member, stage)? else {
        return Ok(false);
    };
    let app = state
        .db
        .site_apps()
        .full_by_id(app_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| "The application row vanished mid-restore".to_string())?;
    // The helper only reads from the backup tree, so the extracted payload
    // has to live there rather than in /tmp — and inside the user's own
    // directory, the one level of it the panel may write.
    let staging = crate::backups::user_backup_dir(&state.settings.backup_root, username)
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    let staged = staging.join(format!(".restore-{}.tar", app.name));
    let outcome = async {
        std::fs::copy(&payload, &staged).map_err(|e| e.to_string())?;
        let result = shell::privileged(
            state.settings.command_dry_run,
            "site-app-import",
            &[
                &crate::site_apps::owner_linux_user(&app)?,
                &crate::site_apps::validate_name(&app.name)?,
                &staged.to_string_lossy(),
            ],
            None,
            Some(&["bash", "-lc", "echo dry-run-app-import"]),
        )
        .await;
        if !result.ok() {
            return Err(result
                .failure_detail("Could not restore the application")
                .trim()
                .to_string());
        }
        Ok(true)
    }
    .await;
    let _ = std::fs::remove_file(&staged);
    outcome
}

// ---------------------------------------------------------------------------
// the backup family
// ---------------------------------------------------------------------------
//
// All five move together because the registry behind them is an in-process
// dict: a job queued on one side of the proxy would be invisible to the
// other, and a customer would press Backup, get a job id, and watch a list
// that never mentions it.

/// `POST /maintenance/backup`.
///
/// Source: `create_backup` — queue it and answer immediately. The work
/// itself can take minutes on a large site, and a request that waited for it
/// would be a request that times out in front of the customer.
async fn queue_site_backup(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website_id = match crate::errors::read_int("website_id", payload.get("website_id")) {
        Ok(Some(id)) => id,
        Ok(None) => return crate::errors::missing_field("website_id", payload.clone()),
        Err(response) => return response,
    };
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let mut job =
        crate::backup_jobs::new_job(current.user.id, "site_backup", "Website backup queued");
    job.website_id = Some(website.id);
    let job_id = job.job_id.clone();
    let public = crate::backup_jobs::remember(job);

    let worker_state = state.clone();
    let user_id = current.user.id;
    tokio::spawn(async move {
        let _permit = crate::backup_jobs::worker_permit().await;
        run_site_backup(worker_state, job_id, user_id, website_id).await;
    });
    axum::Json(public).into_response()
}

/// Source: `_run_site_backup_job`.
///
/// The ownership check runs **again** here rather than trusting what the
/// request thread resolved: the job only carries an id, and between queueing
/// and running the site could have moved or the account could have been
/// suspended.
async fn run_site_backup(state: AppState, job_id: String, user_id: i64, website_id: i64) {
    crate::backup_jobs::start(&job_id, "Creating website backup");
    let outcome = site_backup_work(&state, user_id, website_id).await;
    if let Ok(done) = &outcome {
        audit_detail(&state, user_id, "backup", &done.target, &done.backup_file).await;
    }
    let outcome = outcome.map(|done| crate::backup_jobs::Finished {
        backup_file: done.backup_file,
        message: "Website backup completed".to_string(),
        ..crate::backup_jobs::Finished::default()
    });
    crate::backup_jobs::finish(&job_id, outcome, "Website backup failed");
}

struct SiteArchive {
    backup_file: String,
    /// The domain, which is what the audit log names.
    target: String,
}

async fn site_backup_work(
    state: &AppState,
    user_id: i64,
    website_id: i64,
) -> Result<SiteArchive, String> {
    let user = active_user(state, user_id).await?;
    let website = owned_for_worker(state, &user, website_id).await?;
    let db_name = state
        .db
        .databases()
        .for_website(website.id)
        .await
        .unwrap_or_default()
        .first()
        .map(|row| row.db_name.clone());
    let archive = crate::backups::create_backup(&crate::backups::SiteBackup {
        backup_root: &state.settings.backup_root,
        domain: &website.domain,
        root_path: &website.root_path,
        db_name: db_name.as_deref(),
        dry_run: state.settings.command_dry_run,
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(SiteArchive {
        backup_file: archive,
        target: website.domain,
    })
}

/// `db.query(User).filter(User.id == request_user_id).first()` and the
/// `is_active` check beside it.
async fn active_user(state: &AppState, user_id: i64) -> Result<snpanel_db::User, String> {
    match state.db.users().by_id(user_id).await {
        Ok(Some(user)) if user.is_active => Ok(user),
        Ok(_) => Err("User not found".to_string()),
        Err(e) => Err(format!("Could not read the account: {e}")),
    }
}

/// `get_owned_website` inside a worker, where there is no request to answer.
async fn owned_for_worker(
    state: &AppState,
    user: &snpanel_db::User,
    website_id: i64,
) -> Result<snpanel_db::Website, String> {
    let website = state
        .db
        .websites()
        .by_id(website_id)
        .await
        .map_err(|e| format!("Could not read the website: {e}"))?
        .ok_or_else(|| "Website not found".to_string())?;
    if website.owner_id != user.id && !permissions::has_role(&user.role, permissions::Role::Admin) {
        return Err("Not enough permissions".to_string());
    }
    Ok(website)
}

/// `GET /maintenance/backup-jobs`.
async fn list_backup_jobs(State(state): State<AppState>, current: CurrentUser) -> Response {
    let _ = &state;
    let is_admin = permissions::is_admin_role(&current.user.role);
    axum::Json(json!({
        "jobs": crate::backup_jobs::list(current.user.id, is_admin),
    }))
    .into_response()
}

/// `GET /maintenance/backup-jobs/{job_id}`.
async fn get_backup_job(
    State(state): State<AppState>,
    AxumPath(job_id): AxumPath<String>,
    current: CurrentUser,
) -> Response {
    let _ = &state;
    let Some(job) = crate::backup_jobs::get(&job_id) else {
        return not_found("Backup job not found");
    };
    // A 403, not a 404: the Python distinguishes them, and so does anyone
    // reading the log.
    if job.request_user_id != current.user.id && !permissions::is_admin_role(&current.user.role) {
        return crate::errors::error(axum::http::StatusCode::FORBIDDEN, "Access denied");
    }
    axum::Json(job.public()).into_response()
}

/// `POST /maintenance/user-backup`.
async fn queue_user_backup(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let user_id = match crate::errors::read_int("user_id", payload.get("user_id")) {
        Ok(Some(id)) => id,
        Ok(None) => return crate::errors::missing_field("user_id", payload.clone()),
        Err(response) => return response,
    };
    let target_id = match crate::errors::read_int("target_id", payload.get("target_id")) {
        Ok(value) => value.filter(|id| *id != 0),
        Err(response) => return response,
    };

    // `get_backup_user`: your own account, or anyone's if you are an admin.
    let target_user = match state.db.users().by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return not_found("User not found"),
        Err(e) => {
            tracing::error!("reading user {user_id} failed: {e}");
            return internal_error();
        }
    };
    if target_user.id != current.user.id && !permissions::is_admin_role(&current.user.role) {
        return crate::errors::not_enough_permissions();
    }
    if let Some(target_id) = target_id {
        if !permissions::is_admin_role(&current.user.role) {
            return crate::errors::not_enough_permissions();
        }
        match state.db.sftp_targets().active_exists(target_id).await {
            Ok(true) => {}
            Ok(false) => return not_found("SFTP target not found"),
            Err(e) => {
                tracing::error!("reading SFTP target {target_id} failed: {e}");
                return internal_error();
            }
        }
    }
    audit_request(
        &state,
        &parts,
        current.user.id,
        "queue_backup_user",
        &target_user.username,
        "",
    )
    .await;

    let mut job =
        crate::backup_jobs::new_job(current.user.id, "user_backup", "Full user backup queued");
    job.target_user_id = Some(target_user.id);
    job.target_id = target_id;
    let job_id = job.job_id.clone();
    let public = crate::backup_jobs::remember(job);

    let worker_state = state.clone();
    let requester = current.user.id;
    let is_admin = permissions::is_admin_role(&current.user.role);
    tokio::spawn(async move {
        let _permit = crate::backup_jobs::worker_permit().await;
        run_user_backup(
            worker_state,
            job_id,
            requester,
            is_admin,
            target_user.id,
            target_id,
        )
        .await;
    });
    axum::Json(public).into_response()
}

async fn run_user_backup(
    state: AppState,
    job_id: String,
    requester_id: i64,
    is_admin: bool,
    target_user_id: i64,
    target_id: Option<i64>,
) {
    crate::backup_jobs::start(&job_id, "Creating full user backup");
    let outcome = user_backup_work(&state, requester_id, is_admin, target_user_id, target_id).await;
    if let Ok(done) = &outcome {
        let detail = if done.remote_file.is_empty() {
            done.backup_file.clone()
        } else {
            format!(
                "{} -> {}:{}",
                done.backup_file, done.target, done.remote_file
            )
        };
        audit_detail(&state, requester_id, "backup_user", &done.username, &detail).await;
    }
    let outcome = outcome.map(|done| crate::backup_jobs::Finished {
        backup_file: done.backup_file,
        remote_file: done.remote_file,
        target: done.target,
        message: "Full user backup completed".to_string(),
    });
    crate::backup_jobs::finish(&job_id, outcome, "Full user backup failed");
}

struct UserArchive {
    backup_file: String,
    remote_file: String,
    target: String,
    username: String,
}

async fn user_backup_work(
    state: &AppState,
    requester_id: i64,
    is_admin: bool,
    target_user_id: i64,
    target_id: Option<i64>,
) -> Result<UserArchive, String> {
    let requester = active_user(state, requester_id).await?;
    let _ = &requester;
    let user = match state.db.users().by_id(target_user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err("User not found".to_string()),
        Err(e) => return Err(format!("Could not read the account: {e}")),
    };
    let archive = build_user_backup(state, &user).await?;
    let mut remote_file = String::new();
    let mut target_name = String::new();
    if let Some(target_id) = target_id {
        if !is_admin {
            return Err("Not enough permissions".to_string());
        }
        let uploaded = upload_archive_to_target(state, target_id, &archive).await?;
        target_name = uploaded.0;
        remote_file = uploaded.1;
    }
    Ok(UserArchive {
        backup_file: archive,
        remote_file,
        target: target_name,
        username: user.username,
    })
}

/// `POST /maintenance/backup-sftp`.
async fn queue_sftp_backup(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website_id = match crate::errors::read_int("website_id", payload.get("website_id")) {
        Ok(Some(id)) => id,
        Ok(None) => return crate::errors::missing_field("website_id", payload.clone()),
        Err(response) => return response,
    };
    let target_id = match crate::errors::read_int("target_id", payload.get("target_id")) {
        Ok(Some(id)) => id,
        Ok(None) => return crate::errors::missing_field("target_id", payload.clone()),
        Err(response) => return response,
    };
    if !permissions::is_admin_role(&current.user.role) {
        return crate::errors::not_enough_permissions();
    }
    let website = match owned(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let target = match state.db.sftp_targets().by_id(target_id).await {
        Ok(Some(target)) if target.is_active => target,
        Ok(_) => return not_found("SFTP target not found"),
        Err(e) => {
            tracing::error!("reading SFTP target {target_id} failed: {e}");
            return internal_error();
        }
    };
    audit_request(
        &state,
        &parts,
        current.user.id,
        "queue_backup_sftp",
        &website.domain,
        &target.name,
    )
    .await;

    let mut job = crate::backup_jobs::new_job(current.user.id, "sftp_backup", "SFTP backup queued");
    job.website_id = Some(website.id);
    job.target_id = Some(target.id);
    let job_id = job.job_id.clone();
    let public = crate::backup_jobs::remember(job);

    let worker_state = state.clone();
    let requester = current.user.id;
    tokio::spawn(async move {
        let _permit = crate::backup_jobs::worker_permit().await;
        run_sftp_backup(worker_state, job_id, requester, website_id, target_id).await;
    });
    axum::Json(public).into_response()
}

async fn run_sftp_backup(
    state: AppState,
    job_id: String,
    requester_id: i64,
    website_id: i64,
    target_id: i64,
) {
    crate::backup_jobs::start(&job_id, "Creating and uploading SFTP backup");
    let outcome = sftp_backup_work(&state, requester_id, website_id, target_id).await;
    if let Ok(done) = &outcome {
        audit_detail(
            &state,
            requester_id,
            "backup_sftp",
            &done.username,
            &format!("{}:{}", done.target, done.remote_file),
        )
        .await;
    }
    let outcome = outcome.map(|done| crate::backup_jobs::Finished {
        backup_file: done.backup_file,
        remote_file: done.remote_file,
        target: done.target,
        message: "SFTP backup completed".to_string(),
    });
    crate::backup_jobs::finish(&job_id, outcome, "SFTP backup failed");
}

async fn sftp_backup_work(
    state: &AppState,
    requester_id: i64,
    website_id: i64,
    target_id: i64,
) -> Result<UserArchive, String> {
    let user = active_user(state, requester_id).await?;
    if !permissions::is_admin_role(&user.role) {
        return Err("Not enough permissions".to_string());
    }
    let website = owned_for_worker(state, &user, website_id).await?;
    let archive = site_backup_work(state, requester_id, website_id).await?;
    let (target_name, remote_file) =
        upload_archive_to_target(state, target_id, &archive.backup_file).await?;
    Ok(UserArchive {
        backup_file: archive.backup_file,
        remote_file,
        target: target_name,
        // The audit log names the **domain** on this path, not an account.
        username: website.domain,
    })
}

/// Source: `upload_archive_to_target`.
///
/// Returns the target's name and where the file landed. A host key that was
/// not pinned yet is pinned here, which is the bootstrap half of the TOFU
/// model: everything after this upload is checked against it.
async fn upload_archive_to_target(
    state: &AppState,
    target_id: i64,
    archive: &str,
) -> Result<(String, String), String> {
    let target = match state.db.sftp_targets().by_id(target_id).await {
        Ok(Some(target)) if target.is_active => target,
        Ok(_) => return Err("SFTP target not found".to_string()),
        Err(e) => return Err(format!("Could not read the SFTP target: {e}")),
    };
    let secrets = state
        .db
        .sftp_targets()
        .secrets(target_id)
        .await
        .map_err(|e| format!("Could not read the SFTP target: {e}"))?
        .ok_or_else(|| "SFTP target not found".to_string())?;
    let decrypt = |value: Option<String>| -> Option<String> {
        value.filter(|text| !text.is_empty()).and_then(|text| {
            snpanel_core::crypto::fernet::decrypt(
                &state.settings.secret_key,
                Some(&text),
                state.settings.strict_decrypt,
            )
            .ok()
        })
    };
    let password = decrypt(secrets.password);
    let private_key = decrypt(secrets.private_key);

    let uploaded = crate::sftp::upload(
        archive,
        &crate::sftp::Target {
            host: &target.host,
            port: u16::try_from(target.port).unwrap_or(22),
            username: &target.username,
            remote_path: &target.remote_path,
            password: password.as_deref(),
            private_key: private_key.as_deref(),
            expected_host_key_type: target.host_key_type.as_deref(),
            expected_host_key_fingerprint: target.host_key_fingerprint.as_deref(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    // `if not target.host_key_fingerprint and result[...]` — written once,
    // when there was nothing to compare against.
    let unpinned = target
        .host_key_fingerprint
        .as_deref()
        .is_none_or(str::is_empty);
    if unpinned && !uploaded.host_key_fingerprint.is_empty() {
        if let Err(e) = state
            .db
            .sftp_targets()
            .pin_host_key(
                target_id,
                &uploaded.host_key_type,
                &uploaded.host_key_fingerprint,
            )
            .await
        {
            tracing::error!("could not pin the host key for target {target_id}: {e}");
        }
    }
    Ok((target.name, uploaded.remote_file))
}

/// `log_action(..., request=request)` — the shape with `ip=` and `ua=` on it.
async fn audit_request(
    state: &AppState,
    parts: &axum::http::request::Parts,
    user_id: i64,
    action: &str,
    target: &str,
    detail: &str,
) {
    let detail = snpanel_db::AuditRepo::detail_with_request(
        detail,
        &crate::client::audit_ip(parts),
        parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );
    if let Err(e) = state
        .db
        .audits()
        .log(Some(user_id), action, target, &detail)
        .await
    {
        tracing::error!("Failed to write audit log: action={action} target={target}: {e}");
    }
}

/// Source: `create_user_backup`, the collecting half.
///
/// Everything a customer owns, in one archive: the account row, each site's
/// files and database dump, and each application's directory and volumes.
/// The applications are the part that is easy to leave out — their data is
/// not under any website root — and leaving them out is how a restore brings
/// back the sites and quietly drops every container's workflows.
pub(crate) async fn build_user_backup(
    state: &AppState,
    user: &snpanel_db::User,
) -> Result<String, String> {
    let backup_dir = crate::backups::user_backup_dir(&state.settings.backup_root, &user.username)
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| format!("Cannot make the backup directory: {e}"))?;
    // The staging directory sits **inside** the backup directory, as the
    // Python's `TemporaryDirectory(dir=backup_dir)` does: the dumps can be
    // the size of the databases and /tmp is often a small filesystem.
    let staging = backup_dir.join(format!(
        ".snpanel-user-backup-{}-{}",
        std::process::id(),
        crate::file_jobs::new_job_id()
    ));
    std::fs::create_dir_all(&staging)
        .map_err(|e| format!("Cannot make the staging directory: {e}"))?;

    let outcome = collect_user_backup(state, user, &staging).await;
    // A full copy of a customer's databases; it goes either way.
    let _ = std::fs::remove_dir_all(&staging);
    outcome
}

async fn collect_user_backup(
    state: &AppState,
    user: &snpanel_db::User,
    staging: &std::path::Path,
) -> Result<String, String> {
    let websites = state
        .db
        .websites()
        .list(Some(user.id), "")
        .await
        .map_err(|e| format!("Could not read the websites: {e}"))?;

    let mut apps = Vec::new();
    let mut app_entries = Vec::new();
    for (entry, payload, name) in collect_applications(state, user, staging).await {
        app_entries.push(entry);
        apps.push(crate::backups::ManifestApp { name, payload });
    }

    let mut sites = Vec::new();
    let mut site_entries = Vec::new();
    for website in &websites {
        let aliases = state
            .db
            .websites()
            .aliases(website.id)
            .await
            .unwrap_or_default();
        let alias_domains: Vec<String> = aliases
            .iter()
            .filter(|alias| alias.mode == "alias")
            .map(|alias| alias.domain.clone())
            .collect();
        let mut entry = json!({
            "domain": website.domain,
            "php_version": website.php_version,
            "app_type": if website.app_type.is_empty() { "wordpress" } else { &website.app_type },
            "status": if website.status.is_empty() { "active" } else { &website.status },
            "document_root": if website.document_root.is_empty() { "public_html" } else { &website.document_root },
            "nginx_custom": website.nginx_custom,
            "nginx_config_mode": "managed",
            "nginx_rewrite_mode": if website.nginx_rewrite_mode.is_empty() { "none" } else { &website.nginx_rewrite_mode },
            "waf_enabled": website.waf_enabled,
            "waf_default_rules": website.waf_default_rules,
            "waf_custom_rules": website.waf_custom_rules,
            "http_flood_enabled": website.http_flood_enabled,
            "http_flood_config": website.http_flood_config,
            "aliases": alias_domains,
            "database": Value::Null,
        });

        let mut sql_file = None;
        let accounts = state
            .db
            .databases()
            .for_website(website.id)
            .await
            .unwrap_or_default();
        if let Some(account) = accounts.first() {
            let name = format!("{}.sql", website.domain);
            let path = staging.join(&name);
            crate::mariadb::export_database(&account.db_name, &path.to_string_lossy())
                .await
                .map_err(|e| e.to_string())?;
            if state.settings.command_dry_run && !path.exists() {
                let _ = std::fs::write(
                    &path,
                    format!("-- DRY RUN database dump for {}\n", account.db_name),
                );
            }
            // `except RuntimeError: db_password = ""` — a password the panel
            // can no longer decrypt is recorded as empty, and the restore
            // makes a new one. Losing the old password beats losing the site.
            let db_password = snpanel_core::crypto::fernet::decrypt(
                &state.settings.secret_key,
                Some(&account.db_password),
                state.settings.strict_decrypt,
            )
            .unwrap_or_default();
            entry["database"] = json!({
                "db_name": account.db_name,
                "db_user": account.db_user,
                "db_password": db_password,
                "sql_member": format!("databases/{name}"),
            });
            sql_file = Some(path);
        }

        site_entries.push(entry);
        sites.push(crate::backups::ManifestSite {
            domain: website.domain.clone(),
            root_path: website.root_path.clone(),
            sql_file,
        });
    }

    let manifest = json!({
        "kind": "snpanel_user",
        "version": 1,
        "generated_at": format!("{}Z", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6f")),
        "user": {
            "username": user.username,
            "email": user.email,
            "hashed_password": user.hashed_password,
            "role": user.role,
            "is_active": user.is_active,
            "website_limit": user.website_limit,
            "storage_limit_mb": user.storage_limit_mb,
        },
        "websites": site_entries,
        "applications": app_entries,
    });

    crate::backups::write_user_backup(
        &state.settings.backup_root,
        &user.username,
        &manifest,
        &sites,
        &apps,
        staging,
    )
    .map_err(|e| e.to_string())
}

/// Source: `_collect_applications`.
///
/// An application whose data cannot be read is still recorded — coming back
/// with the settings and an empty directory beats not coming back at all —
/// and the manifest says so, so a restore can tell the customer which ones
/// need their data putting back by hand.
async fn collect_applications(
    state: &AppState,
    user: &snpanel_db::User,
    staging: &std::path::Path,
) -> Vec<(Value, Option<std::path::PathBuf>, String)> {
    if !super::addons::application_installed() {
        return Vec::new();
    }
    let apps = state
        .db
        .site_apps()
        .full_list(Some(user.id))
        .await
        .unwrap_or_default();
    let mut collected = Vec::new();
    for app in apps {
        let mut entry = json!({
            "name": app.name,
            "kind": app.kind,
            "port": app.port,
            "memory_limit_mb": app.memory_limit_mb,
            "cpu_limit": if app.cpu_limit.is_empty() { "1" } else { &app.cpu_limit },
            "autostart": app.autostart,
            "env": app.env,
            "start_kind": app.start_kind,
            "start_arg": app.start_arg,
            "node_major": app.node_major,
            "image": app.image,
            "container_port": app.container_port,
            "compose_source": app.compose_source,
            "web_service": app.web_service,
            "websites": app.websites,
            "payload_member": Value::Null,
            "payload_error": "",
        });
        let target = staging.join(format!("app-{}.tar", app.name));
        let payload = match export_app_payload(state, &app, &target).await {
            Ok(()) if target.exists() => {
                entry["payload_member"] = json!(format!("applications/{}.tar", app.name));
                Some(target)
            }
            Ok(()) => None,
            Err(why) => {
                tracing::warn!("Could not export application {}: {why}", app.name);
                entry["payload_error"] = json!(last_chars(&why, 500));
                None
            }
        };
        collected.push((entry, payload, app.name));
    }
    collected
}

/// Source: `site_apps.export_payload`.
///
/// An application's directory and its container volumes are both out of the
/// panel's reach — parts of the directory belong to container users, the
/// volumes live under `/var/lib/docker` — so the helper is the only way a
/// backup can hold them.
async fn export_app_payload(
    state: &AppState,
    app: &snpanel_db::SiteApp,
    destination: &std::path::Path,
) -> Result<(), String> {
    let owner = crate::site_apps::owner_linux_user(app)?;
    let name = crate::site_apps::validate_name(&app.name)?;
    let quoted = shell::shlex_quote(&destination.to_string_lossy());
    let fallback = format!("printf '' > {quoted}; echo 0");
    let result = shell::privileged_timed(
        state.settings.command_dry_run,
        "site-app-export",
        &[&owner, &name, &destination.to_string_lossy()],
        None,
        Some(&["bash", "-lc", &fallback]),
        Some(3600),
    )
    .await;
    if !result.ok() {
        return Err(result
            .failure_detail("Could not export the application")
            .trim()
            .to_string());
    }
    Ok(())
}
