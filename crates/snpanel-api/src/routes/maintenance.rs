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
            get(list_files).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/{website_id}/read",
            get(read_file).fallback(crate::fallback),
        )
        .route(
            "/maintenance/files/{website_id}/download",
            get(download_file).fallback(crate::fallback),
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
            get(list_restore_backups).fallback(crate::fallback),
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
    let path = params.get("path").cloned().unwrap_or_default();
    match files::list_files(&website.root_path, &path) {
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
    let Some(path) = params.get("path") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "path"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    let allow_sensitive = permissions::is_admin_role(&current.user.role);
    let target = match files::readable_text_file(&website.root_path, path, allow_sensitive) {
        Ok(t) => t,
        Err(e) => return bad_request(&e.to_string()),
    };

    // A site with a Linux user owns its files, and the panel account cannot
    // read into them - so the read happens as that user, through the helper.
    match website.linux_user.as_deref().filter(|u| !u.is_empty()) {
        Some(user) => {
            let root = std::fs::canonicalize(&website.root_path)
                .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
            let root_str = root.to_string_lossy().into_owned();
            let relative = files::helper_relative_path(&website.root_path, &target);
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
    let Some(path) = params.get("path") else {
        return crate::errors::validation_error(vec![json!({
            "type": "missing",
            "loc": ["query", "path"],
            "msg": "Field required",
            "input": null,
        })]);
    };
    let allow_sensitive = permissions::is_admin_role(&current.user.role);
    let target = match files::download_file_path(&website.root_path, path, allow_sensitive) {
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
    let Some(user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) else {
        return Err(bad_request("Website has no runtime user configured"));
    };
    let root = std::fs::canonicalize(&website.root_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&website.root_path));
    let root_str = root.to_string_lossy().into_owned();
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
    website: &snpanel_db::Website,
    incoming_bytes: u64,
    replaced_bytes: u64,
) -> Result<(), Response> {
    let owner = match state.db.users().by_id(website.owner_id).await {
        Ok(Some(u)) => u,
        // Source: `website.owner` being `None`. The Python would raise
        // `AttributeError` reading `.role` off it, which is a 500 - not a
        // silently unlimited write.
        Ok(None) => {
            tracing::error!("website {} has no owner row", website.id);
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
    if let Err(r) = quota_check(&state, &website, total_size(&sources), 0).await {
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
    if let Err(r) = quota_check(&state, &website, 0, 0).await {
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
    if let Err(r) = quota_check(&state, &website, content_size, existing_file_size(&target)).await {
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
}
