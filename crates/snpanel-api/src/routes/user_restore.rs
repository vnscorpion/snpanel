//! `/api/maintenance/restore/...` - accounts put back from their backups,
//! the way DirectAdmin's restore goes: where the backups are, which of them,
//! then one button.
//!
//! Not in the Python, which restored one uploaded archive at a time. The
//! archives are listed at their source - this server's backup folders, an
//! SFTP destination, an S3 destination - and the ones chosen are restored
//! one after another in the background, each fetched into the restore folder
//! first when it is not on this server. A fetched archive is removed once it
//! is restored (the destination still has it) and kept when the restore
//! fails, so it can be looked at or tried again.
//!
//! One restore at a time, and none while a DirectAdmin import runs - nor an
//! import while a restore does: both create and overwrite users, sites and
//! databases, and two at once would race over the same rows and folders.
//! The jobs live in memory, like the imports'; a restart forgets them, and a
//! restore it interrupted is only ever part-way through one account.

use std::path::{Path as FsPath, PathBuf};
use std::sync::{Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;

use crate::auth::CurrentUser;
use crate::backups;
use crate::errors::{bad_request, conflict, not_enough_permissions, not_found};
use crate::state::AppState;

/// The most archives one restore takes.
const MAX_FILES: usize = 200;
/// The largest archive fetched from a destination.
const MAX_FETCH_BYTES: u64 = 200 * 1024 * 1024 * 1024;
/// What a fetch leaves free on the disk: a full disk stops MariaDB, and with
/// it every site on the server.
const KEEP_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// How many restores are remembered.
const KEPT_JOBS: usize = 10;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/maintenance/restore/local",
            get(list_local).fallback(crate::fallback),
        )
        .route(
            "/maintenance/restore/sftp/{target_id}",
            get(list_sftp).fallback(crate::fallback),
        )
        .route(
            "/maintenance/restore/s3/{target_id}",
            get(list_s3).fallback(crate::fallback),
        )
        .route(
            "/maintenance/restore/jobs",
            get(latest_job).post(start).fallback(crate::fallback),
        )
        .route(
            "/maintenance/restore/jobs/{job_id}",
            get(one_job).fallback(crate::fallback),
        )
}

/// Where the archives are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Local,
    Sftp(i64),
    S3(i64),
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Sftp(_) => "sftp",
            Self::S3(_) => "s3",
        }
    }
}

// ---------------------------------------------------------------------------
// the jobs
// ---------------------------------------------------------------------------

fn jobs() -> &'static Mutex<Vec<Value>> {
    static JOBS: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Whether a restore is running - which a DirectAdmin import waits for.
pub fn running() -> bool {
    jobs().lock().is_ok_and(|jobs| {
        jobs.iter()
            .any(|job| job.get("status").and_then(Value::as_str) == Some("running"))
    })
}

fn find(id: &str) -> Option<Value> {
    jobs()
        .lock()
        .ok()?
        .iter()
        .find(|job| job.get("id").and_then(Value::as_str) == Some(id))
        .cloned()
}

fn change(id: &str, apply: impl FnOnce(&mut Value)) {
    if let Ok(mut jobs) = jobs().lock() {
        if let Some(job) = jobs
            .iter_mut()
            .find(|job| job.get("id").and_then(Value::as_str) == Some(id))
        {
            apply(job);
        }
    }
}

fn set_item(id: &str, index: usize, status: &str, message: &str) {
    change(id, |job| {
        job["current"] = job["items"][index]["name"].clone();
        let item = &mut job["items"][index];
        item["status"] = json!(status);
        item["message"] = json!(message);
    });
}

fn file_name(file: &str) -> String {
    FsPath::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_string())
}

fn new_job(source: Source, target_name: &str, files: &[String], usernames: &[String]) -> Value {
    let target_id = match source {
        Source::Local => Value::Null,
        Source::Sftp(id) | Source::S3(id) => json!(id),
    };
    json!({
        "id": crate::da_jobs::new_job_id(),
        "source": source.name(),
        "target_id": target_id,
        "target_name": target_name,
        "status": "running",
        "total": files.len(),
        "done": 0,
        "failed": 0,
        "current": "",
        "items": files.iter().zip(usernames).map(|(file, username)| json!({
            "file": file,
            "name": file_name(file),
            "username": username,
            "status": "queued",
            "message": "",
            "websites": 0,
            "databases": 0,
        })).collect::<Vec<_>>(),
        "created_at": crate::da_jobs::now_iso(),
        "finished_at": Value::Null,
    })
}

// ---------------------------------------------------------------------------
// what each source holds
// ---------------------------------------------------------------------------

fn admin(current: &CurrentUser) -> Result<(), Response> {
    if permissions::is_admin_role(&current.user.role) {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

/// `GET /maintenance/restore/local` - every user backup on this server:
/// each account's folder, the restore folder and the uploads, each described
/// from its own manifest.
async fn list_local(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = admin(&current) {
        return r;
    }
    let root = state.settings.backup_root.clone();
    if state.settings.command_dry_run {
        return axum::Json(json!({ "items": [] })).into_response();
    }
    let items = tokio::task::spawn_blocking(move || local_archives(&root))
        .await
        .unwrap_or_default();
    axum::Json(json!({ "items": items })).into_response()
}

fn local_archives(root: &str) -> Vec<Value> {
    let users = FsPath::new(root).join("users");
    let mut items = Vec::new();
    let Ok(folders) = std::fs::read_dir(&users) else {
        return items;
    };
    for folder in folders.flatten() {
        let Ok(kind) = folder.file_type() else {
            continue;
        };
        // A link could lead out of the backup folder; the restore refuses
        // what resolves outside it anyway.
        if !kind.is_dir() {
            continue;
        }
        let folder_name = folder.file_name().to_string_lossy().into_owned();
        let Ok(files) = std::fs::read_dir(folder.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            let is_archive = file.file_type().is_ok_and(|t| t.is_file())
                && path.to_string_lossy().ends_with(".tar.gz");
            if !is_archive {
                continue;
            }
            let mut item = backups::describe_user_backup(root, &path.to_string_lossy());
            item["folder"] = json!(folder_name);
            let modified = file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    chrono::DateTime::<chrono::Utc>::from(t)
                        .format("%Y-%m-%dT%H:%M:%SZ")
                        .to_string()
                })
                .unwrap_or_default();
            item["modified"] = json!(modified);
            items.push(item);
        }
    }
    items.sort_by(|a, b| {
        let key = |v: &Value| v["modified"].as_str().unwrap_or("").to_string();
        key(b).cmp(&key(a))
    });
    items
}

/// A remote archive as the page lists it: the account its name says, or
/// none when the name is not a user backup's.
fn remote_item(name: &str, size: u64, modified: &str) -> Value {
    let username = backups::user_of_archive(name);
    json!({
        "name": name,
        "size": size,
        "modified": modified,
        "username": username.clone().unwrap_or_default(),
        "valid": username.is_some(),
    })
}

/// `GET /maintenance/restore/sftp/{id}` - the archives in the destination's
/// folder. Only the names are known before one is fetched.
async fn list_sftp(
    State(state): State<AppState>,
    Path(target_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    if let Err(r) = admin(&current) {
        return r;
    }
    match super::maintenance::sftp_archives(&state, target_id).await {
        Ok(archives) => {
            let items: Vec<Value> = archives
                .iter()
                .map(|archive| {
                    let modified = archive
                        .modified
                        .and_then(|secs| chrono::DateTime::from_timestamp(i64::from(secs), 0))
                        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                        .unwrap_or_default();
                    remote_item(&archive.name, archive.size, &modified)
                })
                .collect();
            axum::Json(json!({ "items": items })).into_response()
        }
        Err(message) => crate::errors::error(StatusCode::BAD_GATEWAY, &message),
    }
}

/// `GET /maintenance/restore/s3/{id}` - the archives in the destination's
/// folder of the bucket.
async fn list_s3(
    State(state): State<AppState>,
    Path(target_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    if let Err(r) = admin(&current) {
        return r;
    }
    match super::s3_targets::s3_archives(&state, target_id).await {
        Ok(archives) => {
            let items: Vec<Value> = archives
                .iter()
                .map(|(name, size, modified)| remote_item(name, *size, modified))
                .collect();
            axum::Json(json!({ "items": items })).into_response()
        }
        Err(message) => crate::errors::error(StatusCode::BAD_GATEWAY, &message),
    }
}

// ---------------------------------------------------------------------------
// the restore
// ---------------------------------------------------------------------------

/// `GET /maintenance/restore/jobs` - the restore running, or the last one:
/// what the page shows when it is opened again part-way through.
async fn latest_job(current: CurrentUser) -> Response {
    if let Err(r) = admin(&current) {
        return r;
    }
    let job = jobs().lock().ok().and_then(|jobs| jobs.last().cloned());
    axum::Json(json!({ "job": job })).into_response()
}

/// `GET /maintenance/restore/jobs/{id}`.
async fn one_job(Path(job_id): Path<String>, current: CurrentUser) -> Response {
    if let Err(r) = admin(&current) {
        return r;
    }
    match find(&job_id) {
        Some(job) => axum::Json(job).into_response(),
        None => not_found("Restore not found"),
    }
}

/// `POST /maintenance/restore/jobs` - `{source, target_id, files}`: the
/// archives, by path on this server or by name in the destination's folder.
async fn start(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = admin(&current) {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target_id = payload.get("target_id").and_then(Value::as_i64);
    let source = match (payload.get("source").and_then(Value::as_str), target_id) {
        (Some("local"), _) => Source::Local,
        (Some("sftp"), Some(id)) => Source::Sftp(id),
        (Some("s3"), Some(id)) => Source::S3(id),
        _ => return bad_request("Choose where the backups are"),
    };
    let files: Vec<String> = payload
        .get("files")
        .and_then(Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if files.is_empty() {
        return bad_request("Choose at least one backup");
    }
    if files.len() > MAX_FILES {
        return bad_request(&format!("At most {MAX_FILES} backups at a time"));
    }
    let mut unique = files.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != files.len() {
        return bad_request("A backup is chosen twice");
    }

    let root = state.settings.backup_root.clone();
    let mut usernames = Vec::with_capacity(files.len());
    let target_name = match source {
        Source::Local => {
            for file in &files {
                if backups::user_backup_path(&root, file).is_err() {
                    return not_found(&format!("Backup file not found: {}", file_name(file)));
                }
                usernames.push(String::new());
            }
            String::new()
        }
        Source::Sftp(id) | Source::S3(id) => {
            for file in &files {
                if !crate::sftp::archive_name_ok(file) {
                    return bad_request(&format!("Not a backup archive: {file}"));
                }
                usernames.push(backups::user_of_archive(file).unwrap_or_default());
            }
            let name = if matches!(source, Source::Sftp(_)) {
                match state.db.sftp_targets().by_id(id).await {
                    Ok(Some(row)) => row.name,
                    Ok(None) => return not_found("SFTP target not found"),
                    Err(e) => {
                        tracing::error!("reading SFTP target {id} failed: {e}");
                        return crate::errors::internal_error();
                    }
                }
            } else {
                match state.db.s3_targets().by_id(id).await {
                    Ok(Some(row)) => row.name,
                    Ok(None) => return not_found("S3 destination not found"),
                    Err(e) => {
                        tracing::error!("reading S3 destination {id} failed: {e}");
                        return crate::errors::internal_error();
                    }
                }
            };
            name
        }
    };

    // Checked and recorded under one lock, so two clicks cannot both start.
    let job = new_job(source, &target_name, &files, &usernames);
    let job_id = job["id"].as_str().unwrap_or_default().to_string();
    {
        let Ok(mut all) = jobs().lock() else {
            return crate::errors::internal_error();
        };
        if all
            .iter()
            .any(|job| job.get("status").and_then(Value::as_str) == Some("running"))
        {
            return conflict("A restore is already running.");
        }
        if crate::da_jobs::any_running() {
            return crate::errors::error(
                StatusCode::TOO_MANY_REQUESTS,
                "An import is already running. Please wait.",
            );
        }
        all.push(job.clone());
        let excess = all.len().saturating_sub(KEPT_JOBS);
        all.drain(..excess);
    }

    let from = match source {
        Source::Local => "this server".to_string(),
        _ => target_name.clone(),
    };
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "restore_users",
        &format!("{} backup(s) from {from}", files.len()),
    )
    .await;

    let worker_state = state.clone();
    let admin_id = current.user.id;
    tokio::spawn(async move {
        work(worker_state, job_id, source, files, admin_id).await;
    });
    axum::Json(job).into_response()
}

/// The archives, one after another. One that fails is recorded and the
/// rest go on: an account that cannot be restored should not keep the next
/// one from being.
async fn work(state: AppState, job_id: String, source: Source, files: Vec<String>, admin_id: i64) {
    for (index, file) in files.iter().enumerate() {
        let (archive, fetched) = match source {
            Source::Local => (file.clone(), false),
            Source::Sftp(_) | Source::S3(_) => {
                set_item(&job_id, index, "fetching", "");
                match fetch(&state, source, file).await {
                    Ok(path) => (path.to_string_lossy().into_owned(), true),
                    Err(message) => {
                        set_item(&job_id, index, "error", &message);
                        change(&job_id, |job| {
                            job["failed"] = json!(job["failed"].as_i64().unwrap_or(0) + 1)
                        });
                        continue;
                    }
                }
            }
        };
        set_item(&job_id, index, "restoring", "");
        match super::maintenance::run_user_restore(&state, &archive).await {
            Ok(result) => {
                let username = result
                    .get("username")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let count = |key: &str| {
                    result
                        .get(key)
                        .map(|v| {
                            v.as_array()
                                .map_or_else(|| v.as_i64().unwrap_or(0), |a| a.len() as i64)
                        })
                        .unwrap_or(0)
                };
                let (websites, databases) = (count("websites"), count("databases"));
                change(&job_id, |job| {
                    let item = &mut job["items"][index];
                    item["status"] = json!("done");
                    item["message"] = json!("");
                    item["username"] = json!(username);
                    item["websites"] = json!(websites);
                    item["databases"] = json!(databases);
                    job["done"] = json!(job["done"].as_i64().unwrap_or(0) + 1);
                });
                let detail = format!("{}: {}", source.name(), file_name(file));
                if let Err(e) = state
                    .db
                    .audits()
                    .log(Some(admin_id), "restore_user", &username, &detail)
                    .await
                {
                    tracing::error!(
                        "Failed to write audit log: action=restore_user target={username}: {e}"
                    );
                }
                if fetched {
                    let _ = std::fs::remove_file(&archive);
                }
            }
            Err(why) => {
                let message = if fetched {
                    format!("{why} (the archive is kept in {archive})")
                } else {
                    why
                };
                set_item(&job_id, index, "error", &message);
                change(&job_id, |job| {
                    job["failed"] = json!(job["failed"].as_i64().unwrap_or(0) + 1)
                });
            }
        }
    }
    change(&job_id, |job| {
        job["status"] = json!("done");
        job["current"] = json!("");
        job["finished_at"] = json!(crate::da_jobs::now_iso());
    });
}

/// An archive from the destination into the restore folder, under its own
/// name or - when that is taken - with a stamp and six hex characters, as an
/// upload would be. The disk keeps [`KEEP_FREE_BYTES`] free.
async fn fetch(state: &AppState, source: Source, name: &str) -> Result<PathBuf, String> {
    let dir = backups::user_restore_dir(&state.settings.backup_root);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create the restore folder: {e}"))?;
    let free = free_bytes(&dir).unwrap_or(u64::MAX);
    if free <= KEEP_FREE_BYTES {
        return Err(format!(
            "Not enough free disk space to fetch {name}: {} MB left",
            free / (1024 * 1024)
        ));
    }
    let limit = MAX_FETCH_BYTES.min(free - KEEP_FREE_BYTES);
    let mut dest = dir.join(name);
    if dest.exists() {
        let stem = name.trim_end_matches(".tar.gz");
        dest = dir.join(format!(
            "{stem}-{}-{}.tar.gz",
            backups::stamp(),
            crate::ratelimit::random_hex(3)
        ));
    }
    let fetched = match source {
        Source::Sftp(id) => super::maintenance::sftp_fetch(state, id, name, &dest, limit).await,
        Source::S3(id) => super::s3_targets::s3_fetch(state, id, name, &dest, limit).await,
        Source::Local => return Ok(PathBuf::from(name)),
    };
    match fetched {
        Ok(_) => Ok(dest),
        Err(message) if message.contains("larger than") => Err(format!(
            "{name} does not fit in the free disk space ({} MB left)",
            free / (1024 * 1024)
        )),
        Err(message) => Err(message),
    }
}

/// The bytes free for an unprivileged writer on the filesystem of `path`.
fn free_bytes(path: &FsPath) -> Option<u64> {
    let text = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: a zeroed statvfs is a valid out-parameter, the path is a
    // NUL-terminated string that outlives the call, and the result is only
    // read when the call says it succeeded.
    unsafe {
        let mut buf: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(text.as_ptr(), &mut buf) != 0 {
            return None;
        }
        Some(buf.f_bavail as u64 * buf.f_frsize as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_archive_says_whose_its_name_says_it_is() {
        let item = remote_item(
            "user-alice-20260925020000.tar.gz",
            42,
            "2026-09-25T02:00:03Z",
        );
        assert_eq!(item["username"], "alice");
        assert_eq!(item["valid"], true);
        assert_eq!(item["size"], 42);
        let site = remote_item("example.com-20260925020000.tar.gz", 1, "");
        assert_eq!(site["username"], "");
        assert_eq!(site["valid"], false);
    }

    #[test]
    fn a_job_starts_with_every_archive_queued() {
        let files = vec![
            "user-a-20260925020000.tar.gz".to_string(),
            "b.tar.gz".to_string(),
        ];
        let job = new_job(
            Source::Sftp(3),
            "Offsite",
            &files,
            &["a".into(), "b".into()],
        );
        assert_eq!(job["source"], "sftp");
        assert_eq!(job["target_id"], 3);
        assert_eq!(job["status"], "running");
        assert_eq!(job["total"], 2);
        let items = job["items"].as_array().unwrap();
        assert!(items.iter().all(|item| item["status"] == "queued"));
        assert_eq!(items[1]["username"], "b");
        assert_eq!(items[0]["name"], "user-a-20260925020000.tar.gz");
    }

    #[test]
    fn a_local_archive_is_named_by_its_file() {
        assert_eq!(
            file_name("/var/backups/snpanel/users/alice/alice.tar.gz"),
            "alice.tar.gz"
        );
    }

    #[test]
    fn the_free_space_of_a_real_folder_is_read() {
        assert!(free_bytes(&std::env::temp_dir()).is_some_and(|free| free > 0));
        assert!(free_bytes(FsPath::new("/nonexistent/snpanel")).is_none());
    }

    #[test]
    fn the_local_listing_reads_every_folder_under_users() {
        let root = std::env::temp_dir().join(format!("snpanel-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (folder, name) in [("alice", "alice.tar.gz"), ("restore", "bob.tar.gz")] {
            let dir = root.join("users").join(folder);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), b"not really an archive").unwrap();
        }
        std::fs::write(root.join("users/alice/notes.txt"), b"x").unwrap();
        let items = local_archives(&root.to_string_lossy());
        let mut folders: Vec<&str> = items
            .iter()
            .map(|i| i["folder"].as_str().unwrap())
            .collect();
        folders.sort_unstable();
        assert_eq!(folders, ["alice", "restore"]);
        // Not a real archive: listed, and said to be invalid.
        assert!(items.iter().all(|i| i["valid"] == false));
        let _ = std::fs::remove_dir_all(&root);
    }
}
