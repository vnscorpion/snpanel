//! `/api/maintenance/restore/...` - accounts put back from their backups,
//! the way DirectAdmin's restore goes: where the backups are, which of them,
//! then one button.
//!
//! Not in the Python, which restored one uploaded archive at a time. The
//! archives are listed at their source - this server's backup folders, an
//! SFTP destination, an S3 destination, or another server given by hand over
//! SFTP, FTP or FTPS - and the ones chosen are restored one after another in
//! the background, each fetched into the restore folder first when it is not
//! on this server.
//!
//! Another server's password is used for the listing and held in memory for
//! the restore that follows, and nowhere else: not saved, not in the job the
//! page reads, not in a log. Its SFTP host key, seen when the folder was
//! listed, is the one the fetch insists on; an FTPS certificate this machine
//! does not vouch for is used only once the administrator trusts its
//! SHA-256. A fetched archive is removed once it
//! is restored (the destination still has it) and kept when the restore
//! fails, so it can be looked at or tried again.
//!
//! One restore at a time, and none while a DirectAdmin import runs - nor an
//! import while a restore does: both create and overwrite users, sites and
//! databases, and two at once would race over the same rows and folders.
//! The jobs live in memory, like the imports'; a restart forgets them, and a
//! restore it interrupted is only ever part-way through one account.

use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
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
            "/maintenance/restore/connection",
            post(list_connection).fallback(crate::fallback),
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
    /// Another server, given by hand: its [`Connection`] travels beside.
    Connection,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Sftp(_) => "sftp",
            Self::S3(_) => "s3",
            Self::Connection => "connection",
        }
    }
}

/// How another server is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Sftp,
    Ftp,
    Ftps,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Sftp => "sftp",
            Self::Ftp => "ftp",
            Self::Ftps => "ftps",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Sftp => 22,
            Self::Ftp | Self::Ftps => 21,
        }
    }
}

/// Another server, given by hand for one restore and never saved.
#[derive(Clone)]
struct Connection {
    protocol: Protocol,
    host: String,
    port: u16,
    username: String,
    password: String,
    /// The folder on that server; empty is where the account starts.
    folder: String,
    /// SFTP: the host key seen when the folder was listed, so that the
    /// fetch is from the same server.
    host_key: Option<String>,
    /// FTPS: a certificate this machine does not vouch for, trusted by its
    /// SHA-256.
    certificate: Option<String>,
}

/// Never the password.
impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

impl Connection {
    /// How the job and the audit log name it - without the password.
    fn describe(&self) -> String {
        format!(
            "{}://{}@{}:{}",
            self.protocol.name(),
            self.username,
            self.host,
            self.port
        )
    }

    fn sftp_target(&self) -> crate::sftp::Target<'_> {
        crate::sftp::Target {
            host: &self.host,
            port: self.port,
            username: &self.username,
            remote_path: &self.folder,
            password: Some(&self.password),
            private_key: None,
            expected_host_key_type: None,
            expected_host_key_fingerprint: self.host_key.as_deref(),
        }
    }

    fn ftp_server(&self) -> crate::ftp::Server<'_> {
        crate::ftp::Server {
            host: &self.host,
            port: self.port,
            username: &self.username,
            password: &self.password,
            tls: self.protocol == Protocol::Ftps,
            trusted: self.certificate.as_deref(),
        }
    }
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Another server as the page gives it, checked.
fn connection_from(value: Option<&Value>) -> Result<Connection, Response> {
    let Some(given) = value.and_then(Value::as_object) else {
        return Err(bad_request("Say which server the backups are on"));
    };
    let text = |key: &str| given.get(key).and_then(Value::as_str).unwrap_or("");
    let protocol = match text("protocol") {
        "sftp" => Protocol::Sftp,
        "ftp" => Protocol::Ftp,
        "ftps" => Protocol::Ftps,
        _ => return Err(bad_request("The protocol is SFTP, FTP or FTPS")),
    };
    let host = text("host").trim().to_ascii_lowercase();
    if !host_ok(&host) {
        return Err(bad_request(
            "The server is a host name or an address, such as backup.example.com",
        ));
    }
    let port = match given.get("port") {
        None | Some(Value::Null) => protocol.default_port(),
        Some(Value::String(text)) if text.trim().is_empty() => protocol.default_port(),
        Some(value) => {
            let number = value
                .as_u64()
                .or_else(|| value.as_str().and_then(|t| t.trim().parse().ok()));
            match number
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| *n > 0)
            {
                Some(port) => port,
                None => return Err(bad_request("The port is a number from 1 to 65535")),
            }
        }
    };
    let username = text("username").trim().to_string();
    if username.is_empty() || username.len() > 255 || username.chars().any(char::is_control) {
        return Err(bad_request("Enter the user name to sign in with"));
    }
    let password = given
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if password.is_empty() {
        return Err(bad_request("Enter the password"));
    }
    if password.len() > 1024 || password.contains(['\r', '\n', '\0']) {
        return Err(bad_request("The password cannot have line breaks in it"));
    }
    let folder = text("folder").trim().to_string();
    if folder.len() > 1024 || folder.chars().any(char::is_control) {
        return Err(bad_request(
            "The folder is a path on that server, such as /backups",
        ));
    }
    let host_key = text("host_key").trim().to_string();
    if host_key.len() > 200 || host_key.chars().any(|c| c.is_control() || c == ' ') {
        return Err(bad_request("That is not a host key's fingerprint"));
    }
    let certificate = text("certificate")
        .trim()
        .to_ascii_lowercase()
        .replace(':', "");
    if !certificate.is_empty()
        && !(certificate.len() == 64 && certificate.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(bad_request(
            "That is not a certificate's SHA-256 fingerprint",
        ));
    }
    Ok(Connection {
        protocol,
        host,
        port,
        username,
        password,
        folder,
        host_key: (!host_key.is_empty()).then_some(host_key),
        certificate: (!certificate.is_empty()).then_some(certificate),
    })
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
        Source::Local | Source::Connection => Value::Null,
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

/// `POST /maintenance/restore/connection` - `{protocol, host, port,
/// username, password, folder, host_key?, certificate?}`: the archives in
/// that server's folder. SFTP answers with the host key it saw, for the
/// restore to insist on; FTPS with a certificate this machine does not vouch
/// for - or not the one given as `certificate` - answers `untrusted` and its
/// SHA-256, and no archives, until it is given back as `certificate`.
async fn list_connection(State(state): State<AppState>, req: axum::extract::Request) -> Response {
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
    let connection = match connection_from(Some(&payload)) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let items = |archives: &[crate::sftp::RemoteArchive]| -> Vec<Value> {
        archives
            .iter()
            .map(|archive| {
                let modified = archive
                    .modified
                    .and_then(|secs| chrono::DateTime::from_timestamp(i64::from(secs), 0))
                    .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_default();
                remote_item(&archive.name, archive.size, &modified)
            })
            .collect()
    };
    match connection.protocol {
        Protocol::Sftp => match crate::sftp::list(&connection.sftp_target()).await {
            Ok((archives, host_key)) => axum::Json(json!({
                "items": items(&archives),
                "host_key": {
                    "type": host_key.host_key_type,
                    "fingerprint": host_key.host_key_fingerprint,
                },
            }))
            .into_response(),
            Err(e) => crate::errors::error(StatusCode::BAD_GATEWAY, &e.to_string()),
        },
        Protocol::Ftp | Protocol::Ftps => {
            match crate::ftp::list(&connection.ftp_server(), &connection.folder).await {
                Ok(archives) => axum::Json(json!({
                    "items": items(&archives),
                    "certificate": connection.certificate,
                }))
                .into_response(),
                Err(crate::ftp::FtpError::Untrusted(fingerprint)) => axum::Json(json!({
                    "items": [],
                    "untrusted": { "fingerprint": fingerprint },
                }))
                .into_response(),
                Err(crate::ftp::FtpError::Failed(message)) => {
                    crate::errors::error(StatusCode::BAD_GATEWAY, &message)
                }
            }
        }
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
/// archives, by path on this server or by name in the destination's folder;
/// for another server, `source` is `connection` and `connection` says which,
/// as the listing had it.
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
        (Some("connection"), _) => Source::Connection,
        _ => return bad_request("Choose where the backups are"),
    };
    let connection = if source == Source::Connection {
        match connection_from(payload.get("connection")) {
            Ok(c) => Some(Arc::new(c)),
            Err(r) => return r,
        }
    } else {
        None
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
        Source::Sftp(_) | Source::S3(_) | Source::Connection => {
            for file in &files {
                if !crate::sftp::archive_name_ok(file) {
                    return bad_request(&format!("Not a backup archive: {file}"));
                }
                usernames.push(backups::user_of_archive(file).unwrap_or_default());
            }
            let name = if let Some(connection) = &connection {
                connection.describe()
            } else if let Source::Sftp(id) = source {
                match state.db.sftp_targets().by_id(id).await {
                    Ok(Some(row)) => row.name,
                    Ok(None) => return not_found("SFTP target not found"),
                    Err(e) => {
                        tracing::error!("reading SFTP target {id} failed: {e}");
                        return crate::errors::internal_error();
                    }
                }
            } else if let Source::S3(id) = source {
                match state.db.s3_targets().by_id(id).await {
                    Ok(Some(row)) => row.name,
                    Ok(None) => return not_found("S3 destination not found"),
                    Err(e) => {
                        tracing::error!("reading S3 destination {id} failed: {e}");
                        return crate::errors::internal_error();
                    }
                }
            } else {
                String::new()
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
        work(worker_state, job_id, source, files, admin_id, connection).await;
    });
    axum::Json(job).into_response()
}

/// The archives, one after another. One that fails is recorded and the
/// rest go on: an account that cannot be restored should not keep the next
/// one from being.
async fn work(
    state: AppState,
    job_id: String,
    source: Source,
    files: Vec<String>,
    admin_id: i64,
    connection: Option<Arc<Connection>>,
) {
    for (index, file) in files.iter().enumerate() {
        let (archive, fetched) = match source {
            Source::Local => (file.clone(), false),
            Source::Sftp(_) | Source::S3(_) | Source::Connection => {
                set_item(&job_id, index, "fetching", "");
                match fetch(&state, source, file, connection.as_deref()).await {
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
async fn fetch(
    state: &AppState,
    source: Source,
    name: &str,
    connection: Option<&Connection>,
) -> Result<PathBuf, String> {
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
        Source::Connection => match connection {
            Some(c) if c.protocol == Protocol::Sftp => {
                crate::sftp::download(&c.sftp_target(), name, &dest, limit)
                    .await
                    .map(|(written, _)| written)
                    .map_err(|e| e.to_string())
            }
            Some(c) => crate::ftp::download(&c.ftp_server(), &c.folder, name, &dest, limit)
                .await
                .map_err(|e| e.to_string()),
            None => Err("Say which server the backups are on".to_string()),
        },
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
    fn another_server_is_checked_and_never_named_with_its_password() {
        let given = json!({
            "protocol": "ftps", "host": "Backup.Example.com", "username": "old",
            "password": "p4ss word", "folder": "/backups",
            "certificate": format!("AB:CD:{}", "ef".repeat(30)),
        });
        let connection = connection_from(Some(&given)).unwrap();
        assert_eq!(connection.port, 21);
        assert_eq!(connection.host, "backup.example.com");
        assert_eq!(connection.certificate.as_deref().map(str::len), Some(64));
        let named = connection.describe();
        assert_eq!(named, "ftps://old@backup.example.com:21");
        assert!(!format!("{connection:?}").contains("p4ss"));
        assert!(connection.ftp_server().tls);

        let sftp = connection_from(Some(&json!({
            "protocol": "sftp", "host": "10.0.0.5", "port": "2222", "username": "u", "password": "p",
        })))
        .unwrap();
        assert_eq!((sftp.port, sftp.protocol), (2222, Protocol::Sftp));
        assert_eq!(sftp.sftp_target().password, Some("p"));

        for bad in [
            json!({"protocol": "scp", "host": "a", "username": "u", "password": "p"}),
            json!({"protocol": "ftp", "host": "a b", "username": "u", "password": "p"}),
            json!({"protocol": "ftp", "host": "a", "username": "u", "password": "p\r\nDELE x"}),
            json!({"protocol": "ftp", "host": "a", "username": "", "password": "p"}),
            json!({"protocol": "ftp", "host": "a", "username": "u", "password": ""}),
            json!({"protocol": "ftp", "host": "a", "port": 70000, "username": "u", "password": "p"}),
            json!({"protocol": "ftps", "host": "a", "username": "u", "password": "p", "certificate": "nope"}),
        ] {
            assert!(connection_from(Some(&bad)).is_err(), "{bad}");
        }
        assert!(connection_from(None).is_err());
    }

    #[test]
    fn a_job_from_another_server_has_no_target_id() {
        let job = new_job(
            Source::Connection,
            "sftp://old@backup.example.com:22",
            &["user-a-20260925020000.tar.gz".to_string()],
            &["a".into()],
        );
        assert_eq!(job["source"], "connection");
        assert_eq!(job["target_id"], Value::Null);
        assert_eq!(job["target_name"], "sftp://old@backup.example.com:22");
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
