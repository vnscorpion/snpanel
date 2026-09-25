//! Finding, reading and removing backup archives.
//!
//! Source: the listing half of `app.services.backup`. The half that *makes*
//! an archive is a different job and a later batch; this is what the screens
//! that show them need.
//!
//! Every path here is checked against the backup root before it is touched,
//! because the file name arrives in a query string. `backup_path` and
//! `user_backup_path` are that check, and they are why a request cannot ask
//! for `/etc/shadow` and be handed it as a download.

use std::path::{Path, PathBuf};

use snpanel_db::s3_targets::NameStyle;

/// Source: `BACKUP_MANIFEST`.
const BACKUP_MANIFEST: &str = "manifest.json";

/// Source: `PANEL_USERNAME_RE` - `^[A-Za-z0-9._-]{3,64}$`.
///
/// Note that it is *not* the Linux user pattern: a panel account name may
/// carry capitals and dots, and the backup directory is named after it.
fn valid_panel_username(name: &str) -> bool {
    let len = name.chars().count();
    (3..=64).contains(&len)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Debug)]
pub enum BackupError {
    /// Source: `FileNotFoundError("Backup not found")`, which the endpoints
    /// turn into a 404.
    NotFound,
    /// Source: `ValueError`, which becomes a 400.
    Invalid(String),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Backup not found"),
            Self::Invalid(m) => write!(f, "{m}"),
        }
    }
}

/// `Path.resolve()` on a path that may not exist.
fn resolve(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// `path.suffixes[-2:] == [".tar", ".gz"]`.
fn is_tar_gz(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy().ends_with(".tar.gz"))
        .unwrap_or(false)
}

/// Every `*.tar.gz` in a directory, newest name first.
///
/// Source: `sorted(dir.glob("*.tar.gz"), reverse=True)` - sorted by *path*,
/// descending, which for the panel's stamped names is newest first.
fn list_archives(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_tar_gz(p) && p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    out.sort();
    out.reverse();
    out
}

/// Source: `list_backups`.
pub fn list_backups(backup_root: &str, domain: &str, dry_run: bool) -> Vec<String> {
    if dry_run {
        return Vec::new();
    }
    list_archives(&Path::new(backup_root).join(domain))
}

/// Source: `backup_path`.
///
/// Note the containment test: the resolved backup root must be a *parent* of
/// the resolved path, so the directory itself does not pass and neither does
/// a sibling whose name merely starts the same way.
pub fn backup_path(
    backup_root: &str,
    domain: &str,
    backup_file: &str,
) -> Result<PathBuf, BackupError> {
    let root = resolve(&resolve(Path::new(backup_root)).join(domain));
    let path = resolve(Path::new(backup_file));
    if !path.ancestors().skip(1).any(|a| a == root) {
        return Err(BackupError::NotFound);
    }
    if !path.is_file() || !is_tar_gz(&path) {
        return Err(BackupError::NotFound);
    }
    Ok(path)
}

/// Source: `delete_backup`.
pub fn delete_backup(
    backup_root: &str,
    domain: &str,
    backup_file: &str,
) -> Result<String, BackupError> {
    let path = backup_path(backup_root, domain, backup_file)?;
    std::fs::remove_file(&path).map_err(|_| BackupError::NotFound)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Source: `_user_backup_dir`.
pub fn user_backup_dir(backup_root: &str, username: &str) -> Result<PathBuf, BackupError> {
    if !valid_panel_username(username) {
        return Err(BackupError::Invalid("Invalid panel username".into()));
    }
    Ok(Path::new(backup_root).join("users").join(username))
}

/// Source: `_user_restore_dir`.
pub fn user_restore_dir(backup_root: &str) -> PathBuf {
    Path::new(backup_root).join("users").join("restore")
}

/// Source: `list_user_backups`.
pub fn list_user_backups(
    backup_root: &str,
    username: &str,
    dry_run: bool,
) -> Result<Vec<String>, BackupError> {
    let dir = user_backup_dir(backup_root, username)?;
    if dry_run {
        return Ok(Vec::new());
    }
    Ok(list_archives(&dir))
}

/// Source: `prune_user_backups`.
///
/// ```python
/// keep = max(int(keep or 1), 1)
/// for old_backup in list_user_backups(username)[keep:]:
///     Path(old_backup).unlink(missing_ok=True)
/// ```
///
/// **The ordering is the whole of it.** `list_user_backups` sorts the paths
/// *descending*, so the list runs newest first and `[keep:]` is the tail —
/// the oldest. A list built ascending and pruned the same way would delete
/// the customer's newest backups and keep the oldest, silently, and the
/// first anybody would know is a restore from three months ago.
///
/// A retention of zero or less keeps one, which is `keep or 1` followed by
/// `max(..., 1)`: there is no setting that means "delete everything".
///
/// `unlink(missing_ok=True)`: a file that went between the listing and the
/// delete is not an error. Two schedules for the same user can overlap.
///
/// Not the Python's in one way: only the archives `style` names are counted
/// and deleted - see [`in_family`]. The Python counted every `*.tar.gz` in
/// the directory, which made no difference while every one of them was
/// `user-<name>-<stamp>`; now a schedule may name its archives otherwise, and
/// a nightly timestamped schedule must not delete a week of `-monday` files.
/// A style whose names repeat - `None`, `Weekday` - replaces its files
/// instead, and has nothing to prune.
pub fn prune_user_backups(
    backup_root: &str,
    username: &str,
    style: NameStyle,
    keep: i64,
    dry_run: bool,
) -> Result<usize, BackupError> {
    if matches!(style, NameStyle::None | NameStyle::Weekday) {
        return Ok(0);
    }
    let keep = keep.max(1) as usize;
    let archives = list_user_backups(backup_root, username, dry_run)?
        .into_iter()
        .filter(|path| {
            Path::new(path)
                .file_name()
                .is_some_and(|name| in_family(&name.to_string_lossy(), username, style))
        });
    let mut removed = 0;
    for old in archives.skip(keep) {
        if std::fs::remove_file(&old).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Source: `user_backup_path`.
///
/// Different from `backup_path` in one way that matters: the root itself
/// passes the containment test here (`backup_root != path` is allowed to be
/// false only when the path *is* the root, which then fails the file check).
pub fn user_backup_path(backup_root: &str, backup_file: &str) -> Result<PathBuf, BackupError> {
    let root = resolve(Path::new(backup_root));
    let path = resolve(Path::new(backup_file));
    if root != path && !path.ancestors().skip(1).any(|a| a == root) {
        return Err(BackupError::NotFound);
    }
    if !path.is_file() || !is_tar_gz(&path) {
        return Err(BackupError::NotFound);
    }
    Ok(path)
}

/// Source: `delete_user_backup`.
pub fn delete_user_backup(backup_root: &str, backup_file: &str) -> Result<String, BackupError> {
    let path = user_backup_path(backup_root, backup_file)?;
    std::fs::remove_file(&path).map_err(|_| BackupError::NotFound)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Source: `read_backup_manifest` - `manifest.json` out of the archive.
/// Source: `MAX_UPLOAD_BYTES` — one gigabyte.
pub const MAX_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024;

/// Whether an upload is over the limit.
///
/// Source: `if written > MAX_UPLOAD_BYTES` — **strictly** greater, so an
/// archive of exactly a gigabyte is allowed. Its own function because the
/// call sites take a gigabyte of bytes to exercise and this does not.
pub fn over_upload_limit(len: u64) -> bool {
    len > MAX_UPLOAD_BYTES
}

/// The name an uploaded archive is allowed to land under.
///
/// Source: the three lines `save_uploaded_backup` and
/// `save_uploaded_user_backup` share. `Path(filename).name` throws away
/// every directory component, so `../../etc/x.tar.gz` becomes `x.tar.gz`
/// before anything else looks at it — and the resolve-and-compare below is
/// what catches what is left, a name that is `.` or `..` or empty and so
/// resolves to the directory itself.
fn uploaded_archive_name(filename: &str) -> Result<String, BackupError> {
    let name = std::path::Path::new(filename)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !name.ends_with(".tar.gz") {
        return Err(BackupError::Invalid(
            "Only .tar.gz backup files are supported".to_string(),
        ));
    }
    Ok(name)
}

/// `backup_dir not in target.parents` — the target must be *inside* the
/// directory, not the directory itself.
fn inside(dir: &std::path::Path, target: &std::path::Path) -> bool {
    target.parent().is_some_and(|parent| parent == dir)
}

/// Source: `save_uploaded_backup` — one website's own backup folder.
///
/// A name that is already there is **overwritten**, unlike the user-backup
/// saver below. That is the Python's choice and it is defensible here: a
/// site's backups are named by timestamp, so a collision means the same
/// archive being re-uploaded.
pub fn save_uploaded_backup(
    backup_root: &str,
    domain: &str,
    filename: &str,
    data: &[u8],
) -> Result<String, BackupError> {
    if over_upload_limit(data.len() as u64) {
        return Err(BackupError::Invalid("Backup file is too large".to_string()));
    }
    let name = uploaded_archive_name(filename)?;
    let dir = std::path::Path::new(backup_root).join(domain);
    std::fs::create_dir_all(&dir)
        .map_err(|e| BackupError::Invalid(format!("Cannot create the backup folder: {e}")))?;
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    let target = dir.join(&name);
    if !inside(&dir, &target) {
        return Err(BackupError::Invalid("Invalid backup filename".to_string()));
    }
    std::fs::write(&target, data)
        .map_err(|e| BackupError::Invalid(format!("Cannot write the backup: {e}")))?;
    Ok(target.to_string_lossy().into_owned())
}

/// Source: `save_uploaded_user_backup` — the shared restore folder.
///
/// **A name that is already there is not overwritten here.** These are
/// archives an administrator is uploading to restore *other people's*
/// accounts, and two of them can easily share a name; silently replacing
/// one with the other would restore the wrong customer. The second gets a
/// timestamp and six random hex characters.
pub fn save_uploaded_user_backup(
    backup_root: &str,
    filename: &str,
    data: &[u8],
    stamp: &str,
    nonce: &str,
) -> Result<String, BackupError> {
    if over_upload_limit(data.len() as u64) {
        return Err(BackupError::Invalid("Backup file is too large".to_string()));
    }
    let name = uploaded_archive_name(filename)?;
    let dir = user_restore_dir(backup_root);
    std::fs::create_dir_all(&dir)
        .map_err(|e| BackupError::Invalid(format!("Cannot create the restore folder: {e}")))?;
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    let mut target = dir.join(&name);
    if !inside(&dir, &target) {
        return Err(BackupError::Invalid("Invalid backup filename".to_string()));
    }
    if target.exists() {
        let stem = name.trim_end_matches(".tar.gz");
        target = dir.join(format!("{stem}-{stamp}-{nonce}.tar.gz"));
    }
    std::fs::write(&target, data)
        .map_err(|e| BackupError::Invalid(format!("Cannot write the backup: {e}")))?;
    Ok(target.to_string_lossy().into_owned())
}

/// Source: `delete_user_restore_backup`.
///
/// The path has to resolve **inside the restore folder**, which is what
/// keeps this from being a way to unlink anything on the machine that ends
/// in `.tar.gz`. A path outside it is reported as not found rather than as
/// refused: it is not there, as far as this endpoint is concerned.
pub fn delete_user_restore_backup(
    backup_root: &str,
    backup_file: &str,
) -> Result<String, BackupError> {
    let path = user_backup_path(backup_root, backup_file)?;
    let dir = user_restore_dir(backup_root);
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    let resolved = std::fs::canonicalize(&path).unwrap_or(path);
    if !inside(&dir, &resolved) {
        return Err(BackupError::NotFound);
    }
    std::fs::remove_file(&resolved).map_err(|_| BackupError::NotFound)?;
    Ok(resolved.to_string_lossy().into_owned())
}

pub fn read_backup_manifest(
    backup_root: &str,
    backup_file: &str,
) -> Result<serde_json::Value, BackupError> {
    use std::io::Read;

    let archive = user_backup_path(backup_root, backup_file)?;
    let file = std::fs::File::open(&archive).map_err(|_| BackupError::NotFound)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(decoder);
    let entries = tar
        .entries()
        .map_err(|e| BackupError::Invalid(format!("Backup manifest cannot be read: {e}")))?;
    for entry in entries.flatten() {
        let Ok(path) = entry.path() else { continue };
        if path.to_string_lossy() != BACKUP_MANIFEST {
            continue;
        }
        if entry.header().size().unwrap_or(0) > 2 * 1024 * 1024 {
            return Err(BackupError::Invalid("Backup manifest is too large".into()));
        }
        let mut text = String::new();
        let mut entry = entry;
        entry
            .read_to_string(&mut text)
            .map_err(|_| BackupError::Invalid("Backup manifest cannot be read".into()))?;
        return serde_json::from_str(&text)
            .map_err(|e| BackupError::Invalid(format!("Backup manifest cannot be read: {e}")));
    }
    Err(BackupError::Invalid("Backup manifest not found".into()))
}

/// Source: `list_uploaded_user_backups`.
///
/// Two directories, de-duplicated, and when a username is given each archive
/// is opened to check whose it is - a manifest that cannot be read means the
/// archive is skipped rather than attributed to the wrong account.
pub fn list_uploaded_user_backups(
    backup_root: &str,
    username: Option<&str>,
    dry_run: bool,
) -> Vec<String> {
    if dry_run {
        return Vec::new();
    }
    let dirs = [
        user_restore_dir(backup_root),
        Path::new(backup_root).join("users").join("uploads"),
    ];
    let mut items: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for dir in dirs {
        for path in list_archives(&dir) {
            if seen.contains(&path) {
                continue;
            }
            if let Some(wanted) = username {
                let Ok(manifest) = read_backup_manifest(backup_root, &path) else {
                    continue;
                };
                let owner = manifest
                    .get("user")
                    .and_then(|u| u.get("username"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if owner != wanted {
                    continue;
                }
            }
            seen.push(path.clone());
            items.push(path);
        }
    }
    items
}

/// Source: `describe_user_backup` - what the restore screen lists.
pub fn describe_user_backup(backup_root: &str, backup_file: &str) -> serde_json::Value {
    let path = match user_backup_path(backup_root, backup_file) {
        Ok(p) => p,
        Err(_) => return serde_json::json!({ "backup_file": backup_file, "valid": false }),
    };
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut item = serde_json::json!({
        "backup_file": path.to_string_lossy(),
        "filename": filename,
        "size": size,
        "username": "",
        "generated_at": "",
        "websites": 0,
        "applications": 0,
        "valid": false,
        "source": "snpanel",
        "error": "",
    });
    match read_backup_manifest(backup_root, &path.to_string_lossy()) {
        Ok(manifest) => {
            let user = manifest.get("user");
            item["username"] = serde_json::Value::String(
                user.and_then(|u| u.get("username"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            item["generated_at"] = serde_json::Value::String(
                manifest
                    .get("generated_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            item["websites"] = serde_json::json!(manifest
                .get("websites")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0));
            item["applications"] = serde_json::json!(manifest
                .get("applications")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0));
            // Source: `RESTORABLE_BACKUP_KINDS` - two kinds, and anything
            // else is listed with the reason rather than hidden.
            let kind = manifest.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let valid = kind == "snpanel_user" || kind == "opanel_user";
            item["valid"] = serde_json::Value::Bool(valid);
            item["source"] = serde_json::Value::String(
                if kind == "opanel_user" {
                    "opanel"
                } else {
                    "snpanel"
                }
                .to_string(),
            );
            if !valid {
                item["error"] = serde_json::Value::String(
                    "This is not a snpanel or opanel user backup".to_string(),
                );
            }
        }
        Err(e) => {
            item["error"] = serde_json::Value::String(e.to_string());
        }
    }
    item
}

// --- writing an archive ----------------------------------------------------

/// Day names for [`NameStyle::Weekday`], Monday first as chrono counts.
const WEEKDAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];

/// Not in the Python: the name a user backup is written under.
///
/// `Timestamp` is the Python's `user-<name>-<UTC stamp>.tar.gz`, a new file
/// every run. The others are what a schedule may choose instead, and read
/// the clock the schedule's cron fields are read in - a schedule for 02:00
/// on Mondays writes `-monday`:
///
/// - `None`: `<name>.tar.gz`, replaced by every run;
/// - `Weekday`: `<name>-monday.tar.gz`, one per day of the week;
/// - `Date`: `<name>-2026-09-25.tar.gz`, one per day, kept to the
///   schedule's retention.
pub fn archive_name(
    username: &str,
    style: NameStyle,
    now: chrono::DateTime<chrono::Local>,
) -> String {
    use chrono::Datelike;
    match style {
        NameStyle::Timestamp => format!(
            "user-{username}-{}.tar.gz",
            now.with_timezone(&chrono::Utc).format("%Y%m%d%H%M%S")
        ),
        NameStyle::None => format!("{username}.tar.gz"),
        NameStyle::Weekday => format!(
            "{username}-{}.tar.gz",
            WEEKDAYS[now.weekday().num_days_from_monday() as usize]
        ),
        NameStyle::Date => format!("{username}-{}.tar.gz", now.format("%Y-%m-%d")),
    }
}

/// Whether `file_name` is one of the archives `style` names for `username`:
/// what a schedule's retention counts, and so all its prune may delete.
///
/// The four families never share a file, whatever the name - `user-` is
/// only the timestamped prefix, and the others are the name itself, a day
/// name or an ISO date after it.
fn in_family(file_name: &str, username: &str, style: NameStyle) -> bool {
    let Some(stem) = file_name.strip_suffix(".tar.gz") else {
        return false;
    };
    let suffix = || {
        stem.strip_prefix(username)
            .and_then(|rest| rest.strip_prefix('-'))
    };
    match style {
        NameStyle::Timestamp => stem
            .strip_prefix("user-")
            .and_then(|rest| rest.strip_prefix(username))
            .is_some_and(|rest| rest.starts_with('-')),
        NameStyle::None => stem == username,
        NameStyle::Weekday => suffix().is_some_and(|day| WEEKDAYS.contains(&day)),
        NameStyle::Date => suffix().is_some_and(|date| {
            date.len() == 10 && chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok()
        }),
    }
}

/// `datetime.utcnow().strftime("%Y%m%d%H%M%S")`.
pub fn stamp() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%S").to_string()
}

/// Add a whole directory to a tar under `arcname`, the way `tar.add` does.
///
/// Links are skipped, as they are everywhere else this codebase writes an
/// archive: a link in a customer's tree points at something the archive does
/// not necessarily hold, and one that points out of it is a way to make a
/// restore write where it should not.
fn add_tree<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    arcname: &str,
) -> std::io::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    if root.is_file() {
        return builder.append_path_with_name(root, arcname);
    }
    builder.append_dir(arcname, root)?;
    let mut stack = vec![(root.to_path_buf(), arcname.to_string())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries.flatten().collect(),
            // A directory the panel cannot read is skipped rather than
            // failing the whole archive: the rest of the site is still worth
            // backing up.
            Err(_) => continue,
        };
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let inner = format!("{prefix}/{name}");
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                builder.append_dir(&inner, &path)?;
                stack.push((path, inner));
            } else if meta.is_file() {
                builder.append_path_with_name(&path, &inner)?;
            }
        }
    }
    Ok(())
}

/// Everything a site backup writes, so the caller cannot swap two paths.
pub struct SiteBackup<'a> {
    pub backup_root: &'a str,
    pub domain: &'a str,
    pub root_path: &'a str,
    /// The database to dump beside the files, when the site has one.
    pub db_name: Option<&'a str>,
    pub dry_run: bool,
}

/// Source: `create_backup`.
///
/// The SQL dump is written **next to** the archive rather than inside a
/// temporary directory, and left there: that is the Python's behaviour and
/// what the restore's `database/` member is read back out of.
pub async fn create_backup(site: &SiteBackup<'_>) -> Result<String, BackupError> {
    let stamp = stamp();
    let backup_dir = Path::new(site.backup_root).join(site.domain);
    let archive = backup_dir.join(format!("{}-{stamp}.tar.gz", site.domain));
    let sql_file = backup_dir.join(format!("{}-{stamp}.sql", site.domain));
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| BackupError::Invalid(format!("Cannot make the backup directory: {e}")))?;

    if let Some(db_name) = site.db_name.filter(|name| !name.is_empty()) {
        crate::mariadb::export_database(db_name, &sql_file.to_string_lossy())
            .await
            .map_err(|e| BackupError::Invalid(e.to_string()))?;
        if site.dry_run && !sql_file.exists() {
            let _ = std::fs::write(
                &sql_file,
                format!("-- DRY RUN database dump for {db_name}\n"),
            );
        }
    }

    let file = std::fs::File::create(&archive)
        .map_err(|e| BackupError::Invalid(format!("Cannot write the archive: {e}")))?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    add_tree(&mut builder, Path::new(site.root_path), "site")
        .map_err(|e| BackupError::Invalid(format!("Cannot add the site files: {e}")))?;
    if sql_file.exists() {
        let name = sql_file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        builder
            .append_path_with_name(&sql_file, format!("database/{name}"))
            .map_err(|e| BackupError::Invalid(format!("Cannot add the database dump: {e}")))?;
    }
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .map_err(|e| BackupError::Invalid(format!("Cannot finish the archive: {e}")))?;
    Ok(archive.to_string_lossy().into_owned())
}

/// One site, as the manifest of a user backup records it.
///
/// Not the manifest entry itself: that is assembled from the same values
/// beside this, and a second copy here would be one that could drift.
pub struct ManifestSite {
    pub domain: String,
    pub root_path: String,
    /// The dump this site's database was written to, when it has one.
    pub sql_file: Option<PathBuf>,
}

/// Not in the Python: a database the user owns that no site entry carries -
/// one made on the Databases page, or a site's second - the same way.
pub struct ManifestDatabase {
    /// Where the dump goes in the archive: `databases/owned/...`.
    pub member: String,
    pub sql_file: PathBuf,
}

/// One application, the same way.
pub struct ManifestApp {
    pub name: String,
    /// The tar the helper exported, when it could.
    pub payload: Option<PathBuf>,
}

/// Source: `create_user_backup`, from the point where everything has been
/// collected.
///
/// The caller does the collecting because it needs the database, and this
/// does the writing because it needs none of it.
///
/// Not the Python's: the archive is written beside its name and renamed onto
/// it when complete. A name a schedule reuses - `alice.tar.gz` - is then
/// never a half-written file in place of last night's good one, and no name
/// is ever an archive that stopped halfway.
#[allow(clippy::too_many_arguments)]
pub fn write_user_backup(
    backup_root: &str,
    username: &str,
    file_name: &str,
    manifest: &serde_json::Value,
    sites: &[ManifestSite],
    databases: &[ManifestDatabase],
    apps: &[ManifestApp],
    staging: &Path,
) -> Result<String, BackupError> {
    let backup_dir = user_backup_dir(backup_root, username)?;
    if file_name.contains('/') || file_name.starts_with('.') || !file_name.ends_with(".tar.gz") {
        return Err(BackupError::Invalid("Invalid backup file name".into()));
    }
    std::fs::create_dir_all(&backup_dir)
        .map_err(|e| BackupError::Invalid(format!("Cannot make the backup directory: {e}")))?;
    let archive = backup_dir.join(file_name);
    // Unique, so two runs writing one name cannot share a partial file; and
    // not `*.tar.gz`, so no listing shows it.
    let partial = backup_dir.join(format!(
        ".{file_name}.{}-{}.partial",
        std::process::id(),
        crate::file_jobs::new_job_id()
    ));
    let written =
        write_archive(&partial, manifest, sites, databases, apps, staging).and_then(|()| {
            std::fs::rename(&partial, &archive)
                .map_err(|e| BackupError::Invalid(format!("Cannot write the archive: {e}")))
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    written.map(|()| archive.to_string_lossy().into_owned())
}

fn write_archive(
    archive: &Path,
    manifest: &serde_json::Value,
    sites: &[ManifestSite],
    databases: &[ManifestDatabase],
    apps: &[ManifestApp],
    staging: &Path,
) -> Result<(), BackupError> {
    // `json.dumps(manifest, ensure_ascii=True, indent=2)`.
    let text = serde_json::to_string_pretty(manifest)
        .map_err(|e| BackupError::Invalid(format!("Cannot write the manifest: {e}")))?;
    let manifest_path = staging.join(BACKUP_MANIFEST);
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&manifest_path, ascii_escape(&text))
        .map_err(|e| BackupError::Invalid(format!("Cannot write the manifest: {e}")))?;

    let file = std::fs::File::create(archive)
        .map_err(|e| BackupError::Invalid(format!("Cannot write the archive: {e}")))?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    builder
        .append_path_with_name(&manifest_path, BACKUP_MANIFEST)
        .map_err(|e| BackupError::Invalid(format!("Cannot add the manifest: {e}")))?;
    for site in sites {
        add_tree(
            &mut builder,
            Path::new(&site.root_path),
            &format!("sites/{}/site", site.domain),
        )
        .map_err(|e| BackupError::Invalid(format!("Cannot add {}: {e}", site.domain)))?;
        if let Some(sql) = site.sql_file.as_ref().filter(|path| path.exists()) {
            builder
                .append_path_with_name(sql, format!("databases/{}.sql", site.domain))
                .map_err(|e| BackupError::Invalid(format!("Cannot add the dump: {e}")))?;
        }
    }
    for database in databases.iter().filter(|db| db.sql_file.exists()) {
        builder
            .append_path_with_name(&database.sql_file, &database.member)
            .map_err(|e| BackupError::Invalid(format!("Cannot add the dump: {e}")))?;
    }
    for app in apps {
        if let Some(payload) = app.payload.as_ref().filter(|path| path.exists()) {
            builder
                .append_path_with_name(payload, format!("applications/{}.tar", app.name))
                .map_err(|e| BackupError::Invalid(format!("Cannot add {}: {e}", app.name)))?;
        }
    }
    builder
        .into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .map_err(|e| BackupError::Invalid(format!("Cannot finish the archive: {e}")))?;
    Ok(())
}

/// `json.dumps(..., ensure_ascii=True)` — every character above ASCII as a
/// `\uXXXX` escape.
///
/// `serde_json` always writes UTF-8, so this is applied afterwards. It matters
/// because the manifest is read by the Python side too, and a byte sequence
/// that is valid UTF-8 here but not there would be a file neither can open.
fn ascii_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii() {
            out.push(ch);
            continue;
        }
        let mut buffer = [0u16; 2];
        for unit in ch.encode_utf16(&mut buffer) {
            out.push_str(&format!("\\u{unit:04x}"));
        }
    }
    out
}

#[cfg(test)]
mod upload_tests {
    use super::*;
    /// A user backup directory with `count` archives whose names sort in the
    /// order they were taken.
    fn seeded(tag: &str, count: usize) -> (String, String) {
        let root = std::env::temp_dir().join(format!("bp-prune-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("users").join("acme");
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..count {
            // `user-acme-20260101020000.tar.gz`, ... — timestamped as the
            // real names are, so the lexicographic order is chronological,
            // which is the assumption the prune rests on.
            std::fs::write(
                dir.join(format!("user-acme-202601{:02}020000.tar.gz", i + 1)),
                b"x",
            )
            .unwrap();
        }
        (
            root.to_string_lossy().into_owned(),
            dir.to_string_lossy().into_owned(),
        )
    }

    fn names(dir: &str) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    /// **The oldest go, the newest stay.** Pruning the other way round would
    /// delete the customer's newest backups silently, and the first anybody
    /// would know is a restore from three months ago.
    #[test]
    fn pruning_keeps_the_newest_and_deletes_the_oldest() {
        let (root, dir) = seeded("order", 5);
        let removed = prune_user_backups(&root, "acme", NameStyle::Timestamp, 2, false).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(
            names(&dir),
            [
                "user-acme-20260104020000.tar.gz",
                "user-acme-20260105020000.tar.gz"
            ],
            "the wrong end of the list was deleted"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// There is no setting that means "delete everything".
    #[test]
    fn a_retention_of_zero_or_less_still_keeps_one() {
        for keep in [0, -1, -100] {
            let (root, dir) = seeded(&format!("zero{keep}"), 3);
            prune_user_backups(&root, "acme", NameStyle::Timestamp, keep, false).unwrap();
            assert_eq!(
                names(&dir),
                ["user-acme-20260103020000.tar.gz"],
                "keep={keep} removed everything"
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// Fewer archives than the retention is not an error and deletes
    /// nothing — the ordinary case for a new schedule.
    #[test]
    fn nothing_is_deleted_when_there_is_nothing_to_spare() {
        let (root, dir) = seeded("few", 2);
        assert_eq!(
            prune_user_backups(&root, "acme", NameStyle::Timestamp, 7, false).unwrap(),
            0
        );
        assert_eq!(names(&dir).len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A dry run reads as an empty listing on the Python side too, so it
    /// deletes nothing rather than deleting everything but the newest.
    #[test]
    fn a_dry_run_deletes_nothing() {
        let (root, dir) = seeded("dry", 5);
        assert_eq!(
            prune_user_backups(&root, "acme", NameStyle::Timestamp, 1, true).unwrap(),
            0
        );
        assert_eq!(names(&dir).len(), 5);
        let _ = std::fs::remove_dir_all(&root);
    }

    use serde_json::Value;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/backup_uploads.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the upload corpus"))
            .expect("the corpus parses")
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "backup-upload-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    /// Where a website's uploaded backup lands, for every filename.
    ///
    /// `Path(filename).name` throws away every directory component first,
    /// so `../../etc/x.tar.gz` becomes `x.tar.gz` and lands in the site's
    /// own folder — the escape never reaches the filesystem. And the
    /// extension test is **exact**: `.TAR.GZ` is refused, and so is
    /// `.tar.gz ` with a trailing space, because the name is not trimmed.
    #[test]
    fn a_site_backup_lands_where_python_puts_it() {
        let corpus = corpus();
        let cases = corpus["save_uploaded_backup"]
            .as_array()
            .expect("the cases");
        assert_eq!(cases.len(), 20, "the corpus changed size");
        let root = scratch("site");

        let mut failures: Vec<String> = Vec::new();
        let mut saved = 0usize;
        let mut refused = 0usize;
        for case in cases {
            let filename = case["filename"].as_str().unwrap_or("");
            let got = save_uploaded_backup(
                &root.to_string_lossy(),
                "site.example.com",
                filename,
                b"hello",
            );
            match (
                case.get("target").and_then(Value::as_str),
                case.get("error"),
            ) {
                (Some(want), _) => {
                    saved += 1;
                    let want_path = std::fs::canonicalize(&root)
                        .unwrap_or_else(|_| root.clone())
                        .join(want);
                    match got {
                        Ok(ref path) if std::path::Path::new(path) == want_path => {}
                        other => {
                            failures.push(format!("{filename:?}: python {want:?}, rust {other:?}"))
                        }
                    }
                }
                (None, Some(error)) => {
                    refused += 1;
                    let want = error.as_str().unwrap_or("");
                    match got {
                        Err(ref e) if e.to_string() == want => {}
                        other => {
                            failures.push(format!("{filename:?}: python {want:?}, rust {other:?}"))
                        }
                    }
                }
                _ => failures.push(format!("{filename:?}: the corpus says neither")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(saved >= 10, "only {saved} names saved");
        assert!(refused >= 7, "only {refused} names refused");

        // The site saver **overwrites**, which the restore saver does not.
        let first = save_uploaded_backup(&root.to_string_lossy(), "s.example", "x.tar.gz", b"aaa")
            .expect("the first");
        let second = save_uploaded_backup(&root.to_string_lossy(), "s.example", "x.tar.gz", b"bb")
            .expect("the second");
        assert_eq!(first, second, "a site backup is replaced in place");
        assert_eq!(
            std::fs::metadata(&second).map(|m| m.len()).unwrap_or(0),
            2,
            "the newer bytes won"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The restore folder, where a name that is taken is **not** replaced.
    ///
    /// These are archives an administrator uploads to restore other
    /// people's accounts, and two of them can easily share a filename.
    /// Replacing one with the other would restore the wrong customer, so
    /// the second gets a timestamp and six hex characters instead.
    #[test]
    fn a_restore_upload_never_replaces_one_that_is_there() {
        let corpus = corpus();
        let root = scratch("restore");
        let rootstr = root.to_string_lossy().into_owned();

        let first =
            save_uploaded_user_backup(&rootstr, "dup.tar.gz", b"a", "20260101000000", "abc123")
                .expect("the first");
        let second =
            save_uploaded_user_backup(&rootstr, "dup.tar.gz", b"b", "20260101000000", "abc123")
                .expect("the second");
        assert_ne!(first, second, "the second overwrote the first");
        assert!(std::path::Path::new(&first).exists(), "the first was lost");
        let name = std::path::Path::new(&second)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(name.ends_with(".tar.gz"), "{name}");
        assert!(name.starts_with("dup-"), "{name}");
        // Both land in the restore folder, not in the backup root: the root
        // holds one directory per site, and an archive loose in it would be
        // invisible to the listing that offers restores.
        let restore =
            std::fs::canonicalize(user_restore_dir(&rootstr)).expect("the restore folder exists");
        for path in [&first, &second] {
            assert_eq!(
                std::path::Path::new(path).parent(),
                Some(restore.as_path()),
                "{path} is not in the restore folder"
            );
        }
        // Which is the shape the Python produced.
        let want = corpus["collision"]["second_name"].as_str().unwrap_or("");
        assert!(
            want.starts_with("dup-") && want.ends_with(".tar.gz"),
            "{want}"
        );
        assert!(
            corpus["collision"]["first_survives"]
                .as_bool()
                .unwrap_or(false),
            "the Python kept the first too"
        );

        // And the name rules are the site saver's, refusal for refusal.
        for case in corpus["save_uploaded_user_backup"]
            .as_array()
            .expect("the cases")
        {
            let filename = case["filename"].as_str().unwrap_or("");
            let Some(error) = case.get("error").and_then(Value::as_str) else {
                continue;
            };
            let got = save_uploaded_user_backup(&rootstr, filename, b"x", "s", "n");
            match got {
                Err(ref e) if e.to_string() == error => {}
                other => panic!("{filename:?}: python {error:?}, rust {other:?}"),
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Deleting from the restore folder, and the surprise in it.
    ///
    /// **A relative name is not resolved against the backup root.**
    /// `Path(backup_file).resolve()` resolves against the *process working
    /// directory*, so `gone.tar.gz` is not found even when a file of that
    /// name is sitting in the restore folder. The panel always sends the
    /// absolute path it was given in the listing, so this is not a bug the
    /// page can hit — but a port that helpfully joined the root would
    /// accept names the Python refuses, which is a wider door than the one
    /// being replaced.
    #[test]
    fn deleting_a_restore_backup_needs_the_path_the_listing_gave() {
        let corpus = corpus();
        let root = scratch("delete");
        let rootstr = root.to_string_lossy().into_owned();
        let restore = user_restore_dir(&rootstr);
        std::fs::create_dir_all(&restore).expect("the restore folder");
        let inside = restore.join("gone.tar.gz");
        std::fs::write(&inside, b"x").expect("the fixture");
        let outside = root.join("elsewhere.tar.gz");
        std::fs::write(&outside, b"x").expect("the fixture");
        let nested = restore.join("deep");
        std::fs::create_dir_all(&nested).expect("the nested folder");
        std::fs::write(nested.join("deep.tar.gz"), b"x").expect("the fixture");

        // A bare name: refused, exactly as the Python refuses it.
        assert!(
            delete_user_restore_backup(&rootstr, "gone.tar.gz").is_err(),
            "a relative name was accepted"
        );
        assert!(inside.exists(), "the file was deleted by a relative name");
        // The absolute path the listing hands out: accepted, once.
        let deleted = delete_user_restore_backup(&rootstr, &inside.to_string_lossy())
            .expect("the absolute path");
        assert!(deleted.ends_with("gone.tar.gz"));
        assert!(!inside.exists());
        assert!(delete_user_restore_backup(&rootstr, &inside.to_string_lossy()).is_err());
        // Inside the backup root but outside the restore folder: refused,
        // and the file is still there.
        assert!(delete_user_restore_backup(&rootstr, &outside.to_string_lossy()).is_err());
        assert!(
            outside.exists(),
            "a file outside the restore folder was deleted"
        );
        // One directory deeper is also outside, because the check is on the
        // immediate parent.
        let deeper = nested.join("deep.tar.gz");
        assert!(delete_user_restore_backup(&rootstr, &deeper.to_string_lossy()).is_err());
        assert!(deeper.exists());

        // Every one of the Python's answers, for the record.
        let cases = corpus["delete_user_restore_backup"]
            .as_array()
            .expect("the cases");
        assert_eq!(cases.len(), 7, "the corpus changed size");
        let accepted = cases.iter().filter(|c| c.get("deleted").is_some()).count();
        assert_eq!(accepted, 1, "only the absolute path inside was accepted");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// One gigabyte, and the refusal is the customer's message.
    #[test]
    fn an_upload_over_the_limit_is_refused() {
        let corpus = corpus();
        assert_eq!(
            corpus["max_upload_bytes"].as_u64(),
            Some(MAX_UPLOAD_BYTES),
            "the limit changed"
        );
        assert_eq!(MAX_UPLOAD_BYTES, 1024 * 1024 * 1024);
        // Strictly greater: exactly a gigabyte is allowed, and one byte
        // more is not. The call sites cannot be exercised without holding a
        // gigabyte of bytes, which is why the comparison lives here.
        assert!(!over_upload_limit(0));
        assert!(!over_upload_limit(MAX_UPLOAD_BYTES - 1));
        assert!(!over_upload_limit(MAX_UPLOAD_BYTES));
        assert!(over_upload_limit(MAX_UPLOAD_BYTES + 1));
        assert!(over_upload_limit(u64::MAX));
    }
}

#[cfg(test)]
mod naming_tests {
    use super::*;
    use chrono::{Datelike, TimeZone};

    /// 02:00 on Monday 28 September 2026, local time.
    fn monday() -> chrono::DateTime<chrono::Local> {
        let now = chrono::Local
            .with_ymd_and_hms(2026, 9, 28, 2, 0, 0)
            .single()
            .unwrap();
        assert_eq!(now.weekday(), chrono::Weekday::Mon);
        now
    }

    #[test]
    fn each_style_names_the_archive_its_own_way() {
        let now = monday();
        assert_eq!(archive_name("alice", NameStyle::None, now), "alice.tar.gz");
        assert_eq!(
            archive_name("alice", NameStyle::Weekday, now),
            "alice-monday.tar.gz"
        );
        assert_eq!(
            archive_name("alice", NameStyle::Date, now),
            "alice-2026-09-28.tar.gz"
        );
        // The Python's, in UTC as its `utcnow()` is.
        assert_eq!(
            archive_name("alice", NameStyle::Timestamp, now),
            format!(
                "user-alice-{}.tar.gz",
                now.with_timezone(&chrono::Utc).format("%Y%m%d%H%M%S")
            )
        );
        let week: Vec<String> = (0..7)
            .map(|d| archive_name("a.b", NameStyle::Weekday, now + chrono::Duration::days(d)))
            .collect();
        assert_eq!(
            week,
            [
                "a.b-monday.tar.gz",
                "a.b-tuesday.tar.gz",
                "a.b-wednesday.tar.gz",
                "a.b-thursday.tar.gz",
                "a.b-friday.tar.gz",
                "a.b-saturday.tar.gz",
                "a.b-sunday.tar.gz",
            ]
        );
    }

    /// A prune deletes only its own family, so no name one style makes may
    /// be counted by another - whatever the account is called.
    #[test]
    fn the_families_never_share_a_file() {
        let now = monday();
        for username in [
            "alice",
            "user-bob",
            "acme-2026",
            "a.b_c-d",
            "monday",
            "user",
            "2026-09-28",
        ] {
            for made in NameStyle::ALL {
                let name = archive_name(username, made, now);
                for style in NameStyle::ALL {
                    assert_eq!(
                        in_family(&name, username, style),
                        style == made,
                        "{name} of {username} counted as {style:?}"
                    );
                }
            }
        }
        for (name, style) in [
            ("alice.tar", NameStyle::None),
            (".alice.tar.gz.1-x.partial", NameStyle::None),
            ("alice-2026-13-01.tar.gz", NameStyle::Date),
            ("alice-2026-9-28.tar.gz", NameStyle::Date),
            ("alice-funday.tar.gz", NameStyle::Weekday),
            ("user-alice2-20260101020000.tar.gz", NameStyle::Timestamp),
            ("user-alice.tar.gz", NameStyle::Timestamp),
        ] {
            assert!(
                !in_family(name, "alice", style),
                "{name} counted as {style:?}"
            );
        }
    }

    fn scratch(tag: &str) -> (String, PathBuf) {
        let root = std::env::temp_dir().join(format!("bp-naming-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("users").join("acme");
        std::fs::create_dir_all(&dir).unwrap();
        (root.to_string_lossy().into_owned(), dir)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn each_prune_counts_only_its_own_archives() {
        let (root, dir) = scratch("families");
        for name in [
            "user-acme-20260101020000.tar.gz",
            "user-acme-20260102020000.tar.gz",
            "user-acme-20260103020000.tar.gz",
            "acme.tar.gz",
            "acme-monday.tar.gz",
            "acme-tuesday.tar.gz",
            "acme-2026-01-01.tar.gz",
            "acme-2026-01-02.tar.gz",
            "acme-2026-01-03.tar.gz",
            "acme-2026-01-04.tar.gz",
        ] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        let prune = |style, keep| prune_user_backups(&root, "acme", style, keep, false).unwrap();
        assert_eq!(prune(NameStyle::None, 1), 0);
        assert_eq!(prune(NameStyle::Weekday, 1), 0);
        assert_eq!(prune(NameStyle::Timestamp, 1), 2);
        assert_eq!(prune(NameStyle::Date, 2), 2);
        assert_eq!(
            names(&dir),
            [
                "acme-2026-01-03.tar.gz",
                "acme-2026-01-04.tar.gz",
                "acme-monday.tar.gz",
                "acme-tuesday.tar.gz",
                "acme.tar.gz",
                "user-acme-20260103020000.tar.gz",
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn write(root: &str, name: &str, staging: &Path, n: i64) -> Result<String, BackupError> {
        let manifest = serde_json::json!({ "kind": "snpanel_user", "version": 1, "n": n });
        write_user_backup(root, "acme", name, &manifest, &[], &[], &[], staging)
    }

    /// A name a schedule reuses is replaced by the next archive whole, and
    /// nothing of the writing is left beside it.
    #[test]
    fn a_reused_name_is_replaced_whole() {
        let (root, dir) = scratch("replace");
        let staging = dir.join(".staging");
        std::fs::create_dir_all(&staging).unwrap();
        let first = write(&root, "acme.tar.gz", &staging, 1).unwrap();
        let second = write(&root, "acme.tar.gz", &staging, 2).unwrap();
        assert_eq!(first, second);
        assert_eq!(second, dir.join("acme.tar.gz").to_string_lossy());
        assert_eq!(names(&dir), [".staging", "acme.tar.gz"]);
        let manifest = read_backup_manifest(&root, &second).unwrap();
        assert_eq!(manifest["n"], 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_name_that_is_not_a_plain_archive_name_is_refused() {
        let (root, dir) = scratch("refused");
        let staging = dir.join(".staging");
        std::fs::create_dir_all(&staging).unwrap();
        for bad in ["../x.tar.gz", "a/b.tar.gz", ".hidden.tar.gz", "x.zip", ""] {
            assert!(
                write(&root, bad, &staging, 1).is_err(),
                "{bad:?} was written"
            );
        }
        assert_eq!(names(&dir), [".staging"]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
