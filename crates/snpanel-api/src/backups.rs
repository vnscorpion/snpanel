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
