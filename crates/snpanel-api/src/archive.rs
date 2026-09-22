//! What an uploaded archive is allowed to contain.
//!
//! Source: the archive half of `app/services/file_manager.py`.
//!
//! Every check here stands between a customer's upload and the rest of a
//! shared machine. A member called `../../etc/cron.d/x` writes outside the
//! site; a symlink member turns a later write into a write anywhere; a
//! member that claims to be a directory where a file already sits destroys
//! it. The scan also totals the **uncompressed** size, which is what the
//! quota is checked against — an archive that lies about that is a
//! disk-full for every site on the box.
//!
//! The extraction itself is the helper's `site-archive-extract`. This is
//! only the decision about whether to ask for it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Source: `MAX_ARCHIVE_ITEMS` — `_env_int("SNPANEL_MAX_ARCHIVE_ITEMS", …)`.
pub fn max_archive_items() -> u64 {
    env_int("SNPANEL_MAX_ARCHIVE_ITEMS", 1_000_000)
}

/// Source: `MAX_ARCHIVE_UNCOMPRESSED_BYTES`.
pub fn max_archive_uncompressed_bytes() -> u64 {
    env_int(
        "SNPANEL_MAX_ARCHIVE_UNCOMPRESSED_BYTES",
        100 * 1024 * 1024 * 1024,
    )
}

fn env_int(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// Source: `_clean_relative_path`.
///
/// Backslashes become slashes first, so a Windows-made archive cannot use
/// them to smuggle a separator past the `..` check. A leading slash and a
/// colon in the **first** segment are both "escapes the website root": the
/// second is the drive letter in `C:/x`, which `Path` on Linux would
/// otherwise treat as an ordinary directory name.
pub fn clean_relative_path(path: &str) -> Result<String, String> {
    if path.contains('\0') {
        return Err("Invalid path".to_string());
    }
    let normalized = path.replace('\\', "/");
    let first_segment = normalized.split('/').next().unwrap_or("");
    if normalized.starts_with('/') || first_segment.contains(':') {
        return Err("Path escapes website root".to_string());
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err("Path escapes website root".to_string());
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

/// Source: `_validate_archive_destination`.
///
/// The cleaned path is joined to the destination and **resolved**, then
/// checked to be the destination or below it. Resolving is what catches a
/// member whose parent is a symlink out of the tree — the name alone looks
/// harmless.
pub fn validate_archive_destination(base: &Path, member_name: &str) -> Result<PathBuf, String> {
    let clean = clean_relative_path(member_name)?;
    if clean.is_empty() {
        return Err("Invalid archive member path".to_string());
    }
    let joined = base.join(&clean);
    let target = resolve(&joined);
    let base = resolve(base);
    if base != target && !target.starts_with(&base) {
        return Err("Archive contains unsafe paths".to_string());
    }
    Ok(target)
}

/// `Path.resolve()` — the real path where it exists, lexically normalised
/// where it does not.
///
/// `std::fs::canonicalize` fails on a path that is not there yet, and every
/// member of an archive is by definition not there yet. Python resolves the
/// longest existing prefix and appends the rest, which is what this does.
fn resolve(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    while let Some(parent) = current.parent().map(Path::to_path_buf) {
        let Some(name) = current.file_name().map(std::ffi::OsStr::to_os_string) else {
            break;
        };
        rest.push(name);
        if let Ok(real) = std::fs::canonicalize(&parent) {
            let mut out = real;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        current = parent;
    }
    path.to_path_buf()
}

/// Source: `_get_implied_dirs`.
///
/// Every prefix of every member name, whether or not the archive carries an
/// entry for it. An archive holding only `x/y/z.txt` still creates `x` and
/// `x/y`, and without this they would be counted as files.
pub fn implied_dirs(names: &[String]) -> BTreeSet<String> {
    let mut implied = BTreeSet::new();
    for name in names {
        let normalized = name.replace('\\', "/");
        let parts: Vec<&str> = normalized.split('/').collect();
        for i in 1..parts.len() {
            implied.insert(parts[..i].join("/"));
        }
    }
    implied
}

/// Source: `_zip_info_is_dir`.
///
/// **Three ways to be a directory**, and an archiver may use any of them:
/// the trailing slash, the mode bits with a zero size, or being the implied
/// parent of another member. `zip` on Linux writes directory entries
/// without the slash, so the first test alone misses them and the extractor
/// would try to write a file there.
pub fn zip_info_is_dir(name: &str, size: u64, mode: u32, implied: &BTreeSet<String>) -> bool {
    let normalized = name.replace('\\', "/");
    if normalized.ends_with('/') {
        return true;
    }
    if mode & 0o170000 == 0o040000 && size == 0 {
        return true;
    }
    // The implied-parent test also needs a zero size: a *file* called `x`
    // in an archive that also holds `x/y.txt` is a broken archive either
    // way, but a non-empty one is not silently turned into a directory.
    size == 0 && implied.contains(normalized.trim_end_matches('/'))
}

/// One zip member, as the scan needs it.
pub struct ZipEntry {
    pub name: String,
    pub size: u64,
    /// `ZipFile::unix_mode()`, which is `external_attr >> 16` for an archive
    /// made on a unix host and `None` otherwise — zero here, which is what
    /// Python's `(external_attr >> 16) & 0o170000` also yields for one.
    pub mode: u32,
}

/// Source: `_zip_uncompressed_size`.
///
/// The count is the **loop index**, not the number of members kept: an
/// archive of a million directories is still too many files. And the size
/// is checked as it accumulates rather than at the end, so a zip bomb is
/// refused partway through the header scan rather than after it.
pub fn zip_uncompressed_size(
    entries: &[ZipEntry],
    destination: &Path,
    archive_file: &Path,
    implied: &BTreeSet<String>,
) -> Result<u64, String> {
    let max_items = max_archive_items();
    let max_bytes = max_archive_uncompressed_bytes();
    let archive_real = resolve(archive_file);
    let mut total = 0u64;
    for (index, entry) in entries.iter().enumerate() {
        if index as u64 >= max_items {
            return Err(format!("Archive has too many files (limit {max_items})"));
        }
        if entry.mode & 0o170000 == 0o120000 {
            return Err("Archive symlinks are not allowed".to_string());
        }
        let target = validate_archive_destination(destination, &entry.name)?;
        // An archive that contains itself is skipped rather than refused:
        // it is what happens when somebody zips the directory they are
        // standing in, and refusing would be a puzzle to debug.
        if target == archive_real {
            continue;
        }
        if is_symlink(&target) {
            return Err("Refusing to overwrite a symlink".to_string());
        }
        if zip_info_is_dir(&entry.name, entry.size, entry.mode, implied) {
            if target.exists() && !target.is_dir() {
                // An empty file is treated as nothing and overwritten; a
                // file with content is not, because the directory would
                // destroy it.
                match std::fs::metadata(&target) {
                    Ok(meta) if meta.len() == 0 => {}
                    _ => {
                        return Err("Archive directory conflicts with an existing file".to_string())
                    }
                }
            }
            continue;
        }
        if target.is_dir() {
            return Err("Archive file conflicts with an existing directory".to_string());
        }
        // `_assert_write_allowed` sits here in the Python and is a no-op on
        // this path: `extract_archive` is the only caller and it passes
        // `allow_executable=True`. The rule it would apply — no `.php`, no
        // `.htaccess` — is enforced on the single-file write endpoints, not
        // on an upload the customer is unpacking into their own tree.
        total += entry.size;
        if total > max_bytes {
            return Err("Archive is too large".to_string());
        }
    }
    Ok(total)
}

/// What a tar member is, which decides whether it may be unpacked at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TarKind {
    File,
    Dir,
    LinkOrDevice,
    Other,
}

/// One tar member, as the scan needs it.
pub struct TarEntry {
    pub name: String,
    pub size: u64,
    pub kind: TarKind,
}

/// Source: `_tar_uncompressed_size`.
///
/// Stricter than the zip scan in one way that matters: tar can carry a
/// hard link, a FIFO and a device node, and **all** of them are refused
/// rather than only symlinks. A device node unpacked into a customer's
/// tree with the helper's privileges is a hole nothing else here would
/// catch.
pub fn tar_uncompressed_size(
    entries: &[TarEntry],
    destination: &Path,
    archive_file: &Path,
) -> Result<u64, String> {
    let max_items = max_archive_items();
    let max_bytes = max_archive_uncompressed_bytes();
    let archive_real = resolve(archive_file);
    let mut total = 0u64;
    for (index, entry) in entries.iter().enumerate() {
        if index as u64 >= max_items {
            return Err(format!("Archive has too many files (limit {max_items})"));
        }
        if entry.kind == TarKind::LinkOrDevice {
            return Err("Archive links and devices are not allowed".to_string());
        }
        let target = validate_archive_destination(destination, &entry.name)?;
        if target == archive_real {
            continue;
        }
        if is_symlink(&target) {
            return Err("Refusing to overwrite a symlink".to_string());
        }
        if entry.kind == TarKind::Dir {
            if target.exists() && !target.is_dir() {
                return Err("Archive directory conflicts with an existing file".to_string());
            }
            continue;
        }
        if entry.kind != TarKind::File {
            return Err("Archive contains unsupported entries".to_string());
        }
        if target.is_dir() {
            return Err("Archive file conflicts with an existing directory".to_string());
        }
        total += entry.size;
        if total > max_bytes {
            return Err("Archive is too large".to_string());
        }
    }
    Ok(total)
}

/// `target.exists() and target.is_symlink()`.
///
/// Both halves: a **broken** symlink does not exist as far as Python is
/// concerned, and the Python's check therefore lets it through here — the
/// resolve in `validate_archive_destination` is what deals with it.
fn is_symlink(target: &Path) -> bool {
    std::fs::symlink_metadata(target).is_ok_and(|meta| meta.file_type().is_symlink())
        && target.exists()
}

/// Read a zip's directory, or say it is unreadable.
///
/// Source: `with zipfile.ZipFile(archive_file) as _: pass`, and then the
/// `infolist()` the scan walks. Opening is what tells a corrupt upload from
/// a dangerous one — the customer is told immediately rather than watching
/// a job card fail with nothing to act on.
pub fn read_zip_entries(path: &Path) -> Result<Vec<ZipEntry>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let member = archive.by_index(index).map_err(|e| e.to_string())?;
        entries.push(ZipEntry {
            name: member.name().to_string(),
            size: member.size(),
            mode: member.unix_mode().unwrap_or(0),
        });
    }
    Ok(entries)
}

/// Read a gzipped tar's members, or say it is unreadable.
///
/// Source: `with tarfile.open(archive_file, "r:gz") as _: pass`. Only
/// `r:gz` — a `.tar.gz` that is not actually gzipped is a corrupt archive
/// here, as it is there, rather than being quietly read as a plain tar.
pub fn read_tar_entries(path: &Path) -> Result<Vec<TarEntry>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let reader = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(reader);
    let mut entries = Vec::new();
    for member in archive.entries().map_err(|e| e.to_string())? {
        let member = member.map_err(|e| e.to_string())?;
        let kind = member.header().entry_type();
        entries.push(TarEntry {
            name: member
                .path()
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .into_owned(),
            size: member.size(),
            kind: if kind.is_dir() {
                TarKind::Dir
            } else if kind.is_symlink()
                || kind.is_hard_link()
                || kind.is_fifo()
                || kind.is_block_special()
                || kind.is_character_special()
            {
                TarKind::LinkOrDevice
            } else if kind.is_file() {
                TarKind::File
            } else {
                TarKind::Other
            },
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The limits come from the environment, which is one per process, so
    /// the tests that read them take turns. Without this the limits test
    /// lowers the ceiling under whichever other test is running and that
    /// one fails as though the port were wrong.
    fn serialise() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/archive_extract.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the archive corpus"))
            .expect("the corpus parses")
    }

    fn decode(case: &Value, key: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(case[key].as_str().expect("the archive"))
            .expect("valid base64")
    }

    /// A directory nothing else in the test owns.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("archive-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    /// Read the archive the way the handler reads it.
    ///
    /// Deliberately **not** a second copy of the reader: an earlier version
    /// of these tests classified each member itself, so breaking
    /// `read_tar_entries` — which is what decides whether a hard link or a
    /// device node reaches the scan at all — changed nothing they could
    /// see.
    fn zip_entries(path: &Path) -> Vec<ZipEntry> {
        read_zip_entries(path).expect("a readable zip")
    }

    /// What the path cleaner makes of a member name, or what it refuses.
    ///
    /// The colon test is the one a reading of the code skips over: it
    /// applies to the **first segment only**, because that is where a
    /// Windows drive letter is. `a/b:c.txt` is an ordinary (if odd) file
    /// name on Linux and is allowed through.
    #[test]
    fn a_member_name_is_cleaned_the_way_python_cleans_it() {
        let _lock = serialise();
        let corpus = corpus();
        let cases = corpus["clean_relative_path"].as_array().expect("the cases");
        assert_eq!(cases.len(), 29, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut cleaned = 0usize;
        let mut refused = 0usize;
        for case in cases {
            let name = case["name"].as_str().unwrap_or("");
            let got = clean_relative_path(name);
            match (case.get("clean").and_then(Value::as_str), case.get("error")) {
                (Some(want), _) => {
                    cleaned += 1;
                    match got {
                        Ok(ref value) if value == want => {}
                        other => {
                            failures.push(format!("{name:?}: python {want:?}, rust {other:?}"))
                        }
                    }
                }
                (None, Some(error)) => {
                    refused += 1;
                    let want = error.as_str().unwrap_or("");
                    match got {
                        Err(ref value) if value == want => {}
                        other => {
                            failures.push(format!("{name:?}: python {want:?}, rust {other:?}"))
                        }
                    }
                }
                _ => failures.push(format!("{name:?}: the corpus says neither")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(cleaned >= 14, "only {cleaned} names cleaned");
        assert!(refused >= 8, "only {refused} names refused");
    }

    /// Every archive the real file manager was asked about.
    ///
    /// The archives travel as bytes, so what is compared is the Rust zip
    /// reader's view of the same file — not a description of it that could
    /// agree with the Python while the reader disagreed.
    #[test]
    fn a_zip_is_scanned_the_way_python_scans_it() {
        let _lock = serialise();
        let corpus = corpus();
        let cases = corpus["zip"].as_array().expect("the zips");
        assert_eq!(cases.len(), 23, "the corpus changed size");
        let dir = scratch("zip");
        let destination = dir.join("dest");
        std::fs::create_dir_all(&destination).expect("the destination");

        let mut failures: Vec<String> = Vec::new();
        let mut accepted = 0usize;
        let mut distinct_errors = std::collections::BTreeSet::new();
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let bytes = decode(case, "zip_base64");
            let archive_file = dir.join("in.zip");
            std::fs::write(&archive_file, &bytes).expect("the fixture");
            let entries = zip_entries(&archive_file);

            // The reader agrees with Python about what is in the file.
            let want_entries = case["entries"].as_array().expect("the entries");
            if entries.len() != want_entries.len() {
                failures.push(format!(
                    "{label}: python {} entries, rust {}",
                    want_entries.len(),
                    entries.len()
                ));
                continue;
            }
            let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
            let implied = implied_dirs(&names);
            let want_implied: Vec<&str> = case["implied_dirs"]
                .as_array()
                .expect("the implied dirs")
                .iter()
                .map(|v| v.as_str().unwrap_or(""))
                .collect();
            let got_implied: Vec<&str> = implied.iter().map(String::as_str).collect();
            if got_implied != want_implied {
                failures.push(format!(
                    "{label} implied: python {want_implied:?}, rust {got_implied:?}"
                ));
            }
            for (entry, want) in entries.iter().zip(want_entries) {
                let got_dir = zip_info_is_dir(&entry.name, entry.size, entry.mode, &implied);
                if Some(got_dir) != want["is_dir"].as_bool() {
                    failures.push(format!(
                        "{label} /{:?} is_dir: python {}, rust {got_dir}",
                        entry.name, want["is_dir"]
                    ));
                }
                if Some(entry.size) != want["size"].as_u64() {
                    failures.push(format!(
                        "{label} /{:?} size: python {}, rust {}",
                        entry.name, want["size"], entry.size
                    ));
                }
            }

            let got = zip_uncompressed_size(&entries, &destination, &archive_file, &implied);
            match (case.get("total").and_then(Value::as_u64), case.get("error")) {
                (Some(want), _) => {
                    accepted += 1;
                    match got {
                        Ok(value) if value == want => {}
                        other => failures.push(format!("{label}: python {want}, rust {other:?}")),
                    }
                }
                (None, Some(error)) => {
                    let want = error.as_str().unwrap_or("");
                    distinct_errors.insert(want.to_string());
                    match got {
                        Err(ref value) if value == want => {}
                        other => failures.push(format!("{label}: python {want:?}, rust {other:?}")),
                    }
                }
                _ => failures.push(format!("{label}: the corpus says neither")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(accepted >= 12, "only {accepted} archives accepted");
        // Three distinct refusals on this set, each a different way out of
        // the tree. The conflict messages come from the separate fixture
        // with something already in the destination.
        assert_eq!(distinct_errors.len(), 3, "{distinct_errors:?}");
        assert!(distinct_errors.contains("Archive symlinks are not allowed"));
        assert!(distinct_errors.contains("Path escapes website root"));
        assert!(distinct_errors.contains("Invalid archive member path"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The tar scan, which refuses more than the zip scan does.
    #[test]
    fn a_tar_is_scanned_the_way_python_scans_it() {
        let _lock = serialise();
        let corpus = corpus();
        let cases = corpus["tar"].as_array().expect("the tars");
        assert_eq!(cases.len(), 10, "the corpus changed size");
        let dir = scratch("tar");
        let destination = dir.join("dest");
        std::fs::create_dir_all(&destination).expect("the destination");

        let mut failures: Vec<String> = Vec::new();
        let mut refused_links = 0usize;
        let mut refused_unknown = 0usize;
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let archive_file = dir.join("in.tar.gz");
            std::fs::write(&archive_file, decode(case, "tar_base64")).expect("the fixture");

            let entries = read_tar_entries(&archive_file).expect("a readable tar");

            let want_entries = case["entries"].as_array().expect("the entries");
            if entries.len() != want_entries.len() {
                failures.push(format!(
                    "{label}: python {} members, rust {}",
                    want_entries.len(),
                    entries.len()
                ));
                continue;
            }

            let got = tar_uncompressed_size(&entries, &destination, &archive_file);
            match (case.get("total").and_then(Value::as_u64), case.get("error")) {
                (Some(want), _) => match got {
                    Ok(value) if value == want => {}
                    other => failures.push(format!("{label}: python {want}, rust {other:?}")),
                },
                (None, Some(error)) => {
                    let want = error.as_str().unwrap_or("");
                    if want == "Archive links and devices are not allowed" {
                        refused_links += 1;
                    }
                    if want == "Archive contains unsupported entries" {
                        refused_unknown += 1;
                    }
                    match got {
                        Err(ref value) if value == want => {}
                        other => failures.push(format!("{label}: python {want:?}, rust {other:?}")),
                    }
                }
                _ => failures.push(format!("{label}: the corpus says neither")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // A symlink, a hard link, a FIFO and a character device: tar can
        // carry all four and none of them may be unpacked with the helper's
        // privileges into a customer's tree.
        assert_eq!(
            refused_links, 4,
            "only {refused_links} link/device refusals"
        );
        // And a typeflag that is none of those is refused separately, which
        // is the only way into that branch: every ordinary tar type is a
        // file, a directory, a link or a device.
        assert_eq!(refused_unknown, 1, "the unknown typeflag was not refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What happens when the destination already holds something.
    ///
    /// The last case is the one worth reading twice: overwriting a symlink
    /// is refused as **"Archive contains unsafe paths"**, not as "Refusing
    /// to overwrite a symlink", because resolving the target follows the
    /// link out of the tree and the earlier check fires first. A port that
    /// produced the later message would still be safe — and would still be
    /// a different answer on the customer's screen.
    #[test]
    fn an_existing_file_decides_what_may_be_unpacked_over_it() {
        let _lock = serialise();
        let corpus = corpus();
        let cases = corpus["conflicts"].as_array().expect("the conflicts");
        assert_eq!(cases.len(), 5, "the corpus changed size");
        let dir = scratch("conflict");
        let busy = dir.join("busy");
        std::fs::create_dir_all(&busy).expect("the destination");
        std::fs::write(busy.join("a.txt"), b"existing").expect("a.txt");
        std::fs::write(busy.join("d"), b"a file where a directory wants to be").expect("d");
        std::fs::write(busy.join("empty"), b"").expect("empty");
        std::fs::create_dir(busy.join("adir")).expect("adir");
        std::os::unix::fs::symlink("/etc/passwd", busy.join("slink")).expect("slink");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let bytes = decode(case, "zip_base64");
            let archive_file = dir.join("conflict.zip");
            std::fs::write(&archive_file, &bytes).expect("the fixture");
            let entries = zip_entries(&archive_file);
            let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
            let implied = implied_dirs(&names);
            let got = zip_uncompressed_size(&entries, &busy, &archive_file, &implied);
            match (case.get("total").and_then(Value::as_u64), case.get("error")) {
                (Some(want), _) => match got {
                    Ok(value) if value == want => {}
                    other => failures.push(format!("{label}: python {want}, rust {other:?}")),
                },
                (None, Some(error)) => {
                    let want = error.as_str().unwrap_or("");
                    match got {
                        Err(ref value) if value == want => {}
                        other => failures.push(format!("{label}: python {want:?}, rust {other:?}")),
                    }
                }
                _ => failures.push(format!("{label}: the corpus says neither")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two limits, which are read from the environment.
    #[test]
    fn the_limits_are_the_pythons_and_can_be_lowered() {
        let _lock = serialise();
        let corpus = corpus();
        assert_eq!(
            corpus["limits"]["max_items"].as_u64(),
            Some(max_archive_items())
        );
        assert_eq!(
            corpus["limits"]["max_uncompressed_bytes"].as_u64(),
            Some(max_archive_uncompressed_bytes())
        );

        let _env = crate::testenv::EnvGuard::set(&[
            ("SNPANEL_MAX_ARCHIVE_ITEMS", "2"),
            ("SNPANEL_MAX_ARCHIVE_UNCOMPRESSED_BYTES", "4"),
        ]);
        assert_eq!(max_archive_items(), 2);
        assert_eq!(max_archive_uncompressed_bytes(), 4);

        let dir = scratch("limits");
        let destination = dir.join("dest");
        std::fs::create_dir_all(&destination).expect("the destination");
        let archive_file = dir.join("none.zip");
        let entry = |name: &str, size: u64| ZipEntry {
            name: name.to_string(),
            size,
            mode: 0o100644,
        };
        let implied = BTreeSet::new();

        // The count is the loop index, so the third member is refused
        // whatever it is.
        let three = [entry("a", 1), entry("b", 1), entry("c", 1)];
        assert_eq!(
            zip_uncompressed_size(&three, &destination, &archive_file, &implied),
            Err("Archive has too many files (limit 2)".to_string())
        );
        // And the size is checked as it accumulates: two members of three
        // bytes each is refused on the second, not after the whole scan.
        let big = [entry("a", 3), entry("b", 3)];
        assert_eq!(
            zip_uncompressed_size(&big, &destination, &archive_file, &implied),
            Err("Archive is too large".to_string())
        );
        // Exactly at each limit is allowed.
        let fits = [entry("a", 2), entry("b", 2)];
        assert_eq!(
            zip_uncompressed_size(&fits, &destination, &archive_file, &implied),
            Ok(4)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
