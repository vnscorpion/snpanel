//! The file manager's path safety.
//!
//! Source: `app.services.file_manager`. These two functions decide whether a
//! customer's file manager can reach outside their own site, and everything
//! else in that module is built on them - so a port that is subtly wrong here
//! is a directory traversal with a nice interface.
//!
//! `safe_path` is not a pure function. It walks the filesystem and refuses a
//! symlink anywhere along the path, which is why its tests run against a real
//! tree with real symlinks rather than a table of strings.
//!
//! Plan §8 Stage C.

use std::path::{Component, Path, PathBuf};

/// Source: every `raise ValueError` in the module, kept as its own type so a
/// caller cannot confuse "the customer asked for something impossible" with
/// "something went wrong".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError(pub String);

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PathError {}

fn refuse<T>(message: &str) -> Result<T, PathError> {
    Err(PathError(message.to_string()))
}

/// Source: `BLOCKED_WRITE_SUFFIXES`, `BLOCKED_WRITE_NAMES`,
/// `SENSITIVE_READ_NAMES` - all three are empty sets, and the comment above
/// them says why: "Website ownership is the permission boundary. End users
/// must be able to deploy real web sources, including PHP, .htaccess, .env,
/// and wp-config.php."
///
/// They are kept as empty constants rather than dropped, because the checks
/// that consult them are real code paths that a future policy would fill in,
/// and a port that removed them would hide that the hook exists.
pub const BLOCKED_WRITE_NAMES: &[&str] = &[];
pub const BLOCKED_WRITE_SUFFIXES: &[&str] = &[];
pub const SENSITIVE_READ_NAMES: &[&str] = &[];

/// Source: `_assert_write_allowed`.
pub fn assert_write_allowed(
    path: &Path,
    action: &str,
    allow_executable: bool,
) -> Result<(), PathError> {
    if allow_executable {
        return Ok(());
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if BLOCKED_WRITE_NAMES.contains(&name.as_str()) {
        return refuse(&format!("{action} {name} requires admin permissions"));
    }
    let suffix = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if BLOCKED_WRITE_SUFFIXES.contains(&suffix.as_str()) {
        return refuse(&format!(
            "{action} executable files requires admin permissions"
        ));
    }
    Ok(())
}

/// Source: `_assert_sensitive_read_allowed`.
pub fn assert_sensitive_read_allowed(
    path: &Path,
    action: &str,
    allow_sensitive: bool,
) -> Result<(), PathError> {
    if allow_sensitive {
        return Ok(());
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if SENSITIVE_READ_NAMES.contains(&name.as_str()) {
        return refuse(&format!("{action} {name} requires admin permissions"));
    }
    Ok(())
}

/// Source: `_safe_upload_name`.
pub fn safe_upload_name(filename: &str) -> Result<String, PathError> {
    let name = filename
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
        return refuse("Invalid filename");
    }
    Ok(name)
}

/// Source: `_safe_entry_name`.
pub fn safe_entry_name(name: &str) -> Result<String, PathError> {
    let safe = safe_upload_name(name)?;
    if safe == "/" || safe == "\\" {
        return refuse("Invalid filename");
    }
    Ok(safe)
}

/// Source: `_clean_relative_path`.
///
/// Note what it does *not* do: `....` is not `..`, and a name with spaces
/// keeps them. The corpus pins both, because a port that "tidied" either
/// would refuse paths the panel has always accepted.
// Not called yet: its callers in the Python are the upload and archive
// endpoints, which are a later batch. It is here now, and tested against the
// Python's own verdicts, because it is half of the pair that keeps the file
// manager inside a customer's site and porting it apart from `safe_path`
// would mean generating the corpus twice.
#[allow(dead_code)]
pub fn clean_relative_path(path: &str) -> Result<String, PathError> {
    if path.contains('\0') {
        return refuse("Invalid path");
    }
    let normalized = path.replace('\\', "/");
    // `":" in normalized.split("/", 1)[0]` - a drive letter, or anything else
    // with a colon in the first segment.
    let first = normalized.split('/').next().unwrap_or("");
    if normalized.starts_with('/') || first.contains(':') {
        return refuse("Path escapes website root");
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return refuse("Path escapes website root");
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

/// Source: `_safe_path`.
///
/// Resolve a relative path under the website root and refuse anything that
/// escapes it - through `..`, through an absolute path, or through a symlink
/// anywhere along the way.
///
/// `allow_leaf_symlink` exists for deletion: a Laravel-style `public/storage`
/// has to be unlinkable without being followed. It returns the link itself,
/// unresolved, and it applies **only** to the final component - so
/// `link/inside` is still refused even when `link` alone would be allowed.
pub fn safe_path(
    root_path: &str,
    relative_path: &str,
    allow_leaf_symlink: bool,
) -> Result<PathBuf, PathError> {
    if relative_path.contains('\0') {
        return refuse("Invalid path");
    }
    let root = match std::fs::canonicalize(root_path) {
        Ok(r) => r,
        Err(_) => return refuse("Website root not found"),
    };

    // `(relative_path or "").lstrip("/").lstrip("\\")` - every leading slash,
    // then every leading backslash. Not both interleaved, which is what a
    // single `trim_start_matches(['/', '\\'])` would do.
    let rel = relative_path
        .trim_start_matches('/')
        .trim_start_matches('\\');

    let candidate = if rel.is_empty() {
        root.clone()
    } else {
        root.join(rel)
    };

    let mut accumulated = root.clone();
    if candidate != root {
        // `candidate.relative_to(root)` is lexical, and `candidate` was built
        // by joining onto `root`, so it succeeds; the `..` it may contain is
        // caught by the loop rather than by resolving first.
        let Ok(relative) = candidate.strip_prefix(&root) else {
            let resolved = resolve(&candidate);
            if resolved != root && !resolved.starts_with(&root) {
                return refuse("Path escapes website root");
            }
            return Ok(resolved);
        };
        let parts: Vec<Component<'_>> = relative.components().collect();
        for (index, part) in parts.iter().enumerate() {
            match part {
                Component::ParentDir | Component::CurDir => {
                    return refuse("Path escapes website root")
                }
                other => accumulated.push(other.as_os_str()),
            }
            if is_symlink(&accumulated) {
                if allow_leaf_symlink && index == parts.len() - 1 {
                    return Ok(accumulated);
                }
                return refuse("Symlinks are not allowed");
            }
        }
    }

    let target = resolve(&accumulated);
    if target != root && !target.starts_with(&root) {
        return refuse("Path escapes website root");
    }
    Ok(target)
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// `Path.resolve()` with `strict=False`: the longest existing prefix made
/// real, the rest applied lexically.
/// `Path.resolve(strict=False)`: symlinks resolved where the path exists,
/// the rest normalised lexically.
pub(crate) fn resolve(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path.to_path_buf();
    while let (Some(parent), Some(name)) = (
        cursor.parent().map(Path::to_path_buf),
        cursor.file_name().map(|n| n.to_os_string()),
    ) {
        tail.push(name);
        if let Ok(real) = std::fs::canonicalize(&parent) {
            let mut out = real;
            for n in tail.iter().rev() {
                out.push(n);
            }
            return lexical(&out);
        }
        if parent.as_os_str().is_empty() {
            break;
        }
        cursor = parent;
    }
    lexical(path)
}

fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// the operations the file manager screens call
// ---------------------------------------------------------------------------

/// Source: `MAX_TEXT_FILE_BYTES`.
pub const MAX_TEXT_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Source: `_relative_to_root`.
fn relative_to_root(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

/// Source: `_entry_info`.
fn entry_info(root: &Path, item: &Path) -> Option<serde_json::Value> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(item).ok()?;
    let modified = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(serde_json::json!({
        "name": item.file_name()?.to_string_lossy(),
        "path": relative_to_root(root, item),
        "is_dir": meta.is_dir(),
        "size": meta.len(),
        "modified": modified,
        // `f"{stat.S_IMODE(mode):03o}"` - the twelve permission bits, at
        // least three digits. A setgid directory prints as four.
        "mode": format!("{:03o}", meta.permissions().mode() & 0o7777),
    }))
}

/// Source: `list_files`.
///
/// A path that is not a directory is an empty listing rather than an error,
/// which is what the screen wants when a customer deletes the folder they
/// were looking at.
pub fn list_files(
    root_path: &str,
    relative_path: &str,
) -> Result<Vec<serde_json::Value>, PathError> {
    let target = safe_path(root_path, relative_path, false)?;
    if !target.is_dir() {
        return Ok(Vec::new());
    }
    let root =
        std::fs::canonicalize(root_path).map_err(|_| PathError("Website root not found".into()))?;
    let Ok(entries) = std::fs::read_dir(&target) else {
        return Ok(Vec::new());
    };
    let mut items: Vec<serde_json::Value> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // Symlinks are hidden rather than followed.
        if std::fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            continue;
        }
        if let Some(info) = entry_info(&root, &path) {
            items.push(info);
        }
    }
    items.sort_by(|a, b| {
        let dir_a = !a["is_dir"].as_bool().unwrap_or(false);
        let dir_b = !b["is_dir"].as_bool().unwrap_or(false);
        let name_a = a["name"].as_str().unwrap_or("").to_lowercase();
        let name_b = b["name"].as_str().unwrap_or("").to_lowercase();
        (dir_a, name_a).cmp(&(dir_b, name_b))
    });
    Ok(items)
}

/// Source: `download_file_path`.
pub fn download_file_path(
    root_path: &str,
    relative_path: &str,
    allow_sensitive: bool,
) -> Result<PathBuf, PathError> {
    let target = safe_path(root_path, relative_path, false)?;
    if !target.is_file() {
        return refuse("File not found");
    }
    if is_symlink(&target) {
        return refuse("Symlinks are not allowed");
    }
    assert_sensitive_read_allowed(&target, "Downloading", allow_sensitive)?;
    Ok(target)
}

/// The checks `read_text_file` makes before it reads anything.
///
/// Split from the read itself because the read goes through the helper when
/// the site has a Linux user - the panel cannot read into a customer's
/// directory - and that call is async while these are not.
pub fn readable_text_file(
    root_path: &str,
    relative_path: &str,
    allow_sensitive: bool,
) -> Result<PathBuf, PathError> {
    let target = safe_path(root_path, relative_path, false)?;
    if !target.is_file() {
        return refuse("File not found");
    }
    if is_symlink(&target) {
        return refuse("Symlinks are not allowed");
    }
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if SENSITIVE_READ_NAMES.contains(&name.as_str()) && !allow_sensitive {
        return refuse(&format!("Reading {name} requires admin permissions"));
    }
    let size = std::fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
    if size > MAX_TEXT_FILE_BYTES {
        return refuse("File is too large");
    }
    Ok(target)
}

/// Source: `_helper_relative_path` - what the site-user command is given, so
/// the path it acts on is resolved inside the site rather than passed in
/// whole from a request.
pub fn helper_relative_path(root_path: &str, target: &Path) -> String {
    match std::fs::canonicalize(root_path) {
        Ok(root) => relative_to_root(&root, target),
        Err(_) => target.to_string_lossy().into_owned(),
    }
}

/// Source: `_assert_tree_read_allowed`.
///
/// Unlike the write walk this has no `allow_symlinks`: a read that follows a
/// link reads somebody else's file, and there is no caller that wants that.
///
/// [`SENSITIVE_READ_NAMES`] is empty today, so what this refuses in practice
/// is symlinks. It is written out in full anyway, because the constant exists
/// to be filled and a check that is only correct while a list is empty is not
/// a check.
pub fn assert_tree_read_allowed(
    path: &Path,
    action: &str,
    allow_sensitive: bool,
) -> Result<(), PathError> {
    if is_symlink(path) {
        return refuse("Symlinks are not allowed");
    }
    if !path.is_dir() {
        return assert_sensitive_read_allowed(path, action, allow_sensitive);
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            // `except PermissionError: return` - the walk stops and the
            // operation proceeds, the same way the write walk gives up.
            return Ok(());
        };
        for entry in entries.flatten() {
            let item = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&item) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                return refuse("Symlinks are not allowed");
            }
            if meta.is_dir() {
                stack.push(item);
            } else if meta.is_file() {
                assert_sensitive_read_allowed(&item, action, allow_sensitive)?;
            }
        }
    }
    Ok(())
}

/// Source: `_assert_tree_write_allowed`.
///
/// A directory is checked entry by entry, and a `PermissionError` while
/// walking is *not* a refusal: the panel account often cannot read into a
/// site user's directory, and the delete itself runs as that user through the
/// helper. Failing here would refuse the operation for a reason that has
/// nothing to do with whether it is allowed.
pub fn assert_tree_write_allowed(
    path: &Path,
    action: &str,
    allow_executable: bool,
    allow_symlinks: bool,
) -> Result<(), PathError> {
    if is_symlink(path) {
        if allow_symlinks {
            return assert_write_allowed(path, action, allow_executable);
        }
        return refuse("Symlinks are not allowed");
    }
    if !path.is_dir() {
        return assert_write_allowed(path, action, allow_executable);
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            // `except PermissionError: return` - the whole walk stops, not
            // just this directory, and the operation is allowed to proceed.
            return Ok(());
        };
        for entry in entries.flatten() {
            let item = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&item) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                if allow_symlinks {
                    continue;
                }
                return refuse("Symlinks are not allowed");
            }
            if meta.is_dir() {
                stack.push(item);
            } else if meta.is_file() {
                assert_write_allowed(&item, action, allow_executable)?;
            }
        }
    }
    Ok(())
}

/// Source: `chmod_entry`'s mode parsing, which is where the policy lives.
///
/// The nine ordinary permission bits are the owner's to set, the same way
/// DirectAdmin and cPanel expose them: executable scripts and 777 upload
/// directories are legitimate, and the website root is already the trust
/// boundary. Only the special bits stay restricted - setgid is allowed on a
/// folder because that is what keeps group inheritance working under a site
/// root, while setuid and the sticky bit have no use here and are the classic
/// shape of a planted backdoor.
pub fn parse_chmod_mode(mode: &str, target_is_dir: bool) -> Result<u32, PathError> {
    let clean = mode.trim();
    if !(clean.len() == 3 || clean.len() == 4) || !clean.bytes().all(|b| (b'0'..=b'7').contains(&b))
    {
        return refuse("Mode must be octal, for example 644 or 755");
    }
    let numeric = u32::from_str_radix(clean, 8)
        .map_err(|_| PathError("Mode must be octal, for example 644 or 755".to_string()))?;
    if numeric > 0o7777 {
        return refuse("Mode is out of range");
    }
    if numeric & 0o4000 != 0 {
        return refuse("Mode cannot include the setuid bit");
    }
    if numeric & 0o1000 != 0 {
        return refuse("Mode cannot include the sticky bit");
    }
    if numeric & 0o2000 != 0 && !target_is_dir {
        return refuse("The setgid bit can only be set on a folder");
    }
    Ok(numeric)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The same tree the fixture generator built, because `safe_path` walks
    /// the filesystem: a table of strings cannot express "there is a symlink
    /// at this component".
    struct Sandbox {
        base: PathBuf,
    }

    impl Sandbox {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "snpanel-files-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&base);
            let root = base.join("home/u/files.example.com");
            std::fs::create_dir_all(root.join("public_html")).unwrap();
            std::fs::write(root.join("public_html/index.php"), "<?php\n").unwrap();
            std::fs::create_dir_all(root.join("deep/nested")).unwrap();
            std::fs::write(root.join("deep/nested/file.txt"), "hello\n").unwrap();
            let outside = base.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("secret.txt"), "secret\n").unwrap();
            std::os::unix::fs::symlink(root.join("public_html"), root.join("link-inside")).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("link-outside")).unwrap();
            std::os::unix::fs::symlink(root.join("deep/nested"), root.join("deep/link-inside"))
                .unwrap();
            Self { base }
        }

        fn root(&self) -> PathBuf {
            self.base.join("home/u/files.example.com")
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/file_paths.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("the path corpus"))
            .expect("the corpus parses")
    }

    #[test]
    fn clean_relative_path_agrees_with_python() {
        let cases = corpus();
        let cases = cases["clean"].as_array().expect("the clean cases");
        assert!(cases.len() > 40, "the corpus shrank to {}", cases.len());

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let input = case["input"].as_str().expect("an input");
            let python_ok = case["ok"].as_bool().expect("a verdict");
            match (clean_relative_path(input), python_ok) {
                (Ok(got), true) => {
                    let want = case["value"].as_str().unwrap_or("");
                    if got != want {
                        failures.push(format!("{input:?}: python {want:?}, rust {got:?}"));
                    }
                }
                (Err(_), false) => {}
                (Ok(got), false) => failures.push(format!(
                    "{input:?}: rust ACCEPTED as {got:?} what python refused ({})",
                    case["error"].as_str().unwrap_or("?")
                )),
                (Err(e), true) => {
                    failures.push(format!("{input:?}: rust refused what python accepted: {e}"))
                }
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

    #[test]
    fn safe_path_agrees_with_python_against_a_real_tree() {
        let sandbox = Sandbox::new("safe");
        let root = sandbox.root();
        let root_str = root.to_string_lossy().into_owned();
        let real_root = std::fs::canonicalize(&root).expect("the sandbox root");

        let cases = corpus();
        let cases = cases["safe"].as_array().expect("the safe cases");
        assert!(cases.len() > 80, "the corpus shrank to {}", cases.len());

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let input = case["input"].as_str().expect("an input");
            let leaf = case["allow_leaf_symlink"].as_bool().unwrap_or(false);
            let python_ok = case["ok"].as_bool().expect("a verdict");

            match (safe_path(&root_str, input, leaf), python_ok) {
                (Ok(got), true) => {
                    // The fixture records the result relative to the root, or
                    // `<OUTSIDE>...` when Python returned something beyond it.
                    let want = case["value"].as_str().unwrap_or("");
                    let got_rel = match got.strip_prefix(&real_root) {
                        Ok(r) if r.as_os_str().is_empty() => ".".to_string(),
                        Ok(r) => r.to_string_lossy().into_owned(),
                        Err(_) => format!("<OUTSIDE>{}", got.display()),
                    };
                    let matches = if want.starts_with("<OUTSIDE>") {
                        got_rel.starts_with("<OUTSIDE>")
                    } else {
                        got_rel == want
                    };
                    if !matches {
                        failures.push(format!(
                            "{input:?} leaf={leaf}: python {want:?}, rust {got_rel:?}"
                        ));
                    }
                }
                (Err(_), false) => {}
                (Ok(got), false) => failures.push(format!(
                    "{input:?} leaf={leaf}: rust ACCEPTED {} where python refused ({})",
                    got.display(),
                    case["error"].as_str().unwrap_or("?")
                )),
                (Err(e), true) => failures.push(format!(
                    "{input:?} leaf={leaf}: rust refused what python accepted: {e}"
                )),
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

    #[test]
    fn a_leaf_symlink_is_returned_unresolved_so_it_can_be_unlinked() {
        // The point of `allow_leaf_symlink`: a Laravel `public/storage` has
        // to be removable without following it. If this resolved, deleting
        // the link would delete what it points at - which, for
        // `link-outside`, is a directory outside the customer's site.
        let sandbox = Sandbox::new("leaf");
        let root = sandbox.root().to_string_lossy().into_owned();
        let got = safe_path(&root, "link-outside", true).expect("a leaf symlink is allowed");
        assert!(
            got.symlink_metadata().unwrap().file_type().is_symlink(),
            "the link itself must come back, not its target: {}",
            got.display()
        );
        assert!(
            safe_path(&root, "link-outside/secret.txt", true).is_err(),
            "and it must not extend to anything under the link"
        );
    }
}
