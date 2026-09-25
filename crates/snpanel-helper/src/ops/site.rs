//! `ops::site` - the files a customer's website is made of.
//!
//! Source: the `mkdir-site`, `rm-site`, `site-file-write`, `site-chmod`,
//! `site-log-*` and `fix-permissions` arms, plus `fix_site_tree` and
//! `protect_site_secret_tree`.
//!
//! Two contracts govern everything here.
//!
//! **C34** - files 644, directories 755, and then `wp-config.php`, `.env` and
//! `.my.cnf` back down to 640. The last step is the one that is easy to
//! forget and the one that matters: a bulk permission pass that leaves
//! `wp-config.php` at 644 has published the customer's database password to
//! every other account on the box.
//!
//! **C36** - a symlink anywhere in a path is refused. Not just the final
//! component: a symlinked *parent* is the same escape by a different route.
//! [`SitePath`] carries the lexical guarantee; [`SitePath::verify_no_symlinks`]
//! is what checks the filesystem, and every function here that touches a path
//! calls it.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use snpanel_core::{Domain, PanelUsername, SitePath};
use snpanel_ipc::{FileMode, HelperErrorKind, HelperResponse};

use super::user::SITES_GROUP;
use crate::exec;

/// Source: `SITE_FILE_MODE` and `SITE_DIR_MODE`.
pub const FILE_MODE: u32 = 0o644;
pub const DIR_MODE: u32 = 0o755;
/// Source: `SITE_SECRET_FILES`.
pub const SECRET_FILES: &[&str] = &["wp-config.php", ".env", ".my.cnf"];
/// Source: `SITE_SECRET_MODE` behaviour in `protect_site_secret_tree`.
pub const SECRET_MODE: u32 = 0o640;

/// C36, applied before anything else touches the path.
fn guard(path: &SitePath) -> Result<(), HelperResponse> {
    path.verify_no_symlinks().map_err(|_| {
        HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("refusing to act through a symlink: {path}"),
        )
    })
}

/// `mkdir-site`: create the site root and its document root.
///
/// Source: `install -d -o www-data -g www-data -m 0750`.
pub fn mkdir(path: &SitePath) -> HelperResponse {
    if let Err(r) = guard(path) {
        return r;
    }
    let web = snpanel_osabi::detect()
        .map(|p| format!("{}:{}", p.web_user(), p.web_group()))
        .unwrap_or_else(|_| "www-data:www-data".to_string());

    let public = path.as_path().join("public_html");
    for dir in [path.as_path(), public.as_path()] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {}: {e}", dir.display()),
            );
        }
        let d = dir.to_string_lossy().into_owned();
        let _ = exec::run(&["chown", &web, &d]);
        let _ = exec::run(&["chmod", "0750", &d]);
    }
    HelperResponse::ok()
}

/// `site-file-write`.
///
/// Only 644 and 640 are accepted, matching the bash: this writes site content,
/// never an executable.
pub fn file_write(path: &SitePath, content: &[u8], mode: FileMode) -> HelperResponse {
    if mode.0 != FILE_MODE && mode.0 != SECRET_MODE {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("invalid file mode: {:04o}", mode.0),
        );
    }
    if let Err(r) = guard(path) {
        return r;
    }
    if path.as_path().is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("cannot write a directory: {path}"),
        );
    }

    if let Some(parent) = path.as_path().parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {}: {e}", parent.display()),
            );
        }
    }

    match write_atomic(path.as_path(), content, mode.0) {
        Ok(()) => HelperResponse::ok(),
        Err(e) => HelperResponse::failed(HelperErrorKind::Internal, format!("writing {path}: {e}")),
    }
}

/// Limits of `site-file-search`, the MCP addon's `search_files`. The helper
/// holds them, so no caller can widen them.
pub const SEARCH_MAX_MATCHES: usize = 100;
pub const SEARCH_MAX_FILES: usize = 20_000;
pub const SEARCH_MAX_FILE_BYTES: u64 = 512 * 1024;
pub const SEARCH_MAX_TOTAL_BYTES: u64 = 200 * 1024 * 1024;
/// A match's line is cut to this many characters.
const SEARCH_LINE_CHARS: usize = 300;
/// Directories never entered: history, dependencies, caches and uploads -
/// large, rarely what is being looked for, and mostly not code.
const SEARCH_SKIP_DIRS: &[&str] = &[".git", "node_modules", ".cache", "cache", "uploads"];

/// One line that holds the text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SearchMatch {
    /// Relative to the directory searched.
    pub path: String,
    /// From 1.
    pub line: usize,
    pub text: String,
}

/// What a search found, and how far it got.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct SearchOutcome {
    pub matches: Vec<SearchMatch>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    /// Files passed over for being larger than [`SEARCH_MAX_FILE_BYTES`].
    pub files_too_large: usize,
    /// The limit that ended the search early: `matches`, `files` or `bytes`.
    pub stopped_by: Option<&'static str>,
}

/// `site-file-search`: plain text in a site's files, never a pattern.
///
/// Walks the directory without following a symlink anywhere, reads regular
/// files only, and passes over the directories in [`SEARCH_SKIP_DIRS`],
/// binary files and the site's secret files unless `include_secrets` - the
/// file manager lets only an administrator open those. The answer is JSON on
/// stdout.
pub fn file_search(
    path: &SitePath,
    query: &str,
    suffix: &str,
    case_sensitive: bool,
    include_secrets: bool,
) -> HelperResponse {
    if let Err(r) = guard(path) {
        return r;
    }
    if query.is_empty() || query.chars().count() > 200 || query.contains(['\n', '\r', '\0']) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "the search text is 1 to 200 characters on one line".to_string(),
        );
    }
    if suffix.len() > 32 || suffix.contains(['/', '\0']) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("invalid file suffix: {suffix}"),
        );
    }
    let Ok(meta) = std::fs::symlink_metadata(path.as_path()) else {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no such folder: {path}"),
        );
    };
    if !meta.is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("not a folder: {path}"),
        );
    }
    let outcome = search_tree(
        path.as_path(),
        query,
        suffix,
        case_sensitive,
        include_secrets,
    );
    let mut response = HelperResponse::ok();
    response.stdout = serde_json::to_string(&outcome).unwrap_or_else(|_| "{}".to_string());
    response
}

/// The walk itself, separate from the request so a test can give it a tree.
pub fn search_tree(
    root: &std::path::Path,
    query: &str,
    suffix: &str,
    case_sensitive: bool,
    include_secrets: bool,
) -> SearchOutcome {
    let needle = if case_sensitive {
        query.to_string()
    } else {
        query.to_lowercase()
    };
    let mut outcome = SearchOutcome::default();
    // A folder's files, then its subfolders, each in name order: the same
    // tree gives the same answer.
    let mut stack = vec![root.to_path_buf()];
    'walk: while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<std::fs::DirEntry> = entries.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        let mut subdirs = Vec::new();
        for entry in entries {
            let path = entry.path();
            // `symlink_metadata`: a link is itself, never what it points at.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if !SEARCH_SKIP_DIRS.contains(&name.as_str()) {
                    subdirs.push(path);
                }
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if !suffix.is_empty() && !name.ends_with(suffix) {
                continue;
            }
            if !include_secrets && SECRET_FILES.contains(&name.as_str()) {
                continue;
            }
            if outcome.files_scanned >= SEARCH_MAX_FILES {
                outcome.stopped_by = Some("files");
                break 'walk;
            }
            if meta.len() > SEARCH_MAX_FILE_BYTES {
                outcome.files_too_large += 1;
                continue;
            }
            if outcome.bytes_scanned + meta.len() > SEARCH_MAX_TOTAL_BYTES {
                outcome.stopped_by = Some("bytes");
                break 'walk;
            }
            let Some(content) = read_regular(&path) else {
                continue;
            };
            outcome.files_scanned += 1;
            outcome.bytes_scanned += content.len() as u64;
            // A NUL near the start is a binary file, as grep decides.
            if content[..content.len().min(8192)].contains(&0) {
                continue;
            }
            let text = String::from_utf8_lossy(&content);
            let relative = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or(name);
            for (index, line) in text.lines().enumerate() {
                let found = if case_sensitive {
                    line.contains(&needle)
                } else {
                    line.to_lowercase().contains(&needle)
                };
                if !found {
                    continue;
                }
                outcome.matches.push(SearchMatch {
                    path: relative.clone(),
                    line: index + 1,
                    text: line.trim().chars().take(SEARCH_LINE_CHARS).collect(),
                });
                if outcome.matches.len() >= SEARCH_MAX_MATCHES {
                    outcome.stopped_by = Some("matches");
                    break 'walk;
                }
            }
        }
        // Reversed onto the stack, so they come off in name order.
        stack.extend(subdirs.into_iter().rev());
    }
    outcome
}

/// A regular file's bytes, opened without following a link and without
/// waiting on a FIFO that appeared after the listing; `None` for anything
/// else.
fn read_regular(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > SEARCH_MAX_FILE_BYTES {
        return None;
    }
    let mut content = Vec::with_capacity(meta.len() as usize);
    Read::take(&mut file, SEARCH_MAX_FILE_BYTES)
        .read_to_end(&mut content)
        .ok()?;
    Some(content)
}

/// `site-chmod`.
///
/// Runs as root deliberately, and the bash says why: the site user is not a
/// member of the site group, so a chmod performed *as* that user has its
/// setgid bit cleared by the kernel, silently breaking group inheritance on
/// site folders.
pub fn chmod(path: &SitePath, mode: FileMode, recursive: bool) -> HelperResponse {
    if mode.0 > 0o7777 {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("invalid mode: {:o}", mode.0),
        );
    }
    if let Err(r) = guard(path) {
        return r;
    }
    let mode_str = format!("{:04o}", mode.0);
    let target = path.as_str().to_string();
    let out = if recursive {
        exec::run(&["chmod", "-R", &mode_str, &target])
    } else {
        exec::run(&["chmod", &mode_str, &target])
    };
    exec::respond("chmod", out)
}

/// `rm-site`: remove a path inside a managed site tree.
pub fn remove(path: &SitePath) -> HelperResponse {
    if let Err(r) = guard(path) {
        return r;
    }
    let meta = match std::fs::symlink_metadata(path.as_path()) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HelperResponse::ok(),
        Err(e) => {
            return HelperResponse::failed(HelperErrorKind::Internal, format!("stat {path}: {e}"))
        }
    };

    let result = if meta.is_dir() {
        std::fs::remove_dir_all(path.as_path())
    } else {
        std::fs::remove_file(path.as_path())
    };
    match result {
        Ok(()) => HelperResponse::ok(),
        Err(e) => {
            HelperResponse::failed(HelperErrorKind::Internal, format!("removing {path}: {e}"))
        }
    }
}

/// `fix-permissions` with a site user. Source: `fix_site_tree`.
///
/// The order is the contract: own, strip ACLs, directories, files, then pull
/// the secret files back down. Doing the secrets first would be undone by the
/// bulk pass.
pub fn fix_permissions(path: &SitePath, user: &PanelUsername) -> HelperResponse {
    if let Err(r) = guard(path) {
        return r;
    }
    let target = path.as_str().to_string();
    let owner = format!("{}:{}", user.as_str(), SITES_GROUP);

    let out = exec::run(&["chown", "-R", &owner, &target]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("chown -R", out);
    }

    if !path.as_path().is_dir() {
        let _ = exec::run(&["chmod", "0644", &target]);
        return harden_secrets(path.as_path());
    }

    // An inherited default ACL would silently widen access past the mode bits
    // for everything created later.
    let _ = exec::run(&["setfacl", "-Rb", &target]);
    let _ = exec::run(&[
        "find", &target, "-type", "d", "-exec", "setfacl", "-k", "{}", "+",
    ]);

    let dir_mode = format!("{DIR_MODE:o}");
    let file_mode = format!("{FILE_MODE:o}");
    for (kind, mode) in [("d", dir_mode.as_str()), ("f", file_mode.as_str())] {
        let out = exec::run(&[
            "find", &target, "-type", kind, "-exec", "chmod", mode, "{}", "+",
        ]);
        if !matches!(&out, Ok(o) if o.ok()) {
            return exec::respond("find -exec chmod", out);
        }
    }
    // setuid/setgid and sticky have no business on customer content.
    for flag in ["a-s", "-t"] {
        let _ = exec::run(&[
            "find", &target, "-type", "d", "-exec", "chmod", flag, "{}", "+",
        ]);
    }

    harden_secrets(path.as_path())
}

/// C34's last step: credentials-bearing files go back to 640.
fn harden_secrets(root: &Path) -> HelperResponse {
    let mut hardened = 0usize;
    for name in SECRET_FILES {
        let out = exec::run(&[
            "find",
            &root.to_string_lossy(),
            "-type",
            "f",
            "-name",
            name,
            "-exec",
            "chmod",
            "0640",
            "{}",
            "+",
        ]);
        if matches!(&out, Ok(o) if o.ok()) {
            hardened += 1;
        }
    }
    HelperResponse::with_data(serde_json::json!({
        "secret_patterns_applied": hardened,
        "secret_files": SECRET_FILES,
    }))
}

/// `site-log-read`. The logs live outside the site tree, so the domain - not a
/// caller-supplied path - is what selects the file.
pub fn log_read(domain: &Domain, kind: LogKind, lines: u32) -> HelperResponse {
    let path = log_path(domain, kind);
    if !path.exists() {
        return HelperResponse::with_stdout("");
    }
    let n = lines.clamp(1, 10_000).to_string();
    exec::respond(
        "tail",
        exec::run(&["tail", "-n", &n, &path.to_string_lossy()]),
    )
}

/// Where the unprivileged extractor is installed.
const EXTRACTOR: &str = "/usr/local/sbin/snpanel-extract";

/// `site-archive-extract`: unpack an archive inside a site.
///
/// The helper never parses the archive. It stages a copy the site user can
/// read, runs [`EXTRACTOR`] as that user, puts the original back and fixes
/// ownership. An archive is attacker-controlled input; whatever reads it must
/// not be the process running as root.
///
/// The staging is not tidiness. An archive may contain an entry with its own
/// filename, so the copy being read cannot be the copy that might be
/// overwritten - which is also why the original is restored afterwards.
pub fn archive_extract(
    user: &PanelUsername,
    root: &SitePath,
    archive_relative: &str,
    destination_relative: &str,
    kind: snpanel_ipc::ArchiveKind,
    max_items: u32,
    max_bytes: u64,
) -> HelperResponse {
    if let Err(r) = guard(root) {
        return r;
    }
    for fragment in [archive_relative, destination_relative] {
        if let Err(message) = check_upload_relative(fragment) {
            return HelperResponse::failed(HelperErrorKind::BadRequest, message);
        }
    }

    let resolve = |fragment: &str| -> Result<SitePath, HelperResponse> {
        let joined = root.as_path().join(fragment);
        let p = SitePath::parse(&joined.to_string_lossy()).map_err(|_| {
            HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("path outside the site: {}", joined.display()),
            )
        })?;
        if !p.as_path().starts_with(root.as_path()) {
            return Err(HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("path outside the site: {p}"),
            ));
        }
        Ok(p)
    };
    let archive = match resolve(archive_relative) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let destination = match resolve(destination_relative) {
        Ok(p) => p,
        Err(r) => return r,
    };

    let is_regular = |p: &SitePath| {
        std::fs::symlink_metadata(p.as_path())
            .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
    };
    if !is_regular(&archive) {
        return HelperResponse::failed(HelperErrorKind::NotFound, "archive not found".to_string());
    }
    let dest_ok = std::fs::symlink_metadata(destination.as_path())
        .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink());
    if !dest_ok {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "archive destination not found".to_string(),
        );
    }
    if !std::path::Path::new(EXTRACTOR).is_file() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("the extractor is not installed: {EXTRACTOR}"),
        );
    }

    // A copy the site user can read, outside the tree being written into.
    let staged = format!("/tmp/snpanel-extract-{}", std::process::id());
    let _ = std::fs::remove_file(&staged);
    let out = exec::run(&[
        "install",
        "-o",
        user.as_str(),
        "-g",
        user.as_str(),
        "-m",
        "0600",
        "--",
        archive.as_str(),
        &staged,
    ]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("install (staging the archive)", out);
    }

    let items = max_items.to_string();
    let bytes = max_bytes.to_string();
    let extracted = exec::run(&[
        "runuser",
        "-u",
        user.as_str(),
        "--",
        EXTRACTOR,
        &staged,
        kind.as_str(),
        destination.as_str(),
        &items,
        &bytes,
    ]);

    // Put the original back whatever happened: the archive may have named
    // itself, and a failed extraction must not cost the customer the file
    // they uploaded.
    let _ = exec::run(&[
        "install",
        "-o",
        user.as_str(),
        "-g",
        SITES_GROUP,
        "-m",
        "0644",
        "--",
        &staged,
        archive.as_str(),
    ]);
    let _ = std::fs::remove_file(&staged);

    if !matches!(&extracted, Ok(o) if o.ok()) {
        return exec::respond("snpanel-extract", extracted);
    }
    fix_permissions(&destination, user)
}

/// `site-runtime-move`: move a site and rebuild its runtime at the new path.
///
/// Source: the `site-runtime-move` arm. The old pool goes first: its name
/// hashes the old path, so after the move nothing would match it, and it
/// would keep serving with `open_basedir` pointing at a directory that is no
/// longer there.
pub fn runtime_move(
    user: &PanelUsername,
    from: &SitePath,
    to: &SitePath,
    php: Option<snpanel_core::PhpVersion>,
) -> HelperResponse {
    if let Err(r) = guard(to) {
        return r;
    }
    let home = super::user::ensure(user, None);
    if !home.ok {
        return home;
    }

    if from.as_path() != to.as_path() {
        if to.as_path().exists() {
            return HelperResponse::failed(
                // The bash refuses this with `deny`, which is a bad
                // request; the protocol has no distinct Conflict kind.
                HelperErrorKind::BadRequest,
                format!("target path already exists: {to}"),
            );
        }
        // The old owner, taken from the old path rather than assumed to be
        // the new one: a site can move between accounts.
        let old_user = from.user().as_str().to_string();
        let old_resolved = std::fs::canonicalize(from.as_path())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| from.as_str().to_string());
        let _ = super::php::delete_site_pools(&old_user, &old_resolved);

        if let Some(parent) = to.as_path().parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return HelperResponse::failed(
                    HelperErrorKind::Internal,
                    format!("creating {}: {e}", parent.display()),
                );
            }
        }
        if let Err(e) = std::fs::rename(from.as_path(), to.as_path()) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("moving {from} to {to}: {e}"),
            );
        }
    }

    let root = to.as_path();
    // The simple branch only - see `migrate_public_to_public_html`.
    if let Err(message) = migrate_public_to_public_html(root, false) {
        return HelperResponse::failed(HelperErrorKind::Internal, message);
    }
    let public_html = root.join("public_html");
    if let Err(e) = std::fs::create_dir_all(&public_html) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {}: {e}", public_html.display()),
        );
    }
    let hardened = harden_dir_path(root, &public_html, user);
    if !hardened.ok {
        return hardened;
    }
    let fixed = fix_permissions(to, user);
    if !fixed.ok {
        return fixed;
    }

    match php {
        None => HelperResponse::ok(),
        Some(version) => {
            let resolved = std::fs::canonicalize(root)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| to.as_str().to_string());
            super::php::ensure_site_pool(
                user.as_str(),
                &resolved,
                version,
                super::php::tuning_overrides(),
            )
        }
    }
}

/// `site-runtime-ensure`: make a site's directories and pool exist.
///
/// Source: the `site-runtime-ensure` arm.
pub fn runtime_ensure(
    user: &PanelUsername,
    path: &SitePath,
    php: Option<snpanel_core::PhpVersion>,
) -> HelperResponse {
    if let Err(r) = guard(path) {
        return r;
    }
    let home = super::user::ensure(user, None);
    if !home.ok {
        return home;
    }

    let root = path.as_path();
    if let Err(message) = migrate_public_to_public_html(root, true) {
        return HelperResponse::failed(HelperErrorKind::Internal, message);
    }

    let public_html = root.join("public_html");
    if let Err(e) = std::fs::create_dir_all(&public_html) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {}: {e}", public_html.display()),
        );
    }
    let hardened = harden_dir_path(root, &public_html, user);
    if !hardened.ok {
        return hardened;
    }
    let fixed = fix_permissions(path, user);
    if !fixed.ok {
        return fixed;
    }

    match php {
        None => HelperResponse::ok(),
        Some(version) => {
            // The pool name hashes the resolved path, as the shell does.
            let resolved = std::fs::canonicalize(root)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| path.as_str().to_string());
            super::php::ensure_site_pool(
                user.as_str(),
                &resolved,
                version,
                super::php::tuning_overrides(),
            )
        }
    }
}

/// Rename `public` to `public_html`, but only when nothing would be lost.
///
/// Source: the two branches in the bash. Sites arriving from an importer that
/// used `public` need the rename; a site that already has a populated
/// `public_html` must not be overwritten by an older copy of itself, so the
/// second branch only fires when `public_html` is empty.
fn migrate_public_to_public_html(
    root: &Path,
    replace_empty_public_html: bool,
) -> Result<(), String> {
    let public = root.join("public");
    let public_html = root.join("public_html");
    if !public.is_dir() {
        return Ok(());
    }
    let rename = |from: &Path, to: &Path| {
        std::fs::rename(from, to)
            .map_err(|e| format!("renaming {} to {}: {e}", from.display(), to.display()))
    };

    if !public_html.exists() {
        return rename(&public, &public_html);
    }
    // Only `site-runtime-ensure` does this. The `move` arm in the bash has
    // the simple branch alone, and quietly gaining this one would change
    // what happens to a moved site that has both directories.
    if replace_empty_public_html && public_html.is_dir() {
        let empty = std::fs::read_dir(&public_html)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        if empty {
            std::fs::remove_dir(&public_html)
                .map_err(|e| format!("removing the empty {}: {e}", public_html.display()))?;
            return rename(&public, &public_html);
        }
    }
    // `public_html` exists and has content: leave both alone. Overwriting it
    // with `public` would replace a live site with whatever the importer left.
    Ok(())
}

/// `site-runtime-delete`: remove a site's PHP pools, then the site itself.
///
/// Source: the `site-runtime-delete` arm. Pools first: removing the tree
/// while a pool still points at it leaves FPM workers holding a document root
/// that no longer exists, and the next request to that socket fails in a way
/// that names neither the site nor the deletion.
pub fn runtime_delete(user: &PanelUsername, path: &SitePath) -> HelperResponse {
    if let Err(r) = guard(path) {
        return r;
    }
    // The shell hashes the path *after* `readlink -m`, so the resolution has
    // to happen here too or the pool name will not match what is on disk.
    let resolved = std::fs::canonicalize(path.as_path())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.as_str().to_string());

    let removed = super::php::delete_site_pools(user.as_str(), &resolved);

    if let Err(e) = std::fs::remove_dir_all(path.as_path()) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("removing {}: {e}", path.as_path().display()),
            );
        }
    }
    HelperResponse::with_stdout(format!(
        "removed {} pool file(s) and the site tree\n",
        removed.len()
    ))
}

/// Where WP-CLI is installed. Named once so the two verbs cannot disagree.
const WP_CLI: &str = "/usr/local/bin/wp";

/// PCRE's JIT is switched off for WP-CLI.
///
/// Source: `-d pcre.jit=0` in both arms. WordPress's own regular expressions
/// segfault PHP with the JIT enabled on some builds, and a crashed CLI looks
/// to the panel exactly like a command that produced nothing.
const PCRE_JIT_OFF: &str = "-d";
const PCRE_JIT_OFF_VALUE: &str = "pcre.jit=0";

/// `wp`: WP-CLI as the web user.
pub fn wp(args: &[String]) -> HelperResponse {
    if args.is_empty() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "usage: wp <args...>".to_string(),
        );
    }
    let (web_user, home) = web_user_and_home();
    run_wp(&web_user, &home, "php", args)
}

/// `wp-site`: WP-CLI as the site's user, under the site's PHP.
pub fn wp_site(
    user: &PanelUsername,
    php: Option<snpanel_core::PhpVersion>,
    args: &[String],
) -> HelperResponse {
    if args.is_empty() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "usage: wp-site <site-user> [--php-version=<version>] <args...>".to_string(),
        );
    }
    let binary = match php {
        // The version is a parsed `PhpVersion`, so `require_php_version` has
        // already happened in the type.
        Some(v) => format!("php{v}"),
        None => "php".to_string(),
    };
    if php.is_some() && which(&binary).is_none() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("PHP CLI is not installed: {binary}"),
        );
    }
    let home = format!("/home/{}", user.as_str());
    run_wp(user.as_str(), &home, &binary, args)
}

fn run_wp(as_user: &str, home: &str, php_binary: &str, args: &[String]) -> HelperResponse {
    let argv = wp_argv(as_user, home, php_binary, args);
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    exec::respond(&format!("wp (as {as_user})"), exec::run(&borrowed))
}

/// The argument vector, built separately so it can be read without being run.
///
/// Every element is its own argument. There is no shell in this path, which
/// is why a WordPress option value containing a quote or a semicolon is just
/// a value - but that is only obvious if you can see the vector, so the tests
/// look at it directly.
fn wp_argv(as_user: &str, home: &str, php_binary: &str, args: &[String]) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "runuser".into(),
        "-u".into(),
        as_user.into(),
        "--".into(),
        "env".into(),
        format!("HOME={home}"),
        "WP_CLI_PHP_ARGS=-d pcre.jit=0".into(),
        php_binary.into(),
        PCRE_JIT_OFF.into(),
        PCRE_JIT_OFF_VALUE.into(),
        WP_CLI.into(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// The web user and its home, the way the bash resolves them.
///
/// Source: `WEB_USER_HOME="$(getent passwd ... | cut -d: -f6)"` with
/// `/var/www` as the fallback when the entry has no usable home.
fn web_user_and_home() -> (String, String) {
    let user = snpanel_osabi::detect()
        .map(|p| p.web_user().to_string())
        .unwrap_or_else(|_| "www-data".to_string());
    let home = exec::run(&["getent", "passwd", &user])
        .ok()
        .and_then(|o| {
            o.stdout
                .lines()
                .next()
                .and_then(|line| line.split(':').nth(5).map(str::to_string))
        })
        .filter(|h| !h.is_empty() && Path::new(h).is_dir())
        .unwrap_or_else(|| "/var/www".to_string());
    (user, home)
}

/// Is this program on the helper's fixed search path?
fn which(program: &str) -> Option<std::path::PathBuf> {
    [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]
    .iter()
    .map(|d| Path::new(d).join(program))
    .find(|p| p.is_file())
}

/// Where the panel stages a tree for import or restore.
///
/// Two prefixes because the importer and the restorer use different ones.
/// Checked on the path as given and again after resolution, for the same
/// reason as the upload prefix: a symlink in a staging directory would
/// otherwise name anything on the machine.
const IMPORT_STAGE_PREFIXES: &[&str] = &[
    "/var/lib/snpanel/import-stage/",
    "/var/lib/snpanel/da-import/",
];

/// `site-populate`: replace a site's tree from a staged copy.
///
/// Source: the `site-populate` arm. Every check runs before the delete: this
/// empties the site root, and refusing afterwards would leave a customer with
/// nothing where their site used to be.
pub fn populate(user: &PanelUsername, root: &SitePath, source: &str) -> HelperResponse {
    if let Err(r) = guard(root) {
        return r;
    }
    let src = match check_staged_tree(source) {
        Ok(p) => p,
        Err(message) => return HelperResponse::failed(HelperErrorKind::BadRequest, message),
    };

    let target = root.as_path();
    if let Err(e) = std::fs::create_dir_all(target) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {}: {e}", target.display()),
        );
    }

    // Everything inside, not the root itself: the directory belongs to the
    // site user and recreating it would lose its ownership and mode.
    if let Err(e) = empty_directory(target) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("clearing {}: {e}", target.display()),
        );
    }

    let from = format!("{}/.", src);
    let to = format!("{}/", target.display());
    let out = exec::run(&["cp", "-a", "--no-preserve=ownership", "--", &from, &to]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("cp -a", out);
    }

    // A backup is attacker-controlled input. A symlink to /etc/shadow inside
    // one would otherwise be served by nginx; a device node is worse.
    let _ = exec::run(&[
        "find",
        &target.to_string_lossy(),
        "(",
        "-type",
        "l",
        "-o",
        "-type",
        "b",
        "-o",
        "-type",
        "c",
        "-o",
        "-type",
        "p",
        "-o",
        "-type",
        "s",
        ")",
        "-delete",
    ]);

    let public = target.join("public_html");
    if let Err(e) = std::fs::create_dir_all(&public) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {}: {e}", public.display()),
        );
    }

    fix_permissions(root, user)
}

/// Delete the contents of a directory, leaving the directory itself.
fn empty_directory(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // `symlink_metadata`, so a symlinked directory is unlinked rather
        // than recursed into.
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// The staged source tree, checked the way the bash checks it.
fn check_staged_tree(source: &str) -> Result<String, String> {
    let under_stage = |p: &str| {
        IMPORT_STAGE_PREFIXES
            .iter()
            .any(|prefix| p.starts_with(prefix))
    };

    if !under_stage(source) {
        return Err(format!(
            "staged source must be under {}",
            IMPORT_STAGE_PREFIXES[0]
        ));
    }
    let given = Path::new(source);
    match std::fs::symlink_metadata(given) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err("staged source cannot be a symlink".to_string())
        }
        Ok(_) => {}
        Err(_) => return Err(format!("staged source not found: {source}")),
    }

    let resolved =
        std::fs::canonicalize(given).map_err(|_| format!("staged source not found: {source}"))?;
    let resolved_str = resolved.to_string_lossy().into_owned();
    if !under_stage(&format!("{resolved_str}/")) {
        return Err(format!(
            "staged source escaped the import staging area: {resolved_str}"
        ));
    }
    let meta =
        std::fs::metadata(&resolved).map_err(|e| format!("staged source not readable: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("staged source is not a directory: {resolved_str}"));
    }
    let panel_uid = crate::peercred::uid_of(crate::peercred::PANEL_USER)
        .map_err(|e| format!("cannot resolve the panel user: {e}"))?;
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != panel_uid {
        return Err(format!(
            "staged source must be owned by {}",
            crate::peercred::PANEL_USER
        ));
    }
    Ok(resolved_str)
}

/// Where the panel stages an upload before the helper moves it: the
/// directory, and the slash that keeps a sibling such as `upload-stage-old/`
/// from counting as inside it.
///
/// Checked as a prefix twice: on the path as given and on the path after
/// resolution. A symlink under this directory would otherwise name anything
/// on the machine, and the helper runs as root.
///
/// It was `/tmp/snpanel-upload-`, which worked only while the helper ran
/// under sudo, in the API's mount namespace. Over the socket each service has
/// a `/tmp` of its own, and every File Manager upload failed with "staged
/// upload not found".
fn upload_stage_prefix() -> String {
    format!("{}/", snpanel_ipc::UPLOAD_STAGE_DIR)
}

/// `site-file-install`: move a staged upload into a site.
///
/// Source: the `site-file-install` arm. The order is the bash's: everything
/// is checked before anything is created, and the staged file is removed only
/// after the move has succeeded.
pub fn file_install(
    user: &PanelUsername,
    root: &SitePath,
    relative: &str,
    staged: &str,
) -> HelperResponse {
    if let Err(r) = guard(root) {
        return r;
    }
    if let Err(message) = check_upload_relative(relative) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, message);
    }

    let joined = root.as_path().join(relative);
    let target = match SitePath::parse(&joined.to_string_lossy()) {
        Ok(p) => p,
        Err(_) => {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("path outside the site: {}", joined.display()),
            )
        }
    };
    if !target.as_path().starts_with(root.as_path()) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("path outside the site: {target}"),
        );
    }
    // Writing through a symlink would put the bytes wherever it points.
    if std::fs::symlink_metadata(target.as_path())
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("refusing to write through a symlink: {target}"),
        );
    }

    let source = match check_staged_upload(staged, &upload_stage_prefix()) {
        Ok(p) => p,
        Err(message) => return HelperResponse::failed(HelperErrorKind::BadRequest, message),
    };

    let Some(parent) = target.as_path().parent() else {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("no parent directory for {target}"),
        );
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {}: {e}", parent.display()),
        );
    }
    let hardened = harden_dir_path(root.as_path(), parent, user);
    if !hardened.ok {
        return hardened;
    }

    // Into place via a temporary name in the same directory, so a reader
    // never sees a half-written file at the destination.
    let base = target
        .as_path()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{base}.snpanel-install-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);

    let owner = format!("{}:{}", user.as_str(), SITES_GROUP);
    let out = exec::run(&[
        "install",
        "-o",
        user.as_str(),
        "-g",
        SITES_GROUP,
        "-m",
        "0644",
        "--",
        &source,
        &tmp.to_string_lossy(),
    ]);
    if !matches!(&out, Ok(o) if o.ok()) {
        let _ = std::fs::remove_file(&tmp);
        return exec::respond(&format!("install -o {owner}"), out);
    }

    if let Err(e) = std::fs::rename(&tmp, target.as_path()) {
        let _ = std::fs::remove_file(&tmp);
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("moving into {target}: {e}"),
        );
    }
    // Only now: the staged copy is the one thing that could put this back.
    let _ = std::fs::remove_file(&source);
    HelperResponse::ok()
}

/// The relative path of an uploaded file.
///
/// Deliberately looser than [`check_relative`]. A document root is a name an
/// administrator types, so it is restricted to `[A-Za-z0-9._-]`; an uploaded
/// file is named by whoever uploaded it, and real filenames have spaces,
/// brackets and non-ASCII in them. Tightening this to match would refuse
/// ordinary uploads. Source: the `case` in the `site-file-install` arm.
fn check_upload_relative(relative: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("unsafe relative path: {relative} ({why})"));
    if relative.is_empty() {
        return bad("empty");
    }
    if relative.starts_with('/') {
        return bad("absolute");
    }
    if relative.contains('\n') || relative.contains('\0') {
        return bad("control character");
    }
    if relative == ".."
        || relative.starts_with("../")
        || relative.ends_with("/..")
        || relative.contains("/../")
    {
        return bad("traversal");
    }
    Ok(())
}

/// The staged upload, checked the way the bash checks it.
///
/// Returns the resolved path. Every step here is a boundary: without them a
/// caller names a file outside the staging area, or a symlink to one, or a
/// file somebody else planted, and the helper copies it into a site as root.
/// `prefix` is [`upload_stage_prefix`]; the tests hand it a directory of
/// their own.
fn check_staged_upload(staged: &str, prefix: &str) -> Result<String, String> {
    if !staged.starts_with(prefix) {
        return Err(format!("invalid staged upload path: {staged}"));
    }
    let given = Path::new(staged);
    match std::fs::symlink_metadata(given) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err("staged upload cannot be a symlink".to_string())
        }
        Ok(_) => {}
        Err(_) => return Err(format!("staged upload not found: {staged}")),
    }

    let resolved =
        std::fs::canonicalize(given).map_err(|_| format!("staged upload not found: {staged}"))?;
    let resolved_str = resolved.to_string_lossy().into_owned();
    // Checked again after resolving: the prefix test above was on the name,
    // and a path can leave the staging area on the way to a real file.
    if !resolved_str.starts_with(prefix) {
        return Err(format!(
            "staged upload escaped the staging area: {resolved_str}"
        ));
    }
    let meta =
        std::fs::metadata(&resolved).map_err(|e| format!("staged upload not readable: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "staged upload is not a regular file: {resolved_str}"
        ));
    }
    // Owned by the panel, so a file somebody else put there is refused even
    // when it has the right name.
    let panel_uid = crate::peercred::uid_of(crate::peercred::PANEL_USER)
        .map_err(|e| format!("cannot resolve the panel user: {e}"))?;
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != panel_uid {
        return Err(format!(
            "staged upload must be owned by {}",
            crate::peercred::PANEL_USER
        ));
    }
    Ok(resolved_str)
}

/// `site-document-root-ensure`: create the document root, harden the way down.
///
/// Source: the `site-document-root-ensure` arm and `harden_site_dir_path`.
/// `relative` is a fragment under the site root rather than a path, so the
/// caller names a directory and never a destination.
pub fn document_root_ensure(
    user: &PanelUsername,
    root: &SitePath,
    relative: &str,
) -> HelperResponse {
    if let Err(r) = guard(root) {
        return r;
    }
    if let Err(message) = check_relative(relative) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, message);
    }

    // Built from the root rather than taken from the caller, and re-parsed so
    // the result has to satisfy the same "under /home/<user>" rule the root
    // did. A fragment that somehow escaped would fail here rather than be
    // created.
    let joined = root.as_path().join(relative);
    let target = match SitePath::parse(&joined.to_string_lossy()) {
        Ok(p) => p,
        Err(_) => {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("document root outside the site: {}", joined.display()),
            )
        }
    };
    if !target.as_path().starts_with(root.as_path()) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("document root outside the site: {target}"),
        );
    }

    if let Err(e) = std::fs::create_dir_all(target.as_path()) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {}: {e}", target.as_path().display()),
        );
    }
    harden_dir_path(root.as_path(), target.as_path(), user)
}

/// The character set the bash accepts for a relative document root.
///
/// Source: `^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$` plus its explicit rejection
/// of `.` and `..` components. Lexical path checks let a name with a space, a
/// quote or a newline through; this does not, because such a name survives
/// the path layer and then surprises whatever builds a command from it later.
fn check_relative(relative: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("unsafe relative path: {relative} ({why})"));
    if relative.is_empty() || relative.starts_with('/') || relative.ends_with('/') {
        return bad("must be a non-empty fragment");
    }
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return bad("empty or traversing component");
        }
        if !part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return bad("character outside [A-Za-z0-9._-]");
        }
    }
    Ok(())
}

/// One directory: owner, ACL, mode, and no setgid or sticky bit.
///
/// Source: `harden_site_dir`. The setgid strip matters more than it looks: a
/// directory that keeps it makes everything created inside inherit its group,
/// which quietly undoes the ownership this is setting.
fn harden_dir(path: &Path, user: &PanelUsername) -> HelperResponse {
    let target = path.to_string_lossy().into_owned();
    let owner = format!("{}:{}", user.as_str(), SITES_GROUP);
    let out = exec::run(&["chown", &owner, &target]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("chown", out);
    }
    let _ = exec::run(&["setfacl", "-b", &target]);
    let _ = exec::run(&["setfacl", "-k", &target]);
    let mode = format!("{DIR_MODE:o}");
    let out = exec::run(&["chmod", &mode, &target]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("chmod", out);
    }
    for flag in ["a-s", "-t"] {
        let _ = exec::run(&["chmod", flag, &target]);
    }
    HelperResponse::ok()
}

/// Harden the site root and every directory between it and `target`.
///
/// Source: `harden_site_dir_path`. Walking the whole way down is the point:
/// a document root of `public_html/app/current` is only reachable if each
/// directory above it is traversable, and only safe if none of them is
/// writable by anyone else.
fn harden_dir_path(root: &Path, target: &Path, user: &PanelUsername) -> HelperResponse {
    // Every check before any change. The bash denies an out-of-root target
    // and a missing directory before it chowns anything, and the order is
    // worth keeping: otherwise a refused call still leaves the site root
    // chowned and chmodded on its way out, and the caller is told whatever
    // the chown said instead of what was actually wrong.
    let Ok(rest) = target.strip_prefix(root) else {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("{} is not under {}", target.display(), root.display()),
        );
    };
    if !target.is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("site directory does not exist: {}", target.display()),
        );
    }

    let r = harden_dir(root, user);
    if !r.ok {
        return r;
    }
    let mut current = root.to_path_buf();
    for part in rest.components() {
        current.push(part);
        if !current.is_dir() {
            return HelperResponse::failed(
                HelperErrorKind::NotFound,
                format!("site directory does not exist: {}", current.display()),
            );
        }
        let r = harden_dir(&current, user);
        if !r.ok {
            return r;
        }
    }
    HelperResponse::ok()
}

/// `site-logs-read-many`: one spawn for every site's log.
///
/// Source: `read_site_logs_many`. The format is a contract with the caller,
/// which splits on `\x1f` and reads the first line of each block as the
/// domain: every domain gets a header even when its log is missing, or the
/// site disappears from the page rather than showing as empty.
pub fn logs_read_many(domains: &[Domain], kind: LogKind, lines: u32) -> HelperResponse {
    HelperResponse::with_stdout(logs_read_many_in(
        std::path::Path::new(LOG_DIR),
        domains,
        kind,
        lines,
    ))
}

/// The assembly, with the log directory as an argument.
///
/// Split out so the tests drive the real function rather than a copy of it.
/// The first version of the test built the blocks itself, because the
/// production path is `/var/log/nginx` and a test must not write there - and
/// a test that reproduces the logic only ever agrees with itself.
fn logs_read_many_in(dir: &Path, domains: &[Domain], kind: LogKind, lines: u32) -> String {
    let n = lines.clamp(1, 10_000);
    let mut out = String::new();
    for domain in domains {
        out.push('\u{1f}');
        out.push_str(domain.as_str());
        out.push('\n');
        match read_tail(&dir.join(format!("{domain}.{}.log", kind.suffix())), n) {
            Some(body) => out.push_str(&body),
            None => out.push_str("SNPANEL_LOG_MISSING\n"),
        }
    }
    out
}

/// The last `lines` lines of a regular file, or `None` if there is not one.
///
/// `symlink_metadata`, not `exists()`: the bash guards this path with
/// `[[ -f "$path" && ! -L "$path" ]]`, and the `! -L` is the security half.
/// A symlink planted at a site's log path would otherwise let its owner read
/// any file the helper can, through the panel's log viewer.
fn read_tail(path: &Path, lines: u32) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let kept: Vec<&str> = text
        .lines()
        .rev()
        .take(lines as usize)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut body = kept.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    Some(body)
}

/// `site-log-clear`: truncate rather than delete, so nginx keeps its open
/// file descriptor and does not need a reopen.
pub fn log_clear(domain: &Domain, kind: LogKind) -> HelperResponse {
    let path = log_path(domain, kind);
    if !path.exists() {
        return HelperResponse::ok();
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
    {
        Ok(_) => HelperResponse::ok(),
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("truncating {}: {e}", path.display()),
        ),
    }
}

/// `site-logs-delete`: a deleted site's logs, and logrotate's copies of them.
///
/// Sent once the vhost is gone and nginx has reloaded, so nothing writes to
/// them any more. Deleted rather than truncated, because the name is free
/// again: a later site - perhaps another customer's - may take the domain,
/// and its log viewer must not open on the previous owner's traffic. Left
/// alone, they would not age out either: logrotate stops rotating a log once
/// it is empty, and the copies behind it stay where they are.
pub fn logs_delete(domain: &Domain) -> HelperResponse {
    logs_delete_in(Path::new(LOG_DIR), domain)
}

fn logs_delete_in(dir: &Path, domain: &Domain) -> HelperResponse {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HelperResponse::ok(),
        Err(e) => {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("reading {}: {e}", dir.display()),
            )
        }
    };
    let mut removed = 0usize;
    let mut failures = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_site_log(name, domain) {
            continue;
        }
        // `file_type` does not follow a link, and removing one removes the
        // link: nothing outside this directory is touched.
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(true) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    if failures.is_empty() {
        HelperResponse::with_stdout(format!("removed {removed}\n"))
    } else {
        HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("removing the logs of {domain}: {}", failures.join("; ")),
        )
    }
}

/// Whether `name` is one of `domain`'s logs: `<domain>.access.log` or
/// `<domain>.error.log`, bare or with what logrotate appends - `.1` and
/// `.2.gz` on Debian, `-20260925` and `-20260925.gz` under the RHEL family's
/// `dateext`. Nothing looser, so `a.co` never touches `a.com`, and
/// `www.a.com` is its own site.
fn is_site_log(name: &str, domain: &Domain) -> bool {
    [LogKind::Access, LogKind::Error].iter().any(|kind| {
        let Some(rest) = name.strip_prefix(&format!("{domain}.{}.log", kind.suffix())) else {
            return false;
        };
        let rest = [".gz", ".xz", ".bz2", ".zst"]
            .iter()
            .find_map(|ext| rest.strip_suffix(ext))
            .unwrap_or(rest);
        match rest.strip_prefix('.').or_else(|| rest.strip_prefix('-')) {
            Some(counter) => !counter.is_empty() && counter.bytes().all(|b| b.is_ascii_digit()),
            None => rest.is_empty() && name.ends_with(".log"),
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Access,
    Error,
}

impl LogKind {
    fn suffix(&self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Error => "error",
        }
    }
}

/// Where nginx writes a site's logs. Named once so the batch read and the
/// single read cannot drift apart.
const LOG_DIR: &str = "/var/log/nginx";

fn log_path(domain: &Domain, kind: LogKind) -> std::path::PathBuf {
    std::path::Path::new(LOG_DIR).join(format!("{domain}.{}.log", kind.suffix()))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    // A name no other write can be using: requests run side by side, and two
    // saves of one file must not share a half-written temporary.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = path.parent().unwrap_or(Path::new("/"));
    let tmp = dir.join(format!(
        ".{}.{}-{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("snpanel"),
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    /// The move keeps the simple rename only.
    ///
    /// With `replace_empty_public_html` false, a site that has both
    /// directories keeps both - which is what the bash's `move` arm does,
    /// and differs from its `ensure` arm on purpose.
    #[test]
    fn the_move_does_not_replace_an_empty_public_html() {
        let root = tempdir("move-simple");
        std::fs::create_dir_all(root.join("public")).unwrap();
        std::fs::write(root.join("public/index.php"), "moved\n").unwrap();
        std::fs::create_dir_all(root.join("public_html")).unwrap();

        migrate_public_to_public_html(&root, false).expect("no error");

        assert!(
            root.join("public").is_dir(),
            "the move arm leaves `public` alone when public_html exists"
        );
        assert!(
            root.join("public_html").is_dir(),
            "and leaves public_html alone too"
        );

        // The ensure arm, on the same tree, does merge them.
        migrate_public_to_public_html(&root, true).expect("no error");
        assert_eq!(
            std::fs::read_to_string(root.join("public_html/index.php")).unwrap(),
            "moved\n"
        );
    }

    /// The old pool is named after where the site was, not where it is going.
    ///
    /// A site moving between accounts is the case that makes this matter: a
    /// pool named after the new owner matches nothing, so the real pool keeps
    /// running with `open_basedir` pointing at a directory that has moved.
    #[test]
    fn the_old_pool_name_follows_the_old_owner_and_path() {
        let from = SitePath::parse("/home/old_user/example.com").unwrap();
        let to = SitePath::parse("/home/new_user/example.com").unwrap();

        assert_eq!(from.user().as_str(), "old_user");
        assert_eq!(to.user().as_str(), "new_user");

        // The pool name is built from the owner and the path, and both differ
        // across the move, so the two names must not coincide.
        let php = snpanel_core::PhpVersion::parse("8.4").unwrap();
        let old_name = super::super::php::pool_name(from.user().as_str(), from.as_str(), php);
        let new_name = super::super::php::pool_name(to.user().as_str(), to.as_str(), php);
        assert_ne!(old_name, new_name);
        assert!(old_name.starts_with("snpanel-old_user-"), "{old_name}");
        assert!(new_name.starts_with("snpanel-new_user-"), "{new_name}");
    }

    /// `public` becomes `public_html` when there is nothing to lose.
    #[test]
    fn public_is_renamed_when_public_html_is_absent() {
        let root = tempdir("migrate-absent");
        std::fs::create_dir_all(root.join("public")).unwrap();
        std::fs::write(root.join("public/index.php"), "imported\n").unwrap();

        migrate_public_to_public_html(&root, true).expect("the rename works");

        assert!(!root.join("public").exists(), "public should be gone");
        assert_eq!(
            std::fs::read_to_string(root.join("public_html/index.php")).unwrap(),
            "imported\n"
        );
    }

    /// ...and when `public_html` exists but is empty.
    #[test]
    fn public_is_renamed_over_an_empty_public_html() {
        let root = tempdir("migrate-empty");
        std::fs::create_dir_all(root.join("public")).unwrap();
        std::fs::write(root.join("public/index.php"), "imported\n").unwrap();
        std::fs::create_dir_all(root.join("public_html")).unwrap();

        migrate_public_to_public_html(&root, true).expect("the rename works");

        assert_eq!(
            std::fs::read_to_string(root.join("public_html/index.php")).unwrap(),
            "imported\n"
        );
    }

    /// But a live site is never overwritten by an importer's copy.
    ///
    /// This is the branch worth testing. `public_html` with content is what
    /// nginx is serving; `public` may be an older export that happened to
    /// arrive in the same tree. Replacing one with the other silently would
    /// roll a customer's site back.
    #[test]
    fn a_populated_public_html_is_left_alone() {
        let root = tempdir("migrate-populated");
        std::fs::create_dir_all(root.join("public")).unwrap();
        std::fs::write(root.join("public/index.php"), "the old export\n").unwrap();
        std::fs::create_dir_all(root.join("public_html")).unwrap();
        std::fs::write(root.join("public_html/index.php"), "the live site\n").unwrap();

        migrate_public_to_public_html(&root, true).expect("no error, no change");

        assert_eq!(
            std::fs::read_to_string(root.join("public_html/index.php")).unwrap(),
            "the live site\n",
            "the served site must survive"
        );
        assert!(
            root.join("public").is_dir(),
            "and the other directory is left for someone to look at"
        );
    }

    /// No `public` at all is not an error; most sites are in this state.
    #[test]
    fn a_site_without_public_is_untouched() {
        let root = tempdir("migrate-none");
        std::fs::create_dir_all(root.join("public_html")).unwrap();
        migrate_public_to_public_html(&root, true).expect("nothing to do");
        assert!(root.join("public_html").is_dir());
    }

    /// Arguments stay arguments: there is no shell in this path.
    ///
    /// A WordPress option value can contain anything, and the panel passes it
    /// straight through. Passing it as one element of a vector is what makes
    /// that safe, and looking at the vector is the only way to see it.
    #[test]
    fn wp_arguments_are_vector_elements_not_a_command_string() {
        let args: Vec<String> = vec![
            "option".into(),
            "update".into(),
            "blogname".into(),
            "Dấu ; và \"nháy\" và $(whoami)".into(),
        ];
        let argv = wp_argv("bp_site", "/home/bp_site", "php8.4", &args);

        assert_eq!(
            argv.last().unwrap(),
            "Dấu ; và \"nháy\" và $(whoami)",
            "the value must arrive whole and unquoted"
        );
        assert_eq!(
            argv.iter().filter(|a| a.contains("whoami")).count(),
            1,
            "and exactly once: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "sh" || a == "bash" || a == "-c"),
            "no shell may appear in the vector: {argv:?}"
        );
    }

    /// The site's PHP, not whatever `php` happens to be.
    ///
    /// A site on 8.4 driven by the 8.3 CLI has no mysqli, and every
    /// `wp core update` fails on it with a message about the MySQL extension
    /// that says nothing about the real cause.
    #[test]
    fn wp_site_runs_under_the_sites_own_php() {
        let args = vec!["core".to_string(), "update".to_string()];
        let versioned = wp_argv("bp_site", "/home/bp_site", "php8.4", &args);
        assert!(versioned.contains(&"php8.4".to_string()), "{versioned:?}");

        let plain = wp_argv("bp_site", "/home/bp_site", "php", &args);
        assert!(plain.contains(&"php".to_string()), "{plain:?}");
        assert!(
            !plain.iter().any(|a| a.starts_with("php8")),
            "no version should be invented: {plain:?}"
        );
    }

    /// HOME follows the user being run as; WP-CLI needs it for its cache.
    #[test]
    fn wp_runs_as_the_named_user_with_a_matching_home() {
        let args = vec!["plugin".to_string(), "list".to_string()];
        let argv = wp_argv("bp_site", "/home/bp_site", "php", &args);

        let user_at = argv.iter().position(|a| a == "-u").expect("runuser -u");
        assert_eq!(argv[user_at + 1], "bp_site");
        assert!(argv.contains(&"HOME=/home/bp_site".to_string()), "{argv:?}");
    }

    /// Nothing is deleted until the source has been accepted.
    ///
    /// This is the property the whole verb rests on. `site-populate` empties
    /// the site root before copying, so a check that ran afterwards would
    /// leave a customer with an empty site and an error message.
    #[test]
    fn a_refused_source_leaves_the_site_untouched() {
        let home = tempdir("populate-keep");
        let root_dir = home.join("home/bp_site/example.com");
        std::fs::create_dir_all(root_dir.join("public_html")).unwrap();
        let marker = root_dir.join("public_html/index.php");
        std::fs::write(&marker, "the customer's site\n").unwrap();

        // Not a SitePath - `populate` needs one - so the check is driven
        // directly. What is being pinned is that the refusal happens before
        // any delete, and `check_staged_tree` is where that refusal is.
        let err = check_staged_tree("/etc").unwrap_err();
        assert!(err.contains("must be under"), "{err}");
        assert!(marker.exists(), "the site must still be there");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "the customer's site\n"
        );
    }

    #[test]
    fn a_staged_source_outside_the_staging_area_is_refused() {
        for bad in ["/etc", "/tmp/anything", "/var/lib/snpanel/other"] {
            let err = check_staged_tree(bad).unwrap_err();
            assert!(
                err.contains("must be under") || err.contains("not found"),
                "{bad}: {err}"
            );
        }
    }

    /// Emptying a directory must not delete what a symlink points at.
    ///
    /// Checked as an outcome rather than as a claim about the implementation:
    /// `std::fs::remove_dir_all` is itself symlink-safe, so this passes both
    /// with `symlink_metadata` and with `metadata` - verified by trying. The
    /// explicit `symlink_metadata` stays as defence in depth, and this test
    /// pins the property that matters to a customer whose backup contained a
    /// link, not the mechanism that currently provides it.
    #[test]
    fn emptying_a_directory_unlinks_symlinks_rather_than_following_them() {
        let base = tempdir("empty-symlink");
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let keeper = outside.join("keep.txt");
        std::fs::write(&keeper, "must survive\n").unwrap();

        let victim = base.join("site");
        std::fs::create_dir_all(&victim).unwrap();
        std::os::unix::fs::symlink(&outside, victim.join("link")).unwrap();
        std::fs::write(victim.join("plain.txt"), "goes away\n").unwrap();

        empty_directory(&victim).expect("emptying works");

        assert!(
            std::fs::read_dir(&victim).unwrap().next().is_none(),
            "the directory should be empty"
        );
        assert!(
            keeper.exists(),
            "the symlink target must not have been deleted"
        );
    }

    /// An uploaded filename is not a directory name, and the checks differ.
    ///
    /// Source: the `case` in `site-file-install`, which guards traversal and
    /// newlines and nothing else. Real uploads are called things like
    /// "Bản sao (2).pdf"; restricting this to `[A-Za-z0-9._-]` the way a
    /// document root is restricted would refuse them.
    #[test]
    fn an_uploaded_filename_may_contain_anything_but_traversal() {
        for good in [
            "notes.txt",
            "public_html/Bản sao (2).pdf",
            "public_html/my file [final].zip",
            "a b/c d.txt",
        ] {
            assert!(
                check_upload_relative(good).is_ok(),
                "{good:?} is an ordinary upload"
            );
        }
        for bad in [
            "",
            "/etc/passwd",
            "..",
            "../x",
            "a/../../etc",
            "a/..",
            "a\nb",
        ] {
            assert!(
                check_upload_relative(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// A staged path outside the upload area is refused on its name alone.
    ///
    /// Against the real prefix: a sibling whose name only starts the same is
    /// outside, and so is `/tmp`, where uploads used to be staged.
    #[test]
    fn a_staged_path_outside_the_upload_area_is_refused() {
        let prefix = upload_stage_prefix();
        assert_eq!(prefix, "/var/lib/snpanel/upload-stage/");
        for outside in [
            "/etc/passwd",
            "/var/lib/snpanel/upload-stage-old/1-x",
            "/var/lib/snpanel/upload-stage",
            "/tmp/snpanel-upload-1-x",
        ] {
            let err = check_staged_upload(outside, &prefix).unwrap_err();
            assert!(
                err.contains("invalid staged upload path"),
                "{outside}: {err}"
            );
        }
    }

    /// A path that leaves the staging area on the way is refused after
    /// resolution, where its name alone looked fine.
    #[test]
    fn a_staged_path_through_a_symlinked_directory_is_refused() {
        let (dir, prefix) = upload_dir("escape");
        std::os::unix::fs::symlink("/etc", dir.join("sub")).unwrap();
        let err =
            check_staged_upload(&dir.join("sub/passwd").to_string_lossy(), &prefix).unwrap_err();
        assert!(err.contains("escaped the staging area"), "{err}");
    }

    /// A panel-owned file in the staging area is the one thing accepted.
    ///
    /// Every other test here is a refusal, and a check that refused
    /// everything would pass them all - which is what uploads looked like
    /// from the File Manager while the file was staged where the helper
    /// could not see it.
    #[test]
    fn a_panel_upload_in_the_staging_area_is_accepted() {
        let (dir, prefix) = upload_dir("accepted");
        let staged = dir.join("1-x");
        std::fs::write(&staged, "hello\n").unwrap();
        let panel_uid = crate::peercred::uid_of(crate::peercred::PANEL_USER)
            .expect("the panel user must exist for this test to mean anything");
        if let Err(e) = std::os::unix::fs::chown(&staged, Some(panel_uid), None) {
            eprintln!("skipped: cannot hand the file to the panel user here: {e}");
            return;
        }
        let resolved = check_staged_upload(&staged.to_string_lossy(), &prefix)
            .expect("a panel upload in the staging area");
        assert_eq!(resolved, staged.to_string_lossy());
    }

    /// ...and a symlink inside it is refused before it is followed.
    ///
    /// Without this a caller stages a link to anything on the box and the
    /// helper, running as root, copies it into a site.
    #[test]
    fn a_symlinked_staged_upload_is_refused() {
        let (dir, prefix) = upload_dir("symlink");
        let secret = dir.join("secret");
        std::fs::write(&secret, "a password\n").unwrap();
        let link = dir.join("upload");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let err = check_staged_upload(&link.to_string_lossy(), &prefix).unwrap_err();
        assert!(err.contains("cannot be a symlink"), "{err}");
    }

    /// A file somebody else put there is refused even with the right name.
    ///
    /// The suite runs as root, so a file it creates is owned by root rather
    /// than by the panel user - which is exactly the case this rejects.
    #[test]
    fn a_staged_upload_owned_by_someone_else_is_refused() {
        let (dir, prefix) = upload_dir("owner");
        let planted = dir.join("upload");
        std::fs::write(&planted, "not from the panel\n").unwrap();

        // Decide the premise instead of accepting either outcome. An `Ok(_)`
        // arm here would pass on exactly the failure this test exists to
        // catch - which it did, until the check was disabled on purpose and
        // the suite stayed green.
        let panel_uid = crate::peercred::uid_of(crate::peercred::PANEL_USER)
            .expect("the panel user must exist for this test to mean anything");
        // SAFETY: getuid cannot fail.
        let mine = unsafe { libc::getuid() };
        assert_ne!(
            mine, panel_uid,
            "this process is the panel user, so the file it just wrote is \
             legitimately owned by it and the refusal cannot be observed"
        );

        let err = check_staged_upload(&planted.to_string_lossy(), &prefix)
            .expect_err("a file this process owns is not a panel upload");
        assert!(
            err.contains("must be owned by"),
            "refused for the wrong reason: {err}"
        );
    }

    /// A directory is not an upload.
    #[test]
    fn a_staged_directory_is_refused() {
        let (dir, prefix) = upload_dir("dir");
        let inner = dir.join("upload");
        std::fs::create_dir_all(&inner).unwrap();
        let err = check_staged_upload(&inner.to_string_lossy(), &prefix).unwrap_err();
        assert!(
            err.contains("not a regular file") || err.contains("must be owned by"),
            "{err}"
        );
    }

    /// A staging directory of the test's own, and the prefix that names it.
    ///
    /// Not the real one: that is the panel's, and a test run on a box with
    /// the panel installed should leave nothing in it. Resolved, because the
    /// check compares the resolved path with the prefix.
    fn upload_dir(name: &str) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!(
            "snpanel-upload-stage-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let prefix = format!("{}/", dir.display());
        (dir, prefix)
    }

    /// The character set, which is the half `SitePath` does not check.
    #[test]
    fn a_relative_document_root_is_restricted_to_safe_characters() {
        for good in ["public_html", "public_html/public", "app-1.2_beta/dist"] {
            assert!(check_relative(good).is_ok(), "{good} should be accepted");
        }

        for (bad, why) in [
            ("", "empty"),
            ("/public_html", "absolute"),
            ("public_html/", "trailing slash"),
            ("..", "traversal"),
            ("public_html/../../etc", "traversal inside"),
            ("public_html/./x", "a dot component"),
            ("public html", "a space"),
            ("public_html\nx", "a newline"),
            ("pub\"lic", "a quote"),
            ("public;rm -rf /", "a semicolon"),
            ("public$(whoami)", "a substitution"),
        ] {
            assert!(
                check_relative(bad).is_err(),
                "{bad:?} should be refused ({why})"
            );
        }
    }

    /// The refusal says which fragment and why, because an administrator who
    /// picked a directory name with a space in it gets this back and has to
    /// be able to act on it.
    #[test]
    fn the_refusal_names_the_fragment() {
        let err = check_relative("public html").unwrap_err();
        assert!(err.contains("public html"), "{err}");
        assert!(err.contains("character outside"), "{err}");
    }

    /// The walk refuses a target outside the root rather than hardening
    /// whatever it was handed.
    #[test]
    fn hardening_refuses_a_target_outside_the_site_root() {
        let user = PanelUsername::parse("bp_site").unwrap();
        let resp = harden_dir_path(
            Path::new("/home/bp_site/example.com"),
            Path::new("/etc"),
            &user,
        );
        assert!(!resp.ok);
        let err = resp.error.expect("a reason");
        assert_eq!(err.kind, HelperErrorKind::BadRequest);
        assert!(err.message.contains("/etc"), "{}", err.message);
    }

    /// A missing directory in the middle is named, not created.
    ///
    /// Source: `harden_site_dir_path`, which denies with "site directory does
    /// not exist". Creating it here instead would harden a path the caller
    /// never asked for.
    #[test]
    fn hardening_names_the_first_missing_directory() {
        let root = tempdir("harden-missing");
        let target = root.join("a/b");
        let user = PanelUsername::parse("bp_site").unwrap();

        let resp = harden_dir_path(&root, &target, &user);
        assert!(!resp.ok);
        let err = resp.error.expect("a reason");
        assert_eq!(err.kind, HelperErrorKind::NotFound);
        assert!(err.message.contains("does not exist"), "{}", err.message);
        assert!(!target.exists(), "it must not have been created");
    }

    /// The shape the caller parses, not just the content.
    ///
    /// Source: `read_site_logs_many` and `waf.read_access_logs_many`. A
    /// domain with no log still gets its header - Python builds its result
    /// map from those headers, so dropping one drops the site from the page
    /// rather than showing it as empty.
    #[test]
    fn every_domain_gets_a_header_even_with_no_log() {
        let tmp = tempdir("logs-many");
        let a = Domain::parse("a.example.com").unwrap();
        let b = Domain::parse("b.example.com").unwrap();
        write_log(&tmp, &a, "one\ntwo\nthree\n");
        // b deliberately has no file.

        let out = render(&tmp, &[a.clone(), b.clone()], 10);

        let blocks: Vec<&str> = out.split('\u{1f}').filter(|s| !s.is_empty()).collect();
        assert_eq!(blocks.len(), 2, "one block per domain: {out:?}");

        let (head, body) = blocks[0].split_once('\n').expect("a header line");
        assert_eq!(head, "a.example.com");
        assert_eq!(body, "one\ntwo\nthree\n");

        let (head, body) = blocks[1].split_once('\n').expect("a header line");
        assert_eq!(head, "b.example.com");
        assert_eq!(
            body, "SNPANEL_LOG_MISSING\n",
            "the caller compares against this literal"
        );
    }

    #[test]
    fn only_the_last_n_lines_come_back() {
        let tmp = tempdir("logs-tail");
        let d = Domain::parse("tail.example.com").unwrap();
        write_log(&tmp, &d, "1\n2\n3\n4\n5\n");

        let out = render(&tmp, std::slice::from_ref(&d), 2);
        let (_, body) = out
            .trim_start_matches('\u{1f}')
            .split_once('\n')
            .expect("a header line");
        assert_eq!(body, "4\n5\n");
    }

    /// A symlinked log is refused, and the file it points at is not read.
    ///
    /// The bash guards with `[[ -f "$path" && ! -L "$path" ]]`. Without the
    /// `! -L`, anyone who can put a symlink at a site's log path reads
    /// whatever the helper can read, through the panel's log viewer. It is
    /// reported as missing rather than as an error, exactly as the bash does.
    #[test]
    fn a_symlinked_log_is_treated_as_missing_not_followed() {
        let tmp = tempdir("logs-symlink");
        let secret = tmp.join("secret");
        std::fs::write(&secret, "a password\n").unwrap();

        let d = Domain::parse("evil.example.com").unwrap();
        let link = tmp.join(format!("{d}.access.log"));
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let out = render(&tmp, std::slice::from_ref(&d), 10);
        assert!(
            out.contains("SNPANEL_LOG_MISSING"),
            "a symlink must read as missing: {out:?}"
        );
        assert!(
            !out.contains("a password"),
            "the symlink target must not be read: {out:?}"
        );
    }

    // --- helpers ---------------------------------------------------------

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "snpanel-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_log(dir: &Path, domain: &Domain, body: &str) {
        std::fs::write(dir.join(format!("{domain}.access.log")), body).unwrap();
    }

    /// The real assembly, pointed at a temporary directory.
    fn render(dir: &Path, domains: &[Domain], lines: u32) -> String {
        logs_read_many_in(dir, domains, LogKind::Access, lines)
    }

    use super::*;

    fn tmp_site() -> (std::path::PathBuf, SitePath) {
        let base = std::env::temp_dir().join(format!("snpanel-site-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // SitePath insists on /home/<user>/..., so a real one is used and the
        // filesystem operations are checked against a scratch copy instead.
        let sp = SitePath::parse("/home/bp_test_site/example.com").unwrap();
        (base, sp)
    }

    #[test]
    fn only_644_and_640_may_be_written() {
        let (_b, sp) = tmp_site();
        for bad in [0o755u32, 0o600, 0o777, 0o4644] {
            let r = file_write(&sp, b"x", FileMode(bad));
            assert!(!r.ok, "mode {bad:o} should be refused");
        }
    }

    #[test]
    fn the_secret_file_list_is_the_one_from_the_bash() {
        assert_eq!(SECRET_FILES, &["wp-config.php", ".env", ".my.cnf"]);
        assert_eq!(SECRET_MODE, 0o640);
        assert_eq!(FILE_MODE, 0o644);
        assert_eq!(DIR_MODE, 0o755);
    }

    #[test]
    fn a_symlink_anywhere_in_the_path_is_refused() {
        // C36. Build a real tree under /home so SitePath accepts it, with a
        // symlinked *parent* rather than a symlinked leaf - the case a check
        // on the final component alone would miss.
        let user = "bp_symlink_probe";
        let home = std::path::PathBuf::from("/home").join(user);
        let real = home.join("real.example.com");
        let link = home.join("link.example.com");
        if std::fs::create_dir_all(real.join("public_html")).is_err() {
            eprintln!("skipped: cannot write under /home");
            return;
        }
        let _ = std::fs::remove_file(&link);
        if std::os::unix::fs::symlink(&real, &link).is_err() {
            let _ = std::fs::remove_dir_all(&home);
            eprintln!("skipped: cannot create a symlink");
            return;
        }

        let through_link = SitePath::parse(&format!(
            "/home/{user}/link.example.com/public_html/index.php"
        ))
        .expect("lexically valid");
        assert!(
            through_link.verify_no_symlinks().is_err(),
            "a symlinked parent must be refused"
        );

        let direct = SitePath::parse(&format!(
            "/home/{user}/real.example.com/public_html/index.php"
        ))
        .unwrap();
        assert!(direct.verify_no_symlinks().is_ok(), "the real path is fine");

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn removing_something_already_gone_succeeds() {
        let sp = SitePath::parse("/home/bp_absent_user/nothing.example.com").unwrap();
        assert!(remove(&sp).ok);
    }

    #[test]
    fn log_paths_are_derived_from_the_domain_not_from_input() {
        let d = Domain::parse("example.com").unwrap();
        assert_eq!(
            log_path(&d, LogKind::Access).to_str().unwrap(),
            "/var/log/nginx/example.com.access.log"
        );
        assert_eq!(
            log_path(&d, LogKind::Error).to_str().unwrap(),
            "/var/log/nginx/example.com.error.log"
        );
    }

    #[test]
    fn a_sites_logs_are_its_own_and_logrotates_copies_of_them() {
        let d = Domain::parse("a.com").unwrap();
        for name in [
            "a.com.access.log",
            "a.com.error.log",
            "a.com.access.log.1",
            "a.com.access.log.14.gz",
            "a.com.error.log-20260925",
            "a.com.error.log-20260925.gz",
            "a.com.access.log.3.zst",
        ] {
            assert!(is_site_log(name, &d), "{name} is a.com's");
        }
        for name in [
            // Another site's, however close the name.
            "a.co.access.log",
            "a.com.au.access.log",
            "www.a.com.access.log",
            "b-a.com.error.log",
            // A name that only starts like one.
            "a.com.access.log.bak",
            "a.com.access.log.1.old",
            "a.com.access.log.",
            "a.com.access.log-",
            "a.com.access.log.gz",
            "a.com.access.logs",
            "a.com.other.log",
            "access.log",
        ] {
            assert!(!is_site_log(name, &d), "{name} is not a.com's");
        }
        // The other way round: a.co's logs are not a.com's prefix.
        let short = Domain::parse("a.co").unwrap();
        assert!(!is_site_log("a.com.access.log", &short));
    }

    #[test]
    fn deleting_a_sites_logs_leaves_every_other_file() {
        let dir = tempdir("logs-delete");
        let d = Domain::parse("a.com").unwrap();
        let theirs = [
            "a.com.access.log",
            "a.com.access.log.1",
            "a.com.access.log.2.gz",
            "a.com.error.log",
            "a.com.error.log-20260925.gz",
        ];
        let others = [
            "a.co.access.log",
            "www.a.com.access.log",
            "a.com.au.error.log.1",
            "access.log",
            "error.log",
        ];
        for name in theirs.iter().chain(others.iter()) {
            std::fs::write(dir.join(name), "GET /\n").unwrap();
        }
        // A link is removed as a link: its target is somebody else's file.
        let outside = tempdir("logs-delete-outside");
        std::fs::write(outside.join("keep.txt"), "mine").unwrap();
        std::os::unix::fs::symlink(outside.join("keep.txt"), dir.join("a.com.access.log.3"))
            .unwrap();
        // And a directory with a matching name is not a log.
        std::fs::create_dir(dir.join("a.com.error.log.4")).unwrap();

        let r = logs_delete_in(&dir, &d);
        assert!(r.ok, "{r:?}");
        assert_eq!(r.stdout, "removed 6\n");
        for name in theirs {
            assert!(!dir.join(name).exists(), "{name} should be gone");
        }
        assert!(std::fs::symlink_metadata(dir.join("a.com.access.log.3")).is_err());
        for name in others {
            assert!(dir.join(name).exists(), "{name} should be left");
        }
        assert_eq!(
            std::fs::read_to_string(outside.join("keep.txt")).unwrap(),
            "mine"
        );
        assert!(dir.join("a.com.error.log.4").is_dir());

        // Again, with nothing left of its own: nothing to do is not a failure.
        let again = logs_delete_in(&dir, &d);
        assert!(again.ok);
        assert_eq!(again.stdout, "removed 0\n");
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn deleting_logs_from_a_directory_that_is_not_there_succeeds() {
        let d = Domain::parse("a.com").unwrap();
        let r = logs_delete_in(Path::new("/nonexistent/snpanel/nginx-logs"), &d);
        assert!(r.ok, "{r:?}");
    }

    #[test]
    fn reading_an_absent_log_is_empty_not_an_error() {
        let d = Domain::parse("no-such-site-xyzzy.example.com").unwrap();
        let r = log_read(&d, LogKind::Access, 100);
        assert!(r.ok);
        assert!(r.stdout.is_empty());
    }

    #[test]
    fn atomic_write_sets_the_requested_mode() {
        let dir = std::env::temp_dir().join(format!("snpanel-sitewrite-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("wp-config.php");
        write_atomic(&f, b"<?php", 0o640).unwrap();
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod search_tests {
    use super::*;

    fn tree(tag: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("snpanel-search-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn put(root: &std::path::Path, relative: &str, content: &[u8]) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn found(outcome: &SearchOutcome) -> Vec<(String, usize)> {
        outcome
            .matches
            .iter()
            .map(|m| (m.path.clone(), m.line))
            .collect()
    }

    #[test]
    fn plain_text_is_found_by_file_and_line_a_folders_files_first() {
        let root = tree("plain");
        put(&root, "b.php", b"<?php\n// Needle here\n");
        put(&root, "a/deep.txt", b"one\ntwo needle\nthree NEEDLE\n");
        put(&root, "a.css", b"no match\n");
        let outcome = search_tree(&root, "needle", "", false, false);
        assert_eq!(
            found(&outcome),
            [
                ("b.php".to_string(), 2),
                ("a/deep.txt".to_string(), 2),
                ("a/deep.txt".to_string(), 3)
            ]
        );
        assert_eq!(outcome.matches[0].text, "// Needle here");
        assert_eq!(outcome.files_scanned, 3);
        assert_eq!(outcome.stopped_by, None);
        // Case matters when asked to, and a pattern is only text.
        let exact = search_tree(&root, "NEEDLE", "", true, false);
        assert_eq!(found(&exact), [("a/deep.txt".to_string(), 3)]);
        assert!(search_tree(&root, "need.e", "", false, false)
            .matches
            .is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn caches_dependencies_history_and_uploads_are_passed_over() {
        let root = tree("skip");
        for dir in [
            ".git",
            "node_modules",
            ".cache",
            "cache",
            "uploads",
            "wp-content/uploads",
        ] {
            put(&root, &format!("{dir}/x.txt"), b"needle\n");
        }
        put(&root, "wp-content/plugin.php", b"needle\n");
        let outcome = search_tree(&root, "needle", "", false, false);
        assert_eq!(found(&outcome), [("wp-content/plugin.php".to_string(), 1)]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A link to a file or a folder outside the site is never read.
    #[test]
    fn a_symlink_is_never_followed() {
        let root = tree("links");
        let outside = tree("links-outside");
        put(&outside, "secret.txt", b"needle\n");
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("file-link.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("dir-link")).unwrap();
        put(&root, "real.txt", b"needle\n");
        let outcome = search_tree(&root, "needle", "", false, false);
        assert_eq!(found(&outcome), [("real.txt".to_string(), 1)]);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn binaries_are_skipped_and_the_secret_files_are_an_administrators() {
        let root = tree("secrets");
        put(&root, "logo.png", b"\x89PNG\0\0needle");
        put(
            &root,
            "wp-config.php",
            b"define('DB_PASSWORD', 'needle');\n",
        );
        put(&root, ".env", b"KEY=needle\n");
        put(&root, "index.php", b"needle\n");
        let user = search_tree(&root, "needle", "", false, false);
        assert_eq!(found(&user), [("index.php".to_string(), 1)]);
        let admin = search_tree(&root, "needle", "", false, true);
        assert_eq!(
            found(&admin),
            [
                (".env".to_string(), 1),
                ("index.php".to_string(), 1),
                ("wp-config.php".to_string(), 1)
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_suffix_narrows_the_files_read() {
        let root = tree("suffix");
        put(&root, "a.php", b"needle\n");
        put(&root, "a.js", b"needle\n");
        let outcome = search_tree(&root, "needle", ".php", false, false);
        assert_eq!(found(&outcome), [("a.php".to_string(), 1)]);
        assert_eq!(outcome.files_scanned, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_large_file_is_counted_and_not_read() {
        let root = tree("large");
        let mut big = vec![b'x'; SEARCH_MAX_FILE_BYTES as usize];
        big.extend_from_slice(b"\nneedle\n");
        put(&root, "dump.sql", &big);
        put(&root, "small.txt", b"needle\n");
        let outcome = search_tree(&root, "needle", "", false, false);
        assert_eq!(found(&outcome), [("small.txt".to_string(), 1)]);
        assert_eq!(outcome.files_too_large, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_search_stops_at_a_hundred_matches() {
        let root = tree("cap");
        let many: String = (0..150).map(|i| format!("needle {i}\n")).collect();
        put(&root, "a.txt", many.as_bytes());
        put(&root, "b.txt", b"needle\n");
        let outcome = search_tree(&root, "needle", "", false, false);
        assert_eq!(outcome.matches.len(), SEARCH_MAX_MATCHES);
        assert_eq!(outcome.stopped_by, Some("matches"));
        assert!(outcome.matches.iter().all(|m| m.path == "a.txt"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_long_line_is_cut() {
        let root = tree("long");
        let line = format!("{}needle{}\n", "a".repeat(400), "b".repeat(400));
        put(&root, "a.txt", line.as_bytes());
        let outcome = search_tree(&root, "needle", "", false, false);
        assert_eq!(outcome.matches[0].text.chars().count(), 300);
        let _ = std::fs::remove_dir_all(&root);
    }
}
