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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Access,
    Error,
}

impl LogKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "access" => Some(Self::Access),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    fn suffix(&self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Error => "error",
        }
    }
}

fn log_path(domain: &Domain, kind: LogKind) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/var/log/nginx/{domain}.{}.log", kind.suffix()))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("snpanel")
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
    fn only_the_two_log_kinds_parse() {
        assert_eq!(LogKind::parse("access"), Some(LogKind::Access));
        assert_eq!(LogKind::parse("error"), Some(LogKind::Error));
        for bad in ["", "Access", "../../etc/passwd", "access.log"] {
            assert!(LogKind::parse(bad).is_none(), "{bad:?}");
        }
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
