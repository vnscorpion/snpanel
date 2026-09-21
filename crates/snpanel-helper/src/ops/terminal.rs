//! `ops::terminal` - running a customer's command as the customer.
//!
//! Source: the `terminal-exec` arm of the bash helper.
//!
//! Three things here are load-bearing and none of them is the command.
//!
//! **The command never reaches a shell.** `AllowlistedArgv` has already
//! refused anything not on the list, and what is built below is an argv vector
//! handed to `execve` through `runuser`. A filename containing `; rm -rf /` is
//! an argument no program will match.
//!
//! **`open_basedir` is a tenant boundary, not a tidy-up.** The comment in the
//! bash records what it closed: PHP started from the terminal was completely
//! unconfined while the same site's PHP-FPM pool ran under `open_basedir`, so
//! `php -r "readfile('/home/other/...')"` read another customer's files. Site
//! files are world-readable by design and `/home/<user>` is 0751 - not
//! listable, but traversable if you know the name. It was verified on a live
//! server before the fix, and it printed `/etc/passwd`.
//!
//! **The boundary is the tenant's home, not one site root.** A customer with
//! several sites still has to work across them; the leak being closed is
//! between customers.

use std::path::{Path, PathBuf};

use snpanel_core::{PanelUsername, PhpVersion};
use snpanel_ipc::{AllowlistedArgv, HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: `HOME_ROOT`.
const HOME_ROOT: &str = "/home";

/// Source: `terminal_env` - and nothing else.
///
/// The environment is built, not inherited. `COMPOSER_HOME` and
/// `npm_config_cache` are set because without them both tools fall back to
/// `$HOME/.config` paths that may not exist for a site user, and then write
/// to `/tmp` or fail; `PATH` is fixed so a binary dropped into a writable
/// directory cannot shadow one of the allowed commands.
fn terminal_env(user: &str) -> Vec<(String, String)> {
    let home = format!("{HOME_ROOT}/{user}");
    vec![
        ("HOME".to_string(), home.clone()),
        ("COMPOSER_HOME".to_string(), format!("{home}/.composer")),
        ("npm_config_cache".to_string(), format!("{home}/.npm")),
        (
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        ),
    ]
}

/// Source: `terminal_open_basedir`.
///
/// `/var/lib/php/{sessions,uploads}/<user>` match the pool.  `/tmp` and
/// `/usr/share/php` are what Composer and PEAR-era libraries expect. Each
/// tool's own directory is appended at its call site, because the interpreter
/// has to be able to read the phar it is being asked to run.
pub(crate) fn open_basedir(user: &str) -> String {
    format!(
        "{HOME_ROOT}/{user}:/var/lib/php/sessions/{user}:/var/lib/php/uploads/{user}:\
         /tmp:/usr/share/php"
    )
}

/// Source: `require_terminal_cwd`.
///
/// Resolved first, then required to be the user's home or under it. Resolving
/// afterwards would let a symlink inside the home point anywhere and pass.
pub(crate) fn resolve_cwd(user: &str, raw: &str) -> Result<PathBuf, String> {
    let resolved = crate::ops::packages::readlink_m(Path::new(raw));
    let home = format!("{HOME_ROOT}/{user}");
    let text = resolved.to_string_lossy().into_owned();
    if text != home && !text.starts_with(&format!("{home}/")) {
        return Err(format!(
            "terminal cwd is not owned by panel Linux user {user}: {text}"
        ));
    }
    if !resolved.is_dir() {
        return Err(format!("terminal cwd is not a directory: {text}"));
    }
    Ok(resolved)
}

/// Source: `require_terminal_path_args`.
///
/// Every argument that is not a flag is resolved - relative ones against the
/// working directory - and required to land under the user's home.
///
/// The literal `..` checks come first and are on the **raw** argument, before
/// any resolution. That is deliberate: `readlink -m` would happily resolve
/// `../../etc/passwd` to something outside the home and then be caught by the
/// prefix test, but a newline in an argument is checked here because the bash
/// carries the same case and a path with a newline in it is never a path a
/// panel produced.
pub(crate) fn check_path_args(user: &str, cwd: &Path, args: &[String]) -> Result<(), String> {
    let home_prefix = format!("{HOME_ROOT}/{user}/");
    for arg in args {
        // `""|"-"*|"--") continue` - flags are not paths.
        if arg.is_empty() || arg.starts_with('-') {
            continue;
        }
        if arg.contains('\n')
            || arg == ".."
            || arg.starts_with("../")
            || arg.ends_with("/..")
            || arg.contains("/../")
        {
            return Err(format!("terminal path argument escapes user home: {arg}"));
        }
        // The branch mirrors the bash's and is not what makes this work:
        // `Path::join` with an absolute argument discards the base, so
        // `cwd.join("/etc/passwd")` is already `/etc/passwd`. Kept for the
        // reader, and noted so nobody takes it for the check itself.
        let resolved = if arg.starts_with('/') {
            crate::ops::packages::readlink_m(Path::new(arg))
        } else {
            crate::ops::packages::readlink_m(&cwd.join(arg))
        };
        // `case "$resolved/" in "$HOME_ROOT/$user/"*)` - the trailing slash on
        // both sides is what stops `/home/aliceX` passing for `/home/alice`.
        let with_slash = format!("{}/", resolved.to_string_lossy());
        if !with_slash.starts_with(&home_prefix) {
            return Err(format!(
                "terminal path argument is outside panel user home: {arg}"
            ));
        }
    }
    Ok(())
}

/// Source: `require_terminal_download_args`.
///
/// `curl` and `wget` are allowed to name a URL, so their arguments cannot all
/// be treated as paths - but whatever `-o`/`-O` names is a path and is checked
/// like one. `file://` is refused outright in any position: it turns a
/// download into a read of the local filesystem, which is the boundary this
/// whole module exists to hold.
pub(crate) fn check_download_args(user: &str, cwd: &Path, args: &[String]) -> Result<(), String> {
    let mut expect_output = false;
    for arg in args {
        // `case "${arg,,}" in file://*)` - lowercased, so `FILE://` is caught.
        if arg.to_ascii_lowercase().starts_with("file://") {
            return Err(format!(
                "terminal URL argument uses local file scheme: {arg}"
            ));
        }
        if expect_output {
            check_path_args(user, cwd, std::slice::from_ref(arg))?;
            expect_output = false;
            continue;
        }
        if let Some(value) = arg
            .strip_prefix("--output=")
            .or_else(|| arg.strip_prefix("--output-document="))
            .or_else(|| arg.strip_prefix("-O="))
        {
            check_path_args(user, cwd, &[value.to_string()])?;
        } else if matches!(arg.as_str(), "-o" | "-O" | "--output" | "--output-document") {
            expect_output = true;
        } else if is_url(arg) || arg.starts_with('-') || arg.is_empty() {
            // A URL, a flag, or an empty argument: not a path.
        } else {
            check_path_args(user, cwd, std::slice::from_ref(arg))?;
        }
    }
    if expect_output {
        return Err("terminal download output path is missing".to_string());
    }
    Ok(())
}

/// The schemes the bash lets past unchecked.
///
/// Anything else falls through to the path check - and a scheme that is not
/// on this list resolves there as a *relative* path, so `gopher://x/y`
/// becomes `<cwd>/gopher:/x/y` and passes. Measured against the bash, which
/// does the same; curl would still treat it as a URL either way. The refusal
/// that is load-bearing is `file://`, which is checked before any of this and
/// in any position.
fn is_url(arg: &str) -> bool {
    ["http://", "https://", "ftp://", "ftps://", "sftp://"]
        .iter()
        .any(|scheme| arg.starts_with(scheme))
}

/// `terminal-exec <user> <cwd> [--timeout=N] [--php-version=V] <cmd> [args...]`.
pub fn exec_as_user(
    user: &PanelUsername,
    cwd: &str,
    argv: &AllowlistedArgv,
    budget_secs: Option<u64>,
    php_version: Option<PhpVersion>,
) -> HelperResponse {
    let user_str = user.as_str();

    // `id -u "$user"` - a panel row whose Linux account was removed by hand
    // must say so rather than have `runuser` fail with something obscure.
    if !matches!(exec::run(&["id", "-u", user_str]), Ok(o) if o.ok()) {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("panel Linux user does not exist: {user_str}"),
        );
    }

    let target = match resolve_cwd(user_str, cwd) {
        Ok(path) => path,
        Err(message) => return HelperResponse::failed(HelperErrorKind::BadRequest, message),
    };

    // `install -d -o user -g user -m 0700` - Composer and npm write here, and
    // a cache directory owned by root would make every command fail in a way
    // that reads like a broken tool.
    for dir in [".composer", ".npm"] {
        let path = format!("{HOME_ROOT}/{user_str}/{dir}");
        if std::fs::create_dir_all(&path).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
            let _ = exec::run(&["chown", &format!("{user_str}:{user_str}"), &path]);
        }
    }

    // "Validate cwd exists immediately before cd to avoid TOCTOU."
    if !target.is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("working directory does not exist: {}", target.display()),
        );
    }

    let php_bin = match php_version {
        Some(v) => {
            let name = format!("php{}", v.dotted());
            if !crate::ops::runtime::have(&name) {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    format!("PHP CLI is not installed: {name}"),
                );
            }
            name
        }
        None => "php".to_string(),
    };

    let command = argv.binary();
    let args = argv.args();

    // The argument checks, before anything is run.
    if snpanel_ipc::TERMINAL_PATH_CHECKED.contains(&command) {
        if let Err(message) = check_path_args(user_str, &target, args) {
            return HelperResponse::failed(HelperErrorKind::BadRequest, message);
        }
    } else if snpanel_ipc::TERMINAL_DOWNLOAD_CHECKED.contains(&command) {
        if let Err(message) = check_download_args(user_str, &target, args) {
            return HelperResponse::failed(HelperErrorKind::BadRequest, message);
        }
    }

    let basedir = open_basedir(user_str);
    let mut program: Vec<String> = Vec::new();
    let mut extra_env: Vec<(String, String)> = Vec::new();

    match command {
        "php" => {
            program.push(php_bin.clone());
            program.push("-d".to_string());
            program.push(format!("open_basedir={basedir}"));
        }
        "composer" => {
            let Some(bin) = which(&target, "composer") else {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    "composer not found".to_string(),
                );
            };
            program.push(php_bin.clone());
            program.push("-d".to_string());
            program.push(format!("open_basedir={basedir}:{}", parent_of(&bin)));
            program.push(bin);
        }
        "wp" => {
            const WP: &str = "/usr/local/bin/wp";
            if !Path::new(WP).is_file() {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    "wp-cli not found".to_string(),
                );
            }
            // `pcre.jit=0` is WP-CLI's own workaround for a PCRE JIT crash on
            // some builds, and it has to be set for the child WP-CLI spawns
            // too - hence the environment variable as well as the flag.
            extra_env.push((
                "WP_CLI_PHP_ARGS".to_string(),
                format!("-d pcre.jit=0 -d open_basedir={basedir}:/usr/local/bin"),
            ));
            program.push(php_bin.clone());
            program.push("-d".to_string());
            program.push("pcre.jit=0".to_string());
            program.push("-d".to_string());
            program.push(format!("open_basedir={basedir}:/usr/local/bin"));
            program.push(WP.to_string());
        }
        "phpunit" => {
            // "Projects normally ship PHPUnit in vendor/bin instead of
            // globally."
            let vendor = target.join("vendor/bin/phpunit");
            let bin = which(&target, "phpunit").or_else(|| {
                crate::ops::packages::is_executable(&vendor.to_string_lossy())
                    .then(|| vendor.to_string_lossy().into_owned())
            });
            let Some(bin) = bin else {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    "phpunit not found (install it globally or with composer)".to_string(),
                );
            };
            program.push(php_bin.clone());
            program.push("-d".to_string());
            program.push(format!("open_basedir={basedir}:{}", parent_of(&bin)));
            program.push(bin);
        }
        "artisan" => {
            // "Bare `artisan` is a convenience alias for `php artisan`.
            // Laravel keeps it at the project root, one level above
            // public_html."
            if !target.join("artisan").is_file() {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    format!(
                        "artisan not found in {} (Laravel keeps it in the site root; \
                         try 'cd ..' first)",
                        target.display()
                    ),
                );
            }
            program.push(php_bin.clone());
            program.push("-d".to_string());
            program.push(format!("open_basedir={basedir}"));
            program.push("artisan".to_string());
        }
        other => program.push(other.to_string()),
    }
    program.extend(args.iter().cloned());

    run_as(user_str, &target, budget_secs, &program, &extra_env)
}

/// `command -v <name>`, with the working directory's `vendor/bin` never
/// consulted - `PATH` is the fixed one from `terminal_env`.
fn which(_cwd: &Path, name: &str) -> Option<String> {
    for dir in ["/usr/local/bin", "/usr/bin", "/bin"] {
        let candidate = format!("{dir}/{name}");
        if crate::ops::packages::is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn parent_of(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string())
}

/// Source: `terminal_runner` plus `env "${terminal_env[@]}"`.
///
/// `timeout --signal=TERM --kill-after=10` and not a plain wait, because the
/// point is to kill the **process group**: "Composer, npm and WP-CLI can wedge
/// on a slow network, and without this the API worker would block on the pipe
/// until the client gives up."
fn run_as(
    user: &str,
    cwd: &Path,
    budget_secs: Option<u64>,
    program: &[String],
    extra_env: &[(String, String)],
) -> HelperResponse {
    let mut argv: Vec<String> = Vec::new();
    let budget_text;
    if let Some(secs) = budget_secs {
        if crate::ops::runtime::have("timeout") {
            budget_text = secs.to_string();
            argv.extend([
                "timeout".to_string(),
                "--signal=TERM".to_string(),
                "--kill-after=10".to_string(),
                budget_text,
            ]);
        }
    }
    argv.extend([
        "runuser".to_string(),
        "-u".to_string(),
        user.to_string(),
        "--".to_string(),
        "env".to_string(),
    ]);
    for (key, value) in terminal_env(user).iter().chain(extra_env.iter()) {
        argv.push(format!("{key}={value}"));
    }
    argv.extend(program.iter().cloned());

    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    // `umask 022` before the command: files a tool creates are readable by the
    // web server, which is what a site needs, and not group-writable.
    let previous = unsafe { libc::umask(0o022) };
    let result = exec::run_in_dir(&borrowed, cwd);
    unsafe {
        libc::umask(previous);
    }

    match result {
        Ok(out) => HelperResponse {
            ok: out.ok(),
            stdout: out.stdout,
            stderr: out.stderr,
            data: None,
            error: None,
            // The command's own status is the answer. `grep` that matches
            // nothing exits 1 and that is not a refusal.
            exit_code: Some(out.status.unwrap_or(124)),
        },
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("running the terminal command: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// `require_terminal_path_args`: every non-flag argument has to land
    /// inside the user's own home.
    ///
    /// The trailing slash on both sides of the comparison is the part worth
    /// reading twice. Without it `/home/aliceX` starts with `/home/alice` and
    /// one customer's terminal reaches another customer's home - which is the
    /// exact boundary this module exists to hold.
    #[test]
    fn a_path_argument_may_not_leave_the_users_home() {
        let cwd = Path::new("/home/alice/example.com");

        // Inside: absolute, relative, and the home itself.
        for good in [
            "/home/alice/example.com/index.php",
            "index.php",
            "public_html/index.php",
            "/home/alice",
            "../other-site/index.php",
        ] {
            // `..` in the middle is refused by the literal check before
            // resolution, so that one is expected to fail; the rest pass.
            let result = check_path_args("alice", cwd, &args(&[good]));
            if good.starts_with("..") {
                assert!(result.is_err(), "{good}");
            } else {
                assert!(result.is_ok(), "{good}: {result:?}");
            }
        }

        // The neighbour whose name merely starts the same way.
        let err = check_path_args("alice", cwd, &args(&["/home/aliceX/secret.txt"]))
            .expect_err("aliceX is not alice");
        assert!(err.contains("outside panel user home"), "{err}");

        // Straightforwardly outside.
        for bad in [
            "/etc/passwd",
            "/home/bob/site/wp-config.php",
            "/root/.ssh/id_rsa",
            "/",
        ] {
            assert!(
                check_path_args("alice", cwd, &args(&[bad])).is_err(),
                "{bad} was allowed"
            );
        }

        // `..` is refused on the raw argument, whatever it would resolve to.
        for bad in [
            "..",
            "../..",
            "../../etc/passwd",
            "a/../../../etc/passwd",
            "x/..",
        ] {
            let err = check_path_args("alice", cwd, &args(&[bad])).expect_err(bad);
            assert!(err.contains("escapes user home"), "{bad}: {err}");
        }

        // A newline in a path is never a path a panel produced.
        assert!(check_path_args("alice", cwd, &args(&["a\nb"])).is_err());

        // Flags and empty strings are not paths.
        for flag in ["-la", "--recursive", "--", "-", ""] {
            assert!(
                check_path_args("alice", cwd, &args(&[flag])).is_ok(),
                "{flag:?} should be skipped"
            );
        }

        // One bad argument among good ones still refuses.
        assert!(
            check_path_args("alice", cwd, &args(&["-la", "index.php", "/etc/passwd"])).is_err()
        );
    }

    /// `require_terminal_download_args`: a URL is not a path, but whatever
    /// `-o` names is.
    #[test]
    fn a_download_may_name_a_url_but_not_write_outside_the_home() {
        let cwd = Path::new("/home/alice/example.com");

        // The ordinary shapes.
        for good in [
            vec!["https://example.com/x.zip"],
            vec!["-fsSL", "https://example.com/x.zip"],
            vec!["https://example.com/x.zip", "-o", "x.zip"],
            vec!["https://example.com/x.zip", "--output=x.zip"],
            vec!["https://example.com/x.zip", "-O=x.zip"],
            vec!["https://example.com/x.zip", "--output-document=sub/x.zip"],
            vec!["ftp://example.com/x.zip"],
            vec!["sftp://example.com/x.zip"],
        ] {
            assert!(
                check_download_args("alice", cwd, &args(&good)).is_ok(),
                "{good:?}"
            );
        }

        // `file://` turns a download into a read of the local filesystem.
        for bad in ["file:///etc/passwd", "FILE:///etc/passwd", "File://x"] {
            let err = check_download_args("alice", cwd, &args(&[bad])).expect_err(bad);
            assert!(err.contains("local file scheme"), "{bad}: {err}");
        }
        // In any position, not only the first.
        assert!(
            check_download_args("alice", cwd, &args(&["-fsSL", "file:///etc/shadow"])).is_err()
        );

        // The output path is checked like any other path.
        for bad in [
            vec!["https://example.com/x", "-o", "/etc/cron.d/pwn"],
            vec!["https://example.com/x", "-O", "/home/bob/x"],
            vec!["https://example.com/x", "--output=/etc/passwd"],
            vec!["https://example.com/x", "--output-document=../../etc/x"],
            vec!["https://example.com/x", "-O=/root/x"],
        ] {
            assert!(
                check_download_args("alice", cwd, &args(&bad)).is_err(),
                "{bad:?} was allowed"
            );
        }

        // `-o` with nothing after it is a refusal, not a silently dropped
        // flag - otherwise the check has simply not happened.
        let err = check_download_args("alice", cwd, &args(&["https://example.com/x", "-o"]))
            .expect_err("dangling -o");
        assert!(err.contains("output path is missing"), "{err}");

        // A scheme that is neither listed nor `file://` falls through to the
        // path check, and `gopher://x/y` resolves as a *relative* path under
        // the working directory - `/home/alice/example.com/gopher:/x/y` - so
        // it passes. That is what the bash does, and it is reproduced rather
        // than tightened: curl would still treat it as a URL, so the refusal
        // that is actually load-bearing is `file://`, which is checked above.
        assert!(check_download_args("alice", cwd, &args(&["gopher://x/y"])).is_ok());
        assert!(check_download_args("alice", cwd, &args(&["dict://x/y"])).is_ok());
        // An absolute one still goes outside the home and is refused.
        assert!(check_download_args("alice", cwd, &args(&["/etc/passwd"])).is_err());
    }

    /// The basedir is the tenant's home plus the pool's own directories.
    ///
    /// Not one site root: a customer with several sites still has to work
    /// across them, and the leak being closed is between customers.
    #[test]
    fn the_open_basedir_is_the_tenant_not_the_site() {
        let dir = open_basedir("alice");
        let parts: Vec<&str> = dir.split(':').collect();
        assert_eq!(
            parts,
            vec![
                "/home/alice",
                "/var/lib/php/sessions/alice",
                "/var/lib/php/uploads/alice",
                "/tmp",
                "/usr/share/php",
            ]
        );
        // The neighbour is not in it, and neither is /etc.
        assert!(!dir.contains("/home/bob"));
        assert!(!dir.contains("/etc"));
        // And it is per-user: two customers do not share a basedir.
        assert_ne!(open_basedir("alice"), open_basedir("bob"));
    }

    /// The environment is built, not inherited.
    #[test]
    fn the_environment_is_four_variables_and_a_fixed_path() {
        let env = terminal_env("alice");
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            vec!["HOME", "COMPOSER_HOME", "npm_config_cache", "PATH"]
        );

        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_eq!(map["HOME"], "/home/alice");
        assert_eq!(map["COMPOSER_HOME"], "/home/alice/.composer");
        assert_eq!(map["npm_config_cache"], "/home/alice/.npm");
        // A fixed PATH, so a binary dropped into a writable directory cannot
        // shadow one of the allowed commands. `.` is not on it.
        assert_eq!(map["PATH"], "/usr/local/bin:/usr/bin:/bin");
        assert!(!map["PATH"].split(':').any(|p| p == "." || p.is_empty()));
        assert!(!map["PATH"].contains("/home"));
    }

    /// The allow-list, against the bash's own `case`.
    ///
    /// It carried 27 of the 52. The 25 it was missing are all accepted by the
    /// bash and all listed in the panel's help, so answering `terminal-exec`
    /// here would have made them stop working with "not on the terminal
    /// allowlist" while the panel kept offering them.
    #[test]
    fn the_allowlist_is_the_bashs_and_every_command_has_exactly_one_group() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            all: Vec<String>,
            groups: std::collections::BTreeMap<String, Vec<String>>,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/terminal_allowlist.json");
        let raw = std::fs::read_to_string(&path).expect("the allowlist fixture");
        let fixture: Fixture = serde_json::from_str(&raw).expect("it parses");

        assert_eq!(fixture.all.len(), 52, "the bash accepts 52 commands");
        let mut ours: Vec<String> = snpanel_ipc::TERMINAL_ALLOWLIST
            .iter()
            .map(|s| s.to_string())
            .collect();
        ours.sort();
        assert_eq!(ours, fixture.all);

        // Each of the four groups matches the bash arm it came from.
        for (name, expected) in [
            ("php_hosted", snpanel_ipc::TERMINAL_PHP_HOSTED),
            ("path_checked", snpanel_ipc::TERMINAL_PATH_CHECKED),
            ("download_checked", snpanel_ipc::TERMINAL_DOWNLOAD_CHECKED),
            ("plain", snpanel_ipc::TERMINAL_PLAIN),
        ] {
            let mut got: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            got.sort();
            assert_eq!(got, fixture.groups[name], "group {name}");
        }

        // Exactly one group each: a command in none would be accepted and
        // then have no arm; a command in two would be checked one way and run
        // another.
        for command in snpanel_ipc::TERMINAL_ALLOWLIST {
            let count = [
                snpanel_ipc::TERMINAL_PHP_HOSTED,
                snpanel_ipc::TERMINAL_PATH_CHECKED,
                snpanel_ipc::TERMINAL_DOWNLOAD_CHECKED,
                snpanel_ipc::TERMINAL_PLAIN,
            ]
            .iter()
            .filter(|group| group.contains(command))
            .count();
            assert_eq!(count, 1, "{command} is in {count} groups");
        }

        // The ones that must be path-checked, spelled out: each can be
        // pointed at a file, and `curl`/`wget` can be pointed at a URL.
        for command in ["cat", "rm", "cp", "mv", "chmod", "chown", "tar", "sed"] {
            assert!(
                snpanel_ipc::TERMINAL_PATH_CHECKED.contains(&command),
                "{command} takes a path and must be checked"
            );
        }
        for command in ["curl", "wget"] {
            assert!(snpanel_ipc::TERMINAL_DOWNLOAD_CHECKED.contains(&command));
        }
        // And what must never be on the list at all.
        for command in ["sh", "bash", "sudo", "su", "python3", "perl", "nc", "ssh"] {
            assert!(
                !snpanel_ipc::TERMINAL_ALLOWLIST.contains(&command),
                "{command} is on the terminal allowlist"
            );
        }
    }

    /// `require_terminal_cwd`: the home or below it, and a directory.
    #[test]
    fn the_working_directory_must_be_the_users_own() {
        // Only the string half can be checked without a real tree; the
        // is_dir half is exercised against one below.
        let err = resolve_cwd("alice", "/home/bob/site").expect_err("bob is not alice");
        assert!(err.contains("not owned by panel Linux user alice"), "{err}");
        let err = resolve_cwd("alice", "/etc").expect_err("/etc");
        assert!(err.contains("not owned by panel Linux user alice"), "{err}");
        // The prefix trap again.
        let err = resolve_cwd("alice", "/home/aliceX").expect_err("aliceX");
        assert!(err.contains("not owned by"), "{err}");

        let base = std::env::temp_dir().join(format!("term-cwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("the dir");
        // A path under the home that is a file, not a directory.
        assert!(resolve_cwd("alice", "/home/alice/definitely-not-there-12345").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `check_path_args` and `check_download_args` against the bash's own
    /// `require_terminal_*_args`, run on Debian 13.
    ///
    /// The harness that produced this fixture self-checks first - it asserts
    /// that `index.php` is accepted and `/etc/passwd` refused before it
    /// records anything. Two earlier attempts returned "refused" for all 62
    /// cases: once because the helper's prelude reads `/etc/nginx/nginx.conf`
    /// and dies under `set -e` on a box without nginx, and once because the
    /// prelude included `cmd="${1:-}"; shift`, which ate the username so the
    /// function judged the working directory as one. Both look exactly like a
    /// very strict validator.
    #[test]
    fn terminal_argument_checks_agree_with_the_bash_helper() {
        #[derive(serde::Deserialize)]
        struct Case {
            args: Vec<String>,
            ok: bool,
        }
        #[derive(serde::Deserialize)]
        struct Fixture {
            user: String,
            cwd: String,
            path_args: Vec<Case>,
            download_args: Vec<Case>,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/terminal_args.json");
        let raw = std::fs::read_to_string(&path).expect("the terminal args fixture");
        let fixture: Fixture = serde_json::from_str(&raw).expect("it parses");
        let cwd = Path::new(&fixture.cwd);

        for case in &fixture.path_args {
            let got = check_path_args(&fixture.user, cwd, &case.args).is_ok();
            assert_eq!(got, case.ok, "path args {:?}", case.args);
        }
        for case in &fixture.download_args {
            let got = check_download_args(&fixture.user, cwd, &case.args).is_ok();
            assert_eq!(got, case.ok, "download args {:?}", case.args);
        }

        // A fixture that had drifted to all-accept or all-refuse would satisfy
        // every assertion above while proving nothing - which is the failure
        // mode this whole corpus was built twice to avoid.
        let accepted = fixture.path_args.iter().filter(|c| c.ok).count()
            + fixture.download_args.iter().filter(|c| c.ok).count();
        let refused = fixture.path_args.len() + fixture.download_args.len() - accepted;
        assert!(accepted > 20, "only {accepted} accepted");
        assert!(refused > 20, "only {refused} refused");
    }
}
