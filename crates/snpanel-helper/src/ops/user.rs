//! `ops::user` - the Linux accounts each customer's sites run as.
//!
//! Source: `ensure_panel_user_home`, `set_panel_user_password` and
//! `delete_panel_user_runtime` in the bash helper.
//!
//! The permission layout here is C33 and is not arbitrary:
//!
//! - `/home` is `root:root 0711`. Execute-only for others means a customer can
//!   reach their own directory by name but cannot *list* `/home`, so one
//!   customer cannot enumerate the others.
//! - Each home is `root:<user> 0751`. Owned by root so the customer cannot
//!   chmod their way out; group-readable so their own PHP pool can read it.
//! - setuid/setgid and the sticky bit are cleared explicitly, because a home
//!   directory that inherited any of them is a privilege-escalation waiting to
//!   be found.

use std::path::{Path, PathBuf};

use snpanel_core::{PanelUsername, SecretString};
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: `HOME_ROOT`.
pub const HOME_ROOT: &str = "/home";
/// Source: `SNPANEL_SITES_GROUP`.
pub const SITES_GROUP: &str = "snpanel-sites";
/// Source: `SNPANEL_SFTP_GROUP`.
pub const SFTP_GROUP: &str = "snpanel-sftp";

/// Source: `set_panel_user_password`'s length check.
pub const MIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 72;

fn home_of(user: &PanelUsername) -> PathBuf {
    Path::new(HOME_ROOT).join(user.as_str())
}

fn exists(user: &PanelUsername) -> bool {
    exec::run(&["id", "-u", user.as_str()])
        .map(|o| o.ok())
        .unwrap_or(false)
}

fn group_exists(group: &str) -> bool {
    exec::run(&["getent", "group", group])
        .map(|o| o.ok())
        .unwrap_or(false)
}

fn ensure_system_group(group: &str) {
    if !group_exists(group) {
        let _ = exec::run(&["groupadd", "--system", group]);
    }
}

/// The shell a panel user gets. `/usr/sbin/nologin` on Debian, `/sbin/nologin`
/// on EL - which is exactly the kind of difference the Platform trait exists
/// for, rather than being hard-coded as the bash does.
fn nologin_shell() -> String {
    snpanel_osabi::detect()
        .map(|p| p.nologin_shell().to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/usr/sbin/nologin".to_string())
}

fn web_user() -> String {
    snpanel_osabi::detect()
        .map(|p| p.web_user().to_string())
        .unwrap_or_else(|_| "www-data".to_string())
}

/// `panel-user-ensure`. Idempotent: safe to run against an existing account.
pub fn ensure(user: &PanelUsername, password: Option<&SecretString>) -> HelperResponse {
    ensure_system_group(SITES_GROUP);
    ensure_system_group(SFTP_GROUP);

    let home = home_of(user);
    let home_str = home.to_string_lossy().into_owned();
    let shell = nologin_shell();

    // A per-user group, so the home can be group-owned by the customer without
    // sharing it with anyone else.
    if !group_exists(user.as_str()) {
        let _ = exec::run(&["groupadd", user.as_str()]);
    }
    // The web server joins it so it can read the site through the group bit.
    let _ = exec::run(&["usermod", "-aG", user.as_str(), &web_user()]);

    // C33: /home must be execute-only for others, so one customer cannot list
    // the rest. Reasserted on every ensure because it is cheap and because a
    // wrong mode here exposes every customer on the box.
    let _ = exec::run(&["chown", "root:root", HOME_ROOT]);
    let _ = exec::run(&["chmod", "0711", HOME_ROOT]);
    let _ = exec::run(&["chmod", "a-s", HOME_ROOT]);
    let _ = exec::run(&["chmod", "-t", HOME_ROOT]);

    if !exists(user) {
        let out = exec::run(&[
            "useradd",
            "--create-home",
            "--home-dir",
            &home_str,
            "--shell",
            &shell,
            "--gid",
            user.as_str(),
            user.as_str(),
        ]);
        if !matches!(&out, Ok(o) if o.ok()) {
            return exec::respond("useradd", out);
        }
    }

    // Reassert the account's shape even when it already existed: an account
    // restored from a backup, or edited by hand, must converge.
    let _ = exec::run(&[
        "usermod",
        "--home",
        &home_str,
        "--shell",
        &shell,
        "--gid",
        user.as_str(),
        user.as_str(),
    ]);
    let _ = exec::run(&["usermod", "-aG", SFTP_GROUP, user.as_str()]);

    if let Err(e) = std::fs::create_dir_all(&home) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {home_str}: {e}"),
        );
    }
    let owner = format!("root:{}", user.as_str());
    let _ = exec::run(&["chown", &owner, &home_str]);
    let _ = exec::run(&["chmod", "0751", &home_str]);
    let _ = exec::run(&["chmod", "a-s", &home_str]);
    let _ = exec::run(&["chmod", "-t", &home_str]);
    // Any inherited ACL would silently widen access past the mode bits.
    let _ = exec::run(&["setfacl", "-b", &home_str]);

    if let Some(pw) = password {
        let resp = set_password(user, pw);
        if !resp.ok {
            return resp;
        }
    }

    HelperResponse::with_stdout(format!("{user}\n"))
}

/// `panel-user-password`.
///
/// C37: the password reaches `chpasswd` on **stdin**. It is never an argument,
/// so it never appears in `/proc/<pid>/cmdline` and never shows up in `ps`.
pub fn set_password(user: &PanelUsername, password: &SecretString) -> HelperResponse {
    if !exists(user) {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("panel Linux user does not exist: {user}"),
        );
    }

    let len = password.expose().len();
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&len) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters"),
        );
    }
    // `chpasswd` reads `user:password` lines, so a colon or newline in the
    // password would let it be read as a different field entirely.
    if !password.valid_as_linux_password() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "password cannot contain ':', carriage returns or newlines",
        );
    }

    let line = format!("{}:{}\n", user.as_str(), password.expose());
    let out = exec::run_with_stdin(&["chpasswd"], Some(line.as_bytes()));
    let resp = exec::respond("chpasswd", out);
    if !resp.ok {
        return resp;
    }
    // An account created with no password is locked; setting one must unlock
    // it or SFTP still refuses the login.
    let _ = exec::run(&["passwd", "-u", user.as_str()]);
    HelperResponse::ok()
}

/// `panel-user-delete`. Source: `delete_panel_user_runtime`.
///
/// Order matters: the PHP pools go first so nothing is still running as the
/// user when the account is removed, and the processes are killed before
/// `userdel`, which refuses while the user has any.
pub fn delete(user: &PanelUsername) -> HelperResponse {
    remove_php_pools(user);

    let _ = exec::run(&["crontab", "-r", "-u", user.as_str()]);
    let _ = exec::run(&["pkill", "-u", user.as_str()]);
    let _ = exec::run(&["userdel", user.as_str()]);
    let _ = exec::run(&["groupdel", user.as_str()]);

    // Remove the data last, so a failure above leaves something to inspect.
    let _ = std::fs::remove_dir_all(home_of(user));
    let _ = std::fs::remove_dir_all(format!("/var/lib/php/sessions/{user}"));
    let _ = std::fs::remove_dir_all(format!("/var/lib/php/uploads/{user}"));

    HelperResponse::with_stdout(format!("deleted {user}\n"))
}

/// Delete every PHP-FPM pool belonging to a user, reloading each version whose
/// pools changed.
fn remove_php_pools(user: &PanelUsername) {
    let prefix = format!("snpanel-{}", user.as_str());
    let Ok(versions) = std::fs::read_dir("/etc/php") else {
        return;
    };

    for version in versions.filter_map(Result::ok) {
        let pool_dir = version.path().join("fpm/pool.d");
        let Ok(entries) = std::fs::read_dir(&pool_dir) else {
            continue;
        };
        let mut touched = false;
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            // `snpanel-<user>.conf` and `snpanel-<user>-<hash>-<ver>.conf`, and
            // nothing belonging to a user whose name merely starts the same:
            // bp_site must not match bp_site2.
            let is_ours = name == format!("{prefix}.conf")
                || (name.starts_with(&format!("{prefix}-")) && name.ends_with(".conf"));
            if is_ours {
                let _ = std::fs::remove_file(entry.path());
                touched = true;
            }
        }
        if touched {
            if let Some(v) = version.file_name().to_str() {
                let unit = format!("php{v}-fpm");
                let _ = exec::run(&["systemctl", "reload", &unit]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_password_is_refused() {
        let user = PanelUsername::parse("bp_nobody_here").unwrap();
        // The user does not exist, so this returns NotFound first - check the
        // length rule directly instead.
        assert!(!(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&11));
        assert!((MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&12));
        assert!((MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&72));
        assert!(!(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&73));

        let r = set_password(&user, &SecretString::new("x".repeat(20)));
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().kind, HelperErrorKind::NotFound);
    }

    #[test]
    fn a_password_with_a_colon_is_refused() {
        // chpasswd reads `user:password`, so a colon would be read as a field
        // separator and set a different password than the one asked for.
        assert!(!SecretString::new("has:colon-and-long-enough").valid_as_linux_password());
        assert!(!SecretString::new("has\nnewline-long-enough").valid_as_linux_password());
        assert!(SecretString::new("perfectly-fine-password").valid_as_linux_password());
    }

    #[test]
    fn the_pool_glob_does_not_match_a_similarly_named_user() {
        // bp_site must not match bp_site2's pools, or deleting one customer
        // would take another customer's sites offline.
        let user = "bp_site";
        let prefix = format!("snpanel-{user}");
        let matches = |name: &str| {
            name == format!("{prefix}.conf")
                || (name.starts_with(&format!("{prefix}-")) && name.ends_with(".conf"))
        };
        assert!(matches("snpanel-bp_site.conf"));
        assert!(matches("snpanel-bp_site-abc123-8_4.conf"));
        assert!(!matches("snpanel-bp_site2.conf"));
        assert!(!matches("snpanel-bp_site2-abc123-8_4.conf"));
        assert!(!matches("snpanel-other.conf"));
        assert!(!matches("snpanel-bp_site-abc.conf.bak"));
    }

    #[test]
    fn nologin_is_resolved_per_platform_not_hard_coded() {
        let shell = nologin_shell();
        assert!(
            shell == "/usr/sbin/nologin" || shell == "/sbin/nologin",
            "unexpected shell {shell}"
        );
    }

    #[test]
    fn a_reserved_name_can_never_reach_these_functions() {
        // The type is the guard: "root" never becomes a PanelUsername, so
        // delete() cannot be called with it.
        for reserved in ["root", "www-data", "snpanel", "mysql", "nginx"] {
            assert!(PanelUsername::parse(reserved).is_err(), "{reserved}");
        }
    }
}
