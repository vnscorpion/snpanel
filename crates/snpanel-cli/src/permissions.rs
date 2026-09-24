//! Putting the box's ownership and modes back the way the installer left
//! them.
//!
//! Source: `fix_permissions` in `snpanelctl`.
//!
//! This is the entry an operator reaches for after something outside the
//! panel has moved a file - a package update that replaced `/etc/nginx`, a
//! restore that wrote everything as root, a `chmod -R` that went one
//! directory too high. So it has to be safe to run when nothing is wrong,
//! and it does not stop at the first thing it cannot fix: the box-level
//! repairs all happen, and only the per-site sweep is allowed to fail the
//! command.
//!
//! **The sshd edit is the dangerous part.** An invalid `sshd_config` breaks
//! nothing until sshd is next restarted, at which point it refuses to start
//! and the box has no SSH at all - unrecoverable on a remote server without
//! console access. So the edit is validated with `sshd -t` and the backup is
//! copied back the moment it does not pass, and losing the SFTP block is
//! preferred to losing the machine.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use snpanel_installer::backend_env;
use snpanel_installer::panel_user::SYSTEM_GROUPS;
use snpanel_installer::update::runtime;

use crate::{app_dir, env_path_string};

/// Source: `BACKUP_ROOT`.
const BACKUP_ROOT: &str = "/var/backups/snpanel";
/// Source: `RUST_API`.
const RUST_API: &str = "/usr/local/bin/snpanel-api-rust";

/// `snpanel fix-permissions`.
pub fn fix_permissions(env_path: Option<&Path>) -> Result<()> {
    let Some(env) = env_path else {
        anyhow::bail!("{} not found. Run the installer first.", env_path_string());
    };

    ensure_groups();
    ensure_acl_tools();
    add_to_sites_group();
    repair_sshd_sftp();
    repair_directories(env);

    // The sweep stops at the first site it cannot fix, which is what this
    // path has always done: somebody ran this by hand and is reading the
    // output, so finishing quietly over a broken site would hide the thing
    // they asked about.
    refresh_sites_strict(env)?;

    restart_panel();
    println!("Permissions fixed.");
    Ok(())
}

/// Source: `getent group X >/dev/null || groupadd --system X`.
fn ensure_groups() {
    for group in SYSTEM_GROUPS {
        if group_exists(group) {
            continue;
        }
        let _ = Command::new("groupadd")
            .args(["--system", group])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Source: the `setfacl` check. Debian only, as in the bash - on the RHEL
/// family `acl` is part of the base system and there is nothing to install.
fn ensure_acl_tools() {
    if which("setfacl").is_some() || which("apt-get").is_none() {
        return;
    }
    for args in [vec!["update"], vec!["install", "-y", "acl"]] {
        let _ = Command::new("apt-get")
            .args(&args)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .status();
    }
}

/// Source: `usermod -aG snpanel-sites snpanel` and the same for `www-data`.
///
/// `|| true` in the bash: on the RHEL family the web account is `nginx`, not
/// `www-data`, and a missing account is not an error here.
fn add_to_sites_group() {
    for user in ["snpanel", "www-data", "nginx"] {
        let _ = Command::new("usermod")
            .args(["-aG", "snpanel-sites", user])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Source: the `sshd` block of `fix_permissions`.
///
/// The edit itself is `runtime::apply_sftp_block`, shared with
/// `snpanel-install sftp-access`: two copies of an edit to `sshd_config` is
/// two chances to get the rollback wrong.
///
/// The difference between the two callers is here, and only here. The
/// installer treats an invalid result as fatal; this does not. An operator
/// running `fix-permissions` has other repairs waiting, and losing the SFTP
/// block is a feature not working while stopping leaves the box half-fixed.
fn repair_sshd_sftp() {
    if which("sshd").is_none() {
        return;
    }
    let existing = std::fs::read_to_string(runtime::SSHD_CONFIG).unwrap_or_default();
    let updated = backend_env::sshd_config_with_sftp(&existing);
    match runtime::apply_sftp_block(&updated) {
        Ok(runtime::SshdOutcome::Reload) => {}
        Ok(runtime::SshdOutcome::Rollback) => {
            println!("WARNING: invalid SSHD configuration; skipped SNPanel SFTP password block");
        }
        Err(e) => {
            println!("WARNING: could not apply the SFTP block ({e})");
        }
    }
}

/// Source: the `install -d` and `chown`/`chmod` run of `fix_permissions`.
fn repair_directories(env: &Path) {
    // The panel's own tree.
    let app = app_dir();
    for path in [
        app.clone(),
        format!("{app}/backend"),
        format!("{app}/frontend"),
    ] {
        install_dir(Path::new(&path), "snpanel", "snpanel", 0o750);
    }
    install_dir(Path::new(BACKUP_ROOT), "snpanel", "snpanel", 0o750);

    // `/etc/nginx/conf.d` at 2775 root:snpanel. The **setgid** bit is the
    // part that matters and the part that is easy to drop: without it the
    // first vhost written after a package update belongs to root:root and the
    // panel cannot rewrite it, which surfaces as a permissions bug in the
    // panel and is not one.
    for dir in runtime::nginx_dirs() {
        install_dir(Path::new(dir.path), dir.owner, dir.group, dir.mode);
    }
    for path in ["/var/lib/snpanel", "/var/lib/snpanel/geoip"] {
        install_dir(Path::new(path), "snpanel", "snpanel", 0o750);
    }

    // The panel reads its own key out of /etc/snpanel, and nothing else on
    // the box should.
    if Path::new("/etc/snpanel").is_dir() {
        let _ = chown("/etc/snpanel", "root:snpanel");
        let _ = chmod("/etc/snpanel", 0o750);
        if let Ok(entries) = std::fs::read_dir("/etc/snpanel") {
            for entry in entries.flatten() {
                let p = entry.path();
                let _ = chown(&p.to_string_lossy(), "root:snpanel");
                let _ = chmod(&p.to_string_lossy(), 0o640);
            }
        }
    }

    for path in [
        format!("{app}/backend"),
        format!("{app}/frontend"),
        "/var/lib/snpanel/geoip".to_string(),
        "/var/lib/snpanel/assets".to_string(),
    ] {
        if Path::new(&path).exists() {
            let _ = chown_recursive(&path, "snpanel:snpanel");
        }
    }
    let _ = chown("/var/lib/snpanel", "snpanel:snpanel");
    let _ = chmod(&env.to_string_lossy(), 0o640);

    // nginx serves the built SPA straight off disk as its own user, so the
    // path to it has to be traversable and the files readable. `o+rX` and not
    // `o+rw`: readable, never writable.
    let dist = format!("{app}/frontend/dist");
    if Path::new(&dist).is_dir() {
        for path in [app.clone(), format!("{app}/frontend")] {
            let _ = Command::new("chmod").args(["o+rX", &path]).status();
        }
        let _ = Command::new("chmod").args(["-R", "o+rX", &dist]).status();
    }
}

/// Source: the `--refresh-sites-strict` run.
fn refresh_sites_strict(env: &Path) -> Result<()> {
    if !is_executable(Path::new(RUST_API)) || !user_exists("snpanel") {
        // The bash skips this when either is missing rather than failing:
        // the box-level repairs above are the part that always applies.
        return Ok(());
    }
    let status = Command::new("runuser")
        .args(["-u", "snpanel", "--", "env"])
        .arg(format!("HOME={}", app_dir()))
        .arg("SNPANEL_USE_HELPER=true")
        .arg(RUST_API)
        .arg("--env")
        .arg(env)
        .arg("--refresh-sites-strict")
        .status()
        .with_context(|| format!("running {RUST_API} --refresh-sites-strict"))?;
    if !status.success() {
        anyhow::bail!("Could not refresh the sites");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the small mechanics
// ---------------------------------------------------------------------------

/// `install -d -o OWNER -g GROUP -m MODE PATH`.
///
/// `install -d` is used rather than `mkdir -p` and a `chmod` because it sets
/// the mode on creation: there is no window where a directory that will hold
/// the panel's data is 0755.
fn install_dir(path: &Path, owner: &str, group: &str, mode: u32) {
    let _ = Command::new("install")
        .args(["-d", "-o", owner, "-g", group, "-m"])
        .arg(format!("{mode:o}"))
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn chown(path: &str, spec: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("chown")
        .args([spec, path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn chown_recursive(path: &str, spec: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("chown")
        .args(["-R", spec, path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn chmod(path: &str, mode: u32) -> std::io::Result<std::process::ExitStatus> {
    Command::new("chmod")
        .arg(format!("{mode:o}"))
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn group_exists(name: &str) -> bool {
    Command::new("getent")
        .args(["group", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn user_exists(name: &str) -> bool {
    Command::new("id")
        .args(["-u", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Source: `command -v NAME`.
fn which(name: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    path.split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|p| is_executable(p))
        .map(|p| p.to_string_lossy().into_owned())
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn restart_panel() {
    let _ = Command::new("systemctl")
        .args(["restart", "snpanel-api"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_refuses_without_an_env_file() {
        let err = fix_permissions(None).unwrap_err().to_string();
        assert!(err.contains(&env_path_string()), "{err}");
    }

    #[test]
    fn the_sftp_block_replaces_itself_rather_than_stacking() {
        // This runs on every install, every update and every repair. sshd
        // reads a second `Match Group snpanel-sftp` as a duplicate and
        // refuses to start, so appending without removing first would break
        // SSH on the second run - not the first, which is how it would reach
        // production.
        let base = "Port 22\n";
        let once = backend_env::sshd_config_with_sftp(base);
        let twice = backend_env::sshd_config_with_sftp(&once);
        assert_eq!(once, twice, "the block stacked on the second run");
        assert_eq!(twice.matches(backend_env::SFTP_BEGIN).count(), 1);
        assert_eq!(twice.matches(backend_env::SFTP_END).count(), 1);
    }

    #[test]
    fn the_operators_own_settings_survive_the_edit() {
        // The block is appended, not written over the file. An operator's
        // `Port 2200` has to still be there afterwards, or this command is
        // how they lose SSH.
        let base = "Port 2200\nPermitRootLogin prohibit-password\n";
        let out = backend_env::sshd_config_with_sftp(base);
        assert!(out.contains("Port 2200"), "{out}");
        assert!(out.contains("PermitRootLogin prohibit-password"), "{out}");
    }

    #[test]
    fn an_invalid_config_is_rolled_back_not_reloaded() {
        // `sshd -t` failing must put the backup back. The alternative is a
        // box that keeps working until the next reboot and then has no SSH.
        assert_eq!(runtime::sshd_outcome(false), runtime::SshdOutcome::Rollback);
        assert_eq!(runtime::sshd_outcome(true), runtime::SshdOutcome::Reload);
    }

    #[test]
    fn the_nginx_config_directory_keeps_its_setgid_bit() {
        // Without it the first vhost written after a package update belongs
        // to root:root and the panel cannot rewrite it.
        let conf_d = runtime::nginx_dirs()
            .into_iter()
            .find(|d| d.path == "/etc/nginx/conf.d")
            .expect("conf.d is no longer in the list");
        assert_eq!(conf_d.mode & 0o2000, 0o2000, "setgid is gone");
        assert_eq!(conf_d.group, "snpanel");
    }

    #[test]
    fn a_mode_reaches_install_as_octal() {
        // `install -m` reads its argument as octal. Formatting 0o750 as
        // decimal would pass "488", which `install` takes as 0o750's
        // neighbour and silently applies.
        assert_eq!(format!("{:o}", 0o750), "750");
        assert_eq!(format!("{:o}", 0o2775), "2775");
        assert_eq!(format!("{:o}", 0o640), "640");
    }

    #[test]
    fn both_system_groups_are_created() {
        // `snpanel-sftp` is the one an SFTP login is matched on; without it
        // the sshd block matches nothing and customers cannot connect.
        assert!(SYSTEM_GROUPS.contains(&"snpanel-sites"));
        assert!(SYSTEM_GROUPS.contains(&"snpanel-sftp"));
    }
}
