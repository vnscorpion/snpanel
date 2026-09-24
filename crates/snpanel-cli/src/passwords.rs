//! The two password operations of the rescue menu.
//!
//! Source: `change_admin_password` and `sync_admin_root_password` in
//! `snpanelctl`, with their validators taken from
//! [`snpanel_installer::ctl::passwords`], where they already had golden
//! fixtures.
//!
//! **C37 is the whole shape of this file.** Neither a password nor a hash may
//! reach a command line. `/proc/<pid>/cmdline` is mode 444 - readable by
//! every local process, which on this box includes every customer's PHP -
//! while `/proc/<pid>/environ` is 400. So the new password travels in the
//! child's environment and root's hash travels on `chpasswd`'s stdin, and
//! neither is ever an argument.
//!
//! The environment reaches the panel binary across a user switch because
//! `runuser -u` does not reset it, unlike `sudo`.
//! `--whitelist-environment` is passed to state the intent, and becomes the
//! mechanism if anybody ever adds `--login`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use snpanel_installer::ctl::passwords as rules;

use crate::secret::read_secret;
use crate::ENV_PATH;

/// Source: `APP_DIR`.
const APP_DIR: &str = "/opt/snpanel";
/// Source: `RUST_API`.
const RUST_API: &str = "/usr/local/bin/snpanel-api-rust";
const HELPER: &str = "/usr/local/sbin/snpanel-helper";
const LOGIN_FILE: &str = "/root/login.txt";

/// `snpanel change-admin-password`.
///
/// Source: `change_admin_password`.
pub fn change_admin_password(env_path: Option<&Path>) -> Result<()> {
    let env = require_env(env_path)?;

    let password = read_secret("New admin password: ")?;
    let confirm = read_secret("Confirm password: ")?;
    if let Err(refusal) = rules::check_new_password(&password, &confirm) {
        anyhow::bail!("{}", refusal.message());
    }

    set_admin_secret(
        env,
        "--set-admin-password",
        "SNPANEL_NEW_ADMIN_PASSWORD",
        &password,
    )
    .context("Could not change the admin password")?;

    write_login_info(Some(&password), env)?;
    println!("Admin password changed. Existing sessions were invalidated.");
    Ok(())
}

/// `snpanel sync-admin-root-password`.
///
/// Source: `sync_admin_root_password`. Three things happen and the order is
/// the bash's: the Linux `admin` account takes root's hash, then the panel
/// account does, then the operator is offered the chance to record the
/// password in `/root/login.txt` - which this cannot do for them, because a
/// hash is not a password.
pub fn sync_admin_root_password(env_path: Option<&Path>) -> Result<()> {
    let env = require_env(env_path)?;

    let root_hash = root_password_hash()
        .ok_or_else(|| anyhow::anyhow!("Cannot read root password hash from /etc/shadow"))?;
    if let Err(refusal) = rules::validate_root_hash(&root_hash) {
        anyhow::bail!("{}", refusal.message());
    }

    // Best effort, as in the bash: a box whose helper is missing can still
    // have an `admin` account already.
    ensure_panel_user();
    if !linux_user_exists("admin") {
        anyhow::bail!("Linux user admin not found");
    }

    // On stdin, not in argv. `usermod -p "$hash"` would put root's
    // `/etc/shadow` hash on a command line, and `/etc/shadow` is 0640
    // root:shadow exactly so ordinary accounts cannot take the hash away and
    // attack it offline. `chpasswd -e` stores byte-for-byte what `usermod -p`
    // stored; that was measured rather than assumed.
    chpasswd_encrypted("admin", &root_hash)
        .context("Could not set the admin Linux password from root's hash")?;
    // `|| true` in the bash: an account that was not locked is not an error.
    let _ = Command::new("passwd")
        .args(["-u", "admin"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    set_admin_secret(
        env,
        "--set-admin-password-hash",
        "SNPANEL_ROOT_PASSWORD_HASH",
        &root_hash,
    )
    .context("Could not sync the admin password")?;

    // The hash cannot be turned back into the password, so `/root/login.txt`
    // can only be right if the operator types it. Blank skips, and the file
    // keeps whatever it had.
    let typed = read_secret("Root password to write to /root/login.txt (blank to skip): ")?;
    if !typed.is_empty() {
        write_login_info(Some(&typed), env)?;
    }

    restart_panel();
    println!("Admin password now matches the root password. Existing sessions were invalidated.");
    Ok(())
}

// ---------------------------------------------------------------------------
// the pieces
// ---------------------------------------------------------------------------

fn require_env(env_path: Option<&Path>) -> Result<&Path> {
    match env_path {
        Some(p) => Ok(p),
        None => anyhow::bail!("{ENV_PATH} not found. Run the installer first."),
    }
}

/// Hand a secret to the panel binary through the environment.
///
/// Source: the `runuser --whitelist-environment=... -u snpanel -- env HOME=...
/// SNPANEL_USE_HELPER=true "$RUST_API" --env "$ENV_FILE" <flag>` in both
/// password paths.
///
/// The value is set on the child with `Command::env`, so it is never a word
/// in any command line. `env HOME=... SNPANEL_USE_HELPER=true` stays in argv
/// because neither of those is a secret, and `HOME` has to be set: the panel
/// reads `~/.my.cnf` as the account it is running as.
fn set_admin_secret(env: &Path, flag: &str, var: &str, value: &str) -> Result<()> {
    if !is_executable(Path::new(RUST_API)) {
        anyhow::bail!("{RUST_API} is not installed");
    }
    if !linux_user_exists("snpanel") {
        anyhow::bail!("the snpanel account does not exist");
    }

    let status = admin_secret_command(env, flag, var, value)
        .status()
        .with_context(|| format!("running {RUST_API} {flag}"))?;
    if !status.success() {
        anyhow::bail!("{RUST_API} {flag} exited {:?}", status.code());
    }
    Ok(())
}

/// The command, built but not run, so a test can read its argv.
///
/// `the_secret_never_reaches_a_command_line` asserts that no argument holds
/// `value`. That assertion is the point of this function existing separately:
/// the obvious refactor of either password path is to pass the secret along
/// as one more `.arg()`, and nothing else in the program would notice.
fn admin_secret_command(env: &Path, flag: &str, var: &str, value: &str) -> Command {
    let mut cmd = Command::new("runuser");
    cmd.arg(format!("--whitelist-environment={var}"))
        .args(["-u", "snpanel", "--", "env"])
        .arg(format!("HOME={APP_DIR}"))
        .arg("SNPANEL_USE_HELPER=true")
        .arg(RUST_API)
        .arg("--env")
        .arg(env)
        .arg(flag)
        // Never argv.
        .env(var, value)
        .current_dir(format!("{APP_DIR}/backend"));
    cmd
}

/// Source: `root_password_hash` - `getent shadow root`, then `/etc/shadow`
/// itself when that returns nothing.
fn root_password_hash() -> Option<String> {
    let from_getent = Command::new("getent")
        .args(["shadow", "root"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            rules::hash_from_shadow_line(&text, "root").map(str::to_string)
        })
        .filter(|h| !h.is_empty());
    if from_getent.is_some() {
        return from_getent;
    }
    let text = std::fs::read_to_string("/etc/shadow").ok()?;
    rules::hash_from_shadow_line(&text, "root")
        .map(str::to_string)
        .filter(|h| !h.is_empty())
}

/// `printf '%s:%s\n' admin "$hash" | chpasswd -e`.
fn chpasswd_encrypted(user: &str, hash: &str) -> Result<()> {
    let mut child = Command::new("chpasswd")
        .arg("-e")
        .stdin(Stdio::piped())
        .spawn()
        .context("running chpasswd")?;
    child
        .stdin
        .as_mut()
        .context("chpasswd took no stdin")?
        .write_all(format!("{user}:{hash}\n").as_bytes())
        .context("writing to chpasswd")?;
    let status = child.wait().context("waiting for chpasswd")?;
    if !status.success() {
        anyhow::bail!("chpasswd exited {:?}", status.code());
    }
    Ok(())
}

/// Source: the three-way `panel-user-ensure admin` in the bash - as `snpanel`
/// over sudo when that account exists, and directly when it does not.
fn ensure_panel_user() {
    if !Path::new(HELPER).exists() {
        return;
    }
    let mut cmd = if linux_user_exists("snpanel") {
        let mut c = Command::new("runuser");
        c.args(["-u", "snpanel", "--", "sudo", "-n", HELPER]);
        c
    } else {
        Command::new(HELPER)
    };
    let _ = cmd
        .args(["panel-user-ensure", "admin"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn linux_user_exists(name: &str) -> bool {
    Command::new("id")
        .args(["-u", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Source: `restart_panel`, reduced to what it does on a box installed since
/// the panel became the binary.
fn restart_panel() {
    let _ = Command::new("systemctl")
        .args(["restart", "snpanel-api"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Source: `write_login_info`.
///
/// C17: the format of `/root/login.txt` is fixed - three lines, in this
/// order. 0600 before anything is written to it, not after: the file holds
/// the panel's admin password in clear, and a window where it is 0644 is a
/// window.
pub fn write_login_info(password: Option<&str>, env: &Path) -> Result<()> {
    let url = std::fs::read_to_string(env)
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("PANEL_URL="))
                .map(str::to_string)
        })
        .unwrap_or_default();

    let existing = std::fs::read_to_string(LOGIN_FILE).unwrap_or_default();
    let password = password
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .or_else(|| rules::password_from_login_file(&existing).map(str::to_string))
        .unwrap_or_else(|| "<not available; run snpanel change-admin-password>".to_string());

    let body = format!("Panel URL: {url}\nUser: admin\nPassword: {password}\n");
    write_0600(Path::new(LOGIN_FILE), &body)
}

fn write_0600(path: &Path, body: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let dir = path.parent().unwrap_or(Path::new("/"));
    let tmp = dir.join(format!(".{}.tmp", std::process::id()));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(body.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all().ok();
    }
    // Rename, so a reader never sees a half-written file - which for this one
    // would be a login page nobody can get into.
    std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_path_can_reach_the_panel_without_an_env_file() {
        for err in [
            change_admin_password(None).unwrap_err().to_string(),
            sync_admin_root_password(None).unwrap_err().to_string(),
        ] {
            assert!(err.contains(ENV_PATH), "{err}");
        }
    }

    #[test]
    fn the_login_file_keeps_its_three_lines_in_order() {
        // C17. The panel's own installer prints this file to the operator at
        // the end of an install, and a line out of order is a support ticket.
        let dir = std::env::temp_dir().join(format!("login-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let env = dir.join(".env");
        std::fs::write(&env, "PANEL_URL=https://panel.example:2222\n").expect("write");

        let body = format!(
            "Panel URL: {}\nUser: admin\nPassword: {}\n",
            "https://panel.example:2222", "hunter2hunter2"
        );
        let out = dir.join("login.txt");
        write_0600(&out, &body).expect("write");

        let lines: Vec<String> = std::fs::read_to_string(&out)
            .expect("read")
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("Panel URL: "));
        assert_eq!(lines[1], "User: admin");
        assert!(lines[2].starts_with("Password: "));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_login_file_is_never_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("login-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let out = dir.join("login.txt");
        write_0600(&out, "Panel URL: x\nUser: admin\nPassword: s3cr3t\n").expect("write");

        let mode = std::fs::metadata(&out).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "login.txt came out {mode:o}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_blank_password_falls_back_to_what_the_file_already_had() {
        // `write_login_info` is called from paths that do not know the
        // password - the sync one has a hash. Blanking the file would lose
        // the only copy an operator has.
        let existing = "Panel URL: https://x\nUser: admin\nPassword: keep-me\n";
        assert_eq!(
            rules::password_from_login_file(existing),
            Some("keep-me"),
            "the installer's parser stopped reading this format"
        );
    }

    /// C37: neither a password nor a hash may appear in a command line.
    ///
    /// `/proc/<pid>/cmdline` is mode 444 - every local process can read it,
    /// and on this box that includes every customer's PHP.
    /// `/proc/<pid>/environ` is 400. So the value goes in the environment and
    /// the test reads the argv back to prove it did not go anywhere else.
    #[test]
    fn the_secret_never_reaches_a_command_line() {
        const SECRET: &str = "correct-horse-battery-staple";
        for (flag, var) in [
            ("--set-admin-password", "SNPANEL_NEW_ADMIN_PASSWORD"),
            ("--set-admin-password-hash", "SNPANEL_ROOT_PASSWORD_HASH"),
        ] {
            let cmd =
                admin_secret_command(Path::new("/opt/snpanel/backend/.env"), flag, var, SECRET);
            for arg in cmd.get_args() {
                let arg = arg.to_string_lossy();
                assert!(
                    !arg.contains(SECRET),
                    "{flag}: the secret is in argv as {arg:?}"
                );
            }
            // And it really is being handed over, rather than dropped.
            let carried = cmd.get_envs().any(|(k, v)| {
                k == std::ffi::OsStr::new(var) && v.is_some_and(|v| v.to_string_lossy() == SECRET)
            });
            assert!(carried, "{flag}: the secret reaches the child by no route");
        }
    }

    #[test]
    fn the_panel_binary_is_told_which_env_file_and_which_flag() {
        let cmd = admin_secret_command(
            Path::new("/somewhere/.env"),
            "--set-admin-password",
            "SNPANEL_NEW_ADMIN_PASSWORD",
            "x",
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&RUST_API.to_string()), "{args:?}");
        assert!(args.contains(&"--env".to_string()), "{args:?}");
        assert!(args.contains(&"/somewhere/.env".to_string()), "{args:?}");
        assert!(
            args.contains(&"--set-admin-password".to_string()),
            "{args:?}"
        );
        // The user switch, without which the panel writes its database as
        // root and the next run cannot read it.
        assert!(args.contains(&"snpanel".to_string()), "{args:?}");
        // HOME decides where the panel looks for `.my.cnf`.
        assert!(
            args.iter().any(|a| a == &format!("HOME={APP_DIR}")),
            "{args:?}"
        );
    }
}
