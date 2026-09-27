//! A panel user's SFTP login, where it meets the rest of the panel.
//!
//! Not in the Python, where the SFTP login was the panel password, copied into
//! the Linux account on every change and never shown anywhere. It is an
//! account of its own now - see `snpanel_db::sftp_accounts` - and three things
//! ask about it:
//!
//! - a panel password change reaches the Linux account only while the SFTP
//!   login still follows it;
//! - un-suspending a user unlocks their Linux account only when their SFTP is
//!   on;
//! - the Users page and the user's own Security page show it and change it.

use snpanel_db::sftp_accounts::SftpAccess;
use snpanel_db::Database;

/// The Linux account of a panel user: the panel name, lowercased.
///
/// Source: `linux_user_for_panel_username` - parsing is what validates it.
pub fn linux_account(username: &str) -> Result<snpanel_core::types::PanelUsername, String> {
    snpanel_core::types::PanelUsername::parse(username.trim().to_lowercase().as_str())
        .map_err(|e| format!("invalid username: {e}"))
}

/// What the panel decided for this user, or the default.
pub async fn access(db: &Database, user_id: i64, username: &str) -> Result<SftpAccess, String> {
    db.sftp_accounts()
        .get(user_id, username)
        .await
        .map_err(|e| format!("reading the SFTP settings failed: {e}"))
}

/// A panel password that changed, into the Linux account when the SFTP login
/// follows it; nothing otherwise.
///
/// Not while SFTP is off: setting the password unlocks the account, and a
/// password change would switch SFTP back on behind the administrator's back.
/// Not when the SFTP login has a password of its own: that is what it is for.
pub async fn follow_panel_password(
    db: &Database,
    dry_run: bool,
    user_id: i64,
    username: &str,
    password: &str,
) -> Result<(), String> {
    if !access(db, user_id, username)
        .await?
        .follows_panel_password()
    {
        return Ok(());
    }
    let account = linux_account(username)?;
    // On stdin, never in argv: `/proc/<pid>/cmdline` is world-readable (C37).
    let result = crate::shell::privileged(
        dry_run,
        "panel-user-password",
        &[account.as_str()],
        Some(&format!("{password}\n")),
        // Source: `fallback=["true"]` - a machine with no helper still
        // changes the panel password.
        Some(&["true"]),
    )
    .await;
    if result.ok() {
        Ok(())
    } else {
        Err(result
            .failure_detail("panel-user-password")
            .trim()
            .to_string())
    }
}

/// Lock or unlock the Linux accounts of a user being suspended or let back
/// in: their own, and each of their sites' runtime accounts.
///
/// Their own as well, which the per-site loop this replaces missed: a user
/// with no sites kept their SFTP login through a suspension. And unlocking
/// only when their SFTP is on - a user whose SFTP an administrator switched
/// off stays locked when the suspension ends.
///
/// Source: `site_users.lock_linux_user` / `unlock_linux_user`, inside a bare
/// `except Exception: pass`: a refusal is logged and the rest go on.
pub async fn set_locked(
    db: &Database,
    dry_run: bool,
    user_id: i64,
    username: &str,
    site_accounts: &[Option<String>],
    lock: bool,
) {
    let decided = if lock {
        // Locking does not depend on it, and must not wait on it.
        SftpAccess::DEFAULT
    } else {
        match access(db, user_id, username).await {
            Ok(access) => access,
            Err(e) => {
                // Unlocking an account that was meant to stay locked is the
                // worse mistake of the two.
                tracing::warn!("not unlocking {username}: {e}");
                return;
            }
        }
    };
    for account in lock_targets(username, site_accounts, lock, decided) {
        let Ok(safe) = snpanel_core::types::PanelUsername::parse(&account) else {
            continue;
        };
        let result = if lock {
            crate::shell::privileged(
                dry_run,
                "panel-user-lock",
                &[safe.as_str()],
                None,
                Some(&["usermod", "-L", safe.as_str()]),
            )
            .await
        } else {
            crate::shell::privileged(
                dry_run,
                "panel-user-unlock",
                &[safe.as_str()],
                None,
                Some(&["usermod", "-U", safe.as_str()]),
            )
            .await
        };
        if !result.ok() {
            tracing::warn!(
                "could not {} {safe}: {}",
                if lock { "lock" } else { "unlock" },
                result.failure_detail("no detail").trim()
            );
        }
    }
    // The user's own SFTP accounts: locked with them, and unlocked when the
    // suspension ends - they have passwords of their own, which the owner's
    // SFTP being switched off says nothing about.
    let subaccounts = db
        .sftp_subaccounts()
        .list_for(user_id)
        .await
        .unwrap_or_default();
    for sub in subaccounts {
        let Ok(safe) = snpanel_core::types::PanelUsername::parse(&sub.username) else {
            continue;
        };
        let result = if lock {
            crate::shell::privileged(dry_run, "panel-user-lock", &[safe.as_str()], None, None).await
        } else {
            crate::shell::privileged(dry_run, "panel-user-unlock", &[safe.as_str()], None, None)
                .await
        };
        if !result.ok() {
            tracing::warn!("could not lock or unlock SFTP account {safe}");
        }
    }
}

/// The accounts a suspension locks, or its end unlocks: the user's own and
/// their sites', each once - and none to unlock while their SFTP is off.
fn lock_targets(
    username: &str,
    site_accounts: &[Option<String>],
    lock: bool,
    access: SftpAccess,
) -> Vec<String> {
    if !lock && !access.enabled {
        return Vec::new();
    }
    let mut accounts = std::collections::BTreeSet::new();
    accounts.insert(username.trim().to_lowercase());
    for site in site_accounts.iter().flatten() {
        if !site.is_empty() {
            accounts.insert(site.clone());
        }
    }
    accounts.into_iter().collect()
}

/// The ports sshd listens on, as the helper reads them; empty when it
/// cannot say.
pub async fn ssh_ports(dry_run: bool) -> Vec<u16> {
    let result = crate::shell::privileged(dry_run, "ssh-ports", &[], None, None).await;
    if !result.ok() {
        return Vec::new();
    }
    serde_json::from_str::<serde_json::Value>(result.stdout.trim())
        .ok()
        .and_then(|v| {
            v["ports"].as_array().map(|ports| {
                ports
                    .iter()
                    .filter_map(|p| p.as_u64().and_then(|p| u16::try_from(p).ok()))
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// A password for the SFTP login, when the administrator asks for one.
///
/// Twenty letters and digits, without the ones that read as each other -
/// `0`/`O`, `1`/`l`/`I` - because somebody will read it out over the phone.
/// About 116 bits. No `:` either, which `chpasswd` would read as the end of
/// the name.
pub fn generated_password() -> String {
    use rand::RngCore;

    const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    const LENGTH: usize = 20;
    // Rejection sampling, not `% len`, as `mariadb::random_password` does.
    let limit = (256 / ALPHABET.len()) * ALPHABET.len();
    let mut out = String::with_capacity(LENGTH);
    let mut buf = [0u8; 64];
    while out.len() < LENGTH {
        rand::rngs::OsRng.fill_bytes(&mut buf);
        for byte in buf {
            if out.len() == LENGTH {
                break;
            }
            if (byte as usize) < limit {
                out.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
            }
        }
    }
    out
}

/// A password typed for the SFTP login: the helper's rules, checked first so
/// the page can say which one.
pub fn check_password(password: &str) -> Result<(), &'static str> {
    let length = password.chars().count();
    if length < 12 {
        return Err("The SFTP password must be at least 12 characters.");
    }
    if password.len() > 72 {
        return Err("The SFTP password must be at most 72 bytes.");
    }
    if password.contains([':', '\r', '\n', '\0']) {
        return Err("The SFTP password cannot contain ':' or line breaks.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_is_the_panel_name_lowercased() {
        assert_eq!(linux_account(" Alice ").unwrap().as_str(), "alice");
        assert!(linux_account("../etc").is_err());
    }

    /// The user's own account whether or not they have sites - a user with
    /// none kept theirs unlocked through a suspension - each account once,
    /// and nothing unlocked while their SFTP is off.
    #[test]
    fn a_suspension_locks_every_account_and_its_end_unlocks_only_with_sftp_on() {
        let sites = [
            Some("alice".to_string()),
            None,
            Some(String::new()),
            Some("alice".to_string()),
        ];
        let off = SftpAccess {
            enabled: false,
            own_password: true,
        };
        assert_eq!(lock_targets("Alice", &[], true, off), ["alice"]);
        assert_eq!(lock_targets("Alice", &sites, true, off), ["alice"]);
        assert_eq!(
            lock_targets(
                "alice",
                &[Some("legacy_site".to_string())],
                true,
                SftpAccess::DEFAULT
            ),
            ["alice", "legacy_site"]
        );
        assert!(lock_targets("alice", &sites, false, off).is_empty());
        assert_eq!(
            lock_targets("alice", &sites, false, SftpAccess::DEFAULT),
            ["alice"]
        );
    }

    #[test]
    fn a_typed_password_meets_the_helpers_rules() {
        assert_eq!(check_password("correct horse battery"), Ok(()));
        assert!(check_password("short").is_err());
        // The edges, which are the helper's: 12 characters to 72 bytes.
        assert!(check_password("elevenchars").is_err());
        assert_eq!(check_password("twelve chars"), Ok(()));
        assert_eq!(check_password(&"x".repeat(72)), Ok(()));
        assert!(check_password(&"x".repeat(73)).is_err());
        // Twelve characters, of which some are two bytes each.
        assert_eq!(check_password("mật khẩu dài!"), Ok(()));
        for bad in [
            "correct:horse battery",
            "correct horse\nbattery",
            "correct horse\rbattery",
        ] {
            assert!(check_password(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_generated_password_is_one_the_helper_takes() {
        for _ in 0..50 {
            let password = generated_password();
            assert_eq!(password.len(), 20);
            assert_eq!(check_password(&password), Ok(()));
            assert!(
                password.chars().all(|c| c.is_ascii_alphanumeric()),
                "{password}"
            );
            assert!(!password.contains(['0', 'O', '1', 'l', 'I']), "{password}");
        }
    }
}
