//! The database writes `snpanelctl` asks for.
//!
//! Source: the two inline Python blocks in `installer/files/snpanelctl` —
//! `change_admin_password` and `sync_admin_root_password`. Each opened a
//! session, read the `admin` row, wrote `hashed_password`, bumped
//! `token_version` and committed. That is the last of the panel's own logic
//! that the shipped bash reached for Python to do.
//!
//! **Run as `snpanel`, through the `runuser` the bash already has.** Not
//! because the writes need privilege — they do not — but because SQLite
//! creates `-wal` and `-shm` beside the database, and a root-owned pair of
//! those is a panel that cannot write to its own database afterwards. The
//! shell keeps the user switch; only the command inside it changes.
//!
//! The secret arrives in the **environment**, under the name the bash
//! already exports. C37: `/proc/<pid>/cmdline` is mode 444 and a hosting box
//! runs other people's PHP, so a flag taking the password as an argument
//! would undo the thing `snpanelctl` was fixed for in the first place.

use snpanel_db::Database;

/// The flags the bash passes.
pub(crate) const SET_ADMIN_PASSWORD: &str = "--set-admin-password";
pub(crate) const SET_ADMIN_PASSWORD_HASH: &str = "--set-admin-password-hash";

/// `snpanel reset-admin-2fa`. New in the Rust port: no secret travels, so
/// nothing is read from the environment.
pub(crate) const RESET_ADMIN_2FA: &str = "--reset-admin-2fa";

/// Source: `export SNPANEL_NEW_ADMIN_PASSWORD="$password"`.
pub(crate) const NEW_PASSWORD_ENV: &str = "SNPANEL_NEW_ADMIN_PASSWORD";

/// Source: `export SNPANEL_ROOT_PASSWORD_HASH="$root_hash"`.
pub(crate) const ROOT_HASH_ENV: &str = "SNPANEL_ROOT_PASSWORD_HASH";

/// Source: `db.query(User).filter(User.username == "admin")`.
pub(crate) const ADMIN_USERNAME: &str = "admin";

/// Source: `raise SystemExit("admin user not found")`.
const NO_ADMIN: &str = "admin user not found";

/// Source: the `change_admin_password` Python block.
///
/// Three things in an order that is not arbitrary. The Linux account's
/// password is set **first**, through the helper: if that fails the panel
/// row is untouched, and the operator retries with the two still agreeing.
/// Done the other way round, a helper failure would leave the panel
/// accepting a password that SSH does not.
///
/// **There is no unit test for that ordering**, and the reason is the
/// Python's own `fallback=["true"]`: on a machine with no helper the
/// fallback succeeds and the change proceeds, which is the behaviour being
/// reproduced. The failure is only reachable on a box that has a helper
/// which then refuses, so a test here could only ever pass.
pub(crate) async fn set_admin_password(
    db: &Database,
    password: &str,
    dry_run: bool,
) -> anyhow::Result<()> {
    let users = db.users();
    let Some(admin) = users.by_username(ADMIN_USERNAME).await? else {
        anyhow::bail!("{NO_ADMIN}");
    };

    // Source: `site_users.set_panel_user_password(user.username, password)`.
    // On stdin, as the helper takes it - while the SFTP login still follows
    // the panel password.
    if snpanel_core::types::PanelUsername::parse(&admin.username).is_err() {
        anyhow::bail!("{} is not a usable Linux account name", admin.username);
    }
    if let Err(detail) =
        crate::sftp_access::follow_panel_password(db, dry_run, admin.id, &admin.username, password)
            .await
    {
        anyhow::bail!("Could not set the admin system password: {detail}");
    }

    let hash = snpanel_core::crypto::password::hash_password(password)
        .map_err(|e| anyhow::anyhow!("could not hash the password: {e}"))?;
    users
        .set_password_and_invalidate_sessions(admin.id, &hash)
        .await?;
    Ok(())
}

/// Source: the `sync_admin_root_password` Python block.
///
/// The hash is stored **as given**: it is root's crypt(3) hash out of
/// `/etc/shadow`, not bcrypt, and re-hashing it would make the panel accept
/// a password nobody has. `snpanel_core::crypto::password` is what tells the
/// two schemes apart at verify time.
///
/// No helper call here, and that is the Python's shape too — the shell has
/// already given the Linux account the same hash before it gets this far.
pub(crate) async fn set_admin_password_hash(db: &Database, hash: &str) -> anyhow::Result<()> {
    let users = db.users();
    let Some(admin) = users.by_username(ADMIN_USERNAME).await? else {
        anyhow::bail!("{NO_ADMIN}");
    };
    users
        .set_password_and_invalidate_sessions(admin.id, hash)
        .await?;
    Ok(())
}

/// The admin's two-step sign-in taken away - the authenticator-app code and
/// every passkey - for an administrator who lost the device, or whose only
/// passkeys were made for an address that no longer reaches the panel. New
/// in the Rust port: the Python's only way back was editing the database.
///
/// Root on the server is the proof, as it is for a new password. Every
/// session ends with it: `set_totp_enabled` bumps `token_version` whether or
/// not the code was on. Passkeys go first, so a failure halfway leaves the
/// code, which the administrator can still turn off from the page.
///
/// Returns whether the code was on, and how many passkeys went.
pub(crate) async fn reset_admin_two_factor(db: &Database) -> anyhow::Result<(bool, u64)> {
    let users = db.users();
    let Some(admin) = users.by_username(ADMIN_USERNAME).await? else {
        anyhow::bail!("{NO_ADMIN}");
    };
    let passkeys = db.passkeys().delete_for_user(admin.id).await?;
    users.set_totp_enabled(admin.id, false, true).await?;
    Ok((admin.totp_enabled, passkeys))
}

/// What the flag found in the environment, or why it could not run.
///
/// A missing variable is a caller error rather than "no password given":
/// the bash exports it immediately before, so absence means the two sides
/// have drifted, and silently changing nothing would be the worst of the
/// available outcomes.
pub(crate) fn secret_from_env(name: &str) -> anyhow::Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => anyhow::bail!(
            "{name} is not set; it carries the secret, and it is set by the caller \
             rather than passed as an argument because /proc/<pid>/cmdline is \
             world-readable"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real database, built the way an install builds one, with one
    /// admin in it.
    ///
    /// On a file rather than in memory because `Database::from_pool` is
    /// crate-private to `snpanel-db` — and that is the better test anyway:
    /// this goes through `Database::create` and `create_fresh_schema`, which
    /// is the path `--init-db` takes.
    ///
    /// `tag` gives each test its own directory. Six tests here once shared
    /// one name and deleted each other's trees.
    async fn panel(tag: &str) -> (Database, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("snpanel-ctl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snpanel.db");
        // Four slashes for an absolute path: SQLAlchemy's convention, which
        // `sqlite_path` reproduces. `sqlite:///tmp/x` is the *relative*
        // `tmp/x`, which is how this first failed.

        let db = Database::create(&format!("sqlite:///{}", path.display()))
            .await
            .unwrap();
        db.create_fresh_schema().await.unwrap();
        // As every start does before `--set-admin-password` can run: the
        // password change reads the SFTP settings a Rust migration adds.
        db.apply_rust_migrations().await.unwrap();
        db.users()
            .create(&snpanel_db::NewUser {
                username: ADMIN_USERNAME,
                email: "admin@example.com",
                hashed_password: "$2b$12$whatever-was-there-before",
                role: "admin",
                package_id: None,
                website_limit: 999,
                storage_limit_mb: 102_400,
                terminal_enabled: false,
            })
            .await
            .unwrap();
        (db, dir)
    }

    async fn stored(db: &Database) -> (String, i64) {
        let admin = db
            .users()
            .by_username(ADMIN_USERNAME)
            .await
            .unwrap()
            .expect("the fixture puts an admin here");
        (admin.hashed_password, admin.token_version)
    }

    #[tokio::test]
    async fn changing_the_password_stores_bcrypt_and_invalidates_sessions() {
        let (db, dir) = panel("changing").await;
        let (_, before) = stored(&db).await;
        set_admin_password(&db, "a new long password", true)
            .await
            .unwrap();

        let (hash, token_version) = stored(&db).await;
        assert!(
            snpanel_core::crypto::password::verify_password("a new long password", &hash),
            "the stored hash does not verify the password that was set"
        );
        assert_eq!(
            token_version,
            before + 1,
            "every existing session has to stop working"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// **The root hash is stored exactly as it was read.**
    ///
    /// It is a crypt(3) hash out of `/etc/shadow`, not bcrypt. Hashing it
    /// again would store a bcrypt of the *hash text*, and the panel would
    /// then accept a password nobody knows and refuse the root password it
    /// was meant to match.
    #[tokio::test]
    async fn the_root_hash_is_stored_verbatim() {
        let (db, dir) = panel("roothash").await;
        let (_, before) = stored(&db).await;
        let root_hash = "$6$rounds=5000$abcdefgh$0123456789abcdef";
        set_admin_password_hash(&db, root_hash).await.unwrap();

        let (hash, token_version) = stored(&db).await;
        assert_eq!(hash, root_hash);
        assert_eq!(token_version, before + 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// **A lost device is not a locked panel.** The code and every passkey
    /// go, and so does every session - other accounts' passkeys stay.
    #[tokio::test]
    async fn resetting_two_step_sign_in_takes_the_code_and_the_passkeys() {
        let (db, dir) = panel("reset2fa").await;
        let admin = db
            .users()
            .by_username(ADMIN_USERNAME)
            .await
            .unwrap()
            .unwrap();
        let other = db
            .users()
            .create(&snpanel_db::NewUser {
                username: "customer",
                email: "customer@example.com",
                hashed_password: "$2b$12$whatever-was-there-before",
                role: "end_user",
                package_id: None,
                website_limit: 1,
                storage_limit_mb: 100,
                terminal_enabled: false,
            })
            .await
            .unwrap();
        db.users()
            .set_totp_secret(admin.id, Some("fernet:x"))
            .await
            .unwrap();
        db.users()
            .set_totp_enabled(admin.id, true, false)
            .await
            .unwrap();
        for (user_id, username, credential) in [
            (admin.id, ADMIN_USERNAME, "a1"),
            (admin.id, ADMIN_USERNAME, "a2"),
            (other, "customer", "c1"),
        ] {
            db.passkeys()
                .insert(&snpanel_db::NewPasskey {
                    user_id,
                    username,
                    credential_id: credential,
                    public_key: &[1],
                    algorithm: -7,
                    sign_count: 0,
                    rp_id: "panel.example.com",
                    name: "Laptop",
                    aaguid: "00000000-0000-0000-0000-000000000000",
                    created_at: "2026-09-26 10:00:00.000000",
                })
                .await
                .unwrap();
        }
        let (_, before) = stored(&db).await;

        let (had_code, passkeys) = reset_admin_two_factor(&db).await.unwrap();
        assert!(had_code);
        assert_eq!(passkeys, 2);
        let after = db
            .users()
            .by_username(ADMIN_USERNAME)
            .await
            .unwrap()
            .unwrap();
        assert!(!after.totp_enabled);
        assert_eq!(after.totp_secret, None);
        assert_eq!(after.token_version, before + 1, "every session ends");
        assert!(db
            .passkeys()
            .for_user(admin.id, ADMIN_USERNAME)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            db.passkeys()
                .for_user(other, "customer")
                .await
                .unwrap()
                .len(),
            1,
            "another account's passkeys are not the admin's to lose"
        );

        // Nothing left to take: says so.
        assert_eq!(reset_admin_two_factor(&db).await.unwrap(), (false, 0));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_panel_without_an_admin_says_so() {
        let (db, dir) = panel("noadmin").await;
        let admin = db
            .users()
            .by_username(ADMIN_USERNAME)
            .await
            .unwrap()
            .unwrap();
        assert!(db.users().delete(admin.id).await.unwrap());
        for outcome in [
            set_admin_password(&db, "a new long password", true)
                .await
                .unwrap_err()
                .to_string(),
            set_admin_password_hash(&db, "$6$x$y")
                .await
                .unwrap_err()
                .to_string(),
            reset_admin_two_factor(&db).await.unwrap_err().to_string(),
        ] {
            assert_eq!(outcome, NO_ADMIN, "the same words the Python raised");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// **An unset variable is an error, not a quiet no-op.**
    ///
    /// The bash exports it immediately before calling, so absence means the
    /// two sides have drifted — and a run that silently changed nothing,
    /// after telling the operator their password was changed, is the worst
    /// outcome available.
    #[test]
    fn a_missing_secret_is_refused() {
        let name = "SNPANEL_TEST_SECRET_THAT_IS_NOT_SET";
        assert!(secret_from_env(name).is_err());
        assert!(secret_from_env(name)
            .unwrap_err()
            .to_string()
            .contains(name));
    }
}
