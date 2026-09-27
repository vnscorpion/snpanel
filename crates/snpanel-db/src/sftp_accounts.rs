//! `sftp_accounts` - what the panel decided about a user's SFTP login.
//!
//! Not in the Python. There every panel user signed in over SFTP with their
//! panel password, which the panel copied into the Linux account on every
//! change, and a user with no row here still does exactly that. A row records
//! a decision made since: SFTP switched off, or given a password of its own.
//! After the second, a panel password change no longer reaches the Linux
//! account - so the panel password, behind two-step verification, is not also
//! an SFTP password behind nothing.
//!
//! **Rows answer to the username as well as the id**, like passkeys: SQLite
//! can hand a deleted user's id to the next account created.

use sqlx::sqlite::SqlitePool;

use super::DbError;

/// A user's SFTP login, as the panel decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SftpAccess {
    /// Whether the user may sign in over SFTP at all.
    pub enabled: bool,
    /// Whether the SFTP password is its own rather than the panel's.
    pub own_password: bool,
}

impl SftpAccess {
    /// A user the panel never decided anything for: the Python's behaviour.
    pub const DEFAULT: Self = Self {
        enabled: true,
        own_password: false,
    };

    /// Whether a panel password change should reach the Linux account.
    ///
    /// Not while SFTP is off either: setting the password unlocks the
    /// account, and the change would switch SFTP back on.
    pub fn follows_panel_password(&self) -> bool {
        self.enabled && !self.own_password
    }
}

/// A user's row, for the Users page's list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpAccountRow {
    pub user_id: i64,
    pub username: String,
    pub access: SftpAccess,
}

pub struct SftpAccountRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> SftpAccountRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// The user's SFTP login, or the default when nothing was decided.
    pub async fn get(&self, user_id: i64, username: &str) -> Result<SftpAccess, DbError> {
        let row: Option<(bool, bool)> = sqlx::query_as(
            "SELECT enabled, own_password FROM sftp_accounts WHERE user_id = ? AND username = ?",
        )
        .bind(user_id)
        .bind(username)
        .fetch_optional(self.pool)
        .await?;
        Ok(row
            .map(|(enabled, own_password)| SftpAccess {
                enabled,
                own_password,
            })
            .unwrap_or(SftpAccess::DEFAULT))
    }

    /// Every decision on record. A caller matches the username too.
    pub async fn all(&self) -> Result<Vec<SftpAccountRow>, DbError> {
        let rows: Vec<(i64, String, bool, bool)> = sqlx::query_as(
            "SELECT user_id, username, enabled, own_password FROM sftp_accounts ORDER BY user_id",
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(user_id, username, enabled, own_password)| SftpAccountRow {
                    user_id,
                    username,
                    access: SftpAccess {
                        enabled,
                        own_password,
                    },
                },
            )
            .collect())
    }

    /// Record a decision, replacing the last one.
    pub async fn set(
        &self,
        user_id: i64,
        username: &str,
        access: SftpAccess,
        now: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO sftp_accounts (user_id, username, enabled, own_password, updated_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (user_id) DO UPDATE SET username = excluded.username, \
             enabled = excluded.enabled, own_password = excluded.own_password, \
             updated_at = excluded.updated_at",
        )
        .bind(user_id)
        .bind(username)
        .bind(access.enabled)
        .bind(access.own_password)
        .bind(now)
        .execute(self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> super::super::Database {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let db = super::super::Database::from_pool(pool);
        db.create_fresh_schema().await.unwrap();
        db.apply_rust_migrations().await.unwrap();
        // Foreign keys are enforced, so the owners have to exist.
        sqlx::query(
            "INSERT INTO users (id, username, email, hashed_password) \
             VALUES (7, 'alice', 'alice@example.com', 'x'), (8, 'bob', 'bob@example.com', 'x')",
        )
        .execute(db.pool())
        .await
        .unwrap();
        db
    }

    const NOW: &str = "2026-09-25 10:00:00.000000";

    /// A user nobody decided anything for signs in with the panel password.
    #[tokio::test]
    async fn no_row_is_the_pythons_behaviour() {
        let db = db().await;
        let access = db.sftp_accounts().get(7, "alice").await.unwrap();
        assert_eq!(access, SftpAccess::DEFAULT);
        assert!(access.enabled && access.follows_panel_password());
    }

    #[tokio::test]
    async fn a_decision_is_kept_and_replaced() {
        let db = db().await;
        let repo = db.sftp_accounts();
        let off = SftpAccess {
            enabled: false,
            own_password: false,
        };
        repo.set(7, "alice", off, NOW).await.unwrap();
        assert_eq!(repo.get(7, "alice").await.unwrap(), off);
        // Bob is untouched.
        assert_eq!(repo.get(8, "bob").await.unwrap(), SftpAccess::DEFAULT);

        let own = SftpAccess {
            enabled: true,
            own_password: true,
        };
        repo.set(7, "alice", own, NOW).await.unwrap();
        assert_eq!(repo.get(7, "alice").await.unwrap(), own);
        assert_eq!(repo.all().await.unwrap().len(), 1);
    }

    /// Off, or with a password of its own: a panel password change stays
    /// out of the Linux account. Only the default follows it.
    #[test]
    fn only_an_sftp_login_on_the_panel_password_follows_it() {
        for (enabled, own_password, follows) in [
            (true, false, true),
            (true, true, false),
            (false, false, false),
            (false, true, false),
        ] {
            let access = SftpAccess {
                enabled,
                own_password,
            };
            assert_eq!(access.follows_panel_password(), follows, "{access:?}");
        }
    }

    /// A row left by a deleted user does not follow the number.
    #[tokio::test]
    async fn a_row_answers_to_the_username_too() {
        let db = db().await;
        let repo = db.sftp_accounts();
        repo.set(
            7,
            "alice",
            SftpAccess {
                enabled: false,
                own_password: true,
            },
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(repo.get(7, "mallory").await.unwrap(), SftpAccess::DEFAULT);
    }

    /// Deleting the user deletes the decision.
    #[tokio::test]
    async fn deleting_the_user_deletes_the_row() {
        let db = db().await;
        let repo = db.sftp_accounts();
        repo.set(8, "bob", SftpAccess::DEFAULT, NOW).await.unwrap();
        sqlx::query("DELETE FROM users WHERE id = 8")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(repo.all().await.unwrap().is_empty());
    }
}
