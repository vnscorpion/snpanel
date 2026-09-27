//! `passkeys` - the WebAuthn credentials a panel user signs in with.
//!
//! A passkey is a second factor beside the authenticator-app code, never
//! instead of it: the panel only lets someone add one while their app code
//! is set up, and turning the code off removes their passkeys with it. So an
//! account whose passkey is lost still has the code to fall back on.
//!
//! Nothing here is secret. The table holds public keys and credential ids;
//! the private halves never leave the authenticators.
//!
//! **Rows answer to the username as well as the id.** SQLite hands a
//! deleted user's id to the next account created when that user had the
//! highest one. A passkey left behind by such a user must not become a
//! second factor for whoever gets the number next, so every read that
//! decides a sign-in matches on both.

use sqlx::sqlite::SqlitePool;

use super::DbError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Passkey {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    /// base64url, as the browser reports it.
    pub credential_id: String,
    /// The COSE key the authenticator gave at registration.
    pub public_key: Vec<u8>,
    pub algorithm: i64,
    pub sign_count: i64,
    /// The host it was registered on; it only works there.
    pub rp_id: String,
    pub name: String,
    pub aaguid: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// What registration stores.
#[derive(Debug, Clone)]
pub struct NewPasskey<'a> {
    pub user_id: i64,
    pub username: &'a str,
    pub credential_id: &'a str,
    pub public_key: &'a [u8],
    pub algorithm: i64,
    pub sign_count: i64,
    pub rp_id: &'a str,
    pub name: &'a str,
    pub aaguid: &'a str,
    pub created_at: &'a str,
}

const COLUMNS: &str = "id, user_id, username, credential_id, public_key, algorithm, sign_count, \
                       rp_id, name, aaguid, created_at, last_used_at";

pub struct PasskeyRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> PasskeyRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// A user's passkeys, oldest first.
    pub async fn for_user(&self, user_id: i64, username: &str) -> Result<Vec<Passkey>, DbError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM passkeys WHERE user_id = ? AND username = ? ORDER BY id"
        );
        Ok(sqlx::query_as::<_, Passkey>(&sql)
            .bind(user_id)
            .bind(username)
            .fetch_all(self.pool)
            .await?)
    }

    /// Whether a credential id is taken, by anyone.
    pub async fn credential_exists(&self, credential_id: &str) -> Result<bool, DbError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE credential_id = ?")
                .bind(credential_id)
                .fetch_one(self.pool)
                .await?;
        Ok(count > 0)
    }

    pub async fn insert(&self, new: &NewPasskey<'_>) -> Result<Passkey, DbError> {
        let sql = format!(
            "INSERT INTO passkeys (user_id, username, credential_id, public_key, algorithm, \
             sign_count, rp_id, name, aaguid, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING {COLUMNS}"
        );
        Ok(sqlx::query_as::<_, Passkey>(&sql)
            .bind(new.user_id)
            .bind(new.username)
            .bind(new.credential_id)
            .bind(new.public_key)
            .bind(new.algorithm)
            .bind(new.sign_count)
            .bind(new.rp_id)
            .bind(new.name)
            .bind(new.aaguid)
            .bind(new.created_at)
            .fetch_one(self.pool)
            .await?)
    }

    /// After a sign-in: the counter the authenticator reported, and when.
    ///
    /// Conditional on the counter the check was made against, so two
    /// sign-ins racing with one assertion cannot both succeed.
    pub async fn record_use(
        &self,
        id: i64,
        seen_count: i64,
        new_count: i64,
        at: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND sign_count = ?",
        )
        .bind(new_count)
        .bind(at)
        .bind(id)
        .bind(seen_count)
        .execute(self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// One of the user's own; another user's id deletes nothing.
    pub async fn delete(&self, id: i64, user_id: i64) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM passkeys WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Every passkey of a user: when their app code is turned off, and when
    /// the user is deleted.
    pub async fn delete_for_user(&self, user_id: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM passkeys WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(result.rows_affected())
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

    fn new<'a>(user_id: i64, username: &'a str, credential_id: &'a str) -> NewPasskey<'a> {
        NewPasskey {
            user_id,
            username,
            credential_id,
            public_key: &[1, 2, 3],
            algorithm: -7,
            sign_count: 0,
            rp_id: "panel.example.com",
            name: "Laptop",
            aaguid: "",
            created_at: "2026-09-25 10:00:00.000000",
        }
    }

    #[tokio::test]
    async fn a_passkey_is_stored_and_found_by_its_owner() {
        let db = db().await;
        let repo = db.passkeys();
        let stored = repo.insert(&new(7, "alice", "cred-1")).await.unwrap();
        assert_eq!(stored.public_key, vec![1, 2, 3]);
        assert_eq!(stored.last_used_at, None);

        let found = repo.for_user(7, "alice").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_id, "cred-1");
        assert!(repo.credential_exists("cred-1").await.unwrap());
        assert!(!repo.credential_exists("cred-2").await.unwrap());
    }

    /// The id-reuse case: the same number, another name, no passkeys.
    #[tokio::test]
    async fn a_reused_user_id_does_not_inherit_passkeys() {
        let db = db().await;
        let repo = db.passkeys();
        repo.insert(&new(7, "alice", "cred-1")).await.unwrap();
        assert!(repo.for_user(7, "mallory").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_credential_id_is_stored_once() {
        let db = db().await;
        let repo = db.passkeys();
        repo.insert(&new(7, "alice", "cred-1")).await.unwrap();
        assert!(repo.insert(&new(8, "bob", "cred-1")).await.is_err());
    }

    #[tokio::test]
    async fn a_use_is_recorded_once_per_counter_value() {
        let db = db().await;
        let repo = db.passkeys();
        let stored = repo.insert(&new(7, "alice", "cred-1")).await.unwrap();
        assert!(repo
            .record_use(stored.id, 0, 5, "2026-09-25 11:00:00.000000")
            .await
            .unwrap());
        // The same assertion, checked against the old counter, a moment later.
        assert!(!repo
            .record_use(stored.id, 0, 5, "2026-09-25 11:00:01.000000")
            .await
            .unwrap());
        let now = &repo.for_user(7, "alice").await.unwrap()[0];
        assert_eq!(now.sign_count, 5);
        assert_eq!(
            now.last_used_at.as_deref(),
            Some("2026-09-25 11:00:00.000000")
        );
    }

    /// Deleting the user takes their passkeys with them - the foreign key
    /// does it, whichever code deletes the row.
    #[tokio::test]
    async fn a_deleted_user_leaves_no_passkeys() {
        let db = db().await;
        let repo = db.passkeys();
        repo.insert(&new(7, "alice", "cred-1")).await.unwrap();
        repo.insert(&new(8, "bob", "cred-2")).await.unwrap();
        sqlx::query("DELETE FROM users WHERE id = 7")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(!repo.credential_exists("cred-1").await.unwrap());
        assert!(repo.credential_exists("cred-2").await.unwrap());
    }

    #[tokio::test]
    async fn only_the_owner_deletes_and_turning_2fa_off_deletes_all() {
        let db = db().await;
        let repo = db.passkeys();
        let one = repo.insert(&new(7, "alice", "cred-1")).await.unwrap();
        repo.insert(&new(7, "alice", "cred-2")).await.unwrap();
        repo.insert(&new(8, "bob", "cred-3")).await.unwrap();

        assert!(
            !repo.delete(one.id, 8).await.unwrap(),
            "bob cannot delete alice's"
        );
        assert!(repo.delete(one.id, 7).await.unwrap());
        assert_eq!(repo.delete_for_user(7).await.unwrap(), 1);
        assert!(repo.for_user(7, "alice").await.unwrap().is_empty());
        assert_eq!(
            repo.for_user(8, "bob").await.unwrap().len(),
            1,
            "bob's is untouched"
        );
    }
}
