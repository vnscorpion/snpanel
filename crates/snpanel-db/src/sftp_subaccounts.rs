//! `sftp_subaccounts` - a user's own SFTP accounts: extra logins, each shut
//! into one folder of their home.
//!
//! Not in the Python. The Linux accounts, their jails and their mounts are
//! the helper's (`ops/sftp_sub.rs`); this is the list the panel shows and
//! the folder each was given, so a suspension can lock them and a site's
//! removal can take along the accounts that pointed into it.

use sqlx::sqlite::SqlitePool;

use super::DbError;

/// One SFTP account of a user's.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SftpSubaccount {
    pub id: i64,
    pub user_id: i64,
    /// The Linux account: `<owner>_<name>`.
    pub username: String,
    /// Below the owner's home, `.` for all of it.
    pub directory: String,
    pub created_at: String,
}

const COLUMNS: &str = "id, user_id, username, directory, created_at";

pub struct SftpSubaccountRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> SftpSubaccountRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// A user's accounts, the oldest first.
    pub async fn list_for(&self, user_id: i64) -> Result<Vec<SftpSubaccount>, DbError> {
        Ok(sqlx::query_as::<_, SftpSubaccount>(&format!(
            "SELECT {COLUMNS} FROM sftp_subaccounts WHERE user_id = ? ORDER BY id"
        ))
        .bind(user_id)
        .fetch_all(self.pool)
        .await?)
    }

    /// One of a user's accounts - `None` when the id is someone else's.
    pub async fn by_id(&self, user_id: i64, id: i64) -> Result<Option<SftpSubaccount>, DbError> {
        Ok(sqlx::query_as::<_, SftpSubaccount>(&format!(
            "SELECT {COLUMNS} FROM sftp_subaccounts WHERE user_id = ? AND id = ?"
        ))
        .bind(user_id)
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Whether an account of this name exists, anyone's.
    pub async fn username_taken(&self, username: &str) -> Result<bool, DbError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sftp_subaccounts WHERE username = ?")
                .bind(username)
                .fetch_one(self.pool)
                .await?;
        Ok(count > 0)
    }

    pub async fn create(
        &self,
        user_id: i64,
        username: &str,
        directory: &str,
        now: &str,
    ) -> Result<SftpSubaccount, DbError> {
        Ok(sqlx::query_as::<_, SftpSubaccount>(&format!(
            "INSERT INTO sftp_subaccounts (user_id, username, directory, created_at) \
             VALUES (?, ?, ?, ?) RETURNING {COLUMNS}"
        ))
        .bind(user_id)
        .bind(username)
        .bind(directory)
        .bind(now)
        .fetch_one(self.pool)
        .await?)
    }

    pub async fn delete(&self, user_id: i64, id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM sftp_subaccounts WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scratch() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        for statement in [
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)",
            "CREATE TABLE sftp_subaccounts (id INTEGER NOT NULL PRIMARY KEY, \
             user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE, \
             username VARCHAR(32) NOT NULL UNIQUE, directory VARCHAR(1024) NOT NULL, \
             created_at DATETIME NOT NULL)",
            "INSERT INTO users (id, username) VALUES (1, 'alice'), (2, 'bob')",
        ] {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        pool
    }

    #[tokio::test]
    async fn an_account_is_its_owners_and_its_name_is_everyones() {
        let pool = scratch().await;
        let repo = SftpSubaccountRepo::new(&pool);
        let dev = repo
            .create(
                1,
                "alice_dev",
                "example.com/public_html",
                "2026-09-26 10:00:00",
            )
            .await
            .unwrap();
        assert_eq!(dev.directory, "example.com/public_html");
        repo.create(1, "alice_all", ".", "2026-09-26 10:01:00")
            .await
            .unwrap();
        assert_eq!(repo.list_for(1).await.unwrap().len(), 2);
        assert!(repo.list_for(2).await.unwrap().is_empty());
        // By id, but only the owner's.
        assert!(repo.by_id(1, dev.id).await.unwrap().is_some());
        assert!(repo.by_id(2, dev.id).await.unwrap().is_none());
        assert!(repo.username_taken("alice_dev").await.unwrap());
        assert!(
            repo.create(2, "alice_dev", ".", "2026-09-26 10:02:00")
                .await
                .is_err(),
            "a name twice"
        );
        assert!(!repo.delete(2, dev.id).await.unwrap(), "someone else's");
        assert!(repo.delete(1, dev.id).await.unwrap());
        assert!(!repo.username_taken("alice_dev").await.unwrap());
    }
}
