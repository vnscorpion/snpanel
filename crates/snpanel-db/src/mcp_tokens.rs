//! Tokens for the MCP addon: what an AI assistant signs in to `/api/mcp`
//! with, acting as the account that made the token.
//!
//! Not in the Python. Only a token's SHA-256 is stored, with its first
//! twelve characters to tell tokens apart in a list: the token itself is
//! shown once, when it is made, and nowhere after.

use sqlx::sqlite::SqlitePool;

use super::DbError;

/// One row of `mcp_tokens`, without its hash.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct McpToken {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub prefix: String,
    /// "Allow actions": the tools that change something.
    pub can_write: bool,
    /// `YYYY-MM-DD HH:MM:SS.ffffff`, UTC, as every timestamp here.
    pub expires_at: String,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

/// A token with its owner's name, for the list of every token on the panel.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct McpTokenWithOwner {
    #[sqlx(flatten)]
    pub token: McpToken,
    pub username: String,
}

/// What making a token stores.
#[derive(Debug, Clone)]
pub struct NewMcpToken<'a> {
    pub user_id: i64,
    pub name: &'a str,
    pub token_hash: &'a str,
    pub prefix: &'a str,
    pub can_write: bool,
    pub expires_at: &'a str,
    pub created_at: &'a str,
}

const COLUMNS: &str = "id, user_id, name, prefix, can_write, expires_at, last_used_at, created_at";

pub struct McpTokenRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> McpTokenRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, token: &NewMcpToken<'_>) -> Result<i64, DbError> {
        Ok(sqlx::query(
            "INSERT INTO mcp_tokens (user_id, name, token_hash, prefix, can_write, expires_at, \
             created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(token.user_id)
        .bind(token.name)
        .bind(token.token_hash)
        .bind(token.prefix)
        .bind(token.can_write)
        .bind(token.expires_at)
        .bind(token.created_at)
        .execute(self.pool)
        .await?
        .last_insert_rowid())
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<McpToken>, DbError> {
        Ok(
            sqlx::query_as::<_, McpToken>(&format!(
                "SELECT {COLUMNS} FROM mcp_tokens WHERE id = ?"
            ))
            .bind(id)
            .fetch_optional(self.pool)
            .await?,
        )
    }

    /// The token a request presented, by its hash.
    pub async fn by_hash(&self, token_hash: &str) -> Result<Option<McpToken>, DbError> {
        Ok(sqlx::query_as::<_, McpToken>(&format!(
            "SELECT {COLUMNS} FROM mcp_tokens WHERE token_hash = ?"
        ))
        .bind(token_hash)
        .fetch_optional(self.pool)
        .await?)
    }

    /// An account's own tokens, newest first.
    pub async fn for_user(&self, user_id: i64) -> Result<Vec<McpToken>, DbError> {
        Ok(sqlx::query_as::<_, McpToken>(&format!(
            "SELECT {COLUMNS} FROM mcp_tokens WHERE user_id = ? ORDER BY id DESC"
        ))
        .bind(user_id)
        .fetch_all(self.pool)
        .await?)
    }

    /// Every token on the panel, with whose it is, newest first.
    pub async fn all(&self) -> Result<Vec<McpTokenWithOwner>, DbError> {
        Ok(sqlx::query_as::<_, McpTokenWithOwner>(
            "SELECT t.id, t.user_id, t.name, t.prefix, t.can_write, t.expires_at, \
             t.last_used_at, t.created_at, COALESCE(u.username, '') AS username \
             FROM mcp_tokens t LEFT JOIN users u ON u.id = t.user_id ORDER BY t.id DESC",
        )
        .fetch_all(self.pool)
        .await?)
    }

    pub async fn count_for_user(&self, user_id: i64) -> Result<i64, DbError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM mcp_tokens WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(self.pool)
                .await?,
        )
    }

    /// Noted at most once a minute: a busy assistant would otherwise write
    /// the row on every call.
    pub async fn touch(&self, id: i64, now: &str, a_minute_ago: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE mcp_tokens SET last_used_at = ? WHERE id = ? \
             AND (last_used_at IS NULL OR last_used_at < ?)",
        )
        .bind(now)
        .bind(id)
        .bind(a_minute_ago)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM mcp_tokens WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// With the account. The foreign key cascades too; this does not rest on
    /// `PRAGMA foreign_keys` having been on.
    pub async fn delete_for_user(&self, user_id: i64) -> Result<u64, DbError> {
        let done = sqlx::query("DELETE FROM mcp_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    /// Every token on the panel: "Revoke all" on the Addons page.
    pub async fn delete_all(&self) -> Result<u64, DbError> {
        let done = sqlx::query("DELETE FROM mcp_tokens")
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected())
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
        sqlx::query(
            "INSERT INTO users (id, username, email, hashed_password) \
             VALUES (1, 'admin', 'admin@example.com', 'x'), (2, 'alice', 'alice@example.com', 'x')",
        )
        .execute(db.pool())
        .await
        .unwrap();
        db
    }

    fn token<'a>(user_id: i64, hash: &'a str) -> NewMcpToken<'a> {
        NewMcpToken {
            user_id,
            name: "laptop",
            token_hash: hash,
            prefix: "snmcp_abcdef",
            can_write: false,
            expires_at: "2026-12-31 00:00:00.000000",
            created_at: "2026-09-25 10:00:00.000000",
        }
    }

    #[tokio::test]
    async fn a_token_is_found_by_its_hash_and_listed_without_it() {
        let db = db().await;
        let repo = db.mcp_tokens();
        let id = repo.create(&token(2, "hash-a")).await.unwrap();
        let found = repo.by_hash("hash-a").await.unwrap().unwrap();
        assert_eq!((found.id, found.user_id, found.can_write), (id, 2, false));
        assert!(repo.by_hash("hash-b").await.unwrap().is_none());
        assert!(!format!("{found:?}").contains("hash-a"));
        assert_eq!(repo.for_user(2).await.unwrap().len(), 1);
        assert!(repo.for_user(1).await.unwrap().is_empty());
        let all = repo.all().await.unwrap();
        assert_eq!((all[0].username.as_str(), all[0].token.id), ("alice", id));
        assert_eq!(repo.count_for_user(2).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn two_tokens_cannot_share_a_hash() {
        let db = db().await;
        db.mcp_tokens().create(&token(2, "same")).await.unwrap();
        assert!(db.mcp_tokens().create(&token(1, "same")).await.is_err());
    }

    /// Written the first time, then not again within the minute.
    #[tokio::test]
    async fn use_is_noted_at_most_once_a_minute() {
        let db = db().await;
        let repo = db.mcp_tokens();
        let id = repo.create(&token(2, "h")).await.unwrap();
        repo.touch(
            id,
            "2026-09-25 10:00:00.000000",
            "2026-09-25 09:59:00.000000",
        )
        .await
        .unwrap();
        repo.touch(
            id,
            "2026-09-25 10:00:30.000000",
            "2026-09-25 09:59:30.000000",
        )
        .await
        .unwrap();
        let seen = repo.by_id(id).await.unwrap().unwrap().last_used_at;
        assert_eq!(seen.as_deref(), Some("2026-09-25 10:00:00.000000"));
        repo.touch(
            id,
            "2026-09-25 10:01:01.000000",
            "2026-09-25 10:00:01.000000",
        )
        .await
        .unwrap();
        let seen = repo.by_id(id).await.unwrap().unwrap().last_used_at;
        assert_eq!(seen.as_deref(), Some("2026-09-25 10:01:01.000000"));
    }

    #[tokio::test]
    async fn tokens_go_one_at_a_time_by_account_or_all_together() {
        let db = db().await;
        let repo = db.mcp_tokens();
        let a = repo.create(&token(2, "a")).await.unwrap();
        repo.create(&token(2, "b")).await.unwrap();
        repo.create(&token(1, "c")).await.unwrap();
        assert!(repo.delete(a).await.unwrap());
        assert!(!repo.delete(a).await.unwrap());
        assert_eq!(repo.delete_for_user(2).await.unwrap(), 1);
        assert_eq!(repo.delete_all().await.unwrap(), 1);
        assert!(repo.all().await.unwrap().is_empty());
    }

    /// An account deleted takes its tokens with it.
    #[tokio::test]
    async fn deleting_the_account_deletes_its_tokens() {
        let db = db().await;
        db.mcp_tokens().create(&token(2, "a")).await.unwrap();
        sqlx::query("DELETE FROM users WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert!(db.mcp_tokens().by_hash("a").await.unwrap().is_none());
    }
}
