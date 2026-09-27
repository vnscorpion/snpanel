//! `api_tokens` — the Bearer tokens a billing system authenticates with.
//!
//! These are not panel logins. A token belongs to no user, carries its own
//! scopes and its own IP allowlist, and reaches a separate router under
//! `/provisioning/v1` that creates and destroys hosting accounts. A token
//! that leaks is a machine that can terminate customers, so nothing here
//! ever returns the secret: the table stores a hash, and the plaintext is
//! shown once, by the endpoint that made it, and never again.

use sqlx::sqlite::SqlitePool;

use super::DbError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    /// The SHA-256 of the token, never the token.
    pub token_hash: String,
    /// Comma-separated, as the Python stores them.
    pub scopes: String,
    /// Comma-separated; empty means "from anywhere".
    pub allowed_ips: String,
    pub is_active: bool,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: Option<String>,
}

const COLUMNS: &str =
    "id, name, token_hash, scopes, allowed_ips, is_active, last_used_at, revoked_at, created_at";

pub struct ApiTokenRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ApiTokenRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `list_tokens` — `order_by(ApiToken.id.desc())`.
    pub async fn all(&self) -> Result<Vec<ApiToken>, DbError> {
        let sql = format!("SELECT {COLUMNS} FROM api_tokens ORDER BY id DESC");
        Ok(sqlx::query_as::<_, ApiToken>(&sql)
            .fetch_all(self.pool)
            .await?)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<ApiToken>, DbError> {
        let sql = format!("SELECT {COLUMNS} FROM api_tokens WHERE id = ?");
        Ok(sqlx::query_as::<_, ApiToken>(&sql)
            .bind(id)
            .fetch_optional(self.pool)
            .await?)
    }

    /// Source: `authenticate_token`.
    ///
    /// **All three conditions, not just the hash.** A token that was
    /// switched off or revoked still has its row and still has its hash;
    /// matching on the hash alone would make revocation decorative.
    pub async fn by_hash_active(&self, token_hash: &str) -> Result<Option<ApiToken>, DbError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM api_tokens \
             WHERE token_hash = ? AND is_active = 1 AND revoked_at IS NULL"
        );
        Ok(sqlx::query_as::<_, ApiToken>(&sql)
            .bind(token_hash)
            .fetch_optional(self.pool)
            .await?)
    }

    /// Source: the `token.last_used_at = now; db.commit()` in
    /// `authenticate_token` — every successful authentication stamps the row.
    pub async fn touch(&self, id: i64, when: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(when)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `create_token`.
    pub async fn create(
        &self,
        name: &str,
        token_hash: &str,
        scopes: &str,
        allowed_ips: &str,
        created_at: &str,
    ) -> Result<ApiToken, DbError> {
        let sql = format!(
            "INSERT INTO api_tokens (name, token_hash, scopes, allowed_ips, is_active, created_at) \
             VALUES (?, ?, ?, ?, 1, ?) RETURNING {COLUMNS}"
        );
        Ok(sqlx::query_as::<_, ApiToken>(&sql)
            .bind(name)
            .bind(token_hash)
            .bind(scopes)
            .bind(allowed_ips)
            .bind(created_at)
            .fetch_one(self.pool)
            .await?)
    }

    /// Source: `revoke_token`.
    ///
    /// The row is **kept**, switched off and stamped. Deleting it would
    /// leave no record that a token with that name ever existed, which is
    /// the first thing anyone asks after an incident.
    pub async fn revoke(&self, id: i64, when: &str) -> Result<bool, DbError> {
        let result =
            sqlx::query("UPDATE api_tokens SET is_active = 0, revoked_at = ? WHERE id = ?")
                .bind(when)
                .bind(id)
                .execute(self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }
}
