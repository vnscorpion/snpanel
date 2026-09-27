//! Saved Cloudflare API tokens, one per zone.
//!
//! Source: `models.entities.CloudflareCredential`. The token is Fernet
//! ciphertext and "only ever leaves here to be handed to the privileged
//! helper on stdin"; this module moves the ciphertext and never looks
//! inside it - decryption belongs to the one caller that has to hand the
//! plaintext on, so the key is not needed here and a stray `tracing` line
//! in this file could not leak a token even if somebody added one.

use crate::DbError;
use sqlx::SqlitePool;

pub struct CloudflareRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> CloudflareRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Every zone a credential is saved for.
    ///
    /// Source: `db.query(CloudflareCredential).all()`, projected to the one
    /// column the caller uses - reading the ciphertext it does not need would
    /// be the kind of habit that turns into a log line one day.
    pub async fn zones(&self) -> Result<Vec<String>, DbError> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT zone FROM cloudflare_credentials")
                .fetch_all(self.pool)
                .await?,
        )
    }

    /// The stored ciphertext for one zone, if there is one.
    ///
    /// Source: `cloudflare.get_token`, minus the decryption. The zone is
    /// lowercased on the way in exactly as the Python does, so a caller
    /// holding the name Cloudflare returned still finds the row it saved.
    pub async fn ciphertext(&self, zone: &str) -> Result<Option<String>, DbError> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT api_token FROM cloudflare_credentials WHERE zone = ?",
        )
        .bind(zone.to_lowercase())
        .fetch_optional(self.pool)
        .await?)
    }

    /// Save, or replace, the token for one zone.
    ///
    /// Source: `cloudflare.save_credential`. The Python looks the row up
    /// and then either assigns to it or adds a new one; `zone` is unique,
    /// so an upsert is the same two outcomes in one statement and cannot
    /// lose a race to a second request for the same zone.
    ///
    /// `updated_at` moves on the replace branch, which is what SQLAlchemy's
    /// `onupdate` does. A new row gets both timestamps from the same clock
    /// reading rather than from the column default, because the Python's
    /// default and `onupdate` are both `datetime.utcnow`.
    pub async fn save(&self, zone: &str, ciphertext: &str, now: &str) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO cloudflare_credentials (zone, api_token, created_at, updated_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(zone) DO UPDATE SET api_token = excluded.api_token, \
             updated_at = excluded.updated_at",
        )
        .bind(zone.to_lowercase())
        .bind(ciphertext)
        .bind(now)
        .bind(now)
        .execute(self.pool)
        .await?;
        Ok(())
    }
}
