//! Saved Cloudflare API tokens, one per zone.
//!
//! Source: `models.entities.CloudflareCredential`. The token is Fernet
//! ciphertext and "only ever leaves here to be handed to the privileged
//! helper on stdin"; nothing in this repo decrypts it, and the one caller so
//! far needs only the zone names.

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
}
