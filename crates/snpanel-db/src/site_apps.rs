//! `site_apps` - the applications the panel runs for a customer.
//!
//! Source: `models.entities.SiteApp`. Only the columns the ported callers read
//! are here; the table is wider, and the rest arrives when the Application
//! router is ported.

use crate::DbError;
use sqlx::SqlitePool;

/// One row of `site_apps`, with its owner's panel account name folded in.
///
/// The name comes from the join because `site_apps.owner_linux_user` is what
/// every helper call needs and the Python derives it the same way - through
/// `app.owner.username`, not from a column on the app.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteAppRow {
    pub id: i64,
    pub name: String,
    pub owner_id: i64,
    /// `NULL` when the owner row is gone. The Python then raises
    /// "This application has no owner, so it cannot be run".
    pub owner_username: Option<String>,
}

pub struct SiteAppRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> SiteAppRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `db.query(SiteApp).all()`.
    ///
    /// The Python does not order, and SQLite hands back rowid order for a
    /// plain scan. `ORDER BY id` says so rather than relying on it: the only
    /// caller reports the apps it stopped, and a list that reshuffles between
    /// two identical requests is a difference a customer can see.
    pub async fn all(&self) -> Result<Vec<SiteAppRow>, DbError> {
        Ok(sqlx::query_as::<_, SiteAppRow>(
            "SELECT site_apps.id AS id, site_apps.name AS name, \
                    site_apps.owner_id AS owner_id, users.username AS owner_username \
             FROM site_apps LEFT JOIN users ON users.id = site_apps.owner_id \
             ORDER BY site_apps.id",
        )
        .fetch_all(self.pool)
        .await?)
    }
}
