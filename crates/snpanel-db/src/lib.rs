//! The panel's database, shared with Python for the duration of the migration.
//!
//! Plan §9.2 is what makes the strangler work: both implementations open the
//! *same* SQLite file, so there is no data to synchronise and a request can be
//! served by either side. Three consequences shape this crate.
//!
//! **WAL, and a busy timeout.** Two processes writing one SQLite file need
//! write-ahead logging or the second writer gets `SQLITE_BUSY` immediately.
//! The plan calls for turning WAL on in Phase 0 as a backwards-compatible
//! change; [`Database::connect`] asserts it rather than assuming somebody did.
//!
//! **C11: the schema is not touched.** No migrations run from here. Alembic
//! owns the schema while Python is alive, and a Rust migration that "helpfully"
//! adjusted a column would be the one change neither side could recover from.
//! This crate reads and writes rows in tables that already exist.
//!
//! **The column names are the Python ones.** `hashed_password`, not
//! `password_hash`; `totp_secret` holds a Fernet ciphertext with the
//! `fernet:` prefix, not a plain secret.

use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

pub mod backups;
pub mod cloudflare;
mod databases;
pub mod packages;
pub mod site_apps;
mod users;
pub mod websites;

pub use backups::{BackupSchedule, BackupScheduleRepo, ScheduleUsers, SftpTarget, SftpTargetRepo};
pub use cloudflare::CloudflareRepo;
pub use databases::{DatabaseAccount, DatabaseRepo};
pub use packages::{Package, PackageFields, PackageRepo};
pub use site_apps::{SiteAppRepo, SiteAppRow, SiteAppTarget};
pub use users::{AuditEntry, AuditRepo, NewUser, RevokedTokenRepo, User, UserFields, UserRepo};
pub use websites::{NewWebsite, Website, WebsiteAlias, WebsiteRepo};

/// A timestamp in the form SQLAlchemy stores `DateTime` columns as on SQLite.
///
/// `YYYY-MM-DD HH:MM:SS.ffffff`, naive UTC - the format SQLAlchemy's SQLite
/// DATETIME type both writes and parses. A different shape (an ISO `T`
/// separator, or a timezone offset) is written without complaint and then
/// fails to parse when *Python* reads the row back, which surfaces much later
/// as a 500 on a page that only reads. `datetime.utcnow()` is naive, so no
/// offset is appended here either.
pub fn sqlalchemy_now() -> String {
    format_timestamp(chrono::Utc::now().naive_utc())
}

pub fn format_timestamp(t: chrono::NaiveDateTime) -> String {
    t.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("cannot open the database: {0}")]
    Open(String),
    #[error(transparent)]
    Query(#[from] sqlx::Error),
    #[error("the database is not in WAL mode; two writers will collide")]
    NotWal,
}

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open the panel's database.
    ///
    /// `url` is the `DATABASE_URL` from `.env`, in SQLAlchemy's form
    /// (`sqlite:////opt/snpanel/backend/snpanel.db`). The extra slashes are
    /// SQLAlchemy's, not a typo, and have to be stripped rather than passed on.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let path =
            sqlite_path(url).ok_or_else(|| DbError::Open(format!("unsupported URL: {url}")))?;
        if !Path::new(&path).exists() {
            return Err(DbError::Open(format!("{path} does not exist")));
        }

        let options = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .map_err(|e| DbError::Open(e.to_string()))?
            // Never create it: an empty database appearing where the panel's
            // should be looks like total data loss to whoever finds it.
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Wal)
            // §9.2. Without this the second writer fails instantly instead of
            // waiting for a transaction that is about to finish anyway.
            .busy_timeout(std::time::Duration::from_secs(10))
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            // Modest: SQLite serialises writes regardless, and while Python is
            // also connected there is no reason to hold more handles than the
            // work needs.
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|e| DbError::Open(e.to_string()))?;

        let db = Self { pool };
        db.assert_wal().await?;
        Ok(db)
    }

    /// Confirm WAL is actually on, rather than trusting that it was requested.
    ///
    /// `journal_mode=WAL` in the connect options is a request; on a database
    /// another process already has open in a different mode it can be refused.
    /// Finding that out here is far better than finding it out as intermittent
    /// `SQLITE_BUSY` under load.
    async fn assert_wal(&self) -> Result<(), DbError> {
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&self.pool)
            .await?;
        if mode.eq_ignore_ascii_case("wal") {
            Ok(())
        } else {
            tracing::error!(mode, "database is not in WAL mode");
            Err(DbError::NotWal)
        }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn users(&self) -> UserRepo<'_> {
        UserRepo::new(&self.pool)
    }

    pub fn revoked_tokens(&self) -> RevokedTokenRepo<'_> {
        RevokedTokenRepo::new(&self.pool)
    }

    pub fn audits(&self) -> AuditRepo<'_> {
        AuditRepo::new(&self.pool)
    }

    pub fn packages(&self) -> PackageRepo<'_> {
        PackageRepo::new(&self.pool)
    }

    pub fn databases(&self) -> DatabaseRepo<'_> {
        DatabaseRepo::new(&self.pool)
    }

    pub fn backup_schedules(&self) -> BackupScheduleRepo<'_> {
        BackupScheduleRepo::new(&self.pool)
    }

    pub fn sftp_targets(&self) -> SftpTargetRepo<'_> {
        SftpTargetRepo::new(&self.pool)
    }

    pub fn websites(&self) -> WebsiteRepo<'_> {
        WebsiteRepo::new(&self.pool)
    }

    pub fn site_apps(&self) -> SiteAppRepo<'_> {
        SiteAppRepo::new(&self.pool)
    }

    pub fn cloudflare(&self) -> CloudflareRepo<'_> {
        CloudflareRepo::new(&self.pool)
    }

    /// Does the Python schema look present?
    ///
    /// C12: the first Rust migration must be a no-op on an existing database,
    /// and `alembic_version` is how the plan says to recognise one. Nothing
    /// here migrates; this exists so a caller can refuse to run against a
    /// database that is not the panel's.
    pub async fn looks_like_panel_schema(&self) -> Result<bool, DbError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name IN ('users', 'websites', 'alembic_version')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count >= 2)
    }
}

/// Turn a SQLAlchemy SQLite URL into a filesystem path.
///
/// SQLAlchemy writes an absolute path as `sqlite:////abs/path` - four slashes,
/// because the third belongs to the empty host and the fourth starts the path.
/// A relative one is `sqlite:///rel/path`.
pub fn sqlite_path(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("sqlite+aiosqlite://")
        .or_else(|| url.strip_prefix("sqlite://"))?;
    // What is left is `//abs/path`, `/rel/path`, or a bare path.
    let path = rest.strip_prefix('/').unwrap_or(rest);
    if path.is_empty() {
        return None;
    }
    Some(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlalchemy_urls_resolve_to_paths() {
        // The four-slash form is what the installer writes into .env.
        assert_eq!(
            sqlite_path("sqlite:////opt/snpanel/backend/snpanel.db").as_deref(),
            Some("/opt/snpanel/backend/snpanel.db")
        );
        // Three slashes is a relative path.
        assert_eq!(
            sqlite_path("sqlite:///./snpanel.db").as_deref(),
            Some("./snpanel.db")
        );
        assert_eq!(
            sqlite_path("sqlite+aiosqlite:////var/lib/snpanel/db.sqlite").as_deref(),
            Some("/var/lib/snpanel/db.sqlite")
        );
    }

    #[test]
    fn a_non_sqlite_url_is_refused_rather_than_guessed_at() {
        for bad in [
            "postgresql://user@host/db",
            "mysql://root@localhost/snpanel",
            "",
            "sqlite://",
        ] {
            assert!(sqlite_path(bad).is_none(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn refuses_a_database_that_does_not_exist() {
        // Creating one would look like catastrophic data loss to whoever finds
        // an empty database where the panel's should be.
        let result = Database::connect("sqlite:////nonexistent/path/snpanel.db").await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a database that does not exist must not be created"),
        };
        assert!(matches!(err, DbError::Open(_)), "{err}");
    }
}
