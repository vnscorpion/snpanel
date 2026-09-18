//! `user_packages` - the limits an administrator assigns to customers.
//!
//! One behaviour here is easy to miss and would be a silent data bug: when a
//! package's limits change, **every user holding that package has their own
//! `website_limit` and `storage_limit_mb` rewritten**. The columns on `users`
//! are copies, not references, because enforcement reads one row; a user
//! without a package still has to resolve to something. Skipping the cascade
//! would leave an administrator looking at a package that says 20 sites while
//! every customer on it is still capped at 5.

use sqlx::sqlite::SqlitePool;

use super::DbError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Package {
    pub id: i64,
    pub name: String,
    pub slug: Option<String>,
    pub website_limit: i64,
    pub storage_limit_mb: i64,
    pub database_limit: i64,
    pub alias_limit: i64,
    pub backup_retention_days: i64,
    pub terminal_enabled: bool,
    pub waf_enabled: bool,
    pub wordpress_enabled: bool,
    pub node_apps_limit: i64,
    pub node_app_memory_mb: i64,
    /// As SQLite stores it; the API formats it the way Pydantic would.
    pub created_at: Option<String>,
}

/// The fields a create or patch may set. `None` means "leave alone" on a
/// patch, and "use the schema default" on a create - the caller resolves that
/// difference before it gets here.
#[derive(Debug, Default, Clone)]
pub struct PackageFields {
    pub name: Option<String>,
    pub slug: Option<Option<String>>,
    pub website_limit: Option<i64>,
    pub storage_limit_mb: Option<i64>,
    pub database_limit: Option<i64>,
    pub alias_limit: Option<i64>,
    pub backup_retention_days: Option<i64>,
    pub terminal_enabled: Option<bool>,
    pub waf_enabled: Option<bool>,
    pub wordpress_enabled: Option<bool>,
    pub node_apps_limit: Option<i64>,
    pub node_app_memory_mb: Option<i64>,
}

const COLUMNS: &str = "id, name, slug, website_limit, storage_limit_mb, database_limit, \
                       alias_limit, backup_retention_days, terminal_enabled, waf_enabled, \
                       wordpress_enabled, node_apps_limit, node_app_memory_mb, created_at";

pub struct PackageRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> PackageRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `order_by(UserPackage.id.asc())`. The order is part of what the
    /// frontend renders, so it is not left to the database's discretion.
    pub async fn list(&self) -> Result<Vec<Package>, DbError> {
        Ok(sqlx::query_as::<_, Package>(&format!(
            "SELECT {COLUMNS} FROM user_packages ORDER BY id ASC"
        ))
        .fetch_all(self.pool)
        .await?)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<Package>, DbError> {
        Ok(sqlx::query_as::<_, Package>(&format!(
            "SELECT {COLUMNS} FROM user_packages WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Is this name taken by a *different* package?
    ///
    /// `exclude` is the package being renamed, so renaming one to the name it
    /// already has is not a conflict with itself.
    pub async fn name_taken(&self, name: &str, exclude: Option<i64>) -> Result<bool, DbError> {
        let found: Option<i64> = match exclude {
            Some(id) => {
                sqlx::query_scalar("SELECT id FROM user_packages WHERE name = ? AND id != ?")
                    .bind(name)
                    .bind(id)
                    .fetch_optional(self.pool)
                    .await?
            }
            None => {
                sqlx::query_scalar("SELECT id FROM user_packages WHERE name = ?")
                    .bind(name)
                    .fetch_optional(self.pool)
                    .await?
            }
        };
        Ok(found.is_some())
    }

    pub async fn create(&self, f: &PackageFields) -> Result<Package, DbError> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO user_packages \
             (name, slug, website_limit, storage_limit_mb, database_limit, alias_limit, \
              backup_retention_days, terminal_enabled, waf_enabled, wordpress_enabled, \
              node_apps_limit, node_app_memory_mb, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(f.name.as_deref().unwrap_or_default())
        .bind(f.slug.clone().unwrap_or(None))
        .bind(f.website_limit.unwrap_or(5))
        .bind(f.storage_limit_mb.unwrap_or(1024))
        .bind(f.database_limit.unwrap_or(5))
        .bind(f.alias_limit.unwrap_or(0))
        .bind(f.backup_retention_days.unwrap_or(7))
        .bind(f.terminal_enabled.unwrap_or(false))
        .bind(f.waf_enabled.unwrap_or(true))
        .bind(f.wordpress_enabled.unwrap_or(true))
        .bind(f.node_apps_limit.unwrap_or(0))
        .bind(f.node_app_memory_mb.unwrap_or(512))
        .bind(crate::sqlalchemy_now())
        .fetch_one(self.pool)
        .await?;

        self.by_id(id)
            .await?
            .ok_or_else(|| DbError::Open("the package vanished after being created".into()))
    }

    /// Apply a patch and cascade the two copied limits onto its users.
    ///
    /// Both statements run in one transaction: a crash between them would
    /// leave the package and its customers disagreeing about the limits, which
    /// is the kind of inconsistency nobody goes looking for.
    pub async fn update(&self, id: i64, f: &PackageFields) -> Result<Option<Package>, DbError> {
        let mut tx = self.pool.begin().await?;

        macro_rules! set {
            ($column:literal, $value:expr) => {
                if let Some(v) = $value {
                    sqlx::query(concat!(
                        "UPDATE user_packages SET ",
                        $column,
                        " = ? WHERE id = ?"
                    ))
                    .bind(v)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                }
            };
        }

        set!("name", f.name.clone());
        set!("slug", f.slug.clone());
        set!("website_limit", f.website_limit);
        set!("storage_limit_mb", f.storage_limit_mb);
        set!("database_limit", f.database_limit);
        set!("alias_limit", f.alias_limit);
        set!("backup_retention_days", f.backup_retention_days);
        set!("terminal_enabled", f.terminal_enabled);
        set!("waf_enabled", f.waf_enabled);
        set!("wordpress_enabled", f.wordpress_enabled);
        set!("node_apps_limit", f.node_apps_limit);
        set!("node_app_memory_mb", f.node_app_memory_mb);

        // The cascade runs unconditionally, exactly as the Python's loop does:
        // it copies the package's *current* values onto every member, whether
        // or not this particular patch touched them.
        sqlx::query(
            "UPDATE users SET \
                website_limit = (SELECT website_limit FROM user_packages WHERE id = ?), \
                storage_limit_mb = (SELECT storage_limit_mb FROM user_packages WHERE id = ?) \
             WHERE package_id = ?",
        )
        .bind(id)
        .bind(id)
        .bind(id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.by_id(id).await
    }

    /// How many users hold this package - a package in use cannot be deleted.
    pub async fn user_count(&self, id: i64) -> Result<i64, DbError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE package_id = ?")
                .bind(id)
                .fetch_one(self.pool)
                .await?,
        )
    }

    pub async fn delete(&self, id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM user_packages WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scratch() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE user_packages (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE,
                slug TEXT,
                website_limit INTEGER,
                storage_limit_mb INTEGER,
                database_limit INTEGER,
                alias_limit INTEGER,
                backup_retention_days INTEGER,
                terminal_enabled BOOLEAN,
                waf_enabled BOOLEAN,
                wordpress_enabled BOOLEAN,
                node_apps_limit INTEGER,
                node_app_memory_mb INTEGER,
                created_at DATETIME
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                package_id INTEGER,
                website_limit INTEGER,
                storage_limit_mb INTEGER
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    fn named(name: &str) -> PackageFields {
        PackageFields {
            name: Some(name.to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_created_package_takes_the_schema_defaults() {
        let pool = scratch().await;
        let repo = PackageRepo::new(&pool);
        let p = repo.create(&named("Basic")).await.unwrap();
        assert_eq!(p.name, "Basic");
        assert_eq!(p.website_limit, 5);
        assert_eq!(p.storage_limit_mb, 1024);
        assert_eq!(p.database_limit, 5);
        assert_eq!(p.alias_limit, 0);
        assert_eq!(p.backup_retention_days, 7);
        assert!(!p.terminal_enabled, "a shell is not handed out implicitly");
        assert!(p.waf_enabled);
        assert!(p.wordpress_enabled);
        assert_eq!(p.node_apps_limit, 0);
        assert_eq!(p.node_app_memory_mb, 512);
        assert!(p.created_at.is_some());
    }

    #[tokio::test]
    async fn packages_are_listed_by_id_ascending() {
        let pool = scratch().await;
        let repo = PackageRepo::new(&pool);
        for name in ["Zulu", "Alpha", "Mike"] {
            repo.create(&named(name)).await.unwrap();
        }
        let names: Vec<String> = repo
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.name)
            .collect();
        // Creation order, not alphabetical - the frontend renders this order.
        assert_eq!(names, vec!["Zulu", "Alpha", "Mike"]);
    }

    #[tokio::test]
    async fn a_name_is_taken_by_another_package_but_not_by_itself() {
        let pool = scratch().await;
        let repo = PackageRepo::new(&pool);
        let a = repo.create(&named("Basic")).await.unwrap();
        repo.create(&named("Pro")).await.unwrap();

        assert!(repo.name_taken("Pro", None).await.unwrap());
        assert!(repo.name_taken("Pro", Some(a.id)).await.unwrap());
        // Renaming Basic to Basic is not a conflict with itself.
        assert!(!repo.name_taken("Basic", Some(a.id)).await.unwrap());
        assert!(!repo.name_taken("Nothing", None).await.unwrap());
    }

    #[tokio::test]
    async fn changing_a_package_rewrites_the_limits_of_its_members() {
        // The columns on `users` are copies. Leaving them behind would show an
        // administrator 20 sites on the package while every customer on it is
        // still capped at 5.
        let pool = scratch().await;
        let repo = PackageRepo::new(&pool);
        let p = repo.create(&named("Basic")).await.unwrap();
        sqlx::query("INSERT INTO users (id, username, package_id, website_limit, storage_limit_mb) VALUES (1, 'a', ?, 5, 1024), (2, 'b', NULL, 5, 1024)")
            .bind(p.id)
            .execute(&pool)
            .await
            .unwrap();

        repo.update(
            p.id,
            &PackageFields {
                website_limit: Some(20),
                storage_limit_mb: Some(4096),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let member: (i64, i64) =
            sqlx::query_as("SELECT website_limit, storage_limit_mb FROM users WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(member, (20, 4096));

        // A user on no package is untouched.
        let other: (i64, i64) =
            sqlx::query_as("SELECT website_limit, storage_limit_mb FROM users WHERE id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(other, (5, 1024));
    }

    #[tokio::test]
    async fn a_patch_leaves_the_fields_it_does_not_mention() {
        let pool = scratch().await;
        let repo = PackageRepo::new(&pool);
        let p = repo.create(&named("Basic")).await.unwrap();
        let updated = repo
            .update(
                p.id,
                &PackageFields {
                    alias_limit: Some(9),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.alias_limit, 9);
        assert_eq!(updated.name, "Basic", "the name was not in the patch");
        assert_eq!(updated.website_limit, 5);
    }

    #[tokio::test]
    async fn a_package_in_use_is_countable_before_it_is_deleted() {
        let pool = scratch().await;
        let repo = PackageRepo::new(&pool);
        let p = repo.create(&named("Basic")).await.unwrap();
        assert_eq!(repo.user_count(p.id).await.unwrap(), 0);

        sqlx::query("INSERT INTO users (id, username, package_id, website_limit, storage_limit_mb) VALUES (1, 'a', ?, 5, 1024)")
            .bind(p.id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(repo.user_count(p.id).await.unwrap(), 1);

        repo.delete(p.id).await.unwrap();
        assert!(repo.by_id(p.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn patching_a_package_that_is_gone_is_none_not_an_error() {
        let pool = scratch().await;
        let repo = PackageRepo::new(&pool);
        assert!(repo
            .update(999, &PackageFields::default())
            .await
            .unwrap()
            .is_none());
    }
}
