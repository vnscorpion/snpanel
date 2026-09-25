//! S3 backup destinations, and the options a backup schedule has beyond the
//! Python's columns.
//!
//! Not in the Python. `s3_backup_targets` mirrors `sftp_backup_targets`: the
//! row type carries no secret, and the secret key - Fernet ciphertext - is
//! read on its own, by the code that uploads. `backup_schedule_options` holds
//! what a schedule gained here - an S3 destination and how its archives are
//! named - in a table of its own, because a Rust migration only adds (C12).
//! A schedule without a row is the Python's schedule exactly.

use std::collections::HashMap;

use sqlx::sqlite::SqlitePool;

use super::DbError;

/// One row of `s3_backup_targets`, **without** its secret key.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct S3Target {
    pub id: i64,
    pub name: String,
    /// `https://s3.amazonaws.com`, `https://<account>.r2.cloudflarestorage.com`, ...
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// A folder inside the bucket; empty for its root.
    pub prefix: String,
    pub access_key: String,
    /// `endpoint/bucket/key` rather than `bucket.endpoint/key`: what MinIO
    /// and most self-hosted stores need.
    pub path_style: bool,
    pub is_active: bool,
}

/// A target's settings: what creating one stores beside its secret, and what
/// editing one replaces.
#[derive(Debug, Clone)]
pub struct S3TargetFields<'a> {
    pub name: &'a str,
    pub endpoint: &'a str,
    pub region: &'a str,
    pub bucket: &'a str,
    pub prefix: &'a str,
    pub access_key: &'a str,
    pub path_style: bool,
}

const S3_COLUMNS: &str =
    "id, name, endpoint, region, bucket, prefix, access_key, path_style, is_active";

pub struct S3TargetRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> S3TargetRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<S3Target>, DbError> {
        Ok(sqlx::query_as::<_, S3Target>(&format!(
            "SELECT {S3_COLUMNS} FROM s3_backup_targets ORDER BY id"
        ))
        .fetch_all(self.pool)
        .await?)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<S3Target>, DbError> {
        Ok(sqlx::query_as::<_, S3Target>(&format!(
            "SELECT {S3_COLUMNS} FROM s3_backup_targets WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// The secret key's ciphertext, for the upload and nothing else.
    pub async fn secret(&self, id: i64) -> Result<Option<String>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT secret_key FROM s3_backup_targets WHERE id = ?")
                .bind(id)
                .fetch_optional(self.pool)
                .await?,
        )
    }

    /// `secret_key` is Fernet ciphertext.
    pub async fn create(
        &self,
        fields: &S3TargetFields<'_>,
        secret_key: &str,
        created_at: &str,
    ) -> Result<i64, DbError> {
        Ok(sqlx::query(
            "INSERT INTO s3_backup_targets (name, endpoint, region, bucket, prefix, access_key, \
             secret_key, path_style, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
        )
        .bind(fields.name)
        .bind(fields.endpoint)
        .bind(fields.region)
        .bind(fields.bucket)
        .bind(fields.prefix)
        .bind(fields.access_key)
        .bind(secret_key)
        .bind(fields.path_style)
        .bind(created_at)
        .execute(self.pool)
        .await?
        .last_insert_rowid())
    }

    /// New settings, and a new secret when one is given - a key rotated is
    /// the usual reason to edit a target, and an edit that is not about the
    /// key should not need it typed again.
    pub async fn update(
        &self,
        id: i64,
        fields: &S3TargetFields<'_>,
        secret_key: Option<&str>,
    ) -> Result<bool, DbError> {
        let done = sqlx::query(
            "UPDATE s3_backup_targets SET name = ?, endpoint = ?, region = ?, bucket = ?, \
             prefix = ?, access_key = ?, path_style = ?, secret_key = COALESCE(?, secret_key) \
             WHERE id = ?",
        )
        .bind(fields.name)
        .bind(fields.endpoint)
        .bind(fields.region)
        .bind(fields.bucket)
        .bind(fields.prefix)
        .bind(fields.access_key)
        .bind(fields.path_style)
        .bind(secret_key)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Whether another target already has this name.
    pub async fn name_taken(&self, name: &str, except: Option<i64>) -> Result<bool, DbError> {
        let found: Option<i64> =
            sqlx::query_scalar("SELECT id FROM s3_backup_targets WHERE name = ? AND id != ?")
                .bind(name)
                .bind(except.unwrap_or(0))
                .fetch_optional(self.pool)
                .await?;
        Ok(found.is_some())
    }

    /// The schedules that upload to it.
    pub async fn schedules_using(&self, id: i64) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT schedule_id FROM backup_schedule_options WHERE s3_target_id = ? \
             ORDER BY schedule_id",
        )
        .bind(id)
        .fetch_all(self.pool)
        .await?)
    }

    /// Schedules that named it fall back to keeping their archives here:
    /// `ON DELETE SET NULL`.
    pub async fn delete(&self, id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM s3_backup_targets WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

/// How a schedule's archives are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameStyle {
    /// `user-<name>-<date>-<time>.tar.gz`, every run kept: the Python's, and
    /// the default.
    Timestamp,
    /// `<name>.tar.gz`: each run replaces the last.
    None,
    /// `<name>-monday.tar.gz`: a week of them, each replaced a week later.
    Weekday,
    /// `<name>-2026-09-25.tar.gz`: one a day.
    Date,
}

impl NameStyle {
    pub const ALL: [Self; 4] = [Self::Timestamp, Self::None, Self::Weekday, Self::Date];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timestamp => "timestamp",
            Self::None => "none",
            Self::Weekday => "weekday",
            Self::Date => "date",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|style| style.as_str() == raw)
    }
}

/// What a schedule has beyond the Python's columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleOptions {
    /// Where its archives go when that is S3; an SFTP destination stays in
    /// the schedule's own `target_id`.
    pub s3_target_id: Option<i64>,
    pub name_style: NameStyle,
}

impl ScheduleOptions {
    /// A schedule with no row: the Python's.
    pub const DEFAULT: Self = Self {
        s3_target_id: None,
        name_style: NameStyle::Timestamp,
    };
}

pub struct ScheduleOptionsRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ScheduleOptionsRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, schedule_id: i64) -> Result<ScheduleOptions, DbError> {
        let row: Option<(Option<i64>, String)> = sqlx::query_as(
            "SELECT s3_target_id, name_style FROM backup_schedule_options WHERE schedule_id = ?",
        )
        .bind(schedule_id)
        .fetch_optional(self.pool)
        .await?;
        Ok(row
            .map(|(s3_target_id, style)| ScheduleOptions {
                s3_target_id,
                // A value this build does not know is the default, not an
                // error: the schedule still runs, as it did.
                name_style: NameStyle::parse(&style).unwrap_or(NameStyle::Timestamp),
            })
            .unwrap_or(ScheduleOptions::DEFAULT))
    }

    /// Every schedule's that has a row.
    pub async fn all(&self) -> Result<HashMap<i64, ScheduleOptions>, DbError> {
        let rows: Vec<(i64, Option<i64>, String)> = sqlx::query_as(
            "SELECT schedule_id, s3_target_id, name_style FROM backup_schedule_options",
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, s3_target_id, style)| {
                (
                    id,
                    ScheduleOptions {
                        s3_target_id,
                        name_style: NameStyle::parse(&style).unwrap_or(NameStyle::Timestamp),
                    },
                )
            })
            .collect())
    }

    /// Written for every schedule created, defaults included: a schedule id
    /// SQLite hands out again must not inherit a deleted one's options.
    pub async fn set(&self, schedule_id: i64, options: ScheduleOptions) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO backup_schedule_options (schedule_id, s3_target_id, name_style) \
             VALUES (?, ?, ?) ON CONFLICT (schedule_id) DO UPDATE SET \
             s3_target_id = excluded.s3_target_id, name_style = excluded.name_style",
        )
        .bind(schedule_id)
        .bind(options.s3_target_id)
        .bind(options.name_style.as_str())
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// With the schedule. The foreign key cascades too; this does not rest
    /// on `PRAGMA foreign_keys` having been on.
    pub async fn delete(&self, schedule_id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM backup_schedule_options WHERE schedule_id = ?")
            .bind(schedule_id)
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
        sqlx::query(
            "INSERT INTO backup_schedules (id, user_ids, all_users, schedule, retention, is_active, \
             last_status, last_message) VALUES (1, '[]', 1, '0 2 * * *', 7, 1, '', '')",
        )
        .execute(db.pool())
        .await
        .unwrap();
        db
    }

    fn target<'a>(name: &'a str) -> S3TargetFields<'a> {
        S3TargetFields {
            name,
            endpoint: "https://s3.example.com",
            region: "us-east-1",
            bucket: "backups",
            prefix: "panel",
            access_key: "AKIAEXAMPLE",
            path_style: true,
        }
    }

    async fn create(db: &super::super::Database, name: &str) -> i64 {
        db.s3_targets()
            .create(&target(name), "fernet:secret", "2026-09-25 10:00:00.000000")
            .await
            .unwrap()
    }

    /// The row carries no secret; the secret is asked for by name.
    #[tokio::test]
    async fn a_target_is_kept_with_its_secret_apart() {
        let db = db().await;
        let repo = db.s3_targets();
        let id = create(&db, "offsite").await;
        let row = repo.by_id(id).await.unwrap().unwrap();
        assert_eq!(
            (row.name.as_str(), row.bucket.as_str(), row.path_style),
            ("offsite", "backups", true)
        );
        assert!(row.is_active);
        assert!(!format!("{row:?}").contains("fernet"));
        assert_eq!(
            repo.secret(id).await.unwrap().as_deref(),
            Some("fernet:secret")
        );
        assert_eq!(repo.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_schedule_without_options_is_the_pythons() {
        let db = db().await;
        assert_eq!(
            db.schedule_options().get(1).await.unwrap(),
            ScheduleOptions::DEFAULT
        );
    }

    #[tokio::test]
    async fn options_are_kept_and_replaced() {
        let db = db().await;
        let id = create(&db, "offsite").await;
        let options = ScheduleOptions {
            s3_target_id: Some(id),
            name_style: NameStyle::Weekday,
        };
        db.schedule_options().set(1, options).await.unwrap();
        assert_eq!(db.schedule_options().get(1).await.unwrap(), options);
        let local = ScheduleOptions {
            s3_target_id: None,
            name_style: NameStyle::Date,
        };
        db.schedule_options().set(1, local).await.unwrap();
        assert_eq!(db.schedule_options().get(1).await.unwrap(), local);
    }

    /// A target deleted under a schedule leaves the schedule keeping its
    /// archives here - and its naming - rather than failing every night.
    #[tokio::test]
    async fn deleting_a_target_takes_it_off_its_schedules() {
        let db = db().await;
        let id = create(&db, "offsite").await;
        db.schedule_options()
            .set(
                1,
                ScheduleOptions {
                    s3_target_id: Some(id),
                    name_style: NameStyle::None,
                },
            )
            .await
            .unwrap();
        assert!(db.s3_targets().delete(id).await.unwrap());
        assert_eq!(
            db.schedule_options().get(1).await.unwrap(),
            ScheduleOptions {
                s3_target_id: None,
                name_style: NameStyle::None
            }
        );
    }

    /// Deleting the schedule takes its options with it.
    #[tokio::test]
    async fn deleting_a_schedule_deletes_its_options() {
        let db = db().await;
        db.schedule_options()
            .set(
                1,
                ScheduleOptions {
                    s3_target_id: None,
                    name_style: NameStyle::Date,
                },
            )
            .await
            .unwrap();
        sqlx::query("DELETE FROM backup_schedules WHERE id = 1")
            .execute(db.pool())
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_schedule_options")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    /// An edit without a secret keeps the one stored; one with a secret
    /// replaces it.
    #[tokio::test]
    async fn an_edit_keeps_the_secret_unless_given_one() {
        let db = db().await;
        let repo = db.s3_targets();
        let id = create(&db, "offsite").await;
        let mut fields = target("renamed");
        fields.bucket = "other";
        assert!(repo.update(id, &fields, None).await.unwrap());
        let row = repo.by_id(id).await.unwrap().unwrap();
        assert_eq!(
            (row.name.as_str(), row.bucket.as_str()),
            ("renamed", "other")
        );
        assert_eq!(
            repo.secret(id).await.unwrap().as_deref(),
            Some("fernet:secret")
        );
        assert!(repo
            .update(id, &fields, Some("fernet:rotated"))
            .await
            .unwrap());
        assert_eq!(
            repo.secret(id).await.unwrap().as_deref(),
            Some("fernet:rotated")
        );
        assert!(!repo.update(id + 1, &fields, None).await.unwrap());
    }

    #[tokio::test]
    async fn a_name_is_taken_only_by_another_target() {
        let db = db().await;
        let id = create(&db, "offsite").await;
        let repo = db.s3_targets();
        assert!(repo.name_taken("offsite", None).await.unwrap());
        assert!(!repo.name_taken("offsite", Some(id)).await.unwrap());
        assert!(!repo.name_taken("elsewhere", None).await.unwrap());
    }

    #[tokio::test]
    async fn the_schedules_a_target_serves_are_listed() {
        let db = db().await;
        let id = create(&db, "offsite").await;
        assert!(db
            .s3_targets()
            .schedules_using(id)
            .await
            .unwrap()
            .is_empty());
        let options = ScheduleOptions {
            s3_target_id: Some(id),
            name_style: NameStyle::Date,
        };
        db.schedule_options().set(1, options).await.unwrap();
        assert_eq!(db.s3_targets().schedules_using(id).await.unwrap(), [1]);
        let all = db.schedule_options().all().await.unwrap();
        assert_eq!(all.get(&1), Some(&options));
        db.schedule_options().delete(1).await.unwrap();
        assert!(db.schedule_options().all().await.unwrap().is_empty());
    }

    #[test]
    fn every_name_style_reads_back_as_itself() {
        for style in NameStyle::ALL {
            assert_eq!(NameStyle::parse(style.as_str()), Some(style));
        }
        assert_eq!(NameStyle::parse("monthly"), None);
    }
}
