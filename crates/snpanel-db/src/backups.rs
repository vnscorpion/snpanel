//! Backup schedules and SFTP targets.
//!
//! Source: the `backup_schedules` and `sftp_backup_targets` tables. Both are
//! plain CRUD, with one thing worth care: a target's password and private key
//! are stored encrypted and must never leave this crate in the clear - the
//! response model the panel returns does not carry either field, and neither
//! does the row type here.

use sqlx::SqlitePool;

use crate::DbError;

/// One row of `backup_schedules`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BackupSchedule {
    pub id: i64,
    pub user_id: Option<i64>,
    /// A JSON array, as the column stores it.
    pub user_ids: String,
    pub all_users: bool,
    pub target_id: Option<i64>,
    pub schedule: String,
    pub retention: i64,
    pub is_active: bool,
    pub last_run_at: Option<String>,
    pub last_status: String,
    pub last_message: String,
}

/// One row of `sftp_backup_targets`, **without** its secrets.
///
/// `password` and `private_key` are deliberately absent. They are written by
/// [`SftpTargetRepo::create`] and read only by the code that opens the SSH
/// connection; a row type that carried them would put them one `Debug` away
/// from a log line.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SftpTarget {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub username: String,
    pub remote_path: String,
    pub is_active: bool,
    pub host_key_type: Option<String>,
    pub host_key_fingerprint: Option<String>,
}

/// The two encrypted columns, kept apart from the row on purpose.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SftpSecrets {
    pub password: Option<String>,
    pub private_key: Option<String>,
}

const SFTP_COLUMNS: &str =
    "id, name, host, port, username, remote_path, is_active, host_key_type, host_key_fingerprint";
const SCHEDULE_COLUMNS: &str = "id, user_id, user_ids, all_users, target_id, schedule, retention, \
     is_active, last_run_at, last_status, last_message";

/// The columns `_remove_user_from_backup_schedules` reads and writes.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduleUsers {
    pub id: i64,
    pub user_id: Option<i64>,
    /// JSON, or a comma-separated list from before it was JSON. Both shapes
    /// are still out there.
    pub user_ids: Option<String>,
    pub all_users: bool,
}

pub struct BackupScheduleRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> BackupScheduleRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `list_backup_schedules` - newest first.
    pub async fn list(&self) -> Result<Vec<BackupSchedule>, DbError> {
        Ok(sqlx::query_as::<_, BackupSchedule>(&format!(
            "SELECT {SCHEDULE_COLUMNS} FROM backup_schedules ORDER BY id DESC"
        ))
        .fetch_all(self.pool)
        .await?)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<BackupSchedule>, DbError> {
        Ok(sqlx::query_as::<_, BackupSchedule>(&format!(
            "SELECT {SCHEDULE_COLUMNS} FROM backup_schedules WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Source: `create_backup_schedule`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        user_id: Option<i64>,
        user_ids_json: &str,
        all_users: bool,
        target_id: Option<i64>,
        schedule: &str,
        retention: i64,
        is_active: bool,
    ) -> Result<BackupSchedule, DbError> {
        Ok(sqlx::query_as::<_, BackupSchedule>(&format!(
            "INSERT INTO backup_schedules \
             (user_id, user_ids, all_users, target_id, schedule, retention, is_active, \
              last_status, last_message, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', '', ?) \
             RETURNING {SCHEDULE_COLUMNS}"
        ))
        .bind(user_id)
        .bind(user_ids_json)
        .bind(all_users)
        .bind(target_id)
        .bind(schedule)
        .bind(retention)
        .bind(is_active)
        .bind(crate::sqlalchemy_now())
        .fetch_one(self.pool)
        .await?)
    }

    /// Every schedule's user columns, for the one caller that has to rewrite
    /// them: deleting a panel user.
    ///
    /// Returned raw because what the text column *means* is the route's
    /// question - it holds JSON, or a comma-separated list from before it
    /// held JSON, and deciding between them is not a repository's job.
    pub async fn user_columns(&self) -> Result<Vec<ScheduleUsers>, DbError> {
        Ok(sqlx::query_as::<_, ScheduleUsers>(
            "SELECT id, user_id, user_ids, all_users FROM backup_schedules ORDER BY id",
        )
        .fetch_all(self.pool)
        .await?)
    }

    /// Source: the two assignments in `_remove_user_from_backup_schedules`.
    pub async fn set_users(
        &self,
        id: i64,
        user_id: Option<i64>,
        user_ids: &str,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE backup_schedules SET user_id = ?, user_ids = ? WHERE id = ?")
            .bind(user_id)
            .bind(user_ids)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM backup_schedules WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }
}

pub struct SftpTargetRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> SftpTargetRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `list_sftp_targets` - newest first.
    pub async fn list(&self) -> Result<Vec<SftpTarget>, DbError> {
        Ok(sqlx::query_as::<_, SftpTarget>(&format!(
            "SELECT {SFTP_COLUMNS} FROM sftp_backup_targets ORDER BY id DESC"
        ))
        .fetch_all(self.pool)
        .await?)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<SftpTarget>, DbError> {
        Ok(sqlx::query_as::<_, SftpTarget>(&format!(
            "SELECT {SFTP_COLUMNS} FROM sftp_backup_targets WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Whether an *active* target with this id exists.
    ///
    /// Source: the `is_active == True` filter both callers apply. A schedule
    /// pointed at a disabled target would fail at two in the morning with
    /// nobody watching.
    pub async fn active_exists(&self, id: i64) -> Result<bool, DbError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sftp_backup_targets WHERE id = ? AND is_active = 1",
        )
        .bind(id)
        .fetch_one(self.pool)
        .await?;
        Ok(count > 0)
    }

    /// The two secrets, still encrypted, for the one caller that opens a
    /// connection with them.
    ///
    /// Asked for by name rather than carried on [`SftpTarget`]: a row type
    /// that held them would put a customer's private key one `Debug` away
    /// from a log line. Both are `None` when the column is empty, which is
    /// what `decrypt(target.password) if target.password else None` means.
    pub async fn secrets(&self, id: i64) -> Result<Option<SftpSecrets>, DbError> {
        Ok(sqlx::query_as::<_, SftpSecrets>(
            "SELECT password, private_key FROM sftp_backup_targets WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Remember the host key this target answered with.
    ///
    /// Source: the `if not target.host_key_fingerprint` guard — only ever
    /// written when there is nothing pinned yet. A target that already has a
    /// pin keeps it, because overwriting it on every upload would turn the
    /// pin into a record of whoever answered last.
    pub async fn pin_host_key(
        &self,
        id: i64,
        key_type: &str,
        fingerprint: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE sftp_backup_targets SET host_key_type = ?, host_key_fingerprint = ? \
             WHERE id = ? AND (host_key_fingerprint IS NULL OR host_key_fingerprint = '')",
        )
        .bind(key_type)
        .bind(fingerprint)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn name_taken(&self, name: &str) -> Result<bool, DbError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sftp_backup_targets WHERE name = ?")
                .bind(name)
                .fetch_one(self.pool)
                .await?;
        Ok(count > 0)
    }

    /// Source: `create_sftp_target`.
    ///
    /// The secrets arrive already encrypted: this crate does not hold the
    /// panel's key, and a repository that encrypted on the caller's behalf
    /// would be one that could be called without encrypting.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        name: &str,
        host: &str,
        port: i64,
        username: &str,
        encrypted_password: Option<&str>,
        encrypted_private_key: Option<&str>,
        remote_path: &str,
    ) -> Result<SftpTarget, DbError> {
        Ok(sqlx::query_as::<_, SftpTarget>(&format!(
            "INSERT INTO sftp_backup_targets \
             (name, host, port, username, password, private_key, remote_path, is_active, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?) \
             RETURNING {SFTP_COLUMNS}"
        ))
        .bind(name)
        .bind(host)
        .bind(port)
        .bind(username)
        .bind(encrypted_password)
        .bind(encrypted_private_key)
        .bind(remote_path)
        .bind(crate::sqlalchemy_now())
        .fetch_one(self.pool)
        .await?)
    }

    pub async fn delete(&self, id: i64) -> Result<Option<String>, DbError> {
        let name: Option<String> =
            sqlx::query_scalar("DELETE FROM sftp_backup_targets WHERE id = ? RETURNING name")
                .bind(id)
                .fetch_optional(self.pool)
                .await?;
        Ok(name)
    }
}
