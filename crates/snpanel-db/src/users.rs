//! The `users` and `revoked_tokens` tables.
//!
//! Enough of the schema to authenticate a request, which is what Phase 3 needs
//! first. Column names are Python's, and one of them is a trap:
//! **`hashed_password`**, not `password_hash`.

use sqlx::sqlite::SqlitePool;

use super::DbError;

/// A row of `users`, as far as authentication is concerned.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    /// bcrypt, or a crypt(3) hash for the root-synced admin account (C1).
    pub hashed_password: String,
    pub role: String,
    pub is_active: bool,
    /// NULL when no package is assigned; `/auth/session` reports the package's
    /// name, or null.
    pub package_id: Option<i64>,
    pub website_limit: i64,
    pub storage_limit_mb: i64,
    pub terminal_enabled: bool,
    /// Bumped to invalidate every previously-issued token for this user.
    pub token_version: i64,
    /// A Fernet ciphertext with the `fernet:` prefix, or NULL. Never a plain
    /// secret - decrypt it through `snpanel_core::crypto::fernet`.
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
}

impl User {
    /// Through `normalize_role`, not a string comparison: a panel installed
    /// before the rename stores `super_admin`, and comparing literals would
    /// demote the owner of the machine.
    pub fn is_admin(&self) -> bool {
        snpanel_core::permissions::is_admin_role(&self.role)
    }
}

/// The columns a patch may set. `None` leaves the column alone; `package_id`
/// is doubly optional because setting it to NULL (no package) is a real
/// operation distinct from not mentioning it.
#[derive(Debug, Default, Clone)]
/// Every column `create_user` writes.
///
/// A struct rather than eight positional arguments: `username`, `email`,
/// `hashed_password` and `role` are all `&str`, and a call that swapped two of
/// them would compile and store a password where a name goes.
pub struct NewUser<'a> {
    pub username: &'a str,
    pub email: &'a str,
    /// Already bcrypt. C1: the column never holds a plain password.
    pub hashed_password: &'a str,
    pub role: &'a str,
    pub package_id: Option<i64>,
    pub website_limit: i64,
    pub storage_limit_mb: i64,
    pub terminal_enabled: bool,
}

#[derive(Debug, Default, Clone)]
pub struct UserFields {
    pub email: Option<String>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub package_id: Option<Option<i64>>,
    pub website_limit: Option<i64>,
    pub storage_limit_mb: Option<i64>,
    pub terminal_enabled: Option<bool>,
}

pub struct UserRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> UserRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Look a user up by username, which is what the `sub` claim carries.
    pub async fn by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let row = sqlx::query_as::<_, User>(
            "SELECT id, username, email, hashed_password, role, is_active, package_id, \
                    website_limit, storage_limit_mb, terminal_enabled, \
                    token_version, totp_secret, totp_enabled \
             FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(self.pool)
        .await?;
        Ok(row)
    }

    /// Every active user, oldest first.
    ///
    /// Source: `_schedule_users`' `all_users` branch —
    /// `filter(User.is_active == True).order_by(User.id.asc())`.
    ///
    /// The order is part of the contract rather than incidental: the backup
    /// scheduler reports what it did as a list of usernames, and an order
    /// that moved between runs would make two identical runs look different
    /// to whoever is reading the last message.
    pub async fn active_ordered_by_id(&self) -> Result<Vec<User>, DbError> {
        let rows = sqlx::query_as::<_, User>(
            "SELECT id, username, email, hashed_password, role, is_active, package_id, \
                    website_limit, storage_limit_mb, terminal_enabled, \
                    token_version, totp_secret, totp_enabled \
             FROM users WHERE is_active = 1 ORDER BY id ASC",
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<User>, DbError> {
        let row = sqlx::query_as::<_, User>(
            "SELECT id, username, email, hashed_password, role, is_active, package_id, \
                    website_limit, storage_limit_mb, terminal_enabled, \
                    token_version, totp_secret, totp_enabled \
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        Ok(row)
    }

    /// Is this address already on **another** account?
    ///
    /// Source: `db.query(User).filter(User.email == next_email, User.id != id)`.
    /// The exclusion is what lets an administrator submit their own address
    /// unchanged without being told it is taken.
    pub async fn email_taken_by_other(&self, email: &str, id: i64) -> Result<bool, DbError> {
        let found: Option<i64> =
            sqlx::query_scalar("SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1")
                .bind(email)
                .bind(id)
                .fetch_optional(self.pool)
                .await?;
        Ok(found.is_some())
    }

    /// Every address already in use.
    ///
    /// Source: the `while db.query(User).filter(User.email == candidate)`
    /// loop in `_unique_email`. Read once rather than queried per
    /// candidate: the loop can run several times and the table is small.
    pub async fn all_emails(&self) -> Result<Vec<String>, DbError> {
        Ok(sqlx::query_scalar::<_, String>("SELECT email FROM users")
            .fetch_all(self.pool)
            .await?)
    }

    pub async fn count(&self) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(self.pool)
            .await?)
    }

    /// The name of the user's package, or `None`.
    ///
    /// Source: `current_user.package.name if current_user.package else None` -
    /// a relationship in SQLAlchemy, a join here.
    pub async fn package_name(&self, package_id: Option<i64>) -> Result<Option<String>, DbError> {
        let Some(id) = package_id else {
            return Ok(None);
        };
        Ok(
            sqlx::query_scalar("SELECT name FROM user_packages WHERE id = ?")
                .bind(id)
                .fetch_optional(self.pool)
                .await?,
        )
    }

    /// Invalidate every token already issued for this user (C27).
    ///
    /// Written as `token_version + 1` in SQL rather than read-modify-write:
    /// Python and Rust are both serving during the migration, and a lost
    /// update here would leave a session alive that the user believes they
    /// have just logged out of everywhere.
    pub async fn bump_token_version(&self, user_id: i64) -> Result<i64, DbError> {
        let new_version: i64 = sqlx::query_scalar(
            "UPDATE users SET token_version = COALESCE(token_version, 0) + 1 \
             WHERE id = ? RETURNING token_version",
        )
        .bind(user_id)
        .fetch_one(self.pool)
        .await?;
        Ok(new_version)
    }

    /// Source: the opportunistic rehash in `login`.
    pub async fn set_hashed_password(&self, user_id: i64, hash: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET hashed_password = ? WHERE id = ?")
            .bind(hash)
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Store a new TOTP secret. `secret` is already a Fernet ciphertext - this
    /// method never sees a plain one (C3).
    pub async fn set_totp_secret(&self, user_id: i64, secret: Option<&str>) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ?")
            .bind(secret)
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Turn 2FA on or off and invalidate existing sessions in one statement.
    ///
    /// Python does both then commits once; doing it in one UPDATE means a
    /// crash between them cannot leave 2FA disabled with sessions still valid.
    pub async fn set_totp_enabled(
        &self,
        user_id: i64,
        enabled: bool,
        clear_secret: bool,
    ) -> Result<i64, DbError> {
        let sql = if clear_secret {
            "UPDATE users SET totp_enabled = ?, totp_secret = NULL, \
             token_version = COALESCE(token_version, 0) + 1 \
             WHERE id = ? RETURNING token_version"
        } else {
            "UPDATE users SET totp_enabled = ?, \
             token_version = COALESCE(token_version, 0) + 1 \
             WHERE id = ? RETURNING token_version"
        };
        Ok(sqlx::query_scalar(sql)
            .bind(enabled)
            .bind(user_id)
            .fetch_one(self.pool)
            .await?)
    }

    /// Source: `order_by(User.id.desc())` - newest account first, which is the
    /// order the user list renders in.
    pub async fn list_all(&self) -> Result<Vec<User>, DbError> {
        Ok(sqlx::query_as::<_, User>(
            "SELECT id, username, email, hashed_password, role, is_active, package_id, \
                    website_limit, storage_limit_mb, terminal_enabled, \
                    token_version, totp_secret, totp_enabled \
             FROM users ORDER BY id DESC",
        )
        .fetch_all(self.pool)
        .await?)
    }

    /// Apply a patch.
    ///
    /// `bump_token_version` is decided by the caller rather than inferred
    /// here, because *which* changes invalidate a session is policy: a role
    /// change and a deactivation do, an email change does not.
    pub async fn update(
        &self,
        id: i64,
        f: &UserFields,
        bump: bool,
    ) -> Result<Option<User>, DbError> {
        let mut tx = self.pool.begin().await?;

        macro_rules! set {
            ($column:literal, $value:expr) => {
                if let Some(v) = $value {
                    sqlx::query(concat!("UPDATE users SET ", $column, " = ? WHERE id = ?"))
                        .bind(v)
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                }
            };
        }

        set!("email", f.email.clone());
        set!("role", f.role.clone());
        set!("is_active", f.is_active);
        set!("package_id", f.package_id);
        set!("website_limit", f.website_limit);
        set!("storage_limit_mb", f.storage_limit_mb);
        set!("terminal_enabled", f.terminal_enabled);

        if bump {
            sqlx::query(
                "UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id = ?",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        self.by_id(id).await
    }

    /// Every website root belonging to a user, for the storage figure.
    /// Source: `db.add(User(...))` in `create_user`.
    ///
    /// `is_active` and `token_version` are left to their column defaults; the
    /// Python's model sets neither on this path either.
    pub async fn create(&self, new: &NewUser<'_>) -> Result<i64, DbError> {
        Ok(sqlx::query(
            "INSERT INTO users (username, email, hashed_password, role, package_id, \
             website_limit, storage_limit_mb, terminal_enabled, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        )
        .bind(new.username)
        .bind(new.email)
        .bind(new.hashed_password)
        .bind(new.role)
        .bind(new.package_id)
        .bind(new.website_limit)
        .bind(new.storage_limit_mb)
        .bind(new.terminal_enabled)
        .execute(self.pool)
        .await?
        .last_insert_rowid())
    }

    /// Source: `db.delete(user)`.
    pub async fn delete(&self, id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    pub async fn website_roots(&self, owner_id: i64) -> Result<Vec<String>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT root_path FROM websites WHERE owner_id = ? AND root_path IS NOT NULL",
        )
        .bind(owner_id)
        .fetch_all(self.pool)
        .await?)
    }
}

/// One row of `audit_logs`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: Option<i64>,
    pub action: String,
    pub target: String,
    pub detail: Option<String>,
    pub created_at: Option<String>,
}

/// `audit_logs`.
pub struct AuditRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> AuditRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `services/audit.log_action`.
    ///
    /// The Python swallows a failure here and logs it, and so does the caller
    /// of this method: an audit write that fails must not turn a successful
    /// operation into a 500 the user retries.
    pub async fn log(
        &self,
        user_id: Option<i64>,
        action: &str,
        target: &str,
        detail: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO audit_logs (user_id, action, target, detail, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(action)
        .bind(target)
        .bind(detail)
        .bind(crate::sqlalchemy_now())
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `list_audit` - newest first, optionally filtered, with a
    /// window.
    ///
    /// The filters are bound parameters rather than interpolated text. An
    /// `action` reaching a query by concatenation would be a SQL injection in
    /// an endpoint whose whole purpose is the security record.
    pub async fn list(
        &self,
        user_id: Option<i64>,
        action: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEntry>, DbError> {
        let mut sql = String::from(
            "SELECT id, user_id, action, target, detail, created_at FROM audit_logs WHERE 1 = 1",
        );
        if user_id.is_some() {
            sql.push_str(" AND user_id = ?");
        }
        if action.is_some() {
            sql.push_str(" AND action = ?");
        }
        sql.push_str(" ORDER BY id DESC LIMIT ? OFFSET ?");

        let mut query = sqlx::query_as::<_, AuditEntry>(&sql);
        if let Some(id) = user_id {
            query = query.bind(id);
        }
        if let Some(a) = action {
            query = query.bind(a.to_string());
        }
        Ok(query.bind(limit).bind(offset).fetch_all(self.pool).await?)
    }

    /// Build the `detail` string the way `log_action` does: the caller's own
    /// text, then `ip=` and `ua=` joined with spaces after a `|`.
    pub fn detail_with_request(detail: &str, ip: &str, user_agent: &str) -> String {
        let mut extras = Vec::new();
        if !ip.is_empty() {
            extras.push(format!("ip={ip}"));
        }
        if !user_agent.is_empty() {
            // Python slices to 200 *characters*; do the same rather than bytes,
            // or a multibyte user-agent is truncated to a different length.
            let ua: String = user_agent.chars().take(200).collect();
            extras.push(format!("ua={ua}"));
        }
        if extras.is_empty() {
            return detail.to_string();
        }
        let joined = extras.join(" ");
        if detail.is_empty() {
            joined
        } else {
            format!("{detail} | {joined}")
        }
    }
}

pub struct RevokedTokenRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> RevokedTokenRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Has this `jti` been revoked?
    ///
    /// The plan also keeps a revocation list in Redis (C5) for speed. The
    /// database is the durable copy and the one `deps.py` consults, so it is
    /// what authentication checks here - a Redis cache in front of it is an
    /// optimisation, not the source of truth, and getting that backwards would
    /// let a revoked token work again after a Redis restart.
    pub async fn is_revoked(&self, jti: &str) -> Result<bool, DbError> {
        let found: Option<i64> = sqlx::query_scalar("SELECT id FROM revoked_tokens WHERE jti = ?")
            .bind(jti)
            .fetch_optional(self.pool)
            .await?;
        Ok(found.is_some())
    }

    /// Source: `_revoke_request_token`.
    ///
    /// Two things in one call, in the Python's order: drop every row that has
    /// already expired, then insert this `jti` if it is not already there. The
    /// prune is what keeps the table from growing without bound, and it is
    /// safe because a token past its own `exp` is refused by the signature
    /// check anyway - keeping its revocation record buys nothing.
    pub async fn revoke(&self, jti: &str, user_id: i64, expires_at: &str) -> Result<(), DbError> {
        let now = crate::sqlalchemy_now();
        sqlx::query("DELETE FROM revoked_tokens WHERE expires_at <= ?")
            .bind(&now)
            .execute(self.pool)
            .await?;
        // `OR IGNORE` rather than a SELECT then an INSERT: Python checks first,
        // but between its check and its insert another worker can win the race
        // and the unique index turns that into a 500 on a logout.
        sqlx::query(
            "INSERT OR IGNORE INTO revoked_tokens (jti, user_id, expires_at, revoked_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(jti)
        .bind(user_id)
        .bind(expires_at)
        .bind(&now)
        .execute(self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway database with the columns authentication reads, so the
    /// queries are exercised without needing an installed panel.
    async fn scratch() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                email TEXT,
                hashed_password TEXT,
                role TEXT,
                is_active BOOLEAN,
                package_id INTEGER,
                website_limit INTEGER,
                storage_limit_mb INTEGER,
                terminal_enabled BOOLEAN,
                token_version INTEGER,
                totp_secret TEXT,
                totp_enabled BOOLEAN,
                created_at DATETIME
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE revoked_tokens (
                id INTEGER PRIMARY KEY,
                jti TEXT UNIQUE,
                user_id INTEGER,
                expires_at DATETIME,
                revoked_at DATETIME
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, email, hashed_password, role, is_active,
                                website_limit, storage_limit_mb, terminal_enabled,
                                token_version, totp_secret, totp_enabled)
             VALUES (1, 'admin', 'admin@example.com', '$2b$12$abc', 'admin', 1,
                     999, 102400, 0, 3, NULL, 0),
                    (2, 'suspended', 's@example.com', '$2b$12$def', 'end_user', 0,
                     5, 1024, 0, 0, 'fernet:xyz', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn reads_a_user_by_the_name_the_sub_claim_carries() {
        let pool = scratch().await;
        let repo = UserRepo::new(&pool);
        let user = repo.by_username("admin").await.unwrap().expect("admin");
        assert_eq!(user.id, 1);
        assert!(user.is_admin());
        assert!(user.is_active);
        assert_eq!(user.token_version, 3);
        // The column is hashed_password, and this is the trap worth a test.
        assert!(user.hashed_password.starts_with("$2b$"));
    }

    #[tokio::test]
    async fn an_unknown_username_is_none_not_an_error() {
        let pool = scratch().await;
        assert!(UserRepo::new(&pool)
            .by_username("nobody")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_suspended_user_is_readable_but_flagged() {
        // Authentication needs the row in order to refuse it - and an
        // impersonated session is allowed to use it (the `imp` claim).
        let pool = scratch().await;
        let user = UserRepo::new(&pool)
            .by_username("suspended")
            .await
            .unwrap()
            .unwrap();
        assert!(!user.is_active);
        assert!(!user.is_admin());
    }

    #[tokio::test]
    async fn a_totp_secret_is_stored_encrypted() {
        // C3: never a plain secret in this column.
        let pool = scratch().await;
        let user = UserRepo::new(&pool)
            .by_username("suspended")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.totp_secret.as_deref(), Some("fernet:xyz"));
        assert!(user.totp_secret.unwrap().starts_with("fernet:"));
    }

    #[tokio::test]
    async fn revocation_is_looked_up_by_jti() {
        let pool = scratch().await;
        sqlx::query("INSERT INTO revoked_tokens (jti, user_id, expires_at, revoked_at) VALUES (?, 1, '2030-01-01', '2026-01-01')")
            .bind("revoked-jti")
            .execute(&pool)
            .await
            .unwrap();

        let repo = RevokedTokenRepo::new(&pool);
        assert!(repo.is_revoked("revoked-jti").await.unwrap());
        assert!(!repo.is_revoked("some-other-jti").await.unwrap());
    }

    #[tokio::test]
    async fn counting_users_works_on_an_empty_table() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(UserRepo::new(&pool).count().await.unwrap(), 0);
    }
}
