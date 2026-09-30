//! Resellers - not in the Python.
//!
//! A reseller is a user whose role is `reseller`: hosting of its own, and
//! the accounts it made (`user_parents`), on packages of its own
//! (`package_owners`), inside the limits the administrator set
//! (`reseller_accounts`). Every limit is on what is really used across the
//! reseller and its accounts; zero is no limit.

use sqlx::sqlite::SqlitePool;
use sqlx::Row;

use super::DbError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ResellerLimits {
    pub prefix: String,
    pub max_accounts: i64,
    pub max_websites: i64,
    pub max_databases: i64,
    pub max_mailboxes: i64,
    pub max_disk_mb: i64,
}

pub struct ResellerRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ResellerRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn limits(&self, user_id: i64) -> Result<Option<ResellerLimits>, DbError> {
        let row = sqlx::query(
            "SELECT prefix, max_accounts, max_websites, max_databases, max_mailboxes, max_disk_mb \
             FROM reseller_accounts WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| ResellerLimits {
            prefix: r.get(0),
            max_accounts: r.get(1),
            max_websites: r.get(2),
            max_databases: r.get(3),
            max_mailboxes: r.get(4),
            max_disk_mb: r.get(5),
        }))
    }

    /// Whether another reseller has `prefix`.
    pub async fn prefix_taken(&self, prefix: &str, except: Option<i64>) -> Result<bool, DbError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reseller_accounts WHERE prefix = ? AND user_id != ?",
        )
        .bind(prefix)
        .bind(except.unwrap_or(-1))
        .fetch_one(self.pool)
        .await?;
        Ok(n > 0)
    }

    pub async fn set_limits(&self, user_id: i64, l: &ResellerLimits) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO reseller_accounts \
             (user_id, prefix, max_accounts, max_websites, max_databases, max_mailboxes, max_disk_mb, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) \
             ON CONFLICT(user_id) DO UPDATE SET prefix = excluded.prefix, \
             max_accounts = excluded.max_accounts, max_websites = excluded.max_websites, \
             max_databases = excluded.max_databases, max_mailboxes = excluded.max_mailboxes, \
             max_disk_mb = excluded.max_disk_mb",
        )
        .bind(user_id)
        .bind(&l.prefix)
        .bind(l.max_accounts)
        .bind(l.max_websites)
        .bind(l.max_databases)
        .bind(l.max_mailboxes)
        .bind(l.max_disk_mb)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn remove_limits(&self, user_id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM reseller_accounts WHERE user_id = ?")
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// The reseller an account belongs to, if any.
    pub async fn parent_of(&self, user_id: i64) -> Result<Option<i64>, DbError> {
        Ok(sqlx::query_scalar("SELECT parent_id FROM user_parents WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(self.pool)
            .await?)
    }

    /// Every account's reseller, for the administrator's list.
    pub async fn all_parents(&self) -> Result<Vec<(i64, i64)>, DbError> {
        let rows = sqlx::query("SELECT user_id, parent_id FROM user_parents")
            .fetch_all(self.pool)
            .await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    /// The accounts a reseller made.
    pub async fn children(&self, parent_id: i64) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar("SELECT user_id FROM user_parents WHERE parent_id = ? ORDER BY user_id")
            .bind(parent_id)
            .fetch_all(self.pool)
            .await?)
    }

    pub async fn set_parent(&self, user_id: i64, parent_id: Option<i64>) -> Result<(), DbError> {
        match parent_id {
            Some(parent) => {
                sqlx::query(
                    "INSERT INTO user_parents (user_id, parent_id) VALUES (?, ?) \
                     ON CONFLICT(user_id) DO UPDATE SET parent_id = excluded.parent_id, suspended_by_parent = 0",
                )
                .bind(user_id)
                .bind(parent)
                .execute(self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM user_parents WHERE user_id = ?")
                    .bind(user_id)
                    .execute(self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// The accounts suspended with their reseller, to let back in with it.
    pub async fn suspended_with_parent(&self, parent_id: i64) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT user_id FROM user_parents WHERE parent_id = ? AND suspended_by_parent = 1",
        )
        .bind(parent_id)
        .fetch_all(self.pool)
        .await?)
    }

    pub async fn mark_suspended_by_parent(&self, user_id: i64, flag: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE user_parents SET suspended_by_parent = ? WHERE user_id = ?")
            .bind(flag)
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// The reseller a package is, if any.
    pub async fn package_owner(&self, package_id: i64) -> Result<Option<i64>, DbError> {
        Ok(sqlx::query_scalar("SELECT owner_id FROM package_owners WHERE package_id = ?")
            .bind(package_id)
            .fetch_optional(self.pool)
            .await?)
    }

    pub async fn all_package_owners(&self) -> Result<Vec<(i64, i64)>, DbError> {
        let rows = sqlx::query("SELECT package_id, owner_id FROM package_owners")
            .fetch_all(self.pool)
            .await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    pub async fn set_package_owner(&self, package_id: i64, owner_id: Option<i64>) -> Result<(), DbError> {
        match owner_id {
            Some(owner) => {
                sqlx::query(
                    "INSERT INTO package_owners (package_id, owner_id) VALUES (?, ?) \
                     ON CONFLICT(package_id) DO UPDATE SET owner_id = excluded.owner_id",
                )
                .bind(package_id)
                .bind(owner)
                .execute(self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM package_owners WHERE package_id = ?")
                    .bind(package_id)
                    .execute(self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// A reseller's packages become the administrator's (the reseller is
    /// going, its accounts stay).
    pub async fn release_packages(&self, owner_id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM package_owners WHERE owner_id = ?")
            .bind(owner_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// The reseller a provisioning token is, if any.
    pub async fn token_owner(&self, token_id: i64) -> Result<Option<i64>, DbError> {
        Ok(sqlx::query_scalar("SELECT owner_id FROM api_token_owners WHERE token_id = ?")
            .bind(token_id)
            .fetch_optional(self.pool)
            .await?)
    }

    pub async fn all_token_owners(&self) -> Result<Vec<(i64, i64)>, DbError> {
        let rows = sqlx::query("SELECT token_id, owner_id FROM api_token_owners")
            .fetch_all(self.pool)
            .await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    pub async fn set_token_owner(&self, token_id: i64, owner_id: i64) -> Result<(), DbError> {
        sqlx::query("INSERT OR IGNORE INTO api_token_owners (token_id, owner_id) VALUES (?, ?)")
            .bind(token_id)
            .bind(owner_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// The mailboxes a package allows; zero is no limit.
    pub async fn mailbox_limit(&self, package_id: i64) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar("SELECT mailbox_limit FROM package_mail_limits WHERE package_id = ?")
            .bind(package_id)
            .fetch_optional(self.pool)
            .await?
            .unwrap_or(0))
    }

    pub async fn all_mailbox_limits(&self) -> Result<Vec<(i64, i64)>, DbError> {
        let rows = sqlx::query("SELECT package_id, mailbox_limit FROM package_mail_limits")
            .fetch_all(self.pool)
            .await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    pub async fn set_mailbox_limit(&self, package_id: i64, limit: i64) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO package_mail_limits (package_id, mailbox_limit) VALUES (?, ?) \
             ON CONFLICT(package_id) DO UPDATE SET mailbox_limit = excluded.mailbox_limit",
        )
        .bind(package_id)
        .bind(limit)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Websites owned by any of `users`.
    pub async fn count_websites(&self, users: &[i64]) -> Result<i64, DbError> {
        self.count_in("SELECT COUNT(*) FROM websites WHERE owner_id IN", users).await
    }

    /// Databases owned by any of `users`.
    pub async fn count_databases(&self, users: &[i64]) -> Result<i64, DbError> {
        self.count_in("SELECT COUNT(*) FROM database_accounts WHERE owner_id IN", users).await
    }

    async fn count_in(&self, head: &str, users: &[i64]) -> Result<i64, DbError> {
        if users.is_empty() {
            return Ok(0);
        }
        let marks = vec!["?"; users.len()].join(", ");
        let sql = format!("{head} ({marks})");
        let mut q = sqlx::query_scalar::<_, i64>(&sql);
        for u in users {
            q = q.bind(u);
        }
        Ok(q.fetch_one(self.pool).await?)
    }
}
