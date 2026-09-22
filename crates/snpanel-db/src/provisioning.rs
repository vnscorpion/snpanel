//! `provisioning_accounts` — the billing system's view of a hosting account.
//!
//! One row per service a billing system has bought, keyed by **its** id
//! rather than the panel's. The row outlives the panel user: terminating an
//! account clears `user_id` and leaves the record, because the billing
//! module still reads it to show the service as terminated. That is why
//! every join here is a left join and every name that comes through it is
//! optional.

use sqlx::sqlite::SqlitePool;

use super::DbError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProvisioningAccount {
    pub id: i64,
    pub external_id: String,
    pub user_id: Option<i64>,
    pub primary_website_id: Option<i64>,
    pub package_id: Option<i64>,
    pub status: String,
    pub last_action: String,
    pub last_message: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// One account with the three names the payload needs, resolved in the
/// query rather than by three more round trips.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProvisioningAccountView {
    pub external_id: String,
    pub user_id: Option<i64>,
    pub package_id: Option<i64>,
    pub status: String,
    pub created_at: Option<String>,
    /// Empty rather than null when the account has been terminated.
    pub username: Option<String>,
    pub email: Option<String>,
    pub domain: Option<String>,
    pub package_name: Option<String>,
}

const COLUMNS: &str = "id, external_id, user_id, primary_website_id, package_id, status, \
                       last_action, last_message, created_at, updated_at";

pub struct ProvisioningRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ProvisioningRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `_account_by_external_id`.
    pub async fn by_external_id(
        &self,
        external_id: &str,
    ) -> Result<Option<ProvisioningAccount>, DbError> {
        let sql = format!("SELECT {COLUMNS} FROM provisioning_accounts WHERE external_id = ?");
        Ok(sqlx::query_as::<_, ProvisioningAccount>(&sql)
            .bind(external_id)
            .fetch_optional(self.pool)
            .await?)
    }

    /// Source: `account_to_dict`'s three relationship reads, as one query.
    ///
    /// Left joins throughout: a terminated account has no user, an account
    /// bought without a domain has no website, and a package can be deleted
    /// out from under a row. Any of those turning the whole lookup into a
    /// 404 would hide a service the billing system is still charging for.
    pub async fn view(
        &self,
        external_id: &str,
    ) -> Result<Option<ProvisioningAccountView>, DbError> {
        let sql = "SELECT a.external_id, a.user_id, a.package_id, a.status, a.created_at, \
                          u.username AS username, u.email AS email, \
                          w.domain AS domain, p.name AS package_name \
                   FROM provisioning_accounts a \
                   LEFT JOIN users u ON u.id = a.user_id \
                   LEFT JOIN websites w ON w.id = a.primary_website_id \
                   LEFT JOIN user_packages p ON p.id = a.package_id \
                   WHERE a.external_id = ?";
        Ok(sqlx::query_as::<_, ProvisioningAccountView>(sql)
            .bind(external_id)
            .fetch_optional(self.pool)
            .await?)
    }

    /// Source: `account.last_action = ...; db.commit()`.
    ///
    /// The row records what was last done to it, which is the only trace a
    /// billing system's action leaves on the account itself — the audit
    /// entry beside it names no actor, because the caller is a machine.
    pub async fn set_last_action(
        &self,
        id: i64,
        action: &str,
        updated_at: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE provisioning_accounts SET last_action = ?, updated_at = ? WHERE id = ?",
        )
        .bind(action)
        .bind(updated_at)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `change_package` — the account's half of the change.
    ///
    /// The user's half is the caller's: the limits are **copied** onto the
    /// user row, not referenced, because enforcement reads one row.
    pub async fn set_package(
        &self,
        id: i64,
        package_id: i64,
        updated_at: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE provisioning_accounts \
             SET package_id = ?, last_action = 'change_package', updated_at = ? WHERE id = ?",
        )
        .bind(package_id)
        .bind(updated_at)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: the three fields `suspend_account` and `unsuspend_account`
    /// set on the row before committing.
    ///
    /// `last_message` carries the reason a billing system gave, and is
    /// **cleared** on unsuspend rather than left behind — an account that
    /// is running again should not still show why it once stopped.
    pub async fn set_status(
        &self,
        id: i64,
        status: &str,
        last_action: &str,
        last_message: &str,
        updated_at: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE provisioning_accounts \
             SET status = ?, last_action = ?, last_message = ?, updated_at = ? WHERE id = ?",
        )
        .bind(status)
        .bind(last_action)
        .bind(last_message)
        .bind(updated_at)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// How many websites and databases an account's user owns.
    ///
    /// Source: the two `.count()` calls in `get_usage`. They count what the
    /// **user** owns, not what the account's primary website is, because a
    /// customer may have added sites after the account was provisioned.
    pub async fn usage_counts(&self, user_id: i64) -> Result<(i64, i64), DbError> {
        let websites: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM websites WHERE owner_id = ?")
            .bind(user_id)
            .fetch_one(self.pool)
            .await?;
        let databases: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM database_accounts WHERE owner_id = ?")
                .bind(user_id)
                .fetch_one(self.pool)
                .await?;
        Ok((websites, databases))
    }
}
