//! `database_accounts` - the MariaDB databases the panel created.
//!
//! `db_password` holds a **Fernet ciphertext**, never a plain password (C3).
//! It is the column the whole encryption contract exists for: get the key
//! derivation wrong and every customer's database password becomes
//! unrecoverable, which is risk R1 in the plan.

use sqlx::sqlite::SqlitePool;

use super::DbError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DatabaseAccount {
    pub id: i64,
    pub owner_id: i64,
    pub website_id: Option<i64>,
    pub db_name: String,
    pub db_user: String,
    /// Fernet ciphertext with the `fernet:` prefix.
    pub db_password: String,
}

const COLUMNS: &str = "id, owner_id, website_id, db_name, db_user, db_password";

pub struct DatabaseRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> DatabaseRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `list_databases`.
    ///
    /// `owner` restricts the list to one customer; an administrator passes
    /// `None` and sees them all. The filter is applied in SQL rather than
    /// after the fact, so a customer's own row count cannot leak the total.
    ///
    /// `search` is SQLAlchemy's `ilike("%term%")` on the name and the user.
    /// The term is bound, and `%` and `_` inside it are escaped: without that,
    /// a search for `_` matches every single-character name and a search for
    /// `%` matches everything, which is a confusing search box rather than a
    /// vulnerability - but the escape is one line.
    pub async fn list(
        &self,
        owner: Option<i64>,
        search: &str,
    ) -> Result<Vec<DatabaseAccount>, DbError> {
        let mut sql = format!("SELECT {COLUMNS} FROM database_accounts WHERE 1 = 1");
        if owner.is_some() {
            sql.push_str(" AND owner_id = ?");
        }
        if !search.is_empty() {
            sql.push_str(
                " AND (LOWER(db_name) LIKE ? ESCAPE '\\' OR LOWER(db_user) LIKE ? ESCAPE '\\')",
            );
        }
        sql.push_str(" ORDER BY id DESC");

        let mut query = sqlx::query_as::<_, DatabaseAccount>(&sql);
        if let Some(id) = owner {
            query = query.bind(id);
        }
        if !search.is_empty() {
            let like = format!(
                "%{}%",
                search
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            );
            query = query.bind(like.clone()).bind(like);
        }
        Ok(query.fetch_all(self.pool).await?)
    }

    /// Source: `change_database_password` - the column, after MariaDB has
    /// taken the change. Stored encrypted; the panel hands it to phpMyAdmin
    /// later, so it is reversible by design and the key is what protects it.
    pub async fn set_password(&self, id: i64, encrypted: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE database_accounts SET db_password = ? WHERE id = ?")
            .bind(encrypted)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `delete_database_record`.
    pub async fn delete(&self, id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM database_accounts WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<DatabaseAccount>, DbError> {
        Ok(sqlx::query_as::<_, DatabaseAccount>(&format!(
            "SELECT {COLUMNS} FROM database_accounts WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Source: `db.query(DatabaseAccount).filter(DatabaseAccount.website_id ==
    /// website.id).first()` - the database a site is deleted along with.
    pub async fn by_website(&self, website_id: i64) -> Result<Option<DatabaseAccount>, DbError> {
        Ok(sqlx::query_as::<_, DatabaseAccount>(&format!(
            "SELECT {COLUMNS} FROM database_accounts WHERE website_id = ? ORDER BY id LIMIT 1"
        ))
        .bind(website_id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Source: `db.add(DatabaseAccount(...))`.
    ///
    /// The password arrives **already encrypted** - C3. Taking it in plain
    /// here would put one more function between the secret and the column
    /// that has to hold it encrypted, and that is the column risk R1 is
    /// about.
    pub async fn create(
        &self,
        owner_id: i64,
        website_id: Option<i64>,
        db_name: &str,
        db_user: &str,
        encrypted_password: &str,
    ) -> Result<i64, DbError> {
        Ok(sqlx::query(
            "INSERT INTO database_accounts (owner_id, website_id, db_name, db_user, db_password) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(owner_id)
        .bind(website_id)
        .bind(db_name)
        .bind(db_user)
        .bind(encrypted_password)
        .execute(self.pool)
        .await?
        .last_insert_rowid())
    }

    /// Source: `db_account.owner_id = ...` in `install_wordpress_on_website` -
    /// an existing row taken over by the site that just installed on it.
    pub async fn attach_to_website(
        &self,
        id: i64,
        owner_id: i64,
        website_id: i64,
        db_user: &str,
        encrypted_password: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE database_accounts SET owner_id = ?, website_id = ?, db_user = ?, \
             db_password = ? WHERE id = ?",
        )
        .bind(owner_id)
        .bind(website_id)
        .bind(db_user)
        .bind(encrypted_password)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `db.query(DatabaseAccount).filter(DatabaseAccount.db_name ==
    /// db_info["db_name"]).first()`.
    /// Every database account attached to one website.
    ///
    /// Source: `db.query(DatabaseAccount).filter(website_id == ...).all()`.
    /// A website usually has one, but an import that ran twice can leave
    /// two, and deleting the site has to take both.
    pub async fn for_website(&self, website_id: i64) -> Result<Vec<DatabaseAccount>, DbError> {
        let sql =
            format!("SELECT {COLUMNS} FROM database_accounts WHERE website_id = ? ORDER BY id ASC");
        Ok(sqlx::query_as::<_, DatabaseAccount>(&sql)
            .bind(website_id)
            .fetch_all(self.pool)
            .await?)
    }

    /// Every database account one panel user owns.
    ///
    /// Source: `db.query(DatabaseAccount).filter(owner_id == ...).all()`,
    /// which is how an import clears the account it is replacing.
    pub async fn for_owner(&self, owner_id: i64) -> Result<Vec<DatabaseAccount>, DbError> {
        let sql =
            format!("SELECT {COLUMNS} FROM database_accounts WHERE owner_id = ? ORDER BY id ASC");
        Ok(sqlx::query_as::<_, DatabaseAccount>(&sql)
            .bind(owner_id)
            .fetch_all(self.pool)
            .await?)
    }

    /// Point an existing row at what a restore just recreated.
    ///
    /// Source: the `else` arm in `restore_user_backup` — the same four
    /// columns the create path writes, on a row that is already there.
    pub async fn restore_write(
        &self,
        id: i64,
        owner_id: i64,
        db_name: &str,
        db_user: &str,
        encrypted_password: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE database_accounts SET owner_id = ?, db_name = ?, db_user = ?, \
                db_password = ? WHERE id = ?",
        )
        .bind(owner_id)
        .bind(db_name)
        .bind(db_user)
        .bind(encrypted_password)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn by_name(&self, db_name: &str) -> Result<Option<DatabaseAccount>, DbError> {
        Ok(sqlx::query_as::<_, DatabaseAccount>(&format!(
            "SELECT {COLUMNS} FROM database_accounts WHERE db_name = ? ORDER BY id LIMIT 1"
        ))
        .bind(db_name)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Source: `db.query(DatabaseAccount).filter(DatabaseAccount.db_user ==
    /// db_user).first()`.
    ///
    /// Asked separately from `by_name` because the two 409s say different
    /// things: the caller has to know which of the two names to change.
    pub async fn by_user(&self, db_user: &str) -> Result<Option<DatabaseAccount>, DbError> {
        Ok(sqlx::query_as::<_, DatabaseAccount>(&format!(
            "SELECT {COLUMNS} FROM database_accounts WHERE db_user = ? ORDER BY id LIMIT 1"
        ))
        .bind(db_user)
        .fetch_optional(self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scratch() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE database_accounts (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER,
                website_id INTEGER,
                db_name TEXT UNIQUE,
                db_user TEXT UNIQUE,
                db_password TEXT,
                created_at DATETIME
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO database_accounts (id, owner_id, website_id, db_name, db_user, db_password)
             VALUES (1, 1, NULL, 'shop_db', 'shop_user', 'fernet:aaa'),
                    (2, 2, 5, 'blog_db', 'blog_user', 'fernet:bbb'),
                    (3, 1, NULL, 'a_b', 'under_user', 'fernet:ccc')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn a_customer_sees_only_their_own() {
        let pool = scratch().await;
        let repo = DatabaseRepo::new(&pool);
        let mine: Vec<i64> = repo
            .list(Some(1), "")
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.id)
            .collect();
        // Newest first, and nothing belonging to owner 2.
        assert_eq!(mine, vec![3, 1]);
    }

    #[tokio::test]
    async fn an_administrator_sees_them_all() {
        let pool = scratch().await;
        let ids: Vec<i64> = DatabaseRepo::new(&pool)
            .list(None, "")
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(ids, vec![3, 2, 1]);
    }

    #[tokio::test]
    async fn the_search_matches_the_name_or_the_user() {
        let pool = scratch().await;
        let repo = DatabaseRepo::new(&pool);
        assert_eq!(repo.list(None, "shop").await.unwrap().len(), 1);
        assert_eq!(repo.list(None, "user").await.unwrap().len(), 3);
        assert_eq!(repo.list(None, "nothing").await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_wildcard_in_the_search_term_is_taken_literally() {
        // Without the escape, "_" matches any character and "%" matches
        // everything - a search box that ignores what was typed.
        let pool = scratch().await;
        let repo = DatabaseRepo::new(&pool);
        let underscore = repo.list(None, "a_b").await.unwrap();
        assert_eq!(underscore.len(), 1);
        assert_eq!(underscore[0].db_name, "a_b");

        assert_eq!(
            repo.list(None, "%").await.unwrap().len(),
            0,
            "a percent sign is a search term, not a wildcard"
        );
    }

    #[tokio::test]
    async fn the_password_column_is_never_plain() {
        // C3: this is the column risk R1 is about.
        let pool = scratch().await;
        let row = DatabaseRepo::new(&pool).by_id(1).await.unwrap().unwrap();
        assert!(row.db_password.starts_with("fernet:"));
    }
}
