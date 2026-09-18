//! `websites` and `website_aliases`.
//!
//! The largest table the panel renders, and the one whose listing every
//! customer opens first. Two ordering rules are part of the contract rather
//! than incidental: websites come back **newest first** (`id DESC`), and a
//! website's aliases come back **sorted by domain**, because the relationship
//! declares `order_by="WebsiteAlias.domain"`.

use sqlx::sqlite::SqlitePool;

use super::DbError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Website {
    pub id: i64,
    pub domain: String,
    pub owner_id: i64,
    pub root_path: String,
    pub document_root: String,
    pub linux_user: Option<String>,
    pub php_version: String,
    pub app_type: String,
    pub ssl_enabled: bool,
    pub ssl_mode: String,
    pub ssl_cert_path: Option<String>,
    pub ssl_key_path: Option<String>,
    pub ssl_ca_path: Option<String>,
    pub ssl_updated_at: Option<String>,
    pub ssl_source_domain: Option<String>,
    pub status: String,
    pub nginx_custom: String,
    pub nginx_config_mode: String,
    pub nginx_rewrite_mode: String,
    pub waf_enabled: bool,
    pub waf_default_rules: String,
    pub waf_custom_rules: String,
    pub crs_enabled: bool,
    pub http_flood_enabled: bool,
    pub http_flood_config: String,
    pub blocked_bots: String,
    pub app_id: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebsiteAlias {
    pub id: i64,
    pub website_id: i64,
    pub domain: String,
    pub mode: String,
    pub ssl_enabled: bool,
    pub created_at: Option<String>,
}

const COLUMNS: &str = "id, domain, owner_id, root_path, document_root, linux_user, php_version, \
                       app_type, ssl_enabled, ssl_mode, ssl_cert_path, ssl_key_path, ssl_ca_path, \
                       ssl_updated_at, ssl_source_domain, status, nginx_custom, nginx_config_mode, \
                       nginx_rewrite_mode, waf_enabled, waf_default_rules, waf_custom_rules, \
                       crs_enabled, http_flood_enabled, http_flood_config, blocked_bots, app_id";

pub struct WebsiteRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> WebsiteRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `list_websites`.
    ///
    /// The search reaches **aliases** as well as the website's own columns,
    /// through an outer join and a DISTINCT - a customer looking for
    /// `shop.example.com` should find the site that serves it under another
    /// name. Dropping the join would make the search quietly miss those.
    pub async fn list(&self, owner: Option<i64>, search: &str) -> Result<Vec<Website>, DbError> {
        let mut sql = format!("SELECT DISTINCT {} FROM websites w", prefixed(COLUMNS, "w"));
        if !search.is_empty() {
            sql.push_str(" LEFT JOIN website_aliases a ON a.website_id = w.id");
        }
        sql.push_str(" WHERE 1 = 1");
        if owner.is_some() {
            sql.push_str(" AND w.owner_id = ?");
        }
        if !search.is_empty() {
            sql.push_str(
                " AND (LOWER(w.domain) LIKE ? ESCAPE '\\' \
                   OR LOWER(w.root_path) LIKE ? ESCAPE '\\' \
                   OR LOWER(w.linux_user) LIKE ? ESCAPE '\\' \
                   OR LOWER(a.domain) LIKE ? ESCAPE '\\')",
            );
        }
        sql.push_str(" ORDER BY w.id DESC");

        let mut query = sqlx::query_as::<_, Website>(&sql);
        if let Some(id) = owner {
            query = query.bind(id);
        }
        if !search.is_empty() {
            let like = like_pattern(search);
            for _ in 0..4 {
                query = query.bind(like.clone());
            }
        }
        Ok(query.fetch_all(self.pool).await?)
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<Website>, DbError> {
        Ok(
            sqlx::query_as::<_, Website>(&format!("SELECT {COLUMNS} FROM websites WHERE id = ?"))
                .bind(id)
                .fetch_optional(self.pool)
                .await?,
        )
    }

    /// Source: the relationship's `order_by="WebsiteAlias.domain"`.
    pub async fn aliases(&self, website_id: i64) -> Result<Vec<WebsiteAlias>, DbError> {
        Ok(sqlx::query_as::<_, WebsiteAlias>(
            "SELECT id, website_id, domain, mode, ssl_enabled, created_at \
             FROM website_aliases WHERE website_id = ? ORDER BY domain ASC",
        )
        .bind(website_id)
        .fetch_all(self.pool)
        .await?)
    }

    /// Every alias for a set of websites, for a listing that renders them
    /// inline - one query rather than one per row.
    pub async fn aliases_for(&self, ids: &[i64]) -> Result<Vec<WebsiteAlias>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; ids.len()].join(", ");
        let sql = format!(
            "SELECT id, website_id, domain, mode, ssl_enabled, created_at \
             FROM website_aliases WHERE website_id IN ({placeholders}) ORDER BY domain ASC"
        );
        let mut query = sqlx::query_as::<_, WebsiteAlias>(&sql);
        for id in ids {
            query = query.bind(id);
        }
        Ok(query.fetch_all(self.pool).await?)
    }

    /// Source: `_sync_live_ssl_flags` - a certificate that appeared on disk
    /// without the panel doing it (a manual certbot run, a restored backup)
    /// turns the flag on so the UI stops offering to issue one.
    pub async fn set_ssl_enabled(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET ssl_enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

/// `id, domain` -> `w.id, w.domain`, so the join above is unambiguous.
fn prefixed(columns: &str, alias: &str) -> String {
    columns
        .split(',')
        .map(|c| format!("{alias}.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `%term%`, with LIKE's own wildcards escaped so a search for `_` is a search
/// for an underscore.
fn like_pattern(search: &str) -> String {
    format!(
        "%{}%",
        search
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn scratch() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE websites (
                id INTEGER PRIMARY KEY, domain TEXT UNIQUE, owner_id INTEGER,
                root_path TEXT, document_root TEXT, linux_user TEXT, php_version TEXT,
                app_type TEXT, ssl_enabled BOOLEAN, ssl_mode TEXT, ssl_cert_path TEXT,
                ssl_key_path TEXT, ssl_ca_path TEXT, ssl_updated_at DATETIME,
                ssl_source_domain TEXT, status TEXT, nginx_custom TEXT,
                nginx_config_mode TEXT, nginx_rewrite_mode TEXT, waf_enabled BOOLEAN,
                waf_default_rules TEXT, waf_custom_rules TEXT, crs_enabled BOOLEAN,
                http_flood_enabled BOOLEAN, http_flood_config TEXT, blocked_bots TEXT,
                app_id INTEGER, created_at DATETIME
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE website_aliases (
                id INTEGER PRIMARY KEY, website_id INTEGER, domain TEXT UNIQUE,
                mode TEXT, ssl_enabled BOOLEAN, created_at DATETIME
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (id, domain, owner, user) in [
            (1, "first.example.com", 1, "first"),
            (2, "second.example.com", 2, "second"),
            (3, "third.example.com", 1, "third"),
        ] {
            sqlx::query(
                "INSERT INTO websites (id, domain, owner_id, root_path, document_root,
                    linux_user, php_version, app_type, ssl_enabled, ssl_mode, status,
                    nginx_custom, nginx_config_mode, nginx_rewrite_mode, waf_enabled,
                    waf_default_rules, waf_custom_rules, crs_enabled, http_flood_enabled,
                    http_flood_config, blocked_bots)
                 VALUES (?, ?, ?, ?, 'public_html', ?, '8.3', 'wordpress', 0, 'none',
                         'active', '', 'managed', 'none', 1, '', '', 0, 0, '', '')",
            )
            .bind(id)
            .bind(domain)
            .bind(owner)
            .bind(format!("/home/{user}/{domain}"))
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO website_aliases (id, website_id, domain, mode, ssl_enabled)
             VALUES (1, 1, 'zebra.example.com', 'alias', 0),
                    (2, 1, 'apple.example.com', 'redirect', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn websites_come_back_newest_first() {
        let pool = scratch().await;
        let ids: Vec<i64> = WebsiteRepo::new(&pool)
            .list(None, "")
            .await
            .unwrap()
            .into_iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(ids, vec![3, 2, 1]);
    }

    #[tokio::test]
    async fn a_customer_sees_only_their_own() {
        let pool = scratch().await;
        let ids: Vec<i64> = WebsiteRepo::new(&pool)
            .list(Some(1), "")
            .await
            .unwrap()
            .into_iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(ids, vec![3, 1]);
    }

    #[tokio::test]
    async fn the_search_reaches_aliases_too() {
        // A customer looking for the name they typed into DNS should find the
        // site that serves it, even when the site is named something else.
        let pool = scratch().await;
        let repo = WebsiteRepo::new(&pool);
        let found = repo.list(None, "zebra").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].domain, "first.example.com");
    }

    #[tokio::test]
    async fn a_site_matching_twice_is_returned_once() {
        // Both of website 1's aliases match "example.com", and so does its own
        // domain. Without DISTINCT the join returns it three times.
        let pool = scratch().await;
        let found = WebsiteRepo::new(&pool)
            .list(None, "example.com")
            .await
            .unwrap();
        assert_eq!(found.len(), 3, "three sites, not one row per alias");
    }

    #[tokio::test]
    async fn the_search_covers_the_root_path_and_the_linux_user() {
        let pool = scratch().await;
        let repo = WebsiteRepo::new(&pool);
        assert_eq!(repo.list(None, "/home/second").await.unwrap().len(), 1);
        assert_eq!(repo.list(None, "third").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn aliases_are_sorted_by_domain() {
        // The relationship declares order_by, so the order is part of what the
        // page renders rather than whatever the database felt like.
        let pool = scratch().await;
        let domains: Vec<String> = WebsiteRepo::new(&pool)
            .aliases(1)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.domain)
            .collect();
        assert_eq!(domains, vec!["apple.example.com", "zebra.example.com"]);
    }

    #[tokio::test]
    async fn aliases_for_many_websites_come_in_one_query() {
        let pool = scratch().await;
        let all = WebsiteRepo::new(&pool)
            .aliases_for(&[1, 2, 3])
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|a| a.website_id == 1));
        // An empty list is not a query with no placeholders.
        assert!(WebsiteRepo::new(&pool)
            .aliases_for(&[])
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_wildcard_in_a_search_term_is_escaped() {
        assert_eq!(like_pattern("a_b"), "%a\\_b%");
        assert_eq!(like_pattern("50%"), "%50\\%%");
        assert_eq!(like_pattern("plain"), "%plain%");
    }

    #[test]
    fn the_join_columns_are_qualified() {
        // Both tables have `id` and `domain`; an unqualified select is
        // ambiguous the moment the alias join is added.
        let sql = prefixed("id, domain, owner_id", "w");
        assert_eq!(sql, "w.id, w.domain, w.owner_id");
    }
}
