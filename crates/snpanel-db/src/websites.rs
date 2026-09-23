//! `websites` and `website_aliases`.
//!
//! The largest table the panel renders, and the one whose listing every
//! customer opens first. Two ordering rules are part of the contract rather
//! than incidental: websites come back **newest first** (`id DESC`), and a
//! website's aliases come back **sorted by domain**, because the relationship
//! declares `order_by="WebsiteAlias.domain"`.

use sqlx::sqlite::SqlitePool;

use super::DbError;

/// `Default` is for tests building a row to vary one field of. Nothing
/// reads a defaulted row from the database — every column here is `NOT NULL`
/// with its own default in the schema, and those are the schema's business.
#[derive(Debug, Clone, Default, sqlx::FromRow)]
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

    /// Every website, oldest first.
    ///
    /// Source: `db.query(Website).all()` with no `order_by`, which SQLite
    /// answers from a plain table scan in rowid order.
    ///
    /// Separate from [`Self::list`] on purpose. That one is the listing
    /// endpoint's `ORDER BY id DESC` — newest first, which is what the UI
    /// wants and the wrong thing for a sweep that stops at its first
    /// failure: the order decides which sites were already refreshed when it
    /// stopped.
    pub async fn all_by_id(&self) -> Result<Vec<Website>, DbError> {
        Ok(sqlx::query_as::<_, Website>(
            "SELECT id, domain, owner_id, root_path, document_root, linux_user, \
                    php_version, app_type, ssl_enabled, ssl_mode, ssl_cert_path, \
                    ssl_key_path, ssl_ca_path, ssl_updated_at, ssl_source_domain, \
                    status, nginx_custom, nginx_config_mode, nginx_rewrite_mode, \
                    waf_enabled, waf_default_rules, waf_custom_rules, crs_enabled, \
                    http_flood_enabled, http_flood_config, blocked_bots, app_id \
             FROM websites ORDER BY id ASC",
        )
        .fetch_all(self.pool)
        .await?)
    }

    /// Every website, ordered by domain.
    ///
    /// Source: `_select_scan_websites`'s
    /// `db.query(Website).order_by(Website.domain.asc())`. That order is
    /// not cosmetic: it reaches the scan job's `domains` list, which is
    /// what the page shows while the scan runs.
    pub async fn all_by_domain(&self) -> Result<Vec<Website>, DbError> {
        let sql = format!("SELECT {} FROM websites ORDER BY domain ASC", COLUMNS);
        Ok(sqlx::query_as::<_, Website>(&sql)
            .fetch_all(self.pool)
            .await?)
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
    /// Websites borrowing `source_domain`'s certificate.
    ///
    /// Source: `_shared_dependents`. A site that others borrow from cannot
    /// change its own certificate without breaking theirs, so this is what
    /// `_block_if_source` reads before allowing that.
    /// One website by its domain.
    ///
    /// Source: `db.query(Website).filter(Website.domain == ...)`. Domains are
    /// unique, so the first row is the row.
    pub async fn by_domain(&self, domain: &str) -> Result<Option<Website>, DbError> {
        Ok(sqlx::query_as::<_, Website>(&format!(
            "SELECT {COLUMNS} FROM websites WHERE domain = ?"
        ))
        .bind(domain)
        .fetch_optional(self.pool)
        .await?)
    }

    pub async fn shared_dependents(&self, source_domain: &str) -> Result<Vec<Website>, DbError> {
        Ok(sqlx::query_as::<_, Website>(&format!(
            "SELECT {COLUMNS} FROM websites \
             WHERE ssl_mode = 'shared' AND ssl_source_domain = ? ORDER BY domain"
        ))
        .bind(source_domain)
        .fetch_all(self.pool)
        .await?)
    }

    /// The whole SSL block of one row, written together.
    ///
    /// Source: the assignments in `install_shared_ssl` and its siblings. They
    /// move as a set - a row with `ssl_mode = "shared"` and no
    /// `ssl_source_domain` names a certificate that does not exist - so they
    /// are written in one statement rather than one column at a time.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_ssl_state(
        &self,
        id: i64,
        enabled: bool,
        mode: &str,
        source_domain: Option<&str>,
        cert_path: Option<&str>,
        key_path: Option<&str>,
        ca_path: Option<&str>,
        updated_at: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE websites SET ssl_enabled = ?, ssl_mode = ?, ssl_source_domain = ?, \
             ssl_cert_path = ?, ssl_key_path = ?, ssl_ca_path = ?, ssl_updated_at = ? \
             WHERE id = ?",
        )
        .bind(enabled)
        .bind(mode)
        .bind(source_domain)
        .bind(cert_path)
        .bind(key_path)
        .bind(ca_path)
        .bind(updated_at)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_ssl_enabled(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET ssl_enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `set_website_waf` - the column, after nginx has taken the change.
    ///
    /// The order is the Python's and it is deliberate: nginx is edited first
    /// and the column is only written if that succeeded. A database saying
    /// the WAF is on while the vhost does not is a panel claiming protection
    /// it is not providing.
    /// Source: `set_website_crs` - the per-site CRS opt-in, which is separate
    /// from `waf_enabled` because CRS is the one WAF feature with a memory
    /// bill and both switches have to agree before it loads.
    pub async fn set_crs_enabled(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET crs_enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `add_cron` adopting the derived runtime account.
    ///
    /// A site created before the panel wrote this column gets it filled in the
    /// first time a cron job is installed, so the job and the files agree
    /// about which account owns them.
    /// `website.status = "suspended"` / `"active"`.
    ///
    /// Suspending a customer marks every site they own, and the status is
    /// what the panel lists them by - so a vhost rewritten to serve nothing
    /// and a row still saying "active" would disagree in the direction that
    /// looks like a bug in the panel rather than a suspended account.
    pub async fn set_status(&self, id: i64, status: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET status = ? WHERE id = ?")
            .bind(status)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_linux_user(&self, id: i64, linux_user: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET linux_user = ? WHERE id = ?")
            .bind(linux_user)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_waf_enabled(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET waf_enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `set_website_http_flood`.
    pub async fn set_http_flood(
        &self,
        id: i64,
        enabled: bool,
        config_json: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE websites SET http_flood_enabled = ?, http_flood_config = ? WHERE id = ?",
        )
        .bind(enabled)
        .bind(config_json)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `set_website_nginx_custom`, which also sets the mode back to
    /// `managed` - saving a snippet through the panel is the panel taking the
    /// file back.
    /// Source: `save_website_config` - the two columns it sets, written
    /// together because a selection stored without its custom rules is a rule
    /// file the panel can no longer reproduce.
    pub async fn set_waf_rules(
        &self,
        id: i64,
        default_rules: &str,
        custom_rules: &str,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET waf_default_rules = ?, waf_custom_rules = ? WHERE id = ?")
            .bind(default_rules)
            .bind(custom_rules)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `reset_website_nginx_config` - `nginx_custom = ""` and
    /// `nginx_config_mode = "managed"`, set together.
    ///
    /// Together because they describe one state: a site whose mode says
    /// "managed" while the custom column still holds directives is a site the
    /// next render would put them back into.
    pub async fn reset_nginx_custom(&self, id: i64) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE websites SET nginx_custom = '', nginx_config_mode = 'managed' WHERE id = ?",
        )
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `save_website_blocked_bots` - the site's own list, newline
    /// separated, which is the shape `normalize_blocked_bots` reads back.
    pub async fn set_blocked_bots(&self, id: i64, bots: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET blocked_bots = ? WHERE id = ?")
            .bind(bots)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_nginx_custom(&self, id: i64, custom: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE websites SET nginx_custom = ?, nginx_config_mode = 'managed' WHERE id = ?",
        )
        .bind(custom)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// One alias, scoped to its website so an id belonging to another site
    /// cannot be reached by guessing.
    pub async fn alias_by_id(
        &self,
        website_id: i64,
        alias_id: i64,
    ) -> Result<Option<WebsiteAlias>, DbError> {
        Ok(sqlx::query_as::<_, WebsiteAlias>(
            "SELECT id, website_id, domain, mode, ssl_enabled, created_at \
             FROM website_aliases WHERE id = ? AND website_id = ?",
        )
        .bind(alias_id)
        .bind(website_id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Source: `create_website_alias`.
    pub async fn alias_create(
        &self,
        website_id: i64,
        domain: &str,
        mode: &str,
    ) -> Result<WebsiteAlias, DbError> {
        Ok(sqlx::query_as::<_, WebsiteAlias>(
            "INSERT INTO website_aliases (website_id, domain, mode, ssl_enabled, created_at) \
             VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP) \
             RETURNING id, website_id, domain, mode, ssl_enabled, created_at",
        )
        .bind(website_id)
        .bind(domain)
        .bind(mode)
        .fetch_one(self.pool)
        .await?)
    }

    /// Source: `delete_website_alias`. `false` means there was nothing to
    /// delete, which the caller turns into a 404 rather than a success.
    pub async fn alias_delete(&self, website_id: i64, alias_id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM website_aliases WHERE id = ? AND website_id = ?")
            .bind(alias_id)
            .bind(website_id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Source: `_sync_alias_ssl_flags` - whether the certificate that exists
    /// right now covers this alias.
    ///
    /// The column already existed and was never read or written anywhere,
    /// which is how a certbot run that silently dropped one requested name
    /// still showed "Added alias" with nothing wrong.
    pub async fn alias_set_ssl_enabled(&self, alias_id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE website_aliases SET ssl_enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(alias_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `_hostname_conflicts` over `_reserved_hostnames`.
    ///
    /// The reserved set is every website's domain *and* its `www.` form, plus
    /// every alias's domain. The question asked of it is whether either the
    /// candidate or its own `www.` form is in there - so `example.com`
    /// conflicts with an existing `www.example.com` and the other way round.
    /// Without both directions nginx ends up with two server blocks claiming
    /// one name and serves whichever it read first.
    ///
    /// The exclusions are for the update paths: a site keeping its own domain
    /// does not conflict with itself.
    pub async fn hostname_taken(
        &self,
        domain: &str,
        exclude_website_id: Option<i64>,
        exclude_alias_id: Option<i64>,
    ) -> Result<bool, DbError> {
        let candidate = domain.trim().to_ascii_lowercase();
        if candidate.is_empty() {
            // Source: `if not safe_domain: return True`.
            return Ok(true);
        }
        let with_www = format!("www.{candidate}");

        let sql = "SELECT \
             (SELECT COUNT(*) FROM websites \
               WHERE id IS NOT ? AND lower(trim(domain)) IN (?, ?)) \
           + (SELECT COUNT(*) FROM websites \
               WHERE id IS NOT ? AND 'www.' || lower(trim(domain)) IN (?, ?)) \
           + (SELECT COUNT(*) FROM website_aliases \
               WHERE id IS NOT ? AND lower(trim(domain)) IN (?, ?))";
        let count: i64 = sqlx::query_scalar(sql)
            .bind(exclude_website_id)
            .bind(&candidate)
            .bind(&with_www)
            .bind(exclude_website_id)
            .bind(&candidate)
            .bind(&with_www)
            .bind(exclude_alias_id)
            .bind(&candidate)
            .bind(&with_www)
            .fetch_one(self.pool)
            .await?;
        Ok(count > 0)
    }

    /// Every other site's domain, for deciding whether a certificate is still
    /// in use.
    ///
    /// Source: `release_site_certificates` - `db.query(Website.domain)` with
    /// `Website.id != exclude_website_id`.
    pub async fn domains_except(&self, exclude_id: i64) -> Result<Vec<String>, DbError> {
        Ok(
            sqlx::query_scalar::<_, String>("SELECT domain FROM websites WHERE id != ?")
                .bind(exclude_id)
                .fetch_all(self.pool)
                .await?,
        )
    }

    /// The same for aliases, excluding the deleted site's own.
    pub async fn alias_domains_except(&self, exclude_id: i64) -> Result<Vec<String>, DbError> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT domain FROM website_aliases WHERE website_id != ?",
        )
        .bind(exclude_id)
        .fetch_all(self.pool)
        .await?)
    }

    /// Source: `db.query(WebsiteAlias).filter(...).delete()`.
    pub async fn alias_delete_all(&self, website_id: i64) -> Result<u64, DbError> {
        let done = sqlx::query("DELETE FROM website_aliases WHERE website_id = ?")
            .bind(website_id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    /// Source: `db.delete(website)`.
    ///
    /// The aliases go first and separately: SQLite enforces foreign keys only
    /// when `PRAGMA foreign_keys` is on, so a cascade cannot be relied on to
    /// take them.
    pub async fn delete(&self, id: i64) -> Result<bool, DbError> {
        let done = sqlx::query("DELETE FROM websites WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Source: `db.query(Website).filter(Website.owner_id == owner.id,
    /// Website.id != website.id).count()`.
    ///
    /// Excluding one website, because moving a site to the owner it already
    /// has must not count that site against their own limit.
    pub async fn count_for_owner_excluding(
        &self,
        owner_id: i64,
        exclude_id: i64,
    ) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM websites WHERE owner_id = ? AND id != ?",
        )
        .bind(owner_id)
        .bind(exclude_id)
        .fetch_one(self.pool)
        .await?)
    }

    /// Source: `db.query(Website).filter(Website.owner_id == owner_id).count()`
    /// - the count a website limit is checked against.
    pub async fn count_for_owner(&self, owner_id: i64) -> Result<i64, DbError> {
        Ok(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM websites WHERE owner_id = ?")
                .bind(owner_id)
                .fetch_one(self.pool)
                .await?,
        )
    }

    /// Source: `db.add(Website(...))` in `create_website`.
    ///
    /// Every column the Python sets, in one statement, and the new row's id
    /// back.
    ///
    /// **`waf_enabled` and `created_at` are written although `create_website`
    /// never mentions them.** SQLAlchemy applies the *model's* defaults on
    /// insert, and two of them disagree with the column defaults this table
    /// was created with:
    ///
    /// - `waf_enabled` is `default=True` on the model and `DEFAULT 0` on the
    ///   column. A raw insert that left it out would create every new site
    ///   with its firewall **off**, and nothing in the panel would say so -
    ///   the toggle would simply read as off on a page nobody opens until
    ///   something goes wrong;
    /// - `created_at` is `default=datetime.utcnow` and the column is
    ///   nullable, so a row without it sorts to one end of every listing that
    ///   orders by it.
    ///
    /// The rest of the model defaults happen to match their columns. That is
    /// luck, not design, so this list is the full set the Python writes rather
    /// than the set that currently differs.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(&self, new: &NewWebsite<'_>) -> Result<i64, DbError> {
        let id = sqlx::query(
            "INSERT INTO websites (domain, owner_id, root_path, document_root, linux_user, \
             php_version, app_type, nginx_rewrite_mode, app_id, status, waf_enabled, \
             created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(new.domain)
        .bind(new.owner_id)
        .bind(new.root_path)
        .bind(new.document_root)
        .bind(new.linux_user)
        .bind(new.php_version)
        .bind(new.app_type)
        .bind(new.nginx_rewrite_mode)
        .bind(new.app_id)
        .bind(new.status)
        .bind(new.waf_enabled)
        .bind(new.created_at)
        .execute(self.pool)
        .await?
        .last_insert_rowid();
        Ok(id)
    }

    /// Source: the three assignments after `install_wordpress_on_website`
    /// succeeds — `root_path`, `app_type` and `nginx_rewrite_mode`.
    ///
    /// They move together: a row saying `app_type = "wordpress"` with a
    /// rewrite mode of `none` would be served without a front controller, so
    /// every permalink but the home page would 404.
    pub async fn set_wordpress_installed(&self, id: i64, root_path: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE websites SET root_path = ?, app_type = 'wordpress', \
             nginx_rewrite_mode = 'front_controller' WHERE id = ?",
        )
        .bind(root_path)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `website.php_version = payload.php_version`.
    pub async fn set_php_version(&self, id: i64, php_version: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET php_version = ? WHERE id = ?")
            .bind(php_version)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: the three assignments in the `app_type` branch.
    ///
    /// They move together because the rewrite mode is derived from the type
    /// and `app_id` is only meaningful for a proxied one: a row with
    /// `app_type = "static"` and an `app_id` still set names an application
    /// nothing will ever proxy to.
    pub async fn set_app_mode(
        &self,
        id: i64,
        app_type: &str,
        rewrite_mode: &str,
        app_id: Option<i64>,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE websites SET app_type = ?, nginx_rewrite_mode = ?, app_id = ? WHERE id = ?",
        )
        .bind(app_type)
        .bind(rewrite_mode)
        .bind(app_id)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `website.app_id = next_app.id` on the same-mode branch.
    pub async fn set_app_id(&self, id: i64, app_id: Option<i64>) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET app_id = ? WHERE id = ?")
            .bind(app_id)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `website.document_root = next_document_root`.
    pub async fn set_document_root(&self, id: i64, document_root: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET document_root = ? WHERE id = ?")
            .bind(document_root)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: the owner-change branch — `root_path`, `linux_user` and
    /// `owner_id`.
    ///
    /// All three or none: the files have just been moved, and a row that kept
    /// the old `root_path` would point the vhost at a directory that is no
    /// longer there.
    pub async fn set_owner(
        &self,
        id: i64,
        owner_id: i64,
        root_path: &str,
        linux_user: &str,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET owner_id = ?, root_path = ?, linux_user = ? WHERE id = ?")
            .bind(owner_id)
            .bind(root_path)
            .bind(linux_user)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `website.owner_id = payload.owner_id` when the owner did not
    /// actually change — the Python assigns it either way, and the files are
    /// not moved.
    pub async fn set_owner_id(&self, id: i64, owner_id: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET owner_id = ? WHERE id = ?")
            .bind(owner_id)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `website.nginx_config_mode = "managed"` on its own, which is
    /// what the whole-fleet refresh commits when it finds a vhost the panel
    /// had stopped managing.
    ///
    /// **Only the one column.** The refresh does not change the rewrite
    /// mode, and a setter that quietly reset it while marking the file
    /// managed would be precisely the bug the sweep exists to avoid.
    pub async fn set_config_mode_managed(&self, id: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET nginx_config_mode = 'managed' WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `website.nginx_rewrite_mode = next_rewrite_mode;
    /// website.nginx_config_mode = "managed"`.
    ///
    /// Changing the rewrite through the panel is the panel taking the file
    /// back, which is what `nginx_config_mode` records.
    pub async fn set_rewrite_mode(&self, id: i64, rewrite_mode: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE websites SET nginx_rewrite_mode = ?, nginx_config_mode = 'managed' \
             WHERE id = ?",
        )
        .bind(rewrite_mode)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Source: `website.http_flood_enabled = next_enabled`, which the Python
    /// assigns **before** it writes the zones — the zone file is built from
    /// the rows, so the row has to say what it wants first.
    pub async fn set_http_flood_enabled(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        sqlx::query("UPDATE websites SET http_flood_enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

/// Every column `create_website` writes.
///
/// A struct rather than eleven positional arguments, because `domain`,
/// `root_path`, `document_root`, `linux_user`, `php_version`, `app_type`,
/// `nginx_rewrite_mode` and `status` are all `&str` and a call that swapped
/// two of them would compile.
pub struct NewWebsite<'a> {
    pub domain: &'a str,
    pub owner_id: i64,
    pub root_path: &'a str,
    pub document_root: &'a str,
    pub linux_user: Option<&'a str>,
    pub php_version: &'a str,
    pub app_type: &'a str,
    pub nginx_rewrite_mode: &'a str,
    pub app_id: Option<i64>,
    pub status: &'a str,
    /// The model's default, which is **not** the column's. See [`create`].
    pub waf_enabled: bool,
    pub created_at: &'a str,
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

    /// **The sweep walks them oldest first, the opposite of the listing.**
    ///
    /// Two orders for two jobs, asserted next to each other because the
    /// failure mode is somebody tidying one into the other. On a clean
    /// whole-fleet refresh the order changes nothing; on the strict one,
    /// which stops at its first failure, it decides which sites were already
    /// refreshed when it stopped — and that has to be the set the Python
    /// would have refreshed, which is rowid order.
    #[tokio::test]
    async fn the_sweep_walks_oldest_first() {
        let pool = scratch().await;
        let ids: Vec<i64> = WebsiteRepo::new(&pool)
            .all_by_id()
            .await
            .unwrap()
            .into_iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(ids, vec![1, 2, 3]);
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

    // --- the write methods Stage C added ---------------------------------

    #[tokio::test]
    async fn a_hostname_conflicts_in_both_directions() {
        // Source: `_hostname_conflicts` over `_reserved_hostnames`. The
        // reserved set holds every website's domain *and* its `www.` form, and
        // the question asked is whether the candidate **or its own `www.`
        // form** is in there. Both directions, which is what stops nginx
        // ending up with two server blocks claiming one name.
        let pool = scratch().await;
        let repo = WebsiteRepo::new(&pool);

        assert!(repo
            .hostname_taken("first.example.com", None, None)
            .await
            .unwrap());
        assert!(
            repo.hostname_taken("www.first.example.com", None, None)
                .await
                .unwrap(),
            "the www form of an existing domain is reserved"
        );
        assert!(
            !repo
                .hostname_taken("unused.example.com", None, None)
                .await
                .unwrap(),
            "a name nothing serves is free"
        );
        assert!(
            repo.hostname_taken("", None, None).await.unwrap(),
            "an empty name conflicts, the way the Python returns True for it"
        );
    }

    #[tokio::test]
    async fn an_alias_reserves_its_name_too() {
        let pool = scratch().await;
        let repo = WebsiteRepo::new(&pool);
        repo.alias_create(1, "shop.example.com", "alias")
            .await
            .unwrap();

        assert!(repo
            .hostname_taken("shop.example.com", None, None)
            .await
            .unwrap());
        // `www.shop.example.com` is not in the reserved set - only websites
        // contribute their www form - but asking about `shop.example.com`
        // while holding `www.shop...` would find it. This pins the asymmetry
        // rather than assuming it away.
        assert!(
            !repo
                .hostname_taken("www.shop.example.com", None, None)
                .await
                .unwrap(),
            "an alias does not reserve its own www form; only a website does"
        );
    }

    #[tokio::test]
    async fn a_site_keeping_its_own_name_does_not_conflict_with_itself() {
        let pool = scratch().await;
        let repo = WebsiteRepo::new(&pool);
        assert!(repo
            .hostname_taken("first.example.com", None, None)
            .await
            .unwrap());
        assert!(
            !repo
                .hostname_taken("first.example.com", Some(1), None)
                .await
                .unwrap(),
            "excluding the site that owns the name is what makes an update possible"
        );
    }

    #[tokio::test]
    async fn an_alias_round_trips_and_is_scoped_to_its_website() {
        let pool = scratch().await;
        let repo = WebsiteRepo::new(&pool);
        let created = repo
            .alias_create(1, "alias.example.com", "redirect")
            .await
            .unwrap();
        assert_eq!(created.domain, "alias.example.com");
        assert_eq!(created.mode, "redirect");
        assert_eq!(created.website_id, 1);

        assert!(repo.alias_by_id(1, created.id).await.unwrap().is_some());
        assert!(
            repo.alias_by_id(2, created.id).await.unwrap().is_none(),
            "an id belonging to another site must not be reachable by guessing"
        );
        assert!(
            !repo.alias_delete(2, created.id).await.unwrap(),
            "and neither must it be deletable"
        );
        assert!(repo.alias_delete(1, created.id).await.unwrap());
        assert!(
            !repo.alias_delete(1, created.id).await.unwrap(),
            "a second delete reports nothing to delete, which the caller turns into a 404"
        );
    }

    #[tokio::test]
    async fn the_column_writes_land() {
        let pool = scratch().await;
        let repo = WebsiteRepo::new(&pool);

        repo.set_waf_enabled(1, false).await.unwrap();
        repo.set_http_flood(1, true, r#"{"connection_limit":7}"#)
            .await
            .unwrap();
        repo.set_nginx_custom(1, "gzip on;").await.unwrap();

        let site = repo.by_id(1).await.unwrap().expect("the site");
        assert!(!site.waf_enabled);
        assert!(site.http_flood_enabled);
        assert_eq!(site.http_flood_config, r#"{"connection_limit":7}"#);
        assert_eq!(site.nginx_custom, "gzip on;");
        assert_eq!(
            site.nginx_config_mode, "managed",
            "saving a snippet through the panel is the panel taking the file back"
        );
    }
}

/// Every field a user-backup restore writes onto a site.
///
/// The restore is the one caller that sets all of these at once: the row is
/// being rebuilt from an archive rather than edited, so a partial write would
/// leave a site half from the backup and half from whatever was there before.
#[derive(Debug, Clone)]
pub struct RestoredWebsite<'a> {
    pub domain: &'a str,
    pub owner_id: i64,
    pub root_path: &'a str,
    pub document_root: &'a str,
    pub linux_user: &'a str,
    pub php_version: &'a str,
    pub app_type: &'a str,
    pub status: &'a str,
    pub nginx_custom: &'a str,
    pub nginx_rewrite_mode: &'a str,
    pub waf_enabled: bool,
    pub waf_default_rules: &'a str,
    pub waf_custom_rules: &'a str,
    pub http_flood_enabled: bool,
    pub http_flood_config: &'a str,
    pub created_at: &'a str,
}

impl<'a> WebsiteRepo<'a> {
    /// Source: the `if website is None: ... else: ...` pair in
    /// `restore_user_backup`.
    ///
    /// Returns the row's id and whether it had to be created, which is what
    /// the endpoint reports back per site.
    pub async fn restore_write(&self, site: &RestoredWebsite<'_>) -> Result<(i64, bool), DbError> {
        if let Some(existing) = self.by_domain(site.domain).await? {
            sqlx::query(
                "UPDATE websites SET owner_id = ?, root_path = ?, document_root = ?, \
                    linux_user = ?, php_version = ?, app_type = ?, status = ?, \
                    nginx_custom = ?, nginx_config_mode = 'managed', \
                    nginx_rewrite_mode = ?, waf_enabled = ?, waf_default_rules = ?, \
                    waf_custom_rules = ?, http_flood_enabled = ?, http_flood_config = ? \
                 WHERE id = ?",
            )
            .bind(site.owner_id)
            .bind(site.root_path)
            .bind(site.document_root)
            .bind(site.linux_user)
            .bind(site.php_version)
            .bind(site.app_type)
            .bind(site.status)
            .bind(site.nginx_custom)
            .bind(site.nginx_rewrite_mode)
            .bind(site.waf_enabled)
            .bind(site.waf_default_rules)
            .bind(site.waf_custom_rules)
            .bind(site.http_flood_enabled)
            .bind(site.http_flood_config)
            .bind(existing.id)
            .execute(self.pool)
            .await?;
            return Ok((existing.id, false));
        }
        // `ssl_enabled=False` on a new row: the certificate is not in the
        // archive, and a site claiming TLS it has no key for does not start.
        let id = sqlx::query(
            "INSERT INTO websites (domain, owner_id, root_path, document_root, linux_user, \
                php_version, app_type, ssl_enabled, status, nginx_custom, nginx_config_mode, \
                nginx_rewrite_mode, waf_enabled, waf_default_rules, waf_custom_rules, \
                http_flood_enabled, http_flood_config, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'managed', ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(site.domain)
        .bind(site.owner_id)
        .bind(site.root_path)
        .bind(site.document_root)
        .bind(site.linux_user)
        .bind(site.php_version)
        .bind(site.app_type)
        .bind(site.status)
        .bind(site.nginx_custom)
        .bind(site.nginx_rewrite_mode)
        .bind(site.waf_enabled)
        .bind(site.waf_default_rules)
        .bind(site.waf_custom_rules)
        .bind(site.http_flood_enabled)
        .bind(site.http_flood_config)
        .bind(site.created_at)
        .execute(self.pool)
        .await?
        .last_insert_rowid();
        Ok((id, true))
    }

    /// Every alias in the table, with the site it belongs to.
    ///
    /// Source: `db.query(WebsiteAlias).all()` inside `_hostname_conflicts`,
    /// which excludes by **website** id rather than by alias id — so the
    /// existing `hostname_taken` cannot answer this question.
    pub async fn all_aliases(&self) -> Result<Vec<(i64, String)>, DbError> {
        Ok(
            sqlx::query_as::<_, (i64, String)>("SELECT website_id, domain FROM website_aliases")
                .fetch_all(self.pool)
                .await?,
        )
    }

    /// Every site's id and domain, for the same question.
    pub async fn all_domains(&self) -> Result<Vec<(i64, String)>, DbError> {
        Ok(
            sqlx::query_as::<_, (i64, String)>("SELECT id, domain FROM websites")
                .fetch_all(self.pool)
                .await?,
        )
    }
}
