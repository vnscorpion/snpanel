//! `site_apps` - the applications the panel runs for a customer.
//!
//! Source: `models.entities.SiteApp`. Only the columns the ported callers read
//! are here; the table is wider, and the rest arrives when the Application
//! router is ported.

use crate::DbError;
use sqlx::SqlitePool;

/// One row of `site_apps`, with its owner's panel account name folded in.
///
/// The name comes from the join because `site_apps.owner_linux_user` is what
/// every helper call needs and the Python derives it the same way - through
/// `app.owner.username`, not from a column on the app.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteAppRow {
    pub id: i64,
    pub name: String,
    pub owner_id: i64,
    /// `NULL` when the owner row is gone. The Python then raises
    /// "This application has no owner, so it cannot be run".
    pub owner_username: Option<String>,
}

/// The fields a website needs from an application it is pointed at.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteAppTarget {
    pub id: i64,
    pub name: String,
    pub owner_id: i64,
    pub port: i64,
}

pub struct SiteAppRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> SiteAppRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Source: `db.query(SiteApp).filter(SiteApp.id == app_id).first()`.
    ///
    /// Carries the port, which is the only field a website needs from it: the
    /// vhost proxies to `127.0.0.1:<port>`.
    pub async fn by_id(&self, id: i64) -> Result<Option<SiteAppTarget>, DbError> {
        Ok(sqlx::query_as::<_, SiteAppTarget>(
            "SELECT id, name, owner_id, port FROM site_apps WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?)
    }

    /// Source: `db.query(SiteApp).filter(SiteApp.owner_id == user.id).all()`.
    pub async fn by_owner(&self, owner_id: i64) -> Result<Vec<SiteAppRow>, DbError> {
        Ok(sqlx::query_as::<_, SiteAppRow>(
            "SELECT site_apps.id AS id, site_apps.name AS name, \
                    site_apps.owner_id AS owner_id, users.username AS owner_username \
             FROM site_apps LEFT JOIN users ON users.id = site_apps.owner_id \
             WHERE site_apps.owner_id = ? ORDER BY site_apps.id",
        )
        .bind(owner_id)
        .fetch_all(self.pool)
        .await?)
    }

    /// Source: `db.query(SiteApp).all()`.
    ///
    /// The Python does not order, and SQLite hands back rowid order for a
    /// plain scan. `ORDER BY id` says so rather than relying on it: the only
    /// caller reports the apps it stopped, and a list that reshuffles between
    /// two identical requests is a difference a customer can see.
    pub async fn all(&self) -> Result<Vec<SiteAppRow>, DbError> {
        Ok(sqlx::query_as::<_, SiteAppRow>(
            "SELECT site_apps.id AS id, site_apps.name AS name, \
                    site_apps.owner_id AS owner_id, users.username AS owner_username \
             FROM site_apps LEFT JOIN users ON users.id = site_apps.owner_id \
             ORDER BY site_apps.id",
        )
        .fetch_all(self.pool)
        .await?)
    }
}

/// Every column of `site_apps`, plus the two things the Python reaches
/// through a relationship: the owner's account name, and the domains pointed
/// at this app.
///
/// The owner's name comes from the join because the helper needs it for every
/// call and the Python derives it the same way — through `app.owner.username`,
/// not from a column on the app.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteApp {
    pub id: i64,
    pub owner_id: i64,
    pub name: String,
    pub kind: String,
    pub start_kind: Option<String>,
    pub start_arg: Option<String>,
    pub node_major: Option<String>,
    pub image: Option<String>,
    pub container_port: i64,
    pub cpu_limit: String,
    pub env: String,
    pub compose_source: String,
    pub web_service: Option<String>,
    pub port: i64,
    pub memory_limit_mb: i64,
    pub autostart: bool,
    pub status: String,
    pub last_error: String,
    pub created_at: Option<String>,
    /// `NULL` when the owner row is gone. The Python then raises
    /// "This application has no owner, so it cannot be run".
    pub owner_username: Option<String>,
    /// Not a column: filled in by the repo, because `app.websites` is a
    /// relationship and three callers read it.
    #[sqlx(skip)]
    pub websites: Vec<String>,
}

/// What a write refused because a column already holds that value.
///
/// The table carries two: `port` on its own, and `(owner_id, name)` together.
/// The Python catches `IntegrityError` around each write and answers 409 with
/// a different sentence for each caller, so which one fired does not need to
/// be told apart — only that one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duplicate;

/// The fields a new row is written from. Everything the caller does not set
/// takes the column default, as it does when SQLAlchemy builds the object.
#[derive(Debug, Clone, Default)]
pub struct NewSiteApp {
    pub owner_id: i64,
    pub name: String,
    pub kind: String,
    pub start_kind: Option<String>,
    pub start_arg: Option<String>,
    pub node_major: Option<String>,
    pub image: Option<String>,
    pub container_port: i64,
    pub cpu_limit: String,
    pub env: String,
    pub compose_source: String,
    pub web_service: Option<String>,
    pub port: i64,
    pub memory_limit_mb: i64,
    pub autostart: bool,
    /// Written by the caller, as every other table here has it: the value is
    /// `datetime.utcnow()` and the column keeps it as text.
    pub created_at: String,
}

const COLUMNS: &str = "site_apps.id AS id, site_apps.owner_id AS owner_id, \
     site_apps.name AS name, site_apps.kind AS kind, \
     site_apps.start_kind AS start_kind, site_apps.start_arg AS start_arg, \
     site_apps.node_major AS node_major, site_apps.image AS image, \
     site_apps.container_port AS container_port, site_apps.cpu_limit AS cpu_limit, \
     site_apps.env AS env, site_apps.compose_source AS compose_source, \
     site_apps.web_service AS web_service, site_apps.port AS port, \
     site_apps.memory_limit_mb AS memory_limit_mb, site_apps.autostart AS autostart, \
     site_apps.status AS status, site_apps.last_error AS last_error, \
     site_apps.created_at AS created_at, users.username AS owner_username";

impl<'a> SiteAppRepo<'a> {
    /// One app with everything on it, including the domains it serves.
    pub async fn full_by_id(&self, id: i64) -> Result<Option<SiteApp>, DbError> {
        let row = sqlx::query_as::<_, SiteApp>(&format!(
            "SELECT {COLUMNS} FROM site_apps \
             LEFT JOIN users ON users.id = site_apps.owner_id WHERE site_apps.id = ?"
        ))
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        match row {
            Some(mut app) => {
                app.websites = self.domains_for(app.id).await?;
                Ok(Some(app))
            }
            None => Ok(None),
        }
    }

    /// Every app, or every app of one owner, in id order.
    pub async fn full_list(&self, owner_id: Option<i64>) -> Result<Vec<SiteApp>, DbError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM site_apps \
             LEFT JOIN users ON users.id = site_apps.owner_id {} \
             ORDER BY site_apps.id",
            match owner_id {
                Some(_) => "WHERE site_apps.owner_id = ?",
                None => "",
            }
        );
        let query = sqlx::query_as::<_, SiteApp>(&sql);
        let mut apps = match owner_id {
            Some(id) => query.bind(id).fetch_all(self.pool).await?,
            None => query.fetch_all(self.pool).await?,
        };
        for app in &mut apps {
            app.websites = self.domains_for(app.id).await?;
        }
        Ok(apps)
    }

    /// `app.websites` — every domain nginx proxies to this app.
    pub async fn domains_for(&self, app_id: i64) -> Result<Vec<String>, DbError> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT domain FROM websites WHERE app_id = ? ORDER BY id")
                .bind(app_id)
                .fetch_all(self.pool)
                .await?;
        Ok(rows.into_iter().map(|(domain,)| domain).collect())
    }

    /// Source: `db.query(SiteApp).filter(SiteApp.owner_id == owner_id).count()`.
    pub async fn count_for_owner(&self, owner_id: i64) -> Result<i64, DbError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM site_apps WHERE owner_id = ?")
            .bind(owner_id)
            .fetch_one(self.pool)
            .await?;
        Ok(count)
    }

    /// Source: `reserved_ports` — every port already spoken for, less the app
    /// being edited, whose own port is not a clash with itself.
    pub async fn reserved_ports(&self, exclude_app_id: Option<i64>) -> Result<Vec<i64>, DbError> {
        let rows: Vec<(Option<i64>,)> = match exclude_app_id {
            Some(id) => {
                sqlx::query_as("SELECT port FROM site_apps WHERE id != ?")
                    .bind(id)
                    .fetch_all(self.pool)
                    .await?
            }
            None => {
                sqlx::query_as("SELECT port FROM site_apps")
                    .fetch_all(self.pool)
                    .await?
            }
        };
        // `{row for row in db.scalars(query) if row}` — a zero or a NULL is
        // not a reservation.
        Ok(rows
            .into_iter()
            .filter_map(|(port,)| port)
            .filter(|port| *port != 0)
            .collect())
    }

    /// Source: `db.add(app); db.commit()`. Returns the new id, or `Duplicate`
    /// when the name or the port is already taken.
    pub async fn create(&self, app: &NewSiteApp) -> Result<Result<i64, Duplicate>, DbError> {
        let result = sqlx::query(
            "INSERT INTO site_apps (owner_id, name, kind, start_kind, start_arg, node_major, \
                image, container_port, cpu_limit, env, compose_source, web_service, port, \
                memory_limit_mb, autostart, status, last_error, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'stopped', '', ?)",
        )
        .bind(app.owner_id)
        .bind(&app.name)
        .bind(&app.kind)
        .bind(&app.start_kind)
        .bind(&app.start_arg)
        .bind(&app.node_major)
        .bind(&app.image)
        .bind(app.container_port)
        .bind(&app.cpu_limit)
        .bind(&app.env)
        .bind(&app.compose_source)
        .bind(&app.web_service)
        .bind(app.port)
        .bind(app.memory_limit_mb)
        .bind(app.autostart)
        .bind(&app.created_at)
        .execute(self.pool)
        .await;
        match result {
            Ok(done) => Ok(Ok(done.last_insert_rowid())),
            Err(err) if is_unique_violation(&err) => Ok(Err(Duplicate)),
            Err(err) => Err(err.into()),
        }
    }

    /// Write back every field the two editing endpoints can change.
    pub async fn save(&self, app: &SiteApp) -> Result<Result<(), Duplicate>, DbError> {
        let result = sqlx::query(
            "UPDATE site_apps SET name = ?, kind = ?, start_kind = ?, start_arg = ?, \
                node_major = ?, image = ?, container_port = ?, cpu_limit = ?, env = ?, \
                compose_source = ?, web_service = ?, port = ?, memory_limit_mb = ?, \
                autostart = ?, status = ?, last_error = ? WHERE id = ?",
        )
        .bind(&app.name)
        .bind(&app.kind)
        .bind(&app.start_kind)
        .bind(&app.start_arg)
        .bind(&app.node_major)
        .bind(&app.image)
        .bind(app.container_port)
        .bind(&app.cpu_limit)
        .bind(&app.env)
        .bind(&app.compose_source)
        .bind(&app.web_service)
        .bind(app.port)
        .bind(app.memory_limit_mb)
        .bind(app.autostart)
        .bind(&app.status)
        .bind(&app.last_error)
        .bind(app.id)
        .execute(self.pool)
        .await;
        match result {
            Ok(_) => Ok(Ok(())),
            Err(err) if is_unique_violation(&err) => Ok(Err(Duplicate)),
            Err(err) => Err(err.into()),
        }
    }

    /// `_record_status`: the status and the last error, and nothing else.
    pub async fn set_status(&self, id: i64, status: &str, error: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE site_apps SET status = ?, last_error = ? WHERE id = ?")
            .bind(status)
            .bind(error)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Source: `db.delete(app); db.commit()`.
    pub async fn delete(&self, id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM site_apps WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

/// The two unique constraints on this table both arrive as the same SQLite
/// error, which is all the caller needs to know.
fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => db
            .code()
            .map(|code| code == "2067" || code == "1555" || code == "19")
            .unwrap_or(false),
        _ => false,
    }
}
