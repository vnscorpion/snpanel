//! What schema this build expects, and what the database actually has.
//!
//! Contract C11 gives Alembic the schema while Python is alive, and nothing
//! here migrates a Python revision. What it does is **notice**: a panel
//! running against a schema that is not the one it was built for should say
//! so at startup, where somebody is watching, rather than failing on a
//! missing column at request time — which is how a customer finds it, on the
//! one page they needed.
//!
//! The mechanism for Rust-owned migrations is here too, with an empty list.
//! Contract C12 requires the first of them to be a no-op on an existing
//! database, and an empty list is the only version of that which cannot be
//! wrong. When the schema moves to this side, migrations are appended to
//! [`RUST_MIGRATIONS`] and the runner below applies the ones a database has
//! not seen.

use super::DbError;

/// The Alembic revision this build was written against.
///
/// Read from the chain rather than assumed to be the highest filename: the
/// head is the revision with no child, which a branch or a gap would move.
/// Checked at the time of writing to be one linear chain of 31, rooted at
/// `0001_initial`.
pub const PYTHON_HEAD: &str = "0031_website_crs_enabled";

/// What the database had to say about its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaState {
    /// Exactly the revision this build expects.
    AtExpectedHead,
    /// Stamped, but not with the revision this build expects.
    ///
    /// Carries what was found. This is the ordinary shape of an update in
    /// progress — Python migrates when it starts, and the two processes do
    /// not start together.
    OtherRevision(String),
    /// No `alembic_version` row.
    ///
    /// A database that was created but never stamped, which is the legacy
    /// case `run_migrations` handles by stamping `0001_initial` and
    /// upgrading.
    Unstamped,
    /// No `alembic_version` table at all.
    NotManaged,
}

impl SchemaState {
    /// Whether this is worth saying out loud at startup.
    pub fn is_expected(&self) -> bool {
        *self == SchemaState::AtExpectedHead
    }

    /// The line to log.
    ///
    /// Each one names what was found *and* what to do about it. "Schema
    /// mismatch" on its own sends an operator to the wrong place: in every
    /// case here the fix is Python's, because Python still owns the schema.
    pub fn message(&self) -> Option<String> {
        match self {
            Self::AtExpectedHead => None,
            Self::OtherRevision(found) => Some(format!(
                "the database is at Alembic revision {found}, and this build expects \
                 {PYTHON_HEAD}; Python migrates on its next start, and until it does a \
                 column this build uses may not be there"
            )),
            Self::Unstamped => Some(format!(
                "the database has no Alembic revision recorded, and this build expects \
                 {PYTHON_HEAD}; Python stamps and upgrades it on its next start"
            )),
            Self::NotManaged => Some(format!(
                "the database has no alembic_version table, so nothing has ever migrated \
                 it; this build expects {PYTHON_HEAD}"
            )),
        }
    }
}

/// Migrations this side owns.
///
/// Empty, and that is contract C12 rather than an omission: the first Rust
/// migration has to be a no-op on every existing database, and no migration
/// at all is the only version of that which cannot be got wrong. Python
/// owns the schema until the cutover.
///
/// Each entry is `(name, sql)`. The name is recorded so a migration runs
/// once; the SQL has to be safe to run against a database at
/// [`PYTHON_HEAD`].
pub const RUST_MIGRATIONS: &[(&str, &str)] = &[];

/// Where applied Rust migrations are recorded.
///
/// A table of this side's own rather than a row in `alembic_version`:
/// writing into Alembic's table would make Alembic's own `upgrade` disagree
/// with it, and while both sides are alive that is a fight neither wins.
pub const MIGRATIONS_TABLE: &str = "snpanel_rust_migrations";

impl super::Database {
    /// What revision the database is at.
    pub async fn schema_state(&self) -> Result<SchemaState, DbError> {
        let managed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'alembic_version'",
        )
        .fetch_one(self.pool())
        .await?;
        if managed == 0 {
            return Ok(SchemaState::NotManaged);
        }

        let revision: Option<String> =
            sqlx::query_scalar("SELECT version_num FROM alembic_version LIMIT 1")
                .fetch_optional(self.pool())
                .await?;
        Ok(match revision {
            Some(found) if found == PYTHON_HEAD => SchemaState::AtExpectedHead,
            Some(found) => SchemaState::OtherRevision(found),
            None => SchemaState::Unstamped,
        })
    }

    /// Apply any Rust-owned migration this database has not seen.
    ///
    /// Returns the names applied. With [`RUST_MIGRATIONS`] empty this makes
    /// the bookkeeping table and does nothing else, which is the point: the
    /// mechanism is exercised by every start long before it first has to
    /// carry a real migration.
    pub async fn apply_rust_migrations(&self) -> Result<Vec<String>, DbError> {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {MIGRATIONS_TABLE} (\
                name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        ))
        .execute(self.pool())
        .await?;

        let mut applied = Vec::new();
        for (name, sql) in RUST_MIGRATIONS {
            let seen: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {MIGRATIONS_TABLE} WHERE name = ?"
            ))
            .bind(name)
            .fetch_one(self.pool())
            .await?;
            if seen > 0 {
                continue;
            }
            sqlx::query(sql).execute(self.pool()).await?;
            sqlx::query(&format!(
                "INSERT INTO {MIGRATIONS_TABLE} (name, applied_at) VALUES (?, datetime('now'))"
            ))
            .bind(name)
            .execute(self.pool())
            .await?;
            applied.push((*name).to_string());
        }
        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn stamped(revision: Option<&str>) -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        if let Some(revision) = revision {
            sqlx::query("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
                .execute(&pool)
                .await
                .unwrap();
            if !revision.is_empty() {
                sqlx::query("INSERT INTO alembic_version (version_num) VALUES (?)")
                    .bind(revision)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        }
        pool
    }

    async fn state(pool: &SqlitePool) -> SchemaState {
        let db = super::super::Database::from_pool(pool.clone());
        db.schema_state().await.unwrap()
    }

    /// **`PYTHON_HEAD` is still Alembic's head.**
    ///
    /// The constant goes stale the moment somebody adds `0032`, and the
    /// symptom is the opposite of useful: the panel would warn on every
    /// correctly-migrated box and say nothing about the one that was
    /// actually behind. So the chain is read here rather than trusted.
    ///
    /// The head is the revision no other revision points at — not the
    /// highest filename, which a branch or a renumbering would move.
    #[test]
    fn the_expected_head_is_the_head_of_the_chain() {
        let versions =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../backend/alembic/versions");
        let Ok(entries) = std::fs::read_dir(&versions) else {
            // A checkout without the Python tree still builds; there is
            // nothing to compare against and nothing to claim.
            eprintln!("skipped: {} is not there", versions.display());
            return;
        };

        let mut revisions: std::collections::BTreeMap<String, Option<String>> =
            std::collections::BTreeMap::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("py") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(revision) = assignment(&text, "revision") {
                let down = assignment(&text, "down_revision");
                revisions.insert(revision, down);
            }
        }
        assert!(
            revisions.len() >= 30,
            "only found {} revisions; the parse is wrong, not the chain",
            revisions.len()
        );

        let children: std::collections::BTreeSet<&str> =
            revisions.values().filter_map(|d| d.as_deref()).collect();
        let heads: Vec<&str> = revisions
            .keys()
            .map(String::as_str)
            .filter(|r| !children.contains(r))
            .collect();

        assert_eq!(
            heads,
            [PYTHON_HEAD],
            "PYTHON_HEAD is not the head of the Alembic chain"
        );
    }

    /// The quoted value of a module-level assignment.
    ///
    /// `revision: str = "0031_..."`, `down_revision: Union[str, None] = None`.
    /// Anchored at the start of the line and matched up to the `=`, so
    /// `down_revision` is never read as `revision` — which a substring
    /// search would do, and which would make every revision its own parent.
    fn assignment(text: &str, name: &str) -> Option<String> {
        for line in text.lines() {
            let Some(rest) = line.strip_prefix(name) else {
                continue;
            };
            let Some((annotation, after)) = rest.split_once('=') else {
                continue;
            };
            // What sits between the name and the `=` may only be a type
            // annotation; anything else means this was a longer name.
            if !annotation.trim_start().is_empty() && !annotation.trim_start().starts_with(':') {
                continue;
            }
            let after = after.trim();
            if after.starts_with("None") {
                return None;
            }
            let quote = after.chars().next()?;
            if quote != '"' && quote != '\'' {
                continue;
            }
            return after[1..].split(quote).next().map(str::to_string);
        }
        None
    }

    /// The ordinary case: nothing to say.
    #[tokio::test]
    async fn a_database_at_the_expected_head_is_silent() {
        let pool = stamped(Some(PYTHON_HEAD)).await;
        let found = state(&pool).await;
        assert_eq!(found, SchemaState::AtExpectedHead);
        assert!(found.is_expected());
        assert_eq!(found.message(), None);
    }

    /// Each of the three unhappy shapes is distinguishable, because they
    /// call for different things: a box mid-update, a legacy database, and
    /// one nothing has ever migrated.
    #[tokio::test]
    async fn the_three_unhappy_states_are_told_apart() {
        let behind = state(&stamped(Some("0030_user_terminal_enabled")).await).await;
        assert_eq!(
            behind,
            SchemaState::OtherRevision("0030_user_terminal_enabled".into())
        );

        let unstamped = state(&stamped(Some("")).await).await;
        assert_eq!(unstamped, SchemaState::Unstamped);

        let unmanaged = state(&stamped(None).await).await;
        assert_eq!(unmanaged, SchemaState::NotManaged);

        for s in [&behind, &unstamped, &unmanaged] {
            assert!(!s.is_expected());
            let message = s.message().expect("a message");
            // Every one names the revision this build wants, which is the
            // fact an operator needs and cannot get anywhere else.
            assert!(message.contains(PYTHON_HEAD), "{message}");
        }
        // And they do not read the same.
        assert_ne!(behind.message(), unstamped.message());
        assert_ne!(unstamped.message(), unmanaged.message());
    }

    /// The revision that was found is in the message. "Schema mismatch"
    /// without it sends an operator to compare things by hand.
    #[tokio::test]
    async fn the_message_names_what_was_actually_found() {
        let behind = state(&stamped(Some("0007_panel_user_email_invalid_tld")).await).await;
        let message = behind.message().expect("a message");
        assert!(
            message.contains("0007_panel_user_email_invalid_tld"),
            "{message}"
        );
    }

    /// **C12.** With no Rust migrations, a start against a database at head
    /// changes nothing but the bookkeeping table.
    #[tokio::test]
    async fn the_first_start_applies_nothing() {
        let pool = stamped(Some(PYTHON_HEAD)).await;
        let db = super::super::Database::from_pool(pool.clone());
        assert!(RUST_MIGRATIONS.is_empty(), "C12: the list must start empty");
        assert!(db.apply_rust_migrations().await.unwrap().is_empty());
        // The table exists afterwards, so the mechanism is exercised by
        // every start rather than first on the day it matters.
        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(MIGRATIONS_TABLE)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(tables, 1);
    }

    /// Running twice is running once. A migration that reapplied on every
    /// start would be a migration that has to be written idempotent by hand,
    /// which is the thing the bookkeeping table exists to avoid.
    #[tokio::test]
    async fn applying_twice_changes_nothing() {
        let pool = stamped(Some(PYTHON_HEAD)).await;
        let db = super::super::Database::from_pool(pool.clone());
        assert!(db.apply_rust_migrations().await.unwrap().is_empty());
        assert!(db.apply_rust_migrations().await.unwrap().is_empty());
    }

    /// Alembic's table is read and never written. Writing into it would make
    /// Alembic's own `upgrade` disagree with us, and while both sides are
    /// alive that is a fight neither wins.
    #[tokio::test]
    async fn alembics_own_table_is_never_written() {
        let pool = stamped(Some(PYTHON_HEAD)).await;
        let db = super::super::Database::from_pool(pool.clone());
        db.apply_rust_migrations().await.unwrap();
        let revision: String = sqlx::query_scalar("SELECT version_num FROM alembic_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(revision, PYTHON_HEAD);
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alembic_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    }
}
