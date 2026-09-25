//! What schema this build expects, and what the database actually has.
//!
//! **C11 has been withdrawn.** It gave Alembic the schema while Python was
//! alive; new schema changes now come here instead. What did not change is
//! the handover: Alembic owns revisions `0001`–`0031` and they are frozen,
//! so nothing here migrates a Python revision. Anything after is this
//! side's, in its own bookkeeping table.
//!
//! This also still **notices**: a panel running against a schema that is not
//! the one it was built for says so at startup, where somebody is watching,
//! rather than failing on a missing column at request time — which is how a
//! customer finds it, on the one page they needed.
//!
//! A fresh install is the one case this side does build a schema, in
//! [`Database::create_fresh_schema`] — and only on a database with no tables
//! at all. The statements come from [`BOOTSTRAP_DDL`], which was captured
//! from Alembic rather than transcribed from it.
//!
//! **C12, as it reads now: a Rust migration only adds.** It was "the first
//! migration must be a no-op on every existing database", and while the
//! list was empty that was trivially kept. The first entry is a new table,
//! `passkeys`, and C12 keeps what it was for: nothing a migration here does
//! may change a table, index or row that was there before it. Every entry is
//! a `CREATE ... IF NOT EXISTS`, and the tests below check both that and the
//! result - every Python table left exactly as it was.

use super::DbError;

#[path = "bootstrap_schema.rs"]
mod bootstrap_schema;

pub use bootstrap_schema::BOOTSTRAP_DDL;

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

/// What `create_fresh_schema` found, and what it did about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bootstrap {
    /// The database was empty; the schema was built and stamped.
    Created,
    /// Alembic has already been here. Nothing was done, and nothing should
    /// be: Python owns every schema it has stamped (C11).
    AlreadyManaged,
    /// Tables, but no `alembic_version` — the legacy shape from before the
    /// panel adopted Alembic.
    ///
    /// Left alone **deliberately**. Python's `run_migrations` handles this
    /// by stamping `0001_initial` and upgrading from there, which replays
    /// only the DDL that came after. Building the schema here instead would
    /// mean either dropping a live panel's tables or creating alongside
    /// them, and neither is something to do without being asked.
    LeftToPython,
}

/// Migrations this side owns.
///
/// **C12: only additions.** Each entry creates something new - `CREATE TABLE
/// IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS` - and touches nothing that
/// was there before it: no `ALTER`, no `DROP`, no rewritten rows. A Python
/// that still runs beside this side on an upgraded box sees its own tables
/// exactly as it left them.
///
/// This is now where a schema change goes. Adding one to `backend/alembic`
/// instead would put it behind a Python that a cut-over box does not run.
///
/// Each entry is `(name, sql)`, one statement each. The name is recorded so
/// a migration runs once; the SQL has to be safe to run against a database
/// at [`PYTHON_HEAD`].
pub const RUST_MIGRATIONS: &[(&str, &str)] = &[
    // Passkeys: WebAuthn credentials, a second factor beside the TOTP code.
    // See `passkeys.rs`. `username` is there on purpose: SQLite can give a
    // deleted user's id to the next account, and a leftover passkey must not
    // follow the number.
    (
        "rust_0001_passkeys",
        "CREATE TABLE IF NOT EXISTS passkeys (\
            id INTEGER NOT NULL PRIMARY KEY, \
            user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE, \
            username VARCHAR(64) NOT NULL, \
            credential_id VARCHAR(1400) NOT NULL UNIQUE, \
            public_key BLOB NOT NULL, \
            algorithm INTEGER NOT NULL, \
            sign_count INTEGER DEFAULT 0 NOT NULL, \
            rp_id VARCHAR(253) NOT NULL, \
            name VARCHAR(64) NOT NULL, \
            aaguid VARCHAR(36) DEFAULT '' NOT NULL, \
            created_at DATETIME NOT NULL, \
            last_used_at DATETIME)",
    ),
    (
        "rust_0002_passkeys_by_user",
        "CREATE INDEX IF NOT EXISTS ix_passkeys_user_id ON passkeys (user_id)",
    ),
    // SFTP: what the panel decided about a user's SFTP login, when it has
    // decided anything - see `sftp_accounts.rs`. The username, as passkeys
    // keep it, for the same reason.
    (
        "rust_0003_sftp_accounts",
        "CREATE TABLE IF NOT EXISTS sftp_accounts (\
            user_id INTEGER NOT NULL PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE, \
            username VARCHAR(64) NOT NULL, \
            enabled BOOLEAN NOT NULL, \
            own_password BOOLEAN NOT NULL, \
            updated_at DATETIME NOT NULL)",
    ),
    // S3 backup destinations, beside the SFTP ones - see `s3_targets.rs`.
    (
        "rust_0004_s3_backup_targets",
        "CREATE TABLE IF NOT EXISTS s3_backup_targets (\
            id INTEGER NOT NULL PRIMARY KEY, \
            name VARCHAR(64) NOT NULL, \
            endpoint VARCHAR(255) NOT NULL, \
            region VARCHAR(64) NOT NULL, \
            bucket VARCHAR(63) NOT NULL, \
            prefix VARCHAR(255) DEFAULT '' NOT NULL, \
            access_key VARCHAR(255) NOT NULL, \
            secret_key TEXT NOT NULL, \
            path_style BOOLEAN NOT NULL, \
            is_active BOOLEAN DEFAULT 1 NOT NULL, \
            created_at DATETIME NOT NULL)",
    ),
    // What a backup schedule has beyond the Python's columns: an S3
    // destination, and how its archives are named. A table of its own, as C12
    // requires; a schedule without a row is the Python's.
    (
        "rust_0005_backup_schedule_options",
        "CREATE TABLE IF NOT EXISTS backup_schedule_options (\
            schedule_id INTEGER NOT NULL PRIMARY KEY \
                REFERENCES backup_schedules (id) ON DELETE CASCADE, \
            s3_target_id INTEGER REFERENCES s3_backup_targets (id) ON DELETE SET NULL, \
            name_style VARCHAR(16) DEFAULT 'timestamp' NOT NULL)",
    ),
    // The MCP addon's tokens - see `mcp_tokens.rs`. Only a token's hash is
    // kept; an account deleted takes its tokens with it.
    (
        "rust_0006_mcp_tokens",
        "CREATE TABLE IF NOT EXISTS mcp_tokens (\
            id INTEGER NOT NULL PRIMARY KEY, \
            user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE, \
            name VARCHAR(64) NOT NULL, \
            token_hash VARCHAR(64) NOT NULL UNIQUE, \
            prefix VARCHAR(16) NOT NULL, \
            can_write BOOLEAN NOT NULL, \
            expires_at DATETIME NOT NULL, \
            last_used_at DATETIME, \
            created_at DATETIME NOT NULL)",
    ),
    (
        "rust_0007_mcp_tokens_by_user",
        "CREATE INDEX IF NOT EXISTS ix_mcp_tokens_user_id ON mcp_tokens (user_id)",
    ),
];

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

    /// Build the schema a fresh install starts with.
    ///
    /// The statements are [`BOOTSTRAP_DDL`], which is a copy of what
    /// Alembic produces rather than a transcription of it — see that
    /// module. The point of capturing instead of reading is that a column
    /// typed wrongly here would not fail a test; it would corrupt a row
    /// months later.
    ///
    /// **Only an empty database.** Anything else is reported and left
    /// alone; see [`Bootstrap`].
    ///
    /// The `alembic_version` row is written as part of the same
    /// transaction, and that is load-bearing rather than tidy. Without it
    /// Python's own `run_migrations` would find an unstamped database whose
    /// tables already exist, try to replay all of them, and fail on the
    /// first `CREATE TABLE`. Stamping the head is what lets a database this
    /// side created be handed back to Python untouched.
    pub async fn create_fresh_schema(&self) -> Result<Bootstrap, DbError> {
        let existing: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_one(self.pool())
        .await?;
        if existing > 0 {
            return Ok(match self.schema_state().await? {
                SchemaState::NotManaged => Bootstrap::LeftToPython,
                _ => Bootstrap::AlreadyManaged,
            });
        }

        // One transaction: a half-built schema that survived a crash would
        // be the `LeftToPython` shape above, and this side would then never
        // touch it again.
        let mut tx = self.pool().begin().await?;
        for statement in BOOTSTRAP_DDL {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO alembic_version (version_num) VALUES (?)")
            .bind(PYTHON_HEAD)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Bootstrap::Created)
    }

    /// Apply any Rust-owned migration this database has not seen.
    ///
    /// Returns the names applied. With [`RUST_MIGRATIONS`] empty this makes
    /// the bookkeeping table and does nothing else, which is the point: the
    /// mechanism is exercised by every start long before it first has to
    /// carry a real migration.
    pub async fn apply_rust_migrations(&self) -> Result<Vec<String>, DbError> {
        self.apply_migrations(RUST_MIGRATIONS).await
    }

    /// [`Self::apply_rust_migrations`] against a given list.
    ///
    /// Split out so the runner can be tested against a migration that does
    /// something. With [`RUST_MIGRATIONS`] empty, every test of the entry
    /// point above proves only that applying nothing applies nothing — which
    /// was fine while Alembic owned the schema, and is not fine now that new
    /// schema changes come here. Otherwise the first real migration would be
    /// the first time this code ran anything.
    pub async fn apply_migrations(
        &self,
        migrations: &[(&str, &str)],
    ) -> Result<Vec<String>, DbError> {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {MIGRATIONS_TABLE} (\
                name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        ))
        .execute(self.pool())
        .await?;

        let mut applied = Vec::new();
        for (name, sql) in migrations {
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

    /// The dump the generator took, or `None` in a checkout without it.
    ///
    /// Same query as `gen-schema-corpus.py` ran against Python's database,
    /// so the two sides are compared on the same footing.
    fn corpus() -> Option<serde_json::Value> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/schema_head.json");
        let text = std::fs::read_to_string(&path).ok()?;
        Some(serde_json::from_str(&text).unwrap())
    }

    async fn dump(pool: &SqlitePool) -> Vec<(String, String, String, String)> {
        sqlx::query_as(
            "SELECT type, name, tbl_name, sql FROM sqlite_master \
             WHERE sql IS NOT NULL ORDER BY type, name",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// **A database built here is the database Python builds.**
    ///
    /// Every object compared by name *and* by the statement text SQLite
    /// recorded, against a dump taken from a database Alembic migrated. A
    /// column dropped, retyped, renamed or given a different default fails
    /// this by name — which is the whole reason the DDL was captured rather
    /// than transcribed.
    ///
    /// What this does not claim: it is not proof that the port is right in
    /// some absolute sense, because both sides came from the same capture.
    /// It is a drift guard, and drift is the failure that would otherwise
    /// be silent — someone editing the generated file, or Alembic gaining a
    /// revision that nobody re-captured.
    #[tokio::test]
    async fn a_fresh_database_is_the_one_python_builds() {
        let Some(corpus) = corpus() else {
            eprintln!("skipped: no tests/golden/schema_head.json in this checkout");
            return;
        };
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let db = super::super::Database::from_pool(pool.clone());
        assert_eq!(db.create_fresh_schema().await.unwrap(), Bootstrap::Created);

        let expected = corpus["objects"].as_array().unwrap();
        let found = dump(&pool).await;

        let names = |v: &[(String, String, String, String)]| -> Vec<String> {
            v.iter().map(|(t, n, ..)| format!("{t} {n}")).collect()
        };
        let expected_names: Vec<String> = expected
            .iter()
            .map(|o| {
                format!(
                    "{} {}",
                    o["type"].as_str().unwrap(),
                    o["name"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(
            names(&found),
            expected_names,
            "the set of tables and indexes differs from Python's"
        );

        for (object, (ty, name, table, sql)) in expected.iter().zip(&found) {
            assert_eq!(ty, object["type"].as_str().unwrap());
            assert_eq!(name, object["name"].as_str().unwrap());
            assert_eq!(table, object["table"].as_str().unwrap());
            assert_eq!(
                sql,
                object["sql"].as_str().unwrap(),
                "the statement SQLite recorded for {ty} {name} is not the one \
                 Python's database has"
            );
        }
    }

    /// **The capture and the constant describe the same revision.**
    ///
    /// The schema was captured at whatever head Alembic had that day. If
    /// somebody adds `0032` and updates `PYTHON_HEAD` without re-running
    /// the generator, a fresh install would be built at 31 revisions and
    /// stamped as though it were at 32 — and Python would then never apply
    /// the missing one. That is a corrupt install that starts cleanly, so
    /// it is worth a test of its own.
    #[test]
    fn the_schema_was_captured_at_the_revision_this_build_stamps() {
        let Some(corpus) = corpus() else {
            eprintln!("skipped: no tests/golden/schema_head.json in this checkout");
            return;
        };
        assert_eq!(corpus["revision"].as_str().unwrap(), PYTHON_HEAD);
    }

    /// **A database built here can be handed straight back to Python.**
    ///
    /// The stamp is what makes that true. Without it Python's
    /// `run_migrations` finds tables and no revision, replays all 31, and
    /// dies on the first `CREATE TABLE`.
    #[tokio::test]
    async fn a_fresh_database_is_stamped_at_the_head() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let db = super::super::Database::from_pool(pool.clone());
        db.create_fresh_schema().await.unwrap();
        assert_eq!(
            db.schema_state().await.unwrap(),
            SchemaState::AtExpectedHead
        );

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alembic_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "exactly one revision row, as Alembic keeps it");
    }

    /// **Running it twice is not running it twice.**
    #[tokio::test]
    async fn it_leaves_a_database_alembic_has_stamped_alone() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let db = super::super::Database::from_pool(pool.clone());
        assert_eq!(db.create_fresh_schema().await.unwrap(), Bootstrap::Created);
        assert_eq!(
            db.create_fresh_schema().await.unwrap(),
            Bootstrap::AlreadyManaged
        );
        let tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(tables, 14);
    }

    /// **The legacy shape is Python's to fix, and is left for it.**
    ///
    /// Tables but no `alembic_version`: a panel from before Alembic. The
    /// only two things this side could do are drop what is there or build
    /// alongside it, and both lose data on a live box.
    #[tokio::test]
    async fn it_leaves_the_pre_alembic_shape_to_python() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, username) VALUES (1, 'admin')")
            .execute(&pool)
            .await
            .unwrap();

        let db = super::super::Database::from_pool(pool.clone());
        assert_eq!(
            db.create_fresh_schema().await.unwrap(),
            Bootstrap::LeftToPython
        );

        let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(username, "admin", "the existing row is still there");
    }

    /// A database with the schema a fresh install gets.
    async fn fresh() -> (SqlitePool, super::super::Database) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let db = super::super::Database::from_pool(pool.clone());
        db.create_fresh_schema().await.unwrap();
        (pool, db)
    }

    async fn columns(pool: &SqlitePool, table: &str) -> Vec<String> {
        sqlx::query_scalar(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .fetch_all(pool)
            .await
            .unwrap()
    }

    /// **A migration runs, and runs once.**
    ///
    /// The first real one would otherwise be the first time this code ever
    /// applied anything: [`RUST_MIGRATIONS`] is empty, so the shipped entry
    /// point only ever proves that applying nothing applies nothing.
    #[tokio::test]
    async fn a_migration_is_applied_and_then_not_applied_again() {
        let (pool, db) = fresh().await;
        let list: &[(&str, &str)] = &[(
            "0001_test_add_column",
            "ALTER TABLE users ADD COLUMN test_marker TEXT NOT NULL DEFAULT ''",
        )];

        let applied = db.apply_migrations(list).await.unwrap();
        assert_eq!(applied, vec!["0001_test_add_column".to_string()]);
        assert!(columns(&pool, "users")
            .await
            .contains(&"test_marker".to_string()));

        // Twice is once. A migration that reapplied on every start would
        // have to be written idempotent by hand, which is the thing the
        // bookkeeping table exists to avoid — and this one would fail,
        // because the column is already there.
        let again = db.apply_migrations(list).await.unwrap();
        assert!(again.is_empty(), "it applied a second time: {again:?}");
    }

    /// **They run in the order they are written.**
    ///
    /// The second here depends on the first having run. A runner that
    /// reordered them — by name, or by whatever a map iterated — would fail
    /// on a pair like this and work on a pair that happened not to care,
    /// which is the worst way to have that bug.
    #[tokio::test]
    async fn migrations_run_in_the_order_they_are_listed() {
        let (pool, db) = fresh().await;
        let applied = db
            .apply_migrations(&[
                ("0001_add", "ALTER TABLE users ADD COLUMN step_one TEXT"),
                (
                    "0002_use_it",
                    "UPDATE users SET step_one = 'set by the second migration'",
                ),
            ])
            .await
            .unwrap();
        assert_eq!(applied, vec!["0001_add", "0002_use_it"]);
        assert!(columns(&pool, "users")
            .await
            .contains(&"step_one".to_string()));
    }

    /// **A migration that fails is not recorded as applied.**
    ///
    /// Recording it would make the next start skip it, leaving a database
    /// that is missing the change and says it has it — the one state from
    /// which nothing recovers on its own.
    #[tokio::test]
    async fn a_failing_migration_is_not_recorded() {
        let (pool, db) = fresh().await;
        let bad: &[(&str, &str)] = &[("0001_broken", "ALTER TABLE nothing_here ADD COLUMN x TEXT")];

        assert!(db.apply_migrations(bad).await.is_err());

        let recorded: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {MIGRATIONS_TABLE}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(recorded, 0, "a failure must not be remembered as a success");
    }

    /// **A migration after a failing one does not run.**
    ///
    /// Stopping is the only safe answer: the later ones were written
    /// against a schema the failed one was supposed to produce.
    #[tokio::test]
    async fn the_run_stops_at_the_first_failure() {
        let (pool, db) = fresh().await;
        let result = db
            .apply_migrations(&[
                ("0001_broken", "ALTER TABLE nothing_here ADD COLUMN x TEXT"),
                (
                    "0002_after",
                    "ALTER TABLE users ADD COLUMN after_marker TEXT",
                ),
            ])
            .await;
        assert!(result.is_err());
        assert!(
            !columns(&pool, "users")
                .await
                .contains(&"after_marker".to_string()),
            "the migration after the failure ran anyway"
        );
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

    /// **C12, by reading the SQL.** Every Rust migration is one statement
    /// that creates something new, and none says anything that could change
    /// what was already there.
    #[test]
    fn every_rust_migration_only_adds() {
        let names: Vec<&str> = RUST_MIGRATIONS.iter().map(|(name, _)| *name).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "a name used twice runs once");
        for (name, sql) in RUST_MIGRATIONS {
            let upper = sql.to_uppercase();
            assert!(
                [
                    "CREATE TABLE IF NOT EXISTS ",
                    "CREATE INDEX IF NOT EXISTS ",
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                ]
                .iter()
                .any(|prefix| upper.starts_with(prefix)),
                "{name} does not create something new"
            );
            let words: Vec<&str> = upper
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .collect();
            for forbidden in [
                "ALTER", "DROP", "UPDATE", "DELETE", "INSERT", "REPLACE", "RENAME",
            ] {
                // `ON DELETE CASCADE` is a clause of a new column, not a
                // statement against an old table.
                let hits = words.iter().filter(|w| **w == forbidden).count();
                let allowed = if forbidden == "DELETE" {
                    upper.matches("ON DELETE ").count()
                } else {
                    0
                };
                assert_eq!(hits, allowed, "{name} says {forbidden}");
            }
            assert!(!sql.contains(';'), "{name} is more than one statement");
        }
    }

    /// **C12, by the result.** On the schema a fresh install has, applying
    /// every Rust migration leaves each table and index that was there
    /// exactly as it was, and adds only what the migrations name.
    #[tokio::test]
    async fn the_rust_migrations_leave_every_python_table_as_it_was() {
        let (pool, db) = fresh().await;
        let before = dump(&pool).await;
        let applied = db.apply_rust_migrations().await.unwrap();
        assert_eq!(applied.len(), RUST_MIGRATIONS.len());
        let after = dump(&pool).await;
        for entry in &before {
            assert!(after.contains(entry), "{} changed or went", entry.1);
        }
        let mut added: Vec<&str> = after
            .iter()
            .filter(|entry| !before.contains(entry))
            .map(|entry| entry.1.as_str())
            .collect();
        added.sort();
        assert_eq!(
            added,
            vec![
                "backup_schedule_options",
                "ix_mcp_tokens_user_id",
                "ix_passkeys_user_id",
                "mcp_tokens",
                "passkeys",
                "s3_backup_targets",
                "sftp_accounts",
                MIGRATIONS_TABLE
            ],
            "only the passkeys table and its index, the SFTP decisions and the \
             bookkeeping table are new"
        );
    }

    /// Running twice is running once. A migration that reapplied on every
    /// start would be a migration that has to be written idempotent by hand,
    /// which is the thing the bookkeeping table exists to avoid.
    #[tokio::test]
    async fn applying_twice_changes_nothing() {
        let pool = stamped(Some(PYTHON_HEAD)).await;
        let db = super::super::Database::from_pool(pool.clone());
        assert_eq!(
            db.apply_rust_migrations().await.unwrap().len(),
            RUST_MIGRATIONS.len()
        );
        assert!(db.apply_rust_migrations().await.unwrap().is_empty());
    }

    /// The migration runner reads Alembic's table and never writes it.
    /// Writing into it would make Alembic's own `upgrade` disagree with us,
    /// and while both sides are alive that is a fight neither wins.
    ///
    /// There is exactly one place that does write it — `create_fresh_schema`,
    /// on a database that did not exist a moment earlier — and that is the
    /// opposite case: without the stamp Python would find tables and no
    /// revision and try to replay all 31.
    #[tokio::test]
    async fn the_migration_runner_never_writes_alembics_table() {
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
