//! Driving MariaDB with the panel's own credentials.
//!
//! Source: `app.services.mariadb`. Worth stating plainly, because the
//! `databases` router said these endpoints were waiting on "the helper's
//! MariaDB surface": they are not. `_run_sql` calls `shell.run`, not
//! `shell.privileged` - it runs `mysql --defaults-file=~/.my.cnf` as the panel
//! account, with the credentials the installer wrote there. No helper is
//! involved and none needs to be.
//!
//! The SQL goes in on **stdin**, never in argv, so a password never appears
//! in `ps` for the life of the process. C37, applied to a client the panel
//! runs itself rather than to the privileged helper.

use std::path::PathBuf;

/// Source: `IDENTIFIER_CHARS` - lowercase, digits and underscore. Not a
/// quoting rule: a name outside this set is refused rather than escaped.
const IDENTIFIER_CHARS: &str = "abcdefghijklmnopqrstuvwxyz0123456789_";

/// Source: `RESERVED_DB_USERS` - MariaDB's own accounts, plus the one the
/// panel authenticates as. Creating a database must never touch any of them,
/// on any code path, not even a restore.
const RESERVED_DB_USERS: &[&str] = &[
    "root",
    "mysql",
    "mariadb.sys",
    "debian-sys-maint",
    "snpanel",
];

#[derive(Debug)]
pub enum SqlError {
    /// Source: `ValueError` - a 400.
    Invalid(String),
    /// The client ran and failed, or could not be run at all.
    Failed(String),
}

impl std::fmt::Display for SqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Failed(m) => write!(f, "{m}"),
        }
    }
}

/// Source: `_validate_identifier`.
pub fn validate_identifier(value: &str) -> Result<&str, SqlError> {
    if value.is_empty() || value.len() > 64 || !value.chars().all(|c| IDENTIFIER_CHARS.contains(c))
    {
        return Err(SqlError::Invalid("Invalid database identifier".into()));
    }
    Ok(value)
}

/// Source: `_reject_reserved_user`.
pub fn reject_reserved_user(db_user: &str) -> Result<(), SqlError> {
    if RESERVED_DB_USERS.contains(&db_user.trim().to_lowercase().as_str()) {
        return Err(SqlError::Invalid(format!(
            "'{db_user}' is a reserved MariaDB account and cannot be used for a website database"
        )));
    }
    Ok(())
}

/// Source: `_quote_sql_string`.
pub fn quote_sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

/// Source: `_quote_identifier`.
pub fn quote_identifier(value: &str) -> Result<String, SqlError> {
    Ok(format!("`{}`", validate_identifier(value)?))
}

/// `Path.home() / ".my.cnf"`, as the panel account sees it.
fn defaults_file() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let path = PathBuf::from(home).join(".my.cnf");
    path.exists().then_some(path)
}

/// Source: `_run_sql` - the statements on stdin, so secrets never reach argv.
pub async fn run_sql(sql: &str) -> Result<String, SqlError> {
    use tokio::io::AsyncWriteExt;

    let mut command = tokio::process::Command::new("mysql");
    if let Some(cnf) = defaults_file() {
        command.arg(format!("--defaults-file={}", cnf.display()));
    }
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| SqlError::Failed(format!("cannot run mysql: {e}")))?;
    if let Some(mut pipe) = child.stdin.take() {
        let _ = pipe.write_all(sql.as_bytes()).await;
        let _ = pipe.shutdown().await;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| SqlError::Failed(format!("mysql did not finish: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        return Err(SqlError::Failed(if detail.is_empty() {
            "MariaDB command failed".to_string()
        } else {
            detail
        }));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Source: `change_database_password`.
pub async fn change_database_password(db_user: &str, password: &str) -> Result<(), SqlError> {
    let safe = validate_identifier(db_user)?;
    reject_reserved_user(safe)?;
    let sql = format!(
        "ALTER USER {}@'localhost' IDENTIFIED BY {};\nFLUSH PRIVILEGES;\n",
        quote_sql_string(safe),
        quote_sql_string(password)
    );
    run_sql(&sql).await.map(|_| ())
}

/// Source: `random_password`.
///
/// `secrets.choice` over this alphabet, 24 characters. The alphabet is
/// copied exactly rather than "something similar": it is what MariaDB's
/// `IDENTIFIED BY` is known to take through the panel's own quoting, and a
/// character added here is a character that has to survive `_quote_sql_string`
/// and the helper's stdin.
pub fn random_password(length: usize) -> String {
    use rand::RngCore;

    const ALPHABET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^*_+-";
    let mut out = String::with_capacity(length);
    let mut buf = [0u8; 64];
    while out.len() < length {
        rand::rngs::OsRng.fill_bytes(&mut buf);
        for byte in buf {
            if out.len() == length {
                break;
            }
            // Rejection sampling, not `% len`: the modulo would make the
            // first `256 % 70` characters of the alphabet slightly likelier,
            // and this is a password.
            let limit = (256 / ALPHABET.len()) * ALPHABET.len();
            if (byte as usize) < limit {
                out.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
            }
        }
    }
    out
}

/// Source: `safe_db_identifier`.
///
/// **`str.isalnum()` is Unicode-aware and this deliberately is too.** `café`
/// keeps its `é`, which `validate_identifier` then refuses because its
/// character set is ASCII - so an internationalised domain gets a clear 400
/// rather than a database named after a mangled version of itself. A port
/// that used `is_ascii_alphanumeric` here would silently name it
/// `wp_caf__example_com` and create it.
///
/// The two slices are the Python's and they are not the same bound: the
/// domain is cut to 38 characters *before* the prefix is added, and the whole
/// thing to 63 after.
pub fn safe_db_identifier(domain: &str, prefix: &str) -> String {
    let clean: String = domain
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .take(38)
        .collect();
    format!("{prefix}_{clean}").chars().take(63).collect()
}

/// Source: `create_database`.
///
/// `if_not_exists` is **false** on the path that installs WordPress onto an
/// existing website: that one must fail rather than quietly adopt a database
/// somebody else's site is already using.
pub async fn create_database(
    seed: &str,
    prefix: &str,
    if_not_exists: bool,
) -> Result<NewDatabase, SqlError> {
    let db_name = safe_db_identifier(seed, prefix);
    let db_name = validate_identifier(&db_name)?.to_string();
    let db_user = safe_db_identifier(&db_name, "u");
    let db_user = validate_identifier(&db_user)?.to_string();
    reject_reserved_user(&db_user)?;
    let db_password = random_password(24);

    let create_clause = if if_not_exists {
        "CREATE DATABASE IF NOT EXISTS"
    } else {
        "CREATE DATABASE"
    };
    // `CREATE USER IF NOT EXISTS` followed by an unconditional `ALTER USER` is
    // what the Python does here, and it is the pattern
    // `create_database_credentials` was changed to refuse - because the panel
    // authenticates with ALL PRIVILEGES ON *.*, so taking over an existing
    // account resets its password. It is safe on *this* path only because the
    // name is derived from the database name, which is derived from the
    // domain, and `reject_reserved_user` covers the accounts that matter.
    let sql = format!(
        "{create_clause} {} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n\
         CREATE USER IF NOT EXISTS {}@'localhost' IDENTIFIED BY {};\n\
         ALTER USER {}@'localhost' IDENTIFIED BY {};\n\
         GRANT ALL PRIVILEGES ON {}.* TO {}@'localhost';\n\
         FLUSH PRIVILEGES;\n",
        quote_identifier(&db_name)?,
        quote_sql_string(&db_user),
        quote_sql_string(&db_password),
        quote_sql_string(&db_user),
        quote_sql_string(&db_password),
        quote_identifier(&db_name)?,
        quote_sql_string(&db_user),
    );
    run_sql(&sql).await?;
    Ok(NewDatabase {
        db_name,
        db_user,
        db_password,
    })
}

/// What `create_database` hands back.
///
/// The password is **plain** here and is encrypted by the caller before it
/// reaches a column - C3. It exists in this shape for exactly as long as it
/// takes to write `wp-config.php` and one row.
pub struct NewDatabase {
    pub db_name: String,
    pub db_user: String,
    pub db_password: String,
}

/// Source: `drop_database`.
pub async fn drop_database(db_name: &str, db_user: &str) -> Result<(), SqlError> {
    let safe_user = validate_identifier(db_user)?;
    reject_reserved_user(safe_user)?;
    let sql = format!(
        "DROP DATABASE IF EXISTS {};\nDROP USER IF EXISTS {}@'localhost';\nFLUSH PRIVILEGES;\n",
        quote_identifier(db_name)?,
        quote_sql_string(safe_user)
    );
    run_sql(&sql).await.map(|_| ())
}

/// Source: `export_database` - `mysqldump --result-file`, which writes the
/// file itself rather than streaming through the panel.
pub async fn export_database(db_name: &str, output_file: &str) -> Result<(), SqlError> {
    let safe = validate_identifier(db_name)?;
    let mut command = tokio::process::Command::new("mysqldump");
    if let Some(cnf) = defaults_file() {
        command.arg(format!("--defaults-file={}", cnf.display()));
    }
    command.args([safe, "--result-file", output_file]);
    let out = command
        .output()
        .await
        .map_err(|e| SqlError::Failed(format!("cannot run mysqldump: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(SqlError::Failed(if stderr.is_empty() {
            "mysqldump failed".to_string()
        } else {
            stderr
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the real Python names a database, replayed.
    ///
    /// The case that matters is the one that looks like a bug: `café` keeps
    /// its `é` because `str.isalnum()` is Unicode-aware, and
    /// `validate_identifier` then refuses the name because *its* character set
    /// is ASCII. So an internationalised domain gets a clear refusal rather
    /// than a database quietly named `wp_caf__example_com`.
    ///
    /// The two length cuts are not the same bound either: the domain is cut to
    /// 38 characters **before** the prefix is added, and the whole name to 63
    /// after - so `u_` + a 41-character database name comes out at 40, not 43.
    #[test]
    fn a_database_is_named_the_way_the_python_names_it() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/db_identifier.json");
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the identifier corpus"))
                .expect("the corpus parses");
        let cases = corpus["cases"].as_array().expect("the cases");
        assert_eq!(cases.len(), 22, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let domain = case["domain"].as_str().unwrap_or("");
            for prefix in ["wp", "u"] {
                let got = safe_db_identifier(domain, prefix);
                let want = case[format!("{prefix}_name")].as_str().unwrap_or("");
                if got != want {
                    failures.push(format!(
                        "{domain:?} /{prefix}: python {want:?}, rust {got:?}"
                    ));
                }
                let valid = validate_identifier(&got).is_ok();
                let want_valid = case[format!("{prefix}_valid")].as_bool().unwrap_or(false);
                if valid != want_valid {
                    failures.push(format!(
                        "{domain:?} /{prefix}: python {} it, rust {} it",
                        if want_valid { "accepts" } else { "refuses" },
                        if valid { "accepts" } else { "refuses" },
                    ));
                }
            }
            // The account name comes from the *database* name, not the domain:
            // that second pass is where the 63-character cut bites.
            let got = safe_db_identifier(case["wp_name"].as_str().unwrap_or(""), "u");
            let want = case["user_from_db"].as_str().unwrap_or("");
            if got != want {
                failures.push(format!("{domain:?} /user: python {want:?}, rust {got:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    /// A generated password is 24 characters from the Python's alphabet.
    ///
    /// Not a corpus: the value is random by design. What can be pinned is the
    /// length, the alphabet, and that two calls differ - a constant password
    /// would pass any test that only looked at one.
    #[test]
    fn a_generated_password_is_from_the_alphabet_and_not_a_constant() {
        const ALPHABET: &str =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^*_+-";
        let first = random_password(24);
        assert_eq!(first.chars().count(), 24);
        assert!(
            first.chars().all(|c| ALPHABET.contains(c)),
            "{first:?} has a character the Python cannot produce"
        );
        assert_ne!(first, random_password(24));
        assert_eq!(random_password(8).chars().count(), 8);

        // Every character of the alphabet must be reachable. A sampler that
        // dropped the tail - which is what a careless rejection bound does -
        // would quietly shrink the keyspace and nothing else would notice.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.extend(random_password(64).chars());
        }
        let missing: Vec<char> = ALPHABET.chars().filter(|c| !seen.contains(c)).collect();
        assert!(missing.is_empty(), "never generated: {missing:?}");
    }

    #[test]
    fn an_identifier_is_refused_rather_than_escaped() {
        assert!(validate_identifier("wp_site1").is_ok());
        for bad in [
            "",
            "WP",
            "wp-site",
            "wp site",
            "wp;drop",
            "wp`x",
            &"a".repeat(65),
        ] {
            assert!(validate_identifier(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_reserved_accounts_cannot_be_touched() {
        for name in ["root", "mysql", "snpanel", "ROOT", " root "] {
            assert!(
                reject_reserved_user(name).is_err(),
                "{name:?} is a reserved MariaDB account"
            );
        }
        assert!(reject_reserved_user("u_customer").is_ok());
    }

    #[test]
    fn a_string_literal_escapes_both_ways_python_does() {
        // Source: `value.replace("\\", "\\\\").replace("'", "''")` - the
        // backslash first, so an escaped quote does not get double-escaped.
        assert_eq!(quote_sql_string("plain"), "'plain'");
        assert_eq!(quote_sql_string("it's"), "'it''s'");
        assert_eq!(quote_sql_string("a\\b"), "'a\\\\b'");
        assert_eq!(quote_sql_string("a\\'b"), "'a\\\\''b'");
    }
}
