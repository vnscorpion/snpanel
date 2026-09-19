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
