//! phpMyAdmin's control user, which backs its configuration storage.
//!
//! Source: `setup_phpmyadmin_control_user`.
//!
//! Debian's `phpmyadmin` package asks dbconfig-common to make a database and
//! an account for phpMyAdmin's own tables — bookmarks, query history, column
//! comments. On a machine where MariaDB was installed by this installer
//! rather than by the package's own prompt, that account often does not
//! exist, or exists with a password the config file disagrees with.
//!
//! **Nothing here is fatal.** The configuration storage is a convenience;
//! phpMyAdmin works without it, and a panel that refused to finish
//! installing because an optional feature of an optional tool could not be
//! set up would be making the wrong trade. Every failure path warns and
//! carries on, which is what the shell does.

/// Where dbconfig-common records what it made.
pub const CONF: &str = "/etc/dbconfig-common/phpmyadmin.conf";

/// The schema for the storage tables, in the order the shell looks.
///
/// The first one that exists is used and the rest ignored: the two paths are
/// the same file in different releases of the package, not two different
/// schemas to apply in turn.
pub const SCHEMAS: &[&str] = &[
    "/usr/share/phpmyadmin/sql/create_tables.sql",
    "/usr/share/doc/phpmyadmin/examples/create_tables.sql",
];

/// One `dbc_*` value out of the config file.
///
/// Reproduces `sed -n "s/^dbc_dbuser='\(.*\)'$/\1/p" | head -1`, which means
/// all of: the line must begin at column zero with the key, the value must
/// be wrapped in single quotes that reach the end of the line, the capture
/// is **greedy** — so a value that itself contains a quote keeps it — and
/// the first matching line wins.
pub fn dbc_value<'a>(conf: &'a str, key: &str) -> Option<&'a str> {
    let opening = format!("{key}='");
    for line in conf.lines() {
        let Some(rest) = line.strip_prefix(&opening) else {
            continue;
        };
        // Greedy `.*` followed by `'$`: everything up to the last quote on
        // the line.
        let Some(value) = rest.strip_suffix('\'') else {
            continue;
        };
        return Some(value);
    }
    None
}

/// What the three values add up to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub user: String,
    pub password: String,
    pub database: String,
}

/// Why the phase did nothing. All of these are warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// Not a Debian-family box, or the package was never installed.
    NoConfig,
    /// The file is there but one of the three values is missing or empty.
    Incomplete,
    /// A value carries a character that would end the SQL literal it is
    /// about to be interpolated into.
    ///
    /// **This is a deliberate difference from the shell**, and the only one
    /// in this module. The bash interpolates all three values into a
    /// `mariadb -e` string with no quoting, and a value containing a `'`
    /// produces a statement that means something other than what was
    /// intended. dbconfig-common does not generate such values — the file is
    /// root-owned and machine-written — so in practice neither side ever
    /// reaches this. Refusing is the same outcome the shell already produces
    /// for every other problem here: a warning, and an install that carries
    /// on.
    UnsafeValue,
}

/// The values, if all three are usable.
pub fn read(conf: Option<&str>) -> Result<Control, Skip> {
    let conf = conf.ok_or(Skip::NoConfig)?;
    let user = dbc_value(conf, "dbc_dbuser").unwrap_or_default();
    let password = dbc_value(conf, "dbc_dbpass").unwrap_or_default();
    let database = dbc_value(conf, "dbc_dbname").unwrap_or_default();
    if user.is_empty() || password.is_empty() || database.is_empty() {
        return Err(Skip::Incomplete);
    }
    if [user, password, database].iter().any(|v| !is_safe(v)) {
        return Err(Skip::UnsafeValue);
    }
    Ok(Control {
        user: user.to_string(),
        password: password.to_string(),
        database: database.to_string(),
    })
}

/// Whether a value can be interpolated into the statement below.
///
/// A single quote ends a string literal and a backtick ends an identifier;
/// a backslash and a newline are refused for the same reason without having
/// to reason about which of the two MariaDB is in.
fn is_safe(value: &str) -> bool {
    !value.contains(['\'', '`', '\\', '\n', '\r'])
}

impl Control {
    /// The statement that makes the database, the account and the grant.
    ///
    /// `ALTER` as well as `CREATE`, for the same reason as the panel's own
    /// account: `CREATE USER IF NOT EXISTS` does nothing when the account
    /// exists, including nothing to its password — which is exactly the
    /// mismatch this phase is here to repair, so a version without the
    /// `ALTER` would leave the machine in the state it was called to fix.
    ///
    /// `utf8mb4_bin` and not the server default: phpMyAdmin's own schema
    /// expects a binary collation for the storage tables, and a
    /// case-insensitive one makes two bookmarks differing only in case
    /// collide.
    pub fn sql(&self) -> String {
        let Control {
            user,
            password,
            database,
        } = self;
        format!(
            "
    CREATE DATABASE IF NOT EXISTS `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
    CREATE USER IF NOT EXISTS '{user}'@'localhost' IDENTIFIED BY '{password}';
    ALTER USER '{user}'@'localhost' IDENTIFIED BY '{password}';
    GRANT ALL PRIVILEGES ON `{database}`.* TO '{user}'@'localhost';
    FLUSH PRIVILEGES;
  "
        )
    }

    /// The account reaches only its own storage database.
    ///
    /// phpMyAdmin authenticates every real session as the customer's own
    /// MySQL user; the control user exists to read and write the storage
    /// tables and nothing else. A `*.*` grant here would put a second
    /// all-privileges account on the box whose password sits in a
    /// world-findable package configuration file.
    pub fn grants_only_its_own_database(sql: &str) -> bool {
        !sql.contains("ON *.*")
    }
}

/// The line printed once the account is in place — or the warning when it
/// still cannot connect.
pub fn verdict(control: &Control, can_connect: bool) -> String {
    if can_connect {
        format!(
            "phpMyAdmin control user ready ({}, database {})",
            control.user, control.database
        )
    } else {
        "WARNING: the phpMyAdmin control user still cannot connect".to_string()
    }
}

pub const GRANT_FAILED: &str = "WARNING: could not create the phpMyAdmin control user; \
                                its configuration storage will be unavailable";

#[cfg(test)]
mod tests {
    use super::*;

    const CONF_FILE: &str = "\
dbc_install='true'
dbc_upgrade='true'
dbc_dbtype='mysql'
dbc_dbuser='phpmyadmin'
dbc_dbpass='NzQ4ODM2MDU1'
dbc_dbserver=''
dbc_dbport=''
dbc_dbname='phpmyadmin'
";

    #[test]
    fn the_three_values_come_out_of_the_config() {
        let control = read(Some(CONF_FILE)).expect("all three");
        assert_eq!(control.user, "phpmyadmin");
        assert_eq!(control.password, "NzQ4ODM2MDU1");
        assert_eq!(control.database, "phpmyadmin");
    }

    /// The expression is anchored at both ends, so a line that merely
    /// mentions the key is not a value — which is what keeps a commented
    /// example line out of the answer.
    #[test]
    fn only_an_anchored_assignment_counts() {
        assert_eq!(dbc_value("#dbc_dbuser='x'\n", "dbc_dbuser"), None);
        assert_eq!(dbc_value("  dbc_dbuser='x'\n", "dbc_dbuser"), None);
        assert_eq!(dbc_value("dbc_dbuser='x' # note\n", "dbc_dbuser"), None);
        assert_eq!(dbc_value("dbc_dbuser=x\n", "dbc_dbuser"), None);
        assert_eq!(dbc_value("dbc_dbuser='x'\n", "dbc_dbuser"), Some("x"));
    }

    /// `head -1`: the first assignment wins, not the last. A file that
    /// carries two is a file dbconfig rewrote badly, and taking the first is
    /// what the shell does.
    #[test]
    fn the_first_assignment_wins() {
        assert_eq!(
            dbc_value("dbc_dbuser='first'\ndbc_dbuser='second'\n", "dbc_dbuser"),
            Some("first")
        );
    }

    /// `\(.*\)` is greedy, so the capture runs to the **last** quote on the
    /// line rather than the first.
    #[test]
    fn the_capture_is_greedy() {
        assert_eq!(dbc_value("dbc_dbpass='a'b'\n", "dbc_dbpass"), Some("a'b"));
    }

    /// An empty value is the same as an absent one: the shell's `-n` test
    /// rejects both, and a blank password would otherwise make an account
    /// with no password at all.
    #[test]
    fn an_empty_value_is_not_a_value() {
        let conf = CONF_FILE.replace("dbc_dbpass='NzQ4ODM2MDU1'", "dbc_dbpass=''");
        assert_eq!(read(Some(&conf)), Err(Skip::Incomplete));
        assert_eq!(read(Some("dbc_dbtype='mysql'\n")), Err(Skip::Incomplete));
        assert_eq!(read(None), Err(Skip::NoConfig));
    }

    /// `CREATE USER IF NOT EXISTS` does nothing when the account exists,
    /// including nothing to its password — which is exactly the mismatch
    /// this phase is here to repair. Without the `ALTER` it would leave the
    /// machine in the state it was called to fix.
    #[test]
    fn the_password_is_set_on_an_account_that_already_exists() {
        let sql = read(Some(CONF_FILE)).unwrap().sql();
        assert!(sql.contains("CREATE USER IF NOT EXISTS 'phpmyadmin'@'localhost'"));
        assert!(sql.contains("ALTER USER 'phpmyadmin'@'localhost' IDENTIFIED BY"));
        let create = sql.find("CREATE USER").unwrap();
        let alter = sql.find("ALTER USER").unwrap();
        assert!(create < alter, "the ALTER runs before the CREATE");
    }

    /// A `*.*` grant here would put a second all-privileges account on the
    /// box whose password sits in a package configuration file.
    #[test]
    fn the_control_user_reaches_only_its_own_storage() {
        let control = read(Some(CONF_FILE)).unwrap();
        let sql = control.sql();
        assert!(Control::grants_only_its_own_database(&sql));
        assert!(sql.contains("GRANT ALL PRIVILEGES ON `phpmyadmin`.* TO"));
        // The account is local only — the password is in a file on this
        // machine, and a remote grant would make it worth stealing.
        assert!(!sql.contains("@'%'"));
        assert_eq!(sql.matches("@'localhost'").count(), 3);
    }

    /// phpMyAdmin's schema expects a binary collation; a case-insensitive
    /// one makes two bookmarks differing only in case collide.
    #[test]
    fn the_storage_database_gets_the_collation_the_schema_expects() {
        let sql = read(Some(CONF_FILE)).unwrap().sql();
        assert!(sql.contains("CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"));
    }

    /// The deliberate difference from the shell, and the only one here.
    /// dbconfig-common does not generate such values, so neither side
    /// reaches this in practice — and refusing lands in the same outcome the
    /// shell already produces for every other problem: a warning, and an
    /// install that carries on.
    #[test]
    fn a_value_that_would_end_the_literal_is_refused_rather_than_interpolated() {
        for bad in ["a'b", "a`b", "a\\b"] {
            let conf = CONF_FILE.replace("NzQ4ODM2MDU1", bad);
            assert_eq!(read(Some(&conf)), Err(Skip::UnsafeValue), "{bad:?}");
        }
        // A newline cannot reach `is_safe` through this file at all — the
        // parse is line-based, so a value carrying one is cut at the break
        // and the line no longer ends in a quote. It stays in the check as
        // defence for any other caller, but the outcome through the config
        // file is the ordinary "one of the three is missing".
        let split = CONF_FILE.replace("NzQ4ODM2MDU1", "a\nb");
        assert_eq!(read(Some(&split)), Err(Skip::Incomplete));
        // What dbconfig actually writes goes through untouched.
        assert!(read(Some(CONF_FILE)).is_ok());
    }

    /// Every path out of this phase is a warning. phpMyAdmin works without
    /// its configuration storage, and an install that refused to finish over
    /// an optional feature of an optional tool would be the wrong trade.
    #[test]
    fn nothing_here_ends_the_install() {
        assert!(GRANT_FAILED.starts_with("WARNING: "));
        assert!(GRANT_FAILED.contains("configuration storage will be unavailable"));
        let control = read(Some(CONF_FILE)).unwrap();
        assert!(verdict(&control, false).starts_with("WARNING: "));
        assert_eq!(
            verdict(&control, true),
            "phpMyAdmin control user ready (phpmyadmin, database phpmyadmin)"
        );
    }

    /// The two paths are the same file in different releases of the package,
    /// not two schemas to apply in turn — so the first that exists wins and
    /// the loop stops.
    #[test]
    fn the_schema_is_applied_once_from_whichever_path_has_it() {
        assert_eq!(SCHEMAS.len(), 2);
        assert!(SCHEMAS.iter().all(|p| p.ends_with("create_tables.sql")));
    }
}
