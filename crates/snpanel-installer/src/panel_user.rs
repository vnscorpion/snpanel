//! The `snpanel` account, its groups, and how it reaches MariaDB.
//!
//! Source: `setup_panel_user`.
//!
//! Everything the panel does to a customer's files it does as this account
//! or through the helper, so the group memberships here are the whole of
//! what it can read — and the `.my.cnf` is the whole of how it reaches the
//! database. Both are written once and then depended on by every later
//! phase.

/// The groups created before the account is.
pub const SYSTEM_GROUPS: &[&str] = &["snpanel-sites", "snpanel-sftp"];

/// One directory the installer makes, with the ownership and mode it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedDir {
    pub path: &'static str,
    pub owner: &'static str,
    pub group: &'static str,
    pub mode: u32,
}

/// The two nginx directories the panel writes vhosts into.
///
/// `2775` — group-writable **and setgid**, so a file the panel creates
/// inherits the `snpanel` group rather than root's. Without the setgid bit
/// the first vhost written after an update belongs to root and the panel
/// cannot rewrite it, which looks like a permissions bug in the panel and is
/// not.
pub fn nginx_dirs() -> Vec<ManagedDir> {
    vec![
        ManagedDir {
            path: "/etc/nginx/conf.d",
            owner: "root",
            group: "snpanel",
            mode: 0o2775,
        },
        ManagedDir {
            path: "/etc/nginx/snpanel/custom",
            owner: "root",
            group: "snpanel",
            mode: 0o2775,
        },
    ]
}

/// The panel's own data directories, including the DirectAdmin and upload
/// staging areas.
///
/// `0750`: the panel's group can read them and nobody else can. A backup
/// archive holds a customer's whole account, the import staging areas hold
/// their database dumps in plaintext while an import runs, and the upload
/// one a file on its way into their site.
pub fn data_dirs(app_dir: &'static str, backup_root: &'static str) -> Vec<ManagedDir> {
    // The app directory itself is traversable - the Node runtimes applications
    // run on live under it, and they run as the site's own user - and its
    // secrets are one level down, in `backend`, which is not.
    let mut dirs = vec![
        ManagedDir {
            path: app_dir,
            owner: "snpanel",
            group: "snpanel",
            mode: APP_DIR_MODE,
        },
        ManagedDir {
            path: APP_BACKEND_DIR,
            owner: "snpanel",
            group: "snpanel",
            mode: APP_BACKEND_DIR_MODE,
        },
    ];
    dirs.extend(
        [
            backup_root,
            "/home/admin/snpanel_backups/da",
            "/var/lib/snpanel/da-import",
            "/var/lib/snpanel/import-stage",
            "/var/lib/snpanel/upload-stage",
        ]
        .into_iter()
        .map(|path| ManagedDir {
            path,
            owner: "snpanel",
            group: "snpanel",
            mode: 0o750,
        }),
    );
    dirs
}

/// Where `.env` and the panel's database live: the one part of the app
/// directory nobody but the panel may enter.
pub const APP_BACKEND_DIR: &str = "/opt/snpanel/backend";

/// The app directory: passed through by everyone, listed by nobody else.
/// Every update puts it back, because the sync gives it the source tree's.
pub const APP_DIR_MODE: u32 = 0o711;
/// [`APP_BACKEND_DIR`]: the panel's and its group's, nobody else's.
pub const APP_BACKEND_DIR_MODE: u32 = 0o750;

/// `openssl rand -base64 32 | tr -d '/+=' | cut -c1-32`.
///
/// The `tr` is there because the password is interpolated into SQL and into
/// an ini file, and `/`, `+` and `=` are each awkward in one of those. The
/// `cut` then takes the first thirty-two of what is left — which is always
/// enough, because base64 of thirty-two bytes is forty-four characters and
/// only a handful are ever stripped.
pub fn shape_password(base64_bytes: &str) -> String {
    base64_bytes
        .chars()
        .filter(|c| !matches!(c, '/' | '+' | '='))
        .take(32)
        .collect()
}

/// The SQL that makes the account, whether or not it is already there.
///
/// **`ALTER` as well as `CREATE`.** `CREATE USER IF NOT EXISTS` does nothing
/// when the account exists — including nothing to its password — so a second
/// install run would write a new password into `.my.cnf` while the account
/// kept the old one, and every database action in the panel would then fail
/// with "Access denied for user 'snpanel'@'localhost'". Re-running the
/// installer after a failure is a normal thing to do, so it has to converge
/// rather than half-apply.
pub fn grant_sql(password: &str) -> String {
    format!(
        "
    CREATE USER IF NOT EXISTS 'snpanel'@'localhost' IDENTIFIED BY '{password}';
    ALTER USER 'snpanel'@'localhost' IDENTIFIED BY '{password}';
    GRANT ALL PRIVILEGES ON *.* TO 'snpanel'@'localhost' WITH GRANT OPTION;
    FLUSH PRIVILEGES;
  "
    )
}

/// `$APP_DIR/.my.cnf`, mode `0600`, owned by `snpanel`.
///
/// Two sections, because `mysqldump` does not read `[client]` for every
/// option it needs and a backup that cannot authenticate is a backup that
/// silently produces an empty file.
pub fn my_cnf(password: &str) -> String {
    format!(
        "[client]
user=snpanel
password=\"{password}\"
host=localhost

[mysqldump]
user=snpanel
password=\"{password}\"
host=localhost
"
    )
}

/// `0600`. It is the credential for an account with `GRANT OPTION` on
/// everything.
pub const MY_CNF_MODE: u32 = 0o600;

/// The password back out of an existing `.my.cnf`.
///
/// Source: the `awk` in `refresh_snpanel_mariadb_grants`.
///
/// **This is what makes re-running an update safe.** The grant refresh
/// re-issues `ALTER USER ... IDENTIFIED BY`, and if it minted a new password
/// every time it ran, it would work — but any backup or cron job holding the
/// old one would start failing, and so would a second panel process reading
/// a `.my.cnf` it had already opened. Reading the existing password and
/// setting the *same* one converges instead of churning. A new one is minted
/// only when there is nothing to read.
///
/// Section-aware, as the awk is: `password` is taken from `[client]` and the
/// scan stops at the next section header. `[mysqldump]` carries the same
/// value today, so reading the wrong one would happen to work — which is
/// exactly the kind of accident that stops working later.
pub fn password_from_my_cnf(contents: &str) -> Option<&str> {
    let mut in_client = false;
    for line in contents.lines() {
        if line.starts_with("[client]") {
            in_client = true;
            continue;
        }
        if line.starts_with('[') {
            in_client = false;
            continue;
        }
        if !in_client {
            continue;
        }
        // `-F=` then `$1 == "password"`: the field before the first `=`.
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key != "password" {
            continue;
        }
        // `gsub(/^"|"$/, "", value)` — one leading and one trailing quote.
        let value = value.strip_prefix('"').unwrap_or(value);
        let value = value.strip_suffix('"').unwrap_or(value);
        return Some(value);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair has to round-trip, or the update mints a new password on
    /// every run: it writes `.my.cnf`, and the next update reads it back to
    /// decide whether there is anything to change.
    #[test]
    fn what_is_written_can_be_read_back() {
        for password in [
            "abc123",
            &shape_password("ab+cd/ef=ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            "0123456789abcdefghijABCDEFGHIJ12",
        ] {
            let written = my_cnf(password);
            assert_eq!(
                password_from_my_cnf(&written),
                Some(password),
                "{password:?} did not survive the round trip"
            );
        }
    }

    /// `[mysqldump]` carries the same value today, so reading the wrong
    /// section would happen to work — which is exactly the kind of accident
    /// that stops working later.
    #[test]
    fn the_password_is_read_from_the_client_section() {
        let mixed = "[client]\n\
                     user=snpanel\n\
                     password=\"from-client\"\n\
                     \n\
                     [mysqldump]\n\
                     password=\"from-mysqldump\"\n";
        assert_eq!(password_from_my_cnf(mixed), Some("from-client"));

        // And a password that appears only outside `[client]` is not the
        // panel's password.
        let elsewhere = "[mysqldump]\npassword=\"nope\"\n";
        assert_eq!(password_from_my_cnf(elsewhere), None);

        // A file with no sections at all yields nothing rather than the
        // first thing that looks like a password.
        assert_eq!(password_from_my_cnf("password=\"loose\"\n"), None);
    }

    /// Nothing to read means a fresh password is minted — which is right for
    /// a box that has never had one, and is also why the round trip above
    /// matters: a `.my.cnf` this cannot parse is indistinguishable from one
    /// that is not there.
    #[test]
    fn an_unreadable_file_yields_nothing() {
        assert_eq!(password_from_my_cnf(""), None);
        assert_eq!(password_from_my_cnf("[client]\nuser=snpanel\n"), None);
        assert_eq!(password_from_my_cnf("# a comment\n"), None);
    }

    /// Only one quote is stripped from each end, as `gsub(/^"|"$/, ...)`
    /// does — a password that contains quotes keeps the inner ones.
    #[test]
    fn exactly_one_quote_is_stripped_from_each_end() {
        assert_eq!(
            password_from_my_cnf("[client]\npassword=\"a\"b\"\n"),
            Some("a\"b")
        );
        // Unquoted values are read as they are.
        assert_eq!(
            password_from_my_cnf("[client]\npassword=plain\n"),
            Some("plain")
        );
        // And an `=` inside the value survives, since only the first splits.
        assert_eq!(
            password_from_my_cnf("[client]\npassword=\"a=b\"\n"),
            Some("a=b")
        );
    }

    /// Base64 of thirty-two bytes is forty-four characters, so there is
    /// always more than thirty-two left after the strip — the `cut` is what
    /// decides the length, not what survived the `tr`.
    #[test]
    fn a_password_is_thirty_two_characters_of_the_safe_alphabet() {
        let raw = "ab+cd/ef=ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let password = shape_password(raw);
        assert_eq!(password.len(), 32);
        assert!(!password.contains(['/', '+', '=']));
        assert!(password.starts_with("abcdefghij"));
    }

    /// A short input is not padded — `cut -c1-32` gives what there is. Worth
    /// a test because it is the one case where the length is not thirty-two,
    /// and a caller that assumed otherwise would build a shorter credential
    /// without noticing.
    #[test]
    fn a_short_input_yields_a_short_password() {
        assert_eq!(shape_password("abc+def"), "abcdef");
        assert_eq!(shape_password(""), "");
    }

    /// The alphabet the strip leaves is what makes the two interpolations
    /// safe: the password goes into a `'...'` SQL literal and a `"..."` ini
    /// value, and neither is escaped.
    ///
    /// Asserted over **base64's own alphabet**, which is what `openssl rand
    /// -base64` produces. An earlier version of this walked all of ASCII and
    /// proved nothing: `shape_password` takes the first thirty-two, and the
    /// first thirty-two that survive the strip are the control characters —
    /// none of which is a quote either.
    #[test]
    fn nothing_that_survives_the_strip_can_close_a_quote() {
        let base64_alphabet: String = ('A'..='Z')
            .chain('a'..='z')
            .chain('0'..='9')
            .chain(['+', '/', '='])
            .collect();
        assert_eq!(base64_alphabet.len(), 65, "base64 is 64 symbols and a pad");

        let survivors: String = base64_alphabet
            .chars()
            .filter(|c| !matches!(c, '/' | '+' | '='))
            .collect();
        assert_eq!(survivors.len(), 62);
        for ch in survivors.chars() {
            assert!(
                ch.is_ascii_alphanumeric(),
                "a password character that is not alphanumeric: {ch:?}"
            );
        }

        // And `shape_password` is what applies that strip.
        let password = shape_password(&base64_alphabet);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!password.contains(['/', '+', '=']));
    }

    /// Re-running the installer is normal after a failure, and this is the
    /// line that makes it converge rather than leave the account and the
    /// file disagreeing.
    #[test]
    fn the_grant_alters_the_password_as_well_as_creating_the_account() {
        let sql = grant_sql("s3cret");
        assert!(sql.contains("CREATE USER IF NOT EXISTS 'snpanel'@'localhost'"));
        assert!(
            sql.contains("ALTER USER 'snpanel'@'localhost' IDENTIFIED BY 's3cret'"),
            "without the ALTER, a re-run writes a new password into .my.cnf \
             while the account keeps the old one"
        );
        assert!(sql.contains("FLUSH PRIVILEGES"));
    }

    /// `mysqldump` does not read `[client]` for everything it needs, and a
    /// backup that cannot authenticate produces an empty file rather than an
    /// error anyone sees.
    #[test]
    fn the_credentials_file_has_a_section_for_mysqldump() {
        let cnf = my_cnf("s3cret");
        assert!(cnf.contains("[client]\nuser=snpanel\npassword=\"s3cret\""));
        assert!(cnf.contains("[mysqldump]\nuser=snpanel\npassword=\"s3cret\""));
    }

    #[test]
    fn the_credentials_file_is_readable_by_nobody_else() {
        assert_eq!(MY_CNF_MODE & 0o077, 0);
    }

    /// Setgid on both nginx directories. Without it the first vhost written
    /// after an update belongs to root and the panel cannot rewrite it,
    /// which looks like a bug in the panel and is not.
    #[test]
    fn the_nginx_directories_are_setgid_to_the_panels_group() {
        for dir in nginx_dirs() {
            assert_eq!(dir.group, "snpanel", "{}", dir.path);
            assert_eq!(dir.mode & 0o2000, 0o2000, "{} is not setgid", dir.path);
            assert_eq!(
                dir.mode & 0o020,
                0o020,
                "{} is not group-writable",
                dir.path
            );
        }
    }

    /// A backup archive holds a customer's whole account, and the import
    /// staging areas hold their database dumps in plaintext while an import
    /// runs. None of it is anybody else's to read.
    #[test]
    fn nothing_the_panel_stores_is_world_readable() {
        for dir in data_dirs("/opt/snpanel", "/var/backups/snpanel") {
            // The app directory may be passed through, never read: its
            // secrets are in `backend`, which is held to the rule.
            let allowed = if dir.path == "/opt/snpanel" { 0o001 } else { 0 };
            assert_eq!(dir.mode & 0o007, allowed, "{} is world-readable", dir.path);
            assert_eq!(dir.owner, "snpanel", "{}", dir.path);
        }
        let backend = data_dirs("/opt/snpanel", "/var/backups/snpanel")
            .into_iter()
            .find(|d| d.path == APP_BACKEND_DIR)
            .expect("backend is among them");
        assert_eq!(backend.mode, 0o750);
    }

    #[test]
    fn the_staging_areas_are_among_the_directories_made() {
        let paths: Vec<&str> = data_dirs("/opt/snpanel", "/var/backups/snpanel")
            .iter()
            .map(|dir| dir.path)
            .collect();
        assert!(paths.contains(&"/var/lib/snpanel/import-stage"));
        assert!(paths.contains(&"/var/lib/snpanel/da-import"));
        assert!(paths.contains(&"/var/lib/snpanel/upload-stage"));
        assert!(paths.contains(&"/home/admin/snpanel_backups/da"));
    }
}
