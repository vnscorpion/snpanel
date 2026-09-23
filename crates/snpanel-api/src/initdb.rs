//! Building a panel database from nothing, and the admin account in it.
//!
//! Source: `app/seed.py` — `run_migrations()`, then an `admin` row if there
//! is not one, then `site_users.ensure_panel_user`.
//!
//! **A subcommand and not a startup step**, deliberately. `Database::connect`
//! refuses to create the file it is pointed at, because an empty database
//! appearing where the panel's should be looks like total data loss to
//! whoever finds it. That refusal is worth keeping, so creating a database
//! is something you ask for by name rather than something a restart can do
//! by accident.
//!
//! The schema comes from [`snpanel_db::schema::BOOTSTRAP_DDL`], which was
//! captured from Alembic rather than transcribed from it, and is stamped at
//! the head so Python can pick the database up unchanged.

use snpanel_db::schema::Bootstrap;
use snpanel_db::{Database, NewUser};

/// The flag the installer passes.
pub(crate) const INIT_DB: &str = "--init-db";

/// Source: `os.getenv("SNPANEL_ADMIN_PASSWORD")`.
///
/// C18: the name is part of the install contract and cannot change while
/// `install.sh` still sets it.
pub(crate) const PASSWORD_ENV: &str = "SNPANEL_ADMIN_PASSWORD";

/// Source: `if len(password) < 12`. Characters, as Python counts them.
pub(crate) const MIN_LENGTH: usize = 12;

/// Source: `range(24)`.
pub(crate) const GENERATED_LENGTH: usize = 24;

/// Source: `string.ascii_letters + string.digits + "!@#%^*_+-"`.
///
/// Recorded here and used only by the test below, because the generator
/// this delegates to carries its own copy: `seed.py` and `mariadb.py` are
/// two Python functions that happen to agree, and the test is what makes
/// them go on agreeing.
#[cfg(test)]
const GENERATED_ALPHABET: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^*_+-";

/// Source: `any(char in password for char in (":", "\r", "\n", "\x00"))`.
///
/// Not an aesthetic rule. The password is handed to the helper's
/// `panel-user-password` on stdin as one line, and further on to `chpasswd`,
/// which splits on `:`. A newline ends the line early and a NUL truncates
/// the C string — each of those sets a Linux account's password to something
/// other than what the panel recorded, which locks the operator out of the
/// machine they just installed.
pub(crate) const FORBIDDEN: [char; 4] = [':', '\r', '\n', '\0'];

/// Source: the `User(...)` the seed constructs.
pub(crate) const ADMIN_USERNAME: &str = "admin";
pub(crate) const ADMIN_EMAIL: &str = "admin@example.com";
pub(crate) const ADMIN_ROLE: &str = "admin";
pub(crate) const ADMIN_WEBSITE_LIMIT: i64 = 999;
pub(crate) const ADMIN_STORAGE_LIMIT_MB: i64 = 102_400;

/// Why a supplied `SNPANEL_ADMIN_PASSWORD` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PasswordProblem {
    TooShort,
    Forbidden,
}

impl PasswordProblem {
    /// Source: the two `ValueError` messages, word for word — an installer
    /// that printed something else would send an operator searching for a
    /// string that is not in the codebase.
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::TooShort => "SNPANEL_ADMIN_PASSWORD must be at least 12 characters",
            Self::Forbidden => {
                "SNPANEL_ADMIN_PASSWORD cannot contain ':', newlines, or NUL characters"
            }
        }
    }
}

/// Source: `_admin_password`.
///
/// `raw` is what the environment held, which Python read with `os.getenv`
/// and tested for truthiness — so an empty value falls through to a
/// generated password rather than being refused for being too short.
///
/// The length is in characters, not bytes: Python's `len` counts characters,
/// and a twelve-character password of non-ASCII would be refused here if
/// this counted bytes the other way round.
pub(crate) fn admin_password(raw: Option<&str>) -> Result<String, PasswordProblem> {
    match raw {
        Some(supplied) if !supplied.is_empty() => {
            if supplied.chars().count() < MIN_LENGTH {
                return Err(PasswordProblem::TooShort);
            }
            if supplied.chars().any(|c| FORBIDDEN.contains(&c)) {
                return Err(PasswordProblem::Forbidden);
            }
            Ok(supplied.to_string())
        }
        _ => Ok(generated_password()),
    }
}

/// Source: `"".join(secrets.choice(alphabet) for _ in range(24))`.
///
/// Delegated to the generator [`crate::mariadb::random_password`] already
/// uses: `seed.py` and `mariadb.py` are separate Python functions that
/// happen to spell the same alphabet, and a test below pins that agreement
/// rather than leaving it to be noticed when one of them changes.
fn generated_password() -> String {
    crate::mariadb::random_password(GENERATED_LENGTH)
}

/// What the run did, so the caller can print what Python printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admin {
    /// Carries the password, because this is the only moment anybody sees it.
    Created(String),
    AlreadyExists,
}

/// Source: `seed_admin`, minus the migration call — the schema is built
/// separately above.
///
/// `ensure_panel_user` runs in **both** cases, and that is Python's shape
/// rather than an oversight: the panel row and the Linux account are two
/// different things, and a box where the row survived a restore but the home
/// directory did not is exactly when this has to repair itself.
pub(crate) async fn seed_admin(db: &Database, dry_run: bool) -> anyhow::Result<Admin> {
    let users = db.users();
    let outcome = if users.by_username(ADMIN_USERNAME).await?.is_some() {
        Admin::AlreadyExists
    } else {
        let password = admin_password(std::env::var(PASSWORD_ENV).ok().as_deref())
            .map_err(|problem| anyhow::anyhow!("{}", problem.message()))?;
        let hashed = snpanel_core::crypto::password::hash_password(&password)
            .map_err(|e| anyhow::anyhow!("could not hash the admin password: {e}"))?;
        users
            .create(&NewUser {
                username: ADMIN_USERNAME,
                email: ADMIN_EMAIL,
                hashed_password: &hashed,
                role: ADMIN_ROLE,
                package_id: None,
                website_limit: ADMIN_WEBSITE_LIMIT,
                storage_limit_mb: ADMIN_STORAGE_LIMIT_MB,
                // Not in the Python's `User(...)`, so the column default
                // applies: `terminal_enabled BOOLEAN DEFAULT '0'`.
                terminal_enabled: false,
            })
            .await?;
        Admin::Created(password)
    };

    ensure_panel_user(
        dry_run,
        match &outcome {
            Admin::Created(password) => Some(password.as_str()),
            Admin::AlreadyExists => None,
        },
    )
    .await?;

    Ok(outcome)
}

/// Source: `site_users.ensure_panel_user`, for the admin account.
///
/// The password goes to the helper on **stdin** (C37). `/proc/<pid>/cmdline`
/// is world-readable and a hosting box runs other people's PHP.
async fn ensure_panel_user(dry_run: bool, password: Option<&str>) -> anyhow::Result<()> {
    let Ok(panel_user) = snpanel_core::types::PanelUsername::parse(ADMIN_USERNAME) else {
        anyhow::bail!("{ADMIN_USERNAME} is not a usable Linux account name");
    };
    let home = format!("{}/{}", snpanel_core::types::HOME_ROOT, panel_user.as_str());
    let ensured = crate::shell::privileged(
        dry_run,
        "panel-user-ensure",
        &[panel_user.as_str()],
        None,
        // Source: `fallback=["mkdir", "-p", str(HOME_ROOT / linux_user)]`.
        Some(&["mkdir", "-p", &home]),
    )
    .await;
    if !ensured.ok() {
        anyhow::bail!(
            "{}",
            ensured
                .failure_detail("Could not create the admin system account")
                .trim()
        );
    }

    if let Some(password) = password {
        let set = crate::shell::privileged(
            dry_run,
            "panel-user-password",
            &[panel_user.as_str()],
            Some(&format!("{password}\n")),
            // Source: `fallback=["true"]`.
            Some(&["true"]),
        )
        .await;
        if !set.ok() {
            anyhow::bail!(
                "{}",
                set.failure_detail("Could not set the admin system password")
                    .trim()
            );
        }
    }
    Ok(())
}

/// The whole subcommand: make the database if it is not there, build the
/// schema if it is empty, then seed.
///
/// Prints what `app.seed` printed. The installer shows those lines to
/// whoever ran it, and the password appears exactly once in the world.
pub(crate) async fn run(database_url: &str, dry_run: bool) -> anyhow::Result<()> {
    let db = Database::create(database_url).await?;

    match db.create_fresh_schema().await? {
        Bootstrap::Created => {
            println!(
                "Created the panel schema at Alembic revision {}",
                snpanel_db::schema::PYTHON_HEAD
            );
        }
        Bootstrap::AlreadyManaged => {}
        Bootstrap::LeftToPython => anyhow::bail!(
            "{database_url} has tables but has never been stamped by Alembic; that is the \
             pre-Alembic shape, and Python's own `run_migrations` is what upgrades it"
        ),
    }
    db.apply_rust_migrations().await?;

    match seed_admin(&db, dry_run).await? {
        // Source: `print(f"Created admin user: admin / {password}")`.
        Admin::Created(password) => println!("Created admin user: admin / {password}"),
        // Source: `print("Admin user already exists")`.
        Admin::AlreadyExists => println!("Admin user already exists"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_supplied_password_is_used_as_given() {
        assert_eq!(
            admin_password(Some("correct horse battery")).unwrap(),
            "correct horse battery"
        );
    }

    /// **An unset or empty variable generates rather than refuses.**
    ///
    /// `if password := os.getenv(...)` tests for truthiness, so `""` is the
    /// same as absent. Treating it as a zero-length password would refuse
    /// the install with "must be at least 12 characters" over a variable
    /// nobody set.
    #[test]
    fn nothing_supplied_means_a_generated_password() {
        for raw in [None, Some("")] {
            let generated = admin_password(raw).unwrap();
            assert_eq!(generated.chars().count(), GENERATED_LENGTH);
        }
        assert_ne!(
            admin_password(None).unwrap(),
            admin_password(None).unwrap(),
            "two installs must not get the same admin password"
        );
    }

    #[test]
    fn a_short_password_is_refused_with_pythons_words() {
        let eleven = "a".repeat(MIN_LENGTH - 1);
        assert_eq!(
            admin_password(Some(&eleven)).unwrap_err().message(),
            "SNPANEL_ADMIN_PASSWORD must be at least 12 characters"
        );
        // The boundary itself is accepted: `< 12`, not `<= 12`.
        let twelve = "a".repeat(MIN_LENGTH);
        assert_eq!(admin_password(Some(&twelve)).unwrap(), twelve);
    }

    /// **Length is counted in characters, as Python counts it.**
    ///
    /// Twelve non-ASCII characters are more than twelve bytes. Counting
    /// bytes would accept this too — the interesting direction is the other
    /// one, so the case that would actually differ is the one tested: a
    /// password of eleven multi-byte characters is 22 bytes, which a byte
    /// count would wave through.
    #[test]
    fn the_length_is_characters_and_not_bytes() {
        let eleven_chars = "é".repeat(11);
        assert_eq!(
            eleven_chars.len(),
            22,
            "eleven characters, twenty-two bytes"
        );
        assert_eq!(
            admin_password(Some(&eleven_chars)),
            Err(PasswordProblem::TooShort)
        );
    }

    /// **Each forbidden character is refused, and for a stated reason.**
    ///
    /// A colon ends the username field in `chpasswd`; a newline ends the
    /// line; a NUL ends the C string. Any of the three sets the Linux
    /// account to a password the panel did not record, which locks the
    /// operator out of the box they just installed.
    #[test]
    fn the_characters_that_would_truncate_the_password_are_refused() {
        for bad in FORBIDDEN {
            let password = format!("abcdefghijkl{bad}mnop");
            assert_eq!(
                admin_password(Some(&password)),
                Err(PasswordProblem::Forbidden),
                "{bad:?} should be refused"
            );
        }
    }

    /// **`seed.py` and `mariadb.py` still spell the same alphabet.**
    ///
    /// They are separate Python functions, so the agreement is a fact about
    /// today rather than a guarantee. Generating here and comparing the
    /// character set is what turns a silent divergence into a failure: a
    /// character added to one and not the other shows up as a character
    /// outside [`GENERATED_ALPHABET`].
    #[test]
    fn the_generated_password_uses_the_alphabet_python_uses() {
        let expected: std::collections::BTreeSet<char> = GENERATED_ALPHABET.chars().collect();
        assert_eq!(expected.len(), 71, "26 + 26 + 10 + 9, all distinct");

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..500 {
            for c in generated_password().chars() {
                assert!(expected.contains(&c), "{c:?} is not in Python's alphabet");
                seen.insert(c);
            }
        }
        // 12000 draws from 71 symbols: missing one has probability about
        // 71 * (70/71)^12000, which is far below any rate that matters.
        assert_eq!(
            seen, expected,
            "some character of the alphabet never appeared"
        );
    }

    /// **A generated password is never one the seed would then refuse.**
    ///
    /// The alphabet and the forbidden list are two separate constants, and
    /// nothing else would notice if a `:` were added to the first of them —
    /// the install would simply start failing at a rate of about one in
    /// three.
    #[test]
    fn a_generated_password_passes_the_check_a_supplied_one_gets() {
        for _ in 0..200 {
            let generated = generated_password();
            assert_eq!(admin_password(Some(&generated)).unwrap(), generated);
        }
    }
}
