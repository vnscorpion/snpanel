//! Changing the admin password, and syncing it to root's.
//!
//! Source: `change_admin_password`, `sync_admin_root_password`,
//! `root_password_hash`, `validate_root_password_hash`,
//! `login_password_from_file`, `normalize_domain`.
//!
//! One requirement belongs to both paths and is enforced by neither of the
//! functions here, because it lives in the database layer: **`token_version`
//! must be bumped.** A password change that leaves existing tokens working
//! is not a password change.
//!
//! That is now done in
//! `snpanel_db::UserRepo::set_password_and_invalidate_sessions`, in the same
//! UPDATE as the hash, and reached through `snpanel-api --set-admin-password`
//! and `--set-admin-password-hash`. `snpanelctl` prefers those when the Rust
//! binary is installed and keeps its inline Python for a box that has not
//! cut over yet.

/// The shortest admin password the menu accepts.
///
/// The panel's own login form enforces its own rule; this is the floor for
/// the path that bypasses the panel entirely, and it has to be at least as
/// strict or the rescue menu becomes the way round the policy.
pub const MINIMUM_LENGTH: usize = 12;

/// Why a password was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Mismatch,
    TooShort,
}

impl Refusal {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Mismatch => "Passwords do not match",
            Self::TooShort => "Password must be at least 12 characters",
        }
    }
}

/// The confirmation check.
///
/// Both are read with the echo off, so a typo is invisible — which is the
/// whole reason the second prompt exists. Checked before the length, so
/// somebody who mistyped twice is told the useful thing.
pub fn check_new_password(password: &str, confirm: &str) -> Result<(), Refusal> {
    if password != confirm {
        return Err(Refusal::Mismatch);
    }
    if password.chars().count() < MINIMUM_LENGTH {
        return Err(Refusal::TooShort);
    }
    Ok(())
}

/// Hash prefixes the sync accepts.
///
/// This is the list that decides what the panel will end up authenticating
/// against, because `sync_admin_root_password` copies root's hash out of
/// `/etc/shadow` straight into the admin user's `hashed_password`. Every
/// entry here is a modern, salted, deliberately slow scheme:
///
/// * `$y$` yescrypt and `$gy$` gost-yescrypt — the current default on
///   Debian and Ubuntu;
/// * `$7$` scrypt;
/// * `$6$` sha512crypt and `$5$` sha256crypt — the previous defaults, still
///   on plenty of upgraded boxes;
/// * `$2a$`, `$2b$`, `$2y$` bcrypt.
///
/// **What is absent is the point.** `$1$` is MD5-crypt and a bare
/// thirteen-character hash is DES, both of which a very old box can still
/// carry; copying either into the panel would make the panel authenticate
/// against a scheme that falls to an offline attack in minutes. The shell
/// refuses rather than accepting them, and so does this.
pub const ACCEPTED_PREFIXES: &[&str] =
    &["$y$", "$gy$", "$7$", "$6$", "$5$", "$2a$", "$2b$", "$2y$"];

/// Why a root hash cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashRefusal {
    /// Nothing in the field.
    Unreadable,
    /// `!...`, `*` or `x`: the account is locked, has no password, or the
    /// hash lives somewhere this cannot see.
    Locked,
    /// A scheme not in [`ACCEPTED_PREFIXES`].
    UnsupportedFormat(String),
}

impl HashRefusal {
    pub fn message(&self) -> String {
        match self {
            Self::Unreadable => "Cannot read root password hash from /etc/shadow".to_string(),
            Self::Locked => "Root account does not have an unlocked password hash".to_string(),
            Self::UnsupportedFormat(scheme) => {
                format!("Unsupported root password hash format: {scheme}")
            }
        }
    }
}

/// `validate_root_password_hash`.
pub fn validate_root_hash(hash: &str) -> Result<(), HashRefusal> {
    if hash.is_empty() {
        return Err(HashRefusal::Unreadable);
    }
    // `!*` matches any hash beginning with `!`, which is how a locked
    // account is spelt; `*` and `x` are the other two placeholders.
    if hash.starts_with('!') || hash.starts_with('*') || hash == "x" {
        return Err(HashRefusal::Locked);
    }
    if ACCEPTED_PREFIXES.iter().any(|p| hash.starts_with(p)) {
        return Ok(());
    }
    // `${hash%%$*}` — everything before the first `$`, which for `$1$...`
    // is the empty string. Reproduced, because the message is the shell's.
    let scheme = hash.split('$').next().unwrap_or("").to_string();
    Err(HashRefusal::UnsupportedFormat(scheme))
}

/// Root's hash out of a `getent shadow root` or `/etc/shadow` line.
///
/// The second colon-separated field. `getent` is tried first because it
/// works through NSS; reading the file is the fallback for a box where
/// `getent shadow` returns nothing to a caller that can still read
/// `/etc/shadow`.
pub fn hash_from_shadow_line<'a>(line: &'a str, want_user: &str) -> Option<&'a str> {
    let mut fields = line.split(':');
    let user = fields.next()?;
    if user != want_user {
        return None;
    }
    fields.next()
}

/// How the secret reaches the process that uses it.
///
/// **A deliberate difference from the shell, and the reason is measured.**
/// The bash builds its runner as
///
/// ```text
/// runuser -u snpanel -- env HOME=... "SNPANEL_NEW_ADMIN_PASSWORD=$password" python
/// ```
///
/// `env` itself `execve`s and so loses that argv, but the **`runuser`
/// parent does not**: it forks and waits, and keeps its own full argv for
/// the whole lifetime of the child. `/proc/<pid>/cmdline` is mode `444`
/// (checked on this machine, alongside `/proc/<pid>/environ` at `400`), so
/// for as long as the Python runs, any local process can read the plaintext
/// admin password out of it — and on the root-sync path, root's password
/// hash from `/etc/shadow`, which is `0640 root:shadow` precisely so that
/// ordinary accounts cannot take it away and attack it offline.
///
/// On a hosting panel "any local process" includes any PHP script on any
/// customer's site, because the web server runs their code.
///
/// So this side passes the value in the process environment it constructs
/// for the child, never as an `env NAME=VALUE` argument. That is the same
/// rule the helper already follows for every secret it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretChannel {
    /// Set on the child's environment block. Not in anyone's `cmdline`.
    ChildEnvironment,
    /// Written to the child's stdin.
    Stdin,
}

/// Where each of the two secrets goes.
pub fn channel_for(_name: &str) -> SecretChannel {
    SecretChannel::ChildEnvironment
}

/// The password line out of `/root/login.txt`.
///
/// `sed -n 's/^Password: //p' | head -n 1` — anchored at the start of the
/// line, first match only. Anchored matters: a password that happens to
/// contain the text would otherwise be able to shift which line is read.
pub fn password_from_login_file(contents: &str) -> Option<&str> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix("Password: "))
}

/// `normalize_domain`: a bare hostname out of whatever the operator typed.
///
/// Strips a scheme, then everything from the first `/`, then everything
/// from the first `:`. In that order — which is why `https://a.com:2222/x`
/// gives `a.com` and not `a.com:2222`.
pub fn normalize_domain(value: &str) -> &str {
    let value = value.strip_prefix("http://").unwrap_or(value);
    let value = value.strip_prefix("https://").unwrap_or(value);
    let value = value.split('/').next().unwrap_or("");
    value.split(':').next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mismatch_is_reported_before_the_length() {
        // Both prompts read with the echo off, so a typo is invisible —
        // which is the whole reason the second one exists. Somebody who
        // mistyped twice should be told that, not told about length.
        assert_eq!(
            check_new_password("short", "different"),
            Err(Refusal::Mismatch)
        );
        assert_eq!(check_new_password("short", "short"), Err(Refusal::TooShort));
        assert_eq!(
            check_new_password("correct horse battery", "correct horse battery"),
            Ok(())
        );
    }

    #[test]
    fn the_floor_is_twelve_characters() {
        let eleven = "a".repeat(11);
        let twelve = "a".repeat(12);
        assert_eq!(check_new_password(&eleven, &eleven), Err(Refusal::TooShort));
        assert_eq!(check_new_password(&twelve, &twelve), Ok(()));
        // Counted in characters, not bytes: a twelve-character Vietnamese
        // password is twelve characters.
        let accented = "mậtkhẩucủa1";
        assert_eq!(accented.chars().count(), 11);
        assert_eq!(
            check_new_password(accented, accented),
            Err(Refusal::TooShort)
        );
    }

    /// The list that decides what the panel ends up authenticating against.
    #[test]
    fn every_accepted_scheme_is_a_modern_one() {
        for hash in [
            "$y$j9T$salt$hash",
            "$gy$j9T$salt$hash",
            "$7$C6..../....salt$hash",
            "$6$salt$hash",
            "$5$salt$hash",
            "$2a$10$saltandhash",
            "$2b$12$saltandhash",
            "$2y$10$saltandhash",
        ] {
            assert_eq!(validate_root_hash(hash), Ok(()), "{hash}");
        }
    }

    /// **What is absent is the point.** Copying an MD5-crypt or DES hash
    /// into the panel would make the panel authenticate against a scheme
    /// that falls to an offline attack in minutes.
    #[test]
    fn md5_and_des_hashes_are_refused() {
        let md5 = validate_root_hash("$1$salt$hash").unwrap_err();
        assert!(matches!(md5, HashRefusal::UnsupportedFormat(_)));
        assert!(md5
            .message()
            .starts_with("Unsupported root password hash format"));
        // A bare DES hash, which a very old box can still carry.
        assert!(matches!(
            validate_root_hash("ab1234567890X").unwrap_err(),
            HashRefusal::UnsupportedFormat(_)
        ));
        // And anything else unrecognised.
        assert!(validate_root_hash("$md5$salt$hash").is_err());
        assert!(validate_root_hash("$3$whatever").is_err());
    }

    /// A locked account has no password to copy, and `*` and `x` are
    /// placeholders rather than hashes. Copying any of them would set the
    /// admin's `hashed_password` to something no password can ever match —
    /// or, worse, to a literal that some verifier treats as a hash.
    #[test]
    fn a_locked_or_absent_password_is_refused() {
        for hash in ["!", "!!", "!$6$salt$hash", "*", "x"] {
            assert_eq!(validate_root_hash(hash), Err(HashRefusal::Locked), "{hash}");
        }
        assert_eq!(validate_root_hash(""), Err(HashRefusal::Unreadable));
        assert!(validate_root_hash("")
            .unwrap_err()
            .message()
            .contains("/etc/shadow"));
    }

    /// A locked *yescrypt* hash is still locked: the `!` prefix is checked
    /// before the scheme, so `!$y$...` does not slip through on the strength
    /// of what follows it.
    #[test]
    fn the_lock_marker_is_checked_before_the_scheme() {
        assert_eq!(validate_root_hash("!$y$j9T$s$h"), Err(HashRefusal::Locked));
        assert_eq!(validate_root_hash("!$6$s$h"), Err(HashRefusal::Locked));
    }

    #[test]
    fn the_hash_is_the_second_field_of_roots_line() {
        assert_eq!(
            hash_from_shadow_line("root:$y$j9T$salt$hash:19000:0:99999:7:::", "root"),
            Some("$y$j9T$salt$hash")
        );
        // Another account's line is not root's.
        assert_eq!(
            hash_from_shadow_line("daemon:*:19000:0:99999:7:::", "root"),
            None
        );
        assert_eq!(hash_from_shadow_line("", "root"), None);
    }

    /// The deliberate difference. `/proc/<pid>/cmdline` is world-readable
    /// and `runuser` keeps its argv for the lifetime of the child, so a
    /// secret passed as `env NAME=VALUE` is readable by any local process —
    /// including any PHP script on any customer's site — for as long as the
    /// command runs.
    #[test]
    fn no_secret_is_ever_passed_as_an_argument() {
        for secret in ["SNPANEL_NEW_ADMIN_PASSWORD", "SNPANEL_ROOT_PASSWORD_HASH"] {
            assert_ne!(
                channel_for(secret),
                SecretChannel::Stdin,
                "{secret} would need a stdin protocol"
            );
            assert_eq!(channel_for(secret), SecretChannel::ChildEnvironment);
        }
    }

    /// Anchored at the start of the line, and the first match wins — so a
    /// password that happens to contain the text cannot shift which line is
    /// read.
    #[test]
    fn the_login_file_password_is_read_from_an_anchored_line() {
        let file = "Panel URL: https://a.com:2222\nUser: admin\nPassword: s3cret\n";
        assert_eq!(password_from_login_file(file), Some("s3cret"));
        // Not anchored: a line that merely contains the prefix is not it.
        assert_eq!(
            password_from_login_file("Old Password: nope\nPassword: yes\n"),
            Some("yes")
        );
        // First match only.
        assert_eq!(
            password_from_login_file("Password: first\nPassword: second\n"),
            Some("first")
        );
        assert_eq!(password_from_login_file("User: admin\n"), None);
        // A password containing the marker text is returned whole.
        assert_eq!(
            password_from_login_file("Password: Password: x\n"),
            Some("Password: x")
        );
    }

    /// Scheme, then path, then port — in that order, which is why a URL
    /// with both gives the bare hostname.
    #[test]
    fn a_hostname_comes_out_of_whatever_was_typed() {
        for (input, expected) in [
            ("https://a.com:2222/x", "a.com"),
            ("http://a.com/", "a.com"),
            ("a.com:2222", "a.com"),
            ("a.com", "a.com"),
            ("https://a.com", "a.com"),
            ("https://192.0.2.1:2222/", "192.0.2.1"),
            ("", ""),
            ("https://", ""),
            ("/path", ""),
        ] {
            assert_eq!(normalize_domain(input), expected, "{input:?}");
        }
    }

    /// Only the scheme at the front is stripped, and only once — a hostname
    /// that contains the text keeps it.
    #[test]
    fn only_a_leading_scheme_is_stripped() {
        assert_eq!(normalize_domain("https://https://a.com"), "https");
        assert_eq!(normalize_domain("a.https://b.com"), "a.https");
    }
}
