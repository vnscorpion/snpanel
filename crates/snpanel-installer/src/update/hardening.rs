//! Bringing an older box's customer accounts up to the current permissions.
//!
//! Source: `harden_existing_panel_users`.
//!
//! Every panel release that tightened something left the boxes installed
//! before it as they were. This phase closes that gap, and it is the single
//! most dangerous thing in the update script: it runs `usermod`, `chown -R`
//! and `chmod -R` as root over directories whose names came from customers.
//!
//! Two guards do all the work, and both are here with tests:
//!
//! * a list of accounts that are **never** touched, because
//!   `usermod --home /home/root --shell /usr/sbin/nologin root` is not a
//!   recoverable mistake;
//! * a name check before any recursive rewrite, so `chown -R` only ever
//!   descends into something shaped like a domain.

/// Accounts this phase never touches.
///
/// Membership of `snpanel-sftp` is what selects a customer, and a system
/// account that ended up in that group — by an operator's hand, or by an
/// older bug — must not be reshaped into one. `root` is in the list for the
/// obvious reason; so is `snpanel` itself, whose home is the application
/// directory rather than `/home/snpanel`, and `mysql`, whose home is the
/// database.
pub const NEVER_TOUCH: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "_apt",
    "nobody",
    "snpanel",
    "snpanel-sites",
    "snpanel-sftp",
    "mysql",
    "redis",
    "nginx",
];

pub fn may_harden(user: &str) -> bool {
    !user.is_empty() && !NEVER_TOUCH.contains(&user)
}

/// `/home` itself: `root:root`, mode `0711`.
///
/// `0711` and not `0755`: others may traverse into a home they already know
/// the name of, and may **not list** the directory. Without that, any
/// customer with a shell — or any PHP script on any site — can enumerate
/// every other customer's username, which is half of a credential.
pub const HOME_ROOT_MODE: u32 = 0o711;

/// A customer's home: `root:<user>`, mode `0751`.
///
/// Owned by **root**, not by the customer, which is the point: a home the
/// customer owns is a home they can `chmod 777`, and then the traversal
/// restriction above protects nothing. The group is their own, so they can
/// still read it; others get traverse only, for the same reason as `/home`.
pub const HOME_MODE: u32 = 0o751;

/// Inside a site: directories `0755`, ordinary files `0644`.
pub const SITE_DIR_MODE: u32 = 0o755;
pub const SITE_FILE_MODE: u32 = 0o644;

/// Files that hold credentials, tightened to `0640`.
///
/// `wp-config.php` holds the site's database password, `.env` whatever the
/// application put there, and `.my.cnf` a MySQL password in the clear. At
/// `0644` every other customer's PHP can read them — the web server runs
/// their code too.
pub const SECRET_FILES: &[&str] = &["wp-config.php", ".env", ".my.cnf"];
pub const SECRET_FILE_MODE: u32 = 0o640;

/// The PHP upload staging directory: `2700`, plus setgid.
///
/// `0700` so no other customer can read a half-uploaded file, and setgid so
/// what lands there belongs to the site group rather than to whoever wrote
/// it.
pub const UPLOAD_DIR_MODE: u32 = 0o2700;

/// Whether a directory under a customer's home is a site.
///
/// Reproduces the shell's
/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`
/// exactly, and it is worth being precise about because this is the guard
/// in front of `chown -R` and `chmod -R`. The `+` on the second group means
/// **at least one dot is required**, so `public_html`, `backups`, `.ssh`
/// and `tmp` are all left alone.
///
/// Deliberately *not* [`snpanel_core::Domain`]: that one accepts a
/// single-label name like `localhost`, and accepting one here would point a
/// recursive chown at a directory this was never meant to descend into.
pub fn looks_like_site_dir(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut labels = name.split('.');
    let Some(first) = labels.next() else {
        return false;
    };
    if !label_ok(first) {
        return false;
    }
    let mut any = false;
    for label in labels {
        if !label_ok(label) {
            return false;
        }
        any = true;
    }
    // The trailing group is `+`, so a bare label is not a site.
    any
}

/// `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`
fn label_ok(label: &str) -> bool {
    let b = label.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    let ok = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !ok(b[0]) {
        return false;
    }
    if b.len() == 1 {
        return true;
    }
    if !ok(b[b.len() - 1]) {
        return false;
    }
    b[1..b.len() - 1].iter().all(|c| ok(*c) || *c == b'-')
}

/// The members of `snpanel-sftp`, out of a `getent group` line.
///
/// `name:x:gid:a,b,c` — the fourth colon-separated field, split on commas.
/// An empty field is no members, not one member with an empty name.
pub fn group_members(getent_line: &str) -> Vec<&str> {
    let Some(field) = getent_line.split(':').nth(3) else {
        return Vec::new();
    };
    field.split(',').filter(|m| !m.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `usermod --home /home/root --shell /usr/sbin/nologin root` is not a
    /// recoverable mistake, and membership of a group is not a reason to do
    /// it.
    #[test]
    fn no_system_account_is_ever_reshaped() {
        for account in NEVER_TOUCH {
            assert!(!may_harden(account), "{account}");
        }
        assert!(!may_harden("root"));
        assert!(!may_harden(""));
        // An ordinary customer is.
        assert!(may_harden("acme"));
        assert!(may_harden("customer1"));
    }

    /// The panel's own account is in the list too: its home is the
    /// application directory, not `/home/snpanel`, and moving it would take
    /// the panel down.
    #[test]
    fn the_panels_own_accounts_are_in_the_list() {
        for account in ["snpanel", "snpanel-sites", "snpanel-sftp"] {
            assert!(NEVER_TOUCH.contains(&account), "{account}");
        }
        // And the three service accounts whose homes are not homes.
        for account in ["mysql", "redis", "nginx", "www-data"] {
            assert!(NEVER_TOUCH.contains(&account), "{account}");
        }
    }

    /// The guard in front of `chown -R`. At least one dot is required, so
    /// the directories a customer actually has in their home are left
    /// alone.
    #[test]
    fn only_a_domain_shaped_directory_is_recursively_rewritten() {
        for site in [
            "example.com",
            "a.b",
            "sub.example.co.uk",
            "x1-y2.example.com",
            "1.2",
        ] {
            assert!(looks_like_site_dir(site), "{site}");
        }
        for other in [
            "public_html",
            "backups",
            "tmp",
            ".ssh",
            "..",
            ".",
            "",
            "Example.com",
            "-example.com",
            "example-.com",
            "example..com",
            "example.com.",
            ".example.com",
            "exam ple.com",
            "example.com/../..",
        ] {
            assert!(!looks_like_site_dir(other), "{other:?}");
        }
    }

    /// The label length limit, checked against the shell's own `=~` rather
    /// than against my reading of `{0,61}`: the first and last characters
    /// sit outside the repetition, so sixty-three is the longest label and
    /// sixty-four is not a label at all.
    #[test]
    fn a_label_of_sixty_four_characters_is_not_a_label() {
        let sixty_three = "a".repeat(63);
        let sixty_four = "a".repeat(64);
        assert!(looks_like_site_dir(&format!("{sixty_three}.com")));
        assert!(!looks_like_site_dir(&format!("{sixty_four}.com")));
        // Hyphens in the middle, including two in a row, are fine.
        assert!(looks_like_site_dir("a-b.com"));
        assert!(looks_like_site_dir("a--b.com"));
    }

    /// A path separator in the name would make the recursive chown descend
    /// somewhere else entirely, so it can never match.
    #[test]
    fn nothing_with_a_path_separator_is_a_site() {
        for name in ["a/b", "../etc", "a.com/../..", "/etc", "a.com/"] {
            assert!(!looks_like_site_dir(name), "{name}");
        }
    }

    /// A single label is not a site, which is the difference from
    /// `Domain::parse` — accepting `localhost` here would point a recursive
    /// chown at a directory this was never meant to descend into.
    #[test]
    fn a_single_label_is_not_a_site() {
        assert!(!looks_like_site_dir("localhost"));
        assert!(!looks_like_site_dir("wordpress"));
    }

    /// `0711`: others may traverse into a home whose name they already
    /// know, and may not list `/home`. Without that, any customer's PHP can
    /// enumerate every other customer's username.
    #[test]
    fn no_customer_can_list_the_other_customers() {
        assert_eq!(HOME_ROOT_MODE & 0o004, 0, "others can read /home");
        assert_eq!(
            HOME_ROOT_MODE & 0o001,
            0o001,
            "others cannot traverse /home"
        );
        assert_eq!(HOME_ROOT_MODE & 0o022, 0);
    }

    /// A home the customer owns is a home they can `chmod 777`, and then
    /// the traversal restriction protects nothing.
    #[test]
    fn a_customer_does_not_own_their_own_home_directory() {
        // Group-readable for the customer, traverse-only for everyone else,
        // and not writable by either.
        assert_eq!(HOME_MODE & 0o040, 0o040);
        assert_eq!(HOME_MODE & 0o020, 0);
        assert_eq!(HOME_MODE & 0o001, 0o001);
        assert_eq!(HOME_MODE & 0o006, 0);
    }

    /// The web server runs every customer's code, so a credential file any
    /// other customer's PHP can read is a credential every customer has.
    #[test]
    fn the_credential_files_are_not_world_readable() {
        assert_eq!(SECRET_FILE_MODE & 0o007, 0);
        assert_eq!(SECRET_FILE_MODE & 0o040, 0o040);
        assert!(SECRET_FILES.contains(&"wp-config.php"));
        assert!(SECRET_FILES.contains(&".env"));
        assert!(SECRET_FILES.contains(&".my.cnf"));
        // And they are tighter than an ordinary file, which is the whole
        // point of listing them separately.
        assert_ne!(SECRET_FILE_MODE, SITE_FILE_MODE);
        const { assert!(SECRET_FILE_MODE & 0o007 < SITE_FILE_MODE & 0o007) };
    }

    /// Nothing under a site is executable-by-mode or writable by others. A
    /// setuid file in a customer's tree is a privilege escalation, which is
    /// why the phase strips those bits everywhere as well.
    #[test]
    fn nothing_in_a_site_is_writable_by_others() {
        for mode in [SITE_DIR_MODE, SITE_FILE_MODE, SECRET_FILE_MODE] {
            assert_eq!(mode & 0o002, 0, "{mode:o}");
            assert_eq!(mode & 0o4000, 0, "{mode:o} is setuid");
            assert_eq!(mode & 0o2000, 0, "{mode:o} is setgid");
        }
    }

    /// `0700` so no other customer can read a half-uploaded file, and
    /// setgid so what lands there belongs to the site group rather than to
    /// whoever wrote it.
    #[test]
    fn the_upload_directory_is_private_and_setgid() {
        assert_eq!(UPLOAD_DIR_MODE & 0o077, 0);
        assert_eq!(UPLOAD_DIR_MODE & 0o2000, 0o2000);
        assert_eq!(UPLOAD_DIR_MODE & 0o700, 0o700);
    }

    #[test]
    fn the_members_come_out_of_the_fourth_field() {
        assert_eq!(
            group_members("snpanel-sftp:x:1001:acme,beta,gamma"),
            ["acme", "beta", "gamma"]
        );
        // An empty field is no members, not one member with an empty name —
        // which would otherwise be passed to `usermod` as an argument.
        assert!(group_members("snpanel-sftp:x:1001:").is_empty());
        assert!(group_members("snpanel-sftp:x:1001:,,").is_empty());
        assert!(group_members("nonsense").is_empty());
        // Trailing commas do not produce a phantom member either.
        assert_eq!(group_members("g:x:1:a,,b,"), ["a", "b"]);
    }

    /// The two guards compose: a system account in the group is skipped
    /// even though it is a member, and a non-site directory is skipped even
    /// inside an account that is being hardened.
    #[test]
    fn the_two_guards_compose() {
        let members = group_members("snpanel-sftp:x:1001:root,acme,mysql,beta");
        let hardened: Vec<&str> = members.into_iter().filter(|m| may_harden(m)).collect();
        assert_eq!(hardened, ["acme", "beta"]);
    }
}
