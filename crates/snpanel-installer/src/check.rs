//! Did this installation come out right?
//!
//! Source: `installer/files/platform-check.sh`.
//!
//! Run as root after an install. Its governing idea is worth keeping
//! verbatim, because it is what makes the check worth running at all: it
//! **asks the machine rather than assuming a distribution**. A verification
//! script that carried the same per-platform table as the installer would
//! agree with the installer about everything, including the things the
//! installer got wrong.
//!
//! So the web server's account comes out of `nginx.conf`, the
//! Redis-compatible unit is whichever one exists, phpMyAdmin's paths are
//! found rather than guessed, and which PHP versions are installed is read
//! off the filesystem.

/// The web server's account, from the `user` directive in `nginx.conf`.
///
/// Reproduces `awk '$1=="user"{gsub(/;/,"",$2); print $2; exit}'`, which
/// means: the first line whose first whitespace-separated field is exactly
/// `user`, and then **every** semicolon removed from the second field — not
/// just a trailing one. First match only.
///
/// `$1=="user"` is an exact comparison, so `user_something` does not match
/// and a commented `# user nginx;` does not either, because its first field
/// is the `#`. A `#user nginx;` with no space does not match for the same
/// reason. All checked against the real awk.
pub fn nginx_user(conf: &str) -> Option<&str> {
    for line in conf.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("user") {
            continue;
        }
        let Some(value) = fields.next() else {
            continue;
        };
        return Some(value);
    }
    None
}

/// The same, with the semicolons stripped as `gsub` strips them.
pub fn nginx_user_name(conf: &str) -> Option<String> {
    nginx_user(conf).map(|v| v.replace(';', ""))
}

/// When `nginx.conf` says nothing, the check assumes Debian's account
/// rather than giving up — a conf with no `user` directive is nginx running
/// as its compiled-in default, which on the Debian family is this.
pub const DEFAULT_WEB_USER: &str = "www-data";

/// Redis-compatible units, in the order the check looks.
///
/// EL10 ships no `redis` package at all — it was replaced by Valkey — so the
/// check cannot ask for one name. `redis-server` first because that is
/// Debian's, then `valkey`, then the bare `redis` some builds still use.
pub const REDIS_UNITS: &[&str] = &["redis-server", "valkey", "redis"];

/// phpMyAdmin's document root and configuration directory, in the order the
/// check looks.
///
/// **The capitalised spelling first, on both platforms.** EPEL capitalises
/// and Debian does not, and on a case-insensitive filesystem looking for the
/// lowercase one first would find the capitalised directory under the wrong
/// name — which then goes into a path the web server is given.
pub const PMA_ROOTS: &[&str] = &["/usr/share/phpMyAdmin", "/usr/share/phpmyadmin"];
pub const PMA_CONFS: &[&str] = &["/etc/phpMyAdmin", "/etc/phpmyadmin"];

/// The first candidate that exists.
pub fn first_present<'a>(candidates: &[&'a str], exists: impl Fn(&str) -> bool) -> Option<&'a str> {
    candidates.iter().copied().find(|c| exists(c))
}

/// PHP versions the check looks for, oldest first.
///
/// Which versions exist is a property of the machine, not a constant.
/// Hardcoding the current default would have this script report a correctly
/// installed box as missing its PHP the moment the default moved.
pub const PHP_CANDIDATES: &[&str] = &["8.1", "8.2", "8.3", "8.4", "8.5"];

/// Where a version's presence is read from.
pub fn php_fpm_dir(version: &str) -> String {
    format!("/etc/php/{version}/fpm")
}

/// The versions present, and the one the installer would have made default.
///
/// The default is the **newest present**, which is the rule the installer
/// follows — so a box with 8.3 and 8.4 defaults to 8.4, and a box with only
/// 8.2 defaults to 8.2 rather than to nothing.
pub fn php_present(exists: impl Fn(&str) -> bool) -> (Vec<&'static str>, Option<&'static str>) {
    let present: Vec<&'static str> = PHP_CANDIDATES
        .iter()
        .copied()
        .filter(|v| exists(&php_fpm_dir(v)))
        .collect();
    let default = present.last().copied();
    (present, default)
}

/// The three counters the check keeps, and the exit code they add up to.
///
/// Source: `ok`, `bad` and `skip`, which are one line each — a `printf` and
/// an increment. What is worth porting is not the printing but the
/// distinction the three of them draw, which is the method below.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub pass: u32,
    pub fail: u32,
    pub skip: u32,
}

impl Tally {
    /// A skip is **not** a failure.
    ///
    /// The script skips what a box legitimately does not have — no
    /// phpMyAdmin, no WAF engine on EL — and a check that counted those as
    /// failures would report every correctly installed AlmaLinux box as
    /// broken, which teaches operators to ignore it.
    pub fn failed(&self) -> bool {
        self.fail > 0
    }
}

/// The panel is asked over loopback, like everything else the installer
/// checks.
pub fn base_url(panel_port: u16) -> String {
    format!("https://127.0.0.1:{panel_port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checked against the real `awk`, case by case, rather than read off
    /// the expression.
    #[test]
    fn the_web_user_comes_out_of_the_conf_as_awk_reads_it() {
        assert_eq!(
            nginx_user_name("user www-data;").as_deref(),
            Some("www-data")
        );
        assert_eq!(nginx_user_name("    user nginx;").as_deref(), Some("nginx"));
        assert_eq!(nginx_user_name("\tuser nginx;").as_deref(), Some("nginx"));
        // A group after the user is a second field and is ignored.
        assert_eq!(
            nginx_user_name("user nginx nginx;").as_deref(),
            Some("nginx")
        );
        // No semicolon at all still yields the name.
        assert_eq!(nginx_user_name("user nginx").as_deref(), Some("nginx"));
        // First match only.
        assert_eq!(
            nginx_user_name("# comment\nuser nginx;\nuser other;").as_deref(),
            Some("nginx")
        );
        assert_eq!(
            nginx_user_name("worker_processes auto;\nuser nginx;").as_deref(),
            Some("nginx")
        );
    }

    /// `$1=="user"` is an exact comparison, so a commented directive is not
    /// one — its first field is the `#` — and neither is a longer
    /// directive that merely starts with the word.
    #[test]
    fn a_commented_or_longer_directive_is_not_the_user_directive() {
        assert_eq!(nginx_user_name("# user nginx;"), None);
        assert_eq!(nginx_user_name("#user nginx;"), None);
        assert_eq!(nginx_user_name("user_something nginx;"), None);
        assert_eq!(nginx_user_name(""), None);
        assert_eq!(nginx_user_name("user"), None);
    }

    /// `gsub` removes **every** semicolon from the field, not just a
    /// trailing one. Verified against awk; a `strip_suffix` would give
    /// `ng;inx;` here.
    #[test]
    fn every_semicolon_is_removed_and_not_only_the_last() {
        assert_eq!(nginx_user_name("user ng;inx;;").as_deref(), Some("nginx"));
    }

    /// EL10 ships no `redis` package at all, so the check cannot ask for one
    /// name.
    #[test]
    fn the_cache_unit_is_whichever_one_exists() {
        assert_eq!(REDIS_UNITS[0], "redis-server");
        assert!(REDIS_UNITS.contains(&"valkey"));
        let debian = first_present(REDIS_UNITS, |u| u == "redis-server");
        assert_eq!(debian, Some("redis-server"));
        let el = first_present(REDIS_UNITS, |u| u == "valkey");
        assert_eq!(el, Some("valkey"));
        assert_eq!(first_present(REDIS_UNITS, |_| false), None);
    }

    /// The capitalised spelling is looked for first on both platforms: on a
    /// case-insensitive filesystem, checking the lowercase one first would
    /// find EPEL's directory under a name the web server is then given.
    #[test]
    fn phpmyadmin_is_found_under_whichever_spelling_the_platform_uses() {
        assert_eq!(PMA_ROOTS[0], "/usr/share/phpMyAdmin");
        assert_eq!(PMA_CONFS[0], "/etc/phpMyAdmin");
        assert_eq!(
            first_present(PMA_ROOTS, |p| p == "/usr/share/phpmyadmin"),
            Some("/usr/share/phpmyadmin")
        );
        assert_eq!(
            first_present(PMA_ROOTS, |p| p == "/usr/share/phpMyAdmin"),
            Some("/usr/share/phpMyAdmin")
        );
        // A box without it at all is not an error here; the caller reports
        // "not installed".
        assert_eq!(first_present(PMA_ROOTS, |_| false), None);
    }

    /// Hardcoding the current default would have this report a correctly
    /// installed box as missing its PHP the moment the default moved.
    #[test]
    fn the_php_versions_are_read_off_the_machine() {
        let (present, default) =
            php_present(|d| d == "/etc/php/8.3/fpm" || d == "/etc/php/8.4/fpm");
        assert_eq!(present, ["8.3", "8.4"]);
        assert_eq!(default, Some("8.4"));
    }

    /// The default is the newest present, which is the rule the installer
    /// follows — so a box with only an older version defaults to that rather
    /// than to nothing.
    #[test]
    fn the_default_is_the_newest_version_present() {
        let (present, default) = php_present(|d| d == "/etc/php/8.2/fpm");
        assert_eq!(present, ["8.2"]);
        assert_eq!(default, Some("8.2"));

        let (present, default) = php_present(|_| false);
        assert!(present.is_empty());
        assert_eq!(default, None);

        let (_, default) = php_present(|_| true);
        assert_eq!(default, Some("8.5"), "the candidates are not oldest-first");
    }

    /// A skip is not a failure. The script skips what a box legitimately
    /// does not have — no phpMyAdmin, no WAF engine on EL — and counting
    /// those as failures would report every correctly installed AlmaLinux
    /// box as broken, which teaches operators to ignore the check.
    #[test]
    fn a_skip_is_not_a_failure() {
        assert!(!Tally {
            pass: 10,
            fail: 0,
            skip: 3
        }
        .failed());
        assert!(Tally {
            pass: 10,
            fail: 1,
            skip: 0
        }
        .failed());
        assert!(!Tally::default().failed());
    }

    #[test]
    fn the_panel_is_asked_over_loopback() {
        assert_eq!(base_url(2222), "https://127.0.0.1:2222");
        assert!(base_url(8443).starts_with("https://127.0.0.1:"));
    }

    #[test]
    fn a_conf_with_no_user_directive_falls_back_to_the_debian_account() {
        assert_eq!(nginx_user_name("worker_processes auto;\n"), None);
        assert_eq!(DEFAULT_WEB_USER, "www-data");
    }
}
