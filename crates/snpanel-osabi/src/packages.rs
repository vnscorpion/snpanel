//! Asking the package manager two questions.
//!
//! Source: `pkg_exists` and `pkg_installed` in `installer/platform.sh`.
//!
//! Both are per-family and both are asked constantly — `install_php` probes
//! every extension name before the transaction, and `enable_extra_repos`
//! asks whether EPEL is already in. The Debian halves already existed in the
//! helper, where they are used by the PHP-version action; the EL halves did
//! not exist in Rust at all, which is why they are here rather than there:
//! the installer needs both families, and one implementation for two callers
//! is one place for the answer to be wrong.

use crate::platform::Family;

/// The argv that asks whether a package **can be installed**.
///
/// Never a shell string.
pub fn exists_argv(family: Family, package: &str) -> Vec<String> {
    match family {
        // Deliberately `policy` and not `show`. The bash comment records the
        // bug: `apt-cache show` succeeds for a name the archive merely
        // references, so it said yes to `php7.4-fpm` on a release with no
        // such package and the panel offered a PHP it could not install.
        Family::Debian => vec!["apt-cache".into(), "policy".into(), package.into()],
        Family::Rhel => vec!["dnf".into(), "-q".into(), "info".into(), package.into()],
    }
}

/// The argv that asks whether a package **is installed**.
pub fn installed_argv(family: Family, package: &str) -> Vec<String> {
    match family {
        Family::Debian => vec!["dpkg".into(), "-s".into(), package.into()],
        Family::Rhel => vec!["rpm".into(), "-q".into(), package.into()],
    }
}

/// `sed -n 's/^  Candidate: //p'`, then `-n "$c" && "$c" != "(none)"`.
///
/// **Two leading spaces exactly.** `apt-cache policy` indents the candidate
/// line that much, and a looser match would also take the `Candidate:`
/// inside a version table, where it means something else entirely.
pub fn candidate_version(policy: &str) -> Option<&str> {
    policy
        .lines()
        .find_map(|l| l.strip_prefix("  Candidate: "))
        .filter(|c| !c.is_empty() && *c != "(none)")
}

/// Whether the answer to [`exists_argv`] means yes.
///
/// The two families disagree about where the answer is. `dnf -q info` says
/// it in its exit status; `apt-cache policy` exits zero for a name it has
/// never heard of, so on Debian the *output* is the answer and the status
/// is not.
pub fn exists_from_output(family: Family, exit_ok: bool, stdout: &str) -> bool {
    match family {
        Family::Debian => candidate_version(stdout).is_some(),
        Family::Rhel => exit_ok,
    }
}

/// Whether the answer to [`installed_argv`] means yes.
///
/// Both families say it in the exit status. A missing `dpkg` or `rpm`
/// answers "not installed" rather than failing, which is what the shell's
/// `>/dev/null 2>&1` does with it — and is the right answer, since a package
/// manager that is not there has installed nothing.
pub fn installed_from_status(exit_ok: bool) -> bool {
    exit_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `apt-cache policy` answer for a package that exists, taken
    /// from Debian 13 with `cat -A` to confirm the indentation.
    const PRESENT: &str = "\
php8.4-fpm:
  Installed: (none)
  Candidate: 8.4.1-1+0~20241123.16+debian13~1.gbp7e0e0a
  Version table:
     8.4.1-1+0~20241123.16+debian13~1.gbp7e0e0a 500
        500 https://packages.sury.org/php trixie/main amd64 Packages
";

    /// And for one the archive merely references.
    const ABSENT: &str = "\
php7.4-fpm:
  Installed: (none)
  Candidate: (none)
  Version table:
";

    #[test]
    fn a_package_exists_only_when_apt_names_a_candidate() {
        assert_eq!(
            candidate_version(PRESENT),
            Some("8.4.1-1+0~20241123.16+debian13~1.gbp7e0e0a")
        );
        assert_eq!(candidate_version(ABSENT), None);
        assert_eq!(candidate_version(""), None);
    }

    /// **Two leading spaces exactly.** The version table repeats the word
    /// with a different indent and a different meaning; a looser match would
    /// read a mirror's URL as a version.
    #[test]
    fn the_candidate_line_is_matched_by_its_exact_indent() {
        assert_eq!(candidate_version("Candidate: 1.0\n"), None);
        assert_eq!(candidate_version(" Candidate: 1.0\n"), None);
        assert_eq!(candidate_version("   Candidate: 1.0\n"), None);
        assert_eq!(candidate_version("  Candidate: 1.0\n"), Some("1.0"));
        // An empty candidate is no candidate.
        assert_eq!(candidate_version("  Candidate: \n"), None);
    }

    /// `apt-cache policy` exits zero for a name it has never heard of, so on
    /// Debian the output is the answer and the status is not. Reading the
    /// status there would report every package as installable.
    ///
    /// Measured on Debian 13, not assumed:
    ///
    /// ```text
    /// $ apt-cache policy no-such-package-anywhere; echo "exit status: $?"
    /// exit status: 0
    /// ```
    ///
    /// Nothing on stdout, and a zero exit.
    #[test]
    fn debian_reads_the_output_and_el_reads_the_status() {
        assert!(exists_from_output(Family::Debian, true, PRESENT));
        assert!(!exists_from_output(Family::Debian, true, ABSENT));
        // The unknown-name case exactly as apt produces it: no output, and a
        // zero exit that means nothing.
        assert!(!exists_from_output(Family::Debian, true, ""));

        // dnf says it in the status, and its output is not consulted.
        assert!(exists_from_output(Family::Rhel, true, ""));
        assert!(!exists_from_output(Family::Rhel, false, PRESENT));
    }

    #[test]
    fn each_family_is_asked_with_its_own_tool() {
        assert_eq!(
            exists_argv(Family::Debian, "php8.4-fpm"),
            ["apt-cache", "policy", "php8.4-fpm"]
        );
        assert_eq!(
            exists_argv(Family::Rhel, "php84-php-fpm"),
            ["dnf", "-q", "info", "php84-php-fpm"]
        );
        assert_eq!(
            installed_argv(Family::Debian, "epel-release"),
            ["dpkg", "-s", "epel-release"]
        );
        assert_eq!(
            installed_argv(Family::Rhel, "epel-release"),
            ["rpm", "-q", "epel-release"]
        );
    }

    /// `apt-cache show` succeeds for a name the archive merely references.
    /// That is the bug the `policy` spelling exists to avoid, and a future
    /// edit back to `show` would pass every other test here.
    #[test]
    fn debian_is_asked_with_policy_and_never_with_show() {
        let argv = exists_argv(Family::Debian, "anything");
        assert!(argv.contains(&"policy".to_string()));
        assert!(!argv.contains(&"show".to_string()));
    }

    /// Nothing is passed through a shell, on either family.
    #[test]
    fn a_package_name_is_never_interpreted() {
        for family in [Family::Debian, Family::Rhel] {
            for argv in [
                exists_argv(family, "a; rm -rf /"),
                installed_argv(family, "a; rm -rf /"),
            ] {
                // The name arrives whole, as one argument, and nothing else
                // in the argv was built from it.
                assert_eq!(argv.last().unwrap(), "a; rm -rf /");
                assert!(argv[..argv.len() - 1]
                    .iter()
                    .all(|a| !a.contains(';') && !a.contains("rm")));
            }
        }
    }

    /// A package manager that is not there has installed nothing, which is
    /// the right answer rather than an error.
    #[test]
    fn a_missing_package_manager_reports_nothing_installed() {
        assert!(!installed_from_status(false));
        assert!(installed_from_status(true));
    }
}
