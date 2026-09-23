//! The order the phases run in.
//!
//! Source: `main`.
//!
//! An installer is a sequence, and almost every way it can go wrong that is
//! not a bug inside one phase is two phases in the wrong order. Those
//! dependencies are invisible in the bash — `main` is a flat list of calls
//! with log lines between them, and nothing in it says that
//! `install_privileged_helper` needs the group `setup_panel_user` creates.
//!
//! So the order is data here, checked against the shell's own `main`, and
//! the dependencies between phases are tests. Each one names what breaks if
//! the two are swapped.
//!
//! Platform detection is not in the list: it happens before the first phase
//! and it is what tells the rest which PHP versions exist.

/// Every phase, in order.
///
/// Checked against `main` by a fixture extracted from the shell, so this
/// cannot quietly drift into agreeing only with itself.
pub const PHASES: &[&str] = &[
    "validate_sources",
    "ask_panel_url",
    "install_base_packages",
    "install_nodejs",
    "install_php",
    "configure_fastcgi_cache",
    "configure_proxy_upgrade_map",
    "install_waf_engine",
    "install_wp_cli",
    "copy_sources",
    "build_frontend",
    "setup_panel_user",
    "setup_sftp_access",
    "install_privileged_helper",
    "install_panel_cli",
    "validate_privileged_helper",
    "setup_backend",
    "setup_systemd",
    "setup_phpmyadmin_control_user",
    "setup_phpmyadmin_sso",
    "setup_nginx",
    "setup_firewall",
    "configure_log_limits",
    "setup_ssl",
    "enable_ipv6_when_available",
    "write_login_info",
    "write_update_state",
    "print_summary",
    "cleanup_rust_binaries",
    "cleanup_release_source",
];

/// The phases `main` allows to fail.
///
/// Exactly one. `install_waf_engine` is wrapped in `if ! ... then warn`,
/// because a box without a rule engine is still a box with flood protection
/// and a working panel. Everything else in the list is load-bearing, and a
/// second entry here should have to argue for itself.
pub const TOLERATED_FAILURES: &[&str] = &["install_waf_engine"];

/// Where a phase sits in the sequence.
pub fn position(phase: &str) -> Option<usize> {
    PHASES.iter().position(|p| *p == phase)
}

/// Whether `first` runs before `second`.
///
/// Panics if either name is not a phase, so a test cannot pass by naming
/// something that has been renamed out from under it.
pub fn runs_before(first: &str, second: &str) -> bool {
    let a = position(first).unwrap_or_else(|| panic!("{first} is not a phase"));
    let b = position(second).unwrap_or_else(|| panic!("{second} is not a phase"));
    a < b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracted from the shell's `main` rather than transcribed: a
    /// hand-copied list would agree with itself rather than with what runs.
    #[test]
    fn the_order_is_the_shells() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/installer/main-phases.expected");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the phase fixture {}: {e}", path.display()));
        let shell: Vec<&str> = raw.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(PHASES, shell.as_slice());
        // And it is a real sequence, not an empty one that satisfies every
        // ordering check by having nothing in it.
        assert!(PHASES.len() >= 25);
    }

    #[test]
    fn no_phase_runs_twice() {
        let mut seen = std::collections::BTreeSet::new();
        for phase in PHASES {
            assert!(seen.insert(phase), "{phase} runs twice");
        }
    }

    /// Nothing is written until the upload has been checked. Otherwise an
    /// incomplete upload leaves a box with nginx, PHP and MariaDB configured
    /// and no panel, and the operator has to work out what to undo.
    #[test]
    fn nothing_is_written_before_the_sources_are_checked() {
        assert_eq!(PHASES[0], "validate_sources");
    }

    /// The panel's address is baked into the backend's `.env`, its systemd
    /// unit and its vhost, so it has to be known before any of the three is
    /// written. Asking at the end would mean rewriting all of them.
    #[test]
    fn the_address_is_settled_before_anything_bakes_it_in() {
        for later in ["setup_backend", "setup_systemd", "setup_nginx", "setup_ssl"] {
            assert!(runs_before("ask_panel_url", later), "{later}");
        }
    }

    /// The helper is installed `root:snpanel`, so the group has to exist
    /// first — and `install` fails outright on a group that does not,
    /// leaving the box with no privileged path at all.
    #[test]
    fn the_group_exists_before_anything_is_installed_into_it() {
        assert!(runs_before("setup_panel_user", "install_privileged_helper"));
        assert!(runs_before("setup_panel_user", "setup_sftp_access"));
    }

    /// A sudoers rule that parses, a helper that is executable and a group
    /// membership that did not take all look fine separately, so the whole
    /// path is exercised — and it can only be exercised once it exists.
    #[test]
    fn the_privileged_path_is_validated_after_it_is_installed() {
        assert!(runs_before(
            "install_privileged_helper",
            "validate_privileged_helper"
        ));
    }

    /// Two phases drive the helper rather than doing the work themselves, so
    /// both have to come after it is installed *and* after it has been
    /// shown to work. A firewall phase that ran first would silently do
    /// nothing and leave the box open.
    #[test]
    fn the_phases_that_drive_the_helper_run_after_it_is_known_to_work() {
        for driver in ["setup_firewall", "enable_ipv6_when_available"] {
            assert!(
                runs_before("validate_privileged_helper", driver),
                "{driver}"
            );
        }
    }

    /// The build runs inside the copied tree and needs an interpreter new
    /// enough to run Vite. Either one out of order is a build that fails on
    /// something that looks unrelated.
    #[test]
    fn the_frontend_is_built_from_the_copied_tree_with_the_node_that_was_installed() {
        assert!(runs_before("copy_sources", "build_frontend"));
        assert!(runs_before("install_nodejs", "build_frontend"));
    }

    /// The unit names the virtualenv and reads the `.env` that
    /// `setup_backend` writes. Starting the service first is a service that
    /// fails on its first line.
    #[test]
    fn the_service_is_created_after_what_it_runs_exists() {
        assert!(runs_before("setup_backend", "setup_systemd"));
        assert!(runs_before("copy_sources", "setup_backend"));
    }

    /// Everything afterwards needs nginx, MariaDB or PHP from the base
    /// transaction.
    #[test]
    fn the_packages_come_before_anything_that_configures_them() {
        for later in [
            "install_php",
            "configure_fastcgi_cache",
            "install_waf_engine",
            "setup_panel_user",
            "setup_nginx",
        ] {
            assert!(runs_before("install_base_packages", later), "{later}");
        }
    }

    /// The sign-on configuration names the control user's database, and the
    /// storage is useless without the account.
    #[test]
    fn the_control_user_exists_before_the_sign_on_points_at_it() {
        assert!(runs_before(
            "setup_phpmyadmin_control_user",
            "setup_phpmyadmin_sso"
        ));
    }

    /// The login file and the closing summary both carry the panel's URL,
    /// whose scheme `setup_ssl` decides — and the summary also reports what
    /// the IPv6 phase concluded. Printed earlier, both would be wrong in
    /// exactly the way nobody checks.
    #[test]
    fn what_is_reported_is_decided_first() {
        assert!(runs_before("setup_ssl", "write_login_info"));
        assert!(runs_before("setup_ssl", "print_summary"));
        assert!(runs_before("enable_ipv6_when_available", "print_summary"));
    }

    /// `cleanup_rust_binaries` removes the staging directory the binaries
    /// are installed *from*. Running it earlier would delete them before
    /// they were copied into place, and the failure would be a missing
    /// helper rather than an obvious ordering mistake.
    #[test]
    fn the_staging_directory_is_removed_only_after_everything_is_taken_from_it() {
        for installer in ["install_privileged_helper", "install_panel_cli"] {
            assert!(
                runs_before(installer, "cleanup_rust_binaries"),
                "{installer}"
            );
        }
    }

    /// The release source is removed last of all, because every phase that
    /// copies anything copies it from there — including the unit files and
    /// the helper scripts, which are read much later than `copy_sources`.
    #[test]
    fn the_source_is_removed_after_the_last_thing_that_reads_it() {
        assert_eq!(*PHASES.last().unwrap(), "cleanup_release_source");
    }

    /// A box without a rule engine is still a box with flood protection and
    /// a working panel. Everything else in the sequence is load-bearing, and
    /// a second tolerated failure should have to argue for itself.
    #[test]
    fn exactly_one_phase_is_allowed_to_fail() {
        assert_eq!(TOLERATED_FAILURES, ["install_waf_engine"]);
        for tolerated in TOLERATED_FAILURES {
            assert!(position(tolerated).is_some(), "{tolerated} is not a phase");
        }
    }

    /// `runs_before` refuses a name that is not a phase, so a test cannot
    /// pass by asserting something about a function that has been renamed.
    #[test]
    #[should_panic(expected = "is not a phase")]
    fn an_ordering_claim_about_a_phase_that_does_not_exist_is_an_error() {
        runs_before("setup_panel_user", "setup_something_that_went_away");
    }
}
