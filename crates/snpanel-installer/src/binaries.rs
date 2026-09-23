//! Installing the panel's own programs, and the privilege boundary their
//! modes draw.
//!
//! Source: `install_rust_helper`, `install_panel_cli`,
//! `validate_privileged_helper`, `cleanup_rust_binaries`.
//!
//! Everything the panel does as root goes through `snpanel-helper`. Its mode
//! and its group are therefore not housekeeping — they are the boundary, and
//! the sudoers rule is the other half of it. A helper that any local user
//! could execute would make every verb in it reachable by every account on
//! the box, including the unprivileged ones the panel creates for customers.

/// One program the installer puts in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub path: &'static str,
    pub mode: u32,
    pub owner: &'static str,
    pub group: &'static str,
}

/// The two helpers, the extractor, and the unit files.
///
/// `snpanel-helper.sh` stays beside the Rust `snpanel-helper` at the name
/// the Rust one `exec`s for a verb it does not answer yet. Installing both
/// here means a fresh box is never in the state the cutover script exists to
/// move it out of.
pub fn helper_files() -> Vec<Installed> {
    vec![
        Installed {
            path: "/usr/local/sbin/snpanel-helper.sh",
            mode: 0o750,
            owner: "root",
            group: "snpanel",
        },
        Installed {
            path: "/usr/local/sbin/snpanel-helper",
            mode: 0o750,
            owner: "root",
            group: "snpanel",
        },
        // The extractor is the exception, and deliberately so: it runs
        // *unprivileged*, as the site's own user, which is the whole point
        // of it being a separate program. Archive extraction is the part of
        // a restore that handles untrusted bytes.
        Installed {
            path: "/usr/local/sbin/snpanel-extract",
            mode: 0o755,
            owner: "root",
            group: "root",
        },
    ]
}

/// The socket units, when the release carries them.
///
/// The socket lets the panel reach the helper without forking `sudo` for
/// every call. `sudo` still works and is still what an administrator uses by
/// hand — so a socket that fails to start is a warning and a slower panel,
/// not a failed install.
pub const UNITS: &[&str] = &["snpanel-helper.service", "snpanel-helper.socket"];
pub const UNIT_MODE: u32 = 0o644;
pub const SOCKET_WARNING: &str =
    "WARNING: snpanel-helper.socket did not start; the panel will use sudo";

/// Where the two command-line programs end up.
///
/// The names are worth reading twice, because the obvious guess is wrong:
/// the **bash** rescue menu takes the name `snpanel`, with `snpanelctl` as a
/// symlink to it, and the **Rust** CLI — a different program with a
/// different job — is installed beside it as `snpanel-cli`. Putting the
/// wrong program behind the name an operator types in an emergency is not a
/// mistake that announces itself.
pub fn cli_files(release_has_rust_cli: bool) -> Vec<Installed> {
    let mut out = Vec::new();
    if release_has_rust_cli {
        out.push(Installed {
            path: "/usr/local/sbin/snpanel-cli",
            mode: 0o755,
            owner: "root",
            group: "root",
        });
    }
    out.push(Installed {
        path: "/usr/local/sbin/snpanel",
        mode: 0o755,
        owner: "root",
        group: "root",
    });
    out
}

/// `snpanelctl` -> `snpanel`.
pub const CTL_ALIAS: (&str, &str) = ("/usr/local/sbin/snpanelctl", "/usr/local/sbin/snpanel");

/// The check that the privilege path works end to end, before the installer
/// claims success.
///
/// It runs a real verb through the real path — `sudo -u snpanel` then
/// `sudo -n snpanel-helper` — rather than testing the pieces. A sudoers rule
/// that parses, a helper that is executable and a group membership that did
/// not take all look fine separately.
pub const VALIDATION_VERB: &[&str] = &["wp", "--info"];

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary. A helper any local user could execute would put every
    /// verb in it within reach of every account on the box — including the
    /// unprivileged ones the panel creates for customers.
    #[test]
    fn the_helpers_are_not_executable_by_other_users() {
        for file in helper_files() {
            if file.path.ends_with("snpanel-extract") {
                continue;
            }
            assert_eq!(
                file.mode & 0o007,
                0,
                "{} is reachable by other users",
                file.path
            );
            assert_eq!(file.group, "snpanel", "{}", file.path);
            assert_eq!(file.owner, "root", "{}", file.path);
            // And the group can run it but not rewrite it.
            assert_eq!(file.mode & 0o050, 0o050, "{}", file.path);
            assert_eq!(file.mode & 0o020, 0, "{}", file.path);
        }
    }

    /// The extractor is the one exception, and it is the point of the
    /// program: it runs as the site's own user, because archive extraction
    /// is the part of a restore that handles untrusted bytes.
    #[test]
    fn the_extractor_is_the_only_one_anybody_can_run() {
        let open: Vec<&str> = helper_files()
            .iter()
            .filter(|f| f.mode & 0o001 != 0)
            .map(|f| f.path)
            .collect();
        assert_eq!(open, ["/usr/local/sbin/snpanel-extract"]);
    }

    /// Nothing the installer puts in `/usr/local/sbin` is writable by
    /// anyone but root. A group-writable helper is a privilege escalation
    /// for every member of that group.
    #[test]
    fn nothing_installed_is_writable_by_anyone_but_root() {
        for file in helper_files().into_iter().chain(cli_files(true)) {
            assert_eq!(file.mode & 0o022, 0, "{} is writable", file.path);
            assert_eq!(file.owner, "root", "{}", file.path);
        }
        assert_eq!(UNIT_MODE & 0o022, 0);
    }

    /// The bash rescue menu takes `snpanel`, with `snpanelctl` as a symlink
    /// to it; the Rust CLI is installed beside them as `snpanel-cli`.
    /// Putting the wrong program behind the name an operator types in an
    /// emergency is not a mistake that announces itself.
    #[test]
    fn the_rescue_menu_keeps_the_name_an_operator_types() {
        let paths: Vec<&str> = cli_files(true).iter().map(|f| f.path).collect();
        assert!(paths.contains(&"/usr/local/sbin/snpanel"));
        assert!(paths.contains(&"/usr/local/sbin/snpanel-cli"));
        assert_eq!(CTL_ALIAS.0, "/usr/local/sbin/snpanelctl");
        assert_eq!(CTL_ALIAS.1, "/usr/local/sbin/snpanel");
    }

    /// A release without the Rust CLI still installs the rescue menu. The
    /// menu is what an operator reaches for when the panel is down, so it
    /// cannot be conditional on a binary that may not have been built.
    #[test]
    fn the_rescue_menu_is_installed_whether_or_not_the_rust_cli_exists() {
        let without: Vec<&str> = cli_files(false).iter().map(|f| f.path).collect();
        assert_eq!(without, ["/usr/local/sbin/snpanel"]);
    }

    /// `sudo` still works and is still what an administrator uses by hand,
    /// so a socket that did not start is a slower panel rather than a failed
    /// install.
    #[test]
    fn a_socket_that_does_not_start_is_a_warning() {
        assert!(SOCKET_WARNING.starts_with("WARNING: "));
        assert!(SOCKET_WARNING.contains("will use sudo"));
        assert_eq!(UNITS.len(), 2);
        assert!(UNITS.contains(&"snpanel-helper.socket"));
    }

    /// A sudoers rule that parses, a helper that is executable and a group
    /// membership that did not take all look fine separately — so the check
    /// runs a real verb through the real path.
    #[test]
    fn the_privilege_path_is_validated_end_to_end() {
        assert_eq!(VALIDATION_VERB, ["wp", "--info"]);
    }
}
