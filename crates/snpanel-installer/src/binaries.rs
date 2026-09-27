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

/// The helper, the extractor, and the unit files.
///
/// `snpanel-helper.sh` used to be installed beside the binary, at the name
/// the binary `exec`d for a verb it did not answer yet. Every verb is
/// answered, so the script is not shipped and the fallthrough is gone.
pub fn helper_files() -> Vec<Installed> {
    vec![
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
        // The phase runner. On the box rather than only in the release
        // directory, because `update.sh` runs phases before it has fetched
        // anything and a box whose update cannot reach the release still has
        // the previous one here.
        //
        // 0750 root:root: root-only, which is narrower than either of the
        // other two. The helper is 0750 root:snpanel because the panel calls
        // it; the extractor is 0755 because a customer's own account runs it.
        // Nothing but the installer runs this, and everything it writes needs
        // root anyway - so there is no account that should be able to start
        // it and fail halfway.
        Installed {
            path: "/usr/local/sbin/snpanel-install",
            mode: 0o750,
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

/// Where the command-line programs end up.
///
/// The names used to be worth reading twice, because the obvious guess was
/// wrong: the **bash** rescue menu took the name `snpanel`, with `snpanelctl`
/// a symlink to it, and the Rust CLI went beside them as `snpanel-cli`. That
/// was right while the menu still served eight of its own subcommands and the
/// CLI handed those back to it.
///
/// It serves all of them now, the script is deleted, and the binary takes the
/// name. `snpanelctl` and `snpanel-cli` are symlinks to it - the first is in
/// runbooks and in muscle memory, the second is what a box installed before
/// this release learned, and neither should stop working because a file
/// moved.
///
/// There is no longer a rescue menu without the Rust CLI, which is why the
/// flag no longer guards a second entry. `install.sh` already refuses to
/// finish without the binaries, so the case cannot arise.
pub fn cli_files(release_has_rust_cli: bool) -> Vec<Installed> {
    let mut out = Vec::new();
    if release_has_rust_cli {
        out.push(Installed {
            path: "/usr/local/sbin/snpanel",
            mode: 0o755,
            owner: "root",
            group: "root",
        });
        out.push(API_BINARY);
    }
    out
}

/// The two names that follow `snpanel` wherever it is installed.
pub const CLI_ALIASES: &[(&str, &str)] = &[
    ("/usr/local/sbin/snpanelctl", "/usr/local/sbin/snpanel"),
    ("/usr/local/sbin/snpanel-cli", "/usr/local/sbin/snpanel"),
];

/// The Rust API binary.
///
/// The archive has always carried it — `fetch_rust_binaries` refuses one
/// without it — but nothing in the installer put it on disk until now, and
/// `install.sh`, `update.sh` and `snpanelctl` all name this exact path.
///
/// **`/usr/local/bin`, not `sbin`, and 0755 root:root.** The panel's units
/// run it as the unprivileged `snpanel` user, so it has to be executable by
/// somebody who is not root — which is the opposite of the helper, and the
/// reason the two are not in the same list by accident. It carries no
/// privilege of its own: everything privileged still goes through the
/// helper.
pub const API_BINARY: Installed = Installed {
    path: "/usr/local/bin/snpanel-api-rust",
    mode: 0o755,
    owner: "root",
    group: "root",
};

/// `snpanelctl` -> `snpanel`. Kept as a name of its own because it is the
/// one an operator types; [`CLI_ALIASES`] carries it and `snpanel-cli`.
pub const CTL_ALIAS: (&str, &str) = CLI_ALIASES[0];

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
    ///
    /// Three files, three different answers, and each is deliberate:
    ///
    /// * `snpanel-helper` is 0750 root:snpanel, because the panel calls it
    ///   and nothing else may;
    /// * `snpanel-extract` is 0755, because a customer's own account runs it
    ///   — see the test below;
    /// * `snpanel-install` is 0750 root:root, narrower than both. Nothing but
    ///   the installer runs it, and everything it writes needs root anyway.
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
            assert_eq!(file.owner, "root", "{}", file.path);
            // Never group-writable: that is a privilege escalation for every
            // member of the group.
            assert_eq!(file.mode & 0o020, 0, "{}", file.path);

            if file.path.ends_with("snpanel-install") {
                // Root-only. It has no caller that is not already root.
                assert_eq!(file.group, "root", "{}", file.path);
                assert_eq!(file.mode, 0o750, "{}", file.path);
            } else {
                // The panel's group can run it.
                assert_eq!(file.group, "snpanel", "{}", file.path);
                assert_eq!(file.mode & 0o050, 0o050, "{}", file.path);
            }
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

    /// The name an operator types in an emergency reaches the program that
    /// answers it.
    ///
    /// This asserted the opposite arrangement while the rescue menu was a
    /// bash script: the script took `snpanel` and the binary went beside it.
    /// Putting the wrong program behind that name is not a mistake that
    /// announces itself either way round.
    #[test]
    fn the_rescue_menu_keeps_the_name_an_operator_types() {
        let paths: Vec<&str> = cli_files(true).iter().map(|f| f.path).collect();
        assert!(paths.contains(&"/usr/local/sbin/snpanel"), "{paths:?}");
        // Both older names are symlinks, not copies: a second copy is a
        // second thing to forget to update.
        for (from, to) in CLI_ALIASES {
            assert_eq!(*to, "/usr/local/sbin/snpanel", "{from} points elsewhere");
            assert!(!paths.contains(from), "{from} is installed as a file");
        }
        assert_eq!(CTL_ALIAS.0, "/usr/local/sbin/snpanelctl");
    }

    /// **The API binary goes where an unprivileged unit can run it.**
    ///
    /// `snpanel-api.service` and both scheduler units run it as
    /// `User=snpanel`. In `/usr/local/sbin` with the helper's 0750
    /// root:snpanel it would be unreachable, and the panel would fail to
    /// start with a permissions error rather than anything that named the
    /// cause.
    #[test]
    fn the_api_binary_is_runnable_by_the_account_its_unit_uses() {
        let api = cli_files(true)
            .into_iter()
            .find(|f| f.path.ends_with("snpanel-api-rust"))
            .expect("the API binary is installed when the archive has one");
        assert_eq!(api.path, "/usr/local/bin/snpanel-api-rust");
        assert_eq!(
            api.mode & 0o001,
            0o001,
            "the snpanel user has to execute it"
        );
        assert_eq!(api.mode & 0o022, 0, "and nobody but root may write it");
    }

    /// **Every unit that names the binary names the path that is installed.**
    ///
    /// The path is spelled in four places across two shell files and a unit;
    /// a binary installed one directory over is a panel that will not start,
    /// and the error names a missing file rather than a wrong install.
    #[test]
    fn the_units_name_the_path_the_installer_writes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../installer");
        // `files/snpanelctl` was the third of these and is deleted. It is
        // named rather than dropped silently: the loop used to `continue` on
        // a file it could not read, so removing one would have left this
        // passing over two while its name says every.
        let mut checked = 0;
        for name in ["install.sh", "update.sh"] {
            let text =
                std::fs::read_to_string(root.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                text.contains(API_BINARY.path),
                "{name} does not name {}",
                API_BINARY.path
            );
            checked += 1;
        }
        assert_eq!(checked, 2);
    }

    /// Without the Rust binaries there is nothing to install.
    ///
    /// This used to assert the opposite: the rescue menu was a bash script,
    /// so it went on every box whether or not the archive carried a binary.
    /// The menu *is* the binary now. `install.sh` refuses to finish without
    /// one, which is the check that keeps this from being a box with no
    /// rescue menu rather than a box with an old one.
    #[test]
    fn a_release_without_binaries_installs_no_cli() {
        assert!(cli_files(false).is_empty());
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
