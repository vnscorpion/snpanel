//! The checks at either end of an install: what has to be there before it
//! starts, and what has to be true before it claims success.
//!
//! Source: `validate_sources`, `need_dir`, `find_sshd`, `wait_for_backend`,
//! `setup_nginx`, `print_summary`, `cleanup_release_source`,
//! `detect_server_ip`.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// What `validate_sources` insists on before anything is written.
///
/// Four paths, checked up front rather than where each is used. An install
/// that dies twenty minutes in because the upload was missing
/// `frontend/package.json` has already configured nginx, PHP and MariaDB on
/// a box it cannot finish — and the operator has to work out which of those
/// to undo. Finding it in the first second costs nothing.
///
/// It was five. `backend/requirements.txt` went with the Python backend: the
/// shell stopped checking for it, the file is not in the repository any
/// more, and this list kept asking for it. Nothing broke, because nothing
/// called this - which is the failure mode a deciding half without a caller
/// has, and why the test below reads the shell rather than a copy of it.
pub fn required_sources(project_root: &Path, backend: &Path, frontend: &Path) -> Vec<Requirement> {
    vec![
        Requirement::Directory(backend.to_path_buf()),
        Requirement::Directory(frontend.to_path_buf()),
        Requirement::File(project_root.join("VERSION")),
        Requirement::File(frontend.join("package.json")),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    Directory(PathBuf),
    File(PathBuf),
}

impl Requirement {
    /// The message when it is not there.
    ///
    /// A missing directory names what to upload, because the usual cause is
    /// an incomplete upload rather than a corrupted one.
    pub fn missing(&self) -> String {
        match self {
            Self::Directory(path) => format!(
                "Missing directory {}. Upload backend, frontend, and installer.",
                path.display()
            ),
            Self::File(path) => {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name == "VERSION" {
                    "Missing VERSION".to_string()
                } else {
                    // The two remaining ones are named by their position in
                    // the tree, as the shell names them.
                    let parent = path
                        .parent()
                        .and_then(Path::file_name)
                        .unwrap_or_default()
                        .to_string_lossy();
                    format!("Missing {parent}/{name}")
                }
            }
        }
    }
}

/// Where `sshd` might be, when it is not on `PATH`.
///
/// `PATH` is searched first, then these. A minimal image often has
/// `/usr/sbin` off root's `PATH` entirely, and the installer needs the
/// binary to ask it what ports it listens on — which is what keeps the
/// firewall phase from locking the operator out.
pub const SSHD_CANDIDATES: &[&str] = &["/usr/sbin/sshd", "/usr/local/sbin/sshd"];

/// How long the installer waits for its own API before giving up.
///
/// Thirty attempts a second apart, each with its own short timeouts, so a
/// backend that is hanging rather than slow is noticed in two seconds rather
/// than thirty.
pub const BACKEND_ATTEMPTS: u32 = 30;
pub const BACKEND_PAUSE: Duration = Duration::from_secs(1);
pub const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const BACKEND_MAX_TIME: Duration = Duration::from_secs(5);

/// The health endpoint, on loopback.
pub fn health_url(panel_port: u16) -> String {
    format!("http://127.0.0.1:{panel_port}/api/health")
}

/// What the installer does when the API never answered.
///
/// It prints the last eighty lines of the service's journal **before** it
/// fails. The operator is standing at a terminal that is about to end; the
/// reason the service would not start is the only thing that helps them, and
/// making them go and find it is making them do the installer's work.
pub const JOURNAL_LINES: u32 = 80;

pub fn backend_failure(panel_port: u16) -> String {
    format!("snpanel-api did not respond at {}", health_url(panel_port))
}

/// The distro's own default site, which the panel's vhosts have to replace.
///
/// Both families' names are removed, not just this platform's: an operator
/// who moved a box between the two, or who installed nginx from a different
/// source, can have either. Removing a file that is not there costs nothing.
pub const DEFAULT_SITES: &[&str] = &[
    "/etc/nginx/sites-enabled/default",
    "/etc/nginx/conf.d/default.conf",
];

/// A vhost older releases of the panel wrote, under a name this one no
/// longer uses. Left behind it would be a second server block for the panel.
pub const SUPERSEDED_VHOSTS: &[&str] = &[
    "/etc/nginx/sites-enabled/snpanel.conf",
    "/etc/nginx/sites-available/snpanel.conf",
];

/// The IPv6 line in the closing summary.
///
/// Three outcomes and three sentences: an operator reading this is deciding
/// whether there is anything left for them to do, and "not available" and
/// "detected but not enabled" call for different answers.
pub fn ipv6_summary(ipv6_result: &str) -> String {
    if let Some(address) = ipv6_result.strip_prefix("on:") {
        format!("IPv6: enabled on {address}")
    } else if ipv6_result == "failed" {
        "IPv6: detected but not enabled - turn it on in Panel settings".to_string()
    } else {
        "IPv6: not available on this server".to_string()
    }
}

/// Whether the unpacked release source may be deleted.
///
/// Three guards, and the third is the one that matters: **a directory with a
/// `.git` in it is never removed.** The installer can be run from a clone
/// — that is how it is developed and how it is tested — and a `rm -rf` of
/// somebody's working tree is not a recoverable mistake. The other two
/// narrow it further: only when the caller asked, and only at the one path
/// the release unpacker uses.
pub fn may_remove_release_source(
    clean_requested: bool,
    project_root: &Path,
    has_git_dir: bool,
) -> bool {
    clean_requested && project_root == Path::new(RELEASE_SOURCE) && !has_git_dir
}

/// The only path the release unpacker writes to, and so the only one this is
/// ever allowed to remove.
pub const RELEASE_SOURCE: &str = "/opt/snpanel-source";

/// Removed with it: the download and the archive it came out of.
pub const RELEASE_LEFTOVERS: &[&str] = &["/tmp/snpanel-release", "/tmp/snpanel-release.zip"];

/// The first address `hostname -I` reports.
///
/// Whitespace-separated, first field. It can legitimately be empty — a box
/// with only a link-local address, or one behind NAT with no address of its
/// own — and callers treat that as "unknown" rather than as an error.
pub fn first_address(hostname_i: &str) -> Option<&str> {
    hostname_i.split_whitespace().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An install that dies twenty minutes in because the upload was
    /// incomplete has already configured nginx, PHP and MariaDB on a box it
    /// cannot finish.
    #[test]
    fn everything_the_install_needs_is_checked_before_anything_is_written() {
        let required = required_sources(
            Path::new("/opt/snpanel-source"),
            Path::new("/opt/snpanel-source/backend"),
            Path::new("/opt/snpanel-source/frontend"),
        );
        assert_eq!(required.len(), 4);
        assert!(required.contains(&Requirement::Directory(PathBuf::from(
            "/opt/snpanel-source/backend"
        ))));
        assert!(required.contains(&Requirement::Directory(PathBuf::from(
            "/opt/snpanel-source/frontend"
        ))));
        assert!(required.contains(&Requirement::File(PathBuf::from(
            "/opt/snpanel-source/frontend/package.json"
        ))));
        assert!(required.contains(&Requirement::File(PathBuf::from(
            "/opt/snpanel-source/VERSION"
        ))));
    }

    /// And it is the *shell's* list, read from the shell.
    ///
    /// This list is a deciding half with no caller yet, so nothing at run
    /// time would report it drifting - and it had: it went on requiring
    /// `backend/requirements.txt` after the Python backend was deleted, the
    /// shell stopped checking for it, and the file left the repository.
    /// Wiring it up in that state would have failed every install at the
    /// first phase.
    #[test]
    fn the_list_is_the_one_validate_sources_checks() {
        let shell = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../installer/install.sh"),
        )
        .expect("install.sh");

        let body = shell
            .split_once("validate_sources() {")
            .expect("install.sh has no validate_sources")
            .1
            .split_once("\n}")
            .expect("validate_sources does not end")
            .0;

        // What the shell names, as it names it.
        let mut shell_wants: Vec<&str> = Vec::new();
        for (needle, what) in [
            ("$BACKEND_SRC", "backend"),
            ("$FRONTEND_SRC\"", "frontend"),
            ("${PROJECT_ROOT}/VERSION", "VERSION"),
            ("${FRONTEND_SRC}/package.json", "frontend/package.json"),
        ] {
            if body.contains(needle) {
                shell_wants.push(what);
            }
        }
        assert_eq!(
            shell_wants.len(),
            4,
            "validate_sources no longer checks all four: found {shell_wants:?}"
        );
        assert!(
            !body.contains("requirements.txt"),
            "the shell checks requirements.txt again; put it back in required_sources"
        );

        let required = required_sources(
            Path::new("/src"),
            Path::new("/src/backend"),
            Path::new("/src/frontend"),
        );
        assert_eq!(
            required.len(),
            shell_wants.len(),
            "the shell checks {} paths and this list has {}",
            shell_wants.len(),
            required.len()
        );
    }

    /// The usual cause is an incomplete upload, so the message says what to
    /// upload rather than only what is absent.
    #[test]
    fn the_messages_are_the_shells() {
        assert_eq!(
            Requirement::Directory(PathBuf::from("/src/backend")).missing(),
            "Missing directory /src/backend. Upload backend, frontend, and installer."
        );
        assert_eq!(
            Requirement::File(PathBuf::from("/src/VERSION")).missing(),
            "Missing VERSION"
        );
        assert_eq!(
            Requirement::File(PathBuf::from("/src/backend/requirements.txt")).missing(),
            "Missing backend/requirements.txt"
        );
        assert_eq!(
            Requirement::File(PathBuf::from("/src/frontend/package.json")).missing(),
            "Missing frontend/package.json"
        );
    }

    /// A minimal image often has `/usr/sbin` off root's `PATH`, and the
    /// installer needs the binary to ask it what ports it listens on — which
    /// is what keeps the firewall phase from locking the operator out.
    #[test]
    fn sshd_is_looked_for_off_the_path_as_well() {
        assert!(SSHD_CANDIDATES.contains(&"/usr/sbin/sshd"));
        assert!(SSHD_CANDIDATES.iter().all(|p| p.ends_with("/sshd")));
    }

    /// A backend that is hanging rather than slow should be noticed in
    /// seconds, not at the end of the whole budget.
    #[test]
    fn a_hanging_backend_is_noticed_quickly() {
        assert!(BACKEND_CONNECT_TIMEOUT < BACKEND_MAX_TIME);
        assert!(BACKEND_MAX_TIME <= Duration::from_secs(5));
        // Thirty seconds of patience in total, which is what a cold start
        // of the API plus its first database connection costs.
        assert_eq!(BACKEND_ATTEMPTS, 30);
        assert_eq!(BACKEND_PAUSE, Duration::from_secs(1));
    }

    /// The health check is on loopback: at this point in the install the
    /// panel may not be reachable from anywhere else yet, and asking through
    /// its public address would be testing the firewall instead.
    #[test]
    fn the_health_check_asks_over_loopback() {
        let url = health_url(2222);
        assert_eq!(url, "http://127.0.0.1:2222/api/health");
        assert!(!url.contains("localhost"), "a name that DNS could redirect");
    }

    /// The operator is standing at a terminal that is about to end. The
    /// reason the service would not start is the only thing that helps them.
    #[test]
    fn the_journal_is_printed_before_the_install_gives_up() {
        const { assert!(JOURNAL_LINES >= 80) };
        assert_eq!(
            backend_failure(2222),
            "snpanel-api did not respond at http://127.0.0.1:2222/api/health"
        );
    }

    /// Both families' default-site names are removed, because an operator
    /// who moved a box between them — or installed nginx from elsewhere —
    /// can have either, and removing a file that is not there costs nothing.
    #[test]
    fn both_families_default_sites_are_removed() {
        assert!(DEFAULT_SITES.contains(&"/etc/nginx/sites-enabled/default"));
        assert!(DEFAULT_SITES.contains(&"/etc/nginx/conf.d/default.conf"));
        // And the panel's own older vhost name, which would otherwise be a
        // second server block for the panel.
        assert_eq!(SUPERSEDED_VHOSTS.len(), 2);
        assert!(SUPERSEDED_VHOSTS
            .iter()
            .all(|p| p.ends_with("snpanel.conf")));
    }

    /// An operator reading the summary is deciding whether there is anything
    /// left for them to do, and the three outcomes call for different
    /// answers.
    #[test]
    fn the_summary_distinguishes_the_three_ipv6_outcomes() {
        assert_eq!(
            ipv6_summary("on:2001:db8::1"),
            "IPv6: enabled on 2001:db8::1"
        );
        assert_eq!(
            ipv6_summary("failed"),
            "IPv6: detected but not enabled - turn it on in Panel settings"
        );
        assert_eq!(ipv6_summary("off"), "IPv6: not available on this server");
        // Anything unexpected reads as "not available", which is the safe
        // thing to tell somebody: it sends them to look rather than to
        // assume.
        assert_eq!(ipv6_summary(""), "IPv6: not available on this server");
        assert_eq!(ipv6_summary("on"), "IPv6: not available on this server");
    }

    /// **The guard that matters.** The installer can be run from a clone —
    /// that is how it is developed and tested — and a `rm -rf` of somebody's
    /// working tree is not a recoverable mistake.
    #[test]
    fn a_git_checkout_is_never_removed() {
        let release = Path::new(RELEASE_SOURCE);
        assert!(may_remove_release_source(true, release, false));
        assert!(!may_remove_release_source(true, release, true));
    }

    /// And two narrower guards either side of it: only when asked, and only
    /// at the one path the release unpacker writes to.
    #[test]
    fn only_the_unpackers_own_directory_is_ever_removed() {
        let release = Path::new(RELEASE_SOURCE);
        assert!(!may_remove_release_source(false, release, false));
        for other in ["/root/snpanel", "/opt/snpanel", "/", "/opt/snpanel-source2"] {
            assert!(
                !may_remove_release_source(true, Path::new(other), false),
                "{other}"
            );
        }
    }

    #[test]
    fn the_server_address_is_the_first_one_reported() {
        assert_eq!(
            first_address("203.0.113.10 2001:db8::1\n"),
            Some("203.0.113.10")
        );
        assert_eq!(first_address("  203.0.113.10  "), Some("203.0.113.10"));
        // A box with no address of its own is "unknown", not an error: it
        // happens behind NAT and on link-local-only networks.
        assert_eq!(first_address(""), None);
        assert_eq!(first_address("   \n"), None);
    }
}
