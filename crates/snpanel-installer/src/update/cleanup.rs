//! Git bookkeeping, ownership, and the things an update removes when it
//! finishes.
//!
//! Source: `ensure_git_remote`, `reset_worktree_to_ref`,
//! `cleanup_release_work_dir`, `cleanup_stable_copy`,
//! `remove_panel_auto_update_timer`, `ensure_panel_runtime_ownership`,
//! `ensure_terminal_tools`, `remove_filebrowser_runtime`.

use std::path::{Path, PathBuf};

/// How the checkout is moved onto a ref.
///
/// `-f` on both halves, and that is the point of the function: an update
/// pulling a release must not stop because somebody edited a tracked file on
/// the server. The tree is the panel's, not the operator's — any local
/// change to it is an unsupported modification that the next release would
/// have overwritten anyway, and an update that refused to proceed would
/// leave the box stuck for ever on the version where it was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checkout {
    /// A branch to follow, moved to the ref and left attached.
    Branch { name: String, reference: String },
    /// A pinned tag or commit, checked out detached — there is no branch for
    /// it to be the tip of.
    Detached { reference: String },
}

pub fn checkout(reference: &str, branch: Option<&str>) -> Checkout {
    match branch.filter(|b| !b.is_empty()) {
        Some(name) => Checkout::Branch {
            name: name.to_string(),
            reference: reference.to_string(),
        },
        None => Checkout::Detached {
            reference: reference.to_string(),
        },
    }
}

impl Checkout {
    /// The `git checkout` argv, then `git reset --hard <ref>` in both cases.
    pub fn argv(&self) -> Vec<String> {
        match self {
            Self::Branch { name, reference } => vec![
                "git".into(),
                "checkout".into(),
                "-f".into(),
                "-B".into(),
                name.clone(),
                reference.clone(),
            ],
            Self::Detached { reference } => vec![
                "git".into(),
                "checkout".into(),
                "-f".into(),
                "--detach".into(),
                reference.clone(),
            ],
        }
    }

    pub fn reset_argv(&self) -> Vec<String> {
        let reference = match self {
            Self::Branch { reference, .. } | Self::Detached { reference } => reference,
        };
        vec![
            "git".into(),
            "reset".into(),
            "--hard".into(),
            reference.clone(),
        ]
    }
}

/// Whether the remote has to be added.
///
/// Asked rather than assumed: a checkout made by `git clone` already has it,
/// and `git remote add` on an existing name fails. The update would then die
/// on a box where nothing was wrong.
pub fn needs_remote(remote_is_configured: bool) -> bool {
    !remote_is_configured
}

/// The temporary trees an update leaves behind if nothing removes them.
///
/// Both are cleaned by the exit trap rather than at the end of the happy
/// path, which is the whole reason they are listed here: an update that
/// dies half way is exactly the run that would otherwise leave a 30 MB
/// archive in `/tmp`, and it is also the run most likely to be repeated
/// several times in a row.
pub fn temporary_trees(
    work_dir: Option<&str>,
    stable_copy: Option<&str>,
    previous_copy: Option<&str>,
) -> Vec<String> {
    [work_dir, stable_copy, previous_copy]
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

/// The auto-update timer, removed rather than left disabled.
///
/// It was withdrawn: a panel that updates itself unattended is a panel that
/// can break a customer's sites at 3am with nobody watching, and the two
/// units are deleted so a later `systemctl enable` cannot bring it back by
/// accident.
pub const AUTO_UPDATE_UNITS: &[&str] = &[
    "/etc/systemd/system/snpanel-auto-update.service",
    "/etc/systemd/system/snpanel-auto-update.timer",
];

/// FileBrowser, likewise withdrawn — the panel has its own file manager now,
/// and a second one listening on its own port is an extra way in that nobody
/// is maintaining.
pub const FILEBROWSER_PATHS: &[&str] = &[
    "/etc/systemd/system/filebrowser.service",
    "/etc/systemd/system/filebrowser.service.d",
    "/etc/filebrowser",
    "/var/lib/filebrowser",
    "/usr/local/bin/filebrowser",
];
/// And its setting, removed from the `.env` so nothing reads it back.
pub const FILEBROWSER_SETTING: &str = "FILEBROWSER_PORT";

/// Tools the panel shells out to, installed only when absent.
///
/// The file manager needs `zip`/`unzip` and the terminal needs `composer`.
/// Checked with `command -v` rather than asked for unconditionally, so an
/// ordinary update does no package transaction at all — which is what keeps
/// an update on a box with a slow mirror from taking minutes to do nothing.
pub const TERMINAL_TOOLS: &[&str] = &["composer", "zip", "unzip"];

pub fn missing_tools(present: impl Fn(&str) -> bool) -> Vec<&'static str> {
    TERMINAL_TOOLS
        .iter()
        .copied()
        .filter(|t| !present(t))
        .collect()
}

/// A path whose ownership the update re-asserts, and how deeply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owned {
    pub path: PathBuf,
    pub recursive: bool,
    /// `None` leaves the mode alone.
    pub mode: Option<u32>,
}

/// What `ensure_panel_runtime_ownership` fixes.
///
/// A release copied in as root leaves the tree owned by root, and the panel
/// runs as `snpanel` — so it would start and then fail to write anything it
/// owns. This runs after every update for that reason.
///
/// The modes are the ones that must not drift: `.my.cnf` is `0600`
/// because it is the credential for an account with `GRANT OPTION` on
/// everything, and `.env` is `0640` because it holds the `SECRET_KEY`. And
/// the two directories above them: the sync gives both the source tree's
/// mode, and a `backend` others can enter is a database others can read.
pub fn owned_paths(app_dir: &Path) -> Vec<Owned> {
    vec![
        Owned {
            path: app_dir.to_path_buf(),
            recursive: false,
            mode: Some(crate::panel_user::APP_DIR_MODE),
        },
        Owned {
            path: app_dir.join("backend"),
            recursive: true,
            mode: None,
        },
        Owned {
            path: app_dir.join("frontend"),
            recursive: true,
            mode: None,
        },
        Owned {
            path: app_dir.join(".my.cnf"),
            recursive: false,
            mode: Some(0o600),
        },
        Owned {
            path: PathBuf::from("/var/lib/snpanel"),
            recursive: false,
            mode: None,
        },
        Owned {
            path: PathBuf::from("/var/lib/snpanel/geoip"),
            recursive: true,
            mode: None,
        },
        Owned {
            path: PathBuf::from("/var/lib/snpanel/assets"),
            recursive: true,
            mode: None,
        },
        Owned {
            path: app_dir.join("backend/.env"),
            recursive: false,
            mode: Some(0o640),
        },
        // The directory itself, after the tree under it has been given back.
        Owned {
            path: app_dir.join("backend"),
            recursive: false,
            mode: Some(crate::panel_user::APP_BACKEND_DIR_MODE),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `-f` on both halves. An update must not stop because somebody edited
    /// a tracked file on the server: the tree is the panel's, any local
    /// change to it is an unsupported modification the next release would
    /// have overwritten anyway, and refusing would leave the box stuck for
    /// ever on the version where it was made.
    #[test]
    fn a_locally_modified_tree_does_not_stop_the_update() {
        for checkout in [
            checkout("v1.2.3", None),
            checkout("origin/main", Some("main")),
        ] {
            assert!(checkout.argv().contains(&"-f".to_string()), "{checkout:?}");
            assert!(checkout.reset_argv().contains(&"--hard".to_string()));
        }
    }

    /// A pinned tag has no branch to be the tip of, so it is checked out
    /// detached — creating a branch named after a tag would leave a name
    /// that drifts from what it was pinned to.
    #[test]
    fn a_tag_is_detached_and_a_branch_is_attached() {
        assert_eq!(
            checkout("v1.2.3", None),
            Checkout::Detached {
                reference: "v1.2.3".into()
            }
        );
        assert!(checkout("v1.2.3", None).argv().contains(&"--detach".into()));
        assert!(checkout("v1.2.3", Some(""))
            .argv()
            .contains(&"--detach".into()));

        let branch = checkout("origin/main", Some("main"));
        assert_eq!(
            branch,
            Checkout::Branch {
                name: "main".into(),
                reference: "origin/main".into()
            }
        );
        assert!(branch.argv().contains(&"-B".to_string()));
        assert!(!branch.argv().contains(&"--detach".to_string()));
    }

    /// `git remote add` on an existing name fails, so the update would die
    /// on a box where nothing was wrong.
    #[test]
    fn the_remote_is_added_only_when_it_is_missing() {
        assert!(needs_remote(false));
        assert!(!needs_remote(true));
    }

    /// The trap is what cleans these, not the happy path — an update that
    /// dies half way is exactly the run that would otherwise leave a 30 MB
    /// archive behind, and the run most likely to be repeated.
    #[test]
    fn the_temporary_trees_are_all_named() {
        assert_eq!(
            temporary_trees(Some("/tmp/work"), Some("/tmp/a"), Some("/tmp/b")),
            ["/tmp/work", "/tmp/a", "/tmp/b"]
        );
        // Unset variables are not paths, and an empty one is not `/`.
        assert!(temporary_trees(None, None, None).is_empty());
        assert!(temporary_trees(Some(""), Some(""), None).is_empty());
    }

    /// A panel that updates itself unattended can break a customer's sites
    /// at 3am with nobody watching, so the units are deleted rather than
    /// left disabled — a later `systemctl enable` cannot bring back a unit
    /// that is not there.
    #[test]
    fn the_auto_update_timer_is_removed_and_not_merely_disabled() {
        assert_eq!(AUTO_UPDATE_UNITS.len(), 2);
        assert!(AUTO_UPDATE_UNITS
            .iter()
            .all(|p| p.starts_with("/etc/systemd/system/")));
        assert!(AUTO_UPDATE_UNITS.iter().any(|p| p.ends_with(".timer")));
        assert!(AUTO_UPDATE_UNITS.iter().any(|p| p.ends_with(".service")));
    }

    /// A second file manager listening on its own port is an extra way in
    /// that nobody is maintaining. The binary, the units, the data and the
    /// setting all go.
    #[test]
    fn filebrowser_is_removed_completely() {
        assert!(FILEBROWSER_PATHS.contains(&"/usr/local/bin/filebrowser"));
        assert!(FILEBROWSER_PATHS.contains(&"/var/lib/filebrowser"));
        assert!(FILEBROWSER_PATHS
            .iter()
            .any(|p| p.ends_with("filebrowser.service")));
        // Including the drop-in directory, which would otherwise survive the
        // unit it belonged to.
        assert!(FILEBROWSER_PATHS
            .iter()
            .any(|p| p.ends_with("filebrowser.service.d")));
        assert_eq!(FILEBROWSER_SETTING, "FILEBROWSER_PORT");
    }

    /// Checked rather than asked for unconditionally, so an ordinary update
    /// does no package transaction at all — which is what keeps an update on
    /// a box with a slow mirror from taking minutes to do nothing.
    #[test]
    fn only_the_missing_tools_are_installed() {
        assert!(missing_tools(|_| true).is_empty());
        assert_eq!(missing_tools(|_| false), ["composer", "zip", "unzip"]);
        assert_eq!(missing_tools(|t| t != "zip"), ["zip"]);
    }

    /// A release copied in as root leaves the tree owned by root, and the
    /// panel runs as `snpanel` — so it would start and then fail to write
    /// anything it owns.
    #[test]
    fn the_application_tree_is_given_back_to_the_panel() {
        let owned = owned_paths(Path::new("/opt/snpanel"));
        let recursive: Vec<&Path> = owned
            .iter()
            .filter(|o| o.recursive)
            .map(|o| o.path.as_path())
            .collect();
        assert!(recursive.contains(&Path::new("/opt/snpanel/backend")));
        assert!(recursive.contains(&Path::new("/opt/snpanel/frontend")));
    }

    /// The two modes that must not drift: `.my.cnf` is the credential for an
    /// account with `GRANT OPTION` on everything, and `.env` holds the
    /// `SECRET_KEY`.
    #[test]
    fn the_two_credential_files_keep_their_modes() {
        let owned = owned_paths(Path::new("/opt/snpanel"));
        let mode_of = |name: &str| {
            owned
                .iter()
                .find(|o| o.path.ends_with(name))
                .unwrap_or_else(|| panic!("{name}"))
                .mode
        };
        assert_eq!(mode_of(".my.cnf"), Some(0o600));
        assert_eq!(mode_of(".env"), Some(0o640));
        // Neither is readable by anyone outside the panel.
        for mode in [0o600u32, 0o640] {
            assert_eq!(mode & 0o007, 0);
        }
    }

    /// Only those two and the two directories above them get a mode; the
    /// rest are ownership alone, because forcing a mode on a whole tree would
    /// flatten the distinction between a directory and a file.
    #[test]
    fn only_the_credential_files_and_their_directories_have_their_mode_set() {
        let owned = owned_paths(Path::new("/opt/snpanel"));
        let with_mode: Vec<&Owned> = owned.iter().filter(|o| o.mode.is_some()).collect();
        assert_eq!(with_mode.len(), 4);
        assert!(with_mode.iter().all(|o| !o.recursive));
    }

    /// An update gave `backend` the source tree's `0775`, with the database
    /// `0644` inside it. Put back as the install made them: the app directory
    /// passable and not listable, `backend` closed to everyone else.
    #[test]
    fn the_sync_does_not_decide_who_can_read_the_database() {
        let owned = owned_paths(Path::new("/opt/snpanel"));
        let mode_of = |path: &str| {
            owned
                .iter()
                .find(|o| o.path == Path::new(path) && o.mode.is_some())
                .unwrap_or_else(|| panic!("{path}"))
                .mode
                .unwrap()
        };
        assert_eq!(mode_of("/opt/snpanel"), 0o711);
        assert_eq!(mode_of("/opt/snpanel/backend"), 0o750);
        // And the mode comes after the ownership of the tree below it.
        let backend: Vec<usize> = owned
            .iter()
            .enumerate()
            .filter(|(_, o)| o.path == Path::new("/opt/snpanel/backend"))
            .map(|(i, _)| i)
            .collect();
        assert!(owned[backend[0]].recursive && owned[backend[0]].mode.is_none());
        assert_eq!(owned[backend[1]].mode, Some(0o750));
    }
}
