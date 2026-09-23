//! Presenting Remi's PHP layout under Debian's names.
//!
//! Source: `setup_php_compat_shim`.
//!
//! The panel's service layer is written against Debian's PHP layout: it
//! reads and writes `/etc/php/<version>/fpm/{php.ini,conf.d,pool.d}` and
//! restarts `php<version>-fpm`. Rather than thread an OS abstraction through
//! forty call sites, EL presents those names as symlinks into the Remi tree,
//! which makes the existing code correct there.
//!
//! **This is a compatibility shim, not a port**, and it is worth being
//! explicit about what it does not paper over:
//!
//! * Remi shares one `php.d` between the CLI and FPM SAPIs, so a value the
//!   panel sets for FPM also reaches CLI. Debian keeps the two separate, and
//!   no arrangement of symlinks can split one directory into two.
//! * The panel's "install another PHP version" action shells out to
//!   `apt-get` and remains Debian-only; on EL it fails rather than
//!   half-working.

use std::path::PathBuf;

/// One symlink the shim creates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub at: PathBuf,
    pub to: PathBuf,
}

/// Every link, for one PHP version.
///
/// `dotted` is Debian's spelling (`8.4`), `compact` Remi's (`84`), and
/// `etc_dir` is Remi's configuration directory for that version.
///
/// The two inside the Remi tree are **relative** targets, and that is not
/// incidental: they have to resolve after `/etc/php/<v>/fpm` is followed
/// into the Remi tree, so an absolute target would work by luck rather than
/// by construction.
/// The systemd alias is **not** here: it is conditional on the real unit
/// existing, and lives in [`unit_link`].
pub fn links(dotted: &str, etc_dir: &str, binary: &str) -> Vec<Link> {
    vec![
        Link {
            at: PathBuf::from(format!("{etc_dir}/conf.d")),
            to: PathBuf::from("php.d"),
        },
        Link {
            at: PathBuf::from(format!("{etc_dir}/pool.d")),
            to: PathBuf::from("php-fpm.d"),
        },
        Link {
            at: PathBuf::from(format!("/etc/php/{dotted}/fpm")),
            to: PathBuf::from(etc_dir),
        },
        // `php8.4 -v` is used by the installer and by the panel's PHP
        // tuning page. On EL there is no `php<version>` on PATH at all
        // until this exists.
        Link {
            at: PathBuf::from(format!("/usr/local/bin/php{dotted}")),
            to: PathBuf::from(binary),
        },
    ]
}

/// The directory created before the `fpm` link can go in it.
pub fn version_dir(dotted: &str) -> PathBuf {
    PathBuf::from(format!("/etc/php/{dotted}"))
}
pub const VERSION_DIR_MODE: u32 = 0o755;

/// The unit link is only made when the real unit is there.
///
/// A unit file that is a symlink is a systemd *alias*, so both names drive
/// the same service — which is what lets `systemctl restart php8.4-fpm`
/// reach `php84-php-fpm`. Linking to a unit that does not exist would give
/// systemd a broken alias and an error on every `daemon-reload`.
pub fn unit_link(dotted: &str, compact: &str, real_unit_exists: bool) -> Option<Link> {
    real_unit_exists.then(|| Link {
        at: PathBuf::from(format!("/etc/systemd/system/php{dotted}-fpm.service")),
        to: PathBuf::from(format!(
            "/usr/lib/systemd/system/php{compact}-php-fpm.service"
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el_links() -> Vec<Link> {
        links(
            "8.4",
            "/etc/opt/remi/php84",
            "/opt/remi/php84/root/usr/bin/php",
        )
    }

    /// The names the panel's service layer already writes to have to exist,
    /// or forty call sites are wrong on this platform.
    #[test]
    fn debians_names_all_point_into_the_remi_tree() {
        let links = el_links();
        let at: Vec<String> = links
            .iter()
            .map(|l| l.at.to_string_lossy().into_owned())
            .collect();
        assert!(at.contains(&"/etc/php/8.4/fpm".to_string()));
        assert!(at.contains(&"/etc/opt/remi/php84/conf.d".to_string()));
        assert!(at.contains(&"/etc/opt/remi/php84/pool.d".to_string()));
        assert!(at.contains(&"/usr/local/bin/php8.4".to_string()));
    }

    /// `conf.d` and `pool.d` are created *inside* the Remi tree with
    /// relative targets, so that the single `/etc/php/<v>/fpm` link resolves
    /// both of them. An absolute target would happen to work and would stop
    /// working the moment the tree moved.
    #[test]
    fn the_links_inside_the_remi_tree_are_relative() {
        for link in el_links() {
            if link.at.starts_with("/etc/opt/remi") {
                assert!(
                    link.to.is_relative(),
                    "{} points at an absolute {}",
                    link.at.display(),
                    link.to.display()
                );
            }
        }
    }

    /// Debian's names, Remi's contents: `conf.d` is `php.d` and `pool.d` is
    /// `php-fpm.d`. Swapping the two would put pool configuration where the
    /// interpreter looks for ini settings.
    #[test]
    fn each_debian_name_maps_to_the_remi_directory_that_holds_it() {
        let links = el_links();
        let find = |name: &str| {
            links
                .iter()
                .find(|l| l.at.ends_with(name))
                .unwrap_or_else(|| panic!("no {name}"))
                .to
                .clone()
        };
        assert_eq!(find("conf.d"), PathBuf::from("php.d"));
        assert_eq!(find("pool.d"), PathBuf::from("php-fpm.d"));
    }

    /// A unit file that is a symlink is a systemd alias, so both names drive
    /// the same service — which is what lets `systemctl restart php8.4-fpm`
    /// reach `php84-php-fpm`.
    #[test]
    fn the_unit_alias_carries_both_spellings_of_the_version() {
        let link = unit_link("8.4", "84", true).expect("a link");
        assert_eq!(
            link.at,
            PathBuf::from("/etc/systemd/system/php8.4-fpm.service")
        );
        assert_eq!(
            link.to,
            PathBuf::from("/usr/lib/systemd/system/php84-php-fpm.service")
        );
    }

    /// The alias is conditional and the rest is not, so it must not be in
    /// the unconditional set — a box where Remi's unit is missing would
    /// otherwise get a dangling one anyway.
    #[test]
    fn the_conditional_alias_is_not_among_the_unconditional_links() {
        assert!(
            !el_links()
                .iter()
                .any(|l| l.at.starts_with("/etc/systemd/system")),
            "the alias is created unconditionally"
        );
    }

    /// Linking to a unit that does not exist gives systemd a broken alias
    /// and an error on every `daemon-reload`.
    #[test]
    fn no_alias_is_made_for_a_unit_that_is_not_there() {
        assert_eq!(unit_link("8.4", "84", false), None);
    }

    /// The directory has to exist before the `fpm` link can go in it, and it
    /// is read by the panel as `snpanel`, so it is world-readable and
    /// root-owned.
    #[test]
    fn the_version_directory_is_readable_and_not_writable_by_anyone_else() {
        assert_eq!(version_dir("8.4"), PathBuf::from("/etc/php/8.4"));
        assert_eq!(VERSION_DIR_MODE & 0o022, 0);
        assert_eq!(VERSION_DIR_MODE & 0o005, 0o005);
    }

    /// The shim is per version, so two installed versions get two complete
    /// sets and nothing is shared between them by accident.
    #[test]
    fn each_version_gets_its_own_complete_set() {
        let a = links(
            "8.3",
            "/etc/opt/remi/php83",
            "/opt/remi/php83/root/usr/bin/php",
        );
        let b = el_links();
        assert_eq!(a.len(), b.len());
        for link in &a {
            assert!(
                !b.contains(link),
                "{} is shared between versions",
                link.at.display()
            );
        }
    }
}
