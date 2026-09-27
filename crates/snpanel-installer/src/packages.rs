//! The base package transaction, and the two things around it.
//!
//! Source: `apt_get_locked`, `enable_extra_repos`, `install_base_packages`.
//!
//! What is here is the policy rather than the package list — the list is
//! `BASE_PACKAGES`, which belongs to the platform table. The policy is where
//! the installs that fail in the field actually fail: a dpkg lock held by
//! cloud-init, a repository that is not on the base image, and one specific
//! broken-dependency state that apt itself knows how to repair.

use std::time::Duration;

/// The locks `apt_get_locked` waits on.
///
/// All three, because which one is held depends on what the other package
/// manager is doing, and a wait on only `lock-frontend` returns while an
/// `apt-get update` still holds the lists lock.
pub const DPKG_LOCKS: &[&str] = &[
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
    "/var/lib/apt/lists/lock",
];

/// How often the lock is re-checked, and for how long.
///
/// Five minutes is not arbitrary: a fresh cloud image usually has
/// `unattended-upgrades` running at first boot, and it is normal for that to
/// hold the lock for two or three. Failing sooner turns a normal boot into a
/// failed install; waiting forever turns a stuck package manager into an
/// install that never says anything.
pub const LOCK_POLL: Duration = Duration::from_secs(5);
pub const LOCK_CEILING: Duration = Duration::from_secs(300);

/// Printed once, on the first wait — not on every poll, which would fill an
/// install log with sixty identical lines.
pub const WAITING_MESSAGE: &str = "Waiting for another package manager to finish...";
/// And the message when the ceiling is reached.
pub const LOCK_TIMEOUT_MESSAGE: &str = "Timed out after 5 minutes waiting for the dpkg lock.";

/// `DEBIAN_FRONTEND=noninteractive`, on every apt invocation.
///
/// Without it a package with a debconf prompt — `iptables-persistent` is the
/// usual one — stops on a dialog nobody is there to answer, and the install
/// hangs rather than failing.
pub const APT_ENV: (&str, &str) = ("DEBIAN_FRONTEND", "noninteractive");

/// Whether the wait should carry on, having already waited `waited`.
///
/// `Err` is the timeout. Separated from the sleeping so the policy can be
/// tested without one.
pub fn keep_waiting(waited: Duration) -> Result<Duration, &'static str> {
    if waited >= LOCK_CEILING {
        return Err(LOCK_TIMEOUT_MESSAGE);
    }
    Ok(waited + LOCK_POLL)
}

/// A repository that has to exist before the base transaction runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repo {
    /// Installed as a package, if it is not installed already.
    Package(&'static str),
    /// Installed from a URL, because EL does not carry Remi's release
    /// package in any repository it already has.
    Rpm(String),
    /// A repository that is already configured and only needs enabling.
    ///
    /// Best-effort: CRB is enabled out of the box on AlmaLinux 10 but not on
    /// every EL rebuild, and some EPEL packages need it. Enabling it twice
    /// is harmless, and failing to enable it is not worth ending an install
    /// that may not need it.
    Enable(&'static str),
}

impl Repo {
    /// Whether a failure here ends the install.
    pub fn required(&self) -> bool {
        !matches!(self, Self::Enable(_))
    }
}

/// The repositories to add before installing the base packages.
///
/// Debian and Ubuntu get none: Ondrej's PPA is added by `install_php`, where
/// it is used. EL needs both EPEL and Remi *before* the base transaction,
/// because EPEL carries three packages the base list asks for — certbot,
/// phpMyAdmin and composer — and a transaction that runs first simply
/// reports them as not found.
pub fn extra_repos(is_rhel: bool, os_major: u32) -> Vec<Repo> {
    if !is_rhel {
        return Vec::new();
    }
    vec![
        Repo::Package("epel-release"),
        Repo::Enable("crb"),
        Repo::Rpm(format!(
            "https://rpms.remirepo.net/enterprise/remi-release-{os_major}.rpm"
        )),
    ]
}

/// What to do when the base transaction fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnFailure {
    /// Run `apt-get --fix-broken install -y`, ignore whether *that* worked,
    /// and try the same package list once more.
    ///
    /// Seen on several VPS images: a stuck package pin — `libsystemd-shared`
    /// is the one that turned up — leaves an unrelated dependency "not going
    /// to be installed", and apt's own output suggests exactly this fix.
    /// Repairing once and retrying turns a whole failed install into either
    /// a success or a failure that names the real package.
    RepairAndRetry,
    /// Stop, with the reason.
    ///
    /// dnf has no equivalent repair step, and inventing one would mean
    /// guessing at a state nobody has reported.
    Fail(&'static str),
}

pub const DNF_FAILURE: &str = "Base package installation failed; see the dnf output above.";
pub const REPAIRING_MESSAGE: &str =
    "Package install hit a broken dependency; repairing and retrying...";

pub fn on_failure(is_rhel: bool) -> OnFailure {
    if is_rhel {
        OnFailure::Fail(DNF_FAILURE)
    } else {
        OnFailure::RepairAndRetry
    }
}

/// A service the base phase brings up, and whether the install depends on
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enable {
    pub unit: String,
    /// `false` means `|| true` in the shell: the install carries on.
    pub required: bool,
}

/// The services enabled once the packages are in.
///
/// Three are required, and they are the three the panel cannot be a panel
/// without: the web server, the database and the cache. The rest are
/// best-effort on purpose — `ssh` is tried under three names because the
/// unit is `ssh` on Debian and `sshd` on EL and a container may have
/// neither, and cron is tried because a minimal EL image does not run it
/// while Ubuntu already does. An install that died because a container had
/// no sshd would be refusing to finish over something the operator did
/// deliberately.
pub fn services(redis: &str, ssh: &str, cron: &str) -> Vec<Enable> {
    let mut out = vec![
        Enable {
            unit: "nginx".into(),
            required: true,
        },
        Enable {
            unit: "mariadb".into(),
            required: true,
        },
        Enable {
            unit: redis.into(),
            required: true,
        },
    ];
    // The platform's name first, then the two conventional ones. Duplicates
    // are dropped: `systemctl enable --now ssh` twice is not an error, but a
    // log line saying it happened twice is a question an operator has to
    // answer.
    for name in [ssh, "ssh", "sshd"] {
        if !out.iter().any(|e| e.unit == name) {
            out.push(Enable {
                unit: name.into(),
                required: false,
            });
        }
    }
    out.push(Enable {
        unit: cron.into(),
        required: false,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wait on only `lock-frontend` returns while an `apt-get update`
    /// still holds the lists lock, and the transaction then fails on a lock
    /// the installer just finished waiting for.
    #[test]
    fn all_three_locks_are_waited_on() {
        assert_eq!(DPKG_LOCKS.len(), 3);
        assert!(DPKG_LOCKS.contains(&"/var/lib/apt/lists/lock"));
        assert!(DPKG_LOCKS.contains(&"/var/lib/dpkg/lock-frontend"));
        assert!(DPKG_LOCKS.contains(&"/var/lib/dpkg/lock"));
    }

    /// The ceiling is reached in exactly sixty polls, and the message says
    /// five minutes — so the two have to agree, or an operator reads a
    /// timeout that did not happen when it said it did.
    #[test]
    fn the_wait_ends_when_the_message_says_it_does() {
        let mut waited = Duration::ZERO;
        let mut polls = 0;
        loop {
            match keep_waiting(waited) {
                Ok(next) => {
                    waited = next;
                    polls += 1;
                    assert!(polls <= 1000, "the wait never ends");
                }
                Err(message) => {
                    assert_eq!(message, LOCK_TIMEOUT_MESSAGE);
                    break;
                }
            }
        }
        assert_eq!(polls, 60);
        assert_eq!(waited, LOCK_CEILING);
        assert!(LOCK_TIMEOUT_MESSAGE.contains("5 minutes"));
        assert_eq!(LOCK_CEILING, Duration::from_secs(5 * 60));
    }

    /// Both of these are printed once and read by whoever is looking at an
    /// install that is taking longer than they expected. The wait message in
    /// particular is what tells an operator the installer is waiting on
    /// something else rather than stuck.
    #[test]
    fn the_two_progress_messages_say_what_is_happening() {
        assert_eq!(
            WAITING_MESSAGE,
            "Waiting for another package manager to finish..."
        );
        assert_eq!(
            REPAIRING_MESSAGE,
            "Package install hit a broken dependency; repairing and retrying..."
        );
    }

    /// A package with a debconf prompt would otherwise stop on a dialog
    /// nobody is there to answer — an install that hangs rather than fails.
    #[test]
    fn apt_is_never_interactive() {
        assert_eq!(APT_ENV, ("DEBIAN_FRONTEND", "noninteractive"));
    }

    /// EPEL carries three packages the base list asks for, so it has to be
    /// there before the transaction and not after it.
    #[test]
    fn el_gets_both_repositories_and_the_debian_family_gets_none() {
        assert!(extra_repos(false, 13).is_empty());
        let el = extra_repos(true, 10);
        assert!(el.contains(&Repo::Package("epel-release")));
        assert!(el
            .iter()
            .any(|r| matches!(r, Repo::Rpm(u) if u.contains("remi-release-10.rpm"))));
    }

    /// The Remi release package is named for the EL major, and installing
    /// the wrong one gives a repository pointing at another release's
    /// packages.
    #[test]
    fn the_remi_release_follows_the_el_major() {
        for major in [9, 10] {
            let repos = extra_repos(true, major);
            let url = repos
                .iter()
                .find_map(|r| match r {
                    Repo::Rpm(u) => Some(u.clone()),
                    _ => None,
                })
                .expect("a Remi rpm");
            assert!(url.ends_with(&format!("remi-release-{major}.rpm")), "{url}");
        }
    }

    /// CRB is already on for AlmaLinux 10 and absent from some rebuilds.
    /// Ending an install over a repository that may not be needed would be
    /// the wrong trade.
    #[test]
    fn only_crb_is_allowed_to_fail() {
        for repo in extra_repos(true, 10) {
            assert_eq!(
                repo.required(),
                !matches!(repo, Repo::Enable(_)),
                "{repo:?}"
            );
        }
        assert!(!Repo::Enable("crb").required());
        assert!(Repo::Package("epel-release").required());
    }

    /// apt's own output suggests the repair, so taking it turns a whole
    /// failed install into either a success or a failure that names the real
    /// package. dnf has no equivalent, and inventing one would be guessing.
    #[test]
    fn only_apt_repairs_and_retries() {
        assert_eq!(on_failure(false), OnFailure::RepairAndRetry);
        assert_eq!(on_failure(true), OnFailure::Fail(DNF_FAILURE));
    }

    /// The three the panel cannot be a panel without, and nothing else.
    #[test]
    fn exactly_the_three_load_bearing_services_are_required() {
        let units = services("redis-server", "ssh", "cron");
        let required: Vec<&str> = units
            .iter()
            .filter(|e| e.required)
            .map(|e| e.unit.as_str())
            .collect();
        assert_eq!(required, ["nginx", "mariadb", "redis-server"]);

        // Valkey on EL, and it is still required — the name changed, not
        // what the panel needs from it.
        let el = services("valkey", "sshd", "crond");
        let required: Vec<&str> = el
            .iter()
            .filter(|e| e.required)
            .map(|e| e.unit.as_str())
            .collect();
        assert_eq!(required, ["nginx", "mariadb", "valkey"]);
    }

    /// The unit is `ssh` on Debian and `sshd` on EL, and a container may
    /// have neither. All the names get tried, none of them is required, and
    /// none is tried twice.
    #[test]
    fn ssh_is_tried_under_every_name_and_required_under_none() {
        for (platform_name, expected) in [("ssh", 2), ("sshd", 2), ("openssh", 3)] {
            let units = services("redis-server", platform_name, "cron");
            let ssh: Vec<&str> = units
                .iter()
                .filter(|e| e.unit.contains("ssh"))
                .map(|e| e.unit.as_str())
                .collect();
            assert_eq!(ssh.len(), expected, "{platform_name}: {ssh:?}");
            assert_eq!(ssh[0], platform_name);
            assert!(units
                .iter()
                .filter(|e| e.unit.contains("ssh"))
                .all(|e| !e.required));
        }
    }

    /// A minimal EL image does not run cron and Ubuntu already does, so it
    /// is enabled either way — and an install that died because a container
    /// had no cron would be refusing to finish over something the operator
    /// did deliberately.
    #[test]
    fn cron_is_enabled_but_not_demanded() {
        let units = services("redis-server", "ssh", "crond");
        let cron = units.last().expect("something");
        assert_eq!(cron.unit, "crond");
        assert!(!cron.required);
    }
}
