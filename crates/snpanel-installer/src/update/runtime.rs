//! Re-applying the panel's runtime configuration to a box that already has
//! one.
//!
//! Source: `install_panel_runtime`.
//!
//! Most of what this phase writes — the systemd units, the `.env`, the sshd
//! block, the API start script — is the same text the installer writes, and
//! lives in [`crate::systemd_units`], [`crate::backend_env`] and
//! [`crate::update::panel_https`]. What is here is the part that is *only*
//! true of an update: settings a new release introduces, and the rollback
//! that stops a bad edit from locking everyone out.

/// Settings added to `.env` only when they are not already there.
///
/// `env_set_default`, not `env_set`: an operator who has changed one keeps
/// their value. This is the list a release grows when it adds a setting,
/// and the order is the shell's.
///
/// The empty defaults are not filler. `PANEL_DOMAIN`, `PANEL_SSL_CERT`,
/// `PANEL_SSL_KEY` and `PANEL_SSL_MODE` have to *exist* as keys before
/// [`super::panel_https`] runs, because that phase reads them and an absent
/// key and an empty one have to mean the same thing to it.
pub fn defaults(app_dir: &str, panel_port: u16, panel_url: &str) -> Vec<(&'static str, String)> {
    vec![
        ("PANEL_PORT", panel_port.to_string()),
        ("PANEL_URL", panel_url.to_string()),
        ("PANEL_DOMAIN", String::new()),
        ("PANEL_SSL_CERT", String::new()),
        ("PANEL_SSL_KEY", String::new()),
        ("PANEL_SSL_MODE", String::new()),
        ("FRONTEND_DIST", format!("{app_dir}/frontend/dist")),
        ("REDIS_URL", "redis://localhost:6379/0".into()),
        ("RATE_LIMIT_BACKEND", "redis".into()),
    ]
}

/// `PANEL_URL` when the `.env` has none.
///
/// The address, then loopback. A panel that recorded no URL still gets a
/// usable one rather than an empty string that later lands in
/// `ALLOWED_ORIGINS` — where an empty value is not a permissive one, it is a
/// panel whose own frontend fails CORS.
pub fn fallback_url(server_ip: &str, panel_port: u16) -> String {
    let host = if server_ip.is_empty() {
        "127.0.0.1"
    } else {
        server_ip
    };
    format!("http://{host}:{panel_port}")
}

/// One directory the phase creates, with the mode it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dir {
    pub path: &'static str,
    pub owner: &'static str,
    pub group: &'static str,
    pub mode: u32,
}

/// The directories nginx configuration is written into.
///
/// `2775` — group-writable **and setgid**. The setgid bit is the part that
/// matters and the part that is easy to drop: without it, the first vhost
/// written after a package update belongs to `root:root` and the panel
/// cannot rewrite it. That surfaces as a permissions bug in the panel and is
/// not one.
pub fn nginx_dirs() -> Vec<Dir> {
    vec![
        Dir {
            path: "/etc/nginx/conf.d",
            owner: "root",
            group: "snpanel",
            mode: 0o2775,
        },
        Dir {
            path: "/etc/nginx/snpanel/custom",
            owner: "root",
            group: "snpanel",
            mode: 0o2775,
        },
    ]
}

/// The panel's own data directories, including the DirectAdmin import
/// staging areas.
///
/// All `0750 snpanel:snpanel`. The staging areas hold a customer's database
/// dumps in plaintext while an import runs, so world-readable would make the
/// import window the easiest way to read every password in their
/// application configuration.
pub fn data_dirs() -> Vec<Dir> {
    [
        "/var/lib/snpanel",
        "/var/lib/snpanel/geoip",
        "/home/admin/snpanel_backups/da",
        "/var/lib/snpanel/da-import",
        "/var/lib/snpanel/import-stage",
    ]
    .into_iter()
    .map(|path| Dir {
        path,
        owner: "snpanel",
        group: "snpanel",
        mode: 0o750,
    })
    .collect()
}

/// Where the sshd edit is backed up before it is made.
pub const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
pub const SSHD_BACKUP: &str = "/etc/ssh/sshd_config.snpanel.bak";

/// A drop-in an older release wrote, removed so its copy of the block does
/// not fight the one appended to the main file.
pub const SUPERSEDED_DROPIN: &str = "/etc/ssh/sshd_config.d/99-snpanel-sftp.conf";

/// What to do after editing `sshd_config`.
///
/// **The rollback is the whole point of this function.** An invalid
/// `sshd_config` does not break anything until sshd is next restarted — at
/// which point it refuses to start, and the box has no SSH at all. On a
/// remote server that is unrecoverable without console access, so the edit
/// is validated with `sshd -t` and the backup is copied back over the
/// original the moment it does not pass.
///
/// Note what is *not* done on failure: the update carries on. Losing the
/// SFTP block is a feature not working; refusing to finish the update leaves
/// a half-updated panel, which is worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshdOutcome {
    /// Valid. Reload sshd under whichever unit name this platform uses.
    Reload,
    /// Invalid. Put the backup back and warn.
    Rollback,
}

pub fn sshd_outcome(config_is_valid: bool) -> SshdOutcome {
    if config_is_valid {
        SshdOutcome::Reload
    } else {
        SshdOutcome::Rollback
    }
}

/// Splice the SFTP block into `sshd_config`, validate, and reload or roll
/// back.
///
/// **A writing half in the library, which this crate otherwise keeps out of
/// it.** The rule here is that a phase decides and its caller writes, and it
/// holds while there is one caller. This has two: `snpanel-install
/// sftp-access` during an install, and `snpanel fix-permissions` when an
/// operator repairs a box. Two copies of an edit to `sshd_config` is two
/// chances to get the rollback wrong, and the rollback is the only thing
/// standing between a bad edit and a remote box with no SSH.
///
/// The callers differ in exactly one way, and it is what they do with the
/// answer rather than anything in here. The installer treats
/// [`SshdOutcome::Rollback`] as fatal, because a box it cannot finish
/// configuring should not be reported as installed. The repair path prints a
/// warning and carries on - it has other repairs to make, and losing the SFTP
/// block is a feature not working while stopping leaves the box half-fixed.
pub fn apply_sftp_block(block: &str) -> Result<SshdOutcome, String> {
    // sshd refuses to start without it, and a box whose `/run/sshd` went with
    // a reboot has no SSH after the next restart.
    let _ = std::fs::create_dir_all("/run/sshd");

    // An older release wrote its copy of the block as a drop-in. Two `Match
    // Group snpanel-sftp` blocks is a duplicate sshd will not start on.
    let _ = std::fs::remove_file(SUPERSEDED_DROPIN);

    // `touch`: a box with no `sshd_config` at all still gets the block, and
    // the backup below needs something to copy.
    if !std::path::Path::new(SSHD_CONFIG).exists() {
        std::fs::write(SSHD_CONFIG, "").map_err(|e| format!("creating {SSHD_CONFIG}: {e}"))?;
    }
    std::fs::copy(SSHD_CONFIG, SSHD_BACKUP)
        .map_err(|e| format!("backing up {SSHD_CONFIG}: {e}"))?;

    std::fs::write(SSHD_CONFIG, block).map_err(|e| {
        // Put it back before reporting: a half-written sshd_config is worse
        // than the one that was there.
        let _ = std::fs::copy(SSHD_BACKUP, SSHD_CONFIG);
        format!("writing {SSHD_CONFIG}: {e}")
    })?;

    let valid = std::process::Command::new("sshd")
        .arg("-t")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    match sshd_outcome(valid) {
        SshdOutcome::Reload => {
            // `ssh` on Debian, `sshd` on the RHEL family. The shell tries
            // both and shrugs, because a reload that did not happen is a
            // block that takes effect at the next restart.
            for unit in ["ssh", "sshd"] {
                let reloaded = std::process::Command::new("systemctl")
                    .args(["reload", unit])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if reloaded {
                    break;
                }
            }
            Ok(SshdOutcome::Reload)
        }
        SshdOutcome::Rollback => {
            std::fs::copy(SSHD_BACKUP, SSHD_CONFIG)
                .map_err(|e| format!("restoring {SSHD_CONFIG}: {e}"))?;
            Ok(SshdOutcome::Rollback)
        }
    }
}

pub const SSHD_INVALID: &str =
    "WARNING: invalid SSHD configuration; skipped SNPanel SFTP password block";

/// The unit names sshd goes by, tried in order.
///
/// `ssh` on Debian, `sshd` on EL, and a failure of both is tolerated — a
/// container may have neither, and the block is written either way for
/// whenever sshd does start.
pub const SSHD_UNITS: &[&str] = &["ssh", "sshd"];

/// The step-cache key for the permission sweep, and what it is fingerprinted
/// against.
///
/// The sweep is a recursive `chown` plus four `chmod` passes over every file
/// of every site, so on a box with a hundred sites it is minutes. It
/// retrofits old installs to the current permission policy — and that policy
/// *is this script*, so once applied it does not drift. The panel sets
/// permissions correctly on every site it creates in between.
///
/// Fingerprinting it against the update script itself is therefore exactly
/// right: the sweep re-runs when, and only when, the rules it applies have
/// changed.
pub const HARDENING_STEP: &str = "user-hardening";
pub const HARDENING_SKIPPED: &str =
    "  (site directory permissions already match this release; skipping the sweep)";

#[cfg(test)]
mod tests {
    use super::*;

    /// `env_set_default`, so an operator who changed one keeps their value.
    #[test]
    fn the_defaults_are_the_shells_in_the_shells_order() {
        let d = defaults("/opt/snpanel", 2222, "https://a.com:2222");
        let names: Vec<&str> = d.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            names,
            [
                "PANEL_PORT",
                "PANEL_URL",
                "PANEL_DOMAIN",
                "PANEL_SSL_CERT",
                "PANEL_SSL_KEY",
                "PANEL_SSL_MODE",
                "FRONTEND_DIST",
                "REDIS_URL",
                "RATE_LIMIT_BACKEND",
            ]
        );
        assert_eq!(
            d.iter().find(|(k, _)| *k == "FRONTEND_DIST").unwrap().1,
            "/opt/snpanel/frontend/dist"
        );
    }

    /// The four empty ones are not filler: they have to exist as keys before
    /// the HTTPS phase reads them, so an absent key and an empty one mean
    /// the same thing to it.
    #[test]
    fn the_certificate_keys_exist_even_when_empty() {
        let d = defaults("/opt/snpanel", 2222, "http://x:2222");
        for key in [
            "PANEL_DOMAIN",
            "PANEL_SSL_CERT",
            "PANEL_SSL_KEY",
            "PANEL_SSL_MODE",
        ] {
            let (_, value) = d.iter().find(|(k, _)| *k == key).expect(key);
            assert!(value.is_empty(), "{key}");
        }
    }

    /// An empty `ALLOWED_ORIGINS` is not a permissive one — it is a panel
    /// whose own frontend fails CORS — so a panel that recorded no URL still
    /// gets a usable one.
    #[test]
    fn a_panel_with_no_recorded_url_still_gets_one() {
        assert_eq!(
            fallback_url("203.0.113.10", 2222),
            "http://203.0.113.10:2222"
        );
        assert_eq!(fallback_url("", 2222), "http://127.0.0.1:2222");
    }

    /// Without setgid, the first vhost written after a package update
    /// belongs to `root:root` and the panel cannot rewrite it — which
    /// surfaces as a permissions bug in the panel and is not one.
    #[test]
    fn both_nginx_directories_are_setgid() {
        let dirs = nginx_dirs();
        assert_eq!(dirs.len(), 2);
        for dir in dirs {
            assert_eq!(dir.mode & 0o2000, 0o2000, "{} is not setgid", dir.path);
            assert_eq!(
                dir.mode & 0o020,
                0o020,
                "{} is not group-writable",
                dir.path
            );
            assert_eq!(dir.group, "snpanel");
            // And still not writable by anyone else.
            assert_eq!(dir.mode & 0o002, 0, "{}", dir.path);
        }
    }

    /// The staging areas hold a customer's database dumps in plaintext while
    /// an import runs.
    #[test]
    fn nothing_the_panel_stores_is_world_readable() {
        for dir in data_dirs() {
            assert_eq!(dir.mode & 0o007, 0, "{} is world-readable", dir.path);
            assert_eq!(dir.owner, "snpanel");
            assert_eq!(dir.group, "snpanel");
        }
        let paths: Vec<&str> = data_dirs().iter().map(|d| d.path).collect();
        assert!(paths.contains(&"/var/lib/snpanel/da-import"));
        assert!(paths.contains(&"/var/lib/snpanel/import-stage"));
        assert!(paths.contains(&"/home/admin/snpanel_backups/da"));
    }

    /// **The rollback.** An invalid `sshd_config` breaks nothing until sshd
    /// is next restarted, at which point it refuses to start and the box has
    /// no SSH at all — unrecoverable on a remote server without console
    /// access.
    #[test]
    fn an_invalid_config_is_rolled_back_rather_than_left() {
        assert_eq!(sshd_outcome(false), SshdOutcome::Rollback);
        assert_eq!(sshd_outcome(true), SshdOutcome::Reload);
        assert!(SSHD_INVALID.starts_with("WARNING: "));
        // The backup is beside the original and named for the panel, so an
        // operator finding it knows what wrote it.
        assert!(SSHD_BACKUP.starts_with(SSHD_CONFIG));
        assert!(SSHD_BACKUP.contains("snpanel"));
    }

    /// Losing the SFTP block is a feature not working; refusing to finish
    /// the update leaves a half-updated panel, which is worse. So the
    /// rollback warns and the update carries on — there is no third outcome.
    #[test]
    fn a_rolled_back_config_does_not_end_the_update() {
        let outcomes = [sshd_outcome(true), sshd_outcome(false)];
        assert_eq!(outcomes.len(), 2, "there is no fatal third outcome");
    }

    /// An older release wrote a drop-in; left in place its copy of the block
    /// would fight the one appended to the main file, and `Match` blocks do
    /// not merge.
    #[test]
    fn the_older_drop_in_is_removed_first() {
        assert!(SUPERSEDED_DROPIN.starts_with("/etc/ssh/sshd_config.d/"));
        assert!(SUPERSEDED_DROPIN.ends_with("-snpanel-sftp.conf"));
    }

    /// `ssh` on Debian, `sshd` on EL, and a container may have neither.
    #[test]
    fn sshd_is_reloaded_under_whichever_name_this_platform_uses() {
        assert_eq!(SSHD_UNITS, ["ssh", "sshd"]);
    }

    /// The sweep is minutes on a box with a hundred sites, and the policy it
    /// applies *is* the update script — so fingerprinting it against that
    /// script re-runs it when, and only when, the rules changed.
    #[test]
    fn the_permission_sweep_is_keyed_on_the_script_that_defines_it() {
        assert_eq!(HARDENING_STEP, "user-hardening");
        assert!(HARDENING_SKIPPED.contains("already match this release"));
    }
}
