//! The installer's phases, as a program `install.sh` can call.
//!
//! [`snpanel_installer`] has held the *deciding* half of most of
//! `installer/install.sh` for some time — each phase split into a pure
//! function with a golden fixture taken from the bash running on a real
//! Debian 13, and a writing half of a few lines of `std::fs`. What it has
//! never had is a caller: no binary depended on the crate, so CI built and
//! tested it and no machine ran a line of it.
//!
//! This is the caller. One subcommand per phase, each one the writing half
//! the crate deliberately left out, so a phase moves across by replacing a
//! shell function with a line that runs this.
//!
//! **It is not a general-purpose tool.** It runs as root, during an install
//! or an update, from a script that has already decided the order. There is
//! no argument parsing beyond the verb because there is nothing for an
//! operator to choose: the settings come from the environment `install.sh`
//! already exports.

use std::process::ExitCode;

use snpanel_installer::systemd_units::{self, UnitSettings};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("systemd-units") => run(phase_systemd_units()),
        Some("log-limits") => run(phase_log_limits()),
        Some("--help") | Some("-h") | None => {
            help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("snpanel-install: unknown phase: {other}");
            help();
            ExitCode::from(1)
        }
    }
}

fn help() {
    println!("snpanel-install - one phase of a SNPanel install\n");
    println!("  snpanel-install systemd-units    write and enable the panel's units");
    println!("  snpanel-install log-limits       cap the journal and rotate btmp\n");
    println!("Settings come from the environment install.sh exports:");
    println!("  APP_DIR       default /opt/snpanel");
    println!("  BACKUP_ROOT   default /var/backups/snpanel");
    println!("  PANEL_PORT    default 2222");
}

fn run(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("snpanel-install: {e}");
            ExitCode::from(1)
        }
    }
}

/// Source: `setup_systemd` in `install.sh`.
///
/// The eight unit bodies come from the crate, where they have golden
/// fixtures. What is here is what the shell did around them: create the data
/// directories, write, reload, drop the units a previous release left
/// behind, and enable.
///
/// **One measured difference.** The shell writes
/// `After=network.target clamav-daemon` in the malware scheduler, without the
/// `.service` suffix, and systemd silently drops a dependency it cannot
/// resolve - `systemctl show -p After` on a unit written that way does not
/// list ClamAV at all. The crate's `clamav_unit_name` adds the suffix, so
/// the weekly scan waits for the daemon it scans with. The fixture recorded
/// from an earlier install.sh has the suffix too; the shell drifted.
///
/// Every `systemctl` here is best-effort except the two that decide whether
/// the panel runs at all. An install that cannot enable the autotune unit is
/// an install with untuned PHP pools; one that cannot start `snpanel-api` is
/// not an install.
fn phase_systemd_units() -> Result<(), String> {
    let platform = snpanel_osabi::detect().map_err(|e| format!("unsupported platform: {e}"))?;
    let mut settings = UnitSettings::for_platform(platform.as_ref());
    if let Some(v) = env_opt("APP_DIR") {
        settings.app_dir = v;
    }
    if let Some(v) = env_opt("BACKUP_ROOT") {
        settings.backup_root = v;
    }
    if let Some(v) = env_opt("PANEL_PORT").and_then(|v| v.parse().ok()) {
        settings.panel_port = v;
    }

    // `install -d -o snpanel -g snpanel -m 0750 /var/lib/snpanel
    // /var/lib/snpanel/geoip`, which the shell does between two heredocs.
    for dir in ["/var/lib/snpanel", "/var/lib/snpanel/geoip"] {
        install_dir(dir, "snpanel", "snpanel", 0o750);
    }

    let units = unit_files(&settings);
    for (path, body) in &units {
        std::fs::write(path, body).map_err(|e| format!("writing {path}: {e}"))?;
    }

    systemctl(&["daemon-reload"]);

    // A release before this one shipped an auto-update timer. Leaving it
    // enabled means two things updating the panel.
    systemctl(&["disable", "--now", "snpanel-auto-update.timer"]);
    for stale in [
        "/etc/systemd/system/snpanel-auto-update.service",
        "/etc/systemd/system/snpanel-auto-update.timer",
    ] {
        let _ = std::fs::remove_file(stale);
    }
    systemctl(&["daemon-reload"]);

    // All three are fatal, because all three are in the shell under
    // `set -euo pipefail` with no `|| true`. The first draft here made the
    // malware timer non-fatal on the reasoning that a box without ClamAV
    // still has a panel - which is true and is not what the installer has
    // been doing, and a timer that silently did not get enabled is a weekly
    // scan that never runs.
    for unit in [
        "snpanel-api",
        "snpanel-backup-scheduler.timer",
        "snpanel-malware-scheduler.timer",
    ] {
        if !systemctl(&["enable", "--now", unit]) {
            return Err(format!("could not enable {unit}"));
        }
    }

    systemctl(&["enable", "snpanel-autotune.service"]);
    systemctl(&["start", "snpanel-autotune.service"]);
    systemctl(&["enable", "snpanel-timesync.timer"]);

    // Start the clock unit only once the helper that answers `time-sync` is
    // in place, so it never flashes up as a failed unit mid-install.
    if user_exists("snpanel") {
        systemctl(&["start", "snpanel-timesync.timer"]);
        systemctl(&["start", "snpanel-timesync.service"]);
        for verb in [
            "certbot-auto-renew-install",
            "firewall-blocklist-timer-install",
            "panel-sni-sync",
        ] {
            helper(&settings.app_dir, verb);
        }
    }
    Ok(())
}

/// Every unit the panel runs from, and where it goes.
///
/// A list rather than eight `write` calls so
/// `every_recorded_unit_is_written` can read it: the fixtures in
/// `tests/golden/installer` were recorded from `install.sh` writing these
/// files, so a unit dropped from here is one the shell used to write and
/// this no longer does - and nothing at run time would say so, because a
/// missing timer is a job that quietly never runs.
fn unit_files(settings: &UnitSettings) -> [(&'static str, String); 8] {
    [
        (
            "/etc/systemd/system/snpanel-api.service",
            systemd_units::api_service(settings),
        ),
        (
            "/etc/systemd/system/snpanel-backup-scheduler.service",
            systemd_units::backup_scheduler_service(settings),
        ),
        (
            "/etc/systemd/system/snpanel-backup-scheduler.timer",
            systemd_units::backup_scheduler_timer(),
        ),
        (
            "/etc/systemd/system/snpanel-malware-scheduler.service",
            systemd_units::malware_scheduler_service(settings),
        ),
        (
            "/etc/systemd/system/snpanel-malware-scheduler.timer",
            systemd_units::malware_scheduler_timer(),
        ),
        (
            "/etc/systemd/system/snpanel-autotune.service",
            systemd_units::autotune_service(),
        ),
        (
            "/etc/systemd/system/snpanel-timesync.service",
            systemd_units::timesync_service(),
        ),
        (
            "/etc/systemd/system/snpanel-timesync.timer",
            systemd_units::timesync_timer(),
        ),
    ]
}

/// Source: `configure_log_limits` in `install.sh`.
///
/// Why it exists, from the shell's own comment: journald ships with no size
/// limit and falls back to 10% of the filesystem, which on a 72G disk is
/// 7.2G. Measured on a live server the journal had reached 2.7G - fifty-three
/// times every nginx log put together - fed mostly by SSH password-guessing
/// hitting sshd thousands of times an hour. And `btmp`, which records every
/// failed login, had grown to 130M holding 62,000 attempts with no rule to
/// rotate it.
///
/// A drop-in rather than an edit of `journald.conf`, so a distribution
/// upgrade cannot quietly revert it.
///
/// Nothing here is fatal. A box whose journald will not restart keeps its old
/// limits, which is untidy and not a failed install.
fn phase_log_limits() -> Result<(), String> {
    write_best_effort(
        systemd_units::JOURNALD_DROPIN_PATH,
        &systemd_units::journald_dropin(),
    );
    systemctl(&["restart", "systemd-journald"]);
    // The drop-in caps what the journal may grow to from here; this is what
    // gets back the space it has already taken.
    let _ = std::process::Command::new("journalctl")
        .arg("--vacuum-size=500M")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    write_best_effort(
        systemd_units::BTMP_LOGROTATE_PATH,
        &systemd_units::btmp_logrotate(),
    );
    // `chmod 644`: logrotate refuses to read a configuration file that is
    // group- or world-writable, and says so only in its own log.
    if let Ok(meta) = std::fs::metadata(systemd_units::BTMP_LOGROTATE_PATH) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = meta.permissions();
        perms.set_mode(0o644);
        let _ = std::fs::set_permissions(systemd_units::BTMP_LOGROTATE_PATH, perms);
    }
    Ok(())
}

// ---------------------------------------------------------------------------

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// `systemctl ...`, with its output swallowed. Returns whether it succeeded,
/// which most callers ignore on purpose.
fn systemctl(args: &[&str]) -> bool {
    std::process::Command::new("systemctl")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The shell writes these with `cat >` and carries on whatever happens: a box
/// whose journald has no drop-in directory keeps its old log limits, which is
/// untidy and not a failed install.
fn write_best_effort(path: &str, body: &str) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, body);
}

fn install_dir(path: &str, owner: &str, group: &str, mode: u32) {
    let _ = std::process::Command::new("install")
        .args(["-d", "-o", owner, "-g", group, "-m"])
        .arg(format!("{mode:o}"))
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn user_exists(name: &str) -> bool {
    std::process::Command::new("id")
        .args(["-u", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `sudo -u snpanel env HOME=$APP_DIR sudo -n snpanel-helper <verb>`.
///
/// The double `sudo` is the shell's and it is not redundant: the helper
/// authorises on being reached *by the snpanel account through sudo*, so a
/// call made directly as root takes a different path through its own checks
/// than the one the panel uses. Running it the way the panel does is what
/// makes this a test of the path and not only of the verb.
fn helper(app_dir: &str, verb: &str) {
    let _ = std::process::Command::new("sudo")
        .args(["-u", "snpanel", "env"])
        .arg(format!("HOME={app_dir}"))
        .args(["sudo", "-n", "/usr/local/sbin/snpanel-helper", verb])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/installer")
    }

    /// Every unit the shell used to write is one this writes.
    ///
    /// The fixtures were recorded from `install.sh` writing these files, so
    /// the directory is the record of what a box is supposed to end up with.
    /// A unit dropped from `unit_files` would be a timer that quietly never
    /// runs, and nothing at run time would report it.
    #[test]
    fn every_recorded_unit_is_written() {
        let settings = UnitSettings {
            app_dir: "/opt/snpanel".to_string(),
            backup_root: "/var/backups/snpanel".to_string(),
            web_group: "www-data".to_string(),
            clamav_service: "clamav-daemon.service".to_string(),
            panel_port: 2222,
        };
        let written: Vec<String> = unit_files(&settings)
            .iter()
            .map(|(path, _)| {
                std::path::Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        let mut recorded = Vec::new();
        for entry in std::fs::read_dir(golden_dir())
            .expect("the fixtures")
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(unit) = name.strip_suffix(".expected") else {
                continue;
            };
            if unit.starts_with("snpanel-")
                && (unit.ends_with(".service") || unit.ends_with(".timer"))
            {
                recorded.push(unit.to_string());
            }
        }
        recorded.sort();
        assert_eq!(recorded.len(), 8, "the fixture set changed: {recorded:?}");

        for unit in &recorded {
            assert!(
                written.contains(unit),
                "{unit} has a fixture and is not written: {written:?}"
            );
        }
    }

    /// Units go where systemd reads them, and nowhere else.
    #[test]
    fn units_are_written_under_etc_systemd_system() {
        let settings = UnitSettings::for_platform(&snpanel_osabi::debian::Debian13);
        for (path, body) in unit_files(&settings) {
            assert!(
                path.starts_with("/etc/systemd/system/"),
                "{path} is outside the unit directory"
            );
            // A unit with no `[Unit]` section is a file systemd ignores.
            assert!(body.starts_with("[Unit]\n"), "{path} has no [Unit]");
            assert!(body.ends_with('\n'), "{path} does not end in a newline");
        }
    }

    /// The malware scheduler waits for the daemon it scans with.
    ///
    /// `install.sh` wrote `After=network.target clamav-daemon`, without the
    /// suffix, and systemd drops a dependency it cannot resolve without
    /// saying so - `systemctl show -p After` on a unit written that way does
    /// not list ClamAV at all. Measured on the demo container before this
    /// phase moved across.
    #[test]
    fn the_clamav_dependency_names_a_unit_systemd_can_resolve() {
        let settings = UnitSettings::for_platform(&snpanel_osabi::debian::Debian13);
        let (_, body) = unit_files(&settings)
            .into_iter()
            .find(|(p, _)| p.ends_with("snpanel-malware-scheduler.service"))
            .expect("the malware scheduler");
        let after = body
            .lines()
            .find(|l| l.starts_with("After="))
            .expect("an After= line");
        assert!(after.contains(".service"), "{after}");
    }
}
