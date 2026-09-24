//! The units the panel runs from, and the two log-size drop-ins beside them.
//!
//! Source: `setup_systemd` and `configure_log_limits` in
//! `installer/install.sh` — the writing half of each. What the shell does
//! *after* writing them (`daemon-reload`, `enable --now`, the certbot and
//! blocklist timers it asks the helper to install) is the acting half and
//! lives in the phase, so this file can be tested without a systemd.
//!
//! Three values shape every unit and they all come from somewhere else:
//! `app_dir` and `backup_root` from the installer's own settings, and the web
//! group and the ClamAV unit name from [`snpanel_osabi::Platform`] — which is
//! why an RHEL box gets `nginx` and `clamd@scan.service` where a Debian one
//! gets `www-data` and `clamav-daemon.service`.

use snpanel_osabi::Platform;

/// What every unit is built from.
///
/// Owned rather than borrowed: it is built once per install, and one of its
/// fields has to be derived rather than copied.
#[derive(Debug, Clone)]
pub struct UnitSettings {
    /// `APP_DIR`, `/opt/snpanel` unless the operator set it.
    pub app_dir: String,
    /// `BACKUP_ROOT`, `/var/backups/snpanel` unless the operator set it.
    pub backup_root: String,
    /// `WEB_GROUP`. The API runs as `snpanel` and needs this as a
    /// supplementary group to read into a customer's web root.
    pub web_group: String,
    /// `CLAMAV_SERVICE`, **with** its `.service` suffix — the unit files
    /// spell it that way in `After=`, which is the conventional form there.
    pub clamav_service: String,
    /// `PANEL_PORT`. The API unit carries it in `--listen`; the Python
    /// wrapper this replaced read it from the environment instead.
    pub panel_port: u16,
}

impl UnitSettings {
    /// The defaults a stock install uses, with the two platform values filled
    /// in from the detected distribution.
    pub fn for_platform(platform: &dyn Platform) -> UnitSettings {
        UnitSettings {
            app_dir: "/opt/snpanel".to_string(),
            backup_root: "/var/backups/snpanel".to_string(),
            web_group: platform.web_group().to_string(),
            // `Platform::clamav_service` is the **bare** name, because its
            // other caller hands it to `systemctl is-active`, which takes
            // either spelling. A unit file's `After=` wants the suffix, and
            // the platform table's test records that asymmetry as the one
            // deliberate difference between the two copies of this value.
            clamav_service: clamav_unit_name(platform.clamav_service()),
            panel_port: 2222,
        }
    }

    /// The paths the API and the backup runner are allowed to write, despite
    /// `ProtectSystem` being off.
    ///
    /// Listed here once rather than in two heredocs: the two units carried
    /// the same line and a path added to one of them only would be a backup
    /// that cannot write where the panel can.
    fn read_write_paths(&self) -> String {
        format!(
            "{} /home {} /etc/nginx/conf.d /etc/nginx/snpanel/custom /tmp /var/lib/snpanel \
/home/admin/snpanel_backups/da /var/lib/snpanel/da-import /var/lib/snpanel/import-stage",
            self.app_dir, self.backup_root
        )
    }
}

/// `<name>.service`, idempotently.
///
/// Kept as a function rather than a `format!` at the call site so the
/// already-suffixed case is handled in one place: a platform that started
/// reporting `clamav-daemon.service` would otherwise produce
/// `clamav-daemon.service.service` in an `After=` line, which systemd
/// silently treats as a unit that does not exist.
fn clamav_unit_name(bare: &str) -> String {
    if bare.ends_with(".service") {
        return bare.to_string();
    }
    format!("{bare}.service")
}

/// The wrapper `snpanel-api.service` executes.
///
/// A script rather than an `ExecStart=` line because `app.serve` builds the
/// uvicorn server in Python: the same options the command line used to take,
/// plus one certificate per hostname, so the panel is reachable on every
/// domain on this machine that has a certificate rather than only on the one
pub fn api_service(settings: &UnitSettings) -> String {
    let UnitSettings {
        app_dir,
        web_group,
        panel_port,
        ..
    } = settings;
    let read_write = settings.read_write_paths();
    format!(
        "[Unit]
Description=SNPanel API
After=network.target mariadb.service

[Service]
Type=exec
User=snpanel
Group=snpanel
SupplementaryGroups={web_group} snpanel-sites
WorkingDirectory={app_dir}/backend
EnvironmentFile={app_dir}/backend/.env
Environment=HOME={app_dir}
Environment=SNPANEL_USE_HELPER=true
ExecStart=/usr/local/bin/snpanel-api-rust --listen 0.0.0.0:{panel_port} --env {app_dir}/backend/.env
Restart=always
RestartSec=3

# Hardening. These settings must not block the sudo helper; privileged work is
# restricted by /usr/local/sbin/snpanel-helper and /etc/sudoers.d/snpanel.
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths={read_write}
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=false
LockPersonality=true
MemoryDenyWriteExecute=false
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=~

[Install]
WantedBy=multi-user.target
"
    )
}

/// The timer runs `snpanel-api --run-backup-schedules`.
///
/// It named the Python runner until the panel itself became the binary, and
/// was switched by a drop-in the cutover wrote. There is no cutover: the
/// installer puts the binary on the box before it writes this unit, so the
/// unit can name it.
///
/// [`crate::update::runtime`] writes the same unit, and the two have to stay
/// identical — an update that rewrote it differently would change what a
/// timer runs without anybody asking for it.
pub fn backup_scheduler_service(settings: &UnitSettings) -> String {
    let UnitSettings {
        app_dir, web_group, ..
    } = settings;
    let read_write = settings.read_write_paths();
    format!(
        "[Unit]
Description=SNPanel scheduled backup runner
After=network.target mariadb.service

[Service]
Type=oneshot
User=snpanel
Group=snpanel
SupplementaryGroups={web_group} snpanel-sites
WorkingDirectory={app_dir}/backend
EnvironmentFile={app_dir}/backend/.env
Environment=HOME={app_dir}
Environment=SNPANEL_USE_HELPER=true
ExecStart=/usr/local/bin/snpanel-api-rust --run-backup-schedules --env {app_dir}/backend/.env
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths={read_write}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"
    )
}

pub fn backup_scheduler_timer() -> String {
    "[Unit]
Description=Run SNPanel scheduled backups every minute

[Timer]
OnBootSec=90s
OnUnitActiveSec=60s
AccuracySec=15s
Persistent=true

[Install]
WantedBy=timers.target
"
    .to_string()
}

/// The weekly malware scan.
///
/// `TimeoutStartSec=infinity` is the line that matters: the runner blocks
/// until the scan it started finishes, and a whole-server scan can take
/// hours. Without it systemd's ninety-second default kills the runner and the
/// scan lands in `interrupted`.
///
/// Its `ReadWritePaths` is **shorter** than the API's — no nginx directories,
/// no DA import staging. That is the shell's, and a scanner that could write
/// into `/etc/nginx` would be a scanner that could rewrite a vhost.
/// The timer runs `snpanel-api --run-malware-schedules`, for the same
/// reasons as the backup one above.
pub fn malware_scheduler_service(settings: &UnitSettings) -> String {
    let UnitSettings {
        app_dir,
        backup_root,
        web_group,
        clamav_service,
        ..
    } = settings;
    format!(
        "[Unit]
Description=SNPanel weekly malware scan runner
After=network.target {clamav_service}

[Service]
Type=oneshot
# The runner blocks until the scan it starts finishes (a whole-server scan can
# take hours). Without this, systemd's 90s default start timeout kills it and
# the scan lands in 'interrupted'.
TimeoutStartSec=infinity
User=snpanel
Group=snpanel
SupplementaryGroups={web_group} snpanel-sites
WorkingDirectory={app_dir}/backend
EnvironmentFile={app_dir}/backend/.env
Environment=HOME={app_dir}
Environment=SNPANEL_USE_HELPER=true
ExecStart=/usr/local/bin/snpanel-api-rust --run-malware-schedules --env {app_dir}/backend/.env
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
ReadWritePaths={app_dir} /home {backup_root} /tmp /var/lib/snpanel
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"
    )
}

pub fn malware_scheduler_timer() -> String {
    "[Unit]
Description=Ask every quarter of an hour whether the weekly malware scan is due

[Timer]
# Often enough that a server asleep at the appointed hour still scans when it
# comes back, while the runner itself refuses to start twice in one window.
OnBootSec=5min
OnUnitActiveSec=15min
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
"
    .to_string()
}

/// `SUDO_USER=snpanel` is not decoration.
///
/// `snpanel-helper` refuses to run unless `SUDO_USER` names the panel
/// account. These boot units have no real sudo in front of them — they run as
/// root directly — so they set it themselves. The timesync unit below does
/// the same.
pub fn autotune_service() -> String {
    "[Unit]
Description=Auto tune SNPanel PHP-FPM pools and MariaDB for this VPS
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=oneshot
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper php-fpm-retune
ExecStart=/usr/local/sbin/snpanel-helper mariadb-retune
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
"
    .to_string()
}

/// Keeping the clock honest.
///
/// TOTP logins reject every code once the clock drifts past about thirty
/// seconds, and many budget VPS hosts block outbound UDP 123 so
/// `systemd-timesyncd` never converges. `snpanel-helper time-sync` then falls
/// back to an HTTPS `Date` header.
pub fn timesync_service() -> String {
    "[Unit]
Description=Correct the SNPanel server clock when NTP cannot reach the network
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper time-sync
RemainAfterExit=no
"
    .to_string()
}

pub fn timesync_timer() -> String {
    "[Unit]
Description=Check the SNPanel server clock at boot and hourly

[Timer]
OnBootSec=45s
OnUnitActiveSec=1h
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
"
    .to_string()
}

// --- log limits ------------------------------------------------------------

pub const JOURNALD_DROPIN_PATH: &str = "/etc/systemd/journald.conf.d/99-snpanel-size.conf";
pub const BTMP_LOGROTATE_PATH: &str = "/etc/logrotate.d/btmp";

/// A cap on the journal.
///
/// `systemd-journald` ships with no size limit: it falls back to ten per cent
/// of the filesystem, which on a 72G disk is 7.2G. Measured on a live server
/// the journal had reached 2.7G — fifty-three times the size of every nginx
/// log put together — fed mostly by SSH password-guessing hitting sshd
/// thousands of times an hour.
///
/// A drop-in rather than an edit of `journald.conf`, so a distribution
/// upgrade cannot quietly revert it.
pub fn journald_dropin() -> String {
    "# Managed by SNPanel.
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
MaxRetentionSec=2week
"
    .to_string()
}

/// Rotation for `btmp`, which records every failed login and which Ubuntu
/// ships no rule for. On the same server it had grown to 130M across two
/// files, holding 62,000 failed SSH attempts.
///
/// `su root root` is required: `/var/log` is `root:syslog` and
/// group-writable, and logrotate refuses to act on a file in a directory it
/// considers unsafe unless told whose identity to use.
pub fn btmp_logrotate() -> String {
    "# Managed by SNPanel.
/var/log/btmp {
    su root root
    missingok
    weekly
    create 0660 root utmp
    rotate 4
    compress
    notifempty
}
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/installer")
            .join(format!("{name}.expected"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the fixture {}: {e}", path.display()))
    }

    /// The settings the fixture was recorded with: a stock Debian 13 install
    /// at the documented defaults.
    fn debian() -> UnitSettings {
        UnitSettings {
            app_dir: "/opt/snpanel".to_string(),
            backup_root: "/var/backups/snpanel".to_string(),
            web_group: "www-data".to_string(),
            clamav_service: "clamav-daemon.service".to_string(),
            panel_port: 2222,
        }
    }

    #[test]
    fn every_unit_is_what_the_shell_writes() {
        let s = debian();
        assert_eq!(api_service(&s), fixture("snpanel-api.service"));
        assert_eq!(
            backup_scheduler_service(&s),
            fixture("snpanel-backup-scheduler.service")
        );
        assert_eq!(
            backup_scheduler_timer(),
            fixture("snpanel-backup-scheduler.timer")
        );
        assert_eq!(
            malware_scheduler_service(&s),
            fixture("snpanel-malware-scheduler.service")
        );
        assert_eq!(
            malware_scheduler_timer(),
            fixture("snpanel-malware-scheduler.timer")
        );
        assert_eq!(autotune_service(), fixture("snpanel-autotune.service"));
        assert_eq!(timesync_service(), fixture("snpanel-timesync.service"));
        assert_eq!(timesync_timer(), fixture("snpanel-timesync.timer"));
    }

    #[test]
    fn the_log_limits_are_what_the_shell_writes() {
        assert_eq!(journald_dropin(), fixture("99-snpanel-size.conf"));
        assert_eq!(btmp_logrotate(), fixture("btmp"));
    }

    /// The fixture can only be Debian's — there is no AlmaLinux here to run
    /// the shell on — so the RHEL shape is checked by the substitutions it
    /// makes rather than byte for byte. Both values come from the platform
    /// table, which has its own test against the shell's copy.
    #[test]
    fn the_rhel_units_carry_the_rhel_web_group_and_clamav_unit() {
        let rhel: &dyn Platform = &snpanel_osabi::rhel::AlmaLinux10;
        let settings = UnitSettings::for_platform(rhel);
        assert_eq!(settings.web_group, "nginx");
        // The suffix is added here, not carried by the platform table.
        assert_eq!(rhel.clamav_service(), "clamd@scan");
        assert_eq!(settings.clamav_service, "clamd@scan.service");

        let api = api_service(&settings);
        assert!(api.contains("SupplementaryGroups=nginx snpanel-sites"));
        assert!(!api.contains("www-data"));

        let malware = malware_scheduler_service(&settings);
        assert!(malware.contains("After=network.target clamd@scan.service"));
    }

    /// The suffix the unit files want, derived rather than copied — and
    /// the reason `clamav_unit_name` exists at all. It returned the bare name
    /// once, which would have put a unit systemd does not have into an
    /// `After=` line, where the failure is silent.
    #[test]
    fn the_clamav_unit_name_gains_the_suffix_it_is_missing() {
        assert_eq!(clamav_unit_name("clamav-daemon"), "clamav-daemon.service");
        assert_eq!(clamav_unit_name("clamd@scan"), "clamd@scan.service");
        // Idempotent, so a table that starts carrying the suffix does not
        // produce `clamav-daemon.service.service`.
        assert_eq!(
            clamav_unit_name("clamav-daemon.service"),
            "clamav-daemon.service"
        );

        let debian_platform: &dyn Platform = &snpanel_osabi::debian::Debian13;
        assert_eq!(
            UnitSettings::for_platform(debian_platform).clamav_service,
            "clamav-daemon.service"
        );
    }

    /// The scanner's writable set is deliberately smaller than the API's.
    ///
    /// A scanner that could write into `/etc/nginx` would be a scanner that
    /// could rewrite a vhost, and the shell's two `ReadWritePaths` lines
    /// differ for that reason rather than by oversight.
    #[test]
    fn the_scanner_cannot_write_where_the_api_can() {
        let s = debian();
        let api = api_service(&s);
        let malware = malware_scheduler_service(&s);
        assert!(api.contains("/etc/nginx/conf.d"));
        assert!(!malware.contains("/etc/nginx"));
        assert!(!malware.contains("import-stage"));
    }

    /// Both boot units run as root with no sudo in front of them, and the
    /// helper refuses to run unless `SUDO_USER` names the panel account.
    #[test]
    fn the_boot_units_name_the_account_the_helper_demands() {
        for unit in [autotune_service(), timesync_service()] {
            assert!(
                unit.contains("Environment=SUDO_USER=snpanel"),
                "a helper unit with no SUDO_USER does nothing but log a refusal"
            );
        }
    }

    /// A whole-server scan can take hours; systemd's default would kill it at
    /// ninety seconds and the scan would land in `interrupted`.
    #[test]
    fn the_scan_runner_is_allowed_to_take_as_long_as_it_takes() {
        assert!(malware_scheduler_service(&debian()).contains("TimeoutStartSec=infinity"));
    }
}
