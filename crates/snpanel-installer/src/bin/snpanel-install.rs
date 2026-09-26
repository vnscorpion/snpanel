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

// Two modules, one name. `signon_edits` rewrites the three values in the
// files an earlier install left; `phpmyadmin` writes those files in the
// first place.
use snpanel_core::phpmyadmin as signon_edits;
use snpanel_installer::backend_env;
use snpanel_installer::nginx_conf;
use snpanel_installer::php;
use snpanel_installer::phpmyadmin;
use snpanel_installer::systemd_units::{self, UnitSettings};
use snpanel_installer::tools_vhost;
use snpanel_installer::update::migrations;
use snpanel_installer::update::runtime;

/// Source: the `install -d` in `write_modsec_base_conf`.
const MODSEC_DIR: &str = "/etc/nginx/modsec";
const MODSEC_SITES_DIR: &str = "/etc/nginx/modsec/sites";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("systemd-units") => run(phase_systemd_units()),
        Some("update-units") => run(phase_update_units()),
        Some("log-limits") => run(phase_log_limits()),
        Some("nginx-conf") => run(phase_nginx_conf()),
        Some("http-flood") => run(phase_http_flood()),
        Some("modsec-conf") => run(phase_modsec_conf()),
        Some("waf-default-rules") => run(phase_waf_default_rules()),
        Some("sftp-access") => run(phase_sftp_access()),
        Some("tools-vhost") => run(phase_tools_vhost()),
        Some("phpmyadmin-signon") => run(phase_phpmyadmin_signon()),
        Some("phpmyadmin-sso") => run(phase_phpmyadmin_sso()),
        Some("backend-env") => run(phase_backend_env()),
        Some("migrate-csp") => run(phase_migrate_csp()),
        Some("php-ini") => run(phase_php_ini(args.get(1))),
        Some("php-fpm-pool") => run(phase_php_fpm_pool(args.get(1), args.get(2))),
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
    println!("  snpanel-install update-units     the units an update writes, without the API unit");
    println!("  snpanel-install log-limits       cap the journal and rotate btmp");
    println!("  snpanel-install nginx-conf       the fastcgi cache and the upgrade map");
    println!("  snpanel-install http-flood       the shared flood-protection zones");
    println!("  snpanel-install modsec-conf      the ModSecurity include chain");
    println!("  snpanel-install waf-default-rules  the rules every site gets");
    println!("  snpanel-install sftp-access      the sshd block SFTP logins match");
    println!("  snpanel-install tools-vhost      the default server phpMyAdmin sits on");
    println!("  snpanel-install phpmyadmin-signon  point the sign-on shim at the panel");
    println!("  snpanel-install phpmyadmin-sso   write the sign-on config and shim");
    println!("  snpanel-install backend-env      the panel's .env, then seed the database");
    println!("  snpanel-install migrate-csp      add worker-src to existing vhosts");
    println!("  snpanel-install php-ini <path>   the panel's seven php.ini settings");
    println!("  snpanel-install php-fpm-pool <path> <socket>");
    println!("                                   point a pool at the panel's socket\n");
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
/// **On the ClamAV dependency, which an earlier commit got wrong.** That
/// commit claimed `install.sh` wrote `After=network.target clamav-daemon`
/// without the `.service` suffix and that systemd was therefore dropping the
/// dependency. It was not: `installer/platform.sh` sets
/// `CLAMAV_SERVICE="clamav-daemon.service"` with the suffix already in it, so
/// `After=network.target ${CLAMAV_SERVICE}` expanded correctly on both
/// families. The difference came from the substitution table in the
/// throwaway drift-checking script, not from the shell.
///
/// What is true is the measurement underneath it: a unit written with a bare
/// name *is* silently dropped - `systemctl show -p After` on one does not
/// list the dependency at all - which is why `clamav_unit_name` exists, since
/// `Platform::clamav_service` returns the bare name for its other caller,
/// `systemctl is-active`.
///
/// The test below pins that this phase emits a resolvable name. It is worth
/// keeping on its own terms; it is not evidence of a bug in the shell.
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

/// Source: `update.sh`, the systemd block in `install_panel_runtime`.
///
/// Seven units and one drop-in - what an *update* writes, which is not what
/// an install writes.
///
/// `systemd-units` is the install's phase and does more: it writes
/// `snpanel-api.service` itself, removes the retired auto-update timer, and
/// `enable --now`s `snpanel-api`. On a box that has cut over to
/// `snpanel-rust` that last one starts a second panel on the port the first
/// is already listening on. So an update gets its own phase rather than
/// calling that one, and the seven units come from the same `unit_files` so
/// the two cannot drift apart.
///
/// The enables are not fatal here. Both are `|| true` in the shell, unlike
/// the installer's three, and the difference is the usual one: an update has
/// a box that already works and other work left to do.
fn phase_update_units() -> Result<(), String> {
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

    for (path, body) in update_unit_files(&settings) {
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {dir:?}: {e}"))?;
        }
        std::fs::write(path, &body).map_err(|e| format!("writing {path}: {e}"))?;
    }

    systemctl(&["daemon-reload"]);
    systemctl(&["enable", "snpanel-autotune.service"]);
    systemctl(&["enable", "snpanel-timesync.timer"]);
    Ok(())
}

/// What `update.sh` writes: every unit `unit_files` has except
/// `snpanel-api.service`, plus the drop-in it writes in place of it.
///
/// Derived from `unit_files` rather than listed again. A unit added there is
/// one an update starts writing too, which is what should happen - the one
/// deliberate exception is named here and nowhere else.
fn update_unit_files(settings: &UnitSettings) -> Vec<(&'static str, String)> {
    const REPLACED_BY_THE_DROPIN: &str = "/etc/systemd/system/snpanel-api.service";
    const DROPIN: &str = "/etc/systemd/system/snpanel-api.service.d/20-panel-port.conf";

    let mut files: Vec<(&'static str, String)> = unit_files(settings)
        .into_iter()
        .filter(|(path, _)| *path != REPLACED_BY_THE_DROPIN)
        .collect();
    files.push((DROPIN, systemd_units::panel_port_dropin(settings)));
    files
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

/// Source: `configure_fastcgi_cache` and `configure_proxy_upgrade_map`.
///
/// Two files the shell writes next to each other in `main()`. Both are
/// `conf.d` includes that every vhost depends on, and the upgrade map is the
/// one with teeth: without it a `proxy_set_header Connection
/// $connection_upgrade` in any site config makes nginx refuse to start, so it
/// has to exist before the first proxy vhost is written.
fn phase_nginx_conf() -> Result<(), String> {
    let platform = snpanel_osabi::detect().map_err(|e| format!("unsupported platform: {e}"))?;

    // The cache directory belongs to the web account, which is `www-data` on
    // Debian and `nginx` on the RHEL family.
    install_dir(
        nginx_conf::FASTCGI_CACHE_DIR,
        platform.web_user(),
        platform.web_group(),
        0o755,
    );
    // `find ... -mindepth 1 -delete`: entries left by an older cache
    // configuration are keyed differently and will never be hit again, so
    // they are dead bytes on the disk until something clears them.
    clear_directory(nginx_conf::FASTCGI_CACHE_DIR);

    write_conf(
        nginx_conf::FASTCGI_CACHE_PATH,
        &nginx_conf::fastcgi_cache_conf(),
    )?;
    write_conf(
        nginx_conf::UPGRADE_MAP_PATH,
        &nginx_conf::upgrade_map_conf(),
    )
}

/// Source: `write_http_flood_nginx_conf`.
///
/// The zones file is written **only when it is absent**, and that is the one
/// thing to get right here: `limit_conn_zone` allocates shared memory, and
/// rewriting it under a running nginx is how the counters an operator is
/// relying on during an attack get reset. The include that points at it is
/// rewritten every time, because it is one line and carries no state.
fn phase_http_flood() -> Result<(), String> {
    for dir in ["/etc/nginx/snpanel", "/etc/nginx/conf.d"] {
        install_dir(dir, "root", "root", 0o755);
    }

    if !std::path::Path::new(nginx_conf::HTTP_FLOOD_ZONES_PATH).exists() {
        write_conf(
            nginx_conf::HTTP_FLOOD_ZONES_PATH,
            &nginx_conf::http_flood_zones_conf(),
        )?;
    }
    write_conf(
        nginx_conf::HTTP_FLOOD_INCLUDE_PATH,
        &nginx_conf::http_flood_include_conf(),
    )?;

    // Two files an older release wrote. The server-level one in particular
    // would now be included twice.
    for stale in [
        "/etc/nginx/conf.d/snpanel-http-flood.conf",
        "/etc/nginx/snpanel/http-flood-server.conf",
    ] {
        let _ = std::fs::remove_file(stale);
    }

    for path in [
        nginx_conf::HTTP_FLOOD_INCLUDE_PATH,
        nginx_conf::HTTP_FLOOD_ZONES_PATH,
    ] {
        set_root_owned_0644(path);
    }
    Ok(())
}

/// Source: `write_waf_default_rules`.
///
/// A phase of its own because the shell calls it on two paths: from
/// `write_modsec_main_conf` on a box that has the rule engine, and on its own
/// where ModSecurity is not packaged - there the rules are written and never
/// loaded, so the panel's WAF page can say the engine is unavailable rather
/// than pretend the rules are in force.
///
/// This file has three authors: this, the helper's `waf-update`, and the
/// panel's per-site copy. The first two are byte-identical and both pinned to
/// the same fixture.
fn phase_waf_default_rules() -> Result<(), String> {
    install_dir(MODSEC_DIR, "root", "root", 0o755);
    write_conf(
        nginx_conf::MODSEC_DEFAULT_PATH,
        nginx_conf::WAF_DEFAULT_RULES,
    )
}

/// Source: `write_modsec_main_conf` and `write_modsec_base_conf`.
///
/// Three files and the order they include each other in.
/// `snpanel-custom.conf` is created and never written: whatever an operator
/// puts in it is theirs, and it is included last so it can override the
/// defaults.
fn phase_modsec_conf() -> Result<(), String> {
    phase_waf_default_rules()?;

    install_dir(MODSEC_DIR, "root", "root", 0o755);
    install_dir(MODSEC_SITES_DIR, "root", "root", 0o755);

    // `[[ -f /etc/modsecurity/modsecurity.conf ]] && echo "Include ..."`.
    // The distribution's own configuration carries the engine's defaults, and
    // a box that has it wants them; one that does not must not get an
    // `Include` of a file that is not there, which ModSecurity refuses to
    // start on.
    let distro_conf = std::path::Path::new(nginx_conf::DISTRO_MODSECURITY_CONF).is_file();
    write_conf(
        nginx_conf::MODSEC_BASE_PATH,
        &nginx_conf::modsec_base_conf(distro_conf),
    )?;

    // `touch`, never written.
    if !std::path::Path::new(nginx_conf::MODSEC_CUSTOM_PATH).exists() {
        write_conf(nginx_conf::MODSEC_CUSTOM_PATH, "")?;
    }

    write_conf(
        nginx_conf::MODSEC_MAIN_PATH,
        &nginx_conf::modsec_main_conf(),
    )
}

/// Source: `setup_sftp_access`.
///
/// **Fatal when `sshd -t` refuses the result**, which is the one thing that
/// differs from the same edit made by `snpanel fix-permissions`: an installer
/// that cannot finish configuring a box must not report it as installed,
/// while a repair has other repairs to make and prefers losing the SFTP block
/// to stopping half-way. Both go through `runtime::apply_sftp_block`, so
/// there is one copy of the rollback - and the rollback is the only thing
/// between a bad edit and a remote box with no SSH at its next restart.
fn phase_sftp_access() -> Result<(), String> {
    // The group an SFTP login is matched on. Without it the block matches
    // nothing and the feature is silently off.
    // And the customers' own SFTP accounts', matched by the second block.
    for group in ["snpanel-sftp", "snpanel-sftp-sub"] {
        if !group_exists(group) {
            let _ = std::process::Command::new("groupadd")
                .args(["--system", group])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }

    let existing = std::fs::read_to_string(runtime::SSHD_CONFIG).unwrap_or_default();
    let updated = backend_env::sshd_config_with_sftp(&existing);
    match runtime::apply_sftp_block(&updated)? {
        runtime::SshdOutcome::Reload => Ok(()),
        runtime::SshdOutcome::Rollback => {
            Err("Invalid SSHD configuration for SNPanel SFTP users".to_string())
        }
    }
}

fn group_exists(name: &str) -> bool {
    std::process::Command::new("getent")
        .args(["group", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Source: `write_tools_nginx_config`.
///
/// The default server: the ACME challenge the panel's own certificate is
/// issued through, and phpMyAdmin. Two shapes, chosen by whether the panel
/// has a certificate - and by whether the files are **on disk**, not only
/// named in `.env`, because an `ssl_certificate` pointing at a file that is
/// not there stops nginx from starting at all.
///
/// This file has more writers than any other the installer touches, and the
/// one that bit was the `PHP_VALUE` line: Twig raises its deprecations as
/// `E_USER_DEPRECATED`, which `php.ini`'s `E_ALL & ~E_DEPRECATED` does not
/// exclude, so Debian's pairing of phpMyAdmin 5.2 with Twig 3.21 shows the
/// administrator a wall of notices about a library they cannot change. Four
/// writers existed and two carried the suppression; a run of the one that did
/// not put the notices back.
fn phase_tools_vhost() -> Result<(), String> {
    let platform = snpanel_osabi::detect().map_err(|e| format!("unsupported platform: {e}"))?;

    let php_default = env_opt("PHP_DEFAULT").unwrap_or_else(|| platform.php_default().to_string());
    let pma_root = env_opt("PHPMYADMIN_ROOT")
        .unwrap_or_else(|| platform.phpmyadmin_root().to_string_lossy().into_owned());

    // Both set **and** present. `.env` can name a certificate a restore did
    // not bring back.
    let cert = env_opt("PANEL_SSL_CERT").filter(|p| std::path::Path::new(p).is_file());
    let key = env_opt("PANEL_SSL_KEY").filter(|p| std::path::Path::new(p).is_file());
    let ssl = match (&cert, &key) {
        (Some(c), Some(k)) => Some(tools_vhost::ToolsTls {
            cert_path: c,
            key_path: k,
        }),
        _ => None,
    };

    let body = tools_vhost::tools_vhost(&tools_vhost::ToolsVhost {
        phpmyadmin_root: &pma_root,
        php_default: &php_default,
        ssl,
    });
    write_conf(tools_vhost::TOOLS_CONF_PATH, &body)
}

/// Source: the three `sed -i -E` calls at the end of `update.sh`'s
/// `write_tools_nginx_config`.
///
/// phpMyAdmin comes from the distribution's package, so SNPanel does not own
/// these two files; it drops a single-sign-on shim into them at install time
/// and afterwards has to keep three values following the panel. The
/// substitutions are `snpanel_core::phpmyadmin`, checked against GNU `sed`'s
/// own output row by row.
///
/// This is an update-only phase. `install.sh` writes both files from scratch
/// with placeholders it then fills, so it has nothing to patch; `update.sh`
/// finds whatever the last install left.
///
/// Every one of the three ends `|| true` in the bash, and so does every one
/// here: phpMyAdmin is optional, and a box that refused to finish updating
/// because a database tool is not installed would be the wrong trade. A file
/// that is not there is not an error, and neither is one this does not
/// recognise.
///
/// The scheme follows a certificate that is **named in `.env` and present on
/// disk**, which is the same test `tools-vhost` makes - the vhost and the
/// cookie have to agree about whether this box is HTTPS, or phpMyAdmin sets a
/// `secure` cookie that the browser then will not send back.
fn phase_phpmyadmin_signon() -> Result<(), String> {
    let platform = snpanel_osabi::detect().map_err(|e| format!("unsupported platform: {e}"))?;

    let root = env_opt("PHPMYADMIN_ROOT")
        .unwrap_or_else(|| platform.phpmyadmin_root().to_string_lossy().into_owned());
    // The bash hard-codes Debian's `/etc/phpmyadmin` here. `install.sh` has
    // always had the platform's in `PHPMYADMIN_CONF_DIR`, so it is taken from
    // the environment and falls back to what the bash had.
    let conf_dir = env_opt("PHPMYADMIN_CONF_DIR").unwrap_or_else(|| "/etc/phpmyadmin".to_string());

    let shim = std::path::Path::new(&root).join("snpanel-signon.php");
    let conf = std::path::Path::new(&conf_dir)
        .join("conf.d")
        .join("snpanel-signon.php");

    let port = env_opt("PANEL_PORT").unwrap_or_else(|| "2222".to_string());
    let cert = env_opt("PANEL_SSL_CERT").filter(|p| std::path::Path::new(p).is_file());
    let key = env_opt("PANEL_SSL_KEY").filter(|p| std::path::Path::new(p).is_file());
    let secure = cert.is_some() && key.is_some();
    let scheme = if secure { "https" } else { "http" };
    // `host="${panel_domain:-$server_ip}"`, and the substitution is skipped
    // when both are empty rather than writing `https:///phpmyadmin/`.
    let host = env_opt("PANEL_DOMAIN").or_else(|| env_opt("SERVER_IP"));

    edit_in_place(&shim, |text| {
        signon_edits::rewrite_sso_url(text, scheme, &port)
    });
    for path in [&conf, &shim] {
        edit_in_place(path, |text| signon_edits::rewrite_secure_flag(text, secure));
    }
    if let Some(host) = host.as_deref() {
        edit_in_place(&conf, |text| {
            signon_edits::rewrite_absolute_uri(text, scheme, host)
        });
    }
    // A box installed before the directory was made here has it `0755` on EL,
    // and phpMyAdmin's sign-on fails there until this runs. Only where the
    // shim is: no phpMyAdmin, nothing to keep a session for.
    if shim.is_file() {
        session_dir()?;
    }
    Ok(())
}

/// Read, rewrite, write back only if it changed - and stay quiet about all
/// three going wrong, which is what `sed -i ... || true` does.
///
/// Not writing an unchanged file matters more than it looks: `update.sh` runs
/// this on every update, and a write that changes nothing still moves the
/// mtime, which is the signal an administrator uses to see what an update
/// touched.
fn edit_in_place(path: &std::path::Path, rewrite: impl Fn(&str) -> String) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let rewritten = rewrite(&text);
    if rewritten != text {
        let _ = std::fs::write(path, rewritten);
    }
}

/// Source: `setup_phpmyadmin_sso` in `install.sh`.
///
/// The two files that let the panel put a customer into phpMyAdmin without
/// handing them a database password to type. Both bodies are
/// `snpanel_installer::phpmyadmin`, which has had fixtures recorded from this
/// shell function for some time and no caller at all.
///
/// The shell wrote the shim with `__SNPANEL_API_BASE__` and
/// `__SNPANEL_PMA_COOKIE_SECURE__` placeholders and then `sed`ed them. Here
/// the values are arguments, so there is nothing to substitute afterwards and
/// no window in which the file on disk names a placeholder.
///
/// **The blowfish secret is generated here and never becomes a shell
/// variable.** `openssl rand -hex 32` in the bash put it in the function's
/// environment and then in a heredoc; this reads `/dev/urandom` and writes
/// it straight into the file. It is what encrypts phpMyAdmin's session
/// cookie, so it belongs in exactly one place: a file that is `0640`
/// root and the web group.
///
/// The other file is `0644` because nginx serves it, and it holds no secret -
/// the token it posts is minted per request by the panel.
///
/// Rewriting it every run is deliberate and matches the shell: a new blowfish
/// secret invalidates the sessions phpMyAdmin had open, which on an install
/// is none and on a re-run is the right answer anyway.
fn phase_phpmyadmin_sso() -> Result<(), String> {
    let platform = snpanel_osabi::detect().map_err(|e| format!("unsupported platform: {e}"))?;

    let root = env_opt("PHPMYADMIN_ROOT")
        .unwrap_or_else(|| platform.phpmyadmin_root().to_string_lossy().into_owned());
    let conf_dir = env_opt("PHPMYADMIN_CONF_DIR").unwrap_or_else(|| "/etc/phpmyadmin".to_string());
    let paths = phpmyadmin::PhpMyAdminPaths {
        conf_dir: &conf_dir,
        root: &root,
    };

    // `pma_host="${PANEL_DOMAIN:-$SERVER_IP}"`, and the shell falls back to
    // `detect_server_ip` when both are empty. That detection stays in the
    // shell, which already has it; what arrives here is the answer.
    let host = env_opt("PANEL_DOMAIN")
        .or_else(|| env_opt("SERVER_IP"))
        .unwrap_or_default();
    let secure = env_opt("ENABLE_SSL").as_deref() == Some("yes");
    let panel_port: u16 = env_opt("PANEL_PORT")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2222);
    let web_group = env_opt("WEB_GROUP").unwrap_or_else(|| platform.web_group().to_string());

    let config = paths.config_file();
    write_conf(
        &config,
        &phpmyadmin::config_php(&random_hex(32)?, &host, secure),
    )?;
    set_owner_and_mode(&config, "root", &web_group, phpmyadmin::CONFIG_MODE)?;

    let signon = paths.signon_file();
    let api_base = phpmyadmin::api_base(secure, panel_port);
    write_conf(&signon, &phpmyadmin::signon_php(&api_base, secure))?;
    set_mode(&signon, phpmyadmin::SIGNON_MODE)?;
    session_dir()
}

/// `install -d -o root -g root -m 1733 /var/lib/php/sessions`: the directory
/// both sign-on files keep the session in, as Debian's `php-common` makes it.
/// On the Debian family it is already exactly that and nothing changes; on
/// EL no package makes it, and this is what does.
fn session_dir() -> Result<(), String> {
    let dir = phpmyadmin::SESSION_DIR;
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
    set_owner_and_mode(dir, "root", "root", phpmyadmin::SESSION_DIR_MODE)
}

/// `chown <owner>:<group> <path>` then `chmod <mode> <path>`.
///
/// Fatal, both of them. A config file that kept the default mode would leave
/// the blowfish secret world-readable, and one the web group cannot read is
/// a phpMyAdmin that cannot start - neither is a state to continue an install
/// in.
fn set_owner_and_mode(path: &str, owner: &str, group: &str, mode: u32) -> Result<(), String> {
    let status = std::process::Command::new("chown")
        .arg(format!("{owner}:{group}"))
        .arg(path)
        .status()
        .map_err(|e| format!("chown {path}: {e}"))?;
    if !status.success() {
        return Err(format!("chown {owner}:{group} {path} failed"));
    }
    set_mode(path, mode)
}

/// Source: `setup_backend`.
///
/// Writes the panel's `.env`, hands the tree to the `snpanel` account, and
/// seeds the database.
///
/// **C18: every name in that file stays exactly as it is.** It is written
/// here, rewritten by every update, and read by the panel on every start; a
/// rename strands existing boxes. The list is
/// `snpanel_installer::backend_env`, with a fixture.
///
/// **C37 for the admin password.** It arrives in this process's environment
/// and leaves in the child's, never in either argv. `/proc/<pid>/cmdline` is
/// mode 444 and on a hosting box every customer's PHP can read it; measured
/// once in a container, an unprivileged account read the password out of
/// `/proc` while the seed ran. `/proc/<pid>/environ` is 400.
///
/// The password stays the shell's to generate, because the shell needs the
/// value afterwards for `/root/login.txt` and the summary it prints. The
/// `SECRET_KEY` does not, so it is generated here and never becomes a shell
/// variable at all.
fn phase_backend_env() -> Result<(), String> {
    let app_dir = app_dir();
    let env_path = format!("{app_dir}/backend/.env");

    let platform = snpanel_osabi::detect().map_err(|e| format!("unsupported platform: {e}"))?;
    let php_default = env_opt("PHP_DEFAULT").unwrap_or_else(|| platform.php_default().to_string());

    let secret_key = random_hex(32)?;
    let body = backend_env::backend_env(&backend_env::BackendEnv {
        app_dir: &app_dir,
        secret_key: &secret_key,
        panel_url: &env_opt("PANEL_URL").unwrap_or_default(),
        panel_domain: &env_opt("PANEL_DOMAIN").unwrap_or_default(),
        panel_port: env_opt("PANEL_PORT")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2222),
        backup_root: &env_opt("BACKUP_ROOT").unwrap_or_else(|| "/var/backups/snpanel".to_string()),
        ssl_email: &env_opt("SSL_EMAIL").unwrap_or_default(),
        default_php_version: &php_default,
    });

    write_conf(&env_path, &body)?;
    // 0640 before anything reads it: the file holds `SECRET_KEY`, which is
    // what makes a session token valid.
    set_mode(&env_path, backend_env::ENV_MODE)?;

    // The panel runs as `snpanel` and writes its own database here.
    for dir in [format!("{app_dir}/backend"), format!("{app_dir}/frontend")] {
        if std::path::Path::new(&dir).exists() {
            let _ = std::process::Command::new("chown")
                .args(["-R", "snpanel:snpanel", &dir])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }

    // `--init-db` builds the schema from a dump captured out of Alembic and
    // stamps it at the same revision, so the database is one Alembic would
    // recognise if it were ever pointed at it again.
    //
    // `runuser -u` does not reset the environment, unlike sudo - which is
    // what carries the password across the user switch without it ever being
    // written down. `--whitelist-environment` is stated for intent and
    // becomes the mechanism the day somebody adds `--login`.
    // Inherited rather than set: the value is already in this process's
    // environment, put there by the shell, and copying it into a variable
    // here would be one more place it lives.
    let status = init_db_command(&app_dir, &env_path)
        .status()
        .map_err(|e| format!("running snpanel-api-rust --init-db: {e}"))?;
    if !status.success() {
        return Err(format!("--init-db exited {:?}", status.code()));
    }
    Ok(())
}

/// The seed command, built but not run, so a test can read its argv.
///
/// Separated for the same reason the panel's password paths separate theirs:
/// the obvious way to hand a secret to a child is one more `.arg()`, and
/// nothing else in the program would notice.
/// `the_seed_never_carries_the_password_in_argv` reads it back.
fn init_db_command(app_dir: &str, env_path: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("runuser");
    cmd.arg("--whitelist-environment=SNPANEL_ADMIN_PASSWORD")
        .args(["-u", "snpanel", "--", "env"])
        .arg(format!("HOME={app_dir}"))
        .arg("SNPANEL_USE_HELPER=true")
        .arg("/usr/local/bin/snpanel-api-rust")
        .arg("--env")
        .arg(env_path)
        .arg("--init-db")
        .current_dir(format!("{app_dir}/backend"));
    cmd
}

/// `openssl rand -hex <n>`.
///
/// Read from `/dev/urandom` rather than through a crate, which keeps this
/// binary's dependencies at the three the library already has. **Fatal if it
/// cannot be read in full**: a short read here would be a `SECRET_KEY` with
/// less entropy than it looks like, and every session token on the box is
/// signed with it.
fn random_hex(bytes: usize) -> Result<String, String> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("reading /dev/urandom: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn set_mode(path: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
    let mut perms = meta.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|e| format!("chmod {path}: {e}"))
}

/// `APP_DIR`, `/opt/snpanel` unless the operator set it.
fn app_dir() -> String {
    env_opt("APP_DIR").unwrap_or_else(|| "/opt/snpanel".to_string())
}

/// Source: the seven `sed -e` expressions at the end of `install_php`'s loop.
///
/// A path rather than a version, because the shell already knows where the
/// file is - `php_ini_path` differs between the Debian family and Remi's SCL
/// layout, and that lookup is one the platform table would have to grow to
/// answer.
///
/// The pattern is `^\s*;\?\s*<key>\s*=.*`, and the two load-bearing parts of
/// it are in `php::php_ini`: a **commented** default is rewritten into a live
/// setting, so a distribution shipping `;upload_max_filesize = 2M` ends up
/// with the panel's value rather than PHP's compiled-in one; and whitespace
/// is allowed before the semicolon as well as after.
///
/// A missing file is not an error: the shell guards with `[[ -f ]]` and
/// carries on, because a PHP version whose package did not land is already
/// being reported elsewhere.
fn phase_php_ini(path: Option<&String>) -> Result<(), String> {
    let Some(path) = path else {
        return Err("usage: snpanel-install php-ini <path>".to_string());
    };
    if !std::path::Path::new(path).is_file() {
        return Ok(());
    }
    let existing = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let updated = php::php_ini(&existing);
    std::fs::write(path, updated).map_err(|e| format!("writing {path}: {e}"))
}

/// Source: `configure_php_fpm_pool`.
///
/// Points the distribution's own `www` pool at the web account and the
/// panel's socket. Every one of the seven settings is rewritten whether or
/// not it is commented out: `;listen.owner` in a stock file has to become a
/// live `listen.owner`, not stay a comment.
///
/// `/run` is a tmpfs, so `/run/php` has to be recreated on every boot - which
/// is what the tmpfiles rule is for, and why it is written here rather than
/// left to the package.
fn phase_php_fpm_pool(path: Option<&String>, socket: Option<&String>) -> Result<(), String> {
    let (Some(path), Some(socket)) = (path, socket) else {
        return Err("usage: snpanel-install php-fpm-pool <pool-path> <socket>".to_string());
    };
    if !std::path::Path::new(path).is_file() {
        return Ok(());
    }

    let platform = snpanel_osabi::detect().map_err(|e| format!("unsupported platform: {e}"))?;

    write_best_effort(backend_env::TMPFILES_PATH, &backend_env::php_run_tmpfiles());
    let _ = std::process::Command::new("systemd-tmpfiles")
        .args(["--create", backend_env::TMPFILES_PATH])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    install_dir("/run/php", "root", "root", 0o755);

    let existing = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let updated =
        backend_env::php_fpm_pool(&existing, platform.web_user(), platform.web_group(), socket);
    std::fs::write(path, updated).map_err(|e| format!("writing {path}: {e}"))
}

/// Source: `migrate_nginx_wordpress_csp_worker_src`, which was embedded
/// `python3` in `update.sh`.
///
/// WordPress's block editor loads workers from `blob:` URLs. A policy written
/// before that was known blocks them, and the symptom is an editor that will
/// not open with the reason only in the browser console - so this edits
/// vhosts an operator did not ask it to touch. The alternative is telling
/// every customer to go and fix their own, which is why the decision of what
/// to write is pinned in `migrations::csp` rather than made here.
///
/// A file that cannot be read as UTF-8 is read as Latin-1, as the Python did:
/// a vhost with a stray byte in a comment is still a vhost, and skipping it
/// would leave one site's editor broken for a reason nobody would connect to
/// this.
fn phase_migrate_csp() -> Result<(), String> {
    for root in ["/etc/nginx/conf.d", "/etc/nginx/sites-enabled"] {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let mut paths: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("conf"))
            .collect();
        // `sorted(root.glob("*.conf"))` - the order the messages come out in.
        paths.sort();

        for path in paths {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let text = match String::from_utf8(bytes.clone()) {
                Ok(text) => text,
                // `except UnicodeDecodeError: read_text(encoding="latin-1")`.
                // Every byte is a code point in Latin-1, so this cannot fail.
                Err(_) => bytes.iter().map(|b| *b as char).collect(),
            };
            let updated = migrations::csp::migrate(&text);
            if updated == text {
                continue;
            }
            if std::fs::write(&path, &updated).is_ok() {
                println!("Updated CSP worker-src in {}", path.display());
            }
        }
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

/// Write an nginx include, creating its directory first.
///
/// Fatal, unlike the log drop-ins: nginx will not start without a file a
/// vhost includes, so a box that gets here without one has no web server.
fn write_conf(path: &str, body: &str) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(path, body).map_err(|e| format!("writing {path}: {e}"))
}

/// `find <dir> -mindepth 1 -delete` - the contents, not the directory.
fn clear_directory(dir: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let _ = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
}

/// `chown root:root` and `chmod 0644`.
///
/// nginx reads these as root and never writes them; group-writable would let
/// anything in the `snpanel` group rewrite what every vhost includes.
fn set_root_owned_0644(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::process::Command::new("chown")
        .args(["root:root", path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o644);
        let _ = std::fs::set_permissions(path, perms);
    }
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

    /// Neither installer script runs anything from the virtualenv.
    ///
    /// The Python backend is gone and `update.sh` deletes the `.venv` a
    /// previous release left. What survived that removal was the block after
    /// it: a `python -m py_compile` over thirty `app/*.py` files, and the
    /// `deactivate` that used to close the `source .venv/bin/activate` above
    /// it. Both were still there with nothing left to activate.
    ///
    /// On Debian this is not a no-op. There is no `python` at all - only
    /// `python3` - so under `set -euo pipefail` the update stopped at that
    /// line, part-done, with "python: command not found".
    ///
    /// `python3` is deliberately still allowed: `certbot` is written in it,
    /// and the update's own status file is still four `python3` heredocs.
    #[test]
    fn neither_installer_script_still_runs_the_virtualenv() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut scanned = 0;
        for name in ["installer/update.sh", "installer/install.sh"] {
            let path = root.join(name);
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            for (n, line) in text.lines().enumerate() {
                let code = line.trim();
                if code.starts_with('#') {
                    continue;
                }
                scanned += 1;
                let first = code.split_whitespace().next().unwrap_or("");
                assert!(
                    first != "python" && first != "pip" && first != "deactivate",
                    "{name}:{}: `{first}` is the virtualenv's, and there is no virtualenv: {code}",
                    n + 1
                );
                assert!(
                    !code.contains("bin/activate"),
                    "{name}:{}: activating a virtualenv that no release creates: {code}",
                    n + 1
                );
            }
        }
        assert!(
            scanned > 2000,
            "only {scanned} lines scanned across both scripts"
        );
    }

    /// Every variable a phase call interpolates is one the script sets.
    ///
    /// Both installer scripts run under `set -euo pipefail`, so a name the
    /// script never assigns does not arrive empty - it aborts the run at that
    /// line, having done nothing. And a phase call is the worst place for it:
    /// the settings are on the command line, so the mistake is silent until
    /// the update reaches it.
    ///
    /// Twice while moving these phases across, a call was written by copying
    /// `install.sh`'s, where the name is a shell variable, into `update.sh`,
    /// where the same name is only ever an `.env` key:
    ///
    /// * `PANEL_SSL_CERT="${PANEL_SSL_CERT:-}"` - which has a default, so it
    ///   ran, and quietly wrote a tools vhost with no `listen 443 ssl`;
    /// * `PANEL_PORT="$PANEL_PORT"` - which does not, so it would have
    ///   aborted every update at the line that writes the panel's units.
    ///
    /// The first was caught by reading a diff and the second by running the
    /// block on a container. This is so the third is caught here.
    #[test]
    fn every_variable_a_phase_call_passes_is_one_the_script_sets() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0;
        for name in ["installer/update.sh", "installer/install.sh"] {
            let path = root.join(name);
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            // Both scripts source these two, so a name set there is set by
            // the time a phase call runs. `RUST_BIN_DIR` is
            // `fetch_rust_binaries`'s, and `WEB_GROUP` is the platform
            // table's.
            let mut assigned = assigned_names(&text);
            for sourced in ["installer/platform.sh", "installer/lib/rust-binaries.sh"] {
                let p = root.join(sourced);
                let t = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p:?}: {e}"));
                assigned.extend(assigned_names(&t));
            }
            assert!(
                assigned.contains("APP_DIR"),
                "{name}: the assignment scanner found no APP_DIR, so it is not reading this script"
            );

            let mut calls = 0;
            for block in phase_call_blocks(&text) {
                calls += 1;
                for var in interpolated_without_default(&block) {
                    // A block that guards the name anywhere - `${NAME:-}` in
                    // the `if` that decides whether to use it at all - has
                    // already said what happens when it is unset.
                    if block.contains(&format!("${{{var}:-")) {
                        continue;
                    }
                    assert!(
                        assigned.contains(var.as_str()),
                        "{name}: a phase call passes ${var}, which this script never sets - \
                         under `set -u` that aborts the run at this line:\n{block}"
                    );
                }
            }
            assert!(
                calls > 0,
                "{name}: no phase calls found, so this checks nothing"
            );
            checked += calls;
        }
        assert!(
            checked >= 10,
            "only {checked} phase calls across both scripts"
        );
    }

    /// Every name the script assigns **for the rest of the run**: `NAME=`
    /// as a statement of its own, and `local a b c`.
    ///
    /// Not `NAME=value some-command`, which sets it for that command only.
    /// That distinction is the whole point: the phase calls themselves are
    /// written that way, so counting them would have this test conclude that
    /// `PANEL_PORT` is set because a different phase call passes it - which
    /// is exactly the mistake it is here to catch, and did miss once.
    fn assigned_names(text: &str) -> std::collections::HashSet<String> {
        let mut out = std::collections::HashSet::new();
        for line in text.lines() {
            let continued = line.trim_end().ends_with('\\');
            let segments: Vec<&str> = line.split(';').collect();
            let last = segments.len() - 1;
            for (n, segment) in segments.iter().enumerate() {
                let trimmed = segment.trim();
                if let Some(rest) = trimmed.strip_prefix("local ") {
                    for word in rest.split_whitespace() {
                        let name = word.split('=').next().unwrap_or(word);
                        if is_name(name) {
                            out.insert(name.to_string());
                        }
                    }
                    continue;
                }
                let (names, remainder) = leading_assignments(trimmed);
                // A command follows, or the line runs on into one.
                if !remainder.is_empty() || (n == last && continued) {
                    continue;
                }
                out.extend(names);
            }
        }
        out
    }

    /// The `NAME=...` tokens a segment starts with, and whatever follows
    /// them.
    fn leading_assignments(segment: &str) -> (Vec<String>, &str) {
        let mut names = Vec::new();
        let mut rest = segment;
        loop {
            let name_len = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let name = &rest[..name_len];
            if name.is_empty() || !is_name(name) || !rest[name_len..].starts_with('=') {
                return (names, rest.trim());
            }
            names.push(name.to_string());
            // Step over the value, respecting one level of quoting.
            let mut i = name_len + 1;
            let bytes = rest.as_bytes();
            let mut quote = None;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' | b'\'' if quote.is_none() => quote = Some(bytes[i]),
                    c if Some(c) == quote => quote = None,
                    b' ' | b'\t' if quote.is_none() => break,
                    _ => {}
                }
                i += 1;
            }
            rest = rest[i..].trim_start();
        }
    }

    /// `<needle>` then whitespace then a lower-case letter: the shape of a
    /// phase name, and not of `]]` or `;`.
    fn followed_by_a_verb(line: &str, needle: &str) -> bool {
        let Some(i) = line.find(needle) else {
            return false;
        };
        line[i + needle.len()..]
            .trim_start()
            .starts_with(|c: char| c.is_ascii_lowercase())
    }

    fn is_name(s: &str) -> bool {
        !s.is_empty()
            && !s.starts_with(|c: char| c.is_ascii_digit())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Each phase invocation, joined across its `\` continuations.
    fn phase_call_blocks(text: &str) -> Vec<String> {
        let lines: Vec<&str> = text.lines().collect();
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            // The invocation, not the mention. Both scripts also *test*
            // this path - `[[ -x "${RUST_BIN_DIR}/snpanel-install" ]]` - so
            // what follows the closing quote has to be a verb.
            if !followed_by_a_verb(line, "phase_runner)\"")
                && !followed_by_a_verb(line, "/snpanel-install\"")
            {
                continue;
            }
            // Walk back over the continuation lines that carry the settings.
            let mut start = i;
            while start > 0 && lines[start - 1].trim_end().ends_with('\\') {
                start -= 1;
            }
            out.push(lines[start..=i].join("\n"));
        }
        out
    }

    /// `$NAME` and `${NAME}`, but not `${NAME:-...}` or `${NAME-...}`, which
    /// carry their own default and cannot be unbound.
    fn interpolated_without_default(block: &str) -> Vec<String> {
        let mut out = Vec::new();
        let bytes = block.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if bytes[i] != b'$' {
                i += 1;
                continue;
            }
            // `$(` is a command substitution, not a variable.
            if bytes[i + 1] == b'(' {
                i += 2;
                continue;
            }
            let braced = bytes[i + 1] == b'{';
            let mut j = i + 1 + usize::from(braced);
            let start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > start {
                let name = &block[start..j];
                let has_default = braced && j < bytes.len() && bytes[j] != b'}';
                if !has_default {
                    out.push(name.to_string());
                }
            }
            i = j.max(i + 1);
        }
        out
    }

    /// The drop-in, against a copy recorded from `update.sh` writing it on a
    /// Debian 13 box - not against a retyping of the heredoc.
    #[test]
    fn the_update_dropin_is_what_the_shell_wrote() {
        let settings = UnitSettings {
            app_dir: "/opt/snpanel".to_string(),
            backup_root: "/var/backups/snpanel".to_string(),
            web_group: "www-data".to_string(),
            clamav_service: "clamav-daemon.service".to_string(),
            panel_port: 2222,
        };
        let path = golden_dir().join("20-panel-port.conf.expected");
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        assert_eq!(systemd_units::panel_port_dropin(&settings), expected);
    }

    /// An update writes every unit an install does except the API unit, for
    /// which it writes a drop-in instead.
    ///
    /// Asserted against `unit_files` rather than against a second list, so a
    /// unit added to the install is one the update starts writing too. The
    /// alternative - two lists - is how `update.sh` came to be writing its
    /// own copy of seven unit files in the first place.
    #[test]
    fn an_update_writes_every_unit_but_the_api_one() {
        let settings = UnitSettings::for_platform(&snpanel_osabi::debian::Debian13);
        let install: Vec<&str> = unit_files(&settings).into_iter().map(|(p, _)| p).collect();
        let update: Vec<&str> = update_unit_files(&settings)
            .into_iter()
            .map(|(p, _)| p)
            .collect();

        assert!(
            install.contains(&"/etc/systemd/system/snpanel-api.service"),
            "the install stopped writing the API unit, so the exception below is stale"
        );
        assert!(
            !update.contains(&"/etc/systemd/system/snpanel-api.service"),
            "an update must not replace the API unit - `systemd-units` is the phase that does"
        );
        assert!(update.contains(&"/etc/systemd/system/snpanel-api.service.d/20-panel-port.conf"));

        for path in &install {
            if *path == "/etc/systemd/system/snpanel-api.service" {
                continue;
            }
            assert!(
                update.contains(path),
                "{path} is written by an install and not by an update"
            );
        }
        assert_eq!(
            update.len(),
            install.len(),
            "seven units and one drop-in: {update:?}"
        );
    }

    /// The seven shared units are the *same bytes* on both paths, not merely
    /// the same file names.
    #[test]
    fn the_shared_units_are_byte_for_byte_the_installers() {
        let settings = UnitSettings::for_platform(&snpanel_osabi::debian::Debian13);
        let install = unit_files(&settings);
        let update = update_unit_files(&settings);
        let mut shared = 0;
        for (path, body) in &install {
            if *path == "/etc/systemd/system/snpanel-api.service" {
                continue;
            }
            let theirs = update
                .iter()
                .find(|(p, _)| p == path)
                .unwrap_or_else(|| panic!("{path} missing from the update's list"));
            assert_eq!(&theirs.1, body, "{path} differs between install and update");
            shared += 1;
        }
        assert_eq!(shared, 7);
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
    /// systemd does not append `.service` in a dependency directive and does
    /// not complain about a name it cannot resolve: measured on the demo
    /// container, `systemctl show -p After` on a unit written with a bare
    /// name does not list the dependency at all.
    ///
    /// That makes this worth pinning, because `Platform::clamav_service`
    /// returns the **bare** name - its other caller hands it to `systemctl
    /// is-active`, which takes either spelling. `clamav_unit_name` is what
    /// bridges the two, and this is what notices if it stops being called.
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

    /// C37: the admin password is never a word on a command line.
    ///
    /// `/proc/<pid>/cmdline` is mode 444 and on a hosting box every
    /// customer's PHP can read it. Measured once in a container: an
    /// unprivileged account read the password out of `/proc` while the seed
    /// ran, and could not after the shell stopped spelling it out in argv.
    /// This keeps it that way on the Rust side.
    #[test]
    fn the_seed_never_carries_the_password_in_argv() {
        const SECRET: &str = "correct-horse-battery-staple";
        // What the shell puts here before calling this binary.
        std::env::set_var("SNPANEL_ADMIN_PASSWORD", SECRET);

        let cmd = init_db_command("/opt/snpanel", "/opt/snpanel/backend/.env");
        for arg in cmd.get_args() {
            let arg = arg.to_string_lossy();
            assert!(!arg.contains(SECRET), "the password is in argv as {arg:?}");
        }
        // And nothing in here puts it back into the child's environment by
        // hand either - it arrives by inheritance, which is what
        // `--whitelist-environment` is naming.
        assert!(
            cmd.get_envs().next().is_none(),
            "the command sets an environment variable explicitly"
        );
        let named = cmd
            .get_args()
            .any(|a| a.to_string_lossy().contains("SNPANEL_ADMIN_PASSWORD"));
        assert!(named, "the whitelist no longer names the variable");

        std::env::remove_var("SNPANEL_ADMIN_PASSWORD");
    }

    /// `openssl rand -hex 32`, and it has to be 32 *bytes*.
    #[test]
    fn the_secret_key_is_sixty_four_hex_characters() {
        let key = random_hex(32).expect("/dev/urandom");
        assert_eq!(key.len(), 64, "{key}");
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
        // Two reads must differ. A `SECRET_KEY` that is the same on every box
        // is a session token minted on one that is valid on all of them.
        assert_ne!(key, random_hex(32).expect("/dev/urandom"));
    }

    /// The web account the pool phase uses is the one the shell would have
    /// used.
    ///
    /// `configure_php_fpm_pool` passed `$WEB_USER` and `$WEB_GROUP`, set by
    /// `installer/platform.sh`. The phase takes them from
    /// `snpanel_osabi::Platform` instead, which is only safe while the two
    /// agree - and if they stopped agreeing, PHP would listen on a socket
    /// owned by one account while nginx connected as another, which reads as
    /// a 502 and not as a configuration mistake.
    #[test]
    fn the_web_account_matches_the_shell() {
        let shell = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../installer/platform.sh"),
        )
        .expect("platform.sh");

        // Every `WEB_USER=`/`WEB_GROUP=` the shell sets, in order.
        let mut pairs = Vec::new();
        let mut user: Option<String> = None;
        for line in shell.lines().map(str::trim) {
            if let Some(v) = line.strip_prefix("WEB_USER=") {
                user = Some(v.trim_matches('"').to_string());
            }
            if let Some(v) = line.strip_prefix("WEB_GROUP=") {
                if let Some(u) = user.take() {
                    pairs.push((u, v.trim_matches('"').to_string()));
                }
            }
        }
        assert!(
            pairs.len() >= 2,
            "platform.sh sets {} web accounts; the scan is broken, not the code",
            pairs.len()
        );

        let from_platform: Vec<(String, String)> = [
            &snpanel_osabi::debian::Debian13 as &dyn snpanel_osabi::Platform,
            &snpanel_osabi::rhel::AlmaLinux10,
        ]
        .iter()
        .map(|p| (p.web_user().to_string(), p.web_group().to_string()))
        .collect();

        for pair in &from_platform {
            assert!(
                pairs.contains(pair),
                "{pair:?} is not one of the accounts platform.sh sets: {pairs:?}"
            );
        }
    }

    /// A phase `install.sh` can call but `--help` does not mention is a phase
    /// nobody finds, and one in the help that no arm answers is a line that
    /// tells an operator to run something that exits 1. Both have happened in
    /// this project already - `snpanel firewall reopen` asked for a verb no
    /// mapping ever had, and nothing said so until it was run.
    ///
    /// This reads its own source, because the dispatch is a `match` on string
    /// literals and the help is a list of `println!`s; nothing else connects
    /// them.
    #[test]
    fn every_phase_is_in_the_help_and_every_help_line_is_a_phase() {
        let source = include_str!("snpanel-install.rs");

        let mut dispatched: Vec<&str> = Vec::new();
        for line in source.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("Some(\"") else {
                continue;
            };
            let Some((name, tail)) = rest.split_once('"') else {
                continue;
            };
            // `Some("--help") | Some("-h") | None` is the one arm that is not
            // a phase.
            let tail = tail.trim_start().trim_start_matches(')').trim_start();
            if tail.starts_with("=>") && !name.starts_with('-') {
                dispatched.push(name);
            }
        }

        let mut documented: Vec<&str> = Vec::new();
        for line in source.lines() {
            let Some(rest) = line.trim().strip_prefix("println!(\"  snpanel-install ") else {
                continue;
            };
            if let Some(name) = rest.split_whitespace().next() {
                documented.push(name);
            }
        }

        assert!(
            !dispatched.is_empty() && !documented.is_empty(),
            "the scanner found nothing, so it is not reading this file any more"
        );
        for name in &dispatched {
            assert!(
                documented.contains(name),
                "`snpanel-install {name}` runs but `--help` never mentions it"
            );
        }
        for name in &documented {
            assert!(
                dispatched.contains(name),
                "`--help` offers `snpanel-install {name}`, which no arm answers"
            );
        }
        assert_eq!(
            dispatched.len(),
            documented.len(),
            "a phase is listed twice: {dispatched:?} against {documented:?}"
        );
    }

    /// Every writer of the malware scheduler names the *platform's* ClamAV
    /// unit, with a suffix systemd can resolve.
    ///
    /// Three writers, and each got there differently, which is why this reads
    /// all three rather than trusting one:
    ///
    /// * `installer/platform.sh` sets `CLAMAV_SERVICE` **with** the suffix,
    ///   and `install.sh` interpolates it as-is;
    /// * `snpanel_osabi::Platform::clamav_service` returns it **without**,
    ///   because its other caller hands it to `systemctl is-active`, so
    ///   `clamav_unit_name` adds one;
    /// * `update.sh` hard-coded Debian's name until this commit, which on the
    ///   RHEL family wrote a dependency on a unit that is not there.
    ///
    /// A bare name is not an error systemd reports. It is dropped, and
    /// `systemctl show -p After` on such a unit lists nothing - so the weekly
    /// scan would start without waiting for the daemon it scans with, and the
    /// only sign would be a scan that found nothing.
    #[test]
    fn every_writer_names_the_platforms_clamav_unit() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

        // The shell's table, both families, suffix included.
        let platform_sh =
            std::fs::read_to_string(root.join("installer/platform.sh")).expect("platform.sh");
        let shell_names: Vec<String> = platform_sh
            .lines()
            .filter_map(|l| l.trim().strip_prefix("CLAMAV_SERVICE="))
            .map(|v| v.trim_matches('"').to_string())
            .collect();
        assert_eq!(shell_names.len(), 2, "{shell_names:?}");
        for name in &shell_names {
            assert!(name.ends_with(".service"), "platform.sh: {name}");
        }

        // The Rust table, which spells it the other way and bridges with
        // `clamav_unit_name` - so what a unit ends up with must match.
        for platform in [
            &snpanel_osabi::debian::Debian13 as &dyn snpanel_osabi::Platform,
            &snpanel_osabi::rhel::AlmaLinux10,
        ] {
            let settings = UnitSettings::for_platform(platform);
            assert!(
                settings.clamav_service.ends_with(".service"),
                "{}",
                settings.clamav_service
            );
            assert!(
                shell_names.contains(&settings.clamav_service),
                "{} is not one of the names platform.sh sets: {shell_names:?}",
                settings.clamav_service
            );
        }

        // `update.sh` was the third writer and is not one any more: it
        // calls `update-units`, so the unit above is the copy it gets.
        //
        // This test announced that itself. It failed the moment the block
        // moved, saying "update.sh no longer orders the scanner after
        // ClamAV" - which is the right way round: a writer leaving should
        // fail a test that names it rather than quietly check one fewer
        // file.
        //
        // What is asserted now is that it stayed gone. Counted, not scanned
        // for a bad name: a loop over the `After=` lines of a script that
        // has none passes without checking anything, which is the shape of
        // test this project has had to take back out three times.
        let update_sh =
            std::fs::read_to_string(root.join("installer/update.sh")).expect("update.sh");
        let ordering: Vec<&str> = update_sh
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("After=") || l.starts_with("Requires="))
            .collect();
        assert!(
            ordering.is_empty(),
            "update.sh writes systemd unit ordering again: {ordering:?} - if a unit \
             has come back here, it needs the platform's ${{CLAMAV_SERVICE}} and a \
             line in this test, not a name typed into a heredoc"
        );
    }
}
