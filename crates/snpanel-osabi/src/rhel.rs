//! AlmaLinux 10.
//!
//! Every path here differs from the Debian family, which is the whole reason
//! the `Platform` trait exists. The Remi layout in particular is not a variant
//! spelling of the Debian one - PHP lives under `/opt/remi/phpXY/root/...`,
//! the service is `phpXY-php-fpm`, and extension packages are `phpXY-php-<ext>`.
//!
//! Also note `dnf module reset php` must run before Remi is usable, or the
//! AppStream module stream shadows it (plan §6.5).

use std::path::PathBuf;

use snpanel_core::PhpVersion;

use crate::platform::{CertbotMethod, CpuBaseline, Distro, Family, PhpRepo, Platform, TimeSync};

#[derive(Debug, Clone, Copy, Default)]
pub struct AlmaLinux10;

impl Platform for AlmaLinux10 {
    fn distro(&self) -> Distro {
        Distro::AlmaLinux10
    }
    fn family(&self) -> Family {
        Family::Rhel
    }

    fn php_versions(&self) -> &'static [&'static str] {
        &["8.3", "8.4"]
    }
    fn php_default(&self) -> &'static str {
        "8.4"
    }
    fn php_repo(&self) -> PhpRepo {
        PhpRepo::Remi
    }
    fn install_argv(&self) -> Vec<&'static str> {
        vec!["dnf", "install", "-y"]
    }
    fn remove_argv(&self) -> Vec<&'static str> {
        vec!["dnf", "remove", "-y"]
    }
    fn update_index_argv(&self) -> Vec<&'static str> {
        vec!["dnf", "makecache"]
    }

    fn php_service(&self, v: PhpVersion) -> String {
        format!("php{}-php-fpm", v.compact())
    }
    fn php_binary(&self, v: PhpVersion) -> PathBuf {
        PathBuf::from(format!("/opt/remi/php{}/root/usr/bin/php", v.compact()))
    }
    fn php_fpm_pool_dir(&self, v: PhpVersion) -> PathBuf {
        PathBuf::from(format!("/etc/opt/remi/php{}/php-fpm.d", v.compact()))
    }
    fn php_ini_path(&self, v: PhpVersion) -> PathBuf {
        PathBuf::from(format!("/etc/opt/remi/php{}/php.ini", v.compact()))
    }
    fn php_package(&self, v: PhpVersion, ext: &str) -> String {
        format!("php{}-php-{}", v.compact(), ext)
    }

    fn web_user(&self) -> &'static str {
        "nginx"
    }
    fn web_group(&self) -> &'static str {
        "nginx"
    }

    fn mariadb_conf_dir(&self) -> PathBuf {
        PathBuf::from("/etc/my.cnf.d")
    }
    /// **Valkey, not Redis.** EL10 ships no `redis` package at all - it was
    /// replaced by Valkey, packaged as `valkey` with a `valkey.service` unit.
    /// The daemon is wire-compatible and listens on 6379 as before, so
    /// `REDIS_URL` needs no change; only the unit name does. Enabling a
    /// service nothing provides would fail on every install.
    fn redis_service(&self) -> &'static str {
        "valkey"
    }

    fn certbot_install(&self) -> CertbotMethod {
        CertbotMethod::Dnf
    }
    fn clamav_service(&self) -> &'static str {
        "clamd@scan"
    }
    fn clamav_freshclam(&self) -> &'static str {
        "clamav-freshclam"
    }
    fn cron_service(&self) -> &'static str {
        "crond"
    }
    fn timesync(&self) -> TimeSync {
        TimeSync::Chronyd
    }
    fn nologin_shell(&self) -> PathBuf {
        PathBuf::from("/sbin/nologin")
    }
    fn cpu_baseline(&self) -> CpuBaseline {
        CpuBaseline::V3
    }
    fn phpmyadmin_root(&self) -> PathBuf {
        // Packaged in EPEL as `phpmyadmin`, and laid out with the project's own
        // capitalisation - not Debian's lowercase path. Measured on 10.2:
        // /usr/share/phpMyAdmin/index.php.
        PathBuf::from("/usr/share/phpMyAdmin")
    }
}
