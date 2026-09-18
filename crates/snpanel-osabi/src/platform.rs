//! The `Platform` trait: the single place every OS difference lives.
//!
//! Plan §6.1, and its governing rule: there is no `if cfg!(debian)` scattered
//! through the business logic. A service module that needs to know which
//! distro it is on is a sign that a method is missing from this trait, not a
//! reason to branch at the call site.

use std::path::PathBuf;

use snpanel_core::PhpVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Debian,
    Rhel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Distro {
    Ubuntu2404,
    Ubuntu2604,
    Debian13,
    AlmaLinux10,
}

impl Distro {
    pub fn pretty(&self) -> &'static str {
        match self {
            Self::Ubuntu2404 => "Ubuntu 24.04",
            Self::Ubuntu2604 => "Ubuntu 26.04",
            Self::Debian13 => "Debian 13",
            Self::AlmaLinux10 => "AlmaLinux 10",
        }
    }
}

/// Where PHP packages come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhpRepo {
    /// `ppa:ondrej/php` - Ubuntu only.
    Ondrej,
    /// `packages.sury.org/php` - Debian, needs a GPG key.
    Sury,
    /// Remi, on top of EPEL. Needs `dnf module reset php` first.
    Remi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertbotMethod {
    /// Distro package.
    Apt,
    /// EPEL package.
    Dnf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSync {
    SystemdTimesyncd,
    Chronyd,
}

/// The CPU baseline a distro requires.
///
/// AlmaLinux 10 needs x86-64-v3 (AVX2, BMI, FMA). Plenty of cheap VPS hosts
/// still sell Xeon E5 v1/v2 instances, which cannot boot it at all (plan R5).
/// The installer has to say so clearly rather than fail halfway through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CpuBaseline {
    V1,
    V2,
    V3,
}

/// Everything that differs between the four supported distributions.
pub trait Platform: Send + Sync {
    fn distro(&self) -> Distro;
    fn family(&self) -> Family;

    // --- Packages ---
    fn php_repo(&self) -> PhpRepo;
    fn epel_required(&self) -> bool {
        self.family() == Family::Rhel
    }
    /// The command that installs packages, as argv. Never a shell string.
    fn install_argv(&self) -> Vec<&'static str>;
    fn remove_argv(&self) -> Vec<&'static str>;
    fn update_index_argv(&self) -> Vec<&'static str>;

    // --- PHP ---
    fn php_service(&self, v: PhpVersion) -> String;
    fn php_binary(&self, v: PhpVersion) -> PathBuf;
    fn php_fpm_pool_dir(&self, v: PhpVersion) -> PathBuf;
    fn php_ini_path(&self, v: PhpVersion) -> PathBuf;
    /// Package name for one PHP extension, e.g. `gd`.
    fn php_package(&self, v: PhpVersion, ext: &str) -> String;

    // --- Web ---
    fn web_user(&self) -> &'static str;
    fn web_group(&self) -> &'static str;
    fn nginx_conf_dir(&self) -> PathBuf {
        PathBuf::from("/etc/nginx/conf.d")
    }
    fn nginx_service(&self) -> &'static str {
        "nginx"
    }

    // --- Database and cache ---
    fn mariadb_service(&self) -> &'static str {
        "mariadb"
    }
    fn mariadb_conf_dir(&self) -> PathBuf;
    fn redis_service(&self) -> &'static str;

    // --- System ---
    fn selinux_enforcing_by_default(&self) -> bool {
        self.family() == Family::Rhel
    }
    fn certbot_install(&self) -> CertbotMethod;
    fn clamav_service(&self) -> &'static str;
    fn clamav_freshclam(&self) -> &'static str {
        "clamav-freshclam"
    }
    fn cron_service(&self) -> &'static str;
    fn timesync(&self) -> TimeSync;
    fn nologin_shell(&self) -> PathBuf;
    fn cpu_baseline(&self) -> CpuBaseline;
    /// firewalld ships enabled on EL and must be stopped: SNPanel drives nft
    /// directly, the same model as UFW on Ubuntu today (plan §8 Phase 4, 2d).
    fn disable_firewalld(&self) -> bool {
        self.family() == Family::Rhel
    }

    // --- Other paths ---
    fn phpmyadmin_root(&self) -> PathBuf;
    /// EL has no phpMyAdmin package: the tarball is fetched and checksummed.
    fn phpmyadmin_from_package(&self) -> bool {
        self.family() == Family::Debian
    }
}

/// Shared PHP-FPM pool naming, identical on every distro.
///
/// Source: `site_users.php_fpm_pool_name`. The socket path is
/// `/run/php/<pool>.sock` everywhere, because SNPanel sets it explicitly in the
/// pool file rather than taking the distro default.
pub fn php_fpm_socket_dir() -> PathBuf {
    PathBuf::from("/run/php")
}
