//! Ubuntu 24.04, Debian 12 and Debian 13.
//!
//! The two share almost every path; they differ in where PHP comes from
//! (Ondrej PPA is Ubuntu-only, Debian needs Sury) and in their CPU baseline.
//!
//! Ubuntu 26.04 was implemented here and removed: Ondrej's PPA publishes no
//! `resolute` suite, so the only PHP on it is the distribution's 8.5.

use std::path::PathBuf;

use snpanel_core::PhpVersion;

use crate::platform::{CertbotMethod, CpuBaseline, Distro, Family, PhpRepo, Platform, TimeSync};

macro_rules! debian_family {
    ($name:ident, $distro:expr, $php_repo:expr, $baseline:expr, $php:expr, $default:expr) => {
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $name;

        impl Platform for $name {
            fn distro(&self) -> Distro {
                $distro
            }
            fn family(&self) -> Family {
                Family::Debian
            }

            fn php_repo(&self) -> PhpRepo {
                $php_repo
            }
            fn php_versions(&self) -> &'static [&'static str] {
                $php
            }
            fn php_default(&self) -> &'static str {
                $default
            }
            fn install_argv(&self) -> Vec<&'static str> {
                vec!["apt-get", "install", "-y", "--no-install-recommends"]
            }
            fn remove_argv(&self) -> Vec<&'static str> {
                vec!["apt-get", "remove", "-y"]
            }
            fn update_index_argv(&self) -> Vec<&'static str> {
                vec!["apt-get", "update"]
            }

            fn php_service(&self, v: PhpVersion) -> String {
                format!("php{}-fpm", v.dotted())
            }
            fn php_binary(&self, v: PhpVersion) -> PathBuf {
                PathBuf::from(format!("/usr/bin/php{}", v.dotted()))
            }
            fn php_fpm_pool_dir(&self, v: PhpVersion) -> PathBuf {
                PathBuf::from(format!("/etc/php/{}/fpm/pool.d", v.dotted()))
            }
            fn php_ini_path(&self, v: PhpVersion) -> PathBuf {
                PathBuf::from(format!("/etc/php/{}/fpm/php.ini", v.dotted()))
            }
            fn php_package(&self, v: PhpVersion, ext: &str) -> String {
                format!("php{}-{}", v.dotted(), ext)
            }

            fn web_user(&self) -> &'static str {
                "www-data"
            }
            fn web_group(&self) -> &'static str {
                "www-data"
            }

            fn mariadb_conf_dir(&self) -> PathBuf {
                PathBuf::from("/etc/mysql/mariadb.conf.d")
            }
            fn redis_service(&self) -> &'static str {
                "redis-server"
            }

            fn certbot_install(&self) -> CertbotMethod {
                CertbotMethod::Apt
            }
            fn clamav_service(&self) -> &'static str {
                "clamav-daemon"
            }
            fn cron_service(&self) -> &'static str {
                "cron"
            }
            fn timesync(&self) -> TimeSync {
                TimeSync::SystemdTimesyncd
            }
            fn nologin_shell(&self) -> PathBuf {
                PathBuf::from("/usr/sbin/nologin")
            }
            fn cpu_baseline(&self) -> CpuBaseline {
                $baseline
            }
            fn phpmyadmin_root(&self) -> PathBuf {
                PathBuf::from("/usr/share/phpmyadmin")
            }
        }
    };
}

debian_family!(
    Ubuntu2404,
    Distro::Ubuntu2404,
    PhpRepo::Ondrej,
    CpuBaseline::V2,
    &["8.3", "8.4"],
    "8.4"
);
debian_family!(
    Debian13,
    Distro::Debian13,
    PhpRepo::Sury,
    CpuBaseline::V1,
    &["8.3", "8.4"],
    "8.4"
);
// Bookworm's Sury suite carries 8.2 and 8.3, not 8.3 and 8.4. This is the
// only value in the whole table that differs between the two Debians, and
// it is the one `install.sh` reads first.
debian_family!(
    Debian12,
    Distro::Debian12,
    PhpRepo::Sury,
    CpuBaseline::V1,
    &["8.2", "8.3"],
    "8.3"
);
