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
    Debian12,
    Debian13,
    AlmaLinux10,
}

impl Distro {
    pub fn pretty(&self) -> &'static str {
        match self {
            Self::Ubuntu2404 => "Ubuntu 24.04",
            Self::Debian12 => "Debian 12",
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

    /// The PHP versions this platform can actually provide, newest last.
    ///
    /// Source: `PLATFORM_PHP_VERSIONS`. `install.sh`'s `main()` reads it on
    /// its second line and every later phase works from what it says — a
    /// wrong value here is a pool directory that never appears and a default
    /// version no package provides.
    fn php_versions(&self) -> &'static [&'static str];

    /// Source: `PLATFORM_PHP_DEFAULT`. Always one of [`php_versions`].
    fn php_default(&self) -> &'static str;
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

#[cfg(test)]
mod shell_table_tests {
    use super::*;

    /// The platform table exists twice: here, and in `installer/platform.sh`.
    ///
    /// `platform.sh`'s own header says so - "The Rust side solves this with
    /// `snpanel_osabi::platform::Platform`; this is the same table for the
    /// shell" - and two copies of a table is how two copies of a table drift.
    /// Its header also records what drift costs: "writing this from EL9 habits
    /// produced four wrong values that measuring on AlmaLinux 10.2
    /// corrected".
    ///
    /// The fixture is produced by **running** both `platform_debian` and
    /// `platform_rhel10`, not by reading them: several values are built from
    /// others, and a regex over the file records the expression rather than
    /// the answer.
    ///
    /// This is Stage F's first check. The installer is still bash, and while
    /// it is, every value it sets has to agree with the one the panel uses
    /// afterwards - a web user of `nginx` in the installer and `www-data` in
    /// the panel is a box where nothing can read a customer's files.
    #[test]
    fn the_shell_installers_table_agrees_with_this_one() {
        type Table = std::collections::BTreeMap<String, String>;
        #[derive(serde::Deserialize)]
        struct Tables {
            platform_ubuntu: Table,
            platform_debian: Table,
            platform_debian12: Table,
            platform_rhel10: Table,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/platform_table.json");
        let raw = std::fs::read_to_string(&path).expect("the platform fixture");
        let tables: Tables = serde_json::from_str(&raw).expect("it parses");

        let ubuntu: &dyn Platform = &crate::debian::Ubuntu2404;
        let debian: &dyn Platform = &crate::debian::Debian13;
        let bookworm: &dyn Platform = &crate::debian::Debian12;
        let rhel: &dyn Platform = &crate::rhel::AlmaLinux10;

        for (name, table, platform) in [
            ("ubuntu", &tables.platform_ubuntu, ubuntu),
            ("debian", &tables.platform_debian, debian),
            ("debian12", &tables.platform_debian12, bookworm),
            ("rhel", &tables.platform_rhel10, rhel),
        ] {
            let shell = |key: &str| -> &str {
                table
                    .get(key)
                    .unwrap_or_else(|| panic!("{name}: the shell table has no {key}"))
                    .as_str()
            };

            assert_eq!(platform.web_user(), shell("WEB_USER"), "{name} WEB_USER");
            assert_eq!(platform.web_group(), shell("WEB_GROUP"), "{name} WEB_GROUP");
            assert_eq!(
                platform.redis_service(),
                shell("REDIS_SERVICE"),
                "{name} REDIS_SERVICE"
            );
            assert_eq!(
                platform.cron_service(),
                shell("CRON_SERVICE"),
                "{name} CRON_SERVICE"
            );
            assert_eq!(
                platform.nologin_shell().to_string_lossy(),
                shell("NOLOGIN_SHELL"),
                "{name} NOLOGIN_SHELL"
            );
            assert_eq!(
                platform.phpmyadmin_root().to_string_lossy(),
                shell("PHPMYADMIN_ROOT"),
                "{name} PHPMYADMIN_ROOT"
            );

            // One deliberate difference, and it is contextual rather than a
            // value disagreement: the shell writes its name into
            // `After=network.target ${CLAMAV_SERVICE}` in a unit file, where
            // the `.service` suffix is the conventional spelling; this side
            // hands the name to `systemctl is-active`, which takes either.
            // Compared with the suffix stripped so the *unit* still has to
            // match.
            assert_eq!(
                platform.clamav_service(),
                shell("CLAMAV_SERVICE")
                    .strip_suffix(".service")
                    .unwrap_or_else(|| panic!(
                        "{name}: the shell's CLAMAV_SERVICE lost its .service suffix, \
                         so the two spellings are no longer the documented difference"
                    )),
                "{name} CLAMAV_SERVICE"
            );

            // `install.sh`'s `main()` reads these two on its second line,
            // and every later phase works from what they say. They are the
            // one place Debian 12 and Debian 13 disagree.
            assert_eq!(
                platform.php_versions().join(" "),
                shell("PLATFORM_PHP_VERSIONS"),
                "{name} PLATFORM_PHP_VERSIONS"
            );
            assert_eq!(
                platform.php_default(),
                shell("PLATFORM_PHP_DEFAULT"),
                "{name} PLATFORM_PHP_DEFAULT"
            );
            assert!(
                platform.php_versions().contains(&platform.php_default()),
                "{name}: the default PHP is not one of the versions offered"
            );

            // Where PHP comes from, which the shell records as two flags and
            // this side as one enum. A box that takes PHP from the wrong
            // repository gets no PHP at all.
            let repo = match platform.php_repo() {
                PhpRepo::Ondrej => ("yes", "no"),
                PhpRepo::Sury => ("no", "yes"),
                PhpRepo::Remi => ("no", "no"),
            };
            assert_eq!(
                (shell("PHP_FROM_PPA"), shell("PHP_FROM_SURY")),
                repo,
                "{name} PHP repository"
            );

            // The family name the shell picks has to be the one this side
            // would pick, or every branch downstream of it differs.
            let family = match platform.family() {
                Family::Debian => "debian",
                Family::Rhel => "rhel",
            };
            assert_eq!(family, shell("OS_FAMILY"), "{name} OS_FAMILY");
        }

        // The fixture has to be a real table, not an empty one that satisfies
        // every lookup by never being asked.
        for table in [
            &tables.platform_ubuntu,
            &tables.platform_debian,
            &tables.platform_debian12,
            &tables.platform_rhel10,
        ] {
            assert!(table.len() >= 15);
        }
        // And the two Debians have to actually differ, or the fixture was
        // generated without `OS_MAJOR` reaching the function and both rows
        // are the same distribution recorded twice.
        assert_ne!(
            tables.platform_debian.get("PLATFORM_PHP_VERSIONS"),
            tables.platform_debian12.get("PLATFORM_PHP_VERSIONS"),
        );
        // As do Ubuntu and Debian, which differ in where PHP comes from.
        assert_ne!(
            tables.platform_ubuntu.get("PHP_FROM_SURY"),
            tables.platform_debian.get("PHP_FROM_SURY"),
        );
    }
}
