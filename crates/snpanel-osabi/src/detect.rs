//! Reading `/etc/os-release` and picking the right [`Platform`].
//!
//! Source: `detect_platform` in `installer/platform.sh`, which does the
//! same reading and then sources one of the per-distribution tables.
//!
//! Plan §6.1. This replaces `installer/install.sh` line 17, which hard-refuses
//! anything that is not Ubuntu 24.04:
//!
//! ```bash
//! if [[ "${ID}" != "ubuntu" || "${VERSION_ID}" != "24.04" ]]; then
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use crate::debian::{Debian12, Debian13, Ubuntu2404};
use crate::platform::{CpuBaseline, Platform};
use crate::rhel::AlmaLinux10;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OsError {
    #[error("cannot read /etc/os-release: {0}")]
    Unreadable(String),
    #[error("unsupported operating system: {id} {ver}")]
    Unsupported { id: String, ver: String },
    #[error(
        "this CPU is too old for {distro}: it requires the {required:?} instruction set baseline. \
         Older Xeon E5 v1/v2 hosts cannot run it at all. Pick a Debian-family distro instead."
    )]
    CpuTooOld {
        distro: &'static str,
        required: CpuBaseline,
    },
}

/// The parsed contents of `/etc/os-release`.
#[derive(Debug, Clone, Default)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
    pub id_like: Vec<String>,
}

impl OsRelease {
    pub fn read(path: impl AsRef<Path>) -> Result<Self, OsError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| OsError::Unreadable(e.to_string()))?;
        Ok(Self::parse(&text))
    }

    /// `os-release(5)`: `KEY=value`, values optionally quoted.
    pub fn parse(text: &str) -> Self {
        let mut map = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = v.trim();
            let v = v.strip_prefix('"').unwrap_or(v);
            let v = v.strip_suffix('"').unwrap_or(v);
            let v = v.strip_prefix('\'').unwrap_or(v);
            let v = v.strip_suffix('\'').unwrap_or(v);
            map.insert(k.trim().to_string(), v.to_string());
        }
        Self {
            id: map.get("ID").cloned().unwrap_or_default(),
            version_id: map.get("VERSION_ID").cloned().unwrap_or_default(),
            pretty_name: map.get("PRETTY_NAME").cloned().unwrap_or_default(),
            id_like: map
                .get("ID_LIKE")
                .map(|s| s.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
        }
    }
}

/// Detect the running system.
pub fn detect() -> Result<Box<dyn Platform>, OsError> {
    let os = OsRelease::read("/etc/os-release")?;
    platform_for(&os)
}

/// Pick a platform for an already-read `os-release`. Separated out so it can be
/// tested against captured files from all four distros without a container.
pub fn platform_for(os: &OsRelease) -> Result<Box<dyn Platform>, OsError> {
    // VERSION_ID is "10" on AlmaLinux 10.0 but "10.1" on a point release, so
    // the RHEL arm matches on the major only.
    let major = os.version_id.split('.').next().unwrap_or("");
    match (os.id.as_str(), os.version_id.as_str(), major) {
        ("ubuntu", "24.04", _) => Ok(Box::new(Ubuntu2404)),
        ("debian", _, "13") => Ok(Box::new(Debian13)),
        // The shell installer has accepted bookworm all along. Refusing
        // it here would make the Rust installer a downgrade on every
        // Debian 12 box that already runs the panel.
        ("debian", _, "12") => Ok(Box::new(Debian12)),
        // Rocky, RHEL and Oracle 10 share the AlmaLinux layout exactly, so
        // they get the same impl. Plan §8 Phase 7 lists this as an extension;
        // it costs nothing to accept them now, and refusing them would be an
        // arbitrary "unsupported" for a system we already handle correctly.
        ("almalinux" | "rocky" | "rhel" | "ol" | "centos", _, "10") => Ok(Box::new(AlmaLinux10)),
        _ => Err(OsError::Unsupported {
            id: os.id.clone(),
            ver: os.version_id.clone(),
        }),
    }
}

/// Read the CPU flags this machine reports.
pub fn cpu_baseline() -> CpuBaseline {
    let flags = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let flag_line = flags
        .lines()
        .find(|l| l.starts_with("flags"))
        .unwrap_or_default();
    baseline_from_flags(flag_line)
}

/// x86-64-v3 is AVX2 + BMI1 + BMI2 + FMA + MOVBE + F16C + LZCNT;
/// x86-64-v2 is SSE4.2 + POPCNT + SSSE3 + CX16.
/// Checking the headline members of each set is enough in practice - no real
/// CPU ships AVX2 without the rest of v3.
pub fn baseline_from_flags(flag_line: &str) -> CpuBaseline {
    let has = |f: &str| flag_line.split_whitespace().any(|x| x == f);
    if has("avx2") && has("bmi2") && has("fma") {
        CpuBaseline::V3
    } else if has("sse4_2") && has("popcnt") {
        CpuBaseline::V2
    } else {
        CpuBaseline::V1
    }
}

/// Plan R5: refuse early and explain, rather than failing halfway through an
/// install on a host that could never have worked.
pub fn check_cpu_supported(platform: &dyn Platform) -> Result<(), OsError> {
    let required = platform.cpu_baseline();
    let actual = cpu_baseline();
    if actual < required {
        return Err(OsError::CpuTooOld {
            distro: platform.distro().pretty(),
            required,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{Distro, Family, PhpRepo};

    const UBUNTU_2404: &str = r#"PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"#;

    const UBUNTU_2604: &str = r#"PRETTY_NAME="Ubuntu 26.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION_CODENAME=resolute
ID=ubuntu
ID_LIKE=debian
"#;

    const DEBIAN_13: &str = r#"PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
ID=debian
"#;

    const ALMA_10: &str = r#"NAME="AlmaLinux"
VERSION_ID="10.0"
ID="almalinux"
ID_LIKE="rhel centos fedora"
PRETTY_NAME="AlmaLinux 10.0 (Purple Lion)"
"#;

    #[test]
    fn parses_os_release_with_and_without_quotes() {
        let os = OsRelease::parse(ALMA_10);
        assert_eq!(os.id, "almalinux");
        assert_eq!(os.version_id, "10.0");
        assert_eq!(os.pretty_name, "AlmaLinux 10.0 (Purple Lion)");
        assert_eq!(os.id_like, vec!["rhel", "centos", "fedora"]);

        let os = OsRelease::parse(UBUNTU_2404);
        assert_eq!(os.id, "ubuntu");
        assert_eq!(os.version_id, "24.04");
    }

    #[test]
    fn detects_every_supported_distro() {
        let cases = [
            (UBUNTU_2404, Distro::Ubuntu2404),
            (DEBIAN_13, Distro::Debian13),
            (ALMA_10, Distro::AlmaLinux10),
        ];
        for (text, expected) in cases {
            let p = platform_for(&OsRelease::parse(text)).expect("supported");
            assert_eq!(p.distro(), expected);
        }
    }

    #[test]
    fn ubuntu_2604_is_refused_rather_than_guessed_at() {
        // Kept as a real captured os-release, not an invented one: the point
        // is that a machine which genuinely reports 26.04 is turned away,
        // where before it was accepted and then could not install PHP 8.3 or
        // 8.4 because Ondrej's PPA has no `resolute` suite. Silently falling
        // back to the 24.04 table would be worse than refusing - it would
        // name packages that do not exist on the machine.
        // Matched rather than `expect_err`: the Ok side is a `Box<dyn
        // Platform>`, which has no Debug for the panic message to print.
        let msg = match platform_for(&OsRelease::parse(UBUNTU_2604)) {
            Ok(p) => panic!("26.04 should be refused, got {}", p.distro().pretty()),
            Err(e) => e.to_string(),
        };
        assert!(
            msg.contains("ubuntu"),
            "the message should name the id: {msg}"
        );
        assert!(
            msg.contains("26.04"),
            "the message should name the version: {msg}"
        );
    }

    #[test]
    fn an_almalinux_point_release_still_matches() {
        let os = OsRelease::parse("ID=almalinux\nVERSION_ID=\"10.2\"\n");
        assert_eq!(platform_for(&os).unwrap().distro(), Distro::AlmaLinux10);
    }

    #[test]
    fn el_rebuilds_share_the_almalinux_implementation() {
        for id in ["rocky", "rhel", "ol"] {
            let os = OsRelease::parse(&format!("ID={id}\nVERSION_ID=\"10.0\"\n"));
            assert_eq!(platform_for(&os).unwrap().distro(), Distro::AlmaLinux10);
        }
    }

    /// Debian 12 is accepted, and that is a Phase 7 item brought forward
    /// on purpose.
    ///
    /// The shell installer has taken bookworm all along, and every runtime
    /// caller of `detect()` falls back to the Debian branch when it fails —
    /// so the panel has worked there by accident of the fallback rather than
    /// by decision. The **installer** cannot rely on that: bookworm's Sury
    /// suite carries PHP 8.2 and 8.3 where trixie's carries 8.3 and 8.4, and
    /// a Rust installer that could not tell them apart would ask bookworm
    /// for a php8.4 it has no package for.
    #[test]
    fn bookworm_is_its_own_platform_and_not_trixies() {
        let os = OsRelease::parse("ID=debian\nVERSION_ID=\"12\"\n");
        let platform = platform_for(&os).expect("Debian 12 is supported");
        assert_eq!(platform.distro(), Distro::Debian12);
        assert_eq!(platform.php_versions(), ["8.2", "8.3"]);
        assert_eq!(platform.php_default(), "8.3");

        let trixie = platform_for(&OsRelease::parse("ID=debian\nVERSION_ID=\"13\"\n")).unwrap();
        assert_eq!(trixie.php_versions(), ["8.3", "8.4"]);
        assert_eq!(trixie.php_default(), "8.4");
        // Everything else about the two is the same, which is why one table
        // serves both in the shell.
        assert_eq!(platform.web_user(), trixie.web_user());
        assert_eq!(platform.php_repo(), trixie.php_repo());
    }

    #[test]
    fn unsupported_systems_say_what_they_are() {
        for text in [
            "ID=ubuntu\nVERSION_ID=\"22.04\"\n",
            "ID=centos\nVERSION_ID=\"7\"\n",
            "ID=debian\nVERSION_ID=\"11\"\n",
            "ID=almalinux\nVERSION_ID=\"9.4\"\n",
        ] {
            let result = platform_for(&OsRelease::parse(text));
            let err = match result {
                Err(e) => e,
                Ok(p) => panic!("{text} should be unsupported, got {:?}", p.distro()),
            };
            assert!(
                matches!(err, OsError::Unsupported { .. }),
                "{text} -> {err}"
            );
        }
    }

    #[test]
    fn php_paths_differ_exactly_where_the_matrix_says() {
        let php = snpanel_core::PhpVersion::parse("8.4").unwrap();

        let ubuntu = platform_for(&OsRelease::parse(UBUNTU_2404)).unwrap();
        assert_eq!(ubuntu.php_service(php), "php8.4-fpm");
        assert_eq!(ubuntu.php_binary(php).to_str().unwrap(), "/usr/bin/php8.4");
        assert_eq!(
            ubuntu.php_fpm_pool_dir(php).to_str().unwrap(),
            "/etc/php/8.4/fpm/pool.d"
        );
        assert_eq!(ubuntu.php_package(php, "gd"), "php8.4-gd");
        assert_eq!(ubuntu.web_user(), "www-data");

        let alma = platform_for(&OsRelease::parse(ALMA_10)).unwrap();
        assert_eq!(alma.php_service(php), "php84-php-fpm");
        assert_eq!(
            alma.php_binary(php).to_str().unwrap(),
            "/opt/remi/php84/root/usr/bin/php"
        );
        assert_eq!(
            alma.php_fpm_pool_dir(php).to_str().unwrap(),
            "/etc/opt/remi/php84/php-fpm.d"
        );
        assert_eq!(alma.php_package(php, "gd"), "php84-php-gd");
        assert_eq!(alma.web_user(), "nginx");
    }

    #[test]
    fn service_names_match_the_matrix() {
        let ubuntu = platform_for(&OsRelease::parse(UBUNTU_2404)).unwrap();
        assert_eq!(ubuntu.redis_service(), "redis-server");
        assert_eq!(ubuntu.cron_service(), "cron");
        assert_eq!(ubuntu.clamav_service(), "clamav-daemon");
        assert_eq!(
            ubuntu.nologin_shell().to_str().unwrap(),
            "/usr/sbin/nologin"
        );
        assert_eq!(
            ubuntu.mariadb_conf_dir().to_str().unwrap(),
            "/etc/mysql/mariadb.conf.d"
        );

        let alma = platform_for(&OsRelease::parse(ALMA_10)).unwrap();
        // Valkey, not Redis. This assertion said "redis" until it was checked
        // against AlmaLinux 10.2, which packages no `redis` at all - only
        // `valkey` 8.0.11, with a `valkey.service` unit. The test had been
        // written from the same assumption as the code, so it agreed with it
        // and reported nothing; enabling a unit nothing provides would have
        // failed on every EL10 install.
        assert_eq!(alma.redis_service(), "valkey");
        assert_eq!(alma.cron_service(), "crond");
        assert_eq!(alma.clamav_service(), "clamd@scan");
        assert_eq!(alma.nologin_shell().to_str().unwrap(), "/sbin/nologin");
        assert_eq!(alma.mariadb_conf_dir().to_str().unwrap(), "/etc/my.cnf.d");
        // Packaged in EPEL, with the project's own capitalisation - measured at
        // /usr/share/phpMyAdmin/index.php on 10.2, not Debian's lowercase path.
        assert_eq!(
            alma.phpmyadmin_root().to_str().unwrap(),
            "/usr/share/phpMyAdmin"
        );
    }

    #[test]
    fn php_repo_per_distro() {
        let cases = [
            (UBUNTU_2404, PhpRepo::Ondrej),
            (DEBIAN_13, PhpRepo::Sury),
            (ALMA_10, PhpRepo::Remi),
        ];
        for (text, expected) in cases {
            assert_eq!(
                platform_for(&OsRelease::parse(text)).unwrap().php_repo(),
                expected
            );
        }
    }

    #[test]
    fn only_the_rhel_family_carries_selinux_and_firewalld() {
        let ubuntu = platform_for(&OsRelease::parse(UBUNTU_2404)).unwrap();
        assert!(!ubuntu.selinux_enforcing_by_default());
        assert!(!ubuntu.disable_firewalld());
        assert!(!ubuntu.epel_required());
        assert!(ubuntu.phpmyadmin_from_package());

        let alma = platform_for(&OsRelease::parse(ALMA_10)).unwrap();
        assert!(alma.selinux_enforcing_by_default());
        assert!(alma.disable_firewalld());
        assert!(alma.epel_required());
        assert!(!alma.phpmyadmin_from_package());
        assert_eq!(alma.family(), Family::Rhel);
    }

    #[test]
    fn package_manager_argv_never_goes_through_a_shell() {
        let alma = platform_for(&OsRelease::parse(ALMA_10)).unwrap();
        assert_eq!(alma.install_argv()[0], "dnf");
        let ubuntu = platform_for(&OsRelease::parse(UBUNTU_2404)).unwrap();
        assert_eq!(ubuntu.install_argv()[0], "apt-get");
        // Each element is a single argument: no embedded spaces to be split.
        for p in [&alma, &ubuntu] {
            assert!(p.install_argv().iter().all(|a| !a.contains(' ')));
        }
    }

    #[test]
    fn cpu_baseline_reads_the_flag_line() {
        assert_eq!(
            baseline_from_flags("flags : fpu vme de pse tsc"),
            CpuBaseline::V1
        );
        assert_eq!(
            baseline_from_flags("flags : fpu sse4_2 popcnt ssse3"),
            CpuBaseline::V2
        );
        assert_eq!(
            baseline_from_flags("flags : sse4_2 popcnt avx2 bmi2 fma"),
            CpuBaseline::V3
        );
    }

    #[test]
    fn alma_needs_v3_and_the_debian_family_does_not() {
        assert_eq!(
            platform_for(&OsRelease::parse(ALMA_10))
                .unwrap()
                .cpu_baseline(),
            CpuBaseline::V3
        );
        assert_eq!(
            platform_for(&OsRelease::parse(DEBIAN_13))
                .unwrap()
                .cpu_baseline(),
            CpuBaseline::V1
        );
        assert_eq!(
            platform_for(&OsRelease::parse(UBUNTU_2404))
                .unwrap()
                .cpu_baseline(),
            CpuBaseline::V2
        );
    }
}
