//! What the Hosting Edition upgrade needs to know about a machine, and the
//! readiness verdict built from it.
//!
//! `docs/hosting/UPGRADE-PLAN.md` §3.2. The verdict is a pure function of
//! [`Facts`], so every threshold is tested against made-up machines; only
//! [`gather`] touches the real one. `snpanel doctor --enterprise-readiness`
//! prints it today, and `snpanel upgrade cloudlinux` will refuse on it with the
//! per-check exit code.

use std::path::Path;
use std::process::Command;

use crate::detect::{cpu_baseline, OsRelease};
use crate::platform::CpuBaseline;

/// Present on every CloudLinux machine; the only reliable marker.
pub const CLOUDLINUX_RELEASE: &str = "/etc/cloudlinux-release";

/// A converted machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudLinux {
    /// The text of `/etc/cloudlinux-release`, e.g. "CloudLinux release 10".
    pub release: String,
    /// Whether the LVE kernel module is loaded - i.e. the machine has been
    /// rebooted since `cldeploy`.
    pub lve_loaded: bool,
}

/// Recognise CloudLinux from `/etc/cloudlinux-release` and `/proc/modules`.
///
/// CloudLinux 10 keeps `ID=almalinux` in `/etc/os-release` and runs the
/// AlmaLinux kernel with LVE as a module (CL-0 report, F1), so neither the
/// os-release ID nor the kernel name says anything. The release file does.
pub fn cloudlinux_from(release: Option<&str>, proc_modules: &str) -> Option<CloudLinux> {
    let release = release?.trim();
    if release.is_empty() {
        return None;
    }
    let lve_loaded = proc_modules
        .lines()
        .any(|l| l.split_whitespace().next() == Some("kmodlve"));
    Some(CloudLinux {
        release: release.to_string(),
        lve_loaded,
    })
}

/// Where a loaded module appears in sysfs. Readable by every account, unlike
/// `/proc/modules`, which CloudLinux refuses to non-root users ("Operation not
/// permitted") - and the panel's API runs as one.
const LVE_SYSFS: &str = "/sys/module/kmodlve";

/// [`cloudlinux_from`] for this machine.
pub fn cloudlinux() -> Option<CloudLinux> {
    let release = std::fs::read_to_string(CLOUDLINUX_RELEASE).ok();
    let modules = std::fs::read_to_string("/proc/modules").unwrap_or_default();
    let mut cl = cloudlinux_from(release.as_deref(), &modules)?;
    cl.lve_loaded |= Path::new(LVE_SYSFS).is_dir();
    Some(cl)
}

/// Another control panel, by the file each one installs.
const OTHER_PANELS: &[(&str, &str)] = &[
    ("/usr/local/cpanel/cpanel", "cPanel"),
    ("/usr/local/directadmin/directadmin", "DirectAdmin"),
    ("/usr/local/psa/version", "Plesk"),
    ("/usr/local/interworx", "InterWorx"),
    ("/usr/local/mgr5", "ISPmanager"),
];

/// Everything the verdict is computed from.
#[derive(Debug, Clone)]
pub struct Facts {
    pub os: OsRelease,
    pub arch: String,
    pub cpu: CpuBaseline,
    /// `systemd-detect-virt`: "none", "kvm", "lxc", ...
    pub virt: String,
    /// `systemd-detect-virt --container`: `None` when not in a container.
    pub container: Option<String>,
    pub mem_total_mb: u64,
    pub root_free_mb: Option<u64>,
    pub boot_free_mb: Option<u64>,
    /// Filesystem type of `/home`, as `findmnt` names it ("xfs", "ext4").
    pub home_fs: Option<String>,
    pub other_panel: Option<&'static str>,
    pub cloudlinux: Option<CloudLinux>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Pass,
    Warn,
    Fail,
}

/// One line of the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    /// What to do about a warning or a failure; empty on a pass.
    pub remedy: String,
    /// The exit code `snpanel upgrade cloudlinux` uses when this check fails
    /// (plan §3.2), so provisioning scripts can branch without parsing text.
    pub exit_code: u8,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>, exit_code: u8) -> Self {
        Self {
            name,
            level: Level::Pass,
            detail: detail.into(),
            remedy: String::new(),
            exit_code,
        }
    }

    fn warn(name: &'static str, detail: impl Into<String>, remedy: &str, exit_code: u8) -> Self {
        Self {
            name,
            level: Level::Warn,
            detail: detail.into(),
            remedy: remedy.to_string(),
            exit_code,
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>, remedy: &str, exit_code: u8) -> Self {
        Self {
            name,
            level: Level::Fail,
            detail: detail.into(),
            remedy: remedy.to_string(),
            exit_code,
        }
    }
}

/// Exit codes, plan §3.2.
pub mod exit {
    pub const OS: u8 = 10;
    pub const ARCH: u8 = 11;
    pub const CPU: u8 = 12;
    pub const CONTAINER: u8 = 13;
    pub const RESOURCES: u8 = 14;
    pub const OTHER_PANEL: u8 = 16;
    pub const KERNEL: u8 = 17;
}

const MIN_RAM_MB: u64 = 2048;
const WARN_RAM_MB: u64 = 4096;
/// The full stack measured 5.8 GB on the trial (CageFS skeleton 3.5 GB of it).
const MIN_DISK_MB: u64 = 10 * 1024;
/// Room for more alt-php versions and CageFS updates.
const WARN_DISK_MB: u64 = 25 * 1024;
/// A new kernel plus its initramfs, beside the running one.
const MIN_BOOT_MB: u64 = 300;
const WARN_BOOT_MB: u64 = 500;

/// The verdict. The first failure's `exit_code` is what the upgrade exits with.
pub fn readiness(f: &Facts) -> Vec<Check> {
    let mut out = Vec::new();

    // --- OS -------------------------------------------------------------
    let major = f.os.version_id.split('.').next().unwrap_or("");
    let pretty = if f.os.pretty_name.is_empty() {
        format!("{} {}", f.os.id, f.os.version_id)
    } else {
        f.os.pretty_name.clone()
    };
    out.push(match (&f.cloudlinux, f.os.id.as_str(), major) {
        (Some(cl), _, _) => Check::pass(
            "os",
            format!(
                "{} - already converted, the conversion step is skipped",
                cl.release
            ),
            exit::OS,
        ),
        (None, "almalinux", "10") => Check::pass("os", pretty, exit::OS),
        _ => Check::fail(
            "os",
            format!("{pretty} - CloudLinux 10 converts from AlmaLinux 10 only"),
            "move the accounts to a new AlmaLinux 10 server with SNPanel backup/restore",
            exit::OS,
        ),
    });

    // --- Architecture and CPU ----------------------------------------------
    out.push(if f.arch == "x86_64" {
        Check::pass("arch", "x86_64", exit::ARCH)
    } else {
        Check::fail(
            "arch",
            f.arch.clone(),
            "CloudLinux 10 is built for x86_64 only",
            exit::ARCH,
        )
    });
    out.push(if f.cpu >= CpuBaseline::V3 {
        Check::pass("cpu", format!("{:?}", f.cpu), exit::CPU)
    } else {
        Check::fail(
            "cpu",
            format!(
                "{:?}, below the x86-64-v3 that AlmaLinux 10 requires",
                f.cpu
            ),
            "pick a newer host CPU",
            exit::CPU,
        )
    });

    // --- Virtualisation ---------------------------------------------------
    out.push(match &f.container {
        Some(kind) => Check::fail(
            "virtualisation",
            format!("container ({kind})"),
            "LVE is a kernel module and needs its own kernel: use a KVM/Xen VPS or bare metal",
            exit::CONTAINER,
        ),
        None if f.virt == "none" || f.virt.is_empty() => {
            Check::pass("virtualisation", "bare metal", exit::CONTAINER)
        }
        None => Check::pass("virtualisation", f.virt.clone(), exit::CONTAINER),
    });

    // --- Resources --------------------------------------------------------
    out.push(if f.mem_total_mb < MIN_RAM_MB {
        Check::fail(
            "ram",
            format!("{} MB", f.mem_total_mb),
            "at least 2 GB is needed",
            exit::RESOURCES,
        )
    } else if f.mem_total_mb < WARN_RAM_MB {
        Check::warn(
            "ram",
            format!("{} MB", f.mem_total_mb),
            "4 GB or more is recommended for a hosting server",
            exit::RESOURCES,
        )
    } else {
        Check::pass("ram", format!("{} MB", f.mem_total_mb), exit::RESOURCES)
    });
    out.push(match f.root_free_mb {
        Some(mb) if mb < MIN_DISK_MB => Check::fail(
            "disk",
            format!("{} free on /", human_mb(mb)),
            "at least 10 GB free is needed (the CloudLinux stack uses about 6 GB)",
            exit::RESOURCES,
        ),
        Some(mb) if mb < WARN_DISK_MB => Check::warn(
            "disk",
            format!("{} free on /", human_mb(mb)),
            "25 GB or more is recommended: every alt-php version and CageFS update needs room",
            exit::RESOURCES,
        ),
        Some(mb) => Check::pass(
            "disk",
            format!("{} free on /", human_mb(mb)),
            exit::RESOURCES,
        ),
        None => Check::warn(
            "disk",
            "could not measure",
            "check free space on / by hand",
            exit::RESOURCES,
        ),
    });
    out.push(match f.boot_free_mb {
        Some(mb) if mb < MIN_BOOT_MB => Check::fail(
            "boot",
            format!("{mb} MB free on /boot"),
            "free space on /boot (remove old kernels) so a new kernel can be installed",
            exit::KERNEL,
        ),
        Some(mb) if mb < WARN_BOOT_MB => Check::warn(
            "boot",
            format!("{mb} MB free on /boot"),
            "500 MB is recommended",
            exit::KERNEL,
        ),
        Some(mb) => Check::pass("boot", format!("{mb} MB free on /boot"), exit::KERNEL),
        None => Check::warn(
            "boot",
            "could not measure",
            "check free space on /boot by hand",
            exit::KERNEL,
        ),
    });

    // --- Quota filesystem -----------------------------------------------
    out.push(match f.home_fs.as_deref() {
        Some("xfs") => Check::pass("home-fs", "xfs (project quota)", 0),
        Some(fs) => Check::warn(
            "home-fs",
            fs.to_string(),
            "disk quota will be per UID instead of XFS project quota",
            0,
        ),
        None => Check::warn(
            "home-fs",
            "could not determine",
            "disk quota may not be available",
            0,
        ),
    });

    // --- Another panel ----------------------------------------------------
    out.push(match f.other_panel {
        Some(name) => Check::fail(
            "other-panel",
            format!("{name} is installed"),
            "CloudLinux integrates with one control panel per server",
            exit::OTHER_PANEL,
        ),
        None => Check::pass("other-panel", "none", exit::OTHER_PANEL),
    });

    out
}

fn human_mb(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1} GB", mb as f64 / 1024.0)
    } else {
        format!("{mb} MB")
    }
}

/// `MemTotal` from `/proc/meminfo`, in MB.
pub fn mem_total_mb(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

/// The "Available" column of `df -Pk <path>`, in MB.
pub fn df_available_mb(df_output: &str) -> Option<u64> {
    let line = df_output.lines().nth(1)?;
    let kb: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(kb / 1024)
}

fn output(argv: &[&str]) -> Option<String> {
    let out = Command::new(argv[0]).args(&argv[1..]).output().ok()?;
    // systemd-detect-virt exits 1 when it prints "none"; the text is what counts.
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Collect [`Facts`] from this machine. Read-only.
pub fn gather() -> Facts {
    let os = OsRelease::read("/etc/os-release").unwrap_or_default();
    let arch = std::fs::read_to_string("/proc/sys/kernel/arch")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::consts::ARCH.to_string());
    let container = output(&["systemd-detect-virt", "--container"]).filter(|v| v != "none");
    Facts {
        os,
        arch,
        cpu: cpu_baseline(),
        virt: output(&["systemd-detect-virt"]).unwrap_or_default(),
        container,
        mem_total_mb: std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|m| mem_total_mb(&m))
            .unwrap_or(0),
        root_free_mb: output(&["df", "-Pk", "/"]).and_then(|o| df_available_mb(&o)),
        boot_free_mb: output(&["df", "-Pk", "/boot"]).and_then(|o| df_available_mb(&o)),
        home_fs: output(&["findmnt", "-n", "-o", "FSTYPE", "-T", "/home"]),
        other_panel: OTHER_PANELS
            .iter()
            .find(|(path, _)| Path::new(path).exists())
            .map(|(_, name)| *name),
        cloudlinux: cloudlinux(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALMA_102: &str = "NAME=\"AlmaLinux\"\nVERSION_ID=\"10.2\"\nID=\"almalinux\"\n\
        ID_LIKE=\"rhel centos fedora\"\nPRETTY_NAME=\"AlmaLinux 10.2 (Lavender Lion)\"\n";

    /// The trial VPS (CL-0), before conversion.
    fn trial_box() -> Facts {
        Facts {
            os: OsRelease::parse(ALMA_102),
            arch: "x86_64".into(),
            cpu: CpuBaseline::V3,
            virt: "kvm".into(),
            container: None,
            mem_total_mb: 5919,
            root_free_mb: Some(52 * 1024),
            boot_free_mb: Some(740),
            home_fs: Some("xfs".into()),
            other_panel: None,
            cloudlinux: None,
        }
    }

    fn level(checks: &[Check], name: &str) -> Level {
        checks.iter().find(|c| c.name == name).unwrap().level
    }

    #[test]
    fn the_trial_machine_passes_every_check() {
        let checks = readiness(&trial_box());
        assert!(checks.iter().all(|c| c.level == Level::Pass), "{checks:#?}");
    }

    #[test]
    fn cloudlinux_is_recognised_by_its_release_file_not_by_os_release() {
        // F1: after cldeploy, os-release still says almalinux.
        let modules =
            "kmodlve 51265536 3 - Live 0x0000000000000000 (OE)\nxfs 3104768 2 - Live 0x0\n";
        let cl = cloudlinux_from(Some("CloudLinux release 10\n"), modules).unwrap();
        assert_eq!(cl.release, "CloudLinux release 10");
        assert!(cl.lve_loaded);

        let not_rebooted =
            cloudlinux_from(Some("CloudLinux release 10"), "xfs 1 2 - Live 0x0\n").unwrap();
        assert!(!not_rebooted.lve_loaded);

        assert_eq!(cloudlinux_from(None, modules), None);
        assert_eq!(cloudlinux_from(Some("  \n"), modules), None);
    }

    #[test]
    fn a_module_named_like_kmodlve_does_not_count() {
        let cl = cloudlinux_from(
            Some("CloudLinux release 10"),
            "kmodlve_extra 1 0 - Live 0x0\n",
        )
        .unwrap();
        assert!(!cl.lve_loaded);
    }

    #[test]
    fn an_already_converted_machine_is_ready_and_skips_the_conversion() {
        let mut f = trial_box();
        f.cloudlinux = Some(CloudLinux {
            release: "CloudLinux release 10".into(),
            lve_loaded: true,
        });
        let checks = readiness(&f);
        let os = checks.iter().find(|c| c.name == "os").unwrap();
        assert_eq!(os.level, Level::Pass);
        assert!(os.detail.contains("already converted"));
    }

    #[test]
    fn only_almalinux_10_can_be_converted() {
        for (id, ver) in [
            ("ubuntu", "24.04"),
            ("debian", "13"),
            ("rocky", "10.1"),
            ("almalinux", "9.6"),
        ] {
            let mut f = trial_box();
            f.os = OsRelease {
                id: id.into(),
                version_id: ver.into(),
                ..Default::default()
            };
            let checks = readiness(&f);
            let os = checks.iter().find(|c| c.name == "os").unwrap();
            assert_eq!(os.level, Level::Fail, "{id} {ver}");
            assert_eq!(os.exit_code, exit::OS);
        }
    }

    #[test]
    fn a_container_is_refused_because_lve_needs_a_kernel() {
        for kind in ["lxc", "openvz", "systemd-nspawn", "docker", "podman", "wsl"] {
            let mut f = trial_box();
            f.virt = kind.into();
            f.container = Some(kind.into());
            let checks = readiness(&f);
            assert_eq!(level(&checks, "virtualisation"), Level::Fail, "{kind}");
        }
        let mut f = trial_box();
        f.virt = "none".into();
        let checks = readiness(&f);
        let v = checks.iter().find(|c| c.name == "virtualisation").unwrap();
        assert_eq!((v.level, v.detail.as_str()), (Level::Pass, "bare metal"));
    }

    #[test]
    fn arch_and_cpu_baseline_are_hard_requirements() {
        let mut f = trial_box();
        f.arch = "aarch64".into();
        f.cpu = CpuBaseline::V2;
        let checks = readiness(&f);
        assert_eq!(level(&checks, "arch"), Level::Fail);
        assert_eq!(level(&checks, "cpu"), Level::Fail);
    }

    #[test]
    fn resource_thresholds() {
        let cases = [
            (1500, Level::Fail),
            (2048, Level::Warn),
            (4095, Level::Warn),
            (4096, Level::Pass),
        ];
        for (mb, want) in cases {
            let mut f = trial_box();
            f.mem_total_mb = mb;
            assert_eq!(level(&readiness(&f), "ram"), want, "{mb} MB RAM");
        }
        for (mb, want) in [
            (8 * 1024, Level::Fail),
            (18 * 1024, Level::Warn),
            (30 * 1024, Level::Pass),
        ] {
            let mut f = trial_box();
            f.root_free_mb = Some(mb);
            assert_eq!(level(&readiness(&f), "disk"), want, "{mb} MB disk");
        }
        for (mb, want) in [(200, Level::Fail), (400, Level::Warn), (740, Level::Pass)] {
            let mut f = trial_box();
            f.boot_free_mb = Some(mb);
            assert_eq!(level(&readiness(&f), "boot"), want, "{mb} MB /boot");
        }
    }

    #[test]
    fn unmeasurable_space_warns_rather_than_blocks() {
        let mut f = trial_box();
        f.root_free_mb = None;
        f.boot_free_mb = None;
        f.home_fs = None;
        let checks = readiness(&f);
        assert!(checks.iter().all(|c| c.level != Level::Fail));
    }

    #[test]
    fn ext4_home_is_a_warning_not_a_refusal() {
        let mut f = trial_box();
        f.home_fs = Some("ext4".into());
        assert_eq!(level(&readiness(&f), "home-fs"), Level::Warn);
    }

    #[test]
    fn another_panel_is_refused() {
        let mut f = trial_box();
        f.other_panel = Some("DirectAdmin");
        let checks = readiness(&f);
        let c = checks.iter().find(|c| c.name == "other-panel").unwrap();
        assert_eq!((c.level, c.exit_code), (Level::Fail, exit::OTHER_PANEL));
    }

    #[test]
    fn exit_codes_are_distinct_per_reason() {
        let codes = [
            exit::OS,
            exit::ARCH,
            exit::CPU,
            exit::CONTAINER,
            exit::RESOURCES,
            exit::OTHER_PANEL,
            exit::KERNEL,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    #[test]
    fn parses_meminfo_and_df() {
        assert_eq!(
            mem_total_mb("MemTotal:        6060656 kB\nMemFree: 1 kB\n"),
            Some(5918)
        );
        assert_eq!(mem_total_mb("MemFree: 1 kB\n"), None);
        let df = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n\
                  /dev/sda4         56563712 6012000  50551712      11% /\n";
        assert_eq!(df_available_mb(df), Some(49366));
        assert_eq!(df_available_mb("garbage"), None);
    }
}
