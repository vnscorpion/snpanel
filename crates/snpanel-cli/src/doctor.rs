//! `snpanel doctor` - diagnose an installed machine.
//!
//! New in the Rust port (plan §8, Phase 1). The motivation is support load:
//! almost every "the panel is down" ticket is one of a dozen things, and each
//! one currently needs an engineer to SSH in and check by hand.
//!
//! Every check is read-only. `doctor` never repairs anything, because an
//! operator running a diagnostic on a box that is already misbehaving should
//! not have to wonder what it changed.

use std::fmt;
use std::path::Path;

use snpanel_core::config::Settings;
use snpanel_osabi::firewall::{legacy_iptables_present, FirewallBackend, NftablesBackend};
use snpanel_osabi::{detect, CpuBaseline, Platform};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Note,
    Warn,
    Fail,
}

impl Severity {
    fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Note => "note",
            Self::Warn => "warn",
            Self::Fail => "FAIL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `pad`, not `write_str`: a Display impl that writes directly ignores
        // any width in the format string, which silently breaks the column
        // alignment in `Report::print`.
        f.pad(self.label())
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub check: String,
    pub severity: Severity,
    pub detail: String,
    /// What to do about it. Empty when there is nothing to do.
    pub remedy: String,
}

impl Finding {
    fn new(check: &str, severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            check: check.to_string(),
            severity,
            detail: detail.into(),
            remedy: String::new(),
        }
    }

    fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = remedy.into();
        self
    }
}

/// The result of a full run.
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn worst(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Ok)
    }

    /// Process exit code: non-zero when something needs attention, so this can
    /// be dropped into a monitoring check.
    pub fn exit_code(&self) -> i32 {
        match self.worst() {
            Severity::Fail => 2,
            Severity::Warn => 1,
            _ => 0,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "worst": self.worst().label(),
            "findings": self.findings.iter().map(|f| serde_json::json!({
                "check": f.check,
                "severity": f.severity.label(),
                "detail": f.detail,
                "remedy": f.remedy,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn print(&self) {
        let width = self
            .findings
            .iter()
            .map(|f| f.check.len())
            .max()
            .unwrap_or(0)
            .max(10);
        println!("SNPanel doctor\n");
        for f in &self.findings {
            println!(
                "  [{:>4}] {:<width$}  {}",
                f.severity,
                f.check,
                f.detail,
                width = width
            );
            if !f.remedy.is_empty() {
                println!("         {:<width$}  -> {}", "", f.remedy, width = width);
            }
        }
        println!();
        match self.worst() {
            Severity::Ok | Severity::Note => println!("No problems found."),
            Severity::Warn => println!("Finished with warnings."),
            Severity::Fail => println!("Problems found that need attention."),
        }
    }
}

/// Run every check.
pub fn run(env_path: Option<&Path>) -> Report {
    let mut report = Report::default();

    let platform = check_platform(&mut report);
    check_cpu(&mut report, platform.as_deref());
    check_config(&mut report, env_path);
    check_firewall_backend(&mut report, platform.as_deref());
    check_selinux(&mut report, platform.as_deref());
    check_paths(&mut report);

    report
}

fn check_platform(report: &mut Report) -> Option<Box<dyn Platform>> {
    match detect() {
        Ok(p) => {
            report.push(Finding::new(
                "os",
                Severity::Ok,
                format!("{} (supported)", p.distro().pretty()),
            ));
            Some(p)
        }
        Err(e) => {
            report.push(
                Finding::new("os", Severity::Fail, e.to_string()).with_remedy(
                    "SNPanel supports Ubuntu 24.04, Ubuntu 26.04, Debian 13 and AlmaLinux 10",
                ),
            );
            None
        }
    }
}

fn check_cpu(report: &mut Report, platform: Option<&dyn Platform>) {
    let actual = snpanel_osabi::cpu_baseline();
    let detail = format!("{actual:?}");
    match platform {
        Some(p) if actual < p.cpu_baseline() => report.push(
            Finding::new(
                "cpu",
                Severity::Fail,
                format!(
                    "{detail}, but {} needs {:?}",
                    p.distro().pretty(),
                    p.cpu_baseline()
                ),
            )
            .with_remedy("this host cannot run this distribution; use a Debian-family one"),
        ),
        _ => {
            let note = if actual == CpuBaseline::V3 {
                "meets every supported distribution's baseline"
            } else {
                "below x86-64-v3, so AlmaLinux 10 is not an option on this host"
            };
            report.push(Finding::new(
                "cpu",
                Severity::Ok,
                format!("{detail}, {note}"),
            ));
        }
    }
}

fn check_config(report: &mut Report, env_path: Option<&Path>) {
    let Some(path) = env_path else {
        report.push(Finding::new(
            "config",
            Severity::Note,
            "no .env path given, skipping",
        ));
        return;
    };
    if !path.exists() {
        report.push(
            Finding::new(
                "config",
                Severity::Warn,
                format!("{} does not exist", path.display()),
            )
            .with_remedy("the panel is probably not installed on this machine"),
        );
        return;
    }
    match Settings::load(Some(path)) {
        Ok(s) => {
            report.push(Finding::new(
                "config",
                Severity::Ok,
                format!("{} parsed, {} keys", path.display(), s.raw.len()),
            ));
            if s.secret_key.len() < 32 {
                report.push(
                    Finding::new(
                        "secret-key",
                        Severity::Fail,
                        "SECRET_KEY is shorter than 32 characters",
                    )
                    .with_remedy(
                        "rotating it invalidates stored database passwords; plan it deliberately",
                    ),
                );
            } else {
                report.push(Finding::new(
                    "secret-key",
                    Severity::Ok,
                    "present and long enough",
                ));
            }
            if s.strangler_enabled() {
                report.push(Finding::new(
                    "strangler",
                    Severity::Note,
                    format!("unported routes proxy to {}", s.strangler_upstream),
                ));
            }
        }
        Err(e) => report.push(Finding::new("config", Severity::Fail, e.to_string())),
    }
}

fn check_firewall_backend(report: &mut Report, platform: Option<&dyn Platform>) {
    let nft = NftablesBackend;
    let has_nft = nft.is_available();
    let has_legacy = legacy_iptables_present();

    match (has_nft, has_legacy) {
        (true, false) => report.push(Finding::new("firewall", Severity::Ok, "nftables available")),
        (true, true) => report.push(
            Finding::new(
                "firewall",
                Severity::Note,
                "nftables available; legacy iptables/ipset also present",
            )
            .with_remedy(
                "run `snpanel firewall migrate-nft` once the panel is on the Rust backend",
            ),
        ),
        (false, true) => report.push(
            Finding::new(
                "firewall",
                Severity::Warn,
                "only the legacy iptables/ipset backend is present",
            )
            .with_remedy(
                "install nftables: it is required on AlmaLinux 10 and the default everywhere",
            ),
        ),
        (false, false) => report.push(
            Finding::new(
                "firewall",
                Severity::Fail,
                "neither nftables nor iptables is installed",
            )
            .with_remedy("install the nftables package"),
        ),
    }

    if let Some(p) = platform {
        if p.disable_firewalld() && Path::new("/usr/sbin/firewalld").exists() {
            report.push(
                Finding::new("firewalld", Severity::Warn, "firewalld is installed")
                    .with_remedy("SNPanel drives nft directly; stop and disable firewalld"),
            );
        }
    }
}

fn check_selinux(report: &mut Report, platform: Option<&dyn Platform>) {
    let Some(p) = platform else { return };
    if !p.selinux_enforcing_by_default() {
        report.push(Finding::new(
            "selinux",
            Severity::Ok,
            "not applicable on this distribution",
        ));
        return;
    }
    // /sys/fs/selinux/enforce is "1" when enforcing.
    match std::fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(v) if v.trim() == "1" => report.push(
            Finding::new("selinux", Severity::Note, "enforcing").with_remedy(
                "site contexts and booleans must be applied; see `snpanel doctor` output above",
            ),
        ),
        Ok(_) => report.push(Finding::new(
            "selinux",
            Severity::Warn,
            "present but permissive",
        )),
        Err(_) => report.push(Finding::new(
            "selinux",
            Severity::Warn,
            "expected on this distribution but not active",
        )),
    }
}

fn check_paths(report: &mut Report) {
    for (path, what) in [
        ("/var/lib/snpanel/firewall/rules.tsv", "firewall rules"),
        ("/etc/snpanel/sni", "panel SNI certificates"),
        ("/var/lib/snpanel/update-status.json", "update status"),
    ] {
        let p = Path::new(path);
        if p.exists() {
            report.push(Finding::new(
                "paths",
                Severity::Ok,
                format!("{what}: {path}"),
            ));
        } else {
            report.push(Finding::new(
                "paths",
                Severity::Note,
                format!("{what}: {path} not present"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_worst_last() {
        assert!(Severity::Fail > Severity::Warn);
        assert!(Severity::Warn > Severity::Note);
        assert!(Severity::Note > Severity::Ok);
    }

    #[test]
    fn the_report_surfaces_the_worst_finding() {
        let mut r = Report::default();
        r.push(Finding::new("a", Severity::Ok, "fine"));
        r.push(Finding::new("b", Severity::Warn, "hmm"));
        r.push(Finding::new("c", Severity::Ok, "fine"));
        assert_eq!(r.worst(), Severity::Warn);
        assert_eq!(r.exit_code(), 1);

        r.push(Finding::new("d", Severity::Fail, "broken"));
        assert_eq!(r.worst(), Severity::Fail);
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn an_empty_report_is_a_pass() {
        let r = Report::default();
        assert_eq!(r.worst(), Severity::Ok);
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn notes_do_not_fail_the_run() {
        // "not installed yet" is information, not a problem to alert on.
        let mut r = Report::default();
        r.push(Finding::new("paths", Severity::Note, "not present"));
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn json_output_carries_every_field() {
        let mut r = Report::default();
        r.push(Finding::new("os", Severity::Fail, "nope").with_remedy("do this"));
        let json = r.to_json();
        assert_eq!(json["worst"], "FAIL");
        assert_eq!(json["findings"][0]["check"], "os");
        assert_eq!(json["findings"][0]["severity"], "FAIL");
        assert_eq!(json["findings"][0]["remedy"], "do this");
    }

    #[test]
    fn a_missing_env_file_warns_rather_than_crashing() {
        let mut r = Report::default();
        check_config(&mut r, Some(Path::new("/nonexistent/path/.env")));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, Severity::Warn);
    }

    #[test]
    fn runs_end_to_end_on_whatever_machine_this_is() {
        // The point is that it completes and says something without panicking,
        // on a box that may or may not have the panel installed.
        let report = run(None);
        assert!(!report.findings.is_empty());
        assert!(report
            .findings
            .iter()
            .any(|f| f.check == "os" || f.check == "cpu"));
    }
}
