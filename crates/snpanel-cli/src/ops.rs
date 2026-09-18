//! What each command actually does.
//!
//! The read-only commands (`status`, `login`, `logs`, firewall inspection) are
//! implemented natively. The ones that change privileged state still delegate
//! to the existing bash during Phase 1 - see the note in `main.rs`.

use std::io;
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use snpanel_core::config::Settings;
use snpanel_osabi::firewall::{
    rules::{FirewallRuleset, FirewallState},
    FirewallBackend, NftablesBackend,
};

/// Source: `FIREWALL_RULES_FILE` in the helper.
const RULES_TSV: &str = "/var/lib/snpanel/firewall/rules.tsv";
const FIREWALL_STATE: &str = "/var/lib/snpanel/firewall/state";
/// Source: `write_login_info` in snpanelctl.
const LOGIN_FILE: &str = "/root/login.txt";
const SNPANELCTL: &str = "/usr/local/sbin/snpanelctl";
const HELPER: &str = "/usr/local/sbin/snpanel-helper";

/// C17: `/root/login.txt` keeps its format, so this just prints it.
pub fn show_login_info() -> Result<()> {
    match std::fs::read_to_string(LOGIN_FILE) {
        Ok(contents) => {
            print!("{contents}");
            if !contents.ends_with('\n') {
                println!();
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            println!("No saved login information at {LOGIN_FILE}.");
            println!("Run `snpanel change-admin-password` to set a new password.");
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            anyhow::bail!("{LOGIN_FILE} is readable by root only; run this with sudo")
        }
        Err(e) => Err(e).context(format!("reading {LOGIN_FILE}")),
    }
}

pub fn status(env_path: Option<&Path>) -> Result<()> {
    println!("SNPanel status\n");

    match snpanel_osabi::detect() {
        Ok(p) => println!("  OS               {}", p.distro().pretty()),
        Err(e) => println!("  OS               unsupported ({e})"),
    }

    if let Some(path) = env_path {
        match Settings::load(Some(path)) {
            Ok(s) => {
                println!("  Panel port       {}", s.panel_port);
                if !s.panel_url.is_empty() {
                    println!("  Panel URL        {}", s.panel_url);
                }
                if !s.panel_domain.is_empty() {
                    println!("  Panel domain     {}", s.panel_domain);
                }
                println!(
                    "  Panel SSL        {}",
                    if s.panel_ssl_mode.is_empty() {
                        "not configured"
                    } else {
                        &s.panel_ssl_mode
                    }
                );
            }
            Err(e) => println!("  Config           unreadable: {e}"),
        }
    } else {
        println!("  Config           not installed on this machine");
    }

    println!("\n  Services");
    // The Redis-compatible server is `redis-server` on Debian and `valkey` on
    // EL10, so both are asked for - but only units systemd actually knows get
    // printed. "valkey inactive" on a machine with no valkey package reads as a
    // service that has stopped rather than one that was never there.
    for service in panel_units()
        .into_iter()
        .chain(["nginx", "mariadb", "redis-server", "valkey"])
    {
        if !unit_is_loaded(service) {
            continue;
        }
        if let Some(state) = service_state(service) {
            println!("    {service:<16} {state}");
        }
    }

    println!("\n  Firewall");
    print_firewall_summary();

    Ok(())
}

/// The units that serve the panel on this machine.
///
/// Before the Rust cutover the panel is a single unit, `snpanel-api`. After it,
/// the Rust front door holds the port and the Python runs behind it as
/// `snpanel-upstream`, with `snpanel-api` stopped on purpose. Which one is in
/// use has to be discovered: naming the wrong one makes `status` report a
/// serving panel as down, `logs` read an empty journal, and `restart` restart
/// something that is deliberately stopped while reporting success.
fn panel_units() -> Vec<&'static str> {
    if unit_is_loaded("snpanel-rust") {
        vec!["snpanel-rust", "snpanel-upstream"]
    } else {
        vec!["snpanel-api"]
    }
}

/// Does systemd know this unit at all? `is-active` cannot answer that: a unit
/// that exists and is stopped and one that does not exist both report
/// "inactive".
fn unit_is_loaded(service: &str) -> bool {
    Command::new("systemctl")
        .args(["show", "-p", "LoadState", "--value", service])
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "loaded")
        .unwrap_or(false)
}

fn service_state(service: &str) -> Option<String> {
    let out = Command::new("systemctl")
        .args(["is-active", service])
        .output()
        .ok()?;
    let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // `unknown` means the unit does not exist; do not list it at all.
    if state.is_empty() || state == "unknown" {
        None
    } else {
        Some(state)
    }
}

fn print_firewall_summary() {
    let state = std::fs::read_to_string(FIREWALL_STATE)
        .map(|s| FirewallState::parse(&s))
        .unwrap_or(FirewallState::Enabled);
    let rules = std::fs::read_to_string(RULES_TSV)
        .map(|s| FirewallRuleset::parse_rules_tsv(&s))
        .unwrap_or_default();

    let backend = if NftablesBackend.is_available() {
        "nftables"
    } else {
        "not available"
    };
    println!(
        "    State            {}",
        match state {
            FirewallState::Enabled => "enabled",
            FirewallState::Disabled => "disabled",
        }
    );
    println!("    Backend          {backend}");
    println!("    Rules            {}", rules.len());
    if snpanel_osabi::firewall::legacy_iptables_present() {
        println!("    Legacy           iptables/ipset still installed");
    }
}

pub fn firewall_status() -> Result<()> {
    println!("SNPanel firewall\n");
    print_firewall_summary();

    let rules = std::fs::read_to_string(RULES_TSV)
        .map(|s| FirewallRuleset::parse_rules_tsv(&s))
        .unwrap_or_default();
    if rules.is_empty() {
        println!("\n  (no rules)");
        return Ok(());
    }
    println!("\n  Rules");
    for r in &rules {
        let target = match r.port {
            Some(p) => format!("{}/{}", p, r.protocol),
            None => "any port".to_string(),
        };
        let src =
            r.ip.as_ref()
                .map(|i| i.to_string())
                .unwrap_or_else(|| "any".into());
        println!(
            "    [{}] {:<5} {:<22} from {}",
            r.id,
            r.action.as_str().to_uppercase(),
            target,
            src
        );
    }
    Ok(())
}

/// Plan §6.3: migrate from iptables/ipset to nftables.
///
/// Reads `rules.tsv`, never `iptables-save`. That is the whole reason this is
/// safe - the running firewall may be in any state, including half-built, and
/// the result is the same either way.
pub fn firewall_migrate_nft(dry_run: bool, env_path: Option<&Path>) -> Result<()> {
    let tsv = std::fs::read_to_string(RULES_TSV).unwrap_or_default();
    let rules = FirewallRuleset::parse_rules_tsv(&tsv);
    let state = std::fs::read_to_string(FIREWALL_STATE)
        .map(|s| FirewallState::parse(&s))
        .unwrap_or(FirewallState::Enabled);

    let panel_port = env_path
        .and_then(|p| Settings::load(Some(p)).ok())
        .map(|s| s.panel_port.get())
        .unwrap_or(2222);

    let ruleset = FirewallRuleset {
        state,
        rules,
        protected_ports: FirewallRuleset::compute_protected_ports(&sshd_ports(), panel_port),
        // Always on: see FirewallRuleset::ipv6_enabled. Gating this on the
        // host having a global v6 address would drop existing v6 rules.
        ipv6_enabled: true,
        ..Default::default()
    };

    let rendered = NftablesBackend.render(&ruleset);

    if dry_run {
        print!("{rendered}");
        return Ok(());
    }

    anyhow::bail!(
        "loading the ruleset needs root and lands in Phase 2 with snpanel-helper.\n\
         Run `snpanel firewall migrate-nft --dry-run` to see what would be loaded, or pipe it:\n\
         \n    snpanel firewall migrate-nft --dry-run | sudo nft -f -\n"
    );
}

/// Source: `firewall_protected_ports`, which prefers `sshd -T` and falls back
/// to the raw config when sshd cannot validate it.
fn sshd_ports() -> Vec<u16> {
    let from_sshd = Command::new("sshd")
        .arg("-T")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.strip_prefix("port "))
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !from_sshd.is_empty() {
        return from_sshd;
    }

    let mut ports = Vec::new();
    for path in ["/etc/ssh/sshd_config"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                let mut parts = line.split_whitespace();
                if parts.next().is_some_and(|k| k.eq_ignore_ascii_case("port")) {
                    if let Some(p) = parts.next().and_then(|p| p.parse::<u16>().ok()) {
                        ports.push(p);
                    }
                }
            }
        }
    }
    if ports.is_empty() {
        // Never return nothing: an empty SSH port list is how a box locks
        // itself out.
        ports.push(22);
    }
    ports
}

pub fn logs(follow: bool, lines: u32) -> Result<()> {
    let mut cmd = Command::new("journalctl");
    for unit in panel_units() {
        cmd.args(["-u", unit]);
    }
    cmd.args(["-n", &lines.to_string(), "--no-pager"]);
    if follow {
        cmd.arg("-f");
    }
    let status = cmd.status().context("running journalctl")?;
    if !status.success() {
        anyhow::bail!("journalctl exited with {status}");
    }
    Ok(())
}

pub fn restart() -> Result<()> {
    for service in panel_units().into_iter().chain(["nginx"]) {
        println!("Restarting {service}...");
        let status = Command::new("systemctl")
            .args(["restart", service])
            .status()
            .context("running systemctl")?;
        if !status.success() {
            anyhow::bail!("restarting {service} failed");
        }
    }
    println!("Done.");
    Ok(())
}

/// Hand off to the bash implementation that still owns this operation.
pub fn delegate_to_snpanelctl(args: &[&str]) -> Result<ExitCode> {
    delegate(SNPANELCTL, args)
}

pub fn delegate_to_helper(args: &[&str]) -> Result<ExitCode> {
    delegate(HELPER, args)
}

fn delegate(binary: &str, args: &[&str]) -> Result<ExitCode> {
    if !Path::new(binary).exists() {
        anyhow::bail!(
            "{binary} is not installed. This command is still served by the bash \
             implementation until Phase 2 of the Rust migration lands."
        );
    }
    let status = Command::new(binary)
        .args(args)
        .status()
        .with_context(|| format!("running {binary}"))?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_ports_never_come_back_empty() {
        // An empty list would drop SSH out of the protected set and lock the
        // operator out of the box.
        assert!(!sshd_ports().is_empty());
    }

    #[test]
    fn delegating_to_a_missing_binary_explains_itself() {
        let err = delegate("/nonexistent/snpanelctl", &["status"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not installed"));
        assert!(msg.contains("Phase 2"));
    }

    #[test]
    fn a_dry_run_migration_renders_without_root() {
        // The whole point of --dry-run: an operator can see what would be
        // loaded before anything touches the kernel.
        assert!(firewall_migrate_nft(true, None).is_ok());
    }

    #[test]
    fn a_real_migration_refuses_and_says_how_to_do_it() {
        let err = firewall_migrate_nft(false, None).unwrap_err();
        assert!(err.to_string().contains("--dry-run"));
    }

    #[test]
    fn status_runs_without_an_installed_panel() {
        assert!(status(None).is_ok());
    }

    #[test]
    fn firewall_status_runs_with_no_rules_file() {
        assert!(firewall_status().is_ok());
    }
}
