//! What each command actually does.
//!
//! The read-only commands (`status`, `login`, `logs`, firewall inspection) are
//! implemented natively. The ones that change privileged state still delegate
//! to the existing bash during Phase 1 - see the note in `main.rs`.

use std::io;
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};

use crate::ENV_PATH;
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

/// Source: `DEFAULT_PANEL_PORT` in `snpanelctl`.
const DEFAULT_PANEL_PORT: &str = "2222";

/// `snpanel repair-firewall`, and `snpanel firewall reopen`.
///
/// Source: `repair_firewall` in `snpanelctl`.
///
/// The two names ran different code and only one of them worked. `firewall
/// reopen` asked the helper for `firewall-reopen`, a verb no helper has ever
/// had - not this one, and not the bash it replaced - so it printed "unknown
/// command" and exited 1. They are the same function now, because "reopen the
/// ports" is what an operator locked out of the panel is looking for, under
/// whichever name they reach for first.
///
/// What it does is narrower than it sounds. SSH, the panel port and
/// 80/443/465/587 are *protected* ports: the helper derives them from `sshd`
/// and `.env` every time it renders the chain, so rebuilding the chain is
/// what reopens them. The explicit `firewall-allow-port` calls below are for
/// the non-standard SSH ports, which a rule has to name.
pub fn repair_firewall(env_path: Option<&Path>) -> Result<()> {
    // `ensure_env_file`: without it there is no panel to reopen a port for,
    // and the ports this would rebuild from are unknown.
    let Some(env) = env_path else {
        anyhow::bail!("{ENV_PATH} not found. Run the installer first.");
    };

    // Read and validate, then do nothing with it. The bash does the same: a
    // panel port that is not a port means the `.env` is corrupt, and finding
    // that out here - before rebuilding the firewall from it - is the point.
    let panel_port = env_value(env, "PANEL_PORT")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PANEL_PORT.to_string());
    if panel_port.parse::<u16>().ok().filter(|p| *p > 0).is_none() {
        anyhow::bail!("Invalid panel port in {}: {panel_port}", env.display());
    }

    // Port 22 is protected and needs no rule; any other port an operator
    // reaches this box on does.
    for port in sshd_ports().into_iter().filter(|p| *p != 22) {
        let _ = helper(&["firewall-allow-port", &port.to_string(), "tcp"]);
    }

    if helper(&["firewall-apply"]).is_err() {
        println!("(could not reach the helper to rebuild the chain)");
    }
    let _ = firewall_status();

    println!();
    println!("Firewall rescue rules refreshed.");
    println!("If the server is still unreachable, run: snpanel-rescue-firewall");
    Ok(())
}

/// Run one helper verb the way `run_firewall_helper` does: as `snpanel`, with
/// its output swallowed, and never fatal to the caller.
///
/// The bash ends every one of these with `|| true`. The caller here may be an
/// operator who has just locked themselves out, and a helper that is missing
/// or refuses one port must not stop the rebuild that reopens the rest.
fn helper(args: &[&str]) -> Result<()> {
    if !Path::new(HELPER).exists() {
        anyhow::bail!("{HELPER} is not installed");
    }
    let status = Command::new(HELPER)
        .args(args)
        .env("SUDO_USER", "snpanel")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("running {HELPER}"))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("{HELPER} {} exited {:?}", args[0], status.code())
    }
}

/// Source: `env_get` - the **first** match, and everything after the first
/// `=`.
fn env_value(path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::to_string)
}

/// Source: `/usr/local/sbin/snpanel-update`, which `install.sh` installs from
/// `installer/update.sh`.
const UPDATE_SCRIPT: &str = "/usr/local/sbin/snpanel-update";
/// Source: `/usr/local/sbin/snpanel-change-ip`, installed from `change_IP.sh`.
const CHANGE_IP_SCRIPT: &str = "/usr/local/sbin/snpanel-change-ip";

/// Which version an update is aimed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateTarget {
    /// The latest tagged release - what the bash always did.
    Release,
    Tag(String),
    Branch(String),
}

impl UpdateTarget {
    /// The flag handed to `snpanel-update`.
    fn args(&self) -> Vec<String> {
        match self {
            Self::Release => vec!["--release".into()],
            Self::Tag(t) => vec!["--tag".into(), t.clone()],
            Self::Branch(b) => vec!["--branch".into(), b.clone()],
        }
    }

    /// What the confirmation asks, so it names what will actually happen.
    fn question(&self) -> String {
        match self {
            Self::Release => "Update SNPanel to the latest vX.Y.Z release now?".into(),
            Self::Tag(t) => format!("Update SNPanel to {t} now?"),
            Self::Branch(b) => format!("Update SNPanel to the head of {b} now?"),
        }
    }
}

/// `snpanel update [--release|--tag T|--branch B]`.
///
/// Source: `run_panel_update`.
///
/// **A measured divergence, and the reason for it.** The bash dispatches
/// `update|--update) run_panel_update ;;` with no `shift` and no `"$@"`, so
/// `run_panel_update` never saw an argument: `snpanel update --tag v1.2.3`
/// asked about "the latest vX.Y.Z release", and then installed it. Both flags
/// have been on this CLI's own `--help` the whole time, documented as
/// "Update to a specific tag" and "Update to the head of a branch". Carrying
/// the bash's behaviour across would mean shipping a flag that does not do
/// what the program says it does, so they are passed through, and the
/// question names the target.
pub fn run_update(target: UpdateTarget) -> Result<()> {
    if !is_executable(Path::new(UPDATE_SCRIPT)) {
        anyhow::bail!("{UPDATE_SCRIPT} not found");
    }
    if !confirm(&target.question())? {
        println!("Canceled.");
        return Ok(());
    }
    let args = target.args();
    let status = Command::new(UPDATE_SCRIPT)
        .args(&args)
        .status()
        .with_context(|| format!("running {UPDATE_SCRIPT}"))?;
    if !status.success() {
        anyhow::bail!("{UPDATE_SCRIPT} exited {:?}", status.code());
    }
    Ok(())
}

/// `snpanel change-ip [<old> <new>]`.
///
/// Source: `change_panel_ip`. Two addresses, or none and it asks; anything
/// else is a usage error rather than a guess, because this rewrites every
/// file on the box that records an address.
pub fn change_ip(addresses: &[String]) -> Result<()> {
    if !is_executable(Path::new(CHANGE_IP_SCRIPT)) {
        anyhow::bail!(
            "{CHANGE_IP_SCRIPT} not found. Reinstall/update SNPanel or copy \
             change_IP.sh to that path."
        );
    }

    let (old_ip, new_ip) = match addresses.len() {
        2 => (addresses[0].clone(), addresses[1].clone()),
        0 => {
            let old = ask("Old IP: ")?;
            // The address this box answers on is the one it is usually being
            // changed *to*, so it is offered as the default.
            let current = detect_ip();
            let new = match current.as_deref().filter(|c| !c.is_empty()) {
                Some(c) => {
                    let typed = ask(&format!("New IP [{c}]: "))?;
                    if typed.is_empty() {
                        c.to_string()
                    } else {
                        typed
                    }
                }
                None => ask("New IP: ")?,
            };
            (old, new)
        }
        _ => anyhow::bail!("usage: snpanel change-ip <old-ip> <new-ip>"),
    };

    let status = Command::new(CHANGE_IP_SCRIPT)
        .args([&old_ip, &new_ip])
        .status()
        .with_context(|| format!("running {CHANGE_IP_SCRIPT}"))?;
    if !status.success() {
        anyhow::bail!("{CHANGE_IP_SCRIPT} exited {:?}", status.code());
    }
    Ok(())
}

/// Source: `detect_ip` - `hostname -I | awk '{print $1}'`, and an empty
/// answer rather than an error.
fn detect_ip() -> Option<String> {
    let out = Command::new("hostname").arg("-I").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
}

/// Source: `read -rp "... [y/N]: "` and `case y|Y|yes|YES`.
///
/// Anything else is no, including EOF: a confirmation that defaults to yes
/// when nobody answered is not a confirmation.
fn confirm(question: &str) -> Result<bool> {
    let answer = ask(&format!("{question} [y/N]: "))?;
    Ok(matches!(answer.as_str(), "y" | "Y" | "yes" | "YES"))
}

fn ask(prompt: &str) -> Result<String> {
    use std::io::Write;
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(String::new());
    }
    Ok(line.trim().to_string())
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
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

    /// Every verb this CLI hands to the helper is one the helper answers.
    ///
    /// The panel has the same test over its own call sites. This one exists
    /// because that one does not read this crate, and the gap was not
    /// theoretical: `firewall reopen` asked for `firewall-reopen`, which no
    /// mapping has ever had and which was not an arm of the bash helper
    /// either. The command printed "unknown command" from whichever helper
    /// was installed, and nothing said so.
    ///
    /// These names are strings, not enum variants, so the compiler does not
    /// catch them and the bash no longer does.
    #[test]
    fn every_verb_the_cli_hands_the_helper_is_one_it_answers() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir)
                .expect("a source directory")
                .flatten()
            {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
                    // This file *defines* `delegate_to_helper`; the calls are
                    // in `main.rs`.
                    && path.file_name().and_then(|n| n.to_str()) != Some("ops.rs")
                {
                    out.push(path);
                }
            }
        }

        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        files.sort();

        let mut verbs = std::collections::BTreeSet::new();
        for path in &files {
            let text = std::fs::read_to_string(path).expect("a source file");
            let mut from = 0;
            // `delegate_to_helper(&["verb", "arg", ...])`
            while let Some(hit) = text[from..].find("delegate_to_helper(&[") {
                let at = from + hit + "delegate_to_helper(&[".len();
                from = at;
                let Some(end) = text[at..].find(']') else {
                    break;
                };
                let args: Vec<String> = text[at..at + end]
                    .split(',')
                    .map(|a| a.trim().trim_matches('"').to_string())
                    .filter(|a| !a.is_empty())
                    .collect();
                if let Some(verb) = args.first().filter(|v| {
                    !v.is_empty()
                        && v.bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                }) {
                    verbs.insert(verb.clone());
                }
            }
        }

        assert!(!verbs.is_empty(), "the scan found no verbs at all");
        let mut unknown = Vec::new();
        for verb in &verbs {
            // `from_argv` matches on `(name, arity)`, so any arity that maps
            // proves the name is one the helper knows.
            let known = (0..=8).any(|n| {
                let argv: Vec<String> = std::iter::once(verb.clone())
                    .chain((0..n).map(|i| format!("arg{i}")))
                    .collect();
                !matches!(
                    snpanel_ipc::HelperRequest::from_argv(&argv, Vec::new),
                    Err(ref e) if e.is_unmapped()
                )
            });
            if !known {
                unknown.push(verb.clone());
            }
        }
        assert!(
            unknown.is_empty(),
            "the helper answers none of: {unknown:?}"
        );
    }

    #[test]
    fn repairing_without_an_env_file_says_what_is_missing() {
        // `ensure_env_file`. The operator running this is usually locked out
        // of the panel already; "not found. Run the installer first." is the
        // difference between that and a box that was never installed.
        let err = repair_firewall(None).unwrap_err().to_string();
        assert!(err.contains(ENV_PATH), "{err}");
        assert!(err.contains("installer"), "{err}");
    }

    #[test]
    fn a_corrupt_panel_port_stops_the_rebuild() {
        // The port is read and then unused - the chain is rebuilt from the
        // helper's own view of `.env`. Checking it here is what turns a
        // corrupt file into a message instead of a firewall rebuilt from a
        // file nobody has read.
        let dir = std::env::temp_dir().join(format!("repairfw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let env = dir.join(".env");

        for bad in [
            "PANEL_PORT=not-a-port\n",
            "PANEL_PORT=0\n",
            "PANEL_PORT=99999\n",
        ] {
            std::fs::write(&env, bad).expect("write");
            let err = repair_firewall(Some(&env)).unwrap_err().to_string();
            assert!(err.contains("Invalid panel port"), "{bad:?} gave {err}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_panel_port_falls_back_rather_than_failing() {
        // `env_get` returning nothing is a `.env` written before the key
        // existed, not a corrupt one. The bash defaults and carries on.
        let dir = std::env::temp_dir().join(format!("repairfw-dflt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let env = dir.join(".env");
        std::fs::write(&env, "SOMETHING_ELSE=1\n").expect("write");

        // It gets past the validation; whether the helper is reachable from a
        // test machine is not what this asserts.
        let out = repair_firewall(Some(&env));
        assert!(
            out.is_ok(),
            "a .env with no PANEL_PORT should use the default: {out:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_first_panel_port_wins() {
        // `awk '$1 == key { ...; exit }'` - the first match. The panel's own
        // loader takes the *last*, which is why `env_set` rewrites every copy
        // of a key rather than appending one.
        let dir = std::env::temp_dir().join(format!("repairfw-first-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let env = dir.join(".env");
        std::fs::write(&env, "PANEL_PORT=2222\nPANEL_PORT=not-a-port\n").expect("write");

        assert_eq!(env_value(&env, "PANEL_PORT").as_deref(), Some("2222"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_update_target_reaches_the_script_as_its_own_flag() {
        // The bash dropped these. `snpanel update --tag v1.2.3` asked about
        // "the latest vX.Y.Z release" and then installed it, because
        // `update|--update) run_panel_update ;;` has no `shift` and
        // `run_panel_update` has no `"$@"`.
        assert_eq!(UpdateTarget::Release.args(), vec!["--release"]);
        assert_eq!(
            UpdateTarget::Tag("v1.2.3".into()).args(),
            vec!["--tag", "v1.2.3"]
        );
        assert_eq!(
            UpdateTarget::Branch("main".into()).args(),
            vec!["--branch", "main"]
        );
    }

    #[test]
    fn the_question_names_what_will_happen() {
        // A prompt that says "release" before installing a branch is how an
        // operator confirms something they did not mean.
        assert!(UpdateTarget::Release.question().contains("release"));
        assert!(UpdateTarget::Tag("v9.9.9".into())
            .question()
            .contains("v9.9.9"));
        let branch = UpdateTarget::Branch("hotfix".into()).question();
        assert!(branch.contains("hotfix"), "{branch}");
        assert!(branch.contains("head"), "{branch}");
    }

    #[test]
    fn updating_without_the_script_says_so() {
        // Every box that installed from a release has it; one that copied the
        // binaries by hand may not.
        let err = run_update(UpdateTarget::Release).unwrap_err().to_string();
        assert!(err.contains(UPDATE_SCRIPT), "{err}");
    }

    #[test]
    fn changing_the_ip_needs_two_addresses_or_none() {
        // One address is the shape that could mean either, and this rewrites
        // every file on the box that records an address. The bash refuses it
        // and so does this.
        let err = change_ip(&["10.0.0.1".to_string()])
            .unwrap_err()
            .to_string();
        // The missing-script check comes first on a machine without it; on
        // one with it, the arity check does. Either way it must not run.
        assert!(
            err.contains("usage: snpanel change-ip") || err.contains(CHANGE_IP_SCRIPT),
            "{err}"
        );

        let err3 = change_ip(&["a".into(), "b".into(), "c".into()])
            .unwrap_err()
            .to_string();
        assert!(
            err3.contains("usage: snpanel change-ip") || err3.contains(CHANGE_IP_SCRIPT),
            "{err3}"
        );
    }

    #[test]
    fn the_change_ip_script_is_named_when_it_is_missing() {
        // `change_IP.sh` is not in the repository, so no release installs
        // this path. The message has to say which file and where from, or the
        // operator has nothing to act on.
        let err = change_ip(&["10.0.0.1".into(), "10.0.0.2".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains(CHANGE_IP_SCRIPT), "{err}");
        assert!(err.contains("change_IP.sh"), "{err}");
    }
}
