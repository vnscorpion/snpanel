//! `ops::firewall` - the nftables backend.
//!
//! Plan Appendix B marks this ★: written new, not ported.
//!
//! The plan's reason - that `ipset` is deprecated on RHEL 10 - does not hold
//! up: `ipset` is packaged on AlmaLinux 10.2. What is missing there is legacy
//! `iptables`, which leaves only an nft translation shim. See the header of
//! `snpanel_osabi::firewall::nft` for the measured package list.
//!
//! What does *not* change is where the truth lives. `rules.tsv` stays the
//! source of truth (C13) and every apply rebuilds the entire ruleset from it.
//! That is what makes swapping the backend safe: there is no state hiding in
//! the running firewall to migrate, and a half-applied ruleset cannot exist
//! because `nft -f` is atomic.

use std::path::{Path, PathBuf};

use snpanel_core::IpOrCidr;
use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::firewall::{
    rules::{Action, FirewallRuleset, FirewallState},
    FirewallBackend, NftablesBackend,
};

use crate::exec;

/// Source: `FIREWALL_DIR` and friends in the bash helper.
pub const FIREWALL_DIR: &str = "/var/lib/snpanel/firewall";
pub const RULES_TSV: &str = "/var/lib/snpanel/firewall/rules.tsv";
pub const STATE_FILE: &str = "/var/lib/snpanel/firewall/state";
/// Where `firewall-blocklist-run` leaves the networks it downloaded.
///
/// This used to be `/var/lib/snpanel/firewall/blocklist.work`, which nothing
/// has ever written: the bash helper's `FIREWALL_BLOCKLIST_WORK` is the path
/// below, and `installer/rescue-firewall.sh` reads the same one. The
/// consequence was silent - `firewall-apply` rebuilt the ruleset without the
/// blocklist and reported success - and it stayed hidden because
/// `firewall-apply` has no Python caller; the panel reaches it through
/// `firewall-reload`, which fell through to the bash until that verb was
/// mapped.
///
/// `the_blocklist_path_is_the_bash_helpers` pins it to the bash's definition.
pub const BLOCKLIST_WORK: &str = "/var/lib/snpanel/firewall-blocklists.current";
/// Where the rendered ruleset is staged before `nft -f` reads it.
pub const RULESET_PATH: &str = "/run/snpanel/ruleset.nft";

/// Read everything the renderer needs off disk.
pub fn load_ruleset(panel_port: u16, ssh_ports: &[u16]) -> FirewallRuleset {
    let rules = std::fs::read_to_string(RULES_TSV)
        .map(|s| FirewallRuleset::parse_rules_tsv(&s))
        .unwrap_or_default();
    let state = std::fs::read_to_string(STATE_FILE)
        .map(|s| FirewallState::parse(&s))
        .unwrap_or(FirewallState::Enabled);

    let (v4, v6) = load_blocklist();

    FirewallRuleset {
        state,
        rules,
        protected_ports: FirewallRuleset::compute_protected_ports(ssh_ports, panel_port),
        blocklist_v4: v4,
        blocklist_v6: v6,
        // Always rendered: see FirewallRuleset::ipv6_enabled. `table inet`
        // carries v6 rules at no cost, and gating them would silently drop
        // existing v6 entries from rules.tsv.
        ipv6_enabled: true,
    }
}

/// Source: the URL blocklist split in `firewall_sync_sets` - v6 is anything
/// containing a colon, v4 is everything else.
fn load_blocklist() -> (Vec<IpOrCidr>, Vec<IpOrCidr>) {
    let Ok(text) = std::fs::read_to_string(BLOCKLIST_WORK) else {
        return (Vec::new(), Vec::new());
    };
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // A malformed entry is skipped rather than failing the whole apply: a
        // downloaded blocklist is third-party data and one bad line should not
        // leave the box with no firewall at all.
        let Ok(entry) = IpOrCidr::parse(line) else {
            continue;
        };
        if entry.is_ipv4() {
            v4.push(entry);
        } else {
            v6.push(entry);
        }
    }
    (v4, v6)
}

/// Render and load. This is `firewall-apply`.
pub fn apply(ruleset: &FirewallRuleset) -> HelperResponse {
    let backend = NftablesBackend;
    if !backend.is_available() {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            "nft is not installed (apt-get install nftables / dnf install nftables)",
        );
    }

    let rendered = backend.render(ruleset);

    if let Err(e) = stage(&rendered) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("staging the ruleset: {e}"),
        );
    }

    // Check before loading, so a renderer bug is a clean error rather than a
    // partially-applied firewall. `nft -f` is atomic, but --check also gives a
    // readable parse error.
    let checked = exec::run(&["nft", "--check", "-f", RULESET_PATH]);
    if !matches!(&checked, Ok(o) if o.ok()) {
        let mut resp = exec::respond("nft --check", checked);
        if let Some(err) = resp.error.as_mut() {
            err.message = format!("generated ruleset is invalid, not loading: {}", err.message);
        }
        return resp;
    }

    let loaded = exec::run(&["nft", "-f", RULESET_PATH]);
    let mut resp = exec::respond("nft -f", loaded);
    if resp.ok {
        // A ruleset lives in the running kernel only. Without the unit that
        // loads it at boot, every machine installed since the port came back
        // from its first reboot with no firewall at all, while the panel went
        // on saying "enabled".
        if let Err(e) = write_boot_unit() {
            resp.stdout
                .push_str(&format!("warning: the boot unit was not written: {e}\n"));
        }
        resp.data = Some(serde_json::json!({
            "rules": ruleset.rules.len(),
            "protected_ports": ruleset.protected_ports,
            "state": match ruleset.state {
                FirewallState::Enabled => "enabled",
                FirewallState::Disabled => "disabled",
            },
            "blocklist_v4": ruleset.blocklist_v4.len(),
            "blocklist_v6": ruleset.blocklist_v6.len(),
        }));
    }
    resp
}

/// Source: `firewall_write_boot_unit`.
pub const BOOT_UNIT_PATH: &str = "/etc/systemd/system/snpanel-firewall.service";

/// The unit that loads the ruleset at boot, before the network and nginx.
///
/// `SUDO_USER` because that is who the helper records as its caller when it
/// is run by hand; systemd runs it as root and nobody else.
pub const BOOT_UNIT: &str = "[Unit]
Description=SNPanel firewall (nftables)
After=network-pre.target
Wants=network-pre.target
Before=network.target nginx.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=SUDO_USER=snpanel
ExecStart=/usr/local/sbin/snpanel-helper firewall-apply
ExecStop=/usr/local/sbin/snpanel-helper firewall-flush

[Install]
WantedBy=multi-user.target
";

/// Write the boot unit when it differs, and enable it - not `--now`: the
/// ruleset was just loaded, and starting the unit would load it again.
fn write_boot_unit() -> Result<(), String> {
    let current = std::fs::read_to_string(BOOT_UNIT_PATH).unwrap_or_default();
    if current != BOOT_UNIT {
        super::nginx::write_atomic(
            std::path::Path::new(BOOT_UNIT_PATH),
            BOOT_UNIT.as_bytes(),
            0o644,
        )
        .map_err(|e| format!("writing {BOOT_UNIT_PATH}: {e}"))?;
        let _ = exec::run(&["systemctl", "daemon-reload"]);
    }
    let enabled = exec::run(&[
        "systemctl",
        "is-enabled",
        "--quiet",
        "snpanel-firewall.service",
    ]);
    if !matches!(&enabled, Ok(o) if o.ok()) {
        let out = exec::run(&["systemctl", "enable", "snpanel-firewall.service"]);
        if !matches!(&out, Ok(o) if o.ok()) {
            return Err("systemctl enable snpanel-firewall.service failed".to_string());
        }
    }
    Ok(())
}

/// Remove SNPanel's table entirely. This is `firewall-flush`, and it is what
/// `snpanel-rescue-firewall` calls on a box that has locked itself out.
///
/// Deleting the table takes the base chain with it, so the hook is gone and
/// nothing of SNPanel's remains in the path. Other tables are untouched.
pub fn flush() -> HelperResponse {
    // `nft delete table` fails when the table is absent, which is the desired
    // end state - so that case is success.
    let exists = exec::run(&["nft", "list", "table", "inet", "snpanel"]);
    if !matches!(&exists, Ok(o) if o.ok()) {
        return HelperResponse::with_stdout("no snpanel table loaded");
    }
    exec::respond(
        "nft delete table inet snpanel",
        exec::run(&["nft", "delete", "table", "inet", "snpanel"]),
    )
}

/// Whether SNPanel's table is loaded with its input hook - the difference
/// between a firewall that is configured and one that is enforcing.
/// `firewall-status` prints it; `firewall-list` reports it.
pub fn chain_active() -> bool {
    let loaded = exec::run(&["nft", "list", "table", "inet", "snpanel"]);
    matches!(&loaded, Ok(o) if o.ok() && o.stdout.contains("hook input"))
}

/// What is actually loaded right now, as text.
///
/// The output format is the bash `firewall_status`'s, line for line, because
/// the panel shows it **verbatim**: `services/firewall.py::status()` hands the
/// whole `CommandResult` back and `App.jsx` renders `firewallStatus.stdout` as
/// a text block.
///
/// An earlier version of this returned JSON here. That is NT1's exact failure
/// mode - an improvement nobody asked for, in a place with a contract - and
/// what the operator saw on the Firewall page was a JSON blob where the status
/// lines belong. Structured data is what `firewall-list` is for, and that is
/// the call the panel parses.
///
/// The one deliberate difference is the engine name: it really is nftables now.
pub fn status(ruleset: &FirewallRuleset) -> HelperResponse {
    use std::fmt::Write;

    let chain_active = chain_active();

    let mut out = String::with_capacity(1024);
    let state = match ruleset.state {
        FirewallState::Enabled => "enabled",
        FirewallState::Disabled => "disabled",
    };
    let protected: Vec<String> = ruleset.protected_ports.iter().map(u16::to_string).collect();

    let _ = writeln!(out, "Status: {state}");
    let _ = writeln!(out, "Engine: nftables");
    let _ = writeln!(
        out,
        "Chain active: {}",
        if chain_active { "yes" } else { "no" }
    );
    let _ = writeln!(
        out,
        "IPv6: {}",
        if ruleset.ipv6_enabled { "yes" } else { "no" }
    );
    let _ = writeln!(out, "Default incoming: deny (unlisted ports)");
    let _ = writeln!(out, "Protected ports (tcp): {}", protected.join(","));
    let _ = writeln!(out);
    let _ = writeln!(out, "Rules:");
    if ruleset.rules.is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        for r in &ruleset.rules {
            // Same columns and widths as the bash awk, so the page looks the
            // same after the swap as before it.
            let target = match r.port {
                Some(p) => format!("{}/{}", p, r.protocol),
                None => "any port".to_string(),
            };
            let src =
                r.ip.as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "any".into());
            let _ = writeln!(
                out,
                "  [{}] {:<5} {:<22} from {}",
                r.id,
                r.action.as_str().to_uppercase(),
                target,
                src
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Sets:");
    for (name, count) in [
        (
            "snpanel-allow4",
            ruleset.host_rules(Action::Allow, false).len(),
        ),
        (
            "snpanel-deny4",
            ruleset.host_rules(Action::Deny, false).len(),
        ),
        ("snpanel-block4", ruleset.blocklist_v4.len()),
        (
            "snpanel-allow6",
            ruleset.host_rules(Action::Allow, true).len(),
        ),
        (
            "snpanel-deny6",
            ruleset.host_rules(Action::Deny, true).len(),
        ),
        ("snpanel-block6", ruleset.blocklist_v6.len()),
    ] {
        let _ = writeln!(out, "  {name:<18} {count} entries");
    }

    HelperResponse::with_stdout(out)
}

fn stage(rendered: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let path = PathBuf::from(RULESET_PATH);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::File::create(&path)?;
    f.write_all(rendered.as_bytes())?;
    f.sync_all()?;
    // The ruleset names every allowed address; it is not secret, but it is not
    // the customers' business either.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Ensure the state directory exists with the permissions the bash uses.
/// Source: `ensure_firewall_dir`.
pub fn ensure_dir() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(FIREWALL_DIR)?;
    std::fs::set_permissions(FIREWALL_DIR, std::fs::Permissions::from_mode(0o750))?;
    if !Path::new(RULES_TSV).exists() {
        std::fs::write(RULES_TSV, "")?;
        std::fs::set_permissions(RULES_TSV, std::fs::Permissions::from_mode(0o640))?;
    }
    if !Path::new(STATE_FILE).exists() {
        std::fs::write(STATE_FILE, "enabled\n")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the downloaded IP blocklists
// ---------------------------------------------------------------------------

/// Source: `FIREWALL_BLOCKLIST_URLS`.
pub const BLOCKLIST_URLS: &str = "/var/lib/snpanel/firewall-blocklists.urls";

const BLOCKLIST_SERVICE: &str = "/etc/systemd/system/snpanel-blocklist.service";
const BLOCKLIST_TIMER: &str = "/etc/systemd/system/snpanel-blocklist.timer";
/// The units this replaced. They ran an nginx-era blocklist and are removed on
/// every write, because two timers refreshing the same file would race.
const LEGACY_SERVICE: &str = "/etc/systemd/system/snpanel-firewall-blocklist.service";
const LEGACY_TIMER: &str = "/etc/systemd/system/snpanel-firewall-blocklist.timer";

const SERVICE_UNIT: &str = "[Unit]\n\
Description=Refresh SNPanel IP blocklists (iptables + ipset)\n\
After=network-online.target snpanel-firewall.service\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n\
Environment=SUDO_USER=snpanel\n\
ExecStart=/usr/local/sbin/snpanel-helper firewall-blocklist-run\n";

const TIMER_UNIT: &str = "[Unit]\n\
Description=Refresh SNPanel IP blocklists daily\n\
\n\
[Timer]\n\
OnCalendar=*-*-* 01:00:00\n\
RandomizedDelaySec=1800\n\
Persistent=true\n\
\n\
[Install]\n\
WantedBy=timers.target\n";

/// Source: `require_url` - `^https?://[^[:space:]]+$`.
///
/// Deliberately narrow. This string ends up in a systemd-scheduled `curl` run
/// as root, so a scheme the helper does not understand - `file://`, say - must
/// not get that far.
fn valid_url(value: &str) -> bool {
    let rest = match value.strip_prefix("https://") {
        Some(rest) => rest,
        None => match value.strip_prefix("http://") {
            Some(rest) => rest,
            None => return false,
        },
    };
    !rest.is_empty() && !rest.chars().any(char::is_whitespace)
}

/// Source: `firewall_blocklist_urls` - blanks dropped, sorted, deduplicated.
pub fn blocklist_urls() -> Vec<String> {
    let text = std::fs::read_to_string(BLOCKLIST_URLS).unwrap_or_default();
    let mut urls: Vec<String> = text
        .lines()
        // `sed '/^[[:space:]]*$/d'` - a line of only whitespace is dropped;
        // one with content keeps its spacing, which `sort -u` then compares.
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect();
    urls.sort();
    urls.dedup();
    urls
}

fn write_urls(urls: &[String]) -> Result<(), HelperResponse> {
    if let Err(e) = std::fs::create_dir_all("/var/lib/snpanel") {
        return Err(HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating /var/lib/snpanel: {e}"),
        ));
    }
    let mut out = urls.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    std::fs::write(BLOCKLIST_URLS, out).map_err(|e| {
        HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {BLOCKLIST_URLS}: {e}"),
        )
    })
}

/// Source: `firewall_blocklist_write_timer`.
///
/// `daemon-reload` runs only when a unit file actually changed, which is why
/// the bash compares before installing: adding a URL is a cheap operation and
/// reloading systemd on every one of them is not.
fn write_timer() {
    let mut changed = false;
    for (path, body) in [
        (BLOCKLIST_SERVICE, SERVICE_UNIT),
        (BLOCKLIST_TIMER, TIMER_UNIT),
    ] {
        let current = std::fs::read_to_string(path).unwrap_or_default();
        if current != body && std::fs::write(path, body).is_ok() {
            changed = true;
        }
    }
    if Path::new(LEGACY_TIMER).exists() {
        let _ = exec::run(&[
            "systemctl",
            "disable",
            "--now",
            "snpanel-firewall-blocklist.timer",
        ]);
        let _ = std::fs::remove_file(LEGACY_SERVICE);
        let _ = std::fs::remove_file(LEGACY_TIMER);
        changed = true;
    }
    if changed {
        let _ = exec::run(&["systemctl", "daemon-reload"]);
    }
    // `|| true` in the bash: a box without systemd still gets the file.
    let _ = exec::run(&["systemctl", "enable", "--now", "snpanel-blocklist.timer"]);
}

/// `firewall-blocklist-timer-install`.
///
/// Source: the bash arm, which is `firewall_blocklist_write_timer` and a
/// line of output. `write_timer` already ran on every `blocklist_add`; the
/// installer calls this so a box that has never added a URL still gets the
/// units, and so an upgrade replaces the nginx-era pair.
pub fn blocklist_timer_install() -> HelperResponse {
    write_timer();
    HelperResponse::with_stdout("IP blocklist timer installed\n".to_string())
}

/// `firewall-blocklist-add`.
pub fn blocklist_add(url: &str) -> HelperResponse {
    if !valid_url(url) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, format!("invalid URL: {url}"));
    }
    let mut urls = blocklist_urls();
    // `grep -Fxq` - a whole-line, fixed-string match, so a URL that merely
    // contains another is a separate entry.
    if !urls.iter().any(|existing| existing == url) {
        urls.push(url.to_string());
    }
    urls.sort();
    urls.dedup();
    if let Err(resp) = write_urls(&urls) {
        return resp;
    }
    write_timer();
    HelperResponse::with_stdout("IP blocklist URL added\n".to_string())
}

/// `firewall-blocklist-delete`.
///
/// Removing a URL that is not there is a success, as it is in the bash: the
/// caller asked for it to be gone and it is.
pub fn blocklist_delete(url: &str) -> HelperResponse {
    if !valid_url(url) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, format!("invalid URL: {url}"));
    }
    let urls: Vec<String> = blocklist_urls()
        .into_iter()
        .filter(|existing| existing != url)
        .collect();
    if let Err(resp) = write_urls(&urls) {
        return resp;
    }
    write_timer();
    HelperResponse::with_stdout("IP blocklist URL removed\n".to_string())
}

/// Source: `re.split(r"[\s#;,]+", raw.strip(), 1)[0]` in `firewall_blocklist_run`.
///
/// Downloaded blocklists are not a format, they are a genre: bare addresses,
/// `1.2.3.0/24 # spammer`, semicolon comments, comma-separated rows, and
/// whole-line comments starting with `#`. Taking the first token of each line
/// is what reads all of them.
///
/// A line that *begins* with one of those separators yields an empty first
/// token, and an empty token is dropped - which is how `# header` and a blank
/// line both disappear without a special case.
pub(crate) fn first_token(raw: &str) -> &str {
    let trimmed = raw.trim();
    let end = trimmed
        .find(|c: char| c.is_whitespace() || c == '#' || c == ';' || c == ',')
        .unwrap_or(trimmed.len());
    &trimmed[..end]
}

/// Source: the `python3` heredoc in `firewall_blocklist_run`.
///
/// Order is preserved and duplicates are dropped on the **normalised** value,
/// so `1.2.3.4/24` and `1.2.3.0/24` collapse into one entry rather than two
/// that mean the same network. Porting this takes the last `python3` out of
/// the firewall path.
pub(crate) fn normalize_blocklist(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut networks = Vec::new();
    for raw in text.lines() {
        let token = first_token(raw);
        if token.is_empty() {
            continue;
        }
        // A line that is not an address is skipped, not refused: this is
        // third-party data fetched over the network and one bad row must not
        // cost the administrator the other two million.
        let Some(value) = snpanel_core::normalized_network(token) else {
            continue;
        };
        if seen.insert(value.clone()) {
            networks.push(value);
        }
    }
    networks
}

/// `firewall-blocklist-run`.
///
/// Fetch every configured list, normalise it, and reload the firewall with
/// the result. Run from `snpanel-blocklist.timer` at 01:00 as well as from
/// the panel button.
pub fn blocklist_run(panel_port: u16, ssh_ports: &[u16]) -> HelperResponse {
    if let Err(e) = ensure_dir() {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("preparing {FIREWALL_DIR}: {e}"),
        );
    }

    let mut fetched = String::new();
    let mut warnings = String::new();
    for url in blocklist_urls() {
        // `require_url` - the bash denies on a bad URL, aborting the whole
        // run rather than skipping the entry. A list nobody can name is a
        // configuration error, not a transient one.
        if !valid_url(&url) {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("invalid URL: {url}"),
            );
        }
        match exec::run(&[
            "curl",
            "-fsSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "60",
            &url,
        ]) {
            Ok(o) if o.ok() => fetched.push_str(&o.stdout),
            // `|| echo "WARNING: could not fetch $url" >&2` - one unreachable
            // list does not abort the refresh, because the others are still
            // worth loading and the timer will try again tomorrow.
            _ => warnings.push_str(&format!("WARNING: could not fetch {url}\n")),
        }
        // `printf '\n' >>"$fetched"` - a file that does not end in a newline
        // would otherwise glue its last address to the next list's first.
        fetched.push('\n');
    }

    let networks = normalize_blocklist(&fetched);
    let mut body = networks.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    // `install -m 0640 -o root -g root`: readable by root alone. It is not
    // secret, but it is the input to the packet filter and nothing else on
    // the box has any business writing it.
    if let Err(e) = std::fs::write(BLOCKLIST_WORK, &body) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {BLOCKLIST_WORK}: {e}"),
        );
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(BLOCKLIST_WORK, std::fs::Permissions::from_mode(0o640));
    }

    // Loaded *after* the write, so the ruleset carries the networks this run
    // just produced rather than the previous run's.
    let applied = apply(&load_ruleset(panel_port, ssh_ports));
    if !applied.ok {
        return applied;
    }
    write_timer();

    let count = networks.len();
    let mut out = warnings;
    out.push_str(&format!(
        "IP blocklist refreshed: {count} network(s) loaded into the nftables set\n"
    ));
    HelperResponse::with_stdout(out)
}

/// `firewall-blocklist-status`.
///
/// The section headers, and a few lines under them, are a contract with the
/// browser, not decoration. `parseBlocklistStatus` in
/// `frontend/src/pages/Firewall.jsx` treats a line like `URLs:` as a header,
/// then reads the `http` lines under `URLs:` (the list of lists), the
/// `snpanel-block4 N entries` and `snpanel-block6 N entries` lines under
/// `Sets:` (the networks blocked), and the first line under `Timer:` when it
/// is one lowercase word - `systemctl is-enabled`'s answer. Renaming a header
/// or reshaping one of those lines empties that part of the page while the
/// verb still looks like it answered.
///
/// The engine line is the one deliberate difference, as in
/// [`status`]: it really is nftables now, and saying "iptables + ipset"
/// because the bash did would be a fact about the machine that is not true.
pub fn blocklist_status(ruleset: &FirewallRuleset) -> HelperResponse {
    let networks: Vec<String> = std::fs::read_to_string(BLOCKLIST_WORK)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();

    let mut timer = String::new();
    if let Ok(o) = exec::run(&["systemctl", "is-enabled", "snpanel-blocklist.timer"]) {
        timer.push_str(&o.stdout);
    }
    if let Ok(o) = exec::run(&[
        "systemctl",
        "list-timers",
        "snpanel-blocklist.timer",
        "--no-pager",
    ]) {
        timer.push_str(&o.stdout);
    }

    HelperResponse::with_stdout(blocklist_status_lines(
        &blocklist_urls(),
        ruleset.blocklist_v4.len(),
        ruleset.blocklist_v6.len(),
        &networks,
        &timer,
    ))
}

/// The page itself, separated from the four things it reports, so a test can
/// drive it.
pub(crate) fn blocklist_status_lines(
    urls: &[String],
    v4: usize,
    v6: usize,
    networks: &[String],
    timer: &str,
) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(2048);

    let _ = writeln!(out, "URLs:");
    if urls.is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        for url in urls {
            let _ = writeln!(out, "  {url}");
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Engine:");
    let _ = writeln!(out, "  nftables");
    let _ = writeln!(out, "Sets:");
    let _ = writeln!(out, "  snpanel-block4      {v4} entries");
    // The bash prints this line only when `ip6tables -S INPUT` works. `table
    // inet` carries v6 unconditionally here, so the count is always real and
    // always shown; nothing parses it.
    let _ = writeln!(out, "  snpanel-block6      {v6} entries");

    let _ = writeln!(out);
    let _ = writeln!(out, "Networks:");
    if networks.is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        // 50, as the bash shows. A list with two million entries must not be
        // sent to a browser in full to answer "is it loaded?".
        const SHOWN: usize = 50;
        let total = networks.len();
        let _ = writeln!(out, "  {total} network(s), showing first {SHOWN}:");
        for network in networks.iter().take(SHOWN) {
            let _ = writeln!(out, "  {network}");
        }
        if total > SHOWN {
            let _ = writeln!(out, "  ... {} more", total - SHOWN);
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Timer:");
    out.push_str(timer);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What brings the firewall back at boot: the helper's own apply, before
    /// the network and nginx, and its flush when the unit is stopped.
    #[test]
    fn the_boot_unit_loads_the_ruleset_before_the_network() {
        assert!(BOOT_UNIT.contains("\nExecStart=/usr/local/sbin/snpanel-helper firewall-apply\n"));
        assert!(BOOT_UNIT.contains("\nExecStop=/usr/local/sbin/snpanel-helper firewall-flush\n"));
        assert!(BOOT_UNIT.contains("\nBefore=network.target nginx.service\n"));
        assert!(BOOT_UNIT.contains("\nType=oneshot\nRemainAfterExit=yes\n"));
        assert!(BOOT_UNIT.contains("\nWantedBy=multi-user.target\n"));
        assert_eq!(
            BOOT_UNIT_PATH,
            "/etc/systemd/system/snpanel-firewall.service"
        );
    }

    /// The URL check is `^https?://[^[:space:]]+$` and nothing more.
    ///
    /// This string ends up in a systemd-scheduled `curl` run as root, so a
    /// scheme the helper does not understand must not get that far. It is also
    /// deliberately not a URL grammar: tightening it here would refuse lists
    /// the panel already has.
    #[test]
    fn a_blocklist_url_has_to_be_http_or_https_with_no_whitespace() {
        for good in [
            "http://example.com/list.txt",
            "https://example.com/list.txt",
            "https://example.com/a?b=c&d=e#f",
            "http://1.2.3.4:8080/x",
        ] {
            assert!(valid_url(good), "{good} should be accepted");
        }
        for bad in [
            "",
            "example.com/list.txt",
            "ftp://example.com/list.txt",
            "file:///etc/passwd",
            "https://",
            "http://",
            "https://example.com/ list.txt",
            "https://example.com/list.txt\n",
            " https://example.com/list.txt",
            "HTTPS://example.com/list.txt",
        ] {
            assert!(!valid_url(bad), "{bad:?} should be refused");
        }
    }

    /// Adding and removing a URL, against a real file.
    ///
    /// The list is sorted and deduplicated on every write, which is what makes
    /// "already there" a no-op rather than a second entry - and the match is a
    /// whole line, so one URL that contains another is still two entries.
    #[test]
    fn the_url_list_is_sorted_deduplicated_and_matched_whole() {
        let dir = std::env::temp_dir().join(format!("blocklist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the temp dir");
        let file = dir.join("urls");

        let write = |lines: &[&str]| {
            let mut text = lines.join("\n");
            if !text.is_empty() {
                text.push('\n');
            }
            std::fs::write(&file, text).expect("the list");
        };
        let read_back = |path: &std::path::Path| -> Vec<String> {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            let mut urls: Vec<String> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(str::to_string)
                .collect();
            urls.sort();
            urls.dedup();
            urls
        };

        // Blank lines are dropped; the rest is sorted and deduplicated.
        write(&[
            "https://b.example/list",
            "",
            "https://a.example/list",
            "   ",
            "https://b.example/list",
        ]);
        assert_eq!(
            read_back(&file),
            vec![
                "https://a.example/list".to_string(),
                "https://b.example/list".to_string()
            ]
        );

        // A URL that contains another is a separate entry, because the match
        // is a whole line.
        write(&["https://a.example/list", "https://a.example/list2"]);
        assert_eq!(read_back(&file).len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The three paths the blocklist uses, and the units that refresh it.
    ///
    /// These were compared against the bash helper, which wrote the same
    /// files: the bug they guard is that a writer and a reader drift apart
    /// while each looks right on its own, and `firewall-apply` reading a path
    /// nothing writes reports success with no blocklist in the ruleset.
    ///
    /// With the bash gone there is one writer and one reader and the drift
    /// cannot happen, so what is left is the part an operator depends on: the
    /// units fire, and they name a directory that exists.
    #[test]
    fn the_blocklist_files_live_under_the_data_directory() {
        for path in [BLOCKLIST_URLS, BLOCKLIST_WORK] {
            assert!(
                path.starts_with("/var/lib/snpanel/"),
                "{path} is outside the data directory"
            );
        }
        assert_ne!(BLOCKLIST_URLS, BLOCKLIST_WORK);
    }

    /// The schedule is compared rather than described: a timer that never
    /// fires is a blocklist that goes stale without anybody noticing.
    #[test]
    fn the_blocklist_units_say_when_and_what() {
        assert!(TIMER_UNIT.contains("OnCalendar=*-*-* 01:00:00"));
        assert!(TIMER_UNIT.contains("[Install]\nWantedBy=timers.target"));
        assert!(TIMER_UNIT.contains("Persistent=true"));
        assert!(SERVICE_UNIT
            .contains("ExecStart=/usr/local/sbin/snpanel-helper firewall-blocklist-run"));
        // The helper refuses a call it cannot attribute, and a timer has no
        // sudo to set this.
        assert!(SERVICE_UNIT.contains("Environment=SUDO_USER=snpanel"));
    }

    #[test]
    fn a_missing_rules_file_yields_an_empty_ruleset_not_a_panic() {
        // A box mid-install has no rules.tsv yet.
        let rs = load_ruleset(2222, &[22]);
        assert!(rs.protected_ports.contains(&2222));
        assert!(rs.protected_ports.contains(&22));
    }

    #[test]
    fn the_protected_set_always_carries_ssh_and_the_panel() {
        let rs = load_ruleset(8443, &[2200]);
        assert!(rs.protected_ports.contains(&8443), "locking out the panel");
        assert!(rs.protected_ports.contains(&2200), "locking out SSH");
        for standard in [80, 443, 465, 587] {
            assert!(rs.protected_ports.contains(&standard));
        }
    }

    #[test]
    fn a_malformed_blocklist_line_is_skipped_not_fatal() {
        // Third-party data. One bad line must not leave the box unprotected.
        let dir = std::env::temp_dir().join(format!("snpanel-fw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("blocklist.work");
        std::fs::write(
            &f,
            "1.2.3.0/24\nnot-an-address\n\n2001:db8::/32\n<html>error</html>\n",
        )
        .unwrap();

        // Exercise the same parsing the loader does.
        let mut v4 = 0;
        let mut v6 = 0;
        for line in std::fs::read_to_string(&f).unwrap().lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(e) = IpOrCidr::parse(line) {
                if e.is_ipv4() {
                    v4 += 1
                } else {
                    v6 += 1
                }
            }
        }
        assert_eq!((v4, v6), (1, 1));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_emits_the_text_shape_the_panel_renders() {
        // App.jsx shows firewallStatus.stdout as a text block, so these lines
        // ARE the contract. Returning JSON here put a JSON blob on the
        // Firewall page - the NT1 failure this test now prevents.
        let rs = FirewallRuleset {
            rules: FirewallRuleset::parse_rules_tsv(
                "1\tallow\t203.0.113.4/32\t\ttcp\n2\tdeny\t10.0.0.0/8\t3306\ttcp\n",
            ),
            protected_ports: FirewallRuleset::compute_protected_ports(&[22], 2222),
            ..Default::default()
        };
        let out = status(&rs);
        assert!(out.ok);
        let text = &out.stdout;
        assert!(
            out.data.is_none(),
            "no JSON here; firewall-list is the structured call"
        );

        for line in [
            "Status: enabled",
            "Engine: nftables",
            "Default incoming: deny (unlisted ports)",
            "Protected ports (tcp): 22,80,443,465,587,2222",
            "Rules:",
            "Sets:",
        ] {
            assert!(text.contains(line), "missing {line:?} in:\n{text}");
        }
        // The rule lines keep the bash's column layout.
        assert!(text.contains("[1] ALLOW any port"), "in:\n{text}");
        assert!(text.contains("from 203.0.113.4/32"), "in:\n{text}");
        assert!(text.contains("[2] DENY  3306/tcp"), "in:\n{text}");
    }

    #[test]
    fn status_says_none_rather_than_nothing_when_there_are_no_rules() {
        let out = status(&FirewallRuleset::default());
        assert!(out.stdout.contains("  (none)"));
    }

    #[test]
    fn the_staged_ruleset_is_valid_nft_syntax() {
        // Not asserting on the kernel here - just that what apply() would hand
        // to nft parses as a ruleset and keeps its braces balanced.
        let rs = load_ruleset(2222, &[22]);
        let rendered = NftablesBackend.render(&rs);
        assert!(rendered.contains("table inet snpanel"));
        assert_eq!(rendered.matches('{').count(), rendered.matches('}').count());
    }

    /// `normalize_blocklist` against the bash helper's own `python3` block,
    /// over whole files rather than single addresses.
    ///
    /// The fixture was produced by extracting the heredoc out of
    /// `firewall_blocklist_run` and running it, so it covers the splitting,
    /// the ordering and the de-duplication as well as the normalisation -
    /// and covers them on the shapes a downloaded list really arrives in:
    /// hash and semicolon comments, comma-separated rows, CRLF, an HTML error
    /// page served instead of a list, and two lists concatenated.
    #[test]
    fn a_blocklist_normalizes_exactly_as_the_bash_helper_does() {
        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            input: String,
            output: Vec<String>,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/blocklist_normalize.json");
        let raw = std::fs::read_to_string(&path).expect("the blocklist corpus");
        let cases: Vec<Case> = serde_json::from_str(&raw).expect("the corpus parses");
        assert!(cases.len() >= 20, "the corpus is {} cases", cases.len());

        for case in &cases {
            let got = normalize_blocklist(&case.input);
            // The one deliberate difference, and the only case that carries
            // it: CPython keeps `fe80::1%eth0/128`, which is not a string
            // `nft` will load, so the bash writes an entry that fails where
            // it is used. Dropping it is the safer disagreement, and a
            // link-local address is never routed anyway.
            let expected: Vec<String> = if case.name == "ipv6 scoped" {
                case.output
                    .iter()
                    .filter(|n| !n.contains('%'))
                    .cloned()
                    .collect()
            } else {
                assert!(
                    !case.output.iter().any(|n| n.contains('%')),
                    "{}: a second scoped case appeared and needs deciding on, not \
                     silently passing",
                    case.name
                );
                case.output.clone()
            };
            assert_eq!(got, expected, "case {:?}", case.name);
        }

        // A corpus of nothing but empty expectations would satisfy every
        // assertion above.
        let produced: usize = cases.iter().map(|c| c.output.len()).sum();
        assert!(produced > 30, "the corpus only expects {produced} networks");
    }

    /// `re.split(r"[\s#;,]+", raw.strip(), 1)[0]`.
    ///
    /// Downloaded lists are a genre, not a format. The first token is what
    /// reads all of them, and a line beginning with a separator yields an
    /// empty token - which is how `# header` disappears without a rule of
    /// its own.
    #[test]
    fn the_first_token_is_what_a_blocklist_line_means() {
        assert_eq!(first_token("1.2.3.4"), "1.2.3.4");
        assert_eq!(first_token("  1.2.3.4  "), "1.2.3.4");
        assert_eq!(first_token("1.2.3.4 # a spammer"), "1.2.3.4");
        assert_eq!(first_token("1.2.3.4#nospace"), "1.2.3.4");
        assert_eq!(first_token("1.2.3.4;note"), "1.2.3.4");
        assert_eq!(first_token("1.2.3.4,2024-01-01"), "1.2.3.4");
        assert_eq!(first_token("1.2.3.4\tbad"), "1.2.3.4");
        assert_eq!(first_token("1.2.3.4\r"), "1.2.3.4");

        // Leading separators leave nothing, which is what drops the line.
        assert_eq!(first_token("# header"), "");
        assert_eq!(first_token("#1.2.3.4"), "");
        assert_eq!(first_token(";1.2.3.4"), "");
        assert_eq!(first_token(",1.2.3.4"), "");
        assert_eq!(first_token(""), "");
        assert_eq!(first_token("   "), "");
    }

    /// De-duplication happens on the **normalised** value.
    ///
    /// `1.2.3.0/24` and `1.2.3.99/24` are the same network written two ways.
    /// Comparing the raw text would load it twice; comparing after
    /// normalisation is what makes the set what it claims to be.
    #[test]
    fn two_spellings_of_one_network_load_once() {
        let got = normalize_blocklist("1.2.3.0/24\n1.2.3.99/24\n1.2.3.4/255.255.255.0\n");
        assert_eq!(got, vec!["1.2.3.0/24"]);

        // And order is the order of first appearance, not sorted.
        let got = normalize_blocklist("9.9.9.9\n1.1.1.1\n9.9.9.9\n");
        assert_eq!(got, vec!["9.9.9.9/32", "1.1.1.1/32"]);
    }

    /// An HTML error page is a list of no networks, not an error.
    ///
    /// A mirror that answers 200 with a "service unavailable" page is the
    /// normal failure, and `curl -f` does not catch it. Every line fails to
    /// parse and the result is empty - which leaves the previous blocklist
    /// replaced by nothing, so this is worth seeing rather than assuming.
    #[test]
    fn a_page_of_html_yields_no_networks() {
        let html = "<!DOCTYPE html>\n<html><head><title>404</title></head>\n\
                    <body>Not Found</body></html>\n";
        assert!(normalize_blocklist(html).is_empty());
        // One good line among the noise still survives, which is the property
        // that lets a partly-corrupt list stay useful.
        assert_eq!(
            normalize_blocklist("<html>\n1.2.3.4\n</html>\n"),
            vec!["1.2.3.4/32"]
        );
    }

    /// What `firewall-blocklist-status` writes is read by the browser, not
    /// just displayed.
    ///
    /// `parseBlocklistStatus` in `frontend/src/pages/Firewall.jsx` takes a
    /// line like `URLs:` for a header, and reads the `http` lines under
    /// `URLs:`, the `snpanel-block4`/`snpanel-block6` sizes under `Sets:`, and
    /// the first line under `Timer:` if it is one lowercase word. `parse` here
    /// is that function; `urls` below is what it did before the page read the
    /// other two.
    #[test]
    fn the_blocklist_status_headers_are_what_the_browser_parses() {
        struct Parsed {
            urls: Vec<String>,
            blocked: Option<u64>,
            timer: Option<String>,
        }

        /// `parseBlocklistStatus`, in its effects.
        fn parse_all(text: &str) -> Parsed {
            let is_header = |line: &str| {
                let Some(name) = line.strip_suffix(':') else {
                    return false;
                };
                let mut chars = name.chars();
                chars.next().is_some_and(|c| c.is_ascii_uppercase())
                    && chars.all(|c| c.is_ascii_alphabetic() || c == ' ')
            };
            let mut out = Parsed {
                urls: Vec::new(),
                blocked: None,
                timer: None,
            };
            let mut section = "";
            for raw in text.lines() {
                let line = raw.trim();
                if is_header(line) {
                    section = &line[..line.len() - 1];
                    continue;
                }
                let lower = line.to_ascii_lowercase();
                if section == "URLs"
                    && (lower.starts_with("http://") || lower.starts_with("https://"))
                {
                    out.urls.push(line.to_string());
                }
                if section == "Sets" {
                    let count = ["snpanel-block4", "snpanel-block6"]
                        .iter()
                        .find_map(|set| line.strip_prefix(set))
                        .filter(|rest| rest.starts_with(char::is_whitespace))
                        .and_then(|rest| rest.trim_start().strip_suffix(" entries"))
                        .and_then(|n| n.parse::<u64>().ok());
                    if let Some(n) = count {
                        out.blocked = Some(out.blocked.unwrap_or(0) + n);
                    }
                }
                if section == "Timer"
                    && out.timer.is_none()
                    && !line.is_empty()
                    && line.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                {
                    out.timer = Some(line.to_string());
                }
            }
            out
        }
        fn parse(text: &str) -> Vec<String> {
            parse_all(text).urls
        }

        // The real formatter, not a sample written here: this test used to
        // parse a literal of its own and so proved nothing about the verb.
        let urls = vec![
            "https://example.com/drop.txt".to_string(),
            "http://lists.example.org/bad.txt".to_string(),
        ];
        let networks: Vec<String> = (0..60).map(|i| format!("10.0.{i}.0/24")).collect();
        let page = blocklist_status_lines(&urls, 3, 0, &networks, "enabled\n");

        assert_eq!(
            parse(&page),
            vec![
                "https://example.com/drop.txt",
                "http://lists.example.org/bad.txt"
            ],
            "page was:\n{page}"
        );

        // The headers the browser keys on, each on a line of its own.
        for header in ["URLs:", "Sets:", "Networks:", "Timer:"] {
            assert!(
                page.lines().any(|l| l.trim() == header),
                "{header} is missing from:\n{page}"
            );
        }

        // The two facts under the list: networks blocked, and the timer.
        let facts = parse_all(&page);
        assert_eq!(facts.blocked, Some(3), "v4 3 + v6 0, from:\n{page}");
        assert_eq!(facts.timer.as_deref(), Some("enabled"), "{page}");
        let v6 = parse_all(&blocklist_status_lines(&[], 3, 4, &[], "disabled\n"));
        assert_eq!(v6.blocked, Some(7));
        assert_eq!(v6.timer.as_deref(), Some("disabled"));
        // A timer unit that does not exist: is-enabled prints nothing, and
        // the list-timers table must not be taken for its answer.
        let no_unit = parse_all(&blocklist_status_lines(
            &[],
            0,
            0,
            &[],
            "NEXT LEFT LAST PASSED UNIT ACTIVATES\n\n0 timers listed.\n",
        ));
        assert_eq!(no_unit.timer, None);

        // 50 shown, the rest counted - a list of two million must not be sent
        // to a browser in full to answer "is it loaded?".
        assert!(page.contains("60 network(s), showing first 50:"), "{page}");
        assert!(page.contains("10.0.49.0/24"), "the 50th is shown");
        assert!(!page.contains("10.0.50.0/24"), "the 51st is not");
        assert!(page.contains("... 10 more"), "{page}");

        // Nothing configured: the placeholders must not parse as URLs, and
        // every header must still be there for the parser to find.
        let empty = blocklist_status_lines(&[], 0, 0, &[], "");
        assert!(parse(&empty).is_empty());
        assert_eq!(
            parse_all(&empty).blocked,
            Some(0),
            "zero is said, not left out"
        );
        assert_eq!(parse_all(&empty).timer, None);
        for header in ["URLs:", "Sets:", "Networks:", "Timer:"] {
            assert!(
                empty.lines().any(|l| l.trim() == header),
                "{header}: {empty}"
            );
        }
        assert_eq!(empty.matches("  (none)").count(), 2, "{empty}");

        // Renaming a header is what would empty the table in the panel while
        // the verb still looked like it answered.
        let renamed = page.replace("URLs:", "Blocklist URLs:");
        assert!(parse(&renamed).is_empty());
    }
}
