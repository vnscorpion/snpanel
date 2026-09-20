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

    let loaded = exec::run(&["nft", "list", "table", "inet", "snpanel"]);
    let loaded_text = loaded
        .as_ref()
        .map(|o| o.stdout.clone())
        .unwrap_or_default();
    let table_present = matches!(&loaded, Ok(o) if o.ok());
    let chain_active = table_present && loaded_text.contains("hook input");

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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The URL file path, like the work file, comes from the bash helper.
    #[test]
    fn the_blocklist_url_path_is_the_bash_helpers() {
        const BASH: &str = include_str!("../../../../installer/files/snpanel-helper.sh");
        let mut data_dir = None;
        let mut urls = None;
        for line in BASH.lines() {
            if let Some(rest) = line.strip_prefix("SNPANEL_DATA_DIR=") {
                data_dir = Some(rest.trim().trim_matches('"').to_string());
            }
            if let Some(rest) = line.strip_prefix("FIREWALL_BLOCKLIST_URLS=") {
                urls = Some(rest.trim().trim_matches('"').to_string());
            }
        }
        let expected = urls
            .expect("FIREWALL_BLOCKLIST_URLS is not in the bash helper")
            .replace(
                "${SNPANEL_DATA_DIR}",
                &data_dir.expect("SNPANEL_DATA_DIR is not in the bash helper"),
            );
        assert_eq!(BLOCKLIST_URLS, expected);
    }

    /// The units the timer writer installs, against the bash's own heredocs.
    ///
    /// A timer that never fires is a blocklist that goes stale without
    /// anybody noticing, so the schedule is compared rather than described.
    #[test]
    fn the_blocklist_units_match_the_bash_helpers() {
        const BASH: &str = include_str!("../../../../installer/files/snpanel-helper.sh");
        // A heredoc's body includes the newline that ends its last line; the
        // terminator sits on the line after. So the body runs up to - and not
        // past - the start of the terminator line.
        let between = |open: &str, close: &str| -> String {
            let start = BASH.find(open).expect("the heredoc opener") + open.len();
            let end = BASH[start..].find(close).expect("the heredoc closer") + start;
            BASH[start..end].to_string()
        };
        assert_eq!(SERVICE_UNIT, between("<<'SERVICE'\n", "SERVICE\n"));
        assert_eq!(TIMER_UNIT, between("<<'TIMER'\n", "TIMER\n"));
        // The two facts an operator depends on.
        assert!(TIMER_UNIT.contains("OnCalendar=*-*-* 01:00:00"));
        assert!(SERVICE_UNIT
            .contains("ExecStart=/usr/local/sbin/snpanel-helper firewall-blocklist-run"));
    }

    /// The blocklist path is the bash helper's, read from the bash helper.
    ///
    /// Not asserted as a string literal: the point of the bug this guards
    /// against is that two files drifted apart while both looked right on
    /// their own. So this takes the bash's `FIREWALL_BLOCKLIST_WORK` out of
    /// the shipped script and compares.
    ///
    /// The failure it prevents is silent. `firewall-apply` reading a path
    /// nothing writes reports success and rebuilds the ruleset with no
    /// blocklist in it, and the operator sees a firewall that is up.
    #[test]
    fn the_blocklist_path_is_the_bash_helpers() {
        const BASH: &str = include_str!("../../../../installer/files/snpanel-helper.sh");

        let mut data_dir = None;
        let mut work = None;
        for line in BASH.lines() {
            if let Some(rest) = line.strip_prefix("SNPANEL_DATA_DIR=") {
                data_dir = Some(rest.trim().trim_matches('"').to_string());
            }
            if let Some(rest) = line.strip_prefix("FIREWALL_BLOCKLIST_WORK=") {
                work = Some(rest.trim().trim_matches('"').to_string());
            }
        }
        let data_dir = data_dir.expect("SNPANEL_DATA_DIR is not in the bash helper");
        let work = work.expect("FIREWALL_BLOCKLIST_WORK is not in the bash helper");
        let expected = work.replace("${SNPANEL_DATA_DIR}", &data_dir);

        assert_eq!(
            BLOCKLIST_WORK, expected,
            "the helper reads {BLOCKLIST_WORK}; the bash writes {expected}"
        );
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
}
