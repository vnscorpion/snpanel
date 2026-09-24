//! `ops::fwmigrate` - the one-way move off UFW.
//!
//! Source: `firewall_migrate`, `firewall_import_ufw_rules`,
//! `firewall_purge_ufw` and `firewall_purge_nginx_blocklist`.
//!
//! Distinct from `FirewallMigrateNft`, which moves an already-SNPanel-managed
//! box from the iptables backend to nft. This one is about the box that
//! arrived with UFW enforcing and an nginx geo-map blocking addresses, and it
//! runs once, from the installer.
//!
//! The ordering is the whole of the safety here. Rules are read out of UFW and
//! written into `rules.tsv` **before** UFW is disabled, and the new ruleset is
//! applied **after**. A box whose administrator reaches it over a non-standard
//! SSH port has that port in UFW and nowhere else; losing it between the two
//! firewalls is losing the box.
//!
//! The bash shells out to an embedded `python3` to read `ufw status numbered`.
//! That parser is [`parse_status`] here, which is the last `python3` the
//! helper ran.

use snpanel_core::{IpOrCidr, Port};
use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::firewall::rules::{Action, FirewallRuleset, FirewallState, Protocol};

use super::firewall::{self, BLOCKLIST_URLS, STATE_FILE};
use super::{fwrules, runtime, Context};
use crate::exec;

const NGINX_CONF_DIR: &str = "/etc/nginx/conf.d";
const NGINX_SNPANEL_DIR: &str = "/etc/nginx/snpanel";
const BLOCKLIST_CONF: &str = "/etc/nginx/conf.d/snpanel-ip-blocklist.conf";
const BLOCKLIST_RULES: &str = "/etc/nginx/snpanel/ip-blocklist-geo.conf";
const BLOCKLIST_SERVER_CONF: &str = "/etc/nginx/snpanel/ip-blocklist-server.conf";

/// Source: the here-document of `firewall_purge_nginx_blocklist`.
///
/// The file is emptied rather than deleted: a vhost an administrator wrote by
/// hand may still `include` it, and a missing include is an nginx that will
/// not start.
const EMPTY_SERVER_CONF: &str =
    "# Managed by SNPanel. IP blocking moved to iptables + ipset; this file is kept\n\
     # empty so older vhosts that still include it keep loading.\n";

// ---------------------------------------------------------------------------
// reading `ufw status numbered`
// ---------------------------------------------------------------------------

/// One importable rule, as the bash's Python prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UfwRule {
    /// `allow` or `deny`, lowercased as the Python lowercases it.
    pub action: Action,
    /// Empty for "Anywhere".
    pub source: String,
    /// Empty when the target was a bare `Anywhere`.
    pub port: String,
    pub protocol: Protocol,
}

/// Split a line into `(target, action, direction, source)`.
///
/// Source: the Python
/// `^(?:\[\s*\d+\]\s*)?(.+?)\s{2,}(ALLOW|DENY)(?:\s+(IN|OUT))?\s{2,}(.+?)\s*$`,
/// case-insensitive.
///
/// `(.+?)` is non-greedy, so the leftmost target that lets the rest of the
/// pattern match is the one taken - which is why this tries split points in
/// increasing order and returns the first that parses to the end of the line,
/// rather than searching for the first `ALLOW`. A source such as `INTERNAL`
/// otherwise reads as the direction `IN` followed by `TERNAL`.
fn split_line(line: &str) -> Option<(String, &str, &str, String)> {
    let s = line.trim_end();
    let body = strip_numbered_prefix(s);
    let bytes = body.as_bytes();

    // The target needs at least one character, so a split point cannot be 0.
    for i in 1..bytes.len() {
        if !bytes[i].is_ascii_whitespace() {
            continue;
        }
        let gap_end = run_of_whitespace(bytes, i);
        if gap_end - i < 2 {
            continue;
        }
        let Some((action, after_action)) = keyword(&body[gap_end..], &["ALLOW", "DENY"]) else {
            continue;
        };
        // `(?:\s+(IN|OUT))?` - taken when it is there, skipped when taking it
        // would make the `\s{2,}` after it fail.
        for direction in directions(after_action) {
            let (dir, after_dir) = direction;
            let rest_bytes = after_dir.as_bytes();
            if rest_bytes.is_empty() || !rest_bytes[0].is_ascii_whitespace() {
                continue;
            }
            let end = run_of_whitespace(rest_bytes, 0);
            if end < 2 {
                continue;
            }
            let source = after_dir[end..].trim();
            // `(.+?)` - a rule with no source column is not a rule.
            if source.is_empty() {
                continue;
            }
            return Some((body[..i].trim().to_string(), action, dir, source.to_string()));
        }
    }
    None
}

/// `(?:\[\s*\d+\]\s*)?` - the `[ 1]` that `numbered` prepends.
fn strip_numbered_prefix(s: &str) -> &str {
    let Some(rest) = s.strip_prefix('[') else {
        return s;
    };
    let rest = rest.trim_start();
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return s;
    }
    match rest[digits..].strip_prefix(']') {
        Some(after) => after.trim_start(),
        None => s,
    }
}

fn run_of_whitespace(bytes: &[u8], from: usize) -> usize {
    let mut end = from;
    while end < bytes.len() && bytes[end].is_ascii_whitespace() {
        end += 1;
    }
    end
}

/// Match one of `words` case-insensitively at the start of `s`.
fn keyword<'a>(s: &'a str, words: &[&'static str]) -> Option<(&'static str, &'a str)> {
    for word in words {
        if s.len() >= word.len() && s[..word.len()].eq_ignore_ascii_case(word) {
            return Some((word, &s[word.len()..]));
        }
    }
    None
}

/// The two ways the optional direction group can resolve, in the order the
/// regex tries them: taken first, then skipped.
fn directions(after_action: &str) -> Vec<(&'static str, &str)> {
    let mut options: Vec<(&'static str, &str)> = Vec::new();
    let bytes = after_action.as_bytes();
    if !bytes.is_empty() && bytes[0].is_ascii_whitespace() {
        let end = run_of_whitespace(bytes, 0);
        if let Some((dir, rest)) = keyword(&after_action[end..], &["IN", "OUT"]) {
            options.push((dir, rest));
        }
    }
    options.push(("IN", after_action));
    options
}

/// `re.sub(r"\s*#.*$", "", source).strip()`.
fn strip_comment(source: &str) -> &str {
    match source.find('#') {
        Some(i) => source[..i].trim(),
        None => source.trim(),
    }
}

/// `^(\d{1,5})(?:/(tcp|udp))?$`.
fn parse_target(target: &str) -> Option<(String, Protocol)> {
    let (digits, protocol) = match target.split_once('/') {
        Some((d, "tcp")) => (d, Protocol::Tcp),
        Some((d, "udp")) => (d, Protocol::Udp),
        Some(_) => return None,
        None => (target, Protocol::Tcp),
    };
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((digits.to_string(), protocol))
}

/// Source: the embedded Python of `firewall_import_ufw_rules`.
///
/// Everything it skips is skipped here for the reason its comment gives: an
/// application profile (`Nginx Full`), a port range, a v6 duplicate or an
/// `OUT` rule does not become a single rule in the new chain, and the ports
/// those profiles cover are protected ports there anyway.
pub fn parse_status(text: &str) -> Vec<UfwRule> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let Some((target, action, direction, source)) = split_line(raw) else {
            continue;
        };
        if direction != "IN" {
            continue;
        }
        let source = strip_comment(&source);
        if target.contains("(v6)") || source.contains("(v6)") {
            continue;
        }
        let source = if source.len() >= "anywhere".len()
            && source[.."anywhere".len()].eq_ignore_ascii_case("anywhere")
        {
            ""
        } else {
            source
        };

        let (port, protocol) = match parse_target(&target) {
            Some(found) => found,
            // `elif target.lower() != "anywhere": continue`
            None if target.eq_ignore_ascii_case("anywhere") => (String::new(), Protocol::Tcp),
            None => continue,
        };
        if port.is_empty() && source.is_empty() {
            continue;
        }
        out.push(UfwRule {
            action: if action.eq_ignore_ascii_case("deny") {
                Action::Deny
            } else {
                Action::Allow
            },
            source: source.to_string(),
            port,
            protocol,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// the migration
// ---------------------------------------------------------------------------

/// Source: `firewall_import_ufw_rules`. Returns how many rules landed.
fn import_ufw_rules(ctx: &Context) -> u32 {
    if !runtime::have("ufw") {
        return 0;
    }
    let Ok(out) = exec::run(&["ufw", "status", "numbered"]) else {
        return 0;
    };
    let protected = FirewallRuleset::compute_protected_ports(&ctx.ssh_ports, ctx.panel_port);

    let mut imported = 0;
    for rule in parse_status(&out.stdout) {
        // A whole-host rule for a port the new chain protects already is
        // skipped rather than recorded: recording it would put a rule in
        // `rules.tsv` that the panel then offers to delete, and deleting it
        // would not close the port.
        if rule.source.is_empty() && !rule.port.is_empty() {
            if let Ok(p) = rule.port.parse::<u16>() {
                if protected.contains(&p) {
                    continue;
                }
            }
        }
        let ip = match rule.source.as_str() {
            "" => None,
            raw => match IpOrCidr::parse(raw) {
                Ok(ip) => Some(ip),
                // The bash runs `firewall_add_rule` in a subshell precisely so
                // its `deny` on bad input kills the subshell and not the
                // migration. An address UFW printed that this cannot parse is
                // one rule lost, not a failed migration.
                Err(_) => continue,
            },
        };
        let port = match rule.port.as_str() {
            "" => None,
            raw => match Port::parse(raw) {
                Ok(p) => Some(p),
                Err(_) => continue,
            },
        };
        if fwrules::add_rule(ctx, rule.action, ip.as_ref(), port, rule.protocol).ok {
            imported += 1;
        }
    }
    imported
}

/// Source: `firewall_purge_ufw`.
///
/// Every step ends in `|| true` in the bash and every step is ignored here.
/// UFW is being taken out of service, and a box where `apt-get purge` fails
/// because another package holds the lock is still a box whose UFW is
/// disabled and masked.
fn purge_ufw(out: &mut String) {
    if !runtime::have("ufw") {
        return;
    }
    out.push_str("Removing UFW ...\n");
    let _ = exec::run(&["ufw", "--force", "disable"]);
    let _ = exec::run(&["ufw", "--force", "reset"]);
    let _ = exec::run(&["systemctl", "disable", "--now", "ufw"]);
    let _ = exec::run(&["systemctl", "mask", "ufw"]);
    let _ = exec::run_with_env(
        &["apt-get", "purge", "-y", "ufw"],
        &[("DEBIAN_FRONTEND", "noninteractive")],
    );
    let _ = std::fs::remove_dir_all("/etc/ufw");
    let _ = std::fs::remove_dir_all("/lib/ufw");
    let _ = std::fs::remove_file("/etc/systemd/system/snpanel-firewall-blocklist.service");
    let _ = std::fs::remove_file("/etc/systemd/system/snpanel-firewall-blocklist.timer");
    let _ = exec::run(&["systemctl", "daemon-reload"]);
}

/// Source: `firewall_purge_nginx_blocklist`.
///
/// nginx is reloaded only when something changed **and** `nginx -t` passes.
/// Reloading a configuration that does not parse is how a blocklist migration
/// takes the websites down.
fn purge_nginx_blocklist() {
    let _ = exec::run(&[
        "install", "-d", "-o", "root", "-g", "root", "-m", "0755", NGINX_SNPANEL_DIR,
    ]);
    let _ = std::fs::write(BLOCKLIST_SERVER_CONF, EMPTY_SERVER_CONF);
    let _ = exec::run(&["chown", "root:root", BLOCKLIST_SERVER_CONF]);
    let _ = exec::run(&["chmod", "0644", BLOCKLIST_SERVER_CONF]);

    let mut changed = false;
    if let Ok(entries) = std::fs::read_dir(NGINX_CONF_DIR) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("conf") || !path.is_file() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if !text.contains("ip-blocklist-server.conf") {
                continue;
            }
            // `sed -i '/ip-blocklist-server\.conf/d'` - the whole line goes.
            let kept = strip_include_lines(&text);
            if std::fs::write(&path, kept).is_ok() {
                changed = true;
            }
        }
    }
    for path in [BLOCKLIST_CONF, BLOCKLIST_RULES] {
        if std::path::Path::new(path).exists() {
            changed = true;
        }
        let _ = std::fs::remove_file(path);
    }
    if changed && exec::run(&["nginx", "-t"]).is_ok_and(|o| o.ok()) {
        let _ = exec::run(&["systemctl", "reload", "nginx"]);
    }
}

/// `sed -i '/ip-blocklist-server\.conf/d'`.
///
/// `sed` writes a trailing newline after the last line it keeps, so a file
/// that did not end in one gains it. That is what the bash does and files
/// under `conf.d` all end in a newline anyway.
pub fn strip_include_lines(text: &str) -> String {
    text.lines()
        .filter(|l| !l.contains("ip-blocklist-server.conf"))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Was something already enforcing traffic before this ran?
///
/// Source: the `first_run` block of `firewall_migrate`, comment and all: a box
/// with no active firewall must not be switched to default-deny, because
/// SNPanel does not know about its mail server, its game server or its
/// custom daemons - but a box with blocklist URLs was relying on IP blocking
/// through nginx, and that has to keep working.
fn was_enforcing() -> bool {
    if runtime::have("ufw") {
        let active = exec::run(&["ufw", "status"])
            .ok()
            .and_then(|o| o.stdout.lines().next().map(str::to_string))
            .is_some_and(|first| first.to_ascii_lowercase().contains("active"));
        if active {
            return true;
        }
    }
    // `[[ -s "$FIREWALL_BLOCKLIST_URLS" ]]` - non-empty, not merely present.
    std::fs::metadata(BLOCKLIST_URLS).is_ok_and(|m| m.len() > 0)
}

/// `firewall-migrate`.
pub fn migrate(ctx: &Context) -> HelperResponse {
    // `firewall_require_tools`. The bash `deny`s, which exits 1.
    for tool in ["iptables", "ipset"] {
        if !runtime::have(tool) {
            return HelperResponse::failed(
                HelperErrorKind::CommandFailed,
                format!("{tool} is not installed"),
            );
        }
    }

    // Read before `ensure_dir` creates it: the state file's absence is how
    // the bash knows this is the first migration on this box.
    let first_run = !std::path::Path::new(STATE_FILE).exists();
    if let Err(e) = firewall::ensure_dir() {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("preparing the firewall directory: {e}"),
        );
    }

    let mut out = String::new();
    let imported = import_ufw_rules(ctx);
    if imported > 0 {
        out.push_str(&format!("Imported {imported} rule(s) from UFW\n"));
    }

    if first_run {
        if was_enforcing() {
            let resp = fwrules::set_state(ctx, FirewallState::Enabled);
            if !resp.ok {
                return resp;
            }
        } else {
            let resp = fwrules::set_state(ctx, FirewallState::Disabled);
            if !resp.ok {
                return resp;
            }
            out.push_str("No active firewall detected; rules are staged but not enforced.\n");
            out.push_str(
                "Turn them on from the panel Firewall page or: snpanel-helper firewall-enable\n",
            );
        }
    }

    purge_ufw(&mut out);
    purge_nginx_blocklist();

    let mut resp = firewall::apply(&firewall::load_ruleset(ctx.panel_port, &ctx.ssh_ports));
    out.push_str(&resp.stdout);
    resp.stdout = out;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `ufw status numbered` output, plus the shapes that made the bash's
    /// regex the size it is.
    const SAMPLE: &str = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 2222/tcp                   ALLOW IN    Anywhere                   # snpanel:PanelZone
[ 3] 3306/tcp                   ALLOW IN    10.0.0.5
[ 4] 80,443/tcp                 ALLOW IN    Anywhere
[ 5] Nginx Full                 ALLOW IN    Anywhere
[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 7] 8080                       ALLOW IN    203.0.113.0/24
[ 8] 25/tcp                     DENY IN     198.51.100.7
[ 9] 53/udp                     ALLOW IN    Anywhere
[10] Anywhere                   ALLOW IN    192.0.2.1
[11] 9000/tcp                   ALLOW OUT   Anywhere
[12] Anywhere                   ALLOW IN    Anywhere
[13] 5000:6000/tcp              ALLOW IN    Anywhere
[14] 7777/tcp                   ALLOW IN    INTERNAL
[15] 123/udp                    ALLOW IN    Anywhere                   # ntp
22/tcp                          ALLOW IN    Anywhere
[16] 1234/sctp                  ALLOW IN    Anywhere
[17] 999999/tcp                 ALLOW IN    Anywhere
[18] 443/tcp                    ALLOW  IN     Anywhere
[19] 4444/tcp                   allow in    10.1.2.3
[20] 65535/tcp                  DENY IN     Anywhere
garbage line with no action at all
[21] 8443/tcp                   ALLOW IN    OUTSIDE
[22] 7777/tcp                   ALLOW    INTERNAL
[23] 9443/tcp                   ALLOW    OUTSIDE
[24] 25/tcp                     DENY    INTERNAL
";

    /// What the bash's embedded `python3` prints for `SAMPLE`, tab-separated,
    /// captured by running that parser against this input.
    const PYTHON_OUTPUT: &str = "\
allow\t\t22\ttcp
allow\t\t2222\ttcp
allow\t10.0.0.5\t3306\ttcp
allow\t203.0.113.0/24\t8080\ttcp
deny\t198.51.100.7\t25\ttcp
allow\t\t53\tudp
allow\t192.0.2.1\t\ttcp
allow\tINTERNAL\t7777\ttcp
allow\t\t123\tudp
allow\t\t22\ttcp
allow\t\t443\ttcp
allow\t10.1.2.3\t4444\ttcp
deny\t\t65535\ttcp
allow\tOUTSIDE\t8443\ttcp
allow\tINTERNAL\t7777\ttcp
allow\tOUTSIDE\t9443\ttcp
deny\tINTERNAL\t25\ttcp
";

    fn as_python_prints(rules: &[UfwRule]) -> String {
        rules
            .iter()
            .map(|r| {
                let action = match r.action {
                    Action::Allow => "allow",
                    Action::Deny => "deny",
                };
                let proto = match r.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                };
                format!("{action}\t{}\t{}\t{proto}\n", r.source, r.port)
            })
            .collect()
    }

    #[test]
    fn the_reader_agrees_with_the_python_it_replaces() {
        // The bash pipes `ufw status numbered` through 35 lines of embedded
        // `python3`. This is that parser's own output for this input, so the
        // test fails if the port decides differently about any line - which
        // is the only way to know, since the Python is what has been running.
        assert_eq!(as_python_prints(&parse_status(SAMPLE)), PYTHON_OUTPUT);
    }

    #[test]
    fn a_source_beginning_in_is_not_a_direction() {
        // `(?:\s+(IN|OUT))?` is optional and the regex backtracks out of it.
        // Reading `INTERNAL` as the direction `IN` plus `TERNAL` would drop
        // the rule, silently, on exactly the hand-written rules an operator
        // is most likely to care about.
        // With the direction column present the group matches and nothing is
        // backtracked; it is the line *without* one that decides, because
        // there `IN` can only come from the source itself.
        let with_column = parse_status("[14] 7777/tcp                   ALLOW IN    INTERNAL\n");
        assert_eq!(with_column.len(), 1);
        assert_eq!(with_column[0].source, "INTERNAL");

        let no_column = parse_status("[22] 7777/tcp                   ALLOW    INTERNAL\n");
        assert_eq!(no_column.len(), 1, "the rule was dropped");
        assert_eq!(no_column[0].source, "INTERNAL");
        assert_eq!(no_column[0].port, "7777");

        // `OUT` is the other half of the group and the same trap.
        let out = parse_status("[23] 9443/tcp                   ALLOW    OUTSIDE\n");
        assert_eq!(out.len(), 1, "the rule was dropped");
        assert_eq!(out[0].source, "OUTSIDE");
    }

    #[test]
    fn an_out_rule_is_not_imported() {
        // The new chain filters INPUT only; an OUT rule has nowhere to go.
        assert!(parse_status("[11] 9000/tcp                   ALLOW OUT   Anywhere\n").is_empty());
    }

    #[test]
    fn v6_duplicates_and_profiles_and_ranges_are_skipped() {
        for line in [
            "[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)\n",
            "[ 5] Nginx Full                 ALLOW IN    Anywhere\n",
            "[13] 5000:6000/tcp              ALLOW IN    Anywhere\n",
            "[ 4] 80,443/tcp                 ALLOW IN    Anywhere\n",
            "[16] 1234/sctp                  ALLOW IN    Anywhere\n",
            // `\d{1,5}` - six digits is not a port.
            "[17] 999999/tcp                 ALLOW IN    Anywhere\n",
            // Neither a port nor a source is not a rule.
            "[12] Anywhere                   ALLOW IN    Anywhere\n",
        ] {
            assert!(parse_status(line).is_empty(), "should have skipped: {line}");
        }
    }

    #[test]
    fn a_comment_is_not_part_of_the_source() {
        let rules =
            parse_status("[ 2] 2222/tcp  ALLOW IN    Anywhere                   # snpanel:PanelZone\n");
        assert_eq!(rules.len(), 1);
        // "Anywhere" becomes the empty source, and the comment goes with it.
        assert_eq!(rules[0].source, "");
    }

    #[test]
    fn the_numbered_prefix_is_optional() {
        // `ufw status` without `numbered` prints no `[ n]`, and the regex
        // makes the prefix optional rather than requiring it.
        let with = parse_status("[ 1] 22/tcp                     ALLOW IN    Anywhere\n");
        let without = parse_status("22/tcp                          ALLOW IN    Anywhere\n");
        assert_eq!(with, without);
    }

    #[test]
    fn the_include_stripper_takes_whole_lines() {
        let before = "server {\n    include /etc/nginx/snpanel/ip-blocklist-server.conf;\n    listen 80;\n}\n";
        assert_eq!(
            strip_include_lines(before),
            "server {\n    listen 80;\n}\n"
        );
    }

    #[test]
    fn the_include_stripper_leaves_a_file_without_the_include_alone() {
        // `sed` only rewrites the file when a line matches; the caller uses
        // the same condition to decide whether nginx needs reloading, so a
        // stripper that rewrote every file would reload nginx on every box.
        let text = "server {\n    listen 80;\n}\n";
        assert_eq!(strip_include_lines(text), text);
    }

    #[test]
    fn the_empty_server_conf_is_a_comment_and_nothing_else() {
        // It is included by vhosts that have not been rewritten yet. Anything
        // other than comments in it would be applied to them.
        for line in EMPTY_SERVER_CONF.lines() {
            assert!(
                line.trim_start().starts_with('#'),
                "not a comment: {line:?}"
            );
        }
    }
}
