//! The firewall's source of truth: `/var/lib/snpanel/firewall/rules.tsv`.
//!
//! Contract C13 - the format does not change. The file is the reason the
//! backend swap in plan §6.3 is safe at all: every apply rebuilds the entire
//! ruleset from this file, so there is no hidden state in `iptables-save` to
//! migrate. Change the renderer, keep the file, and no rule is lost.
//!
//! Format, from `installer/files/snpanel-helper.sh`:
//! ```text
//! id <TAB> action <TAB> ip <TAB> port <TAB> protocol
//! ```
//! `ip` is empty for port-only rules; `port` is empty for whole-host rules.
//! Lines that do not start with a digit are ignored, exactly as the bash
//! `grep -E '^[0-9]+\b'` does.

use std::fmt;

use snpanel_core::{IpOrCidr, Port};

/// Ports the panel must never close, before SSH and the panel port are added.
/// Source: `FIREWALL_PROTECTED_PORTS` in the helper.
pub const BASE_PROTECTED_PORTS: &[u16] = &[80, 443, 465, 587];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

impl Action {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: u32,
    pub action: Action,
    /// `None` for a port-only rule.
    pub ip: Option<IpOrCidr>,
    /// `None` for a whole-host rule.
    pub port: Option<Port>,
    pub protocol: Protocol,
}

impl Rule {
    /// Parse one TSV line. Returns `None` for a line the bash version skips.
    pub fn parse_line(line: &str) -> Option<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        let mut fields = line.split('\t');
        let id: u32 = fields.next()?.trim().parse().ok()?;
        let action = Action::parse(fields.next()?)?;
        let ip_raw = fields.next().unwrap_or("").trim();
        let port_raw = fields.next().unwrap_or("").trim();
        let proto_raw = fields.next().unwrap_or("").trim();

        let ip = if ip_raw.is_empty() {
            None
        } else {
            Some(IpOrCidr::parse(ip_raw).ok()?)
        };
        let port = if port_raw.is_empty() {
            None
        } else {
            Some(Port::parse(port_raw).ok()?)
        };
        // The helper defaults a missing protocol to tcp (`"${proto:-tcp}"`).
        let protocol = Protocol::parse(proto_raw).unwrap_or(Protocol::Tcp);

        Some(Self {
            id,
            action,
            ip,
            port,
            protocol,
        })
    }

    /// Render back to the TSV line, so a rewrite round-trips (C13).
    pub fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            self.id,
            self.action.as_str(),
            self.ip.as_ref().map(|i| i.to_string()).unwrap_or_default(),
            self.port.map(|p| p.to_string()).unwrap_or_default(),
            self.protocol.as_str(),
        )
    }

    fn is_ipv6(&self) -> bool {
        self.ip.as_ref().is_some_and(|i| !i.is_ipv4())
    }
}

/// Whether the firewall is enforcing. Source: `firewall_state`, which treats
/// anything that is not exactly `disabled` as enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallState {
    Enabled,
    Disabled,
}

impl FirewallState {
    pub fn parse(raw: &str) -> Self {
        if raw.trim() == "disabled" {
            Self::Disabled
        } else {
            Self::Enabled
        }
    }
}

/// Everything needed to render a complete ruleset.
#[derive(Debug, Clone)]
pub struct FirewallRuleset {
    pub state: FirewallState,
    pub rules: Vec<Rule>,
    /// Sorted, deduplicated. Source: `firewall_protected_ports`.
    pub protected_ports: Vec<u16>,
    /// The URL blocklist, already split by family.
    pub blocklist_v4: Vec<IpOrCidr>,
    pub blocklist_v6: Vec<IpOrCidr>,
    /// Whether to emit the IPv6 sets and rules.
    ///
    /// Defaults to true and should stay true. The bash `firewall_has_ipv6`
    /// gate exists because iptables and ip6tables are separate ruleset trees
    /// and loading into a missing one errors. `table inet` has no such split:
    /// v6 rules on a v4-only host simply never match, at no cost.
    ///
    /// Leaving this on also avoids a data-loss bug. Gating it on "does this
    /// host have a global IPv6 address" would silently drop an existing
    /// `deny 2001:db8::/32` rule from `rules.tsv` during migration - the rule
    /// would vanish from the firewall while still being listed in the panel.
    pub ipv6_enabled: bool,
}

impl Default for FirewallRuleset {
    fn default() -> Self {
        Self {
            state: FirewallState::Enabled,
            rules: Vec::new(),
            protected_ports: BASE_PROTECTED_PORTS.to_vec(),
            blocklist_v4: Vec::new(),
            blocklist_v6: Vec::new(),
            ipv6_enabled: true,
        }
    }
}

impl FirewallRuleset {
    /// Parse the whole `rules.tsv`.
    pub fn parse_rules_tsv(contents: &str) -> Vec<Rule> {
        contents.lines().filter_map(Rule::parse_line).collect()
    }

    /// Combine the fixed ports, the sshd ports and the panel port, then sort
    /// and deduplicate - `sort -un` in the bash.
    pub fn compute_protected_ports(ssh_ports: &[u16], panel_port: u16) -> Vec<u16> {
        let mut ports: Vec<u16> = BASE_PROTECTED_PORTS.to_vec();
        ports.extend_from_slice(ssh_ports);
        ports.push(panel_port);
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Whole-host rules, split by action and family.
    ///
    /// Public because the helper's `firewall-status` reports per-set counts,
    /// which is part of the text format the panel renders.
    pub fn host_rules(&self, action: Action, ipv6: bool) -> Vec<&IpOrCidr> {
        self.rules
            .iter()
            .filter(|r| r.action == action && r.port.is_none() && r.is_ipv6() == ipv6)
            .filter_map(|r| r.ip.as_ref())
            .collect()
    }

    /// Rules that pin an address *and* a port.
    pub(crate) fn host_port_rules(&self, action: Action, ipv6: bool) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| {
                r.action == action && r.port.is_some() && r.ip.is_some() && r.is_ipv6() == ipv6
            })
            .collect()
    }

    /// Port-only allow rules - open to the world.
    pub(crate) fn open_ports(&self) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.action == Action::Allow && r.ip.is_none() && r.port.is_some())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_tsv_shape() {
        let r = Rule::parse_line("1\tallow\t203.0.113.4\t\ttcp").unwrap();
        assert_eq!(r.id, 1);
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.ip.as_ref().unwrap().to_string(), "203.0.113.4");
        assert!(r.port.is_none());

        let r = Rule::parse_line("2\tdeny\t10.0.0.0/8\t22\ttcp").unwrap();
        assert_eq!(r.action, Action::Deny);
        assert_eq!(r.port.unwrap().get(), 22);

        let r = Rule::parse_line("3\tallow\t\t8080\tudp").unwrap();
        assert!(r.ip.is_none());
        assert_eq!(r.protocol, Protocol::Udp);
    }

    #[test]
    fn skips_the_lines_the_bash_skips() {
        // `grep -E '^[0-9]+\b'` - anything not starting with a digit is out.
        assert!(Rule::parse_line("# a comment").is_none());
        assert!(Rule::parse_line("").is_none());
        assert!(Rule::parse_line("notanid\tallow\t1.2.3.4\t\ttcp").is_none());
        assert!(Rule::parse_line("1\tbogus-action\t1.2.3.4\t\ttcp").is_none());
    }

    #[test]
    fn a_missing_protocol_defaults_to_tcp() {
        // The helper writes "${proto:-tcp}".
        let r = Rule::parse_line("4\tallow\t\t9000\t").unwrap();
        assert_eq!(r.protocol, Protocol::Tcp);
    }

    #[test]
    fn every_line_round_trips() {
        let input = "1\tallow\t203.0.113.4\t\ttcp\n\
                     2\tdeny\t10.0.0.0/8\t22\ttcp\n\
                     3\tallow\t\t8080\tudp\n\
                     4\tdeny\t2001:db8::/32\t\ttcp\n";
        for line in input.lines() {
            let rule = Rule::parse_line(line).unwrap();
            assert_eq!(rule.to_line(), line, "C13: rules.tsv must round-trip");
        }
    }

    #[test]
    fn parses_a_whole_file_and_ignores_noise() {
        let rules = FirewallRuleset::parse_rules_tsv(
            "# SNPanel firewall rules\n\
             1\tallow\t203.0.113.4\t\ttcp\n\
             \n\
             2\tdeny\t198.51.100.0/24\t\ttcp\n",
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, 1);
        assert_eq!(rules[1].id, 2);
    }

    #[test]
    fn protected_ports_are_sorted_and_deduplicated() {
        // sort -un: SSH on 22 and 2222, panel also on 2222.
        let ports = FirewallRuleset::compute_protected_ports(&[22, 2222], 2222);
        assert_eq!(ports, vec![22, 80, 443, 465, 587, 2222]);
    }

    #[test]
    fn the_panel_port_is_always_protected() {
        let ports = FirewallRuleset::compute_protected_ports(&[22], 8443);
        assert!(
            ports.contains(&8443),
            "locking yourself out of the panel is the one unforgivable bug"
        );
        assert!(ports.contains(&22), "and out of SSH is the other");
    }

    #[test]
    fn state_defaults_to_enabled_for_anything_unexpected() {
        assert_eq!(FirewallState::parse("disabled"), FirewallState::Disabled);
        assert_eq!(FirewallState::parse("enabled"), FirewallState::Enabled);
        assert_eq!(FirewallState::parse(""), FirewallState::Enabled);
        assert_eq!(FirewallState::parse("garbage"), FirewallState::Enabled);
    }

    #[test]
    fn rules_split_by_family_and_shape() {
        let rs = FirewallRuleset {
            rules: FirewallRuleset::parse_rules_tsv(
                "1\tallow\t203.0.113.4\t\ttcp\n\
                 2\tallow\t2001:db8::1\t\ttcp\n\
                 3\tdeny\t198.51.100.0/24\t\ttcp\n\
                 4\tallow\t203.0.113.9\t3306\ttcp\n\
                 5\tallow\t\t8080\ttcp\n",
            ),
            ..Default::default()
        };
        assert_eq!(rs.host_rules(Action::Allow, false).len(), 1);
        assert_eq!(rs.host_rules(Action::Allow, true).len(), 1);
        assert_eq!(rs.host_rules(Action::Deny, false).len(), 1);
        assert_eq!(rs.host_port_rules(Action::Allow, false).len(), 1);
        assert_eq!(rs.open_ports().len(), 1);
    }
}
