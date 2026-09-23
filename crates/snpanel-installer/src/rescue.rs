//! Getting back into a box that a firewall locked everyone out of.
//!
//! Source: `installer/rescue-firewall.sh`.
//!
//! This runs when the panel cannot be reached — an oversized blocklist, a
//! deny rule that matched more than it was meant to, leftover UFW rules from
//! a previous life. Two properties make it a rescue tool rather than just
//! another firewall script, and both are inverted from what ordinary code
//! does:
//!
//! * **it backs up before it touches anything**, because the state it is
//!   about to destroy is also the evidence for why the box broke;
//! * **it fails open.** Every teardown ends with `INPUT` set to `ACCEPT`, so
//!   a rebuild that does not work leaves a reachable box rather than a
//!   silent one. On any other tool that would be a bug. Here it is the
//!   entire point: an operator who cannot reach the machine cannot fix the
//!   machine.

/// Where the backup goes: `/root/snpanel-firewall-rescue-<timestamp>`.
///
/// Under `/root` rather than `/tmp` so it survives a reboot — which is a
/// thing an operator locked out of a box tends to try — and timestamped so
/// a second run does not overwrite the evidence from the first.
pub fn backup_dir(timestamp: &str) -> String {
    format!("/root/snpanel-firewall-rescue-{timestamp}")
}

/// What is saved before anything is torn down.
///
/// The kernel's own view first, then the panel's rules, then UFW's if it is
/// installed. Each is best-effort: a box with no `ip6tables` still gets a
/// rescue, and a backup step that could abort the run would defeat the
/// purpose.
pub const BACKED_UP: &[&str] = &[
    "iptables-save.txt",
    "ip6tables-save.txt",
    "ipset-save.txt",
    "rules.tsv",
    "ufw-status-numbered.txt",
    "ufw-etc-backup.tar.gz",
];

/// The panel's chain, removed from both families.
pub const CHAIN: &str = "SNPANEL-INPUT";

/// Every ipset the panel creates, destroyed by name.
///
/// Five shapes in two families: the allow and deny lists, their
/// port-qualified twins, and the URL blocklist. Named explicitly rather than
/// matched by prefix, because `ipset destroy` with no argument destroys
/// *everything* — including sets some other tool on the box owns.
pub const IPSETS: &[&str] = &[
    "snpanel-allow4",
    "snpanel-allowp4",
    "snpanel-deny4",
    "snpanel-denyp4",
    "snpanel-block4",
    "snpanel-allow6",
    "snpanel-allowp6",
    "snpanel-deny6",
    "snpanel-denyp6",
    "snpanel-block6",
];

/// The policy `INPUT` is left at after the teardown.
///
/// `ACCEPT`, and see the module header. A rescue that left the policy at
/// `DROP` and then failed to rebuild would have finished the job the broken
/// firewall started.
pub const INPUT_POLICY_AFTER_TEARDOWN: &str = "ACCEPT";

/// The ports the rebuilt chain keeps open.
///
/// `ssh_port` and `panel_port` are discovered rather than assumed — from
/// `sshd -T` and from the `.env` — because a box whose SSH moved to 2022 is
/// exactly the box somebody is rescuing, and a rescue that reopened only 22
/// would leave them locked out by the rescue.
pub fn protected_ports(ssh_port: u16, panel_port: u16) -> Vec<u16> {
    let mut ports = vec![ssh_port, panel_port, 80, 443, 465, 587];
    ports.dedup();
    ports
}

/// `sshd -T | awk '$1 == "port" { print $2; exit }'`, defaulting to 22.
///
/// The first `port` line only. `sshd -T` lists one per configured port, and
/// the rescue seeds the first; the rebuilt chain's protected list is what
/// covers the rest.
pub fn ssh_port(sshd_t: &str) -> u16 {
    for line in sshd_t.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("port") {
            continue;
        }
        if let Some(port) = fields.next().and_then(|p| p.parse().ok()) {
            return port;
        }
    }
    DEFAULT_SSH_PORT
}

/// `awk -F= '$1 == "PANEL_PORT" {print $2; exit}' | tr -d '"'`.
pub fn panel_port(env: Option<&str>) -> u16 {
    let Some(env) = env else {
        return DEFAULT_PANEL_PORT;
    };
    for line in env.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key != "PANEL_PORT" {
            continue;
        }
        if let Ok(port) = value.replace('"', "").parse() {
            return port;
        }
        break;
    }
    DEFAULT_PANEL_PORT
}

pub const DEFAULT_SSH_PORT: u16 = 22;
pub const DEFAULT_PANEL_PORT: u16 = 2222;

/// The panel's rule file, reset to nothing but left enabled.
///
/// `0640`, because the rules name the addresses an operator allowed in and
/// that is a map of who they are. Emptied rather than deleted so the panel
/// finds the file it expects, and the state left at `enabled` so the box is
/// protected again the moment the rules are rebuilt — a rescue that turned
/// the firewall off would leave the operator to remember to turn it back on.
pub const RULES_FILE: &str = "/var/lib/snpanel/firewall/rules.tsv";
pub const RULES_MODE: u32 = 0o640;
pub const STATE_AFTER_RESCUE: &str = "enabled";

/// What is printed when the rebuild could not run.
///
/// It says what state the box is in, which is the one thing the operator
/// needs to know next.
pub const REBUILD_SKIPPED: &str =
    "ipset or snpanel-helper missing; leaving INPUT policy at ACCEPT.";
pub const REBUILD_FAILED: &str =
    "WARNING: snpanel-helper firewall-apply failed; INPUT is left at ACCEPT.";

#[cfg(test)]
mod tests {
    use super::*;

    /// Under `/root` rather than `/tmp`, so it survives the reboot an
    /// operator locked out of a box tends to try — and timestamped, so a
    /// second run does not overwrite the evidence from the first.
    #[test]
    fn the_backup_survives_a_reboot_and_a_second_run() {
        let first = backup_dir("20260923-010203");
        let second = backup_dir("20260923-010204");
        assert!(first.starts_with("/root/"));
        assert!(!first.starts_with("/tmp"));
        assert_ne!(first, second);
    }

    /// The state it is about to destroy is also the evidence for why the box
    /// broke.
    #[test]
    fn the_kernels_view_and_the_panels_rules_are_both_saved() {
        assert!(BACKED_UP.contains(&"iptables-save.txt"));
        assert!(BACKED_UP.contains(&"ip6tables-save.txt"));
        assert!(BACKED_UP.contains(&"ipset-save.txt"));
        assert!(BACKED_UP.contains(&"rules.tsv"));
        // And UFW's, for a box carrying leftovers from a previous life.
        assert!(BACKED_UP.iter().any(|f| f.starts_with("ufw-")));
    }

    /// **The inversion that makes this a rescue tool.** A rescue that left
    /// the policy at `DROP` and then failed to rebuild would have finished
    /// the job the broken firewall started.
    #[test]
    fn the_teardown_leaves_the_box_reachable() {
        assert_eq!(INPUT_POLICY_AFTER_TEARDOWN, "ACCEPT");
        assert!(REBUILD_SKIPPED.contains("ACCEPT"));
        assert!(REBUILD_FAILED.contains("ACCEPT"));
    }

    /// `ipset destroy` with no argument destroys everything, including sets
    /// another tool on the box owns. Every name is spelt out.
    #[test]
    fn every_ipset_is_named_rather_than_matched_by_prefix() {
        assert_eq!(IPSETS.len(), 10);
        assert!(IPSETS.iter().all(|s| s.starts_with("snpanel-")));
        // Five shapes, in both families.
        for shape in ["allow", "allowp", "deny", "denyp", "block"] {
            assert!(
                IPSETS.contains(&format!("snpanel-{shape}4").as_str()),
                "{shape}4"
            );
            assert!(
                IPSETS.contains(&format!("snpanel-{shape}6").as_str()),
                "{shape}6"
            );
        }
    }

    /// A box whose SSH moved to 2022 is exactly the box somebody is
    /// rescuing, and a rescue that reopened only 22 would leave them locked
    /// out by the rescue.
    #[test]
    fn the_discovered_ports_are_kept_open() {
        let ports = protected_ports(2022, 8443);
        assert!(ports.contains(&2022));
        assert!(ports.contains(&8443));
        for web in [80, 443, 465, 587] {
            assert!(ports.contains(&web), "{web}");
        }
    }

    #[test]
    fn the_ssh_port_comes_out_of_sshd_t() {
        let sshd_t = "addressfamily any\nport 2022\nport 22\npermitrootlogin yes\n";
        assert_eq!(ssh_port(sshd_t), 2022);
        // The first only — the rebuilt chain's protected list covers the
        // rest.
        assert_ne!(ssh_port(sshd_t), 22);
        // And 22 when sshd says nothing this can read.
        assert_eq!(ssh_port(""), 22);
        assert_eq!(ssh_port("permitrootlogin yes\n"), 22);
        assert_eq!(ssh_port("port notanumber\n"), 22);
    }

    #[test]
    fn the_panel_port_comes_out_of_the_env_with_quotes_stripped() {
        assert_eq!(panel_port(Some("PANEL_PORT=8443\n")), 8443);
        assert_eq!(panel_port(Some("PANEL_PORT=\"8443\"\n")), 8443);
        assert_eq!(panel_port(Some("OTHER=1\nPANEL_PORT=8443\n")), 8443);
        // A box with no `.env`, or an unreadable value, still gets a rescue.
        assert_eq!(panel_port(None), 2222);
        assert_eq!(panel_port(Some("")), 2222);
        assert_eq!(panel_port(Some("PANEL_PORT=abc\n")), 2222);
        // A key that merely starts with the name is not the key.
        assert_eq!(panel_port(Some("PANEL_PORT_OLD=9999\n")), 2222);
    }

    /// The rules name the addresses an operator allowed in, which is a map
    /// of who they are.
    #[test]
    fn the_rule_file_is_not_world_readable() {
        assert_eq!(RULES_MODE & 0o007, 0);
        assert_eq!(RULES_MODE & 0o040, 0o040);
    }

    /// A rescue that turned the firewall off would leave the operator to
    /// remember to turn it back on. It is emptied and left enabled, so the
    /// box is protected again the moment the rules are rebuilt.
    #[test]
    fn the_firewall_is_left_enabled_with_no_rules_rather_than_disabled() {
        assert_eq!(STATE_AFTER_RESCUE, "enabled");
        assert!(RULES_FILE.ends_with("rules.tsv"));
    }
}
