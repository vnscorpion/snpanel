//! Editing `rules.tsv`: the rest of the firewall domain.
//!
//! Source: `firewall_add_rule`, `firewall_delete_rule`, `firewall_set_state`
//! and the blocklist handling in the bash helper.
//!
//! Every mutation rewrites the file and then re-applies, because the file is
//! the source of truth (C13) and the loaded ruleset is derived from it. There
//! is deliberately no path that edits the running firewall directly.

use std::io::Write;

use snpanel_core::{IpOrCidr, Port};
use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::firewall::rules::{
    Action, FirewallRuleset, FirewallState, Protocol, Rule, BASE_PROTECTED_PORTS,
};

use super::firewall::{self, RULES_TSV, STATE_FILE};
use super::Context;

/// Read the rules file.
fn read_rules() -> Vec<Rule> {
    std::fs::read_to_string(RULES_TSV)
        .map(|s| FirewallRuleset::parse_rules_tsv(&s))
        .unwrap_or_default()
}

/// Rewrite the rules file, preserving the mode the bash installs it with.
fn write_rules(rules: &[Rule]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let body: String = rules.iter().map(|r| format!("{}\n", r.to_line())).collect();

    let tmp = format!("{RULES_TSV}.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    }
    std::fs::rename(&tmp, RULES_TSV)
}

/// Source: `firewall_next_id` - the highest id seen plus one, so ids are never
/// reused even after deletions.
fn next_id(rules: &[Rule]) -> u32 {
    rules.iter().map(|r| r.id).max().unwrap_or(0) + 1
}

/// Re-render and load after any change.
fn reapply(ctx: &Context) -> HelperResponse {
    firewall::apply(&firewall::load_ruleset(ctx.panel_port, &ctx.ssh_ports))
}

/// `firewall-allow-ip`, `firewall-deny-ip`, `firewall-allow-port`.
///
/// Source: `firewall_add_rule`, including all four of its refusals.
pub fn add_rule(
    ctx: &Context,
    action: Action,
    ip: Option<&IpOrCidr>,
    port: Option<Port>,
    protocol: Protocol,
) -> HelperResponse {
    if ip.is_none() && port.is_none() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "a firewall rule needs an IP or a port",
        );
    }

    // Source: the explicit refusal in the bash. Denying a port for everyone is
    // already the default - unlisted ports are dropped - so a rule saying so
    // would be a no-op the operator would reasonably expect to do something.
    if ip.is_none() && action == Action::Deny {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "closing a port for every source is not supported; \
             the firewall denies unlisted ports already",
        );
    }

    // Opening a port that is already protected is reported, not recorded.
    if ip.is_none() {
        if let Some(p) = port {
            let protected =
                FirewallRuleset::compute_protected_ports(&ctx.ssh_ports, ctx.panel_port);
            if protected.contains(&p.get()) {
                return HelperResponse::with_stdout(format!(
                    "Port {p} is already open as a protected panel port\n"
                ));
            }
        }
    }

    // The protocol column is empty for a whole-host rule, matching the bash.
    let stored_protocol = protocol;
    let mut rules = read_rules();

    // Duplicate detection compares the *normalised* address, which is why
    // IpOrCidr::normalized has to agree with Python's ipaddress.
    let normalized = ip.map(|i| i.normalized());
    let already = rules.iter().find(|r| {
        r.action == action
            && r.ip.as_ref().map(|i| i.normalized()) == normalized
            && r.port == port
            && (port.is_none() || r.protocol == stored_protocol)
    });
    if let Some(existing) = already {
        let id = existing.id;
        let mut resp = reapply(ctx);
        resp.stdout = format!("Rule already exists (#{id})\n");
        return resp;
    }

    let id = next_id(&rules);
    let stored_ip = match ip {
        Some(i) => match IpOrCidr::parse(&i.normalized()) {
            Ok(n) => Some(n),
            Err(e) => return HelperResponse::failed(HelperErrorKind::BadRequest, e.to_string()),
        },
        None => None,
    };

    rules.push(Rule {
        id,
        action,
        ip: stored_ip,
        port,
        protocol: stored_protocol,
    });

    if let Err(e) = write_rules(&rules) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {RULES_TSV}: {e}"),
        );
    }

    let mut resp = reapply(ctx);
    if resp.ok {
        resp.stdout = format!("Rule #{id} added\n");
    }
    resp
}

/// `firewall-delete`. Source: `firewall_delete_rule`.
pub fn delete_rule(ctx: &Context, id: u32) -> HelperResponse {
    let rules = read_rules();
    if !rules.iter().any(|r| r.id == id) {
        return HelperResponse::failed(HelperErrorKind::NotFound, format!("rule #{id} not found"));
    }
    let remaining: Vec<Rule> = rules.into_iter().filter(|r| r.id != id).collect();
    if let Err(e) = write_rules(&remaining) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {RULES_TSV}: {e}"),
        );
    }
    let mut resp = reapply(ctx);
    if resp.ok {
        resp.stdout = format!("Rule #{id} deleted\n");
    }
    resp
}

/// `firewall-enable` / `firewall-disable`.
///
/// C39: disabling removes the hook and keeps the chain, rather than flipping a
/// policy. The renderer implements that; here we only record the intent.
pub fn set_state(ctx: &Context, state: FirewallState) -> HelperResponse {
    let word = match state {
        FirewallState::Enabled => "enabled",
        FirewallState::Disabled => "disabled",
    };
    if let Err(e) = firewall::ensure_dir() {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("preparing the firewall directory: {e}"),
        );
    }
    if let Err(e) = std::fs::write(STATE_FILE, format!("{word}\n")) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {STATE_FILE}: {e}"),
        );
    }
    let mut resp = reapply(ctx);
    if resp.ok {
        resp.stdout = format!("Firewall {word}\n");
    }
    resp
}

/// `firewall-panel-allow-port`: open the panel's own port.
///
/// Source: the bash arm of the same name. It exists so changing the panel port
/// cannot lock the operator out - the new port is opened before the panel
/// moves to it.
pub fn panel_allow_port(ctx: &Context, port: Port) -> HelperResponse {
    add_rule(ctx, Action::Allow, None, Some(port), Protocol::Tcp)
}

/// `firewall-list`: the rules as structured data, **on stdout**.
///
/// The panel reads this verb's stdout - `rules()` in the API's firewall
/// routes, and `snpanel-cli`'s panel-port move. Over the helper socket the
/// API is handed `stdout` and never `data`, so while this answered in `data`
/// the listing reached the panel as an empty string: the Firewall page showed
/// no rules however many there were, and every delete was refused as "not
/// found", because the delete looks the rule up in this list first. The
/// sudo path hid it - the CLI prints `data` - and the socket is the default.
///
/// Pretty JSON and a newline: byte for byte what the CLI printed from `data`,
/// so a script that read the old output reads this.
pub fn list(ctx: &Context) -> HelperResponse {
    let rules = read_rules();
    let state = std::fs::read_to_string(STATE_FILE)
        .map(|s| FirewallState::parse(&s))
        .unwrap_or(FirewallState::Enabled);
    let protected = FirewallRuleset::compute_protected_ports(&ctx.ssh_ports, ctx.panel_port);

    let items: Vec<serde_json::Value> = rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "number": r.id,
                "action": r.action.as_str().to_uppercase(),
                "ip": r.ip.as_ref().map(|i| i.to_string()),
                "from": r.ip.as_ref().map(|i| i.to_string()).unwrap_or_else(|| "any".into()),
                "port": r.port.map(|p| p.get()),
                "protocol": r.port.map(|_| r.protocol.as_str()),
                "to": match r.port {
                    Some(p) => format!("{}/{}", p, r.protocol),
                    None => "any".to_string(),
                },
                "zone": "UserZone",
                "protected": false,
            })
        })
        .collect();

    let listing = serde_json::json!({
        "state": match state {
            FirewallState::Enabled => "enabled",
            FirewallState::Disabled => "disabled",
        },
        "engine": "nftables",
        // Whether the stored state is actually in force: "enabled" with no
        // hook loaded is a firewall that protects nothing.
        "chain_active": firewall::chain_active(),
        "rules": items,
        "protected_ports": protected,
        "base_protected_ports": BASE_PROTECTED_PORTS,
    });
    HelperResponse::with_stdout(format!(
        "{}\n",
        serde_json::to_string_pretty(&listing).unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, line: &str) -> Rule {
        let r = Rule::parse_line(line).expect("valid line");
        assert_eq!(r.id, id);
        r
    }

    #[test]
    fn ids_continue_past_the_highest_even_after_deletions() {
        // Source: firewall_next_id takes max + 1, not count + 1, so a deleted
        // id is never handed out again.
        let rules = [
            rule(1, "1\tallow\t203.0.113.1/32\t\ttcp"),
            rule(5, "5\tallow\t203.0.113.5/32\t\ttcp"),
        ];
        assert_eq!(next_id(&rules), 6);
        assert_eq!(next_id(&[]), 1);
    }

    #[test]
    fn the_listing_is_on_stdout_where_the_panel_reads_it() {
        // Over the socket the API gets `stdout` and never `data`. A listing in
        // `data` reached the Firewall page as nothing: no rules shown, and
        // every delete refused as "not found".
        let r = list(&Context::default());
        assert!(r.ok);
        assert!(r.data.is_none(), "`data` is what the bug put it in");
        let v: serde_json::Value =
            serde_json::from_str(&r.stdout).expect("stdout is the JSON listing");
        for key in [
            "state",
            "engine",
            "chain_active",
            "rules",
            "protected_ports",
            "base_protected_ports",
        ] {
            assert!(v.get(key).is_some(), "{key} is missing from the listing");
        }
        assert_eq!(v["engine"], "nftables");
        assert!(v["rules"].is_array());
        assert!(v["protected_ports"].is_array());
        assert!(v["chain_active"].is_boolean());
        // What the CLI printed from `data`: pretty, then one newline.
        assert_eq!(
            r.stdout,
            format!("{}\n", serde_json::to_string_pretty(&v).unwrap())
        );
    }

    #[test]
    fn a_rule_needs_an_ip_or_a_port() {
        let ctx = Context::default();
        let r = add_rule(&ctx, Action::Allow, None, None, Protocol::Tcp);
        assert!(!r.ok);
        assert!(r.error.unwrap().message.contains("needs an IP or a port"));
    }

    #[test]
    fn denying_a_port_for_everyone_is_refused_with_the_reason() {
        // It would be a no-op that looks like it did something: unlisted ports
        // are already dropped.
        let ctx = Context::default();
        let r = add_rule(
            &ctx,
            Action::Deny,
            None,
            Some(Port::new(8080).unwrap()),
            Protocol::Tcp,
        );
        assert!(!r.ok);
        assert!(r.error.unwrap().message.contains("already"));
    }

    #[test]
    fn opening_an_already_protected_port_says_so_instead_of_adding_a_rule() {
        let ctx = Context {
            panel_port: 2222,
            ssh_ports: vec![22],
        };
        for p in [22u16, 80, 443, 2222] {
            let r = add_rule(
                &ctx,
                Action::Allow,
                None,
                Some(Port::new(p as u32).unwrap()),
                Protocol::Tcp,
            );
            assert!(r.ok, "port {p}");
            assert!(
                r.stdout.contains("already open as a protected"),
                "port {p}: {}",
                r.stdout
            );
        }
    }

    #[test]
    fn deleting_a_rule_that_is_not_there_is_not_found() {
        let ctx = Context::default();
        let r = delete_rule(&ctx, 999_999);
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().kind, HelperErrorKind::NotFound);
    }

    #[test]
    fn rules_serialise_back_to_the_tsv_format() {
        let rules = [
            rule(1, "1\tallow\t203.0.113.1/32\t\ttcp"),
            rule(2, "2\tdeny\t10.0.0.0/8\t3306\ttcp"),
        ];
        let body: String = rules.iter().map(|r| format!("{}\n", r.to_line())).collect();
        assert_eq!(
            body,
            "1\tallow\t203.0.113.1/32\t\ttcp\n2\tdeny\t10.0.0.0/8\t3306\ttcp\n"
        );
    }

    #[test]
    fn duplicate_detection_compares_normalised_addresses() {
        // 10.0.0.5/8 and 10.0.0.0/8 are the same network. If the duplicate
        // check compared the raw text they would both be stored, and the
        // operator would see two rules that do one thing.
        let a = IpOrCidr::parse("10.0.0.5/8").unwrap();
        let b = IpOrCidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(a.normalized(), b.normalized());
    }
}
