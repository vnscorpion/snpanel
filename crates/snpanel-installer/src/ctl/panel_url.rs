//! Moving the panel's address after it is installed.
//!
//! Source: `set_panel_url`, `close_old_panel_port`,
//! `refresh_phpmyadmin_api_base`, `panel_sni_hostnames`.
//!
//! This is the entry an operator reaches for when the panel has become
//! unreachable — a domain that no longer resolves, a port a new firewall
//! blocks. So it has to work without the panel, and it must not leave the
//! box *less* reachable than it found it.

/// Whether the new address can keep HTTPS.
///
/// **Only when the domain has not changed and both files are still there.**
/// A certificate issued for the old domain is not valid for the new one, and
/// serving it anyway gives the operator a browser warning on every visit —
/// which teaches them to click through warnings on the one page where that
/// habit is most expensive.
///
/// The port is not part of the decision: a certificate is bound to a name,
/// not to a port, so moving from 2222 to 8443 keeps it.
pub fn keeps_https(
    new_domain: &str,
    current_domain: &str,
    cert: &str,
    key: &str,
    cert_exists: bool,
    key_exists: bool,
) -> bool {
    !new_domain.is_empty()
        && current_domain == new_domain
        && !cert.is_empty()
        && !key.is_empty()
        && cert_exists
        && key_exists
}

/// What the move writes back into the `.env`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub scheme: &'static str,
    pub host: String,
    pub port: u16,
    pub url: String,
    /// `PANEL_DOMAIN`, empty when the panel answers on an address.
    pub domain: String,
    /// Cleared when the scheme drops to HTTP, so the panel does not go on
    /// trying to serve a certificate that no longer matches its name.
    pub clear_certificate: bool,
}

pub fn address(host: &str, port: u16, domain: &str, https: bool) -> Address {
    let scheme = if https { "https" } else { "http" };
    Address {
        scheme,
        host: host.to_string(),
        port,
        url: format!("{scheme}://{host}:{port}"),
        domain: domain.to_string(),
        clear_certificate: !https,
    }
}

/// Ports `close_old_panel_port` refuses to close.
///
/// `22` is the one that matters: the operator is running this over SSH, and
/// a menu entry that closed their own session while moving a web port would
/// be unforgivable. The rest are ports a box is expected to keep answering
/// on — HTTP, HTTPS and the two mail submission ports — which the panel did
/// not open and has no business closing.
pub const NEVER_CLOSED: &[u16] = &[22, 80, 443, 465, 587];

/// Whether the old port's rule should be removed.
pub fn may_close_old_port(old: Option<u16>, new: u16) -> bool {
    let Some(old) = old else {
        return false;
    };
    old != new && !NEVER_CLOSED.contains(&old)
}

/// One firewall rule, as `firewall-list` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub port: u16,
    /// A rule the helper marks as protected — the panel did not create it
    /// and will not remove it.
    pub protected: bool,
    /// Set when the rule allows one source address rather than everyone.
    pub ip: Option<String>,
}

/// The rule to delete when the panel moves off a port.
///
/// Three conditions, and the two beyond the port number are what stop this
/// from removing somebody else's rule that happens to share it:
///
/// * not protected — those are rules the panel did not create;
/// * no source address — a rule scoped to one IP was written by hand for a
///   reason, and it is not the blanket allow the panel added;
/// * the first match only, as the Python's `break` takes.
pub fn rule_to_delete(rules: &[Rule], old_port: u16) -> Option<&Rule> {
    rules
        .iter()
        .find(|r| !r.protected && r.ip.is_none() && r.port == old_port)
}

/// The loopback URL inside phpMyAdmin's sign-on endpoint, rewritten when the
/// panel's scheme or port changes.
///
/// The endpoint asks the panel what a token is worth over `127.0.0.1`, so
/// the port has to follow the panel. Left stale, every sign-on fails with
/// "Expired token" — which reads as an authentication problem and is a
/// connection refused.
pub fn api_base(scheme: &str, port: u16) -> String {
    format!("{scheme}://127.0.0.1:{port}/api/databases/phpmyadmin-sso/")
}

/// A directory under `/etc/snpanel/sni` is a usable hostname only when it
/// holds **both** halves of a certificate.
///
/// A directory with only a `fullchain.pem` is one whose key was removed or
/// never arrived, and listing it would tell the operator to try an address
/// where the TLS handshake fails.
pub fn sni_hostname_usable(has_fullchain: bool, has_privkey: bool) -> bool {
    has_fullchain && has_privkey
}

pub fn sni_url(name: &str, port: u16) -> String {
    format!("https://{name}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate issued for the old domain is not valid for the new one,
    /// and serving it anyway teaches the operator to click through browser
    /// warnings on the one page where that habit is most expensive.
    #[test]
    fn changing_the_domain_drops_to_http() {
        assert!(!keeps_https("new.com", "old.com", "/c", "/k", true, true));
        // And the certificate paths are cleared with it, so the panel does
        // not go on trying to serve a name it no longer has.
        let moved = address("new.com", 2222, "new.com", false);
        assert!(moved.clear_certificate);
        assert_eq!(moved.url, "http://new.com:2222");
    }

    /// Keeping the same domain keeps HTTPS — this entry is often used to
    /// move only the port.
    #[test]
    fn the_same_domain_with_both_files_keeps_https() {
        assert!(keeps_https("a.com", "a.com", "/c", "/k", true, true));
        let moved = address("a.com", 8443, "a.com", true);
        assert_eq!(moved.url, "https://a.com:8443");
        assert!(!moved.clear_certificate);
    }

    /// A certificate is bound to a name, not to a port.
    #[test]
    fn moving_only_the_port_keeps_the_certificate() {
        assert!(keeps_https("a.com", "a.com", "/c", "/k", true, true));
    }

    /// A configured path that no longer points at a file is not a
    /// certificate. Serving with one half missing is a panel that accepts
    /// the connection and then fails the handshake, which looks like the
    /// network rather than like a missing file.
    #[test]
    fn a_certificate_whose_files_are_gone_does_not_keep_https() {
        assert!(!keeps_https("a.com", "a.com", "/c", "/k", false, true));
        assert!(!keeps_https("a.com", "a.com", "/c", "/k", true, false));
        assert!(!keeps_https("a.com", "a.com", "", "/k", true, true));
        assert!(!keeps_https("a.com", "a.com", "/c", "", true, true));
    }

    /// Moving to an IP address means there is no name for a certificate to
    /// be issued for.
    #[test]
    fn an_address_without_a_domain_is_served_over_http() {
        assert!(!keeps_https("", "a.com", "/c", "/k", true, true));
        let moved = address("203.0.113.10", 2222, "", false);
        assert_eq!(moved.url, "http://203.0.113.10:2222");
        assert_eq!(moved.domain, "");
        assert!(moved.clear_certificate);
    }

    /// **The operator is running this over SSH.** A menu entry that closed
    /// their own session while moving a web port would be unforgivable.
    #[test]
    fn the_ssh_port_is_never_closed() {
        assert!(!may_close_old_port(Some(22), 2222));
        assert!(NEVER_CLOSED.contains(&22));
    }

    /// The other four are ports a box is expected to keep answering on. The
    /// panel did not open them and has no business closing them.
    #[test]
    fn the_ports_the_panel_did_not_open_are_never_closed() {
        for port in [80, 443, 465, 587] {
            assert!(!may_close_old_port(Some(port), 2222), "{port}");
        }
    }

    #[test]
    fn an_ordinary_old_panel_port_is_closed() {
        assert!(may_close_old_port(Some(2222), 8443));
        // Unless it is the port being moved to.
        assert!(!may_close_old_port(Some(2222), 2222));
        // Or there was no old port to close.
        assert!(!may_close_old_port(None, 2222));
    }

    /// The two conditions beyond the port number are what stop this from
    /// removing somebody else's rule that happens to share it.
    #[test]
    fn only_the_panels_own_blanket_rule_is_removed() {
        let rules = vec![
            Rule {
                id: "a".into(),
                port: 2222,
                protected: true,
                ip: None,
            },
            Rule {
                id: "b".into(),
                port: 2222,
                protected: false,
                ip: Some("203.0.113.5".into()),
            },
            Rule {
                id: "c".into(),
                port: 2222,
                protected: false,
                ip: None,
            },
        ];
        assert_eq!(
            rule_to_delete(&rules, 2222).map(|r| r.id.as_str()),
            Some("c")
        );
        // A protected rule alone leaves nothing to delete.
        assert_eq!(rule_to_delete(&rules[..1], 2222), None);
        // A rule scoped to one address was written by hand for a reason.
        assert_eq!(rule_to_delete(&rules[1..2], 2222), None);
        // And another port's rule is not this port's.
        assert_eq!(rule_to_delete(&rules, 8443), None);
    }

    /// The first match only, as the Python's `break` takes — two identical
    /// blanket rules are not both removed in one pass.
    #[test]
    fn the_first_matching_rule_wins() {
        let rules = vec![
            Rule {
                id: "first".into(),
                port: 2222,
                protected: false,
                ip: None,
            },
            Rule {
                id: "second".into(),
                port: 2222,
                protected: false,
                ip: None,
            },
        ];
        assert_eq!(
            rule_to_delete(&rules, 2222).map(|r| r.id.as_str()),
            Some("first")
        );
    }

    /// Left stale, every phpMyAdmin sign-on fails with "Expired token" —
    /// which reads as an authentication problem and is a connection
    /// refused.
    #[test]
    fn the_sign_on_endpoint_follows_the_panel() {
        assert_eq!(
            api_base("https", 8443),
            "https://127.0.0.1:8443/api/databases/phpmyadmin-sso/"
        );
        assert_eq!(
            api_base("http", 2222),
            "http://127.0.0.1:2222/api/databases/phpmyadmin-sso/"
        );
        // Always loopback, whatever the panel's public address became.
        assert!(api_base("https", 8443).contains("//127.0.0.1:"));
    }

    /// Listing a hostname whose key is missing tells the operator to try an
    /// address where the handshake fails.
    #[test]
    fn a_hostname_is_listed_only_when_both_halves_are_present() {
        assert!(sni_hostname_usable(true, true));
        assert!(!sni_hostname_usable(true, false));
        assert!(!sni_hostname_usable(false, true));
        assert!(!sni_hostname_usable(false, false));
        assert_eq!(
            sni_url("panel.example.com", 2222),
            "https://panel.example.com:2222"
        );
    }
}
