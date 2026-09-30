//! The mail server's accounts, as the panel hands them to `mail-sync`.
//!
//! The whole state every time: which domains take mail here, the mailboxes
//! and the forwarders. The helper writes Exim's and Dovecot's files from it;
//! a password travels only when it is being set, and only its hash is kept.
//! UNIX ids are not taken from here: the helper resolves the owners itself.

use serde::{Deserialize, Serialize};
use snpanel_core::{Domain, PanelUsername, SecretString};

pub const MAX_DOMAINS: usize = 50_000;
pub const MAX_MAILBOXES: usize = 200_000;
pub const MAX_FORWARDERS: usize = 200_000;
pub const MAX_DESTINATIONS: usize = 20;
/// 1 TB, in MB. Zero is "no limit".
pub const MAX_QUOTA_MB: u32 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailState {
    pub domains: Vec<MailDomain>,
    pub mailboxes: Vec<MailBox>,
    pub forwarders: Vec<MailForwarder>,
    /// Mailboxes whose mail is deleted from disk now (a mailbox removed
    /// from the panel). Only an address no longer in `mailboxes`.
    #[serde(default)]
    pub purge: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailDomain {
    pub domain: Domain,
    /// The account whose home the mailboxes live in.
    pub owner: PanelUsername,
    /// Mail for the domain is delivered here. False: its MX is elsewhere,
    /// and mail from this server to it goes there.
    pub local: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailBox {
    pub address: String,
    /// Zero: no limit.
    pub quota_mb: u32,
    /// Set only when it changes; otherwise the hash already on disk is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailForwarder {
    pub source: String,
    pub destinations: Vec<String>,
}

/// The local part the panel allows: letters, digits and `. _ + -`, not
/// starting or ending with a dot, no two dots in a row.
pub fn local_part_valid(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= 64
        && local
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && !local.starts_with('-')
}

/// `local@domain`, lower case, with a local part [`local_part_valid`] accepts.
pub fn split_address(address: &str) -> Option<(&str, &str)> {
    let (local, domain) = address.rsplit_once('@')?;
    if !local_part_valid(local)
        || Domain::parse(domain)
            .map(|d| d.as_str() != domain)
            .unwrap_or(true)
    {
        return None;
    }
    Some((local, domain))
}

/// A forwarder's destination: any address, but one Exim's lsearch file and
/// its redirect router read as exactly one address - no spaces, commas,
/// colons, pipes, slashes or quotes.
pub fn destination_valid(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    address.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-=".contains(&b))
        && !local.starts_with('.')
        && Domain::parse(domain).is_ok()
        && domain == domain.to_ascii_lowercase()
}

impl MailState {
    pub fn validate(&self) -> Result<(), String> {
        if self.domains.len() > MAX_DOMAINS
            || self.mailboxes.len() > MAX_MAILBOXES
            || self.forwarders.len() > MAX_FORWARDERS
            || self.purge.len() > MAX_MAILBOXES
        {
            return Err("mail state too large".into());
        }
        let mut domains = std::collections::HashSet::new();
        for d in &self.domains {
            if !domains.insert(d.domain.as_str()) {
                return Err(format!("{} is listed twice", d.domain.as_str()));
            }
        }
        let mut boxes = std::collections::HashSet::new();
        for b in &self.mailboxes {
            let (_, domain) = split_address(&b.address)
                .ok_or_else(|| format!("{} is not a valid mailbox", b.address))?;
            if !domains.contains(domain) {
                return Err(format!("{} is not on a mail domain", b.address));
            }
            if !boxes.insert(b.address.as_str()) {
                return Err(format!("{} is listed twice", b.address));
            }
            if b.quota_mb > MAX_QUOTA_MB {
                return Err(format!("{}: quota too large", b.address));
            }
            if let Some(p) = &b.password {
                let p = p.expose();
                if p.is_empty() || p.len() > 256 || p.chars().any(|c| c.is_control()) {
                    return Err(format!("{}: unusable password", b.address));
                }
            }
        }
        let mut sources = std::collections::HashSet::new();
        for f in &self.forwarders {
            let (_, domain) = split_address(&f.source)
                .ok_or_else(|| format!("{} is not a valid address", f.source))?;
            if !domains.contains(domain) {
                return Err(format!("{} is not on a mail domain", f.source));
            }
            if !sources.insert(f.source.as_str()) {
                return Err(format!("{} is listed twice", f.source));
            }
            if f.destinations.is_empty() || f.destinations.len() > MAX_DESTINATIONS {
                return Err(format!(
                    "{}: between 1 and {MAX_DESTINATIONS} destinations",
                    f.source
                ));
            }
            for d in &f.destinations {
                if !destination_valid(d) {
                    return Err(format!("{d} is not a valid destination"));
                }
            }
        }
        for p in &self.purge {
            if split_address(p).is_none() || boxes.contains(p.as_str()) {
                return Err(format!("{p} cannot be purged"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> MailState {
        MailState {
            domains: vec![MailDomain {
                domain: Domain::parse("example.com").unwrap(),
                owner: PanelUsername::parse("alice").unwrap(),
                local: true,
            }],
            mailboxes: vec![MailBox {
                address: "info@example.com".into(),
                quota_mb: 1024,
                password: None,
            }],
            forwarders: vec![MailForwarder {
                source: "sales@example.com".into(),
                destinations: vec!["info@example.com".into(), "Boss@gmail.com".into()],
            }],
            purge: vec!["old@example.com".into()],
        }
    }

    #[test]
    fn a_consistent_state_passes() {
        assert!(state().validate().is_ok());
    }

    #[test]
    fn addresses_are_checked() {
        for bad in [
            "Info@example.com",
            ".a@example.com",
            "a..b@example.com",
            "a b@example.com",
            "a@other.com",
            "a:b@example.com",
            "@example.com",
        ] {
            let mut s = state();
            s.mailboxes[0].address = bad.into();
            assert!(s.validate().is_err(), "{bad}");
        }
        let mut s = state();
        s.forwarders[0].destinations = vec!["x@y.com, z@w.com".into()];
        assert!(s.validate().is_err());
        let mut s = state();
        s.forwarders[0].destinations = vec!["|/bin/sh@x.com".into()];
        assert!(s.validate().is_err());
        let mut s = state();
        s.purge = vec!["info@example.com".into()];
        assert!(s.validate().is_err(), "a live mailbox is never purged");
        let mut s = state();
        s.mailboxes[0].password = Some(SecretString::new("line\nbreak"));
        assert!(s.validate().is_err());
    }
}
