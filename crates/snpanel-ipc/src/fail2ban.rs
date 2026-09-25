//! What the panel decides about Fail2ban, as the helper receives it.
//!
//! Typed rather than text, because a jail file can name actions and an action
//! is a shell command fail2ban runs as root. A file written from the panel's
//! text would let anything that can reach the helper socket run anything; the
//! helper renders the file itself, from these values and nothing else.

use serde::{Deserialize, Serialize};
use snpanel_core::IpOrCidr;

/// A jail the panel manages.
///
/// The names are fail2ban's: three of them are fail2ban's own jails, switched
/// on and pointed at the right ports, and the two `snpanel-` ones come with
/// filters the panel writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Fail2banJail {
    /// SSH, on whatever ports sshd listens on.
    #[serde(rename = "sshd")]
    Sshd,
    /// Sign-ins to the panel, on the panel's port.
    #[serde(rename = "snpanel-login")]
    PanelLogin,
    /// WordPress sign-ins, from every site's access log.
    #[serde(rename = "snpanel-wordpress")]
    Wordpress,
    /// Password-protected directories, from every site's error log.
    #[serde(rename = "nginx-http-auth")]
    NginxHttpAuth,
    /// Addresses banned again and again: a week, on every port.
    #[serde(rename = "recidive")]
    Recidive,
}

impl Fail2banJail {
    /// In the order the page lists them.
    pub const ALL: [Self; 5] = [
        Self::Sshd,
        Self::PanelLogin,
        Self::Wordpress,
        Self::NginxHttpAuth,
        Self::Recidive,
    ];

    /// The jail's name in fail2ban.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sshd => "sshd",
            Self::PanelLogin => "snpanel-login",
            Self::Wordpress => "snpanel-wordpress",
            Self::NginxHttpAuth => "nginx-http-auth",
            Self::Recidive => "recidive",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|jail| jail.name() == raw)
    }
}

/// The settings the page saves and the helper renders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fail2banConfig {
    /// Addresses never banned, besides loopback, which always is.
    pub ignoreip: Vec<IpOrCidr>,
    /// Seconds an address stays banned.
    pub bantime: u32,
    /// Seconds over which failures are counted.
    pub findtime: u32,
    /// Failures within `findtime` that earn a ban.
    pub maxretry: u32,
    /// The jails switched on.
    pub jails: Vec<Fail2banJail>,
}

impl Fail2banConfig {
    /// A minute to a year.
    pub const BANTIME: std::ops::RangeInclusive<u32> = 60..=31_536_000;
    /// A minute to a week.
    pub const FINDTIME: std::ops::RangeInclusive<u32> = 60..=604_800;
    pub const MAXRETRY: std::ops::RangeInclusive<u32> = 1..=100;
    /// A list longer than this is a mistake, not a policy.
    pub const MAX_IGNOREIP: usize = 100;

    /// Fail2ban's own defaults - ten failures' worth of patience is not one
    /// of them: five in ten minutes, banned for ten - with every jail that
    /// needs nothing extra switched on, and the address of the administrator
    /// who installs it never banned.
    ///
    /// `nginx-http-auth` starts off: it only matters on a site with a
    /// password-protected directory, and a customer mistyping their own
    /// password would lose every site on the server for ten minutes.
    pub fn defaults(installer: Option<std::net::IpAddr>) -> Self {
        let ignoreip = installer
            .and_then(|addr| IpOrCidr::parse(&addr.to_string()).ok())
            .into_iter()
            .collect();
        Self {
            ignoreip,
            bantime: 600,
            findtime: 600,
            maxretry: 5,
            jails: vec![
                Fail2banJail::Sshd,
                Fail2banJail::PanelLogin,
                Fail2banJail::Wordpress,
                Fail2banJail::Recidive,
            ],
        }
    }

    /// Every value inside its range, and no list longer than it should be.
    ///
    /// Checked by the IPC when a request is built from arguments, and again
    /// by the helper before it writes anything: a request that arrives over
    /// the socket was deserialized without passing through the first.
    pub fn validate(&self) -> Result<(), String> {
        let within = |what: &str, value: u32, range: &std::ops::RangeInclusive<u32>| {
            if range.contains(&value) {
                Ok(())
            } else {
                Err(format!(
                    "{what} must be between {} and {}, not {value}",
                    range.start(),
                    range.end()
                ))
            }
        };
        within("bantime", self.bantime, &Self::BANTIME)?;
        within("findtime", self.findtime, &Self::FINDTIME)?;
        within("maxretry", self.maxretry, &Self::MAXRETRY)?;
        if self.ignoreip.len() > Self::MAX_IGNOREIP {
            return Err(format!(
                "at most {} addresses can be exempt, not {}",
                Self::MAX_IGNOREIP,
                self.ignoreip.len()
            ));
        }
        Ok(())
    }

    /// Whether `jail` is switched on.
    pub fn enables(&self, jail: Fail2banJail) -> bool {
        self.jails.contains(&jail)
    }

    /// Whether `addr` is exempt: loopback, or inside an `ignoreip` entry.
    pub fn exempts(&self, addr: std::net::IpAddr) -> bool {
        let addr = addr.to_canonical();
        addr.is_loopback() || self.ignoreip.iter().any(|entry| contains(entry, addr))
    }
}

/// Whether the network `entry` names contains `addr`.
fn contains(entry: &IpOrCidr, addr: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match (entry.addr().to_canonical(), addr) {
        (IpAddr::V4(net), IpAddr::V4(a)) => {
            let prefix = u32::from(entry.prefix().min(32));
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(net) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(a)) => {
            let prefix = u32::from(entry.prefix().min(128));
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(net) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_jail_is_named_as_fail2ban_names_it() {
        for jail in Fail2banJail::ALL {
            assert_eq!(Fail2banJail::parse(jail.name()), Some(jail));
            assert_eq!(
                serde_json::to_string(&jail).unwrap(),
                format!("\"{}\"", jail.name())
            );
        }
        assert_eq!(Fail2banJail::parse("sshd-ddos"), None);
        assert_eq!(Fail2banJail::parse(""), None);
    }

    #[test]
    fn the_defaults_are_valid_and_spare_the_installer() {
        let admin: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let config = Fail2banConfig::defaults(Some(admin));
        assert_eq!(config.validate(), Ok(()));
        assert!(config.exempts(admin));
        assert!(!config.enables(Fail2banJail::NginxHttpAuth));
        assert!(config.enables(Fail2banJail::PanelLogin));
        assert!(Fail2banConfig::defaults(None).ignoreip.is_empty());
    }

    #[test]
    fn every_number_has_a_range() {
        let good = Fail2banConfig::defaults(None);
        for (what, broken) in [
            (
                "bantime",
                Fail2banConfig {
                    bantime: 59,
                    ..good.clone()
                },
            ),
            (
                "bantime",
                Fail2banConfig {
                    bantime: 31_536_001,
                    ..good.clone()
                },
            ),
            (
                "findtime",
                Fail2banConfig {
                    findtime: 0,
                    ..good.clone()
                },
            ),
            (
                "findtime",
                Fail2banConfig {
                    findtime: 604_801,
                    ..good.clone()
                },
            ),
            (
                "maxretry",
                Fail2banConfig {
                    maxretry: 0,
                    ..good.clone()
                },
            ),
            (
                "maxretry",
                Fail2banConfig {
                    maxretry: 101,
                    ..good.clone()
                },
            ),
        ] {
            let err = broken.validate().unwrap_err();
            assert!(err.starts_with(what), "{err}");
        }
        for edge in [
            Fail2banConfig {
                bantime: 60,
                findtime: 60,
                maxretry: 1,
                ..good.clone()
            },
            Fail2banConfig {
                bantime: 31_536_000,
                findtime: 604_800,
                maxretry: 100,
                ..good.clone()
            },
        ] {
            assert_eq!(edge.validate(), Ok(()));
        }
        let many = Fail2banConfig {
            ignoreip: (0..=100)
                .map(|i| IpOrCidr::parse(&format!("10.0.{}.{}", i / 250, i % 250)).unwrap())
                .collect(),
            ..good
        };
        assert!(many.validate().unwrap_err().contains("at most 100"));
    }

    /// Anything the page did not send is refused rather than ignored: a field
    /// the helper does not know is a field it would silently not apply.
    #[test]
    fn an_unknown_field_is_refused() {
        let json =
            r#"{"ignoreip":[],"bantime":600,"findtime":600,"maxretry":5,"jails":[],"action":"x"}"#;
        assert!(serde_json::from_str::<Fail2banConfig>(json).is_err());
        let json = r#"{"ignoreip":["not an address"],"bantime":600,"findtime":600,"maxretry":5,"jails":[]}"#;
        assert!(serde_json::from_str::<Fail2banConfig>(json).is_err());
        let json =
            r#"{"ignoreip":[],"bantime":600,"findtime":600,"maxretry":5,"jails":["sshd-ddos"]}"#;
        assert!(serde_json::from_str::<Fail2banConfig>(json).is_err());
    }

    #[test]
    fn exemption_follows_the_networks_listed() {
        let config = Fail2banConfig {
            ignoreip: ["198.51.100.0/24", "2001:db8::/32", "192.0.2.9"]
                .iter()
                .map(|e| IpOrCidr::parse(e).unwrap())
                .collect(),
            ..Fail2banConfig::defaults(None)
        };
        let exempt = |a: &str| config.exempts(a.parse().unwrap());
        assert!(exempt("198.51.100.200"));
        assert!(exempt("2001:db8:1::5"));
        assert!(exempt("192.0.2.9"));
        // Loopback always, and an IPv4 address written the IPv6 way is the
        // same address.
        assert!(exempt("127.0.0.1"));
        assert!(exempt("::1"));
        assert!(exempt("::ffff:198.51.100.1"));
        assert!(!exempt("198.51.101.1"));
        assert!(!exempt("192.0.2.10"));
        assert!(!exempt("2001:db9::1"));
    }
}
