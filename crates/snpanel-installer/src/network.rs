//! The firewall, and IPv6.
//!
//! Source: `setup_firewall`, `enable_ipv6_when_available`.
//!
//! Both phases are thin: the work is done by helper verbs that already exist
//! on this side. What is here is the part the shell does around them, which
//! in both cases is a decision about what a failure means.

/// The firewall phase.
///
/// IP filtering is driven by `snpanel-helper`, which picks its backend per
/// platform — iptables plus ipset on Ubuntu, nftables on EL.
pub mod firewall {
    /// SSH ports seeded before the firewall is turned on.
    ///
    /// The helper's own discovery reads `sshd -T`, which misses ports that
    /// are only visible from the live SSH session or from a non-default
    /// `sshd_config`. Seeding them first is the difference between an
    /// install that finishes and one that locks the operator out of the box
    /// it is running on.
    ///
    /// Reproduces the shell's `[[ "$p" =~ ^[0-9]{1,5}$ ]]`: digits only, one
    /// to five of them. Note what that does *not* check — 99999 passes here
    /// and is not a port. The helper refuses it, which is where that check
    /// belongs; this one exists to keep obvious rubbish out of the argv.
    pub fn seedable_port(raw: &str) -> bool {
        let raw = raw.trim();
        (1..=5).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_digit())
    }

    /// One helper call.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Step {
        /// `firewall-allow-port <port> tcp`, for an SSH port the helper's own
        /// discovery would miss.
        AllowPort(String),
        /// `firewall-migrate`, which brings an older box's rules forward.
        Migrate,
        /// `firewall-enable`.
        Enable,
    }

    /// The phase, in order.
    ///
    /// Two properties of that order are what make it safe to run over a live
    /// SSH session, and both are asserted:
    ///
    /// * every seeded port is allowed **before** anything enables the
    ///   firewall — the other way round is an operator locked out of the box
    ///   the installer is running on;
    /// * `Enable` is always last and always present. `firewall-migrate`
    ///   inherits the previous state when it is upgrading an existing box,
    ///   which is right for an upgrade and wrong for a new install, where
    ///   there is no previous state and "inherit" would mean "leave it off".
    ///   A panel installed with its firewall off is a box whose operator
    ///   believes it is protected.
    ///
    /// A failure of any step does not end the install: the shell wraps the
    /// whole phase in `set +e` and returns 0. That is the right trade here —
    /// a firewall that half-applied is recoverable from the panel, and an
    /// install that died at this point leaves a box with no panel to recover
    /// it from.
    pub fn steps<S: AsRef<str>>(ssh_ports: &[S]) -> Vec<Step> {
        let mut out: Vec<Step> = Vec::new();
        for port in ssh_ports {
            let port = port.as_ref().trim();
            if seedable_port(port) && !out.contains(&Step::AllowPort(port.to_string())) {
                out.push(Step::AllowPort(port.to_string()));
            }
        }
        out.push(Step::Migrate);
        out.push(Step::Enable);
        out
    }
}

/// IPv6.
///
/// A fresh install takes the network as it finds it: a machine that already
/// holds a global IPv6 address should serve on it without somebody having to
/// go and find the switch. Servers that *update* into this are left alone —
/// their admin decides.
///
/// Nothing here can conjure an address the provider assigned but never
/// configured; only the addresses the machine actually holds are detected.
pub mod ipv6 {
    /// What the phase concluded.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Result_ {
        /// No global address. Not a failure — most machines are like this.
        Off,
        /// Detected and enabled, with the first address found.
        On(String),
        /// Detected but the helper refused to enable it.
        ///
        /// Distinguished from `Off` on purpose: `Off` needs no action and
        /// this needs the operator to go and look, so the message points at
        /// the panel setting rather than leaving them to find it.
        Failed,
    }

    impl Result_ {
        /// The value written into `IPV6_RESULT`, which the final summary
        /// reads.
        pub fn tag(&self) -> String {
            match self {
                Self::Off => "off".to_string(),
                Self::On(address) => format!("on:{address}"),
                Self::Failed => "failed".to_string(),
            }
        }
    }

    /// Whether the helper reported a global address.
    ///
    /// The shell tests the whole blob with `*"available=yes"*` rather than
    /// parsing the line, and this matches it. A stricter parse would differ
    /// on output shapes neither side will ever see, and matching is worth
    /// more than tidiness while both are running.
    pub fn available(status: &str) -> bool {
        status.contains("available=yes")
    }

    /// The address to report, out of `addresses=a,b,c`.
    ///
    /// `sed -n 's/^addresses=//p' | head -n1` takes the whole remainder of
    /// the first such line — so with several addresses this is the entire
    /// comma-separated list, not the first address. Reproduced, because the
    /// message it lands in is one an operator compares against what the
    /// panel's settings page shows.
    pub fn reported_address(status: &str) -> String {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("addresses=") {
                return rest.to_string();
            }
        }
        String::new()
    }

    /// The line the installer logs.
    pub fn message(result: &Result_) -> String {
        match result {
            Result_::Off => "No global IPv6 address on this server; IPv6 stays off".to_string(),
            Result_::On(address) => {
                format!("IPv6 detected ({address}); websites and panel will answer on it too")
            }
            Result_::Failed => "WARNING: IPv6 was detected but could not be enabled; \
                                turn it on from Panel settings"
                .to_string(),
        }
    }

    /// The whole decision, given what the helper said and whether enabling
    /// worked.
    pub fn decide(status: Option<&str>, enabled: bool) -> Result_ {
        let Some(status) = status else {
            return Result_::Off;
        };
        if !available(status) {
            return Result_::Off;
        }
        if enabled {
            Result_::On(reported_address(status))
        } else {
            Result_::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ipv6::Result_;
    use super::*;

    #[test]
    fn a_port_is_one_to_five_digits_and_nothing_else() {
        for good in ["22", "2222", "65535", "1", "99999"] {
            assert!(firewall::seedable_port(good), "{good}");
        }
        for bad in ["", "123456", "22a", "-22", "2 2", "0x16", " "] {
            assert!(!firewall::seedable_port(bad), "{bad:?}");
        }
    }

    /// 99999 is not a port, and this check passes it. That is the shell's
    /// behaviour and it is deliberate: the helper refuses it, which is where
    /// the real check belongs. Recorded so a future tightening here is a
    /// decision rather than an accident.
    #[test]
    fn the_seed_check_is_a_shape_check_and_not_a_range_check() {
        assert!(firewall::seedable_port("99999"));
    }

    /// Allowing the ports after enabling the firewall is an operator locked
    /// out of the box the installer is running on.
    #[test]
    fn every_ssh_port_is_allowed_before_anything_enables_the_firewall() {
        let steps = firewall::steps(&["22", "2222"]);
        let enable = steps
            .iter()
            .position(|s| *s == firewall::Step::Enable)
            .expect("the enable");
        let migrate = steps
            .iter()
            .position(|s| *s == firewall::Step::Migrate)
            .expect("the migrate");
        for (at, step) in steps.iter().enumerate() {
            if matches!(step, firewall::Step::AllowPort(_)) {
                assert!(at < migrate, "a port is seeded after the migrate");
                assert!(at < enable, "a port is seeded after the firewall is on");
            }
        }
    }

    /// `firewall-migrate` inherits the previous state, which on a fresh
    /// install means "leave it off". A panel installed with its firewall off
    /// is a box whose operator believes it is protected.
    #[test]
    fn the_firewall_is_always_turned_on_last() {
        for ports in [vec![], vec!["22"], vec!["22", "2222", "nonsense"]] {
            let steps = firewall::steps(&ports);
            assert_eq!(
                steps.last(),
                Some(&firewall::Step::Enable),
                "{ports:?} did not end by enabling the firewall"
            );
        }
    }

    /// Rubbish from `detect_ssh_ports` never reaches the helper's argv, and
    /// a port listed twice is asked for once.
    #[test]
    fn only_port_shaped_values_are_seeded_and_only_once() {
        let steps = firewall::steps(&["22", "22", "not-a-port", "", "2222"]);
        let allowed: Vec<&str> = steps
            .iter()
            .filter_map(|s| match s {
                firewall::Step::AllowPort(p) => Some(p.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(allowed, ["22", "2222"]);
    }

    #[test]
    fn no_global_address_is_not_a_failure() {
        let status = "available=no\nenabled=no\naddresses=\n";
        assert_eq!(ipv6::decide(Some(status), false), Result_::Off);
        assert_eq!(ipv6::decide(Some(status), true), Result_::Off);
        // And the helper not answering at all is the same conclusion: this
        // cannot conjure an address, so silence means off.
        assert_eq!(ipv6::decide(None, true), Result_::Off);
        assert_eq!(ipv6::decide(Some(status), false).tag(), "off");
    }

    #[test]
    fn a_detected_address_is_turned_on_and_reported() {
        let status = "available=yes\nenabled=no\naddresses=2001:db8::1\n";
        let result = ipv6::decide(Some(status), true);
        assert_eq!(result, Result_::On("2001:db8::1".into()));
        assert_eq!(result.tag(), "on:2001:db8::1");
        assert!(ipv6::message(&result).contains("2001:db8::1"));
        assert!(ipv6::message(&result).contains("websites and panel will answer on it too"));
    }

    /// `head -n1` takes the whole first line after the prefix, so several
    /// addresses come through as the list — not as the first one. The
    /// message an operator reads then matches what the panel's settings page
    /// shows them.
    #[test]
    fn several_addresses_are_reported_as_the_list_the_helper_gave() {
        let status = "available=yes\nenabled=no\naddresses=2001:db8::1,2001:db8::2\n";
        assert_eq!(ipv6::reported_address(status), "2001:db8::1,2001:db8::2");
        assert_eq!(ipv6::reported_address("available=yes\n"), "");
    }

    /// "Detected but not enabled" needs the operator to go and look, and
    /// "off" does not. Collapsing the two would lose the only signal that
    /// something went wrong.
    #[test]
    fn a_detection_that_could_not_be_enabled_is_distinct_from_off() {
        let status = "available=yes\nenabled=no\naddresses=2001:db8::1\n";
        let failed = ipv6::decide(Some(status), false);
        assert_eq!(failed, Result_::Failed);
        assert_ne!(failed, Result_::Off);
        assert_eq!(failed.tag(), "failed");
        let message = ipv6::message(&failed);
        assert!(message.starts_with("WARNING: "));
        // And it says where the switch is, rather than leaving them to look.
        assert!(message.contains("turn it on from Panel settings"));
    }
}
