//! Getting an existing panel off plain HTTP.
//!
//! Source: `ensure_panel_https`.
//!
//! The panel takes an admin password and hands out a session token, so it
//! has no business answering in the clear. Boxes installed before that was
//! enforced are still on HTTP, and this is the phase that moves them.
//!
//! A server with no domain has nothing a certificate authority will sign, so
//! it gets a self-signed certificate. That is not security theatre: a
//! warning the operator clicks through once beats a password crossing the
//! network in the clear, every time.

/// What the phase decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The panel's own domain already has a real certificate. Copy it.
    ///
    /// A name the browser trusts beats one it warns about, and when the
    /// panel's hostname *is* the domain in question there is nothing to
    /// choose between.
    UseDomainCertificate { host: String },
    /// A certificate is already configured and both files are there.
    /// Nothing to do.
    KeepExisting,
    /// Mint one. `host` is the name it will be issued for.
    SelfSign { host: String },
}

/// Where a Let's Encrypt certificate for a name would be.
pub fn live_dir(host: &str) -> String {
    format!("/etc/letsencrypt/live/{host}")
}

/// The decision.
///
/// `mode` is `PANEL_SSL_MODE`, and the guard on it is worth stating
/// precisely because it is not obvious: the domain-certificate branch is
/// skipped when the mode is already `letsencrypt` or `domain`. In the
/// ordinary case that changes nothing — a box in one of those modes has
/// `PANEL_SSL_CERT` pointing at files that exist, so it takes
/// [`Decision::KeepExisting`] on the next check anyway.
///
/// Where it does bite: a box in `domain` mode whose copied files have been
/// **deleted** falls through to a self-signed certificate rather than
/// re-copying from `/etc/letsencrypt`. Reproduced rather than corrected —
/// this side is not the place to change what the two implementations
/// disagree about — but recorded here, because "the panel went back to a
/// self-signed certificate on its own" is otherwise a mystery.
/// What the phase found before deciding.
///
/// A struct rather than eight positional arguments, and not only for
/// tidiness: four of them are strings and three are booleans, so a caller
/// that transposed `cert_exists` and `key_exists` would compile, pass most
/// of the tests below, and mint a self-signed certificate over a working
/// one.
#[derive(Debug, Clone, Default)]
pub struct Observed<'a> {
    /// `PANEL_DOMAIN`. Empty when the panel answers on an address.
    pub panel_domain: &'a str,
    /// `PANEL_SSL_MODE`.
    pub mode: &'a str,
    /// `PANEL_SSL_CERT` and `PANEL_SSL_KEY`, as configured.
    pub cert: &'a str,
    pub key: &'a str,
    /// Whether those two paths are files right now.
    pub cert_exists: bool,
    pub key_exists: bool,
    /// Whether `/etc/letsencrypt/live/<domain>` holds both halves.
    pub letsencrypt_present: bool,
    /// The address `hostname -I` reported, if any.
    pub server_ip: &'a str,
}

pub fn decide(seen: &Observed<'_>) -> Decision {
    if !seen.panel_domain.is_empty()
        && seen.letsencrypt_present
        && seen.mode != "letsencrypt"
        && seen.mode != "domain"
    {
        return Decision::UseDomainCertificate {
            host: seen.panel_domain.to_string(),
        };
    }
    if !seen.cert.is_empty() && !seen.key.is_empty() && seen.cert_exists && seen.key_exists {
        return Decision::KeepExisting;
    }
    // `${host:-${server_ip:-127.0.0.1}}` — the domain, then the address,
    // then loopback. Loopback is the last resort rather than a failure: a
    // certificate for 127.0.0.1 is still a certificate, and the alternative
    // is leaving the password on the wire.
    let host = if !seen.panel_domain.is_empty() {
        seen.panel_domain
    } else if !seen.server_ip.is_empty() {
        seen.server_ip
    } else {
        "127.0.0.1"
    };
    Decision::SelfSign {
        host: host.to_string(),
    }
}

/// `/etc/snpanel`, and the two files in it.
///
/// `0750` on the directory and `0640` on the files, both `root:snpanel`. The
/// private key is readable by the panel's group and by nothing else — the
/// panel has to read it to serve TLS, and a key any local account could read
/// is a key that can impersonate the panel to every browser that trusts it.
pub const DIR_MODE: u32 = 0o750;
pub const FILE_MODE: u32 = 0o640;
pub const DIR: &str = "/etc/snpanel";

pub const DOMAIN_CERT: &str = "/etc/snpanel/panel-fullchain.pem";
pub const DOMAIN_KEY: &str = "/etc/snpanel/panel-privkey.pem";
pub const SELFSIGNED_CERT: &str = "/etc/snpanel/panel-selfsigned-fullchain.pem";
pub const SELFSIGNED_KEY: &str = "/etc/snpanel/panel-selfsigned-privkey.pem";

/// What goes into `PANEL_SSL_MODE` afterwards, so a later run can tell how
/// the panel got its certificate.
pub fn mode_for(decision: &Decision) -> Option<&'static str> {
    match decision {
        Decision::UseDomainCertificate { .. } => Some("domain"),
        Decision::SelfSign { .. } => Some("selfsigned"),
        Decision::KeepExisting => None,
    }
}

/// The URL the panel moves to.
pub fn https_url(host: &str, port: u16) -> String {
    format!("https://{host}:{port}")
}

/// Whether a certificate that could not be generated stops the update.
///
/// It does not. An update that bricked a working panel because `openssl`
/// was missing would be a worse outcome than the one it was trying to fix:
/// the box stays on HTTP, the message says so, and the operator can act on
/// it at a time of their choosing.
pub const GENERATION_FAILURE_IS_FATAL: bool = false;
pub const GENERATION_FAILED: &str =
    "    Could not generate a certificate; leaving the panel on HTTP";

#[cfg(test)]
mod tests {
    use super::*;

    /// A name the browser trusts beats one it warns about.
    #[test]
    fn a_domain_with_a_real_certificate_uses_it() {
        assert_eq!(
            decide(&Observed {
                panel_domain: "a.com",
                mode: "",
                cert: "",
                key: "",
                cert_exists: false,
                key_exists: false,
                letsencrypt_present: true,
                server_ip: "203.0.113.10",
            }),
            Decision::UseDomainCertificate {
                host: "a.com".into()
            }
        );
        assert_eq!(live_dir("a.com"), "/etc/letsencrypt/live/a.com");
    }

    /// Already configured and both files present: nothing to do. Re-issuing
    /// on every update would replace a trusted certificate with a
    /// self-signed one.
    #[test]
    fn an_existing_certificate_is_left_alone() {
        assert_eq!(
            decide(&Observed {
                panel_domain: "a.com",
                mode: "selfsigned",
                cert: "/c",
                key: "/k",
                cert_exists: true,
                key_exists: true,
                letsencrypt_present: false,
                server_ip: "",
            }),
            Decision::KeepExisting
        );
        assert_eq!(mode_for(&Decision::KeepExisting), None);
    }

    /// A configured path that no longer points at a file is not a
    /// certificate, so the panel gets a new one rather than failing its
    /// handshake for ever.
    #[test]
    fn a_certificate_whose_files_are_gone_is_replaced() {
        for (cert_exists, key_exists) in [(false, true), (true, false), (false, false)] {
            assert_eq!(
                decide(&Observed {
                    panel_domain: "a.com",
                    mode: "selfsigned",
                    cert: "/c",
                    key: "/k",
                    cert_exists,
                    key_exists,
                    letsencrypt_present: false,
                    server_ip: "",
                }),
                Decision::SelfSign {
                    host: "a.com".into()
                },
                "{cert_exists}/{key_exists}"
            );
        }
    }

    /// The host falls back domain, then address, then loopback. Loopback is
    /// a last resort rather than a failure: a certificate for 127.0.0.1 is
    /// still a certificate, and the alternative is a password on the wire.
    #[test]
    fn the_name_falls_back_to_the_address_and_then_to_loopback() {
        assert_eq!(
            decide(&Observed {
                panel_domain: "a.com",
                mode: "",
                cert: "",
                key: "",
                cert_exists: false,
                key_exists: false,
                letsencrypt_present: false,
                server_ip: "203.0.113.10",
            }),
            Decision::SelfSign {
                host: "a.com".into()
            }
        );
        assert_eq!(
            decide(&Observed {
                panel_domain: "",
                mode: "",
                cert: "",
                key: "",
                cert_exists: false,
                key_exists: false,
                letsencrypt_present: false,
                server_ip: "203.0.113.10",
            }),
            Decision::SelfSign {
                host: "203.0.113.10".into()
            }
        );
        assert_eq!(
            decide(&Observed {
                panel_domain: "",
                mode: "",
                cert: "",
                key: "",
                cert_exists: false,
                key_exists: false,
                letsencrypt_present: false,
                server_ip: "",
            }),
            Decision::SelfSign {
                host: "127.0.0.1".into()
            }
        );
    }

    /// A box already in one of the two certificate-backed modes does not
    /// re-copy. In the ordinary case that is invisible, because such a box
    /// takes `KeepExisting` anyway — but when the copied files have been
    /// deleted it drops to a self-signed certificate rather than re-copying
    /// from `/etc/letsencrypt`.
    ///
    /// Reproduced rather than corrected, and asserted so that "the panel
    /// went back to a self-signed certificate on its own" has an
    /// explanation somebody can find.
    #[test]
    fn a_box_already_in_domain_mode_does_not_recopy() {
        // The ordinary case: files present, so nothing changes either way.
        assert_eq!(
            decide(&Observed {
                panel_domain: "a.com",
                mode: "domain",
                cert: DOMAIN_CERT,
                key: DOMAIN_KEY,
                cert_exists: true,
                key_exists: true,
                letsencrypt_present: true,
                server_ip: "",
            }),
            Decision::KeepExisting
        );
        // The case that bites: files gone, Let's Encrypt still has them, and
        // the answer is a self-signed certificate rather than a re-copy.
        assert_eq!(
            decide(&Observed {
                panel_domain: "a.com",
                mode: "domain",
                cert: DOMAIN_CERT,
                key: DOMAIN_KEY,
                cert_exists: false,
                key_exists: false,
                letsencrypt_present: true,
                server_ip: "",
            }),
            Decision::SelfSign {
                host: "a.com".into()
            }
        );
        assert_eq!(
            decide(&Observed {
                panel_domain: "a.com",
                mode: "letsencrypt",
                cert: "",
                key: "",
                cert_exists: false,
                key_exists: false,
                letsencrypt_present: true,
                server_ip: "",
            }),
            Decision::SelfSign {
                host: "a.com".into()
            }
        );
    }

    /// A key any local account could read is a key that can impersonate the
    /// panel to every browser that trusts it.
    #[test]
    fn the_private_key_is_readable_only_by_the_panels_group() {
        assert_eq!(FILE_MODE & 0o007, 0, "the key is world-readable");
        assert_eq!(FILE_MODE & 0o040, 0o040, "the panel cannot read its key");
        assert_eq!(FILE_MODE & 0o020, 0, "the panel can rewrite its key");
        // And the directory does not let anyone else in to look.
        assert_eq!(DIR_MODE & 0o007, 0);
        assert_eq!(DIR_MODE & 0o050, 0o050);
    }

    /// The four paths are distinct, so a self-signed certificate never
    /// overwrites a copied one — which is what lets the domain branch be
    /// taken again later without anything having been lost.
    #[test]
    fn the_copied_and_minted_certificates_do_not_share_a_path() {
        let paths = [DOMAIN_CERT, DOMAIN_KEY, SELFSIGNED_CERT, SELFSIGNED_KEY];
        let unique: std::collections::BTreeSet<&str> = paths.iter().copied().collect();
        assert_eq!(unique.len(), 4);
        assert!(paths.iter().all(|p| p.starts_with(DIR)));
    }

    #[test]
    fn the_mode_records_how_the_certificate_was_obtained() {
        assert_eq!(
            mode_for(&Decision::UseDomainCertificate { host: "a".into() }),
            Some("domain")
        );
        assert_eq!(
            mode_for(&Decision::SelfSign { host: "a".into() }),
            Some("selfsigned")
        );
    }

    /// An update that bricked a working panel because `openssl` was missing
    /// would be worse than the problem it was fixing.
    #[test]
    fn a_certificate_that_cannot_be_generated_leaves_the_panel_working() {
        const { assert!(!GENERATION_FAILURE_IS_FATAL) };
        assert!(GENERATION_FAILED.contains("leaving the panel on HTTP"));
    }

    #[test]
    fn the_panel_moves_to_an_https_url_on_its_own_port() {
        assert_eq!(https_url("a.com", 2222), "https://a.com:2222");
        assert_eq!(https_url("203.0.113.10", 8443), "https://203.0.113.10:8443");
    }
}
