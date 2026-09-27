//! The panel's own certificate, and the `.env` edits around it.
//!
//! Source: `setup_selfsigned_ssl`, `setup_ssl`, `write_login_info` and
//! `write_update_state`.
//!
//! A panel with no domain still takes an admin password, so it gets a
//! certificate of its own rather than answering in the clear: the browser
//! warns once, which is one warning more than plain HTTP gives anybody.
//!
//! The part worth testing is not the `openssl` call — it is the subject
//! alternative name handed to it, and the `.env` rewrites that follow. A
//! certificate whose SAN does not cover the address the operator types is a
//! certificate the browser refuses **and** a panel that then reverts to HTTP.

/// The `subjectAltName` for a self-signed panel certificate.
///
/// `DNS:` for a hostname and `IP:` for an address, because a browser checks
/// the two differently and a bare `DNS:203.0.113.10` matches nothing. The
/// server's own address is added as a second SAN when it differs from the
/// name being certified, so an operator who reaches the panel by address
/// after setting a domain still gets a certificate that covers it.
///
/// The address test is the shell's `^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`, which
/// is looser than an IPv4 address really is — `999.999.999.999` passes it.
/// Reproduced rather than tightened: `openssl` is the one that decides, and
/// a stricter test here would change which hosts get a certificate at all.
pub fn subject_alt_name(host: &str, server_ip: Option<&str>) -> String {
    let mut san = if looks_like_ipv4(host) {
        format!("IP:{host}")
    } else {
        format!("DNS:{host}")
    };
    if let Some(ip) = server_ip.filter(|ip| !ip.is_empty() && *ip != host) {
        san.push_str(&format!(",IP:{ip}"));
    }
    san
}

/// `^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$` — four runs of digits, and nothing
/// about their size.
fn looks_like_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// The name the panel certifies itself under.
///
/// Source: `host="${PANEL_DOMAIN:-${SERVER_IP:-127.0.0.1}}"`.
pub fn certificate_host(panel_domain: &str, server_ip: &str) -> String {
    for candidate in [panel_domain, server_ip] {
        if !candidate.is_empty() {
            return candidate.to_string();
        }
    }
    "127.0.0.1".to_string()
}

/// Set a key in an `.env`, the way the shell's `sed` does.
///
/// `s#^KEY=.*#KEY=value#` replaces **every** line that starts with the key,
/// not just the first — so a file that somehow carried two of them ends up
/// with two identical ones rather than one of each. Reproduced, because a
/// port that quietly deduplicated would be a port whose output differs from
/// the file every existing box has.
///
/// A key that is not there at all is **not** added: the shell's `sed` has
/// nothing to match. The one place that needs it appended says so explicitly,
/// which is what [`set_or_append`] is for.
pub fn set_key(contents: &str, key: &str, value: &str) -> String {
    let mut out = String::with_capacity(contents.len() + value.len());
    for line in contents.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        if bare.starts_with(&format!("{key}=")) {
            out.push_str(&format!("{key}={value}"));
            if line.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }
        out.push_str(line);
    }
    out
}

/// Source: `grep -q "^KEY=" && sed ... || echo "KEY=value" >>`.
///
/// Used for `PANEL_SSL_MODE`, which older installs do not have in their
/// `.env` at all — so setting it has to be able to create it.
pub fn set_or_append(contents: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    if contents.lines().any(|line| line.starts_with(&prefix)) {
        return set_key(contents, key, value);
    }
    let mut out = contents.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("{key}={value}\n"));
    out
}

/// The four keys a certificate lands in, and the two it is taken back out
/// of.
///
/// Reverting is not the same as never having set them: a panel that failed
/// to come up over HTTPS has to go back to a working HTTP, and leaving a
/// `PANEL_SSL_CERT` pointing at a certificate the panel could not serve is
/// how an operator ends up locked out of their own box.
pub fn env_with_certificate(contents: &str, cert: &str, key: &str, panel_url: &str) -> String {
    let mut out = set_key(contents, "PANEL_SSL_CERT", cert);
    out = set_key(&out, "PANEL_SSL_KEY", key);
    out = set_key(&out, "PANEL_URL", panel_url);
    set_key(&out, "ALLOWED_ORIGINS", panel_url)
}

/// Back to HTTP, because the panel did not answer over HTTPS.
///
/// **Better a panel that answers than a locked-out operator.** The
/// certificate stays on disk; only the panel's own use of it is undone.
pub fn env_without_certificate(contents: &str, panel_url: &str) -> String {
    let mut out = set_key(contents, "PANEL_SSL_CERT", "");
    out = set_key(&out, "PANEL_SSL_KEY", "");
    out = set_key(&out, "PANEL_SSL_MODE", "");
    out = set_key(&out, "PANEL_URL", panel_url);
    set_key(&out, "ALLOWED_ORIGINS", panel_url)
}

/// `/root/login.txt`, mode `0600`.
pub fn login_info(panel_url: &str, admin_password: &str) -> String {
    format!(
        "Panel URL: {panel_url}\n\
         User: admin\n\
         Password: {admin_password}\n"
    )
}

/// `/var/lib/snpanel/update-status.json`, mode `0640`.
///
/// Written at the end of an install so the updater does not immediately
/// offer the version that was just installed.
pub fn update_status(version: &str, now: &str) -> String {
    format!(
        r#"{{
  "current_version": "{version}",
  "latest_tag": "v{version}",
  "latest_version": "{version}",
  "last_checked_at": "{now}",
  "last_update_finished_at": "{now}",
  "last_update_ref": "v{version}",
  "last_update_status": "installed"
}}
"#
    )
}

/// The version an install records, from `VERSION` or from the Python.
///
/// Source: `source_version`, and the `${version:-1.0.59}` after it — a tree
/// with neither still has to write a number, because the updater reads this
/// file and a missing one is treated as "never installed".
pub fn source_version(version_file: Option<&str>, version_py: Option<&str>) -> String {
    if let Some(raw) = version_file {
        let digits: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if !digits.is_empty() {
            return digits;
        }
    }
    if let Some(py) = version_py {
        for line in py.lines() {
            // `s/^APP_VERSION = "([^"]+)"/\1/p`, first match only.
            let Some(rest) = line.strip_prefix("APP_VERSION = \"") else {
                continue;
            };
            if let Some((value, _)) = rest.split_once('"') {
                if !value.is_empty() {
                    return value.to_string();
                }
            }
        }
    }
    "1.0.59".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hostname_is_certified_by_name_and_an_address_by_address() {
        assert_eq!(
            subject_alt_name("panel.example.com", None),
            "DNS:panel.example.com"
        );
        assert_eq!(subject_alt_name("203.0.113.10", None), "IP:203.0.113.10");
    }

    /// An operator who set a domain can still reach the panel by address,
    /// and a certificate that does not cover it is a warning they cannot
    /// click past on some clients.
    #[test]
    fn the_servers_own_address_is_a_second_name() {
        assert_eq!(
            subject_alt_name("panel.example.com", Some("203.0.113.10")),
            "DNS:panel.example.com,IP:203.0.113.10"
        );
        // Not twice, when the host *is* the address.
        assert_eq!(
            subject_alt_name("203.0.113.10", Some("203.0.113.10")),
            "IP:203.0.113.10"
        );
        assert_eq!(
            subject_alt_name("panel.example.com", Some("")),
            "DNS:panel.example.com"
        );
    }

    /// The shell's test is four runs of digits and says nothing about their
    /// size. Reproduced rather than tightened: `openssl` decides, and a
    /// stricter test here would change which hosts get a certificate at all.
    #[test]
    fn the_address_test_is_the_shells_loose_one() {
        assert!(looks_like_ipv4("1.2.3.4"));
        assert!(looks_like_ipv4("999.999.999.999"));
        assert!(!looks_like_ipv4("1.2.3"));
        assert!(!looks_like_ipv4("1.2.3.4.5"));
        assert!(!looks_like_ipv4("1.2.3.x"));
        assert!(!looks_like_ipv4("::1"));
        assert!(!looks_like_ipv4(""));
    }

    #[test]
    fn the_certificate_host_falls_back_to_loopback() {
        assert_eq!(
            certificate_host("panel.example.com", "203.0.113.10"),
            "panel.example.com"
        );
        assert_eq!(certificate_host("", "203.0.113.10"), "203.0.113.10");
        assert_eq!(certificate_host("", ""), "127.0.0.1");
    }

    const ENV: &str = "APP_ENV=production\n\
                       PANEL_SSL_CERT=\n\
                       PANEL_SSL_KEY=\n\
                       PANEL_URL=http://x:2222\n\
                       ALLOWED_ORIGINS=http://x:2222\n";

    #[test]
    fn a_key_is_replaced_in_place() {
        let out = set_key(ENV, "PANEL_URL", "https://x:2222");
        assert!(out.contains("PANEL_URL=https://x:2222\n"));
        // And nothing else moved.
        assert_eq!(out.lines().count(), ENV.lines().count());
        assert!(out.starts_with("APP_ENV=production\n"));
    }

    /// `sed s#^KEY=.*#...#` has no `1` address on it, so it replaces every
    /// matching line. A port that deduplicated would produce a file unlike
    /// the one every existing box has.
    #[test]
    fn every_matching_line_is_replaced_not_only_the_first() {
        let doubled = "PANEL_URL=a\nOTHER=1\nPANEL_URL=b\n";
        assert_eq!(
            set_key(doubled, "PANEL_URL", "c"),
            "PANEL_URL=c\nOTHER=1\nPANEL_URL=c\n"
        );
    }

    /// A key the file does not have is not added by `sed`. The one place
    /// that needs it appended asks for that explicitly.
    #[test]
    fn a_missing_key_is_not_invented() {
        assert_eq!(set_key(ENV, "PANEL_SSL_MODE", "selfsigned"), ENV);
        let appended = set_or_append(ENV, "PANEL_SSL_MODE", "selfsigned");
        assert!(appended.ends_with("PANEL_SSL_MODE=selfsigned\n"));
        // And appending to a file that already has it replaces instead.
        assert_eq!(
            set_or_append(&appended, "PANEL_SSL_MODE", "letsencrypt")
                .matches("PANEL_SSL_MODE=")
                .count(),
            1
        );
    }

    /// The name has to match whole: `PANEL_URL` must not claim
    /// `PANEL_URL_EXTRA`, or setting one would silently rewrite the other.
    #[test]
    fn a_key_does_not_claim_the_ones_it_prefixes() {
        let file = "PANEL_URL=a\nPANEL_URL_EXTRA=b\n";
        assert_eq!(
            set_key(file, "PANEL_URL", "c"),
            "PANEL_URL=c\nPANEL_URL_EXTRA=b\n"
        );
    }

    #[test]
    fn enabling_and_reverting_move_the_same_four_keys() {
        let on = env_with_certificate(
            ENV,
            "/etc/snpanel/panel-selfsigned-fullchain.pem",
            "/etc/snpanel/panel-selfsigned-privkey.pem",
            "https://x:2222",
        );
        assert!(on.contains("PANEL_SSL_CERT=/etc/snpanel/panel-selfsigned-fullchain.pem\n"));
        assert!(on.contains("ALLOWED_ORIGINS=https://x:2222\n"));

        let back = env_without_certificate(&on, "http://x:2222");
        assert!(back.contains("PANEL_SSL_CERT=\n"));
        assert!(back.contains("PANEL_SSL_KEY=\n"));
        assert!(back.contains("PANEL_URL=http://x:2222\n"));
        assert!(back.contains("ALLOWED_ORIGINS=http://x:2222\n"));
    }

    /// **Better a panel that answers than a locked-out operator.** A revert
    /// that left `PANEL_SSL_CERT` pointing at a certificate the panel could
    /// not serve is how somebody loses access to their own box.
    #[test]
    fn a_revert_leaves_nothing_pointing_at_the_certificate() {
        let on = env_with_certificate(
            ENV,
            "/etc/snpanel/c.pem",
            "/etc/snpanel/k.pem",
            "https://x:2222",
        );
        let on = set_or_append(&on, "PANEL_SSL_MODE", "selfsigned");
        let back = env_without_certificate(&on, "http://x:2222");
        assert!(!back.contains("/etc/snpanel/c.pem"));
        assert!(!back.contains("/etc/snpanel/k.pem"));
        assert!(back.contains("PANEL_SSL_MODE=\n"));
        assert!(!back.contains("https://"));
    }

    #[test]
    fn the_login_file_is_three_lines() {
        assert_eq!(
            login_info("https://x:2222", "s3cret"),
            "Panel URL: https://x:2222\nUser: admin\nPassword: s3cret\n"
        );
    }

    #[test]
    fn the_update_state_says_the_install_is_current() {
        let json = update_status("1.0.59", "2026-01-01T00:00:00Z");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("it parses");
        assert_eq!(parsed["current_version"], "1.0.59");
        assert_eq!(parsed["latest_tag"], "v1.0.59");
        assert_eq!(parsed["last_update_status"], "installed");
        // Same stamp on both, so the updater does not think a check is due.
        assert_eq!(parsed["last_checked_at"], parsed["last_update_finished_at"]);
    }

    #[test]
    fn the_version_comes_from_the_file_then_the_python_then_a_default() {
        assert_eq!(source_version(Some(" 1.2.3 \n"), None), "1.2.3");
        assert_eq!(
            source_version(None, Some("X = 1\nAPP_VERSION = \"9.9.9\"\nY = 2\n")),
            "9.9.9"
        );
        // A tree with neither still writes a number: the updater reads this
        // file, and a missing one is treated as "never installed".
        assert_eq!(source_version(None, None), "1.0.59");
        assert_eq!(source_version(Some("  \n"), None), "1.0.59");
    }
}
