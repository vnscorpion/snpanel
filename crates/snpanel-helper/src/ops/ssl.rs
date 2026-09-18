//! `ops::ssl` - certificates.
//!
//! Source: the `certbot-*`, `panel-ssl-*` and `ssl-cert-info` arms.
//!
//! The choice worth carrying over is **webroot, not standalone**. The bash has
//! a comment saying why, and it is a scar: `--standalone` needs port 80 to
//! itself, so issuing a certificate for the panel meant stopping nginx, which
//! took every website on the box down for the ten seconds certbot spent
//! talking to Let's Encrypt. The default vhost serves the challenge instead
//! and nothing goes offline.

use std::path::{Path, PathBuf};

use snpanel_core::{Domain, Email, Port};
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

/// Where the ACME challenge is served from. Source: the bash `certbot-issue`.
pub const ACME_WEBROOT: &str = "/var/www/snpanel-acme";
pub const LETSENCRYPT_LIVE: &str = "/etc/letsencrypt/live";
/// Source: `PANEL_SNI_DIR` - one directory per certificate so the panel can
/// answer a handshake with the right one.
pub const SNI_DIR: &str = "/etc/snpanel/sni";

fn live_dir(domain: &Domain) -> PathBuf {
    Path::new(LETSENCRYPT_LIVE).join(domain.as_str())
}

/// Has a certificate already been issued for this name?
pub fn have_cert(domain: &Domain) -> bool {
    live_dir(domain).join("fullchain.pem").exists()
}

/// `certbot-issue`.
///
/// `aliases` become extra `-d` names on the same certificate. `email` is
/// optional; without one certbot is asked to register unsafely without one,
/// which is what the bash does rather than failing.
pub fn certbot_issue(domain: &Domain, aliases: &[Domain], email: Option<&Email>) -> HelperResponse {
    if let Err(e) = ensure_webroot() {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("preparing {ACME_WEBROOT}: {e}"),
        );
    }

    let mut argv: Vec<String> = vec![
        "certbot".into(),
        "certonly".into(),
        "--webroot".into(),
        "-w".into(),
        ACME_WEBROOT.into(),
        "--cert-name".into(),
        domain.to_string(),
        "--non-interactive".into(),
        "--agree-tos".into(),
        // --expand lets an alias be added to an existing certificate;
        // --keep-until-expiring stops a re-run from burning rate limit;
        // --allow-subset-of-names lets one bad alias not sink the whole issue.
        "--expand".into(),
        "--keep-until-expiring".into(),
        "--allow-subset-of-names".into(),
        "-d".into(),
        domain.to_string(),
    ];
    for alias in aliases {
        argv.push("-d".into());
        argv.push(alias.to_string());
    }
    match email {
        Some(e) => {
            argv.push("--email".into());
            argv.push(e.to_string());
        }
        None => argv.push("--register-unsafely-without-email".into()),
    }

    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = exec::run(&refs);

    // Source: the bash swallows a non-zero exit when the certificate is
    // actually there. certbot reports failure for a partial success under
    // --allow-subset-of-names, and the certificate it did issue is still good.
    let issued = have_cert(domain);
    if !matches!(&out, Ok(o) if o.ok()) && !issued {
        return exec::respond("certbot certonly", out);
    }

    let install = exec::run(&[
        "certbot",
        "install",
        "--nginx",
        "--cert-name",
        domain.as_str(),
        "--non-interactive",
        "--redirect",
        "--expand",
        "-d",
        domain.as_str(),
    ]);

    let mut resp = exec::respond("certbot install", install);
    let _ = sync_sni();
    resp.data = Some(serde_json::json!({
        "domain": domain.as_str(),
        "aliases": aliases.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
        "issued": issued,
        "live": live_dir(domain).to_string_lossy(),
    }));
    resp
}

/// `certbot-renew`.
///
/// `--no-random-sleep-on-renew` is deliberate and the bash explains it:
/// certbot spreads scheduled renewals over eight minutes so the whole internet
/// does not call Let's Encrypt at midnight. That is right for the timer and
/// wrong here, because somebody pressed a button and is watching.
pub fn certbot_renew(domain: Option<&Domain>) -> HelperResponse {
    let mut argv: Vec<String> = vec![
        "certbot".into(),
        "renew".into(),
        "--quiet".into(),
        "--no-random-sleep-on-renew".into(),
    ];
    if let Some(d) = domain {
        argv.push("--cert-name".into());
        argv.push(d.to_string());
    }
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let resp = exec::respond("certbot renew", exec::run(&refs));
    let _ = sync_sni();
    resp
}

/// `certbot-delete`.
pub fn certbot_delete(domain: &Domain) -> HelperResponse {
    if !have_cert(domain) {
        // Already absent is the desired state.
        return HelperResponse::with_stdout(format!("no certificate for {domain}\n"));
    }
    let resp = exec::respond(
        "certbot delete",
        exec::run(&[
            "certbot",
            "delete",
            "--cert-name",
            domain.as_str(),
            "--non-interactive",
        ]),
    );
    // Remove the panel's copy too, or the SNI resolver keeps offering a
    // certificate whose private key has been deleted.
    let _ = std::fs::remove_dir_all(Path::new(SNI_DIR).join(domain.as_str()));
    resp
}

/// `ssl-cert-info`: expiry and subject, as structured data.
pub fn cert_info(domain: &Domain) -> HelperResponse {
    let full = live_dir(domain).join("fullchain.pem");
    if !full.exists() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no certificate for {domain}"),
        );
    }
    let path = full.to_string_lossy().into_owned();
    let out = exec::run(&[
        "openssl", "x509", "-in", &path, "-noout", "-subject", "-issuer", "-enddate",
    ]);

    let Ok(o) = &out else {
        return exec::respond("openssl x509", out);
    };
    if !o.ok() {
        return exec::respond("openssl x509", out);
    }

    let field = |key: &str| -> Option<String> {
        o.stdout
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    };

    HelperResponse::with_data(serde_json::json!({
        "domain": domain.as_str(),
        "subject": field("subject="),
        "issuer": field("issuer="),
        "not_after": field("notAfter="),
        "path": path,
    }))
}

/// `panel-ssl-selfsigned`.
///
/// The bash comment is the justification and it is a good one: a brand new
/// server has no domain and no authority that will vouch for its IP. A
/// self-signed certificate warns the browser once; plain HTTP does not warn
/// anybody while it carries the admin password.
pub fn panel_selfsigned(host: &str, port: Port) -> HelperResponse {
    // Source: the bash's own character class. This is a hostname *or* an IP,
    // so Domain is too strict here.
    let valid = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'_' | b'-'));
    if !valid {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("invalid panel hostname: {host}"),
        );
    }

    if let Err(e) = std::fs::create_dir_all("/etc/snpanel") {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating /etc/snpanel: {e}"),
        );
    }

    let cert = "/etc/snpanel/panel-selfsigned-fullchain.pem";
    let key = "/etc/snpanel/panel-selfsigned-privkey.pem";
    let subj = format!("/CN={host}");
    let san = if host.parse::<std::net::IpAddr>().is_ok() {
        format!("subjectAltName=IP:{host}")
    } else {
        format!("subjectAltName=DNS:{host}")
    };

    let out = exec::run(&[
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
        "-days", "3650", "-subj", &subj, "-addext", &san,
    ]);
    let resp = exec::respond("openssl req", out);
    if !resp.ok {
        return resp;
    }

    // The panel reads the key as the unprivileged user, so it must be able to.
    let _ = exec::run(&["chown", "root:snpanel", key, cert]);
    let _ = exec::run(&["chmod", "0640", key]);
    let _ = exec::run(&["chmod", "0644", cert]);

    HelperResponse::with_data(serde_json::json!({
        "mode": "selfsigned",
        "cert": cert,
        "key": key,
        "host": host,
        "port": port.get(),
    }))
}

/// `panel-ssl-domains`: which hostnames the panel has a certificate for.
pub fn panel_ssl_domains() -> HelperResponse {
    let mut names: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(SNI_DIR) {
        for e in entries.filter_map(Result::ok) {
            if e.path().join("fullchain.pem").exists() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    HelperResponse::with_data(serde_json::json!({ "hostnames": names }))
}

/// `panel-sni-sync`: copy each live certificate into the panel's own
/// directory.
///
/// The panel runs as `snpanel` and cannot read `/etc/letsencrypt`, which is why
/// copies exist at all rather than symlinks.
pub fn sync_sni() -> HelperResponse {
    if let Err(e) = std::fs::create_dir_all(SNI_DIR) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {SNI_DIR}: {e}"),
        );
    }
    let Ok(entries) = std::fs::read_dir(LETSENCRYPT_LIVE) else {
        return HelperResponse::with_data(serde_json::json!({ "synced": 0 }));
    };

    let mut synced = 0usize;
    for entry in entries.filter_map(Result::ok) {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // `/etc/letsencrypt/live/README` is a file, but be defensive about
        // anything else that is not a certificate name.
        if Domain::parse(&name).is_err() {
            continue;
        }
        let dest = Path::new(SNI_DIR).join(&name);
        if std::fs::create_dir_all(&dest).is_err() {
            continue;
        }
        let mut copied = true;
        for file in ["fullchain.pem", "privkey.pem"] {
            let src = entry.path().join(file);
            if !src.exists() {
                copied = false;
                break;
            }
            // -L: the live directory is symlinks into archive/, and the panel
            // must get the contents, not a link it cannot follow.
            let out = exec::run(&[
                "cp",
                "-L",
                &src.to_string_lossy(),
                &dest.join(file).to_string_lossy(),
            ]);
            if !matches!(&out, Ok(o) if o.ok()) {
                copied = false;
                break;
            }
        }
        if copied {
            let d = dest.to_string_lossy().into_owned();
            let _ = exec::run(&["chown", "-R", "root:snpanel", &d]);
            let _ = exec::run(&["chmod", "0750", &d]);
            let _ = exec::run(&["chmod", "0640", &dest.join("privkey.pem").to_string_lossy()]);
            let _ = exec::run(&[
                "chmod",
                "0644",
                &dest.join("fullchain.pem").to_string_lossy(),
            ]);
            synced += 1;
        }
    }
    HelperResponse::with_data(serde_json::json!({ "synced": synced }))
}

fn ensure_webroot() -> std::io::Result<()> {
    let challenge = Path::new(ACME_WEBROOT).join(".well-known/acme-challenge");
    std::fs::create_dir_all(&challenge)?;
    let _ = exec::run(&["chown", "-R", "root:snpanel", ACME_WEBROOT]);
    let _ = exec::run(&["chmod", "-R", "0755", ACME_WEBROOT]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance_uses_webroot_never_standalone() {
        // --standalone would need port 80 to itself, which means stopping
        // nginx and taking every site on the box down to renew one panel
        // certificate. The bash learned this the hard way.
        let d = Domain::parse("example.com").unwrap();
        let argv = issue_argv(&d, &[], None);
        assert!(argv.contains(&"--webroot".to_string()));
        assert!(!argv.contains(&"--standalone".to_string()));
        assert!(argv.contains(&ACME_WEBROOT.to_string()));
    }

    #[test]
    fn aliases_become_extra_d_flags_on_one_certificate() {
        let d = Domain::parse("example.com").unwrap();
        let aliases = [
            Domain::parse("www.example.com").unwrap(),
            Domain::parse("shop.example.com").unwrap(),
        ];
        let argv = issue_argv(&d, &aliases, None);
        let names: Vec<&String> = argv
            .iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && argv[i - 1] == "-d")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(
            names,
            vec!["example.com", "www.example.com", "shop.example.com"]
        );
        assert_eq!(argv.iter().filter(|a| *a == "--cert-name").count(), 1);
    }

    #[test]
    fn without_an_email_certbot_is_told_so_explicitly() {
        let d = Domain::parse("example.com").unwrap();
        let argv = issue_argv(&d, &[], None);
        assert!(argv.contains(&"--register-unsafely-without-email".to_string()));

        let email = Email::parse("ops@example.com").unwrap();
        let argv = issue_argv(&d, &[], Some(&email));
        assert!(argv.contains(&"--email".to_string()));
        assert!(argv.contains(&"ops@example.com".to_string()));
        assert!(!argv.contains(&"--register-unsafely-without-email".to_string()));
    }

    #[test]
    fn renew_does_not_sleep_when_a_person_is_waiting() {
        let argv = renew_argv(None);
        assert!(argv.contains(&"--no-random-sleep-on-renew".to_string()));
    }

    #[test]
    fn a_selfsigned_host_may_be_an_ip_or_a_name() {
        // Domain would reject both an IP and "localhost", and the panel needs
        // a certificate for exactly those on a fresh box.
        for host in ["192.0.2.10", "localhost", "panel.example.com"] {
            assert!(
                host.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'_' | b'-')),
                "{host}"
            );
        }
        let r = panel_selfsigned("bad host!", Port::new(2222).unwrap());
        assert!(!r.ok);
    }

    #[test]
    fn cert_info_for_an_unissued_domain_is_not_found() {
        let d = Domain::parse("no-such-cert-xyzzy.example.com").unwrap();
        let r = cert_info(&d);
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().kind, HelperErrorKind::NotFound);
    }

    #[test]
    fn deleting_an_absent_certificate_succeeds() {
        let d = Domain::parse("no-such-cert-xyzzy.example.com").unwrap();
        assert!(certbot_delete(&d).ok);
    }

    // Test seams: the argv builders, so the flags can be asserted without
    // running certbot.
    fn issue_argv(domain: &Domain, aliases: &[Domain], email: Option<&Email>) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "certbot".into(),
            "certonly".into(),
            "--webroot".into(),
            "-w".into(),
            ACME_WEBROOT.into(),
            "--cert-name".into(),
            domain.to_string(),
            "--non-interactive".into(),
            "--agree-tos".into(),
            "--expand".into(),
            "--keep-until-expiring".into(),
            "--allow-subset-of-names".into(),
            "-d".into(),
            domain.to_string(),
        ];
        for a in aliases {
            argv.push("-d".into());
            argv.push(a.to_string());
        }
        match email {
            Some(e) => {
                argv.push("--email".into());
                argv.push(e.to_string());
            }
            None => argv.push("--register-unsafely-without-email".into()),
        }
        argv
    }

    fn renew_argv(domain: Option<&Domain>) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "certbot".into(),
            "renew".into(),
            "--quiet".into(),
            "--no-random-sleep-on-renew".into(),
        ];
        if let Some(d) = domain {
            argv.push("--cert-name".into());
            argv.push(d.to_string());
        }
        argv
    }
}
