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

/// `ssl-cert-info`: when a certificate expires, and what names it covers.
///
/// Source: `ssl_cert_info`. Two `key=value` lines, which is what `cert_info`
/// in `backend/app/services/ssl.py` parses - it partitions each line on `=`
/// and keeps `not_after` and `sans`.
///
/// `sans` is the half that matters and the half JSON dropped entirely:
/// `cert_covers(sans, domain)` decides whether an existing certificate
/// already covers a name. An empty list makes that answer "no" for every
/// domain, which does not merely mis-display - it sends the panel to certbot
/// for a certificate it already holds, against an issuer with rate limits.
pub fn cert_info(domain: &Domain) -> HelperResponse {
    // The bash looks at the leaf, and at the manual-upload directory second:
    // a certificate an administrator pasted in is still a certificate this
    // server serves.
    let letsencrypt = live_dir(domain).join("cert.pem");
    let manual = Path::new(MANUAL_SSL_DIR)
        .join(domain.as_str())
        .join("cert.crt");
    let cert = if letsencrypt.is_file() {
        letsencrypt
    } else if manual.is_file() {
        manual
    } else {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no certificate on this server for {domain}"),
        );
    };
    let path = cert.to_string_lossy().into_owned();

    // `openssl x509 -enddate -noout | cut -d= -f2-`: everything after the
    // first `=`, so a date containing one survives.
    let not_after = exec::run(&["openssl", "x509", "-enddate", "-noout", "-in", &path])
        .ok()
        .filter(exec::Output::ok)
        .and_then(|o| {
            o.stdout
                .lines()
                .find_map(|l| l.split_once('=').map(|(_, v)| v.to_string()))
        })
        .unwrap_or_default();

    // `openssl x509 -ext subjectAltName | grep -oE 'DNS:[^,]+' | sed
    // 's/DNS://g;s/ //g' | paste -sd, -`
    let sans = exec::run(&[
        "openssl",
        "x509",
        "-ext",
        "subjectAltName",
        "-noout",
        "-in",
        &path,
    ])
    .ok()
    .map(|o| dns_names(&o.stdout))
    .unwrap_or_default();

    let sans = if sans.is_empty() {
        // "A certificate with no SAN extension is old, but it is not invalid
        // - its CN is the only name it covers."
        exec::run(&["openssl", "x509", "-subject", "-noout", "-in", &path])
            .ok()
            .map(|o| common_names(&o.stdout).join("\n"))
            .unwrap_or_default()
    } else {
        sans.join(",")
    };

    HelperResponse::with_stdout(format!("not_after={not_after}\nsans={sans}\n"))
}

/// `grep -oE 'DNS:[^,]+' | sed 's/DNS://g;s/ //g'`.
///
/// Every occurrence on every line, not the first - a multi-name certificate
/// lists them all on one line.
pub(crate) fn dns_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let mut rest = line;
        while let Some(i) = rest.find("DNS:") {
            let after = &rest[i + 4..];
            let end = after.find(',').unwrap_or(after.len());
            let name: String = after[..end].chars().filter(|c| *c != ' ').collect();
            if !name.is_empty() {
                names.push(name);
            }
            rest = &after[end..];
        }
    }
    names
}

/// `grep -oE 'CN ?= ?[^,/]+' | sed -E 's/CN ?= ?//'`.
///
/// The optional spaces are there because openssl's subject formatting changed
/// between 1.1 and 3.0 - `CN=example.com` on one, `CN = example.com` on the
/// other - and a helper that only understood one of them reported no name at
/// all on the other.
fn common_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i + 2 <= bytes.len() {
            if line[i..].starts_with("CN") {
                let mut j = i + 2;
                if bytes.get(j) == Some(&b' ') {
                    j += 1;
                }
                if bytes.get(j) != Some(&b'=') {
                    i += 1;
                    continue;
                }
                j += 1;
                if bytes.get(j) == Some(&b' ') {
                    j += 1;
                }
                let rest = &line[j..];
                let end = rest.find([',', '/']).unwrap_or(rest.len());
                if end > 0 {
                    names.push(rest[..end].to_string());
                    i = j + end;
                    continue;
                }
            }
            i += 1;
        }
    }
    names
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
    // `/etc/letsencrypt/live/*/`, not the panel's own copies: the question is
    // which of this server's websites hold a certificate the panel *could*
    // borrow, and reading the directory it has already borrowed into can only
    // ever answer with what it borrowed before.
    if let Ok(entries) = std::fs::read_dir(LETSENCRYPT_LIVE) {
        for e in entries.filter_map(Result::ok) {
            let dir = e.path();
            // Both halves, as the bash checks: a live directory with no
            // private key is one certbot is mid-way through writing, and
            // offering it would hand nginx a certificate it cannot serve.
            if dir.join("fullchain.pem").is_file() && dir.join("privkey.pem").is_file() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    // One bare name per line. `domains_with_certificate` in
    // `backend/app/services/panel_settings.py` reads stdout line by line and
    // drops anything that is not a domain, so a JSON wrapper left the
    // "borrow an existing certificate" list empty on every server.
    let mut out = String::new();
    for name in &names {
        out.push_str(name);
        out.push('\n');
    }
    HelperResponse::with_stdout(out)
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

// ---------------------------------------------------------------------------
// certificates an administrator uploaded
// ---------------------------------------------------------------------------

/// Source: `/etc/nginx/snpanel/ssl/sites/<domain>`.
const MANUAL_SSL_DIR: &str = "/etc/nginx/snpanel/ssl/sites";

/// The four files a manual certificate lives in.
///
/// `fullchain.crt` is what nginx is pointed at, and it is the certificate on
/// its own when no CA bundle was uploaded - so the vhost never has to know
/// which of the two cases it is in.
const MANUAL_SSL_FILES: &[&str] = &["cert.crt", "privkey.key", "ca.crt", "fullchain.crt"];

/// `manual-ssl-install <domain>`, with the certificate on stdin as JSON.
///
/// The bash pipes that payload through `python3` to split it into files. This
/// does it here, which is one more reason the helper no longer needs Python.
///
/// The payload is JSON rather than three arguments for the reason C37 gives:
/// a private key in argv is readable in `/proc/<pid>/cmdline` by every account
/// on the machine for as long as the process lives.
pub fn manual_ssl_install(domain: &Domain, payload: &str) -> HelperResponse {
    let parsed: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(e) => {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("certificate payload is not JSON: {e}"),
            )
        }
    };
    let field = |name: &str| -> String {
        parsed
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let certificate = field("certificate");
    let private_key = field("private_key");
    let ca_bundle = field("ca_bundle");

    // Source: `if not content or "\x00" in content: raise SystemExit(...)`.
    // A NUL would truncate the file where nginx reads it, so what gets served
    // is not what was reviewed.
    for (name, content) in [("cert.crt", &certificate), ("privkey.key", &private_key)] {
        if content.is_empty() || content.contains('\0') {
            return HelperResponse::failed(HelperErrorKind::BadRequest, format!("invalid {name}"));
        }
    }
    if !ca_bundle.is_empty() && ca_bundle.contains('\0') {
        return HelperResponse::failed(HelperErrorKind::BadRequest, "invalid ca.crt".to_string());
    }

    let base = format!("{MANUAL_SSL_DIR}/{domain}");
    if let Err(e) = std::fs::create_dir_all(&base) {
        return HelperResponse::failed(HelperErrorKind::Internal, format!("creating {base}: {e}"));
    }
    // `install -d -o root -g snpanel -m 0750` then `-m 0640` per file: the
    // panel account has to read the key to serve the panel's own SNI, and
    // nobody else does.
    if let Err(resp) = set_owner_mode(&base, 0o750) {
        return resp;
    }

    let mut writes: Vec<(&str, String)> = vec![
        ("cert.crt", certificate.clone()),
        ("privkey.key", private_key),
    ];
    if ca_bundle.is_empty() {
        // No bundle: the previous one must go, or `fullchain.crt` below and
        // the leftover `ca.crt` would disagree about what this site serves.
        let _ = std::fs::remove_file(format!("{base}/ca.crt"));
        writes.push(("fullchain.crt", certificate));
    } else {
        // `cat cert.crt ca.crt > fullchain.crt` - in that order. The leaf
        // first is what the TLS handshake requires.
        writes.push(("fullchain.crt", format!("{certificate}{ca_bundle}")));
        writes.push(("ca.crt", ca_bundle));
    }

    for (name, content) in writes {
        let path = format!("{base}/{name}");
        if let Err(e) = std::fs::write(&path, content) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("writing {path}: {e}"),
            );
        }
        if let Err(resp) = set_owner_mode(&path, 0o640) {
            return resp;
        }
    }

    HelperResponse::with_stdout(format!("Manual SSL installed for {domain}\n"))
}

/// `manual-ssl-remove <domain>`.
///
/// The directory is removed only when it is empty - `rmdir`, not `rm -r`.
/// Anything else in there was not put there by this verb and is not its to
/// delete.
pub fn manual_ssl_remove(domain: &Domain) -> HelperResponse {
    let base = format!("{MANUAL_SSL_DIR}/{domain}");
    for name in MANUAL_SSL_FILES {
        let _ = std::fs::remove_file(format!("{base}/{name}"));
    }
    let _ = std::fs::remove_dir(&base);
    HelperResponse::with_stdout(format!("Manual SSL removed for {domain}\n"))
}

/// `-o root -g snpanel -m <mode>`.
///
/// The group is looked up rather than assumed: a box where the installer has
/// not yet created it should not have the write fail, and the mode is the part
/// that matters for secrecy.
fn set_owner_mode(path: &str, mode: u32) -> Result<(), HelperResponse> {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        return Err(HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("setting permissions on {path}: {e}"),
        ));
    }
    let _ = exec::run(&["chown", "root:snpanel", path]);
    Ok(())
}


// ---------------------------------------------------------------------------
// the nightly renewal
// ---------------------------------------------------------------------------

const AUTO_RENEW_SERVICE: &str = "/etc/systemd/system/snpanel-ssl-auto-renew.service";
const AUTO_RENEW_TIMER: &str = "/etc/systemd/system/snpanel-ssl-auto-renew.timer";

const AUTO_RENEW_SERVICE_UNIT: &str = "[Unit]\n\
Description=Renew SNPanel SSL certificates that expire within 10 days\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n\
Environment=SUDO_USER=snpanel\n\
ExecStart=/usr/local/sbin/snpanel-helper certbot-renew-soon 10\n";

const AUTO_RENEW_TIMER_UNIT: &str = "[Unit]\n\
Description=Check SNPanel SSL certificates daily\n\
\n\
[Timer]\n\
OnCalendar=*-*-* 01:30:00\n\
Persistent=true\n\
\n\
[Install]\n\
WantedBy=timers.target\n";

/// Source: `write_ssl_auto_renew_timer`.
///
/// The bash writes unconditionally and reloads every time. This compares
/// first for the same reason the blocklist timer does - `renew_soon` calls it
/// on every nightly run, and a `daemon-reload` a day is noise in the journal
/// for a file that has not changed since it was installed.
///
/// `systemctl` failing is not an error: the bash ends the enable with
/// `|| true`, so a container without systemd still gets the unit files.
fn write_auto_renew_timer() {
    let mut changed = false;
    for (path, body) in [
        (AUTO_RENEW_SERVICE, AUTO_RENEW_SERVICE_UNIT),
        (AUTO_RENEW_TIMER, AUTO_RENEW_TIMER_UNIT),
    ] {
        let current = std::fs::read_to_string(path).unwrap_or_default();
        if current != body && std::fs::write(path, body).is_ok() {
            changed = true;
        }
    }
    if changed {
        let _ = exec::run(&["systemctl", "daemon-reload"]);
    }
    let _ = exec::run(&[
        "systemctl",
        "enable",
        "--now",
        "snpanel-ssl-auto-renew.timer",
    ]);
}

/// `certbot-auto-renew-install`.
pub fn auto_renew_install() -> HelperResponse {
    write_auto_renew_timer();
    HelperResponse::with_stdout("SSL auto-renew timer installed\n".to_string())
}

/// Source: `renew_ssl_soon` - the `days` guard, `[1-30]`.
///
/// The window is bounded on both sides. Below 1 the check would renew
/// nothing; above 30 every certificate on the box looks due on every run, and
/// Let's Encrypt rate-limits five duplicate certificates a week.
const RENEW_SOON_MIN_DAYS: u32 = 1;
const RENEW_SOON_MAX_DAYS: u32 = 30;

/// The names under `/etc/letsencrypt/live` that are not lineages.
///
/// Source: `[[ "$cert_name" == "README" ]] && continue`. Certbot writes a
/// `README` in that directory explaining not to edit the symlinks.
const NOT_A_LINEAGE: &[&str] = &["README"];

/// Source: the `--deploy-hook` of `renew_ssl_soon`.
///
/// Reloading nginx is what makes the new certificate serve; restarting the
/// panel is what makes it serve its own. Both end in `|| true` because a
/// renewal that succeeded must not be reported as failed by the thing that
/// picks it up.
const DEPLOY_HOOK: &str = "systemctl reload nginx || true; systemctl restart snpanel-api || true";

/// `certbot-renew-soon [days]`.
///
/// Walks every lineage and renews the ones that expire inside the window.
/// This is not `certbot renew`: certbot's own schedule renews at 30 days, and
/// the panel's certificate has to be copied out of `/etc/letsencrypt`
/// afterwards, which certbot has no way to know about.
pub fn renew_soon(days: u32) -> HelperResponse {
    if !(RENEW_SOON_MIN_DAYS..=RENEW_SOON_MAX_DAYS).contains(&days) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "usage: certbot-renew-soon [1-30 days]".to_string(),
        );
    }
    // Installing the timer is part of the run, not only of the install verb:
    // the bash does it here so a box whose units were removed gets them back
    // on the next nightly run.
    write_auto_renew_timer();

    if !super::runtime::have("certbot") {
        // Exit 0. "certbot is not installed" is an answer, not a failure.
        return HelperResponse::with_stdout("certbot is not installed\n".to_string());
    }

    let seconds = u64::from(days) * 86_400;
    let mut out = String::new();
    let (mut checked, mut renewed) = (0u32, 0u32);

    for name in lineages() {
        checked += 1;
        let cert = format!("{LETSENCRYPT_LIVE}/{name}/cert.pem");
        let checkend = seconds.to_string();
        let still_valid = exec::run(&[
            "openssl",
            "x509",
            "-checkend",
            &checkend,
            "-noout",
            "-in",
            &cert,
        ])
        .is_ok_and(|o| o.ok());
        if still_valid {
            continue;
        }
        out.push_str(&format!("Renewing certificate: {name}\n"));
        let ok = exec::run(&[
            "certbot",
            "renew",
            "--cert-name",
            &name,
            "--quiet",
            "--force-renewal",
            "--deploy-hook",
            DEPLOY_HOOK,
        ])
        .is_ok_and(|o| o.ok());
        if ok {
            renewed += 1;
        } else {
            // `>&2` in the bash: a lineage that would not renew is a warning,
            // and the run carries on to the others.
            out.push_str(&format!("WARNING: could not renew {name}\n"));
        }
    }

    let env = std::fs::read_to_string(super::panel::ENV_FILE).unwrap_or_default();
    let panel_domain = super::panel::env_get(&env, "PANEL_DOMAIN").unwrap_or_default();
    super::panel::copy_panel_live_certificate(&panel_domain);

    if renewed > 0 {
        let _ = exec::run(&["systemctl", "reload", "nginx"]);
        let _ = exec::run(&["systemctl", "restart", "snpanel-api"]);
    }
    out.push_str(&format!(
        "SSL auto-renew checked {checked} certificate(s); renewed {renewed} certificate(s) within {days} day(s).\n"
    ));
    HelperResponse::with_stdout(out)
}

/// Every lineage under `/etc/letsencrypt/live` that has a `cert.pem`.
///
/// Source: `for cert in /etc/letsencrypt/live/*/cert.pem` under `nullglob` -
/// a missing or empty directory means the loop body never runs, which is why
/// every failure here is an empty list rather than an error.
fn lineages() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(LETSENCRYPT_LIVE) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !NOT_A_LINEAGE.contains(&name.as_str()))
        .filter(|name| Path::new(LETSENCRYPT_LIVE).join(name).join("cert.pem").is_file())
        .collect();
    // A glob expands in sorted order; `read_dir` does not, and the summary
    // line names certificates in the order they were walked.
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What an uploaded certificate turns into on disk.
    ///
    /// `fullchain.crt` is what nginx is pointed at, so the vhost never has to
    /// know whether a CA bundle was supplied - and the leaf comes **first**,
    /// which is what the TLS handshake requires. Getting that order wrong
    /// produces a file openssl still reads and browsers reject.
    #[test]
    fn a_manual_certificate_lands_as_four_files_with_the_leaf_first() {
        let base = std::env::temp_dir().join(format!("manual-ssl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("the dir");

        // With a bundle: cert, key, ca, and a fullchain that is cert then ca.
        let cert = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n";
        let ca = "-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n";
        let fullchain = format!("{cert}{ca}");
        assert!(fullchain.starts_with(cert), "the leaf has to come first");
        assert!(fullchain.ends_with(ca));
        assert_eq!(fullchain.matches("BEGIN CERTIFICATE").count(), 2);

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The refusals, which are the whole of the validation.
    ///
    /// A NUL truncates the file where nginx reads it, so what gets served is
    /// not what was reviewed - and an empty certificate or key would leave
    /// nginx pointed at a file that cannot be parsed.
    #[test]
    fn an_empty_or_nul_bearing_certificate_is_refused() {
        let domain = snpanel_core::Domain::parse("example.com").expect("a domain");

        for payload in [
            r#"{"certificate":"","private_key":"k"}"#,
            r#"{"private_key":"k"}"#,
            "{\"certificate\":\"a\\u0000b\",\"private_key\":\"k\"}",
            r#"{"certificate":"c","private_key":""}"#,
            "{\"certificate\":\"c\",\"private_key\":\"a\\u0000b\"}",
            "{\"certificate\":\"c\",\"private_key\":\"k\",\"ca_bundle\":\"a\\u0000b\"}",
            "not json at all",
        ] {
            let resp = manual_ssl_install(&domain, payload);
            assert!(!resp.ok, "{payload} should be refused");
        }
    }

    /// The files this verb owns, and only those.
    ///
    /// `remove_manual_ssl` uses `rmdir`, not `rm -r`: anything else in that
    /// directory was not put there by this verb and is not its to delete.
    #[test]
    fn removal_takes_the_four_files_and_leaves_a_non_empty_directory() {
        assert_eq!(
            MANUAL_SSL_FILES,
            &["cert.crt", "privkey.key", "ca.crt", "fullchain.crt"]
        );

        let base = std::env::temp_dir().join(format!("manual-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("the dir");
        for name in MANUAL_SSL_FILES {
            std::fs::write(base.join(name), "x").expect("a file");
        }
        std::fs::write(base.join("notes.txt"), "somebody else's").expect("a stray file");

        for name in MANUAL_SSL_FILES {
            let _ = std::fs::remove_file(base.join(name));
        }
        let removed = std::fs::remove_dir(&base);
        assert!(
            removed.is_err(),
            "a directory with a stray file must survive"
        );
        assert!(base.join("notes.txt").exists());

        let _ = std::fs::remove_dir_all(&base);
    }

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

    /// `cert_info` in `backend/app/services/ssl.py`, applied to these lines.
    ///
    /// `sans` is the half the JSON answer dropped altogether, and it is the
    /// one with consequences: `cert_covers(sans, domain)` decides whether a
    /// certificate already covers a name, and an empty list answers "no" for
    /// every domain. That does not just mis-display - it sends the panel back
    /// to certbot for a certificate it already holds, against an issuer with
    /// rate limits.
    #[test]
    fn cert_info_says_what_the_python_parser_reads() {
        /// The loop in `cert_info`: partition each line on `=`, keep two keys.
        fn parse(output: &str) -> (String, Vec<String>) {
            let mut not_after = String::new();
            let mut sans = Vec::new();
            for line in output.lines() {
                let (key, value) = line.split_once('=').unwrap_or((line, ""));
                if key == "not_after" {
                    not_after = value.trim().to_string();
                } else if key == "sans" {
                    sans = value
                        .trim()
                        .split(',')
                        .filter(|n| !n.is_empty())
                        .map(str::to_string)
                        .collect();
                }
            }
            (not_after, sans)
        }

        let text = "not_after=Dec  8 09:12:44 2026 GMT\nsans=example.com,www.example.com\n";
        let (not_after, sans) = parse(text);
        assert_eq!(not_after, "Dec  8 09:12:44 2026 GMT");
        assert_eq!(sans, vec!["example.com", "www.example.com"]);

        // `cut -d= -f2-`, not `-f2`: a date is allowed to contain an `=`, and
        // taking only the second field would silently truncate it.
        let (not_after, _) = parse("not_after=a=b\nsans=x\n");
        assert_eq!(not_after, "a=b");

        // And the shape the bug had: neither key survives, so the panel shows
        // no expiry and believes the certificate covers nothing.
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "domain": "example.com",
            "not_after": "Dec  8 09:12:44 2026 GMT",
            "path": "/etc/letsencrypt/live/example.com/cert.pem",
        }))
        .expect("json");
        assert_eq!(parse(&json), (String::new(), vec![]));
    }

    /// `grep -oE 'DNS:[^,]+' | sed 's/DNS://g;s/ //g'`.
    ///
    /// Every name on the line, not the first - which is the whole point of a
    /// multi-name certificate.
    #[test]
    fn every_subject_alternative_name_is_extracted() {
        // What `openssl x509 -ext subjectAltName -noout` actually prints.
        let sample = "X509v3 Subject Alternative Name: \n    DNS:example.com, DNS:www.example.com, DNS:api.example.com\n";
        assert_eq!(
            dns_names(sample),
            vec!["example.com", "www.example.com", "api.example.com"]
        );

        // `s/ //g` removes spaces anywhere in the name, not only around it.
        assert_eq!(
            dns_names("DNS: spaced.example.com\n"),
            vec!["spaced.example.com"]
        );

        // A certificate with no SAN extension prints nothing useful.
        assert!(dns_names("").is_empty());
        assert!(dns_names("no extension here\n").is_empty());

        // An IP entry is not a DNS name and the bash's pattern does not take
        // it - `IP Address:` has no `DNS:` prefix.
        assert_eq!(
            dns_names("DNS:example.com, IP Address:192.0.2.1\n"),
            vec!["example.com"]
        );
    }

    /// `grep -oE 'CN ?= ?[^,/]+' | sed -E 's/CN ?= ?//'`.
    ///
    /// The optional spaces matter: openssl 1.1 prints `subject=CN=example.com`
    /// and openssl 3.0 prints `subject=CN = example.com`. A reader that
    /// understood only one of them reported no name at all on the other, which
    /// is the same failure as the JSON one, one layer down.
    #[test]
    fn a_common_name_is_read_in_both_openssl_spellings() {
        assert_eq!(
            common_names("subject=CN=example.com\n"),
            vec!["example.com"]
        );
        assert_eq!(
            common_names("subject=CN = example.com\n"),
            vec!["example.com"]
        );
        assert_eq!(
            common_names("subject=CN= example.com\n"),
            vec!["example.com"]
        );
        assert_eq!(
            common_names("subject=CN =example.com\n"),
            vec!["example.com"]
        );

        // `[^,/]+` stops at either separator, so the rest of a full subject
        // line does not get swept into the name.
        assert_eq!(
            common_names("subject=C = GB, O = Example Ltd, CN = example.com\n"),
            vec!["example.com"]
        );
        assert_eq!(
            common_names("subject=/C=GB/CN=example.com/O=x\n"),
            vec!["example.com"]
        );

        assert!(common_names("subject=O = Example Ltd\n").is_empty());
        assert!(common_names("").is_empty());
    }

    /// `panel-ssl-domains` writes bare names, one per line.
    ///
    /// `domains_with_certificate` reads stdout line by line and keeps only
    /// what matches a domain pattern, so a JSON wrapper left the "borrow a
    /// certificate from one of your sites" list empty on every server.
    #[test]
    fn panel_ssl_domains_writes_one_bare_name_per_line() {
        let names = ["example.com", "beta.example.org"];
        let mut out = String::new();
        for name in names {
            out.push_str(name);
            out.push('\n');
        }
        // The Python filter: strip, drop slashes, require a domain.
        let kept: Vec<String> = out
            .lines()
            .map(|l| l.trim().trim_matches('/').to_string())
            .filter(|n| !n.is_empty() && n != "README" && n.contains('.'))
            .collect();
        assert_eq!(kept, names);

        let json =
            serde_json::to_string_pretty(&serde_json::json!({ "hostnames": names })).expect("json");
        let kept: Vec<String> = json
            .lines()
            .map(|l| l.trim().trim_matches('/').to_string())
            .filter(|n| {
                !n.is_empty() && n != "README" && !n.contains(['{', '}', '[', ']', ':', '"'])
            })
            .collect();
        assert!(kept.is_empty(), "JSON must yield no names: {kept:?}");
    }

    /// Both halves of a live directory, as the bash checks.
    ///
    /// A directory holding `fullchain.pem` but no `privkey.pem` is one certbot
    /// is part-way through writing. Offering it hands nginx a certificate it
    /// cannot serve, and nginx then refuses to start - taking every site on
    /// the box down, not just this one.
    #[test]
    fn a_live_directory_needs_both_the_chain_and_the_key() {
        let base = std::env::temp_dir().join(format!("live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let complete = base.join("example.com");
        std::fs::create_dir_all(&complete).expect("the dir");
        std::fs::write(complete.join("fullchain.pem"), "x").expect("chain");
        std::fs::write(complete.join("privkey.pem"), "x").expect("key");

        let half = base.join("partial.example.com");
        std::fs::create_dir_all(&half).expect("the dir");
        std::fs::write(half.join("fullchain.pem"), "x").expect("chain only");

        let mut found: Vec<String> = std::fs::read_dir(&base)
            .expect("read")
            .filter_map(Result::ok)
            .filter(|e| {
                e.path().join("fullchain.pem").is_file() && e.path().join("privkey.pem").is_file()
            })
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        assert_eq!(found, vec!["example.com"]);

        let _ = std::fs::remove_dir_all(&base);
    }

    // --- the nightly renewal ---------------------------------------------

    #[test]
    fn the_renewal_window_is_bounded_at_both_ends() {
        // Source: `[[ "$days" =~ ^[0-9]+$ && "$days" -ge 1 && "$days" -le 30 ]]`.
        assert_eq!(RENEW_SOON_MIN_DAYS, 1);
        assert_eq!(RENEW_SOON_MAX_DAYS, 30);
        // The unit this installs passes 10, which has to be inside it or the
        // nightly run refuses itself.
        assert!((RENEW_SOON_MIN_DAYS..=RENEW_SOON_MAX_DAYS).contains(&10));
    }

    #[test]
    fn the_timer_asks_for_the_days_the_unit_passes() {
        // The service's ExecStart and the description have to agree: an
        // operator reads "within 10 days" and gets whatever the argument is.
        assert!(AUTO_RENEW_SERVICE_UNIT.contains("certbot-renew-soon 10"));
        assert!(AUTO_RENEW_SERVICE_UNIT.contains("expire within 10 days"));
    }

    #[test]
    fn the_units_carry_sudo_user_and_an_install_section() {
        // `Environment=SUDO_USER=snpanel`: the helper refuses an invocation
        // it cannot attribute, and a timer has no sudo to set it.
        assert!(AUTO_RENEW_SERVICE_UNIT.contains("Environment=SUDO_USER=snpanel"));
        // Without `[Install]` the `enable` is a no-op and the timer silently
        // never runs - which is a certificate that expires in sixty days.
        assert!(AUTO_RENEW_TIMER_UNIT.contains("[Install]\nWantedBy=timers.target"));
        assert!(AUTO_RENEW_TIMER_UNIT.contains("Persistent=true"));
    }

    #[test]
    fn the_readme_certbot_writes_is_not_a_lineage() {
        // certbot leaves a README beside the lineages. Treating it as one
        // sends `openssl x509 -checkend` at a file that is not a
        // certificate, and the failure reads as "expiring".
        assert!(NOT_A_LINEAGE.contains(&"README"));
    }

    #[test]
    fn the_deploy_hook_cannot_fail_the_renewal() {
        // Both halves end in `|| true`. certbot treats a failing deploy hook
        // as a failed renewal, so a box whose nginx is stopped would report
        // a renewal that in fact succeeded as an error, every night.
        let parts: Vec<&str> = DEPLOY_HOOK.split(';').collect();
        assert_eq!(parts.len(), 2, "{DEPLOY_HOOK:?}");
        for part in parts {
            assert!(part.trim_end().ends_with("|| true"), "{part:?}");
        }
    }

}
