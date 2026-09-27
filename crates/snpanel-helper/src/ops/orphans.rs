//! `ops::orphans` - what a deleted website leaves behind, and clearing it.
//!
//! Source: `cleanup_orphans`.
//!
//! Two rules shape the whole module and neither is about finding orphans.
//!
//! **The panel decides what is live, not the filesystem.** The list of live
//! domains arrives on stdin. A helper that inferred it from the directory it
//! is about to delete from would be reasoning in a circle, and the circle
//! closes on a customer's certificate.
//!
//! **Nothing is deleted without a copy.** Everything goes to
//! `/root/snpanel-removed/orphans-<stamp>` first. "Unreferenced" is a strong
//! inference, not a certainty, and an administrator who removed a site by
//! accident should be able to get it back.

use std::path::Path;

use snpanel_core::Domain;
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: `ORPHAN_ARCHIVE_ROOT`.
const ARCHIVE_ROOT: &str = "/root/snpanel-removed";
const RENEWAL_DIR: &str = "/etc/letsencrypt/renewal";
const LIVE_DIR: &str = "/etc/letsencrypt/live";
const WAF_SITE_DIR: &str = "/etc/nginx/modsec/sites";
const NGINX_CONF_DIR: &str = "/etc/nginx/conf.d";
const MANUAL_SSL_DIR: &str = "/etc/nginx/snpanel/ssl/sites";
const SNI_DIR: &str = "/etc/snpanel/sni";
const ENV_FILE: &str = "/opt/snpanel/backend/.env";

/// Source: `orphan_live_domains`.
///
/// "Anything that is not a valid domain is dropped, not trusted."
/// `tr -d '[:space:]'` removes whitespace **anywhere** in the line, not just
/// at the ends, and the result is lowercased before it is checked.
pub(crate) fn live_domains(stdin: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in stdin.lines() {
        let squeezed: String = line
            .chars()
            .filter(|c| !c.is_whitespace())
            .flat_map(char::to_lowercase)
            .collect();
        if squeezed.is_empty() {
            continue;
        }
        // `is_domain` is the bash's regex, and `Domain::parse` is the same
        // shape - the type exists so this check has one definition.
        if Domain::parse(&squeezed).is_ok() {
            out.push(squeezed);
        }
    }
    out
}

/// Source: `env_get PANEL_DOMAIN`.
///
/// The panel's own hostname is live by definition; leaving it out would make
/// the panel's certificate an orphan and take :2222 down with it.
fn panel_domain() -> Option<String> {
    let text = std::fs::read_to_string(ENV_FILE).ok()?;
    // `awk -F= '$1 == key { sub(/^[^=]*=/, ""); print; exit }'` - the first
    // match wins, and everything after the first `=` is the value.
    text.lines()
        .find_map(|l| l.strip_prefix("PANEL_DOMAIN="))
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
}

/// Source: `orphan_cert_covers_live`.
///
/// "A lineage named for a dead site can still carry a live name as a SAN, and
/// deleting it would take that live site's HTTPS down."
fn cert_covers_live(cert: &Path, live: &[String]) -> bool {
    if !cert.is_file() {
        return false;
    }
    let Ok(out) = exec::run(&[
        "openssl",
        "x509",
        "-ext",
        "subjectAltName",
        "-noout",
        "-in",
        &cert.to_string_lossy(),
    ]) else {
        return false;
    };
    crate::ops::ssl::dns_names(&out.stdout)
        .iter()
        .any(|san| live.iter().any(|l| l == san))
}

/// What the scan found, in the order the bash reports it.
#[derive(Default)]
pub(crate) struct Found {
    pub(crate) certs: Vec<String>,
    pub(crate) waf_rules: Vec<String>,
    pub(crate) vhost_backups: Vec<String>,
    pub(crate) manual_ssl: Vec<String>,
    pub(crate) sni_copies: Vec<String>,
}

/// `date -u +%Y%m%d-%H%M%S`.
fn stamp(secs: i64) -> String {
    // `format_utc` gives `YYYY-MM-DDTHH:MM:SSZ`; this is the same instant in
    // the shape the archive directory uses.
    let iso = crate::ops::packages::format_utc(secs);
    let (date, time) = iso.split_once('T').unwrap_or((&iso, ""));
    format!(
        "{}-{}",
        date.replace('-', ""),
        time.trim_end_matches('Z').replace(':', "")
    )
}

/// `orphans-scan` / `orphans-clean`, with the live domains on stdin.
pub fn cleanup(clean: bool, stdin: &str) -> HelperResponse {
    let mut live = live_domains(stdin);
    if let Some(domain) = panel_domain() {
        live.push(domain);
    }
    // "An empty list almost certainly means the caller failed, not that the
    // server hosts nothing. Refuse rather than delete everything on the
    // machine."
    if live.is_empty() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "refusing to clean orphans: no live domains were supplied".to_string(),
        );
    }

    let is_live = |name: &str| live.iter().any(|l| l == name);
    let mut found = Found::default();

    // 1. Let's Encrypt lineages. "These are the ones that matter: the renewal
    //    config keeps waking certbot.timer and starts failing the day the
    //    domain stops pointing here."
    for name in sorted_names(RENEWAL_DIR, Some("conf")) {
        if is_live(&name) {
            continue;
        }
        if cert_covers_live(&Path::new(LIVE_DIR).join(&name).join("cert.pem"), &live) {
            continue;
        }
        found.certs.push(name);
    }

    // 2. Per-site WAF rule files.
    for name in sorted_names(WAF_SITE_DIR, Some("conf")) {
        if !is_live(&name) {
            found.waf_rules.push(name);
        }
    }

    // 3. Vhost backups nginx never reads, and only where no vhost is left.
    for base in backup_basenames(NGINX_CONF_DIR) {
        let name = base.split(".conf.bak").next().unwrap_or("").to_string();
        if name.is_empty() || Domain::parse(&name).is_err() || is_live(&name) {
            continue;
        }
        if Path::new(NGINX_CONF_DIR)
            .join(format!("{name}.conf"))
            .is_file()
        {
            continue;
        }
        found.vhost_backups.push(base);
    }

    // 4. Uploaded certificates.
    for name in sorted_dirs(MANUAL_SSL_DIR) {
        if !is_live(&name) {
            found.manual_ssl.push(name);
        }
    }

    // 5. SNI copies. Reported only: `sync_panel_sni_certificates` drops copies
    //    whose source is gone, so `clean` clears them by running that.
    for name in sorted_dirs(SNI_DIR) {
        if !is_live(&name) {
            found.sni_copies.push(name);
        }
    }

    let mut out = String::new();
    for name in &found.certs {
        out.push_str(&format!("cert\t{name}\n"));
    }
    for name in &found.waf_rules {
        out.push_str(&format!("waf-rules\t{name}\n"));
    }
    for base in &found.vhost_backups {
        out.push_str(&format!("vhost-backup\t{base}\n"));
    }
    for name in &found.manual_ssl {
        out.push_str(&format!("manual-ssl\t{name}\n"));
    }
    for name in &found.sni_copies {
        out.push_str(&format!("sni-copy\t{name}\n"));
    }

    let mut archive = String::new();
    if clean {
        archive = apply(&found);
    }

    out.push_str(&summary_line(&found));
    // `[[ "$mode" == "clean" && -d "$archive" ]]` - the directory is removed
    // again by `rmdir` when nothing was put in it, so an empty run reports no
    // archive rather than an empty one.
    if clean && !archive.is_empty() && Path::new(&archive).is_dir() {
        out.push_str(&format!("archive\t{archive}\n"));
    }
    HelperResponse::with_stdout(out)
}

/// The `summary` line: a tab, then `certs=N waf-rules=N vhost-backups=N
/// manual-ssl=N sni-copies=N` separated by spaces.
///
/// Tab after `summary`, spaces between the pairs: `_parse` in
/// `backend/app/services/orphans.py` splits the line on tabs, takes the second
/// field, and then splits *that* on whitespace.
pub(crate) fn summary_line(found: &Found) -> String {
    format!(
        "summary\tcerts={} waf-rules={} vhost-backups={} manual-ssl={} sni-copies={}\n",
        found.certs.len(),
        found.waf_rules.len(),
        found.vhost_backups.len(),
        found.manual_ssl.len(),
        found.sni_copies.len(),
    )
}

/// Archive, then remove. Returns the archive path.
fn apply(found: &Found) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let archive = format!("{ARCHIVE_ROOT}/orphans-{}", stamp(now));
    if make_private_dir(&archive).is_err() {
        return String::new();
    }

    for name in &found.certs {
        let dir = format!("{archive}/certs");
        let _ = make_private_dir(&dir);
        let conf = format!("{RENEWAL_DIR}/{name}.conf");
        let _ = exec::run(&["cp", "-a", &conf, &format!("{dir}/")]);
        // `-h`: the live directory is symlinks into `archive/`, so the copy
        // has to follow them or it preserves nothing.
        let _ = exec::run(&[
            "tar",
            "czhf",
            &format!("{dir}/{name}.tar.gz"),
            "-C",
            LIVE_DIR,
            name,
        ]);
        let _ = exec::run(&[
            "certbot",
            "delete",
            "--cert-name",
            name,
            "--non-interactive",
        ]);
    }

    for name in &found.waf_rules {
        let dir = format!("{archive}/waf");
        let _ = make_private_dir(&dir);
        let _ = exec::run(&[
            "cp",
            "-a",
            &format!("{WAF_SITE_DIR}/{name}.conf"),
            &format!("{dir}/"),
        ]);
        // "delete_waf_site_rules has the check that matters - a file a running
        // vhost still names must never go - so reuse it."
        if let Ok(domain) = Domain::parse(name) {
            let _ = crate::ops::waf::site_rules_delete(&domain);
        }
    }

    for base in &found.vhost_backups {
        let dir = format!("{archive}/vhost");
        let _ = make_private_dir(&dir);
        let path = format!("{NGINX_CONF_DIR}/{base}");
        let _ = exec::run(&["cp", "-a", &path, &format!("{dir}/")]);
        let _ = std::fs::remove_file(&path);
    }

    for name in &found.manual_ssl {
        let dir = format!("{archive}/manual-ssl");
        let _ = make_private_dir(&dir);
        let _ = exec::run(&[
            "tar",
            "czf",
            &format!("{dir}/{name}.tar.gz"),
            "-C",
            MANUAL_SSL_DIR,
            name,
        ]);
        if let Ok(domain) = Domain::parse(name) {
            let _ = crate::ops::ssl::manual_ssl_remove(&domain);
        }
    }

    let _ = crate::ops::ssl::sync_sni();
    if matches!(exec::run(&["nginx", "-t"]), Ok(o) if o.ok()) {
        let _ = exec::run(&["systemctl", "reload", "nginx"]);
    }
    // `rmdir` - it goes only if nothing was archived into it. Never `rm -r`.
    let _ = std::fs::remove_dir(&archive);
    archive
}

/// `install -d -m 0700` - these are customer certificates.
fn make_private_dir(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Entries of `dir` whose basename (minus `ext`) is a domain, sorted.
///
/// A glob in bash iterates in sorted order; `read_dir` does not, and the
/// output of a scan is read by a person comparing it with the last one.
fn sorted_names(dir: &str, ext: Option<&str>) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| {
            let file = e.file_name().to_string_lossy().into_owned();
            let stem = match ext {
                Some(ext) => file.strip_suffix(&format!(".{ext}"))?.to_string(),
                None => file,
            };
            Domain::parse(&stem).ok().map(|_| stem)
        })
        .collect();
    names.sort();
    names
}

/// Subdirectories of `dir` whose name is a domain, sorted.
fn sorted_dirs(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            Domain::parse(&name).ok().map(|_| name)
        })
        .collect();
    names.sort();
    names
}

/// `*.conf.bak*` in `dir`, sorted, as basenames.
fn backup_basenames(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".conf.bak"))
        .collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `orphan_live_domains`, replayed against what the bash actually does on
    /// Debian 13.
    ///
    /// Two of its answers are easy to read past and easy to get wrong:
    ///
    ///   * `tr -d '[:space:]'` removes whitespace **anywhere**, so
    ///     `exa mple.com` becomes `example.com` and two names on one line are
    ///     glued into one;
    ///   * `is_domain` allows all-digit labels, so `192.0.2.1` is accepted as
    ///     a "domain" and stays on the live list.
    ///
    /// The second one matters here: a list that dropped it would make a
    /// certificate for that name an orphan.
    #[test]
    fn live_domains_normalize_exactly_as_the_bash_does() {
        #[derive(serde::Deserialize)]
        struct Case {
            input: String,
            output: Vec<String>,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/orphan_live_domains.json");
        let raw = std::fs::read_to_string(&path).expect("the live-domains fixture");
        let cases: Vec<Case> = serde_json::from_str(&raw).expect("it parses");
        assert!(cases.len() >= 15, "the fixture is {} cases", cases.len());

        for case in &cases {
            assert_eq!(
                live_domains(&case.input),
                case.output,
                "on input {:?}",
                case.input
            );
        }

        // A fixture that had drifted to all-empty would satisfy the loop.
        let kept: usize = cases.iter().map(|c| c.output.len()).sum();
        assert!(kept >= 8, "only {kept} names kept across the fixture");
    }

    /// The output shape, run through `_parse` from
    /// `backend/app/services/orphans.py`.
    ///
    /// Tab-separated, and the summary is a tab *then* space-separated pairs:
    /// that function splits the line on `\t`, takes field two, and splits that
    /// on whitespace. A space where the tab belongs loses every item, and the
    /// panel reports a clean server.
    #[test]
    fn the_report_is_what_the_python_parser_reads() {
        /// What `_parse` pulls out: the items, the summary pairs, and the
        /// archive path.
        type Parsed = (Vec<(String, String)>, Vec<(String, u32)>, String);

        /// `_parse`, in its effects.
        fn parse(text: &str) -> Parsed {
            const CATEGORIES: &[&str] = &[
                "cert",
                "waf-rules",
                "vhost-backup",
                "manual-ssl",
                "sni-copy",
            ];
            let mut items = Vec::new();
            let mut summary = Vec::new();
            let mut archive = String::new();
            for line in text.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 2 {
                    continue;
                }
                let (kind, value) = (parts[0].trim(), parts[1].trim());
                if kind == "summary" {
                    for token in value.split_whitespace() {
                        let (key, count) = token.split_once('=').unwrap_or((token, ""));
                        summary.push((key.to_string(), count.parse().unwrap_or(0)));
                    }
                } else if kind == "archive" {
                    archive = value.to_string();
                } else if CATEGORIES.contains(&kind) {
                    items.push((kind.to_string(), value.to_string()));
                }
            }
            (items, summary, archive)
        }

        let found = Found {
            certs: vec!["gone.example.com".into()],
            waf_rules: vec!["old.example.com".into(), "older.example.com".into()],
            vhost_backups: vec!["dead.example.com.conf.bak.2024".into()],
            manual_ssl: vec![],
            sni_copies: vec!["stale.example.com".into()],
        };

        let mut text = String::new();
        for name in &found.certs {
            text.push_str(&format!("cert\t{name}\n"));
        }
        for name in &found.waf_rules {
            text.push_str(&format!("waf-rules\t{name}\n"));
        }
        for base in &found.vhost_backups {
            text.push_str(&format!("vhost-backup\t{base}\n"));
        }
        for name in &found.sni_copies {
            text.push_str(&format!("sni-copy\t{name}\n"));
        }
        text.push_str(&summary_line(&found));
        text.push_str("archive\t/root/snpanel-removed/orphans-20260921-101500\n");

        let (items, summary, archive) = parse(&text);
        assert_eq!(items.len(), 5, "every item reaches the parser:\n{text}");
        assert_eq!(
            items[0],
            ("cert".to_string(), "gone.example.com".to_string())
        );
        assert_eq!(archive, "/root/snpanel-removed/orphans-20260921-101500");
        assert_eq!(
            summary,
            vec![
                ("certs".to_string(), 1),
                ("waf-rules".to_string(), 2),
                ("vhost-backups".to_string(), 1),
                ("manual-ssl".to_string(), 0),
                ("sni-copies".to_string(), 1),
            ]
        );

        // The tab is the contract. A space in its place loses everything.
        let spaced = text.replace('\t', " ");
        let (items, summary, archive) = parse(&spaced);
        assert!(items.is_empty() && summary.is_empty() && archive.is_empty());
    }

    /// The summary counts each category, and reports zero rather than
    /// omitting a key.
    #[test]
    fn an_empty_scan_still_reports_every_counter() {
        let line = summary_line(&Found::default());
        assert_eq!(
            line,
            "summary\tcerts=0 waf-rules=0 vhost-backups=0 manual-ssl=0 sni-copies=0\n"
        );
        // One tab, then spaces: `_parse` takes field two and splits it.
        assert_eq!(line.matches('\t').count(), 1);
        assert_eq!(
            line.split('\t').nth(1).unwrap().split_whitespace().count(),
            5
        );
    }

    /// `date -u +%Y%m%d-%H%M%S`.
    #[test]
    fn the_archive_stamp_is_sortable() {
        // 2026-09-21T10:15:00Z
        assert_eq!(stamp(1_789_985_700), "20260921-101500");
        // The epoch, and a second before it.
        assert_eq!(stamp(0), "19700101-000000");
        assert_eq!(stamp(-1), "19691231-235959");
        // Sortable as text, which is the point of the format.
        assert!(stamp(1_789_985_700) > stamp(1_789_985_699));
        assert!(stamp(0) < stamp(1));
    }

    /// An empty live list is a refusal, not an empty scan.
    ///
    /// "An empty list almost certainly means the caller failed, not that the
    /// server hosts nothing. Refuse rather than delete everything on the
    /// machine." The Python refuses to ask as well, so this is the second of
    /// two independent guards on the same mistake.
    #[test]
    fn no_live_domains_is_refused_rather_than_deleting_everything() {
        // `panel_domain()` reads the panel's own .env, which is absent in a
        // test environment; where it is present, the panel's own hostname is
        // a live domain and the refusal does not apply.
        if std::path::Path::new(ENV_FILE).exists() {
            eprintln!("skipped: {ENV_FILE} exists here");
            return;
        }
        for input in ["", "\n\n", "   \n", "not a domain\n", "-bad.com\n"] {
            let resp = cleanup(true, input);
            assert!(!resp.ok, "{input:?} should be refused");
            let message = resp
                .error
                .as_ref()
                .map(|e| e.message.clone())
                .unwrap_or_default();
            assert_eq!(
                message, "refusing to clean orphans: no live domains were supplied",
                "{input:?}"
            );
        }
    }
}
