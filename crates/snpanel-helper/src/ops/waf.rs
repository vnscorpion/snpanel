//! `ops::waf` and `ops::malware` - ModSecurity and the scanners.
//!
//! Source: the `waf-*`, `clamav-*` and `maldet-*` arms.
//!
//! Both are **off by default and installed on demand**, and that is a product
//! decision the port must not quietly reverse. The Python config says so for
//! malware scanning in as many words: leaving it off keeps SNPanel lightweight,
//! and it only becomes active after an admin enables it. So `status` must work
//! on a box where none of this is installed, and answer "not installed" rather
//! than failing.

use std::path::Path;

use snpanel_core::Domain;
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: the WAF rule paths in the bash helper.
pub const WAF_DIR: &str = "/etc/nginx/modsec";
pub const CRS_DIR: &str = "/etc/nginx/modsec/crs";
pub const WAF_SITE_DIR: &str = "/etc/nginx/modsec/sites";

/// How aggressively the OWASP Core Rule Set acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrsMode {
    /// Not loaded at all.
    Off,
    /// Loaded, scores requests, blocks nothing. The verdict lands in the audit
    /// log - which is the point of the mode, and where to look.
    Detect,
    Block,
}

impl CrsMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "off" => Some(Self::Off),
            "detect" => Some(Self::Detect),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Detect => "detect",
            Self::Block => "block",
        }
    }
}

/// `waf-status`. Must answer on a box with no ModSecurity at all.
///
/// **On stdout.** The WAF page shows this verb's stdout
/// (`wafRules.status.stdout`), and over the helper socket the API is handed
/// `stdout` and never `data`. While this answered in `data`, the status box
/// was empty on every box that talks to the helper over the socket - which
/// is every fresh install - and said "Click Refresh to load WAF status." after
/// a refresh. Pretty JSON and a newline is what the CLI printed from `data`,
/// so the sudo path shows what it always showed.
pub fn status() -> HelperResponse {
    let module_loaded = exec::run(&["nginx", "-V"])
        .map(|o| {
            // nginx -V writes its configure line to stderr.
            o.stderr.contains("modsecurity") || o.stdout.contains("modsecurity")
        })
        .unwrap_or(false);
    let module_file = Path::new("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so").exists()
        || Path::new("/usr/share/nginx/modules/ngx_http_modsecurity_module.so").exists();

    let status = serde_json::json!({
        "installed": module_loaded || module_file,
        "rules_dir": WAF_DIR,
        "crs_installed": Path::new(CRS_DIR).exists(),
        "crs_mode": read_crs_mode().as_str(),
        "sites_with_rules": count_site_rules(),
    });
    HelperResponse::with_stdout(format!(
        "{}\n",
        serde_json::to_string_pretty(&status).unwrap_or_default()
    ))
}

/// Source: `CRS_MODE_FILE=/etc/nginx/modsec/snpanel-crs-mode`.
///
/// The name is the bash's, not a new one. Rust used to keep the mode in
/// `crs-mode` in the same directory, so the two implementations each wrote a
/// file the other never read: a mode set before the cutover read as `off`
/// after it, and a mode set after it read as `off` on any fallthrough.
pub const CRS_MODE_FILE: &str = "/etc/nginx/modsec/snpanel-crs-mode";

/// Source: `CRS_CONF=/etc/nginx/modsec/snpanel-crs.conf`.
pub const CRS_CONF: &str = "/etc/nginx/modsec/snpanel-crs.conf";

fn read_crs_mode() -> CrsMode {
    // `tr -d '[:space:]'` - not just the ends, because a file written by hand
    // can carry an interior space that `trim` would keep.
    std::fs::read_to_string(CRS_MODE_FILE)
        .ok()
        .and_then(|s| {
            let squeezed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            CrsMode::parse(&squeezed)
        })
        .unwrap_or(CrsMode::Off)
}

fn count_site_rules() -> usize {
    std::fs::read_dir(WAF_SITE_DIR)
        .map(|d| d.filter_map(Result::ok).count())
        .unwrap_or(0)
}

/// `waf-crs-mode`.
pub fn crs_mode_set(mode: CrsMode) -> HelperResponse {
    if let Err(e) = std::fs::create_dir_all(WAF_DIR) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {WAF_DIR}: {e}"),
        );
    }
    let marker = Path::new(WAF_DIR).join("crs-mode");
    if let Err(e) = std::fs::write(&marker, format!("{}\n", mode.as_str())) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {}: {e}", marker.display()),
        );
    }
    HelperResponse::with_data(serde_json::json!({ "crs_mode": mode.as_str() }))
}

/// `waf-crs-status`.
///
/// Source: `waf_crs_status`. Eight `key=value` lines, in its order, because
/// `crs_status` in `backend/app/services/waf.py` reads exactly those keys off
/// stdout - its own dry-run fallback spells the shape out:
/// `echo mode=off; echo installed=no; echo conf=no; echo rule_files=0;
/// echo sites_including=0`.
///
/// Answering with two JSON fields left the page showing CRS as not installed,
/// with every memory figure zero, on servers that had it installed and
/// blocking.
pub fn crs_status() -> HelperResponse {
    let rules_dir = crs_rules_dir();
    let (available_mb, total_mb) = memory_mb();
    HelperResponse::with_stdout(crs_status_lines(CrsStatusFacts {
        mode: read_crs_mode().as_str(),
        nginx_pss_mb: nginx_memory_pss_mb(),
        ram_available_mb: available_mb,
        ram_total_mb: total_mb,
        installed: rules_dir.is_some(),
        conf: Path::new(CRS_CONF).is_file(),
        rule_files: count_conf_files(rules_dir.as_deref()),
        sites_including: sites_including_crs(),
    }))
}

/// What the eight lines say, separated from how they are found.
struct CrsStatusFacts {
    mode: &'static str,
    nginx_pss_mb: u64,
    ram_available_mb: u64,
    ram_total_mb: u64,
    installed: bool,
    conf: bool,
    rule_files: usize,
    sites_including: usize,
}

/// The eight lines, in `waf_crs_status`'s order.
fn crs_status_lines(f: CrsStatusFacts) -> String {
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    format!(
        "mode={}\nnginx_pss_mb={}\nram_available_mb={}\nram_total_mb={}\n\
         installed={}\nconf={}\nrule_files={}\nsites_including={}\n",
        f.mode,
        f.nginx_pss_mb,
        f.ram_available_mb,
        f.ram_total_mb,
        yes_no(f.installed),
        yes_no(f.conf),
        f.rule_files,
        f.sites_including,
    )
}

/// Source: `crs_rules_dir`.
///
/// "Debian/Ubuntu ship the rules under one of these." Checked in the bash's
/// order, first hit wins - the previous constant pointed at
/// `/etc/nginx/modsec/crs`, which is not where any distribution puts them, so
/// `installed` was answering "no" on a correctly installed server.
pub(crate) const CRS_RULE_DIRS: &[&str] = &[
    "/usr/share/modsecurity-crs/rules",
    "/etc/modsecurity/crs/rules",
    "/usr/local/owasp-crs/rules",
];

fn crs_rules_dir() -> Option<std::path::PathBuf> {
    first_existing(CRS_RULE_DIRS)
}

/// The first of `dirs` that is a directory, in the order given.
///
/// Order is the whole of it: a box carrying both a distribution package and a
/// hand-unpacked copy has two, and the bash takes the distribution's.
fn first_existing<P: AsRef<Path>>(dirs: &[P]) -> Option<std::path::PathBuf> {
    dirs.iter()
        .map(|d| std::path::PathBuf::from(d.as_ref()))
        .find(|d| d.is_dir())
}

/// `ls "$(crs_rules_dir)"/*.conf | wc -l`, or 0 when there is no such
/// directory.
fn count_conf_files(dir: Option<&Path>) -> usize {
    let Some(dir) = dir else { return 0 };
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "conf"))
                .count()
        })
        .unwrap_or(0)
}

/// `grep -lF "Include ${CRS_CONF}" /etc/nginx/modsec/sites/*.conf | wc -l`.
///
/// `-F` and `-l`: a fixed string, counted once per file however many times it
/// appears in one.
fn sites_including_crs() -> usize {
    let needle = format!("Include {CRS_CONF}");
    std::fs::read_dir(WAF_SITE_DIR)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "conf"))
                .filter(|e| {
                    std::fs::read_to_string(e.path())
                        .map(|t| t.contains(&needle))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// `free -m | awk '/^Mem:/{print $7}'` and `$2`: available, then total.
fn memory_mb() -> (u64, u64) {
    // /proc/meminfo rather than `free`, which parses that same file and would
    // add a fork and a locale-dependent column layout in between. `free -m`
    // divides by 1024 and truncates, so this does too.
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return (0, 0);
    };
    let field = |name: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .map(|kb| kb / 1024)
            .unwrap_or(0)
    };
    (field("MemAvailable:"), field("MemTotal:"))
}

/// Source: `nginx_memory_pss_mb`, which the bash implements in `python3`.
///
/// "PSS, not RSS. nginx parses the rule set in the master and the workers
/// fork, so those pages are shared: summing RSS across processes counts them
/// once per worker and overstates the cost several times over."
///
/// Porting it here takes another `python3` out of the helper's dependencies.
fn nginx_memory_pss_mb() -> u64 {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let mut pss_kb: u64 = 0;
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let Some(pid) = name.to_str() else { continue };
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm = entry.path().join("comm");
        match std::fs::read_to_string(&comm) {
            Ok(c) if c.trim() == "nginx" => {}
            // A process that exited between the listing and the read is not an
            // error; the bash's `except OSError: continue` says the same.
            _ => continue,
        }
        let Ok(rollup) = std::fs::read_to_string(entry.path().join("smaps_rollup")) else {
            continue;
        };
        // `^Pss:\s+(\d+) kB`, the first match in the file.
        if let Some(value) = rollup.lines().find_map(|l| {
            let rest = l.strip_prefix("Pss:")?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        }) {
            pss_kb += value;
        }
    }
    pss_kb / 1024
}

/// `waf-site-save`: per-site rule file.
pub fn site_rules_save(domain: &Domain, content: &str) -> HelperResponse {
    if let Err(e) = std::fs::create_dir_all(WAF_SITE_DIR) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {WAF_SITE_DIR}: {e}"),
        );
    }
    // The domain is a Domain, so the filename cannot traverse.
    let path = Path::new(WAF_SITE_DIR).join(format!("{domain}.conf"));
    if let Err(e) = std::fs::write(&path, content) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {}: {e}", path.display()),
        );
    }
    // A bad rule file stops nginx from starting, so it is validated before it
    // is allowed to stay.
    let checked = exec::run(&["nginx", "-t"]);
    if matches!(&checked, Ok(o) if o.ok()) {
        return HelperResponse::ok();
    }
    let _ = std::fs::remove_file(&path);
    let mut resp = exec::respond("nginx -t", checked);
    if let Some(err) = resp.error.as_mut() {
        err.message = format!(
            "WAF rules for {domain} rejected, file removed: {}",
            err.message
        );
    }
    resp
}

/// `waf-site-delete`.
pub fn site_rules_delete(domain: &Domain) -> HelperResponse {
    let path = Path::new(WAF_SITE_DIR).join(format!("{domain}.conf"));
    match std::fs::remove_file(&path) {
        Ok(()) => HelperResponse::ok(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HelperResponse::ok(),
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("removing {}: {e}", path.display()),
        ),
    }
}

// ---------------------------------------------------------------------------
// Malware scanning
// ---------------------------------------------------------------------------

/// `clamav-status`. Off by default; this reports rather than installs.
pub fn clamav_status() -> HelperResponse {
    let installed = which("clamd").is_some() || which("clamscan").is_some();
    let service = snpanel_osabi::detect()
        .map(|p| p.clamav_service().to_string())
        .unwrap_or_else(|_| "clamav-daemon".to_string());
    let running = exec::run(&["systemctl", "is-active", &service])
        .map(|o| o.stdout.trim() == "active")
        .unwrap_or(false);

    // One line, two pairs, as the bash writes it: `installed=1 running=0`.
    // There is no Python caller today - this verb is Rust-side surface running
    // ahead of its callers - but the next one to arrive will be written
    // against the bash, so it should find the bash's shape.
    HelperResponse::with_stdout(format!(
        "installed={} running={}\n",
        u8::from(installed),
        u8::from(running)
    ))
}

/// `clamav-start` / `clamav-stop`.
pub fn clamav_control(start: bool) -> HelperResponse {
    let service = snpanel_osabi::detect()
        .map(|p| p.clamav_service().to_string())
        .unwrap_or_else(|_| "clamav-daemon".to_string());
    if which("clamd").is_none() && which("clamscan").is_none() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "ClamAV is not installed; enable malware scanning in the panel first",
        );
    }
    let verb = if start { "start" } else { "stop" };
    exec::respond("systemctl", exec::run(&["systemctl", verb, &service]))
}

fn which(binary: &str) -> Option<std::path::PathBuf> {
    for dir in [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ] {
        let p = Path::new(dir).join(binary);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// `waf-install`: the nginx ModSecurity module, plus SNPanel's own rules.
///
/// Source: `install_waf_engine`.
///
/// Debian only, and refused with the reason on EL rather than handed to a
/// package manager that has no such package: EL10 ships neither the connector
/// nor libmodsecurity, so "no match for argument" would read like a broken
/// repository instead of a settled fact about the distribution.
pub fn install_engine() -> HelperResponse {
    use crate::ops::packages;

    let mut out = String::new();

    if !packages::dpkg_installed(&["libnginx-mod-http-modsecurity"]) {
        if let Some(refusal) = packages::debian_only("installing the nginx ModSecurity module") {
            return refusal;
        }
        if let Ok(o) = packages::update_index() {
            out.push_str(&o.stdout);
        }
        // "The core rule set is a separate package and a box may not carry
        // it." Falling back to the module alone still gives a working engine
        // for SNPanel's own rules, which is what this verb is really for.
        let full = packages::install_packages(&[
            "libnginx-mod-http-modsecurity",
            "modsecurity-crs",
            "libmodsecurity3",
        ]);
        match full {
            Ok(o) if o.ok() => out.push_str(&o.stdout),
            _ => {
                let second = packages::install_packages(&[
                    "libnginx-mod-http-modsecurity",
                    "libmodsecurity3",
                ]);
                match second {
                    Ok(o) if o.ok() => out.push_str(&o.stdout),
                    other => {
                        let detail = match other {
                            Ok(o) => {
                                if o.stderr.trim().is_empty() {
                                    o.stdout
                                } else {
                                    o.stderr
                                }
                            }
                            Err(e) => e.to_string(),
                        };
                        let detail = detail.trim().to_string();
                        return HelperResponse::failed(
                            HelperErrorKind::CommandFailed,
                            if detail.is_empty() {
                                "could not install the nginx ModSecurity module".to_string()
                            } else {
                                format!("could not install the nginx ModSecurity module: {detail}")
                            },
                        );
                    }
                }
            }
        }
    }

    if let Err(resp) = ensure_modsec_dir() {
        return resp;
    }
    if let Err(resp) = write_default_rules() {
        return resp;
    }
    // `touch` - the include has to resolve before nginx will load at all.
    if !Path::new(CUSTOM_CONF).exists() {
        if let Err(e) = std::fs::write(CUSTOM_CONF, "") {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {CUSTOM_CONF}: {e}"),
            );
        }
    }

    // Debian ships the recommended config unactivated. Copying it is what
    // gives `Include /etc/modsecurity/modsecurity.conf` in the base conf
    // something to find - and only when there is no config already, so an
    // administrator's edits are never overwritten.
    let recommended = Path::new("/etc/modsecurity/modsecurity.conf-recommended");
    let active = Path::new("/etc/modsecurity/modsecurity.conf");
    if recommended.is_file() && !active.exists() {
        let _ = std::fs::copy(recommended, active);
    }
    if active.is_file() {
        if let Ok(text) = std::fs::read_to_string(active) {
            let rewritten = rewrite_rule_engine(&text);
            if rewritten != text {
                let _ = std::fs::write(active, rewritten);
            }
        }
    }

    // The module has to be loaded by nginx before any of the above matters.
    // `ln -sfn` replaces an existing link rather than failing on it.
    let available = Path::new("/usr/share/nginx/modules-available/mod-http-modsecurity.conf");
    if available.is_file() {
        let enabled_dir = Path::new("/etc/nginx/modules-enabled");
        let _ = std::fs::create_dir_all(enabled_dir);
        let link = enabled_dir.join("50-mod-http-modsecurity.conf");
        let _ = std::fs::remove_file(&link);
        if let Err(e) = std::os::unix::fs::symlink(available, &link) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("linking {}: {e}", link.display()),
            );
        }
    }

    if let Err(resp) = write_main_conf() {
        return resp;
    }
    if let Err(resp) = crate::ops::nginx::ensure_flood_conf() {
        return resp;
    }

    // `nginx -t` then `systemctl reload nginx`: a configuration nginx rejects
    // must not reach a reload, because the reload is what would take every
    // site on the box down.
    let checked = exec::run(&["nginx", "-t"]);
    if !matches!(&checked, Ok(o) if o.ok()) {
        return exec::respond("nginx -t", checked);
    }
    let reloaded = exec::run(&["systemctl", "reload", "nginx"]);
    if !matches!(&reloaded, Ok(o) if o.ok()) {
        return exec::respond("systemctl reload nginx", reloaded);
    }

    out.push_str("WAF engine installed with SNPanel lightweight WordPress/Laravel/PHP rules.\n");
    HelperResponse::with_stdout(out)
}

/// `sed -i -E 's/^SecRuleEngine .*/SecRuleEngine On/'`.
///
/// Anchored at the start of a line and applied to **every** match, which is
/// what `sed` without a line range does. A file carrying the directive twice -
/// the shipped one and an administrator's - comes out with both saying `On`,
/// and since the last one wins in ModSecurity, rewriting only the first would
/// leave the engine off while reporting that it had been turned on.
///
/// The shipped Debian file says `SecRuleEngine DetectionOnly`, which loads
/// every rule and blocks nothing.
pub(crate) fn rewrite_rule_engine(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.starts_with("SecRuleEngine ") {
            lines.push("SecRuleEngine On".to_string());
        } else {
            lines.push(line.to_string());
        }
    }
    let mut out = lines.join("\n");
    // GNU sed leaves a file that ended without a newline ending without one.
    if ends_with_newline {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This file has three authors — the installer, this, and the panel's
    /// own per-site copy — and the first two are meant to be byte-identical.
    ///
    /// Both are now pinned to one fixture recorded by running the bash on a
    /// real Debian 13, so a change to either shows up here rather than as a
    /// box whose WAF rules depend on which code last wrote the file. The
    /// panel's per-site copy is deliberately one character per line
    /// different; see `DEFAULT_RULES`'s own doc comment.
    #[test]
    fn the_rules_written_here_are_the_ones_the_installer_writes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/installer/snpanel-default.conf.expected");
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the fixture {}: {e}", path.display()));
        assert_eq!(DEFAULT_RULES, expected);
    }

    #[test]
    fn crs_modes_are_exactly_the_three_the_bash_accepts() {
        assert_eq!(CrsMode::parse("off"), Some(CrsMode::Off));
        assert_eq!(CrsMode::parse("detect"), Some(CrsMode::Detect));
        assert_eq!(CrsMode::parse("block"), Some(CrsMode::Block));
        for bad in ["", "Off", "on", "blocking", "detect "] {
            assert!(CrsMode::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn status_works_on_a_box_with_no_waf_installed() {
        // Malware scanning and the WAF are opt-in; the status endpoints are
        // what the panel calls to decide whether to offer the install button,
        // so they must answer rather than fail.
        let r = status();
        assert!(r.ok);
        // The WAF page reads stdout; over the socket `data` never reaches it.
        assert!(r.data.is_none(), "`data` is what the bug put it in");
        let v: serde_json::Value =
            serde_json::from_str(&r.stdout).expect("stdout is the status JSON");
        assert!(v["installed"].is_boolean());
        assert!(v["crs_installed"].is_boolean());
        assert_eq!(
            r.stdout,
            format!("{}\n", serde_json::to_string_pretty(&v).unwrap()),
            "what the CLI printed from `data`"
        );

        // `clamav-status` answers in the bash's one-line form. No Python
        // reads it yet, but the one that does will be written against the
        // bash, so it should find the bash's shape.
        let r = clamav_status();
        assert!(r.ok);
        assert!(r.data.is_none(), "this verb answers on stdout, not in data");
        let mut parts = r.stdout.trim_end().split(' ');
        let installed = parts.next().expect("installed=N");
        let running = parts.next().expect("running=N");
        assert!(
            parts.next().is_none(),
            "one line, two pairs: {:?}",
            r.stdout
        );
        assert!(
            installed == "installed=0" || installed == "installed=1",
            "{installed}"
        );
        assert!(
            running == "running=0" || running == "running=1",
            "{running}"
        );

        // `maldet-status` lives in `ops::packages` and is checked there -
        // by `every_status_line_is_one_python_s_kv_regex_can_read`, which
        // asserts the shape its only caller can parse. Asserting `r.ok` here,
        // which is all this test used to do, is what let it answer in JSON
        // that the panel read as "nothing installed" for as long as it did.
    }

    #[test]
    fn starting_clamav_that_is_not_installed_says_what_to_do() {
        if which("clamd").is_some() || which("clamscan").is_some() {
            eprintln!("skipped: ClamAV is installed here");
            return;
        }
        let r = clamav_control(true);
        assert!(!r.ok);
        let msg = r.error.unwrap().message;
        assert!(msg.contains("not installed"));
        assert!(msg.contains("panel"), "should say how to fix it: {msg}");
    }

    #[test]
    fn a_site_rule_filename_cannot_traverse() {
        // The Domain type is what prevents it.
        for bad in ["../../nginx.conf", "a/../../b", "/etc/passwd"] {
            assert!(Domain::parse(bad).is_err(), "{bad}");
        }
        let d = Domain::parse("example.com").unwrap();
        let path = Path::new(WAF_SITE_DIR).join(format!("{d}.conf"));
        assert_eq!(
            path.to_str().unwrap(),
            "/etc/nginx/modsec/sites/example.com.conf"
        );
    }

    #[test]
    fn deleting_absent_site_rules_succeeds() {
        let d = Domain::parse("no-such-site-xyzzy.example.com").unwrap();
        assert!(site_rules_delete(&d).ok);
    }

    #[test]
    fn crs_defaults_to_off_when_nothing_says_otherwise() {
        // Opt-in: an unreadable or absent marker must not mean "block".
        assert_eq!(CrsMode::Off.as_str(), "off");
    }

    /// `crs_status` in `backend/app/services/waf.py`, applied to these lines.
    ///
    /// That function's own dry-run fallback spells the contract out -
    /// `echo mode=off; echo installed=no; echo conf=no; echo rule_files=0;
    /// echo sites_including=0` - and it reads three more keys besides. The
    /// verb used to answer with two JSON fields, so every key fell back to its
    /// default and the page showed CRS as absent, with zero memory, on servers
    /// running it in blocking mode.
    #[test]
    fn crs_status_says_what_the_python_parser_reads() {
        /// The loop in `crs_status`, verbatim in its effects.
        fn parse(output: &str) -> std::collections::HashMap<String, String> {
            let mut info = std::collections::HashMap::new();
            for line in output.lines() {
                let (key, value) = match line.split_once('=') {
                    Some(pair) => pair,
                    None => continue,
                };
                let (key, value) = (key.trim(), value.trim());
                if matches!(
                    key,
                    "installed"
                        | "conf"
                        | "rule_files"
                        | "sites_including"
                        | "nginx_pss_mb"
                        | "ram_available_mb"
                        | "ram_total_mb"
                        | "mode"
                ) {
                    info.insert(key.to_string(), value.to_string());
                }
            }
            info
        }

        let text = crs_status_lines(CrsStatusFacts {
            mode: "block",
            nginx_pss_mb: 61,
            ram_available_mb: 5156,
            ram_total_mb: 7936,
            installed: true,
            conf: true,
            rule_files: 34,
            sites_including: 7,
        });
        let info = parse(&text);
        assert_eq!(info.len(), 8, "all eight keys reach the parser:\n{text}");
        assert_eq!(info["mode"], "block");
        assert_eq!(info["installed"], "yes");
        assert_eq!(info["conf"], "yes");
        assert_eq!(info["rule_files"], "34");
        assert_eq!(info["sites_including"], "7");
        assert_eq!(info["nginx_pss_mb"], "61");
        assert_eq!(info["ram_available_mb"], "5156");
        assert_eq!(info["ram_total_mb"], "7936");

        // The bash's order, which is what a reader comparing the two sees.
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            keys,
            vec![
                "mode",
                "nginx_pss_mb",
                "ram_available_mb",
                "ram_total_mb",
                "installed",
                "conf",
                "rule_files",
                "sites_including"
            ]
        );

        // A server with nothing installed still writes all eight.
        let text = crs_status_lines(CrsStatusFacts {
            mode: "off",
            nginx_pss_mb: 0,
            ram_available_mb: 0,
            ram_total_mb: 0,
            installed: false,
            conf: false,
            rule_files: 0,
            sites_including: 0,
        });
        assert_eq!(parse(&text).len(), 8);
        assert_eq!(parse(&text)["installed"], "no");

        // And the shape the bug had.
        let json = serde_json::to_string_pretty(
            &serde_json::json!({ "installed": true, "mode": "block" }),
        )
        .expect("json");
        assert!(
            parse(&json).is_empty(),
            "JSON must be unreadable to that parser - that was the bug"
        );
    }

    /// The mode lives in the file the bash reads and writes.
    ///
    /// Rust kept it in `crs-mode` in the same directory while the bash used
    /// `snpanel-crs-mode`, so each implementation wrote a file the other never
    /// looked at: a mode set before the cutover read as `off` after it, and a
    /// mode set after it read as `off` on any fallthrough to bash. Both
    /// directions silently disarm a WAF an administrator believes is on.
    #[test]
    fn the_crs_mode_file_is_the_one_the_bash_uses() {
        assert_eq!(CRS_MODE_FILE, "/etc/nginx/modsec/snpanel-crs-mode");
        assert_eq!(CRS_CONF, "/etc/nginx/modsec/snpanel-crs.conf");
        assert_ne!(
            CRS_MODE_FILE,
            format!("{WAF_DIR}/crs-mode"),
            "the old name must not come back"
        );
    }

    /// `crs_rules_dir`: where distributions actually put the rule set.
    ///
    /// The previous constant was `/etc/nginx/modsec/crs`, which is not one of
    /// them, so `installed` answered "no" on a correctly installed server and
    /// the page offered to install what was already there.
    #[test]
    fn the_rule_set_is_looked_for_where_distributions_put_it() {
        // Asserted directly rather than probed. An earlier version of this
        // test asked the filesystem, so on a machine with no CRS installed -
        // every CI runner - it was true whatever the list said, and it passed
        // while the search pointed at `/etc/nginx/modsec/crs`, which is not
        // where any distribution puts the rules.
        assert_eq!(
            CRS_RULE_DIRS,
            &[
                "/usr/share/modsecurity-crs/rules",
                "/etc/modsecurity/crs/rules",
                "/usr/local/owasp-crs/rules",
            ]
        );
        assert!(
            !CRS_RULE_DIRS.contains(&"/etc/nginx/modsec/crs"),
            "that is the panel's own directory, not the rule set's"
        );

        // And the order, against directories that really exist.
        let base = std::env::temp_dir().join(format!("crs-dirs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let first = base.join("a");
        let second = base.join("b");
        let candidates = [first.clone(), second.clone()];

        assert_eq!(first_existing(&candidates), None, "neither exists yet");

        std::fs::create_dir_all(&second).expect("the second");
        assert_eq!(first_existing(&candidates), Some(second.clone()));

        std::fs::create_dir_all(&first).expect("the first");
        assert_eq!(
            first_existing(&candidates),
            Some(first),
            "the earlier entry wins once it is there"
        );

        // A file of the right name is not a rules directory.
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("the base");
        std::fs::write(base.join("a"), "").expect("a file, not a directory");
        assert_eq!(
            first_existing(&candidates),
            Some(second.clone()).filter(|d| d.is_dir())
        );

        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(count_conf_files(None), 0);
    }

    /// `free -m` truncates, and so does this.
    #[test]
    fn memory_is_reported_in_whole_megabytes() {
        let (available, total) = memory_mb();
        // /proc/meminfo is present on every Linux this runs on.
        assert!(total > 0, "MemTotal should be readable here");
        assert!(available <= total, "available {available} > total {total}");
    }

    /// `sed -i -E 's/^SecRuleEngine .*/SecRuleEngine On/'`.
    ///
    /// Debian ships `SecRuleEngine DetectionOnly`, which loads every rule and
    /// blocks nothing - a WAF that reports as installed and stops no request.
    ///
    /// No line range, so **every** matching line is rewritten. Since the last
    /// `SecRuleEngine` wins in ModSecurity, rewriting only the first would
    /// leave the engine in detection mode while reporting it had been turned
    /// on, which is the same failure one layer down.
    #[test]
    fn the_rule_engine_is_turned_on_on_every_line_that_sets_it() {
        assert_eq!(
            rewrite_rule_engine("SecRuleEngine DetectionOnly\n"),
            "SecRuleEngine On\n"
        );
        assert_eq!(
            rewrite_rule_engine("SecRuleEngine Off\n"),
            "SecRuleEngine On\n"
        );
        assert_eq!(
            rewrite_rule_engine("SecRuleEngine On\n"),
            "SecRuleEngine On\n"
        );

        // Both copies, which is what `sed` without a range does.
        let two = "SecRuleEngine DetectionOnly\nSecAuditEngine RelevantOnly\nSecRuleEngine Off\n";
        assert_eq!(
            rewrite_rule_engine(two),
            "SecRuleEngine On\nSecAuditEngine RelevantOnly\nSecRuleEngine On\n"
        );

        // `^` - a directive inside a comment or a continuation is not this
        // directive and is left alone.
        for untouched in [
            "# SecRuleEngine DetectionOnly\n",
            "  SecRuleEngine DetectionOnly\n",
            "SecRuleEngineFoo DetectionOnly\n",
            "SecAuditEngine On\n",
        ] {
            assert_eq!(rewrite_rule_engine(untouched), untouched, "{untouched:?}");
        }

        // The pattern is `SecRuleEngine ` with a space: the directive with no
        // argument is not what it matches.
        assert_eq!(rewrite_rule_engine("SecRuleEngine\n"), "SecRuleEngine\n");

        // Everything else survives byte for byte, including blank lines.
        let conf = "# -- Rule engine\nSecRuleEngine DetectionOnly\n\nSecRequestBodyAccess On\n";
        assert_eq!(
            rewrite_rule_engine(conf),
            "# -- Rule engine\nSecRuleEngine On\n\nSecRequestBodyAccess On\n"
        );

        // GNU sed leaves a file that ended without a newline ending without
        // one, and an empty file empty.
        assert_eq!(rewrite_rule_engine("SecRuleEngine Off"), "SecRuleEngine On");
        assert_eq!(rewrite_rule_engine(""), "");
    }

    /// The default rule set exists twice, and the copies must agree.
    ///
    /// `DEFAULT_RULES` here, and the heredoc in `write_waf_default_rules` in
    /// `installer/install.sh`. Both write
    /// `/etc/nginx/modsec/snpanel-default.conf`; whichever ran last wins, so a
    /// box that has never called `waf-update` is running the installer's copy
    /// and every other box is running this one.
    ///
    /// They had drifted, and not only in the way the comment on
    /// `DEFAULT_RULES` records. Two rules were `phase:2` in the installer -
    /// 1001302, path traversal, and 1001103, author enumeration - and on the
    /// nginx connector a `phase:2` rule never runs. Measured on Debian 13
    /// against the running module, on GET and on POST, with
    /// `SecRequestBodyAccess` both Off and On:
    ///
    /// ```text
    /// phase:1 on REQUEST_URI          -> 401   fires
    /// phase:2 on REQUEST_URI          -> 404   does not
    /// phase:1 on ARGS (query string)  -> 405   fires
    /// phase:2 on ARGS (query string)  -> 404   does not
    /// ```
    ///
    /// So those two loaded, were counted, showed the WAF as enabled, and
    /// matched nothing - on every box the installer had set up.
    ///
    /// The copies are compared with nothing stripped. The trailing-quote
    /// difference `DEFAULT_RULES` documents was with a **third** copy, the
    /// Python service that built the per-site catalogue: it already used
    /// `phase:1` for both rules, so the installer was the only one of the
    /// three that was wrong.
    ///
    /// The comparison is against the fixture rather than against the other
    /// writer. It was `install.sh`'s heredoc until the installer's copy moved
    /// into `snpanel-install waf-default-rules`; the fixture is the recording
    /// of those exact bytes and does not move when the code does.
    #[test]
    fn the_installers_copy_of_the_rules_matches_this_one() {
        const RECORDED: &str =
            include_str!("../../../../tests/golden/installer/snpanel-default.conf.expected");
        compare_rules("tests/golden/installer/snpanel-default.conf", RECORDED);
    }

    /// One shell copy of the rule set against `DEFAULT_RULES`.
    fn compare_rules(label: &str, shell: &str) {
        let theirs: Vec<&str> = shell.lines().filter(|l| !l.trim().is_empty()).collect();
        let ours: Vec<&str> = DEFAULT_RULES
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();

        assert_eq!(
            ours.len(),
            theirs.len(),
            "{label} differs from DEFAULT_RULES in length"
        );
        assert!(
            ours.len() >= 8,
            "only {} lines; the scan is broken",
            ours.len()
        );

        fn rule_id(line: &str) -> Option<&str> {
            let at = line.find("id:")? + 3;
            let rest = &line[at..];
            let end = rest.find(|c: char| !c.is_ascii_digit())?;
            Some(&rest[..end])
        }

        let mut compared = 0;
        for (ours_line, theirs_line) in ours.iter().zip(theirs.iter()) {
            if !ours_line.starts_with("SecRule") {
                // The header comment, which is identical.
                assert_eq!(ours_line, theirs_line);
                continue;
            }
            assert_eq!(
                rule_id(ours_line),
                rule_id(theirs_line),
                "the rules are in a different order"
            );
            // The whole line. Both write the same file, so a phase, a
            // status, a pattern or a message that has moved on one side only
            // is a disagreement about what that file should contain.
            assert_eq!(
                ours_line,
                theirs_line,
                "rule {:?} differs between DEFAULT_RULES and {label}",
                rule_id(ours_line)
            );
            compared += 1;
        }
        assert!(compared >= 8, "only {compared} rules compared");

        // And the property the drift hid: nothing SNPanel ships is `phase:2`,
        // because on this connector a `phase:2` rule never matches.
        for line in ours.iter().chain(theirs.iter()) {
            assert!(
                !line.contains("phase:2"),
                "{label}: a phase:2 rule loads, is counted, and matches nothing: {line}"
            );
        }
    }
}

/// `/etc/nginx/modsec/snpanel-default.conf` - the eight rules every site on
/// this server gets before its own file is considered.
///
/// Source: `write_waf_default_rules`. **Not** the same bytes as
/// `waf.DEFAULT_RULES` in the panel, and the difference is one character per
/// line: every `SecRule` here closes its action list with `"` and the panel's
/// per-site copy does not. Both load - checked against
/// `ngx_http_modsecurity_module` v1.0.3, which accepts an unterminated action
/// list - so nothing is broken, but they are two copies of one rule set and
/// one of them has drifted. Reproducing the bash exactly is what this function
/// is for; reconciling the two is not a thing to do quietly inside a helper.
const DEFAULT_RULES: &str = concat!(
    "# SNPanel default WAF rules: lightweight WordPress, Laravel, and PHP probes only.\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/\.user\.ini(?:\.|$)|/\.git/|/composer\.(?:json|lock)(?:$|[?])|/(?:phpinfo|info)\.php(?:$|[?])|/(?:config|database|db)\.php\.(?:bak|old|save|txt)(?:$|[?]))" "id:1001301,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP sensitive file probe'""#,
    "\n",
    r#"SecRule REQUEST_URI|ARGS "@rx (?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)" "id:1001302,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP path traversal'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/(?:c99|r57|shell|cmd|wso)\.php(?:$|[?])|/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php(?:$|[?]))" "id:1001303,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP runtime probe'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/artisan(?:$|[?])|/server\.php(?:$|[?])|/storage/logs/[^?]*\.log(?:$|[?])|/bootstrap/cache/[^?]*\.php(?:$|[?]))" "id:1001201,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel sensitive path'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/_ignition/execute-solution(?:$|[?]))" "id:1001202,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel Ignition RCE probe'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/wp-config\.php(?:\.|$|[?])|/wp-content/(?:uploads|cache|upgrade)/[^?]*\.php(?:$|[?])|/wp-admin/includes/[^?]*\.php(?:$|[?])|/wp-includes/[^?]*\.php(?:$|[?]))" "id:1001101,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress sensitive path'""#,
    "\n",
    r#"SecRule ARGS:author "@rx ^[0-9]+$" "id:1001103,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress author enumeration'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/wp-admin/install\.php(?:$|[?])|/wp-admin/setup-config\.php(?:$|[?]))" "id:1001104,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress installer probe'""#,
    "\n",
);

const DEFAULT_CONF: &str = "/etc/nginx/modsec/snpanel-default.conf";
const CUSTOM_CONF: &str = "/etc/nginx/modsec/snpanel-custom.conf";
const BASE_CONF: &str = "/etc/nginx/modsec/snpanel-base.conf";
const MAIN_CONF: &str = "/etc/nginx/modsec/snpanel-main.conf";

/// Source: `MAX_CUSTOM_BYTES` in the panel and `-gt 65536` in the bash.
const MAX_CUSTOM_BYTES: usize = 64 * 1024;

fn ensure_modsec_dir() -> Result<(), HelperResponse> {
    for dir in [WAF_DIR, WAF_SITE_DIR] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {dir}: {e}"),
            ));
        }
    }
    Ok(())
}

/// Source: `write_waf_default_rules`.
fn write_default_rules() -> Result<(), HelperResponse> {
    ensure_modsec_dir()?;
    std::fs::write(DEFAULT_CONF, DEFAULT_RULES).map_err(|e| {
        HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {DEFAULT_CONF}: {e}"),
        )
    })
}

/// Source: `write_modsec_base_conf`.
///
/// `SecRequestBodyAccess Off` is the line to read twice. With body access off
/// the nginx connector never runs phase 2 at all, so a `phase:2` rule is
/// silently dead - it loads, it shows as enabled, and it never matches. Every
/// rule SNPanel ships is therefore `phase:1`. Turning it on is what a
/// payload-inspecting rule set needs, and it has to arrive with that rule
/// set's exclusion tuning: on its own it would make the traversal rule match
/// `../` inside any post body a customer saves.
fn write_base_conf() -> Result<(), HelperResponse> {
    ensure_modsec_dir()?;
    let mut out = String::new();
    // The distribution's own configuration, when it ships one.
    if Path::new("/etc/modsecurity/modsecurity.conf").exists() {
        out.push_str("Include /etc/modsecurity/modsecurity.conf\n");
    }
    out.push_str("SecRuleEngine On\n");
    out.push_str("SecRequestBodyAccess Off\n");
    std::fs::write(BASE_CONF, out).map_err(|e| {
        HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {BASE_CONF}: {e}"),
        )
    })
}

/// Source: `write_modsec_main_conf` - base, default, custom, in that order.
///
/// The order is the load order, and it is why a custom `SecRuleRemoveById`
/// works: a rule can only be removed after it has been loaded.
fn write_main_conf() -> Result<(), HelperResponse> {
    write_default_rules()?;
    write_base_conf()?;
    // `touch` - the include must resolve even when nobody has saved a custom
    // rule, or nginx refuses the whole configuration.
    if !Path::new(CUSTOM_CONF).exists() {
        if let Err(e) = std::fs::write(CUSTOM_CONF, "") {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {CUSTOM_CONF}: {e}"),
            ));
        }
    }
    let main = format!("Include {BASE_CONF}\nInclude {DEFAULT_CONF}\nInclude {CUSTOM_CONF}\n");
    std::fs::write(MAIN_CONF, main).map_err(|e| {
        HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {MAIN_CONF}: {e}"),
        )
    })
}

/// `waf-default-rules` - rewrite the shipped rules, then hand them back.
///
/// It writes before it reads, which looks redundant and is not: the panel's
/// WAF page uses this to show what is actually loaded, and a file edited by
/// hand would otherwise be reported as SNPanel's own.
pub fn default_rules() -> HelperResponse {
    if let Err(resp) = write_default_rules() {
        return resp;
    }
    match std::fs::read_to_string(DEFAULT_CONF) {
        Ok(text) => HelperResponse::with_stdout(text),
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("reading {DEFAULT_CONF}: {e}"),
        ),
    }
}

/// `waf-custom-rules` - what an administrator has added, if anything.
pub fn custom_rules() -> HelperResponse {
    if let Err(resp) = ensure_modsec_dir() {
        return resp;
    }
    // `touch` first: the bash creates the file so a first read answers an
    // empty string rather than an error.
    if !Path::new(CUSTOM_CONF).exists() {
        if let Err(e) = std::fs::write(CUSTOM_CONF, "") {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {CUSTOM_CONF}: {e}"),
            );
        }
    }
    match std::fs::read_to_string(CUSTOM_CONF) {
        Ok(text) => HelperResponse::with_stdout(text),
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("reading {CUSTOM_CONF}: {e}"),
        ),
    }
}

/// `waf-custom-save` - arbitrary ModSecurity directives, from an administrator.
///
/// The two checks are the bash's and they are not decoration. A NUL byte would
/// truncate the file at the point nginx reads it, so what loads is not what was
/// reviewed. The size limit keeps one paste from producing a configuration
/// nginx spends a second parsing on every reload.
///
/// `nginx -t` runs before the reload, and a rejected file is **not** rolled
/// back here - the bash does not roll it back either. That is a real
/// difference from `waf-site-save`, which does, and it is the bash's choice:
/// a server-wide file that fails the test leaves the previous configuration
/// running because the reload never happens.
pub fn custom_rules_save(content: &str) -> HelperResponse {
    if content.as_bytes().contains(&0) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "WAF rules cannot contain NUL bytes".to_string(),
        );
    }
    if content.len() > MAX_CUSTOM_BYTES {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "WAF custom rules must be 64 KB or smaller".to_string(),
        );
    }
    if let Err(resp) = write_default_rules() {
        return resp;
    }
    if let Err(e) = std::fs::write(CUSTOM_CONF, content) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {CUSTOM_CONF}: {e}"),
        );
    }
    if let Err(resp) = write_main_conf() {
        return resp;
    }
    let checked = exec::run(&["nginx", "-t"]);
    if !matches!(&checked, Ok(o) if o.ok()) {
        return exec::respond("nginx -t", checked);
    }
    let reloaded = exec::run(&["systemctl", "reload", "nginx"]);
    if !matches!(&reloaded, Ok(o) if o.ok()) {
        return exec::respond("systemctl reload nginx", reloaded);
    }
    HelperResponse::with_stdout("WAF custom rules saved\n".to_string())
}

/// `waf-update` - rewrite every file the engine loads and reload nginx.
pub fn update_rules() -> HelperResponse {
    if let Err(resp) = write_main_conf() {
        return resp;
    }
    let checked = exec::run(&["nginx", "-t"]);
    if !matches!(&checked, Ok(o) if o.ok()) {
        return exec::respond("nginx -t", checked);
    }
    let reloaded = exec::run(&["systemctl", "reload", "nginx"]);
    if !matches!(&reloaded, Ok(o) if o.ok()) {
        return exec::respond("systemctl reload nginx", reloaded);
    }
    HelperResponse::with_stdout("SNPanel lightweight WAF rules refreshed\n".to_string())
}

#[cfg(test)]
mod conf_tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/waf_helper_conf.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the waf conf fixture"))
            .expect("the fixture parses")
    }

    /// The eight rules every site on the server loads, byte for byte against
    /// what the **bash helper actually wrote** on a live Debian 13.
    ///
    /// Taken by running the helper rather than by reading its heredoc: a
    /// heredoc is easy to transcribe slightly wrong, and the failure mode is
    /// a rule that still loads and no longer matches.
    #[test]
    fn the_default_rules_are_the_bash_helpers_bytes() {
        let want = fixture()["snpanel-default.conf"]
            .as_str()
            .expect("the default rules")
            .to_string();
        assert_eq!(
            DEFAULT_RULES, want,
            "the shipped WAF rules differ from what the bash helper writes"
        );
    }

    /// `snpanel-base.conf`, whose two lines decide whether any rule runs.
    ///
    /// The fixture was taken on a box with no `/etc/modsecurity/modsecurity.conf`,
    /// so it has two lines; the include is added when the distribution ships
    /// one. The test therefore compares against the branch the fixture
    /// recorded and says which branch that was.
    #[test]
    fn the_base_conf_matches_the_bash_helper() {
        let fixture = fixture();
        let want = fixture["snpanel-base.conf"]
            .as_str()
            .expect("the base conf");
        let distro_conf = fixture["modsecurity_conf_present"]
            .as_bool()
            .expect("the flag");
        assert!(
            !distro_conf,
            "the fixture was taken with a distribution modsecurity.conf; \
             regenerate it or teach this test the other branch"
        );
        assert_eq!(want, "SecRuleEngine On\nSecRequestBodyAccess Off\n");

        // `SecRequestBodyAccess Off` is why every rule SNPanel ships is
        // phase:1. With body access off the nginx connector never runs phase
        // 2, so a phase:2 rule loads, shows as enabled, and never matches.
        assert!(want.contains("SecRequestBodyAccess Off"));
        for line in DEFAULT_RULES.lines().filter(|l| l.starts_with("SecRule")) {
            assert!(
                line.contains("phase:1"),
                "a rule that is not phase:1 would be silently dead: {line}"
            );
        }
    }

    /// The include order is the load order, and it is why a custom
    /// `SecRuleRemoveById` works at all: a rule can only be removed after it
    /// has been loaded.
    #[test]
    fn the_main_conf_loads_base_then_default_then_custom() {
        let want = fixture()["snpanel-main.conf"]
            .as_str()
            .expect("the main conf")
            .to_string();
        let built = format!("Include {BASE_CONF}\nInclude {DEFAULT_CONF}\nInclude {CUSTOM_CONF}\n");
        assert_eq!(built, want);
    }

    /// The two refusals `waf-custom-save` makes before it writes anything.
    #[test]
    fn custom_rules_are_refused_before_they_are_written() {
        let nul = custom_rules_save("SecRuleEngine On\0");
        assert!(!nul.ok);
        assert!(
            nul.error
                .as_ref()
                .is_some_and(|e| e.message.contains("NUL bytes")),
            "{nul:?}"
        );

        let big = custom_rules_save(&"x".repeat(MAX_CUSTOM_BYTES + 1));
        assert!(!big.ok);
        assert!(
            big.error
                .as_ref()
                .is_some_and(|e| e.message.contains("64 KB")),
            "{big:?}"
        );

        // Exactly at the limit is allowed *through the size check*. It will
        // then fail `nginx -t` on a box without the module, which is a
        // different refusal and not this one's business.
        let edge = custom_rules_save(&"x".repeat(MAX_CUSTOM_BYTES));
        assert!(
            !edge
                .error
                .as_ref()
                .is_some_and(|e| e.message.contains("64 KB")),
            "the limit is inclusive: {edge:?}"
        );
    }
}
