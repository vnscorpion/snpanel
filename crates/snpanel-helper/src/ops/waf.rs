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
pub fn status() -> HelperResponse {
    let module_loaded = exec::run(&["nginx", "-V"])
        .map(|o| {
            // nginx -V writes its configure line to stderr.
            o.stderr.contains("modsecurity") || o.stdout.contains("modsecurity")
        })
        .unwrap_or(false);
    let module_file = Path::new("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so").exists()
        || Path::new("/usr/share/nginx/modules/ngx_http_modsecurity_module.so").exists();

    HelperResponse::with_data(serde_json::json!({
        "installed": module_loaded || module_file,
        "rules_dir": WAF_DIR,
        "crs_installed": Path::new(CRS_DIR).exists(),
        "crs_mode": read_crs_mode().as_str(),
        "sites_with_rules": count_site_rules(),
    }))
}

fn read_crs_mode() -> CrsMode {
    std::fs::read_to_string(Path::new(WAF_DIR).join("crs-mode"))
        .ok()
        .and_then(|s| CrsMode::parse(s.trim()))
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
pub fn crs_status() -> HelperResponse {
    HelperResponse::with_data(serde_json::json!({
        "installed": Path::new(CRS_DIR).exists(),
        "mode": read_crs_mode().as_str(),
    }))
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

    HelperResponse::with_data(serde_json::json!({
        "installed": installed,
        "service": service,
        "running": running,
    }))
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

/// `maldet-status`.
pub fn maldet_status() -> HelperResponse {
    HelperResponse::with_data(serde_json::json!({
        "installed": which("maldet").is_some(),
        "signatures": Path::new("/usr/local/maldetect/sigs").exists(),
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(r.data.unwrap()["installed"].is_boolean());

        let r = clamav_status();
        assert!(r.ok);
        assert!(r.data.unwrap()["installed"].is_boolean());

        let r = maldet_status();
        assert!(r.ok);
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
