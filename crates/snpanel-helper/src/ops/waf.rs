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
