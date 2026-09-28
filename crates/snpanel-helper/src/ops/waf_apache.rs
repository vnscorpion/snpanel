//! `ops::waf_apache` - the WAF on a Hosting Edition server.
//!
//! After `snpanel upgrade cloudlinux` there is no nginx: Apache runs
//! ModSecurity 2 (`mod_security2`), and LiteSpeed Enterprise runs its own
//! ModSecurity engine over the same Apache configuration - so one rule set,
//! written once under `/etc/httpd`, protects whichever of the two is serving
//! (and keeps protecting after a failover). Verified on the CL-0 trial: the
//! same rule refused the same request on LiteSpeed and on the Apache standby.
//!
//! The OWASP Core Rule Set comes from its GitHub release, pinned by version
//! and SHA-256 below: EL/CloudLinux repositories do not package it.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use super::waf::CrsMode;
use crate::exec;

/// Apache's ModSecurity module, as CloudLinux/EL ship it.
pub const MODSEC_SO: &str = "/usr/lib64/httpd/modules/mod_security2.so";
/// SNPanel's ModSecurity files on a Hosting Edition server.
pub const MODSEC_DIR: &str = "/etc/httpd/modsec";
/// Loaded by the stock `mod_security.conf` (`IncludeOptional modsecurity.d/*.conf`).
pub const CRS_CONF: &str = "/etc/httpd/modsecurity.d/snpanel-crs.conf";
pub const CRS_MODE_FILE: &str = "/etc/httpd/modsec/snpanel-crs-mode";
/// The administrator's copy of `crs-setup.conf`: kept across CRS updates.
pub const CRS_SETUP: &str = "/etc/httpd/modsec/crs-setup.conf";
/// Where CRS releases are unpacked, one directory per version plus `current`.
pub const CRS_HOME: &str = "/usr/share/snpanel-crs";
/// The pinned release, and the SHA-256 GitHub publishes for its
/// `coreruleset-<version>-minimal.tar.gz` asset.
pub const CRS_VERSION: &str = "4.29.0";
pub const CRS_SHA256: &str = "1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed";

fn crs_url() -> String {
    format!(
        "https://github.com/coreruleset/coreruleset/releases/download/v{CRS_VERSION}/coreruleset-{CRS_VERSION}-minimal.tar.gz"
    )
}

/// This machine serves the web through Apache/LiteSpeed with ModSecurity 2,
/// and not through nginx.
pub fn active() -> bool {
    Path::new(MODSEC_SO).exists() && !Path::new("/usr/sbin/nginx").exists()
}

fn current() -> PathBuf {
    Path::new(CRS_HOME).join("current")
}

pub fn crs_installed() -> bool {
    current().join("rules").is_dir()
}

pub fn read_mode() -> CrsMode {
    std::fs::read_to_string(CRS_MODE_FILE)
        .ok()
        .and_then(|s| {
            let squeezed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            CrsMode::parse(&squeezed)
        })
        .unwrap_or(CrsMode::Off)
}

/// `waf-status` on Hosting Edition. Same shape as the nginx answer (the WAF
/// page reads `installed`, `rules_dir`, `crs_installed`, `crs_mode`).
pub fn status() -> HelperResponse {
    let status = serde_json::json!({
        "installed": true,
        "engine": "modsecurity2",
        "rules_dir": MODSEC_DIR,
        "crs_installed": crs_installed(),
        "crs_version": CRS_VERSION,
        "crs_mode": read_mode().as_str(),
        // Rules apply server-wide here until per-site vhost rules exist.
        "sites_with_rules": 0,
    });
    HelperResponse::with_stdout(format!(
        "{}\n",
        serde_json::to_string_pretty(&status).unwrap_or_default()
    ))
}

/// The files CRS ships in `rules/`.
pub fn rule_files() -> usize {
    std::fs::read_dir(current().join("rules"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "conf"))
                .count()
        })
        .unwrap_or(0)
}

/// The include, for `mode`. Request-body and audit settings already come from
/// the stock `mod_security.conf`; this only brings CRS in.
pub fn conf_text(mode: CrsMode) -> String {
    let (inbound, outbound) = if mode == CrsMode::Detect {
        (1_000_000, 1_000_000)
    } else {
        (5, 4)
    };
    let base = current();
    let base = base.display();
    let mut lines = vec![
        "# SNPANEL MANAGED - OWASP Core Rule Set, server-wide. Generated, do not edit."
            .to_string(),
        format!("# mode: {} - CRS {CRS_VERSION}", mode.as_str()),
        "# Read by Apache (mod_security2) and by LiteSpeed through the Apache configuration."
            .to_string(),
        format!("Include {CRS_SETUP}"),
        "SecAction \"id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=1\""
            .to_string(),
        format!("SecAction \"id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold={inbound},setvar:tx.outbound_anomaly_score_threshold={outbound}\""),
        format!("IncludeOptional {base}/plugins/*-config.conf"),
        format!("IncludeOptional {base}/plugins/*-before.conf"),
        format!("Include {base}/rules/*.conf"),
        format!("IncludeOptional {base}/plugins/*-after.conf"),
    ];
    if mode == CrsMode::Detect {
        // Scores still count; these report what block mode would refuse.
        lines.push("SecRule TX:ANOMALY_SCORE \"@ge 5\" \"id:1009001,phase:2,pass,log,auditlog,msg:'SNPanel CRS detect: inbound score %{tx.anomaly_score}, block mode would have refused this request'\"".to_string());
        lines.push("SecRule TX:OUTBOUND_ANOMALY_SCORE \"@ge 4\" \"id:1009002,phase:4,pass,log,auditlog,msg:'SNPanel CRS detect: outbound score %{tx.outbound_anomaly_score}, block mode would have refused this response'\"".to_string());
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// SHA-256 of a file, hex.
fn sha256_of(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Download, verify and unpack the pinned CRS if it is not there yet.
fn ensure_crs() -> Result<String, HelperResponse> {
    let dir = Path::new(CRS_HOME).join(CRS_VERSION);
    let mut out = String::new();
    if !dir.join("rules").is_dir() {
        let tmp = std::env::temp_dir().join(format!("snpanel-crs-{CRS_VERSION}.tar.gz"));
        let fetched = exec::run(&[
            "curl",
            "-fsSL",
            "--max-time",
            "120",
            "-o",
            &tmp.to_string_lossy(),
            &crs_url(),
        ]);
        if !matches!(&fetched, Ok(o) if o.ok()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(exec::respond("downloading OWASP CRS", fetched));
        }
        match sha256_of(&tmp) {
            Ok(sum) if sum == CRS_SHA256 => {}
            Ok(sum) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(HelperResponse::failed(
                    HelperErrorKind::CommandFailed,
                    format!("OWASP CRS {CRS_VERSION} checksum mismatch: got {sum}, expected {CRS_SHA256}"),
                ));
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(HelperResponse::failed(
                    HelperErrorKind::Internal,
                    format!("reading the CRS download: {e}"),
                ));
            }
        }
        let staging = Path::new(CRS_HOME).join(format!(".{CRS_VERSION}.new"));
        let _ = std::fs::remove_dir_all(&staging);
        if let Err(e) = std::fs::create_dir_all(&staging) {
            let _ = std::fs::remove_file(&tmp);
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {}: {e}", staging.display()),
            ));
        }
        let unpacked = exec::run(&[
            "tar",
            "xzf",
            &tmp.to_string_lossy(),
            "-C",
            &staging.to_string_lossy(),
            "--strip-components=1",
            "--no-same-owner",
        ]);
        let _ = std::fs::remove_file(&tmp);
        if !matches!(&unpacked, Ok(o) if o.ok()) || !staging.join("rules").is_dir() {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(exec::respond("unpacking OWASP CRS", unpacked));
        }
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(e) = std::fs::rename(&staging, &dir) {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("installing {}: {e}", dir.display()),
            ));
        }
        out.push_str(&format!(
            "Installed OWASP CRS {CRS_VERSION} (SHA-256 verified)\n"
        ));
    }
    let linked = exec::run(&[
        "ln",
        "-sfn",
        &dir.to_string_lossy(),
        &current().to_string_lossy(),
    ]);
    if !matches!(&linked, Ok(o) if o.ok()) {
        return Err(exec::respond("linking OWASP CRS", linked));
    }
    if !Path::new(CRS_SETUP).exists() {
        if let Err(e) = std::fs::create_dir_all(MODSEC_DIR)
            .and_then(|_| std::fs::copy(dir.join("crs-setup.conf.example"), CRS_SETUP).map(|_| ()))
        {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {CRS_SETUP}: {e}"),
            ));
        }
    }
    Ok(out)
}

/// `httpd -t`, then Apache reloaded and LiteSpeed restarted (graceful).
fn apply() -> Result<(), HelperResponse> {
    let tested = exec::run(&["httpd", "-t"]);
    if !matches!(&tested, Ok(o) if o.ok()) {
        return Err(exec::respond("httpd -t", tested));
    }
    let reloaded = exec::run(&["systemctl", "reload", "httpd"]);
    if !matches!(&reloaded, Ok(o) if o.ok()) {
        return Err(exec::respond("systemctl reload httpd", reloaded));
    }
    let lsws = "/usr/local/lsws/bin/lswsctrl";
    if Path::new(lsws).exists() {
        let restarted = exec::run(&[lsws, "restart"]);
        if !matches!(&restarted, Ok(o) if o.ok()) {
            return Err(exec::respond("lswsctrl restart", restarted));
        }
    }
    Ok(())
}

fn write_file(path: &str, text: &str) -> Result<(), HelperResponse> {
    crate::ops::nginx::write_atomic(Path::new(path), text.as_bytes(), 0o644).map_err(|e| {
        HelperResponse::failed(HelperErrorKind::Internal, format!("writing {path}: {e}"))
    })
}

/// `waf-crs-mode` on Hosting Edition.
pub fn crs_mode_set(mode: CrsMode) -> HelperResponse {
    if let Err(e) = std::fs::create_dir_all(MODSEC_DIR) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {MODSEC_DIR}: {e}"),
        );
    }
    let previous = std::fs::read_to_string(CRS_CONF).ok();
    let mut out = String::new();
    if mode == CrsMode::Off {
        match std::fs::remove_file(CRS_CONF) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return HelperResponse::failed(
                    HelperErrorKind::Internal,
                    format!("removing {CRS_CONF}: {e}"),
                )
            }
        }
    } else {
        match ensure_crs() {
            Ok(s) => out.push_str(&s),
            Err(r) => return r,
        }
        if let Err(r) = write_file(CRS_CONF, &conf_text(mode)) {
            return r;
        }
    }
    if let Err(r) = apply() {
        // Put back what was running, so a bad include never takes the web down.
        match &previous {
            Some(text) => {
                let _ = write_file(CRS_CONF, text);
            }
            None => {
                let _ = std::fs::remove_file(CRS_CONF);
            }
        }
        let _ = apply();
        return r;
    }
    if let Err(r) = write_file(CRS_MODE_FILE, &format!("{}\n", mode.as_str())) {
        return r;
    }
    out.push_str(&format!("OWASP CRS mode: {}\n", mode.as_str()));
    let mut resp = HelperResponse::with_stdout(out);
    resp.data = Some(serde_json::json!({ "crs_mode": mode.as_str() }));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_mode_uses_crs_default_thresholds() {
        let t = conf_text(CrsMode::Block);
        assert!(t.contains("inbound_anomaly_score_threshold=5"));
        assert!(t.contains("outbound_anomaly_score_threshold=4"));
        assert!(t.contains(&format!("Include {CRS_SETUP}")));
        assert!(t.contains("/rules/*.conf"));
        assert!(!t.contains("1009001"));
    }

    #[test]
    fn detect_mode_blocks_nothing_but_reports_what_block_would() {
        let t = conf_text(CrsMode::Detect);
        assert!(t.contains("inbound_anomaly_score_threshold=1000000"));
        assert!(t.contains("id:1009001") && t.contains("id:1009002"));
    }

    #[test]
    fn the_setup_include_comes_before_the_rules() {
        let t = conf_text(CrsMode::Block);
        let setup = t.find("crs-setup.conf").unwrap();
        let rules = t.find("/rules/*.conf").unwrap();
        assert!(setup < rules);
    }

    #[test]
    fn the_pin_is_a_sha256() {
        assert_eq!(CRS_SHA256.len(), 64);
        assert!(CRS_SHA256.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(crs_url().ends_with(&format!("coreruleset-{CRS_VERSION}-minimal.tar.gz")));
    }

    #[test]
    fn sha256_matches_a_known_value() {
        let p = std::env::temp_dir().join(format!("snpanel-sha-{}", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            sha256_of(&p).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(&p);
    }
}
