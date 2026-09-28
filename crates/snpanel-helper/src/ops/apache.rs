//! `ops::apache` - website vhosts on the Hosting Edition.
//!
//! The API renders each site's vhost (`snpanel-api/src/apache_vhost.rs`);
//! the helper puts it in `/etc/httpd/snpanel/sites/`, which Apache and
//! LiteSpeed (in its Apache-configuration mode) both read, and makes sure
//! the configuration still loads before either reloads. A vhost Apache
//! refuses is taken back, so one site's change never stops the others.

use std::path::{Path, PathBuf};

use snpanel_ipc::{HelperErrorKind, HelperResponse};

use super::waf_apache::apply;

pub const SITES_DIR: &str = "/etc/httpd/snpanel/sites";
/// The ports Apache listens on, as literals (LiteSpeed expands no `Define`)
/// and the TLS session cache the site vhosts on 8443 share.
pub const LISTEN_INC: &str = "/etc/httpd/conf.d/00-snpanel-listen.inc";
const LISTEN_TEXT: &str = "Listen 8080\nListen 8443 https\nSSLSessionCache shmcb:/run/httpd/sslcache(512000)\nSSLSessionCacheTimeout 300\n";
/// Every vhost the panel writes starts with this; nothing else is accepted.
const MARKER: &str = "# SNPANEL MANAGED VHOST";
const MAX_BYTES: usize = 256 * 1024;

/// Whether this is the Hosting Edition: Apache, and no nginx.
pub fn active() -> bool {
    Path::new("/usr/sbin/httpd").exists() && !Path::new("/usr/sbin/nginx").exists()
}

fn site_path(domain: &str) -> PathBuf {
    // A Domain: no separators, so it cannot leave SITES_DIR.
    Path::new(SITES_DIR).join(format!("{domain}.conf"))
}

fn failed(message: String) -> HelperResponse {
    HelperResponse::failed(HelperErrorKind::Internal, message)
}

/// `apache-site-write`.
pub fn site_write(domain: &str, content: &str) -> HelperResponse {
    if !active() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "apache-site-write is for the Hosting Edition".to_string(),
        );
    }
    if !content.starts_with(MARKER) || content.len() > MAX_BYTES || content.contains('\0') {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "not a vhost the panel wrote".to_string(),
        );
    }
    if let Err(e) = std::fs::create_dir_all(SITES_DIR) {
        return failed(format!("creating {SITES_DIR}: {e}"));
    }
    let listen_before = std::fs::read(LISTEN_INC).ok();
    if listen_before.as_deref() != Some(LISTEN_TEXT.as_bytes()) {
        if let Err(e) = std::fs::write(LISTEN_INC, LISTEN_TEXT) {
            return failed(format!("writing {LISTEN_INC}: {e}"));
        }
    }
    let path = site_path(domain);
    let previous = std::fs::read(&path).ok();
    if let Err(e) = crate::ops::nginx::write_atomic(&path, content.as_bytes(), 0o644) {
        return failed(format!("writing {}: {e}", path.display()));
    }
    if let Err(mut resp) = apply() {
        let _ = match &previous {
            Some(bytes) => std::fs::write(&path, bytes),
            None => std::fs::remove_file(&path),
        };
        if let Some(bytes) = &listen_before {
            let _ = std::fs::write(LISTEN_INC, bytes);
        }
        let _ = apply();
        if let Some(err) = resp.error.as_mut() {
            err.message = format!(
                "vhost for {domain} rejected, previous one restored: {}",
                err.message
            );
        }
        return resp;
    }
    HelperResponse::with_stdout(format!("{}\n", path.display()))
}

/// `apache-site-delete`. A missing vhost is not an error.
pub fn site_delete(domain: &str) -> HelperResponse {
    if !active() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "apache-site-delete is for the Hosting Edition".to_string(),
        );
    }
    let path = site_path(domain);
    match std::fs::remove_file(&path) {
        Ok(()) => match apply() {
            Ok(()) => HelperResponse::ok(),
            Err(resp) => resp,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HelperResponse::ok(),
        Err(e) => failed(format!("removing {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_listen_file_carries_both_ports_as_literals() {
        assert!(super::LISTEN_TEXT.contains("Listen 8080\n"));
        assert!(super::LISTEN_TEXT.contains("Listen 8443 https\n"));
        assert!(!super::LISTEN_TEXT.contains("${"));
    }
}
