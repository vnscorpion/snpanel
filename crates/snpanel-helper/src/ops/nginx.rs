//! `ops::nginx` - writing vhosts and reloading.
//!
//! Source: the `nginx-test`, `nginx-reload`, `nginx-custom-write` and
//! `nginx-custom-delete` arms of the bash helper.
//!
//! The ordering here is the thing to preserve: **test before reload, always**.
//! `systemctl reload nginx` on a broken config leaves the old workers running
//! and returns success, so the panel would report "saved" while serving the
//! previous configuration - the worst kind of failure, because it is silent.

use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use snpanel_core::Domain;
use snpanel_ipc::{HelperErrorKind, HelperResponse, VhostKind};

use crate::exec;

/// Source: `NGINX_CONF_DIR`.
pub const CONF_DIR: &str = "/etc/nginx/conf.d";

/// Where a site's operator-supplied extra directives live.
/// Source: `_custom_include_path` in `services/nginx.py`.
pub const CUSTOM_DIR: &str = "/etc/nginx/snpanel-custom";

pub fn vhost_path(domain: &Domain) -> PathBuf {
    PathBuf::from(CONF_DIR).join(format!("{domain}.conf"))
}

pub fn custom_path(domain: &Domain) -> PathBuf {
    PathBuf::from(CUSTOM_DIR).join(format!("{domain}.conf"))
}

pub fn test() -> HelperResponse {
    exec::respond("nginx -t", exec::run(&["nginx", "-t"]))
}

pub fn reload() -> HelperResponse {
    // Test first. The bash does the same, and for the same reason.
    let checked = exec::run(&["nginx", "-t"]);
    match &checked {
        Ok(o) if o.ok() => {}
        _ => {
            let mut resp = exec::respond("nginx -t", checked);
            if let Some(err) = resp.error.as_mut() {
                err.message = format!("refusing to reload, config is invalid: {}", err.message);
            }
            return resp;
        }
    }
    exec::respond(
        "systemctl reload nginx",
        exec::run(&["systemctl", "reload", "nginx"]),
    )
}

/// Write a rendered vhost, then verify the whole config still parses.
///
/// If it does not, the previous file is put back. A panel that leaves nginx
/// unable to start has taken every site on the box down, not just the one
/// being edited.
pub fn write_site(domain: &Domain, rendered: &str, _kind: VhostKind) -> HelperResponse {
    let path = vhost_path(domain);
    let previous = std::fs::read(&path).ok();

    if let Err(e) = write_atomic(&path, rendered.as_bytes(), 0o644) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {}: {e}", path.display()),
        );
    }

    let checked = exec::run(&["nginx", "-t"]);
    let good = matches!(&checked, Ok(o) if o.ok());
    if good {
        return HelperResponse::ok();
    }

    // Roll back.
    match previous {
        Some(bytes) => {
            let _ = write_atomic(&path, &bytes, 0o644);
        }
        None => {
            let _ = std::fs::remove_file(&path);
        }
    }
    let mut resp = exec::respond("nginx -t", checked);
    if let Some(err) = resp.error.as_mut() {
        err.message = format!(
            "vhost for {domain} rejected by nginx, previous config restored: {}",
            err.message
        );
    }
    resp
}

pub fn custom_write(domain: &Domain, content: &str) -> HelperResponse {
    let path = custom_path(domain);
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("creating {}: {e}", parent.display()),
            );
        }
    }
    let previous = std::fs::read(&path).ok();
    if let Err(e) = write_atomic(&path, content.as_bytes(), 0o644) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {}: {e}", path.display()),
        );
    }
    let checked = exec::run(&["nginx", "-t"]);
    if matches!(&checked, Ok(o) if o.ok()) {
        return HelperResponse::ok();
    }
    match previous {
        Some(bytes) => {
            let _ = write_atomic(&path, &bytes, 0o644);
        }
        None => {
            let _ = std::fs::remove_file(&path);
        }
    }
    exec::respond("nginx -t", checked)
}

pub fn custom_delete(domain: &Domain) -> HelperResponse {
    let path = custom_path(domain);
    match std::fs::remove_file(&path) {
        Ok(()) => HelperResponse::ok(),
        // Already gone is the desired state.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HelperResponse::ok(),
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("removing {}: {e}", path.display()),
        ),
    }
}

/// Write via a temporary file and rename.
///
/// nginx may be reading the file at the moment it is replaced; a rename is
/// atomic, a truncate-and-write is not.
fn write_atomic(path: &std::path::Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dir = path.parent().unwrap_or(std::path::Path::new("/"));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("snpanel")
    ));

    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// the shared HTTP flood zones
// ---------------------------------------------------------------------------

/// Source: `NGINX_HTTP_FLOOD_ZONES` and friends.
const FLOOD_ZONES: &str = "/etc/nginx/snpanel/http-flood-zones.conf";
const FLOOD_CONF: &str = "/etc/nginx/conf.d/00-snpanel-http-flood.conf";
/// Two names this file used to have. They are removed on every write, because
/// nginx loads everything in `conf.d` and a leftover copy would declare the
/// same `limit_req_zone` twice - which nginx refuses, taking every site down
/// on the next reload.
const FLOOD_LEGACY_CONF: &str = "/etc/nginx/conf.d/snpanel-http-flood.conf";
const FLOOD_SERVER_CONF: &str = "/etc/nginx/snpanel/http-flood-server.conf";

/// Source: `-gt 131072` in `save_http_flood_zones`.
const MAX_FLOOD_BYTES: usize = 128 * 1024;

/// The file the bash writes when there is nothing to write - and the one it
/// restores to when a rejected configuration has no backup to go back to.
///
/// It is not empty, and that is deliberate: every vhost with flood protection
/// on refers to `$snpanel_http_flood_key` and `snpanel_conn_flood`, so an
/// empty file fails `nginx -t` for those sites rather than merely disabling
/// them.
const FLOOD_ZONES_FALLBACK: &str = concat!(
    "# Managed by SNPanel. Shared zones for per-website HTTP flood protection.\n",
    "map $cookie_snpanel_http_flood_ok $snpanel_http_flood_key {\n",
    "    default $binary_remote_addr;\n",
    "    1 \"\";\n",
    "}\n",
    "limit_conn_zone $snpanel_http_flood_key zone=snpanel_conn_flood:10m;\n",
);

/// Source: `write_http_flood_nginx_conf`.
pub(crate) fn ensure_flood_conf() -> Result<(), HelperResponse> {
    if let Err(e) = std::fs::create_dir_all("/etc/nginx/snpanel") {
        return Err(HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating /etc/nginx/snpanel: {e}"),
        ));
    }
    if !Path::new(FLOOD_ZONES).exists() {
        if let Err(e) = std::fs::write(FLOOD_ZONES, FLOOD_ZONES_FALLBACK) {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("writing {FLOOD_ZONES}: {e}"),
            ));
        }
    }
    let conf = concat!(
        "# Managed by SNPanel. Shared zones for per-website HTTP flood protection.\n",
        "include /etc/nginx/snpanel/http-flood-zones.conf;\n",
    );
    if let Err(e) = std::fs::write(FLOOD_CONF, conf) {
        return Err(HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {FLOOD_CONF}: {e}"),
        ));
    }
    let _ = std::fs::remove_file(FLOOD_LEGACY_CONF);
    let _ = std::fs::remove_file(FLOOD_SERVER_CONF);
    Ok(())
}

/// `http-flood-zones-save` - the server-wide zone file, from stdin.
///
/// The rollback is the whole shape of this function. The file is shared by
/// every site with flood protection on, so a version nginx rejects does not
/// just disable the feature: it stops the *next* reload for every vhost on the
/// box. So the previous bytes are kept, restored if `nginx -t` fails, and when
/// there were no previous bytes the fallback above is written instead - never
/// nothing.
pub fn flood_zones_save(content: &str) -> HelperResponse {
    if content.len() > MAX_FLOOD_BYTES {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "HTTP flood zones are too large".to_string(),
        );
    }
    if content.as_bytes().contains(&0) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "HTTP flood zones cannot contain NUL bytes".to_string(),
        );
    }

    // The bash copies the old file to `<path>.bak.<epoch>` and moves it back.
    // Holding the bytes in memory reaches the same end without leaving a
    // timestamped file behind when the process dies between the two steps.
    let previous = std::fs::read_to_string(FLOOD_ZONES).ok();

    if let Err(e) = std::fs::create_dir_all("/etc/nginx/snpanel") {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating /etc/nginx/snpanel: {e}"),
        );
    }
    if let Err(e) = std::fs::write(FLOOD_ZONES, content) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {FLOOD_ZONES}: {e}"),
        );
    }
    if let Err(resp) = ensure_flood_conf() {
        return resp;
    }

    let checked = exec::run(&["nginx", "-t"]);
    if !matches!(&checked, Ok(o) if o.ok()) {
        let restore = previous.as_deref().unwrap_or(FLOOD_ZONES_FALLBACK);
        let _ = std::fs::write(FLOOD_ZONES, restore);
        let mut resp = exec::respond("nginx -t", checked);
        if let Some(err) = resp.error.as_mut() {
            err.message = format!("Nginx rejected HTTP flood zones: {}", err.message);
        }
        return resp;
    }

    let reloaded = exec::run(&["systemctl", "reload", "nginx"]);
    if !matches!(&reloaded, Ok(o) if o.ok()) {
        return exec::respond("systemctl reload nginx", reloaded);
    }
    HelperResponse::with_stdout("HTTP flood zones saved\n".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_follow_the_installed_layout() {
        let d = Domain::parse("example.com").unwrap();
        assert_eq!(
            vhost_path(&d).to_str().unwrap(),
            "/etc/nginx/conf.d/example.com.conf"
        );
        assert_eq!(
            custom_path(&d).to_str().unwrap(),
            "/etc/nginx/snpanel-custom/example.com.conf"
        );
    }

    #[test]
    fn a_domain_cannot_escape_the_conf_directory() {
        // The type is what stops this: these never become a Domain, so they
        // never reach vhost_path at all.
        for bad in ["../../etc/nginx/nginx.conf", "a/b", "..", "/etc/passwd"] {
            assert!(Domain::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn atomic_write_replaces_content_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("snpanel-nginx-{}", std::process::id()));
        let path = dir.join("test.conf");

        write_atomic(&path, b"first", 0o644).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");

        write_atomic(&path, b"second", 0o644).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        // No temporary file left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "temp file not cleaned up");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deleting_an_absent_custom_block_succeeds() {
        // Idempotent: the caller asked for it gone, and it is gone.
        let d = Domain::parse("no-such-site-xyzzy.example.com").unwrap();
        assert!(custom_delete(&d).ok);
    }
}
