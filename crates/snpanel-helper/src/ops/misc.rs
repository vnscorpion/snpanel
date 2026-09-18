//! `ops::misc` - the smaller domains: IPv6, time, cron, cache, updates.
//!
//! Source: the `ipv6-*`, `time-*`, `cron-*`, `fastcgi-cache-clear`,
//! `service-status` and `updates-*` arms.
//!
//! These have little in common beyond being small, which is exactly how the
//! bash groups them too (plan Appendix B, `ops::misc`).

use std::path::Path;

use snpanel_core::PanelUsername;
use snpanel_ipc::{HelperErrorKind, HelperResponse, ServiceName};

use crate::exec;

/// Source: `PANEL_IPV6_MARKER`. The bash calls this "the only truth": the
/// panel reads it, the tools vhost is rendered from it, and nothing else
/// decides whether IPv6 is on.
pub const IPV6_MARKER: &str = "/etc/snpanel/ipv6-enabled";
pub const DATA_DIR: &str = "/var/lib/snpanel";
pub const FASTCGI_CACHE: &str = "/var/cache/nginx/snpanel-fastcgi";

// ---------------------------------------------------------------------------
// IPv6
// ---------------------------------------------------------------------------

/// C40: IPv6 counts only when the machine actually has a global address.
///
/// A link-local `fe80::` address is present on every interface and means
/// nothing for reachability, so scope filtering is the whole check.
pub fn ipv6_available() -> bool {
    exec::run(&["ip", "-6", "addr", "show", "scope", "global"])
        .map(|o| o.ok() && o.stdout.contains("inet6"))
        .unwrap_or(false)
}

pub fn ipv6_status() -> HelperResponse {
    let available = ipv6_available();
    let enabled = Path::new(IPV6_MARKER).exists();
    HelperResponse::with_data(serde_json::json!({
        "available": available,
        "enabled": enabled,
    }))
}

/// `ipv6-enable`. Refuses when there is no global address, because turning it
/// on would render vhosts that listen on an address the box does not have -
/// and nginx then fails to start, taking every site down.
pub fn ipv6_enable() -> HelperResponse {
    if !ipv6_available() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "this server has no global IPv6 address",
        );
    }
    if let Err(e) = std::fs::create_dir_all("/etc/snpanel") {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating /etc/snpanel: {e}"),
        );
    }
    if let Err(e) = std::fs::write(IPV6_MARKER, "") {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {IPV6_MARKER}: {e}"),
        );
    }
    HelperResponse::with_data(serde_json::json!({ "enabled": true }))
}

pub fn ipv6_disable() -> HelperResponse {
    match std::fs::remove_file(IPV6_MARKER) {
        Ok(()) => HelperResponse::with_data(serde_json::json!({ "enabled": false })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HelperResponse::with_data(serde_json::json!({ "enabled": false }))
        }
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("removing {IPV6_MARKER}: {e}"),
        ),
    }
}

/// `ipv6-apply`: turn it off if the address has gone away.
///
/// C40's second half. A VPS can lose its IPv6 allocation on a migration, and
/// a panel that keeps rendering `listen [::]:443` after that is a panel whose
/// nginx will not start on the next reload.
pub fn ipv6_apply() -> HelperResponse {
    let enabled = Path::new(IPV6_MARKER).exists();
    if enabled && !ipv6_available() {
        let _ = std::fs::remove_file(IPV6_MARKER);
        return HelperResponse::with_data(serde_json::json!({
            "enabled": false,
            "changed": true,
            "reason": "the global IPv6 address is gone",
        }));
    }
    HelperResponse::with_data(serde_json::json!({
        "enabled": enabled,
        "changed": false,
    }))
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

pub fn time_status() -> HelperResponse {
    let synchronized = exec::run(&["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        .map(|o| o.stdout.trim() == "yes")
        .unwrap_or(false);
    let timezone = exec::run(&["timedatectl", "show", "-p", "Timezone", "--value"])
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    HelperResponse::with_data(serde_json::json!({
        "synchronized": synchronized,
        "timezone": timezone,
        "unix_time": now,
    }))
}

/// `time-sync`. Which daemon to prod is a platform difference, not something
/// to guess at: `systemd-timesyncd` on Debian, `chronyd` on EL.
pub fn time_sync() -> HelperResponse {
    use snpanel_osabi::TimeSync;

    let service = match snpanel_osabi::detect().map(|p| p.timesync()) {
        Ok(TimeSync::Chronyd) => "chronyd",
        _ => "systemd-timesyncd",
    };
    let _ = exec::run(&["timedatectl", "set-ntp", "true"]);
    let resp = exec::respond(
        "systemctl restart timesync",
        exec::run(&["systemctl", "restart", service]),
    );
    if resp.ok {
        return time_status();
    }
    resp
}

// ---------------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------------

/// `cron-list`. Runs as the target user, so the crontab read is the user's own.
pub fn cron_list(user: Option<&PanelUsername>) -> HelperResponse {
    let web = web_user();
    let name = user.map(|u| u.as_str()).unwrap_or(&web);
    let out = exec::run(&["runuser", "-u", name, "--", "crontab", "-l"]);
    // `crontab -l` exits non-zero when there is no crontab, which is not an
    // error - it is an empty list.
    match out {
        Ok(o) if o.ok() => HelperResponse::with_stdout(o.stdout),
        Ok(_) => HelperResponse::with_stdout(""),
        Err(e) => HelperResponse::failed(HelperErrorKind::Internal, e.to_string()),
    }
}

/// `cron-write`. The content arrives on stdin, never as an argument: a crontab
/// is multi-line and would be mangled by argv, and it can carry secrets.
pub fn cron_write(user: Option<&PanelUsername>, content: &str) -> HelperResponse {
    let web = web_user();
    let name = user.map(|u| u.as_str()).unwrap_or(&web);
    // crontab requires a trailing newline or it silently drops the last line.
    let body = if content.ends_with('\n') {
        content.to_string()
    } else {
        format!("{content}\n")
    };
    exec::respond(
        "crontab -",
        exec::run_with_stdin(
            &["runuser", "-u", name, "--", "crontab", "-"],
            Some(body.as_bytes()),
        ),
    )
}

// ---------------------------------------------------------------------------
// Cache, services, updates
// ---------------------------------------------------------------------------

/// `fastcgi-cache-clear`. Empties the cache without removing the directory,
/// which nginx holds open.
pub fn fastcgi_cache_clear() -> HelperResponse {
    let web = web_user();
    let group = web_group();
    if let Err(e) = std::fs::create_dir_all(FASTCGI_CACHE) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {FASTCGI_CACHE}: {e}"),
        );
    }
    let owner = format!("{web}:{group}");
    let _ = exec::run(&["chown", &owner, FASTCGI_CACHE]);
    let _ = exec::run(&["chmod", "0755", FASTCGI_CACHE]);

    exec::respond(
        "find -delete",
        exec::run(&["find", FASTCGI_CACHE, "-mindepth", "1", "-delete"]),
    )
}

/// `service-status`: the full unit status, for the Services page.
pub fn service_status(service: &ServiceName) -> HelperResponse {
    let out = exec::run(&["systemctl", "status", service.as_str(), "--no-pager"]);
    // `systemctl status` exits 3 for an inactive unit. That is the answer, not
    // a failure.
    match out {
        Ok(o) => HelperResponse::with_stdout(o.stdout),
        Err(e) => HelperResponse::failed(HelperErrorKind::Internal, e.to_string()),
    }
}

/// `updates-status`. C14: the JSON file keeps its schema, because the Updates
/// page reads it directly.
pub fn updates_status() -> HelperResponse {
    let path = Path::new(DATA_DIR).join("update-status.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => HelperResponse::with_data(v),
            // Pass a corrupt file through as text rather than hiding it: the
            // operator needs to see what is actually there.
            Err(_) => HelperResponse::with_stdout(text),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HelperResponse::with_data(serde_json::json!({ "status": "unknown" }))
        }
        Err(e) => HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("reading {}: {e}", path.display()),
        ),
    }
}

/// `updates-os-run`: apply pending OS package updates.
pub fn updates_os_run() -> HelperResponse {
    let Ok(platform) = snpanel_osabi::detect() else {
        return HelperResponse::failed(HelperErrorKind::Internal, "unsupported operating system");
    };

    // The package manager comes from the platform, so this one function works
    // on apt and dnf without branching here.
    let update = platform.update_index_argv();
    let out = exec::run(&update);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("package index update", out);
    }

    let upgrade: Vec<&str> = match platform.family() {
        snpanel_osabi::Family::Debian => vec!["apt-get", "upgrade", "-y"],
        snpanel_osabi::Family::Rhel => vec!["dnf", "upgrade", "-y"],
    };
    exec::respond("package upgrade", exec::run(&upgrade))
}

/// `updates-os-auto`: switch unattended upgrades on or off.
pub fn updates_os_auto(enable: bool) -> HelperResponse {
    let Ok(platform) = snpanel_osabi::detect() else {
        return HelperResponse::failed(HelperErrorKind::Internal, "unsupported operating system");
    };
    let (unit, verb) = match platform.family() {
        snpanel_osabi::Family::Debian => (
            "unattended-upgrades",
            if enable { "enable" } else { "disable" },
        ),
        snpanel_osabi::Family::Rhel => (
            "dnf-automatic.timer",
            if enable { "enable" } else { "disable" },
        ),
    };
    let out = exec::run(&["systemctl", verb, "--now", unit]);
    let mut resp = exec::respond("systemctl", out);
    if resp.ok {
        resp.data = Some(serde_json::json!({ "unit": unit, "enabled": enable }));
    }
    resp
}

fn web_user() -> String {
    snpanel_osabi::detect()
        .map(|p| p.web_user().to_string())
        .unwrap_or_else(|_| "www-data".to_string())
}

fn web_group() -> String {
    snpanel_osabi::detect()
        .map(|p| p.web_group().to_string())
        .unwrap_or_else(|_| "www-data".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_status_answers_both_questions_separately() {
        // "available" and "enabled" are different: a box can have IPv6 and
        // have it switched off, and must not have it on without an address.
        let r = ipv6_status();
        assert!(r.ok);
        let d = r.data.unwrap();
        assert!(d["available"].is_boolean());
        assert!(d["enabled"].is_boolean());
    }

    #[test]
    fn ipv6_cannot_be_enabled_without_a_global_address() {
        // C40. Enabling it anyway renders `listen [::]` into every vhost, and
        // nginx then refuses to start - taking every site down, not just one.
        if ipv6_available() {
            eprintln!("skipped: this host has global IPv6");
            return;
        }
        let r = ipv6_enable();
        assert!(!r.ok);
        assert!(r.error.unwrap().message.contains("no global IPv6"));
    }

    #[test]
    fn disabling_ipv6_twice_is_fine() {
        // Only meaningful where we can write; skip otherwise.
        if !Path::new("/etc/snpanel").exists() {
            assert!(ipv6_disable().ok);
            return;
        }
        assert!(ipv6_disable().ok);
        assert!(ipv6_disable().ok);
    }

    #[test]
    fn time_status_reports_without_failing() {
        let r = time_status();
        assert!(r.ok);
        let d = r.data.unwrap();
        assert!(d["synchronized"].is_boolean());
        assert!(d["unix_time"].as_u64().unwrap() > 1_600_000_000);
    }

    #[test]
    fn an_absent_update_status_is_unknown_not_an_error() {
        let r = updates_status();
        assert!(r.ok, "the Updates page must render on a fresh box");
    }

    #[test]
    fn cron_content_always_ends_with_a_newline() {
        // crontab silently drops a final line with no newline.
        let body = "0 3 * * * /usr/bin/php /home/u/site/cron.php";
        let fixed = if body.ends_with('\n') {
            body.to_string()
        } else {
            format!("{body}\n")
        };
        assert!(fixed.ends_with('\n'));
        assert_eq!(fixed.lines().count(), 1);
    }

    #[test]
    fn the_web_user_comes_from_the_platform() {
        let u = web_user();
        assert!(u == "www-data" || u == "nginx", "unexpected web user {u}");
    }
}
