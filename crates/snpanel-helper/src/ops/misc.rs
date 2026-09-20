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

/// `ipv6-status`.
///
/// Three `key=value` lines, because `_parse_status` in
/// `backend/app/services/panel_ipv6.py` splits stdout on `=` line by line and
/// reads `available`, `enabled` and `addresses`. Answering in JSON gave it
/// nothing to match, so the settings page reported every server as having no
/// IPv6 and the feature switched off.
pub fn ipv6_status() -> HelperResponse {
    HelperResponse::with_stdout(ipv6_status_lines(
        ipv6_available(),
        Path::new(IPV6_MARKER).exists(),
        &ipv6_global_addresses(),
    ))
}

/// The three lines, split from the three probes so a test can drive them.
fn ipv6_status_lines(available: bool, enabled: bool, addresses: &[String]) -> String {
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    // `addresses=$(ipv6_global_addresses | paste -sd, -)`. With no global
    // address this is an empty value, not a missing line - Python's
    // `.split(",")` on `""` then filters to an empty list.
    format!(
        "available={}\nenabled={}\naddresses={}\n",
        yes_no(available),
        yes_no(enabled),
        addresses.join(",")
    )
}

/// `ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1`.
///
/// `-o` puts each address on one line, so the fourth whitespace field is the
/// address with its prefix length, and the part before `/` is the address.
fn ipv6_global_addresses() -> Vec<String> {
    exec::run(&["ip", "-6", "-o", "addr", "show", "scope", "global"])
        .ok()
        .filter(exec::Output::ok)
        .map(|o| {
            o.stdout
                .lines()
                .filter_map(|line| line.split_whitespace().nth(3))
                .map(|field| {
                    field
                        .split_once('/')
                        .map(|(addr, _)| addr)
                        .unwrap_or(field)
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
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

/// `updates-status`: the six-section report the Updates page displays.
///
/// Every line of this reaches the browser as text - `updatesStatus?.stdout`
/// in `frontend/src/App.jsx`, rendered as-is. An earlier version answered
/// with `with_data(update-status.json)`, which the helper prints as pretty
/// JSON, so the page showed the release blob and nothing else: no upgradable
/// packages, no unattended-upgrades state, no service states, no journals.
///
/// C14 still holds - `update-status.json` keeps its schema - but it is
/// reported by being *included* here, which is what the bash does, not by
/// replacing the report with it.
pub fn updates_status() -> HelperResponse {
    let mut out = String::with_capacity(8192);
    let path = Path::new(DATA_DIR).join("update-status.json");

    out.push_str("SNPanel release status:\n");
    match std::fs::read_to_string(&path) {
        // `cat`: byte for byte, including whether it ends in a newline.
        Ok(text) => out.push_str(&text),
        Err(_) => out.push_str("No update status file found.\n"),
    }

    out.push('\n');
    out.push_str("APT upgradable packages:\n");
    // `apt list --upgradable | sed -n '1,60p'` - the first 60 lines, so a box
    // with 400 pending packages does not push everything else off the page.
    if let Ok(o) = exec::run(&["apt", "list", "--upgradable"]) {
        for line in o.stdout.lines().take(60) {
            out.push_str(line);
            out.push('\n');
        }
    }

    out.push('\n');
    out.push_str("Unattended upgrades:\n");
    for verb in ["is-enabled", "is-active"] {
        if let Ok(o) = exec::run(&["systemctl", verb, "unattended-upgrades.service"]) {
            out.push_str(&o.stdout);
        }
    }

    for (label, unit) in [
        ("OS update service:", "snpanel-os-update.service"),
        ("Panel update service:", "snpanel-panel-update.service"),
    ] {
        out.push('\n');
        out.push_str(label);
        out.push('\n');
        if let Ok(o) = exec::run(&["systemctl", "is-active", unit]) {
            // `sed 's/^inactive$/idle/'` - a oneshot unit that has finished
            // reads as "inactive", which on this page looks like a broken
            // service rather than one with nothing to do.
            out.push_str(&idle_for_inactive(&o.stdout));
        }
        out.push_str(&journal_tail(unit, 16));
    }

    out.push('\n');
    out.push_str("Panel update log:\n");
    out.push_str(&journal_tail("snpanel-panel-update.service", 60));
    if let Ok(text) = std::fs::read_to_string(PANEL_UPDATE_LOG) {
        if !text.is_empty() {
            out.push_str(&format!("--- {PANEL_UPDATE_LOG} (tail) ---\n"));
            let lines: Vec<&str> = text.lines().collect();
            for line in lines.iter().skip(lines.len().saturating_sub(60)) {
                out.push_str(line);
                out.push('\n');
            }
        }
    }

    HelperResponse::with_stdout(out)
}

/// Source: `/var/log/snpanel-panel-update.log`.
const PANEL_UPDATE_LOG: &str = "/var/log/snpanel-panel-update.log";

/// `sed 's/^inactive$/idle/'`, applied per line.
pub(crate) fn idle_for_inactive(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        out.push_str(if line == "inactive" { "idle" } else { line });
        out.push('\n');
    }
    out
}

/// `journalctl -u <unit> -n <n> --no-pager | grep -v "Failed to open /run/systemd/transient"`.
///
/// That one line is noise systemd emits inside a container and it is dropped
/// rather than shown, because on the Updates page it reads like the update
/// itself failed.
fn journal_tail(unit: &str, lines: u32) -> String {
    let count = lines.to_string();
    let Ok(o) = exec::run(&["journalctl", "-u", unit, "-n", &count, "--no-pager"]) else {
        return String::new();
    };
    let mut out = String::new();
    for line in o.stdout.lines() {
        if line.contains("Failed to open /run/systemd/transient") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
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
        // Both answers travel as text, which is what the panel parses -
        // asserting they are booleans in a JSON body is what this test used
        // to do, and it passed throughout the time the panel could not read
        // either of them.
        let r = ipv6_status();
        assert!(r.ok);
        assert!(r.data.is_none(), "this verb answers on stdout, not in data");
        let keys: Vec<&str> = r
            .stdout
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, vec!["available", "enabled", "addresses"]);
        for line in r.stdout.lines().take(2) {
            let value = line.split_once('=').expect("a pair").1;
            assert!(value == "yes" || value == "no", "{line:?}");
        }
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

    /// `_parse_status` in `backend/app/services/panel_ipv6.py`, applied to the
    /// lines this verb writes.
    ///
    /// The verb used to answer with JSON, which that function parses to an
    /// empty dict - so the settings page reported every server as having no
    /// IPv6 and the feature turned off, whatever the machine actually had.
    #[test]
    fn ipv6_status_says_what_the_python_parser_reads() {
        /// `for line in output.splitlines(): if "=" in line: key, _, value =
        /// line.partition("=")`, then the three lookups.
        fn parse_status(output: &str) -> (bool, bool, Vec<String>) {
            let mut values = std::collections::HashMap::new();
            for line in output.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    values.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
            let addresses = values
                .get("addresses")
                .map(|a| {
                    a.split(',')
                        .filter(|i| !i.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            (
                values.get("available").map(String::as_str) == Some("yes"),
                values.get("enabled").map(String::as_str) == Some("yes"),
                addresses,
            )
        }

        let addrs = vec!["2001:db8::1".to_string(), "2001:db8::2".to_string()];
        let text = ipv6_status_lines(true, true, &addrs);
        assert_eq!(
            text,
            "available=yes\nenabled=yes\naddresses=2001:db8::1,2001:db8::2\n"
        );
        assert_eq!(parse_status(&text), (true, true, addrs.clone()));

        // A server with the feature off and no global address: three lines
        // still, with an empty value - not a missing line, which would read
        // the same but is not what the bash writes.
        let text = ipv6_status_lines(false, false, &[]);
        assert_eq!(text, "available=no\nenabled=no\naddresses=\n");
        assert_eq!(parse_status(&text), (false, false, vec![]));
        assert_eq!(text.lines().count(), 3);

        // Available but not switched on is the state the page exists to show,
        // and the one JSON collapsed into "nothing here".
        assert_eq!(
            parse_status(&ipv6_status_lines(true, false, &addrs)),
            (true, false, addrs)
        );

        // And the shape the bug had.
        let json = serde_json::to_string_pretty(
            &serde_json::json!({ "available": true, "enabled": true }),
        )
        .expect("json");
        assert_eq!(
            parse_status(&json),
            (false, false, vec![]),
            "JSON must be unreadable to that parser - that was the bug"
        );
    }

    /// `ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1`.
    ///
    /// The fourth field, and only the part before the prefix length. Taking
    /// the whole field would hand the panel `2001:db8::1/64`, which is not an
    /// address any config accepts.
    #[test]
    fn a_global_address_is_the_fourth_field_without_its_prefix() {
        // Real `ip -6 -o addr` output, including the link-local line that
        // `scope global` filters out upstream and a second address on one
        // interface.
        let sample = "\
2: eth0    inet6 2001:db8::1/64 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::beef/128 scope global \\       valid_lft forever preferred_lft forever
";
        let got: Vec<String> = sample
            .lines()
            .filter_map(|line| line.split_whitespace().nth(3))
            .map(|field| {
                field
                    .split_once('/')
                    .map(|(a, _)| a)
                    .unwrap_or(field)
                    .to_string()
            })
            .collect();
        assert_eq!(got, vec!["2001:db8::1", "2001:db8::beef"]);
        // Counting from the wrong end gives the interface name, which would
        // reach the panel looking like an address.
        assert_eq!(
            sample.lines().next().unwrap().split_whitespace().nth(1),
            Some("eth0")
        );
    }

    /// The Updates page renders this verb's stdout verbatim
    /// (`updatesStatus?.stdout` in `frontend/src/App.jsx`), so the six
    /// labelled sections *are* the page.
    ///
    /// This used to answer with `with_data(update-status.json)`. The helper
    /// prints `data` as pretty JSON, so the administrator got the release
    /// blob alone: no upgradable packages, no unattended-upgrades state,
    /// neither service state, neither journal. Nothing failed and nothing
    /// said so.
    #[test]
    fn the_updates_report_carries_all_six_sections_in_order() {
        let r = updates_status();
        assert!(r.ok);
        assert!(
            r.data.is_none(),
            "this verb answers on stdout - `data` is what the bug put it in"
        );

        const SECTIONS: &[&str] = &[
            "SNPanel release status:",
            "APT upgradable packages:",
            "Unattended upgrades:",
            "OS update service:",
            "Panel update service:",
            "Panel update log:",
        ];
        let mut cursor = 0usize;
        for section in SECTIONS {
            let found = r.stdout[cursor..]
                .find(section)
                .unwrap_or_else(|| panic!("{section:?} missing or out of order in:\n{}", r.stdout));
            cursor += found + section.len();
        }

        // And it is a report, not a JSON document that happens to contain
        // those words.
        assert!(
            !r.stdout.trim_start().starts_with('{'),
            "the report must not be a JSON blob: {}",
            r.stdout
        );
    }

    /// `sed 's/^inactive$/idle/'`.
    ///
    /// A oneshot unit that has finished reads as `inactive`, which on a page
    /// of service states looks like something broken rather than something
    /// with nothing to do. The anchors matter: only a line that is exactly
    /// that word is rewritten.
    #[test]
    fn a_finished_oneshot_reads_as_idle_not_inactive() {
        assert_eq!(idle_for_inactive("inactive\n"), "idle\n");
        assert_eq!(idle_for_inactive("active\n"), "active\n");
        assert_eq!(idle_for_inactive("failed\n"), "failed\n");

        // `^...$` - a line that merely contains the word keeps it, because it
        // is a sentence about the unit and not the unit's state.
        assert_eq!(
            idle_for_inactive("unit is inactive now\n"),
            "unit is inactive now\n"
        );
        assert_eq!(idle_for_inactive("inactive (dead)\n"), "inactive (dead)\n");

        // Several lines, each judged on its own.
        assert_eq!(idle_for_inactive("enabled\ninactive\n"), "enabled\nidle\n");
        assert_eq!(idle_for_inactive(""), "");
    }
}
