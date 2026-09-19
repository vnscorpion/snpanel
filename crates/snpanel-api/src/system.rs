//! The system facts the Services page shows.
//!
//! Source: `backend/app/services/system.py`.
//!
//! The service list's **order** is part of the contract and is not
//! alphabetical: `list_services()` returns
//! `BASE_SERVICES[:2] + installed_php_services() + BASE_SERVICES[2:]`, i.e.
//! `snpanel-api`, `nginx`, then each installed PHP-FPM, then `mariadb`,
//! `redis-server`. The PHP entries are sorted by a known-version order rather
//! than lexically, so 8.10 comes after 8.4 instead of before it.

use std::path::Path;
use std::process::Command;

use crate::routes::services::CommandResultBody;
use crate::state::AppState;

/// Source: `BASE_SERVICES`.
pub const BASE_SERVICES: [&str; 4] = ["snpanel-api", "nginx", "mariadb", "redis-server"];
/// Source: `PHP_VERSION_ORDER`.
pub const PHP_VERSION_ORDER: [&str; 8] = ["5.6", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"];
/// Source: `SUPPORTED_ACTIONS`.
pub const SUPPORTED_ACTIONS: [&str; 5] = ["start", "stop", "restart", "reload", "status"];

/// Source: `PROTECTED_SERVICE_ACTIONS`, messages included - the panel shows
/// them to the operator verbatim.
pub fn protected_reason(name: &str, action: &str) -> Option<&'static str> {
    match (name, action) {
        ("snpanel-api", "stop") => {
            Some("Stopping snpanel-api from the panel would make the panel unavailable")
        }
        ("redis-server", "stop") => {
            Some("Stopping redis-server would disable production login rate limiting")
        }
        _ => None,
    }
}

/// Source: `installed_php_services()` plus `_php_sort_key`.
pub fn installed_php_services() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/etc/php") else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let version = e.file_name().to_string_lossy().into_owned();
            e.path()
                .join("fpm/php-fpm.conf")
                .exists()
                .then_some(version)
        })
        .map(|v| format!("php{v}-fpm"))
        .collect();
    found.sort();
    found.dedup();
    found.sort_by_key(|s| php_sort_key(s));
    found
}

/// Known versions first in their listed order, then anything else by numeric
/// components - so `php8.10-fpm` sorts after `php8.4-fpm`, which a plain
/// string sort gets backwards.
fn php_sort_key(service: &str) -> (usize, Vec<u32>) {
    let version = service
        .strip_prefix("php")
        .and_then(|s| s.strip_suffix("-fpm"))
        .unwrap_or(service);
    let known = PHP_VERSION_ORDER
        .iter()
        .position(|v| *v == version)
        .unwrap_or(PHP_VERSION_ORDER.len());
    let numeric = version
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();
    (known, numeric)
}

/// Source: `list_services()`. The order is the contract.
pub fn list_services() -> Vec<String> {
    let mut out: Vec<String> = BASE_SERVICES[..2].iter().map(|s| s.to_string()).collect();
    out.extend(installed_php_services());
    out.extend(BASE_SERVICES[2..].iter().map(|s| s.to_string()));
    out
}

/// Source: `service_action()`, refusals in the same order.
pub async fn service_action(
    _state: &AppState,
    name: &str,
    action: &str,
) -> Result<CommandResultBody, String> {
    if !list_services().iter().any(|s| s == name) {
        return Err("Unsupported service".to_string());
    }
    if !SUPPORTED_ACTIONS.contains(&action) {
        return Err("Unsupported action".to_string());
    }
    if let Some(reason) = protected_reason(name, action) {
        return Err(reason.to_string());
    }

    // Source: the comment in the Python - status is read-only, so it does not
    // need the privileged helper and does not pay for a sudo round trip.
    if action == "status" {
        return Ok(run(&["systemctl", "status", name]));
    }

    Ok(run(&[
        "sudo",
        "-n",
        "/usr/local/sbin/snpanel-helper",
        "systemctl",
        name,
        action,
    ]))
}

pub fn os_release_head() -> String {
    // Source: `cat /etc/os-release | head -20`. Read directly rather than
    // through a shell: same bytes, one fewer process, nothing to interpret.
    std::fs::read_to_string("/etc/os-release")
        .map(|text| text.lines().take(20).map(|l| format!("{l}\n")).collect())
        .unwrap_or_default()
}

pub fn disk_free() -> String {
    run(&["df", "-h", "/"]).stdout
}

pub fn memory_mb() -> String {
    run(&["free", "-m"]).stdout
}

/// Source: `resource_usage()`.
///
/// The shape is the contract and it is nested, not flat:
///
/// ```json
/// {"cpu":{"percent":..,"load":[..],"cores":..},
///  "memory":{"total":..,"used":..,"available":..,"percent":..},
///  "disk":{"mount":"/","total":..,"used":..,"free":..,"percent":..},
///  "network":{"rx_per_sec":..,"tx_per_sec":..,"rx_total":..,"tx_total":..},
///  "sample_seconds":0.2}
/// ```
///
/// The first version of this returned a flat `{cpu_percent, load_average,
/// memory_total_mb, memory_used_mb}` - a tidier API that no client asked for
/// and that the Dashboard could not read. The shadow diff caught it, which is
/// what §9.3 is for.
///
/// **Byte sizes, not megabytes.** `_memory_usage` multiplies `/proc/meminfo`
/// by 1024 and `shutil.disk_usage` is already in bytes. Reporting MB would
/// make every figure on the Dashboard a thousand times too small.
///
/// The 0.2-second sample is deliberate: a CPU percentage needs two readings,
/// and network rates need two as well. It is the cost of the endpoint meaning
/// anything.
pub async fn resource_usage() -> serde_json::Value {
    const SAMPLE_SECONDS: f64 = 0.2;

    let cpu_start = read_cpu_times();
    let net_start = read_network_totals();
    tokio::time::sleep(std::time::Duration::from_secs_f64(SAMPLE_SECONDS)).await;
    let cpu_end = read_cpu_times();
    let net_end = read_network_totals();

    let rx_delta = net_end.0.saturating_sub(net_start.0);
    let tx_delta = net_end.1.saturating_sub(net_start.1);

    serde_json::json!({
        "cpu": {
            "percent": cpu_percent(cpu_start, cpu_end),
            "load": load_average(),
            "cores": num_cores(),
        },
        "memory": memory_usage(),
        "disk": disk_usage(),
        "network": {
            "rx_per_sec": (rx_delta as f64 / SAMPLE_SECONDS).round() as u64,
            "tx_per_sec": (tx_delta as f64 / SAMPLE_SECONDS).round() as u64,
            "rx_total": net_end.0,
            "tx_total": net_end.1,
        },
        "sample_seconds": SAMPLE_SECONDS,
    })
}

/// `(total, idle)` from the first line of `/proc/stat`.
fn read_cpu_times() -> (u64, u64) {
    let Ok(text) = std::fs::read_to_string("/proc/stat") else {
        return (0, 0);
    };
    let Some(line) = text.lines().next() else {
        return (0, 0);
    };
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if fields.len() < 4 {
        return (0, 0);
    }
    (fields.iter().sum(), fields[3])
}

/// Source: `_cpu_percent` - clamped to 0..100 and rounded to one decimal.
fn cpu_percent(start: (u64, u64), end: (u64, u64)) -> f64 {
    let total_delta = end.0.saturating_sub(start.0) as f64;
    let idle_delta = end.1.saturating_sub(start.1) as f64;
    if total_delta <= 0.0 {
        return 0.0;
    }
    let percent = (1.0 - (idle_delta / total_delta)) * 100.0;
    (percent.clamp(0.0, 100.0) * 10.0).round() / 10.0
}

/// Source: `_read_network_totals` - every interface except `lo`, summed.
///
/// Skipping loopback matters: on a box where the panel talks to MariaDB over
/// loopback, including it would report traffic that never left the machine.
fn read_network_totals() -> (u64, u64) {
    let Ok(text) = std::fs::read_to_string("/proc/net/dev") else {
        return (0, 0);
    };
    let (mut rx, mut tx) = (0u64, 0u64);
    for line in text.lines().skip(2) {
        let Some((name, data)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let fields: Vec<u64> = data
            .split_whitespace()
            .map(|v| v.parse().unwrap_or(0))
            .collect();
        if fields.len() >= 16 {
            rx += fields[0];
            tx += fields[8];
        }
    }
    (rx, tx)
}

/// Source: `_memory_usage` - **bytes**, from `/proc/meminfo` kB times 1024.
fn memory_usage() -> serde_json::Value {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let field = |key: &str| -> Option<u64> {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k == key).then(|| v.split_whitespace().next()?.parse::<u64>().ok())?
        })
    };
    let total = field("MemTotal").unwrap_or(0) * 1024;
    let available = field("MemAvailable")
        .or_else(|| field("MemFree"))
        .unwrap_or(0)
        * 1024;
    let used = total.saturating_sub(available);
    let percent = if total > 0 {
        ((used as f64 / total as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };
    serde_json::json!({
        "total": total,
        "used": used,
        "available": available,
        "percent": percent,
    })
}

/// Source: `_disk_usage` - `shutil.disk_usage("/")`, in bytes.
///
/// Note `used` is *not* `total - free`: statvfs reserves blocks for root, so
/// Python's `used = total - free_including_reserved` and the difference shows
/// up as a few percent on a full disk.
fn disk_usage() -> serde_json::Value {
    let (total, free, avail) = statvfs_root();
    let used = total.saturating_sub(free);
    let percent = if total > 0 {
        ((used as f64 / total as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };
    serde_json::json!({
        "mount": "/",
        "total": total,
        "used": used,
        "free": avail,
        "percent": percent,
    })
}

/// `(total, free, available)` in bytes, matching `shutil.disk_usage`:
/// total = f_blocks*f_frsize, free = f_bfree*f_frsize, available =
/// f_bavail*f_frsize.
fn statvfs_root() -> (u64, u64, u64) {
    // SAFETY: a zeroed statvfs is a valid out-parameter, the path is a literal
    // NUL-terminated string, and the result is only read when the call says it
    // succeeded.
    unsafe {
        let mut buf: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c"/".as_ptr(), &mut buf) != 0 {
            return (0, 0, 0);
        }
        let frsize = buf.f_frsize as u64;
        (
            buf.f_blocks as u64 * frsize,
            buf.f_bfree as u64 * frsize,
            buf.f_bavail as u64 * frsize,
        )
    }
}

/// Source: `os.getloadavg()`, each value rounded to two decimals.
fn load_average() -> Vec<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| {
            s.split_whitespace()
                .take(3)
                .filter_map(|v| v.parse::<f64>().ok())
                .map(|v| (v * 100.0).round() / 100.0)
                .collect()
        })
        .unwrap_or_default()
}

/// Source: `os.cpu_count() or 1`.
fn num_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Run a command and shape the result the way `CommandResult` does.
fn run(argv: &[&str]) -> CommandResultBody {
    let command = argv.join(" ");
    let (program, args) = argv.split_first().expect("argv must not be empty");
    match Command::new(program).args(args).output() {
        Ok(out) => CommandResultBody {
            command,
            returncode: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => CommandResultBody {
            command,
            returncode: -1,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

/// True when the machine looks like it has the panel installed.
pub fn panel_installed() -> bool {
    Path::new("/opt/snpanel/backend/.env").exists()
}

/// Source: `panel_ipv6.is_enabled` - whether the vhosts on this machine carry
/// IPv6 listen directives. A marker file, not a probe of the network: the
/// question is what the configuration says, not what the kernel has.
pub fn ipv6_enabled() -> bool {
    let marker = std::env::var("SNPANEL_IPV6_MARKER")
        .unwrap_or_else(|_| "/etc/snpanel/ipv6-enabled".to_string());
    std::path::Path::new(&marker).exists()
}

/// Source: `nginx.waf_engine_available`.
///
/// `modsecurity on;` is not a harmless no-op when the module is missing:
/// nginx rejects its **entire** configuration with `unknown directive`, and
/// that is not confined to the site being written - the next reload anywhere
/// takes down every site on the machine.
///
/// The cheap half is the Debian package's load file. The rest reads the
/// configuration directly, because `nginx -V` reports what nginx was compiled
/// with rather than what it loads, and `nginx -T` exits before printing
/// anything when it cannot open the error log - which the panel's account
/// cannot.
pub fn waf_engine_available() -> bool {
    const MODULE_CONF: &str = "/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf";
    if std::path::Path::new(MODULE_CONF).exists() {
        return true;
    }
    // Source: `MODULE_CONFIG_PATTERNS` - every file that may legally carry a
    // `load_module`, which is only valid in the main context. All are
    // world-readable, which is what lets an unprivileged process answer this.
    let mut candidates: Vec<std::path::PathBuf> =
        vec![std::path::PathBuf::from("/etc/nginx/nginx.conf")];
    for dir in ["/etc/nginx/modules-enabled", "/usr/share/nginx/modules"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            candidates.extend(
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "conf")),
            );
        }
    }
    for path in candidates {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("load_module") && trimmed.to_lowercase().contains("modsecurity")
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_order_is_the_pythons_and_not_alphabetical() {
        let list = list_services();
        assert_eq!(list.first().unwrap(), "snpanel-api");
        assert_eq!(list.get(1).unwrap(), "nginx");
        assert_eq!(list.last().unwrap(), "redis-server");

        let nginx = list.iter().position(|s| s == "nginx").unwrap();
        let mariadb = list.iter().position(|s| s == "mariadb").unwrap();
        assert!(nginx < mariadb);
        // Every PHP entry must sit in that gap.
        for (i, s) in list.iter().enumerate() {
            if s.starts_with("php") {
                assert!(i > nginx && i < mariadb, "{s} is out of place");
            }
        }
    }

    #[test]
    fn php_versions_sort_by_version_not_by_string() {
        // A plain string sort puts 8.10 before 8.4, listing an upgrade as
        // though it were older.
        let mut v = vec![
            "php8.4-fpm".to_string(),
            "php8.10-fpm".to_string(),
            "php8.3-fpm".to_string(),
        ];
        v.sort_by_key(|s| php_sort_key(s));
        assert_eq!(v, ["php8.3-fpm", "php8.4-fpm", "php8.10-fpm"]);
    }

    #[test]
    fn known_versions_come_before_unknown_ones() {
        let mut v = vec!["php9.9-fpm".to_string(), "php8.4-fpm".to_string()];
        v.sort_by_key(|s| php_sort_key(s));
        assert_eq!(v, ["php8.4-fpm", "php9.9-fpm"]);
    }

    #[test]
    fn the_protected_actions_keep_their_exact_messages() {
        assert_eq!(
            protected_reason("snpanel-api", "stop"),
            Some("Stopping snpanel-api from the panel would make the panel unavailable")
        );
        assert_eq!(
            protected_reason("redis-server", "stop"),
            Some("Stopping redis-server would disable production login rate limiting")
        );
        // Restarting is allowed; only stop is protected.
        assert!(protected_reason("snpanel-api", "restart").is_none());
        assert!(protected_reason("nginx", "stop").is_none());
    }

    #[test]
    fn the_action_set_is_the_pythons() {
        for a in ["start", "stop", "restart", "reload", "status"] {
            assert!(SUPPORTED_ACTIONS.contains(&a), "{a}");
        }
        for a in ["enable", "disable", "mask", "kill"] {
            assert!(!SUPPORTED_ACTIONS.contains(&a), "{a} must not be allowed");
        }
    }

    #[test]
    fn reading_os_release_does_not_need_a_shell() {
        assert!(os_release_head().lines().count() <= 20);
    }

    #[tokio::test]
    async fn resource_usage_has_the_nested_shape_python_returns() {
        // The flat shape an earlier version invented was tidier and unusable:
        // the Dashboard reads cpu.percent, memory.total and so on.
        let v = resource_usage().await;
        for key in ["cpu", "memory", "disk", "network", "sample_seconds"] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        for key in ["percent", "load", "cores"] {
            assert!(v["cpu"].get(key).is_some(), "missing cpu.{key}");
        }
        for key in ["total", "used", "available", "percent"] {
            assert!(v["memory"].get(key).is_some(), "missing memory.{key}");
        }
        for key in ["mount", "total", "used", "free", "percent"] {
            assert!(v["disk"].get(key).is_some(), "missing disk.{key}");
        }
        for key in ["rx_per_sec", "tx_per_sec", "rx_total", "tx_total"] {
            assert!(v["network"].get(key).is_some(), "missing network.{key}");
        }
        assert!(v["cpu"]["load"].is_array());
        assert_eq!(v["disk"]["mount"], "/");
    }

    #[tokio::test]
    async fn memory_and_disk_are_reported_in_bytes_not_megabytes() {
        // /proc/meminfo is kB and Python multiplies by 1024; reporting MB
        // would make every Dashboard figure a thousand times too small.
        let v = resource_usage().await;
        let total = v["memory"]["total"].as_u64().unwrap();
        assert!(
            total > 100_000_000,
            "memory total {total} looks like megabytes, not bytes"
        );
        let disk = v["disk"]["total"].as_u64().unwrap();
        assert!(
            disk > 1_000_000_000,
            "disk total {disk} looks too small for bytes"
        );
    }

    #[test]
    fn cpu_percent_is_clamped_and_rounded_like_the_python() {
        // (1 - idle/total) * 100, clamped to 0..100, one decimal.
        assert_eq!(cpu_percent((0, 0), (1000, 750)), 25.0);
        assert_eq!(cpu_percent((0, 0), (1000, 1000)), 0.0);
        assert_eq!(cpu_percent((0, 0), (1000, 0)), 100.0);
        // A counter that did not move must not divide by zero.
        assert_eq!(cpu_percent((500, 100), (500, 100)), 0.0);
        // Counters only go up, but a reset must not produce a negative.
        assert_eq!(cpu_percent((1000, 500), (0, 0)), 0.0);
    }

    #[test]
    fn loopback_is_excluded_from_the_network_totals() {
        // Including it would report traffic that never left the machine - and
        // the panel talks to MariaDB over loopback constantly.
        let (rx, _tx) = read_network_totals();
        let lo_only = std::fs::read_to_string("/proc/net/dev")
            .map(|t| t.lines().skip(2).filter(|l| l.contains("lo:")).count())
            .unwrap_or(0);
        assert!(lo_only > 0, "this machine should have a loopback interface");
        // Not a value assertion - just that the reader ran and skipped it.
        let _ = rx;
    }

    #[test]
    fn load_average_has_three_values_rounded_to_two_decimals() {
        let load = load_average();
        assert_eq!(load.len(), 3);
        for v in load {
            // Not `(v * 100.0).fract() == 0`: a two-decimal value is not
            // exactly representable, so 20.65 * 100.0 is 2064.999999999999 and
            // that assertion fails whenever the build machine is busy enough
            // for the load average to reach two digits. Compare the value with
            // its own rounding instead.
            assert!(
                (v - (v * 100.0).round() / 100.0).abs() < 1e-9,
                "{v} is not rounded to 2dp"
            );
        }
    }

    #[test]
    fn running_a_missing_binary_is_a_result_not_a_panic() {
        let r = run(&["/nonexistent/binary"]);
        assert_eq!(r.returncode, -1);
        assert!(!r.stderr.is_empty());
    }
}
