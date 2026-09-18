//! Panel and OS updates - `services/updates.py`.
//!
//! The Updates page asks one endpoint for everything: what the OS has pending,
//! what the newest panel release is, and the tail of the last panel update's
//! log. Three sources, and the rule that ties them together is that **the
//! Updates page must never be the thing that breaks**. Every failure here
//! degrades: an unreachable git remote becomes a `check_error` string beside
//! the versions it could not refresh, an unreadable log becomes an empty list,
//! and a state file that will not write is skipped rather than raised.
//!
//! The release check is cached for five minutes in a state file both
//! implementations share, which is also what keeps them agreeing: whichever
//! one refreshes writes the answer, and the other reads it.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Source: `STATUS_CACHE_SECONDS`.
const STATUS_CACHE_SECONDS: f64 = 300.0;
const DEFAULT_REPO_URL: &str = "https://github.com/vnscorpion/snpanel.git";
const DEFAULT_STATE_FILE: &str = "/var/lib/snpanel/update-status.json";
/// Source: `_read_panel_update_log(max_lines=100)`.
const LOG_LINES: usize = 100;

fn repo_url() -> String {
    std::env::var("SNPANEL_REPO_URL").unwrap_or_else(|_| DEFAULT_REPO_URL.to_string())
}

fn state_file() -> PathBuf {
    PathBuf::from(
        std::env::var("SNPANEL_UPDATE_STATE_FILE")
            .unwrap_or_else(|_| DEFAULT_STATE_FILE.to_string()),
    )
}

/// Source: `_utc_now` - `%Y-%m-%dT%H:%M:%SZ`, seconds only and an explicit Z.
fn utc_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn epoch_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Source: `_semver_tuple` - `None` for anything that is not three integers.
///
/// A tag like `v1.2` or `v1.2.3-rc1` deliberately does not parse: comparing it
/// would mean guessing, and a wrong guess here tells an administrator an
/// update is available when it is not, or hides one that is.
pub fn semver_tuple(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let nums: Vec<u64> = parts
        .iter()
        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .filter_map(|p| p.parse().ok())
        .collect();
    if nums.len() != 3 {
        return None;
    }
    Some((nums[0], nums[1], nums[2]))
}

/// Source: `SEMVER_TAG_RE` - `v` then three parts, none with a leading zero.
fn parse_release_tag(reference: &str) -> Option<(u64, u64, u64)> {
    let rest = reference.strip_prefix('v')?;
    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut out = Vec::with_capacity(3);
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        // `(0|[1-9][0-9]*)`: "01" is not a release tag.
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        out.push(part.parse().ok()?);
    }
    Some((out[0], out[1], out[2]))
}

fn read_state() -> Value {
    std::fs::read_to_string(state_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

/// Source: `_write_update_state` - written to a temporary file and renamed, so
/// a reader never sees half a document, and every failure is swallowed
/// because update status must not break the page that shows it.
fn write_state(state: &Value) {
    let path = state_file();
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let tmp = path.with_extension("tmp");
    let body = match serde_json::to_string_pretty(state) {
        Ok(b) => format!("{b}\n"),
        Err(_) => return,
    };
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Source: `_latest_release_from_git`.
fn latest_release_from_git() -> Result<(String, String), String> {
    let out = std::process::Command::new("git")
        .args(["ls-remote", "--tags", "--refs", &repo_url(), "refs/tags/v*"])
        .output()
        .map_err(|e| format!("Could not read release tags: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let message = [stderr.trim(), stdout.trim(), "Could not read release tags"]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("Could not read release tags");
        return Err(message.to_string());
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut best: Option<((u64, u64, u64), String)> = None;
    for line in text.lines() {
        let reference = line.rsplit('/').next().unwrap_or("").trim();
        if let Some(version) = parse_release_tag(reference) {
            if best.as_ref().is_none_or(|(b, _)| version > *b) {
                best = Some((version, reference.to_string()));
            }
        }
    }
    match best {
        Some((_, tag)) => {
            let version = tag.trim_start_matches('v').to_string();
            Ok((tag, version))
        }
        None => Err("No release tags found".to_string()),
    }
}

/// Source: `panel_release_status`.
pub fn panel_release_status(current_version: &str, force_refresh: bool) -> Value {
    let mut state = read_state();
    let now = utc_now();
    let current_tuple = semver_tuple(current_version);

    let mut latest_version = state
        .get("latest_version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut latest_tag = state
        .get("latest_tag")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if latest_tag.is_empty() && !latest_version.is_empty() {
        latest_tag = format!("v{latest_version}");
    }
    let mut check_error = String::new();

    let checked_at = state
        .get("last_checked_epoch")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let should_refresh = force_refresh
        || latest_version.is_empty()
        || (epoch_now() - checked_at > STATUS_CACHE_SECONDS);

    if should_refresh {
        let map = state.as_object_mut().expect("read_state returns an object");
        match latest_release_from_git() {
            Ok((tag, version)) => {
                latest_tag = tag.clone();
                latest_version = version.clone();
                map.insert("current_version".into(), json!(current_version));
                map.insert("latest_tag".into(), json!(tag));
                map.insert("latest_version".into(), json!(version));
                map.insert("last_checked_at".into(), json!(now));
                map.insert("last_checked_epoch".into(), json!(epoch_now()));
                map.insert("check_error".into(), json!(""));
            }
            Err(message) => {
                check_error = message.clone();
                map.insert("current_version".into(), json!(current_version));
                map.insert("last_checked_at".into(), json!(now));
                map.insert("last_checked_epoch".into(), json!(epoch_now()));
                map.insert("check_error".into(), json!(message));
            }
        }
        write_state(&state);
    } else if let Some(map) = state.as_object_mut() {
        map.insert("current_version".into(), json!(current_version));
    }

    let latest_tuple = semver_tuple(&latest_version);
    // `None` when either version is unparsable - the page shows "unknown"
    // rather than claiming the panel is current.
    let update_available = match (current_tuple, latest_tuple) {
        (Some(current), Some(latest)) => json!(latest > current),
        _ => {
            if check_error.is_empty() {
                check_error = state
                    .get("check_error")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
            }
            Value::Null
        }
    };

    let s = |key: &str| -> String {
        state
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    json!({
        "current_version": current_version,
        "latest_version": latest_version,
        "latest_tag": latest_tag,
        "update_available": update_available,
        "last_checked_at": s("last_checked_at"),
        "last_update_started_at": s("last_update_started_at"),
        "last_update_finished_at": s("last_update_finished_at"),
        "last_update_status": s("last_update_status"),
        "last_update_ref": s("last_update_ref"),
        "check_error": if check_error.is_empty() { s("check_error") } else { check_error },
        "progress_percent": state.get("progress_percent").cloned().unwrap_or(json!(0)),
        "progress_phase": s("progress_phase"),
        "progress_message": s("progress_message"),
        "state_file": state_file().to_string_lossy(),
    })
}

/// Source: `_read_panel_update_log` - the journal first, the flat file when
/// there is no journal to read (a container without systemd).
pub fn panel_update_log() -> Vec<String> {
    let have_unit = std::process::Command::new("systemctl")
        .args(["cat", "snpanel-panel-update.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if have_unit {
        if let Ok(out) = std::process::Command::new("journalctl")
            .args([
                "-u",
                "snpanel-panel-update.service",
                "-n",
                &LOG_LINES.to_string(),
                "--no-pager",
                "--output=cat",
            ])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if out.status.success() && !text.trim().is_empty() {
                return tail(text.lines().map(str::to_string).collect(), LOG_LINES);
            }
        }
    }

    match std::fs::read_to_string("/var/log/snpanel-panel-update.log") {
        Ok(text) => tail(text.lines().map(str::to_string).collect(), LOG_LINES),
        Err(_) => Vec::new(),
    }
}

fn tail(mut lines: Vec<String>, max: usize) -> Vec<String> {
    if lines.len() > max {
        lines.drain(..lines.len() - max);
    }
    lines
}

/// Source: `run_panel_update` - the state file is marked *before* the helper
/// runs, so a page refreshed while the update is starting shows "checking"
/// rather than the previous run's result.
pub fn mark_panel_update_starting() {
    let mut state = read_state();
    if let Some(map) = state.as_object_mut() {
        map.insert("last_update_status".into(), json!("checking"));
        map.insert("last_update_started_at".into(), json!(utc_now()));
        map.insert("last_update_message".into(), json!("Starting panel update"));
        map.insert("progress_percent".into(), json!(0));
        map.insert("progress_phase".into(), json!("starting"));
        map.insert("progress_message".into(), json!("Starting panel update"));
    }
    write_state(&state);
}

pub fn mark_panel_update_failed(message: &str) {
    let mut state = read_state();
    if let Some(map) = state.as_object_mut() {
        map.insert("last_update_status".into(), json!("failed"));
        map.insert("last_update_finished_at".into(), json!(utc_now()));
        map.insert("last_update_message".into(), json!(message));
        map.insert("progress_phase".into(), json!("failed"));
        map.insert(
            "progress_message".into(),
            json!("Panel update could not be started"),
        );
    }
    write_state(&state);
}

/// Source: `configure_os_auto_update` - the only two modes there are.
pub fn valid_auto_update_mode(mode: &str) -> bool {
    matches!(mode, "security" | "all")
}

/// The panel's installed version. Source: `core.version.APP_VERSION`.
pub fn app_version() -> String {
    std::fs::read_to_string(Path::new("/opt/snpanel/VERSION"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_is_three_integers_or_nothing() {
        assert_eq!(semver_tuple("1.2.3"), Some((1, 2, 3)));
        assert_eq!(semver_tuple("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(semver_tuple(" 10.0.134 "), Some((10, 0, 134)));
        // Guessing at these would tell an administrator an update exists when
        // it does not, or hide one that does.
        for bad in ["1.2", "1.2.3.4", "1.2.x", "", "v", "latest"] {
            assert_eq!(semver_tuple(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_release_tag_may_not_have_a_leading_zero() {
        assert_eq!(parse_release_tag("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_release_tag("v0.1.0"), Some((0, 1, 0)));
        // The regex is `(0|[1-9][0-9]*)`, so these are not releases.
        assert_eq!(parse_release_tag("v01.2.3"), None);
        assert_eq!(parse_release_tag("v1.02.3"), None);
        assert_eq!(parse_release_tag("1.2.3"), None, "the v is required");
        assert_eq!(parse_release_tag("v1.2.3-rc1"), None);
    }

    #[test]
    fn versions_order_numerically_not_as_strings() {
        // The bug this prevents: "1.0.9" > "1.0.10" as text.
        assert!(semver_tuple("1.0.10") > semver_tuple("1.0.9"));
        assert!(semver_tuple("2.0.0") > semver_tuple("1.99.99"));
        assert!(semver_tuple("1.0.134") > semver_tuple("1.0.99"));
    }

    #[test]
    fn a_log_is_trimmed_to_its_last_lines() {
        let many: Vec<String> = (0..250).map(|i| i.to_string()).collect();
        let trimmed = tail(many, 100);
        assert_eq!(trimmed.len(), 100);
        assert_eq!(trimmed[0], "150", "the *last* hundred, not the first");
        assert_eq!(trimmed[99], "249");
    }

    #[test]
    fn a_short_log_is_left_alone() {
        let few: Vec<String> = vec!["a".into(), "b".into()];
        assert_eq!(tail(few.clone(), 100), few);
        assert_eq!(tail(Vec::new(), 100), Vec::<String>::new());
    }

    #[test]
    fn only_two_auto_update_modes_exist() {
        assert!(valid_auto_update_mode("security"));
        assert!(valid_auto_update_mode("all"));
        for bad in ["", "none", "everything", "SECURITY"] {
            assert!(!valid_auto_update_mode(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_status_reports_every_field_the_page_renders() {
        // Read against a state file that does not exist, so this exercises the
        // "nothing cached and git unreachable" path too.
        std::env::set_var(
            "SNPANEL_UPDATE_STATE_FILE",
            "/nonexistent/dir/update-status.json",
        );
        std::env::set_var("SNPANEL_REPO_URL", "/nonexistent/repo.git");
        let v = panel_release_status("1.0.134", false);
        std::env::remove_var("SNPANEL_UPDATE_STATE_FILE");
        std::env::remove_var("SNPANEL_REPO_URL");

        for key in [
            "current_version",
            "latest_version",
            "latest_tag",
            "update_available",
            "last_checked_at",
            "last_update_started_at",
            "last_update_finished_at",
            "last_update_status",
            "last_update_ref",
            "check_error",
            "progress_percent",
            "progress_phase",
            "progress_message",
            "state_file",
        ] {
            assert!(v.get(key).is_some(), "{key} is missing");
        }
        assert_eq!(v["current_version"], json!("1.0.134"));
        // Unknown, not "you are up to date".
        assert_eq!(v["update_available"], Value::Null);
        assert!(
            !v["check_error"].as_str().unwrap_or("").is_empty(),
            "an unreachable remote has to say so"
        );
    }
}
