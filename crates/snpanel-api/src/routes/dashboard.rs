//! `/api/dashboard/*` - what the dashboard shows, in one request.
//!
//! Not in the Python. The dashboard used to repeat the sidebar as three
//! blocks of tiles; it shows the state of things now - websites, SSL,
//! databases, backups, the firewall, the WAF, the malware scanner and the
//! services - so that what needs attention is on the first page an
//! administrator opens. A customer gets their own sites and databases and
//! whether their account has two-step verification.
//!
//! Each figure comes from the same source as the page that manages it, so the
//! two cannot disagree. Pending updates are a request of their own
//! (`/dashboard/updates`): asking apt takes a second or two, and the rest of
//! the page should not wait for it.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};

use crate::auth::CurrentUser;
use crate::errors::{internal_error, not_enough_permissions};
use crate::shell;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard/summary", get(summary).fallback(crate::fallback))
        .route("/dashboard/updates", get(updates).fallback(crate::fallback))
}

/// `GET /api/dashboard/summary`.
async fn summary(State(state): State<AppState>, current: CurrentUser) -> Response {
    let admin = current.user.is_admin();
    let owner = if admin { None } else { Some(current.user.id) };
    let websites = match state.db.websites().list(owner, "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("dashboard: listing websites failed: {e}");
            return internal_error();
        }
    };
    let databases = match state.db.databases().list(owner, "").await {
        Ok(rows) => rows.len(),
        Err(e) => {
            tracing::error!("dashboard: listing databases failed: {e}");
            return internal_error();
        }
    };
    let sites = website_counts(&websites);

    if !admin {
        let passkeys = state
            .db
            .passkeys()
            .for_user(current.user.id, &current.user.username)
            .await
            .map(|rows| rows.len())
            .unwrap_or(0);
        return axum::Json(json!({
            "role": "customer",
            "websites": sites,
            "databases": { "total": databases },
            "two_factor": { "totp": current.user.totp_enabled, "passkeys": passkeys },
        }))
        .into_response();
    }

    let schedules = match state.db.backup_schedules().list().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("dashboard: listing backup schedules failed: {e}");
            return internal_error();
        }
    };
    let dry = state.settings.command_dry_run;
    // The two that ask the machine run together; neither waits on the other.
    let (firewall, services) = tokio::join!(
        super::firewall::firewall_summary(&state),
        service_states(dry),
    );
    let malware_installed =
        crate::malware::maldet_installed() || crate::malware::clamav_installed();
    let malware = malware_state(
        &crate::malware_jobs::list(None),
        malware_installed,
        crate::malware::persisted_enabled(state.settings.malware_scan_enabled),
    );

    axum::Json(json!({
        "role": "admin",
        "websites": sites,
        "databases": { "total": databases },
        "backups": backup_state(&schedules),
        "firewall": {
            "state": firewall.get("state").cloned().unwrap_or(Value::Null),
            "chain_active": firewall.get("chain_active").cloned().unwrap_or(Value::Null),
        },
        "waf": { "engine": crate::system::waf_engine_available() },
        "malware": malware,
        "services": services,
    }))
    .into_response()
}

/// `GET /api/dashboard/updates` - how many OS packages wait, and whether a
/// newer SNPanel release is out. Administrators only, like the Updates page.
async fn updates(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !current.user.is_admin() {
        return not_enough_permissions();
    }
    let result = shell::privileged(
        state.settings.command_dry_run,
        "updates-status",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "apt list --upgradable 2>/dev/null | head -40",
        ]),
    )
    .await;
    let os = if result.ok() {
        count_os_updates(&result.stdout)
    } else {
        None
    };
    // The release check may reach GitHub when its cache is old: off the
    // runtime, and from the cache when it is not.
    let version = crate::updates::app_version();
    let panel =
        tokio::task::spawn_blocking(move || crate::updates::panel_release_status(&version, false))
            .await
            .unwrap_or(Value::Null);
    axum::Json(json!({
        "os": os,
        "panel": {
            "available": panel.get("update_available").cloned().unwrap_or(Value::Null),
            "latest": panel.get("latest_version").cloned().unwrap_or(Value::Null),
        },
    }))
    .into_response()
}

/// How many websites, and how many are suspended, have a certificate and
/// have the WAF on.
fn website_counts(websites: &[snpanel_db::Website]) -> Value {
    json!({
        "total": websites.len(),
        "suspended": websites.iter().filter(|w| w.status == "suspended").count(),
        "with_ssl": websites.iter().filter(|w| w.ssl_enabled).count(),
        "waf_on": websites.iter().filter(|w| w.waf_enabled).count(),
        // The ones without a certificate, for the "needs attention" line.
        "without_ssl": websites.iter().filter(|w| !w.ssl_enabled && w.status != "suspended")
            .map(|w| w.domain.clone()).collect::<Vec<_>>(),
    })
}

/// Scheduled backups: none at all, none run yet, the last runs fine, or one
/// of them failing - with the names of the failing ones.
fn backup_state(schedules: &[snpanel_db::BackupSchedule]) -> Value {
    let active: Vec<&snpanel_db::BackupSchedule> =
        schedules.iter().filter(|s| s.is_active).collect();
    let last_run_at = active
        .iter()
        .filter_map(|s| s.last_run_at.as_deref())
        .max()
        .map(str::to_string);
    let failing: Vec<Value> = active
        .iter()
        .filter(|s| s.last_status == "error")
        .map(|s| json!({ "id": s.id, "message": s.last_message }))
        .collect();
    let state = if active.is_empty() {
        "none"
    } else if !failing.is_empty() {
        "error"
    } else if last_run_at.is_none() {
        "never"
    } else {
        "ok"
    };
    json!({
        "state": state,
        "schedules": active.len(),
        "last_run_at": last_run_at,
        "failing": failing,
    })
}

/// The scanner: installed and on, and what the latest scan of each target
/// found. The latest of *each*: a clean scan of one site must not hide the
/// threats the scan before it found on another.
fn malware_state(jobs: &[Value], installed: bool, enabled: bool) -> Value {
    let mut seen: Vec<String> = Vec::new();
    let mut threats = 0u64;
    let mut last_scan_at: Option<String> = None;
    let mut infected_job: Option<String> = None;
    // Newest first, as `malware_jobs::list` returns them.
    for job in jobs {
        let status = job.get("status").and_then(Value::as_str).unwrap_or("");
        if !matches!(status, "done" | "infected") {
            continue;
        }
        if last_scan_at.is_none() {
            last_scan_at = job
                .get("finished_at")
                .or_else(|| job.get("updated_at"))
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        let target = format!(
            "{}:{}",
            job.get("scope").and_then(Value::as_str).unwrap_or(""),
            job.get("domains")
                .and_then(Value::as_array)
                .map(|d| d
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","))
                .unwrap_or_default(),
        );
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        let found = job.get("infected").and_then(Value::as_u64).unwrap_or(0);
        if found > 0 && infected_job.is_none() {
            infected_job = job
                .get("job_id")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        threats += found;
    }
    let state = if !installed {
        "not_installed"
    } else if seen.is_empty() {
        "never"
    } else if threats > 0 {
        "threats"
    } else {
        "clean"
    };
    json!({
        "state": state,
        "installed": installed,
        "enabled": enabled,
        "threats": threats,
        "last_scan_at": last_scan_at,
        "infected_job": infected_job,
    })
}

/// The Services page's list, and which of them are running.
async fn service_states(dry_run: bool) -> Value {
    let names = crate::system::list_services();
    if dry_run {
        return services_state(&names, "");
    }
    let args: Vec<String> = names.clone();
    let answers = tokio::task::spawn_blocking(move || {
        std::process::Command::new("systemctl")
            .arg("is-active")
            .arg("--")
            .args(&args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    services_state(&names, &answers)
}

/// `systemctl is-active` prints one word per unit, in the order asked: a unit
/// that is not "active" is stopped for the dashboard's purposes, and so is
/// one it printed no answer for.
fn services_state(names: &[String], answers: &str) -> Value {
    let words: Vec<&str> = answers.lines().map(str::trim).collect();
    let stopped: Vec<&String> = names
        .iter()
        .enumerate()
        .filter(|(i, _)| words.get(*i).copied() != Some("active"))
        .map(|(_, name)| name)
        .collect();
    json!({
        "total": names.len(),
        "running": names.len() - stopped.len(),
        "stopped": stopped,
    })
}

/// The number of packages the helper's update report lists as upgradable, or
/// `None` when the report has no such section - an unknown, not a zero.
///
/// The report is the helper's `updates-status`: an "APT upgradable packages:"
/// or "DNF upgradable packages:" heading, one package per line under it until
/// the next heading. apt's "Listing..." line is not a package, and neither
/// are the "Available Upgrades" and metadata lines dnf prints even with -q.
fn count_os_updates(report: &str) -> Option<u64> {
    let mut inside = false;
    let mut found = false;
    let mut count = 0u64;
    for line in report.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with("upgradable packages:") {
            inside = true;
            found = true;
            continue;
        }
        if inside && !line.starts_with(' ') && trimmed.ends_with(':') {
            inside = false;
            continue;
        }
        let noise = trimmed.starts_with("Listing")
            || trimmed
                .to_ascii_lowercase()
                .starts_with("available upgrades")
            || trimmed.starts_with("Last metadata expiration");
        if inside && !trimmed.is_empty() && !noise {
            count += 1;
        }
    }
    found.then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(
        id: i64,
        active: bool,
        last_run_at: Option<&str>,
        status: &str,
    ) -> snpanel_db::BackupSchedule {
        snpanel_db::BackupSchedule {
            id,
            user_id: None,
            user_ids: "[]".to_string(),
            all_users: true,
            target_id: None,
            schedule: "0 3 * * *".to_string(),
            retention: 7,
            is_active: active,
            last_run_at: last_run_at.map(str::to_string),
            last_status: status.to_string(),
            last_message: String::new(),
        }
    }

    #[test]
    fn backups_are_none_never_ok_or_failing() {
        assert_eq!(backup_state(&[])["state"], "none");
        // An inactive schedule is not a schedule the dashboard can count on.
        assert_eq!(
            backup_state(&[schedule(1, false, None, "")])["state"],
            "none"
        );
        assert_eq!(
            backup_state(&[schedule(1, true, None, "")])["state"],
            "never"
        );
        let ok = backup_state(&[schedule(1, true, Some("2026-09-26T03:00:00Z"), "ok")]);
        assert_eq!(ok["state"], "ok");
        assert_eq!(ok["last_run_at"], "2026-09-26T03:00:00Z");
        let mixed = backup_state(&[
            schedule(1, true, Some("2026-09-25T03:00:00Z"), "ok"),
            schedule(2, true, Some("2026-09-26T03:00:00Z"), "error"),
        ]);
        assert_eq!(mixed["state"], "error");
        assert_eq!(mixed["failing"][0]["id"], 2);
        assert_eq!(mixed["last_run_at"], "2026-09-26T03:00:00Z");
    }

    fn job(id: &str, scope: &str, domains: &[&str], status: &str, infected: u64) -> Value {
        json!({ "job_id": id, "scope": scope, "domains": domains, "status": status,
                "infected": infected, "finished_at": format!("2026-09-26T0{}:00:00Z", id.len()) })
    }

    #[test]
    fn a_clean_scan_of_one_site_does_not_hide_threats_on_another() {
        // Newest first: shop clean just now, blog infected before it.
        let jobs = vec![
            job("shop2", "website", &["shop.example.com"], "done", 0),
            job("blog1", "website", &["blog.example.com"], "infected", 1),
        ];
        let state = malware_state(&jobs, true, true);
        assert_eq!(state["state"], "threats");
        assert_eq!(state["threats"], 1);
        assert_eq!(state["infected_job"], "blog1");
    }

    #[test]
    fn only_the_latest_scan_of_a_target_counts() {
        // blog was infected, then cleaned and scanned again.
        let jobs = vec![
            job("blog2", "website", &["blog.example.com"], "done", 0),
            job("blog1", "website", &["blog.example.com"], "infected", 3),
        ];
        assert_eq!(malware_state(&jobs, true, true)["state"], "clean");
        // A running or failed scan says nothing about what is on disk.
        let running = vec![
            job("x", "server", &[], "running", 0),
            job("y", "server", &[], "error", 0),
        ];
        assert_eq!(malware_state(&running, true, true)["state"], "never");
        assert_eq!(malware_state(&[], false, false)["state"], "not_installed");
    }

    #[test]
    fn a_unit_without_an_answer_is_stopped() {
        let names: Vec<String> = ["nginx", "mariadb", "php8.4-fpm"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let state = services_state(&names, "active\nfailed\n");
        assert_eq!(state["total"], 3);
        assert_eq!(state["running"], 1);
        assert_eq!(state["stopped"], json!(["mariadb", "php8.4-fpm"]));
        assert_eq!(services_state(&names, "")["running"], 0);
    }

    #[test]
    fn upgradable_packages_are_counted_under_their_heading_only() {
        let apt = "APT upgradable packages:\nListing...\nbase-files/stable 13.1 amd64 [upgradable from: 13.0]\nlibc6/stable 2.41-12 amd64 [upgradable from: 2.41-11]\n\nUnattended upgrades:\ndisabled\n";
        assert_eq!(count_os_updates(apt), Some(2));
        let dnf = "DNF upgradable packages:\nAvailable Upgrades\nkernel.x86_64  6.12.0-55.el10  baseos\n\nAutomatic updates (dnf-automatic):\ninactive\n";
        assert_eq!(count_os_updates(dnf), Some(1));
        assert_eq!(
            count_os_updates(
                "APT upgradable packages:\nListing...\n\nUnattended upgrades:\nenabled\n"
            ),
            Some(0)
        );
        // No section at all is not knowing, not zero.
        assert_eq!(count_os_updates("helper not found"), None);
    }
}
