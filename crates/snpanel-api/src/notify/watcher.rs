//! What nobody asks about until it is too late: services that stopped, a
//! disk filling up, certificates renewal did not renew, accounts out of
//! room, a new release. Looked at from inside the panel, since nothing else
//! looks.
//!
//! Not in the Python. Every five minutes, while the Notifications addon is
//! installed: the services and the disk. Once a day: certificates, storage
//! and the release. What was already told is remembered in
//! `notifications-state.json`, so a restart does not tell it again and a
//! problem is told once - when it starts, and for a service when it ends.
//! A service is only "stopped" when two looks five minutes apart both find
//! it so: a restart in progress is not an outage. Nothing is looked at, and
//! nothing remembered, while no way of sending is set up.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Event, Expiring};
use crate::state::AppState;

/// Between two looks at the services and the disk.
pub const INTERVAL: Duration = Duration::from_secs(300);
/// Before the first, so a panel starting with the rest of the machine does
/// not find everything stopped.
const FIRST_LOOK: Duration = Duration::from_secs(120);
/// Between the daily looks.
const DAY: i64 = 24 * 60 * 60;
/// A disk this full is told of, once, until it drops below [`DISK_CLEAR`].
const DISK_ALERT: f64 = 90.0;
const DISK_CLEAR: f64 = 85.0;
/// An account this full, likewise.
const STORAGE_ALERT: f64 = 90.0;
const STORAGE_CLEAR: f64 = 85.0;
/// A certificate with this few days left is told of.
const SSL_WARN_DAYS: i64 = 7;

/// What was already told.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Memo {
    /// Seen stopped once, not yet told.
    #[serde(default)]
    pub suspect: Vec<String>,
    /// Told as stopped.
    #[serde(default)]
    pub down: Vec<String>,
    #[serde(default)]
    pub disk_told: bool,
    /// Seconds since the epoch of the last daily look.
    #[serde(default)]
    pub last_daily: i64,
    /// The release last told of.
    #[serde(default)]
    pub release_told: String,
    /// Per domain: the certificate's end, and the stage told for it - `7`,
    /// `1` or `0` days.
    #[serde(default)]
    pub ssl_told: BTreeMap<String, String>,
    /// Accounts told of as nearly full.
    #[serde(default)]
    pub storage_told: Vec<i64>,
}

fn memo_file() -> PathBuf {
    PathBuf::from(std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()))
        .join("notifications-state.json")
}

impl Memo {
    pub fn load() -> Self {
        std::fs::read_to_string(memo_file())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let path = memo_file();
        let tmp = path.with_extension("json.tmp");
        let written = serde_json::to_vec_pretty(self)
            .map_err(std::io::Error::other)
            .and_then(|body| std::fs::write(&tmp, body))
            .and_then(|_| std::fs::rename(&tmp, &path));
        if let Err(e) = written {
            tracing::warn!("notifications: cannot remember what was told: {e}");
        }
    }
}

/// The services' side: which to tell as stopped, which as running again,
/// from what is stopped now. The memo moves on.
pub fn services(memo: &mut Memo, stopped_now: &[String]) -> (Vec<String>, Vec<String>) {
    let mut stopped = Vec::new();
    for name in stopped_now {
        if memo.down.contains(name) {
            continue;
        }
        if memo.suspect.contains(name) {
            stopped.push(name.clone());
        }
    }
    let running_again: Vec<String> = memo
        .down
        .iter()
        .filter(|name| !stopped_now.contains(name))
        .cloned()
        .collect();
    memo.down.retain(|name| stopped_now.contains(name));
    memo.down.extend(stopped.iter().cloned());
    memo.suspect = stopped_now
        .iter()
        .filter(|name| !memo.down.contains(name))
        .cloned()
        .collect();
    (stopped, running_again)
}

/// Whether to tell of the disk at `percent`; the memo moves on.
pub fn disk(memo: &mut Memo, percent: f64) -> bool {
    if percent >= DISK_ALERT && !memo.disk_told {
        memo.disk_told = true;
        return true;
    }
    if percent < DISK_CLEAR {
        memo.disk_told = false;
    }
    false
}

/// The stage a certificate with `days` left is at, if any.
pub fn ssl_stage(days: i64) -> Option<&'static str> {
    match days {
        d if d <= 0 => Some("0"),
        d if d <= 1 => Some("1"),
        d if d <= SSL_WARN_DAYS => Some("7"),
        _ => None,
    }
}

/// `openssl x509 -enddate`'s date - `Dec  8 09:12:44 2026 GMT` - as whole
/// days from `now`, rounded down.
pub fn days_left(not_after: &str, now: chrono::DateTime<chrono::Utc>) -> Option<i64> {
    let text = not_after.trim().trim_end_matches("GMT").trim();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let end = chrono::NaiveDateTime::parse_from_str(&text, "%b %d %H:%M:%S %Y").ok()?;
    let seconds = end.and_utc().signed_duration_since(now).num_seconds();
    Some(seconds.div_euclid(DAY))
}

/// Every account at or past [`STORAGE_ALERT`] that was not told, and the
/// memo moved on for every account below [`STORAGE_CLEAR`].
pub fn storage(memo: &mut Memo, figures: &[(i64, f64)]) -> Vec<i64> {
    let mut tell = Vec::new();
    for (user, percent) in figures {
        if *percent >= STORAGE_ALERT && !memo.storage_told.contains(user) {
            memo.storage_told.push(*user);
            tell.push(*user);
        } else if *percent < STORAGE_CLEAR {
            memo.storage_told.retain(|u| u != user);
        }
    }
    tell
}

/// The loop, for the server's lifetime.
pub fn start(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_LOOK).await;
        loop {
            look(&state, false).await;
            tokio::time::sleep(INTERVAL).await;
        }
    });
}

/// One look: the services and the disk, and the daily ones when a day has
/// passed - or now, when `daily` says so (`--run-notification-checks`).
pub async fn look(state: &AppState, daily: bool) {
    if !super::installed() {
        return;
    }
    // Nothing is looked at while nobody can be told: a problem remembered as
    // told then would never be told once e-mail or Telegram is set up, and
    // the daily looks run at the first look after that.
    if !super::load_channels().ready() {
        return;
    }
    let mut memo = Memo::load();

    let stopped_now =
        crate::routes::dashboard::stopped_services(state.settings.command_dry_run).await;
    let (stopped, running_again) = services(&mut memo, &stopped_now);
    if !stopped.is_empty() || !running_again.is_empty() {
        super::deliver(
            state,
            Event::Services {
                stopped,
                running_again,
            },
        )
        .await;
    }

    let (total, free, percent) = crate::system::root_disk();
    if total > 0 && disk(&mut memo, percent) {
        super::deliver(
            state,
            Event::DiskLow {
                mount: "/".into(),
                percent,
                free,
            },
        )
        .await;
    }

    let now = chrono::Utc::now();
    if daily || now.timestamp() - memo.last_daily >= DAY {
        memo.last_daily = now.timestamp();
        certificates(state, &mut memo, now).await;
        accounts(state, &mut memo).await;
        release(state, &mut memo).await;
    }
    memo.save();
}

async fn certificates(state: &AppState, memo: &mut Memo, now: chrono::DateTime<chrono::Utc>) {
    let websites = match state.db.websites().all_by_domain().await {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("notifications: cannot list the websites: {e}");
            return;
        }
    };
    let mut expiring = Vec::new();
    let mut seen = Vec::new();
    for site in websites.iter().filter(|w| w.ssl_enabled) {
        let (not_after, _) = crate::routes::websites::cert_info(state, &site.domain).await;
        let Some(days) = days_left(&not_after, now) else {
            continue;
        };
        seen.push(site.domain.clone());
        let Some(stage) = ssl_stage(days) else {
            memo.ssl_told.remove(&site.domain);
            continue;
        };
        let told = format!("{not_after}|{stage}");
        if memo.ssl_told.get(&site.domain) == Some(&told) {
            continue;
        }
        memo.ssl_told.insert(site.domain.clone(), told);
        expiring.push(Expiring {
            domain: site.domain.clone(),
            days,
        });
    }
    memo.ssl_told.retain(|domain, _| seen.contains(domain));
    if !expiring.is_empty() {
        super::deliver(
            state,
            Event::SslExpiring {
                certificates: expiring,
            },
        )
        .await;
    }
}

async fn accounts(state: &AppState, memo: &mut Memo) {
    let users = match state.db.users().active_ordered_by_id().await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("notifications: cannot list the accounts: {e}");
            return;
        }
    };
    let application = crate::routes::addons::application_installed();
    let mut figures = Vec::new();
    let mut sizes = BTreeMap::new();
    for user in users
        .iter()
        .filter(|u| !u.is_admin() && u.storage_limit_mb > 0)
    {
        let used = crate::storage_quota::user_storage_used_bytes_cached(
            state.settings.command_dry_run,
            &state.db,
            user.id,
            application,
        )
        .await;
        let limit = (user.storage_limit_mb as u64) * 1024 * 1024;
        let percent = used as f64 * 100.0 / limit as f64;
        figures.push((user.id, percent));
        sizes.insert(user.id, (used, limit, percent));
    }
    for owner in storage(memo, &figures) {
        let Some(user) = users.iter().find(|u| u.id == owner) else {
            continue;
        };
        let (used, limit, percent) = sizes[&owner];
        super::deliver(
            state,
            Event::StorageFull {
                username: user.username.clone(),
                percent,
                used,
                limit,
            },
        )
        .await;
    }
}

async fn release(state: &AppState, memo: &mut Memo) {
    let current = crate::updates::app_version();
    let status = tokio::task::spawn_blocking({
        let current = current.clone();
        move || crate::updates::panel_release_status(&current, false)
    })
    .await
    .unwrap_or_default();
    if status.get("update_available").and_then(|v| v.as_bool()) != Some(true) {
        return;
    }
    let latest = status
        .get("latest_version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if latest.is_empty() || memo.release_told == latest {
        return;
    }
    memo.release_told = latest.clone();
    super::deliver(state, Event::PanelUpdate { current, latest }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_service_is_stopped_after_two_looks_and_told_once() {
        let mut memo = Memo::default();
        assert_eq!(
            services(&mut memo, &names(&["nginx"])),
            (vec![], vec![]),
            "once is a restart"
        );
        assert_eq!(
            services(&mut memo, &names(&["nginx"])),
            (names(&["nginx"]), vec![])
        );
        assert_eq!(
            services(&mut memo, &names(&["nginx"])),
            (vec![], vec![]),
            "told once"
        );
        assert_eq!(
            services(&mut memo, &names(&[])),
            (vec![], names(&["nginx"]))
        );
        assert_eq!(memo, Memo::default());
        // Stopped once and back: never told.
        services(&mut memo, &names(&["mariadb"]));
        assert_eq!(services(&mut memo, &names(&[])), (vec![], vec![]));
    }

    #[test]
    fn the_disk_is_told_once_until_it_has_room_again() {
        let mut memo = Memo::default();
        assert!(!disk(&mut memo, 80.0));
        assert!(disk(&mut memo, 91.0));
        assert!(!disk(&mut memo, 95.0));
        assert!(!disk(&mut memo, 87.0), "not clear yet");
        assert!(!disk(&mut memo, 92.0));
        assert!(!disk(&mut memo, 84.0));
        assert!(disk(&mut memo, 90.0));
    }

    #[test]
    fn a_certificates_end_is_read_as_days_left() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(days_left("Oct  1 12:00:00 2026 GMT", now), Some(5));
        assert_eq!(days_left("Oct 10 11:00:00 2026 GMT", now), Some(13));
        assert_eq!(days_left("Sep 26 11:00:00 2026 GMT", now), Some(-1));
        assert_eq!(days_left("", now), None);
        assert_eq!(ssl_stage(5), Some("7"));
        assert_eq!(ssl_stage(1), Some("1"));
        assert_eq!(ssl_stage(-1), Some("0"));
        assert_eq!(ssl_stage(8), None);
    }

    #[test]
    fn an_account_is_told_once_until_it_has_room_again() {
        let mut memo = Memo::default();
        assert_eq!(storage(&mut memo, &[(2, 50.0), (3, 95.0)]), vec![3]);
        assert_eq!(storage(&mut memo, &[(2, 91.0), (3, 96.0)]), vec![2]);
        assert!(storage(&mut memo, &[(2, 88.0), (3, 80.0)]).is_empty());
        assert_eq!(storage(&mut memo, &[(2, 92.0), (3, 90.0)]), vec![3]);
    }
}
