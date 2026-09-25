//! The Fail2ban addon's settings, and the helper calls behind its page.
//!
//! Not in the Python. The settings live in `fail2ban.json` beside
//! `addons.json`; fail2ban's own files are rendered from them by the helper,
//! which is handed the values and never text.

use std::path::PathBuf;

use serde_json::{json, Value};
use snpanel_ipc::{Fail2banConfig, Fail2banJail};

use crate::state::AppState;

fn settings_file() -> PathBuf {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".to_string());
    PathBuf::from(dir).join("fail2ban.json")
}

/// The saved settings, when there are any and they are still valid.
pub fn stored() -> Option<Fail2banConfig> {
    let text = std::fs::read_to_string(settings_file()).ok()?;
    let config: Fail2banConfig = serde_json::from_str(&text).ok()?;
    config.validate().ok()?;
    Some(config)
}

/// A temporary file in the same directory, then a rename, like `addons.json`.
pub fn save(config: &Fail2banConfig) -> std::io::Result<()> {
    let path = settings_file();
    let dir = path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir)?;
    let mut text = serde_json::to_string_pretty(config)?;
    text.push('\n');
    let temp = dir.join(format!(".fail2ban.json.{}", std::process::id()));
    std::fs::write(&temp, text)?;
    std::fs::rename(&temp, &path)
}

/// A helper call's stdout, or why it failed.
///
/// Each caller names its verb as a literal, so the test that checks every
/// verb the panel asks for against the helper's mapping can read them.
fn outcome(result: crate::shell::CommandResult, what: &str) -> Result<String, String> {
    if result.ok() {
        Ok(result.stdout)
    } else {
        Err(result.failure_detail(what).trim().to_string())
    }
}

fn payload(config: &Fail2banConfig) -> String {
    serde_json::to_string(config).expect("the settings serialize")
}

/// The package, the files and the service - minutes, the first time.
pub async fn install(state: &AppState, config: &Fail2banConfig) -> Result<(), String> {
    let settings = payload(config);
    let dry = state.settings.command_dry_run;
    let result =
        crate::shell::privileged(dry, "fail2ban-install", &[], Some(&settings), None).await;
    outcome(result, "fail2ban could not be installed").map(drop)
}

/// The files rewritten from `config` and read by fail2ban.
pub async fn configure(state: &AppState, config: &Fail2banConfig) -> Result<(), String> {
    let settings = payload(config);
    let dry = state.settings.command_dry_run;
    let result =
        crate::shell::privileged(dry, "fail2ban-configure", &[], Some(&settings), None).await;
    outcome(result, "fail2ban refused the settings").map(drop)
}

/// Stopped and disabled at boot; every ban is lifted with it.
pub async fn stop(state: &AppState) -> Result<(), String> {
    let dry = state.settings.command_dry_run;
    let result = crate::shell::privileged(dry, "fail2ban-stop", &[], None, None).await;
    outcome(result, "fail2ban could not be stopped").map(drop)
}

pub async fn ban(
    state: &AppState,
    jail: Fail2banJail,
    address: std::net::IpAddr,
) -> Result<(), String> {
    let dry = state.settings.command_dry_run;
    let address = address.to_string();
    let result =
        crate::shell::privileged(dry, "fail2ban-ban", &[jail.name(), &address], None, None).await;
    outcome(result, "the address could not be banned").map(drop)
}

pub async fn unban(state: &AppState, address: std::net::IpAddr) -> Result<(), String> {
    let dry = state.settings.command_dry_run;
    let address = address.to_string();
    let result = crate::shell::privileged(dry, "fail2ban-unban", &[&address], None, None).await;
    outcome(result, "the address could not be let back in").map(drop)
}

/// What the helper reports, or "not installed" when it cannot say.
pub async fn service_status(state: &AppState) -> Value {
    let dry = state.settings.command_dry_run;
    let result = crate::shell::privileged(dry, "fail2ban-status", &[], None, None).await;
    outcome(result, "")
        .ok()
        .and_then(|stdout| serde_json::from_str::<Value>(stdout.trim()).ok())
        .filter(Value::is_object)
        .unwrap_or_else(
            || json!({ "installed": false, "running": false, "version": null, "jails": [] }),
        )
}

/// After a site is added or removed.
///
/// The WordPress jail reads every site's access log, and fail2ban finds log
/// files only when it reads its settings - a new site would otherwise go
/// unwatched until the next reboot. In the background: a reload takes a few
/// seconds, and the site is created whether or not it works.
pub fn refresh_in_background(state: &AppState) {
    if !crate::routes::addons::fail2ban_installed() {
        return;
    }
    let Some(config) = stored() else {
        return;
    };
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(message) = configure(&state, &config).await {
            tracing::warn!("fail2ban did not re-read its settings: {message}");
        }
    });
}
