//! Resellers - not in the Python.
//!
//! A reseller is an end user with hosting of its own who also manages the
//! accounts it made: it creates them (their usernames start with its
//! prefix), puts them on packages of its own, suspends, deletes and signs in
//! as them. It never reaches the server: every admin-only page stays
//! admin-only, and on the hosting pages a reseller is the customer of its
//! own account.
//!
//! Its limits are on what is really used across its own account and every
//! account it made - accounts, websites, databases, mailboxes and disk. Its
//! packages may promise more than that in total (overselling); what is
//! refused is the account, website, database or mailbox that would take the
//! real total past a limit. Zero is no limit.

use axum::response::Response;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_db::{ResellerLimits, User};

use crate::auth::CurrentUser;
use crate::errors::{internal_error, not_enough_permissions};
use crate::state::AppState;

/// Who may manage accounts, and which.
#[derive(Debug, Clone)]
pub enum Manager {
    Admin,
    Reseller { id: i64, limits: ResellerLimits },
}

impl Manager {
    pub fn is_admin(&self) -> bool {
        matches!(self, Manager::Admin)
    }

    pub fn reseller_id(&self) -> Option<i64> {
        match self {
            Manager::Reseller { id, .. } => Some(*id),
            Manager::Admin => None,
        }
    }
}

fn db_failed(what: &str, e: impl std::fmt::Display) -> Response {
    tracing::error!("{what} failed: {e}");
    internal_error()
}

/// The caller as a manager of accounts: an administrator, or a reseller
/// (with its limits). Anyone else is refused.
pub async fn manager(state: &AppState, current: &CurrentUser) -> Result<Manager, Response> {
    if permissions::has_role(&current.user.role, Role::Admin) {
        return Ok(Manager::Admin);
    }
    if permissions::is_reseller_role(&current.user.role) {
        let limits = state
            .db
            .resellers()
            .limits(current.user.id)
            .await
            .map_err(|e| db_failed("reading reseller limits", e))?
            .unwrap_or_else(|| empty_limits(&current.user.username));
        return Ok(Manager::Reseller { id: current.user.id, limits });
    }
    Err(not_enough_permissions())
}

fn empty_limits(username: &str) -> ResellerLimits {
    ResellerLimits {
        prefix: username.chars().take(8).collect(),
        max_accounts: 0,
        max_websites: 0,
        max_databases: 0,
        max_mailboxes: 0,
        max_disk_mb: 0,
    }
}

/// Whether `manager` may manage `target`: an administrator any account but
/// its own role's peers are still its to manage; a reseller only the
/// accounts it made.
pub async fn may_manage(state: &AppState, manager: &Manager, target: &User) -> Result<bool, Response> {
    match manager {
        Manager::Admin => Ok(true),
        Manager::Reseller { id, .. } => {
            if target.id == *id || !permissions::has_role(&target.role, Role::EndUser) || target.is_admin() {
                return Ok(false);
            }
            let parent = state
                .db
                .resellers()
                .parent_of(target.id)
                .await
                .map_err(|e| db_failed("reading an account's reseller", e))?;
            Ok(parent == Some(*id))
        }
    }
}

/// A prefix: 2 to 8 lower-case letters and digits, starting with a letter.
pub fn prefix_valid(prefix: &str) -> bool {
    (2..=8).contains(&prefix.len())
        && prefix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && prefix.as_bytes()[0].is_ascii_lowercase()
}

/// `name` with the reseller's prefix: `abc` becomes `rs1_abc`, and a name
/// that already starts with it is left alone.
pub fn prefixed(prefix: &str, name: &str) -> String {
    let head = format!("{prefix}_");
    if name.starts_with(&head) {
        name.to_string()
    } else {
        format!("{head}{name}")
    }
}

/// The reseller whose limits cover `user_id`: the account itself when it is
/// a reseller, else the reseller that made it.
pub async fn reseller_of(state: &AppState, user_id: i64) -> Result<Option<(i64, ResellerLimits)>, String> {
    let repo = state.db.resellers();
    let user = state.db.users().by_id(user_id).await.map_err(|e| e.to_string())?;
    let Some(user) = user else { return Ok(None) };
    let reseller_id = if permissions::is_reseller_role(&user.role) {
        user.id
    } else {
        match repo.parent_of(user.id).await.map_err(|e| e.to_string())? {
            Some(p) => p,
            None => return Ok(None),
        }
    };
    let limits = repo.limits(reseller_id).await.map_err(|e| e.to_string())?;
    Ok(limits.map(|l| (reseller_id, l)))
}

/// What a reseller and its accounts really use.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Usage {
    pub accounts: i64,
    pub websites: i64,
    pub databases: i64,
    pub mailboxes: i64,
    pub disk_bytes: u64,
}

pub async fn usage(state: &AppState, reseller_id: i64) -> Result<Usage, String> {
    let repo = state.db.resellers();
    let children = repo.children(reseller_id).await.map_err(|e| e.to_string())?;
    let mut members = children.clone();
    members.push(reseller_id);
    let websites = repo.count_websites(&members).await.map_err(|e| e.to_string())?;
    let databases = repo.count_databases(&members).await.map_err(|e| e.to_string())?;
    let mailboxes = if crate::routes::addons::mail_installed() {
        let domains = crate::mail::domains(state).await?;
        let owned: std::collections::BTreeSet<&str> = domains
            .iter()
            .filter(|d| members.contains(&d.owner_id))
            .map(|d| d.name.as_str())
            .collect();
        crate::mail::load()
            .mailboxes
            .iter()
            .filter(|b| b.address.rsplit_once('@').is_some_and(|(_, d)| owned.contains(d)))
            .count() as i64
    } else {
        0
    };
    let app = crate::routes::addons::application_installed();
    let mut disk_bytes = 0u64;
    for id in &members {
        disk_bytes += crate::storage_quota::user_storage_used_bytes_cached(
            state.settings.command_dry_run,
            &state.db,
            *id,
            app,
        )
        .await;
    }
    Ok(Usage { accounts: children.len() as i64, websites, databases, mailboxes, disk_bytes })
}

/// What is being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Account,
    Website,
    Database,
    Mailbox,
}

/// Whether one more `resource` fits: `Err` names the limit it would pass.
pub fn room(limits: &ResellerLimits, used: &Usage, resource: Resource) -> Result<(), String> {
    let over = |max: i64, have: i64, what: &str| {
        if max > 0 && have >= max {
            Err(format!("The reseller's limit of {max} {what} is reached"))
        } else {
            Ok(())
        }
    };
    match resource {
        Resource::Account => over(limits.max_accounts, used.accounts, "accounts")?,
        Resource::Website => over(limits.max_websites, used.websites, "websites")?,
        Resource::Database => over(limits.max_databases, used.databases, "databases")?,
        Resource::Mailbox => over(limits.max_mailboxes, used.mailboxes, "mailboxes")?,
    }
    if limits.max_disk_mb > 0 && used.disk_bytes >= (limits.max_disk_mb as u64) * 1024 * 1024 {
        return Err(format!("The reseller's disk space of {} MB is used up", limits.max_disk_mb));
    }
    Ok(())
}

/// [`room`] for an account's owner: nothing to check outside a reseller.
pub async fn check_room(state: &AppState, owner_id: i64, resource: Resource) -> Result<(), String> {
    let Some((reseller_id, limits)) = reseller_of(state, owner_id).await? else {
        return Ok(());
    };
    let used = usage(state, reseller_id).await?;
    room(&limits, &used, resource)
}

/// The reseller's part of a user's record.
pub async fn describe(state: &AppState, user: &User) -> Value {
    let repo = state.db.resellers();
    let mut out = json!({});
    if permissions::is_reseller_role(&user.role) {
        if let Ok(Some(limits)) = repo.limits(user.id).await {
            out["reseller"] = json!(limits);
        }
    }
    if let Ok(Some(parent)) = repo.parent_of(user.id).await {
        out["parent_id"] = json!(parent);
        if let Ok(Some(p)) = state.db.users().by_id(parent).await {
            out["parent_username"] = json!(p.username);
        }
    }
    out
}

/// The limits in a request body: `{"prefix": .., "max_accounts": .., ...}`.
pub fn limits_from(body: &Value, current: Option<&ResellerLimits>) -> Result<ResellerLimits, String> {
    let mut l = current.cloned().unwrap_or_else(|| empty_limits(""));
    if let Some(p) = body.get("prefix").filter(|v| !v.is_null()) {
        let p = p.as_str().ok_or("prefix must be text")?.trim().to_ascii_lowercase();
        if !prefix_valid(&p) {
            return Err("The prefix is 2 to 8 lower-case letters and digits, starting with a letter".into());
        }
        l.prefix = p;
    }
    if !prefix_valid(&l.prefix) {
        return Err("A reseller needs a prefix for its accounts' usernames".into());
    }
    for (key, max, slot) in [
        ("max_accounts", 100_000i64, &mut l.max_accounts),
        ("max_websites", 1_000_000, &mut l.max_websites),
        ("max_databases", 1_000_000, &mut l.max_databases),
        ("max_mailboxes", 1_000_000, &mut l.max_mailboxes),
        ("max_disk_mb", 1024 * 1024 * 1024, &mut l.max_disk_mb),
    ] {
        if let Some(v) = body.get(key).filter(|v| !v.is_null()) {
            let n = v.as_i64().filter(|n| (0..=max).contains(n)).ok_or(format!("{key} must be 0 to {max}"))?;
            *slot = n;
        }
    }
    Ok(l)
}

/// Before an account goes: its provisioning tokens are revoked. Without
/// this, deleting the row would drop the token's owner and leave a token
/// the provisioning API reads as the administrator's.
pub async fn revoke_tokens_of(state: &AppState, user_id: i64) -> Result<(), String> {
    let ids = state.db.resellers().tokens_of(user_id).await.map_err(|e| e.to_string())?;
    for id in ids {
        state
            .db
            .api_tokens()
            .revoke(id, &snpanel_db::sqlalchemy_now())
            .await
            .map_err(|e| e.to_string())?;
    }
    state.db.resellers().forget_provisioning(user_id).await.map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Brand (white label)
// ---------------------------------------------------------------------------

fn assets_dir() -> std::path::PathBuf {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into());
    crate::spa::brand_assets_dir(std::path::Path::new(&dir))
}

/// An account's uploaded logo, removed with it (its brand row goes by the
/// foreign key).
pub fn forget_brand_assets(user_id: i64) {
    let prefix = format!("reseller-{user_id}-logo.");
    if let Ok(entries) = std::fs::read_dir(assets_dir()) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// The name and logo a brand shows, as the panel's settings name them.
pub fn brand_fields(brand: &snpanel_db::ResellerBrand) -> Value {
    let mut out = json!({});
    if !brand.app_name.trim().is_empty() {
        out["app_name"] = json!(brand.app_name);
    }
    let logo = crate::spa::asset_url(&assets_dir(), &brand.logo_filename);
    if !logo.is_empty() {
        out["logo_url"] = json!(logo);
    }
    out
}

/// The brand an account sees: its own when it is a reseller, else its
/// reseller's. `None` for the server's own.
pub async fn brand_for_user(state: &AppState, user: &User) -> Option<Value> {
    let (reseller, _) = reseller_of(state, user.id).await.ok().flatten()?;
    let brand = state.db.resellers().brand(reseller).await.ok().flatten()?;
    let fields = brand_fields(&brand);
    (fields.as_object().is_some_and(|o| !o.is_empty())).then_some(fields)
}

/// The brand whose panel hostname `host` is.
pub async fn brand_for_host(state: &AppState, host: &str) -> Option<snpanel_db::ResellerBrand> {
    let host = crate::tls::normalize_hostname(host);
    if host.is_empty() {
        return None;
    }
    state.db.resellers().brand_by_host(&host).await.ok().flatten()
}

/// The URL an account's reseller has its customers sign in at, if it set
/// one: `https://<its host>:<panel port>`.
pub async fn panel_url_for_user(state: &AppState, user_id: i64) -> Option<String> {
    let (reseller, _) = reseller_of(state, user_id).await.ok().flatten()?;
    let host = state.db.resellers().brand(reseller).await.ok().flatten()?.panel_host?;
    Some(format!("https://{host}:{}", state.settings.panel_port.get()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ResellerLimits {
        ResellerLimits {
            prefix: "rs1".into(),
            max_accounts: 2,
            max_websites: 0,
            max_databases: 5,
            max_mailboxes: 1,
            max_disk_mb: 100,
        }
    }

    #[test]
    fn usernames_get_the_prefix_once() {
        assert_eq!(prefixed("rs1", "abc"), "rs1_abc");
        assert_eq!(prefixed("rs1", "rs1_abc"), "rs1_abc");
        assert_eq!(prefixed("rs1", "rs10_abc"), "rs1_rs10_abc");
        assert!(prefix_valid("rs1"));
        assert!(!prefix_valid("1rs"));
        assert!(!prefix_valid("r"));
        assert!(!prefix_valid("RS"));
        assert!(!prefix_valid("toolongprefix"));
    }

    #[test]
    fn a_limit_is_on_what_is_used_and_zero_is_none() {
        let l = limits();
        let used = Usage { accounts: 1, websites: 999, databases: 4, mailboxes: 1, disk_bytes: 10 };
        assert!(room(&l, &used, Resource::Account).is_ok());
        assert!(room(&l, &used, Resource::Website).is_ok(), "no website limit");
        assert!(room(&l, &used, Resource::Database).is_ok());
        assert!(room(&l, &used, Resource::Mailbox).is_err());
        let full = Usage { accounts: 2, ..used.clone() };
        assert!(room(&l, &full, Resource::Account).is_err());
        let disk = Usage { disk_bytes: 100 * 1024 * 1024, accounts: 0, ..used };
        assert!(room(&l, &disk, Resource::Website).unwrap_err().contains("disk"));
    }

    #[test]
    fn limits_are_read_and_checked() {
        let body = json!({"prefix": "RS2", "max_accounts": 10, "max_disk_mb": 2048});
        let l = limits_from(&body, None).unwrap();
        assert_eq!(l.prefix, "rs2");
        assert_eq!(l.max_accounts, 10);
        assert_eq!(l.max_websites, 0);
        assert!(limits_from(&json!({"max_accounts": 1}), None).is_err(), "a prefix is needed");
        assert!(limits_from(&json!({"prefix": "rs", "max_accounts": -1}), None).is_err());
        let kept = limits_from(&json!({"max_websites": 3}), Some(&limits())).unwrap();
        assert_eq!((kept.prefix.as_str(), kept.max_websites, kept.max_accounts), ("rs1", 3, 2));
    }
}
