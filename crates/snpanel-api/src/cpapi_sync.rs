//! Keeping CloudLinux's picture of the panel current (Hosting Edition).
//!
//! CloudLinux asks the panel, through the CPAPI integration scripts, which
//! accounts exist and which package each is on, and gives every account its
//! package's LVE limits. The scripts read a snapshot; this module builds it
//! from the database and has the helper write it (`cpapi-sync`).
//!
//! A change that decides limits - an account's package, a package's name, an
//! account created or deleted - calls [`poke`], and the snapshot follows
//! within a second. Everything else a snapshot holds (sites, aliases, their
//! PHP versions) is picked up by a slower sweep. The helper leaves the file
//! alone when nothing changed, so the sweep costs a few queries.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

use snpanel_core::{Domain, PanelUsername};
use snpanel_db::{PackageRepo, UserRepo, WebsiteRepo};
use snpanel_ipc::{CpapiDomain, CpapiSnapshot, CpapiUser, LvePackageName};
use tokio::sync::Notify;

use crate::state::AppState;

const SWEEP: Duration = Duration::from_secs(60);
/// Changes arrive in bursts (a package edit, then the accounts on it).
const SETTLE: Duration = Duration::from_millis(500);

fn wake() -> &'static Notify {
    static WAKE: OnceLock<Notify> = OnceLock::new();
    WAKE.get_or_init(Notify::new)
}

/// Ask for a sync soon. Cheap, and harmless where there is no CloudLinux.
pub fn poke() {
    wake().notify_one();
}

/// Whether this server is one the snapshot is for.
pub fn applies() -> bool {
    crate::system::is_hosting_edition() && snpanel_osabi::hosting::cloudlinux().is_some()
}

/// Start the sync loop, on a CloudLinux Hosting Edition server only.
pub fn start(state: &AppState) {
    if !applies() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = sync_now(&state).await {
                tracing::warn!("CloudLinux CPAPI snapshot not written: {e}");
            }
            let _ = tokio::time::timeout(SWEEP, wake().notified()).await;
            tokio::time::sleep(SETTLE).await;
        }
    });
}

/// The document root CloudLinux should see for a site.
fn document_root(root_path: &str, document_root: &str, rewrite_mode: &str) -> String {
    let mut root = format!(
        "{}/{}",
        root_path.trim_end_matches('/'),
        document_root.trim_matches('/')
    );
    if rewrite_mode == "laravel" {
        root.push_str("/public");
    }
    root.trim_end_matches('/').to_string()
}

fn dotted_php(v: &str) -> String {
    let b = v.as_bytes();
    if b.len() == 3 && b[0].is_ascii_digit() && b[1] == b'.' && b[2].is_ascii_digit() {
        v.to_string()
    } else {
        // A site without PHP still has to name one; the selector's default.
        "8.4".to_string()
    }
}

/// The snapshot, from the database.
pub async fn build(state: &AppState) -> Result<CpapiSnapshot, String> {
    let pool = state.db.pool();
    let packages = PackageRepo::new(pool)
        .list()
        .await
        .map_err(|e| e.to_string())?;
    let users = UserRepo::new(pool)
        .list_all()
        .await
        .map_err(|e| e.to_string())?;
    let sites = WebsiteRepo::new(pool)
        .all_by_id()
        .await
        .map_err(|e| e.to_string())?;
    let ids: Vec<i64> = sites.iter().map(|s| s.id).collect();
    let aliases = WebsiteRepo::new(pool)
        .aliases_for(&ids)
        .await
        .map_err(|e| e.to_string())?;

    let package_name: BTreeMap<i64, LvePackageName> = packages
        .iter()
        .filter_map(|p| Some((p.id, LvePackageName::parse(&p.name).ok()?)))
        .collect();

    let admin_email = users
        .iter()
        .find(|u| u.role == "admin")
        .map(|u| u.email.clone());
    // Every account with a UNIX user, the administrator's too: its sites
    // are hosted like anyone's and CloudLinux has to know whose they are
    // (limits, CageFS isolates). Accounts without one are dropped by the
    // helper, which resolves the uids.
    let cl_users: Vec<CpapiUser> = users
        .iter()
        .filter_map(|u| {
            Some(CpapiUser {
                username: PanelUsername::parse(&u.username).ok()?,
                email: Some(u.email.clone()).filter(|e| !e.is_empty()),
                package: u.package_id.and_then(|id| package_name.get(&id).cloned()),
            })
        })
        .collect();
    let known: HashSet<&str> = cl_users.iter().map(|u| u.username.as_str()).collect();

    let mut domains = Vec::new();
    let mut has_main: HashSet<String> = HashSet::new();
    let mut seen: HashSet<String> = HashSet::new();
    for site in &sites {
        let Some(owner) = site.linux_user.as_deref().filter(|u| known.contains(u)) else {
            continue;
        };
        let Ok(owner) = PanelUsername::parse(owner) else {
            continue;
        };
        let Ok(domain) = Domain::parse(&site.domain) else {
            continue;
        };
        let root = document_root(
            &site.root_path,
            &site.document_root,
            &site.nginx_rewrite_mode,
        );
        let php = dotted_php(&site.php_version);
        let is_main = has_main.insert(owner.as_str().to_string());
        seen.insert(domain.as_str().to_string());
        domains.push(CpapiDomain {
            domain,
            owner: owner.clone(),
            document_root: root.clone(),
            is_main,
            php_version: php.clone(),
        });
        for alias in aliases.iter().filter(|a| a.website_id == site.id) {
            let Ok(domain) = Domain::parse(&alias.domain) else {
                continue;
            };
            if !seen.insert(domain.as_str().to_string()) {
                continue;
            }
            domains.push(CpapiDomain {
                domain,
                owner: owner.clone(),
                document_root: root.clone(),
                is_main: false,
                php_version: php.clone(),
            });
        }
    }

    let port = state.settings.panel_port.get();
    let url = crate::panel_urls::configured_panel_url(&state.settings);
    let login_url = if url.is_empty() {
        let host = crate::panel_urls::configured_panel_host(&state.settings);
        format!("https://{host}:{port}/")
    } else {
        url
    };

    let snapshot = CpapiSnapshot {
        version: crate::updates::app_version(),
        login_url,
        admin_email,
        packages: package_name.into_values().collect(),
        users: cl_users,
        // A site whose root the validation would refuse is left out rather
        // than failing everyone else's.
        domains: domains
            .into_iter()
            .filter(|d| {
                let one = CpapiSnapshot {
                    version: String::new(),
                    login_url: String::new(),
                    admin_email: None,
                    packages: Vec::new(),
                    users: Vec::new(),
                    domains: vec![d.clone()],
                };
                one.validate().is_ok()
            })
            .collect(),
    };
    snapshot.validate()?;
    Ok(snapshot)
}

/// The name of the package an account is on, if any.
pub async fn package_of(state: &AppState, username: &str) -> Option<String> {
    let pool = state.db.pool();
    let user = UserRepo::new(pool).by_username(username).await.ok()??;
    UserRepo::new(pool)
        .package_name(user.package_id)
        .await
        .ok()?
}

/// Build the snapshot and have the helper write it.
pub async fn sync_now(state: &AppState) -> Result<(), String> {
    let snapshot = build(state).await?;
    let body = serde_json::to_string(&snapshot).map_err(|e| e.to_string())?;
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "cpapi-sync",
        &[],
        Some(&body),
        None,
    )
    .await;
    if result.ok() {
        Ok(())
    } else {
        Err(result.failure_detail("cpapi-sync failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_roots_join_the_way_the_site_serves_them() {
        assert_eq!(
            document_root("/home/alice/a.test", "public_html", "wordpress"),
            "/home/alice/a.test/public_html"
        );
        assert_eq!(
            document_root("/home/alice/a.test/", "/public_html/", "laravel"),
            "/home/alice/a.test/public_html/public"
        );
    }

    #[test]
    fn a_site_without_php_still_names_a_version() {
        assert_eq!(dotted_php("8.3"), "8.3");
        assert_eq!(dotted_php("none"), "8.4");
        assert_eq!(dotted_php(""), "8.4");
    }
}
