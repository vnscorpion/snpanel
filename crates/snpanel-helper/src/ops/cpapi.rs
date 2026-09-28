//! `ops::cpapi` - the snapshot CloudLinux's integration scripts read.
//!
//! `snpanel-cpapi` (the `integration.ini` scripts) answers CloudLinux's
//! questions - which accounts exist, which package each is on, which domains
//! they own - from `/var/lib/snpanel-cpapi/data.json`. The panel sends the
//! facts; the helper resolves UNIX ids itself, writes the file atomically and
//! re-applies LVE limits, because an account's package decides its limits.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};
use snpanel_ipc::{CpapiSnapshot, HelperResponse};

use crate::exec;
use crate::ops::nginx::write_atomic;
use crate::peercred::uid_of;

const DIR: &str = "/var/lib/snpanel-cpapi";
const DATA: &str = "/var/lib/snpanel-cpapi/data.json";

/// The file as `snpanel-cpapi` reads it. Accounts without a UNIX user (not
/// provisioned yet, or already removed) are left out: CloudLinux could do
/// nothing with them.
pub fn render(snap: &CpapiSnapshot, uid: impl Fn(&str) -> Option<u32>) -> Value {
    let mut main_domain: BTreeMap<&str, &str> = BTreeMap::new();
    let mut domains = serde_json::Map::new();
    for d in &snap.domains {
        if d.is_main {
            main_domain
                .entry(d.owner.as_str())
                .or_insert(d.domain.as_str());
        }
        domains.insert(
            d.domain.as_str().to_string(),
            json!({
                "owner": d.owner.as_str(),
                "document_root": d.document_root,
                "is_main": d.is_main,
                "php_version": d.php_version,
            }),
        );
    }
    let users: Vec<Value> = snap
        .users
        .iter()
        .filter_map(|u| {
            let id = uid(u.username.as_str())?;
            Some(json!({
                "id": id,
                "username": u.username.as_str(),
                "owner": "admin",
                "domain": main_domain.get(u.username.as_str()).copied().unwrap_or(""),
                "package": u.package.as_ref().map(|p| json!({"name": p.as_str(), "owner": "admin"})),
                "email": u.email,
                "locale_code": "EN_us",
            }))
        })
        .collect();
    json!({
        "version": snap.version,
        "login_url": snap.login_url,
        "admin_email": snap.admin_email,
        "users": users,
        "domains": domains,
        "packages": snap.packages.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
    })
}

/// `cpapi-sync`.
pub fn sync(snap: &CpapiSnapshot) -> HelperResponse {
    if let Err(m) = snap.validate() {
        return HelperResponse::failed(snpanel_ipc::HelperErrorKind::BadRequest, m);
    }
    let body = render(snap, |name| uid_of(name).ok());
    let mut bytes = serde_json::to_vec_pretty(&body).unwrap_or_default();
    bytes.push(b'\n');
    if std::fs::read(DATA).ok().as_deref() == Some(bytes.as_slice()) {
        return HelperResponse::with_stdout("unchanged\n".to_string());
    }
    if let Err(e) = std::fs::create_dir_all(DIR)
        .and_then(|_| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(DIR, std::fs::Permissions::from_mode(0o755))
        })
        .and_then(|_| write_atomic(Path::new(DATA), &bytes, 0o644))
    {
        return HelperResponse::failed(
            snpanel_ipc::HelperErrorKind::Internal,
            format!("writing {DATA}: {e}"),
        );
    }
    // Which package an account is on decides its limits; CloudLinux reads
    // that from the scripts, and running LVEs pick it up on re-apply.
    match snpanel_osabi::hosting::cloudlinux() {
        Some(cl) if cl.lve_loaded => {
            exec::respond("lvectl apply all", exec::run(&["lvectl", "apply", "all"]))
        }
        _ => HelperResponse::with_stdout("written\n".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_what_snpanel_cpapi_reads() {
        let snap: CpapiSnapshot = serde_json::from_value(json!({
            "version": "1.1.0",
            "login_url": "https://panel.example.com:2222/",
            "admin_email": "admin@example.com",
            "packages": ["Starter", "Pro"],
            "users": [
                {"username": "alice", "email": "alice@example.com", "package": "Starter"},
                {"username": "bob", "email": null, "package": null},
                {"username": "ghost", "email": null, "package": "Pro"},
            ],
            "domains": [
                {"domain": "b.alice.test", "owner": "alice", "document_root": "/home/alice/b.alice.test/public_html", "is_main": false, "php_version": "8.3"},
                {"domain": "a.alice.test", "owner": "alice", "document_root": "/home/alice/a.alice.test/public_html", "is_main": true, "php_version": "8.4"},
            ],
        }))
        .unwrap();
        let uids = |n: &str| match n {
            "alice" => Some(1001),
            "bob" => Some(1002),
            _ => None,
        };
        let out = render(&snap, uids);
        let users = out["users"].as_array().unwrap();
        assert_eq!(users.len(), 2, "an account without a UNIX user is left out");
        assert_eq!(users[0]["id"], 1001);
        assert_eq!(users[0]["domain"], "a.alice.test");
        assert_eq!(
            users[0]["package"],
            json!({"name": "Starter", "owner": "admin"})
        );
        assert_eq!(users[1]["package"], Value::Null);
        assert_eq!(users[1]["domain"], "");
        assert_eq!(out["domains"]["b.alice.test"]["php_version"], "8.3");
        assert_eq!(out["packages"], json!(["Starter", "Pro"]));
    }
}
