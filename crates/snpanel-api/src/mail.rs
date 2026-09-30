//! The Email addon: mailboxes and forwarders on the websites' domains.
//!
//! Not in the Python. What the panel keeps is `mail.json` beside
//! `addons.json`: the mailboxes (never their passwords - only Dovecot's file
//! holds a hash), the forwarders, and the domains whose mail is elsewhere.
//! Which domains there are, and whose they are, comes from the websites each
//! time, so a site moved to another account takes its mail with it.
//!
//! Every change hands the helper the whole state (`mail-sync`), which writes
//! the files Exim and Dovecot read and answers with each domain's DKIM
//! record; with the DNS Manager addon those records are published in the
//! domain's zone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use snpanel_core::SecretString;
use snpanel_ipc::{MailBox, MailDomain, MailForwarder, MailState};

use crate::state::AppState;

pub const SSO_KEY_FILE: &str = "/etc/snpanel/webmail-sso-key";
pub const WEBMAIL_PORT: u16 = 2096;
pub const DEFAULT_QUOTA_MB: u32 = 1024;
pub const MIN_PASSWORD: usize = 8;
pub const MAX_PASSWORD: usize = 128;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub mailboxes: Vec<StoredMailbox>,
    #[serde(default)]
    pub forwarders: Vec<StoredForwarder>,
    /// Domains whose MX is elsewhere: mail from here to them goes there.
    #[serde(default)]
    pub remote_domains: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMailbox {
    pub address: String,
    pub quota_mb: u32,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredForwarder {
    pub source: String,
    pub destinations: Vec<String>,
}

fn store_file() -> PathBuf {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into());
    PathBuf::from(dir).join("mail.json")
}

pub fn load() -> Store {
    std::fs::read_to_string(store_file())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(store: &Store) -> std::io::Result<()> {
    let path = store_file();
    let dir = path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| ".".into());
    std::fs::create_dir_all(&dir)?;
    let mut text = serde_json::to_string_pretty(store)?;
    text.push('\n');
    let temp = dir.join(format!(".mail.json.{}", std::process::id()));
    std::fs::write(&temp, text)?;
    std::fs::rename(&temp, &path)
}

/// One change at a time: read, change, sync, save.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A mail domain: a website's domain or alias, and the account it is on.
#[derive(Debug, Clone)]
pub struct Domain {
    pub name: String,
    pub owner_id: i64,
    pub linux_user: String,
}

/// Every website domain and alias with an account to keep mail in.
pub async fn domains(state: &AppState) -> Result<Vec<Domain>, String> {
    let sites = state
        .db
        .websites()
        .all_by_id()
        .await
        .map_err(|e| e.to_string())?;
    let ids: Vec<i64> = sites.iter().map(|s| s.id).collect();
    let aliases = state
        .db
        .websites()
        .aliases_for(&ids)
        .await
        .map_err(|e| e.to_string())?;
    let mut out: BTreeMap<String, Domain> = BTreeMap::new();
    for site in &sites {
        let Some(user) = site
            .linux_user
            .clone()
            .filter(|u| snpanel_core::PanelUsername::parse(u).is_ok())
        else {
            continue;
        };
        out.insert(
            site.domain.to_ascii_lowercase(),
            Domain {
                name: site.domain.to_ascii_lowercase(),
                owner_id: site.owner_id,
                linux_user: user.clone(),
            },
        );
        for alias in aliases.iter().filter(|a| a.website_id == site.id) {
            out.entry(alias.domain.to_ascii_lowercase())
                .or_insert(Domain {
                    name: alias.domain.to_ascii_lowercase(),
                    owner_id: site.owner_id,
                    linux_user: user.clone(),
                });
        }
    }
    Ok(out.into_values().collect())
}

fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

/// The helper's view of `store`, for the domains there are now. Mailboxes
/// and forwarders on a domain that is gone are left out.
pub fn build(
    store: &Store,
    domains: &[Domain],
    passwords: &BTreeMap<String, SecretString>,
    purge: &[String],
) -> Result<MailState, String> {
    let known: BTreeMap<&str, &Domain> = domains.iter().map(|d| (d.name.as_str(), d)).collect();
    let mut state = MailState {
        domains: domains
            .iter()
            .map(|d| {
                Ok(MailDomain {
                    domain: snpanel_core::Domain::parse(&d.name).map_err(|e| e.to_string())?,
                    owner: snpanel_core::PanelUsername::parse(&d.linux_user)
                        .map_err(|e| e.to_string())?,
                    local: !store.remote_domains.contains(&d.name),
                })
            })
            .collect::<Result<_, String>>()?,
        mailboxes: Vec::new(),
        forwarders: Vec::new(),
        purge: Vec::new(),
    };
    let boxes: BTreeSet<&str> = store
        .mailboxes
        .iter()
        .filter(|b| known.contains_key(domain_of(&b.address)))
        .map(|b| b.address.as_str())
        .collect();
    for b in store
        .mailboxes
        .iter()
        .filter(|b| boxes.contains(b.address.as_str()))
    {
        state.mailboxes.push(MailBox {
            address: b.address.clone(),
            quota_mb: b.quota_mb,
            password: passwords.get(&b.address).cloned(),
        });
    }
    for f in store
        .forwarders
        .iter()
        .filter(|f| known.contains_key(domain_of(&f.source)))
    {
        let mut destinations = f.destinations.clone();
        // A forwarder on a mailbox keeps a copy there.
        if boxes.contains(f.source.as_str()) && !destinations.contains(&f.source) {
            destinations.insert(0, f.source.clone());
        }
        state.forwarders.push(MailForwarder {
            source: f.source.clone(),
            destinations,
        });
    }
    state.purge = purge
        .iter()
        .filter(|p| !boxes.contains(p.as_str()))
        .cloned()
        .collect();
    state.validate()?;
    Ok(state)
}

/// The state written by the helper, and the DKIM records it answered with
/// published. `passwords` are the ones being set; `purge` the mailboxes
/// whose mail goes.
async fn apply(
    state: &AppState,
    store: &Store,
    passwords: &BTreeMap<String, SecretString>,
    purge: &[String],
) -> Result<(), String> {
    let domains = domains(state).await?;
    let mail = build(store, &domains, passwords, purge)?;
    let payload = serde_json::to_string(&mail).map_err(|e| e.to_string())?;
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "mail-sync",
        &[],
        Some(&payload),
        None,
    )
    .await;
    if !result.ok() {
        return Err(result
            .failure_detail("the mail server refused the change")
            .trim()
            .to_string());
    }
    let answer: Value = serde_json::from_str(result.stdout.trim()).unwrap_or(Value::Null);
    if let Some(dkim) = answer["dkim"].as_object() {
        let records: BTreeMap<String, String> = dkim
            .iter()
            .filter_map(|(d, r)| r.as_str().map(|r| (d.clone(), r.to_string())))
            .collect();
        publish_dns(&records, store).await;
    }
    Ok(())
}

/// Change the store with `change`, then apply it; the store is saved only
/// once the mail server has taken it.
pub async fn update<F>(
    state: &AppState,
    passwords: BTreeMap<String, SecretString>,
    purge: Vec<String>,
    change: F,
) -> Result<Store, String>
where
    F: FnOnce(&mut Store) -> Result<(), String>,
{
    let _guard = LOCK.lock().await;
    let mut store = load();
    change(&mut store)?;
    apply(state, &store, &passwords, &purge).await?;
    save(&store).map_err(|e| format!("saving mail.json: {e}"))?;
    Ok(store)
}

/// The state again, as it is: the websites changed.
pub async fn refresh(state: &AppState) {
    if !crate::routes::addons::mail_installed() {
        return;
    }
    let _guard = LOCK.lock().await;
    let store = load();
    if let Err(e) = apply(state, &store, &BTreeMap::new(), &[]).await {
        tracing::warn!("mail sync: {e}");
    }
}

/// A website or alias is gone: its mailboxes and forwarders with it, and
/// the mailboxes' mail.
pub async fn domain_deleted(state: &AppState, domain: &str) {
    if !crate::routes::addons::mail_installed() {
        return;
    }
    let domain = domain.to_ascii_lowercase();
    let purge: Vec<String> = load()
        .mailboxes
        .iter()
        .filter(|b| domain_of(&b.address) == domain)
        .map(|b| b.address.clone())
        .collect();
    let dropped = update(state, BTreeMap::new(), purge, |store| {
        store.mailboxes.retain(|b| domain_of(&b.address) != domain);
        store.forwarders.retain(|f| domain_of(&f.source) != domain);
        store.remote_domains.remove(&domain);
        Ok(())
    })
    .await;
    if let Err(e) = dropped {
        tracing::warn!("mail for {domain}: {e}");
    }
}

/// DKIM and DMARC in each mail domain's zone, when the DNS Manager addon
/// answers for it. The DKIM record is kept current; a DMARC record someone
/// wrote is left alone.
async fn publish_dns(dkim: &BTreeMap<String, String>, store: &Store) {
    if !crate::routes::addons::dns_installed() {
        return;
    }
    let Ok(hosted) = crate::dns::zones().await else {
        return;
    };
    let mut changes: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut zone_cache: BTreeMap<String, Value> = BTreeMap::new();
    for (domain, record) in dkim {
        let zone = if hosted.contains(domain) {
            domain.clone()
        } else if let Some(parent) = crate::dns::parent_zone(domain, &hosted) {
            parent.clone()
        } else {
            continue;
        };
        if !zone_cache.contains_key(&zone) {
            match crate::dns::zone(&zone).await {
                Ok(Some(z)) => {
                    zone_cache.insert(zone.clone(), z);
                }
                _ => continue,
            }
        }
        let existing = &zone_cache[&zone];
        let current = |name: &str, rtype: &str| -> Option<Vec<String>> {
            existing["rrsets"]
                .as_array()?
                .iter()
                .find(|s| s["name"] == name && s["type"] == rtype)
                .map(|s| {
                    s["records"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|r| r["content"].as_str().map(str::to_string))
                        .collect()
                })
        };
        let Ok(content) = crate::dns::normalize_content("TXT", record, &zone) else {
            continue;
        };
        let dkim_name = format!("default._domainkey.{domain}.");
        if current(&dkim_name, "TXT").as_deref() != Some(std::slice::from_ref(&content)) {
            changes
                .entry(zone.clone())
                .or_default()
                .push(txt_set(&dkim_name, &content));
        }
        let dmarc_name = format!("_dmarc.{domain}.");
        if current(&dmarc_name, "TXT").is_none() {
            changes
                .entry(zone.clone())
                .or_default()
                .push(txt_set(&dmarc_name, "\"v=DMARC1; p=none\""));
        }
        // A domain whose mail is here has an MX here.
        if !store.remote_domains.contains(domain) && current(&format!("{domain}."), "MX").is_none()
        {
            changes.entry(zone.clone()).or_default().push(json!({
                "name": format!("{domain}."), "type": "MX", "ttl": 3600, "changetype": "REPLACE",
                "records": [{"content": format!("10 {domain}."), "disabled": false}],
            }));
        }
    }
    for (zone, rrsets) in changes {
        if let Err(e) = crate::dns::patch_zone(&zone, rrsets).await {
            tracing::warn!("mail DNS records for {zone}: {e}");
        }
    }
}

fn txt_set(name: &str, content: &str) -> Value {
    json!({
        "name": name, "type": "TXT", "ttl": 3600, "changetype": "REPLACE",
        "records": [{"content": content, "disabled": false}],
    })
}

// ---------------------------------------------------------------------------
// The webmail's single sign-on
// ---------------------------------------------------------------------------

/// A token the webmail takes once, within two minutes: base64url JSON of
/// the mailbox, the expiry and a nonce, then its HMAC-SHA256 with the key
/// the helper shares with the webmail.
pub fn sso_token(email: &str, key: &str, now: i64, nonce: &str) -> String {
    use base64::Engine;
    use hmac::Mac;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = json!({ "email": email, "exp": now + 60, "nonce": nonce }).to_string();
    let body = b64.encode(payload.as_bytes());
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).expect("any key length");
    mac.update(body.as_bytes());
    let sig = b64.encode(mac.finalize().into_bytes());
    format!("{body}.{sig}")
}

pub fn sso_key() -> Result<String, String> {
    std::fs::read_to_string(SSO_KEY_FILE)
        .map(|k| k.trim().to_string())
        .ok()
        .filter(|k| k.len() >= 32)
        .ok_or_else(|| {
            "The webmail's sign-on key is missing: install the Email addon again".to_string()
        })
}

/// Where the webmail opens `email`, signed in.
pub fn webmail_link(host: &str, email: &str) -> Result<String, String> {
    use rand::RngCore;
    let key = sso_key()?;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let token = sso_token(email, &key, chrono::Utc::now().timestamp(), &nonce);
    Ok(format!(
        "https://{host}:{WEBMAIL_PORT}/api/auth/sso?token={token}"
    ))
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

pub fn password_valid(password: &str) -> Result<(), String> {
    let n = password.chars().count();
    if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&n) {
        return Err(format!(
            "The password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters"
        ));
    }
    if password.chars().any(char::is_control) {
        return Err("The password cannot hold control characters".into());
    }
    Ok(())
}

/// `local@domain` from the page, lower case and checked.
pub fn address(raw: &str) -> Result<String, String> {
    let address = raw.trim().to_ascii_lowercase();
    snpanel_ipc::split_address(&address)
        .map(|_| address.clone())
        .ok_or_else(|| {
            format!("{raw} is not a valid address: letters, digits and . _ + - before the @")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str) -> Domain {
        Domain {
            name: name.into(),
            owner_id: 2,
            linux_user: "alice".into(),
        }
    }

    #[test]
    fn the_state_follows_the_domains_there_are() {
        let store = Store {
            mailboxes: vec![
                StoredMailbox {
                    address: "info@a.test".into(),
                    quota_mb: 100,
                    created_at: String::new(),
                },
                StoredMailbox {
                    address: "x@gone.test".into(),
                    quota_mb: 100,
                    created_at: String::new(),
                },
            ],
            forwarders: vec![
                StoredForwarder {
                    source: "info@a.test".into(),
                    destinations: vec!["me@gmail.com".into()],
                },
                StoredForwarder {
                    source: "sales@a.test".into(),
                    destinations: vec!["me@gmail.com".into()],
                },
            ],
            remote_domains: ["b.test".to_string()].into(),
        };
        let state = build(
            &store,
            &[domain("a.test"), domain("b.test")],
            &BTreeMap::new(),
            &["x@gone.test".into()],
        )
        .unwrap();
        assert_eq!(
            state.mailboxes.len(),
            1,
            "the mailbox on a domain that is gone is left out"
        );
        assert!(state
            .domains
            .iter()
            .any(|d| d.domain.as_str() == "b.test" && !d.local));
        // A forwarder on a mailbox keeps a copy in it; one on a bare address does not.
        assert_eq!(
            state.forwarders[0].destinations,
            ["info@a.test", "me@gmail.com"]
        );
        assert_eq!(state.forwarders[1].destinations, ["me@gmail.com"]);
        assert_eq!(state.purge, ["x@gone.test"]);
    }

    #[test]
    fn the_sign_on_token_is_what_the_webmail_checks() {
        use base64::Engine;
        use hmac::Mac;
        let token = sso_token("a@example.com", "k".repeat(64).as_str(), 1_000, "n1");
        let (body, sig) = token.split_once('.').unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload: Value = serde_json::from_slice(&b64.decode(body).unwrap()).unwrap();
        assert_eq!(payload["email"], "a@example.com");
        assert_eq!(payload["exp"], 1_060);
        assert_eq!(payload["nonce"], "n1");
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice("k".repeat(64).as_bytes()).unwrap();
        mac.update(body.as_bytes());
        assert_eq!(
            b64.decode(sig).unwrap(),
            mac.finalize().into_bytes().to_vec()
        );
    }

    #[test]
    fn passwords_and_addresses_are_checked() {
        assert!(password_valid("short").is_err());
        assert!(password_valid("long enough").is_ok());
        assert!(password_valid("tab\there").is_err());
        assert_eq!(address(" Info@Example.com ").unwrap(), "info@example.com");
        assert!(address("a b@example.com").is_err());
        assert!(address("noat").is_err());
    }
}
