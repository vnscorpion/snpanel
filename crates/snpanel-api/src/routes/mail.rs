//! `/api/mail` - not in the Python: the Email addon's page.
//!
//! Every role, while the addon is installed (a 409 otherwise). An
//! administrator sees every domain and the services; anyone else the
//! domains of their own websites and aliases, decided from the websites each
//! time. Passwords are passed on to the helper, which keeps only a hash;
//! nothing here stores or returns one.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_core::SecretString;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, not_found};
use crate::mail::{self, StoredForwarder, StoredMailbox};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/mail", get(overview).fallback(crate::fallback))
        .route("/mail/mailboxes", post(create_mailbox).fallback(crate::fallback))
        .route(
            "/mail/mailboxes/{address}",
            axum::routing::patch(update_mailbox)
                .delete(delete_mailbox)
                .fallback(crate::fallback),
        )
        .route(
            "/mail/mailboxes/{address}/webmail",
            post(open_webmail).fallback(crate::fallback),
        )
        .route("/mail/forwarders", post(create_forwarder).fallback(crate::fallback))
        .route(
            "/mail/forwarders/{source}",
            axum::routing::delete(delete_forwarder).fallback(crate::fallback),
        )
        .route("/mail/domains/{domain}", put(set_domain).fallback(crate::fallback))
}

async fn admit(state: &AppState, parts: &mut Parts) -> Result<CurrentUser, Response> {
    let current = CurrentUser::from_parts(parts, state).await?;
    if !super::addons::mail_installed() {
        return Err(crate::errors::conflict(
            "The Email addon is not installed. Install it on the Addons page first.",
        ));
    }
    Ok(current)
}

fn is_admin(current: &CurrentUser) -> bool {
    permissions::has_role(&current.user.role, Role::Admin)
}

fn unprocessable(message: &str) -> Response {
    error(StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// The mail domains the caller may manage.
async fn visible_domains(state: &AppState, current: &CurrentUser) -> Result<Vec<mail::Domain>, Response> {
    let all = mail::domains(state).await.map_err(|e| {
        tracing::error!("listing mail domains failed: {e}");
        crate::errors::internal_error()
    })?;
    Ok(if is_admin(current) {
        all
    } else {
        all.into_iter().filter(|d| d.owner_id == current.user.id).collect()
    })
}

/// The domain of `address`, when the caller may manage it.
async fn domain_for(state: &AppState, current: &CurrentUser, address: &str) -> Result<mail::Domain, Response> {
    let domain = address.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
    visible_domains(state, current)
        .await?
        .into_iter()
        .find(|d| d.name == domain)
        .ok_or_else(|| not_found("No such mail domain"))
}

/// The hostname mail clients and the webmail are reached at: the one the
/// panel was opened on.
fn host_of(parts: &Parts) -> String {
    parts
        .headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            if h.starts_with('[') {
                h.split(']').next().map(|v| format!("{v}]")).unwrap_or_default()
            } else {
                h.split(':').next().unwrap_or("").to_string()
            }
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// The name the mail servers and the webmail have a certificate for: the
/// panel's own domain, or the name the panel was opened on.
fn mail_host(state: &AppState, parts: &Parts) -> String {
    let domain = state.settings.panel_domain.trim().to_ascii_lowercase();
    if snpanel_core::Domain::parse(&domain).is_ok() {
        domain
    } else {
        host_of(parts)
    }
}

async fn status(state: &AppState) -> Value {
    let result = crate::shell::privileged(state.settings.command_dry_run, "mail-status", &[], None, None).await;
    serde_json::from_str(result.stdout.trim()).unwrap_or(Value::Null)
}

async fn page(state: &AppState, current: &CurrentUser, parts: &Parts) -> Result<Value, Response> {
    let domains = visible_domains(state, current).await?;
    let store = mail::load();
    let service = status(state).await;
    let names: Vec<&str> = domains.iter().map(|d| d.name.as_str()).collect();
    let on = |address: &str| names.contains(&address.rsplit_once('@').map(|(_, d)| d).unwrap_or(""));
    let mailboxes: Vec<Value> = store
        .mailboxes
        .iter()
        .filter(|b| on(&b.address))
        .map(|b| {
            json!({
                "address": b.address,
                "quota_mb": b.quota_mb,
                "used_bytes": service["usage"][&b.address].as_u64().unwrap_or(0),
                "created_at": b.created_at,
            })
        })
        .collect();
    let forwarders: Vec<&StoredForwarder> = store.forwarders.iter().filter(|f| on(&f.source)).collect();
    let host = mail_host(state, parts);
    let mut body = json!({
        "is_admin": is_admin(current),
        "domains": domains.iter().map(|d| json!({
            "domain": d.name,
            "local": !store.remote_domains.contains(&d.name),
            "mailboxes": store.mailboxes.iter().filter(|b| b.address.ends_with(&format!("@{}", d.name))).count(),
        })).collect::<Vec<_>>(),
        "mailboxes": mailboxes,
        "forwarders": forwarders,
        "client": {
            "host": host,
            "imap": 993, "pop3": 995, "smtp": 465, "submission": 587,
            "webmail": format!("https://{host}:{}/", mail::WEBMAIL_PORT),
        },
        "default_quota_mb": mail::DEFAULT_QUOTA_MB,
    });
    if is_admin(current) {
        body["service"] = json!({
            "services": service["services"],
            "queue": service["queue"],
            "hostname": service["hostname"],
        });
    }
    Ok(body)
}

async fn overview(State(state): State<AppState>, mut parts: Parts) -> Response {
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match page(&state, &current, &parts).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}

/// The request's body, with the caller admitted.
async fn admitted_body(state: &AppState, req: axum::extract::Request) -> Result<(Parts, CurrentUser, Value), Response> {
    let (mut parts, body) = req.into_parts();
    let current = admit(state, &mut parts).await?;
    let body = super::auth::read_json_body(body).await?;
    Ok((parts, current, body))
}

fn quota_in(body: &Value) -> Result<Option<u32>, Response> {
    match &body["quota_mb"] {
        Value::Null => Ok(None),
        v => v
            .as_u64()
            .filter(|q| *q <= u64::from(snpanel_ipc::MAIL_MAX_QUOTA_MB))
            .map(|q| Some(q as u32))
            .ok_or_else(|| unprocessable("The quota is a number of MB (0 for no limit)")),
    }
}

async fn respond(state: &AppState, current: &CurrentUser, parts: &Parts, notice: &str) -> Response {
    match page(state, current, parts).await {
        Ok(mut v) => {
            v["message"] = json!(notice);
            axum::Json(v).into_response()
        }
        Err(r) => r,
    }
}

async fn create_mailbox(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (parts, current, body) = match admitted_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let address = match mail::address(body["address"].as_str().unwrap_or("")) {
        Ok(a) => a,
        Err(m) => return unprocessable(&m),
    };
    if let Err(r) = domain_for(&state, &current, &address).await {
        return r;
    }
    let password = body["password"].as_str().unwrap_or("");
    if let Err(m) = mail::password_valid(password) {
        return unprocessable(&m);
    }
    let quota = match quota_in(&body) {
        Ok(q) => q.unwrap_or(mail::DEFAULT_QUOTA_MB),
        Err(r) => return r,
    };
    let passwords = BTreeMap::from([(address.clone(), SecretString::new(password))]);
    let created = mail::update(&state, passwords, Vec::new(), |store| {
        if store.mailboxes.iter().any(|b| b.address == address) {
            return Err(format!("{address} already exists"));
        }
        if store.forwarders.iter().any(|f| f.source == address) {
            return Err(format!("{address} is a forwarder; remove it first"));
        }
        store.mailboxes.push(StoredMailbox {
            address: address.clone(),
            quota_mb: quota,
            created_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        });
        Ok(())
    })
    .await;
    if let Err(m) = created {
        return bad_request(&m);
    }
    super::packages::audit_action_detail(&state, &parts, current.user.id, "mail_mailbox_create", &address, &format!("quota={quota}"))
        .await;
    respond(&state, &current, &parts, &format!("{address} is ready.")).await
}

async fn update_mailbox(
    State(state): State<AppState>,
    Path(address): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, current, body) = match admitted_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let address = match mail::address(&address) {
        Ok(a) => a,
        Err(m) => return unprocessable(&m),
    };
    if let Err(r) = domain_for(&state, &current, &address).await {
        return r;
    }
    let mut passwords = BTreeMap::new();
    if let Some(password) = body["password"].as_str() {
        if let Err(m) = mail::password_valid(password) {
            return unprocessable(&m);
        }
        passwords.insert(address.clone(), SecretString::new(password));
    }
    let quota = match quota_in(&body) {
        Ok(q) => q,
        Err(r) => return r,
    };
    if passwords.is_empty() && quota.is_none() {
        return unprocessable("Nothing to change: give a password or a quota");
    }
    let changed = mail::update(&state, passwords.clone(), Vec::new(), |store| {
        let b = store
            .mailboxes
            .iter_mut()
            .find(|b| b.address == address)
            .ok_or_else(|| format!("{address} does not exist"))?;
        if let Some(q) = quota {
            b.quota_mb = q;
        }
        Ok(())
    })
    .await;
    if let Err(m) = changed {
        return bad_request(&m);
    }
    let detail = format!("password={} quota={}", !passwords.is_empty(), quota.map(|q| q.to_string()).unwrap_or_default());
    super::packages::audit_action_detail(&state, &parts, current.user.id, "mail_mailbox_update", &address, &detail).await;
    respond(&state, &current, &parts, &format!("{address} is saved.")).await
}

async fn delete_mailbox(State(state): State<AppState>, Path(address): Path<String>, mut parts: Parts) -> Response {
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let address = match mail::address(&address) {
        Ok(a) => a,
        Err(m) => return unprocessable(&m),
    };
    if let Err(r) = domain_for(&state, &current, &address).await {
        return r;
    }
    let removed = mail::update(&state, BTreeMap::new(), vec![address.clone()], |store| {
        let before = store.mailboxes.len();
        store.mailboxes.retain(|b| b.address != address);
        if store.mailboxes.len() == before {
            return Err(format!("{address} does not exist"));
        }
        Ok(())
    })
    .await;
    if let Err(m) = removed {
        return bad_request(&m);
    }
    super::packages::audit_action_detail(&state, &parts, current.user.id, "mail_mailbox_delete", &address, "").await;
    respond(&state, &current, &parts, &format!("{address} and its mail are deleted.")).await
}

async fn open_webmail(State(state): State<AppState>, Path(address): Path<String>, mut parts: Parts) -> Response {
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let address = match mail::address(&address) {
        Ok(a) => a,
        Err(m) => return unprocessable(&m),
    };
    if let Err(r) = domain_for(&state, &current, &address).await {
        return r;
    }
    if !mail::load().mailboxes.iter().any(|b| b.address == address) {
        return not_found("No such mailbox");
    }
    match mail::webmail_link(&mail_host(&state, &parts), &address) {
        Ok(url) => {
            super::packages::audit_action_detail(&state, &parts, current.user.id, "mail_webmail_open", &address, "").await;
            axum::Json(json!({ "url": url })).into_response()
        }
        Err(m) => bad_request(&m),
    }
}

async fn create_forwarder(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (parts, current, body) = match admitted_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let source = match mail::address(body["source"].as_str().unwrap_or("")) {
        Ok(a) => a,
        Err(m) => return unprocessable(&m),
    };
    if let Err(r) = domain_for(&state, &current, &source).await {
        return r;
    }
    let destinations: Vec<String> = match &body["destinations"] {
        Value::Array(items) => items.iter().filter_map(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Value::String(s) => s.split([',', '\n', ' ']).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    };
    let destinations: Vec<String> = destinations
        .into_iter()
        .map(|d| match d.rsplit_once('@') {
            Some((l, dom)) => format!("{l}@{}", dom.to_ascii_lowercase()),
            None => d,
        })
        .collect();
    if destinations.is_empty() || destinations.len() > snpanel_ipc::MAIL_MAX_DESTINATIONS {
        return unprocessable("Give between 1 and 20 destination addresses");
    }
    if let Some(bad) = destinations.iter().find(|d| !snpanel_ipc::destination_valid(d) || **d == source) {
        return unprocessable(&format!("{bad} is not a valid destination"));
    }
    let created = mail::update(&state, BTreeMap::new(), Vec::new(), |store| {
        match store.forwarders.iter_mut().find(|f| f.source == source) {
            Some(f) => f.destinations = destinations.clone(),
            None => store.forwarders.push(StoredForwarder { source: source.clone(), destinations: destinations.clone() }),
        }
        Ok(())
    })
    .await;
    if let Err(m) = created {
        return bad_request(&m);
    }
    super::packages::audit_action_detail(&state, &parts, current.user.id, "mail_forwarder_save", &source, &destinations.join(",")).await;
    respond(&state, &current, &parts, &format!("Mail to {source} is forwarded.")).await
}

async fn delete_forwarder(State(state): State<AppState>, Path(source): Path<String>, mut parts: Parts) -> Response {
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let source = match mail::address(&source) {
        Ok(a) => a,
        Err(m) => return unprocessable(&m),
    };
    if let Err(r) = domain_for(&state, &current, &source).await {
        return r;
    }
    let removed = mail::update(&state, BTreeMap::new(), Vec::new(), |store| {
        let before = store.forwarders.len();
        store.forwarders.retain(|f| f.source != source);
        if store.forwarders.len() == before {
            return Err(format!("{source} is not forwarded"));
        }
        Ok(())
    })
    .await;
    if let Err(m) = removed {
        return bad_request(&m);
    }
    super::packages::audit_action_detail(&state, &parts, current.user.id, "mail_forwarder_delete", &source, "").await;
    respond(&state, &current, &parts, &format!("Mail to {source} is no longer forwarded.")).await
}

/// Whether a domain's mail is delivered here, or where its MX says.
async fn set_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, current, body) = match admitted_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let domain = domain.trim().to_ascii_lowercase();
    if !visible_domains(&state, &current).await.map(|d| d.iter().any(|x| x.name == domain)).unwrap_or(false) {
        return not_found("No such mail domain");
    }
    let Some(local) = body["local"].as_bool() else {
        return unprocessable("local must be true or false");
    };
    let changed = mail::update(&state, BTreeMap::new(), Vec::new(), |store| {
        if local {
            store.remote_domains.remove(&domain);
        } else {
            store.remote_domains.insert(domain.clone());
        }
        Ok(())
    })
    .await;
    if let Err(m) = changed {
        return bad_request(&m);
    }
    super::packages::audit_action_detail(&state, &parts, current.user.id, "mail_domain_routing", &domain, if local { "local" } else { "remote" }).await;
    respond(
        &state,
        &current,
        &parts,
        &if local {
            format!("Mail for {domain} is delivered here.")
        } else {
            format!("Mail for {domain} goes to its own mail server.")
        },
    )
    .await
}
