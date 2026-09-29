//! `/api/dns` - not in the Python: the DNS Manager addon's page.
//!
//! Every role, while the addon is installed (a 409 otherwise). An
//! administrator sees and edits every zone and the settings; anyone else
//! only the zones of their own websites' domains and aliases - decided from
//! the websites each time, so a site moved to another account takes its
//! zone with it. The SOA is PowerDNS's own, and the zone's NS records are
//! the administrator's.

use std::collections::BTreeSet;

use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};

use crate::auth::CurrentUser;
use crate::dns::{self, DnsSettings, PdnsError};
use crate::errors::{bad_request, error, not_found};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dns", get(overview).fallback(crate::fallback))
        .route("/dns/settings", put(save_settings).fallback(crate::fallback))
        .route("/dns/nameservers", put(save_nameservers).fallback(crate::fallback))
        .route(
            "/dns/zones/{zone}",
            get(read_zone)
                .patch(patch_zone)
                .fallback(crate::fallback),
        )
        .route(
            "/dns/zones/{zone}/reset",
            post(reset_zone).fallback(crate::fallback),
        )
}

/// The caller, while the addon is installed.
async fn admit(state: &AppState, parts: &mut Parts) -> Result<CurrentUser, Response> {
    let current = CurrentUser::from_parts(parts, state).await?;
    if !super::addons::dns_installed() {
        return Err(crate::errors::conflict(
            "The DNS Manager addon is not installed. Install it on the Addons page first.",
        ));
    }
    Ok(current)
}

fn is_admin(current: &CurrentUser) -> bool {
    permissions::has_role(&current.user.role, Role::Admin)
}

fn pdns_failed(e: PdnsError) -> Response {
    error(StatusCode::BAD_GATEWAY, &e.0)
}

/// The domains of the caller's websites and their aliases.
async fn own_domains(state: &AppState, user_id: i64) -> Result<BTreeSet<String>, Response> {
    let sites = state.db.websites().list(Some(user_id), "").await.map_err(|e| {
        tracing::error!("listing websites failed: {e}");
        crate::errors::internal_error()
    })?;
    let ids: Vec<i64> = sites.iter().map(|s| s.id).collect();
    let aliases = state.db.websites().aliases_for(&ids).await.map_err(|e| {
        tracing::error!("listing aliases failed: {e}");
        crate::errors::internal_error()
    })?;
    Ok(sites
        .into_iter()
        .map(|s| s.domain)
        .chain(aliases.into_iter().map(|a| a.domain))
        .map(|d| d.to_ascii_lowercase())
        .collect())
}

/// The account whose website (or alias) the zone is, if any.
async fn zone_owner(state: &AppState, zone: &str) -> Option<String> {
    crate::mail::domains(state).await.ok()?.into_iter().find(|d| d.name == zone).map(|d| d.linux_user)
}

/// Every zone's account, for the list.
async fn owners_of(state: &AppState) -> Value {
    let map: serde_json::Map<String, Value> = crate::mail::domains(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|d| (d.name, json!(d.linux_user)))
        .collect();
    Value::Object(map)
}

/// The zone from the path, when the caller may touch it.
async fn zone_for(state: &AppState, current: &CurrentUser, raw: &str) -> Result<String, Response> {
    let zone = dns::zone_name(raw).map_err(|m| bad_request(&m))?;
    if !is_admin(current) && !own_domains(state, current.user.id).await?.contains(&zone) {
        // The same answer as a zone that does not exist: whether someone
        // else's domain is hosted here is not this caller's business.
        return Err(not_found("No such zone"));
    }
    Ok(zone)
}

async fn overview(State(state): State<AppState>, mut parts: Parts) -> Response {
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let admin = is_admin(&current);
    let settings = dns::settings();
    let domains: BTreeSet<String> = match if admin {
        dns::all_domains(&state).await.map(|d| d.into_iter().collect()).map_err(|e| {
            tracing::error!("listing domains failed: {e}");
            crate::errors::internal_error()
        })
    } else {
        own_domains(&state, current.user.id).await
    } {
        Ok(d) => d,
        Err(r) => return r,
    };
    // Zones are never made by hand: whatever is missing is made now, so the
    // page always shows every domain.
    if let Err(e) = dns::ensure_domains(&state, domains.iter().cloned().collect()).await {
        tracing::warn!("DNS zones not checked: {e}");
    }
    let (hosted, problem) = match dns::zones().await {
        Ok(z) => (z, None),
        Err(e) => (Vec::new(), Some(e.0)),
    };
    let zones: Vec<&String> = hosted
        .iter()
        .filter(|z| admin || domains.contains(*z))
        .collect();
    // The nameservers the caller's domains are delegated to: a reseller's
    // own (and so its customers'), or the server's.
    let effective = dns::settings_for_owner(&state, Some(current.user.id)).await;
    let reseller = permissions::is_reseller_role(&current.user.role);
    let mut body = json!({
        "is_admin": admin,
        "is_reseller": reseller,
        "zones": zones,
        "zone_owners": owners_of(&state).await,
        "nameservers": effective.nameservers,
        "default_nameservers": settings.nameservers,
        "reseller_nameservers": if reseller { json!(dns::reseller_nameservers(current.user.id)) } else { Value::Null },
        "server_ip": dns::server_ip(&settings),
        "types": dns::TYPES,
        "problem": problem,
    });
    if admin {
        let status = crate::shell::privileged(
            state.settings.command_dry_run,
            "dns-status",
            &[],
            None,
            None,
        )
        .await;
        body["service"] = serde_json::from_str::<Value>(status.stdout.trim()).unwrap_or(Value::Null);
        body["settings"] = serde_json::to_value(&settings).unwrap_or(Value::Null);
        body["default_template"] =
            serde_json::to_value(dns::default_template()).unwrap_or(Value::Null);
    }
    axum::Json(body).into_response()
}

/// `PUT /dns/nameservers` - a reseller's own nameservers, for its zones and
/// its customers'; an empty list goes back to the server's. The zones there
/// are are changed now.
async fn save_nameservers(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::is_reseller_role(&current.user.role) {
        return crate::errors::not_enough_permissions();
    }
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let raw: Vec<String> = body["nameservers"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let names = if raw.iter().all(|n| n.trim().is_empty()) {
        None
    } else {
        match dns::nameservers_valid(&raw) {
            Ok(n) => Some(n),
            Err(m) => return error(StatusCode::UNPROCESSABLE_ENTITY, &m),
        }
    };
    if let Err(e) = dns::save_reseller_nameservers(current.user.id, names.clone()) {
        tracing::error!("saving a reseller's nameservers failed: {e}");
        return crate::errors::internal_error();
    }
    let changed = dns::apply_reseller_nameservers(&state, current.user.id).await;
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "dns_reseller_nameservers",
        &current.user.username,
        &names.clone().unwrap_or_default().join(","),
    )
    .await;
    axum::Json(json!({
        "nameservers": names,
        "zones_changed": changed,
        "message": format!("Nameservers saved; {changed} zone(s) updated."),
    }))
    .into_response()
}

async fn save_settings(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !is_admin(&current) {
        return crate::errors::not_enough_permissions();
    }
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let settings = match serde_json::from_value::<DnsSettings>(body)
        .map_err(|e| format!("The settings are not in the expected form: {e}"))
        .and_then(DnsSettings::validated)
    {
        Ok(s) => s,
        Err(message) => return error(StatusCode::UNPROCESSABLE_ENTITY, &message),
    };
    if let Err(e) = dns::save_settings(&settings) {
        tracing::error!("writing dns.json failed: {e}");
        return crate::errors::internal_error();
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "dns_settings",
        "dns",
        &format!(
            "nameservers={} template={}",
            settings.nameservers.join(","),
            settings.template.len()
        ),
    )
    .await;
    axum::Json(json!({ "settings": settings })).into_response()
}

/// The zone as the page shows it: names relative, one RRset per row.
async fn zone_response(state: &AppState, current: &CurrentUser, zone: &str) -> Response {
    let found = match dns::zone(zone).await {
        Ok(Some(z)) => z,
        Ok(None) => return not_found("No such zone"),
        Err(e) => return pdns_failed(e),
    };
    let admin = is_admin(current);
    let apex = format!("{zone}.");
    let mut rrsets: Vec<Value> = found["rrsets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|set| {
            let rtype = set["type"].as_str().unwrap_or("");
            let name = set["name"].as_str().unwrap_or("");
            let editable = dns::TYPES.contains(&rtype) && (admin || !(rtype == "NS" && name == apex));
            json!({
                "name": dns::relative_name(name, zone),
                "fqdn": name.trim_end_matches('.'),
                "type": rtype,
                "ttl": set["ttl"],
                "records": set["records"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r["content"].as_str())
                    .collect::<Vec<_>>(),
                "editable": editable,
            })
        })
        .collect();
    let order = |t: &str| {
        ["SOA", "NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"]
            .iter()
            .position(|x| *x == t)
            .unwrap_or(99)
    };
    rrsets.sort_by(|a, b| {
        let key = |v: &Value| {
            let name = v["name"].as_str().unwrap_or("").to_string();
            (name != "@", name, order(v["type"].as_str().unwrap_or("")))
        };
        key(a).cmp(&key(b))
    });
    // Whether the registrar sends the world here: what a public resolver
    // says the zone's nameservers are, beside the ones it should have.
    let expected = dns::settings_for(state, zone).await.nameservers;
    // No NS answer at all (a subdomain served by its parent, a name not
    // registered yet) says nothing about where it points: leave it unknown.
    let public = dns::public_nameservers(zone).await.filter(|ns| !ns.is_empty());
    let delegated_here = public
        .as_ref()
        .map(|ns| ns.iter().all(|n| expected.iter().any(|e| e == n)));
    let records = rrsets.iter().map(|r| r["records"].as_array().map_or(0, Vec::len)).sum::<usize>();
    axum::Json(json!({
        "name": zone,
        "serial": found["serial"],
        "rrsets": rrsets,
        "records": records,
        "nameservers": expected,
        "public_nameservers": public,
        "delegated_here": delegated_here,
        "owner": zone_owner(state, zone).await,
    }))
    .into_response()
}

async fn read_zone(
    State(state): State<AppState>,
    Path(zone): Path<String>,
    mut parts: Parts,
) -> Response {
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let zone = match zone_for(&state, &current, &zone).await {
        Ok(z) => z,
        Err(r) => return r,
    };
    zone_response(&state, &current, &zone).await
}

/// One change from the page: the RRset `name`/`type` becomes `records`
/// (none: removed). Checked here, in PowerDNS's form.
fn rrset_change(change: &Value, zone: &str, admin: bool, default_ttl: u32) -> Result<Value, String> {
    let rtype = change["type"].as_str().unwrap_or("").trim().to_ascii_uppercase();
    if !dns::TYPES.contains(&rtype.as_str()) {
        return Err(format!("{rtype} records cannot be edited here"));
    }
    let name = dns::record_name(change["name"].as_str().unwrap_or("@"), zone)?;
    let apex = format!("{zone}.");
    if rtype == "NS" && name == apex && !admin {
        return Err("The zone's nameservers are set by the administrator".into());
    }
    let records: Vec<String> = match &change["records"] {
        Value::Array(items) => items
            .iter()
            .map(|r| r.as_str().map(str::to_string).ok_or("A record must be text".to_string()))
            .collect::<Result<_, _>>()?,
        Value::Null => Vec::new(),
        _ => return Err("records must be a list".into()),
    };
    if records.is_empty() {
        if rtype == "NS" && name == apex {
            return Err("A zone must keep its nameservers".into());
        }
        return Ok(json!({"name": name, "type": rtype, "changetype": "DELETE"}));
    }
    if records.len() > 100 {
        return Err("At most 100 records per name and type".into());
    }
    if rtype == "CNAME" && (name == apex || records.len() > 1) {
        return Err(if name == apex {
            "A CNAME cannot be at the zone's own name (@)".to_string()
        } else {
            "A name has at most one CNAME".to_string()
        });
    }
    let ttl = match &change["ttl"] {
        Value::Null => default_ttl,
        v => v
            .as_u64()
            .filter(|t| (u64::from(dns::MIN_TTL)..=u64::from(dns::MAX_TTL)).contains(t))
            .ok_or_else(|| {
                format!("The TTL must be from {} to {} seconds", dns::MIN_TTL, dns::MAX_TTL)
            })? as u32,
    };
    let mut contents: Vec<String> = Vec::new();
    for raw in &records {
        let content = dns::normalize_content(&rtype, raw, zone)?;
        if !contents.contains(&content) {
            contents.push(content);
        }
    }
    Ok(json!({
        "name": name,
        "type": rtype,
        "ttl": ttl,
        "changetype": "REPLACE",
        "records": contents.iter().map(|c| json!({"content": c, "disabled": false})).collect::<Vec<_>>(),
    }))
}

async fn patch_zone(
    State(state): State<AppState>,
    Path(zone): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let zone = match zone_for(&state, &current, &zone).await {
        Ok(z) => z,
        Err(r) => return r,
    };
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(changes) = body["rrsets"].as_array().filter(|c| !c.is_empty() && c.len() <= 50) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "rrsets must be a list of one to fifty changes",
        );
    };
    let default_ttl = dns::settings().default_ttl;
    let admin = is_admin(&current);
    let mut rrsets = Vec::new();
    for change in changes {
        match rrset_change(change, &zone, admin, default_ttl) {
            Ok(v) => rrsets.push(v),
            Err(m) => return error(StatusCode::UNPROCESSABLE_ENTITY, &m),
        }
    }
    if let Err(e) = dns::patch_zone(&zone, rrsets.clone()).await {
        return bad_request(&e.0);
    }
    let summary: Vec<String> = rrsets
        .iter()
        .map(|r| {
            format!(
                "{} {} {}",
                r["changetype"].as_str().unwrap_or(""),
                r["name"].as_str().unwrap_or(""),
                r["type"].as_str().unwrap_or("")
            )
        })
        .collect();
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "dns_records",
        &zone,
        &summary.join("; "),
    )
    .await;
    zone_response(&state, &current, &zone).await
}

/// The zone made again from the template: every record in it replaced.
async fn reset_zone(
    State(state): State<AppState>,
    Path(zone): Path<String>,
    mut parts: Parts,
) -> Response {
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let zone = match zone_for(&state, &current, &zone).await {
        Ok(z) => z,
        Err(r) => return r,
    };
    let settings = dns::settings_for(&state, &zone).await;
    let ip = dns::server_ip(&settings).unwrap_or_default();
    let fresh = match dns::zone_rrsets(&zone, &settings, &ip) {
        Ok(r) => r,
        Err(m) => return bad_request(&m),
    };
    let existing = match dns::zone(&zone).await {
        Ok(Some(z)) => z,
        Ok(None) => return not_found("No such zone"),
        Err(e) => return pdns_failed(e),
    };
    // Everything not in the template goes, the SOA stays (its serial keeps
    // counting up), and the template's sets replace what was there.
    let mut changes: Vec<Value> = existing["rrsets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|set| set["type"] != "SOA")
        .filter(|set| {
            !fresh
                .iter()
                .any(|f| f["name"] == set["name"] && f["type"] == set["type"])
        })
        .map(|set| json!({"name": set["name"], "type": set["type"], "changetype": "DELETE"}))
        .collect();
    changes.extend(fresh.into_iter().filter(|f| f["type"] != "SOA"));
    if let Err(e) = dns::patch_zone(&zone, changes).await {
        return bad_request(&e.0);
    }
    super::packages::audit_action_detail(&state, &parts, current.user.id, "dns_zone_reset", &zone, "")
        .await;
    zone_response(&state, &current, &zone).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_is_checked_and_put_in_powerdns_form() {
        let change = json!({"name": "www", "type": "a", "ttl": 300, "records": ["192.0.2.1", "192.0.2.1"]});
        let out = rrset_change(&change, "example.com", false, 3600).unwrap();
        assert_eq!(out["name"], "www.example.com.");
        assert_eq!(out["type"], "A");
        assert_eq!(out["ttl"], 300);
        assert_eq!(out["changetype"], "REPLACE");
        assert_eq!(out["records"].as_array().unwrap().len(), 1);

        let delete = json!({"name": "old", "type": "TXT", "records": []});
        assert_eq!(rrset_change(&delete, "example.com", false, 3600).unwrap()["changetype"], "DELETE");
    }

    #[test]
    fn a_customer_cannot_touch_the_zones_nameservers_or_its_soa() {
        let ns = json!({"name": "@", "type": "NS", "records": ["ns.example.net"]});
        assert!(rrset_change(&ns, "example.com", false, 3600).is_err());
        assert!(rrset_change(&ns, "example.com", true, 3600).is_ok());
        // A delegation below the zone is theirs.
        let sub = json!({"name": "lab", "type": "NS", "records": ["ns.example.net"]});
        assert!(rrset_change(&sub, "example.com", false, 3600).is_ok());
        let soa = json!({"name": "@", "type": "SOA", "records": ["x"]});
        assert!(rrset_change(&soa, "example.com", true, 3600).is_err());
        let gone = json!({"name": "@", "type": "NS", "records": []});
        assert!(rrset_change(&gone, "example.com", true, 3600).is_err());
    }

    #[test]
    fn cname_rules_and_ttl_bounds_hold() {
        let apex = json!({"name": "@", "type": "CNAME", "records": ["x.example.net"]});
        assert!(rrset_change(&apex, "example.com", true, 3600).is_err());
        let two = json!({"name": "w", "type": "CNAME", "records": ["a.example.net", "b.example.net"]});
        assert!(rrset_change(&two, "example.com", true, 3600).is_err());
        let low = json!({"name": "w", "type": "A", "ttl": 5, "records": ["192.0.2.1"]});
        assert!(rrset_change(&low, "example.com", true, 3600).is_err());
        let default = json!({"name": "w", "type": "A", "records": ["192.0.2.1"]});
        assert_eq!(rrset_change(&default, "example.com", true, 1800).unwrap()["ttl"], 1800);
    }
}
