//! `/api/reseller/brand` - not in the Python: a reseller's white label.
//!
//! The name and logo its customers see in the panel, and the hostname they
//! sign in at. The hostname has to be one of the reseller's own website
//! domains or aliases: the reseller controls its DNS, and the certificate
//! the site has is the one the panel serves for it (every live certificate
//! is copied to the panel's SNI store).

use axum::extract::{FromRequest, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, internal_error, not_enough_permissions};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/reseller/brand", get(read).put(save).fallback(crate::fallback))
        .route(
            "/reseller/brand/logo",
            post(upload_logo).delete(remove_logo).fallback(crate::fallback),
        )
}

fn reseller_only(current: &CurrentUser) -> Result<(), Response> {
    if permissions::is_reseller_role(&current.user.role) {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

fn db_failed(e: impl std::fmt::Display) -> Response {
    tracing::error!("reseller brand: {e}");
    internal_error()
}

/// The reseller's own domains: its websites and their aliases.
async fn own_domains(state: &AppState, user_id: i64) -> Vec<String> {
    crate::mail::domains(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|d| d.owner_id == user_id)
        .map(|d| d.name)
        .collect()
}

async fn page(state: &AppState, user_id: i64) -> Result<Value, Response> {
    let brand = state.db.resellers().brand(user_id).await.map_err(db_failed)?.unwrap_or_default();
    let fields = crate::resellers::brand_fields(&brand);
    let domains = own_domains(state, user_id).await;
    let certified: Vec<&String> = domains
        .iter()
        .filter(|d| std::path::Path::new(crate::tls::DEFAULT_SNI_DIR).join(d.as_str()).is_dir())
        .collect();
    Ok(json!({
        "app_name": brand.app_name,
        "logo_url": fields["logo_url"],
        "panel_host": brand.panel_host,
        "panel_url": brand.panel_host.as_ref().map(|h| format!("https://{h}:{}", state.settings.panel_port.get())),
        "domains": domains,
        "domains_with_certificate": certified,
    }))
}

async fn read(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = reseller_only(&current) {
        return r;
    }
    match page(&state, current.user.id).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}

async fn save(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = reseller_only(&current) {
        return r;
    }
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let repo = state.db.resellers();
    let mut brand = match repo.brand(current.user.id).await {
        Ok(b) => b.unwrap_or(snpanel_db::ResellerBrand { user_id: current.user.id, ..Default::default() }),
        Err(e) => return db_failed(e),
    };
    if let Some(raw) = body.get("app_name").filter(|v| !v.is_null()) {
        let Some(name) = raw.as_str() else {
            return crate::errors::string_type("app_name", raw);
        };
        let name = name.trim();
        if name.chars().count() > 60 || name.chars().any(char::is_control) {
            return error(StatusCode::UNPROCESSABLE_ENTITY, "The name is at most 60 characters");
        }
        brand.app_name = name.to_string();
    }
    if let Some(raw) = body.get("panel_host") {
        let host = raw.as_str().map(crate::tls::normalize_hostname).filter(|h| !h.is_empty());
        if let Some(host) = &host {
            if !own_domains(&state, current.user.id).await.contains(host) {
                return bad_request("The panel hostname has to be one of your own website domains");
            }
            match repo.brand_by_host(host).await {
                Ok(Some(other)) if other.user_id != current.user.id => {
                    return error(StatusCode::CONFLICT, "Another reseller uses this hostname");
                }
                Ok(_) => {}
                Err(e) => return db_failed(e),
            }
        }
        brand.panel_host = host;
    }
    if let Err(e) = repo.save_brand(&brand).await {
        return db_failed(e);
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "reseller_brand",
        &current.user.username,
        brand.panel_host.as_deref().unwrap_or(""),
    )
    .await;
    match page(&state, current.user.id).await {
        Ok(mut v) => {
            v["message"] = json!("Brand saved.");
            axum::Json(v).into_response()
        }
        Err(r) => r,
    }
}

async fn upload_logo(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = reseller_only(&current) {
        return r;
    }
    let request = Request::from_parts(parts.clone(), body);
    let mut multipart = match axum::extract::Multipart::from_request(request, &state).await {
        Ok(m) => m,
        Err(e) => return bad_request(&e.body_text()),
    };
    let mut content: Option<Vec<u8>> = None;
    let mut filename = String::new();
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                if field.name() != Some("file") {
                    continue;
                }
                filename = field.file_name().unwrap_or_default().to_string();
                match field.bytes().await {
                    Ok(bytes) => content = Some(bytes.to_vec()),
                    Err(e) => return bad_request(&e.body_text()),
                }
            }
            Ok(None) => break,
            Err(e) => return bad_request(&e.body_text()),
        }
    }
    let Some(content) = content else {
        return crate::errors::missing_field("file", Value::Null);
    };
    if content.len() > 1024 * 1024 {
        return bad_request("Image must be 1 MB or smaller");
    }
    let ext = match super::panel_settings::detect_asset_type(&content, &filename) {
        Ok(e) => e,
        Err(m) => return bad_request(&m),
    };
    let dir = std::path::PathBuf::from(std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()))
        .join("assets");
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return db_failed(e);
    }
    let repo = state.db.resellers();
    let mut brand = match repo.brand(current.user.id).await {
        Ok(b) => b.unwrap_or(snpanel_db::ResellerBrand { user_id: current.user.id, ..Default::default() }),
        Err(e) => return db_failed(e),
    };
    let name = format!("reseller-{}-logo.{ext}", current.user.id);
    if !brand.logo_filename.is_empty() && brand.logo_filename != name {
        let _ = tokio::fs::remove_file(dir.join(&brand.logo_filename)).await;
    }
    if let Err(e) = tokio::fs::write(dir.join(&name), &content).await {
        return db_failed(e);
    }
    brand.logo_filename = name;
    if let Err(e) = repo.save_brand(&brand).await {
        return db_failed(e);
    }
    super::packages::audit_action(&state, &parts, current.user.id, "reseller_brand_logo", &current.user.username).await;
    match page(&state, current.user.id).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}

async fn remove_logo(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = reseller_only(&current) {
        return r;
    }
    let repo = state.db.resellers();
    let Ok(Some(mut brand)) = repo.brand(current.user.id).await else {
        return match page(&state, current.user.id).await {
            Ok(v) => axum::Json(v).into_response(),
            Err(r) => r,
        };
    };
    if !brand.logo_filename.is_empty() {
        let dir = std::path::PathBuf::from(std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()))
            .join("assets");
        let _ = tokio::fs::remove_file(dir.join(&brand.logo_filename)).await;
        brand.logo_filename.clear();
        if let Err(e) = repo.save_brand(&brand).await {
            return db_failed(e);
        }
    }
    match page(&state, current.user.id).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}
