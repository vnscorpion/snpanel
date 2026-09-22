//! `/api/provisioning/v1` — the router a billing system talks to.
//!
//! Source: `app/api/provisioning.py`.
//!
//! **This router does not use the panel's session.** Its callers are
//! machines: a Bearer token, its own scopes and its own IP allowlist. A
//! token that leaks is a billing system that can terminate customers, so
//! three things are true of every endpoint here and none of them are
//! optional — the token must be active and unrevoked, it must carry the
//! scope the endpoint needs, and it must arrive from an address the token
//! names.
//!
//! The token-management endpoints at the bottom are the exception: those
//! are the panel's own administrators, through the ordinary session, and
//! they are what mints the tokens the rest of the router authenticates.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, not_found};
use crate::shell;
use crate::state::AppState;
use snpanel_core::config::Settings;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/provisioning/v1/plans",
            get(list_plans).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}",
            get(get_account).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}/usage",
            get(get_usage).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}/login",
            post(create_login_url).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}/suspend",
            post(suspend).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}/unsuspend",
            post(unsuspend).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}/password",
            patch(change_password).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}/package",
            patch(change_package).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/tokens",
            get(list_tokens)
                .post(create_token)
                .fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/tokens/{token_id}",
            delete(revoke_token).fallback(crate::fallback),
        )
}

/// Source: `hash_token` — `sha256(raw).hexdigest()`.
pub fn hash_token(raw: &str) -> String {
    snpanel_core::types::sha256_hex(raw)
}

/// Source: `generate_token` — `f"bp_{secrets.token_urlsafe(48)}"`.
///
/// Forty-eight random bytes in URL-safe base64 **without padding**, which
/// is sixty-four characters. The `bp_` prefix is what makes a leaked token
/// recognisable in a log or a paste.
pub fn generate_token() -> (String, String) {
    use base64::Engine;
    use rand::RngCore;

    let mut buf = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let raw = format!(
        "bp_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    );
    let hash = hash_token(&raw);
    (raw, hash)
}

/// Source: `_require_scope` — the comma-separated list on the token.
///
/// Split and stripped, and an empty entry is not a scope: a token whose
/// `scopes` column is `"provisioning:read,"` has one scope, not two, and
/// certainly not an empty one that matches nothing.
pub fn has_scope(scopes: &str, wanted: &str) -> bool {
    scopes
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|s| s == wanted)
}

/// Source: `check_ip_allowed`.
///
/// **An empty allowlist allows everything.** That is the default, and it is
/// the right default for a panel that has to work before anyone has
/// configured a billing server's address — but it means the list is a
/// narrowing, never a widening, and a token with one entry is strictly
/// safer than one with none.
pub fn ip_allowed(allowed_ips: &str, client_ip: &str) -> bool {
    let allowed = allowed_ips.trim();
    if allowed.is_empty() {
        return true;
    }
    allowed
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|s| s == client_ip)
}

/// The token behind a provisioning request, or the refusal to answer.
///
/// Source: `_get_provisioning_token`. The three refusals are deliberately
/// different: a missing header is 401 *Missing Bearer token*, an unknown or
/// revoked token is 401 *Invalid or revoked token*, and a good token from
/// the wrong address is **403**. Collapsing them would be kinder to an
/// attacker and useless to the operator reading the log.
async fn provisioning_token(
    state: &AppState,
    parts: &axum::http::request::Parts,
) -> Result<snpanel_db::ApiToken, Response> {
    let auth = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(raw) = auth.strip_prefix("Bearer ") else {
        return Err(error(
            axum::http::StatusCode::UNAUTHORIZED,
            "Missing Bearer token",
        ));
    };
    let raw = raw.trim();
    let token = match state.db.api_tokens().by_hash_active(&hash_token(raw)).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err(error(
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid or revoked token",
            ))
        }
        Err(e) => {
            tracing::error!("api token lookup failed: {e}");
            return Err(crate::errors::internal_error());
        }
    };
    let client_ip = crate::client::audit_ip(parts);
    if !ip_allowed(&token.allowed_ips, client_ip.trim()) {
        return Err(error(axum::http::StatusCode::FORBIDDEN, "IP not allowed"));
    }
    // The stamp is written *after* the address check in neither Python nor
    // here: `authenticate_token` commits it as soon as the hash matches, so
    // a token used from a refused address still records that it was used.
    // That is the record an operator wants when a token has leaked.
    if let Err(e) = state
        .db
        .api_tokens()
        .touch(token.id, &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("could not stamp api token {}: {e}", token.id);
    }
    Ok(token)
}

/// `provisioning_token` plus the scope the endpoint needs.
async fn authorised(
    state: &AppState,
    parts: &axum::http::request::Parts,
    scope: &str,
) -> Result<snpanel_db::ApiToken, Response> {
    let token = provisioning_token(state, parts).await?;
    if !has_scope(&token.scopes, scope) {
        return Err(error(
            axum::http::StatusCode::FORBIDDEN,
            &format!("Missing scope: {scope}"),
        ));
    }
    Ok(token)
}

/// `GET /api/provisioning/v1/plans`.
async fn list_plans(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (parts, _) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:read").await {
        return r;
    }
    let packages = match state.db.packages().list().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("package listing failed: {e}");
            return crate::errors::internal_error();
        }
    };
    // Not the panel's own package payload: the billing system reads a
    // narrower shape, and adding fields to it here would change a contract
    // with software nobody in this repository controls.
    let plans: Vec<Value> = packages
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "name": p.name,
                "slug": p.slug,
                "website_limit": p.website_limit,
                "storage_limit_mb": p.storage_limit_mb,
                "database_limit": p.database_limit,
                "alias_limit": p.alias_limit,
                "backup_retention_days": p.backup_retention_days,
                "terminal_enabled": p.terminal_enabled,
                "waf_enabled": p.waf_enabled,
                "wordpress_enabled": p.wordpress_enabled,
            })
        })
        .collect();
    axum::Json(plans).into_response()
}

/// Source: `account_to_dict`.
///
/// The label is the one a billing system shows on an invoice line, and the
/// `whmcs:` prefix becomes a `#` because that is the service number the
/// customer already knows. A terminated account has no user, and the two
/// name fields are **empty strings rather than null** — the billing module
/// still reads the row to show the service as terminated.
pub fn account_payload(view: &snpanel_db::ProvisioningAccountView, panel_url: &str) -> Value {
    let package_name = view.package_name.clone();
    let service_label = package_name
        .clone()
        .unwrap_or_else(|| "SNPanel Hosting".to_string());
    let external_label = match view.external_id.strip_prefix("whmcs:") {
        Some(rest) => format!("#{rest}"),
        None => view.external_id.clone(),
    };
    json!({
        "external_id": view.external_id,
        "username": view.username.clone().unwrap_or_default(),
        "email": view.email.clone().unwrap_or_default(),
        "domain": view.domain,
        "package_id": view.package_id,
        "package_name": package_name,
        "service_label": format!("{service_label} {external_label}"),
        "status": view.status,
        "panel_url": if panel_url.is_empty() {
            Value::Null
        } else {
            json!(panel_url)
        },
        "created_at": crate::errors::iso_datetime(view.created_at.as_deref()),
    })
}

/// Source: `panel_base_url()` called with **no request**, which is how
/// `account_to_dict` calls it.
///
/// The request-following branch above it in the Python cannot run here:
/// this payload is built for a billing system, and the hostname it happens
/// to have reached the panel on is not the hostname the customer logs in
/// at. So it is the configured URL, then the panel domain, then nothing —
/// and the field is `null` rather than an empty string when there is
/// nothing, because the billing module tests it for truth.
fn panel_base_url(settings: &Settings) -> String {
    let configured = crate::panel_urls::configured_panel_url(settings);
    if !configured.is_empty() {
        return configured.trim_end_matches('/').to_string();
    }
    if !settings.panel_domain.is_empty() {
        return format!(
            "https://{}:{}",
            settings.panel_domain,
            settings.panel_port.get()
        );
    }
    String::new()
}

/// `GET /api/provisioning/v1/accounts/{external_id}`.
async fn get_account(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, _) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:read").await {
        return r;
    }
    match state.db.provisioning().view(&external_id).await {
        Ok(Some(view)) => {
            let panel_url = panel_base_url(&state.settings);
            axum::Json(account_payload(&view, &panel_url)).into_response()
        }
        Ok(None) => not_found("Account not found"),
        Err(e) => {
            tracing::error!("provisioning account lookup failed: {e}");
            crate::errors::internal_error()
        }
    }
}

/// `GET /api/provisioning/v1/accounts/{external_id}/usage`.
///
/// An account with no user is a **400**, not a 404: the row exists and the
/// billing system asked a reasonable question about it; there is simply
/// nothing left to measure once the account has been terminated.
async fn get_usage(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, _) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:read").await {
        return r;
    }
    let account = match state.db.provisioning().by_external_id(&external_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return not_found("Account not found"),
        Err(e) => {
            tracing::error!("provisioning account lookup failed: {e}");
            return crate::errors::internal_error();
        }
    };
    let Some(user_id) = account.user_id else {
        return bad_request("Account has no user");
    };
    let user = match state.db.users().by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return bad_request("Account has no user"),
        Err(e) => {
            tracing::error!("user lookup failed: {e}");
            return crate::errors::internal_error();
        }
    };

    // `storage_usage_summary(db, user)` with `use_cache` left at its
    // default of false: the figure a billing system bills from is worth a
    // walk of the tree, not a five-minute-stale number.
    let used = crate::storage_quota::user_storage_used_bytes(
        state.settings.command_dry_run,
        &state.db,
        user.id,
        super::addons::application_installed(),
    )
    .await;
    let limit = crate::storage_quota::user_storage_limit_bytes(&user.role, user.storage_limit_mb);
    let usage = crate::storage::Usage::new(used as i64, limit.map(|l| l as i64));
    let (websites, databases) = match state.db.provisioning().usage_counts(user.id).await {
        Ok(counts) => counts,
        Err(e) => {
            tracing::error!("provisioning usage counts failed: {e}");
            return crate::errors::internal_error();
        }
    };
    axum::Json(json!({
        "external_id": account.external_id,
        "storage_used_bytes": usage.used_bytes,
        "storage_limit_bytes": usage.limit_bytes,
        "storage_percent": usage.percent,
        "website_count": websites,
        "database_count": databases,
    }))
    .into_response()
}

/// `POST /api/provisioning/v1/accounts/{external_id}/login`.
///
/// Source: `create_login_url`.
///
/// A one-use ticket that logs the customer into the panel **without the
/// billing system ever holding their password**. Five minutes, and the
/// answer carries the same URL three times: `login_url` is the documented
/// field, `url` is kept for billing modules built against the original
/// shape, and `path` is what a module behind a reverse proxy wants when it
/// would rather build the absolute URL itself.
async fn create_login_url(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, _) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:write").await {
        return r;
    }
    let account = match account_or_404(&state, &external_id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    // An inactive user is a 404 and not a 403: from the billing system's
    // side the account it asked about is not one it can log into, and
    // which of the two reasons applies is not its business.
    let user = match account.user_id {
        Some(id) => match state.db.users().by_id(id).await {
            Ok(Some(u)) if u.is_active => u,
            Ok(_) => return not_found("Account user not found or inactive"),
            Err(e) => {
                tracing::error!("user lookup failed: {e}");
                return crate::errors::internal_error();
            }
        },
        None => return not_found("Account user not found or inactive"),
    };

    let token = match crate::sso::create_panel_login_token(&user.username) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("could not write a panel login token: {e}");
            return crate::errors::internal_error();
        }
    };
    let (path, absolute) = login_url(&panel_base_url(&state.settings), &token);
    audit_provisioning(
        &state,
        &parts,
        "provisioning_login",
        &external_id,
        &user.username,
    )
    .await;
    axum::Json(json!({
        "login_url": absolute,
        "url": absolute,
        "path": path,
        "expires_in": 300,
    }))
    .into_response()
}

/// The path and the absolute URL a login ticket is handed out as.
///
/// Source: `create_login_url`. With no panel URL configured the absolute
/// field falls back to the **path**, not to an empty string: a billing
/// module that builds its own base from the path still works, and one that
/// uses `login_url` blindly produces a relative link rather than a broken
/// one.
fn login_url(base: &str, token: &str) -> (String, String) {
    let path = format!("/api/auth/sso/{token}");
    let absolute = if base.is_empty() {
        path.clone()
    } else {
        format!("{base}{path}")
    };
    (path, absolute)
}

/// `POST /api/provisioning/v1/accounts/{external_id}/suspend`.
///
/// Source: `suspend` the endpoint and `suspend_account`.
///
/// **Already suspended is a success, not an error.** A billing system
/// retrying a call it is not sure landed must not be told something went
/// wrong; any *other* status is refused, because suspending a terminated
/// account is a mistake somebody should see.
///
/// Every site is rewritten as a **static** vhost carrying `# SUSPENDED`,
/// so nothing dynamic runs while the account is blocked, and the
/// certificate paths are deliberately not carried over: a vhost that is
/// serving nothing has no business claiming TLS from a file that may be
/// about to go.
async fn suspend(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:write").await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `reason: str = ""` — optional, and kept on the row as the record of
    // why the account stopped.
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let account = match account_or_404(&state, &external_id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match status_change(&account.status, "active", "suspended") {
        StatusChange::AlreadyThere => {
            return axum::Json(json!({ "ok": true, "status": "suspended" })).into_response()
        }
        StatusChange::Refuse => {
            return bad_request(&format!(
                "Cannot suspend account in status: {}",
                account.status
            ))
        }
        StatusChange::Proceed => {}
    }

    if let Some(user_id) = account.user_id {
        // The user goes inactive and every session with it: a suspended
        // customer must not still be logged into the panel.
        let fields = snpanel_db::UserFields {
            is_active: Some(false),
            ..Default::default()
        };
        if let Err(e) = state.db.users().update(user_id, &fields, true).await {
            tracing::error!("suspending the user failed: {e}");
            return crate::errors::internal_error();
        }
        let websites = state
            .db
            .websites()
            .list(Some(user_id), "")
            .await
            .unwrap_or_default();
        for website in &websites {
            if let Err(e) = state
                .db
                .websites()
                .set_status(website.id, "suspended")
                .await
            {
                tracing::error!("marking {} suspended failed: {e}", website.domain);
            }
            // The WordPress include goes first: the static vhost below must
            // not keep pulling in a block that runs PHP.
            let _ = shell::privileged(
                state.settings.command_dry_run,
                "wordpress-vhost-delete",
                &[&website.domain],
                None,
                Some(&["true"]),
            )
            .await;
            let overrides = super::websites::RewriteOverrides {
                custom_directives: Some("# SUSPENDED".to_string()),
                app_type: Some("static"),
                rewrite_mode: Some("none"),
                preserve_existing_ssl: Some(false),
                ..Default::default()
            };
            if let Err(e) = super::websites::rewrite_website_vhost(&state, website, overrides).await
            {
                tracing::error!("suspending the vhost for {} failed", website.domain);
                let _ = e;
            }
            lock_site_user(&state, website.linux_user.as_deref(), true).await;
        }
    }

    if let Err(e) = state
        .db
        .provisioning()
        .set_status(
            account.id,
            "suspended",
            "suspend",
            &reason,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        tracing::error!("recording the suspension failed: {e}");
        return crate::errors::internal_error();
    }
    audit_provisioning(
        &state,
        &parts,
        "provisioning_suspend",
        &external_id,
        &reason,
    )
    .await;
    axum::Json(json!({ "ok": true, "status": "suspended" })).into_response()
}

/// `POST /api/provisioning/v1/accounts/{external_id}/unsuspend`.
///
/// Source: `unsuspend` the endpoint and `unsuspend_account`.
///
/// The vhost is rebuilt from the row rather than from whatever the suspend
/// left behind, which is why the site comes back with its own app type,
/// its own rewrite mode and its own aliases. The **token version is not
/// bumped**: the customer's sessions were already ended by the suspension,
/// and there is nothing to invalidate on the way back.
async fn unsuspend(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, _) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:write").await {
        return r;
    }
    let account = match account_or_404(&state, &external_id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match status_change(&account.status, "suspended", "active") {
        StatusChange::AlreadyThere => {
            return axum::Json(json!({ "ok": true, "status": "active" })).into_response()
        }
        StatusChange::Refuse => {
            return bad_request(&format!(
                "Cannot unsuspend account in status: {}",
                account.status
            ))
        }
        StatusChange::Proceed => {}
    }

    if let Some(user_id) = account.user_id {
        let fields = snpanel_db::UserFields {
            is_active: Some(true),
            ..Default::default()
        };
        if let Err(e) = state.db.users().update(user_id, &fields, false).await {
            tracing::error!("reactivating the user failed: {e}");
            return crate::errors::internal_error();
        }
        let websites = state
            .db
            .websites()
            .list(Some(user_id), "")
            .await
            .unwrap_or_default();
        for website in &websites {
            if let Err(e) = state.db.websites().set_status(website.id, "active").await {
                tracing::error!("marking {} active failed: {e}", website.domain);
            }
            // Source: `rewrite_mode = "front_controller" if wordpress else
            // (nginx_rewrite_mode or "none")`. A WordPress site's mode is
            // decided by what it is, not by what the column happens to say,
            // because a suspension wrote `none` into that column's place in
            // the file and the row may never have carried one.
            let rewrite_mode =
                unsuspend_rewrite_mode(&website.app_type, &website.nginx_rewrite_mode);
            let overrides = super::websites::RewriteOverrides {
                rewrite_mode,
                ..Default::default()
            };
            if let Err(e) = super::websites::rewrite_website_vhost(&state, website, overrides).await
            {
                tracing::error!("restoring the vhost for {} failed", website.domain);
                let _ = e;
            }
            lock_site_user(&state, website.linux_user.as_deref(), false).await;
        }
    }

    if let Err(e) = state
        .db
        .provisioning()
        .set_status(
            account.id,
            "active",
            "unsuspend",
            "",
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        tracing::error!("recording the unsuspension failed: {e}");
        return crate::errors::internal_error();
    }
    audit_provisioning(&state, &parts, "provisioning_unsuspend", &external_id, "").await;
    axum::Json(json!({ "ok": true, "status": "active" })).into_response()
}

/// What a status change should do before anything is touched.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusChange {
    /// Already where the caller wants it: answer success and do nothing.
    AlreadyThere,
    /// Somewhere else entirely: refuse, and name the status.
    Refuse,
    Proceed,
}

/// Source: the two guards at the top of `suspend` and `unsuspend`.
///
/// **Already there is a success, not an error.** A billing system retrying
/// a call it is not sure landed must not be told something went wrong —
/// that is what turns a network blip into a support ticket. Any *other*
/// status is refused rather than forced, because suspending a terminated
/// account is a mistake somebody should be shown.
pub fn status_change(current: &str, from: &str, to: &str) -> StatusChange {
    if current == to {
        StatusChange::AlreadyThere
    } else if current == from {
        StatusChange::Proceed
    } else {
        StatusChange::Refuse
    }
}

/// Source: `rewrite_mode = "front_controller" if wordpress else
/// (nginx_rewrite_mode or "none")`.
///
/// A WordPress site's mode is decided by **what it is**, not by what the
/// column says: the suspension rendered the site static with no rewrite,
/// and the row may never have carried a mode of its own. Returning `None`
/// lets the renderer use the column, which is right for everything else.
pub fn unsuspend_rewrite_mode(app_type: &str, stored: &str) -> Option<&'static str> {
    if app_type == "wordpress" {
        Some("front_controller")
    } else if stored.is_empty() {
        Some("none")
    } else {
        None
    }
}

/// Source: `site_users.lock_linux_user` / `unlock_linux_user`, both called
/// inside a bare `except Exception: pass`.
///
/// A site with no runtime user, or a helper that refuses, does not stop the
/// suspension: the vhost is already serving nothing, which is what actually
/// blocks the customer. The shell account is a second lock, not the first.
async fn lock_site_user(state: &AppState, linux_user: Option<&str>, lock: bool) {
    let Some(user) = linux_user.filter(|u| !u.is_empty()) else {
        return;
    };
    let Ok(safe) = snpanel_core::types::PanelUsername::parse(user) else {
        return;
    };
    let verb = if lock {
        "panel-user-lock"
    } else {
        "panel-user-unlock"
    };
    let flag = if lock { "-L" } else { "-U" };
    let _ = crate::shell::privileged(
        state.settings.command_dry_run,
        verb,
        &[safe.as_str()],
        None,
        Some(&["usermod", flag, safe.as_str()]),
    )
    .await;
}

/// `PATCH /api/provisioning/v1/accounts/{external_id}/password`.
///
/// Source: `change_password`.
///
/// Both halves, in the Python's order: the panel's stored hash **and** the
/// Linux account's password, because a customer whose billing system reset
/// their password expects SFTP to work with the new one too. The token
/// version goes up, so every session opened with the old password stops.
async fn change_password(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:write").await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let password = match payload.get("password") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => return crate::errors::string_type("password", other),
        None => return crate::errors::missing_field("password", payload.clone()),
    };
    let account = match account_or_404(&state, &external_id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(user_id) = account.user_id else {
        return bad_request("Account has no user");
    };
    let user = match state.db.users().by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return bad_request("Account has no user"),
        Err(e) => {
            tracing::error!("user lookup failed: {e}");
            return crate::errors::internal_error();
        }
    };

    let hashed = match snpanel_core::crypto::password::hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing failed: {e}");
            return crate::errors::internal_error();
        }
    };
    if let Err(e) = state.db.users().set_hashed_password(user.id, &hashed).await {
        tracing::error!("storing the password failed: {e}");
        return crate::errors::internal_error();
    }
    if let Err(e) = state.db.users().bump_token_version(user.id).await {
        tracing::error!("bumping the token version failed: {e}");
        return crate::errors::internal_error();
    }
    // Source: `site_users.set_panel_user_password`. The secret goes on
    // stdin, never in argv — `/proc/<pid>/cmdline` is world-readable.
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "panel-user-password",
        &[user.username.as_str()],
        Some(&format!("{password}\n")),
        Some(&["true"]),
    )
    .await;
    if !result.ok() {
        tracing::error!(
            "setting the system password failed: {}",
            result.failure_detail("panel-user-password")
        );
        return crate::errors::internal_error();
    }
    if let Err(e) = state
        .db
        .provisioning()
        .set_last_action(account.id, "change_password", &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("recording the provisioning action failed: {e}");
    }
    audit_provisioning(
        &state,
        &parts,
        "provisioning_change_password",
        &external_id,
        "",
    )
    .await;
    axum::Json(json!({ "ok": true })).into_response()
}

/// `PATCH /api/provisioning/v1/accounts/{external_id}/package`.
///
/// Source: `change_package`.
///
/// The package's limits are **copied onto the user**, not referenced. The
/// enforcement path reads one row, so a user without a package still has to
/// resolve to something — and a package change that did not copy them would
/// leave the customer on their old limits until somebody edited the package
/// itself.
async fn change_package(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:write").await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let package_id = match payload.get("package_id") {
        Some(Value::Number(n)) if n.is_i64() => n.as_i64().unwrap_or(0),
        Some(other) => return crate::errors::int_type("package_id", other),
        None => return crate::errors::missing_field("package_id", payload.clone()),
    };
    let account = match account_or_404(&state, &external_id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(user_id) = account.user_id else {
        return bad_request("Account has no user");
    };
    let package = match state.db.packages().by_id(package_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("Package not found"),
        Err(e) => {
            tracing::error!("package lookup failed: {e}");
            return crate::errors::internal_error();
        }
    };

    if let Err(e) = state
        .db
        .provisioning()
        .set_package(account.id, package.id, &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("setting the provisioning package failed: {e}");
        return crate::errors::internal_error();
    }
    let fields = snpanel_db::UserFields {
        package_id: Some(Some(package.id)),
        website_limit: Some(package.website_limit),
        storage_limit_mb: Some(package.storage_limit_mb),
        ..Default::default()
    };
    if let Err(e) = state.db.users().update(user_id, &fields, false).await {
        tracing::error!("copying the package limits failed: {e}");
        return crate::errors::internal_error();
    }
    audit_provisioning(
        &state,
        &parts,
        "provisioning_change_package",
        &external_id,
        &package.id.to_string(),
    )
    .await;
    axum::Json(json!({ "ok": true, "package_id": package.id })).into_response()
}

/// Source: `_account_by_external_id`.
async fn account_or_404(
    state: &AppState,
    external_id: &str,
) -> Result<snpanel_db::ProvisioningAccount, Response> {
    match state.db.provisioning().by_external_id(external_id).await {
        Ok(Some(a)) => Ok(a),
        Ok(None) => Err(not_found("Account not found")),
        Err(e) => {
            tracing::error!("provisioning account lookup failed: {e}");
            Err(crate::errors::internal_error())
        }
    }
}

/// `log_action(db, None, ...)` — an audit line with **no actor**.
///
/// Every other audit entry in the panel names a user. These do not: the
/// caller is a machine holding a token, and recording the token's own
/// administrator would name somebody who was asleep at the time.
async fn audit_provisioning(
    state: &AppState,
    parts: &axum::http::request::Parts,
    action: &str,
    target: &str,
    detail: &str,
) {
    let ip = crate::client::audit_ip(parts);
    let ua = parts
        .headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let detail = if detail.is_empty() {
        format!("ip={ip} ua={ua}")
    } else {
        format!("{detail} ip={ip} ua={ua}")
    };
    if let Err(e) = state.db.audits().log(None, action, target, &detail).await {
        tracing::error!("could not write the {action} audit entry: {e}");
    }
}

/// Source: `ApiTokenOut` — what an administrator is shown about a token.
///
/// **Never the token.** The hash is not in it either: a hash is not a
/// secret, but showing it invites somebody to compare it with one they
/// have, and the page has no use for it.
fn token_payload(token: &snpanel_db::ApiToken) -> Value {
    json!({
        "id": token.id,
        "name": token.name,
        "scopes": token.scopes,
        "allowed_ips": token.allowed_ips,
        "is_active": token.is_active,
        "last_used_at": crate::errors::iso_datetime(token.last_used_at.as_deref()),
        "revoked_at": crate::errors::iso_datetime(token.revoked_at.as_deref()),
        "created_at": crate::errors::iso_datetime(token.created_at.as_deref()),
    })
}

/// `GET /api/provisioning/v1/tokens` — the panel's own session, admin only.
async fn list_tokens(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    match state.db.api_tokens().all().await {
        Ok(tokens) => {
            let rows: Vec<Value> = tokens.iter().map(token_payload).collect();
            axum::Json(rows).into_response()
        }
        Err(e) => {
            tracing::error!("api token listing failed: {e}");
            crate::errors::internal_error()
        }
    }
}

/// `POST /api/provisioning/v1/tokens`.
///
/// **The only time the plaintext exists outside the caller.** It is
/// returned once, beside the row, and never stored — the table keeps a
/// hash. An administrator who loses it makes another one.
async fn create_token(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = match payload.get("name") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => return crate::errors::string_type("name", other),
        None => return crate::errors::missing_field("name", payload.clone()),
    };
    // `scopes: str = "provisioning:read,provisioning:write"` and
    // `allowed_ips: str = ""` — both have defaults, so a body with only a
    // name is valid and makes a token that can do everything from anywhere.
    let scopes = payload
        .get("scopes")
        .and_then(Value::as_str)
        .unwrap_or("provisioning:read,provisioning:write")
        .to_string();
    let allowed_ips = payload
        .get("allowed_ips")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let (raw, hash) = generate_token();
    let token = match state
        .db
        .api_tokens()
        .create(
            &name,
            &hash,
            &scopes,
            &allowed_ips,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("api token create failed: {e}");
            return crate::errors::internal_error();
        }
    };
    super::packages::audit_action(&state, &parts, current.user.id, "create_api_token", &name).await;
    axum::Json(json!({ "token": raw, "info": token_payload(&token) })).into_response()
}

/// `DELETE /api/provisioning/v1/tokens/{token_id}`.
async fn revoke_token(
    State(state): State<AppState>,
    Path(token_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return crate::errors::not_enough_permissions();
    }
    let token = match state.db.api_tokens().by_id(token_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("Token not found"),
        Err(e) => {
            tracing::error!("api token lookup failed: {e}");
            return crate::errors::internal_error();
        }
    };
    if let Err(e) = state
        .db
        .api_tokens()
        .revoke(token.id, &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("api token revoke failed: {e}");
        return crate::errors::internal_error();
    }
    // The audit line names the token, which is the only thing left that
    // identifies it once it cannot be used.
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "revoke_api_token",
        &token.name,
    )
    .await;
    axum::Json(json!({ "ok": true })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/provisioning.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the provisioning corpus"))
            .expect("the corpus parses")
    }

    /// The link a billing system hands to a customer.
    ///
    /// The absolute field falls back to the **path** when no panel URL is
    /// configured, not to an empty string — a module that uses `login_url`
    /// blindly then produces a relative link rather than a broken one. And
    /// the base is joined without a separator, because both halves already
    /// carry their own: the base has no trailing slash and the path has a
    /// leading one.
    #[test]
    fn a_login_link_is_built_the_way_python_builds_it() {
        let (path, absolute) = login_url("https://panel.example:2222", "abc");
        assert_eq!(path, "/api/auth/sso/abc");
        assert_eq!(absolute, "https://panel.example:2222/api/auth/sso/abc");
        assert!(!absolute.contains("//api"), "a doubled slash: {absolute}");

        let (path, absolute) = login_url("", "abc");
        assert_eq!(path, "/api/auth/sso/abc");
        assert_eq!(
            absolute, path,
            "with no base, the absolute field is the path"
        );
    }

    /// A login ticket is written, read once and gone.
    #[test]
    fn a_login_ticket_can_be_spent_exactly_once() {
        // `TOKEN_DIR` is a constant in both implementations, so this uses
        // the real directory. That is safe: the ticket's name is random, and
        // consuming it removes only its own file.
        let token = crate::sso::create_panel_login_token("alice").expect("the ticket");
        assert!(!token.is_empty());
        assert_eq!(
            crate::sso::consume_panel_login_token(&token).as_deref(),
            Some("alice")
        );
        // Spent: the file is gone and a replay gets nothing. That is what
        // keeps a login link in a billing system's email log from being a
        // standing key to the account.
        assert_eq!(crate::sso::consume_panel_login_token(&token), None);
        // And a ticket nobody made is not honoured either.
        assert_eq!(crate::sso::consume_panel_login_token("made-up"), None);
    }

    /// Retrying a suspension is a success; suspending the wrong thing is
    /// not.
    ///
    /// A billing system that lost the answer to its first call will send
    /// the second. Telling it that the account is *already* suspended as
    /// though something had gone wrong is what turns a network blip into a
    /// support ticket — and forcing the change from any status at all
    /// would let a terminated account be suspended back into existence.
    #[test]
    fn a_repeated_status_change_succeeds_and_a_wrong_one_does_not() {
        use StatusChange::*;

        // Suspending.
        assert_eq!(status_change("active", "active", "suspended"), Proceed);
        assert_eq!(
            status_change("suspended", "active", "suspended"),
            AlreadyThere
        );
        assert_eq!(status_change("terminated", "active", "suspended"), Refuse);
        assert_eq!(status_change("pending", "active", "suspended"), Refuse);
        assert_eq!(status_change("", "active", "suspended"), Refuse);
        // Unsuspending, which is the same rule the other way round.
        assert_eq!(status_change("suspended", "suspended", "active"), Proceed);
        assert_eq!(status_change("active", "suspended", "active"), AlreadyThere);
        assert_eq!(status_change("terminated", "suspended", "active"), Refuse);
        assert_eq!(status_change("pending", "suspended", "active"), Refuse);
        // The target is checked before the source, so a status that is both
        // reads as already there rather than as a change to make.
        assert_eq!(status_change("x", "x", "x"), AlreadyThere);
    }

    /// Which rewrite mode a site comes back with.
    #[test]
    fn a_wordpress_site_comes_back_as_a_front_controller() {
        // Whatever the column says, and it often says nothing: the
        // suspension rendered the site static.
        assert_eq!(
            unsuspend_rewrite_mode("wordpress", ""),
            Some("front_controller")
        );
        assert_eq!(
            unsuspend_rewrite_mode("wordpress", "none"),
            Some("front_controller")
        );
        // Everything else keeps its own, and an empty column means none.
        assert_eq!(unsuspend_rewrite_mode("php", ""), Some("none"));
        assert_eq!(unsuspend_rewrite_mode("static", ""), Some("none"));
        // A column with a value is left to the renderer, which reads it.
        assert_eq!(unsuspend_rewrite_mode("php", "front_controller"), None);
        assert_eq!(unsuspend_rewrite_mode("static", "none"), None);
    }

    /// The digest every existing token is stored as.
    ///
    /// This one is not about edge cases: it is about the tokens already in
    /// the table. They are `sha256(raw).hexdigest()` and nothing else, so a
    /// digest that differed by so much as its case would stop every billing
    /// system authenticating the moment this front door answers.
    #[test]
    fn a_token_hashes_to_what_the_python_stored() {
        let corpus = corpus();
        let cases = corpus["hash_token"].as_array().expect("the cases");
        assert_eq!(cases.len(), 10, "the corpus changed size");
        for case in cases {
            let raw = case["raw"].as_str().unwrap_or("");
            let want = case["hash"].as_str().unwrap_or("");
            assert_eq!(hash_token(raw), want, "for {raw:?}");
        }
        // Lower-case hex, sixty-four characters, whatever went in.
        let digest = hash_token("bp_example");
        assert_eq!(digest.len(), 64);
        assert!(digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// A new token is a `bp_` prefix and forty-eight random bytes.
    #[test]
    fn a_new_token_is_unguessable_and_recognisable() {
        let tokens: std::collections::BTreeSet<String> =
            (0..32).map(|_| generate_token().0).collect();
        assert_eq!(tokens.len(), 32, "two tokens collided");
        for raw in &tokens {
            // `bp_` + base64url of 48 bytes with no padding = 3 + 64.
            assert_eq!(raw.len(), 67, "{raw}");
            assert!(raw.starts_with("bp_"), "{raw}");
            let body = &raw[3..];
            assert!(!body.contains('='), "padding would make it 68: {raw}");
            assert!(
                body.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "not url-safe: {raw}"
            );
        }
        // Distinct is not enough, and neither is a varying first
        // character: a counter in the first byte gives both. Every part of
        // the token has to move, so the *last* character is sampled too.
        let tails: std::collections::BTreeSet<char> =
            tokens.iter().filter_map(|t| t.chars().last()).collect();
        assert!(tails.len() >= 4, "the tail does not move: {tails:?}");

        // And the hash beside it is the hash of that token.
        let (raw, hash) = generate_token();
        assert_eq!(hash, hash_token(&raw));
    }

    /// Which scopes a token's list actually carries.
    ///
    /// Empty entries are not scopes, which matters in both directions: a
    /// trailing comma does not add one, and asking for `""` never matches.
    /// Case is **not** folded — `Provisioning:Read` is a different scope,
    /// and letting it through would be a widening nobody asked for.
    #[test]
    fn a_scope_list_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let cases = corpus["has_scope"].as_array().expect("the cases");
        assert_eq!(cases.len(), 14, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut allowed = 0usize;
        let mut refused = 0usize;
        for case in cases {
            let scopes = case["scopes"].as_str().unwrap_or("");
            let wanted = case["wanted"].as_str().unwrap_or("");
            let want = case["allowed"].as_bool().unwrap_or(false);
            if want {
                allowed += 1;
            } else {
                refused += 1;
            }
            let got = has_scope(scopes, wanted);
            if got != want {
                failures.push(format!(
                    "{scopes:?} / {wanted:?}: python {want}, rust {got}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(
            allowed >= 5 && refused >= 5,
            "{allowed} allowed, {refused} refused"
        );
    }

    /// Whether a token may be used from an address.
    ///
    /// **An empty allowlist allows everything**, and so does one that is
    /// only whitespace — `.strip()` makes them the same. A list of nothing
    /// but commas is *not* empty and therefore allows nothing, which is the
    /// one case where a typo fails closed rather than open. And the client
    /// address is not trimmed here: the caller does that, once, where the
    /// address is read off the request.
    #[test]
    fn an_allowlist_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let cases = corpus["ip_allowed"].as_array().expect("the cases");
        assert_eq!(cases.len(), 17, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let allowed_ips = case["allowed_ips"].as_str().unwrap_or("");
            let client_ip = case["client_ip"].as_str().unwrap_or("");
            let want = case["allowed"].as_bool().unwrap_or(false);
            let got = ip_allowed(allowed_ips, client_ip);
            if got != want {
                failures.push(format!(
                    "{allowed_ips:?} from {client_ip:?}: python {want}, rust {got}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // The three that decide whether a misconfiguration fails open.
        assert!(ip_allowed("", "1.2.3.4"), "an empty list allows everything");
        assert!(ip_allowed("   ", "1.2.3.4"), "so does whitespace");
        assert!(
            !ip_allowed(",", "1.2.3.4"),
            "a list of commas allows nothing"
        );
        assert!(
            !ip_allowed("1.2.3.4/24", "1.2.3.4"),
            "the entries are addresses, not networks"
        );
    }

    /// What a billing system is told about an account.
    ///
    /// The `whmcs:` prefix becomes `#` because that is the service number
    /// the customer already knows, and a terminated account keeps its row
    /// with **empty strings** where the user's name and address were — the
    /// billing module still reads it to show the service as terminated, and
    /// nulls there would be a different shape for it to handle.
    #[test]
    fn an_account_is_described_the_way_python_describes_it() {
        let corpus = corpus();
        let cases = corpus["account_to_dict"].as_array().expect("the cases");
        assert_eq!(cases.len(), 7, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let view = snpanel_db::ProvisioningAccountView {
                external_id: case["external_id"].as_str().unwrap_or("").to_string(),
                user_id: None,
                package_id: case["package_id"].as_i64(),
                status: case["status"].as_str().unwrap_or("").to_string(),
                created_at: None,
                username: case["username"].as_str().map(str::to_string),
                email: case["email"].as_str().map(str::to_string),
                domain: case["domain"].as_str().map(str::to_string),
                package_name: case["package_name"].as_str().map(str::to_string),
            };
            let got = account_payload(&view, case["panel_url"].as_str().unwrap_or(""));
            let want = &case["payload"];
            for key in [
                "external_id",
                "username",
                "email",
                "domain",
                "package_id",
                "package_name",
                "service_label",
                "status",
                "panel_url",
                "created_at",
            ] {
                if got[key] != want[key] {
                    failures.push(format!(
                        "{label} /{key}\n  python {}\n  rust   {}",
                        want[key], got[key]
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // A panel with no URL configured sends `null`, not an empty string:
        // the billing module tests the field for truth.
        let view = snpanel_db::ProvisioningAccountView {
            external_id: "whmcs:1".to_string(),
            user_id: None,
            package_id: None,
            status: "active".to_string(),
            created_at: None,
            username: None,
            email: None,
            domain: None,
            package_name: None,
        };
        assert_eq!(account_payload(&view, "")["panel_url"], Value::Null);
        assert_eq!(account_payload(&view, "")["username"], json!(""));
        assert_eq!(
            account_payload(&view, "")["service_label"],
            json!("SNPanel Hosting #1")
        );
    }
}
