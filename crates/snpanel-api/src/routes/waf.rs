//! `/api/waf` - ported from `api/waf.py`.
//!
//! Everything except reading the access logs, which needs the log parser and
//! the GeoIP table the Python builds on a background thread - the same shape
//! as `malware`, where the line count is a poor measure of the work. Clearing
//! them is here; reading them is not.
//!
//! The note here used to say the per-site rules belonged to a surface Phase 2
//! had not finished. [`crate::waf`] renders them now.
//!
//! `/rules` is worth porting on its own account: it is what the WAF page opens
//! with, and it is three helper calls plus a catalogue the panel holds in
//! code. That catalogue now lives in [`crate::waf`] with the rule bodies
//! beside it, generated from the Python's own `DEFAULT_RULES` rather than
//! retyped - eight entries of prose that go straight into an API response,
//! where a typo is a difference nobody would ever notice by reading.

use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};

use crate::auth::CurrentUser;
use crate::errors::{bad_request, not_enough_permissions};
use crate::shell;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/waf/status", get(status).fallback(crate::fallback))
        .route("/waf/rules", get(rules).fallback(crate::fallback))
        .route(
            "/waf/websites/{website_id}",
            get(website_waf)
                .put(save_website_waf)
                .fallback(crate::fallback),
        )
        .route(
            "/waf/bots",
            get(list_blocked_bots).fallback(crate::fallback),
        )
        .route(
            "/waf/bots/global",
            axum::routing::put(save_global_bots).fallback(crate::fallback),
        )
        .route(
            "/waf/bots/apply",
            axum::routing::post(apply_blocked_bots).fallback(crate::fallback),
        )
        .route(
            "/waf/websites/{website_id}/bots",
            axum::routing::put(save_website_bots).fallback(crate::fallback),
        )
        .route(
            "/waf/rules/custom",
            axum::routing::put(save_custom_rules).fallback(crate::fallback),
        )
        .route(
            "/waf/install",
            axum::routing::post(install_engine).fallback(crate::fallback),
        )
        .route(
            "/waf/update-rules",
            axum::routing::post(update_rules).fallback(crate::fallback),
        )
        .route(
            "/waf/crs",
            get(get_crs).put(set_crs).fallback(crate::fallback),
        )
        .route(
            "/waf/websites/{website_id}/crs",
            axum::routing::put(set_website_crs).fallback(crate::fallback),
        )
        .route("/waf/orphans", get(scan_orphans).fallback(crate::fallback))
        .route(
            "/waf/orphans/clean",
            axum::routing::post(clean_orphans).fallback(crate::fallback),
        )
        .route(
            "/waf/access-logs",
            get(access_logs)
                .delete(clear_access_logs)
                .fallback(crate::fallback),
        )
}

fn require_admin(current: &CurrentUser) -> Result<(), Response> {
    if permissions::has_role(&current.user.role, Role::Admin) {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

async fn status(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }
    axum::Json(waf_status(&state).await.to_json()).into_response()
}

async fn waf_status(state: &AppState) -> shell::CommandResult {
    shell::privileged(
        state.settings.command_dry_run,
        "waf-status",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "test -f /etc/nginx/modsec/snpanel-base.conf && echo installed || echo not-installed",
        ]),
    )
    .await
}

async fn rules(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current) {
        return r;
    }

    // Three helper calls, in the Python's order.
    let status = waf_status(&state).await;
    let default_rules = shell::privileged(
        state.settings.command_dry_run,
        "waf-default-rules",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "cat /etc/nginx/modsec/snpanel-default.conf 2>/dev/null || true",
        ]),
    )
    .await;
    let custom_rules = shell::privileged(
        state.settings.command_dry_run,
        "waf-custom-rules",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "cat /etc/nginx/modsec/snpanel-custom.conf 2>/dev/null || true",
        ]),
    )
    .await;

    axum::Json(json!({
        "status": status.to_json(),
        // Only `stdout` - the rule bodies, not the command result around them.
        "default_rules": default_rules.stdout,
        "default_rule_definitions": rule_definitions(),
        "custom_rules": custom_rules.stdout,
    }))
    .into_response()
}

/// Source: `waf.default_rule_definitions()` - the identifying fields only,
/// never the rule bodies.
///
/// Projected from [`crate::waf::DEFAULT_RULES`], which is the one table. This
/// module used to keep a second four-field copy for exactly this response,
/// and two catalogues of the same eight rules is a drift waiting to happen -
/// the kind where the WAF page names a rule the renderer no longer writes.
fn rule_definitions() -> Vec<Value> {
    crate::waf::DEFAULT_RULES
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "category": rule.category,
                "title": rule.title,
                "description": rule.description,
                // Always true: the projection hard-codes it, because these are
                // the rules a site gets unless it turns one off.
                "enabled_default": true,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// one site's rule selection
// ---------------------------------------------------------------------------

/// Source: `panel_settings._read_raw()` - the settings file, unadorned.
fn raw_panel_settings() -> Value {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into());
    std::fs::read_to_string(std::path::Path::new(&dir).join("panel-settings.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

/// Source: `panel_settings.crs_mode()`.
pub(super) fn server_crs_mode() -> String {
    raw_panel_settings()
        .get("crs_mode")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

/// Source: `_owned_website` - "a website the caller may configure: their own,
/// or any if admin".
///
/// **404, not 403**, for a site owned by somebody else. That is deliberate and
/// is not the shape the rest of the panel uses: it means this endpoint cannot
/// be used to enumerate which website ids exist on the server. The package
/// check *is* a 403, because by then the caller has already proved the site is
/// theirs and there is nothing left to leak.
async fn owned_website(
    state: &AppState,
    current: &CurrentUser,
    website_id: i64,
) -> Result<snpanel_db::Website, Response> {
    let website = state
        .db
        .websites()
        .by_id(website_id)
        .await
        .map_err(|e| {
            tracing::error!("website lookup failed: {e}");
            crate::errors::internal_error()
        })?
        .ok_or_else(|| crate::errors::not_found("Website not found"))?;

    if !permissions::is_admin_role(&current.user.role) {
        if website.owner_id != current.user.id {
            return Err(crate::errors::not_found("Website not found"));
        }
        let flag = match current.user.package_id {
            Some(id) => match state.db.packages().by_id(id).await {
                Ok(Some(package)) => Some(package.waf_enabled),
                _ => None,
            },
            None => None,
        };
        if !crate::waf::may_manage_waf(&current.user.role, flag) {
            return Err(crate::errors::error(
                axum::http::StatusCode::FORBIDDEN,
                "Your hosting package does not include WAF settings",
            ));
        }
    }
    Ok(website)
}

/// Source: `get_website_waf`.
async fn website_waf(
    State(state): State<AppState>,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match owned_website(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let mut data = crate::waf::site_config(&website, &server_crs_mode(), &raw_panel_settings());
    // The custom-rules box is admin-only to write; tell the UI so it can show
    // it read-only rather than offering an edit that will be refused.
    data["may_edit_custom_rules"] = json!(permissions::is_admin_role(&current.user.role));
    axum::Json(data).into_response()
}

/// Source: `save_website_waf`.
///
/// The custom-rules box is the reason this is not a plain write. Custom rules
/// are arbitrary ModSecurity directives loaded into nginx: a `SecRule` can run
/// a script or read a file the nginx worker can reach, so letting a customer
/// write them would hand out code execution on a shared server. Toggling the
/// shipped rules is safe; this is not. A non-admin whose payload *matches*
/// what is already stored is allowed through - the WAF page sends the whole
/// form back, and refusing a customer who only changed a checkbox would make
/// the page unusable for them.
async fn save_website_waf(
    State(state): State<AppState>,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match owned_website(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    // Source: `enabled_rule_ids: list[str] = Field(default_factory=list)` -
    // an absent field is an empty list, which means *no* rules, not all of
    // them. That is the opposite of what an empty stored column means, and it
    // is the pydantic default rather than an oversight.
    let mut enabled: Vec<String> = Vec::new();
    if let Some(items) = payload.get("enabled_rule_ids") {
        let Some(list) = items.as_array() else {
            return crate::errors::validation_error(vec![json!({
                "type": "list_type",
                "loc": ["body", "enabled_rule_ids"],
                "msg": "Input should be a valid list",
                "input": items,
            })]);
        };
        for item in list {
            let Some(text) = item.as_str() else {
                return crate::errors::string_type("enabled_rule_ids", item);
            };
            enabled.push(text.to_string());
        }
    }
    let requested_custom = payload
        .get("custom_rules")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let is_admin = permissions::is_admin_role(&current.user.role);
    let custom_rules = if is_admin {
        requested_custom
    } else {
        let existing =
            crate::waf::validate_custom_rules(&website.waf_custom_rules).unwrap_or_default();
        if requested_custom.trim() != existing.trim() {
            return crate::errors::error(
                axum::http::StatusCode::FORBIDDEN,
                "Custom WAF rules can only be changed by an administrator",
            );
        }
        existing
    };

    let plan = match crate::waf::plan_website_config(
        &website,
        &enabled,
        &custom_rules,
        &server_crs_mode(),
    ) {
        Ok(p) => p,
        Err(e) => return bad_request(&e.to_string()),
    };
    let result = match crate::waf::write_site_rules(
        state.settings.command_dry_run,
        &website.domain,
        &plan.content,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !result.ok() {
        return bad_request(result.failure_detail("Could not save WAF rules").trim());
    }

    // The columns only after the file is on disk: a row that says a rule is
    // off while the file still enforces it is a customer told something that
    // is not true about their own site.
    if let Err(e) = state
        .db
        .websites()
        .set_waf_rules(website.id, &plan.default_rules, &plan.custom_rules)
        .await
    {
        tracing::error!("storing the WAF rule selection failed: {e}");
        return crate::errors::internal_error();
    }

    let fresh = match state.db.websites().by_id(website.id).await {
        Ok(Some(w)) => w,
        Ok(None) => return crate::errors::not_found("Website not found"),
        Err(e) => {
            tracing::error!("re-reading the website failed: {e}");
            return crate::errors::internal_error();
        }
    };

    // Only when the site's WAF is on: the block that includes the rule file
    // has to be rewritten so nginx picks the new one up, and there is nothing
    // to rewrite on a site that is not loading it.
    if fresh.waf_enabled {
        if let Err(r) = super::websites::update_waf_block(&state, &fresh.domain, true).await {
            return r;
        }
    }

    let mut data = crate::waf::site_config(&fresh, &server_crs_mode(), &raw_panel_settings());
    data["message"] = json!("Website WAF rules saved.");
    axum::Json(data).into_response()
}

// ---------------------------------------------------------------------------
// bot blocking
// ---------------------------------------------------------------------------

/// Source: `panel_settings._write_raw` - the same atomic write `addons.json`
/// gets, for the same reason: everything on the panel reads this file.
fn write_panel_settings(data: &Value) -> std::io::Result<()> {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into());
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir)?;
    let mut text = serde_json::to_string_pretty(data)?;
    text.push('\n');
    let temp = dir.join(format!(".panel-settings.json.{}", std::process::id()));
    std::fs::write(&temp, text)?;
    std::fs::rename(&temp, dir.join("panel-settings.json"))
}

/// Source: `nginx.update_bot_block` - "rewrite just the bot block in a live
/// vhost, leaving everything else".
///
/// Edited in place rather than re-rendered from the template, so a site whose
/// vhost has been customised keeps its customisations. The rollback in
/// `apply_vhost` matters more here than anywhere: the block is built from
/// operator-supplied text.
async fn update_bot_block(state: &AppState, domain: &str, bots: &[String]) -> Result<(), String> {
    if state.settings.command_dry_run {
        return Ok(());
    }
    let Some(path) = super::websites::vhost_path_for(state, domain) else {
        return Err("Invalid domain".to_string());
    };
    let Some(existing) = tokio::fs::read_to_string(&path).await.ok() else {
        // Source: `raise FileNotFoundError(str(target))`.
        return Err(path.to_string_lossy().into_owned());
    };
    let updated = snpanel_nginx::replace_bot_block(&existing, bots).map_err(|e| e.to_string())?;
    super::websites::apply_vhost_plan(
        state,
        snpanel_nginx::VhostPlan {
            path,
            content: updated,
            previous: Some(existing),
            custom_include: String::new(),
            custom_include_path: String::new(),
        },
    )
    .await
}

/// Source: `save_website_blocked_bots`.
///
/// Returns the site's **own** cleaned list, not the effective one, because
/// that is what the caller just edited - while the vhost is written from the
/// effective list, which is the site's plus the server-wide one.
async fn save_site_bots(
    state: &AppState,
    website: &snpanel_db::Website,
    raw: &str,
    mode: &str,
) -> Result<Vec<String>, String> {
    let incoming = snpanel_nginx::normalize_blocked_bots(&crate::waf::split_bot_list(raw))
        .map_err(|e| e.to_string())?;
    let bots = if mode == "add" {
        crate::waf::merge_bots(&crate::waf::website_blocked_bots(website), &incoming)
    } else {
        incoming
    };

    // The vhost is rendered from the *new* list, not from the stored row: the
    // Python assigns `website.blocked_bots` before it renders, and the row is
    // only committed afterwards.
    let effective = crate::waf::merge_bots(
        &crate::waf::global_blocked_bots(&raw_panel_settings()),
        &bots,
    );
    update_bot_block(state, &website.domain, &effective).await?;

    state
        .db
        .websites()
        .set_blocked_bots(website.id, &bots.join("\n"))
        .await
        .map_err(|e| {
            tracing::error!("storing the bot list failed: {e}");
            "Panel database error".to_string()
        })?;
    Ok(bots)
}

/// Source: `list_blocked_bots` - "every website and the bot list it currently
/// blocks".
///
/// What the Bot blocking screen opens with: the operator needs to see which
/// sites are already covered before applying a list to more of them.
async fn list_blocked_bots(State(state): State<AppState>, current: CurrentUser) -> Response {
    let admin = permissions::is_admin_role(&current.user.role);
    if !admin {
        let flag = match current.user.package_id {
            Some(id) => match state.db.packages().by_id(id).await {
                Ok(Some(package)) => Some(package.waf_enabled),
                _ => None,
            },
            None => None,
        };
        if !crate::waf::may_manage_waf(&current.user.role, flag) {
            return crate::errors::error(
                axum::http::StatusCode::FORBIDDEN,
                "Your hosting package does not include WAF settings",
            );
        }
    }
    let owner = if admin { None } else { Some(current.user.id) };
    let mut websites = match state.db.websites().list(owner, "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing websites failed: {e}");
            return crate::errors::internal_error();
        }
    };
    // Source: `order_by(Website.domain)`.
    websites.sort_by(|a, b| a.domain.cmp(&b.domain));

    let settings = raw_panel_settings();
    axum::Json(json!({
        "max_bots": snpanel_nginx::MAX_BLOCKED_BOTS,
        "global_blocked_bots": crate::waf::global_blocked_bots(&settings),
        "websites": websites
            .iter()
            .map(|site| json!({
                "website_id": site.id,
                "domain": site.domain,
                "blocked_bots": crate::waf::website_blocked_bots(site),
                "effective_blocked_bots": crate::waf::effective_blocked_bots(site, &settings),
            }))
            .collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Source: `save_global_bots` - "replace the server-wide bad-bot list and
/// re-render every vhost".
///
/// One list for the whole server is the point: adding a bot here protects
/// every site at once instead of being copied into each one, where the copies
/// then drift apart.
async fn save_global_bots(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let raw = payload
        .get("blocked_bots")
        .and_then(Value::as_str)
        .unwrap_or("");

    let bots = match snpanel_nginx::normalize_blocked_bots(&crate::waf::split_bot_list(raw)) {
        Ok(list) => list,
        Err(e) => return bad_request(&e.to_string()),
    };
    let mut settings = raw_panel_settings();
    settings["global_blocked_bots"] = json!(bots.join("\n"));
    if let Err(e) = write_panel_settings(&settings) {
        tracing::error!("writing panel-settings.json failed: {e}");
        return crate::errors::internal_error();
    }

    let mut websites = match state.db.websites().list(None, "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing websites failed: {e}");
            return crate::errors::internal_error();
        }
    };
    websites.sort_by(|a, b| a.domain.cmp(&b.domain));

    // Source: `resync_bot_blocks` - "each site is written independently and a
    // failure on one does not abandon the rest: changing the global list
    // touches every vhost on the server, and the operator needs to know
    // exactly which ones took it."
    let settings = raw_panel_settings();
    let mut applied: Vec<String> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for site in &websites {
        let effective = crate::waf::effective_blocked_bots(site, &settings);
        match update_bot_block(&state, &site.domain, &effective).await {
            Ok(()) => applied.push(site.domain.clone()),
            Err(error) => failed.push(json!({ "domain": site.domain, "error": error })),
        }
    }

    let mut message = format!(
        "{} bot(s) blocked globally; {} website(s) updated.",
        bots.len(),
        applied.len()
    );
    if !failed.is_empty() {
        message.push_str(&format!(" {} failed.", failed.len()));
    }
    axum::Json(json!({
        "global_blocked_bots": bots,
        "applied": applied,
        "failed": failed,
        "message": message,
    }))
    .into_response()
}

/// Source: `save_website_bots`.
async fn save_website_bots(
    State(state): State<AppState>,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match owned_website(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let raw = payload
        .get("blocked_bots")
        .and_then(Value::as_str)
        .unwrap_or("");

    match save_site_bots(&state, &website, raw, "replace").await {
        Ok(bots) => axum::Json(json!({
            "website_id": website.id,
            "domain": website.domain,
            "blocked_bots": bots,
            "message": format!("{} bot(s) blocked on {}.", bots.len(), website.domain),
        }))
        .into_response(),
        Err(e) => bad_request(&e),
    }
}

/// Source: `apply_blocked_bots` - "apply one list to several websites in a
/// single call".
///
/// Each site is written and reloaded independently, and a failure on one is
/// reported without abandoning the rest: applying a list to twenty sites
/// should not leave the operator guessing which of them took effect.
async fn apply_blocked_bots(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let raw = payload
        .get("blocked_bots")
        .and_then(Value::as_str)
        .unwrap_or("");
    // Source: `mode: Literal["replace", "add"] = "add"` - **add** is the
    // default. Merging is the safer default for importing a public blocklist
    // on top of entries an operator added by hand.
    let mode = payload.get("mode").and_then(Value::as_str).unwrap_or("add");
    if mode != "replace" && mode != "add" {
        return crate::errors::validation_error(vec![json!({
            "type": "literal_error",
            "loc": ["body", "mode"],
            "msg": "Input should be 'replace' or 'add'",
            "input": mode,
            "ctx": { "expected": "'replace' or 'add'" },
        })]);
    }

    let ids: Vec<i64> = payload
        .get("website_ids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return bad_request("Select at least one website.");
    }

    let all = match state.db.websites().list(None, "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing websites failed: {e}");
            return crate::errors::internal_error();
        }
    };
    let selected: Vec<&snpanel_db::Website> = all.iter().filter(|w| ids.contains(&w.id)).collect();
    let missing: Vec<i64> = ids
        .iter()
        .copied()
        .filter(|id| !selected.iter().any(|w| w.id == *id))
        .collect();
    if !missing.is_empty() {
        // Source: `f"Website not found: {missing}"` - a Python list, printed.
        let printed: Vec<String> = missing.iter().map(|id| id.to_string()).collect();
        return crate::errors::not_found(&format!("Website not found: [{}]", printed.join(", ")));
    }

    let mut applied: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for site in selected {
        match save_site_bots(&state, site, raw, mode).await {
            Ok(bots) => applied.push(json!({
                "website_id": site.id,
                "domain": site.domain,
                "blocked_bots": bots,
            })),
            Err(error) => failed.push(json!({ "domain": site.domain, "error": error })),
        }
    }

    let mut message = format!("Applied to {} website(s).", applied.len());
    if !failed.is_empty() {
        message.push_str(&format!(" {} failed.", failed.len()));
    }
    axum::Json(json!({ "applied": applied, "failed": failed, "message": message })).into_response()
}

// ---------------------------------------------------------------------------
// the engine, the rule set, and the CRS switch
// ---------------------------------------------------------------------------

/// Source: `panel_settings.save_crs_mode`.
fn save_crs_mode(mode: &str) -> std::io::Result<()> {
    let mut settings = raw_panel_settings();
    settings["crs_mode"] = json!(mode);
    write_panel_settings(&settings)
}

/// Source: `_install_engine_command` - the fallback when there is no helper.
///
/// EL10 packages no nginx ModSecurity module at all - not the module, not
/// libmodsecurity, not the core rule set - so there is nothing for the "install
/// engine" button to install there. Saying so beats handing dnf a package name
/// it will reject with "no match for argument", which reads like a transient
/// repository problem rather than a settled fact about the distribution.
fn install_engine_command() -> String {
    let rhel = snpanel_osabi::detect()
        .map(|p| p.family() == snpanel_osabi::Family::Rhel)
        .unwrap_or(false);
    if rhel {
        return "echo 'ModSecurity for nginx is not packaged on this distribution; \
                the WAF rule engine would have to be built from source.' >&2; exit 1"
            .to_string();
    }
    "export DEBIAN_FRONTEND=noninteractive; apt-get update \
     && apt-get install -y libnginx-mod-http-modsecurity modsecurity-crs"
        .to_string()
}

/// Source: `save_waf_custom_rules` - the server-wide custom rule file.
async fn save_custom_rules(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = payload
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let cleaned = match crate::waf::validate_custom_rules(&content) {
        Ok(c) => c,
        Err(e) => return bad_request(&e.to_string()),
    };

    let result = shell::privileged(
        state.settings.command_dry_run,
        "waf-custom-save",
        &[],
        Some(&cleaned),
        Some(&[
            "bash",
            "-lc",
            "cat >/tmp/snpanel-waf-custom.conf && echo WAF custom rules saved",
        ]),
    )
    .await;
    if !result.ok() {
        return bad_request(result.failure_detail("Could not save WAF rules").trim());
    }
    // Source: `return result.__dict__` - the four fields, in the CommandResult's
    // own order.
    axum::Json(result.to_json()).into_response()
}

/// Source: `install_waf`.
async fn install_engine(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let fallback = install_engine_command();
    let result = shell::privileged(
        state.settings.command_dry_run,
        "waf-install",
        &[],
        None,
        Some(&["bash", "-lc", &fallback]),
    )
    .await;
    // The Python clears `waf_engine_available`'s `lru_cache` here, "which is
    // what lets a successful install take effect without restarting the
    // panel". There is nothing to clear on this side: the Rust version scans
    // the nginx config directories on every call. Both are fresh after an
    // install; before one, Python can answer from a cache where this re-reads.
    // A difference, and in the direction of being more current rather than
    // less - which is why it is recorded here instead of a cache being added
    // to match.

    axum::Json(result.to_json()).into_response()
}

/// Source: `update_waf_rules`.
async fn update_rules(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let result = shell::privileged(
        state.settings.command_dry_run,
        "waf-update",
        &[],
        None,
        Some(&["bash", "-lc", "echo no WAF updater found"]),
    )
    .await;
    axum::Json(result.to_json()).into_response()
}

/// Source: `waf.crs_status` - what the machine reports, plus the mode the
/// panel recorded.
async fn crs_status(state: &AppState) -> Value {
    let result = shell::privileged(
        state.settings.command_dry_run,
        "waf-crs-status",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "echo mode=off; echo installed=no; echo conf=no; echo rule_files=0; echo sites_including=0",
        ]),
    )
    .await;
    parse_crs_status(
        &result.stdout,
        &server_crs_mode(),
        // Whether the rules *could* run at all. Without nginx's ModSecurity
        // module there is nothing to load them into, so the page shows the
        // control as unavailable rather than offering an action that cannot
        // succeed.
        crate::system::waf_engine_available(),
    )
}

/// The `key=value` lines the helper prints, turned into the CRS page.
///
/// Three rules here are each easy to get wrong and each decides what an
/// administrator is told about a protection. `partition` takes the **first**
/// `=`, so `mode=block=extra` has the value `block=extra` - which then fails
/// the mode check and reads as off. `isdigit` refuses a negative number and a
/// decimal, so those fields become 0 rather than raising. And a line with no
/// `=` at all is a key with an empty value, not a line to skip.
fn parse_crs_status(stdout: &str, panel_mode: &str, engine_available: bool) -> Value {
    let mut mode = "off".to_string();
    let mut installed = false;
    let mut conf = false;
    let mut numbers: std::collections::BTreeMap<&str, i64> = [
        ("rule_files", 0),
        ("sites_including", 0),
        ("nginx_pss_mb", 0),
        ("ram_available_mb", 0),
        ("ram_total_mb", 0),
    ]
    .into_iter()
    .collect();

    for line in stdout.lines() {
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (line.trim(), ""),
        };
        match key {
            "installed" => installed = value == "yes",
            "conf" => conf = value == "yes",
            "mode" => mode = crate::waf::normalize_crs_mode(value).to_string(),
            _ => {
                if let Some(slot) = numbers.get_mut(key) {
                    *slot = if !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()) {
                        value.parse().unwrap_or(0)
                    } else {
                        0
                    };
                }
            }
        }
    }

    json!({
        "mode": mode,
        "installed": installed,
        "conf": conf,
        "rule_files": numbers["rule_files"],
        "sites_including": numbers["sites_including"],
        "nginx_pss_mb": numbers["nginx_pss_mb"],
        "ram_available_mb": numbers["ram_available_mb"],
        "ram_total_mb": numbers["ram_total_mb"],
        "panel_mode": crate::waf::normalize_crs_mode(panel_mode),
        "engine_available": engine_available,
    })
}

/// Source: `get_crs`.
async fn get_crs(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let mut status = crs_status(&state).await;
    status["modes"] = json!(["off", "detect", "block"]);

    let websites = match state.db.websites().list(None, "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing websites failed: {e}");
            return crate::errors::internal_error();
        }
    };
    let opted_in = websites
        .iter()
        .filter(|w| crate::waf::site_uses_crs(w))
        .count();

    status["websites"] = json!(websites
        .iter()
        .map(|w| json!({
            "website_id": w.id,
            "domain": w.domain,
            "waf_enabled": w.waf_enabled,
            "crs_enabled": w.crs_enabled,
        }))
        .collect::<Vec<_>>());
    status["sites_opted_in"] = json!(opted_in);
    // CRS is the one WAF feature with a memory bill, and it is large enough
    // that an admin should see it before switching anything on.
    status["rss_mb_per_site"] = json!(crate::waf::CRS_RSS_MB_PER_SITE);
    status["estimated_rss_mb"] = json!(crate::waf::crs_memory_estimate(opted_in));
    axum::Json(status).into_response()
}

/// Source: `set_website_crs` - one site's opt-in.
///
/// The column moves first and is put back if the rule file cannot be written.
/// The Python does the same with two commits, and the reason is the same: a
/// row saying a site loads CRS while its rule file does not is a panel that
/// reports a protection the server is not providing.
async fn set_website_crs(
    State(state): State<AppState>,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match state.db.websites().by_id(website_id).await {
        Ok(Some(w)) => w,
        Ok(None) => return crate::errors::not_found("Website not found"),
        Err(e) => {
            tracing::error!("website lookup failed: {e}");
            return crate::errors::internal_error();
        }
    };
    let Some(raw) = payload.get("enabled") else {
        return crate::errors::missing_field("enabled", payload.clone());
    };
    let enabled = match crate::errors::read_bool("enabled", Some(raw), false) {
        Ok(value) => value,
        Err(response) => return response,
    };

    if let Err(e) = state
        .db
        .websites()
        .set_crs_enabled(website.id, enabled)
        .await
    {
        tracing::error!("storing the CRS opt-in failed: {e}");
        return crate::errors::internal_error();
    }
    let mut updated = website.clone();
    updated.crs_enabled = enabled;

    let result = match crate::waf::sync_website_rules(
        state.settings.command_dry_run,
        &updated,
        &server_crs_mode(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !result.ok() {
        let _ = state
            .db
            .websites()
            .set_crs_enabled(website.id, !enabled)
            .await;
        return bad_request(result.failure_detail("Could not apply CRS").trim());
    }

    let mode = crate::waf::normalize_crs_mode(&server_crs_mode());
    // "Every other per-site protection switch leaves an audit entry; this one
    // did not, so there was no way to tell who turned CRS on for a site or
    // when."
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "update_website_crs",
        &website.domain,
    )
    .await;

    let message = if !enabled {
        format!("OWASP CRS is off for {}.", website.domain)
    } else if mode == "off" {
        format!(
            "{} is opted in, but OWASP CRS is switched off server-wide, \
             so nothing is loaded yet.",
            website.domain
        )
    } else {
        format!(
            "OWASP CRS is {mode} on {}. Restart nginx to see the memory change; \
             expect about {} MB for this site.",
            website.domain,
            crate::waf::CRS_RSS_MB_PER_SITE
        )
    };
    axum::Json(json!({
        "ok": true,
        "message": message,
        "crs_enabled": enabled,
        "mode": mode,
    }))
    .into_response()
}

/// Source: `set_crs` and `waf.set_crs_mode`.
///
/// **The order of the two halves cost an outage the first time round.** Going
/// to `off`, the mode is saved and every site's rule file is rewritten
/// *before* `snpanel-crs.conf` is removed - deleting the file first leaves
/// every site including a path that no longer exists, so the very next
/// `nginx -t`, triggered by rewriting the first site, fails and the rest of
/// the rewrite never happens. Going the other way the helper runs first,
/// because there is no point rewriting sites to include a file that could not
/// be created.
async fn set_crs(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let requested = payload
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let target = crate::waf::normalize_crs_mode(&requested);
    // `normalize_crs_mode` alone would turn nonsense into "off"; the Python
    // checks the raw value against the list first so that asking for a mode
    // that does not exist is an error rather than a silent disable.
    if !["off", "detect", "block"].contains(&requested.trim().to_lowercase().as_str()) {
        return bad_request(&format!("Unknown CRS mode: {requested}"));
    }
    // Turning it off must always work - that is the way out of a bad state -
    // but turning it on without the module would record a protection the
    // server is not providing.
    if target != "off" && !crate::system::waf_engine_available() {
        return bad_request(
            "The OWASP rule set needs nginx's ModSecurity module, which is not \
             installed on this server. AlmaLinux 10 packages neither the module \
             nor the rule set, so there is nothing to install; the WAF page \
             reports the engine as unavailable for the same reason.",
        );
    }

    let websites = match state.db.websites().list(None, "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing websites failed: {e}");
            return crate::errors::internal_error();
        }
    };

    let rewrite = |mode_for_sites: &'static str, sites: Vec<snpanel_db::Website>| {
        let state = state.clone();
        async move {
            let mut problems: Vec<Value> = Vec::new();
            for site in sites {
                match crate::waf::sync_website_rules(
                    state.settings.command_dry_run,
                    &site,
                    mode_for_sites,
                )
                .await
                {
                    Ok(outcome) if outcome.ok() => {}
                    Ok(outcome) => problems.push(json!({
                        "domain": site.domain,
                        "error": truncate_200(outcome.failure_detail("")),
                    })),
                    Err(e) => problems.push(json!({
                        "domain": site.domain,
                        "error": truncate_200(e.to_string()),
                    })),
                }
            }
            problems
        }
    };

    let helper = |mode: &'static str, fallback: String| {
        let state = state.clone();
        async move {
            shell::privileged(
                state.settings.command_dry_run,
                "waf-crs-mode",
                &[mode],
                None,
                Some(&["bash", "-lc", &fallback]),
            )
            .await
        }
    };

    let (result, failures) = if target == "off" {
        if let Err(e) = save_crs_mode("off") {
            tracing::error!("writing panel-settings.json failed: {e}");
            return crate::errors::internal_error();
        }
        let failures = rewrite("off", websites.clone()).await;
        let result = helper("off", "echo 'OWASP CRS disabled'".to_string()).await;
        (result, failures)
    } else {
        let result = helper(target, format!("echo 'OWASP CRS mode: {target}'")).await;
        if !result.ok() {
            return bad_request(
                result
                    .failure_detail("Could not change the CRS mode")
                    .trim(),
            );
        }
        if let Err(e) = save_crs_mode(target) {
            tracing::error!("writing panel-settings.json failed: {e}");
            return crate::errors::internal_error();
        }
        let failures = rewrite(target, websites.clone()).await;
        (result, failures)
    };
    if !result.ok() {
        return bad_request(
            result
                .failure_detail("Could not change the CRS mode")
                .trim(),
        );
    }

    let sites_using_crs = if target == "off" {
        0
    } else {
        websites
            .iter()
            .filter(|w| crate::waf::site_uses_crs(w))
            .count()
    };

    let mut message = match target {
        "off" => "OWASP CRS is off.".to_string(),
        "detect" => "OWASP CRS is in detect mode: every rule logs, nothing is blocked.".to_string(),
        _ => "OWASP CRS is blocking at paranoia level 1.".to_string(),
    };
    if !failures.is_empty() {
        let names: Vec<String> = failures
            .iter()
            .take(5)
            .map(|f| f["domain"].as_str().unwrap_or("").to_string())
            .collect();
        message = format!(
            "{message} {} site(s) could not be updated: {}",
            failures.len(),
            names.join(", ")
        );
    }

    // "Switching every site to blocking is the largest single change an admin
    // can make here, and it left no trace at all."
    super::packages::audit_action(&state, &parts, current.user.id, "update_crs_mode", target).await;

    axum::Json(json!({
        "ok": true,
        "message": message,
        "mode": target,
        "failures": failures,
        "sites_using_crs": sites_using_crs,
    }))
    .into_response()
}

/// Source: `str(exc)[:200]` and `(...).strip()[:200]` - Python slices
/// *characters*, so a multi-byte message must not be cut by bytes.
fn truncate_200(value: String) -> String {
    let trimmed = value.trim();
    trimmed.chars().take(200).collect()
}

// ---------------------------------------------------------------------------
// what a deleted website left behind
// ---------------------------------------------------------------------------

/// Source: `orphans.CATEGORY_LABELS`.
///
/// The labels go straight into the page, and the first one is the one that
/// hurts: "a renewal config for a site nobody hosts wakes certbot twice a day
/// and eventually fails for good."
const CATEGORY_LABELS: &[(&str, &str)] = &[
    ("cert", "Let's Encrypt certificate"),
    ("waf-rules", "WAF rule file"),
    ("vhost-backup", "vhost backup"),
    ("manual-ssl", "uploaded certificate"),
    ("sni-copy", "panel SNI copy"),
];

/// Source: `orphans.live_domains` - "every domain this panel still serves,
/// websites and aliases alike".
///
/// An alias is as live as the website carrying it: a certificate covering only
/// an alias is still in use, and deleting it would break a site that works.
async fn live_domains(state: &AppState) -> Result<Vec<String>, Response> {
    let websites = state.db.websites().list(None, "").await.map_err(|e| {
        tracing::error!("listing websites failed: {e}");
        crate::errors::internal_error()
    })?;
    let ids: Vec<i64> = websites.iter().map(|w| w.id).collect();
    let aliases = state
        .db
        .websites()
        .aliases_for(&ids)
        .await
        .unwrap_or_default();

    let mut names: Vec<String> = Vec::new();
    for domain in websites
        .iter()
        .map(|w| w.domain.as_str())
        .chain(aliases.iter().map(|a| a.domain.as_str()))
    {
        let cleaned = domain.trim().to_lowercase();
        if !cleaned.is_empty() && !names.contains(&cleaned) {
            names.push(cleaned);
        }
    }
    names.sort();
    Ok(names)
}

/// Source: `orphans._parse` - the helper's tab-separated report.
fn parse_orphans(result: &crate::shell::CommandResult) -> Value {
    let mut items: Vec<Value> = Vec::new();
    let mut summary = serde_json::Map::new();
    let mut archive = String::new();

    for line in result.stdout.lines() {
        // `line.split("\t")` with fewer than two fields is skipped, so a
        // blank line or a stray message cannot become an item.
        let mut parts = line.split('\t');
        let (Some(kind), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (kind, value) = (kind.trim(), value.trim());
        match kind {
            "summary" => {
                for token in value.split_whitespace() {
                    let (key, count) = match token.split_once('=') {
                        Some((k, c)) => (k, c),
                        None => (token, ""),
                    };
                    // `int(count) if count.isdigit() else 0`.
                    let number: i64 =
                        if !count.is_empty() && count.chars().all(|c| c.is_ascii_digit()) {
                            count.parse().unwrap_or(0)
                        } else {
                            0
                        };
                    summary.insert(key.to_string(), json!(number));
                }
            }
            "archive" => archive = value.to_string(),
            _ => {
                if let Some((_, label)) = CATEGORY_LABELS.iter().find(|(k, _)| *k == kind) {
                    items.push(json!({ "type": kind, "label": label, "name": value }));
                }
            }
        }
    }

    let ok = result.returncode == 0;
    json!({
        "items": items,
        "summary": summary,
        "archive": archive,
        "total": items.len(),
        "ok": ok,
        // `[:400]` slices characters, not bytes.
        "error": if ok {
            String::new()
        } else {
            result
                .failure_detail("")
                .trim()
                .chars()
                .take(400)
                .collect::<String>()
        },
    })
}

/// Source: `orphans._run`.
///
/// The empty-list guard is the important line. An empty list would mean
/// "nothing on this server is live", which the helper refuses - but the Python
/// does not even ask, so a broken query cannot turn into a delete request at
/// all. That guard is reproduced here rather than left to the helper.
async fn run_orphans(state: &AppState, verb: &str) -> Result<Value, Response> {
    let domains = live_domains(state).await?;
    if domains.is_empty() {
        return Err(bad_request(
            "refusing to run orphan cleanup without any live domains",
        ));
    }
    let payload = domains.join("\n") + "\n";
    let result = shell::privileged(
        state.settings.command_dry_run,
        verb,
        &[],
        Some(&payload),
        Some(&[
            "bash",
            "-lc",
            "cat >/dev/null; echo 'summary\tcerts=0 waf-rules=0'",
        ]),
    )
    .await;
    Ok(parse_orphans(&result))
}

/// Source: `scan_orphans` - "what deleted websites left behind. Touches
/// nothing."
async fn scan_orphans(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let mut outcome = match run_orphans(&state, "orphans-scan").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let total = outcome["total"].as_u64().unwrap_or(0);
    outcome["message"] = json!(if total > 0 {
        format!("{total} orphaned item(s) on disk.")
    } else {
        "Nothing orphaned.".to_string()
    });
    axum::Json(outcome).into_response()
}

/// Source: `clean_orphans` - "remove them, after copying everything to
/// /root/snpanel-removed".
async fn clean_orphans(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return not_enough_permissions();
    }
    let mut outcome = match run_orphans(&state, "orphans-clean").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    outcome["message"] = json!(describe_orphans(&outcome));
    axum::Json(outcome).into_response()
}

/// Source: `orphans.describe`.
fn describe_orphans(outcome: &Value) -> String {
    if !outcome["ok"].as_bool().unwrap_or(false) {
        let error = outcome["error"].as_str().unwrap_or("");
        let error = if error.is_empty() {
            "unknown error"
        } else {
            error
        };
        return format!("Orphan cleanup failed: {error}");
    }
    let total = outcome["total"].as_u64().unwrap_or(0);
    if total == 0 {
        return "Nothing orphaned: every certificate and config on disk belongs to \
                a website this panel serves."
            .to_string();
    }
    // `sorted(outcome["summary"].items())` and only the non-zero counts -
    // serde_json's map is already sorted by key.
    let counts: Vec<String> = outcome["summary"]
        .as_object()
        .map(|map| {
            map.iter()
                .filter(|(_, value)| value.as_i64().unwrap_or(0) != 0)
                .map(|(key, value)| format!("{key} {value}"))
                .collect()
        })
        .unwrap_or_default();
    let mut message = format!("Removed {total} orphaned item(s): {}.", counts.join(", "));
    let archive = outcome["archive"].as_str().unwrap_or("");
    if !archive.is_empty() {
        message.push_str(&format!(" A copy is in {archive}."));
    }
    message
}

/// The website list these two endpoints work from.
///
/// Source: the query the Python builds before `access_logs` and
/// `clear_access_logs`. The owner filter is not a nicety: "without this an end
/// user asking for no website_id would be handed every site's access log on
/// the server."
async fn log_scope(
    state: &AppState,
    current: &CurrentUser,
    website_id: Option<i64>,
) -> Result<Vec<snpanel_db::Website>, Response> {
    let admin = permissions::is_admin_role(&current.user.role);
    if !admin {
        let flag = match current.user.package_id {
            Some(id) => match state.db.packages().by_id(id).await {
                Ok(Some(package)) => Some(package.waf_enabled),
                _ => None,
            },
            None => None,
        };
        if !crate::waf::may_manage_waf(&current.user.role, flag) {
            return Err(crate::errors::error(
                axum::http::StatusCode::FORBIDDEN,
                "Your hosting package does not include WAF settings",
            ));
        }
    }
    let owner = if admin { None } else { Some(current.user.id) };
    let mut websites = state.db.websites().list(owner, "").await.map_err(|e| {
        tracing::error!("listing websites failed: {e}");
        crate::errors::internal_error()
    })?;
    if let Some(id) = website_id {
        websites.retain(|w| w.id == id);
        // A `website_id` that matched nothing is a 404 - including when the
        // site exists but belongs to somebody else, which is what keeps this
        // from being an id oracle.
        if websites.is_empty() {
            return Err(crate::errors::not_found("Website not found"));
        }
    }
    websites.sort_by(|a, b| a.domain.cmp(&b.domain));
    Ok(websites)
}

/// Source: `clear_waf_access_logs`.
async fn clear_access_logs(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let website_id = match params.get("website_id") {
        Some(raw) => match raw.parse::<i64>() {
            // `Query(default=None, ge=1)`.
            Ok(id) if id >= 1 => Some(id),
            _ => {
                return crate::errors::validation_error(vec![json!({
                    "type": "greater_than_equal",
                    "loc": ["query", "website_id"],
                    "msg": "Input should be greater than or equal to 1",
                    "input": raw,
                    "ctx": { "ge": 1 },
                })])
            }
        },
        None => None,
    };
    let websites = match log_scope(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let mut cleared = 0usize;
    for site in &websites {
        let Ok(domain) = crate::waf::validate_domain(&site.domain) else {
            return bad_request("Invalid domain");
        };
        let path = format!("/var/log/nginx/{domain}.access.log");
        let result = shell::privileged(
            state.settings.command_dry_run,
            "site-log-clear",
            &[&domain, "access"],
            None,
            Some(&[
                "bash",
                "-lc",
                "test -f \"$1\" && : >\"$1\" || true",
                "snpanel-clear-log",
                &path,
            ]),
        )
        .await;
        if !result.ok() {
            return bad_request(result.failure_detail("Cannot clear log file").trim());
        }
        cleared += 1;
    }

    axum::Json(json!({
        "message": format!("Cleared access logs for {cleared} website(s)."),
        "cleared": cleared,
    }))
    .into_response()
}

/// Source: `access_logs`' four query parameters and their bounds.
struct AccessLogQuery {
    verdict: String,
    query: String,
    limit: usize,
    lines: usize,
}

fn access_log_query(
    params: &std::collections::HashMap<String, String>,
) -> Result<AccessLogQuery, Response> {
    let website_verdict = params
        .get("verdict")
        .map(String::as_str)
        .unwrap_or("all")
        .to_string();
    // `pattern="^(all|allow|block|error)^"` on the query parameter, which
    // pydantic refuses before the handler runs.
    if !matches!(
        website_verdict.as_str(),
        "all" | "allow" | "block" | "error"
    ) {
        return Err(crate::errors::validation_error(vec![json!({
            "type": "string_pattern_mismatch",
            "loc": ["query", "verdict"],
            "msg": "String should match pattern '^(all|allow|block|error)$'",
            "input": website_verdict,
            "ctx": { "pattern": "^(all|allow|block|error)$" },
        })]));
    }
    let query = params.get("q").cloned().unwrap_or_default();
    if query.chars().count() > 200 {
        return Err(crate::errors::validation_error(vec![json!({
            "type": "string_too_long",
            "loc": ["query", "q"],
            "msg": "String should have at most 200 characters",
            "input": query,
            "ctx": { "max_length": 200 },
        })]));
    }
    let number = |name: &str, default: i64, min: i64, max: i64| -> Result<i64, Response> {
        let Some(raw) = params.get(name) else {
            return Ok(default);
        };
        let Ok(value) = raw.trim().parse::<i64>() else {
            return Err(crate::errors::validation_error(vec![json!({
                "type": "int_parsing",
                "loc": ["query", name],
                "msg": "Input should be a valid integer, unable to parse string as an integer",
                "input": raw,
            })]));
        };
        if value < min || value > max {
            return Err(crate::errors::validation_error(vec![json!({
                "type": if value < min { "greater_than_equal" } else { "less_than_equal" },
                "loc": ["query", name],
                "msg": if value < min {
                    format!("Input should be greater than or equal to {min}")
                } else {
                    format!("Input should be less than or equal to {max}")
                },
                "input": raw,
                "ctx": if value < min { json!({ "ge": min }) } else { json!({ "le": max }) },
            })]));
        }
        Ok(value)
    };
    Ok(AccessLogQuery {
        verdict: website_verdict,
        query,
        limit: number("limit", 50, 1, 500)? as usize,
        lines: number("lines", 5000, 1, 5000)? as usize,
    })
}

/// Source: `scan_lines` in `access_logs`.
///
/// **Without a filter the newest `limit` lines per site are all that can be
/// shown**, so there is no reason to tail (and parse) thousands. With a
/// filter the deep history is needed to find enough matches — a search for an
/// IP that last appeared an hour ago has to reach it.
fn access_scan_lines(limit: usize, lines: usize, filtering: bool) -> usize {
    if filtering {
        lines
    } else {
        lines.min((limit * 4).max(400))
    }
}

/// Source: `_read_site_logs` — one helper spawn for every site's log.
///
/// The helper answers with `\x1f`-separated blocks, each `domain\ncontent`,
/// and `SNPANEL_LOG_MISSING` for a file that is not there. A missing file is
/// **not** an empty one: the payload reports it under `missing` so the page
/// can say "this site has never been visited" rather than "no matches".
///
/// **A batch that does not answer is retried one site at a time.** The batch
/// verb is only asked when the helper is in use at all, and a non-zero answer
/// from it is not evidence that the logs are unreadable — so the fallback
/// reads each site through `site-log-read`, exactly as the per-site log
/// viewer does. A read that genuinely fails there stops the request with the
/// helper's own message; reporting every site as missing instead would show
/// an operator "nobody has visited any of your sites" for what is really a
/// broken log directory.
async fn read_site_logs(
    state: &AppState,
    domains: &[String],
    lines: usize,
) -> Result<std::collections::HashMap<String, Option<String>>, String> {
    let mut blocks: std::collections::HashMap<String, Option<String>> =
        domains.iter().map(|d| (d.clone(), None)).collect();
    if domains.is_empty() {
        return Ok(blocks);
    }
    let count = lines.to_string();
    let batch = if shell::use_helper() {
        let mut args: Vec<&str> = vec!["access", &count];
        args.extend(domains.iter().map(String::as_str));
        let result = shell::privileged(
            state.settings.command_dry_run,
            "site-logs-read-many",
            &args,
            None,
            None,
        )
        .await;
        result.ok().then_some(result)
    } else {
        None
    };

    let Some(result) = batch else {
        for domain in domains {
            let path = format!("/var/log/nginx/{domain}.access.log");
            let result = shell::privileged(
                state.settings.command_dry_run,
                "site-log-read",
                &[domain, "access", &count],
                None,
                Some(&["tail", "-n", &count, &path]),
            )
            .await;
            // The helper says so on stderr rather than failing, because "no
            // log yet" is the normal state of a site nobody has visited.
            let missing = result.stderr.contains("SNPANEL_LOG_MISSING=1");
            if !result.ok() && !missing {
                return Err(result
                    .failure_detail("Cannot read log file")
                    .trim()
                    .to_string());
            }
            blocks.insert(
                domain.clone(),
                if missing { None } else { Some(result.stdout) },
            );
        }
        return Ok(blocks);
    };

    split_log_blocks(&result.stdout, &mut blocks);
    Ok(blocks)
}

/// Source: the `\x1f` loop in `_read_site_logs`.
///
/// Every rule here is a contract with `site-logs-read-many`: the separator
/// leads each block, so the first chunk is empty and skipped; a block with no
/// newline is a domain that produced nothing; a domain nobody asked for is
/// ignored rather than added; and `SNPANEL_LOG_MISSING` means the file is not
/// there, which the payload reports separately from an empty one.
fn split_log_blocks(stdout: &str, blocks: &mut std::collections::HashMap<String, Option<String>>) {
    for chunk in stdout.split('\x1f') {
        if chunk.is_empty() {
            continue;
        }
        let (head, body) = match chunk.split_once('\n') {
            Some((head, body)) => (head, body),
            None => (chunk, ""),
        };
        let domain = head.trim();
        if !blocks.contains_key(domain) {
            continue;
        }
        let value = if body.trim() == "SNPANEL_LOG_MISSING" {
            None
        } else {
            Some(body.to_string())
        };
        blocks.insert(domain.to_string(), value);
    }
}

/// `datetime.now(timezone.utc).isoformat()`.
///
/// **With microseconds and `+00:00`, not `Z`.** `isoformat` omits the
/// microseconds only when they are zero, and `now()` essentially never is —
/// so the field the page displays carries six digits, and a port that wrote
/// seconds would differ on every request.
fn generated_at_now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string()
}

/// `GET /waf/access-logs`.
///
/// Source: `get_waf_access_logs`.
///
/// **The cache is deliberately not ported.** The Python keeps the last
/// thirty-two answers for four seconds because reading two dozen nginx logs
/// off a cold disk takes seconds and the page polls; this process reads the
/// same files through the same helper and pays the same cost, so the cache is
/// worth having — but it is a *process-local* cache, and while both
/// implementations are serving, two caches keyed the same way would answer
/// differently depending on which front door the poll reached. `cached` is
/// always `false` here, which is what the page renders when the answer is
/// fresh.
async fn access_logs(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let website_id = match params.get("website_id") {
        Some(raw) => match raw.trim().parse::<i64>() {
            Ok(id) if id >= 1 => Some(id),
            Ok(_) => {
                return crate::errors::validation_error(vec![json!({
                    "type": "greater_than_equal",
                    "loc": ["query", "website_id"],
                    "msg": "Input should be greater than or equal to 1",
                    "input": raw,
                    "ctx": { "ge": 1 },
                })])
            }
            Err(_) => {
                return crate::errors::validation_error(vec![json!({
                    "type": "int_parsing",
                    "loc": ["query", "website_id"],
                    "msg": "Input should be a valid integer, unable to parse string as an integer",
                    "input": raw,
                })])
            }
        },
        None => None,
    };
    let q = match access_log_query(&params) {
        Ok(q) => q,
        Err(r) => return r,
    };
    let websites = match log_scope(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let filtering = q.verdict != "all" || !q.query.trim().is_empty();
    let scan_lines = access_scan_lines(q.limit, q.lines, filtering);
    // `[_validate_domain(w.domain) for w in websites]`. A stored domain that
    // no longer passes the pattern stops the whole request rather than being
    // skipped, because the name is about to be pasted into a log path.
    let mut domains: Vec<String> = Vec::with_capacity(websites.len());
    for site in &websites {
        match crate::waf::validate_domain(&site.domain) {
            Ok(domain) => domains.push(domain),
            Err(e) => return bad_request(&e.to_string()),
        }
    }
    let blocks = match read_site_logs(&state, &domains, scan_lines).await {
        Ok(blocks) => blocks,
        Err(detail) => return bad_request(&detail),
    };

    let mut sortable: Vec<(i64, u64, Value)> = Vec::new();
    let mut parsed_count = 0u64;
    let mut sequence = 0u64;
    let mut missing: Vec<String> = Vec::new();
    for domain in &domains {
        let Some(Some(content)) = blocks.get(domain) else {
            missing.push(domain.clone());
            continue;
        };
        for line in content.lines() {
            sequence += 1;
            // The country table is not ported; see the plan. An empty pair is
            // what the Python gives when neither source can answer, which is
            // what a stock installation has.
            let Some(entry) = crate::access_log::parse_access_line(
                domain,
                line,
                sequence,
                &(String::new(), String::new()),
            ) else {
                continue;
            };
            parsed_count += 1;
            if crate::access_log::matches_access_filter(&entry.item, &q.verdict, &q.query) {
                sortable.push((entry.sort_time, parsed_count, entry.item));
            }
        }
    }
    // `sort(key=(time, parsed_count), reverse=True)` — the counter breaks a
    // tie, so two entries in the same second keep the order they were read
    // in, newest first.
    sortable.sort_by_key(|(time, seq, _)| std::cmp::Reverse((*time, *seq)));
    let total = sortable.len();
    let items: Vec<Value> = sortable
        .into_iter()
        .take(q.limit)
        .map(|(_, _, v)| v)
        .collect();

    axum::Json(json!({
        "items": items,
        "total": total,
        "scanned": parsed_count,
        "limit": q.limit,
        "lines": scan_lines,
        "verdict": q.verdict,
        "query": q.query.trim(),
        "missing": missing,
        "generated_at": generated_at_now(),
        "cached": false,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the panel makes of the helper's `key=value` lines.
    ///
    /// The three rules that are easy to get wrong are each represented in the
    /// corpus: the first `=` wins, a non-digit value is zero rather than an
    /// error, and an unrecognised mode is off. Every one of them decides what
    /// an administrator is told about a protection they may be relying on.
    #[test]
    fn the_crs_status_lines_are_read_the_way_python_reads_them() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/crs_status.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the crs corpus"))
                .expect("the corpus parses");

        let mut failures: Vec<String> = Vec::new();
        for case in corpus["cases"].as_array().expect("the cases") {
            let stdout = case["stdout"].as_str().unwrap_or("");
            // The corpus was generated with `crs_mode` = detect and the engine
            // reported as available.
            let got = parse_crs_status(stdout, "detect", true);
            let want = &case["status"];
            for (key, want_value) in want.as_object().expect("an object") {
                let got_value = &got[key.as_str()];
                if got_value != want_value {
                    failures.push(format!(
                        "{stdout:?}: {key} python {want_value}, rust {got_value}"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn the_crs_memory_estimate_is_per_site() {
        // CRS is the one WAF feature with a memory bill, and the page shows
        // this before an admin switches anything on.
        assert_eq!(crate::waf::crs_memory_estimate(0), 0);
        assert_eq!(crate::waf::crs_memory_estimate(1), 50);
        assert_eq!(crate::waf::crs_memory_estimate(19), 950);
    }

    #[test]
    fn every_definition_carries_the_five_fields() {
        let defs = rule_definitions();
        assert_eq!(defs.len(), 8);
        for d in &defs {
            for key in ["id", "category", "title", "description", "enabled_default"] {
                assert!(d.get(key).is_some(), "{key} missing from {d}");
            }
            assert_eq!(d["enabled_default"], json!(true));
        }
    }

    #[test]
    fn the_rule_bodies_are_not_in_the_definitions() {
        // `default_rule_definitions()` projects five fields; the `rules` text
        // reaches the client through `default_rules` instead, which is what
        // the helper reads off disk.
        for d in rule_definitions() {
            assert!(d.get("rules").is_none(), "{d}");
        }
    }

    #[test]
    fn the_catalogue_covers_the_three_application_families() {
        let categories: std::collections::BTreeSet<String> = rule_definitions()
            .iter()
            .map(|d| d["category"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            categories,
            ["Laravel", "PHP", "WordPress"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
    }

    #[test]
    fn the_identifiers_are_unique() {
        // They are what a site's "rule off" toggle stores, so a duplicate
        // would silently disable two rules at once.
        let ids: std::collections::BTreeSet<&str> = crate::waf::DEFAULT_RULES
            .iter()
            .map(|rule| rule.id)
            .collect();
        assert_eq!(ids.len(), crate::waf::DEFAULT_RULES.len());
    }

    /// How deep the read goes, and why it is not always `lines`.
    ///
    /// Source: `scan_lines = safe_lines if filtering else min(safe_lines,
    /// max(safe_limit * 4, 400))`. Unfiltered, only the newest `limit` lines
    /// can be shown, so tailing five thousand and parsing them would be work
    /// nobody sees — but the cap is `limit * 4`, not `limit`, because a line
    /// that does not parse still consumes one. **Filtering flips it**: a
    /// search for an IP that last appeared an hour ago has to reach back that
    /// far, so the full `lines` is read.
    #[test]
    fn a_search_reads_deeper_than_a_first_page_does() {
        // Unfiltered: the floor is 400 even for a tiny page.
        assert_eq!(access_scan_lines(1, 5000, false), 400);
        assert_eq!(access_scan_lines(50, 5000, false), 400);
        // Above 100 the multiple takes over from the floor.
        assert_eq!(access_scan_lines(100, 5000, false), 400);
        assert_eq!(access_scan_lines(101, 5000, false), 404);
        assert_eq!(access_scan_lines(500, 5000, false), 2000);
        // `lines` still caps it: asking for a big page of a short read.
        assert_eq!(access_scan_lines(500, 100, false), 100);
        // Filtering reads everything that was asked for, whatever the page.
        assert_eq!(access_scan_lines(1, 5000, true), 5000);
        assert_eq!(access_scan_lines(500, 5000, true), 5000);
        assert_eq!(access_scan_lines(50, 10, true), 10);
    }

    /// What the four query parameters accept, and what they refuse.
    ///
    /// These are `Query(...)` declarations, so pydantic refuses them before
    /// the handler runs and the answer is a 422 naming the parameter — not
    /// the clamp the service would apply to the same value if it were called
    /// directly.
    #[test]
    fn the_query_parameters_are_bounded_the_way_pydantic_bounds_them() {
        let q = |pairs: &[(&str, &str)]| {
            let params: std::collections::HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect();
            access_log_query(&params)
        };

        let ok = q(&[]).unwrap_or_else(|_| panic!("the defaults are valid"));
        assert_eq!(ok.verdict, "all");
        assert_eq!(ok.query, "");
        assert_eq!(ok.limit, 50);
        assert_eq!(ok.lines, 5000);

        for verdict in ["all", "allow", "block", "error"] {
            assert!(q(&[("verdict", verdict)]).is_ok(), "{verdict} is a verdict");
        }
        // Not a prefix match, and not case-folded.
        for verdict in ["", "ALL", "allowed", "block ", "deny"] {
            assert!(q(&[("verdict", verdict)]).is_err(), "{verdict:?} is not");
        }

        // The bounds, each side of each edge.
        assert!(q(&[("limit", "1")]).is_ok());
        assert!(q(&[("limit", "500")]).is_ok());
        assert!(q(&[("limit", "0")]).is_err());
        assert!(q(&[("limit", "501")]).is_err());
        assert!(q(&[("limit", "-1")]).is_err());
        assert!(q(&[("limit", "50.0")]).is_err(), "a float is not an int");
        assert!(q(&[("limit", "")]).is_err());
        assert!(q(&[("lines", "1")]).is_ok());
        assert!(q(&[("lines", "5000")]).is_ok());
        assert!(q(&[("lines", "0")]).is_err());
        assert!(q(&[("lines", "5001")]).is_err());

        // `max_length` counts characters, not bytes: a 200-character search
        // in a non-Latin script is 600 bytes and still allowed.
        let two_hundred_wide: String = "é".repeat(200);
        assert_eq!(
            two_hundred_wide.len(),
            400,
            "the needle is wider than ASCII"
        );
        assert!(q(&[("q", &two_hundred_wide)]).is_ok());
        let too_long: String = "a".repeat(201);
        assert!(q(&[("q", &too_long)]).is_err());
        // The search is *not* trimmed here; the payload echoes it trimmed,
        // but a needle of 200 spaces is a valid parameter.
        let spaces = " ".repeat(200);
        assert_eq!(q(&[("q", &spaces)]).ok().map(|v| v.query), Some(spaces));
    }

    /// The `\x1f` framing, including the block that is not a file.
    #[test]
    fn the_helpers_blocks_are_unpacked_per_site() {
        let mut blocks: std::collections::HashMap<String, Option<String>> =
            ["a.example.com", "b.example.com", "c.example.com"]
                .iter()
                .map(|d| ((*d).to_string(), None))
                .collect();
        // A leading separator, a site with content, a site whose file is not
        // there, a site that was never asked for, and a bare domain.
        let stdout = "\x1fa.example.com\nfirst\nsecond\n\
                      \x1fb.example.com\nSNPANEL_LOG_MISSING\n\
                      \x1fnot-asked-for.example.com\nignored\n\
                      \x1fc.example.com";
        split_log_blocks(stdout, &mut blocks);

        assert_eq!(
            blocks["a.example.com"].as_deref(),
            Some("first\nsecond\n"),
            "the content keeps its own newlines"
        );
        assert_eq!(
            blocks["b.example.com"], None,
            "a missing file is not an empty one"
        );
        assert_eq!(
            blocks["c.example.com"].as_deref(),
            Some(""),
            "a block with no newline is a site that produced nothing"
        );
        assert_eq!(blocks.len(), 3, "an unasked-for domain is not added");

        // An empty answer leaves every site as it was, which is `None` —
        // reported under `missing`, not as a site with no visitors.
        let mut untouched: std::collections::HashMap<String, Option<String>> =
            [("a.example.com".to_string(), None)].into_iter().collect();
        split_log_blocks("", &mut untouched);
        assert_eq!(untouched["a.example.com"], None);
    }

    /// `isoformat()` writes microseconds and `+00:00`, never `Z`.
    #[test]
    fn the_generated_at_stamp_is_shaped_like_pythons() {
        let stamp = generated_at_now();
        assert_eq!(stamp.len(), 32, "{stamp}");
        assert!(stamp.ends_with("+00:00"), "{stamp}");
        assert!(!stamp.contains('Z'), "{stamp}");
        let (date, rest) = stamp.split_once('T').expect("a T separator");
        assert_eq!(date.len(), 10, "{stamp}");
        let fraction = rest
            .trim_end_matches("+00:00")
            .split_once('.')
            .expect("a fractional part")
            .1;
        assert_eq!(fraction.len(), 6, "microseconds, not milliseconds: {stamp}");
        assert!(fraction.chars().all(|c| c.is_ascii_digit()), "{stamp}");
    }
}
