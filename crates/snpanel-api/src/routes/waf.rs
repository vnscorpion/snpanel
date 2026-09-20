//! `/api/waf` - ported from `api/waf.py`.
//!
//! The engine-level reads and one site's rule selection. What is left edits
//! bot lists, reads access logs and installs the engine itself.
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
fn server_crs_mode() -> String {
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
    let Some(enabled) = raw.as_bool() else {
        return crate::errors::bool_parsing("enabled", raw);
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
}
