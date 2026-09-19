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

#[cfg(test)]
mod tests {
    use super::*;

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
