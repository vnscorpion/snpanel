//! `/api/waf` - ported from `api/waf.py`, the two engine-level reads.
//!
//! The rest of this router edits per-site ModSecurity rules, rewrites vhosts
//! and reads access logs through the helper, all of which belongs to the site
//! surface Phase 2 has not finished.
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
use crate::errors::not_enough_permissions;
use crate::shell;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/waf/status", get(status).fallback(crate::fallback))
        .route("/waf/rules", get(rules).fallback(crate::fallback))
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
