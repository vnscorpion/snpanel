//! `/api/waf` - ported from `api/waf.py`, the two engine-level reads.
//!
//! The rest of this router edits per-site ModSecurity rules, rewrites vhosts
//! and reads access logs through the helper, all of which belongs to the site
//! surface Phase 2 has not finished.
//!
//! `/rules` is worth porting on its own account: it is what the WAF page opens
//! with, and it is three helper calls plus a catalogue the panel holds in
//! code. The catalogue was generated from the Python's own `DEFAULT_RULES`
//! rather than retyped - eight entries of prose that go straight into an API
//! response, where a typo is a difference nobody would ever notice by reading.

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

/// Source: `waf.DEFAULT_RULES`, as `default_rule_definitions()` projects it -
/// the identifying fields only, never the rule bodies.
///
/// Generated from the Python list (`id`, `category`, `title`, `description`).
const DEFAULT_RULE_DEFINITIONS: &[(&str, &str, &str, &str)] = &[
    (
        "php-sensitive-files",
        "PHP",
        "PHP sensitive files",
        "Blocks direct probes for PHP app secrets, Composer metadata, git data, and phpinfo files.",
    ),
    (
        "php-path-traversal",
        "PHP",
        "Path traversal",
        "Blocks ../ and encoded traversal probes in URLs and query arguments.",
    ),
    (
        "php-runtime-probes",
        "PHP",
        "PHP runtime probes",
        "Blocks direct probes for common PHP webshell names and old PHPUnit RCE paths.",
    ),
    (
        "laravel-sensitive-files",
        "Laravel",
        "Laravel sensitive files",
        "Blocks probes for Laravel environment files, logs, artisan, and cached PHP config.",
    ),
    (
        "laravel-ignition-rce",
        "Laravel",
        "Laravel Ignition RCE probes",
        "Blocks direct probes for the old Laravel Ignition execute-solution endpoint.",
    ),
    (
        "wordpress-sensitive-files",
        "WordPress",
        "WordPress sensitive files",
        "Blocks wp-config probes, uploads PHP execution probes, and internal WordPress PHP paths.",
    ),
    (
        "wordpress-xmlrpc-author-scan",
        "WordPress",
        "WordPress author scans",
        "Blocks ?author= enumeration scans while leaving XML-RPC compatibility to site policy.",
    ),
    (
        "wordpress-install-upgrade",
        "WordPress",
        "WordPress installer probes",
        "Blocks direct access to WordPress installation scripts after deployment.",
    ),
];

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

fn rule_definitions() -> Vec<Value> {
    DEFAULT_RULE_DEFINITIONS
        .iter()
        .map(|(id, category, title, description)| {
            json!({
                "id": id,
                "category": category,
                "title": title,
                "description": description,
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
        let ids: std::collections::BTreeSet<&str> = DEFAULT_RULE_DEFINITIONS
            .iter()
            .map(|(id, _, _, _)| *id)
            .collect();
        assert_eq!(ids.len(), DEFAULT_RULE_DEFINITIONS.len());
    }
}
