//! `/api/websites` - ported from `api/websites.py`, the read half.
//!
//! The largest router in the panel, and the one where the split between what
//! can move and what cannot is sharpest. Creating a website makes a Linux
//! account, renders a vhost, reloads nginx, installs WordPress and issues a
//! certificate; deleting one undoes all of it. Every one of those is the
//! helper's site surface, which Phase 2 has not finished, so they are proxied.
//!
//! What is here is what the Websites page *reads*: the listing, a site's
//! aliases, and the two nginx views. Between them they are most of the traffic
//! this router sees.
//!
//! Two behaviours in the listing are easy to miss and are not cosmetic.
//!
//! **A certificate that appeared on disk turns the flag on.** `ssl_enabled` is
//! a cached answer, and a manual certbot run or a restored backup leaves it
//! stale - so the listing checks the filesystem and *writes the correction
//! back*. A read endpoint that writes is unusual enough to say out loud.
//!
//! **`wordpress_installed` is never stored.** It is computed per request by
//! looking for `wp-config.php` and `wp-admin` under the document root, because
//! a customer who deletes WordPress by FTP would otherwise leave the panel
//! claiming it is still there.

use axum::extract::Request;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, internal_error, not_enough_permissions, not_found};
use crate::shell;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/websites", get(list).fallback(crate::fallback))
        .route(
            "/websites/{website_id}/aliases",
            get(aliases).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/nginx-custom",
            get(nginx_custom).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/nginx-config",
            get(nginx_config).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/logs",
            get(logs).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/nginx-custom",
            put(set_nginx_custom).fallback(crate::fallback),
        )
}

/// Source: `WebsiteAliasOut`.
fn alias_json(a: &snpanel_db::WebsiteAlias) -> Value {
    json!({
        "id": a.id,
        "website_id": a.website_id,
        "domain": a.domain,
        "mode": a.mode,
        "ssl_enabled": a.ssl_enabled,
        "created_at": crate::errors::iso_datetime(a.created_at.as_deref()),
    })
}

/// Source: `WebsiteOut`, including its `derive_ssl_fields` validator.
///
/// The three `ssl_*_path` fields are `Field(exclude=True)`: they are read from
/// the row and then deliberately kept out of the response. Only `ssl_has_ca`
/// survives, as a boolean. Leaking the paths would tell a customer where the
/// server keeps its private keys.
fn website_json(
    w: &snpanel_db::Website,
    aliases: &[snpanel_db::WebsiteAlias],
    wordpress_installed: bool,
    ssl_enabled: bool,
) -> Value {
    // `if not self.ssl_mode: "letsencrypt" if ssl_enabled else "none"`.
    let ssl_mode = if w.ssl_mode.is_empty() {
        if ssl_enabled { "letsencrypt" } else { "none" }.to_string()
    } else {
        w.ssl_mode.clone()
    };

    json!({
        "id": w.id,
        "domain": w.domain,
        "owner_id": w.owner_id,
        "root_path": w.root_path,
        "document_root": w.document_root,
        "linux_user": w.linux_user,
        // Never stored, and never returned by these endpoints: they exist on
        // the schema so *create* can hand back the credentials once.
        "panel_username": Value::Null,
        "panel_password": Value::Null,
        "php_version": w.php_version,
        "app_type": w.app_type,
        "ssl_enabled": ssl_enabled,
        "ssl_mode": ssl_mode,
        "ssl_source_domain": w.ssl_source_domain,
        "ssl_updated_at": crate::errors::iso_datetime(w.ssl_updated_at.as_deref()),
        "ssl_has_ca": w.ssl_ca_path.as_deref().is_some_and(|p| !p.is_empty()),
        "status": w.status,
        "nginx_custom": w.nginx_custom,
        "nginx_config_mode": w.nginx_config_mode,
        "nginx_rewrite_mode": w.nginx_rewrite_mode,
        "waf_enabled": w.waf_enabled,
        "waf_default_rules": w.waf_default_rules,
        "waf_custom_rules": w.waf_custom_rules,
        "http_flood_enabled": w.http_flood_enabled,
        "http_flood_config": w.http_flood_config,
        "blocked_bots": w.blocked_bots,
        "wordpress_installed": wordpress_installed,
        "app_id": w.app_id,
        "aliases": aliases.iter().map(alias_json).collect::<Vec<_>>(),
    })
}

/// Source: `_has_live_certificate`.
///
/// Three cases, and the middle one is a judgement rather than a check: a
/// Cloudflare or shared certificate lives under root-only
/// `/etc/letsencrypt/live`, which the unprivileged API cannot stat, so the
/// mode is trusted instead. Stat'ing it as `snpanel` would answer "no
/// certificate" for every site that has one.
fn has_live_certificate(w: &snpanel_db::Website) -> bool {
    match w.ssl_mode.as_str() {
        "manual" => match (w.ssl_cert_path.as_deref(), w.ssl_key_path.as_deref()) {
            (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
                PathBuf::from(cert).is_file() && PathBuf::from(key).is_file()
            }
            _ => false,
        },
        "cloudflare" | "shared" => w
            .ssl_source_domain
            .as_deref()
            .is_some_and(|d| !d.is_empty()),
        _ => {
            let live = PathBuf::from("/etc/letsencrypt/live").join(&w.domain);
            live.join("fullchain.pem").is_file() && live.join("privkey.pem").is_file()
        }
    }
}

/// Source: `_has_wordpress_install`.
fn has_wordpress_install(w: &snpanel_db::Website) -> bool {
    let document_root = if w.document_root.is_empty() {
        "public_html"
    } else {
        &w.document_root
    };
    // `site_users.document_root` refuses anything that escapes the site root;
    // a `..` in the column would otherwise let this probe the whole disk.
    if document_root.contains("..") || document_root.starts_with('/') {
        return false;
    }
    let public = PathBuf::from(&w.root_path).join(document_root);
    public.join("wp-config.php").is_file() && public.join("wp-admin").is_dir()
}

async fn list(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let q = params.get("q").cloned().unwrap_or_default();
    if q.chars().count() > 255 {
        return crate::errors::validation_error(vec![json!({
            "type": "string_too_long",
            "loc": ["query", "q"],
            "msg": "String should have at most 255 characters",
            "input": q,
            "ctx": { "max_length": 255 },
        })]);
    }
    let search = q.trim().to_lowercase();
    let owner = if permissions::is_admin_role(&current.user.role) {
        None
    } else {
        Some(current.user.id)
    };

    let websites = match state.db.websites().list(owner, &search).await {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("listing websites failed: {e}");
            return internal_error();
        }
    };
    let ids: Vec<i64> = websites.iter().map(|w| w.id).collect();
    let all_aliases = state
        .db
        .websites()
        .aliases_for(&ids)
        .await
        .unwrap_or_default();

    render(&state, websites, all_aliases).await
}

/// The filesystem checks and the SSL correction, shared by every listing.
async fn render(
    state: &AppState,
    websites: Vec<snpanel_db::Website>,
    all_aliases: Vec<snpanel_db::WebsiteAlias>,
) -> Response {
    // One blocking pass for every site: each is a handful of stat calls, and
    // doing them on a tokio worker would stall every other request.
    let probe = websites.clone();
    let checks = match tokio::task::spawn_blocking(move || {
        probe
            .iter()
            .map(|w| (has_live_certificate(w), has_wordpress_install(w)))
            .collect::<Vec<_>>()
    })
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("the website filesystem checks panicked: {e}");
            return internal_error();
        }
    };

    let mut out = Vec::with_capacity(websites.len());
    for (w, (live_cert, wordpress)) in websites.iter().zip(checks) {
        // Source: `_sync_live_ssl_flags` - the correction is written back, so
        // the UI stops offering to issue a certificate that already exists.
        let ssl_enabled = if !w.ssl_enabled && live_cert {
            if let Err(e) = state.db.websites().set_ssl_enabled(w.id, true).await {
                tracing::warn!("could not record a certificate found on disk: {e}");
            }
            true
        } else {
            w.ssl_enabled
        };

        let aliases: Vec<snpanel_db::WebsiteAlias> = all_aliases
            .iter()
            .filter(|a| a.website_id == w.id)
            .cloned()
            .collect();
        out.push(website_json(w, &aliases, wordpress, ssl_enabled));
    }
    axum::Json(out).into_response()
}

/// Source: `_get_authorized_website`.
async fn authorized(
    state: &AppState,
    current: &CurrentUser,
    id: i64,
) -> Result<snpanel_db::Website, Response> {
    let website = state
        .db
        .websites()
        .by_id(id)
        .await
        .map_err(|e| {
            tracing::error!("website lookup failed: {e}");
            internal_error()
        })?
        .ok_or_else(|| not_found("Website not found"))?;

    if website.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return Err(not_enough_permissions());
    }
    Ok(website)
}

async fn aliases(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    match state.db.websites().aliases(website.id).await {
        Ok(rows) => axum::Json(rows.iter().map(alias_json).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!("listing aliases failed: {e}");
            internal_error()
        }
    }
}

/// Source: `get_website_nginx_custom` - `WebsiteNginxCustom`.
async fn nginx_custom(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    axum::Json(json!({ "nginx_custom": website.nginx_custom })).into_response()
}

/// Source: `get_website_nginx_config`.
///
/// Three things here were guessed wrong the first time and are worth naming.
/// It is **admin-only**, not owner-or-admin, because the file it returns is
/// the server's nginx configuration rather than the customer's snippet. It
/// reads the **file on disk**, not the `nginx_custom` column. And the response
/// field is `nginx_config`, not a `{mode, config}` pair I invented - the
/// shadow diff reported both halves of that as "only rust has it", which is
/// what an invented shape looks like.
async fn nginx_config(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return not_enough_permissions();
    }
    // Looked up without the ownership check, exactly as the Python does: the
    // role check above has already settled it.
    let website = match state.db.websites().by_id(website_id).await {
        Ok(Some(w)) => w,
        Ok(None) => return not_found("Website not found"),
        Err(e) => {
            tracing::error!("website lookup failed: {e}");
            return internal_error();
        }
    };

    let path = match vhost_path(&state, &website.domain) {
        Some(p) => p,
        // `_vhost_path` raises ValueError("Invalid domain"), which the handler
        // turns into a 404 carrying that text.
        None => return not_found("Invalid domain"),
    };

    match std::fs::read_to_string(&path) {
        Ok(text) => axum::Json(json!({ "nginx_config": normalise_config(&text) })).into_response(),
        // FileNotFoundError(str(target)) - the 404's detail is the path.
        Err(_) => not_found(&path.to_string_lossy()),
    }
}

/// Source: `nginx._vhost_path`.
fn vhost_path(state: &AppState, domain: &str) -> Option<PathBuf> {
    let safe = domain.to_lowercase();
    if !is_domain(&safe) {
        return None;
    }
    Some(PathBuf::from(&state.settings.nginx_sites_available).join(format!("{safe}.conf")))
}

/// Source: `nginx.DOMAIN_RE`, as `_vhost_path` applies it - the name goes
/// straight into a filename, so this is what keeps a `../` out of it.
fn is_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').count() >= 2
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Source: the `validate_nginx_config` field validator, which runs on the way
/// **out** as well as in - `WebsiteNginxConfig(nginx_config=...)` validates.
/// So the file's content is normalised before it is returned: CRLF to LF,
/// stripped, and exactly one trailing newline.
fn normalise_config(text: &str) -> String {
    format!("{}\n", text.replace("\r\n", "\n").trim())
}

// ---------------------------------------------------------------------------
// Stage C: the first of the write endpoints
// ---------------------------------------------------------------------------

/// Read the vhost on disk, or `None` if the site has none yet.
///
/// The panel writes this file directly - `/etc/nginx` is root's, but the
/// installer gives the `snpanel` account an ACL on the sites directory, and
/// the Python has always written it with a plain `write_text`. Only the test
/// and the reload go through the helper.
async fn read_vhost(state: &AppState, domain: &str) -> Option<String> {
    let path = vhost_path(state, domain)?;
    tokio::fs::read_to_string(path).await.ok()
}

/// Write a planned vhost, test it, and roll back if nginx refuses it.
///
/// The rollback is the point. `nginx -t` checks the whole configuration, so a
/// file this request wrote can be rejected because of something in it - and
/// leaving it there means the *next* reload, for any site on the box, fails
/// too. The Python restores the previous bytes for exactly that reason.
async fn apply_vhost(state: &AppState, plan: &snpanel_nginx::VhostPlan) -> Result<(), Response> {
    if state.settings.command_dry_run {
        return Ok(());
    }
    if let Err(e) = tokio::fs::write(&plan.path, &plan.content).await {
        tracing::error!("writing {} failed: {e}", plan.path.display());
        return Err(internal_error());
    }
    let test = shell::privileged(false, "nginx-test", &[], None, Some(&["nginx", "-t"])).await;
    if !test.ok() {
        // Put back what was there, or remove a file this request created.
        match &plan.previous {
            Some(old) => {
                let _ = tokio::fs::write(&plan.path, old).await;
            }
            None => {
                let _ = tokio::fs::remove_file(&plan.path).await;
            }
        }
        return Err(bad_request(test.failure_detail("nginx -t failed").trim()));
    }
    let _ = shell::privileged(
        false,
        "nginx-reload",
        &[],
        None,
        Some(&["bash", "-lc", "nginx -t && systemctl reload nginx"]),
    )
    .await;
    Ok(())
}

/// Source: `get_website_log` - which is not `_get_authorized_website`: it
/// looks the site up first and only then decides, so an id that does not
/// exist is a 404 for an administrator and for a customer alike.
async fn logs(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let kind = params
        .get("kind")
        .cloned()
        .unwrap_or_else(|| "access".to_string());
    if kind != "access" && kind != "error" {
        return crate::errors::validation_error(vec![json!({
            "type": "string_pattern_mismatch",
            "loc": ["query", "kind"],
            "msg": "String should match pattern '^(access|error)$'",
            "input": kind,
            "ctx": { "pattern": "^(access|error)$" },
        })]);
    }
    let lines_raw = params
        .get("lines")
        .cloned()
        .unwrap_or_else(|| "200".to_string());
    let lines: i64 = match lines_raw.parse() {
        Ok(n) => n,
        Err(_) => {
            return crate::errors::validation_error(vec![json!({
                "type": "int_parsing",
                "loc": ["query", "lines"],
                "msg": "Input should be a valid integer, unable to parse string as an integer",
                "input": lines_raw,
            })])
        }
    };
    if !(1..=5000).contains(&lines) {
        let (kind_name, msg, ctx) = if lines < 1 {
            (
                "greater_than_equal",
                "Input should be greater than or equal to 1",
                json!({ "ge": 1 }),
            )
        } else {
            (
                "less_than_equal",
                "Input should be less than or equal to 5000",
                json!({ "le": 5000 }),
            )
        };
        return crate::errors::validation_error(vec![json!({
            "type": kind_name,
            "loc": ["query", "lines"],
            "msg": msg,
            "input": lines_raw,
            "ctx": ctx,
        })]);
    }

    let website = match state.db.websites().by_id(website_id).await {
        Ok(Some(w)) => w,
        Ok(None) => return not_found("Website not found"),
        Err(e) => {
            tracing::error!("website lookup failed: {e}");
            return internal_error();
        }
    };
    if website.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return not_enough_permissions();
    }

    let path = format!("/var/log/nginx/{}.{kind}.log", website.domain);
    let lines_arg = lines.to_string();
    let result = shell::privileged(
        state.settings.command_dry_run,
        "site-log-read",
        &[&website.domain, &kind, &lines_arg],
        None,
        Some(&["tail", "-n", &lines_arg, &path]),
    )
    .await;

    // Source: the helper says so on stderr rather than failing, because "no
    // log yet" is the normal state of a site nobody has visited.
    let missing = result.stderr.contains("SNPANEL_LOG_MISSING=1");
    if !result.ok() && !missing {
        return bad_request(result.failure_detail("Cannot read log file").trim());
    }
    axum::Json(json!({
        "domain": website.domain,
        "kind": kind,
        "path": path,
        "lines": lines,
        "content": result.stdout,
        "exists": !missing,
    }))
    .into_response()
}

/// Source: `set_website_nginx_custom` -> `nginx.update_custom_block`.
///
/// The snippet goes into its own include file, not into the vhost; what the
/// vhost gets is the `include` line, positioned after `location /` and before
/// the static-asset location. nginx picks the first matching prefix location,
/// so a customer's `location /assets` has to be seen before the catch-all.
async fn set_nginx_custom(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
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
    let Some(raw) = payload.get("nginx_custom") else {
        return crate::errors::missing_field("nginx_custom", payload.clone());
    };
    let Some(text) = raw.as_str() else {
        return crate::errors::string_type("nginx_custom", raw);
    };

    let website = match state.db.websites().by_id(website_id).await {
        Ok(Some(w)) => w,
        Ok(None) => return not_found("Website not found"),
        Err(e) => {
            tracing::error!("website lookup failed: {e}");
            return internal_error();
        }
    };
    if website.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return not_enough_permissions();
    }

    let validated = match snpanel_nginx::CustomDirectives::validate(text) {
        Ok(v) => v,
        Err(e) => return bad_request(&e.to_string()),
    };

    if !state.settings.command_dry_run {
        let Some(existing) = read_vhost(&state, &website.domain).await else {
            return bad_request(&format!(
                "/etc/nginx/sites-available/{}.conf",
                website.domain
            ));
        };
        let positioned =
            match snpanel_nginx::ensure_custom_include_position(&existing, &website.domain) {
                Ok(p) => p,
                Err(e) => return bad_request(&e.to_string()),
            };
        let write = shell::privileged(
            false,
            "nginx-custom-write",
            &[&website.domain],
            Some(validated.as_str()),
            None,
        )
        .await;
        if !write.ok() {
            return bad_request(
                write
                    .failure_detail("Cannot write the custom nginx block")
                    .trim(),
            );
        }
        if positioned != existing {
            let plan = snpanel_nginx::VhostPlan {
                path: vhost_path(&state, &website.domain).expect("a validated domain"),
                content: positioned,
                previous: Some(existing),
                custom_include: validated.as_str().to_string(),
                custom_include_path: String::new(),
            };
            if let Err(r) = apply_vhost(&state, &plan).await {
                return r;
            }
        } else {
            let test =
                shell::privileged(false, "nginx-test", &[], None, Some(&["nginx", "-t"])).await;
            if !test.ok() {
                return bad_request(test.failure_detail("nginx -t failed").trim());
            }
            let _ = shell::privileged(
                false,
                "nginx-reload",
                &[],
                None,
                Some(&["bash", "-lc", "nginx -t && systemctl reload nginx"]),
            )
            .await;
        }
    }

    if let Err(e) = state
        .db
        .websites()
        .set_nginx_custom(website.id, validated.as_str())
        .await
    {
        tracing::error!("storing the custom nginx block failed: {e}");
        return internal_error();
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "update_nginx_custom",
        &website.domain,
    )
    .await;

    match state.db.websites().by_id(website.id).await {
        Ok(Some(updated)) => single(&state, updated).await,
        _ => internal_error(),
    }
}

/// One website in the `WebsiteOut` shape, with the same two corrections the
/// listing makes: a certificate that appeared on disk turns the flag on, and
/// a WordPress install is detected rather than remembered.
async fn single(state: &AppState, website: snpanel_db::Website) -> Response {
    let aliases = state
        .db
        .websites()
        .aliases(website.id)
        .await
        .unwrap_or_default();
    let probe = website.clone();
    let (live_cert, wordpress) = match tokio::task::spawn_blocking(move || {
        (has_live_certificate(&probe), has_wordpress_install(&probe))
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("the website filesystem checks panicked: {e}");
            return internal_error();
        }
    };
    let ssl_enabled = if !website.ssl_enabled && live_cert {
        if let Err(e) = state.db.websites().set_ssl_enabled(website.id, true).await {
            tracing::warn!("could not record a certificate found on disk: {e}");
        }
        true
    } else {
        website.ssl_enabled
    };
    axum::Json(website_json(&website, &aliases, wordpress, ssl_enabled)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn website() -> snpanel_db::Website {
        snpanel_db::Website {
            id: 1,
            domain: "example.com".into(),
            owner_id: 2,
            root_path: "/home/user/example.com".into(),
            document_root: "public_html".into(),
            linux_user: Some("user".into()),
            php_version: "8.3".into(),
            app_type: "wordpress".into(),
            ssl_enabled: false,
            ssl_mode: "none".into(),
            ssl_cert_path: None,
            ssl_key_path: None,
            ssl_ca_path: None,
            ssl_updated_at: None,
            ssl_source_domain: None,
            status: "active".into(),
            nginx_custom: String::new(),
            nginx_config_mode: "managed".into(),
            nginx_rewrite_mode: "none".into(),
            waf_enabled: true,
            waf_default_rules: String::new(),
            waf_custom_rules: String::new(),
            crs_enabled: false,
            http_flood_enabled: false,
            http_flood_config: String::new(),
            blocked_bots: String::new(),
            app_id: None,
        }
    }

    #[test]
    fn the_certificate_paths_never_reach_the_response() {
        // Field(exclude=True) on all three. They would tell a customer where
        // the server keeps its private keys.
        let mut w = website();
        w.ssl_cert_path = Some("/etc/ssl/site.crt".into());
        w.ssl_key_path = Some("/etc/ssl/site.key".into());
        w.ssl_ca_path = Some("/etc/ssl/chain.pem".into());

        let v = website_json(&w, &[], false, true);
        assert!(v.get("ssl_cert_path").is_none(), "{v}");
        assert!(v.get("ssl_key_path").is_none(), "{v}");
        assert!(v.get("ssl_ca_path").is_none(), "{v}");
        // Only the derived boolean survives.
        assert_eq!(v["ssl_has_ca"], json!(true));
    }

    #[test]
    fn ssl_has_ca_is_false_without_a_chain() {
        let v = website_json(&website(), &[], false, false);
        assert_eq!(v["ssl_has_ca"], json!(false));
    }

    #[test]
    fn an_empty_ssl_mode_is_derived_from_the_flag() {
        let mut w = website();
        w.ssl_mode = String::new();
        assert_eq!(
            website_json(&w, &[], false, true)["ssl_mode"],
            json!("letsencrypt")
        );
        assert_eq!(
            website_json(&w, &[], false, false)["ssl_mode"],
            json!("none")
        );
        // A mode that is set is left alone.
        w.ssl_mode = "cloudflare".into();
        assert_eq!(
            website_json(&w, &[], false, true)["ssl_mode"],
            json!("cloudflare")
        );
    }

    #[test]
    fn a_shared_certificate_is_trusted_rather_than_stat_ed() {
        // It lives under root-only /etc/letsencrypt/live. Stat'ing it as the
        // unprivileged API would answer "no certificate" for every site that
        // has one.
        let mut w = website();
        w.ssl_mode = "cloudflare".into();
        assert!(
            !has_live_certificate(&w),
            "no source domain, no certificate"
        );
        w.ssl_source_domain = Some("example.com".into());
        assert!(has_live_certificate(&w));

        w.ssl_mode = "shared".into();
        assert!(has_live_certificate(&w));
    }

    #[test]
    fn a_manual_certificate_needs_both_files_to_exist() {
        let mut w = website();
        w.ssl_mode = "manual".into();
        assert!(!has_live_certificate(&w), "no paths at all");

        w.ssl_cert_path = Some("/nonexistent/cert.pem".into());
        w.ssl_key_path = Some("/nonexistent/key.pem".into());
        assert!(!has_live_certificate(&w), "paths that do not exist");
    }

    #[test]
    fn a_document_root_that_escapes_the_site_is_refused() {
        // The column is not user input today, but this probe would otherwise
        // stat whatever it names.
        let mut w = website();
        w.document_root = "../../etc".into();
        assert!(!has_wordpress_install(&w));
        w.document_root = "/etc".into();
        assert!(!has_wordpress_install(&w));
    }

    #[test]
    fn wordpress_is_looked_for_rather_than_remembered() {
        // A customer who deletes WordPress by FTP would otherwise leave the
        // panel claiming it is still installed.
        let w = website();
        assert!(!has_wordpress_install(&w), "nothing at that path");
        assert_eq!(
            website_json(&w, &[], false, false)["wordpress_installed"],
            json!(false)
        );
        assert_eq!(
            website_json(&w, &[], true, false)["wordpress_installed"],
            json!(true)
        );
    }

    #[test]
    fn the_aliases_are_rendered_inline() {
        let alias = snpanel_db::WebsiteAlias {
            id: 7,
            website_id: 1,
            domain: "www.example.com".into(),
            mode: "redirect".into(),
            ssl_enabled: true,
            created_at: Some("2026-09-17 10:00:00.000000".into()),
        };
        let v = website_json(&website(), std::slice::from_ref(&alias), false, false);
        let list = v["aliases"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["domain"], json!("www.example.com"));
        assert_eq!(list[0]["mode"], json!("redirect"));
        assert_eq!(list[0]["created_at"], json!("2026-09-17T10:00:00"));
    }

    #[test]
    fn a_config_is_normalised_on_the_way_out_as_well_as_in() {
        // The Pydantic validator runs when the response model is *constructed*,
        // so the file's bytes are not what the endpoint returns.
        assert_eq!(normalise_config("server {}\r\n\r\n"), "server {}\n");
        assert_eq!(normalise_config("  server {}  "), "server {}\n");
        assert_eq!(normalise_config("server {}"), "server {}\n");
        assert_eq!(normalise_config(""), "\n");
    }

    #[test]
    fn a_domain_that_could_escape_the_directory_is_refused() {
        // The name goes straight into a filename.
        for bad in [
            "../../etc/passwd",
            "a/b.conf",
            "",
            "nodot",
            "-leading.example.com",
            "trailing-.example.com",
            "spa ce.example.com",
            "under_score.example.com",
        ] {
            assert!(!is_domain(bad), "{bad:?}");
        }
        for good in ["example.com", "a.b.c.example.com", "xn--80ak6aa92e.com"] {
            assert!(is_domain(good), "{good:?}");
        }
    }

    #[test]
    fn the_credentials_fields_are_null_on_a_read() {
        // They exist so *create* can hand the password back once.
        let v = website_json(&website(), &[], false, false);
        assert_eq!(v["panel_username"], Value::Null);
        assert_eq!(v["panel_password"], Value::Null);
    }
}
