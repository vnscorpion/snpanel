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
use crate::errors::{bad_request, conflict, internal_error, not_enough_permissions, not_found};
use crate::shell;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/websites", get(list).fallback(crate::fallback))
        .route(
            "/websites/{website_id}/aliases",
            get(aliases).post(create_alias).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/aliases/{alias_id}",
            axum::routing::delete(delete_alias).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/nginx-custom",
            get(nginx_custom).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/nginx-config",
            get(nginx_config)
                .put(set_nginx_config)
                .fallback(crate::fallback),
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

// ---------------------------------------------------------------------------
// rewriting a site's vhost, and the alias screens that need it
// ---------------------------------------------------------------------------

/// Source: `site_users.site_php_fpm_socket` - the per-site pool, named after
/// the resolved root so two sites of the same user do not share one.
fn site_fpm_socket(website: &snpanel_db::Website, php_version: Option<&str>) -> Option<String> {
    let user = website.linux_user.as_deref().filter(|u| !u.is_empty())?;
    let version = php_version.filter(|v| !v.is_empty())?;
    let resolved = std::fs::canonicalize(&website.root_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| website.root_path.clone());
    let hash = snpanel_core::types::site_hash(&resolved);
    Some(format!(
        "/run/php/snpanel-{user}-{hash}-{}.sock",
        version.replace('.', "_")
    ))
}

/// Source: `_alias_domains` and `_redirect_domains` - sorted by domain, split
/// by mode, with anything unrecognised treated as an alias.
fn domains_by_mode(aliases: &[snpanel_db::WebsiteAlias], mode: &str) -> Vec<String> {
    let mut rows: Vec<&snpanel_db::WebsiteAlias> = aliases.iter().collect();
    rows.sort_by(|a, b| a.domain.cmp(&b.domain));
    rows.iter()
        .filter(|a| {
            let m = if a.mode.is_empty() { "alias" } else { &a.mode };
            m == mode
        })
        .map(|a| a.domain.clone())
        .collect()
}

/// What a rewrite may override, as `_rewrite_website_vhost`'s keyword
/// arguments do.
#[derive(Default)]
struct RewriteOverrides {
    aliases: Option<Vec<String>>,
    redirects: Option<Vec<String>>,
    custom_directives: Option<String>,
}

/// Source: `_rewrite_website_vhost` followed by `nginx.rewrite_vhost`.
///
/// The overrides matter because the caller often knows something the database
/// does not yet: an alias that has been added inside this transaction and is
/// not committed, for instance.
async fn rewrite_website_vhost(
    state: &AppState,
    website: &snpanel_db::Website,
    overrides: RewriteOverrides,
) -> Result<String, Response> {
    let aliases_rows = state
        .db
        .websites()
        .aliases(website.id)
        .await
        .unwrap_or_default();
    let aliases = overrides
        .aliases
        .unwrap_or_else(|| domains_by_mode(&aliases_rows, "alias"));
    let redirects = overrides
        .redirects
        .unwrap_or_else(|| domains_by_mode(&aliases_rows, "redirect"));
    let custom_text = overrides
        .custom_directives
        .unwrap_or_else(|| website.nginx_custom.clone());
    let custom = snpanel_nginx::CustomDirectives::validate(&custom_text)
        .map_err(|e| bad_request(&e.to_string()))?;

    let app_type = if website.app_type.is_empty() {
        "wordpress"
    } else {
        &website.app_type
    };
    // Source: `runtime_php_version` - a static or proxied site gets no pool.
    let runtime_php = matches!(app_type, "wordpress" | "php")
        .then_some(website.php_version.as_str())
        .filter(|v| !v.is_empty());
    let socket = site_fpm_socket(website, runtime_php);

    let rewrite_mode = if website.nginx_rewrite_mode.is_empty() {
        "none"
    } else {
        &website.nginx_rewrite_mode
    };
    let document_root = if website.document_root.is_empty() {
        "public_html"
    } else {
        &website.document_root
    };

    // Source: `_rewrite_ssl_kwargs` - a manual certificate is passed through;
    // a borrowed one (cloudflare, shared) is resolved from its source domain,
    // which is not ported yet, so those fall back to no explicit paths and
    // `preserve_existing_ssl` keeps whatever certbot left in the file.
    let (cert, key, ca) = if website.ssl_mode == "manual" {
        (
            website.ssl_cert_path.clone(),
            website.ssl_key_path.clone(),
            website.ssl_ca_path.clone(),
        )
    } else {
        (None, None, None)
    };

    let root_path = std::path::PathBuf::from(&website.root_path);
    let mut input = snpanel_nginx::VhostInput::new(&website.domain, &root_path, &custom);
    input.app_type = app_type;
    input.php_version = runtime_php;
    input.php_fpm_socket_override = socket.as_deref();
    input.waf_enabled = website.waf_enabled;
    input.http_flood_enabled = website.http_flood_enabled;
    input.http_flood_config = snpanel_nginx::HttpFloodConfig::from_text(&website.http_flood_config);
    input.document_root = document_root;
    input.rewrite_mode = Some(rewrite_mode);
    input.ssl_cert_path = cert.as_deref();
    input.ssl_key_path = key.as_deref();
    input.ssl_ca_path = ca.as_deref();
    input.aliases = &aliases;
    input.redirects = &redirects;

    let env = snpanel_nginx::VhostEnv {
        ipv6: crate::system::ipv6_enabled(),
        waf_engine: crate::system::waf_engine_available(),
        default_php_version: state.settings.default_php_version.clone(),
        home_root: std::path::PathBuf::from("/home"),
    };
    let sites = std::path::PathBuf::from(&state.settings.nginx_sites_available);
    let existing = read_vhost(state, &website.domain).await;
    let plan = snpanel_nginx::plan_rewrite(&input, &env, &sites, existing.as_deref(), true)
        .map_err(|e| bad_request(&e.to_string()))?;

    // The customer's snippet goes to its own include file, through the helper.
    if !state.settings.command_dry_run {
        let write = shell::privileged(
            false,
            "nginx-custom-write",
            &[&website.domain],
            Some(plan.custom_include.as_str()),
            None,
        )
        .await;
        if !write.ok() {
            return Err(bad_request(
                write.failure_detail("Cannot write Nginx config").trim(),
            ));
        }
    }
    apply_vhost(state, &plan).await?;
    Ok(plan.path.to_string_lossy().into_owned())
}

/// Source: `ssl.cert_info` - read through the helper, because
/// `/etc/letsencrypt/live` is root's.
async fn cert_sans(state: &AppState, domain: &str) -> Vec<String> {
    let probe = format!("echo 'no cert info for {domain}'; exit 1");
    let result = shell::privileged(
        state.settings.command_dry_run,
        "ssl-cert-info",
        &[domain],
        None,
        Some(&["bash", "-lc", &probe]),
    )
    .await;
    if !result.ok() {
        return Vec::new();
    }
    for line in result.stdout.lines() {
        if let Some(value) = line.strip_prefix("sans=") {
            return value
                .trim()
                .split(',')
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .collect();
        }
    }
    Vec::new()
}

/// Source: `ssl._hostname_matches` - an exact name, or a wildcard that covers
/// exactly one more label.
fn hostname_matches(domain: &str, pattern: &str) -> bool {
    if pattern == domain {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix('*') else {
        return false;
    };
    if !pattern.starts_with("*.") {
        return false;
    }
    domain.ends_with(suffix) && domain.matches('.').count() == suffix.matches('.').count()
}

/// Source: `ssl.cert_covers`.
fn cert_covers(sans: &[String], domain: &str) -> bool {
    let target = domain.trim().to_ascii_lowercase();
    sans.iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .any(|n| hostname_matches(&target, &n))
}

/// Source: `_sync_alias_ssl_flags`.
///
/// `issue_ssl` can succeed overall while dropping one requested name - bad or
/// not-yet-pointed DNS, through certbot's `--allow-subset-of-names` - and a
/// plain "Added alias" toast then tells the administrator nothing went wrong
/// for that name, even though it still has no working certificate.
async fn sync_alias_ssl_flags(state: &AppState, website: &snpanel_db::Website) {
    if website.ssl_mode != "letsencrypt" {
        return;
    }
    let sans = cert_sans(state, &website.domain).await;
    let aliases = state
        .db
        .websites()
        .aliases(website.id)
        .await
        .unwrap_or_default();
    for alias in aliases {
        let covered = !sans.is_empty() && cert_covers(&sans, &alias.domain);
        if covered != alias.ssl_enabled {
            if let Err(e) = state
                .db
                .websites()
                .alias_set_ssl_enabled(alias.id, covered)
                .await
            {
                tracing::warn!("could not record alias certificate coverage: {e}");
            }
        }
    }
}

/// Source: `set_website_nginx_config`, which refuses every call.
///
/// Ported as the 405 it is. The route exists so the frontend gets the message
/// rather than a 404, and the message is the whole behaviour.
async fn set_nginx_config() -> Response {
    (
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        axum::Json(json!({
            "detail": "The main Nginx vhost is managed by SNPanel. Use Custom Nginx instead."
        })),
    )
        .into_response()
}

/// Source: `create_website_alias`.
async fn create_alias(
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
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let Some(domain_raw) = payload.get("domain") else {
        return crate::errors::missing_field("domain", payload.clone());
    };
    let Some(domain) = domain_raw.as_str() else {
        return crate::errors::string_type("domain", domain_raw);
    };
    let mode = payload
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("alias")
        .to_string();

    // Source: `payload.domain == website.domain or _hostname_conflicts(...)`.
    if domain == website.domain {
        return conflict("Domain alias already exists");
    }
    match state.db.websites().hostname_taken(domain, None, None).await {
        Ok(true) => return conflict("Domain alias already exists"),
        Ok(false) => {}
        Err(e) => {
            tracing::error!("hostname conflict check failed: {e}");
            return internal_error();
        }
    }

    let created = match state
        .db
        .websites()
        .alias_create(website.id, domain, &mode)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!("creating an alias failed: {e}");
            return internal_error();
        }
    };

    // The vhost is rewritten with the new name already in the list. If that
    // fails the alias goes again - the Python rolls its transaction back, and
    // leaving a row whose name nginx does not serve would be worse than
    // refusing.
    let rows = state
        .db
        .websites()
        .aliases(website.id)
        .await
        .unwrap_or_default();
    let overrides = RewriteOverrides {
        aliases: Some(domains_by_mode(&rows, "alias")),
        redirects: Some(domains_by_mode(&rows, "redirect")),
        custom_directives: None,
    };
    if let Err(r) = rewrite_website_vhost(&state, &website, overrides).await {
        let _ = state
            .db
            .websites()
            .alias_delete(website.id, created.id)
            .await;
        return r;
    }
    // No certificate is issued here, and that is the same split DirectAdmin
    // uses: adding a domain wires it into nginx now, and a certificate that
    // covers it is an explicit step on the SSL page. Issuing one here would
    // make this request's success depend on that domain's DNS being ready
    // this second.
    sync_alias_ssl_flags(&state, &website).await;

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "create_website_alias",
        &website.domain,
    )
    .await;
    axum::Json(alias_json(&created)).into_response()
}

/// Source: `delete_website_alias`.
async fn delete_alias(
    State(state): State<AppState>,
    Path((website_id, alias_id)): Path<(i64, i64)>,
    req: Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let alias = match state.db.websites().alias_by_id(website.id, alias_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return not_found("Alias not found"),
        Err(e) => {
            tracing::error!("alias lookup failed: {e}");
            return internal_error();
        }
    };

    let rows = state
        .db
        .websites()
        .aliases(website.id)
        .await
        .unwrap_or_default();
    let keep = |mode: &str| -> Vec<String> {
        domains_by_mode(&rows, mode)
            .into_iter()
            .filter(|d| d != &alias.domain)
            .collect()
    };
    let overrides = RewriteOverrides {
        aliases: Some(keep("alias")),
        redirects: Some(keep("redirect")),
        custom_directives: None,
    };
    // nginx first: a row removed from a vhost that still serves the name is
    // recoverable; a name nginx still claims with no row behind it is not.
    if let Err(r) = rewrite_website_vhost(&state, &website, overrides).await {
        return r;
    }
    match state.db.websites().alias_delete(website.id, alias_id).await {
        Ok(true) => {}
        Ok(false) => return not_found("Alias not found"),
        Err(e) => {
            tracing::error!("deleting an alias failed: {e}");
            return internal_error();
        }
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "delete_website_alias",
        &website.domain,
    )
    .await;
    axum::Json(json!({ "ok": true })).into_response()
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

    /// A wildcard rule got slightly wrong is either a site the panel calls
    /// unprotected when it is not, or - worse - one it reports as covered
    /// when the browser will disagree. The answers come from the real
    /// `ssl._hostname_matches` and `ssl.cert_covers`.
    #[test]
    fn certificate_coverage_agrees_with_python() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/hostname_match.json");
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the hostname corpus"))
                .expect("the corpus parses");

        let matches = corpus["matches"].as_array().expect("the match cases");
        assert!(matches.len() > 50, "the corpus shrank to {}", matches.len());
        let mut failures: Vec<String> = Vec::new();
        for case in matches {
            let domain = case["domain"].as_str().unwrap_or("");
            let pattern = case["pattern"].as_str().unwrap_or("");
            let want = case["result"].as_bool().unwrap_or(false);
            let got = hostname_matches(domain, pattern);
            if got != want {
                failures.push(format!(
                    "{domain:?} vs {pattern:?}: python {want}, rust {got}"
                ));
            }
        }

        let covers = corpus["covers"].as_array().expect("the cover cases");
        for case in covers {
            let Some(want) = case["result"].as_bool() else {
                continue; // Python raised; not a case this compares.
            };
            let sans: Vec<String> = case["sans"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let domain = case["domain"].as_str().unwrap_or("");
            let got = cert_covers(&sans, domain);
            if got != want {
                failures.push(format!(
                    "cert_covers({sans:?}, {domain:?}): python {want}, rust {got}"
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
