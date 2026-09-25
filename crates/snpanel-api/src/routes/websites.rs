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
use axum::routing::{get, post};
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
        .route(
            "/websites",
            get(list).post(create_website).fallback(crate::fallback),
        )
        .route(
            "/websites/wordpress",
            post(create_wordpress).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/wordpress",
            post(install_wordpress_on_website).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}",
            axum::routing::delete(delete_website)
                .patch(update_website)
                .fallback(crate::fallback),
        )
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
            get(nginx_custom)
                .put(set_nginx_custom)
                .fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/nginx-config",
            get(nginx_config)
                .put(set_nginx_config)
                .fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/http-flood",
            axum::routing::patch(set_http_flood).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/fix-nginx-security",
            axum::routing::post(fix_nginx_security).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/nginx-config/reset",
            axum::routing::post(reset_nginx_config).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/ssl",
            post(enable_ssl).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/ssl/cloudflare-zone",
            get(cloudflare_zone).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/ssl/manual",
            post(install_manual_ssl).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/ssl/shared",
            post(install_shared_ssl).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/ssl/wildcard",
            post(install_wildcard_ssl).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/ssl/sources",
            get(ssl_sources).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/waf",
            axum::routing::patch(set_waf).fallback(crate::fallback),
        )
        .route(
            "/websites/{website_id}/logs",
            get(logs).fallback(crate::fallback),
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

/// Source: `nginx.update_custom_block`.
///
/// Write the customer's snippet to its own include file, then make sure the
/// vhost includes it **in the right place** — and rewrite the vhost only if
/// the include line moved. When it did not, the file is left alone and only
/// tested and reloaded: rewriting a file that does not need it is a backup
/// taken, a window where the file is half-written, and a diff for an
/// administrator to wonder about.
///
/// Two endpoints call this: `PUT /websites/{id}/nginx-custom` and the
/// `nginx_custom` branch of `PATCH /websites/{id}`.
async fn update_custom_block(
    state: &AppState,
    domain: &str,
    validated: &snpanel_nginx::CustomDirectives,
) -> Result<(), Response> {
    if state.settings.command_dry_run {
        return Ok(());
    }
    let Some(existing) = read_vhost(state, domain).await else {
        // Source: `FileNotFoundError(str(target))` — the Python's message is
        // the path and nothing else.
        return Err(bad_request(&format!(
            "/etc/nginx/sites-available/{domain}.conf"
        )));
    };
    let positioned = snpanel_nginx::ensure_custom_include_position(&existing, domain)
        .map_err(|e| bad_request(&e.to_string()))?;
    let write = shell::privileged(
        false,
        "nginx-custom-write",
        &[domain],
        Some(validated.as_str()),
        None,
    )
    .await;
    if !write.ok() {
        return Err(bad_request(
            write
                .failure_detail("Cannot write the custom nginx block")
                .trim(),
        ));
    }
    if positioned != existing {
        let plan = snpanel_nginx::VhostPlan {
            path: vhost_path_for(state, domain).expect("a validated domain"),
            content: positioned,
            previous: Some(existing),
            custom_include: validated.as_str().to_string(),
            custom_include_path: String::new(),
        };
        return apply_vhost(state, &plan).await;
    }
    let test = shell::privileged(false, "nginx-test", &[], None, Some(&["nginx", "-t"])).await;
    if !test.ok() {
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

    let path = match vhost_path_for(&state, &website.domain) {
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
pub(super) fn vhost_path_for(state: &AppState, domain: &str) -> Option<PathBuf> {
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
    let path = vhost_path_for(state, domain)?;
    tokio::fs::read_to_string(path).await.ok()
}

/// Source: `nginx._write_backup` - `<vhost>.conf.bak`, written through a
/// temporary file in the same directory so the backup is never a half-written
/// file, and `0640` because it is a copy of a root-owned config.
///
/// Best effort: the Python lets a backup failure through to the write, and a
/// site must not become uneditable because the directory filled up.
async fn write_vhost_backup(path: &std::path::Path, previous: &str) {
    let Some(dir) = path.parent() else { return };
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return;
    };
    let temp = dir.join(format!(".{name}.bak-{}", std::process::id()));
    if tokio::fs::write(&temp, previous).await.is_err() {
        return;
    }
    let _ = tokio::fs::set_permissions(&temp, std::os::unix::fs::PermissionsExt::from_mode(0o640))
        .await;
    let _ = tokio::fs::rename(&temp, path.with_extension("conf.bak")).await;
}

/// Write a planned vhost, test it, and roll back if nginx refuses it.
///
/// The rollback is the point. `nginx -t` checks the whole configuration, so a
/// file this request wrote can be rejected because of something in it - and
/// leaving it there means the *next* reload, for any site on the box, fails
/// too. The Python restores the previous bytes for exactly that reason.
async fn apply_vhost(state: &AppState, plan: &snpanel_nginx::VhostPlan) -> Result<(), Response> {
    apply_vhost_message(state, plan).await.map_err(|message| {
        if message.starts_with("internal:") {
            internal_error()
        } else {
            bad_request(&message)
        }
    })
}

/// [`apply_vhost`], returning the failure **text** rather than a built
/// response.
///
/// The bot endpoints write several vhosts in one request and report which
/// ones failed, so they need the message rather than a `Response` they cannot
/// look inside.
pub(super) async fn apply_vhost_plan(
    state: &AppState,
    plan: snpanel_nginx::VhostPlan,
) -> Result<(), String> {
    apply_vhost_message(state, &plan).await
}

async fn apply_vhost_message(
    state: &AppState,
    plan: &snpanel_nginx::VhostPlan,
) -> Result<(), String> {
    if state.settings.command_dry_run {
        return Ok(());
    }
    // Source: `_write_backup(target, existing)`, which every vhost writer in
    // the Python calls before it overwrites. This was missing: the rollback
    // below restores the previous bytes when `nginx -t` refuses, but a write
    // that *succeeds* and turns out to be wrong later left an administrator
    // with nothing to go back to.
    if let Some(previous) = &plan.previous {
        write_vhost_backup(&plan.path, previous).await;
    }
    if let Err(e) = tokio::fs::write(&plan.path, &plan.content).await {
        tracing::error!("writing {} failed: {e}", plan.path.display());
        return Err("internal:could not write the vhost".to_string());
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
        return Err(test.failure_detail("nginx -t failed").trim().to_string());
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

    if let Err(r) = update_custom_block(&state, &website.domain, &validated).await {
        return r;
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

/// Which certificate paths a rewrite writes into the file.
///
/// Source: `_rewrite_website_vhost` - `if overrides.pop("include_ssl", True):
/// rewrite_kwargs.update(_rewrite_ssl_kwargs(website))`.
///
/// `include_ssl` and `preserve_existing_ssl` are **different switches** and
/// only one of them is thrown on any given path. Suspension throws the
/// second: the certificate paths certbot left in the file are not carried
/// into a vhost deliberately serving nothing, but a suspended site on an
/// uploaded certificate still names it, because the row still says that is
/// what it has. The Let's Encrypt path throws the first: the file is
/// rewritten with no certificate at all, because certbot is about to edit it
/// and the uploaded files are about to be deleted.
fn vhost_ssl_paths(
    website: &snpanel_db::Website,
    overrides: &RewriteOverrides,
) -> (Option<String>, Option<String>, Option<String>) {
    if overrides.include_ssl == Some(false) {
        return (None, None, None);
    }
    rewrite_ssl_paths(website)
}

/// Source: `_rewrite_ssl_kwargs`.
///
/// Which certificate this site's vhost should point at, by mode.
fn rewrite_ssl_paths(
    website: &snpanel_db::Website,
) -> (Option<String>, Option<String>, Option<String>) {
    let filled = |v: &Option<String>| v.clone().filter(|s| !s.is_empty());
    if website.ssl_mode == "manual" {
        let cert = filled(&website.ssl_cert_path);
        let key = filled(&website.ssl_key_path);
        if cert.is_some() && key.is_some() {
            return (cert, key, filled(&website.ssl_ca_path));
        }
        return (None, None, None);
    }
    if matches!(website.ssl_mode.as_str(), "cloudflare" | "shared") {
        if let Some(source) = filled(&website.ssl_source_domain) {
            return borrowed_ssl_paths(&source);
        }
    }
    (None, None, None)
}

/// Source: `_borrowed_ssl_paths` - where the certificate a site is *borrowing*
/// actually lives.
///
/// Its own manual directory first, because that one is group-readable by the
/// panel and can be checked. Otherwise the source's certbot lineage, returned
/// **unchecked**: `/etc/letsencrypt/live` is root-only, so stat'ing it as
/// `snpanel` answers "no certificate" for every site that has one. Whoever put
/// this site into shared or cloudflare mode has already verified the
/// certificate through the helper.
fn borrowed_ssl_paths(source_domain: &str) -> (Option<String>, Option<String>, Option<String>) {
    borrowed_ssl_paths_with(source_domain, |p| PathBuf::from(p).is_file())
}

/// [`borrowed_ssl_paths`] with the existence check handed in.
///
/// It is an argument so the choice can be tested without a filesystem: a test
/// that stats real paths is true on any machine where those paths do not
/// exist, whatever the code under it says.
fn borrowed_ssl_paths_with(
    source_domain: &str,
    exists: impl Fn(&str) -> bool,
) -> (Option<String>, Option<String>, Option<String>) {
    let (cert, key, ca) = manual_ssl_paths(source_domain);
    if exists(&cert) && exists(&key) {
        let ca = exists(&ca).then_some(ca);
        return (Some(cert), Some(key), ca);
    }
    let live = PathBuf::from("/etc/letsencrypt/live").join(source_domain);
    (
        Some(live.join("fullchain.pem").to_string_lossy().into_owned()),
        Some(live.join("privkey.pem").to_string_lossy().into_owned()),
        None,
    )
}

/// What a rewrite may override, as `_rewrite_website_vhost`'s keyword
/// arguments do.
#[derive(Default)]
pub(super) struct RewriteOverrides {
    pub(super) aliases: Option<Vec<String>>,
    pub(super) redirects: Option<Vec<String>>,
    pub(super) custom_directives: Option<String>,
    /// Suspension renders the site as `static`, whatever it really is, so
    /// nothing dynamic runs while the account is blocked.
    pub(super) app_type: Option<&'static str>,
    pub(super) rewrite_mode: Option<&'static str>,
    /// `preserve_existing_ssl=False` on the suspend path: the certificate
    /// paths certbot left in the file are not carried into a vhost that is
    /// deliberately serving nothing.
    pub(super) preserve_existing_ssl: Option<bool>,
    /// `include_ssl=False` on the Let's Encrypt path: the file is rewritten
    /// **without** a certificate on purpose, because `certbot --nginx` edits a
    /// plain HTTP server block and cannot work from one that already claims to
    /// serve TLS from a file that is about to be deleted.
    pub(super) include_ssl: Option<bool>,
    /// The loopback port a proxied site is sent to.
    ///
    /// Defaulted from the app the site points at, which is what
    /// `app_port_for_website` does. An override is for the caller that knows
    /// something the row does not yet — an application whose port has just
    /// moved.
    pub(super) app_port: Option<i64>,
}

/// `log_action(db, user.id, action, target)` - a detail of `""` and no
/// request, which is how these two endpoints call it.
///
/// `packages::audit_action` is the other shape, with `ip=` and `ua=` and no
/// detail. Both exist in the Python and which one is right differs per
/// endpoint; this is the one the Python uses here.
async fn audit_website(state: &AppState, actor_id: i64, action: &str, target: &str) {
    if let Err(e) = state
        .db
        .audits()
        .log(Some(actor_id), action, target, "")
        .await
    {
        tracing::error!("could not write the {action} audit entry: {e}");
    }
}

/// [`rewrite_website_vhost`] for another router.
///
/// `users::suspend` renders every site a customer owns, and it renders them
/// through this rather than through a copy: the suspended shape differs only
/// in its overrides, and a second renderer is how two of them drift apart.
pub(super) async fn rewrite_owned_vhost(
    state: &AppState,
    website: &snpanel_db::Website,
    overrides: RewriteOverrides,
) -> Result<String, String> {
    rewrite_website_vhost(state, website, overrides)
        .await
        .map_err(|_| format!("could not rewrite the vhost for {}", website.domain))
}

/// Source: `_rewrite_website_vhost` followed by `nginx.rewrite_vhost`.
///
/// The overrides matter because the caller often knows something the database
/// does not yet: an alias that has been added inside this transaction and is
/// not committed, for instance.
pub(super) async fn rewrite_website_vhost(
    state: &AppState,
    website: &snpanel_db::Website,
    overrides: RewriteOverrides,
) -> Result<String, Response> {
    // Read before anything moves a field out of `overrides`.
    let (cert, key, ca) = vhost_ssl_paths(website, &overrides);
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

    let app_type = match overrides.app_type {
        Some(forced) => forced,
        None if website.app_type.is_empty() => "wordpress",
        None => &website.app_type,
    };
    // Source: `runtime_php_version` - a static or proxied site gets no pool.
    // It decides the **socket** and nothing else: the version handed to the
    // renderer below is the row's, whatever the app type, because
    // `_check_php_version` runs on it and a `None` would skip that check.
    let runtime_php = matches!(app_type, "wordpress" | "php")
        .then_some(website.php_version.as_str())
        .filter(|v| !v.is_empty());
    let socket = site_fpm_socket(website, runtime_php);
    let declared_php = Some(website.php_version.as_str()).filter(|v| !v.is_empty());

    let rewrite_mode = match overrides.rewrite_mode {
        Some(forced) => forced,
        None if website.nginx_rewrite_mode.is_empty() => "none",
        None => &website.nginx_rewrite_mode,
    };
    let document_root = if website.document_root.is_empty() {
        "public_html"
    } else {
        &website.document_root
    };

    // Source: `app_port=overrides.pop("app_port", site_apps.app_port_for_website(website))`.
    // Without it a proxied vhost has no upstream and `_check_app_port`
    // refuses to render one at all.
    let app_port = match overrides.app_port {
        Some(port) => Some(port),
        None => match website.app_id {
            Some(app_id) => state
                .db
                .site_apps()
                .by_id(app_id)
                .await
                .ok()
                .flatten()
                .map(|app| app.port),
            None => None,
        },
    };

    let root_path = std::path::PathBuf::from(&website.root_path);
    let mut input = snpanel_nginx::VhostInput::new(&website.domain, &root_path, &custom);
    input.app_type = app_type;
    input.app_port = app_port;
    input.php_version = declared_php;
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
    let plan = snpanel_nginx::plan_rewrite(
        &input,
        &env,
        &sites,
        existing.as_deref(),
        overrides.preserve_existing_ssl.unwrap_or(true),
    )
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

/// The names a certificate covers, from [`cert_info`].
async fn cert_sans(state: &AppState, domain: &str) -> Vec<String> {
    cert_info(state, domain).await.1
}

/// Source: `ssl._hostname_matches` - an exact name, or a wildcard that covers
/// exactly one more label.
pub(crate) fn hostname_matches(domain: &str, pattern: &str) -> bool {
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
        ..RewriteOverrides::default()
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
        ..RewriteOverrides::default()
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

// ---------------------------------------------------------------------------
// the WAF switch
// ---------------------------------------------------------------------------

/// Source: `panel_settings.crs_mode()` - the server-wide OWASP CRS mode.
///
/// Read straight from the settings file rather than through the whole of
/// `current_settings`, for the reason the Python gives: this is consulted on
/// every vhost and site-rule render, and refreshing a malware scan status to
/// get one string would be a poor trade.
fn server_crs_mode() -> String {
    let dir = std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into());
    std::fs::read_to_string(std::path::Path::new(&dir).join("panel-settings.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| {
            value
                .get("crs_mode")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default()
        .trim()
        .to_lowercase()
}

/// Source: `api.waf.may_manage_waf`, which needs the caller's package.
async fn may_manage_waf(state: &AppState, current: &CurrentUser) -> bool {
    // The package flag, when there is a package to read it from. A row that
    // cannot be read is not a refusal: the Python's `getattr(package,
    // "waf_enabled", True)` defaults the same way, and so does an account with
    // no package at all.
    let flag = match current.user.package_id {
        Some(id) => match state.db.packages().by_id(id).await {
            Ok(Some(package)) => Some(package.waf_enabled),
            _ => None,
        },
        None => None,
    };
    crate::waf::may_manage_waf(&current.user.role, flag)
}

/// Source: `nginx.update_waf_block` - swap the WAF block in this site's vhost.
///
/// Under `COMMAND_DRY_RUN` the Python renders the replacement against a stub
/// server block and returns without touching anything, which is why a dry run
/// does not need the file to exist.
pub(super) async fn update_waf_block(
    state: &AppState,
    domain: &str,
    enabled: bool,
) -> Result<(), Response> {
    if state.settings.command_dry_run {
        return Ok(());
    }
    let Some(path) = vhost_path_for(state, domain) else {
        return Err(bad_request("Invalid domain"));
    };
    let Some(existing) = read_vhost(state, domain).await else {
        // Source: `raise FileNotFoundError(str(target))`, which the router
        // catches alongside ValueError and turns into a 400.
        return Err(bad_request(&path.to_string_lossy()));
    };
    // `waf_engine` is whether nginx has the ModSecurity module at all. A
    // block that turns the WAF on where the module is absent does not fail
    // safe - it fails `nginx -t`, and the next reload takes every site down.
    let engine = crate::system::waf_engine_available();
    let updated = match snpanel_nginx::replace_waf_block(&existing, enabled, Some(domain), engine) {
        Ok(text) => text,
        Err(e) => return Err(bad_request(&e.to_string())),
    };
    apply_vhost(
        state,
        &snpanel_nginx::VhostPlan {
            path,
            content: updated,
            previous: Some(existing),
            custom_include: String::new(),
            custom_include_path: String::new(),
        },
    )
    .await
}

/// Source: `set_website_waf`.
///
/// The order is the Python's and it is not arbitrary: the rule file is written
/// first, then the vhost block that includes it, and only then the column. A
/// vhost that points at a rule file which was never written fails `nginx -t`,
/// and a column that says "on" for a site whose vhost was never changed is a
/// customer told they are protected when they are not.
async fn set_waf(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    req: axum::extract::Request,
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
    if !may_manage_waf(&state, &current).await {
        return crate::errors::error(
            axum::http::StatusCode::FORBIDDEN,
            "Your hosting package does not include WAF settings",
        );
    }
    let Some(raw) = payload.get("waf_enabled") else {
        return crate::errors::missing_field("waf_enabled", payload.clone());
    };
    let waf_enabled = match crate::errors::read_bool("waf_enabled", Some(raw), false) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // `sync_website_rules` renders from the site's **stored** flags, not from
    // the one being set. That is the Python's behaviour: the rule file is
    // brought up to date, and whether nginx loads it is what the block below
    // decides.
    let result = match crate::waf::sync_website_rules(
        state.settings.command_dry_run,
        &website,
        &server_crs_mode(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return bad_request(&e.to_string()),
    };
    if !result.ok() {
        return bad_request(result.failure_detail("Could not write WAF rules").trim());
    }
    if let Err(r) = update_waf_block(&state, &website.domain, waf_enabled).await {
        return r;
    }

    if let Err(e) = state
        .db
        .websites()
        .set_waf_enabled(website.id, waf_enabled)
        .await
    {
        tracing::error!("storing the WAF flag failed: {e}");
        return internal_error();
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "update_waf",
        &website.domain,
    )
    .await;

    match state.db.websites().by_id(website.id).await {
        Ok(Some(fresh)) => single(&state, fresh).await,
        Ok(None) => not_found("Website not found"),
        Err(e) => {
            tracing::error!("re-reading the website failed: {e}");
            internal_error()
        }
    }
}

/// Source: `_sync_http_flood_zones` - re-render the server-wide zone file
/// from **every** website, not just the one being changed.
///
/// It has to be every one: the file is shared, so writing it from a single
/// site would drop the zones of all the others, and the next reload would fail
/// for every vhost that names one.
async fn sync_http_flood_zones(state: &AppState) -> Result<(), Response> {
    sync_flood_zones(state)
        .await
        .map_err(|why| bad_request(&why))
}

/// The same write, for a caller that has to print the reason rather than
/// return it.
///
/// Source: the same `nginx.sync_http_flood_zones`. The eleven handlers above
/// go through [`sync_http_flood_zones`], which turns this into the response
/// they always made.
pub(super) async fn sync_flood_zones(state: &AppState) -> Result<(), String> {
    let websites = state.db.websites().list(None, "").await.map_err(|e| {
        tracing::error!("listing websites for the flood zones failed: {e}");
        format!("could not list the websites for the flood zones: {e}")
    })?;

    let configs: Vec<(String, bool, snpanel_nginx::HttpFloodConfig)> = websites
        .iter()
        .map(|w| {
            (
                w.domain.clone(),
                w.http_flood_enabled,
                crate::waf::http_flood_config(w),
            )
        })
        .collect();
    let sites: Vec<snpanel_nginx::FloodSite<'_>> = configs
        .iter()
        .map(|(domain, enabled, config)| snpanel_nginx::FloodSite {
            domain,
            enabled: *enabled,
            config: *config,
        })
        .collect();
    let content = snpanel_nginx::render_http_flood_zones(&sites).map_err(|e| e.to_string())?;

    let result = shell::privileged(
        state.settings.command_dry_run,
        "http-flood-zones-save",
        &[],
        Some(&content),
        Some(&[
            "bash",
            "-lc",
            "cat >/tmp/snpanel-http-flood-zones.conf && echo HTTP flood zones saved",
        ]),
    )
    .await;
    if result.ok() {
        Ok(())
    } else {
        Err(result
            .failure_detail("Could not save HTTP flood zones")
            .trim()
            .to_string())
    }
}

/// Re-render this site's WAF rule file from its stored flags.
///
/// Shared by the two endpoints below, which both start by bringing the rule
/// file up to date before they touch the vhost.
async fn resync_site_waf(state: &AppState, website: &snpanel_db::Website) -> Result<(), Response> {
    let result =
        crate::waf::sync_website_rules(state.settings.command_dry_run, website, &server_crs_mode())
            .await
            .map_err(|e| bad_request(&e.to_string()))?;
    if !result.ok() {
        return Err(bad_request(
            result.failure_detail("Could not write WAF rules").trim(),
        ));
    }
    Ok(())
}

/// Source: `fix_nginx_security`.
///
/// Note what this is *not*: it does not look the site up through
/// `_get_authorized_website`. It fetches first and decides after, so an id
/// that does not exist is a 404 for an administrator and a customer alike.
async fn fix_nginx_security(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = resync_site_waf(&state, &website).await {
        return r;
    }
    // Only when this site has flood protection on. The file is shared, but
    // the Python does not re-render it for a site that contributes nothing.
    if website.http_flood_enabled {
        if let Err(r) = sync_http_flood_zones(&state).await {
            return r;
        }
    }
    let target = match rewrite_website_vhost(&state, &website, RewriteOverrides::default()).await {
        Ok(path) => path,
        Err(r) => return r,
    };

    audit_website(
        &state,
        current.user.id,
        "fix_nginx_security",
        &website.domain,
    )
    .await;
    axum::Json(json!({
        "message": format!("Rewrote Nginx security template for {}", website.domain),
        "path": target,
    }))
    .into_response()
}

/// Source: `reset_website_nginx_config` - throw away the customer's own
/// directives and go back to the managed template.
///
/// Administrator only, unlike `fix-nginx-security`: this discards whatever the
/// site owner wrote in the custom block, and `ensure_role` is checked *before*
/// the website is looked up, so a customer gets a 403 rather than learning
/// whether the id exists.
async fn reset_nginx_config(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return not_enough_permissions();
    }
    let website = match state.db.websites().by_id(website_id).await {
        Ok(Some(w)) => w,
        Ok(None) => return not_found("Website not found"),
        Err(e) => {
            tracing::error!("website lookup failed: {e}");
            return internal_error();
        }
    };

    if let Err(r) = resync_site_waf(&state, &website).await {
        return r;
    }
    if website.http_flood_enabled {
        if let Err(r) = sync_http_flood_zones(&state).await {
            return r;
        }
    }
    // The empty custom block is the whole point: the vhost is rewritten with
    // nothing from the customer in it, and only then is the column cleared.
    // Clearing the column first would leave a site whose stored config says
    // "managed" while the file on disk still carries the old directives.
    if let Err(r) = rewrite_website_vhost(
        &state,
        &website,
        RewriteOverrides {
            custom_directives: Some(String::new()),
            ..RewriteOverrides::default()
        },
    )
    .await
    {
        return r;
    }

    if let Err(e) = state.db.websites().reset_nginx_custom(website.id).await {
        tracing::error!("clearing the custom nginx block failed: {e}");
        return internal_error();
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "reset_nginx_config",
        &website.domain,
    )
    .await;

    match state.db.websites().by_id(website.id).await {
        Ok(Some(fresh)) => single(&state, fresh).await,
        Ok(None) => not_found("Website not found"),
        Err(e) => {
            tracing::error!("re-reading the website failed: {e}");
            internal_error()
        }
    }
}

/// `json.dumps(config, ensure_ascii=True)` for the flood config, byte for
/// byte.
///
/// Two things serde would get wrong on its own: Python's default separators
/// put a space after the comma and after the colon, and the key order is the
/// dict's insertion order from `validate_http_flood_config` rather than
/// alphabetical. Both parse back the same; both are what a shadow diff
/// compares in the `http_flood_config` column.
fn flood_config_json(config: &snpanel_nginx::HttpFloodConfig) -> String {
    format!(
        "{{\"access_limit_requests\": {}, \"access_limit_window\": {}, \
         \"access_limit_burst\": {}, \"connection_limit\": {}}}",
        config.access_limit_requests,
        config.access_limit_window,
        config.access_limit_burst,
        config.connection_limit
    )
}

/// Source: `nginx.update_http_flood_block`.
async fn update_http_flood_block(
    state: &AppState,
    domain: &str,
    enabled: bool,
    config: &snpanel_nginx::HttpFloodConfig,
) -> Result<(), Response> {
    if state.settings.command_dry_run {
        return Ok(());
    }
    let Some(path) = vhost_path_for(state, domain) else {
        return Err(bad_request("Invalid domain"));
    };
    let Some(existing) = read_vhost(state, domain).await else {
        return Err(bad_request(&path.to_string_lossy()));
    };
    let updated =
        match snpanel_nginx::replace_http_flood_block(&existing, enabled, Some(domain), config) {
            Ok(text) => text,
            Err(e) => return Err(bad_request(&e.to_string())),
        };
    apply_vhost(
        state,
        &snpanel_nginx::VhostPlan {
            path,
            content: updated,
            previous: Some(existing),
            custom_include: String::new(),
            custom_include_path: String::new(),
        },
    )
    .await
}

/// Source: `_http_flood_payload_config`, with the ranges pydantic enforces.
///
/// Out of range is a **422**, not a clamp: `validate_http_flood_config` does
/// clamp, but pydantic has already refused anything outside the bounds before
/// it runs, so the clamp only ever sees values that are already inside them.
fn flood_payload_config(payload: &Value) -> Result<snpanel_nginx::HttpFloodConfig, Response> {
    let field = |name: &str, default: i64, min: i64, max: i64| -> Result<i64, Response> {
        let Some(raw) = payload.get(name) else {
            return Ok(default);
        };
        let Some(value) = raw.as_i64() else {
            return Err(crate::errors::int_parsing(name, raw));
        };
        crate::errors::check_range(name, value, min, max)?;
        Ok(value)
    };
    Ok(snpanel_nginx::HttpFloodConfig {
        access_limit_requests: field("access_limit_requests", 100, 1, 100_000)?,
        access_limit_window: field("access_limit_window", 10, 1, 3_600)?,
        access_limit_burst: field("access_limit_burst", 100, 0, 100_000)?,
        connection_limit: field("connection_limit", 60, 1, 10_000)?,
    })
}

/// Source: `set_website_http_flood`.
///
/// The order of the two writes is **asymmetric and deliberate**. Turning the
/// feature on writes the shared zone file first and then the vhost block,
/// because the block names a zone by name and nginx refuses a configuration
/// that references one which does not exist. Turning it off does the reverse:
/// the reference goes first, then the zone. Either way round the wrong way is
/// a moment where `nginx -t` fails - and a failed reload is every site on the
/// box, not just this one.
async fn set_http_flood(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return not_enough_permissions();
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match state.db.websites().by_id(website_id).await {
        Ok(Some(w)) => w,
        Ok(None) => return not_found("Website not found"),
        Err(e) => {
            tracing::error!("website lookup failed: {e}");
            return internal_error();
        }
    };

    let Some(raw) = payload.get("http_flood_enabled") else {
        return crate::errors::missing_field("http_flood_enabled", payload.clone());
    };
    let next_enabled = match crate::errors::read_bool("http_flood_enabled", Some(raw), false) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let config = match flood_payload_config(&payload) {
        Ok(c) => c,
        Err(r) => return r,
    };

    // The column is written before either file in the Python, because
    // `_sync_http_flood_zones` calls `db.flush()` and re-reads every row - so
    // this site's new state has to be visible to it. Writing it here reaches
    // the same place: the zone file below is rendered from the database.
    if let Err(e) = state
        .db
        .websites()
        .set_http_flood(website.id, next_enabled, &flood_config_json(&config))
        .await
    {
        tracing::error!("storing the HTTP flood settings failed: {e}");
        return internal_error();
    }

    let outcome = if next_enabled {
        match sync_http_flood_zones(&state).await {
            Ok(()) => update_http_flood_block(&state, &website.domain, true, &config).await,
            Err(r) => Err(r),
        }
    } else {
        match update_http_flood_block(&state, &website.domain, false, &config).await {
            Ok(()) => sync_http_flood_zones(&state).await,
            Err(r) => Err(r),
        }
    };
    if let Err(r) = outcome {
        // The Python's `except` leaves the ORM object dirty and never commits,
        // so the column goes back. Put it back here too, or a failed request
        // leaves a row claiming a protection the vhost does not have.
        if let Err(e) = state
            .db
            .websites()
            .set_http_flood(
                website.id,
                website.http_flood_enabled,
                &website.http_flood_config,
            )
            .await
        {
            tracing::error!("could not restore the HTTP flood settings: {e}");
        }
        return r;
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "update_http_flood",
        &website.domain,
    )
    .await;

    match state.db.websites().by_id(website.id).await {
        Ok(Some(fresh)) => single(&state, fresh).await,
        Ok(None) => not_found("Website not found"),
        Err(e) => {
            tracing::error!("re-reading the website failed: {e}");
            internal_error()
        }
    }
}

// ---------------------------------------------------------------------------
// the two SSL reads
// ---------------------------------------------------------------------------

/// Source: `_cloudflare_zone_for` - "(zone, token) for `domain`, resolved from
/// a saved Cloudflare credential. Tries each saved zone that is a suffix of
/// the domain, longest first."
///
/// Longest first matters: a panel holding credentials for both `example.com`
/// and `eu.example.com` must use the more specific token for
/// `shop.eu.example.com`, because the broader one may not cover that zone.
async fn cloudflare_zone_for(state: &AppState, domain: &str) -> Option<String> {
    let domain = domain.trim().to_lowercase();
    let zones = state.db.cloudflare().zones().await.ok()?;
    zones
        .into_iter()
        .filter(|zone| domain == *zone || domain.ends_with(&format!(".{zone}")))
        .max_by_key(|zone| zone.len())
}

/// Source: `cloudflare_zone`.
///
/// The token itself never leaves the database here - only whether one exists,
/// which is what the page needs to decide between offering a wildcard and
/// asking for a credential.
async fn cloudflare_zone(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let zone = cloudflare_zone_for(&state, &website.domain).await;
    axum::Json(json!({
        "zone": zone,
        // `has_token=zone is not None` - the Python reports a token as present
        // whenever a zone matched, without checking that it decrypts. Kept, so
        // a credential the panel cannot read still shows as configured rather
        // than silently disappearing from the page.
        "has_token": zone.is_some(),
    }))
    .into_response()
}

/// Which Cloudflare token to use, and where it came from.
///
/// Source: the `if token: ... else: ...` fork at the top of
/// `install_wildcard_ssl`. Split out because the two halves fail
/// differently and the difference is the whole of what a caller sees: a
/// token that was *sent* and is bad is a **400** naming Cloudflare's
/// reason, while no saved token at all is a **409** asking for one.
enum TokenSource {
    /// The caller sent one. It has been verified and its zone looked up,
    /// and it is about to be saved for the next renewal.
    Supplied { zone: String, token: String },
    /// A credential saved earlier covers this domain.
    Stored { zone: String, token: String },
}

impl TokenSource {
    fn parts(&self) -> (&str, &str) {
        match self {
            Self::Supplied { zone, token } | Self::Stored { zone, token } => (zone, token),
        }
    }
}

/// Source: the token fork, including `cloudflare.save_credential`.
///
/// The supplied token is verified **before** it is stored. Saving first
/// would leave a bad credential behind for the next unattended renewal to
/// fail on, at which point nobody is watching.
async fn wildcard_token(
    state: &AppState,
    domain: &str,
    supplied: Option<&str>,
) -> Result<TokenSource, Response> {
    if let Some(token) = supplied {
        // `except cloudflare.CloudflareError as exc: raise HTTPException(400,
        // str(exc))` - every refusal from the two calls lands as the same
        // 400, carrying Cloudflare's own words.
        if let Err(exc) = crate::cloudflare::verify_token(token).await {
            return Err(bad_request(&exc.0));
        }
        let zone = match crate::cloudflare::zone_for_domain(token, domain).await {
            Ok(zone) => zone,
            Err(exc) => return Err(bad_request(&exc.0)),
        };
        let ciphertext = snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, token);
        if let Err(e) = state
            .db
            .cloudflare()
            .save(&zone, &ciphertext, &snpanel_db::sqlalchemy_now())
            .await
        {
            tracing::error!("saving the Cloudflare credential failed: {e}");
            return Err(internal_error());
        }
        return Ok(TokenSource::Supplied {
            zone,
            token: token.to_string(),
        });
    }

    // `zone, token = _cloudflare_zone_for(db, website.domain)`. A zone with
    // no readable token is the same answer as no zone: the Python's `if not
    // token` sees an empty string either way.
    let stored = match cloudflare_zone_for(state, domain).await {
        Some(zone) => {
            let ciphertext = match state.db.cloudflare().ciphertext(&zone).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("reading the Cloudflare credential failed: {e}");
                    return Err(internal_error());
                }
            };
            match snpanel_core::crypto::fernet::decrypt(
                &state.settings.secret_key,
                ciphertext.as_deref(),
                state.settings.strict_decrypt,
            ) {
                Ok(token) => Some((zone, token)),
                // The Python's `decrypt` raises here and nothing catches it,
                // so the caller gets a 500. Reproduced: a credential the
                // panel cannot read is a broken installation, and answering
                // 409 would send an administrator to re-enter a token that
                // is already there.
                Err(e) => {
                    tracing::error!("could not decrypt the stored Cloudflare token: {e}");
                    return Err(internal_error());
                }
            }
        }
        None => None,
    };
    match stored {
        Some((zone, token)) if !token.is_empty() => Ok(TokenSource::Stored { zone, token }),
        _ => Err(crate::errors::error(
            axum::http::StatusCode::CONFLICT,
            "No Cloudflare API token saved for this domain's zone. Provide one.",
        )),
    }
}

/// Source: `platform.install_command("python3-certbot-dns-cloudflare")`, the
/// fallback `ssl.ensure_cloudflare_plugin` uses when the helper is absent.
fn certbot_dns_plugin_install_command() -> String {
    crate::system::install_command(CERTBOT_DNS_PLUGIN)
}

/// The package that answers a DNS-01 challenge through Cloudflare.
const CERTBOT_DNS_PLUGIN: &str = "python3-certbot-dns-cloudflare";

/// `POST /websites/{website_id}/ssl/wildcard`.
///
/// Source: `install_wildcard_ssl`. A certificate for `zone` **and**
/// `*.zone`, proved over DNS-01 instead of HTTP-01.
///
/// This is the only endpoint in the panel that calls out to the public
/// internet, and the only one that hands a third-party credential to the
/// privileged helper. Two things follow from that and neither is
/// negotiable:
///
/// - **The token goes to the helper on stdin.** `/proc/<pid>/cmdline` is
///   world-readable, so a token in argv is a token every account on the
///   machine can read for as long as certbot runs.
/// - **The token is never in an error, a log line or the response.** The
///   400s below carry Cloudflare's words about the token, never the token.
///
/// The wildcard covers the **zone**, not the site: asking Cloudflare which
/// zone the domain sits in is what makes `shop.example.com` issue a
/// certificate for `example.com` and `*.example.com`, which is the one that
/// can actually be renewed from a DNS record the panel controls.
async fn install_wildcard_ssl(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Pydantic runs before the handler, so a malformed body is a 422 whether
    // or not the website exists - and that ordering is what stops this
    // endpoint from being a way to probe which website ids are real.
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let supplied = match wildcard_token_field(&payload) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let source = match wildcard_token(&state, &website.domain, supplied.as_deref()).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let (zone, token) = source.parts();

    // `ssl.ensure_cloudflare_plugin()` - certbot cannot answer a DNS-01
    // challenge without the Cloudflare plugin, and the check is first so a
    // machine missing it fails before a token is sent anywhere.
    let install = certbot_dns_plugin_install_command();
    let plugin = shell::privileged(
        state.settings.command_dry_run,
        "certbot-dns-cloudflare-install",
        &[],
        None,
        Some(&["bash", "-lc", &install]),
    )
    .await;
    if !plugin.ok() {
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &command_error(&plugin),
        );
    }

    // `_safe_domain(zone)`. The zone came from Cloudflare rather than from
    // the caller, but it is about to be an argument to certbot and a path
    // under `/etc/letsencrypt/live`, so it is checked like any other.
    let safe_zone = match crate::manual_ssl::safe_domain(zone) {
        Ok(z) => z,
        // `ValueError("Invalid domain")` out of a service call is a 500 in
        // the Python, not a 400: the caller did not choose this name.
        Err(message) => {
            return crate::errors::error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
    };
    let email = state.settings.ssl_email.clone();
    let mut args: Vec<&str> = vec![&safe_zone];
    if !email.is_empty() {
        args.push(&email);
    }
    let issued = shell::privileged(
        state.settings.command_dry_run,
        "cloudflare-ssl-issue",
        &args,
        // The token, on stdin. Never in `args`.
        Some(token),
        Some(&[
            "bash",
            "-lc",
            "echo 'cloudflare-ssl-issue needs the snpanel helper'; exit 1",
        ]),
    )
    .await;
    if !issued.ok() {
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &command_error(&issued),
        );
    }

    let previous = (
        website.ssl_mode.clone(),
        website.ssl_source_domain.clone(),
        website.ssl_cert_path.clone(),
        website.ssl_key_path.clone(),
        website.ssl_ca_path.clone(),
    );
    let now = snpanel_db::sqlalchemy_now();
    if let Err(e) = state
        .db
        .websites()
        .set_ssl_state(
            website.id,
            true,
            "cloudflare",
            Some(zone),
            None,
            None,
            None,
            &now,
        )
        .await
    {
        tracing::error!("updating the SSL state failed: {e}");
        return internal_error();
    }

    // The row the wiring reads has to be the row that was just written.
    let mut updated = website.clone();
    updated.ssl_enabled = true;
    updated.ssl_mode = "cloudflare".to_string();
    updated.ssl_source_domain = Some(zone.to_string());
    updated.ssl_cert_path = None;
    updated.ssl_key_path = None;
    updated.ssl_ca_path = None;

    if let Err(message) = resync_and_rewrite(&state, &updated, RewriteOverrides::default()).await {
        // `except Exception: roll the row back on any wiring failure`. The
        // **certificate stays** - it was issued, and throwing it away because
        // the vhost would not render would burn a Let's Encrypt rate limit
        // for nothing. Only the row goes back.
        if let Err(e) = state
            .db
            .websites()
            .set_ssl_state(
                website.id,
                website.ssl_enabled,
                &previous.0,
                previous.1.as_deref(),
                previous.2.as_deref(),
                previous.3.as_deref(),
                previous.4.as_deref(),
                &now,
            )
            .await
        {
            tracing::error!("rolling the SSL state back failed: {e}");
        }
        return bad_request(&message);
    }

    resync_shared_dependents(&state, &website.domain).await;

    // `log_action(..., detail=zone, request=request)` - the zone is the
    // detail, because the certificate is not for the domain in `target` and
    // an administrator reading this back needs to know which zone was
    // touched.
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "install_wildcard_ssl",
        &website.domain,
        zone,
    )
    .await;

    let row = match state.db.websites().by_id(website.id).await {
        Ok(Some(row)) => row,
        _ => return internal_error(),
    };
    let aliases = state
        .db
        .websites()
        .aliases(row.id)
        .await
        .unwrap_or_default();
    let ssl_enabled = row.ssl_enabled;
    axum::Json(website_json(&row, &aliases, false, ssl_enabled)).into_response()
}

/// Source: `WildcardSslRequest` - `Optional[str] = None` with a validator
/// that strips it and turns what is left of an empty string back into
/// `None`.
///
/// The strip is Python's, so a token pasted with a trailing newline - which
/// is how most of them arrive - is the same token as one without.
fn wildcard_token_field(payload: &Value) -> Result<Option<String>, Response> {
    let raw = match payload.get("cloudflare_api_token") {
        None | Some(Value::Null) => return Ok(None),
        Some(other) => other,
    };
    let Some(text) = raw.as_str() else {
        return Err(crate::errors::string_type("cloudflare_api_token", raw));
    };
    let trimmed = snpanel_core::pyunicode::trim(text);
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

/// Source: `ssl.cert_info` - expiry and covered names for a certificate on
/// this machine, read through the helper because `/etc/letsencrypt/live` is
/// root's.
async fn cert_info(state: &AppState, domain: &str) -> (String, Vec<String>) {
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
        return (String::new(), Vec::new());
    }
    let mut not_after = String::new();
    let mut sans: Vec<String> = Vec::new();
    for line in result.stdout.lines() {
        // `line.partition("=")` - the first `=`, and the key is compared
        // without trimming.
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k, v),
            None => (line, ""),
        };
        match key {
            "not_after" => not_after = value.trim().to_string(),
            "sans" => {
                sans = value
                    .trim()
                    .split(',')
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                    .collect()
            }
            _ => {}
        }
    }
    (not_after, sans)
}

/// Source: `ssl_sources` - the certificates already on this server that would
/// cover this website.
///
/// A customer only sees their own sites' certificates. That is not cosmetic:
/// the list is what the "borrow a certificate" screen offers, and borrowing
/// points this site's vhost at another site's key.
async fn ssl_sources(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    let admin = permissions::is_admin_role(&current.user.role);
    let all = match state.db.websites().list(None, "").await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing websites failed: {e}");
            return internal_error();
        }
    };

    let mut out: Vec<Value> = Vec::new();
    for candidate in all
        .iter()
        .filter(|c| c.id != website.id && c.ssl_enabled)
        .filter(|c| admin || c.owner_id == current.user.id)
    {
        // `candidate.ssl_source_domain or candidate.domain` - a site already
        // borrowing a certificate offers the certificate it borrowed, not one
        // of its own that does not exist.
        let source = candidate
            .ssl_source_domain
            .as_deref()
            .filter(|d| !d.is_empty())
            .unwrap_or(&candidate.domain);
        let (not_after, sans) = cert_info(&state, source).await;
        if sans.is_empty() || !cert_covers(&sans, &website.domain) {
            continue;
        }
        out.push(json!({
            "domain": candidate.domain,
            "ssl_mode": candidate.ssl_mode,
            "wildcard": sans.iter().any(|name| name.starts_with("*.")),
            "not_after": not_after,
        }));
    }
    axum::Json(out).into_response()
}

/// Source: `_shared_dependents` + `_block_if_source`.
///
/// A site whose certificate others borrow cannot change it without breaking
/// theirs, and the refusal names them: an administrator told only "no" would
/// have to go looking for which sites to fix first.
async fn block_if_source(state: &AppState, website: &snpanel_db::Website) -> Result<(), Response> {
    let dependents = state
        .db
        .websites()
        .shared_dependents(&website.domain)
        .await
        .map_err(|e| {
            tracing::error!("looking up shared dependents failed: {e}");
            internal_error()
        })?;
    if dependents.is_empty() {
        return Ok(());
    }
    let domains: Vec<&str> = dependents.iter().map(|d| d.domain.as_str()).collect();
    Err(crate::errors::error(
        axum::http::StatusCode::CONFLICT,
        &shared_source_refusal(&domains),
    ))
}

/// The message `_block_if_source` raises, sorted.
///
/// An administrator told only "no" has to go looking for which sites to fix,
/// so the message is the list - and sorted, so it reads the same twice.
fn shared_source_refusal(domains: &[&str]) -> String {
    let mut names: Vec<&str> = domains.to_vec();
    names.sort_unstable();
    format!(
        "{} website(s) borrow this certificate ({}). Change their SSL first.",
        domains.len(),
        names.join(", ")
    )
}

/// Source: `cert_name = source.ssl_source_domain or source.domain`.
///
/// If B borrows from A and C then borrows from B, C stores **A**. The
/// certificate C serves is A's file, and a chain that stored B would name one
/// that does not exist - and `shared_dependents` looks rows up by that stored
/// name, so getting it wrong also hides C from the check that stops A
/// changing its certificate.
fn shared_cert_name(source: &snpanel_db::Website) -> String {
    source
        .ssl_source_domain
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| source.domain.clone())
}

/// `POST /websites/{website_id}/ssl/shared`.
///
/// Source: `install_shared_ssl`. One site serves another's certificate rather
/// than asking a certificate authority for a second one covering a name it
/// has already signed — and it renews with the source, which a second
/// certificate would not.
///
/// The row moves before the wiring and is **put back if the wiring fails**.
/// The alternative — commit first, wire after — leaves a row saying the site
/// is on a shared certificate while nginx is still serving whatever it served
/// before, and nothing afterwards would notice.
async fn install_shared_ssl(
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
    if let Err(r) = block_if_source(&state, &website).await {
        return r;
    }

    let source_domain = payload
        .get("source_domain")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if source_domain == website.domain {
        return bad_request("A website cannot borrow its own certificate");
    }

    let source = match state.db.websites().by_domain(&source_domain).await {
        Ok(Some(w)) => w,
        Ok(None) => return not_found("Source website not found"),
        Err(e) => {
            tracing::error!("source lookup failed: {e}");
            return internal_error();
        }
    };
    // Borrowing reaches into another account's certificate, so it takes the
    // same permission as touching that account's website would.
    if source.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return not_enough_permissions();
    }

    let cert_name = shared_cert_name(&source);

    let (_not_after, sans) = cert_info(&state, &cert_name).await;
    if sans.is_empty() {
        return bad_request(&format!(
            "No usable certificate found for {}",
            source.domain
        ));
    }
    if !cert_covers(&sans, &website.domain) {
        return bad_request(&format!(
            "{}'s certificate does not cover {}",
            source.domain, website.domain
        ));
    }

    let previous = (
        website.ssl_enabled,
        website.ssl_mode.clone(),
        website.ssl_source_domain.clone(),
    );
    let now = snpanel_db::sqlalchemy_now();
    if let Err(e) = state
        .db
        .websites()
        .set_ssl_state(
            website.id,
            true,
            "shared",
            Some(&cert_name),
            None,
            None,
            None,
            &now,
        )
        .await
    {
        tracing::error!("updating the SSL state failed: {e}");
        return internal_error();
    }

    // The row the wiring reads has to be the row that was just written.
    let mut updated = website.clone();
    updated.ssl_enabled = true;
    updated.ssl_mode = "shared".to_string();
    updated.ssl_source_domain = Some(cert_name.clone());
    updated.ssl_cert_path = None;
    updated.ssl_key_path = None;
    updated.ssl_ca_path = None;

    let wired = wire_shared_ssl(&state, &updated).await;
    if let Err(message) = wired {
        // `except Exception: roll the row back on any wiring failure`.
        if let Err(e) = state
            .db
            .websites()
            .set_ssl_state(
                website.id,
                previous.0,
                &previous.1,
                previous.2.as_deref(),
                website.ssl_cert_path.as_deref(),
                website.ssl_key_path.as_deref(),
                website.ssl_ca_path.as_deref(),
                &now,
            )
            .await
        {
            tracing::error!("rolling the SSL state back failed: {e}");
        }
        return bad_request(&message);
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "install_shared_ssl",
        &website.domain,
    )
    .await;

    let row = match state.db.websites().by_id(website.id).await {
        Ok(Some(row)) => row,
        _ => return internal_error(),
    };
    let aliases = state
        .db
        .websites()
        .aliases(row.id)
        .await
        .unwrap_or_default();
    let ssl_enabled = row.ssl_enabled;
    axum::Json(website_json(&row, &aliases, false, ssl_enabled)).into_response()
}

/// The three things that have to succeed together for a borrowed certificate
/// to actually be served.
async fn wire_shared_ssl(state: &AppState, website: &snpanel_db::Website) -> Result<(), String> {
    let waf =
        crate::waf::sync_website_rules(state.settings.command_dry_run, website, &server_crs_mode())
            .await
            .map_err(|e| e.to_string())?;
    if !waf.ok() {
        return Err(waf
            .failure_detail("Could not save WAF rules")
            .trim()
            .to_string());
    }
    if website.http_flood_enabled {
        sync_http_flood_zones(state)
            .await
            .map_err(|_| "Could not write the HTTP flood zones".to_string())?;
    }
    rewrite_owned_vhost(state, website, RewriteOverrides::default()).await?;
    Ok(())
}

/// Source: `manual_ssl_paths` - the three files a manual certificate lives in.
///
/// The row stores the paths rather than deriving them, because a site whose
/// certificate later moves has to keep serving from where the file actually
/// is until something rewrites the row.
fn manual_ssl_paths(domain: &str) -> (String, String, String) {
    let base = format!("/etc/nginx/snpanel/ssl/sites/{domain}");
    (
        format!("{base}/cert.crt"),
        format!("{base}/privkey.key"),
        format!("{base}/ca.crt"),
    )
}

/// What was on disk before the upload replaced it.
///
/// Source: `ManualSslSnapshot`. The files are `root:snpanel 0640`, so the
/// panel account can read them without the helper; putting them **back**
/// needs the helper, because writing there does not.
struct ManualSslSnapshot {
    domain: String,
    certificate: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    ca_bundle: Option<Vec<u8>>,
}

/// Source: `snapshot_manual_ssl_domain`.
async fn snapshot_manual_ssl(domain: &str) -> ManualSslSnapshot {
    let (cert, key, ca) = manual_ssl_paths(domain);
    let read = |p: String| async move { tokio::fs::read(&p).await.ok() };
    ManualSslSnapshot {
        domain: domain.to_string(),
        certificate: read(cert).await,
        private_key: read(key).await,
        ca_bundle: read(ca).await,
    }
}

/// Source: `restore_manual_ssl`, whose body is wrapped in `except (RuntimeError,
/// OSError): pass`.
///
/// Rolling back is best-effort **on purpose**: the caller is already on its
/// way to a 400 with the real reason, and a failure here would replace that
/// reason with a second one about the rollback. The site is the loser either
/// way; the administrator at least gets told what they actually did wrong.
///
/// A site that had no manual certificate before has its directory removed
/// rather than left holding half an upload, which is what `remove_manual_ssl`
/// does on the Python's `else` branch.
async fn restore_manual_ssl(state: &AppState, snapshot: &ManualSslSnapshot) {
    let verb = rollback_verb(snapshot);
    let payload = match (&snapshot.certificate, &snapshot.private_key) {
        (Some(cert), Some(key)) => Some(manual_ssl_payload(
            cert,
            key,
            snapshot.ca_bundle.as_deref().unwrap_or(b""),
        )),
        _ => None,
    };
    let result = shell::privileged(
        state.settings.command_dry_run,
        verb,
        &[&snapshot.domain],
        payload.as_deref(),
        None,
    )
    .await;
    if !result.ok() {
        tracing::error!(
            "{verb} for {} failed while rolling back: {}",
            snapshot.domain,
            result.failure_detail("no detail").trim()
        );
    }
}

/// Which verb puts the previous state back.
///
/// Source: `ManualSslSnapshot.restore` - `if cert and key:` write them back,
/// `else:` remove the directory. **Half a snapshot is not a snapshot**: a site
/// that had only a certificate on disk and no key had nothing serving, and
/// writing that half back would leave exactly the state the rollback exists to
/// avoid - a certificate nobody has the key for, which nginx refuses to load.
fn rollback_verb(snapshot: &ManualSslSnapshot) -> &'static str {
    match (&snapshot.certificate, &snapshot.private_key) {
        (Some(_), Some(_)) => "manual-ssl-install",
        _ => "manual-ssl-remove",
    }
}

/// The JSON `manual-ssl-install` reads on stdin.
///
/// Source: `_write_manual_ssl_files`. It goes on **stdin, not argv** for the
/// reason C37 gives: a private key in `argv` is readable in
/// `/proc/<pid>/cmdline` by every account on the machine for as long as the
/// process lives, and a shared host has plenty of those.
fn manual_ssl_payload(certificate: &[u8], private_key: &[u8], ca_bundle: &[u8]) -> String {
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    serde_json::json!({
        "certificate": text(certificate),
        "private_key": text(private_key),
        "ca_bundle": if ca_bundle.is_empty() { String::new() } else { text(ca_bundle) },
    })
    .to_string()
}

/// One of the three parts, from whichever of its two form fields carried it.
///
/// Source: `_read_ssl_input`. A file part wins **only if it has a filename** -
/// a browser that submits an empty file input sends the part anyway, with an
/// empty filename, and treating that as "the administrator uploaded a file"
/// would refuse the text they typed into the box next to it.
fn read_ssl_input(
    upload: Option<&(String, Vec<u8>)>,
    text: &str,
    label: &str,
    required: bool,
) -> Result<Vec<u8>, String> {
    match upload {
        Some((filename, data)) if !filename.is_empty() => crate::manual_ssl::read_ssl_part(
            &crate::manual_ssl::SslPart::Upload { filename, data },
            label,
            required,
        ),
        _ => crate::manual_ssl::read_ssl_part(
            &crate::manual_ssl::SslPart::Text(text),
            label,
            required,
        ),
    }
}

/// The six form fields the manual-SSL form submits.
#[derive(Default)]
struct ManualSslForm {
    uploads: std::collections::HashMap<String, (String, Vec<u8>)>,
    texts: std::collections::HashMap<String, String>,
}

impl ManualSslForm {
    fn upload(&self, name: &str) -> Option<&(String, Vec<u8>)> {
        self.uploads.get(name)
    }

    fn text(&self, name: &str) -> &str {
        self.texts.get(name).map(String::as_str).unwrap_or("")
    }
}

/// Read the form, whichever of the two encodings it arrived in.
///
/// The panel's own page sends `FormData`, which is `multipart/form-data`. An
/// API client that sends only the three text fields may use
/// `application/x-www-form-urlencoded` instead, and FastAPI's `Form()` accepts
/// that - so a port that took multipart alone would refuse a request the
/// Python answers.
async fn read_manual_ssl_form(
    state: &AppState,
    parts: &axum::http::request::Parts,
    body: axum::body::Body,
) -> Result<ManualSslForm, Response> {
    let content_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut form = ManualSslForm::default();

    if content_type.starts_with("application/x-www-form-urlencoded") {
        let bytes = axum::body::to_bytes(body, MAX_MANUAL_SSL_BODY)
            .await
            .map_err(|_| bad_request("Could not read the form"))?;
        // Parsed with the panel's own decoder rather than a crate's, because
        // `auth::read_form` already has one and two decoders that disagree
        // about `+` is how a certificate arrives with a space in its base64.
        for pair in bytes.split(|b| *b == b'&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.iter().position(|b| *b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &[][..]),
            };
            form.texts.insert(
                super::auth::percent_decode(k),
                super::auth::percent_decode(v),
            );
        }
        return Ok(form);
    }

    use axum::extract::FromRequest as _;
    let request = Request::from_parts(parts.clone(), body);
    let mut multipart = axum::extract::Multipart::from_request(request, state)
        .await
        .map_err(|e| bad_request(&e.body_text()))?;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                let Some(name) = field.name().map(str::to_string) else {
                    continue;
                };
                let filename = field.file_name().map(str::to_string);
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| bad_request(&e.body_text()))?
                    .to_vec();
                match filename {
                    // A part with a filename is a file part even when the
                    // filename is empty - that is exactly the case
                    // `read_ssl_input` has to see in order to fall through to
                    // the text field.
                    Some(filename) => {
                        form.uploads.insert(name, (filename, bytes));
                    }
                    None => {
                        form.texts
                            .insert(name, String::from_utf8_lossy(&bytes).into_owned());
                    }
                }
            }
            Ok(None) => break,
            Err(e) => return Err(bad_request(&e.body_text())),
        }
    }
    Ok(form)
}

/// Three parts at 256 KiB apiece, with room for the boundaries around them.
const MAX_MANUAL_SSL_BODY: usize = 4 * 1024 * 1024;

/// `POST /websites/{website_id}/ssl/manual`.
///
/// Source: `install_manual_ssl`. A certificate an administrator bought from
/// somewhere else, rather than one certbot issued.
///
/// **What is on disk is captured before anything is written and put back if
/// any later step fails.** Unlike the Let's Encrypt path there is nothing to
/// re-issue from: if the upload half-lands and the vhost rewrite then fails,
/// the site is left serving a certificate nobody has the key for, and the only
/// copy of what it was serving before is the one taken here.
async fn install_manual_ssl(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    req: Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = block_if_source(&state, &website).await {
        return r;
    }

    let form = match read_manual_ssl_form(&state, &parts, body).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    // `except ValueError as exc: raise HTTPException(400, str(exc))` - the
    // message names which of the three parts is wrong, because the
    // administrator is holding three files and has to know which to look at.
    let read = |file: &str, text: &str, label: &str, required: bool| {
        read_ssl_input(form.upload(file), form.text(text), label, required)
    };
    let certificate = match read("certificate", "certificate_text", "certificate", true) {
        Ok(v) => v,
        Err(message) => return bad_request(&message),
    };
    let private_key = match read("private_key", "private_key_text", "private_key", true) {
        Ok(v) => v,
        Err(message) => return bad_request(&message),
    };
    let ca_bundle = match read("ca_bundle", "ca_bundle_text", "ca_bundle", false) {
        Ok(v) => v,
        Err(message) => return bad_request(&message),
    };

    let aliases_rows = state
        .db
        .websites()
        .aliases(website.id)
        .await
        .unwrap_or_default();
    // `aliases=_ssl_domains(website)` - the aliases and the redirects, both,
    // because nginx serves every one of them from this certificate and a name
    // it does not carry is a TLS error rather than a missing page.
    let ssl_domains: Vec<String> = domains_by_mode(&aliases_rows, "alias")
        .into_iter()
        .chain(domains_by_mode(&aliases_rows, "redirect"))
        .collect();

    let snapshot = snapshot_manual_ssl(&website.domain).await;
    match install_manual_ssl_files(
        &state,
        &website,
        &certificate,
        &private_key,
        &ca_bundle,
        &ssl_domains,
    )
    .await
    {
        Ok(()) => {}
        Err(message) => {
            restore_manual_ssl(&state, &snapshot).await;
            return bad_request(&message);
        }
    }

    // `_resync_shared_dependents(db, website.domain)` - a site borrowing this
    // certificate is serving the file that was just replaced, so its vhost is
    // repointed at the new one. Each failure is swallowed, as in the Python:
    // one borrower with a broken vhost does not undo an upload that worked.
    resync_shared_dependents(&state, &website.domain).await;

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "install_manual_ssl",
        &website.domain,
    )
    .await;

    let row = match state.db.websites().by_id(website.id).await {
        Ok(Some(row)) => row,
        _ => return internal_error(),
    };
    let aliases = state
        .db
        .websites()
        .aliases(row.id)
        .await
        .unwrap_or_default();
    let ssl_enabled = row.ssl_enabled;
    axum::Json(website_json(&row, &aliases, false, ssl_enabled)).into_response()
}

/// Validate, write, record and wire - the whole of the Python's `try:` block.
///
/// It is one function because every step in it is inside one rollback: the
/// caller restores the snapshot on any error from here, and a step that
/// returned early past the caller would leave the site half-changed.
async fn install_manual_ssl_files(
    state: &AppState,
    website: &snpanel_db::Website,
    certificate: &[u8],
    private_key: &[u8],
    ca_bundle: &[u8],
    ssl_domains: &[String],
) -> Result<(), String> {
    crate::manual_ssl::validate_manual_ssl(
        &website.domain,
        certificate,
        private_key,
        ca_bundle,
        ssl_domains,
        chrono::Utc::now().timestamp(),
    )?;
    let domain = crate::manual_ssl::safe_domain(&website.domain)?;

    let payload = manual_ssl_payload(certificate, private_key, ca_bundle);
    let result = shell::privileged(
        state.settings.command_dry_run,
        "manual-ssl-install",
        &[&domain],
        Some(&payload),
        None,
    )
    .await;
    if !result.ok() {
        return Err(result
            .failure_detail("Could not install manual SSL")
            .trim()
            .to_string());
    }

    let (cert_path, key_path, ca_path) = manual_ssl_paths(&domain);
    // `paths["ca"] = None` when no bundle was uploaded: the row must not name
    // a file the helper just deleted, or the vhost written from it points at
    // nothing.
    let ca_path = if ca_bundle.is_empty() {
        None
    } else {
        Some(ca_path)
    };
    let now = snpanel_db::sqlalchemy_now();
    state
        .db
        .websites()
        .set_ssl_state(
            website.id,
            true,
            "manual",
            // `install_manual_ssl` writes five SSL columns and
            // `ssl_source_domain` is **not** one of them, so a site moving off
            // a borrowed certificate keeps the stale name. Inert - every
            // reader of that column first checks `ssl_mode in {cloudflare,
            // shared}` - and carried across rather than tidied up, because a
            // port that also cleans is a port whose rows stop matching.
            website.ssl_source_domain.as_deref(),
            Some(&cert_path),
            Some(&key_path),
            ca_path.as_deref(),
            &now,
        )
        .await
        .map_err(|e| {
            tracing::error!("updating the SSL state failed: {e}");
            "Could not record the certificate".to_string()
        })?;

    // The row the wiring reads has to be the row that was just written.
    let mut updated = website.clone();
    updated.ssl_enabled = true;
    updated.ssl_mode = "manual".to_string();
    updated.ssl_cert_path = Some(cert_path);
    updated.ssl_key_path = Some(key_path);
    updated.ssl_ca_path = ca_path;

    let waf = crate::waf::sync_website_rules(
        state.settings.command_dry_run,
        &updated,
        &server_crs_mode(),
    )
    .await
    .map_err(|e| e.to_string())?;
    if !waf.ok() {
        return Err(waf
            .failure_detail("Could not save WAF rules")
            .trim()
            .to_string());
    }
    if updated.http_flood_enabled {
        sync_http_flood_zones(state)
            .await
            .map_err(|_| "Could not write the HTTP flood zones".to_string())?;
    }
    rewrite_owned_vhost(state, &updated, RewriteOverrides::default()).await?;
    Ok(())
}

/// Source: `_resync_shared_dependents` - a source's certificate just changed,
/// so every borrower's vhost is repointed at it.
async fn resync_shared_dependents(state: &AppState, source_domain: &str) {
    let dependents = match state.db.websites().shared_dependents(source_domain).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("listing the borrowers of {source_domain} failed: {e}");
            return;
        }
    };
    for dependent in dependents {
        // `except (RuntimeError, ValueError): pass`.
        if let Err(message) =
            rewrite_owned_vhost(state, &dependent, RewriteOverrides::default()).await
        {
            tracing::error!("repointing {} failed: {message}", dependent.domain);
        }
    }
}

/// The names certbot is asked to put on the certificate.
///
/// Source: `ssl.issue_ssl`. **`www.` is added even when nobody asked for it**,
/// because nginx's own vhost always listens on `www.<domain>` (see
/// `nginx._server_names`) whether or not it is an alias - a certificate
/// covering only the bare name leaves every visitor who types "www." with a
/// hard TLS mismatch instead of the site.
///
/// It is added *here* rather than in `safe_domain_list`, which is the shared
/// helper: that one also builds the list a manually-uploaded certificate is
/// checked against, and plenty of real certificates cover only the bare domain
/// on purpose.
fn certbot_domains(domain: &str, aliases: &[String]) -> Result<Vec<String>, String> {
    let safe = crate::manual_ssl::safe_domain(domain)?;
    let mut extra = aliases.to_vec();
    if !safe.starts_with("www.") {
        let www = format!("www.{safe}");
        // The fold here is the Python's (`existing = {_safe_domain(a) for a
        // in extra_aliases}`) and it is **redundant**: `safe_domain_list`
        // below folds and de-duplicates too, so pushing a `www.` that is
        // already an alias under a different spelling changes nothing. Kept
        // because it is what the Python does, and recorded as redundant
        // because no test can tell the two apart - a mutation that removed
        // the fold survived, and that is the honest reason why.
        let mut already = false;
        for alias in aliases {
            if crate::manual_ssl::safe_domain(alias)? == www {
                already = true;
            }
        }
        if !already {
            extra.push(www);
        }
    }
    crate::manual_ssl::safe_domain_list(domain, &extra)
}

/// `_command_error(result)`.
fn command_error(result: &crate::shell::CommandResult) -> String {
    result
        .failure_detail(&format!("Command failed with code {}", result.returncode))
        .trim()
        .to_string()
}

/// Source: `ssl.remove_manual_ssl_files` - the uploaded certificate this site
/// is no longer using.
///
/// Called after the row has been cleared and before it is committed, so a
/// failure here leaves files behind rather than a row pointing at files that
/// are gone. That is the right way round: the orphan sweep finds the files.
///
/// The Python falls back to unlinking each path itself when the helper verb
/// fails. That fallback is unreachable on a real installation - the files are
/// `root:snpanel 0640` in a `0750` directory and the panel account cannot
/// unlink them - so it is not ported; the failure is logged instead.
async fn remove_manual_ssl_files(state: &AppState, cert_path: Option<&str>) {
    let Some(cert_path) = cert_path.filter(|p| !p.is_empty()) else {
        return;
    };
    let Some(domain) = PathBuf::from(cert_path)
        .parent()
        .and_then(std::path::Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
    else {
        return;
    };
    let result = shell::privileged(
        state.settings.command_dry_run,
        "manual-ssl-remove",
        &[&domain],
        None,
        None,
    )
    .await;
    if !result.ok() {
        tracing::error!(
            "could not remove the uploaded certificate for {domain}: {}",
            result.failure_detail("no detail").trim()
        );
    }
}

/// `POST /websites/{website_id}/ssl`.
///
/// Source: `enable_ssl`. Ask Let's Encrypt for a certificate.
///
/// **The manual-certificate case is the whole difficulty.** `certbot --nginx`
/// edits a plain HTTP server block; it cannot work from one already claiming
/// to serve TLS from files that are about to be deleted. So a site on an
/// uploaded certificate has its vhost rewritten *without* SSL first - and if
/// certbot then fails, the site is left serving nothing at all unless the
/// uploaded certificate is put back and the vhost rewritten again. Both of
/// those are on the failure path below, and the site is down until they run.
async fn enable_ssl(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    current: CurrentUser,
) -> Response {
    let website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };
    if let Err(r) = block_if_source(&state, &website).await {
        return r;
    }

    let was_manual = website.ssl_mode == "manual";
    let previous_cert_path = website.ssl_cert_path.clone();
    let snapshot = snapshot_manual_ssl(&website.domain).await;

    if was_manual {
        let prepared = rewrite_website_vhost(
            &state,
            &website,
            RewriteOverrides {
                preserve_existing_ssl: Some(false),
                include_ssl: Some(false),
                ..RewriteOverrides::default()
            },
        )
        .await;
        if prepared.is_err() {
            return bad_request(&format!(
                "Cannot prepare Nginx config for Let's Encrypt: could not rewrite the vhost for {}",
                website.domain
            ));
        }
    }

    let aliases_rows = state
        .db
        .websites()
        .aliases(website.id)
        .await
        .unwrap_or_default();
    let ssl_domains: Vec<String> = domains_by_mode(&aliases_rows, "alias")
        .into_iter()
        .chain(domains_by_mode(&aliases_rows, "redirect"))
        .collect();
    let domains = match certbot_domains(&website.domain, &ssl_domains) {
        Ok(d) => d,
        Err(message) => return bad_request(&message),
    };

    let mut args: Vec<&str> = domains.iter().map(String::as_str).collect();
    // `helper_args.append(settings.ssl_email)` - the email is the **last**
    // argument, and the argv parser refuses it anywhere else.
    let email = state.settings.ssl_email.clone();
    if !email.is_empty() {
        args.push(&email);
    }
    let result = shell::privileged(
        state.settings.command_dry_run,
        "certbot-issue",
        &args,
        None,
        None,
    )
    .await;
    if !result.ok() {
        if was_manual {
            restore_manual_ssl(&state, &snapshot).await;
            // `except (RuntimeError, ValueError): pass` - the 500 below carries
            // certbot's reason, and a second failure here would replace it.
            let _ = rewrite_owned_vhost(&state, &website, RewriteOverrides::default()).await;
        }
        // A 500, not a 400: the Python distinguishes "you sent something wrong"
        // from "the certificate authority said no", and an administrator
        // retrying a rate-limited domain needs to know which one it was.
        return crate::errors::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &command_error(&result),
        );
    }

    let now = snpanel_db::sqlalchemy_now();
    if let Err(e) = state
        .db
        .websites()
        .set_ssl_state(
            website.id,
            true,
            "letsencrypt",
            None,
            None,
            None,
            None,
            &now,
        )
        .await
    {
        tracing::error!("updating the SSL state failed: {e}");
        return internal_error();
    }
    remove_manual_ssl_files(&state, previous_cert_path.as_deref()).await;

    let mut updated = website.clone();
    updated.ssl_enabled = true;
    updated.ssl_mode = "letsencrypt".to_string();
    updated.ssl_source_domain = None;
    updated.ssl_cert_path = None;
    updated.ssl_key_path = None;
    updated.ssl_ca_path = None;

    // A redirect-domain alias has no server block of its own until this runs
    // (see `nginx._append_certbot_redirect_vhosts`) - it only gets one here,
    // reusing the certificate this site now has, never from certbot's own
    // nginx plugin. That plugin only ever touches `$domain`, for exactly this
    // reason: it has no way to build a new, correctly confined block for an
    // alias and falls back to cloning whichever server block it finds first.
    if !domains_by_mode(&aliases_rows, "redirect").is_empty() {
        let _ = rewrite_owned_vhost(&state, &updated, RewriteOverrides::default()).await;
    }
    sync_alias_ssl_flags(&state, &updated).await;
    resync_shared_dependents(&state, &website.domain).await;

    // `log_action(db, user.id, "enable_ssl", domain)` - no request, so no IP
    // or user agent. The other shape is what the manual and shared paths use;
    // which one is right differs per endpoint and this is the Python's.
    audit_website(&state, current.user.id, "enable_ssl", &website.domain).await;

    let row = match state.db.websites().by_id(website.id).await {
        Ok(Some(row)) => row,
        _ => return internal_error(),
    };
    let aliases = state
        .db
        .websites()
        .aliases(row.id)
        .await
        .unwrap_or_default();
    let ssl_enabled = row.ssl_enabled;
    axum::Json(website_json(&row, &aliases, false, ssl_enabled)).into_response()
}

/// Source: `ssl.release_site_certificates`.
///
/// **One certificate often covers more than the site it was issued for** - an
/// alias, a subdomain added later, the hostname the panel itself answers on.
/// Deleting the lineage in that case takes a *live* site's HTTPS down, so
/// anything still covering a name this server hosts is left alone and named
/// in the message an administrator reads.
///
/// Never fails the request: a website must stay deletable when certbot is
/// unhappy. Every failure here becomes a sentence, not a status code.
pub(super) async fn release_site_certificates(
    state: &AppState,
    domain: &str,
    exclude_website_id: i64,
) -> String {
    let Ok(safe_domain) = crate::manual_ssl::safe_domain(domain) else {
        return String::new();
    };

    let mut keep: Vec<String> = Vec::new();
    let mut add = |name: &str| {
        let name = name.trim().to_lowercase();
        if !name.is_empty() && name != safe_domain && !keep.contains(&name) {
            keep.push(name);
        }
    };
    // `except Exception: return ""` - a broken query must not block a
    // deletion. It also must not *delete* on no information, which is why the
    // empty answer is a refusal to touch the certificate rather than an empty
    // keep-list.
    let (Ok(domains), Ok(alias_domains)) = (
        state.db.websites().domains_except(exclude_website_id).await,
        state
            .db
            .websites()
            .alias_domains_except(exclude_website_id)
            .await,
    ) else {
        return String::new();
    };
    for name in domains.iter().chain(alias_domains.iter()) {
        add(name);
    }
    // The panel's own hostname is not a website row when an administrator
    // pointed it at a domain by hand, so it is read separately. Losing it
    // would log everyone out of the panel over HTTPS.
    add(&crate::panel_urls::configured_panel_host(&state.settings));

    if !keep.is_empty() {
        let sans = cert_sans(state, &safe_domain).await;
        let mut still_used: Vec<&String> = keep
            .iter()
            .filter(|name| cert_covers(&sans, name))
            .collect();
        still_used.sort();
        if !still_used.is_empty() {
            let names: Vec<&str> = still_used.iter().map(|s| s.as_str()).collect();
            return format!(
                "kept the certificate for {safe_domain}: still covers {}",
                names.join(", ")
            );
        }
    }

    let result = shell::privileged(
        state.settings.command_dry_run,
        "certbot-delete",
        &[&safe_domain],
        None,
        None,
    )
    .await;
    if !result.ok() {
        return format!(
            "could not remove the certificate for {safe_domain}: {}",
            result.failure_detail("").trim()
        );
    }
    result.stdout.trim().to_string()
}

/// Source: `nginx.delete_wordpress_vhost`.
///
/// The file, then the customer's include, then a reload. The reload is last
/// and its failure is not reported: the vhost is already gone from disk, so
/// the site is down either way and a 500 here would leave the administrator
/// thinking the deletion did not happen.
pub(super) async fn delete_website_vhost(state: &AppState, domain: &str) {
    if state.settings.command_dry_run {
        return;
    }
    let path = std::path::PathBuf::from(&state.settings.nginx_sites_available)
        .join(format!("{domain}.conf"));
    if let Err(e) = tokio::fs::remove_file(&path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::error!("removing {} failed: {e}", path.display());
        }
    }
    let _ = shell::privileged(false, "nginx-custom-delete", &[domain], None, None).await;
    let _ = shell::privileged(false, "nginx-reload", &[], None, None).await;
}

/// The sentence the toast shows.
///
/// Source: `message = f"Deleted {domain}."` then the certificate note with its
/// first letter capitalised. **"Kept" is the surprising outcome** - the
/// administrator needs to know the lineage is still on the machine, or they
/// will hit the Let's Encrypt rate limit re-issuing a certificate they still
/// have.
fn deletion_message(domain: &str, ssl_note: &str) -> String {
    let message = format!("Deleted {domain}.");
    if ssl_note.is_empty() {
        return message;
    }
    let mut chars = ssl_note.chars();
    let first = chars
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    format!("{message} {first}{}", chars.as_str())
}

/// `DELETE /websites/{website_id}`.
///
/// Source: `delete_website`.
///
/// The order is the order: the vhost goes before the certificate and the WAF
/// rules, because both of those are still referenced by the file while it
/// exists - `waf.remove_site_rules` says so outright, and a missing
/// `modsecurity_rules_file` fails `nginx -t`, which takes **every** site down
/// at the next reload, not just this one.
async fn delete_website(
    State(state): State<AppState>,
    Path(website_id): Path<i64>,
    Query(params): Query<HashMap<String, String>>,
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
    if let Err(r) = block_if_source(&state, &website).await {
        return r;
    }

    let delete_files = query_flag(&params, "delete_files");
    let delete_database = query_flag(&params, "delete_database");
    let domain = website.domain.clone();

    let db_item = state
        .db
        .databases()
        .by_website(website.id)
        .await
        .unwrap_or_default();
    if delete_database {
        if let Some(item) = &db_item {
            // `mariadb.drop_database` raises on a bad identifier, and the
            // Python does not catch it: a row whose name would need quoting
            // refuses the whole deletion rather than running the SQL.
            if let Err(e) = crate::mariadb::drop_database(&item.db_name, &item.db_user).await {
                return bad_request(&e.to_string());
            }
        }
    }

    if let Err(e) = state.db.websites().alias_delete_all(website.id).await {
        tracing::error!("deleting the aliases of {domain} failed: {e}");
        return internal_error();
    }
    delete_website_vhost(&state, &domain).await;

    // The vhost is gone, so nothing reads the certificate or the rule file any
    // more: retire both before the row disappears and we no longer know which
    // names were ours.
    let ssl_note = release_site_certificates(&state, &domain, website.id).await;
    let _ = shell::privileged(
        state.settings.command_dry_run,
        "waf-site-delete",
        &[&domain],
        None,
        None,
    )
    .await;

    // `if website.linux_user: delete_site_runtime(...) else:
    // wordpress.delete_wordpress(root_path)`. The second branch is the
    // pre-site-user layout, where the files were owned by the panel account
    // and it could remove them itself. Nothing the installer builds today
    // produces a site without a Linux user, and the helper has no verb for
    // that shape, so a row without one keeps its files and says so.
    if delete_files {
        match website.linux_user.as_deref().filter(|u| !u.is_empty()) {
            Some(linux_user) => {
                let _ = shell::privileged(
                    state.settings.command_dry_run,
                    "site-runtime-delete",
                    &[linux_user, &website.root_path],
                    None,
                    None,
                )
                .await;
            }
            None => tracing::warn!(
                "{domain} has no Linux user, so its files under {} were left in place",
                website.root_path
            ),
        }
    }

    if let Some(item) = &db_item {
        if let Err(e) = state.db.databases().delete(item.id).await {
            tracing::error!("deleting the database row for {domain} failed: {e}");
            return internal_error();
        }
    }
    if let Err(e) = state.db.websites().delete(website.id).await {
        tracing::error!("deleting the row for {domain} failed: {e}");
        return internal_error();
    }
    // After the row is gone, so the zone file no longer names it.
    if website.http_flood_enabled {
        if let Err(r) = sync_http_flood_zones(&state).await {
            return r;
        }
    }

    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "delete_website",
        &domain,
        &ssl_note,
    )
    .await;
    crate::fail2ban::refresh_in_background(&state);

    axum::Json(json!({
        "ok": true,
        "message": deletion_message(&domain, &ssl_note),
    }))
    .into_response()
}

/// A FastAPI `bool = True` query parameter.
///
/// Source: pydantic's bool parsing, which is what `delete_files: bool = True`
/// gets. Absent means **true**, and the false spellings are the ones pydantic
/// accepts - a caller who passes `?delete_files=0` expects the files kept,
/// and a port that only understood `false` would delete them.
fn query_flag(params: &HashMap<String, String>, name: &str) -> bool {
    match params.get(name) {
        None => true,
        Some(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "f" | "false" | "n" | "no"
        ),
    }
}

/// Source: `storage_quota.STATIC_SITE_ESTIMATE_BYTES` and
/// `WORDPRESS_SITE_ESTIMATE_BYTES`.
///
/// A guess at what a site will occupy, charged against the quota **before**
/// anything is written. A WordPress install is a hundred megabytes of files
/// this request is about to download; a static site is the placeholder page.
const STATIC_SITE_ESTIMATE_BYTES: u64 = 1024 * 1024;
const WORDPRESS_SITE_ESTIMATE_BYTES: u64 = 100 * 1024 * 1024;

/// Source: `create_website`'s `install_wp`.
///
/// **Both conditions, not either.** `install_wordpress=true` with
/// `app_type="static"` creates a static site, and the flag is ignored rather
/// than the type. A port that took the flag alone would install WordPress
/// into a site the customer asked to be static and then serve it as static -
/// a hundred megabytes of PHP served as text.
fn installs_wordpress(install_wordpress: bool, app_type: &str) -> bool {
    install_wordpress && app_type == "wordpress"
}

/// Source: `app_type_value` in the non-WordPress branch.
///
/// A request for `wordpress` that is *not* installing WordPress becomes
/// `php` - the vhost has to serve something, and an empty directory rendered
/// with WordPress's rewrite rules serves nothing but 404s.
fn site_app_type(install_wp: bool, requested: &str) -> &str {
    if install_wp {
        "wordpress"
    } else if requested == "wordpress" {
        "php"
    } else {
        requested
    }
}

/// Source: `nginx_rewrite_mode="front_controller" if app_type_value ==
/// "wordpress" else "none"`.
fn site_rewrite_mode(app_type: &str) -> &'static str {
    if app_type == "wordpress" {
        "front_controller"
    } else {
        "none"
    }
}

/// `POST /websites`.
///
/// Source: `create_website`. A domain folder and an nginx vhost, and
/// optionally a database and a WordPress install inside them.
///
/// **Everything written before the row exists is cleaned up on failure**, and
/// the row is written last. The other order leaves a website in the list that
/// has no files, no vhost and no database, which an administrator can neither
/// use nor delete without hitting the same failure again.
async fn create_website(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    create_site_from(state, parts, current, payload, None).await
}

/// `POST /websites/wordpress`.
///
/// Source: `create_wordpress` - "legacy endpoint for backwards
/// compatibility", which is `create_website` with two fields forced. It is
/// ported as the same call with the same overrides rather than as a copy,
/// because a second copy is how the two of them drift apart.
async fn create_wordpress(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    create_site_from(state, parts, current, payload, Some(true)).await
}

/// What `WebsiteCreate` carries, after pydantic.
pub(super) struct CreateRequest {
    pub domain: String,
    pub owner_id: Option<i64>,
    pub php_version: String,
    pub app_type: String,
    pub app_id: Option<i64>,
    pub install_wordpress: bool,
    pub title: String,
    pub admin_user: String,
    pub admin_password: String,
    pub admin_email: String,
}

/// Source: `WebsiteCreate`'s field defaults.
fn create_request(payload: &Value, force_wordpress: Option<bool>) -> Result<CreateRequest, String> {
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let domain = text("domain").trim().to_lowercase();
    if domain.is_empty() {
        return Err("domain is required".to_string());
    }
    let php_version = match payload.get("php_version").and_then(Value::as_str) {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        // `WebsiteCreate.php_version` has no default of its own; the column's
        // is what a row gets, and the vhost renderer needs a value now.
        _ => String::new(),
    };
    let app_type = match payload.get("app_type").and_then(Value::as_str) {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => "wordpress".to_string(),
    };
    if !snpanel_nginx::ALLOWED_APP_TYPES.contains(&app_type.as_str()) {
        return Err(format!(
            "app_type must be one of {:?}",
            snpanel_nginx::ALLOWED_APP_TYPES
        ));
    }
    Ok(CreateRequest {
        domain,
        owner_id: payload.get("owner_id").and_then(Value::as_i64),
        php_version,
        app_type: match force_wordpress {
            Some(true) => "wordpress".to_string(),
            _ => app_type,
        },
        app_id: payload.get("app_id").and_then(Value::as_i64),
        install_wordpress: force_wordpress.unwrap_or_else(|| {
            payload
                .get("install_wordpress")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }),
        title: text("title"),
        admin_user: text("admin_user"),
        admin_password: text("admin_password"),
        admin_email: text("admin_email"),
    })
}

async fn create_site_from(
    state: AppState,
    parts: axum::http::request::Parts,
    current: CurrentUser,
    payload: Value,
    force_wordpress: Option<bool>,
) -> Response {
    let request = match create_request(&payload, force_wordpress) {
        Ok(r) => r,
        Err(message) => {
            return crate::errors::error(axum::http::StatusCode::UNPROCESSABLE_ENTITY, &message)
        }
    };

    // Asking for somebody else's site is an administrator's job, and the
    // check comes before the domain is even looked at: a customer probing for
    // which domains exist should not learn it through a 409.
    if let Some(requested) = request.owner_id {
        if requested != current.user.id
            && !permissions::has_role(&current.user.role, permissions::Role::Admin)
        {
            return not_enough_permissions();
        }
    }

    let taken = state
        .db
        .websites()
        .hostname_taken(&request.domain, None, None)
        .await
        .unwrap_or(true);
    if taken || vhost_exists(&state, &request.domain).await {
        return crate::errors::error(axum::http::StatusCode::CONFLICT, "Domain already exists");
    }

    let owner = match request.owner_id {
        Some(id) => match state.db.users().by_id(id).await {
            Ok(Some(u)) => u,
            Ok(None) => return not_found("Owner not found"),
            Err(e) => {
                tracing::error!("owner lookup failed: {e}");
                return internal_error();
            }
        },
        None => current.user.clone(),
    };

    let count = state
        .db
        .websites()
        .count_for_owner(owner.id)
        .await
        .unwrap_or(i64::MAX);
    if !permissions::is_admin_role(&owner.role) && count >= owner.website_limit {
        return crate::errors::error(axum::http::StatusCode::FORBIDDEN, "Website limit reached");
    }

    let install_wp = installs_wordpress(request.install_wordpress, &request.app_type);
    let estimate = if install_wp {
        WORDPRESS_SITE_ESTIMATE_BYTES
    } else {
        STATIC_SITE_ESTIMATE_BYTES
    };
    if let Err(message) = enforce_owner_quota(&state, &owner, estimate).await {
        return crate::errors::error(axum::http::StatusCode::PAYLOAD_TOO_LARGE, &message);
    }

    let Ok(panel_user) = snpanel_core::types::PanelUsername::parse(&owner.username) else {
        return internal_error();
    };
    let Ok(domain) = snpanel_core::Domain::parse(&request.domain) else {
        return bad_request("Invalid domain");
    };
    let site_root = snpanel_core::types::SitePath::site_root(&panel_user, &domain);
    let root_path = site_root.as_path().to_string_lossy().into_owned();
    let linux_user = panel_user.as_str().to_string();

    if install_wp && (request.admin_email.is_empty() || request.admin_password.is_empty()) {
        return bad_request(
            "admin_email and admin_password are required when install_wordpress is true",
        );
    }

    let app_type = site_app_type(install_wp, &request.app_type).to_string();
    let rewrite_mode = site_rewrite_mode(&app_type);
    let runtime_php = matches!(app_type.as_str(), "wordpress" | "php")
        .then(|| request.php_version.clone())
        .filter(|v| !v.is_empty());

    // An application-backed site is pointed at an app its owner owns; without
    // the ownership check a customer could aim their domain at another
    // tenant's application by guessing an id.
    let app_port = if app_type == "application" {
        match resolve_app_for_owner(&state, owner.id, request.app_id, &current).await {
            Ok(app) => Some(app),
            Err(r) => return r,
        }
    } else {
        None
    };

    let outcome = build_new_site(
        &state,
        &NewSite {
            domain: &request.domain,
            root_path: &root_path,
            linux_user: &linux_user,
            app_type: &app_type,
            rewrite_mode,
            php_version: &request.php_version,
            runtime_php: runtime_php.as_deref(),
            app_port: app_port.as_ref().map(|a| a.port),
            install_wp,
            request: &request,
        },
    )
    .await;
    let db_info = match outcome {
        Ok(info) => info,
        Err(message) => return bad_request(&message),
    };

    let now = snpanel_db::sqlalchemy_now();
    let new_row = snpanel_db::NewWebsite {
        domain: &request.domain,
        owner_id: owner.id,
        root_path: &root_path,
        document_root: "public_html",
        linux_user: Some(&linux_user),
        php_version: &request.php_version,
        app_type: &app_type,
        nginx_rewrite_mode: rewrite_mode,
        app_id: app_port.as_ref().map(|a| a.id),
        status: "active",
        // `Website.waf_enabled` is `default=True` on the model and `DEFAULT 0`
        // on the column, and `create_website` sets neither - so SQLAlchemy's
        // default is what a new row gets.
        waf_enabled: true,
        created_at: &now,
    };
    let website_id = match state.db.websites().create(&new_row).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("creating the row for {} failed: {e}", request.domain);
            return internal_error();
        }
    };

    if let Some(info) = &db_info {
        // C3: the column holds Fernet ciphertext, never the password.
        let encrypted =
            snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, &info.db_password);
        if let Err(e) = state
            .db
            .databases()
            .create(
                owner.id,
                Some(website_id),
                &info.db_name,
                &info.db_user,
                &encrypted,
            )
            .await
        {
            tracing::error!(
                "creating the database row for {} failed: {e}",
                request.domain
            );
            return internal_error();
        }
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        if install_wp {
            "create_wordpress"
        } else {
            "create_site"
        },
        &request.domain,
    )
    .await;
    // The WordPress jail reads every site's access log, and fail2ban finds
    // log files only when it reads its settings.
    crate::fail2ban::refresh_in_background(&state);

    let row = match state.db.websites().by_id(website_id).await {
        Ok(Some(row)) => row,
        _ => return internal_error(),
    };
    axum::Json(website_json(&row, &[], install_wp, row.ssl_enabled)).into_response()
}

/// Everything `build_new_site` needs, so its arguments cannot be swapped.
pub(super) struct NewSite<'a> {
    pub domain: &'a str,
    pub root_path: &'a str,
    pub linux_user: &'a str,
    pub app_type: &'a str,
    pub rewrite_mode: &'static str,
    pub php_version: &'a str,
    pub runtime_php: Option<&'a str>,
    pub app_port: Option<i64>,
    pub install_wp: bool,
    pub request: &'a CreateRequest,
}

/// Make the files and the vhost, and clean up if any of it fails.
///
/// Source: the two `try:` blocks in `create_website`, which differ only in
/// what they put inside the directory. The cleanup is the point: a half-made
/// site with no row is invisible to the panel, so nothing would ever come
/// back for it.
async fn build_new_site(
    state: &AppState,
    site: &NewSite<'_>,
) -> Result<Option<crate::mariadb::NewDatabase>, String> {
    let dry = state.settings.command_dry_run;

    // `site-runtime-ensure` makes the home, the public directory and the PHP
    // pool. `"none"` rather than an empty argument when there is no runtime
    // PHP: the helper reads the third argument positionally.
    let php_arg = site.runtime_php.unwrap_or("none");
    let ensured = shell::privileged(
        dry,
        "site-runtime-ensure",
        &[site.linux_user, site.root_path, php_arg],
        None,
        None,
    )
    .await;
    if !ensured.ok() {
        return Err(ensured
            .failure_detail("Could not prepare the website directory")
            .trim()
            .to_string());
    }

    let mut db_info = None;
    if site.install_wp {
        let created = crate::mariadb::create_database(site.domain, "wp", true)
            .await
            .map_err(|e| e.to_string())?;
        if let Err(message) = install_wordpress(state, site, &created).await {
            // `mariadb.drop_database(...)` then `_cleanup_failed_site(...)`,
            // in that order and both best-effort: the 400 carries the real
            // reason and a failure here must not replace it.
            let _ = crate::mariadb::drop_database(&created.db_name, &created.db_user).await;
            cleanup_failed_site(state, site).await;
            return Err(message);
        }
        db_info = Some(created);
    } else if !dry {
        // Just the placeholder page, then hand the directory back to the
        // site's own user.
        if let Err(message) = write_placeholder_page(state, site).await {
            cleanup_failed_site(state, site).await;
            return Err(message);
        }
    }

    if let Err(message) = write_new_vhost(state, site).await {
        if let Some(created) = &db_info {
            let _ = crate::mariadb::drop_database(&created.db_name, &created.db_user).await;
        }
        cleanup_failed_site(state, site).await;
        return Err(message);
    }
    Ok(db_info)
}

/// Source: `_ensure_default_waf_file` then `nginx.write_vhost`.
async fn write_new_vhost(state: &AppState, site: &NewSite<'_>) -> Result<(), String> {
    ensure_new_site_waf(state, site.domain).await?;
    write_site_vhost(state, site).await
}

/// Source: `_ensure_default_waf_file`.
///
/// Separate from the vhost write because `create_account` puts the
/// placeholder page between the two, and a placeholder that fails there
/// leaves the rule file already written.
pub(super) async fn ensure_new_site_waf(state: &AppState, domain: &str) -> Result<(), String> {
    let dry = state.settings.command_dry_run;
    let waf = crate::waf::ensure_default_site_rules(dry, domain)
        .await
        .map_err(|e| e.to_string())?;
    if !waf.ok() {
        return Err(waf
            .failure_detail("Could not save WAF rules")
            .trim()
            .to_string());
    }
    Ok(())
}

/// Source: `nginx.write_vhost` for a site that has no row yet.
pub(super) async fn write_site_vhost(state: &AppState, site: &NewSite<'_>) -> Result<(), String> {
    let custom = snpanel_nginx::CustomDirectives::validate("").map_err(|e| e.to_string())?;
    let root = std::path::PathBuf::from(site.root_path);
    let socket = new_site_fpm_socket(site);
    let mut input = snpanel_nginx::VhostInput::new(site.domain, &root, &custom);
    input.app_type = site.app_type;
    // The requested version, not the runtime one - see the note in
    // `rewrite_website_vhost`.
    input.php_version = Some(site.php_version).filter(|v| !v.is_empty());
    input.php_fpm_socket_override = socket.as_deref();
    input.document_root = "public_html";
    input.rewrite_mode = Some(site.rewrite_mode);
    input.app_port = site.app_port;

    let env = snpanel_nginx::VhostEnv {
        ipv6: crate::system::ipv6_enabled(),
        waf_engine: crate::system::waf_engine_available(),
        default_php_version: state.settings.default_php_version.clone(),
        home_root: std::path::PathBuf::from("/home"),
    };
    let sites = std::path::PathBuf::from(&state.settings.nginx_sites_available);
    let plan =
        snpanel_nginx::plan_rewrite(&input, &env, &sites, None, true).map_err(|e| e.to_string())?;

    if !state.settings.command_dry_run {
        let write = shell::privileged(
            false,
            "nginx-custom-write",
            &[site.domain],
            Some(plan.custom_include.as_str()),
            None,
        )
        .await;
        if !write.ok() {
            return Err(write
                .failure_detail("Cannot write Nginx config")
                .trim()
                .to_string());
        }
    }
    apply_vhost_plan(state, plan).await
}

/// Source: `site_users.site_php_fpm_socket(linux_user, root_path, php)`.
///
/// The same shape as [`site_fpm_socket`], for a site that has no row yet.
fn new_site_fpm_socket(site: &NewSite<'_>) -> Option<String> {
    let version = site.runtime_php?;
    let resolved = std::fs::canonicalize(site.root_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| site.root_path.to_string());
    let hash = snpanel_core::types::site_hash(&resolved);
    Some(format!(
        "/run/php/snpanel-{}-{hash}-{}.sock",
        site.linux_user,
        version.replace('.', "_")
    ))
}

/// Source: `_cleanup_failed_site`.
///
/// Best-effort, and it removes the files: a directory left behind under the
/// customer's home counts against their quota for a site that does not exist.
async fn cleanup_failed_site(state: &AppState, site: &NewSite<'_>) {
    let result = shell::privileged(
        state.settings.command_dry_run,
        "site-runtime-delete",
        &[site.linux_user, site.root_path],
        None,
        None,
    )
    .await;
    if !result.ok() {
        tracing::error!(
            "could not clean up {} after a failed creation: {}",
            site.root_path,
            result.failure_detail("no detail").trim()
        );
    }
}

/// Source: `nginx.vhost_exists`.
///
/// The websites table is the usual source of truth, but a leftover config
/// from a half-removed site or an out-of-band import would otherwise be
/// silently overwritten by a fresh create - taking whatever that file was
/// serving down with it.
pub(super) async fn vhost_exists(state: &AppState, domain: &str) -> bool {
    let path = std::path::PathBuf::from(&state.settings.nginx_sites_available)
        .join(format!("{domain}.conf"));
    tokio::fs::metadata(&path)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Source: `storage_quota.enforce_user_storage_quota(db, owner, incoming)`.
///
/// `replaced_bytes` is zero: a new site replaces nothing.
async fn enforce_owner_quota(
    state: &AppState,
    owner: &snpanel_db::User,
    incoming_bytes: u64,
) -> Result<(), String> {
    let subject = crate::storage_quota::QuotaSubject {
        dry_run: state.settings.command_dry_run,
        user_id: owner.id,
        role: &owner.role,
        storage_limit_mb: owner.storage_limit_mb,
        application_installed: super::addons::application_installed(),
    };
    crate::storage_quota::enforce_user_storage_quota(&state.db, &subject, incoming_bytes, 0)
        .await
        .map_err(|e| e.to_string())
}

/// Source: `_resolve_app_for_owner`.
///
/// The app a website may serve: **one its owner owns**. Without the ownership
/// check a customer could aim their domain at another tenant's application by
/// guessing an id, and the proxy would happily serve it.
///
/// Application mode belongs to the addon, so the addon check comes first -
/// whichever route the request arrived on.
async fn resolve_app_for_owner(
    state: &AppState,
    owner_id: i64,
    app_id: Option<i64>,
    current: &CurrentUser,
) -> Result<snpanel_db::SiteAppTarget, Response> {
    super::addons::require_application()?;
    let Some(app_id) = app_id else {
        return Err(bad_request(
            "Pick an installed application for this website, or choose a different website mode.",
        ));
    };
    let app = match state.db.site_apps().by_id(app_id).await {
        Ok(Some(app)) => app,
        Ok(None) => return Err(not_found("Application not found")),
        Err(e) => {
            tracing::error!("application lookup failed: {e}");
            return Err(internal_error());
        }
    };
    if app.owner_id != owner_id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return Err(not_enough_permissions());
    }
    Ok(app)
}

/// Source: `wordpress.install_wordpress`.
///
/// Four helper calls in order: download the files, write `wp-config.php`,
/// hand the directory to the site's user, then run `wp core install`.
///
/// **Neither the database password nor the admin password reaches `argv`.**
/// The config is rendered here and written through the helper's stdin, and
/// the admin password goes in on stdin too via `--prompt=admin_password`.
/// C37: `/proc/<pid>/cmdline` is readable by every account on the machine for
/// as long as the process lives, and a shared host is full of them.
pub(super) async fn install_wordpress(
    state: &AppState,
    site: &NewSite<'_>,
    db: &crate::mariadb::NewDatabase,
) -> Result<(), String> {
    use crate::wordpress::{self, WpValue};

    let title = if site.request.title.trim().is_empty() {
        site.domain.to_string()
    } else {
        site.request.title.clone()
    };
    let title = wordpress::safe_value(&title, WpValue::Title)?;
    let admin_user = wordpress::safe_value(&site.request.admin_user, WpValue::User)?;
    let admin_email = wordpress::safe_value(&site.request.admin_email, WpValue::Email)?;
    wordpress::check_admin_password(&site.request.admin_password)?;

    let dry = state.settings.command_dry_run;
    let public = format!("{}/public_html", site.root_path);
    let wp_path = format!("--path={public}");
    let php_flag = wordpress::wp_php_flag(site.runtime_php);

    let mut download: Vec<&str> = vec![site.linux_user];
    download.extend(php_flag.iter().map(String::as_str));
    download.extend(["core", "download", &wp_path]);
    let result = shell::privileged(dry, "wp-site", &download, None, None).await;
    if !result.ok() {
        return Err(result
            .failure_detail("Could not download WordPress")
            .trim()
            .to_string());
    }

    let config = wordpress::render_wp_config(&db.db_name, &db.db_user, &db.db_password);
    if !dry {
        let write = shell::privileged(
            false,
            "site-file-write",
            &[
                site.linux_user,
                site.root_path,
                "public_html/wp-config.php",
                "0640",
            ],
            Some(&config),
            None,
        )
        .await;
        if !write.ok() {
            return Err(write
                .failure_detail("Could not write wp-config.php")
                .trim()
                .to_string());
        }
    }
    // `check=False`: the ownership fix is best-effort in the Python too.
    let _ = shell::privileged(
        dry,
        "site-path-fix",
        &[&public, site.linux_user],
        None,
        None,
    )
    .await;

    let url = format!("--url=https://{}", site.domain);
    let title_arg = format!("--title={title}");
    let user_arg = format!("--admin_user={admin_user}");
    let email_arg = format!("--admin_email={admin_email}");
    let mut install: Vec<&str> = vec![site.linux_user];
    install.extend(php_flag.iter().map(String::as_str));
    install.extend([
        "core",
        "install",
        &wp_path,
        &url,
        &title_arg,
        &user_arg,
        &email_arg,
        "--prompt=admin_password",
        "--skip-email",
        "--allow-root",
    ]);
    let password_stdin = format!("{}\n", site.request.admin_password);
    let result = shell::privileged(dry, "wp-site", &install, Some(&password_stdin), None).await;
    if !result.ok() {
        return Err(result
            .failure_detail("Could not install WordPress")
            .trim()
            .to_string());
    }

    // `fix_permissions` then a second `site-file-write` whose only job is the
    // mode: `wp core install` rewrites `wp-config.php` and leaves it
    // world-readable, and that file holds the database password.
    let _ = shell::privileged(
        dry,
        "fix-permissions",
        &[site.root_path, site.linux_user],
        None,
        None,
    )
    .await;
    if !dry {
        let _ = shell::privileged(
            false,
            "site-file-write",
            &[
                site.linux_user,
                site.root_path,
                "public_html/wp-config.php",
                "0640",
            ],
            Some(&config),
            None,
        )
        .await;
    }
    Ok(())
}

/// Source: `_write_placeholder_page`.
///
/// The one template the panel renders with **autoescaping on**. The vhost
/// templates cannot escape - escaping would corrupt the config - but this one
/// is HTML, and the only variable is a domain already constrained to
/// `[a-z0-9-.]`. The escaping is here so that constraint stops being
/// load-bearing.
pub(super) async fn write_placeholder_page(
    state: &AppState,
    site: &NewSite<'_>,
) -> Result<(), String> {
    let path = format!("{}/public_html/index.html", site.root_path);
    if tokio::fs::metadata(&path).await.is_ok() {
        // `if placeholder.exists(): return` - an import that already put a
        // page there keeps it.
        return Ok(());
    }
    let rendered = snpanel_nginx::render_placeholder(site.domain).map_err(|e| e.to_string())?;
    let write = shell::privileged(
        state.settings.command_dry_run,
        "site-file-write",
        &[
            site.linux_user,
            site.root_path,
            "public_html/index.html",
            "0644",
        ],
        Some(&rendered),
        None,
    )
    .await;
    if !write.ok() {
        return Err(write
            .failure_detail("Could not write the placeholder page")
            .trim()
            .to_string());
    }
    // `site_users.fix_site_path(str(public), linux_user)`.
    let public = format!("{}/public_html", site.root_path);
    let _ = shell::privileged(
        state.settings.command_dry_run,
        "site-path-fix",
        &[&public, site.linux_user],
        None,
        None,
    )
    .await;
    Ok(())
}

/// `POST /websites/{website_id}/wordpress`.
///
/// Source: `install_wordpress_on_website`. WordPress into a site that already
/// exists — a static or PHP site the customer now wants WordPress on.
///
/// **The database is created with `if_not_exists=False`.** That path must
/// fail rather than quietly adopt a database another site is already using:
/// two sites sharing one WordPress database is a data-loss shape, not a
/// warning.
async fn install_wordpress_on_website(
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
    if has_wordpress_install(&website) {
        return bad_request("WordPress is already installed for this website");
    }

    let owner = match state.db.users().by_id(website.owner_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("Owner not found"),
        Err(e) => {
            tracing::error!("owner lookup failed: {e}");
            return internal_error();
        }
    };
    if let Err(message) = enforce_owner_quota(&state, &owner, WORDPRESS_SITE_ESTIMATE_BYTES).await {
        return crate::errors::error(axum::http::StatusCode::PAYLOAD_TOO_LARGE, &message);
    }

    let text = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let request = CreateRequest {
        domain: website.domain.clone(),
        owner_id: Some(website.owner_id),
        php_version: website.php_version.clone(),
        app_type: "wordpress".to_string(),
        app_id: None,
        install_wordpress: true,
        title: text("title"),
        admin_user: text("admin_user"),
        admin_password: text("admin_password"),
        admin_email: text("admin_email"),
    };
    let linux_user = website.linux_user.clone().unwrap_or_default();
    let runtime_php = Some(website.php_version.clone()).filter(|v| !v.is_empty());
    let site = NewSite {
        domain: &website.domain,
        root_path: &website.root_path,
        linux_user: &linux_user,
        app_type: "wordpress",
        rewrite_mode: "front_controller",
        php_version: &website.php_version,
        runtime_php: runtime_php.as_deref(),
        app_port: None,
        install_wp: true,
        request: &request,
    };

    let created = match crate::mariadb::create_database(&website.domain, "wp", false).await {
        Ok(info) => info,
        Err(e) => return bad_request(&e.to_string()),
    };
    // `except (RuntimeError, ValueError, OSError): mariadb.drop_database(...)`
    // — and **no** `_cleanup_failed_site` here, unlike `create_website`: the
    // directory belonged to a site that already existed and was serving
    // before this request arrived. Deleting it would take a working site down
    // because an install on top of it failed.
    if let Err(message) = install_wordpress(&state, &site, &created).await {
        let _ = crate::mariadb::drop_database(&created.db_name, &created.db_user).await;
        return bad_request(&message);
    }
    if let Err(message) = rewrite_for_wordpress(&state, &website).await {
        let _ = crate::mariadb::drop_database(&created.db_name, &created.db_user).await;
        return bad_request(&message);
    }

    if let Err(e) = state
        .db
        .websites()
        .set_wordpress_installed(website.id, &website.root_path)
        .await
    {
        tracing::error!(
            "recording the WordPress install for {} failed: {e}",
            website.domain
        );
        return internal_error();
    }

    // C3: the column holds Fernet ciphertext, never the password.
    let encrypted =
        snpanel_core::crypto::fernet::encrypt(&state.settings.secret_key, &created.db_password);
    // `db.query(DatabaseAccount).filter(db_name == ...).first()` — a row may
    // already carry this name from a site that was deleted without its
    // database, and the Python takes it over rather than colliding on it.
    let existing = state
        .db
        .databases()
        .by_name(&created.db_name)
        .await
        .unwrap_or_default();
    let stored = match existing {
        Some(row) => {
            state
                .db
                .databases()
                .attach_to_website(
                    row.id,
                    website.owner_id,
                    website.id,
                    &created.db_user,
                    &encrypted,
                )
                .await
        }
        None => state
            .db
            .databases()
            .create(
                website.owner_id,
                Some(website.id),
                &created.db_name,
                &created.db_user,
                &encrypted,
            )
            .await
            .map(|_| ()),
    };
    if let Err(e) = stored {
        tracing::error!(
            "storing the database row for {} failed: {e}",
            website.domain
        );
        return internal_error();
    }

    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "install_wordpress",
        &website.domain,
    )
    .await;

    let row = match state.db.websites().by_id(website.id).await {
        Ok(Some(row)) => row,
        _ => return internal_error(),
    };
    let aliases = state
        .db
        .websites()
        .aliases(row.id)
        .await
        .unwrap_or_default();
    let ssl_enabled = row.ssl_enabled;
    axum::Json(website_json(&row, &aliases, true, ssl_enabled)).into_response()
}

/// Source: `_ensure_default_waf_file` then `_rewrite_website_vhost(app_type=
/// "wordpress", rewrite_mode="front_controller")`.
///
/// **The rule file goes back to the defaults.** A site that had custom WAF
/// rules loses them here, because `_ensure_default_waf_file` writes the
/// default set with no custom block. That is the Python's behaviour and it is
/// reproduced rather than improved on — but it is worth knowing, because the
/// endpoint is named after WordPress and says nothing about the firewall.
async fn rewrite_for_wordpress(
    state: &AppState,
    website: &snpanel_db::Website,
) -> Result<(), String> {
    let waf =
        crate::waf::ensure_default_site_rules(state.settings.command_dry_run, &website.domain)
            .await
            .map_err(|e| e.to_string())?;
    if !waf.ok() {
        return Err(waf
            .failure_detail("Could not save WAF rules")
            .trim()
            .to_string());
    }
    // The row the rewrite reads is the row as it is about to become.
    let mut updated = website.clone();
    updated.app_type = "wordpress".to_string();
    updated.nginx_rewrite_mode = "front_controller".to_string();
    rewrite_owned_vhost(
        state,
        &updated,
        RewriteOverrides {
            app_type: Some("wordpress"),
            rewrite_mode: Some("front_controller"),
            ..RewriteOverrides::default()
        },
    )
    .await
    .map(|_| ())
}

/// Source: `WebsiteUpdate`'s validators.
///
/// Each field is optional, and each one that is present is validated before
/// any of them is applied — pydantic runs on the whole body first. So a
/// request carrying a good `php_version` and a bad `status` changes nothing,
/// which is **not** what the handler's own per-branch failures do.
struct WebsiteUpdateFields {
    php_version: Option<String>,
    app_type: Option<String>,
    app_id: Option<i64>,
    document_root: Option<String>,
    status: Option<String>,
    owner_id: Option<i64>,
    nginx_custom: Option<String>,
    nginx_rewrite_mode: Option<String>,
    waf_enabled: Option<bool>,
    http_flood_enabled: Option<bool>,
}

/// Source: `_validate_document_root`.
///
/// **Not the same function as `DocumentRoot::parse`**, which is
/// `site_users.validate_document_root` and allows a different set of
/// characters. This one is the schema's, and it is stricter: every segment
/// must match `[A-Za-z0-9._-]+`, so `public html` is refused here and
/// accepted there.
fn schema_document_root(value: &str) -> Result<String, String> {
    let cleaned = value.trim().replace('\\', "/");
    let bytes = cleaned.as_bytes();
    let drive_prefix =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/';
    if cleaned.starts_with('/') || drive_prefix {
        return Err("document_root must be relative to the website root".to_string());
    }
    let cleaned = cleaned.trim_matches('/');
    if cleaned.is_empty() || cleaned.chars().count() > 255 {
        return Err("document_root must be a relative path up to 255 characters".to_string());
    }
    let parts: Vec<&str> = cleaned.split('/').collect();
    let safe = |part: &&str| {
        !part.is_empty()
            && *part != "."
            && *part != ".."
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    if !parts.iter().all(safe) {
        return Err(
            "document_root must be a safe relative path such as public_html/public".to_string(),
        );
    }
    Ok(parts.join("/"))
}

/// Source: `WebsiteUpdate`'s five `field_validator`s.
///
/// Every message is the Python's, because pydantic renders a raised
/// `ValueError` as `Value error, <message>` and an administrator reads it.
fn website_update_fields(payload: &Value) -> Result<WebsiteUpdateFields, Response> {
    let text = |key: &str| payload.get(key).and_then(Value::as_str);
    let value_error = |field: &str, message: &str| {
        crate::errors::value_error(field, message, payload.get(field).unwrap_or(&Value::Null))
    };

    let php_version = match text("php_version") {
        Some(v) => {
            if !snpanel_nginx::ALLOWED_PHP_VERSIONS.contains(&v) {
                let mut allowed: Vec<&str> = snpanel_nginx::ALLOWED_PHP_VERSIONS.to_vec();
                allowed.sort_unstable();
                return Err(value_error(
                    "php_version",
                    &format!("Unsupported PHP version. Allowed: {allowed:?}"),
                ));
            }
            Some(v.to_string())
        }
        None => None,
    };

    let app_type = match text("app_type") {
        Some(v) => {
            if !snpanel_nginx::ALLOWED_APP_TYPES.contains(&v) {
                let mut allowed: Vec<&str> = snpanel_nginx::ALLOWED_APP_TYPES.to_vec();
                allowed.sort_unstable();
                return Err(value_error(
                    "app_type",
                    &format!("Unsupported app type. Allowed: {allowed:?}"),
                ));
            }
            Some(v.to_string())
        }
        None => None,
    };

    // `value.strip().lower()` **before** the membership check, and the
    // normalised value is what is stored — so ` Laravel ` is accepted and
    // saved as `laravel`.
    let nginx_rewrite_mode = match text("nginx_rewrite_mode") {
        Some(v) => {
            let normalized = v.trim().to_lowercase();
            if !snpanel_nginx::ALLOWED_REWRITE_MODES.contains(&normalized.as_str()) {
                let mut allowed: Vec<&str> = snpanel_nginx::ALLOWED_REWRITE_MODES.to_vec();
                allowed.sort_unstable();
                return Err(value_error(
                    "nginx_rewrite_mode",
                    &format!("Unsupported nginx rewrite mode. Allowed: {allowed:?}"),
                ));
            }
            Some(normalized)
        }
        None => None,
    };

    let document_root = match text("document_root") {
        Some(v) => match schema_document_root(v) {
            Ok(cleaned) => Some(cleaned),
            Err(message) => return Err(value_error("document_root", &message)),
        },
        None => None,
    };

    let status = match text("status") {
        Some(v) => {
            if !matches!(v, "active" | "suspended" | "pending") {
                return Err(value_error(
                    "status",
                    "status must be one of ['active', 'pending', 'suspended']",
                ));
            }
            Some(v.to_string())
        }
        None => None,
    };

    Ok(WebsiteUpdateFields {
        php_version,
        app_type,
        app_id: payload.get("app_id").and_then(Value::as_i64),
        document_root,
        status,
        owner_id: payload.get("owner_id").and_then(Value::as_i64),
        nginx_custom: text("nginx_custom").map(str::to_string),
        nginx_rewrite_mode,
        waf_enabled: payload.get("waf_enabled").and_then(Value::as_bool),
        http_flood_enabled: payload.get("http_flood_enabled").and_then(Value::as_bool),
    })
}

/// Source: `next_rewrite_mode` in the `app_type` branch.
///
/// **The requested rewrite mode is only honoured for a type that has a
/// choice.** A WordPress site is a front controller and a static site is
/// none, whatever was asked for — asking for `laravel` on a static site would
/// otherwise write a `try_files` that reaches a PHP pool the site does not
/// have.
fn rewrite_mode_for_app_type<'a>(
    app_type: &str,
    requested: Option<&'a str>,
    current: &'a str,
) -> &'a str {
    match app_type {
        "wordpress" => "front_controller",
        "static" => "none",
        _ => requested.unwrap_or(current),
    }
}

/// An allow-listed app type, as a `'static` string.
///
/// `RewriteOverrides` holds `&'static str` because the suspend path passes a
/// literal. The value here came out of `ALLOWED_APP_TYPES`, so the matching
/// entry of that list **is** the same string with a longer lifetime. The
/// fallback is unreachable for a validated value, and it is the Python's own
/// default rather than a panic.
fn static_app_type(value: &str) -> &'static str {
    snpanel_nginx::ALLOWED_APP_TYPES
        .iter()
        .copied()
        .find(|t| *t == value)
        .unwrap_or("wordpress")
}

/// The same for a rewrite mode.
fn static_rewrite_mode(value: &str) -> &'static str {
    snpanel_nginx::ALLOWED_REWRITE_MODES
        .iter()
        .copied()
        .find(|m| *m == value)
        .unwrap_or("none")
}

/// The three things every branch that touches the vhost does first.
///
/// Source: `waf.sync_website_rules` then `_sync_http_flood_zones` then
/// `_rewrite_website_vhost`, repeated in five of this endpoint's branches.
/// Written once because five copies is five places for the order to drift,
/// and the order matters: the rule file has to exist before a vhost that
/// includes it is tested.
async fn resync_and_rewrite(
    state: &AppState,
    website: &snpanel_db::Website,
    overrides: RewriteOverrides,
) -> Result<(), String> {
    let waf =
        crate::waf::sync_website_rules(state.settings.command_dry_run, website, &server_crs_mode())
            .await
            .map_err(|e| e.to_string())?;
    if !waf.ok() {
        return Err(command_error(&waf));
    }
    if website.http_flood_enabled {
        sync_http_flood_zones(state)
            .await
            .map_err(|_| "Could not write the HTTP flood zones".to_string())?;
    }
    rewrite_owned_vhost(state, website, overrides)
        .await
        .map(|_| ())
}

/// `PATCH /websites/{website_id}`.
///
/// Source: `update_website`. Nine independent branches, each with its own
/// `try`.
///
/// **A branch that fails does not undo the branches before it.** The Python
/// assigns each field to the session as its branch succeeds and commits once
/// at the end, so a request that changes the PHP version and then fails on
/// the document root leaves the new PHP version written. That is reproduced
/// rather than tidied into all-or-nothing: an administrator who retries sees
/// the same state the Python would have left them.
async fn update_website(
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
    // Pydantic validates the whole body before the handler runs, so a bad
    // field refuses the request without applying the good ones.
    let fields = match website_update_fields(&payload) {
        Ok(f) => f,
        Err(r) => return r,
    };
    let mut website = match authorized(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    if let Some(php_version) = &fields.php_version {
        if let Err(r) = apply_php_version(&state, &mut website, php_version).await {
            return r;
        }
    }

    let requested_app_type = fields
        .app_type
        .as_deref()
        .filter(|t| *t != current_app_type(&website));
    if let Some(next_app_type) = requested_app_type {
        if let Err(r) = apply_app_type(&state, &current, &mut website, next_app_type, &fields).await
        {
            return r;
        }
    } else if let Some(app_id) = fields.app_id {
        // Same mode, different application behind it. Only for a type that
        // proxies: setting `app_id` on a static site would store a pointer
        // nothing reads.
        if website.app_type == "application" {
            if let Err(r) = apply_app_id(&state, &current, &mut website, app_id).await {
                return r;
            }
        }
    }

    if let Some(status) = &fields.status {
        if let Err(e) = state.db.websites().set_status(website.id, status).await {
            tracing::error!("setting the status of {} failed: {e}", website.domain);
            return internal_error();
        }
        website.status = status.clone();
    }

    if let Some(document_root) = fields
        .document_root
        .as_deref()
        .filter(|d| *d != current_document_root(&website))
    {
        if let Err(r) = apply_document_root(&state, &mut website, document_root).await {
            return r;
        }
    }

    if let Some(owner_id) = fields.owner_id {
        if let Err(r) = apply_owner(&state, &current, &mut website, owner_id).await {
            return r;
        }
    }

    if let Some(nginx_custom) = &fields.nginx_custom {
        let validated = match snpanel_nginx::CustomDirectives::validate(nginx_custom) {
            Ok(v) => v,
            Err(e) => return bad_request(&e.to_string()),
        };
        if let Err(r) = update_custom_block(&state, &website.domain, &validated).await {
            return r;
        }
        if let Err(e) = state
            .db
            .websites()
            .set_nginx_custom(website.id, validated.as_str())
            .await
        {
            tracing::error!("saving the custom block for {} failed: {e}", website.domain);
            return internal_error();
        }
        website.nginx_custom = validated.as_str().to_string();
        website.nginx_config_mode = "managed".to_string();
    }

    if let Some(requested) = fields
        .nginx_rewrite_mode
        .as_deref()
        .filter(|m| *m != current_rewrite_mode(&website))
    {
        if let Err(r) = apply_rewrite_mode(&state, &mut website, requested).await {
            return r;
        }
    }

    if let Some(waf_enabled) = fields.waf_enabled {
        if let Err(r) = apply_waf_enabled(&state, &current, &mut website, waf_enabled).await {
            return r;
        }
    }

    if let Some(http_flood_enabled) = fields.http_flood_enabled {
        // `ensure_role(current_user.role, Role.admin)` — the flood zones are
        // shared nginx state, so a customer cannot turn their own on.
        if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
            return not_enough_permissions();
        }
        if let Err(r) = apply_http_flood(&state, &mut website, http_flood_enabled).await {
            return r;
        }
    }

    audit_website(&state, current.user.id, "update_website", &website.domain).await;

    let row = match state.db.websites().by_id(website.id).await {
        Ok(Some(row)) => row,
        _ => return internal_error(),
    };
    let aliases = state
        .db
        .websites()
        .aliases(row.id)
        .await
        .unwrap_or_default();
    let wordpress = has_wordpress_install(&row);
    let ssl_enabled = row.ssl_enabled;
    axum::Json(website_json(&row, &aliases, wordpress, ssl_enabled)).into_response()
}

/// `website.app_type or "wordpress"`, which the Python writes six times.
fn current_app_type(website: &snpanel_db::Website) -> &str {
    if website.app_type.is_empty() {
        "wordpress"
    } else {
        &website.app_type
    }
}

/// `website.document_root or "public_html"`.
fn current_document_root(website: &snpanel_db::Website) -> &str {
    if website.document_root.is_empty() {
        "public_html"
    } else {
        &website.document_root
    }
}

/// `_website_rewrite_mode` — `website.nginx_rewrite_mode or "none"`.
fn current_rewrite_mode(website: &snpanel_db::Website) -> &str {
    if website.nginx_rewrite_mode.is_empty() {
        "none"
    } else {
        &website.nginx_rewrite_mode
    }
}

async fn apply_php_version(
    state: &AppState,
    website: &mut snpanel_db::Website,
    php_version: &str,
) -> Result<(), Response> {
    let app_type = current_app_type(website).to_string();
    let runtime_php = matches!(app_type.as_str(), "wordpress" | "php").then_some(php_version);
    if let (Some(linux_user), Some(runtime)) = (
        website.linux_user.as_deref().filter(|u| !u.is_empty()),
        runtime_php,
    ) {
        // The pool for the new version has to exist before a vhost pointing
        // at its socket is tested.
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "site-runtime-ensure",
            &[linux_user, &website.root_path, runtime],
            None,
            None,
        )
        .await;
    }

    // The row the rewrite reads is the row as it is about to become.
    let mut updated = website.clone();
    updated.php_version = php_version.to_string();
    resync_and_rewrite(
        state,
        &updated,
        RewriteOverrides {
            app_type: Some(static_app_type(&app_type)),
            ..RewriteOverrides::default()
        },
    )
    .await
    .map_err(|message| bad_request(&format!("Cannot write Nginx config: {message}")))?;

    state
        .db
        .websites()
        .set_php_version(website.id, php_version)
        .await
        .map_err(|e| {
            tracing::error!("setting the PHP version of {} failed: {e}", website.domain);
            internal_error()
        })?;
    website.php_version = php_version.to_string();

    // `except (RuntimeError, ValueError): pass` — existing cron lines carry
    // the previous PHP CLI path, and leaving them would keep running the site
    // on a version it no longer has. A failure here is not worth undoing the
    // version change for.
    retarget_website_cron(state, website).await;
    Ok(())
}

/// Source: `cron.retarget_php_binary`.
///
/// Reads the whole crontab, rewrites the lines carrying this site's marker,
/// and writes it back — but **only if something changed**, because a crontab
/// rewritten to the same bytes is still a crontab replaced.
async fn retarget_website_cron(state: &AppState, website: &snpanel_db::Website) {
    let php_bin = crate::cron::php_binary(&website.php_version);
    let cron_user = crate::cron::cron_user_for_website(
        website.linux_user.as_deref(),
        &website.root_path,
        &super::maintenance::web_user(),
    );
    let marker = format!("snpanel:{}", website.domain);
    let all = super::maintenance::list_cron_all(state, &cron_user).await;

    let mut changed = 0usize;
    let mut updated: Vec<String> = Vec::new();
    for line in all.lines() {
        if line.contains(&marker) {
            let next = crate::cron::retarget_php_line(line, &php_bin);
            if next != line {
                changed += 1;
                updated.push(next);
                continue;
            }
        }
        updated.push(line.to_string());
    }
    if changed == 0 {
        return;
    }
    let content = if updated.is_empty() {
        String::new()
    } else {
        format!("{}\n", updated.join("\n"))
    };
    if let Err(e) = super::maintenance::write_crontab(state, &cron_user, &content).await {
        tracing::error!(
            "could not retarget the cron jobs of {}: {e:?}",
            website.domain
        );
    }
}

async fn apply_app_type(
    state: &AppState,
    current: &CurrentUser,
    website: &mut snpanel_db::Website,
    next_app_type: &str,
    fields: &WebsiteUpdateFields,
) -> Result<(), Response> {
    let next_app = if next_app_type == "application" {
        Some(resolve_app_for_owner(state, website.owner_id, fields.app_id, current).await?)
    } else {
        None
    };

    let runtime_php = matches!(next_app_type, "wordpress" | "php")
        .then(|| website.php_version.clone())
        .filter(|v| !v.is_empty());
    if let (Some(linux_user), Some(runtime)) = (
        website.linux_user.as_deref().filter(|u| !u.is_empty()),
        runtime_php.as_deref(),
    ) {
        let _ = shell::privileged(
            state.settings.command_dry_run,
            "site-runtime-ensure",
            &[linux_user, &website.root_path, runtime],
            None,
            None,
        )
        .await;
    }

    let next_rewrite_mode = rewrite_mode_for_app_type(
        next_app_type,
        fields.nginx_rewrite_mode.as_deref(),
        current_rewrite_mode(website),
    )
    .to_string();

    let mut updated = website.clone();
    updated.app_type = next_app_type.to_string();
    updated.nginx_rewrite_mode = next_rewrite_mode.clone();
    updated.app_id = next_app.as_ref().map(|a| a.id);
    resync_and_rewrite(
        state,
        &updated,
        RewriteOverrides {
            app_type: Some(static_app_type(next_app_type)),
            rewrite_mode: Some(static_rewrite_mode(&next_rewrite_mode)),
            ..RewriteOverrides::default()
        },
    )
    .await
    .map_err(|message| bad_request(&format!("Cannot change website mode: {message}")))?;

    state
        .db
        .websites()
        .set_app_mode(
            website.id,
            next_app_type,
            &next_rewrite_mode,
            next_app.as_ref().map(|a| a.id),
        )
        .await
        .map_err(|e| {
            tracing::error!("setting the mode of {} failed: {e}", website.domain);
            internal_error()
        })?;
    website.app_type = next_app_type.to_string();
    website.nginx_rewrite_mode = next_rewrite_mode;
    website.app_id = next_app.as_ref().map(|a| a.id);
    Ok(())
}

async fn apply_app_id(
    state: &AppState,
    current: &CurrentUser,
    website: &mut snpanel_db::Website,
    app_id: i64,
) -> Result<(), Response> {
    let app = resolve_app_for_owner(state, website.owner_id, Some(app_id), current).await?;
    let name = app.name.clone();
    rewrite_owned_vhost(state, website, RewriteOverrides::default())
        .await
        .map_err(|message| {
            bad_request(&format!("Cannot point this website at {name}: {message}"))
        })?;
    state
        .db
        .websites()
        .set_app_id(website.id, Some(app.id))
        .await
        .map_err(|e| {
            tracing::error!("setting the application of {} failed: {e}", website.domain);
            internal_error()
        })?;
    website.app_id = Some(app.id);
    Ok(())
}

async fn apply_document_root(
    state: &AppState,
    website: &mut snpanel_db::Website,
    document_root: &str,
) -> Result<(), Response> {
    let wrap = |message: String| bad_request(&format!("Cannot change document root: {message}"));

    // `site_users.ensure_document_root` — the directory has to exist before a
    // vhost with a `root` pointing at it is tested.
    if let Some(linux_user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) {
        let result = shell::privileged(
            state.settings.command_dry_run,
            "site-document-root-ensure",
            &[linux_user, &website.root_path, document_root],
            None,
            None,
        )
        .await;
        if !result.ok() {
            return Err(wrap(command_error(&result)));
        }
    }

    let mut updated = website.clone();
    updated.document_root = document_root.to_string();
    resync_and_rewrite(
        state,
        &updated,
        RewriteOverrides {
            app_type: Some(static_app_type(current_app_type(website))),
            ..RewriteOverrides::default()
        },
    )
    .await
    .map_err(wrap)?;

    state
        .db
        .websites()
        .set_document_root(website.id, document_root)
        .await
        .map_err(|e| {
            tracing::error!(
                "setting the document root of {} failed: {e}",
                website.domain
            );
            internal_error()
        })?;
    website.document_root = document_root.to_string();
    Ok(())
}

async fn apply_owner(
    state: &AppState,
    current: &CurrentUser,
    website: &mut snpanel_db::Website,
    owner_id: i64,
) -> Result<(), Response> {
    if !permissions::has_role(&current.user.role, permissions::Role::Admin) {
        return Err(not_enough_permissions());
    }
    let owner = match state.db.users().by_id(owner_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(not_found("Owner not found")),
        Err(e) => {
            tracing::error!("owner lookup failed: {e}");
            return Err(internal_error());
        }
    };
    // The count excludes this website: moving a site to an owner who is
    // already at their limit is refused, but moving it to the owner it
    // already has is not.
    let assigned = state
        .db
        .websites()
        .count_for_owner_excluding(owner.id, website.id)
        .await
        .unwrap_or(i64::MAX);
    if !permissions::is_admin_role(&owner.role) && assigned >= owner.website_limit {
        return Err(crate::errors::error(
            axum::http::StatusCode::FORBIDDEN,
            "Website limit reached",
        ));
    }
    if owner_id == website.owner_id {
        // The Python still assigns it, and the files are not moved.
        state
            .db
            .websites()
            .set_owner_id(website.id, owner_id)
            .await
            .map_err(|e| {
                tracing::error!("setting the owner of {} failed: {e}", website.domain);
                internal_error()
            })?;
        return Ok(());
    }

    // The new owner's allowance has to cover what is about to land in it.
    let incoming = crate::storage_quota::website_storage_used_bytes(&website.root_path);
    if let Err(message) = enforce_owner_quota(state, &owner, incoming).await {
        return Err(crate::errors::error(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            &message,
        ));
    }

    let Ok(panel_user) = snpanel_core::types::PanelUsername::parse(&owner.username) else {
        return Err(internal_error());
    };
    let Ok(domain) = snpanel_core::Domain::parse(&website.domain) else {
        return Err(internal_error());
    };
    let new_root = snpanel_core::types::SitePath::site_root(&panel_user, &domain);
    let new_root_path = new_root.as_path().to_string_lossy().into_owned();
    let new_linux_user = panel_user.as_str().to_string();
    let runtime_php = matches!(current_app_type(website), "wordpress" | "php")
        .then(|| website.php_version.clone())
        .filter(|v| !v.is_empty());

    let moved = shell::privileged(
        state.settings.command_dry_run,
        "site-runtime-move",
        &[
            &new_linux_user,
            &website.root_path,
            &new_root_path,
            runtime_php.as_deref().unwrap_or("none"),
        ],
        None,
        None,
    )
    .await;
    if !moved.ok() {
        return Err(bad_request(&command_error(&moved)));
    }

    let mut updated = website.clone();
    updated.root_path = new_root_path.clone();
    updated.linux_user = Some(new_linux_user.clone());
    resync_and_rewrite(
        state,
        &updated,
        RewriteOverrides {
            app_type: Some(static_app_type(current_app_type(website))),
            ..RewriteOverrides::default()
        },
    )
    .await
    .map_err(|message| bad_request(&message))?;

    state
        .db
        .websites()
        .set_owner(website.id, owner_id, &new_root_path, &new_linux_user)
        .await
        .map_err(|e| {
            tracing::error!("moving {} to another owner failed: {e}", website.domain);
            internal_error()
        })?;
    // Not in the Python: its databases go with it, so they are in the new
    // owner's backup and on their Databases page rather than the old one's.
    if let Err(e) = state
        .db
        .databases()
        .move_with_site(website.id, owner_id)
        .await
    {
        tracing::error!("moving the databases of {} failed: {e}", website.domain);
    }
    website.owner_id = owner_id;
    website.root_path = new_root_path;
    website.linux_user = Some(new_linux_user);
    Ok(())
}

async fn apply_rewrite_mode(
    state: &AppState,
    website: &mut snpanel_db::Website,
    requested: &str,
) -> Result<(), Response> {
    let app_type = current_app_type(website).to_string();
    let next = rewrite_mode_for_app_type(&app_type, Some(requested), requested).to_string();

    let mut updated = website.clone();
    updated.nginx_rewrite_mode = next.clone();
    resync_and_rewrite(
        state,
        &updated,
        RewriteOverrides {
            app_type: Some(static_app_type(&app_type)),
            rewrite_mode: Some(static_rewrite_mode(&next)),
            ..RewriteOverrides::default()
        },
    )
    .await
    .map_err(|message| bad_request(&format!("Cannot change Nginx rewrite: {message}")))?;

    state
        .db
        .websites()
        .set_rewrite_mode(website.id, &next)
        .await
        .map_err(|e| {
            tracing::error!("setting the rewrite mode of {} failed: {e}", website.domain);
            internal_error()
        })?;
    website.nginx_rewrite_mode = next;
    website.nginx_config_mode = "managed".to_string();
    Ok(())
}

async fn apply_waf_enabled(
    state: &AppState,
    current: &CurrentUser,
    website: &mut snpanel_db::Website,
    waf_enabled: bool,
) -> Result<(), Response> {
    // This endpoint already restricts the website itself to its owner, so the
    // only extra question is whether their package includes the WAF.
    if !may_manage_waf(state, current).await {
        return Err(crate::errors::error(
            axum::http::StatusCode::FORBIDDEN,
            "Your hosting package does not include WAF settings",
        ));
    }
    let waf =
        crate::waf::sync_website_rules(state.settings.command_dry_run, website, &server_crs_mode())
            .await
            .map_err(|e| bad_request(&e.to_string()))?;
    if !waf.ok() {
        return Err(bad_request(&command_error(&waf)));
    }
    update_waf_block(state, &website.domain, waf_enabled).await?;
    state
        .db
        .websites()
        .set_waf_enabled(website.id, waf_enabled)
        .await
        .map_err(|e| {
            tracing::error!("setting the WAF flag of {} failed: {e}", website.domain);
            internal_error()
        })?;
    website.waf_enabled = waf_enabled;
    Ok(())
}

async fn apply_http_flood(
    state: &AppState,
    website: &mut snpanel_db::Website,
    enabled: bool,
) -> Result<(), Response> {
    // The row is written **first**, because the zone file is built from the
    // rows: writing the zones before the row would build them from the old
    // answer.
    state
        .db
        .websites()
        .set_http_flood_enabled(website.id, enabled)
        .await
        .map_err(|e| {
            tracing::error!("setting the flood flag of {} failed: {e}", website.domain);
            internal_error()
        })?;
    website.http_flood_enabled = enabled;

    let config = snpanel_nginx::HttpFloodConfig::from_text(&website.http_flood_config);
    // **Turning it on writes the zones first; turning it off writes the vhost
    // first.** Either way the vhost never references a zone that is not
    // defined, which nginx refuses to start on — and that would take every
    // site down, not just this one.
    if enabled {
        sync_http_flood_zones(state).await?;
        update_http_flood_block(state, &website.domain, true, &config).await?;
    } else {
        update_http_flood_block(state, &website.domain, false, &config).await?;
        sync_http_flood_zones(state).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rewrite mode a type is allowed to have.
    ///
    /// Source: `next_rewrite_mode = "front_controller" if app_type ==
    /// "wordpress" else "none" if app_type == "static" else
    /// payload.nginx_rewrite_mode or _website_rewrite_mode(website)`.
    ///
    /// **Two of the four types have no choice.** Asking for `laravel` on a
    /// static site would otherwise write a `try_files` that falls through to a
    /// PHP pool the site does not have, and every URL that is not a file
    /// would 502 rather than 404.
    #[test]
    fn only_a_type_with_a_choice_gets_the_rewrite_mode_it_asked_for() {
        // WordPress and static are decided by the type, whatever was asked.
        assert_eq!(
            rewrite_mode_for_app_type("wordpress", Some("laravel"), "none"),
            "front_controller"
        );
        assert_eq!(
            rewrite_mode_for_app_type("static", Some("laravel"), "front_controller"),
            "none"
        );
        // PHP and application take the request.
        assert_eq!(
            rewrite_mode_for_app_type("php", Some("laravel"), "none"),
            "laravel"
        );
        assert_eq!(
            rewrite_mode_for_app_type("application", Some("codeigniter"), "none"),
            "codeigniter"
        );
        // And keep what the row had when nothing was asked for.
        assert_eq!(
            rewrite_mode_for_app_type("php", None, "seohburl"),
            "seohburl"
        );
        assert_eq!(
            rewrite_mode_for_app_type("application", None, "none"),
            "none"
        );
    }

    /// The schema's document root is not the site's.
    ///
    /// Source: `_validate_document_root` in `schemas.py`, which is **not**
    /// `site_users.validate_document_root`. The schema's is stricter: every
    /// segment must match `[A-Za-z0-9._-]+`, so a space is refused here and
    /// accepted by the other one. Two functions with the same name and
    /// different answers is exactly the shape that got `is_domain` wrong
    /// earlier in this migration.
    #[test]
    fn the_schemas_document_root_is_the_stricter_of_the_two() {
        assert_eq!(
            schema_document_root("public_html").as_deref(),
            Ok("public_html")
        );
        assert_eq!(
            schema_document_root("  public_html/public  ").as_deref(),
            Ok("public_html/public")
        );
        // Backslashes become slashes, and the surrounding ones are stripped.
        assert_eq!(
            schema_document_root("/public_html\\public/")
                .as_deref()
                .map_err(String::as_str),
            Err("document_root must be relative to the website root")
        );
        assert_eq!(
            schema_document_root("public_html\\public").as_deref(),
            Ok("public_html/public")
        );
        // An empty segment is refused rather than collapsed: the Python
        // splits on `/` and checks every part, and `""` is in the rejected
        // set alongside `.` and `..`.
        assert!(schema_document_root("a//b").is_err());
        // A **trailing** slash is stripped, and this is the only shape that
        // says so: every other case here with a slash to strip has one at the
        // start, which the check above refuses before the strip is reached.
        assert_eq!(
            schema_document_root("public_html/").as_deref(),
            Ok("public_html")
        );
        assert_eq!(
            schema_document_root("public_html//").as_deref(),
            Ok("public_html")
        );
        assert_eq!(schema_document_root("a/b/").as_deref(), Ok("a/b"));
        // Stripped to nothing is refused, not accepted as empty.
        assert!(schema_document_root("//").is_err());
        // The **message**, not just the refusal. A Windows drive prefix is
        // also caught by the character rule below it - `:` is not in
        // `[A-Za-z0-9._-]` - so only the message says which check fired, and
        // a mutation deleting the drive check survived a test that read one
        // and not the other.
        assert_eq!(
            schema_document_root("C:/win")
                .as_deref()
                .map_err(String::as_str),
            Err("document_root must be relative to the website root")
        );
        assert_eq!(
            schema_document_root("a b")
                .as_deref()
                .map_err(String::as_str),
            Err("document_root must be a safe relative path such as public_html/public")
        );
        assert_eq!(
            schema_document_root("   ")
                .as_deref()
                .map_err(String::as_str),
            Err("document_root must be a relative path up to 255 characters")
        );

        for bad in ["/abs", "C:/win", "", "   ", "..", "a/../b", "a/./b"] {
            assert!(schema_document_root(bad).is_err(), "{bad:?} was accepted");
        }
        // A space is a segment character the *other* validator allows.
        assert!(schema_document_root("public html").is_err());
        assert!(schema_document_root("a b/c").is_err());
        // 255 characters, counted after the slashes are stripped.
        assert!(schema_document_root(&"a".repeat(255)).is_ok());
        assert!(schema_document_root(&"a".repeat(256)).is_err());
    }

    /// The payload is validated whole before anything is applied.
    ///
    /// Source: pydantic, which runs on the body before the handler sees it.
    /// So a request carrying a good `php_version` and a bad `status` changes
    /// **nothing** — which is not what the handler's own per-branch failures
    /// do, and the difference is worth keeping straight.
    #[test]
    fn a_bad_field_refuses_the_request_rather_than_the_branch() {
        let fields = |payload: Value| website_update_fields(&payload);

        assert!(fields(json!({})).is_ok());
        // Good php_version, bad status: refused, and nothing is applied.
        assert!(fields(json!({ "php_version": "8.4", "status": "paused" })).is_err());
        assert!(fields(json!({ "php_version": "9.9" })).is_err());
        assert!(fields(json!({ "app_type": "django" })).is_err());
        assert!(fields(json!({ "document_root": "/abs" })).is_err());
        assert!(fields(json!({ "nginx_rewrite_mode": "symfony" })).is_err());

        // The rewrite mode is trimmed and lowered **before** the membership
        // check, and the normalised value is what is stored.
        let ok = fields(json!({ "nginx_rewrite_mode": "  LARAVEL  " })).expect("accepted");
        assert_eq!(ok.nginx_rewrite_mode.as_deref(), Some("laravel"));

        // The three statuses, and nothing else.
        for status in ["active", "suspended", "pending"] {
            assert!(fields(json!({ "status": status })).is_ok(), "{status}");
        }
        for status in ["Active", "deleted", ""] {
            assert!(fields(json!({ "status": status })).is_err(), "{status}");
        }

        // A field that is absent stays absent rather than becoming a default:
        // `PATCH` with `{}` must change nothing at all.
        let empty = fields(json!({})).expect("accepted");
        assert!(empty.php_version.is_none());
        assert!(empty.app_type.is_none());
        assert!(empty.status.is_none());
        assert!(empty.owner_id.is_none());
        assert!(empty.waf_enabled.is_none());
        assert!(empty.http_flood_enabled.is_none());
    }

    /// The row's blank columns read as the Python's defaults.
    ///
    /// Source: `website.app_type or "wordpress"`, `website.document_root or
    /// "public_html"`, `_website_rewrite_mode`. A row written before a column
    /// had a default carries an empty string, and comparing the request
    /// against `""` rather than against the default would rewrite the vhost
    /// for a change that is not one.
    #[test]
    fn a_blank_column_reads_as_the_python_default() {
        let mut w = website();
        w.app_type = String::new();
        w.document_root = String::new();
        w.nginx_rewrite_mode = String::new();
        assert_eq!(current_app_type(&w), "wordpress");
        assert_eq!(current_document_root(&w), "public_html");
        assert_eq!(current_rewrite_mode(&w), "none");

        w.app_type = "php".to_string();
        w.document_root = "public".to_string();
        w.nginx_rewrite_mode = "laravel".to_string();
        assert_eq!(current_app_type(&w), "php");
        assert_eq!(current_document_root(&w), "public");
        assert_eq!(current_rewrite_mode(&w), "laravel");
    }

    /// An allow-listed value keeps its identity, not a default.
    #[test]
    fn a_validated_value_survives_the_lifetime_widening() {
        for app_type in snpanel_nginx::ALLOWED_APP_TYPES {
            assert_eq!(static_app_type(app_type), *app_type);
        }
        for mode in snpanel_nginx::ALLOWED_REWRITE_MODES {
            assert_eq!(static_rewrite_mode(mode), *mode);
        }
        // The fallbacks are the Python's defaults, reached only by a value
        // that never came through the validator.
        assert_eq!(static_app_type("django"), "wordpress");
        assert_eq!(static_rewrite_mode("symfony"), "none");
    }

    /// `install_wordpress=true` on a static site installs nothing.
    ///
    /// Source: `install_wp = payload.install_wordpress and payload.app_type ==
    /// "wordpress"`. **Both, not either.** A port that took the flag alone
    /// would download a hundred megabytes of PHP into a site the customer
    /// asked to be static, and then serve it as text - every `.php` file in
    /// WordPress readable over HTTP, `wp-config.php` among them.
    #[test]
    fn installing_wordpress_takes_the_flag_and_the_mode_together() {
        assert!(installs_wordpress(true, "wordpress"));
        assert!(!installs_wordpress(true, "static"));
        assert!(!installs_wordpress(true, "php"));
        assert!(!installs_wordpress(true, "application"));
        assert!(!installs_wordpress(false, "wordpress"));
    }

    /// Asking for WordPress and not getting it leaves a PHP site, not a
    /// WordPress one.
    ///
    /// Source: `app_type_value = "php" if payload.app_type == "wordpress" else
    /// payload.app_type`. An empty directory rendered with WordPress's
    /// front-controller rewrite serves nothing but 404s, because every request
    /// goes to an `index.php` that is not there.
    #[test]
    fn a_site_that_did_not_get_wordpress_is_served_as_php() {
        assert_eq!(site_app_type(true, "wordpress"), "wordpress");
        assert_eq!(site_app_type(false, "wordpress"), "php");
        assert_eq!(site_app_type(false, "static"), "static");
        assert_eq!(site_app_type(false, "php"), "php");
        assert_eq!(site_app_type(false, "application"), "application");

        // And the rewrite mode follows the type it ends up with.
        assert_eq!(site_rewrite_mode("wordpress"), "front_controller");
        for other in ["php", "static", "application"] {
            assert_eq!(site_rewrite_mode(other), "none", "{other}");
        }
    }

    /// The quota is charged for what the request is about to write.
    ///
    /// A WordPress install is a hundred megabytes this request downloads; a
    /// static site is the placeholder page. Charging the static figure for a
    /// WordPress install lets a customer at their limit start one that then
    /// fails part-way, leaving files behind that the cleanup has to find.
    #[test]
    fn the_quota_estimate_matches_what_is_about_to_be_written() {
        // Read through a binding: clippy sees straight through a comparison
        // of two constants and calls it a constant assertion, which it is -
        // but the constants are the point, and a test that cannot name them
        // is a test that lets them drift.
        let wordpress: u64 = WORDPRESS_SITE_ESTIMATE_BYTES;
        let static_site: u64 = STATIC_SITE_ESTIMATE_BYTES;
        assert_eq!(wordpress, 100 * 1024 * 1024);
        assert_eq!(static_site, 1024 * 1024);
        assert!(wordpress > static_site);
    }

    /// The legacy endpoint is the same call with two fields forced.
    ///
    /// Source: `create_wordpress` - `payload.model_copy(update={
    /// "install_wordpress": True, "app_type": "wordpress"})`. Forcing both is
    /// what makes it install anything: forcing the flag alone would fall foul
    /// of the `and` above and quietly create a static site on an endpoint
    /// named `/wordpress`.
    #[test]
    fn the_legacy_wordpress_endpoint_forces_both_fields() {
        let payload = json!({
            "domain": "example.com",
            "app_type": "static",
            "install_wordpress": false,
        });
        let forced = create_request(&payload, Some(true)).expect("valid");
        assert_eq!(forced.app_type, "wordpress");
        assert!(forced.install_wordpress);
        assert!(installs_wordpress(
            forced.install_wordpress,
            &forced.app_type
        ));

        // The ordinary endpoint leaves the payload alone.
        let plain = create_request(&payload, None).expect("valid");
        assert_eq!(plain.app_type, "static");
        assert!(!plain.install_wordpress);
    }

    /// The payload's defaults, and the app type it refuses.
    #[test]
    fn a_create_payload_defaults_the_way_pydantic_does() {
        let minimal = create_request(&json!({ "domain": "Example.COM " }), None).expect("valid");
        // The domain is folded and trimmed before anything looks it up, or
        // two spellings of one name would both be "available".
        assert_eq!(minimal.domain, "example.com");
        assert_eq!(minimal.app_type, "wordpress");
        assert!(!minimal.install_wordpress);
        assert_eq!(minimal.owner_id, None);

        assert!(create_request(&json!({ "domain": "  " }), None).is_err());
        assert!(create_request(&json!({}), None).is_err());
        // An app type the renderer has no template for is refused here rather
        // than at render time, after the directory has been made.
        assert!(create_request(&json!({ "domain": "a.com", "app_type": "django" }), None).is_err());
        for allowed in snpanel_nginx::ALLOWED_APP_TYPES {
            assert!(
                create_request(&json!({ "domain": "a.com", "app_type": allowed }), None).is_ok(),
                "{allowed} was refused"
            );
        }
    }

    /// The placeholder page escapes what it interpolates.
    ///
    /// The only variable is a domain already constrained to `[a-z0-9-.]`, so
    /// this is a no-op for every value that can reach it today. It is asserted
    /// so that constraint stops being the only thing standing between a domain
    /// and a script tag on the page it renders.
    #[test]
    fn the_placeholder_page_escapes_its_domain() {
        let page = snpanel_nginx::render_placeholder("example.com").expect("renders");
        assert!(page.starts_with("<!DOCTYPE html>"));
        assert!(page.contains("<title>example.com</title>"));

        let nasty = snpanel_nginx::render_placeholder("a<script>b").expect("renders");
        assert!(!nasty.contains("<script>b"), "the domain was not escaped");
        assert!(nasty.contains("a&lt;script&gt;b"));
    }

    /// `?delete_files=0` keeps the files.
    ///
    /// Source: `delete_files: bool = True` - pydantic's bool parsing, not
    /// Rust's. Absent means **true**, and a caller who passes `0`, `off` or
    /// `no` expects the files kept. A port that understood only `false` would
    /// delete a customer's site because their client spelled it `0`, and
    /// there is nothing to undo that with.
    #[test]
    fn a_falsey_query_flag_keeps_the_files() {
        let flag = |value: Option<&str>| {
            let mut params = HashMap::new();
            if let Some(v) = value {
                params.insert("delete_files".to_string(), v.to_string());
            }
            query_flag(&params, "delete_files")
        };

        // Absent is the default, which is true.
        assert!(flag(None));
        for falsey in ["0", "off", "f", "false", "n", "no", "FALSE", " No "] {
            assert!(!flag(Some(falsey)), "{falsey:?} deleted the files");
        }
        for truthy in ["1", "on", "t", "true", "y", "yes", "TRUE"] {
            assert!(flag(Some(truthy)), "{truthy:?} kept the files");
        }
        // Anything pydantic would refuse is not a reason to keep them: the
        // Python 422s, and the closest this can do without changing the
        // response shape is the default.
        assert!(flag(Some("maybe")));
    }

    /// The toast says what happened to the certificate.
    ///
    /// Source: `message = f"Deleted {domain}."` plus the note with its first
    /// letter capitalised. **"Kept" is the surprising outcome**: the row is
    /// gone, so this sentence is the only thing telling an administrator the
    /// lineage is still on the machine. Without it they re-issue a
    /// certificate they already have and spend a Let's Encrypt rate limit on
    /// it.
    #[test]
    fn the_deletion_message_says_what_became_of_the_certificate() {
        assert_eq!(
            deletion_message("a.example.com", ""),
            "Deleted a.example.com."
        );
        assert_eq!(
            deletion_message(
                "a.example.com",
                "kept the certificate for a.example.com: still covers b.example.com"
            ),
            "Deleted a.example.com. Kept the certificate for a.example.com: \
             still covers b.example.com"
        );
        assert_eq!(
            deletion_message("a.example.com", "could not remove the certificate"),
            "Deleted a.example.com. Could not remove the certificate"
        );
        // A one-character note does not lose its only character.
        assert_eq!(
            deletion_message("a.example.com", "x"),
            "Deleted a.example.com. X"
        );
    }

    /// `include_ssl` and `preserve_existing_ssl` are different switches.
    ///
    /// Source: `_rewrite_website_vhost`. Suspension throws the second one and
    /// leaves the first alone; the Let's Encrypt path throws the first. Both
    /// end up with a vhost that serves no TLS, which is why they read as the
    /// same switch and are not:
    ///
    /// - **suspend** stops carrying forward whatever certbot wrote into the
    ///   file, but a suspended site on an uploaded certificate still names it,
    ///   because the row still says that is what it has;
    /// - **Let's Encrypt** names no certificate at all, because certbot is
    ///   about to edit the file and those uploaded files are about to be
    ///   deleted. A vhost still pointing at them would leave nginx unable to
    ///   reload the moment they went.
    #[test]
    fn only_the_letsencrypt_path_rewrites_a_vhost_with_no_certificate() {
        let mut manual = website();
        manual.ssl_mode = "manual".to_string();
        manual.ssl_cert_path = Some("/etc/nginx/snpanel/ssl/sites/a/cert.crt".into());
        manual.ssl_key_path = Some("/etc/nginx/snpanel/ssl/sites/a/privkey.key".into());
        manual.ssl_ca_path = None;
        let its_own = (
            manual.ssl_cert_path.clone(),
            manual.ssl_key_path.clone(),
            None,
        );

        // An ordinary rewrite names what the row has.
        assert_eq!(
            vhost_ssl_paths(&manual, &RewriteOverrides::default()),
            its_own
        );

        // Suspension still names it - this is the assertion that says the two
        // switches have not been collapsed into one.
        assert_eq!(
            vhost_ssl_paths(&manual, &super::super::users::vhost_overrides(true)),
            its_own
        );

        // The Let's Encrypt path names nothing.
        assert_eq!(
            vhost_ssl_paths(
                &manual,
                &RewriteOverrides {
                    include_ssl: Some(false),
                    preserve_existing_ssl: Some(false),
                    ..RewriteOverrides::default()
                }
            ),
            (None, None, None)
        );
    }

    /// Certbot is asked for `www.` whether or not anyone added it.
    ///
    /// Source: `ssl.issue_ssl`. nginx's own vhost listens on `www.<domain>`
    /// regardless (`nginx._server_names`), so a certificate covering only the
    /// bare name gives every visitor who types "www." a hard TLS mismatch
    /// rather than the site. It is added here and **not** in
    /// `safe_domain_list`, which also builds the list an uploaded certificate
    /// is checked against - plenty of real certificates cover only the bare
    /// domain on purpose, and checking them against a `www.` nobody bought
    /// would refuse them.
    #[test]
    fn certbot_is_always_asked_for_the_www_name_too() {
        let names = |domain: &str, aliases: &[&str]| {
            certbot_domains(
                domain,
                &aliases.iter().map(|a| (*a).to_string()).collect::<Vec<_>>(),
            )
            .expect("valid")
        };

        assert_eq!(
            names("example.com", &[]),
            vec!["example.com", "www.example.com"]
        );
        // The site's own name first, then the aliases in order, then `www.`.
        assert_eq!(
            names("example.com", &["shop.example.com"]),
            vec!["example.com", "shop.example.com", "www.example.com"]
        );
        // Already an alias: asked for once, not twice. Certbot refuses a
        // duplicate `-d`.
        assert_eq!(
            names("example.com", &["www.example.com"]),
            vec!["example.com", "www.example.com"]
        );
        // Case and whitespace are folded before the comparison, so a `WWW.`
        // alias is still not added a second time.
        assert_eq!(
            names("example.com", &[" WWW.Example.com "]),
            vec!["example.com", "www.example.com"]
        );
        // A site that *is* the www name does not get `www.www.`.
        assert_eq!(names("www.example.com", &[]), vec!["www.example.com"]);
        // A name that could escape the certificate directory is refused
        // before certbot ever sees it.
        assert!(certbot_domains("../etc", &[]).is_err());
        assert!(certbot_domains("example.com", &["a/b".to_string()]).is_err());
    }

    /// The message an administrator gets when a command fails.
    ///
    /// Source: `_command_error` - stderr, else stdout, else the exit code.
    /// The last case matters: a command that fails silently would otherwise
    /// produce an empty toast, which reads as "nothing happened".
    #[test]
    fn a_failed_command_always_says_something() {
        let result = |out: &str, err: &str, code: i32| {
            command_error(&crate::shell::CommandResult {
                command: "certbot-issue".to_string(),
                returncode: code,
                stdout: out.to_string(),
                stderr: err.to_string(),
            })
        };
        assert_eq!(result("out", "err", 1), "err");
        assert_eq!(result("out", "  ", 1), "out");
        assert_eq!(result("", "", 43), "Command failed with code 43");
        assert_eq!(result("  \n padded \n ", "", 1), "padded");
    }

    /// A site borrowing a certificate has to be pointed at the file.
    ///
    /// Source: `_rewrite_ssl_kwargs`. This one shipped wrong: the vhost
    /// renderer returned no paths for `shared` and `cloudflare`, leaving
    /// `preserve_existing_ssl` to carry over whatever the file already had.
    /// For a site that had never had a certificate there was nothing to carry,
    /// so `POST /websites/{id}/ssl/shared` wrote a row saying the site had SSL
    /// and a vhost serving none - the exact disagreement that endpoint's
    /// rollback exists to prevent.
    #[test]
    fn a_borrowed_certificate_is_the_one_the_vhost_points_at() {
        let paths = |mode: &str, source: Option<&str>, cert: Option<&str>, key: Option<&str>| {
            let mut w = website();
            w.ssl_mode = mode.to_string();
            w.ssl_source_domain = source.map(str::to_string);
            w.ssl_cert_path = cert.map(str::to_string);
            w.ssl_key_path = key.map(str::to_string);
            w.ssl_ca_path = None;
            rewrite_ssl_paths(&w)
        };

        // Borrowing resolves through the source, not through this row's own
        // (empty) path columns.
        for mode in ["shared", "cloudflare"] {
            let (cert, key, _ca) = paths(mode, Some("a.example.com"), None, None);
            assert_eq!(
                cert.as_deref(),
                Some("/etc/letsencrypt/live/a.example.com/fullchain.pem"),
                "{mode} resolved no certificate"
            );
            assert_eq!(
                key.as_deref(),
                Some("/etc/letsencrypt/live/a.example.com/privkey.pem")
            );
        }
        // A borrowing row with no source names nothing rather than guessing
        // its own domain: the certificate would not be there.
        assert_eq!(paths("shared", None, None, None), (None, None, None));

        // A manual certificate is its own, and a half-filled row is refused
        // rather than passed to nginx as a path with no key beside it.
        assert_eq!(
            paths("manual", None, Some("/c.crt"), Some("/k.key")),
            (Some("/c.crt".to_string()), Some("/k.key".to_string()), None)
        );
        assert_eq!(
            paths("manual", None, Some("/c.crt"), None),
            (None, None, None)
        );

        // Let's Encrypt passes nothing: certbot wrote the paths into the file
        // and `preserve_existing_ssl` keeps them.
        assert_eq!(
            paths("letsencrypt", None, Some("/c.crt"), Some("/k.key")),
            (None, None, None)
        );
    }

    /// The source's own uploaded certificate wins over its certbot lineage.
    ///
    /// Source: `_borrowed_ssl_paths`. The manual directory is group-readable
    /// by the panel and can be checked; `/etc/letsencrypt/live` is root-only,
    /// so that path is returned **unchecked** - stat'ing it as `snpanel`
    /// answers "no certificate" for every site that has one.
    #[test]
    fn a_borrowed_path_prefers_what_it_can_actually_see() {
        let base = "/etc/nginx/snpanel/ssl/sites/a.example.com";
        let with = |present: &[&str]| {
            let present: Vec<String> = present.iter().map(|s| (*s).to_string()).collect();
            borrowed_ssl_paths_with("a.example.com", move |p| present.iter().any(|q| q == p))
        };

        // An uploaded certificate, with a CA bundle beside it.
        assert_eq!(
            with(&[
                &format!("{base}/cert.crt"),
                &format!("{base}/privkey.key"),
                &format!("{base}/ca.crt"),
            ]),
            (
                Some(format!("{base}/cert.crt")),
                Some(format!("{base}/privkey.key")),
                Some(format!("{base}/ca.crt")),
            )
        );
        // The same, without one. The row must not name a CA file that is not
        // there: nginx refuses to load an `ssl_trusted_certificate` it cannot
        // open, and the site stops serving rather than serving without it.
        assert_eq!(
            with(&[&format!("{base}/cert.crt"), &format!("{base}/privkey.key")]),
            (
                Some(format!("{base}/cert.crt")),
                Some(format!("{base}/privkey.key")),
                None,
            )
        );
        // A certificate with no key beside it is not half a certificate; it
        // falls through to the lineage.
        assert_eq!(
            with(&[&format!("{base}/cert.crt")]),
            (
                Some("/etc/letsencrypt/live/a.example.com/fullchain.pem".to_string()),
                Some("/etc/letsencrypt/live/a.example.com/privkey.pem".to_string()),
                None,
            )
        );
        // Nothing on disk: the lineage, unchecked.
        assert_eq!(
            with(&[]),
            (
                Some("/etc/letsencrypt/live/a.example.com/fullchain.pem".to_string()),
                Some("/etc/letsencrypt/live/a.example.com/privkey.pem".to_string()),
                None,
            )
        );
    }

    /// The typed-in text is used when the file input was left empty.
    ///
    /// Source: `_read_ssl_input` - `if upload is not None and upload.filename`.
    /// A browser submits an empty `<input type=file>` as a part with an empty
    /// filename rather than not submitting it, so "a part arrived" is not the
    /// same question as "a file was chosen". Reading it as the former throws
    /// away what the administrator pasted into the box and tells them the
    /// certificate is required while it is on screen in front of them.
    #[test]
    fn an_empty_file_input_does_not_shadow_the_pasted_certificate() {
        let pasted = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----";
        let want = format!("{pasted}\n").into_bytes();

        // No file part at all.
        assert_eq!(
            read_ssl_input(None, pasted, "certificate", true),
            Ok(want.clone())
        );
        // A file part with an empty filename - the empty file input.
        let empty_input = (String::new(), Vec::new());
        assert_eq!(
            read_ssl_input(Some(&empty_input), pasted, "certificate", true),
            Ok(want.clone())
        );
        // A file part with a filename wins over the text, even when both came.
        let chosen = ("cert.crt".to_string(), b"from the file\n".to_vec());
        assert_eq!(
            read_ssl_input(Some(&chosen), pasted, "certificate", true),
            Ok(b"from the file\n".to_vec())
        );
        // And the filename is still checked when a file really was chosen.
        let wrong_kind = ("cert.txt".to_string(), b"x\n".to_vec());
        assert_eq!(
            read_ssl_input(Some(&wrong_kind), pasted, "certificate", true),
            Err("certificate must be .crt, .pem, .key, or .ca".to_string())
        );
        // Neither: the message names the part, not "invalid input".
        assert_eq!(
            read_ssl_input(None, "", "private_key", true),
            Err("private_key is required".to_string())
        );
        // The CA bundle is the one that may be absent.
        assert_eq!(read_ssl_input(None, "", "ca_bundle", false), Ok(Vec::new()));
    }

    /// The key never goes in `argv`.
    ///
    /// C37. `/proc/<pid>/cmdline` is world-readable, and a shared host is full
    /// of accounts that are not the administrator uploading this. The payload
    /// is JSON on stdin; the only argument is the domain.
    #[test]
    fn the_private_key_travels_on_stdin_as_json() {
        let payload = manual_ssl_payload(b"CERT\n", b"KEY\n", b"CA\n");
        let parsed: Value = serde_json::from_str(&payload).expect("it is JSON");
        assert_eq!(parsed["certificate"], json!("CERT\n"));
        assert_eq!(parsed["private_key"], json!("KEY\n"));
        assert_eq!(parsed["ca_bundle"], json!("CA\n"));

        // No bundle is an empty string rather than a missing key: the helper
        // reads `ca_bundle` unconditionally and an absent one would leave the
        // previous CA file in place beside a `fullchain.crt` that no longer
        // includes it.
        let none = manual_ssl_payload(b"CERT\n", b"KEY\n", b"");
        let parsed: Value = serde_json::from_str(&none).expect("it is JSON");
        assert_eq!(parsed["ca_bundle"], json!(""));
    }

    /// The row names the files the helper actually wrote.
    ///
    /// Source: `manual_ssl_paths`, and `paths["ca"] = None` when no bundle was
    /// uploaded. A row that names `ca.crt` after the helper deleted it gives
    /// the vhost an `ssl_trusted_certificate` pointing at nothing, and nginx
    /// refuses to reload - after the row already says the site has SSL.
    #[test]
    fn the_row_names_the_files_that_exist() {
        let (cert, key, ca) = manual_ssl_paths("a.example.com");
        assert_eq!(cert, "/etc/nginx/snpanel/ssl/sites/a.example.com/cert.crt");
        assert_eq!(
            key,
            "/etc/nginx/snpanel/ssl/sites/a.example.com/privkey.key"
        );
        assert_eq!(ca, "/etc/nginx/snpanel/ssl/sites/a.example.com/ca.crt");
    }

    /// Rolling back distinguishes "there was one" from "there was not".
    ///
    /// Source: `ManualSslSnapshot.restore` - `if cert and key:` write them
    /// back, `else:` remove the directory. A site that had no manual
    /// certificate before a failed upload must not be left holding half of
    /// one: the next reload would serve a certificate whose key is missing.
    #[test]
    fn a_rollback_with_nothing_to_restore_removes_rather_than_writes() {
        let verb = |cert: Option<&[u8]>, key: Option<&[u8]>| {
            rollback_verb(&ManualSslSnapshot {
                domain: "a.example.com".to_string(),
                certificate: cert.map(<[u8]>::to_vec),
                private_key: key.map(<[u8]>::to_vec),
                ca_bundle: None,
            })
        };
        assert_eq!(verb(Some(b"CERT"), Some(b"KEY")), "manual-ssl-install");
        assert_eq!(verb(None, None), "manual-ssl-remove");
        // Half a snapshot is not a snapshot. Writing back a certificate with
        // no key would leave exactly the state the rollback exists to avoid.
        assert_eq!(verb(Some(b"CERT"), None), "manual-ssl-remove");
        assert_eq!(verb(None, Some(b"KEY")), "manual-ssl-remove");
    }

    /// The `http_flood_config` column, byte for byte.
    ///
    /// `json.dumps` puts a space after the comma **and** after the colon, and
    /// the key order is the dict's insertion order rather than alphabetical -
    /// which is what `serde_json` would give. Both forms parse back the same,
    /// and that is exactly why this is the byte a port gets wrong and never
    /// notices until a shadow diff compares two databases.
    #[test]
    fn the_flood_config_column_is_the_pythons_bytes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/http_flood_zones.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the flood corpus"))
                .expect("the corpus parses");

        let mut failures: Vec<String> = Vec::new();
        for case in corpus["columns"].as_array().expect("the columns") {
            let config = snpanel_nginx::HttpFloodConfig::from_json(&case["config"]);
            let got = flood_config_json(&config);
            let want = case["column"].as_str().unwrap_or("");
            if got != want {
                failures.push(format!("python {want}\nrust   {got}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Out of range is a 422 from pydantic, not a clamp.
    ///
    /// `validate_http_flood_config` does clamp - but pydantic refuses anything
    /// outside the bounds before it ever runs, so the clamp only sees values
    /// that are already inside them. A port that clamped instead would accept
    /// a request the panel refuses and store a number the customer did not
    /// ask for.
    #[test]
    fn a_flood_value_out_of_range_is_refused_rather_than_clamped() {
        let ok = flood_payload_config(&json!({
            "access_limit_requests": 100,
            "access_limit_window": 10,
            "access_limit_burst": 0,
            "connection_limit": 1,
        }));
        assert!(ok.is_ok());

        for bad in [
            json!({ "access_limit_requests": 0 }),
            json!({ "access_limit_requests": 100_001 }),
            json!({ "access_limit_window": 0 }),
            json!({ "access_limit_window": 3_601 }),
            json!({ "access_limit_burst": -1 }),
            json!({ "connection_limit": 0 }),
            json!({ "connection_limit": 10_001 }),
        ] {
            assert!(
                flood_payload_config(&bad).is_err(),
                "{bad} should be refused, not clamped"
            );
        }

        // An absent field is its default, which is how pydantic reads it.
        let defaults = flood_payload_config(&json!({})).expect("the defaults");
        assert_eq!(defaults.access_limit_requests, 100);
        assert_eq!(defaults.access_limit_window, 10);
        assert_eq!(defaults.access_limit_burst, 100);
        assert_eq!(defaults.connection_limit, 60);
    }

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

    /// A borrower points at the lineage, not at the borrower in front of it.
    ///
    /// Source: `cert_name = source.ssl_source_domain or source.domain`. If B
    /// borrows from A and C then borrows from B, C must store A's name - the
    /// certificate C serves is A's file, and a chain that stored B would name
    /// a certificate that does not exist. `shared_dependents` looks rows up by
    /// that stored name, so getting it wrong also hides C from the check that
    /// stops A changing its certificate.
    #[test]
    fn a_chain_of_borrowers_all_name_the_certificate_that_exists() {
        // Driving the function the handler calls, not a copy of it.
        fn cert_name(source_domain: &str, source_ssl_source: Option<&str>) -> String {
            let mut w = website();
            w.domain = source_domain.to_string();
            w.ssl_source_domain = source_ssl_source.map(str::to_string);
            shared_cert_name(&w)
        }

        // Borrowing from a site that owns its certificate.
        assert_eq!(cert_name("a.example.com", None), "a.example.com");
        // Borrowing from a site that is itself borrowing.
        assert_eq!(
            cert_name("b.example.com", Some("a.example.com")),
            "a.example.com"
        );
        // An empty string is not a name: a row written by an older build with
        // `""` rather than NULL must not become the certificate's name.
        assert_eq!(cert_name("b.example.com", Some("")), "b.example.com");
    }

    /// The refusal names the sites that have to be fixed first.
    ///
    /// Source: `_block_if_source`. An administrator told only "no" has to go
    /// looking; the message is the list, sorted so it reads the same twice.
    #[test]
    fn refusing_to_change_a_shared_source_lists_the_borrowers() {
        let message = shared_source_refusal;

        assert_eq!(
            message(&["b.example.com"]),
            "1 website(s) borrow this certificate (b.example.com). Change their SSL first."
        );
        // Sorted, not in whatever order the query returned.
        assert_eq!(
            message(&["c.example.com", "a.example.com", "b.example.com"]),
            "3 website(s) borrow this certificate \
             (a.example.com, b.example.com, c.example.com). Change their SSL first."
        );
    }

    /// A certificate that does not cover the borrower is refused.
    ///
    /// This is the check that matters: serving a name the certificate does
    /// not carry gives every visitor a TLS error, which is worse than the
    /// self-signed certificate the site had before.
    #[test]
    fn a_borrowed_certificate_has_to_cover_the_borrower() {
        let sans = vec![
            "a.example.com".to_string(),
            "*.wild.example.com".to_string(),
        ];
        assert!(cert_covers(&sans, "a.example.com"));
        assert!(cert_covers(&sans, "one.wild.example.com"));
        // A wildcard covers exactly one more label.
        assert!(!cert_covers(&sans, "two.levels.wild.example.com"));
        assert!(!cert_covers(&sans, "wild.example.com"));
        assert!(!cert_covers(&sans, "b.example.com"));
        // No certificate at all is not "covers everything".
        assert!(!cert_covers(&[], "a.example.com"));
    }

    /// Source: `WildcardSslRequest._clean_token`.
    ///
    /// The difference between `None` and `Some("")` decides which of two
    /// answers the caller gets - a 409 asking for a token, or a 400 from
    /// Cloudflare about a token of nothing - so the stripping is not
    /// cosmetic.
    #[test]
    fn the_wildcard_token_field_is_stripped_like_pydantics() {
        let field = |v: Value| wildcard_token_field(&v).map_err(|_| "refused");

        // Absent, null and blank are all the same `None`.
        assert_eq!(field(json!({})), Ok(None));
        assert_eq!(field(json!({"cloudflare_api_token": null})), Ok(None));
        assert_eq!(field(json!({"cloudflare_api_token": ""})), Ok(None));
        assert_eq!(field(json!({"cloudflare_api_token": "   "})), Ok(None));
        // `str.strip()` is Python's `isspace`, which covers `\x1c`-`\x1f`;
        // Rust's own `trim` does not, and a token of those would otherwise
        // become a live `Bearer` header.
        assert_eq!(
            field(json!({"cloudflare_api_token": "\u{1c}\u{1f}"})),
            Ok(None)
        );

        // A real token keeps its value and loses its edges - a token pasted
        // from a web page almost always arrives with a newline.
        assert_eq!(
            field(json!({"cloudflare_api_token": "  abc123\n"})),
            Ok(Some("abc123".to_string()))
        );
        assert_eq!(
            field(json!({"cloudflare_api_token": "abc123"})),
            Ok(Some("abc123".to_string()))
        );

        // Pydantic will not coerce a number into a string, so neither does
        // this: it is a 422 before the handler runs.
        assert_eq!(field(json!({"cloudflare_api_token": 5})), Err("refused"));
        assert_eq!(field(json!({"cloudflare_api_token": true})), Err("refused"));
        assert_eq!(field(json!({"cloudflare_api_token": []})), Err("refused"));
    }

    /// Source: `platform.install_command`.
    ///
    /// This is the command that runs when the privileged helper is absent,
    /// which is a panel somebody is installing by hand. Getting the package
    /// name wrong there produces "no match for argument", which reads like
    /// a broken mirror rather than a typo in the panel.
    #[test]
    fn the_dns_plugin_install_command_matches_the_platforms() {
        let for_plugin = |rhel| crate::system::install_command_for(rhel, CERTBOT_DNS_PLUGIN);
        assert_eq!(
            for_plugin(true),
            "dnf -y install python3-certbot-dns-cloudflare"
        );
        assert_eq!(
            for_plugin(false),
            "export DEBIAN_FRONTEND=noninteractive; apt-get update \
             && apt-get install -y python3-certbot-dns-cloudflare"
        );
        // apt without `DEBIAN_FRONTEND=noninteractive` can stop on a
        // configuration prompt, and there is nobody at the keyboard.
        assert!(for_plugin(false).contains("noninteractive"));
        // Whichever platform this machine is, the real call answers with
        // one of the two and never with an empty string.
        assert!(!certbot_dns_plugin_install_command().is_empty());
    }
}
