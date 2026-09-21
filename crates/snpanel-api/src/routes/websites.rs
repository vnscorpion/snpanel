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
use axum::routing::get;
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
            "/websites/{website_id}/ssl/cloudflare-zone",
            get(cloudflare_zone).fallback(crate::fallback),
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
                path: vhost_path_for(&state, &website.domain).expect("a validated domain"),
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

    let app_type = match overrides.app_type {
        Some(forced) => forced,
        None if website.app_type.is_empty() => "wordpress",
        None => &website.app_type,
    };
    // Source: `runtime_php_version` - a static or proxied site gets no pool.
    let runtime_php = matches!(app_type, "wordpress" | "php")
        .then_some(website.php_version.as_str())
        .filter(|v| !v.is_empty());
    let socket = site_fpm_socket(website, runtime_php);

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
    let Some(waf_enabled) = raw.as_bool() else {
        return crate::errors::bool_parsing("waf_enabled", raw);
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
    let websites = state.db.websites().list(None, "").await.map_err(|e| {
        tracing::error!("listing websites for the flood zones failed: {e}");
        internal_error()
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
    let content =
        snpanel_nginx::render_http_flood_zones(&sites).map_err(|e| bad_request(&e.to_string()))?;

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
        Err(bad_request(
            result
                .failure_detail("Could not save HTTP flood zones")
                .trim(),
        ))
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
    let Some(next_enabled) = raw.as_bool() else {
        return crate::errors::bool_parsing("http_flood_enabled", raw);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
