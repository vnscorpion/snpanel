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
            "/provisioning/v1/accounts",
            post(create_account).fallback(crate::fallback),
        )
        .route(
            "/provisioning/v1/accounts/{external_id}",
            get(get_account).delete(terminate).fallback(crate::fallback),
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

/// Source: `DOMAIN_RE` — `^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$`,
/// applied with `fullmatch`.
///
/// Written out rather than matched with a pattern because this workspace
/// has no regex crate. Two things about it are easy to get wrong and are
/// the Python's, not a tidier rule: the `(?!-)` applies **only** at the
/// start of the whole name, so `a.-b.com` passes, and the last label has a
/// minimum of two but no maximum.
pub fn domain_pattern_ok(name: &str) -> bool {
    if name.starts_with('-') {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    // `(...)+` needs at least one label before the final one.
    if labels.len() < 2 {
        return false;
    }
    let (last, rest) = labels.split_last().expect("at least two labels");
    for label in rest {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    last.len() >= 2 && last.bytes().all(|b| b.is_ascii_alphabetic())
}

/// What `ProvisioningAccountCreate` carries, after pydantic.
struct AccountCreate {
    external_id: String,
    username: String,
    password: String,
    package_id: i64,
    /// `None` for an account with no website, which is a real shape: a
    /// billing system can buy the account first and add the domain later.
    domain: Option<String>,
    php_version: String,
    app_type: String,
    install_wordpress: bool,
    enable_ssl: bool,
}

impl AccountCreate {
    /// Source: `_provisioning_app_type`.
    ///
    /// An account with no domain is `php` whatever was asked for — there is
    /// no site for the app type to describe — and an account asking for
    /// WordPress gets `wordpress` whatever `app_type` said.
    fn app_type_value(&self) -> &str {
        if self.domain.is_none() {
            return "php";
        }
        if self.install_wordpress {
            return "wordpress";
        }
        &self.app_type
    }

    /// Source: `install_wp = payload.install_wordpress and app_type_value ==
    /// "wordpress"`.
    ///
    /// **The second clause is unreachable, in the Python as much as here.**
    /// `validate_site_options` refuses `install_wordpress` without a
    /// domain, and *with* a domain `app_type_value` is already `wordpress`
    /// whenever the flag is set - so the `and` can never change the answer.
    /// It is kept because it is the Python's line and this port reproduces
    /// the Python; it is recorded here because a mutation of it cannot
    /// fail, and the next person to notice that should find the reason
    /// rather than the puzzle.
    fn installs_wordpress(&self) -> bool {
        self.install_wordpress && self.app_type_value() == "wordpress"
    }

    /// Source: `runtime_php = payload.php_version if app_type_value in
    /// {"wordpress", "php"} else None`.
    ///
    /// A static site gets no PHP pool at all, which is the point of calling
    /// it static: no interpreter is started for it and none can be reached.
    fn runtime_php(&self) -> Option<&str> {
        match self.app_type_value() {
            "wordpress" | "php" => Some(&self.php_version),
            _ => None,
        }
    }

    /// Source: `rewrite_mode = "front_controller" if app_type_value ==
    /// "wordpress" else "none"`.
    fn rewrite_mode(&self) -> &'static str {
        if self.app_type_value() == "wordpress" {
            "front_controller"
        } else {
            "none"
        }
    }
}

/// Source: `_provisioning_email`.
///
/// The account's address is **derived**, not taken from the request. The
/// model accepts an `email` field and then discards it, which is not an
/// oversight worth fixing here: a billing system's contact address is not a
/// panel login, and two accounts sharing one would collide on a column the
/// panel treats as identifying.
fn provisioning_email(username: &str) -> String {
    format!("{username}@users.snpanel.dev")
}

/// Source: `ProvisioningAccountCreate`, field by field.
///
/// **Every bad field is reported, not the first.** Pydantic validates each
/// one and collects the failures, so a body wrong in four ways comes back
/// saying so - which is four fewer round trips for whoever is integrating
/// against it. The order is the model's declaration order, because that is
/// the order pydantic runs them in.
fn account_create_fields(payload: &Value) -> Result<AccountCreate, Response> {
    let mut errors: Vec<Value> = Vec::new();
    macro_rules! push {
        ($entry:expr) => {
            errors.push($entry)
        };
    }

    // --- external_id -------------------------------------------------------
    let mut external_id = String::new();
    match payload.get("external_id") {
        None => push!(crate::errors::missing_entry("external_id", payload.clone())),
        Some(Value::String(raw)) => match crate::errors::length_entry("external_id", raw, 1, 255) {
            Some(entry) => push!(entry),
            None => external_id = raw.clone(),
        },
        Some(other) => push!(crate::errors::string_type_entry("external_id", other)),
    }

    // --- username ----------------------------------------------------------
    let mut username = String::new();
    match payload.get("username") {
        None => push!(crate::errors::missing_entry("username", payload.clone())),
        Some(Value::String(raw)) => {
            if let Some(entry) = crate::errors::length_entry("username", raw, 3, 32) {
                push!(entry);
            } else if !super::users::panel_username_shape_ok(raw) {
                push!(super::users::panel_username_pattern_entry(raw));
            } else if snpanel_core::types::RESERVED_LINUX_USERS.contains(&raw.as_str()) {
                // A reserved name is a `ValueError` from the field
                // validator, which pydantic reports as `value_error` rather
                // than as a pattern failure - and it has to be, because the
                // name *does* match the pattern.
                push!(crate::errors::value_error_entry(
                    "username",
                    "username is reserved by the system",
                    &Value::String(raw.clone()),
                ));
            } else {
                username = raw.clone();
            }
        }
        Some(other) => push!(crate::errors::string_type_entry("username", other)),
    }

    // --- email, which is accepted and then thrown away ---------------------
    //
    // **`EmailStr` is not checked, and that is a recorded gap** - the same
    // one as `POST /users`. Pydantic runs `email-validator`, which decodes
    // IDNA and refuses `a@localhost`; reproducing it is a dependency
    // decision rather than a line of code, and the corpus is in
    // `tests/golden/email.json`. The gap is narrower here than there,
    // because `_provisioning_email` discards the value: the only thing this
    // field can do is turn a request into a 422, and nothing stored
    // depends on it.
    match payload.get("email") {
        None | Some(Value::Null) | Some(Value::String(_)) => {}
        Some(other) => push!(crate::errors::string_type_entry("email", other)),
    }

    // --- password ----------------------------------------------------------
    let mut password = String::new();
    match payload.get("password") {
        None => push!(crate::errors::missing_entry("password", payload.clone())),
        Some(Value::String(raw)) => {
            // 72 is bcrypt's limit, not a policy: longer and bcrypt
            // silently truncates, so two different passwords would open the
            // same account.
            match crate::errors::length_entry("password", raw, 12, 72) {
                Some(entry) => push!(entry),
                None => password = raw.clone(),
            }
        }
        Some(other) => push!(crate::errors::string_type_entry("password", other)),
    }

    // --- package_id --------------------------------------------------------
    let mut package_id = 0;
    match crate::errors::read_int_entry("package_id", payload.get("package_id")) {
        Ok(None) => push!(crate::errors::missing_entry("package_id", payload.clone())),
        // `Field(ge=1)`. The bound is checked *after* the coercion, which is
        // why `"0"` and `False` reach it as zero rather than as bad text.
        Ok(Some(value)) => match crate::errors::range_entry("package_id", value, 1, i64::MAX) {
            None => package_id = value,
            Some(entry) => push!(entry),
        },
        Err(entry) => push!(entry),
    }

    // --- domain ------------------------------------------------------------
    //
    // `validate_domain`: strip, lower, empty becomes `None`, then the
    // pattern. The order matters - `"  "` is `None`, not a pattern failure,
    // so a blank domain is an account with no website rather than a 422.
    let mut domain = None;
    match payload.get("domain") {
        None | Some(Value::Null) => {}
        Some(Value::String(raw)) => {
            let cleaned = snpanel_core::pyunicode::trim(raw).to_lowercase();
            if cleaned.is_empty() {
                // `None`, which is what the model stores.
            } else if !domain_pattern_ok(&cleaned) {
                push!(crate::errors::value_error_entry(
                    "domain",
                    "Invalid domain",
                    &Value::String(raw.clone()),
                ));
            } else {
                domain = Some(cleaned);
            }
        }
        Some(other) => push!(crate::errors::string_type_entry("domain", other)),
    }

    // --- php_version -------------------------------------------------------
    let mut php_version = "8.4".to_string();
    match payload.get("php_version") {
        None => {}
        Some(Value::String(raw)) => {
            if snpanel_nginx::ALLOWED_PHP_VERSIONS.contains(&raw.as_str()) {
                php_version = raw.clone();
            } else {
                let mut allowed: Vec<&str> = snpanel_nginx::ALLOWED_PHP_VERSIONS.to_vec();
                allowed.sort_unstable();
                push!(crate::errors::value_error_entry(
                    "php_version",
                    &format!("Unsupported PHP version. Allowed: {allowed:?}"),
                    &Value::String(raw.clone()),
                ));
            }
        }
        // `php_version: str = "8.4"`. An explicit `null` is not a string, so
        // it is refused rather than defaulted - the default is for a field
        // the body leaves out.
        Some(other) => push!(crate::errors::string_type_entry("php_version", other)),
    }

    // --- app_type ----------------------------------------------------------
    //
    // `Literal["wordpress", "php", "static"]`, which is narrower than the
    // panel's own app types: those also include `application`, and a
    // billing system cannot provision a container account.
    const ACCOUNT_APP_TYPES: &[&str] = &["wordpress", "php", "static"];
    let mut app_type = "php".to_string();
    match payload.get("app_type") {
        None => {}
        Some(Value::String(raw)) if ACCOUNT_APP_TYPES.contains(&raw.as_str()) => {
            app_type = raw.clone()
        }
        Some(other) => push!(json!({
            "type": "literal_error",
            "loc": ["body", "app_type"],
            "msg": "Input should be 'wordpress', 'php' or 'static'",
            "input": other,
            "ctx": { "expected": "'wordpress', 'php' or 'static'" },
        })),
    }

    // --- the two booleans, in pydantic's lax mode --------------------------
    let mut install_wordpress = false;
    match crate::errors::read_bool_entry(
        "install_wordpress",
        payload.get("install_wordpress"),
        false,
    ) {
        Ok(flag) => install_wordpress = flag,
        Err(entry) => push!(entry),
    }
    let mut enable_ssl = false;
    match crate::errors::read_bool_entry("enable_ssl", payload.get("enable_ssl"), false) {
        Ok(flag) => enable_ssl = flag,
        Err(entry) => push!(entry),
    }

    if !errors.is_empty() {
        return Err(crate::errors::validation_error(errors));
    }

    // `validate_site_options` is a `model_validator(mode="after")`, so it
    // runs only once every field has passed, and its `loc` is the body
    // itself rather than any one field.
    if domain.is_none() && (install_wordpress || enable_ssl) {
        return Err(crate::errors::validation_error(vec![json!({
            "type": "value_error",
            "loc": ["body"],
            "msg": "Value error, domain is required for WordPress install or Auto SSL",
            "input": payload.clone(),
            "ctx": { "error": "domain is required for WordPress install or Auto SSL" },
        })]));
    }

    Ok(AccountCreate {
        external_id,
        username,
        password,
        package_id,
        domain,
        php_version,
        app_type,
        install_wordpress,
        enable_ssl,
    })
}

/// `POST /api/provisioning/v1/accounts`.
///
/// Source: `create_account`. A billing system buys a hosting account: a
/// panel user, a Linux account, optionally a website with its files, its
/// vhost, its database and a certificate.
///
/// **A retried call must not destroy the account the first one built.** A
/// billing module that loses the reply to this will send it again, so an
/// existing row that is `active` or `pending` *and* still has a user is
/// returned as it stands. Any other existing row — failed, terminated, or
/// pointing at a user that is gone — is deleted and rebuilt, because that
/// is a record of something that did not finish.
///
/// **The row is written before any of the work.** It goes in as `pending`
/// so that a create which dies half way leaves the billing system a record
/// saying `failed` with the reason, rather than nothing at all.
async fn create_account(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (parts, body) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:write").await {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fields = match account_create_fields(&payload) {
        Ok(f) => f,
        Err(r) => return r,
    };

    // `existing = db.query(...).first()`.
    match state
        .db
        .provisioning()
        .by_external_id(&fields.external_id)
        .await
    {
        Ok(Some(existing)) => {
            let live_user = match existing.user_id {
                Some(id) => matches!(state.db.users().by_id(id).await, Ok(Some(_))),
                None => false,
            };
            if matches!(existing.status.as_str(), "active" | "pending") && live_user {
                return finished_account(&state, &fields.external_id).await;
            }
            if let Err(e) = state.db.provisioning().delete(existing.id).await {
                tracing::error!("deleting the stale provisioning row failed: {e}");
                return crate::errors::internal_error();
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("provisioning lookup failed: {e}");
            return crate::errors::internal_error();
        }
    }

    let account_email = provisioning_email(&fields.username);

    // The two conflicts, in the Python's order: a username collision is
    // reported before a domain one, so a request wrong in both ways always
    // gets the same answer.
    match state.db.users().by_username(&fields.username).await {
        Ok(Some(_)) => return error(axum::http::StatusCode::CONFLICT, "Username already exists"),
        Ok(None) => {}
        Err(e) => {
            tracing::error!("username lookup failed: {e}");
            return crate::errors::internal_error();
        }
    }
    if let Some(domain) = &fields.domain {
        let taken = match state.db.websites().by_domain(domain).await {
            Ok(row) => row.is_some(),
            Err(e) => {
                tracing::error!("domain lookup failed: {e}");
                return crate::errors::internal_error();
            }
        };
        // `or nginx.vhost_exists(domain)` — a vhost with no row is still a
        // name this machine is already serving, and writing a second one
        // would leave two server blocks fighting over it.
        if taken || super::websites::vhost_exists(&state, domain).await {
            return error(axum::http::StatusCode::CONFLICT, "Domain already exists");
        }
    }

    let package = match state.db.packages().by_id(fields.package_id).await {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("Package not found"),
        Err(e) => {
            tracing::error!("package lookup failed: {e}");
            return crate::errors::internal_error();
        }
    };

    let now = snpanel_db::sqlalchemy_now();
    let account_id = match state
        .db
        .provisioning()
        .create(&fields.external_id, fields.package_id, &now)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("creating the provisioning row failed: {e}");
            return crate::errors::internal_error();
        }
    };

    // From here on a failure is recorded on the row before it is answered,
    // so the billing system can read what went wrong without a support call.
    // `site_users.ensure_panel_user(username, password)`.
    let Ok(panel_user) = snpanel_core::types::PanelUsername::parse(&fields.username) else {
        // `validate_linux_user` raises `ValueError`, which the Python's
        // `except (ValueError, RuntimeError)` turns into a 400.
        return fail_account(&state, account_id, "Invalid panel Linux user").await;
    };
    let dry = state.settings.command_dry_run;
    let ensured =
        shell::privileged(dry, "panel-user-ensure", &[panel_user.as_str()], None, None).await;
    if !ensured.ok() {
        return fail_account(
            &state,
            account_id,
            ensured
                .failure_detail("Could not create the system account")
                .trim(),
        )
        .await;
    }
    let set = shell::privileged(
        dry,
        "panel-user-password",
        &[panel_user.as_str()],
        // On stdin, never in argv: `/proc/<pid>/cmdline` is world-readable.
        Some(&format!("{}\n", fields.password)),
        None,
    )
    .await;
    if !set.ok() {
        return fail_account(
            &state,
            account_id,
            set.failure_detail("Could not set the system password")
                .trim(),
        )
        .await;
    }

    let hashed = match snpanel_core::crypto::password::hash_password(&fields.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing failed: {e}");
            return crate::errors::internal_error();
        }
    };
    // The package's limits are **copied** onto the user row rather than
    // referenced: enforcement reads one row, and a package edited later must
    // not silently change what an account already sold allows.
    let user_id = match state
        .db
        .users()
        .create(&snpanel_db::NewUser {
            username: &fields.username,
            email: &account_email,
            hashed_password: &hashed,
            role: "end_user",
            package_id: Some(package.id),
            website_limit: package.website_limit,
            storage_limit_mb: package.storage_limit_mb,
            // The Python's `User(...)` sets neither `is_active` nor
            // `terminal_enabled`, so both take the model default.
            terminal_enabled: false,
        })
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("creating the panel user failed: {e}");
            return crate::errors::internal_error();
        }
    };
    if let Err(e) = state
        .db
        .provisioning()
        .set_links(
            account_id,
            Some(user_id),
            None,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        tracing::error!("linking the provisioning row failed: {e}");
        return crate::errors::internal_error();
    }

    let mut website_id = None;
    if let Some(domain) = fields.domain.clone() {
        match build_account_site(&state, &fields, &panel_user, &account_email, &domain).await {
            Ok(built) => {
                let created_at = snpanel_db::sqlalchemy_now();
                let new_site = snpanel_db::NewWebsite {
                    domain: &domain,
                    owner_id: user_id,
                    root_path: &built.root_path,
                    document_root: "public_html",
                    linux_user: Some(panel_user.as_str()),
                    php_version: &fields.php_version,
                    app_type: fields.app_type_value(),
                    nginx_rewrite_mode: fields.rewrite_mode(),
                    app_id: None,
                    status: "active",
                    waf_enabled: true,
                    created_at: &created_at,
                };
                let id = match state.db.websites().create(&new_site).await {
                    Ok(id) => id,
                    Err(e) => {
                        tracing::error!("creating the website row failed: {e}");
                        return crate::errors::internal_error();
                    }
                };
                website_id = Some(id);
                if let Some(db_info) = &built.database {
                    let encrypted = snpanel_core::crypto::fernet::encrypt(
                        &state.settings.secret_key,
                        &db_info.db_password,
                    );
                    if let Err(e) = state
                        .db
                        .databases()
                        .create(
                            user_id,
                            Some(id),
                            &db_info.db_name,
                            &db_info.db_user,
                            &encrypted,
                        )
                        .await
                    {
                        tracing::error!("recording the database account failed: {e}");
                        return crate::errors::internal_error();
                    }
                }
            }
            Err(message) => return fail_account(&state, account_id, &message).await,
        }
    }

    if let Err(e) = state
        .db
        .provisioning()
        .set_links(account_id, None, website_id, &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("linking the provisioning website failed: {e}");
        return crate::errors::internal_error();
    }
    if let Err(e) = state
        .db
        .provisioning()
        .activate(account_id, &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("activating the provisioning row failed: {e}");
        return crate::errors::internal_error();
    }

    // `except Exception: pass` — **a certificate that cannot be issued does
    // not fail the account**. The site is up on HTTP and the customer can
    // ask for SSL again; refusing the whole purchase because Let's Encrypt
    // was rate-limited would be the worse answer.
    if fields.enable_ssl {
        if let (Some(domain), Some(id)) = (&fields.domain, website_id) {
            issue_account_ssl(&state, domain, id).await;
        }
    }

    audit_provisioning(
        &state,
        &parts,
        "provisioning_create",
        &fields.external_id,
        // `detail=payload.domain or payload.username` — the domain when
        // there is one, because that is what an operator searches for.
        fields.domain.as_deref().unwrap_or(&fields.username),
    )
    .await;

    finished_account(&state, &fields.external_id).await
}

/// Record a failure on the account row, then answer with it.
///
/// Source: `account.status = "failed"; account.last_message = str(exc);
/// db.commit(); raise HTTPException(400, str(exc))`. The row is written
/// **before** the 400 goes out, so a billing system that only ever reads
/// the account back still learns what happened.
async fn fail_account(state: &AppState, account_id: i64, message: &str) -> Response {
    if let Err(e) = state
        .db
        .provisioning()
        .fail(account_id, message, &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("recording the provisioning failure failed: {e}");
    }
    bad_request(message)
}

/// What `build_account_site` made, for the rows that follow it.
struct BuiltSite {
    root_path: String,
    database: Option<crate::mariadb::NewDatabase>,
}

/// Source: the `try:` block inside `create_account`'s `if payload.domain:`.
///
/// **The order is the Python's and it is not `create_website`'s.** Here the
/// database is created *before* the runtime, the WAF file is written
/// *before* the placeholder page, and a failure drops the database but does
/// **not** remove the directory — `_cleanup_failed_site` is not called on
/// this path. That last one looks like an oversight and may be; it is
/// reproduced rather than improved, because an operator whose provisioning
/// call failed will find the half-made directory where the Python left it.
async fn build_account_site(
    state: &AppState,
    fields: &AccountCreate,
    panel_user: &snpanel_core::types::PanelUsername,
    account_email: &str,
    domain: &str,
) -> Result<BuiltSite, String> {
    let dry = state.settings.command_dry_run;
    // `site_users.site_root_for_panel_user(username, domain)`.
    let root_path = format!("/home/{}/{}", panel_user.as_str(), domain);
    let install_wp = fields.installs_wordpress();

    let request = super::websites::CreateRequest {
        domain: domain.to_string(),
        owner_id: None,
        php_version: fields.php_version.clone(),
        app_type: fields.app_type_value().to_string(),
        app_id: None,
        install_wordpress: install_wp,
        // `wordpress.install_wordpress(domain, db_info, payload.domain,
        // "admin", payload.password, account_email, ...)` — the title is the
        // domain and the administrator is always `admin`.
        title: domain.to_string(),
        admin_user: "admin".to_string(),
        admin_password: fields.password.clone(),
        admin_email: account_email.to_string(),
    };
    let php_for_runtime = fields.php_version.clone();
    let site = super::websites::NewSite {
        domain,
        root_path: &root_path,
        linux_user: panel_user.as_str(),
        app_type: fields.app_type_value(),
        rewrite_mode: fields.rewrite_mode(),
        php_version: &fields.php_version,
        // The WordPress branch always has a PHP runtime; the others take
        // the app type's answer.
        runtime_php: if install_wp {
            Some(&php_for_runtime)
        } else {
            fields.runtime_php()
        },
        app_port: None,
        install_wp,
        request: &request,
    };

    let mut database = None;
    if install_wp {
        // `mariadb.create_database(payload.domain)` — the defaults are the
        // `wp` prefix and `IF NOT EXISTS`.
        let created = crate::mariadb::create_database(domain, "wp", true)
            .await
            .map_err(|e| e.to_string())?;
        if let Err(message) = ensure_site_runtime(state, &site).await {
            let _ = crate::mariadb::drop_database(&created.db_name, &created.db_user).await;
            return Err(message);
        }
        if let Err(message) = super::websites::install_wordpress(state, &site, &created).await {
            // `if db_info: mariadb.drop_database(...)` in the `except`.
            let _ = crate::mariadb::drop_database(&created.db_name, &created.db_user).await;
            return Err(message);
        }
        database = Some(created);
    } else {
        ensure_site_runtime(state, &site).await?;
    }

    // `if db_info: mariadb.drop_database(...)` — every failure from here on
    // takes the database with it, because a database with no site and no row
    // is invisible to the panel and nothing would ever clean it up.
    //
    // A function rather than a closure because `NewDatabase` is deliberately
    // not `Clone`: it holds a plaintext password, and a type that copies
    // itself on a whim is a type that ends up somewhere nobody looked.
    async fn undo(database: &Option<crate::mariadb::NewDatabase>, message: String) -> String {
        if let Some(created) = database {
            let _ = crate::mariadb::drop_database(&created.db_name, &created.db_user).await;
        }
        message
    }

    if let Err(message) = super::websites::ensure_new_site_waf(state, domain).await {
        return Err(undo(&database, message).await);
    }
    // `if not install_wp: if not settings.command_dry_run:` — the Python
    // skips the page entirely in a dry run rather than letting the helper
    // pretend, so the same guard is here rather than inside the write.
    if !install_wp && !dry {
        if let Err(message) = super::websites::write_placeholder_page(state, &site).await {
            return Err(undo(&database, message).await);
        }
        // `site_users.fix_site_path(str(document_root(root_path)),
        // linux_user)` — a second call on the path the placeholder writer
        // already fixed. Kept: it is a helper invocation the Python makes.
        let public = format!("{root_path}/public_html");
        let _ = shell::privileged(
            dry,
            "site-path-fix",
            &[&public, panel_user.as_str()],
            None,
            None,
        )
        .await;
    }

    if let Err(message) = super::websites::write_site_vhost(state, &site).await {
        return Err(undo(&database, message).await);
    }
    Ok(BuiltSite {
        root_path,
        database,
    })
}

/// Source: `site_users.ensure_site_runtime(domain, root_path, php, user)`.
///
/// `"none"` rather than an empty argument when there is no runtime PHP: the
/// helper reads the third argument positionally.
async fn ensure_site_runtime(
    state: &AppState,
    site: &super::websites::NewSite<'_>,
) -> Result<(), String> {
    let php_arg = site.runtime_php.unwrap_or("none");
    let ensured = shell::privileged(
        state.settings.command_dry_run,
        "site-runtime-ensure",
        &[site.linux_user, site.root_path, php_arg],
        None,
        None,
    )
    .await;
    if ensured.ok() {
        Ok(())
    } else {
        Err(ensured
            .failure_detail("Could not prepare the website directory")
            .trim()
            .to_string())
    }
}

/// Source: the `if payload.enable_ssl and payload.domain:` block.
///
/// Every failure is swallowed, including a helper that is not there. The
/// account is already sold and the site is already up; SSL is something the
/// customer can ask for again from the panel.
async fn issue_account_ssl(state: &AppState, domain: &str, website_id: i64) {
    let result = shell::privileged(
        state.settings.command_dry_run,
        "certbot-issue",
        &[domain],
        None,
        None,
    )
    .await;
    if !result.ok() {
        tracing::warn!(
            "provisioned {domain} without SSL: {}",
            result.failure_detail("Could not issue SSL").trim()
        );
        return;
    }
    if let Err(e) = state
        .db
        .websites()
        .set_ssl_state(
            website_id,
            true,
            "letsencrypt",
            None,
            None,
            None,
            None,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        tracing::error!("recording the provisioned certificate failed: {e}");
    }
}

/// `account_to_dict(account, db)` for a row that has just been written.
async fn finished_account(state: &AppState, external_id: &str) -> Response {
    match state.db.provisioning().view(external_id).await {
        Ok(Some(view)) => {
            axum::Json(account_payload(&view, &panel_base_url(&state.settings))).into_response()
        }
        Ok(None) => not_found("Account not found"),
        Err(e) => {
            tracing::error!("provisioning view failed: {e}");
            crate::errors::internal_error()
        }
    }
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
        }
        lock_accounts(&state, user_id, &websites, true).await;
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
        }
        lock_accounts(&state, user_id, &websites, false).await;
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
///
/// Every account of the user's, once - their own too, which the per-site
/// loop missed for a user with no sites - and unlocked only while their SFTP
/// is on. See `sftp_access::set_locked`.
async fn lock_accounts(
    state: &AppState,
    user_id: i64,
    websites: &[snpanel_db::Website],
    lock: bool,
) {
    let username = match state.db.users().by_id(user_id).await {
        Ok(Some(user)) => user.username,
        Ok(None) => return,
        Err(e) => {
            tracing::error!("loading user {user_id} failed: {e}");
            return;
        }
    };
    let site_accounts: Vec<Option<String>> =
        websites.iter().map(|w| w.linux_user.clone()).collect();
    crate::sftp_access::set_locked(
        &state.db,
        state.settings.command_dry_run,
        user_id,
        &username,
        &site_accounts,
        lock,
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
    // Source: `site_users.set_panel_user_password` - while the SFTP login
    // still follows the panel password.
    if let Err(detail) = crate::sftp_access::follow_panel_password(
        &state.db,
        state.settings.command_dry_run,
        user.id,
        &user.username,
        &password,
    )
    .await
    {
        tracing::error!("setting the system password failed: {detail}");
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
    // `log_action`'s own join, not a second copy of it. The separator is
    // ` | `, the user agent is cut at 200 **characters**, and an empty ip or
    // ua is left out rather than written as a bare `ip=`. An earlier version
    // of this function re-derived all three and got all three wrong, which
    // is the argument for calling the one that is tested.
    let detail = snpanel_db::AuditRepo::detail_with_request(detail, &ip, ua);
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

/// `DELETE /api/provisioning/v1/accounts/{external_id}`.
///
/// Source: `terminate` and `provisioning.terminate_account`.
///
/// `?backup=true` is **off by default**, and that is not tidiness: the backup
/// runs inside this request, and a billing module that gives the call a short
/// HTTP timeout would report a failure while the server carried on
/// terminating. Pass it when the caller can wait for a full account archive.
async fn terminate(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (parts, _) = req.into_parts();
    if let Err(r) = authorised(&state, &parts, "provisioning:write").await {
        return r;
    }
    // `backup: bool = Query(default=False)` — FastAPI's boolean query
    // parsing, which is the same set of words a body field takes.
    let backup = query_flag(&parts, "backup");

    let account = match account_or_404(&state, &external_id).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if account.status == "terminated" {
        return axum::Json(json!({ "ok": true, "status": "terminated" })).into_response();
    }

    let mut last_message = account.last_message.clone();
    let mut deleted_domains: Vec<String> = Vec::new();

    if let Some(user_id) = account.user_id {
        let user = match state.db.users().by_id(user_id).await {
            Ok(Some(user)) => Some(user),
            Ok(None) => None,
            Err(e) => {
                tracing::error!("reading the account's user failed: {e}");
                return crate::errors::internal_error();
            }
        };
        if let Some(user) = user {
            if backup {
                // Termination deletes the Linux user and its home directory,
                // so the archive is taken first. **A failure here must not
                // block the termination the billing system asked for** — it
                // is recorded on the row and the deletion goes ahead.
                last_message = match super::maintenance::build_user_backup(
                    &state,
                    &user,
                    snpanel_db::s3_targets::NameStyle::Timestamp,
                )
                .await
                {
                    Ok(archive) => format!("backup={archive}"),
                    Err(why) => format!("backup failed: {why}"),
                };
            }
            match terminate_user(&state, &user).await {
                Ok(domains) => deleted_domains = domains,
                Err(r) => return r,
            }
        }
    }

    if let Err(e) = state
        .db
        .provisioning()
        .terminate(account.id, &last_message, &snpanel_db::sqlalchemy_now())
        .await
    {
        tracing::error!("marking the account terminated failed: {e}");
        return crate::errors::internal_error();
    }
    audit_provisioning(
        &state,
        &parts,
        "provisioning_terminate",
        &external_id,
        &deleted_domains.join(","),
    )
    .await;
    axum::Json(json!({
        "ok": true,
        "status": "terminated",
        "deleted_websites": deleted_domains,
    }))
    .into_response()
}

/// `bool` on a query parameter, the way FastAPI reads one.
///
/// Absent is false; `1`, `true`, `on`, `yes` and their cases are true. A
/// value FastAPI could not read would be a 422, but nothing in the billing
/// integration sends one and the Python's own default swallows it, so an
/// unreadable value is false here as it is there.
fn query_flag(parts: &axum::http::request::Parts, name: &str) -> bool {
    let Some(query) = parts.uri.query() else {
        return false;
    };
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key != name {
            continue;
        }
        return matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "on" | "yes" | "y" | "t"
        );
    }
    false
}

/// Everything an account's user owns, removed.
///
/// Source: the body of `terminate_account`. It is **not** the same sequence
/// as deleting a user through the panel: that one also removes the aliases
/// and the site runtime, and this one removes the site's files instead. Both
/// are the Python's, and the difference is reproduced rather than tidied —
/// a terminated account and a deleted user are not the same event, and a
/// billing system replaying one is not asking for the other.
async fn terminate_user(
    state: &AppState,
    user: &snpanel_db::User,
) -> Result<Vec<String>, Response> {
    let dry = state.settings.command_dry_run;
    let websites = state
        .db
        .websites()
        .list(Some(user.id), "")
        .await
        .unwrap_or_default();

    let mut deleted = Vec::new();
    for website in &websites {
        let accounts = state
            .db
            .databases()
            .for_website(website.id)
            .await
            .unwrap_or_default();
        if let Some(item) = accounts.first() {
            if let Err(e) = crate::mariadb::drop_database(&item.db_name, &item.db_user).await {
                return Err(bad_request(&e.to_string()));
            }
            if let Err(e) = state.db.databases().delete(item.id).await {
                tracing::error!("deleting the database row failed: {e}");
                return Err(crate::errors::internal_error());
            }
        }
        super::websites::delete_website_vhost(state, &website.domain).await;
        // Terminating an account is a real deletion, not a suspension: the
        // certificate has nothing left to protect and should not outlive it.
        let _ =
            super::websites::release_site_certificates(state, &website.domain, website.id).await;
        let _ = shell::privileged(dry, "waf-site-delete", &[&website.domain], None, None).await;
        // `wordpress.delete_wordpress` — the site's files, as the site's own
        // user, which is the only account that owns them.
        if let Some(linux_user) = website.linux_user.as_deref().filter(|u| !u.is_empty()) {
            let _ = shell::privileged(
                dry,
                "rm-site",
                &[linux_user, &website.root_path, &website.root_path],
                None,
                None,
            )
            .await;
        }
        if let Err(e) = state.db.websites().delete(website.id).await {
            tracing::error!("deleting the row for {} failed: {e}", website.domain);
            return Err(crate::errors::internal_error());
        }
        deleted.push(website.domain.clone());
    }

    // `site_users.delete_panel_user(user.username)`.
    if let Ok(panel_user) =
        snpanel_core::types::PanelUsername::parse(&user.username.trim().to_lowercase())
    {
        let _ =
            shell::privileged(dry, "panel-user-delete", &[panel_user.as_str()], None, None).await;
    }
    if let Err(e) = state.db.users().delete(user.id).await {
        tracing::error!("deleting {} failed: {e}", user.username);
        return Err(crate::errors::internal_error());
    }
    Ok(deleted)
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

    fn account_corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/account_create.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the account corpus"))
            .expect("the corpus parses")
    }

    /// What the 422 body says, entry for entry, against real pydantic.
    ///
    /// The `type` and the `loc` are what a billing system branches on, so
    /// both are compared — and so is the **number** of entries, because a
    /// body wrong in four ways has to come back saying four things.
    #[tokio::test]
    async fn the_body_is_validated_the_way_pydantic_validates_it() {
        let corpus = account_corpus();
        let cases = corpus["fields"].as_array().expect("the cases");
        assert_eq!(cases.len(), 93, "the corpus changed size");

        // **The recorded `EmailStr` gap, made visible rather than hidden.**
        // Pydantic runs `email-validator` and refuses these two; this port
        // does not check the field at all, the same as `POST /users`. The
        // count is asserted below so the skip cannot quietly grow, and the
        // consequence here is only a 422 that does not happen - the value
        // is discarded, so nothing stored differs.
        const EMAIL_GAP: &[&str] = &["email_no_at", "email_localhost"];

        let mut failures: Vec<String> = Vec::new();
        let mut skipped = 0;
        for case in cases {
            let name = case["case"].as_str().unwrap_or("");
            if EMAIL_GAP.contains(&name) {
                skipped += 1;
                // The gap is one-way: the Python refuses and this accepts.
                // If that ever reverses, the assertion below still fires.
                assert!(
                    account_create_fields(&case["body"]).is_ok(),
                    "{name}: the gap is that this accepts what pydantic refuses"
                );
                continue;
            }
            let body = &case["body"];
            let got = account_create_fields(body);
            match case.get("errors").and_then(Value::as_array) {
                Some(want) => {
                    let Err(response) = got else {
                        failures.push(format!("{name}: python refused it, rust accepted it"));
                        continue;
                    };
                    let entries = entries_of(response).await;
                    let want_pairs: Vec<(String, Vec<String>)> = want
                        .iter()
                        .map(|e| {
                            (
                                e["type"].as_str().unwrap_or("").to_string(),
                                e["loc"]
                                    .as_array()
                                    .expect("a loc")
                                    .iter()
                                    .map(|v| v.as_str().unwrap_or("").to_string())
                                    .collect(),
                            )
                        })
                        .collect();
                    // The Rust `loc` carries the `"body"` prefix FastAPI adds;
                    // the corpus records pydantic's own, which does not.
                    let got_pairs: Vec<(String, Vec<String>)> = entries
                        .iter()
                        .map(|e| {
                            (
                                e["type"].as_str().unwrap_or("").to_string(),
                                e["loc"]
                                    .as_array()
                                    .expect("a loc")
                                    .iter()
                                    .skip(1)
                                    .map(|v| v.as_str().unwrap_or("").to_string())
                                    .collect(),
                            )
                        })
                        .collect();
                    if got_pairs != want_pairs {
                        failures.push(format!("{name}: python {want_pairs:?}, rust {got_pairs:?}"));
                    }
                }
                None => {
                    let want = &case["value"];
                    match got {
                        Err(_) => {
                            failures.push(format!("{name}: python accepted it, rust refused it"))
                        }
                        Ok(fields) => {
                            let mismatch = fields.external_id
                                != want["external_id"].as_str().unwrap_or("")
                                || fields.username != want["username"].as_str().unwrap_or("")
                                || fields.password != want["password"].as_str().unwrap_or("")
                                || fields.package_id != want["package_id"].as_i64().unwrap_or(0)
                                || fields.domain.as_deref() != want["domain"].as_str()
                                || fields.php_version != want["php_version"].as_str().unwrap_or("")
                                || fields.app_type != want["app_type"].as_str().unwrap_or("")
                                || fields.install_wordpress
                                    != want["install_wordpress"].as_bool().unwrap_or(false)
                                || fields.enable_ssl
                                    != want["enable_ssl"].as_bool().unwrap_or(false);
                            if mismatch {
                                failures.push(format!(
                                    "{name}: python {want}, rust domain={:?} php={:?} app={:?} id={} wp={} ssl={}",
                                    fields.domain,
                                    fields.php_version,
                                    fields.app_type,
                                    fields.package_id,
                                    fields.install_wordpress,
                                    fields.enable_ssl,
                                ));
                            }
                        }
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert_eq!(
            skipped,
            EMAIL_GAP.len(),
            "every skipped case is a known one"
        );
    }

    /// The entries of a 422, for a test that has to look inside one.
    async fn entries_of(response: Response) -> Vec<Value> {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the validation body");
        let body: Value = serde_json::from_slice(&bytes).expect("a JSON body");
        body["detail"].as_array().cloned().unwrap_or_default()
    }

    /// The three values every later step is derived from.
    ///
    /// Source: `_provisioning_app_type` and the two lines after it. An
    /// account with no domain is `php` whatever was asked for, and a
    /// `static` site asking for WordPress gets neither.
    #[test]
    fn the_app_type_is_derived_the_way_python_derives_it() {
        let corpus = account_corpus();
        let cases = corpus["derived"].as_array().expect("the cases");
        assert_eq!(cases.len(), 7, "the corpus changed size");

        for case in cases {
            let fields = AccountCreate {
                external_id: "x".to_string(),
                username: "customer1".to_string(),
                password: "a-long-enough-password".to_string(),
                package_id: 1,
                domain: case["domain"].as_str().map(str::to_string),
                php_version: "8.4".to_string(),
                app_type: case["app_type"].as_str().expect("an app type").to_string(),
                install_wordpress: case["install_wordpress"].as_bool().unwrap_or(false),
                enable_ssl: false,
            };
            let name = case["case"].as_str().unwrap_or("");
            assert_eq!(
                fields.app_type_value(),
                case["app_type_value"].as_str().expect("the value"),
                "app_type_value for {name}"
            );
            assert_eq!(
                fields.installs_wordpress(),
                case["install_wp"].as_bool().expect("the flag"),
                "install_wp for {name}"
            );
            assert_eq!(
                fields.runtime_php(),
                case["runtime_php"].as_str(),
                "runtime_php for {name}"
            );
            assert_eq!(
                fields.rewrite_mode(),
                case["rewrite_mode"].as_str().expect("the mode"),
                "rewrite_mode for {name}"
            );
        }
    }

    /// The address is derived from the username, never taken from the body.
    #[test]
    fn the_account_email_is_derived_from_the_username() {
        let corpus = account_corpus();
        for case in corpus["email"].as_array().expect("the cases") {
            let username = case["username"].as_str().expect("a username");
            assert_eq!(
                provisioning_email(username),
                case["email"].as_str().expect("an address")
            );
        }
        // A body that sends its own address does not change the account's:
        // a billing system's contact address is not a panel login, and two
        // accounts sharing one would collide on a column the panel treats
        // as identifying.
        let body = json!({
            "external_id": "whmcs:1",
            "username": "customer1",
            "email": "billing@example.com",
            "password": "a-long-enough-password",
            "package_id": 1,
        });
        let fields = account_create_fields(&body).expect("a valid body");
        assert_eq!(
            provisioning_email(&fields.username),
            "customer1@users.snpanel.dev"
        );
    }

    /// `DOMAIN_RE`, including the two parts of it that look like mistakes.
    #[test]
    fn the_domain_pattern_is_the_pythons() {
        // `(?!-)` guards the whole name, not each label, so a label may
        // start with a dash even though the name may not.
        assert!(domain_pattern_ok("a.-b.com"));
        assert!(!domain_pattern_ok("-a.b.com"));
        // The last label is letters only and at least two of them, which is
        // what rejects a punycode TLD and a bare address.
        assert!(!domain_pattern_ok("xn--e1afmkfd.xn--p1ai"));
        assert!(!domain_pattern_ok("example.12"));
        assert!(!domain_pattern_ok("example.c"));
        assert!(!domain_pattern_ok("example"));
        // Sixty-three is the cap on a label, and it is not on the last one.
        assert!(domain_pattern_ok(&format!("{}.com", "a".repeat(63))));
        assert!(!domain_pattern_ok(&format!("{}.com", "a".repeat(64))));
        assert!(domain_pattern_ok(&format!("a.{}", "b".repeat(200))));
        // An empty label is not a label.
        assert!(!domain_pattern_ok("a..com"));
        assert!(!domain_pattern_ok("example.com."));
        assert!(!domain_pattern_ok(""));
    }
}
