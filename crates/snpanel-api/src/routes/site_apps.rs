//! `/api/site-apps` and `/api/site-runtimes` — ported from `api/site_apps.py`.
//!
//! An app belongs to a panel user, not to a website. It gets its own
//! directory, its own loopback port and its own systemd unit — a Node
//! process or a container. A website set to "application" mode points at
//! one, and nginx proxies the domain to that port; that side lives in
//! `routes/websites.rs`.
//!
//! The whole feature is an addon, so nothing here answers on a panel that has
//! not installed it. That is one guard, applied in each handler rather than
//! per route, which is the kind of thing that gets forgotten on the next
//! route someone adds — so it is the first line of every one of them.

use axum::extract::{Path, Query, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions;
use snpanel_db::SiteApp;

use crate::auth::CurrentUser;
use crate::site_apps as service;
use crate::site_apps::PortInput;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        // The two static paths are matched ahead of `/{app_id}` by the
        // router itself. Under FastAPI they had to be declared first, and
        // `/site-runtimes` needed a prefix of its own or `/{app_id}/status`
        // would have shadowed it into a 422.
        .route(
            "/site-apps",
            get(list).post(create).fallback(crate::fallback),
        )
        .route(
            "/site-apps/suggest-port",
            get(suggest_port).fallback(crate::fallback),
        )
        .route(
            "/site-apps/compose/validate",
            post(validate_compose).fallback(crate::fallback),
        )
        .route(
            "/site-apps/{app_id}",
            put(update).delete(remove).fallback(crate::fallback),
        )
        .route(
            "/site-apps/{app_id}/deploy",
            post(deploy).fallback(crate::fallback),
        )
        .route(
            "/site-apps/{app_id}/control",
            post(control).fallback(crate::fallback),
        )
        .route(
            "/site-apps/{app_id}/status",
            get(status).fallback(crate::fallback),
        )
        .route(
            "/site-apps/{app_id}/logs",
            get(logs).fallback(crate::fallback),
        )
        .route(
            "/site-runtimes/status",
            get(runtime_status).fallback(crate::fallback),
        )
        .route(
            "/site-runtimes/docker-install",
            post(install_docker).fallback(crate::fallback),
        )
        .route(
            "/site-runtimes/docker-prune",
            post(prune_docker).fallback(crate::fallback),
        )
        .route(
            "/site-runtimes/node-install",
            post(install_node).fallback(crate::fallback),
        )
}

/// `ensure_role(current_user.role, Role.end_user)` — every authenticated role
/// passes, but an unrecognised one does not.
fn ensure_end_user(current: &CurrentUser) -> Result<(), Response> {
    if permissions::normalize_role(&current.user.role).is_none() {
        return Err(crate::errors::error(
            axum::http::StatusCode::FORBIDDEN,
            "Invalid role",
        ));
    }
    Ok(())
}

fn ensure_admin(current: &CurrentUser) -> Result<(), Response> {
    if !permissions::is_admin_role(&current.user.role) {
        return Err(crate::errors::error(
            axum::http::StatusCode::FORBIDDEN,
            "Insufficient permissions",
        ));
    }
    Ok(())
}

/// Source: `_owned_app`. A 404 when there is no such app, and an admin-only
/// 403 when it belongs to someone else.
async fn owned_app(
    state: &AppState,
    current: &CurrentUser,
    app_id: i64,
) -> Result<SiteApp, Response> {
    let app = match state.db.site_apps().full_by_id(app_id).await {
        Ok(Some(app)) => app,
        Ok(None) => {
            return Err(crate::errors::error(
                axum::http::StatusCode::NOT_FOUND,
                "Application not found",
            ))
        }
        Err(e) => {
            tracing::error!("reading application {app_id} failed: {e}");
            return Err(crate::errors::internal_error());
        }
    };
    if app.owner_id != current.user.id {
        ensure_admin(current)?;
    }
    Ok(app)
}

/// Source: `_resolve_owner`.
async fn resolve_owner(
    state: &AppState,
    current: &CurrentUser,
    owner_id: Option<i64>,
) -> Result<snpanel_db::User, Response> {
    match owner_id {
        None => Ok(current.user.clone()),
        Some(id) if id == current.user.id => Ok(current.user.clone()),
        Some(id) => {
            ensure_admin(current)?;
            match state.db.users().by_id(id).await {
                Ok(Some(user)) => Ok(user),
                Ok(None) => Err(crate::errors::error(
                    axum::http::StatusCode::NOT_FOUND,
                    "Owner not found",
                )),
                Err(e) => {
                    tracing::error!("reading owner {id} failed: {e}");
                    Err(crate::errors::internal_error())
                }
            }
        }
    }
}

/// Source: `_app_out`.
///
/// The directory and the unit name are both derived, and both are reported as
/// an empty string when they cannot be — an app whose owner row is gone has
/// neither, and the page shows a blank rather than an error.
fn app_out(app: &SiteApp) -> Value {
    json!({
        "id": app.id,
        "owner_id": app.owner_id,
        "name": app.name,
        "kind": app.kind,
        "port": app.port,
        "start_kind": app.start_kind,
        "start_arg": app.start_arg,
        "node_major": app.node_major,
        "image": app.image,
        "container_port": app.container_port,
        "cpu_limit": app.cpu_limit,
        "env": app.env,
        "compose_source": app.compose_source,
        "web_service": app.web_service,
        "memory_limit_mb": app.memory_limit_mb,
        "autostart": app.autostart,
        "status": app.status,
        "last_error": app.last_error,
        "created_at": crate::errors::iso_datetime(app.created_at.as_deref()),
        // Where the customer uploads code. Their SFTP is chrooted to their
        // home, so the path is reachable without going through the panel.
        "directory": service::directory_for(app).unwrap_or_default(),
        "unit": service::unit_name(app, None).unwrap_or_default(),
        "websites": app.websites,
    })
}

// ---------------------------------------------------------------------------
// listing
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct ListQuery {
    owner_id: Option<i64>,
}

async fn list(
    State(state): State<AppState>,
    current: CurrentUser,
    Query(query): Query<ListQuery>,
) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    // An administrator sees everyone's unless they ask for one owner; a
    // customer only ever sees their own, whatever they ask for.
    let filter = if permissions::is_admin_role(&current.user.role) {
        query.owner_id
    } else {
        Some(current.user.id)
    };
    let apps = match state.db.site_apps().full_list(filter).await {
        Ok(apps) => apps,
        Err(e) => {
            tracing::error!("listing applications failed: {e}");
            return crate::errors::internal_error();
        }
    };
    let package = service::package_for(&state.db, &current.user).await;
    let used = state
        .db
        .site_apps()
        .count_for_owner(current.user.id)
        .await
        .unwrap_or(0);
    axum::Json(json!({
        "items": apps.iter().map(app_out).collect::<Vec<_>>(),
        // The limit and the usage are the **caller's**, not the owner's the
        // listing was filtered by: they are what the page greys the Create
        // button out with.
        "limit": service::app_limit_for(package.as_ref()),
        "used": used,
        "memory_ceiling_mb": service::memory_ceiling_for(package.as_ref()),
        "port_range": [service::PORT_RANGE_START, service::PORT_RANGE_END],
    }))
    .into_response()
}

async fn suggest_port(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    match service::allocate_port(
        state.settings.command_dry_run,
        &state.db,
        &PortInput::Missing,
        None,
    )
    .await
    {
        Ok(port) => axum::Json(json!({ "port": port })).into_response(),
        Err(why) => crate::errors::bad_request(&why),
    }
}

// ---------------------------------------------------------------------------
// the compose dry run
// ---------------------------------------------------------------------------

/// The two panel names that stand in for a domain the app has not been given
/// yet. Source: the `setdefault` pair every compose caller repeats.
fn with_placeholders(env: &str) -> Vec<(String, String)> {
    let mut values = crate::compose::read_variables(env);
    service::default_variable(&mut values, "SNPANEL_URL", "https://<domain>");
    service::default_variable(&mut values, "SNPANEL_DOMAIN", "<domain>");
    values
}

/// Report what the panel can run from a pasted compose file.
///
/// A dry run: nothing is stored, so the customer can paste, read the issues
/// and fix them before committing to an application.
async fn validate_compose(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }

    let mut entries = Vec::new();
    // `compose_source: str` with no default — the one required field.
    let source = match payload.get("compose_source") {
        Some(Value::String(text)) => text.clone(),
        Some(other) => {
            entries.push(crate::errors::string_type_entry("compose_source", other));
            String::new()
        }
        None => {
            entries.push(crate::errors::missing_entry(
                "compose_source",
                payload.clone(),
            ));
            String::new()
        }
    };
    let web_service = match optional_string(&payload, "web_service") {
        Ok(value) => value.unwrap_or_default(),
        Err(entry) => {
            entries.push(entry);
            String::new()
        }
    };
    let env = match optional_string(&payload, "env") {
        // `env: str = ""` — a null is a wrong type here, not the default.
        Ok(value) => value.unwrap_or_default(),
        Err(entry) => {
            entries.push(entry);
            String::new()
        }
    };
    // `web_port: Optional[int] = None`: the page sends a null when no port
    // was chosen, and that asks for the plan without one - it is not a
    // wrong type.
    let web_port = read_optional_int(&payload, "web_port", &mut entries);
    if let Some(port) = web_port {
        if let Some(entry) = crate::errors::range_entry("web_port", port, 1, 65535) {
            entries.push(entry);
        }
    }
    if !entries.is_empty() {
        return crate::errors::validation_error(entries);
    }

    // Same registry rule as a container application: admins may reach a
    // registry the panel does not ship in its allowlist, customers may not.
    let enforce = !permissions::is_admin_role(&current.user.role);
    let plan = crate::compose::analyse(
        &source,
        &web_service,
        enforce,
        &with_placeholders(&env),
        web_port.map(i128::from),
    );
    axum::Json(plan.as_json()).into_response()
}

/// A field declared `Optional[str]`: absent or null is nothing, a string is
/// itself, and anything else is `string_type`.
fn optional_string(payload: &Value, field: &str) -> Result<Option<String>, Value> {
    match payload.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(other) => Err(crate::errors::string_type_entry(field, other)),
    }
}

/// A `Literal[...]` field, which pydantic reports by name with the options it
/// would have taken.
fn optional_literal(
    payload: &Value,
    field: &str,
    allowed: &[&str],
) -> Result<Option<String>, Value> {
    match payload.get(field) {
        // `Optional[Literal[...]]` — a null is the None arm, not a bad value.
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if allowed.contains(&text.as_str()) => Ok(Some(text.clone())),
        // A literal is checked by **membership**, not by type: a number that
        // is not one of the options is `literal_error`, not `string_type`.
        Some(other) => Err(crate::errors::literal_entry(field, other, allowed)),
    }
}

// ---------------------------------------------------------------------------
// creating one
// ---------------------------------------------------------------------------

/// Every field of `SiteAppCreate`, read the way pydantic reads it.
///
/// All of them, and in declaration order: pydantic reports every bad field in
/// one answer rather than stopping at the first, and a form that shows one
/// error at a time when the panel used to show four is a difference a
/// customer notices immediately.
#[derive(Debug)]
struct CreateFields {
    name: String,
    kind: String,
    compose_source: Option<String>,
    web_service: Option<String>,
    owner_id: Option<i64>,
    port: Option<i64>,
    start_kind: Option<String>,
    start_arg: Option<String>,
    node_major: Option<String>,
    image: Option<String>,
    container_port: Option<i64>,
    cpu_limit: Option<String>,
    env: Option<String>,
    memory_limit_mb: Option<i64>,
    autostart: bool,
}

fn create_fields(payload: &Value) -> Result<CreateFields, Vec<Value>> {
    let mut entries = Vec::new();
    let take_string = |field: &str, entries: &mut Vec<Value>| match optional_string(payload, field)
    {
        Ok(value) => value,
        Err(entry) => {
            entries.push(entry);
            None
        }
    };
    // `name: str = "app"` — a default, so a missing field is not an error,
    // but an explicit `null` is the wrong type.
    let name = match payload.get("name") {
        None => "app".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => {
            entries.push(crate::errors::string_type_entry("name", other));
            String::new()
        }
    };
    let kind = match payload.get("kind") {
        None => "node".to_string(),
        Some(Value::String(text)) if service::APP_KINDS.contains(&text.as_str()) => text.clone(),
        Some(other) => {
            entries.push(crate::errors::literal_entry("kind", other, KIND_ORDER));
            String::new()
        }
    };
    let compose_source = take_string("compose_source", &mut entries);
    let web_service = take_string("web_service", &mut entries);
    let owner_id = read_optional_int(payload, "owner_id", &mut entries);
    let port = read_optional_int(payload, "port", &mut entries);
    let start_kind = match optional_literal(payload, "start_kind", START_ORDER) {
        Ok(value) => value,
        Err(entry) => {
            entries.push(entry);
            None
        }
    };
    let start_arg = take_string("start_arg", &mut entries);
    let node_major = take_string("node_major", &mut entries);
    let image = take_string("image", &mut entries);
    let container_port = read_optional_int(payload, "container_port", &mut entries);
    let cpu_limit = take_string("cpu_limit", &mut entries);
    let env = take_string("env", &mut entries);
    let memory_limit_mb = read_optional_int(payload, "memory_limit_mb", &mut entries);
    let autostart =
        match crate::errors::read_bool_entry("autostart", payload.get("autostart"), true) {
            Ok(value) => value,
            Err(entry) => {
                entries.push(entry);
                true
            }
        };
    if !entries.is_empty() {
        return Err(entries);
    }
    Ok(CreateFields {
        name,
        kind,
        compose_source,
        web_service,
        owner_id,
        port,
        start_kind,
        start_arg,
        node_major,
        image,
        container_port,
        cpu_limit,
        env,
        memory_limit_mb,
        autostart,
    })
}

/// The order the literals are **declared** in, which is the order pydantic
/// prints them back. `APP_KINDS` is sorted for the message
/// `validate_kind` builds, and the two are not the same list.
const KIND_ORDER: &[&str] = &["node", "docker", "compose"];
const START_ORDER: &[&str] = &["node", "npm", "npx", "yarn"];

/// Every field of `SiteAppUpdate`.
///
/// A field left out and a field set to `null` are the same thing here: both
/// are `None`, and the handler leaves that part of the app alone.
struct UpdateFields {
    name: Option<String>,
    compose_source: Option<String>,
    web_service: Option<String>,
    port: Option<i64>,
    start_kind: Option<String>,
    start_arg: Option<String>,
    node_major: Option<String>,
    image: Option<String>,
    container_port: Option<i64>,
    cpu_limit: Option<String>,
    env: Option<String>,
    memory_limit_mb: Option<i64>,
    autostart: Option<bool>,
}

fn update_fields(payload: &Value) -> Result<UpdateFields, Vec<Value>> {
    let mut entries = Vec::new();
    let take_string = |field: &str, entries: &mut Vec<Value>| match optional_string(payload, field)
    {
        Ok(value) => value,
        Err(entry) => {
            entries.push(entry);
            None
        }
    };
    let name = take_string("name", &mut entries);
    let port = read_optional_int(payload, "port", &mut entries);
    let compose_source = take_string("compose_source", &mut entries);
    let web_service = take_string("web_service", &mut entries);
    let start_kind = match optional_literal(payload, "start_kind", START_ORDER) {
        Ok(value) => value,
        Err(entry) => {
            entries.push(entry);
            None
        }
    };
    let start_arg = take_string("start_arg", &mut entries);
    let node_major = take_string("node_major", &mut entries);
    let image = take_string("image", &mut entries);
    let container_port = read_optional_int(payload, "container_port", &mut entries);
    let cpu_limit = take_string("cpu_limit", &mut entries);
    let env = take_string("env", &mut entries);
    let memory_limit_mb = read_optional_int(payload, "memory_limit_mb", &mut entries);
    let autostart = read_optional_bool(payload, "autostart", &mut entries);
    if !entries.is_empty() {
        return Err(entries);
    }
    Ok(UpdateFields {
        name,
        compose_source,
        web_service,
        port,
        start_kind,
        start_arg,
        node_major,
        image,
        container_port,
        cpu_limit,
        env,
        memory_limit_mb,
        autostart,
    })
}

/// `Optional[bool]`: absent or null is nothing, and anything else is read the
/// way a required boolean is.
fn read_optional_bool(payload: &Value, field: &str, entries: &mut Vec<Value>) -> Option<bool> {
    match payload.get(field) {
        None | Some(Value::Null) => None,
        Some(_) => match crate::errors::read_bool_entry(field, payload.get(field), false) {
            Ok(value) => Some(value),
            Err(entry) => {
                entries.push(entry);
                None
            }
        },
    }
}

fn read_optional_int(payload: &Value, field: &str, entries: &mut Vec<Value>) -> Option<i64> {
    // `Optional[int]` takes a null; `read_int_entry` is written for a field
    // that does not, and calls one `int_type`.
    if matches!(payload.get(field), None | Some(Value::Null)) {
        return None;
    }
    match crate::errors::read_int_entry(field, payload.get(field)) {
        Ok(value) => value,
        Err(entry) => {
            entries.push(entry);
            None
        }
    }
}

/// The 400 a compose file that cannot be imported answers with — a dict
/// detail, not a sentence, because the page lists the issues one per line.
fn compose_rejected(plan: &crate::compose::Plan) -> Response {
    crate::errors::detail(
        axum::http::StatusCode::BAD_REQUEST,
        json!({
            "message": "Compose file cannot be imported as it is",
            "issues": plan.issues.iter().map(crate::compose::Issue::as_json).collect::<Vec<_>>(),
        }),
    )
}

async fn create(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fields = match create_fields(&payload) {
        Ok(fields) => fields,
        Err(entries) => return crate::errors::validation_error(entries),
    };
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    let owner = match resolve_owner(&state, &current, fields.owner_id).await {
        Ok(owner) => owner,
        Err(r) => return r,
    };
    let is_admin = permissions::is_admin_role(&current.user.role);
    let dry = state.settings.command_dry_run;

    let package = service::package_for(&state.db, &owner).await;
    if let Err(why) =
        service::ensure_app_quota(&state.db, owner.id, package.as_ref(), is_admin).await
    {
        return crate::errors::bad_request(&why);
    }
    let ceiling = if is_admin {
        None
    } else {
        Some(service::memory_ceiling_for(package.as_ref()))
    };

    let name = match service::validate_name(&fields.name) {
        Ok(value) => value,
        Err(why) => return crate::errors::bad_request(&why),
    };
    let kind = match service::validate_kind(&fields.kind) {
        Ok(value) => value,
        Err(why) => return crate::errors::bad_request(&why),
    };
    let memory_limit_mb =
        match service::validate_memory_mb(&int_input(fields.memory_limit_mb), ceiling) {
            Ok(value) => value,
            Err(why) => return crate::errors::bad_request(&why),
        };

    let (mut start_kind, mut start_arg, mut node_major) = (None, None, None);
    let (mut image, mut container_port, mut cpu_limit) = (None, 3000i64, "1".to_string());
    let (mut compose_source, mut web_service) = (String::new(), None);
    match kind.as_str() {
        "node" => {
            match service::validate_start(
                fields.start_kind.as_deref().unwrap_or(""),
                fields.start_arg.as_deref().unwrap_or(""),
            ) {
                Ok((k, a)) => {
                    start_kind = Some(k);
                    start_arg = Some(a);
                }
                Err(why) => return crate::errors::bad_request(&why),
            }
            match service::validate_node_major(json_string_option(&fields.node_major).as_ref()) {
                // `or "22"` — an omitted version is the panel's default.
                Ok(value) => node_major = Some(value.unwrap_or_else(|| "22".to_string())),
                Err(why) => return crate::errors::bad_request(&why),
            }
        }
        "docker" => {
            match service::validate_image(fields.image.as_deref().unwrap_or(""), !is_admin) {
                Ok(value) => image = Some(value),
                Err(why) => return crate::errors::bad_request(&why),
            }
            match service::validate_container_port(&int_input(fields.container_port)) {
                Ok(value) => container_port = value,
                Err(why) => return crate::errors::bad_request(&why),
            }
            match service::validate_cpu_limit(json_string_option(&fields.cpu_limit).as_ref()) {
                Ok(value) => cpu_limit = value,
                Err(why) => return crate::errors::bad_request(&why),
            }
        }
        _ => {
            match service::validate_cpu_limit(json_string_option(&fields.cpu_limit).as_ref()) {
                Ok(value) => cpu_limit = value,
                Err(why) => return crate::errors::bad_request(&why),
            }
            let plan = crate::compose::analyse(
                fields.compose_source.as_deref().unwrap_or(""),
                fields.web_service.as_deref().unwrap_or(""),
                !is_admin,
                &with_placeholders(fields.env.as_deref().unwrap_or("")),
                fields.container_port.map(i128::from),
            );
            if !plan.ok() {
                return compose_rejected(&plan);
            }
            compose_source = fields.compose_source.clone().unwrap_or_default();
            web_service = Some(plan.web_service.clone());
            container_port = plan
                .services
                .iter()
                .find(|service| service.name == plan.web_service)
                .and_then(|service| service.container_port)
                .map(|port| port as i64)
                .unwrap_or(container_port);
        }
    }
    let env = match service::validate_env(fields.env.as_deref()) {
        Ok(value) => value,
        Err(why) => return crate::errors::bad_request(&why),
    };
    let port = match service::allocate_port(dry, &state.db, &int_input(fields.port), None).await {
        Ok(value) => value,
        Err(why) => return crate::errors::bad_request(&why),
    };

    let row = snpanel_db::NewSiteApp {
        owner_id: owner.id,
        name: name.clone(),
        kind,
        start_kind,
        start_arg,
        node_major,
        image,
        container_port,
        cpu_limit,
        env,
        compose_source,
        web_service,
        port,
        memory_limit_mb,
        autostart: fields.autostart,
        created_at: snpanel_db::sqlalchemy_now(),
    };
    let app_id = match state.db.site_apps().create(&row).await {
        Ok(Ok(id)) => id,
        Ok(Err(snpanel_db::Duplicate)) => {
            return crate::errors::error(
                axum::http::StatusCode::CONFLICT,
                "You already have an application with that name",
            )
        }
        Err(e) => {
            tracing::error!("storing the application row failed: {e}");
            return crate::errors::internal_error();
        }
    };
    let app = match state.db.site_apps().full_by_id(app_id).await {
        Ok(Some(app)) => app,
        _ => return crate::errors::internal_error(),
    };
    // So the customer can upload code straight away instead of having to
    // deploy an empty application first. A failure here is not one the
    // caller hears about: the app exists either way.
    let _ = service::ensure_directory(dry, &app).await;
    audit(
        &state,
        current.user.id,
        "create_site_app",
        owner.username.as_str(),
        &format!("{name} :{port}"),
    )
    .await;
    axum::Json(app_out(&app)).into_response()
}

/// `int(...)` as the validators take it: a pydantic-coerced integer, or
/// nothing at all.
fn int_input(value: Option<i64>) -> PortInput {
    match value {
        Some(number) => PortInput::Int(number),
        None => PortInput::Missing,
    }
}

/// The two validators that take whatever JSON sent, given what pydantic has
/// already narrowed to a string.
fn json_string_option(value: &Option<String>) -> Option<Value> {
    value.as_ref().map(|text| Value::String(text.clone()))
}

async fn audit(state: &AppState, user_id: i64, action: &str, target: &str, detail: &str) {
    if let Err(e) = state
        .db
        .audits()
        .log(Some(user_id), action, target, detail)
        .await
    {
        tracing::error!("Failed to write audit log: action={action} target={target}: {e}");
    }
}

// ---------------------------------------------------------------------------
// editing one
// ---------------------------------------------------------------------------

/// Everything the systemd unit is built from. Change any of these on a
/// deployed app and the running process is out of date until it is rewritten.
fn unit_fields(app: &SiteApp) -> Vec<String> {
    vec![
        app.port.to_string(),
        app.memory_limit_mb.to_string(),
        app.cpu_limit.clone(),
        format!("{:?}", app.image),
        app.container_port.to_string(),
        format!("{:?}", app.start_kind),
        format!("{:?}", app.start_arg),
        format!("{:?}", app.node_major),
        app.env.clone(),
        app.name.clone(),
        app.compose_source.clone(),
        format!("{:?}", app.web_service),
    ]
}

async fn update(State(state): State<AppState>, Path(app_id): Path<i64>, req: Request) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fields = match update_fields(&payload) {
        Ok(fields) => fields,
        Err(entries) => return crate::errors::validation_error(entries),
    };
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    let mut app = match owned_app(&state, &current, app_id).await {
        Ok(app) => app,
        Err(r) => return r,
    };
    // `db.query(User).filter(User.id == app.owner_id).first() or current_user`
    // — an app whose owner row is gone is held to the caller's package.
    let owner = match state.db.users().by_id(app.owner_id).await {
        Ok(Some(user)) => user,
        _ => current.user.clone(),
    };
    let is_admin = permissions::is_admin_role(&current.user.role);
    let dry = state.settings.command_dry_run;
    let previous_port = app.port;
    let before = unit_fields(&app);
    let previous_name = app.name.clone();

    if let Some(name) = &fields.name {
        match service::validate_name(name) {
            Ok(value) => app.name = value,
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    if fields.memory_limit_mb.is_some() {
        let package = service::package_for(&state.db, &owner).await;
        let ceiling = if is_admin {
            None
        } else {
            Some(service::memory_ceiling_for(package.as_ref()))
        };
        match service::validate_memory_mb(&int_input(fields.memory_limit_mb), ceiling) {
            Ok(value) => app.memory_limit_mb = value,
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    if let Some(autostart) = fields.autostart {
        app.autostart = autostart;
    }
    if fields.node_major.is_some() {
        match service::validate_node_major(json_string_option(&fields.node_major).as_ref()) {
            // No `or "22"` on this side: the update stores what was asked
            // for, and `write_runtime` supplies the default when it reads it.
            Ok(value) => app.node_major = value,
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    if fields.image.is_some() {
        match service::validate_image(fields.image.as_deref().unwrap_or(""), !is_admin) {
            Ok(value) => app.image = Some(value),
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    if fields.container_port.is_some() {
        match service::validate_container_port(&int_input(fields.container_port)) {
            Ok(value) => app.container_port = value,
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    if fields.cpu_limit.is_some() {
        match service::validate_cpu_limit(json_string_option(&fields.cpu_limit).as_ref()) {
            Ok(value) => app.cpu_limit = value,
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    if fields.env.is_some() {
        match service::validate_env(fields.env.as_deref()) {
            Ok(value) => app.env = value,
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    let touched_compose =
        fields.compose_source.is_some() || fields.web_service.is_some() || fields.env.is_some();
    if app.kind == "compose" && touched_compose {
        let source = fields
            .compose_source
            .clone()
            .unwrap_or_else(|| app.compose_source.clone());
        let wanted = fields
            .web_service
            .clone()
            .unwrap_or_else(|| app.web_service.clone().unwrap_or_default());
        let mut variables = service::compose_variables(&state.db, &app).await;
        service::default_variable(&mut variables, "SNPANEL_URL", "https://<domain>");
        service::default_variable(&mut variables, "SNPANEL_DOMAIN", "<domain>");
        // The registry allowlist is **not** enforced here, which is the
        // Python's own asymmetry: `analyse` is called without the flag, so it
        // takes its default of `True`.
        let plan = crate::compose::analyse(
            &source,
            &wanted,
            true,
            &variables,
            fields.container_port.map(i128::from),
        );
        if !plan.ok() {
            return compose_rejected(&plan);
        }
        app.compose_source = source;
        app.web_service = Some(plan.web_service.clone());
        if let Some(port) = plan
            .services
            .iter()
            .find(|service| service.name == plan.web_service)
            .and_then(|service| service.container_port)
        {
            app.container_port = port as i64;
        }
    }
    if fields.start_kind.is_some() || fields.start_arg.is_some() {
        // `payload.start_kind or app.start_kind` — an empty string falls
        // back to what the app already had.
        let kind = pick(&fields.start_kind, &app.start_kind);
        let arg = pick(&fields.start_arg, &app.start_arg);
        match service::validate_start(&kind, &arg) {
            Ok((k, a)) => {
                app.start_kind = Some(k);
                app.start_arg = Some(a);
            }
            Err(why) => return crate::errors::bad_request(&why),
        }
    }
    if let Some(port) = fields.port.filter(|port| *port != previous_port) {
        match service::allocate_port(dry, &state.db, &PortInput::Int(port), Some(app.id)).await {
            Ok(value) => app.port = value,
            Err(why) => return crate::errors::bad_request(&why),
        }
    }

    if let Ok(Err(snpanel_db::Duplicate)) = state.db.site_apps().save(&app).await {
        return crate::errors::error(
            axum::http::StatusCode::CONFLICT,
            "An application with that name or port already exists",
        );
    }
    app.websites = state
        .db
        .site_apps()
        .domains_for(app.id)
        .await
        .unwrap_or_default();

    if app.name != previous_name {
        if let Err(why) = service::rename_directory(dry, &app, &previous_name).await {
            return crate::errors::bad_request(&why);
        }
    }
    if app.kind == "docker" || app.kind == "compose" || unit_fields(&app) != before {
        // The unit still carries the old port, memory cap or start command
        // until it is rewritten, so a change that only touched the database
        // would leave the running process stale until someone thought to
        // press Deploy.
        //
        // A container app re-applies even when nothing in the file changed:
        // with a tag like `:latest` the version that should run moves without
        // the text moving, and saving is how someone asks for what the tag
        // points at now.
        reapply_runtime(&state, &mut app, &previous_name).await;
    }
    if app.port != previous_port {
        if let Err(r) = resync_websites(&state, &app).await {
            return r;
        }
    }

    audit(
        &state,
        current.user.id,
        "update_site_app",
        &app.name,
        &format!(":{}", app.port),
    )
    .await;
    axum::Json(app_out(&app)).into_response()
}

/// `a or b` for two optional strings — an empty one is falsy and falls
/// through to the second.
fn pick(first: &Option<String>, second: &Option<String>) -> String {
    match first {
        Some(text) if !text.is_empty() => text.clone(),
        _ => second.clone().unwrap_or_default(),
    }
}

/// Rewrite the unit and restart, but only for an app already deployed.
async fn reapply_runtime(state: &AppState, app: &mut SiteApp, previous_name: &str) {
    let dry = state.settings.command_dry_run;
    let Ok(unit) = service::unit_name(app, Some(previous_name)) else {
        return;
    };
    if !std::path::Path::new(&format!("/etc/systemd/system/{unit}.service")).exists() {
        return;
    }
    if !previous_name.is_empty() && previous_name != app.name {
        // A rename moves the unit, so the old one has to go or it keeps
        // running the app under a name nothing points at any more.
        service::delete_runtime(dry, app, Some(previous_name)).await;
    }
    let outcome = async {
        service::write_runtime(dry, &state.db, app).await?;
        // Fetch first, so the containers currently serving stay up while the
        // new image downloads. A bad tag then fails here, with the old ones
        // running.
        service::fetch_images(dry, app).await?;
        service::control(dry, app, "restart").await
    }
    .await;
    if let Err(why) = outcome {
        record_status(
            state,
            app,
            "error",
            &last_chars(&format!("Could not restart on the new port: {why}"), 2000),
        )
        .await;
        return;
    }
    let running = service::settled_state(dry, app, 4, 1500).await == "active";
    let detail = if running {
        ""
    } else {
        "The application did not come back on the new port. Check the log."
    };
    record_status(
        state,
        app,
        if running { "running" } else { "error" },
        detail,
    )
    .await;
}

/// Every domain serving this app has to follow its port.
async fn resync_websites(state: &AppState, app: &SiteApp) -> Result<(), Response> {
    for domain in &app.websites {
        let Ok(Some(website)) = state.db.websites().by_domain(domain).await else {
            continue;
        };
        let overrides = super::websites::RewriteOverrides {
            app_port: Some(app.port),
            ..Default::default()
        };
        if let Err(_response) =
            super::websites::rewrite_website_vhost(state, &website, overrides).await
        {
            return Err(crate::errors::bad_request(&format!(
                "Cannot write Nginx config for {domain}: could not rewrite the vhost"
            )));
        }
    }
    Ok(())
}

/// `_record_status` — the status and the last error, clipped to the last two
/// thousand characters the column is given.
async fn record_status(state: &AppState, app: &mut SiteApp, status: &str, error: &str) {
    app.status = status.to_string();
    app.last_error = last_chars(error, 2000);
    if let Err(e) = state
        .db
        .site_apps()
        .set_status(app.id, &app.status, &app.last_error)
        .await
    {
        tracing::error!("recording the status of application {} failed: {e}", app.id);
    }
}

fn last_chars(text: &str, n: usize) -> String {
    let count = text.chars().count();
    text.chars().skip(count.saturating_sub(n)).collect()
}

// ---------------------------------------------------------------------------
// deleting one
// ---------------------------------------------------------------------------

async fn remove(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(app_id): Path<i64>,
) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    let app = match owned_app(&state, &current, app_id).await {
        Ok(app) => app,
        Err(r) => return r,
    };
    if !app.websites.is_empty() {
        return crate::errors::error(
            axum::http::StatusCode::CONFLICT,
            &format!(
                "This application still serves {}. Point those websites at something else first.",
                app.websites.join(", ")
            ),
        );
    }
    let (name, port) = (app.name.clone(), app.port);
    service::delete_runtime(state.settings.command_dry_run, &app, None).await;
    if let Err(e) = state.db.site_apps().delete(app.id).await {
        tracing::error!("deleting application {} failed: {e}", app.id);
        return crate::errors::internal_error();
    }
    audit(
        &state,
        current.user.id,
        "delete_site_app",
        &name,
        &format!(":{port}"),
    )
    .await;
    axum::Json(json!({ "deleted": name, "port": port })).into_response()
}

// ---------------------------------------------------------------------------
// the runtime lifecycle
// ---------------------------------------------------------------------------

/// Fetch what the app needs, write its unit, and start it.
async fn deploy(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(app_id): Path<i64>,
) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    let mut app = match owned_app(&state, &current, app_id).await {
        Ok(app) => app,
        Err(r) => return r,
    };
    let dry = state.settings.command_dry_run;

    let mut steps: Vec<String> = Vec::new();
    let unit = match deploy_steps(&state, &app, &mut steps).await {
        Ok(unit) => unit,
        Err(why) => {
            record_status(&state, &mut app, "error", &why).await;
            return crate::errors::bad_request(&why);
        }
    };

    // Give it a few seconds to fall over before calling the deploy a success.
    let state_text = service::settled_state(dry, &app, 4, 1500).await;
    let mut running = state_text == "active";
    let mut trouble = String::new();
    if running && app.kind == "compose" {
        // `docker compose up` stays attached through a container's crash
        // loop, so the unit being active says nothing about the containers
        // themselves.
        trouble = service::compose_trouble(dry, &app).await;
        running = trouble.is_empty();
    }
    let detail = if running {
        String::new()
    } else if !trouble.is_empty() {
        trouble
    } else {
        format!(
            "The application did not stay running (systemd reports '{state_text}'). Check the log."
        )
    };
    record_status(
        &state,
        &mut app,
        if running { "running" } else { "error" },
        &detail,
    )
    .await;
    audit(
        &state,
        current.user.id,
        "deploy_site_app",
        &app.name,
        &format!(":{} {state_text}", app.port),
    )
    .await;
    let output: Vec<&str> = steps
        .iter()
        .map(String::as_str)
        .filter(|step| !step.is_empty())
        .collect();
    axum::Json(json!({
        "unit": unit,
        "status": app.status,
        "running": running,
        "output": last_chars(&output.join("\n"), 4000),
    }))
    .into_response()
}

/// The part of a deploy that can fail, in the order it has to happen.
async fn deploy_steps(
    state: &AppState,
    app: &SiteApp,
    steps: &mut Vec<String>,
) -> Result<String, String> {
    let dry = state.settings.command_dry_run;
    let unit = if app.kind == "compose" {
        // The unit and the generated file come first: pulling reads that file.
        let unit = service::write_runtime(dry, &state.db, app).await?;
        steps.push(service::fetch_images(dry, app).await?);
        unit
    } else {
        if app.kind == "docker" {
            steps.push(service::fetch_images(dry, app).await?);
        } else {
            match service::install_dependencies(dry, app).await {
                Ok(output) => steps.push(output),
                // No package.json is normal for a single-file entry point.
                Err(why) if why.to_lowercase().contains("no package.json") => {}
                Err(why) => return Err(why),
            }
        }
        service::write_runtime(dry, &state.db, app).await?
    };
    service::control(dry, app, if app.autostart { "enable" } else { "disable" }).await?;
    service::control(dry, app, "restart").await?;
    Ok(unit)
}

async fn control(State(state): State<AppState>, Path(app_id): Path<i64>, req: Request) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `action: Literal["start", "stop", "restart"]` — required, and only
    // those three. The wider `CONTROL_ACTIONS` the service knows is not
    // reachable from here.
    const ACTIONS: &[&str] = &["start", "stop", "restart"];
    let action = match payload.get("action") {
        Some(Value::String(text)) if ACTIONS.contains(&text.as_str()) => text.clone(),
        None => return crate::errors::missing_field("action", payload.clone()),
        Some(other) => {
            return crate::errors::validation_error(vec![crate::errors::literal_entry(
                "action", other, ACTIONS,
            )])
        }
    };
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    let mut app = match owned_app(&state, &current, app_id).await {
        Ok(app) => app,
        Err(r) => return r,
    };
    let dry = state.settings.command_dry_run;
    let output = match service::control(dry, &app, &action).await {
        Ok(output) => output,
        Err(why) => return crate::errors::bad_request(&why),
    };
    let running = service::is_running(dry, &app).await;
    record_status(
        &state,
        &mut app,
        if running { "running" } else { "stopped" },
        "",
    )
    .await;
    audit(
        &state,
        current.user.id,
        &format!("{action}_site_app"),
        &app.name,
        "",
    )
    .await;
    axum::Json(json!({
        "action": action,
        "running": running,
        "status": app.status,
        "output": last_chars(&output, 2000),
    }))
    .into_response()
}

async fn status(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(app_id): Path<i64>,
) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    let app = match owned_app(&state, &current, app_id).await {
        Ok(app) => app,
        Err(r) => return r,
    };
    let dry = state.settings.command_dry_run;
    let running = service::is_running(dry, &app).await;
    let trouble = if running && app.kind == "compose" {
        service::compose_trouble(dry, &app).await
    } else {
        String::new()
    };
    // Not guarded, unlike the one in `_app_out`: an app with no owner is a
    // 500 here, which is what the Python's uncaught `ValueError` produces.
    let unit = match service::unit_name(&app, None) {
        Ok(unit) => unit,
        Err(why) => {
            tracing::error!(
                "the unit name of application {} cannot be built: {why}",
                app.id
            );
            return crate::errors::internal_error();
        }
    };
    axum::Json(json!({
        "running": running && trouble.is_empty(),
        "unit": unit,
        "status": if trouble.is_empty() { app.status.clone() } else { "error".to_string() },
        "last_error": if trouble.is_empty() { app.last_error.clone() } else { trouble },
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct LogsQuery {
    lines: Option<i64>,
}

async fn logs(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(app_id): Path<i64>,
    Query(query): Query<LogsQuery>,
) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    // `lines: int = 200` as a query parameter.
    let lines = query.lines.unwrap_or(200);
    let app = match owned_app(&state, &current, app_id).await {
        Ok(app) => app,
        Err(r) => return r,
    };
    match service::logs(state.settings.command_dry_run, &app, lines).await {
        Ok(log) => axum::Json(json!({ "log": log })).into_response(),
        Err(why) => crate::errors::bad_request(&why),
    }
}

// ---------------------------------------------------------------------------
// the runtimes the server has installed
// ---------------------------------------------------------------------------

async fn runtime_status(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_end_user(&current) {
        return r;
    }
    let dry = state.settings.command_dry_run;
    axum::Json(json!({
        "docker": service::docker_status(dry).await,
        "node_majors": service::installed_node_majors(dry).await,
        "allowed_registries": service::allowed_registries(),
    }))
    .into_response()
}

async fn install_docker(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_admin(&current) {
        return r;
    }
    let dry = state.settings.command_dry_run;
    match service::install_docker(dry).await {
        Ok(output) => axum::Json(json!({
            "message": "Docker is ready.",
            "output": output,
            "docker": service::docker_status(dry).await,
        }))
        .into_response(),
        Err(why) => crate::errors::bad_request(&why),
    }
}

/// Reclaim what pulling images left behind.
///
/// Server-wide, so it is an administrator's button: images are shared between
/// tenants and cannot be charged to one customer's quota.
async fn prune_docker(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    if let Err(r) = ensure_admin(&current) {
        return r;
    }
    let dry = state.settings.command_dry_run;
    match service::prune_docker(dry).await {
        Ok(output) => {
            audit(&state, current.user.id, "prune_docker", "docker", "").await;
            axum::Json(json!({
                "message": "Unused layers and build cache removed.",
                "output": output,
                "docker": service::docker_status(dry).await,
            }))
            .into_response()
        }
        Err(why) => crate::errors::bad_request(&why),
    }
}

async fn install_node(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = super::addons::require_application() {
        return r;
    }
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // `major: str` with no default.
    let major = match payload.get("major") {
        Some(Value::String(text)) => text.clone(),
        None => return crate::errors::missing_field("major", payload.clone()),
        Some(other) => return crate::errors::string_type("major", other),
    };
    if let Err(r) = ensure_admin(&current) {
        return r;
    }
    let dry = state.settings.command_dry_run;
    match service::install_node(dry, Some(&Value::String(major.clone()))).await {
        Ok(output) => axum::Json(json!({
            "message": format!("Node {major} is ready."),
            "output": output,
            "node_majors": service::installed_node_majors(dry).await,
        }))
        .into_response(),
        Err(why) => crate::errors::bad_request(&why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/site_app_fields.json"
        ))
        .expect("the corpus");
        serde_json::from_str(&text).expect("the corpus parses")
    }

    /// The `type` and `loc` of each entry, in order. The message and the
    /// context are pydantic's own wording and are checked by the entry
    /// builders in `errors.rs`; what matters here is that the same fields are
    /// complained about, for the same reason, in the same order.
    fn signature(entries: &[Value]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| {
                let kind = entry["type"].as_str().unwrap_or("");
                let field = entry["loc"]
                    .as_array()
                    .and_then(|loc| loc.last())
                    .and_then(Value::as_str)
                    .unwrap_or("");
                format!("{field}:{kind}")
            })
            .collect()
    }

    fn want_signature(case: &Value) -> Vec<String> {
        case["errors"]
            .as_array()
            .map(|entries| signature(entries))
            .unwrap_or_default()
    }

    #[test]
    fn a_create_body_is_read_the_way_pydantic_reads_it() {
        let corpus = corpus();
        let cases = corpus["create"].as_array().expect("the cases");
        assert_eq!(cases.len(), 43, "the corpus changed size");
        let mut failures = Vec::new();
        for case in cases {
            let body = &case["body"];
            match (create_fields(body), case["ok"].as_bool().unwrap_or(false)) {
                (Ok(fields), true) => {
                    let want = &case["value"];
                    // Only the fields the handler goes on to read; the rest
                    // are carried through untouched.
                    let got = json!({
                        "name": fields.name,
                        "kind": fields.kind,
                        "autostart": fields.autostart,
                        "port": fields.port,
                        "owner_id": fields.owner_id,
                        "container_port": fields.container_port,
                        "memory_limit_mb": fields.memory_limit_mb,
                        "start_kind": fields.start_kind,
                        "node_major": fields.node_major,
                        "cpu_limit": fields.cpu_limit,
                        "env": fields.env,
                        "image": fields.image,
                        "compose_source": fields.compose_source,
                        "web_service": fields.web_service,
                        "start_arg": fields.start_arg,
                    });
                    for (key, value) in got.as_object().expect("an object") {
                        if &want[key] != value {
                            failures.push(format!("{body}: {key} want {}, got {value}", want[key]));
                        }
                    }
                }
                (Err(entries), false) => {
                    let got = signature(&entries);
                    let want = want_signature(case);
                    if got != want {
                        failures.push(format!("{body}: want {want:?}, got {got:?}"));
                    }
                }
                (Ok(_), false) => failures.push(format!("{body}: accepted, pydantic refused it")),
                (Err(entries), true) => failures.push(format!(
                    "{body}: refused with {:?}, pydantic took it",
                    signature(&entries)
                )),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn an_update_body_is_read_the_way_pydantic_reads_it() {
        let corpus = corpus();
        let cases = corpus["update"].as_array().expect("the cases");
        assert_eq!(cases.len(), 13, "the corpus changed size");
        let mut failures = Vec::new();
        for case in cases {
            let body = &case["body"];
            match (update_fields(body), case["ok"].as_bool().unwrap_or(false)) {
                (Ok(fields), true) => {
                    let want = &case["value"];
                    let got = json!({
                        "name": fields.name,
                        "autostart": fields.autostart,
                        "port": fields.port,
                        "memory_limit_mb": fields.memory_limit_mb,
                        "start_kind": fields.start_kind,
                        "image": fields.image,
                    });
                    for (key, value) in got.as_object().expect("an object") {
                        if &want[key] != value {
                            failures.push(format!("{body}: {key} want {}, got {value}", want[key]));
                        }
                    }
                }
                (Err(entries), false) => {
                    let got = signature(&entries);
                    let want = want_signature(case);
                    if got != want {
                        failures.push(format!("{body}: want {want:?}, got {got:?}"));
                    }
                }
                (Ok(_), false) => failures.push(format!("{body}: accepted, pydantic refused it")),
                (Err(entries), true) => failures.push(format!(
                    "{body}: refused with {:?}, pydantic took it",
                    signature(&entries)
                )),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// A model that does not declare a field **ignores** it, so a PUT that
    /// carries a kind is not a 422 — the kind simply does not change.
    #[test]
    fn an_update_ignores_a_field_the_model_does_not_have() {
        let body = json!({"kind": "nonsense", "owner_id": "not a number"});
        assert!(update_fields(&body).is_ok());
        // The same body on create is two errors, because both fields exist
        // there.
        let entries = create_fields(&body).expect_err("create refuses it");
        assert_eq!(
            signature(&entries),
            ["kind:literal_error", "owner_id:int_parsing"]
        );
    }

    /// Pydantic's literal message names the options in the order they were
    /// declared, which is not the order `APP_KINDS` is sorted into.
    #[test]
    fn a_literal_lists_its_options_the_way_pydantic_lists_them() {
        let entry = crate::errors::literal_entry("kind", &json!("x"), KIND_ORDER);
        assert_eq!(
            entry["msg"].as_str(),
            Some("Input should be 'node', 'docker' or 'compose'")
        );
        assert_eq!(
            entry["ctx"]["expected"].as_str(),
            Some("'node', 'docker' or 'compose'")
        );
    }
}
