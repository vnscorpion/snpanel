//! `/api/hosting/lve` - not in the Python: CloudLinux LVE limits for the
//! Hosting Edition (`docs/hosting/UPGRADE-PLAN.md` §5 D).
//!
//! Administrators only, and only on a CloudLinux server with the LVE module
//! loaded - a 409 otherwise, like the addons', which says the feature is not
//! on this server rather than that the caller may not use it. The frontend
//! uses exactly that to decide whether to show the page.

use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_core::PanelUsername;
use snpanel_ipc::LveLimits;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, not_enough_permissions, not_found};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/hosting/lve", get(read).fallback(crate::fallback))
        .route(
            "/hosting/lve/default",
            put(set_default).fallback(crate::fallback),
        )
        .route(
            "/hosting/lve/users/{username}",
            put(set_user).delete(reset_user).fallback(crate::fallback),
        )
}

/// The caller, when it is an administrator and LVE is running here.
async fn admit(state: &AppState, parts: &mut Parts) -> Result<CurrentUser, Response> {
    let current = CurrentUser::from_parts(parts, state).await?;
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return Err(not_enough_permissions());
    }
    match snpanel_osabi::hosting::cloudlinux() {
        Some(cl) if cl.lve_loaded => Ok(current),
        Some(_) => Err(crate::errors::conflict(
            "CloudLinux is installed but LVE is not active yet. Reboot the server to finish the conversion.",
        )),
        None => Err(crate::errors::conflict(
            "LVE limits need CloudLinux. Run `snpanel upgrade cloudlinux` on this server first.",
        )),
    }
}

/// The six limits out of a request body, all required, as whole numbers.
fn parse_limits(body: &Value) -> Result<LveLimits, String> {
    let field = |name: &str| -> Result<u32, String> {
        body.get(name)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| format!("{name} must be a whole number"))
    };
    let limits = LveLimits {
        speed_percent: field("speed_percent")?,
        pmem_mb: field("pmem_mb")?,
        ep: field("ep")?,
        nproc: field("nproc")?,
        io_kbps: field("io_kbps")?,
        iops: field("iops")?,
    };
    limits.validate()?;
    Ok(limits)
}

/// The helper's `lve-status` as JSON.
async fn status(state: &AppState) -> Result<Value, Response> {
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "lve-status",
        &[],
        None,
        None,
    )
    .await;
    if !result.ok() {
        return Err(helper_error(
            &result.failure_detail("Could not read LVE limits"),
        ));
    }
    Ok(serde_json::from_str::<Value>(result.stdout.trim())
        .unwrap_or_else(|_| json!({ "default": null, "users": [] })))
}

fn helper_error(detail: &str) -> Response {
    let detail = detail.trim();
    if detail.contains("No such user") {
        not_found("That user has no LVE on this server")
    } else {
        bad_request(detail)
    }
}

fn numbers(l: &LveLimits) -> [String; 6] {
    [
        l.speed_percent.to_string(),
        l.pmem_mb.to_string(),
        l.ep.to_string(),
        l.nproc.to_string(),
        l.io_kbps.to_string(),
        l.iops.to_string(),
    ]
}

async fn read(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, _) = req.into_parts();
    if let Err(r) = admit(&state, &mut parts).await {
        return r;
    }
    match status(&state).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}

/// Read the body into limits, answering 422 on anything malformed.
async fn body_limits(body: axum::body::Body) -> Result<LveLimits, Response> {
    let body = super::auth::read_json_body(body).await?;
    parse_limits(&body).map_err(|m| error(StatusCode::UNPROCESSABLE_ENTITY, &m))
}

async fn set_default(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let limits = match body_limits(body).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let n = numbers(&limits);
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "lve-set",
        &["default", &n[0], &n[1], &n[2], &n[3], &n[4], &n[5]],
        None,
        None,
    )
    .await;
    if !result.ok() {
        return helper_error(&result.failure_detail("Could not set the default LVE limits"));
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "lve_default_set",
        "lve",
        &json!(limits).to_string(),
    )
    .await;
    match status(&state).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}

async fn set_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let user = match PanelUsername::parse(&username) {
        Ok(u) => u,
        Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
    };
    let limits = match body_limits(body).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    let n = numbers(&limits);
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "lve-set",
        &[user.as_str(), &n[0], &n[1], &n[2], &n[3], &n[4], &n[5]],
        None,
        None,
    )
    .await;
    if !result.ok() {
        return helper_error(&result.failure_detail("Could not set the LVE limits"));
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "lve_user_set",
        user.as_str(),
        &json!(limits).to_string(),
    )
    .await;
    match status(&state).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}

async fn reset_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let user = match PanelUsername::parse(&username) {
        Ok(u) => u,
        Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
    };
    let result = crate::shell::privileged(
        state.settings.command_dry_run,
        "lve-reset",
        &[user.as_str()],
        None,
        None,
    )
    .await;
    if !result.ok() {
        return helper_error(&result.failure_detail("Could not reset the LVE limits"));
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "lve_user_reset",
        user.as_str(),
        "default",
    )
    .await;
    match status(&state).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_read_as_whole_numbers_and_range_checked() {
        let ok = json!({"speed_percent":100,"pmem_mb":1024,"ep":20,"nproc":100,"io_kbps":1024,"iops":1024});
        assert_eq!(parse_limits(&ok).unwrap().pmem_mb, 1024);

        let missing = json!({"speed_percent":100});
        assert!(parse_limits(&missing).unwrap_err().starts_with("pmem_mb"));

        let text = json!({"speed_percent":"100","pmem_mb":1024,"ep":20,"nproc":100,"io_kbps":1024,"iops":1024});
        assert!(parse_limits(&text)
            .unwrap_err()
            .starts_with("speed_percent"));

        let fractional = json!({"speed_percent":100,"pmem_mb":1024.5,"ep":20,"nproc":100,"io_kbps":1024,"iops":1024});
        assert!(parse_limits(&fractional).is_err());

        let too_small = json!({"speed_percent":100,"pmem_mb":16,"ep":20,"nproc":100,"io_kbps":1024,"iops":1024});
        assert!(parse_limits(&too_small).unwrap_err().starts_with("pmem_mb"));

        let negative = json!({"speed_percent":-1,"pmem_mb":1024,"ep":20,"nproc":100,"io_kbps":1024,"iops":1024});
        assert!(parse_limits(&negative).is_err());
    }
}
