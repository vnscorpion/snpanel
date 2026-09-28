//! `/api/hosting/web` - not in the Python: LiteSpeed and its Apache standby
//! on the Hosting Edition (`docs/hosting/UPGRADE-PLAN.md` §5 C).
//!
//! Which server answers 80/443, the last failover, switching back, restarting
//! LiteSpeed and a new WebAdmin password. Administrators only; a 409 where
//! LiteSpeed is not installed, which the frontend reads as "no such feature".

use axum::extract::State;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_ipc::WebServer;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, error, not_enough_permissions};
use crate::state::AppState;

const LSWS_CTRL: &str = "/usr/local/lsws/bin/lswsctrl";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/hosting/web", get(read).fallback(crate::fallback))
        .route(
            "/hosting/web/switch",
            post(switch).fallback(crate::fallback),
        )
        .route(
            "/hosting/lsws/restart",
            post(restart).fallback(crate::fallback),
        )
        .route(
            "/hosting/lsws/admin-password",
            post(admin_password).fallback(crate::fallback),
        )
}

async fn admit(state: &AppState, parts: &mut Parts) -> Result<CurrentUser, Response> {
    let current = CurrentUser::from_parts(parts, state).await?;
    if !permissions::has_role(&current.user.role, Role::Admin) {
        return Err(not_enough_permissions());
    }
    if !std::path::Path::new(LSWS_CTRL).exists() {
        return Err(crate::errors::conflict(
            "LiteSpeed Enterprise is not installed on this server.",
        ));
    }
    Ok(current)
}

/// The helper's answer, or a 400 carrying what it said.
fn checked(result: crate::shell::CommandResult, what: &str) -> Result<String, Response> {
    if result.ok() {
        Ok(result.stdout)
    } else {
        Err(bad_request(result.failure_detail(what).trim()))
    }
}

async fn status(state: &AppState) -> Response {
    match checked(
        crate::shell::privileged(
            state.settings.command_dry_run,
            "web-status",
            &[],
            None,
            None,
        )
        .await,
        "Could not read the web server status",
    ) {
        Ok(out) => match serde_json::from_str::<Value>(out.trim()) {
            Ok(v) => axum::Json(v).into_response(),
            Err(_) => error(StatusCode::BAD_GATEWAY, "Unreadable web server status"),
        },
        Err(r) => r,
    }
}

async fn read(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, _) = req.into_parts();
    if let Err(r) = admit(&state, &mut parts).await {
        return r;
    }
    status(&state).await
}

async fn switch(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let body = match super::auth::read_json_body(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let to = match body.get("to").and_then(Value::as_str).map(WebServer::parse) {
        Some(Ok(to)) => to,
        Some(Err(m)) => return error(StatusCode::UNPROCESSABLE_ENTITY, &m),
        None => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "to must be \"lsws\" or \"apache\"",
            )
        }
    };
    if let Err(r) = checked(
        crate::shell::privileged(
            state.settings.command_dry_run,
            "web-switch",
            &[to.as_str()],
            None,
            None,
        )
        .await,
        "Could not switch the web server",
    ) {
        return r;
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "web_switch",
        "web",
        to.as_str(),
    )
    .await;
    status(&state).await
}

async fn restart(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = checked(
        crate::shell::privileged(
            state.settings.command_dry_run,
            "lsws-restart",
            &[],
            None,
            None,
        )
        .await,
        "Could not restart LiteSpeed",
    ) {
        return r;
    }
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "lsws_restart",
        "lshttpd",
        "",
    )
    .await;
    // A graceful restart takes a moment before LiteSpeed answers again.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    status(&state).await
}

/// A new WebAdmin password, shown once and never stored by the panel.
async fn admin_password(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match admit(&state, &mut parts).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let out = match checked(
        crate::shell::privileged(
            state.settings.command_dry_run,
            "lsws-admin-password",
            &[],
            None,
            None,
        )
        .await,
        "Could not set the WebAdmin password",
    ) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Ok(v) = serde_json::from_str::<Value>(out.trim()) else {
        return error(StatusCode::BAD_GATEWAY, "Unreadable answer from the helper");
    };
    // The audit entry says that it happened, not what the password is.
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "lsws_admin_password",
        "webadmin",
        "",
    )
    .await;
    let mut resp = axum::Json(json!({
        "username": v["username"],
        "password": v["password"],
    }))
    .into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    resp
}
