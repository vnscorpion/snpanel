//! `/api/updates` - ported from `api/updates.py`.
//!
//! Four admin-only endpoints. Three of them return the helper's raw
//! `CommandResult`; `status` folds in the panel's release check and the tail
//! of the last update's log, because the Updates page asks once and renders
//! everything.
//!
//! Every one uses `check=False`, so a helper that fails is *reported* rather
//! than raised - an administrator looking at the Updates page needs to see why
//! the update did not start, not a 500.

use axum::extract::{Query, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use std::collections::HashMap;

use crate::auth::CurrentUser;
use crate::errors::{internal_error, not_enough_permissions};
use crate::state::AppState;
use crate::{shell, updates};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/updates/status", get(status))
        .route("/updates/os/run", post(run_os_update))
        .route("/updates/os/auto", post(configure_os_auto_update))
        .route("/updates/panel/run", post(run_panel_update))
}

fn require_admin(current: &CurrentUser) -> Result<(), Response> {
    if permissions::has_role(&current.user.role, Role::Admin) {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

async fn status(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }
    // Source: `refresh: bool = Query(default=False)`. FastAPI accepts the
    // usual spellings for a boolean query parameter.
    let refresh = params
        .get("refresh")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    let result = shell::privileged(
        state.settings.command_dry_run,
        "updates-status",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "apt list --upgradable 2>/dev/null | head -40",
        ]),
    )
    .await;

    // The git check and the log read are both blocking and both talk to the
    // outside world, so they run off the async runtime.
    let version = updates::app_version();
    let (panel, log) = match tokio::task::spawn_blocking(move || {
        (
            updates::panel_release_status(&version, refresh),
            updates::panel_update_log(),
        )
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("the update status check panicked: {e}");
            return internal_error();
        }
    };

    let mut body = result.to_json();
    body["panel"] = panel;
    body["panel_update_log"] = json!(log);
    axum::Json(body).into_response()
}

async fn admin_only(state: &AppState, req: Request) -> Result<(), Response> {
    let (mut parts, _) = req.into_parts();
    let current = CurrentUser::from_parts(&mut parts, state).await?;
    require_admin(&current)
}

async fn run_os_update(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = admin_only(&state, req).await {
        return r;
    }
    let result = shell::privileged(
        state.settings.command_dry_run,
        "updates-os-run",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "nohup bash -lc 'apt-get update && apt-get upgrade -y' \
             >/tmp/snpanel-os-update.log 2>&1 & \
             echo OS update started in background. Log: /tmp/snpanel-os-update.log",
        ]),
    )
    .await;
    axum::Json(result.to_json()).into_response()
}

async fn configure_os_auto_update(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&current) {
        return r;
    }
    let payload = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    // Source: `SystemAutoUpdateConfig`, every field of which has a **default**:
    //
    //     enabled: bool = True
    //     mode: Literal["security", "all"] = "security"
    //     auto_reboot: bool = False
    //
    // So `{}` is a valid body that turns security updates on. Reading the
    // service's `ValueError` and assuming the fields were required produced a
    // 422 where the panel answers 200 - an administrator's "enable automatic
    // security updates" button doing nothing. The schema is the contract, not
    // the guard behind it.
    let enabled = match payload.get("enabled") {
        Some(Value::Bool(b)) => *b,
        None | Some(Value::Null) => true,
        Some(other) => return crate::errors::bool_parsing("enabled", other),
    };
    let auto_reboot = match payload.get("auto_reboot") {
        Some(Value::Bool(b)) => *b,
        None | Some(Value::Null) => false,
        Some(other) => return crate::errors::bool_parsing("auto_reboot", other),
    };
    let mode = match payload.get("mode") {
        Some(Value::String(s)) => s.clone(),
        None | Some(Value::Null) => "security".to_string(),
        Some(other) => return crate::errors::string_type("mode", other),
    };

    // A `Literal` field, so an unknown mode is a 422 from Pydantic and the
    // service's own ValueError is unreachable. It answered 500 here until the
    // shadow diff put the two side by side.
    if !updates::valid_auto_update_mode(&mode) {
        return crate::errors::validation_error(vec![json!({
            "type": "literal_error",
            "loc": ["body", "mode"],
            "msg": "Input should be 'security' or 'all'",
            "input": mode,
            "ctx": { "expected": "'security' or 'all'" },
        })]);
    }

    let on_off = |v: bool| if v { "on" } else { "off" };
    let result = shell::privileged(
        state.settings.command_dry_run,
        "updates-os-auto",
        &[on_off(enabled), &mode, on_off(auto_reboot)],
        None,
        Some(&[
            "bash",
            "-lc",
            "echo unattended-upgrades helper is not installed",
        ]),
    )
    .await;
    axum::Json(result.to_json()).into_response()
}

async fn run_panel_update(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = admin_only(&state, req).await {
        return r;
    }

    // Marked before the helper runs: a page refreshed while the update is
    // starting shows "checking" rather than the previous run's result.
    let _ = tokio::task::spawn_blocking(updates::mark_panel_update_starting).await;

    let result = shell::privileged(
        state.settings.command_dry_run,
        "updates-panel-run",
        &[],
        None,
        Some(&["bash", "installer/update.sh"]),
    )
    .await;

    if !result.ok() {
        let message = result.failure_detail("Panel update could not be started");
        let _ =
            tokio::task::spawn_blocking(move || updates::mark_panel_update_failed(&message)).await;
    }
    axum::Json(result.to_json()).into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_refresh_flag_accepts_the_spellings_fastapi_accepts() {
        for yes in ["1", "true", "yes", "on", "True"] {
            assert!(
                matches!(yes.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
                "{yes}"
            );
        }
        for no in ["0", "false", "no", "off", ""] {
            assert!(
                !matches!(no.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
                "{no}"
            );
        }
    }
}
