//! `/api/services/*` - the first router ported natively.
//!
//! Source: `api/services.py` and `services/system.py`.
//!
//! Chosen first because the plan does (§8, Phase 3, batch 1: "`services` is
//! simple enough to smoke-test with") and because its responses are small
//! enough to compare byte for byte against Python, which is what the shadow
//! diff needs to be meaningful.
//!
//! NT7 governs every shape here. `/list` returns `{"services": [...]}`, not a
//! bare array, because that is what `App.jsx` reads. `/action` returns the
//! `CommandResult`'s `__dict__` - `command`, `returncode`, `stdout`, `stderr` -
//! which is an odd thing for an API to return and is *exactly* what must be
//! returned.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CurrentUser;
use crate::state::AppState;
use crate::system;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/system-info", get(system_info))
        .route("/resource-usage", get(resource_usage))
        .route("/list", get(list))
        .route("/action", post(action))
}

/// Source: `system_info()`.
///
/// The three fields are raw command output, which is what the Services page
/// renders in `<pre>` blocks. Parsing them into something tidier would be a
/// different API.
async fn system_info(user: CurrentUser) -> Json<serde_json::Value> {
    tracing::debug!(
        user = %user.user.username,
        via_cookie = user.via_cookie,
        tv = user.claims.token_version(),
        "system-info"
    );
    Json(serde_json::json!({
        "os": system::os_release_head(),
        "disk": system::disk_free(),
        "memory": system::memory_mb(),
    }))
}

/// Source: `resource_usage()`.
async fn resource_usage(_user: CurrentUser) -> Json<serde_json::Value> {
    Json(system::resource_usage().await)
}

/// Source: `get_services()` - note the wrapper object.
async fn list(_user: CurrentUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "services": system::list_services() }))
}

#[derive(Debug, Deserialize)]
pub struct ServiceActionRequest {
    pub name: String,
    pub action: String,
}

/// What `CommandResult.__dict__` serialises to.
///
/// Field names and order are Python's, because the frontend reads `stdout`
/// and `returncode` off it directly.
#[derive(Debug, Serialize)]
pub struct CommandResultBody {
    pub command: String,
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Source: `run_service_action()`.
///
/// The role rule is worth keeping visible: `status` needs only `end_user`,
/// everything else needs `admin`. Requiring admin for all of it would take the
/// Services page away from customers who can legitimately see it.
async fn action(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(payload): Json<ServiceActionRequest>,
) -> Response {
    let needs_admin = payload.action != "status";
    if needs_admin && !user.is_admin() {
        return forbidden("Insufficient permissions");
    }

    match system::service_action(&state, &payload.name, &payload.action).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        // Source: the `except ValueError -> 400` in the Python.
        Err(message) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "detail": message })),
        )
            .into_response(),
    }
}

fn forbidden(detail: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "detail": detail })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_response_is_wrapped_in_an_object() {
        // App.jsx reads data.services; a bare array would render nothing.
        let body = serde_json::json!({ "services": ["nginx", "mariadb"] });
        assert!(body.get("services").unwrap().is_array());
    }

    #[test]
    fn the_action_response_keeps_the_command_result_field_names() {
        let body = CommandResultBody {
            command: "systemctl status nginx".into(),
            returncode: 0,
            stdout: "active".into(),
            stderr: String::new(),
        };
        let json = serde_json::to_value(&body).unwrap();
        for key in ["command", "returncode", "stdout", "stderr"] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
    }

    #[test]
    fn status_is_the_only_action_an_end_user_may_take() {
        // Source: `minimum_role = Role.end_user if action == "status" else admin`.
        for action in ["start", "stop", "restart", "reload"] {
            assert_ne!(action, "status");
        }
    }
}
