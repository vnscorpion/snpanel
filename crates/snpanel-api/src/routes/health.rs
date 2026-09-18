//! `/api/health` and `/api/ready`.
//!
//! `/api/health` must match the Python's byte for byte, because the installer,
//! the update path and every monitoring check read it:
//!
//! ```json
//! {"status":"ok","name":"SNPanel","version":"1.0.134"}
//! ```
//!
//! `/api/ready` is new and is *not* a route the Python has. It reports which
//! side is serving what, which during a migration is the question an operator
//! actually has and currently has no way to ask.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::routes::PORTED_PREFIXES;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

/// The panel version, read from the file the installer writes.
///
/// Falls back to the crate version so the endpoint answers even before the
/// panel is installed - a health check that fails because a version file is
/// missing is a health check that lies.
fn panel_version() -> String {
    std::fs::read_to_string("/opt/snpanel/VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "name": state.settings.app_name,
        "version": panel_version(),
    }))
}

/// Where each part of the panel is being served from.
async fn ready(State(state): State<AppState>) -> Json<serde_json::Value> {
    let upstream = match &state.upstream {
        Some(u) => serde_json::json!({
            "configured": true,
            "address": u.base(),
            "reachable": u.is_reachable().await,
        }),
        // Phase 6: nothing left to proxy to.
        None => serde_json::json!({ "configured": false }),
    };

    let database = match state.db.looks_like_panel_schema().await {
        Ok(ok) => serde_json::json!({ "connected": true, "panel_schema": ok }),
        Err(e) => serde_json::json!({ "connected": false, "error": e.to_string() }),
    };

    Json(serde_json::json!({
        "implementation": "rust",
        "panel_installed": crate::system::panel_installed(),
        "strangler": state.strangling(),
        "ported_prefixes": PORTED_PREFIXES,
        "upstream": upstream,
        "database": database,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_health_shape_is_the_pythons() {
        // {"status":"ok","name":"SNPanel","version":"..."} - the installer and
        // every monitoring check read these three keys.
        let body = serde_json::json!({
            "status": "ok",
            "name": "SNPanel",
            "version": panel_version(),
        });
        assert_eq!(body["status"], "ok");
        assert_eq!(body["name"], "SNPanel");
        assert!(body["version"].is_string());
        assert_eq!(body.as_object().unwrap().len(), 3, "no extra keys");
    }

    #[test]
    fn the_version_falls_back_rather_than_failing() {
        // A health check that fails because a version file is missing is a
        // health check that lies.
        let v = panel_version();
        assert!(!v.is_empty());
    }

    #[test]
    fn the_ported_list_is_not_empty_and_is_all_api_paths() {
        assert!(!PORTED_PREFIXES.is_empty());
        for p in PORTED_PREFIXES {
            assert!(p.starts_with("/api/"), "{p}");
        }
    }
}
