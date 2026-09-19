//! The routers ported so far.
//!
//! Plan §8, Phase 3 orders the 211 endpoints across eleven batches. One batch
//! is here. The rest reach Python through the strangler, and the point of the
//! arrangement is that moving the next one changes this file and nothing else.

pub mod addons;
pub mod auth;
pub mod databases;
pub mod firewall;
pub mod health;
pub mod maintenance;
pub mod malware;
pub mod packages;
pub mod panel_settings;
pub mod services;
pub mod terminal;
pub mod updates;
pub mod users;
pub mod waf;
pub mod websites;

use axum::Router;

use crate::state::AppState;

/// Everything this process serves itself.
///
/// Mounted under `/api`, so the paths match the Python's exactly - NT7 again:
/// no route is renamed on the way across.
pub fn api_router() -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .nest("/auth", auth::router())
        .nest("/services", services::router())
        .merge(packages::router())
        .merge(users::router())
        .merge(firewall::router())
        .merge(databases::router())
        .merge(updates::router())
        .merge(addons::router())
        .merge(websites::router())
        .merge(waf::router())
        .merge(terminal::router())
        .merge(maintenance::router())
        .merge(malware::router())
        .merge(panel_settings::router())
}

/// The path prefixes handled natively, for the readiness report and for
/// anyone trying to work out which side answered.
pub const PORTED_PREFIXES: &[&str] = &[
    "/api/health",
    "/api/ready",
    "/api/addons",
    "/api/auth",
    "/api/packages",
    "/api/panel-settings",
    "/api/services",
    "/api/terminal",
    "/api/updates",
    "/api/waf",
    "/api/firewall",
    "/api/malware",
    // Partially ported: some methods on these paths still reach Python.
    "/api/databases",
    // Partially ported: the file manager's reads. Everything else under
    // /api/maintenance - backups, restore, PHP, cron - still reaches Python.
    "/api/maintenance",
    // Partially ported: some methods on these paths still reach Python.
    "/api/users",
    "/api/websites",
];
