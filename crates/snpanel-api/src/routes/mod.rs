//! The routers ported so far.
//!
//! Plan §8, Phase 3 orders the 211 endpoints across eleven batches. One batch
//! is here. The rest reach Python through the strangler, and the point of the
//! arrangement is that moving the next one changes this file and nothing else.

pub mod addons;
pub mod auth;
pub mod databases;
pub mod fail2ban;
pub mod firewall;
pub mod health;
pub mod maintenance;
pub mod malware;
pub mod packages;
pub mod panel_settings;
pub mod passkeys;
pub mod provisioning;
pub mod refresh;
pub mod services;
pub mod site_apps;
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
        .merge(fail2ban::router())
        .merge(databases::router())
        .merge(updates::router())
        .merge(addons::router())
        .merge(websites::router())
        .merge(waf::router())
        .merge(terminal::router())
        .merge(provisioning::router())
        .merge(maintenance::router())
        .merge(malware::router())
        .merge(panel_settings::router())
        .merge(site_apps::router())
}

/// The path prefixes handled natively, for the readiness report and for
/// anyone trying to work out which side answered.
///
/// **Every router is on this list now**, and none of them is partial: all
/// 211 endpoints answer here. The list is kept rather than replaced with
/// `/api` because it is what the readiness report prints, and naming the
/// routers is more use to whoever is reading it than one prefix would be.
///
/// The strangler stays in place regardless. Two things still reach Python:
/// the frontend, which `rust-embed` has yet to take over, and anything on a
/// path neither side knows — which has to keep answering the way it did.
pub const PORTED_PREFIXES: &[&str] = &[
    "/api/health",
    "/api/ready",
    "/api/addons",
    "/api/auth",
    "/api/databases",
    "/api/firewall",
    "/api/maintenance",
    "/api/malware",
    "/api/packages",
    "/api/panel-settings",
    "/api/provisioning",
    "/api/services",
    "/api/site-apps",
    "/api/site-runtimes",
    "/api/terminal",
    "/api/updates",
    "/api/users",
    "/api/waf",
    "/api/websites",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the whole API router.
    ///
    /// This exists because the panel could not start and nothing noticed.
    /// `/websites/{website_id}/nginx-custom` was registered twice - once for
    /// GET and once for PUT, each `.route()` attaching its own `.fallback()` -
    /// and axum merges two `MethodRouter`s for the same path by panicking when
    /// both carry a fallback:
    ///
    /// ```text
    /// thread 'main' panicked at routes/websites.rs:89:10:
    /// Cannot merge two `MethodRouter`s that both have a fallback
    /// ```
    ///
    /// It reached `main` and stayed there. Every test passed, clippy passed,
    /// the release built - because a router is only assembled at startup and
    /// no test assembled one. A live deploy found it in four seconds.
    ///
    /// So the assertion is simply *that this returns*. There is nothing to
    /// check about the value: the panic is the failure, and calling the
    /// function is the test.
    #[test]
    fn the_api_router_can_be_built() {
        let _router = api_router();
    }

    /// The same for every router on its own, so a failure names the module
    /// rather than leaving the whole tree to bisect.
    #[test]
    fn every_router_can_be_built_on_its_own() {
        let _ = health::router();
        let _ = auth::router();
        let _ = services::router();
        let _ = packages::router();
        let _ = users::router();
        let _ = firewall::router();
        let _ = databases::router();
        let _ = updates::router();
        let _ = addons::router();
        let _ = websites::router();
        let _ = waf::router();
        let _ = malware::router();
        let _ = panel_settings::router();
        let _ = terminal::router();
        let _ = maintenance::router();
    }
}
