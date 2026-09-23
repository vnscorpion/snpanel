//! `snpanel-api` - the panel's HTTP API.
//!
//! Phase 3 of `RUST_MIGRATION_PLAN.md`, using the strangler pattern from §9:
//! this process serves the routes it has ported and forwards the rest to the
//! Python implementation on localhost. Both sides share the SQLite file, Redis
//! and `SECRET_KEY`, so a session works through either.
//!
//! Run it in front of the existing panel:
//!
//! ```text
//! STRANGLER_UPSTREAM=http://127.0.0.1:8000 \
//! DATABASE_URL=sqlite:////opt/snpanel/backend/snpanel.db \
//! SECRET_KEY=... \
//! snpanel-api --listen 127.0.0.1:2223
//! ```
//!
//! With `STRANGLER_UPSTREAM` empty, unported routes 404 instead of proxying,
//! which is the Phase 6 end state.

// A handler that fails returns the response it wants sent, which is how axum
// is meant to be written; `Result<T, Response>` is therefore everywhere and
// `Response` is a large type. Boxing every error path to satisfy the lint
// would add an allocation to the failure of every request and obscure what the
// code does.
#![allow(clippy::result_large_err)]

mod access_log;
mod archive;
mod auth;
mod backup_jobs;
mod backups;
mod clamav;
mod client;
mod cloudflare;
mod compose;
mod cron;
mod da_import;
mod da_jobs;
mod errors;
mod file_jobs;
mod files;
mod helper_socket;
mod listen;
mod malware;
mod malware_jobs;
mod malware_scan;
mod malware_schedule;
mod manual_ssl;
mod mariadb;
mod middleware;
mod panel_urls;
mod php;
mod php_tune;
mod qr;
mod ratelimit;
mod restore;
mod routes;
mod sftp;
mod shell;
mod shlex;
mod site_apps;
mod spa;
mod sso;
mod state;
mod storage;
mod storage_quota;
mod strangler;
mod system;
mod tarfilter;
#[cfg(test)]
mod testenv;
mod tls;
mod updates;
mod waf;
mod wordpress;
mod yaml;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use snpanel_core::config::Settings;
use snpanel_db::Database;

use state::AppState;
use strangler::Upstream;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SNPANEL_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("snpanel-api: {e:#}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let listen = arg_value(&args, "--listen").unwrap_or_else(|| "127.0.0.1:2223".to_string());
    let env_path =
        arg_value(&args, "--env").unwrap_or_else(|| "/opt/snpanel/backend/.env".to_string());

    let settings = Settings::load(Some(std::path::Path::new(&env_path)))?;
    tracing::info!(env = %env_path, "configuration loaded");

    let db = Database::connect(&settings.database_url).await?;
    if !db.looks_like_panel_schema().await? {
        anyhow::bail!(
            "{} does not look like the panel's database (no users/websites table)",
            settings.database_url
        );
    }

    let upstream = if settings.strangler_enabled() {
        let u = Upstream::new(&settings.strangler_upstream);
        // Say so at startup rather than at the first proxied request: an
        // operator who has just swapped the front end wants to know now.
        if u.is_reachable().await {
            tracing::info!(address = u.base(), "strangler upstream is reachable");
        } else {
            tracing::warn!(
                address = u.base(),
                "strangler upstream is NOT reachable; unported routes will 502"
            );
        }
        Some(u)
    } else {
        tracing::info!("no strangler upstream: unported routes will 404");
        None
    };

    let rate_limiter = Arc::new(ratelimit::RateLimiter::new(
        settings.rate_limit_backend,
        &settings.redis_url,
    ));

    let tls = tls_config(&settings)?;

    let state = AppState {
        settings: Arc::new(settings),
        db,
        rate_limiter,
        upstream,
        serves_tls: tls.is_some(),
    };

    let app = build_router(state);
    let addr: SocketAddr = listen.parse()?;

    // `into_make_service_with_connect_info` is what puts the peer address in
    // the request extensions. Without it every request looks like it came from
    // nowhere, the rate limiter collapses onto one key, and the audit log
    // records no IP at all.
    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    // Source: `dual_stack_socket` in `serve.py`. One socket for both
    // families when IPv6 is on, and an ordinary IPv4 bind when it is not or
    // when the machine cannot give us one — see `listen` for why every
    // failure lands there rather than propagating.
    let dual = listen::dual_stack(addr.port(), system::ipv6_enabled());
    let dual = match dual {
        Ok(listener) => {
            tracing::info!(port = addr.port(), "listening on IPv4 and IPv6");
            Some(listener)
        }
        Err(reason) => {
            if let Some(message) = reason.message() {
                tracing::warn!("{message}");
            }
            None
        }
    };

    match tls {
        Some(config) => {
            tracing::info!(%addr, "listening with TLS");
            // axum-server rather than axum::serve: the handshake needs a
            // certificate chosen per connection, which `axum::serve` has no
            // place to put.
            match dual {
                Some(listener) => {
                    axum_server::from_tcp_rustls(listener, config)
                        .serve(service)
                        .await?;
                }
                None => {
                    axum_server::bind_rustls(addr, config)
                        .serve(service)
                        .await?;
                }
            }
        }
        None => {
            let listener = match dual {
                // `axum::serve` wants a tokio listener, and a tokio listener
                // wants a non-blocking descriptor. `from_std` does not set
                // that for us, and a blocking accept inside the runtime
                // stalls every other task on the thread.
                Some(std_listener) => {
                    std_listener.set_nonblocking(true)?;
                    tokio::net::TcpListener::from_std(std_listener)?
                }
                None => tokio::net::TcpListener::bind(addr).await?,
            };
            tracing::info!(%addr, "listening without TLS");
            axum::serve(listener, service)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }
    Ok(())
}

/// Build the TLS configuration, or `None` to serve plain HTTP.
///
/// Source: `_certificate_pair` in `serve.py` - a certificate is used only when
/// both files are configured *and* present. A missing file is not an error:
/// the panel is served over plain `http://IP:2222` between the installer
/// creating it and certbot issuing anything, and refusing to start there would
/// make the panel unreachable exactly when somebody needs it to finish the
/// install.
fn tls_config(
    settings: &Settings,
) -> anyhow::Result<Option<axum_server::tls_rustls::RustlsConfig>> {
    let cert = settings.panel_ssl_cert.trim();
    let key = settings.panel_ssl_key.trim();
    if cert.is_empty() || key.is_empty() {
        return Ok(None);
    }
    let (cert_path, key_path) = (std::path::Path::new(cert), std::path::Path::new(key));
    if !cert_path.is_file() || !key_path.is_file() {
        tracing::warn!(cert, key, "no usable certificate pair; serving plain HTTP");
        return Ok(None);
    }

    // rustls 0.23 requires a process-wide crypto provider to be chosen.
    // Installing it explicitly rather than relying on a default feature makes
    // the failure a startup error instead of a panic inside a handshake.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a rustls crypto provider was already installed");
    }

    let (default_key, names) = tls::load_certified_key(cert_path, key_path)?;
    tracing::info!(cert, names = ?names, "default panel certificate loaded");

    let sni_dir = settings
        .raw
        .get("PANEL_SNI_DIR")
        .map(String::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(tls::DEFAULT_SNI_DIR)
        .to_string();
    let store = Arc::new(tls::SniStore::new(&sni_dir, Some(default_key)));
    tracing::info!(
        directory = %sni_dir,
        hostnames = store.hostnames().len(),
        "panel serves extra hostnames from their own certificates"
    );

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(store);
    // The frontend is served over HTTP/1.1 and the proxy speaks it upstream;
    // advertising h2 without serving it is how a browser ends up with a
    // connection neither side can use.
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Some(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    )))
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .nest("/api", routes::api_router())
        // Anything not matched above: proxy it, or 404 once there is nothing
        // left to proxy to.
        .fallback(fallback)
        // Applied outermost-first, so the order here mirrors `main.py`, where
        // `slide_session` is registered before `security_headers` and
        // therefore wraps it.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::slide_session,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::security_headers,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Unported routes.
///
/// A 404 here would be wrong while Python is still serving: the route exists,
/// it is simply not this process's job yet.
///
/// Also used as a *method* fallback by partially-ported routers: a path where
/// `GET` is ported and `DELETE` is not would otherwise answer 405 to the
/// delete instead of letting Python handle it.
pub(crate) async fn fallback(State(state): State<AppState>, req: Request<Body>) -> Response {
    match state.upstream.clone() {
        // While Python is still there, nothing about this path changes.
        // Serving the frontend from here *as well* would be harmless in
        // principle and is not worth the risk in practice: FastAPI also
        // answers `/docs` and `/openapi.json`, and a catch-all on this side
        // would start returning `index.html` for them.
        Some(upstream) => strangler::proxy(State(upstream), req).await,
        // Nothing left to proxy to. This is the Stage G state, and the
        // panel has to serve its own frontend or answer 404 at `/`.
        None => serve_frontend(&state, req).await,
    }
}

/// Source: `main.py`'s `favicon`, `brand_asset` and `serve_spa`, which are
/// the whole of what Python answers outside `/api`.
async fn serve_frontend(state: &AppState, req: Request<Body>) -> Response {
    let path = req.uri().path().trim_start_matches('/').to_string();
    let data_dir = spa::brand_assets_dir(&std::path::PathBuf::from(
        std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()),
    ));

    // `/favicon.png` - the operator's upload if there is one, then the
    // build's own.
    if path == "favicon.png" {
        let custom = crate::routes::panel_settings::favicon_filename();
        if let Some(name) = custom.as_deref().and_then(spa::safe_asset_name) {
            if let Some(response) = send_asset(&data_dir.join(name), spa::media_type(name)) {
                return response;
            }
        }
    }

    if let Some(name) = path.strip_prefix("brand-assets/") {
        let Some(name) = spa::safe_asset_name(name) else {
            return not_found();
        };
        return send_asset(&data_dir.join(name), spa::media_type(name)).unwrap_or_else(not_found);
    }

    let dist = std::path::PathBuf::from(&state.settings.frontend_dist);
    match spa::route(&dist, &path) {
        spa::Spa::File(file) => send_file(&file),
        spa::Spa::Index => send_file(&dist.join("index.html")),
        spa::Spa::NotFound => not_found(),
    }
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({ "detail": "Not Found" })),
    )
        .into_response()
}

/// A brand asset, with the revalidation header Python sends.
fn send_asset(path: &std::path::Path, media_type: Option<&'static str>) -> Option<Response> {
    let media_type = media_type?;
    let bytes = std::fs::read(path).ok()?;
    Some(
        (
            [
                (axum::http::header::CONTENT_TYPE, media_type),
                (axum::http::header::CACHE_CONTROL, spa::REVALIDATE),
            ],
            bytes,
        )
            .into_response(),
    )
}

fn send_file(path: &std::path::Path) -> Response {
    let Ok(bytes) = std::fs::read(path) else {
        return not_found();
    };
    let media_type = spa::frontend_media_type(path);
    ([(axum::http::header::CONTENT_TYPE, media_type)], bytes).into_response()
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == flag)?;
    args.get(idx + 1).cloned()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_read_by_name() {
        let args: Vec<String> = ["--listen", "0.0.0.0:2223", "--env", "/tmp/.env"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            arg_value(&args, "--listen").as_deref(),
            Some("0.0.0.0:2223")
        );
        assert_eq!(arg_value(&args, "--env").as_deref(), Some("/tmp/.env"));
        assert!(arg_value(&args, "--absent").is_none());
    }

    #[test]
    fn a_flag_with_no_value_is_none_rather_than_a_panic() {
        let args = vec!["--listen".to_string()];
        assert!(arg_value(&args, "--listen").is_none());
    }
}
