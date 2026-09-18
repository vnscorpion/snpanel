//! What every handler is given.

use std::sync::Arc;

use snpanel_core::config::Settings;
use snpanel_db::Database;

use crate::ratelimit::RateLimiter;
use crate::strangler::Upstream;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub db: Database,
    /// Shared: the login counters are process-wide when the backend is memory,
    /// and the Redis client behind it is pooled. A limiter per handler would
    /// mean no limit at all.
    pub rate_limiter: Arc<RateLimiter>,
    /// True when this process terminates TLS itself.
    ///
    /// Python reads `request.url.scheme`, which uvicorn sets to `https` when
    /// it holds the certificate. Rust has no equivalent on the request - the
    /// URI of a server-side request carries no scheme - so the fact is carried
    /// here instead. Getting it wrong is not cosmetic: it decides whether the
    /// session and CSRF cookies are marked `Secure`, and an unmarked cookie
    /// will be sent over plain HTTP by any browser that can be talked into
    /// making the request.
    pub serves_tls: bool,
    /// Present while any route is still served by Python. Absent means this
    /// process is the whole panel, which is the Phase 6 end state.
    pub upstream: Option<Upstream>,
}

impl AppState {
    pub fn strangling(&self) -> bool {
        self.upstream.is_some()
    }
}
