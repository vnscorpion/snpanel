//! Login rate limiting and lockout - contract C9.
//!
//! Source: the `_login_*` helpers in `api/auth.py`.
//!
//! Two counters per key, and the difference between them is the whole design:
//!
//! - **attempts** - every login try inside a 60-second window. Eight is the
//!   cap. This is what stops a burst.
//! - **failures** - only failures, inside a 15-minute window. Twenty locks the
//!   key out. This is what stops a slow grind.
//!
//! And two keys per request, treated differently on purpose:
//!
//! - the **client IP** gets both counters, so one source that keeps guessing
//!   is eventually locked out;
//! - the **username** gets the rate limit but **not** the lockout, because an
//!   attacker who knows a username could otherwise lock its owner out of their
//!   own panel by spraying wrong passwords from many addresses. The Python
//!   says so in as many words, and getting this backwards turns a protection
//!   into a denial-of-service tool.
//!
//! **Redis is the production backend**, and the keys below are *the Python's
//! keys*, byte for byte. That is not tidiness: while the strangler is in place
//! a login can be served by either implementation, and a second set of
//! counters under different names would mean eight attempts through Rust plus
//! eight more through Python. The window would silently double.
//!
//! When Redis is unavailable the Python logs a warning and falls back to the
//! in-process counters rather than refusing to authenticate anyone - a Redis
//! outage must not lock every customer out of the panel. Same here.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use snpanel_core::config::RateLimitBackend;

/// Source: `_LOGIN_WINDOW_SECONDS`.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Source: `_LOGIN_MAX_ATTEMPTS`.
pub const MAX_ATTEMPTS: usize = 8;
/// Source: `_LOGIN_LOCKOUT_SECONDS`.
pub const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Source: `_LOGIN_LOCKOUT_THRESHOLD`.
pub const LOCKOUT_THRESHOLD: usize = 20;

/// Source: `_raise_locked` and the "Slow down" branch. The frontend shows this
/// text to the user, so the wording is part of the contract.
pub const LOCKED_DETAIL: &str = "Too many login attempts. Try again later.";
pub const SLOW_DOWN_DETAIL: &str = "Too many login attempts. Slow down.";

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// 429 with a `Retry-After` header, as the Python sets it.
    Refuse {
        detail: &'static str,
        retry_after: u64,
    },
}

impl Decision {
    /// Source: `_raise_locked`, which clamps to at least a second - a
    /// `Retry-After: 0` invites an immediate retry that is refused again.
    pub fn locked(retry_after: u64) -> Self {
        Decision::Refuse {
            detail: LOCKED_DETAIL,
            retry_after: retry_after.max(1),
        }
    }

    pub fn slow_down() -> Self {
        Decision::Refuse {
            detail: SLOW_DOWN_DETAIL,
            retry_after: WINDOW.as_secs(),
        }
    }
}

/// Source: `_rate_limit_key` - `snpanel:login:{kind}:{key}`.
fn redis_key(kind: &str, key: &str) -> String {
    format!("snpanel:login:{kind}:{key}")
}

#[derive(Default)]
struct Counters {
    attempts: VecDeque<Instant>,
    failures: VecDeque<Instant>,
    locked_until: Option<Instant>,
}

pub struct RateLimiter {
    memory: Mutex<HashMap<String, Counters>>,
    redis: Option<redis::Client>,
    backend: RateLimitBackend,
}

impl RateLimiter {
    /// `redis_url` is only dialled when the configured backend is Redis.
    pub fn new(backend: RateLimitBackend, redis_url: &str) -> Self {
        let redis = match backend {
            RateLimitBackend::Redis => match redis::Client::open(redis_url) {
                Ok(c) => Some(c),
                Err(e) => {
                    // Not fatal: the memory backend still protects the login,
                    // and refusing to start would take the panel down over a
                    // malformed URL.
                    tracing::error!("REDIS_URL is not usable ({e}); using in-memory rate limits");
                    None
                }
            },
            RateLimitBackend::Memory => None,
        };
        Self {
            memory: Mutex::new(HashMap::new()),
            redis,
            backend,
        }
    }

    /// Source: `_username_key` - lowercased, and a blank name still gets a
    /// key so it cannot slip past the limiter entirely.
    pub fn username_key(username: &str) -> String {
        let name = username.trim().to_lowercase();
        if name.is_empty() {
            "user:_unknown".to_string()
        } else {
            format!("user:{name}")
        }
    }

    fn using_redis(&self) -> bool {
        self.backend == RateLimitBackend::Redis && self.redis.is_some()
    }

    /// May this key attempt a login?
    pub async fn check(&self, key: &str) -> Decision {
        if self.using_redis() {
            match self.redis_check(key).await {
                Ok(d) => return d,
                Err(e) => self.log_fallback(e),
            }
        }
        self.memory_check(key)
    }

    /// Record a failed attempt. `apply_lockout` is false for the username key.
    pub async fn record_failure(&self, key: &str, apply_lockout: bool) {
        if self.using_redis() {
            match self.redis_record_failure(key, apply_lockout).await {
                Ok(()) => return,
                Err(e) => self.log_fallback(e),
            }
        }
        self.memory_record_failure(key, apply_lockout);
    }

    /// A successful login clears every counter for the key.
    pub async fn record_success(&self, key: &str) {
        if self.using_redis() {
            match self.redis_record_success(key).await {
                Ok(()) => return,
                Err(e) => self.log_fallback(e),
            }
        }
        self.memory_record_success(key);
    }

    fn log_fallback(&self, e: redis::RedisError) {
        // Source: `_log_redis_fallback`. A Redis outage must never block
        // authentication, so this is a warning and the memory backend runs.
        tracing::warn!("Redis unavailable ({e}), falling back to in-memory rate limiter");
    }

    // ---- Redis, using exactly the Python's keys and structures ------------

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection, redis::RedisError> {
        self.redis
            .as_ref()
            .expect("using_redis() checked")
            .get_multiplexed_async_connection()
            .await
    }

    async fn redis_check(&self, key: &str) -> Result<Decision, redis::RedisError> {
        let mut conn = self.conn().await?;
        let lockout_key = redis_key("lockout", key);
        let attempts_key = redis_key("attempts", key);

        let ttl: i64 = redis::cmd("TTL")
            .arg(&lockout_key)
            .query_async(&mut conn)
            .await?;
        if ttl > 0 {
            return Ok(Decision::locked(ttl as u64));
        }

        let now = unix_seconds();
        let (_, attempts): (i64, i64) = redis::pipe()
            .cmd("ZREMRANGEBYSCORE")
            .arg(&attempts_key)
            .arg(0)
            .arg(now - WINDOW.as_secs_f64())
            .cmd("ZCARD")
            .arg(&attempts_key)
            .query_async(&mut conn)
            .await?;

        if attempts >= MAX_ATTEMPTS as i64 {
            return Ok(Decision::slow_down());
        }
        Ok(Decision::Allow)
    }

    async fn redis_record_failure(
        &self,
        key: &str,
        apply_lockout: bool,
    ) -> Result<(), redis::RedisError> {
        let mut conn = self.conn().await?;
        let now = unix_seconds();
        // Source: `f"{now}:{secrets.token_hex(8)}"`. The random half is what
        // keeps two failures in the same instant from collapsing into one
        // member of the sorted set - a ZSET member is unique, so without it a
        // burst would be undercounted.
        let member = format!("{now}:{}", random_hex(8));

        let attempts_key = redis_key("attempts", key);
        let failures_key = redis_key("failures", key);
        let lockout_key = redis_key("lockout", key);

        if !apply_lockout {
            redis::pipe()
                .cmd("ZADD")
                .arg(&attempts_key)
                .arg(now)
                .arg(&member)
                .cmd("EXPIRE")
                .arg(&attempts_key)
                .arg(WINDOW.as_secs())
                .query_async::<()>(&mut conn)
                .await?;
            return Ok(());
        }

        let mut results: Vec<i64> = redis::pipe()
            .cmd("ZADD")
            .arg(&attempts_key)
            .arg(now)
            .arg(&member)
            .cmd("EXPIRE")
            .arg(&attempts_key)
            .arg(WINDOW.as_secs())
            .cmd("ZREMRANGEBYSCORE")
            .arg(&failures_key)
            .arg(0)
            .arg(now - LOCKOUT.as_secs_f64())
            .cmd("ZADD")
            .arg(&failures_key)
            .arg(now)
            .arg(&member)
            .cmd("EXPIRE")
            .arg(&failures_key)
            .arg(LOCKOUT.as_secs())
            .cmd("ZCARD")
            .arg(&failures_key)
            .query_async(&mut conn)
            .await?;

        let failure_count = results.pop().unwrap_or(0);
        if failure_count >= LOCKOUT_THRESHOLD as i64 {
            redis::cmd("SET")
                .arg(&lockout_key)
                .arg("1")
                .arg("EX")
                .arg(LOCKOUT.as_secs())
                .query_async::<()>(&mut conn)
                .await?;
        }
        Ok(())
    }

    async fn redis_record_success(&self, key: &str) -> Result<(), redis::RedisError> {
        let mut conn = self.conn().await?;
        redis::cmd("DEL")
            .arg(redis_key("attempts", key))
            .arg(redis_key("failures", key))
            .arg(redis_key("lockout", key))
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    // ---- The in-process fallback -----------------------------------------

    fn memory_check(&self, key: &str) -> Decision {
        let now = Instant::now();
        let mut map = self.memory.lock().expect("rate limiter mutex");
        let entry = map.entry(key.to_string()).or_default();

        if let Some(until) = entry.locked_until {
            if until > now {
                return Decision::locked((until - now).as_secs());
            }
            entry.locked_until = None;
        }

        prune(&mut entry.attempts, now, WINDOW);
        if entry.attempts.len() >= MAX_ATTEMPTS {
            return Decision::slow_down();
        }
        Decision::Allow
    }

    fn memory_record_failure(&self, key: &str, apply_lockout: bool) {
        let now = Instant::now();
        let mut map = self.memory.lock().expect("rate limiter mutex");
        let entry = map.entry(key.to_string()).or_default();

        entry.attempts.push_back(now);
        // Pruned even when no lockout applies, or the username keys grow
        // without bound - the Python comments on this too.
        prune(&mut entry.attempts, now, WINDOW);
        if !apply_lockout {
            return;
        }

        entry.failures.push_back(now);
        prune(&mut entry.failures, now, LOCKOUT);
        if entry.failures.len() >= LOCKOUT_THRESHOLD {
            entry.locked_until = Some(now + LOCKOUT);
        }
    }

    fn memory_record_success(&self, key: &str) {
        let mut map = self.memory.lock().expect("rate limiter mutex");
        // Source: the three `pop`s - attempts, failures and the lockout all go.
        map.remove(key);
    }
}

fn prune(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = q.front() {
        if now.duration_since(*front) >= window {
            q.pop_front();
        } else {
            break;
        }
    }
}

fn unix_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_limiter() -> RateLimiter {
        RateLimiter::new(RateLimitBackend::Memory, "")
    }

    #[test]
    fn the_thresholds_are_the_pythons() {
        assert_eq!(MAX_ATTEMPTS, 8);
        assert_eq!(WINDOW.as_secs(), 60);
        assert_eq!(LOCKOUT_THRESHOLD, 20);
        assert_eq!(LOCKOUT.as_secs(), 900);
    }

    #[test]
    fn the_redis_keys_are_the_pythons() {
        // Both implementations serve logins during the migration. A different
        // key here means two sets of counters and a window that silently
        // doubles.
        assert_eq!(
            redis_key("attempts", "1.2.3.4"),
            "snpanel:login:attempts:1.2.3.4"
        );
        assert_eq!(
            redis_key("lockout", "user:admin"),
            "snpanel:login:lockout:user:admin"
        );
        assert_eq!(
            redis_key("failures", "unknown"),
            "snpanel:login:failures:unknown"
        );
    }

    #[tokio::test]
    async fn eight_attempts_are_allowed_and_the_ninth_is_not() {
        let rl = memory_limiter();
        for i in 0..MAX_ATTEMPTS {
            assert!(
                matches!(rl.check("ip").await, Decision::Allow),
                "attempt {i}"
            );
            rl.record_failure("ip", true).await;
        }
        assert_eq!(
            rl.check("ip").await,
            Decision::Refuse {
                detail: SLOW_DOWN_DETAIL,
                retry_after: 60
            }
        );
    }

    #[tokio::test]
    async fn twenty_failures_lock_the_key_out() {
        let rl = memory_limiter();
        for _ in 0..LOCKOUT_THRESHOLD {
            rl.record_failure("ip", true).await;
        }
        match rl.check("ip").await {
            Decision::Refuse {
                detail,
                retry_after,
            } => {
                assert_eq!(detail, LOCKED_DETAIL);
                assert!(retry_after > 800, "should be most of 15 minutes");
            }
            other => panic!("expected a lockout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_username_key_is_never_locked_out() {
        // The attack this prevents: knowing a username and spraying wrong
        // passwords from many addresses to lock its owner out of their own
        // panel. The short-window rate limit still applies; the lockout does
        // not, and that asymmetry is the entire point.
        let rl = memory_limiter();
        for _ in 0..(LOCKOUT_THRESHOLD * 3) {
            rl.record_failure("user:admin", false).await;
        }
        match rl.check("user:admin").await {
            Decision::Allow => {}
            Decision::Refuse { detail, .. } => assert_eq!(
                detail, SLOW_DOWN_DETAIL,
                "a username may be rate-limited but never locked out"
            ),
        }
    }

    #[tokio::test]
    async fn a_success_clears_every_counter() {
        let rl = memory_limiter();
        for _ in 0..(LOCKOUT_THRESHOLD - 1) {
            rl.record_failure("ip", true).await;
        }
        rl.record_success("ip").await;
        // One more failure must not tip it over, because the count was reset.
        rl.record_failure("ip", true).await;
        assert!(matches!(rl.check("ip").await, Decision::Allow));
    }

    #[tokio::test]
    async fn a_locked_key_reports_at_least_one_second() {
        // Retry-After: 0 invites an immediate retry that is refused again.
        assert_eq!(
            Decision::locked(0),
            Decision::Refuse {
                detail: LOCKED_DETAIL,
                retry_after: 1
            }
        );
    }

    #[test]
    fn username_keys_are_normalised() {
        assert_eq!(RateLimiter::username_key("Admin"), "user:admin");
        assert_eq!(RateLimiter::username_key("  admin  "), "user:admin");
        assert_eq!(RateLimiter::username_key(""), "user:_unknown");
        assert_eq!(RateLimiter::username_key("   "), "user:_unknown");
    }

    #[tokio::test]
    async fn keys_are_counted_independently() {
        let rl = memory_limiter();
        for _ in 0..MAX_ATTEMPTS {
            rl.record_failure("ip-a", true).await;
        }
        assert!(!matches!(rl.check("ip-a").await, Decision::Allow));
        assert!(
            matches!(rl.check("ip-b").await, Decision::Allow),
            "one address must not affect another"
        );
    }

    #[tokio::test]
    async fn an_unreachable_redis_falls_back_instead_of_refusing_logins() {
        // A Redis outage must not lock every customer out of the panel.
        let rl = RateLimiter::new(RateLimitBackend::Redis, "redis://127.0.0.1:1/0");
        assert!(matches!(rl.check("ip").await, Decision::Allow));
        rl.record_failure("ip", true).await;
        rl.record_success("ip").await;
    }

    #[test]
    fn the_zset_member_is_unique_per_failure() {
        // Without the random half two failures in the same instant collapse
        // into one member and the burst is undercounted.
        assert_ne!(random_hex(8), random_hex(8));
        assert_eq!(random_hex(8).len(), 16);
    }
}
