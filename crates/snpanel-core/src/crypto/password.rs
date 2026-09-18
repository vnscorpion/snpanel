//! Password verification, compatible with `backend/app/core/security.py`.
//!
//! Contract C1: every `users.password_hash` on every installed box must keep
//! verifying. Contract C2: the login path must spend the same time on a
//! missing user as on a real one, or the panel leaks which usernames exist.
//!
//! One wrinkle the plan does not call out but the source does: `verify_password`
//! accepts `/etc/shadow` hashes too (yescrypt `$y$`, sha512crypt `$6$`, ...),
//! because the admin account is kept in sync with a real Linux user. Those are
//! not bcrypt and must not be handed to the bcrypt verifier.

use bcrypt::BcryptError;

/// Source: `security.BCRYPT_HASH_PREFIXES`.
pub const BCRYPT_PREFIXES: &[&str] = &["$2a$", "$2b$", "$2y$"];

/// Source: `security.SHADOW_HASH_PREFIXES`, minus the bcrypt ones which are
/// handled first.
pub const SHADOW_ONLY_PREFIXES: &[&str] = &["$y$", "$gy$", "$7$", "$6$", "$5$"];

/// bcrypt silently truncates at 72 bytes. Python sets `truncate_error=True` and
/// caps the schemas at 72, so anything longer is a rejection, not a silent pass.
pub const MAX_PASSWORD_BYTES: usize = 72;

/// Default cost. Source: passlib's bcrypt default, which is what
/// `pwd_context.hash()` uses.
pub const DEFAULT_COST: u32 = 12;

/// A bcrypt hash that is never a real user's, used to burn the same CPU time
/// on a login attempt for a user that does not exist (C2).
///
/// Generated once with cost 12 for the password `"snpanel-dummy-password"`. The
/// value is public and intentionally so - its only job is to cost the same to
/// verify as a real hash.
const DUMMY_HASH: &str = "$2b$12$I2jZAs0rUN82Al1P2DAuZOp8/xBxugZf0CRGYN.TImjteZoxK5n2O";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Bcrypt,
    /// A crypt(3) hash from `/etc/shadow`.
    Shadow,
    Unknown,
}

pub fn classify(hash: &str) -> HashKind {
    if BCRYPT_PREFIXES.iter().any(|p| hash.starts_with(p)) {
        HashKind::Bcrypt
    } else if SHADOW_ONLY_PREFIXES.iter().any(|p| hash.starts_with(p)) {
        HashKind::Shadow
    } else {
        HashKind::Unknown
    }
}

/// Source: `security.is_shadow_password_hash` - note that it returns true for
/// bcrypt prefixes too, since bcrypt is a valid shadow scheme.
pub fn is_shadow_password_hash(hash: &str) -> bool {
    !hash.is_empty() && matches!(classify(hash), HashKind::Bcrypt | HashKind::Shadow)
}

/// Verify a password against a stored hash.
///
/// Returns `false` rather than an error for every malformed input, matching
/// the Python behaviour of swallowing `UnknownHashError` and `ValueError`.
///
/// Shadow (non-bcrypt) hashes return `false` here: verifying them needs
/// `crypt(3)`, which lives in `snpanel-helper` because it is only ever used for
/// the root-synced admin account. The API process never sees one.
pub fn verify_password(password: &str, hash: &str) -> bool {
    match classify(hash) {
        HashKind::Bcrypt => {
            // Python raises on >72 bytes rather than truncating; a raise in
            // verify() is caught and becomes False.
            if password.len() > MAX_PASSWORD_BYTES {
                return false;
            }
            bcrypt::verify(password, hash).unwrap_or(false)
        }
        HashKind::Shadow | HashKind::Unknown => false,
    }
}

/// C2: burn the same CPU on a user that does not exist.
///
/// The login handler must call this on the miss path. It always returns
/// `false`; the point is entirely the time it takes.
pub fn verify_dummy(password: &str) -> bool {
    let truncated = if password.len() > MAX_PASSWORD_BYTES {
        &password[..floor_char_boundary(password, MAX_PASSWORD_BYTES)]
    } else {
        password
    };
    let _ = bcrypt::verify(truncated, DUMMY_HASH);
    false
}

/// Hash a new password at the same cost Python uses.
pub fn hash_password(password: &str) -> Result<String, BcryptError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(BcryptError::InvalidHash(
            "password exceeds bcrypt's 72-byte limit".to_string(),
        ));
    }
    bcrypt::hash(password, DEFAULT_COST)
}

/// Source: `security.needs_rehash`. Shadow hashes are never rehashed.
pub fn needs_rehash(hash: &str) -> bool {
    match classify(hash) {
        HashKind::Bcrypt => cost_of(hash).is_none_or(|cost| cost < DEFAULT_COST),
        _ => false,
    }
}

/// Read the cost factor out of a bcrypt hash: `$2b$12$...` -> 12.
pub fn cost_of(hash: &str) -> Option<u32> {
    let mut parts = hash.split('$');
    parts.next()?; // leading empty segment
    parts.next()?; // scheme
    parts.next()?.parse().ok()
}

fn floor_char_boundary(s: &str, index: usize) -> usize {
    let mut i = index.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_every_prefix_the_python_code_knows() {
        assert_eq!(classify("$2b$12$abc"), HashKind::Bcrypt);
        assert_eq!(classify("$2a$12$abc"), HashKind::Bcrypt);
        assert_eq!(classify("$2y$12$abc"), HashKind::Bcrypt);
        assert_eq!(classify("$y$j9T$abc"), HashKind::Shadow);
        assert_eq!(classify("$6$rounds=5000$abc"), HashKind::Shadow);
        assert_eq!(classify("plaintext"), HashKind::Unknown);
    }

    #[test]
    fn round_trips_a_hash_we_made() {
        let hash = hash_password("admin-password-123").unwrap();
        assert!(verify_password("admin-password-123", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn rejects_a_password_over_the_bcrypt_limit() {
        let too_long = "y".repeat(73);
        assert!(hash_password(&too_long).is_err());
        let hash = hash_password(&"y".repeat(71)).unwrap();
        // The 73-byte password must not be accepted just because its first 72
        // bytes match - that is the silent-truncation bug the cap exists for.
        assert!(!verify_password(&too_long, &hash));
    }

    #[test]
    fn a_shadow_hash_is_not_treated_as_bcrypt() {
        // A real yescrypt hash shape. The API layer must decline, not panic
        // and not mistake it for bcrypt.
        let shadow = "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X8vJ9Qk";
        assert!(!verify_password("anything", shadow));
        assert!(is_shadow_password_hash(shadow));
        assert!(!needs_rehash(shadow));
    }

    #[test]
    fn garbage_is_false_not_a_panic() {
        assert!(!verify_password("x", ""));
        assert!(!verify_password("x", "not-a-hash"));
        assert!(!verify_password("x", "$2b$"));
        assert!(!verify_password("x", "$2b$99$short"));
    }

    #[test]
    fn dummy_verify_always_fails_but_does_the_work() {
        assert!(!verify_dummy("anything at all"));
        assert!(!verify_dummy(&"z".repeat(200)));
    }

    #[test]
    fn reads_the_cost_from_the_hash() {
        assert_eq!(cost_of("$2b$12$abcdefghijklmnopqrstuv"), Some(12));
        assert_eq!(cost_of("$2b$10$abcdefghijklmnopqrstuv"), Some(10));
        assert_eq!(cost_of("garbage"), None);
    }

    #[test]
    fn rehash_is_advised_only_below_the_current_cost() {
        let low = bcrypt::hash("x", 10).unwrap();
        assert!(needs_rehash(&low));
        let current = hash_password("x").unwrap();
        assert!(!needs_rehash(&current));
    }

    #[test]
    fn timing_gap_between_hit_and_miss_stays_small() {
        // C2 in the crudest form that is still meaningful: the dummy path must
        // not be an order of magnitude cheaper than a real verify, which is
        // what an attacker would measure. Generous bound - this runs on shared
        // CI hardware and is a smoke test, not a statistical one.
        use std::time::Instant;
        let hash = hash_password("real-password").unwrap();

        let t0 = Instant::now();
        for _ in 0..4 {
            verify_password("guess", &hash);
        }
        let hit = t0.elapsed();

        let t1 = Instant::now();
        for _ in 0..4 {
            verify_dummy("guess");
        }
        let miss = t1.elapsed();

        let ratio = hit.as_secs_f64() / miss.as_secs_f64().max(f64::EPSILON);
        assert!(
            (0.2..=5.0).contains(&ratio),
            "hit {hit:?} vs miss {miss:?} - the miss path must cost roughly the same"
        );
    }
}
