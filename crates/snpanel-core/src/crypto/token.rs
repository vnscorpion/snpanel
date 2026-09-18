//! JWT issuing and verification, compatible with `python-jose` as used by
//! `backend/app/core/security.py`.
//!
//! Contract C4, and the thing that makes the strangler pattern (plan §9)
//! possible at all: while Rust and Python both serve traffic they share one
//! `SECRET_KEY`, so a token signed by either must verify in the other. If this
//! is wrong, every logged-in session drops the moment a route moves over.
//!
//! Python side:
//! ```python
//! payload = {"sub": subject, "exp": expire, "iat": now,
//!            "jti": secrets.token_urlsafe(32)}
//! payload.update(extra or {})
//! jwt.encode(payload, settings.secret_key, algorithm="HS256")
//! ```

use std::collections::BTreeMap;

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Source: `security.ALGORITHM`.
pub const ALGORITHM: Algorithm = Algorithm::HS256;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token has expired")]
    Expired,
    #[error("token signature is invalid")]
    BadSignature,
    #[error("token is malformed: {0}")]
    Malformed(String),
    #[error("token uses algorithm {0:?}, which is not accepted")]
    BadAlgorithm(String),
}

/// The name of the token-version claim.
///
/// **`tv`, not `token_version`.** `api/auth.py` builds
/// `{"role": user.role, "tv": user.token_version or 0}` and `api/deps.py`
/// reads `payload.get("tv", 0)`. Using the long name would make a
/// Rust-issued token read as version 0 in Python, mismatch the user's real
/// `token_version`, and 401 - every open session dropping the moment a route
/// moved to Rust, which is exactly what C4 exists to prevent.
pub const TOKEN_VERSION_CLAIM: &str = "tv";

/// The impersonation claim. Set only by the impersonate endpoint, which has
/// already checked the caller is an admin; it lets an admin "log in as" a
/// suspended user, so it bypasses the `is_active` check.
pub const IMPERSONATION_CLAIM: &str = "imp";

/// The claims SNPanel puts in an access token.
///
/// `extra` collects everything the Python side merges in via its `extra`
/// argument - `role`, `tv`, and `imp` on an impersonated session - so an
/// unknown claim added by a still-running Python process survives a round
/// trip through Rust instead of being silently dropped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// The **username**, not the id: `create_access_token(user.username, ...)`
    /// and `deps.py` then looks the user up by `User.username == sub`.
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    /// Unique token id; the revocation list is keyed on this.
    pub jti: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Claims {
    /// The username the session belongs to.
    pub fn username(&self) -> &str {
        &self.sub
    }

    /// The token version, which invalidates every existing session for a user
    /// when it is bumped (suspend, password reset, role change - C27).
    ///
    /// Absent is read as 0, matching `payload.get("tv", 0)`, so a token minted
    /// before the claim existed still authenticates a user whose version is 0.
    pub fn token_version(&self) -> i64 {
        self.extra
            .get(TOKEN_VERSION_CLAIM)
            .and_then(Value::as_i64)
            .unwrap_or(0)
    }

    pub fn role(&self) -> Option<&str> {
        self.extra.get("role").and_then(Value::as_str)
    }

    pub fn is_admin(&self) -> bool {
        self.role() == Some("admin")
    }

    /// True on an admin's "log in as" session, which is allowed to target a
    /// suspended user.
    pub fn is_impersonation(&self) -> bool {
        self.extra
            .get(IMPERSONATION_CLAIM)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
}

/// Generate a `jti` the same shape Python's `secrets.token_urlsafe(32)` makes:
/// 32 random bytes, urlsafe-base64, unpadded (43 characters).
pub fn generate_jti() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Mint an access token. `extra` is merged into the payload exactly as the
/// Python `extra` argument is.
pub fn create_access_token(
    secret_key: &str,
    subject: &str,
    extra: BTreeMap<String, Value>,
    expires_minutes: i64,
) -> Result<String, TokenError> {
    let now = chrono_now();
    let claims = Claims {
        sub: subject.to_string(),
        iat: now,
        exp: now + expires_minutes * 60,
        jti: generate_jti(),
        extra,
    };
    encode(
        &Header::new(ALGORITHM),
        &claims,
        &EncodingKey::from_secret(secret_key.as_bytes()),
    )
    .map_err(|e| TokenError::Malformed(e.to_string()))
}

/// Verify and decode.
///
/// Pins the algorithm to HS256. Accepting whatever the header asks for is the
/// classic JWT `alg: none` hole, and python-jose is given an explicit
/// algorithm list on the Python side too.
pub fn decode_access_token(secret_key: &str, token: &str) -> Result<Claims, TokenError> {
    let mut validation = Validation::new(ALGORITHM);
    validation.validate_exp = true;
    // python-jose does not require `aud` or `iss`, and SNPanel sets neither.
    validation.required_spec_claims.clear();
    validation.validate_aud = false;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret_key.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::Expired,
        jsonwebtoken::errors::ErrorKind::InvalidSignature => TokenError::BadSignature,
        jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => {
            TokenError::BadAlgorithm(format!("{:?}", e.kind()))
        }
        other => TokenError::Malformed(format!("{other:?}")),
    })
}

/// Decode without checking `exp`, for inspecting a token that has already
/// expired (the logout path still wants the `jti` so it can be revoked).
pub fn decode_ignoring_expiry(secret_key: &str, token: &str) -> Result<Claims, TokenError> {
    let mut validation = Validation::new(ALGORITHM);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    validation.validate_aud = false;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret_key.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidSignature => TokenError::BadSignature,
        other => TokenError::Malformed(format!("{other:?}")),
    })
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-key-at-least-32-chars-long";

    fn extras() -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert(TOKEN_VERSION_CLAIM.into(), Value::from(3));
        m.insert("role".into(), Value::from("admin"));
        m
    }

    #[test]
    fn round_trips_its_own_token() {
        let token = create_access_token(SECRET, "admin", extras(), 120).unwrap();
        let claims = decode_access_token(SECRET, &token).unwrap();
        assert_eq!(claims.sub, "admin", "sub is the username, not the id");
        assert_eq!(claims.token_version(), 3);
        assert_eq!(claims.role(), Some("admin"));
        assert_eq!(claims.exp - claims.iat, 120 * 60);
    }

    #[test]
    fn a_different_secret_does_not_verify() {
        let token = create_access_token(SECRET, "admin", extras(), 120).unwrap();
        assert!(matches!(
            decode_access_token("another-secret-key-of-sufficient-length", &token),
            Err(TokenError::BadSignature)
        ));
    }

    #[test]
    fn an_expired_token_is_rejected_but_still_readable_for_revocation() {
        let token = create_access_token(SECRET, "admin", extras(), -10).unwrap();
        assert!(matches!(
            decode_access_token(SECRET, &token),
            Err(TokenError::Expired)
        ));
        // Logout must still be able to read the jti off an expired token.
        let claims = decode_ignoring_expiry(SECRET, &token).unwrap();
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn jti_matches_python_token_urlsafe_32() {
        let jti = generate_jti();
        // 32 bytes urlsafe-base64 unpadded is always 43 chars.
        assert_eq!(jti.len(), 43);
        assert!(jti
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(jti, generate_jti(), "jti must be unique per token");
    }

    #[test]
    fn the_token_version_claim_is_tv() {
        // The whole of C4 rests on this name. A rename here silently drops
        // every session the moment a route moves between implementations.
        assert_eq!(TOKEN_VERSION_CLAIM, "tv");

        let token = create_access_token(SECRET, "admin", extras(), 120).unwrap();
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let payload: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(payload["tv"], 3, "the wire name must be tv");
        assert!(
            payload.get("token_version").is_none(),
            "the long name must not appear"
        );
    }

    #[test]
    fn a_missing_token_version_reads_as_zero() {
        // payload.get("tv", 0) on the Python side, so a token minted before
        // the claim existed still authenticates a version-0 user.
        let token = create_access_token(SECRET, "admin", BTreeMap::new(), 120).unwrap();
        let claims = decode_access_token(SECRET, &token).unwrap();
        assert_eq!(claims.token_version(), 0);
        assert!(!claims.is_impersonation());
        assert!(!claims.is_admin());
    }

    #[test]
    fn unknown_claims_survive_a_round_trip() {
        let mut extra = extras();
        extra.insert("some_future_claim".into(), Value::from("keep me"));
        let token = create_access_token(SECRET, "admin", extra, 60).unwrap();
        let claims = decode_access_token(SECRET, &token).unwrap();
        assert_eq!(
            claims
                .extra
                .get("some_future_claim")
                .and_then(Value::as_str),
            Some("keep me")
        );
    }

    #[test]
    fn the_alg_none_trick_does_not_work() {
        // Header {"alg":"none","typ":"JWT"} with our claims and an empty
        // signature. Must be refused rather than trusted.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD
            .encode(br#"{"sub":"1","exp":4102444800,"iat":1700000000,"jti":"x","role":"admin"}"#);
        let forged = format!("{header}.{body}.");
        assert!(decode_access_token(SECRET, &forged).is_err());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for bad in ["", "not.a.token", "a.b.c", "....."] {
            assert!(decode_access_token(SECRET, bad).is_err());
        }
    }
}
