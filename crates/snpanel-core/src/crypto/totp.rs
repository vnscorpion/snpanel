//! TOTP, compatible with `pyotp` as used by `backend/app/api/auth.py`.
//!
//! Contract C6: a secret already enrolled in someone's authenticator app must
//! keep producing accepted codes. Getting this wrong locks every 2FA user out
//! of their own panel, and the recovery path for that is a support ticket per
//! user.
//!
//! pyotp defaults, which are what the panel relies on: SHA-1, 6 digits, a
//! 30-second step, counted from the Unix epoch.

use totp_rs::{Algorithm, Secret, TOTP};

/// Source: pyotp defaults.
pub const DIGITS: usize = 6;
pub const PERIOD: u64 = 30;
pub const ALGORITHM: Algorithm = Algorithm::SHA1;

/// How many steps either side of now are accepted.
///
/// `totp-rs` checks now-1, now and now+1 via `check`, i.e. a skew of one step.
/// pyotp's `verify(code, valid_window=1)` is the same window; the auth router
/// uses the default `valid_window=0`, so we verify the exact step and expose
/// the tolerant form separately.
pub const DEFAULT_SKEW: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("TOTP secret is not valid base32")]
    BadSecret,
    #[error("could not build a TOTP generator: {0}")]
    Build(String),
}

fn generator(
    secret_base32: &str,
    issuer: Option<String>,
    account: String,
) -> Result<TOTP, TotpError> {
    let bytes = Secret::Encoded(secret_base32.trim().to_string())
        .to_bytes()
        .map_err(|_| TotpError::BadSecret)?;
    // `TOTP::new` enforces the RFC 4226 minimum of 128 bits. pyotp does not,
    // and this code's job is to keep reading what pyotp wrote (C6).
    //
    // SNPanel's own enrolments are 160-bit (`pyotp.random_base32()` returns 32
    // base32 characters), so the check would pass for them - but a secret
    // imported from another panel, or issued by an older version, can be
    // shorter. Refusing it here would lock that user out of their own account
    // with no recovery path but a support ticket, which is precisely the
    // failure C6 exists to prevent. New secrets are generated at 160 bits by
    // `generate_secret`, so the weaker ones can only ever be pre-existing.
    Ok(TOTP::new_unchecked(
        ALGORITHM,
        DIGITS,
        DEFAULT_SKEW,
        PERIOD,
        bytes,
        issuer,
        account,
    ))
}

/// The code for a given Unix timestamp. Equivalent to `pyotp.TOTP(s).at(ts)`.
pub fn code_at(secret_base32: &str, timestamp: u64) -> Result<String, TotpError> {
    let totp = generator(secret_base32, None, "snpanel".to_string())?;
    Ok(totp.generate(timestamp))
}

/// Verify a code against the current time, exactly - no skew.
///
/// Matches `pyotp.TOTP.verify(code)` with its default `valid_window=0`, which
/// is what `api/auth.py` calls.
pub fn verify_exact(secret_base32: &str, code: &str, timestamp: u64) -> Result<bool, TotpError> {
    let expected = code_at(secret_base32, timestamp)?;
    Ok(constant_time_eq(
        expected.as_bytes(),
        code.trim().as_bytes(),
    ))
}

/// Verify allowing one step either side, for flows that need to tolerate clock
/// drift. Equivalent to `pyotp.TOTP.verify(code, valid_window=1)`.
pub fn verify_with_skew(
    secret_base32: &str,
    code: &str,
    timestamp: u64,
) -> Result<bool, TotpError> {
    let code = code.trim();
    for step in [-1i64, 0, 1] {
        let ts = (timestamp as i64 + step * PERIOD as i64).max(0) as u64;
        if constant_time_eq(code_at(secret_base32, ts)?.as_bytes(), code.as_bytes()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A fresh random secret, in the base32 form pyotp's `random_base32()` returns.
pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// The `otpauth://` URI encoded into the enrolment QR code.
///
/// Source: `pyotp.TOTP(secret, issuer=X).provisioning_uri(name, issuer_name=X)`.
pub fn provisioning_uri(
    secret_base32: &str,
    account: &str,
    issuer: &str,
) -> Result<String, TotpError> {
    let totp = generator(secret_base32, Some(issuer.to_string()), account.to_string())?;
    Ok(totp.get_url())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The secret from RFC 4226 / the pyotp docs.
    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    #[test]
    fn generates_a_six_digit_code() {
        let code = code_at(SECRET, 1_700_000_000).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn the_code_is_stable_within_one_step_and_changes_across_one() {
        // 1_700_000_010 and 1_700_000_020 are in the same 30s window;
        // 1_700_000_040 is in the next one.
        let a = code_at(SECRET, 1_700_000_010).unwrap();
        let b = code_at(SECRET, 1_700_000_020).unwrap();
        let c = code_at(SECRET, 1_700_000_040).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn verify_exact_accepts_only_the_current_step() {
        let now = 1_700_000_000;
        let code = code_at(SECRET, now).unwrap();
        assert!(verify_exact(SECRET, &code, now).unwrap());
        // One step earlier is a different code, and the exact form rejects it.
        let previous = code_at(SECRET, now - PERIOD).unwrap();
        if previous != code {
            assert!(!verify_exact(SECRET, &previous, now).unwrap());
        }
    }

    #[test]
    fn verify_with_skew_accepts_the_neighbouring_steps() {
        let now = 1_700_000_000;
        for offset in [-(PERIOD as i64), 0, PERIOD as i64] {
            let ts = (now as i64 + offset) as u64;
            let code = code_at(SECRET, ts).unwrap();
            assert!(
                verify_with_skew(SECRET, &code, now).unwrap(),
                "offset {offset} should be inside the skew window"
            );
        }
        let far = code_at(SECRET, now + 5 * PERIOD).unwrap();
        assert!(!verify_with_skew(SECRET, &far, now).unwrap());
    }

    #[test]
    fn a_bad_secret_is_an_error() {
        assert!(code_at("not base32 at all!!", 0).is_err());
    }

    #[test]
    fn a_short_legacy_secret_still_works() {
        // 80 bits: under the RFC minimum, but pyotp issues and accepts it, so
        // a user enrolled with one must not be locked out.
        let code = code_at(SECRET, 1_700_000_000).unwrap();
        assert_eq!(code.len(), 6);
        assert!(verify_exact(SECRET, &code, 1_700_000_000).unwrap());
    }

    #[test]
    fn new_enrolments_are_full_length() {
        // pyotp.random_base32() is 32 base32 chars = 160 bits.
        assert_eq!(generate_secret().len(), 32);
    }

    #[test]
    fn generated_secrets_work_and_differ() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert_ne!(s1, s2);
        let code = code_at(&s1, 1_700_000_000).unwrap();
        assert!(verify_exact(&s1, &code, 1_700_000_000).unwrap());
    }

    #[test]
    fn provisioning_uri_names_the_issuer() {
        let uri = provisioning_uri(SECRET, "admin", "SNPanel").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=SNPanel"));
        assert!(uri.contains(SECRET));
    }

    #[test]
    fn whitespace_around_a_code_is_tolerated() {
        let now = 1_700_000_000;
        let code = code_at(SECRET, now).unwrap();
        assert!(verify_exact(SECRET, &format!("  {code} "), now).unwrap());
    }
}
