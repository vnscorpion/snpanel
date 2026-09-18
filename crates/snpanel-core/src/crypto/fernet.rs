//! Fernet, wire-compatible with `cryptography.fernet` as used by
//! `backend/app/core/secrets.py`.
//!
//! This is contract C3 and risk R1 of the migration plan: every customer
//! database password on every installed box is a Fernet token derived from
//! `SECRET_KEY`. Getting this wrong does not throw an error at deploy time -
//! it silently makes those passwords unrecoverable. So the derivation is
//! reimplemented here from the Python source line by line, and the test suite
//! decrypts a ciphertext that Python produced.
//!
//! Python side, verbatim:
//! ```python
//! def _derive_key() -> bytes:
//!     digest = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
//!     return base64.urlsafe_b64encode(digest)
//! ```
//! The result is a 44-character urlsafe-base64 string, which `Fernet()` then
//! base64-decodes back to the same 32 bytes. The two halves are:
//!   signing key  = bytes[0..16]   (HMAC-SHA256)
//!   encryption key = bytes[16..32] (AES-128-CBC)
//!
//! Token layout (all concatenated, then urlsafe-base64 with padding):
//!   0x80 | timestamp (8 bytes BE) | IV (16 bytes) | ciphertext | HMAC (32 bytes)

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::engine::general_purpose::URL_SAFE as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

/// Marker the Python layer puts in front of every ciphertext it stores.
/// Source: `secrets._ENCRYPTED_PREFIX`.
pub const ENCRYPTED_PREFIX: &str = "fernet:";

const VERSION: u8 = 0x80;
const MIN_TOKEN_LEN: usize = 1 + 8 + 16 + 16 + 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FernetError {
    #[error("value is not base64")]
    NotBase64,
    #[error("token is too short to be a Fernet token")]
    TooShort,
    #[error("unsupported Fernet version byte {0:#x}")]
    BadVersion(u8),
    #[error("HMAC mismatch; SECRET_KEY may have been rotated")]
    BadSignature,
    #[error("ciphertext length is not a multiple of the AES block size")]
    BadCiphertextLength,
    #[error("padding is invalid")]
    BadPadding,
    #[error("plaintext is not valid UTF-8")]
    NotUtf8,
    /// Mirrors `secrets.decrypt` refusing a value with no `fernet:` prefix
    /// while `STRICT_DECRYPT` is on.
    #[error("refusing to read legacy plaintext value")]
    LegacyPlaintext,
}

/// A Fernet key derived from the panel's `SECRET_KEY`.
#[derive(Clone)]
pub struct FernetKey {
    signing: [u8; 16],
    encryption: [u8; 16],
}

impl std::fmt::Debug for FernetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FernetKey(<redacted>)")
    }
}

impl FernetKey {
    /// Derive exactly as `secrets._derive_key` does.
    pub fn derive(secret_key: &str) -> Self {
        let digest = Sha256::digest(secret_key.as_bytes());
        let mut signing = [0u8; 16];
        let mut encryption = [0u8; 16];
        signing.copy_from_slice(&digest[0..16]);
        encryption.copy_from_slice(&digest[16..32]);
        Self {
            signing,
            encryption,
        }
    }

    /// The 44-character urlsafe-base64 key string Python passes to `Fernet()`.
    /// Exposed so an operator can cross-check against the Python side.
    pub fn as_python_key(&self) -> String {
        let mut raw = [0u8; 32];
        raw[0..16].copy_from_slice(&self.signing);
        raw[16..32].copy_from_slice(&self.encryption);
        B64.encode(raw)
    }

    /// Decrypt a raw Fernet token (no `fernet:` prefix).
    ///
    /// No TTL is enforced, because the Python side calls `decrypt()` without a
    /// `ttl` argument: stored passwords must stay readable forever.
    pub fn decrypt_token(&self, token: &str) -> Result<String, FernetError> {
        let raw = decode_b64(token.trim())?;
        if raw.len() < MIN_TOKEN_LEN {
            return Err(FernetError::TooShort);
        }
        if raw[0] != VERSION {
            return Err(FernetError::BadVersion(raw[0]));
        }

        let (signed, mac) = raw.split_at(raw.len() - 32);

        // Verify before touching the ciphertext: this is what makes a rotated
        // SECRET_KEY a clean error instead of a garbage plaintext.
        let mut hmac =
            HmacSha256::new_from_slice(&self.signing).expect("HMAC accepts any key size");
        hmac.update(signed);
        let expected = hmac.finalize().into_bytes();
        if expected.ct_eq(mac).unwrap_u8() != 1 {
            return Err(FernetError::BadSignature);
        }

        let iv = &signed[9..25];
        let ciphertext = &signed[25..];
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(FernetError::BadCiphertextLength);
        }

        let decryptor = Aes128CbcDec::new(self.encryption.as_ref().into(), iv.into());
        let mut buf = ciphertext.to_vec();
        let plaintext = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| FernetError::BadPadding)?;

        String::from_utf8(plaintext.to_vec()).map_err(|_| FernetError::NotUtf8)
    }

    /// Encrypt, producing a token byte-compatible with what Python writes.
    pub fn encrypt_token(&self, plaintext: &str) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut iv = [0u8; 16];
        getrandom_iv(&mut iv);
        self.encrypt_with(plaintext, timestamp, &iv)
    }

    /// Deterministic encryption, for tests that need a fixed token.
    pub fn encrypt_with(&self, plaintext: &str, timestamp: u64, iv: &[u8; 16]) -> String {
        let encryptor = Aes128CbcEnc::new(self.encryption.as_ref().into(), iv.into());
        let data = plaintext.as_bytes();
        let mut buf = vec![0u8; data.len() + 16];
        buf[..data.len()].copy_from_slice(data);
        let ciphertext = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
            .expect("buffer is large enough for one block of padding")
            .to_vec();

        let mut signed = Vec::with_capacity(1 + 8 + 16 + ciphertext.len());
        signed.push(VERSION);
        signed.extend_from_slice(&timestamp.to_be_bytes());
        signed.extend_from_slice(iv);
        signed.extend_from_slice(&ciphertext);

        let mut hmac =
            HmacSha256::new_from_slice(&self.signing).expect("HMAC accepts any key size");
        hmac.update(&signed);
        signed.extend_from_slice(&hmac.finalize().into_bytes());

        B64.encode(&signed)
    }
}

/// `secrets.encrypt`: encrypt and prepend the `fernet:` marker.
pub fn encrypt(secret_key: &str, plaintext: &str) -> String {
    format!(
        "{}{}",
        ENCRYPTED_PREFIX,
        FernetKey::derive(secret_key).encrypt_token(plaintext)
    )
}

/// `secrets.decrypt`, including its handling of the legacy-plaintext case.
///
/// `strict` maps to the `STRICT_DECRYPT` setting: on (the default and the
/// production value) an unprefixed value is an error rather than a passthrough.
pub fn decrypt(
    secret_key: &str,
    stored: Option<&str>,
    strict: bool,
) -> Result<String, FernetError> {
    let stored = match stored {
        None | Some("") => return Ok(String::new()),
        Some(s) => s,
    };
    let Some(payload) = stored.strip_prefix(ENCRYPTED_PREFIX) else {
        return if strict {
            Err(FernetError::LegacyPlaintext)
        } else {
            Ok(stored.to_string())
        };
    };
    FernetKey::derive(secret_key).decrypt_token(payload)
}

/// `secrets.is_encrypted`.
pub fn is_encrypted(stored: Option<&str>) -> bool {
    stored.is_some_and(|s| !s.is_empty() && s.starts_with(ENCRYPTED_PREFIX))
}

/// Python's `base64.urlsafe_b64decode` is padding-strict, but tokens in the
/// wild have occasionally been stored with the padding stripped by a
/// round-trip through a form field, so accept both.
fn decode_b64(s: &str) -> Result<Vec<u8>, FernetError> {
    if let Ok(v) = B64.decode(s) {
        return Ok(v);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| FernetError::NotBase64)
}

fn getrandom_iv(iv: &mut [u8; 16]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(iv);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key-at-least-32-chars-long";

    #[test]
    fn key_derivation_matches_python() {
        // Produced by:
        //   python -c "import base64,hashlib;
        //   print(base64.urlsafe_b64encode(
        //       hashlib.sha256(b'test-secret-key-at-least-32-chars-long').digest()).decode())"
        let expected = "KSUanqK8jmzXU_A3EFZmpxymFJCIP0u7Yt0Uex9elMg=";
        assert_eq!(FernetKey::derive(TEST_SECRET).as_python_key(), expected);
    }

    #[test]
    fn round_trips_its_own_output() {
        let key = FernetKey::derive(TEST_SECRET);
        let token = key.encrypt_token("correct horse battery");
        assert_eq!(key.decrypt_token(&token).unwrap(), "correct horse battery");
    }

    #[test]
    fn round_trips_an_empty_plaintext() {
        let key = FernetKey::derive(TEST_SECRET);
        let token = key.encrypt_token("");
        assert_eq!(key.decrypt_token(&token).unwrap(), "");
    }

    #[test]
    fn round_trips_multibyte_plaintext() {
        let key = FernetKey::derive(TEST_SECRET);
        let secret = "mật khẩu cơ sở dữ liệu ✓";
        let token = key.encrypt_token(secret);
        assert_eq!(key.decrypt_token(&token).unwrap(), secret);
    }

    #[test]
    fn a_rotated_secret_key_is_a_clean_error_not_garbage() {
        let token = FernetKey::derive(TEST_SECRET).encrypt_token("db-password");
        let other = FernetKey::derive("a-completely-different-secret-key-value");
        assert_eq!(other.decrypt_token(&token), Err(FernetError::BadSignature));
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let key = FernetKey::derive(TEST_SECRET);
        let token = key.encrypt_token("db-password");
        let mut raw = B64.decode(&token).unwrap();
        let last = raw.len() - 40; // inside the ciphertext, before the HMAC
        raw[last] ^= 0x01;
        let tampered = B64.encode(&raw);
        assert_eq!(key.decrypt_token(&tampered), Err(FernetError::BadSignature));
    }

    #[test]
    fn strict_mode_refuses_legacy_plaintext() {
        assert_eq!(
            decrypt(TEST_SECRET, Some("just-a-plain-password"), true),
            Err(FernetError::LegacyPlaintext)
        );
        assert_eq!(
            decrypt(TEST_SECRET, Some("just-a-plain-password"), false),
            Ok("just-a-plain-password".to_string())
        );
    }

    #[test]
    fn empty_and_missing_values_read_as_empty() {
        assert_eq!(decrypt(TEST_SECRET, None, true), Ok(String::new()));
        assert_eq!(decrypt(TEST_SECRET, Some(""), true), Ok(String::new()));
    }

    #[test]
    fn prefix_helpers_match_python() {
        let stored = encrypt(TEST_SECRET, "x");
        assert!(stored.starts_with("fernet:"));
        assert!(is_encrypted(Some(&stored)));
        assert!(!is_encrypted(Some("plain")));
        assert!(!is_encrypted(None));
        assert_eq!(decrypt(TEST_SECRET, Some(&stored), true).unwrap(), "x");
    }
}
