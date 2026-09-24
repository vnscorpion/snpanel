//! WebAuthn - checking what a browser's authenticator sends back.
//!
//! A passkey is registered with `navigator.credentials.create` and used with
//! `navigator.credentials.get`. Each comes back to the panel as three or four
//! byte strings: `clientDataJSON`, and either an `attestationObject` or an
//! `authenticatorData` and a `signature`. This module checks them against the
//! challenge the panel issued, the origin and relying-party id it expects,
//! and - for a sign-in - the public key it stored at registration.
//!
//! What it deliberately does not do, so nobody assumes it does:
//!
//! - **Attestation is not verified.** The panel asks for `attestation:
//!   "none"`: it does not choose which makers of authenticators to trust. A
//!   passkey is bound to an account at a moment when the account holder has
//!   just entered their authenticator-app code, and that is what vouches for
//!   it. An authenticator that sends a statement anyway (`packed`, `tpm`, ...)
//!   is accepted; the statement is not read.
//! - **Three algorithms**: ES256 (-7), RS256 (-257, at least 2048 bits) and
//!   EdDSA (-8, Ed25519). Between them, every platform and security-key
//!   passkey in use.
//! - **The CBOR WebAuthn uses**: definite lengths, no tags, no floats. The
//!   decoder refuses anything else rather than guessing at it.
//!
//! Every check that can fail says which one it was ([`WebAuthnError`]), for
//! the log. What a person is told is decided by the caller.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// User present: someone touched the authenticator.
pub const FLAG_UP: u8 = 0x01;
/// User verified: by PIN or biometrics, not just presence.
pub const FLAG_UV: u8 = 0x04;
/// Attested credential data follows the counter (registration only).
pub const FLAG_AT: u8 = 0x40;
/// Extension data follows everything else.
pub const FLAG_ED: u8 = 0x80;

/// COSE algorithm numbers.
pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_RS256: i64 = -257;

/// What `pubKeyCredParams` offers, in order of preference.
pub const SUPPORTED_ALGORITHMS: [i64; 3] = [ALG_ES256, ALG_EDDSA, ALG_RS256];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("malformed CBOR: {0}")]
    Cbor(&'static str),
    #[error("malformed authenticator data: {0}")]
    AuthenticatorData(&'static str),
    #[error("malformed attestation object: {0}")]
    AttestationObject(&'static str),
    #[error("malformed client data: {0}")]
    ClientData(&'static str),
    #[error("client data is for {found}, not {expected}")]
    WrongCeremony {
        expected: &'static str,
        found: String,
    },
    #[error("the challenge is not the one issued")]
    WrongChallenge,
    #[error("origin {0} is not the panel's")]
    WrongOrigin(String),
    #[error("the request came from a cross-origin frame")]
    CrossOrigin,
    #[error("the relying party id does not match")]
    WrongRelyingParty,
    #[error("the authenticator did not report a user present")]
    UserNotPresent,
    #[error("no credential in the registration")]
    NoCredential,
    #[error("unsupported public key: {0}")]
    UnsupportedKey(&'static str),
    #[error("the signature does not verify")]
    BadSignature,
    #[error("the signature counter went from {stored} to {received}: a copied authenticator?")]
    CounterWentBack { stored: u32, received: u32 },
}

type Result<T> = std::result::Result<T, WebAuthnError>;

// ---------------------------------------------------------------------------
// CBOR, the part WebAuthn uses
// ---------------------------------------------------------------------------

/// A decoded CBOR item.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Unsigned(u64),
    /// `-1 - n`, kept as `n` so the whole range fits.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Cbor::Unsigned(n) => i64::try_from(*n).ok(),
            Cbor::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(s) => Some(s),
            _ => None,
        }
    }

    /// The value under an integer key (COSE keys use those).
    pub fn get_int(&self, key: i64) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.as_int() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value under a text key (the attestation object uses those).
    pub fn get_text(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Nesting deeper than this is not something an authenticator sends.
const MAX_DEPTH: usize = 16;

/// Decode one item from the front of `input`; returns it and how many bytes
/// it took. Trailing bytes are the caller's business.
pub fn decode_cbor(input: &[u8]) -> Result<(Cbor, usize)> {
    let mut pos = 0;
    let value = decode_item(input, &mut pos, 0)?;
    Ok((value, pos))
}

fn take<'a>(input: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(n)
        .ok_or(WebAuthnError::Cbor("length overflow"))?;
    let slice = input
        .get(*pos..end)
        .ok_or(WebAuthnError::Cbor("truncated"))?;
    *pos = end;
    Ok(slice)
}

fn decode_item(input: &[u8], pos: &mut usize, depth: usize) -> Result<Cbor> {
    if depth > MAX_DEPTH {
        return Err(WebAuthnError::Cbor("nested too deep"));
    }
    let initial = take(input, pos, 1)?[0];
    let major = initial >> 5;
    let info = initial & 0x1f;

    // Major type 7 carries simple values in `info` itself.
    if major == 7 {
        return match info {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 | 23 => Ok(Cbor::Null),
            _ => Err(WebAuthnError::Cbor(
                "floats and other simple values are not used",
            )),
        };
    }

    let argument: u64 = match info {
        0..=23 => u64::from(info),
        24 => u64::from(take(input, pos, 1)?[0]),
        25 => u64::from(u16::from_be_bytes(take(input, pos, 2)?.try_into().unwrap())),
        26 => u64::from(u32::from_be_bytes(take(input, pos, 4)?.try_into().unwrap())),
        27 => u64::from_be_bytes(take(input, pos, 8)?.try_into().unwrap()),
        31 => return Err(WebAuthnError::Cbor("indefinite lengths are not used")),
        _ => return Err(WebAuthnError::Cbor("reserved additional information")),
    };

    // A count can never exceed the bytes left: every element takes at least
    // one. Checking that first keeps a forged length from allocating.
    let remaining = (input.len() - *pos) as u64;
    match major {
        0 => Ok(Cbor::Unsigned(argument)),
        1 => Ok(Cbor::Negative(argument)),
        2 | 3 => {
            if argument > remaining {
                return Err(WebAuthnError::Cbor("truncated"));
            }
            let bytes = take(input, pos, argument as usize)?.to_vec();
            if major == 2 {
                Ok(Cbor::Bytes(bytes))
            } else {
                String::from_utf8(bytes)
                    .map(Cbor::Text)
                    .map_err(|_| WebAuthnError::Cbor("text is not UTF-8"))
            }
        }
        4 => {
            if argument > remaining {
                return Err(WebAuthnError::Cbor("truncated"));
            }
            let mut items = Vec::with_capacity(argument as usize);
            for _ in 0..argument {
                items.push(decode_item(input, pos, depth + 1)?);
            }
            Ok(Cbor::Array(items))
        }
        5 => {
            if argument.saturating_mul(2) > remaining {
                return Err(WebAuthnError::Cbor("truncated"));
            }
            let mut entries = Vec::with_capacity(argument as usize);
            for _ in 0..argument {
                let key = decode_item(input, pos, depth + 1)?;
                let value = decode_item(input, pos, depth + 1)?;
                entries.push((key, value));
            }
            Ok(Cbor::Map(entries))
        }
        _ => Err(WebAuthnError::Cbor("tags are not used")),
    }
}

// ---------------------------------------------------------------------------
// authenticator data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested: Option<AttestedCredential>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// The COSE key as the authenticator wrote it; stored as is.
    pub public_key: Vec<u8>,
}

pub fn parse_authenticator_data(bytes: &[u8]) -> Result<AuthenticatorData> {
    if bytes.len() < 37 {
        return Err(WebAuthnError::AuthenticatorData("shorter than 37 bytes"));
    }
    let rp_id_hash: [u8; 32] = bytes[..32].try_into().unwrap();
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes(bytes[33..37].try_into().unwrap());
    let mut rest = &bytes[37..];

    let attested = if flags & FLAG_AT != 0 {
        if rest.len() < 18 {
            return Err(WebAuthnError::AuthenticatorData("attested data truncated"));
        }
        let aaguid: [u8; 16] = rest[..16].try_into().unwrap();
        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        rest = &rest[18..];
        if rest.len() < id_len {
            return Err(WebAuthnError::AuthenticatorData("credential id truncated"));
        }
        let credential_id = rest[..id_len].to_vec();
        rest = &rest[id_len..];
        let (_, used) = decode_cbor(rest)?;
        let public_key = rest[..used].to_vec();
        rest = &rest[used..];
        Some(AttestedCredential {
            aaguid,
            credential_id,
            public_key,
        })
    } else {
        None
    };

    if flags & FLAG_ED != 0 {
        let (extensions, used) = decode_cbor(rest)?;
        if !matches!(extensions, Cbor::Map(_)) {
            return Err(WebAuthnError::AuthenticatorData("extensions are not a map"));
        }
        rest = &rest[used..];
    }
    if !rest.is_empty() {
        return Err(WebAuthnError::AuthenticatorData("trailing bytes"));
    }

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

// ---------------------------------------------------------------------------
// public keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum PublicKey {
    Es256 { x: [u8; 32], y: [u8; 32] },
    Rs256 { n: Vec<u8>, e: Vec<u8> },
    EdDsa { x: [u8; 32] },
}

impl PublicKey {
    pub fn algorithm(&self) -> i64 {
        match self {
            PublicKey::Es256 { .. } => ALG_ES256,
            PublicKey::Rs256 { .. } => ALG_RS256,
            PublicKey::EdDsa { .. } => ALG_EDDSA,
        }
    }
}

fn fixed32(value: Option<&Cbor>, what: &'static str) -> Result<[u8; 32]> {
    value
        .and_then(Cbor::as_bytes)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(WebAuthnError::UnsupportedKey(what))
}

/// A COSE_Key (RFC 9053) in one of the three supported shapes.
pub fn parse_cose_key(bytes: &[u8]) -> Result<PublicKey> {
    let (key, used) = decode_cbor(bytes)?;
    if used != bytes.len() {
        return Err(WebAuthnError::UnsupportedKey(
            "trailing bytes after the key",
        ));
    }
    let kty = key.get_int(1).and_then(Cbor::as_int);
    let alg = key.get_int(3).and_then(Cbor::as_int);
    match (kty, alg) {
        // EC2, ES256, curve P-256.
        (Some(2), Some(ALG_ES256)) => {
            if key.get_int(-1).and_then(Cbor::as_int) != Some(1) {
                return Err(WebAuthnError::UnsupportedKey(
                    "ES256 on a curve other than P-256",
                ));
            }
            Ok(PublicKey::Es256 {
                x: fixed32(key.get_int(-2), "ES256 x is not 32 bytes")?,
                y: fixed32(key.get_int(-3), "ES256 y is not 32 bytes")?,
            })
        }
        // RSA, RS256.
        (Some(3), Some(ALG_RS256)) => {
            let n = key.get_int(-1).and_then(Cbor::as_bytes);
            let e = key.get_int(-2).and_then(Cbor::as_bytes);
            match (n, e) {
                (Some(n), Some(e)) if !n.is_empty() && !e.is_empty() => Ok(PublicKey::Rs256 {
                    n: n.to_vec(),
                    e: e.to_vec(),
                }),
                _ => Err(WebAuthnError::UnsupportedKey("RS256 without n and e")),
            }
        }
        // OKP, EdDSA, curve Ed25519.
        (Some(1), Some(ALG_EDDSA)) => {
            if key.get_int(-1).and_then(Cbor::as_int) != Some(6) {
                return Err(WebAuthnError::UnsupportedKey(
                    "EdDSA on a curve other than Ed25519",
                ));
            }
            Ok(PublicKey::EdDsa {
                x: fixed32(key.get_int(-2), "Ed25519 x is not 32 bytes")?,
            })
        }
        _ => Err(WebAuthnError::UnsupportedKey("not ES256, RS256 or EdDSA")),
    }
}

/// RSA keys shorter than this are refused: 2048 bits is the floor anything
/// current generates, and a shorter key is a weaker second factor than the
/// authenticator-app code it would stand in for.
pub const MIN_RSA_BITS: usize = 2048;

pub fn verify_signature(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    match key {
        PublicKey::Es256 { x, y } => {
            use p256::ecdsa::signature::Verifier;
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| WebAuthnError::UnsupportedKey("ES256 point is not on the curve"))?;
            // WebAuthn ES256 signatures are ASN.1 DER, not the raw r||s pair.
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| WebAuthnError::BadSignature)?;
            key.verify(message, &signature)
                .map_err(|_| WebAuthnError::BadSignature)
        }
        PublicKey::Rs256 { n, e } => {
            use rsa::signature::Verifier;
            let bits = n.iter().skip_while(|b| **b == 0).count() * 8;
            if bits < MIN_RSA_BITS {
                return Err(WebAuthnError::UnsupportedKey(
                    "RSA key shorter than 2048 bits",
                ));
            }
            let key = rsa::RsaPublicKey::new(
                rsa::BoxedUint::from_be_slice_vartime(n),
                rsa::BoxedUint::from_be_slice_vartime(e),
            )
            .map_err(|_| WebAuthnError::UnsupportedKey("RSA key is not valid"))?;
            let key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key);
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| WebAuthnError::BadSignature)?;
            key.verify(message, &signature)
                .map_err(|_| WebAuthnError::BadSignature)
        }
        PublicKey::EdDsa { x } => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(x)
                .map_err(|_| WebAuthnError::UnsupportedKey("Ed25519 key is not valid"))?;
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .map_err(|_| WebAuthnError::BadSignature)?;
            key.verify_strict(message, &signature)
                .map_err(|_| WebAuthnError::BadSignature)
        }
    }
}

// ---------------------------------------------------------------------------
// the two ceremonies
// ---------------------------------------------------------------------------

/// What the panel expects of a response: the challenge it issued, and where.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub challenge: &'a [u8],
    /// `https://host[:port]`, exactly as the browser writes it.
    pub origin: &'a str,
    /// The host, without scheme or port.
    pub rp_id: &'a str,
}

/// `user.id` for `navigator.credentials.create`: sixteen bytes that name the
/// account to the authenticator without carrying its name or number.
pub fn user_handle(user_id: i64, username: &str) -> [u8; 16] {
    let digest = Sha256::digest(format!("snpanel-passkey-user:{user_id}:{username}").as_bytes());
    digest[..16].try_into().unwrap()
}

pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn from_base64url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

fn check_client_data(
    client_data_json: &[u8],
    ceremony: &'static str,
    expected: &Expected,
) -> Result<()> {
    let data: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|_| WebAuthnError::ClientData("not JSON"))?;
    let kind = data
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(WebAuthnError::ClientData("no type"))?;
    if kind != ceremony {
        return Err(WebAuthnError::WrongCeremony {
            expected: ceremony,
            found: kind.to_string(),
        });
    }
    let challenge = data
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        .and_then(from_base64url)
        .ok_or(WebAuthnError::ClientData("no challenge"))?;
    // `ct_eq` on slices of different lengths is false, so a short or long
    // challenge fails here too.
    if !bool::from(challenge.ct_eq(expected.challenge)) {
        return Err(WebAuthnError::WrongChallenge);
    }
    let origin = data
        .get("origin")
        .and_then(serde_json::Value::as_str)
        .ok_or(WebAuthnError::ClientData("no origin"))?;
    if origin != expected.origin {
        return Err(WebAuthnError::WrongOrigin(origin.to_string()));
    }
    if data.get("crossOrigin").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(WebAuthnError::CrossOrigin);
    }
    Ok(())
}

fn check_rp_id_hash(auth: &AuthenticatorData, rp_id: &str) -> Result<()> {
    let expected: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if bool::from(auth.rp_id_hash.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(WebAuthnError::WrongRelyingParty)
    }
}

/// A passkey the panel is about to store.
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: i64,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    pub user_verified: bool,
}

/// Check a `navigator.credentials.create` response.
pub fn verify_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    expected: &Expected,
) -> Result<Registration> {
    check_client_data(client_data_json, "webauthn.create", expected)?;

    let (object, used) = decode_cbor(attestation_object)?;
    if used != attestation_object.len() {
        return Err(WebAuthnError::AttestationObject("trailing bytes"));
    }
    let fmt = object
        .get_text("fmt")
        .and_then(Cbor::as_text)
        .ok_or(WebAuthnError::AttestationObject("no fmt"))?;
    let statement = object
        .get_text("attStmt")
        .ok_or(WebAuthnError::AttestationObject("no attStmt"))?;
    if fmt == "none" && *statement != Cbor::Map(Vec::new()) {
        return Err(WebAuthnError::AttestationObject(
            "fmt none with a statement",
        ));
    }
    let auth_data = object
        .get_text("authData")
        .and_then(Cbor::as_bytes)
        .ok_or(WebAuthnError::AttestationObject("no authData"))?;

    let auth = parse_authenticator_data(auth_data)?;
    check_rp_id_hash(&auth, expected.rp_id)?;
    if auth.flags & FLAG_UP == 0 {
        return Err(WebAuthnError::UserNotPresent);
    }
    let credential = auth.attested.ok_or(WebAuthnError::NoCredential)?;
    if credential.credential_id.len() < 16 || credential.credential_id.len() > 1023 {
        return Err(WebAuthnError::AuthenticatorData(
            "credential id length out of range",
        ));
    }
    let key = parse_cose_key(&credential.public_key)?;
    if let PublicKey::Rs256 { n, .. } = &key {
        if n.iter().skip_while(|b| **b == 0).count() * 8 < MIN_RSA_BITS {
            return Err(WebAuthnError::UnsupportedKey(
                "RSA key shorter than 2048 bits",
            ));
        }
    }

    Ok(Registration {
        credential_id: credential.credential_id,
        public_key: credential.public_key,
        algorithm: key.algorithm(),
        sign_count: auth.sign_count,
        aaguid: credential.aaguid,
        user_verified: auth.flags & FLAG_UV != 0,
    })
}

/// A `navigator.credentials.get` response.
#[derive(Debug, Clone, Copy)]
pub struct Assertion<'a> {
    pub client_data_json: &'a [u8],
    pub authenticator_data: &'a [u8],
    pub signature: &'a [u8],
}

/// Check a sign-in against the stored key and counter; returns the counter
/// to store next.
pub fn verify_assertion(
    assertion: &Assertion,
    stored_public_key: &[u8],
    stored_sign_count: u32,
    expected: &Expected,
) -> Result<u32> {
    check_client_data(assertion.client_data_json, "webauthn.get", expected)?;
    let auth = parse_authenticator_data(assertion.authenticator_data)?;
    if auth.attested.is_some() {
        return Err(WebAuthnError::AuthenticatorData(
            "a sign-in carries no new credential",
        ));
    }
    check_rp_id_hash(&auth, expected.rp_id)?;
    if auth.flags & FLAG_UP == 0 {
        return Err(WebAuthnError::UserNotPresent);
    }

    let key = parse_cose_key(stored_public_key)?;
    let mut message = assertion.authenticator_data.to_vec();
    message.extend_from_slice(&Sha256::digest(assertion.client_data_json));
    verify_signature(&key, &message, assertion.signature)?;

    // A counter that stands still or goes back means two authenticators hold
    // one key. Many passkeys keep no counter at all and always send 0; that
    // is fine as long as it stays 0.
    if (auth.sign_count != 0 || stored_sign_count != 0) && auth.sign_count <= stored_sign_count {
        return Err(WebAuthnError::CounterWentBack {
            stored: stored_sign_count,
            received: auth.sign_count,
        });
    }
    Ok(auth.sign_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- a little CBOR writer, for building what an authenticator sends ----

    fn head(major: u8, n: u64) -> Vec<u8> {
        let m = major << 5;
        match n {
            0..=23 => vec![m | n as u8],
            24..=0xff => vec![m | 24, n as u8],
            0x100..=0xffff => {
                let mut v = vec![m | 25];
                v.extend_from_slice(&(n as u16).to_be_bytes());
                v
            }
            0x1_0000..=0xffff_ffff => {
                let mut v = vec![m | 26];
                v.extend_from_slice(&(n as u32).to_be_bytes());
                v
            }
            _ => {
                let mut v = vec![m | 27];
                v.extend_from_slice(&n.to_be_bytes());
                v
            }
        }
    }
    fn int(n: i64) -> Vec<u8> {
        if n >= 0 {
            head(0, n as u64)
        } else {
            head(1, (-1 - n) as u64)
        }
    }
    fn bytes(b: &[u8]) -> Vec<u8> {
        let mut v = head(2, b.len() as u64);
        v.extend_from_slice(b);
        v
    }
    fn text(s: &str) -> Vec<u8> {
        let mut v = head(3, s.len() as u64);
        v.extend_from_slice(s.as_bytes());
        v
    }
    fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut v = head(5, entries.len() as u64);
        for (k, value) in entries {
            v.extend_from_slice(k);
            v.extend_from_slice(value);
        }
        v
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ---- what the panel issued, and a key or three ----

    const RP_ID: &str = "panel.example.com";
    const ORIGIN: &str = "https://panel.example.com:2222";
    const CHALLENGE: [u8; 32] = [0x5a; 32];

    fn expected() -> Expected<'static> {
        Expected {
            challenge: &CHALLENGE,
            origin: ORIGIN,
            rp_id: RP_ID,
        }
    }

    fn es256_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
    }
    fn es256_cose(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        let point = key.verifying_key().to_sec1_point(false);
        let point = point.as_bytes();
        map(&[
            (int(1), int(2)),
            (int(3), int(ALG_ES256)),
            (int(-1), int(1)),
            (int(-2), bytes(&point[1..33])),
            (int(-3), bytes(&point[33..65])),
        ])
    }
    fn es256_sign(key: &p256::ecdsa::SigningKey, message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = key.sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    fn client_data(kind: &str, challenge: &[u8], origin: &str, cross_origin: bool) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": kind,
            "challenge": base64url(challenge),
            "origin": origin,
            "crossOrigin": cross_origin,
        }))
        .unwrap()
    }

    fn auth_data(rp_id: &str, flags: u8, count: u32, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
        let mut v: Vec<u8> = Sha256::digest(rp_id.as_bytes()).to_vec();
        v.push(flags);
        v.extend_from_slice(&count.to_be_bytes());
        if let Some((credential_id, cose)) = attested {
            v.extend_from_slice(&[0x11; 16]);
            v.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
            v.extend_from_slice(credential_id);
            v.extend_from_slice(cose);
        }
        v
    }

    fn attestation(fmt: &str, statement: Vec<u8>, auth: &[u8]) -> Vec<u8> {
        map(&[
            (text("fmt"), text(fmt)),
            (text("attStmt"), statement),
            (text("authData"), bytes(auth)),
        ])
    }

    const CREDENTIAL_ID: [u8; 16] = [0xc1; 16];

    // ---- CBOR -----------------------------------------------------------

    /// RFC 8949 Appendix A, the items WebAuthn uses.
    #[test]
    fn cbor_decodes_the_rfc_examples() {
        let cases: &[(&str, Cbor)] = &[
            ("00", Cbor::Unsigned(0)),
            ("17", Cbor::Unsigned(23)),
            ("1818", Cbor::Unsigned(24)),
            ("1903e8", Cbor::Unsigned(1000)),
            ("1a000f4240", Cbor::Unsigned(1_000_000)),
            ("1bffffffffffffffff", Cbor::Unsigned(u64::MAX)),
            ("20", Cbor::Negative(0)),
            ("3863", Cbor::Negative(99)),
            ("4401020304", Cbor::Bytes(vec![1, 2, 3, 4])),
            ("6449455446", Cbor::Text("IETF".into())),
            (
                "83010203",
                Cbor::Array(vec![
                    Cbor::Unsigned(1),
                    Cbor::Unsigned(2),
                    Cbor::Unsigned(3),
                ]),
            ),
            (
                "a201020304",
                Cbor::Map(vec![
                    (Cbor::Unsigned(1), Cbor::Unsigned(2)),
                    (Cbor::Unsigned(3), Cbor::Unsigned(4)),
                ]),
            ),
            ("f4", Cbor::Bool(false)),
            ("f5", Cbor::Bool(true)),
            ("f6", Cbor::Null),
        ];
        for (input, want) in cases {
            let bytes = hex(input);
            assert_eq!(
                decode_cbor(&bytes),
                Ok((want.clone(), bytes.len())),
                "{input}"
            );
        }
        assert_eq!(Cbor::Negative(99).as_int(), Some(-100));
        assert_eq!(Cbor::Negative(0).as_int(), Some(-1));
    }

    #[test]
    fn cbor_refuses_what_webauthn_does_not_send() {
        for (input, why) in [
            ("5f42010243030405ff", "indefinite byte string"),
            ("c11a514b67b0", "a tag"),
            ("f93c00", "a half float"),
            ("1c", "reserved additional information"),
            ("1a0001", "a truncated argument"),
            ("45010203", "a byte string shorter than it says"),
            (
                "5bffffffffffffffff",
                "a length that would not fit in memory",
            ),
            ("9bffffffffffffffff", "an array longer than the input"),
            ("62c328", "text that is not UTF-8"),
        ] {
            assert!(decode_cbor(&hex(input)).is_err(), "{why}");
        }
        // Nesting past the limit.
        let deep: Vec<u8> = std::iter::repeat_n(0x81, 64).chain([0x00]).collect();
        assert_eq!(
            decode_cbor(&deep),
            Err(WebAuthnError::Cbor("nested too deep"))
        );
    }

    // ---- authenticator data ---------------------------------------------

    #[test]
    fn authenticator_data_is_read_field_by_field() {
        let plain = auth_data(RP_ID, FLAG_UP | FLAG_UV, 42, None);
        let parsed = parse_authenticator_data(&plain).unwrap();
        assert_eq!(parsed.flags, FLAG_UP | FLAG_UV);
        assert_eq!(parsed.sign_count, 42);
        assert!(parsed.attested.is_none());

        let cose = es256_cose(&es256_key());
        let with = auth_data(RP_ID, FLAG_UP | FLAG_AT, 0, Some((&CREDENTIAL_ID, &cose)));
        let attested = parse_authenticator_data(&with).unwrap().attested.unwrap();
        assert_eq!(attested.credential_id, CREDENTIAL_ID);
        assert_eq!(attested.public_key, cose);
        assert_eq!(attested.aaguid, [0x11; 16]);

        // Extensions after everything else, when the flag says so.
        let mut extended = auth_data(RP_ID, FLAG_UP | FLAG_ED, 0, None);
        extended.extend(map(&[(text("credProtect"), int(1))]));
        assert!(parse_authenticator_data(&extended).is_ok());

        assert!(parse_authenticator_data(&plain[..36]).is_err(), "short");
        let mut trailing = plain.clone();
        trailing.push(0);
        assert_eq!(
            parse_authenticator_data(&trailing),
            Err(WebAuthnError::AuthenticatorData("trailing bytes"))
        );
        let cut = &with[..with.len() - cose.len() - 3];
        assert!(
            parse_authenticator_data(cut).is_err(),
            "credential id cut short"
        );
    }

    // ---- keys -------------------------------------------------------------

    #[test]
    fn cose_keys_are_read_in_the_three_shapes_and_nothing_else() {
        let key = parse_cose_key(&es256_cose(&es256_key())).unwrap();
        assert_eq!(key.algorithm(), ALG_ES256);

        let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let ed_cose = map(&[
            (int(1), int(1)),
            (int(3), int(ALG_EDDSA)),
            (int(-1), int(6)),
            (int(-2), bytes(&ed.verifying_key().to_bytes())),
        ]);
        assert_eq!(parse_cose_key(&ed_cose).unwrap().algorithm(), ALG_EDDSA);

        let p384 = map(&[
            (int(1), int(2)),
            (int(3), int(ALG_ES256)),
            (int(-1), int(2)),
            (int(-2), bytes(&[1; 32])),
            (int(-3), bytes(&[2; 32])),
        ]);
        assert!(parse_cose_key(&p384).is_err(), "ES256 names P-256 only");
        let no_y = map(&[
            (int(1), int(2)),
            (int(3), int(ALG_ES256)),
            (int(-1), int(1)),
            (int(-2), bytes(&[1; 32])),
        ]);
        assert!(parse_cose_key(&no_y).is_err(), "a point needs both halves");
        let es384 = map(&[(int(1), int(2)), (int(3), int(-35))]);
        assert!(parse_cose_key(&es384).is_err(), "ES384 is not offered");
        let mut trailing = es256_cose(&es256_key());
        trailing.push(0);
        assert!(parse_cose_key(&trailing).is_err());
    }

    // ---- registration ----------------------------------------------------------

    fn registration_parts(flags: u8) -> (Vec<u8>, Vec<u8>) {
        let cose = es256_cose(&es256_key());
        let auth = auth_data(RP_ID, flags, 0, Some((&CREDENTIAL_ID, &cose)));
        (
            client_data("webauthn.create", &CHALLENGE, ORIGIN, false),
            attestation("none", map(&[]), &auth),
        )
    }

    #[test]
    fn a_sound_registration_is_accepted() {
        let (client, object) = registration_parts(FLAG_UP | FLAG_UV | FLAG_AT);
        let got = verify_registration(&client, &object, &expected()).unwrap();
        assert_eq!(got.credential_id, CREDENTIAL_ID);
        assert_eq!(got.algorithm, ALG_ES256);
        assert_eq!(got.public_key, es256_cose(&es256_key()));
        assert!(got.user_verified);

        // A statement in another format is accepted and not read.
        let cose = es256_cose(&es256_key());
        let auth = auth_data(RP_ID, FLAG_UP | FLAG_AT, 0, Some((&CREDENTIAL_ID, &cose)));
        let packed = attestation(
            "packed",
            map(&[(text("alg"), int(-7)), (text("sig"), bytes(&[1, 2, 3]))]),
            &auth,
        );
        assert!(verify_registration(&client, &packed, &expected()).is_ok());
    }

    #[test]
    fn a_registration_is_refused_for_each_thing_that_is_wrong() {
        let (client, object) = registration_parts(FLAG_UP | FLAG_AT);
        let other = |kind: &str, challenge: &[u8], origin: &str, cross: bool| {
            client_data(kind, challenge, origin, cross)
        };

        assert!(matches!(
            verify_registration(
                &other("webauthn.get", &CHALLENGE, ORIGIN, false),
                &object,
                &expected()
            ),
            Err(WebAuthnError::WrongCeremony { .. })
        ));
        assert_eq!(
            verify_registration(
                &other("webauthn.create", &[0x5b; 32], ORIGIN, false),
                &object,
                &expected()
            ),
            Err(WebAuthnError::WrongChallenge)
        );
        assert_eq!(
            verify_registration(
                &other("webauthn.create", &CHALLENGE[..16], ORIGIN, false),
                &object,
                &expected()
            ),
            Err(WebAuthnError::WrongChallenge)
        );
        assert!(matches!(
            verify_registration(
                &other(
                    "webauthn.create",
                    &CHALLENGE,
                    "https://evil.example.com",
                    false
                ),
                &object,
                &expected()
            ),
            Err(WebAuthnError::WrongOrigin(_))
        ));
        assert!(
            matches!(
                verify_registration(
                    &other(
                        "webauthn.create",
                        &CHALLENGE,
                        "https://panel.example.com",
                        false
                    ),
                    &object,
                    &expected()
                ),
                Err(WebAuthnError::WrongOrigin(_))
            ),
            "the port is part of the origin"
        );
        assert_eq!(
            verify_registration(
                &other("webauthn.create", &CHALLENGE, ORIGIN, true),
                &object,
                &expected()
            ),
            Err(WebAuthnError::CrossOrigin)
        );

        let cose = es256_cose(&es256_key());
        let foreign = attestation(
            "none",
            map(&[]),
            &auth_data(
                "evil.example.com",
                FLAG_UP | FLAG_AT,
                0,
                Some((&CREDENTIAL_ID, &cose)),
            ),
        );
        assert_eq!(
            verify_registration(&client, &foreign, &expected()),
            Err(WebAuthnError::WrongRelyingParty)
        );

        let (_, absent) = registration_parts(FLAG_AT);
        assert_eq!(
            verify_registration(&client, &absent, &expected()),
            Err(WebAuthnError::UserNotPresent)
        );

        let no_credential = attestation("none", map(&[]), &auth_data(RP_ID, FLAG_UP, 0, None));
        assert_eq!(
            verify_registration(&client, &no_credential, &expected()),
            Err(WebAuthnError::NoCredential)
        );

        let with_statement = attestation(
            "none",
            map(&[(text("x"), int(1))]),
            &auth_data(RP_ID, FLAG_UP | FLAG_AT, 0, Some((&CREDENTIAL_ID, &cose))),
        );
        assert!(
            verify_registration(&client, &with_statement, &expected()).is_err(),
            "none carries no statement"
        );

        let short_id = attestation(
            "none",
            map(&[]),
            &auth_data(RP_ID, FLAG_UP | FLAG_AT, 0, Some((&[1; 8], &cose))),
        );
        assert!(
            verify_registration(&client, &short_id, &expected()).is_err(),
            "credential ids are 16 bytes or more"
        );

        let mut trailing = object.clone();
        trailing.push(0);
        assert!(verify_registration(&client, &trailing, &expected()).is_err());
    }

    // ---- sign-in -------------------------------------------------------------------

    fn assertion_parts(flags: u8, count: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let client = client_data("webauthn.get", &CHALLENGE, ORIGIN, false);
        let auth = auth_data(RP_ID, flags, count, None);
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(&client));
        let signature = es256_sign(&es256_key(), &message);
        (client, auth, signature)
    }

    fn check(client: &[u8], auth: &[u8], signature: &[u8], key: &[u8], stored: u32) -> Result<u32> {
        verify_assertion(
            &Assertion {
                client_data_json: client,
                authenticator_data: auth,
                signature,
            },
            key,
            stored,
            &expected(),
        )
    }

    #[test]
    fn an_es256_sign_in_verifies_and_moves_the_counter() {
        let key = es256_cose(&es256_key());
        let (client, auth, signature) = assertion_parts(FLAG_UP | FLAG_UV, 6);
        assert_eq!(check(&client, &auth, &signature, &key, 5), Ok(6));

        // A passkey that keeps no counter sends 0 every time.
        let (client, auth, signature) = assertion_parts(FLAG_UP, 0);
        assert_eq!(check(&client, &auth, &signature, &key, 0), Ok(0));
    }

    #[test]
    fn a_sign_in_is_refused_for_each_thing_that_is_wrong() {
        let key = es256_cose(&es256_key());
        let (client, auth, signature) = assertion_parts(FLAG_UP, 6);

        let mut tampered = signature.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            check(&client, &auth, &tampered, &key, 5),
            Err(WebAuthnError::BadSignature)
        );

        // The signature covers the client data: another challenge, re-signed
        // by nobody, fails the challenge check before it gets that far.
        let other_challenge = client_data("webauthn.get", &[1; 32], ORIGIN, false);
        assert_eq!(
            check(&other_challenge, &auth, &signature, &key, 5),
            Err(WebAuthnError::WrongChallenge)
        );
        let created = client_data("webauthn.create", &CHALLENGE, ORIGIN, false);
        assert!(matches!(
            check(&created, &auth, &signature, &key, 5),
            Err(WebAuthnError::WrongCeremony { .. })
        ));
        let elsewhere = client_data(
            "webauthn.get",
            &CHALLENGE,
            "https://evil.example.com",
            false,
        );
        assert!(matches!(
            check(&elsewhere, &auth, &signature, &key, 5),
            Err(WebAuthnError::WrongOrigin(_))
        ));

        // Authenticator data for another relying party, properly signed.
        let foreign = auth_data("evil.example.com", FLAG_UP, 6, None);
        let mut message = foreign.clone();
        message.extend_from_slice(&Sha256::digest(&client));
        let signed = es256_sign(&es256_key(), &message);
        assert_eq!(
            check(&client, &foreign, &signed, &key, 5),
            Err(WebAuthnError::WrongRelyingParty)
        );

        let (client, absent, signature) = assertion_parts(0, 6);
        assert_eq!(
            check(&client, &absent, &signature, &key, 5),
            Err(WebAuthnError::UserNotPresent)
        );

        // The counter: standing still, going back, or dropping to zero.
        for (stored, received) in [(6, 6), (6, 5), (6, 0)] {
            let (client, auth, signature) = assertion_parts(FLAG_UP, received);
            assert_eq!(
                check(&client, &auth, &signature, &key, stored),
                Err(WebAuthnError::CounterWentBack { stored, received }),
                "{stored} -> {received}"
            );
        }

        // Someone else's key.
        let stranger = p256::ecdsa::SigningKey::from_slice(&[8u8; 32]).unwrap();
        let (client, auth, signature) = assertion_parts(FLAG_UP, 6);
        assert_eq!(
            check(&client, &auth, &signature, &es256_cose(&stranger), 5),
            Err(WebAuthnError::BadSignature)
        );

        // A sign-in that tries to carry a new credential, properly signed.
        let with_credential = auth_data(RP_ID, FLAG_UP | FLAG_AT, 6, Some((&CREDENTIAL_ID, &key)));
        let mut message = with_credential.clone();
        message.extend_from_slice(&Sha256::digest(&client));
        let signed = es256_sign(&es256_key(), &message);
        assert_eq!(
            check(&client, &with_credential, &signed, &key, 5),
            Err(WebAuthnError::AuthenticatorData(
                "a sign-in carries no new credential"
            ))
        );
    }

    #[test]
    fn eddsa_and_rs256_sign_ins_verify_too() {
        let client = client_data("webauthn.get", &CHALLENGE, ORIGIN, false);
        let auth = auth_data(RP_ID, FLAG_UP, 0, None);
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(&client));

        // Ed25519.
        {
            use ed25519_dalek::Signer;
            let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
            let cose = map(&[
                (int(1), int(1)),
                (int(3), int(ALG_EDDSA)),
                (int(-1), int(6)),
                (int(-2), bytes(&ed.verifying_key().to_bytes())),
            ]);
            let signature = ed.sign(&message).to_bytes();
            assert_eq!(check(&client, &auth, &signature, &cose, 0), Ok(0));
            let mut bad = signature;
            bad[0] ^= 1;
            assert_eq!(
                check(&client, &auth, &bad, &cose, 0),
                Err(WebAuthnError::BadSignature)
            );
        }

        // RSA, PKCS#1 v1.5 with SHA-256, from a key made for this test and
        // used for nothing else.
        {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            use rsa::signature::{SignatureEncoding, Signer};
            use rsa::traits::PublicKeyParts;
            let der = base64::engine::general_purpose::STANDARD
                .decode(include_str!("../../testdata/webauthn-rs256-test-key.der.b64").trim())
                .unwrap();
            let private = rsa::RsaPrivateKey::from_pkcs1_der(&der).unwrap();
            let public = private.to_public_key();
            let cose = map(&[
                (int(1), int(3)),
                (int(3), int(ALG_RS256)),
                (int(-1), bytes(&public.n().to_be_bytes())),
                (int(-2), bytes(&public.e().to_be_bytes())),
            ]);
            let signer = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private);
            let signature = signer.sign(&message).to_vec();
            assert_eq!(check(&client, &auth, &signature, &cose, 0), Ok(0));
            let mut bad = signature.clone();
            bad[10] ^= 1;
            assert_eq!(
                check(&client, &auth, &bad, &cose, 0),
                Err(WebAuthnError::BadSignature)
            );

            // The same key, cut to 1024 bits' worth of modulus, is refused
            // before any signature is looked at.
            let short = map(&[
                (int(1), int(3)),
                (int(3), int(ALG_RS256)),
                (int(-1), bytes(&public.n().to_be_bytes()[..128])),
                (int(-2), bytes(&public.e().to_be_bytes())),
            ]);
            assert!(matches!(
                check(&client, &auth, &signature, &short, 0),
                Err(WebAuthnError::UnsupportedKey(_))
            ));
        }
    }
}
