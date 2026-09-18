//! The compatibility gate.
//!
//! Every value here was produced by the Python implementation that is running
//! in production today (`tests/fixtures/generate.py`). Nothing in this file
//! checks Rust against Rust - that would pass while being entirely wrong.
//!
//! Plan §8, Phase 0: "If the Fernet spike fails and there is no way to fix it,
//! stop the project and redesign." This is that spike, plus the other three.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;
use snpanel_core::crypto::{fernet, password, token, totp};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\n\nRegenerate the fixtures:\n  \
             python3 -m venv .venv\n  \
             .venv/bin/pip install -r backend/requirements.txt\n  \
             .venv/bin/python tests/fixtures/generate.py\n",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("fixture is valid JSON")
}

// ---------------------------------------------------------------------------
// C3 - Fernet. Risk R1: getting this wrong loses every customer's database
// password, silently.
// ---------------------------------------------------------------------------

#[test]
fn c3_key_derivation_matches_python() {
    let f = fixture("fernet.json");
    let secret = f["secret_key"].as_str().unwrap();
    let expected = f["derived_key"].as_str().unwrap();
    assert_eq!(
        fernet::FernetKey::derive(secret).as_python_key(),
        expected,
        "the derived Fernet key must be byte-identical to Python's"
    );
}

#[test]
fn c3_rust_decrypts_every_python_ciphertext() {
    let f = fixture("fernet.json");
    let secret = f["secret_key"].as_str().unwrap();
    let cases = f["cases"].as_object().unwrap();
    assert!(!cases.is_empty(), "fixture must contain cases");

    for (name, case) in cases {
        let stored = case["stored"].as_str().unwrap();
        let expected = case["plaintext"].as_str().unwrap();
        let got = fernet::decrypt(secret, Some(stored), true).unwrap_or_else(|e| {
            panic!("case {name}: Rust could not decrypt a Python ciphertext: {e}")
        });
        assert_eq!(got, expected, "case {name}");
    }
}

#[test]
fn c3_python_ciphertexts_carry_the_stored_prefix() {
    let f = fixture("fernet.json");
    for (name, case) in f["cases"].as_object().unwrap() {
        let stored = case["stored"].as_str().unwrap();
        assert!(
            stored.starts_with("fernet:"),
            "case {name}: the DB column holds the prefix too"
        );
        assert!(fernet::is_encrypted(Some(stored)));
    }
}

#[test]
fn c3_a_rust_ciphertext_is_shaped_like_pythons() {
    // The other direction: Python must be able to read what Rust writes, for
    // as long as both are running during the strangler phase. We cannot invoke
    // Python from here, so check the invariants its parser enforces - version
    // byte, block alignment, HMAC length - by round-tripping through our own
    // parser and comparing the framing to a known-good Python token.
    let f = fixture("fernet.json");
    let secret = f["secret_key"].as_str().unwrap();
    let python_token = f["cases"]["simple"]["stored"]
        .as_str()
        .unwrap()
        .strip_prefix("fernet:")
        .unwrap();

    use base64::engine::general_purpose::URL_SAFE;
    use base64::Engine;
    let python_raw = URL_SAFE.decode(python_token).unwrap();

    let rust_stored = fernet::encrypt(secret, "correct horse battery");
    let rust_raw = URL_SAFE
        .decode(rust_stored.strip_prefix("fernet:").unwrap())
        .unwrap();

    assert_eq!(rust_raw[0], python_raw[0], "version byte");
    assert_eq!(
        rust_raw.len(),
        python_raw.len(),
        "same plaintext, same framing"
    );
    // And it must decrypt back.
    assert_eq!(
        fernet::decrypt(secret, Some(&rust_stored), true).unwrap(),
        "correct horse battery"
    );
}

// ---------------------------------------------------------------------------
// C1 - bcrypt
// ---------------------------------------------------------------------------

#[test]
fn c1_rust_verifies_every_passlib_hash() {
    let f = fixture("bcrypt.json");
    let cases = f["cases"].as_object().unwrap();
    assert!(!cases.is_empty());

    for (name, case) in cases {
        let pw = case["password"].as_str().unwrap();
        let hash = case["hash"].as_str().unwrap();
        assert!(
            password::verify_password(pw, hash),
            "case {name}: an existing user could not log in"
        );
        assert!(
            !password::verify_password("definitely-the-wrong-password", hash),
            "case {name}: the wrong password was accepted"
        );
    }
}

#[test]
fn c1_the_cost_is_read_from_the_hash() {
    let f = fixture("bcrypt.json");
    let hash = f["cases"]["cost_10"]["hash"].as_str().unwrap();
    assert_eq!(password::cost_of(hash), Some(10));
    // ...and a hash below the current cost is flagged for rehash on next login.
    assert!(password::needs_rehash(hash));
}

#[test]
fn c1_shadow_hashes_are_not_mistaken_for_bcrypt() {
    let f = fixture("bcrypt.json");
    for prefix in f["shadow_prefixes"].as_array().unwrap() {
        let prefix = prefix.as_str().unwrap();
        let fake = format!("{prefix}rounds$abcdefghijklmnop");
        assert!(
            !password::verify_password("anything", &fake),
            "{prefix} is a crypt(3) hash, not bcrypt"
        );
    }
    for prefix in f["bcrypt_prefixes"].as_array().unwrap() {
        assert_eq!(
            password::classify(&format!("{}12$x", prefix.as_str().unwrap())),
            password::HashKind::Bcrypt
        );
    }
}

// ---------------------------------------------------------------------------
// C4 - JWT. This is what makes the strangler pattern work: while both
// implementations serve traffic they must accept each other's tokens.
// ---------------------------------------------------------------------------

#[test]
fn c4_rust_verifies_a_python_token() {
    let f = fixture("jwt.json");
    let secret = f["secret_key"].as_str().unwrap();
    let raw = f["valid"]["token"].as_str().unwrap();

    let claims = token::decode_access_token(secret, raw).expect("a live session must survive");
    // sub is the username, which is what deps.py looks the user up by.
    assert_eq!(claims.sub, f["valid"]["claims"]["sub"].as_str().unwrap());
    assert_eq!(claims.sub, "admin");
    assert_eq!(claims.jti, f["valid"]["claims"]["jti"].as_str().unwrap());
    assert_eq!(claims.exp, f["valid"]["claims"]["exp"].as_i64().unwrap());
    assert_eq!(claims.iat, f["valid"]["claims"]["iat"].as_i64().unwrap());
}

#[test]
fn c4_the_extra_claims_survive() {
    // token_version is what invalidates sessions on suspend (C27); role drives
    // authorisation. Dropping either would be a security bug, not a cosmetic one.
    let f = fixture("jwt.json");
    let secret = f["secret_key"].as_str().unwrap();
    let claims = token::decode_access_token(secret, f["valid"]["token"].as_str().unwrap()).unwrap();
    // `tv`, not `token_version` - see TOKEN_VERSION_CLAIM.
    assert_eq!(claims.token_version(), 3);
    assert_eq!(claims.role(), Some("admin"));
    assert!(claims.is_admin());
    assert!(!claims.is_impersonation());
}

#[test]
fn c4_the_impersonation_claim_is_understood() {
    // An admin's "log in as" session carries `imp`, and it is what lets the
    // session target a suspended user. Not reading it would make every
    // impersonated session fail once auth moves to Rust.
    let f = fixture("jwt.json");
    let secret = f["secret_key"].as_str().unwrap();
    let claims =
        token::decode_access_token(secret, f["impersonation"]["token"].as_str().unwrap()).unwrap();
    assert!(claims.is_impersonation());

    let normal = token::decode_access_token(secret, f["valid"]["token"].as_str().unwrap()).unwrap();
    assert!(!normal.is_impersonation());
}

#[test]
fn c4_an_expired_python_token_is_rejected() {
    let f = fixture("jwt.json");
    let secret = f["secret_key"].as_str().unwrap();
    assert!(matches!(
        token::decode_access_token(secret, f["expired"]["token"].as_str().unwrap()),
        Err(token::TokenError::Expired)
    ));
}

#[test]
fn c4_a_token_signed_with_another_key_is_rejected() {
    let f = fixture("jwt.json");
    let secret = f["secret_key"].as_str().unwrap();
    assert!(matches!(
        token::decode_access_token(secret, f["wrong_key"]["token"].as_str().unwrap()),
        Err(token::TokenError::BadSignature)
    ));
}

#[test]
fn c4_a_rust_token_has_the_claims_python_expects() {
    // The reverse direction. python-jose requires sub/exp/iat to be present
    // and of the right type; the panel additionally reads jti and token_version.
    let f = fixture("jwt.json");
    let secret = f["secret_key"].as_str().unwrap();

    let mut extra = BTreeMap::new();
    extra.insert(token::TOKEN_VERSION_CLAIM.to_string(), Value::from(3));
    extra.insert("role".to_string(), Value::from("admin"));
    let raw = token::create_access_token(secret, "admin", extra, 120).unwrap();

    // Decode the payload independently of our own parser.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload_b64 = raw.split('.').nth(1).expect("a JWT has three parts");
    let payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();

    assert_eq!(payload["sub"], "admin");
    assert!(
        payload["exp"].is_i64(),
        "exp must be a number, not a string"
    );
    assert!(payload["iat"].is_i64());
    assert!(payload["jti"].is_string());
    assert_eq!(payload["tv"], 3, "the claim Python reads is tv");
    assert!(payload.get("token_version").is_none());
    assert_eq!(payload["role"], "admin");

    // And the header must say HS256.
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(raw.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "HS256");
}

// ---------------------------------------------------------------------------
// C13 - the form rules.tsv stores
// ---------------------------------------------------------------------------

#[test]
fn c13_ip_normalisation_matches_python_ipaddress() {
    use snpanel_core::IpOrCidr;

    let f = fixture("ipnorm.json");
    let cases = f.as_object().expect("a map of input -> normalised");
    assert!(!cases.is_empty());

    for (input, expected) in cases {
        let parsed = IpOrCidr::parse(input).unwrap_or_else(|e| panic!("{input} should parse: {e}"));
        assert_eq!(
            parsed.normalized(),
            expected.as_str().unwrap(),
            "{input}: the bash writes what ipaddress.ip_network(strict=False) \
             produces, so a mismatch means a rule written by one side will not \
             match the other's duplicate check"
        );
    }
}

// ---------------------------------------------------------------------------
// C6 - TOTP
// ---------------------------------------------------------------------------

#[test]
fn c6_rust_generates_the_same_codes_as_pyotp() {
    let f = fixture("totp.json");
    let secret = f["secret"].as_str().unwrap();
    let codes = f["codes"].as_object().unwrap();
    assert!(!codes.is_empty());

    for (ts, expected) in codes {
        let ts: u64 = ts.parse().unwrap();
        let got = totp::code_at(secret, ts).expect("an enrolled secret must keep working");
        assert_eq!(
            got,
            expected.as_str().unwrap(),
            "at t={ts}: a 2FA user would be locked out"
        );
    }
}

#[test]
fn c6_verification_accepts_the_pyotp_code() {
    let f = fixture("totp.json");
    let secret = f["secret"].as_str().unwrap();
    for (ts, code) in f["codes"].as_object().unwrap() {
        let ts: u64 = ts.parse().unwrap();
        assert!(totp::verify_exact(secret, code.as_str().unwrap(), ts).unwrap());
    }
}

#[test]
fn c6_the_parameters_are_the_pyotp_defaults() {
    let f = fixture("totp.json");
    assert_eq!(f["digits"].as_u64().unwrap() as usize, totp::DIGITS);
    assert_eq!(f["period"].as_u64().unwrap(), totp::PERIOD);
    assert_eq!(f["algorithm"].as_str().unwrap(), "SHA1");
}

#[test]
fn c6_the_provisioning_uri_matches() {
    let f = fixture("totp.json");
    let secret = f["secret"].as_str().unwrap();
    let expected = f["provisioning_uri"].as_str().unwrap();
    let got = totp::provisioning_uri(secret, "admin", "SNPanel").unwrap();

    // Compare the parts rather than the whole string: query parameter order is
    // not significant to any authenticator app, and the two libraries differ.
    let params = |uri: &str| -> BTreeMap<String, String> {
        uri.split_once('?')
            .map(|(_, q)| q)
            .unwrap_or("")
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };

    let (got_params, expected_params) = (params(&got), params(expected));
    assert_eq!(got_params.get("secret"), expected_params.get("secret"));
    assert_eq!(got_params.get("issuer"), expected_params.get("issuer"));
    assert!(got.starts_with("otpauth://totp/"));
}
