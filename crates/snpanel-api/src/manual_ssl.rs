//! The certificate an administrator uploads, rather than one certbot issued.
//!
//! Source: `app/services/ssl.py` - `read_ssl_part`, `validate_manual_ssl` and
//! the private helpers they call.
//!
//! Every refusal here is one an administrator reads in a toast while holding
//! a certificate they paid for, so the message has to say which of the three
//! parts is wrong and why. The strings are the Python's, character for
//! character; the corpus in `tests/golden/manual_ssl.json` was produced by
//! running the real `app.services.ssl` over real generated key material, and
//! the tests replay it.

use x509_parser::prelude::*;

/// Source: `MAX_SSL_PART_BYTES = 256 * 1024`.
pub const MAX_SSL_PART_BYTES: usize = 256 * 1024;

/// Source: `ALLOWED_SSL_EXTENSIONS`.
const ALLOWED_SSL_EXTENSIONS: &[&str] = &[".crt", ".pem", ".key", ".ca"];

/// `str.strip()` with no argument, which is not `str::trim`.
///
/// Python strips every character `str.isspace()` calls whitespace, and that
/// set is Unicode `White_Space` **plus** U+001C..U+001F - the four ASCII file
/// and record separators, which Rust does not consider whitespace. A
/// certificate is not going to arrive with a record separator glued to it,
/// but the whole point of a corpus is that the two implementations are the
/// same function, and "close enough on the inputs I thought of" is how a port
/// grows a difference nobody looks for.
fn python_strip(text: &str) -> &str {
    let is_space = |c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c);
    text.trim_matches(is_space)
}

/// `pathlib.PurePath(name).suffix`, lowered.
///
/// CPython's rule is `i = name.rfind('.')` then `name[i:] if 0 < i < len - 1
/// else ''`, so `.crt` on its own is a hidden file with no extension and
/// `cert.` has none either. A port that reached for "split on the last dot"
/// would accept an upload named `.crt` that the Python refuses.
fn python_suffix(filename: &str) -> String {
    // `PurePosixPath("a/b.crt").name` - the last component, ignoring any
    // trailing slashes.
    let name = filename
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("");
    match name.rfind('.') {
        Some(i) if i > 0 && i < name.len() - 1 => name[i..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Source: `_safe_domain`.
///
/// This is the guard that keeps a domain out of a path: the caller turns it
/// straight into `/etc/nginx/snpanel/ssl/sites/<domain>`.
pub fn safe_domain(domain: &str) -> Result<String, String> {
    let safe = domain.trim().to_lowercase();
    if safe.is_empty() || safe.contains('/') || safe.contains('\\') || safe.contains("..") {
        return Err("Invalid domain".to_string());
    }
    Ok(safe)
}

/// Source: `_safe_domain_list` - the site's own name first, then each alias
/// that is not already in the list, in the order given.
pub fn safe_domain_list(domain: &str, aliases: &[String]) -> Result<Vec<String>, String> {
    let mut names = vec![safe_domain(domain)?];
    for alias in aliases {
        let safe = safe_domain(alias)?;
        if !names.contains(&safe) {
            names.push(safe);
        }
    }
    Ok(names)
}

/// Source: `_normalize_pem`.
///
/// CRLF becomes LF and the result ends in exactly one newline, because these
/// bytes are written to a file OpenSSL parses and a stray CR inside a base64
/// line is a parse error in some versions and silent truncation in others.
pub fn normalize_pem(raw: &[u8], label: &str, required: bool) -> Result<Vec<u8>, String> {
    let missing = || {
        if required {
            Err(format!("{label} is required"))
        } else {
            Ok(Vec::new())
        }
    };
    if raw.is_empty() {
        return missing();
    }
    if raw.contains(&0) {
        return Err(format!("{label} contains a NUL byte"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| format!("{label} must be UTF-8 PEM text"))?;
    let text = text.replace("\r\n", "\n");
    let text = python_strip(&text);
    if text.is_empty() {
        return missing();
    }
    Ok(format!("{text}\n").into_bytes())
}

/// Where one of the three parts came from.
///
/// The distinction is not cosmetic: `_read_limited` caps an **uploaded** file
/// at [`MAX_SSL_PART_BYTES`] and the pasted-text field has no cap at all,
/// because the text arrives through the form parser which has its own. A port
/// that capped both would refuse a paste the Python accepts.
pub enum SslPart<'a> {
    /// A multipart file part, with the filename the browser sent.
    Upload { filename: &'a str, data: &'a [u8] },
    /// A pasted-in form field.
    Text(&'a str),
}

/// Source: `read_ssl_part`, reached through `_read_ssl_input`.
pub fn read_ssl_part(part: &SslPart<'_>, label: &str, required: bool) -> Result<Vec<u8>, String> {
    match part {
        SslPart::Upload { filename, data } => {
            if !filename.is_empty() {
                let suffix = python_suffix(filename);
                if !ALLOWED_SSL_EXTENSIONS.contains(&suffix.as_str()) {
                    return Err(format!("{label} must be .crt, .pem, .key, or .ca"));
                }
            }
            if data.len() > MAX_SSL_PART_BYTES {
                return Err(format!("{label} is too large"));
            }
            normalize_pem(data, label, required)
        }
        SslPart::Text(text) => normalize_pem(text.as_bytes(), label, required),
    }
}

/// The PEM blocks of the given label, with a flag for "this file does not
/// frame correctly".
///
/// **The two ways a certificate can be wrong are not the same way**, and the
/// corpus is what says so rather than a reading of the library:
///
/// - a block whose **base64 does not decode** poisons the whole file, even
///   for the single-certificate reader and even when it sits *after* a
///   perfectly good certificate. The PEM layer runs over the file before
///   anything looks at a certificate;
/// - a block that decodes to **bytes that are not a certificate** is only a
///   problem for whoever reads it. The single-certificate reader takes the
///   first block and never looks further, so junk after a good certificate
///   loads; junk *before* one does not. A bundle reads all of them, so junk
///   anywhere refuses.
///
/// Getting this backwards is how a port starts accepting a file OpenSSL will
/// refuse at nginx reload - after the row already says the site has SSL.
///
/// `cryptography` does skip whole sections it is not interested in: a file
/// that leads with the private key, or with a note above the certificate,
/// loads fine. Both are in the corpus (`key-then-cert`, `junk-then-cert`).
fn pem_blocks(raw: &[u8], want_label: &str) -> (Vec<Vec<u8>>, bool) {
    use base64::Engine as _;
    let text = String::from_utf8_lossy(raw);
    let begin = format!("-----BEGIN {want_label}-----");
    let end = format!("-----END {want_label}-----");
    let mut out = Vec::new();
    let mut malformed = false;
    let mut body: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        match &mut body {
            None if line == begin => body = Some(String::new()),
            None => {}
            Some(_) if line == end => {
                let collected = body.take().unwrap_or_default();
                match base64::engine::general_purpose::STANDARD.decode(collected.as_bytes()) {
                    Ok(der) => out.push(der),
                    // Carrying on and stopping here give the same answer for
                    // every input, because both callers check the flag before
                    // they look at a block. This form is the one that stays
                    // right if a third caller ever does not.
                    Err(_) => malformed = true,
                }
            }
            Some(acc) => acc.push_str(line),
        }
    }
    (out, malformed)
}

/// Source: `_load_certificate` - the leaf, whatever else is in the file.
///
/// The first block only, but the whole file has to frame correctly first.
fn load_certificate(raw: &[u8], label: &str) -> Result<Vec<u8>, String> {
    let (blocks, malformed) = pem_blocks(raw, "CERTIFICATE");
    if malformed {
        return Err(format!("{label} is not a valid PEM certificate"));
    }
    let der = blocks
        .into_iter()
        .next()
        .ok_or_else(|| format!("{label} is not a valid PEM certificate"))?;
    X509Certificate::from_der(&der)
        .map_err(|_| format!("{label} is not a valid PEM certificate"))?;
    Ok(der)
}

/// Source: `_load_ca_bundle` - every block has to parse, and there has to be
/// at least one.
fn load_ca_bundle(raw: &[u8]) -> Result<(), String> {
    let bad = || "ca_bundle is not a valid PEM certificate bundle".to_string();
    let (blocks, malformed) = pem_blocks(raw, "CERTIFICATE");
    if malformed || blocks.is_empty() {
        return Err(bad());
    }
    for der in &blocks {
        X509Certificate::from_der(der).map_err(|_| bad())?;
    }
    Ok(())
}

/// Source: `_validate_certificate_time`.
fn validate_certificate_time(cert: &X509Certificate<'_>, now_unix: i64) -> Result<(), String> {
    let validity = cert.validity();
    if now_unix < validity.not_before.timestamp() {
        return Err("certificate is not valid yet".to_string());
    }
    if now_unix >= validity.not_after.timestamp() {
        return Err("certificate is expired".to_string());
    }
    Ok(())
}

/// The names a certificate offers, lowered.
///
/// Source: `_validate_certificate_domain`. The subject CN is consulted **only
/// when there is no SAN at all** - a certificate that carries a SAN for
/// `b.example.com` and a CN of `a.example.com` does not cover `a.example.com`,
/// which is what every TLS client has done since RFC 2818 was deprecated and
/// what the corpus records the Python doing.
pub fn certificate_names(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.push(dns.to_lowercase());
            }
        }
    }
    if names.is_empty() {
        for cn in cert.subject().iter_common_name() {
            if let Ok(value) = cn.as_str() {
                names.push(value.to_lowercase());
            }
        }
    }
    names
}

/// Source: `_validate_key_matches_certificate`.
///
/// The Python signs a fixed message with the uploaded key and verifies it
/// with the certificate's public key, falling back to comparing the two
/// SubjectPublicKeyInfo encodings. Both answer the same question - do these
/// two halves belong together - and the comparison is the one that needs no
/// signing operation, so it is the one done here.
///
/// **A documented difference.** The Python also accepts an Ed448 or a DSA
/// key; ring does not implement either, so a key of one of those types is
/// refused here with `private_key does not match certificate` even when it
/// matches. No public certificate authority issues either, and the failure is
/// in the refusing direction: an administrator is told no rather than handed
/// a site nginx cannot start on.
fn key_matches_certificate(key_pem: &[u8], cert_der: &[u8]) -> Result<(), String> {
    let mismatch = || "private_key does not match certificate".to_string();
    let key_der = parse_private_key(key_pem).ok_or_else(mismatch)?;
    let signing =
        rustls::crypto::ring::sign::any_supported_type(&key_der).map_err(|_| mismatch())?;
    let key_spki = signing.public_key().ok_or_else(mismatch)?;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| mismatch())?;
    let cert_spki = cert.tbs_certificate.subject_pki.raw;
    if key_spki.as_ref() == cert_spki {
        return Ok(());
    }
    // The algorithm identifiers can differ where the key bits do not - an
    // RSASSA-PSS certificate names a different OID from the `rsaEncryption`
    // the key was stored under. The Python's sign-and-verify path does not
    // care, because it only ever touches the public key itself, so neither
    // does this.
    let cert_bits = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    let key_bits = spki_public_key_bits(key_spki.as_ref()).ok_or_else(mismatch)?;
    if key_bits == cert_bits {
        return Ok(());
    }
    Err(mismatch())
}

/// The BIT STRING payload of a DER SubjectPublicKeyInfo.
fn spki_public_key_bits(spki: &[u8]) -> Option<&[u8]> {
    let (_, parsed) = x509_parser::x509::SubjectPublicKeyInfo::from_der(spki).ok()?;
    // `data` borrows from `spki`, which outlives the return.
    let bits = parsed.subject_public_key.data;
    match bits {
        std::borrow::Cow::Borrowed(b) => Some(b),
        std::borrow::Cow::Owned(_) => None,
    }
}

/// Source: `serialization.load_pem_private_key(raw, password=None)`.
///
/// PKCS#1, PKCS#8 and SEC1 all load; an encrypted key does not, which is why
/// the Python's message says *unencrypted*.
fn parse_private_key(raw: &[u8]) -> Option<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(raw);
    rustls_pemfile::private_key(&mut reader).ok().flatten()
}

/// Source: `validate_manual_ssl`.
///
/// The order of the checks is the order of the messages, and the order is not
/// arbitrary: an administrator who uploaded a certificate for the wrong site
/// *and* the wrong key should be told about the certificate first, because
/// that is the file they have to go and find again.
pub fn validate_manual_ssl(
    domain: &str,
    certificate: &[u8],
    private_key: &[u8],
    ca_bundle: &[u8],
    aliases: &[String],
    now_unix: i64,
) -> Result<(), String> {
    let domains = safe_domain_list(domain, aliases)?;
    let cert_der = load_certificate(certificate, "certificate")?;
    if parse_private_key(private_key).is_none() {
        return Err("private_key is not a valid unencrypted PEM private key".to_string());
    }
    if !ca_bundle.is_empty() {
        load_ca_bundle(ca_bundle)?;
    }
    let (_, cert) = X509Certificate::from_der(&cert_der)
        .map_err(|_| "certificate is not a valid PEM certificate".to_string())?;
    validate_certificate_time(&cert, now_unix)?;

    let names = certificate_names(&cert);
    for wanted in &domains {
        if !names
            .iter()
            .any(|pattern| crate::routes::websites::hostname_matches(wanted, pattern))
        {
            return Err("certificate CN/SAN does not match the website domain".to_string());
        }
    }
    key_matches_certificate(private_key, &cert_der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::Value;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/manual_ssl.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the manual SSL corpus"))
            .expect("the corpus parses")
    }

    fn b64(value: &Value, key: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value[key].as_str().unwrap_or(""))
            .expect("base64 in the corpus")
    }

    /// Every `read_ssl_part` verdict the real Python gave, replayed.
    ///
    /// The cases that matter most are the ones that look like nothing: a
    /// filename of `.crt` is a hidden file with no extension and is refused,
    /// `cert.tar.crt` has the extension `.crt` and is accepted, and the size
    /// cap applies to an upload but not to pasted text.
    #[test]
    fn the_uploaded_parts_are_read_the_way_the_python_reads_them() {
        let corpus = corpus();
        let cases = corpus["read_ssl_part"].as_array().expect("read cases");
        // A corpus loop over an empty array passes while asserting nothing.
        assert_eq!(cases.len(), 25, "the read corpus changed size");
        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let required = case["required"].as_bool().unwrap_or(true);
            let data = b64(case, "input");
            let text_owned;
            let part = if case["kind"] == "upload" {
                SslPart::Upload {
                    filename: case["filename"].as_str().unwrap_or(""),
                    data: &data,
                }
            } else {
                text_owned = String::from_utf8_lossy(&data).into_owned();
                SslPart::Text(&text_owned)
            };
            let got = read_ssl_part(&part, "certificate", required);
            let want: Result<Vec<u8>, String> = if case["ok"].as_bool().unwrap_or(false) {
                Ok(b64(case, "output"))
            } else {
                Err(case["error"].as_str().unwrap_or("").to_string())
            };
            if got != want {
                failures.push(format!(
                    "{label}\n  python {:?}\n  rust   {:?}",
                    want.as_ref()
                        .map(|v| String::from_utf8_lossy(v).into_owned()),
                    got.as_ref()
                        .map(|v| String::from_utf8_lossy(v).into_owned()),
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} read cases disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    /// Every `validate_manual_ssl` verdict, replayed against real key material.
    ///
    /// The certificates in the corpus were generated and signed by the real
    /// `cryptography`, so this exercises the parser against bytes a certificate
    /// authority would produce rather than against a fixture written by hand
    /// to match what the parser already does.
    #[test]
    fn a_manual_certificate_is_judged_the_way_the_python_judges_it() {
        let corpus = corpus();
        // The corpus fixes validity windows relative to when it was generated,
        // so the expiry cases are read at that instant rather than at now -
        // otherwise the "not yet valid" case turns valid on its own and the
        // test quietly stops asserting anything.
        let now = corpus_now(&corpus);
        let mut failures: Vec<String> = Vec::new();
        let cases = corpus["validate_manual_ssl"].as_array().expect("cases");
        assert_eq!(cases.len(), 48, "the validate corpus changed size");
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let aliases: Vec<String> = case["aliases"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|v| v.as_str().unwrap_or("").to_string())
                        .collect()
                })
                .unwrap_or_default();
            let got = validate_manual_ssl(
                case["domain"].as_str().unwrap_or(""),
                &b64(case, "certificate"),
                &b64(case, "private_key"),
                &b64(case, "ca_bundle"),
                &aliases,
                now,
            );
            let want: Result<(), String> = if case["ok"].as_bool().unwrap_or(false) {
                Ok(())
            } else {
                Err(case["error"].as_str().unwrap_or("").to_string())
            };
            if got != want {
                failures.push(format!("{label}\n  python {want:?}\n  rust   {got:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} validate cases disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    /// When the corpus was generated, read off a certificate inside it.
    ///
    /// `rsa_cert` was issued for `now - 1 day .. now + 30 days`, so its
    /// `not_before` plus a day is the instant the Python was run.
    fn corpus_now(corpus: &Value) -> i64 {
        let der = base64::engine::general_purpose::STANDARD
            .decode(corpus["material"]["rsa_cert"].as_str().expect("rsa_cert"))
            .expect("base64");
        let der = pem_blocks(&der, "CERTIFICATE")
            .0
            .into_iter()
            .next()
            .expect("a certificate block");
        let (_, cert) = X509Certificate::from_der(&der).expect("it parses");
        cert.validity().not_before.timestamp() + 24 * 60 * 60
    }

    /// A domain becomes a path, so the guard is the one that matters.
    #[test]
    fn a_domain_that_could_escape_the_certificate_directory_is_refused() {
        assert_eq!(
            safe_domain("A.Example.COM  ").as_deref(),
            Ok("a.example.com")
        );
        for bad in ["", "   ", "a/b", "a\\b", "../etc", "a..b", "/absolute"] {
            assert_eq!(
                safe_domain(bad),
                Err("Invalid domain".to_string()),
                "{bad:?} was accepted"
            );
        }
    }

    /// `Path(name).suffix` is not "the bit after the last dot".
    #[test]
    fn a_hidden_file_has_no_extension_the_way_python_counts_them() {
        assert_eq!(python_suffix("cert.crt"), ".crt");
        assert_eq!(python_suffix("CERT.CRT"), ".crt");
        assert_eq!(python_suffix("cert.tar.crt"), ".crt");
        assert_eq!(python_suffix("dir/cert.crt"), ".crt");
        // A leading dot is the stem of a hidden file, not an extension.
        assert_eq!(python_suffix(".crt"), "");
        // A trailing dot is not one either.
        assert_eq!(python_suffix("cert."), "");
        assert_eq!(python_suffix("cert"), "");
    }

    /// The aliases join the site's own name once each, in order.
    #[test]
    fn the_names_a_certificate_must_carry_are_the_site_and_its_aliases() {
        let aliases = [
            "www.a.com".to_string(),
            "A.COM".to_string(),
            "b.com".to_string(),
        ];
        assert_eq!(
            safe_domain_list("a.com", &aliases).expect("valid"),
            vec!["a.com", "www.a.com", "b.com"]
        );
        // One bad alias refuses the whole list rather than being dropped.
        assert!(safe_domain_list("a.com", &["../x".to_string()]).is_err());
    }
}
