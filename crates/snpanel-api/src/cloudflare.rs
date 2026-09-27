//! The three things the panel needs from Cloudflare.
//!
//! Source: `app/services/cloudflare.py`.
//!
//! Prove a token works, find which zone a domain belongs to, and let the
//! caller store it so certbot can renew a wildcard unattended. **The token
//! is never logged**, not in an error and not in a trace: it is a key to
//! the customer's whole DNS zone, and an error path that printed it would
//! put it in the journal of every machine that ever failed a renewal.
//!
//! It is built from what the workspace already has - `hyper`, `hyper-util`,
//! `rustls`, `tokio-rustls` and `rustls-pemfile` - rather than pulling in a
//! client stack, and the roots come from the system bundle the rest of the
//! machine trusts. The S3 backup destination (`s3.rs`) is built the same way
//! and shares that trust store, [`system_roots`].
//!
//! The shapes below look over-careful for a JSON API that documents its
//! responses. They are not: every branch here is a verdict the real Python
//! gave for a body somebody could actually receive from a proxy, a captive
//! portal or a Cloudflare error page, and `success` is checked with
//! **Python truthiness** because that is what `if not payload.get(...)`
//! does - `1` and `"yes"` are successes to the Python and so they are here.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use snpanel_core::pyunicode;

/// Source: `API_ROOT`.
const API_HOST: &str = "api.cloudflare.com";
const API_PREFIX: &str = "/client/v4";

/// Source: `_TIMEOUT`.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Where a Linux distribution keeps the trust store, in the order the
/// distributions this panel installs on use.
///
/// Reading the system bundle rather than compiling roots in is deliberate:
/// an operator who adds a corporate CA, or removes one that has been
/// withdrawn, expects the panel to follow the machine - which is what the
/// Python does, since OpenSSL reads these same files.
const CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
];

/// Source: `CloudflareError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareError(pub String);

impl std::fmt::Display for CloudflareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fault(exc: impl std::fmt::Display) -> CloudflareError {
    CloudflareError(format!("Could not reach the Cloudflare API: {exc}"))
}

/// Python's `bool(value)` for a parsed JSON value.
///
/// Source: `if not payload.get("success")`. The Python does not ask whether
/// the field *is* `True`; it asks whether it is truthy, and the corpus has
/// bodies where it is `1` and `"yes"`. A port that wrote `== true` would
/// turn those into refusals.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Python's `str(value)` for a parsed JSON value, which is what an f-string
/// interpolates.
///
/// A missing key is `None`, and `str(None)` is `"None"` - which is why the
/// corpus contains `Cloudflare API error: None` and
/// `Cloudflare token status is 'None'`. Writing `""` there would quietly
/// turn "Cloudflare sent an error with no message" into "Cloudflare sent
/// nothing", and an operator reading the two needs them apart.
fn python_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(Value::Bool(false)) => "False".to_string(),
        Some(Value::String(s)) => s.clone(),
        // serde writes `5` for an integer and `5.0` for a float, which is
        // what `str()` gives for each - it keeps which one was parsed. The
        // one place the two part company is an exponent, where Python
        // writes `1e+100` and serde `1e100`; no field the panel reads is a
        // float at all, let alone that large.
        Some(Value::Number(n)) => n.to_string(),
        // Containers do not appear in these two messages on any body the
        // API produces. Rendering them as JSON is not Python's `repr`, and
        // is marked here rather than pretended otherwise.
        Some(other) => other.to_string(),
    }
}

/// One authenticated GET against the Cloudflare API.
///
/// Source: `_get`. The failure shapes are kept apart because they mean
/// different things to whoever reads them: an HTTP status says Cloudflare
/// answered and refused, a transport error says the machine could not get
/// there at all, and an unreadable body says something that was not
/// Cloudflare answered.
pub async fn get(path: &str, token: &str) -> Result<Value, CloudflareError> {
    let bytes = fetch(path, token).await?;
    // `json.loads` on a body that is not JSON raises `ValueError`, which is
    // the third arm of the Python's `except`. An empty body lands here too.
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| {
        CloudflareError("Cloudflare API returned an unreadable response".to_string())
    })?;
    check_success(&payload)?;
    Ok(payload)
}

/// The transport half of [`get`], separated so the JSON half can be tested
/// without a socket.
async fn fetch(path: &str, token: &str) -> Result<Vec<u8>, CloudflareError> {
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store()?)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(API_HOST)
        .map_err(fault)?
        .to_owned();
    let request = hyper::Request::builder()
        .method("GET")
        .uri(format!("{API_PREFIX}{path}"))
        .header(hyper::header::HOST, API_HOST)
        // `token.strip()` - a token pasted from a web page arrives with a
        // newline more often than not, and a header value carrying one is
        // refused by the builder rather than by Cloudflare.
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", pyunicode::trim(token)),
        )
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::USER_AGENT, "SNPanel SSL")
        .body(axum::body::Body::empty())
        // A token with a control character in it cannot go in a header.
        // The message says so without saying what the token was.
        .map_err(|_| CloudflareError("Cloudflare API token is not a usable header".to_string()))?;

    let exchange = async {
        let tcp = tokio::net::TcpStream::connect((API_HOST, 443))
            .await
            .map_err(fault)?;
        let tls = connector.connect(server_name, tcp).await.map_err(fault)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(fault)?;
        // The connection task owns the socket for as long as the body is
        // being read; dropping it early would truncate the response.
        let pump = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await.map_err(fault)?;
        let status = response.status();
        let body = response.into_body().collect().await.map_err(fault)?;
        pump.abort();
        // `urllib` raises `HTTPError` before the caller ever sees the body,
        // so the status wins over whatever the body might have said - a
        // Cloudflare error page served with a 502 is "HTTP 502", not
        // "unreadable response".
        if !status.is_success() {
            return Err(CloudflareError(format!(
                "Cloudflare API returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(body.to_bytes().to_vec())
    };

    match tokio::time::timeout(TIMEOUT, exchange).await {
        Ok(result) => result,
        // `socket.timeout` is a `TimeoutError`, whose `str` is `timed out`.
        Err(_) => Err(fault("timed out")),
    }
}

/// The trust store, read once; `None` when the machine has none.
pub(crate) fn system_roots() -> Option<Arc<rustls::RootCertStore>> {
    static ROOTS: std::sync::OnceLock<Option<Arc<rustls::RootCertStore>>> =
        std::sync::OnceLock::new();
    ROOTS
        .get_or_init(|| {
            for path in CA_BUNDLES {
                let Ok(bytes) = std::fs::read(path) else {
                    continue;
                };
                let mut store = rustls::RootCertStore::empty();
                let mut reader = std::io::BufReader::new(&bytes[..]);
                for cert in rustls_pemfile::certs(&mut reader).flatten() {
                    // A bundle with one unparsable entry is still a bundle:
                    // refusing one certificate must not throw away the hundred
                    // before it.
                    let _ = store.add(cert);
                }
                if !store.is_empty() {
                    return Some(Arc::new(store));
                }
            }
            None
        })
        .clone()
}

fn root_store() -> Result<Arc<rustls::RootCertStore>, CloudflareError> {
    // OpenSSL would have raised an `SSLError`, which is an `OSError`, which
    // is the Python's second arm.
    system_roots().ok_or_else(|| fault("no system CA bundle found"))
}

/// Source: the `if not payload.get("success")` tail of `_get`.
///
/// Cloudflare answers `200` with `"success": false` for a refusal, so the
/// status alone is not the answer - and the message shown is the **first**
/// error, because the list is ordered most-specific first and showing all
/// of them turns a readable refusal into a wall.
pub fn check_success(payload: &Value) -> Result<(), CloudflareError> {
    if truthy(payload.get("success")) {
        return Ok(());
    }
    // `payload.get("errors") or [{"message": "unknown error"}]`. The
    // Python's `or` is not reproduced as a truthiness test because it
    // cannot change the answer here: an empty list, a null and a value of
    // the wrong type all reach `None` through `as_array`/`first` anyway,
    // and so all three take the default below.
    let first = payload
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first());
    let message = match first {
        Some(entry) => python_str(entry.get("message")),
        None => "unknown error".to_string(),
    };
    Err(CloudflareError(format!("Cloudflare API error: {message}")))
}

/// Source: the status check in `verify_token`.
///
/// A token that exists but is disabled is refused with its status named,
/// because "expired" and "disabled" send an operator to different places.
pub fn check_token_status(payload: &Value) -> Result<(), CloudflareError> {
    // `(payload.get("result") or {}).get("status")`. The `or {}` needs no
    // counterpart: a missing `result`, a null one and an empty one all
    // read the status as absent, and so does anything that is not an
    // object - which is the one place this differs from the Python, where
    // a `result` that is a *list* raises `AttributeError` and answers 500.
    // No body from this API has one; the 400 here is the better answer.
    let status = payload
        .get("result")
        .and_then(|result| result.get("status"));
    if matches!(status, Some(Value::String(s)) if s == "active") {
        return Ok(());
    }
    Err(CloudflareError(format!(
        "Cloudflare token status is '{}', expected 'active'",
        python_str(status)
    )))
}

/// The domain as the search works on it.
///
/// Source: `(domain or "").strip().lower().rstrip(".")`. The order is the
/// Python's: stripping first means `"  example.com. "` loses the spaces
/// before the trailing dot is even visible to `rstrip`.
pub fn normalise_domain(domain: &str) -> String {
    pyunicode::trim(domain)
        .to_lowercase()
        .trim_end_matches('.')
        .to_string()
}

/// Every name to ask Cloudflare about, most specific first.
///
/// Source: the loop in `zone_for_domain`. It stops one label short -
/// `range(len(labels) - 1)` - so a bare TLD is never asked about, and it
/// asks by name rather than listing zones so an account with hundreds of
/// them still answers in one round trip per candidate.
pub fn zone_candidates(domain: &str) -> Vec<String> {
    let name = normalise_domain(domain);
    let labels: Vec<&str> = name.split('.').collect();
    // `range(len(labels) - 1)` is empty for a single label, which is what a
    // bare TLD, an empty string and a string of only dots all become.
    (0..labels.len().saturating_sub(1))
        .map(|start| labels[start..].join("."))
        .collect()
}

/// Which name the answer is taken to be.
///
/// Source: `result[0].get("name") or candidate`. A zone whose `name` came
/// back empty or missing is still a zone - the candidate asked for is the
/// name Cloudflare matched, so it is what certbot is given.
pub fn pick_zone(result: Option<&Value>, candidate: &str) -> Option<String> {
    let first = result
        .filter(|r| truthy(Some(r)))
        .and_then(Value::as_array)
        .and_then(|items| items.first())?;
    let name = first.get("name");
    if truthy(name) {
        // Only a string is a name. Anything else is truthy, so the Python
        // would return it - but a non-string zone name reaching certbot's
        // argv is worth refusing rather than reproducing, and no body from
        // this API has one.
        if let Some(text) = name.and_then(Value::as_str) {
            return Some(text.to_string());
        }
    }
    Some(candidate.to_string())
}

/// Source: the refusal at the end of `zone_for_domain`.
pub fn no_zone_error(domain: &str) -> CloudflareError {
    CloudflareError(format!(
        "No Cloudflare zone this token manages covers {}. \
         Check the token's zone scope, or that the domain's DNS is on Cloudflare.",
        normalise_domain(domain)
    ))
}

/// Source: `verify_token`.
///
/// The Python returns `payload["result"]`; no caller in the panel reads it,
/// so this returns nothing rather than handing a token's metadata to code
/// that has no use for it.
pub async fn verify_token(token: &str) -> Result<(), CloudflareError> {
    if pyunicode::trim(token).is_empty() {
        return Err(CloudflareError("Cloudflare API token is empty".to_string()));
    }
    let payload = get("/user/tokens/verify", token).await?;
    check_token_status(&payload)
}

/// Source: `zone_for_domain`.
pub async fn zone_for_domain(token: &str, domain: &str) -> Result<String, CloudflareError> {
    for candidate in zone_candidates(domain) {
        let payload = get(&format!("/zones?name={}", urlencode(&candidate)), token).await?;
        if let Some(zone) = pick_zone(payload.get("result"), &candidate) {
            return Ok(zone);
        }
    }
    Err(no_zone_error(domain))
}

/// Source: `urllib.parse.quote`, with its default safe set of `/`.
///
/// A zone name is letters, digits, hyphens and dots, so this is belt and
/// braces - but the name reaches a URL, and a port that trusted the input
/// because "domains are safe" would be one validation change away from
/// being wrong.
pub fn urlencode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/cloudflare.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the cloudflare corpus"))
            .expect("the corpus parses")
    }

    /// The body half of `_get`, which is every case that does not need a
    /// socket: is this a success, and if not, what does it say.
    #[test]
    fn a_refusal_inside_an_http_200_is_still_a_refusal() {
        let corpus = corpus();
        let cases = corpus["check_success"].as_array().expect("the cases");
        assert_eq!(cases.len(), 14, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let payload = &case["payload"];
            let got = check_success(payload);
            match case.get("error").and_then(Value::as_str) {
                Some(want) => {
                    if got.as_ref().err().map(|e| e.0.as_str()) != Some(want) {
                        failures.push(format!("{payload}: python {want:?}, rust {got:?}"));
                    }
                }
                None => {
                    if got.is_err() {
                        failures.push(format!("{payload}: python accepted it, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // The three the corpus makes a point of, restated so a reader does
        // not have to open the JSON to see what is being claimed.
        assert!(
            check_success(&json!({"success": 1})).is_ok(),
            "`1` is truthy to Python, so it is a success"
        );
        assert_eq!(
            check_success(&json!({"success": false, "errors": [{"code": 1000}]}))
                .unwrap_err()
                .0,
            "Cloudflare API error: None",
            "an error with no message interpolates `None`, not an empty string"
        );
        assert_eq!(
            check_success(&json!({})).unwrap_err().0,
            "Cloudflare API error: unknown error",
            "no `errors` key at all falls back to the Python's default list"
        );
    }

    /// A token that is not `active` is named, not merely refused.
    #[test]
    fn a_token_status_other_than_active_is_reported() {
        let corpus = corpus();
        let cases = corpus["verify_token"].as_array().expect("the cases");
        assert_eq!(cases.len(), 12, "the corpus changed size");

        let mut checked = 0;
        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            // The empty-token cases never reach a payload; they are
            // covered by `an_empty_token_never_reaches_the_network`.
            let Some(payload) = case.get("payload").filter(|p| !p.is_null()) else {
                continue;
            };
            checked += 1;
            let got = check_token_status(payload);
            match case.get("error").and_then(Value::as_str) {
                Some(want) => {
                    if got.as_ref().err().map(|e| e.0.as_str()) != Some(want) {
                        failures.push(format!("{payload}: python {want:?}, rust {got:?}"));
                    }
                }
                None => {
                    if got.is_err() {
                        failures.push(format!("{payload}: python accepted it, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert_eq!(checked, 8, "the payload-carrying cases");

        // A missing `result`, a null one and an empty one all say `'None'`
        // rather than three different things.
        for payload in [
            json!({"success": true}),
            json!({"success": true, "result": null}),
            json!({"success": true, "result": {}}),
        ] {
            assert_eq!(
                check_token_status(&payload).unwrap_err().0,
                "Cloudflare token status is 'None', expected 'active'"
            );
        }
    }

    /// An empty token is refused before a socket is opened.
    ///
    /// Not a nicety: a blank token would otherwise be sent as
    /// `Authorization: Bearer`, and the panel would be asking Cloudflare to
    /// tell it what an unauthenticated caller can see.
    #[tokio::test]
    async fn an_empty_token_never_reaches_the_network() {
        let corpus = corpus();
        let mut checked = 0;
        for case in corpus["verify_token"].as_array().expect("the cases") {
            if !case["payload"].is_null() {
                continue;
            }
            checked += 1;
            let token = case["token"].as_str().unwrap_or("");
            let got = verify_token(token).await;
            assert_eq!(
                got.unwrap_err().0,
                case["error"].as_str().expect("the message"),
                "for {token:?}"
            );
        }
        assert_eq!(checked, 4, "the empty-token cases");
        // `str.strip()` is Python's `isspace`, not Unicode `White_Space`:
        // `\x1c`-`\x1f` are whitespace to the one and not the other, so a
        // token of nothing but those is empty to the Python and would be a
        // live `Bearer` header to a port that reached for `str::trim`.
        assert_eq!(
            verify_token("\u{1c}\u{1d}\u{1e}\u{1f}")
                .await
                .unwrap_err()
                .0,
            "Cloudflare API token is empty"
        );
    }

    /// Which names are asked about, and in which order.
    ///
    /// Most specific first, so `blog.shop.example.com` finds
    /// `shop.example.com` when the token manages both that and
    /// `example.com` - the narrower zone is the one whose DNS the customer
    /// actually controls. The loop stops one label short, so a bare TLD is
    /// never asked about: `?name=com` would match nothing and the round
    /// trip is wasted.
    #[test]
    fn the_search_asks_the_pythons_names_in_the_pythons_order() {
        let corpus = corpus();
        let cases = corpus["zone_for_domain"].as_array().expect("the cases");
        assert_eq!(cases.len(), 15, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let domain = case["domain"].as_str().unwrap_or("");
            // The corpus records the *encoded* names the real loop asked
            // for, so this checks the candidates and the quoting together.
            let want: Vec<String> = case["encoded"]
                .as_array()
                .expect("the encoded names")
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let got: Vec<String> = zone_candidates(domain)
                .iter()
                .map(|c| urlencode(c))
                .collect();
            if got != want {
                failures.push(format!("{domain:?}: python {want:?}, rust {got:?}"));
            }
            // Every case in the corpus answered with an empty result, so
            // every one ends in the refusal.
            let want_error = case["error"].as_str().expect("the refusal");
            let got_error = no_zone_error(domain).0;
            if got_error != want_error {
                failures.push(format!(
                    "{domain:?}: python {want_error:?}, rust {got_error:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        assert_eq!(
            zone_candidates("blog.shop.example.com"),
            vec!["blog.shop.example.com", "shop.example.com", "example.com"]
        );
        assert!(
            zone_candidates("com").is_empty(),
            "a bare label is never asked about"
        );
        assert!(
            zone_candidates("trailing...").is_empty(),
            "`rstrip('.')` takes every trailing dot, leaving one label"
        );
    }

    /// Which name comes back when Cloudflare matches.
    #[test]
    fn the_matched_zone_name_is_the_pythons() {
        let corpus = corpus();
        let cases = corpus["zone_pick"].as_array().expect("the cases");
        assert_eq!(cases.len(), 6, "the corpus changed size");

        for case in cases {
            // Every case in the corpus was asked about `a.example.com`,
            // whose first candidate is the whole name.
            let candidate = "a.example.com";
            let got = pick_zone(Some(&case["result"]), candidate);
            let want = case["value"].as_str().expect("the zone");
            assert_eq!(got.as_deref(), Some(want), "for {}", case["case"]);
        }

        // No match at all keeps the search going rather than answering.
        assert_eq!(pick_zone(Some(&json!([])), "example.com"), None);
        assert_eq!(pick_zone(None, "example.com"), None);
        // A zone whose name came back blank is still the zone that matched.
        assert_eq!(
            pick_zone(Some(&json!([{"name": ""}])), "example.com").as_deref(),
            Some("example.com")
        );
    }

    /// The token never appears in an error.
    ///
    /// Every message this module can produce is built from a status code, a
    /// zone name or a string Cloudflare sent. A token in one of them would
    /// reach the journal of every machine that ever failed a renewal, and
    /// that journal is readable by more people than the panel's database.
    #[test]
    fn no_error_message_carries_the_token() {
        let secret = "cf-secret-token-value";
        let messages = [
            check_success(&json!({"success": false, "errors": [{"message": "bad"}]}))
                .unwrap_err()
                .0,
            check_token_status(&json!({"result": {"status": "expired"}}))
                .unwrap_err()
                .0,
            fault("timed out").0,
            CloudflareError("Cloudflare API returned HTTP 403".to_string()).0,
        ];
        for message in &messages {
            assert!(!message.contains(secret), "{message}");
            assert!(
                !message.to_lowercase().contains("bearer"),
                "no message quotes the header: {message}"
            );
        }
        // The one message that *does* carry caller input carries the
        // domain, which is already public, and nothing else.
        let refusal = no_zone_error("example.com").0;
        assert!(refusal.contains("example.com") && !refusal.contains(secret));
    }

    /// A zone name reaches a URL, so it is encoded on the way.
    #[test]
    fn a_zone_name_is_percent_encoded_like_quote() {
        let corpus = corpus();
        let cases = corpus["urlencode"].as_array().expect("the cases");
        assert_eq!(cases.len(), 17, "the corpus changed size");

        for case in cases {
            let raw = case["raw"].as_str().unwrap_or("");
            let want = case["encoded"].as_str().unwrap_or("");
            assert_eq!(urlencode(raw), want, "for {raw:?}");
        }
        // The safe set is `quote`'s default, which keeps `/` - and `+`,
        // which `quote_plus` would have turned into a space, is escaped.
        assert_eq!(urlencode("a/b"), "a/b");
        assert_eq!(urlencode("a+b"), "a%2Bb");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        // The escape is two hex digits, upper case. A byte below `\x10`
        // is the only place a missing zero shows, and `%9` is not what
        // `quote` writes for a tab.
        assert_eq!(urlencode("a\tb"), "a%09b");
        assert_eq!(urlencode("\u{1}\u{f}\u{10}"), "%01%0F%10");
    }

    /// Python truthiness, which is the whole of the `success` check.
    #[test]
    fn truthiness_is_pythons() {
        for value in [
            json!(true),
            json!(1),
            json!(-1),
            json!(0.5),
            json!("no"),
            json!([0]),
            json!({"a": 1}),
        ] {
            assert!(truthy(Some(&value)), "{value} is truthy to Python");
        }
        for value in [
            json!(false),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!({}),
            json!(null),
        ] {
            assert!(!truthy(Some(&value)), "{value} is falsy to Python");
        }
        assert!(!truthy(None), "a missing key is `None`, which is falsy");
    }

    /// What an f-string interpolates, which is what the two messages say.
    #[test]
    fn interpolation_is_pythons_str() {
        assert_eq!(python_str(None), "None");
        assert_eq!(python_str(Some(&json!(null))), "None");
        assert_eq!(python_str(Some(&json!(true))), "True");
        assert_eq!(python_str(Some(&json!(false))), "False");
        assert_eq!(python_str(Some(&json!("active"))), "active");
        assert_eq!(python_str(Some(&json!(5))), "5");
        assert_eq!(python_str(Some(&json!(5.0))), "5.0");
        assert_eq!(python_str(Some(&json!(1.5))), "1.5");
    }
}
