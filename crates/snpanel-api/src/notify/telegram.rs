//! The Telegram Bot API, as far as notifications need it: who the bot is,
//! a message to a chat, and the updates a link is found in.
//!
//! Not in the Python. Built as the Cloudflare client is - hyper over
//! `tokio-rustls`, the machine's trust store - and, like it, **the token is
//! never in an error or a log**: it is in every request's path, so no URL is
//! ever printed.
//!
//! `SNPANEL_TELEGRAM_API_BASE` in the panel's environment points it at
//! another server - `http://127.0.0.1:8099` for the end-to-end check, which
//! has no bot. It is read from the process environment only, which is the
//! administrator's.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

const DEFAULT_BASE: &str = "https://api.telegram.org";
const TIMEOUT: Duration = Duration::from_secs(20);
/// Telegram's own limit on a message.
pub const MAX_TEXT: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramError(pub String);

impl std::fmt::Display for TelegramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail(message: impl Into<String>) -> TelegramError {
    TelegramError(message.into())
}

/// Whether `token` looks like a bot token - `<digits>:<letters, digits, _ and ->`
/// - which is also what keeps it from changing the path it goes in.
pub fn token_shape_ok(token: &str) -> bool {
    let Some((id, secret)) = token.split_once(':') else {
        return false;
    };
    !id.is_empty()
        && id.len() <= 20
        && id.chars().all(|c| c.is_ascii_digit())
        && secret.len() >= 20
        && secret.len() <= 100
        && secret
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// A chat id as Telegram gives them: a number, negative for a group, or a
/// channel's `@name`.
pub fn chat_shape_ok(chat: &str) -> bool {
    let digits = chat.strip_prefix('-').unwrap_or(chat);
    (!digits.is_empty() && digits.len() <= 20 && digits.chars().all(|c| c.is_ascii_digit()))
        || (chat.len() > 5
            && chat.len() <= 33
            && chat.starts_with('@')
            && chat[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// Where the API is: scheme, host, port.
fn base() -> (bool, String, u16) {
    let raw = std::env::var("SNPANEL_TELEGRAM_API_BASE").unwrap_or_default();
    let raw = if raw.trim().is_empty() {
        DEFAULT_BASE.to_string()
    } else {
        raw.trim().trim_end_matches('/').to_string()
    };
    let (tls, rest) = match raw.split_once("://") {
        Some(("http", rest)) => (false, rest.to_string()),
        Some((_, rest)) => (true, rest.to_string()),
        None => (true, raw.clone()),
    };
    let default_port = if tls { 443 } else { 80 };
    match rest.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (tls, host.to_string(), port.parse().unwrap_or(default_port))
        }
        _ => (tls, rest, default_port),
    }
}

/// What Telegram answered, as its `{"ok": false, "description": ...}` says it.
fn verdict(status: u16, body: &[u8]) -> Result<Value, TelegramError> {
    let parsed: Value = serde_json::from_slice(body).map_err(|_| {
        fail(format!(
            "Telegram answered HTTP {status} with something that is not JSON"
        ))
    })?;
    if parsed.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(parsed.get("result").cloned().unwrap_or(Value::Null));
    }
    let described = parsed
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("no reason given");
    let described: String = described
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    Err(fail(match status {
        401 | 404 => "Telegram does not know this bot token".to_string(),
        _ => format!("Telegram refused: {described}"),
    }))
}

/// One Bot API method, with a JSON body.
pub async fn call(token: &str, method: &str, body: &Value) -> Result<Value, TelegramError> {
    use hyper_util::rt::TokioIo;

    let token = token.trim();
    if !token_shape_ok(token) {
        return Err(fail(
            "That is not a bot token: it looks like 123456789:AA...",
        ));
    }
    let (tls, host, port) = base();
    let payload = serde_json::to_vec(body).map_err(|_| fail("A message could not be written"))?;
    let request = hyper::Request::builder()
        .method("POST")
        .uri(format!("/bot{token}/{method}"))
        .header(hyper::header::HOST, host.as_str())
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::USER_AGENT, "SNPanel")
        .body(axum::body::Body::from(payload))
        .map_err(|_| fail("A request to Telegram could not be made"))?;

    let exchange = async {
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| fail(format!("Cannot reach Telegram: {e}")))?;
        let (status, bytes) = if tls {
            let roots = crate::cloudflare::system_roots().ok_or_else(|| {
                fail("This machine has no trusted certificates to check Telegram's against")
            })?;
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| fail("Telegram's address cannot be checked against a certificate"))?;
            let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, tcp)
                .await
                .map_err(|e| fail(format!("The TLS handshake with Telegram failed: {e}")))?;
            round_trip(TokioIo::new(stream), request).await?
        } else {
            round_trip(TokioIo::new(tcp), request).await?
        };
        Ok::<_, TelegramError>((status, bytes))
    };
    let (status, bytes) = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| fail("Telegram did not answer in time"))??;
    verdict(status, &bytes)
}

async fn round_trip<I>(
    io: I,
    request: hyper::Request<axum::body::Body>,
) -> Result<(u16, Vec<u8>), TelegramError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use http_body_util::BodyExt;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| fail(format!("Cannot talk to Telegram: {e}")))?;
    let pump = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| fail(format!("Cannot talk to Telegram: {e}")))?;
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| fail(format!("Telegram's answer broke off: {e}")))?;
    pump.abort();
    Ok((status, body.to_bytes().to_vec()))
}

/// The bot's `@username`: what proves a token works, and what a link goes to.
pub async fn bot_username(token: &str) -> Result<String, TelegramError> {
    let me = call(token, "getMe", &json!({})).await?;
    me.get("username")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| fail("Telegram did not say who the bot is"))
}

/// A message to a chat, in Telegram's HTML: `<b>`, `<i>`, `<code>`, `<a>`.
pub async fn send(token: &str, chat: &str, html: &str) -> Result<(), TelegramError> {
    let text: String = html.chars().take(MAX_TEXT).collect();
    call(
        token,
        "sendMessage",
        &json!({
            "chat_id": chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        }),
    )
    .await
    .map(|_| ())
}

/// A `/start <code>` somebody sent the bot, and from which chat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub update_id: i64,
    pub code: String,
    pub chat_id: String,
    /// `@username`, or the name, for the page.
    pub who: String,
}

/// What the bot has been sent since `offset`: the `/start <code>` messages
/// among it, and the offset that confirms all of it read.
pub async fn starts(token: &str, offset: i64) -> Result<(Vec<Start>, i64), TelegramError> {
    let updates = call(
        token,
        "getUpdates",
        &json!({ "offset": offset, "timeout": 0, "allowed_updates": ["message"] }),
    )
    .await?;
    Ok(read_starts(&updates, offset))
}

fn read_starts(updates: &Value, offset: i64) -> (Vec<Start>, i64) {
    let mut next = offset;
    let mut found = Vec::new();
    for update in updates.as_array().into_iter().flatten() {
        let Some(id) = update.get("update_id").and_then(Value::as_i64) else {
            continue;
        };
        next = next.max(id + 1);
        let Some(message) = update.get("message") else {
            continue;
        };
        let text = message.get("text").and_then(Value::as_str).unwrap_or("");
        let mut words = text.split_whitespace();
        let command = words.next().unwrap_or("");
        // `/start CODE`, or `/start@bot CODE` from a group.
        if command != "/start" && !command.starts_with("/start@") {
            continue;
        }
        let Some(code) = words.next() else {
            continue;
        };
        let Some(chat_id) = message
            .get("chat")
            .and_then(|c| c.get("id"))
            .and_then(Value::as_i64)
        else {
            continue;
        };
        let chat = message.get("chat").cloned().unwrap_or(Value::Null);
        let from = message.get("from").cloned().unwrap_or(Value::Null);
        let who = chat
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                from.get("username")
                    .and_then(Value::as_str)
                    .map(|u| format!("@{u}"))
            })
            .or_else(|| {
                from.get("first_name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| chat_id.to_string());
        found.push(Start {
            update_id: id,
            code: code.to_string(),
            chat_id: chat_id.to_string(),
            who: who.chars().filter(|c| !c.is_control()).take(64).collect(),
        });
    }
    (found, next)
}

/// Text for Telegram's HTML: the three characters it reads as markup.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_and_a_chat_have_their_shapes() {
        assert!(token_shape_ok(
            "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"
        ));
        assert!(!token_shape_ok("123456789:AAH/../../getMe"));
        assert!(!token_shape_ok("not a token"));
        assert!(!token_shape_ok(":AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        assert!(chat_shape_ok("123456789"));
        assert!(chat_shape_ok("-1001234567890"));
        assert!(chat_shape_ok("@snpanel_alerts"));
        assert!(!chat_shape_ok("12 34"));
        assert!(!chat_shape_ok("@a"));
        assert!(!chat_shape_ok("-"));
    }

    #[test]
    fn telegrams_refusals_are_its_own_words_and_never_the_token() {
        let err = verdict(
            400,
            br#"{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}"#,
        )
        .unwrap_err();
        assert_eq!(err.0, "Telegram refused: Bad Request: chat not found");
        let err = verdict(
            401,
            br#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#,
        )
        .unwrap_err();
        assert_eq!(err.0, "Telegram does not know this bot token");
        assert_eq!(
            verdict(200, br#"{"ok":true,"result":{"username":"snpanel_bot"}}"#).unwrap(),
            json!({"username": "snpanel_bot"})
        );
    }

    #[test]
    fn a_start_with_a_code_is_found_among_the_updates() {
        let updates = json!([
            {"update_id": 10, "message": {"text": "hello", "chat": {"id": 1}}},
            {"update_id": 11, "message": {"text": "/start ABC123", "chat": {"id": 42, "type": "private"},
                "from": {"id": 42, "username": "alice", "first_name": "Alice"}}},
            {"update_id": 12, "message": {"text": "/start@snpanel_bot XYZ", "chat": {"id": -100, "title": "Ops team"},
                "from": {"id": 43, "first_name": "Bob"}}},
            {"update_id": 13, "edited_message": {"text": "/start NOPE", "chat": {"id": 5}}},
        ]);
        let (found, next) = read_starts(&updates, 9);
        assert_eq!(next, 14);
        assert_eq!(found.len(), 2);
        assert_eq!(
            (
                found[0].code.as_str(),
                found[0].chat_id.as_str(),
                found[0].who.as_str()
            ),
            ("ABC123", "42", "@alice")
        );
        assert_eq!(
            (
                found[1].code.as_str(),
                found[1].chat_id.as_str(),
                found[1].who.as_str()
            ),
            ("XYZ", "-100", "Ops team")
        );
    }

    #[test]
    fn markup_in_a_value_stays_text() {
        assert_eq!(escape("<b>&co</b>"), "&lt;b&gt;&amp;co&lt;/b&gt;");
    }
}
