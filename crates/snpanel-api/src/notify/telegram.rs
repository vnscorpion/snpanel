//! The Telegram Bot API, as far as notifications need it: who the bot is,
//! a chat and what it is called, the chats that wrote to the bot, and a
//! message to a chat.
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
    let described: String = parsed
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    Err(fail(match status {
        401 | 404 => "Telegram does not know this bot token".to_string(),
        _ if described.trim().is_empty() => {
            format!("Telegram refused without saying why (HTTP {status})")
        }
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

/// A chat the bot can write in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chat {
    /// As Telegram numbers it: a person's, a group's (negative), a channel's.
    pub id: String,
    /// `private`, `group`, `supergroup` or `channel`.
    pub kind: String,
    /// A group's or channel's title, or a person's name and `@username`.
    pub name: String,
}

/// What a chat is called, from Telegram's `Chat` object.
pub fn chat_name(chat: &Value) -> String {
    let field = |key: &str| chat.get(key).and_then(Value::as_str).unwrap_or("").trim();
    let name = if !field("title").is_empty() {
        field("title").to_string()
    } else {
        let person = format!("{} {}", field("first_name"), field("last_name"))
            .trim()
            .to_string();
        match (person.is_empty(), field("username")) {
            (false, "") => person,
            (false, user) => format!("{person} (@{user})"),
            (true, "") => String::new(),
            (true, user) => format!("@{user}"),
        }
    };
    name.chars().filter(|c| !c.is_control()).take(80).collect()
}

fn read_chat(chat: &Value) -> Option<Chat> {
    let id = chat.get("id").and_then(Value::as_i64)?;
    Some(Chat {
        id: id.to_string(),
        kind: chat
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("private")
            .chars()
            .filter(char::is_ascii_lowercase)
            .take(12)
            .collect(),
        name: chat_name(chat),
    })
}

/// The chat `chat` names - a number, or a channel's `@name` - as the bot
/// sees it: which proves the bot can reach it, and says what it is called.
pub async fn chat(token: &str, chat: &str) -> Result<Chat, TelegramError> {
    let found = call(token, "getChat", &json!({ "chat_id": chat })).await?;
    read_chat(&found).ok_or_else(|| fail("Telegram did not say which chat that is"))
}

/// Where the updates that name a chat keep it.
const UPDATES_WITH_A_CHAT: [&str; 4] = [
    "message",
    "edited_message",
    "channel_post",
    "my_chat_member",
];

/// The chats that wrote to the bot, or that it was added to, in the last
/// day - newest first, each once. Nothing is confirmed as read, so looking
/// changes nothing: Telegram keeps an unconfirmed update for a day.
pub async fn recent_chats(token: &str) -> Result<Vec<Chat>, TelegramError> {
    let updates = call(
        token,
        "getUpdates",
        &json!({ "timeout": 0, "limit": 100, "allowed_updates": UPDATES_WITH_A_CHAT }),
    )
    .await?;
    Ok(read_chats(&updates))
}

fn read_chats(updates: &Value) -> Vec<Chat> {
    let mut found: Vec<Chat> = Vec::new();
    for update in updates.as_array().into_iter().flatten().rev() {
        let Some(chat) = UPDATES_WITH_A_CHAT
            .iter()
            .find_map(|key| update.get(*key).and_then(|m| m.get("chat")))
            .and_then(read_chat)
        else {
            continue;
        };
        if !found.iter().any(|c| c.id == chat.id) {
            found.push(chat);
        }
    }
    found
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
        // Put together here: a whole token written out in the source is
        // what secret scanners report, whoever's it is.
        let secret = "Ab1_-".repeat(7);
        assert!(token_shape_ok(&format!("123456789:{secret}")));
        assert!(!token_shape_ok("123456789:AAH/../../getMe"));
        assert!(!token_shape_ok("not a token"));
        assert!(!token_shape_ok(&format!(":{secret}")));
        assert!(!token_shape_ok(&format!("123456789:{}", &secret[..19])));
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
    fn the_chats_that_wrote_to_the_bot_newest_first_each_once() {
        let updates = json!([
            {"update_id": 10, "message": {"text": "hi", "chat": {"id": 42, "type": "private",
                "first_name": "Alice", "last_name": "Nguyen", "username": "alice"}}},
            {"update_id": 11, "my_chat_member": {"chat": {"id": -1001234567890_i64, "type": "supergroup",
                "title": "Ops team"}}},
            {"update_id": 12, "channel_post": {"text": "x", "chat": {"id": -1009876543210_i64, "type": "channel",
                "title": "Alerts", "username": "snpanel_alerts"}}},
            {"update_id": 13, "message": {"text": "again", "chat": {"id": 42, "type": "private",
                "first_name": "Alice"}}},
            {"update_id": 14, "callback_query": {"id": "1"}},
        ]);
        let chats = read_chats(&updates);
        let seen: Vec<(&str, &str, &str)> = chats
            .iter()
            .map(|c| (c.id.as_str(), c.kind.as_str(), c.name.as_str()))
            .collect();
        assert_eq!(
            seen,
            [
                ("42", "private", "Alice"),
                ("-1009876543210", "channel", "Alerts"),
                ("-1001234567890", "supergroup", "Ops team"),
            ]
        );
        assert_eq!(
            chat_name(&json!({"first_name": "Alice", "last_name": "Nguyen", "username": "alice"})),
            "Alice Nguyen (@alice)"
        );
        assert_eq!(chat_name(&json!({"username": "bob"})), "@bob");
        assert_eq!(chat_name(&json!({"title": "Ops\nteam"})), "Opsteam");
    }

    #[test]
    fn markup_in_a_value_stays_text() {
        assert_eq!(escape("<b>&co</b>"), "&lt;b&gt;&amp;co&lt;/b&gt;");
    }
}
