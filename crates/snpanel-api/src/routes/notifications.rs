//! `/api/notifications*` - the Notifications addon's page, which is the
//! administrators' alone.
//!
//! Not in the Python. How messages go out - the SMTP server and the
//! addresses it sends to, the Telegram bot and the chat it writes in - what
//! is told and in which language, a test message, and what was sent. A
//! customer is answered 403 everywhere: nothing is sent to customers. See
//! `crate::notify`.
//!
//! Only `GET /api/notifications` answers while the addon is not installed,
//! so the page can say so; everything else is a 409 until it is.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth::CurrentUser;
use crate::errors::{bad_request, conflict, error, internal_error, not_enough_permissions};
use crate::notify::{self, smtp, telegram, Channels, Lang, SmtpConfig, TelegramConfig};
use crate::state::AppState;

/// Between two test messages from one administrator.
const TEST_GAP: Duration = Duration::from_secs(5);
/// How many addresses e-mail goes to, at most.
const MAX_ADDRESSES: usize = 20;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(overview).fallback(crate::fallback))
        .route(
            "/notifications/smtp",
            put(save_smtp).delete(remove_smtp).fallback(crate::fallback),
        )
        .route(
            "/notifications/telegram",
            put(save_telegram)
                .delete(remove_telegram)
                .fallback(crate::fallback),
        )
        .route(
            "/notifications/telegram/chats",
            post(find_chats).fallback(crate::fallback),
        )
        .route(
            "/notifications/settings",
            put(save_settings).fallback(crate::fallback),
        )
        .route("/notifications/test", post(test).fallback(crate::fallback))
        .route("/notifications/log", get(log).fallback(crate::fallback))
}

fn not_installed() -> Response {
    conflict("The Notifications addon is not installed")
}

/// Administrators only: nothing here is a customer's.
fn administrator(current: &CurrentUser) -> Result<(), Response> {
    if current.user.is_admin() {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

/// An administrator, and the addon installed.
fn admin_only(current: &CurrentUser) -> Result<(), Response> {
    administrator(current)?;
    if !notify::installed() {
        return Err(not_installed());
    }
    Ok(())
}

async fn caller(state: &AppState, req: Request) -> Result<(CurrentUser, Value), Response> {
    let (mut parts, body) = req.into_parts();
    let current = CurrentUser::from_parts(&mut parts, state).await?;
    admin_only(&current)?;
    let payload = super::auth::read_json_body(body).await?;
    Ok((current, payload))
}

fn text<'a>(payload: &'a Value, key: &str) -> &'a str {
    payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
}

// ---------------------------------------------------------------- reading

/// The page's whole view.
async fn view(state: &AppState) -> Value {
    let channels = notify::load_channels();
    let smtp = channels.smtp.as_ref();
    let bot = channels.telegram.as_ref();
    json!({
        "installed": notify::installed(),
        "ready": channels.ready(),
        "email": {
            "ready": smtp.is_some(),
            "smtp": smtp.map(|s| json!({
                "host": s.host,
                "port": s.port,
                "security": s.security,
                "username": s.username,
                "password_set": !s.password.is_empty(),
                "from_address": s.from_address,
                "from_name": s.from_name,
            })),
            "to": smtp.map(|s| s.to.clone()).unwrap_or_default(),
            // Where it goes when no address is set.
            "administrators": notify::admin_addresses(state).await,
        },
        "telegram": {
            "ready": channels.telegram_chat().is_some(),
            "bot": bot.map(|b| b.username.clone()),
            "chat_id": bot.map(|b| b.chat_id.clone()).unwrap_or_default(),
            "chat_name": bot.map(|b| b.chat_name.clone()).unwrap_or_default(),
        },
        "language": channels.language.clone().unwrap_or_else(|| "vi".into()),
        "events": notify::KINDS.iter().map(|k| json!({
            "key": k.key,
            "group": k.group,
            "default": k.default_on,
            "on": channels.wants(k.key),
        })).collect::<Vec<_>>(),
    })
}

async fn answer(state: &AppState) -> Response {
    Json(view(state).await).into_response()
}

async fn overview(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = administrator(&current) {
        return r;
    }
    answer(&state).await
}

async fn log(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = admin_only(&current) {
        return r;
    }
    match state.db.notifications().recent(100).await {
        Ok(rows) => Json(json!({
            "items": rows.iter().map(|r| json!({
                "id": r.id,
                "created_at": r.created_at,
                "event": r.event,
                "channel": r.channel,
                "target": r.target,
                "subject": r.subject,
                "status": r.status,
                "detail": r.detail,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("reading the notification log failed: {e}");
            internal_error()
        }
    }
}

// ---------------------------------------------------------------- e-mail

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// The addresses to send to - a list, or one text of them separated by
/// commas, semicolons or spaces - each checked, each once.
fn addresses(payload: &Value) -> Result<Vec<String>, Response> {
    let given: Vec<String> = match payload.get("to") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(list)) => list
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(str::to_string)
            .collect(),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                let Some(address) = item.as_str() else {
                    return Err(bad_request("The addresses to send to are e-mail addresses"));
                };
                out.push(address.to_string());
            }
            out
        }
        Some(_) => return Err(bad_request("The addresses to send to are e-mail addresses")),
    };
    let mut out: Vec<String> = Vec::new();
    for address in given.iter().map(|a| a.trim()).filter(|a| !a.is_empty()) {
        if !smtp::valid_address(address) {
            return Err(bad_request(&format!("{address} is not an e-mail address")));
        }
        if !out.iter().any(|a| a.eq_ignore_ascii_case(address)) {
            out.push(address.to_string());
        }
    }
    if out.len() > MAX_ADDRESSES {
        return Err(bad_request(&format!(
            "E-mail goes to at most {MAX_ADDRESSES} addresses"
        )));
    }
    Ok(out)
}

fn saved(channels: &Channels) -> Result<(), Response> {
    notify::save_channels(channels).map_err(|e| {
        tracing::error!("saving the notification channels failed: {e}");
        internal_error()
    })
}

async fn save_smtp(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let host = text(&payload, "host").to_ascii_lowercase();
    if !host_ok(&host) {
        return bad_request("The SMTP server is a host name or an address, such as smtp.gmail.com");
    }
    let port = payload.get("port").and_then(Value::as_u64).unwrap_or(0);
    let Ok(port) = u16::try_from(port) else {
        return bad_request("The port is a number from 1 to 65535");
    };
    if port == 0 {
        return bad_request("The port is a number from 1 to 65535");
    }
    let security = text(&payload, "security");
    let Some(parsed) = smtp::Security::parse(security) else {
        return bad_request("Security is starttls, tls or none");
    };
    let username = text(&payload, "username").to_string();
    if username.chars().any(char::is_control) || username.len() > 255 {
        return bad_request("The user name cannot have line breaks in it");
    }
    let from_address = text(&payload, "from_address").to_string();
    if !smtp::valid_address(&from_address) {
        return bad_request("The sender is an e-mail address, such as panel@example.com");
    }
    let from_name = text(&payload, "from_name").to_string();
    if from_name.chars().count() > 80 {
        return bad_request("The sender's name is at most 80 characters");
    }
    let to = match addresses(&payload) {
        Ok(to) => to,
        Err(r) => return r,
    };
    let mut channels = notify::load_channels();
    // A blank password keeps the one saved - the page never gets it back to
    // send again - unless the user name changed, when it goes.
    let given = payload
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or("");
    if given.contains(['\r', '\n', '\0']) {
        return bad_request("The password cannot have line breaks in it");
    }
    let password = match channels.smtp.as_ref() {
        _ if !given.is_empty() => notify::conceal(&state, given),
        Some(old) if old.username == username && old.host == host => old.password.clone(),
        _ => String::new(),
    };
    if parsed == smtp::Security::None && !username.is_empty() && !smtp::is_loopback(&host) {
        return bad_request(
            "Without encryption the password would cross the network in the clear: choose STARTTLS or SSL/TLS",
        );
    }
    channels.smtp = Some(SmtpConfig {
        host,
        port,
        security: parsed.name().to_string(),
        username,
        password,
        from_address,
        from_name,
        to,
    });
    if let Err(r) = saved(&channels) {
        return r;
    }
    audit(&state, &current, "notifications_smtp", "saved").await;
    answer(&state).await
}

async fn remove_smtp(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = admin_only(&current) {
        return r;
    }
    let mut channels = notify::load_channels();
    channels.smtp = None;
    if let Err(r) = saved(&channels) {
        return r;
    }
    audit(&state, &current, "notifications_smtp", "removed").await;
    answer(&state).await
}

// ---------------------------------------------------------------- Telegram

/// What Telegram refused, and what to do about it.
fn telegram_failed(why: &str) -> Response {
    let said = why.to_ascii_lowercase();
    if said.contains("chat not found") {
        return error(
            StatusCode::BAD_GATEWAY,
            "Telegram does not know that chat for this bot. Open the bot in Telegram and press Start - or add it to the group or channel - then try again.",
        );
    }
    if said.contains("blocked by the user") {
        return error(
            StatusCode::BAD_GATEWAY,
            "That person has blocked the bot. Unblock it in Telegram, then try again.",
        );
    }
    if said.contains("not a member") || said.contains("kicked") {
        return error(
            StatusCode::BAD_GATEWAY,
            "The bot is not in that group or channel. Add it - to a channel as an administrator that may post - then try again.",
        );
    }
    if said.contains("not enough rights") || said.contains("administrator rights") {
        return error(
            StatusCode::BAD_GATEWAY,
            "The bot may not post in that chat. Let it post - in a channel, make it an administrator - then try again.",
        );
    }
    if said.contains("webhook") {
        return error(
            StatusCode::BAD_GATEWAY,
            "This bot hands what it is sent to a webhook, so the panel cannot see who wrote to it. Enter the chat ID yourself.",
        );
    }
    if said.contains("conflict") {
        return error(
            StatusCode::BAD_GATEWAY,
            "Another program is reading this bot's messages. Give the panel a bot of its own, or enter the chat ID yourself.",
        );
    }
    error(StatusCode::BAD_GATEWAY, why)
}

/// The token given, or - when none is - the one saved, in the clear.
fn token_to_use(state: &AppState, given: &str) -> Result<String, Response> {
    if !given.is_empty() {
        if !telegram::token_shape_ok(given) {
            return Err(bad_request(
                "That is not a bot token: @BotFather gives one like 123456789:AA...",
            ));
        }
        return Ok(given.to_string());
    }
    let Some(bot) = notify::load_channels().telegram else {
        return Err(bad_request("Paste the bot token @BotFather gave you"));
    };
    notify::bot_token(state, &bot)
        .map_err(|_| conflict("The saved bot token cannot be read: paste it again"))
}

/// A bot and the chat it writes in, saved once both are proved: Telegram
/// knows the token, the bot can see the chat, and a test message reached
/// it. A blank token keeps the one saved.
async fn save_telegram(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let token = match token_to_use(&state, text(&payload, "token")) {
        Ok(token) => token,
        Err(r) => return r,
    };
    let chat = text(&payload, "chat_id");
    if chat.is_empty() {
        return bad_request("Enter the chat ID, or find it with Find chat ID");
    }
    if !telegram::chat_shape_ok(chat) {
        return bad_request(
            "A chat ID is a number, such as 123456789 or -1001234567890, or a channel's @name",
        );
    }
    let username = match telegram::bot_username(&token).await {
        Ok(name) => name,
        Err(e) => return telegram_failed(&e.0),
    };
    let found = match telegram::chat(&token, chat).await {
        Ok(found) => found,
        Err(e) => return telegram_failed(&e.0),
    };
    let mut channels = notify::load_channels();
    let rendered = notify::render(
        &notify::test_content(),
        channels.lang(),
        &notify::app_name(&state),
        &notify::base_url(&state),
    );
    if let Err(e) = telegram::send(&token, &found.id, &rendered.telegram).await {
        return telegram_failed(&e.0);
    }
    let bot = TelegramConfig {
        token: notify::conceal(&state, &token),
        username,
        chat_id: found.id,
        chat_name: found.name,
    };
    let label = notify::chat_label(&bot);
    channels.telegram = Some(bot);
    if let Err(r) = saved(&channels) {
        return r;
    }
    notify::log(
        &state,
        "test",
        "telegram",
        &label,
        &rendered.subject,
        &Ok(()),
    )
    .await;
    audit(&state, &current, "notifications_telegram", "saved").await;
    answer(&state).await
}

/// The chats that wrote to the bot, or that it was added to, lately - to
/// pick the chat from rather than look its number up.
async fn find_chats(State(state): State<AppState>, req: Request) -> Response {
    let (_, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let token = match token_to_use(&state, text(&payload, "token")) {
        Ok(token) => token,
        Err(r) => return r,
    };
    let bot = match telegram::bot_username(&token).await {
        Ok(name) => name,
        Err(e) => return telegram_failed(&e.0),
    };
    match telegram::recent_chats(&token).await {
        Ok(chats) => Json(json!({
            "bot": bot,
            "chats": chats.iter().map(|c| json!({
                "id": c.id,
                "kind": c.kind,
                "name": c.name,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => telegram_failed(&e.0),
    }
}

async fn remove_telegram(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = admin_only(&current) {
        return r;
    }
    let mut channels = notify::load_channels();
    channels.telegram = None;
    if let Err(r) = saved(&channels) {
        return r;
    }
    audit(&state, &current, "notifications_telegram", "removed").await;
    answer(&state).await
}

// ---------------------------------------------------------------- what is told

async fn save_settings(State(state): State<AppState>, req: Request) -> Response {
    let (_, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut channels = notify::load_channels();
    if payload.get("language").is_some() {
        let language = text(&payload, "language");
        if Lang::parse(Some(language)).is_none() {
            return bad_request("The language is en or vi");
        }
        channels.language = Some(language.to_string());
    }
    if let Some(chosen) = payload.get("events").filter(|v| !v.is_null()) {
        let Some(chosen) = chosen.as_object() else {
            return bad_request("The events are each on or off: true or false");
        };
        for (key, on) in chosen {
            let Some(kind) = notify::kind(key) else {
                return bad_request(&format!("There is no event called {key}"));
            };
            let Some(on) = on.as_bool() else {
                return bad_request("The events are each on or off: true or false");
            };
            channels.events.insert(kind.key.to_string(), on);
        }
    }
    if let Err(r) = saved(&channels) {
        return r;
    }
    answer(&state).await
}

async fn audit(state: &AppState, current: &CurrentUser, action: &str, detail: &str) {
    let _ = state
        .db
        .audits()
        .log(
            Some(current.user.id),
            action,
            &current.user.username,
            detail,
        )
        .await;
}

// ---------------------------------------------------------------- a test message

static LAST_TEST: Mutex<Option<HashMap<i64, Instant>>> = Mutex::new(None);

/// One test message per administrator every few seconds: a button held
/// down is not a mail storm.
fn test_allowed(user_id: i64) -> bool {
    let mut guard = LAST_TEST.lock().unwrap_or_else(|p| p.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let now = Instant::now();
    if map
        .get(&user_id)
        .is_some_and(|at| now.duration_since(*at) < TEST_GAP)
    {
        return false;
    }
    map.insert(user_id, now);
    true
}

/// A test by e-mail - to the address given, or to every address messages go
/// to - or to the Telegram chat.
async fn test(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !test_allowed(current.user.id) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Wait a few seconds before sending another test",
        );
    }
    let channels = notify::load_channels();
    let rendered = notify::render(
        &notify::test_content(),
        channels.lang(),
        &notify::app_name(&state),
        &notify::base_url(&state),
    );
    match text(&payload, "channel") {
        "email" => {
            let Some(config) = channels.smtp.as_ref() else {
                return conflict("No SMTP server is set up yet");
            };
            let asked = text(&payload, "to");
            let targets = if asked.is_empty() {
                notify::recipients(&state, config).await
            } else if smtp::valid_address(asked) {
                vec![asked.to_string()]
            } else {
                return bad_request("That is not an e-mail address");
            };
            if targets.is_empty() {
                return conflict(
                    "No administrator has an e-mail address: enter the addresses to send to",
                );
            }
            for to in &targets {
                let outcome = notify::send_mail(&state, config, to, &rendered).await;
                notify::log(&state, "test", "email", to, &rendered.subject, &outcome).await;
                if let Err(why) = outcome {
                    return error(StatusCode::BAD_GATEWAY, &why);
                }
            }
            Json(json!({ "sent": true, "channel": "email", "to": targets.join(", ") }))
                .into_response()
        }
        "telegram" => {
            let Some((bot, chat)) = channels.telegram_chat() else {
                return conflict("No Telegram bot and chat are set up yet");
            };
            let label = notify::chat_label(bot);
            let outcome = notify::send_telegram(&state, bot, chat, &rendered).await;
            notify::log(
                &state,
                "test",
                "telegram",
                &label,
                &rendered.subject,
                &outcome,
            )
            .await;
            match outcome {
                Ok(()) => Json(json!({ "sent": true, "channel": "telegram", "to": label }))
                    .into_response(),
                Err(why) => telegram_failed(&why),
            }
        }
        _ => bad_request("The channel is email or telegram"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_waits_a_few_seconds_after_the_last() {
        assert!(test_allowed(-7));
        assert!(!test_allowed(-7));
        assert!(test_allowed(-8));
    }

    #[test]
    fn a_host_is_a_name_or_an_address() {
        for good in [
            "smtp.gmail.com",
            "127.0.0.1",
            "[::1]",
            "mail-01.example.net",
        ] {
            assert!(host_ok(good), "{good}");
        }
        for bad in ["", "smtp.example.com\r\nX", "a b", "smtp.example.com/path"] {
            assert!(!host_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_addresses_to_send_to_are_a_list_or_one_text_of_them() {
        let list = addresses(
            &json!({ "to": "a@example.com, B@example.com;b@example.com\nc@example.net" }),
        )
        .unwrap();
        assert_eq!(list, ["a@example.com", "B@example.com", "c@example.net"]);
        assert_eq!(
            addresses(&json!({ "to": ["ops@example.com", " "] })).unwrap(),
            ["ops@example.com"]
        );
        assert!(addresses(&json!({})).unwrap().is_empty());
        assert!(addresses(&json!({ "to": "" })).unwrap().is_empty());
        assert_eq!(
            addresses(&json!({ "to": "nobody" })).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            addresses(&json!({ "to": [1] })).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        let many: Vec<String> = (0..=MAX_ADDRESSES)
            .map(|i| format!("a{i}@example.com"))
            .collect();
        assert!(addresses(&json!({ "to": many })).is_err());
    }
}
