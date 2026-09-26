//! `/api/notifications*` - the Notifications addon's page.
//!
//! Not in the Python. Everyone reads and sets their own choices - where they
//! are told, of what, in which language - and links a Telegram chat. An
//! administrator also sets how messages go out: the SMTP server, the
//! Telegram bot, the default language, and reads what was sent. See
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
use rand::Rng;
use serde_json::{json, Map, Value};
use snpanel_db::notifications::NotificationSettings;
use snpanel_db::User;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, conflict, error, internal_error, not_enough_permissions};
use crate::notify::{self, smtp, telegram, Channels, Lang, SmtpConfig, TelegramConfig};
use crate::state::AppState;

/// How long a Telegram link code is good for.
const LINK_TTL: Duration = Duration::from_secs(600);
/// Between two test messages from one account.
const TEST_GAP: Duration = Duration::from_secs(5);

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(overview).fallback(crate::fallback))
        .route(
            "/notifications/me",
            put(save_mine).fallback(crate::fallback),
        )
        .route(
            "/notifications/smtp",
            put(save_smtp).delete(remove_smtp).fallback(crate::fallback),
        )
        .route(
            "/notifications/telegram",
            put(save_bot).delete(remove_bot).fallback(crate::fallback),
        )
        .route(
            "/notifications/defaults",
            put(save_defaults).fallback(crate::fallback),
        )
        .route("/notifications/test", post(test).fallback(crate::fallback))
        .route(
            "/notifications/telegram/link",
            post(start_link).delete(unlink).fallback(crate::fallback),
        )
        .route(
            "/notifications/telegram/link/check",
            post(check_link).fallback(crate::fallback),
        )
        .route(
            "/notifications/telegram/chat",
            put(set_chat).fallback(crate::fallback),
        )
        .route("/notifications/log", get(log).fallback(crate::fallback))
}

fn not_installed() -> Response {
    conflict("The Notifications addon is not installed")
}

async fn caller(state: &AppState, req: Request) -> Result<(CurrentUser, Value), Response> {
    let (mut parts, body) = req.into_parts();
    let current = CurrentUser::from_parts(&mut parts, state).await?;
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

/// The page's whole view, for the caller.
async fn view(state: &AppState, user: &User) -> Result<Value, Response> {
    let channels = notify::load_channels();
    let admin = user.is_admin();
    let settings = state
        .db
        .notifications()
        .get(user.id, &user.username)
        .await
        .map_err(|e| {
            tracing::error!("reading notification settings failed: {e}");
            internal_error()
        })?;
    let kinds: Vec<&notify::Kind> = notify::KINDS.iter().filter(|k| admin || !k.admin).collect();
    let mut events = Map::new();
    for kind in &kinds {
        events.insert(
            kind.key.to_string(),
            json!(notify::wants(&settings, kind.key)),
        );
    }
    let smtp = channels.smtp.as_ref();
    let bot = channels.telegram.as_ref();
    let mut out = json!({
        "installed": notify::installed(),
        "admin": admin,
        "channels": {
            "email": { "ready": smtp.is_some(), "from": smtp.map(|s| s.from_address.clone()) },
            "telegram": { "ready": bot.is_some(), "bot": bot.map(|b| b.username.clone()) },
        },
        "me": {
            "email_enabled": settings.email_enabled,
            "email": settings.email,
            "account_email": user.email,
            "telegram_enabled": settings.telegram_enabled,
            "telegram": {
                "linked": settings.telegram_chat_id.is_some(),
                "name": settings.telegram_name,
            },
            "language": settings.language,
            "events": events,
        },
        "events": kinds.iter().map(|k| json!({
            "key": k.key, "admin": k.admin, "default": k.default_on,
        })).collect::<Vec<_>>(),
    });
    if admin {
        out["smtp"] = match smtp {
            Some(s) => json!({
                "host": s.host,
                "port": s.port,
                "security": s.security,
                "username": s.username,
                "password_set": !s.password.is_empty(),
                "from_address": s.from_address,
                "from_name": s.from_name,
            }),
            None => Value::Null,
        };
        out["language"] = json!(channels.language.clone().unwrap_or_else(|| "vi".into()));
    }
    Ok(out)
}

async fn overview(State(state): State<AppState>, current: CurrentUser) -> Response {
    match view(&state, &current.user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

async fn log(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !current.user.is_admin() {
        return not_enough_permissions();
    }
    if !notify::installed() {
        return not_installed();
    }
    match state.db.notifications().recent(100).await {
        Ok(rows) => Json(json!({
            "items": rows.iter().map(|r| json!({
                "id": r.id,
                "created_at": r.created_at,
                "event": r.event,
                "username": r.username,
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

// ---------------------------------------------------------------- an account's own

async fn save_mine(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !notify::installed() {
        return not_installed();
    }
    let user = &current.user;
    let repo = state.db.notifications();
    let mut settings = match repo.get(user.id, &user.username).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("reading notification settings failed: {e}");
            return internal_error();
        }
    };
    if let Some(on) = payload.get("email_enabled").and_then(Value::as_bool) {
        settings.email_enabled = on;
    }
    if let Some(on) = payload.get("telegram_enabled").and_then(Value::as_bool) {
        settings.telegram_enabled = on;
    }
    if payload.get("email").is_some() {
        let address = text(&payload, "email");
        if address.is_empty() || address.eq_ignore_ascii_case(&user.email) {
            settings.email = None;
        } else if smtp::valid_address(address) {
            settings.email = Some(address.to_string());
        } else {
            return bad_request("That is not an e-mail address");
        }
    }
    if payload.get("language").is_some() {
        let language = text(&payload, "language");
        settings.language = match language {
            "" => None,
            code if Lang::parse(Some(code)).is_some() => Some(code.to_string()),
            _ => return bad_request("The language is en or vi"),
        };
    }
    if let Some(chosen) = payload.get("events").and_then(Value::as_object) {
        let mut events: Map<String, Value> =
            serde_json::from_str(&settings.events).unwrap_or_default();
        for (key, on) in chosen {
            let Some(kind) = notify::kind(key) else {
                return bad_request(&format!("There is no event called {key}"));
            };
            if kind.admin && !user.is_admin() {
                return not_enough_permissions();
            }
            let Some(on) = on.as_bool() else {
                return bad_request("An event is on or off: true or false");
            };
            events.insert(key.clone(), json!(on));
        }
        settings.events = Value::Object(events).to_string();
    }
    if let Err(e) = repo
        .save(
            user.id,
            &user.username,
            &settings,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        tracing::error!("saving notification settings failed: {e}");
        return internal_error();
    }
    match view(&state, user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------- the administrator's

fn admin_only(current: &CurrentUser) -> Result<(), Response> {
    if !current.user.is_admin() {
        return Err(not_enough_permissions());
    }
    if !notify::installed() {
        return Err(not_installed());
    }
    Ok(())
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
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
    if let Err(r) = admin_only(&current) {
        return r;
    }
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
    });
    if let Err(r) = saved(&channels) {
        return r;
    }
    audit(&state, &current, "notifications_smtp", "saved").await;
    match view(&state, &current.user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
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
    match view(&state, &current.user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

async fn save_bot(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = admin_only(&current) {
        return r;
    }
    let token = text(&payload, "token");
    if !telegram::token_shape_ok(token) {
        return bad_request("That is not a bot token: @BotFather gives one like 123456789:AA...");
    }
    // Whether it works is found out now, not at the first message.
    let username = match telegram::bot_username(token).await {
        Ok(name) => name,
        Err(e) => return error(StatusCode::BAD_GATEWAY, &e.0),
    };
    let mut channels = notify::load_channels();
    channels.telegram = Some(TelegramConfig {
        token: notify::conceal(&state, token),
        username,
    });
    if let Err(r) = saved(&channels) {
        return r;
    }
    audit(&state, &current, "notifications_telegram", "saved").await;
    match view(&state, &current.user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

async fn remove_bot(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = admin_only(&current) {
        return r;
    }
    let mut channels = notify::load_channels();
    channels.telegram = None;
    if let Err(r) = saved(&channels) {
        return r;
    }
    audit(&state, &current, "notifications_telegram", "removed").await;
    match view(&state, &current.user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

async fn save_defaults(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = admin_only(&current) {
        return r;
    }
    let language = text(&payload, "language");
    if Lang::parse(Some(language)).is_none() {
        return bad_request("The language is en or vi");
    }
    let mut channels = notify::load_channels();
    channels.language = Some(language.to_string());
    if let Err(r) = saved(&channels) {
        return r;
    }
    match view(&state, &current.user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
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

/// One test message per account every few seconds: a button held down is
/// not a mail storm.
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

async fn test(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !notify::installed() {
        return not_installed();
    }
    let user = &current.user;
    if !test_allowed(user.id) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Wait a few seconds before sending another test",
        );
    }
    let channels = notify::load_channels();
    let settings = match state.db.notifications().get(user.id, &user.username).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("reading notification settings failed: {e}");
            return internal_error();
        }
    };
    let lang = Lang::parse(settings.language.as_deref())
        .or_else(|| Lang::parse(channels.language.as_deref()))
        .unwrap_or(Lang::Vi);
    let rendered = notify::render(
        &notify::test_content(),
        lang,
        &notify::app_name(&state),
        &user.username,
        &notify::base_url(&state),
    );
    let (channel, target, outcome) = match text(&payload, "channel") {
        "email" => {
            let Some(config) = channels.smtp.as_ref() else {
                return conflict("No SMTP server is set up yet");
            };
            // An administrator may try any address; everyone else their own.
            let asked = text(&payload, "to");
            let to = if user.is_admin() && !asked.is_empty() {
                asked.to_string()
            } else {
                settings.email.clone().unwrap_or_else(|| user.email.clone())
            };
            if !smtp::valid_address(&to) {
                return bad_request("That is not an e-mail address");
            }
            let outcome = notify::send_mail(&state, config, &to, &rendered).await;
            ("email", to, outcome)
        }
        "telegram" => {
            let Some(config) = channels.telegram.as_ref() else {
                return conflict("No Telegram bot is set up yet");
            };
            let Some(chat) = settings.telegram_chat_id.clone() else {
                return conflict("Link a Telegram chat first");
            };
            let outcome = notify::send_telegram(&state, config, &chat, &rendered).await;
            ("telegram", chat, outcome)
        }
        _ => return bad_request("The channel is email or telegram"),
    };
    let masked = if channel == "email" {
        notify::masked_address(&target)
    } else {
        notify::masked_chat(&target)
    };
    let now = snpanel_db::sqlalchemy_now();
    let (status, detail) = match &outcome {
        Ok(()) => ("sent", String::new()),
        Err(why) => ("failed", why.clone()),
    };
    let _ = state
        .db
        .notifications()
        .log(&snpanel_db::notifications::NewLogEntry {
            created_at: &now,
            event: "test",
            user_id: Some(user.id),
            username: Some(&user.username),
            channel,
            target: &masked,
            subject: &rendered.subject,
            status,
            detail: &detail,
        })
        .await;
    match outcome {
        Ok(()) => Json(json!({ "sent": true, "channel": channel, "to": masked })).into_response(),
        Err(why) => error(StatusCode::BAD_GATEWAY, &why),
    }
}

// ---------------------------------------------------------------- linking Telegram

#[derive(Clone)]
struct PendingLink {
    user_id: i64,
    username: String,
    code: String,
    created: Instant,
}

static PENDING: Mutex<Vec<PendingLink>> = Mutex::new(Vec::new());
/// The next update to ask Telegram for, so an update is read once.
static OFFSET: Mutex<i64> = Mutex::new(0);
/// One `getUpdates` at a time: two with the same offset would each take
/// what the other then marks read.
static POLLING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn new_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    (0..16)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

async fn start_link(State(state): State<AppState>, req: Request) -> Response {
    let (current, _) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !notify::installed() {
        return not_installed();
    }
    let Some(bot) = notify::load_channels().telegram else {
        return conflict("No Telegram bot is set up yet");
    };
    let code = new_code();
    {
        let mut pending = PENDING.lock().unwrap_or_else(|p| p.into_inner());
        pending.retain(|p| p.created.elapsed() < LINK_TTL && p.user_id != current.user.id);
        if pending.len() >= 200 {
            pending.remove(0);
        }
        pending.push(PendingLink {
            user_id: current.user.id,
            username: current.user.username.clone(),
            code: code.clone(),
            created: Instant::now(),
        });
    }
    Json(json!({
        "code": code,
        "bot": bot.username,
        "url": format!("https://t.me/{}?start={code}", bot.username),
        "expires_in": LINK_TTL.as_secs(),
    }))
    .into_response()
}

/// Read what the bot was sent, and link every account whose code is in it -
/// not only the caller's, since whoever reads an update marks it read.
async fn check_link(State(state): State<AppState>, req: Request) -> Response {
    let (current, _) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !notify::installed() {
        return not_installed();
    }
    let Some(bot) = notify::load_channels().telegram else {
        return conflict("No Telegram bot is set up yet");
    };
    let Some(token) = notify::reveal(&state, &bot.token).filter(|t| !t.is_empty()) else {
        return conflict("The saved bot token cannot be read: save it again");
    };
    let waiting = {
        let pending = PENDING.lock().unwrap_or_else(|p| p.into_inner());
        pending
            .iter()
            .any(|p| p.user_id == current.user.id && p.created.elapsed() < LINK_TTL)
    };
    if !waiting {
        return conflict("The link has expired. Start again.");
    }

    let _polling = POLLING.lock().await;
    let offset = *OFFSET.lock().unwrap_or_else(|p| p.into_inner());
    let (starts, next) = match telegram::starts(&token, offset).await {
        Ok(v) => v,
        Err(e) => {
            let hint = if e.0.contains("webhook") || e.0.contains("Conflict") {
                "This bot is read by something else (a webhook, or another program polling it). Give the panel a bot of its own."
            } else {
                ""
            };
            let message = if hint.is_empty() {
                e.0
            } else {
                hint.to_string()
            };
            return error(StatusCode::BAD_GATEWAY, &message);
        }
    };
    *OFFSET.lock().unwrap_or_else(|p| p.into_inner()) = next;

    let mut linked_me: Option<String> = None;
    for start in starts {
        let found = {
            let mut pending = PENDING.lock().unwrap_or_else(|p| p.into_inner());
            let index = pending
                .iter()
                .position(|p| p.code == start.code && p.created.elapsed() < LINK_TTL);
            index.map(|i| pending.remove(i))
        };
        let Some(link) = found else {
            continue;
        };
        let repo = state.db.notifications();
        let mut settings: NotificationSettings = match repo.get(link.user_id, &link.username).await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("reading notification settings failed: {e}");
                continue;
            }
        };
        settings.telegram_chat_id = Some(start.chat_id.clone());
        settings.telegram_name = Some(start.who.clone());
        settings.telegram_enabled = true;
        if let Err(e) = repo
            .save(
                link.user_id,
                &link.username,
                &settings,
                &snpanel_db::sqlalchemy_now(),
            )
            .await
        {
            tracing::error!("saving a Telegram link failed: {e}");
            continue;
        }
        let lang = Lang::parse(settings.language.as_deref()).unwrap_or(Lang::Vi);
        let hello = notify::linked_hello(lang, &link.username, &notify::app_name(&state));
        let _ = telegram::send(&token, &start.chat_id, &hello).await;
        if link.user_id == current.user.id {
            linked_me = Some(start.who.clone());
        }
    }
    Json(json!({ "linked": linked_me.is_some(), "name": linked_me })).into_response()
}

async fn unlink(State(state): State<AppState>, current: CurrentUser) -> Response {
    if !notify::installed() {
        return not_installed();
    }
    let user = &current.user;
    let repo = state.db.notifications();
    let mut settings = match repo.get(user.id, &user.username).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("reading notification settings failed: {e}");
            return internal_error();
        }
    };
    settings.telegram_chat_id = None;
    settings.telegram_name = None;
    if let Err(e) = repo
        .save(
            user.id,
            &user.username,
            &settings,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        tracing::error!("saving notification settings failed: {e}");
        return internal_error();
    }
    match view(&state, user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

/// A chat given by its id - a group's or a channel's, where the bot is a
/// member - proved by a message the bot sends it.
async fn set_chat(State(state): State<AppState>, req: Request) -> Response {
    let (current, payload) = match caller(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !notify::installed() {
        return not_installed();
    }
    let chat = text(&payload, "chat");
    if !telegram::chat_shape_ok(chat) {
        return bad_request(
            "A chat id is a number, such as 123456789 or -1001234567890, or a channel's @name",
        );
    }
    let Some(bot) = notify::load_channels().telegram else {
        return conflict("No Telegram bot is set up yet");
    };
    let rendered = notify::render(
        &notify::test_content(),
        Lang::Vi,
        &notify::app_name(&state),
        &current.user.username,
        &notify::base_url(&state),
    );
    if let Err(why) = notify::send_telegram(&state, &bot, chat, &rendered).await {
        return error(StatusCode::BAD_GATEWAY, &why);
    }
    let user = &current.user;
    let repo = state.db.notifications();
    let mut settings = match repo.get(user.id, &user.username).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("reading notification settings failed: {e}");
            return internal_error();
        }
    };
    settings.telegram_chat_id = Some(chat.to_string());
    settings.telegram_name = Some(chat.to_string());
    settings.telegram_enabled = true;
    if let Err(e) = repo
        .save(
            user.id,
            &user.username,
            &settings,
            &snpanel_db::sqlalchemy_now(),
        )
        .await
    {
        tracing::error!("saving notification settings failed: {e}");
        return internal_error();
    }
    match view(&state, user).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_code_is_sixteen_unambiguous_characters() {
        let a = new_code();
        assert_eq!(a.len(), 16);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !"0O1lI".contains(c)));
        assert_ne!(a, new_code());
    }

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
}
