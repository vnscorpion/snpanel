//! The MCP addon: an AI assistant - Claude Code, Cursor, VS Code - reads and
//! works the panel through the Model Context Protocol, with a token of the
//! account it acts for.
//!
//! Not in the Python. OPanel's MCP addon (v1.16.0) is the model: the same
//! transport, tools and guards, ported onto this panel.
//!
//! - Streamable HTTP, answering JSON only: no event stream and no session.
//! - The JSON-RPC is written here. The protocol is small, and a library
//!   would be most of the attack surface.
//! - A tool the token may not use is not in `tools/list`, and calling it is
//!   an unknown tool: the list cannot be probed for what exists.
//! - A tool that changes something calls the panel's own endpoint as the
//!   token's owner ([`Context::call`]), so ownership, quotas and the audit
//!   log are what the pages get - and every such call is audited again here
//!   as `mcp_tool`.

pub mod guards;
pub mod tools;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Map, Value};
use snpanel_db::mcp_tokens::McpToken;
use snpanel_db::User;

use crate::auth::{CurrentUser, McpCaller};
use crate::state::AppState;

/// Newest first. A client asking for a version not here gets the newest.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// Every token starts with this, which is also how a stray one is recognised.
pub const TOKEN_PREFIX: &str = "snmcp_";
pub const MAX_TOKENS: i64 = 10;
pub const ENDPOINT_PATH: &str = "/api/mcp";
/// What a 401 names in `WWW-Authenticate`.
pub const REALM: &str = "snpanel-mcp";

/// Sent in `initialize`: how to use the tools well.
pub const INSTRUCTIONS: &str = "Tools for the SNPanel hosting control panel. They act as the \
account that made the token: an administrator sees the whole server, anyone else their own \
websites, databases, files and backups. Websites are named by domain. To look into traffic or \
an attack, start with traffic_summary, then read_waf_access_log for the detail. Prefer \
add_waf_rule on one website to block_ip, which blocks an address from the whole server, and \
do not block an address that may belong to a CDN or a proxy in front of a site - behind \
Cloudflare the log shows Cloudflare's addresses. Read a file before overwriting it, and ask \
the user before delete_file. Tools that change something need a token that allows actions.";

// --------------------------------------------------------------------- tokens

/// A new token: the prefix and 32 random bytes as URL-safe base64.
pub fn new_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// What is stored in place of the token.
pub fn token_hash(token: &str) -> String {
    snpanel_core::types::sha256_hex(token)
}

/// The start of a token, to tell one from another in a list.
pub fn token_prefix(token: &str) -> String {
    token.chars().take(12).collect()
}

/// Whether a presented token is shaped like one of ours - checked before
/// the database is asked anything.
pub fn looks_like_token(token: &str) -> bool {
    token.starts_with(TOKEN_PREFIX)
        && token.len() <= 128
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn parse_stamp(text: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f").ok()
}

/// Whether a token's expiry has passed; an unreadable one has.
pub fn expired(expires_at: &str, now: chrono::NaiveDateTime) -> bool {
    parse_stamp(expires_at).is_none_or(|at| at <= now)
}

/// A stored timestamp as ISO 8601 UTC, for the pages.
pub fn iso(text: &str) -> String {
    parse_stamp(text)
        .map(|at| at.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------- tools

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    String,
    Integer,
    Boolean,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::String => "string",
            Kind::Integer => "integer",
            Kind::Boolean => "boolean",
        }
    }
}

/// One argument a tool takes, and what it may be.
#[derive(Debug, Clone, Copy)]
pub struct Param {
    pub name: &'static str,
    pub kind: Kind,
    pub description: &'static str,
    pub required: bool,
    pub choices: &'static [&'static str],
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
}

impl Param {
    pub const fn text(name: &'static str, description: &'static str) -> Param {
        Param {
            name,
            kind: Kind::String,
            description,
            required: false,
            choices: &[],
            minimum: None,
            maximum: None,
        }
    }

    pub const fn number(
        name: &'static str,
        description: &'static str,
        min: i64,
        max: i64,
    ) -> Param {
        Param {
            kind: Kind::Integer,
            minimum: Some(min),
            maximum: Some(max),
            ..Param::text(name, description)
        }
    }

    pub const fn flag(name: &'static str, description: &'static str) -> Param {
        Param {
            kind: Kind::Boolean,
            ..Param::text(name, description)
        }
    }

    pub const fn one_of(
        name: &'static str,
        description: &'static str,
        choices: &'static [&'static str],
    ) -> Param {
        Param {
            choices,
            ..Param::text(name, description)
        }
    }

    pub const fn required(self) -> Param {
        Param {
            required: true,
            ..self
        }
    }
}

/// A failure a tool reports to the assistant, in words it can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError(pub String);

impl ToolError {
    pub fn new(message: impl Into<String>) -> Self {
        ToolError(message.into())
    }
}

pub type ToolResult = Result<Value, ToolError>;
pub type ToolFuture = Pin<Box<dyn Future<Output = ToolResult> + Send>>;
pub type Arguments = Map<String, Value>;

pub struct Tool {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub params: &'static [Param],
    /// Only an administrator sees it.
    pub admin_only: bool,
    /// Changes something: only for a token that allows actions, and audited.
    pub writes: bool,
    /// Tells the client to ask before it runs.
    pub destructive: bool,
    pub run: fn(Arc<Context>, Arguments) -> ToolFuture,
}

/// The JSON Schema of a tool's arguments. Nothing beyond them is accepted.
pub fn input_schema(tool: &Tool) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for param in tool.params {
        let mut property = json!({ "type": param.kind.name(), "description": param.description });
        if !param.choices.is_empty() {
            property["enum"] = json!(param.choices);
        }
        if let Some(min) = param.minimum {
            property["minimum"] = json!(min);
        }
        if let Some(max) = param.maximum {
            property["maximum"] = json!(max);
        }
        properties.insert(param.name.to_string(), property);
        if param.required {
            required.push(param.name);
        }
    }
    let mut schema = json!({
        "type": "object",
        "properties": properties,
        "additionalProperties": false,
    });
    if !required.is_empty() {
        schema["required"] = json!(required);
    }
    schema
}

/// A tool as `tools/list` shows it.
pub fn describe(tool: &Tool) -> Value {
    json!({
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": input_schema(tool),
        "annotations": {
            "title": tool.title,
            "readOnlyHint": !tool.writes,
            "destructiveHint": tool.destructive,
            "idempotentHint": !tool.writes,
            "openWorldHint": false,
        },
    })
}

/// Whether a caller may see - and so call - a tool.
pub fn visible(tool: &Tool, is_admin: bool, can_write: bool) -> bool {
    (!tool.admin_only || is_admin) && (!tool.writes || can_write)
}

/// The arguments of a call, checked against the tool: no name it does not
/// take, every required one, each of its kind, choice and range. An explicit
/// `null` is an argument left out.
pub fn check_arguments(tool: &Tool, raw: Option<&Value>) -> Result<Arguments, String> {
    let given = match raw {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err("The arguments must be an object".to_string()),
    };
    for name in given.keys() {
        if !tool.params.iter().any(|param| param.name == name) {
            return Err(format!("Unknown argument: {name}"));
        }
    }
    let mut args = Map::new();
    for param in tool.params {
        let value = match given.get(param.name) {
            None | Some(Value::Null) => {
                if param.required {
                    return Err(format!("Missing required argument: {}", param.name));
                }
                continue;
            }
            Some(value) => value,
        };
        let checked = match param.kind {
            Kind::String => {
                let Some(text) = value.as_str() else {
                    return Err(format!("{} must be a string", param.name));
                };
                if !param.choices.is_empty() && !param.choices.contains(&text) {
                    return Err(format!(
                        "{} must be one of: {}",
                        param.name,
                        param.choices.join(", ")
                    ));
                }
                Value::String(text.to_string())
            }
            Kind::Integer => {
                let number = value.as_i64().or_else(|| {
                    value
                        .as_f64()
                        .filter(|f| f.fract() == 0.0)
                        .map(|f| f as i64)
                });
                let Some(number) = number else {
                    return Err(format!("{} must be a whole number", param.name));
                };
                if let Some(min) = param.minimum.filter(|min| number < *min) {
                    return Err(format!("{} must be at least {min}", param.name));
                }
                if let Some(max) = param.maximum.filter(|max| number > *max) {
                    return Err(format!("{} must be at most {max}", param.name));
                }
                json!(number)
            }
            Kind::Boolean => {
                let Some(flag) = value.as_bool() else {
                    return Err(format!("{} must be true or false", param.name));
                };
                json!(flag)
            }
        };
        args.insert(param.name.to_string(), checked);
    }
    Ok(args)
}

// -------------------------------------------------------------------- context

/// Who is calling, and how to reach the panel as them.
pub struct Context {
    pub state: AppState,
    pub current: CurrentUser,
    pub token: McpToken,
    /// The address the audit log records.
    pub client_ip: String,
    pub user_agent: String,
    /// Carried into the calls this makes, so their audit entries name the
    /// same address: the peer, and the proxy's headers when one is trusted.
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    forwarded: Vec<(header::HeaderName, header::HeaderValue)>,
}

impl Context {
    pub fn new(
        state: AppState,
        current: CurrentUser,
        token: McpToken,
        parts: &axum::http::request::Parts,
    ) -> Context {
        let client = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .chars()
            .take(120)
            .collect::<String>();
        let forwarded = ["x-forwarded-for", "x-real-ip"]
            .iter()
            .filter_map(|name| {
                let value = parts.headers.get(*name)?.clone();
                Some((header::HeaderName::from_static(name), value))
            })
            .collect();
        Context {
            client_ip: crate::client::audit_ip(parts),
            user_agent: if client.is_empty() {
                "SNPanel MCP".to_string()
            } else {
                format!("SNPanel MCP ({client})")
            },
            peer: parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .copied(),
            forwarded,
            state,
            current,
            token,
        }
    }

    pub fn is_admin(&self) -> bool {
        self.current.user.is_admin()
    }

    pub fn user(&self) -> &User {
        &self.current.user
    }

    /// One of the panel's own endpoints, as the token's owner: the route,
    /// its checks and its audit entry exactly as the pages get them. A
    /// refusal comes back as the endpoint's own message.
    pub async fn call(&self, method: Method, path: &str, body: Option<Value>) -> ToolResult {
        use tower::ServiceExt;

        let bytes = match &body {
            Some(value) => serde_json::to_vec(value).unwrap_or_default(),
            None => Vec::new(),
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, &self.user_agent);
        for (name, value) in &self.forwarded {
            builder = builder.header(name, value);
        }
        let mut request = builder
            .body(Body::from(bytes))
            .map_err(|e| ToolError::new(format!("Cannot make the request: {e}")))?;
        request
            .extensions_mut()
            .insert(McpCaller(self.current.clone()));
        if let Some(peer) = self.peer {
            request.extensions_mut().insert(peer);
        }
        let response = router(&self.state)
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {});
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
            .await
            .map_err(|e| ToolError::new(format!("Cannot read the answer: {e}")))?;
        let value: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        if status.is_success() {
            Ok(value)
        } else {
            Err(ToolError(failure_text(status, &value)))
        }
    }

    /// A website by domain, when this account may work on it. Somebody
    /// else's reads exactly as one that does not exist.
    pub async fn website(&self, domain: &str) -> Result<snpanel_db::Website, ToolError> {
        let wanted = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let found = self
            .state
            .db
            .websites()
            .by_domain(&wanted)
            .await
            .map_err(|e| ToolError::new(format!("Cannot read the websites: {e}")))?;
        match found {
            Some(site) if self.is_admin() || site.owner_id == self.user().id => Ok(site),
            _ => Err(ToolError::new(format!(
                "No website {wanted} on this account"
            ))),
        }
    }

    /// The account a tool acts on: the caller's, or - for an administrator -
    /// the one named. Anyone else naming another account is refused.
    pub async fn account(&self, username: Option<&str>) -> Result<User, ToolError> {
        let Some(name) = username.map(str::trim).filter(|name| !name.is_empty()) else {
            return Ok(self.user().clone());
        };
        if name == self.user().username {
            return Ok(self.user().clone());
        }
        if !self.is_admin() {
            return Err(ToolError::new(
                "Only an administrator can act on another account",
            ));
        }
        self.state
            .db
            .users()
            .by_username(name)
            .await
            .map_err(|e| ToolError::new(format!("Cannot read the accounts: {e}")))?
            .ok_or_else(|| ToolError::new(format!("No account named {name}")))
    }
}

/// The API's own routes, built once. The layers around them - session
/// sliding, security headers - belong to answers that leave the process, and
/// these do not.
fn router(state: &AppState) -> axum::Router {
    static ROUTER: std::sync::OnceLock<axum::Router> = std::sync::OnceLock::new();
    ROUTER
        .get_or_init(|| crate::routes::api_router().with_state(state.clone()))
        .clone()
}

/// A refusal an endpoint function handed back, as the assistant reads it.
pub async fn response_error(response: axum::response::Response) -> ToolError {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    ToolError(failure_text(status, &value))
}

/// An endpoint's refusal as a sentence: its `detail`, or each field's
/// message of a validation error.
pub fn failure_text(status: StatusCode, body: &Value) -> String {
    match body.get("detail") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(Value::Array(items)) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(|item| {
                    let message = item.get("msg")?.as_str()?;
                    let field = item
                        .get("loc")
                        .and_then(Value::as_array)
                        .and_then(|loc| loc.last())
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    Some(if field.is_empty() {
                        message.to_string()
                    } else {
                        format!("{field}: {message}")
                    })
                })
                .collect();
            if parts.is_empty() {
                format!("The panel refused the request (HTTP {})", status.as_u16())
            } else {
                parts.join("; ")
            }
        }
        _ => match body {
            Value::String(text) if !text.trim().is_empty() => {
                text.trim().chars().take(500).collect()
            }
            _ => format!("The panel refused the request (HTTP {})", status.as_u16()),
        },
    }
}

// ------------------------------------------------------------------- protocol

fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// The answer to a body that is not JSON.
pub fn parse_error() -> Value {
    error_reply(Value::Null, -32700, "Parse error")
}

/// What `initialize` answers: the version the client asked for when this
/// server speaks it, the newest otherwise.
pub fn initialize(params: Option<&Value>) -> Value {
    let asked = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let version = if PROTOCOL_VERSIONS.contains(&asked) {
        asked
    } else {
        PROTOCOL_VERSIONS[0]
    };
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "snpanel",
            "title": "SNPanel",
            "version": crate::updates::app_version(),
        },
        "instructions": INSTRUCTIONS,
    })
}

/// The tools this caller may use, as `tools/list` shows them.
pub fn list_tools(is_admin: bool, can_write: bool) -> Vec<Value> {
    tools::ALL
        .iter()
        .filter(|tool| visible(tool, is_admin, can_write))
        .map(describe)
        .collect()
}

/// A whole request body: one message, or a batch. `None` when nothing in
/// it wants an answer - notifications, and responses the client sends.
pub async fn handle_body(ctx: &Arc<Context>, body: &Value) -> Option<Value> {
    match body {
        Value::Array(messages) => {
            if messages.is_empty() {
                return Some(error_reply(Value::Null, -32600, "Invalid Request"));
            }
            let mut replies = Vec::new();
            for message in messages {
                if let Some(reply) = handle_message(ctx, message).await {
                    replies.push(reply);
                }
            }
            (!replies.is_empty()).then_some(Value::Array(replies))
        }
        message => handle_message(ctx, message).await,
    }
}

async fn handle_message(ctx: &Arc<Context>, message: &Value) -> Option<Value> {
    let Some(object) = message.as_object() else {
        return Some(error_reply(Value::Null, -32600, "Invalid Request"));
    };
    let id = object.get("id").cloned();
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        // A response from the client, to a request this server never makes.
        if object.contains_key("result") || object.contains_key("error") {
            return None;
        }
        return Some(error_reply(
            id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request",
        ));
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return id.map(|id| error_reply(id, -32600, "Invalid Request"));
    }
    // A notification: nothing is answered, whatever it says.
    let id = id?;
    let params = object.get("params");
    let outcome = match method {
        "initialize" => Ok(initialize(params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": list_tools(ctx.is_admin(), ctx.token.can_write) })),
        "tools/call" => call_tool(ctx, params).await,
        _ => Err((-32601, format!("Method not found: {method}"))),
    };
    Some(match outcome {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => error_reply(id, code, &message),
    })
}

async fn call_tool(ctx: &Arc<Context>, params: Option<&Value>) -> Result<Value, (i64, String)> {
    let name = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .ok_or((-32602, "tools/call needs the name of a tool".to_string()))?;
    let tool = tools::find(name)
        .filter(|tool| visible(tool, ctx.is_admin(), ctx.token.can_write))
        .ok_or((-32602, format!("Unknown tool: {name}")))?;
    let args = check_arguments(tool, params.and_then(|p| p.get("arguments")))
        .map_err(|message| (-32602, message))?;
    let outcome = (tool.run)(ctx.clone(), args.clone()).await;
    if tool.writes {
        audit(ctx, tool, &args, &outcome).await;
    }
    Ok(match outcome {
        Ok(value) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&value).unwrap_or_default() }],
            "isError": false,
        }),
        Err(ToolError(message)) => json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true,
        }),
    })
}

/// A tool's arguments as the audit log keeps them: a file's content only as
/// its length - it may be `wp-config.php`.
pub fn audited_arguments(args: &Arguments) -> String {
    let mut shown = args.clone();
    if let Some(Value::String(content)) = shown.get("content") {
        let length = content.chars().count();
        shown.insert(
            "content".to_string(),
            json!(format!("<{length} characters>")),
        );
    }
    let text = serde_json::to_string(&shown).unwrap_or_default();
    text.chars().take(1000).collect()
}

async fn audit(ctx: &Arc<Context>, tool: &Tool, args: &Arguments, outcome: &ToolResult) {
    let mut detail = audited_arguments(args);
    if let Err(ToolError(message)) = outcome {
        let message: String = message.chars().take(300).collect();
        detail.push_str(&format!(" -> failed: {message}"));
    }
    let detail =
        snpanel_db::AuditRepo::detail_with_request(&detail, &ctx.client_ip, &ctx.user_agent);
    if let Err(e) = ctx
        .state
        .db
        .audits()
        .log(Some(ctx.user().id), "mcp_tool", tool.name, &detail)
        .await
    {
        tracing::error!(
            "Failed to write audit log: action=mcp_tool target={}: {e}",
            tool.name
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(params: &'static [Param], admin_only: bool, writes: bool) -> Tool {
        fn run(_: Arc<Context>, _: Arguments) -> ToolFuture {
            Box::pin(async { Ok(json!({})) })
        }
        Tool {
            name: "t",
            title: "T",
            description: "d",
            params,
            admin_only,
            writes,
            destructive: false,
            run,
        }
    }

    const PARAMS: &[Param] = &[
        Param::text("domain", "a domain").required(),
        Param::one_of("kind", "which", &["access", "error"]),
        Param::number("lines", "how many", 1, 500),
        Param::flag("enabled", "on or off"),
    ];

    #[test]
    fn a_token_is_the_prefix_and_43_random_characters() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert!(a.starts_with("snmcp_") && a.len() == 6 + 43, "{a}");
        assert!(looks_like_token(&a));
        assert_eq!(token_prefix(&a).len(), 12);
        assert_eq!(token_hash(&a).len(), 64);
        assert_ne!(token_hash(&a), token_hash(&b));
        for bad in [
            "",
            "opmcp_abc",
            "snmcp_ab cd",
            "snmcp_a\"b",
            &format!("snmcp_{}", "a".repeat(200)),
        ] {
            assert!(!looks_like_token(bad), "{bad}");
        }
    }

    #[test]
    fn a_token_past_its_expiry_or_with_none_readable_is_expired() {
        let now = parse_stamp("2026-09-25 10:00:00.000000").unwrap();
        assert!(!expired("2026-09-25 10:00:01.000000", now));
        assert!(expired("2026-09-25 10:00:00.000000", now));
        assert!(expired("2026-09-24 10:00:00", now));
        assert!(expired("soon", now));
        assert_eq!(iso("2026-09-25 10:00:00.123456"), "2026-09-25T10:00:00Z");
    }

    #[test]
    fn the_schema_is_the_arguments_and_nothing_else() {
        let schema = input_schema(&tool(PARAMS, false, false));
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["domain"]));
        assert_eq!(
            schema["properties"]["kind"]["enum"],
            json!(["access", "error"])
        );
        assert_eq!(schema["properties"]["lines"]["maximum"], 500);
        assert_eq!(schema["properties"]["enabled"]["type"], "boolean");
        let described = describe(&tool(PARAMS, false, true));
        assert_eq!(described["annotations"]["readOnlyHint"], false);
        assert_eq!(described["annotations"]["idempotentHint"], false);
        assert_eq!(described["annotations"]["openWorldHint"], false);
    }

    #[test]
    fn arguments_are_checked_by_name_kind_choice_and_range() {
        let t = tool(PARAMS, false, false);
        let check = |v: Value| check_arguments(&t, Some(&v));
        assert_eq!(
            check(json!({})).unwrap_err(),
            "Missing required argument: domain"
        );
        assert_eq!(
            check(json!({"domain": "a.com", "x": 1})).unwrap_err(),
            "Unknown argument: x"
        );
        assert_eq!(
            check(json!({"domain": 5})).unwrap_err(),
            "domain must be a string"
        );
        assert_eq!(
            check(json!({"domain": "a.com", "kind": "debug"})).unwrap_err(),
            "kind must be one of: access, error"
        );
        assert_eq!(
            check(json!({"domain": "a.com", "lines": 0})).unwrap_err(),
            "lines must be at least 1"
        );
        assert_eq!(
            check(json!({"domain": "a.com", "lines": 501})).unwrap_err(),
            "lines must be at most 500"
        );
        assert_eq!(
            check(json!({"domain": "a.com", "lines": 2.5})).unwrap_err(),
            "lines must be a whole number"
        );
        assert_eq!(
            check(json!({"domain": "a.com", "enabled": "yes"})).unwrap_err(),
            "enabled must be true or false"
        );
        assert!(check_arguments(&t, Some(&json!([1]))).is_err());
        let good = check(json!({"domain": "a.com", "lines": 20.0, "kind": null})).unwrap();
        assert_eq!(
            good,
            json!({"domain": "a.com", "lines": 20})
                .as_object()
                .unwrap()
                .clone()
        );
    }

    #[test]
    fn a_tool_is_seen_only_by_whom_it_is_for() {
        let admin_tool = tool(&[], true, false);
        let write_tool = tool(&[], false, true);
        let read_tool = tool(&[], false, false);
        assert!(!visible(&admin_tool, false, true));
        assert!(visible(&admin_tool, true, false));
        assert!(!visible(&write_tool, true, false));
        assert!(visible(&write_tool, false, true));
        assert!(visible(&read_tool, false, false));
    }

    #[test]
    fn the_newest_version_answers_an_unknown_one() {
        assert_eq!(
            initialize(Some(&json!({"protocolVersion": "2025-03-26"})))["protocolVersion"],
            "2025-03-26"
        );
        assert_eq!(
            initialize(Some(&json!({"protocolVersion": "1999-01-01"})))["protocolVersion"],
            "2025-06-18"
        );
        assert_eq!(
            initialize(None)["capabilities"]["tools"]["listChanged"],
            false
        );
        assert_eq!(initialize(None)["serverInfo"]["name"], "snpanel");
    }

    #[test]
    fn a_refusal_reads_as_the_endpoints_own_words() {
        assert_eq!(
            failure_text(
                StatusCode::NOT_FOUND,
                &json!({"detail": "Website not found"})
            ),
            "Website not found"
        );
        assert_eq!(
            failure_text(
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!({"detail": [{"loc": ["body", "path"], "msg": "Field required"}]})
            ),
            "path: Field required"
        );
        assert_eq!(
            failure_text(StatusCode::BAD_GATEWAY, &Value::Null),
            "The panel refused the request (HTTP 502)"
        );
    }

    #[test]
    fn a_files_content_is_audited_as_its_length() {
        let args = json!({"domain": "a.com", "path": "wp-config.php", "content": "secret ✓"});
        let text = audited_arguments(args.as_object().unwrap());
        assert!(
            text.contains("<8 characters>") && !text.contains("secret"),
            "{text}"
        );
    }

    /// Every tool's name is unique, and its schema is one a client accepts.
    #[test]
    fn the_catalogue_is_well_formed() {
        let mut names: Vec<&str> = tools::ALL.iter().map(|t| t.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "a tool name is used twice");
        assert_eq!(count, 32);
        for tool in tools::ALL {
            assert!(tools::find(tool.name).is_some());
            assert!(
                tool.description.len() > 20,
                "{} is not described",
                tool.name
            );
            assert!(
                !tool.destructive || tool.writes,
                "{} destroys without writing",
                tool.name
            );
            let schema = input_schema(tool);
            assert_eq!(schema["type"], "object");
        }
        // A user sees 13 tools read-only and 20 with actions; an
        // administrator 20 and 32.
        assert_eq!(list_tools(false, false).len(), 13);
        assert_eq!(list_tools(false, true).len(), 20);
        assert_eq!(list_tools(true, false).len(), 20);
        assert_eq!(list_tools(true, true).len(), 32);
    }
}
