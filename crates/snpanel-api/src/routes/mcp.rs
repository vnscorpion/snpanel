//! `/api/mcp` - not in the Python: the MCP addon's endpoint, and its tokens.
//!
//! `POST /api/mcp` is the Model Context Protocol for an assistant holding a
//! token - see `crate::mcp`. The rest are for the pages, with the panel
//! session: `GET /api/mcp/info`, and an account's tokens, made, listed and
//! revoked.
//!
//! A request to the endpoint is refused, in this order: when the addon is
//! not installed (404), when it comes from a web page of another site (403 -
//! an MCP client sends no `Origin`, so a page's request is a browser being
//! used against the panel through DNS rebinding), and when its token is
//! missing, unknown, expired or its account suspended (401).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde_json::{json, Value};
use snpanel_db::mcp_tokens::{McpToken, NewMcpToken};

use crate::auth::CurrentUser;
use crate::errors::{conflict, error, internal_error, not_enough_permissions, not_found};
use crate::mcp;
use crate::state::AppState;

/// A request to the endpoint may carry a file's whole content.
const MAX_BODY: usize = 8 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/mcp",
            axum::routing::post(endpoint)
                .get(not_allowed)
                .delete(not_allowed),
        )
        .route("/mcp/info", get(info).fallback(crate::fallback))
        .route(
            "/mcp/tokens",
            get(list_tokens)
                .post(create_token)
                .delete(revoke_all)
                .fallback(crate::fallback),
        )
        .route(
            "/mcp/tokens/{token_id}",
            delete(revoke).fallback(crate::fallback),
        )
}

fn unprocessable(message: &str) -> Response {
    error(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn now() -> chrono::NaiveDateTime {
    chrono::Utc::now().naive_utc()
}

fn token_json(token: &McpToken, at: chrono::NaiveDateTime) -> Value {
    json!({
        "id": token.id,
        "name": token.name,
        "prefix": token.prefix,
        "can_write": token.can_write,
        "expires_at": mcp::iso(&token.expires_at),
        "expired": mcp::expired(&token.expires_at, at),
        "last_used_at": token.last_used_at.as_deref().map(mcp::iso),
        "created_at": mcp::iso(&token.created_at),
    })
}

/// `GET /api/mcp/info` - whether the pages should offer tokens, and where
/// an assistant is pointed.
async fn info(current: CurrentUser) -> Response {
    Json(json!({
        "enabled": super::addons::mcp_installed(),
        "endpoint_path": mcp::ENDPOINT_PATH,
        "max_tokens": mcp::MAX_TOKENS,
        "can_manage_all": current.user.is_admin(),
    }))
    .into_response()
}

/// `GET /api/mcp/tokens` - the caller's own; `?all=true`, an
/// administrator's view of every account's.
async fn list_tokens(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    current: CurrentUser,
) -> Response {
    let at = now();
    if query.get("all").is_some_and(|v| v == "true" || v == "1") {
        if !current.user.is_admin() {
            return not_enough_permissions();
        }
        return match state.db.mcp_tokens().all().await {
            Ok(rows) => {
                let items: Vec<Value> = rows
                    .iter()
                    .map(|row| {
                        let mut item = token_json(&row.token, at);
                        item["user_id"] = json!(row.token.user_id);
                        item["owner"] = json!(row.username);
                        item
                    })
                    .collect();
                Json(json!({ "items": items })).into_response()
            }
            Err(e) => {
                tracing::error!("listing MCP tokens failed: {e}");
                internal_error()
            }
        };
    }
    match state.db.mcp_tokens().for_user(current.user.id).await {
        Ok(rows) => {
            let items: Vec<Value> = rows.iter().map(|t| token_json(t, at)).collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => {
            tracing::error!("listing MCP tokens failed: {e}");
            internal_error()
        }
    }
}

/// `POST /api/mcp/tokens` `{name, can_write, expires_days}` - the answer
/// carries the token itself, this once.
async fn create_token(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !super::addons::mcp_installed() {
        return conflict("MCP is not enabled on this panel");
    }
    let body = match super::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return unprocessable("The token's name is 1 to 64 characters.");
    }
    let can_write = match body.get("can_write") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return unprocessable("can_write must be true or false"),
    };
    let days = match body.get("expires_days") {
        None | Some(Value::Null) => 90,
        Some(value) => match value.as_i64().filter(|d| (1..=365).contains(d)) {
            Some(days) => days,
            None => return unprocessable("A token lasts 1 to 365 days."),
        },
    };
    let repo = state.db.mcp_tokens();
    match repo.count_for_user(current.user.id).await {
        Ok(count) if count >= mcp::MAX_TOKENS => {
            return conflict(&format!(
                "An account has at most {} MCP tokens; revoke one first.",
                mcp::MAX_TOKENS
            ))
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!("counting MCP tokens failed: {e}");
            return internal_error();
        }
    }
    let raw = mcp::new_token();
    let made = now();
    let expires = made + chrono::Duration::days(days);
    let id = match repo
        .create(&NewMcpToken {
            user_id: current.user.id,
            name,
            token_hash: &mcp::token_hash(&raw),
            prefix: &mcp::token_prefix(&raw),
            can_write,
            expires_at: &snpanel_db::format_timestamp(expires),
            created_at: &snpanel_db::format_timestamp(made),
        })
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("creating an MCP token failed: {e}");
            return internal_error();
        }
    };
    super::packages::audit_action_detail(
        &state,
        &parts,
        current.user.id,
        "create_mcp_token",
        name,
        if can_write {
            "actions allowed"
        } else {
            "read only"
        },
    )
    .await;
    match repo.by_id(id).await {
        Ok(Some(token)) => {
            let mut answer = token_json(&token, made);
            answer["token"] = json!(raw);
            Json(answer).into_response()
        }
        _ => internal_error(),
    }
}

/// `DELETE /api/mcp/tokens/{id}` - by its account, or an administrator.
/// Somebody else's token is not found, as a missing one is.
async fn revoke(
    State(state): State<AppState>,
    Path(token_id): Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let token = match state.db.mcp_tokens().by_id(token_id).await {
        Ok(Some(token)) if token.user_id == current.user.id || current.user.is_admin() => token,
        Ok(_) => return not_found("Token not found"),
        Err(e) => {
            tracing::error!("reading MCP token {token_id} failed: {e}");
            return internal_error();
        }
    };
    if let Err(e) = state.db.mcp_tokens().delete(token.id).await {
        tracing::error!("revoking MCP token {token_id} failed: {e}");
        return internal_error();
    }
    super::packages::audit_action(
        &state,
        &parts,
        current.user.id,
        "revoke_mcp_token",
        &token.name,
    )
    .await;
    Json(json!({ "ok": true })).into_response()
}

/// `DELETE /api/mcp/tokens?all=true` - every account's, for an
/// administrator. The flag is required: a bare DELETE of the collection is
/// too easy to send by mistake.
async fn revoke_all(
    State(state): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !current.user.is_admin() {
        return not_enough_permissions();
    }
    if !query.get("all").is_some_and(|v| v == "true" || v == "1") {
        return unprocessable("Add all=true to revoke every account's tokens.");
    }
    match state.db.mcp_tokens().delete_all().await {
        Ok(revoked) => {
            super::packages::audit_action(
                &state,
                &parts,
                current.user.id,
                "revoke_all_mcp_tokens",
                &revoked.to_string(),
            )
            .await;
            Json(json!({ "revoked": revoked })).into_response()
        }
        Err(e) => {
            tracing::error!("revoking every MCP token failed: {e}");
            internal_error()
        }
    }
}

/// `GET` and `DELETE /api/mcp`: this server keeps no stream and no session.
async fn not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        Json(json!({ "detail": "Method Not Allowed" })),
    )
        .into_response()
}

/// Whether an `Origin` names the host the request was sent to - a page of
/// this panel. Any other, and `null`, is not.
pub fn same_origin(origin: &str, host: &str) -> bool {
    let origin = origin.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    let default = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return false,
    };
    let bare = |a: &str| a.strip_suffix(default).unwrap_or(a).to_string();
    !host.is_empty() && bare(authority.trim_end_matches('/')) == bare(&host)
}

fn unauthorised(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            format!("Bearer realm=\"{}\"", mcp::REALM),
        )],
        Json(json!({ "detail": detail })),
    )
        .into_response()
}

/// The token a request carries, and the account it acts for.
async fn authenticate(
    state: &AppState,
    parts: &axum::http::request::Parts,
) -> Result<(CurrentUser, McpToken), Response> {
    let raw = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| unauthorised("An MCP token is required"))?;
    if !mcp::looks_like_token(raw) {
        return Err(unauthorised("Invalid token"));
    }
    let token = state
        .db
        .mcp_tokens()
        .by_hash(&mcp::token_hash(raw))
        .await
        .map_err(|e| {
            tracing::error!("reading an MCP token failed: {e}");
            internal_error()
        })?
        .ok_or_else(|| unauthorised("Invalid token"))?;
    let at = now();
    if mcp::expired(&token.expires_at, at) {
        return Err(unauthorised("This token has expired"));
    }
    let user = match state.db.users().by_id(token.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(unauthorised("Invalid token")),
        Err(e) => {
            tracing::error!("reading the account of an MCP token failed: {e}");
            return Err(internal_error());
        }
    };
    if !user.is_active {
        return Err(unauthorised("This account is suspended"));
    }
    let _ = state
        .db
        .mcp_tokens()
        .touch(
            token.id,
            &snpanel_db::format_timestamp(at),
            &snpanel_db::format_timestamp(at - chrono::Duration::seconds(60)),
        )
        .await;
    Ok((CurrentUser::acting_for(user), token))
}

/// `POST /api/mcp`.
async fn endpoint(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    if !super::addons::mcp_installed() {
        return not_found("MCP is not enabled on this panel");
    }
    let (parts, body) = req.into_parts();
    if let Some(origin) = parts.headers.get(header::ORIGIN) {
        let host = parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !same_origin(origin.to_str().unwrap_or(""), host) {
            return error(
                StatusCode::FORBIDDEN,
                "Requests from web pages are not accepted",
            );
        }
    }
    let (current, token) = match authenticate(&state, &parts).await {
        Ok(found) => found,
        Err(r) => return r,
    };
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY).await else {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "The request is larger than 8 MB",
        );
    };
    let Ok(message) = serde_json::from_slice::<Value>(&bytes) else {
        return (StatusCode::BAD_REQUEST, Json(mcp::parse_error())).into_response();
    };
    let ctx = Arc::new(mcp::Context::new(state, current, token, &parts));
    match mcp::handle_body(&ctx, &message).await {
        Some(reply) => Json(reply).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_page_of_this_panel_is_its_own_origin() {
        assert!(same_origin(
            "https://panel.example.com:2222",
            "panel.example.com:2222"
        ));
        assert!(same_origin(
            "HTTPS://Panel.Example.com:2222/",
            "panel.example.com:2222"
        ));
        assert!(same_origin(
            "https://panel.example.com",
            "panel.example.com:443"
        ));
        assert!(same_origin("http://10.0.0.5:80", "10.0.0.5"));
        assert!(!same_origin(
            "https://evil.example.com",
            "panel.example.com:2222"
        ));
        assert!(!same_origin(
            "https://panel.example.com:2223",
            "panel.example.com:2222"
        ));
        assert!(!same_origin("null", "panel.example.com:2222"));
        assert!(!same_origin("file://x", "x"));
        assert!(!same_origin("https://panel.example.com:2222", ""));
    }
}
