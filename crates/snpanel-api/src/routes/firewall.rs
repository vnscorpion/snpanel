//! `/api/firewall` - ported from `api/firewall.py` and `services/firewall.py`.
//!
//! Every endpoint is admin-only and every one of them ends at the helper. The
//! router validates, the helper owns the rule file and the kernel state, and
//! the response is the helper's own `{command, returncode, stdout, stderr}`.
//!
//! Three rules carry real weight:
//!
//! **A protected rule cannot be deleted.** SSH, the web ports, mail and the
//! panel's own port are refused - deleting the panel's port through the panel
//! is how an administrator locks themselves out of a machine they may have no
//! other way into. The check runs against the rule *as the helper reports it*,
//! not against the number the caller sent.
//!
//! **`check=True` means a failure is a 500.** `enable`, `disable`, `reload`
//! and the rule endpoints raise in Python when the helper fails, and an
//! unhandled exception is a 500. The blocklist endpoints use `check=False` and
//! turn a failure into a 400 with the helper's message. Those are different
//! answers to the same kind of problem, and both are reproduced.
//!
//! **An address is normalised before it is stored** (C13):
//! `ipaddress.ip_network(value, strict=False)` turns `203.0.113.4` into
//! `203.0.113.4/32` and masks the host bits off `10.1.2.3/8`. The helper
//! stores what it is given, so normalising differently would write a rule the
//! panel cannot match against its own list.

use axum::extract::{Path, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde_json::{json, Value};
use snpanel_core::permissions::{self, Role};
use snpanel_core::types::IpOrCidr;

use crate::auth::CurrentUser;
use crate::errors::{bad_request, internal_error, not_enough_permissions};
use crate::shell;
use crate::state::AppState;

/// Source: `DEFAULT_PROTECTED_PORTS`.
const DEFAULT_PROTECTED_PORTS: &[i64] = &[22, 80, 443, 465, 587, 2222];
/// Source: `PANEL_ZONE`.
const PANEL_ZONE: &str = "PanelZone";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/firewall/status", get(status))
        .route("/firewall/enable", post(enable))
        .route("/firewall/disable", post(disable))
        .route("/firewall/reload", post(reload))
        .route("/firewall/allow-port", post(allow_port))
        .route("/firewall/allow-ip", post(allow_ip))
        .route("/firewall/block-ip", post(block_ip))
        .route("/firewall/rules/{number}", delete(delete_rule))
        .route("/firewall/blocklists", get(blocklists).post(add_blocklist))
        .route("/firewall/blocklists/delete", post(delete_blocklist))
        .route("/firewall/blocklists/update", post(update_blocklists))
}

fn require_admin(current: &CurrentUser) -> Result<(), Response> {
    if permissions::has_role(&current.user.role, Role::Admin) {
        Ok(())
    } else {
        Err(not_enough_permissions())
    }
}

/// Every endpoint but `status` shares this shape: authenticate, require admin,
/// read the body, run one helper command.
async fn admin_and_body(
    state: &AppState,
    req: Request,
) -> Result<(axum::http::request::Parts, Value), Response> {
    let (mut parts, body) = req.into_parts();
    let current = CurrentUser::from_parts(&mut parts, state).await?;
    require_admin(&current)?;
    let payload = super::auth::read_json_body(body).await?;
    Ok((parts, payload))
}

async fn admin_only(state: &AppState, req: Request) -> Result<(), Response> {
    let (mut parts, _) = req.into_parts();
    let current = CurrentUser::from_parts(&mut parts, state).await?;
    require_admin(&current)
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

async fn status(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }
    // `check=False`: a firewall that cannot be queried still renders a page
    // saying so, rather than a 500 that tells the administrator nothing.
    let result = shell::privileged(
        state.settings.command_dry_run,
        "firewall-status",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "echo 'Status: unknown'; echo 'Engine: iptables + ipset'",
        ]),
    )
    .await;
    let listing = listing(&state).await;
    let mut body = result.to_json();
    body["rules"] = Value::Array(parse_rules(&listing));
    // Not in the Python. What the page shows at a glance - on or off, whether
    // that is actually in force, which ports can never be closed - taken from
    // the same `firewall-list` call as the rules, so the page need not read
    // it out of the status text, which is for people.
    body["summary"] = parse_summary(&listing);
    axum::Json(body).into_response()
}

/// The helper's `firewall-list` answer, or nothing.
async fn listing(state: &AppState) -> String {
    let result = shell::privileged(
        state.settings.command_dry_run,
        "firewall-list",
        &[],
        None,
        Some(&["bash", "-lc", "echo '{\"rules\": []}'"]),
    )
    .await;
    if result.ok() {
        result.stdout
    } else {
        String::new()
    }
}

/// Source: `firewall.rules()` - the helper's structured list, or an empty one.
///
/// An unparsable answer is an empty list rather than an error: the status page
/// must not break on a single bad line from a machine that is otherwise fine.
async fn rules(state: &AppState) -> Vec<Value> {
    parse_rules(&listing(state).await)
}

/// `state`, `engine`, `chain_active` and `protected_ports` from the listing,
/// each `null` (the ports an empty list) when the helper did not say it in
/// the expected shape - the same forgiveness as [`parse_rules`], and for the
/// same reason.
fn parse_summary(output: &str) -> Value {
    let data = serde_json::from_str::<Value>(output).unwrap_or(Value::Null);
    let state = match data.get("state").and_then(Value::as_str) {
        Some(s @ ("enabled" | "disabled")) => json!(s),
        _ => Value::Null,
    };
    let engine = data
        .get("engine")
        .and_then(Value::as_str)
        .map_or(Value::Null, |e| json!(e));
    let chain_active = data
        .get("chain_active")
        .and_then(Value::as_bool)
        .map_or(Value::Null, |b| json!(b));
    let protected_ports: Vec<Value> = data
        .get("protected_ports")
        .and_then(Value::as_array)
        .map(|ports| ports.iter().filter(|p| p.is_u64()).cloned().collect())
        .unwrap_or_default();
    json!({
        "state": state,
        "engine": engine,
        "chain_active": chain_active,
        "protected_ports": protected_ports,
    })
}

/// Source: `parse_rules` - a bare list, or an object with a `rules` key.
fn parse_rules(output: &str) -> Vec<Value> {
    let Ok(data) = serde_json::from_str::<Value>(if output.trim().is_empty() {
        "{}"
    } else {
        output
    }) else {
        return Vec::new();
    };
    let items = match &data {
        Value::Array(items) => items.clone(),
        Value::Object(map) => match map.get("rules") {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        },
        _ => return Vec::new(),
    };
    items.into_iter().filter(|i| i.is_object()).collect()
}

/// Source: `is_protected_rule`.
fn is_protected_rule(rule: &Value, panel_port: i64) -> bool {
    if rule
        .get("protected")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    if rule.get("zone").and_then(Value::as_str).unwrap_or("") == PANEL_ZONE {
        return true;
    }
    if !rule
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .eq_ignore_ascii_case("allow")
    {
        return false;
    }
    // A rule scoped to one address is the administrator's own and may go; the
    // protected set is about ports open to everybody.
    if rule
        .get("ip")
        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    {
        return false;
    }
    let port = match rule.get("port") {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    DEFAULT_PROTECTED_PORTS.contains(&port) || port == panel_port
}

// ---------------------------------------------------------------------------
// The three that take no body
// ---------------------------------------------------------------------------

/// `check=True` in the Python, so a failing helper is a 500 rather than a
/// reported failure. Reproduced: an endpoint that starts answering 400 where
/// it used to answer 500 is a different API.
async fn run_checked(state: &AppState, command: &str, args: &[&str]) -> Response {
    // `fallback=["true"]` at every one of these call sites: on a development
    // box with no helper the operation reports success and changes nothing.
    let result = shell::privileged(
        state.settings.command_dry_run,
        command,
        args,
        None,
        Some(&["true"]),
    )
    .await;
    if !result.ok() {
        tracing::error!(
            command = %result.command,
            returncode = result.returncode,
            "privileged command failed: {}",
            result.stderr.trim()
        );
        return internal_error();
    }
    axum::Json(result.to_json()).into_response()
}

async fn enable(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = admin_only(&state, req).await {
        return r;
    }
    run_checked(&state, "firewall-enable", &[]).await
}

async fn disable(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = admin_only(&state, req).await {
        return r;
    }
    run_checked(&state, "firewall-disable", &[]).await
}

async fn reload(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = admin_only(&state, req).await {
        return r;
    }
    run_checked(&state, "firewall-reload", &[]).await
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Source: `_validate_port` - a string of at most five digits, 1 to 65535.
fn validate_port(raw: &Value) -> Result<String, Response> {
    let text = match raw {
        Value::String(s) => s.trim().to_string(),
        // Pydantic declares `port: str`, so a JSON number is a type error
        // before any of this runs.
        other => return Err(crate::errors::string_type("port", other)),
    };
    let numeric = !text.is_empty() && text.len() <= 5 && text.chars().all(|c| c.is_ascii_digit());
    let value: i64 = text.parse().unwrap_or(0);
    if !numeric || !(1..=65535).contains(&value) {
        return Err(bad_request("Port must be a number from 1 to 65535"));
    }
    Ok(text)
}

/// Source: `_validate_protocol`.
fn validate_protocol(raw: Option<&Value>) -> Result<String, Response> {
    let text = match raw {
        None | Some(Value::Null) => "tcp".to_string(),
        Some(Value::String(s)) => s.trim().to_lowercase(),
        Some(other) => return Err(crate::errors::string_type("protocol", other)),
    };
    // An empty string falls back to tcp, as `(protocol or "tcp")` does.
    let text = if text.is_empty() {
        "tcp".to_string()
    } else {
        text
    };
    if text != "tcp" && text != "udp" {
        return Err(bad_request("Protocol must be tcp or udp"));
    }
    Ok(text)
}

/// Source: `_validate_network` - `ip_network(value, strict=False)`, which
/// always emits a prefix and masks the host bits away (C13).
fn validate_network(raw: Option<&Value>) -> Result<String, Response> {
    let text = match raw {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(other) => return Err(crate::errors::string_type("ip", other)),
        None => return Err(crate::errors::missing_field("ip", Value::Null)),
    };
    match IpOrCidr::parse(&text) {
        Ok(parsed) => Ok(parsed.normalized()),
        Err(_) => Err(bad_request(
            "IP must be a valid IPv4/IPv6 address or CIDR network",
        )),
    }
}

async fn allow_port(State(state): State<AppState>, req: Request) -> Response {
    let (_, payload) = match admin_and_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(port_raw) = payload.get("port") else {
        return crate::errors::missing_field("port", payload.clone());
    };
    let port = match validate_port(port_raw) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let protocol = match validate_protocol(payload.get("protocol")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    run_checked(&state, "firewall-allow-port", &[&port, &protocol]).await
}

/// `allow-ip` and `block-ip` differ only in the helper operation they call.
async fn ip_rule(state: &AppState, payload: &Value, command: &str) -> Response {
    let network = match validate_network(payload.get("ip")) {
        Ok(n) => n,
        Err(r) => return r,
    };
    // A rule with no port covers every port, and the helper takes one argument
    // instead of three. `if not port` in the Python, so an empty string counts
    // as absent too.
    let port_given = payload
        .get("port")
        .map(|v| !matches!(v, Value::Null) && v.as_str() != Some(""))
        .unwrap_or(false);
    if !port_given {
        return run_checked(state, command, &[&network]).await;
    }
    let port = match validate_port(payload.get("port").unwrap()) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let protocol = match validate_protocol(payload.get("protocol")) {
        Ok(p) => p,
        Err(r) => return r,
    };
    run_checked(state, command, &[&network, &port, &protocol]).await
}

async fn allow_ip(State(state): State<AppState>, req: Request) -> Response {
    let (_, payload) = match admin_and_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    ip_rule(&state, &payload, "firewall-allow-ip").await
}

async fn block_ip(State(state): State<AppState>, req: Request) -> Response {
    let (_, payload) = match admin_and_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    ip_rule(&state, &payload, "firewall-deny-ip").await
}

async fn delete_rule(
    State(state): State<AppState>,
    Path(number): Path<i64>,
    req: Request,
) -> Response {
    if let Err(r) = admin_only(&state, req).await {
        return r;
    }
    if number < 1 {
        return bad_request("Rule number must be greater than 0");
    }

    // Looked up in the helper's own list rather than trusted from the caller:
    // the protection below is only worth anything if it is applied to the rule
    // that will actually be deleted.
    let all = rules(&state).await;
    let Some(rule) = all
        .iter()
        .find(|r| r.get("id").and_then(Value::as_i64) == Some(number))
    else {
        return bad_request(&format!("Rule #{number} was not found"));
    };

    let panel_port: i64 = state.settings.panel_port.get() as i64;
    if is_protected_rule(rule, panel_port) {
        return bad_request("Default panel, mail, web, and SSH firewall rules cannot be deleted");
    }

    run_checked(&state, "firewall-delete", &[&number.to_string()]).await
}

// ---------------------------------------------------------------------------
// Blocklists - `check=False`, so a failure is a 400 carrying the message
// ---------------------------------------------------------------------------

async fn blocklists(State(state): State<AppState>, current: CurrentUser) -> Response {
    if let Err(r) = require_admin(&current) {
        return r;
    }
    let result = shell::privileged(
        state.settings.command_dry_run,
        "firewall-blocklist-status",
        &[],
        None,
        Some(&[
            "bash",
            "-lc",
            "echo 'URLs:'; echo '  (none)'; echo; echo 'Engine:'; echo '  iptables + ipset'",
        ]),
    )
    .await;
    axum::Json(result.to_json()).into_response()
}

/// Source: the `validate_url` field validator.
fn validate_url(payload: &Value) -> Result<String, Response> {
    let raw = match payload.get("url") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => return Err(crate::errors::string_type("url", other)),
        None => return Err(crate::errors::missing_field("url", payload.clone())),
    };
    crate::errors::check_length("url", &raw, 8, 2048)?;
    let value = raw.trim().to_string();
    let scheme_ok = value.starts_with("http://") || value.starts_with("https://");
    let has_host = value
        .split_once("://")
        .map(|(_, rest)| !rest.is_empty() && !rest.starts_with('/'))
        .unwrap_or(false);
    if !scheme_ok || !has_host {
        return Err(crate::errors::value_error(
            "url",
            "URL must start with http:// or https://",
            &json!(raw),
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(crate::errors::value_error(
            "url",
            "URL must not contain whitespace",
            &json!(raw),
        ));
    }
    Ok(value)
}

async fn run_unchecked(
    state: &AppState,
    command: &str,
    args: &[&str],
    default: &str,
    fallback: Option<&[&str]>,
) -> Response {
    let result = shell::privileged(
        state.settings.command_dry_run,
        command,
        args,
        None,
        fallback,
    )
    .await;
    if !result.ok() {
        return bad_request(&result.failure_detail(default));
    }
    axum::Json(result.to_json()).into_response()
}

async fn add_blocklist(State(state): State<AppState>, req: Request) -> Response {
    let (_, payload) = match admin_and_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let url = match validate_url(&payload) {
        Ok(u) => u,
        Err(r) => return r,
    };
    run_unchecked(
        &state,
        "firewall-blocklist-add",
        &[&url],
        "Could not add URL",
        Some(&["bash", "-lc", "echo URL added"]),
    )
    .await
}

async fn delete_blocklist(State(state): State<AppState>, req: Request) -> Response {
    let (_, payload) = match admin_and_body(&state, req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let url = match validate_url(&payload) {
        Ok(u) => u,
        Err(r) => return r,
    };
    run_unchecked(
        &state,
        "firewall-blocklist-delete",
        &[&url],
        "Could not delete URL",
        Some(&["bash", "-lc", "echo URL deleted"]),
    )
    .await
}

async fn update_blocklists(State(state): State<AppState>, req: Request) -> Response {
    if let Err(r) = admin_only(&state, req).await {
        return r;
    }
    run_unchecked(
        &state,
        "firewall-blocklist-update",
        &[],
        "Could not update blocklists",
        Some(&["bash", "-lc", "echo blocklists updated"]),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_must_be_a_number_in_range() {
        assert_eq!(validate_port(&json!("80")).unwrap(), "80");
        assert_eq!(validate_port(&json!(" 8080 ")).unwrap(), "8080");
        assert_eq!(validate_port(&json!("65535")).unwrap(), "65535");
        for bad in ["0", "65536", "", "abc", "-1", "8.0", "123456"] {
            assert!(validate_port(&json!(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_protocol_defaults_to_tcp_and_accepts_nothing_exotic() {
        assert_eq!(validate_protocol(None).unwrap(), "tcp");
        assert_eq!(validate_protocol(Some(&json!(""))).unwrap(), "tcp");
        assert_eq!(validate_protocol(Some(&json!("UDP"))).unwrap(), "udp");
        assert_eq!(validate_protocol(Some(&json!(" tcp "))).unwrap(), "tcp");
        assert!(validate_protocol(Some(&json!("icmp"))).is_err());
        assert!(validate_protocol(Some(&json!("tcp; rm -rf /"))).is_err());
    }

    #[test]
    fn an_address_is_normalised_the_way_python_normalises_it() {
        // C13. A bare address gains its full-length prefix, and host bits are
        // masked off - store it differently and the panel cannot match its own
        // rule against the list the helper reports.
        assert_eq!(
            validate_network(Some(&json!("203.0.113.4"))).unwrap(),
            "203.0.113.4/32"
        );
        assert_eq!(
            validate_network(Some(&json!("10.1.2.3/8"))).unwrap(),
            "10.0.0.0/8"
        );
        assert_eq!(validate_network(Some(&json!("::1"))).unwrap(), "::1/128");
        for bad in ["", "not-an-ip", "999.1.1.1", "10.0.0.0/33"] {
            assert!(validate_network(Some(&json!(bad))).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_rule_list_survives_anything_the_helper_says() {
        // An unparsable answer is an empty list, not a broken status page.
        assert_eq!(parse_rules("").len(), 0);
        assert_eq!(parse_rules("not json").len(), 0);
        assert_eq!(parse_rules("null").len(), 0);
        assert_eq!(parse_rules(r#"{"rules": "nonsense"}"#).len(), 0);
        // Both shapes the helper may use.
        assert_eq!(parse_rules(r#"{"rules": [{"id": 1}]}"#).len(), 1);
        assert_eq!(parse_rules(r#"[{"id": 1}, {"id": 2}]"#).len(), 2);
        // Non-objects inside the list are dropped rather than passed through.
        assert_eq!(parse_rules(r#"[{"id": 1}, "junk", 7]"#).len(), 1);
    }

    #[test]
    fn the_summary_survives_anything_the_helper_says() {
        let nothing = json!({
            "state": null, "engine": null, "chain_active": null, "protected_ports": [],
        });
        for junk in [
            "",
            "not json",
            "null",
            "[]",
            r#"[{"id": 1}]"#,
            r#"{"rules": []}"#,
        ] {
            assert_eq!(parse_summary(junk), nothing, "{junk:?}");
        }
        // Wrong types are dropped, not passed on.
        assert_eq!(
            parse_summary(
                r#"{"state": "maybe", "engine": 5, "chain_active": "yes", "protected_ports": ["22", 80, -1]}"#
            ),
            json!({ "state": null, "engine": null, "chain_active": null, "protected_ports": [80] })
        );
        // What the helper actually says.
        assert_eq!(
            parse_summary(
                r#"{"state": "enabled", "engine": "nftables", "chain_active": false,
                    "rules": [], "protected_ports": [22, 80, 443, 465, 587, 2222]}"#
            ),
            json!({
                "state": "enabled",
                "engine": "nftables",
                "chain_active": false,
                "protected_ports": [22, 80, 443, 465, 587, 2222],
            })
        );
    }

    #[test]
    fn the_panels_own_port_cannot_be_deleted() {
        // Deleting this through the panel is how an administrator locks
        // themselves out of a machine they may have no other way into.
        let rule = json!({"id": 3, "action": "ALLOW", "port": 2222});
        assert!(is_protected_rule(&rule, 2222));
        // Even on a panel moved to another port, the *configured* port is the
        // one protected.
        let rule = json!({"id": 3, "action": "ALLOW", "port": 9443});
        assert!(is_protected_rule(&rule, 9443));
        assert!(!is_protected_rule(&rule, 2222));
    }

    #[test]
    fn the_default_protected_ports_are_protected() {
        for port in [22, 80, 443, 465, 587, 2222] {
            let rule = json!({"id": 1, "action": "ALLOW", "port": port});
            assert!(is_protected_rule(&rule, 2222), "port {port}");
        }
        // A port string rather than a number, as the helper may emit.
        assert!(is_protected_rule(
            &json!({"action": "allow", "port": "22"}),
            2222
        ));
    }

    #[test]
    fn an_ordinary_rule_is_deletable() {
        assert!(!is_protected_rule(
            &json!({"id": 9, "action": "ALLOW", "port": 8080}),
            2222
        ));
        // A DENY on a protected port is still the administrator's own rule.
        assert!(!is_protected_rule(
            &json!({"id": 9, "action": "DENY", "port": 22}),
            2222
        ));
        // A rule scoped to one address is not part of the protected set.
        assert!(!is_protected_rule(
            &json!({"id": 9, "action": "ALLOW", "port": 22, "ip": "203.0.113.4/32"}),
            2222
        ));
    }

    #[test]
    fn the_explicit_markers_protect_a_rule_whatever_else_it_says() {
        assert!(is_protected_rule(&json!({"protected": true}), 2222));
        assert!(is_protected_rule(&json!({"zone": "PanelZone"}), 2222));
    }

    #[test]
    fn a_blocklist_url_must_be_http_with_a_host() {
        assert_eq!(
            validate_url(&json!({"url": " https://example.com/list.txt "})).unwrap(),
            "https://example.com/list.txt"
        );
        for bad in [
            "ftp://example.com/list",
            "https://",
            "javascript:alert(1)",
            "file:///etc/passwd",
        ] {
            assert!(validate_url(&json!({ "url": bad })).is_err(), "{bad:?}");
        }
        // Whitespace inside is refused: the helper writes this into a file it
        // later reads a line at a time.
        assert!(validate_url(&json!({"url": "https://a.example/a b"})).is_err());
        // Too short to be a URL at all.
        assert!(validate_url(&json!({"url": "http://"})).is_err());
    }
}
