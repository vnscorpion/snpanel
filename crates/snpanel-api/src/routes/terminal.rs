//! `/api/terminal` - ported from `api/terminal.py`.
//!
//! The allow-list, one-shot execution, and the interactive session.
//!
//! The websocket used to be described here as "a pty relay, not a request",
//! and left with Python on that basis. It is neither: `resize` is a no-op on
//! the Python side too, and every `input` message runs the same one-shot
//! `exec_command` the REST endpoint runs. What the socket adds over
//! `/terminal/exec` is a session `cwd` and a message loop.
//!
//! It could not have stayed with Python in any case. The strangler strips
//! `connection` and `upgrade` as hop-by-hop headers — correctly, for an
//! ordinary proxied request — so a websocket upgrade never reached uvicorn
//! at all, and the interactive terminal was unreachable on any box where
//! this process held the port.
//!
//! The allow-list is what the frontend uses for completion and for the help
//! panel.
//!
//! **This list mirrors the helper's own allow-list for `terminal-exec`, and
//! the two are kept in sync deliberately.** The panel's copy is advisory - it
//! tells the user what will work - while the helper's copy is the one that
//! actually refuses. A name in this list that the helper does not accept is a
//! confusing error; a name the helper accepts that is missing here is worse,
//! because the allow-list stops looking like the whole story.
//!
//! The helper's copy was a `case` statement in `snpanel-helper.sh` until that
//! script was deleted; it is `ops::terminal` now, and the pairing is the
//! same.

use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use snpanel_core::permissions;

use crate::auth::CurrentUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/terminal/allowed-commands",
            get(allowed_commands).fallback(crate::fallback),
        )
        .route(
            "/terminal/exec/{website_id}",
            post(exec).fallback(crate::fallback),
        )
        .route(
            "/terminal/ws/{website_id}",
            get(session).fallback(crate::fallback),
        )
}

/// Source: `RUNTIME_COMMANDS` - the toolchains a PHP, WordPress or Laravel
/// site actually needs.
const RUNTIME_COMMANDS: &[&str] = &[
    "php", "composer", "artisan", "wp", "phpunit", "node", "npm", "npx", "yarn", "git",
];

/// Source: `UTILITY_COMMANDS` - the ones the helper path-checks, so every path
/// argument has to resolve inside the site owner's home.
const UTILITY_COMMANDS: &[&str] = &[
    "ls", "cat", "mkdir", "rmdir", "rm", "cp", "mv", "chmod", "chown", "touch", "grep", "find",
    "tar", "zip", "unzip", "diff", "head", "tail", "less", "du", "df", "sed", "awk", "wc", "sort",
    "uniq", "stat", "file", "curl", "wget",
];

/// Source: `INFO_COMMANDS` - report state and never touch a caller-supplied
/// path.
const INFO_COMMANDS: &[&str] = &[
    "pwd", "echo", "cd", "clear", "date", "whoami", "which", "id", "uname", "printenv", "basename",
    "dirname", "realpath",
];

/// Source: `sorted(terminal.ALLOWED_COMMANDS)` - the union, sorted, because
/// the Python hands a set to `sorted()` and the frontend renders the order.
fn allowed() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = RUNTIME_COMMANDS
        .iter()
        .chain(UTILITY_COMMANDS)
        .chain(INFO_COMMANDS)
        .copied()
        .collect();
    all.sort_unstable();
    all.dedup();
    all
}

async fn allowed_commands(_current: CurrentUser) -> Response {
    axum::Json(json!({ "commands": allowed() })).into_response()
}

// ---------------------------------------------------------------------------
// running one command
// ---------------------------------------------------------------------------

/// Source: `MAX_COMMAND_CHARS` - "keeps accidental paste storms out of the
/// helper boundary".
const MAX_COMMAND_CHARS: usize = 4096;
/// Source: `MAX_OUTPUT_BYTES`.
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Source: `DEFAULT_TIMEOUT`.
const DEFAULT_TIMEOUT: u64 = 60;
/// Source: `LONG_RUNNING_TIMEOUT`.
const LONG_RUNNING_TIMEOUT: u64 = 900;
/// Source: `MAX_TIMEOUT`.
const MAX_TIMEOUT: u64 = 1800;

/// Source: `LONG_RUNNING_COMMANDS` - "dependency installers and WordPress
/// updates routinely run for minutes, so they get their own budget instead of
/// being killed at the interactive default".
const LONG_RUNNING_COMMANDS: &[&str] = &[
    "composer", "npm", "npx", "yarn", "node", "git", "wp", "artisan", "php", "phpunit", "curl",
    "wget", "tar", "zip", "unzip",
];

/// Source: `timeout_for`.
fn timeout_for(command_name: &str) -> u64 {
    if LONG_RUNNING_COMMANDS.contains(&command_name) {
        LONG_RUNNING_TIMEOUT
    } else {
        DEFAULT_TIMEOUT
    }
}

/// Source: `_PHP_VERSION_RE` - `^\d+\.\d+$`.
///
/// Anchored at **both** ends. `re.match` only anchors the start; the `$` does
/// the rest, so `8.4.1` is refused and `08.04` is accepted. Getting that
/// backwards would put `--php-version=8.4.1` in front of the helper for a
/// string that is not a version.
///
/// Two smaller differences from `re`, both deliberate. Python's `$` also
/// matches just before a single trailing newline, which is reproduced. And
/// Python's `\d` matches any Unicode decimal digit, while this matches ASCII
/// only: `php_version` reaches here from the websites table, which is written
/// from the installed-version list, so a Devanagari digit has no way in. It is
/// a difference, and it is written down rather than left to be discovered.
fn php_version_flag_ok(value: &str) -> bool {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let Some((major, minor)) = value.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}

/// Source: `_truncate_output` - cut at the byte limit, drop whatever partial
/// character that leaves, and say so.
fn truncate_output(output: &str) -> String {
    if output.len() <= MAX_OUTPUT_BYTES {
        return output.to_string();
    }
    let bytes = &output.as_bytes()[..MAX_OUTPUT_BYTES];
    // `bytes.decode("utf-8", errors="ignore")` on a cut that lands inside a
    // character drops that character; `from_utf8_lossy` would put a
    // replacement character there instead, which is a different string.
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t.to_string(),
        Err(e) => String::from_utf8_lossy(&bytes[..e.valid_up_to()]).into_owned(),
    };
    text + "\n... (output truncated)"
}

/// Source: `site_users.document_root(root)` followed by `terminal.default_cwd`.
///
/// It uses the **default** `public_html`, not the website's configured
/// document root. That looks like an oversight and may well be one, but a site
/// served from `public_html/public` would have its terminal open somewhere
/// else the moment this "improved", and the customer's muscle memory is built
/// on where it opens today. NT1.
fn default_cwd(site_root: &str) -> String {
    let root = std::path::Path::new(site_root);
    let resolved = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let candidate = resolved.join("public_html");
    if candidate.is_dir() {
        // `.resolve()` again in the Python; a symlinked `public_html` resolves
        // to its target and the helper is what checks where that lands.
        let target = std::fs::canonicalize(&candidate).unwrap_or(candidate);
        if target.starts_with(&resolved) {
            return target.to_string_lossy().into_owned();
        }
        // Source: `document_root` raising when the target leaves the root.
        // The Python would propagate that as a 500; here it is the same
        // refusal, stated rather than silently falling back to the root.
        return resolved.to_string_lossy().into_owned();
    }
    resolved.to_string_lossy().into_owned()
}

/// `Path.resolve(strict=False)`: follow symlinks as far as they go, fold
/// `.` and `..`, and append whatever tail does not exist yet.
///
/// Rust's `canonicalize` refuses a path that is not there, and `cd
/// nosuchdir` has to get far enough to be told *which* error it is — the
/// containment check runs before the existence check, so a non-existent path
/// still has to be resolved.
fn resolve_lenient(path: &Path) -> PathBuf {
    resolve_lenient_inner(path, 0)
}

/// 40 is the same ceiling Linux puts on symlink resolution; a cycle has to
/// end somewhere and an unbounded recursion here is a stack overflow in a
/// request handler.
const MAX_SYMLINK_DEPTH: u32 = 40;

fn resolve_lenient_inner(path: &Path, depth: u32) -> PathBuf {
    use std::path::Component;

    let mut out = PathBuf::from("/");
    if depth >= MAX_SYMLINK_DEPTH {
        return path.to_path_buf();
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => out = PathBuf::from("/"),
            Component::CurDir => {}
            // Popping the *resolved* path, which is what makes `..` after a
            // symlink mean what the filesystem means by it.
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(name);
                if let Ok(target) = std::fs::read_link(&out) {
                    let joined = if target.is_absolute() {
                        target
                    } else {
                        out.parent().unwrap_or(Path::new("/")).join(target)
                    };
                    out = resolve_lenient_inner(&joined, depth + 1);
                }
            }
        }
    }
    out
}

/// Source: `terminal.resolve_cwd` - "resolve a cd target, keeping the session
/// inside one website root."
///
/// Two orderings carry the security of this function, and both are recorded
/// in the corpus rather than reasoned about:
///
/// * **containment before existence.** `cd /etc` is "outside this website",
///   not a directory listing, and `cd ../../nosuchdir` is outside rather than
///   missing. Reporting existence first would tell a customer whether a path
///   outside their site is there.
/// * **containment on the resolved paths, component-wise.** A sibling
///   directory named `siteX` beside a root named `site` is outside, which a
///   string-prefix check would get wrong, and a symlink pointing out of the
///   tree is refused because it is followed before the comparison.
fn resolve_cwd(site_root: &str, current_cwd: &str, target: &str) -> Result<String, String> {
    let root = resolve_lenient(Path::new(site_root));
    let current = resolve_lenient(Path::new(if current_cwd.is_empty() {
        site_root
    } else {
        current_cwd
    }));

    // `target = (target or "").strip()` - and the error messages below quote
    // this stripped value, not what arrived.
    let target = target.trim();
    let candidate = if target.is_empty() || target == "~" {
        root.clone()
    } else {
        let raw = Path::new(target);
        if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            current.join(raw)
        }
    };
    let resolved = resolve_lenient(&candidate);

    // `os.path.commonpath([root, resolved]) == root`. `starts_with` is
    // component-wise in Rust, so this is that comparison and not a string
    // prefix.
    if !resolved.starts_with(&root) {
        return Err("Path is outside this website".to_string());
    }
    if !resolved.exists() {
        return Err(format!("No such directory: {target}"));
    }
    if !resolved.is_dir() {
        return Err(format!("Not a directory: {target}"));
    }
    Ok(resolved.to_string_lossy().into_owned())
}

/// Source: `may_use_terminal`.
///
/// Separate from owning the website on purpose: owning a site says which site
/// you may act on, not whether a shell is part of what you are paying for.
/// The frontend hides the terminal for accounts without it, and hiding a
/// button is not access control - this endpoint answers curl just as happily.
fn may_use_terminal(user: &snpanel_db::User) -> bool {
    permissions::is_admin_role(&user.role) || user.terminal_enabled
}

/// Source: `get_user_website` - the website, the ownership check, and the
/// entitlement check, in that order.
async fn terminal_website(
    state: &AppState,
    current: &CurrentUser,
    website_id: i64,
) -> Result<snpanel_db::Website, Response> {
    let website = state
        .db
        .websites()
        .by_id(website_id)
        .await
        .map_err(|e| {
            tracing::error!("website lookup failed: {e}");
            crate::errors::internal_error()
        })?
        .ok_or_else(|| crate::errors::not_found("Website not found"))?;
    if website.owner_id != current.user.id
        && !permissions::has_role(&current.user.role, permissions::Role::Admin)
    {
        return Err(crate::errors::not_enough_permissions());
    }
    if !may_use_terminal(&current.user) {
        return Err(crate::errors::error(
            axum::http::StatusCode::FORBIDDEN,
            "Terminal is not enabled for your account.",
        ));
    }
    Ok(website)
}

/// Source: `terminal.exec_command`.
///
/// Every early return here is a `CommandResult` with a non-zero exit code, not
/// an HTTP error, and that is the Python's shape: the terminal reports a
/// refusal the way it reports a command that failed, in the same box, because
/// that is where the customer is looking. 126 for a command outside the
/// allow-list is the shell's own number for "found but not executable".
async fn exec_command(
    dry_run: bool,
    linux_user: &str,
    command: &str,
    cwd: &str,
    php_version: Option<&str>,
) -> (i32, String, String) {
    if linux_user.is_empty() {
        return (
            1,
            String::new(),
            "Website has no runtime user configured".to_string(),
        );
    }

    // Source: `split_command`.
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return (2, String::new(), "Empty command".to_string());
    }
    if trimmed.chars().count() > MAX_COMMAND_CHARS {
        return (
            2,
            String::new(),
            format!("Command is too long; max {MAX_COMMAND_CHARS} characters"),
        );
    }
    let argv = match crate::shlex::split(trimmed) {
        Ok(parts) if parts.is_empty() => return (2, String::new(), "Empty command".to_string()),
        Ok(parts) => parts,
        Err(e) => return (2, String::new(), format!("Invalid command syntax: {e}")),
    };

    let allowed = allowed();
    if !allowed.contains(&argv[0].as_str()) {
        return (
            126,
            String::new(),
            format!(
                "Command not allowed. Allowed commands: {}",
                allowed.join(", ")
            ),
        );
    }
    if argv[0] == "cd" {
        return (
            2,
            String::new(),
            "cd is handled by the interactive terminal session".to_string(),
        );
    }

    let limit = timeout_for(&argv[0]).clamp(1, MAX_TIMEOUT);

    let timeout_flag = format!("--timeout={limit}");
    let mut helper_args: Vec<&str> = vec![linux_user, cwd, &timeout_flag];
    let php_flag;
    if let Some(version) = php_version.filter(|v| php_version_flag_ok(v)) {
        // So the helper calls `php8.4` rather than the system default and
        // Composer's platform checks see the version the site actually runs.
        php_flag = format!("--php-version={version}");
        helper_args.push(&php_flag);
    }
    helper_args.extend(argv.iter().map(String::as_str));

    let result = crate::shell::privileged_timed(
        dry_run,
        "terminal-exec",
        &helper_args,
        None,
        None,
        // The helper kills the command itself; this is only a backstop for a
        // wedged sudo or helper process, so it gets a little headroom.
        Some(limit + 15),
    )
    .await;

    let stdout = truncate_output(&result.stdout);
    let mut stderr = truncate_output(&result.stderr);
    if result.returncode == 124 && stderr.trim().is_empty() {
        // The helper's own kill, which says nothing. A timeout from the
        // backstop above already carries its message.
        stderr = format!("Command timed out after {limit}s");
    }
    (result.returncode, stdout, stderr)
}

/// Source: `exec_command` the endpoint - "suitable for non-interactive
/// commands like php artisan migrate, composer install, npm run build".
async fn exec(
    State(state): State<AppState>,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, body) = req.into_parts();
    let current = match CurrentUser::from_parts(&mut parts, &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let payload = match crate::routes::auth::read_json_body(body).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let website = match terminal_website(&state, &current, website_id).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let Some(raw) = payload.get("command") else {
        return crate::errors::missing_field("command", payload.clone());
    };
    let Some(command) = raw.as_str() else {
        return crate::errors::string_type("command", raw);
    };

    let (exit_code, stdout, stderr) = exec_command(
        state.settings.command_dry_run,
        website.linux_user.as_deref().unwrap_or(""),
        command,
        &default_cwd(&website.root_path),
        Some(website.php_version.as_str()),
    )
    .await;

    // Source: `TerminalExecResponse` - three fields, in this order.
    axum::Json(json!({
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }))
    .into_response()
}

/// Source: `_origin_allowed` - the websocket's CSRF defence.
///
/// **A websocket upgrade is a `GET`**, so the CSRF header check that
/// [`CurrentUser`] makes for mutating methods does not run. The browser's
/// same-origin policy does not help either: unlike `fetch`, a `WebSocket`
/// may be opened cross-origin by any page, and the session cookie is sent
/// with it. This check is the only thing between a page on another site and
/// a shell on the customer's website.
///
/// The rules, in the Python's order:
///
/// * **no `Origin` at all is allowed.** A non-browser client — `wscat`, a
///   test — sends none, and it has no cookie to be abused either. Refusing
///   would lock out the tools without protecting anything.
/// * an `Origin` whose host equals the request's `Host` is the panel
///   talking to itself, whatever port or scheme it was reached on.
/// * otherwise the exact origin has to be one the panel was configured to
///   accept.
/// * and an empty allow-list permits everything, which is the Python's
///   `not allowed or ...` — a box that configured none is not locked out of
///   its own terminal.
fn origin_allowed(origin: Option<&str>, host: Option<&str>, allowed: &[String]) -> bool {
    let Some(origin) = origin.map(|o| o.trim_end_matches('/')) else {
        return true;
    };
    if origin.is_empty() {
        return true;
    }

    // `urlparse(origin).netloc` - the authority, host and port together.
    let origin_host = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let request_host = host.unwrap_or("").to_ascii_lowercase();
    if !origin_host.is_empty() && !request_host.is_empty() && origin_host == request_host {
        return true;
    }

    let allowed: Vec<&str> = allowed.iter().map(|a| a.trim_end_matches('/')).collect();
    allowed.is_empty() || allowed.contains(&origin)
}

/// `GET /api/terminal/ws/{website_id}` - Source: `terminal_websocket`.
///
/// Authentication is the ordinary [`CurrentUser`] extractor, which performs
/// the same six checks the Python repeats inline: signature, subject, the
/// user exists and is active, `token_version`, and a revoked `jti`. Failing
/// any of them rejects the upgrade, which is what the Python's
/// `close()`-before-`accept()` does as well — a browser sees a failed
/// connection either way, because there is no socket yet to carry a code.
///
/// The ownership and entitlement checks are [`terminal_website`], the same
/// ones `/terminal/exec` makes. Both doors have to be locked: the socket is
/// reachable without ever touching the REST endpoint.
async fn session(
    ws: axum::extract::ws::WebSocketUpgrade,
    State(state): State<AppState>,
    current: CurrentUser,
    axum::extract::Path(website_id): axum::extract::Path<i64>,
    headers: axum::http::HeaderMap,
) -> Response {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let mut allowed = state.settings.cors_origins();
    if !state.settings.panel_url.is_empty() {
        allowed.push(state.settings.panel_url.trim_end_matches('/').to_string());
    }
    if !origin_allowed(header("origin"), header("host"), &allowed) {
        return crate::errors::error(axum::http::StatusCode::FORBIDDEN, "Origin not allowed");
    }

    let website = match terminal_website(&state, &current, website_id).await {
        Ok(w) => w,
        Err(response) => return response,
    };
    if website.linux_user.as_deref().unwrap_or("").is_empty() {
        return crate::errors::not_found("Website runtime user is missing");
    }
    let root = std::path::Path::new(&website.root_path);
    if !root.is_dir() {
        return crate::errors::not_found("Website root path does not exist or is not accessible");
    }

    let dry_run = state.settings.command_dry_run;
    ws.on_upgrade(move |socket| run_session(socket, website, dry_run))
}

/// One message, as the frontend sends them.
///
/// Unknown fields are ignored rather than refused: the client and the panel
/// are released together, but a browser left open across an update is a
/// client one release behind.
#[derive(serde::Deserialize)]
struct ClientMessage {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    data: Option<String>,
}

/// The session loop.
///
/// Every reply is a JSON object with a `type`, and the set is the one
/// `Terminal.jsx` switches on: `output`, `exit`, `cwd`, `clear`, `error`,
/// `pong`.
async fn run_session(
    mut socket: axum::extract::ws::WebSocket,
    website: snpanel_db::Website,
    dry_run: bool,
) {
    use axum::extract::ws::Message;

    let mut cwd = default_cwd(&website.root_path);
    // The prompt cannot be drawn until the client knows where it is, so this
    // goes before anything is read.
    if send(&mut socket, json!({"type": "cwd", "data": cwd}))
        .await
        .is_err()
    {
        return;
    }

    while let Some(Ok(message)) = socket.recv().await {
        let text = match message {
            Message::Text(t) => t.to_string(),
            // A browser's keep-alive; axum answers Ping itself.
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
            Message::Binary(_) => continue,
        };

        let Ok(msg) = serde_json::from_str::<ClientMessage>(&text) else {
            if send(
                &mut socket,
                json!({"type": "error", "data": "Invalid JSON message"}),
            )
            .await
            .is_err()
            {
                break;
            }
            continue;
        };

        let replies = match msg.kind.as_str() {
            "ping" => vec![json!({"type": "pong"})],
            // A no-op in the Python as well; the size is the client's
            // business while execution is one-shot.
            "resize" => continue,
            "input" => {
                handle_input(dry_run, &website, &mut cwd, msg.data.unwrap_or_default()).await
            }
            other => vec![json!({
                "type": "error",
                "data": format!("Unknown message type: {other}"),
            })],
        };
        for reply in replies {
            if send(&mut socket, reply).await.is_err() {
                return;
            }
        }
    }
}

/// One `input` message, and everything it can turn into.
///
/// Returned as a list rather than written directly so the whole decision is
/// testable without a socket — which is the only way it *is* testable here.
async fn handle_input(
    dry_run: bool,
    website: &snpanel_db::Website,
    cwd: &mut String,
    data: String,
) -> Vec<serde_json::Value> {
    let command = data.trim();
    if command.is_empty() {
        return vec![json!({"type": "exit", "code": 0})];
    }
    // Handled here rather than by the shell: there is no persistent terminal
    // to clear, so the client does it.
    if command == "clear" || command == "cls" {
        return vec![json!({"type": "clear"}), json!({"type": "exit", "code": 0})];
    }

    let argv = match crate::shlex::split(command) {
        Ok(parts) if !parts.is_empty() => parts,
        Ok(_) => return vec![json!({"type": "exit", "code": 0})],
        Err(e) => {
            return vec![
                json!({"type": "output", "data": format!("{e}\r\n")}),
                json!({"type": "exit", "code": 2}),
            ]
        }
    };

    if argv[0] == "cd" {
        if argv.len() > 2 {
            return vec![
                json!({"type": "output", "data": "usage: cd [path]\r\n"}),
                json!({"type": "exit", "code": 2}),
            ];
        }
        let target = if argv.len() == 2 {
            argv[1].as_str()
        } else {
            ""
        };
        return match resolve_cwd(&website.root_path, cwd, target) {
            Ok(next) => {
                *cwd = next;
                vec![
                    json!({"type": "cwd", "data": cwd.clone()}),
                    json!({"type": "exit", "code": 0}),
                ]
            }
            Err(e) => vec![
                json!({"type": "output", "data": format!("{e}\r\n")}),
                json!({"type": "exit", "code": 1}),
            ],
        };
    }

    let php_version = website.php_version.trim();
    let (code, out, err) = exec_command(
        dry_run,
        website.linux_user.as_deref().unwrap_or(""),
        command,
        cwd,
        (!php_version.is_empty()).then_some(php_version),
    )
    .await;
    vec![
        json!({"type": "output", "data": format!("{out}{err}")}),
        json!({"type": "exit", "code": code}),
    ]
}

async fn send(
    socket: &mut axum::extract::ws::WebSocket,
    value: serde_json::Value,
) -> Result<(), axum::Error> {
    socket
        .send(axum::extract::ws::Message::Text(value.to_string().into()))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole of `exec_command`, against the real Python run in dry-run
    /// mode - which means the comparison is not just the exit code but the
    /// **command line the helper would have been handed**, byte for byte.
    ///
    /// That is the half that matters. A port that agreed about which commands
    /// to refuse and then built argv differently would pass an allow-list test
    /// and still run something else as another user.
    #[tokio::test]
    async fn one_shot_execution_agrees_with_python() {
        let _env = crate::testenv::EnvGuard::set(&[("SNPANEL_USE_HELPER", "true")]);

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/terminal_exec.json");
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the terminal corpus"))
                .expect("the corpus parses");

        let mut failures: Vec<String> = Vec::new();
        for case in corpus["cases"].as_array().expect("the cases") {
            let command = case["command"].as_str().unwrap_or("");
            let user = case["linux_user"].as_str().unwrap_or("alice");
            let cwd = if user.is_empty() {
                "/home/alice"
            } else {
                "/home/alice/example.com/public_html"
            };
            let php = case["php_version"].as_str();
            let (code, stdout, stderr) = exec_command(true, user, command, cwd, php).await;

            let want_code = case["exit_code"].as_i64().unwrap_or(0) as i32;
            let want_out = case["stdout"].as_str().unwrap_or("");
            let want_err = case["stderr"].as_str().unwrap_or("");
            let label = format!("{command:.40?} php={php:?}");
            if code != want_code {
                failures.push(format!("{label}: exit python {want_code}, rust {code}"));
            }
            if stdout != want_out {
                failures.push(format!(
                    "{label}: argv differs\n  python {want_out}\n  rust   {stdout}"
                ));
            }
            if stderr != want_err {
                failures.push(format!(
                    "{label}: stderr python {want_err:?}, rust {stderr:?}"
                ));
            }
        }

        // The budgets decide how long a customer's Composer install may run
        // before it is killed. Getting one wrong is a build that dies at sixty
        // seconds with no explanation anyone can act on.
        for (name, want) in corpus["budgets"].as_object().expect("the budgets") {
            let got = timeout_for(name);
            let want = want.as_u64().unwrap_or(0);
            if got != want {
                failures.push(format!("budget for {name}: python {want}, rust {got}"));
            }
        }

        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Every `cd` the Python was asked, answered by this side.
    ///
    /// The tree is rebuilt here rather than shipped: the corpus records
    /// absolute paths, and the point is that the *same* shapes — a sibling
    /// whose name starts with the root's, a symlink out of the tree, a
    /// symlink back into it — reach the same verdicts.
    #[test]
    fn every_cd_agrees_with_the_python() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../../../tests/golden/resolve_cwd.json"))
                .expect("the corpus parses");

        let recorded_base = corpus["base"].as_str().expect("a base");
        let base = std::env::temp_dir().join(format!("bp-cd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("site");
        std::fs::create_dir_all(root.join("public_html/deep")).unwrap();
        std::fs::create_dir_all(root.join("storage")).unwrap();
        std::fs::write(root.join("file.txt"), "x").unwrap();
        // A sibling whose name starts with the root's, which a string-prefix
        // containment check would let through.
        std::fs::create_dir_all(base.join("siteX")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), root.join("escape")).unwrap();
        std::os::unix::fs::symlink(root.join("storage"), root.join("public_html/to-storage"))
            .unwrap();

        let here = |recorded: &str| recorded.replace(recorded_base, &base.to_string_lossy());
        let site_root = here(corpus["root"].as_str().expect("a root"));

        let cases = corpus["cases"].as_array().expect("cases");
        assert!(cases.len() >= 20, "the corpus is too small to mean much");
        let mut errors = 0;
        for case in cases {
            let cwd = here(case["cwd"].as_str().expect("a cwd"));
            let target = here(case["target"].as_str().expect("a target"));
            let got = resolve_cwd(&site_root, &cwd, &target);
            match (case.get("ok"), case.get("error")) {
                (Some(expected), None) => assert_eq!(
                    got.as_deref(),
                    Ok(here(expected.as_str().unwrap()).as_str()),
                    "cd {target:?} from {cwd:?}"
                ),
                (None, Some(expected)) => {
                    errors += 1;
                    assert_eq!(
                        got.as_ref().err().map(String::as_str),
                        Some(here(expected.as_str().unwrap()).as_str()),
                        "cd {target:?} from {cwd:?}"
                    );
                }
                _ => panic!("a case with neither an answer nor an error"),
            }
        }
        // The corpus has to exercise the refusals, not only the happy path.
        assert!(errors >= 8, "only {errors} cases were refused");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// **The websocket's CSRF defence.** A `WebSocket` may be opened
    /// cross-origin by any page and the session cookie goes with it, so
    /// without this a page on another site gets a shell on the customer's
    /// website.
    #[test]
    fn a_page_on_another_site_cannot_open_a_session() {
        let allowed = vec!["https://panel.example.com:2222".to_string()];
        for evil in [
            "https://evil.example",
            "http://panel.example.com.evil.example",
            "https://panel.example.com.evil.example:2222",
            "null",
        ] {
            assert!(
                !origin_allowed(Some(evil), Some("panel.example.com:2222"), &allowed),
                "{evil} was allowed"
            );
        }
    }

    /// The panel talking to itself, whatever port or scheme it was reached
    /// on — which is the ordinary case and must not need configuring.
    #[test]
    fn the_panels_own_page_is_allowed() {
        let allowed = vec!["https://configured.example".to_string()];
        for (origin, host) in [
            ("https://panel.example.com:2222", "panel.example.com:2222"),
            ("http://panel.example.com:2222", "panel.example.com:2222"),
            ("https://PANEL.example.com:2222", "panel.example.com:2222"),
            ("https://panel.example.com:2222/", "panel.example.com:2222"),
        ] {
            assert!(
                origin_allowed(Some(origin), Some(host), &allowed),
                "{origin}"
            );
        }
        // And a configured origin, on a different host.
        assert!(origin_allowed(
            Some("https://configured.example"),
            Some("panel.example.com:2222"),
            &allowed
        ));
    }

    /// A non-browser client sends no `Origin`, and has no cookie to be
    /// abused either — refusing would lock out the tools without protecting
    /// anything.
    #[test]
    fn a_client_that_sends_no_origin_is_allowed() {
        let allowed = vec!["https://panel.example.com".to_string()];
        assert!(origin_allowed(None, Some("panel.example.com"), &allowed));
        assert!(origin_allowed(
            Some(""),
            Some("panel.example.com"),
            &allowed
        ));
    }

    /// A box that configured no origins is not locked out of its own
    /// terminal — the Python's `not allowed or ...`.
    #[test]
    fn an_empty_allow_list_permits_everything() {
        assert!(origin_allowed(
            Some("https://anywhere.example"),
            Some("panel.example.com"),
            &[]
        ));
    }

    /// A host the request did not carry cannot be matched against, so the
    /// allow-list is the only thing left.
    #[test]
    fn a_missing_host_falls_back_to_the_allow_list() {
        let allowed = vec!["https://panel.example.com".to_string()];
        assert!(origin_allowed(
            Some("https://panel.example.com"),
            None,
            &allowed
        ));
        assert!(!origin_allowed(
            Some("https://evil.example"),
            None,
            &allowed
        ));
    }

    /// A website with just enough filled in to drive a session.
    fn site(root: &str) -> snpanel_db::Website {
        snpanel_db::Website {
            id: 1,
            domain: "example.com".into(),
            owner_id: 1,
            root_path: root.into(),
            document_root: root.into(),
            linux_user: Some("acme".into()),
            php_version: "8.4".into(),
            app_type: "php".into(),
            ssl_enabled: false,
            ssl_mode: String::new(),
            ssl_cert_path: None,
            ssl_key_path: None,
            ssl_ca_path: None,
            ssl_updated_at: None,
            ssl_source_domain: None,
            status: "active".into(),
            nginx_custom: String::new(),
            nginx_config_mode: String::new(),
            nginx_rewrite_mode: String::new(),
            waf_enabled: false,
            waf_default_rules: String::new(),
            waf_custom_rules: String::new(),
            crs_enabled: false,
            http_flood_enabled: false,
            http_flood_config: String::new(),
            blocked_bots: String::new(),
            app_id: None,
        }
    }

    fn kinds(replies: &[serde_json::Value]) -> Vec<&str> {
        replies
            .iter()
            .map(|r| r["type"].as_str().unwrap())
            .collect()
    }

    /// An empty line is not an error and not a command — the client is
    /// waiting for an `exit` to draw the next prompt, so one has to come
    /// back or the terminal hangs.
    #[tokio::test]
    async fn an_empty_line_still_ends_the_prompt() {
        let website = site("/tmp");
        let mut cwd = "/tmp".to_string();
        for input in ["", "   ", "\t"] {
            let replies = handle_input(true, &website, &mut cwd, input.into()).await;
            assert_eq!(kinds(&replies), ["exit"], "{input:?}");
            assert_eq!(replies[0]["code"], 0);
        }
    }

    /// There is no persistent terminal to clear, so the client does it —
    /// and still gets the `exit` that draws the next prompt.
    #[tokio::test]
    async fn clear_is_handled_without_running_anything() {
        let website = site("/tmp");
        let mut cwd = "/tmp".to_string();
        for input in ["clear", "cls"] {
            let replies = handle_input(true, &website, &mut cwd, input.into()).await;
            assert_eq!(kinds(&replies), ["clear", "exit"], "{input}");
            assert_eq!(replies[1]["code"], 0);
        }
    }

    /// `cd` is the one command the session holds state for, and the state is
    /// what `/terminal/exec` cannot have.
    #[tokio::test]
    async fn cd_moves_the_session_and_reports_where_it_went() {
        let base = std::env::temp_dir().join(format!("bp-ws-cd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("public_html")).unwrap();
        let root = base.to_string_lossy().into_owned();
        let website = site(&root);
        let mut cwd = root.clone();

        let replies = handle_input(true, &website, &mut cwd, "cd public_html".into()).await;
        assert_eq!(kinds(&replies), ["cwd", "exit"]);
        assert_eq!(replies[1]["code"], 0);
        assert!(cwd.ends_with("public_html"), "{cwd}");
        assert_eq!(replies[0]["data"].as_str().unwrap(), cwd);

        // And back up, which is the move that has to stay inside the site.
        let replies = handle_input(true, &website, &mut cwd, "cd ..".into()).await;
        assert_eq!(kinds(&replies), ["cwd", "exit"]);
        assert!(!cwd.ends_with("public_html"), "{cwd}");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A refused `cd` leaves the session where it was. Moving anyway would
    /// put the next command somewhere the customer was told they could not
    /// go.
    #[tokio::test]
    async fn a_refused_cd_does_not_move_the_session() {
        let base = std::env::temp_dir().join(format!("bp-ws-cdno-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let root = base.to_string_lossy().into_owned();
        let website = site(&root);
        let mut cwd = root.clone();

        for attempt in ["cd /etc", "cd ../..", "cd nosuchdir"] {
            let replies = handle_input(true, &website, &mut cwd, attempt.into()).await;
            assert_eq!(kinds(&replies), ["output", "exit"], "{attempt}");
            assert_eq!(replies[1]["code"], 1, "{attempt}");
            assert_eq!(cwd, root, "{attempt} moved the session");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `cd a b` is a usage error rather than a move to `a`, which is what a
    /// shell does and what stops a mistyped path from being acted on.
    #[tokio::test]
    async fn cd_takes_at_most_one_argument() {
        let website = site("/tmp");
        let mut cwd = "/tmp".to_string();
        let replies = handle_input(true, &website, &mut cwd, "cd a b".into()).await;
        assert_eq!(kinds(&replies), ["output", "exit"]);
        assert_eq!(replies[1]["code"], 2);
        assert!(replies[0]["data"]
            .as_str()
            .unwrap()
            .contains("usage: cd [path]"));
        assert_eq!(cwd, "/tmp");
    }

    /// Unbalanced quotes are the session's problem, not the shell's: the
    /// message says so and the prompt comes back.
    #[tokio::test]
    async fn a_command_that_will_not_parse_is_reported_in_the_terminal() {
        let website = site("/tmp");
        let mut cwd = "/tmp".to_string();
        let replies = handle_input(true, &website, &mut cwd, "echo \"unclosed".into()).await;
        assert_eq!(kinds(&replies), ["output", "exit"]);
        assert_eq!(replies[1]["code"], 2);
        assert!(replies[0]["data"].as_str().unwrap().ends_with("\r\n"));
    }

    /// Every reply this side sends is one `Terminal.jsx` switches on. A
    /// `type` the two do not agree on is a terminal that silently does
    /// nothing — no output, no new prompt, and nothing in any log.
    ///
    /// `handle_input` produces four of them; `pong` and `error` come from
    /// the message loop around it, so they are named rather than exercised
    /// here.
    #[tokio::test]
    async fn every_reply_type_is_one_the_frontend_handles() {
        // The list in `Terminal.jsx`'s `onmessage`.
        let handled = ["output", "exit", "cwd", "clear", "error", "pong"];

        let base = std::env::temp_dir().join(format!("bp-ws-types-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("public_html")).unwrap();
        let root = base.to_string_lossy().into_owned();
        let website = site(&root);
        let mut cwd = root.clone();

        let mut seen = std::collections::BTreeSet::new();
        for input in [
            "",               // exit
            "clear",          // clear, exit
            "cd public_html", // cwd, exit
            "cd a b",         // output, exit
            "cd /etc",        // output, exit
        ] {
            for reply in handle_input(true, &website, &mut cwd, input.into()).await {
                seen.insert(reply["type"].as_str().unwrap().to_string());
            }
        }
        for kind in &seen {
            assert!(
                handled.contains(&kind.as_str()),
                "{kind} is not handled by Terminal.jsx"
            );
        }
        assert_eq!(
            seen.iter().map(String::as_str).collect::<Vec<_>>(),
            ["clear", "cwd", "exit", "output"],
            "handle_input's reply types changed"
        );
        // And the two the loop adds are in the same set.
        assert!(handled.contains(&"pong"));
        assert!(handled.contains(&"error"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn output_is_cut_at_the_byte_limit_and_says_so() {
        let short = "hello";
        assert_eq!(truncate_output(short), short);

        let long = "a".repeat(MAX_OUTPUT_BYTES + 10);
        let cut = truncate_output(&long);
        assert!(cut.ends_with("\n... (output truncated)"));
        assert_eq!(
            cut.len(),
            MAX_OUTPUT_BYTES + "\n... (output truncated)".len()
        );

        // A cut that lands inside a multi-byte character: Python decodes with
        // `errors="ignore"`, which drops the partial character rather than
        // putting a replacement in its place.
        let mut text = "a".repeat(MAX_OUTPUT_BYTES - 1);
        text.push('é'); // two bytes, so the second is past the limit
        let cut = truncate_output(&text);
        assert!(
            !cut.contains('\u{fffd}'),
            "a replacement character crept in"
        );
        assert!(cut.starts_with(&"a".repeat(MAX_OUTPUT_BYTES - 1)));
    }

    #[test]
    fn the_list_is_sorted_and_has_no_duplicates() {
        let all = allowed();
        let mut sorted = all.clone();
        sorted.sort_unstable();
        assert_eq!(all, sorted);

        let unique: std::collections::BTreeSet<&str> = all.iter().copied().collect();
        assert_eq!(unique.len(), all.len());
    }

    #[test]
    fn the_three_sets_are_the_pythons() {
        assert_eq!(RUNTIME_COMMANDS.len(), 10);
        assert_eq!(UTILITY_COMMANDS.len(), 30);
        assert_eq!(INFO_COMMANDS.len(), 13);
        assert_eq!(allowed().len(), 53);
    }

    #[test]
    fn nothing_that_would_escape_the_allowlist_is_in_it() {
        // The list is advisory - the helper refuses - but a shell or an
        // interpreter here would tell a customer to try something that then
        // fails, or worse, suggest the boundary is not what it is.
        let all = allowed();
        for forbidden in [
            "bash", "sh", "zsh", "dash", "su", "sudo", "ssh", "python", "python3", "perl", "nc",
        ] {
            assert!(!all.contains(&forbidden), "{forbidden} must not be listed");
        }
    }

    #[test]
    fn the_toolchains_a_site_needs_are_there() {
        let all = allowed();
        for needed in ["php", "composer", "wp", "npm", "git", "ls", "cat", "pwd"] {
            assert!(all.contains(&needed), "{needed} is missing");
        }
    }
}
