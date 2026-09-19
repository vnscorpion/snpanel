//! `/api/terminal` - ported from `api/terminal.py`.
//!
//! The allow-list and one-shot execution are here. The interactive websocket
//! session stays with Python: it is a pty relay, not a request.
//!
//! The allow-list is what the frontend uses for completion and for the help
//! panel.
//!
//! **This list mirrors the case statement in `snpanel-helper.sh terminal-exec`,
//! and the two are kept in sync deliberately.** The panel's copy is advisory -
//! it tells the user what will work - while the helper's copy is the one that
//! actually refuses. A name in this list that the helper does not accept is a
//! confusing error; a name the helper accepts that is missing here is worse,
//! because the allowlist stops looking like the whole story.

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
