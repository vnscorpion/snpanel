//! `/api/terminal` - ported from `api/terminal.py`, the allowlist.
//!
//! Executing a command and the websocket session both run through the helper's
//! `terminal-exec` trampoline and stay with Python. What is here is the list of
//! commands the terminal will accept, which the frontend uses for completion
//! and for the help panel.
//!
//! **This list mirrors the case statement in `snpanel-helper.sh terminal-exec`,
//! and the two are kept in sync deliberately.** The panel's copy is advisory -
//! it tells the user what will work - while the helper's copy is the one that
//! actually refuses. A name in this list that the helper does not accept is a
//! confusing error; a name the helper accepts that is missing here is worse,
//! because the allowlist stops looking like the whole story.

use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::json;

use crate::auth::CurrentUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/terminal/allowed-commands",
        get(allowed_commands).fallback(crate::fallback),
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

#[cfg(test)]
mod tests {
    use super::*;

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
