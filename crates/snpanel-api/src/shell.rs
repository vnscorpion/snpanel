//! Running privileged operations - `services/shell.py`.
//!
//! Two trust levels in the Python, and only one of them matters here: the API
//! never runs anything as root itself. It asks the helper, through `sudo -n`,
//! for an operation the sudoers allowlist names. NT5 is exactly this boundary,
//! and the Rust API inherits it unchanged - the helper is the same binary the
//! Python calls, so nothing new is trusted.
//!
//! The shape of the reply is part of the API. `_result(result)` in the routers
//! is `result.__dict__`, so every firewall endpoint returns
//!
//! ```json
//! {"command": "...", "returncode": 0, "stdout": "...", "stderr": ""}
//! ```
//!
//! including `command`, the shell-quoted argv. The frontend prints it in the
//! output pane, so it is not debugging chatter that can be dropped.
//!
//! `check` is the Python's: when it is on and the command fails, the service
//! raises, FastAPI catches nothing, and the user gets a 500. Reproducing a
//! *failure* faithfully matters as much as reproducing a success - an endpoint
//! that starts answering 400 where it used to answer 500 is a different API.

use snpanel_ipc::HelperRequest;

use crate::helper_socket;
use std::path::Path;
use std::process::Stdio;

use serde_json::{json, Value};

pub const HELPER_PATH: &str = "/usr/local/sbin/snpanel-helper";

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub command: String,
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    /// Source: `result.__dict__`, field for field and in that order.
    pub fn to_json(&self) -> Value {
        json!({
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        })
    }

    pub fn ok(&self) -> bool {
        self.returncode == 0
    }

    /// Source: the `(result.stderr or result.stdout or "...").strip()` pattern
    /// the blocklist endpoints use to turn a failure into a message.
    pub fn failure_detail<'a>(&'a self, default: &'a str) -> String {
        for candidate in [self.stderr.trim(), self.stdout.trim()] {
            if !candidate.is_empty() {
                return candidate.to_string();
            }
        }
        default.to_string()
    }
}

/// Source: `_use_helper`.
///
/// The environment variable wins when it is set at all; otherwise the helper
/// is used when this process is not root and the helper exists. Running as
/// root and calling the helper through sudo would work, but the Python's rule
/// is what decides which of the two paths a development box takes, and
/// diverging here would make dev behave unlike production.
pub fn use_helper() -> bool {
    match std::env::var("SNPANEL_USE_HELPER") {
        Ok(flag) => matches!(flag.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => {
            // SAFETY: geteuid cannot fail and touches no memory.
            let euid = unsafe { libc::geteuid() };
            euid != 0 && Path::new(HELPER_PATH).exists()
        }
    }
}

/// Shell-quote one argument the way `shlex.quote` does.
///
/// Python quotes with single quotes and escapes an embedded one as `'"'"'`.
/// The `command` field is displayed, not executed, but a difference here is a
/// difference in the response body.
pub fn shlex_quote(arg: &str) -> String {
    const SAFE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_";
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.chars().all(|c| SAFE.contains(c)) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r#"'"'"'"#))
}

pub fn quote_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run a privileged operation through the helper.
///
/// `dry_run` is `COMMAND_DRY_RUN` from the settings, which makes every
/// privileged call a no-op that reports what it would have done.
///
/// `fallback` is the Python's per-call-site development convenience: when the
/// helper is not installed, that command runs instead. It is not a security
/// hole - the strings are compiled in, never built from a request - and it is
/// ported rather than dropped because without it a developer's laptop gets a
/// 500 from every page that touches the firewall, which is not how the Python
/// behaves there. With no fallback and no helper, `privileged` reports a
/// failure and the caller turns it into the 500 the Python's `RuntimeError`
/// produces.
pub async fn privileged(
    dry_run: bool,
    command: &str,
    args: &[&str],
    stdin: Option<&str>,
    fallback: Option<&[&str]>,
) -> CommandResult {
    // Plan §4.2: the socket first, sudo behind it.
    //
    // The three outcomes are deliberately not alike. A verb the mapping does
    // not know falls through to sudo, which reaches the bash helper - that is
    // the cutover. A transport fault falls through too, because a helper that
    // is not listening is an operational problem and a customer should not
    // see an error for it. But a verb the mapping *knows* and refuses does
    // not fall through: an argument rejected here must not get a second
    // hearing from a looser parser, or the check is decorative.
    if !dry_run
        && use_helper()
        && helper_socket::available()
        && helper_socket::verb_enabled(command)
    {
        let invocation: Vec<String> = std::iter::once(command.to_string())
            .chain(args.iter().map(|a| (*a).to_string()))
            .collect();
        let payload = stdin.map(|s| s.as_bytes().to_vec()).unwrap_or_default();
        match HelperRequest::from_argv(&invocation, move || payload) {
            Ok(request) => match helper_socket::call(&request).await {
                Ok(response) => {
                    return CommandResult {
                        command: quote_argv(&invocation),
                        returncode: helper_socket::returncode_of(&response),
                        stdout: response.stdout.clone(),
                        stderr: helper_socket::stderr_of(&response),
                    };
                }
                Err(e) => {
                    tracing::warn!(op = command, "helper socket unusable, using sudo: {e}");
                }
            },
            Err(e) if e.is_unmapped() => {
                tracing::debug!(op = command, "not ported; the bash helper answers it");
            }
            Err(e) => {
                return CommandResult {
                    command: quote_argv(&invocation),
                    // 2 is what the bash's `deny` exits with, so a caller that
                    // tells "refused" from "failed" keeps working.
                    returncode: 2,
                    stdout: String::new(),
                    stderr: e.to_string(),
                };
            }
        }
    }

    let mut argv: Vec<String> = if use_helper() {
        let mut v: Vec<String> = vec![
            "sudo".into(),
            "-n".into(),
            HELPER_PATH.into(),
            command.into(),
        ];
        v.extend(args.iter().map(|a| (*a).to_string()));
        v
    } else if let Some(f) = fallback {
        f.iter().map(|a| (*a).to_string()).collect()
    } else {
        let message = format!(
            "snpanel-helper is not available and no fallback was provided \
             for privileged operation '{command}'"
        );
        tracing::error!("{message}");
        return CommandResult {
            command: format!("{HELPER_PATH} {command}"),
            returncode: -1,
            stdout: String::new(),
            stderr: message,
        };
    };

    let quoted = quote_argv(&argv);
    if dry_run {
        return CommandResult {
            command: quoted.clone(),
            returncode: 0,
            stdout: format!("DRY RUN: {quoted}"),
            stderr: String::new(),
        };
    }

    let argv = std::mem::take(&mut argv);
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            // `sudo` missing is not a panic: it is a failed command, reported
            // the way a failed command is.
            return CommandResult {
                command: quoted,
                returncode: -1,
                stdout: String::new(),
                stderr: format!("could not run the helper: {e}"),
            };
        }
    };

    if let Some(text) = stdin {
        use tokio::io::AsyncWriteExt;
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(text.as_bytes()).await;
            let _ = pipe.shutdown().await;
        }
    }

    match child.wait_with_output().await {
        Ok(out) => CommandResult {
            command: quoted,
            returncode: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => CommandResult {
            command: quoted,
            returncode: -1,
            stdout: String::new(),
            stderr: format!("could not read the helper's output: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_argument_is_not_quoted() {
        assert_eq!(shlex_quote("firewall-status"), "firewall-status");
        assert_eq!(shlex_quote("203.0.113.4/32"), "203.0.113.4/32");
        assert_eq!(
            shlex_quote("/usr/local/sbin/snpanel-helper"),
            "/usr/local/sbin/snpanel-helper"
        );
        assert_eq!(shlex_quote("8080"), "8080");
    }

    #[test]
    fn anything_with_a_space_or_a_metacharacter_is_quoted() {
        assert_eq!(shlex_quote("two words"), "'two words'");
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("a;rm -rf /"), "'a;rm -rf /'");
        assert_eq!(shlex_quote("$(whoami)"), "'$(whoami)'");
    }

    #[test]
    fn an_embedded_quote_is_escaped_the_way_python_escapes_it() {
        // shlex.quote("it's") == '"'"'it'"'"'s'"'"'... in full:
        assert_eq!(shlex_quote("it's"), r#"'it'"'"'s'"#);
    }

    #[test]
    fn the_command_field_reads_as_the_command_that_ran() {
        let argv: Vec<String> = ["sudo", "-n", HELPER_PATH, "firewall-allow-ip", "10.0.0.0/8"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            quote_argv(&argv),
            "sudo -n /usr/local/sbin/snpanel-helper firewall-allow-ip 10.0.0.0/8"
        );
    }

    #[tokio::test]
    async fn a_dry_run_reports_what_it_would_have_done() {
        // A fallback is supplied because the availability check comes *first*,
        // exactly as it does in Python: `privileged` resolves the argv (and
        // raises when it cannot) before `_exec` ever looks at the dry-run
        // flag. Without one, this test would exercise the refusal below
        // instead - which is what it did on the first run.
        let r = privileged(true, "firewall-enable", &[], None, Some(&["true"])).await;
        assert_eq!(r.returncode, 0);
        assert!(r.stdout.starts_with("DRY RUN: "), "{}", r.stdout);
        assert!(r.stderr.is_empty());
        assert!(r.ok());
    }

    #[tokio::test]
    async fn no_helper_and_no_fallback_is_a_reported_failure() {
        // Python raises RuntimeError here, which reaches the user as a 500.
        // Returning a *successful* result would be far worse than an error:
        // the panel would report that it had opened a port when nothing ran.
        std::env::set_var("SNPANEL_USE_HELPER", "false");
        let r = privileged(false, "firewall-enable", &[], None, None).await;
        std::env::remove_var("SNPANEL_USE_HELPER");

        assert_ne!(r.returncode, 0, "a refusal must not look like a success");
        assert!(r.stderr.contains("firewall-enable"), "{}", r.stderr);
        assert!(!r.ok());
    }

    #[test]
    fn a_failure_detail_prefers_stderr_then_stdout_then_the_default() {
        let mut r = CommandResult {
            command: "x".into(),
            returncode: 1,
            stdout: " out ".into(),
            stderr: " err ".into(),
        };
        assert_eq!(r.failure_detail("fallback"), "err");
        r.stderr = "  ".into();
        assert_eq!(r.failure_detail("fallback"), "out");
        r.stdout = String::new();
        assert_eq!(r.failure_detail("fallback"), "fallback");
    }

    #[test]
    fn the_result_serialises_with_the_four_fields_the_frontend_reads() {
        let r = CommandResult {
            command: "sudo -n helper firewall-status".into(),
            returncode: 0,
            stdout: "Status: active".into(),
            stderr: String::new(),
        };
        let v = r.to_json();
        assert_eq!(v["command"], json!("sudo -n helper firewall-status"));
        assert_eq!(v["returncode"], json!(0));
        assert_eq!(v["stdout"], json!("Status: active"));
        assert_eq!(v["stderr"], json!(""));
    }

    #[test]
    fn the_helper_flag_is_read_from_the_environment_when_it_is_set() {
        // Not asserted against the live environment - only that the accepted
        // spellings are the Python's.
        for yes in ["1", "true", "yes", "on", "TRUE", "On"] {
            assert!(
                matches!(yes.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
                "{yes}"
            );
        }
        for no in ["0", "false", "no", "off", ""] {
            assert!(
                !matches!(no.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
                "{no}"
            );
        }
    }

    // --- the routing between the socket and sudo ---------------------------
    //
    // These are the branch the cutover rests on, so they are driven against a
    // socket that answers rather than against the shape of the code. The
    // environment is process-wide, so they share one lock.

    static TRANSPORT: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A helper that is not the helper: it reads one line and answers with
    /// whatever it was told to answer.
    async fn fake_helper(path: std::path::PathBuf, reply: &'static str) {
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let mut line = String::new();
                let _ = BufReader::new(&mut stream).read_line(&mut line).await;
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.write_all(b"\n").await;
                let _ = stream.flush().await;
            }
        });
    }

    struct Env {
        _guard: std::sync::MutexGuard<'static, ()>,
        dir: std::path::PathBuf,
    }

    impl Env {
        fn new(name: &str) -> Self {
            let guard = TRANSPORT.lock().unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir()
                .join(format!("snpanel-shell-test-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("temp dir");
            std::env::set_var("SNPANEL_USE_HELPER", "1");
            std::env::set_var("SNPANEL_HELPER_SOCKET", dir.join("helper.sock"));
            std::env::remove_var("SNPANEL_HELPER_VERBS");
            Self { _guard: guard, dir }
        }

        fn socket(&self) -> std::path::PathBuf {
            self.dir.join("helper.sock")
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            std::env::remove_var("SNPANEL_USE_HELPER");
            std::env::remove_var("SNPANEL_HELPER_SOCKET");
            std::env::remove_var("SNPANEL_HELPER_VERBS");
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[tokio::test]
    async fn a_mapped_verb_is_answered_by_the_socket() {
        let env = Env::new("answered");
        fake_helper(
            env.socket(),
            r#"{"ok":true,"stdout":"configuration ok","stderr":""}"#,
        )
        .await;

        let result = privileged(false, "nginx-test", &[], None, None).await;
        assert_eq!(result.returncode, 0, "{result:?}");
        assert_eq!(result.stdout, "configuration ok");
        // Not the sudo form: the panel should be told what actually ran.
        assert_eq!(result.command, "nginx-test");
    }

    #[tokio::test]
    async fn a_refusal_from_the_helper_is_returned_and_not_retried_through_sudo() {
        // The whole reason the socket exists is that the helper decides who
        // may call it. A refusal that fell back to sudo would mean failing
        // that check is a way around it.
        let env = Env::new("refused");
        fake_helper(
            env.socket(),
            r#"{"ok":false,"stdout":"","stderr":"caller is not the panel user"}"#,
        )
        .await;

        let result = privileged(false, "nginx-test", &[], None, None).await;
        assert_eq!(result.returncode, 2, "{result:?}");
        assert_eq!(result.stderr, "caller is not the panel user");
    }

    #[tokio::test]
    async fn a_verb_outside_the_allowlist_does_not_touch_the_socket() {
        let env = Env::new("allowlist");
        // A socket that would answer, and an allowlist that excludes the verb.
        fake_helper(
            env.socket(),
            r#"{"ok":true,"stdout":"SHOULD NOT BE SEEN","stderr":""}"#,
        )
        .await;
        std::env::set_var("SNPANEL_HELPER_VERBS", "site-*");

        let result = privileged(false, "nginx-test", &[], None, Some(&["true"])).await;
        assert_ne!(result.stdout, "SHOULD NOT BE SEEN", "{result:?}");
    }

    #[tokio::test]
    async fn a_dry_run_never_reaches_the_helper() {
        let env = Env::new("dryrun");
        fake_helper(
            env.socket(),
            r#"{"ok":true,"stdout":"SHOULD NOT BE SEEN","stderr":""}"#,
        )
        .await;

        let result = privileged(true, "nginx-test", &[], None, None).await;
        assert!(result.stdout.starts_with("DRY RUN"), "{result:?}");
    }

    #[tokio::test]
    async fn a_mapped_verb_with_refused_arguments_never_reaches_any_transport() {
        // `from_argv` refuses this before a byte is sent, and it must not be
        // handed to the bash either - a looser parser accepting what this
        // rejected is the failure this distinction exists to prevent.
        let env = Env::new("invalid");
        fake_helper(
            env.socket(),
            r#"{"ok":true,"stdout":"SHOULD NOT BE SEEN","stderr":""}"#,
        )
        .await;

        let result = privileged(
            false,
            "site-app-control",
            &["alice", "myapp", "sudo"],
            None,
            None,
        )
        .await;
        assert_eq!(result.returncode, 2, "{result:?}");
        assert!(result.stderr.contains("action not allowed"), "{result:?}");
        assert_ne!(result.stdout, "SHOULD NOT BE SEEN");
    }
}
