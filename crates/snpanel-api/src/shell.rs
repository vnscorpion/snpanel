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
    privileged_timed(dry_run, command, args, stdin, fallback, None).await
}

/// [`privileged`] with the wall-clock budget the Python's `timeout=` argument
/// gives it.
///
/// Source: `ShellRunner.run(..., timeout=...)`. When it fires the Python does
/// not raise - with `check=False` it returns returncode **124**, whatever the
/// command managed to print before the kill, and `Command timed out after Ns`
/// on the end of stderr. All three matter: `terminal.exec_command` reads the
/// 124, and a customer whose Composer install was killed at fifteen minutes
/// wants the log up to that point, not a blank box.
///
/// The budget covers the child process, as it does in Python. It is not
/// applied to the helper socket, which has its own; the socket path returns
/// before this is reached.
///
/// Nothing else has been given a budget yet. Every other ported call site
/// still runs without one, which is the same gap this fixes here - it is
/// recorded in the plan rather than fixed blind, because each Python call
/// site has its own number and guessing them is worse than not having them.
pub async fn privileged_timed(
    dry_run: bool,
    command: &str,
    args: &[&str],
    stdin: Option<&str>,
    fallback: Option<&[&str]>,
    timeout: Option<u64>,
) -> CommandResult {
    // Plan §4.2: the socket first, sudo behind it.
    //
    // The three outcomes are deliberately not alike. A verb the mapping does
    // not know falls through to sudo. That used to reach the bash helper and
    // was the cutover mechanism; with the script gone, sudo reaches the same
    // binary and it reports the verb as unknown - the same answer, by a
    // longer road, and the road is kept because it is also what carries the
    // second case. A transport fault falls through too, because a helper that
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
                // The helper has no arm for it. Not a refusal - see
                // `helper_socket::not_implemented` - so the bash answers.
                Ok(response) if helper_socket::not_implemented(&response) => {
                    tracing::debug!(
                        op = command,
                        "no implementation in the helper; the bash answers it"
                    );
                }
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
                    // 1 is what the bash's `deny` exits with, so a caller
                    // that tells "refused" from "failed" keeps working. 2 is
                    // reserved for "you may not call me at all".
                    returncode: 1,
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
    exec_argv(argv, quoted, stdin, timeout).await
}

/// Run an argv as this process's own user.
///
/// Source: `subprocess.run(..., capture_output=True, timeout=...)`, which
/// is what `scan_file_with_clamdscan` calls directly. No helper and no
/// sudo: scanning a file the panel already owns needs neither.
pub async fn run_timed(dry_run: bool, program: &str, args: &[&str], timeout: u64) -> CommandResult {
    let mut argv: Vec<String> = vec![program.to_string()];
    argv.extend(args.iter().map(|a| (*a).to_string()));
    let quoted = quote_argv(&argv);
    if dry_run {
        return CommandResult {
            command: quoted.clone(),
            returncode: 0,
            stdout: format!("DRY RUN: {quoted}"),
            stderr: String::new(),
        };
    }
    exec_argv(argv, quoted, None, Some(timeout)).await
}

/// Spawn an argv, drain both pipes, and honour a timeout.
async fn exec_argv(
    argv: Vec<String>,
    quoted: String,
    stdin: Option<&str>,
    timeout: Option<u64>,
) -> CommandResult {
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
            // A missing binary is not a panic: it is a failed command,
            // reported the way a failed command is. `clamdscan` absent is
            // exactly this, and the Python's own `except FileNotFoundError`
            // says so too.
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

    // Both pipes are drained by their own task, so a command that fills one
    // of them cannot wedge waiting for a reader that is blocked on the other.
    // `wait_with_output` did this internally; it is spelled out here because
    // the timeout needs to kill the child and then still collect what the
    // readers got, which is the partial output Python returns.
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        if let Some(pipe) = out_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });
    let err_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        if let Some(pipe) = err_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });

    let mut timed_out = false;
    let status = match timeout {
        Some(seconds) => {
            match tokio::time::timeout(std::time::Duration::from_secs(seconds), child.wait()).await
            {
                Ok(result) => result.ok(),
                Err(_) => {
                    // Python's `subprocess.run` kills the child and then
                    // collects what was captured. Killing closes this end of
                    // the pipes, which is what lets the readers below finish.
                    let _ = child.kill().await;
                    timed_out = true;
                    None
                }
            }
        }
        None => child.wait().await.ok(),
    };

    let stdout = String::from_utf8_lossy(&out_task.await.unwrap_or_default()).into_owned();
    let mut stderr = String::from_utf8_lossy(&err_task.await.unwrap_or_default()).into_owned();

    if timed_out {
        // Source: `f"Command timed out after {timeout:g}s"`, appended after a
        // newline. The 124 is what `exec_command` reads to tell a kill from a
        // command that simply failed.
        let seconds = timeout.unwrap_or(0);
        stderr.push_str(&format!("\nCommand timed out after {seconds}s"));
        return CommandResult {
            command: quoted,
            returncode: 124,
            stdout,
            stderr,
        };
    }

    match status {
        Some(status) => CommandResult {
            command: quoted,
            returncode: status.code().unwrap_or(-1),
            stdout,
            stderr,
        },
        None => CommandResult {
            command: quoted,
            returncode: -1,
            stdout: String::new(),
            stderr: "could not read the helper's output".to_string(),
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

    // The guard has to be held across the await: the await is exactly when
    // the environment must stay put. Each `#[tokio::test]` gets its own
    // runtime, so there is no other task on it waiting for this lock and
    // nothing to deadlock against.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn no_helper_and_no_fallback_is_a_reported_failure() {
        // Python raises RuntimeError here, which reaches the user as a 500.
        // Returning a *successful* result would be far worse than an error:
        // the panel would report that it had opened a port when nothing ran.
        // Under the same lock as the transport tests. `use_helper()` reads a
        // process-global variable, so every test that writes one has to take
        // the same lock or they interleave - which this one did, clearing
        // SNPANEL_USE_HELPER underneath a transport test and sending it down
        // the sudo path. It passed locally and on Debian and failed on
        // AlmaLinux, which is what a race looks like from the outside.
        let _guard = crate::testenv::lock();
        std::env::set_var("SNPANEL_USE_HELPER", "false");
        let r = privileged(false, "firewall-enable", &[], None, None).await;
        std::env::remove_var("SNPANEL_USE_HELPER");

        assert_ne!(r.returncode, 0, "a refusal must not look like a success");
        assert!(r.stderr.contains("firewall-enable"), "{}", r.stderr);
        assert!(!r.ok());
    }

    /// A budget that fires has to look like Python's: exit 124, the message on
    /// the end of stderr, and - the part that is easy to drop - whatever the
    /// command printed before it was killed.
    ///
    /// A customer whose fifteen-minute Composer install is killed gets the log
    /// up to that point from the Python. A port that returned an empty box
    /// would be a worse panel that passed every test about exit codes.
    #[tokio::test]
    async fn a_budget_that_fires_looks_exactly_like_the_pythons() {
        let _env = crate::testenv::EnvGuard::set(&[("SNPANEL_USE_HELPER", "false")]);
        let r = privileged_timed(
            false,
            "terminal-exec",
            &[],
            None,
            Some(&["bash", "-c", "echo partial; sleep 30"]),
            Some(1),
        )
        .await;

        assert_eq!(r.returncode, 124, "stderr was: {}", r.stderr);
        assert_eq!(r.stdout, "partial\n", "the output before the kill is lost");
        assert!(
            r.stderr.ends_with("\nCommand timed out after 1s"),
            "stderr was: {:?}",
            r.stderr
        );
    }

    /// The other half: a command that finishes inside its budget is not
    /// touched by it. Worth its own test because a timeout bolted onto a
    /// process wait is just as easy to get wrong in the direction that kills
    /// healthy commands.
    #[tokio::test]
    async fn a_command_that_finishes_in_time_is_untouched() {
        let _env = crate::testenv::EnvGuard::set(&[("SNPANEL_USE_HELPER", "false")]);
        let r = privileged_timed(
            false,
            "terminal-exec",
            &[],
            None,
            Some(&["bash", "-c", "echo out; echo err >&2; exit 3"]),
            Some(30),
        )
        .await;

        assert_eq!(r.returncode, 3);
        assert_eq!(r.stdout, "out\n");
        assert_eq!(r.stderr, "err\n");
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
            let guard = crate::testenv::lock();
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
        // An ordinary refusal: 1, the code `deny` uses. The response carries
        // no `error.kind`, so it is not the not-authorised case even though
        // its message reads like one.
        assert_eq!(result.returncode, 1, "{result:?}");
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
        // Refused before any transport: 1, as `deny` would.
        assert_eq!(result.returncode, 1, "{result:?}");
        assert!(result.stderr.contains("action not allowed"), "{result:?}");
        assert_ne!(result.stdout, "SHOULD NOT BE SEEN");
    }

    #[tokio::test]
    async fn a_helper_with_no_arm_for_the_verb_does_not_end_the_call() {
        // The one answer that falls through. It is produced only by a
        // dispatch catch-all, after the request has been parsed and accepted,
        // so it carries no decision about the caller. The helper in this tree
        // never sends it - `dispatch` is exhaustive - but one from the
        // previous release, mid-update, still can.
        let env = Env::new("notimpl");
        fake_helper(
            env.socket(),
            r#"{"ok":false,"stdout":"","stderr":"","error":{"kind":"not-implemented","message":"still served by snpanel-helper.sh"}}"#,
        )
        .await;

        let result = privileged(false, "nginx-test", &[], None, None).await;
        // It did not return that answer: it went on to the sudo path, which
        // has no sudo to run here and says so.
        assert!(!result.stderr.contains("still served by"), "{result:?}");
    }

    #[tokio::test]
    async fn being_told_the_caller_is_not_authorised_is_final() {
        // The security-critical half of the same branch. If this fell through
        // to sudo, failing the peer-credential check would be a way past it.
        let env = Env::new("notauth");
        fake_helper(
            env.socket(),
            r#"{"ok":false,"stdout":"","stderr":"","error":{"kind":"not-authorised","message":"caller uid 1001 is not the panel user"}}"#,
        )
        .await;

        let result = privileged(false, "nginx-test", &[], None, None).await;
        // 2, and deliberately not 1: this is the socket's version of the
        // bash's `SUDO_USER` guard, which exits 2 for exactly this.
        assert_eq!(result.returncode, 2, "{result:?}");
        assert!(result.stderr.contains("not the panel user"), "{result:?}");
    }

    /// The second argument of the second argument: what the panel names when
    /// it asks the helper for something.
    ///
    /// Returns the verb literals, and how many call sites compute the verb
    /// instead of spelling it.
    fn helper_verbs_the_panel_asks_for() -> (std::collections::BTreeSet<String>, usize) {
        fn second_arg(text: &str, open: usize) -> Option<String> {
            let b = text.as_bytes();
            let (mut depth, mut i) = (0usize, open);
            let (mut args, mut cur) = (Vec::new(), String::new());
            while i < b.len() {
                match b[i] {
                    b'(' | b'[' | b'{' => {
                        depth += 1;
                        if depth == 1 {
                            i += 1;
                            continue;
                        }
                    }
                    b')' | b']' | b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            args.push(std::mem::take(&mut cur));
                            break;
                        }
                    }
                    b'"' => {
                        // Skip the whole literal so a comma inside one does
                        // not split the argument list.
                        let mut j = i + 1;
                        while j < b.len() && !(b[j] == b'"' && b[j - 1] != b'\\') {
                            j += 1;
                        }
                        cur.push_str(&text[i..=j.min(b.len() - 1)]);
                        i = j + 1;
                        continue;
                    }
                    b',' if depth == 1 => {
                        args.push(std::mem::take(&mut cur));
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
                cur.push(b[i] as char);
                i += 1;
            }
            args.get(1).map(|a| a.trim().to_string())
        }

        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("a source directory").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
                    // This file *defines* `privileged`; its own tests call it
                    // with fixture verbs, which are not what the panel asks
                    // the helper for.
                    && path.file_name().and_then(|n| n.to_str()) != Some("shell.rs")
                {
                    out.push(path);
                }
            }
        }

        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        files.sort();

        let mut verbs = std::collections::BTreeSet::new();
        let mut computed = 0;
        for path in files {
            let text = std::fs::read_to_string(&path).expect("a source file");
            let mut from = 0;
            while let Some(hit) = text[from..].find("privileged") {
                let at = from + hit;
                from = at + "privileged".len();
                // `privileged(`, `privileged_timed(` - and not `privileged_x`.
                let tail = &text[at..];
                let open = if let Some(rest) = tail.strip_prefix("privileged_timed") {
                    if rest.starts_with('(') { at + "privileged_timed".len() } else { continue }
                } else if tail[..text.len().min(at + 11) - at].starts_with("privileged(") {
                    at + "privileged".len()
                } else {
                    continue;
                };
                let Some(arg) = second_arg(&text, open) else {
                    continue;
                };
                let literal = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"'));
                match literal {
                    Some(v)
                        if !v.is_empty()
                            && v.bytes()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') =>
                    {
                        verbs.insert(v.to_string());
                    }
                    // A verb chosen at runtime, from a variable or a `match`.
                    // Those cannot be checked from the source; the count is
                    // asserted so a new one is noticed rather than missed.
                    _ => computed += 1,
                }
            }
        }
        (verbs, computed)
    }

    /// Every verb the panel names is one the helper answers.
    ///
    /// While the bash helper existed this did not need saying: a name the
    /// Rust mapping did not know fell through to a script that did. The
    /// fallthrough is gone, so a verb the panel asks for and the mapping does
    /// not have is an error the operator sees, and nothing else catches it -
    /// these names are strings, not enum variants, so the compiler does not
    /// either.
    #[test]
    fn every_verb_the_panel_asks_for_is_one_the_helper_answers() {
        let (verbs, computed) = helper_verbs_the_panel_asks_for();
        assert!(verbs.len() > 80, "the scan found only {}", verbs.len());

        let mut unknown = Vec::new();
        for verb in &verbs {
            // `from_argv` matches on `(name, arity)`, so a known name with
            // the wrong count of arguments also reads as unmapped. The arity
            // is usually built at runtime, so any arity that maps proves the
            // name is one the helper knows.
            let known = (0..=8).any(|n| {
                let argv: Vec<String> = std::iter::once(verb.clone())
                    .chain((0..n).map(|i| format!("arg{i}")))
                    .collect();
                !matches!(
                    snpanel_ipc::HelperRequest::from_argv(&argv, Vec::new),
                    Err(ref e) if e.is_unmapped()
                )
            });
            if !known {
                unknown.push(verb.clone());
            }
        }
        // Two names nothing has ever answered - not the bash either, which
        // had no arm for them. Both call sites discard the result, so today
        // they are no-ops that log a refusal, and removing the bash does not
        // change that. They are listed rather than silently tolerated: the
        // work each one names is either happening somewhere else or is not
        // happening, and that is worth someone deciding rather than
        // inheriting.
        const ANSWERED_BY_NOTHING: &[&str] = &["nginx-vhost-delete", "wordpress-vhost-delete"];
        unknown.retain(|v| !ANSWERED_BY_NOTHING.contains(&v.as_str()));
        assert!(unknown.is_empty(), "the helper answers none of: {unknown:?}");

        assert_eq!(
            computed, 8,
            "the number of call sites that choose a verb at runtime changed; \
             each one is a name this test cannot check"
        );
    }

}
