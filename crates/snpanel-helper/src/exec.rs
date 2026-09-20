//! Running external commands.
//!
//! One rule, and it is the reason a whole class of bugs disappears with the
//! bash: **there is no shell here**. Every command is an argv vector handed
//! straight to `execve`. Nothing is word-split, nothing is glob-expanded,
//! nothing re-parses a quote. A domain containing `; rm -rf /` is just an
//! argument that no program will match.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use snpanel_ipc::{HelperErrorKind, HelperResponse};

/// Result of running a command.
pub struct Output {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// Run `argv`, capturing output.
///
/// `argv[0]` is the program. An empty argv is a programming error, not a
/// runtime condition, so it panics rather than returning.
pub fn run(argv: &[&str]) -> std::io::Result<Output> {
    run_with_stdin(argv, None)
}

/// Run `argv`, optionally writing `stdin_data` to its standard input.
///
/// C37: secrets reach a program this way, never through argv, because argv is
/// world-readable in `/proc/<pid>/cmdline` for as long as the process lives.
/// Run `argv` with a few extra environment variables on top of the cleared
/// one.
///
/// The environment is cleared on purpose - the helper runs as root and must
/// not inherit anything the caller chose - so a program that genuinely needs a
/// variable has to be given it here, by name, at the call site.
/// `DEBIAN_FRONTEND=noninteractive` is the one that matters: without it
/// `apt-get` can stop on a prompt nobody will ever answer.
pub fn run_with_env(argv: &[&str], extra: &[(&str, &str)]) -> std::io::Result<Output> {
    run_inner(argv, None, extra)
}

pub fn run_with_stdin(argv: &[&str], stdin_data: Option<&[u8]>) -> std::io::Result<Output> {
    run_inner(argv, stdin_data, &[])
}

fn run_inner(
    argv: &[&str],
    stdin_data: Option<&[u8]>,
    extra: &[(&str, &str)],
) -> std::io::Result<Output> {
    let (program, args) = argv.split_first().expect("argv must not be empty");

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A predictable environment: the helper runs as root and must not
        // inherit anything the caller chose.
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C");
    for (key, value) in extra {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn()?;

    if let Some(data) = stdin_data {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data)?;
            // Dropping closes the pipe, which many programs wait for.
        }
    }

    let out = child.wait_with_output()?;
    Ok(Output {
        status: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Run with a wall-clock budget, killing the process if it overruns.
///
/// Used for anything that talks to the network or to a customer's code, where
/// "hangs forever" is a realistic outcome and an unbounded wait would pin a
/// helper connection open indefinitely.
// Not yet called from a handler: the operation that needs it is
// `terminal-exec`, whose 60s/900s budgets are C30, and that lands with the
// rest of `ops::misc`. Kept and tested now because the timeout logic is the
// part worth getting right before there is a caller depending on it.
#[allow(dead_code)]
pub fn run_with_timeout(argv: &[&str], budget: Duration) -> std::io::Result<Output> {
    let (program, args) = argv.split_first().expect("argv must not be empty");
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C")
        .spawn()?;

    let started = Instant::now();
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None if started.elapsed() >= budget => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(Output {
                    status: None,
                    stdout: String::new(),
                    stderr: format!("timed out after {}s", budget.as_secs()),
                });
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let out = child.wait_with_output()?;
    Ok(Output {
        status: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Turn a command result into the response the caller sees.
pub fn respond(operation: &str, result: std::io::Result<Output>) -> HelperResponse {
    match result {
        Ok(out) if out.ok() => HelperResponse {
            ok: true,
            stdout: out.stdout,
            stderr: out.stderr,
            data: None,
            error: None,
        },
        Ok(out) if out.status.is_none() => HelperResponse::failed(
            HelperErrorKind::Timeout,
            format!("{operation}: {}", out.stderr.trim()),
        ),
        Ok(out) => {
            let mut resp = HelperResponse::failed(
                HelperErrorKind::CommandFailed,
                format!(
                    "{operation} exited {}: {}",
                    out.status.unwrap_or(-1),
                    out.stderr.trim()
                ),
            );
            // The caller often needs the output even on failure - `nginx -t`
            // puts the reason the config is broken on stderr.
            resp.stdout = out.stdout;
            resp.stderr = out.stderr;
            resp
        }
        Err(e) => HelperResponse::failed(HelperErrorKind::Internal, format!("{operation}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_a_command_and_captures_stdout() {
        let out = run(&["echo", "hello"]).unwrap();
        assert!(out.ok());
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[test]
    fn there_is_no_shell_to_inject_into() {
        // The whole argument is one argv element. A shell would run `id`;
        // `echo` just prints the text, which is the point.
        let out = run(&["echo", "x; id", "&& whoami"]).unwrap();
        assert!(out.ok());
        assert!(out.stdout.contains("x; id"));
        assert!(!out.stdout.contains("uid="));
    }

    #[test]
    fn globs_are_not_expanded() {
        let out = run(&["echo", "/etc/*"]).unwrap();
        assert_eq!(out.stdout.trim(), "/etc/*");
    }

    #[test]
    fn a_nonzero_exit_is_reported_not_swallowed() {
        let out = run(&["false"]).unwrap();
        assert!(!out.ok());
        assert_eq!(out.status, Some(1));
    }

    #[test]
    fn the_environment_is_cleared() {
        // The caller must not be able to steer the helper through the
        // environment - LD_PRELOAD being the obvious one.
        std::env::set_var("SNPANEL_TEST_LEAK", "should-not-appear");
        let out = run(&["env"]).unwrap();
        assert!(!out.stdout.contains("SNPANEL_TEST_LEAK"));
        assert!(out.stdout.contains("PATH="));
        std::env::remove_var("SNPANEL_TEST_LEAK");
    }

    #[test]
    fn stdin_carries_data_that_argv_must_not() {
        // C37: a password goes in this way, so it never appears in `ps`.
        let out = run_with_stdin(&["cat"], Some(b"s3cret-password")).unwrap();
        assert!(out.ok());
        assert_eq!(out.stdout, "s3cret-password");
    }

    #[test]
    fn a_hanging_command_is_killed_at_the_budget() {
        let started = Instant::now();
        let out = run_with_timeout(&["sleep", "30"], Duration::from_millis(400)).unwrap();
        assert!(out.status.is_none(), "should have been killed");
        assert!(out.stderr.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_command_inside_its_budget_returns_normally() {
        let out = run_with_timeout(&["echo", "quick"], Duration::from_secs(5)).unwrap();
        assert!(out.ok());
        assert_eq!(out.stdout.trim(), "quick");
    }

    #[test]
    fn respond_maps_failure_onto_the_wire_shape() {
        let ok = respond("echo", run(&["echo", "hi"]));
        assert!(ok.ok);

        let bad = respond("false", run(&["false"]));
        assert!(!bad.ok);
        assert_eq!(
            bad.error.as_ref().unwrap().kind,
            HelperErrorKind::CommandFailed
        );

        let missing = respond("nope", run(&["/nonexistent/binary"]));
        assert!(!missing.ok);
        assert_eq!(missing.error.unwrap().kind, HelperErrorKind::Internal);
    }

    #[test]
    fn a_timeout_is_distinguishable_from_a_failure() {
        let out = respond(
            "sleep",
            run_with_timeout(&["sleep", "30"], Duration::from_millis(300)),
        );
        assert_eq!(out.error.unwrap().kind, HelperErrorKind::Timeout);
    }
}
