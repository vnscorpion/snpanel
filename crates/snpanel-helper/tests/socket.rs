//! End-to-end tests for the socket transport.
//!
//! These drive the real binary over a real Unix socket, because the things
//! worth testing here - that an unauthorised caller is refused, that a
//! malformed request cannot crash the server - are properties of the wired-up
//! system, not of any one function.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Where cargo puts the binary under test.
fn helper_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test binary path");
    dir.pop(); // the test's own filename
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("snpanel-helper")
}

/// A check that could not run here - and whether that is acceptable.
///
/// Every test in this file guards on something the machine may not provide:
/// root, a helper that starts, a client that can drop privileges. On a
/// developer's box those guards are right; it is not root and should not be.
/// In CI they are not. The job runs as root in a container built for these
/// tests, so a skip there is coverage quietly disappearing - which is exactly
/// what had happened: the helper will not serve without the `snpanel` account,
/// no container had it, and three of the four tests below had never run
/// anywhere that would notice.
#[track_caller]
fn skip(reason: &str) {
    if std::env::var_os("CI").is_some() {
        panic!(
            "this check must not be skipped in CI, and was: {reason}\n\
             Either the container is missing something the workflow should \
             set up, or the guard is wrong. Do not relax the guard to make \
             this pass."
        );
    }
    eprintln!("skipped: {reason}");
}

fn is_root() -> bool {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() == 0 }
}

struct Server {
    child: Child,
    socket: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Start the helper on a private socket path.
///
/// `SNPANEL_HELPER_SOCKET` moves where it listens; nothing else about the
/// server changes, so this exercises the same accept/authorise/dispatch path
/// production uses.
///
/// Socket activation is deliberately *not* simulated here. Doing so needs
/// `LISTEN_PID` to equal the child's pid, which means setting an environment
/// variable inside `pre_exec` - and `set_var` is not async-signal-safe, so
/// after `fork` it can deadlock on the environment lock. It did, the first
/// time this was written, and the test suite hung. The systemd path is
/// verified in the container instead, where systemd itself passes the fd.
fn start_server(socket: PathBuf) -> Option<Server> {
    let _ = std::fs::remove_file(&socket);

    let child = Command::new(helper_binary())
        .arg("--serve")
        .env("SNPANEL_HELPER_SOCKET", &socket)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let server = Server {
        child,
        socket: socket.clone(),
    };

    // Wait until the socket exists and answers, so no test races startup.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if server.socket.exists() && UnixStream::connect(&server.socket).is_ok() {
            return Some(server);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(server);
    None
}

fn request(socket: &PathBuf, payload: &str) -> Option<String> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(payload.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    stream.flush().ok()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    Some(line)
}

fn socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("snpanel-test-{}-{}.sock", name, std::process::id()))
}

/// The CLI must pass an unported operation to the bash helper, and say so.
///
/// This is what makes the cutover safe, so it is worth a test that does not
/// need a real installation: with no bash helper present the message has to
/// name both the operation and the missing fallback, rather than failing
/// vaguely.
/// An operation nothing answers is reported the way the bash reported one.
///
/// This test used to name `site-runtime-ensure` and check that the helper
/// said which bash script it had looked for and not found. Both halves had
/// rotted: `site-runtime-ensure` was ported at some point and stopped
/// reaching that path at all, and the bash it looked for is now deleted. So
/// it named a verb that *was* served and asserted about a branch it never
/// entered - which reads as coverage and is not.
///
/// The verb below cannot be ported by accident, and the message is the
/// bash's own, because a caller that matched on it keeps working.
#[test]
fn an_unknown_operation_is_reported_as_unknown() {
    if !is_root() {
        skip("the CLI path requires root");
        return;
    }
    let out = Command::new(helper_binary())
        .arg("no-such-operation-exists")
        .output()
        .expect("helper runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown command: no-such-operation-exists"),
        "must name the operation: {stderr}"
    );
    // `deny` exits 1, and so does this.
    assert_eq!(out.status.code(), Some(1), "{stderr}");
}

#[test]
fn a_well_formed_request_gets_a_structured_answer() {
    if !is_root() {
        skip("needs root to run the helper");
        return;
    }
    let sock = socket_path("ok");
    let Some(server) = start_server(sock.clone()) else {
        skip("could not start the helper - does the `snpanel` user exist?");
        return;
    };

    let reply = request(
        &server.socket,
        r#"{"version":1,"request":{"op":"firewall-status"}}"#,
    )
    .expect("a reply");

    let parsed: serde_json::Value = serde_json::from_str(&reply).expect("JSON reply");
    assert!(parsed.get("ok").is_some(), "reply must carry `ok`: {reply}");
}

#[test]
fn a_malformed_request_is_refused_without_killing_the_server() {
    if !is_root() {
        skip("needs root");
        return;
    }
    let sock = socket_path("malformed");
    let Some(server) = start_server(sock.clone()) else {
        skip("could not start the helper - does the `snpanel` user exist?");
        return;
    };

    for bad in [
        "not json at all",
        "{}",
        r#"{"version":1}"#,
        r#"{"version":99,"request":{"op":"nginx-test"}}"#,
        r#"{"version":1,"request":{"op":"no-such-operation"}}"#,
        // The one that matters: a path outside /home cannot deserialize.
        r#"{"version":1,"request":{"op":"selinux-restore-site","path":"/etc/shadow"}}"#,
        // Nor can an arbitrary systemd unit.
        r#"{"version":1,"request":{"op":"service-control","service":"sshd","action":"stop"}}"#,
    ] {
        let reply = request(&server.socket, bad).unwrap_or_else(|| panic!("no reply to {bad}"));
        let parsed: serde_json::Value =
            serde_json::from_str(&reply).unwrap_or_else(|_| panic!("bad JSON for {bad}: {reply}"));
        assert_eq!(parsed["ok"], false, "{bad} should be refused");
    }

    // Still alive after all of that.
    let reply = request(
        &server.socket,
        r#"{"version":1,"request":{"op":"firewall-status"}}"#,
    )
    .expect("server survived");
    assert!(reply.contains("\"ok\""));
}

#[test]
fn an_unauthorised_uid_is_refused_by_the_kernel_check() {
    if !is_root() {
        skip("needs root to drop privileges");
        return;
    }
    let sock = socket_path("peercred");
    let Some(server) = start_server(sock.clone()) else {
        skip("could not start the helper - does the `snpanel` user exist?");
        return;
    };
    // The socket mode would stop this too; loosen it so the test proves that
    // SO_PEERCRED - not the mode bits - is what refuses the caller.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&server.socket, std::fs::Permissions::from_mode(0o666)).unwrap();

    // Connect as nobody, from a child process.
    let script = format!(
        r#"
import socket, json, sys, os, time
os.setgid(65534); os.setuid(65534)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect({sock:?})
# Deliberately pause between connecting and sending. The server decides from
# the peer's credentials alone, so by now it has already written its refusal;
# if it closed the socket at that point this send raises EPIPE and the
# refusal - sitting in the receive buffer - is never read. That was a rare
# flake until the server learned to drain instead of closing, and sleeping
# here makes the client lose the race every time instead of one run in ten.
time.sleep(0.05)
s.sendall(b'{{"version":1,"request":{{"op":"firewall-status"}}}}\n')
print(s.recv(65536).decode(), end="")
"#,
        sock = server.socket.to_str().unwrap()
    );

    // Skipped rather than panicked when python3 is missing. This test is
    // about the helper refusing an unprivileged peer; dying because the
    // container has no interpreter tells nobody anything about that, and it
    // is what turned two matrix entries red. CI installs python3 so the check
    // does run - a test that always skips is not a test.
    let out = match Command::new("python3").arg("-c").arg(&script).output() {
        Ok(out) => out,
        Err(e) => {
            skip(&format!("python3 is not available to run the client ({e})"));
            return;
        }
    };

    let reply = String::from_utf8_lossy(&out.stdout);
    if reply.trim().is_empty() {
        skip(&format!(
            "could not run the unprivileged client ({})",
            String::from_utf8_lossy(&out.stderr)
        ));
        return;
    }

    let parsed: serde_json::Value =
        serde_json::from_str(reply.trim()).unwrap_or_else(|_| panic!("bad JSON: {reply}"));
    assert_eq!(parsed["ok"], false, "uid 65534 must be refused");
    assert_eq!(
        parsed["error"]["kind"], "not-authorised",
        "and refused specifically for who it is: {reply}"
    );
}
