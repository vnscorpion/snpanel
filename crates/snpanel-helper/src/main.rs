//! `snpanel-helper` - the only code that runs as root for the panel.
//!
//! Phase 2 of `RUST_MIGRATION_PLAN.md`. Two transports, one set of operations
//! (plan §4.2):
//!
//! - **Socket** (`--serve`): a Unix socket at `/run/snpanel/helper.sock`, with
//!   the caller authenticated by `SO_PEERCRED`. This is how the API will talk
//!   to it.
//! - **CLI** (`snpanel-helper <op> [args]`): the same operations, reachable by
//!   hand. Kept deliberately - it is how the *existing Python* can drive this
//!   helper before anything else is ported, which is exactly the Phase 2
//!   definition of done, and it is how an administrator debugs a broken box.
//!
//! Every operation is dispatched through the same `ops::dispatch`, so the two
//! paths cannot drift apart.

mod audit;
mod exec;
mod ops;
mod peercred;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;

use snpanel_ipc::{Envelope, HelperErrorKind, HelperResponse, SOCKET_PATH};

use ops::Context;

fn main() -> ExitCode {
    // Same reasoning as the CLI: `snpanel-helper firewall-status | head` should
    // exit quietly, not panic.
    // SAFETY: called once, before any thread exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    // Where the audit trail goes is worth knowing: journald when there is a
    // journal, stderr otherwise. It is reported by `--help` so an operator can
    // check rather than assume.
    let sink = audit::init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--serve") => serve(),
        Some("--help") | Some("-h") | None => {
            print_help(sink);
            ExitCode::SUCCESS
        }
        Some(_) => cli(&args),
    }
}

/// How many of the bash helper's verbs this binary answers, and how many
/// there are.
///
/// Printed by `--help`, which is what an operator reads during a cutover to
/// decide what has moved. It is checked against both files by
/// `the_help_text_counts_are_the_measured_ones`, because the previous figure
/// was hardcoded and went twenty-four verbs stale without anything noticing.
const ANSWERED_VERBS: usize = 103;
const BASH_VERBS: usize = 147;

fn print_help(sink: audit::Sink) {
    println!("snpanel-helper - privileged operations for SNPanel\n");
    println!("  snpanel-helper --serve            listen on {SOCKET_PATH}");
    println!("  snpanel-helper <op> [args...]     run one operation directly\n");
    println!("Operations answered by Rust ({ANSWERED_VERBS} of the bash helper's {BASH_VERBS}):");
    for line in [
        "  firewall-*      apply, flush, status, list, migrate-nft, allow-ip,",
        "                  deny-ip, allow-port, panel-allow-port, delete,",
        "                  enable, disable, reload;",
        "                  blocklist-add, blocklist-delete",
        "  nginx-*         test, reload, custom-write, custom-delete;",
        "                  http-flood-zones-save",
        "  panel-user-*    ensure, delete, password (password on stdin),",
        "                  lock, unlock",
        "  site-*          mkdir, rm, path-fix, file-write, file-install, chmod,",
        "                  log-read, log-clear, logs-read-many, document-root-ensure,",
        "                  populate, archive-extract, runtime-ensure, runtime-move,",
        "                  runtime-delete",
        "  docker-*        status, prune;         node-list",
        "  site-app-*      write (node, docker), control, logs, delete, dir-ensure,",
        "                  rename, pull, install-deps, export, import, volume-usage,",
        "                  compose-ps, compose-pull",
        "  wp, wp-site",
        "  fix-permissions",
        "  certbot-*       issue, renew, delete;  ssl-cert-info",
        "  panel-ssl-*     selfsigned, domains;   panel-sni-sync",
        "  php-*           opcache-set, config-write, tune-write, pools-retune",
        "  ipv6-*          status, enable, disable, apply",
        "  time-*          status, sync;          cron-list, cron-write",
        "  updates-*       status, os-run, os-auto",
        "  waf-*           status, crs-status, crs-mode, site-save, site-delete,",
        "                  default-rules, custom-rules, custom-save, update",
        "  clamav-*        status, start, stop;   maldet-status",
        "  systemctl, daemon-reload, service-status, fastcgi-cache-clear",
        "  selinux-*       restore-site, port-add (no-op off the RHEL family)",
    ] {
        println!("{line}");
    }
    println!("\nAny other operation is passed through to snpanel-helper.sh,");
    println!("so the panel can call this binary for everything.");
    println!(
        "\nAudit trail: {}",
        match sink {
            audit::Sink::Journald => concat!(
                "journald  -  journalctl -t snpanel-helper\n",
                "             fields are F_OP, F_CALLER_UID, F_CALLER_PID\n",
                "             e.g. journalctl -t snpanel-helper F_OP=firewall-deny-ip"
            ),
            audit::Sink::Stderr => "stderr - no journal socket on this machine",
        }
    );
}

// ---------------------------------------------------------------------------
// Socket transport
// ---------------------------------------------------------------------------

fn serve() -> ExitCode {
    if !is_root() {
        eprintln!("snpanel-helper --serve must run as root");
        return ExitCode::from(1);
    }

    let panel_uid = match peercred::uid_of(peercred::PANEL_USER) {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("snpanel-helper: {e}");
            return ExitCode::from(1);
        }
    };

    let listener = match listener_from_systemd() {
        Some(l) => {
            tracing::info!("accepted socket from systemd activation");
            l
        }
        None => match bind_socket() {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "snpanel-helper: cannot bind {}: {e}",
                    socket_path().display()
                );
                return ExitCode::from(1);
            }
        },
    };

    let ctx = Context::from_system();
    tracing::info!(panel_uid, panel_port = ctx.panel_port, "helper ready");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle(s, panel_uid, &ctx),
            Err(e) => tracing::warn!("accept failed: {e}"),
        }
    }
    ExitCode::SUCCESS
}

/// Take the listening socket from systemd, if we were socket-activated.
///
/// The protocol is `LISTEN_FDS` / `LISTEN_PID`; the first passed fd is 3.
fn listener_from_systemd() -> Option<UnixListener> {
    use std::os::unix::io::FromRawFd;

    let pid: i32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    // SAFETY: getpid cannot fail.
    if pid != unsafe { libc::getpid() } {
        return None;
    }
    let count: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if count < 1 {
        return None;
    }
    // SAFETY: systemd guarantees fd 3 is a listening socket it opened for us,
    // and this is the only place that claims it.
    Some(unsafe { UnixListener::from_raw_fd(3) })
}

/// The socket to bind when systemd has not handed us one.
///
/// `SNPANEL_HELPER_SOCKET` overrides it. That exists for two real cases: an
/// administrator running a second helper on a scratch path to reproduce
/// something without disturbing the live one, and the integration tests. It
/// changes only where the helper listens - `SO_PEERCRED` still decides who may
/// talk to it, so an override cannot be used to get around authorisation.
fn socket_path() -> std::path::PathBuf {
    std::env::var_os("SNPANEL_HELPER_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(SOCKET_PATH))
}

fn bind_socket() -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    let owned = socket_path();
    let path = owned.as_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A stale socket from a previous run would make bind fail with EADDRINUSE.
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path)?;
    // The filesystem permission is a second line of defence; SO_PEERCRED is
    // the one that actually decides. Both, because a mode bit is easy to get
    // wrong and a kernel check is not.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn handle(stream: UnixStream, panel_uid: u32, ctx: &Context) {
    let peer = match peercred::peer_of(&stream) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("refusing connection: {e}");
            let _ = respond_to(
                &stream,
                &HelperResponse::failed(HelperErrorKind::NotAuthorised, e.to_string()),
            );
            drain_after_refusal(&stream);
            return;
        }
    };

    if let Err(e) = peercred::authorise(peer, panel_uid) {
        // Worth a loud log: something on this box is trying to reach root
        // through the panel's helper.
        tracing::warn!(
            peer_uid = peer.uid,
            peer_pid = peer.pid,
            "unauthorised caller: {e}"
        );
        let _ = respond_to(
            &stream,
            &HelperResponse::failed(HelperErrorKind::NotAuthorised, e.to_string()),
        );
        drain_after_refusal(&stream);
        return;
    }

    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("cannot read from peer: {e}");
            return;
        }
    });

    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => return, // peer hung up
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("read failed: {e}");
            return;
        }
    }

    let response = match Envelope::decode(line.as_bytes()) {
        Ok(env) => {
            audit::log_request(&env.request, peer.uid, peer.pid);
            let resp = ops::dispatch(&env.request, ctx);
            audit::log_result(env.request.op_name(), &resp);
            resp
        }
        Err(e) => {
            tracing::warn!(peer_uid = peer.uid, "malformed request: {e}");
            HelperResponse::failed(HelperErrorKind::BadRequest, e.to_string())
        }
    };

    let _ = respond_to(&stream, &response);
}

fn respond_to(stream: &UnixStream, response: &HelperResponse) -> std::io::Result<()> {
    let mut out = serde_json::to_vec(response)?;
    out.push(b'\n');
    (&mut &*stream).write_all(&out)?;
    Ok(())
}

/// Give a refused caller time to finish its request and read the answer.
///
/// A refusal is decided from the peer's credentials, before the request is
/// read - so the client is usually still writing when the decision is made.
/// Dropping the stream there closes both directions, the client's `write`
/// gets EPIPE, and it never sees the refusal already waiting in its receive
/// buffer. It would report a broken pipe for what was an authorisation
/// decision, which is exactly the distinction this protocol exists to make.
///
/// Bounded in time and in bytes on purpose: the peer here is one that has
/// just been told no.
fn drain_after_refusal(stream: &UnixStream) {
    use std::io::Read;

    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
    let mut sink = [0u8; 4096];
    let mut total = 0usize;
    while total < 64 * 1024 {
        match (&mut &*stream).read(&mut sink) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// CLI transport
// ---------------------------------------------------------------------------

/// Map a bash-style invocation onto the same request enum.
///
/// The names match the bash subcommands exactly, so a script or a Python call
/// site that shells out to `snpanel-helper nginx-reload` keeps working when the
/// binary underneath is swapped.
fn cli(args: &[String]) -> ExitCode {
    use snpanel_ipc::HelperRequest;

    if !is_root() {
        eprintln!("snpanel-helper must run as root");
        return ExitCode::from(1);
    }

    // The mapping itself lives in the protocol crate, because the API needs
    // the identical one to build a request for the socket. Plan §4.3.
    //
    // An unmapped verb is handed to the bash helper - that fallthrough is the
    // cutover mechanism. A *mapped* verb with arguments this refuses is not:
    // it is reported, because an argument rejected here must not get a second
    // hearing from an implementation that may parse it more loosely.
    let request = match HelperRequest::from_argv(args, read_stdin_bytes) {
        Ok(request) => request,
        Err(e) if e.is_unmapped() => return delegate_to_bash(args),
        Err(e) => return fail(&e.to_string()),
    };

    let ctx = Context::from_system();
    audit::log_request(&request, current_uid(), std::process::id() as i32);
    let response = ops::dispatch(&request, &ctx);
    audit::log_result(request.op_name(), &response);

    if !response.stdout.is_empty() {
        print!("{}", response.stdout);
    }
    if !response.stderr.is_empty() {
        eprint!("{}", response.stderr);
    }
    if let Some(data) = &response.data {
        println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
    }

    if response.ok {
        ExitCode::SUCCESS
    } else {
        if let Some(err) = &response.error {
            eprintln!("snpanel-helper: {}", err.message);
        }
        ExitCode::from(1)
    }
}

/// The bash helper, kept alongside for operations not yet ported.
const BASH_HELPER: &str = "/usr/local/sbin/snpanel-helper.sh";

/// Hand an unported operation to the bash helper.
///
/// This is the mechanism that lets the panel be switched to the Rust helper
/// today rather than after the last of 111 subcommands is done: the panel
/// calls one path, Rust answers what it has ported, and everything else
/// reaches exactly the code that was serving it yesterday.
///
/// `exec` rather than spawn-and-wait, for three reasons that all matter here:
///
/// - the environment carries through, including `SUDO_USER`, which the bash
///   helper checks as its own authorisation;
/// - stdin, stdout and stderr are the same file descriptors, so an operation
///   that reads a password or a crontab from stdin still works, and output is
///   not buffered or mangled;
/// - the exit status is the bash helper's own, with no wrapper to translate
///   it wrongly.
fn delegate_to_bash(args: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt;

    if !std::path::Path::new(BASH_HELPER).exists() {
        eprintln!(
            "snpanel-helper: '{}' is not implemented in the Rust helper, and \
             {BASH_HELPER} is not installed to fall back to",
            args[0]
        );
        return ExitCode::from(2);
    }

    tracing::info!(
        op = args[0].as_str(),
        "not ported yet; delegating to the bash helper"
    );

    // On success this never returns: the process becomes the bash helper.
    let err = std::process::Command::new(BASH_HELPER).args(args).exec();
    eprintln!("snpanel-helper: cannot exec {BASH_HELPER}: {err}");
    ExitCode::from(2)
}

/// The same, for content that is not necessarily UTF-8 - a site file can be
/// an image or an archive.
fn read_stdin_bytes() -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
    buf
}

fn fail(message: &str) -> ExitCode {
    eprintln!("snpanel-helper: {message}");
    ExitCode::from(2)
}

fn is_root() -> bool {
    current_uid() == 0
}

fn current_uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two numbers in `--help` are the measured ones.
    ///
    /// They were hardcoded, and by the time Stage B started they were wrong by
    /// twenty-four verbs - at exactly the moment an operator reads them to
    /// decide what has moved. Recounted here from the two files that decide
    /// it: the bash helper's `case` labels, and the mapping's match arms.
    ///
    /// Counting the mapping's *arms* rather than its quoted strings matters.
    /// An arm holds argument literals too - "0640", "tcp", "start" - and
    /// counting those gave 92, which is not a number of verbs at all. Only a
    /// string that is also a `case` label in the bash counts.
    #[test]
    fn the_help_text_counts_are_the_measured_ones() {
        const BASH: &str = include_str!("../../../installer/files/snpanel-helper.sh");
        const MAPPING: &str = include_str!("../../../crates/snpanel-ipc/src/argv.rs");

        // `  <verb>)` at the top level of the helper's case statement - and
        // `  <verb>|<alias>|<alias>)`, which is how a third of them are
        // written. Matching only the first form counted a subset of the
        // helper and called it the whole.
        let verbs: Vec<&str> = BASH
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("  ")?;
                let arm = rest.strip_suffix(')')?;
                let names: Vec<&str> = arm.split('|').collect();
                let ok = !names.is_empty()
                    && names.iter().all(|name| {
                        !name.is_empty()
                            && name.starts_with(|c: char| c.is_ascii_lowercase())
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    });
                ok.then_some(names)
            })
            .flatten()
            .collect();

        let mapping = match MAPPING.find("pub fn from_argv") {
            Some(at) => &MAPPING[at..],
            None => panic!("from_argv is not in the mapping any more"),
        };
        let mapping = match mapping.find("#[cfg(test)]") {
            Some(at) => &mapping[..at],
            None => mapping,
        };

        let answered = verbs
            .iter()
            .filter(|v| mapping.contains(&format!("(\"{v}\"")))
            .count();

        assert_eq!(
            verbs.len(),
            BASH_VERBS,
            "the bash helper has {} verbs, --help says {BASH_VERBS}",
            verbs.len()
        );
        assert_eq!(
            answered, ANSWERED_VERBS,
            "the mapping answers {answered} of them, --help says {ANSWERED_VERBS}"
        );
    }
}
