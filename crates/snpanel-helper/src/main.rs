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

fn print_help(sink: audit::Sink) {
    println!("snpanel-helper - privileged operations for SNPanel\n");
    println!("  snpanel-helper --serve            listen on {SOCKET_PATH}");
    println!("  snpanel-helper <op> [args...]     run one operation directly\n");
    println!("Operations implemented in Rust (61 of the bash helper's 111):");
    for line in [
        "  firewall-*      apply, flush, status, list, migrate-nft, allow-ip,",
        "                  deny-ip, allow-port, panel-allow-port, delete,",
        "                  enable, disable",
        "  nginx-*         test, reload, custom-write, custom-delete",
        "  panel-user-*    ensure, delete, password (password on stdin)",
        "  site-*          mkdir, rm, file-write, chmod, log-read, log-clear",
        "  fix-permissions",
        "  certbot-*       issue, renew, delete;  ssl-cert-info",
        "  panel-ssl-*     selfsigned, domains;   panel-sni-sync",
        "  php-*           opcache-set, config-write",
        "  ipv6-*          status, enable, disable, apply",
        "  time-*          status, sync;          cron-list, cron-write",
        "  updates-*       status, os-run, os-auto",
        "  waf-*           status, crs-status, crs-mode, site-save, site-delete",
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

// ---------------------------------------------------------------------------
// CLI transport
// ---------------------------------------------------------------------------

/// Map a bash-style invocation onto the same request enum.
///
/// The names match the bash subcommands exactly, so a script or a Python call
/// site that shells out to `snpanel-helper nginx-reload` keeps working when the
/// binary underneath is swapped.
fn cli(args: &[String]) -> ExitCode {
    use snpanel_core::{IpOrCidr, PanelUsername, Port, SitePath};
    use snpanel_ipc::{HelperRequest, ServiceAction, ServiceName};

    if !is_root() {
        eprintln!("snpanel-helper must run as root");
        return ExitCode::from(1);
    }

    let op = args[0].as_str();
    let rest = &args[1..];

    let request = match (op, rest.len()) {
        ("nginx-test", 0) => HelperRequest::NginxTest,
        ("nginx-reload", 0) => HelperRequest::NginxReload,
        ("daemon-reload", 0) => HelperRequest::DaemonReload,
        ("firewall-apply", 0) => HelperRequest::FirewallApply,
        ("firewall-flush", 0) => HelperRequest::FirewallFlush,
        ("firewall-status", 0) => HelperRequest::FirewallStatus,
        ("firewall-migrate-nft", 0) => HelperRequest::FirewallMigrateNft,

        ("systemctl", 2) => {
            let service = match ServiceName::parse(&rest[0]) {
                Ok(s) => s,
                Err(e) => return fail(&e.to_string()),
            };
            let action = match rest[1].as_str() {
                "start" => ServiceAction::Start,
                "stop" => ServiceAction::Stop,
                "restart" => ServiceAction::Restart,
                "reload" => ServiceAction::Reload,
                "status" | "is-active" => ServiceAction::Status,
                other => return fail(&format!("action not allowed: {other}")),
            };
            HelperRequest::ServiceControl { service, action }
        }

        ("firewall-enable", 0) => HelperRequest::FirewallEnable,
        ("firewall-disable", 0) => HelperRequest::FirewallDisable,
        ("firewall-list", 0) => HelperRequest::FirewallList,
        ("ipv6-status", 0) => HelperRequest::Ipv6Status,
        ("ipv6-enable", 0) => HelperRequest::Ipv6Enable,
        ("ipv6-disable", 0) => HelperRequest::Ipv6Disable,
        ("ipv6-apply", 0) => HelperRequest::Ipv6Apply,
        ("time-status", 0) => HelperRequest::TimeStatus,
        ("time-sync", 0) => HelperRequest::TimeSync,
        ("fastcgi-cache-clear", 0) => HelperRequest::FastcgiCacheClear,
        ("updates-status", 0) => HelperRequest::UpdatesStatus,
        ("updates-os-run", 0) => HelperRequest::UpdatesOsRun,
        ("waf-status", 0) => HelperRequest::WafStatus,
        ("waf-crs-status", 0) => HelperRequest::WafCrsStatus,
        ("clamav-status", 0) => HelperRequest::ClamavStatus,
        ("maldet-status", 0) => HelperRequest::MaldetStatus,
        ("panel-ssl-domains", 0) => HelperRequest::PanelSslDomains,
        ("panel-sni-sync", 0) => HelperRequest::PanelSniSync,
        ("certbot-renew", 0) => HelperRequest::CertbotRenew { domain: None },

        ("firewall-allow-ip", 1) | ("ufw-allow-ip", 1) => match IpOrCidr::parse(&rest[0]) {
            Ok(ip) => HelperRequest::FirewallAllowIp {
                ip,
                port: None,
                protocol: snpanel_ipc::Protocol::Tcp,
            },
            Err(e) => return fail(&e.to_string()),
        },
        ("firewall-deny-ip", 1) | ("ufw-deny-ip", 1) => match IpOrCidr::parse(&rest[0]) {
            Ok(ip) => HelperRequest::FirewallDenyIp {
                ip,
                port: None,
                protocol: snpanel_ipc::Protocol::Tcp,
            },
            Err(e) => return fail(&e.to_string()),
        },
        ("firewall-allow-port", 1) | ("firewall-allow-port", 2) => {
            let port = match Port::parse(&rest[0]) {
                Ok(p) => p,
                Err(e) => return fail(&e.to_string()),
            };
            let protocol = match rest.get(1).map(String::as_str) {
                None | Some("tcp") => snpanel_ipc::Protocol::Tcp,
                Some("udp") => snpanel_ipc::Protocol::Udp,
                Some(other) => return fail(&format!("invalid protocol: {other}")),
            };
            HelperRequest::FirewallAllowPort { port, protocol }
        }
        ("firewall-panel-allow-port", 1) => match Port::parse(&rest[0]) {
            Ok(port) => HelperRequest::FirewallPanelAllowPort { port },
            Err(e) => return fail(&e.to_string()),
        },
        ("firewall-delete", 1) | ("ufw-delete", 1) => match rest[0].parse::<u32>() {
            Ok(id) => HelperRequest::FirewallDelete { id },
            Err(_) => return fail(&format!("invalid rule id: {}", rest[0])),
        },

        ("panel-user-ensure", 1) => match PanelUsername::parse(&rest[0]) {
            Ok(username) => HelperRequest::PanelUserEnsure {
                username,
                password: None,
            },
            Err(e) => return fail(&e.to_string()),
        },
        ("panel-user-delete", 1) => match PanelUsername::parse(&rest[0]) {
            Ok(username) => HelperRequest::PanelUserDelete { username },
            Err(e) => return fail(&e.to_string()),
        },
        ("panel-user-password", 1) => {
            // C37: the password arrives on stdin, never as an argument, so it
            // is not visible in `ps` for the life of the process.
            let username = match PanelUsername::parse(&rest[0]) {
                Ok(u) => u,
                Err(e) => return fail(&e.to_string()),
            };
            let mut password = String::new();
            if std::io::Read::read_to_string(&mut std::io::stdin(), &mut password).is_err() {
                return fail("could not read the password from stdin");
            }
            HelperRequest::PanelUserPassword {
                username,
                password: snpanel_core::SecretString::new(password.trim_end_matches('\n')),
            }
        }

        ("mkdir-site", 1) => match SitePath::parse(&rest[0]) {
            Ok(path) => HelperRequest::SiteMkdir { path },
            Err(e) => return fail(&e.to_string()),
        },
        ("site-log-read", 3) => {
            let domain = match snpanel_core::Domain::parse(&rest[0]) {
                Ok(d) => d,
                Err(e) => return fail(&e.to_string()),
            };
            let kind = match ops::site::LogKind::parse(&rest[1]) {
                Some(ops::site::LogKind::Access) => snpanel_ipc::LogKind::Access,
                Some(ops::site::LogKind::Error) => snpanel_ipc::LogKind::Error,
                None => return fail(&format!("invalid log kind: {}", rest[1])),
            };
            let lines = rest[2].parse::<u32>().unwrap_or(200);
            HelperRequest::SiteLogRead {
                domain,
                kind,
                lines,
            }
        }
        ("site-log-clear", 2) => {
            let domain = match snpanel_core::Domain::parse(&rest[0]) {
                Ok(d) => d,
                Err(e) => return fail(&e.to_string()),
            };
            let kind = match ops::site::LogKind::parse(&rest[1]) {
                Some(ops::site::LogKind::Access) => snpanel_ipc::LogKind::Access,
                Some(ops::site::LogKind::Error) => snpanel_ipc::LogKind::Error,
                None => return fail(&format!("invalid log kind: {}", rest[1])),
            };
            HelperRequest::SiteLogClear { domain, kind }
        }
        ("fix-permissions", 2) => {
            let path = match SitePath::parse(&rest[0]) {
                Ok(p) => p,
                Err(e) => return fail(&e.to_string()),
            };
            match PanelUsername::parse(&rest[1]) {
                Ok(user) => HelperRequest::SiteFixPermissions { path, user },
                Err(e) => return fail(&e.to_string()),
            }
        }

        ("ssl-cert-info", 1) => match snpanel_core::Domain::parse(&rest[0]) {
            Ok(domain) => HelperRequest::SslCertInfo { domain },
            Err(e) => return fail(&e.to_string()),
        },
        ("certbot-delete", 1) => match snpanel_core::Domain::parse(&rest[0]) {
            Ok(domain) => HelperRequest::CertbotDelete { domain },
            Err(e) => return fail(&e.to_string()),
        },
        ("panel-ssl-selfsigned", 1) | ("panel-ssl-selfsigned", 2) => {
            let port = match rest.get(1) {
                Some(p) => match Port::parse(p) {
                    Ok(p) => p,
                    Err(e) => return fail(&e.to_string()),
                },
                None => Port::new(2222).expect("2222 is valid"),
            };
            HelperRequest::PanelSslSelfsigned {
                host: rest[0].clone(),
                port,
            }
        }

        ("php-opcache-set", 2) => {
            let version = match snpanel_core::PhpVersion::parse(&rest[0]) {
                Ok(v) => v,
                Err(e) => return fail(&e.to_string()),
            };
            let enabled = match rest[1].as_str() {
                "1" => true,
                "0" => false,
                other => return fail(&format!("opcache switch must be 0 or 1, got {other}")),
            };
            HelperRequest::PhpOpcacheSet { version, enabled }
        }

        ("service-status", 1) => match ServiceName::parse(&rest[0]) {
            Ok(service) => HelperRequest::ServiceStatus { service },
            Err(e) => return fail(&e.to_string()),
        },
        ("updates-os-auto", 1) => HelperRequest::UpdatesOsAuto {
            enable: rest[0] == "on" || rest[0] == "1" || rest[0] == "true",
        },
        ("waf-crs-mode", 1) => {
            let mode = match rest[0].as_str() {
                "off" => snpanel_ipc::CrsMode::Off,
                "detect" => snpanel_ipc::CrsMode::Detect,
                "block" => snpanel_ipc::CrsMode::Block,
                other => return fail(&format!("invalid CRS mode: {other}")),
            };
            HelperRequest::WafCrsMode { mode }
        }
        ("waf-site-delete", 1) => match snpanel_core::Domain::parse(&rest[0]) {
            Ok(domain) => HelperRequest::WafSiteDelete { domain },
            Err(e) => return fail(&e.to_string()),
        },
        ("clamav-start", 0) => HelperRequest::ClamavControl { start: true },
        ("clamav-stop", 0) => HelperRequest::ClamavControl { start: false },

        ("cron-list", 0) => HelperRequest::CronList { user: None },
        ("cron-list", 1) => match PanelUsername::parse(&rest[0]) {
            Ok(u) => HelperRequest::CronList { user: Some(u) },
            Err(e) => return fail(&e.to_string()),
        },

        // --- operations that read their payload from stdin ---
        // The bash takes these the same way: the content is multi-line and can
        // be large, so argv is the wrong channel for it.
        ("nginx-custom-write", 1) => match snpanel_core::Domain::parse(&rest[0]) {
            Ok(domain) => HelperRequest::NginxCustomWrite {
                domain,
                content: read_stdin(),
            },
            Err(e) => return fail(&e.to_string()),
        },
        ("nginx-custom-delete", 1) => match snpanel_core::Domain::parse(&rest[0]) {
            Ok(domain) => HelperRequest::NginxCustomDelete { domain },
            Err(e) => return fail(&e.to_string()),
        },
        ("waf-site-save", 1) => match snpanel_core::Domain::parse(&rest[0]) {
            Ok(domain) => HelperRequest::WafSiteSave {
                domain,
                content: read_stdin(),
            },
            Err(e) => return fail(&e.to_string()),
        },
        ("php-config-write", 1) => match snpanel_core::PhpVersion::parse(&rest[0]) {
            Ok(version) => HelperRequest::PhpConfigWrite {
                version,
                content: read_stdin(),
            },
            Err(e) => return fail(&e.to_string()),
        },
        ("cron-write", 0) => HelperRequest::CronWrite {
            user: None,
            content: read_stdin(),
        },
        ("cron-write", 1) => match PanelUsername::parse(&rest[0]) {
            Ok(u) => HelperRequest::CronWrite {
                user: Some(u),
                content: read_stdin(),
            },
            Err(e) => return fail(&e.to_string()),
        },

        // --- the site operations, which the bash addresses as three separate
        // arguments that together name one path ---
        ("site-file-write", 3) | ("site-file-write", 4) => {
            // <site-user> <site-root> <relative-path> [0644|0640]
            let path = match site_path_from(&rest[0], &rest[1], Some(&rest[2])) {
                Ok(p) => p,
                Err(e) => return fail(&e),
            };
            let mode = match rest.get(3).map(String::as_str) {
                None | Some("0644") => snpanel_ipc::FileMode::FILE,
                Some("0640") => snpanel_ipc::FileMode::SENSITIVE,
                Some(other) => return fail(&format!("invalid file mode: {other}")),
            };
            HelperRequest::SiteFileWrite {
                path,
                content: read_stdin_bytes(),
                mode,
            }
        }
        ("site-chmod", 4) => {
            // <site-user> <site-root> <absolute-path> <mode>
            let path = match site_path_from(&rest[0], &rest[1], None) {
                Ok(_) => match SitePath::parse(&rest[2]) {
                    Ok(p) => p,
                    Err(e) => return fail(&e.to_string()),
                },
                Err(e) => return fail(&e),
            };
            // Three to five octal digits, as the bash accepts.
            let raw = rest[3].as_str();
            if raw.len() < 3 || raw.len() > 5 || !raw.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return fail(&format!("invalid mode: {raw}"));
            }
            let mode = match u32::from_str_radix(raw, 8) {
                Ok(m) => snpanel_ipc::FileMode(m),
                Err(_) => return fail(&format!("invalid mode: {raw}")),
            };
            HelperRequest::SiteChmod {
                path,
                mode,
                recursive: false,
            }
        }
        ("rm-site", 3) => {
            // <site-user> <site-root> <path>
            match site_path_from(&rest[0], &rest[1], None) {
                Ok(_) => match SitePath::parse(&rest[2]) {
                    Ok(path) => HelperRequest::SiteRemove { path },
                    Err(e) => return fail(&e.to_string()),
                },
                Err(e) => return fail(&e),
            }
        }

        ("certbot-issue", n) if n >= 1 => {
            // <domain> [alias-domain ...] [email]   -- email is last if present
            let domain = match snpanel_core::Domain::parse(&rest[0]) {
                Ok(d) => d,
                Err(e) => return fail(&e.to_string()),
            };
            let mut aliases = Vec::new();
            let mut email = None;
            for (i, arg) in rest[1..].iter().enumerate() {
                if arg.contains('@') {
                    if i + 2 != rest.len() {
                        return fail("email must be the final certbot-issue argument");
                    }
                    match snpanel_core::Email::parse(arg) {
                        Ok(e) => email = Some(e),
                        Err(e) => return fail(&e.to_string()),
                    }
                    break;
                }
                match snpanel_core::Domain::parse(arg) {
                    Ok(d) => aliases.push(d),
                    Err(e) => return fail(&e.to_string()),
                }
            }
            HelperRequest::CertbotIssue {
                domain,
                aliases,
                email,
            }
        }

        ("selinux-restore-site", 1) => match SitePath::parse(&rest[0]) {
            Ok(path) => HelperRequest::SelinuxRestoreSite { path },
            Err(e) => return fail(&e.to_string()),
        },

        ("selinux-port-add", 1) => match Port::parse(&rest[0]) {
            Ok(port) => HelperRequest::SelinuxPortAdd { port },
            Err(e) => return fail(&e.to_string()),
        },

        // Everything the Rust helper does not implement yet is handed to the
        // bash one. This is what makes the cutover safe: the panel calls one
        // path, and each operation moves to Rust independently.
        _ => return delegate_to_bash(args),
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

/// Read the whole of stdin as text.
///
/// C37's companion: content that is multi-line, large, or secret comes in this
/// way, never through argv, where it would be visible in `ps` for the life of
/// the process.
fn read_stdin() -> String {
    use std::io::Read;
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

/// The same, for content that is not necessarily UTF-8 - a site file can be
/// an image or an archive.
fn read_stdin_bytes() -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
    buf
}

/// Build a [`SitePath`] from the bash's three-argument form.
///
/// The bash addresses a site file as `<site-user> <site-root> <path>` and
/// re-derives the safety check in each arm. The typed protocol carries one
/// `SitePath` that already guarantees it, so the job here is to check the
/// three agree with each other before collapsing them - a mismatched user and
/// root is a caller bug worth reporting rather than silently trusting one of
/// them.
fn site_path_from(
    user: &str,
    root: &str,
    relative: Option<&str>,
) -> Result<snpanel_core::SitePath, String> {
    use snpanel_core::{PanelUsername, SitePath};

    let user = PanelUsername::parse(user).map_err(|e| e.to_string())?;
    let root_path = SitePath::parse(root).map_err(|e| e.to_string())?;
    if root_path.user() != &user {
        return Err(format!("site root {root} does not belong to {user}"));
    }
    match relative {
        Some(rel) => root_path.join(rel).map_err(|e| e.to_string()),
        None => Ok(root_path),
    }
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
