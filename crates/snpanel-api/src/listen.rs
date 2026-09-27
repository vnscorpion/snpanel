//! A listening socket that answers on IPv4 *and* IPv6.
//!
//! Source: `dual_stack_socket` in `serve.py`.
//!
//! Binding `[::]` is not enough on its own, and the reason is the whole of
//! this module. A kernel may or may not share an `AF_INET6` socket with
//! IPv4 — `net.ipv6.bindv6only` decides the default — and a runtime that
//! sets `IPV6_V6ONLY` for you, as Python's asyncio deliberately does, leaves
//! the panel answering over IPv6 and refusing every IPv4 client.
//!
//! So the option is cleared explicitly and then **read back**. A kernel that
//! silently refused to clear it would cost us IPv4, which is far worse than
//! not gaining IPv6 — and that asymmetry is the rule the whole module
//! follows: every failure lands on "IPv4 only" rather than on an error.

use std::net::TcpListener;
use std::os::fd::FromRawFd;

/// The listen backlog, matching `serve.py`.
///
/// 2048 rather than the usual 128: the panel is behind nginx, which opens
/// connections in bursts when a page pulls several API calls at once, and a
/// short backlog turns that into resets rather than into waiting.
pub const BACKLOG: i32 = 2048;

/// Why there is no dual-stack socket.
///
/// Carried rather than discarded because each one is a different sentence in
/// the log, and an operator who turned IPv6 on wants to know which of these
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoDualStack {
    /// IPv6 is switched off for this panel. Not a failure.
    Disabled,
    /// The machine has no IPv6 at all.
    NoIpv6(String),
    /// The socket existed but could not be made to serve both families.
    CouldNotListen(String),
}

impl NoDualStack {
    /// The line the panel logs.
    pub fn message(&self) -> Option<String> {
        match self {
            // Nothing to say: the operator turned it off.
            Self::Disabled => None,
            Self::NoIpv6(why) => Some(format!(
                "IPv6 is on but this machine has no IPv6 ({why}); listening on IPv4 only"
            )),
            Self::CouldNotListen(why) => Some(format!(
                "Could not listen on IPv6 ({why}); listening on IPv4 only"
            )),
        }
    }
}

/// The message when a kernel will not clear the option.
///
/// `net.ipv6.bindv6only` only sets the *default*; a kernel that refuses to
/// clear it would leave a socket that answers IPv6 alone. Checked rather
/// than assumed, because the failure is silent: `setsockopt` succeeds and
/// the socket is simply not what was asked for.
pub const KERNEL_WILL_NOT_SHARE: &str = "this kernel will not share the socket with IPv4";

/// Build the socket, or say why not.
///
/// # Safety and failure
///
/// Every error path closes the descriptor and returns a reason. Nothing here
/// propagates an error upward: losing IPv4 is far worse than not gaining
/// IPv6, so the caller's job is to fall back to an ordinary IPv4 bind.
pub fn dual_stack(port: u16, ipv6_enabled: bool) -> Result<TcpListener, NoDualStack> {
    if !ipv6_enabled {
        return Err(NoDualStack::Disabled);
    }
    // SAFETY: `socket` is a plain syscall; the descriptor it returns is
    // owned here and closed on every path below.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(NoDualStack::NoIpv6(last_error()));
    }

    match configure(fd, port) {
        Ok(()) => {
            // SAFETY: `fd` is a listening socket this function owns and has
            // not closed; ownership moves into the listener.
            Ok(unsafe { TcpListener::from_raw_fd(fd) })
        }
        Err(why) => {
            // SAFETY: closing a descriptor this function owns, exactly once,
            // on the path where it is not handed to anything else.
            unsafe { libc::close(fd) };
            Err(NoDualStack::CouldNotListen(why))
        }
    }
}

fn configure(fd: i32, port: u16) -> Result<(), String> {
    set_bool(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, true)?;
    set_bool(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, false)?;

    // Read it back. `setsockopt` can succeed without the socket becoming
    // what was asked for, and the difference is invisible until an IPv4
    // client is refused.
    if get_bool(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)? {
        return Err(KERNEL_WILL_NOT_SHARE.to_string());
    }

    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        // The wildcard address, written out rather than taken from
        // `libc::in6addr_any` — that is an extern static, and sixteen zero
        // bytes is what it holds.
        sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
        sin6_scope_id: 0,
    };
    // SAFETY: `addr` is a correctly initialised `sockaddr_in6` and the
    // length passed is its own size.
    let bound = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` is a bound socket.
    if unsafe { libc::listen(fd, BACKLOG) } < 0 {
        return Err(last_error());
    }
    Ok(())
}

fn set_bool(fd: i32, level: i32, name: i32, value: bool) -> Result<(), String> {
    let value: libc::c_int = i32::from(value);
    // SAFETY: `value` outlives the call and its size is passed correctly.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    Ok(())
}

fn get_bool(fd: i32, level: i32, name: i32) -> Result<bool, String> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: both out-parameters are owned here and correctly sized.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of_mut!(value).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    Ok(value != 0)
}

fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};

    /// Whether this machine has IPv6 at all, asked independently of the code
    /// under test.
    ///
    /// A plain bind to loopback: if that works, the kernel has IPv6 and any
    /// refusal from [`dual_stack`] is a bug here rather than a fact about the
    /// box.
    fn machine_has_ipv6() -> bool {
        TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok()
    }

    /// A dual-stack listener, or `None` only when this machine genuinely
    /// cannot provide one.
    ///
    /// **Not** `let Ok(..) else { skip }`. That swallowed a broken
    /// implementation: with `IPV6_V6ONLY` set instead of cleared, the
    /// read-back check refuses, every test skips, and all eight pass having
    /// tested nothing. Found by mutation, which is the only way a test like
    /// that gets found.
    fn listener_or_skip() -> Option<TcpListener> {
        match dual_stack(0, true) {
            Ok(listener) => Some(listener),
            Err(NoDualStack::NoIpv6(why)) => {
                eprintln!("skipped: this machine has no IPv6 ({why})");
                None
            }
            Err(other) if !machine_has_ipv6() => {
                eprintln!("skipped: this machine cannot serve IPv6 ({other:?})");
                None
            }
            Err(other) => panic!(
                "this machine has IPv6 and dual_stack still refused: {other:?} - \
                 that is a bug here, not a property of the box"
            ),
        }
    }

    /// The operator turned it off. Nothing to log, and no socket.
    #[test]
    fn ipv6_switched_off_is_not_a_failure() {
        assert_eq!(dual_stack(0, false).unwrap_err(), NoDualStack::Disabled);
        assert_eq!(NoDualStack::Disabled.message(), None);
    }

    /// Each reason is a different sentence, because an operator who turned
    /// IPv6 on wants to know which of them happened.
    #[test]
    fn each_reason_reads_differently() {
        let no_ipv6 = NoDualStack::NoIpv6("no such protocol".into())
            .message()
            .expect("a message");
        let no_listen = NoDualStack::CouldNotListen("address in use".into())
            .message()
            .expect("a message");
        assert!(no_ipv6.contains("this machine has no IPv6"));
        assert!(no_listen.contains("Could not listen on IPv6"));
        assert_ne!(no_ipv6, no_listen);
        // Both say what the panel did instead, which is the part that
        // matters to somebody reading the log.
        assert!(no_ipv6.ends_with("listening on IPv4 only"));
        assert!(no_listen.ends_with("listening on IPv4 only"));
    }

    /// The whole point of the module: one socket, both families.
    ///
    /// Bound on an ephemeral port and connected to over **both** an IPv6 and
    /// an IPv4 loopback address. An `IPV6_V6ONLY` socket accepts the first
    /// and refuses the second, so this is the test that would have caught
    /// the bug the read-back check exists to prevent.
    #[test]
    fn one_socket_answers_both_families() {
        let Some(listener) = listener_or_skip() else {
            return;
        };
        let port = listener.local_addr().expect("a local address").port();

        let accept = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("an accepted connection");
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).expect("the client's bytes");
                stream.write_all(&buf).expect("the echo");
            }
        });

        for addr in [
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ] {
            let mut client =
                TcpStream::connect(addr).unwrap_or_else(|e| panic!("connecting over {addr}: {e}"));
            client.write_all(b"ping").expect("the request");
            let mut echoed = [0u8; 4];
            client.read_exact(&mut echoed).expect("the response");
            assert_eq!(&echoed, b"ping", "over {addr}");
        }
        accept.join().expect("the accept thread");
    }

    /// The socket is bound to the wildcard address, not to loopback — a
    /// panel bound to `::1` would answer nothing from outside the machine.
    #[test]
    fn the_socket_is_bound_to_the_wildcard_address() {
        let Some(listener) = listener_or_skip() else {
            return;
        };
        let addr = listener.local_addr().expect("a local address");
        assert!(addr.is_ipv6(), "{addr}");
        assert!(addr.ip().is_unspecified(), "{addr} is not the wildcard");
        assert_ne!(addr.port(), 0, "the kernel assigned no port");
    }

    /// 2048 rather than the usual 128: the panel sits behind nginx, which
    /// opens connections in bursts when a page pulls several API calls at
    /// once, and a short backlog turns that into resets rather than waiting.
    #[test]
    fn the_backlog_is_the_one_the_python_asked_for() {
        assert_eq!(BACKLOG, 2048);
    }

    /// The read-back is what this module exists for. `setsockopt` can
    /// succeed without the socket becoming what was asked for, and the
    /// difference is invisible until an IPv4 client is refused.
    #[test]
    fn the_v6only_option_is_read_back_after_it_is_cleared() {
        let Some(listener) = listener_or_skip() else {
            return;
        };
        use std::os::fd::AsRawFd;
        let v6only = get_bool(listener.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)
            .expect("reading the option back");
        assert!(!v6only, "the socket came back IPv6-only");
        assert!(KERNEL_WILL_NOT_SHARE.contains("will not share"));
    }

    /// The conversion the server actually performs.
    ///
    /// `axum::serve` wants a tokio listener, and a tokio listener wants a
    /// non-blocking descriptor — `from_std` does not set that for us, and a
    /// blocking accept inside the runtime stalls every other task on the
    /// thread. This walks the whole path `main` walks: dual-stack socket,
    /// `set_nonblocking`, `from_std`, serve, and then a real HTTP request
    /// over **both** families.
    ///
    /// The request is written by hand rather than with an HTTP client,
    /// because adding a dependency to prove a socket works would be a poor
    /// trade.
    #[tokio::test]
    async fn the_server_answers_both_families_through_the_tokio_conversion() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Some(std_listener) = listener_or_skip() else {
            return;
        };
        let port = std_listener.local_addr().expect("a local address").port();
        std_listener
            .set_nonblocking(true)
            .expect("the descriptor goes non-blocking");
        let listener =
            tokio::net::TcpListener::from_std(std_listener).expect("the tokio conversion");

        let app = axum::Router::new().route("/api/health", axum::routing::get(|| async { "ok" }));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });

        for host in ["[::1]", "127.0.0.1"] {
            let mut stream =
                tokio::net::TcpStream::connect((host.trim_matches(|c| c == '[' || c == ']'), port))
                    .await
                    .unwrap_or_else(|e| panic!("connecting over {host}: {e}"));
            stream
                .write_all(
                    format!(
                        "GET /api/health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("the request");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("the response");
            let response = String::from_utf8_lossy(&response);
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "over {host}: {response}"
            );
            assert!(response.ends_with("ok"), "over {host}: {response}");
        }
        server.abort();
    }

    /// Two panels cannot hold the same port, and the second attempt has to
    /// say so rather than panicking — the caller falls back to IPv4, which
    /// will then fail loudly on the same port.
    #[test]
    fn a_port_already_held_is_reported_rather_than_fatal() {
        let Some(first) = listener_or_skip() else {
            return;
        };
        let port = first.local_addr().expect("a local address").port();
        match dual_stack(port, true) {
            Err(NoDualStack::CouldNotListen(why)) => {
                assert!(!why.is_empty(), "no reason given");
            }
            Err(other) => panic!("wrong reason: {other:?}"),
            Ok(_) => panic!("two sockets bound the same port"),
        }
    }
}
