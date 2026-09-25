//! The line a failed sign-in leaves for the Fail2ban addon.
//!
//! Not in the Python. `login failure from <address>`, to the journal as
//! `snpanel-auth` with the facility `auth`, whether or not the addon is
//! installed - it is an ordinary record of a failed sign-in as well.
//!
//! Nothing the client typed is in it. The username is the obvious thing to
//! add, and it is also the part of the line an attacker writes: a jail
//! reading it could be steered into banning whatever address they put there.
//! The address itself comes from `client::client_host`, which believes
//! `X-Forwarded-For` only from the local nginx.

use axum::http::request::Parts;

/// What is written for a failure from `host`, or nothing when `host` is not
/// an address (a trusted proxy that sent none).
fn failure_line(host: Option<&str>) -> Option<String> {
    let address: std::net::IpAddr = host?.parse().ok()?;
    Some(format!("login failure from {}", address.to_canonical()))
}

/// Record a failed sign-in.
pub fn login_failure(parts: &Parts) {
    if let Some(line) = failure_line(crate::client::client_host(parts).as_deref()) {
        syslog_auth(&line);
    }
}

/// One message to syslog - the journal, on every distribution the panel
/// supports - as `snpanel-auth`.
fn syslog_auth(line: &str) {
    static OPEN: std::sync::Once = std::sync::Once::new();
    OPEN.call_once(|| {
        // SAFETY: the identifier is a 'static C string, and openlog keeps the
        // pointer for the life of the process.
        unsafe { libc::openlog(c"snpanel-auth".as_ptr(), libc::LOG_PID, libc::LOG_AUTH) };
    });
    let Ok(message) = std::ffi::CString::new(line) else {
        return;
    };
    // SAFETY: a "%s" format with one NUL-terminated argument; the message is
    // never used as the format.
    unsafe {
        libc::syslog(
            libc::LOG_WARNING | libc::LOG_AUTH,
            c"%s".as_ptr(),
            message.as_ptr(),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_names_the_address_and_nothing_else() {
        assert_eq!(
            failure_line(Some("203.0.113.4")).as_deref(),
            Some("login failure from 203.0.113.4")
        );
        assert_eq!(
            failure_line(Some("2001:db8::1")).as_deref(),
            Some("login failure from 2001:db8::1")
        );
        // An IPv4 client on a dual-stack socket is banned as the IPv4
        // address it is; the IPv6 spelling would never match its packets.
        assert_eq!(
            failure_line(Some("::ffff:203.0.113.4")).as_deref(),
            Some("login failure from 203.0.113.4")
        );
    }

    #[test]
    fn anything_that_is_not_an_address_writes_nothing() {
        for host in [
            None,
            Some("None"),
            Some(""),
            Some("example.com"),
            Some("203.0.113.4 login failure from 198.51.100.1"),
            Some("203.0.113.4\nlogin failure from 198.51.100.1"),
        ] {
            assert_eq!(failure_line(host), None, "{host:?}");
        }
    }
}
