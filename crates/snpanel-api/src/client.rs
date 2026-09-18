//! Who sent this request - uvicorn's `ProxyHeadersMiddleware`, ported.
//!
//! The panel runs uvicorn with `proxy_headers=True` and
//! `forwarded_allow_ips="127.0.0.1"`, and the comment in `serve.py` says why
//! in one line: *only the local Nginx may set X-Forwarded-For, so a direct hit
//! on the panel port cannot spoof the audit log IP or the rate-limit key.*
//!
//! That makes this more than plumbing. The address decided here becomes
//!
//! - the **rate-limit key**, so getting it wrong either lets an attacker
//!   sidestep the limiter by sending a header, or lumps every customer behind
//!   one key and locks them all out together; and
//! - the **audit log's `ip=`**, which is the record of who did what.
//!
//! Two rules, both uvicorn's:
//!
//! 1. The header is honoured **only** when the connection itself comes from a
//!    trusted address. A request arriving straight from the Internet carries
//!    no weight no matter what it claims.
//! 2. The list is walked **from the right**, returning the first entry that is
//!    not itself a trusted proxy. Nginx appends the real peer, so the
//!    rightmost untrusted entry is the earliest address we have any reason to
//!    believe. Taking the *leftmost* - the obvious reading of "the client" -
//!    would take whatever the caller wrote there, which is the spoof this
//!    design exists to prevent.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::request::Parts;

/// Source: `TRUSTED_FORWARDERS` in `serve.py`.
pub const TRUSTED_FORWARDERS: &[&str] = &["127.0.0.1"];

/// The address Python's `request.client.host` would hold.
///
/// `None` is Python's `None`, which happens when every entry in the header is
/// itself a trusted proxy. It is not the same as "no client": the rate limiter
/// renders it into a key as the string `None` (an f-string does that silently)
/// while the audit log treats it as empty and omits the `ip=` field. Both
/// behaviours are reproduced by the callers rather than smoothed over here.
pub fn client_host(parts: &Parts) -> Option<String> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());

    let peer_trusted = peer
        .as_deref()
        .is_some_and(|p| TRUSTED_FORWARDERS.contains(&p));
    if !peer_trusted {
        // Untrusted peer: the header is ignored entirely.
        return peer;
    }

    let forwarded = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    let Some(forwarded) = forwarded else {
        return peer;
    };

    let hosts: Vec<&str> = forwarded.split(',').map(str::trim).collect();
    trusted_client_host(&hosts)
}

/// Source: `ProxyHeadersMiddleware.get_trusted_client_host`, with a fixed
/// (non-wildcard) trusted list.
fn trusted_client_host(hosts: &[&str]) -> Option<String> {
    hosts
        .iter()
        .rev()
        .find(|h| !TRUSTED_FORWARDERS.contains(*h))
        .map(|h| h.to_string())
}

/// The rate limiter's key. Source: `_client_key`, including the fact that a
/// `None` host is formatted into the key as the literal text `None`.
pub fn rate_limit_key(parts: &Parts) -> String {
    match parts.extensions.get::<ConnectInfo<SocketAddr>>() {
        // `request.client` is present for every TCP connection, so the
        // "unknown" branch is only reached when there is no peer at all.
        Some(_) => client_host(parts).unwrap_or_else(|| "None".to_string()),
        None => "unknown".to_string(),
    }
}

/// The audit log's `ip=`. Source: `log_action`, where a `None` host is falsy
/// and the field is left out.
pub fn audit_ip(parts: &Parts) -> String {
    client_host(parts).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts_from(peer: Option<&str>, forwarded: Option<&str>) -> Parts {
        let mut builder = Request::builder().uri("/api/auth/login");
        if let Some(f) = forwarded {
            builder = builder.header("x-forwarded-for", f);
        }
        let mut parts = builder.body(()).unwrap().into_parts().0;
        if let Some(p) = peer {
            let addr: SocketAddr = format!("{p}:40000").parse().unwrap();
            parts.extensions.insert(ConnectInfo(addr));
        }
        parts
    }

    #[test]
    fn a_header_from_an_untrusted_peer_is_ignored() {
        // The whole point: a request straight off the Internet cannot choose
        // its own rate-limit key or forge the audit trail.
        let parts = parts_from(Some("203.0.113.9"), Some("1.2.3.4"));
        assert_eq!(client_host(&parts).as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn the_local_nginx_is_believed() {
        let parts = parts_from(Some("127.0.0.1"), Some("203.0.113.9"));
        assert_eq!(client_host(&parts).as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn a_forged_prefix_does_not_win_because_the_list_is_read_from_the_right() {
        // The attacker sends "1.2.3.4"; nginx appends the real peer. Reading
        // from the left would trust the attacker's value.
        let parts = parts_from(Some("127.0.0.1"), Some("1.2.3.4, 203.0.113.9"));
        assert_eq!(client_host(&parts).as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn a_chain_of_trusted_proxies_resolves_to_nothing() {
        // Python's get_trusted_client_host returns None here, and the key
        // becomes the literal string "None" while the audit log omits the IP.
        let parts = parts_from(Some("127.0.0.1"), Some("127.0.0.1, 127.0.0.1"));
        assert_eq!(client_host(&parts), None);
        assert_eq!(rate_limit_key(&parts), "None");
        assert_eq!(audit_ip(&parts), "");
    }

    #[test]
    fn no_header_falls_back_to_the_peer() {
        let parts = parts_from(Some("127.0.0.1"), None);
        assert_eq!(client_host(&parts).as_deref(), Some("127.0.0.1"));
        assert_eq!(rate_limit_key(&parts), "127.0.0.1");
    }

    #[test]
    fn no_peer_at_all_is_unknown() {
        let parts = parts_from(None, Some("1.2.3.4"));
        assert_eq!(rate_limit_key(&parts), "unknown");
    }

    #[test]
    fn whitespace_around_the_entries_is_trimmed() {
        let parts = parts_from(Some("127.0.0.1"), Some("  203.0.113.9  "));
        assert_eq!(client_host(&parts).as_deref(), Some("203.0.113.9"));
    }
}
