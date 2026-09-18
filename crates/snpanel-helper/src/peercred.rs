//! Who is on the other end of the socket.
//!
//! This replaces the bash helper's first line of defence:
//!
//! ```bash
//! if [[ "${SUDO_USER:-}" != "snpanel" ]]; then
//! ```
//!
//! That check trusts an environment variable. It is sound only because sudo is
//! the thing that sets it and the sudoers file is narrow - but it is a string
//! the caller's environment carries, and the helper has no way to tell a real
//! sudo invocation from a process that simply exported `SUDO_USER=snpanel` and
//! happened to already be root.
//!
//! `SO_PEERCRED` is answered by the kernel about the process on the other end
//! of the connection. It cannot be set, spoofed or inherited. That is what
//! plan §4.2 means by "chặt hơn sudoers allowlist".

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// The unprivileged account the API runs as.
pub const PANEL_USER: &str = "snpanel";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum PeerCredError {
    #[error("cannot read peer credentials: {0}")]
    Unavailable(String),
    #[error("user '{0}' does not exist on this system")]
    NoSuchUser(String),
    #[error("caller uid {got} is not the panel user (uid {expected})")]
    WrongUser { got: u32, expected: u32 },
}

/// Ask the kernel who the peer is.
pub fn peer_of(stream: &UnixStream) -> Result<PeerCred, PeerCredError> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: `cred` is a correctly sized, correctly aligned ucred, `len`
    // matches it, and the fd is owned by the live `stream` borrow.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(PeerCredError::Unavailable(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(PeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Resolve a username to a uid via NSS.
pub fn uid_of(username: &str) -> Result<u32, PeerCredError> {
    let c_name = std::ffi::CString::new(username)
        .map_err(|_| PeerCredError::NoSuchUser(username.to_string()))?;
    // SAFETY: `getpwnam` takes a NUL-terminated string and returns a pointer
    // into a static buffer, which is read before any further libc call.
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return Err(PeerCredError::NoSuchUser(username.to_string()));
    }
    // SAFETY: non-null, and `pw_uid` is a plain field.
    Ok(unsafe { (*pw).pw_uid })
}

/// The authorisation decision.
///
/// root is accepted alongside the panel user so an administrator can drive the
/// socket by hand while debugging - the same latitude the bash has, where root
/// can always run the script directly.
pub fn authorise(peer: PeerCred, panel_uid: u32) -> Result<(), PeerCredError> {
    if peer.uid == panel_uid || peer.uid == 0 {
        Ok(())
    } else {
        Err(PeerCredError::WrongUser {
            got: peer.uid,
            expected: panel_uid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_the_panel_user_are_accepted() {
        let panel_uid = 1001;
        assert!(authorise(
            PeerCred {
                pid: 1,
                uid: panel_uid,
                gid: 1001
            },
            panel_uid
        )
        .is_ok());
        assert!(authorise(
            PeerCred {
                pid: 1,
                uid: 0,
                gid: 0
            },
            panel_uid
        )
        .is_ok());
    }

    #[test]
    fn anyone_else_is_refused() {
        let panel_uid = 1001;
        // The exact case the socket exists to stop: a compromised site's PHP
        // pool, running as its own user, opening the helper socket.
        for uid in [33, 1000, 1002, 65534] {
            let err = authorise(
                PeerCred {
                    pid: 42,
                    uid,
                    gid: uid,
                },
                panel_uid,
            )
            .unwrap_err();
            assert!(matches!(err, PeerCredError::WrongUser { .. }), "uid {uid}");
        }
    }

    #[test]
    fn peer_credentials_come_from_the_kernel_not_the_message() {
        // A socketpair stands in for a connection; both ends are this process,
        // so the kernel must report this process's own identity.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let peer = peer_of(&a).expect("SO_PEERCRED is supported on Linux");
        // SAFETY: getuid/getpid cannot fail.
        let (me, my_pid) = unsafe { (libc::getuid(), libc::getpid()) };
        assert_eq!(peer.uid, me);
        assert_eq!(peer.pid, my_pid);
    }

    #[test]
    fn root_resolves() {
        assert_eq!(uid_of("root").unwrap(), 0);
    }

    #[test]
    fn an_unknown_user_is_an_error_not_a_zero() {
        // Falling back to 0 here would authorise everyone.
        assert!(matches!(
            uid_of("definitely-not-a-real-account-xyzzy"),
            Err(PeerCredError::NoSuchUser(_))
        ));
    }
}
