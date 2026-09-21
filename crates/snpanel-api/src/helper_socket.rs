//! The socket transport to the privileged helper.
//!
//! Plan §4.2 and §9.2. The panel has always reached the helper by running
//! `sudo -n /usr/local/sbin/snpanel-helper <verb> <args>`, and sudo plus a
//! verb allowlist was the whole of the boundary. This sends the same call
//! over a Unix socket instead, where the kernel answers "who is connected"
//! through `SO_PEERCRED` and the caller cannot lie about it.
//!
//! Three rules hold this together, and the second is the one worth reading
//! twice.
//!
//! **A verb this build does not map falls through to sudo, which reaches the
//! bash helper.** That is the cutover: domains land one at a time on machines
//! already serving customers.
//!
//! **A refusal is an answer, not a failure.** If the helper replies at all -
//! ok or not, including "you are not authorised" - that reply is returned. It
//! is never retried through sudo. Retrying it would mean the one check this
//! transport exists to add could be got around by failing it.
//!
//! **A transport fault falls back.** No socket, a connection refused, a short
//! read: the panel goes back to sudo rather than showing a customer an error,
//! because a helper that is not listening is an operational problem and not a
//! security one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use snpanel_ipc::{Envelope, HelperErrorKind, HelperRequest, HelperResponse, SOCKET_PATH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// How long to wait for the helper, end to end.
///
/// Long, because the operations behind it are long: `certbot-issue` talks to
/// Let's Encrypt and `site-app-import` unpacks a customer's backup. Not
/// unbounded, because a wedged helper must not hold an axum worker forever.
const TIMEOUT: Duration = Duration::from_secs(900);

/// Where the helper listens.
///
/// `SNPANEL_HELPER_SOCKET` overrides it, for an administrator running a
/// second helper on a scratch path and for the tests. It changes only where
/// the panel connects; `SO_PEERCRED` still decides who may talk, so an
/// override cannot be used to get around authorisation.
pub fn socket_path() -> PathBuf {
    std::env::var_os("SNPANEL_HELPER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SOCKET_PATH))
}

/// Whether the socket is there at all.
pub fn available() -> bool {
    Path::new(&socket_path()).exists()
}

/// Which verbs this installation sends over the socket.
///
/// Unset means every verb the mapping answers, which is the end state. A
/// comma-separated list narrows it, and an entry ending in `*` matches a
/// prefix - so `SNPANEL_HELPER_VERBS=site-*,wp,wp-site` is a first deployment
/// that moves the site domain and leaves everything else on the path it has
/// been using. This is the per-verb cutover the plan asks for, and it is an
/// environment variable rather than a rebuild because the machine it has to
/// be reversible on is one already serving customers.
pub fn verb_enabled(verb: &str) -> bool {
    let Some(list) = std::env::var_os("SNPANEL_HELPER_VERBS") else {
        return true;
    };
    let list = list.to_string_lossy().into_owned();
    if list.trim().is_empty() {
        return true;
    }
    list.split(',')
        .map(str::trim)
        .any(|entry| match entry.strip_suffix('*') {
            Some(prefix) => verb.starts_with(prefix),
            None => entry == verb,
        })
}

/// What went wrong with the transport itself.
///
/// Every variant here means "the helper did not answer", which is why they
/// share one fate: fall back to sudo. A helper that answered - with anything
/// at all - does not produce one of these.
#[derive(Debug)]
pub enum TransportError {
    NoSocket,
    Connect(std::io::Error),
    Write(std::io::Error),
    Read(std::io::Error),
    Timeout,
    /// The helper answered with something that is not a response. Treated as
    /// a transport fault because a reply that cannot be parsed carries no
    /// decision to honour.
    Malformed(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSocket => write!(f, "the helper socket is not present"),
            Self::Connect(e) => write!(f, "cannot connect to the helper: {e}"),
            Self::Write(e) => write!(f, "cannot send to the helper: {e}"),
            Self::Read(e) => write!(f, "cannot read from the helper: {e}"),
            Self::Timeout => {
                write!(f, "the helper did not answer within {}s", TIMEOUT.as_secs())
            }
            Self::Malformed(e) => write!(f, "the helper sent a malformed reply: {e}"),
        }
    }
}

/// Send one request and read the one-line reply.
pub async fn call(request: &HelperRequest) -> Result<HelperResponse, TransportError> {
    call_at(&socket_path(), request).await
}

/// The same, against a named socket.
///
/// Split out so a test can point at a path that is not there without setting
/// a process-wide environment variable and then holding a lock across an
/// await to keep it still.
pub async fn call_at(
    path: &Path,
    request: &HelperRequest,
) -> Result<HelperResponse, TransportError> {
    if !path.exists() {
        return Err(TransportError::NoSocket);
    }

    let mut line = match serde_json::to_vec(&Envelope::new(request.clone())) {
        Ok(bytes) => bytes,
        Err(e) => return Err(TransportError::Malformed(e.to_string())),
    };
    line.push(b'\n');

    let work = async {
        let mut stream = UnixStream::connect(path)
            .await
            .map_err(TransportError::Connect)?;
        stream
            .write_all(&line)
            .await
            .map_err(TransportError::Write)?;
        stream.flush().await.map_err(TransportError::Write)?;

        let mut reply = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut reply)
            .await
            .map_err(TransportError::Read)?;
        if reply.trim().is_empty() {
            return Err(TransportError::Read(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the helper closed the connection without replying",
            )));
        }
        serde_json::from_str::<HelperResponse>(&reply)
            .map_err(|e| TransportError::Malformed(e.to_string()))
    };

    match tokio::time::timeout(TIMEOUT, work).await {
        Ok(result) => result,
        Err(_) => Err(TransportError::Timeout),
    }
}

/// Whether the helper answered "I have no implementation for this".
///
/// This is the one response that is allowed to fall through to sudo, and it
/// is worth being precise about why that is not a hole in the rule that a
/// refusal is never retried.
///
/// `NotImplemented` is produced in exactly one place: the catch-all of the
/// dispatch table, reached when a request's enum variant has no arm. By then
/// the request has already been parsed and every value in it accepted. The
/// helper is not deciding about the call; it is saying which implementation
/// serves it, and today that is still `snpanel-helper.sh`. Nothing a caller
/// can put in a request turns a `NotAuthorised` or a `BadRequest` into this.
pub fn not_implemented(response: &HelperResponse) -> bool {
    matches!(&response.error, Some(e) if e.kind == HelperErrorKind::NotImplemented)
}

/// The exit status a command-line caller would have seen.
///
/// The panel's call sites read `returncode`, because that is what running the
/// bash helper gave them. A refusal is 2, which is what the bash's `deny`
/// exits with, so a caller that distinguishes "refused" from "failed" keeps
/// working across the transport change.
pub fn returncode_of(response: &HelperResponse) -> i32 {
    // A verb that ran a command on the caller's behalf reports the command's
    // status. `terminal-exec` is the only one: `grep` that matches nothing
    // exits 1 and must not reach the customer as "refused".
    if let Some(code) = response.exit_code {
        return code;
    }
    response.exit_status()
}

/// What a refused or failed response says, in the field the panel reads.
pub fn stderr_of(response: &HelperResponse) -> String {
    if !response.stderr.is_empty() {
        return response.stderr.clone();
    }
    match &response.error {
        Some(error) => error.message.clone(),
        None if response.ok => String::new(),
        None => "the helper refused the operation".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_verbs<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let _guard = crate::testenv::lock();
        let previous = std::env::var_os("SNPANEL_HELPER_VERBS");
        match value {
            Some(v) => std::env::set_var("SNPANEL_HELPER_VERBS", v),
            None => std::env::remove_var("SNPANEL_HELPER_VERBS"),
        }
        let out = body();
        match previous {
            Some(v) => std::env::set_var("SNPANEL_HELPER_VERBS", v),
            None => std::env::remove_var("SNPANEL_HELPER_VERBS"),
        }
        out
    }

    #[test]
    fn with_no_list_every_mapped_verb_goes_over_the_socket() {
        with_verbs(None, || {
            assert!(verb_enabled("site-app-control"));
            assert!(verb_enabled("firewall-apply"));
        });
    }

    #[test]
    fn an_empty_list_is_not_read_as_an_empty_allowlist() {
        // A variable set to nothing is far more likely to be a deployment
        // accident than an instruction to route nothing, and reading it as
        // "no verbs" would silently undo the cutover on the next restart.
        with_verbs(Some("   "), || assert!(verb_enabled("site-app-control")));
    }

    #[test]
    fn a_prefix_moves_one_domain_and_leaves_the_rest() {
        with_verbs(Some("site-*,wp,wp-site"), || {
            assert!(verb_enabled("site-app-control"));
            assert!(verb_enabled("site-runtime-ensure"));
            assert!(verb_enabled("wp"));
            assert!(!verb_enabled("firewall-apply"));
            assert!(!verb_enabled("certbot-issue"));
        });
    }

    #[test]
    fn an_exact_entry_does_not_match_a_longer_verb() {
        with_verbs(Some("wp"), || {
            assert!(verb_enabled("wp"));
            assert!(!verb_enabled("wp-site"));
        });
    }

    /// 1, which is what the bash's `deny` exits with.
    ///
    /// This asserted 2 until the installed helper was asked: a bad domain, a
    /// wrong argument count and an unknown verb all exit 1, and only the
    /// `SUDO_USER` guard exits 2.
    #[test]
    fn a_refusal_reads_as_the_exit_code_the_bash_used() {
        let refused = HelperResponse {
            ok: false,
            stdout: String::new(),
            stderr: "not allowed".into(),
            data: None,
            error: None,
            exit_code: None,
        };
        assert_eq!(returncode_of(&refused), 1);
        assert_eq!(stderr_of(&refused), "not allowed");
        assert_eq!(returncode_of(&HelperResponse::ok()), 0);
    }

    #[test]
    fn a_refusal_with_no_stderr_still_says_something() {
        let refused = HelperResponse {
            ok: false,
            stdout: String::new(),
            stderr: String::new(),
            data: None,
            error: None,
            exit_code: None,
        };
        assert!(!stderr_of(&refused).is_empty());
    }

    #[tokio::test]
    async fn an_absent_socket_is_a_transport_fault_so_the_caller_falls_back() {
        // Which is what makes the panel fall back to sudo instead of showing
        // a customer an error because a unit is not running.
        let result = call_at(
            Path::new("/nonexistent/snpanel-helper.sock"),
            &HelperRequest::NginxTest,
        )
        .await;
        assert!(
            matches!(result, Err(TransportError::NoSocket)),
            "{result:?}"
        );
    }
}
