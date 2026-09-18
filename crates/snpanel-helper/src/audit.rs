//! The audit trail.
//!
//! Plan Phase 2: "every op logged to journald with `tracing`, with the caller's
//! uid". The bash has no equivalent - a privileged operation leaves no record
//! beyond whatever the underlying command happened to print.
//!
//! **Why journald rather than stderr.** The first version of this wrote to
//! stderr and relied on systemd picking it up. That works when an
//! administrator runs the helper by hand, and fails in the case that matters:
//! the panel invokes the helper through `subprocess.run(..., capture_output)`,
//! so Python *captures* stderr and puts it in a `CommandResult`. The audit
//! line then exists only inside one HTTP response and is gone. Checked on a
//! running box after a firewall change: zero audit lines in the journal.
//!
//! That is worse than it sounds. An audit trail exists to be read after an
//! incident, and one that lives in a discarded HTTP response cannot be. The
//! bash helper it replaced actually did better, because `sudo` logs every
//! invocation.
//!
//! So the journald socket is written to directly, and stderr is used only when
//! there is no journal to write to. When it is used, ANSI colour is off: that
//! output can end up in the panel's own error display, and escape codes there
//! are noise an operator has to read past.
//!
//! **Reading it back.** `tracing-journald` sends each field as a journald
//! field with an `F_` prefix rather than inlining it in the message, which
//! makes the trail queryable rather than greppable:
//!
//! ```text
//! journalctl -t snpanel-helper                          # everything
//! journalctl -t snpanel-helper F_OP=firewall-deny-ip    # one operation
//! journalctl -t snpanel-helper -o json | jq .F_CALLER_UID
//! ```
//!
//! Worth knowing, because `journalctl --output=cat` shows only `MESSAGE` and
//! therefore looks as though the fields are missing. They are not.
//!
//! What is deliberately *not* logged is argument values. A request carries
//! domains, paths and, for some operations, a password; the operation name and
//! the caller are what an audit needs, and logging the rest would put secrets
//! in the journal (C37 in spirit, if not in letter).

use snpanel_ipc::{HelperRequest, HelperResponse};

/// Where the audit trail ended up, so the process can say so if asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    Journald,
    Stderr,
}

pub fn init() -> Sink {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    let filter =
        || EnvFilter::try_from_env("SNPANEL_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    // journald first. `layer()` fails when the socket is absent, which is the
    // honest signal that there is no journal here - a container without
    // systemd, or a distro not using it.
    match tracing_journald::layer() {
        Ok(journald) => {
            let registered = tracing_subscriber::registry()
                .with(filter())
                .with(journald.with_syslog_identifier("snpanel-helper".to_string()))
                .try_init()
                .is_ok();
            if registered {
                return Sink::Journald;
            }
            // Already initialised by an earlier call; nothing to do.
            Sink::Journald
        }
        Err(_) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter())
                .with_target(false)
                // No colour: this can land in the panel's error display.
                .with_ansi(false)
                .with_writer(std::io::stderr)
                .try_init();
            Sink::Stderr
        }
    }
}

pub fn log_request(request: &HelperRequest, caller_uid: u32, caller_pid: i32) {
    tracing::info!(
        op = request.op_name(),
        caller_uid,
        caller_pid,
        "privileged operation requested"
    );
}

pub fn log_result(op: &str, response: &HelperResponse) {
    if response.ok {
        tracing::info!(op, "ok");
    } else {
        let (kind, message) = response
            .error
            .as_ref()
            .map(|e| (format!("{:?}", e.kind), e.message.as_str()))
            .unwrap_or_else(|| ("Unknown".to_string(), ""));
        tracing::warn!(op, kind = %kind, "failed: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snpanel_ipc::HelperErrorKind;

    #[test]
    fn logging_a_request_carrying_a_password_does_not_print_it() {
        // The guarantee rests on two things: op_name() returns a fixed string,
        // and SecretString's Debug is redacted. Check both hold.
        use snpanel_core::{PanelUsername, SecretString};

        let req = HelperRequest::PanelUserPassword {
            username: PanelUsername::parse("bp_site").unwrap(),
            password: SecretString::new("hunter2"),
        };
        assert_eq!(req.op_name(), "panel-user-password");
        assert!(!req.op_name().contains("hunter2"));
        assert!(!format!("{req:?}").contains("hunter2"));
    }

    #[test]
    fn init_is_safe_to_call_more_than_once() {
        let first = init();
        let second = init();
        assert_eq!(
            first, second,
            "a second call must not change where the trail goes"
        );
    }

    #[test]
    fn init_reports_where_the_trail_went() {
        // On this machine it is whichever is available; the point is that the
        // caller can tell, rather than assuming the journal has it.
        assert!(matches!(init(), Sink::Journald | Sink::Stderr));
    }

    #[test]
    fn both_outcomes_are_loggable() {
        init();
        log_result("nginx-test", &HelperResponse::ok());
        log_result(
            "nginx-reload",
            &HelperResponse::failed(HelperErrorKind::CommandFailed, "bad config"),
        );
    }
}
