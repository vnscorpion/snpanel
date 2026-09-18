//! `ops::system` - driving systemd units.
//!
//! Source: the `systemctl` and `daemon-reload` arms of the bash helper.
//!
//! The allowlist itself now lives in the type ([`ServiceName`]), so by the
//! time a request reaches here the unit name has already been checked. What is
//! left is the part that cannot be expressed in a type: whether a
//! dynamically-named `phpX.Y-fpm` actually exists on this box, and the refusal
//! to stop the panel's own services.

use std::path::Path;

use snpanel_ipc::{HelperErrorKind, HelperResponse, ServiceAction, ServiceName};

use crate::exec;

pub fn service_control(service: &ServiceName, action: ServiceAction) -> HelperResponse {
    // Source: the explicit refusal in the bash. Stopping snpanel-api from the
    // panel removes the only means of starting it again.
    if matches!(action, ServiceAction::Stop) && !service.may_stop() {
        return HelperResponse::failed(
            HelperErrorKind::NotAuthorised,
            format!("refusing to stop panel-critical service: {service}"),
        );
    }

    // Source: `is_allowed_service` - a phpX.Y-fpm name is accepted only if its
    // pool config is present.
    if service.is_php_fpm() {
        if let Some(version) = service.php_version() {
            let conf = format!("/etc/php/{version}/fpm/php-fpm.conf");
            if !Path::new(&conf).exists() {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    format!("service not allowed: {service} (no {conf})"),
                );
            }
        }
    }

    let verb = match action {
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Restart => "restart",
        ServiceAction::Reload => "reload",
        ServiceAction::Status => "is-active",
    };

    let out = exec::run(&["systemctl", verb, service.as_str()]);

    // `is-active` exits non-zero for an inactive unit. That is information,
    // not a failure - the bash returns the word and lets the caller decide.
    if matches!(action, ServiceAction::Status) {
        return match out {
            Ok(o) => HelperResponse::with_stdout(o.stdout),
            Err(e) => HelperResponse::failed(HelperErrorKind::Internal, e.to_string()),
        };
    }

    exec::respond(&format!("systemctl {verb} {service}"), out)
}

pub fn daemon_reload() -> HelperResponse {
    exec::respond(
        "systemctl daemon-reload",
        exec::run(&["systemctl", "daemon-reload"]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopping_the_panel_is_refused() {
        for critical in ["snpanel-api", "redis-server"] {
            let svc = ServiceName::parse(critical).unwrap();
            let r = service_control(&svc, ServiceAction::Stop);
            assert!(!r.ok, "{critical}");
            assert_eq!(r.error.unwrap().kind, HelperErrorKind::NotAuthorised);
        }
    }

    #[test]
    fn restarting_the_panel_is_allowed() {
        // Only *stop* is refused; restart has to work or the panel could never
        // apply its own updates.
        let svc = ServiceName::parse("snpanel-api").unwrap();
        let r = service_control(&svc, ServiceAction::Stop);
        assert!(!r.ok);
        // Not asserting on the restart result: there is no snpanel-api here.
        // The point is that it is not refused up front.
        let r = service_control(&svc, ServiceAction::Restart);
        assert!(
            r.error.as_ref().map(|e| e.kind) != Some(HelperErrorKind::NotAuthorised),
            "restart must not be refused by policy"
        );
    }

    #[test]
    fn an_absent_php_pool_is_not_found_rather_than_attempted() {
        let svc = ServiceName::parse("php5.6-fpm").unwrap();
        let r = service_control(&svc, ServiceAction::Reload);
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().kind, HelperErrorKind::NotFound);
    }

    #[test]
    fn status_reports_state_rather_than_failing() {
        // A unit that does not exist is "inactive"/"unknown", which is an
        // answer, not an error the caller should see as a fault.
        let svc = ServiceName::parse("nginx").unwrap();
        let r = service_control(&svc, ServiceAction::Status);
        assert!(r.ok, "is-active must report, not fail");
    }
}
