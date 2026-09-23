//! What the rescue menu reports, and the order it restarts things in.
//!
//! Source: `show_status`, `print_other_panel_urls`, `show_login_info`,
//! `restart_panel_command`, `show_logs`, `repair_firewall`.
//!
//! Everything here is read by somebody whose panel is not working. That
//! shapes it more than it looks: a status line that says "failed" without
//! saying why sends them to the logs, and a status line that says "ok" when
//! it is not sends them somewhere worse.

/// Which scheme the panel is answering on.
///
/// Configured **and present**: a `PANEL_SSL_CERT` pointing at a file that is
/// gone means the panel is not serving TLS, whatever the `.env` says, and a
/// health check that asked over HTTPS would report the panel down when it is
/// up.
///
/// Note this is a looser rule than the one that decides whether to *keep*
/// HTTPS when the address moves ([`super::panel_url::keeps_https`]), which
/// also requires the domain to be unchanged. That is right: this one is
/// asking what is true now, not what should be true next.
pub fn scheme(cert: &str, key: &str, cert_exists: bool, key_exists: bool) -> &'static str {
    if !cert.is_empty() && !key.is_empty() && cert_exists && key_exists {
        "https"
    } else {
        "http"
    }
}

pub fn health_url(scheme: &str, port: u16) -> String {
    format!("{scheme}://127.0.0.1:{port}/api/health")
}

/// The health line.
///
/// A failure carries **both** curl's exit code and the HTTP status, plus
/// whatever curl said on stderr. That is three pieces of information for one
/// line, and each answers a different question: exit 7 is "nothing is
/// listening", exit 0 with 502 is "nginx is up and the API is not", and the
/// stderr text is what distinguishes a TLS failure from a refused
/// connection.
pub fn health(curl_available: bool, exit_code: i32, http_code: &str, stderr: &str) -> String {
    if !curl_available {
        return "unknown (curl not found)".to_string();
    }
    if exit_code == 0 && http_code == "200" {
        return "ok (HTTP 200)".to_string();
    }
    // `tr '\n' ' '` then strip trailing whitespace — a multi-line curl error
    // must not break the one-line-per-fact shape of this report.
    let flattened = stderr.replace('\n', " ");
    let trimmed = flattened.trim_end();
    let code = if http_code.is_empty() {
        "000"
    } else {
        http_code
    };
    if trimmed.is_empty() {
        format!("failed (curl={exit_code}, http={code})")
    } else {
        format!("failed (curl={exit_code}, http={code}, {trimmed})")
    }
}

/// Services whose state is reported, in the order they are listed.
pub const REPORTED: &[&str] = &["snpanel-api", "nginx", "mariadb", "redis-server"];

/// `systemctl is-active` with a fallback.
///
/// A unit systemd has never heard of prints nothing and exits non-zero, and
/// an empty field in a status report reads as a bug in the report. `unknown`
/// is the honest answer and it is visibly not `active`.
pub fn is_active(output: Option<&str>) -> &str {
    match output {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => "unknown",
    }
}

/// The order services are restarted in.
///
/// **Not alphabetical, and not arbitrary.** The API opens a database
/// connection and a Redis connection as it starts, so it goes last — started
/// first it would come up, fail both, and sit there in a failed state while
/// the things it needed started behind it. nginx before the API for the same
/// reason in reverse: it is the one that answers while the API restarts.
pub const RESTART_ORDER: &[&str] = &["mariadb", "redis-server", "nginx", "snpanel-api"];

/// What `show_login_info` says when `/root/login.txt` is gone.
///
/// It says *why*, which matters: an operator who is told only "not
/// available" will look for the file, and the file is not the problem. The
/// password is not recoverable from the panel's database because what is
/// stored there is a hash, and the useful next step is to set a new one.
pub const NO_LOGIN_FILE: &str = "Password: <not available; run snpanel change-admin-password>";
pub const NO_LOGIN_REASON: &str =
    "Note: /root/login.txt is missing and database password hashes cannot be reversed.";

/// How much of each log is shown.
///
/// The API's journal gets the most, because it is the one that usually has
/// the answer; nginx's error log and the update log get enough to see the
/// last failure without filling the terminal.
pub const API_JOURNAL_LINES: u32 = 120;
pub const NGINX_LOG_LINES: u32 = 80;
pub const UPDATE_LOG_LINES: u32 = 80;

/// Whether an SSH port needs allowing during a firewall repair.
///
/// Port 22 is skipped because the rebuilt chain always includes it — it is
/// one of the protected ports in `rules.tsv`. Adding it again would leave a
/// duplicate rule that the panel then shows to the operator as something
/// they created.
pub fn needs_allowing(ssh_port: &str) -> bool {
    !ssh_port.is_empty() && ssh_port != "22"
}

/// The line printed when the repair cannot reach far enough.
///
/// A menu that only said "refreshed" would leave somebody locked out with no
/// idea what to try next; the rescue script runs outside the panel
/// entirely.
pub const RESCUE_HINT: &str = "If the server is still unreachable, run: snpanel-rescue-firewall";

#[cfg(test)]
mod tests {
    use super::*;

    /// A `PANEL_SSL_CERT` pointing at a file that is gone means the panel is
    /// not serving TLS, whatever the `.env` says — and a health check that
    /// asked over HTTPS would report the panel down when it is up.
    #[test]
    fn the_scheme_is_what_is_true_now_and_not_what_was_configured() {
        assert_eq!(scheme("/c", "/k", true, true), "https");
        assert_eq!(scheme("/c", "/k", false, true), "http");
        assert_eq!(scheme("/c", "/k", true, false), "http");
        assert_eq!(scheme("", "/k", true, true), "http");
        assert_eq!(scheme("/c", "", true, true), "http");
        assert_eq!(scheme("", "", false, false), "http");
    }

    #[test]
    fn the_health_check_asks_over_loopback() {
        assert_eq!(
            health_url("https", 2222),
            "https://127.0.0.1:2222/api/health"
        );
        assert_eq!(health_url("http", 8443), "http://127.0.0.1:8443/api/health");
    }

    #[test]
    fn a_healthy_panel_says_so_plainly() {
        assert_eq!(health(true, 0, "200", ""), "ok (HTTP 200)");
    }

    /// Three pieces of information, each answering a different question:
    /// exit 7 is "nothing is listening", exit 0 with 502 is "nginx is up and
    /// the API is not", and the stderr text distinguishes a TLS failure from
    /// a refused connection.
    #[test]
    fn a_failure_carries_both_codes_and_the_reason() {
        assert_eq!(
            health(true, 7, "000", "curl: (7) Failed to connect"),
            "failed (curl=7, http=000, curl: (7) Failed to connect)"
        );
        assert_eq!(health(true, 0, "502", ""), "failed (curl=0, http=502)");
    }

    /// An empty HTTP code is `000` rather than blank: a report field that is
    /// sometimes empty reads as a bug in the report.
    #[test]
    fn an_absent_http_code_is_shown_as_zero() {
        assert_eq!(
            health(true, 7, "", "boom"),
            "failed (curl=7, http=000, boom)"
        );
    }

    /// A multi-line curl error must not break the one-line-per-fact shape of
    /// the report.
    #[test]
    fn a_multi_line_error_is_flattened() {
        let out = health(true, 60, "000", "curl: (60) SSL error\nMore detail here\n");
        assert!(!out.contains('\n'), "{out}");
        assert_eq!(
            out,
            "failed (curl=60, http=000, curl: (60) SSL error More detail here)"
        );
    }

    /// Reporting "failed" on a box that simply has no curl would send
    /// somebody looking for a panel outage that is not happening.
    #[test]
    fn a_box_without_curl_says_unknown_rather_than_failed() {
        let out = health(false, 0, "", "");
        assert_eq!(out, "unknown (curl not found)");
        assert!(!out.contains("failed"));
    }

    /// An empty field in a status report reads as a bug in the report.
    #[test]
    fn a_unit_systemd_does_not_know_is_reported_as_unknown() {
        assert_eq!(is_active(Some("active")), "active");
        assert_eq!(is_active(Some("failed")), "failed");
        assert_eq!(is_active(Some("active\n")), "active");
        assert_eq!(is_active(Some("")), "unknown");
        assert_eq!(is_active(Some("  \n")), "unknown");
        assert_eq!(is_active(None), "unknown");
    }

    /// **Not alphabetical, and not arbitrary.** The API opens a database and
    /// a Redis connection as it starts; started first it would come up, fail
    /// both, and sit in a failed state while the things it needed started
    /// behind it.
    #[test]
    fn the_api_is_restarted_after_what_it_depends_on() {
        let api = RESTART_ORDER
            .iter()
            .position(|s| *s == "snpanel-api")
            .expect("the api");
        for dependency in ["mariadb", "redis-server", "nginx"] {
            let at = RESTART_ORDER
                .iter()
                .position(|s| *s == dependency)
                .unwrap_or_else(|| panic!("{dependency}"));
            assert!(at < api, "{dependency} restarts after the API");
        }
        assert_eq!(*RESTART_ORDER.last().unwrap(), "snpanel-api");
    }

    /// An operator told only "not available" will look for the file, and the
    /// file is not the problem.
    #[test]
    fn a_missing_login_file_explains_itself() {
        assert!(NO_LOGIN_FILE.contains("change-admin-password"));
        assert!(NO_LOGIN_REASON.contains("cannot be reversed"));
    }

    /// The journal usually has the answer, so it gets the most lines.
    #[test]
    fn the_api_journal_is_the_longest_of_the_three() {
        const { assert!(API_JOURNAL_LINES > NGINX_LOG_LINES) };
        assert_eq!(UPDATE_LOG_LINES, NGINX_LOG_LINES);
    }

    /// The rebuilt chain always includes 22, so allowing it again would
    /// leave a duplicate rule that the panel then shows to the operator as
    /// something they created.
    #[test]
    fn port_twenty_two_is_not_added_again() {
        assert!(!needs_allowing("22"));
        assert!(needs_allowing("2222"));
        assert!(!needs_allowing(""));
    }

    /// A menu that only said "refreshed" would leave somebody locked out
    /// with no idea what to try next.
    #[test]
    fn the_repair_names_the_thing_to_try_next() {
        assert!(RESCUE_HINT.contains("snpanel-rescue-firewall"));
    }

    #[test]
    fn every_service_that_is_restarted_is_also_reported() {
        for service in RESTART_ORDER {
            assert!(REPORTED.contains(service), "{service} is restarted unseen");
        }
    }
}
