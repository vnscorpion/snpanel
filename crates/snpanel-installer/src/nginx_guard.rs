//! Stopping a stale ModSecurity module from taking nginx down.
//!
//! Source: `installer/files/nginx-module-guard-install.sh`.
//!
//! The module is built against one nginx version. When a package update
//! moves nginx to a different one, nginx cannot load it — and does not
//! merely lose the WAF, it **refuses to start**. On a box serving real sites
//! that is the whole web server gone, during a package update nobody was
//! watching.
//!
//! So a guard runs before nginx's own `-t` check. If the configuration is
//! broken *and* the breakage mentions the module, it moves the load
//! directive aside so nginx starts without the WAF, and says so loudly.
//! Degraded beats down.
//!
//! **The guard always exits zero**, on every path. An `ExecStartPre` that
//! fails prevents the start it exists to protect, so a guard that reported a
//! problem by failing would cause exactly the outage it was written to
//! avoid. That is a property of the shell script rather than of anything
//! here, which is why it is stated and not asserted: there is nothing in
//! this module that could return a failure for a test to catch.

/// Where the guard is installed, and the module configuration it watches.
pub const GUARD: &str = "/usr/local/sbin/snpanel-nginx-module-guard";
pub const GUARD_MODE: u32 = 0o755;
pub const MODULE_CONF: &str = "/usr/share/nginx/modules/50-mod-http-modsecurity.conf";

/// The suffix the disabled file takes.
///
/// Moved rather than deleted, and named for what did it: an operator finding
/// a `.disabled-by-snpanel` file knows both what happened and how to undo
/// it. A deletion would leave them with a missing file and no explanation.
pub const DISABLED_SUFFIX: &str = ".disabled-by-snpanel";

pub fn disabled_path() -> String {
    format!("{MODULE_CONF}{DISABLED_SUFFIX}")
}

/// What the guard decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No module configuration, or nginx is happy. Do nothing.
    Nothing,
    /// nginx is unhappy **and** the complaint names the module.
    DisableModule,
}

/// The decision.
///
/// Both conditions are required, and the second is what keeps this narrow: a
/// configuration broken by a customer's bad vhost also fails `nginx -t`, and
/// disabling the WAF would not fix it — it would silently drop a security
/// control while leaving nginx just as broken.
pub fn decide(module_conf_present: bool, nginx_t_ok: bool, nginx_t_output: &str) -> Action {
    if !module_conf_present || nginx_t_ok {
        return Action::Nothing;
    }
    if mentions_module(nginx_t_output) {
        Action::DisableModule
    } else {
        Action::Nothing
    }
}

/// `grep -qi 'modsecurity'`.
pub fn mentions_module(output: &str) -> bool {
    let needle = b"modsecurity";
    output
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// The message, which names the version to rebuild against.
///
/// "Rebuild it" without saying against what leaves the operator to work out
/// which nginx they are now on — which is the fact that changed and the only
/// one they need.
pub fn message(nginx_version: &str) -> String {
    format!(
        "SNPanel: nginx could not load the ModSecurity module, so it was disabled to let nginx \
         start. Rebuild it against nginx {nginx_version} to restore the WAF."
    )
}

/// `nginx -v` prints `nginx version: nginx/1.26.2` on stderr.
pub fn version_from_banner(banner: &str) -> &str {
    banner.trim().rsplit('/').next().unwrap_or("").trim()
}

/// The drop-in that puts the guard ahead of nginx's own check.
///
/// The distribution's unit runs `nginx -t` as its own `ExecStartPre`, and a
/// failing one stops the start — so the guard has to run first. Systemd
/// accumulates `ExecStartPre` entries in order and gives no way to insert
/// one at the front, so the list is **reset and restated**.
///
/// The two lines after the guard are nginx.service's own as shipped on EL10.
/// If the distribution changes them this drop-in has to be revisited, which
/// the shell says in a comment and this says in a test.
pub const DROPIN: &str = "/etc/systemd/system/nginx.service.d/10-snpanel-module-guard.conf";

pub fn exec_start_pre() -> Vec<&'static str> {
    vec![
        // The reset. Without it the guard is appended after the `nginx -t`
        // it is supposed to precede, and does nothing at all.
        "",
        GUARD,
        "/usr/bin/rm -f /run/nginx.pid",
        "/usr/sbin/nginx -t",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both conditions are required. A configuration broken by a customer's
    /// bad vhost also fails `nginx -t`, and disabling the WAF would not fix
    /// it — it would silently drop a security control while leaving nginx
    /// just as broken.
    #[test]
    fn an_unrelated_configuration_error_does_not_disable_the_waf() {
        let unrelated = "nginx: [emerg] invalid parameter \"foo\" in /etc/nginx/conf.d/a.conf:12";
        assert_eq!(decide(true, false, unrelated), Action::Nothing);
    }

    /// And when the complaint does name the module, it goes.
    #[test]
    fn a_module_that_cannot_load_is_disabled() {
        let complaint = "nginx: [emerg] dlopen() \"/usr/share/nginx/modules/ngx_http_modsecurity_module.so\" failed";
        assert_eq!(decide(true, false, complaint), Action::DisableModule);
    }

    /// A healthy nginx is left entirely alone, whatever else is true.
    #[test]
    fn a_working_nginx_is_never_touched() {
        assert_eq!(decide(true, true, ""), Action::Nothing);
        assert_eq!(
            decide(true, true, "modsecurity is mentioned here"),
            Action::Nothing
        );
        // And a box with no module configuration has nothing to disable.
        assert_eq!(decide(false, false, "modsecurity"), Action::Nothing);
    }

    /// `grep -qi`: the message spells it `ModSecurity`, and a future nginx
    /// spelling it differently should still be recognised.
    #[test]
    fn the_match_ignores_case() {
        assert!(mentions_module("ModSecurity"));
        assert!(mentions_module("MODSECURITY"));
        assert!(mentions_module("ngx_http_modsecurity_module.so"));
        assert!(!mentions_module("mod_security"));
        assert!(!mentions_module(""));
    }

    /// Moved rather than deleted, and named for what did it: an operator
    /// finding the file knows both what happened and how to undo it.
    #[test]
    fn the_module_is_set_aside_recoverably() {
        assert_eq!(
            disabled_path(),
            "/usr/share/nginx/modules/50-mod-http-modsecurity.conf.disabled-by-snpanel"
        );
        assert!(disabled_path().starts_with(MODULE_CONF));
        assert!(DISABLED_SUFFIX.contains("snpanel"));
    }

    /// "Rebuild it" without saying against what leaves the operator to work
    /// out which nginx they are now on — the fact that changed, and the only
    /// one they need.
    #[test]
    fn the_message_names_the_version_to_rebuild_against() {
        let m = message("1.26.2");
        assert!(m.contains("1.26.2"));
        assert!(m.contains("Rebuild it against nginx"));
        assert!(m.contains("to let nginx start"));
    }

    #[test]
    fn the_version_comes_out_of_the_banner() {
        assert_eq!(version_from_banner("nginx version: nginx/1.26.2"), "1.26.2");
        assert_eq!(version_from_banner("nginx/1.24.0\n"), "1.24.0");
        assert_eq!(version_from_banner(""), "");
    }

    /// **The reset is the load-bearing line.** systemd accumulates
    /// `ExecStartPre` entries in order and gives no way to insert one at the
    /// front, so without the empty entry the guard is appended *after* the
    /// `nginx -t` it is supposed to precede — and does nothing at all.
    #[test]
    fn the_guard_runs_before_nginxs_own_check() {
        let entries = exec_start_pre();
        assert_eq!(entries[0], "", "the list is not reset");
        let guard = entries.iter().position(|e| *e == GUARD).expect("the guard");
        let check = entries
            .iter()
            .position(|e| e.contains("nginx -t"))
            .expect("the check");
        assert!(guard < check, "the guard runs after the check it precedes");
    }

    /// The two lines after the guard are the distribution's own. If EL
    /// changes them this drop-in has to be revisited, which the shell says
    /// in a comment and this says here.
    #[test]
    fn the_restated_lines_are_the_distributions_own() {
        let entries = exec_start_pre();
        assert_eq!(entries[2], "/usr/bin/rm -f /run/nginx.pid");
        assert_eq!(entries[3], "/usr/sbin/nginx -t");
        assert_eq!(entries.len(), 4, "a restated line was added or dropped");
    }

    #[test]
    fn the_guard_is_executable_and_not_writable_by_anyone_else() {
        assert_eq!(GUARD_MODE & 0o111, 0o111);
        assert_eq!(GUARD_MODE & 0o022, 0);
        assert!(DROPIN.starts_with("/etc/systemd/system/nginx.service.d/"));
    }
}
