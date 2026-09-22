//! The WAF: HTTP flood protection everywhere, the rule engine where it is
//! packaged.
//!
//! Source: `install_waf_engine`.
//!
//! The two halves are separated on purpose. Flood protection is plain nginx
//! — a `map` plus a `limit_conn_zone` — and works on every platform. Only
//! the ModSecurity rule engine is packaged on some distributions and not
//! others. A panel that conflated them would either refuse to protect a box
//! it could protect, or claim a rule engine it has not got.

/// What this phase can do on the platform it is running on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Both halves.
    Full,
    /// Flood protection only, and the panel's WAF page says the rule engine
    /// is unavailable.
    ///
    /// Not "disabled": disabled is a setting an operator can change, and
    /// unavailable is a fact about the box. Telling them the wrong one sends
    /// them looking for a switch that does not exist.
    FloodOnly,
}

pub fn plan(waf_available: bool) -> Plan {
    if waf_available {
        Plan::Full
    } else {
        Plan::FloodOnly
    }
}

impl Plan {
    /// Whether the default rule file and the flood configuration get
    /// written. Both, either way — the degraded path is still a configured
    /// box, not a skipped phase.
    pub fn writes_flood_protection(&self) -> bool {
        true
    }
    pub fn writes_default_rules(&self) -> bool {
        true
    }
    pub fn writes_modsec_main_conf(&self) -> bool {
        *self == Plan::Full
    }
}

/// What the installer prints when the rule engine is not packaged.
///
/// It names the three packages it looked for, because the next question an
/// operator asks is "can I not just install it myself?" — and the answer on
/// EL10 is that `mod_security` is the Apache module, not nginx's, which is
/// the trap this message exists to spring first.
pub fn unavailable_notice(os_pretty: &str) -> String {
    format!(
        "ModSecurity for nginx is not packaged on {os_pretty}:\n  \
         nginx-mod-modsecurity, modsecurity and modsecurity-crs are all absent,\n  \
         and mod_security is the Apache module, not nginx's.\n\
         Configuring HTTP flood protection only. The panel's WAF page will\n\
         report the rule engine as unavailable, which is the truth - it is not\n\
         silently disabled."
    )
}

/// The packages asked for, most complete first.
///
/// **The underlying library is deliberately not named.** It was
/// `libmodsecurity3` on 24.04 and is `libmodsecurity3t64` after the 64-bit
/// `time_t` transition, and the nginx module depends on whichever one this
/// release carries — so asking for the module alone is both correct and
/// version-proof. Naming the library would pin the installer to one
/// release's spelling of a package it does not use directly.
///
/// The second attempt drops the rule set, which some releases do not
/// package: an engine with no rules is still an engine the panel can load
/// rules into.
pub fn package_attempts() -> [&'static [&'static str]; 2] {
    [
        &["libnginx-mod-http-modsecurity", "modsecurity-crs"],
        &["libnginx-mod-http-modsecurity"],
    ]
}

/// The nginx module drop-in, linked into `modules-enabled` when the package
/// left one in `modules-available`.
pub const MODULE_AVAILABLE: &str = "/usr/share/nginx/modules-available/mod-http-modsecurity.conf";
pub const MODULE_ENABLED: &str = "/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf";

/// Where ModSecurity's own configuration lives, and the file the package
/// ships instead of it.
pub const MODSEC_CONF: &str = "/etc/modsecurity/modsecurity.conf";
pub const MODSEC_RECOMMENDED: &str = "/etc/modsecurity/modsecurity.conf-recommended";

/// Whether to seed `modsecurity.conf` from the recommended file.
///
/// Only when the recommended file exists and the real one does not: an
/// operator's edited configuration is never overwritten by a reinstall.
pub fn seed_from_recommended(recommended_exists: bool, conf_exists: bool) -> bool {
    recommended_exists && !conf_exists
}

/// `SecRuleEngine On`, in place of whatever the line said.
///
/// The package ships `DetectionOnly`, which logs and permits — a WAF that
/// looks like it is working and blocks nothing.
///
/// Matches the shell's `sed -E 's/^SecRuleEngine .*/SecRuleEngine On/'`
/// exactly, which means: only a line beginning at column zero, and only one
/// that has a space after the directive. A commented-out line is left
/// commented, and a file with no such line is left without one — the shell
/// does not append, and neither does this.
pub fn sec_rule_engine_on(existing: &str) -> String {
    let mut out = String::with_capacity(existing.len());
    for line in existing.split_inclusive('\n') {
        let (body, eol) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        if body.starts_with("SecRuleEngine ") {
            out.push_str("SecRuleEngine On");
            out.push_str(eol);
        } else {
            out.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flood protection is plain nginx and works everywhere. A platform
    /// without the rule engine still gets it — the degraded path configures
    /// the box rather than skipping the phase.
    #[test]
    fn the_degraded_path_still_protects_the_box() {
        for plan in [Plan::Full, Plan::FloodOnly] {
            assert!(plan.writes_flood_protection(), "{plan:?}");
            assert!(plan.writes_default_rules(), "{plan:?}");
        }
        assert!(Plan::Full.writes_modsec_main_conf());
        assert!(!Plan::FloodOnly.writes_modsec_main_conf());
    }

    #[test]
    fn the_plan_follows_the_platform() {
        assert_eq!(plan(true), Plan::Full);
        assert_eq!(plan(false), Plan::FloodOnly);
    }

    /// "Unavailable" and "disabled" are different claims: disabled is a
    /// setting an operator can change, unavailable is a fact about the box.
    /// The notice has to say the second, and name what was looked for.
    #[test]
    fn the_notice_says_unavailable_rather_than_disabled() {
        let notice = unavailable_notice("AlmaLinux 10");
        assert!(notice.contains("AlmaLinux 10"));
        assert!(notice.contains("report the rule engine as unavailable"));
        assert!(notice.contains("not\nsilently disabled"));
        // The three packages, so the operator does not go looking for them
        // one at a time.
        assert!(notice.contains("nginx-mod-modsecurity"));
        assert!(notice.contains("modsecurity-crs"));
        // And the trap it exists to spring first.
        assert!(notice.contains("mod_security is the Apache module"));
    }

    /// `libmodsecurity3` became `libmodsecurity3t64` in the 64-bit `time_t`
    /// transition. The installer asks for the *module*, which depends on
    /// whichever one this release has — so naming the library anywhere here
    /// would pin it to one release's spelling.
    #[test]
    fn the_underlying_library_is_never_named() {
        for attempt in package_attempts() {
            for package in attempt {
                assert!(
                    !package.starts_with("libmodsecurity"),
                    "{package} pins a library spelling"
                );
            }
        }
    }

    /// The rule set is not packaged everywhere, and an engine with no rules
    /// is still an engine the panel can load rules into.
    #[test]
    fn the_rule_set_is_dropped_before_the_engine_is() {
        let [first, second] = package_attempts();
        assert!(first.contains(&"libnginx-mod-http-modsecurity"));
        assert!(first.contains(&"modsecurity-crs"));
        assert_eq!(second, ["libnginx-mod-http-modsecurity"]);
        assert!(first.len() > second.len());
    }

    /// An operator's edited configuration is never overwritten by a
    /// reinstall.
    #[test]
    fn the_recommended_file_only_seeds_a_configuration_that_is_not_there() {
        assert!(seed_from_recommended(true, false));
        assert!(!seed_from_recommended(true, true));
        assert!(!seed_from_recommended(false, false));
        assert!(!seed_from_recommended(false, true));
    }

    /// The package ships `DetectionOnly`, which logs and permits — a WAF
    /// that looks like it is working and blocks nothing.
    #[test]
    fn detection_only_becomes_on() {
        let conf = "SecRuleEngine DetectionOnly\nSecRequestBodyAccess On\n";
        assert_eq!(
            sec_rule_engine_on(conf),
            "SecRuleEngine On\nSecRequestBodyAccess On\n"
        );
        // Already on: unchanged.
        let already = "SecRuleEngine On\n";
        assert_eq!(sec_rule_engine_on(already), already);
    }

    /// The shell's expression is anchored at column zero and requires the
    /// space, and this side matches it exactly — including where that means
    /// doing nothing.
    #[test]
    fn only_the_lines_the_shell_rewrites_are_rewritten() {
        // Commented out: left alone. The shell allows no `#?` here, so a
        // configuration whose only such line is commented stays off — and
        // reproducing that is the point, because diverging would make the
        // Rust installer's WAF state differ from the bash one's.
        let commented = "#SecRuleEngine DetectionOnly\n";
        assert_eq!(sec_rule_engine_on(commented), commented);
        // Indented: not at column zero, left alone.
        let indented = "  SecRuleEngine DetectionOnly\n";
        assert_eq!(sec_rule_engine_on(indented), indented);
        // No space after the directive: not a match.
        let nospace = "SecRuleEngineFoo Off\n";
        assert_eq!(sec_rule_engine_on(nospace), nospace);
        // Absent entirely: nothing is appended.
        let absent = "SecRequestBodyAccess On\n";
        assert_eq!(sec_rule_engine_on(absent), absent);
    }

    /// Every occurrence, and the final line with no newline keeps having
    /// none.
    #[test]
    fn every_occurrence_is_rewritten_and_the_file_shape_is_kept() {
        assert_eq!(
            sec_rule_engine_on("SecRuleEngine Off\nx\nSecRuleEngine DetectionOnly\n"),
            "SecRuleEngine On\nx\nSecRuleEngine On\n"
        );
        assert_eq!(
            sec_rule_engine_on("x\nSecRuleEngine Off"),
            "x\nSecRuleEngine On"
        );
        assert_eq!(sec_rule_engine_on(""), "");
    }

    /// The link is created rather than the file copied, so a package update
    /// that changes the drop-in reaches nginx without the installer running
    /// again.
    #[test]
    fn the_module_drop_in_is_linked_from_where_the_package_put_it() {
        assert!(MODULE_AVAILABLE.starts_with("/usr/share/nginx/modules-available/"));
        assert!(MODULE_ENABLED.starts_with("/etc/nginx/modules-enabled/"));
        // The numeric prefix is load order: the module has to be loaded
        // before any configuration that uses its directives.
        assert!(MODULE_ENABLED.contains("/50-"));
    }
}
