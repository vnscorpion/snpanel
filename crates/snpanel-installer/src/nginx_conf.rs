//! The nginx and ModSecurity files the installer drops into place.
//!
//! Five of them, written before any website exists, and every later vhost
//! depends on them: the FastCGI cache zone, the WebSocket upgrade map, the
//! HTTP-flood zones, and the two ModSecurity includes. A vhost that names a
//! zone no file declares does not fail at the vhost — it fails `nginx -t` for
//! **every** site on the box, which is why these are written first and why
//! their contents are pinned.
//!
//! Source: `configure_fastcgi_cache`, `configure_proxy_upgrade_map`,
//! `write_http_flood_nginx_conf`, `write_modsec_base_conf`,
//! `write_modsec_main_conf` and `write_waf_default_rules` in
//! `installer/install.sh`.

/// `/etc/nginx/conf.d/00-snpanel-fastcgi-cache.conf`.
///
/// The `00-` prefix is load-bearing: nginx reads `conf.d/*.conf` in glob
/// order, and a site that names `SNPANEL_FASTCGI` before the zone is declared
/// is a configuration that will not load.
pub const FASTCGI_CACHE_PATH: &str = "/etc/nginx/conf.d/00-snpanel-fastcgi-cache.conf";
pub const FASTCGI_CACHE_DIR: &str = "/var/cache/nginx/snpanel-fastcgi";

pub fn fastcgi_cache_conf() -> String {
    concat!(
        "fastcgi_cache_path /var/cache/nginx/snpanel-fastcgi levels=1:2 ",
        "keys_zone=SNPANEL_FASTCGI:32m inactive=30m max_size=256m use_temp_path=off;\n",
        "fastcgi_cache_key \"$scheme$request_method$host$request_uri\";\n",
    )
    .to_string()
}

/// `/etc/nginx/conf.d/00-snpanel-upgrade-map.conf`.
///
/// Shared by every proxied vhost. Without it a
/// `proxy_set_header Connection $connection_upgrade` in a site config makes
/// nginx fail to start, so this has to exist before any proxy vhost is
/// written — which is why it is a phase of its own rather than part of a
/// site's template.
pub const UPGRADE_MAP_PATH: &str = "/etc/nginx/conf.d/00-snpanel-upgrade-map.conf";

pub fn upgrade_map_conf() -> String {
    concat!(
        "map $http_upgrade $connection_upgrade {\n",
        "    default upgrade;\n",
        "    ''      close;\n",
        "}\n",
    )
    .to_string()
}

pub const HTTP_FLOOD_ZONES_PATH: &str = "/etc/nginx/snpanel/http-flood-zones.conf";
pub const HTTP_FLOOD_INCLUDE_PATH: &str = "/etc/nginx/conf.d/00-snpanel-http-flood.conf";

/// The zones themselves.
///
/// Written **only when the file is absent**: the panel rewrites this file as
/// sites turn flood protection on and off, so an installer that overwrote it
/// on every update would undo whatever the operator had configured. That
/// condition lives in the phase, not here.
pub fn http_flood_zones_conf() -> String {
    concat!(
        "# Managed by SNPanel. Shared zones for per-website HTTP flood protection.\n",
        "map $cookie_snpanel_http_flood_ok $snpanel_http_flood_key {\n",
        "    default $binary_remote_addr;\n",
        "    1 \"\";\n",
        "}\n",
        "limit_conn_zone $snpanel_http_flood_key zone=snpanel_conn_flood:10m;\n",
    )
    .to_string()
}

/// The one-line include that pulls the zones in. Rewritten every time,
/// unlike the zones themselves.
pub fn http_flood_include_conf() -> String {
    concat!(
        "# Managed by SNPanel. Shared zones for per-website HTTP flood protection.\n",
        "include /etc/nginx/snpanel/http-flood-zones.conf;\n",
    )
    .to_string()
}

pub const MODSEC_BASE_PATH: &str = "/etc/nginx/modsec/snpanel-base.conf";
pub const MODSEC_MAIN_PATH: &str = "/etc/nginx/modsec/snpanel-main.conf";
pub const MODSEC_DEFAULT_PATH: &str = "/etc/nginx/modsec/snpanel-default.conf";
pub const MODSEC_CUSTOM_PATH: &str = "/etc/nginx/modsec/snpanel-custom.conf";
pub const DISTRO_MODSECURITY_CONF: &str = "/etc/modsecurity/modsecurity.conf";

/// The engine settings.
///
/// `distro_conf_present` decides whether the distribution's own
/// `modsecurity.conf` is included, and it is a real branch rather than a
/// tidy-up: that file carries the audit-log and request-body settings, and a
/// box where ModSecurity was never packaged gets the engine turned on with
/// nothing else configured. Both shapes are in the fixtures.
pub fn modsec_base_conf(distro_conf_present: bool) -> String {
    let mut out = String::new();
    if distro_conf_present {
        out.push_str("Include /etc/modsecurity/modsecurity.conf\n");
    }
    out.push_str("SecRuleEngine On\n");
    out.push_str("SecRequestBodyAccess Off\n");
    out
}

/// The three includes, in the order they are read.
///
/// `snpanel-custom.conf` is last so an operator's own rules can override the
/// defaults, and it is only ever `touch`ed by the installer — never written,
/// because whatever is in it is theirs.
pub fn modsec_main_conf() -> String {
    concat!(
        "Include /etc/nginx/modsec/snpanel-base.conf\n",
        "Include /etc/nginx/modsec/snpanel-default.conf\n",
        "Include /etc/nginx/modsec/snpanel-custom.conf\n",
    )
    .to_string()
}

/// The eight rules every site on this server gets.
///
/// **Every rule is `phase:1`, and that is not a style choice.** On the nginx
/// connector a `phase:2` rule never runs — measured on Debian 13 against
/// `ngx_http_modsecurity_module`, on GET and on POST, with
/// `SecRequestBodyAccess` both `Off` and `On` — so it loads, it is counted,
/// the panel shows the WAF as enabled, and it matches nothing. Two rules here
/// were `phase:2` and were dead on every box this installer has set up:
/// 1001302 (path traversal) and 1001103 (author enumeration).
///
/// This file has **three** authors: this, the helper's `waf-update`, and the
/// panel's own per-site copy. The first two are byte-identical and are both
/// pinned to `tests/golden/installer/snpanel-default.conf.expected`, so a
/// change to either shows up as a failing test rather than as a box whose
/// rules depend on which code last wrote them. The panel's per-site copy is
/// one character per line different — it does not close its action list with
/// a quote — which is recorded in `snpanel-helper` and is not this crate's to
/// reconcile.
pub const WAF_DEFAULT_RULES: &str = concat!(
    "# SNPanel default WAF rules: lightweight WordPress, Laravel, and PHP probes only.\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/\.user\.ini(?:\.|$)|/\.git/|/composer\.(?:json|lock)(?:$|[?])|/(?:phpinfo|info)\.php(?:$|[?])|/(?:config|database|db)\.php\.(?:bak|old|save|txt)(?:$|[?]))" "id:1001301,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP sensitive file probe'""#,
    "\n",
    r#"SecRule REQUEST_URI|ARGS "@rx (?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)" "id:1001302,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP path traversal'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/(?:c99|r57|shell|cmd|wso)\.php(?:$|[?])|/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php(?:$|[?]))" "id:1001303,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP runtime probe'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/artisan(?:$|[?])|/server\.php(?:$|[?])|/storage/logs/[^?]*\.log(?:$|[?])|/bootstrap/cache/[^?]*\.php(?:$|[?]))" "id:1001201,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel sensitive path'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/_ignition/execute-solution(?:$|[?]))" "id:1001202,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel Ignition RCE probe'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/wp-config\.php(?:\.|$|[?])|/wp-content/(?:uploads|cache|upgrade)/[^?]*\.php(?:$|[?])|/wp-admin/includes/[^?]*\.php(?:$|[?])|/wp-includes/[^?]*\.php(?:$|[?]))" "id:1001101,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress sensitive path'""#,
    "\n",
    r#"SecRule ARGS:author "@rx ^[0-9]+$" "id:1001103,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress author enumeration'""#,
    "\n",
    r#"SecRule REQUEST_URI "@rx (?i)(?:/wp-admin/install\.php(?:$|[?])|/wp-admin/setup-config\.php(?:$|[?]))" "id:1001104,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress installer probe'""#,
    "\n",
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Read a fixture recorded by running the bash on a real Debian 13.
    ///
    /// Run, not transcribed: `write_modsec_base_conf` builds its file line by
    /// line from a shell conditional, so reading the heredoc would record the
    /// template and not what a box ends up with.
    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/installer")
            .join(format!("{name}.expected"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the fixture {}: {e}", path.display()))
    }

    #[test]
    fn the_shared_nginx_files_are_what_the_shell_writes() {
        assert_eq!(
            fastcgi_cache_conf(),
            fixture("00-snpanel-fastcgi-cache.conf")
        );
        assert_eq!(upgrade_map_conf(), fixture("00-snpanel-upgrade-map.conf"));
        assert_eq!(http_flood_zones_conf(), fixture("http-flood-zones.conf"));
        assert_eq!(
            http_flood_include_conf(),
            fixture("00-snpanel-http-flood.conf")
        );
    }

    /// Both branches, because which one a box takes decides whether the WAF
    /// has any engine settings beyond being switched on.
    #[test]
    fn the_modsec_base_includes_the_distros_own_config_only_when_it_is_there() {
        assert_eq!(modsec_base_conf(true), fixture("snpanel-base.conf"));
        assert_eq!(
            modsec_base_conf(false),
            fixture("snpanel-base.no-modsecurity.conf")
        );
        // The difference is exactly the one line.
        assert_eq!(
            modsec_base_conf(true),
            format!(
                "Include {DISTRO_MODSECURITY_CONF}\n{}",
                modsec_base_conf(false)
            )
        );
    }

    #[test]
    fn the_modsec_includes_are_in_the_order_the_shell_writes_them() {
        assert_eq!(modsec_main_conf(), fixture("snpanel-main.conf"));
        // The operator's own file is last, so their rules win.
        let main = modsec_main_conf();
        assert_eq!(
            main.lines().last(),
            Some("Include /etc/nginx/modsec/snpanel-custom.conf")
        );
    }

    #[test]
    fn the_default_waf_rules_are_what_the_shell_writes() {
        assert_eq!(WAF_DEFAULT_RULES, fixture("snpanel-default.conf"));
    }

    /// The claim in the doc comment, checked rather than asserted in prose:
    /// a rule that ran in phase 2 would load, be counted, and match nothing.
    #[test]
    fn every_default_rule_runs_in_phase_one() {
        let mut rules = 0;
        for line in WAF_DEFAULT_RULES.lines() {
            if !line.starts_with("SecRule") {
                continue;
            }
            rules += 1;
            assert!(
                line.contains(",phase:1,"),
                "this rule would never run on the nginx connector: {line}"
            );
        }
        assert_eq!(rules, 8, "the rule set changed size");
    }
}
