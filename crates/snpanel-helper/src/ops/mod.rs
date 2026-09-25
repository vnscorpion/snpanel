//! The privileged operations.
//!
//! Plan Appendix B groups the 133 bash subcommands into 12 domains. Four are
//! implemented here; the rest follow the same shape, which is the point of
//! landing them first:
//!
//! - every argument arrives already parsed, so no handler re-validates;
//! - no handler builds a shell string;
//! - every handler returns a [`HelperResponse`] rather than exiting.
//!
//! The last one matters more than it looks. The bash uses `exec` for most
//! operations, so the helper process *becomes* nginx or systemctl and its exit
//! status is the only channel back. A structured response means the API can
//! distinguish "nginx said the config is bad" from "nginx is not installed"
//! without parsing English out of stderr.

pub mod fail2ban;
pub mod firewall;
pub mod fwmigrate;
pub mod fwrules;
pub mod mariadb;
pub mod misc;
pub mod nginx;
pub mod orphans;
pub mod packages;
pub mod panel;
pub mod php;
pub mod runtime;
pub mod selinux;
pub mod site;
pub mod siteapp;
pub mod ssl;
pub mod system;
pub mod terminal;
pub mod user;
pub mod waf;

use snpanel_ipc::{HelperErrorKind, HelperRequest, HelperResponse};
use snpanel_osabi::firewall::rules::{Action, FirewallState};

/// The wire enums and the firewall's own enums are deliberately separate
/// types: the protocol is a contract that outlives any one backend, and a
/// rename in `snpanel-osabi` should not silently change what the API sends.
fn proto(p: snpanel_ipc::Protocol) -> snpanel_osabi::firewall::rules::Protocol {
    match p {
        snpanel_ipc::Protocol::Tcp => snpanel_osabi::firewall::rules::Protocol::Tcp,
        snpanel_ipc::Protocol::Udp => snpanel_osabi::firewall::rules::Protocol::Udp,
    }
}

fn log_kind(k: snpanel_ipc::LogKind) -> site::LogKind {
    match k {
        snpanel_ipc::LogKind::Access => site::LogKind::Access,
        snpanel_ipc::LogKind::Error => site::LogKind::Error,
    }
}

fn crs_mode(m: snpanel_ipc::CrsMode) -> waf::CrsMode {
    match m {
        snpanel_ipc::CrsMode::Off => waf::CrsMode::Off,
        snpanel_ipc::CrsMode::Detect => waf::CrsMode::Detect,
        snpanel_ipc::CrsMode::Block => waf::CrsMode::Block,
    }
}

/// Everything the helper needs to know about its own environment.
pub struct Context {
    pub panel_port: u16,
    pub ssh_ports: Vec<u16>,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            panel_port: 2222,
            ssh_ports: vec![22],
        }
    }
}

impl Context {
    /// Read the panel port from the installed `.env`, falling back to 2222.
    pub fn from_system() -> Self {
        let panel_port = std::fs::read_to_string("/opt/snpanel/backend/.env")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|l| l.trim().strip_prefix("PANEL_PORT=").map(str::to_string))
            })
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(2222);

        Self {
            panel_port,
            ssh_ports: sshd_ports(),
        }
    }
}

/// Source: `firewall_protected_ports`, which prefers `sshd -T` and falls back
/// to the raw config when sshd cannot validate it.
fn sshd_ports() -> Vec<u16> {
    let from_sshd = crate::exec::run(&["sshd", "-T"])
        .ok()
        .filter(|o| o.ok())
        .map(|o| {
            o.stdout
                .lines()
                .filter_map(|l| l.strip_prefix("port "))
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !from_sshd.is_empty() {
        return from_sshd;
    }

    let mut ports = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/ssh/sshd_config") {
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if parts.next().is_some_and(|k| k.eq_ignore_ascii_case("port")) {
                if let Some(p) = parts.next().and_then(|p| p.parse::<u16>().ok()) {
                    ports.push(p);
                }
            }
        }
    }
    // Never empty: an empty SSH port list is how a box locks itself out.
    if ports.is_empty() {
        ports.push(22);
    }
    ports
}

/// Dispatch one request.
///
/// Operations not yet ported return `NotFound` naming themselves, rather than
/// a generic failure - during the migration the API may legitimately ask for
/// something the Rust helper does not do yet, and the message should say so.
pub fn dispatch(request: &HelperRequest, ctx: &Context) -> HelperResponse {
    match request {
        HelperRequest::ServiceControl { service, action } => {
            system::service_control(service, *action)
        }
        HelperRequest::DaemonReload => system::daemon_reload(),

        HelperRequest::NginxTest => nginx::test(),
        HelperRequest::NginxReload => nginx::reload(),
        HelperRequest::NginxWriteSite {
            domain,
            rendered,
            kind,
        } => nginx::write_site(domain, rendered, *kind),
        HelperRequest::NginxCustomWrite { domain, content } => nginx::custom_write(domain, content),
        HelperRequest::NginxCustomDelete { domain } => nginx::custom_delete(domain),

        HelperRequest::FirewallApply => {
            if let Err(e) = firewall::ensure_dir() {
                return HelperResponse::failed(
                    HelperErrorKind::Internal,
                    format!("preparing {}: {e}", firewall::FIREWALL_DIR),
                );
            }
            firewall::apply(&firewall::load_ruleset(ctx.panel_port, &ctx.ssh_ports))
        }
        HelperRequest::FirewallFlush => firewall::flush(),
        HelperRequest::FirewallStatus => {
            firewall::status(&firewall::load_ruleset(ctx.panel_port, &ctx.ssh_ports))
        }
        HelperRequest::FirewallMigrateUfw => fwmigrate::migrate(ctx),
        HelperRequest::FirewallMigrateNft => {
            // Migration is an apply: the ruleset is rebuilt from rules.tsv,
            // never read back out of iptables, so there is nothing else to do.
            let resp = firewall::apply(&firewall::load_ruleset(ctx.panel_port, &ctx.ssh_ports));
            if resp.ok {
                // Only once the new ruleset is live does the old one go.
                let _ = crate::exec::run(&["iptables", "-D", "INPUT", "-j", "SNPANEL-INPUT"]);
                let _ = crate::exec::run(&["iptables", "-F", "SNPANEL-INPUT"]);
                let _ = crate::exec::run(&["iptables", "-X", "SNPANEL-INPUT"]);
            }
            resp
        }

        HelperRequest::SelinuxRestoreSite { path } => selinux::restore_site(path),
        HelperRequest::SelinuxPortAdd { port } => selinux::port_add(port.get()),

        // --- firewall rules ---
        HelperRequest::FirewallAllowIp { ip, port, protocol } => {
            fwrules::add_rule(ctx, Action::Allow, Some(ip), *port, proto(*protocol))
        }
        HelperRequest::FirewallDenyIp { ip, port, protocol } => {
            fwrules::add_rule(ctx, Action::Deny, Some(ip), *port, proto(*protocol))
        }
        HelperRequest::FirewallAllowPort { port, protocol } => {
            fwrules::add_rule(ctx, Action::Allow, None, Some(*port), proto(*protocol))
        }
        HelperRequest::FirewallPanelAllowPort { port } => fwrules::panel_allow_port(ctx, *port),
        HelperRequest::FirewallDelete { id } => fwrules::delete_rule(ctx, *id),
        HelperRequest::FirewallEnable => fwrules::set_state(ctx, FirewallState::Enabled),
        HelperRequest::FirewallDisable => fwrules::set_state(ctx, FirewallState::Disabled),
        HelperRequest::FirewallList => fwrules::list(ctx),

        // --- user ---
        HelperRequest::PanelUserEnsure { username, password } => {
            user::ensure(username, password.as_ref())
        }
        HelperRequest::PanelUserDelete { username } => user::delete(username),
        HelperRequest::PanelUserPassword { username, password } => {
            user::set_password(username, password)
        }

        // --- site ---
        HelperRequest::SiteMkdir { path } => site::mkdir(path),
        HelperRequest::SiteRemove { path } => site::remove(path),
        HelperRequest::SiteFileWrite {
            path,
            content,
            mode,
        } => site::file_write(path, content, *mode),
        HelperRequest::SiteChmod {
            path,
            mode,
            recursive,
        } => site::chmod(path, *mode, *recursive),
        HelperRequest::SiteFileSearch {
            path,
            query,
            suffix,
            case_sensitive,
            include_secrets,
        } => site::file_search(path, query, suffix, *case_sensitive, *include_secrets),
        HelperRequest::SiteFixPermissions { path, user: u } => site::fix_permissions(path, u),
        HelperRequest::SiteLogRead {
            domain,
            kind,
            lines,
        } => site::log_read(domain, log_kind(*kind), *lines),
        HelperRequest::SiteLogClear { domain, kind } => site::log_clear(domain, log_kind(*kind)),
        HelperRequest::SiteAppWrite {
            user: u,
            app,
            runtime,
            port,
            memory_mb,
        } => siteapp::write(u, app, runtime, port.get(), *memory_mb),
        HelperRequest::SiteAppRename { user: u, from, to } => siteapp::rename(u, from, to),
        HelperRequest::SiteAppExport { user: u, app, dest } => siteapp::export(u, app, dest),
        HelperRequest::SiteAppImport {
            user: u,
            app,
            source,
        } => siteapp::import(u, app, source),
        HelperRequest::SiteAppDirEnsure { user: u, app } => siteapp::dir_ensure(u, app),
        HelperRequest::SiteAppDelete { user: u, app } => siteapp::delete(u, app),
        HelperRequest::SiteAppPull { image } => siteapp::pull(image),
        HelperRequest::SiteAppInstallDeps {
            user: u,
            app,
            node_major,
        } => siteapp::install_deps(u, app, *node_major),
        HelperRequest::SiteAppControl {
            user: u,
            app,
            action,
        } => siteapp::control(u, app, *action),
        HelperRequest::SiteAppLogs {
            user: u,
            app,
            lines,
        } => siteapp::logs(u, app, *lines),
        HelperRequest::SiteAppComposePs { user: u, app } => siteapp::compose_ps(u, app),
        HelperRequest::SiteAppComposePull { user: u, app } => siteapp::compose_pull(u, app),
        HelperRequest::SiteAppVolumeUsage { user: u } => siteapp::volume_usage(u),
        HelperRequest::SiteArchiveExtract {
            user: u,
            root,
            archive_relative,
            destination_relative,
            kind,
            max_items,
            max_bytes,
        } => site::archive_extract(
            u,
            root,
            archive_relative,
            destination_relative,
            *kind,
            *max_items,
            *max_bytes,
        ),
        HelperRequest::SiteRuntimeMove {
            user: u,
            from,
            to,
            php,
        } => site::runtime_move(u, from, to, *php),
        HelperRequest::SiteRuntimeEnsure { user: u, path, php } => {
            site::runtime_ensure(u, path, *php)
        }
        HelperRequest::SiteRuntimeDelete { user: u, path } => site::runtime_delete(u, path),
        HelperRequest::Wp { args } => site::wp(args),
        HelperRequest::WpSite { user: u, php, args } => site::wp_site(u, *php, args),
        HelperRequest::SitePopulate {
            user: u,
            root,
            source,
        } => site::populate(u, root, source),
        HelperRequest::SiteFileInstall {
            user: u,
            root,
            relative,
            staged,
        } => site::file_install(u, root, relative, staged),
        HelperRequest::SiteDocumentRootEnsure {
            user: u,
            root,
            relative,
        } => site::document_root_ensure(u, root, relative),
        HelperRequest::SiteLogsReadMany {
            domains,
            kind,
            lines,
        } => site::logs_read_many(domains, log_kind(*kind), *lines),

        // --- ssl ---
        HelperRequest::CertbotIssue {
            domain,
            aliases,
            email,
        } => ssl::certbot_issue(domain, aliases, email.as_ref()),
        HelperRequest::CertbotRenew { domain } => ssl::certbot_renew(domain.as_ref()),
        HelperRequest::CertbotAutoRenewInstall => ssl::auto_renew_install(),
        HelperRequest::CertbotRenewSoon { days } => ssl::renew_soon(*days),
        HelperRequest::CertbotDelete { domain } => ssl::certbot_delete(domain),
        HelperRequest::SslCertInfo { domain } => ssl::cert_info(domain),
        HelperRequest::PanelSslSelfsigned { host, port } => ssl::panel_selfsigned(host, *port),
        HelperRequest::PanelSslDomains => ssl::panel_ssl_domains(),
        HelperRequest::PanelSniSync => ssl::sync_sni(),

        // --- php ---
        HelperRequest::PhpOpcacheSet { version, enabled } => php::opcache_set(*version, *enabled),
        HelperRequest::PhpConfigWrite { version, content } => php::config_write(*version, content),

        // --- misc ---
        HelperRequest::Ipv6Status => misc::ipv6_status(),
        HelperRequest::Ipv6Enable => misc::ipv6_enable(),
        HelperRequest::Ipv6Disable => misc::ipv6_disable(),
        HelperRequest::Ipv6Apply => misc::ipv6_apply(),
        HelperRequest::TimeStatus => misc::time_status(),
        HelperRequest::TimeSync => misc::time_sync(),
        HelperRequest::CronList { user: u } => misc::cron_list(u.as_ref()),
        HelperRequest::CronWrite { user: u, content } => misc::cron_write(u.as_ref(), content),
        HelperRequest::FastcgiCacheClear => misc::fastcgi_cache_clear(),
        HelperRequest::ServiceStatus { service } => misc::service_status(service),
        HelperRequest::UpdatesStatus => misc::updates_status(),
        HelperRequest::UpdatesOsRun => misc::updates_os_run(),
        HelperRequest::UpdatesOsAuto { enable } => misc::updates_os_auto(*enable),

        // --- waf / malware ---
        HelperRequest::WafStatus => waf::status(),
        HelperRequest::WafCrsStatus => waf::crs_status(),
        HelperRequest::WafCrsMode { mode } => waf::crs_mode_set(crs_mode(*mode)),
        HelperRequest::WafSiteSave { domain, content } => waf::site_rules_save(domain, content),
        HelperRequest::WafSiteDelete { domain } => waf::site_rules_delete(domain),
        HelperRequest::PanelUserLock { user, locked } => user::lock(user, *locked),
        HelperRequest::PhpPoolsRetune => php::pools_retune(),
        HelperRequest::MariadbRetune => mariadb::retune(),
        HelperRequest::CertbotDnsCloudflareInstall => packages::certbot_dns_cloudflare_install(),
        HelperRequest::MaldetScan {
            job,
            mode,
            days,
            paths,
        } => packages::maldet_scan(job, mode, days, paths),
        HelperRequest::MalwareScanServer { job } => packages::malware_scan_server(job),
        HelperRequest::NodeInstall { major } => packages::node_install(major),
        HelperRequest::ClamavInstall => packages::clamav_install(),
        HelperRequest::MaldetInstall => packages::maldet_install(),
        HelperRequest::MaldetMonitor { action } => packages::maldet_monitor(action),
        HelperRequest::MaldetUpdateSigs => packages::maldet_update_sigs("/usr/local/sbin/maldet"),
        HelperRequest::NginxUpgradeMapEnsure => packages::upgrade_map_ensure(),
        HelperRequest::UpdatesPanelRun => packages::panel_update_run(packages::UPDATE_SCRIPT),
        HelperRequest::PhpTuneWrite { version, content } => php::tune_write(*version, content),
        HelperRequest::PhpInstall { version } => packages::php_install(*version),
        HelperRequest::TerminalExec {
            user,
            cwd,
            argv,
            budget_secs,
            php_version,
        } => terminal::exec_as_user(
            user,
            cwd.as_str(),
            argv,
            // 0 means the caller asked for no budget; the bash treats an
            // empty `--timeout=` the same way, by not wrapping in `timeout`.
            (*budget_secs > 0).then_some(*budget_secs),
            *php_version,
        ),
        HelperRequest::OrphanCleanup {
            clean,
            live_domains,
        } => orphans::cleanup(*clean, live_domains),
        HelperRequest::PanelUrlSet { https, host, port } => {
            panel::url_set(ctx, *https, host, *port)
        }
        HelperRequest::PanelSslUseDomain { domain, port } => {
            panel::ssl_use_domain(ctx, domain, *port)
        }
        HelperRequest::PanelSslInstall {
            domain,
            port,
            email,
        } => panel::ssl_install(ctx, domain, *port, email.as_ref()),
        HelperRequest::CloudflareSslIssue { zone, email, token } => {
            panel::cloudflare_ssl_issue(zone, email.as_ref(), token.expose())
        }
        HelperRequest::WafInstall => waf::install_engine(),
        HelperRequest::FirewallBlocklistRun => {
            firewall::blocklist_run(ctx.panel_port, &ctx.ssh_ports)
        }
        HelperRequest::FirewallBlocklistStatus => {
            firewall::blocklist_status(&firewall::load_ruleset(ctx.panel_port, &ctx.ssh_ports))
        }
        HelperRequest::FirewallBlocklistTimerInstall => firewall::blocklist_timer_install(),
        HelperRequest::FirewallBlocklistUrl { url, add } => {
            if *add {
                firewall::blocklist_add(url)
            } else {
                firewall::blocklist_delete(url)
            }
        }
        HelperRequest::ManualSsl {
            domain,
            install,
            payload,
        } => {
            let response = if *install {
                ssl::manual_ssl_install(domain, payload)
            } else {
                ssl::manual_ssl_remove(domain)
            };
            // The bash runs `sync_panel_sni_certificates` after both, so the
            // panel starts or stops serving this name on its own port in the
            // same call that changed the certificate.
            if response.ok {
                let _ = ssl::sync_sni();
            }
            response
        }
        HelperRequest::DockerInstall => packages::docker_install(),
        HelperRequest::DockerStatus => runtime::docker_status(),
        HelperRequest::DockerPrune => runtime::docker_prune(),
        HelperRequest::NodeList => runtime::node_list(),
        HelperRequest::HttpFloodZonesSave { content } => nginx::flood_zones_save(content),
        HelperRequest::WafDefaultRules => waf::default_rules(),
        HelperRequest::WafCustomRules => waf::custom_rules(),
        HelperRequest::WafCustomSave { content } => waf::custom_rules_save(content),
        HelperRequest::WafUpdate => waf::update_rules(),
        HelperRequest::ClamavStatus => waf::clamav_status(),
        HelperRequest::ClamavControl { start } => waf::clamav_control(*start),
        HelperRequest::Fail2banInstall { config } => fail2ban::install(config, ctx),
        HelperRequest::Fail2banConfigure { config } => fail2ban::configure(config, ctx),
        HelperRequest::Fail2banStatus => fail2ban::status(),
        HelperRequest::Fail2banBan { jail, address } => fail2ban::ban(*jail, *address),
        HelperRequest::Fail2banUnban { address } => fail2ban::unban(*address),
        HelperRequest::Fail2banStop => fail2ban::stop(),
        // Afresh, not `ctx.ssh_ports`: that was read when the helper started,
        // and a port changed since is the one somebody will connect to.
        HelperRequest::SshPorts => HelperResponse::with_stdout(format!(
            "{}\n",
            serde_json::json!({ "ports": sshd_ports() })
        )),
        HelperRequest::MaldetStatus => packages::maldet_status(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_ports_are_never_empty() {
        assert!(!sshd_ports().is_empty());
    }

    #[test]
    fn a_ported_operation_is_not_reported_as_missing() {
        let ctx = Context::default();
        let resp = dispatch(&HelperRequest::FirewallStatus, &ctx);
        // May or may not succeed depending on whether nft is present, but it
        // must not claim to be unimplemented.
        if let Some(err) = resp.error {
            assert_ne!(err.kind, HelperErrorKind::NotFound);
        }
    }

    #[test]
    fn context_falls_back_when_the_panel_is_not_installed() {
        let ctx = Context::from_system();
        assert!(ctx.panel_port > 0);
        assert!(!ctx.ssh_ports.is_empty());
    }

    /// Every verb a systemd unit this crate writes asks for must be one the
    /// binary answers.
    ///
    /// This mattered less while the bash was there to catch a name the Rust
    /// did not map. With the bash gone, a unit naming a verb that no longer
    /// exists is a timer that fails silently every night - certificates that
    /// stop renewing, blocklists that stop refreshing - and nothing reports
    /// it but the journal.
    #[test]
    fn every_unit_execstart_names_a_verb_the_binary_answers() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ops");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("src/ops").flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("a source file");
            for line in text.lines() {
                // The unit bodies are Rust string literals, so the line ends
                // in `\n";` or `\n\` - take what is between the binary and
                // the first of those.
                // Only a real unit line, not a test asserting about one.
                let Some(rest) = line.trim_start().strip_prefix("ExecStart=") else {
                    continue;
                };
                let Some(args) = rest.split("snpanel-helper ").nth(1) else {
                    continue;
                };
                // Anything after the verb is its arguments; the escape at the
                // end of the literal is not.
                // The literal ends in `\n";` or `\n\`; the verb and its
                // arguments are everything before the first backslash or
                // quote.
                let end = args.find(['\\', '"']).unwrap_or(args.len());
                let argv: Vec<String> =
                    args[..end].split_whitespace().map(str::to_string).collect();
                if argv.is_empty() {
                    continue;
                }
                let parsed = snpanel_ipc::HelperRequest::from_argv(&argv, Vec::new);
                assert!(
                    parsed.is_ok(),
                    "{}: unit asks for `{}`, which the mapping refuses: {:?}",
                    path.display(),
                    argv.join(" "),
                    parsed.err(),
                );
                checked += 1;
            }
        }
        // Two units carry an ExecStart today. A refactor that stopped this
        // test finding them would leave it passing while checking nothing.
        assert_eq!(checked, 2, "expected to check two ExecStart lines");
    }
}
