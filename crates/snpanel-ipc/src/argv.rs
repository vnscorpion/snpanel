//! A bash-style invocation, mapped onto the request enum.
//!
//! The panel calls the helper as `snpanel-helper <verb> <arg>...` - the shape
//! the bash helper has always taken, and the shape every call site in the API
//! still uses. Stage B puts a socket underneath that call without changing it,
//! so the same argument list has to become a typed request in two places: in
//! the helper binary, which still answers a command line, and in the API,
//! which now builds the request itself.
//!
//! One mapping, in the crate both already depend on, because what the two
//! copies would drift about is which arguments are accepted for an operation
//! that runs as root.
//!
//! Plan §4.3.

use crate::{
    AppAction, AppRuntime, ArchiveKind, CrsMode, FileMode, HelperRequest, LogKind, NodeExec,
    Protocol, ServiceAction, ServiceName,
};
use snpanel_core::{AppName, DockerImage, IpOrCidr, PanelUsername, Port, SitePath};

/// Why an argument list did not become a request.
///
/// The two cases are not interchangeable, and the difference decides what the
/// caller does next. [`InvocationError::Unmapped`] means this build does not answer
/// the verb, so the caller hands it to the bash helper - that fallthrough is
/// the cutover mechanism itself. [`InvocationError::Invalid`] means the verb *is*
/// answered here and its arguments were refused, and the caller must report
/// that rather than try the bash: an argument rejected here must not get a
/// second hearing from an implementation that may parse it more loosely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationError {
    Unmapped(String),
    Invalid(String),
}

impl InvocationError {
    pub fn unmapped(op: &str) -> Self {
        Self::Unmapped(op.to_string())
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// Whether the bash helper should be given this call instead.
    pub fn is_unmapped(&self) -> bool {
        matches!(self, Self::Unmapped(_))
    }
}

impl std::fmt::Display for InvocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmapped(op) => write!(f, "{op} is not implemented in the Rust helper"),
            Self::Invalid(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for InvocationError {}

/// Whatever the caller read from stdin, as text.
///
/// C37's companion: content that is multi-line, large, or secret travels this
/// way and never through argv, where it would sit in `ps` for the life of the
/// process. A library cannot read the process's own stdin on the caller's
/// behalf - the API has none to read - so it is passed in.
fn stdin_text(read: impl FnOnce() -> Vec<u8>) -> String {
    String::from_utf8_lossy(&read()).into_owned()
}

fn stdin_bytes(read: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    read()
}

/// Build a [`SitePath`] from the bash's three-argument form.
///
/// The bash addresses a site file as `<site-user> <site-root> <path>` and
/// re-derives the safety check in each arm. The typed protocol carries one
/// `SitePath` that already guarantees it, so the job here is to check the
/// three agree with each other before collapsing them - a mismatched user and
/// root is a caller bug worth reporting rather than silently trusting one of
/// them.
fn site_path_from(user: &str, root: &str, relative: Option<&str>) -> Result<SitePath, String> {
    let user = PanelUsername::parse(user).map_err(|e| e.to_string())?;
    let root_path = SitePath::parse(root).map_err(|e| e.to_string())?;
    if root_path.user() != &user {
        return Err(format!("site root {root} does not belong to {user}"));
    }
    match relative {
        Some(rel) => root_path.join(rel).map_err(|e| e.to_string()),
        None => Ok(root_path),
    }
}

/// A count the bash accepts, with the bash's default when it is absent.
fn lines_or(raw: Option<&String>, default: u32) -> Result<u32, InvocationError> {
    match raw {
        None => Ok(default),
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| InvocationError::invalid(format!("invalid line count: {s}"))),
    }
}

fn user_of(raw: &str) -> Result<PanelUsername, InvocationError> {
    PanelUsername::parse(raw).map_err(|e| InvocationError::invalid(e.to_string()))
}

fn app_of(raw: &str) -> Result<AppName, InvocationError> {
    AppName::parse(raw).map_err(|e| InvocationError::invalid(e.to_string()))
}

/// `<php-version|none>`, as the bash spells "this site runs no PHP".
///
/// A static site gets no pool, rather than a pool for a version that is not
/// installed.
fn php_or_none(raw: &str) -> Result<Option<snpanel_core::PhpVersion>, InvocationError> {
    if raw == "none" || raw.is_empty() {
        return Ok(None);
    }
    snpanel_core::PhpVersion::parse(raw)
        .map(Some)
        .map_err(|e| InvocationError::invalid(e.to_string()))
}

/// Source: `require_node_major`, `^[1-9][0-9]$` - two digits, not one.
fn node_major_of(raw: &str) -> Result<u8, InvocationError> {
    let bad = || InvocationError::invalid(format!("invalid node major version: {raw}"));
    if raw.len() != 2 || !raw.bytes().all(|b| b.is_ascii_digit()) || raw.starts_with('0') {
        return Err(bad());
    }
    raw.parse::<u8>().map_err(|_| bad())
}

/// Source: `^[A-Za-z0-9._@/-]{1,120}$`, the start argument of a node app.
fn start_argument(raw: &str) -> Result<String, InvocationError> {
    let ok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'/' | b'-');
    if raw.is_empty() || raw.len() > 120 || !raw.bytes().all(ok) {
        return Err(InvocationError::invalid(format!(
            "invalid start argument: {raw}"
        )));
    }
    Ok(raw.to_string())
}

/// Source: `require_app_memory`, 64 to 16384 megabytes.
fn memory_mb(raw: &str) -> Result<u32, InvocationError> {
    let value = raw
        .parse::<u32>()
        .map_err(|_| InvocationError::invalid(format!("invalid memory limit: {raw}")))?;
    if !(64..=16384).contains(&value) {
        return Err(InvocationError::invalid(format!(
            "memory limit out of range: {raw}"
        )));
    }
    Ok(value)
}

/// Whole CPUs in hundredths. Source: `require_app_cpus`, `^[0-9]{1,2}(\.[0-9])?$`.
///
/// An integer because a float in a unit file is a rounding argument waiting to
/// happen, and because "1.5" has to come out of the other side as exactly
/// 1.50 and not 1.4999999.
fn cpus_centi(raw: &str) -> Result<u32, InvocationError> {
    let bad = || InvocationError::invalid(format!("invalid cpu limit: {raw}"));
    let (whole, tenth) = match raw.split_once('.') {
        Some((w, t)) => {
            if t.len() != 1 || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            (w, t.parse::<u32>().map_err(|_| bad())?)
        }
        None => (raw, 0),
    };
    if whole.is_empty() || whole.len() > 2 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok(whole.parse::<u32>().map_err(|_| bad())? * 100 + tenth * 10)
}

/// The flags of `site-app-write`, with the bash's defaults.
struct AppFlags<'a> {
    port: Option<&'a str>,
    memory: &'a str,
    node_major: Option<&'a str>,
    exec: Option<&'a str>,
    arg: &'a str,
    image: Option<&'a str>,
    container_port: &'a str,
    cpus: &'a str,
}

impl Default for AppFlags<'_> {
    fn default() -> Self {
        Self {
            port: None,
            memory: "512",
            node_major: None,
            exec: None,
            arg: "",
            image: None,
            container_port: "3000",
            cpus: "1",
        }
    }
}

impl HelperRequest {
    /// Map `<verb> <arg>...` onto a request.
    ///
    /// `stdin` is *called* only by the verbs that carry a payload, which is
    /// why it is a closure and not bytes. A verb this build does not answer is
    /// handed to the bash helper, and the bash helper reads that payload
    /// itself - so reading it here to decide would consume the very thing the
    /// fallthrough needs. Laziness is the guarantee, not an optimisation.
    pub fn from_argv(
        argv: &[String],
        stdin: impl FnOnce() -> Vec<u8>,
    ) -> Result<Self, InvocationError> {
        if argv.is_empty() {
            return Err(InvocationError::invalid("no operation given"));
        }
        let op = argv[0].as_str();
        let rest = &argv[1..];

        let request = match (op, rest.len()) {
            ("nginx-test", 0) => HelperRequest::NginxTest,
            ("nginx-reload", 0) => HelperRequest::NginxReload,
            ("daemon-reload", 0) => HelperRequest::DaemonReload,
            ("firewall-apply", 0) | ("firewall-reload", 0) | ("ufw-reload", 0) => {
                HelperRequest::FirewallApply
            }
            ("firewall-flush", 0) => HelperRequest::FirewallFlush,
            ("firewall-status", 0) => HelperRequest::FirewallStatus,
            ("firewall-migrate-nft", 0) => HelperRequest::FirewallMigrateNft,

            ("systemctl", 2) => {
                let service = match ServiceName::parse(&rest[0]) {
                    Ok(s) => s,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                let action = match rest[1].as_str() {
                    "start" => ServiceAction::Start,
                    "stop" => ServiceAction::Stop,
                    "restart" => ServiceAction::Restart,
                    "reload" => ServiceAction::Reload,
                    "status" | "is-active" => ServiceAction::Status,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "action not allowed: {other}"
                        )))
                    }
                };
                HelperRequest::ServiceControl { service, action }
            }

            ("firewall-enable", 0) => HelperRequest::FirewallEnable,
            ("firewall-disable", 0) => HelperRequest::FirewallDisable,
            ("firewall-list", 0) => HelperRequest::FirewallList,
            ("ipv6-status", 0) => HelperRequest::Ipv6Status,
            ("ipv6-enable", 0) => HelperRequest::Ipv6Enable,
            ("ipv6-disable", 0) => HelperRequest::Ipv6Disable,
            ("ipv6-apply", 0) => HelperRequest::Ipv6Apply,
            ("time-status", 0) => HelperRequest::TimeStatus,
            ("time-sync", 0) => HelperRequest::TimeSync,
            ("fastcgi-cache-clear", 0) => HelperRequest::FastcgiCacheClear,
            ("updates-status", 0) => HelperRequest::UpdatesStatus,
            ("updates-os-run", 0) => HelperRequest::UpdatesOsRun,
            ("waf-status", 0) => HelperRequest::WafStatus,
            ("waf-crs-status", 0) => HelperRequest::WafCrsStatus,
            ("clamav-status", 0) => HelperRequest::ClamavStatus,
            ("maldet-status", 0) => HelperRequest::MaldetStatus,
            ("panel-ssl-domains", 0) => HelperRequest::PanelSslDomains,
            ("panel-sni-sync", 0) => HelperRequest::PanelSniSync,
            ("certbot-renew", 0) => HelperRequest::CertbotRenew { domain: None },

            ("firewall-allow-ip", 1) | ("ufw-allow-ip", 1) => match IpOrCidr::parse(&rest[0]) {
                Ok(ip) => HelperRequest::FirewallAllowIp {
                    ip,
                    port: None,
                    protocol: Protocol::Tcp,
                },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("firewall-deny-ip", 1) | ("ufw-deny-ip", 1) => match IpOrCidr::parse(&rest[0]) {
                Ok(ip) => HelperRequest::FirewallDenyIp {
                    ip,
                    port: None,
                    protocol: Protocol::Tcp,
                },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("firewall-allow-port", 1) | ("firewall-allow-port", 2) => {
                let port = match Port::parse(&rest[0]) {
                    Ok(p) => p,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                let protocol = match rest.get(1).map(String::as_str) {
                    None | Some("tcp") => Protocol::Tcp,
                    Some("udp") => Protocol::Udp,
                    Some(other) => {
                        return Err(InvocationError::invalid(format!(
                            "invalid protocol: {other}"
                        )))
                    }
                };
                HelperRequest::FirewallAllowPort { port, protocol }
            }
            ("firewall-panel-allow-port", 1) => match Port::parse(&rest[0]) {
                Ok(port) => HelperRequest::FirewallPanelAllowPort { port },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("firewall-delete", 1) | ("ufw-delete", 1) => match rest[0].parse::<u32>() {
                Ok(id) => HelperRequest::FirewallDelete { id },
                Err(_) => {
                    return Err(InvocationError::invalid(format!(
                        "invalid rule id: {}",
                        rest[0]
                    )))
                }
            },

            ("panel-user-ensure", 1) => match PanelUsername::parse(&rest[0]) {
                Ok(username) => HelperRequest::PanelUserEnsure {
                    username,
                    password: None,
                },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("panel-user-delete", 1) => match PanelUsername::parse(&rest[0]) {
                Ok(username) => HelperRequest::PanelUserDelete { username },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("panel-user-password", 1) => {
                // C37: the password arrives on stdin, never as an argument, so it
                // is not visible in `ps` for the life of the process.
                let username = match PanelUsername::parse(&rest[0]) {
                    Ok(u) => u,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                let mut password = String::new();
                if std::io::Read::read_to_string(&mut std::io::stdin(), &mut password).is_err() {
                    return Err(InvocationError::invalid(
                        "could not read the password from stdin",
                    ));
                }
                HelperRequest::PanelUserPassword {
                    username,
                    password: snpanel_core::SecretString::new(password.trim_end_matches('\n')),
                }
            }

            ("mkdir-site", 1) => match SitePath::parse(&rest[0]) {
                Ok(path) => HelperRequest::SiteMkdir { path },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("site-log-read", 3) => {
                let domain = match snpanel_core::Domain::parse(&rest[0]) {
                    Ok(d) => d,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                let kind = match rest[1].as_str() {
                    "access" => LogKind::Access,
                    "error" => LogKind::Error,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "invalid log kind: {other}"
                        )))
                    }
                };
                let lines = rest[2].parse::<u32>().unwrap_or(200);
                HelperRequest::SiteLogRead {
                    domain,
                    kind,
                    lines,
                }
            }
            ("site-log-clear", 2) => {
                let domain = match snpanel_core::Domain::parse(&rest[0]) {
                    Ok(d) => d,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                let kind = match rest[1].as_str() {
                    "access" => LogKind::Access,
                    "error" => LogKind::Error,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "invalid log kind: {other}"
                        )))
                    }
                };
                HelperRequest::SiteLogClear { domain, kind }
            }
            ("fix-permissions", 2) | ("site-path-fix", 2) => {
                let path = match SitePath::parse(&rest[0]) {
                    Ok(p) => p,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                match PanelUsername::parse(&rest[1]) {
                    Ok(user) => HelperRequest::SiteFixPermissions { path, user },
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                }
            }

            ("ssl-cert-info", 1) => match snpanel_core::Domain::parse(&rest[0]) {
                Ok(domain) => HelperRequest::SslCertInfo { domain },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("certbot-delete", 1) => match snpanel_core::Domain::parse(&rest[0]) {
                Ok(domain) => HelperRequest::CertbotDelete { domain },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("panel-ssl-selfsigned", 1) | ("panel-ssl-selfsigned", 2) => {
                let port = match rest.get(1) {
                    Some(p) => match Port::parse(p) {
                        Ok(p) => p,
                        Err(e) => return Err(InvocationError::invalid(e.to_string())),
                    },
                    None => Port::new(2222).expect("2222 is valid"),
                };
                HelperRequest::PanelSslSelfsigned {
                    host: rest[0].clone(),
                    port,
                }
            }

            ("php-opcache-set", 2) => {
                let version = match snpanel_core::PhpVersion::parse(&rest[0]) {
                    Ok(v) => v,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                let enabled = match rest[1].as_str() {
                    "1" => true,
                    "0" => false,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "opcache switch must be 0 or 1, got {other}"
                        )))
                    }
                };
                HelperRequest::PhpOpcacheSet { version, enabled }
            }

            ("service-status", 1) => match ServiceName::parse(&rest[0]) {
                Ok(service) => HelperRequest::ServiceStatus { service },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("updates-os-auto", 1) => HelperRequest::UpdatesOsAuto {
                enable: rest[0] == "on" || rest[0] == "1" || rest[0] == "true",
            },
            ("waf-crs-mode", 1) => {
                let mode = match rest[0].as_str() {
                    "off" => CrsMode::Off,
                    "detect" => CrsMode::Detect,
                    "block" => CrsMode::Block,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "invalid CRS mode: {other}"
                        )))
                    }
                };
                HelperRequest::WafCrsMode { mode }
            }
            // The bash answers three names per arm; the two older ones are
            // from when this was an nginx and then a ufw feature. A verb the
            // mapping does not know falls through to the bash and still
            // works, so the aliases are here for the same reason the bash
            // keeps them: an operator's muscle memory and a script somebody
            // wrote years ago.
            ("firewall-blocklist-add", 1)
            | ("nginx-blocklist-add", 1)
            | ("ufw-blocklist-add", 1)
            | ("firewall-blocklist-delete", 1)
            | ("nginx-blocklist-delete", 1)
            | ("ufw-blocklist-delete", 1) => HelperRequest::FirewallBlocklistUrl {
                url: rest[0].clone(),
                add: op.ends_with("-add"),
            },
            ("docker-status", 0) => HelperRequest::DockerStatus,
            ("docker-prune", 0) => HelperRequest::DockerPrune,
            ("node-list", 0) => HelperRequest::NodeList,
            ("panel-user-lock", 1) | ("panel-user-unlock", 1) => HelperRequest::PanelUserLock {
                user: user_of(&rest[0])?,
                locked: op == "panel-user-lock",
            },
            ("http-flood-zones-save", 0) => HelperRequest::HttpFloodZonesSave {
                content: String::from_utf8_lossy(&stdin()).into_owned(),
            },
            ("waf-default-rules", 0) => HelperRequest::WafDefaultRules,
            ("waf-custom-rules", 0) => HelperRequest::WafCustomRules,
            ("waf-update", 0) => HelperRequest::WafUpdate,
            // The rules arrive on stdin, and `stdin` is a closure for the
            // reason Stage B found: an unmapped verb must leave the payload
            // for the bash fallthrough to read.
            ("waf-custom-save", 0) => HelperRequest::WafCustomSave {
                content: String::from_utf8_lossy(&stdin()).into_owned(),
            },
            ("waf-site-delete", 1) => match snpanel_core::Domain::parse(&rest[0]) {
                Ok(domain) => HelperRequest::WafSiteDelete { domain },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("clamav-start", 0) => HelperRequest::ClamavControl { start: true },
            ("clamav-stop", 0) => HelperRequest::ClamavControl { start: false },

            ("cron-list", 0) => HelperRequest::CronList { user: None },
            ("cron-list", 1) => match PanelUsername::parse(&rest[0]) {
                Ok(u) => HelperRequest::CronList { user: Some(u) },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },

            // --- operations that read their payload from stdin ---
            // The bash takes these the same way: the content is multi-line and can
            // be large, so argv is the wrong channel for it.
            ("nginx-custom-write", 1) => match snpanel_core::Domain::parse(&rest[0]) {
                Ok(domain) => HelperRequest::NginxCustomWrite {
                    domain,
                    content: stdin_text(stdin),
                },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("nginx-custom-delete", 1) => match snpanel_core::Domain::parse(&rest[0]) {
                Ok(domain) => HelperRequest::NginxCustomDelete { domain },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("waf-site-save", 1) => match snpanel_core::Domain::parse(&rest[0]) {
                Ok(domain) => HelperRequest::WafSiteSave {
                    domain,
                    content: stdin_text(stdin),
                },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("php-config-write", 1) => match snpanel_core::PhpVersion::parse(&rest[0]) {
                Ok(version) => HelperRequest::PhpConfigWrite {
                    version,
                    content: stdin_text(stdin),
                },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },
            ("cron-write", 0) => HelperRequest::CronWrite {
                user: None,
                content: stdin_text(stdin),
            },
            ("cron-write", 1) => match PanelUsername::parse(&rest[0]) {
                Ok(u) => HelperRequest::CronWrite {
                    user: Some(u),
                    content: stdin_text(stdin),
                },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },

            // --- the site operations, which the bash addresses as three separate
            // arguments that together name one path ---
            ("site-file-write", 3) | ("site-file-write", 4) => {
                // <site-user> <site-root> <relative-path> [0644|0640]
                let path = match site_path_from(&rest[0], &rest[1], Some(&rest[2])) {
                    Ok(p) => p,
                    Err(e) => return Err(InvocationError::invalid(e)),
                };
                let mode = match rest.get(3).map(String::as_str) {
                    None | Some("0644") => FileMode::FILE,
                    Some("0640") => FileMode::SENSITIVE,
                    Some(other) => {
                        return Err(InvocationError::invalid(format!(
                            "invalid file mode: {other}"
                        )))
                    }
                };
                HelperRequest::SiteFileWrite {
                    path,
                    content: stdin_bytes(stdin),
                    mode,
                }
            }
            ("site-chmod", 4) => {
                // <site-user> <site-root> <absolute-path> <mode>
                let path = match site_path_from(&rest[0], &rest[1], None) {
                    Ok(_) => match SitePath::parse(&rest[2]) {
                        Ok(p) => p,
                        Err(e) => return Err(InvocationError::invalid(e.to_string())),
                    },
                    Err(e) => return Err(InvocationError::invalid(e)),
                };
                // Three to five octal digits, as the bash accepts.
                let raw = rest[3].as_str();
                if raw.len() < 3
                    || raw.len() > 5
                    || !raw.bytes().all(|b| (b'0'..=b'7').contains(&b))
                {
                    return Err(InvocationError::invalid(format!("invalid mode: {raw}")));
                }
                let mode = match u32::from_str_radix(raw, 8) {
                    Ok(m) => FileMode(m),
                    Err(_) => return Err(InvocationError::invalid(format!("invalid mode: {raw}"))),
                };
                HelperRequest::SiteChmod {
                    path,
                    mode,
                    recursive: false,
                }
            }
            ("rm-site", 3) => {
                // <site-user> <site-root> <path>
                match site_path_from(&rest[0], &rest[1], None) {
                    Ok(_) => match SitePath::parse(&rest[2]) {
                        Ok(path) => HelperRequest::SiteRemove { path },
                        Err(e) => return Err(InvocationError::invalid(e.to_string())),
                    },
                    Err(e) => return Err(InvocationError::invalid(e)),
                }
            }

            ("certbot-issue", n) if n >= 1 => {
                // <domain> [alias-domain ...] [email]   -- email is last if present
                let domain = match snpanel_core::Domain::parse(&rest[0]) {
                    Ok(d) => d,
                    Err(e) => return Err(InvocationError::invalid(e.to_string())),
                };
                let mut aliases = Vec::new();
                let mut email = None;
                for (i, arg) in rest[1..].iter().enumerate() {
                    if arg.contains('@') {
                        if i + 2 != rest.len() {
                            return Err(InvocationError::invalid(
                                "email must be the final certbot-issue argument",
                            ));
                        }
                        match snpanel_core::Email::parse(arg) {
                            Ok(e) => email = Some(e),
                            Err(e) => return Err(InvocationError::invalid(e.to_string())),
                        }
                        break;
                    }
                    match snpanel_core::Domain::parse(arg) {
                        Ok(d) => aliases.push(d),
                        Err(e) => return Err(InvocationError::invalid(e.to_string())),
                    }
                }
                HelperRequest::CertbotIssue {
                    domain,
                    aliases,
                    email,
                }
            }

            ("selinux-restore-site", 1) => match SitePath::parse(&rest[0]) {
                Ok(path) => HelperRequest::SelinuxRestoreSite { path },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },

            ("selinux-port-add", 1) => match Port::parse(&rest[0]) {
                Ok(port) => HelperRequest::SelinuxPortAdd { port },
                Err(e) => return Err(InvocationError::invalid(e.to_string())),
            },

            // Everything the Rust helper does not implement yet is handed to the
            // bash one. This is what makes the cutover safe: the panel calls one
            // path, and each operation moves to Rust independently.

            // --- the site operations Stage A implemented -----------------------
            //
            // The bash is the contract here: the panel already calls it with these
            // argument positions, so the mapping accepts exactly them. Where the
            // bash re-derives a safety check per arm, the typed request carries a
            // value that already guarantees it, and `site_path_from` is that
            // check expressed once.
            ("site-logs-read-many", n) if n >= 3 => {
                // <access|error> <lines> <domain>...
                let kind = match rest[0].as_str() {
                    "access" => LogKind::Access,
                    "error" => LogKind::Error,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "invalid log kind: {other}"
                        )))
                    }
                };
                let lines = lines_or(rest.get(1), 200)?;
                let mut domains = Vec::with_capacity(rest.len() - 2);
                for raw in &rest[2..] {
                    domains.push(
                        snpanel_core::Domain::parse(raw)
                            .map_err(|e| InvocationError::invalid(e.to_string()))?,
                    );
                }
                HelperRequest::SiteLogsReadMany {
                    domains,
                    kind,
                    lines,
                }
            }
            ("site-document-root-ensure", 3) => {
                // <site-user> <site-root> <relative-path>
                let root =
                    site_path_from(&rest[0], &rest[1], None).map_err(InvocationError::invalid)?;
                HelperRequest::SiteDocumentRootEnsure {
                    user: user_of(&rest[0])?,
                    root,
                    relative: rest[2].clone(),
                }
            }
            ("site-file-install", 4) => {
                // <site-user> <site-root> <relative-path> <staged-path>
                let root =
                    site_path_from(&rest[0], &rest[1], None).map_err(InvocationError::invalid)?;
                HelperRequest::SiteFileInstall {
                    user: user_of(&rest[0])?,
                    root,
                    relative: rest[2].clone(),
                    staged: rest[3].clone(),
                }
            }
            ("site-populate", 3) => {
                // <site-user> <site-root> <staged-source-dir>
                let root =
                    site_path_from(&rest[0], &rest[1], None).map_err(InvocationError::invalid)?;
                HelperRequest::SitePopulate {
                    user: user_of(&rest[0])?,
                    root,
                    source: rest[2].clone(),
                }
            }
            ("site-runtime-delete", 2) => {
                // <site-user> <path>. The path is checked against the user here
                // because it feeds a recursive delete on the other side.
                let path =
                    site_path_from(&rest[0], &rest[1], None).map_err(InvocationError::invalid)?;
                HelperRequest::SiteRuntimeDelete {
                    user: user_of(&rest[0])?,
                    path,
                }
            }
            ("site-runtime-ensure", 3) => {
                // <site-user> <path> <php-version|none>
                let path =
                    site_path_from(&rest[0], &rest[1], None).map_err(InvocationError::invalid)?;
                HelperRequest::SiteRuntimeEnsure {
                    user: user_of(&rest[0])?,
                    path,
                    php: php_or_none(&rest[2])?,
                }
            }
            ("site-runtime-move", 4) => {
                // <site-user> <old-path> <new-path> <php-version|none>
                //
                // The old path is not checked against the new owner: a site can
                // move between accounts, and the bash reads the old owner out of
                // the path for exactly that reason.
                let from = SitePath::parse(&rest[1])
                    .map_err(|e| InvocationError::invalid(e.to_string()))?;
                let to =
                    site_path_from(&rest[0], &rest[2], None).map_err(InvocationError::invalid)?;
                HelperRequest::SiteRuntimeMove {
                    user: user_of(&rest[0])?,
                    from,
                    to,
                    php: php_or_none(&rest[3])?,
                }
            }
            ("site-archive-extract", 7) => {
                // <site-user> <site-root> <archive> <destination> <zip|tar.gz>
                // <max-items> <max-bytes>
                let root =
                    site_path_from(&rest[0], &rest[1], None).map_err(InvocationError::invalid)?;
                let kind = match rest[4].as_str() {
                    "zip" => ArchiveKind::Zip,
                    "tar.gz" => ArchiveKind::TarGz,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "unsupported archive type: {other}"
                        )))
                    }
                };
                let max_items = rest[5].parse::<u32>().map_err(|_| {
                    InvocationError::invalid(format!("invalid archive limits: {}", rest[5]))
                })?;
                let max_bytes = rest[6].parse::<u64>().map_err(|_| {
                    InvocationError::invalid(format!("invalid archive limits: {}", rest[6]))
                })?;
                HelperRequest::SiteArchiveExtract {
                    user: user_of(&rest[0])?,
                    root,
                    archive_relative: rest[2].clone(),
                    destination_relative: rest[3].clone(),
                    kind,
                    max_items,
                    max_bytes,
                }
            }

            // --- WP-CLI --------------------------------------------------------
            ("wp", n) if n >= 1 => HelperRequest::Wp {
                args: rest.to_vec(),
            },
            ("wp-site", n) if n >= 2 => {
                // <site-user> [--php-version=<version>] <args...>
                //
                // The version is the *site's*, not whatever `php` points at: a
                // site on 8.4 driven by the 8.3 CLI has no mysqli, and every
                // `wp core update` on it fails.
                let user = user_of(&rest[0])?;
                let (php, args) = match rest[1].strip_prefix("--php-version=") {
                    Some(version) => (
                        Some(
                            snpanel_core::PhpVersion::parse(version)
                                .map_err(|e| InvocationError::invalid(e.to_string()))?,
                        ),
                        &rest[2..],
                    ),
                    None => (None, &rest[1..]),
                };
                if args.is_empty() {
                    return Err(InvocationError::invalid(
                        "usage: wp-site <site-user> [--php-version=<version>] <args...>",
                    ));
                }
                HelperRequest::WpSite {
                    user,
                    php,
                    args: args.to_vec(),
                }
            }

            // --- site applications ---------------------------------------------
            ("site-app-control", 3) => {
                let action = match rest[2].as_str() {
                    "start" => AppAction::Start,
                    "stop" => AppAction::Stop,
                    "restart" => AppAction::Restart,
                    "status" => AppAction::Status,
                    "is-active" => AppAction::IsActive,
                    "is-enabled" => AppAction::IsEnabled,
                    "enable" => AppAction::Enable,
                    "disable" => AppAction::Disable,
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "action not allowed: {other}"
                        )))
                    }
                };
                HelperRequest::SiteAppControl {
                    user: user_of(&rest[0])?,
                    app: app_of(&rest[1])?,
                    action,
                }
            }
            ("site-app-logs", 2) | ("site-app-logs", 3) => HelperRequest::SiteAppLogs {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
                lines: lines_or(rest.get(2), 200)?,
            },
            ("site-app-compose-ps", 2) => HelperRequest::SiteAppComposePs {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
            },
            ("site-app-compose-pull", 2) => HelperRequest::SiteAppComposePull {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
            },
            ("site-app-volume-usage", 1) => HelperRequest::SiteAppVolumeUsage {
                user: user_of(&rest[0])?,
            },
            ("site-app-dir-ensure", 2) => HelperRequest::SiteAppDirEnsure {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
            },
            ("site-app-delete", 2) => HelperRequest::SiteAppDelete {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
            },
            ("site-app-pull", 1) => HelperRequest::SiteAppPull {
                image: DockerImage::parse(&rest[0])
                    .map_err(|e| InvocationError::invalid(e.to_string()))?,
            },
            ("site-app-install-deps", 3) => HelperRequest::SiteAppInstallDeps {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
                node_major: node_major_of(&rest[2])?,
            },
            ("site-app-rename", 3) => HelperRequest::SiteAppRename {
                user: user_of(&rest[0])?,
                from: app_of(&rest[1])?,
                to: app_of(&rest[2])?,
            },
            ("site-app-export", 3) => HelperRequest::SiteAppExport {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
                dest: rest[2].clone(),
            },
            ("site-app-import", 3) => HelperRequest::SiteAppImport {
                user: user_of(&rest[0])?,
                app: app_of(&rest[1])?,
                source: rest[2].clone(),
            },
            ("site-app-write", n) if n >= 3 => {
                // <owner-user> <name> <node|docker|compose> [--flag=value ...]
                //
                // `compose` writes a second file and resolves bind mounts, and is
                // deliberately not ported (plan §8, Stage A). It must reach the
                // bash, so it is *unmapped* rather than invalid - the difference
                // decides whether the call falls through or is refused.
                let user = user_of(&rest[0])?;
                let app = app_of(&rest[1])?;
                let mut flags = AppFlags::default();
                for flag in &rest[3..] {
                    let Some((name, value)) = flag.split_once('=') else {
                        return Err(InvocationError::invalid(format!(
                            "unknown site-app-write option: {flag}"
                        )));
                    };
                    match name {
                        "--port" => flags.port = Some(value),
                        "--memory" => flags.memory = value,
                        "--node-major" => flags.node_major = Some(value),
                        "--exec" => flags.exec = Some(value),
                        "--arg" => flags.arg = value,
                        "--image" => flags.image = Some(value),
                        "--container-port" => flags.container_port = value,
                        "--cpus" => flags.cpus = value,
                        _ => {
                            return Err(InvocationError::invalid(format!(
                                "unknown site-app-write option: {flag}"
                            )))
                        }
                    }
                }
                let runtime = match rest[2].as_str() {
                    "node" => AppRuntime::Node {
                        node_major: node_major_of(flags.node_major.unwrap_or(""))?,
                        exec: match flags.exec.unwrap_or("") {
                            "node" => NodeExec::Node,
                            "npm" => NodeExec::Npm,
                            "npx" => NodeExec::Npx,
                            "yarn" => NodeExec::Yarn,
                            other => {
                                return Err(InvocationError::invalid(format!(
                                    "invalid start command: {other}"
                                )))
                            }
                        },
                        arg: start_argument(flags.arg)?,
                    },
                    "docker" => AppRuntime::Docker {
                        image: DockerImage::parse(flags.image.unwrap_or(""))
                            .map_err(|e| InvocationError::invalid(e.to_string()))?,
                        container_port: Port::parse(flags.container_port)
                            .map_err(|e| InvocationError::invalid(e.to_string()))?,
                        cpus_centi: cpus_centi(flags.cpus)?,
                    },
                    "compose" => return Err(InvocationError::unmapped(op)),
                    other => {
                        return Err(InvocationError::invalid(format!(
                            "invalid runtime: {other}"
                        )))
                    }
                };
                HelperRequest::SiteAppWrite {
                    user,
                    app,
                    runtime,
                    port: Port::parse(flags.port.unwrap_or(""))
                        .map_err(|e| InvocationError::invalid(e.to_string()))?,
                    memory_mb: memory_mb(flags.memory)?,
                }
            }

            _ => return Err(InvocationError::unmapped(op)),
        };
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// No stdin, and a loud failure if something reads it anyway.
    fn no_stdin() -> Vec<u8> {
        panic!("stdin was read for a verb that does not carry a payload");
    }

    fn map(parts: &[&str]) -> Result<HelperRequest, InvocationError> {
        HelperRequest::from_argv(&argv(parts), no_stdin)
    }

    /// The verbs Stage D added, and the argument counts the bash enforces.
    ///
    /// A verb that maps with the wrong arity is worse than one that does not
    /// map at all: the unmapped one falls through to the bash and still works,
    /// while a wrong arity is a refusal the customer sees.
    #[test]
    fn the_stage_d_verbs_map_with_the_bashs_arities() {
        // No arguments and no payload.
        for verb in ["waf-default-rules", "waf-custom-rules", "waf-update"] {
            assert!(map(&[verb]).is_ok(), "{verb} should map with no arguments");
            assert!(
                map(&[verb, "unexpected"]).is_err(),
                "{verb} takes no arguments"
            );
        }

        // No arguments, payload on stdin - so these get a real one. Using
        // `map` would trip the guard that catches a verb reading stdin when it
        // should not, which is exactly the guard these two are allowed past.
        let with_payload = |parts: &[&str]| {
            HelperRequest::from_argv(&argv(parts), || b"SecRuleEngine On\n".to_vec())
        };
        for verb in ["waf-custom-save", "http-flood-zones-save"] {
            assert!(with_payload(&[verb]).is_ok(), "{verb} should map");
            assert!(
                with_payload(&[verb, "unexpected"]).is_err(),
                "{verb} takes no arguments"
            );
        }

        // One argument, a panel username.
        for verb in ["panel-user-lock", "panel-user-unlock"] {
            assert!(map(&[verb, "alice"]).is_ok(), "{verb} alice");
            assert!(map(&[verb]).is_err(), "{verb} needs a user");
            assert!(map(&[verb, "alice", "extra"]).is_err(), "{verb} takes one");
            // The same refusal every other user-taking verb makes.
            assert!(map(&[verb, "root"]).is_err(), "{verb} root is reserved");
            assert!(map(&[verb, "UPPER"]).is_err(), "{verb} is not normalised");
        }
    }

    /// `panel-user-lock` and `panel-user-unlock` are one operation with a
    /// direction, and the direction has to survive the mapping.
    #[test]
    fn locking_and_unlocking_are_told_apart() {
        let locked = map(&["panel-user-lock", "alice"]).expect("lock");
        let unlocked = map(&["panel-user-unlock", "alice"]).expect("unlock");
        assert_eq!(locked.op_name(), "panel-user-lock");
        assert_eq!(unlocked.op_name(), "panel-user-unlock");
        // Compared through Debug rather than PartialEq: `HelperRequest`
        // carries a `SecretString` in other variants, and a derived equality
        // would compare secrets byte by byte in variable time.
        assert_ne!(format!("{locked:?}"), format!("{unlocked:?}"));
    }

    /// `firewall-reload` is an alias. The bash runs `firewall_apply` for
    /// `firewall-reload`, `ufw-reload` and `firewall-apply` alike, so all
    /// three have to arrive at the same request - not at three of them.
    #[test]
    fn the_firewall_reload_aliases_are_one_operation() {
        let apply = map(&["firewall-apply"]).expect("apply");
        for alias in ["firewall-reload", "ufw-reload"] {
            assert_eq!(
                format!("{:?}", map(&[alias]).expect(alias)),
                format!("{apply:?}"),
                "{alias}"
            );
        }
    }

    /// A payload verb must not consume stdin when the verb is unknown.
    ///
    /// Stage B's finding, re-checked for the two payload verbs added here: the
    /// bash fallthrough reads the same stdin, and a closure that had already
    /// been called would hand it an empty file.
    #[test]
    fn an_unknown_verb_leaves_the_payload_alone() {
        let called = std::cell::Cell::new(false);
        let argv: Vec<String> = vec!["no-such-verb".into(), "x".into()];
        let err = HelperRequest::from_argv(&argv, || {
            called.set(true);
            Vec::new()
        })
        .expect_err("unknown");
        assert!(err.is_unmapped());
        assert!(!called.get(), "stdin was consumed by an unmapped verb");
    }

    // -- the distinction the cutover rests on --------------------------------

    #[test]
    fn a_verb_this_build_does_not_answer_is_unmapped_so_the_bash_gets_it() {
        let e = map(&["docker-install"]).expect_err("not ported");
        assert!(e.is_unmapped(), "got {e:?}");
    }

    #[test]
    fn a_mapped_verb_with_bad_arguments_is_invalid_and_must_not_fall_through() {
        // The whole point of the two cases: this must NOT reach the bash. An
        // argument refused here getting a second hearing from a looser parser
        // is how a rejected path gets in anyway.
        let e = map(&["site-app-control", "alice", "app", "sudo"]).expect_err("bad action");
        assert!(
            !e.is_unmapped(),
            "a refused argument must not fall through: {e:?}"
        );
        assert!(e.to_string().contains("action not allowed"), "{e}");
    }

    #[test]
    fn an_unmapped_verb_does_not_read_stdin() {
        // The bash helper reads the payload itself when the call falls
        // through, so reading it here to decide would consume the very thing
        // the fallthrough needs. `no_stdin` panics if this regresses.
        let touched = Cell::new(false);
        let e = HelperRequest::from_argv(&argv(&["php-install", "8.4"]), || {
            touched.set(true);
            Vec::new()
        })
        .expect_err("not ported");
        assert!(e.is_unmapped());
        assert!(
            !touched.get(),
            "stdin was read before delegating to the bash"
        );
    }

    #[test]
    fn a_verb_that_carries_a_payload_does_read_stdin() {
        let request =
            HelperRequest::from_argv(&argv(&["cron-write"]), || b"* * * * * true\n".to_vec())
                .expect("mapped");
        match request {
            HelperRequest::CronWrite { content, .. } => {
                assert_eq!(content, "* * * * * true\n");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -- every site verb the bash declares -----------------------------------

    #[test]
    fn every_site_verb_maps() {
        // Stage A's exit measured request variants and dispatch arms. It did
        // not measure this, and twenty-four of them were missing here - which
        // meant the panel's own call shape reached the bash for all of them.
        let cases: &[&[&str]] = &[
            &["mkdir-site", "/home/alice/example.com"],
            &[
                "rm-site",
                "alice",
                "/home/alice/example.com",
                "/home/alice/example.com",
            ],
            &["fix-permissions", "/home/alice/example.com", "alice"],
            &["site-path-fix", "/home/alice/example.com", "alice"],
            &["site-log-read", "example.com", "access", "50"],
            &["site-log-clear", "example.com", "error"],
            &[
                "site-logs-read-many",
                "access",
                "50",
                "example.com",
                "two.example.com",
            ],
            &[
                "site-document-root-ensure",
                "alice",
                "/home/alice/example.com",
                "public_html",
            ],
            &[
                "site-file-install",
                "alice",
                "/home/alice/example.com",
                "index.php",
                "/tmp/snpanel-upload-x/f",
            ],
            &[
                "site-populate",
                "alice",
                "/home/alice/example.com",
                "/var/lib/snpanel/import/x",
            ],
            &["site-runtime-delete", "alice", "/home/alice/example.com"],
            &[
                "site-runtime-ensure",
                "alice",
                "/home/alice/example.com",
                "8.3",
            ],
            &[
                "site-runtime-ensure",
                "alice",
                "/home/alice/example.com",
                "none",
            ],
            &[
                "site-runtime-move",
                "alice",
                "/home/bob/old.com",
                "/home/alice/new.com",
                "8.3",
            ],
            &[
                "site-archive-extract",
                "alice",
                "/home/alice/example.com",
                "a.zip",
                "dest",
                "zip",
                "1000",
                "0",
            ],
            &[
                "site-file-write",
                "alice",
                "/home/alice/example.com",
                "index.php",
            ],
            &[
                "site-chmod",
                "alice",
                "/home/alice/example.com",
                "/home/alice/example.com/x",
                "0644",
            ],
            &["wp", "core", "version"],
            &["wp-site", "alice", "--php-version=8.3", "core", "version"],
            &["wp-site", "alice", "core", "version"],
            &["site-app-control", "alice", "myapp", "restart"],
            &["site-app-logs", "alice", "myapp"],
            &["site-app-logs", "alice", "myapp", "500"],
            &["site-app-compose-ps", "alice", "myapp"],
            &["site-app-compose-pull", "alice", "myapp"],
            &["site-app-volume-usage", "alice"],
            &["site-app-dir-ensure", "alice", "myapp"],
            &["site-app-delete", "alice", "myapp"],
            &["site-app-pull", "nginx:1.27"],
            &["site-app-install-deps", "alice", "myapp", "22"],
            &["site-app-rename", "alice", "myapp", "yourapp"],
            &[
                "site-app-export",
                "alice",
                "myapp",
                "/var/backups/snpanel/a.tar",
            ],
            &[
                "site-app-import",
                "alice",
                "myapp",
                "/var/backups/snpanel/a.tar",
            ],
            &[
                "site-app-write",
                "alice",
                "myapp",
                "node",
                "--port=21001",
                "--node-major=22",
                "--exec=npm",
                "--arg=start",
            ],
            &[
                "site-app-write",
                "alice",
                "myapp",
                "docker",
                "--port=21001",
                "--image=nginx:1.27",
            ],
        ];
        for case in cases {
            let result = HelperRequest::from_argv(&argv(case), || b"payload".to_vec());
            assert!(result.is_ok(), "{:?} did not map: {:?}", case, result.err());
        }
    }

    #[test]
    fn the_compose_runtime_falls_through_to_the_bash() {
        // It writes a second file and resolves bind mounts, and is
        // deliberately not ported. Unmapped, not invalid: it has to reach the
        // bash or a customer's compose application stops being deployable.
        let e = map(&[
            "site-app-write",
            "alice",
            "myapp",
            "compose",
            "--port=21001",
        ])
        .expect_err("not ported");
        assert!(e.is_unmapped(), "compose must fall through, got {e:?}");
    }

    // -- the checks the bash makes, kept ------------------------------------

    #[test]
    fn a_site_path_outside_the_named_users_home_is_refused() {
        // This one feeds a recursive delete on the other side.
        let e = map(&["site-runtime-delete", "alice", "/home/bob/example.com"])
            .expect_err("bob's directory is not alice's");
        assert!(!e.is_unmapped());
        assert!(e.to_string().contains("does not belong to"), "{e}");
    }

    #[test]
    fn a_move_may_leave_another_users_home_but_must_arrive_in_the_named_ones() {
        // A site can move between accounts, so the old path is not checked
        // against the new owner - but the new path is.
        assert!(map(&[
            "site-runtime-move",
            "alice",
            "/home/bob/s.com",
            "/home/alice/s.com",
            "none"
        ])
        .is_ok());
        let e = map(&[
            "site-runtime-move",
            "alice",
            "/home/bob/s.com",
            "/home/bob/s.com",
            "none",
        ])
        .expect_err("arriving in bob's home");
        assert!(e.to_string().contains("does not belong to"), "{e}");
    }

    #[test]
    fn cpu_limits_become_hundredths_exactly() {
        let request = map(&[
            "site-app-write",
            "alice",
            "myapp",
            "docker",
            "--port=21001",
            "--image=nginx:1.27",
            "--cpus=1.5",
        ])
        .expect("mapped");
        match request {
            HelperRequest::SiteAppWrite {
                runtime: AppRuntime::Docker { cpus_centi, .. },
                ..
            } => {
                assert_eq!(cpus_centi, 150);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn the_memory_range_the_bash_enforces_is_enforced_here() {
        for bad in ["8", "32768", "abc"] {
            let e = map(&[
                "site-app-write",
                "alice",
                "myapp",
                "docker",
                "--port=21001",
                "--image=nginx:1.27",
                &format!("--memory={bad}"),
            ])
            .expect_err("out of range");
            assert!(!e.is_unmapped(), "{bad} must be refused, not delegated");
        }
        assert!(map(&[
            "site-app-write",
            "alice",
            "myapp",
            "docker",
            "--port=21001",
            "--image=nginx:1.27",
            "--memory=64",
        ])
        .is_ok());
    }

    #[test]
    fn a_one_digit_node_major_is_refused_the_way_the_bash_refuses_it() {
        // `^[1-9][0-9]$`: node 8 is not expressible, and neither is node 220.
        assert!(map(&["site-app-install-deps", "alice", "myapp", "8"]).is_err());
        assert!(map(&["site-app-install-deps", "alice", "myapp", "220"]).is_err());
        assert!(map(&["site-app-install-deps", "alice", "myapp", "22"]).is_ok());
    }

    #[test]
    fn an_unknown_site_app_write_flag_is_refused_rather_than_ignored() {
        let e = map(&[
            "site-app-write",
            "alice",
            "myapp",
            "docker",
            "--port=21001",
            "--image=nginx:1.27",
            "--privileged=1",
        ])
        .expect_err("unknown flag");
        assert!(!e.is_unmapped());
        assert!(
            e.to_string().contains("unknown site-app-write option"),
            "{e}"
        );
    }

    #[test]
    fn wp_site_needs_something_to_run() {
        assert!(map(&["wp-site", "alice", "--php-version=8.3"]).is_err());
    }
}
