//! The protocol between `snpanel-api` (unprivileged) and `snpanel-helper` (root).
//!
//! Plan §4.3. This replaces `sudo -n /usr/local/sbin/snpanel-helper <subcmd>
//! <args...>` with a serde message over a Unix socket. The point is not the
//! transport, it is the types:
//!
//! > `Domain`, `PanelUsername`, `SitePath` have custom `Deserialize` impls -
//! > a message carrying an invalid value **fails to deserialize at all**.
//!
//! So the root side, having received a `Domain`, knows it holds a domain. The
//! whole class of shell-quoting bugs at the privilege boundary disappears with
//! the shell, and the remaining validation cannot be forgotten because it
//! happens before the handler is reached.
//!
//! Phase 2 fills in all ~130 variants (plan Appendix B). The ones here are the
//! set Phase 0/1 needs, plus enough of each domain to pin the shape.

mod argv;
pub use argv::InvocationError;

use serde::{Deserialize, Serialize};
use snpanel_core::{
    AppName, DockerImage, Domain, Email, IpOrCidr, PanelUsername, PhpVersion, Port, SecretString,
    SitePath,
};

/// The socket the helper listens on, created by systemd socket activation.
pub const SOCKET_PATH: &str = "/run/snpanel/helper.sock";

/// Maximum size of a single request. A file write can be large, but not
/// unbounded - an unbounded read from a socket is a memory-exhaustion bug.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VhostKind {
    Wordpress,
    Php,
    Static,
    Application,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Reload,
    Status,
}

/// The two archive formats the panel unpacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveKind {
    Zip,
    #[serde(rename = "tar.gz")]
    TarGz,
}

impl ArchiveKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::TarGz => "tar.gz",
        }
    }
}

/// How a site application is started.
///
/// Source: the `--exec`, `--image` and related flags of `site-app-write`. A
/// node application names a start command and an argument; a container names
/// an image, the port inside it and a CPU share. They are different shapes,
/// so they are different variants rather than a struct of optionals where
/// half the fields are meaningless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AppRuntime {
    Node {
        node_major: u8,
        /// Source: the `case` on `$app_exec`.
        exec: NodeExec,
        /// Source: `^[A-Za-z0-9._@/-]{1,120}$`.
        arg: String,
    },
    Docker {
        image: DockerImage,
        container_port: Port,
        /// Whole CPUs, in hundredths, so "1.5" is 150. An integer because a
        /// float in a unit file is a rounding argument waiting to happen.
        cpus_centi: u32,
    },
}

/// The four start commands a node application may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeExec {
    Node,
    Npm,
    Npx,
    Yarn,
}

impl NodeExec {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Npm => "npm",
            Self::Npx => "npx",
            Self::Yarn => "yarn",
        }
    }
}

/// What may be done to a site application's unit.
///
/// Source: the `is_in` allowlist in `site-app-control`. Eight actions, and no
/// way to express a ninth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppAction {
    Start,
    Stop,
    Restart,
    Status,
    IsActive,
    IsEnabled,
    Enable,
    Disable,
}

impl AppAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Status => "status",
            Self::IsActive => "is-active",
            Self::IsEnabled => "is-enabled",
            Self::Enable => "enable",
            Self::Disable => "disable",
        }
    }
}

/// Which of a site's two nginx logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogKind {
    Access,
    Error,
}

/// Transport protocol for a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// How aggressively the OWASP Core Rule Set acts.
///
/// `detect` is not a half-measure: it scores requests and blocks nothing, and
/// the verdict lands in the audit log. That is where to look when a site owner
/// asks why a request was or was not flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrsMode {
    Off,
    Detect,
    Block,
}

/// File mode as an octal value, e.g. 0o644.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileMode(pub u32);

impl FileMode {
    /// C34: files 644, directories 755.
    pub const FILE: FileMode = FileMode(0o644);
    pub const DIR: FileMode = FileMode(0o755);
    /// C34: `wp-config.php`, `.env` and `.my.cnf` go back to 640 after any
    /// bulk permission pass.
    pub const SENSITIVE: FileMode = FileMode(0o640);
}

/// Services the helper is allowed to act on.
///
/// Source: `ALLOWED_SERVICES` in the bash helper. Anything outside this list,
/// and outside the `phpX.Y-fpm` pattern, cannot be constructed - so a request
/// naming an arbitrary unit fails to deserialize rather than reaching
/// `systemctl`.
pub const ALLOWED_SERVICES: &[&str] = &[
    "nginx",
    "mariadb",
    "redis-server",
    "php8.3-fpm",
    "php8.4-fpm",
    "snpanel-api",
];

/// Services that must never be stopped: stopping one takes the panel down and
/// removes the means to bring it back.
///
/// Source: the explicit refusal in the bash `systemctl` arm.
pub const UNSTOPPABLE_SERVICES: &[&str] = &["snpanel-api", "redis-server"];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ServiceError {
    #[error("service not allowed: {0}")]
    NotAllowed(String),
}

/// A systemd unit the helper may drive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceName(String);

impl ServiceName {
    pub fn parse(raw: &str) -> Result<Self, ServiceError> {
        let name = raw.trim();
        if ALLOWED_SERVICES.contains(&name) {
            return Ok(Self(name.to_string()));
        }
        // The bash also accepts any phpX.Y-fpm whose pool config exists on
        // disk. The shape is accepted here; the helper confirms the file
        // exists before acting, exactly as `is_allowed_service` does.
        if let Some(version) = name
            .strip_prefix("php")
            .and_then(|v| v.strip_suffix("-fpm"))
        {
            let mut parts = version.split('.');
            if let (Some(major), Some(minor), None) = (parts.next(), parts.next(), parts.next()) {
                let numeric = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
                if numeric(major) && numeric(minor) {
                    return Ok(Self(name.to_string()));
                }
            }
        }
        Err(ServiceError::NotAllowed(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for a dynamically accepted `phpX.Y-fpm`, whose config the helper
    /// must still confirm exists on disk.
    pub fn is_php_fpm(&self) -> bool {
        !ALLOWED_SERVICES.contains(&self.0.as_str())
    }

    /// The version out of a `phpX.Y-fpm` name.
    pub fn php_version(&self) -> Option<&str> {
        self.0
            .strip_prefix("php")
            .and_then(|v| v.strip_suffix("-fpm"))
    }

    pub fn may_stop(&self) -> bool {
        !UNSTOPPABLE_SERVICES.contains(&self.0.as_str())
    }
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ServiceName {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        ServiceName::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// A command the terminal endpoint is allowed to run.
///
/// C30: the allowlist is an allowlist. The binary is checked on construction,
/// so a `HelperRequest::TerminalExec` cannot carry an arbitrary command - it
/// fails to deserialize instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowlistedArgv {
    binary: String,
    args: Vec<String>,
}

/// Commands run through the PHP binary with `open_basedir` set.
///
/// Source: the `php`, `composer`, `wp`, `phpunit` and `artisan` arms. Each
/// appends its own tool directory to the basedir so the interpreter can read
/// the phar it is being asked to run.
pub const TERMINAL_PHP_HOSTED: &[&str] = &["artisan", "composer", "php", "phpunit", "wp"];

/// Commands whose every argument is resolved and required to land inside the
/// user's home before they start.
///
/// Source: the arms that call `require_terminal_path_args`. These can be
/// pointed at a path, so they are.
pub const TERMINAL_PATH_CHECKED: &[&str] = &[
    "awk", "cat", "chmod", "chown", "cp", "df", "diff", "du", "file", "find", "grep", "head",
    "less", "ls", "mkdir", "mv", "rm", "rmdir", "sed", "sort", "stat", "tail", "tar", "touch",
    "uniq", "unzip", "wc", "zip",
];

/// Commands that fetch, and whose output path is checked wherever `-o`/`-O`
/// names one.
///
/// Source: the arms that call `require_terminal_download_args`.
pub const TERMINAL_DOWNLOAD_CHECKED: &[&str] = &["curl", "wget"];

/// Everything else: commands that cannot be pointed at a path, so their
/// arguments are not inspected.
pub const TERMINAL_PLAIN: &[&str] = &[
    "basename", "clear", "date", "dirname", "echo", "git", "id", "node", "npm", "npx", "printenv",
    "pwd", "realpath", "uname", "which", "whoami", "yarn",
];

/// Source: the `case "$cmd"` in `snpanel-helper.sh terminal-exec`.
///
/// All 52, in one list for membership tests. The groups above are what
/// decides how each is run, and a command that appears here but in none of
/// them would be accepted and then have no arm - which
/// `every_allowed_command_belongs_to_exactly_one_group` refuses.
pub const TERMINAL_ALLOWLIST: &[&str] = &[
    "artisan", "awk", "basename", "cat", "chmod", "chown", "clear", "composer", "cp", "curl",
    "date", "df", "diff", "dirname", "du", "echo", "file", "find", "git", "grep", "head", "id",
    "less", "ls", "mkdir", "mv", "node", "npm", "npx", "php", "phpunit", "printenv", "pwd",
    "realpath", "rm", "rmdir", "sed", "sort", "stat", "tail", "tar", "touch", "uname", "uniq",
    "unzip", "wc", "wget", "which", "whoami", "wp", "yarn", "zip",
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArgvError {
    #[error("command is empty")]
    Empty,
    #[error("'{0}' is not on the terminal allowlist")]
    NotAllowed(String),
    #[error("argument contains a NUL byte")]
    NulByte,
}

impl AllowlistedArgv {
    pub fn parse(binary: &str, args: Vec<String>) -> Result<Self, ArgvError> {
        let binary = binary.trim();
        if binary.is_empty() {
            return Err(ArgvError::Empty);
        }
        // A path is not a command name: only the bare name is matched, so
        // "/usr/bin/php" and "../../bin/sh" are both refused.
        if !TERMINAL_ALLOWLIST.contains(&binary) {
            return Err(ArgvError::NotAllowed(binary.to_string()));
        }
        if args.iter().any(|a| a.contains('\0')) {
            return Err(ArgvError::NulByte);
        }
        Ok(Self {
            binary: binary.to_string(),
            args,
        })
    }

    pub fn binary(&self) -> &str {
        &self.binary
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }
}

impl<'de> Deserialize<'de> for AllowlistedArgv {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            binary: String,
            args: Vec<String>,
        }
        let raw = Raw::deserialize(d)?;
        AllowlistedArgv::parse(&raw.binary, raw.args).map_err(serde::de::Error::custom)
    }
}

/// The protocol version. Bumped whenever a variant's fields change meaning.
///
/// This exists because `#[serde(deny_unknown_fields)]` does **not** work on an
/// internally tagged enum - serde buffers the content to read the tag and the
/// attribute is silently ignored. Without something in its place, a newer API
/// sending `{"op":"site-chmod", ..., "recursive":true}` to an older helper
/// that predates the `recursive` field would have it quietly dropped, and the
/// chmod would apply to one file instead of a tree. The envelope makes that a
/// loud refusal instead.
pub const PROTOCOL_VERSION: u32 = 1;

/// What actually goes over the socket:
///
/// ```json
/// {"version": 1, "request": {"op": "nginx-reload"}}
/// ```
///
/// The request is nested rather than flattened. `deny_unknown_fields` and
/// `flatten` are mutually exclusive in serde - combining them rejects every
/// message - so nesting is what makes the strict check on this struct real.
///
/// Note the limitation this does *not* remove: serde still ignores an unknown
/// field inside the `request` object, because the enum is internally tagged.
/// `version` is what covers that case. Any change to a variant's fields bumps
/// [`PROTOCOL_VERSION`], so a mismatched pair refuses to talk at all rather
/// than half-understanding each other.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub request: HelperRequest,
}

impl Envelope {
    pub fn new(request: HelperRequest) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request,
        }
    }

    /// Parse a request off the wire, refusing anything from a different
    /// protocol version.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::TooLarge(bytes.len()));
        }
        let envelope: Envelope =
            serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        if envelope.version != PROTOCOL_VERSION {
            return Err(ProtocolError::VersionMismatch {
                got: envelope.version,
                expected: PROTOCOL_VERSION,
            });
        }
        Ok(envelope)
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("HelperRequest is always serialisable")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("request is {0} bytes, over the limit")]
    TooLarge(usize),
    #[error("request is malformed: {0}")]
    Malformed(String),
    #[error("protocol version {got}, but this helper speaks {expected}")]
    VersionMismatch { got: u32, expected: u32 },
}

/// A request to the privileged helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum HelperRequest {
    // --- system ---
    ServiceControl {
        service: ServiceName,
        action: ServiceAction,
    },
    DaemonReload,

    // --- user ---
    PanelUserEnsure {
        username: PanelUsername,
        password: Option<SecretString>,
    },
    PanelUserDelete {
        username: PanelUsername,
    },
    PanelUserPassword {
        username: PanelUsername,
        password: SecretString,
    },

    // --- nginx ---
    NginxWriteSite {
        domain: Domain,
        rendered: String,
        kind: VhostKind,
    },
    NginxTest,
    NginxReload,
    NginxCustomWrite {
        domain: Domain,
        content: String,
    },
    NginxCustomDelete {
        domain: Domain,
    },

    // --- ssl ---
    CertbotIssue {
        domain: Domain,
        aliases: Vec<Domain>,
        /// Optional, because the bash allows issuing without one and falls
        /// back to `--register-unsafely-without-email`. Making it mandatory
        /// here would refuse a request the bash accepts.
        email: Option<Email>,
    },
    CertbotRenew {
        domain: Option<Domain>,
    },
    CertbotDelete {
        domain: Domain,
    },

    // --- site ---
    /// Unpack an archive inside a site.
    ///
    /// The helper does not parse the archive: it runs `snpanel-extract` as
    /// the site's own user. An archive is attacker-controlled input and this
    /// process is root.
    SiteArchiveExtract {
        user: PanelUsername,
        root: SitePath,
        archive_relative: String,
        destination_relative: String,
        kind: ArchiveKind,
        max_items: u32,
        max_bytes: u64,
    },
    /// Write an application's systemd unit.
    ///
    /// Only the node and docker runtimes. `compose` writes a second file and
    /// resolves bind mounts; it stays in the bash until it can be done
    /// properly, and the helper falls through for it.
    SiteAppWrite {
        user: PanelUsername,
        app: AppName,
        runtime: AppRuntime,
        port: Port,
        memory_mb: u32,
    },
    /// Rename an application, moving its directory with it.
    SiteAppRename {
        user: PanelUsername,
        from: AppName,
        to: AppName,
    },
    /// Everything an application owns, in one tar.
    ///
    /// `dest` must be under the backup root; the helper writes it as root, so
    /// a path that could leave that tree would be a way to write anywhere.
    SiteAppExport {
        user: PanelUsername,
        app: AppName,
        dest: String,
    },
    /// Restore an application from an export.
    SiteAppImport {
        user: PanelUsername,
        app: AppName,
        source: String,
    },
    /// Create an application's directory under its owner's home.
    SiteAppDirEnsure {
        user: PanelUsername,
        app: AppName,
    },
    /// Remove an application's runtime, leaving its files.
    ///
    /// The unit, the compose project, the container and the env file go. The
    /// directory does not: removing a runtime never implies removing
    /// somebody's code.
    SiteAppDelete {
        user: PanelUsername,
        app: AppName,
    },
    /// Pull a container image.
    SiteAppPull {
        image: DockerImage,
    },
    /// `npm install` for a node application, as its owner.
    SiteAppInstallDeps {
        user: PanelUsername,
        app: AppName,
        node_major: u8,
    },
    /// Start, stop or query a site application's systemd unit.
    ///
    /// `action` is an enum rather than a string: the bash allowlists eight
    /// verbs, and the point of a type here is that the ninth cannot be
    /// expressed.
    SiteAppControl {
        user: PanelUsername,
        app: AppName,
        action: AppAction,
    },
    /// The last lines of a site application's journal.
    SiteAppLogs {
        user: PanelUsername,
        app: AppName,
        lines: u32,
    },
    /// The state of a compose application's containers.
    SiteAppComposePs {
        user: PanelUsername,
        app: AppName,
    },
    /// Pull the images a compose application uses.
    SiteAppComposePull {
        user: PanelUsername,
        app: AppName,
    },
    /// Total bytes in a user's Docker named volumes.
    ///
    /// They live under /var/lib/docker, which the panel user cannot read, so
    /// without this a customer's container data is invisible to the quota.
    SiteAppVolumeUsage {
        user: PanelUsername,
    },
    /// Move a site's tree, taking its PHP pool with it.
    ///
    /// `from` carries its own user: a site can move between accounts, and the
    /// pool to remove is named after where it was, not where it is going.
    SiteRuntimeMove {
        user: PanelUsername,
        from: SitePath,
        to: SitePath,
        php: Option<PhpVersion>,
    },
    /// The site root as a path, and the PHP version it runs - if any.
    ///
    /// `php` is optional because the caller sends the string "none" for a
    /// site with no PHP. A static site gets no pool, rather than a pool for a
    /// version that is not installed.
    SiteRuntimeEnsure {
        user: PanelUsername,
        path: SitePath,
        php: Option<PhpVersion>,
    },
    /// The site root as a path, not derived from a domain.
    ///
    /// The caller passes `root_path` from the database, and this feeds a
    /// recursive delete: deriving the location instead of being told it would
    /// remove the wrong directory for any site that has been moved. A
    /// `SitePath` is `require_managed_path` expressed as a type - absolute,
    /// traversal-free, under `/home/<user>/`.
    SiteRuntimeDelete {
        user: PanelUsername,
        path: SitePath,
    },
    SiteFileWrite {
        path: SitePath,
        content: Vec<u8>,
        mode: FileMode,
    },
    SiteChmod {
        path: SitePath,
        mode: FileMode,
        recursive: bool,
    },

    // --- firewall ---
    FirewallApply,
    FirewallFlush,
    FirewallStatus,
    /// One-way migration from the iptables/ipset backend (plan §6.3).
    FirewallMigrateNft,

    // --- selinux (no-op off the RHEL family) ---
    SelinuxRestoreSite {
        path: SitePath,
    },
    SelinuxPortAdd {
        port: Port,
    },

    // --- firewall rules (rules.tsv) ---
    FirewallAllowIp {
        ip: IpOrCidr,
        port: Option<Port>,
        protocol: Protocol,
    },
    FirewallDenyIp {
        ip: IpOrCidr,
        port: Option<Port>,
        protocol: Protocol,
    },
    FirewallAllowPort {
        port: Port,
        protocol: Protocol,
    },
    FirewallPanelAllowPort {
        port: Port,
    },
    FirewallDelete {
        id: u32,
    },
    FirewallEnable,
    FirewallDisable,
    FirewallList,

    // --- site ---
    SiteMkdir {
        path: SitePath,
    },
    SiteRemove {
        path: SitePath,
    },
    SiteFixPermissions {
        path: SitePath,
        user: PanelUsername,
    },
    SiteLogRead {
        domain: Domain,
        kind: LogKind,
        lines: u32,
    },
    SiteLogClear {
        domain: Domain,
        kind: LogKind,
    },
    /// Run WP-CLI as the web user.
    ///
    /// `args` is a vector, not a string: there is no shell here to quote for.
    Wp {
        args: Vec<String>,
    },
    /// Run WP-CLI as a site's own user, under that site's PHP.
    ///
    /// `php` is the version the *site* runs, which is not always what `php`
    /// points at. A site on 8.4 driven by the 8.3 CLI has no mysqli, and
    /// every `wp core update` fails on it.
    WpSite {
        user: PanelUsername,
        php: Option<PhpVersion>,
        args: Vec<String>,
    },
    /// Replace a site's tree from a panel-staged directory.
    ///
    /// Used by the importer and by a full-user restore. The source has to sit
    /// in the panel's staging area: this deletes the site's contents before
    /// copying, so a source that turned out to be somewhere else would be
    /// discovered far too late.
    SitePopulate {
        user: PanelUsername,
        root: SitePath,
        source: String,
    },
    /// Move a panel-staged upload into a site, as the site's user.
    ///
    /// `staged` is a path under the panel's upload staging area rather than
    /// anywhere on disk: the helper re-checks it after resolution, because a
    /// symlink placed there would otherwise name any file on the machine.
    SiteFileInstall {
        user: PanelUsername,
        root: SitePath,
        relative: String,
        staged: String,
    },
    /// Create a site's document root and harden every directory down to it.
    ///
    /// `relative` is a path *fragment* under the site root, not a path: the
    /// helper builds the target itself so a caller cannot name somewhere else.
    SiteDocumentRootEnsure {
        user: PanelUsername,
        root: SitePath,
        relative: String,
    },
    /// Every named site's log in one round trip.
    ///
    /// The reply is not JSON: each site contributes a `\x1f<domain>\n` header
    /// followed by its log, because the caller wants the bytes of a log file
    /// and wrapping megabytes of them in JSON strings would cost more than the
    /// round trips this saves.
    SiteLogsReadMany {
        domains: Vec<Domain>,
        kind: LogKind,
        lines: u32,
    },

    // --- ssl ---
    SslCertInfo {
        domain: Domain,
    },
    PanelSslSelfsigned {
        host: String,
        port: Port,
    },
    PanelSslDomains,
    PanelSniSync,

    // --- php ---
    PhpOpcacheSet {
        version: PhpVersion,
        enabled: bool,
    },
    /// The administrator's ini, validated against a seven-directive allowlist
    /// before root installs it. The panel renders the content; the helper does
    /// not invent it, which is what the bash does and what keeps the two in
    /// step.
    PhpConfigWrite {
        version: PhpVersion,
        content: String,
    },

    // --- misc ---
    Ipv6Status,
    Ipv6Enable,
    Ipv6Disable,
    Ipv6Apply,
    TimeStatus,
    TimeSync,
    CronList {
        user: Option<PanelUsername>,
    },
    CronWrite {
        user: Option<PanelUsername>,
        content: String,
    },
    FastcgiCacheClear,
    ServiceStatus {
        service: ServiceName,
    },
    UpdatesStatus,
    UpdatesOsRun,
    UpdatesOsAuto {
        enable: bool,
    },

    // --- waf / malware ---
    WafStatus,
    WafCrsStatus,
    WafCrsMode {
        mode: CrsMode,
    },
    WafSiteSave {
        domain: Domain,
        content: String,
    },
    WafSiteDelete {
        domain: Domain,
    },
    /// `maldet-scan <job-id> <all|recent> <days> <path>...`
    ///
    /// The paths stay `String`s: the helper resolves them and then insists on
    /// `/` or something under `/home`, which is a rule about where a resolved
    /// path *lands* and not a shape a type can carry.
    MaldetScan {
        job: String,
        mode: String,
        days: String,
        paths: Vec<String>,
    },
    /// `malware-scan-server <job-id>` - the whole machine, through clamd.
    MalwareScanServer {
        job: String,
    },
    /// `node-install` - one Node major under /opt/snpanel/node.
    NodeInstall {
        major: String,
    },
    /// `certbot-dns-cloudflare-install` - the DNS-01 plugin wildcards need.
    CertbotDnsCloudflareInstall,
    /// `clamav-install` - the on-demand malware engine.
    ClamavInstall,
    /// `maldet-update-sigs` - refresh LMD's and ClamAV's signatures.
    /// `maldet-install` - download and install Linux Malware Detect.
    ///
    /// Minutes, not seconds: it fetches a tarball from rfxn.com and runs a
    /// third-party installer, so the caller gives it a 600s budget.
    MaldetInstall,

    /// `maldet-monitor <start|stop|status>` - LMD's real-time (Level 2)
    /// inotify monitor.
    MaldetMonitor {
        action: String,
    },

    MaldetUpdateSigs,
    /// `nginx-upgrade-map-ensure` - the http-level `map` a proxied vhost needs
    /// before nginx will load at all.
    NginxUpgradeMapEnsure,
    /// `updates-panel-run` - start the panel's own update, detached.
    UpdatesPanelRun,
    /// `php-pools-retune` - rewrite every site pool against the machine as
    /// it is now.
    PhpPoolsRetune,
    /// `php-tune-write` - the auto-tuner's `95-snpanel-tune.ini`.
    ///
    /// The file is on stdin because it is generated from the machine's RAM and
    /// CPU count and runs to a dozen directives; the version names which
    /// PHP it is for.
    PhpTuneWrite {
        version: PhpVersion,
        content: String,
    },
    /// `php-install <version>` - a PHP version and SNPanel's extension set.
    ///
    /// Minutes: it may add the ondrej PPA, refresh the package lists and
    /// download the ionCube loader before installing fourteen packages.
    PhpInstall {
        version: PhpVersion,
    },

    /// `waf-install` - the nginx ModSecurity module and SNPanel's rules.
    ///
    /// Debian only; refused with the reason on EL, where the connector is not
    /// packaged at all.
    WafInstall,

    /// `firewall-blocklist-run` - download every configured list, normalise
    /// it and reload the firewall with the result.
    ///
    /// Runs from `snpanel-blocklist.timer` as well as from the panel button,
    /// and takes minutes on a slow link: the lists run to millions of rows.
    FirewallBlocklistRun,

    /// `firewall-blocklist-status` - the URLs, the loaded sets and the timer.
    FirewallBlocklistStatus,

    /// `firewall-blocklist-add` / `firewall-blocklist-delete` - the list of
    /// URLs the nightly refresh downloads from.
    ///
    /// The URL is a `String` rather than a parsed type because the bash's
    /// check is a shape (`^https?://\S+$`) and not a URL grammar; parsing it
    /// more strictly here would refuse lists the panel already has.
    FirewallBlocklistUrl {
        url: String,
        add: bool,
    },
    /// `manual-ssl-install` / `manual-ssl-remove` - a certificate an
    /// administrator uploaded.
    ///
    /// The certificate arrives as JSON on stdin, never in argv: a private key
    /// in a command line is readable in `/proc/<pid>/cmdline` by every account
    /// on the machine for as long as the process lives (C37).
    ManualSsl {
        domain: Domain,
        install: bool,
        payload: String,
    },
    /// `docker-install` - the container runtime the Application addon needs.
    DockerInstall,
    /// `docker-status` - installed, running, and what the images cost.
    DockerStatus,
    /// `docker-prune` - dangling layers and build cache only.
    DockerPrune,
    /// `node-list` - the Node majors installed under /opt/snpanel/node.
    NodeList,
    /// `panel-user-lock` / `panel-user-unlock` - a suspended customer's
    /// Linux account.
    ///
    /// One variant with a flag rather than two verbs, because they are one
    /// operation with a direction and nothing else differs.
    PanelUserLock {
        user: PanelUsername,
        locked: bool,
    },
    /// `http-flood-zones-save` - the server-wide `limit_req_zone` file.
    ///
    /// On stdin, like the WAF rules and for the same reason: it is rendered
    /// from every website on the box and can run to hundreds of lines.
    HttpFloodZonesSave {
        content: String,
    },
    /// `waf-default-rules` - the shipped rules, rewritten and read back.
    WafDefaultRules,
    /// `waf-custom-rules` - whatever an administrator added.
    WafCustomRules,
    /// `waf-custom-save` - arbitrary ModSecurity directives.
    ///
    /// The content is a `String` and not a path: the bash reads it from stdin
    /// for the reason C37 gives, and a directive set is exactly the kind of
    /// thing that must not appear in `ps`.
    WafCustomSave {
        content: String,
    },
    /// `waf-update` - rewrite every file the engine loads and reload nginx.
    WafUpdate,
    ClamavStatus,
    ClamavControl {
        start: bool,
    },
    MaldetStatus,

    // --- terminal ---
    TerminalExec {
        user: PanelUsername,
        cwd: SitePath,
        argv: AllowlistedArgv,
        /// Wall-clock budget in seconds. C30: 60s interactive, 900s for a job.
        budget_secs: u64,
        /// `--php-version=`, so Composer's platform checks see the version the
        /// site actually runs rather than the system default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        php_version: Option<PhpVersion>,
    },
}

impl HelperRequest {
    /// A stable name for the audit log. Every request is logged with the
    /// caller's uid before it runs.
    pub fn op_name(&self) -> &'static str {
        match self {
            Self::ServiceControl { .. } => "service-control",
            Self::DaemonReload => "daemon-reload",
            Self::PanelUserEnsure { .. } => "panel-user-ensure",
            Self::PanelUserDelete { .. } => "panel-user-delete",
            Self::PanelUserPassword { .. } => "panel-user-password",
            Self::NginxWriteSite { .. } => "nginx-write-site",
            Self::NginxTest => "nginx-test",
            Self::NginxReload => "nginx-reload",
            Self::NginxCustomWrite { .. } => "nginx-custom-write",
            Self::NginxCustomDelete { .. } => "nginx-custom-delete",
            Self::CertbotIssue { .. } => "certbot-issue",
            Self::CertbotRenew { .. } => "certbot-renew",
            Self::CertbotDelete { .. } => "certbot-delete",
            Self::SiteRuntimeEnsure { .. } => "site-runtime-ensure",
            Self::SiteRuntimeMove { .. } => "site-runtime-move",
            Self::SiteAppVolumeUsage { .. } => "site-app-volume-usage",
            Self::SiteAppComposePull { .. } => "site-app-compose-pull",
            Self::SiteAppComposePs { .. } => "site-app-compose-ps",
            Self::SiteAppLogs { .. } => "site-app-logs",
            Self::SiteAppControl { .. } => "site-app-control",
            Self::SiteAppInstallDeps { .. } => "site-app-install-deps",
            Self::SiteAppPull { .. } => "site-app-pull",
            Self::SiteAppDelete { .. } => "site-app-delete",
            Self::SiteAppDirEnsure { .. } => "site-app-dir-ensure",
            Self::SiteAppImport { .. } => "site-app-import",
            Self::SiteAppExport { .. } => "site-app-export",
            Self::SiteAppRename { .. } => "site-app-rename",
            Self::SiteAppWrite { .. } => "site-app-write",
            Self::SiteArchiveExtract { .. } => "site-archive-extract",
            Self::SiteRuntimeDelete { .. } => "site-runtime-delete",
            Self::SiteFileWrite { .. } => "site-file-write",
            Self::SiteChmod { .. } => "site-chmod",
            Self::FirewallApply => "firewall-apply",
            Self::FirewallFlush => "firewall-flush",
            Self::FirewallStatus => "firewall-status",
            Self::FirewallMigrateNft => "firewall-migrate-nft",
            Self::SelinuxRestoreSite { .. } => "selinux-restore-site",
            Self::SelinuxPortAdd { .. } => "selinux-port-add",
            Self::FirewallAllowIp { .. } => "firewall-allow-ip",
            Self::FirewallDenyIp { .. } => "firewall-deny-ip",
            Self::FirewallAllowPort { .. } => "firewall-allow-port",
            Self::FirewallPanelAllowPort { .. } => "firewall-panel-allow-port",
            Self::FirewallDelete { .. } => "firewall-delete",
            Self::FirewallEnable => "firewall-enable",
            Self::FirewallDisable => "firewall-disable",
            Self::FirewallList => "firewall-list",
            Self::SiteMkdir { .. } => "mkdir-site",
            Self::SiteRemove { .. } => "rm-site",
            Self::SiteFixPermissions { .. } => "fix-permissions",
            Self::SiteLogRead { .. } => "site-log-read",
            Self::SiteLogClear { .. } => "site-log-clear",
            Self::SiteLogsReadMany { .. } => "site-logs-read-many",
            Self::SiteDocumentRootEnsure { .. } => "site-document-root-ensure",
            Self::SiteFileInstall { .. } => "site-file-install",
            Self::SitePopulate { .. } => "site-populate",
            Self::Wp { .. } => "wp",
            Self::WpSite { .. } => "wp-site",
            Self::SslCertInfo { .. } => "ssl-cert-info",
            Self::PanelSslSelfsigned { .. } => "panel-ssl-selfsigned",
            Self::PanelSslDomains => "panel-ssl-domains",
            Self::PanelSniSync => "panel-sni-sync",
            Self::PhpOpcacheSet { .. } => "php-opcache-set",
            Self::PhpConfigWrite { .. } => "php-config-write",
            Self::Ipv6Status => "ipv6-status",
            Self::Ipv6Enable => "ipv6-enable",
            Self::Ipv6Disable => "ipv6-disable",
            Self::Ipv6Apply => "ipv6-apply",
            Self::TimeStatus => "time-status",
            Self::TimeSync => "time-sync",
            Self::CronList { .. } => "cron-list",
            Self::CronWrite { .. } => "cron-write",
            Self::FastcgiCacheClear => "fastcgi-cache-clear",
            Self::ServiceStatus { .. } => "service-status",
            Self::UpdatesStatus => "updates-status",
            Self::UpdatesOsRun => "updates-os-run",
            Self::UpdatesOsAuto { .. } => "updates-os-auto",
            Self::WafStatus => "waf-status",
            Self::WafCrsStatus => "waf-crs-status",
            Self::WafCrsMode { .. } => "waf-crs-mode",
            Self::WafSiteSave { .. } => "waf-site-save",
            Self::WafSiteDelete { .. } => "waf-site-delete",
            Self::MaldetScan { .. } => "maldet-scan",
            Self::MalwareScanServer { .. } => "malware-scan-server",
            Self::NodeInstall { .. } => "node-install",
            Self::CertbotDnsCloudflareInstall => "certbot-dns-cloudflare-install",
            Self::ClamavInstall => "clamav-install",
            Self::MaldetInstall => "maldet-install",
            Self::MaldetMonitor { .. } => "maldet-monitor",
            Self::MaldetUpdateSigs => "maldet-update-sigs",
            Self::NginxUpgradeMapEnsure => "nginx-upgrade-map-ensure",
            Self::UpdatesPanelRun => "updates-panel-run",
            Self::PhpPoolsRetune => "php-pools-retune",
            Self::PhpTuneWrite { .. } => "php-tune-write",
            Self::PhpInstall { .. } => "php-install",
            Self::WafInstall => "waf-install",
            Self::FirewallBlocklistRun => "firewall-blocklist-run",
            Self::FirewallBlocklistStatus => "firewall-blocklist-status",
            Self::FirewallBlocklistUrl { add, .. } => {
                if *add {
                    "firewall-blocklist-add"
                } else {
                    "firewall-blocklist-delete"
                }
            }
            Self::ManualSsl { install, .. } => {
                if *install {
                    "manual-ssl-install"
                } else {
                    "manual-ssl-remove"
                }
            }
            Self::DockerInstall => "docker-install",
            Self::DockerStatus => "docker-status",
            Self::DockerPrune => "docker-prune",
            Self::NodeList => "node-list",
            Self::PanelUserLock { locked, .. } => {
                if *locked {
                    "panel-user-lock"
                } else {
                    "panel-user-unlock"
                }
            }
            Self::HttpFloodZonesSave { .. } => "http-flood-zones-save",
            Self::WafDefaultRules => "waf-default-rules",
            Self::WafCustomRules => "waf-custom-rules",
            Self::WafCustomSave { .. } => "waf-custom-save",
            Self::WafUpdate => "waf-update",
            Self::ClamavStatus => "clamav-status",
            Self::ClamavControl { .. } => "clamav-control",
            Self::MaldetStatus => "maldet-status",
            Self::TerminalExec { .. } => "terminal-exec",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelperError {
    pub kind: HelperErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HelperErrorKind {
    /// The request did not deserialize, or a value was out of range.
    BadRequest,
    /// SO_PEERCRED said the caller is not the panel user.
    NotAuthorised,
    /// The underlying command ran and failed.
    CommandFailed,
    /// The command exceeded its budget.
    Timeout,
    NotFound,
    /// The helper has no implementation for this request.
    ///
    /// Not a refusal, and the distinction is load-bearing. Every other kind
    /// is the helper deciding about a request; this one is the helper saying
    /// which implementation serves it - the bash still does. The panel is
    /// meant to fall through on it, which is safe precisely because it
    /// carries no decision: it is only ever produced by a request whose enum
    /// variant has no arm, long after the arguments were parsed and accepted.
    NotImplemented,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<HelperError>,
    /// The exit status of a command run on the caller's behalf.
    ///
    /// Only `terminal-exec` sets it. Everywhere else a verb either worked or
    /// refused, and the 0/2 convention says that; here the command's own
    /// status *is* the answer, and `grep` finding nothing (1) must not reach
    /// the customer as "refused" (2).
    ///
    /// Optional and skipped when absent, so an older API ignores it and a
    /// newer API falls back to the 0/2 mapping against an older helper.
    /// Nothing that already exists changes meaning, so the protocol version
    /// does not move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl HelperResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            stdout: String::new(),
            stderr: String::new(),
            data: None,
            error: None,
            exit_code: None,
        }
    }

    pub fn with_stdout(stdout: impl Into<String>) -> Self {
        Self {
            stdout: stdout.into(),
            ..Self::ok()
        }
    }

    pub fn with_data(data: serde_json::Value) -> Self {
        Self {
            data: Some(data),
            ..Self::ok()
        }
    }

    /// The exit status a command-line caller sees, and the `returncode` the
    /// panel reads off the socket.
    ///
    /// The bash helper has two refusal codes and they are not
    /// interchangeable:
    ///
    ///   * `deny() { echo ...; exit 1; }` - "no, and here is why".
    ///   * the `SUDO_USER` guard, `exit 2` - "you may not call me at all".
    ///
    /// `NotAuthorised` is the socket's version of the second: the
    /// peer-credential check failing. Everything else is the first.
    ///
    /// A verb that ran a command for the caller reports the command's own
    /// status instead - `terminal-exec` is the only one, and `grep` finding
    /// nothing exits 1 without having been refused.
    ///
    /// This lives here because the helper and the API both need it and
    /// both depend on this crate. It used to exist twice, with a comment
    /// claiming the copies were compared; they were not, and they drifted.
    pub fn exit_status(&self) -> i32 {
        if let Some(code) = self.exit_code {
            return code;
        }
        if self.ok {
            return 0;
        }
        if matches!(&self.error, Some(e) if e.kind == HelperErrorKind::NotAuthorised) {
            return 2;
        }
        1
    }

    pub fn failed(kind: HelperErrorKind, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            stdout: String::new(),
            stderr: String::new(),
            data: None,
            exit_code: None,
            error: Some(HelperError {
                kind,
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_as_json() {
        let req = HelperRequest::NginxWriteSite {
            domain: Domain::parse("example.com").unwrap(),
            rendered: "server { }".into(),
            kind: VhostKind::Wordpress,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""op":"nginx-write-site""#));
        let back: HelperRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.op_name(), "nginx-write-site");
    }

    #[test]
    fn an_invalid_domain_cannot_cross_the_boundary() {
        // This is the property the whole design rests on: the root side never
        // receives a value it then has to validate.
        for bad in ["../../etc/passwd", "exa mple.com", "-bad.com", ""] {
            let json = format!(r#"{{"op":"nginx-reload-x","domain":"{bad}"}}"#);
            assert!(serde_json::from_str::<HelperRequest>(&json).is_err());

            let json = format!(r#"{{"op":"nginx-custom-delete","domain":"{bad}"}}"#);
            assert!(
                serde_json::from_str::<HelperRequest>(&json).is_err(),
                "{bad:?} must not deserialize into a Domain"
            );
        }
    }

    #[test]
    fn a_site_path_outside_home_cannot_cross_the_boundary() {
        let json = r#"{"op":"site-chmod","path":"/etc/shadow","mode":511,"recursive":false}"#;
        assert!(serde_json::from_str::<HelperRequest>(json).is_err());

        let json = r#"{"op":"site-chmod","path":"/home/bp_site/../../etc/shadow","mode":511,"recursive":false}"#;
        assert!(serde_json::from_str::<HelperRequest>(json).is_err());

        let json = r#"{"op":"site-chmod","path":"/home/bp_site/example.com/x","mode":420,"recursive":false}"#;
        assert!(serde_json::from_str::<HelperRequest>(json).is_ok());
    }

    #[test]
    fn a_reserved_username_cannot_cross_the_boundary() {
        let json = r#"{"op":"panel-user-delete","username":"root"}"#;
        assert!(serde_json::from_str::<HelperRequest>(json).is_err());
    }

    #[test]
    fn the_envelope_refuses_unknown_fields() {
        let good = format!(r#"{{"version":{PROTOCOL_VERSION},"request":{{"op":"nginx-reload"}}}}"#);
        assert!(Envelope::decode(good.as_bytes()).is_ok());

        let surprising = format!(
            r#"{{"version":{PROTOCOL_VERSION},"request":{{"op":"nginx-reload"}},"surprise":true}}"#
        );
        assert!(
            matches!(
                Envelope::decode(surprising.as_bytes()),
                Err(ProtocolError::Malformed(_))
            ),
            "an unexpected field means the two sides disagree; guessing is worse than refusing"
        );
    }

    #[test]
    fn a_version_mismatch_is_refused_loudly() {
        let json = r#"{"version":99,"request":{"op":"nginx-reload"}}"#;
        let err = Envelope::decode(json.as_bytes()).expect_err("must be refused");
        assert_eq!(
            err,
            ProtocolError::VersionMismatch {
                got: 99,
                expected: PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn a_missing_version_is_refused() {
        let json = r#"{"request":{"op":"nginx-reload"}}"#;
        assert!(matches!(
            Envelope::decode(json.as_bytes()),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn the_envelope_round_trips() {
        let env = Envelope::new(HelperRequest::FirewallApply);
        let back = Envelope::decode(&env.encode()).unwrap();
        assert_eq!(back.request.op_name(), "firewall-apply");
        assert_eq!(back.version, PROTOCOL_VERSION);
    }

    #[test]
    fn an_oversized_request_is_refused_before_it_is_parsed() {
        // An unbounded read off a socket is a memory-exhaustion bug.
        let huge = vec![b'x'; MAX_REQUEST_BYTES + 1];
        assert!(matches!(
            Envelope::decode(&huge),
            Err(ProtocolError::TooLarge(_))
        ));
    }

    #[test]
    fn the_envelope_still_enforces_the_newtypes() {
        // The version check must not become a way around the parsing.
        let json = format!(
            r#"{{"version":{PROTOCOL_VERSION},"request":{{"op":"nginx-custom-delete","domain":"../../etc"}}}}"#
        );
        assert!(Envelope::decode(json.as_bytes()).is_err());
    }

    #[test]
    fn the_service_allowlist_matches_the_bash() {
        for good in ALLOWED_SERVICES {
            assert!(ServiceName::parse(good).is_ok(), "{good}");
        }
        // The dynamic phpX.Y-fpm form the bash also accepts.
        for good in ["php8.2-fpm", "php7.4-fpm", "php8.5-fpm"] {
            assert!(ServiceName::parse(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn an_arbitrary_unit_cannot_reach_systemctl() {
        for bad in [
            "sshd",
            "systemd-logind",
            "nginx; rm -rf /",
            "../../etc/systemd/system/evil",
            "php-fpm",
            "php8-fpm",
            "php8.4.1-fpm",
            "",
        ] {
            assert!(
                ServiceName::parse(bad).is_err(),
                "{bad:?} must not be constructible"
            );
        }
    }

    #[test]
    fn a_bad_service_cannot_be_smuggled_through_json() {
        let json = format!(
            r#"{{"version":{PROTOCOL_VERSION},"request":{{"op":"service-control","service":"sshd","action":"stop"}}}}"#
        );
        assert!(Envelope::decode(json.as_bytes()).is_err());

        let json = format!(
            r#"{{"version":{PROTOCOL_VERSION},"request":{{"op":"service-control","service":"nginx","action":"reload"}}}}"#
        );
        assert!(Envelope::decode(json.as_bytes()).is_ok());
    }

    #[test]
    fn the_panel_cannot_stop_itself_or_its_session_store() {
        // Stopping either leaves no way to bring the panel back from the UI.
        assert!(!ServiceName::parse("snpanel-api").unwrap().may_stop());
        assert!(!ServiceName::parse("redis-server").unwrap().may_stop());
        assert!(ServiceName::parse("nginx").unwrap().may_stop());
        assert!(ServiceName::parse("php8.4-fpm").unwrap().may_stop());
    }

    #[test]
    fn php_fpm_units_are_flagged_for_an_existence_check() {
        let dynamic = ServiceName::parse("php8.2-fpm").unwrap();
        assert!(dynamic.is_php_fpm());
        assert_eq!(dynamic.php_version(), Some("8.2"));

        // These are in the static list, so no filesystem check is needed.
        assert!(!ServiceName::parse("nginx").unwrap().is_php_fpm());
        assert!(!ServiceName::parse("php8.4-fpm").unwrap().is_php_fpm());
    }

    #[test]
    fn the_terminal_allowlist_is_an_allowlist() {
        assert!(AllowlistedArgv::parse("php", vec!["-v".into()]).is_ok());
        assert_eq!(
            AllowlistedArgv::parse("sh", vec!["-c".into(), "rm -rf /".into()]),
            Err(ArgvError::NotAllowed("sh".into()))
        );
        // A path must not slip past the name check.
        assert!(AllowlistedArgv::parse("/bin/sh", vec![]).is_err());
        assert!(AllowlistedArgv::parse("../../bin/sh", vec![]).is_err());
        assert!(AllowlistedArgv::parse("", vec![]).is_err());
    }

    #[test]
    fn an_argv_with_a_nul_is_refused() {
        assert_eq!(
            AllowlistedArgv::parse("php", vec!["a\0b".into()]),
            Err(ArgvError::NulByte)
        );
    }

    #[test]
    fn a_disallowed_binary_cannot_be_smuggled_through_json() {
        let json = r#"{"op":"terminal-exec","user":"bp_site","cwd":"/home/bp_site/example.com",
                       "argv":{"binary":"sh","args":["-c","id"]},"budget_secs":60}"#;
        assert!(serde_json::from_str::<HelperRequest>(json).is_err());
    }

    #[test]
    fn a_password_is_serialised_for_the_socket_but_never_printed() {
        let req = HelperRequest::PanelUserPassword {
            username: PanelUsername::parse("bp_site").unwrap(),
            password: SecretString::new("hunter2"),
        };
        // C37: it reaches root over the socket, not through argv...
        assert!(serde_json::to_string(&req).unwrap().contains("hunter2"));
        // ...and never through a log line.
        assert!(!format!("{req:?}").contains("hunter2"));
    }

    #[test]
    fn responses_carry_structured_errors() {
        let r = HelperResponse::failed(HelperErrorKind::CommandFailed, "nginx -t failed");
        assert!(!r.ok);
        assert_eq!(
            r.error.as_ref().unwrap().kind,
            HelperErrorKind::CommandFailed
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: HelperResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error.unwrap().message, "nginx -t failed");
    }

    #[test]
    fn every_variant_has_an_audit_name() {
        // A request that reaches root with no name in the audit log is a
        // request nobody can account for afterwards.
        let reqs = [
            HelperRequest::NginxTest,
            HelperRequest::FirewallApply,
            HelperRequest::DaemonReload,
            HelperRequest::FirewallMigrateNft,
        ];
        for r in reqs {
            assert!(!r.op_name().is_empty());
            assert!(!r.op_name().contains(' '));
        }
    }
}
