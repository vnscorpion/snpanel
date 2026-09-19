//! Parsed values for everything that crosses a trust boundary.
//!
//! NT4 of the migration plan: parse, don't validate. Nothing here can be
//! constructed from an invalid string, so the privileged layer never needs to
//! re-check a value it has been handed. Each constructor mirrors the exact
//! rule the Python implementation applies today - the regex each one matches
//! is cited against its source file, because a Rust type that is *stricter*
//! than Python breaks existing sites just as surely as one that is laxer.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

/// Reserved Linux usernames a panel user may never take over.
///
/// Source: `backend/app/services/site_users.py::RESERVED_LINUX_USERS`.
pub const RESERVED_LINUX_USERS: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "_apt",
    "nobody",
    "snpanel",
    "snpanel-sites",
    "snpanel-sftp",
    "mysql",
    "redis",
    "nginx",
];

/// Root under which every managed site lives. Source: `site_users.HOME_ROOT`.
pub const HOME_ROOT: &str = "/home";

/// Source: `site_users.PUBLIC_DIR`.
pub const PUBLIC_DIR: &str = "public_html";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid domain: {0}")]
    Domain(String),
    #[error("invalid panel username: {0}")]
    Username(String),
    #[error("invalid site path: {0}")]
    SitePath(String),
    #[error("unsupported PHP version: {0}")]
    PhpVersion(String),
    #[error("invalid port: {0}")]
    Port(String),
    #[error("invalid IP or CIDR: {0}")]
    IpOrCidr(String),
    #[error("invalid email address: {0}")]
    Email(String),
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// A website domain, lowercased.
///
/// Matches `site_users.DOMAIN_RE`:
/// `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`
///
/// That is the stricter of the two domain regexes in the Python codebase (the
/// other, `schemas.DOMAIN_RE`, accepts uppercase and is applied to input that
/// is lowercased immediately afterwards). We normalise to lowercase on
/// construction and then hold to the strict form, which is what actually
/// reaches the filesystem and nginx.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Domain(String);

/// The twelve hex characters that identify a site in its PHP-FPM pool name.
///
/// Source: `site_php_pool_glob` and `ensure_php_pool`, which both compute
///
/// ```text
/// printf '%s' "$target" | sha256sum | awk '{print substr($1, 1, 12)}'
/// ```
///
/// Must stay byte-identical. The pool files it names already exist on every
/// installed server: a different hash does not produce a wrong name, it
/// produces a name that matches nothing, so deleting a site would leave its
/// pool running with the old document root still open.
///
/// `resolved_path` is the site root after symlink resolution, because that is
/// what the shell hashes - `readlink -m` runs before `sha256sum`.
pub fn site_hash(resolved_path: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(resolved_path.as_bytes());
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    hex[..12].to_string()
}

impl Domain {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let normalized = raw.trim().to_ascii_lowercase();
        if !Self::is_valid(&normalized) {
            return Err(ParseError::Domain(raw.to_string()));
        }
        Ok(Self(normalized))
    }

    fn is_valid(s: &str) -> bool {
        // Total length guard: 253 is the DNS limit. Python relies on the
        // per-label bound plus column widths; we make it explicit.
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        let labels: Vec<&str> = s.split('.').collect();
        // The regex requires at least one dot, i.e. two or more labels.
        if labels.len() < 2 {
            return false;
        }
        labels.iter().all(|label| Self::is_valid_label(label))
    }

    fn is_valid_label(label: &str) -> bool {
        // ^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$
        let bytes = label.as_bytes();
        match bytes.len() {
            0 => false,
            1 => bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit(),
            n if n <= 63 => {
                let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
                let last = bytes[n - 1];
                let last_ok = last.is_ascii_lowercase() || last.is_ascii_digit();
                let middle_ok = bytes[1..n - 1]
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
                first_ok && last_ok && middle_ok
            }
            _ => false,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deterministic Linux username for this domain.
    ///
    /// Source: `site_users.linux_user_for_domain`. Must stay byte-identical -
    /// it names directories that already exist on disk on every installed box.
    pub fn linux_user(&self) -> PanelUsername {
        use sha2::{Digest, Sha256};

        let slug_raw: String = self
            .0
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        // Python: re.sub(r"[^a-z0-9]+", "_", s) collapses runs to one "_".
        let mut slug = String::with_capacity(slug_raw.len());
        let mut prev_underscore = false;
        for c in slug_raw.chars() {
            if c == '_' {
                if !prev_underscore {
                    slug.push(c);
                }
                prev_underscore = true;
            } else {
                slug.push(c);
                prev_underscore = false;
            }
        }
        let slug = slug.trim_matches('_').to_string();
        let slug = if slug.is_empty() {
            "site".to_string()
        } else {
            slug
        };

        let digest = Sha256::digest(self.0.as_bytes());
        let hex = hex_lower(&digest);
        let truncated: String = slug.chars().take(18).collect();
        let username: String = format!("bp_{}_{}", truncated, &hex[..8])
            .chars()
            .take(32)
            .collect();
        PanelUsername(username)
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Domain::parse(&raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// PanelUsername
// ---------------------------------------------------------------------------

/// A Linux/panel account name.
///
/// Matches `site_users.LINUX_USER_RE` (`^[a-z_][a-z0-9_-]{2,31}$`) and rejects
/// every name in [`RESERVED_LINUX_USERS`], exactly as
/// `site_users.validate_linux_user` does.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct PanelUsername(String);

impl PanelUsername {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let normalized = raw.trim().to_ascii_lowercase();
        if !Self::is_valid(&normalized) {
            return Err(ParseError::Username(raw.to_string()));
        }
        if RESERVED_LINUX_USERS.contains(&normalized.as_str()) {
            return Err(ParseError::Username(raw.to_string()));
        }
        Ok(Self(normalized))
    }

    fn is_valid(s: &str) -> bool {
        // ^[a-z_][a-z0-9_-]{2,31}$  => total length 3..=32
        let bytes = s.as_bytes();
        if bytes.len() < 3 || bytes.len() > 32 {
            return false;
        }
        let first = bytes[0];
        if !(first.is_ascii_lowercase() || first == b'_') {
            return false;
        }
        bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `/home/<user>` - the account's home directory.
    pub fn home(&self) -> PathBuf {
        Path::new(HOME_ROOT).join(&self.0)
    }
}

impl fmt::Display for PanelUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PanelUsername {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        PanelUsername::parse(&raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// PhpVersion
// ---------------------------------------------------------------------------

/// A PHP version SNPanel knows how to manage.
///
/// Source: `site_users.PHP_VERSION_RE` = `^(?:5\.6|7\.4|8\.[0-5])$`, which is
/// the same set as `schemas.SUPPORTED_PHP_VERSIONS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct PhpVersion {
    major: u8,
    minor: u8,
}

impl PhpVersion {
    pub const DEFAULT: PhpVersion = PhpVersion { major: 8, minor: 4 };

    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let err = || ParseError::PhpVersion(raw.to_string());
        let (major, minor) = raw.trim().split_once('.').ok_or_else(err)?;
        let major: u8 = major.parse().map_err(|_| err())?;
        let minor: u8 = minor.parse().map_err(|_| err())?;
        let supported = matches!((major, minor), (5, 6) | (7, 4) | (8, 0..=5));
        if !supported {
            return Err(err());
        }
        Ok(Self { major, minor })
    }

    /// `8.4` - the dotted form used in paths and config.
    pub fn dotted(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }

    /// `84` - the compact form Remi uses (`php84-php-fpm`).
    pub fn compact(&self) -> String {
        format!("{}{}", self.major, self.minor)
    }

    /// `8_4` - the form that appears in PHP-FPM pool names.
    pub fn underscored(&self) -> String {
        format!("{}_{}", self.major, self.minor)
    }
}

impl fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl<'de> Deserialize<'de> for PhpVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        PhpVersion::parse(&raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// SitePath
// ---------------------------------------------------------------------------

/// A path guaranteed to live under `/home/<panel-user>/`.
///
/// This is the type that makes C36 ("file manager refuses symlinks anywhere in
/// the path") and the path-traversal guards structural rather than a check
/// someone can forget. Construction is lexical: no `..`, no absolute escape,
/// must start at `/home/<valid-user>/`. Symlink resolution is a separate,
/// filesystem-touching step ([`SitePath::verify_no_symlinks`]) because the
/// helper must be able to build a `SitePath` for a file that does not exist
/// yet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SitePath {
    user: PanelUsername,
    path: PathBuf,
}

impl SitePath {
    /// Parse an absolute path, requiring it to sit under `/home/<user>/`.
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let err = || ParseError::SitePath(raw.to_string());
        let path = Path::new(raw);
        if !path.is_absolute() {
            return Err(err());
        }
        // Reject traversal and oddities lexically. `Component::ParentDir` is
        // the one that matters; `CurDir` we simply drop.
        let mut cleaned = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir => cleaned.push("/"),
                Component::Normal(part) => {
                    let s = part.to_str().ok_or_else(err)?;
                    if s.contains('\0') {
                        return Err(err());
                    }
                    cleaned.push(s);
                }
                Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) => return Err(err()),
            }
        }

        let rest = cleaned.strip_prefix(HOME_ROOT).map_err(|_| err())?;
        let mut parts = rest.components();
        let user_part = parts.next().ok_or_else(err)?;
        let user_str = match user_part {
            Component::Normal(p) => p.to_str().ok_or_else(err)?,
            _ => return Err(err()),
        };
        let user = PanelUsername::parse(user_str).map_err(|_| err())?;

        Ok(Self {
            user,
            path: cleaned,
        })
    }

    /// The site root for a given user and domain: `/home/<user>/<domain>`.
    ///
    /// Source: `site_users.site_root_for_panel_user`.
    pub fn site_root(user: &PanelUsername, domain: &Domain) -> Self {
        Self {
            user: user.clone(),
            path: Path::new(HOME_ROOT)
                .join(user.as_str())
                .join(domain.as_str()),
        }
    }

    /// Join a *relative* segment, keeping the under-`/home/<user>` guarantee.
    pub fn join(&self, relative: &str) -> Result<Self, ParseError> {
        let err = || ParseError::SitePath(relative.to_string());
        let rel = Path::new(relative);
        if rel.is_absolute() {
            return Err(err());
        }
        let mut candidate = self.path.clone();
        for component in rel.components() {
            match component {
                Component::Normal(part) => candidate.push(part),
                Component::CurDir => {}
                _ => return Err(err()),
            }
        }
        Self::parse(candidate.to_str().ok_or_else(err)?)
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn as_str(&self) -> &str {
        // Safe: built from &str throughout.
        self.path.to_str().unwrap_or_default()
    }

    pub fn user(&self) -> &PanelUsername {
        &self.user
    }

    /// C36: refuse a symlink at any position in the path.
    ///
    /// Walks every existing ancestor from `/home` down and rejects the path if
    /// any component is a symlink. Components that do not exist yet are fine -
    /// a file being created cannot be a symlink.
    pub fn verify_no_symlinks(&self) -> Result<(), ParseError> {
        let err = || ParseError::SitePath(self.as_str().to_string());
        let mut walked = PathBuf::from("/");
        for component in self.path.components() {
            if let Component::Normal(part) = component {
                walked.push(part);
                match std::fs::symlink_metadata(&walked) {
                    Ok(meta) if meta.file_type().is_symlink() => return Err(err()),
                    Ok(_) => {}
                    // Does not exist yet: nothing below it can exist either.
                    Err(_) => break,
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for SitePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SitePath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        SitePath::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// A relative document root such as `public_html` or `public_html/public`.
///
/// Source: `site_users.validate_document_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentRoot(String);

impl DocumentRoot {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let err = || ParseError::SitePath(raw.to_string());
        let cleaned = raw.trim().replace('\\', "/");
        let cleaned = if cleaned.is_empty() {
            PUBLIC_DIR.to_string()
        } else {
            cleaned
        };
        if cleaned.starts_with('/') {
            return Err(err());
        }
        // Python also rejects a Windows drive prefix such as "C:/".
        let bytes = cleaned.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'/'
        {
            return Err(err());
        }
        let cleaned = cleaned.trim_matches('/').to_string();
        if cleaned.is_empty() || cleaned.len() > 255 {
            return Err(err());
        }
        let parts: Vec<&str> = cleaned.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err(err());
        }
        for part in &parts {
            if *part == "." || *part == ".." {
                return Err(err());
            }
            if !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
            {
                return Err(err());
            }
        }
        Ok(Self(parts.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for DocumentRoot {
    fn default() -> Self {
        Self(PUBLIC_DIR.to_string())
    }
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

/// A TCP port. Zero is not a usable listen port, so it is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Port(u16);

impl Port {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let trimmed = raw.trim();
        // Source: firewall.PORT_RE = ^[0-9]{1,5}$ - digits only, no sign.
        if trimmed.is_empty() || trimmed.len() > 5 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseError::Port(raw.to_string()));
        }
        let value: u32 = trimmed
            .parse()
            .map_err(|_| ParseError::Port(raw.to_string()))?;
        Self::new(value)
    }

    pub fn new(value: u32) -> Result<Self, ParseError> {
        if value == 0 || value > u16::MAX as u32 {
            return Err(ParseError::Port(value.to_string()));
        }
        Ok(Self(value as u16))
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Accept both 2222 and "2222": the .env file and JSON disagree.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u32),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Port::new(n).map_err(serde::de::Error::custom),
            Raw::Str(s) => Port::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

// ---------------------------------------------------------------------------
// IpOrCidr
// ---------------------------------------------------------------------------

/// A single address or a CIDR range, v4 or v6.
///
/// The firewall stores these in `rules.tsv` (C13), so `Display` must round-trip
/// what was parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct IpOrCidr {
    addr: std::net::IpAddr,
    prefix: u8,
    /// True when the source text carried an explicit `/prefix`.
    explicit_prefix: bool,
}

impl IpOrCidr {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let err = || ParseError::IpOrCidr(raw.to_string());
        let trimmed = raw.trim();
        let (addr_part, prefix_part) = match trimmed.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (trimmed, None),
        };
        let addr: std::net::IpAddr = addr_part.parse().map_err(|_| err())?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => {
                let value: u8 = p.parse().map_err(|_| err())?;
                if value > max_prefix {
                    return Err(err());
                }
                value
            }
            None => max_prefix,
        };
        Ok(Self {
            addr,
            prefix,
            explicit_prefix: prefix_part.is_some(),
        })
    }

    /// The form the firewall stores in `rules.tsv`.
    ///
    /// Source: `require_ip_or_cidr_normalized` in the bash helper, which shells
    /// out to `ipaddress.ip_network(value, strict=False)`. Two consequences,
    /// both load-bearing:
    ///
    /// 1. A bare address gains its full-length prefix: `203.0.113.44` becomes
    ///    `203.0.113.44/32`.
    /// 2. Host bits are **masked off**: `10.0.0.5/8` becomes `10.0.0.0/8`.
    ///
    /// The second is what stops two rules that mean the same network from
    /// being stored as different strings, which would defeat the duplicate
    /// check in `firewall_add_rule`.
    pub fn normalized(&self) -> String {
        match self.addr {
            std::net::IpAddr::V4(v4) => {
                // A shift of 32 is undefined, so /0 is handled separately
                // rather than relying on wrapping behaviour.
                let mask: u32 = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                let masked = u32::from(v4) & mask;
                format!("{}/{}", std::net::Ipv4Addr::from(masked), self.prefix)
            }
            std::net::IpAddr::V6(v6) => {
                let mask: u128 = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                let masked = u128::from(v6) & mask;
                format!("{}/{}", std::net::Ipv6Addr::from(masked), self.prefix)
            }
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn addr(&self) -> std::net::IpAddr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

impl fmt::Display for IpOrCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.explicit_prefix {
            write!(f, "{}/{}", self.addr, self.prefix)
        } else {
            write!(f, "{}", self.addr)
        }
    }
}

impl<'de> Deserialize<'de> for IpOrCidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        IpOrCidr::parse(&raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

/// An email address, validated at the level `email-validator` applies in the
/// Python schemas: one `@`, a non-empty local part, a domain that parses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Email(String);

impl Email {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let err = || ParseError::Email(raw.to_string());
        let trimmed = raw.trim();
        if trimmed.len() > 254 {
            return Err(err());
        }
        let (local, domain) = trimmed.rsplit_once('@').ok_or_else(err)?;
        if local.is_empty() || local.len() > 64 {
            return Err(err());
        }
        if local
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'@' || b == 0)
        {
            return Err(err());
        }
        Domain::parse(domain).map_err(|_| err())?;
        Ok(Self(format!("{}@{}", local, domain.to_ascii_lowercase())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Email {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Email::parse(&raw).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// SecretString
// ---------------------------------------------------------------------------

/// A value that must not be logged, and must never reach a process argv (C37).
///
/// `Debug` and `Display` are redacted; the inner value comes out only through
/// [`SecretString::expose`], which is deliberately awkward to type.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// C37 companion: a Linux login password may not contain `:`, CR, LF or
    /// NUL, because it is synced into the shadow file.
    ///
    /// Source: `schemas._validate_linux_login_password`.
    pub fn valid_as_linux_password(&self) -> bool {
        !self
            .0
            .chars()
            .any(|c| matches!(c, ':' | '\r' | '\n' | '\0'))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Serialised in full: the IPC channel to the helper is a
        // root-owned Unix socket, which is exactly how a password reaches the
        // privileged side without passing through argv.
        s.serialize_str(&self.0)
    }
}

// ---------------------------------------------------------------------------

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

#[cfg(test)]
mod tests {
    /// The pool hash must equal what the shell computes, not merely look like
    /// a hash.
    ///
    /// Compared against the real pipeline rather than a constant, because a
    /// constant is only as good as the person who pasted it, and the cost of
    /// being wrong is a pool file that no longer matches its site.
    #[test]
    fn the_pool_hash_matches_the_shell_pipeline() {
        use std::process::Command;

        for path in [
            "/home/bp_site/example.com",
            "/home/u1/a-very-long.domain.example.co.uk",
            "/home/x/site with spaces",
        ] {
            let out = Command::new("sh")
                .arg("-c")
                .arg("printf '%s' \"$1\" | sha256sum | awk '{print substr($1, 1, 12)}'")
                .arg("sh")
                .arg(path)
                .output();

            let Ok(out) = out else {
                eprintln!("skipped: no shell to compare against");
                return;
            };
            let expected = String::from_utf8_lossy(&out.stdout).trim().to_string();
            assert!(
                expected.len() == 12,
                "sha256sum is not available here, so this proves nothing: {expected:?}"
            );
            assert_eq!(
                site_hash(path),
                expected,
                "the pool name for {path} would not match what is on disk"
            );
        }
    }

    /// Twelve hex characters, and the same answer every time.
    #[test]
    fn the_pool_hash_is_stable_and_the_right_width() {
        let a = site_hash("/home/bp_site/example.com");
        let b = site_hash("/home/bp_site/example.com");
        assert_eq!(a, b);
        assert_eq!(a.len(), 12);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, site_hash("/home/bp_site/example.net"));
    }

    use super::*;

    #[test]
    fn domain_accepts_ordinary_names() {
        for good in [
            "example.com",
            "sub.example.com",
            "a-b.example.co.uk",
            "x1.io",
        ] {
            assert!(Domain::parse(good).is_ok(), "{good} should parse");
        }
    }

    #[test]
    fn domain_rejects_the_shapes_python_rejects() {
        for bad in [
            "example",          // single label
            "-bad.com",         // leading hyphen
            "bad-.com",         // trailing hyphen
            "exa mple.com",     // space
            "example..com",     // empty label
            "",                 // empty
            "example.com/../x", // path smuggling
            "exam\nple.com",    // newline *inside* the name
            "example.com\0",    // NUL
        ] {
            assert!(Domain::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_as_python_does() {
        // site_users does `domain.strip().lower()` before matching, so a value
        // arriving with whitespace around it is accepted, not rejected.
        assert_eq!(
            Domain::parse("  example.com \n").unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn domain_normalises_case() {
        assert_eq!(
            Domain::parse("EXAMPLE.CoM").unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn username_rejects_reserved_names() {
        for reserved in ["root", "www-data", "snpanel", "nginx", "mysql"] {
            assert!(
                PanelUsername::parse(reserved).is_err(),
                "{reserved} must stay reserved"
            );
        }
    }

    #[test]
    fn username_enforces_the_python_shape() {
        assert!(PanelUsername::parse("ab").is_err()); // too short
        assert!(PanelUsername::parse("1abc").is_err()); // starts with a digit
        assert!(PanelUsername::parse("abc").is_ok());
        assert!(PanelUsername::parse("_abc").is_ok());
        assert!(PanelUsername::parse(&"a".repeat(32)).is_ok());
        assert!(PanelUsername::parse(&"a".repeat(33)).is_err());
    }

    #[test]
    fn site_path_refuses_to_leave_home() {
        assert!(SitePath::parse("/etc/passwd").is_err());
        assert!(SitePath::parse("/home/../etc/passwd").is_err());
        assert!(SitePath::parse("/home/bp_site/../../etc/shadow").is_err());
        assert!(SitePath::parse("relative/path").is_err());
        assert!(SitePath::parse("/home").is_err()); // no user component
        assert!(SitePath::parse("/home/root/x").is_err()); // reserved user
    }

    #[test]
    fn site_path_accepts_a_real_site_file() {
        let p = SitePath::parse("/home/bp_example_com_abc/example.com/public_html/index.php")
            .expect("valid site path");
        assert_eq!(p.user().as_str(), "bp_example_com_abc");
    }

    #[test]
    fn site_path_join_cannot_escape() {
        let root = SitePath::parse("/home/bp_site_1/example.com").unwrap();
        assert!(root.join("public_html/index.php").is_ok());
        assert!(root.join("../../../etc/passwd").is_err());
        assert!(root.join("/etc/passwd").is_err());
    }

    #[test]
    fn php_version_matches_supported_set() {
        for good in ["5.6", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"] {
            assert!(PhpVersion::parse(good).is_ok(), "{good} is supported");
        }
        for bad in ["8.6", "7.3", "9.0", "8", "8.4.1", ""] {
            assert!(PhpVersion::parse(bad).is_err(), "{bad:?} is not supported");
        }
    }

    #[test]
    fn php_version_renders_every_form() {
        let v = PhpVersion::parse("8.4").unwrap();
        assert_eq!(v.dotted(), "8.4");
        assert_eq!(v.compact(), "84");
        assert_eq!(v.underscored(), "8_4");
    }

    #[test]
    fn document_root_blocks_traversal() {
        assert_eq!(
            DocumentRoot::parse("public_html").unwrap().as_str(),
            "public_html"
        );
        assert_eq!(
            DocumentRoot::parse("public_html/public").unwrap().as_str(),
            "public_html/public"
        );
        assert!(DocumentRoot::parse("/etc").is_err());
        assert!(DocumentRoot::parse("../etc").is_err());
        assert!(DocumentRoot::parse("public/../../etc").is_err());
        assert!(DocumentRoot::parse("C:/windows").is_err());
    }

    #[test]
    fn port_rejects_zero_and_overflow() {
        assert!(Port::parse("0").is_err());
        assert!(Port::parse("65536").is_err());
        assert!(Port::parse("-1").is_err());
        assert_eq!(Port::parse("2222").unwrap().get(), 2222);
    }

    #[test]
    fn ip_or_cidr_round_trips() {
        for text in ["1.2.3.4", "10.0.0.0/8", "::1", "2001:db8::/32"] {
            let parsed = IpOrCidr::parse(text).unwrap();
            assert_eq!(parsed.to_string(), text, "rules.tsv must round-trip (C13)");
        }
        assert!(IpOrCidr::parse("10.0.0.0/33").is_err());
        assert!(IpOrCidr::parse("not-an-ip").is_err());
    }

    #[test]
    fn secret_string_never_leaks_in_logs() {
        let s = SecretString::new("hunter2");
        assert_eq!(format!("{s}"), "<redacted>");
        assert_eq!(format!("{s:?}"), "SecretString(<redacted>)");
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn linux_password_rule_matches_python() {
        assert!(SecretString::new("ok-password").valid_as_linux_password());
        assert!(!SecretString::new("has:colon").valid_as_linux_password());
        assert!(!SecretString::new("has\nnewline").valid_as_linux_password());
    }
}
