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
    #[error("invalid container image reference: {0}")]
    DockerImage(String),
    #[error("invalid application name: {0}")]
    AppName(String),
    #[error("invalid domain: {0}")]
    Domain(String),
    #[error("invalid panel username: {0}")]
    Username(String),
    /// Source: `deny "reserved panel Linux user: $1"`.
    ///
    /// A separate variant from `Username` because the bash has a separate
    /// message, and the difference is the whole of what it tells the
    /// administrator: `snpanel` is a perfectly well-shaped name, and being
    /// told it is "invalid" sends them looking at the wrong thing.
    #[error("reserved panel Linux user: {0}")]
    ReservedUsername(String),
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

/// A container image reference.
///
/// Source: `require_docker_image`. The character set is
/// `registry/name[:tag][@sha256:...]`, and on top of it a leading dash and a
/// `..` component are refused - not for tidiness, but because `docker pull`
/// would read `-rm` as a flag and `a/../b` as somewhere else.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct DockerImage(String);

impl DockerImage {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let err = || ParseError::DockerImage(raw.to_string());
        if raw.starts_with('-') || raw.contains("..") {
            return Err(err());
        }
        let (rest, digest) = match raw.split_once("@sha256:") {
            Some((r, d)) => (r, Some(d)),
            None => (raw, None),
        };
        if let Some(d) = digest {
            if d.len() != 64
                || !d
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(err());
            }
        }
        let (name, tag) = match rest.rsplit_once(':') {
            // A colon in the registry part is a port, not a tag: only treat
            // it as a tag when what follows has no slash.
            Some((n, t)) if !t.contains('/') => (n, Some(t)),
            _ => (rest, None),
        };
        if let Some(t) = tag {
            if t.is_empty()
                || t.len() > 127
                || !t
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            {
                return Err(err());
            }
        }
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() > 160 {
            return Err(err());
        }
        if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
            return Err(err());
        }
        if !bytes.iter().all(|&b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'/' | b'-' | b':')
        }) {
            return Err(err());
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DockerImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for DockerImage {
    type Error = ParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

/// A site application's name.
///
/// Source: `require_app_name`, `^[a-z0-9]([a-z0-9_-]{0,30}[a-z0-9])?$`. It is
/// a type rather than a string because the same value becomes a systemd unit
/// name, a Docker project name and a directory under the owner's home: three
/// places where a stray slash, space or leading dash means something.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct AppName(String);

impl AppName {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let err = || ParseError::AppName(raw.to_string());
        let bytes = raw.as_bytes();
        if bytes.is_empty() || bytes.len() > 32 {
            return Err(err());
        }
        let ok_edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let ok_middle = |b: u8| ok_edge(b) || b == b'_' || b == b'-';
        if !ok_edge(bytes[0]) {
            return Err(err());
        }
        if bytes.len() > 1 && !ok_edge(bytes[bytes.len() - 1]) {
            return Err(err());
        }
        if !bytes.iter().all(|&b| ok_middle(b)) {
            return Err(err());
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AppName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for AppName {
    type Error = ParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

/// Source: `_parse_access_log_line`'s `digest` — the first sixteen hex
/// characters of `sha256(f"{domain}\0{sequence}\0{line}")`.
///
/// The sequence is in the digest because two identical lines in one file are
/// two different entries, and the page keys its rows on this.
/// Hex SHA-256 of a string.
///
/// Source: `provisioning.hash_token` — `sha256(raw.encode()).hexdigest()`.
/// The provisioning tokens are stored as this and never as themselves, so
/// the digest has to be byte-identical or every existing token stops
/// authenticating the moment the Rust front door answers.
/// `hashlib.sha1(text.encode("utf-8")).hexdigest()`.
///
/// **Not a security primitive, and not used as one.** The DA importer
/// needs a short stable tag so two archives whose account or database
/// names rewrite to the same string do not collide; nothing compares it
/// against anything an attacker supplies. Use [`sha256_hex`] for anything
/// that matters.
pub fn sha1_hex(text: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(text.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn access_entry_id(domain: &str, sequence: u64, line: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(sequence.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(line.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..16]
        .to_string()
}

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
///
/// The Python has two functions here and they are not interchangeable.
/// `validate_linux_user` matches the pattern against what it was given.
/// `linux_user_for_panel_username` lowercases and strips *first*, and is the
/// conversion from a panel account name to a system one. This is the former,
/// because it validates a value at the privilege boundary that the caller has
/// already converted - the two API call sites lowercase before calling it,
/// the way the Python does.
///
/// It used to lowercase, and the harm was not that it accepted a name the
/// bash helper refuses. It is that `SitePath` keeps the bytes it was given:
/// `site-runtime-ensure UPPER /home/UPPER/x` parsed to the user `upper`,
/// agreed with itself that the path belonged to that user, and then created
/// `/home/UPPER/x` as root while the account's home was `/home/upper`. A type
/// that says "this path belongs to user X" has to mean the bytes, not a
/// normalisation of them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct PanelUsername(String);

impl PanelUsername {
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        if !Self::is_valid(raw) {
            return Err(ParseError::Username(raw.to_string()));
        }
        if RESERVED_LINUX_USERS.contains(&raw) {
            return Err(ParseError::ReservedUsername(raw.to_string()));
        }
        Ok(Self(raw.to_string()))
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
            Some(p) => prefix_len(p, addr.is_ipv4()).ok_or_else(err)?,
            None => max_prefix,
        };
        if prefix > max_prefix {
            return Err(err());
        }
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

/// How many leading one-bits `text` asks for, in any of the three spellings
/// `ipaddress.ip_network` accepts.
///
/// CPython's `_prefix_from_ip_string` tries them in this order:
///
/// 1. an integer prefix - `24`, and `032` too, since it parses as one;
/// 2. a **netmask**, `255.255.255.0`, which must be contiguous ones then zeros;
/// 3. a **hostmask**, `0.0.0.255`, which is that inverted.
///
/// Only IPv4 has the mask spellings - `2001:db8::/ffff::` is an error there,
/// and is one here. "Contiguous" is the whole of the validation:
/// `255.0.0.255` names no prefix length and is refused rather than rounded to
/// something plausible, because a firewall rule that silently covers more
/// addresses than it was written to cover is worse than one that is rejected.
fn prefix_len(text: &str, is_ipv4: bool) -> Option<u8> {
    // CPython gates the integer spelling on `prefixlen_str.isdigit()`, not on
    // `int()` succeeding - so `+8` is not a prefix there, even though it is a
    // number. Rust's `parse::<u8>()` accepts a leading `+`, which made `/+8`
    // an address range here and a `ValueError` in the bash. Digits only.
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        // `/300` is digits and still out of range: rejected, never fallen
        // through to the mask spellings to be read as something else.
        return text.parse::<u8>().ok();
    }
    if !is_ipv4 {
        return None;
    }
    let mask: std::net::Ipv4Addr = text.parse().ok()?;
    let bits = u32::from(mask);
    contiguous_prefix(bits).or_else(|| contiguous_prefix(!bits))
}

/// The prefix length of a contiguous run of ones, or `None` if the bits are
/// not `1*0*`.
fn contiguous_prefix(bits: u32) -> Option<u8> {
    let ones = bits.leading_ones();
    // Everything after the leading ones must be zero. `leading_ones() == 32`
    // means the shift below would be undefined, so it is answered first.
    if ones == 32 {
        return Some(32);
    }
    if bits << ones == 0 {
        Some(ones as u8)
    } else {
        None
    }
}

/// `str(ipaddress.ip_network(raw, strict=False))`, or `None` where CPython
/// raises `ValueError`.
///
/// Used by `firewall-blocklist-run`, which normalises third-party lists
/// downloaded from the internet, and so must agree with the CPython the bash
/// helper shells out to on **every** line - including the ones it throws
/// away. A line Rust keeps and CPython drops puts an address into the
/// firewall that the administrator's list did not ask for; a line Rust drops
/// and CPython keeps quietly shrinks the blocklist.
///
/// Unlike [`IpOrCidr::parse`] this does not trim: CPython refuses
/// `" 1.2.3.4"`, and the blocklist splitter has already removed whitespace by
/// the time a token reaches here, so trimming would only paper over a
/// splitter that had stopped working.
///
/// One difference is deliberate and is checked by test: CPython accepts a
/// scoped address such as `fe80::1%eth0` and returns `fe80::1%eth0/128`. That
/// string is not something `nft` will load, so the bash writes a blocklist
/// entry that fails at the point of use. This returns `None` for it instead.
/// Only link-local addresses carry a zone, and those are never routed.
pub fn normalized_network(raw: &str) -> Option<String> {
    let (addr_part, prefix_part) = match raw.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (raw, None),
    };
    let addr: std::net::IpAddr = addr_part.parse().ok()?;
    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_part {
        Some(p) => prefix_len(p, addr.is_ipv4())?,
        None => max_prefix,
    };
    if prefix > max_prefix {
        return None;
    }
    Some(
        IpOrCidr {
            addr,
            prefix,
            explicit_prefix: prefix_part.is_some(),
        }
        .normalized(),
    )
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
    /// What a container image reference may be, and what it may not.
    ///
    /// The refusals are the point. `-rm` and `a/../b` both pass a naive
    /// character check and are both terrible things to hand `docker pull`.
    #[test]
    fn a_docker_image_reference_cannot_be_read_as_a_flag() {
        for good in [
            "nginx",
            "nginx:1.27",
            "library/nginx:alpine",
            "ghcr.io/owner/name:v1.2.3",
            "registry.example.com:5000/team/app:latest",
            "nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(
                DockerImage::parse(good).is_ok(),
                "{good:?} is an ordinary reference"
            );
        }

        for (bad, why) in [
            ("-rm", "docker would read this as a flag"),
            ("--privileged", "so would this"),
            ("a/../b", "a traversal component"),
            ("..", "just a traversal"),
            ("", "empty"),
            ("Nginx", "uppercase is not valid in a repository name"),
            ("nginx latest", "a space"),
            ("nginx:", "an empty tag"),
            ("nginx@sha256:short", "a truncated digest"),
            ("nginx;rm -rf /", "a semicolon"),
        ] {
            assert!(
                DockerImage::parse(bad).is_err(),
                "{bad:?} must be refused ({why})"
            );
        }
    }

    /// An application name and an image reference are different shapes and
    /// must not be interchangeable.
    #[test]
    fn an_app_name_is_not_an_image_reference() {
        assert!(AppName::parse("ghcr.io/owner/name").is_err());
        assert!(DockerImage::parse("my-app").is_ok());
    }

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

    /// A mixed-case name is refused, not quietly lowercased.
    ///
    /// This is the test that was missing. `parse` lowercased first, so
    /// `UPPER` became a valid `PanelUsername` of `upper` - and `SitePath`
    /// keeps the bytes it was given, so `site-runtime-ensure UPPER
    /// /home/UPPER/x` agreed with itself that the path belonged to that user
    /// and created `/home/UPPER/x` as root, while the account's home was
    /// `/home/upper`. Two directories, one account, and a type that said the
    /// path belonged to a user whose home it was not under.
    ///
    /// Found by running it on a live box, not by reading the code.
    ///
    /// Lowercasing is a real operation the Python does - it is
    /// `linux_user_for_panel_username`, and both API call sites do it
    /// themselves before parsing, which is where it belongs. `parse` is
    /// `validate_linux_user`: it matches the pattern against what it is
    /// given.
    #[test]
    fn a_mixed_case_name_is_refused_rather_than_lowercased() {
        for raw in ["UPPER", "Alice", "bOb", "aB_c"] {
            assert!(
                PanelUsername::parse(raw).is_err(),
                "{raw} must be refused, not normalised"
            );
        }
        assert_eq!(PanelUsername::parse("alice").unwrap().as_str(), "alice");
    }

    #[test]
    fn surrounding_whitespace_is_refused_too() {
        // The bash's `require_linux_user` anchors its pattern, so a name with
        // a stray newline from a file or a form is not a name.
        for raw in [" alice", "alice ", "alice\n", "\talice"] {
            assert!(PanelUsername::parse(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn a_reserved_name_is_refused_in_the_case_it_is_written() {
        // The reserved list is compared against what was given, so it has to
        // be reached by names that are already lowercase - which, now that
        // parse does not normalise, is the only form that gets that far.
        for raw in ["root", "www-data", "mysql", "nginx", "snpanel", "nobody"] {
            assert!(PanelUsername::parse(raw).is_err(), "{raw} is reserved");
        }
    }

    /// `normalized_network` against CPython's `ipaddress`, over 1,560 inputs.
    ///
    /// Recorded from the interpreter the bash helper actually shells out to,
    /// and re-checked on Debian 13's CPython 3.13.5 before being committed -
    /// 0 of the 1,560 differ between that and the 3.14 the corpus was written
    /// on.
    ///
    /// The rejected cases matter as much as the accepted ones. This
    /// normalises third-party lists downloaded from the internet: a line Rust
    /// keeps and CPython drops puts an address into the firewall that nobody
    /// asked to block, and a line Rust drops and CPython keeps quietly
    /// shrinks the blocklist.
    #[test]
    fn ip_networks_normalize_exactly_as_cpython_does() {
        #[derive(serde::Deserialize)]
        struct Case {
            raw: String,
            normalized: Option<String>,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/ip_network.json");
        let raw = std::fs::read_to_string(&path).expect("the ip_network corpus");
        let cases: Vec<Case> = serde_json::from_str(&raw).expect("the corpus parses");
        assert!(cases.len() > 1_500, "the corpus is {} cases", cases.len());

        // The one deliberate difference, spelled out so it cannot grow
        // quietly: CPython accepts a scoped address and returns the zone with
        // it, which is not a string `nft` will load.
        let scoped: &[&str] = &["fe80::1%eth0", "fe80::1%1"];

        let mut accepted = 0;
        let mut rejected = 0;
        for case in &cases {
            let got = normalized_network(&case.raw);
            if scoped.contains(&case.raw.as_str()) {
                assert!(
                    case.normalized.is_some(),
                    "{:?} is listed as a scoped exception but CPython rejects it too, \
                     so the exception is stale",
                    case.raw
                );
                assert_eq!(got, None, "{:?} must be dropped here", case.raw);
                continue;
            }
            assert_eq!(
                got.as_deref(),
                case.normalized.as_deref(),
                "on input {:?}",
                case.raw
            );
            if case.normalized.is_some() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        // A corpus that had drifted to all-rejects would pass every assertion
        // above while proving nothing.
        assert!(accepted > 1_400, "only {accepted} accepted");
        assert!(rejected > 50, "only {rejected} rejected");
    }

    /// The three prefix spellings `ipaddress` accepts, and the masks that are
    /// not prefix lengths at all.
    ///
    /// `255.0.0.255` names no prefix. Rounding it to something plausible
    /// would produce a firewall rule covering more addresses than it was
    /// written to cover, so it is refused.
    #[test]
    fn a_prefix_may_be_a_number_a_netmask_or_a_hostmask() {
        let n = |s: &str| normalized_network(s);

        assert_eq!(n("192.0.2.130/24").as_deref(), Some("192.0.2.0/24"));
        assert_eq!(
            n("192.0.2.130/255.255.255.0").as_deref(),
            Some("192.0.2.0/24")
        );
        assert_eq!(n("192.0.2.130/0.0.0.255").as_deref(), Some("192.0.2.0/24"));
        // `032` parses as a number, so it never reaches the mask spellings.
        assert_eq!(n("192.0.2.130/032").as_deref(), Some("192.0.2.130/32"));

        // The extremes, where a shift by the full width would be undefined.
        assert_eq!(n("192.0.2.130/0.0.0.0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(
            n("192.0.2.130/255.255.255.255").as_deref(),
            Some("192.0.2.130/32")
        );
        assert_eq!(n("192.0.2.130/0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(n("192.0.2.130/32").as_deref(), Some("192.0.2.130/32"));

        // Not contiguous: neither a netmask nor a hostmask.
        assert_eq!(n("192.0.2.130/255.0.0.255"), None);
        assert_eq!(n("192.0.2.130/0.255.0.255"), None);

        // Out of range for the family, in both spellings.
        assert_eq!(n("192.0.2.130/33"), None);
        assert_eq!(n("2001:db8::1/129"), None);
        assert_eq!(n("192.0.2.130/-1"), None);
        assert_eq!(n("192.0.2.130/300"), None);

        // The mask spellings are IPv4 only.
        assert_eq!(n("2001:db8::/ffff::"), None);
        assert_eq!(
            n("2001:db8::dead:beef/64").as_deref(),
            Some("2001:db8::/64")
        );

        // A bare address gains its full-length prefix.
        assert_eq!(n("203.0.113.44").as_deref(), Some("203.0.113.44/32"));
        assert_eq!(n("::").as_deref(), Some("::/128"));

        // No trimming: CPython refuses these and so does this.
        assert_eq!(n(" 1.2.3.4"), None);
        assert_eq!(n("1.2.3.4 "), None);
        assert_eq!(n(""), None);
    }

    /// A dotted-quad mask reaches `IpOrCidr::parse` too.
    ///
    /// `require_ip_or_cidr` guards firewall rule input with
    /// `^[0-9a-fA-F.:/]+$`, which lets `255.255.255.0` through, and the bash
    /// then resolves it through the same CPython call. Parsing the prefix
    /// only as an integer - which is what this did - refused a rule an
    /// administrator could add through the bash helper.
    #[test]
    fn a_firewall_rule_may_be_written_with_a_netmask() {
        let parsed = IpOrCidr::parse("10.0.0.5/255.0.0.0").expect("a netmask is a prefix");
        assert_eq!(parsed.prefix(), 8);
        assert_eq!(parsed.normalized(), "10.0.0.0/8");

        let parsed = IpOrCidr::parse("10.0.0.5/0.255.255.255").expect("a hostmask too");
        assert_eq!(parsed.prefix(), 8);
        assert_eq!(parsed.normalized(), "10.0.0.0/8");

        assert!(IpOrCidr::parse("10.0.0.5/255.0.0.255").is_err());
        assert!(IpOrCidr::parse("10.0.0.5/33").is_err());
        assert!(IpOrCidr::parse("2001:db8::/ffff::").is_err());
    }

    /// The two refusals `require_linux_user` has, kept apart.
    ///
    /// Found by A/B against the installed bash helper, not by reading it: the
    /// bash answered "reserved panel Linux user: snpanel" where this said
    /// "invalid panel username: snpanel". `snpanel` is a perfectly
    /// well-shaped name, so being told it is invalid sends an administrator
    /// looking at the shape of a name that has nothing wrong with its shape.
    #[test]
    fn a_reserved_username_says_so_rather_than_invalid() {
        for reserved in ["root", "snpanel", "www-data", "mysql", "nobody"] {
            let err = PanelUsername::parse(reserved).expect_err(reserved);
            assert_eq!(
                err.to_string(),
                format!("reserved panel Linux user: {reserved}")
            );
        }

        let too_long = "a".repeat(33);
        for malformed in ["ab", "1abc", "Abc", "a b", "", too_long.as_str()] {
            let err = PanelUsername::parse(malformed).expect_err(malformed);
            assert_eq!(
                err.to_string(),
                format!("invalid panel username: {malformed}")
            );
        }

        // A name that is neither is accepted.
        assert!(PanelUsername::parse("bp_example").is_ok());
    }
}
