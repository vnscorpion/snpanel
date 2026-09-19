//! Rendering a website's nginx vhost.
//!
//! Contract C19: this must produce the same bytes as `app.services.nginx`.
//! A vhost that differs by one line is a website that stops serving, and
//! nobody notices until a customer reports it - so the templates are the ones
//! the Python uses, rendered by minijinja, and the test walks the golden
//! fixtures the real Jinja2 produced.
//!
//! What is ported here is the work *around* the template: choosing the server
//! names, resolving the document root and the FPM socket, computing the flood
//! zone, replacing the bot block, applying a manual certificate and appending
//! the redirect vhosts. Rendering only the template would leave those four
//! steps untested, which is why the fixtures capture the finished file.
//!
//! Plan §8 Stage C.

use std::path::{Component, Path, PathBuf};

use snpanel_core::Domain;

mod custom;
pub use custom::{CustomDirectives, CustomError};

/// The templates are compiled in rather than read at run time.
///
/// An installation that updated its Python templates without updating this
/// binary would otherwise render something neither side had tested. Compiling
/// them in means the bytes this produces are the bytes the golden fixtures
/// were diffed against.
const WORDPRESS_TEMPLATE: &str =
    include_str!("../../../backend/app/templates/nginx/wordpress.conf.j2");
const PHP_TEMPLATE: &str = include_str!("../../../backend/app/templates/nginx/php.conf.j2");
const STATIC_TEMPLATE: &str = include_str!("../../../backend/app/templates/nginx/static.conf.j2");
const PROXY_TEMPLATE: &str = include_str!("../../../backend/app/templates/nginx/proxy.conf.j2");

pub const ALLOWED_PHP_VERSIONS: &[&str] = &["5.6", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"];
pub const ALLOWED_APP_TYPES: &[&str] = &["wordpress", "php", "static", "application"];
pub const ALLOWED_REWRITE_MODES: &[&str] = &[
    "none",
    "front_controller",
    "laravel",
    "codeigniter",
    "seohburl",
];
const PROXY_TIMEOUT_SECONDS: u32 = 300;
const PUBLIC_DIR: &str = "public_html";
const MAX_BLOCKED_BOTS: usize = 500;
const MAX_BOT_NAME_LENGTH: usize = 120;
/// Source: `_SSL_PATH_ROOTS`.
const SSL_PATH_ROOTS: &[&str] = &["/etc/nginx/snpanel/ssl/sites/", "/etc/letsencrypt/live/"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// Source: every `raise ValueError` in `render_vhost` and its helpers.
    Invalid(String),
    /// minijinja could not render. Not reachable from a valid input, but a
    /// template edit that breaks one should say so rather than panic.
    Template(String),
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "{m}"),
            Self::Template(m) => write!(f, "template error: {m}"),
        }
    }
}

impl std::error::Error for RenderError {}

fn invalid<T>(message: impl Into<String>) -> Result<T, RenderError> {
    Err(RenderError::Invalid(message.into()))
}

/// Two facts about the machine that the render depends on.
///
/// They are arguments rather than probes because a fixture generated on a box
/// with the ModSecurity module and one generated without it would disagree,
/// and the fixtures are the contract. The caller asks the machine; this
/// renders what it was told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhostEnv {
    /// `panel_ipv6.is_enabled()`.
    pub ipv6: bool,
    /// `waf_engine_available()`. `modsecurity on;` where the module is not
    /// loaded makes nginx reject its whole configuration, so the site's own
    /// setting is only half the answer.
    pub waf_engine: bool,
    /// `settings.default_php_version`, used when a site names none.
    pub default_php_version: String,
    /// `site_users.HOME_ROOT`. A parameter so the fixtures can be generated
    /// under a sandbox, exactly as the Python's generator patches it.
    pub home_root: PathBuf,
}

impl Default for VhostEnv {
    fn default() -> Self {
        Self {
            ipv6: false,
            waf_engine: true,
            default_php_version: "8.4".to_string(),
            home_root: PathBuf::from("/home"),
        }
    }
}

/// Everything `render_vhost` takes, with the Python's defaults.
#[derive(Debug, Clone)]
pub struct VhostInput<'a> {
    pub domain: &'a str,
    pub root_path: &'a Path,
    pub app_type: &'a str,
    pub php_version: Option<&'a str>,
    pub custom_directives: &'a CustomDirectives,
    pub php_fpm_socket_override: Option<&'a str>,
    pub waf_enabled: bool,
    pub http_flood_enabled: bool,
    pub http_flood_config: HttpFloodConfig,
    pub document_root: &'a str,
    pub rewrite_mode: Option<&'a str>,
    pub ssl_cert_path: Option<&'a str>,
    pub ssl_key_path: Option<&'a str>,
    pub ssl_ca_path: Option<&'a str>,
    pub aliases: &'a [String],
    pub redirects: &'a [String],
    pub app_port: Option<i64>,
    /// `None` means "keep whatever this vhost already blocks", which is the
    /// Python's contract; the caller reads the existing file and passes what
    /// it found. An empty slice clears the block.
    pub blocked_bots: Option<&'a [String]>,
}

impl<'a> VhostInput<'a> {
    pub fn new(domain: &'a str, root_path: &'a Path, custom: &'a CustomDirectives) -> Self {
        Self {
            domain,
            root_path,
            app_type: "wordpress",
            php_version: None,
            custom_directives: custom,
            php_fpm_socket_override: None,
            waf_enabled: true,
            http_flood_enabled: false,
            http_flood_config: HttpFloodConfig::default(),
            document_root: PUBLIC_DIR,
            rewrite_mode: None,
            ssl_cert_path: None,
            ssl_key_path: None,
            ssl_ca_path: None,
            aliases: &[],
            redirects: &[],
            app_port: None,
            blocked_bots: None,
        }
    }
}

/// Source: `HTTP_FLOOD_DEFAULTS` and `validate_http_flood_config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpFloodConfig {
    pub access_limit_requests: i64,
    pub access_limit_window: i64,
    pub access_limit_burst: i64,
    pub connection_limit: i64,
}

impl Default for HttpFloodConfig {
    fn default() -> Self {
        Self {
            access_limit_requests: 100,
            access_limit_window: 10,
            access_limit_burst: 100,
            connection_limit: 60,
        }
    }
}

impl HttpFloodConfig {
    /// Source: `validate_http_flood_config` - anything unparseable becomes the
    /// default, and everything is clamped rather than rejected.
    pub fn from_json(raw: &serde_json::Value) -> Self {
        let d = Self::default();
        let pick = |key: &str, default: i64, min: i64, max: i64| -> i64 {
            let n = match raw.get(key) {
                Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(default),
                Some(serde_json::Value::String(s)) => s.trim().parse::<i64>().unwrap_or(default),
                _ => default,
            };
            n.clamp(min, max)
        };
        Self {
            access_limit_requests: pick(
                "access_limit_requests",
                d.access_limit_requests,
                1,
                100_000,
            ),
            access_limit_window: pick("access_limit_window", d.access_limit_window, 1, 3_600),
            access_limit_burst: pick("access_limit_burst", d.access_limit_burst, 0, 100_000),
            connection_limit: pick("connection_limit", d.connection_limit, 1, 10_000),
        }
    }

    /// The column holds a JSON string, or an empty one.
    pub fn from_text(raw: &str) -> Self {
        if raw.trim().is_empty() {
            return Self::default();
        }
        match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(value) if value.is_object() => Self::from_json(&value),
            _ => Self::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// names and paths
// ---------------------------------------------------------------------------

/// Source: `_safe_domain`.
fn safe_domain(domain: &str) -> Result<String, RenderError> {
    match Domain::parse(domain.trim()) {
        Ok(d) => Ok(d.as_str().to_string()),
        Err(_) => invalid("Invalid domain"),
    }
}

/// Source: `_safe_alias_domains` - validated, de-duplicated, order kept.
fn safe_alias_domains(aliases: &[String]) -> Result<Vec<String>, RenderError> {
    let mut out: Vec<String> = Vec::new();
    for alias in aliases {
        let safe = safe_domain(alias)?;
        if !out.iter().any(|a| a == &safe) {
            out.push(safe);
        }
    }
    Ok(out)
}

/// Source: `_server_names`.
fn server_names(domain: &str, aliases: &[String]) -> Result<Vec<String>, RenderError> {
    let safe = safe_domain(domain)?;
    let mut names = vec![safe.clone(), format!("www.{safe}")];
    for alias in safe_alias_domains(aliases)? {
        if alias != safe && !names.iter().any(|n| n == &alias) {
            names.push(alias);
        }
    }
    Ok(names)
}

/// Source: `custom_include_path`.
pub fn custom_include_path(domain: &str) -> Result<String, RenderError> {
    Ok(format!(
        "/etc/nginx/snpanel/custom/{}.conf",
        safe_domain(domain)?
    ))
}

/// Source: `waf_rules_file`.
pub fn waf_rules_file(domain: &str) -> Result<String, RenderError> {
    Ok(format!(
        "/etc/nginx/modsec/sites/{}.conf",
        safe_domain(domain)?
    ))
}

/// Source: `http_flood_zone_name` - the first twelve hex of SHA-1.
///
/// SHA-1 is not a security choice here; it is a naming contract with zones
/// already in the nginx configuration of every machine running this panel.
pub fn http_flood_zone_name(domain: &str) -> Result<String, RenderError> {
    use sha1::{Digest, Sha1};
    let safe = safe_domain(domain)?;
    let digest = Sha1::digest(safe.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("snpanel_hf_{}", &hex[..12]))
}

/// Source: `site_users.validate_document_root`.
fn validate_document_root(value: &str) -> Result<String, RenderError> {
    let cleaned = if value.trim().is_empty() {
        PUBLIC_DIR.to_string()
    } else {
        value.trim().replace('\\', "/")
    };
    if cleaned.starts_with('/') {
        return invalid("document_root must be relative to the website root");
    }
    // `^[A-Za-z]:/` - a Windows drive letter is not a relative path either.
    let bytes = cleaned.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        return invalid("document_root must be relative to the website root");
    }
    let cleaned = cleaned.trim_matches('/');
    if cleaned.is_empty() || cleaned.len() > 255 {
        return invalid("document_root must be a relative path up to 255 characters");
    }
    let parts: Vec<&str> = cleaned.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return invalid("document_root must be a relative path up to 255 characters");
    }
    for part in &parts {
        let ok = !part.is_empty()
            && *part != "."
            && *part != ".."
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
        if !ok {
            return invalid(
                "document_root must be a safe relative path such as public_html/public",
            );
        }
    }
    Ok(parts.join("/"))
}

/// Source: `_effective_document_root`.
fn effective_document_root(document_root: &str, rewrite_mode: &str) -> Result<String, RenderError> {
    let safe = validate_document_root(document_root)?;
    if matches!(rewrite_mode, "laravel" | "codeigniter") && safe.trim_end_matches('/') == PUBLIC_DIR
    {
        return Ok("public_html/public".to_string());
    }
    Ok(safe)
}

/// `Path.resolve()` with `strict=False`: canonicalise the longest existing
/// prefix, then normalise the rest lexically.
///
/// The difference matters. A purely lexical normalisation would accept a root
/// reached through a symlink that Python rejects, and this feeds
/// `is_site_root_for_domain`, which is a check and not a convenience.
fn resolve_like_python(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    // The leaf may not exist yet - a document root about to be created, or a
    // fixture path that never will. Canonicalise the longest ancestor that
    // does, so a symlinked site root still resolves the way Python's does,
    // then apply the rest lexically.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path.to_path_buf();
    while let (Some(parent), Some(name)) = (
        cursor.parent().map(Path::to_path_buf),
        cursor.file_name().map(|n| n.to_os_string()),
    ) {
        tail.push(name);
        if let Ok(real) = std::fs::canonicalize(&parent) {
            let mut out = real;
            for n in tail.iter().rev() {
                out.push(n);
            }
            return normalise_lexically(&out);
        }
        if parent.as_os_str().is_empty() {
            break;
        }
        cursor = parent;
    }
    normalise_lexically(path)
}

/// `.` dropped, `..` applied, nothing touched on disk.
fn normalise_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Source: `site_users.document_root`.
fn document_root_path(root: &Path, relative: &str) -> Result<PathBuf, RenderError> {
    let root = resolve_like_python(root);
    let target = resolve_like_python(&root.join(validate_document_root(relative)?));
    if !target.starts_with(&root) {
        return invalid("document_root must stay inside the website root");
    }
    Ok(target)
}

/// Source: `site_users.is_site_root_for_domain`.
fn is_site_root_for_domain(path: &Path, domain: &str, home_root: &Path) -> bool {
    let resolved = resolve_like_python(path);
    let home = resolve_like_python(home_root);
    let Ok(relative) = resolved.strip_prefix(&home) else {
        return false;
    };
    let parts: Vec<_> = relative.components().collect();
    if parts.len() != 2 {
        return false;
    }
    let user = parts[0].as_os_str().to_string_lossy();
    let site = parts[1].as_os_str().to_string_lossy();
    snpanel_core::PanelUsername::parse(&user).is_ok() && site == domain.trim().to_ascii_lowercase()
}

/// Source: `_php_fpm_socket`.
fn php_fpm_socket(php_version: Option<&str>, default: &str) -> Result<String, RenderError> {
    let version = match php_version {
        Some(v) => {
            if !ALLOWED_PHP_VERSIONS.contains(&v) {
                return invalid(format!("Unsupported PHP version: {v}"));
            }
            v
        }
        None => default,
    };
    if !ALLOWED_PHP_VERSIONS.contains(&version) {
        return invalid(format!("Unsupported PHP version: {version}"));
    }
    Ok(format!("/run/php/php{version}-fpm.sock"))
}

// ---------------------------------------------------------------------------
// the render
// ---------------------------------------------------------------------------

/// Source: `render_vhost`.
pub fn render_vhost(input: &VhostInput<'_>, env: &VhostEnv) -> Result<String, RenderError> {
    let names = server_names(input.domain, input.aliases)?;
    let safe_domain = names[0].clone();

    if !ALLOWED_APP_TYPES.contains(&input.app_type) {
        return invalid(format!("Unsupported app type: {}", input.app_type));
    }
    // Source: `_check_app_port` - only the proxied type takes one, and a
    // proxied vhost without a port is a config that fails `nginx -t`.
    let app_port = if input.app_type == "application" {
        match input.app_port {
            Some(p) if (1..=65535).contains(&p) => Some(p),
            Some(_) => return invalid("Application port is out of range"),
            None => return invalid("Pick an installed application for this website first"),
        }
    } else {
        None
    };
    let rewrite_mode = input
        .rewrite_mode
        .unwrap_or("none")
        .trim()
        .to_ascii_lowercase();
    let rewrite_mode = if rewrite_mode.is_empty() {
        "none".to_string()
    } else {
        rewrite_mode
    };
    if !ALLOWED_REWRITE_MODES.contains(&rewrite_mode.as_str()) {
        return invalid(format!(
            "Unsupported nginx rewrite mode: {}",
            input.rewrite_mode.unwrap_or("")
        ));
    }
    if let Some(v) = input.php_version {
        if !ALLOWED_PHP_VERSIONS.contains(&v) {
            return invalid(format!("Unsupported PHP version: {v}"));
        }
    }

    let resolved_root = resolve_like_python(input.root_path);
    if !is_site_root_for_domain(&resolved_root, &safe_domain, &env.home_root) {
        return invalid("root_path must be the managed root for this domain");
    }
    let effective_root = effective_document_root(input.document_root, &rewrite_mode)?;
    let resolved_document_root = document_root_path(&resolved_root, &effective_root)?;
    let include_path = custom_include_path(&safe_domain)?;

    let template_source = match input.app_type {
        "wordpress" => WORDPRESS_TEMPLATE,
        "php" => PHP_TEMPLATE,
        "static" => STATIC_TEMPLATE,
        "application" => PROXY_TEMPLATE,
        other => return invalid(format!("Unsupported app type: {other}")),
    };
    let socket = match input.php_fpm_socket_override {
        Some(s) => s.to_string(),
        None => php_fpm_socket(input.php_version, &env.default_php_version)?,
    };

    let mut environment = minijinja::Environment::new();
    environment
        .add_template("vhost", template_source)
        .map_err(|e| RenderError::Template(e.to_string()))?;
    let template = environment
        .get_template("vhost")
        .map_err(|e| RenderError::Template(e.to_string()))?;

    let context = minijinja::context! {
        ipv6 => env.ipv6,
        domain => safe_domain.clone(),
        server_names => names.clone(),
        root_path => resolved_root.to_string_lossy(),
        document_root_path => resolved_document_root.to_string_lossy(),
        php_fpm_socket => socket,
        custom_include_path => include_path,
        waf_enabled => input.waf_enabled && env.waf_engine,
        waf_rules_file => waf_rules_file(&safe_domain)?,
        http_flood_enabled => input.http_flood_enabled,
        http_flood_zone => http_flood_zone_name(&safe_domain)?,
        http_flood_burst => input.http_flood_config.access_limit_burst,
        http_flood_connections => input.http_flood_config.connection_limit,
        http_flood_challenge_block => http_flood_challenge_block(),
        rewrite_mode => rewrite_mode.clone(),
        app_port => app_port,
        proxy_timeout => PROXY_TIMEOUT_SECONDS,
    };

    let rendered = template
        .render(context)
        .map_err(|e| RenderError::Template(e.to_string()))?;

    let rendered = replace_bot_block(&rendered, input.blocked_bots)?;
    let rendered = if input.ssl_cert_path.is_some() || input.ssl_key_path.is_some() {
        apply_manual_ssl_config(
            &rendered,
            input.ssl_cert_path.unwrap_or(""),
            input.ssl_key_path.unwrap_or(""),
            input.ssl_ca_path,
        )?
    } else {
        rendered
    };
    append_redirect_vhosts(
        &rendered,
        &safe_domain,
        input.redirects,
        input.ssl_cert_path,
        input.ssl_key_path,
        input.ssl_ca_path,
    )
}

/// Source: `_http_flood_challenge_block`.
fn http_flood_challenge_block() -> String {
    let challenge_html = concat!(
        r#"<!doctype html><html><head><meta charset="utf-8">"#,
        r#"<meta name="viewport" content="width=device-width,initial-scale=1">"#,
        r#"<title>Checking browser</title>"#,
        r#"<style>body{font-family:system-ui,sans-serif;background:#f8fafc;color:#0f172a;display:grid;place-items:center;min-height:100vh;margin:0}"#,
        r#"main{max-width:420px;padding:24px;text-align:center}"#,
        r#"strong{display:block;font-size:20px;margin-bottom:8px}</style>"#,
        r#"<script>setTimeout(function(){document.cookie="snpanel_http_flood_ok=1; Max-Age=3600; Path=/; SameSite=Lax";"#,
        r#"window.location.replace(window.location.href)},3000)</script>"#,
        r#"</head><body><main><strong>Checking browser</strong><p>Please wait a moment and refresh automatically.</p></main></body></html>"#,
    );
    format!(
        "    error_page 429 = @snpanel_http_flood_challenge;\n\
         \x20   location @snpanel_http_flood_challenge {{\n\
         \x20       default_type text/html;\n\
         \x20       add_header Cache-Control \"no-store\" always;\n\
         \x20       return 200 '{challenge_html}';\n\
         \x20   }}"
    )
}

// ---------------------------------------------------------------------------
// bot blocking
// ---------------------------------------------------------------------------

/// Source: `normalize_blocked_bots`.
pub fn normalize_blocked_bots(raw: &[String]) -> Result<Vec<String>, RenderError> {
    let mut bots: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for candidate in raw {
        let name = candidate
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        if name.chars().count() > MAX_BOT_NAME_LENGTH {
            let head: String = name.chars().take(40).collect();
            return invalid(format!(
                "Bot name is too long (max {MAX_BOT_NAME_LENGTH} characters): {head}..."
            ));
        }
        // The rendered form is a double-quoted nginx string, and `"` is not a
        // regex metacharacter - escaping for PCRE would not touch it, so a
        // name containing one would close the string early and let the rest be
        // read as configuration.
        if name.contains(['"', '\\', '\r', '\n']) {
            let head: String = name.chars().take(40).collect();
            return invalid(format!(
                "Bot name cannot contain quotes, backslashes or line breaks: {head}"
            ));
        }
        if name.chars().any(|c| (c as u32) < 32) {
            let head: String = name.chars().take(40).collect();
            return invalid(format!(
                "Bot name cannot contain control characters: {head}"
            ));
        }
        let key = name.to_lowercase();
        if seen.iter().any(|s| s == &key) {
            continue;
        }
        seen.push(key);
        bots.push(name);
    }
    if bots.len() > MAX_BLOCKED_BOTS {
        return invalid(format!(
            "Too many bots (max {MAX_BLOCKED_BOTS}); got {}",
            bots.len()
        ));
    }
    Ok(bots)
}

/// Source: `re.escape` as CPython 3.7+ implements it - everything outside
/// `[A-Za-z0-9_]` and ASCII whitespace is backslash-escaped.
fn regex_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        let special = !(c.is_ascii_alphanumeric() || c == '_' || (c as u32) >= 0x80);
        if special && !matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

const BOT_BEGIN: &str = "    # SNPANEL BOT BLOCK BEGIN";
const BOT_END: &str = "    # SNPANEL BOT BLOCK END";

/// Source: `_bot_block`.
fn bot_block(bots: &[String]) -> String {
    let alternation: Vec<String> = bots.iter().map(|b| regex_escape(b)).collect();
    format!(
        "{BOT_BEGIN}\n    if ($http_user_agent ~* \"({})\") {{ return 403; }}\n{BOT_END}",
        alternation.join("|")
    )
}

/// Source: `_replace_bot_block`.
///
/// `None` keeps whatever the file already blocks, which is the Python's
/// contract: the callers that rebuild a vhost do not all know about bot
/// lists, and without it every full rewrite silently dropped the block.
fn replace_bot_block(content: &str, bots: Option<&[String]>) -> Result<String, RenderError> {
    let cleaned = strip_bot_block(content);
    let Some(bots) = bots else {
        return Ok(format!("{}\n", cleaned.trim_end()));
    };
    let safe = normalize_blocked_bots(bots)?;
    if safe.is_empty() {
        return Ok(format!("{}\n", cleaned.trim_end()));
    }
    let block = bot_block(&safe);
    for anchor in ["    # SNPANEL HTTP FLOOD BEGIN", "    # SNPANEL WAF BEGIN"] {
        if let Some(at) = cleaned.find(anchor) {
            let mut out = String::with_capacity(cleaned.len() + block.len() + 2);
            out.push_str(&cleaned[..at]);
            out.push_str(&block);
            out.push_str("\n\n");
            out.push_str(&cleaned[at..]);
            return Ok(out);
        }
    }
    if let Some(at) = cleaned.find("    server_tokens off;") {
        let end = at + "    server_tokens off;".len();
        let mut out = String::with_capacity(cleaned.len() + block.len() + 1);
        out.push_str(&cleaned[..end]);
        out.push('\n');
        out.push_str(&block);
        out.push_str(&cleaned[end..]);
        return Ok(out);
    }
    if let Some(at) = cleaned.find("    server_name ") {
        if let Some(semi) = cleaned[at..].find(';') {
            let end = at + semi + 1;
            let mut out = String::with_capacity(cleaned.len() + block.len() + 1);
            out.push_str(&cleaned[..end]);
            out.push('\n');
            out.push_str(&block);
            out.push_str(&cleaned[end..]);
            return Ok(out);
        }
    }
    if let Some(at) = find_server_brace(&cleaned) {
        let mut out = String::with_capacity(cleaned.len() + block.len() + 1);
        out.push_str(&cleaned[..at]);
        out.push('\n');
        out.push_str(&block);
        out.push_str(&cleaned[at..]);
        return Ok(out);
    }
    invalid("Cannot find server block for bot blocking directives")
}

/// Source: the `\n?    # SNPANEL BOT BLOCK BEGIN\n.*?\n    # SNPANEL BOT BLOCK END`
/// substitution - non-greedy, so it removes each block separately.
fn strip_bot_block(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(begin) = rest.find(BOT_BEGIN) {
        let Some(end_rel) = rest[begin..].find(BOT_END) else {
            break;
        };
        let end = begin + end_rel + BOT_END.len();
        // The pattern starts with an optional newline before the marker.
        let cut = if begin > 0 && rest.as_bytes()[begin - 1] == b'\n' {
            begin - 1
        } else {
            begin
        };
        out.push_str(&rest[..cut]);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Source: `re.search(r"server\s*\{", cleaned)` - the end of the match.
fn find_server_brace(content: &str) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut i = 0;
    while let Some(at) = content[i..].find("server") {
        let start = i + at;
        let mut j = start + "server".len();
        while j < bytes.len() && (bytes[j] as char).is_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'{' {
            return Some(j + 1);
        }
        i = start + 1;
    }
    None
}

// ---------------------------------------------------------------------------
// manual SSL and redirects
// ---------------------------------------------------------------------------

/// Source: `_manual_ssl_paths`.
fn manual_ssl_paths(
    cert_path: &str,
    key_path: &str,
    ca_path: Option<&str>,
) -> Result<(String, String, Option<String>), RenderError> {
    if cert_path.is_empty() || key_path.is_empty() {
        return invalid("Manual SSL certificate and key paths are required");
    }
    let cert = cert_path.replace('\\', "/");
    let key = key_path.replace('\\', "/");
    let ca = ca_path
        .filter(|c| !c.is_empty())
        .map(|c| c.replace('\\', "/"));
    for value in [Some(&cert), Some(&key), ca.as_ref()].into_iter().flatten() {
        if value.contains('\0')
            || value.contains('\n')
            || value.contains('\r')
            || value.contains("..")
        {
            return invalid("Manual SSL path contains unsafe characters");
        }
        if !SSL_PATH_ROOTS.iter().any(|root| value.starts_with(root)) {
            return invalid(
                "SSL paths must be under /etc/nginx/snpanel/ssl/sites or /etc/letsencrypt/live",
            );
        }
    }
    Ok((cert, key, ca))
}

/// Source: `apply_manual_ssl_config`.
fn apply_manual_ssl_config(
    new_content: &str,
    cert_path: &str,
    key_path: &str,
    ca_path: Option<&str>,
) -> Result<String, RenderError> {
    let (cert, key, ca) = manual_ssl_paths(cert_path, key_path, ca_path)?;
    let fullchain = format!(
        "{}/fullchain.crt",
        cert.rsplit_once('/').map_or("", |(h, _)| h)
    );
    let mut server_name = "_".to_string();
    if let Some(at) = new_content.find("server_name ") {
        let after = &new_content[at + "server_name ".len()..];
        if let Some(semi) = after.find(';') {
            server_name = after[..semi].trim().to_string();
        } else {
            server_name = after.trim().to_string();
        }
    }
    let mut ssl_lines = vec![
        format!(
            "    ssl_certificate {};",
            if ca.is_some() { &fullchain } else { &cert }
        ),
        format!("    ssl_certificate_key {key};"),
        "    ssl_protocols TLSv1.2 TLSv1.3;".to_string(),
        "    ssl_prefer_server_ciphers off;".to_string(),
    ];
    if let Some(ca) = &ca {
        ssl_lines.push(format!("    ssl_trusted_certificate {ca};"));
    }

    let mut https_lines: Vec<String> = Vec::new();
    let mut inserted = false;
    // `str::lines`, not `split('\n')`: Python's `splitlines()` does not yield
    // a trailing empty element for text that ends in a newline, and this text
    // always does - `_replace_bot_block` returns `rstrip() + "\n"`. Splitting
    // instead added one blank line to every manually-certificated vhost.
    for line in new_content.lines() {
        if line.contains("listen 80;") {
            https_lines.push(line.replace("listen 80;", "listen 443 ssl http2;"));
        } else {
            https_lines.push(line.to_string());
        }
        if !inserted && line.contains("server_name") {
            https_lines.extend(ssl_lines.iter().cloned());
            inserted = true;
        }
    }
    let redirect_block = [
        "server {",
        "    listen 80;",
        &format!("    server_name {server_name};"),
        "    return 301 https://$host$request_uri;",
        "}",
        "",
    ]
    .join("\n");
    Ok(format!("{redirect_block}{}\n", https_lines.join("\n")))
}

/// Source: `_redirect_vhost_blocks`.
fn redirect_vhost_blocks(
    safe_domain: &str,
    redirects: &[String],
    ssl_cert_path: Option<&str>,
    ssl_key_path: Option<&str>,
    ssl_ca_path: Option<&str>,
) -> Result<String, RenderError> {
    let reserved = [safe_domain.to_string(), format!("www.{safe_domain}")];
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut ca: Option<String> = None;
    if ssl_cert_path.is_some() || ssl_key_path.is_some() {
        let (c, k, a) = manual_ssl_paths(
            ssl_cert_path.unwrap_or(""),
            ssl_key_path.unwrap_or(""),
            ssl_ca_path,
        )?;
        let c = if a.is_some() {
            format!(
                "{}/fullchain.crt",
                c.rsplit_once('/').map_or("", |(h, _)| h)
            )
        } else {
            c
        };
        cert = Some(c);
        key = Some(k);
        ca = a;
    }

    let mut blocks: Vec<String> = Vec::new();
    for redirect_domain in safe_alias_domains(redirects)? {
        if reserved.iter().any(|r| r == &redirect_domain) {
            continue;
        }
        let mut lines = vec![
            "server {".to_string(),
            "    listen 80;".to_string(),
            format!("    server_name {redirect_domain};"),
            String::new(),
            "    # SNPANEL ACME CHALLENGE".to_string(),
            "    location ^~ /.well-known/acme-challenge/ {".to_string(),
            "        root /var/www/snpanel-acme;".to_string(),
            "        default_type text/plain;".to_string(),
            "        try_files $uri =404;".to_string(),
            "        access_log off;".to_string(),
            "        auth_basic off;".to_string(),
            "    }".to_string(),
            String::new(),
            format!("    return 301 https://{safe_domain}$request_uri;"),
            "}".to_string(),
        ];
        if let (Some(cert), Some(key)) = (&cert, &key) {
            lines.extend([
                String::new(),
                "server {".to_string(),
                "    listen 443 ssl http2;".to_string(),
                format!("    server_name {redirect_domain};"),
                format!("    ssl_certificate {cert};"),
                format!("    ssl_certificate_key {key};"),
                "    ssl_protocols TLSv1.2 TLSv1.3;".to_string(),
                "    ssl_prefer_server_ciphers off;".to_string(),
            ]);
            if let Some(ca) = &ca {
                lines.push(format!("    ssl_trusted_certificate {ca};"));
            }
            lines.extend([
                format!("    return 301 https://{safe_domain}$request_uri;"),
                "}".to_string(),
            ]);
        }
        blocks.push(lines.join("\n"));
    }
    Ok(blocks.join("\n\n"))
}

/// Source: `_append_redirect_vhosts`.
fn append_redirect_vhosts(
    content: &str,
    safe_domain: &str,
    redirects: &[String],
    ssl_cert_path: Option<&str>,
    ssl_key_path: Option<&str>,
    ssl_ca_path: Option<&str>,
) -> Result<String, RenderError> {
    let blocks = redirect_vhost_blocks(
        safe_domain,
        redirects,
        ssl_cert_path,
        ssl_key_path,
        ssl_ca_path,
    )?;
    if blocks.is_empty() {
        return Ok(content.to_string());
    }
    Ok(format!("{}\n\n{}\n", content.trim_end(), blocks))
}
