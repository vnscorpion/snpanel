//! Panel configuration, read from the same `.env` the Python process reads.
//!
//! Contract C18: every variable name stays exactly as it is, including the
//! PHP-FPM and MariaDB overrides, because `.env` is written by the installer
//! and rewritten by every update - a rename would strand existing boxes.
//!
//! Contract C35: the panel refuses to start in production with settings that
//! would weaken it. Those checks are reproduced here rather than deferred to
//! the API layer, so the CLI and the helper see the same verdict.
//!
//! Source: `backend/app/core/config.py`.

use std::collections::BTreeMap;
use std::path::Path;

use crate::types::Port;

pub const DEFAULT_SECRET_KEY: &str = "change-this-secret-key";

/// Minimum `SECRET_KEY` length in production. Source: `validate_secret_key`.
pub const MIN_SECRET_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("SECRET_KEY must be changed to a strong random value in production")]
    WeakSecretKey,
    #[error("ALLOWED_ORIGINS cannot be '*' in production with credentials enabled")]
    WildcardOrigin,
    #[error("ALLOWED_ORIGINS entry must include scheme: {0}")]
    OriginWithoutScheme(String),
    #[error("RATE_LIMIT_BACKEND must be 'memory' or 'redis'")]
    BadRateLimitBackend,
    #[error("RATE_LIMIT_BACKEND=redis is required in production")]
    RateLimitMustBeRedis,
    #[error("COMMAND_DRY_RUN=true is refused in production")]
    DryRunInProduction,
    #[error("{0} is not a valid value for {1}")]
    BadValue(String, &'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    Development,
    Production,
}

impl AppEnv {
    fn parse(raw: &str) -> Self {
        if raw.trim().eq_ignore_ascii_case("production") {
            Self::Production
        } else {
            Self::Development
        }
    }

    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitBackend {
    Memory,
    Redis,
}

/// The settings the panel runs on.
///
/// Field names are the snake_case of the environment variable, matching the
/// pydantic-settings convention the Python side uses (`SECRET_KEY` ->
/// `secret_key`).
#[derive(Clone)]
pub struct Settings {
    pub app_name: String,
    pub app_env: AppEnv,
    pub secret_key: String,
    pub access_token_expire_minutes: i64,
    pub remember_me_expire_minutes: i64,
    pub database_url: String,
    pub command_dry_run: bool,
    pub allowed_origins: String,
    pub backup_root: String,
    pub nginx_sites_available: String,
    pub default_php_version: String,
    pub ssl_email: String,
    pub redis_url: String,
    pub rate_limit_backend: RateLimitBackend,
    pub panel_url: String,
    pub panel_domain: String,
    pub panel_port: Port,
    pub panel_ssl_cert: String,
    pub panel_ssl_key: String,
    pub panel_ssl_mode: String,
    pub frontend_dist: String,
    pub totp_issuer: String,
    pub github_token: String,
    pub geoip_country_db: String,
    pub geoip_dbip_country_url: String,
    pub geoip_dbip_cache_dir: String,
    pub malware_scan_enabled: bool,
    pub clamav_socket_path: String,
    pub malware_scan_on_upload: bool,
    pub strict_decrypt: bool,
    /// Strangler upstream (plan §9.1). Empty once Python is gone.
    pub strangler_upstream: String,
    /// Every key that was in the file, including ones we do not model.
    ///
    /// C18 covers 14 PHP-FPM/MariaDB override variables that only the tuning
    /// code reads. Keeping the raw map means a key a newer version adds is
    /// still available after a rollback instead of being dropped on rewrite.
    pub raw: BTreeMap<String, String>,
}

/// Written by hand rather than derived, because `Settings` holds `SECRET_KEY`
/// and `GITHUB_TOKEN`. A derived `Debug` puts both into any log line that ever
/// formats the settings - including a panic message, which is exactly the
/// situation where the output gets pasted into a support ticket.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("app_name", &self.app_name)
            .field("app_env", &self.app_env)
            .field("secret_key", &"<redacted>")
            .field("github_token", &"<redacted>")
            .field("database_url", &self.database_url)
            .field("panel_port", &self.panel_port)
            .field("panel_url", &self.panel_url)
            .field("rate_limit_backend", &self.rate_limit_backend)
            .field("command_dry_run", &self.command_dry_run)
            .field("strict_decrypt", &self.strict_decrypt)
            .field("raw_keys", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl Default for Settings {
    /// The same defaults as the pydantic model, field for field.
    fn default() -> Self {
        Self {
            app_name: "SNPanel".into(),
            app_env: AppEnv::Development,
            secret_key: DEFAULT_SECRET_KEY.into(),
            access_token_expire_minutes: 120,
            remember_me_expire_minutes: 60 * 24 * 30,
            database_url: "sqlite:///./snpanel.db".into(),
            command_dry_run: true,
            allowed_origins: String::new(),
            backup_root: "/var/backups/snpanel".into(),
            nginx_sites_available: "/etc/nginx/conf.d".into(),
            default_php_version: "8.4".into(),
            ssl_email: String::new(),
            redis_url: "redis://localhost:6379/0".into(),
            rate_limit_backend: RateLimitBackend::Redis,
            panel_url: String::new(),
            panel_domain: String::new(),
            panel_port: Port::new(2222).expect("2222 is a valid port"),
            panel_ssl_cert: String::new(),
            panel_ssl_key: String::new(),
            panel_ssl_mode: String::new(),
            frontend_dist: "/opt/snpanel/frontend/dist".into(),
            totp_issuer: "SNPanel".into(),
            github_token: String::new(),
            geoip_country_db: String::new(),
            geoip_dbip_country_url:
                "https://download.db-ip.com/free/dbip-country-lite-{year}-{month}.csv.gz".into(),
            geoip_dbip_cache_dir: "/var/lib/snpanel/geoip".into(),
            malware_scan_enabled: false,
            clamav_socket_path: "/run/clamav/clamd.sock".into(),
            malware_scan_on_upload: true,
            strict_decrypt: true,
            strangler_upstream: String::new(),
            raw: BTreeMap::new(),
        }
    }
}

impl Settings {
    /// Load from a `.env` file, falling back to the process environment for
    /// any key the file does not set - the same precedence pydantic-settings
    /// applies.
    pub fn load(env_path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut raw = BTreeMap::new();
        if let Some(path) = env_path {
            if let Ok(contents) = std::fs::read_to_string(path) {
                raw.extend(parse_dotenv(&contents));
            }
        }
        for (k, v) in std::env::vars() {
            raw.entry(k).or_insert(v);
        }
        Self::from_map(raw)
    }

    pub fn from_map(raw: BTreeMap<String, String>) -> Result<Self, ConfigError> {
        let d = Settings::default();
        let get = |key: &str| raw.get(key).map(|s| s.trim().to_string());
        let string = |key: &str, fallback: &str| get(key).unwrap_or_else(|| fallback.to_string());

        let app_env = get("APP_ENV")
            .map(|v| AppEnv::parse(&v))
            .unwrap_or(d.app_env);

        let rate_limit_backend = match get("RATE_LIMIT_BACKEND")
            .unwrap_or_else(|| "redis".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "memory" => RateLimitBackend::Memory,
            "redis" => RateLimitBackend::Redis,
            _ => return Err(ConfigError::BadRateLimitBackend),
        };

        let panel_port = match get("PANEL_PORT") {
            Some(v) => Port::parse(&v).map_err(|_| ConfigError::BadValue(v, "PANEL_PORT"))?,
            None => d.panel_port,
        };

        let settings = Settings {
            app_name: string("APP_NAME", &d.app_name),
            app_env,
            secret_key: string("SECRET_KEY", &d.secret_key),
            access_token_expire_minutes: parse_int(
                &raw,
                "ACCESS_TOKEN_EXPIRE_MINUTES",
                d.access_token_expire_minutes,
            )?,
            remember_me_expire_minutes: parse_int(
                &raw,
                "REMEMBER_ME_EXPIRE_MINUTES",
                d.remember_me_expire_minutes,
            )?,
            database_url: string("DATABASE_URL", &d.database_url),
            command_dry_run: parse_bool(&raw, "COMMAND_DRY_RUN", d.command_dry_run),
            allowed_origins: string("ALLOWED_ORIGINS", &d.allowed_origins),
            backup_root: string("BACKUP_ROOT", &d.backup_root),
            nginx_sites_available: string("NGINX_SITES_AVAILABLE", &d.nginx_sites_available),
            default_php_version: string("DEFAULT_PHP_VERSION", &d.default_php_version),
            ssl_email: string("SSL_EMAIL", &d.ssl_email),
            redis_url: string("REDIS_URL", &d.redis_url),
            rate_limit_backend,
            panel_url: string("PANEL_URL", &d.panel_url),
            panel_domain: string("PANEL_DOMAIN", &d.panel_domain),
            panel_port,
            panel_ssl_cert: string("PANEL_SSL_CERT", &d.panel_ssl_cert),
            panel_ssl_key: string("PANEL_SSL_KEY", &d.panel_ssl_key),
            panel_ssl_mode: string("PANEL_SSL_MODE", &d.panel_ssl_mode),
            frontend_dist: string("FRONTEND_DIST", &d.frontend_dist),
            totp_issuer: string("TOTP_ISSUER", &d.totp_issuer),
            github_token: string("GITHUB_TOKEN", &d.github_token),
            geoip_country_db: string("GEOIP_COUNTRY_DB", &d.geoip_country_db),
            geoip_dbip_country_url: string("GEOIP_DBIP_COUNTRY_URL", &d.geoip_dbip_country_url),
            geoip_dbip_cache_dir: string("GEOIP_DBIP_CACHE_DIR", &d.geoip_dbip_cache_dir),
            malware_scan_enabled: parse_bool(&raw, "MALWARE_SCAN_ENABLED", d.malware_scan_enabled),
            clamav_socket_path: string("CLAMAV_SOCKET_PATH", &d.clamav_socket_path),
            malware_scan_on_upload: parse_bool(
                &raw,
                "MALWARE_SCAN_ON_UPLOAD",
                d.malware_scan_on_upload,
            ),
            strict_decrypt: parse_bool(&raw, "STRICT_DECRYPT", d.strict_decrypt),
            strangler_upstream: string("STRANGLER_UPSTREAM", &d.strangler_upstream),
            raw,
        };
        settings.validate()?;
        Ok(settings)
    }

    /// C35. Run at construction, and again before the server binds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.app_env.is_production() {
            return Ok(());
        }
        if self.secret_key == DEFAULT_SECRET_KEY || self.secret_key.len() < MIN_SECRET_KEY_LEN {
            return Err(ConfigError::WeakSecretKey);
        }
        for origin in self
            .allowed_origins
            .split(',')
            .map(str::trim)
            .filter(|o| !o.is_empty())
        {
            if origin == "*" {
                return Err(ConfigError::WildcardOrigin);
            }
            if !origin.starts_with("http://") && !origin.starts_with("https://") {
                return Err(ConfigError::OriginWithoutScheme(origin.to_string()));
            }
        }
        if self.rate_limit_backend != RateLimitBackend::Redis {
            return Err(ConfigError::RateLimitMustBeRedis);
        }
        if self.command_dry_run {
            return Err(ConfigError::DryRunInProduction);
        }
        Ok(())
    }

    /// Source: `Settings.cors_origins` - splits, trims, drops `*` and empties,
    /// and strips one trailing slash.
    pub fn cors_origins(&self) -> Vec<String> {
        self.allowed_origins
            .split(',')
            .map(|o| o.trim().trim_end_matches('/'))
            .filter(|o| !o.is_empty() && *o != "*")
            .map(str::to_string)
            .collect()
    }

    /// True while Python is still serving some routes (plan §9).
    pub fn strangler_enabled(&self) -> bool {
        !self.strangler_upstream.is_empty()
    }
}

/// Parse a `.env` file the way python-dotenv does: `KEY=value`, `#` comments,
/// blank lines ignored, optional `export ` prefix, optional matched quotes.
pub fn parse_dotenv(contents: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        out.insert(key.to_string(), value.to_string());
    }
    out
}

/// pydantic's bool parsing: `1/true/yes/on` are true, case-insensitively.
fn parse_bool(raw: &BTreeMap<String, String>, key: &str, fallback: bool) -> bool {
    match raw.get(key) {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "t" | "y"
        ),
        None => fallback,
    }
}

fn parse_int(
    raw: &BTreeMap<String, String>,
    key: &'static str,
    fallback: i64,
) -> Result<i64, ConfigError> {
    match raw.get(key) {
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| ConfigError::BadValue(v.clone(), key)),
        None => Ok(fallback),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn production_base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("APP_ENV", "production"),
            ("SECRET_KEY", "a-secret-key-that-is-definitely-long-enough"),
            ("COMMAND_DRY_RUN", "false"),
            ("RATE_LIMIT_BACKEND", "redis"),
        ]
    }

    #[test]
    fn defaults_match_the_pydantic_model() {
        let s = Settings::from_map(BTreeMap::new()).unwrap();
        assert_eq!(s.app_name, "SNPanel");
        assert_eq!(s.panel_port.get(), 2222);
        assert_eq!(s.access_token_expire_minutes, 120);
        assert_eq!(s.remember_me_expire_minutes, 43_200);
        assert_eq!(s.default_php_version, "8.4");
        assert_eq!(s.nginx_sites_available, "/etc/nginx/conf.d");
        assert!(s.strict_decrypt);
        assert!(s.command_dry_run);
    }

    #[test]
    fn dotenv_parsing_handles_the_shapes_the_installer_writes() {
        let parsed = parse_dotenv(
            r#"
# a comment
SECRET_KEY=abc123
export PANEL_PORT=2222
QUOTED="hello world"
SINGLE='single quoted'
EMPTY=
SPACED  =  value with spaces
NOT_A_PAIR
"#,
        );
        assert_eq!(parsed.get("SECRET_KEY").unwrap(), "abc123");
        assert_eq!(parsed.get("PANEL_PORT").unwrap(), "2222");
        assert_eq!(parsed.get("QUOTED").unwrap(), "hello world");
        assert_eq!(parsed.get("SINGLE").unwrap(), "single quoted");
        assert_eq!(parsed.get("EMPTY").unwrap(), "");
        assert_eq!(parsed.get("SPACED").unwrap(), "value with spaces");
        assert!(!parsed.contains_key("NOT_A_PAIR"));
    }

    #[test]
    fn unknown_keys_are_kept_not_fatal() {
        // The Python model sets extra="ignore" after a production incident
        // where one stale key stopped the panel from starting. C18 also needs
        // the 14 PHP-FPM/MariaDB overrides to survive.
        let mut m = map(&production_base());
        m.insert("PHP_FPM_MAX_CHILDREN".into(), "40".into());
        m.insert("WEB_SERVER".into(), "nginx".into()); // the stale key from the incident
        let s = Settings::from_map(m).unwrap();
        assert_eq!(s.raw.get("PHP_FPM_MAX_CHILDREN").unwrap(), "40");
        assert_eq!(s.raw.get("WEB_SERVER").unwrap(), "nginx");
    }

    #[test]
    fn production_refuses_the_default_secret_key() {
        let mut m = map(&production_base());
        m.insert("SECRET_KEY".into(), DEFAULT_SECRET_KEY.into());
        assert_eq!(
            Settings::from_map(m).unwrap_err(),
            ConfigError::WeakSecretKey
        );
    }

    #[test]
    fn production_refuses_a_short_secret_key() {
        let mut m = map(&production_base());
        m.insert("SECRET_KEY".into(), "too-short".into());
        assert_eq!(
            Settings::from_map(m).unwrap_err(),
            ConfigError::WeakSecretKey
        );
    }

    #[test]
    fn production_refuses_wildcard_origins() {
        let mut m = map(&production_base());
        m.insert(
            "ALLOWED_ORIGINS".into(),
            "https://panel.example.com,*".into(),
        );
        assert_eq!(
            Settings::from_map(m).unwrap_err(),
            ConfigError::WildcardOrigin
        );
    }

    #[test]
    fn production_requires_a_scheme_on_each_origin() {
        let mut m = map(&production_base());
        m.insert("ALLOWED_ORIGINS".into(), "panel.example.com".into());
        assert!(matches!(
            Settings::from_map(m).unwrap_err(),
            ConfigError::OriginWithoutScheme(_)
        ));
    }

    #[test]
    fn production_requires_redis_and_refuses_dry_run() {
        let mut m = map(&production_base());
        m.insert("RATE_LIMIT_BACKEND".into(), "memory".into());
        assert_eq!(
            Settings::from_map(m).unwrap_err(),
            ConfigError::RateLimitMustBeRedis
        );

        let mut m = map(&production_base());
        m.insert("COMMAND_DRY_RUN".into(), "true".into());
        assert_eq!(
            Settings::from_map(m).unwrap_err(),
            ConfigError::DryRunInProduction
        );
    }

    #[test]
    fn development_allows_what_production_refuses() {
        // Same settings, no APP_ENV: a dev box must still start.
        let m = map(&[("SECRET_KEY", "short"), ("COMMAND_DRY_RUN", "true")]);
        assert!(Settings::from_map(m).is_ok());
    }

    #[test]
    fn cors_origins_strips_trailing_slashes_and_wildcards() {
        let mut m = map(&production_base());
        m.insert(
            "ALLOWED_ORIGINS".into(),
            "https://a.example.com/, https://b.example.com".into(),
        );
        let s = Settings::from_map(m).unwrap();
        assert_eq!(
            s.cors_origins(),
            vec!["https://a.example.com", "https://b.example.com"]
        );
    }

    #[test]
    fn bad_port_is_a_clear_error() {
        let mut m = map(&production_base());
        m.insert("PANEL_PORT".into(), "99999".into());
        assert!(matches!(
            Settings::from_map(m).unwrap_err(),
            ConfigError::BadValue(_, "PANEL_PORT")
        ));
    }

    #[test]
    fn debug_output_never_contains_the_secret_key() {
        // A derived Debug would put SECRET_KEY into every panic message and
        // tracing line that formats the settings.
        let mut m = map(&production_base());
        m.insert("GITHUB_TOKEN".into(), "ghp_a_real_looking_token".into());
        let s = Settings::from_map(m).unwrap();
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("a-secret-key-that-is-definitely-long-enough"));
        assert!(!rendered.contains("ghp_a_real_looking_token"));
        assert!(rendered.contains("<redacted>"));
        // Still useful for debugging.
        assert!(rendered.contains("app_env"));
    }

    #[test]
    fn strangler_is_off_unless_an_upstream_is_set() {
        let s = Settings::from_map(map(&production_base())).unwrap();
        assert!(!s.strangler_enabled());

        let mut m = map(&production_base());
        m.insert("STRANGLER_UPSTREAM".into(), "http://127.0.0.1:8000".into());
        assert!(Settings::from_map(m).unwrap().strangler_enabled());
    }
}
