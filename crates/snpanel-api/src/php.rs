//! PHP versions and the panel's `99-snpanel.ini`.
//!
//! Source: `app.services.php`, plus the two functions from `php_tune` and
//! `system` that decide *which* version a request without one acts on.
//!
//! That decision is the part worth reading. `settings.default_php_version` is
//! a preference, not a fact: on a machine that does not have that version,
//! acting on it hands the privileged helper a path that does not exist and
//! shows the operator "Action failed" naming a directory they never chose.

use std::path::{Path, PathBuf};

/// Source: `SUPPORTED_PHP_VERSIONS` - what the panel knows how to read, which
/// is not the same as what is installed.
pub const SUPPORTED_PHP_VERSIONS: &[&str] =
    &["5.6", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"];

/// Source: `PHP_CONFIG_KEYS`.
pub const DEFAULTS: &[(&str, &str)] = &[
    ("display_errors", "Off"),
    ("memory_limit", "1024M"),
    ("upload_max_filesize", "1024M"),
    ("post_max_size", "1024M"),
    ("max_execution_time", "300"),
    ("max_input_time", "600"),
    ("max_input_vars", "10000"),
];

fn allowed_list() -> String {
    let mut all: Vec<&str> = SUPPORTED_PHP_VERSIONS.to_vec();
    all.sort_unstable();
    all.join(", ")
}

/// Source: `installed_php_versions` - oldest first.
pub fn installed_php_versions() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/etc/php") else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let version = e.file_name().to_string_lossy().into_owned();
            e.path()
                .join("fpm/php-fpm.conf")
                .exists()
                .then_some(version)
        })
        .collect();
    found.sort();
    found.dedup();
    found.sort_by_key(|v| version_key(v));
    found
}

/// `[int(x) for x in v.split(".")]`, with anything unparseable last.
fn version_key(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(u32::MAX);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// Source: `system.default_php_version`.
///
/// The configured preference wins when the machine has it - an operator who
/// runs several versions and names one means it. Otherwise the newest
/// installed, and only then the preference as a last resort.
pub fn default_php_version(configured: &str) -> String {
    let installed = installed_php_versions();
    let configured = configured.trim();
    if !configured.is_empty() && installed.iter().any(|v| v == configured) {
        return configured.to_string();
    }
    if let Some(last) = installed.last() {
        return last.clone();
    }
    if configured.is_empty() {
        "8.4".to_string()
    } else {
        configured.to_string()
    }
}

/// Source: `php_tune.resolve_version`.
pub fn resolve_version(requested: Option<&str>, configured: &str) -> Result<String, String> {
    let requested = requested.unwrap_or("").trim();
    if requested.is_empty() {
        return Ok(default_php_version(configured));
    }
    if installed_php_versions().iter().any(|v| v == requested) {
        return Ok(requested.to_string());
    }
    if !SUPPORTED_PHP_VERSIONS.contains(&requested) {
        // Nonsense, rather than a stale default. Refusing is right: nobody
        // meant this, and silently tuning some other version would hide it.
        return Err(format!(
            "Unsupported PHP version: {requested}. Allowed: {}",
            allowed_list()
        ));
    }
    // A version the panel supports and this machine does not have: the
    // interface's stale default arriving, not a choice anyone made.
    Ok(default_php_version(configured))
}

fn ini_path(version: &str, name: &str) -> PathBuf {
    Path::new("/etc/php").join(version).join("fpm").join(name)
}

/// Source: `read_php_ini` - the defaults, then `php.ini`, then the panel's
/// own file, so the panel's value wins where it sets one.
pub fn read_php_ini(
    requested: Option<&str>,
    configured: &str,
) -> Result<serde_json::Value, String> {
    let version = resolve_version(requested, configured)?;
    if !SUPPORTED_PHP_VERSIONS.contains(&version.as_str()) {
        return Err(format!(
            "Unsupported PHP version. Allowed: {}",
            allowed_list()
        ));
    }
    let mut values: Vec<(String, String)> = DEFAULTS
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    for path in [
        ini_path(&version, "php.ini"),
        ini_path(&version, "conf.d/99-snpanel.ini"),
    ] {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            if let Some(slot) = values.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value.to_string();
            }
        }
    }

    let get = |name: &str| -> String {
        values
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    // The three numeric fields come back as numbers, the way the Python casts
    // them; a value the file carries that is not a number falls back to the
    // default rather than failing the whole read.
    let number = |name: &str| -> i64 {
        let default = DEFAULTS
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .unwrap_or("0");
        get(name)
            .parse::<i64>()
            .unwrap_or_else(|_| default.parse().unwrap_or(0))
    };
    Ok(serde_json::json!({
        "php_version": version,
        "display_errors": get("display_errors"),
        "memory_limit": get("memory_limit"),
        "upload_max_filesize": get("upload_max_filesize"),
        "post_max_size": get("post_max_size"),
        "max_execution_time": number("max_execution_time"),
        "max_input_time": number("max_input_time"),
        "max_input_vars": number("max_input_vars"),
    }))
}

/// Source: `_safe_ini_value` - a newline would let one setting become two.
pub fn safe_ini_value(value: &str) -> Result<&str, String> {
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err("Invalid PHP ini value".to_string());
    }
    Ok(value)
}

/// Source: `default_php_config`.
pub fn default_php_config(version: &str) -> Result<serde_json::Value, String> {
    if !SUPPORTED_PHP_VERSIONS.contains(&version) {
        return Err(format!(
            "Unsupported PHP version. Allowed: {}",
            allowed_list()
        ));
    }
    Ok(serde_json::json!({
        "php_version": version,
        "display_errors": "Off",
        "memory_limit": "1024M",
        "upload_max_filesize": "1024M",
        "post_max_size": "1024M",
        "max_execution_time": 300,
        "max_input_time": 600,
        "max_input_vars": 10000,
    }))
}

/// Source: the body `update_php_ini` writes.
pub struct IniUpdate {
    pub display_errors: String,
    pub memory_limit: String,
    pub upload_max_filesize: String,
    pub post_max_size: String,
    pub max_execution_time: i64,
    pub max_input_time: i64,
    pub max_input_vars: i64,
}

impl IniUpdate {
    pub fn render(&self) -> Result<String, String> {
        // `"On" if str(display_errors).lower() in {"1","true","on","yes"}`
        let display = match self.display_errors.to_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => "On",
            _ => "Off",
        };
        Ok(format!(
            "display_errors = {display}\n\
             memory_limit = {}\n\
             upload_max_filesize = {}\n\
             post_max_size = {}\n\
             max_execution_time = {}\n\
             max_input_time = {}\n\
             max_input_vars = {}\n",
            safe_ini_value(&self.memory_limit)?,
            safe_ini_value(&self.upload_max_filesize)?,
            safe_ini_value(&self.post_max_size)?,
            self.max_execution_time,
            self.max_input_time,
            self.max_input_vars,
        ))
    }
}

/// Where `php-config-write` puts it.
pub fn config_target(version: &str) -> String {
    format!("/etc/php/{version}/fpm/conf.d/99-snpanel.ini")
}

/// Source: `list_installed_php`.
pub fn list_installed_php() -> Vec<String> {
    let mut found: Vec<String> = SUPPORTED_PHP_VERSIONS
        .iter()
        .filter(|v| Path::new(&format!("/etc/php/{v}/fpm/php-fpm.conf")).exists())
        .map(|v| v.to_string())
        .collect();
    found.sort_by_key(|v| version_key(v));
    found
}

/// The apt package set `install_php` falls back to.
pub fn install_packages(version: &str) -> Vec<String> {
    [
        "fpm", "cli", "mysql", "sqlite3", "curl", "gd", "mbstring", "xml", "zip", "opcache",
        "intl", "bcmath", "redis", "imagick",
    ]
    .iter()
    .map(|part| format!("php{version}-{part}"))
    .collect()
}
