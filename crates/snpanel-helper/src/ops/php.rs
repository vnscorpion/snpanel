//! `ops::php` - PHP-FPM configuration.
//!
//! Source: the `php-config-write` and `php-opcache-set` arms, plus
//! `validate_php_config_file`.
//!
//! The file-numbering convention carries a decision worth keeping. The
//! generated ini files are read in order:
//!
//! - `95-snpanel-tune.ini` — sizes the tuner derives from the machine
//! - `96-snpanel-opcache.ini` — the OPcache switch
//! - `99-snpanel.ini` — what the administrator set on the PHP config page
//!
//! OPcache lives in its own file *after* the tuning one on purpose: the bash
//! comment says regenerating the tuning file must not turn OPcache back on for
//! somebody who turned it off deliberately. Merging them would do exactly that
//! on the next retune, silently.
//!
//! **The directive allowlist is the security boundary here**, and it is the
//! reason `php-config-write` is not simply "write this file". The content
//! arrives from the panel and is installed by root into PHP's configuration
//! directory. Without the allowlist, whoever can reach the PHP config page can
//! set `extension=`, `disable_functions`, `open_basedir` or `auto_prepend_file`
//! for every site on the box. Seven directives are permitted and everything
//! else is refused by name.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use snpanel_core::PhpVersion;
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

pub const TUNE_FILE: &str = "95-snpanel-tune.ini";
pub const OPCACHE_FILE: &str = "96-snpanel-opcache.ini";
/// Source: the `target` in `write_php_config`.
pub const CONFIG_FILE: &str = "99-snpanel.ini";

/// Source: the size check in `write_php_config`.
pub const MAX_CONFIG_BYTES: usize = 8192;

/// The FPM `conf.d` for a version, via the platform so the Remi layout works.
fn conf_dir(version: PhpVersion) -> Option<PathBuf> {
    let platform = snpanel_osabi::detect().ok()?;
    // php_ini_path is <...>/php.ini; conf.d sits beside it.
    let ini = platform.php_ini_path(version);
    Some(ini.parent()?.join("conf.d"))
}

fn service_name(version: PhpVersion) -> String {
    snpanel_osabi::detect()
        .map(|p| p.php_service(version))
        .unwrap_or_else(|_| format!("php{}-fpm", version.dotted()))
}

// ---------------------------------------------------------------------------
// The directive allowlist
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("PHP config contains a carriage return")]
    CarriageReturn,
    #[error("invalid PHP config line: {0}")]
    NotAnAssignment(String),
    #[error("unsupported PHP config directive: {0}")]
    UnsupportedDirective(String),
    #[error("invalid display_errors value")]
    BadDisplayErrors,
    #[error("invalid PHP size value for {0}")]
    BadSize(String),
    #[error("invalid integer value for {0}")]
    BadInteger(String),
    #[error("{0} out of range")]
    OutOfRange(String),
    #[error("PHP config size out of range")]
    SizeOutOfRange,
}

/// Validate an ini exactly as `validate_php_config_file` does.
///
/// Note it does **not** tolerate comments: the bash skips only empty lines, so
/// a `; comment` line has no `=` and is refused. Accepting them here would be
/// a silent widening of what the panel may send.
pub fn validate_config(content: &str) -> Result<(), ConfigError> {
    if content.is_empty() || content.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::SizeOutOfRange);
    }
    if content.contains('\r') {
        return Err(ConfigError::CarriageReturn);
    }

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigError::NotAnAssignment(line.to_string()));
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "display_errors" => {
                if value != "On" && value != "Off" {
                    return Err(ConfigError::BadDisplayErrors);
                }
            }
            "memory_limit" | "upload_max_filesize" | "post_max_size" => {
                if !is_size(value) {
                    return Err(ConfigError::BadSize(key.to_string()));
                }
            }
            "max_execution_time" | "max_input_time" => {
                let n = parse_bounded(value, 4).ok_or(ConfigError::BadInteger(key.to_string()))?;
                if !(1..=3600).contains(&n) {
                    return Err(ConfigError::OutOfRange(key.to_string()));
                }
            }
            "max_input_vars" => {
                let n = parse_bounded(value, 7).ok_or(ConfigError::BadInteger(key.to_string()))?;
                if !(100..=1_000_000).contains(&n) {
                    return Err(ConfigError::OutOfRange(key.to_string()));
                }
            }
            other => return Err(ConfigError::UnsupportedDirective(other.to_string())),
        }
    }
    Ok(())
}

/// `^[0-9]{1,6}[KMG]?$`
fn is_size(value: &str) -> bool {
    let digits = match value.as_bytes().last() {
        Some(b'K') | Some(b'M') | Some(b'G') => &value[..value.len() - 1],
        _ => value,
    };
    !digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|b| b.is_ascii_digit())
}

/// A decimal integer of at most `max_digits`, so the bash's own width limits
/// are kept rather than accepting anything that happens to parse.
fn parse_bounded(value: &str, max_digits: usize) -> Option<u64> {
    if value.is_empty() || value.len() > max_digits || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// `php-config-write`: install the administrator's ini.
///
/// `restart`, not `reload`: the bash restarts, and some of these directives
/// (`memory_limit` among them) are only picked up by a fresh worker.
pub fn config_write(version: PhpVersion, content: &str) -> HelperResponse {
    let Some(dir) = conf_dir(version) else {
        return HelperResponse::failed(HelperErrorKind::Internal, "unsupported operating system");
    };
    if !dir.is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("PHP FPM config directory not found: {}", dir.display()),
        );
    }
    if let Err(e) = validate_config(content) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, e.to_string());
    }

    let target = dir.join(CONFIG_FILE);
    if let Err(e) = write_ini(&target, content) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {}: {e}", target.display()),
        );
    }

    let unit = service_name(version);
    let out = exec::run(&["systemctl", "restart", &unit]);
    let mut resp = exec::respond("systemctl restart", out);
    if resp.ok {
        resp.stdout = format!("PHP {version} config updated: {}\n", target.display());
    }
    resp
}

/// `php-opcache-set`.
pub fn opcache_set(version: PhpVersion, enabled: bool) -> HelperResponse {
    let Some(dir) = conf_dir(version) else {
        return HelperResponse::failed(HelperErrorKind::Internal, "unsupported operating system");
    };
    if !dir.is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("PHP FPM config directory not found: {}", dir.display()),
        );
    }
    let target = dir.join(OPCACHE_FILE);
    let body = format!(
        "; Generated by SNPanel. OPcache on/off for PHP {version}.\n\
         ; Read after {TUNE_FILE}, so this wins over the tuner.\n\
         opcache.enable = {}\n",
        if enabled { 1 } else { 0 }
    );

    if let Err(e) = write_ini(&target, &body) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {}: {e}", target.display()),
        );
    }

    let unit = service_name(version);
    let _ = exec::run(&["systemctl", "reload", &unit]);

    HelperResponse::with_data(serde_json::json!({
        "php_version": version.dotted(),
        "opcache_enabled": enabled,
        "file": target.to_string_lossy(),
    }))
}

fn write_ini(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(std::path::Path::new("/"));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("snpanel")
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcache_is_numbered_after_the_tuning_file_and_before_the_admin_one() {
        // A retune rewrites 95 and 96 still wins, so OPcache stays off for
        // somebody who turned it off. 99 is the administrator's, read last.
        assert!(TUNE_FILE < OPCACHE_FILE);
        assert!(OPCACHE_FILE < CONFIG_FILE);
    }

    #[test]
    fn the_seven_permitted_directives_are_accepted() {
        let good = "display_errors = Off\n\
                    memory_limit = 512M\n\
                    upload_max_filesize = 64M\n\
                    post_max_size = 64M\n\
                    max_execution_time = 120\n\
                    max_input_time = 120\n\
                    max_input_vars = 5000\n";
        assert_eq!(validate_config(good), Ok(()));
    }

    #[test]
    fn anything_outside_the_allowlist_is_refused_by_name() {
        // This is the security boundary: without it, whoever reaches the PHP
        // config page sets these as root for every site on the box.
        for line in [
            "disable_functions = \n",
            "open_basedir = /\n",
            "auto_prepend_file = /tmp/x.php\n",
            "extension = evil.so\n",
            "zend_extension = /tmp/x.so\n",
            "include_path = /tmp\n",
            "error_log = /etc/shadow\n",
        ] {
            let err = validate_config(line).unwrap_err();
            assert!(
                matches!(err, ConfigError::UnsupportedDirective(_)),
                "{line:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn comments_are_refused_because_the_bash_refuses_them() {
        // validate_php_config_file skips only empty lines, so a comment has no
        // '=' and is rejected. Accepting them here would silently widen what
        // the panel may send.
        let err = validate_config("; a comment\nmemory_limit = 256M\n").unwrap_err();
        assert!(matches!(err, ConfigError::NotAnAssignment(_)), "{err:?}");
    }

    #[test]
    fn size_values_follow_the_bash_regex() {
        for good in ["512M", "1024M", "2G", "128K", "256"] {
            assert_eq!(
                validate_config(&format!("memory_limit = {good}\n")),
                Ok(()),
                "{good}"
            );
        }
        for bad in ["512MB", "abc", "-1", "1234567M", "512m", ""] {
            assert!(
                validate_config(&format!("memory_limit = {bad}\n")).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn integer_ranges_are_enforced_not_just_the_shape() {
        assert_eq!(validate_config("max_execution_time = 1\n"), Ok(()));
        assert_eq!(validate_config("max_execution_time = 3600\n"), Ok(()));
        assert!(validate_config("max_execution_time = 0\n").is_err());
        assert!(validate_config("max_execution_time = 3601\n").is_err());

        assert_eq!(validate_config("max_input_vars = 100\n"), Ok(()));
        assert_eq!(validate_config("max_input_vars = 1000000\n"), Ok(()));
        assert!(validate_config("max_input_vars = 99\n").is_err());
        assert!(validate_config("max_input_vars = 1000001\n").is_err());
    }

    #[test]
    fn display_errors_is_on_or_off_and_nothing_else() {
        assert_eq!(validate_config("display_errors = On\n"), Ok(()));
        assert_eq!(validate_config("display_errors = Off\n"), Ok(()));
        for bad in ["on", "OFF", "1", "true", "yes"] {
            assert!(
                validate_config(&format!("display_errors = {bad}\n")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_carriage_return_is_refused() {
        // A CRLF file would put \r into a value and PHP would read it as part
        // of the setting.
        assert_eq!(
            validate_config("memory_limit = 256M\r\n"),
            Err(ConfigError::CarriageReturn)
        );
    }

    #[test]
    fn the_size_limit_matches_the_bash() {
        assert_eq!(validate_config(""), Err(ConfigError::SizeOutOfRange));
        let huge = format!("memory_limit = 256M\n{}", " ".repeat(MAX_CONFIG_BYTES));
        assert_eq!(validate_config(&huge), Err(ConfigError::SizeOutOfRange));
    }

    #[test]
    fn a_smuggled_second_directive_on_one_line_is_refused() {
        // `memory_limit = 256M` followed by anything else on the same logical
        // line: the key is everything before the first '=', so this becomes an
        // unsupported directive rather than being silently accepted.
        assert!(validate_config("memory_limit 256M\n").is_err());
        let err = validate_config("memory_limit\nextension=x\n").unwrap_err();
        assert!(matches!(err, ConfigError::NotAnAssignment(_)), "{err:?}");
    }

    #[test]
    fn an_unknown_php_version_never_reaches_here() {
        for bad in ["8.9", "9.0", "7.3", "abc"] {
            assert!(PhpVersion::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_service_name_follows_the_platform() {
        let v = PhpVersion::parse("8.4").unwrap();
        let name = service_name(v);
        assert!(
            name == "php8.4-fpm" || name == "php84-php-fpm",
            "unexpected unit {name}"
        );
    }
}
