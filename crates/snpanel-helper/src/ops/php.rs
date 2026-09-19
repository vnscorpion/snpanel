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

/// Every pool file belonging to one site, across every installed PHP version.
///
/// Source: `site_php_pool_glob`. The prefix is what identifies the site; the
/// suffix is the PHP version, so a site that has been moved between versions
/// may have more than one.
fn site_pool_prefix(user: &str, resolved_site_path: &str) -> String {
    format!(
        "snpanel-{user}-{}-",
        snpanel_core::types::site_hash(resolved_site_path)
    )
}

/// `delete_site_php_pools`: remove a site's pools and reload what served them.
///
/// Reload rather than restart, and failures ignored, exactly as the bash has
/// it: a pool that is already gone is not an error, and an FPM that will not
/// reload is a separate problem from the site being deleted.
pub fn delete_site_pools(user: &str, resolved_site_path: &str) -> Vec<String> {
    let prefix = site_pool_prefix(user, resolved_site_path);
    let mut removed = Vec::new();

    let Ok(versions) = std::fs::read_dir("/etc/php") else {
        return removed;
    };
    for entry in versions.flatten() {
        let version = entry.file_name().to_string_lossy().into_owned();
        let pool_dir = entry.path().join("fpm/pool.d");
        let Ok(files) = std::fs::read_dir(&pool_dir) else {
            continue;
        };
        let mut touched = false;
        for file in files.flatten() {
            let name = file.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix)
                && name.ends_with(".conf")
                && std::fs::remove_file(file.path()).is_ok()
            {
                removed.push(name);
                touched = true;
            }
        }
        if touched {
            let service = format!("php{version}-fpm");
            let _ = crate::exec::run(&["systemctl", "reload", &service]);
        }
    }
    removed
}

/// What the helper writes into a pool file.
///
/// Source: the `PHP_FPM_*` variables `calculate_php_fpm_pool_tuning` sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolTuning {
    pub max_children: u64,
    pub idle_timeout: u64,
    pub max_requests: u64,
    pub request_terminate_timeout: u64,
}

/// Overrides an administrator may set, each one optional.
///
/// Source: `php_fpm_tuning_value`, which reads the environment and then the
/// panel's `.env`. Resolving them is the caller's job; this takes the answer.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolTuningOverrides {
    pub worker_mb: Option<u64>,
    pub max_children: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub max_requests: Option<u64>,
    pub request_terminate_timeout: Option<u64>,
}

const DEFAULT_WORKER_MB: u64 = 128;
const DEFAULT_REQUEST_TERMINATE_TIMEOUT: u64 = 300;

/// Source: `positive_int_or_default`. A value outside the range is clamped
/// rather than refused, which is what the shell does - an administrator who
/// asks for 10000 workers gets the cap, not an error at site-creation time.
fn clamped(value: Option<u64>, default: u64, min: u64, max: u64) -> u64 {
    value.unwrap_or(default).clamp(min, max)
}

/// Source: `php_fpm_reserved_memory_mb`. How much RAM is kept away from PHP.
fn reserved_memory_mb(total_mb: u64) -> u64 {
    let mut reserve = if total_mb <= 1024 {
        (total_mb * 45 / 100).max(448)
    } else if total_mb <= 2048 {
        (total_mb * 35 / 100).max(640)
    } else if total_mb <= 4096 {
        (total_mb * 30 / 100).max(896)
    } else if total_mb <= 8192 {
        (total_mb * 25 / 100).max(1280)
    } else {
        (total_mb * 20 / 100).max(2048)
    };
    // Saturating: the shell works on signed integers and would produce a
    // negative here for a machine with under 128 MB, which then trips the
    // floor below. The floor is what matters, so the subtraction is made
    // safe rather than reproduced literally.
    if reserve > total_mb.saturating_sub(128) {
        reserve = total_mb.saturating_sub(128);
    }
    reserve.max(128)
}

/// Source: `calculate_php_fpm_pool_tuning`.
///
/// `pool_count` includes the pool being written, as `php_fpm_pool_count`
/// counts it. The divisor is the integer square root of that count: a machine
/// with many sites gives each one a smaller share, but not linearly, because
/// they are not all busy at once.
pub fn pool_tuning(
    total_mb: u64,
    cpu_count: u64,
    pool_count: u64,
    overrides: PoolTuningOverrides,
) -> PoolTuning {
    let worker_mb = clamped(overrides.worker_mb, DEFAULT_WORKER_MB, 32, 1024);
    let reserve_mb = reserved_memory_mb(total_mb);
    let budget_mb = total_mb.saturating_sub(reserve_mb).max(worker_mb);

    let global_children = (budget_mb / worker_mb).max(1);

    let mut divisor = 1u64;
    while divisor * divisor < pool_count {
        divisor += 1;
    }
    let mut children = (global_children / divisor).max(1);

    let mut cpu_cap = cpu_count * 4;
    if total_mb >= 3072 {
        cpu_cap = cpu_count * 6;
    }
    if total_mb >= 8192 {
        cpu_cap = cpu_count * 8;
    }
    cpu_cap = cpu_cap.clamp(2, 96);

    let (floor, profile_cap, idle_default, requests_default) = if total_mb <= 1024 {
        (1u64, 4u64, 10u64, 300u64)
    } else if total_mb <= 2048 {
        (2, 8, 15, 400)
    } else if total_mb <= 4096 {
        (3, 14, 20, 500)
    } else if total_mb <= 8192 {
        (4, 24, 30, 750)
    } else {
        (6, 48, 45, 1000)
    };

    children = children.max(floor).min(cpu_cap).min(profile_cap);
    if let Some(forced) = overrides.max_children {
        children = forced.clamp(1, 512);
    }

    PoolTuning {
        max_children: children,
        idle_timeout: clamped(overrides.idle_timeout, idle_default, 5, 300),
        max_requests: clamped(overrides.max_requests, requests_default, 50, 10_000),
        request_terminate_timeout: clamped(
            overrides.request_terminate_timeout,
            DEFAULT_REQUEST_TERMINATE_TIMEOUT,
            30,
            3600,
        ),
    }
}

/// The pool name for a site: `snpanel-<user>-<site hash>-<php version>`.
///
/// The version suffix has its dots replaced, because a dot in a pool name is
/// legal but makes the socket path harder to read and the shell wrote it this
/// way first.
pub fn pool_name(user: &str, resolved_site_path: &str, php: PhpVersion) -> String {
    format!(
        "snpanel-{user}-{}-{}",
        snpanel_core::types::site_hash(resolved_site_path),
        php.to_string().replace('.', "_")
    )
}

/// The body of a pool file.
///
/// Built separately from writing it so the tests can read what would be
/// written. Source: the heredoc in `ensure_php_pool`.
#[allow(clippy::too_many_arguments)]
pub fn pool_body(
    pool_name: &str,
    user: &str,
    site_root: &str,
    web_user: &str,
    web_group: &str,
    tuning: PoolTuning,
) -> String {
    let sess_dir = format!("/var/lib/php/sessions/{user}");
    let upload_dir = format!("/var/lib/php/uploads/{user}");
    format!(
        "[{pool_name}]\n\
         user = {user}\n\
         group = {user}\n\
         listen = /run/php/{pool_name}.sock\n\
         listen.owner = {web_user}\n\
         listen.group = {web_group}\n\
         listen.mode = 0660\n\
         ; SNPanel auto-tunes these values from RAM, CPU and managed pool count.\n\
         ; Optional overrides: SNPANEL_PHP_FPM_WORKER_MB, SNPANEL_PHP_FPM_MAX_CHILDREN,\n\
         ; SNPANEL_PHP_FPM_IDLE_TIMEOUT, SNPANEL_PHP_FPM_MAX_REQUESTS,\n\
         ; SNPANEL_PHP_FPM_REQUEST_TERMINATE_TIMEOUT.\n\
         pm = ondemand\n\
         pm.max_children = {children}\n\
         pm.process_idle_timeout = {idle}s\n\
         pm.max_requests = {requests}\n\
         request_terminate_timeout = {terminate}s\n\
         chdir = /\n\
         php_admin_value[open_basedir] = {site_root}:{sess_dir}:{upload_dir}:/usr/share/php\n\
         php_admin_value[upload_tmp_dir] = {upload_dir}\n\
         php_admin_value[session.save_path] = {sess_dir}\n",
        children = tuning.max_children,
        idle = tuning.idle_timeout,
        requests = tuning.max_requests,
        terminate = tuning.request_terminate_timeout,
    )
}

/// How many SNPanel pools this machine has, counting the one about to be
/// written if it does not exist yet.
///
/// Source: `php_fpm_pool_count`.
fn pool_count(current_pool: &std::path::Path) -> u64 {
    let mut count = 0u64;
    if let Ok(versions) = std::fs::read_dir("/etc/php") {
        for entry in versions.flatten() {
            let dir = entry.path().join("fpm/pool.d");
            let Ok(files) = std::fs::read_dir(&dir) else {
                continue;
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                if name.starts_with("snpanel-") && name.ends_with(".conf") {
                    count += 1;
                }
            }
        }
    }
    if !current_pool.exists() {
        count += 1;
    }
    count.max(1)
}

/// The per-user session and upload directories.
///
/// Source: `ensure_php_runtime_dirs`. The modes are the point: 0700 for
/// sessions so no other site can read them, and 2700 with the sites group
/// setgid for uploads so a file keeps a group nginx can read after WordPress
/// moves it.
fn ensure_runtime_dirs(user: &str) -> HelperResponse {
    let sess = format!("/var/lib/php/sessions/{user}");
    let uploads = format!("/var/lib/php/uploads/{user}");
    let sites_group = super::user::SITES_GROUP;

    let out = crate::exec::run(&["install", "-d", "-o", user, "-g", user, "-m", "0700", &sess]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return crate::exec::respond("install -d (sessions)", out);
    }
    let out = crate::exec::run(&[
        "install",
        "-d",
        "-o",
        user,
        "-g",
        sites_group,
        "-m",
        "2700",
        &uploads,
    ]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return crate::exec::respond("install -d (uploads)", out);
    }
    let _ = crate::exec::run(&["chmod", "g+s", &uploads]);
    HelperResponse::ok()
}

/// `ensure_php_pool`: write a site's pool file and reload FPM.
pub fn ensure_site_pool(
    user: &str,
    resolved_site_path: &str,
    php: PhpVersion,
    overrides: PoolTuningOverrides,
) -> HelperResponse {
    let name = pool_name(user, resolved_site_path, php);
    let dir = PathBuf::from(format!("/etc/php/{php}/fpm/pool.d"));
    if !dir.is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no PHP-FPM pool directory for {php}: {}", dir.display()),
        );
    }
    let file = dir.join(format!("{name}.conf"));

    let dirs = ensure_runtime_dirs(user);
    if !dirs.ok {
        return dirs;
    }

    let (web_user, web_group) = snpanel_osabi::detect()
        .map(|p| (p.web_user().to_string(), p.web_group().to_string()))
        .unwrap_or_else(|_| ("www-data".to_string(), "www-data".to_string()));

    let tuning = pool_tuning(total_memory_mb(), cpu_count(), pool_count(&file), overrides);
    let body = pool_body(
        &name,
        user,
        resolved_site_path,
        &web_user,
        &web_group,
        tuning,
    );
    if let Err(e) = write_ini(&file, &body) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {}: {e}", file.display()),
        );
    }
    crate::exec::respond(
        &format!("systemctl reload php{php}-fpm"),
        crate::exec::run(&["systemctl", "reload", &format!("php{php}-fpm")]),
    )
}

/// Total RAM in MiB, from /proc/meminfo.
///
/// Source: `php_fpm_total_memory_mb`. A machine that will not say falls back
/// to 1024, which puts the tuning in its most conservative tier rather than
/// its most generous.
fn total_memory_mb() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| kb / 1024)
        .unwrap_or(1024)
}

/// Source: `php_fpm_cpu_count`. One, if the machine will not say.
fn cpu_count() -> u64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1)
}

/// The administrator's tuning overrides, from the environment and the panel's
/// `.env`.
///
/// Source: `php_fpm_tuning_value`, which checks the shell variable first and
/// then `env_get`. The environment wins for the same reason it does there: it
/// is how an operator tries a value without editing a file the updater
/// rewrites.
pub fn tuning_overrides() -> PoolTuningOverrides {
    let dotenv = std::fs::read_to_string("/opt/snpanel/backend/.env")
        .map(|text| snpanel_core::config::parse_dotenv(&text))
        .unwrap_or_default();

    let get = |key: &str| -> Option<u64> {
        std::env::var(key)
            .ok()
            .or_else(|| dotenv.get(key).cloned())
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<u64>().ok())
    };

    PoolTuningOverrides {
        worker_mb: get("SNPANEL_PHP_FPM_WORKER_MB"),
        max_children: get("SNPANEL_PHP_FPM_MAX_CHILDREN"),
        idle_timeout: get("SNPANEL_PHP_FPM_IDLE_TIMEOUT"),
        max_requests: get("SNPANEL_PHP_FPM_MAX_REQUESTS"),
        request_terminate_timeout: get("SNPANEL_PHP_FPM_REQUEST_TERMINATE_TIMEOUT"),
    }
}

#[cfg(test)]
mod tests {
    /// The ported tuning must equal the shell's, across every tier.
    ///
    /// Driven by extracting the arithmetic from the helper and running it
    /// with fixed inputs, because the bash reads RAM and CPU from the machine
    /// and one machine only ever exercises one tier.
    #[test]
    fn the_tuning_matches_the_shell_across_every_tier() {
        use std::process::Command;

        let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../installer/files/snpanel-helper.sh");
        let Ok(source) = std::fs::read_to_string(&helper) else {
            panic!("the helper script must be readable to compare against");
        };

        // The three functions the calculation needs, lifted out with their
        // dependencies. Extracted rather than sourced: the helper refuses to
        // run without root and a panel installation.
        let mut extracted = String::new();
        for name in [
            "positive_int_or_default",
            "php_fpm_reserved_memory_mb",
            "calculate_php_fpm_pool_tuning",
        ] {
            let start = source
                .find(&format!("\n{name}() {{"))
                .unwrap_or_else(|| panic!("{name} not found in the helper"));
            let end = source[start..]
                .find("\n}\n")
                .unwrap_or_else(|| panic!("{name} has no end"));
            extracted.push_str(&source[start..start + end + 3]);
        }

        // Stubs for the three values the real functions read from the
        // machine, so the inputs can be chosen.
        let harness = r#"
php_fpm_total_memory_mb() { printf '%s\n' "$T"; }
php_fpm_cpu_count() { printf '%s\n' "$C"; }
php_fpm_pool_count() { printf '%s\n' "$P"; }
php_fpm_tuning_value() { printf '%s\n' "$2"; }
PHP_FPM_DEFAULT_WORKER_MB=128
PHP_FPM_DEFAULT_REQUEST_TERMINATE_TIMEOUT=300
calculate_php_fpm_pool_tuning ""
printf '%s %s %s %s\n' "$PHP_FPM_MAX_CHILDREN" "$PHP_FPM_PROCESS_IDLE_TIMEOUT" \
  "$PHP_FPM_MAX_REQUESTS" "$PHP_FPM_REQUEST_TERMINATE_TIMEOUT"
"#;

        let cases: &[(u64, u64, u64)] = &[
            (512, 1, 1),
            (1024, 1, 1),
            (1024, 2, 4),
            (2048, 2, 1),
            (2048, 4, 9),
            (4096, 4, 1),
            (4096, 8, 16),
            (8192, 8, 1),
            (8192, 16, 25),
            (16384, 16, 1),
            (16384, 32, 100),
            (65536, 64, 400),
        ];

        for &(total_mb, cpus, pools) in cases {
            let out = Command::new("bash")
                .arg("-c")
                .arg(format!("{extracted}\n{harness}"))
                .env("T", total_mb.to_string())
                .env("C", cpus.to_string())
                .env("P", pools.to_string())
                .output()
                .expect("bash must be available to compare against");
            let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let got: Vec<u64> = line
                .split_whitespace()
                .map(|v| {
                    v.parse().unwrap_or_else(|_| {
                        panic!(
                            "bad shell output {line:?}: {}",
                            String::from_utf8_lossy(&out.stderr)
                        )
                    })
                })
                .collect();
            assert_eq!(got.len(), 4, "shell produced {line:?}");

            let mine = pool_tuning(total_mb, cpus, pools, PoolTuningOverrides::default());
            assert_eq!(
                (
                    mine.max_children,
                    mine.idle_timeout,
                    mine.max_requests,
                    mine.request_terminate_timeout
                ),
                (got[0], got[1], got[2], got[3]),
                "tuning differs for {total_mb} MB, {cpus} CPUs, {pools} pools"
            );
        }
    }

    /// An override is clamped, not obeyed blindly, and not refused.
    ///
    /// Source: `positive_int_or_default`. An administrator who asks for
    /// 10,000 workers gets the cap - failing site creation instead would be
    /// a worse answer to a typo.
    #[test]
    fn overrides_are_clamped_into_range() {
        let huge = PoolTuningOverrides {
            max_children: Some(10_000),
            ..Default::default()
        };
        assert_eq!(pool_tuning(4096, 4, 1, huge).max_children, 512);

        let tiny = PoolTuningOverrides {
            max_children: Some(0),
            ..Default::default()
        };
        assert_eq!(pool_tuning(4096, 4, 1, tiny).max_children, 1);
    }

    /// The pool body carries the three things that keep sites apart.
    #[test]
    fn the_pool_body_isolates_the_site() {
        let tuning = pool_tuning(4096, 4, 1, PoolTuningOverrides::default());
        let body = pool_body(
            "snpanel-bp_site-abc123def456-8_4",
            "bp_site",
            "/home/bp_site/example.com",
            "www-data",
            "www-data",
            tuning,
        );

        assert!(
            body.contains("php_admin_value[open_basedir] = /home/bp_site/example.com:"),
            "open_basedir must pin the site: {body}"
        );
        assert!(
            body.contains("php_admin_value[session.save_path] = /var/lib/php/sessions/bp_site"),
            "sessions must be per-user, not shared in /tmp: {body}"
        );
        assert!(body.contains("listen.mode = 0660"), "{body}");
        assert!(body.contains("listen.group = www-data"), "{body}");
        assert!(
            body.contains("user = bp_site") && body.contains("group = bp_site"),
            "the pool runs as the site's user: {body}"
        );
    }

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
