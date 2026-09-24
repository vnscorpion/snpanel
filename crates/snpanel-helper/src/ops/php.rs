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
pub(super) fn total_memory_mb() -> u64 {
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
pub(super) fn cpu_count() -> u64 {
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

// ---------------------------------------------------------------------------
// the tuning file the panel sizes from the machine
// ---------------------------------------------------------------------------

/// Source: `validate_php_tune_file`'s `deny` messages.
#[derive(Debug, PartialEq, Eq)]
pub enum TuneError {
    SizeOutOfRange,
    NotAnAssignment(String),
    BadSize(String),
    BadInteger(String),
    BadFlag(String),
    BadJit,
    BadOnOff(String),
    Unsupported(String),
}

impl std::fmt::Display for TuneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SizeOutOfRange => write!(f, "PHP tuning file size out of range"),
            Self::NotAnAssignment(line) => write!(f, "invalid PHP tuning line: {line}"),
            Self::BadSize(key) => write!(f, "invalid size for {key}"),
            Self::BadInteger(key) => write!(f, "invalid integer for {key}"),
            Self::BadFlag(key) => write!(f, "{key} must be 0 or 1"),
            Self::BadJit => write!(f, "invalid opcache.jit value"),
            Self::BadOnOff(key) => write!(f, "{key} must be On or Off"),
            Self::Unsupported(key) => write!(f, "unsupported PHP tuning directive: {key}"),
        }
    }
}

/// `^[0-9]{1,6}[KkMmGg]?$`.
fn is_tune_size(value: &str) -> bool {
    let digits = value.trim_end_matches(['K', 'k', 'M', 'm', 'G', 'g']);
    // Exactly one optional suffix character, so `1MM` is refused.
    if value.len() > digits.len() + 1 {
        return false;
    }
    !digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_digits(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && value.bytes().all(|b| b.is_ascii_digit())
}

/// Source: `validate_php_tune_file`.
///
/// "A separate allowlist from the panel's PHP config page: these are the keys
/// the tuner is allowed to size from the machine, and nothing else reaches a
/// file that root writes into PHP's configuration directory."
///
/// The separation matters. [`validate_config`] guards what a *customer* may
/// put in their own PHP settings; this guards what the panel's auto-tuner may
/// write as root. A key in one is not automatically allowed in the other, and
/// merging them would widen both.
pub fn validate_tune(content: &str) -> Result<(), TuneError> {
    // No size check here. `validate_php_tune_file` walks lines and nothing
    // else; the `(( size <= 0 || size > 8192 ))` test lives in
    // `write_php_tune`, before this is called. So an empty file passes here
    // and is refused there, which is what the corpus records.
    for raw in content.lines() {
        // `line="${line%%;*}"` - everything from the first `;` is a comment,
        // then the remainder is trimmed at both ends.
        let line = raw.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(TuneError::NotAnAssignment(line.to_string()));
        };
        // `${line%%=*}` trims only the *right* of the key and only the left of
        // the value; the line was already trimmed, so both end up trimmed.
        let key = key.trim_end();
        let value = value.trim();

        match key {
            "memory_limit" | "realpath_cache_size" => {
                if !is_tune_size(value) {
                    return Err(TuneError::BadSize(key.to_string()));
                }
            }
            "realpath_cache_ttl"
            | "opcache.memory_consumption"
            | "opcache.interned_strings_buffer"
            | "opcache.max_accelerated_files"
            | "opcache.revalidate_freq" => {
                if !is_digits(value, 7) {
                    return Err(TuneError::BadInteger(key.to_string()));
                }
            }
            "opcache.enable"
            | "opcache.enable_cli"
            | "opcache.validate_timestamps"
            | "opcache.save_comments" => {
                if value != "0" && value != "1" {
                    return Err(TuneError::BadFlag(key.to_string()));
                }
            }
            "opcache.jit" => {
                // Named modes, or the four-digit form PHP also accepts.
                let named = matches!(value, "disable" | "off" | "on" | "tracing" | "function");
                if !named && !(value.len() == 4 && value.bytes().all(|b| b.is_ascii_digit())) {
                    return Err(TuneError::BadJit);
                }
            }
            "opcache.jit_buffer_size" => {
                if !is_tune_size(value) {
                    return Err(TuneError::BadSize("opcache.jit_buffer_size".to_string()));
                }
            }
            "expose_php" | "zlib.output_compression" => {
                if !matches!(value, "On" | "Off" | "0" | "1") {
                    return Err(TuneError::BadOnOff(key.to_string()));
                }
            }
            other => return Err(TuneError::Unsupported(other.to_string())),
        }
    }
    Ok(())
}

/// `php-tune-write` - the auto-tuner's `95-snpanel-tune.ini`.
///
/// Written to the FPM directory and *copied* to the CLI one when that exists:
/// "the CLI reads its own directory; opcache settings there are harmless and
/// realpath cache helps WP-CLI too."
pub fn tune_write(version: PhpVersion, content: &str) -> HelperResponse {
    // The bash's order: size first, then the directives.
    if content.is_empty() || content.len() > 8192 {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            TuneError::SizeOutOfRange.to_string(),
        );
    }
    if let Err(e) = validate_tune(content) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, e.to_string());
    }
    let conf_dir = format!("/etc/php/{version}/fpm/conf.d");
    if !PathBuf::from(&conf_dir).is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("PHP FPM config directory not found: {conf_dir}"),
        );
    }
    let target = format!("{conf_dir}/95-snpanel-tune.ini");

    // The bash writes a temporary file in the same directory and renames it, so
    // a half-written tuning file is never what PHP-FPM reloads into.
    let temp = format!("{conf_dir}/.95-snpanel-tune.ini.{}", std::process::id());
    if let Err(e) = std::fs::write(&temp, content) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("cannot create temporary PHP tuning file: {e}"),
        );
    }
    if let Err(e) = set_mode(&temp, 0o644) {
        let _ = std::fs::remove_file(&temp);
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("cannot set permissions on the PHP tuning file: {e}"),
        );
    }
    if let Err(e) = std::fs::rename(&temp, &target) {
        let _ = std::fs::remove_file(&temp);
        return HelperResponse::failed(HelperErrorKind::Internal, format!("writing {target}: {e}"));
    }

    let cli_dir = format!("/etc/php/{version}/cli/conf.d");
    if PathBuf::from(&cli_dir).is_dir() {
        let cli_target = format!("{cli_dir}/95-snpanel-tune.ini");
        if std::fs::write(&cli_target, content).is_ok() {
            let _ = set_mode(&cli_target, 0o644);
        }
    }

    // `reload || restart` - a pool that is not running cannot be reloaded, and
    // the tuning has to take effect either way.
    let service = format!("php{version}-fpm");
    let reloaded = exec::run(&["systemctl", "reload", &service]);
    if !matches!(&reloaded, Ok(o) if o.ok()) {
        let _ = exec::run(&["systemctl", "restart", &service]);
    }
    HelperResponse::with_stdout(format!("PHP {version} tuned: {target}\n"))
}

fn set_mode(path: &str, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Source: `php_fpm_set_directive`.
///
/// Rewrites the directive in place when it is there - **including a commented
/// one**, because `^[;[:space:]]*<key>[[:space:]]*=` matches `;pm = dynamic`
/// and the replacement drops the semicolon. That is deliberate: a pool file
/// shipped by the distribution comments these out, and appending a second
/// uncommented copy would leave two lines PHP reads in order.
fn set_directive(text: &str, key: &str, value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in text.lines() {
        // `sed -i` with no range rewrites **every** matching line; the absent
        // `g` only means once per line. A pool file with the directive twice
        // ends up with two identical lines rather than one new and one stale.
        if directive_matches(line, key) {
            out.push(format!("{key} = {value}"));
            replaced = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !replaced {
        out.push(format!("{key} = {value}"));
    }
    let mut joined = out.join("\n");
    // The bash appends with `printf '%s\n'` and `sed -i` keeps the file's own
    // trailing newline, so the result always ends with one.
    joined.push('\n');
    joined
}

/// `^[;[:space:]]*<key>[[:space:]]*=` with the key's dots taken literally.
fn directive_matches(line: &str, key: &str) -> bool {
    let rest = line.trim_start_matches([';', ' ', '\t']);
    let Some(after) = rest.strip_prefix(key) else {
        return false;
    };
    after.trim_start_matches([' ', '\t']).starts_with('=')
}

/// The pool files the panel owns: `/etc/php/*/fpm/pool.d/snpanel-*.conf`.
fn snpanel_pool_files() -> Vec<std::path::PathBuf> {
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    let Ok(versions) = std::fs::read_dir("/etc/php") else {
        return found;
    };
    for version in versions.flatten() {
        let dir = version.path().join("fpm/pool.d");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_file() && name.starts_with("snpanel-") && name.ends_with(".conf") {
                found.push(path);
            }
        }
    }
    // `shopt -s nullglob` expands in sorted order; the report lists them and a
    // reshuffle between two runs is a diff an operator would have to read.
    found.sort();
    found
}

/// `php-pools-retune`.
///
/// "Pool sizes are decided when a pool is written. A server that gained RAM
/// keeps the old numbers until every site happens to be touched; this walks
/// them all and rewrites each one against the machine as it is now."
pub fn pools_retune() -> HelperResponse {
    let files = snpanel_pool_files();
    let total_mb = total_memory_mb();
    let cpus = cpu_count();
    let overrides = tuning_overrides();

    let mut out = String::new();
    let mut retuned = 0usize;
    for path in &files {
        // Each pool is sized against how many pools share the machine, which
        // is what `calculate_php_fpm_pool_tuning` does per file.
        let tuning = pool_tuning(total_mb, cpus, pool_count(path), overrides);
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let mut updated = text;
        updated = set_directive(&updated, "pm", "ondemand");
        updated = set_directive(
            &updated,
            "pm.max_children",
            &tuning.max_children.to_string(),
        );
        updated = set_directive(
            &updated,
            "pm.process_idle_timeout",
            &format!("{}s", tuning.idle_timeout),
        );
        updated = set_directive(
            &updated,
            "pm.max_requests",
            &tuning.max_requests.to_string(),
        );
        updated = set_directive(
            &updated,
            "request_terminate_timeout",
            &format!("{}s", tuning.request_terminate_timeout),
        );
        if std::fs::write(path, &updated).is_err() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.push_str(&format!(
            "{name}: pm.max_children={} idle={}s max_requests={}\n",
            tuning.max_children, tuning.idle_timeout, tuning.max_requests
        ));
        retuned += 1;
    }

    // Every FPM version on the box, reloaded once. `|| true` in the bash: a
    // version whose service is not running is not a failure of the retune.
    if let Ok(versions) = std::fs::read_dir("/etc/php") {
        let mut names: Vec<String> = versions
            .flatten()
            .filter(|v| v.path().join("fpm").is_dir())
            .map(|v| v.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for version in names {
            let _ = exec::run(&["systemctl", "reload", &format!("php{version}-fpm")]);
        }
    }

    out.push_str(&format!("retuned {retuned} pool(s)\n"));
    HelperResponse::with_stdout(out)
}

#[cfg(test)]
mod tests {
    /// What the shell's own pool arithmetic produced, across every tier.
    ///
    /// Columns: total MB, CPUs, pools, then `max_children`,
    /// `process_idle_timeout`, `max_requests`, `request_terminate_timeout`.
    ///
    /// This used to run the bash at test time, by lifting
    /// `positive_int_or_default`, `php_fpm_reserved_memory_mb` and
    /// `calculate_php_fpm_pool_tuning` out of the helper and driving them
    /// with stubbed machine facts. The helper is gone; the numbers it
    /// produced are not, so they are frozen here rather than lost. The grid
    /// keeps every case the old test had and adds the tier boundaries either
    /// side of each one.
    const SHELL_TUNING: &str = include_str!("php-pool-tuning.tsv");

    /// The ported tuning still equals the shell's, across every tier.
    ///
    /// One machine only ever exercises one tier, which is why this is a table
    /// and not a run.
    #[test]
    fn the_tuning_matches_the_shell_across_every_tier() {
        let mut rows = 0;
        for line in SHELL_TUNING.lines().filter(|l| !l.trim().is_empty()) {
            let f: Vec<u64> = line
                .split('\t')
                .map(|v| v.parse().expect("a number"))
                .collect();
            assert_eq!(f.len(), 7, "malformed row: {line:?}");
            let (total_mb, cpus, pools) = (f[0], f[1], f[2]);
            let mine = pool_tuning(total_mb, cpus, pools, PoolTuningOverrides::default());
            assert_eq!(
                (
                    mine.max_children,
                    mine.idle_timeout,
                    mine.max_requests,
                    mine.request_terminate_timeout
                ),
                (f[3], f[4], f[5], f[6]),
                "tuning differs for {total_mb} MB, {cpus} CPUs, {pools} pools"
            );
            rows += 1;
        }
        // A fixture that stopped loading would make this pass by checking
        // nothing, which is the failure mode a golden test has.
        assert_eq!(rows, 20, "the fixture lost rows");
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

    /// `php_fpm_set_directive` rewrites a **commented** directive too.
    ///
    /// `^[;[:space:]]*<key>[[:space:]]*=` matches `;pm = dynamic`, and the
    /// replacement drops the semicolon. That is the behaviour that matters:
    /// distribution pool files ship these commented out, and appending an
    /// uncommented copy instead would leave two lines PHP reads in order - the
    /// second winning, which is the opposite of what an operator reading the
    /// file would expect.
    #[test]
    fn a_commented_directive_is_rewritten_rather_than_duplicated() {
        let before = "[pool]\n;pm = dynamic\nuser = alice\n";
        let after = set_directive(before, "pm", "ondemand");
        assert_eq!(after, "[pool]\npm = ondemand\nuser = alice\n");
        assert_eq!(after.matches("pm = ").count(), 1);

        // Leading whitespace and a semicolon together.
        let spaced = set_directive("  ;  pm  =  dynamic\n", "pm", "ondemand");
        assert_eq!(spaced, "pm = ondemand\n");
    }

    /// A directive that is not there is appended, once.
    #[test]
    fn a_missing_directive_is_appended_and_a_present_one_is_replaced() {
        let appended = set_directive("[pool]\nuser = alice\n", "pm.max_children", "7");
        assert_eq!(appended, "[pool]\nuser = alice\npm.max_children = 7\n");

        let replaced = set_directive("pm.max_children = 3\n", "pm.max_children", "7");
        assert_eq!(replaced, "pm.max_children = 7\n");
        assert_eq!(replaced.matches("pm.max_children").count(), 1);
    }

    /// The dot in `pm.max_children` is a literal, not a wildcard.
    ///
    /// `${key//./\\.}` in the bash escapes it. Treating it as "any character"
    /// would make `pm.max_children` match `pmXmax_children` - and, worse,
    /// `pm.max_requests` match nothing it should while matching something it
    /// should not.
    #[test]
    fn the_dot_in_a_directive_name_is_literal() {
        let untouched = set_directive("pmXmax_children = 3\n", "pm.max_children", "7");
        assert!(untouched.contains("pmXmax_children = 3"));
        assert!(untouched.contains("pm.max_children = 7"));

        // And one directive does not match another with a shared prefix.
        let two = set_directive("pm.max_requests = 500\n", "pm.max_children", "7");
        assert!(two.contains("pm.max_requests = 500"));
        assert!(two.contains("pm.max_children = 7"));
    }

    /// Every matching line is rewritten, the way `sed -i` does it.
    ///
    /// A pool file with the directive twice is already contradictory - PHP
    /// reads the last one - and leaving a stale second copy would make the
    /// file disagree with what it does.
    #[test]
    fn a_duplicated_directive_is_rewritten_everywhere_sed_would() {
        let out = set_directive(
            "pm = dynamic\nuser = alice\npm = static\n",
            "pm",
            "ondemand",
        );
        assert_eq!(out, "pm = ondemand\nuser = alice\npm = ondemand\n");
    }

    /// What the auto-tuner is allowed to write into PHP's configuration
    /// directory, against `validate_php_tune_file` run from the shipped bash.
    ///
    /// This is a **separate allowlist** from [`validate_config`], and the
    /// corpus proves it rather than asserting it: `max_execution_time` and
    /// `display_errors` are fine on the customer's PHP settings page and are
    /// refused here, because this file is written by root and sized from the
    /// machine. Merging the two lists would widen both.
    #[test]
    fn the_tuning_allowlist_agrees_with_the_bash_helper() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/php_tune.json");
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the tune corpus"))
                .expect("the corpus parses");
        let cases = corpus["cases"].as_array().expect("the cases");
        let refused = cases
            .iter()
            .filter(|c| !c["ok"].as_bool().unwrap_or(true))
            .count();
        assert!(
            refused > 8,
            "only {refused} refusals; a corpus that accepts everything would \
             pass a validator that accepts everything"
        );

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let content = case["content"].as_str().unwrap_or("");
            let want_ok = case["ok"].as_bool().unwrap_or(false);
            match (validate_tune(content), want_ok) {
                (Ok(()), true) => {}
                (Err(e), false) => {
                    let want = case["error"].as_str().unwrap_or("");
                    if e.to_string() != want {
                        failures.push(format!("{content:?}: bash {want:?}, rust {e}"));
                    }
                }
                (Ok(()), false) => failures.push(format!(
                    "{content:?}: bash refused with {:?}, rust accepted",
                    case["error"]
                )),
                (Err(e), true) => {
                    failures.push(format!("{content:?}: bash accepted, rust refused {e}"))
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
    }

    /// The size bound is the writer's, not the validator's.
    ///
    /// An empty file passes `validate_php_tune_file` and is refused by
    /// `write_php_tune`. Putting the check in the wrong place would still
    /// refuse the same input through the verb, and would make this corpus -
    /// which drives the validator on its own - disagree.
    #[test]
    fn an_empty_tuning_file_passes_the_validator_and_not_the_writer() {
        assert!(validate_tune("").is_ok());
        assert!(validate_tune(&"; comment\n".repeat(10)).is_ok());
        // 8192 is the limit the bash tests, inclusive.
        let at_limit = "; ".to_string() + &"x".repeat(8190);
        assert_eq!(at_limit.len(), 8192);
        assert!(validate_tune(&at_limit).is_ok());
    }

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
