//! Applications: what a form field may say before root acts on it.
//!
//! Source: `services/site_apps.py`.
//!
//! An app belongs to a panel user, not to a website. It gets its own
//! directory, its own loopback port and its own systemd unit — a Node
//! process or a container. Every validator here stands between a form
//! field and something **root** writes: a unit file, a container command
//! line, an `EnvironmentFile`. The helper re-checks each of them before
//! writing; this is the copy that produces a readable error for the person
//! typing it, and the two have to agree.

/// Source: `PORT_RANGE_START` and `PORT_RANGE_END`.
///
/// A loopback range well clear of anything a distribution assigns, so an
/// app cannot be handed a port the system is about to want.
pub const PORT_RANGE_START: i64 = 21000;
pub const PORT_RANGE_END: i64 = 21999;

/// Source: `APP_KINDS`.
pub const APP_KINDS: &[&str] = &["compose", "docker", "node"];

/// Source: `START_KINDS`.
pub const START_KINDS: &[&str] = &["node", "npm", "npx", "yarn"];

/// Source: `DEFAULT_ALLOWED_REGISTRIES`.
pub const DEFAULT_ALLOWED_REGISTRIES: &[&str] = &[
    "docker.io",
    "ghcr.io",
    "quay.io",
    "registry.k8s.io",
    "public.ecr.aws",
];

/// Source: the memory and environment limits.
pub const DEFAULT_MEMORY_MB: i64 = 512;
pub const MIN_MEMORY_MB: i64 = 64;
pub const MAX_MEMORY_MB: i64 = 16384;
pub const MAX_ENV_LINES: usize = 64;
pub const MAX_ENV_VALUE: usize = 4096;

/// Source: `APPS_DIR_NAME`.
pub const APPS_DIR_NAME: &str = "apps";

/// Source: `CONTROL_ACTIONS`.
pub const CONTROL_ACTIONS: &[&str] = &[
    "disable",
    "enable",
    "is-active",
    "is-enabled",
    "restart",
    "start",
    "status",
    "stop",
];

/// `', '.join(sorted(...))` - Python sorts before joining, so the message
/// is alphabetical whatever order the set was written in.
fn sorted_list(values: &[&str]) -> String {
    let mut sorted: Vec<&str> = values.to_vec();
    sorted.sort_unstable();
    sorted.join(", ")
}

/// Source: `validate_name` with
/// `APP_NAME_RE = ^[a-z0-9][a-z0-9_-]{0,30}[a-z0-9]$|^[a-z0-9]$`.
///
/// The name becomes a directory under the customer's home **and** part of
/// a systemd unit name, so it is narrow on purpose: it may not start or
/// end with a separator, and one character is the only length below two.
pub fn validate_name(name: &str) -> Result<String, String> {
    let value = snpanel_core::pyunicode::trim(name).to_lowercase();
    if !app_name_shape_ok(&value) {
        return Err(
            "App name may only use lowercase letters, digits, hyphen and underscore".to_string(),
        );
    }
    Ok(value)
}

fn app_name_shape_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let middle = |b: u8| edge(b) || b == b'_' || b == b'-';
    match bytes.len() {
        // `^[a-z0-9]$` - the second alternative.
        1 => edge(bytes[0]),
        // `^[a-z0-9][a-z0-9_-]{0,30}[a-z0-9]$` - two to thirty-two.
        n if (2..=32).contains(&n) => {
            edge(bytes[0]) && edge(bytes[n - 1]) && bytes[1..n - 1].iter().all(|b| middle(*b))
        }
        _ => false,
    }
}

/// Source: `validate_kind`.
pub fn validate_kind(kind: &str) -> Result<String, String> {
    let value = snpanel_core::pyunicode::trim(kind).to_lowercase();
    if !APP_KINDS.contains(&value.as_str()) {
        return Err(format!(
            "Unsupported app kind. Allowed: {}",
            sorted_list(APP_KINDS)
        ));
    }
    Ok(value)
}

/// Source: `validate_port`.
///
/// `int(port)` accepts a string of digits and refuses a float, which is
/// why `3.7` is "not a number" here while `"21500"` is one.
pub fn validate_port(raw: &PortInput) -> Result<i64, String> {
    let value = raw.as_int().ok_or("Port must be a number")?;
    if !(PORT_RANGE_START..=PORT_RANGE_END).contains(&value) {
        return Err(format!(
            "Port must be between {PORT_RANGE_START} and {PORT_RANGE_END}"
        ));
    }
    Ok(value)
}

/// What `int(x)` will take: an integer, or a string of digits.
///
/// A separate type because the Python's `int()` is the whole rule and it
/// is not obvious: `int(3.7)` truncates, but FastAPI hands these in as
/// JSON, where a float stays a float and `int("3.7")` raises.
#[derive(Debug, Clone, PartialEq)]
pub enum PortInput {
    Missing,
    Int(i64),
    // A request never arrives here as text: pydantic narrows the field to
    // `Optional[int]` before the validator sees it, and what it cannot
    // narrow is a 422. These two arms carry the rest of `int()`'s input
    // domain, which is what the recorded Python verdicts are replayed
    // through, so they are exercised by the tests and not by a caller.
    #[allow(dead_code)]
    Text(String),
    #[allow(dead_code)]
    Other,
}

impl PortInput {
    /// Only the corpus builds one of these from raw JSON; see the note on
    /// the two arms above.
    #[allow(dead_code)]
    pub fn from_json(value: Option<&serde_json::Value>) -> Self {
        match value {
            None | Some(serde_json::Value::Null) => Self::Missing,
            Some(serde_json::Value::Number(n)) => match n.as_i64() {
                Some(exact) => Self::Int(exact),
                // `int(3.7)` truncates - a float reaching here came from
                // JSON and Python would take it.
                None => n
                    .as_f64()
                    .map(|f| Self::Int(f.trunc() as i64))
                    .unwrap_or(Self::Other),
            },
            Some(serde_json::Value::String(s)) => Self::Text(s.clone()),
            Some(_) => Self::Other,
        }
    }

    /// `int(value)`, or nothing.
    fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            // `int("  21500  ")` strips; `int("3.7")` raises.
            Self::Text(text) => text.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    fn is_blank(&self) -> bool {
        matches!(self, Self::Missing) || matches!(self, Self::Text(t) if t.is_empty())
    }
}

/// Source: `validate_memory_mb`.
///
/// **A package ceiling below the default lowers the default rather than
/// refusing every app.** Without that, a package allowing 256 MB would
/// reject every app the customer creates, including ones that asked for
/// no limit at all.
pub fn validate_memory_mb(raw: &PortInput, ceiling: Option<i64>) -> Result<i64, String> {
    let value = if raw.is_blank() {
        match ceiling {
            Some(limit) => std::cmp::min(DEFAULT_MEMORY_MB, limit),
            None => DEFAULT_MEMORY_MB,
        }
    } else {
        raw.as_int().ok_or("Memory limit must be a number of MB")?
    };
    if !(MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&value) {
        return Err(format!(
            "Memory limit must be between {MIN_MEMORY_MB} and {MAX_MEMORY_MB} MB"
        ));
    }
    // `if ceiling and value > ceiling` - a ceiling of zero is falsy to
    // Python and does not apply.
    if let Some(limit) = ceiling.filter(|c| *c != 0) {
        if value > limit {
            return Err(format!("This package allows at most {limit} MB per app"));
        }
    }
    Ok(value)
}

/// Source: `validate_node_major` with `NODE_MAJOR_RE = ^(1[0-9]|[2-9][0-9])$`.
///
/// Two digits, ten to ninety-nine. A single digit is refused because Node
/// 9 is long gone, and three would be a typo.
pub fn validate_node_major(raw: Option<&serde_json::Value>) -> Result<Option<String>, String> {
    // `if node_major in (None, ""): return None` - a **number** is
    // neither, so it goes on to `str()`.
    let Some(raw) = raw.filter(|v| !is_none_or_empty(v)) else {
        return Ok(None);
    };
    let value = snpanel_core::pyunicode::trim(&python_str(raw)).to_string();
    let bytes = value.as_bytes();
    let ok = bytes.len() == 2
        && bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[0] != b'0';
    if !ok {
        return Err(
            "Node version must be a major version number, for example 20 or 22".to_string(),
        );
    }
    Ok(Some(value))
}

/// Source: `validate_start`.
///
/// **Never a free-form shell string.** This ends up inside a systemd unit
/// written by root, so the launcher comes from a fixed set and the
/// argument is checked for shell metacharacters and for climbing out of
/// the app directory.
pub fn validate_start(start_kind: &str, start_arg: &str) -> Result<(String, String), String> {
    let kind = snpanel_core::pyunicode::trim(start_kind).to_lowercase();
    if !START_KINDS.contains(&kind.as_str()) {
        return Err(format!(
            "Start command must be one of: {}",
            sorted_list(START_KINDS)
        ));
    }
    let arg = snpanel_core::pyunicode::trim(start_arg).to_string();
    if arg.is_empty() {
        return Err(
            "Start command needs an argument, for example a script name or entry file".to_string(),
        );
    }
    const FORBIDDEN: &str = " \t\r\n\0'\"\\;&|<>$`()*?[]{}!#~";
    if arg.chars().any(|c| FORBIDDEN.contains(c)) {
        return Err("Start argument may not contain spaces or shell characters".to_string());
    }

    if kind == "node" {
        if !(arg.ends_with(".js") || arg.ends_with(".mjs") || arg.ends_with(".cjs")) {
            return Err("node must be given a .js, .mjs or .cjs entry file".to_string());
        }
        // The entry file is resolved inside the app directory by the
        // helper, so anything that climbs out has to be refused here.
        if !stays_inside(&arg) {
            return Err("Entry file must be inside the app directory".to_string());
        }
    } else if !script_name_ok(&arg) {
        return Err("Script or package name contains characters that are not allowed".to_string());
    }
    Ok((kind, arg))
}

/// `(Path("/app") / arg).resolve().relative_to("/app")`.
///
/// Lexical, because neither path exists at validation time — which is also
/// what `resolve(strict=False)` does for a tail that is not there. The base
/// is not a parameter because it is not a choice: the helper resolves the
/// entry file inside the app directory and nowhere else, so the only
/// question this has to answer is how far the argument climbs.
fn stays_inside(arg: &str) -> bool {
    // An absolute argument replaces the base entirely, as `/` does in
    // `pathlib`'s join.
    if arg.starts_with('/') {
        return false;
    }
    let mut depth = 0i32;
    for part in arg.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

/// `re.fullmatch(r"[A-Za-z0-9._@/-]{1,120}", arg)`.
fn script_name_ok(arg: &str) -> bool {
    let count = arg.chars().count();
    (1..=120).contains(&count)
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '/' | '-'))
}

/// Source: `allowed_registries`.
pub fn allowed_registries() -> Vec<String> {
    let raw = std::env::var("SNPANEL_ALLOWED_REGISTRIES").unwrap_or_default();
    if raw.trim().is_empty() {
        return DEFAULT_ALLOWED_REGISTRIES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
    }
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// Source: `validate_image` with
/// `IMAGE_RE = ^[a-z0-9][a-z0-9._/-]{0,159}(:[A-Za-z0-9._-]{1,127})?(@sha256:[a-f0-9]{64})?$`.
///
/// **The registry is only the first path component when something follows
/// it and it looks like a host.** Without that, `nginx:1.27` reads as the
/// registry `nginx` with port `1.27`, and a plain Docker Hub image is
/// refused.
pub fn validate_image(image: &str, enforce_registry: bool) -> Result<String, String> {
    let value = snpanel_core::pyunicode::trim(image).to_string();
    if value.is_empty() {
        return Err("Container image is required".to_string());
    }
    if !image_shape_ok(&value) || value.starts_with('-') || value.contains("..") {
        return Err(
            "Container image reference contains characters that are not allowed".to_string(),
        );
    }
    if !enforce_registry {
        return Ok(value);
    }
    let head = value.split('/').next().unwrap_or("");
    let is_registry =
        value.contains('/') && (head.contains('.') || head.contains(':') || head == "localhost");
    let registry = if is_registry { head } else { "docker.io" };
    let allowed = allowed_registries();
    if !allowed.iter().any(|a| a == registry) {
        return Err(format!(
            "Images from {registry} are not allowed. Allowed: {}",
            allowed.join(", ")
        ));
    }
    Ok(value)
}

/// The three groups of `IMAGE_RE`, in order: name, optional `:tag`,
/// optional `@sha256:<64 hex>`.
fn image_shape_ok(value: &str) -> bool {
    // The digest comes off first: its `@` is not allowed in the name.
    let (rest, digest_ok) = match value.split_once("@sha256:") {
        Some((head, digest)) => (
            head,
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        ),
        None => (value, true),
    };
    if !digest_ok || rest.contains('@') {
        return false;
    }
    // Then the tag, which may hold upper case where the name may not.
    let (name, tag_ok) = match rest.rsplit_once(':') {
        Some((head, tag)) => (
            head,
            (1..=127).contains(&tag.len())
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        ),
        None => (rest, true),
    };
    if !tag_ok || name.contains(':') {
        return false;
    }
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 160 {
        return false;
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    first_ok
        && bytes[1..].iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(*b, b'.' | b'_' | b'/' | b'-')
        })
}

/// Source: `validate_container_port`.
pub fn validate_container_port(raw: &PortInput) -> Result<i64, String> {
    if raw.is_blank() {
        return Ok(3000);
    }
    let value = raw.as_int().ok_or("Container port must be a number")?;
    if !(1..=65535).contains(&value) {
        return Err("Container port is out of range".to_string());
    }
    Ok(value)
}

/// Source: `validate_cpu_limit` with `CPU_LIMIT_RE = ^[0-9]{1,2}(\.[0-9])?$`.
///
/// Two digits and at most one decimal place, so ninety-nine is the
/// ceiling - not because a machine could have a hundred cores, but
/// because this string goes into a container's `--cpus` and a typo there
/// is a machine nobody else can use.
pub fn validate_cpu_limit(raw: Option<&serde_json::Value>) -> Result<String, String> {
    let Some(raw) = raw.filter(|v| !is_none_or_empty(v)) else {
        return Ok("1".to_string());
    };
    let value = snpanel_core::pyunicode::trim(&python_str(raw)).to_string();
    let shape_ok = cpu_limit_shape_ok(&value);
    let positive = value.parse::<f64>().map(|f| f > 0.0).unwrap_or(false);
    if !shape_ok || !positive {
        return Err("CPU limit must be a number such as 0.5, 1 or 2".to_string());
    }
    Ok(value)
}

fn cpu_limit_shape_ok(value: &str) -> bool {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    let whole_ok = (1..=2).contains(&whole.len()) && whole.bytes().all(|b| b.is_ascii_digit());
    let fraction_ok = match fraction {
        Some(f) => f.len() == 1 && f.bytes().all(|b| b.is_ascii_digit()),
        None => true,
    };
    whole_ok && fraction_ok
}

/// Source: `validate_env`.
///
/// Normalises `KEY=value` lines for the app's `EnvironmentFile`. A value
/// carrying a line break would let one variable become two inside a file
/// root writes, so it is refused rather than escaped.
pub fn validate_env(env: Option<&str>) -> Result<String, String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in snpanel_core::pyunicode::split_lines(env.unwrap_or("")) {
        let line = snpanel_core::pyunicode::trim(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "Environment line is missing '=': {}",
                clip(line, 40)
            ));
        };
        let key = snpanel_core::pyunicode::trim(key);
        if !env_key_ok(key) {
            return Err(format!(
                "Environment name must be UPPER_SNAKE_CASE: {}",
                clip(key, 40)
            ));
        }
        if value.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
            return Err(format!("Environment value for {key} contains a line break"));
        }
        if value.chars().count() > MAX_ENV_VALUE {
            return Err(format!("Environment value for {key} is too long"));
        }
        lines.push(format!("{key}={value}"));
    }
    if lines.len() > MAX_ENV_LINES {
        return Err(format!(
            "At most {MAX_ENV_LINES} environment variables are supported"
        ));
    }
    Ok(lines.join("\n"))
}

/// `ENV_KEY_RE = ^[A-Z_][A-Z0-9_]*$`.
fn env_key_ok(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// `value in (None, "")`.
///
/// A number is neither, which is the whole reason these two validators
/// take a JSON value rather than text: `0.5` is a CPU limit, not an
/// omission.
fn is_none_or_empty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::String(s) => s.is_empty(),
        _ => false,
    }
}

/// Python's `str(value)` for a parsed JSON value.
///
/// `str(20)` is `"20"` and `str(0.5)` is `"0.5"`; serde writes a float
/// with its point and an integer without, which is the same distinction.
fn python_str(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "None".to_string(),
        serde_json::Value::Bool(true) => "True".to_string(),
        serde_json::Value::Bool(false) => "False".to_string(),
        other => other.to_string(),
    }
}

/// `text[:n]` - **characters**, not bytes.
fn clip(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

// --- where an app lives, and who it runs as --------------------------------

use snpanel_db::SiteApp;

/// The Linux account an app runs as: its owner's panel account.
///
/// Source: `owner_linux_user` — `linux_user_for_panel_username` (lower and
/// strip) and then `validate_linux_user` on the result.
pub fn owner_linux_user(app: &SiteApp) -> Result<String, String> {
    let username = app
        .owner_username
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if username.is_empty() {
        return Err("This application has no owner, so it cannot be run".to_string());
    }
    snpanel_core::types::PanelUsername::parse(&username)
        .map(|user| user.as_str().to_string())
        .map_err(|_| "This application has no owner, so it cannot be run".to_string())
}

/// Mirror of the helper's own derivation, for display only.
///
/// Control commands pass the owner and the app name and let the helper build
/// the unit name, so a caller can never aim systemctl at a unit it does not
/// own. Pass *name* to ask about a name the app used to have, which is how a
/// rename finds the unit it has to tear down.
pub fn unit_name(app: &SiteApp, name: Option<&str>) -> Result<String, String> {
    let owner = owner_linux_user(app)?;
    let safe = validate_name(name.unwrap_or(&app.name))?;
    Ok(format!("snpanel-app-{owner}-{safe}"))
}

/// Where an app's files live. Derived, never supplied by the caller.
pub fn app_directory(owner_linux_user: &str, name: &str) -> Result<String, String> {
    let user = snpanel_core::types::PanelUsername::parse(owner_linux_user)
        .map_err(|_| "This application has no owner, so it cannot be run".to_string())?;
    let safe = validate_name(name)?;
    Ok(format!(
        "{}/{}/{APPS_DIR_NAME}/{safe}",
        snpanel_core::types::HOME_ROOT,
        user.as_str()
    ))
}

pub fn directory_for(app: &SiteApp) -> Result<String, String> {
    app_directory(&owner_linux_user(app)?, &app.name)
}

/// Create the app's directory now, not at first deploy.
///
/// The customer has to upload code before there is anything to deploy, so the
/// directory has to exist as soon as the app does. Also repairs ownership on
/// directories made by an earlier release, which the panel user could not
/// read.
pub async fn ensure_directory(dry_run: bool, app: &SiteApp) -> Result<String, String> {
    let owner = owner_linux_user(app)?;
    let name = validate_name(&app.name)?;
    let result = crate::shell::privileged(
        dry_run,
        "site-app-dir-ensure",
        &[&owner, &name],
        None,
        Some(&["bash", "-lc", "true"]),
    )
    .await;
    Ok(snpanel_core::pyunicode::trim(&result.stdout).to_string())
}

/// Carry an app's files across a rename.
///
/// The directory is derived from the name, so without this the customer's
/// code stays behind in the old path and the renamed app starts against
/// nothing.
pub async fn rename_directory(
    dry_run: bool,
    app: &SiteApp,
    previous_name: &str,
) -> Result<String, String> {
    if previous_name.is_empty() || previous_name == app.name {
        return Ok(String::new());
    }
    let owner = owner_linux_user(app)?;
    let before = validate_name(previous_name)?;
    let after = validate_name(&app.name)?;
    let result = crate::shell::privileged(
        dry_run,
        "site-app-rename",
        &[&owner, &before, &after],
        None,
        Some(&["bash", "-lc", "true"]),
    )
    .await;
    if result.returncode != 0 {
        return Err(stdout_or(
            &result.stderr,
            &result.stdout,
            "Could not move the application directory",
        ));
    }
    Ok(snpanel_core::pyunicode::trim(&result.stdout).to_string())
}

/// `(result.stderr or result.stdout or default).strip()` — the default is
/// taken only when both are **empty**, and the strip happens afterwards.
fn stdout_or(stderr: &str, stdout: &str, default: &str) -> String {
    let picked = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        default
    };
    snpanel_core::pyunicode::trim(picked).to_string()
}

/// The same, clipped to the last four thousand characters the way the Python
/// clips a helper's output before it reaches a message.
fn stdout_or_clipped(stderr: &str, stdout: &str, default: &str) -> String {
    last_chars(&stdout_or(stderr, stdout, default), 4000)
}

/// `text[-n:]` — **characters**, not bytes.
fn last_chars(text: &str, n: usize) -> String {
    let count = text.chars().count();
    text.chars().skip(count.saturating_sub(n)).collect()
}

/// uid and gid of the account an app runs as.
///
/// Development machines have no such account; the helper resolves the real
/// ids again before anything runs, so zeroes here are a placeholder and not a
/// grant of root.
pub fn owner_ids(app: &SiteApp) -> (u32, u32) {
    let Ok(user) = owner_linux_user(app) else {
        return (0, 0);
    };
    passwd_ids(&user).unwrap_or((0, 0))
}

/// `pwd.getpwnam(name)`, read straight out of `/etc/passwd`.
///
/// Not a lookup through libc: this process is async and `getpwnam` is
/// blocking and not reentrant. The file is the same source it reads.
fn passwd_ids(name: &str) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next() != Some(name) {
            continue;
        }
        let _password = fields.next()?;
        let uid = fields.next()?.parse().ok()?;
        let gid = fields.next()?.parse().ok()?;
        return Some((uid, gid));
    }
    None
}

// --- ports -----------------------------------------------------------------

/// Ports the kernel currently has a TCP listener on.
///
/// Best effort: if `ss` is missing the DB constraint still prevents handing
/// the same port to two apps, we just lose the check against unmanaged
/// processes.
pub async fn listening_ports(dry_run: bool) -> Vec<i64> {
    let result = crate::shell::run_timed(dry_run, "ss", &["-ltnH"], 60).await;
    if result.returncode != 0 {
        return Vec::new();
    }
    let mut ports = Vec::new();
    for line in result.stdout.split('\n') {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // `local.rpartition(":")` — everything after the last colon, which
        // is the port on both an IPv4 and an IPv6 address.
        let port = match fields[3].rsplit(':').next() {
            Some(text) => text,
            None => continue,
        };
        // `str.isdigit()`, so an empty string is not a number.
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(value) = port.parse::<i64>() {
                if !ports.contains(&value) {
                    ports.push(value);
                }
            }
        }
    }
    ports
}

/// Source: `allocate_port`.
pub async fn allocate_port(
    dry_run: bool,
    db: &snpanel_db::Database,
    preferred: &PortInput,
    exclude_app_id: Option<i64>,
) -> Result<i64, String> {
    let mut taken = db
        .site_apps()
        .reserved_ports(exclude_app_id)
        .await
        .map_err(|e| format!("could not read the ports already in use: {e}"))?;
    taken.extend(listening_ports(dry_run).await);
    if !matches!(preferred, PortInput::Missing) {
        let candidate = validate_port(preferred)?;
        if taken.contains(&candidate) {
            return Err(format!("Port {candidate} is already in use"));
        }
        return Ok(candidate);
    }
    for candidate in PORT_RANGE_START..=PORT_RANGE_END {
        if !taken.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err("No free application port left on this server".to_string())
}

// --- what a package allows -------------------------------------------------

/// `int(package.node_apps_limit or 0)`, and zero when there is no package.
pub fn app_limit_for(package: Option<&snpanel_db::Package>) -> i64 {
    package.map(|p| p.node_apps_limit).unwrap_or(0)
}

/// `package.node_app_memory_mb or DEFAULT_MEMORY_MB`.
pub fn memory_ceiling_for(package: Option<&snpanel_db::Package>) -> i64 {
    let ceiling = package.map(|p| p.node_app_memory_mb).unwrap_or(0);
    if ceiling == 0 {
        DEFAULT_MEMORY_MB
    } else {
        ceiling
    }
}

/// The package a user is on, or nothing.
pub async fn package_for(
    db: &snpanel_db::Database,
    user: &snpanel_db::User,
) -> Option<snpanel_db::Package> {
    let package_id = user.package_id?;
    db.packages().by_id(package_id).await.ok().flatten()
}

/// Source: `ensure_app_quota`. An administrator is not held to one.
pub async fn ensure_app_quota(
    db: &snpanel_db::Database,
    owner_id: i64,
    package: Option<&snpanel_db::Package>,
    is_admin: bool,
) -> Result<(), String> {
    if is_admin {
        return Ok(());
    }
    let limit = app_limit_for(package);
    if limit <= 0 {
        return Err("Application hosting is not enabled for this package".to_string());
    }
    let used = db
        .site_apps()
        .count_for_owner(owner_id)
        .await
        .map_err(|e| format!("could not count this account's applications: {e}"))?;
    if used >= limit {
        return Err(format!(
            "This package allows at most {limit} application(s)"
        ));
    }
    Ok(())
}

// --- compose ---------------------------------------------------------------

/// The URL visitors reach an app on, and the bare domain.
///
/// An app only ever sees a loopback port, so anything it has to print or hand
/// back to a browser — an OAuth callback, a webhook — has to be told the
/// address the website answers on. Empty when no website points here yet.
pub async fn public_address(db: &snpanel_db::Database, app: &SiteApp) -> (String, String) {
    let Some(domain) = app.websites.first() else {
        return (String::new(), String::new());
    };
    let secure = db
        .websites()
        .by_domain(domain)
        .await
        .ok()
        .flatten()
        .map(|site| site.ssl_enabled)
        .unwrap_or(false);
    let scheme = if secure { "https" } else { "http" };
    (format!("{scheme}://{domain}"), domain.clone())
}

/// What a compose file's `${...}` references resolve to for this app.
pub async fn compose_variables(db: &snpanel_db::Database, app: &SiteApp) -> Vec<(String, String)> {
    let (public_url, domain) = public_address(db, app).await;
    let mut values = crate::compose::read_variables(&app.env);
    // The panel's own two names win: they describe where the app is
    // reachable, which is the panel's business and not the customer's to
    // redefine.
    if !public_url.is_empty() {
        set(&mut values, "SNPANEL_URL", &public_url);
        set(&mut values, "SNPANEL_DOMAIN", &domain);
    }
    values
}

fn set(values: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(slot) = values.iter_mut().find(|(known, _)| known == key) {
        slot.1 = value.to_string();
        return;
    }
    values.push((key.to_string(), value.to_string()));
}

/// `dict.setdefault` — only when the name is not already spoken for.
pub fn default_variable(values: &mut Vec<(String, String)>, key: &str, value: &str) {
    if !values.iter().any(|(known, _)| known == key) {
        values.push((key.to_string(), value.to_string()));
    }
}

/// Re-read the customer's compose file into the panel's own model.
pub async fn compose_plan(db: &snpanel_db::Database, app: &SiteApp) -> crate::compose::Plan {
    let variables = compose_variables(db, app).await;
    crate::compose::analyse(
        &app.compose_source,
        app.web_service.as_deref().unwrap_or(""),
        true,
        &variables,
        // `app.container_port or None` — a zero is no request at all.
        Some(i128::from(app.container_port)).filter(|port| *port != 0),
    )
}

pub fn compose_project(app: &SiteApp) -> Result<String, String> {
    let owner = owner_linux_user(app)?;
    let name = validate_name(&app.name)?;
    Ok(format!("snpanel-{owner}-{name}"))
}

/// Build the compose file the server runs, from the imported one.
pub async fn render_compose(db: &snpanel_db::Database, app: &SiteApp) -> Result<String, String> {
    let plan = compose_plan(db, app).await;
    if !plan.ok() {
        let reasons: Vec<&str> = plan
            .issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect();
        let joined = reasons.join("; ");
        return Err(if joined.is_empty() {
            "Compose file is not usable".to_string()
        } else {
            joined
        });
    }
    let (uid, gid) = owner_ids(app);
    crate::compose::render(
        &plan,
        &compose_project(app)?,
        validate_port(&PortInput::Int(app.port))?,
        uid,
        gid,
        validate_memory_mb(&PortInput::Int(app.memory_limit_mb), None)?,
        &validate_cpu_limit(Some(&serde_json::Value::String(app.cpu_limit.clone())))?,
    )
}

/// Fetch every image the compose file names, before the unit starts.
pub async fn compose_pull(dry_run: bool, app: &SiteApp) -> Result<String, String> {
    let owner = owner_linux_user(app)?;
    let name = validate_name(&app.name)?;
    let result = crate::shell::privileged_timed(
        dry_run,
        "site-app-compose-pull",
        &[&owner, &name],
        None,
        Some(&["bash", "-lc", "echo dry-run-compose-pull"]),
        Some(1800),
    )
    .await;
    if result.returncode != 0 {
        return Err(stdout_or_clipped(
            &result.stderr,
            &result.stdout,
            "docker compose pull failed",
        ));
    }
    Ok(last_chars(
        snpanel_core::pyunicode::trim(&result.stdout),
        4000,
    ))
}

/// Download whatever the app needs before it is asked to run.
///
/// Both unit kinds pull implicitly when they start, but that happens with the
/// old containers already gone: the site is down for as long as the download
/// takes, and nothing reports why. Pulling first keeps what is running now
/// serving, and a tag that does not exist is reported without stopping it.
pub async fn fetch_images(dry_run: bool, app: &SiteApp) -> Result<String, String> {
    match app.kind.as_str() {
        "compose" => compose_pull(dry_run, app).await,
        "docker" => pull_image(dry_run, app).await,
        _ => Ok(String::new()),
    }
}

pub async fn pull_image(dry_run: bool, app: &SiteApp) -> Result<String, String> {
    if app.kind != "docker" {
        return Err("Only container applications pull an image".to_string());
    }
    let image = validate_image(app.image.as_deref().unwrap_or(""), true)?;
    let result = crate::shell::privileged_timed(
        dry_run,
        "site-app-pull",
        &[&image],
        None,
        Some(&["bash", "-lc", "echo dry-run-pull"]),
        Some(960),
    )
    .await;
    if result.returncode != 0 {
        return Err(stdout_or_clipped(
            &result.stderr,
            &result.stdout,
            "docker pull failed",
        ));
    }
    Ok(last_chars(
        snpanel_core::pyunicode::trim(&result.stdout),
        4000,
    ))
}

// --- the unit --------------------------------------------------------------

/// Generate and reload the systemd unit for an app.
pub async fn write_runtime(
    dry_run: bool,
    db: &snpanel_db::Database,
    app: &SiteApp,
) -> Result<String, String> {
    let linux_user = owner_linux_user(app)?;
    let mut args: Vec<String> = vec![
        linux_user,
        validate_name(&app.name)?,
        validate_kind(&app.kind)?,
        format!("--port={}", validate_port(&PortInput::Int(app.port))?),
        format!(
            "--memory={}",
            validate_memory_mb(&PortInput::Int(app.memory_limit_mb), None)?
        ),
        format!(
            "--cpus={}",
            validate_cpu_limit(Some(&serde_json::Value::String(app.cpu_limit.clone())))?
        ),
    ];
    if app.kind == "node" {
        let (start_kind, start_arg) = validate_start(
            app.start_kind.as_deref().unwrap_or(""),
            app.start_arg.as_deref().unwrap_or(""),
        )?;
        let major = node_major_or_default(app)?;
        args.push(format!("--node-major={major}"));
        args.push(format!("--exec={start_kind}"));
        args.push(format!("--arg={start_arg}"));
    } else if app.kind == "docker" {
        args.push(format!(
            "--image={}",
            validate_image(app.image.as_deref().unwrap_or(""), true)?
        ));
        args.push(format!(
            "--container-port={}",
            validate_container_port(&PortInput::Int(app.container_port))?
        ));
    }
    // A compose app carries its environment inside the generated file, so
    // that is what goes on stdin instead of an environment file.
    let payload = if app.kind == "compose" {
        render_compose(db, app).await?
    } else {
        format!("{}\n", validate_env(Some(&app.env))?)
    };
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = crate::shell::privileged(
        dry_run,
        "site-app-write",
        &borrowed,
        Some(&payload),
        Some(&["bash", "-lc", "cat >/dev/null && echo dry-run-unit"]),
    )
    .await;
    // `check=True` on this one: the Python raises, and the caller turns that
    // into the 400 a failed deploy shows.
    if result.returncode != 0 {
        return Err(stdout_or(
            &result.stderr,
            &result.stdout,
            "Could not write the unit",
        ));
    }
    Ok(snpanel_core::pyunicode::trim(&result.stdout).to_string())
}

/// `NODE_MAJOR_RE.fullmatch(text)` — two digits, ten to ninety-nine.
fn node_major_shape_ok(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_digit() && bytes[1].is_ascii_digit() && bytes[0] != b'0'
}

/// `validate_node_major(app.node_major) or "22"`.
fn node_major_or_default(app: &SiteApp) -> Result<String, String> {
    let raw = app
        .node_major
        .as_ref()
        .map(|text| serde_json::Value::String(text.clone()));
    Ok(validate_node_major(raw.as_ref())?.unwrap_or_else(|| "22".to_string()))
}

pub async fn control(dry_run: bool, app: &SiteApp, action: &str) -> Result<String, String> {
    if !CONTROL_ACTIONS.contains(&action) {
        return Err(format!(
            "Unsupported action. Allowed: {}",
            sorted_list(CONTROL_ACTIONS)
        ));
    }
    let owner = owner_linux_user(app)?;
    let name = validate_name(&app.name)?;
    let result = crate::shell::privileged(
        dry_run,
        "site-app-control",
        &[&owner, &name, action],
        None,
        Some(&["bash", "-lc", "echo dry-run"]),
    )
    .await;
    Ok(snpanel_core::pyunicode::trim(&format!("{}{}", result.stdout, result.stderr)).to_string())
}

pub async fn active_state(dry_run: bool, app: &SiteApp) -> String {
    match control(dry_run, app, "is-active").await {
        // `"".splitlines()` is empty and `[0]` on it raises, which the Python
        // catches and calls unknown — so an empty answer is not an empty
        // state.
        Ok(text) if text.is_empty() => "unknown".to_string(),
        Ok(text) => {
            snpanel_core::pyunicode::trim(text.split('\n').next().unwrap_or("")).to_string()
        }
        Err(_) => "unknown".to_string(),
    }
}

pub async fn is_running(dry_run: bool, app: &SiteApp) -> bool {
    active_state(dry_run, app).await == "active"
}

/// The unit's state once it has had a moment to fall over.
///
/// systemd calls a `Type=simple` unit active the instant it forks, so an app
/// that dies on startup still reads "active" for a second and a deploy would
/// report success on a crash loop. Sampling a few times catches the restart.
pub async fn settled_state(dry_run: bool, app: &SiteApp, checks: u32, delay_ms: u64) -> String {
    let mut state = active_state(dry_run, app).await;
    for _ in 0..checks.saturating_sub(1) {
        if state != "active" {
            return state;
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        state = active_state(dry_run, app).await;
    }
    state
}

pub async fn logs(dry_run: bool, app: &SiteApp, lines: i64) -> Result<String, String> {
    // `max(1, min(2000, int(lines or 200)))` — a zero is falsy and becomes
    // the default before the clamp.
    let asked = if lines == 0 { 200 } else { lines };
    let safe = asked.clamp(1, 2000);
    let owner = owner_linux_user(app)?;
    let name = validate_name(&app.name)?;
    let result = crate::shell::privileged(
        dry_run,
        "site-app-logs",
        &[&owner, &name, &safe.to_string()],
        None,
        Some(&["bash", "-lc", "echo 'no journal in development'"]),
    )
    .await;
    // `(stdout or "") or (stderr or "")` — no strip, and stderr only when
    // stdout is empty.
    Ok(if result.stdout.is_empty() {
        result.stderr
    } else {
        result.stdout
    })
}

/// Remove an app's unit, container and environment file.
///
/// *name* lets a rename tear down the unit the app used to run under; its
/// files are never touched either way.
pub async fn delete_runtime(dry_run: bool, app: &SiteApp, name: Option<&str>) {
    let Ok(linux_user) = owner_linux_user(app) else {
        return;
    };
    let Ok(safe) = validate_name(name.unwrap_or(&app.name)) else {
        return;
    };
    crate::shell::privileged(
        dry_run,
        "site-app-delete",
        &[&linux_user, &safe],
        None,
        Some(&["bash", "-lc", "true"]),
    )
    .await;
}

pub async fn install_dependencies(dry_run: bool, app: &SiteApp) -> Result<String, String> {
    if app.kind != "node" {
        return Err("Only Node.js applications install dependencies".to_string());
    }
    let owner = owner_linux_user(app)?;
    let name = validate_name(&app.name)?;
    let major = node_major_or_default(app)?;
    let result = crate::shell::privileged_timed(
        dry_run,
        "site-app-install-deps",
        &[&owner, &name, &major],
        None,
        Some(&["bash", "-lc", "echo dry-run-install"]),
        Some(960),
    )
    .await;
    if result.returncode != 0 {
        return Err(stdout_or_clipped(
            &result.stderr,
            &result.stdout,
            "npm install failed",
        ));
    }
    Ok(last_chars(
        snpanel_core::pyunicode::trim(&result.stdout),
        4000,
    ))
}

// --- what the containers are actually doing --------------------------------

/// What each container in a compose app is doing.
///
/// The unit only says whether `docker compose up` is still attached, and it
/// is: a container that crash-loops leaves the unit active, so without asking
/// Docker itself the panel would report a dead application as running.
///
/// `None` means Docker could not be asked — saying nothing is better than
/// reporting an outage the panel has no evidence for.
pub async fn compose_service_states(
    dry_run: bool,
    app: &SiteApp,
) -> Option<Vec<serde_json::Value>> {
    let owner = owner_linux_user(app).ok()?;
    let name = validate_name(&app.name).ok()?;
    let result = crate::shell::privileged_timed(
        dry_run,
        "site-app-compose-ps",
        &[&owner, &name],
        None,
        Some(&["bash", "-lc", "echo ''"]),
        Some(90),
    )
    .await;
    if result.returncode != 0 {
        return None;
    }
    let mut states = Vec::new();
    for line in result.stdout.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let entries = match parsed {
            serde_json::Value::Array(items) => items,
            other => vec![other],
        };
        for entry in entries {
            let named = entry
                .get("service")
                .map(crate::compose::json_truthy)
                .unwrap_or(false);
            if entry.is_object() && named {
                states.push(entry);
            }
        }
    }
    Some(states)
}

/// A sentence naming the container that is not up, or an empty string.
pub async fn compose_trouble(dry_run: bool, app: &SiteApp) -> String {
    let Some(states) = compose_service_states(dry_run, app).await else {
        return String::new();
    };
    if states.is_empty() {
        // `docker compose up` reaches this state while it downloads an image
        // it was never given beforehand: unit active, not one container to
        // show.
        return "no container is running yet (an image may still be downloading)".to_string();
    }
    let mut ordered = states.clone();
    ordered.sort_by_key(|entry| json_str(entry.get("service")));

    let mut problems: Vec<String> = Vec::new();
    for entry in &ordered {
        let name = json_str(entry.get("service"));
        let state = match entry.get("state") {
            Some(value) if crate::compose::json_truthy(value) => json_str(Some(value)),
            _ => "unknown".to_string(),
        };
        let restarts = entry.get("restarts").and_then(json_int).unwrap_or(0);
        if state != "running" {
            problems.push(format!("container '{name}' is {state}"));
        } else if restarts >= crate::compose::CRASH_LOOP_RESTARTS
            && container_uptime(&json_str(entry.get("started")))
                < crate::compose::CRASH_LOOP_UPTIME_SECONDS
        {
            // Up right now, but only because Docker just restarted it again.
            let oom = entry
                .get("oom")
                .map(crate::compose::json_truthy)
                .unwrap_or(false);
            let reason = if oom {
                " (out of memory)".to_string()
            } else {
                format!(" (last exit code {})", json_str(entry.get("exit")))
            };
            problems.push(format!(
                "container '{name}' keeps restarting — {restarts} times so far{reason}"
            ));
        }
    }
    problems.join("; ")
}

/// `str(value)` for a field read out of Docker's JSON.
fn json_str(value: Option<&serde_json::Value>) -> String {
    match value {
        None | Some(serde_json::Value::Null) => "None".to_string(),
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Bool(true)) => "True".to_string(),
        Some(serde_json::Value::Bool(false)) => "False".to_string(),
        Some(other) => other.to_string(),
    }
}

/// `int(value or 0)`.
fn json_int(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|f| f.trunc() as i64)),
        serde_json::Value::String(text) => text.trim().parse().ok(),
        serde_json::Value::Bool(flag) => Some(i64::from(*flag)),
        _ => None,
    }
}

/// Seconds since a container last started, or a very large number when the
/// stamp cannot be read — which keeps a container out of the crash-loop
/// branch rather than into it.
fn container_uptime(started: &str) -> f64 {
    let text = started.replace('Z', "+00:00");
    // Docker prints nanoseconds; `datetime` stops at microseconds.
    let text = match text.split_once('.') {
        Some((head, tail)) => {
            let (fraction, sign, offset) = match tail.find(['+']) {
                Some(at) => (&tail[..at], "+", &tail[at + 1..]),
                None => (tail, "", ""),
            };
            let cut: String = fraction.chars().take(6).collect();
            if sign.is_empty() {
                format!("{head}.{cut}")
            } else {
                format!("{head}.{cut}+{offset}")
            }
        }
        None => text,
    };
    let Some(moment) = parse_iso(&text) else {
        return f64::INFINITY;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    now - moment
}

/// `datetime.fromisoformat`, as seconds since the epoch.
///
/// A stamp with no zone is read as UTC, which is what the Python does by
/// attaching `timezone.utc` to a naive one.
fn parse_iso(text: &str) -> Option<f64> {
    let (date, rest) = text.split_once(['T', ' '])?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;

    let (clock, offset) = match rest.find(['+', 'Z']) {
        Some(at) => (&rest[..at], &rest[at..]),
        None => match rest.rfind('-') {
            Some(at) if at > 0 => (&rest[..at], &rest[at..]),
            _ => (rest, ""),
        },
    };
    let mut clock_parts = clock.split(':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: f64 = clock_parts.next().unwrap_or("0").parse().ok()?;

    let offset_seconds = if offset.is_empty() || offset == "Z" {
        0
    } else {
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let body = &offset[1..];
        let mut pieces = body.split(':');
        let hours: i64 = pieces.next()?.parse().ok()?;
        let minutes: i64 = pieces.next().unwrap_or("0").parse().ok()?;
        sign * (hours * 3600 + minutes * 60)
    };
    let days = days_from_civil(year, month, day);
    Some((days * 86400 + hour * 3600 + minute * 60 - offset_seconds) as f64 + second)
}

/// Days from 1970-01-01 to the given date. Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719468
}

// --- what the server has installed -----------------------------------------

pub async fn docker_status(dry_run: bool) -> serde_json::Value {
    let result = crate::shell::privileged(
        dry_run,
        "docker-status",
        &[],
        None,
        Some(&["bash", "-lc", "echo installed=no"]),
    )
    .await;
    let mut parsed: Vec<(String, String)> = Vec::new();
    let mut disk: Vec<serde_json::Value> = Vec::new();
    for line in result.stdout.split('\n') {
        if let Some(rest) = line.strip_prefix("df=") {
            // Type|Size|Reclaimable, straight from `docker system df`.
            let parts: Vec<&str> = rest.split('|').collect();
            if parts.len() == 3 {
                disk.push(serde_json::json!({
                    "type": parts[0], "size": parts[1], "reclaimable": parts[2]
                }));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = snpanel_core::pyunicode::trim(key).to_string();
            let value = snpanel_core::pyunicode::trim(value).to_string();
            if let Some(slot) = parsed.iter_mut().find(|(known, _)| *known == key) {
                slot.1 = value;
            } else {
                parsed.push((key, value));
            }
        }
    }
    let field = |name: &str| {
        parsed
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    serde_json::json!({
        "installed": field("installed").as_deref() == Some("yes"),
        "version": field("version").unwrap_or_default(),
        "active": field("active").unwrap_or_default(),
        // Server-wide, not per customer: one image serves every tenant using it.
        "disk": disk,
    })
}

/// Reclaim dead layers and build cache. Nothing in use is removed.
pub async fn prune_docker(dry_run: bool) -> Result<String, String> {
    plain_helper(
        dry_run,
        "docker-prune",
        &[],
        900,
        "Docker prune failed",
        "echo dry-run-docker-prune",
    )
    .await
}

pub async fn install_docker(dry_run: bool) -> Result<String, String> {
    plain_helper(
        dry_run,
        "docker-install",
        &[],
        1800,
        "Docker install failed",
        "echo dry-run-docker-install",
    )
    .await
}

pub async fn install_node(
    dry_run: bool,
    major: Option<&serde_json::Value>,
) -> Result<String, String> {
    let Some(safe) = validate_node_major(major)? else {
        return Err("Node version is required".to_string());
    };
    plain_helper(
        dry_run,
        "node-install",
        &[&safe],
        900,
        "Node install failed",
        "echo dry-run-node-install",
    )
    .await
}

pub async fn installed_node_majors(dry_run: bool) -> Vec<String> {
    let result = crate::shell::privileged(
        dry_run,
        "node-list",
        &[],
        None,
        Some(&["bash", "-lc", "true"]),
    )
    .await;
    let mut majors: Vec<String> = result
        .stdout
        .split('\n')
        .map(|line| snpanel_core::pyunicode::trim(line).to_string())
        .filter(|line| node_major_shape_ok(line))
        .collect();
    majors.sort_by_key(|text| text.parse::<i64>().unwrap_or(0));
    majors
}

/// One helper verb with no arguments to shape and one message on failure.
async fn plain_helper(
    dry_run: bool,
    verb: &str,
    args: &[&str],
    timeout: u64,
    default: &str,
    fallback: &str,
) -> Result<String, String> {
    let result = crate::shell::privileged_timed(
        dry_run,
        verb,
        args,
        None,
        Some(&["bash", "-lc", fallback]),
        Some(timeout),
    )
    .await;
    if result.returncode != 0 {
        return Err(stdout_or_clipped(&result.stderr, &result.stdout, default));
    }
    Ok(last_chars(
        snpanel_core::pyunicode::trim(&result.stdout),
        4000,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/site_apps.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the site apps corpus"))
            .expect("the corpus parses")
    }

    /// Compare a `Result<String, String>` against one corpus case.
    fn check(case: &Value, got: Result<String, String>, failures: &mut Vec<String>, label: &str) {
        match case.get("value").and_then(Value::as_str) {
            Some(want) => {
                if got.as_deref() != Ok(want) {
                    failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                }
            }
            None => {
                let want = case["error"].as_str().unwrap_or("");
                if got.as_ref().err().map(String::as_str) != Some(want) {
                    failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                }
            }
        }
    }

    /// The app name, which becomes a directory and a unit name.
    #[test]
    fn an_app_name_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let cases = corpus["validate_name"].as_array().expect("the cases");
        assert_eq!(cases.len(), 22, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().unwrap_or("");
            check(case, validate_name(raw), &mut failures, &format!("{raw:?}"));
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // One character is allowed, and it is the **only** length below
        // two - the pattern's second alternative exists for exactly that.
        assert_eq!(validate_name("a").unwrap(), "a");
        // A separator may not be at either end: the name is joined into a
        // path and a systemd unit, and both read badly with one.
        assert!(validate_name("-a").is_err());
        assert!(validate_name("a-").is_err());
        // Thirty-two is the ceiling.
        assert!(validate_name(&"a".repeat(32)).is_ok());
        assert!(validate_name(&"a".repeat(33)).is_err());
    }

    #[test]
    fn an_app_kind_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["validate_kind"].as_array().expect("the cases") {
            let raw = case["raw"].as_str().unwrap_or("");
            check(case, validate_kind(raw), &mut failures, &format!("{raw:?}"));
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // The message lists the kinds **sorted**, whatever order the set
        // was written in.
        assert_eq!(
            validate_kind("python").unwrap_err(),
            "Unsupported app kind. Allowed: compose, docker, node"
        );
    }

    /// The loopback port, and what `int()` will take.
    #[test]
    fn a_port_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let cases = corpus["validate_port"].as_array().expect("the cases");
        assert_eq!(cases.len(), 12, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let input = PortInput::from_json(Some(&case["raw"]));
            let got = validate_port(&input).map(|v| v.to_string());
            let label = format!("{}", case["raw"]);
            match case.get("value").and_then(Value::as_i64) {
                Some(want) => {
                    if got.as_deref() != Ok(want.to_string().as_str()) {
                        failures.push(format!("{label}: python {want}, rust {got:?}"));
                    }
                }
                None => {
                    let want = case["error"].as_str().unwrap_or("");
                    if got.as_ref().err().map(String::as_str) != Some(want) {
                        failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // The range is inclusive at both ends.
        assert!(validate_port(&PortInput::Int(21000)).is_ok());
        assert!(validate_port(&PortInput::Int(21999)).is_ok());
        assert!(validate_port(&PortInput::Int(20999)).is_err());
        assert!(validate_port(&PortInput::Int(22000)).is_err());
    }

    /// The memory limit, and the ceiling that lowers the default.
    #[test]
    fn a_memory_limit_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let cases = corpus["validate_memory"].as_array().expect("the cases");
        assert_eq!(cases.len(), 16, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let input = PortInput::from_json(Some(&case["raw"]));
            let ceiling = case["ceiling"].as_i64();
            let got = validate_memory_mb(&input, ceiling).map(|v| v.to_string());
            let label = format!("{} ceiling {ceiling:?}", case["raw"]);
            match case.get("value").and_then(Value::as_i64) {
                Some(want) => {
                    if got.as_deref() != Ok(want.to_string().as_str()) {
                        failures.push(format!("{label}: python {want}, rust {got:?}"));
                    }
                }
                None => {
                    let want = case["error"].as_str().unwrap_or("");
                    if got.as_ref().err().map(String::as_str) != Some(want) {
                        failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // **A ceiling below the default lowers the default.** Without
        // that, a package allowing 256 MB would refuse every app the
        // customer creates, including ones that asked for no limit.
        assert_eq!(
            validate_memory_mb(&PortInput::Missing, Some(256)).unwrap(),
            256
        );
        assert_eq!(
            validate_memory_mb(&PortInput::Missing, Some(1024)).unwrap(),
            512
        );
    }

    #[test]
    fn a_node_major_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["validate_node_major"].as_array().expect("the cases") {
            let raw = Some(&case["raw"]).filter(|v| !v.is_null());
            let got = validate_node_major(raw);
            let label = format!("{}", case["raw"]);
            match case.get("value") {
                Some(Value::String(want)) => {
                    if got.as_ref().map(Option::as_deref) != Ok(Some(want.as_str())) {
                        failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                    }
                }
                Some(Value::Null) => {
                    if !matches!(got, Ok(None)) {
                        failures.push(format!("{label}: python None, rust {got:?}"));
                    }
                }
                _ => {
                    let want = case["error"].as_str().unwrap_or("");
                    if got.as_ref().err().map(String::as_str) != Some(want) {
                        failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // Two digits, ten to ninety-nine: a single digit is a Node that
        // is long gone and three would be a typo.
        let text = |s: &str| serde_json::Value::String(s.to_string());
        assert!(validate_node_major(Some(&text("9"))).is_err());
        assert!(validate_node_major(Some(&text("100"))).is_err());
        assert!(validate_node_major(Some(&text("20"))).is_ok());
        // A JSON **number** is a version, not an omission.
        assert_eq!(
            validate_node_major(Some(&serde_json::json!(20)))
                .unwrap()
                .as_deref(),
            Some("20")
        );
    }

    /// The start command, which ends up in a unit file written by root.
    #[test]
    fn a_start_command_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let cases = corpus["validate_start"].as_array().expect("the cases");
        assert_eq!(cases.len(), 22, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let kind = case["kind"].as_str().unwrap_or("");
            let arg = case["arg"].as_str().unwrap_or("");
            let got = validate_start(kind, arg);
            let label = format!("({kind:?}, {arg:?})");
            match case.get("value").and_then(Value::as_array) {
                Some(want) => {
                    let want = (
                        want[0].as_str().unwrap_or("").to_string(),
                        want[1].as_str().unwrap_or("").to_string(),
                    );
                    if got.as_ref() != Ok(&want) {
                        failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                    }
                }
                None => {
                    let want = case["error"].as_str().unwrap_or("");
                    if got.as_ref().err().map(String::as_str) != Some(want) {
                        failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // **Nothing that climbs out of the app directory.** The helper
        // resolves the entry file inside it as root.
        assert!(validate_start("node", "../escape.js").is_err());
        assert!(validate_start("node", "/etc/passwd.js").is_err());
        // And nothing a shell would read as more than one word.
        for bad in ["a b.js", "a;b.js", "a$b.js", "a`b.js", "a|b.js"] {
            assert!(validate_start("node", bad).is_err(), "{bad}");
        }
    }

    /// The container image, and which registry it may come from.
    #[test]
    fn an_image_is_validated_the_way_python_validates_it() {
        // The corpus was generated with the allow-list variable popped, and
        // another test sets it.
        let _guard = crate::testenv::EnvGuard::cleared(&["SNPANEL_ALLOWED_REGISTRIES"]);
        let corpus = corpus();
        let cases = corpus["validate_image"].as_array().expect("the cases");
        assert_eq!(cases.len(), 22, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().unwrap_or("");
            let enforce = case["enforce"].as_bool().unwrap_or(true);
            check(
                case,
                validate_image(raw, enforce),
                &mut failures,
                &format!("{raw:?} enforce={enforce}"),
            );
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // **`nginx:1.27` is a Docker Hub image, not the registry `nginx`
        // on port `1.27`.** The first component is a registry only when
        // something follows it and it looks like a host.
        assert!(validate_image("nginx:1.27", true).is_ok());
        assert!(validate_image("evil.example.com/app", true).is_err());
        // A digest is sixty-four lower-case hex characters.
        assert!(validate_image(&format!("nginx@sha256:{}", "a".repeat(64)), true).is_ok());
        assert!(validate_image(&format!("nginx@sha256:{}", "a".repeat(63)), true).is_err());
        // `..` is refused wherever it appears: this string reaches a
        // container runtime's argv.
        assert!(validate_image("a/../b", true).is_err());
    }

    #[test]
    fn a_container_port_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["validate_container_port"]
            .as_array()
            .expect("the cases")
        {
            let input = PortInput::from_json(Some(&case["raw"]));
            let got = validate_container_port(&input).map(|v| v.to_string());
            let label = format!("{}", case["raw"]);
            match case.get("value").and_then(Value::as_i64) {
                Some(want) => {
                    if got.as_deref() != Ok(want.to_string().as_str()) {
                        failures.push(format!("{label}: python {want}, rust {got:?}"));
                    }
                }
                None => {
                    let want = case["error"].as_str().unwrap_or("");
                    if got.as_ref().err().map(String::as_str) != Some(want) {
                        failures.push(format!("{label}: python {want:?}, rust {got:?}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // Nothing given is 3000, which is what most Node apps listen on.
        assert_eq!(validate_container_port(&PortInput::Missing).unwrap(), 3000);
    }

    #[test]
    fn a_cpu_limit_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["validate_cpu_limit"].as_array().expect("the cases") {
            let raw = Some(&case["raw"]).filter(|v| !v.is_null());
            check(
                case,
                validate_cpu_limit(raw),
                &mut failures,
                &format!("{}", case["raw"]),
            );
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // Two digits and one decimal place: ninety-nine is the ceiling,
        // and zero is refused because a container limited to no CPU never
        // starts.
        let text = |s: &str| serde_json::Value::String(s.to_string());
        assert!(validate_cpu_limit(Some(&text("99"))).is_ok());
        assert!(validate_cpu_limit(Some(&text("100"))).is_err());
        assert!(validate_cpu_limit(Some(&text("0"))).is_err());
        assert!(validate_cpu_limit(Some(&text("1.55"))).is_err());
        // A JSON float is a limit: `str(0.5)` is `"0.5"`.
        assert_eq!(
            validate_cpu_limit(Some(&serde_json::json!(0.5))).unwrap(),
            "0.5"
        );
    }

    /// The environment file, which root writes.
    #[test]
    fn an_environment_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let cases = corpus["validate_env"].as_array().expect("the cases");
        assert_eq!(cases.len(), 19, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str();
            check(case, validate_env(raw), &mut failures, &format!("{raw:?}"));
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // **A line break in a value would make one variable into two**
        // inside a file root writes, so it is refused rather than escaped.
        assert!(validate_env(Some("KEY=a\x00b")).is_err());
        // The key is upper snake case; the value may be anything else.
        assert!(validate_env(Some("lower=v")).is_err());
        assert_eq!(
            validate_env(Some("KEY=has=equals")).unwrap(),
            "KEY=has=equals"
        );
    }

    /// The registry allow-list, which an operator can widen.
    #[test]
    fn the_registry_allowlist_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        for case in corpus["allowed_registries"].as_array().expect("the cases") {
            let raw = case["raw"].as_str().unwrap_or("");
            let want: Vec<String> = case["allowed"]
                .as_array()
                .expect("the list")
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let _guard = crate::testenv::EnvGuard::set(&[("SNPANEL_ALLOWED_REGISTRIES", raw)]);
            assert_eq!(allowed_registries(), want, "for {raw:?}");
        }
    }
}
