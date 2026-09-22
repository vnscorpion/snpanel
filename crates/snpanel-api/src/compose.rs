//! Import a customer's docker-compose file onto the panel's own model.
//!
//! The file a customer pastes is never the file that runs. It is parsed,
//! checked against an allowlist, and a fresh compose file is generated from
//! what survived. That direction matters: a blocklist would have to keep up
//! with every key Compose adds, and one missed key (`privileged`,
//! `network_mode`, a host bind mount) undoes every guardrail around the
//! container. Anything this module does not recognise is refused by name so
//! the customer can see exactly what to change.
//!
//! Source: `backend/app/services/compose.py`.

use crate::yaml::Value;

/// Keys the panel understands. Everything else is refused, including keys
/// that have not been invented yet.
pub const ALLOWED_TOP_LEVEL: &[&str] = &["services", "volumes", "version", "name"];

pub const ALLOWED_SERVICE_KEYS: &[&str] = &[
    "image",
    "environment",
    "command",
    "entrypoint",
    "depends_on",
    "ports",
    "expose",
    "volumes",
    "user",
    "working_dir",
    "hostname",
    "healthcheck",
    "labels",
    "restart",
    "stop_grace_period",
    "tty",
    "stdin_open",
    "container_name",
    // Accepted and then overridden by the panel's own limits.
    "mem_limit",
    "memswap_limit",
    "cpus",
    "pids_limit",
];

/// Refused with a specific explanation rather than the generic message,
/// because these are the ones people actually reach for.
pub const EXPLAINED_SERVICE_KEYS: &[(&str, &str)] = &[
    ("privileged", "chạy container ở chế độ privileged"),
    (
        "network_mode",
        "đặt network_mode (host network bỏ qua chốt firewall)",
    ),
    ("cap_add", "thêm capability"),
    ("devices", "gắn thiết bị của máy chủ"),
    ("pid", "dùng chung PID namespace với máy chủ"),
    ("ipc", "dùng chung IPC namespace"),
    ("userns_mode", "đổi user namespace"),
    ("security_opt", "đổi tuỳ chọn bảo mật"),
    ("sysctls", "đặt sysctl"),
    ("build", "build image tại chỗ; panel chỉ chạy image có sẵn"),
    ("extra_hosts", "ghi đè phân giải tên máy"),
    ("volumes_from", "mượn volume của container khác"),
    ("cgroup_parent", "đổi cgroup cha"),
    ("group_add", "thêm group phụ"),
    (
        "env_file",
        "đọc biến môi trường từ file; dán thẳng vào phần Environment",
    ),
    (
        "networks",
        "tự khai network; panel tạo network riêng cho ứng dụng",
    ),
    ("deploy", "khai báo deploy của swarm"),
];

/// An application behind the panel's proxy never sees its own public address:
/// it listens on a loopback port nobody types. These stand in for the domain
/// the website serves it on, so a value like `WEBHOOK_URL` can be written
/// once and still be right after the domain changes.
pub const PLACEHOLDERS: &[&str] = &["SNPANEL_URL", "SNPANEL_DOMAIN"];

/// What a refused file is reported behind. Only the prefix is the panel's;
/// what follows is the reader's own account of what went wrong, and PyYAML's
/// wording for it was never something a second reader could reproduce.
pub const PARSE_FAILED: &str = "YAML không hợp lệ: ";

pub const MAX_SERVICES: usize = 8;
pub const MAX_SOURCE_BYTES: usize = 64 * 1024;

/// The minimum an image needs to drop from root to its own account at
/// startup — what the official Postgres and MySQL entrypoints do through
/// gosu. Without these the container cannot initialise its data directory.
pub const PRIVILEGE_DROP_CAPS: &[&str] = &["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"];

/// A container Docker has restarted this many times, and which has been up
/// for less than a moment, is going round in a loop rather than having had a
/// bad day.
pub const CRASH_LOOP_RESTARTS: i64 = 3;
pub const CRASH_LOOP_UPTIME_SECONDS: f64 = 180.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub service: String,
    pub message: String,
}

impl Issue {
    fn new(service: &str, message: impl Into<String>) -> Issue {
        Issue {
            service: service.to_string(),
            message: message.into(),
        }
    }

    pub fn as_json(&self) -> serde_json::Value {
        serde_json::json!({"service": self.service, "message": self.message})
    }
}

#[derive(Debug, Clone, Default)]
pub struct Service {
    pub name: String,
    pub image: String,
    /// Insertion-ordered, like the `dict` the Python builds.
    pub environment: Vec<(String, String)>,
    pub command: Option<Value>,
    pub entrypoint: Option<Value>,
    pub depends_on: Vec<String>,
    /// The one the domain reaches.
    pub container_port: Option<i128>,
    /// Every one declared.
    pub container_ports: Vec<i128>,
    /// `data:/var/lib/x`
    pub named_volumes: Vec<String>,
    /// `./src:/app/src`
    pub bind_mounts: Vec<String>,
    pub user: Option<String>,
    pub working_dir: Option<Value>,
    pub healthcheck: Option<Value>,
    pub memory_mb: Option<i64>,
}

impl Service {
    pub fn touches_app_files(&self) -> bool {
        !self.bind_mounts.is_empty()
    }

    fn environment_get(&self, key: &str) -> Option<&str> {
        self.environment
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub services: Vec<Service>,
    pub volumes: Vec<String>,
    pub web_service: String,
    pub issues: Vec<Issue>,
    /// Things worth saying that are not reasons to refuse the file.
    pub notes: Vec<String>,
}

impl Plan {
    pub fn ok(&self) -> bool {
        self.issues.is_empty() && !self.services.is_empty()
    }

    pub fn as_json(&self) -> serde_json::Value {
        let services: Vec<serde_json::Value> = self
            .services
            .iter()
            .map(|service| {
                let mut volumes = service.named_volumes.clone();
                volumes.extend(service.bind_mounts.iter().cloned());
                let mut keys: Vec<&str> = service
                    .environment
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect();
                keys.sort_unstable();
                serde_json::json!({
                    "name": service.name,
                    "image": service.image,
                    "container_port": service.container_port.map(port_number),
                    "container_ports": service.container_ports.iter().copied().map(port_number).collect::<Vec<_>>(),
                    "volumes": volumes,
                    "environment": keys,
                    "web": service.name == self.web_service,
                })
            })
            .collect();
        serde_json::json!({
            "ok": self.ok(),
            "web_service": self.web_service,
            "issues": self.issues.iter().map(Issue::as_json).collect::<Vec<_>>(),
            "notes": self.notes,
            "services": services,
            "volumes": self.volumes,
        })
    }
}

/// A port is validated into 1..=65535 before it is ever stored, so this only
/// ever narrows a number that already fits.
fn port_number(port: i128) -> i64 {
    port as i64
}

// --- reading the pieces ----------------------------------------------------

/// `_as_list`: a missing value is nothing, and a single value is a list of
/// one.
fn as_list(value: Option<&Value>) -> Vec<Value> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::List(items)) => items.clone(),
        Some(other) => vec![other.clone()],
    }
}

/// `int(str(value))` — the strict one, not pydantic's.
///
/// Leading and trailing whitespace is allowed, a sign is allowed, and an
/// underscore is allowed between digits. Nothing else is.
fn python_int(text: &str) -> Option<i128> {
    let body = snpanel_core::pyunicode::trim(text);
    let (sign, digits) = match body.as_bytes().first() {
        Some(b'-') => (-1i128, &body[1..]),
        Some(b'+') => (1, &body[1..]),
        _ => (1, body),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') {
        return None;
    }
    let mut previous_underscore = false;
    for ch in digits.chars() {
        if ch == '_' {
            if previous_underscore {
                return None;
            }
            previous_underscore = true;
            continue;
        }
        if !ch.is_ascii_digit() {
            return None;
        }
        previous_underscore = false;
    }
    let cleaned: String = digits.chars().filter(|c| *c != '_').collect();
    cleaned.parse::<i128>().ok().map(|number| sign * number)
}

/// `float(text)` — again the strict one. `inf`, `nan` and an exponent with
/// no sign are all accepted here, unlike by YAML's own resolver.
fn python_float(text: &str) -> Option<f64> {
    let body = snpanel_core::pyunicode::trim(text);
    if body.is_empty() {
        return None;
    }
    let cleaned: String = body.chars().filter(|c| *c != '_').collect();
    // Rust parses `inf`/`nan` and the `1e5` form the same way Python does,
    // but it also accepts nothing Python refuses here.
    if cleaned.contains(['_']) {
        return None;
    }
    let lowered = cleaned.to_ascii_lowercase();
    match lowered.as_str() {
        "inf" | "+inf" | "-inf" | "infinity" | "+infinity" | "-infinity" | "nan" | "+nan"
        | "-nan" => return lowered.parse::<f64>().ok().or(Some(f64::INFINITY)),
        _ => {}
    }
    if !lowered
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'+' | b'-'))
    {
        return None;
    }
    lowered.parse::<f64>().ok()
}

/// `_parse_environment`.
fn parse_environment(
    raw: Option<&Value>,
    service: &str,
    issues: &mut Vec<Issue>,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();
    let raw = match raw {
        None | Some(Value::Null) => return entries,
        Some(value) => value,
    };
    let mut items: Vec<(String, Value)> = Vec::new();
    match raw {
        Value::Map(pairs) => {
            for (key, value) in pairs {
                items.push((key.python_str(), value.clone()));
            }
        }
        Value::List(lines) => {
            for line in lines {
                let text = line.python_str();
                let Some((key, value)) = text.split_once('=') else {
                    // `- FOO` inherits from the host environment, which for
                    // us is the panel's own process. Never pass that through.
                    issues.push(Issue::new(
                        service,
                        format!("biến môi trường {} không có giá trị", clip(&text, 40)),
                    ));
                    continue;
                };
                items.push((key.to_string(), Value::Str(value.to_string())));
            }
        }
        _ => {
            issues.push(Issue::new(
                service,
                "environment phải là danh sách hoặc mapping",
            ));
            return entries;
        }
    }

    for (key, value) in items {
        let name = snpanel_core::pyunicode::trim(&key).to_string();
        if !env_key_ok(&name) {
            issues.push(Issue::new(
                service,
                format!("tên biến môi trường không hợp lệ: {}", clip(&name, 40)),
            ));
            continue;
        }
        let text = match &value {
            Value::Null => String::new(),
            other => other.python_str(),
        };
        if text.contains(['\r', '\n', '\0']) {
            issues.push(Issue::new(
                service,
                format!("giá trị của {name} chứa xuống dòng"),
            ));
            continue;
        }
        insert(&mut entries, name, text);
    }
    entries
}

/// `^[A-Za-z_][A-Za-z0-9_]*$` — looser than the one the panel applies to its
/// own environment box, because this is Compose's rule and not the panel's.
fn env_key_ok(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn insert(entries: &mut Vec<(String, String)>, key: String, value: String) {
    if let Some(slot) = entries.iter_mut().find(|(known, _)| *known == key) {
        slot.1 = value;
        return;
    }
    entries.push((key, value));
}

/// `_parse_port`: the port the process listens on **inside** the container.
///
/// Host publishing from the file is ignored: the panel decides the loopback
/// port so two customers cannot claim the same one.
fn parse_port(raw: &Value, service: &str, issues: &mut Vec<Issue>) -> Option<i128> {
    let target = match raw {
        Value::Map(_) => match raw.get("target") {
            Some(value) => value.python_str(),
            // `dict.get` with no key is None, and `int(str(None))` fails.
            None => "None".to_string(),
        },
        other => {
            let text = other.python_str();
            let head = text.split('/').next().unwrap_or("").to_string();
            head.rsplit(':').next().unwrap_or("").to_string()
        }
    };
    let Some(port) = python_int(&target) else {
        issues.push(Issue::new(
            service,
            format!("cổng không đọc được: {}", clip(&raw.python_str(), 40)),
        ));
        return None;
    };
    if !(1..=65535).contains(&port) {
        issues.push(Issue::new(service, format!("cổng ngoài phạm vi: {port}")));
        return None;
    }
    Some(port)
}

/// `('named' | 'bind', spec)`.
fn parse_volume(
    raw: &Value,
    service: &str,
    declared: &mut Vec<String>,
    issues: &mut Vec<Issue>,
) -> Option<(&'static str, String)> {
    if raw.as_map().is_some() {
        let kind = match raw.get("type") {
            Some(value) => value.python_str(),
            None => "volume".to_string(),
        };
        let source = raw.get("source").map(Value::python_str).unwrap_or_default();
        let target = raw.get("target").map(Value::python_str).unwrap_or_default();
        let read_only = raw.get("read_only").map(Value::truthy).unwrap_or(false);
        if source.is_empty() || target.is_empty() {
            issues.push(Issue::new(service, "volume thiếu source hoặc target"));
            return None;
        }
        let spec = format!("{source}:{target}{}", if read_only { ":ro" } else { "" });
        if kind != "bind" && kind != "volume" {
            issues.push(Issue::new(
                service,
                format!("loại volume không hỗ trợ: {kind}"),
            ));
            return None;
        }
        return parse_volume(&Value::Str(spec), service, declared, issues);
    }

    let text = raw.python_str();
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() < 2 {
        issues.push(Issue::new(
            service,
            format!("volume phải có dạng nguồn:đích — {}", clip(&text, 50)),
        ));
        return None;
    }
    let (source, target) = (parts[0], parts[1]);
    let suffix = match parts.get(2) {
        Some(mode) if *mode == "ro" || *mode == "rw" => format!(":{mode}"),
        _ => String::new(),
    };
    if !target.starts_with('/') {
        issues.push(Issue::new(
            service,
            format!(
                "đích của volume phải là đường dẫn tuyệt đối — {}",
                clip(&text, 50)
            ),
        ));
        return None;
    }
    if source.starts_with('/') {
        issues.push(Issue::new(
            service,
            format!(
                "mount đường dẫn máy chủ không được phép — {}; \
hãy dùng đường dẫn trong thư mục ứng dụng (./data) hoặc volume có tên",
                clip(&text, 50)
            ),
        ));
        return None;
    }
    if source.starts_with('.') || source.contains('/') {
        // A path relative to the project, which is the application directory.
        let pieces: Vec<&str> = source
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        if pieces.contains(&"..") {
            issues.push(Issue::new(
                service,
                format!("volume trỏ ra ngoài thư mục ứng dụng — {}", clip(&text, 50)),
            ));
            return None;
        }
        let cleaned = pieces.join("/");
        return Some((
            "bind",
            if cleaned.is_empty() {
                format!(".:{target}{suffix}")
            } else {
                format!("./{cleaned}:{target}{suffix}")
            },
        ));
    }
    if !volume_name_ok(source) {
        issues.push(Issue::new(
            service,
            format!("tên volume không hợp lệ: {}", clip(source, 40)),
        ));
        return None;
    }
    if !declared.iter().any(|known| known == source) {
        declared.push(source.to_string());
    }
    Some(("named", format!("{source}:{target}{suffix}")))
}

/// `^[a-z0-9][a-z0-9_-]{0,62}$`.
fn volume_name_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let head = bytes[0];
    if !(head.is_ascii_lowercase() || head.is_ascii_digit()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// `^[a-z0-9][a-z0-9_-]{0,30}$`.
fn service_name_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 31 {
        return false;
    }
    let head = bytes[0];
    if !(head.is_ascii_lowercase() || head.is_ascii_digit()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// `^[A-Za-z0-9_.:-]{1,64}$`, the shape a `user:` may take.
fn user_value_ok(text: &str) -> bool {
    let count = text.chars().count();
    (1..=64).contains(&count)
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// Where a service run under a forced uid should keep its home.
///
/// Overriding `user` with a numeric id leaves the container with no matching
/// passwd entry, so HOME falls back to `/` and the first thing the process
/// writes there fails. Point it at the directory the customer mounted, which
/// is the one place inside the container they own.
///
/// A mount at `/home/node/.n8n` is the app's own dot-directory inside a home
/// the image owns, so the home is its parent — and that parent belongs to the
/// image's account, not ours. Returns `true` alongside it to say the home
/// itself needs to be made writable; the mount underneath it stays persistent
/// either way, because Docker mounts the deeper path last.
pub fn home_for(service: &Service) -> (String, bool) {
    let target = service.bind_mounts[0]
        .split(':')
        .nth(1)
        .unwrap_or("")
        .to_string();
    let (parent, name) = posix_split(&target);
    if name.starts_with('.') {
        (parent, true)
    } else {
        (posix_normalise(&target), false)
    }
}

/// `PurePosixPath(text).name` and `.parent`, as text.
fn posix_split(text: &str) -> (String, String) {
    let normalised = posix_normalise(text);
    match normalised.rsplit_once('/') {
        Some((head, name)) => (
            if head.is_empty() {
                "/".to_string()
            } else {
                head.to_string()
            },
            name.to_string(),
        ),
        None => (".".to_string(), normalised),
    }
}

/// What `str(PurePosixPath(text))` gives back: repeated and trailing slashes
/// collapse, `.` segments fall away, and an empty path becomes `.`.
fn posix_normalise(text: &str) -> String {
    let absolute = text.starts_with('/');
    let pieces: Vec<&str> = text
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if pieces.is_empty() {
        return if absolute {
            "/".to_string()
        } else {
            ".".to_string()
        };
    }
    let body = pieces.join("/");
    if absolute {
        format!("/{body}")
    } else {
        body
    }
}

/// `parse_memory`: a compose memory value — `512m`, `1g`, or a plain byte
/// count — read as MB.
pub fn parse_memory(value: Option<&Value>) -> Option<i64> {
    let raw = match value {
        None | Some(Value::Null) => String::new(),
        Some(other) => other.python_str(),
    };
    let text = snpanel_core::pyunicode::trim(&raw).to_lowercase();
    if text.is_empty() {
        return None;
    }
    let factor = match text.chars().last() {
        Some('k') => Some(1.0 / 1024.0),
        Some('m') => Some(1.0),
        Some('g') => Some(1024.0),
        Some('b') => Some(1.0 / (1024.0 * 1024.0)),
        _ => None,
    };
    let number = match factor {
        // The unit is one **character**, and every one of them is ASCII.
        Some(_) => &text[..text.len() - 1],
        None => &text[..],
    };
    let parsed = python_float(number)?;
    let megabytes = parsed * factor.unwrap_or(1.0 / (1024.0 * 1024.0));
    // `int()` truncates toward zero, and then the floor of 1 applies.
    Some((megabytes as i64).max(1))
}

/// `bool(value)` for a value that came out of JSON rather than YAML.
///
/// Docker's `compose ps --format json` is read the same way the compose file
/// is — an absent field, a null, a zero and an empty string are all false.
pub fn json_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(number) => number.as_f64().unwrap_or(0.0) != 0.0,
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(entries) => !entries.is_empty(),
    }
}

fn clip(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

// --- interpolation ---------------------------------------------------------

/// `read_variables`: the `KEY=value` box, read the way Compose reads a `.env`.
pub fn read_variables(env_text: &str) -> Vec<(String, String)> {
    let mut values: Vec<(String, String)> = Vec::new();
    for raw in env_text.split('\n') {
        let line = snpanel_core::pyunicode::trim(raw.strip_suffix('\r').unwrap_or(raw));
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export ") {
            Some(rest) => rest.trim_start_matches([' ', '\t', '\n', '\r', '\u{b}', '\u{c}']),
            None => line,
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = snpanel_core::pyunicode::trim(key).to_string();
        let mut value = snpanel_core::pyunicode::trim(value).to_string();
        let bytes = value.as_bytes();
        if bytes.len() >= 2
            && bytes[0] == bytes[bytes.len() - 1]
            && (bytes[0] == b'"' || bytes[0] == b'\'')
        {
            value = value[1..value.len() - 1].to_string();
        }
        if env_key_ok(&key) {
            insert(&mut values, key, value);
        }
    }
    values
}

/// Substitute a compose file's variables from the `.env` box.
///
/// A project's compose file is written against the `.env` beside it, so the
/// panel has to resolve the same references or the pasted file quietly means
/// something else here. Anything with no value is collected in *missing*
/// rather than silently becoming an empty string, which is what Compose
/// itself would do.
pub fn interpolate(
    text: &str,
    values: &[(String, String)],
    missing: &mut Vec<(String, String)>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            let ch = text[index..].chars().next().expect("a character");
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        if bytes.get(index + 1) == Some(&b'$') {
            out.push('$');
            index += 2;
            continue;
        }
        match read_reference(&text[index..]) {
            Some((name, operator, argument, used)) => {
                out.push_str(&resolve(&name, operator, argument, values, missing));
                index += used;
            }
            None => {
                // Not a reference the pattern matches, so the dollar is text.
                out.push('$');
                index += 1;
            }
        }
    }
    out
}

/// `${VAR}`, `${VAR:-default}`, `${VAR:?message}` or `$VAR`.
///
/// Returns the name, the operator, its argument, and how many bytes the whole
/// reference took.
fn read_reference(text: &str) -> Option<(String, &'static str, Option<String>, usize)> {
    let rest = text.strip_prefix('$')?;
    if let Some(inside) = rest.strip_prefix('{') {
        let name = read_name(inside);
        if name.is_empty() {
            return None;
        }
        let after = &inside[name.len()..];
        // `(?:(:?[-?])([^}]*))?` — the argument may not carry a `}`.
        let (operator, argument, tail) = if let Some(body) = after.strip_prefix(":-") {
            (":-", Some(body), &after[2..])
        } else if let Some(body) = after.strip_prefix(":?") {
            (":?", Some(body), &after[2..])
        } else if let Some(body) = after.strip_prefix('-') {
            ("-", Some(body), &after[1..])
        } else if let Some(body) = after.strip_prefix('?') {
            ("?", Some(body), &after[1..])
        } else {
            ("", None, after)
        };
        let _ = argument;
        let argument_text: String = tail.chars().take_while(|c| *c != '}').collect();
        let closed = tail[argument_text.len()..].starts_with('}');
        if !closed {
            return None;
        }
        if operator.is_empty() && !argument_text.is_empty() {
            // `${VAR junk}` matches nothing in the pattern.
            return None;
        }
        let used = 2 + name.len() + operator.len() + argument_text.len() + 1;
        let argument = if operator.is_empty() {
            None
        } else {
            Some(argument_text)
        };
        return Some((name, operator, argument, used));
    }
    let name = read_name(rest);
    if name.is_empty() {
        return None;
    }
    let used = 1 + name.len();
    Some((name, "", None, used))
}

/// `[A-Za-z_][A-Za-z0-9_]*` from the start of *text*.
fn read_name(text: &str) -> String {
    let mut out = String::new();
    for (index, ch) in text.char_indices() {
        let ok = if index == 0 {
            ch.is_ascii_alphabetic() || ch == '_'
        } else {
            ch.is_ascii_alphanumeric() || ch == '_'
        };
        if !ok {
            break;
        }
        out.push(ch);
    }
    out
}

fn resolve(
    name: &str,
    operator: &str,
    argument: Option<String>,
    values: &[(String, String)],
    missing: &mut Vec<(String, String)>,
) -> String {
    let known = values
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone());
    if let Some(value) = &known {
        // A value that is there but empty still falls through to the default
        // when the operator carries a colon.
        if !value.is_empty() || !matches!(operator, ":-" | ":?") {
            return value.clone();
        }
    }
    match operator {
        "-" | ":-" => argument.unwrap_or_default(),
        "?" | ":?" => {
            remember(missing, name, &argument.unwrap_or_default());
            String::new()
        }
        _ => {
            remember(missing, name, "");
            String::new()
        }
    }
}

/// `dict.setdefault`: the first note about a name is the one that is kept.
fn remember(missing: &mut Vec<(String, String)>, name: &str, note: &str) {
    if missing.iter().any(|(known, _)| known == name) {
        return;
    }
    missing.push((name.to_string(), note.to_string()));
}

/// Every string in the tree, substituted. Keys are left alone, which is what
/// the Python's comprehension does.
fn interpolate_tree(
    node: &Value,
    values: &[(String, String)],
    missing: &mut Vec<(String, String)>,
) -> Value {
    match node {
        Value::Str(text) => Value::Str(interpolate(text, values, missing)),
        Value::List(items) => Value::List(
            items
                .iter()
                .map(|item| interpolate_tree(item, values, missing))
                .collect(),
        ),
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), interpolate_tree(value, values, missing)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Stop Compose interpolating the file the panel generated.
///
/// Every reference has already been resolved by this point, so a dollar left
/// in a value is part of the value — a password, a shell command — and has to
/// reach the container as one.
fn escape_tree(node: &Value) -> Value {
    match node {
        Value::Str(text) => Value::Str(text.replace('$', "$$")),
        Value::List(items) => Value::List(items.iter().map(escape_tree).collect()),
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), escape_tree(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

// --- one service -----------------------------------------------------------

fn parse_service(
    name: &str,
    raw: &Value,
    declared_volumes: &mut Vec<String>,
    issues: &mut Vec<Issue>,
    enforce_registry: bool,
) -> Option<Service> {
    if !service_name_ok(name) {
        issues.push(Issue::new(
            name,
            "tên service chỉ được dùng chữ thường, số, gạch ngang và gạch dưới",
        ));
        return None;
    }
    let Some(entries) = raw.as_map() else {
        issues.push(Issue::new(name, "service phải là một mapping"));
        return None;
    };

    for (key, _) in entries {
        let key = key.python_str();
        if ALLOWED_SERVICE_KEYS.contains(&key.as_str()) {
            continue;
        }
        match EXPLAINED_SERVICE_KEYS
            .iter()
            .find(|(known, _)| *known == key)
        {
            Some((_, reason)) => issues.push(Issue::new(name, format!("{key}: {reason}"))),
            None => issues.push(Issue::new(name, format!("khoá không được hỗ trợ: {key}"))),
        }
    }

    // `str(raw.get("image", "") or "")` — a falsy value becomes the empty
    // string rather than `False` or `0`.
    let image_value = raw.get("image");
    let image_text = match image_value {
        Some(value) if value.truthy() => value.python_str(),
        _ => String::new(),
    };
    let image = snpanel_core::pyunicode::trim(&image_text).to_string();
    if image.is_empty() {
        issues.push(Issue::new(name, "thiếu image"));
        return None;
    }
    let image = match crate::site_apps::validate_image(&image, enforce_registry) {
        Ok(value) => value,
        Err(why) => {
            issues.push(Issue::new(name, why));
            return None;
        }
    };

    let mut service = Service {
        name: name.to_string(),
        image,
        ..Service::default()
    };
    service.memory_mb = parse_memory(raw.get("mem_limit"));
    service.environment = parse_environment(raw.get("environment"), name, issues);
    service.command = raw.get("command").cloned();
    service.entrypoint = raw.get("entrypoint").cloned();
    service.working_dir = raw.get("working_dir").cloned();
    service.healthcheck = match raw.get("healthcheck") {
        Some(value) if value.as_map().is_some() => Some(value.clone()),
        _ => None,
    };

    service.depends_on = match raw.get("depends_on") {
        Some(Value::Map(pairs)) => pairs.iter().map(|(key, _)| key.python_str()).collect(),
        other => as_list(other).iter().map(Value::python_str).collect(),
    };

    let declared = {
        let ports = as_list(raw.get("ports"));
        if ports.is_empty() {
            as_list(raw.get("expose"))
        } else {
            ports
        }
    };
    for entry in &declared {
        if let Some(port) = parse_port(entry, name, issues) {
            // `if port and port not in ...` — a port is never zero here, the
            // range check saw to that.
            if !service.container_ports.contains(&port) {
                service.container_ports.push(port);
            }
        }
    }
    // Which one the domain reaches is decided later, once the web service is
    // known; until then the first is the sensible guess.
    service.container_port = service.container_ports.first().copied();

    for entry in as_list(raw.get("volumes")) {
        let Some((kind, spec)) = parse_volume(&entry, name, declared_volumes, issues) else {
            continue;
        };
        if kind == "named" {
            service.named_volumes.push(spec);
        } else {
            service.bind_mounts.push(spec);
        }
    }

    if let Some(user) = raw.get("user") {
        if !user.is_null() {
            let text = snpanel_core::pyunicode::trim(&user.python_str()).to_string();
            if matches!(text.as_str(), "root" | "0" | "0:0") || text.starts_with("0:") {
                issues.push(Issue::new(name, "không cho phép chạy service bằng root"));
            } else if !user_value_ok(&text) {
                issues.push(Issue::new(
                    name,
                    format!("giá trị user không hợp lệ: {}", clip(&text, 30)),
                ));
            } else {
                service.user = Some(text);
            }
        }
    }
    Some(service)
}

// --- the whole file --------------------------------------------------------

/// Read a customer's compose file and report what the panel can run.
pub fn analyse(
    source: &str,
    web_service: &str,
    enforce_registry: bool,
    variables: &[(String, String)],
    web_port: Option<i128>,
) -> Plan {
    let mut plan = Plan::default();
    if snpanel_core::pyunicode::trim(source).is_empty() {
        plan.issues
            .push(Issue::new("", "chưa có nội dung docker-compose"));
        return plan;
    }
    if source.len() > MAX_SOURCE_BYTES {
        plan.issues.push(Issue::new("", "file compose quá lớn"));
        return plan;
    }
    let document = match crate::yaml::parse(source) {
        Ok(value) => value,
        Err(why) => {
            // The wording of a parse failure is this reader's own; PyYAML's
            // phrasing is not reproducible without PyYAML.
            plan.issues.push(Issue::new(
                "",
                format!(
                    "{PARSE_FAILED}{}",
                    clip(why.split('\n').next().unwrap_or(""), 120)
                ),
            ));
            return plan;
        }
    };
    if document.as_map().is_none() {
        plan.issues
            .push(Issue::new("", "nội dung phải là một mapping YAML"));
        return plan;
    }

    let mut missing: Vec<(String, String)> = Vec::new();
    let document = interpolate_tree(&document, variables, &mut missing);
    missing.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, note) in &missing {
        if PLACEHOLDERS.contains(&name.as_str()) {
            plan.issues.push(Issue::new(
                "",
                format!(
                    "${{{name}}} chỉ có khi ứng dụng đã gắn với một website; \
hãy trỏ một website vào ứng dụng này trước"
                ),
            ));
        } else {
            plan.issues.push(Issue::new(
                "",
                format!(
                    "thiếu biến {name} — hãy khai {name}=... trong ô .env{}",
                    if note.is_empty() {
                        String::new()
                    } else {
                        format!(" ({note})")
                    }
                ),
            ));
        }
    }
    if !missing.is_empty() {
        return plan;
    }

    for (key, _) in document.as_map().expect("a mapping") {
        let name = key.python_str();
        if ALLOWED_TOP_LEVEL.contains(&name.as_str()) || name.starts_with("x-") {
            continue;
        }
        match EXPLAINED_SERVICE_KEYS
            .iter()
            .find(|(known, _)| *known == name)
        {
            Some((_, reason)) => plan
                .issues
                .push(Issue::new("", format!("{name}: {reason}"))),
            None => plan
                .issues
                .push(Issue::new("", format!("khoá không được hỗ trợ: {name}"))),
        }
    }

    let raw_services = document.get("services").cloned().unwrap_or(Value::Null);
    let service_entries = match raw_services.as_map() {
        Some(entries) if !entries.is_empty() => entries.to_vec(),
        _ => {
            plan.issues
                .push(Issue::new("", "không tìm thấy service nào"));
            return plan;
        }
    };
    if service_entries.len() > MAX_SERVICES {
        plan.issues.push(Issue::new(
            "",
            format!("tối đa {MAX_SERVICES} service cho một ứng dụng"),
        ));
        return plan;
    }

    let mut declared: Vec<String> = Vec::new();
    for (name, raw) in &service_entries {
        if let Some(service) = parse_service(
            &name.python_str(),
            raw,
            &mut declared,
            &mut plan.issues,
            enforce_registry,
        ) {
            plan.services.push(service);
        }
    }

    if let Some(top) = document.get("volumes") {
        if let Some(entries) = top.as_map() {
            for (name, options) in entries {
                let name = name.python_str();
                if !volume_name_ok(&name) {
                    plan.issues.push(Issue::new(
                        "",
                        format!("tên volume không hợp lệ: {}", clip(&name, 40)),
                    ));
                    continue;
                }
                let has_driver_opts = options
                    .get("driver_opts")
                    .map(Value::truthy)
                    .unwrap_or(false);
                if has_driver_opts {
                    // `driver_opts` with `o=bind` is a host mount in disguise.
                    plan.issues.push(Issue::new(
                        "",
                        format!("volume {name}: driver_opts không được phép"),
                    ));
                    continue;
                }
                if !declared.contains(&name) {
                    declared.push(name);
                }
            }
        }
    }
    declared.sort();
    plan.volumes = declared;

    plan.web_service = pick_web_service(&mut plan, web_service);
    if !plan.web_service.is_empty() {
        pick_web_port(&mut plan, web_port);
    }
    plan
}

/// Decide which of a service's ports the domain reaches.
///
/// A service may listen on several — an API and a console, an app and its
/// metrics — and only one can be behind the domain. Picking silently, as this
/// used to, leaves someone staring at the wrong screen; the rest stay
/// reachable between the containers, which is where a metrics or admin port
/// belongs.
fn pick_web_port(plan: &mut Plan, requested: Option<i128>) {
    let web = plan.web_service.clone();
    let index = plan
        .services
        .iter()
        .position(|item| item.name == web)
        .expect("the web service is one of them");
    if let Some(requested) = requested.filter(|port| *port != 0) {
        if !plan.services[index].container_ports.contains(&requested) {
            let declared: Vec<String> = plan.services[index]
                .container_ports
                .iter()
                .map(|port| port.to_string())
                .collect();
            let name = plan.services[index].name.clone();
            plan.issues.push(Issue::new(
                &name,
                format!(
                    "service này không khai cổng {requested}; đang khai: {}",
                    declared.join(", ")
                ),
            ));
            return;
        }
        plan.services[index].container_port = Some(requested);
    }
    let service = &plan.services[index];
    let others: Vec<String> = service
        .container_ports
        .iter()
        .filter(|port| Some(**port) != service.container_port)
        .map(|port| port.to_string())
        .collect();
    if !others.is_empty() {
        let note = format!(
            "{} khai {} cổng; domain vào cổng {}, còn {} chỉ dùng nội bộ giữa các container.",
            service.name,
            service.container_ports.len(),
            service
                .container_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "None".to_string()),
            others.join(", ")
        );
        plan.notes.push(note);
    }
    let mut extra = Vec::new();
    for other in &plan.services {
        if other.name != web && !other.container_ports.is_empty() {
            let ports: Vec<String> = other
                .container_ports
                .iter()
                .map(|port| port.to_string())
                .collect();
            extra.push(format!(
                "{} khai cổng {} — chỉ dùng nội bộ, không ra ngoài.",
                other.name,
                ports.join(", ")
            ));
        }
    }
    plan.notes.extend(extra);
}

fn pick_web_service(plan: &mut Plan, requested: &str) -> String {
    let names: Vec<String> = plan
        .services
        .iter()
        .map(|service| service.name.clone())
        .collect();
    let chosen = if !requested.is_empty() {
        if !names.iter().any(|name| name == requested) {
            plan.issues
                .push(Issue::new("", format!("không có service tên {requested}")));
            return String::new();
        }
        requested.to_string()
    } else {
        let with_ports: Vec<&Service> = plan
            .services
            .iter()
            .filter(|service| service.container_port.is_some())
            .collect();
        if with_ports.len() == 1 {
            with_ports[0].name.clone()
        } else if !with_ports.is_empty() {
            plan.issues.push(Issue::new(
                "",
                "nhiều service khai cổng; hãy chọn service nào phục vụ domain",
            ));
            return String::new();
        } else if !plan.services.is_empty() {
            plan.issues.push(Issue::new(
                "",
                "không service nào khai cổng; hãy chọn service phục vụ domain và cổng của nó",
            ));
            return String::new();
        } else {
            return String::new();
        }
    };
    let service = plan
        .services
        .iter()
        .find(|item| item.name == chosen)
        .expect("one of them");
    if service.container_port.is_none() {
        plan.issues
            .push(Issue::new(&chosen, "service này chưa khai cổng lắng nghe"));
        return String::new();
    }
    chosen
}

// --- the file the server actually runs -------------------------------------

/// Build the compose file the server runs, from the imported one.
///
/// Regenerated on every deploy rather than stored, so a port move or a new
/// memory cap lands without the customer importing their file again.
#[allow(clippy::too_many_arguments)]
pub fn render(
    plan: &Plan,
    project: &str,
    published_port: i64,
    uid: u32,
    gid: u32,
    memory_mb: i64,
    cpus: &str,
) -> Result<String, String> {
    if !plan.ok() {
        return Err("Không thể dựng compose khi còn lỗi chưa xử lý".to_string());
    }

    let mut services: Vec<(Value, Value)> = Vec::new();
    for service in &plan.services {
        let mut entry: Vec<(Value, Value)> = Vec::new();
        put(&mut entry, "image", Value::Str(service.image.clone()));
        if !service.environment.is_empty() {
            put(&mut entry, "environment", environment_value(service));
        }
        if let Some(command) = &service.command {
            put(&mut entry, "command", command.clone());
        }
        if let Some(entrypoint) = &service.entrypoint {
            put(&mut entry, "entrypoint", entrypoint.clone());
        }
        if !service.depends_on.is_empty() {
            put(
                &mut entry,
                "depends_on",
                Value::List(
                    service
                        .depends_on
                        .iter()
                        .map(|name| Value::Str(name.clone()))
                        .collect(),
                ),
            );
        }
        if let Some(working_dir) = service.working_dir.as_ref().filter(|v| v.truthy()) {
            put(&mut entry, "working_dir", working_dir.clone());
        }
        if let Some(healthcheck) = service.healthcheck.as_ref().filter(|v| v.truthy()) {
            put(&mut entry, "healthcheck", healthcheck.clone());
        }

        let mut volumes: Vec<Value> = service
            .named_volumes
            .iter()
            .chain(service.bind_mounts.iter())
            .map(|spec| Value::Str(spec.clone()))
            .collect();
        if !volumes.is_empty() {
            put(&mut entry, "volumes", Value::List(volumes.clone()));
        }

        if service.name == plan.web_service {
            let container_port = service
                .container_port
                .expect("a web service has a port, or the plan is not ok");
            put(
                &mut entry,
                "ports",
                Value::List(vec![Value::Str(format!(
                    "127.0.0.1:{published_port}:{container_port}"
                ))]),
            );
        }

        if let Some(user) = &service.user {
            put(&mut entry, "user", Value::Str(user.clone()));
        } else if service.touches_app_files() {
            // It writes into the customer's own directory, so it has to write
            // as the customer or the files come out owned by someone else.
            put(&mut entry, "user", Value::Str(format!("{uid}:{gid}")));
            if service.environment_get("HOME").is_none() {
                let (home, ephemeral) = home_for(service);
                let mut environment = match take(&mut entry, "environment") {
                    Some(value) => value,
                    None => Value::Map(Vec::new()),
                };
                if let Value::Map(pairs) = &mut environment {
                    pairs.push((Value::Str("HOME".to_string()), Value::Str(home.clone())));
                }
                put(&mut entry, "environment", environment);
                if ephemeral {
                    // A scratch home, so caches and lockfiles the process
                    // expects to write beside its data have somewhere to go.
                    // Nothing that has to survive a restart belongs here —
                    // that is what the customer's mount underneath it is for.
                    let mut tmpfs: Vec<(Value, Value)> = Vec::new();
                    put(&mut tmpfs, "type", Value::Str("tmpfs".to_string()));
                    put(&mut tmpfs, "target", Value::Str(home));
                    let mut options: Vec<(Value, Value)> = Vec::new();
                    put(&mut options, "size", Value::Int(64 * 1024 * 1024));
                    // Compose reads the mode as a number, and its own docs
                    // write 01777 for it; without one the mount lands 0755
                    // root-owned and we are back where we started.
                    put(&mut options, "mode", Value::Int(0o1777));
                    put(&mut tmpfs, "tmpfs", Value::Map(options));
                    volumes.insert(0, Value::Map(tmpfs));
                    put(&mut entry, "volumes", Value::List(volumes.clone()));
                }
            }
        }

        put(
            &mut entry,
            "cap_drop",
            Value::List(vec![Value::Str("ALL".to_string())]),
        );
        let has_user = entry.iter().any(|(key, value)| {
            matches!(key, Value::Str(name) if name == "user") && value.truthy()
        });
        if !has_user {
            // Images that start as root and drop to their own account — every
            // official database does — need these to set up their data
            // directory.
            put(
                &mut entry,
                "cap_add",
                Value::List(
                    PRIVILEGE_DROP_CAPS
                        .iter()
                        .map(|cap| Value::Str((*cap).to_string()))
                        .collect(),
                ),
            );
        }
        put(
            &mut entry,
            "security_opt",
            Value::List(vec![Value::Str("no-new-privileges:true".to_string())]),
        );
        if service.container_port.is_some_and(|port| port < 1024) {
            // Nothing in the container holds CAP_NET_BIND_SERVICE once the
            // capabilities are dropped, and an image told to listen on 80
            // would just fail. The setting is scoped to this container's own
            // network namespace, where a low port means nothing.
            let mut sysctls: Vec<(Value, Value)> = Vec::new();
            put(
                &mut sysctls,
                "net.ipv4.ip_unprivileged_port_start",
                Value::Int(0),
            );
            put(&mut entry, "sysctls", Value::Map(sysctls));
        }
        // The application's cap is a ceiling per service, not a budget shared
        // between them. A file that asks for less keeps its own number, so a
        // database beside a heavy web service does not have to be given the
        // same room just to let the web service have enough.
        let limit = match service.memory_mb {
            Some(asked) if asked != 0 => asked.min(memory_mb),
            _ => memory_mb,
        };
        put(&mut entry, "mem_limit", Value::Str(format!("{limit}m")));
        put(&mut entry, "memswap_limit", Value::Str(format!("{limit}m")));
        let cpus_number = python_float(cpus)
            .ok_or_else(|| format!("could not read the CPU limit `{cpus}` as a number"))?;
        put(&mut entry, "cpus", Value::Float(cpus_number));
        put(&mut entry, "pids_limit", Value::Int(256));
        put(
            &mut entry,
            "restart",
            Value::Str("unless-stopped".to_string()),
        );
        let mut logging: Vec<(Value, Value)> = Vec::new();
        put(&mut logging, "driver", Value::Str("json-file".to_string()));
        let mut options: Vec<(Value, Value)> = Vec::new();
        put(&mut options, "max-size", Value::Str("10m".to_string()));
        put(&mut options, "max-file", Value::Str("3".to_string()));
        put(&mut logging, "options", Value::Map(options));
        put(&mut entry, "logging", Value::Map(logging));

        services.push((Value::Str(service.name.clone()), Value::Map(entry)));
    }

    let mut document: Vec<(Value, Value)> = Vec::new();
    put(&mut document, "name", Value::Str(project.to_string()));
    put(
        &mut document,
        "services",
        escape_tree(&Value::Map(services)),
    );
    if !plan.volumes.is_empty() {
        put(
            &mut document,
            "volumes",
            Value::Map(
                plan.volumes
                    .iter()
                    .map(|name| (Value::Str(name.clone()), Value::Null))
                    .collect(),
            ),
        );
    }

    let header = "# Generated by SNPanel from the imported docker-compose file.\n\
# Edits here are overwritten on the next import.\n";
    Ok(format!(
        "{header}{}",
        crate::yaml::dump(&Value::Map(document))
    ))
}

fn environment_value(service: &Service) -> Value {
    Value::Map(
        service
            .environment
            .iter()
            .map(|(key, value)| (Value::Str(key.clone()), Value::Str(value.clone())))
            .collect(),
    )
}

/// `entry[key] = value`, keeping the place the key first took.
fn put(entries: &mut Vec<(Value, Value)>, key: &str, value: Value) {
    let key = Value::Str(key.to_string());
    if let Some(slot) = entries.iter_mut().find(|(known, _)| *known == key) {
        slot.1 = value;
        return;
    }
    entries.push((key, value));
}

/// `entry.pop(key, None)` — but leaving the slot, because the value is put
/// straight back and has to keep its position.
fn take(entries: &mut [(Value, Value)], key: &str) -> Option<Value> {
    let key = Value::Str(key.to_string());
    entries
        .iter()
        .find(|(known, _)| *known == key)
        .map(|(_, value)| value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/compose.json"
        ))
        .expect("the corpus");
        serde_json::from_str(&text).expect("the corpus parses")
    }

    /// The variables the two endpoints both set up before analysing.
    fn variables_for(env: &str) -> Vec<(String, String)> {
        let mut values = read_variables(env);
        for (name, fallback) in [
            ("SNPANEL_URL", "https://<domain>"),
            ("SNPANEL_DOMAIN", "<domain>"),
        ] {
            if !values.iter().any(|(key, _)| key == name) {
                values.push((name.to_string(), fallback.to_string()));
            }
        }
        values
    }

    fn shape(value: &crate::yaml::Value) -> String {
        use crate::yaml::Value as Y;
        match value {
            Y::Null => "null".to_string(),
            Y::Bool(true) => "bool:true".to_string(),
            Y::Bool(false) => "bool:false".to_string(),
            Y::Int(number) => format!("int:{number}"),
            Y::Float(number) => format!("float:{}", crate::yaml::python_float_str(*number)),
            Y::Str(text) => format!("str:{}", json_string(text)),
            Y::Timestamp(text) => format!("time:{text}"),
            Y::List(items) => {
                let inner: Vec<String> = items.iter().map(shape).collect();
                format!("[{}]", inner.join(","))
            }
            Y::Map(entries) => {
                let inner: Vec<String> = entries
                    .iter()
                    .map(|(key, value)| format!("{}={}", shape(key), shape(value)))
                    .collect();
                format!("{{{}}}", inner.join(","))
            }
        }
    }

    fn json_string(text: &str) -> String {
        let mut out = String::from("\"");
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[test]
    fn a_compose_file_is_analysed_the_way_python_analyses_it() {
        // `analyse` reaches `allowed_registries()` through
        // `validate_image`, so this reads the process environment.
        let _guard = crate::testenv::EnvGuard::cleared(&["SNPANEL_ALLOWED_REGISTRIES"]);
        let corpus = corpus();
        let cases = corpus["analyse"].as_array().expect("the cases");
        assert_eq!(cases.len(), 76, "the corpus changed size");
        let mut failures = Vec::new();
        for case in cases {
            let name = case["name"].as_str().expect("the name");
            let plan = analyse(
                case["source"].as_str().expect("the source"),
                case["web_service"].as_str().expect("the service"),
                case["enforce"].as_bool().expect("the flag"),
                &variables_for(case["env"].as_str().expect("the env")),
                case["web_port"].as_i64().map(i128::from),
            );
            let mut got = plan.as_json();
            let mut want = case["plan"].clone();
            // The wording after `YAML không hợp lệ:` is libyaml's, and this
            // reader has its own. Both sides have to refuse the file, in the
            // same place and with the same prefix; what follows the colon is
            // the one thing here that is not reproducible.
            for side in [&mut got, &mut want] {
                for issue in side["issues"].as_array_mut().expect("the issues") {
                    let message = issue["message"].as_str().unwrap_or("").to_string();
                    if let Some(rest) = message.strip_prefix(PARSE_FAILED) {
                        assert!(!rest.is_empty(), "a parse failure says nothing");
                        issue["message"] = serde_json::Value::String(PARSE_FAILED.to_string());
                    }
                }
            }
            if got != want {
                failures.push(format!("{name}:\n    want {want}\n    got  {got}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The generated file is held to what `docker compose` reads out of it,
    /// not to its layout: this parses both sides and compares the structure.
    #[test]
    fn a_generated_compose_means_what_pythons_means() {
        // `analyse` reaches `allowed_registries()` through
        // `validate_image`, so this reads the process environment.
        let _guard = crate::testenv::EnvGuard::cleared(&["SNPANEL_ALLOWED_REGISTRIES"]);
        let corpus = corpus();
        let mut failures = Vec::new();
        let mut checked = 0;
        for case in corpus["analyse"].as_array().expect("the cases") {
            let Some(want) = case["render_shape"].as_str() else {
                continue;
            };
            checked += 1;
            let name = case["name"].as_str().expect("the name");
            let plan = analyse(
                case["source"].as_str().expect("the source"),
                case["web_service"].as_str().expect("the service"),
                case["enforce"].as_bool().expect("the flag"),
                &variables_for(case["env"].as_str().expect("the env")),
                case["web_port"].as_i64().map(i128::from),
            );
            match render(&plan, "snpanel-alice-app", 21000, 1001, 1002, 512, "1") {
                Ok(text) => match crate::yaml::parse(&text) {
                    Ok(document) => {
                        let got = shape(&document);
                        if got != want {
                            failures.push(format!("{name}:\n    want {want}\n    got  {got}"));
                        }
                    }
                    Err(why) => failures.push(format!("{name}: the generated file: {why}")),
                },
                Err(why) => failures.push(format!("{name}: {why}")),
            }
        }
        assert!(checked >= 20, "only {checked} cases rendered");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// And, for the shapes a compose file actually takes, the layout matches
    /// too — which is what holds the choice between a plain and a quoted
    /// scalar to PyYAML's rather than to my taste.
    #[test]
    fn a_generated_compose_is_written_the_way_python_writes_it() {
        // `analyse` reaches `allowed_registries()` through
        // `validate_image`, so this reads the process environment.
        let _guard = crate::testenv::EnvGuard::cleared(&["SNPANEL_ALLOWED_REGISTRIES"]);
        let corpus = corpus();
        let mut failures = Vec::new();
        let mut checked = 0;
        for case in corpus["analyse"].as_array().expect("the cases") {
            let Some(want) = case["render"].as_str() else {
                continue;
            };
            let name = case["name"].as_str().expect("the name");
            let plan = analyse(
                case["source"].as_str().expect("the source"),
                case["web_service"].as_str().expect("the service"),
                case["enforce"].as_bool().expect("the flag"),
                &variables_for(case["env"].as_str().expect("the env")),
                case["web_port"].as_i64().map(i128::from),
            );
            let Ok(got) = render(&plan, "snpanel-alice-app", 21000, 1001, 1002, 512, "1") else {
                continue;
            };
            checked += 1;
            if got != want {
                failures.push(format!("{name}:\n--- want ---\n{want}--- got ---\n{got}"));
            }
        }
        assert!(checked >= 20, "only {checked} cases rendered");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn the_env_box_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["read_variables"].as_array().expect("the cases") {
            let raw = case["raw"].as_str().expect("the text");
            let got: Vec<(String, String)> = read_variables(raw);
            let want: Vec<(String, String)> = case["values"]
                .as_object()
                .expect("the values")
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().expect("a string").to_string()))
                .collect();
            if got != want {
                failures.push(format!("{raw:?}: want {want:?}, got {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_variable_is_substituted_the_way_python_substitutes_it() {
        let corpus = corpus();
        let cases = corpus["interpolate"].as_array().expect("the cases");
        assert_eq!(cases.len(), 24, "the corpus changed size");
        let mut failures = Vec::new();
        for case in cases {
            let name = case["name"].as_str().expect("the name");
            let text = case["text"].as_str().expect("the text");
            let values: Vec<(String, String)> = case["values"]
                .as_object()
                .expect("the values")
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().expect("a string").to_string()))
                .collect();
            let mut missing = Vec::new();
            let got = interpolate(text, &values, &mut missing);
            let want = case["result"].as_str().expect("the result");
            if got != want {
                failures.push(format!("{name}: want {want:?}, got {got:?}"));
            }
            let mut want_missing: Vec<(String, String)> = case["missing"]
                .as_object()
                .expect("the missing")
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().expect("a string").to_string()))
                .collect();
            want_missing.sort();
            missing.sort();
            if missing != want_missing {
                failures.push(format!(
                    "{name}: missing want {want_missing:?}, got {missing:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_memory_value_is_read_as_mb_the_way_python_reads_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["parse_memory"].as_array().expect("the cases") {
            let raw = case["raw"].as_str();
            let value = raw.map(|text| crate::yaml::Value::Str(text.to_string()));
            let got = parse_memory(value.as_ref());
            let want = case["mb"].as_i64();
            if got != want {
                failures.push(format!("{raw:?}: want {want:?}, got {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_forced_uid_gets_the_home_python_gives_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["home_for"].as_array().expect("the cases") {
            let mounts: Vec<String> = case["mounts"]
                .as_array()
                .expect("the mounts")
                .iter()
                .map(|value| value.as_str().expect("a string").to_string())
                .collect();
            let service = Service {
                name: "s".to_string(),
                image: "x".to_string(),
                bind_mounts: mounts.clone(),
                ..Service::default()
            };
            let (home, ephemeral) = home_for(&service);
            let want_home = case["home"].as_str().expect("the home");
            let want_ephemeral = case["ephemeral"].as_bool().expect("the flag");
            if home != want_home || ephemeral != want_ephemeral {
                failures.push(format!(
                    "{mounts:?}: want ({want_home}, {want_ephemeral}), got ({home}, {ephemeral})"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
