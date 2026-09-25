//! PHP settings sized for the machine the panel is running on.
//!
//! Source: `app/services/php_tune.py`.
//!
//! Almost all of it is arithmetic over one number — how much RAM the box has
//! — and string comparison deciding whether a row is offered as a change. The
//! reason strings are part of the payload the page renders, so they are
//! reproduced byte for byte; `tests/golden/php_tune_plan.json` holds what the
//! real module produced for each of them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use snpanel_core::pyunicode;

/// Mirrors `PHP_FPM_DEFAULT_WORKER_MB` in the bash helper. The pool maths
/// divides the PHP budget by this, so it is also what a sensible
/// `memory_limit` is built from: a limit far above it means the arithmetic
/// protecting the box is fiction.
pub const WORKER_MB: i64 = 128;

/// No amount of arithmetic about small servers pushes `memory_limit` lower.
/// A customer's PHP has to survive a WooCommerce import and a theme demo
/// installer; below this the saving is paid for in support tickets.
pub const MIN_MEMORY_LIMIT_MB: i64 = 1024;

pub const TUNE_FILE_NAME: &str = "95-snpanel-tune.ini";

/// The opcache switch lives in its own file, read after the tuning one:
/// running Auto tune must not quietly turn opcache back on for someone who
/// turned it off on purpose.
pub const OPCACHE_FILE_NAME: &str = "96-snpanel-opcache.ini";

/// JIT arrived in PHP 8.0; writing these on 7.4 would mean nothing.
pub const JIT_MIN_VERSION: [i64; 2] = [8, 0];

/// Extensions that install their own opcode handlers. PHP refuses to run JIT
/// alongside any of them and says so once per worker start. ionCube ships
/// with SNPanel because customers run encrypted commercial scripts, so on
/// most servers this is not a hypothetical.
pub const JIT_BLOCKING_EXTENSIONS: &[&str] = &[
    "ionCube Loader",
    "xdebug",
    "SourceGuardian",
    "snuffleupagus",
    "pcov",
    "newrelic",
];

/// Keys the tuner is allowed to write. The helper enforces the same list;
/// this copy is what the panel offers, so a typo here fails loudly rather
/// than being written and ignored.
pub const TUNABLE_KEYS: &[&str] = &[
    "memory_limit",
    "realpath_cache_size",
    "realpath_cache_ttl",
    "opcache.enable",
    "opcache.enable_cli",
    "opcache.memory_consumption",
    "opcache.interned_strings_buffer",
    "opcache.max_accelerated_files",
    "opcache.revalidate_freq",
    "opcache.validate_timestamps",
    "opcache.save_comments",
    "opcache.jit",
    "opcache.jit_buffer_size",
    "expose_php",
    "zlib.output_compression",
];

const POOL_KEYS: &[&str] = &[
    "pm.max_children",
    "pm.process_idle_timeout",
    "pm.max_requests",
    "request_terminate_timeout",
];

/// Source: `reserved_memory_mb` — RAM kept for everything that is not PHP.
///
/// The same tiers the bash helper uses, so the panel reports the number the
/// pools were actually sized against rather than a second opinion.
pub fn reserved_memory_mb(total_mb: i64) -> i64 {
    let reserve = if total_mb <= 1024 {
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
    reserve.min(total_mb - 128).max(128)
}

/// The numbers that follow from how much RAM the machine has.
pub struct Tier {
    pub memory_limit: i64,
    pub opcache_mb: i64,
    pub interned: i64,
    pub files: i64,
    pub jit_buffer_mb: i64,
}

/// Source: `_tier`.
///
/// opcache is one shared segment per FPM master, not per worker, so it is
/// cheap: the package already ships 128 MB and recommending less would be a
/// downgrade dressed up as tuning.
pub fn tier(total_mb: i64) -> Tier {
    let (memory_limit, opcache_mb, interned, files) = if total_mb <= 1024 {
        (1024, 96, 8, 16229)
    } else if total_mb <= 2048 {
        (1024, 128, 8, 16229)
    } else if total_mb <= 4096 {
        (1024, 192, 16, 32531)
    } else if total_mb <= 8192 {
        (1536, 256, 24, 65407)
    } else {
        (2048, 384, 32, 130987)
    };
    Tier {
        memory_limit: memory_limit.max(MIN_MEMORY_LIMIT_MB),
        opcache_mb,
        interned,
        files,
        // The JIT buffer is shared memory of its own, on top of opcache's.
        jit_buffer_mb: if total_mb <= 2048 {
            32
        } else if total_mb <= 8192 {
            64
        } else {
            128
        },
    }
}

/// Source: `_version_tuple` — `tuple(int(part) for part in v.split("."))`,
/// or `(0,)` when any part is not an integer.
///
/// `int()` is more forgiving than `str::parse`: it strips surrounding
/// whitespace, accepts a leading sign and allows `_` between digits. All
/// three are in the corpus, because all three change what the panel decides
/// about JIT.
pub fn version_tuple(php_version: &str) -> Vec<i64> {
    let mut out = Vec::new();
    for part in php_version.split('.') {
        match python_int(part) {
            Some(value) => out.push(value),
            None => return vec![0],
        }
    }
    out
}

/// `int(text)` for a base-ten string, or nothing.
///
/// Python's `\d` and `int()` accept non-ASCII decimal digits too. This does
/// not, and cannot be reached with them: the only callers read a PHP version
/// off a directory name under `/etc/php` and a value out of an ini file that
/// PHP itself has to be able to parse.
fn python_int(text: &str) -> Option<i64> {
    let text = pyunicode::trim(text);
    let (sign, digits) = match text.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    let mut previous_was_digit = false;
    for c in digits.chars() {
        if c == '_' {
            // A separator has to sit between two digits.
            if !previous_was_digit {
                return None;
            }
            previous_was_digit = false;
            continue;
        }
        let digit = c.to_digit(10)?;
        value = value.checked_mul(10)?.checked_add(i64::from(digit))?;
        previous_was_digit = true;
    }
    if !previous_was_digit {
        return None;
    }
    Some(sign * value)
}

/// Source: `supports_jit` — whether this PHP has JIT at all.
///
/// The comparison is between **tuples**, so a bare `"8"` is `(8,)`, which is
/// less than `(8, 0)`: a version with no minor part does not support JIT.
pub fn supports_jit(php_version: &str) -> bool {
    let got = version_tuple(php_version);
    let want = JIT_MIN_VERSION;
    let mut i = 0usize;
    loop {
        match (got.get(i), want.get(i)) {
            (Some(a), Some(b)) if a == b => i += 1,
            (Some(a), Some(b)) => return a > b,
            // A shorter tuple is less than a longer one it prefixes.
            (None, Some(_)) => return false,
            (Some(_), None) => return true,
            (None, None) => return true,
        }
    }
}

/// What `jit_status` answers: whether JIT exists here, whether it can
/// actually run, and what stops it.
#[derive(Clone, Debug, Default)]
pub struct JitStatus {
    pub supported: bool,
    pub usable: bool,
    pub blocked_by: String,
}

/// Source: `_normalise` — what decides whether a row is shown as a change.
///
/// A difference here is a row the administrator is or is not offered, so
/// every branch is in the corpus. Two are easy to get wrong: an unset value
/// becomes a sentinel that equals nothing (so the panel offers to write it
/// rather than quietly calling it correct), and a **bare number keeps its
/// digits exactly as written** — the branch returns the matched text, not
/// the parsed integer, so `007` stays `007`.
pub fn normalise(value: &str) -> String {
    let text = pyunicode::trim(value).trim_matches('"').to_lowercase();
    if matches!(text.as_str(), "on" | "true" | "yes") {
        return "1".to_string();
    }
    if text.is_empty() || text == "no value" {
        return "\u{0}unset".to_string();
    }
    if matches!(text.as_str(), "off" | "false" | "no") {
        return "0".to_string();
    }
    if let Some((digits, unit)) = size_match(&text) {
        let factor: i64 = match unit {
            Some('k') => 1,
            Some('m') => 1024,
            Some('g') => 1024 * 1024,
            // A bare number is a plain integer setting, not a size.
            _ => return digits.to_string(),
        };
        if let Some(size) = python_int(digits) {
            return format!("{}k", size * factor);
        }
    }
    text
}

/// `re.fullmatch(r"(\d+)\s*([kmg])?", text)` on an already-lowered string.
fn size_match(text: &str) -> Option<(&str, Option<char>)> {
    let bytes = text.as_bytes();
    let mut end = 0usize;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    let digits = &text[..end];
    let rest = pyunicode::trim(&text[end..]);
    match rest.chars().next() {
        None => Some((digits, None)),
        Some(unit @ ('k' | 'm' | 'g')) if rest.chars().count() == 1 => Some((digits, Some(unit))),
        Some(_) => None,
    }
}

/// Source: `_read_ini_values`.
///
/// The last assignment of a key wins, across files as well as within one,
/// and a file that cannot be read is skipped rather than failing the read.
/// Lines are split the way Python splits them — `\x0c` separates two
/// settings, and a reader that missed it would report the second one's text
/// as part of the first one's value.
pub fn read_ini_values(paths: &[PathBuf], keys: &[&str]) -> BTreeMap<String, String> {
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for path in paths {
        let Ok(text) = std::fs::read(path) else {
            continue;
        };
        // `errors="ignore"`, which for our purposes is a lossy decode.
        let text = String::from_utf8_lossy(&text);
        for line in pyunicode::split_lines(&text) {
            let line = pyunicode::trim(line);
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = pyunicode::trim(key);
            if keys.contains(&key) {
                values.insert(
                    key.to_string(),
                    pyunicode::trim(value).trim_matches('"').to_string(),
                );
            }
        }
    }
    values
}

/// The machine figures every recommendation is built from.
#[derive(Clone, Debug)]
pub struct ServerFacts {
    pub cpu_count: i64,
    pub total_memory_mb: i64,
    pub available_memory_mb: i64,
    pub reserved_memory_mb: i64,
    pub php_budget_mb: i64,
    pub pool_count: i64,
    pub worker_mb: i64,
    pub concurrent_requests: i64,
}

impl ServerFacts {
    /// Source: `server_facts` — everything follows from the total.
    pub fn from_total(
        total_memory_mb: i64,
        available_memory_mb: i64,
        cpu_count: i64,
        pool_count: i64,
    ) -> Self {
        let reserved = reserved_memory_mb(total_memory_mb);
        let budget = (total_memory_mb - reserved).max(WORKER_MB);
        Self {
            cpu_count,
            total_memory_mb,
            available_memory_mb,
            reserved_memory_mb: reserved,
            php_budget_mb: budget,
            pool_count,
            worker_mb: WORKER_MB,
            concurrent_requests: (budget / WORKER_MB).max(1),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "cpu_count": self.cpu_count,
            "total_memory_mb": self.total_memory_mb,
            "available_memory_mb": self.available_memory_mb,
            "reserved_memory_mb": self.reserved_memory_mb,
            "php_budget_mb": self.php_budget_mb,
            "pool_count": self.pool_count,
            "worker_mb": self.worker_mb,
            "concurrent_requests": self.concurrent_requests,
        })
    }
}

/// Source: `total_memory_mb` and `available_memory_mb`.
///
/// `MemTotal` missing means the file is not Linux's, and the Python answers
/// 1024 rather than zero — a machine the tuner believes has no memory would
/// be told to reserve all of it.
pub fn meminfo_mb(text: &str, field: &str, fallback: i64, floor: i64) -> i64 {
    for line in pyunicode::split_lines(text) {
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(kb) = rest.split_whitespace().next().and_then(python_int) {
                return (kb / 1024).max(floor);
            }
            // `int(...)` raised, which the Python treats as "no answer at
            // all" rather than as a zero for this field.
            return fallback;
        }
    }
    fallback
}

/// Source: `_tier` and `recommendations` — what to set, and why.
///
/// The reason strings are the product. They are rendered on the page beside
/// each row, and a port that translated or reworded them would change what
/// an administrator reads before deciding.
pub fn recommendations(facts: &ServerFacts, jit: &JitStatus) -> Vec<Value> {
    let t = tier(facts.total_memory_mb);
    let workers = facts.concurrent_requests;
    let total = facts.total_memory_mb;

    let mut rows: Vec<Value> = Vec::new();
    if jit.usable {
        rows.push(json!({
            "key": "opcache.jit",
            "value": "tracing",
            "reason": "Compiles code that runs many times to machine code. A clear gain for heavy computation; WordPress spends most of its time waiting on the database, so it gains little.",
        }));
        rows.push(json!({
            "key": "opcache.jit_buffer_size",
            "value": format!("{}M", t.jit_buffer_mb),
            "reason": format!(
                "Memory for the code JIT generates, on top of opcache's {} MB. 0 turns JIT off.",
                t.opcache_mb
            ),
        }));
    } else if jit.supported {
        // Two sentences rather than a name put into one: the panel shows
        // this in Vietnamese, and "another extension" is words, not a name.
        let reason = if jit.blocked_by.is_empty() {
            "Another extension takes over the opcode handlers, so PHP cannot run JIT. Turned off completely so PHP-FPM stops warning about it at every start.".to_string()
        } else {
            format!(
                "{} takes over the opcode handlers, so PHP cannot run JIT. Turned off completely so PHP-FPM stops warning about it at every start.",
                jit.blocked_by
            )
        };
        rows.push(json!({
            "key": "opcache.jit",
            "value": "disable",
            "reason": reason,
        }));
        rows.push(json!({
            "key": "opcache.jit_buffer_size",
            "value": "0",
            "reason": "PHP 8.4 reserves 64 MB for JIT by default even when JIT cannot run — this gives that memory back.",
        }));
    }

    rows.push(json!({
        "key": "memory_limit",
        "value": format!("{}M", t.memory_limit),
        "reason": format!(
            "The ceiling for each request. {total} MB RAM, {} MB kept for MariaDB/nginx/the panel, {} MB left for PHP; how many requests run at once is capped by pm.max_children (~{workers}), not by this ceiling.",
            facts.reserved_memory_mb, facts.php_budget_mb
        ),
    }));
    rows.push(json!({
        "key": "opcache.enable",
        "value": "1",
        "reason": "Without opcache every request compiles all the source code again.",
    }));
    rows.push(json!({
        "key": "opcache.memory_consumption",
        "value": t.opcache_mb.to_string(),
        "reason": format!(
            "Enough for the compiled code of a WordPress full of plugins ({} MB).",
            t.opcache_mb
        ),
    }));
    rows.push(json!({
        "key": "opcache.interned_strings_buffer",
        "value": t.interned.to_string(),
        "reason": "Repeated strings are shared between the workers instead of copied.",
    }));
    rows.push(json!({
        "key": "opcache.max_accelerated_files",
        "value": t.files.to_string(),
        "reason": "WordPress with plugins often passes 10,000 files; when the slots run out, opcache starts evicting files.",
    }));
    rows.push(json!({
        "key": "opcache.validate_timestamps",
        "value": "1",
        "reason": "Still checks for changed files. Off is slightly faster, but a customer who edits code would see no change.",
    }));
    rows.push(json!({
        "key": "opcache.revalidate_freq",
        "value": "60",
        "reason": "Checks files every 60s instead of on every request.",
    }));
    rows.push(json!({
        "key": "opcache.save_comments",
        "value": "1",
        "reason": "Must stay on: many PHP libraries read annotations in comments.",
    }));
    rows.push(json!({
        "key": "opcache.enable_cli",
        "value": "0",
        "reason": "WP-CLI and cron run once and exit, too soon for the cache to help.",
    }));
    rows.push(json!({
        "key": "realpath_cache_size",
        "value": "4096k",
        "reason": "The default 256k is too small for a WordPress folder tree; fewer stat() calls.",
    }));
    rows.push(json!({
        "key": "realpath_cache_ttl",
        "value": "600",
        "reason": "Keeps resolved paths for 10 minutes.",
    }));
    rows.push(json!({
        "key": "expose_php",
        "value": "Off",
        "reason": "Does not advertise the PHP version in response headers.",
    }));
    rows.push(json!({
        "key": "zlib.output_compression",
        "value": "Off",
        "reason": "Nginx already compresses; compressing twice only costs CPU.",
    }));
    rows
}

/// Source: `render_ini` — the file the helper writes.
pub fn render_ini(facts: &ServerFacts, jit: &JitStatus) -> String {
    let mut out = String::new();
    out.push_str("; Generated by SNPanel from this server's CPU and RAM.\n");
    out.push_str(&format!(
        "; {} MB RAM, {} CPU, {} PHP pool(s), {} MB budget for PHP.\n",
        facts.total_memory_mb, facts.cpu_count, facts.pool_count, facts.php_budget_mb
    ));
    out.push_str("; Values in 99-snpanel.ini are read after this file and still win.\n");
    out.push('\n');
    for row in recommendations(facts, jit) {
        out.push_str(&format!(
            "{} = {}\n",
            row["key"].as_str().unwrap_or(""),
            row["value"].as_str().unwrap_or("")
        ));
    }
    out
}

/// Source: `current_pool_settings` — what is written in each pool file.
///
/// Two rules that look alike and are not: the **first** `[name]` header is
/// the pool's name, and the **last** assignment of a key is its value. A
/// file with two sections therefore reports the first section's name beside
/// the second section's numbers, which is what the Python does and what an
/// administrator reading the page sees.
pub fn pool_settings(dir: &Path) -> Vec<Value> {
    let mut names: Vec<PathBuf> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with("snpanel-") && name.ends_with(".conf") {
            names.push(path);
        }
    }
    names.sort();

    let mut pools = Vec::new();
    for path in names {
        let Ok(raw) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&raw);
        let values = read_ini_values(std::slice::from_ref(&path), POOL_KEYS);
        let name = section_name(&text).unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string()
        });
        let get = |key: &str| values.get(key).cloned().unwrap_or_default();
        pools.push(json!({
            "pool": name,
            "max_children": get("pm.max_children"),
            "idle_timeout": get("pm.process_idle_timeout"),
            "max_requests": get("pm.max_requests"),
            "request_terminate_timeout": get("request_terminate_timeout"),
        }));
    }
    pools
}

/// `re.compile(r"^\(\[^\]]+\)", re.M).search(text)` — the first section
/// header that starts a line.
fn section_name(text: &str) -> Option<String> {
    for line in pyunicode::split_lines(text) {
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        // `[^\]]+` needs at least one character before the bracket.
        let end = rest.find(']')?;
        if end == 0 {
            continue;
        }
        return Some(rest[..end].to_string());
    }
    None
}

/// Source: `plan` — current beside recommended.
///
/// A row that cannot take effect is **not** counted as a change to make:
/// the panel's own PHP configuration page writes `99-snpanel.ini`, which PHP
/// reads after the tuning file, so anything pinned there wins whatever the
/// tuner writes. Showing it as a pending change would promise something the
/// button cannot deliver.
#[allow(clippy::too_many_arguments)]
pub fn plan_payload(
    php_version: &str,
    facts: &ServerFacts,
    live: &BTreeMap<String, String>,
    pinned: &BTreeMap<String, String>,
    jit: &JitStatus,
    pools: Vec<Value>,
) -> Value {
    let mut rows: Vec<Value> = Vec::new();
    let mut changes = 0i64;
    let mut overridden = 0i64;
    for item in recommendations(facts, jit) {
        let key = item["key"].as_str().unwrap_or("");
        let value = item["value"].as_str().unwrap_or("");
        let now = live.get(key).cloned().unwrap_or_default();
        let held = pinned.get(key).cloned().unwrap_or_default();
        let wanted = normalise(value);
        let changed = normalise(&now) != wanted;
        let overridden_value = if !held.is_empty() && normalise(&held) != wanted {
            held
        } else {
            String::new()
        };
        if changed && overridden_value.is_empty() {
            changes += 1;
        }
        if !overridden_value.is_empty() {
            overridden += 1;
        }
        let mut row = item;
        row["current"] = json!(now);
        row["changes"] = json!(changed);
        row["overridden_value"] = json!(overridden_value);
        rows.push(row);
    }

    json!({
        "php_version": php_version,
        "facts": facts.to_json(),
        "settings": rows,
        "pools": pools,
        "changes": changes,
        "overridden": overridden,
        "opcache_enabled": normalise(
            live.get("opcache.enable").map(String::as_str).unwrap_or("")
        ) == "1",
        "jit_supported": jit.supported,
        "jit_usable": jit.usable,
        "jit_blocked_by": jit.blocked_by,
        "tune_file": format!("/etc/php/{php_version}/fpm/conf.d/{TUNE_FILE_NAME}"),
        "overridden_by": format!("/etc/php/{php_version}/fpm/conf.d/99-snpanel.ini"),
    })
}

/// Source: the parse in `_effective_values`.
///
/// `php -i` prints `key => local => master` for a per-directory setting and
/// `key => value` for a plain one; the **local** value is what runs, so it
/// is the one taken. The split is on every `=>`, not the first, which is
/// why a three-arrow line still yields the second field.
pub fn parse_php_info(stdout: &str, keys: &[&str]) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in pyunicode::split_lines(stdout) {
        if !line.contains("=>") {
            continue;
        }
        let parts: Vec<&str> = line.split("=>").map(pyunicode::trim).collect();
        if parts.len() >= 2 && keys.contains(&parts[0]) {
            values.insert(parts[0].to_string(), parts[1].to_string());
        }
    }
    values
}

/// Source: the merge at the end of `current_values`.
///
/// **PHP wins, but only where it answered.** An empty value from `php -i`
/// is not an answer: it would blank out what the files say and the panel
/// would then offer to write a setting that is already there.
pub fn merge_effective(
    from_files: BTreeMap<String, String>,
    from_php: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut values = from_files;
    for (key, value) in from_php {
        if !value.is_empty() {
            values.insert(key, value);
        }
    }
    values
}

/// The PHP snippet `jit_status` runs, built from the blocker list.
pub fn jit_probe_script() -> String {
    let names: Vec<String> = JIT_BLOCKING_EXTENSIONS
        .iter()
        .map(|name| format!("'{name}'"))
        .collect();
    format!(
        "$s = @opcache_get_status(false);\
$loaded = array_map('strtolower', get_loaded_extensions());\
$blockers = array_values(array_filter([{}], fn($n) => in_array(strtolower($n), $loaded, true)));\
echo json_encode(['jit' => (bool)($s['jit']['enabled'] ?? false), 'blockers' => $blockers]);",
        names.join(", ")
    )
}

/// Source: the JSON scan in `jit_status`.
///
/// The **last** line that starts with `{` wins, because PHP may print a
/// startup warning first — which on a box with a blocking extension it
/// reliably does, and that warning is the very thing being asked about.
pub fn parse_jit_output(stdout: &str) -> (bool, Vec<String>) {
    let mut payload: Option<Value> = None;
    for line in pyunicode::split_lines(stdout) {
        let line = pyunicode::trim(line);
        if line.starts_with('{') {
            if let Ok(parsed) = serde_json::from_str::<Value>(line) {
                payload = Some(parsed);
            }
        }
    }
    let Some(payload) = payload else {
        return (false, Vec::new());
    };
    let usable = payload["jit"].as_bool().unwrap_or(false);
    let blockers = payload["blockers"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    (usable, blockers)
}

/// Source: `jit_status`' return value, given the probe's answer.
pub fn jit_status_from(php_version: &str, probe: Option<(bool, Vec<String>)>) -> JitStatus {
    if !supports_jit(php_version) {
        return JitStatus::default();
    }
    let Some((usable, blockers)) = probe else {
        // The binary is missing or the probe timed out. Not "no JIT" and
        // not "JIT works": the answer is that it does not run here, with
        // nothing to name as the reason.
        return JitStatus {
            supported: true,
            usable: false,
            blocked_by: String::new(),
        };
    };
    JitStatus {
        supported: true,
        usable,
        blocked_by: if usable {
            String::new()
        } else {
            blockers.join(", ")
        },
    }
}

/// `/etc/php/<version>/fpm`.
fn fpm_dir(php_version: &str) -> PathBuf {
    Path::new("/etc/php").join(php_version).join("fpm")
}

/// Run one unprivileged `php<version>` with the FPM configuration.
///
/// The environment is replaced rather than extended, exactly as the Python
/// does: a `PHP_INI_SCAN_DIR` inherited from whatever started the panel
/// would make this read a different set of files than FPM does, and the
/// answer would be confidently wrong.
async fn run_php(php_version: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    let ini_dir = fpm_dir(php_version);
    let mut command = tokio::process::Command::new(format!("php{php_version}"));
    command
        .arg("-c")
        .arg(ini_dir.join("php.ini"))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PHP_INI_SCAN_DIR", ini_dir.join("conf.d"))
        .stdin(std::process::Stdio::null());
    let run = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        command.output(),
    );
    let output = run.await.ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Source: `_effective_values` — what PHP resolves the settings to.
///
/// Reading the ini files alone misses everything PHP defaults to without
/// being told, and the panel would report a change where there is none.
pub async fn effective_values(php_version: &str) -> BTreeMap<String, String> {
    match run_php(php_version, &["-i"], 20).await {
        Some(stdout) => parse_php_info(&stdout, TUNABLE_KEYS),
        None => BTreeMap::new(),
    }
}

/// Source: `current_values` — the files, then PHP's own answer over the top.
pub async fn current_values(php_version: &str) -> BTreeMap<String, String> {
    let base = fpm_dir(php_version);
    let mut paths = vec![base.join("php.ini")];
    let conf_d = base.join("conf.d");
    if conf_d.is_dir() {
        let mut extra: Vec<PathBuf> = std::fs::read_dir(&conf_d)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("ini"))
            .collect();
        extra.sort();
        paths.extend(extra);
    }
    let from_files = read_ini_values(&paths, TUNABLE_KEYS);
    merge_effective(from_files, effective_values(php_version).await)
}

/// Source: `pinned_by_php_config` — values PHP reads *after* the tuning
/// file, so anything here wins whatever the tuner writes.
///
/// The panel's own PHP configuration page writes every one of its fields on
/// each save, so `memory_limit` is pinned there the moment an administrator
/// saves that form once. Better to say so on the row than to show a
/// recommendation that cannot take effect.
pub fn pinned_by_php_config(php_version: &str) -> BTreeMap<String, String> {
    let base = fpm_dir(php_version).join("conf.d");
    read_ini_values(
        &[base.join(OPCACHE_FILE_NAME), base.join("99-snpanel.ini")],
        TUNABLE_KEYS,
    )
}

/// Source: `jit_status` — whether JIT would actually switch on here.
///
/// Asked rather than assumed: writing `opcache.jit` on a server where
/// another extension owns the opcode handlers produces a warning on every
/// worker start and changes nothing at all.
pub async fn jit_status(php_version: &str) -> JitStatus {
    if !supports_jit(php_version) {
        return JitStatus::default();
    }
    let script = jit_probe_script();
    let probe = run_php(
        php_version,
        &[
            "-d",
            "opcache.enable_cli=1",
            "-d",
            "opcache.jit=tracing",
            "-d",
            "opcache.jit_buffer_size=16M",
            "-r",
            &script,
        ],
        25,
    )
    .await
    .map(|stdout| parse_jit_output(&stdout));
    jit_status_from(php_version, probe)
}

/// Source: `pool_count` and `_pool_dir` — the managed FPM pools.
pub fn pool_count() -> i64 {
    let mut found = 0i64;
    let Ok(versions) = std::fs::read_dir("/etc/php") else {
        return 1;
    };
    for version in versions.flatten() {
        let dir = version.path().join("fpm").join("pool.d");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with("snpanel-") && name.ends_with(".conf") {
                found += 1;
            }
        }
    }
    found.max(1)
}

/// Source: `server_facts`, reading this machine.
pub fn server_facts() -> ServerFacts {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    ServerFacts::from_total(
        meminfo_mb(&meminfo, "MemTotal:", 1024, 1),
        meminfo_mb(&meminfo, "MemAvailable:", 0, 0),
        cpu_count(),
        pool_count(),
    )
}

/// Source: `os.cpu_count()`, which counts the processors the kernel has
/// online rather than the ones this process is allowed to run on.
///
/// `available_parallelism` answers the second question, and on a
/// cgroup-limited container the two differ — which would change the pool
/// arithmetic the panel reports away from the one the helper used.
pub fn cpu_count() -> i64 {
    // SAFETY: `sysconf` reads a static kernel value and touches no memory.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if online < 1 {
        1
    } else {
        online as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/php_tune_plan.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the tuner corpus"))
            .expect("the corpus parses")
    }

    fn facts_from(value: &Value) -> ServerFacts {
        let n = |key: &str| {
            value[key]
                .as_i64()
                .unwrap_or_else(|| panic!("{key} missing"))
        };
        ServerFacts {
            cpu_count: n("cpu_count"),
            total_memory_mb: n("total_memory_mb"),
            available_memory_mb: n("available_memory_mb"),
            reserved_memory_mb: n("reserved_memory_mb"),
            php_budget_mb: n("php_budget_mb"),
            pool_count: n("pool_count"),
            worker_mb: n("worker_mb"),
            concurrent_requests: n("concurrent_requests"),
        }
    }

    fn jit_from(value: &Value) -> JitStatus {
        JitStatus {
            supported: value["supported"].as_bool().unwrap_or(false),
            usable: value["usable"].as_bool().unwrap_or(false),
            blocked_by: value["blocked_by"].as_str().unwrap_or("").to_string(),
        }
    }

    /// The constants the helper also enforces.
    ///
    /// The allowlist is duplicated in the bash helper on purpose — this copy
    /// is what the panel *offers*, and a key here that the helper refuses
    /// would be written and silently ignored. So a drift between the two
    /// lists is a real fault, and this pins ours to what Python had.
    #[test]
    fn the_constants_are_the_pythons() {
        let corpus = corpus();
        let c = &corpus["constants"];
        assert_eq!(c["worker_mb"].as_i64(), Some(WORKER_MB));
        assert_eq!(c["min_memory_limit_mb"].as_i64(), Some(MIN_MEMORY_LIMIT_MB));
        assert_eq!(c["tune_file_name"].as_str(), Some(TUNE_FILE_NAME));
        assert_eq!(c["opcache_file_name"].as_str(), Some(OPCACHE_FILE_NAME));
        let jit_min: Vec<i64> = c["jit_min_version"]
            .as_array()
            .expect("the version")
            .iter()
            .map(|v| v.as_i64().unwrap_or(0))
            .collect();
        assert_eq!(jit_min, JIT_MIN_VERSION.to_vec());
        let keys: Vec<&str> = c["tunable_keys"]
            .as_array()
            .expect("the keys")
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect();
        assert_eq!(keys, TUNABLE_KEYS.to_vec());
        let blockers: Vec<&str> = c["jit_blocking_extensions"]
            .as_array()
            .expect("the extensions")
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect();
        assert_eq!(blockers, JIT_BLOCKING_EXTENSIONS.to_vec());
        let pool_keys: Vec<&str> = c["pool_keys"]
            .as_array()
            .expect("the pool keys")
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect();
        assert_eq!(pool_keys, POOL_KEYS.to_vec());
    }

    /// How much RAM is kept away from PHP, at every tier boundary.
    ///
    /// Five tiers, each a percentage with a floor, and the whole thing
    /// clamped so that a tiny machine still leaves PHP 128 MB. The
    /// percentages use integer division, and the floors cross the
    /// percentages at points that are not the tier boundaries — 995 MB is
    /// where 45% overtakes the 448 MB floor — so the corpus carries both
    /// sides of each crossing as well as each boundary.
    #[test]
    fn the_reserve_is_the_pythons_at_every_boundary() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        let mut distinct = std::collections::BTreeSet::new();
        for case in corpus["reserved"].as_array().expect("the cases") {
            let total = case["total_mb"].as_i64().unwrap_or(0);
            let want = case["reserved_mb"].as_i64().unwrap_or(0);
            let got = reserved_memory_mb(total);
            distinct.insert(want);
            if got != want {
                failures.push(format!("{total} MB: python {want}, rust {got}"));
            }
            // Whatever the arithmetic says, PHP is never left with nothing
            // and the reserve never exceeds the machine.
            assert!(got >= 128, "{total} MB reserved {got}");
            assert!(got <= total.max(128), "{total} MB reserved {got}");
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(
            distinct.len() >= 15,
            "only {} distinct reserves",
            distinct.len()
        );
        // Both halves of every tier are represented: the percentage, and
        // the floor that overtakes it below the crossing point. A corpus
        // that only sampled one side would agree with a port that dropped
        // the other.
        let floors = [448i64, 640, 896, 1280, 2048];
        for floor in floors {
            assert!(
                distinct.contains(&floor),
                "no case lands on the {floor} MB floor"
            );
        }
        assert!(
            distinct.iter().filter(|r| !floors.contains(r)).count() >= 8,
            "no case is decided by the percentage rather than a floor"
        );
        // And the clamp binds on a machine too small for its own floor.
        assert_eq!(reserved_memory_mb(256), 128);
        assert_eq!(reserved_memory_mb(1), 128);
    }

    /// The five tiers, and the floor that overrides one of them.
    #[test]
    fn the_tiers_are_the_pythons() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["tiers"].as_array().expect("the tiers") {
            let total = case["total_mb"].as_i64().unwrap_or(0);
            let got = tier(total);
            for (name, want, got) in [
                (
                    "memory_limit",
                    case["memory_limit"].as_i64(),
                    Some(got.memory_limit),
                ),
                (
                    "opcache_mb",
                    case["opcache_mb"].as_i64(),
                    Some(got.opcache_mb),
                ),
                ("interned", case["interned"].as_i64(), Some(got.interned)),
                ("files", case["files"].as_i64(), Some(got.files)),
                (
                    "jit_buffer_mb",
                    case["jit_buffer_mb"].as_i64(),
                    Some(got.jit_buffer_mb),
                ),
            ] {
                if want != got {
                    failures.push(format!("{total} MB /{name}: python {want:?}, rust {got:?}"));
                }
            }
            // The floor is not decoration: the smallest tier's own figure is
            // below it, so a port that dropped the `max` would hand a 512 MB
            // box a limit that kills a plugin update.
            assert!(
                tier(total).memory_limit >= MIN_MEMORY_LIMIT_MB,
                "{total} MB fell below the floor"
            );
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// Version comparison, including the shapes that are not versions.
    ///
    /// The comparison is between tuples, so a bare `"8"` is `(8,)` and does
    /// **not** support JIT — it is less than `(8, 0)`. And `int()` is more
    /// forgiving than `parse`: it strips, takes a sign and allows `_`.
    #[test]
    fn a_version_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        let mut supported = 0usize;
        let mut refused = 0usize;
        for case in corpus["versions"].as_array().expect("the versions") {
            let version = case["php_version"].as_str().unwrap_or("");
            let want: Vec<i64> = case["tuple"]
                .as_array()
                .expect("the tuple")
                .iter()
                .map(|v| v.as_i64().unwrap_or(0))
                .collect();
            let got = version_tuple(version);
            if got != want {
                failures.push(format!("{version:?}: python {want:?}, rust {got:?}"));
            }
            let want_jit = case["supports_jit"].as_bool().unwrap_or(false);
            let got_jit = supports_jit(version);
            if got_jit != want_jit {
                failures.push(format!(
                    "{version:?} jit: python {want_jit}, rust {got_jit}"
                ));
            }
            if want_jit {
                supported += 1;
            }
            if want == vec![0] {
                refused += 1;
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(supported >= 6, "only {supported} versions support JIT");
        assert!(refused >= 4, "only {refused} were unreadable");
    }

    /// What counts as the same setting written differently.
    ///
    /// This is what decides whether a row is offered as a change, so a
    /// difference is a change the administrator is or is not shown. Two
    /// branches are easy to lose: an unset value becomes a sentinel that
    /// matches nothing, and a bare number keeps its digits as written.
    #[test]
    fn two_spellings_of_a_setting_compare_the_way_python_compares_them() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        let mut distinct = std::collections::BTreeSet::new();
        for case in corpus["normalise"].as_array().expect("the cases") {
            let value = case["value"].as_str().unwrap_or("");
            let want = case["normalised"].as_str().unwrap_or("");
            let got = normalise(value);
            distinct.insert(want.to_string());
            if got != want {
                failures.push(format!("{value:?}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(
            distinct.len() >= 15,
            "only {} distinct answers",
            distinct.len()
        );
        // The sentinel equals nothing, including itself in the sense that
        // matters: an unset current value is always a change.
        assert_ne!(normalise(""), normalise("1024M"));
        assert_ne!(normalise(""), normalise("0"));
    }

    /// Every recommendation, for six machine sizes and five JIT states.
    #[test]
    fn the_recommendations_are_the_pythons() {
        let corpus = corpus();
        let cases = corpus["recommendations"].as_array().expect("the cases");
        assert_eq!(cases.len(), 34, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut with_jit = 0usize;
        let mut disabled_jit = 0usize;
        let mut no_jit = 0usize;
        for case in cases {
            let facts = facts_from(&case["facts"]);
            let jit = match &case["jit"] {
                Value::Bool(flag) => JitStatus {
                    // `recommendations(jit=bool)` recomputes `supported`
                    // from the version rather than trusting the caller.
                    supported: supports_jit(case["php_version"].as_str().unwrap_or("")),
                    usable: *flag,
                    blocked_by: String::new(),
                },
                other => jit_from(other),
            };
            let want = case["rows"].as_array().expect("the rows");
            let got = recommendations(&facts, &jit);
            if got.len() != want.len() {
                failures.push(format!(
                    "{} MB / {:?}: python {} rows, rust {}",
                    facts.total_memory_mb,
                    case["jit"],
                    want.len(),
                    got.len()
                ));
                continue;
            }
            match (jit.usable, jit.supported) {
                (true, _) => with_jit += 1,
                (false, true) => disabled_jit += 1,
                (false, false) => no_jit += 1,
            }
            for (want_row, got_row) in want.iter().zip(got.iter()) {
                for key in ["key", "value", "reason"] {
                    if want_row[key] != got_row[key] {
                        failures.push(format!(
                            "{} MB /{}\n  python {}\n  rust   {}",
                            facts.total_memory_mb, key, want_row[key], got_row[key]
                        ));
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
        // All three shapes of the JIT block are covered, including the one
        // that writes `disable` rather than leaving PHP 8.4 reserving 64 MB
        // for a JIT that cannot start.
        assert!(with_jit >= 6, "only {with_jit} usable-JIT cases");
        assert!(disabled_jit >= 12, "only {disabled_jit} blocked-JIT cases");
        assert!(no_jit >= 6, "only {no_jit} no-JIT cases");
    }

    /// The generated file, byte for byte.
    #[test]
    fn the_tuning_file_is_the_pythons() {
        let corpus = corpus();
        let cases = corpus["render_ini"].as_array().expect("the files");
        assert_eq!(cases.len(), 9, "the corpus changed size");
        for case in cases {
            let facts = facts_from(&case["facts"]);
            let jit = jit_from(&case["jit"]);
            let want = case["ini"].as_str().unwrap_or("");
            let got = render_ini(&facts, &jit);
            assert_eq!(got, want, "for {} MB", facts.total_memory_mb);
            // The header names the file that still wins, because an
            // administrator who reads the generated file and then wonders
            // why nothing changed has already lost an hour.
            assert!(got.contains("99-snpanel.ini"), "{got}");
        }
    }

    /// Reading an ini file, including the lines that are not lines.
    #[test]
    fn an_ini_file_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let cases = corpus["read_ini"].as_array().expect("the cases");
        assert_eq!(cases.len(), 28, "the corpus changed size");

        let dir = std::env::temp_dir().join(format!("php-tune-ini-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the temp dir");

        let mut failures: Vec<String> = Vec::new();
        let mut non_empty = 0usize;
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let text = case["text"].as_str().unwrap_or("");
            let path = dir.join("one.ini");
            std::fs::write(&path, text).expect("the fixture");
            let got = read_ini_values(std::slice::from_ref(&path), TUNABLE_KEYS);
            let want = case["values"].as_object().expect("the values");
            if got.len() != want.len()
                || want
                    .iter()
                    .any(|(k, v)| got.get(k).map(String::as_str) != v.as_str())
            {
                failures.push(format!("{label}: python {want:?}, rust {got:?}"));
            }
            if !want.is_empty() {
                non_empty += 1;
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(non_empty >= 15, "only {non_empty} cases read anything");

        // Several files, the later one winning, and one that is not there.
        let a = dir.join("a.ini");
        let b = dir.join("b.ini");
        std::fs::write(&a, "memory_limit = 1M\nexpose_php = On\n").expect("a");
        std::fs::write(&b, "memory_limit = 2M\n").expect("b");
        // The unreadable file is in the middle: at the end, a reader that
        // skipped it and one that stopped at it would agree.
        let got = read_ini_values(&[a, dir.join("missing.ini"), b], TUNABLE_KEYS);
        let want = corpus["read_ini_many"]["values"]
            .as_object()
            .expect("the values");
        assert_eq!(got.len(), want.len());
        for (key, value) in want {
            assert_eq!(got.get(key).map(String::as_str), value.as_str(), "{key}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The pool files, and the two rules that look alike and are not.
    #[test]
    fn the_pool_files_are_read_the_way_python_reads_them() {
        let corpus = corpus();
        let dir = std::env::temp_dir().join(format!("php-tune-pools-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the temp dir");
        for (name, text) in corpus["pools"]["files"].as_object().expect("the files") {
            std::fs::write(dir.join(name), text.as_str().unwrap_or("")).expect("a pool file");
        }

        let got = pool_settings(&dir);
        let want = corpus["pools"]["settings"]
            .as_array()
            .expect("the settings");
        assert_eq!(got.len(), want.len(), "python {want:?}, rust {got:?}");
        for (want_row, got_row) in want.iter().zip(got.iter()) {
            assert_eq!(got_row, want_row);
        }
        // `www.conf` is not ours, so it is not listed however it is sized.
        assert!(
            got.iter().all(|p| p["pool"].as_str() != Some("www")),
            "an unmanaged pool was listed"
        );
        // The first header names the pool; the last assignment sets the
        // value. A file with two sections reports one's name and the
        // other's numbers, which is what an administrator sees.
        let gamma = got
            .iter()
            .find(|p| p["pool"].as_str() == Some("first"))
            .expect("the two-section pool");
        assert_eq!(gamma["max_children"].as_str(), Some("2"));

        // A directory that is not there is no pools, not an error.
        assert!(pool_settings(&dir.join("nonexistent")).is_empty());
        assert_eq!(
            corpus["pools"]["missing_dir"].as_array().map(Vec::len),
            Some(0)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole payload, for six machines with different things written
    /// down already.
    #[test]
    fn the_plan_is_assembled_the_way_python_assembles_it() {
        let corpus = corpus();
        let cases = corpus["plans"].as_array().expect("the plans");
        assert_eq!(cases.len(), 7, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut seen_changes = std::collections::BTreeSet::new();
        let mut seen_overrides = std::collections::BTreeSet::new();
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let facts = facts_from(&case["facts"]);
            let jit = jit_from(&case["jit"]);
            let map = |value: &Value| -> BTreeMap<String, String> {
                value
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let want = &case["plan"];
            let pools = want["pools"].as_array().cloned().unwrap_or_default();
            let got = plan_payload(
                "8.4",
                &facts,
                &map(&case["current"]),
                &map(&case["pinned"]),
                &jit,
                pools,
            );
            seen_changes.insert(want["changes"].as_i64().unwrap_or(-1));
            seen_overrides.insert(want["overridden"].as_i64().unwrap_or(-1));
            if got != *want {
                for key in want.as_object().expect("an object").keys() {
                    if got[key] != want[key] {
                        failures.push(format!(
                            "{label} /{key}\n  python {}\n  rust   {}",
                            want[key], got[key]
                        ));
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
        // A corpus where every plan had the same counters would agree with
        // a port that always returned that number.
        assert!(seen_changes.len() >= 3, "only {seen_changes:?}");
        assert!(seen_overrides.contains(&0) && seen_overrides.iter().any(|n| *n > 0));
    }

    /// `/proc/meminfo`, and what happens when it is not there.
    #[test]
    fn the_memory_figures_fall_back_rather_than_reading_zero() {
        let meminfo = "MemTotal:       16316056 kB\nMemFree: 1 kB\nMemAvailable:   10208284 kB\n";
        assert_eq!(meminfo_mb(meminfo, "MemTotal:", 1024, 1), 15933);
        assert_eq!(meminfo_mb(meminfo, "MemAvailable:", 0, 0), 9969);
        // A machine whose meminfo says nothing is assumed to have 1 GB, not
        // zero: a tuner that believed there was no memory would reserve all
        // of it and hand PHP the 128 MB floor.
        assert_eq!(meminfo_mb("", "MemTotal:", 1024, 1), 1024);
        assert_eq!(meminfo_mb("", "MemAvailable:", 0, 0), 0);
        assert_eq!(
            meminfo_mb("MemTotal: nonsense\n", "MemTotal:", 1024, 1),
            1024
        );
        // Under a megabyte still reports at least one, because the budget
        // arithmetic divides by it.
        assert_eq!(meminfo_mb("MemTotal: 100 kB\n", "MemTotal:", 1024, 1), 1);
        assert_eq!(
            meminfo_mb("MemAvailable: 100 kB\n", "MemAvailable:", 0, 0),
            0
        );
    }
}
