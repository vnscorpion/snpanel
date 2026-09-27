//! Reading one nginx access-log line the way the panel reads it.
//!
//! Source: `app/services/waf.py` — `ACCESS_LOG_RE`, `_parse_access_log_line`,
//! `_access_verdict`, `_access_reason` and the helpers they call.
//!
//! Every pattern here is hand-written, because this tree carries no regex
//! engine, and every one of them is checked against
//! `tests/golden/access_log.json` — 29 lines and 350 reason cases produced by
//! running the real Python.

use serde_json::{json, Value};

/// Source: `ACCESS_LOG_RE`.
///
/// ```text
/// ^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes>\S+)
/// (?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?(?: (?P<request_time>[0-9.]+))?
/// ```
///
/// **Both trailing groups are optional**, so the same line parses whether or
/// not nginx was configured with `$request_time`, and a line with a referer
/// but no timing still matches. `[^\]]+` for the time means a line whose
/// bracket holds nonsense **parses** — the timestamp comes out empty and the
/// entry sorts to the bottom rather than being dropped.
///
/// `\d{3}` is exactly three digits, so a two- or four-digit status does not
/// match at all.
pub struct AccessLogFields<'a> {
    pub ip: &'a str,
    pub time: &'a str,
    pub request: &'a str,
    pub status: u16,
    pub referer: &'a str,
    pub user_agent: &'a str,
    pub request_time: &'a str,
}

/// `ACCESS_LOG_RE.match(line)` — anchored at the start, unanchored at the end.
pub fn match_access_line(line: &str) -> Option<AccessLogFields<'_>> {
    let bytes = line.as_bytes();
    let mut at = 0usize;

    // `(?P<ip>\S+) ` — greedy, then one literal space.
    let ip_end = non_space_run(line, at);
    if ip_end == at || bytes.get(ip_end) != Some(&b' ') {
        return None;
    }
    let ip = &line[at..ip_end];
    at = ip_end + 1;

    // `\S+ \S+ ` — the identity and the user, both discarded.
    for _ in 0..2 {
        let end = non_space_run(line, at);
        if end == at || bytes.get(end) != Some(&b' ') {
            return None;
        }
        at = end + 1;
    }

    // `\[(?P<time>[^\]]+)\] `
    if bytes.get(at) != Some(&b'[') {
        return None;
    }
    at += 1;
    let time_start = at;
    while at < bytes.len() && bytes[at] != b']' {
        at += 1;
    }
    if at == time_start || bytes.get(at) != Some(&b']') {
        return None;
    }
    let time = &line[time_start..at];
    at += 1;
    if bytes.get(at) != Some(&b' ') {
        return None;
    }
    at += 1;

    // `"(?P<request>[^"]*)" ` — the star means an empty request matches.
    let (request, next) = quoted(line, at)?;
    at = next;
    if bytes.get(at) != Some(&b' ') {
        return None;
    }
    at += 1;

    // `(?P<status>\d{3}) ` — exactly three, and the fourth digit would have
    // to be the space that follows.
    if at + 3 > bytes.len() || !bytes[at..at + 3].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let status: u16 = line[at..at + 3].parse().ok()?;
    at += 3;
    if bytes.get(at) != Some(&b' ') {
        return None;
    }
    at += 1;

    // `(?P<body_bytes>\S+)` — required, and discarded.
    let body_end = non_space_run(line, at);
    if body_end == at {
        return None;
    }
    at = body_end;

    // `(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?`
    let mut referer = "";
    let mut user_agent = "";
    let mut after_pair = at;
    if bytes.get(at) == Some(&b' ') {
        if let Some((first, next)) = quoted(line, at + 1) {
            if bytes.get(next) == Some(&b' ') {
                if let Some((second, end)) = quoted(line, next + 1) {
                    referer = first;
                    user_agent = second;
                    after_pair = end;
                }
            }
        }
    }
    at = after_pair;

    // `(?: (?P<request_time>[0-9.]+))?`
    let mut request_time = "";
    if bytes.get(at) == Some(&b' ') {
        let start = at + 1;
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
            end += 1;
        }
        if end > start {
            request_time = &line[start..end];
        }
    }

    Some(AccessLogFields {
        ip,
        time,
        request,
        status,
        referer,
        user_agent,
        request_time,
    })
}

/// `\S+` from `at`, as a byte index one past the run.
///
/// **`\S` is the negation of Python's `\s`, not of ASCII whitespace.** The
/// vertical tab, the four separator controls at `\x1c`-`\x1f` and the
/// non-breaking space all end the run, and none of them is
/// `is_ascii_whitespace`. A scanner that did not know them would swallow one
/// into the address field and parse a line the Python refuses outright — so
/// the two would disagree about whether a request happened at all.
fn non_space_run(line: &str, at: usize) -> usize {
    let mut end = at;
    for c in line[at..].chars() {
        if snpanel_core::pyunicode::is_space(c) {
            break;
        }
        end += c.len_utf8();
    }
    end
}

/// `"([^"]*)"` at `at`, returning the contents and the index after the
/// closing quote.
fn quoted(line: &str, at: usize) -> Option<(&str, usize)> {
    let bytes = line.as_bytes();
    if bytes.get(at) != Some(&b'"') {
        return None;
    }
    let start = at + 1;
    let mut end = start;
    while end < bytes.len() && bytes[end] != b'"' {
        end += 1;
    }
    if bytes.get(end) != Some(&b'"') {
        return None;
    }
    Some((&line[start..end], end + 1))
}

/// Source: `_split_request`.
///
/// Split on whitespace, **not** matched: a request with four words keeps the
/// first three and drops the rest, and a one-word request becomes the path
/// with no method at all.
pub fn split_request(value: &str) -> (String, String, String) {
    // `str.split()` with no argument, which is Python's whitespace and not
    // Rust's: `split_whitespace` would keep `\x1f` inside a word.
    let parts: Vec<&str> = value
        .split(snpanel_core::pyunicode::is_space)
        .filter(|part| !part.is_empty())
        .collect();
    match parts.len() {
        0 | 1 => (String::new(), value.to_string(), String::new()),
        2 => (parts[0].to_uppercase(), parts[1].to_string(), String::new()),
        _ => (
            parts[0].to_uppercase(),
            parts[1].to_string(),
            parts[2].to_string(),
        ),
    }
}

/// Source: `_access_verdict`.
///
/// `401`, `403`, `429` and `444` are the panel's own refusals; anything from
/// 500 up is the server's fault. Everything else, **including a 404**, is
/// allowed — a missing page is not a block, and colouring it as one would
/// bury the real refusals.
pub fn access_verdict(status: u16) -> &'static str {
    if matches!(status, 401 | 403 | 429 | 444) {
        return "block";
    }
    if status >= 500 {
        return "error";
    }
    "allow"
}

/// One `ACCESS_REASON_RULES` entry: how to recognise a probe, and what to
/// call it.
///
/// The patterns are case-insensitive in the Python (`re.I`), and every one of
/// them ends in "here, or at a `?`, or at the end" — a query string must not
/// hide a probe.
struct ReasonRule {
    matches: fn(&str) -> bool,
    reason: &'static str,
}

/// `(?:$|[?])` — the tail every path rule shares.
fn ends_or_query(rest: &str) -> bool {
    rest.is_empty() || rest.starts_with('?')
}

/// A case-insensitive `find`, returning byte offsets into the **lowered**
/// copy, which has the same length for the ASCII these patterns are made of.
fn find_ci(haystack_lower: &str, needle: &str) -> Option<usize> {
    haystack_lower.find(needle)
}

fn rule_env(path: &str) -> bool {
    // `(?:^|/)\.env(?:\.|$|[?])`
    let lower = path.to_lowercase();
    let mut from = 0;
    while let Some(at) = find_ci(&lower[from..], ".env").map(|i| i + from) {
        let before_ok = at == 0 || lower.as_bytes()[at - 1] == b'/';
        let rest = &lower[at + 4..];
        if before_ok && (rest.starts_with('.') || ends_or_query(rest)) {
            return true;
        }
        from = at + 1;
    }
    false
}

fn rule_git(path: &str) -> bool {
    // `(?:^|/)\.git/`
    let lower = path.to_lowercase();
    let mut from = 0;
    while let Some(at) = find_ci(&lower[from..], ".git/").map(|i| i + from) {
        if at == 0 || lower.as_bytes()[at - 1] == b'/' {
            return true;
        }
        from = at + 1;
    }
    false
}

/// A literal that must be followed by the end of the path or a `?`.
fn literal_then_end(path: &str, needle: &str) -> bool {
    let lower = path.to_lowercase();
    let mut from = 0;
    while let Some(at) = find_ci(&lower[from..], needle).map(|i| i + from) {
        if ends_or_query(&lower[at + needle.len()..]) {
            return true;
        }
        from = at + 1;
    }
    false
}

fn rule_composer(path: &str) -> bool {
    literal_then_end(path, "/composer.json") || literal_then_end(path, "/composer.lock")
}

fn rule_wp_config(path: &str) -> bool {
    // `/wp-config\.php(?:\.|$|[?])` — the dot is what catches `.bak`.
    let lower = path.to_lowercase();
    let needle = "/wp-config.php";
    let mut from = 0;
    while let Some(at) = find_ci(&lower[from..], needle).map(|i| i + from) {
        let rest = &lower[at + needle.len()..];
        if rest.starts_with('.') || ends_or_query(rest) {
            return true;
        }
        from = at + 1;
    }
    false
}

fn rule_wp_upload_php(path: &str) -> bool {
    // `/wp-content/(?:uploads|cache|upgrade)/[^?]*\.php(?:$|[?])`
    let lower = path.to_lowercase();
    for dir in [
        "/wp-content/uploads/",
        "/wp-content/cache/",
        "/wp-content/upgrade/",
    ] {
        let mut from = 0;
        while let Some(at) = find_ci(&lower[from..], dir).map(|i| i + from) {
            let rest = &lower[at + dir.len()..];
            // `[^?]*` cannot cross a `?`.
            let scan = rest.split('?').next().unwrap_or("");
            if scan.ends_with(".php") {
                return true;
            }
            from = at + 1;
        }
    }
    false
}

fn rule_wp_installer(path: &str) -> bool {
    literal_then_end(path, "/wp-admin/install.php")
        || literal_then_end(path, "/wp-admin/setup-config.php")
}

fn rule_author_scan(path: &str) -> bool {
    // `[?&]author=[0-9]+(?:&|$)`
    let lower = path.to_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(at) = find_ci(&lower[from..], "author=").map(|i| i + from) {
        let lead_ok = at > 0 && matches!(bytes[at - 1], b'?' | b'&');
        let digits_start = at + "author=".len();
        let mut end = digits_start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if lead_ok && end > digits_start && (end == bytes.len() || bytes[end] == b'&') {
            return true;
        }
        from = at + 1;
    }
    false
}

fn rule_ignition(path: &str) -> bool {
    literal_then_end(path, "/_ignition/execute-solution")
}

fn rule_laravel_runtime(path: &str) -> bool {
    literal_then_end(path, "/artisan") || literal_then_end(path, "/server.php")
}

fn rule_laravel_log(path: &str) -> bool {
    // `/storage/logs/[^?]*\.log(?:$|[?])`
    let lower = path.to_lowercase();
    let dir = "/storage/logs/";
    let mut from = 0;
    while let Some(at) = find_ci(&lower[from..], dir).map(|i| i + from) {
        let rest = &lower[at + dir.len()..];
        let scan = rest.split('?').next().unwrap_or("");
        if scan.ends_with(".log") {
            return true;
        }
        from = at + 1;
    }
    false
}

fn rule_traversal(path: &str) -> bool {
    let lower = path.to_lowercase();
    ["../", "..\\", "%2e%2e%2f", "%252e%252e%252f"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn rule_php_shell(path: &str) -> bool {
    ["/c99.php", "/r57.php", "/shell.php", "/cmd.php", "/wso.php"]
        .iter()
        .any(|needle| literal_then_end(path, needle))
}

/// `ACCESS_REASON_RULES`, in order. **The first match wins**, so the order is
/// part of the answer.
const REASON_RULES: &[ReasonRule] = &[
    ReasonRule {
        matches: rule_env,
        reason: "Block environment file probe",
    },
    ReasonRule {
        matches: rule_git,
        reason: "Block git metadata probe",
    },
    ReasonRule {
        matches: rule_composer,
        reason: "Block Composer metadata probe",
    },
    ReasonRule {
        matches: rule_wp_config,
        reason: "Block WordPress config probe",
    },
    ReasonRule {
        matches: rule_wp_upload_php,
        reason: "Block WordPress upload PHP probe",
    },
    ReasonRule {
        matches: rule_wp_installer,
        reason: "Block WordPress installer probe",
    },
    ReasonRule {
        matches: rule_author_scan,
        reason: "Block WordPress author scan",
    },
    ReasonRule {
        matches: rule_ignition,
        reason: "Block Laravel Ignition RCE probe",
    },
    ReasonRule {
        matches: rule_laravel_runtime,
        reason: "Block Laravel runtime probe",
    },
    ReasonRule {
        matches: rule_laravel_log,
        reason: "Block Laravel log probe",
    },
    ReasonRule {
        matches: rule_traversal,
        reason: "Block path traversal",
    },
    ReasonRule {
        matches: rule_php_shell,
        reason: "Block PHP runtime probe",
    },
];

/// Source: `_access_reason`.
///
/// **The rules are only consulted for a refusal.** An allowed request is
/// "Allowed" whatever it asked for, and a 429 is the rate limit before any
/// pattern is tried — a flood of `.env` probes is reported as the flood it
/// is, not as twelve separate probe findings.
pub fn access_reason(path: &str, status: u16) -> String {
    let verdict = access_verdict(status);
    if verdict == "allow" {
        return "Allowed".to_string();
    }
    if status == 429 {
        return "HTTP flood rate limit".to_string();
    }
    for rule in REASON_RULES {
        if (rule.matches)(path) {
            return rule.reason.to_string();
        }
    }
    if status == 403 {
        return "Blocked by WAF or Nginx".to_string();
    }
    if verdict == "error" {
        return "Upstream/server error".to_string();
    }
    "Blocked".to_string()
}

/// Source: `_duration_ms` — `round(float(value) * 1000)`, floored at zero.
///
/// Python's `round` is **banker's rounding**: `round(0.5)` is `0`, not `1`.
/// A request timed at `0.0005` seconds is therefore `0` milliseconds here and
/// `1` under any implementation that rounds half away from zero.
pub fn duration_ms(value: &str) -> i64 {
    let Ok(seconds) = value.trim().parse::<f64>() else {
        return 0;
    };
    let scaled = seconds * 1000.0;
    if !scaled.is_finite() {
        return 0;
    }
    let rounded = banker_round(scaled);
    if rounded < 0.0 {
        0
    } else {
        rounded as i64
    }
}

/// `round()` as Python does it: halves go to the **even** neighbour.
fn banker_round(value: f64) -> f64 {
    let floor = value.floor();
    let diff = value - floor;
    if (diff - 0.5).abs() < f64::EPSILON {
        if (floor as i64) % 2 == 0 {
            floor
        } else {
            floor + 1.0
        }
    } else {
        value.round()
    }
}

/// Source: `_parse_nginx_time` — `%d/%b/%Y:%H:%M:%S %z`, or nothing.
///
/// Returns the ISO string the payload carries and a sortable key. A time the
/// format does not fit is **not** a parse failure for the line: the entry
/// keeps an empty timestamp and sorts to the bottom.
pub fn parse_nginx_time(value: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_str(value, "%d/%b/%Y:%H:%M:%S %z").ok()
}

/// One parsed line, as the payload carries it.
pub struct AccessEntry {
    /// `datetime.min` when the timestamp did not parse, which is what puts
    /// the entry at the bottom of a descending sort.
    pub sort_time: i64,
    pub item: Value,
}

/// Source: `_parse_access_log_line`.
pub fn parse_access_line(
    domain: &str,
    line: &str,
    sequence: u64,
    country: &(String, String),
) -> Option<AccessEntry> {
    let fields = match_access_line(line)?;
    let (method, path, protocol) = split_request(fields.request);
    let timestamp = parse_nginx_time(fields.time);
    let sort_time = timestamp.map_or(i64::MIN, |t| t.timestamp_micros());
    let digest = snpanel_core::types::access_entry_id(domain, sequence, line);
    let reason = access_reason(&path, fields.status);

    let item = json!({
        "id": digest,
        "domain": domain,
        "verdict": access_verdict(fields.status),
        "timestamp": timestamp.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, false))
            .unwrap_or_default(),
        "duration_ms": duration_ms(fields.request_time),
        "ip": fields.ip,
        "country": country.0,
        "country_code": country.1,
        "method": method,
        "path": path,
        "protocol": protocol,
        "status": fields.status,
        "reason": reason,
        "user_agent": fields.user_agent,
        "referer": fields.referer,
        "raw": line,
    });
    Some(AccessEntry { sort_time, item })
}

/// Source: `_matches_access_filter`.
///
/// The needle is looked for in **every** field joined together, including the
/// raw line — so a search for an IP finds it whether the parser put it in the
/// `ip` field or left it in the text.
pub fn matches_access_filter(item: &Value, verdict: &str, query: &str) -> bool {
    if !verdict.is_empty() && verdict != "all" && item["verdict"].as_str() != Some(verdict) {
        return false;
    }
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let haystack: String = [
        "domain",
        "verdict",
        "method",
        "path",
        "ip",
        "country",
        "country_code",
        "reason",
        "status",
        "user_agent",
        "referer",
        "protocol",
        "raw",
    ]
    .iter()
    .map(|key| match &item[*key] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    })
    .collect::<Vec<_>>()
    .join(" ")
    .to_lowercase();
    haystack.contains(&needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/access_log.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the access-log corpus"))
            .expect("the corpus parses")
    }

    /// Every line the real Python parsed, replayed field by field.
    ///
    /// The cases that matter are the ones a reading of the pattern misses:
    /// a line with `[bad time]` **parses** (the bracket holds `[^\]]+`, not a
    /// date) and comes back with an empty timestamp; a two- or four-digit
    /// status does not parse at all; and both trailing groups are optional,
    /// so the same line parses with a referer and no timing, or with
    /// neither.
    #[test]
    fn an_access_line_is_read_the_way_the_python_reads_it() {
        let corpus = corpus();
        assert_eq!(
            corpus["pattern"].as_str(),
            Some(
                r#"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?(?: (?P<request_time>[0-9.]+))?"#
            ),
            "the Python's pattern changed"
        );
        let lines = corpus["lines"].as_array().expect("the lines");
        assert_eq!(lines.len(), 43, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut parsed = 0usize;
        let mut refused = 0usize;
        for case in lines {
            let line = case["line"].as_str().unwrap_or("");
            let got = parse_access_line("example.com", line, 1, &(String::new(), String::new()));
            if !case["parsed"].as_bool().unwrap_or(false) {
                refused += 1;
                if got.is_some() {
                    failures.push(format!("{line:?}: python refused it, rust parsed it"));
                }
                continue;
            }
            parsed += 1;
            let Some(entry) = got else {
                failures.push(format!("{line:?}: python parsed it, rust refused it"));
                continue;
            };
            let want = &case["item"];
            // `country`, `country_code` and `id` are excluded from the corpus:
            // the first two read a table that is not in the tree, and the
            // third is checked separately.
            for key in [
                "domain",
                "verdict",
                "timestamp",
                "duration_ms",
                "ip",
                "method",
                "path",
                "protocol",
                "status",
                "reason",
                "user_agent",
                "referer",
                "raw",
            ] {
                if entry.item[key] != want[key] {
                    failures.push(format!(
                        "{line:?} /{key}\n  python {}\n  rust   {}",
                        want[key], entry.item[key]
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            lines.len(),
            failures.join("\n")
        );
        // A corpus that parsed nothing would agree with a parser that parses
        // nothing, and one that refused nothing would miss the `\d{3}`.
        assert!(parsed >= 32, "only {parsed} lines parsed");
        assert!(refused >= 11, "only {refused} lines were refused");
    }

    /// Every reason the real Python gave, for every probe at every status.
    ///
    /// Twelve patterns tried **in order**, and only for a refusal: an allowed
    /// request is "Allowed" whatever it asked for, and a 429 is the rate
    /// limit before any pattern is tried.
    #[test]
    fn a_refusal_is_explained_the_way_the_python_explains_it() {
        let corpus = corpus();
        let cases = corpus["reasons"].as_array().expect("the reasons");
        assert_eq!(cases.len(), 399, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut distinct = std::collections::HashSet::new();
        for case in cases {
            let path = case["path"].as_str().unwrap_or("");
            let status = case["status"].as_u64().unwrap_or(0) as u16;
            let want = case["reason"].as_str().unwrap_or("");
            distinct.insert(want.to_string());
            let got = access_reason(path, status);
            if got != want {
                failures.push(format!(
                    "{path:?} @{status}\n  python {want:?}\n  rust   {got:?}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
        // All twelve rules, plus Allowed, the rate limit, the two fallbacks.
        assert!(
            distinct.len() >= 15,
            "only {} distinct reasons",
            distinct.len()
        );

        for case in corpus["verdicts"].as_array().expect("the verdicts") {
            let status = case["status"].as_u64().unwrap_or(0) as u16;
            assert_eq!(
                access_verdict(status),
                case["verdict"].as_str().unwrap_or(""),
                "for {status}"
            );
        }
    }

    /// `round()` sends a half to the **even** neighbour.
    ///
    /// Source: `_duration_ms` — `round(float(value) * 1000)`. Python's
    /// `round` is banker's rounding, so `0.0005` seconds is `0` milliseconds
    /// and not `1`. Every implementation that rounds half away from zero
    /// disagrees with it on exactly the values a timing field produces.
    #[test]
    fn a_duration_rounds_the_way_python_rounds() {
        assert_eq!(duration_ms("0.123"), 123);
        assert_eq!(duration_ms("12.5"), 12500);
        assert_eq!(duration_ms("0"), 0);
        assert_eq!(duration_ms(""), 0);
        assert_eq!(duration_ms("nonsense"), 0);
        // Negative timings cannot happen, and are floored rather than kept.
        assert_eq!(duration_ms("-1"), 0);
        // The halves.
        assert_eq!(duration_ms("0.0005"), 0);
        assert_eq!(duration_ms("0.0015"), 2);
        assert_eq!(duration_ms("0.0025"), 2);
    }

    /// The filter reads the raw line too.
    ///
    /// Source: `_matches_access_filter`, which joins **thirteen** fields
    /// including `raw`. A search for something the parser did not put in a
    /// field of its own still finds the line it came from.
    #[test]
    fn a_search_looks_at_the_raw_line_as_well_as_the_fields() {
        let line = r#"9.9.9.9 - - [22/Sep/2026:03:14:15 +0000] "GET /secret HTTP/1.1" 403 0 "-" "curl/8.0" 0.1"#;
        let entry = parse_access_line("example.com", line, 1, &(String::new(), String::new()))
            .expect("it parses");

        assert!(matches_access_filter(&entry.item, "all", ""));
        assert!(matches_access_filter(&entry.item, "block", ""));
        assert!(!matches_access_filter(&entry.item, "allow", ""));
        assert!(!matches_access_filter(&entry.item, "error", ""));

        // A field.
        assert!(matches_access_filter(&entry.item, "all", "secret"));
        assert!(matches_access_filter(&entry.item, "all", "9.9.9.9"));
        // The status, which is a number in the item and text in the haystack.
        // Note this cannot distinguish the number formatting from `raw`:
        // every line's raw text already carries its own status, and `status`
        // is the only non-string field the haystack joins. The arm exists
        // because the Python joins the same thirteen fields, not because a
        // search depends on it.
        assert!(matches_access_filter(&entry.item, "all", "403"));
        // Case is folded on both sides.
        assert!(matches_access_filter(&entry.item, "all", "CURL"));
        // Something only the raw line carries: the identity field.
        assert!(matches_access_filter(&entry.item, "all", "03:14:15"));
        assert!(!matches_access_filter(&entry.item, "all", "nothinghere"));
        // A blank needle matches everything, after trimming.
        assert!(matches_access_filter(&entry.item, "all", "   "));
        // And a padded one is trimmed rather than searched for as typed.
        // The blank case alone does not show this: the two empty country
        // fields join into a run of three spaces, so `"   "` is found in the
        // untrimmed haystack too.
        assert!(matches_access_filter(&entry.item, "all", "  secret  "));
        assert!(matches_access_filter(&entry.item, "all", "\tsecret\n"));
    }

    /// Two identical lines in one file are two entries.
    #[test]
    fn the_entry_id_separates_two_identical_lines() {
        let line = r#"1.2.3.4 - - [22/Sep/2026:03:14:15 +0000] "GET / HTTP/1.1" 200 0"#;
        let blank = (String::new(), String::new());
        let first = parse_access_line("a.example.com", line, 1, &blank).expect("parses");
        let second = parse_access_line("a.example.com", line, 2, &blank).expect("parses");
        let other_site = parse_access_line("b.example.com", line, 1, &blank).expect("parses");

        assert_ne!(
            first.item["id"], second.item["id"],
            "the sequence is not in it"
        );
        assert_ne!(
            first.item["id"], other_site.item["id"],
            "the domain is not in it"
        );
        assert_eq!(first.item["id"].as_str().map(str::len), Some(16));
        // Stable across calls, or the page's rows would move under the reader.
        let again = parse_access_line("a.example.com", line, 1, &blank).expect("parses");
        assert_eq!(first.item["id"], again.item["id"]);
    }
}
