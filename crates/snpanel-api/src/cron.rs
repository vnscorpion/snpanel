//! A website's cron jobs.
//!
//! Source: `app.services.cron`.
//!
//! What makes this more than a list of lines is that a cron command is text a
//! customer writes which `/bin/sh` will execute as their Linux account. The
//! validation is therefore an allow-list in three parts, and each part exists
//! because of a way the obvious implementation goes wrong:
//!
//! * the command is **split with the shell's own lexer** and then re-quoted,
//!   so nothing a customer writes can turn into a second command;
//! * the redirection is rebuilt as *syntax* rather than quoted as arguments,
//!   because quoting `>/dev/null 2>&1` turns a redirect into two literal
//!   arguments and every run mails its output into a void;
//! * the PHP binary is pinned to the site's version, because a bare `php`
//!   resolves through `/etc/alternatives` to the newest installed one, and a
//!   site pinned to 8.1 would silently run on 8.4 and die on the first
//!   version-specific extension - after which cron looks dead although the
//!   schedule fired correctly.

use std::path::{Path, PathBuf};

/// Source: the `ValueError`s this module raises, which the router turns into
/// 400s.
#[derive(Debug)]
pub struct CronError(pub String);

impl std::fmt::Display for CronError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn refuse<T>(message: &str) -> Result<T, CronError> {
    Err(CronError(message.to_string()))
}

/// Source: `ALLOWED_COMMAND_PREFIXES`.
const ALLOWED_COMMAND_PREFIXES: &[&[&str]] = &[
    &["wp", "cron", "event", "run", "--due-now"],
    &["wp", "core", "update"],
    &["wp", "plugin", "update", "--all"],
    &["wp", "theme", "update", "--all"],
];

/// Source: `ALLOWED_PHP_OPTIONS`.
const ALLOWED_PHP_OPTIONS: &[&str] = &["-q"];

/// Source: `WP_CLI_PATH`.
///
/// Whether it is *there* is asked once by the caller and passed in, not
/// probed from inside the validator: a check that asks the machine instead
/// of the question is §7's named repeat offender here, and it would make
/// this module's answers depend on whether the test box has WP-CLI.
pub const WP_CLI_PATH: &str = "/usr/local/bin/wp";
/// Source: `PHP_BIN_DIR`.
const PHP_BIN_DIR: &str = "/usr/bin";

/// Source: `CRON_FIELD_RE` - `(?:\*|\d{1,2})(?:[-/,](?:\*|\d{1,2}))*`.
///
/// One term is a star or one or two digits; the field is a term followed by
/// any number of separator-and-term pairs. It is deliberately loose about
/// *ranges*: `70` in the minutes field passes here and cron rejects it. That
/// is the Python's behaviour and the helper is what refuses it.
fn cron_field_ok(field: &str) -> bool {
    fn term(value: &str) -> bool {
        value == "*"
            || (!value.is_empty() && value.len() <= 2 && value.bytes().all(|b| b.is_ascii_digit()))
    }
    let mut rest = field;
    let first_end = rest.find(['-', '/', ',']).unwrap_or(rest.len());
    if !term(&rest[..first_end]) {
        return false;
    }
    rest = &rest[first_end..];
    while !rest.is_empty() {
        // A separator, then a term.
        let separator = rest.as_bytes()[0];
        if separator != b'-' && separator != b'/' && separator != b',' {
            return false;
        }
        rest = &rest[1..];
        let end = rest.find(['-', '/', ',']).unwrap_or(rest.len());
        if !term(&rest[..end]) {
            return false;
        }
        rest = &rest[end..];
    }
    true
}

/// Source: `_validate_schedule`.
pub fn validate_schedule(schedule: &str) -> Result<String, CronError> {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 || !fields.iter().all(|f| cron_field_ok(f)) {
        return refuse("Invalid cron schedule");
    }
    Ok(fields.join(" "))
}

/// Source: `_validate_domain` with `DOMAIN_GREP_RE` -
/// `^[a-z0-9.\-]{3,253}$`.
///
/// Looser than the nginx domain check on purpose: this one is only used to
/// build the `# snpanel:<domain>` marker the listing greps for, and it is
/// applied to a domain the panel already stored.
pub fn validate_domain(domain: &str) -> Result<String, CronError> {
    let value = domain.to_lowercase();
    let length = value.chars().count();
    if !(3..=253).contains(&length)
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return refuse("Invalid domain");
    }
    Ok(value)
}

/// Source: `php_binary`.
pub fn php_binary(php_version: &str) -> String {
    let version = php_version.trim();
    // `PHP_VERSION_RE` is `^\d\.\d$` - exactly one digit each side.
    let ok = version.len() == 3
        && version.as_bytes()[0].is_ascii_digit()
        && version.as_bytes()[1] == b'.'
        && version.as_bytes()[2].is_ascii_digit();
    if !ok {
        return "php".to_string();
    }
    let candidate = PathBuf::from(PHP_BIN_DIR).join(format!("php{version}"));
    if candidate.exists() {
        candidate.to_string_lossy().into_owned()
    } else {
        "php".to_string()
    }
}

/// Source: `_is_php_interpreter` with `PHP_INTERPRETER_RE` -
/// `^php(?:\d\.\d)?$`, matched against the **basename**.
///
/// Listed entries show the resolved binary, so editing and re-submitting one
/// has to keep validating as a PHP command.
fn is_php_interpreter(arg: &str) -> bool {
    let name = Path::new(arg)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name == "php" {
        return true;
    }
    let bytes = name.as_bytes();
    bytes.len() == 6
        && &bytes[..3] == b"php"
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'.'
        && bytes[5].is_ascii_digit()
}

/// Source: `_escape_percent` - `re.sub(r"(?<!\\)%", r"\\%", command)`.
///
/// "crontab turns an unescaped % into a newline fed to the job's stdin", which
/// truncates the command at that point and feeds the rest to it as input.
pub fn escape_percent(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut previous: Option<char> = None;
    for c in command.chars() {
        if c == '%' && previous != Some('\\') {
            out.push('\\');
        }
        out.push(c);
        previous = Some(c);
    }
    out
}

/// Source: `_unescape_percent`.
fn unescape_percent(command: &str) -> String {
    command.replace("\\%", "%")
}

/// Source: `REDIRECT_DUP_RE` - `^\d?>&\d$`, a full match. `2>&1` duplicates a
/// descriptor; it opens nothing.
fn is_redirect_dup(token: &str) -> bool {
    let b = token.as_bytes();
    match b.len() {
        3 => b[0] == b'>' && b[1] == b'&' && b[2].is_ascii_digit(),
        4 => b[0].is_ascii_digit() && b[1] == b'>' && b[2] == b'&' && b[3].is_ascii_digit(),
        _ => false,
    }
}

/// Source: `REDIRECT_OPEN_RE` - `^(\d?>>?)(.*)$`, returning the operator and
/// whatever followed it.
fn redirect_open(token: &str) -> Option<(String, String)> {
    let b = token.as_bytes();
    let mut i = 0;
    if i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i >= b.len() || b[i] != b'>' {
        return None;
    }
    i += 1;
    if i < b.len() && b[i] == b'>' {
        i += 1;
    }
    Some((token[..i].to_string(), token[i..].to_string()))
}

/// Source: `_split_redirection` - everything from the first redirection token
/// onwards is the redirection.
fn split_redirection(args: &[String]) -> (Vec<String>, Vec<String>) {
    for (index, arg) in args.iter().enumerate() {
        if is_redirect_dup(arg) || redirect_open(arg).is_some() {
            return (args[..index].to_vec(), args[index..].to_vec());
        }
    }
    (args.to_vec(), Vec::new())
}

/// Source: `_validate_redirect_target`.
fn validate_redirect_target(
    target: &str,
    document_root: &Path,
    site_root: &Path,
) -> Result<String, CronError> {
    if target.is_empty() || target.contains(['\r', '\n', '\0']) {
        return refuse("Invalid redirection target");
    }
    if target == "/dev/null" {
        return Ok(target.to_string());
    }
    let script = Path::new(target);
    let base = crate::files::resolve(document_root);
    let safe_root = crate::files::resolve(site_root);
    let candidate = crate::files::resolve(&if script.is_absolute() {
        script.to_path_buf()
    } else {
        base.join(script)
    });
    if !candidate.starts_with(&safe_root) {
        return refuse(
            "Cron output can only be redirected to /dev/null or a file inside this website's folder",
        );
    }
    Ok(candidate.to_string_lossy().into_owned())
}

/// Source: `_validate_redirection` - "rebuild the trailing redirection so
/// /bin/sh still sees it as syntax".
///
/// The operator is **not** quoted and the target is. Quoting the whole token
/// the way an argument is quoted turns `>/dev/null 2>&1` into two literal
/// arguments: the redirect is lost and every run mails its output into a void.
fn validate_redirection(
    tokens: &[String],
    document_root: &Path,
    site_root: &Path,
) -> Result<String, CronError> {
    let mut parts: Vec<String> = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if is_redirect_dup(token) {
            parts.push(token.clone());
            index += 1;
            continue;
        }
        let Some((operator, mut target)) = redirect_open(token) else {
            return refuse("Only the >, >>, 2> and 2>&1 redirections are supported");
        };
        if target.is_empty() {
            index += 1;
            if index >= tokens.len() {
                return refuse("Redirection is missing a target file");
            }
            target = tokens[index].clone();
        }
        let resolved = validate_redirect_target(&target, document_root, site_root)?;
        parts.push(operator + &crate::shell::shlex_quote(&resolved));
        index += 1;
    }
    Ok(parts.join(" "))
}

/// Source: `_validate_php_command`.
fn validate_php_command(
    args: &[String],
    document_root: &Path,
    php_bin: &str,
) -> Result<String, CronError> {
    let option_count =
        usize::from(args.len() > 1 && ALLOWED_PHP_OPTIONS.contains(&args[1].as_str()));
    let script_index = 1 + option_count;
    if args.len() <= script_index || args[script_index].starts_with('-') {
        return refuse("PHP cron commands must run a .php file; only the -q option is allowed");
    }

    let script = Path::new(&args[script_index]);
    let suffix = script
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if suffix != "php" {
        return refuse("PHP cron commands must run a .php file");
    }

    let safe_root = crate::files::resolve(document_root);
    let candidate = crate::files::resolve(&if script.is_absolute() {
        script.to_path_buf()
    } else {
        safe_root.join(script)
    });
    if !candidate.starts_with(&safe_root) {
        return refuse("PHP cron scripts must be inside this website's public_html directory");
    }

    let mut resolved: Vec<String> = vec![php_bin.to_string()];
    resolved.extend_from_slice(&args[1..script_index]);
    resolved.push(candidate.to_string_lossy().into_owned());
    resolved.extend_from_slice(&args[script_index + 1..]);
    Ok(resolved
        .iter()
        .map(|a| crate::shell::shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" "))
}

/// Source: `_validate_wp_command`.
///
/// `--allow-root` is stripped and then put back, so a customer cannot smuggle
/// it into the middle of the argument list to change how a prefix matches.
fn validate_wp_command(
    args: &[String],
    php_bin: &str,
    wp_cli_present: bool,
) -> Result<String, CronError> {
    let normalized: Vec<String> = args
        .iter()
        .filter(|a| a.as_str() != "--allow-root")
        .cloned()
        .collect();
    let allowed = ALLOWED_COMMAND_PREFIXES.iter().any(|prefix| {
        normalized.len() >= prefix.len()
            && normalized[..prefix.len()]
                .iter()
                .zip(prefix.iter())
                .all(|(a, b)| a == b)
    });
    if !allowed {
        return refuse(
            "Only safe WP-CLI maintenance commands or PHP scripts inside this website are allowed",
        );
    }

    let mut resolved = normalized;
    resolved.push("--allow-root".to_string());
    if php_bin != "php" && wp_cli_present {
        // "The wp shebang is `#!/usr/bin/env php`, which would pick the system
        // default PHP instead of the version this website runs on."
        let tail: Vec<String> = resolved[1..].to_vec();
        resolved = vec![php_bin.to_string(), WP_CLI_PATH.to_string()];
        resolved.extend(tail);
    }
    Ok(resolved
        .iter()
        .map(|a| crate::shell::shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" "))
}

/// Source: `_validate_command`.
pub fn validate_command(
    command: &str,
    document_root: &Path,
    site_root: &Path,
    php_bin: &str,
    wp_cli_present: bool,
) -> Result<String, CronError> {
    // Unwrapped on purpose. `terminal.split_command` catches this and
    // re-raises it as `Invalid command syntax: {exc}`; `cron` calls
    // `shlex.split` directly, so the lexer's own words are what the customer
    // reads. Two corpus cases turn on the difference.
    let args = crate::shlex::split(command).map_err(|e| CronError(e.to_string()))?;
    if args.is_empty() {
        return refuse("Cron command is required");
    }
    let (args, redirection) = split_redirection(&args);
    if args.is_empty() {
        return refuse("Cron command is required");
    }
    for arg in &args {
        // `SHELL_OPERATOR_RE` - anything opening with a shell operator "would
        // otherwise be quoted into a literal argument and silently do
        // nothing".
        if arg.starts_with([';', '&', '|', '<', '>']) {
            return refuse("Only the >, >>, 2> and 2>&1 redirections are supported");
        }
    }

    let body = if is_php_interpreter(&args[0]) {
        // "Listed WP-CLI entries read back as `<php binary> /usr/local/bin/wp
        // ...`, so drop the interpreter prefix before validating them again."
        let second_is_wp =
            args.len() > 1 && Path::new(&args[1]).file_name().is_some_and(|n| n == "wp");
        if second_is_wp {
            let mut rebuilt = vec!["wp".to_string()];
            rebuilt.extend_from_slice(&args[2..]);
            validate_wp_command(&rebuilt, php_bin, wp_cli_present)?
        } else {
            validate_php_command(&args, document_root, php_bin)?
        }
    } else {
        validate_wp_command(&args, php_bin, wp_cli_present)?
    };
    let suffix = validate_redirection(&redirection, document_root, site_root)?;
    Ok(format!("{body} {suffix}").trim().to_string())
}

/// Source: `cron_user_for_website` - "the account a website's cron jobs run
/// as when the site has no user of its own".
///
/// `www-data` on Ubuntu, `nginx` on EL. A job installed under the wrong name
/// does not run at all.
pub fn cron_user_for_website(linux_user: Option<&str>, root_path: &str, web_user: &str) -> String {
    if let Some(user) = linux_user.filter(|u| !u.is_empty()) {
        return match snpanel_core::types::PanelUsername::parse(user) {
            Ok(name) => name.as_str().to_string(),
            // The Python raises here and the caller does not catch it, so an
            // invalid stored name is a 500 rather than a silent fallback.
            // Returning the web user would install the job under the wrong
            // account, which is the failure this function exists to avoid.
            Err(_) => web_user.to_string(),
        };
    }
    let root = crate::files::resolve(Path::new(root_path));
    let home = crate::files::resolve(Path::new(snpanel_core::types::HOME_ROOT));
    let Ok(relative) = root.strip_prefix(&home) else {
        return web_user.to_string();
    };
    match relative.components().next() {
        Some(first) => {
            let name = first.as_os_str().to_string_lossy().into_owned();
            match snpanel_core::types::PanelUsername::parse(&name) {
                Ok(parsed) => parsed.as_str().to_string(),
                Err(_) => web_user.to_string(),
            }
        }
        None => web_user.to_string(),
    }
}

/// Source: `_parse_cron_line` - what the listing shows for one line.
pub fn parse_cron_line(index: usize, line: &str) -> serde_json::Value {
    // `line.split(maxsplit=5)` - at most five splits, so at most six pieces,
    // and the sixth keeps its internal spacing.
    let mut pieces: Vec<&str> = Vec::new();
    let mut rest = line.trim_start();
    for _ in 0..5 {
        match rest.find(char::is_whitespace) {
            Some(cut) => {
                pieces.push(&rest[..cut]);
                rest = rest[cut..].trim_start();
            }
            None => {
                if !rest.is_empty() {
                    pieces.push(rest);
                    rest = "";
                }
                break;
            }
        }
    }
    let schedule = if pieces.len() >= 5 {
        pieces[..5].join(" ")
    } else {
        String::new()
    };
    let mut command = if pieces.len() >= 5 && !rest.is_empty() {
        rest.to_string()
    } else {
        String::new()
    };

    // `re.sub(r"\s+#\s*snpanel:[^\s]+\s*$", "", command)` - the marker the
    // panel appends, removed from the end only.
    command = strip_marker(&command).trim().to_string();
    if command.starts_with("cd ") {
        if let Some((_, tail)) = command.split_once(" && ") {
            command = tail.trim().to_string();
        }
    }
    command = unescape_percent(&command).replace(" --allow-root", "");
    serde_json::json!({
        "index": index,
        "schedule": schedule,
        "command": command.trim(),
        "line": line,
    })
}

/// `\s+#\s*snpanel:[^\s]+\s*$` removed from the end.
fn strip_marker(command: &str) -> String {
    let trimmed = command.trim_end();
    let Some(hash) = trimmed.rfind('#') else {
        return command.to_string();
    };
    // There has to be whitespace before the `#`, or it is part of a token.
    if hash == 0 || !trimmed[..hash].ends_with(char::is_whitespace) {
        return command.to_string();
    }
    let tail = trimmed[hash + 1..].trim_start();
    if !tail.starts_with("snpanel:") {
        return command.to_string();
    }
    // `[^\s]+` - the marker cannot contain whitespace.
    if tail["snpanel:".len()..].is_empty() || tail.contains(char::is_whitespace) {
        return command.to_string();
    }
    trimmed[..hash].trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/cron_command.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the cron corpus"))
            .expect("the corpus parses")
    }

    /// The tree the corpus was generated over, rebuilt here.
    ///
    /// The path checks resolve against real directories, so they need one.
    fn build_tree(corpus: &serde_json::Value, label: &str) -> PathBuf {
        let site_root = std::env::temp_dir()
            .join(format!("cron-test-{}-{label}", std::process::id()))
            .join("example.com");
        let _ = std::fs::remove_dir_all(site_root.parent().expect("a parent"));
        std::fs::create_dir_all(&site_root).expect("the site root");
        for entry in corpus["tree"].as_array().expect("the tree") {
            let entry = entry.as_str().unwrap_or("");
            let target = site_root.join(entry.trim_end_matches('/'));
            if entry.ends_with('/') {
                std::fs::create_dir_all(&target).expect("a directory");
            } else {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).expect("a parent");
                }
                std::fs::write(&target, "x").expect("a file");
            }
        }
        // `resolve` follows symlinks, and /tmp is one on some systems, so the
        // comparison has to be against the resolved form.
        crate::files::resolve(&site_root)
    }

    /// Every command, and the **whole line** it becomes.
    ///
    /// Not just accept or refuse: the line is installed verbatim and run by
    /// `/bin/sh` as the customer's account, so a port that agreed about which
    /// commands to allow and then re-quoted them differently would install
    /// something else. The recorded paths are rewritten onto this machine's
    /// tree, and WP-CLI's presence is taken from the corpus rather than from
    /// whatever this box happens to have.
    #[test]
    fn a_cron_command_is_rebuilt_the_way_python_rebuilds_it() {
        let corpus = corpus();
        let site_root = build_tree(&corpus, "commands");
        let document_root = site_root.join("public_html");
        let recorded_root = corpus["site_root"].as_str().expect("the recorded root");
        let wp_cli = corpus["wp_cli_present"].as_bool().unwrap_or(false);
        let here = site_root.to_string_lossy().into_owned();
        let localise = |text: &str| text.replace(recorded_root, &here);

        let mut failures: Vec<String> = Vec::new();
        for case in corpus["commands"].as_array().expect("the commands") {
            let command = case["command"].as_str().unwrap_or("");
            for (php_bin, line_key, error_key) in [
                ("/usr/bin/php8.1", "line", "error"),
                ("php", "line_plain_php", "error_plain_php"),
            ] {
                let got = validate_command(command, &document_root, &site_root, php_bin, wp_cli);
                let label = format!("{command:?} php={php_bin}");
                match (got, case.get(line_key).and_then(|v| v.as_str())) {
                    (Ok(have), Some(want)) => {
                        let want = localise(want);
                        if have != want {
                            failures.push(format!("{label}:\n  python {want}\n  rust   {have}"));
                        }
                    }
                    (Ok(have), None) => failures.push(format!(
                        "{label}: python refused with {:?}, rust {have:?}",
                        case[error_key]
                    )),
                    (Err(e), Some(want)) => {
                        failures.push(format!("{label}: python {want:?}, rust refused {e}"))
                    }
                    (Err(e), None) => {
                        let want = case[error_key].as_str().unwrap_or("");
                        if e.to_string() != want {
                            failures.push(format!("{label}: python {want:?}, rust {e:?}"));
                        }
                    }
                }
            }
        }

        let _ = std::fs::remove_dir_all(site_root.parent().expect("a parent"));
        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.into_iter().take(8).collect::<Vec<_>>().join("\n")
        );
    }

    #[test]
    fn a_schedule_is_validated_the_way_python_validates_it() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["schedules"].as_array().expect("the schedules") {
            let input = case["input"].as_str().unwrap_or("");
            match (
                validate_schedule(input),
                case.get("value").and_then(|v| v.as_str()),
            ) {
                (Ok(got), Some(want)) if got == want => {}
                (Ok(got), Some(want)) => {
                    failures.push(format!("{input:?}: python {want:?}, rust {got:?}"))
                }
                (Ok(got), None) => {
                    failures.push(format!("{input:?}: python refused, rust {got:?}"))
                }
                (Err(_), None) => {}
                (Err(e), Some(want)) => {
                    failures.push(format!("{input:?}: python {want:?}, rust refused {e}"))
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// What the listing shows for a line already in the crontab.
    ///
    /// The `cd ... &&` prefix, the `# snpanel:<domain>` marker and the
    /// `--allow-root` flag are all added by the panel when it writes the line,
    /// so all three come back off when it is read - otherwise editing a job
    /// and saving it again would add them a second time.
    #[test]
    fn a_stored_line_is_read_back_the_way_python_reads_it() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["lines"].as_array().expect("the lines") {
            let line = case["line"].as_str().unwrap_or("");
            let got = parse_cron_line(0, line);
            let want = &case["parsed"];
            for key in ["index", "schedule", "command", "line"] {
                if got[key] != want[key] {
                    failures.push(format!(
                        "{line:?}: {key} python {}, rust {}",
                        want[key], got[key]
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// "crontab turns an unescaped % into a newline fed to the job's stdin",
    /// which truncates the command there and feeds the rest to it as input.
    #[test]
    fn a_percent_is_escaped_unless_it_already_was() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["percents"].as_array().expect("the percent cases") {
            let input = case["input"].as_str().unwrap_or("");
            let got = escape_percent(input);
            let want = case["escaped"].as_str().unwrap_or("");
            if got != want {
                failures.push(format!("{input:?}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
