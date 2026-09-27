//! Two migrations that rewrite files belonging to customers.
//!
//! Source: `migrate_nginx_wordpress_csp_worker_src`,
//! `migrate_site_cron_php_binary`.
//!
//! Both are embedded Python in the shell, and both edit files an operator
//! did not ask them to touch — vhosts and crontabs. That is the right thing
//! to do (the alternative is telling every customer to go and fix their own
//! cron lines) and it is also why every rule here is pinned to a corpus
//! taken from the real expressions rather than read off them: an edit that
//! is *nearly* right silently breaks a site's scheduled work, and nobody
//! looks at a crontab until something has not run for a week.

/// The Content-Security-Policy migration.
///
/// WordPress's block editor loads workers from `blob:` URLs. A policy
/// written before that was known blocks them, and the symptom is an editor
/// that will not open — with the reason only in the browser console.
pub mod csp {
    pub const NEEDLE: &str = "worker-src 'self' blob:;";
    pub const ANCHOR: &str = "frame-src 'self' https: blob:;";
    pub const HEADER: &str = "Content-Security-Policy";

    /// The rewritten file, or the same text when nothing applies.
    ///
    /// Three gates before anything is written, in this order:
    ///
    /// * no `Content-Security-Policy` at all — an unrelated file, left
    ///   alone;
    /// * the directive is already there — a second copy is not harmless,
    ///   since a repeated `worker-src` is a policy the browser may reject
    ///   outright;
    /// * otherwise insert, after the anchor if there is one and before
    ///   `object-src` if not.
    ///
    /// Both insertions replace **every** occurrence, because Python's
    /// `str.replace` does, and a vhost with two server blocks has two
    /// policies that both need it.
    pub fn migrate(text: &str) -> String {
        if !text.contains(HEADER) || text.contains(NEEDLE) {
            return text.to_string();
        }
        if text.contains(ANCHOR) {
            return text.replace(ANCHOR, &format!("{ANCHOR} {NEEDLE}"));
        }
        text.replace("object-src", &format!("{NEEDLE} object-src"))
    }
}

/// Repairing cron lines written before the PHP pinning fix.
///
/// Those lines call a bare `php`, which resolves through
/// `/etc/alternatives` to the newest installed version rather than the one
/// the website runs on — so a site on 8.2 runs its cron under 8.4 and fails
/// on syntax its own code never sees. They also carry shell-quoted
/// redirections like `'>/dev/null'`, which redirect nothing and instead
/// hand the literal text to the program as an argument.
pub mod cron {
    /// `^\d\.\d$` — exactly one digit, a dot, one digit.
    ///
    /// Note what it refuses: `8.10`. When PHP reaches a two-digit minor this
    /// stops matching and the migration stops pinning, which is a migration
    /// that quietly does nothing rather than one that does the wrong thing.
    /// Recorded here so the day it matters somebody finds this comment.
    pub fn version_ok(value: &str) -> bool {
        let b = value.as_bytes();
        b.len() == 3 && b[0].is_ascii_digit() && b[1] == b'.' && b[2].is_ascii_digit()
    }

    /// The domain out of `#\s*snpanel:([a-z0-9.\-]{3,253})\s*$`.
    ///
    /// Anchored at the end of the line: a marker in the middle of a command
    /// is not a marker, which is what stops a line that merely mentions the
    /// panel from being rewritten.
    pub fn marker(line: &str) -> Option<&str> {
        let bytes = line.as_bytes();
        // `search`, so the rightmost `#` that satisfies the whole pattern
        // wins. Scanning from the right finds it first.
        for hash in (0..bytes.len()).rev() {
            if bytes[hash] != b'#' {
                continue;
            }
            let mut at = hash + 1;
            while at < bytes.len() && (bytes[at] as char).is_whitespace() {
                at += 1;
            }
            let Some(rest) = line.get(at..).and_then(|r| r.strip_prefix("snpanel:")) else {
                continue;
            };
            let rest_bytes = rest.as_bytes();
            let mut end = 0;
            while end < rest_bytes.len() && is_marker_byte(rest_bytes[end]) {
                end += 1;
            }
            // Greedy, then the trailing `\s*$` has to hold.
            let mut length = end;
            loop {
                if (3..=253).contains(&length) && rest[length..].chars().all(char::is_whitespace) {
                    return Some(&rest[..length]);
                }
                if length == 0 {
                    break;
                }
                length -= 1;
            }
        }
        None
    }

    fn is_marker_byte(b: u8) -> bool {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
    }

    /// Unquote the shell redirections.
    ///
    /// `\s'((?:\d?>>?|\d?>&\d)[^']*)'` — a whitespace character, then a
    /// quoted run that *begins* like a redirection. Every occurrence, and
    /// the whitespace is replaced by a single space, which is what the
    /// Python's `" " + group(1)` does.
    ///
    /// A quoted string that is not a redirection keeps its quotes: it is an
    /// argument the customer meant to pass.
    pub fn unquote_redirects(line: &str) -> String {
        let bytes = line.as_bytes();
        // Bytes, not chars. A crontab may carry a UTF-8 comment, and
        // rebuilding the line one `byte as char` at a time would turn every
        // multi-byte character into mojibake — a migration that corrupts the
        // file it was asked to repair. Only whole original byte runs and
        // ASCII spaces are ever appended, so the result is valid UTF-8.
        let mut out: Vec<u8> = Vec::with_capacity(line.len());
        let mut at = 0;
        while at < bytes.len() {
            if !bytes[at].is_ascii_whitespace() || at + 1 >= bytes.len() || bytes[at + 1] != b'\'' {
                out.push(bytes[at]);
                at += 1;
                continue;
            }
            let body_start = at + 2;
            let Some(offset) = bytes[body_start..].iter().position(|b| *b == b'\'') else {
                out.push(bytes[at]);
                at += 1;
                continue;
            };
            let body = &bytes[body_start..body_start + offset];
            if redirect_prefix(body) {
                out.push(b' ');
                out.extend_from_slice(body);
                at = body_start + offset + 1;
            } else {
                out.push(bytes[at]);
                at += 1;
            }
        }
        String::from_utf8(out).expect("only whole byte runs and ASCII are appended")
    }

    /// `(?:\d?>>?|\d?>&\d)` at the start of the quoted body.
    fn redirect_prefix(body: &[u8]) -> bool {
        let mut at = 0;
        if at < body.len() && body[at].is_ascii_digit() {
            at += 1;
        }
        if at >= body.len() || body[at] != b'>' {
            return false;
        }
        at += 1;
        // `>&\d` needs the digit; `>` and `>>` do not need anything more.
        if at < body.len() && body[at] == b'&' {
            return at + 1 < body.len() && body[at + 1].is_ascii_digit();
        }
        true
    }

    /// Pin the interpreter.
    ///
    /// `(&&\s+)((?:/usr/bin/)?php(?:\d\.\d)?)(\s)`, replaced **once**. Only
    /// the first interpreter on the line is pinned, which is the shell's
    /// `count=1` — a line that chains two `php` calls keeps the second as it
    /// was.
    pub fn pin_interpreter(line: &str, binary: &str) -> String {
        let bytes = line.as_bytes();
        let mut at = 0;
        while at + 1 < bytes.len() {
            if !(bytes[at] == b'&' && bytes[at + 1] == b'&') {
                at += 1;
                continue;
            }
            let mut after = at + 2;
            let space_start = after;
            while after < bytes.len() && (bytes[after] as char).is_whitespace() {
                after += 1;
            }
            if after == space_start {
                // `\s+` needs at least one.
                at += 1;
                continue;
            }
            let Some(end) = interpreter_end(bytes, after) else {
                at += 1;
                continue;
            };
            // The trailing `(\s)` is part of the match and is kept.
            if end >= bytes.len() || !(bytes[end] as char).is_whitespace() {
                at += 1;
                continue;
            }
            let mut out = String::with_capacity(line.len() + binary.len());
            out.push_str(&line[..after]);
            out.push_str(binary);
            out.push_str(&line[end..]);
            return out;
        }
        line.to_string()
    }

    /// The end of `(?:/usr/bin/)?php(?:\d\.\d)?` starting at `from`, if it
    /// is there.
    fn interpreter_end(bytes: &[u8], from: usize) -> Option<usize> {
        let mut at = from;
        if bytes[at..].starts_with(b"/usr/bin/") {
            at += b"/usr/bin/".len();
        }
        if !bytes[at..].starts_with(b"php") {
            return None;
        }
        at += 3;
        if at + 2 < bytes.len()
            && bytes[at].is_ascii_digit()
            && bytes[at + 1] == b'.'
            && bytes[at + 2].is_ascii_digit()
        {
            at += 3;
        }
        Some(at)
    }

    /// One line's whole rewrite.
    ///
    /// The redirections are unquoted whenever the line carries a marker,
    /// **even when the interpreter cannot be resolved**. The two repairs are
    /// independent, and a site whose PHP version the panel no longer knows
    /// still had its output going to a file named `>/dev/null`.
    pub fn rewrite(line: &str, binary: Option<&str>) -> String {
        if marker(line).is_none() {
            return line.to_string();
        }
        let unquoted = unquote_redirects(line);
        match binary {
            Some(binary) => pin_interpreter(&unquoted, binary),
            None => unquoted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/update_migrations.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the migrations fixture {}: {e}", path.display()));
        serde_json::from_str(&raw).expect("it parses")
    }

    #[test]
    fn the_csp_migration_matches_the_python() {
        let corpus = corpus();
        let cases = corpus["csp"].as_array().expect("an array");
        assert!(cases.len() >= 8);
        let mut changed = 0;
        for case in cases {
            let input = case["input"].as_str().expect("a string");
            let output = case["output"].as_str().expect("a string");
            assert_eq!(csp::migrate(input), output, "{input:?}");
            if input != output {
                changed += 1;
            }
        }
        // The corpus has to exercise the writing path, not only the
        // skipping one.
        assert!(changed >= 4, "only {changed} cases changed anything");
    }

    #[test]
    fn the_cron_migration_matches_the_python() {
        let corpus = corpus();
        let cases = corpus["cron"].as_array().expect("an array");
        assert!(cases.len() >= 15);
        let mut changed = 0;
        for case in cases {
            let input = case["input"].as_str().expect("a string");
            let output = case["output"].as_str().expect("a string");
            let binary = case["binary"].as_str();
            assert_eq!(cron::rewrite(input, binary), output, "{input:?}");
            assert_eq!(
                cron::marker(input),
                case["domain"].as_str(),
                "marker of {input:?}"
            );
            if input != output {
                changed += 1;
            }
        }
        assert!(changed >= 10, "only {changed} cases changed anything");
    }

    #[test]
    fn the_version_check_matches_the_python() {
        let corpus = corpus();
        let cases = corpus["php_version"].as_object().expect("an object");
        assert!(cases.len() >= 8);
        for (value, expected) in cases {
            assert_eq!(
                cron::version_ok(value),
                expected.as_bool().expect("a bool"),
                "{value:?}"
            );
        }
    }

    /// A second `worker-src` is not harmless: a repeated directive is a
    /// policy the browser may reject outright, and the migration runs on
    /// every update.
    #[test]
    fn the_csp_migration_is_idempotent() {
        let once = csp::migrate(
            "add_header Content-Security-Policy \"frame-src 'self' https: blob:;\";\n",
        );
        assert!(once.contains(csp::NEEDLE));
        assert_eq!(csp::migrate(&once), once);
        assert_eq!(once.matches(csp::NEEDLE).count(), 1);
    }

    /// The migration runs on every update, so a line it has already
    /// repaired must come back unchanged.
    #[test]
    fn the_cron_migration_is_idempotent() {
        let line = "*/5 * * * * cd /x && php a.php '>/dev/null' 2>&1 # snpanel:a.com";
        let once = cron::rewrite(line, Some("/usr/bin/php8.4"));
        assert_ne!(once, line);
        assert_eq!(cron::rewrite(&once, Some("/usr/bin/php8.4")), once);
    }

    /// The two repairs are independent. A site whose PHP version the panel
    /// no longer knows still had its output going to a file named
    /// `>/dev/null`.
    #[test]
    fn the_redirection_repair_does_not_depend_on_resolving_the_interpreter() {
        let line = "0 * * * * cd /x && php a.php '>/dev/null' # snpanel:a.com";
        let without = cron::rewrite(line, None);
        assert!(without.contains(" >/dev/null"));
        assert!(without.contains("&& php a.php"), "{without}");
    }

    /// A marker in the middle of a command is not a marker, which is what
    /// stops a line that merely mentions the panel from being rewritten.
    #[test]
    fn only_a_marker_at_the_end_of_the_line_counts() {
        assert_eq!(cron::marker("0 * * * * x # snpanel:a.com"), Some("a.com"));
        assert_eq!(cron::marker("0 * * * * # snpanel:a.com && php a.php"), None);
        assert_eq!(cron::marker("0 * * * * x"), None);
    }

    /// A crontab may carry a UTF-8 comment, and a migration that corrupts
    /// the file it was asked to repair is worse than one that does nothing.
    #[test]
    fn a_line_with_non_ascii_text_comes_back_intact() {
        let line = "0 * * * * x # sao lưu hằng ngày '>/dev/null' # snpanel:a.com";
        let out = cron::unquote_redirects(line);
        assert!(out.contains("sao lưu hằng ngày"), "{out}");
        assert!(out.contains(" >/dev/null"));
        // And a line with nothing to change comes back byte for byte.
        let untouched = "0 * * * * echo 'xin chào' # snpanel:a.com";
        assert_eq!(cron::unquote_redirects(untouched), untouched);
        assert_eq!(cron::rewrite(untouched, None), untouched);
    }

    /// A quoted string that is not a redirection is an argument the
    /// customer meant to pass, and keeps its quotes.
    #[test]
    fn a_quoted_argument_that_is_not_a_redirection_is_left_alone() {
        assert_eq!(
            cron::unquote_redirects("x 'hello world' '>/dev/null'"),
            "x 'hello world' >/dev/null"
        );
        assert_eq!(cron::unquote_redirects("x 'a>b'"), "x 'a>b'");
    }

    /// `php` inside a longer word is not the interpreter — pinning it would
    /// turn `phpunit` into a path that does not exist.
    #[test]
    fn a_longer_word_beginning_with_php_is_not_the_interpreter() {
        let line = "0 * * * * cd /x && phpunit a.php # snpanel:a.com";
        assert_eq!(cron::rewrite(line, Some("/usr/bin/php8.4")), line);
    }

    /// **A limit, recorded rather than fixed.** `^\d\.\d$` refuses `8.10`,
    /// so when PHP reaches a two-digit minor this migration stops pinning.
    /// It then does nothing rather than doing the wrong thing, which is the
    /// safe failure — but it is a failure, and somebody should find this
    /// comment on the day it starts to matter.
    #[test]
    fn a_two_digit_minor_version_is_not_recognised() {
        assert!(cron::version_ok("8.4"));
        assert!(!cron::version_ok("8.10"));
        assert!(!cron::version_ok("10.4"));
    }
}
