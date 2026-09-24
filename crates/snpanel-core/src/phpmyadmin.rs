//! The three in-place edits to phpMyAdmin's single-sign-on shim.
//!
//! phpMyAdmin is installed from the distribution's package, so SNPanel does
//! not own these two files - it adds a shim to them and then has to keep three
//! values in it following the panel: the address the shim posts its token to,
//! whether the session cookie is marked `secure`, and the absolute URL
//! phpMyAdmin builds its own links from.
//!
//! In the bash all three are `sed -i -E`, and they appear in three places: the
//! installer writes the files from scratch with placeholders, `update.sh`
//! patches the files an earlier install left, and `snpanel panel-url` /
//! `snpanel panel-ssl` patch them when the administrator moves the panel.
//! Only the first of those writes the file, so the other two are exactly these
//! substitutions and nothing else.
//!
//! They live here rather than in either caller because both the helper and the
//! installer need them, and the two crates share only this one.
//!
//! Pure, like the rest of this crate: each function takes the file's text and
//! returns the text it should become. Reading and writing is the caller's.

/// `/api\/databases\/phpmyadmin-sso/s#'[^']+/api/databases/phpmyadmin-sso/'#'<scheme>://127.0.0.1:<port>/api/databases/phpmyadmin-sso/'#`
///
/// Only lines that already mention the endpoint, and only the quoted URL on
/// them - the address the shim posts the single-sign-on token to has to follow
/// the panel's port, or logging into phpMyAdmin stops working the moment the
/// port changes.
///
/// The line this lands on is the shim's
/// `$apiUrl = '<url>' . rawurlencode($token);`.
pub fn rewrite_sso_url(text: &str, scheme: &str, port: &str) -> String {
    const NEEDLE: &str = "/api/databases/phpmyadmin-sso";
    const SUFFIX: &str = "/api/databases/phpmyadmin-sso/";
    rewrite_lines(text, NEEDLE, |line| {
        let (before, _, after) = first_quoted_matching(line, |v| v.ends_with(SUFFIX))?;
        Some(format!(
            "{before}'{scheme}://127.0.0.1:{port}{SUFFIX}'{after}"
        ))
    })
}

/// `s#('secure' => )(true|false)#\1<secure>#`
///
/// Both files carry the cookie parameters, so both get this one. A `secure`
/// cookie is not sent over plain HTTP, so a panel that has lost its
/// certificate and kept `true` here cannot log anyone into phpMyAdmin at all -
/// which is why this follows the certificate rather than being set once.
pub fn rewrite_secure_flag(text: &str, secure: bool) -> String {
    let wanted = if secure { "true" } else { "false" };
    let mut out = text.to_string();
    for from in ["'secure' => true", "'secure' => false"] {
        out = out.replace(from, &format!("'secure' => {wanted}"));
    }
    out
}

/// `/PmaAbsoluteUri/s#'https?://[^']+/phpmyadmin/'#'<scheme>://<host>/phpmyadmin/'#`
///
/// The line this lands on is
/// `$cfg['PmaAbsoluteUri'] = '<url>';`, whose *first* quoted string is
/// `PmaAbsoluteUri` and not the URL. `sed` does not care - it matches the
/// leftmost place the whole pattern fits, which is the second - so neither
/// does this.
pub fn rewrite_absolute_uri(text: &str, scheme: &str, host: &str) -> String {
    rewrite_lines(text, "PmaAbsoluteUri", |line| {
        // `'https?://[^']+/phpmyadmin/'`: a scheme, at least one character,
        // then the path. `'http:///phpmyadmin/'` does not match, because
        // `[^']+` has nothing to take.
        let is_the_url = |v: &str| {
            v.strip_prefix("https://")
                .or_else(|| v.strip_prefix("http://"))
                .and_then(|rest| rest.strip_suffix("/phpmyadmin/"))
                .is_some_and(|host_and_path| !host_and_path.is_empty())
        };
        let (before, _, after) = first_quoted_matching(line, is_the_url)?;
        Some(format!("{before}'{scheme}://{host}/phpmyadmin/'{after}"))
    })
}

/// `sed`'s `/needle/s#...#...#`: the substitution is attempted only on lines
/// that contain `needle`, and a line the substitution does not match is left
/// alone.
///
/// The trailing newline is put back the way it was found. `str::lines` drops
/// it, and a `.php` that lost its last newline would still run - but every
/// later comparison against the file, including this crate's own tests, would
/// see a difference that no substitution made.
fn rewrite_lines(text: &str, needle: &str, f: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match line.contains(needle).then(|| f(line)).flatten() {
            Some(replaced) => out.push_str(&replaced),
            None => out.push_str(line),
        }
    }
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// The leftmost `'...'` on the line whose contents satisfy `want`, as
/// (before, value, after).
///
/// Every quote is tried as an opening quote, not only the first, because that
/// is what `sed` does: it looks for the leftmost position the whole pattern
/// matches, and on `$cfg['PmaAbsoluteUri'] = 'https://h/phpmyadmin/';` that is
/// the fourth quote on the line. Taking only the first pair meant this edit
/// silently did nothing to the file it was written for.
fn first_quoted_matching(line: &str, want: impl Fn(&str) -> bool) -> Option<(&str, &str, &str)> {
    let bytes = line.as_bytes();
    for (open, _) in line.match_indices('\'') {
        let rest = &line[open + 1..];
        let Some(close) = rest.find('\'') else {
            // No closing quote after this one, so there is none after any
            // later one either.
            return None;
        };
        let value = &rest[..close];
        // `[^']+` is one or more.
        if value.is_empty() {
            continue;
        }
        if want(value) {
            let end = open + 1 + close + 1;
            debug_assert!(bytes[open] == b'\'' && bytes[end - 1] == b'\'');
            return Some((&line[..open], value, &line[end..]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line `install.sh` writes into
    /// `/etc/phpmyadmin/conf.d/snpanel-signon.php`, copied from the heredoc.
    const ABSOLUTE_URI_LINE: &str = "$cfg['PmaAbsoluteUri'] = 'http://198.51.100.7/phpmyadmin/';\n";

    /// The line `install.sh` writes into the shim, after its placeholder has
    /// been substituted.
    const SSO_LINE: &str =
        "$apiUrl = 'http://127.0.0.1:2222/api/databases/phpmyadmin-sso/' . rawurlencode($token);\n";

    /// The bug this module was extracted to fix.
    ///
    /// `PmaAbsoluteUri` is itself a quoted string, and it comes first on the
    /// line. Matching only the first pair left the file exactly as it was, so
    /// moving the panel to a hostname kept sending phpMyAdmin's own links to
    /// the old address - with nothing failing to say so.
    #[test]
    fn the_absolute_uri_is_not_the_first_quoted_string_on_its_line() {
        let out = rewrite_absolute_uri(ABSOLUTE_URI_LINE, "https", "panel.example.com");
        assert_eq!(
            out, "$cfg['PmaAbsoluteUri'] = 'https://panel.example.com/phpmyadmin/';\n",
            "the URL is the second quoted string on the line, and it has to be the one that changes"
        );
        assert!(
            out.contains("$cfg['PmaAbsoluteUri']"),
            "the key is quoted too, and it is not the thing being replaced"
        );
    }

    #[test]
    fn the_sso_url_follows_the_panel_port() {
        assert_eq!(
            rewrite_sso_url(SSO_LINE, "https", "8443"),
            SSO_LINE.replace("http://127.0.0.1:2222", "https://127.0.0.1:8443")
        );
    }

    /// The rest of the line has to come back untouched, including a trailing
    /// `. rawurlencode($token);` that contains no quotes and a `;` that does.
    #[test]
    fn only_the_quoted_url_changes() {
        let out = rewrite_sso_url(SSO_LINE, "http", "2222");
        assert_eq!(out, SSO_LINE, "same values in, same file out");
    }

    #[test]
    fn a_line_without_the_needle_is_left_alone() {
        let other = "$cfg['Servers'][$i]['host'] = 'localhost';\n";
        assert_eq!(rewrite_absolute_uri(other, "https", "h"), other);
        assert_eq!(rewrite_sso_url(other, "https", "1"), other);
    }

    /// `/PmaAbsoluteUri/` selects the line, but `'https?://[^']+/phpmyadmin/'`
    /// still has to match on it. A commented-out or differently shaped line is
    /// not rewritten, the same as `sed` leaving it.
    #[test]
    fn the_needle_alone_does_not_make_a_line_match() {
        let no_url = "// PmaAbsoluteUri is set below\n";
        assert_eq!(rewrite_absolute_uri(no_url, "https", "h"), no_url);

        let not_a_url = "$cfg['PmaAbsoluteUri'] = getenv('PMA_URI');\n";
        assert_eq!(rewrite_absolute_uri(not_a_url, "https", "h"), not_a_url);

        // `[^']+` is one or more: there is nothing between the scheme and the
        // path here, so `sed` does not match it either.
        let empty_host = "$cfg['PmaAbsoluteUri'] = 'http:///phpmyadmin/';\n";
        assert_eq!(rewrite_absolute_uri(empty_host, "https", "h"), empty_host);
    }

    #[test]
    fn the_secure_flag_goes_both_ways() {
        let cookie = "    'secure' => false,\n    'httponly' => true,\n";
        assert_eq!(
            rewrite_secure_flag(cookie, true),
            "    'secure' => true,\n    'httponly' => true,\n"
        );
        assert_eq!(
            rewrite_secure_flag(&rewrite_secure_flag(cookie, true), false),
            cookie,
            "and back, so losing a certificate is not a one-way door"
        );
        assert_eq!(
            rewrite_secure_flag(cookie, false),
            cookie,
            "already right, so nothing changes"
        );
    }

    /// `'httponly' => true` is next to it in the same array and must not be
    /// caught: a `httponly` that follows the certificate would be a security
    /// change nobody asked for.
    #[test]
    fn the_secure_flag_does_not_take_its_neighbours() {
        let cookie = "    'secure' => false,\n    'httponly' => true,\n";
        assert!(rewrite_secure_flag(cookie, true).contains("'httponly' => true"));
    }

    /// A file with no trailing newline comes back with no trailing newline.
    #[test]
    fn the_last_newline_is_left_as_it_was_found() {
        let no_eol = ABSOLUTE_URI_LINE.trim_end_matches('\n');
        assert!(!rewrite_absolute_uri(no_eol, "https", "h").ends_with('\n'));
        assert!(rewrite_absolute_uri(ABSOLUTE_URI_LINE, "https", "h").ends_with('\n'));
    }

    /// Running the same rewrite twice is running it once. `update.sh` does
    /// exactly this on every update.
    #[test]
    fn rewriting_twice_is_rewriting_once() {
        let once = rewrite_absolute_uri(ABSOLUTE_URI_LINE, "https", "panel.example.com");
        assert_eq!(
            rewrite_absolute_uri(&once, "https", "panel.example.com"),
            once
        );

        let once = rewrite_sso_url(SSO_LINE, "https", "8443");
        assert_eq!(rewrite_sso_url(&once, "https", "8443"), once);
    }

    /// An unbalanced quote must not panic or hang, and must not eat the line.
    #[test]
    fn an_odd_quote_leaves_the_line_alone() {
        let odd = "$cfg['PmaAbsoluteUri] = 'https://h/phpmyadmin/;\n";
        let out = rewrite_absolute_uri(odd, "https", "x");
        assert_eq!(out, odd);
    }
}

/// Every row of `tests/golden/phpmyadmin-signon.tsv`, which was recorded by
/// running GNU `sed` - the program the bash actually calls - over a corpus of
/// the lines these two files carry.
///
/// This is the check that matters. The unit tests above say what the
/// substitutions are meant to do; this one says they do what `sed` did, which
/// is the only definition of right there is while both still exist.
#[cfg(test)]
mod golden {
    use super::*;

    const SCHEME: &str = "https";
    const PORT: &str = "8443";
    const HOST: &str = "panel.example.com";
    const SECURE: bool = true;

    #[test]
    fn the_three_substitutions_agree_with_sed() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden/phpmyadmin-signon.tsv");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));

        let mut rows = 0;
        for (n, line) in text.lines().enumerate() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                4,
                "line {}: expected 4 tab-separated fields, got {}",
                n + 1,
                fields.len()
            );
            let (input, sso, secure, uri) = (fields[0], fields[1], fields[2], fields[3]);

            assert_eq!(
                rewrite_sso_url(input, SCHEME, PORT),
                sso,
                "line {}: sso-url, on {input:?}",
                n + 1
            );
            assert_eq!(
                rewrite_secure_flag(input, SECURE),
                secure,
                "line {}: secure-flag, on {input:?}",
                n + 1
            );
            assert_eq!(
                rewrite_absolute_uri(input, SCHEME, HOST),
                uri,
                "line {}: absolute-uri, on {input:?}",
                n + 1
            );
            rows += 1;
        }
        // Not a floor. A fixture that lost its rows would otherwise pass here
        // while checking nothing, which is the shape of test this project has
        // had to take back out three times.
        assert_eq!(rows, 12, "{path:?} should have 12 corpus rows");
    }
}
