//! Installing WordPress onto a site.
//!
//! Source: `app/services/wordpress.py`.
//!
//! The three values an administrator types — the admin username, the site
//! title and the admin email — go straight to WP-CLI as `--admin_user=`,
//! `--title=` and `--admin_email=`. The checks here are flag-injection
//! defence, not politeness, which is why a value starting with `-` is refused
//! whatever else it contains.

use snpanel_core::pyunicode;

/// What went wrong with one of the values.
///
/// The message is the Python's, word for word: an administrator reads it in a
/// toast beside the field they typed it into.
pub fn invalid(label: &str) -> String {
    format!("Invalid {label}")
}

/// Source: `WP_USER_RE = ^[A-Za-z0-9._@-]{3,60}$`.
fn is_wp_user(value: &str) -> bool {
    let len = value.chars().count();
    (3..=60).contains(&len)
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
}

/// Source: `WP_TITLE_RE = ^[\w\s.,'\-:!()&]{1,150}$`, under `re.UNICODE`.
///
/// `\w` and `\s` are Python's, not Rust's — see [`pyunicode`]. A title in
/// Vietnamese, Japanese or Arabic is accepted; an emoji is not, because `So`
/// is neither a word character nor whitespace.
fn is_wp_title(value: &str) -> bool {
    let len = value.chars().count();
    (1..=150).contains(&len)
        && value.chars().all(|c| {
            pyunicode::is_word(c)
                || pyunicode::is_space(c)
                || matches!(c, '.' | ',' | '\'' | '-' | ':' | '!' | '(' | ')' | '&')
        })
}

/// Source: `EMAIL_RE = ^[^@\s]{1,64}@[^@\s]{3,255}$`.
///
/// Not an address validator and not trying to be: it is the shape WP-CLI is
/// handed. The local part is capped at 64 and the domain at 255 because those
/// are the regex's numbers, not because anything downstream checks them.
///
/// The three-way split and the `@` in `ok` are **redundant with each other**:
/// an address with two at-signs is refused either way, and the regex has the
/// same redundancy, so both are kept. A mutation collapsing the split to two
/// parts cannot fail, which is how the redundancy was noticed.
fn is_wp_email(value: &str) -> bool {
    let ok = |c: char| c != '@' && !pyunicode::is_space(c);
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let local_len = local.chars().count();
    let domain_len = domain.chars().count();
    (1..=64).contains(&local_len)
        && local.chars().all(ok)
        && (3..=255).contains(&domain_len)
        && domain.chars().all(ok)
}

/// Which of the three a value is being checked as.
#[derive(Clone, Copy)]
pub enum WpValue {
    User,
    Title,
    Email,
}

impl WpValue {
    /// The label the Python puts in the message.
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "WordPress admin username",
            Self::Title => "WordPress site title",
            Self::Email => "WordPress admin email",
        }
    }
}

/// Source: `_safe_value`.
///
/// **The value is stripped first**, so a pasted address with a trailing
/// newline is accepted and the newline does not reach WP-CLI. Then the
/// leading-`-` check, then the NUL check, then the pattern — and the order
/// does not matter to the verdict here because all three produce the same
/// message.
pub fn safe_value(value: &str, kind: WpValue) -> Result<String, String> {
    let trimmed: String = value
        .trim_matches(|c: char| pyunicode::is_space(c))
        .to_string();
    let matches_pattern = match kind {
        WpValue::User => is_wp_user(&trimmed),
        WpValue::Title => is_wp_title(&trimmed),
        WpValue::Email => is_wp_email(&trimmed),
    };
    if trimmed.starts_with('-') || trimmed.contains('\0') || !matches_pattern {
        return Err(invalid(kind.label()));
    }
    Ok(trimmed)
}

/// Source: the admin-password check in `install_wordpress`.
///
/// Not a pattern: **ten characters and no NUL**, and nothing else. The length
/// is counted in characters as Python's `len()` does, so ten accented letters
/// are ten characters rather than twenty bytes.
pub fn check_admin_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 10 || password.contains('\0') {
        return Err("WordPress admin password must be at least 10 characters".to_string());
    }
    Ok(())
}

/// The eight constants WordPress wants as its salts.
const WP_SALT_KEYS: &[&str] = &[
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
];

/// Source: `_generate_wp_salts` - `secrets.token_urlsafe(48)` apiece.
///
/// 48 bytes of randomness, base64url without padding. The Python then strips
/// `'` from the result, which is a no-op for base64url and is kept here as a
/// guard rather than dropped: the alphabet is stated in one place and the
/// escape in another, and these salts go inside a PHP single-quoted string.
fn generate_wp_salts() -> String {
    use base64::Engine as _;
    use rand::RngCore;

    WP_SALT_KEYS
        .iter()
        .map(|key| {
            let mut raw = [0u8; 48];
            rand::rngs::OsRng.fill_bytes(&mut raw);
            let salt = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(raw)
                .replace('\'', "");
            format!("define('{key}', '{salt}');")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Source: `_render_wp_config`'s `esc`.
///
/// PHP single-quoted strings need only `'` and `\` escaped — and the
/// backslash goes first, or escaping the quote would then escape its own
/// escape.
fn php_single_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Source: `_render_wp_config`.
///
/// Rendered here and written through the helper's stdin rather than built by
/// `wp config create`, because that would put the database password in
/// `argv`, where every account on the machine can read it out of
/// `/proc/<pid>/cmdline` for as long as the process lives. C37.
pub fn render_wp_config(db_name: &str, db_user: &str, db_password: &str) -> String {
    format!(
        "<?php\n\
         define('DB_NAME', '{}');\n\
         define('DB_USER', '{}');\n\
         define('DB_PASSWORD', '{}');\n\
         define('DB_HOST', 'localhost');\n\
         define('DB_CHARSET', 'utf8mb4');\n\
         define('DB_COLLATE', '');\n\
         \n\
         $table_prefix = 'wp_';\n\
         \n\
         {}\n\
         \n\
         define('WP_DEBUG', false);\n\
         if ( ! defined('ABSPATH') ) {{\n\
         \x20   define('ABSPATH', __DIR__ . '/');\n\
         }}\n\
         require_once ABSPATH . 'wp-settings.php';\n",
        php_single_quoted(db_name),
        php_single_quoted(db_user),
        php_single_quoted(db_password),
        generate_wp_salts(),
    )
}

/// Source: `_wp_php_flag`.
///
/// WP-CLI must run under the site's PHP. Left to the default `php`, a site on
/// one version gets updated by another version's CLI, which may not have the
/// extensions WordPress needs — `mysqli` in particular.
pub fn wp_php_flag(php_version: Option<&str>) -> Vec<String> {
    match php_version.map(str::trim).filter(|v| !v.is_empty()) {
        Some(version) => vec![format!("--php-version={version}")],
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Every `_safe_value` verdict the real Python gave, replayed.
    ///
    /// The cases that matter are the ones a reasonable port gets wrong: a
    /// title in Vietnamese or Japanese is **accepted** because `\w` under
    /// `re.UNICODE` is not `[A-Za-z0-9_]`; a tab and a newline are accepted
    /// because `\s` is in the class; an emoji is refused because `So` is in
    /// neither; and a trailing newline on an email is stripped before the
    /// pattern ever sees it.
    #[test]
    fn the_wordpress_values_are_judged_the_way_the_python_judges_them() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/wp_values.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the value corpus"))
                .expect("the corpus parses");
        let cases = corpus["cases"].as_array().expect("the cases");
        assert_eq!(cases.len(), 89, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let value = case["value"].as_str().unwrap_or("");
            let want: Result<String, String> = if case["ok"].as_bool().unwrap_or(false) {
                Ok(case["output"].as_str().unwrap_or("").to_string())
            } else {
                Err(case["error"].as_str().unwrap_or("").to_string())
            };
            let got = match label {
                "WordPress admin username" => safe_value(value, WpValue::User),
                "WordPress site title" => safe_value(value, WpValue::Title),
                "WordPress admin email" => safe_value(value, WpValue::Email),
                "admin_password" => check_admin_password(value).map(|()| value.to_string()),
                other => {
                    failures.push(format!("unknown label {other:?}"));
                    continue;
                }
            };
            if got != want {
                failures.push(format!(
                    "{label}: {value:?}\n  python {want:?}\n  rust   {got:?}"
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
    }

    /// `wp-config.php` is PHP, and the password goes inside a quoted string.
    #[test]
    fn the_config_escapes_what_php_needs_escaped() {
        // The backslash first: escaping the quote first would then escape the
        // escape, and the file would not parse.
        assert_eq!(php_single_quoted(r"a\b"), r"a\\b");
        assert_eq!(php_single_quoted("it's"), r"it\'s");
        assert_eq!(php_single_quoted(r"a\'b"), r"a\\\'b");

        let rendered = render_wp_config("wp_a", "u_wp_a", r"p'a\ss");
        assert!(rendered.starts_with("<?php\n"));
        assert!(rendered.contains(r"define('DB_PASSWORD', 'p\'a\\ss');"));
        assert!(rendered.ends_with("require_once ABSPATH . 'wp-settings.php';\n"));
        assert!(rendered.contains("$table_prefix = 'wp_';"));
        assert!(rendered.contains("    define('ABSPATH', __DIR__ . '/');"));
    }

    /// Eight salts, all different, none of them able to end the string.
    #[test]
    fn the_salts_are_eight_distinct_secrets() {
        let rendered = render_wp_config("db", "user", "pw");
        let mut seen = std::collections::HashSet::new();
        for key in WP_SALT_KEYS {
            let needle = format!("define('{key}', '");
            let start = rendered
                .find(&needle)
                .unwrap_or_else(|| panic!("{key} is missing"))
                + needle.len();
            let end = start
                + rendered[start..]
                    .find("');")
                    .unwrap_or_else(|| panic!("{key} is unterminated"));
            let salt = &rendered[start..end];
            assert_eq!(salt.len(), 64, "{key} is {} characters", salt.len());
            // `secrets.token_urlsafe` is **base64url**: `-` and `_`, never
            // `+` and `/`. 48 bytes is divisible by three, so the standard
            // alphabet also gives 64 unpadded characters - the length alone
            // cannot tell the two apart, and a mutation swapping them
            // survived until this line existed.
            assert!(
                salt.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{key} is not base64url: {salt}"
            );
            // A quote in a salt would close the PHP string it sits in.
            assert!(!salt.contains('\''), "{key} carries a quote");
            assert!(!salt.contains('\\'), "{key} carries a backslash");
            assert!(seen.insert(salt.to_string()), "{key} repeats another salt");
        }
        assert_eq!(seen.len(), 8);
        // And two renders do not share one.
        let other = render_wp_config("db", "user", "pw");
        assert_ne!(rendered, other);
    }

    /// WP-CLI runs under the site's PHP, or it runs under the wrong one.
    #[test]
    fn the_php_flag_is_passed_only_when_there_is_a_version() {
        assert_eq!(wp_php_flag(Some("8.4")), vec!["--php-version=8.4"]);
        assert!(wp_php_flag(None).is_empty());
        assert!(wp_php_flag(Some("")).is_empty());
        assert!(wp_php_flag(Some("   ")).is_empty());
    }
}
