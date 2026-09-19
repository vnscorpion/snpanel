//! The per-site ModSecurity rule file.
//!
//! Source: `app.services.waf`, the part that renders and writes one site's
//! rules. The file this produces is loaded by nginx's ModSecurity for that
//! site, so a byte wrong is one of two things: rules that do not parse, which
//! fails `nginx -t` and takes the next reload down with every site on it, or
//! rules that parse and no longer match, which is a site a customer believes
//! is protected.
//!
//! The rule table is **generated from the Python's own** rather than copied by
//! hand - eight regex-laden `SecRule` directives is a transcription error
//! waiting to happen, and the one that matters would be silent. 280 rendered
//! files from the real `render_site_rules` are in
//! `tests/golden/waf_site_rules.json`.
//!
//! One thing that looks like a bug and is not: every `SecRule` here opens its
//! action list with `"` and never closes it. That was checked against a real
//! `ngx_http_modsecurity_module` v1.0.3 rather than assumed - both the file as
//! written and the same file with the quote closed load one rule and pass
//! `nginx -t`. libmodsecurity's parser tolerates it. NT1 applies either way:
//! the byte stream is reproduced as it is.

/// Source: one entry of `DEFAULT_RULES`.
///
/// `exceptions` is absent: no rule in the table has one today, and
/// `render_site_rules` appends it only `if rule.get("exceptions")`. The
/// generator asserts that none has grown one, so a rule that gains an
/// exceptions block fails the regeneration rather than being silently dropped.
pub struct DefaultRule {
    pub id: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub rules: &'static str,
}

pub const DEFAULT_RULES: &[DefaultRule] = &[
    DefaultRule {
        id: r#"php-sensitive-files"#,
        category: r#"PHP"#,
        title: r#"PHP sensitive files"#,
        description: r#"Blocks direct probes for PHP app secrets, Composer metadata, git data, and phpinfo files."#,
        rules: r#"SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/\.user\.ini(?:\.|$)|/\.git/|/composer\.(?:json|lock)(?:$|[?])|/(?:phpinfo|info)\.php(?:$|[?])|/(?:config|database|db)\.php\.(?:bak|old|save|txt)(?:$|[?]))" "id:1001301,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP sensitive file probe'"#,
    },
    DefaultRule {
        id: r#"php-path-traversal"#,
        category: r#"PHP"#,
        title: r#"Path traversal"#,
        description: r#"Blocks ../ and encoded traversal probes in URLs and query arguments."#,
        rules: r#"SecRule REQUEST_URI|ARGS "@rx (?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)" "id:1001302,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP path traversal'"#,
    },
    DefaultRule {
        id: r#"php-runtime-probes"#,
        category: r#"PHP"#,
        title: r#"PHP runtime probes"#,
        description: r#"Blocks direct probes for common PHP webshell names and old PHPUnit RCE paths."#,
        rules: r#"SecRule REQUEST_URI "@rx (?i)(?:/(?:c99|r57|shell|cmd|wso)\.php(?:$|[?])|/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php(?:$|[?]))" "id:1001303,phase:1,deny,status:403,log,msg:'SNPanel blocked PHP runtime probe'"#,
    },
    DefaultRule {
        id: r#"laravel-sensitive-files"#,
        category: r#"Laravel"#,
        title: r#"Laravel sensitive files"#,
        description: r#"Blocks probes for Laravel environment files, logs, artisan, and cached PHP config."#,
        rules: r#"SecRule REQUEST_URI "@rx (?i)(?:/\.env(?:\.|$)|/artisan(?:$|[?])|/server\.php(?:$|[?])|/storage/logs/[^?]*\.log(?:$|[?])|/bootstrap/cache/[^?]*\.php(?:$|[?]))" "id:1001201,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel sensitive path'"#,
    },
    DefaultRule {
        id: r#"laravel-ignition-rce"#,
        category: r#"Laravel"#,
        title: r#"Laravel Ignition RCE probes"#,
        description: r#"Blocks direct probes for the old Laravel Ignition execute-solution endpoint."#,
        rules: r#"SecRule REQUEST_URI "@rx (?i)(?:/_ignition/execute-solution(?:$|[?]))" "id:1001202,phase:1,deny,status:403,log,msg:'SNPanel blocked Laravel Ignition RCE probe'"#,
    },
    DefaultRule {
        id: r#"wordpress-sensitive-files"#,
        category: r#"WordPress"#,
        title: r#"WordPress sensitive files"#,
        description: r#"Blocks wp-config probes, uploads PHP execution probes, and internal WordPress PHP paths."#,
        rules: r#"SecRule REQUEST_URI "@rx (?i)(?:/wp-config\.php(?:\.|$|[?])|/wp-content/(?:uploads|cache|upgrade)/[^?]*\.php(?:$|[?])|/wp-admin/includes/[^?]*\.php(?:$|[?])|/wp-includes/[^?]*\.php(?:$|[?]))" "id:1001101,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress sensitive path'"#,
    },
    DefaultRule {
        id: r#"wordpress-xmlrpc-author-scan"#,
        category: r#"WordPress"#,
        title: r#"WordPress author scans"#,
        description: r#"Blocks ?author= enumeration scans while leaving XML-RPC compatibility to site policy."#,
        rules: r#"SecRule ARGS:author "@rx ^[0-9]+$" "id:1001103,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress author enumeration'"#,
    },
    DefaultRule {
        id: r#"wordpress-install-upgrade"#,
        category: r#"WordPress"#,
        title: r#"WordPress installer probes"#,
        description: r#"Blocks direct access to WordPress installation scripts after deployment."#,
        rules: r#"SecRule REQUEST_URI "@rx (?i)(?:/wp-admin/install\.php(?:$|[?])|/wp-admin/setup-config\.php(?:$|[?]))" "id:1001104,phase:1,deny,status:403,log,msg:'SNPanel blocked WordPress installer probe'"#,
    },
];

pub const LEGACY_RULE_ID_MAP: &[(&str, Option<&str>)] = &[
    (r#"general-sensitive-files"#, Some(r#"php-sensitive-files"#)),
    (r#"general-path-traversal"#, Some(r#"php-path-traversal"#)),
    (
        r#"general-command-injection"#,
        Some(r#"php-runtime-probes"#),
    ),
    (r#"general-sqli"#, None),
    (r#"general-xss"#, None),
];

/// Source: `CRS_MODES`.
const CRS_MODES: &[&str] = &["off", "detect", "block"];
/// Source: `CRS_CONF_PATH`.
const CRS_CONF_PATH: &str = "/etc/nginx/modsec/snpanel-crs.conf";
/// Source: `MAX_SITE_RULE_BYTES`.
const MAX_SITE_RULE_BYTES: usize = 160 * 1024;
/// Source: `MAX_CUSTOM_BYTES`.
const MAX_CUSTOM_BYTES: usize = 64 * 1024;

/// Source: the `ValueError`s this module raises, which the routers turn into
/// 400s.
#[derive(Debug)]
pub struct WafError(pub String);

impl std::fmt::Display for WafError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn refuse<T>(message: &str) -> Result<T, WafError> {
    Err(WafError(message.to_string()))
}

/// Source: `normalize_crs_mode` - anything unrecognised is `off`.
///
/// Unrecognised means off rather than an error on purpose: this reads a stored
/// setting, and a settings file somebody edited by hand must not be able to
/// stop every site's rules from rendering.
pub fn normalize_crs_mode(value: &str) -> &'static str {
    let mode = value.trim().to_lowercase();
    CRS_MODES
        .iter()
        .copied()
        .find(|m| *m == mode)
        .unwrap_or("off")
}

/// Source: `DOMAIN_RE` - `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`.
///
/// At least two labels, so a bare `example` is refused: this name becomes a
/// filename under `/etc/nginx/modsec/sites/`.
pub fn validate_domain(domain: &str) -> Result<String, WafError> {
    let value = domain.trim().to_lowercase();
    let mut labels = value.split('.');
    let Some(first) = labels.next() else {
        return refuse("Invalid domain");
    };
    let rest: Vec<&str> = labels.collect();
    if rest.is_empty() || !label_ok(first) || !rest.iter().all(|l| label_ok(l)) {
        return refuse("Invalid domain");
    }
    Ok(value)
}

/// One label: 1 to 63 characters, alphanumeric at each end, hyphens inside.
fn label_ok(label: &str) -> bool {
    let bytes = label.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    match bytes.len() {
        0 => false,
        1 => alnum(bytes[0]),
        2..=63 => {
            alnum(bytes[0])
                && alnum(bytes[bytes.len() - 1])
                && bytes[1..bytes.len() - 1]
                    .iter()
                    .all(|&b| alnum(b) || b == b'-')
        }
        _ => false,
    }
}

/// Source: `_validate_custom_rules`.
pub fn validate_custom_rules(content: &str) -> Result<String, WafError> {
    if content.contains('\0') {
        return refuse("WAF rules cannot contain NUL bytes");
    }
    if content.len() > MAX_CUSTOM_BYTES {
        return refuse("WAF custom rules must be 64 KB or smaller");
    }
    Ok(content.replace("\r\n", "\n").trim().to_string())
}

/// Source: `LEGACY_RULE_ID_MAP.get(rule_id, rule_id)` - the rename, with two
/// ids that map to nothing because the rules behind them were withdrawn.
fn map_legacy(rule_id: &str) -> Option<&str> {
    for (old, new) in LEGACY_RULE_ID_MAP {
        if *old == rule_id {
            return *new;
        }
    }
    Some(rule_id)
}

fn is_known(rule_id: &str) -> bool {
    DEFAULT_RULES.iter().any(|rule| rule.id == rule_id)
}

/// Source: `_parse_enabled_rule_ids` - what the `waf_default_rules` column
/// means.
///
/// An empty column, or one holding anything that is not a JSON list, means
/// **every** rule. That is the opposite of what an empty list means, and it is
/// the safe direction: a site whose stored selection cannot be read gets the
/// full rule set rather than none.
pub fn parse_enabled_rule_ids(value: &str) -> Vec<String> {
    let all = || -> Vec<String> {
        DEFAULT_RULES
            .iter()
            .map(|rule| rule.id.to_string())
            .collect()
    };
    if value.is_empty() {
        return all();
    }
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value) else {
        return all();
    };
    let Some(items) = parsed.as_array() else {
        return all();
    };

    let mut selected: Vec<String> = Vec::new();
    for item in items {
        // Source: `str(item)` - a list of numbers is a list of strings that
        // match nothing, not an error.
        let raw = match item {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if let Some(mapped) = map_legacy(&raw) {
            if is_known(mapped) && !selected.iter().any(|s| s == mapped) {
                selected.push(mapped.to_string());
            }
        }
    }
    selected
}

/// Source: `validate_enabled_rule_ids` - unlike the parser above, an id this
/// does not know is an **error**.
///
/// The two are not interchangeable. The parser reads a stored column and must
/// cope with whatever is in it; this checks what a request asked for, and a
/// request naming a rule that does not exist is a request to be refused rather
/// than quietly narrowed.
pub fn validate_enabled_rule_ids<S: AsRef<str>>(rule_ids: &[S]) -> Result<Vec<String>, WafError> {
    let mut selected: Vec<String> = Vec::new();
    for rule_id in rule_ids {
        let Some(value) = map_legacy(rule_id.as_ref()) else {
            continue;
        };
        if !is_known(value) {
            return Err(WafError(format!("Unknown WAF rule: {value}")));
        }
        if !selected.iter().any(|s| s == value) {
            selected.push(value.to_string());
        }
    }
    Ok(selected)
}

/// Source: `render_site_rules`.
///
/// The rules come out in **`DEFAULT_RULES` order**, not in the order they were
/// asked for: the render walks the table and skips what is not selected. CRS
/// goes after the panel's own rules, which deny outright on a single match and
/// are cheaper - no point scoring a request that is already refused. Custom
/// rules go last, because `SecRuleRemoveById` only affects rules already
/// loaded, so that is where a per-site CRS exception belongs.
pub fn render_site_rules<S: AsRef<str>>(
    domain: &str,
    enabled_rule_ids: &[S],
    custom_rules: &str,
    crs_mode: &str,
) -> Result<String, WafError> {
    let safe_domain = validate_domain(domain)?;
    let enabled = validate_enabled_rule_ids(enabled_rule_ids)?;
    let custom = validate_custom_rules(custom_rules)?;
    let mode = normalize_crs_mode(crs_mode);

    let mut chunks: Vec<String> = vec![
        format!("# SNPanel WAF rules for {safe_domain}"),
        "Include /etc/nginx/modsec/snpanel-base.conf".to_string(),
        String::new(),
        "# SNPanel selected default rules".to_string(),
    ];
    for rule in DEFAULT_RULES {
        if !enabled.iter().any(|id| id == rule.id) {
            continue;
        }
        chunks.push(format!(
            "# {} - {} ({})",
            rule.category, rule.title, rule.id
        ));
        chunks.push(rule.rules.trim().to_string());
    }
    if mode != "off" {
        chunks.push(String::new());
        chunks.push(format!("# OWASP CRS ({mode})"));
        chunks.push(format!("Include {CRS_CONF_PATH}"));
    }
    chunks.push(String::new());
    chunks.push("# SNPanel custom rules".to_string());
    if !custom.is_empty() {
        chunks.push(custom);
    }

    let content = chunks.join("\n").trim().to_string() + "\n";
    if content.len() > MAX_SITE_RULE_BYTES {
        return refuse("WAF site rules are too large");
    }
    Ok(content)
}

/// Source: `site_uses_crs` - "CRS applies to a site only when both toggles
/// agree".
///
/// `waf_enabled` is the site's WAF switch; `crs_enabled` is the separate
/// opt-in that exists because CRS is the one WAF feature with a memory bill.
pub fn site_uses_crs(website: &snpanel_db::Website) -> bool {
    website.waf_enabled && website.crs_enabled
}

/// Source: `sync_website_rules` - render this site's file and write it.
///
/// The CRS mode is the server-wide one **only** when the site opted in. A
/// caller that has not thought about it must not turn CRS on by omission,
/// which is exactly what happened once: creating a website on a server in
/// block mode gave the new site CRS while its own `crs_enabled` said off.
pub async fn sync_website_rules(
    dry_run: bool,
    website: &snpanel_db::Website,
    server_crs_mode: &str,
) -> Result<crate::shell::CommandResult, WafError> {
    let mode = if site_uses_crs(website) {
        normalize_crs_mode(server_crs_mode)
    } else {
        "off"
    };
    let enabled = parse_enabled_rule_ids(&website.waf_default_rules);
    let content = render_site_rules(&website.domain, &enabled, &website.waf_custom_rules, mode)?;
    let safe_domain = validate_domain(&website.domain)?;

    Ok(crate::shell::privileged(
        dry_run,
        "waf-site-save",
        &[&safe_domain],
        Some(&content),
        Some(&[
            "bash",
            "-lc",
            "cat >/tmp/snpanel-waf-site.conf && echo WAF site rules saved",
        ]),
    )
    .await)
}

/// Source: `api.waf.may_manage_waf`.
///
/// `UserPackage.waf_enabled` "has existed, been editable and been displayed
/// since packages were added, and was never read by anything". Its default is
/// **true**, so an account with no package keeps access rather than silently
/// losing a feature.
pub fn may_manage_waf(role: &str, package_waf_enabled: Option<bool>) -> bool {
    snpanel_core::permissions::is_admin_role(role) || package_waf_enabled.unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/waf_site_rules.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the waf corpus"))
            .expect("the corpus parses")
    }

    /// Every rule file the Python renders, byte for byte.
    #[test]
    fn a_site_rule_file_is_rendered_the_way_python_renders_it() {
        let corpus = corpus();
        let renders = corpus["renders"].as_array().expect("the renders");
        assert!(
            renders.len() > 200,
            "the corpus shrank to {}",
            renders.len()
        );

        let mut failures: Vec<String> = Vec::new();
        for case in renders {
            let ids: Vec<String> = case["ids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|v| v.as_str().unwrap_or("").to_string())
                        .collect()
                })
                .unwrap_or_default();
            let custom = case["custom"].as_str().unwrap_or("");
            // Python's `None` mode: `normalize_crs_mode(None)` is "off".
            let mode = case["mode"].as_str().unwrap_or("off");
            let label = format!(
                "{:?} custom={custom:?} mode={:?}",
                case["ids"], case["mode"]
            );

            match (
                render_site_rules("example.com", &ids, custom, mode),
                case.get("content").and_then(|v| v.as_str()),
            ) {
                (Ok(got), Some(want)) if got == want => {}
                (Ok(got), Some(want)) => failures.push(format!(
                    "{label}:\n--- python ---\n{want}\n--- rust ---\n{got}"
                )),
                (Ok(_), None) => failures.push(format!(
                    "{label}: python refused with {:?}, rust rendered",
                    case["error"]
                )),
                (Err(e), Some(_)) => {
                    failures.push(format!("{label}: rust refused {e}, python rendered"))
                }
                (Err(e), None) => {
                    let want = case["error"].as_str().unwrap_or("");
                    if e.to_string() != want {
                        failures.push(format!("{label}: python {want:?}, rust {e}"));
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            renders.len(),
            failures.into_iter().take(3).collect::<Vec<_>>().join("\n")
        );
    }

    /// The domain becomes a filename under `/etc/nginx/modsec/sites/`, so what
    /// this refuses is what keeps a site from writing outside it.
    #[test]
    fn the_domain_check_agrees_with_python() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["domains"].as_array().expect("the domains") {
            let domain = case["domain"].as_str().unwrap_or("");
            let got = validate_domain(domain);
            match (got, case.get("result").and_then(|v| v.as_str())) {
                (Ok(have), Some(want)) if have == want => {}
                (Ok(have), Some(want)) => {
                    failures.push(format!("{domain:?}: python {want:?}, rust {have:?}"))
                }
                (Ok(have), None) => {
                    failures.push(format!("{domain:?}: python refused, rust {have:?}"))
                }
                (Err(_), None) => {}
                (Err(e), Some(want)) => {
                    failures.push(format!("{domain:?}: python {want:?}, rust refused {e}"))
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// An unreadable stored selection means **every** rule, not none. Getting
    /// this backwards silently unprotects a site.
    #[test]
    fn the_stored_selection_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["parsed"].as_array().expect("the parsed cases") {
            let stored = case["stored"].as_str().unwrap_or("");
            let mut got = parse_enabled_rule_ids(stored);
            got.sort();
            let want: Vec<String> = case["ids"]
                .as_array()
                .expect("a list")
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            if got != want {
                failures.push(format!(
                    "{:?}: python {want:?}, rust {got:?}",
                    case["stored"]
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn custom_rules_are_normalised_the_way_python_normalises_them() {
        let corpus = corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["customs"].as_array().expect("the custom cases") {
            let input = case["input"].as_str().unwrap_or("");
            match (
                validate_custom_rules(input),
                case.get("result").and_then(|v| v.as_str()),
            ) {
                (Ok(got), Some(want)) if got == want => {}
                (Ok(got), Some(want)) => {
                    failures.push(format!("{input:?}: python {want:?}, rust {got:?}"))
                }
                (Ok(got), None) => {
                    failures.push(format!("{input:?}: python refused, rust {got:?}"))
                }
                (Err(e), None) => {
                    let want = case["error"].as_str().unwrap_or("");
                    if e.to_string() != want {
                        failures.push(format!("{input:?}: python {want:?}, rust {e}"));
                    }
                }
                (Err(e), Some(want)) => {
                    failures.push(format!("{input:?}: python {want:?}, rust refused {e}"))
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The table came from the Python's; this is the check that it still has
    /// the shape the renderer expects.
    #[test]
    fn the_rule_table_matches_the_corpus() {
        let corpus = corpus();
        let want: Vec<String> = corpus["rule_ids"]
            .as_array()
            .expect("the ids")
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect();
        let mut got: Vec<String> = DEFAULT_RULES.iter().map(|r| r.id.to_string()).collect();
        got.sort();
        assert_eq!(got, want);

        // Two legacy ids map to nothing because the rules behind them were
        // withdrawn. Asking for one is not an error and not a rule.
        assert_eq!(map_legacy("general-sqli"), None);
        assert_eq!(map_legacy("general-xss"), None);
        assert_eq!(
            map_legacy("general-sensitive-files"),
            Some("php-sensitive-files")
        );
        assert_eq!(
            map_legacy("php-sensitive-files"),
            Some("php-sensitive-files")
        );
    }

    #[test]
    fn an_account_with_no_package_keeps_waf_access() {
        // The flag's default is true, so an account with no package must not
        // silently lose a feature that is being granted for the first time.
        assert!(may_manage_waf("end_user", None));
        assert!(may_manage_waf("end_user", Some(true)));
        assert!(!may_manage_waf("end_user", Some(false)));
        // An administrator administers the server.
        assert!(may_manage_waf("admin", Some(false)));
    }
}
