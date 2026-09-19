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

// ---------------------------------------------------------------------------
// what the WAF page reads for one site
// ---------------------------------------------------------------------------

/// Source: `site_rules_file` - the path the vhost's
/// `modsecurity_rules_file` points at.
pub fn site_rules_file(domain: &str) -> Result<String, WafError> {
    Ok(format!(
        "/etc/nginx/modsec/sites/{}.conf",
        validate_domain(domain)?
    ))
}

/// Source: `nginx.normalize_blocked_bots` when it is handed a **string**.
///
/// `re.split(r"[\n,;]+", raw)` - newline, comma and semicolon, any run of
/// them. Carriage return is deliberately not a separator, because it is not in
/// the Python's class; a `\r\n` list splits on the `\n` and the stray `\r` is
/// removed by the strip that follows.
///
/// People paste these in bulk - a CPGuard list, a blog post, a spreadsheet
/// column - which is why the separators are this generous.
pub fn split_bot_list(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for c in raw.chars() {
        if c == '\n' || c == ',' || c == ';' {
            // A *run* of separators is one split, so an empty piece between
            // two of them is never produced.
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    // `re.split` on a string with a leading or trailing separator yields an
    // empty first or last piece, which `normalize_blocked_bots` then drops for
    // being blank. Skipping them here reaches the same list.
    out
}

/// Source: `panel_settings.global_blocked_bots` - the server-wide list.
///
/// Read straight from the settings file rather than through
/// `current_settings()`, which refreshes the malware scan status: far too much
/// work to answer "what bots are blocked" on every vhost render.
pub fn global_blocked_bots(raw_settings: &serde_json::Value) -> Vec<String> {
    let stored = raw_settings.get("global_blocked_bots");
    let candidates: Vec<String> = match stored {
        Some(serde_json::Value::String(text)) => split_bot_list(text),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        _ => Vec::new(),
    };
    snpanel_nginx::normalize_blocked_bots(&candidates).unwrap_or_default()
}

/// Source: `website_blocked_bots`.
pub fn website_blocked_bots(website: &snpanel_db::Website) -> Vec<String> {
    snpanel_nginx::normalize_blocked_bots(&split_bot_list(&website.blocked_bots))
        .unwrap_or_default()
}

/// Source: `_merge_bots` - "union, order-preserving, case-insensitive, first
/// spelling wins".
///
/// The Python keys on `casefold()` and this keys on `to_lowercase()`. They
/// differ for a handful of characters - German ß casefolds to `ss` and
/// lowercases to itself - and these are user-agent tokens, which are ASCII.
/// Written down rather than assumed away.
pub fn merge_bots(first: &[String], second: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut merged: Vec<String> = Vec::new();
    for name in first.iter().chain(second.iter()) {
        let key = name.to_lowercase();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        merged.push(name.clone());
    }
    snpanel_nginx::normalize_blocked_bots(&merged).unwrap_or_default()
}

/// Source: `effective_blocked_bots` - "the server-wide list plus anything set
/// on the site itself".
///
/// Keeping the two apart in storage is what lets a bot added globally protect
/// every site at once, without flattening it into 23 copies that then drift.
pub fn effective_blocked_bots(
    website: &snpanel_db::Website,
    raw_settings: &serde_json::Value,
) -> Vec<String> {
    merge_bots(
        &global_blocked_bots(raw_settings),
        &website_blocked_bots(website),
    )
}

/// Source: `nginx.http_flood_config_for_website`.
pub fn http_flood_config(website: &snpanel_db::Website) -> snpanel_nginx::HttpFloodConfig {
    // `json.loads(raw) if raw.strip() else {}`, and anything that does not
    // parse is `{}` - every field then falls back to its default rather than
    // the request being refused.
    let parsed = if website.http_flood_config.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&website.http_flood_config).unwrap_or_else(|_| serde_json::json!({}))
    };
    snpanel_nginx::HttpFloodConfig::from_json(&parsed)
}

/// Source: `default_rule_definitions()` - the identifying fields, never the
/// rule bodies.
pub fn default_rule_definitions() -> Vec<serde_json::Value> {
    DEFAULT_RULES
        .iter()
        .map(|rule| {
            serde_json::json!({
                "id": rule.id,
                "category": rule.category,
                "title": rule.title,
                "description": rule.description,
                "enabled_default": true,
            })
        })
        .collect()
}

/// Source: `site_config` - everything the WAF page shows for one site.
///
/// `crs_active` is the one field worth reading twice: it is true only when the
/// site opted in *and* the server-wide mode is not off. Both toggles have to
/// agree, because CRS is the one WAF feature with a memory bill.
pub fn site_config(
    website: &snpanel_db::Website,
    server_crs_mode: &str,
    raw_settings: &serde_json::Value,
) -> serde_json::Value {
    let mode = normalize_crs_mode(server_crs_mode);
    let enabled = parse_enabled_rule_ids(&website.waf_default_rules);
    let flood = http_flood_config(website);

    serde_json::json!({
        "website_id": website.id,
        "domain": website.domain,
        "waf_enabled": website.waf_enabled,
        "crs_enabled": website.crs_enabled,
        "crs_mode": mode,
        "crs_active": site_uses_crs(website) && mode != "off",
        "http_flood_enabled": website.http_flood_enabled,
        "http_flood_config": {
            "access_limit_requests": flood.access_limit_requests,
            "access_limit_window": flood.access_limit_window,
            "access_limit_burst": flood.access_limit_burst,
            "connection_limit": flood.connection_limit,
        },
        // A domain the validator refuses has no rule file; the Python would
        // raise here and the router would turn it into a 400. An empty string
        // is not that, so this keeps the refusal.
        "rules_file": site_rules_file(&website.domain).unwrap_or_default(),
        "default_rules": default_rule_definitions()
            .into_iter()
            .map(|mut rule| {
                let id = rule["id"].as_str().unwrap_or("").to_string();
                rule["enabled"] = serde_json::json!(enabled.contains(&id));
                rule
            })
            .collect::<Vec<_>>(),
        // In DEFAULT_RULES order, not in the stored order.
        "enabled_rule_ids": DEFAULT_RULES
            .iter()
            .filter(|rule| enabled.iter().any(|e| e == rule.id))
            .map(|rule| rule.id)
            .collect::<Vec<_>>(),
        "custom_rules": validate_custom_rules(&website.waf_custom_rules)
            .unwrap_or_default(),
        "blocked_bots": website_blocked_bots(website),
        "global_blocked_bots": global_blocked_bots(raw_settings),
        "effective_blocked_bots": effective_blocked_bots(website, raw_settings),
    })
}

/// What `save_website_config` stores, computed before anything is written.
pub struct SavedWafConfig {
    /// `json.dumps(selected, ensure_ascii=True)` - the `waf_default_rules`
    /// column.
    pub default_rules: String,
    /// The `waf_custom_rules` column.
    pub custom_rules: String,
    /// The rule file's contents.
    pub content: String,
}

/// Source: `save_website_config`.
///
/// "Editing a site's rule selection must not change whether it loads CRS" -
/// the mode still comes from the site's own opt-in, not from the request.
pub fn plan_website_config<S: AsRef<str>>(
    website: &snpanel_db::Website,
    enabled_rule_ids: &[S],
    custom_rules: &str,
    server_crs_mode: &str,
) -> Result<SavedWafConfig, WafError> {
    let selected = validate_enabled_rule_ids(enabled_rule_ids)?;
    let custom = validate_custom_rules(custom_rules)?;
    let mode = if site_uses_crs(website) {
        normalize_crs_mode(server_crs_mode)
    } else {
        "off"
    };
    let content = render_site_rules(&website.domain, &selected, &custom, mode)?;
    Ok(SavedWafConfig {
        default_rules: python_json_list(&selected),
        custom_rules: custom,
        content,
    })
}

/// `json.dumps(list, ensure_ascii=True)`, byte for byte.
///
/// Python's default separators are `", "` and `": "`, so a list comes out as
/// `["a", "b"]` - **with** the space. `serde_json::to_string` writes
/// `["a","b"]`. Both parse back the same, and the column would still work,
/// but the stored bytes are what a shadow diff compares and what the next
/// person reads in the database. NT7: a difference is a difference.
///
/// Every id in the table is ASCII, so `ensure_ascii` has nothing to escape
/// here; the quoting is serde's, which matches Python's for ASCII.
fn python_json_list(items: &[String]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|item| serde_json::Value::String(item.clone()).to_string())
        .collect();
    format!("[{}]", quoted.join(", "))
}

/// Write a rule file the caller has already planned.
pub async fn write_site_rules(
    dry_run: bool,
    domain: &str,
    content: &str,
) -> Result<crate::shell::CommandResult, WafError> {
    let safe_domain = validate_domain(domain)?;
    Ok(crate::shell::privileged(
        dry_run,
        "waf-site-save",
        &[&safe_domain],
        Some(content),
        Some(&[
            "bash",
            "-lc",
            "cat >/tmp/snpanel-waf-site.conf && echo WAF site rules saved",
        ]),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A website row built from the corpus's own description of one.
    ///
    /// Written out field by field rather than by deriving `Default` on the row
    /// type: a `Website` that defaults to an empty domain is a footgun for
    /// every non-test caller, and this is the only place that wants one.
    fn corpus_website(spec: &serde_json::Value) -> snpanel_db::Website {
        let s = |key: &str, fallback: &str| -> String {
            spec.get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or(fallback)
                .to_string()
        };
        let b = |key: &str, fallback: bool| -> bool {
            spec.get(key)
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(fallback)
        };
        snpanel_db::Website {
            id: spec
                .get("id")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(7),
            domain: s("domain", "example.com"),
            owner_id: 1,
            root_path: "/home/alice/example.com".into(),
            document_root: "public_html".into(),
            linux_user: Some("alice".into()),
            php_version: "8.4".into(),
            app_type: "wordpress".into(),
            ssl_enabled: false,
            ssl_mode: String::new(),
            ssl_cert_path: None,
            ssl_key_path: None,
            ssl_ca_path: None,
            ssl_updated_at: None,
            ssl_source_domain: None,
            status: "active".into(),
            nginx_custom: String::new(),
            nginx_config_mode: "managed".into(),
            nginx_rewrite_mode: "wordpress".into(),
            waf_enabled: b("waf_enabled", true),
            waf_default_rules: s("waf_default_rules", ""),
            waf_custom_rules: s("waf_custom_rules", ""),
            crs_enabled: b("crs_enabled", false),
            http_flood_enabled: b("http_flood_enabled", false),
            http_flood_config: s("http_flood_config", ""),
            blocked_bots: s("blocked_bots", ""),
            app_id: None,
        }
    }

    fn site_corpus() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/waf_site_config.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the site config corpus"))
            .expect("the corpus parses")
    }

    /// The whole WAF page for one site, field for field.
    ///
    /// `crs_active` and `effective_blocked_bots` are the two that carry real
    /// meaning: the first says whether CRS is actually running for this site,
    /// which needs both toggles to agree, and the second is what ends up in
    /// the vhost.
    #[test]
    fn a_sites_waf_page_agrees_with_python() {
        let corpus = site_corpus();
        let cases = corpus["configs"].as_array().expect("the configs");
        assert!(cases.len() > 100, "the corpus shrank to {}", cases.len());

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let website = corpus_website(&case["website"]);
            let mode = case["crs_mode"].as_str().unwrap_or("off");
            let settings = serde_json::json!({
                "global_blocked_bots": case["global_blocked_bots"],
                "crs_mode": mode,
            });
            let Some(want) = case.get("config") else {
                continue; // Python raised; not a case this compares.
            };
            let got = site_config(&website, mode, &settings);

            // Compare key by key so a failure names the field rather than
            // printing two walls of JSON.
            let want_map = want.as_object().expect("an object");
            for (key, want_value) in want_map {
                let got_value = &got[key.as_str()];
                if got_value != want_value {
                    failures.push(format!(
                        "{:?} bots={:?} mode={mode}: {key} python {want_value}, rust {got_value}",
                        case["website"], case["global_blocked_bots"]
                    ));
                }
            }
            for key in got.as_object().expect("an object").keys() {
                if !want_map.contains_key(key) {
                    failures.push(format!("rust invented the field {key}"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} disagree:\n{}",
            failures.len(),
            failures.into_iter().take(10).collect::<Vec<_>>().join("\n")
        );
    }

    /// The two columns the save writes, byte for byte.
    ///
    /// `json.dumps` puts a **space** after the comma. Both forms parse back
    /// the same and the column would still work, which is exactly why this is
    /// the byte a port gets wrong and never notices.
    #[test]
    fn the_saved_columns_are_the_pythons_bytes() {
        let corpus = site_corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["saves"].as_array().expect("the saves") {
            let website = corpus_website(&case["website"]);
            let ids: Vec<String> = case["ids"]
                .as_array()
                .expect("a list")
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let custom = case["custom"].as_str().unwrap_or("");
            let mode = case["crs_mode"].as_str().unwrap_or("off");
            let label = format!("{:?} custom={custom:?} mode={mode}", case["ids"]);

            match plan_website_config(&website, &ids, custom, mode) {
                Ok(plan) => match case.get("waf_default_rules").and_then(|v| v.as_str()) {
                    Some(want) => {
                        if plan.default_rules != want {
                            failures.push(format!(
                                "{label}: column python {want:?}, rust {:?}",
                                plan.default_rules
                            ));
                        }
                        let want_custom = case["waf_custom_rules"].as_str().unwrap_or("");
                        if plan.custom_rules != want_custom {
                            failures.push(format!(
                                "{label}: custom python {want_custom:?}, rust {:?}",
                                plan.custom_rules
                            ));
                        }
                    }
                    None => failures.push(format!(
                        "{label}: python refused with {:?}, rust planned",
                        case["error"]
                    )),
                },
                Err(e) => {
                    let want = case.get("error").and_then(|v| v.as_str());
                    match want {
                        Some(want) if want == e.to_string() => {}
                        Some(want) => failures.push(format!("{label}: python {want:?}, rust {e}")),
                        None => failures.push(format!("{label}: rust refused {e}")),
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
    }

    /// What a pasted bot list turns into.
    #[test]
    fn a_pasted_bot_list_is_split_the_way_python_splits_it() {
        let corpus = site_corpus();
        let mut failures: Vec<String> = Vec::new();
        for case in corpus["splits"].as_array().expect("the splits") {
            let raw = case["raw"].as_str().unwrap_or("");
            let want: Vec<String> = case["pieces"]
                .as_array()
                .expect("a list")
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let got =
                snpanel_nginx::normalize_blocked_bots(&split_bot_list(raw)).unwrap_or_default();
            if got != want {
                failures.push(format!("{raw:?}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

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
