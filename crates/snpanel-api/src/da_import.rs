//! Reading a DirectAdmin account backup.
//!
//! Source: `services/da_import.py`.
//!
//! A DirectAdmin backup is a tar of somebody else's conventions: an account
//! name that may not be a legal Linux user here, domains listed in three
//! different places, subdomains nested inside their parent's document root,
//! databases named for a panel this one is not, and config files written by
//! whichever application the customer installed. Almost everything here
//! turns one of those into something this panel can hold without colliding
//! with what is already on the machine.
//!
//! **Everything that comes out of an archive is untrusted.** It was
//! uploaded through the browser; its member paths, its account name and its
//! database names all reach a filesystem path, a Linux account or a SQL
//! identifier. Member paths go through [`crate::tarfilter`], and every name
//! is *rewritten* into a shape this panel defines rather than checked and
//! passed through.
//!
//! The upload guards themselves - the accepted suffixes, the uploaded
//! filename, and confining a request's path to the backup directory - live
//! in `routes::maintenance`, where the endpoints that use them are.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Source: `STAGE_BASE`.
///
/// Scan and import stage into the same place, and it is deliberately not
/// `/tmp`: that is frequently a small tmpfs and a DirectAdmin account
/// backup can be tens of gigabytes.
pub fn stage_base() -> PathBuf {
    match std::env::var("DA_IMPORT_STAGE_BASE") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/var/lib/snpanel/da-import"),
    }
}

/// Source: `SQL_SUFFIXES`.
pub const SQL_SUFFIXES: &[&str] = &[".sql", ".sql.gz", ".sql.bz2", ".sql.zst"];

/// Source: `APP_CONFIG_SKIP_DIRS`.
///
/// Directories that never hold an application's database config. Walking
/// into `wp-content` or `node_modules` looking for `wp-config.php` costs
/// minutes on a real site and finds nothing.
pub const APP_CONFIG_SKIP_DIRS: &[&str] = &[
    "wp-content",
    "wp-includes",
    "wp-admin",
    "node_modules",
    "vendor",
    "cache",
    "storage",
    "uploads",
    "images",
    "img",
    "assets",
    "media",
    "backup",
    "backups",
    ".git",
    ".well-known",
    "logs",
    "log",
    "tmp",
    "temp",
];

/// Source: `APP_CONFIG_SCAN_DEPTH`.
const APP_CONFIG_SCAN_DEPTH: usize = 2;

// ---------------------------------------------------------------------------
// the names
// ---------------------------------------------------------------------------

/// Source: `_strip_archive_suffix`.
///
/// A known archive suffix comes off whole - `.tar.gz`, not just `.gz` -
/// and anything else falls back to `Path(name).stem`, which removes only
/// the last extension. The suffix list is ordered so the compound ones are
/// tried first; see `routes::maintenance::ARCHIVE_SUFFIXES`.
pub fn strip_archive_suffix(name: &str) -> String {
    let lower = name.to_lowercase();
    for suffix in crate::routes::maintenance::ARCHIVE_SUFFIXES {
        if lower.ends_with(suffix) {
            return name[..name.len() - suffix.len()].to_string();
        }
    }
    path_stem(name)
}

/// `pathlib.Path(name).stem`.
fn path_stem(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    match base.rfind('.') {
        // A leading dot is not an extension: `.bashrc`'s stem is `.bashrc`.
        Some(0) | None => base.to_string(),
        Some(index) => base[..index].to_string(),
    }
}

/// Source: `_archive_username`.
///
/// The account name the panel falls back to when `user.conf` has none.
/// DirectAdmin names its archives several ways: a `user.`/`reseller.`
/// prefix means the name is **last**, and otherwise the last piece that is
/// not a filler word wins.
pub fn archive_username(name: &str) -> String {
    let base = strip_archive_suffix(name);
    // `re.split(r"[._-]+", base)` - a **run** of separators splits once.
    let pieces: Vec<&str> = base
        .split(['.', '_', '-'])
        .filter(|p| !p.is_empty())
        .collect();
    if pieces.len() >= 3 && matches!(pieces[0], "user" | "reseller") {
        return pieces[pieces.len() - 1].to_string();
    }
    for piece in pieces.iter().rev() {
        if !matches!(
            piece.to_lowercase().as_str(),
            "backup" | "user" | "admin" | "reseller"
        ) {
            return (*piece).to_string();
        }
    }
    base
}

/// Source: `_normalize_username`.
///
/// **The account name from the archive is not a Linux user until this has
/// run.** It may be too long, start with a digit, hold characters no
/// account may have, or name a system account. Each of those is rewritten
/// rather than refused, because an import that stops on a name leaves the
/// operator with nothing - and a collision with a reserved account takes a
/// hash of the original, so two archives cannot land on the same rewrite.
pub fn normalize_username(raw: &str, archive_name: &str) -> String {
    let lowered = snpanel_core::pyunicode::trim(raw).to_lowercase();
    let mut value = replace_runs(&lowered, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'
    });
    value = value.trim_matches(|c| c == '_' || c == '-').to_string();

    if value.is_empty() || !starts_with_letter_or_underscore(&value) {
        value = if value.is_empty() {
            "da_user".to_string()
        } else {
            format!("da_{value}")
        };
    }
    value = take_chars(&value, 32);
    if value.chars().count() < 3 {
        value = take_chars(&format!("{value}_da"), 32);
    }
    if reserved_users().contains(&value.as_str()) || !panel_username_shape_ok(&value) {
        let digest = sha1_prefix(&format!("{raw}{archive_name}"), 8);
        let stem_raw = replace_runs(&value, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
        });
        let stem = stem_raw.trim_matches('_');
        let stem = if stem.is_empty() { "user" } else { stem };
        value = take_chars(&format!("da_{}_{digest}", take_chars(stem, 18)), 32);
    }
    value
}

/// Source: `RESERVED_USERS`.
fn reserved_users() -> &'static [&'static str] {
    snpanel_core::types::RESERVED_LINUX_USERS
}

/// `USER_RE = ^[a-z_][a-z0-9_-]{2,31}$`.
fn panel_username_shape_ok(value: &str) -> bool {
    let count = value.chars().count();
    if !(3..=32).contains(&count) {
        return false;
    }
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn starts_with_letter_or_underscore(value: &str) -> bool {
    matches!(value.chars().next(), Some(c) if c.is_ascii_lowercase() || c == '_')
}

/// `re.sub(r"[^...]+", "_", value)` - a **run** of rejected characters
/// becomes one underscore, not one each.
fn replace_runs(value: &str, keep: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_run = false;
    for c in value.chars() {
        if keep(c) {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// `value[:n]` - **characters**, not bytes.
fn take_chars(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

/// `hashlib.sha1(...).hexdigest()[:n]`.
///
/// **Not a security primitive and not used as one.** It is a short stable
/// tag that keeps two archives whose names rewrite to the same string from
/// colliding; nothing compares it against anything an attacker supplies.
fn sha1_prefix(text: &str, n: usize) -> String {
    snpanel_core::types::sha1_hex(text)
        .chars()
        .take(n)
        .collect()
}

/// Source: `_normalize_domain`.
///
/// **This is not the panel's own `DOMAIN_RE`.** It allows a numeric final
/// label, because a DirectAdmin backup may hold one and refusing it would
/// drop a site without saying so.
pub fn normalize_domain(value: &str) -> Option<String> {
    let domain = snpanel_core::pyunicode::trim(value)
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    if labels.iter().all(|label| domain_label_ok(label)) {
        Some(domain)
    } else {
        None
    }
}

/// `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`, which is also
/// `_SUBDOMAIN_LABEL_RE`.
pub fn domain_label_ok(label: &str) -> bool {
    let bytes = label.as_bytes();
    let ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    match bytes.len() {
        0 => false,
        1 => ok(bytes[0]),
        n if n <= 63 => {
            ok(bytes[0]) && ok(bytes[n - 1]) && bytes[1..n - 1].iter().all(|b| ok(*b) || *b == b'-')
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// the files
// ---------------------------------------------------------------------------

/// Source: `_read_key_values`.
///
/// DirectAdmin's `.conf` files are `key=value`, but some are `key: value`,
/// so both are read - `=` first, because a value holding a colon is far
/// more likely than a key holding one. Keys lowercase, values lose one
/// layer of quotes.
pub fn read_key_values(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for raw in snpanel_core::pyunicode::split_lines(text) {
        let line = snpanel_core::pyunicode::trim(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => match line.split_once(':') {
                Some(pair) => pair,
                None => continue,
            },
        };
        values.insert(
            snpanel_core::pyunicode::trim(key).to_lowercase(),
            snpanel_core::pyunicode::trim(value)
                .trim_matches(|c| c == '\'' || c == '"')
                .to_string(),
        );
    }
    values
}

/// `path.read_text(encoding="utf-8", errors="ignore")`, or nothing.
///
/// A file that cannot be read is a file that is not there, which is what
/// every caller of this in the Python treats it as.
fn read_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    // `errors="ignore"` drops what will not decode rather than failing:
    // one stray byte in a customer's config must not lose the whole file.
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Source: `_discover_domain_pointers`, for one file's lines.
///
/// A pointer line is `pointer.tld=alias` or `=redirect`; a very old backup
/// lists one bare domain per line, which DirectAdmin treats as an alias.
/// **Anything that is not `redirect` is an alias**, which is the safe
/// reading: an alias serves the same site, a redirect sends visitors away.
pub fn parse_pointer_lines(
    text: &str,
    domain: &str,
    seen: &mut Vec<String>,
) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for raw in snpanel_core::pyunicode::split_lines(text) {
        let line = snpanel_core::pyunicode::trim(raw);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, mode) = match line.split_once('=') {
            Some((name, mode)) => (name, mode),
            None => (line, ""),
        };
        let Some(pointer) = normalize_domain(name) else {
            continue;
        };
        if pointer == domain || seen.contains(&pointer) {
            continue;
        }
        seen.push(pointer.clone());
        let mode = if snpanel_core::pyunicode::trim(mode).to_lowercase() == "redirect" {
            "redirect"
        } else {
            "alias"
        };
        found.push((pointer, mode.to_string()));
    }
    found
}

/// Source: `_discover_domain_pointers` - the three places DA writes them.
pub fn discover_domain_pointers(root: &Path, domain: &str) -> Vec<(String, String)> {
    let candidates = [
        root.join("backup").join(format!("{domain}.pointers")),
        root.join("domains").join(domain).join("domain.pointers"),
        root.join("domains").join(domain).join("pointers"),
    ];
    let mut seen = Vec::new();
    let mut found = Vec::new();
    for candidate in candidates {
        if !candidate.is_file() {
            continue;
        }
        let Some(text) = read_text(&candidate) else {
            continue;
        };
        found.extend(parse_pointer_lines(&text, domain, &mut seen));
    }
    found
}

/// Source: `_discover_subdomains`, for one file's lines.
///
/// DA records one label per line. A line may carry a value after `:` or
/// `=`, which is dropped: what is wanted is the label, and a version that
/// writes `blog:on` means the same subdomain as one that writes `blog`.
pub fn parse_subdomain_lines(text: &str, labels: &mut Vec<String>) {
    for raw in snpanel_core::pyunicode::split_lines(text) {
        let label = snpanel_core::pyunicode::trim(raw).to_lowercase();
        if label.is_empty() || label.starts_with('#') {
            continue;
        }
        let label = label.split(':').next().unwrap_or("");
        let label = label.split('=').next().unwrap_or("");
        let label = snpanel_core::pyunicode::trim(label);
        if domain_label_ok(label) && !labels.iter().any(|l| l == label) {
            labels.push(label.to_string());
        }
    }
}

/// Source: `_discover_subdomains` - the four places DA writes them.
pub fn discover_subdomains(root: &Path, parent_domain: &str) -> Vec<String> {
    let backup = root.join("backup");
    let candidates = [
        backup.join(parent_domain).join("subdomain.list"),
        backup.join(format!("{parent_domain}.subdomains")),
        backup
            .join("domains")
            .join(format!("{parent_domain}.subdomains")),
        backup
            .join("domains")
            .join(parent_domain)
            .join("subdomain.list"),
    ];
    let mut labels = Vec::new();
    for candidate in candidates {
        if !candidate.is_file() {
            continue;
        }
        if let Some(text) = read_text(&candidate) {
            parse_subdomain_lines(&text, &mut labels);
        }
    }
    labels
}

/// Source: `_find_backup_root`'s scoring.
///
/// A backup may be wrapped in one or more directories, so the root is
/// found rather than assumed. `domains/` beside a `backup/` is worth most,
/// then `mysql/`, then a `user.conf` inside the `backup/` itself.
pub fn backup_root_score(has_domains: bool, has_mysql: bool, has_user_conf: bool) -> i32 {
    let mut score = 1;
    if has_domains {
        score += 3;
    }
    if has_mysql {
        score += 2;
    }
    if has_user_conf {
        score += 3;
    }
    score
}

/// Source: `_find_backup_root`.
pub fn find_backup_root(extracted: &Path) -> PathBuf {
    for marker in ["backup", "domains", "mysql"] {
        if extracted.join(marker).exists() {
            return extracted.to_path_buf();
        }
    }
    let mut candidates: Vec<(i32, PathBuf)> = Vec::new();
    for path in walk_dirs(extracted, usize::MAX) {
        if path.file_name().and_then(|n| n.to_str()) != Some("backup") || !path.is_dir() {
            continue;
        }
        let Some(parent) = path.parent() else {
            continue;
        };
        candidates.push((
            backup_root_score(
                parent.join("domains").exists(),
                parent.join("mysql").exists(),
                path.join("user.conf").exists(),
            ),
            parent.to_path_buf(),
        ));
    }
    // `sorted(..., reverse=True)[0]` - a **stable** sort, so equal scores
    // keep the order `rglob` produced them in.
    candidates.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    match candidates.into_iter().next() {
        Some((_, parent)) => parent,
        None => extracted.to_path_buf(),
    }
}

/// Every directory under `root`, breadth-first, to a depth.
///
/// A depth limit because a customer's `node_modules` can nest further than
/// anything here needs to look, and an unbounded walk of one is minutes.
fn walk_dirs(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut level = vec![root.to_path_buf()];
    let mut depth = 0;
    while !level.is_empty() && depth < max_depth {
        let mut next = Vec::new();
        for dir in &level {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut children: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir() && !p.is_symlink())
                .collect();
            // `rglob` walks in directory order; sorting makes the result
            // the same on every filesystem, which a scan the operator
            // compares between runs needs.
            children.sort();
            found.extend(children.iter().cloned());
            next.extend(children);
        }
        level = next;
        depth += 1;
    }
    found
}

/// Source: `_source_for_domain`.
///
/// Where a domain's files are, trying the layouts DirectAdmin actually
/// writes before falling back to a search. The order is the Python's:
/// `public_html` first, because a `private_html` beside it is the TLS
/// twin and serving that as the site would show the wrong tree.
pub fn source_for_domain(root: &Path, domain: &str) -> Option<PathBuf> {
    let candidates = [
        root.join("domains").join(domain).join("public_html"),
        root.join("domains").join(domain).join("private_html"),
        root.join("domains").join(domain),
        root.join(domain).join("public_html"),
        root.join(domain),
    ];
    for candidate in candidates {
        if candidate.is_dir() {
            // A directory named for the domain that *contains* a
            // `public_html` is the account layout, not the document root.
            if candidate.file_name().and_then(|n| n.to_str()) == Some(domain)
                && candidate.join("public_html").exists()
            {
                return Some(candidate.join("public_html"));
            }
            return Some(candidate);
        }
    }
    // The fallback: any `public_html` whose path names this domain.
    for path in walk_dirs(root, 6) {
        if path.file_name().and_then(|n| n.to_str()) != Some("public_html") {
            continue;
        }
        let names_domain = path
            .components()
            .any(|c| c.as_os_str().to_string_lossy().to_lowercase() == domain);
        if names_domain {
            return Some(path);
        }
    }
    None
}

/// Source: `_discover_domains`.
///
/// Three places, in the Python's order, and a domain found in the first is
/// not added again by the second: `backup/domains.list`, then every
/// `<domain>.conf` in `backup/`, then every directory under `domains/`.
pub fn discover_domains(root: &Path) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let add = |domain: Option<String>, found: &mut Vec<String>| {
        if let Some(domain) = domain {
            if !found.contains(&domain) {
                found.push(domain);
            }
        }
    };

    if let Some(text) = read_text(&root.join("backup").join("domains.list")) {
        for line in snpanel_core::pyunicode::split_lines(&text) {
            add(normalize_domain(line), &mut found);
        }
    }
    for entry in sorted_entries(&root.join("backup")) {
        if entry.is_file() {
            if let Some(name) = entry.file_name().and_then(|n| n.to_str()) {
                if let Some(stem) = name.strip_suffix(".conf") {
                    add(normalize_domain(stem), &mut found);
                }
            }
        }
    }
    for entry in sorted_entries(&root.join("domains")) {
        if entry.is_dir() {
            if let Some(name) = entry.file_name().and_then(|n| n.to_str()) {
                add(normalize_domain(name), &mut found);
            }
        }
    }
    found
}

/// `sorted(path.iterdir())`, or nothing.
///
/// The Python's `iterdir()` is filesystem order for `_discover_domains`,
/// which means two scans of the same archive could list domains
/// differently. Sorting is the one place this does **not** reproduce the
/// Python exactly, and it is deliberate: an operator comparing two scans
/// should not see a diff that is only the readdir order.
fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    paths
}

/// Source: `_discover_username`.
pub fn discover_username(root: &Path, archive_name: &str) -> (String, String) {
    let user_conf = read_text(&root.join("backup").join("user.conf"))
        .map(|text| read_key_values(&text))
        .unwrap_or_default();
    let raw = ["username", "user", "name"]
        .iter()
        // DirectAdmin's own key for the account name is `name`; its
        // `account` key is the on/off flag, not a name.
        .find_map(|key| user_conf.get(*key).filter(|v| !v.is_empty()).cloned())
        .unwrap_or_else(|| archive_username(archive_name));
    let email = ["email", "emailaddress"]
        .iter()
        .find_map(|key| user_conf.get(*key).filter(|v| !v.is_empty()).cloned())
        .unwrap_or_default();
    (normalize_username(&raw, archive_name), email)
}

/// Source: `_sql_base_name`.
pub fn sql_base_name(name: &str) -> String {
    let lower = name.to_lowercase();
    for suffix in SQL_SUFFIXES {
        if lower.ends_with(suffix) {
            return name[..name.len() - suffix.len()].to_string();
        }
    }
    path_stem(name)
}

fn is_sql_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    SQL_SUFFIXES.iter().any(|s| lower.ends_with(s))
}

/// Source: `_discover_sql_files`.
///
/// `mysql/` and `backup/` first, because that is where DirectAdmin puts
/// them. Only if neither holds anything does it search the whole tree -
/// and then it skips anything under `domains/`, where a `.sql` is a
/// customer's own file rather than the account's database dump.
pub fn discover_sql_files(root: &Path) -> BTreeMap<String, PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    for directory in [root.join("mysql"), root.join("backup")] {
        if directory.exists() {
            files.extend(walk_files(&directory, 8).into_iter().filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(is_sql_name)
            }));
        }
    }
    if files.is_empty() {
        files.extend(walk_files(root, 8).into_iter().filter(|p| {
            let is_sql = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_sql_name);
            let under_domains = p
                .components()
                .any(|c| c.as_os_str().to_string_lossy().to_lowercase() == "domains");
            is_sql && !under_domains
        }));
    }
    // `result.setdefault(key, path)` - the **first** file for a key wins,
    // which is why the preferred directories are searched first.
    let mut result = BTreeMap::new();
    for path in files {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        result
            .entry(sql_base_name(name).to_lowercase())
            .or_insert(path);
    }
    result
}

/// Every regular file under `root`, to a depth, sorted.
fn walk_files(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut level = vec![root.to_path_buf()];
    let mut depth = 0;
    while !level.is_empty() && depth < max_depth {
        let mut next = Vec::new();
        for dir in &level {
            for path in sorted_entries(dir) {
                if path.is_symlink() {
                    continue;
                }
                if path.is_dir() {
                    next.push(path);
                } else if path.is_file() {
                    found.push(path);
                }
            }
        }
        level = next;
        depth += 1;
    }
    found
}

// ---------------------------------------------------------------------------
// what the application says about its own database
// ---------------------------------------------------------------------------

/// Source: `_candidate_config_dirs`.
///
/// Directories that may hold the app's database config, closest first.
/// Looking only at the top of the document root misses two very common
/// layouts: WordPress allows `wp-config.php` one level **above** the
/// document root, and plenty of accounts keep the site in a subfolder.
pub fn candidate_config_dirs(path: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let add = |candidate: PathBuf, found: &mut Vec<PathBuf>| {
        if candidate.is_dir() && !found.contains(&candidate) {
            found.push(candidate);
        }
    };
    add(path.to_path_buf(), &mut found);
    if let Some(parent) = path.parent() {
        add(parent.to_path_buf(), &mut found);
    }

    let mut level = vec![path.to_path_buf()];
    for _ in 0..APP_CONFIG_SCAN_DEPTH {
        let mut children = Vec::new();
        for parent in &level {
            for entry in sorted_entries(parent) {
                if !entry.is_dir() {
                    continue;
                }
                let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if name.starts_with('.')
                    || APP_CONFIG_SKIP_DIRS.contains(&name.to_lowercase().as_str())
                {
                    continue;
                }
                add(entry.clone(), &mut found);
                children.push(entry);
            }
        }
        level = children;
    }
    found
}

/// Source: `_parse_wp_config` - the four `define()` calls WordPress writes.
pub fn parse_wp_config(text: &str) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for key in ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"] {
        if let Some(value) = find_define(text, key) {
            found.insert(key.to_string(), value);
        }
    }
    found
}

/// `define\s*\(\s*['"]KEY['"]\s*,\s*['"]([^'"]*)['"]\s*\)`.
///
/// Hand-written because this workspace has no regex crate. The quote that
/// opens the value is the one that must close it, which is what keeps a
/// password containing the *other* quote from truncating the match - the
/// character class `[^'"]*` in the Python forbids both, so a password with
/// either simply does not match, and that is reproduced.
fn find_define(text: &str, key: &str) -> Option<String> {
    let mut rest = text;
    while let Some(index) = rest.find("define") {
        let after = &rest[index + "define".len()..];
        if let Some(value) = match_define_tail(after, key) {
            return Some(value);
        }
        rest = &rest[index + "define".len()..];
    }
    None
}

fn match_define_tail(after: &str, key: &str) -> Option<String> {
    let s = skip_ws(after);
    let s = s.strip_prefix('(')?;
    let s = skip_ws(s);
    let (found_key, s) = read_quoted(s)?;
    if found_key != key {
        return None;
    }
    let s = skip_ws(s);
    let s = s.strip_prefix(',')?;
    let s = skip_ws(s);
    let (value, s) = read_quoted(s)?;
    let s = skip_ws(s);
    s.strip_prefix(')')?;
    Some(value)
}

fn skip_ws(text: &str) -> &str {
    text.trim_start_matches(|c: char| c.is_ascii_whitespace())
}

/// `['"]([^'"]*)['"]` - the value may hold **neither** quote, which is the
/// Python's character class and not an oversight to tidy.
fn read_quoted(text: &str) -> Option<(String, &str)> {
    let mut chars = text.char_indices();
    let (_, opener) = chars.next()?;
    if opener != '\'' && opener != '"' {
        return None;
    }
    let body_start = opener.len_utf8();
    for (offset, c) in text[body_start..].char_indices() {
        if c == '\'' || c == '"' {
            if c != opener {
                // A different quote inside means `[^'"]*` never matched.
                return None;
            }
            let value = text[body_start..body_start + offset].to_string();
            return Some((value, &text[body_start + offset + c.len_utf8()..]));
        }
    }
    None
}

/// Source: `_parse_dotenv_config` - Laravel and everything that copied it.
pub fn parse_dotenv_config(text: &str) -> BTreeMap<String, String> {
    let values = read_key_values(text);
    let mut result = BTreeMap::new();
    for (from, to) in [
        ("db_database", "DB_NAME"),
        ("db_username", "DB_USER"),
        ("db_password", "DB_PASSWORD"),
        ("db_host", "DB_HOST"),
    ] {
        // `if values.get(key):` - an **empty** value is skipped, so a
        // `.env` with `DB_PASSWORD=` does not overwrite a real one found
        // by an earlier parser.
        if let Some(value) = values.get(from).filter(|v| !v.is_empty()) {
            result.insert(to.to_string(), value.clone());
        }
    }
    result
}

/// Source: `_parse_php_variable_config` - Joomla's `configuration.php` and
/// the many scripts shaped like it.
pub fn parse_php_variable_config(text: &str) -> BTreeMap<String, String> {
    let mappings: [(&str, &[&str]); 4] = [
        ("DB_NAME", &["db", "db_name", "database", "db_database"]),
        (
            "DB_USER",
            &["user", "dbuser", "db_user", "db_username", "username"],
        ),
        ("DB_PASSWORD", &["password", "dbpass", "db_password"]),
        ("DB_HOST", &["host", "db_host"]),
    ];
    let mut result = BTreeMap::new();
    for (key, names) in mappings {
        // The **first** name that matches wins, in the Python's order.
        for name in names {
            if let Some(value) = find_php_variable(text, name) {
                result.insert(key.to_string(), value);
                break;
            }
        }
    }
    result
}

/// `(?:public\s+)?\$NAME\s*=\s*['"]([^'"]*)['"]\s*;`.
fn find_php_variable(text: &str, name: &str) -> Option<String> {
    let needle = format!("${name}");
    let mut base = 0usize;
    while let Some(index) = text[base..].find(&needle) {
        let at = base + index;
        let after_name = &text[at + needle.len()..];
        // No word boundary here, and none in the Python either: the
        // pattern is `\$name\s*=`, so `$db` inside `$dbuser` fails at the
        // `=` rather than at the name. A boundary check would be a guard
        // that cannot change an answer, which is a guard nobody can test.
        if let Some(value) = match_php_assignment(after_name) {
            return Some(value);
        }
        base = at + needle.len();
    }
    None
}

fn match_php_assignment(after: &str) -> Option<String> {
    let s = skip_ws(after);
    let s = s.strip_prefix('=')?;
    let s = skip_ws(s);
    let (value, s) = read_quoted(s)?;
    let s = skip_ws(s);
    s.strip_prefix(';')?;
    Some(value)
}

/// Source: `_locate_app_db_config` then `_parse_app_db_config`.
///
/// The three parsers are tried **per directory**, closest first, and the
/// first that yields a `DB_NAME` wins. A site with both a `.env` and a
/// stale `wp-config.php` takes whichever is nearer the document root,
/// which is the one actually serving.
pub fn parse_app_db_config(path: &Path) -> BTreeMap<String, String> {
    for directory in candidate_config_dirs(path) {
        for (file, parser) in [
            (
                "wp-config.php",
                parse_wp_config as fn(&str) -> BTreeMap<String, String>,
            ),
            (".env", parse_dotenv_config),
            ("configuration.php", parse_php_variable_config),
        ] {
            let candidate = directory.join(file);
            if !candidate.exists() {
                continue;
            }
            let Some(text) = read_text(&candidate) else {
                continue;
            };
            let values = parser(&text);
            if values.get("DB_NAME").is_some_and(|v| !v.is_empty()) {
                return values;
            }
        }
    }
    BTreeMap::new()
}

/// Source: `_has_php_files`.
fn has_php_files(path: &Path) -> bool {
    walk_files(path, 8).iter().any(|p| {
        let lower = p.to_string_lossy().to_lowercase();
        lower.ends_with(".php") || lower.ends_with(".phtml")
    })
}

/// Source: `_detect_app_type`.
///
/// A `wp-config.php` **or** a `wp-config-sample.php` means WordPress: the
/// sample is what an install that has not been run yet still has, and it
/// is the difference between importing a site as WordPress and importing
/// it as a directory of PHP.
pub fn detect_app_type(source: Option<&Path>) -> &'static str {
    let Some(source) = source else {
        return "php";
    };
    for directory in candidate_config_dirs(source) {
        if directory.join("wp-config.php").exists()
            || directory.join("wp-config-sample.php").exists()
        {
            return "wordpress";
        }
    }
    if has_php_files(source) {
        "php"
    } else {
        "static"
    }
}

/// Source: `_matched_sql_for_config`.
///
/// **A single site with a single dump takes it, named or not.** That is
/// the common shape of a one-domain account, and refusing to match it
/// would leave the database behind for a config this importer could not
/// read.
pub fn matched_sql_for_config<'a>(
    app_config: &BTreeMap<String, String>,
    sql_files: &'a BTreeMap<String, PathBuf>,
    single_site: bool,
) -> (String, Option<&'a PathBuf>) {
    if let Some(db_name) = app_config.get("DB_NAME").filter(|v| !v.is_empty()) {
        let key = db_name.to_lowercase();
        if let Some(path) = sql_files.get(&key) {
            return (key, Some(path));
        }
    }
    if single_site && sql_files.len() == 1 {
        let (key, path) = sql_files.iter().next().expect("one entry");
        return (key.clone(), Some(path));
    }
    (String::new(), None)
}

// ---------------------------------------------------------------------------
// the databases
// ---------------------------------------------------------------------------

/// Source: `_normalize_db_identifier`.
///
/// A database name from another panel has to be unique **on this machine**,
/// not in the archive. A collision takes a hash of the original and then a
/// counter, so an import can bring in two customers who both called their
/// database `wordpress`.
pub fn normalize_db_identifier(raw: &str, fallback: &str, existing: &[String]) -> String {
    let source = if raw.is_empty() { fallback } else { raw };
    let lowered = snpanel_core::pyunicode::trim(source).to_lowercase();
    let mut value = replace_runs(&lowered, |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
    });
    value = value.trim_matches('_').to_string();
    if value.is_empty() {
        value = fallback.to_string();
    }
    value = take_chars(&value, 64);
    if !existing.contains(&value) && db_identifier_ok(&value) {
        return value;
    }

    let digest = sha1_prefix(&format!("{raw}{fallback}"), 6);
    let trimmed = take_chars(&value, 55);
    let stem = trimmed.trim_matches('_').to_string();
    let stem = if stem.is_empty() {
        let fb = take_chars(fallback, 55).trim_matches('_').to_string();
        if fb.is_empty() {
            "db".to_string()
        } else {
            fb
        }
    } else {
        stem
    };
    let mut candidate = take_chars(&format!("{stem}_{digest}"), 64);
    let mut counter = 2;
    while existing.contains(&candidate) || !db_identifier_ok(&candidate) {
        let suffix = format!("_{counter}");
        let head = take_chars(&stem, 64 - suffix.chars().count());
        candidate = format!("{head}{suffix}");
        counter += 1;
    }
    candidate
}

/// `DB_RE = ^[a-z0-9_]{1,64}$`.
fn db_identifier_ok(value: &str) -> bool {
    let count = value.chars().count();
    (1..=64).contains(&count)
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// `DA_PASSWORD_HASH_RE = ^\*[0-9A-Fa-f]{40}$`.
///
/// `mysql_native_password` stores a star and forty hex characters.
/// DirectAdmin's `<db>.conf` keeps the original hash, and handing it back
/// to MySQL lets the imported site keep its existing config untouched -
/// which is the difference between a site that is still up after an
/// import and one that is not.
pub fn is_native_password_hash(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('*') else {
        return false;
    };
    rest.len() == 40 && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What a DirectAdmin `<db>.conf` says the password is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaPassword {
    pub password: String,
    pub password_hash: String,
}

impl DaPassword {
    fn clear(value: &str) -> Self {
        Self {
            password: value.to_string(),
            password_hash: String::new(),
        }
    }

    fn hashed(value: &str) -> Self {
        Self {
            password: String::new(),
            password_hash: value.to_string(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.password.is_empty() && self.password_hash.is_empty()
    }
}

/// Source: `_decode_da_conf_password`.
///
/// Two shapes turn up in the wild and both are read: a flat
/// `passwd=...` line, and the whole grant packed into one
/// `&`-delimited, URL-encoded query string. The **first** line that
/// yields anything wins, which is why a `user=` line before the password
/// does not stop the search.
pub fn decode_da_conf_password(text: &str) -> DaPassword {
    for raw in snpanel_core::pyunicode::split_lines(text) {
        let line = snpanel_core::pyunicode::trim(raw);
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (key, value) = line.split_once('=').expect("a separator");
        let key = snpanel_core::pyunicode::trim(key).to_lowercase();
        let value = snpanel_core::pyunicode::trim(value);

        if matches!(
            key.as_str(),
            "passwd" | "password" | "pass" | "db_password" | "dbpass"
        ) {
            let decoded = percent_decode(value);
            let decoded = decoded.trim_matches(|c| c == '\'' || c == '"');
            if !decoded.is_empty() {
                return if is_native_password_hash(decoded) {
                    DaPassword::hashed(decoded)
                } else {
                    DaPassword::clear(decoded)
                };
            }
        }
        // The packed shape: `<db>=accesshosts=...&passwd=...&plugin=...`.
        let lowered = value.to_lowercase();
        if value.contains('&') && (lowered.contains("passwd=") || lowered.contains("password=")) {
            for name in ["passwd", "password", "pass"] {
                let Some(got) = query_field(value, name) else {
                    continue;
                };
                let got = snpanel_core::pyunicode::trim(&got).to_string();
                if got.is_empty() {
                    continue;
                }
                return if is_native_password_hash(&got) {
                    DaPassword::hashed(&got)
                } else {
                    DaPassword::clear(&got)
                };
            }
        }
    }
    DaPassword::default()
}

/// `urllib.parse.parse_qs(value, keep_blank_values=True)[name][0]`.
fn query_field(value: &str, name: &str) -> Option<String> {
    for pair in value.split('&') {
        let (key, raw) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(key) == name {
            return Some(percent_decode(raw));
        }
    }
    None
}

/// `urllib.parse.unquote`.
///
/// `%2A` is how DirectAdmin writes the star that opens a
/// `mysql_native_password` hash, so a decoder that skipped this would see
/// the hash as an ordinary password and set it as one - locking the
/// customer out of their own database.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = &text[index + 1..index + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    // `unquote` decodes as UTF-8 with `errors="replace"`.
    String::from_utf8_lossy(&out).into_owned()
}

/// Source: `_da_db_conf_candidates`.
///
/// DirectAdmin has moved these between versions - beside the dump, under
/// `backup/`, under `mysql/` - and the compression suffix on the dump is
/// not always part of the conf name, so the stem is matched
/// case-insensitively.
pub fn da_conf_candidates(sql_file: &Path, root: &Path, base: &str) -> Vec<PathBuf> {
    let mut candidates = vec![
        sql_file.with_file_name(format!("{base}.conf")),
        root.join("backup").join(format!("{base}.conf")),
    ];
    let parent = sql_file.parent().map(Path::to_path_buf);
    let directories: Vec<PathBuf> = parent
        .into_iter()
        .chain([root.join("backup"), root.join("mysql")])
        .collect();
    for directory in directories {
        if !directory.is_dir() {
            continue;
        }
        for entry in walk_files(&directory, 8) {
            if entry.extension().and_then(|e| e.to_str()) != Some("conf") {
                continue;
            }
            let stem = entry
                .file_stem()
                .map(|s| s.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if stem == base.to_lowercase() && !candidates.contains(&entry) {
                candidates.push(entry);
            }
        }
    }
    candidates
}

/// Source: `_da_db_credentials`.
pub fn da_db_credentials(sql_file: &Path, root: &Path) -> DaPassword {
    let name = sql_file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = sql_base_name(&name);
    for candidate in da_conf_candidates(sql_file, root, &base) {
        if !candidate.is_file() {
            continue;
        }
        let Some(text) = read_text(&candidate) else {
            continue;
        };
        let found = decode_da_conf_password(&text);
        if !found.is_empty() {
            return found;
        }
    }
    DaPassword::default()
}

/// Which secret an imported database user gets, and whether it is reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPassword {
    pub password: String,
    pub password_hash: String,
    /// `True` when the secret came from the backup rather than being made.
    pub reused: bool,
}

/// Source: `_import_db_password`.
///
/// **Reusing what the site already carries is what keeps it online.** The
/// panel rewrites the configs it knows about, but a custom include or a
/// second copy outside the document root would still point at the old
/// secret. So: the application's own config first, then the hash from
/// DirectAdmin's `<db>.conf`, then a clear password from the same place,
/// and only then a fresh one.
pub fn import_db_password(
    app_config: &BTreeMap<String, String>,
    da_credentials: &DaPassword,
    generated: &str,
) -> ImportPassword {
    if let Some(from_config) = app_config.get("DB_PASSWORD").filter(|v| !v.is_empty()) {
        return ImportPassword {
            password: from_config.clone(),
            password_hash: String::new(),
            reused: true,
        };
    }
    if !da_credentials.password_hash.is_empty() {
        return ImportPassword {
            password: String::new(),
            password_hash: da_credentials.password_hash.clone(),
            reused: true,
        };
    }
    if !da_credentials.password.is_empty() {
        return ImportPassword {
            password: da_credentials.password.clone(),
            password_hash: String::new(),
            reused: true,
        };
    }
    ImportPassword {
        password: generated.to_string(),
        password_hash: String::new(),
        reused: false,
    }
}

/// Source: the `renamed and reused` check in `_create_panel_database`.
///
/// **A reused secret only helps if the site's config still points at this
/// database and this user.** If normalisation renamed either, the config
/// is going to be rewritten anyway, so a fresh password costs nothing and
/// a stale hash would cost the customer their database.
pub fn rename_invalidates_reuse(
    old_db: &str,
    new_db: &str,
    old_user: Option<&str>,
    new_user: &str,
) -> bool {
    let renamed_db =
        !old_db.is_empty() && new_db != snpanel_core::pyunicode::trim(old_db).to_lowercase();
    let renamed_user = match old_user {
        Some(old) if !old.is_empty() => {
            new_user != snpanel_core::pyunicode::trim(old).to_lowercase()
        }
        _ => false,
    };
    renamed_db || renamed_user
}

/// Source: `_unique_email`.
///
/// A panel user needs an address, the backup may not carry a usable one,
/// and the column is unique. The local part keeps only what an address may
/// hold; if nothing survives, the username stands in.
pub fn unique_email(
    username: &str,
    preferred: &str,
    domains: &[String],
    taken: &[String],
) -> String {
    let domain = domains
        .first()
        .cloned()
        .unwrap_or_else(|| "import.local".to_string());
    // `preferred if preferred and "@" in preferred else f"{username}@{domain}"`.
    let base = if !preferred.is_empty() && preferred.contains('@') {
        preferred.to_string()
    } else {
        format!("{username}@{domain}")
    };
    let (local, host) = base.split_once('@').unwrap_or((base.as_str(), ""));
    let local = replace_runs(local, |c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '+' || c == '-'
    });
    // `re.sub(...)` there replaces with a **dot**, not an underscore.
    let local = local.replace('_', ".");
    let local = local.trim_matches('.').to_string();
    let local = if local.is_empty() {
        username.to_string()
    } else {
        local
    };
    let host = if host.is_empty() { &domain } else { host };

    let mut candidate = format!("{local}@{host}");
    let mut counter = 2;
    while taken.contains(&candidate) {
        candidate = format!("{local}+{counter}@{host}");
        counter += 1;
    }
    candidate
}

/// Source: `_replace_define`.
///
/// Rewrites one `define()` in a `wp-config.php`, or **appends** it when
/// there is none - because a config that never named the database still
/// has to name the new one, and a site that comes back pointing at
/// nothing is a site that did not come back.
pub fn replace_define(text: &str, key: &str, value: &str) -> String {
    if let Some((value_start, value_end)) = find_define_value_span(text, key) {
        let mut out = String::with_capacity(text.len() + value.len());
        out.push_str(&text[..value_start]);
        out.push_str(&format!("'{value}'"));
        out.push_str(&text[value_end..]);
        return out;
    }
    format!("{text}\ndefine('{key}', '{value}');\n")
}

/// The span of the **value's quoted literal** in the first matching
/// `define\s*\(\s*['"]KEY['"]\s*,\s*['"][^'"]*['"]\s*\)\s*;`.
///
/// Only the value is replaced. The Python's substitution keeps its two
/// captured groups - everything before the value and everything after it -
/// so `define("DB_NAME", "old");` becomes `define("DB_NAME", 'new');`,
/// **keeping the key's double quotes**. Rewriting the whole statement
/// would be tidier and would not be what the Python leaves on disk.
fn find_define_value_span(text: &str, key: &str) -> Option<(usize, usize)> {
    let mut base = 0usize;
    while let Some(index) = text[base..].find("define") {
        let at = base + index;
        let after_offset = at + "define".len();
        if let Some((value_start, value_end)) = match_define_statement(&text[after_offset..], key) {
            return Some((after_offset + value_start, after_offset + value_end));
        }
        base = after_offset;
    }
    None
}

/// Where the value's quoted literal starts and ends, within `after`.
fn match_define_statement(after: &str, key: &str) -> Option<(usize, usize)> {
    let s = skip_ws(after);
    let s = s.strip_prefix('(')?;
    let s = skip_ws(s);
    let (found_key, s) = read_quoted(s)?;
    if found_key != key {
        return None;
    }
    let s = skip_ws(s);
    let s = s.strip_prefix(',')?;
    let s = skip_ws(s);
    let value_start = after.len() - s.len();
    let (_value, s) = read_quoted(s)?;
    let value_end = after.len() - s.len();
    // The statement has to close, or this `define` is not the one.
    let s = skip_ws(s);
    let s = s.strip_prefix(')')?;
    let s = skip_ws(s);
    s.strip_prefix(';')?;
    Some((value_start, value_end))
}

/// Source: `_update_config_dir`.
///
/// After an import has moved a site's database, the site has to be told
/// where it went. Three shapes are rewritten in place - WordPress, a
/// `.env`, and a Joomla-style `configuration.php` - and each is only
/// touched if it is there.
///
/// **The host is not the same in all three.** WordPress and Joomla get
/// `localhost`, which uses the MySQL socket; a `.env` gets `127.0.0.1`,
/// because Laravel's PDO driver treats `localhost` as a socket it may not
/// be configured for. That is the Python's choice and it is not a typo.
pub fn update_config_dir(public: &Path, db_name: &str, db_user: &str, db_password: &str) {
    let wp = public.join("wp-config.php");
    if wp.exists() {
        if let Some(text) = read_text(&wp) {
            let mut out = replace_define(&text, "DB_NAME", db_name);
            out = replace_define(&out, "DB_USER", db_user);
            out = replace_define(&out, "DB_PASSWORD", db_password);
            out = replace_define(&out, "DB_HOST", "localhost");
            let _ = std::fs::write(&wp, out);
        }
    }

    let env_file = public.join(".env");
    if env_file.exists() {
        if let Some(text) = read_text(&env_file) {
            let _ = std::fs::write(
                &env_file,
                rewrite_dotenv(&text, db_name, db_user, db_password),
            );
        }
    }

    let config_php = public.join("configuration.php");
    if config_php.exists() {
        if let Some(text) = read_text(&config_php) {
            let _ = std::fs::write(
                &config_php,
                rewrite_php_config(&text, db_name, db_user, db_password),
            );
        }
    }
}

/// Source: the `.env` half of `_update_config_dir`.
///
/// A key already there is rewritten **in place**, keeping the order of the
/// file; one that is missing is appended. The comparison is
/// case-insensitive and allows a space before the `=`, because a hand-
/// edited `.env` has both - but what is written back is always the
/// canonical upper-case spelling.
pub fn rewrite_dotenv(text: &str, db_name: &str, db_user: &str, db_password: &str) -> String {
    let replacements: [(&str, &str); 4] = [
        ("DB_DATABASE", db_name),
        ("DB_USERNAME", db_user),
        ("DB_PASSWORD", db_password),
        ("DB_HOST", "127.0.0.1"),
    ];
    let mut out: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();

    for line in snpanel_core::pyunicode::split_lines(text) {
        let stripped = snpanel_core::pyunicode::trim(line).to_lowercase();
        let mut matched = false;
        for (key, value) in replacements {
            let lower = key.to_lowercase();
            if stripped.starts_with(&format!("{lower}="))
                || stripped.starts_with(&format!("{lower} ="))
            {
                out.push(format!("{key}={value}"));
                if !seen.contains(&key) {
                    seen.push(key);
                }
                matched = true;
                break;
            }
        }
        if !matched {
            out.push(line.to_string());
        }
    }
    for (key, value) in replacements {
        if !seen.contains(&key) {
            out.push(format!("{key}={value}"));
        }
    }
    // `"\n".join(out) + "\n"` - exactly one trailing newline, whatever the
    // file had.
    format!("{}\n", out.join("\n"))
}

/// Source: the `configuration.php` half of `_update_config_dir`.
///
/// **This requires the `public` keyword and the parser does not.** The
/// pattern here is `public\s+\$?<key>\s*=\s*'...'\s*;`, so a bare
/// `$db = 'x';` is *read* by [`parse_php_variable_config`] and then left
/// alone by this. That asymmetry is the Python's; reproducing it means an
/// imported Joomla site whose config is written that way keeps pointing at
/// the old database, which is a bug worth knowing about rather than one to
/// quietly fix on the way past.
pub fn rewrite_php_config(text: &str, db_name: &str, db_user: &str, db_password: &str) -> String {
    let pairs: [(&str, &str); 10] = [
        ("db", db_name),
        ("db_name", db_name),
        ("user", db_user),
        ("dbuser", db_user),
        ("db_username", db_user),
        ("password", db_password),
        ("dbpass", db_password),
        ("db_password", db_password),
        ("host", "localhost"),
        ("db_host", "localhost"),
    ];
    let mut out = text.to_string();
    for (key, value) in pairs {
        // `count=1`: only the first of each key.
        if let Some((start, end)) = find_public_assignment_span(&out, key) {
            let mut next = String::with_capacity(out.len() + value.len());
            next.push_str(&out[..start]);
            next.push_str(&format!("'{value}'"));
            next.push_str(&out[end..]);
            out = next;
        }
    }
    out
}

/// The span of the quoted value in `public\s+\$?KEY\s*=\s*['"][^'"]*['"]\s*;`.
fn find_public_assignment_span(text: &str, key: &str) -> Option<(usize, usize)> {
    let mut base = 0usize;
    while let Some(index) = text[base..].find("public") {
        let at = base + index;
        let after_offset = at + "public".len();
        let after = &text[after_offset..];
        if let Some((value_start, value_end)) = match_public_assignment(after, key) {
            return Some((after_offset + value_start, after_offset + value_end));
        }
        base = after_offset;
    }
    None
}

fn match_public_assignment(after: &str, key: &str) -> Option<(usize, usize)> {
    // `public\s+` - at least one space, unlike the optional one elsewhere.
    let trimmed = skip_ws(after);
    if trimmed.len() == after.len() {
        return None;
    }
    // `\$?` - the dollar is optional.
    let s = trimmed.strip_prefix('$').unwrap_or(trimmed);
    let s = s.strip_prefix(key)?;
    // The name must end here, or `db` would match inside `dbuser`.
    match s.chars().next() {
        Some(c) if c.is_ascii_alphanumeric() || c == '_' => return None,
        _ => {}
    }
    let s = skip_ws(s);
    let s = s.strip_prefix('=')?;
    let s = skip_ws(s);
    let value_start = after.len() - s.len();
    let (_value, s) = read_quoted(s)?;
    let value_end = after.len() - s.len();
    let s = skip_ws(s);
    s.strip_prefix(';')?;
    Some((value_start, value_end))
}

// ---------------------------------------------------------------------------
// opening the archive
// ---------------------------------------------------------------------------

/// `tempfile.TemporaryDirectory(prefix=..., dir=STAGE_BASE)`.
///
/// Created with `O_EXCL` semantics through `create_dir`, which fails if
/// the name is taken - so two scans running at once cannot be handed the
/// same directory and unpack into each other.
pub fn make_stage_dir(base: &Path, prefix: &str) -> Option<PathBuf> {
    use rand::RngCore;
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let candidate = base.join(format!("{prefix}{suffix}"));
        if std::fs::create_dir(&candidate).is_ok() {
            return Some(candidate);
        }
    }
    None
}

/// Source: `_safe_extract_tar`, and the `_checked_members` generator it
/// consumes.
///
/// Three things are refused, and each has cost somebody a machine
/// somewhere:
///
/// - **A member that escapes the destination.** `../../etc/cron.d/x` in a
///   tar is the oldest trick there is, and this archive was uploaded
///   through a browser.
/// - **Every link, hard or symbolic.** DirectAdmin backups contain none
///   this importer needs, and skipping them keeps the extracted tree from
///   holding anything that points outside the staging directory - so a
///   later pass that copies files cannot be walked out of it.
/// - **Anything that is not a file or a directory.** A device node or a
///   socket in a customer's backup is not something to recreate as root.
///
/// The Python's `filter="data"` does the rest - the ownership and mode
/// clamping - which here is [`crate::tarfilter::data_filter`].
pub fn safe_extract_tar(archive: &Path, destination: &Path) -> Result<(), String> {
    std::fs::create_dir_all(destination).map_err(|e| e.to_string())?;
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let reader = std::io::BufReader::new(file);

    // One `match` per compression rather than a boxed reader, because each
    // decoder has its own type and the tar reader is generic over it.
    if name.ends_with(".tar.zst") || name.ends_with(".tzst") {
        let decoder =
            ruzstd::decoding::StreamingDecoder::new(reader).map_err(|e| format!("zstd: {e}"))?;
        extract_members(tar::Archive::new(decoder), destination, &name)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let decoder = flate2::read::GzDecoder::new(reader);
        extract_members(tar::Archive::new(decoder), destination, &name)
    } else if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
        let decoder = bzip2_rs::DecoderReader::new(reader);
        extract_members(tar::Archive::new(decoder), destination, &name)
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        // `lzma-rs` decodes into memory rather than streaming, so the
        // whole archive is held at once. A DirectAdmin backup can be tens
        // of gigabytes, which is why `.tar.xz` is the one shape this
        // refuses above a limit rather than trying and being killed.
        let mut input =
            std::io::BufReader::new(std::fs::File::open(archive).map_err(|e| e.to_string())?);
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut input, &mut out).map_err(|e| format!("xz: {e}"))?;
        extract_members(
            tar::Archive::new(std::io::Cursor::new(out)),
            destination,
            &name,
        )
    } else {
        extract_members(tar::Archive::new(reader), destination, &name)
    }
}

/// The member loop, shared by every compression.
///
/// **A single pass.** The Python's comment says why: a `.tar.zst` is
/// decompressed through a pipe, so the stream is not seekable and can only
/// be walked once - validating in a separate pass first would leave
/// nothing for the extraction to read. The same is true of every streaming
/// decoder here.
fn extract_members<R: std::io::Read>(
    mut archive: tar::Archive<R>,
    destination: &Path,
    archive_name: &str,
) -> Result<(), String> {
    let base = crate::files::resolve(destination);
    let entries = archive.entries().map_err(|e| e.to_string())?;
    for entry in entries {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let raw = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();

        let target = crate::files::resolve(&destination.join(&raw));
        if !target.starts_with(&base) {
            return Err(format!("Unsafe path in {archive_name}: {raw}"));
        }
        let kind = entry.header().entry_type();
        // The Python refuses links explicitly and then refuses anything
        // that is not a file or a directory. The second check already
        // covers the first - a link is neither - so this one cannot
        // change an answer. It is the Python's line and it stays, said
        // out loud because a mutation of it has nothing to catch and the
        // next person to notice should find the reason, not the puzzle.
        if kind.is_symlink() || kind.is_hard_link() {
            continue;
        }
        if !(kind.is_file() || kind.is_dir()) {
            continue;
        }
        if kind.is_dir() {
            std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        entry.unpack(&target).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Source: `_extract_nested_domain_archives`.
///
/// Newer DirectAdmin backups store a domain's files as
/// `backup/example.com.tar.gz` instead of an extracted
/// `domains/example.com/` tree. Each one is unpacked so the rest of the
/// importer sees the layout it expects.
///
/// **One bad archive must not stop the import**: a failure logs, removes
/// the half-made directory and moves on, because the other domains in the
/// account are still worth bringing in.
pub fn extract_nested_domain_archives(root: &Path) {
    let backup_dir = root.join("backup");
    if !backup_dir.is_dir() {
        return;
    }
    let domains_dir = root.join("domains");
    for item in sorted_entries(&backup_dir) {
        if !item.is_file() {
            continue;
        }
        let Some(name) = item.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !crate::routes::maintenance::ARCHIVE_SUFFIXES
            .iter()
            .any(|s| name.to_lowercase().ends_with(s))
        {
            continue;
        }
        let Some(domain) = normalize_domain(&strip_archive_suffix(name)) else {
            continue;
        };
        let target_dir = domains_dir.join(&domain);
        if target_dir.exists() {
            continue;
        }
        if std::fs::create_dir_all(&target_dir).is_err() {
            continue;
        }
        match safe_extract_tar(&item, &target_dir) {
            Ok(()) => unwrap_single_wrapper(&target_dir),
            Err(message) => {
                tracing::warn!("could not extract {name}: {message}");
                let _ = std::fs::remove_dir_all(&target_dir);
            }
        }
    }
}

/// DA sometimes wraps the whole domain in one subdirectory.
///
/// Source: the `len(children) == 1` block. The wrapper is unwrapped, but
/// an archive whose own root **is** `public_html/` is left alone - that is
/// the document root, not a wrapper, and flattening it would move the
/// site's files one level up into nothing.
fn unwrap_single_wrapper(target_dir: &Path) {
    let children = sorted_entries(target_dir);
    if children.len() != 1 {
        return;
    }
    let inner = &children[0];
    if !inner.is_dir() {
        return;
    }
    let name = inner
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name == "public_html" || name == "private_html" {
        return;
    }
    if !(inner.join("public_html").exists() || inner.join("private_html").exists()) {
        return;
    }
    for child in sorted_entries(inner) {
        let Some(base) = child.file_name() else {
            continue;
        };
        let _ = std::fs::rename(&child, target_dir.join(base));
    }
    let _ = std::fs::remove_dir(inner);
}

// ---------------------------------------------------------------------------
// the scan
// ---------------------------------------------------------------------------

/// One site the scan found.
#[derive(Debug, Clone)]
pub struct ScannedDomain {
    pub domain: String,
    pub source: Option<PathBuf>,
}

/// Source: the body of `scan_da_backup`, once the archive is extracted.
///
/// Separated from the extraction so it can be run against a directory
/// laid out by hand, which is what the tests do: the interesting part of
/// a scan is what it makes of a layout, not that a tar can be opened.
pub fn scan_extracted(root: &Path, archive_name: &str) -> Value {
    let (username, email) = discover_username(root, archive_name);
    let domains = discover_domains(root);
    let sql_files = discover_sql_files(root);

    // DirectAdmin subdomains come in as their own websites, nested under
    // the parent's document root; they are listed beside the parents.
    let mut targets: Vec<ScannedDomain> = domains
        .iter()
        .map(|domain| ScannedDomain {
            domain: domain.clone(),
            source: source_for_domain(root, domain),
        })
        .collect();
    let parents = targets.clone();
    for parent in &parents {
        let parent_public = parent.source.clone();
        for label in discover_subdomains(root, &parent.domain) {
            let Some(fqdn) = normalize_domain(&format!("{label}.{}", parent.domain)) else {
                continue;
            };
            if domains.contains(&fqdn) || targets.iter().any(|t| t.domain == fqdn) {
                continue;
            }
            let src = parent_public.as_ref().map(|p| p.join(&label));
            targets.push(ScannedDomain {
                domain: fqdn,
                source: src.filter(|p| p.is_dir()),
            });
        }
    }

    let single_site = targets.len() == 1;
    let mut domain_entries: Vec<Value> = Vec::new();
    let mut assigned: Vec<String> = Vec::new();
    for target in &targets {
        let app_type = detect_app_type(target.source.as_deref());
        let app_config = match &target.source {
            Some(source) => parse_app_db_config(source),
            None => BTreeMap::new(),
        };
        let (matched_key, matched_sql) =
            matched_sql_for_config(&app_config, &sql_files, single_site);

        let db_name = app_config
            .get("DB_NAME")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or(matched_key);
        if !db_name.is_empty() {
            assigned.push(db_name.to_lowercase());
        }
        domain_entries.push(json!({
            "domain": target.domain,
            "app_type": app_type,
            "has_files": target.source.is_some(),
            "db_name": db_name,
            "db_user": app_config.get("DB_USER").cloned().unwrap_or_default(),
            "has_sql_dump": matched_sql.is_some(),
            "aliases": discover_domain_pointers(root, &target.domain)
                .into_iter()
                .map(|(name, mode)| json!({ "domain": name, "mode": mode }))
                .collect::<Vec<_>>(),
        }));
    }

    // Every dump no site claimed, so an operator can see a database that
    // would otherwise be imported with nothing pointing at it.
    let databases: Vec<Value> = sql_files
        .iter()
        .filter(|(key, _)| !assigned.contains(key))
        .map(|(key, path)| {
            json!({
                "db_name": key,
                "sql_file": path.to_string_lossy(),
                "has_sql_dump": true,
            })
        })
        .collect();

    json!({
        "username": username,
        "email": email,
        "domains": domain_entries,
        "databases": databases,
    })
}

// ---------------------------------------------------------------------------
// the import
// ---------------------------------------------------------------------------

/// Source: `DEFAULT_PHP_VERSION` and `DEFAULT_STORAGE_MB`.
pub fn default_php_version() -> String {
    std::env::var("DA_IMPORT_PHP").unwrap_or_else(|_| "8.3".to_string())
}

pub fn default_storage_mb() -> i64 {
    std::env::var("DA_IMPORT_STORAGE_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(102400)
}

/// Source: `_utc_stamp`.
fn utc_stamp() -> String {
    chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string()
}

/// Source: `_copy_site_files`.
///
/// **Symlinks are not followed and not copied.** A backup that links
/// `/etc` into its public directory would otherwise have the importer
/// copy the machine into a customer's site; one that links `/dev/zero`
/// would have it copy forever.
pub fn copy_site_files(source: Option<&Path>, public: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(public)?;
    let Some(source) = source.filter(|s| s.exists()) else {
        return Ok(());
    };
    copy_tree(source, public)
}

fn copy_tree(source: &Path, target: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(target)?;
    for entry in sorted_entries(source) {
        let Some(name) = entry.file_name() else {
            continue;
        };
        if entry.is_symlink() {
            continue;
        }
        let destination = target.join(name);
        if entry.is_dir() {
            copy_tree(&entry, &destination)?;
        } else if entry.is_file() {
            std::fs::copy(&entry, &destination)?;
        }
    }
    Ok(())
}

/// Source: `_relocate_da_subdomain_sources`.
///
/// DirectAdmin nests `sub.example.com` inside `example.com`'s
/// `public_html`. This panel has no parent/child website, so each one
/// becomes its own site with its own root - and moving the directory out
/// first is what keeps the **parent** import from copying the subdomain's
/// files a second time into a tree that no longer serves them.
///
/// The move is a rename inside the staging tree this process owns, so it
/// is cheap and touches nothing live.
pub fn relocate_subdomain_sources(
    root: &Path,
    parent_domains: &[String],
) -> Vec<(String, Option<PathBuf>)> {
    let holding = root.join("_snpanel_subdomains");
    let mut sources: Vec<(String, Option<PathBuf>)> = Vec::new();
    for parent in parent_domains {
        let labels = discover_subdomains(root, parent);
        if labels.is_empty() {
            continue;
        }
        let parent_public = source_for_domain(root, parent);
        for label in labels {
            let Some(fqdn) = normalize_domain(&format!("{label}.{parent}")) else {
                continue;
            };
            if sources.iter().any(|(name, _)| *name == fqdn) {
                continue;
            }
            let src = parent_public.as_ref().map(|p| p.join(&label));
            let staged = match src {
                Some(src) if src.is_dir() && !src.is_symlink() => {
                    let dest = holding.join(&fqdn);
                    if let Some(parent_dir) = dest.parent() {
                        let _ = std::fs::create_dir_all(parent_dir);
                    }
                    let _ = std::fs::remove_dir_all(&dest);
                    match std::fs::rename(&src, &dest) {
                        Ok(()) => Some(dest),
                        // A rename across devices cannot happen inside one
                        // staging tree, but a permission fault can; the
                        // subdomain then imports empty rather than failing
                        // the whole account.
                        Err(e) => {
                            tracing::warn!("could not stage {fqdn}: {e}");
                            None
                        }
                    }
                }
                _ => None,
            };
            sources.push((fqdn, staged));
        }
    }
    sources
}

/// One site the import is going to create.
pub struct ImportTarget {
    pub domain: String,
    pub source: Option<PathBuf>,
}

/// Source: `import_targets` - the parents in discovery order, then the
/// relocated subdomains.
pub fn import_targets(
    root: &Path,
    domains: &[String],
    subdomains: &[(String, Option<PathBuf>)],
) -> Vec<ImportTarget> {
    let mut targets: Vec<ImportTarget> = domains
        .iter()
        .map(|domain| ImportTarget {
            domain: domain.clone(),
            source: source_for_domain(root, domain),
        })
        .collect();
    targets.extend(subdomains.iter().map(|(fqdn, src)| ImportTarget {
        domain: fqdn.clone(),
        source: src.clone(),
    }));
    targets
}

/// Source: `all_domains = domains + [d for d in subdomain_sources if d not in domains]`.
pub fn all_domains(domains: &[String], subdomains: &[(String, Option<PathBuf>)]) -> Vec<String> {
    let mut all = domains.to_vec();
    for (fqdn, _) in subdomains {
        if !all.contains(fqdn) {
            all.push(fqdn.clone());
        }
    }
    all
}

/// Source: the `if not force:` conflict check.
///
/// **An import is destructive.** It replaces the panel user, its websites,
/// their files and their databases. Refusing unless the caller asked for
/// it is what stops a re-run of a finished import from wiping a site that
/// has been live for a month.
pub fn conflict_message(
    existing_user: bool,
    username: &str,
    existing_domains: &[String],
) -> Option<String> {
    let mut conflicts: Vec<String> = Vec::new();
    if existing_user {
        conflicts.push(format!("panel user '{username}'"));
    }
    for domain in existing_domains {
        conflicts.push(format!("website '{domain}'"));
    }
    if conflicts.is_empty() {
        return None;
    }
    Some(format!(
        "Already exists: {}. Re-run with force to replace (this deletes the existing files and databases).",
        conflicts.join(", ")
    ))
}

/// Source: the `errors = [w for item in summary ...]` filter.
///
/// Only the warnings that name a failure become errors. A warning that a
/// site had no files is worth showing and is not a failure, and a page
/// that turned every warning red would train the operator to ignore them.
pub fn errors_from_warnings(warnings: &[String]) -> Vec<String> {
    warnings
        .iter()
        .filter(|w| {
            let lower = w.to_lowercase();
            lower.contains("failed") || lower.contains("error")
        })
        .cloned()
        .collect()
}

/// Source: the `credentials` header written at the top of every import.
pub fn credentials_header(stamp: &str, archive_name: &str) -> Vec<String> {
    vec![
        "# SNPanel DirectAdmin import credentials".to_string(),
        format!("# Web import: {stamp}"),
        format!("# Archive: {archive_name}"),
        "# Keep this file private. It contains generated panel and database passwords.".to_string(),
    ]
}

/// Source: the `credentials.append(f"database target=...")` lines.
///
/// **A reused `mysql_native_password` hash has no plaintext behind it**,
/// so there is nothing to write down. Saying so beats writing an empty
/// password an operator would then try to use.
pub fn database_credential_line(
    target: &str,
    db_name: &str,
    db_user: &str,
    db_password: &str,
) -> String {
    if db_password.is_empty() {
        format!(
            "database target={target} db_name={db_name} db_user={db_user} \
             db_password=<kept DirectAdmin password hash; unchanged>"
        )
    } else {
        format!(
            "database target={target} db_name={db_name} db_user={db_user} db_password={db_password}"
        )
    }
}

/// Source: `_temporary_sql_file`.
///
/// A dump arrives in one of four shapes and `mysql` reads a plain stream,
/// so it is decompressed into the staging area first. The temporary file
/// is created with `O_EXCL` and mode `0600`: it holds the customer's
/// whole database in plaintext, including whatever passwords their
/// application stored.
///
/// The caller removes it; a dump of a busy site is gigabytes.
pub fn decompress_sql(sql_file: &Path) -> Result<PathBuf, String> {
    use std::io::Read;

    let name = sql_file
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let base = stage_base();
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let Some(dir) = make_stage_dir(&base, "snpanel-da-sql-") else {
        return Err("Could not stage the SQL dump".to_string());
    };
    let target = dir.join("dump.sql");

    let file = std::fs::File::open(sql_file).map_err(|e| e.to_string())?;
    let reader = std::io::BufReader::new(file);
    let mut decoded: Box<dyn Read> = if name.ends_with(".sql.gz") {
        Box::new(flate2::read::GzDecoder::new(reader))
    } else if name.ends_with(".sql.bz2") {
        Box::new(bzip2_rs::DecoderReader::new(reader))
    } else if name.ends_with(".sql.zst") {
        Box::new(ruzstd::decoding::StreamingDecoder::new(reader).map_err(|e| format!("zstd: {e}"))?)
    } else {
        Box::new(reader)
    };

    let mut out = create_private_file(&target)?;
    std::io::copy(&mut decoded, &mut out).map_err(|e| e.to_string())?;
    Ok(target)
}

/// `O_CREAT | O_EXCL | O_WRONLY` at mode `0600`.
///
/// The dump is plaintext customer data; a file created at the umask's
/// mercy in a shared staging directory is a file another account on the
/// machine may be able to read while the import runs.
fn create_private_file(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())
}

/// Source: `stage_dir = STAGE_BASE / f"web-{stamp}-{token_hex(4)}"`.
pub fn make_import_stage() -> Option<PathBuf> {
    let base = stage_base();
    std::fs::create_dir_all(&base).ok()?;
    make_stage_dir(&base, &format!("web-{}-", utc_stamp()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/da_import.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the da import corpus"))
            .expect("the corpus parses")
    }

    #[test]
    fn an_archive_suffix_comes_off_whole() {
        let corpus = corpus();
        let cases = corpus["strip_suffix"].as_array().expect("the cases");
        let mut failures = Vec::new();
        for case in cases {
            let raw = case["name"].as_str().unwrap_or("");
            let want = case["stripped"].as_str().unwrap_or("");
            let got = strip_archive_suffix(raw);
            if got != want {
                failures.push(format!("{raw:?}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // `.tar.gz`, not `.gz`; and an unknown extension falls back to the
        // stem, which removes only the last one.
        assert_eq!(strip_archive_suffix("user.bob.tar.gz"), "user.bob");
        assert_eq!(strip_archive_suffix("user.bob.backup"), "user.bob");
    }

    #[test]
    fn an_archive_name_yields_the_pythons_username() {
        let corpus = corpus();
        let cases = corpus["archive_username"].as_array().expect("the cases");
        let mut failures = Vec::new();
        for case in cases {
            let raw = case["name"].as_str().unwrap_or("");
            let want = case["username"].as_str().unwrap_or("");
            let got = archive_username(raw);
            if got != want {
                failures.push(format!("{raw:?}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // A `user.` prefix means the name is **last**; otherwise the last
        // piece that is not a filler word wins.
        assert_eq!(archive_username("user.bob.smith.tar.gz"), "smith");
        assert_eq!(archive_username("bob.backup.tar.gz"), "bob");
    }

    /// An account name becoming a Linux user.
    #[test]
    fn a_username_is_normalized_the_way_python_normalizes_it() {
        let corpus = corpus();
        let cases = corpus["normalize_username"].as_array().expect("the cases");
        assert_eq!(cases.len(), 34, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().unwrap_or("");
            let archive = case["archive"].as_str().unwrap_or("");
            let want = case["username"].as_str().unwrap_or("");
            let got = normalize_username(raw, archive);
            if got != want {
                failures.push(format!(
                    "({raw:?}, {archive:?}): python {want:?}, rust {got:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // Whatever comes out is a name this panel can actually create, and
        // is never a system account.
        for case in cases {
            let got = normalize_username(
                case["raw"].as_str().unwrap_or(""),
                case["archive"].as_str().unwrap_or(""),
            );
            assert!(panel_username_shape_ok(&got), "{got:?} is not usable");
            assert!(
                !reserved_users().contains(&got.as_str()),
                "{got:?} is reserved"
            );
        }
    }

    #[test]
    fn a_domain_is_normalized_the_way_python_normalizes_it() {
        let corpus = corpus();
        let cases = corpus["normalize_domain"].as_array().expect("the cases");
        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().unwrap_or("");
            let want = case["domain"].as_str();
            let got = normalize_domain(raw);
            if got.as_deref() != want {
                failures.push(format!("{raw:?}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // **Not the panel's own `DOMAIN_RE`**: a numeric final label is
        // allowed, because a DirectAdmin backup may hold one and refusing
        // it would drop a site without saying so.
        assert_eq!(
            normalize_domain("example.12").as_deref(),
            Some("example.12")
        );
    }

    #[test]
    fn a_conf_file_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        for case in corpus["key_values"].as_array().expect("the cases") {
            let text = case["text"].as_str().unwrap_or("");
            let want = case["values"].as_object().expect("the values");
            let got = read_key_values(text);
            for (key, value) in want {
                assert_eq!(
                    got.get(key).map(String::as_str),
                    value.as_str(),
                    "key {key} of {text:?}"
                );
            }
            assert_eq!(got.len(), want.len(), "for {text:?}");
        }
        // `=` wins over `:`, because a value holding a colon is far more
        // likely than a key holding one.
        assert_eq!(
            read_key_values("url=http://example.com")
                .get("url")
                .map(String::as_str),
            Some("http://example.com")
        );
    }

    #[test]
    fn pointers_are_read_the_way_python_reads_them() {
        let corpus = corpus();
        for case in corpus["pointers"].as_array().expect("the cases") {
            let text = case["text"].as_str().unwrap_or("");
            let domain = case["domain"].as_str().unwrap_or("");
            let want: Vec<(String, String)> = case["pointers"]
                .as_array()
                .expect("the pointers")
                .iter()
                .map(|p| {
                    (
                        p[0].as_str().unwrap_or("").to_string(),
                        p[1].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect();
            let mut seen = Vec::new();
            assert_eq!(
                parse_pointer_lines(text, domain, &mut seen),
                want,
                "for {text:?}"
            );
        }
        // Anything that is not `redirect` is an alias - the safe reading.
        let mut seen = Vec::new();
        assert_eq!(
            parse_pointer_lines("a.com=something", "b.com", &mut seen),
            vec![("a.com".to_string(), "alias".to_string())]
        );
        // And a domain cannot point at itself.
        let mut seen = Vec::new();
        assert!(parse_pointer_lines("b.com=alias", "b.com", &mut seen).is_empty());
    }

    #[test]
    fn subdomain_labels_are_read_the_way_python_reads_them() {
        let corpus = corpus();
        for case in corpus["subdomains"].as_array().expect("the cases") {
            let text = case["text"].as_str().unwrap_or("");
            let want: Vec<&str> = case["labels"]
                .as_array()
                .expect("the labels")
                .iter()
                .map(|v| v.as_str().unwrap_or(""))
                .collect();
            let mut labels = Vec::new();
            parse_subdomain_lines(text, &mut labels);
            assert_eq!(labels, want, "for {text:?}");
        }
        // A value after the label is dropped: `blog:on` is the same
        // subdomain as `blog`.
        let mut labels = Vec::new();
        parse_subdomain_lines("blog:on\nshop=1\n", &mut labels);
        assert_eq!(labels, vec!["blog", "shop"]);
    }

    #[test]
    fn the_backup_root_is_scored_the_way_python_scores_it() {
        assert_eq!(backup_root_score(false, false, false), 1);
        assert_eq!(backup_root_score(true, false, false), 4);
        assert_eq!(backup_root_score(false, true, false), 3);
        assert_eq!(backup_root_score(false, false, true), 4);
        assert_eq!(backup_root_score(true, true, true), 9);
        // `domains/` beats `mysql/`.
        assert!(backup_root_score(true, false, false) > backup_root_score(false, true, false));
    }

    #[test]
    fn a_wp_config_is_parsed_the_way_python_parses_it() {
        let corpus = corpus();
        for case in corpus["wp_config"].as_array().expect("the cases") {
            let text = case["text"].as_str().unwrap_or("");
            let want = case["values"].as_object().expect("the values");
            let got = parse_wp_config(text);
            let got_json: serde_json::Map<String, Value> = got
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            assert_eq!(&got_json, want, "for {text:?}");
        }
        // The value may hold **neither** quote, which is the Python's
        // character class: a password containing one simply does not
        // match, and the field is left unset rather than truncated.
        assert!(parse_wp_config("define('DB_NAME', 'a\"b');").is_empty());
    }

    #[test]
    fn a_dotenv_is_parsed_the_way_python_parses_it() {
        let corpus = corpus();
        for case in corpus["dotenv"].as_array().expect("the cases") {
            let text = case["text"].as_str().unwrap_or("");
            let want = case["values"].as_object().expect("the values");
            let got = parse_dotenv_config(text);
            let got_json: serde_json::Map<String, Value> = got
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            assert_eq!(&got_json, want, "for {text:?}");
        }
        // An **empty** value is skipped, so a `.env` with `DB_PASSWORD=`
        // does not overwrite a real one found earlier.
        assert!(!parse_dotenv_config("DB_DATABASE=x\nDB_PASSWORD=\n").contains_key("DB_PASSWORD"));
    }

    #[test]
    fn a_php_variable_config_is_parsed_the_way_python_parses_it() {
        let corpus = corpus();
        for case in corpus["php_config"].as_array().expect("the cases") {
            let text = case["text"].as_str().unwrap_or("");
            let want = case["values"].as_object().expect("the values");
            let got = parse_php_variable_config(text);
            let got_json: serde_json::Map<String, Value> = got
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            assert_eq!(&got_json, want, "for {text:?}");
        }
        // `$db` must not match `$dbuser`: the name has to end where the
        // pattern says it does.
        let values = parse_php_variable_config("public $dbuser = 'u';\npublic $db = 'd';");
        assert_eq!(values.get("DB_NAME").map(String::as_str), Some("d"));
    }

    #[test]
    fn a_single_site_takes_its_only_dump() {
        let mut sql = BTreeMap::new();
        sql.insert("anything".to_string(), PathBuf::from("/x/anything.sql"));
        let empty = BTreeMap::new();

        // One site, one dump, no name in the config: it is taken anyway,
        // because that is the common shape of a one-domain account and
        // leaving it behind would import the site without its database.
        let (key, matched) = matched_sql_for_config(&empty, &sql, true);
        assert_eq!(key, "anything");
        assert!(matched.is_some());

        // More than one site and no name: nothing is guessed.
        let (key, matched) = matched_sql_for_config(&empty, &sql, false);
        assert!(key.is_empty() && matched.is_none());

        // A named database wins over the single-dump rule.
        let mut two = BTreeMap::new();
        two.insert("wanted".to_string(), PathBuf::from("/x/wanted.sql"));
        two.insert("other".to_string(), PathBuf::from("/x/other.sql"));
        let mut config = BTreeMap::new();
        config.insert("DB_NAME".to_string(), "WANTED".to_string());
        let (key, matched) = matched_sql_for_config(&config, &two, false);
        assert_eq!(key, "wanted");
        assert_eq!(
            matched.map(|p| p.to_string_lossy().into_owned()).as_deref(),
            Some("/x/wanted.sql")
        );
    }

    fn scan_corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/da_scan.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the da scan corpus"))
            .expect("the corpus parses")
    }

    /// A scratch directory that removes itself, however the test ends.
    ///
    /// `std::env::temp_dir()` with a unique name, which is what the rest
    /// of this crate's tests use; there is no `tempfile` dependency and
    /// this does not need one.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "snpanel-da-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Unpack one of the corpus archives into a fresh directory.
    fn stage(corpus: &Value, name: &str) -> (Scratch, PathBuf) {
        use base64::Engine;
        let encoded = corpus["archives"][name]
            .as_str()
            .unwrap_or_else(|| panic!("{name} is not in the corpus"));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("the archive decodes");
        let dir = Scratch::new("stage");
        let archive = dir.path().join(name);
        std::fs::write(&archive, bytes).expect("the archive is written");
        (dir, archive)
    }

    /// What a whole scan makes of a real DirectAdmin layout.
    ///
    /// The archive is the one the Python scanned, byte for byte, and the
    /// answer is compared field by field. This is the test that would
    /// notice a domain going missing, a site being called static because
    /// its PHP was not found, or a database dump being attached to the
    /// wrong site.
    #[test]
    fn a_real_archive_scans_the_way_python_scans_it() {
        let corpus = scan_corpus();
        let scans = corpus["scans"].as_array().expect("the scans");
        assert_eq!(scans.len(), 5, "five compressions");

        let mut failures = Vec::new();
        for case in scans {
            let mode = case["mode"].as_str().unwrap_or("");
            let name = case["name"].as_str().unwrap_or("");
            assert!(
                case.get("skipped").is_none(),
                "{mode}: the corpus was recorded without it"
            );
            let want = &case["scan"]["users"][0];

            let (dir, archive) = stage(&corpus, name);
            let extracted = dir.path().join("extracted");
            if let Err(message) = safe_extract_tar(&archive, &extracted) {
                failures.push(format!("{mode}: extraction failed: {message}"));
                continue;
            }
            let root = find_backup_root(&extracted);
            extract_nested_domain_archives(&root);
            let got = scan_extracted(&root, name);

            for field in ["username", "email"] {
                if got[field] != want[field] {
                    failures.push(format!(
                        "{mode}: {field} python {}, rust {}",
                        want[field], got[field]
                    ));
                }
            }
            let want_domains = want["domains"].as_array().expect("the domains");
            let got_domains = got["domains"].as_array().expect("the domains");
            if got_domains.len() != want_domains.len() {
                failures.push(format!(
                    "{mode}: python found {} domains, rust {}",
                    want_domains.len(),
                    got_domains.len()
                ));
                continue;
            }
            // **By name, not by position.** `_discover_domains` walks the
            // directory with `iterdir()`, which is filesystem order; two
            // extractions of one archive can list the same domains
            // differently. This port sorts, which is a deliberate
            // difference and the only one here - so what is compared is
            // what each domain says about itself.
            for want_domain in want_domains {
                let name = want_domain["domain"].as_str().unwrap_or("");
                let Some(got_domain) = got_domains
                    .iter()
                    .find(|d| d["domain"].as_str() == Some(name))
                else {
                    failures.push(format!("{mode}: rust did not find {name}"));
                    continue;
                };
                for field in [
                    "app_type",
                    "has_files",
                    "db_name",
                    "db_user",
                    "has_sql_dump",
                    "aliases",
                ] {
                    if got_domain[field] != want_domain[field] {
                        failures.push(format!(
                            "{mode}: {name} {field} python {}, rust {}",
                            want_domain[field], got_domain[field]
                        ));
                    }
                }
            }
            let want_dbs: Vec<&str> = want["databases"]
                .as_array()
                .expect("the databases")
                .iter()
                .map(|d| d["db_name"].as_str().unwrap_or(""))
                .collect();
            let got_dbs: Vec<&str> = got["databases"]
                .as_array()
                .expect("the databases")
                .iter()
                .map(|d| d["db_name"].as_str().unwrap_or(""))
                .collect();
            let mut want_sorted = want_dbs.clone();
            let mut got_sorted = got_dbs.clone();
            want_sorted.sort_unstable();
            got_sorted.sort_unstable();
            if got_sorted != want_sorted {
                failures.push(format!(
                    "{mode}: unassigned databases python {want_dbs:?}, rust {got_dbs:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The five compressions are five spellings of one archive.
    ///
    /// `tarfile.open(path, "r:*")` hides the difference and a port must
    /// not: a `.tar.xz` that decoded to something slightly different from
    /// the `.tar` would be a bug nobody would look for.
    #[test]
    fn every_compression_yields_the_same_scan() {
        let corpus = scan_corpus();
        let names: Vec<&str> = corpus["scans"]
            .as_array()
            .expect("the scans")
            .iter()
            .map(|c| c["name"].as_str().unwrap_or(""))
            .collect();

        let mut answers: Vec<(String, Value)> = Vec::new();
        for name in names {
            let (dir, archive) = stage(&corpus, name);
            let extracted = dir.path().join("extracted");
            safe_extract_tar(&archive, &extracted)
                .unwrap_or_else(|e| panic!("{name} did not extract: {e}"));
            let root = find_backup_root(&extracted);
            extract_nested_domain_archives(&root);
            // The account name is derived from the **filename**, which
            // differs by suffix, so it is compared separately above.
            let mut scan = scan_extracted(&root, "user.bobsmith.tar");
            // The unassigned-database list carries staging paths.
            scan["databases"] = Value::Null;
            answers.push((name.to_string(), scan));
        }

        let (first_name, first) = &answers[0];
        for (name, answer) in &answers[1..] {
            assert_eq!(
                answer, first,
                "{name} scanned differently from {first_name}"
            );
        }
    }

    /// An account with no `user.conf` at all.
    ///
    /// The name then comes from the **filename**, and a single site with a
    /// single dump takes it even though nothing named it - which is the
    /// common shape of a one-domain account.
    #[test]
    fn an_account_with_no_user_conf_is_named_from_its_archive() {
        let corpus = scan_corpus();
        let name = corpus["no_user_conf"]["name"].as_str().expect("the name");
        let want = &corpus["no_user_conf"]["scan"]["users"][0];

        let (dir, archive) = stage(&corpus, name);
        let extracted = dir.path().join("extracted");
        safe_extract_tar(&archive, &extracted).expect("it extracts");
        let root = find_backup_root(&extracted);
        extract_nested_domain_archives(&root);
        let got = scan_extracted(&root, name);

        assert_eq!(got["username"], want["username"]);
        // `reseller.acme.carol.tar.gz` - the reseller prefix means the
        // name is the **last** piece.
        assert_eq!(got["username"], "carol");
        assert_eq!(got["email"], want["email"]);
        assert_eq!(got["domains"][0]["domain"], want["domains"][0]["domain"]);
        assert_eq!(got["domains"][0]["db_name"], want["domains"][0]["db_name"]);
        assert_eq!(got["domains"][0]["has_sql_dump"], true);
    }

    /// A member that tries to leave the destination stops the extraction.
    ///
    /// The archive arrived through a browser upload, so `../../etc/cron.d`
    /// in a member name is not hypothetical.
    #[test]
    fn an_archive_cannot_write_outside_its_destination() {
        let dir = Scratch::new("evil");
        let archive = dir.path().join("evil.tar");
        // `tar::Builder` refuses `..` in a path, so the header is written
        // by hand - which is also how a real hostile archive is made.
        let mut header = tar::Header::new_gnu();
        header
            .set_path("../escaped.txt")
            .or_else(|_| {
                // Some versions refuse even here; fall back to the raw
                // bytes, which is what an attacker would send.
                header.as_old_mut().name[..15].copy_from_slice(b"../escaped.txt\0");
                Ok::<(), std::io::Error>(())
            })
            .expect("a path");
        header.set_size(3);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append(&header, &b"bad"[..])
            .expect("the member is written");
        let bytes = builder.into_inner().expect("the archive");
        std::fs::write(&archive, bytes).expect("the archive is written");

        let destination = dir.path().join("out");
        let result = safe_extract_tar(&archive, &destination);
        assert!(result.is_err(), "an escaping member was extracted");
        assert!(
            !dir.path().join("escaped.txt").exists(),
            "a file was written outside the destination"
        );
    }

    /// No link is ever extracted, symbolic or hard.
    ///
    /// DirectAdmin backups hold none this importer needs, and skipping
    /// them keeps the staged tree free of anything pointing outside it -
    /// so the passes that copy files afterwards cannot be walked out of
    /// the staging directory by something the archive chose.
    #[test]
    fn an_archive_link_is_never_extracted() {
        let dir = Scratch::new("links");
        let archive = dir.path().join("links.tar");

        let mut builder = tar::Builder::new(Vec::new());
        // A real file, so there is something for the links to point at
        // and something to prove the extraction ran at all.
        let mut real = tar::Header::new_gnu();
        real.set_path("real.txt").expect("a path");
        real.set_size(4);
        real.set_entry_type(tar::EntryType::Regular);
        real.set_mode(0o644);
        real.set_cksum();
        builder.append(&real, &b"real"[..]).expect("the file");

        let mut symlink = tar::Header::new_gnu();
        symlink.set_path("pointer").expect("a path");
        symlink.set_size(0);
        symlink.set_entry_type(tar::EntryType::Symlink);
        symlink.set_mode(0o777);
        symlink.set_link_name("/etc/passwd").expect("a link target");
        symlink.set_cksum();
        builder
            .append(&symlink, std::io::empty())
            .expect("the link");

        let mut hard = tar::Header::new_gnu();
        hard.set_path("copy.txt").expect("a path");
        hard.set_size(0);
        hard.set_entry_type(tar::EntryType::Link);
        hard.set_mode(0o644);
        hard.set_link_name("real.txt").expect("a link target");
        hard.set_cksum();
        builder.append(&hard, std::io::empty()).expect("the link");

        let bytes = builder.into_inner().expect("the archive");
        std::fs::write(&archive, bytes).expect("the archive is written");

        let destination = dir.path().join("out");
        safe_extract_tar(&archive, &destination).expect("the archive extracts");

        assert!(
            destination.join("real.txt").is_file(),
            "the ordinary file should have been extracted"
        );
        assert!(
            !destination.join("pointer").exists()
                && std::fs::symlink_metadata(destination.join("pointer")).is_err(),
            "a symbolic link was extracted"
        );
        assert!(
            !destination.join("copy.txt").exists(),
            "a hard link was extracted"
        );
    }

    fn db_corpus() -> Value {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/da_db.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the da db corpus"))
            .expect("the corpus parses")
    }

    /// A database name that has to be unique on *this* machine.
    #[test]
    fn a_database_name_is_normalized_the_way_python_normalizes_it() {
        let corpus = corpus();
        let cases = corpus["normalize_db"].as_array().expect("the cases");
        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().unwrap_or("");
            let fallback = case["fallback"].as_str().unwrap_or("");
            let existing: Vec<String> = case["existing"]
                .as_array()
                .expect("the existing names")
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let want = case["name"].as_str().unwrap_or("");
            let got = normalize_db_identifier(raw, fallback, &existing);
            if got != want {
                failures.push(format!(
                    "({raw:?}, {fallback:?}, {existing:?}): python {want:?}, rust {got:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // A name already taken gets a hash of the original, so two
        // customers who both called their database `wordpress` can both
        // be imported.
        let taken = vec!["wordpress".to_string()];
        let renamed = normalize_db_identifier("wordpress", "site", &taken);
        assert_ne!(renamed, "wordpress");
        assert!(db_identifier_ok(&renamed));
    }

    /// The password out of a DirectAdmin `<db>.conf`.
    ///
    /// **`%2A` is the star that opens a `mysql_native_password` hash.** A
    /// reader that did not percent-decode would see the hash as an
    /// ordinary password and set it as one, locking the customer out of
    /// their own database with a password that is the text of their hash.
    #[test]
    fn a_da_conf_password_is_read_the_way_python_reads_it() {
        let corpus = db_corpus();
        let cases = corpus["da_conf_password"].as_array().expect("the cases");
        assert_eq!(cases.len(), 23, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let name = case["case"].as_str().unwrap_or("");
            let text = case["text"].as_str().unwrap_or("");
            let want_password = case["found"]["password"].as_str().unwrap_or("");
            let want_hash = case["found"]["password_hash"].as_str().unwrap_or("");
            let got = decode_da_conf_password(text);
            if got.password != want_password || got.password_hash != want_hash {
                failures.push(format!(
                    "{name}: python ({want_password:?}, {want_hash:?}), rust {got:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // The two the corpus makes a point of.
        let encoded =
            decode_da_conf_password("passwd=%2A1234567890ABCDEF1234567890ABCDEF12345678\n");
        assert_eq!(
            encoded.password_hash,
            "*1234567890ABCDEF1234567890ABCDEF12345678"
        );
        assert!(encoded.password.is_empty());
        // Forty hex characters exactly: one short and it is a password.
        assert!(!is_native_password_hash("*1234567890ABCDEF"));
        assert!(is_native_password_hash(
            "*1234567890abcdef1234567890abcdef12345678"
        ));
    }

    /// Which secret an imported database user gets.
    #[test]
    fn the_reused_password_is_chosen_the_way_python_chooses_it() {
        let corpus = db_corpus();
        let cases = corpus["import_db_password"].as_array().expect("the cases");
        assert_eq!(cases.len(), 7, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let name = case["case"].as_str().unwrap_or("");
            let app_config: BTreeMap<String, String> = case["app_config"]
                .as_object()
                .expect("the app config")
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect();
            let da = DaPassword {
                password: case["da_credentials"]["password"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                password_hash: case["da_credentials"]["password_hash"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            };
            let got = import_db_password(&app_config, &da, "<generated>");
            let want_reused = case["reused"].as_bool().unwrap_or(false);
            let want_password = case["password"].as_str().unwrap_or("");
            let want_hash = case["password_hash"].as_str().unwrap_or("");
            if got.reused != want_reused
                || got.password != want_password
                || got.password_hash != want_hash
            {
                failures.push(format!(
                    "{name}: python ({want_password:?}, {want_hash:?}, {want_reused}), rust {got:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // **A reused secret only helps if the config still points at this
        // database and this user.** A rename means the config is going to
        // be rewritten anyway, so a fresh password costs nothing - and a
        // stale hash would cost the customer their database.
        assert!(rename_invalidates_reuse("old_db", "new_db", None, "u"));
        assert!(rename_invalidates_reuse("db", "db", Some("old_u"), "new_u"));
        assert!(!rename_invalidates_reuse("db", "db", Some("u"), "u"));
        // Nothing to rename is not a rename.
        assert!(!rename_invalidates_reuse("", "anything", None, "u"));
    }

    /// The account's address, which the column requires to be unique.
    #[test]
    fn an_account_email_is_built_the_way_python_builds_it() {
        let corpus = db_corpus();
        let cases = corpus["unique_email"].as_array().expect("the cases");
        assert_eq!(cases.len(), 7, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let name = case["case"].as_str().unwrap_or("");
            let username = case["username"].as_str().unwrap_or("");
            let preferred = case["preferred"].as_str().unwrap_or("");
            let domains: Vec<String> = case["domains"]
                .as_array()
                .expect("the domains")
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let want = case["email"].as_str().unwrap_or("");
            let got = unique_email(username, preferred, &domains, &[]);
            if got != want {
                failures.push(format!("{name}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // An address already taken gets a `+2` tag rather than failing the
        // import: the account still has to exist.
        let taken = vec!["bob@example.com".to_string()];
        assert_eq!(
            unique_email("bob", "", &["example.com".to_string()], &taken),
            "bob+2@example.com"
        );
        // With no domains at all there is still a host.
        assert_eq!(unique_email("bob", "", &[], &[]), "bob@import.local");
    }

    /// Rewriting a `wp-config.php` to point at the imported database.
    #[test]
    fn a_define_is_replaced_the_way_python_replaces_it() {
        let corpus = db_corpus();
        let cases = corpus["replace_define"].as_array().expect("the cases");
        assert_eq!(cases.len(), 7, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let name = case["case"].as_str().unwrap_or("");
            let text = case["text"].as_str().unwrap_or("");
            let key = case["key"].as_str().unwrap_or("");
            let value = case["value"].as_str().unwrap_or("");
            let want = case["result"].as_str().unwrap_or("");
            let got = replace_define(text, key, value);
            if got != want {
                failures.push(format!("{name}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // **A config that never named the database still has to name the
        // new one.** A site that comes back pointing at nothing is a site
        // that did not come back.
        let appended = replace_define("<?php\n", "DB_NAME", "new");
        assert!(appended.contains("define('DB_NAME', 'new');"));
        // Only the first is replaced, which is what `count=1` means.
        let twice = replace_define(
            "<?php\ndefine('DB_NAME','a');\ndefine('DB_NAME','b');\n",
            "DB_NAME",
            "new",
        );
        assert!(twice.contains("'new'") && twice.contains("'b'"));
    }

    /// Rewriting a site's config to point at the imported database.
    ///
    /// Measured through the real `_update_config_dir`, which writes the
    /// files back, so what is compared is the file as it lands on disk.
    #[test]
    fn a_site_config_is_rewritten_the_way_python_rewrites_it() {
        let corpus = db_corpus();
        let cases = corpus["update_config"].as_array().expect("the cases");
        assert_eq!(cases.len(), 15, "the corpus changed size");

        let mut failures = Vec::new();
        for case in cases {
            let name = case["case"].as_str().unwrap_or("");
            let file = case["file"].as_str().unwrap_or("");
            let before = case["before"].as_str().unwrap_or("");
            let want = case["after"].as_str().unwrap_or("");

            let dir = Scratch::new("rewrite");
            std::fs::write(dir.path().join(file), before).expect("the config is written");
            update_config_dir(dir.path(), "new_db", "new_user", "new_pass");
            let got = std::fs::read_to_string(dir.path().join(file)).expect("the config");
            if got != want {
                failures.push(format!("{name}: python {want:?}, rust {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // **The host differs by file, and it is not a typo.** WordPress
        // and Joomla get `localhost`, which uses the MySQL socket; a
        // `.env` gets `127.0.0.1`, because Laravel's PDO driver treats
        // `localhost` as a socket it may not be configured for.
        let env = rewrite_dotenv("", "d", "u", "p");
        assert!(env.contains("DB_HOST=127.0.0.1"));
        let wp = replace_define("<?php\n", "DB_HOST", "localhost");
        assert!(wp.contains("define('DB_HOST', 'localhost');"));

        // **A bare `$db = 'x';` is read and then left alone.** The
        // rewriter's pattern requires `public`; the parser's does not.
        // Reproduced rather than fixed: an imported Joomla site written
        // that way keeps pointing at the old database, which is worth
        // knowing about rather than quietly changing.
        assert_eq!(
            parse_php_variable_config("<?php\n$db = 'old';\n")
                .get("DB_NAME")
                .map(String::as_str),
            Some("old")
        );
        assert_eq!(
            rewrite_php_config("<?php\n$db = 'old';\n", "new", "u", "p"),
            "<?php\n$db = 'old';\n"
        );
        // And `public db` without the dollar **is** rewritten, because the
        // pattern's `\$?` is optional.
        assert!(
            rewrite_php_config("<?php\npublic db = 'old';\n", "new", "u", "p").contains("'new'")
        );
    }

    #[test]
    fn a_sql_name_loses_its_whole_suffix() {
        assert_eq!(sql_base_name("wp_main.sql.gz"), "wp_main");
        assert_eq!(sql_base_name("wp_main.sql"), "wp_main");
        assert_eq!(sql_base_name("wp_main.sql.zst"), "wp_main");
        // Not a dump suffix: the stem, which removes only the last one.
        assert_eq!(sql_base_name("wp_main.dump"), "wp_main");
    }
}
