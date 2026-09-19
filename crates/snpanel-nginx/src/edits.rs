//! Targeted edits to a vhost that already exists.
//!
//! Turning the WAF on, changing a flood limit or saving a custom snippet does
//! not rebuild the file - it replaces one marked block in it. That matters:
//! a full rewrite would also reset anything certbot, a previous panel version
//! or an administrator put there, and these three screens have no business
//! doing that.
//!
//! Every function here is pure. The caller reads the file, calls one of
//! these, writes the result, asks the helper to test the configuration and
//! restores the old bytes if it refuses.

use crate::{
    bot_block, find_server_brace, http_flood_challenge_block, http_flood_zone_name,
    normalize_blocked_bots, safe_domain, waf_rules_file, HttpFloodConfig, RenderError,
};

const WAF_BEGIN: &str = "    # SNPANEL WAF BEGIN";
const WAF_END: &str = "    # SNPANEL WAF END";
const FLOOD_BEGIN: &str = "    # SNPANEL HTTP FLOOD BEGIN";
const FLOOD_END: &str = "    # SNPANEL HTTP FLOOD END";

/// Source: the `\n?<begin>\n.*?<end>` substitutions, which are non-greedy and
/// take the newline before the marker with them.
pub(crate) fn strip_marked_block(content: &str, begin: &str, end: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    while let Some(at) = rest.find(begin) {
        let Some(end_rel) = rest[at..].find(end) else {
            break;
        };
        let stop = at + end_rel + end.len();
        let cut = if at > 0 && rest.as_bytes()[at - 1] == b'\n' {
            at - 1
        } else {
            at
        };
        out.push_str(&rest[..cut]);
        rest = &rest[stop..];
    }
    out.push_str(rest);
    out
}

/// The insertion ladder every one of these blocks walks: an earlier marked
/// block if there is one, then `server_tokens off;`, then the `server_name`
/// line, then straight after the opening brace.
fn insert_block(
    cleaned: &str,
    block: &str,
    before_markers: &[&str],
    what: &str,
) -> Result<String, RenderError> {
    for marker in before_markers {
        if let Some(at) = cleaned.find(marker) {
            let mut out = String::with_capacity(cleaned.len() + block.len() + 2);
            out.push_str(&cleaned[..at]);
            out.push_str(block);
            out.push_str("\n\n");
            out.push_str(&cleaned[at..]);
            return Ok(out);
        }
    }
    if let Some(at) = cleaned.find("    server_tokens off;") {
        let end = at + "    server_tokens off;".len();
        return Ok(format!("{}\n{block}{}", &cleaned[..end], &cleaned[end..]));
    }
    if let Some(at) = cleaned.find("    server_name ") {
        if let Some(semi) = cleaned[at..].find(';') {
            let end = at + semi + 1;
            return Ok(format!("{}\n{block}{}", &cleaned[..end], &cleaned[end..]));
        }
    }
    if let Some(at) = find_server_brace(cleaned) {
        return Ok(format!("{}\n{block}{}", &cleaned[..at], &cleaned[at..]));
    }
    Err(RenderError::Invalid(format!(
        "Cannot find server block for {what} directives"
    )))
}

/// Source: `_waf_block`.
fn waf_block(domain: &str) -> Result<String, RenderError> {
    Ok(format!(
        "{WAF_BEGIN}\n    modsecurity on;\n    modsecurity_rules_file {};\n{WAF_END}",
        waf_rules_file(domain)?
    ))
}

/// Source: `_replace_waf_block`.
///
/// `waf_engine` is the machine's answer, passed in. When the module is not
/// loaded the block is left out even though the caller asked for it: the
/// site's setting stays as the operator left it in the database, and what
/// changes is that a directive nginx cannot parse is not written to disk.
/// Writing it would make nginx reject its whole configuration, taking down
/// every site on the box at the next reload.
pub fn replace_waf_block(
    content: &str,
    enabled: bool,
    domain: Option<&str>,
    waf_engine: bool,
) -> Result<String, RenderError> {
    let cleaned = strip_marked_block(content, WAF_BEGIN, WAF_END);
    if !enabled || !waf_engine {
        return Ok(format!("{}\n", cleaned.trim_end()));
    }
    let domain = match domain {
        Some(d) => d.to_string(),
        None => domain_from_vhost(&cleaned),
    };
    insert_block(&cleaned, &waf_block(&domain)?, &[], "WAF")
}

/// Source: `_http_flood_block`.
fn flood_block(domain: &str, config: &HttpFloodConfig) -> Result<String, RenderError> {
    let zone = http_flood_zone_name(domain)?;
    let limit_req = if config.access_limit_burst > 0 {
        format!("limit_req zone={zone} burst={};", config.access_limit_burst)
    } else {
        format!("limit_req zone={zone};")
    };
    Ok(format!(
        "{FLOOD_BEGIN}\n    {limit_req}\n    limit_conn snpanel_conn_flood {};\n    \
         limit_req_status 429;\n    limit_conn_status 429;\n{}\n{FLOOD_END}",
        config.connection_limit,
        http_flood_challenge_block()
    ))
}

/// Source: `_replace_http_flood_block`.
pub fn replace_http_flood_block(
    content: &str,
    enabled: bool,
    domain: Option<&str>,
    config: &HttpFloodConfig,
) -> Result<String, RenderError> {
    let cleaned = strip_marked_block(content, FLOOD_BEGIN, FLOOD_END);
    if !enabled {
        return Ok(format!("{}\n", cleaned.trim_end()));
    }
    let domain = match domain {
        Some(d) => d.to_string(),
        None => domain_from_vhost(&cleaned),
    };
    insert_block(
        &cleaned,
        &flood_block(&domain, config)?,
        &[WAF_BEGIN],
        "HTTP flood",
    )
}

/// Source: `_replace_bot_block`, exposed for the screen that edits it.
pub fn replace_bot_block(content: &str, bots: &[String]) -> Result<String, RenderError> {
    let cleaned = strip_marked_block(
        content,
        "    # SNPANEL BOT BLOCK BEGIN",
        "    # SNPANEL BOT BLOCK END",
    );
    let safe = normalize_blocked_bots(bots)?;
    if safe.is_empty() {
        return Ok(format!("{}\n", cleaned.trim_end()));
    }
    insert_block(
        &cleaned,
        &bot_block(&safe),
        &[FLOOD_BEGIN, WAF_BEGIN],
        "bot blocking",
    )
}

/// Source: `_domain_from_vhost` - `(?m)^\s*server_name\s+([^;]+);`.
pub fn domain_from_vhost(content: &str) -> String {
    const FALLBACK: &str = "example.com";
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("server_name") {
            continue;
        }
        let rest = &trimmed["server_name".len()..];
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let Some((names, _)) = rest.split_once(';') else {
            continue;
        };
        let Some(first) = names.split_whitespace().next() else {
            continue;
        };
        let first = first.strip_prefix("www.").unwrap_or(first);
        return match safe_domain(first) {
            Ok(d) => d,
            Err(_) => FALLBACK.to_string(),
        };
    }
    FALLBACK.to_string()
}

/// Source: `_custom_include_block`.
fn custom_include_block(domain: &str) -> Result<String, RenderError> {
    Ok(format!(
        "    # SNPANEL CUSTOM INCLUDE\n    include {};",
        crate::custom_include_path(domain)?
    ))
}

/// Source: `_ensure_custom_include_position`.
///
/// The include has to sit after `location /` and before the static-asset
/// location, because nginx picks the first matching prefix location and a
/// customer's `location /assets` has to be seen before the catch-all. So the
/// existing include is removed, the main location is lifted out, and both are
/// put back in that order.
pub fn ensure_custom_include_position(content: &str, domain: &str) -> Result<String, RenderError> {
    let safe = safe_domain(domain)?;
    let block = custom_include_block(&safe)?;
    let include_line = format!("    include {};", crate::custom_include_path(&safe)?);

    // `\n?[ \t]*# SNPANEL CUSTOM INCLUDE[ \t]*\n[ \t]*include <path>;[ \t]*\n?`
    // replaced by a single newline, everywhere it appears.
    let cleaned = strip_existing_include(content, &include_line);

    // `\n    location / \{\n(?:        [^\n]*\n)*    \}\n`
    let (cleaned, main_location) = lift_main_location(&cleaned);

    const STATIC_LOCATION: &str =
        "\n    location ~* \\.(jpg|jpeg|gif|png|css|js|ico|webp|svg|woff|woff2|ttf|eot)$ {";
    let insert_at = cleaned
        .find(STATIC_LOCATION)
        .or_else(|| cleaned.rfind("\n}"));
    let Some(insert_at) = insert_at else {
        return Ok(format!("{}\n\n{block}\n", cleaned.trim_end()));
    };
    let before = cleaned[..insert_at].trim_end();
    let after = cleaned[insert_at + 1..].trim_start_matches('\n');
    let main_block = match &main_location {
        Some(m) => format!("\n\n{m}"),
        None => String::new(),
    };
    Ok(format!("{before}\n\n{block}{main_block}\n\n{after}"))
}

fn strip_existing_include(content: &str, include_line: &str) -> String {
    const MARKER: &str = "# SNPANEL CUSTOM INCLUDE";
    let mut out = String::with_capacity(content.len());
    let mut rest = content;
    loop {
        let Some(at) = rest.find(MARKER) else {
            out.push_str(rest);
            return out;
        };
        // The marker may be indented; the pattern allows only spaces and tabs
        // before it, and an optional newline before those.
        let line_start = rest[..at].rfind('\n').map_or(0, |n| n + 1);
        if !rest[line_start..at]
            .bytes()
            .all(|b| b == b' ' || b == b'\t')
        {
            // Not at the start of a line: leave it alone and move past it.
            let keep = at + MARKER.len();
            out.push_str(&rest[..keep]);
            rest = &rest[keep..];
            continue;
        }
        // The rest of the marker line must be blank.
        let Some(eol) = rest[at..].find('\n') else {
            out.push_str(rest);
            return out;
        };
        let marker_end = at + eol + 1;
        if !rest[at + MARKER.len()..at + eol]
            .bytes()
            .all(|b| b == b' ' || b == b'\t')
        {
            out.push_str(&rest[..marker_end]);
            rest = &rest[marker_end..];
            continue;
        }
        // Then the include line itself.
        let next_line_end = rest[marker_end..]
            .find('\n')
            .map(|n| marker_end + n + 1)
            .unwrap_or(rest.len());
        let next_line = rest[marker_end..next_line_end].trim_end_matches('\n');
        if next_line.trim_end() != include_line {
            out.push_str(&rest[..marker_end]);
            rest = &rest[marker_end..];
            continue;
        }
        // `\n?` before the marker is part of the match.
        let cut = if line_start > 0 {
            line_start - 1
        } else {
            line_start
        };
        out.push_str(&rest[..cut]);
        out.push('\n');
        rest = &rest[next_line_end..];
    }
}

/// `\n    location / \{\n(?:        [^\n]*\n)*    \}\n` - lifted out, with the
/// surrounding text closed up the way the Python closes it.
fn lift_main_location(content: &str) -> (String, Option<String>) {
    const HEAD: &str = "\n    location / {\n";
    let Some(start) = content.find(HEAD) else {
        return (content.to_string(), None);
    };
    let mut at = start + HEAD.len();
    loop {
        let line_end = match content[at..].find('\n') {
            Some(n) => at + n + 1,
            None => return (content.to_string(), None),
        };
        let line = &content[at..line_end - 1];
        if line == "    }" {
            let matched = &content[start..line_end];
            let before = content[..start].trim_end();
            let after = content[line_end..].trim_start_matches('\n');
            return (
                format!("{before}\n{after}"),
                Some(matched.trim_matches('\n').to_string()),
            );
        }
        if !line.starts_with("        ") {
            return (content.to_string(), None);
        }
        at = line_end;
    }
}
