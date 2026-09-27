//! What a vhost rewrite writes, decided separately from who writes it.
//!
//! Source: the second half of `rewrite_vhost`, after `render_vhost` returns.
//! That half reads the file on disk, carries three things across the rewrite -
//! the blocked bots, a certbot certificate, the redirect vhosts - and then
//! writes, tests and reloads.
//!
//! The decisions and the I/O are split here. This produces a [`VhostPlan`]:
//! the bytes that should end up in each file and the bytes that were there
//! before. The caller writes them, asks the helper to test the configuration
//! and rolls back with what the plan handed it.
//!
//! Two reasons for the split rather than a trait with the I/O behind it. The
//! caller's helper calls are async and this crate has no runtime; and the
//! interesting part - what happens to a live certificate when a customer
//! renames their document root - is then a pure function with the file
//! contents as arguments, which is something a test can drive.

use std::path::{Path, PathBuf};

use crate::{
    append_redirect_vhosts, render_vhost, safe_alias_domains, safe_domain, RenderError, VhostEnv,
    VhostInput,
};

/// Everything a rewrite changes on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhostPlan {
    /// `<sites-available>/<domain>.conf`.
    pub path: PathBuf,
    /// What that file should contain.
    pub content: String,
    /// What it contained before, or `None` if it did not exist. The caller
    /// restores this if `nginx -t` refuses the result.
    pub previous: Option<String>,
    /// What the customer's include should contain, written through the
    /// helper's `nginx-custom-write` because `/etc/nginx` is root's.
    pub custom_include: String,
    /// Where that include lives, for the caller's rollback.
    pub custom_include_path: String,
}

/// Source: `_vhost_path`.
pub fn vhost_path(sites_available: &Path, domain: &str) -> Result<PathBuf, RenderError> {
    Ok(sites_available.join(format!("{}.conf", safe_domain(domain)?)))
}

/// Source: `_has_ssl_config`.
fn has_ssl_config(content: &str) -> bool {
    content.contains("ssl_certificate") || content.contains("listen 443")
}

/// Source: `_certbot_ssl_lines` - the lines certbot added, de-duplicated by
/// their stripped form but kept with their original indentation.
fn certbot_ssl_lines(content: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for line in content.lines() {
        let stripped = line.trim().to_string();
        let interesting = line.contains("ssl_certificate")
            || line.contains("include /etc/letsencrypt/options-ssl-nginx.conf")
            || line.contains("ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem");
        if interesting && !seen.contains(&stripped) {
            lines.push(line.to_string());
            seen.push(stripped);
        }
    }
    lines
}

/// The `server_name` of the first server block, or `_`.
fn first_server_name(content: &str) -> String {
    match content.split_once("server_name ") {
        Some((_, rest)) => match rest.split_once(';') {
            Some((name, _)) => name.trim().to_string(),
            None => rest.trim().to_string(),
        },
        None => "_".to_string(),
    }
}

/// Source: `_merge_certbot_ssl_config`.
///
/// This is the one that must not be got wrong. A site whose certificate
/// certbot installed has its `ssl_certificate` lines in the file and nowhere
/// else - not in the database, not in the template. A rewrite that drops them
/// takes HTTPS off a working site, and the customer finds out before the
/// panel does.
fn merge_certbot_ssl_config(new_content: &str, existing_content: &str) -> String {
    let server_name = first_server_name(new_content);
    let ssl_lines = certbot_ssl_lines(existing_content);

    let mut https_lines: Vec<String> = Vec::new();
    for line in new_content.lines() {
        if line.contains("listen 80;") {
            https_lines.push(line.replace("listen 80;", "listen 443 ssl http2;"));
        } else {
            https_lines.push(line.to_string());
        }
        // Note: no `inserted` flag here, unlike `apply_manual_ssl_config`.
        // The Python repeats the block after *every* line containing
        // `server_name`, and the redirect vhosts this later appends each have
        // one. Faithful, because the alternative is a different file.
        if line.contains("server_name") && !ssl_lines.is_empty() {
            https_lines.extend(ssl_lines.iter().cloned());
        }
    }
    let redirect_block = [
        "server {",
        "    listen 80;",
        &format!("    server_name {server_name};"),
        "    return 301 https://$host$request_uri;",
        "}",
        "",
    ]
    .join("\n");
    format!("{redirect_block}{}\n", https_lines.join("\n"))
}

/// Source: `_append_certbot_redirect_vhosts`.
fn append_certbot_redirect_vhosts(
    content: &str,
    domain: &str,
    redirects: &[String],
) -> Result<String, RenderError> {
    let safe = safe_domain(domain)?;
    let reserved = [safe.clone(), format!("www.{safe}")];
    let ssl_lines = certbot_ssl_lines(content);
    let mut blocks: Vec<String> = Vec::new();
    for redirect_domain in safe_alias_domains(redirects)? {
        if reserved.iter().any(|r| r == &redirect_domain) {
            continue;
        }
        let mut lines = vec![
            "server {".to_string(),
            "    listen 80;".to_string(),
            format!("    server_name {redirect_domain};"),
            String::new(),
            "    # SNPANEL ACME CHALLENGE".to_string(),
            "    location ^~ /.well-known/acme-challenge/ {".to_string(),
            "        root /var/www/snpanel-acme;".to_string(),
            "        default_type text/plain;".to_string(),
            "        try_files $uri =404;".to_string(),
            "        access_log off;".to_string(),
            "        auth_basic off;".to_string(),
            "    }".to_string(),
            String::new(),
            format!("    return 301 https://{safe}$request_uri;"),
            "}".to_string(),
        ];
        if !ssl_lines.is_empty() {
            lines.extend([
                String::new(),
                "server {".to_string(),
                "    listen 443 ssl http2;".to_string(),
                format!("    server_name {redirect_domain};"),
            ]);
            lines.extend(ssl_lines.iter().cloned());
            lines.extend([
                format!("    return 301 https://{safe}$request_uri;"),
                "}".to_string(),
            ]);
        }
        blocks.push(lines.join("\n"));
    }
    if blocks.is_empty() {
        return Ok(content.to_string());
    }
    Ok(format!(
        "{}\n\n{}\n",
        content.trim_end(),
        blocks.join("\n\n")
    ))
}

/// Source: `blocked_bots_in_vhost`.
///
/// The names went through `re.escape` on the way in, so they come back
/// through a matching unescape. Anything that does not parse yields an empty
/// list, which the caller reads as "nothing to preserve" rather than a guess.
pub fn blocked_bots_in_vhost(content: &str) -> Vec<String> {
    const BEGIN: &str = "# SNPANEL BOT BLOCK BEGIN\n";
    let Some(at) = content.find(BEGIN) else {
        return Vec::new();
    };
    let rest = &content[at + BEGIN.len()..];
    // `\s*if \(\$http_user_agent ~\* "\((.*?)\)"\) \{ return 403; \}`
    let rest = rest.trim_start();
    const HEAD: &str = "if ($http_user_agent ~* \"(";
    if !rest.starts_with(HEAD) {
        return Vec::new();
    }
    let after = &rest[HEAD.len()..];
    // `(.*?)` is non-greedy, so it stops at the first `)")` that is followed
    // by the rest of the line.
    const TAIL: &str = ")\") { return 403; }";
    let Some(end) = after.find(TAIL) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for piece in after[..end].split('|') {
        if piece.is_empty() {
            continue;
        }
        names.push(unescape(piece));
    }
    names
}

/// `re.sub(r"\\(.)", r"\1", piece)` - one backslash removed before any
/// character, left to right.
fn unescape(piece: &str) -> String {
    let mut out = String::with_capacity(piece.len());
    let mut chars = piece.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Decide what a rewrite should put on disk.
///
/// `existing` is the current content of the vhost file, which the caller
/// reads; `None` means the site has no vhost yet. `preserve_existing_ssl` is
/// the Python's argument of the same name: a full rewrite must not remove a
/// certificate that certbot installed, unless the caller is installing one of
/// its own.
pub fn plan_rewrite(
    input: &VhostInput<'_>,
    env: &VhostEnv,
    sites_available: &Path,
    existing: Option<&str>,
    preserve_existing_ssl: bool,
) -> Result<VhostPlan, RenderError> {
    let safe = safe_domain(input.domain)?;
    let path = vhost_path(sites_available, &safe)?;

    // `blocked_bots=None` means "keep whatever this vhost already blocks".
    // Without it every full rewrite - a PHP version change, a new alias -
    // silently dropped the block, because the callers that rebuild a vhost do
    // not all know about bot lists.
    let carried: Vec<String> = match (input.blocked_bots, existing) {
        (Some(_), _) => Vec::new(),
        (None, Some(text)) => blocked_bots_in_vhost(text),
        (None, None) => Vec::new(),
    };

    // The redirects are appended after the certificate work, not by the
    // renderer, exactly as the Python does it.
    let no_redirects: [String; 0] = [];
    // Struct-update syntax rather than `clone()` then assign: `carried` is a
    // local, and the clone would keep the caller's longer lifetime.
    let render_input = VhostInput {
        redirects: &no_redirects,
        blocked_bots: match input.blocked_bots {
            Some(bots) => Some(bots),
            None => Some(&carried),
        },
        ..input.clone()
    };
    let mut content = render_vhost(&render_input, env)?;

    let manual = input.ssl_cert_path.is_some() && input.ssl_key_path.is_some();
    if let Some(existing) = existing {
        if preserve_existing_ssl && has_ssl_config(existing) && !manual {
            content = merge_certbot_ssl_config(&content, existing);
        }
    }
    content = if preserve_existing_ssl && !manual {
        append_certbot_redirect_vhosts(&content, &safe, input.redirects)?
    } else {
        append_redirect_vhosts(
            &content,
            &safe,
            input.redirects,
            input.ssl_cert_path,
            input.ssl_key_path,
            input.ssl_ca_path,
        )?
    };

    Ok(VhostPlan {
        path,
        content,
        previous: existing.map(str::to_string),
        custom_include: input.custom_directives.as_str().to_string(),
        custom_include_path: crate::custom_include_path(&safe)?,
    })
}
