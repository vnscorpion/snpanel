//! Replacing the server's IP address everywhere the panel wrote it down.
//!
//! Source: `change_IP.sh`.
//!
//! **That file was never in the repository.** One commit has ever touched it,
//! the initial import, and no release has carried it - so
//! `/usr/local/sbin/snpanel-change-ip` does not exist on a box installed from
//! one, and `snpanel change-ip` has been reporting a missing script rather
//! than doing anything. Porting it is what makes the command work at all.
//!
//! What it does is narrow on purpose: it edits text files and nothing else,
//! and it copies every file it is about to touch into a backup directory
//! first. An address appears in the panel's `.env`, in nginx vhosts, in
//! systemd units, in phpMyAdmin's sign-on file and in `/etc/hosts`, and a
//! run that got one of them wrong would be a box reachable at neither
//! address.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// Source: `APP_DIR`, `SNPANEL_DATA_DIR`, `LOGIN_FILE`.
const DATA_DIR: &str = "/var/lib/snpanel";
const LOGIN_FILE: &str = "/root/login.txt";

/// Extensions the walk will read.
///
/// Source: the `case` in `collect_glob`. An allow-list rather than a
/// deny-list: the alternative is deciding what a `.bak` or a `.orig` is, and
/// the cost of missing a file is a stale address while the cost of editing
/// the wrong one is a corrupt database.
const TEXT_SUFFIXES: &[&str] = &[
    ".env", ".conf", ".json", ".php", ".txt", ".yml", ".yaml", ".ini", ".service", ".timer",
    ".socket", ".sh", ".js", ".css", ".html",
];

/// Directories the walk does not descend into.
///
/// Source: the `-prune` list. `assets` is there because it holds uploaded
/// files, which are a customer's and not the panel's to rewrite.
const PRUNED: &[&str] = &[".git", ".venv", "node_modules", "__pycache__", "assets"];

/// Trees the panel writes an address into.
const TREES: &[&str] = &["/etc/nginx", "/etc/phpmyadmin", "/etc/systemd/system"];

/// Source: `is_ipv4` - four dotted decimal octets, each 0-255.
///
/// Deliberately not a general address parser. The file this rewrites holds
/// `listen` directives and `ALLOWED_ORIGINS`; accepting something that is not
/// a v4 address would mean rewriting text that merely looks like one.
pub fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// Source: the Perl `s/(?<![0-9.])\Qold\E(?![0-9.])/new/g`.
///
/// The lookarounds are the whole of it. Without them, changing `10.0.0.1`
/// would also rewrite the `10.0.0.1` inside `10.0.0.10` and inside
/// `110.0.0.1`, turning one address into two wrong ones - and the second is
/// the kind of thing nobody notices until a firewall rule stops matching.
pub fn replace_address(text: &str, old: &str, new: &str) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut hits = 0;
    while let Some(found) = text[i..].find(old) {
        let at = i + found;
        let end = at + old.len();
        let before_ok = at == 0 || !is_address_char(bytes[at - 1]);
        let after_ok = end == bytes.len() || !is_address_char(bytes[end]);
        out.push_str(&text[i..at]);
        if before_ok && after_ok {
            out.push_str(new);
            hits += 1;
        } else {
            out.push_str(old);
        }
        i = end;
    }
    out.push_str(&text[i..]);
    (out, hits)
}

fn is_address_char(b: u8) -> bool {
    b.is_ascii_digit() || b == b'.'
}

/// Is this a file the walk should read?
pub fn is_text_candidate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    // `.env.production` and friends: the source matches `*.env.*` as well as
    // `*.env`.
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    TEXT_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Source: `grep -I` - a file with a NUL byte in it is binary, and the shell
/// skips it rather than deciding what a text replacement would mean there.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

/// `snpanel change-ip <old> <new>`.
pub fn change_ip(old_ip: &str, new_ip: &str, app_dir: &str) -> Result<()> {
    if !is_ipv4(old_ip) {
        anyhow::bail!("Invalid old IP: {old_ip}");
    }
    if !is_ipv4(new_ip) {
        anyhow::bail!("Invalid new IP: {new_ip}");
    }
    if old_ip == new_ip {
        anyhow::bail!("Old IP and new IP are the same");
    }

    let backup_root = make_backup_root()?;
    let files = collect_files(app_dir);

    let mut changed: Vec<PathBuf> = Vec::new();
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        if looks_binary(&bytes) {
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let (updated, hits) = replace_address(&text, old_ip, new_ip);
        if hits == 0 {
            continue;
        }
        back_up(path, &backup_root)?;
        std::fs::write(path, updated).with_context(|| format!("writing {}", path.display()))?;
        changed.push(path.clone());
    }

    // Two files the replacement cannot fix on its own, because what they hold
    // is derived from `.env` rather than being a copy of the address.
    let panel_url = env_value(app_dir, "PANEL_URL");
    if let Some(url) = panel_url.filter(|u| !u.is_empty()) {
        if sync_panel_settings(&url, &backup_root)? {
            changed.push(PathBuf::from(format!("{DATA_DIR}/panel-settings.json")));
        }
        if sync_login_file(&url, &backup_root)? {
            changed.push(PathBuf::from(LOGIN_FILE));
        }
    }

    if !changed.is_empty() {
        reload_services();
    }

    println!("Updated {} file(s).", changed.len());
    if changed.is_empty() {
        println!("No matching SNPanel files contained {old_ip}.");
        println!("Backup: {} (no files were changed)", backup_root.display());
    } else {
        println!("Backup: {}", backup_root.display());
        println!("Changed files:");
        for path in &changed {
            println!("  {}", path.display());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------

/// Source: `mktemp -d /root/snpanel-ip-change.XXXXXX`.
///
/// Under `/root` rather than `/tmp`: the copies hold the panel's `SECRET_KEY`
/// and its admin password, and `/tmp` is world-readable.
fn make_backup_root() -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    for attempt in 0..64 {
        let suffix = format!("{:06x}", std::process::id() as u32 ^ (attempt << 16));
        let path = PathBuf::from(format!("/root/snpanel-ip-change.{suffix}"));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).context("creating the backup directory under /root"),
        }
    }
    anyhow::bail!("could not create a backup directory under /root")
}

/// `cp -a` into the backup tree, keeping the original path below it.
fn back_up(src: &Path, backup_root: &Path) -> Result<()> {
    let relative = src.strip_prefix("/").unwrap_or(src);
    let dest = backup_root.join(relative);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::copy(src, &dest).with_context(|| format!("backing up {}", src.display()))?;
    Ok(())
}

/// Every file the panel might have written the address into.
fn collect_files(app_dir: &str) -> Vec<PathBuf> {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    // The named ones first, including the two that are not under any tree.
    for path in [
        format!("{app_dir}/backend/.env"),
        format!("{DATA_DIR}/panel-settings.json"),
        LOGIN_FILE.to_string(),
        "/etc/hosts".to_string(),
        "/usr/share/phpmyadmin/snpanel-signon.php".to_string(),
    ] {
        let p = PathBuf::from(&path);
        if p.is_file() {
            if let Ok(resolved) = p.canonicalize() {
                seen.insert(resolved);
            }
        }
    }

    let mut roots: Vec<String> = vec![app_dir.to_string(), DATA_DIR.to_string()];
    roots.extend(TREES.iter().map(|t| t.to_string()));
    for root in roots {
        walk(Path::new(&root), &mut seen);
    }

    seen.into_iter().collect()
}

fn walk(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if PRUNED.iter().any(|p| *p == name) {
                continue;
            }
            walk(&path, out);
        } else if kind.is_file() && is_text_candidate(&path) {
            if let Ok(resolved) = path.canonicalize() {
                out.insert(resolved);
            }
        }
    }
}

/// Source: `env_value` - the first match, everything after the first `=`.
fn env_value(app_dir: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("{app_dir}/backend/.env")).ok()?;
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::to_string)
}

/// Source: `sync_panel_settings_json`, which shelled out to `python3`.
///
/// The address in this file is not a copy of the old one - it is a whole URL
/// the panel serves itself on - so the text replacement above will have
/// fixed it only if the old address appears in it literally. This makes it
/// agree with `.env` either way.
pub fn merged_panel_settings(existing: &str, panel_url: &str) -> Option<String> {
    let mut value: serde_json::Value =
        serde_json::from_str(existing).unwrap_or_else(|_| serde_json::json!({}));
    if !value.is_object() {
        value = serde_json::json!({});
    }
    if value.get("panel_url").and_then(|v| v.as_str()) == Some(panel_url) {
        return None;
    }
    value["panel_url"] = serde_json::Value::String(panel_url.to_string());
    // `json.dumps(..., ensure_ascii=True, indent=2, sort_keys=True) + "\n"`.
    // serde_json's maps preserve insertion order unless the crate is built
    // with `preserve_order` off, so the keys are collected and sorted here
    // rather than relied on.
    let sorted = sort_keys(value);
    Some(format!("{}\n", serde_json::to_string_pretty(&sorted).ok()?))
}

fn sort_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::new();
            for (k, v) in entries {
                out.insert(k, sort_keys(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sort_keys).collect())
        }
        other => other,
    }
}

fn sync_panel_settings(panel_url: &str, backup_root: &Path) -> Result<bool> {
    let path = PathBuf::from(format!("{DATA_DIR}/panel-settings.json"));
    if !path.is_file() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let Some(updated) = merged_panel_settings(&existing, panel_url) else {
        return Ok(false);
    };
    back_up(&path, backup_root)?;
    std::fs::write(&path, updated).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// Source: `sync_login_info_url`.
///
/// C17: the file's first line is `Panel URL: `. The source inserts one when
/// it is missing rather than leaving the file without it.
pub fn login_file_with_url(existing: &str, panel_url: &str) -> Option<String> {
    let mut lines: Vec<String> = existing.lines().map(str::to_string).collect();
    let wanted = format!("Panel URL: {panel_url}");
    match lines.iter_mut().find(|l| l.starts_with("Panel URL: ")) {
        Some(line) => {
            if *line == wanted {
                return None;
            }
            *line = wanted;
        }
        None => lines.insert(0, wanted),
    }
    Some(format!("{}\n", lines.join("\n")))
}

fn sync_login_file(panel_url: &str, backup_root: &Path) -> Result<bool> {
    let path = PathBuf::from(LOGIN_FILE);
    if !path.is_file() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let Some(updated) = login_file_with_url(&existing, panel_url) else {
        return Ok(false);
    };
    back_up(&path, backup_root)?;
    // 0600, as `write_login_info` writes it: the file holds the admin
    // password in clear.
    crate::passwords::write_0600(&path, &updated)?;
    Ok(true)
}

/// Source: `reload_systemd`, `restart_if_loaded snpanel-api`, `reload_nginx`.
///
/// **One measured difference.** The shell restarts `snpanel-api` and only
/// that. On a box that cut over to `snpanel-rust` the unit is not loaded, so
/// the shell restarts nothing and the panel goes on serving the old address
/// until somebody notices. That is the third time in this migration that code
/// written before the cutover named the one unit it knew about, and it is
/// recorded as a recurring failure rather than a one-off - so this uses the
/// same resolution the rest of this CLI does.
fn reload_services() {
    let _ = Command::new("systemctl")
        .arg("daemon-reload")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    for unit in crate::ops::panel_units() {
        if !unit_is_loaded(unit) {
            continue;
        }
        let ok = Command::new("systemctl")
            .args(["restart", unit])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("WARN: Could not restart {unit}");
        }
    }

    if unit_is_loaded("nginx") {
        let valid = Command::new("nginx")
            .arg("-t")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !valid {
            eprintln!("WARN: nginx -t failed; please review the edited config files manually");
            return;
        }
        let ok = Command::new("systemctl")
            .args(["reload", "nginx"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("WARN: Could not reload nginx");
        }
    }
}

fn unit_is_loaded(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["show", "-p", "LoadState", "--value", unit])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "loaded")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_four_octets_and_nothing_else() {
        for good in ["10.0.0.1", "0.0.0.0", "255.255.255.255", "192.0.2.1"] {
            assert!(is_ipv4(good), "{good}");
        }
        for bad in [
            "",
            "10.0.0",
            "10.0.0.1.1",
            "256.0.0.1",
            "10.0.0.-1",
            "10.0.0.a",
            "1000.0.0.1",
            " 10.0.0.1",
            "10.0.0.1 ",
            "::1",
        ] {
            assert!(!is_ipv4(bad), "{bad} should be refused");
        }
    }

    /// The lookarounds, which are the whole point of the replacement.
    #[test]
    fn a_longer_address_that_starts_the_same_is_left_alone() {
        // `10.0.0.1` inside `10.0.0.10` and inside `110.0.0.1`.
        let text = "a=10.0.0.1\nb=10.0.0.10\nc=110.0.0.1\nd=10.0.0.1:2222\n";
        let (out, hits) = replace_address(text, "10.0.0.1", "192.0.2.5");
        assert_eq!(hits, 2, "{out}");
        assert_eq!(
            out,
            "a=192.0.2.5\nb=10.0.0.10\nc=110.0.0.1\nd=192.0.2.5:2222\n"
        );
    }

    #[test]
    fn a_file_without_the_address_is_untouched() {
        let text = "listen 80;\nserver_name example.com;\n";
        let (out, hits) = replace_address(text, "10.0.0.1", "192.0.2.5");
        assert_eq!(hits, 0);
        assert_eq!(out, text);
    }

    #[test]
    fn the_replacement_keeps_a_file_that_does_not_end_in_a_newline() {
        // The source slurps the whole file with `perl -0pi`, so a file whose
        // last line has no newline keeps it that way.
        let (out, hits) = replace_address("url=10.0.0.1", "10.0.0.1", "192.0.2.5");
        assert_eq!(hits, 1);
        assert_eq!(out, "url=192.0.2.5");
    }

    #[test]
    fn only_text_shaped_names_are_read() {
        for good in [
            "/opt/snpanel/backend/.env",
            "/opt/snpanel/backend/.env.production",
            "/etc/nginx/conf.d/site.conf",
            "/var/lib/snpanel/panel-settings.json",
            "/root/login.txt",
            "/etc/systemd/system/snpanel-api.service",
            "/usr/share/phpmyadmin/snpanel-signon.php",
        ] {
            assert!(is_text_candidate(Path::new(good)), "{good}");
        }
        // The ones the source names explicitly, because editing them is how a
        // run stops being recoverable.
        for bad in [
            "/opt/snpanel/backend/snpanel.db",
            "/etc/snpanel/panel-privkey.pem",
            "/etc/snpanel/panel-fullchain.crt",
            "/var/lib/snpanel/assets/logo.png",
            "/root/backup.tar.gz",
        ] {
            assert!(
                !is_text_candidate(Path::new(bad)),
                "{bad} should be skipped"
            );
        }
    }

    #[test]
    fn a_binary_file_is_skipped_even_with_a_text_name() {
        // `grep -I`. A `.conf` that is actually a database would otherwise be
        // rewritten as if it were text.
        assert!(looks_binary(b"SQLite format 3\0\x04\x00"));
        assert!(!looks_binary(b"listen 80;\n"));
    }

    #[test]
    fn the_settings_file_is_left_alone_when_it_already_agrees() {
        let existing = "{\n  \"panel_url\": \"https://x:2222\"\n}\n";
        assert!(merged_panel_settings(existing, "https://x:2222").is_none());
    }

    #[test]
    fn the_settings_file_keeps_its_other_keys_and_sorts_them() {
        let existing = "{\"zebra\": 1, \"alpha\": 2, \"panel_url\": \"https://old:2222\"}";
        let out = merged_panel_settings(existing, "https://new:2222").expect("a rewrite");
        assert!(out.contains("\"panel_url\": \"https://new:2222\""), "{out}");
        assert!(out.contains("\"zebra\": 1"), "{out}");
        assert!(out.contains("\"alpha\": 2"), "{out}");
        // sort_keys=True, and a trailing newline.
        assert!(out.find("\"alpha\"") < out.find("\"panel_url\""), "{out}");
        assert!(out.find("\"panel_url\"") < out.find("\"zebra\""), "{out}");
        assert!(out.ends_with("}\n"), "{out:?}");
    }

    #[test]
    fn an_unreadable_settings_file_becomes_one_with_the_url_in_it() {
        // `except Exception: data = {}`. A settings file somebody edited into
        // invalid JSON must not stop the address change.
        let out = merged_panel_settings("not json at all", "https://new:2222").expect("a rewrite");
        assert!(out.contains("\"panel_url\": \"https://new:2222\""), "{out}");
    }

    #[test]
    fn the_login_file_keeps_its_shape() {
        let existing = "Panel URL: https://old:2222\nUser: admin\nPassword: s3cr3t\n";
        let out = login_file_with_url(existing, "https://new:2222").expect("a rewrite");
        assert_eq!(
            out,
            "Panel URL: https://new:2222\nUser: admin\nPassword: s3cr3t\n"
        );
        // And the password line is not touched by any of this.
        assert!(out.contains("Password: s3cr3t"));
    }

    #[test]
    fn a_login_file_without_a_url_line_gains_one_first() {
        let out = login_file_with_url("User: admin\nPassword: s3cr3t\n", "https://new:2222")
            .expect("a rewrite");
        assert!(out.starts_with("Panel URL: https://new:2222\n"), "{out}");
    }

    #[test]
    fn the_login_file_is_left_alone_when_it_already_agrees() {
        let existing = "Panel URL: https://x:2222\nUser: admin\n";
        assert!(login_file_with_url(existing, "https://x:2222").is_none());
    }

    #[test]
    fn the_two_addresses_have_to_differ() {
        let err = change_ip("10.0.0.1", "10.0.0.1", "/opt/snpanel")
            .unwrap_err()
            .to_string();
        assert!(err.contains("the same"), "{err}");
    }

    #[test]
    fn a_bad_address_is_refused_before_anything_is_written() {
        for (old, new) in [("nonsense", "10.0.0.1"), ("10.0.0.1", "nonsense")] {
            let err = change_ip(old, new, "/opt/snpanel").unwrap_err().to_string();
            assert!(err.contains("Invalid"), "{err}");
        }
    }
}
