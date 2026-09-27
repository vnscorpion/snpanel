//! Reading a user backup back in.
//!
//! The archive is a customer's whole account — their sites, their databases,
//! their applications — and it may have come from another machine. So every
//! name out of it is checked before it is used for anything: a domain against
//! the panel's own pattern, a member path against the destination it is
//! extracted into, a database name against what already exists.
//!
//! Source: `backend/app/services/backup.py`, the `restore_user_backup` half.

use std::path::{Path, PathBuf};

use crate::tarfilter::{data_filter, Member, MemberKind};

/// Source: `RESTORABLE_BACKUP_KINDS`. The panel reads its own archives and
/// the ones the tool it replaced wrote.
pub const RESTORABLE_KINDS: &[&str] = &["snpanel_user", "opanel_user"];

/// Source: `_PLACEHOLDER_EMAIL_SUFFIXES`.
///
/// An address the panel invented for an account that never had one. Carrying
/// it across would leave a restored account looking like it has a real
/// address on a domain this installation does not own.
pub const PLACEHOLDER_EMAIL_SUFFIXES: &[&str] = &[
    "@users.snpanel.test",
    "@users.snpanel.vn",
    "@users.opanel.test",
    "@users.opanel.vn",
];

/// `MAX_UPLOAD_BYTES` — the ceiling on a single member read out of an
/// archive.
pub const MAX_MEMBER_BYTES: u64 = 1024 * 1024 * 1024;

/// Extract everything under `prefix/` into `destination`, with the prefix
/// taken off the front of each name.
///
/// Source: `_safe_extract_prefix`. Two rules, and the order matters: a hard
/// link is dropped before anything else looks at it, and what is left goes
/// through `data_filter`, which is what clamps the mode and refuses a path
/// or a link that points out of the destination.
pub fn extract_prefix(archive: &Path, prefix: &str, destination: &Path) -> Result<(), String> {
    std::fs::create_dir_all(destination).map_err(|e| e.to_string())?;
    let prefix = prefix.trim_matches('/');
    let file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let decoder = flate2::read::GzDecoder::new(std::io::BufReader::new(file));
    let mut tar = tar::Archive::new(decoder);
    let entries = tar.entries().map_err(|e| e.to_string())?;

    for entry in entries {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let raw = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        if raw == prefix {
            continue;
        }
        let Some(name) = raw.strip_prefix(&format!("{prefix}/")) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let header = entry.header();
        let kind = header.entry_type();
        // `if original.islnk(): continue` — a hard link into a tree being
        // rebuilt from scratch has nothing to point at.
        if kind.is_hard_link() {
            continue;
        }
        let member = Member {
            name: name.to_string(),
            kind: match kind {
                k if k.is_dir() => MemberKind::Directory,
                k if k.is_symlink() => MemberKind::Symlink,
                k if k.is_file() => MemberKind::Regular,
                _ => MemberKind::Special,
            },
            mode: header.mode().ok(),
            linkname: entry
                .link_name()
                .ok()
                .flatten()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            uid: header.uid().ok().map(|v| v as u32),
            gid: header.gid().ok().map(|v| v as u32),
            uname: header.username().ok().flatten().map(str::to_string),
            gname: header.groupname().ok().flatten().map(str::to_string),
        };
        let filtered = match data_filter(&member, destination) {
            Ok(filtered) => filtered,
            // `data_filter` raising is the Python's "Backup archive contains
            // unsafe paths": the whole restore stops rather than the member
            // being skipped, because a backup that tries to write outside
            // itself is not one to take the rest of on trust.
            Err(why) => {
                return Err(format!(
                    "Backup archive contains unsafe paths: {}",
                    why.as_str()
                ))
            }
        };
        let target = destination.join(&filtered.name);
        match filtered.kind {
            MemberKind::Directory => {
                std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
            }
            MemberKind::Regular => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                entry.unpack(&target).map_err(|e| e.to_string())?;
            }
            MemberKind::Symlink => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                let _ = std::fs::remove_file(&target);
                std::os::unix::fs::symlink(&filtered.linkname, &target)
                    .map_err(|e| e.to_string())?;
            }
            // A device node or a socket in a customer's backup is not
            // something to recreate as root.
            MemberKind::Hardlink | MemberKind::Special => continue,
        }
        if let (Some(mode), MemberKind::Regular | MemberKind::Directory) =
            (filtered.mode, filtered.kind)
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode));
        }
    }
    Ok(())
}

/// Pull one named member out and write it beside the others.
///
/// Source: `_extract_member_to_file`. A member that is not there is not an
/// error — a backup without a SQL dump is a site without a database — but one
/// that is there and is not a plain file, or is enormous, is.
pub fn extract_member_to_file(
    archive: &Path,
    member_name: &str,
    output_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    use std::io::{Read, Write};

    let file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let decoder = flate2::read::GzDecoder::new(std::io::BufReader::new(file));
    let mut tar = tar::Archive::new(decoder);
    let entries = tar.entries().map_err(|e| e.to_string())?;

    for entry in entries {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let raw = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        if raw != member_name {
            continue;
        }
        let header = entry.header();
        if !header.entry_type().is_file() || header.size().unwrap_or(0) > MAX_MEMBER_BYTES {
            return Err("Invalid SQL backup member".to_string());
        }
        std::fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
        // `output_dir / Path(member_name).name` — the basename, so a member
        // called `a/b/c.sql` lands as `c.sql` and cannot climb.
        let base = Path::new(member_name)
            .file_name()
            .map(|n| n.to_owned())
            .ok_or_else(|| "Invalid SQL backup member".to_string())?;
        let target = output_dir.join(base);
        let mut out = std::fs::File::create(&target).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = entry.read(&mut buffer).map_err(|e| e.to_string())?;
            if read == 0 {
                break;
            }
            out.write_all(&buffer[..read]).map_err(|e| e.to_string())?;
        }
        return Ok(Some(target));
    }
    Ok(None)
}

/// Is this hostname already spoken for?
///
/// Source: `_hostname_conflicts`. Every site's domain counts, and so does
/// `www.` in front of it — two sites answering for the same name is a config
/// nginx will not load, and finding that out at `nginx -t` time leaves a
/// half-restored account behind.
pub fn hostname_conflicts(
    domain: &str,
    websites: &[(i64, String)],
    aliases: &[(i64, String)],
    exclude_website_id: Option<i64>,
) -> bool {
    let safe = domain.trim().to_lowercase();
    if safe.is_empty() {
        return true;
    }
    let mut reserved: Vec<String> = Vec::new();
    for (id, hostname) in websites {
        if exclude_website_id == Some(*id) {
            continue;
        }
        let hostname = hostname.trim().to_lowercase();
        if hostname.is_empty() {
            continue;
        }
        reserved.push(format!("www.{hostname}"));
        reserved.push(hostname);
    }
    for (website_id, alias) in aliases {
        if exclude_website_id == Some(*website_id) {
            continue;
        }
        let alias = alias.trim().to_lowercase();
        if !alias.is_empty() {
            reserved.push(alias);
        }
    }
    reserved.contains(&safe) || reserved.contains(&format!("www.{safe}"))
}

/// `email.endswith(_PLACEHOLDER_EMAIL_SUFFIXES)`.
pub fn is_placeholder_email(email: &str) -> bool {
    PLACEHOLDER_EMAIL_SUFFIXES
        .iter()
        .any(|suffix| email.ends_with(suffix))
}

/// The four rewrite modes a restored site may declare, and the fallback.
///
/// Source: the two `if ... not in {...}` guards. A mode the panel does not
/// know becomes the sensible one for the app type rather than being refused:
/// the archive may have been written by a release that had another.
pub fn rewrite_mode_for(declared: Option<&str>, app_type: &str) -> String {
    const KNOWN: &[&str] = &[
        "none",
        "front_controller",
        "laravel",
        "codeigniter",
        "seohburl",
    ];
    match declared {
        Some(mode) if KNOWN.contains(&mode) => mode.to_string(),
        _ => {
            if app_type == "wordpress" || app_type == "php" {
                "front_controller".to_string()
            } else {
                "none".to_string()
            }
        }
    }
}

/// Source: the `app_type not in {...}` guard.
pub fn app_type_for(declared: Option<&str>) -> String {
    match declared {
        Some(kind) if matches!(kind, "wordpress" | "php" | "static") => kind.to_string(),
        _ => "wordpress".to_string(),
    }
}

/// The alias list a restored site should end up with.
///
/// Source: the two comprehensions — trimmed, lowercased, the site's own
/// domain dropped, and de-duplicated into sorted order.
pub fn alias_domains(raw: &[String], domain: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for alias in raw {
        let alias = alias.trim().to_lowercase();
        if alias.is_empty() || alias == domain {
            continue;
        }
        if !out.contains(&alias) {
            out.push(alias);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_www_prefix_counts_as_taken() {
        let sites = vec![(1i64, "example.com".to_string())];
        assert!(hostname_conflicts("example.com", &sites, &[], None));
        // The site reserves `www.` in front of itself...
        assert!(hostname_conflicts("www.example.com", &sites, &[], None));
        // ...and a name whose `www.` form is taken is taken too.
        assert!(!hostname_conflicts("other.com", &sites, &[], None));
        // Excluding the site itself frees both.
        assert!(!hostname_conflicts("example.com", &sites, &[], Some(1)));
    }

    #[test]
    fn an_alias_of_another_site_conflicts() {
        let aliases = vec![(2i64, "shop.example.com".to_string())];
        assert!(hostname_conflicts("shop.example.com", &[], &aliases, None));
        assert!(!hostname_conflicts(
            "shop.example.com",
            &[],
            &aliases,
            Some(2)
        ));
    }

    #[test]
    fn an_empty_hostname_is_always_a_conflict() {
        assert!(hostname_conflicts("", &[], &[], None));
        assert!(hostname_conflicts("   ", &[], &[], None));
    }

    #[test]
    fn the_site_own_domain_is_not_one_of_its_aliases() {
        let raw = vec![
            "  WWW.Example.com ".to_string(),
            "example.com".to_string(),
            "shop.example.com".to_string(),
            "shop.example.com".to_string(),
            "".to_string(),
        ];
        assert_eq!(
            alias_domains(&raw, "example.com"),
            ["shop.example.com", "www.example.com"]
        );
    }

    #[test]
    fn an_unknown_rewrite_mode_falls_back_by_app_type() {
        assert_eq!(rewrite_mode_for(Some("laravel"), "php"), "laravel");
        assert_eq!(
            rewrite_mode_for(Some("nonsense"), "php"),
            "front_controller"
        );
        assert_eq!(rewrite_mode_for(None, "static"), "none");
        assert_eq!(rewrite_mode_for(None, "wordpress"), "front_controller");
    }

    #[test]
    fn an_unknown_app_type_becomes_wordpress() {
        assert_eq!(app_type_for(Some("static")), "static");
        assert_eq!(app_type_for(Some("node")), "wordpress");
        assert_eq!(app_type_for(None), "wordpress");
    }

    #[test]
    fn a_placeholder_address_is_recognised_on_every_domain_the_panel_invented() {
        for suffix in PLACEHOLDER_EMAIL_SUFFIXES {
            assert!(is_placeholder_email(&format!("bob{suffix}")));
        }
        assert!(!is_placeholder_email("bob@example.com"));
        // The one the panel writes *now* is not in the list: it is what a
        // placeholder is replaced **with**, so treating it as one would
        // rewrite a fresh address on every restore.
        assert!(!is_placeholder_email("bob@users.snpanel.invalid"));
    }
}
