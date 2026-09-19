//! `snpanel-extract` - unpack a customer's archive, with no privileges at all.
//!
//! A separate binary on purpose. The archive is attacker-controlled input, so
//! whatever reads it must not be running as root; the bash drops to the site's
//! own user with `runuser` before touching it, and this keeps that property.
//! Three ways to do it in-process were considered and rejected: re-executing
//! the helper needs it to be world-executable (it is installed 0750
//! root:snpanel, and widening that to avoid shipping a small binary is the
//! wrong trade), `fork` plus `setuid` is not safe from a threaded process
//! when what follows allocates, and extracting as root and chowning
//! afterwards gives up the containment entirely.
//!
//! So: a program that needs no privileges, does one thing, and is run as the
//! site user by the helper.
//!
//! The order is the bash's and it is the whole safety of the verb. Everything
//! is validated first - every path, every entry type, the item count and the
//! byte total - and only then is anything written. A refusal after the first
//! file would leave a customer's directory half-filled with the contents of
//! an archive that was rejected.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: snpanel-extract <archive> <zip|tar.gz> <destination> <max-items> <max-bytes>"
        );
        return std::process::ExitCode::from(2);
    }
    let archive = PathBuf::from(&args[1]);
    let kind = args[2].clone();
    let destination = PathBuf::from(&args[3]);
    let max_items: usize = args[4].parse().unwrap_or(0);
    let max_bytes: u64 = args[5].parse().unwrap_or(0);

    match run(&archive, &kind, &destination, max_items, max_bytes) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("snpanel-extract: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(
    archive: &Path,
    kind: &str,
    destination: &Path,
    max_items: usize,
    max_bytes: u64,
) -> Result<(), String> {
    let destination = std::fs::canonicalize(destination)
        .map_err(|e| format!("cannot resolve the destination: {e}"))?;
    // The archive may sit inside the directory it is being unpacked into, and
    // may even contain an entry with its own name. It is skipped rather than
    // overwritten while it is still being read.
    let source =
        std::fs::canonicalize(archive).map_err(|e| format!("cannot resolve the archive: {e}"))?;

    let entries = match kind {
        "zip" => read_zip(archive)?,
        "tar.gz" => read_tar(archive)?,
        other => return Err(format!("unsupported archive type: {other}")),
    };

    let planned = validate(&entries, &destination, &source, max_items, max_bytes)?;
    write_out(&planned, archive, kind, &destination, &source)
}

/// One entry as the archive describes it, before anything is trusted.
struct Entry {
    name: String,
    is_dir: bool,
    /// Symlink, hard link, device, fifo or socket - anything that is not a
    /// plain file or a directory.
    is_special: bool,
    size: u64,
}

/// A validated entry, with the place it will actually be written.
#[derive(Debug)]
struct Planned {
    target: PathBuf,
    is_dir: bool,
    name: String,
}

fn read_zip(archive: &Path) -> Result<Vec<Entry>, String> {
    let file = std::fs::File::open(archive).map_err(|e| format!("opening the archive: {e}"))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("reading the archive: {e}"))?;

    // A directory can be implied by a deeper path rather than stored as its
    // own entry, which is why a zero-length entry whose name is a prefix of
    // another is a directory and not an empty file. Source: `zip_implied_dirs`.
    let mut implied: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut raw = Vec::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i).map_err(|e| format!("entry {i}: {e}"))?;
        let name = entry.name().to_string();
        let normalized = name.replace('\\', "/");
        let parts: Vec<&str> = normalized
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        for depth in 1..parts.len() {
            implied.insert(parts[..depth].join("/"));
        }
        let mode = entry.unix_mode().unwrap_or(0);
        raw.push((name, normalized, entry.is_dir(), entry.size(), mode));
    }

    Ok(raw
        .into_iter()
        .map(|(name, normalized, is_dir, size, mode)| {
            let trimmed = normalized.trim_end_matches('/').to_string();
            let dir = is_dir
                || normalized.ends_with('/')
                || (mode & 0o170000 == 0o040000 && size == 0)
                || (size == 0 && implied.contains(&trimmed));
            Entry {
                name,
                is_dir: dir,
                is_special: mode & 0o170000 == 0o120000,
                size,
            }
        })
        .collect())
}

fn read_tar(archive: &Path) -> Result<Vec<Entry>, String> {
    let file = std::fs::File::open(archive).map_err(|e| format!("opening the archive: {e}"))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut out = Vec::new();
    for entry in tar
        .entries()
        .map_err(|e| format!("reading the archive: {e}"))?
    {
        let entry = entry.map_err(|e| format!("reading an entry: {e}"))?;
        let kind = entry.header().entry_type();
        let name = entry
            .path()
            .map_err(|e| format!("an entry has an unreadable name: {e}"))?
            .to_string_lossy()
            .into_owned();
        out.push(Entry {
            name,
            is_dir: kind.is_dir(),
            is_special: !kind.is_dir() && !kind.is_file(),
            size: entry.header().size().unwrap_or(0),
        });
    }
    Ok(out)
}

/// Where an entry may be written, or why it may not.
///
/// Source: `safe_target`. A backslash is normalised first, because an archive
/// built on Windows uses them and `a\..\..\etc` is a traversal that a
/// slash-only check does not see.
fn safe_target(name: &str, destination: &Path) -> Result<PathBuf, String> {
    if name.contains('\0') {
        return Err("archive contains an unsafe path".to_string());
    }
    let normalized = name.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err("archive contains an absolute path".to_string());
    }
    // A drive letter in the first component, which is absolute on Windows and
    // meaningless here.
    if normalized
        .split('/')
        .next()
        .is_some_and(|first| first.contains(':'))
    {
        return Err("archive contains an absolute path".to_string());
    }
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.is_empty() || parts.contains(&"..") {
        return Err("archive contains an unsafe path".to_string());
    }

    let mut target = destination.to_path_buf();
    for part in &parts {
        target.push(part);
    }
    // Lexical check as well as the canonical one below: the canonical check
    // can only see a path whose parents exist, and the first entry of an
    // archive creates them.
    if !lexically_inside(&target, destination) {
        return Err("archive path escapes destination".to_string());
    }
    Ok(target)
}

fn lexically_inside(target: &Path, destination: &Path) -> bool {
    let mut cleaned = PathBuf::new();
    for component in target.components() {
        match component {
            Component::ParentDir => return false,
            Component::CurDir => {}
            other => cleaned.push(other),
        }
    }
    cleaned.starts_with(destination)
}

/// Everything is checked before anything is written.
fn validate(
    entries: &[Entry],
    destination: &Path,
    source: &Path,
    max_items: usize,
    max_bytes: u64,
) -> Result<Vec<Planned>, String> {
    let mut planned = Vec::new();
    let mut total: u64 = 0;
    for (index, entry) in entries.iter().enumerate() {
        if max_items != 0 && index + 1 > max_items {
            return Err("archive has too many files".to_string());
        }
        if entry.is_special {
            return Err("archive links and devices are not allowed".to_string());
        }
        let target = safe_target(&entry.name, destination)?;

        // An entry naming the archive itself is skipped, not written: it is
        // open for reading, and the bash restores it afterwards for the same
        // reason.
        if std::fs::canonicalize(&target).is_ok_and(|resolved| resolved == source) {
            continue;
        }

        if entry.is_dir {
            ensure_directory_target(&target)?;
        } else {
            ensure_regular_target(&target)?;
            total = total.saturating_add(entry.size);
            if max_bytes != 0 && total > max_bytes {
                return Err("archive is too large".to_string());
            }
        }
        planned.push(Planned {
            target,
            is_dir: entry.is_dir,
            name: entry.name.clone(),
        });
    }
    Ok(planned)
}

/// Source: `ensure_regular_target`.
fn ensure_regular_target(target: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(target) {
        Ok(m) if m.file_type().is_symlink() => Err("refusing to overwrite a symlink".to_string()),
        Ok(m) if m.is_dir() => Err("archive file conflicts with an existing directory".to_string()),
        _ => Ok(()),
    }
}

/// Source: `ensure_directory_target`. An existing empty file is allowed to be
/// replaced by a directory, which is what the bash does; anything else is a
/// conflict rather than something to overwrite.
fn ensure_directory_target(target: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(target) {
        Ok(m) if m.file_type().is_symlink() => Err("refusing to overwrite a symlink".to_string()),
        Ok(m) if !m.is_dir() => {
            if m.len() == 0 {
                Ok(())
            } else {
                Err("archive directory conflicts with an existing file".to_string())
            }
        }
        _ => Ok(()),
    }
}

fn write_out(
    planned: &[Planned],
    archive: &Path,
    kind: &str,
    destination: &Path,
    source: &Path,
) -> Result<(), String> {
    let wanted: std::collections::HashMap<&str, &Planned> =
        planned.iter().map(|p| (p.name.as_str(), p)).collect();

    for p in planned.iter().filter(|p| p.is_dir) {
        if std::fs::symlink_metadata(&p.target).is_ok_and(|m| !m.is_dir()) {
            let _ = std::fs::remove_file(&p.target);
        }
        std::fs::create_dir_all(&p.target)
            .map_err(|e| format!("creating {}: {e}", p.target.display()))?;
    }

    match kind {
        "zip" => {
            let file =
                std::fs::File::open(archive).map_err(|e| format!("opening the archive: {e}"))?;
            let mut zip =
                zip::ZipArchive::new(file).map_err(|e| format!("reading the archive: {e}"))?;
            for i in 0..zip.len() {
                let mut entry = zip.by_index(i).map_err(|e| format!("entry {i}: {e}"))?;
                let name = entry.name().to_string();
                let Some(p) = wanted.get(name.as_str()) else {
                    continue;
                };
                if p.is_dir {
                    continue;
                }
                write_file(&p.target, &mut entry)?;
            }
        }
        _ => {
            let file =
                std::fs::File::open(archive).map_err(|e| format!("opening the archive: {e}"))?;
            let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
            for entry in tar
                .entries()
                .map_err(|e| format!("reading the archive: {e}"))?
            {
                let mut entry = entry.map_err(|e| format!("reading an entry: {e}"))?;
                let name = entry
                    .path()
                    .map_err(|e| format!("an entry has an unreadable name: {e}"))?
                    .to_string_lossy()
                    .into_owned();
                let Some(p) = wanted.get(name.as_str()) else {
                    continue;
                };
                if p.is_dir {
                    continue;
                }
                write_file(&p.target, &mut entry)?;
            }
        }
    }
    let _ = (destination, source);
    Ok(())
}

fn write_file(target: &Path, source: &mut impl Read) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let mut out =
        std::fs::File::create(target).map_err(|e| format!("creating {}: {e}", target.display()))?;
    std::io::copy(source, &mut out).map_err(|e| format!("writing {}: {e}", target.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest() -> PathBuf {
        PathBuf::from("/home/bp_site/example.com/public_html")
    }

    /// The zip-slip defence, tested by what it refuses.
    #[test]
    fn an_entry_cannot_name_somewhere_outside_the_destination() {
        let d = dest();
        for good in [
            "index.html",
            "assets/app.js",
            "./assets/app.css",
            "a/b/c/d.txt",
        ] {
            assert!(safe_target(good, &d).is_ok(), "{good:?} is ordinary");
        }

        for (bad, why) in [
            ("/etc/passwd", "absolute"),
            ("../escape.html", "traversal"),
            ("a/../../escape", "traversal in the middle"),
            ("a/..", "traversal at the end"),
            (
                "C:/windows/system32",
                "a drive letter is absolute on Windows",
            ),
            (
                "..\\..\\escape",
                "backslash traversal, which a slash-only check misses",
            ),
            ("", "empty"),
            (".", "names the destination itself"),
        ] {
            assert!(
                safe_target(bad, &d).is_err(),
                "{bad:?} must be refused ({why})"
            );
        }
    }

    /// A backslash is normalised before the path is judged.
    ///
    /// An archive built on Windows uses them, and `a\..\..\etc` is a
    /// traversal that a check looking only at `/` would let through.
    #[test]
    fn backslashes_are_normalised_first() {
        let d = dest();
        let target = safe_target("assets\\app.js", &d).expect("a Windows-built path");
        assert_eq!(target, d.join("assets").join("app.js"));
    }

    /// Nothing is written when a limit is exceeded, because validation
    /// happens before any file is created.
    #[test]
    fn the_limits_are_decided_before_anything_is_written() {
        let d = dest();
        let entries = vec![
            Entry {
                name: "a.txt".into(),
                is_dir: false,
                is_special: false,
                size: 10,
            },
            Entry {
                name: "b.txt".into(),
                is_dir: false,
                is_special: false,
                size: 10,
            },
            Entry {
                name: "c.txt".into(),
                is_dir: false,
                is_special: false,
                size: 10,
            },
        ];
        let source = PathBuf::from("/tmp/nowhere.tar.gz");

        let err = validate(&entries, &d, &source, 2, 0).unwrap_err();
        assert!(err.contains("too many files"), "{err}");

        let err = validate(&entries, &d, &source, 0, 25).unwrap_err();
        assert!(err.contains("too large"), "{err}");

        // Within both limits, all three are planned.
        let planned = validate(&entries, &d, &source, 10, 1000).expect("within limits");
        assert_eq!(planned.len(), 3);
    }

    /// A limit of zero means no limit, as the bash has it.
    #[test]
    fn zero_means_unlimited() {
        let d = dest();
        let entries = vec![Entry {
            name: "big.bin".into(),
            is_dir: false,
            is_special: false,
            size: u64::MAX / 2,
        }];
        let source = PathBuf::from("/tmp/nowhere.tar.gz");
        assert!(validate(&entries, &d, &source, 0, 0).is_ok());
    }

    /// Links and devices are refused outright rather than skipped.
    ///
    /// Skipping would be quieter and worse: the customer would get an
    /// incomplete extraction and no reason for it.
    #[test]
    fn links_and_devices_are_refused_not_skipped() {
        let d = dest();
        let entries = vec![Entry {
            name: "shadow".into(),
            is_dir: false,
            is_special: true,
            size: 0,
        }];
        let source = PathBuf::from("/tmp/nowhere.tar.gz");
        let err = validate(&entries, &d, &source, 0, 0).unwrap_err();
        assert!(err.contains("links and devices"), "{err}");
    }
}
