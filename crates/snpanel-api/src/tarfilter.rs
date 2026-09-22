//! `tarfile.data_filter`, which is the whole of the safety on a restore.
//!
//! Source: CPython's `tarfile._get_filtered_attrs(member, dest, for_data=True)`,
//! as `backup.restore_backup` calls it.
//!
//! The archive was written by this panel, but it is a file on disk that an
//! administrator can replace, so every member goes through here before it is
//! written into a customer's site. The filter does two jobs and a port that
//! only did the first would be unsafe in a quiet way: it **refuses** members
//! that escape the destination, and it **rewrites** the ones it keeps —
//! stripping a leading slash, dropping ownership, and clamping the mode.
//! Without the rewriting a backup could restore a setuid binary owned by
//! root into a directory the customer controls.
//!
//! The Python has a fallback branch for interpreters older than 3.12 that
//! lack the `filter` parameter. The panel's virtualenv is 3.13, so that
//! branch never runs and is not ported.

use std::path::{Component, Path, PathBuf};

/// Why a member may not be written.
///
/// Named after CPython's exception classes because the names are what the
/// corpus records and what an operator reading a log will search for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilterError {
    AbsolutePath,
    OutsideDestination,
    SpecialFile,
    AbsoluteLink,
    LinkOutsideDestination,
}

impl FilterError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AbsolutePath => "AbsolutePathError",
            Self::OutsideDestination => "OutsideDestinationError",
            Self::SpecialFile => "SpecialFileError",
            Self::AbsoluteLink => "AbsoluteLinkError",
            Self::LinkOutsideDestination => "LinkOutsideDestinationError",
        }
    }
}

/// What a tar member is, as far as the filter cares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemberKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
    /// A FIFO, a device node, or anything else.
    Special,
}

/// One member, before and after the filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    pub kind: MemberKind,
    /// `None` once the filter has decided the mode does not apply.
    pub mode: Option<u32>,
    pub linkname: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub uname: Option<String>,
    pub gname: Option<String>,
}

/// Source: `os.path.normpath` — **lexical** only, no filesystem.
///
/// Collapses repeated separators, drops `.`, and resolves `..` against the
/// component before it — but a leading `..` survives, because there is
/// nothing above it to cancel. That difference is the one the link check
/// below depends on.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    // `//foo` is implementation-defined in POSIX and `normpath` keeps the
    // two slashes; three or more collapse to one. Nothing here produces a
    // double slash that matters, but reproducing it costs one line.
    let leading = if path.starts_with("//") && !path.starts_with("///") {
        "//"
    } else if absolute {
        "/"
    } else {
        ""
    };

    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if let Some(last) = parts.last() {
                    if *last != ".." {
                        parts.pop();
                        continue;
                    }
                }
                if absolute {
                    // `/..` is `/`.
                    continue;
                }
                parts.push("..");
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    let out = format!("{leading}{joined}");
    if out.is_empty() {
        ".".to_string()
    } else {
        out
    }
}

/// Source: `os.path.realpath(path, strict=ALLOW_MISSING)`.
///
/// Walks the path one component at a time, expanding a symlink wherever it
/// finds one and letting a component that does not exist through rather
/// than failing. **`..` is applied after the symlink before it has been
/// resolved**, which is why this cannot be done lexically: `a/../b` is
/// `b` when `a` is a directory and something else entirely when `a` is a
/// link out of the tree, and that is exactly the case the filter is there
/// to catch.
pub fn realpath(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::from("/");
    // A bound on symlink expansion, as the kernel has: a loop of links
    // would otherwise hang the restore rather than failing it.
    let mut budget = 40usize;

    let mut pending: Vec<String> = Vec::new();
    let start = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    resolved = if path.is_absolute() { resolved } else { start };
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::CurDir => {}
            Component::ParentDir => pending.push("..".to_string()),
            Component::Normal(part) => pending.push(part.to_string_lossy().into_owned()),
        }
    }
    pending.reverse();

    while let Some(part) = pending.pop() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(&part);
        let Ok(meta) = std::fs::symlink_metadata(&candidate) else {
            // Missing: keep it and carry on, which is what ALLOW_MISSING
            // means. Everything after it is missing too.
            resolved = candidate;
            continue;
        };
        if !meta.file_type().is_symlink() || budget == 0 {
            resolved = candidate;
            continue;
        }
        budget -= 1;
        let Ok(target) = std::fs::read_link(&candidate) else {
            resolved = candidate;
            continue;
        };
        if target.is_absolute() {
            resolved = PathBuf::from("/");
        }
        // The link's own target is walked next, before the rest of the path.
        let mut expanded: Vec<String> = Vec::new();
        for component in target.components() {
            match component {
                Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
                Component::ParentDir => expanded.push("..".to_string()),
                Component::Normal(p) => expanded.push(p.to_string_lossy().into_owned()),
            }
        }
        expanded.reverse();
        pending.extend(expanded);
    }
    resolved
}

/// `os.path.commonpath([target, dest]) == dest`.
///
/// True when `target` **is** `dest` or sits under it. Both have already
/// been through `realpath`, so this is a component comparison and not a
/// string prefix one — `/srv/site2` must not count as inside `/srv/site`.
fn inside_destination(target: &Path, dest: &Path) -> bool {
    target == dest || target.starts_with(dest)
}

/// Source: `_get_filtered_attrs(member, dest_path, for_data=True)`.
///
/// Returns the member as it should be written, or the reason it may not be.
pub fn data_filter(member: &Member, dest: &Path) -> Result<Member, FilterError> {
    let dest = realpath(dest);
    let mut out = member.clone();

    // `name.lstrip('/')` — **every** leading slash, not one.
    let mut name = member.name.clone();
    if name.starts_with('/') {
        name = name.trim_start_matches('/').to_string();
        out.name = name.clone();
    }
    if name.starts_with('/') {
        // Unreachable after the strip on this platform; it is here because
        // the Python has it for `C:/foo` on Windows and leaving it out
        // would make the two read differently.
        return Err(FilterError::AbsolutePath);
    }

    let target_path = realpath(&dest.join(&name));
    if !inside_destination(&target_path, &dest) {
        return Err(FilterError::OutsideDestination);
    }

    // `mode & 0o755` — the high bits go first, so setuid, setgid and the
    // sticky bit never survive whatever else happens below.
    if let Some(mode) = member.mode {
        let mut mode = mode & 0o755;
        match member.kind {
            MemberKind::Regular | MemberKind::Hardlink => {
                if mode & 0o100 == 0 {
                    // Not executable by its owner, so not executable at
                    // all: a backup must not turn a data file into one.
                    mode &= !0o111;
                }
                // The owner can always read and write what was restored,
                // or the customer cannot fix their own site.
                mode |= 0o600;
                out.mode = Some(mode);
            }
            MemberKind::Directory | MemberKind::Symlink => out.mode = None,
            MemberKind::Special => return Err(FilterError::SpecialFile),
        }
    } else if member.kind == MemberKind::Special {
        return Err(FilterError::SpecialFile);
    }

    // Ownership is dropped entirely: everything lands as whoever is doing
    // the extraction, which is the site's user.
    out.uid = None;
    out.gid = None;
    out.uname = None;
    out.gname = None;

    if matches!(member.kind, MemberKind::Symlink | MemberKind::Hardlink) {
        if member.linkname.starts_with('/') {
            return Err(FilterError::AbsoluteLink);
        }
        // A link that resolves to the destination directory itself would
        // replace it, redirecting every member after this one.
        if target_path == dest {
            return Err(FilterError::OutsideDestination);
        }
        let normalized = normpath(&member.linkname);
        if normalized != member.linkname {
            out.linkname = normalized.clone();
        }
        let link_target = if member.kind == MemberKind::Symlink {
            // A symlink is created at `name`, so its target is relative to
            // the directory holding it — not to the destination root.
            let trimmed = name.trim_end_matches('/');
            let dir = Path::new(trimmed).parent().unwrap_or(Path::new(""));
            dest.join(dir).join(&normalized)
        } else {
            dest.join(&normalized)
        };
        if !inside_destination(&realpath(&link_target), &dest) {
            return Err(FilterError::LinkOutsideDestination);
        }
    }

    Ok(out)
}

/// Source: the `safe_filter` closure inside `restore_backup`.
///
/// Three rules on top of the standard filter, and each of them is about
/// this archive's own shape rather than about safety in general:
///
/// - **A hard link is refused outright.** They are uncommon inside a
///   backup and the standard filter would allow one pointing at a file
///   already in the tree; refusing is cheaper than reasoning about it.
/// - `database/` holds the SQL dump, which is restored separately and must
///   not land in the document root where nginx could serve it.
/// - When the archive carries a `site/` prefix — which the panel's own
///   archives do — everything outside it is skipped and the prefix is
///   stripped, so `site/index.php` is restored as `index.php`.
pub fn safe_filter(
    member: &Member,
    dest: &Path,
    has_site_prefix: bool,
) -> Result<Option<Member>, FilterError> {
    if member.kind == MemberKind::Hardlink {
        return Ok(None);
    }
    if member.name.starts_with("database/") {
        return Ok(None);
    }
    let mut member = member.clone();
    if has_site_prefix {
        if member.name == "site" {
            return Ok(None);
        }
        let Some(rest) = member.name.strip_prefix("site/") else {
            return Ok(None);
        };
        member.name = rest.to_string();
    }
    data_filter(&member, dest).map(Some)
}

/// Whether an archive's members carry the panel's `site/` prefix.
///
/// Source: `any(m.name == "site" or m.name.startswith("site/"))`. A
/// directory entry alone is enough, so an archive of an empty site still
/// restores to the right place.
pub fn has_site_prefix<'a>(names: impl IntoIterator<Item = &'a str>) -> bool {
    names
        .into_iter()
        .any(|name| name == "site" || name.starts_with("site/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/data_filter.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the filter corpus"))
            .expect("the corpus parses")
    }

    /// The tar type bytes, as `TarInfo.type` reports them.
    fn kind_of(type_str: &str) -> MemberKind {
        match type_str {
            "0" => MemberKind::Regular,
            "5" => MemberKind::Directory,
            "2" => MemberKind::Symlink,
            "1" => MemberKind::Hardlink,
            _ => MemberKind::Special,
        }
    }

    fn member_from(case: &Value) -> Member {
        Member {
            name: case["name"].as_str().unwrap_or("").to_string(),
            kind: kind_of(case["type"].as_str().unwrap_or("")),
            mode: case["mode"].as_u64().map(|m| m as u32),
            linkname: case["linkname"].as_str().unwrap_or("").to_string(),
            uid: Some(0),
            gid: Some(0),
            uname: Some("root".to_string()),
            gname: Some("root".to_string()),
        }
    }

    /// A destination that exists, so the walk has something real to resolve.
    fn destination(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tarfilter-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("site")).expect("the destination");
        dir.join("site")
    }

    /// Every member CPython was asked about, replayed.
    ///
    /// Both halves matter. The refusals keep a backup from writing outside
    /// the site; the **rewrites** keep it from writing a setuid binary
    /// owned by root inside it, and a port that reproduced only the first
    /// would pass a test suite that only looked for errors.
    #[test]
    fn a_member_is_filtered_the_way_python_filters_it() {
        let corpus = corpus();
        let cases = corpus["data_filter"].as_array().expect("the cases");
        assert_eq!(cases.len(), 39, "the corpus changed size");
        let dest = destination("data");

        let mut failures: Vec<String> = Vec::new();
        let mut kept = 0usize;
        let mut refusals = std::collections::BTreeSet::new();
        for case in cases {
            let member = member_from(case);
            let label = format!(
                "{:?} {} {:o}",
                member.name,
                case["type"].as_str().unwrap_or(""),
                member.mode.unwrap_or(0)
            );
            let got = data_filter(&member, &dest);
            match (case.get("kept"), case.get("error")) {
                (Some(want), None) => {
                    kept += 1;
                    match got {
                        Ok(ref out) => {
                            if out.name != want["name"].as_str().unwrap_or("")
                                || out.mode.map(u64::from) != want["mode"].as_u64()
                                || out.linkname != want["linkname"].as_str().unwrap_or("")
                                || out.uid.is_some()
                                || out.gid.is_some()
                                || out.uname.is_some()
                                || out.gname.is_some()
                            {
                                failures
                                    .push(format!("{label}\n  python {want}\n  rust   {out:?}"));
                            }
                        }
                        Err(e) => failures.push(format!("{label}: python kept it, rust {e:?}")),
                    }
                }
                (None, Some(error)) => {
                    let want = error.as_str().unwrap_or("");
                    refusals.insert(want.to_string());
                    match got {
                        Err(e) if e.as_str() == want => {}
                        other => failures.push(format!("{label}: python {want}, rust {other:?}")),
                    }
                }
                _ => failures.push(format!("{label}: the corpus says neither")),
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
        assert!(kept >= 20, "only {kept} members were kept");
        // Every refusal the filter can produce on this platform.
        assert!(refusals.contains("OutsideDestinationError"), "{refusals:?}");
        assert!(refusals.contains("SpecialFileError"), "{refusals:?}");
        assert!(refusals.contains("AbsoluteLinkError"), "{refusals:?}");
        assert!(
            refusals.contains("LinkOutsideDestinationError"),
            "{refusals:?}"
        );

        let _ = std::fs::remove_dir_all(dest.parent().unwrap_or(&dest));
    }

    /// The mode arithmetic, stated on its own.
    ///
    /// These are the numbers a reader has to hold in their head to see that
    /// the filter is doing anything: the high bits go first, then the
    /// executable bits go unless the owner already had one, then the owner
    /// gets read and write back.
    #[test]
    fn the_mode_is_clamped_the_way_python_clamps_it() {
        let dest = destination("mode");
        let filtered = |mode: u32, kind: MemberKind| -> Option<u32> {
            data_filter(
                &Member {
                    name: "a.txt".to_string(),
                    kind,
                    mode: Some(mode),
                    linkname: String::new(),
                    uid: Some(0),
                    gid: Some(0),
                    uname: None,
                    gname: None,
                },
                &dest,
            )
            .expect("kept")
            .mode
        };

        // setuid, setgid and sticky never survive.
        assert_eq!(filtered(0o4755, MemberKind::Regular), Some(0o755));
        assert_eq!(filtered(0o2755, MemberKind::Regular), Some(0o755));
        assert_eq!(filtered(0o1777, MemberKind::Regular), Some(0o755));
        // Group and other write go with them.
        assert_eq!(filtered(0o777, MemberKind::Regular), Some(0o755));
        assert_eq!(filtered(0o666, MemberKind::Regular), Some(0o644));
        // Not executable by the owner: not executable at all.
        assert_eq!(filtered(0o711, MemberKind::Regular), Some(0o711));
        assert_eq!(filtered(0o611, MemberKind::Regular), Some(0o600));
        assert_eq!(filtered(0o444, MemberKind::Regular), Some(0o644));
        // The owner always ends up able to read and write.
        assert_eq!(filtered(0o000, MemberKind::Regular), Some(0o600));
        assert_eq!(filtered(0o004, MemberKind::Regular), Some(0o604));
        // Directories and symlinks carry no mode at all.
        assert_eq!(filtered(0o777, MemberKind::Directory), None);
        assert_eq!(filtered(0o777, MemberKind::Symlink), None);

        let _ = std::fs::remove_dir_all(dest.parent().unwrap_or(&dest));
    }

    /// The wrapper the restore puts around it, both ways round.
    #[test]
    fn the_restore_wrapper_strips_and_skips_the_way_python_does() {
        let corpus = corpus();
        let cases = corpus["safe_filter"].as_array().expect("the cases");
        assert_eq!(cases.len(), 78, "the corpus changed size");
        let dest = destination("wrapper");

        let mut failures: Vec<String> = Vec::new();
        let mut skipped = 0usize;
        for case in cases {
            let member = member_from(case);
            let prefixed = case["has_site_prefix"].as_bool().unwrap_or(false);
            let label = format!("{:?} prefix={prefixed}", member.name);
            let got = safe_filter(&member, &dest, prefixed);
            match (case.get("kept"), case.get("error")) {
                (Some(Value::Null), None) => {
                    skipped += 1;
                    if !matches!(got, Ok(None)) {
                        failures.push(format!("{label}: python skipped it, rust {got:?}"));
                    }
                }
                (Some(want), None) => match got {
                    Ok(Some(ref out)) => {
                        if out.name != want["name"].as_str().unwrap_or("")
                            || out.mode.map(u64::from) != want["mode"].as_u64()
                            || out.linkname != want["linkname"].as_str().unwrap_or("")
                        {
                            failures.push(format!("{label}\n  python {want}\n  rust   {out:?}"));
                        }
                    }
                    other => failures.push(format!("{label}: python kept it, rust {other:?}")),
                },
                (None, Some(error)) | (Some(Value::Null), Some(error)) => {
                    let want = error.as_str().unwrap_or("");
                    match got {
                        Err(e) if e.as_str() == want => {}
                        other => failures.push(format!("{label}: python {want}, rust {other:?}")),
                    }
                }
                _ => failures.push(format!("{label}: the corpus says neither")),
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
        assert!(skipped >= 20, "only {skipped} members were skipped");

        // The three rules, stated.
        let hard = Member {
            name: "h".to_string(),
            kind: MemberKind::Hardlink,
            mode: Some(0o644),
            linkname: "a.txt".to_string(),
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        };
        assert!(matches!(safe_filter(&hard, &dest, false), Ok(None)));
        let dump = Member {
            name: "database/x.sql".to_string(),
            ..hard.clone()
        };
        let dump = Member {
            kind: MemberKind::Regular,
            ..dump
        };
        assert!(matches!(safe_filter(&dump, &dest, false), Ok(None)));
        let inside = Member {
            name: "site/index.php".to_string(),
            kind: MemberKind::Regular,
            ..hard.clone()
        };
        assert_eq!(
            safe_filter(&inside, &dest, true)
                .expect("kept")
                .map(|m| m.name),
            Some("index.php".to_string()),
            "the prefix is stripped"
        );
        // And with no prefix in the archive the same name is left alone.
        assert_eq!(
            safe_filter(&inside, &dest, false)
                .expect("kept")
                .map(|m| m.name),
            Some("site/index.php".to_string())
        );

        let _ = std::fs::remove_dir_all(dest.parent().unwrap_or(&dest));
    }

    /// `..` is resolved **after** the symlink before it.
    ///
    /// This is why the containment check cannot be lexical. A member called
    /// `link/../x` where `link` points out of the site resolves outside it,
    /// and a port that normalised the string first would see `x` and allow
    /// the write.
    #[test]
    fn a_parent_step_is_taken_after_the_link_before_it() {
        let dest = destination("realpath");
        let outside = dest.parent().expect("a parent").join("outside");
        std::fs::create_dir_all(&outside).expect("the outside directory");
        std::os::unix::fs::symlink(&outside, dest.join("link")).expect("the link");
        std::fs::create_dir_all(dest.join("real")).expect("a real directory");

        // Through a real directory, `..` cancels it.
        assert_eq!(realpath(&dest.join("real/../x")), realpath(&dest).join("x"));
        // Through a symlink, it does not: the link is followed first.
        assert_eq!(
            realpath(&dest.join("link/../x")),
            realpath(&outside).parent().expect("a parent").join("x")
        );
        // Which the filter turns into a refusal.
        let member = Member {
            name: "link/../escape.txt".to_string(),
            kind: MemberKind::Regular,
            mode: Some(0o644),
            linkname: String::new(),
            uid: None,
            gid: None,
            uname: None,
            gname: None,
        };
        assert_eq!(
            data_filter(&member, &dest),
            Err(FilterError::OutsideDestination)
        );

        let _ = std::fs::remove_dir_all(dest.parent().unwrap_or(&dest));
    }

    /// `normpath` is lexical, and a leading `..` survives it.
    #[test]
    fn normpath_is_lexical_and_keeps_a_leading_parent() {
        assert_eq!(normpath("a/b"), "a/b");
        assert_eq!(normpath("a//b"), "a/b");
        assert_eq!(normpath("a/./b"), "a/b");
        assert_eq!(normpath("a/../b"), "b");
        assert_eq!(normpath("a/b/.."), "a");
        assert_eq!(normpath(".."), "..");
        assert_eq!(normpath("../.."), "../..");
        assert_eq!(normpath("../a"), "../a");
        assert_eq!(normpath("a/../../b"), "../b");
        assert_eq!(normpath(""), ".");
        assert_eq!(normpath("."), ".");
        assert_eq!(normpath("/"), "/");
        assert_eq!(normpath("/.."), "/");
        assert_eq!(normpath("/a/../b"), "/b");
    }

    /// A sibling whose name starts with the destination's is not inside it.
    #[test]
    fn a_sibling_with_a_longer_name_is_not_inside() {
        let base = std::env::temp_dir().join(format!("tarfilter-sib-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("site")).expect("the destination");
        std::fs::create_dir_all(base.join("site2")).expect("the sibling");
        let dest = base.join("site");

        assert!(inside_destination(&dest, &dest), "itself counts");
        assert!(inside_destination(&dest.join("a"), &dest));
        assert!(
            !inside_destination(&base.join("site2"), &dest),
            "a string prefix is not containment"
        );
        assert!(!inside_destination(&base, &dest));

        let _ = std::fs::remove_dir_all(&base);
    }
}
