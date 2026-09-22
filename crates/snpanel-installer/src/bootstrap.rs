//! Getting the Rust binaries onto the machine, and the sudoers rule that
//! lets the panel reach them.
//!
//! Source: `resolve_release_tag`, `fetch_rust_binaries` and the `requiretty`
//! half of `install_privileged_helper`.
//!
//! This is the part of the installer that runs a program fetched over the
//! network as root, so the rule it is built on is worth stating plainly:
//! **a release with no checksums, or with checksums that do not match, stops
//! the install.** A release with no binaries at all does not — that is an
//! older tag, and the bash helper still produces a working panel. The
//! difference between "degrade" and "abort" is the whole security property
//! here, and it is what [`Outcome`] exists to make explicit.

use std::path::{Path, PathBuf};

/// `^v[0-9]+\.[0-9]+\.[0-9]+$`.
///
/// Anything else is refused rather than passed to a URL. The tag is
/// interpolated into `releases/download/<tag>/...`, so a value carrying a
/// slash or a `..` would fetch from somewhere other than the release.
pub fn valid_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// Source: `resolve_release_tag`.
///
/// The environment wins, then the `VERSION` file in the tree, and a value
/// that is not a release tag is no tag at all rather than a tag to try.
pub fn resolve_release_tag(
    env_version: Option<&str>,
    version_file: Option<&str>,
) -> Option<String> {
    let candidate = match env_version.filter(|text| !text.is_empty()) {
        Some(tag) => tag.to_string(),
        None => {
            let raw = version_file?;
            // `tr -d '[:space:]'` — every space anywhere, not just the ends.
            let digits: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
            format!("v{digits}")
        }
    };
    valid_release_tag(&candidate).then_some(candidate)
}

/// The four binaries a release archive has to carry.
pub const REQUIRED_BINARIES: &[&str] = &[
    "snpanel-helper",
    "snpanel-extract",
    "snpanel-api",
    "snpanel",
];

/// What the installer should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Install these binaries.
    Install(PathBuf),
    /// Carry on without them: the bash helper still produces a working
    /// panel. The message is logged, not shown as an error.
    Degrade(String),
    /// Stop. Something about this release is wrong in a way that must not be
    /// installed as root.
    Abort(String),
}

/// What was found, so the decision can be tested without a network.
#[derive(Debug, Clone, Default)]
pub struct Fetched {
    /// A tree that has already been built, if there is one.
    pub locally_built: Option<PathBuf>,
    pub tag: Option<String>,
    /// The archive, once downloaded.
    pub archive: Option<PathBuf>,
    /// `SHA256SUMS`. `None` means the download failed or it was not
    /// published.
    pub sums: Option<PathBuf>,
    /// Whether every file named in `SHA256SUMS` that is present matched.
    pub checksums_ok: bool,
    /// Where the archive unpacked to, if it did.
    pub unpacked: Option<PathBuf>,
    /// Which of [`REQUIRED_BINARIES`] were not found, or not executable.
    pub missing: Vec<String>,
}

/// Source: the sequence of guards in `fetch_rust_binaries`.
///
/// A tree that has been built wins over the release: somebody running this
/// from a checkout is testing what they built, and downloading a release over
/// it would make the install say nothing about their work.
pub fn decide(found: &Fetched) -> Outcome {
    if let Some(built) = &found.locally_built {
        return Outcome::Install(built.clone());
    }
    let Some(tag) = &found.tag else {
        return Outcome::Degrade(
            "No release tag to fetch Rust binaries for; the bash helper will be installed"
                .to_string(),
        );
    };
    if found.archive.is_none() {
        return Outcome::Degrade(format!(
            "No Rust binaries published for {tag}; the bash helper will be installed"
        ));
    }
    // From here on every failure aborts. The archive exists, so this is a
    // release that means to ship binaries — and one that ships them without
    // checksums, or with the wrong ones, is not one to run as root.
    if found.sums.is_none() {
        return Outcome::Abort(format!(
            "Rust binaries for {tag} have no SHA256SUMS; refusing to install them"
        ));
    }
    if !found.checksums_ok {
        return Outcome::Abort(format!(
            "The Rust binaries for {tag} do not match their published checksums"
        ));
    }
    let Some(unpacked) = &found.unpacked else {
        return Outcome::Abort(format!("Could not unpack the Rust binaries for {tag}"));
    };
    if !found.missing.is_empty() {
        return Outcome::Abort(format!(
            "The Rust archive for {tag} is missing: {}",
            found.missing.join(" ")
        ));
    }
    Outcome::Install(unpacked.clone())
}

/// One line of a `SHA256SUMS` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumLine {
    pub digest: String,
    pub name: String,
}

/// Parse `SHA256SUMS` the way `sha256sum --check` reads it.
///
/// `<64 hex>  <name>` — two spaces for a text-mode entry, ` *` for binary.
/// A line that is neither is skipped rather than failing the file, which is
/// what `sha256sum` does with a blank line or a comment.
pub fn parse_sums(text: &str) -> Vec<SumLine> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((digest, rest)) = line.split_once(' ') else {
            continue;
        };
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        // The second character is a space (text) or a star (binary).
        let name = match rest.strip_prefix([' ', '*']) {
            Some(name) => name,
            None => continue,
        };
        if name.is_empty() {
            continue;
        }
        out.push(SumLine {
            digest: digest.to_ascii_lowercase(),
            name: name.to_string(),
        });
    }
    out
}

/// `sha256sum --check --ignore-missing`.
///
/// **`--ignore-missing` is not laxity.** The published `SHA256SUMS` covers
/// every asset of the release, and the installer downloads one of them; a
/// check that insisted on all of them would fail every time. What it must
/// still do is verify the file it *did* download — so a run where nothing
/// matched, because nothing was present, is a failure and not a pass.
pub fn check_sums(sums: &[SumLine], present: &dyn Fn(&str) -> Option<String>) -> bool {
    let mut checked = 0;
    for entry in sums {
        let Some(actual) = present(&entry.name) else {
            continue;
        };
        if !actual.eq_ignore_ascii_case(&entry.digest) {
            return false;
        }
        checked += 1;
    }
    // `sha256sum --check --ignore-missing` exits non-zero when every listed
    // file was missing, and so does this.
    checked > 0
}

/// Whether the four binaries are there and executable.
pub fn missing_binaries(dir: &Path, is_executable: &dyn Fn(&Path) -> bool) -> Vec<String> {
    REQUIRED_BINARIES
        .iter()
        .filter(|name| !is_executable(&dir.join(name)))
        .map(|name| (*name).to_string())
        .collect()
}

/// The one line dropped from the sudoers file on a sudo that does not know
/// the setting.
pub const REQUIRETTY_LINE: &str = "Defaults:snpanel !requiretty";

/// Source: the `sed -i '/^Defaults:snpanel[[:space:]]*!requiretty$/d'`.
///
/// `requiretty` was removed in sudo 1.9.17. Ubuntu 26.04's build rejects the
/// whole file over the negation, and a rejected sudoers file means the panel
/// has **no privileged path at all**; AlmaLinux 10 ships the same sudo
/// version and accepts it. The line exists because RHEL once enabled
/// `requiretty` globally and the helper runs with no TTY.
///
/// Which way to go is decided by asking `visudo`, not by branching on the
/// distribution — the caller does that and passes the answer here.
pub fn sudoers_for(contents: &str, sudo_understands_requiretty: bool) -> String {
    if sudo_understands_requiretty {
        return contents.to_string();
    }
    let mut out = String::with_capacity(contents.len());
    for line in contents.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        if is_requiretty_line(bare) {
            continue;
        }
        out.push_str(line);
    }
    out
}

/// `^Defaults:snpanel[[:space:]]*!requiretty$`.
fn is_requiretty_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("Defaults:snpanel") else {
        return false;
    };
    rest.trim_start_matches([' ', '\t']) == "!requiretty"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_release_tag_reaches_a_url() {
        for good in ["v1.0.0", "v0.0.0", "v10.20.30"] {
            assert!(valid_release_tag(good), "{good}");
        }
        for bad in [
            "1.0.0",
            "v1.0",
            "v1.0.0.0",
            "v1.0.0-rc1",
            "v1.0.x",
            "v../../etc",
            "v1.0.0/../other",
            "",
            "v",
        ] {
            assert!(!valid_release_tag(bad), "{bad} should be refused");
        }
    }

    #[test]
    fn the_tag_comes_from_the_environment_then_the_version_file() {
        assert_eq!(
            resolve_release_tag(Some("v2.0.0"), Some("1.0.0")).as_deref(),
            Some("v2.0.0")
        );
        assert_eq!(
            resolve_release_tag(None, Some("1.0.59\n")).as_deref(),
            Some("v1.0.59")
        );
        // `tr -d '[:space:]'` strips space anywhere, not only at the ends.
        assert_eq!(
            resolve_release_tag(None, Some(" 1. 0 .59 \n")).as_deref(),
            Some("v1.0.59")
        );
        // Neither source, or a source that is not a tag.
        assert_eq!(resolve_release_tag(None, None), None);
        assert_eq!(resolve_release_tag(Some(""), None), None);
        assert_eq!(resolve_release_tag(None, Some("main")), None);
    }

    fn found() -> Fetched {
        Fetched {
            tag: Some("v1.0.0".to_string()),
            archive: Some(PathBuf::from("/tmp/a.tar.gz")),
            sums: Some(PathBuf::from("/tmp/SHA256SUMS")),
            checksums_ok: true,
            unpacked: Some(PathBuf::from("/tmp/unpacked")),
            ..Fetched::default()
        }
    }

    #[test]
    fn a_built_tree_wins_over_the_release() {
        let mut f = found();
        f.locally_built = Some(PathBuf::from("/src/target/release"));
        // Even a release that would abort does not get looked at.
        f.checksums_ok = false;
        assert_eq!(
            decide(&f),
            Outcome::Install(PathBuf::from("/src/target/release"))
        );
    }

    /// The line between degrading and stopping, which is the security
    /// property this whole module exists for.
    #[test]
    fn a_release_without_binaries_degrades_and_one_with_bad_ones_stops() {
        // No tag, and no archive: both are ordinary. An install that cannot
        // reach the release must still produce a working panel.
        let mut f = found();
        f.tag = None;
        assert!(matches!(decide(&f), Outcome::Degrade(_)));

        let mut f = found();
        f.archive = None;
        assert!(matches!(decide(&f), Outcome::Degrade(_)));

        // But an archive that arrived without checksums, or with wrong ones,
        // is a root binary nobody vouched for.
        let mut f = found();
        f.sums = None;
        let Outcome::Abort(why) = decide(&f) else {
            panic!("a release with no SHA256SUMS must not be installed");
        };
        assert!(why.contains("refusing to install"));

        let mut f = found();
        f.checksums_ok = false;
        assert!(matches!(decide(&f), Outcome::Abort(_)));

        let mut f = found();
        f.unpacked = None;
        assert!(matches!(decide(&f), Outcome::Abort(_)));

        let mut f = found();
        f.missing = vec!["snpanel-api".to_string()];
        let Outcome::Abort(why) = decide(&f) else {
            panic!("an incomplete archive must not be installed");
        };
        assert!(why.contains("snpanel-api"));
    }

    #[test]
    fn a_complete_release_installs() {
        assert_eq!(
            decide(&found()),
            Outcome::Install(PathBuf::from("/tmp/unpacked"))
        );
    }

    #[test]
    fn the_sums_file_is_read_the_way_sha256sum_reads_it() {
        let text = format!(
            "{d}  text-mode.tar.gz\n\
             {d} *binary-mode.tar.gz\n\
             \n\
             # a comment\n\
             deadbeef  too-short\n\
             {d}  \n\
             {d}  with spaces in it.tar.gz\n",
            d = "a".repeat(64)
        );
        let parsed = parse_sums(&text);
        assert_eq!(
            parsed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            [
                "text-mode.tar.gz",
                "binary-mode.tar.gz",
                "with spaces in it.tar.gz"
            ]
        );
    }

    #[test]
    fn a_digest_that_does_not_match_fails_the_check() {
        let good = "a".repeat(64);
        let sums = vec![SumLine {
            digest: good.clone(),
            name: "x.tar.gz".to_string(),
        }];
        assert!(check_sums(&sums, &|_| Some(good.clone())));
        // Case does not matter; the digest does.
        assert!(check_sums(&sums, &|_| Some(good.to_uppercase())));
        assert!(!check_sums(&sums, &|_| Some("b".repeat(64))));
    }

    /// `--ignore-missing` lets the check pass over assets this install did
    /// not download. It must not let it pass when **nothing** was checked:
    /// that would turn a `SHA256SUMS` naming only other files into a
    /// verification that verified nothing.
    #[test]
    fn a_check_that_verified_nothing_is_not_a_pass() {
        let sums = vec![SumLine {
            digest: "a".repeat(64),
            name: "some-other-asset.tar.gz".to_string(),
        }];
        assert!(!check_sums(&sums, &|_| None));
    }

    #[test]
    fn every_required_binary_is_looked_for() {
        let dir = Path::new("/tmp/unpacked");
        assert!(missing_binaries(dir, &|_| true).is_empty());
        assert_eq!(missing_binaries(dir, &|_| false).len(), 4);
        let missing = missing_binaries(dir, &|path| {
            path.file_name().and_then(|n| n.to_str()) != Some("snpanel-extract")
        });
        assert_eq!(missing, ["snpanel-extract"]);
    }

    /// A sudoers file sudo will not parse is a panel with no privileged path
    /// at all — every action goes through `sudo -n snpanel-helper`.
    #[test]
    fn the_requiretty_line_goes_only_where_sudo_does_not_know_it() {
        let file = "# a comment\n\
                    Defaults:snpanel !requiretty\n\
                    Defaults:snpanel env_reset\n\
                    snpanel ALL=(root) NOPASSWD: /usr/local/sbin/snpanel-helper *\n";
        assert_eq!(sudoers_for(file, true), file);

        let stripped = sudoers_for(file, false);
        assert!(!stripped.contains("!requiretty"));
        // And nothing else moved: the grant is what the panel runs on.
        assert!(stripped.contains("Defaults:snpanel env_reset\n"));
        assert!(
            stripped.contains("snpanel ALL=(root) NOPASSWD: /usr/local/sbin/snpanel-helper *\n")
        );
        assert_eq!(stripped.lines().count(), file.lines().count() - 1);
    }

    /// Only that exact line. A `Defaults:snpanel !requiretty_something` or a
    /// different user's line is not this one.
    #[test]
    fn only_the_one_line_matches() {
        assert!(is_requiretty_line("Defaults:snpanel !requiretty"));
        assert!(is_requiretty_line("Defaults:snpanel\t!requiretty"));
        assert!(!is_requiretty_line("Defaults:snpanel requiretty"));
        assert!(!is_requiretty_line("Defaults:root !requiretty"));
        assert!(!is_requiretty_line("Defaults:snpanel !requiretty_extra"));
        assert!(!is_requiretty_line("# Defaults:snpanel !requiretty"));
    }

    /// The real file, with the line in it — so a sudoers rule that stopped
    /// carrying it (or started spelling it differently) is caught here rather
    /// than on an Ubuntu 26.04 box where sudo rejects the whole thing.
    #[test]
    fn the_shipped_sudoers_carries_the_line_this_strips() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../installer/files/snpanel-sudoers");
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the sudoers file {}: {e}", path.display()));
        assert!(
            contents.lines().any(is_requiretty_line),
            "the installed sudoers file no longer carries the line the strip targets"
        );
        let stripped = sudoers_for(&contents, false);
        assert!(!stripped.lines().any(is_requiretty_line));
        assert_eq!(stripped.lines().count(), contents.lines().count() - 1);
    }
}
