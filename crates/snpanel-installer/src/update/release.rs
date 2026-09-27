//! Working out what to download, and checking what arrived.
//!
//! Source: `release_archive_url`, `download_release_source`,
//! `current_panel_version`.

/// The tag shape `latest_release_tag` asks the remote for.
///
/// A glob, passed to `git ls-remote` as a ref pattern — so the filtering
/// happens on the server and a repository with a thousand tags does not send
/// them all. Note what it matches beyond releases: `v2.0.0-rc1` has the same
/// shape, and [`super::version_sort`] then sorts it *after* `v2.0.0`.
pub const PATTERN: &str = "v[0-9]*.[0-9]*.[0-9]*";

/// Where the release archive comes from.
///
/// An explicit `RELEASE_ZIP_URL` wins, with `{tag}` substituted — that is the
/// escape hatch for a mirror or a repository host this does not know. Failing
/// that, the two GitHub spellings are recognised and anything else is
/// refused **with the two ways out named**: a repository host nobody
/// anticipated is a support question, and a message that only says "cannot
/// derive" turns it into one.
pub fn archive_url(
    repo_url: &str,
    tag: &str,
    zip_url_template: Option<&str>,
) -> Result<String, String> {
    if let Some(template) = zip_url_template.filter(|t| !t.is_empty()) {
        return Ok(template.replace("{tag}", tag));
    }
    let base = if let Some(rest) = repo_url.strip_prefix("https://github.com/") {
        format!("https://github.com/{}", strip_git_suffix(rest))
    } else if let Some(rest) = repo_url.strip_prefix("git@github.com:") {
        format!("https://github.com/{}", strip_git_suffix(rest))
    } else {
        return Err(
            "Cannot derive release zip URL from REPO_URL. Set RELEASE_ZIP_URL or use --branch."
                .to_string(),
        );
    };
    Ok(format!("{base}/archive/refs/tags/{tag}.zip"))
}

/// `${repo%.git}` — one trailing `.git`, and only at the end.
fn strip_git_suffix(path: &str) -> &str {
    path.strip_suffix(".git").unwrap_or(path)
}

/// What an unpacked release has to contain before it is used.
///
/// A GitHub archive unpacks into a single directory named for the tag, so
/// the extraction directory has exactly one child. The two subdirectories
/// are checked because the failure this guards against is not a corrupt zip
/// — it is a **404 page saved as `snpanel-release.zip`**, which unzips to
/// nothing useful and would otherwise be noticed as a mysteriously empty
/// deployment.
pub fn unpacked_source_ok(
    children: &[&str],
    has_backend: bool,
    has_frontend: bool,
) -> Result<(), String> {
    const MESSAGE: &str = "Release archive does not contain backend/frontend source";
    if children.is_empty() || !has_backend || !has_frontend {
        return Err(MESSAGE.to_string());
    }
    Ok(())
}

/// Where the download is staged.
///
/// Under `/tmp` with a random suffix, and removed by the script's exit trap
/// whatever happens — including on the failure paths, which is the point: an
/// update that dies halfway must not leave a 30 MB archive behind on every
/// attempt.
pub const WORK_DIR_TEMPLATE: &str = "/tmp/snpanel-release-update.XXXXXX";

/// The version the box is on now.
///
/// `VERSION` first, because that is the file the installer writes and the
/// one an update refreshes. The Python constant is the fallback for a box
/// installed before that file existed — and it is a fallback rather than the
/// primary source because it will stop existing when the Python does.
pub fn current_version(version_file: Option<&str>, version_py: Option<&str>) -> Option<String> {
    if let Some(raw) = version_file {
        let trimmed: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
        // An empty `VERSION` falls through rather than answering with "",
        // which would be reported to the operator as the version they are
        // on.
    }
    let py = version_py?;
    for line in py.lines() {
        let Some(rest) = line.strip_prefix("APP_VERSION = \"") else {
            continue;
        };
        let Some(value) = rest.split('"').next() else {
            continue;
        };
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// The `latest` field of the update-state file.
///
/// `${ref#v}`, but blank when the ref did not begin with `v` — so a branch
/// name never appears in a field that means "the version available". A box
/// following `main` reports no latest version rather than a latest version
/// called `main`.
pub fn latest_field(reference: &str) -> String {
    match reference.strip_prefix('v') {
        Some(rest) => rest.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "https://github.com/vnscorpion/snpanel.git";

    #[test]
    fn a_github_url_becomes_an_archive_url() {
        assert_eq!(
            archive_url(REPO, "v1.2.3", None).unwrap(),
            "https://github.com/vnscorpion/snpanel/archive/refs/tags/v1.2.3.zip"
        );
        // Without the `.git`, which is how the URL is often written.
        assert_eq!(
            archive_url("https://github.com/vnscorpion/snpanel", "v1.2.3", None).unwrap(),
            "https://github.com/vnscorpion/snpanel/archive/refs/tags/v1.2.3.zip"
        );
    }

    /// An operator who cloned over SSH has an `scp`-style remote, and the
    /// archive still has to be fetchable over HTTPS.
    #[test]
    fn an_ssh_remote_still_yields_an_https_archive() {
        assert_eq!(
            archive_url("git@github.com:vnscorpion/snpanel.git", "v1.2.3", None).unwrap(),
            "https://github.com/vnscorpion/snpanel/archive/refs/tags/v1.2.3.zip"
        );
    }

    /// Only a trailing `.git` is removed, and only one. A repository whose
    /// name contains the word elsewhere keeps it.
    #[test]
    fn only_a_trailing_git_suffix_is_removed() {
        assert_eq!(
            archive_url("https://github.com/a/git-things.git", "v1", None).unwrap(),
            "https://github.com/a/git-things/archive/refs/tags/v1.zip"
        );
        assert_eq!(
            archive_url("https://github.com/a/b.github.git", "v1", None).unwrap(),
            "https://github.com/a/b.github/archive/refs/tags/v1.zip"
        );
    }

    /// The escape hatch, for a mirror or a host this does not know — and it
    /// wins over the derivation, so setting it is enough.
    #[test]
    fn an_explicit_template_wins_and_substitutes_the_tag() {
        assert_eq!(
            archive_url(REPO, "v1.2.3", Some("https://mirror.example/{tag}/src.zip")).unwrap(),
            "https://mirror.example/v1.2.3/src.zip"
        );
        // More than once, if the template names it twice.
        assert_eq!(
            archive_url(REPO, "v1.2.3", Some("https://m/{tag}/snpanel-{tag}.zip")).unwrap(),
            "https://m/v1.2.3/snpanel-v1.2.3.zip"
        );
        // An empty template is not a template.
        assert!(archive_url(REPO, "v1.2.3", Some(""))
            .unwrap()
            .contains("github.com"));
    }

    /// A repository host nobody anticipated is a support question, and a
    /// message that only says "cannot derive" turns it into one. Both ways
    /// out are named.
    #[test]
    fn an_unknown_host_is_refused_with_the_two_ways_out() {
        let error = archive_url("https://gitlab.example/a/b.git", "v1.2.3", None).unwrap_err();
        assert!(error.contains("RELEASE_ZIP_URL"), "{error}");
        assert!(error.contains("--branch"), "{error}");
        // And a URL that merely mentions github is not a github URL.
        assert!(archive_url("https://example.com/github.com/a/b", "v1", None).is_err());
    }

    /// The failure this guards against is not a corrupt zip — it is a 404
    /// page saved as `snpanel-release.zip`, which unzips to nothing useful.
    #[test]
    fn an_archive_without_the_source_is_refused() {
        assert!(unpacked_source_ok(&["snpanel-1.2.3"], true, true).is_ok());
        for (children, backend, frontend) in [
            (&[][..], true, true),
            (&["snpanel-1.2.3"][..], false, true),
            (&["snpanel-1.2.3"][..], true, false),
            (&["snpanel-1.2.3"][..], false, false),
        ] {
            let error = unpacked_source_ok(children, backend, frontend).unwrap_err();
            assert_eq!(
                error,
                "Release archive does not contain backend/frontend source"
            );
        }
    }

    #[test]
    fn the_version_comes_from_the_file_the_installer_writes() {
        assert_eq!(
            current_version(Some("1.2.3\n"), None).as_deref(),
            Some("1.2.3")
        );
        // Whitespace anywhere is stripped, as `tr -d '[:space:]'` does.
        assert_eq!(
            current_version(Some(" 1.2.3 \r\n"), None).as_deref(),
            Some("1.2.3")
        );
    }

    /// The fallback is for a box installed before `VERSION` existed, and it
    /// is a fallback rather than the primary source because it stops
    /// existing when the Python does.
    #[test]
    fn a_box_with_no_version_file_falls_back_to_the_python_constant() {
        let py = "\"\"\"Version.\"\"\"\nAPP_VERSION = \"1.1.0\"\nOTHER = 1\n";
        assert_eq!(current_version(None, Some(py)).as_deref(), Some("1.1.0"));
        // The file wins when both are there.
        assert_eq!(
            current_version(Some("1.2.3\n"), Some(py)).as_deref(),
            Some("1.2.3")
        );
    }

    /// An empty `VERSION` must not be reported to the operator as the
    /// version they are on.
    #[test]
    fn an_empty_version_file_is_not_a_version() {
        let py = "APP_VERSION = \"1.1.0\"\n";
        assert_eq!(
            current_version(Some("\n"), Some(py)).as_deref(),
            Some("1.1.0")
        );
        assert_eq!(current_version(Some(""), None), None);
        assert_eq!(current_version(None, None), None);
        assert_eq!(current_version(None, Some("nothing here\n")), None);
    }

    /// A box following `main` reports no latest version, rather than a
    /// latest version called `main`.
    #[test]
    fn only_a_version_tag_becomes_a_latest_version() {
        assert_eq!(latest_field("v1.2.3"), "1.2.3");
        assert_eq!(latest_field("main"), "");
        assert_eq!(latest_field("release/2026-09"), "");
        assert_eq!(latest_field(""), "");
    }

    /// The pattern filters on the server, so a repository with a thousand
    /// tags does not send them all — and it matches more than releases,
    /// which is where the release-candidate ordering matters.
    #[test]
    fn the_pattern_is_a_glob_that_also_matches_a_candidate() {
        assert_eq!(PATTERN, "v[0-9]*.[0-9]*.[0-9]*");
        // A glob, not a regex: `*` is any run of characters, so the shape
        // `v2.0.0-rc1` matches it too.
        assert!(PATTERN.starts_with("v["));
    }
}
