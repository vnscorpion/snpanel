//! Validating everything the operator can set.
//!
//! Source: `require_git_ref_name` and the argument checks beneath it.
//!
//! The update script runs as root and takes a repository URL, a remote name,
//! a branch and a tag — all of which end up as arguments to `git`. The check
//! that matters most is the dullest one: **nothing may begin with `-`.** A
//! value that does is not a ref at all, it is an option, and `git` will read
//! it as one. That is how a branch called `--upload-pack=...` becomes a
//! command.

/// What a value is being checked as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Branch,
    ReleaseTag,
}

impl Kind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Branch => "BRANCH",
            Self::ReleaseTag => "RELEASE_TAG",
        }
    }

    /// What `git check-ref-format` is asked about.
    ///
    /// A branch is checked with `--branch`, which also accepts the `@{-1}`
    /// shorthands; a tag is checked as the full `refs/tags/<name>` it will
    /// become. Checking a tag as a branch would let through a name that is
    /// legal as a branch and not as a tag.
    pub fn ref_format_argument(&self, value: &str) -> Vec<String> {
        match self {
            Self::Branch => vec!["--branch".to_string(), value.to_string()],
            Self::ReleaseTag => vec![format!("refs/tags/{value}")],
        }
    }
}

/// The checks that run before `git check-ref-format` is consulted.
///
/// `Ok(())` means the value is worth asking git about; `Err` is the message
/// the script fails with.
pub fn precheck(kind: Kind, value: &str) -> Result<(), String> {
    let label = kind.label();
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if value.starts_with('-') {
        return Err(format!("{label} must not start with '-'"));
    }
    Ok(())
}

/// The message when git rejects the name.
pub fn bad_ref_characters(kind: Kind, value: &str) -> String {
    format!("{} has invalid git ref characters: {value}", kind.label())
}

/// A remote name.
///
/// Stricter than a ref, and deliberately so: it is a short identifier the
/// operator types, there is no reason for it to contain anything else, and
/// `git remote` takes it in positions where a slash would change its
/// meaning.
pub fn remote_name_ok(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

pub fn remote_name_error(value: &str) -> String {
    if value.is_empty() {
        "GIT_REMOTE cannot be empty".to_string()
    } else if value.starts_with('-') {
        "GIT_REMOTE must not start with '-'".to_string()
    } else {
        format!("GIT_REMOTE must match [A-Za-z0-9._-]+ (got: {value})")
    }
}

/// Where an update comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// The latest published release.
    Release,
    /// A branch, followed.
    Branch,
    /// One pinned tag.
    Tag,
}

impl Channel {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "release" => Ok(Self::Release),
            "branch" => Ok(Self::Branch),
            "tag" => Ok(Self::Tag),
            other => Err(format!(
                "UPDATE_CHANNEL must be release|branch|tag (got: {other})"
            )),
        }
    }

    /// Which value this channel validates, if any.
    ///
    /// The release channel validates neither, and a `RELEASE_TAG` set
    /// alongside it is **ignored with a notice** rather than refused — the
    /// operator has usually just switched channels and left the old value
    /// behind, and failing the update over it would be unhelpful. The notice
    /// says how to pin it if that is what they meant.
    pub fn validates(&self) -> Option<Kind> {
        match self {
            Self::Release => None,
            Self::Branch => Some(Kind::Branch),
            Self::Tag => Some(Kind::ReleaseTag),
        }
    }
}

pub fn ignored_tag_notice(tag: &str) -> String {
    format!("INFO: ignoring RELEASE_TAG in release channel; use --tag to pin {tag}.")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check that matters most, and the dullest. A value beginning with
    /// `-` is not a ref, it is an option, and `git` reads it as one.
    #[test]
    fn nothing_that_git_would_read_as_an_option_gets_through() {
        for kind in [Kind::Branch, Kind::ReleaseTag] {
            for value in [
                "-",
                "--upload-pack=touch /tmp/x",
                "--exec=sh",
                "-b",
                "--help",
            ] {
                let error = precheck(kind, value).expect_err(value);
                assert!(error.contains("must not start with '-'"), "{error}");
            }
        }
        assert!(!remote_name_ok("--upload-pack=x"));
        assert!(remote_name_error("-x").contains("must not start with '-'"));
    }

    #[test]
    fn an_empty_value_is_refused_by_name() {
        assert_eq!(
            precheck(Kind::Branch, "").unwrap_err(),
            "BRANCH cannot be empty"
        );
        assert_eq!(
            precheck(Kind::ReleaseTag, "").unwrap_err(),
            "RELEASE_TAG cannot be empty"
        );
        assert_eq!(remote_name_error(""), "GIT_REMOTE cannot be empty");
        assert!(!remote_name_ok(""));
    }

    /// An ordinary name goes through to git, which is where the real ref
    /// grammar lives — this side does not reimplement it.
    #[test]
    fn ordinary_names_reach_git() {
        for value in ["main", "v1.2.3", "release/2026-09", "feature_x"] {
            assert!(precheck(Kind::Branch, value).is_ok(), "{value}");
        }
    }

    /// A tag is checked as the full `refs/tags/<name>` it becomes, not as a
    /// branch: checking it as a branch would let through a name that is
    /// legal as one and not as a tag.
    #[test]
    fn each_kind_is_checked_as_what_it_will_become() {
        assert_eq!(
            Kind::ReleaseTag.ref_format_argument("v1.2.3"),
            ["refs/tags/v1.2.3"]
        );
        assert_eq!(
            Kind::Branch.ref_format_argument("main"),
            ["--branch", "main"]
        );
    }

    /// A remote name is a short identifier the operator types, and `git
    /// remote` takes it in positions where a slash would change its
    /// meaning.
    #[test]
    fn a_remote_name_is_stricter_than_a_ref() {
        for good in ["origin", "up-stream", "a.b", "a_b", "origin2"] {
            assert!(remote_name_ok(good), "{good}");
        }
        for bad in ["a/b", "a b", "a:b", "a@b", "üp", "a\nb", "a;b"] {
            assert!(!remote_name_ok(bad), "{bad:?}");
            assert!(remote_name_error(bad).contains("must match"), "{bad:?}");
        }
        // And a slash *is* legal in a branch, which is why the two checks
        // are different rather than one shared one.
        assert!(precheck(Kind::Branch, "release/2026-09").is_ok());
    }

    #[test]
    fn the_three_channels_and_nothing_else() {
        assert_eq!(Channel::parse("release"), Ok(Channel::Release));
        assert_eq!(Channel::parse("branch"), Ok(Channel::Branch));
        assert_eq!(Channel::parse("tag"), Ok(Channel::Tag));
        for bad in ["", "Release", "stable", "main"] {
            assert_eq!(
                Channel::parse(bad).unwrap_err(),
                format!("UPDATE_CHANNEL must be release|branch|tag (got: {bad})")
            );
        }
    }

    /// Each channel validates the value it is going to use, and only that
    /// one — so a stale `BRANCH` left over from a previous setting does not
    /// fail a tag update.
    #[test]
    fn a_channel_validates_only_the_value_it_uses() {
        assert_eq!(Channel::Branch.validates(), Some(Kind::Branch));
        assert_eq!(Channel::Tag.validates(), Some(Kind::ReleaseTag));
        assert_eq!(Channel::Release.validates(), None);
    }

    /// The operator has usually just switched channels and left the old
    /// value behind. Failing the update over it would be unhelpful, so it is
    /// a notice that says how to pin it if that is what they meant.
    #[test]
    fn a_leftover_tag_on_the_release_channel_is_a_notice_and_not_a_failure() {
        let notice = ignored_tag_notice("v1.2.3");
        assert!(notice.starts_with("INFO: "));
        assert!(notice.contains("v1.2.3"));
        assert!(notice.contains("use --tag to pin"));
    }
}
