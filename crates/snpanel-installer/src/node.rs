//! Node.js, which the panel needs to build its frontend.
//!
//! Source: `install_nodejs`.
//!
//! Where it comes from is a per-platform fact and lives in
//! [`snpanel_osabi::Platform::node_from_nodesource`]; what is here is the
//! rest — the setup URL that follows from the major version, and the check
//! that whatever got installed is new enough to be worth having.
//!
//! That check is not ceremony. Three of the four supported platforms take
//! Node from the distribution, and a distribution that moved its `nodejs`
//! package back a release would otherwise be found much later, as a frontend
//! build failing on syntax inside a dependency rather than as a version that
//! is too old.

/// `NODE_MAJOR="${NODE_MAJOR:-22}"` — the major NodeSource is asked for.
pub const DEFAULT_MAJOR: u32 = 22;

/// The oldest major the panel's frontend build works on.
///
/// Stated separately from [`DEFAULT_MAJOR`] because the two answer different
/// questions: this one is the floor every platform has to clear, including
/// the three that take whatever their distribution ships.
pub const MINIMUM_MAJOR: u32 = 20;

/// Where Node comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// NodeSource's setup script, piped into `bash`.
    ///
    /// This is the one place in the installer that runs a script fetched
    /// from a third party, which is why it is a named variant rather than a
    /// URL passed around: a reader should be able to find every occurrence.
    NodeSource { setup_url: String },
    /// The distribution's own `nodejs`.
    ///
    /// `npm` is a separate package here, and a weak dependency on EL — so it
    /// is asked for by name, and only when the package manager has it. A
    /// distribution that bundles npm into nodejs would otherwise fail the
    /// whole transaction on a package that does not exist.
    Distro,
}

/// The setup script for one major version.
pub fn setup_url(major: u32) -> String {
    format!("https://deb.nodesource.com/setup_{major}.x")
}

pub fn source(from_nodesource: bool, major: u32) -> Source {
    if from_nodesource {
        Source::NodeSource {
            setup_url: setup_url(major),
        }
    } else {
        Source::Distro
    }
}

/// The major version out of `node --version` or `process.versions.node`.
///
/// Both spellings are accepted: the first prints `v22.11.0` and the second
/// `22.11.0`, and which one a caller holds depends on whether it asked the
/// binary or ran a script inside it.
pub fn parse_major(raw: &str) -> Option<u32> {
    let raw = raw.trim();
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let digits: String = raw.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// What the shell's inline Node script says about the version it was given.
///
/// `Ok` carries the line the shell prints on success and `Err` the message
/// it throws with; both keep the `v`-prefixed spelling of `process.version`,
/// because that is what an operator has seen in the log of every install so
/// far.
pub fn check(version: &str) -> Result<String, String> {
    let printable = if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    };
    match parse_major(version) {
        Some(major) if major >= MINIMUM_MAJOR => Ok(format!("Using Node.js {printable}")),
        _ => Err(format!(
            "Node.js {MINIMUM_MAJOR}+ is required, current: {printable}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setup_url_carries_the_major_it_was_asked_for() {
        assert_eq!(
            setup_url(DEFAULT_MAJOR),
            "https://deb.nodesource.com/setup_22.x"
        );
        assert_eq!(setup_url(20), "https://deb.nodesource.com/setup_20.x");
    }

    /// Only the platform that says so pipes a script off the internet into a
    /// shell. Every other platform takes a package.
    #[test]
    fn only_nodesource_fetches_a_script() {
        assert_eq!(source(false, DEFAULT_MAJOR), Source::Distro);
        assert!(matches!(
            source(true, DEFAULT_MAJOR),
            Source::NodeSource { .. }
        ));
    }

    #[test]
    fn the_major_comes_out_of_either_spelling() {
        assert_eq!(parse_major("v22.11.0"), Some(22));
        assert_eq!(parse_major("22.11.0"), Some(22));
        assert_eq!(parse_major("  v20.19.2\n"), Some(20));
        assert_eq!(parse_major("v9.11.2"), Some(9));
        assert_eq!(parse_major(""), None);
        assert_eq!(parse_major("v"), None);
        assert_eq!(parse_major("not a version"), None);
    }

    /// The floor, and the boundary either side of it.
    #[test]
    fn twenty_is_enough_and_nineteen_is_not() {
        assert!(check("v20.0.0").is_ok());
        assert!(check("v22.11.0").is_ok());
        assert!(check("v19.9.0").is_err());
        assert!(check("v18.20.4").is_err());
    }

    /// A version that cannot be read is not a version that passes. Treating
    /// an unreadable answer as "probably fine" is how a `node` that is
    /// really a wrapper script printing a banner gets through.
    #[test]
    fn an_unreadable_version_fails_rather_than_passing() {
        assert!(check("").is_err());
        assert!(check("banana").is_err());
    }

    /// The messages are the shell's, because they are the ones an operator
    /// searching an install log will look for.
    #[test]
    fn the_messages_match_the_shells() {
        assert_eq!(check("v22.11.0").unwrap(), "Using Node.js v22.11.0");
        assert_eq!(
            check("v18.20.4").unwrap_err(),
            "Node.js 20+ is required, current: v18.20.4"
        );
        // `process.version` carries the `v` and `process.versions.node` does
        // not; the message keeps it either way.
        assert_eq!(
            check("18.20.4").unwrap_err(),
            check("v18.20.4").unwrap_err()
        );
    }

    /// The version NodeSource is asked for has to be one that would pass the
    /// check it is then put through, or the default configuration fails its
    /// own test.
    #[test]
    fn the_default_major_clears_the_floor() {
        const { assert!(DEFAULT_MAJOR >= MINIMUM_MAJOR) };
        assert!(check(&format!("v{DEFAULT_MAJOR}.0.0")).is_ok());
    }
}
