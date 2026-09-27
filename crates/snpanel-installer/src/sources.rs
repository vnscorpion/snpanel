//! Getting the panel's own code onto the box, and building the frontend.
//!
//! Source: `copy_sources`, `build_frontend`, `install_wp_cli`.

use std::path::{Path, PathBuf};

/// WP-CLI, which the panel shells out to for every WordPress action.
pub mod wp_cli {
    /// Where it goes, and the mode it needs.
    pub const PATH: &str = "/usr/local/bin/wp";
    /// It is a phar run as a program, so it has to be executable — and it
    /// is public code with no secret in it.
    pub const MODE: u32 = 0o755;

    pub const URL: &str =
        "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar";

    /// Whether to fetch it.
    ///
    /// Skipped when `wp` is already on `PATH`, which is how an operator who
    /// installed it from their distribution keeps their copy — and how a
    /// re-run of the installer avoids a needless download.
    pub fn should_install(wp_on_path: bool) -> bool {
        !wp_on_path
    }
}

/// What `copy_sources` removes before copying.
///
/// The two trees are deleted rather than copied over. An update that only
/// overlaid files would leave a module deleted upstream still sitting in the
/// tree, still importable, and still doing whatever it used to do.
pub fn replaced_trees(app_dir: &Path) -> Vec<PathBuf> {
    vec![app_dir.join("backend"), app_dir.join("frontend")]
}

/// The mode `VERSION` is installed with. Read by the updater to decide
/// whether there is anything to do.
pub const VERSION_MODE: u32 = 0o644;

/// What `build_frontend` clears before running `npm install`.
///
/// A clean build every time, including the lockfile. That is deliberate and
/// it is a trade: it costs a slower install and gives a build that cannot
/// inherit a half-written `node_modules` from an interrupted run — which is
/// a failure mode that presents as a Vite error about a module that is
/// plainly there.
pub fn build_artefacts(frontend: &Path) -> Vec<PathBuf> {
    ["node_modules", "package-lock.json", "dist", ".vite"]
        .iter()
        .map(|name| frontend.join(name))
        .collect()
}

/// `VITE_API_URL`, which is baked into the bundle at build time.
///
/// A path and not a URL, so the bundle works whatever hostname or port the
/// panel ends up served on — including after the operator changes it. An
/// absolute URL here is a panel that breaks the day its address changes.
pub const VITE_API_URL: (&str, &str) = ("VITE_API_URL", "/api");

/// The file whose presence means the build produced something.
///
/// `npm run build` can exit zero having written nothing useful, so the exit
/// status alone is not the check.
pub fn build_succeeded(frontend: &Path, index_exists: bool) -> Result<(), String> {
    if index_exists {
        return Ok(());
    }
    Err(format!(
        "Frontend build failed: {}/dist/index.html is missing",
        frontend.display()
    ))
}

/// The bundle has to be world-readable, because nginx serves it as the web
/// user and it is public anyway.
///
/// `o+rX` rather than `o+rx`: the capital only adds the execute bit to
/// directories, so a stray `x` never lands on a JavaScript file.
pub const BUNDLE_OTHERS: u32 = 0o005;

/// The hashed entry point out of `dist/index.html`, for the line the
/// installer prints.
///
/// Reproduces `grep -oE 'index-[a-zA-Z0-9_-]+\.js' | head -n1`, including
/// the fallback when there is no match.
pub fn built_bundle(index_html: &str) -> String {
    let bytes = index_html.as_bytes();
    let prefix = b"index-";
    let mut at = 0;
    while at + prefix.len() <= bytes.len() {
        if &bytes[at..at + prefix.len()] != prefix {
            at += 1;
            continue;
        }
        let start = at;
        let mut end = at + prefix.len();
        while end < bytes.len() {
            let c = bytes[end];
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
                end += 1;
            } else {
                break;
            }
        }
        // At least one character, then `.js`.
        if end > at + prefix.len() && bytes[end..].starts_with(b".js") {
            return String::from_utf8_lossy(&bytes[start..end + 3]).into_owned();
        }
        at = start + 1;
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp_cli_is_left_alone_when_it_is_already_there() {
        assert!(wp_cli::should_install(false));
        assert!(!wp_cli::should_install(true));
    }

    #[test]
    fn wp_cli_is_executable_and_writable_by_no_one_else() {
        assert_eq!(wp_cli::MODE & 0o111, 0o111);
        assert_eq!(wp_cli::MODE & 0o022, 0);
        assert!(wp_cli::URL.starts_with("https://"));
        assert!(wp_cli::URL.ends_with(".phar"));
    }

    /// An update that overlaid files would leave a module deleted upstream
    /// still sitting in the tree, still importable, and still doing whatever
    /// it used to do.
    #[test]
    fn the_trees_are_replaced_rather_than_overlaid() {
        let trees = replaced_trees(Path::new("/opt/snpanel"));
        assert_eq!(
            trees,
            [
                PathBuf::from("/opt/snpanel/backend"),
                PathBuf::from("/opt/snpanel/frontend")
            ]
        );
    }

    /// A half-written `node_modules` from an interrupted run presents as a
    /// Vite error about a module that is plainly there, and costs an hour
    /// before anyone thinks to delete it.
    #[test]
    fn the_build_starts_from_nothing_including_the_lockfile() {
        let cleared = build_artefacts(Path::new("/opt/snpanel/frontend"));
        let names: Vec<String> = cleared
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            ["node_modules", "package-lock.json", "dist", ".vite"]
        );
    }

    /// An absolute URL baked into the bundle is a panel that breaks the day
    /// its address changes.
    #[test]
    fn the_api_url_in_the_bundle_is_a_path() {
        assert_eq!(VITE_API_URL.1, "/api");
        assert!(!VITE_API_URL.1.contains("://"));
    }

    /// `npm run build` can exit zero having written nothing useful, so the
    /// exit status alone is not the check.
    #[test]
    fn a_build_that_produced_no_bundle_is_a_failed_build() {
        let frontend = Path::new("/opt/snpanel/frontend");
        assert!(build_succeeded(frontend, true).is_ok());
        assert_eq!(
            build_succeeded(frontend, false).unwrap_err(),
            "Frontend build failed: /opt/snpanel/frontend/dist/index.html is missing"
        );
    }

    /// `o+rX` and not `o+rx`: the capital only adds execute to directories,
    /// so a stray `x` never lands on a JavaScript file.
    #[test]
    fn the_bundle_is_readable_by_the_web_server_and_not_writable_by_anyone() {
        assert_eq!(BUNDLE_OTHERS & 0o004, 0o004);
        assert_eq!(BUNDLE_OTHERS & 0o002, 0);
    }

    #[test]
    fn the_built_bundle_is_named_from_the_index() {
        let html = r#"<!doctype html><html><head>
<script type="module" crossorigin src="/assets/index-C3kd_9-x.js"></script>
<link rel="stylesheet" href="/assets/index-a1B2c3.css">
</head></html>"#;
        assert_eq!(built_bundle(html), "index-C3kd_9-x.js");
    }

    /// The first match, as `head -n1` takes — not the last, and not all of
    /// them.
    #[test]
    fn the_first_match_wins() {
        assert_eq!(
            built_bundle("index-aaa.js and index-bbb.js"),
            "index-aaa.js"
        );
    }

    /// Three cases where the expression does something that reading it
    /// quickly would get wrong. Each was run through the shell's own
    /// `grep -oE 'index-[a-zA-Z0-9_-]+\.js' | head -n1` and the answer
    /// recorded, rather than reasoned about.
    #[test]
    fn the_awkward_corners_of_the_expression_match_grep() {
        // A dot is not in the character class, so the run cannot cross one
        // and `.b.js` is not the suffix being looked for.
        assert_eq!(built_bundle("index-a.b.js"), "unknown");
        // A hyphen *is* in the class, so a second `index-` is swallowed by
        // the first match rather than starting a new one.
        assert_eq!(built_bundle("index-index-x.js"), "index-index-x.js");
        // `.js` is not anchored to the end, so a `.jsx` yields the `.js`
        // inside it.
        assert_eq!(built_bundle("index-abc.jsx"), "index-abc.js");
    }

    /// A build that produced something unrecognisable still prints a line.
    /// This runs after the `dist/index.html` check, so an empty answer here
    /// is a bundle named differently, not a failed build — and saying
    /// "unknown" is better than saying nothing.
    #[test]
    fn an_unrecognisable_bundle_prints_unknown_rather_than_nothing() {
        assert_eq!(built_bundle(""), "unknown");
        assert_eq!(built_bundle("<html></html>"), "unknown");
        // `index-` with nothing after it is not a name.
        assert_eq!(built_bundle("index-.js"), "unknown");
        // A CSS file is not the entry point.
        assert_eq!(built_bundle("/assets/index-a1B2c3.css"), "unknown");
        // And the scan resumes rather than giving up at the first `index-`
        // that leads nowhere.
        assert_eq!(
            built_bundle("index-.css then index-real.js"),
            "index-real.js"
        );
    }
}
