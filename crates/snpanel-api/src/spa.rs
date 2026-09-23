//! Serving the built frontend, and the panel's own brand assets.
//!
//! Source: `main.py`'s `serve_spa`, `favicon` and `brand_asset`, plus the
//! `/assets` mount.
//!
//! Until now every path outside `/api` fell through to the strangler and
//! Python served the page. That is the last thing keeping a Python process
//! on the box, and with the upstream gone a panel would answer 404 at `/`.
//!
//! The frontend is read from `FRONTEND_DIST` rather than embedded in the
//! binary. The installer builds it on the machine with `npm run build`, and
//! `FRONTEND_DIST` is one of the names contract C18 says may not change — so
//! embedding it would mean the release build runs npm and every existing box
//! points at a directory nothing reads. Embedding remains an option worth
//! taking later, together with dropping Node from the installer; it is not
//! part of closing this gap.

use std::path::{Path, PathBuf};

/// The one rule that matters here.
///
/// `serve_spa` joins a caller-supplied path onto the dist directory,
/// **resolves it**, and then requires the result to still be inside. That
/// order is what makes it safe: resolving first means `..` is gone before
/// the check, and it also means a symlink inside the tree pointing outside
/// is refused rather than followed — a build step that left one would
/// otherwise turn the panel into a file server for the whole disk.
///
/// `None` is a 404.
pub fn resolve_within(dist: &Path, requested: &str) -> Option<PathBuf> {
    // `full_path.startswith("api/")` - the API is this process's own, and a
    // path under it that reached here is one no router claimed.
    if requested.starts_with("api/") {
        return None;
    }
    let root = dist.canonicalize().ok()?;
    let candidate = root.join(requested).canonicalize().ok()?;
    candidate.starts_with(&root).then_some(candidate)
}

/// What to serve for a path that is not a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spa {
    /// A real file inside the dist directory.
    File(PathBuf),
    /// `index.html`, so the browser's router can take over. This is what
    /// makes a deep link like `/websites/12` work on a page reload.
    Index,
    NotFound,
}

/// Source: `serve_spa`.
///
/// A missing file under `assets/` is a 404 rather than the index, and that
/// distinction is load-bearing: a stale bundle reference would otherwise be
/// answered with HTML, and the browser would report a JavaScript syntax
/// error on the first `<` instead of a missing file.
pub fn route(dist: &Path, requested: &str) -> Spa {
    match resolve_within(dist, requested) {
        Some(path) if path.is_file() => Spa::File(path),
        _ if requested.starts_with("api/") => Spa::NotFound,
        _ if requested.starts_with("assets/") => Spa::NotFound,
        _ => Spa::Index,
    }
}

/// Brand assets live outside the frontend build, because an operator uploads
/// them and a rebuild would wipe anything kept there.
pub fn brand_assets_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("assets")
}

/// The URL a stored brand asset is served from.
///
/// Source: `_asset_url`. Three things it does, all of which matter:
///
/// * the path is `/brand-assets/<name>`, which is what the browser asks for;
/// * a filename with no file behind it becomes the empty string, so the
///   frontend falls back to the built-in image rather than showing a broken
///   one;
/// * the `?v=` is `<mtime_ns>-<size>`, which is what makes a *replaced* logo
///   appear. Without it the browser keeps serving the old one from cache
///   under the same URL, and the operator concludes the upload silently
///   failed.
pub fn asset_url(dir: &Path, filename: &str) -> String {
    if filename.is_empty() {
        return String::new();
    }
    let Ok(meta) = std::fs::metadata(dir.join(filename)) else {
        return String::new();
    };
    use std::os::unix::fs::MetadataExt;
    let version = format!("{}-{}", meta.mtime_nsec_total(), meta.size());
    format!("/brand-assets/{filename}?v={version}")
}

/// `st_mtime_ns` as Python reports it: whole nanoseconds since the epoch, not
/// the sub-second part on its own.
trait MtimeNs {
    fn mtime_nsec_total(&self) -> i128;
}

impl MtimeNs for std::fs::Metadata {
    fn mtime_nsec_total(&self) -> i128 {
        use std::os::unix::fs::MetadataExt;
        i128::from(self.mtime()) * 1_000_000_000 + i128::from(self.mtime_nsec())
    }
}

/// Source: `ALLOWED_ASSET_TYPES`.
///
/// An allow-list, and the reason is the upload rather than the download: a
/// file the panel will hand back with a media type is a file somebody may be
/// able to persuade a browser to execute, so the set is closed.
pub fn media_type(filename: &str) -> Option<&'static str> {
    match filename.rsplit('.').next()?.to_ascii_lowercase().as_str() {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "svg" => Some("image/svg+xml"),
        "ico" => Some("image/x-icon"),
        _ => None,
    }
}

/// A brand asset filename, checked before it is joined to a directory.
///
/// No separators and no `..`: the name comes out of a URL, and this is the
/// only thing between it and `std::fs::read`.
pub fn safe_asset_name(filename: &str) -> Option<&str> {
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains('\0')
        || filename == "."
        || filename == ".."
        || filename.starts_with("..")
    {
        return None;
    }
    Some(filename)
}

/// What the panel sends with a brand asset and with the favicon.
///
/// `no-cache, must-revalidate` — the browser may keep the bytes but has to
/// ask before using them. The `?v=` on the URL handles the ordinary case;
/// this covers `/favicon.png`, which has no version in its path and would
/// otherwise survive a rebrand in cache for as long as the tab stayed open.
pub const REVALIDATE: &str = "no-cache, must-revalidate";

/// The media types a built frontend actually contains.
///
/// A bundle served as `text/plain` is a page that loads nothing, and the
/// browser says only that it refused to execute a script - so the mapping is
/// explicit rather than guessed.
pub fn frontend_media_type(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build directory of this test's own.
    ///
    /// `name` rather than the pid: every test used `bp-spa-<pid>`, the
    /// harness runs them in parallel, and one test's cleanup deleted
    /// another's tree mid-run. Which two failed depended on scheduling,
    /// which is the tell.
    fn fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bp-spa-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("index.html"), "<!doctype html>").unwrap();
        std::fs::write(dir.join("assets/index-abc.js"), "console.log(1)").unwrap();
        std::fs::write(dir.join("favicon.png"), [0u8; 8]).unwrap();
        dir
    }

    /// **The traversal check.** Resolving before comparing is what makes it
    /// safe, and every one of these would be a file outside the tree if it
    /// were not.
    #[test]
    fn nothing_outside_the_build_directory_can_be_reached() {
        let dist = fixture("traversal");
        std::fs::write(
            dist.parent()
                .unwrap()
                .join(format!("bp-spa-secret-{}", std::process::id())),
            "x",
        )
        .unwrap();
        for attempt in [
            &format!("../bp-spa-secret-{}", std::process::id()),
            "../../etc/passwd",
            &format!("assets/../../bp-spa-secret-{}", std::process::id()),
            &format!("./../bp-spa-secret-{}", std::process::id()),
            "/etc/passwd",
            "..",
        ] {
            assert_eq!(
                resolve_within(&dist, attempt),
                None,
                "{attempt} escaped the build directory"
            );
        }
        let _ = std::fs::remove_dir_all(&dist);
    }

    /// A symlink inside the tree pointing outside is refused rather than
    /// followed — resolving first is what catches it. A build step that left
    /// one would otherwise make the panel a file server for the whole disk.
    #[test]
    fn a_symlink_out_of_the_tree_is_refused() {
        let dist = fixture("symlink");
        let outside = dist
            .parent()
            .unwrap()
            .join(format!("bp-spa-outside-{}", std::process::id()));
        std::fs::write(&outside, "secret").unwrap();
        let link = dist.join("escape");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        assert_eq!(resolve_within(&dist, "escape"), None);
        assert_eq!(route(&dist, "escape"), Spa::Index);

        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&dist);
    }

    /// An ordinary file is served, and the path it resolves to is inside.
    #[test]
    fn a_real_file_is_served() {
        let dist = fixture("realfile");
        let Spa::File(path) = route(&dist, "assets/index-abc.js") else {
            panic!("the bundle was not served");
        };
        assert!(path.ends_with("assets/index-abc.js"));
        assert!(matches!(route(&dist, "favicon.png"), Spa::File(_)));
        let _ = std::fs::remove_dir_all(&dist);
    }

    /// A deep link reloaded in the browser has to reach the app, not a 404 —
    /// that is what makes `/websites/12` survive a refresh.
    #[test]
    fn an_unknown_path_falls_through_to_the_app() {
        let dist = fixture("deeplink");
        for path in ["", "websites", "websites/12", "settings/branding"] {
            assert_eq!(route(&dist, path), Spa::Index, "{path:?}");
        }
        let _ = std::fs::remove_dir_all(&dist);
    }

    /// **But a missing bundle is a 404, not the index.** Answering HTML to a
    /// stale `assets/` reference makes the browser report a JavaScript
    /// syntax error on the first `<`, which sends whoever is debugging it a
    /// long way from the actual problem.
    #[test]
    fn a_missing_asset_is_not_answered_with_html() {
        let dist = fixture("missing");
        assert_eq!(route(&dist, "assets/index-gone.js"), Spa::NotFound);
        assert_eq!(route(&dist, "assets/"), Spa::NotFound);
        let _ = std::fs::remove_dir_all(&dist);
    }

    /// An `/api/` path that reached here is one no router claimed, and it
    /// must not be answered with the app.
    #[test]
    fn an_api_path_is_never_answered_with_the_app() {
        let dist = fixture("apipath");
        assert_eq!(route(&dist, "api/websites"), Spa::NotFound);
        assert_eq!(resolve_within(&dist, "api/anything"), None);
        let _ = std::fs::remove_dir_all(&dist);
    }

    /// The name comes out of a URL, and this is the only thing between it
    /// and `std::fs::read`.
    #[test]
    fn a_brand_asset_name_cannot_address_another_directory() {
        for bad in [
            "",
            "..",
            ".",
            "../secret",
            "a/b",
            "a\\b",
            "../../etc/passwd",
        ] {
            assert_eq!(safe_asset_name(bad), None, "{bad:?}");
        }
        assert_eq!(safe_asset_name("logo.png"), Some("logo.png"));
        assert_eq!(safe_asset_name("logo-abc123.png"), Some("logo-abc123.png"));
    }

    /// A closed set: a file the panel hands back with a media type is a file
    /// somebody may be able to persuade a browser to execute.
    #[test]
    fn only_image_types_are_served() {
        assert_eq!(media_type("logo.png"), Some("image/png"));
        assert_eq!(media_type("logo.PNG"), Some("image/png"));
        assert_eq!(media_type("a.jpeg"), Some("image/jpeg"));
        for bad in ["a.html", "a.js", "a.svgz", "a", "a.php", ".png.php"] {
            assert_eq!(media_type(bad), None, "{bad}");
        }
    }

    /// A filename with no file behind it becomes the empty string, so the
    /// frontend falls back to its built-in image rather than showing a
    /// broken one.
    #[test]
    fn an_asset_that_is_not_there_has_no_url() {
        let dir = std::env::temp_dir().join(format!("bp-brand-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(asset_url(&dir, ""), "");
        assert_eq!(asset_url(&dir, "missing.png"), "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The `?v=` is what makes a replaced logo appear.** Without it the
    /// browser keeps serving the old one from cache under the same URL, and
    /// the operator concludes the upload silently failed.
    #[test]
    fn replacing_an_asset_changes_its_url() {
        let dir = std::env::temp_dir().join(format!("bp-brand-v-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("logo.png"), [0u8; 10]).unwrap();
        let first = asset_url(&dir, "logo.png");
        assert!(first.starts_with("/brand-assets/logo.png?v="), "{first}");

        // A different size is a different version even if the clock did not
        // move.
        std::fs::write(dir.join("logo.png"), [0u8; 20]).unwrap();
        let second = asset_url(&dir, "logo.png");
        assert_ne!(first, second, "a replaced asset kept its URL");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The path is the one the browser asks for, and the one Python serves.
    #[test]
    fn the_url_is_the_one_python_publishes() {
        let dir = std::env::temp_dir().join(format!("bp-brand-p-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("icon.png"), [0u8; 4]).unwrap();
        let url = asset_url(&dir, "icon.png");
        assert!(url.starts_with("/brand-assets/icon.png?v="), "{url}");
        assert!(!url.contains("/api/"), "{url}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bundle served as `text/plain` is a page that loads nothing, and the
    /// browser says only that it refused to execute a script — which points
    /// at the JavaScript rather than at the header that caused it.
    #[test]
    fn the_frontend_is_served_with_types_a_browser_will_act_on() {
        assert_eq!(
            frontend_media_type(Path::new("a/index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            frontend_media_type(Path::new("a/index-abc.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            frontend_media_type(Path::new("a/index-abc.css")),
            "text/css; charset=utf-8"
        );
        // Fonts, which a bundle always has and which fail silently when the
        // type is wrong.
        assert_eq!(frontend_media_type(Path::new("a/f.woff2")), "font/woff2");
        // Case does not matter; the build tool's output is not guaranteed.
        assert_eq!(
            frontend_media_type(Path::new("a/INDEX.HTML")),
            "text/html; charset=utf-8"
        );
        // Anything unrecognised is a download, never a guess.
        assert_eq!(
            frontend_media_type(Path::new("a/thing.bin")),
            "application/octet-stream"
        );
        assert_eq!(
            frontend_media_type(Path::new("a/noextension")),
            "application/octet-stream"
        );
    }

    /// The build's `.js` must never be served as something a browser will
    /// not execute — the whole page is that one file.
    #[test]
    fn a_bundle_is_never_served_as_plain_text() {
        for name in ["main.js", "index-abc.mjs"] {
            let t = frontend_media_type(Path::new(name));
            assert!(t.starts_with("text/javascript"), "{name} -> {t}");
        }
    }

    #[test]
    fn the_assets_directory_is_beside_the_panels_other_data() {
        assert_eq!(
            brand_assets_dir(Path::new("/var/lib/snpanel")),
            PathBuf::from("/var/lib/snpanel/assets")
        );
    }

    /// `/favicon.png` carries no version in its path, so it would otherwise
    /// survive a rebrand in cache for as long as the tab stayed open.
    #[test]
    fn the_browser_has_to_ask_before_reusing_a_brand_image() {
        assert_eq!(REVALIDATE, "no-cache, must-revalidate");
    }
}
