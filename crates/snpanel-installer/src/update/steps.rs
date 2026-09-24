//! Skipping the steps whose inputs have not changed.
//!
//! Source: `fingerprint`, `step_inputs_changed`, `step_mark_done`.
//!
//! An update that takes twenty minutes is one an operator postpones, and a
//! postponed update is a box running old code. Most of this script's steps
//! are idempotent and expensive — rebuilding a virtualenv, rebuilding the
//! frontend — so each records a fingerprint of the files that drive it and
//! is skipped while that fingerprint holds.
//!
//! The whole mechanism is a cache, and a cache that is wrong in the
//! *skipping* direction is much worse than one that is wrong in the running
//! direction: a step wrongly re-run costs a minute, and a step wrongly
//! skipped leaves a box on a version nobody believes it is on. Every
//! uncertainty here therefore resolves to "run it".

use std::path::{Path, PathBuf};

use snpanel_core::types::sha256_bytes;

/// Where the fingerprints live.
///
/// `/var/lib/snpanel` and not `/tmp` or the application directory: it has to
/// survive a reboot and a reinstall of the application tree, and it must not
/// survive a fresh install of the machine — which is exactly the lifetime
/// `/var/lib` has.
pub const STATE_DIR: &str = "/var/lib/snpanel/update-state";

/// The environment variable that turns the whole mechanism off.
pub const FORCE_VARIABLE: &str = "SNPANEL_FORCE_FULL_UPDATE";

/// One file's contribution to a fingerprint.
///
/// **Only the content hash, never the name.** That is the property the whole
/// thing rests on: the same files are fingerprinted from a release temporary
/// directory on one run and from `/usr/local/sbin` on the next, and if the
/// path went into the hash every step would re-run every time and the cache
/// would do nothing at all.
pub fn file_digest(bytes: &[u8]) -> String {
    sha256_bytes(bytes)
}

/// The fingerprint of a set of files.
///
/// `files` is every regular file under the paths that exist, as
/// `(path, contents)`. The path is taken only to make the caller's job
/// describable; it is not hashed.
///
/// `None` when nothing exists — which callers treat as "changed", so a step
/// whose inputs have all gone missing runs rather than being skipped.
pub fn fingerprint<'a, I, B>(files: I) -> Option<String>
where
    I: IntoIterator<Item = (&'a Path, B)>,
    B: AsRef<[u8]>,
{
    let mut digests: Vec<String> = files
        .into_iter()
        .map(|(_, bytes)| file_digest(bytes.as_ref()))
        .collect();
    if digests.is_empty() {
        return None;
    }
    // `LC_ALL=C sort`: byte order, so the answer does not depend on the
    // machine's locale. A fingerprint that differed between two boxes would
    // make every step re-run on one of them.
    digests.sort_unstable();
    // Newline-separated **with a trailing newline**, because what the shell
    // hashes is `sort`'s output and `sort` terminates every line. Verified
    // against the real pipeline rather than read off it: concatenating the
    // digests with no separator gives a different answer, and the difference
    // would show up only as every step re-running once on a box whose stored
    // fingerprints the bash wrote.
    let mut joined = digests.join("\n");
    joined.push('\n');
    Some(sha256_bytes(joined.as_bytes()))
}

/// Where a step's fingerprint is stored.
pub fn state_file(name: &str) -> PathBuf {
    Path::new(STATE_DIR).join(name)
}

/// Whether a step has to run.
///
/// Three ways to be `true`, and they are all the safe direction:
///
/// * the operator forced a full update;
/// * the inputs could not be fingerprinted at all;
/// * the fingerprint differs from the stored one — including when there is
///   no stored one, which is what makes the first update after this
///   mechanism was added run everything.
pub fn inputs_changed(forced: bool, now: Option<&str>, stored: Option<&str>) -> bool {
    if forced {
        return true;
    }
    let Some(now) = now else {
        return true;
    };
    if now.is_empty() {
        return true;
    }
    Some(now) != stored
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(contents: &[(&'static str, &'static str)]) -> Vec<(PathBuf, &'static str)> {
        contents
            .iter()
            .map(|(path, body)| (PathBuf::from(path), *body))
            .collect()
    }

    fn print(files: &[(PathBuf, &'static str)]) -> Option<String> {
        fingerprint(files.iter().map(|(p, b)| (p.as_path(), *b)))
    }

    /// The property the cache rests on: the same files under a different
    /// prefix fingerprint the same. They are hashed from a release temporary
    /// directory on one run and from their installed paths on the next, and
    /// if the path went into the hash every step would re-run every time.
    #[test]
    fn the_same_contents_under_different_paths_fingerprint_alike() {
        let from_release = files(&[
            ("/tmp/snpanel-release/files/snpanel-helper", "#!/bin/sh\n"),
            ("/tmp/snpanel-release/files/snpanelctl", "menu\n"),
        ]);
        let installed = files(&[
            ("/usr/local/sbin/snpanel-helper", "#!/bin/sh\n"),
            ("/usr/local/sbin/snpanel", "menu\n"),
        ]);
        assert_eq!(print(&from_release), print(&installed));
        assert!(print(&installed).is_some());
    }

    /// Pinned to the shell's own pipeline, run on two files containing
    /// `one` and `two`. Everything else in this module is a property; this
    /// is the one value, and it is what lets a fingerprint the bash wrote be
    /// read by this side without re-running every step.
    #[test]
    fn the_fingerprint_is_the_one_the_shell_computes() {
        // `sha256sum` of each file, as the pipeline produces them.
        assert_eq!(
            file_digest(b"one"),
            "7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed"
        );
        assert_eq!(
            file_digest(b"two"),
            "3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3"
        );
        // And the hash over them, sorted in byte order and newline
        // terminated.
        assert_eq!(
            print(&files(&[("/a", "one"), ("/b", "two")])).unwrap(),
            "8367c97dc67a22797234f0ddf8ef870f9ce2a814c54b0146d56c6bea6d68dd2f"
        );
    }

    /// And a change to any file's *contents* does move it, or the cache
    /// would skip a step whose inputs really had changed.
    #[test]
    fn a_change_to_any_file_moves_the_fingerprint() {
        let before = files(&[("/a", "one"), ("/b", "two")]);
        let after = files(&[("/a", "one"), ("/b", "two!")]);
        assert_ne!(print(&before), print(&after));
    }

    /// The order the files are found in is not the order they are hashed
    /// in: `find` makes no promise, and a fingerprint that depended on it
    /// would flap between runs on the same unchanged box.
    #[test]
    fn the_order_the_files_arrive_in_does_not_matter() {
        let one = files(&[("/a", "one"), ("/b", "two"), ("/c", "three")]);
        let other = files(&[("/c", "three"), ("/a", "one"), ("/b", "two")]);
        assert_eq!(print(&one), print(&other));
    }

    /// Two files with identical contents are two entries, not one — so
    /// deleting one of a pair of copies is a change.
    #[test]
    fn duplicate_contents_are_not_collapsed() {
        let two = files(&[("/a", "same"), ("/b", "same")]);
        let one = files(&[("/a", "same")]);
        assert_ne!(print(&two), print(&one));
    }

    /// Nothing to hash is not a fingerprint of nothing; it is no answer,
    /// and the caller runs the step.
    #[test]
    fn nothing_to_hash_is_no_answer_rather_than_an_empty_one() {
        assert_eq!(print(&[]), None);
        assert!(inputs_changed(false, None, Some("anything")));
    }

    /// The first update after this mechanism was added has no stored
    /// fingerprint for any step, and every step has to run.
    #[test]
    fn a_step_with_no_stored_fingerprint_runs() {
        assert!(inputs_changed(false, Some("abc"), None));
    }

    /// The only case that skips.
    #[test]
    fn a_step_whose_inputs_are_unchanged_is_skipped() {
        assert!(!inputs_changed(false, Some("abc"), Some("abc")));
    }

    /// And forcing overrides even that — which is the escape hatch for a box
    /// whose state directory says a step was done and whose filesystem
    /// disagrees.
    #[test]
    fn forcing_runs_everything() {
        assert!(inputs_changed(true, Some("abc"), Some("abc")));
        assert_eq!(FORCE_VARIABLE, "SNPANEL_FORCE_FULL_UPDATE");
    }

    /// A cache wrong in the skipping direction leaves a box on a version
    /// nobody believes it is on; wrong in the running direction it costs a
    /// minute. Every uncertain input therefore runs the step.
    #[test]
    fn every_uncertainty_resolves_to_running_the_step() {
        for (now, stored) in [
            (None, None),
            (None, Some("abc")),
            (Some(""), Some("")),
            (Some("abc"), None),
            (Some("abc"), Some("def")),
        ] {
            assert!(
                inputs_changed(false, now, stored),
                "{now:?}/{stored:?} was skipped"
            );
        }
    }

    /// `/var/lib` is the one place with the lifetime this needs: it survives
    /// a reboot and a reinstall of the application tree, and it does not
    /// survive a fresh install of the machine.
    #[test]
    fn the_state_outlives_the_application_tree_and_not_the_machine() {
        assert!(STATE_DIR.starts_with("/var/lib/"));
        assert!(!STATE_DIR.starts_with("/tmp"));
        assert!(!STATE_DIR.starts_with("/opt"));
        assert_eq!(
            state_file("frontend"),
            PathBuf::from("/var/lib/snpanel/update-state/frontend")
        );
    }
}
