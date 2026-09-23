//! `sort -V`, which decides which release is the newest one.
//!
//! Source: the `| sort -V | tail -n 1` in `latest_release_tag`.
//!
//! This is the one place in the update script where getting it subtly wrong
//! updates the box **backwards**: a lexicographic sort puts `v1.9.0` after
//! `v1.10.0`, so a panel on 1.10 would be "updated" to 1.9 — and the update
//! would report success, because from its point of view it did exactly what
//! it was told.
//!
//! So this is GNU's `filevercmp`, ported from its own specification and
//! checked against a corpus taken from GNU coreutils 9.7 running in a
//! container — not from this machine, which has uutils, and not from
//! reasoning about what version numbers ought to do.

/// The order GNU gives a byte when comparing the non-digit runs.
///
/// Three classes, and the first is the interesting one: `~` sorts **before
/// the end of the string**, which is how Debian spells "this is a
/// pre-release of what follows". Nothing else does — see
/// [`a_release_candidate_sorts_after_its_own_release`].
fn order(byte: u8) -> i32 {
    if byte.is_ascii_digit() {
        0
    } else if byte.is_ascii_alphabetic() {
        byte as i32
    } else if byte == b'~' {
        -1
    } else {
        byte as i32 + 256
    }
}

/// GNU's `verrevcmp`: alternating runs of non-digits and digits.
///
/// Non-digit runs compare byte by byte through [`order`], with the end of
/// the string counting as `0`. Digit runs compare numerically, leading zeros
/// skipped, longer run wins.
fn verrevcmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() || j < b.len() {
        let mut first_diff = 0i32;
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = if i == a.len() { 0 } else { order(a[i]) };
            let bc = if j == b.len() { 0 } else { order(b[j]) };
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == 0 {
                first_diff = a[i] as i32 - b[j] as i32;
            }
            i += 1;
            j += 1;
        }
        // One run of digits is longer than the other, so it is the larger
        // number whatever the digits were.
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

/// The length of the part before the file suffix.
///
/// GNU documents the suffix as the last match of
/// `(\.[A-Za-z~][A-Za-z0-9~]*)*$`, and this implements that definition
/// directly rather than reproducing the C: the leftmost position from which
/// the rest of the string is a run of such groups.
///
/// For a release tag it almost never bites — `v1.2.3` has no dot followed by
/// a letter at the end — but `v1.2.tar` would, and leaving it out would make
/// the two implementations differ on an input the pattern can match.
fn prefix_len(s: &[u8]) -> usize {
    for start in 0..s.len() {
        if s[start] != b'.' {
            continue;
        }
        if matches_suffix(&s[start..]) {
            return start;
        }
    }
    s.len()
}

/// Whether the whole slice is `(\.[A-Za-z~][A-Za-z0-9~]*)*`.
fn matches_suffix(s: &[u8]) -> bool {
    let mut at = 0;
    while at < s.len() {
        if s[at] != b'.' {
            return false;
        }
        at += 1;
        if at >= s.len() || !(s[at].is_ascii_alphabetic() || s[at] == b'~') {
            return false;
        }
        at += 1;
        while at < s.len() && (s[at].is_ascii_alphanumeric() || s[at] == b'~') {
            at += 1;
        }
    }
    true
}

/// GNU's `filevercmp`: the prefixes first, then the whole strings.
pub fn filevercmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let by_prefix = verrevcmp(&a[..prefix_len(a)], &b[..prefix_len(b)]);
    if by_prefix != std::cmp::Ordering::Equal {
        return by_prefix;
    }
    verrevcmp(a, b)
}

/// `sort -V`, including the tie-break.
///
/// When two keys compare equal, `sort` falls back to comparing the whole
/// lines bytewise. Without that, `v01.2.3` and `v1.2.3` — which `filevercmp`
/// calls equal — would come out in whatever order they arrived in, and the
/// answer would depend on what `git ls-remote` happened to print first.
pub fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    filevercmp(a, b).then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// `sort -V | tail -n 1`.
///
/// `None` for an empty list, which is what an unreachable remote or a
/// repository with no matching tags produces — and the caller must not treat
/// that as "no update needed".
pub fn latest<'a, I: IntoIterator<Item = &'a str>>(tags: I) -> Option<&'a str> {
    tags.into_iter().max_by(|a, b| compare(a, b))
}

/// The tag out of one `git ls-remote --tags --refs` line.
///
/// The shell's `awk '{ sub("refs/tags/", "", $2); print $2 }'` — the second
/// whitespace-separated field with the prefix removed. `--refs` is what
/// keeps `^{}` dereference lines out, so nothing here has to strip them.
pub fn tag_from_ls_remote(line: &str) -> Option<&str> {
    let mut fields = line.split_whitespace();
    let _hash = fields.next()?;
    let reference = fields.next()?;
    Some(reference.strip_prefix("refs/tags/").unwrap_or(reference))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/version_sort.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the version fixture {}: {e}", path.display()));
        serde_json::from_str(&raw).expect("it parses")
    }

    /// The whole corpus, sorted by this side, has to come out in the order
    /// GNU coreutils put it in.
    #[test]
    fn the_order_is_gnus() {
        let corpus = corpus();
        let expected: Vec<&str> = corpus["sorted"]
            .as_array()
            .expect("an array")
            .iter()
            .map(|v| v.as_str().expect("a string"))
            .collect();
        assert!(expected.len() >= 20, "the corpus is too small to mean much");

        // Sorted from a deliberately wrong starting order, so the test
        // cannot pass by leaving the input alone.
        let mut got = expected.clone();
        got.reverse();
        got.sort_by(|a, b| compare(a, b));
        assert_eq!(got, expected);

        // And it really was recorded from the implementation the servers
        // run, not from this machine's.
        let version = corpus["sort_version"].as_str().expect("a version");
        assert!(version.contains("GNU coreutils"), "{version}");
    }

    /// Every ordered pair, compared directly — so a sort that happened to
    /// produce the right whole order from a wrong comparison is still
    /// caught.
    #[test]
    fn every_pair_compares_the_way_gnu_orders_it() {
        use std::cmp::Ordering;
        let corpus = corpus();
        let pairs = corpus["pairs"].as_object().expect("an object");
        assert!(pairs.len() >= 100);
        for (key, value) in pairs {
            let (a, b) = key.split_once('|').expect("a pair");
            let expected = match value.as_i64().expect("an integer") {
                -1 => Ordering::Less,
                1 => Ordering::Greater,
                _ => Ordering::Equal,
            };
            let got = if expected == Ordering::Equal {
                filevercmp(a, b)
            } else {
                compare(a, b)
            };
            assert_eq!(got, expected, "{a} vs {b}");
        }
    }

    /// What the function actually returns, over sixty random subsets.
    #[test]
    fn the_newest_of_a_set_is_the_one_gnu_puts_last() {
        let corpus = corpus();
        let cases = corpus["latest"].as_object().expect("an object");
        assert!(cases.len() >= 50);
        for (input, expected) in cases {
            let tags: Vec<&str> = input.lines().collect();
            assert_eq!(
                latest(tags.iter().copied()),
                Some(expected.as_str().expect("a string")),
                "{input:?}"
            );
        }
    }

    /// The reason any of this is written down. A lexicographic sort puts
    /// `v1.9.0` after `v1.10.0`, so a panel on 1.10 would be "updated" to
    /// 1.9 — and would report success, because from its point of view it did
    /// what it was told.
    #[test]
    fn ten_is_newer_than_nine() {
        assert_eq!(latest(["v1.9.0", "v1.10.0"]), Some("v1.10.0"));
        assert_eq!(latest(["v1.10.0", "v1.9.0"]), Some("v1.10.0"));
        assert_eq!(latest(["v1.0.2", "v1.0.10"]), Some("v1.0.10"));
        assert_eq!(latest(["v2.0.0", "v10.0.0", "v9.9.9"]), Some("v10.0.0"));
    }

    /// **A hazard, reproduced deliberately.** `filevercmp` sorts a release
    /// candidate *after* the release it is a candidate for, because `-` is a
    /// non-digit byte and the end of a string counts as less than any of
    /// them. `~` is the one character that sorts before the end, and `-rc`
    /// does not get that treatment.
    ///
    /// `RELEASE_PATTERN` is `v[0-9]*.[0-9]*.[0-9]*`, which matches
    /// `v2.0.0-rc1`. So publishing a release candidate under a tag of that
    /// shape makes every box on the release channel take it as the newest
    /// release. This side does not differ from the shell about it — that
    /// would be its own kind of surprise — but it is recorded here rather
    /// than left to be discovered.
    #[test]
    fn a_release_candidate_sorts_after_its_own_release() {
        assert_eq!(latest(["v2.0.0", "v2.0.0-rc1"]), Some("v2.0.0-rc1"));
        // A `~` would have behaved the way one would want, which is what
        // makes the `-` case a choice of spelling rather than a law.
        assert_eq!(latest(["v2.0.0", "v2.0.0~rc1"]), Some("v2.0.0"));
    }

    /// Release candidates among themselves are ordered numerically, which is
    /// the part that does work.
    #[test]
    fn release_candidates_are_ordered_by_number_and_not_by_digit() {
        assert_eq!(
            latest(["v2.0.0-rc1", "v2.0.0-rc2", "v2.0.0-rc10"]),
            Some("v2.0.0-rc10")
        );
    }

    /// Leading zeros make no difference to the version, so the tie-break
    /// decides — and without it the answer would depend on what `git
    /// ls-remote` happened to print first.
    #[test]
    fn equal_versions_are_ordered_by_their_bytes() {
        use std::cmp::Ordering;
        assert_eq!(filevercmp("v01.2.3", "v1.2.3"), Ordering::Equal);
        assert_eq!(compare("v01.2.3", "v1.2.3"), Ordering::Less);
        assert_eq!(latest(["v1.2.3", "v01.2.3"]), Some("v1.2.3"));
        assert_eq!(latest(["v01.2.3", "v1.2.3"]), Some("v1.2.3"));
    }

    /// An unreachable remote and a repository with no matching tags both
    /// produce nothing, and the caller must not read that as "already up to
    /// date".
    #[test]
    fn no_tags_is_no_answer() {
        assert_eq!(latest(std::iter::empty()), None);
    }

    #[test]
    fn the_tag_comes_out_of_the_second_field() {
        assert_eq!(
            tag_from_ls_remote("9f1a2b3c4d5e6f708192a3b4c5d6e7f809a1b2c3\trefs/tags/v1.2.3"),
            Some("v1.2.3")
        );
        // Spaces as well as tabs, since awk splits on either.
        assert_eq!(
            tag_from_ls_remote("9f1a2b3c refs/tags/v1.2.3"),
            Some("v1.2.3")
        );
        // A line with no second field is not a tag.
        assert_eq!(tag_from_ls_remote("9f1a2b3c"), None);
        assert_eq!(tag_from_ls_remote(""), None);
    }

    /// The suffix rule almost never bites on a release tag, but the pattern
    /// can match something it does bite on — and leaving it out would make
    /// the two implementations differ there.
    #[test]
    fn the_file_suffix_rule_is_implemented_rather_than_assumed_away() {
        // `.tar` is a suffix; `.3` is not, because a suffix group needs a
        // letter or `~` after the dot.
        // The prefix is "v1.2", four bytes, and the suffix is ".tar".
        assert_eq!(prefix_len(b"v1.2.tar"), 4);
        assert_eq!(prefix_len(b"v1.2.3"), 6);
        assert_eq!(prefix_len(b"v1.2.3."), 7);
        // Several groups in a row are all part of the suffix.
        assert_eq!(prefix_len(b"v1.2.tar.gz"), 4);
        // And a dot in the middle followed by digits does not start one.
        assert_eq!(prefix_len(b"v1.2.tar.3"), 10);
    }
}
