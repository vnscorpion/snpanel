//! Editing the backend's `.env` in place.
//!
//! Source: `env_get`, `env_set`, `env_set_default`.
//!
//! The file holds the panel's `SECRET_KEY` and its database password, and it
//! is `0640 snpanel:snpanel` — the service reads it and nothing else can.
//! **The mode is why the write is done the way it is.** The shell renders
//! the new file into a `mktemp` and then `cat`s it back over the original
//! rather than `mv`ing it into place: a `mv` replaces the inode, so the file
//! would take the temporary file's ownership and mode, and `snpanel` would
//! no longer be able to read its own configuration. The panel would fail to
//! start with an error about a missing `SECRET_KEY`, on a box where the key
//! is plainly there.

/// How the file must end up, whatever is done to it.
pub const MODE: u32 = 0o640;

/// One value out of the file.
///
/// Reproduces `awk -F= '$1 == key { sub(/^[^=]*=/, ""); print; exit }'`:
/// the key is the text before the **first** `=`, matched exactly, and the
/// value is everything after that first `=` — so a value containing an `=`
/// survives intact, which matters because a base64 `SECRET_KEY` ends in one.
///
/// The first match wins and the rest are not read.
pub fn get<'a>(contents: &'a str, key: &str) -> Option<&'a str> {
    for line in contents.lines() {
        // `lines()` is right here: awk's `$0` has the newline stripped
        // before the field split, so a trailing `\r` would be part of the
        // value on a CRLF file in the shell too.
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name == key {
            return Some(value);
        }
    }
    None
}

/// Add a key only if it is not already there.
///
/// Used for settings introduced by a new release: an operator who has
/// deliberately changed one keeps their value, and a box that has never
/// heard of it gets the default.
pub fn set_default(contents: &str, key: &str, value: &str) -> String {
    if has_key(contents, key) {
        return contents.to_string();
    }
    let mut out = contents.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("{key}={value}\n"));
    out
}

/// Whether the file already assigns this key.
///
/// The shell's `grep -q "^${key}="` — the `=` is part of the pattern, so
/// `DB` does not match a line `DB_HOST=...`.
pub fn has_key(contents: &str, key: &str) -> bool {
    let prefix = format!("{key}=");
    contents
        .split_inclusive('\n')
        .any(|line| line.starts_with(&prefix))
}

/// Replace a value, or append it when the key is new.
///
/// Reproduces the awk exactly, including two behaviours that are easy to
/// miss:
///
/// * a key assigned more than once keeps **one** line, in the position of
///   the first — the later ones are dropped rather than left to shadow it;
/// * a key that is not there is appended at the end, so the function never
///   silently does nothing.
pub fn set(contents: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let mut out = String::with_capacity(contents.len() + key.len() + value.len() + 2);
    let mut written = false;
    // `split_inclusive` and not `lines()`: `lines()` strips a trailing `\r`,
    // so a file with CRLF endings would come back rewritten to LF
    // throughout — a whole-file diff from a function asked to change one
    // setting. The awk this ports touches only the line it matches.
    for line in contents.split_inclusive('\n') {
        if line.starts_with(&prefix) {
            if !written {
                out.push_str(&format!("{key}={value}\n"));
                written = true;
            }
            continue;
        }
        out.push_str(line);
    }
    if !written {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("{key}={value}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: &str = "\
SECRET_KEY=abc123
DATABASE_URL=mysql://snpanel:pw@localhost/snpanel
PANEL_PORT=2222
DB_HOST=localhost
";

    #[test]
    fn a_value_is_everything_after_the_first_equals() {
        assert_eq!(get(ENV, "SECRET_KEY"), Some("abc123"));
        assert_eq!(get(ENV, "PANEL_PORT"), Some("2222"));
        assert_eq!(get(ENV, "NOT_THERE"), None);
    }

    /// A base64 `SECRET_KEY` ends in `=`, and a database URL contains them.
    /// Splitting on every `=` would truncate both.
    #[test]
    fn a_value_containing_an_equals_survives() {
        let env = "SECRET_KEY=YWJjZGVmZ2hpams=\nX=a=b=c\n";
        assert_eq!(get(env, "SECRET_KEY"), Some("YWJjZGVmZ2hpams="));
        assert_eq!(get(env, "X"), Some("a=b=c"));
        assert_eq!(
            get(ENV, "DATABASE_URL"),
            Some("mysql://snpanel:pw@localhost/snpanel")
        );
    }

    /// The `=` is part of the pattern, so a key is not a prefix of another
    /// key's name. Without it, setting `DB` would rewrite `DB_HOST`.
    #[test]
    fn a_key_is_never_a_prefix_of_another_key() {
        assert!(has_key(ENV, "DB_HOST"));
        assert!(!has_key(ENV, "DB"));
        assert_eq!(get(ENV, "DB"), None);
        // And setting it appends rather than rewriting the neighbour.
        let after = set(ENV, "DB", "x");
        assert!(after.contains("DB_HOST=localhost\n"));
        assert!(after.contains("DB=x\n"));
    }

    #[test]
    fn a_value_is_replaced_in_place() {
        let after = set(ENV, "PANEL_PORT", "8443");
        assert_eq!(get(&after, "PANEL_PORT"), Some("8443"));
        // In place: the lines around it do not move.
        let lines: Vec<&str> = after.lines().collect();
        assert_eq!(lines[2], "PANEL_PORT=8443");
        assert_eq!(lines[3], "DB_HOST=localhost");
        assert_eq!(lines.len(), 4);
    }

    /// A key assigned twice keeps one line, in the position of the first.
    /// Leaving the second would let it shadow the value that was just set —
    /// which is how a password change appears to have worked and has not.
    #[test]
    fn a_duplicated_key_is_collapsed_to_the_first_position() {
        let env = "A=1\nPANEL_PORT=2222\nB=2\nPANEL_PORT=9999\nC=3\n";
        let after = set(env, "PANEL_PORT", "8443");
        assert_eq!(after, "A=1\nPANEL_PORT=8443\nB=2\nC=3\n");
        assert_eq!(after.matches("PANEL_PORT=").count(), 1);
    }

    /// A key that is not there is appended, so the function never silently
    /// does nothing.
    #[test]
    fn a_new_key_is_appended_rather_than_dropped() {
        let after = set(ENV, "NEW_SETTING", "on");
        assert!(after.ends_with("NEW_SETTING=on\n"));
        assert_eq!(get(&after, "NEW_SETTING"), Some("on"));
        // The rest is untouched.
        assert!(after.starts_with(ENV));
    }

    /// An operator who has deliberately changed a setting keeps their value
    /// when a release adds a default for it.
    #[test]
    fn a_default_never_overwrites_a_value_that_is_already_there() {
        assert_eq!(set_default(ENV, "PANEL_PORT", "2222"), ENV);
        assert_eq!(set_default(ENV, "PANEL_PORT", "9999"), ENV);
        assert_eq!(
            get(&set_default(ENV, "PANEL_PORT", "9999"), "PANEL_PORT"),
            Some("2222")
        );
    }

    #[test]
    fn a_default_for_a_new_setting_is_added() {
        let after = set_default(ENV, "NEW_SETTING", "on");
        assert_eq!(get(&after, "NEW_SETTING"), Some("on"));
        assert!(after.starts_with(ENV));
    }

    /// A file that does not end in a newline gets one before the append,
    /// rather than the new setting being glued onto the last line.
    #[test]
    fn a_file_with_no_trailing_newline_is_not_corrupted() {
        let ragged = "A=1\nB=2";
        assert_eq!(set_default(ragged, "C", "3"), "A=1\nB=2\nC=3\n");
        assert_eq!(set(ragged, "C", "3"), "A=1\nB=2\nC=3\n");
        assert_eq!(set(ragged, "B", "9"), "A=1\nB=9\n");
        assert_eq!(set_default("", "A", "1"), "A=1\n");
    }

    /// A function asked to change one setting must not return a whole-file
    /// diff. `lines()` strips a trailing `\r`, so a CRLF file would come
    /// back rewritten to LF throughout; the awk this ports touches only the
    /// line it matches.
    #[test]
    fn a_file_with_crlf_endings_keeps_them_on_every_line_but_the_one_changed() {
        let crlf = "A=1\r\nPANEL_PORT=2222\r\nB=2\r\n";
        let after = set(crlf, "PANEL_PORT", "8443");
        assert!(after.starts_with("A=1\r\n"), "{after:?}");
        assert!(after.ends_with("B=2\r\n"), "{after:?}");
        assert_eq!(after.matches("\r\n").count(), 2);
        // Appending leaves every existing line alone.
        let appended = set_default(crlf, "NEW", "x");
        assert!(appended.starts_with(crlf), "{appended:?}");
        assert!(appended.ends_with("NEW=x\n"));
    }

    /// The mode is why the write goes through a temporary file that is
    /// copied *back* rather than moved into place: a move replaces the
    /// inode, the file takes the temporary's ownership, and `snpanel` can no
    /// longer read its own configuration — a panel that will not start with
    /// an error about a missing `SECRET_KEY` on a box where the key is
    /// plainly there.
    #[test]
    fn the_file_holding_the_secret_key_is_not_readable_by_other_users() {
        assert_eq!(MODE & 0o007, 0);
        assert_eq!(MODE & 0o040, 0o040);
        assert_eq!(MODE & 0o020, 0);
    }
}
