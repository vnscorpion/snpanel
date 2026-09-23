//! A copy of the panel's database, taken before the update touches
//! anything.
//!
//! Source: `backup_db`.
//!
//! The update runs migrations, and a migration that goes wrong on a box
//! carrying a hundred customers' websites is not something to discover
//! without a way back. This is that way back.

use std::path::{Path, PathBuf};

/// Where snapshots go, under the backup root.
pub fn snapshot_dir(backup_root: &Path) -> PathBuf {
    backup_root.join("db-snapshots")
}

/// The default backup root, when `BACKUP_ROOT` is unset.
pub const DEFAULT_BACKUP_ROOT: &str = "/var/backups/snpanel";

/// `0750`, owned by `snpanel`.
///
/// The snapshots are the panel's database: every customer's account, every
/// website, and the hashed panel passwords. World-readable would make a
/// backup directory the easiest way to read them.
pub const DIR_MODE: u32 = 0o750;

/// `snpanel-YYYYmmdd-HHMMSS.db`, in UTC.
///
/// UTC rather than local time so the names sort chronologically on a box
/// whose timezone changes, and across boxes in different ones.
pub fn snapshot_name(stamp: &str) -> String {
    format!("snpanel-{stamp}.db")
}

/// How the copy is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `sqlite3 <db> ".backup '<snap>'"`.
    ///
    /// Preferred, and not merely for neatness: the panel may still be
    /// running, and a plain copy of a live SQLite database can catch it
    /// between a write to the file and the matching write to the WAL — which
    /// produces a file that opens cleanly and is missing the last
    /// transaction. `.backup` takes a consistent snapshot through the same
    /// locking the database itself uses.
    SqliteBackup,
    /// `cp -a`, when there is no `sqlite3` binary.
    ///
    /// A copy that might be torn is worth more than no copy at all — but it
    /// is the fallback, never the first choice.
    Copy,
}

pub fn method(sqlite3_available: bool) -> Method {
    if sqlite3_available {
        Method::SqliteBackup
    } else {
        Method::Copy
    }
}

/// How many snapshots are kept.
pub const KEEP: usize = 10;

/// Which snapshots to remove, given them newest first.
///
/// `ls -1t | tail -n +11 | xargs -r rm -f` — everything past the tenth. The
/// `-r` matters: without it `xargs` runs `rm` with no arguments when there
/// is nothing to delete, and `rm` then fails. That is why a box with nine
/// snapshots does not print an error on every update.
pub fn to_remove(newest_first: &[String]) -> &[String] {
    if newest_first.len() <= KEEP {
        return &[];
    }
    &newest_first[KEEP..]
}

/// Whether the snapshot is taken at all.
///
/// Only when there is a database to copy. A fresh box, or one whose panel
/// has never started, has none — and an update that failed because it could
/// not back up a file that does not exist would be refusing to install on a
/// new machine.
pub fn should_snapshot(database_exists: bool) -> bool {
    database_exists
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The panel may still be running, and a plain copy of a live SQLite
    /// database can catch it between the file and the WAL — producing a file
    /// that opens cleanly and is missing the last transaction.
    #[test]
    fn a_consistent_copy_is_preferred_to_a_plain_one() {
        assert_eq!(method(true), Method::SqliteBackup);
        assert_eq!(method(false), Method::Copy);
    }

    /// The names have to sort chronologically on a box whose timezone
    /// changes, and across boxes in different ones.
    #[test]
    fn the_names_sort_in_the_order_they_were_taken() {
        let names = [
            snapshot_name("20260923-010203"),
            snapshot_name("20260923-234500"),
            snapshot_name("20260924-000100"),
        ];
        assert_eq!(names[0], "snpanel-20260923-010203.db");
        let mut sorted = names.to_vec();
        sorted.sort();
        assert_eq!(sorted, names);
    }

    #[test]
    fn everything_past_the_tenth_is_removed() {
        let all: Vec<String> = (0..13).map(|i| format!("snap{i:02}")).collect();
        let removed = to_remove(&all);
        assert_eq!(removed.len(), 3);
        // Newest first, so what goes is the tail.
        assert_eq!(removed, ["snap10", "snap11", "snap12"]);
    }

    /// Exactly ten is not too many, and the boundary is where an off-by-one
    /// would delete the snapshot this run just took.
    #[test]
    fn ten_snapshots_are_all_kept() {
        let ten: Vec<String> = (0..10).map(|i| format!("snap{i}")).collect();
        assert!(to_remove(&ten).is_empty());
        let eleven: Vec<String> = (0..11).map(|i| format!("snap{i}")).collect();
        assert_eq!(to_remove(&eleven), ["snap10"]);
        assert!(to_remove(&[]).is_empty());
    }

    /// An update that failed because it could not back up a file that does
    /// not exist would be refusing to install on a new machine.
    #[test]
    fn a_box_with_no_database_is_not_a_failure() {
        assert!(!should_snapshot(false));
        assert!(should_snapshot(true));
    }

    /// The snapshots are the panel's database: every customer's account,
    /// every website, and the hashed panel passwords.
    #[test]
    fn the_snapshot_directory_is_not_world_readable() {
        assert_eq!(DIR_MODE & 0o007, 0);
        assert_eq!(DIR_MODE & 0o050, 0o050);
        assert_eq!(
            snapshot_dir(Path::new(DEFAULT_BACKUP_ROOT)),
            PathBuf::from("/var/backups/snpanel/db-snapshots")
        );
    }

    /// They go under the configured backup root, so an operator who moved
    /// backups to another volume does not find the snapshots left behind on
    /// the one that filled up.
    #[test]
    fn the_snapshots_follow_the_configured_backup_root() {
        assert_eq!(
            snapshot_dir(Path::new("/mnt/backups")),
            PathBuf::from("/mnt/backups/db-snapshots")
        );
    }
}
