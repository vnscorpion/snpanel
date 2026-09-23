//! Deciding which backup schedules are due, and what to record about them.
//!
//! Called by `--run-backup-schedules`, the one-shot mode a systemd timer
//! invokes. The unit does **not** call it yet: the Rust binary is installed
//! as `/usr/local/bin/snpanel-api-rust` and only by `api-cutover.sh`, so
//! pointing the timer at it before a box has cut over would stop backups
//! silently. That one line moves with the cutover; see
//! [`snpanel_installer::systemd_units::backup_scheduler_service`]. That mode does the same setup the server does — the same
//! settings, the same database, the same schema check — because a scheduler
//! that read its configuration differently from the panel is a scheduler
//! that backs up something else.
//!
//! Source: `run_due_schedules` in `app/services/backup_scheduler.py`.
//!
//! Split the way the installer phases are: the part that **decides** is here
//! and is pure, and the part that **acts** — creating an archive, uploading
//! it, pruning old ones — already exists on this side and is called by the
//! runner. A scheduler is a program nobody watches, so the decisions it
//! makes should be readable somewhere other than a log.

use crate::cron_due;

/// Why a schedule is not running this minute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// Switched off by its owner.
    Inactive,
    /// Not this minute.
    NotDue,
    /// Already ran this minute.
    ///
    /// **The guard that makes a 60-second timer safe.** The unit fires every
    /// minute and `OnBootSec`/`AccuracySec` mean two firings can land inside
    /// the same wall-clock minute; without this a schedule would run twice
    /// and the customer would get two archives and two SFTP uploads for one
    /// scheduled backup.
    AlreadyRanThisMinute,
}

/// Whether a schedule should run, given the minute it is being asked about.
///
/// `last_run_at` is compared **truncated to the minute**, which is what the
/// Python's `replace(second=0, microsecond=0)` does on both sides of the
/// comparison. Comparing exact timestamps would never match and the guard
/// would never fire.
/// The minute the scheduler is asking about.
///
/// A struct rather than five loose numbers: `minute`, `hour`, `day`,
/// `month` and `weekday` are all `u32`, and a caller that transposed day and
/// month would compile, pass most of these tests, and run a customer's
/// monthly backup on the wrong day for eleven months of the year.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Minute<'a> {
    /// `YYYY-MM-DDTHH:MM`, truncated to the minute — the same truncation the
    /// Python applies to both sides of the `last_run_at` comparison.
    pub stamp: &'a str,
    pub minute: u32,
    pub hour: u32,
    pub day: u32,
    pub month: u32,
    /// Monday as 0, which is what `datetime.weekday()` returns.
    pub weekday: u32,
}

pub fn should_run(
    is_active: bool,
    schedule: &str,
    last_run_minute: Option<&str>,
    now: Minute<'_>,
) -> Result<(), Skip> {
    if !is_active {
        return Err(Skip::Inactive);
    }
    if !cron_due::is_due(
        schedule,
        now.minute,
        now.hour,
        now.day,
        now.month,
        now.weekday,
    ) {
        return Err(Skip::NotDue);
    }
    if last_run_minute == Some(now.stamp) {
        return Err(Skip::AlreadyRanThisMinute);
    }
    Ok(())
}

/// What a finished schedule records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: &'static str,
    pub message: String,
    /// Whether this schedule counts towards the run total.
    ///
    /// Only a clean run does. A schedule where one user of five failed is
    /// reported as an error and **not** counted, which is what makes the
    /// number the unit prints mean "backups that worked" rather than
    /// "schedules that were looked at".
    pub counts_as_run: bool,
}

/// Source: the `if errors:` branch.
///
/// The successes are summarised first and then listed, so the line starts
/// with the number an operator is looking for even when it is later cut.
pub fn outcome(successes: &[String], errors: &[String]) -> Outcome {
    let head = format!("ok {} user(s)", successes.len());
    if errors.is_empty() {
        let mut parts = vec![head];
        parts.extend(successes.iter().cloned());
        Outcome {
            status: "ok",
            message: short_message(&parts),
            counts_as_run: true,
        }
    } else {
        let mut parts = vec![head];
        parts.extend(errors.iter().cloned());
        Outcome {
            status: "error",
            message: short_message(&parts),
            counts_as_run: false,
        }
    }
}

/// A schedule that selected nobody.
///
/// Recorded as an error with `last_run_at` set, rather than skipped: a
/// schedule whose user set became empty would otherwise be retried every
/// minute for ever, and the customer would never be told why nothing was
/// backed up.
pub fn no_users() -> Outcome {
    Outcome {
        status: "error",
        message: "No users selected".to_string(),
        counts_as_run: false,
    }
}

/// `"; ".join(parts)[:4000]`.
///
/// Truncated by **characters**, not bytes. The messages carry usernames and
/// error text, and slicing a UTF-8 string at a byte offset would panic in
/// the middle of one — in a scheduler, where nobody is watching.
pub fn short_message(parts: &[String]) -> String {
    let joined = parts.join("; ");
    if joined.chars().count() <= MAX_MESSAGE_CHARS {
        return joined;
    }
    joined.chars().take(MAX_MESSAGE_CHARS).collect()
}

pub const MAX_MESSAGE_CHARS: usize = 4000;

#[cfg(test)]
mod tests {
    use super::*;

    fn due(last: Option<&str>) -> Result<(), Skip> {
        // 2026-01-04 00:00 is a Sunday.
        should_run(
            true,
            "0 0 * * 0",
            last,
            Minute {
                stamp: "2026-01-04T00:00",
                minute: 0,
                hour: 0,
                day: 4,
                month: 1,
                weekday: 6,
            },
        )
    }

    /// **The guard that makes a 60-second timer safe.** Two firings can land
    /// inside the same wall-clock minute, and without this the customer gets
    /// two archives and two SFTP uploads for one scheduled backup.
    #[test]
    fn a_schedule_does_not_run_twice_in_the_same_minute() {
        assert_eq!(due(None), Ok(()));
        assert_eq!(due(Some("2026-01-03T23:59")), Ok(()));
        assert_eq!(
            due(Some("2026-01-04T00:00")),
            Err(Skip::AlreadyRanThisMinute)
        );
    }

    #[test]
    fn an_inactive_schedule_is_never_due() {
        assert_eq!(
            should_run(
                false,
                "* * * * *",
                None,
                Minute {
                    stamp: "2026-01-04T00:00",
                    minute: 0,
                    hour: 0,
                    day: 4,
                    month: 1,
                    weekday: 6,
                }
            ),
            Err(Skip::Inactive)
        );
    }

    /// Inactive is checked before due, so a switched-off schedule is not
    /// reported as merely out of hours.
    #[test]
    fn the_reasons_are_distinguishable() {
        assert_eq!(
            should_run(
                true,
                "0 3 * * *",
                None,
                Minute {
                    stamp: "2026-01-04T00:00",
                    minute: 0,
                    hour: 0,
                    day: 4,
                    month: 1,
                    weekday: 6,
                }
            ),
            Err(Skip::NotDue)
        );
        assert_eq!(
            should_run(
                false,
                "0 3 * * *",
                None,
                Minute {
                    stamp: "2026-01-04T00:00",
                    minute: 0,
                    hour: 0,
                    day: 4,
                    month: 1,
                    weekday: 6,
                }
            ),
            Err(Skip::Inactive)
        );
    }

    /// One failure out of five is an error, and does **not** count towards
    /// the run total — which is what makes the number the unit prints mean
    /// "backups that worked".
    #[test]
    fn a_partial_failure_is_an_error_and_is_not_counted() {
        let ok = vec!["alice: /backups/alice.tar.gz".to_string()];
        let bad = vec!["bob: disk full".to_string()];
        let outcome = outcome(&ok, &bad);
        assert_eq!(outcome.status, "error");
        assert!(!outcome.counts_as_run);
        // The successes are summarised even when the failures are listed.
        assert!(outcome.message.starts_with("ok 1 user(s)"));
        assert!(outcome.message.contains("bob: disk full"));
    }

    #[test]
    fn a_clean_run_is_counted_and_lists_what_it_did() {
        let ok = vec![
            "alice: /backups/alice.tar.gz".to_string(),
            "bob: /backups/bob.tar.gz".to_string(),
        ];
        let outcome = outcome(&ok, &[]);
        assert_eq!(outcome.status, "ok");
        assert!(outcome.counts_as_run);
        assert!(outcome.message.starts_with("ok 2 user(s)"));
        assert!(outcome.message.contains("alice:"));
    }

    /// A schedule whose user set became empty would otherwise be retried
    /// every minute for ever, and nobody would be told why nothing was
    /// backed up.
    #[test]
    fn a_schedule_with_no_users_records_a_reason() {
        let outcome = no_users();
        assert_eq!(outcome.status, "error");
        assert_eq!(outcome.message, "No users selected");
        assert!(!outcome.counts_as_run);
    }

    /// The count comes first, so it survives the cut.
    #[test]
    fn a_long_message_is_truncated_after_the_summary() {
        let many: Vec<String> = (0..500)
            .map(|i| format!("user{i}: /backups/user{i}.tar.gz"))
            .collect();
        let outcome = outcome(&many, &[]);
        assert_eq!(outcome.message.chars().count(), MAX_MESSAGE_CHARS);
        assert!(outcome.message.starts_with("ok 500 user(s)"));
    }

    /// Truncated by characters, not bytes: the messages carry usernames and
    /// error text, and slicing UTF-8 at a byte offset panics in the middle
    /// of a character — in a scheduler, where nobody is watching.
    #[test]
    fn a_message_of_multi_byte_characters_is_cut_without_panicking() {
        // Four bytes each, so a byte-slice at 4000 would land mid-character.
        // 5000 characters, so the cut actually happens — at 3000 there is
        // nothing to truncate and the test proves nothing.
        let parts = vec!["🧿".repeat(5000)];
        let cut = short_message(&parts);
        assert_eq!(cut.chars().count(), MAX_MESSAGE_CHARS);
        // Still valid UTF-8, which is the thing a byte slice would have
        // destroyed.
        assert!(cut.chars().all(|c| c == '🧿'));
    }

    #[test]
    fn a_short_message_is_left_alone() {
        let parts = vec!["ok 1 user(s)".to_string(), "alice: x".to_string()];
        assert_eq!(short_message(&parts), "ok 1 user(s); alice: x");
        assert_eq!(short_message(&[]), "");
    }
}
