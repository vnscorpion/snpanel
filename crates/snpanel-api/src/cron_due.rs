//! Is a schedule due at this minute?
//!
//! **Not yet called.** This is the decision half of the backup scheduler,
//! landed ahead of the runner that uses it — see
//! [`crate::backup_scheduler`] for what that runner still needs. It is
//! `allow(dead_code)` deliberately rather than by oversight: the rules here
//! are fully checked against the Python and there is nothing to gain by
//! holding them back until the plumbing is ready.
//!
//! Source: `_field_matches` and `_cron_due` in
//! `app/services/backup_scheduler.py`.
//!
//! This decides whether a customer's backup runs. Too eager and the box
//! backs up every minute; too shy and a schedule silently never fires, which
//! nobody notices until they need the backup. The step and range arithmetic
//! is where a hand-port goes wrong, so every rule here is pinned to a corpus
//! taken from the real expressions.

/// One comma-separated field against one value.
///
/// Reproduces the Python exactly, including two things that look like bugs
/// and are not worth diverging over:
///
/// * `*` expands to `0-59` for **every** field, not to the field's own
///   range. Nothing reaches this with a value outside its real range, so the
///   wider bound never shows — but a port that "fixed" it to `0-23` for
///   hours would change nothing and invite the next reader to wonder which
///   is right.
/// * an empty part is skipped rather than refused, so `1,,2` is `1,2`. The
///   expression was validated when it was saved; this is the reader, not the
///   gate.
///
/// A part that will not parse is treated as not matching rather than as an
/// error: a stored schedule that somehow became malformed should stop firing,
/// not stop the scheduler from running everybody else's.
pub fn field_matches(field: &str, value: u32) -> bool {
    for part in field.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // `part/step`, where an empty step is 1 and a zero step is clamped to
        // 1 — `max(int(step_text or "1"), 1)`.
        let (part, step) = match part.split_once('/') {
            Some((head, tail)) => {
                let tail = tail.trim();
                let step = if tail.is_empty() {
                    1
                } else {
                    match tail.parse::<i64>() {
                        Ok(n) => n.max(1) as u32,
                        Err(_) => continue,
                    }
                };
                (head.trim(), step)
            }
            None => (part, 1),
        };

        let (start, end) = if part == "*" {
            (0u32, 59u32)
        } else if let Some((from, to)) = part.split_once('-') {
            match (from.trim().parse::<u32>(), to.trim().parse::<u32>()) {
                (Ok(a), Ok(b)) => (a, b),
                _ => continue,
            }
        } else {
            match part.parse::<u32>() {
                Ok(n) => (n, n),
                Err(_) => continue,
            }
        };

        if start <= value && value <= end && (value - start) % step == 0 {
            return true;
        }
    }
    false
}

/// The five fields, and the weekday convention.
///
/// `now_weekday` is Monday-as-0, which is what `datetime.weekday()` returns.
/// Cron counts Sunday as 0, so it is rotated — and **7 is Sunday too**,
/// which is the alias every crontab supports and which a schedule saved as
/// `0 0 * * 7` depends on.
pub fn is_due(
    schedule: &str,
    minute: u32,
    hour: u32,
    day: u32,
    month: u32,
    now_weekday: u32,
) -> bool {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    // `schedule.split()` unpacked into five names: anything else raises, and
    // the scheduler treats a schedule it cannot read as not due rather than
    // failing the whole run.
    if fields.len() != 5 {
        return false;
    }
    let cron_weekday = (now_weekday + 1) % 7;
    field_matches(fields[0], minute)
        && field_matches(fields[1], hour)
        && field_matches(fields[2], day)
        && field_matches(fields[3], month)
        && (field_matches(fields[4], cron_weekday)
            || (cron_weekday == 0 && field_matches(fields[4], 7)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../tests/golden/cron_due.json"))
            .expect("the corpus parses")
    }

    /// Every field the Python was asked, answered the same way.
    #[test]
    fn every_field_match_agrees_with_the_python() {
        let corpus = corpus();
        let cases = corpus["fields"].as_array().expect("fields");
        assert!(cases.len() >= 200, "the corpus is too small to mean much");
        let mut matched = 0;
        for case in cases {
            let field = case["field"].as_str().expect("a field");
            let value = case["value"].as_u64().expect("a value") as u32;
            let expected = case["matches"].as_bool().expect("a verdict");
            assert_eq!(
                field_matches(field, value),
                expected,
                "{field:?} vs {value}"
            );
            if expected {
                matched += 1;
            }
        }
        // Both answers have to appear, or the test passes by always saying no.
        assert!(matched > 0 && matched < cases.len());
    }

    /// And every schedule, at every instant.
    #[test]
    fn every_schedule_is_due_when_the_python_says_so() {
        let corpus = corpus();
        let cases = corpus["due"].as_array().expect("due");
        assert!(cases.len() >= 200);
        let mut due = 0;
        for case in cases {
            let schedule = case["schedule"].as_str().expect("a schedule");
            let now = case["now"].as_str().expect("a timestamp");
            let weekday = case["weekday"].as_u64().expect("a weekday") as u32;
            let expected = case["due"].as_bool().expect("a verdict");

            // `2026-01-01T00:00:00`
            let (date, time) = now.split_once('T').expect("an ISO timestamp");
            let mut d = date.split('-').map(|p| p.parse::<u32>().unwrap());
            let (_year, month, day) = (d.next().unwrap(), d.next().unwrap(), d.next().unwrap());
            let mut t = time.split(':').map(|p| p.parse::<u32>().unwrap());
            let (hour, minute) = (t.next().unwrap(), t.next().unwrap());

            assert_eq!(
                is_due(schedule, minute, hour, day, month, weekday),
                expected,
                "{schedule:?} at {now} (weekday {weekday})"
            );
            if expected {
                due += 1;
            }
        }
        assert!(due > 0 && due < cases.len());
    }

    /// **Sunday is both 0 and 7.** A schedule saved as `0 0 * * 7` depends on
    /// it, and the rotation from `datetime.weekday()` is what makes Monday-0
    /// into cron's Sunday-0.
    #[test]
    fn sunday_answers_to_both_of_its_numbers() {
        // 2026-01-04 is a Sunday: `weekday()` says 6.
        for field in ["0", "7"] {
            let schedule = format!("0 0 * * {field}");
            assert!(is_due(&schedule, 0, 0, 4, 1, 6), "{schedule} on a Sunday");
        }
        // And Monday, `weekday()` 0, is cron's 1 rather than 0.
        assert!(is_due("0 0 * * 1", 0, 0, 5, 1, 0));
        assert!(!is_due("0 0 * * 0", 0, 0, 5, 1, 0));
    }

    /// A schedule with the wrong number of fields stops firing rather than
    /// stopping the scheduler: the Python's unpack raises, and the caller
    /// runs everybody else's schedules regardless.
    #[test]
    fn a_schedule_that_cannot_be_read_is_not_due() {
        for bad in ["", "* * * *", "* * * * * *", "nonsense"] {
            assert!(!is_due(bad, 0, 0, 1, 1, 0), "{bad:?}");
        }
    }

    /// A step of zero would divide by zero; the Python clamps it to one.
    #[test]
    fn a_zero_or_missing_step_is_one() {
        assert!(field_matches("*/0", 7));
        assert!(field_matches("*/", 7));
        assert!(field_matches("*/1", 7));
    }
}
