//! The file-manager's background jobs.
//!
//! Source: `_file_jobs` and its helpers in `app/api/maintenance.py`.
//!
//! **A process-local registry, deliberately.** It is only a problem if one
//! process writes it and another reads it, and the proxy routes by path and
//! method — so the endpoint that creates a job and the two that read it move
//! together and the whole registry stays on one side of the line. Jobs in
//! flight at the moment of a cutover are lost, which is what a restart
//! already does to them.
//!
//! Two bounds are reproduced rather than improved on. The registry holds
//! fifty entries and drops the **oldest finished** ones to stay there, so a
//! job still running is never evicted while it runs. And the work itself is
//! limited to two at a time, which on a shared box is a deliberate ceiling
//! on how much disk an extraction storm can move at once, not an accident of
//! how the Python was written.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

/// Source: `FILE_JOB_LIMIT`.
pub const FILE_JOB_LIMIT: usize = 50;

/// Source: `ThreadPoolExecutor(max_workers=2)`.
pub const FILE_JOB_WORKERS: usize = 2;

/// One job, in the shape the registry keeps it.
#[derive(Clone, Debug)]
pub struct FileJob {
    /// Where this job sits in insertion order.
    ///
    /// Python keeps the registry in a dict, which is ordered, and both the
    /// listing and the eviction sort **stably** on the timestamp alone — so
    /// two jobs created in the same second keep the order they were queued
    /// in. A `HashMap` has no such order, and the stamp has one-second
    /// resolution, so without this the two would come back either way
    /// round. `remember` fills it; callers leave it zero.
    pub sequence: u64,
    pub job_id: String,
    pub kind: String,
    pub status: String,
    pub user_id: i64,
    pub website_id: Option<i64>,
    pub target_key: String,
    pub archive_path: String,
    pub destination_path: String,
    pub target: String,
    pub message: String,
    pub error: String,
    pub created_at: String,
    pub started_at: String,
    pub finished_at: String,
}

impl FileJob {
    /// Source: `_public_file_job` — what a caller is allowed to see.
    ///
    /// `user_id` is **not** in it. The registry needs it to decide who may
    /// read the job; the answer does not need to say whose it was.
    pub fn public(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "kind": self.kind,
            "status": self.status,
            "website_id": self.website_id,
            "target_key": self.target_key,
            "archive_path": self.archive_path,
            "destination_path": self.destination_path,
            "target": self.target,
            "message": self.message,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        })
    }

    /// `queued` and `running` are in flight; everything else is finished.
    fn in_flight(&self) -> bool {
        self.status == "queued" || self.status == "running"
    }
}

fn registry() -> &'static Mutex<HashMap<String, FileJob>> {
    static JOBS: OnceLock<Mutex<HashMap<String, FileJob>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_sequence() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Source: `uuid.uuid4().hex` — thirty-two hex characters from sixteen
/// random bytes.
///
/// The version and variant bits a real UUID4 carries are **not** set,
/// because nothing parses this back: it is an opaque handle the page puts
/// in a URL. What matters is that it is unguessable, which is what `OsRng`
/// gives and what keeps `GET /files/jobs/{job_id}` from being a way to
/// enumerate other customers' work.
pub fn new_job_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Source: `file_target_key`.
///
/// A website id and an app id are separate sequences, so a bare number
/// would let one target's jobs show up under the other's listing.
pub fn target_key(website_id: Option<i64>, app_id: Option<i64>) -> String {
    match app_id.filter(|id| *id != 0) {
        Some(id) => format!("app:{id}"),
        None => format!(
            "site:{}",
            website_id.map(|id| id.to_string()).unwrap_or_default()
        ),
    }
}

/// Source: `_now_iso` — `utcnow().isoformat(timespec="seconds") + "Z"`.
///
/// Seconds, not microseconds, and a `Z` rather than an offset. It is only
/// ever compared to another one of these, so the format is what matters.
pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Source: `_remember_file_job`.
///
/// The eviction only considers jobs that have **finished**: a queue of more
/// than fifty running extractions grows past the limit rather than losing
/// the record of work that is still happening.
pub fn remember(mut job: FileJob) -> Value {
    job.sequence = next_sequence();
    let public = job.public();
    let mut jobs = registry().lock().expect("the job registry");
    jobs.insert(job.job_id.clone(), job);
    if jobs.len() > FILE_JOB_LIMIT {
        let to_remove = jobs.len() - FILE_JOB_LIMIT;
        // `removable.sort(key=created_at)`, stable, over a dict in
        // insertion order — so the oldest *queued* of two jobs created in
        // the same second is the one that goes.
        let mut removable: Vec<(String, u64, String)> = jobs
            .values()
            .filter(|job| !job.in_flight())
            .map(|job| (job.created_at.clone(), job.sequence, job.job_id.clone()))
            .collect();
        removable.sort();
        for (_, _, job_id) in removable.into_iter().take(to_remove) {
            jobs.remove(&job_id);
        }
    }
    public
}

/// Source: `_set_file_job` — update in place, or do nothing if it is gone.
pub fn update(job_id: &str, apply: impl FnOnce(&mut FileJob)) {
    let mut jobs = registry().lock().expect("the job registry");
    if let Some(job) = jobs.get_mut(job_id) {
        apply(job);
    }
}

/// Source: `_get_file_job`.
pub fn get(job_id: &str) -> Option<FileJob> {
    registry()
        .lock()
        .expect("the job registry")
        .get(job_id)
        .cloned()
}

/// Source: `_list_file_jobs`.
///
/// **Finished work is not listed.** The completion notice and the refreshed
/// file listing already report it, so a card for it would mean every
/// archive ever unpacked piling up in the corner of the screen. Ten at
/// most, newest first.
pub fn list(user_id: i64, is_admin: bool, website_id: Option<i64>) -> Vec<Value> {
    let jobs: Vec<FileJob> = registry()
        .lock()
        .expect("the job registry")
        .values()
        .cloned()
        .collect();
    let mut visible: Vec<FileJob> = jobs
        .into_iter()
        .filter(|job| is_admin || job.user_id == user_id)
        .filter(|job| website_id.is_none_or(|id| job.website_id == Some(id)))
        .filter(|job| job.status != "done")
        .collect();
    // `sorted(..., key=created_at, reverse=True)`. `reverse=True` does
    // **not** reverse ties: Python's sort is stable, so two jobs created in
    // the same second come back in the order they were queued. Newest
    // second first, oldest job within a second first.
    visible.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.sequence.cmp(&b.sequence))
    });
    visible.truncate(10);
    visible.iter().map(FileJob::public).collect()
}

/// The two-at-a-time bound on extraction work.
///
/// Source: `ThreadPoolExecutor(max_workers=2)`. An unbounded spawn would be
/// the obvious port and the wrong one: on a shared box this is the ceiling
/// on how much disk several customers' extractions can move at once, and
/// removing it turns one busy afternoon into an I/O stall for every site.
pub async fn worker_permit() -> tokio::sync::OwnedSemaphorePermit {
    static WORKERS: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();
    WORKERS
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(FILE_JOB_WORKERS)))
        .clone()
        .acquire_owned()
        .await
        .expect("the worker semaphore is never closed")
}

/// Empty the registry. Tests only: the Python's equivalent is a fresh
/// process.
#[cfg(test)]
pub fn clear() {
    registry().lock().expect("the job registry").clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is one global, as it is in Python, so the tests take
    /// turns with it. Without this they race: `cargo test` runs them in
    /// threads and one test's `clear()` empties another's fixtures, which
    /// fails in a way that looks like a bug in the code under test.
    fn serialise() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn job(id: &str, user_id: i64, website_id: i64, status: &str, created_at: &str) -> FileJob {
        FileJob {
            sequence: 0,
            job_id: id.to_string(),
            kind: "extract_archive".to_string(),
            status: status.to_string(),
            user_id,
            website_id: Some(website_id),
            target_key: format!("site:{website_id}"),
            archive_path: "public_html/x.zip".to_string(),
            destination_path: "public_html".to_string(),
            target: String::new(),
            message: "Extraction queued".to_string(),
            error: String::new(),
            created_at: created_at.to_string(),
            started_at: String::new(),
            finished_at: String::new(),
        }
    }

    /// Who may see a job, and which jobs are worth a card.
    ///
    /// Three rules, and each one hides something: another customer's job is
    /// not listed at all, a job for a different website is not listed on
    /// this website's page, and a job that has **finished** is not listed
    /// anywhere — the file listing already shows what it did.
    #[test]
    fn a_listing_shows_only_this_callers_work_that_is_still_in_flight() {
        let _lock = serialise();
        clear();
        remember(job("a", 1, 7, "running", "2026-09-22T09:00:01Z"));
        remember(job("b", 1, 7, "done", "2026-09-22T09:00:02Z"));
        remember(job("c", 1, 8, "queued", "2026-09-22T09:00:03Z"));
        remember(job("d", 2, 7, "error", "2026-09-22T09:00:04Z"));

        let ids = |rows: Vec<Value>| -> Vec<String> {
            rows.iter()
                .map(|r| r["job_id"].as_str().unwrap_or("").to_string())
                .collect()
        };

        // Newest first, this caller's only, nothing finished.
        assert_eq!(ids(list(1, false, None)), vec!["c", "a"]);
        // Narrowed to one website.
        assert_eq!(ids(list(1, false, Some(7))), vec!["a"]);
        assert_eq!(ids(list(1, false, Some(8))), vec!["c"]);
        assert_eq!(ids(list(1, false, Some(9))), Vec::<String>::new());
        // An administrator sees everyone's, including the failed one.
        assert_eq!(ids(list(1, true, None)), vec!["d", "c", "a"]);
        // And the other customer sees only their own.
        assert_eq!(ids(list(2, false, None)), vec!["d"]);
        // `error` is in flight for listing purposes — only `done` is hidden,
        // because a failure is the one thing the caller has to be told.
        assert!(ids(list(1, true, None)).contains(&"d".to_string()));
        assert!(!ids(list(1, true, None)).contains(&"b".to_string()));
    }

    /// Two jobs in the same second come back in the order they were queued.
    ///
    /// The stamp has one-second resolution, so a customer who unpacks two
    /// archives gets this on the first click. Python's dict is ordered and
    /// its sort is stable; a `HashMap` is neither, so without the sequence
    /// the two cards would swap places between one poll and the next.
    #[test]
    fn two_jobs_in_the_same_second_keep_the_order_they_were_queued_in() {
        let _lock = serialise();
        for _ in 0..8 {
            clear();
            remember(job("first", 1, 7, "queued", "2026-09-22T09:00:00Z"));
            remember(job("second", 1, 7, "queued", "2026-09-22T09:00:00Z"));
            remember(job("third", 1, 7, "queued", "2026-09-22T09:00:00Z"));
            // A later second still sorts above all three.
            remember(job("later", 1, 7, "queued", "2026-09-22T09:00:01Z"));
            let ids: Vec<&str> = list(1, false, None)
                .iter()
                .map(|r| r["job_id"].as_str().unwrap_or(""))
                .collect::<Vec<_>>()
                .iter()
                .map(|s| match *s {
                    "first" => "first",
                    "second" => "second",
                    "third" => "third",
                    "later" => "later",
                    _ => "?",
                })
                .collect();
            assert_eq!(ids, vec!["later", "first", "second", "third"]);
        }
    }

    /// The listing stops at ten however many are queued.
    #[test]
    fn a_listing_is_ten_at_most() {
        let _lock = serialise();
        clear();
        for i in 0..25 {
            remember(job(
                &format!("j{i:02}"),
                1,
                7,
                "queued",
                &format!("2026-09-22T09:{:02}:00Z", i),
            ));
        }
        let rows = list(1, false, None);
        assert_eq!(rows.len(), 10);
        assert_eq!(rows[0]["job_id"].as_str(), Some("j24"), "newest first");
        assert_eq!(rows[9]["job_id"].as_str(), Some("j15"));
    }

    /// What is dropped when the registry is full.
    ///
    /// The oldest **finished** jobs go. A running job is never evicted, so
    /// a box that is busy keeps every record of the work in flight and
    /// exceeds the limit rather than forgetting what it is doing.
    #[test]
    fn a_full_registry_forgets_finished_work_and_not_running_work() {
        let _lock = serialise();
        clear();
        // Fifty jobs in flight, half of them still queued rather than
        // running: neither is removable, and a port that only protected
        // the running ones would drop work that has not started.
        for i in 0..50 {
            remember(job(
                &format!("r{i:02}"),
                1,
                7,
                if i % 2 == 0 { "running" } else { "queued" },
                &format!("2026-09-22T09:00:{:02}Z", i),
            ));
        }
        remember(job("r50", 1, 7, "running", "2026-09-22T09:01:00Z"));
        assert_eq!(
            registry().lock().expect("the registry").len(),
            51,
            "a running job was evicted"
        );

        clear();
        // Fifty finished ones, then one more: the oldest finished one goes.
        for i in 0..50 {
            remember(job(
                &format!("d{i:02}"),
                1,
                7,
                "done",
                &format!("2026-09-22T09:00:{:02}Z", i),
            ));
        }
        remember(job("new", 1, 7, "queued", "2026-09-22T09:01:00Z"));
        let jobs = registry().lock().expect("the registry");
        assert_eq!(jobs.len(), 50);
        assert!(!jobs.contains_key("d00"), "the oldest finished job stayed");
        assert!(jobs.contains_key("d49"));
        assert!(jobs.contains_key("new"));
    }

    /// The id is thirty-two hex characters and not a counter.
    #[test]
    fn a_job_id_is_unguessable() {
        let ids: std::collections::BTreeSet<String> = (0..64).map(|_| new_job_id()).collect();
        assert_eq!(ids.len(), 64, "two ids collided");
        for id in &ids {
            assert_eq!(id.len(), 32, "{id}");
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "{id}"
            );
        }
        // Distinct is not enough: a counter is distinct too, and a counter
        // would let one customer read the next job's id off their own. The
        // leading digit has to move.
        let leads: std::collections::BTreeSet<char> =
            ids.iter().filter_map(|id| id.chars().next()).collect();
        assert!(leads.len() >= 8, "the ids look sequential: {leads:?}");
    }

    /// A website id and an app id are different sequences.
    #[test]
    fn the_target_key_separates_a_website_from_an_application() {
        assert_eq!(target_key(Some(7), None), "site:7");
        assert_eq!(target_key(Some(7), Some(0)), "site:7");
        assert_eq!(target_key(None, Some(7)), "app:7");
        // Both given: the application wins, which is what
        // `getattr(target, "app_id", None)` does on a `SiteApp`.
        assert_eq!(target_key(Some(3), Some(7)), "app:7");
        // Neither: an empty site key rather than a panic.
        assert_eq!(target_key(None, None), "site:");
    }

    /// An update to a job that is no longer there does nothing.
    ///
    /// The worker outlives the registry entry when the registry has evicted
    /// it, and the Python's `if not job: return` is what keeps that from
    /// resurrecting a job nobody is watching.
    #[test]
    fn finishing_a_forgotten_job_does_not_bring_it_back() {
        let _lock = serialise();
        clear();
        remember(job("a", 1, 7, "running", "2026-09-22T09:00:00Z"));
        update("a", |job| job.status = "done".to_string());
        assert_eq!(get("a").map(|j| j.status), Some("done".to_string()));

        clear();
        update("a", |job| job.status = "done".to_string());
        assert!(get("a").is_none());
        assert_eq!(registry().lock().expect("the registry").len(), 0);
    }

    /// The stamp the listing sorts on.
    #[test]
    fn the_stamp_is_seconds_and_a_z() {
        let stamp = now_iso();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert!(!stamp.contains('.'), "no microseconds: {stamp}");
        assert!(!stamp.contains('+'), "{stamp}");
        // Sorting the text sorts the times, which is what the listing
        // relies on instead of parsing them back.
        assert!("2026-09-22T09:00:01Z" < "2026-09-22T09:00:02Z");
        assert!("2026-09-22T09:59:59Z" < "2026-09-22T10:00:00Z");
        assert!("2026-09-30T23:59:59Z" < "2026-10-01T00:00:00Z");
    }

    /// The public shape carries no `user_id`.
    #[test]
    fn the_public_job_does_not_name_its_owner() {
        let public = job("a", 42, 7, "queued", "2026-09-22T09:00:00Z").public();
        let keys: std::collections::BTreeSet<&str> = public
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert!(!keys.contains("user_id"));
        assert_eq!(
            keys,
            [
                "archive_path",
                "created_at",
                "destination_path",
                "error",
                "finished_at",
                "job_id",
                "kind",
                "message",
                "started_at",
                "status",
                "target",
                "target_key",
                "website_id",
            ]
            .into_iter()
            .collect()
        );
    }
}
