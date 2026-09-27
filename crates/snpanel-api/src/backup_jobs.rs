//! The backup family's background jobs.
//!
//! Source: `_backup_jobs` and its helpers in `app/api/maintenance.py`.
//!
//! **A process-local registry, deliberately** — and the reason the five
//! endpoints around it had to move together rather than one at a time. There
//! is no file behind this: a job queued on one side of the proxy would be
//! invisible to the other, so a customer would press Backup, get a job id
//! back, and watch a list that never mentions it. Jobs in flight at the
//! moment of a cutover are lost, which is what a restart already does to
//! them.
//!
//! Two bounds are reproduced rather than improved on. The registry holds
//! fifty entries and drops the **oldest finished** ones to stay there, so a
//! job still running is never evicted while it runs. And the work itself is
//! limited to two at a time: on a shared box this is the ceiling on how much
//! disk and how many database dumps several customers' backups can move at
//! once.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

/// Source: `BACKUP_JOB_LIMIT`.
pub const BACKUP_JOB_LIMIT: usize = 50;

/// Source: `ThreadPoolExecutor(max_workers=2)`.
pub const BACKUP_JOB_WORKERS: usize = 2;

/// One job, in the shape the registry keeps it.
#[derive(Clone, Debug, Default)]
pub struct BackupJob {
    /// Where this job sits in insertion order; see `file_jobs::FileJob`.
    pub sequence: u64,
    pub job_id: String,
    pub kind: String,
    pub status: String,
    /// Who asked for it. The registry needs this to decide who may read the
    /// job back.
    pub request_user_id: i64,
    pub website_id: Option<i64>,
    /// Whose account a full user backup is of, which is **not** always the
    /// caller: an administrator can back up someone else's.
    pub target_user_id: Option<i64>,
    /// The SFTP destination, when there is one.
    pub target_id: Option<i64>,
    pub backup_file: String,
    pub remote_file: String,
    pub target: String,
    pub message: String,
    pub error: String,
    pub created_at: String,
    pub started_at: String,
    pub finished_at: String,
}

impl BackupJob {
    /// Source: `_public_backup_job`.
    ///
    /// `request_user_id` is not in it, and `target_user_id` is reported as
    /// `user_id` — the account the backup is *of*, which is what the page
    /// shows.
    pub fn public(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "kind": self.kind,
            "status": self.status,
            "website_id": self.website_id,
            "user_id": self.target_user_id,
            "target_id": self.target_id,
            "backup_file": self.backup_file,
            "remote_file": self.remote_file,
            "target": self.target,
            "message": self.message,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        })
    }

    fn in_flight(&self) -> bool {
        self.status == "queued" || self.status == "running"
    }
}

fn registry() -> &'static Mutex<HashMap<String, BackupJob>> {
    static JOBS: OnceLock<Mutex<HashMap<String, BackupJob>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_sequence() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Source: `_queue_backup_job` — the fields every job starts with.
pub fn new_job(request_user_id: i64, kind: &str, message: &str) -> BackupJob {
    BackupJob {
        sequence: 0,
        job_id: crate::file_jobs::new_job_id(),
        kind: kind.to_string(),
        status: "queued".to_string(),
        request_user_id,
        message: message.to_string(),
        created_at: crate::file_jobs::now_iso(),
        ..BackupJob::default()
    }
}

/// Source: `_remember_backup_job`.
///
/// The eviction only considers jobs that have **finished**: fifty running
/// backups grow past the limit rather than losing the record of work that is
/// still happening.
pub fn remember(mut job: BackupJob) -> Value {
    job.sequence = next_sequence();
    let public = job.public();
    let mut jobs = registry().lock().expect("the backup job registry");
    jobs.insert(job.job_id.clone(), job);
    if jobs.len() > BACKUP_JOB_LIMIT {
        let to_remove = jobs.len() - BACKUP_JOB_LIMIT;
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

/// Source: `_set_backup_job` — update in place, or do nothing if it is gone.
pub fn update(job_id: &str, apply: impl FnOnce(&mut BackupJob)) {
    let mut jobs = registry().lock().expect("the backup job registry");
    if let Some(job) = jobs.get_mut(job_id) {
        apply(job);
    }
}

/// Mark a job as started. Every worker's first line.
pub fn start(job_id: &str, message: &str) {
    let message = message.to_string();
    update(job_id, move |job| {
        job.status = "running".to_string();
        job.started_at = crate::file_jobs::now_iso();
        job.message = message;
    });
}

/// Mark a job as finished, one way or the other.
pub fn finish(job_id: &str, outcome: Result<Finished, String>, failed_message: &str) {
    let failed_message = failed_message.to_string();
    update(job_id, move |job| {
        job.finished_at = crate::file_jobs::now_iso();
        match outcome {
            Ok(done) => {
                job.status = "done".to_string();
                job.backup_file = done.backup_file;
                job.remote_file = done.remote_file;
                job.target = done.target;
                job.message = done.message;
            }
            Err(why) => {
                job.status = "error".to_string();
                job.error = why;
                job.message = failed_message;
            }
        }
    });
}

/// What a worker has to report when it succeeds.
#[derive(Debug, Default)]
pub struct Finished {
    pub backup_file: String,
    pub remote_file: String,
    pub target: String,
    pub message: String,
}

/// Source: `_get_backup_job`.
pub fn get(job_id: &str) -> Option<BackupJob> {
    registry()
        .lock()
        .expect("the backup job registry")
        .get(job_id)
        .cloned()
}

/// Source: `_list_backup_jobs`.
///
/// **Finished work is listed here**, unlike the file-manager's registry: a
/// backup's whole point is the archive it left behind, and the path to it is
/// only on the job. Twelve at most, newest first.
pub fn list(user_id: i64, is_admin: bool) -> Vec<Value> {
    let jobs: Vec<BackupJob> = registry()
        .lock()
        .expect("the backup job registry")
        .values()
        .cloned()
        .collect();
    let mut visible: Vec<BackupJob> = jobs
        .into_iter()
        .filter(|job| is_admin || job.request_user_id == user_id)
        .collect();
    // `sorted(..., key=created_at, reverse=True)` over a dict in insertion
    // order. `reverse=True` does **not** reverse ties, because Python's sort
    // is stable: newest second first, oldest job within a second first.
    visible.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.sequence.cmp(&b.sequence))
    });
    visible.truncate(12);
    visible.iter().map(BackupJob::public).collect()
}

/// The two-at-a-time bound on backup work.
///
/// Source: `ThreadPoolExecutor(max_workers=2)`. An unbounded spawn would be
/// the obvious port and the wrong one: several full-account backups running
/// at once is several `mysqldump`s and several `tar`s competing for the same
/// disk.
pub async fn worker_permit() -> tokio::sync::OwnedSemaphorePermit {
    static WORKERS: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();
    WORKERS
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(BACKUP_JOB_WORKERS)))
        .clone()
        .acquire_owned()
        .await
        .expect("the worker semaphore is never closed")
}

/// Empty the registry. Tests only.
#[cfg(test)]
pub fn clear() {
    registry().lock().expect("the backup job registry").clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry is one global, as it is in Python, so the tests take
    /// turns with it.
    fn guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK.get_or_init(|| Mutex::new(()));
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        guard
    }

    fn queued(user_id: i64, kind: &str, created_at: &str) -> BackupJob {
        let mut job = new_job(user_id, kind, "queued");
        job.created_at = created_at.to_string();
        job
    }

    #[test]
    fn a_job_is_only_visible_to_who_asked_for_it_or_an_admin() {
        let _guard = guard();
        remember(queued(1, "site_backup", "2026-01-01T00:00:00Z"));
        remember(queued(2, "site_backup", "2026-01-01T00:00:01Z"));

        assert_eq!(list(1, false).len(), 1);
        assert_eq!(list(2, false).len(), 1);
        assert_eq!(list(1, true).len(), 2);
        // Someone with no jobs and no admin sees nothing rather than an
        // error.
        assert_eq!(list(3, false).len(), 0);
    }

    /// Unlike the file-manager's listing, a finished backup stays: the path
    /// to the archive is the answer, and it only lives on the job.
    #[test]
    fn a_finished_backup_is_still_listed() {
        let _guard = guard();
        let job = queued(1, "site_backup", "2026-01-01T00:00:00Z");
        let job_id = job.job_id.clone();
        remember(job);
        finish(
            &job_id,
            Ok(Finished {
                backup_file: "/backups/example.com-1.tar.gz".to_string(),
                message: "Website backup completed".to_string(),
                ..Finished::default()
            }),
            "Website backup failed",
        );
        let listed = list(1, false);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["status"], "done");
        assert_eq!(listed[0]["backup_file"], "/backups/example.com-1.tar.gz");
    }

    #[test]
    fn the_newest_second_comes_first_and_ties_keep_their_order() {
        let _guard = guard();
        let first = queued(1, "site_backup", "2026-01-01T00:00:00Z");
        let second = queued(1, "user_backup", "2026-01-01T00:00:00Z");
        let later = queued(1, "sftp_backup", "2026-01-01T00:00:05Z");
        remember(first);
        remember(second);
        remember(later);
        let listed = list(1, false);
        assert_eq!(listed[0]["kind"], "sftp_backup");
        // Same second: the one queued first is still first.
        assert_eq!(listed[1]["kind"], "site_backup");
        assert_eq!(listed[2]["kind"], "user_backup");
    }

    /// Fifty is the cap, and a job still in flight is never the one that
    /// goes — however old it is.
    #[test]
    fn eviction_takes_the_oldest_finished_job_and_never_a_running_one() {
        let _guard = guard();
        let ancient = queued(1, "site_backup", "2020-01-01T00:00:00Z");
        let ancient_id = ancient.job_id.clone();
        remember(ancient);
        update(&ancient_id, |job| job.status = "running".to_string());

        let mut finished_ids = Vec::new();
        for index in 0..BACKUP_JOB_LIMIT {
            let job = queued(1, "site_backup", &format!("2026-01-01T00:00:{index:02}Z"));
            finished_ids.push(job.job_id.clone());
            let job_id = job.job_id.clone();
            remember(job);
            update(&job_id, |job| job.status = "done".to_string());
        }
        // The running one from 2020 survives; the oldest *finished* one goes.
        assert!(get(&ancient_id).is_some());
        assert!(get(&finished_ids[0]).is_none());
        assert!(get(&finished_ids[1]).is_some());
    }

    #[test]
    fn a_failed_job_carries_the_reason_and_not_a_path() {
        let _guard = guard();
        let job = queued(1, "user_backup", "2026-01-01T00:00:00Z");
        let job_id = job.job_id.clone();
        remember(job);
        finish(
            &job_id,
            Err("mysqldump: refused".to_string()),
            "Full user backup failed",
        );
        let found = get(&job_id).expect("the job");
        assert_eq!(found.status, "error");
        assert_eq!(found.error, "mysqldump: refused");
        assert_eq!(found.message, "Full user backup failed");
        assert_eq!(found.backup_file, "");
    }

    /// `user_id` in the answer is the account the backup is **of**, not the
    /// administrator who asked for it.
    #[test]
    fn the_reported_user_is_whose_backup_it_is() {
        let _guard = guard();
        let mut job = queued(1, "user_backup", "2026-01-01T00:00:00Z");
        job.target_user_id = Some(9);
        let public = remember(job);
        assert_eq!(public["user_id"], 9);
    }
}
