//! The DirectAdmin import job registry.
//!
//! Source: `_da_import_jobs` and `_da_bulk_import_jobs` in
//! `api/maintenance.py`, plus the single-worker executor they share.
//!
//! **This registry is only in memory.** Unlike the malware jobs it has no
//! directory of JSON files behind it, so a restart loses every record of
//! what ran - which is why the four endpoints that use it had to move
//! together, and why they could not be split between two processes for
//! even one release.
//!
//! **One import at a time, across both kinds.** A DirectAdmin import
//! deletes and recreates panel users, sites, files and databases; two of
//! them at once on the same account would race over the same rows and the
//! same directories. The Python enforces that with a single-worker
//! executor plus a `429` on either endpoint if *either* kind is already
//! running, and both halves of that are reproduced.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

/// Which registry a job lives in.
///
/// They are separate maps in the Python and the payloads differ - a single
/// import carries one `result`, a bulk one carries `results` and a
/// progress counter - so they stay separate here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Single,
    Bulk,
}

type Registry = Mutex<HashMap<String, Value>>;

fn jobs(kind: Kind) -> &'static Registry {
    static SINGLE: OnceLock<Registry> = OnceLock::new();
    static BULK: OnceLock<Registry> = OnceLock::new();
    match kind {
        Kind::Single => SINGLE.get_or_init(|| Mutex::new(HashMap::new())),
        Kind::Bulk => BULK.get_or_init(|| Mutex::new(HashMap::new())),
    }
}

/// Source: `datetime.utcnow().isoformat()`.
///
/// No `Z` and no offset: `utcnow()` is naive, and the page reads it as
/// written. Microseconds are included, and **omitted when they are zero**,
/// which is what `isoformat()` does.
pub fn now_iso() -> String {
    let now = chrono::Utc::now().naive_utc();
    let micros = now.format("%.6f").to_string();
    if micros == ".000000" {
        now.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        now.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

/// Source: `str(uuid.uuid4())` - **with** dashes, unlike the malware jobs.
pub fn new_job_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Source: the `_da_import_jobs[job_id] = {...}` literal.
pub fn new_single_job(archive_name: &str, archive_path: &str) -> Value {
    json!({
        "id": new_job_id(),
        "status": "pending",
        "archive": archive_name,
        "archive_path": archive_path,
        "created_at": now_iso(),
        "result": Value::Null,
        "error": Value::Null,
    })
}

/// Source: the `_da_bulk_import_jobs[job_id] = {...}` literal.
pub fn new_bulk_job(paths: &[String]) -> Value {
    json!({
        "id": new_job_id(),
        "status": "pending",
        "total": paths.len(),
        "current": 0,
        "current_archive": "",
        "archive_paths": paths,
        "created_at": now_iso(),
        "results": Value::Null,
    })
}

pub fn remember(kind: Kind, job: &Value) {
    if let Some(id) = job.get("id").and_then(Value::as_str) {
        if let Ok(mut map) = jobs(kind).lock() {
            map.insert(id.to_string(), job.clone());
        }
    }
}

/// Source: `_da_import_jobs[job_id].update(...)` under the lock.
pub fn update(kind: Kind, job_id: &str, updates: Vec<(&str, Value)>) {
    let Ok(mut map) = jobs(kind).lock() else {
        return;
    };
    let Some(Value::Object(fields)) = map.get_mut(job_id) else {
        return;
    };
    for (key, value) in updates {
        fields.insert(key.to_string(), value);
    }
}

/// Source: `_da_import_jobs.get(job_id)`.
pub fn get(kind: Kind, job_id: &str) -> Option<Value> {
    jobs(kind).lock().ok()?.get(job_id).cloned()
}

/// Whether an import of **either** kind is running.
///
/// Source: the two `sum(1 for j in ... if j["status"] == "running")`
/// checks, which each endpoint makes against *both* registries. An import
/// deletes and recreates users, sites and databases; a second one running
/// beside it would race the first over the same rows.
pub fn any_running() -> bool {
    [Kind::Single, Kind::Bulk].iter().any(|kind| {
        jobs(*kind)
            .lock()
            .map(|map| {
                map.values()
                    .any(|job| job.get("status").and_then(Value::as_str) == Some("running"))
            })
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id shape, which the page puts straight into a URL.
    #[test]
    fn a_job_id_is_a_dashed_uuid() {
        let id = new_job_id();
        assert_eq!(id.len(), 36);
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(parts
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_hexdigit())));
        // **Dashed**, unlike the malware jobs' `uuid4().hex`. The two
        // registries are read by different pages and neither parses the
        // other's ids, but a port that swapped them would still be wrong.
        assert_ne!(id, new_job_id());
    }

    /// `datetime.utcnow().isoformat()` - no `Z`, no offset.
    #[test]
    fn a_timestamp_is_naive_isoformat() {
        let stamp = now_iso();
        assert!(!stamp.ends_with('Z'), "{stamp} carries a zone");
        assert!(!stamp.contains('+'), "{stamp} carries an offset");
        assert_eq!(stamp.as_bytes()[10], b'T', "{stamp} has no T separator");
        // `YYYY-MM-DDTHH:MM:SS` is nineteen characters; microseconds add
        // seven more and are omitted when zero.
        assert!(stamp.len() == 19 || stamp.len() == 26, "{stamp}");
    }

    /// A new job carries every field the page reads.
    #[test]
    fn a_new_job_has_every_field_the_page_reads() {
        let single = new_single_job("user.bob.tar.gz", "/backups/user.bob.tar.gz");
        for key in [
            "id",
            "status",
            "archive",
            "archive_path",
            "created_at",
            "result",
            "error",
        ] {
            assert!(single.get(key).is_some(), "a single job carries {key}");
        }
        assert_eq!(single["status"], "pending");
        // `None`, not `""`: the page tests them for truth.
        assert_eq!(single["result"], Value::Null);
        assert_eq!(single["error"], Value::Null);

        let bulk = new_bulk_job(&["/a.tar.gz".to_string(), "/b.tar.gz".to_string()]);
        for key in [
            "id",
            "status",
            "total",
            "current",
            "current_archive",
            "archive_paths",
            "created_at",
            "results",
        ] {
            assert!(bulk.get(key).is_some(), "a bulk job carries {key}");
        }
        assert_eq!(bulk["total"], 2);
        assert_eq!(bulk["current"], 0);
        assert_eq!(bulk["current_archive"], "");
        assert_eq!(bulk["results"], Value::Null);
    }

    /// One import at a time, across **both** kinds.
    #[test]
    fn a_running_import_of_either_kind_blocks_the_other() {
        // The registries are process-global, so this test names its own
        // ids and puts them back; it is the only test that writes them.
        let single = new_single_job("a.tar.gz", "/a.tar.gz");
        let single_id = single["id"].as_str().expect("an id").to_string();
        let bulk = new_bulk_job(&["/b.tar.gz".to_string()]);
        let bulk_id = bulk["id"].as_str().expect("an id").to_string();

        remember(Kind::Single, &single);
        remember(Kind::Bulk, &bulk);
        assert!(!any_running(), "two pending jobs are not a running one");

        update(Kind::Single, &single_id, vec![("status", json!("running"))]);
        assert!(any_running(), "a running single import must block");
        update(
            Kind::Single,
            &single_id,
            vec![("status", json!("completed"))],
        );
        assert!(!any_running());

        update(Kind::Bulk, &bulk_id, vec![("status", json!("running"))]);
        assert!(any_running(), "a running bulk import must block too");
        update(Kind::Bulk, &bulk_id, vec![("status", json!("completed"))]);
        assert!(!any_running());

        // And a job that was never remembered is not found.
        assert!(get(Kind::Single, "nope").is_none());
        assert_eq!(
            get(Kind::Single, &single_id).map(|j| j["status"].clone()),
            Some(json!("completed"))
        );
    }
}
