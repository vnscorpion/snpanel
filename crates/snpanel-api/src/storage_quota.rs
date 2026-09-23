//! How much disk a customer is using, and whether the next write fits.
//!
//! Source: `app.services.storage_quota`.
//!
//! Two things about this module are easy to get wrong in a port, and both
//! decide whether a customer can write a file.
//!
//! **A limit of zero is a limit.** `user_storage_limit_bytes` returns `None`
//! only for an administrator; a customer whose package says 0 MB gets a limit
//! of zero bytes, and every write is refused. Treating 0 as "unlimited" would
//! hand that customer the whole disk.
//!
//! **The enforcement path does not use the cache.** `user_storage_used_bytes`
//! takes `use_cache` and `enforce_user_storage_quota` leaves it at its default
//! of false, so a quota check always walks the tree. That is the expensive
//! choice and it is the right one: a five-minute-stale figure is fine on a
//! user list and is not fine when it decides whether a write is allowed.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Source: `BYTES_PER_MB`.
pub const BYTES_PER_MB: u64 = 1024 * 1024;

/// Source: `VOLUME_USAGE_TTL_SECONDS`.
const VOLUME_USAGE_TTL: Duration = Duration::from_secs(60);

/// Source: `USER_USAGE_TTL_SECONDS`.
///
/// Five minutes, against the volume cache's one. The two answer different
/// questions: the volume figure is one helper call, and the user figure is a
/// walk of every file the customer owns — which on a busy box is the
/// difference between a user list that loads and one that does not.
const USER_USAGE_TTL: Duration = Duration::from_secs(300);

/// Source: `StorageQuotaExceeded` - a `ValueError` subclass, which the router
/// turns into a 413 rather than the 400 every other `ValueError` becomes.
#[derive(Debug)]
pub struct StorageQuotaExceeded(pub String);

impl std::fmt::Display for StorageQuotaExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Source: `user_storage_limit_bytes`.
///
/// `None` means no limit, and only an administrator gets it. `Some(0)` is a
/// real limit of zero bytes.
///
/// One difference, stated rather than hidden: Python's `is_admin_role` raises
/// a 403 for a role it does not recognise, and this returns false for one, so
/// an unknown role gets a limit here where Python would refuse the request.
/// It is not reachable - the request was authenticated against the same role
/// before it got this far - but it is a difference.
pub fn user_storage_limit_bytes(role: &str, storage_limit_mb: i64) -> Option<u64> {
    if snpanel_core::permissions::is_admin_role(role) {
        return None;
    }
    Some(storage_limit_mb.max(0) as u64 * BYTES_PER_MB)
}

/// Source: `path_usage_bytes`.
///
/// Symlinks are counted neither for their own size nor followed. A link is
/// somebody else's bytes, and following one would let a customer's quota be
/// spent by a link into `/usr`, or count the same tree twice.
///
/// Every error is swallowed the way the Python's `except OSError: continue`
/// swallows it, except at the root: a root that cannot be stat'ed is zero, not
/// a partial walk.
pub fn path_usage_bytes(path: impl AsRef<Path>) -> u64 {
    use std::os::unix::fs::MetadataExt;

    let root = path.as_ref();
    let Ok(meta) = std::fs::symlink_metadata(root) else {
        return 0;
    };
    let mut total = meta.size();

    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            total += meta.size();
            if meta.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    total
}

/// Source: `website_storage_used_bytes`.
pub fn website_storage_used_bytes(root_path: &str) -> u64 {
    if root_path.is_empty() {
        return 0;
    }
    path_usage_bytes(root_path)
}

/// Source: `_volume_usage_cache`, with the same sixty-second life.
///
/// This process has its own copy, separate from the Python's. Both are caches
/// of the same measurement, so they agree on the number and can disagree on
/// how fresh it is - which is a difference in how long a figure is stale by,
/// not in what the figure is.
///
/// The Python's `forget_volume_usage` is deliberately not ported: nothing in
/// the panel calls it, so the cache is only ever emptied by its own sixty
/// seconds running out. Worth knowing before trusting this figure right after
/// a container was removed.
static VOLUME_USAGE: Mutex<Option<Vec<(String, Instant, u64)>>> = Mutex::new(None);

/// Source: `_user_usage_cache`, keyed by user id.
static USER_USAGE: Mutex<Option<Vec<(i64, Instant, u64)>>> = Mutex::new(None);

fn cached_user_usage(user_id: i64) -> Option<u64> {
    let cache = USER_USAGE.lock().ok()?;
    let entries = cache.as_ref()?;
    let (_, at, value) = entries.iter().find(|(id, ..)| *id == user_id)?;
    (at.elapsed() < USER_USAGE_TTL).then_some(*value)
}

fn remember_user_usage(user_id: i64, total: u64) {
    if let Ok(mut cache) = USER_USAGE.lock() {
        let entries = cache.get_or_insert_with(Vec::new);
        entries.retain(|(id, ..)| *id != user_id);
        entries.push((user_id, Instant::now(), total));
    }
}

/// Source: `volume_usage_bytes`.
///
/// Zero when Docker is not installed or the helper cannot answer: a number the
/// panel cannot measure must not be allowed to look like a full disk.
pub async fn volume_usage_bytes(dry_run: bool, linux_user: &str, use_cache: bool) -> u64 {
    if linux_user.is_empty() {
        return 0;
    }
    if use_cache {
        if let Ok(cache) = VOLUME_USAGE.lock() {
            if let Some(entries) = cache.as_ref() {
                if let Some((_, at, value)) = entries.iter().find(|(u, ..)| u == linux_user) {
                    if at.elapsed() < VOLUME_USAGE_TTL {
                        return *value;
                    }
                }
            }
        }
    }

    let result = crate::shell::privileged_timed(
        dry_run,
        "site-app-volume-usage",
        &[linux_user],
        None,
        Some(&["bash", "-lc", "echo 0"]),
        Some(120),
    )
    .await;

    // Source: `text[-1].isdigit()` - the *last* line, and only when the whole
    // of it is digits. A helper that printed a warning first still answers.
    let mut total = 0u64;
    if result.returncode == 0 {
        if let Some(last) = result.stdout.trim().lines().next_back() {
            if !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()) {
                total = last.parse().unwrap_or(0);
            }
        }
    }

    if let Ok(mut cache) = VOLUME_USAGE.lock() {
        let entries = cache.get_or_insert_with(Vec::new);
        entries.retain(|(u, ..)| u != linux_user);
        entries.push((linux_user.to_string(), Instant::now(), total));
    }
    total
}

/// Source: `app_storage_used_bytes` - "an application's own directory plus the
/// volumes its containers write to. Both sat outside what the quota measured:
/// the directory because it is not a website root, the volumes because they
/// are not even under /home."
pub async fn app_storage_used_bytes(
    dry_run: bool,
    db: &snpanel_db::Database,
    user_id: i64,
    application_installed: bool,
) -> u64 {
    if !application_installed {
        return 0;
    }
    let Ok(apps) = db.site_apps().by_owner(user_id).await else {
        return 0;
    };
    if apps.is_empty() {
        return 0;
    }

    let mut total = 0u64;
    let mut linux_users: Vec<String> = Vec::new();
    for app in &apps {
        // Source: the `except (ValueError, AttributeError): continue` - an app
        // whose owner is gone, or whose name no longer validates, is skipped
        // rather than counted as zero or refused.
        let username = app
            .owner_username
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let Ok(owner) = snpanel_core::types::PanelUsername::parse(&username) else {
            continue;
        };
        let Some(directory) = app_directory(owner.as_str(), &app.name) else {
            continue;
        };
        total += path_usage_bytes(directory);
        if !linux_users.iter().any(|u| u == owner.as_str()) {
            linux_users.push(owner.as_str().to_string());
        }
    }
    for linux_user in &linux_users {
        total += volume_usage_bytes(dry_run, linux_user, true).await;
    }
    total
}

/// Source: `site_apps.app_directory` - "where an app's files live. Derived,
/// never supplied by the caller."
fn app_directory(owner_linux_user: &str, name: &str) -> Option<std::path::PathBuf> {
    let safe_name = crate::routes::addons::validate_app_name(name)?;
    Some(
        Path::new(snpanel_core::types::HOME_ROOT)
            .join(owner_linux_user)
            .join("apps")
            .join(safe_name),
    )
}

/// Source: `user_storage_used_bytes` with `use_cache=False`, which is what
/// every quota check uses.
pub async fn user_storage_used_bytes(
    dry_run: bool,
    db: &snpanel_db::Database,
    user_id: i64,
    application_installed: bool,
) -> u64 {
    let websites = db
        .websites()
        .list(Some(user_id), "")
        .await
        .unwrap_or_default();
    let mut total: u64 = websites
        .iter()
        .map(|w| website_storage_used_bytes(&w.root_path))
        .sum();
    total += app_storage_used_bytes(dry_run, db, user_id, application_installed).await;
    total
}

/// Source: `user_storage_used_bytes` with `use_cache=True`.
///
/// Only the user **list** asks for this, matching Python's
/// `_user_out(..., cached_usage=True)`: it walks every account's files at
/// once, and a five-minute-old figure on a list is fine. **Nothing that
/// decides whether a write is allowed may use it** — see the module header.
pub async fn user_storage_used_bytes_cached(
    dry_run: bool,
    db: &snpanel_db::Database,
    user_id: i64,
    application_installed: bool,
) -> u64 {
    if let Some(cached) = cached_user_usage(user_id) {
        return cached;
    }
    let total = user_storage_used_bytes(dry_run, db, user_id, application_installed).await;
    remember_user_usage(user_id, total);
    total
}

/// The account whose allowance a write is about to spend.
///
/// Source: `website.owner` - the four things `enforce_user_storage_quota`
/// reads off it, plus the two flags the Rust side needs and Python reads from
/// module state. They travel together because getting one of them from a
/// different user is the bug this makes hard to write.
pub struct QuotaSubject<'a> {
    pub dry_run: bool,
    pub user_id: i64,
    pub role: &'a str,
    pub storage_limit_mb: i64,
    /// Source: `addons.is_installed(addons.APPLICATION)`, which decides
    /// whether application directories and container volumes count at all.
    pub application_installed: bool,
}

/// Source: `enforce_user_storage_quota`.
///
/// `replaced_bytes` is what the write is overwriting, so replacing a 10 MB
/// file with an 11 MB one costs 1 MB and not 11. Both operands are floored at
/// zero before use, and the subtraction is floored too - which matters,
/// because a `replaced_bytes` larger than the measured total would otherwise
/// wrap rather than clamp.
pub async fn enforce_user_storage_quota(
    db: &snpanel_db::Database,
    subject: &QuotaSubject<'_>,
    incoming_bytes: u64,
    replaced_bytes: u64,
) -> Result<(), StorageQuotaExceeded> {
    let Some(limit_bytes) = user_storage_limit_bytes(subject.role, subject.storage_limit_mb) else {
        return Ok(());
    };
    let used_bytes = user_storage_used_bytes(
        subject.dry_run,
        db,
        subject.user_id,
        subject.application_installed,
    )
    .await;
    let projected = used_bytes.saturating_sub(replaced_bytes) + incoming_bytes;
    if projected > limit_bytes {
        // The message is what the customer reads, so the arithmetic in it is
        // the Python's: integer division to MB, of the projected figure and
        // the limit, not of the difference.
        return Err(StorageQuotaExceeded(format!(
            "Storage quota exceeded: {} MB used/projected, limit {} MB",
            projected / BYTES_PER_MB,
            limit_bytes / BYTES_PER_MB
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    /// Every place that reports a customer's usage asks this module for the
    /// figure.
    ///
    /// The bug this is about had already happened: the enforcement path
    /// counted an application's directory and its container volumes, and the
    /// two endpoints that *reported* usage summed website roots alone. A
    /// customer with a site app was refused a write at a figure the panel
    /// had never shown them, and nothing failed — both halves were
    /// individually correct.
    ///
    /// **The compiler is now the real guard.** `storage.rs` used to carry a
    /// second copy of the tree walk, and deleting it means there is no
    /// longer a function a caller could quietly go back to; both mutations
    /// tried against this fail to compile rather than failing here.
    ///
    /// What this test still catches is narrower and worth its three lines:
    /// a caller that stops asking for the figure at all. It is a statement
    /// of intent more than a net.
    #[test]
    fn every_reported_usage_figure_counts_applications_too() {
        for (name, source) in [
            ("auth.rs", include_str!("routes/auth.rs")),
            ("users.rs", include_str!("routes/users.rs")),
            ("provisioning.rs", include_str!("routes/provisioning.rs")),
        ] {
            assert!(
                source.contains("storage_quota::user_storage_used_bytes"),
                "{name} no longer asks storage_quota for the figure"
            );
            assert!(
                !source.contains("storage::website_usage"),
                "{name} sums website roots itself again - applications would \
                 stop being counted, silently"
            );
        }
    }

    // Moved from `storage.rs`, which carried a second copy of this walk.
    // The other two cases it covered — a missing path, and a symlink —
    // were already tested here; this one was not.
    #[test]
    fn a_directory_counts_its_own_inode_and_its_contents() {
        let dir = std::env::temp_dir().join(format!("bp-usage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let mut f = std::fs::File::create(dir.join("sub/file")).unwrap();
        f.write_all(&[0u8; 1234]).unwrap();
        drop(f);

        let total = path_usage_bytes(&dir);
        // The file, plus both directory inodes - so strictly more than the
        // file alone. Omitting the root's own size is the subtle version of
        // this bug and it would never show up as an obvious failure.
        assert!(
            total > 1234,
            "expected the directories to count too, got {total}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    /// A package of 0 MB is a limit of zero, not an absence of one. Reading it
    /// as "unlimited" would give the customer with the smallest package the
    /// whole disk.
    #[test]
    fn a_zero_limit_is_a_limit_and_only_an_admin_has_none() {
        assert_eq!(user_storage_limit_bytes("end_user", 0), Some(0));
        assert_eq!(
            user_storage_limit_bytes("end_user", 10),
            Some(10 * BYTES_PER_MB)
        );
        assert_eq!(user_storage_limit_bytes("end_user", -5), Some(0));
        assert_eq!(user_storage_limit_bytes("admin", 10), None);
        // The legacy aliases, which `normalize_role` maps before the enum.
        assert_eq!(user_storage_limit_bytes("super_admin", 0), None);
        assert_eq!(user_storage_limit_bytes("user", 3), Some(3 * BYTES_PER_MB));
        assert_eq!(
            user_storage_limit_bytes("readonly", 3),
            Some(3 * BYTES_PER_MB)
        );
    }

    #[test]
    fn a_symlink_is_neither_counted_nor_followed() {
        let dir = std::env::temp_dir().join(format!("quota-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real")).expect("the tree");
        std::fs::write(dir.join("real/file"), vec![b'x'; 4096]).expect("a file");

        let plain = path_usage_bytes(&dir);
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).expect("a link");
        let linked = path_usage_bytes(&dir);

        // The link adds its own directory entry to the parent's size on some
        // filesystems, so this asserts the thing that matters: the 4 KB file
        // behind it is not counted a second time.
        assert!(
            linked < plain + 4096,
            "a symlinked tree was counted twice: {plain} then {linked}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_path_is_zero_rather_than_an_error() {
        assert_eq!(path_usage_bytes("/nonexistent/for/this/test"), 0);
        assert_eq!(website_storage_used_bytes(""), 0);
    }
}
