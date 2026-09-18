//! How much disk a user is using - `services/storage_quota.py`.
//!
//! `/auth/session` folds this into its reply, so the number the Dashboard
//! prints comes through here. Three details decide whether it matches Python's:
//!
//! 1. **The root's own size counts.** `path_usage_bytes` starts with
//!    `lstat(root).st_size` and then adds every entry beneath it. A directory
//!    inode is typically 4096 bytes, so omitting it is a small, permanent,
//!    unexplainable difference on every site.
//! 2. **Symlinks are skipped entirely** - not followed, and not counted. They
//!    are not added to the total at all, so a tree full of them measures
//!    smaller than `du` would say.
//! 3. **An unreadable directory is skipped, not an error.** The API runs as
//!    `snpanel` and customer homes are 0750; a permission error must leave the
//!    figure short rather than failing the request.
//!
//! The walk is blocking, so callers run it on the blocking pool: a WordPress
//! tree is tens of thousands of `stat` calls and holding a tokio worker for
//! that stalls every other request on the runtime.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Source: `BYTES_PER_MB`.
pub const BYTES_PER_MB: i64 = 1024 * 1024;

/// What `storage_usage_summary` returns.
#[derive(Debug, Clone, PartialEq)]
pub struct Usage {
    pub used_bytes: i64,
    /// `None` for admins - they have no quota, and the JSON carries `null`.
    pub limit_bytes: Option<i64>,
    pub percent: f64,
}

impl Usage {
    /// Source: `storage_usage_summary`.
    pub fn new(used_bytes: i64, limit_bytes: Option<i64>) -> Self {
        let percent = match limit_bytes {
            Some(limit) if limit > 0 => {
                // min(999.0, round(x, 2)) - the clamp keeps a user who is
                // wildly over quota from rendering as a four-digit bar.
                let raw = (used_bytes as f64 / limit as f64) * 100.0;
                round2(raw).min(999.0)
            }
            _ => 0.0,
        };
        Self {
            used_bytes,
            limit_bytes,
            percent,
        }
    }
}

/// Python's `round(x, 2)`, which is banker's rounding on a tie.
///
/// `format!("{:.2}")` rounds half away from zero, so it disagrees with Python
/// on exact halves - rare in a percentage, but the shadow diff compares the
/// number, not the neighbourhood.
fn round2(x: f64) -> f64 {
    let scaled = x * 100.0;
    let rounded = if (scaled.fract().abs() - 0.5).abs() < f64::EPSILON {
        // Exactly .5: round to even, as Python does.
        let floor = scaled.floor();
        if (floor as i64) % 2 == 0 {
            floor
        } else {
            floor + 1.0
        }
    } else {
        scaled.round()
    };
    rounded / 100.0
}

/// Source: `user_storage_limit_bytes` - `None` for an admin.
pub fn limit_bytes(role: &str, storage_limit_mb: i64) -> Option<i64> {
    if snpanel_core::permissions::is_admin_role(role) {
        return None;
    }
    Some(storage_limit_mb.max(0) * BYTES_PER_MB)
}

/// Source: `path_usage_bytes`.
pub fn path_usage_bytes(path: impl AsRef<Path>) -> i64 {
    let root = path.as_ref();
    // lstat, not stat: the root's own inode size is part of the total.
    let Ok(root_meta) = std::fs::symlink_metadata(root) else {
        return 0;
    };
    let mut total = root_meta.size() as i64;

    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            // 0750 customer homes read by the unprivileged API: short, not
            // fatal.
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_symlink() {
                // Not followed and not counted, exactly as Python has it.
                continue;
            }
            total += meta.size() as i64;
            if meta.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    total
}

/// Source: `website_storage_used_bytes`.
pub fn website_usage(root_path: &str) -> i64 {
    if root_path.is_empty() {
        return 0;
    }
    path_usage_bytes(root_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn an_admin_has_no_limit_and_no_percentage() {
        // `null`, not 0: the Dashboard renders "Unlimited" from the absence.
        assert_eq!(limit_bytes("admin", 1024), None);
        assert_eq!(limit_bytes("super_admin", 1024), None);
        let usage = Usage::new(5_000_000, None);
        assert_eq!(usage.limit_bytes, None);
        assert_eq!(usage.percent, 0.0);
    }

    #[test]
    fn a_customer_limit_is_megabytes_times_1024_squared() {
        assert_eq!(limit_bytes("end_user", 1024), Some(1024 * 1024 * 1024));
        // A negative or absent limit clamps to zero rather than going negative.
        assert_eq!(limit_bytes("end_user", -5), Some(0));
        assert_eq!(limit_bytes("end_user", 0), Some(0));
    }

    #[test]
    fn a_zero_limit_is_zero_percent_not_a_division_by_zero() {
        assert_eq!(Usage::new(100, Some(0)).percent, 0.0);
    }

    #[test]
    fn the_percentage_is_rounded_to_two_places_and_clamped() {
        assert_eq!(Usage::new(500, Some(1000)).percent, 50.0);
        // 1/3 -> 33.33
        assert_eq!(Usage::new(1, Some(3)).percent, 33.33);
        // Far over quota clamps at 999, not 12345.
        assert_eq!(Usage::new(1_000_000, Some(100)).percent, 999.0);
    }

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

    #[test]
    fn a_missing_path_is_zero_rather_than_an_error() {
        assert_eq!(path_usage_bytes("/nonexistent/path/for/a/test"), 0);
        assert_eq!(website_usage(""), 0);
    }

    #[test]
    fn a_symlink_is_not_counted_and_not_followed() {
        // A before/after comparison would be a bad test: on tmpfs the
        // directory's own inode grows as entries are added, so the figure
        // moves even when nothing beneath it was counted. What actually
        // matters is whether the *target* got followed, so the target is made
        // large enough that following it would be unmistakable.
        let dir = std::env::temp_dir().join(format!("bp-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let target = dir.join("target");
        std::fs::write(&target, vec![0u8; 500_000]).unwrap();
        assert!(
            path_usage_bytes(&dir) >= 500_000,
            "a real file must count towards the total"
        );

        let linked = dir.join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::os::unix::fs::symlink(&target, linked.join("link")).unwrap();
        let link_only = path_usage_bytes(&linked);
        assert!(
            link_only < 10_000,
            "a symlink must not drag its 500 KB target into the total, got {link_only}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rounding_matches_pythons_round() {
        assert_eq!(round2(33.333333), 33.33);
        assert_eq!(round2(66.666666), 66.67);
        assert_eq!(round2(0.0), 0.0);
    }
}
