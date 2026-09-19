//! One lock for the process environment, shared by every test that writes it.
//!
//! `use_helper()` and `verb_enabled()` read process-global variables, so a
//! test that writes one is writing something every other test can see. Two
//! modules here had a mutex each, guarding the same variables, which is the
//! same as having none: `shell` cleared `SNPANEL_HELPER_VERBS` under one lock
//! while `helper_socket` set it under the other.
//!
//! It passed locally, passed on Debian 13, and failed on AlmaLinux - which is
//! what a race looks like from the outside, and why the lock is one static in
//! one place rather than a convention.

use std::sync::{Mutex, MutexGuard};

static ENV: Mutex<()> = Mutex::new(());

/// Hold this for as long as the test reads or writes `SNPANEL_*`.
///
/// Poisoning is ignored on purpose: a test that panicked while holding it
/// tells us nothing about whether the environment is usable, and refusing to
/// run every later test because an earlier one failed turns one red test into
/// a red file.
pub fn lock() -> MutexGuard<'static, ()> {
    ENV.lock().unwrap_or_else(|e| e.into_inner())
}
