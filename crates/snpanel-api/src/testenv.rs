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

/// The lock, plus the variables a test sets, put back on the way out.
///
/// Held as a field rather than as a `let _guard` binding because a
/// `MutexGuard` is not `Send`: clippy refuses one held across an await point,
/// and an async test that writes the environment needs both the lock and the
/// await.
///
/// Dropping restores the environment even when the test panics, which a
/// `remove_var` after the assertions does not - that leaves the variable set
/// for every test that runs afterwards and turns one failure into several.
pub struct EnvGuard {
    _guard: MutexGuard<'static, ()>,
    names: Vec<String>,
}

impl EnvGuard {
    pub fn set(vars: &[(&str, &str)]) -> Self {
        let guard = lock();
        let mut names = Vec::new();
        for (name, value) in vars {
            std::env::set_var(name, value);
            names.push((*name).to_string());
        }
        Self {
            _guard: guard,
            names,
        }
    }

    /// The lock, with these variables **removed** for the duration.
    ///
    /// For a test whose corpus was generated with the variable unset: it is
    /// not enough to leave it alone, because another test may be setting it
    /// at that moment.
    pub fn cleared(names: &[&str]) -> Self {
        let guard = lock();
        let mut held = Vec::new();
        for name in names {
            std::env::remove_var(name);
            held.push((*name).to_string());
        }
        Self {
            _guard: guard,
            names: held,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for name in &self.names {
            std::env::remove_var(name);
        }
    }
}
