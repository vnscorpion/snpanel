//! `installer/update.sh`, which is a different program from the installer
//! and fails in different ways.
//!
//! An install runs once on a machine with nothing on it. An update runs on a
//! machine that is *serving* — customers' sites are up, their databases are
//! in use, and the panel is the thing the operator would use to fix whatever
//! the update breaks. Two consequences run through everything here:
//!
//! * a step that has already been done must be cheap to skip, because an
//!   update that takes twenty minutes is one an operator postpones;
//! * anything the operator can set has to be validated before it reaches a
//!   command, because the update script runs as root and takes a branch
//!   name, a tag and a repository URL.

pub mod cleanup;
pub mod env_file;
pub mod hardening;
pub mod migrations;
pub mod panel_https;
pub mod refs;
pub mod release;
pub mod runtime;
pub mod snapshot;
pub mod state;
pub mod steps;
pub mod version_sort;
