//! Every operating-system difference SNPanel has to care about, in one place.
//!
//! Plan §6. The governing rule is that business logic never asks which distro
//! it is running on - it asks a [`Platform`] for the path, service name or
//! package it needs. If a service module ever needs `if distro == ...`, the
//! fix is a new method on the trait, not a branch at the call site.

pub mod debian;
pub mod detect;
pub mod firewall;
pub mod packages;
pub mod platform;
pub mod rhel;
pub mod selinux;

pub use detect::{check_cpu_supported, cpu_baseline, detect, OsError, OsRelease};
pub use platform::{CertbotMethod, CpuBaseline, Distro, Family, PhpRepo, Platform, TimeSync};
