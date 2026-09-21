//! Shared foundation for every SNPanel binary.
//!
//! Phase 0 of `RUST_MIGRATION_PLAN.md`. Three jobs:
//!
//! 1. **Types** (`types`) - the newtypes that make NT4 structural. A
//!    `Domain` cannot hold something that is not a domain, so the privileged
//!    layer never re-validates.
//! 2. **Crypto** (`crypto`) - bit-compatible reimplementations of the four
//!    primitives that guard existing data: Fernet (C3), bcrypt (C1), JWT (C4)
//!    and TOTP (C6). These are the project's go/no-go gate.
//! 3. **Config** (`config`) - the same `.env` keys and the same refusal to
//!    start with unsafe production settings (C18, C35).
//!
//! Nothing here touches the network or spawns a process, so it is equally
//! usable from the unprivileged API and the root helper.

pub mod config;
pub mod crypto;
pub mod error;
pub mod permissions;
pub mod pyunicode;
pub mod types;

pub use error::{Result, SnpanelError};
pub use types::{
    normalized_network, AppName, DockerImage, DocumentRoot, Domain, Email, IpOrCidr, PanelUsername,
    ParseError, PhpVersion, Port, SecretString, SitePath,
};

/// The version of the panel this build corresponds to.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
