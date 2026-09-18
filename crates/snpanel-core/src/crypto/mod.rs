//! Everything that must stay bit-compatible with the Python implementation.
//!
//! These four modules are the go/no-go gate of the whole migration (plan §8,
//! Phase 0). They are shared by `snpanel-api` and `snpanel-helper` so there is
//! exactly one implementation of each primitive.

pub mod fernet;
pub mod password;
pub mod token;
pub mod totp;

pub use fernet::{FernetError, FernetKey};
pub use password::{verify_dummy, verify_password};
pub use token::{Claims, TokenError};
