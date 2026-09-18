//! The error type every crate shares, and how it maps onto an HTTP status.
//!
//! The mapping lives here rather than in `snpanel-api` so the helper and the
//! CLI report the same thing the API would, and so a new variant cannot be
//! added without deciding what the browser sees.

use crate::config::ConfigError;
use crate::crypto::fernet::FernetError;
use crate::crypto::token::TokenError;
use crate::types::ParseError;

#[derive(Debug, thiserror::Error)]
pub enum SnpanelError {
    #[error("{0}")]
    Invalid(String),

    #[error("not found")]
    NotFound,

    #[error("not authenticated")]
    Unauthenticated,

    #[error("not permitted")]
    Forbidden,

    #[error("{0} already exists")]
    Conflict(String),

    #[error("too many requests")]
    RateLimited,

    /// A value could not be parsed into its type (NT4).
    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Token(#[from] TokenError),

    #[error("could not read a stored secret: {0}")]
    Secret(#[from] FernetError),

    #[error("{operation} failed: {message}")]
    Helper { operation: String, message: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Anything unexpected. Rendered to the client as a bare 500 with no
    /// detail - the detail goes to the journal.
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type Result<T, E = SnpanelError> = std::result::Result<T, E>;

impl SnpanelError {
    /// The HTTP status this error becomes.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Invalid(_) | Self::Parse(_) => 400,
            Self::Unauthenticated | Self::Token(_) => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict(_) => 409,
            Self::RateLimited => 429,
            Self::Config(_)
            | Self::Secret(_)
            | Self::Helper { .. }
            | Self::Io(_)
            | Self::Internal(_) => 500,
        }
    }

    /// What the client is allowed to read.
    ///
    /// A 500 says nothing: leaking a path, a helper's stderr or a decryption
    /// failure to the browser tells an attacker about the box. The real text
    /// is logged.
    pub fn client_message(&self) -> String {
        if self.status_code() >= 500 {
            "Internal server error".to_string()
        } else {
            self.to_string()
        }
    }

    /// True when the full text belongs in the journal rather than the response.
    pub fn should_log_detail(&self) -> bool {
        self.status_code() >= 500
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_the_fastapi_behaviour() {
        assert_eq!(SnpanelError::NotFound.status_code(), 404);
        assert_eq!(SnpanelError::Unauthenticated.status_code(), 401);
        assert_eq!(SnpanelError::Forbidden.status_code(), 403);
        assert_eq!(SnpanelError::RateLimited.status_code(), 429);
        assert_eq!(SnpanelError::Conflict("website".into()).status_code(), 409);
        assert_eq!(
            SnpanelError::Invalid("bad domain".into()).status_code(),
            400
        );
    }

    #[test]
    fn a_parse_failure_is_a_400_not_a_500() {
        let err: SnpanelError = ParseError::Domain("nope".into()).into();
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn server_errors_tell_the_client_nothing() {
        let err = SnpanelError::Helper {
            operation: "nginx-reload".into(),
            message: "/etc/nginx/conf.d/example.com.conf: permission denied".into(),
        };
        assert_eq!(err.status_code(), 500);
        assert_eq!(err.client_message(), "Internal server error");
        assert!(err.should_log_detail());
        // ...but the detail is still there for the journal.
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn a_decryption_failure_never_reaches_the_browser() {
        let err: SnpanelError = FernetError::BadSignature.into();
        assert_eq!(err.client_message(), "Internal server error");
    }

    #[test]
    fn client_errors_keep_their_message() {
        let err = SnpanelError::Invalid("domain is already in use".into());
        assert_eq!(err.client_message(), "domain is already in use");
        assert!(!err.should_log_detail());
    }
}
