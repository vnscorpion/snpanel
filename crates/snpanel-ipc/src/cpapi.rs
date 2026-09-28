//! What the panel tells CloudLinux about its accounts, through the CPAPI
//! "vendors" integration scripts (`/opt/cpvendor/etc/integration.ini`).
//!
//! The scripts never open the panel's database: they read a snapshot the
//! helper writes. The snapshot is readable by every account and mounted into
//! CageFS (`domains` runs as the customer), so it carries nothing secret, and
//! UNIX ids are not taken from here: the helper resolves them itself.

use serde::{Deserialize, Serialize};
use snpanel_core::{Domain, PanelUsername};

use crate::lve::LvePackageName;

/// Upper bounds, so a snapshot cannot grow without limit on its way to disk.
pub const MAX_USERS: usize = 20_000;
pub const MAX_DOMAINS: usize = 200_000;
pub const MAX_PACKAGES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpapiSnapshot {
    /// SNPanel's version, for `panel_info`.
    pub version: String,
    /// Where a customer signs in, for `panel_info`.
    pub login_url: String,
    pub admin_email: Option<String>,
    pub packages: Vec<LvePackageName>,
    pub users: Vec<CpapiUser>,
    pub domains: Vec<CpapiDomain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpapiUser {
    pub username: PanelUsername,
    pub email: Option<String>,
    pub package: Option<LvePackageName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpapiDomain {
    pub domain: Domain,
    pub owner: PanelUsername,
    /// Absolute: the site's root joined with its document root.
    pub document_root: String,
    pub is_main: bool,
    /// Dotted, as the panel stores it: "8.4".
    pub php_version: String,
}

impl CpapiSnapshot {
    /// What the types cannot say on their own.
    pub fn validate(&self) -> Result<(), String> {
        if self.users.len() > MAX_USERS
            || self.domains.len() > MAX_DOMAINS
            || self.packages.len() > MAX_PACKAGES
        {
            return Err("snapshot too large".to_string());
        }
        let short = |what: &str, s: &str| {
            if s.len() <= 512 && !s.chars().any(char::is_control) {
                Ok(())
            } else {
                Err(format!("invalid {what}"))
            }
        };
        short("version", &self.version)?;
        short("login_url", &self.login_url)?;
        if let Some(e) = &self.admin_email {
            short("admin_email", e)?;
        }
        for u in &self.users {
            if let Some(e) = &u.email {
                short("email", e)?;
            }
        }
        for d in &self.domains {
            let root = &d.document_root;
            let home = format!("/home/{}/", d.owner.as_str());
            if !root.starts_with(&home)
                || root.split('/').any(|c| c == ".." || c == ".")
                || root.contains("//")
            {
                return Err(format!(
                    "{}: document root outside the owner's home",
                    d.domain
                ));
            }
            short("document_root", root)?;
            let v = d.php_version.as_bytes();
            let dotted =
                v.len() == 3 && v[0].is_ascii_digit() && v[1] == b'.' && v[2].is_ascii_digit();
            if !dotted {
                return Err(format!("{}: invalid PHP version", d.domain));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> CpapiSnapshot {
        serde_json::from_value(serde_json::json!({
            "version": "1.1.0",
            "login_url": "https://panel.example.com:2222/",
            "admin_email": "admin@example.com",
            "packages": ["Starter"],
            "users": [{"username": "alice", "email": "alice@example.com", "package": "Starter"}],
            "domains": [{"domain": "alice.test", "owner": "alice",
                         "document_root": "/home/alice/alice.test/public_html",
                         "is_main": true, "php_version": "8.4"}],
        }))
        .unwrap()
    }

    #[test]
    fn a_normal_snapshot_is_accepted() {
        assert_eq!(snap().validate(), Ok(()));
    }

    #[test]
    fn document_roots_stay_in_the_owners_home() {
        for root in [
            "/home/bob/x/public_html",
            "/home/alice/../bob/public_html",
            "/etc/passwd",
            "/home/alice//x",
            "/home/alice/./x",
        ] {
            let mut s = snap();
            s.domains[0].document_root = root.to_string();
            assert!(s.validate().is_err(), "{root}");
        }
    }

    #[test]
    fn php_versions_are_dotted() {
        for v in ["84", "8.4.1", "x.y", ""] {
            let mut s = snap();
            s.domains[0].php_version = v.to_string();
            assert!(s.validate().is_err(), "{v}");
        }
    }

    #[test]
    fn root_and_flags_never_reach_the_snapshot() {
        let bad_user = r#"{"version":"1","login_url":"u","admin_email":null,"packages":[],
            "users":[{"username":"root","email":null,"package":null}],"domains":[]}"#;
        assert!(serde_json::from_str::<CpapiSnapshot>(bad_user).is_err());
        let bad_pkg = r#"{"version":"1","login_url":"u","admin_email":null,"packages":["-x"],
            "users":[],"domains":[]}"#;
        assert!(serde_json::from_str::<CpapiSnapshot>(bad_pkg).is_err());
    }
}
