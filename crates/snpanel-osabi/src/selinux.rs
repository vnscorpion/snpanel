//! SELinux, which is a no-op everywhere except AlmaLinux 10.
//!
//! Plan §6.4 calls this the item most likely to be skipped and most likely to
//! break the install if it is. Sites live under
//! `/home/<user>/<domain>/public_html`, and under a default enforcing policy
//! nginx is simply not allowed to read that path.
//!
//! Only the policy *decisions* live here - which contexts, which booleans,
//! which ports. Actually running `semanage` is the helper's job, since it
//! needs root. Keeping the decisions separate means they can be tested on any
//! machine, including the Ubuntu box this was written on.

use std::path::Path;

use crate::platform::{Family, Platform};

/// File contexts for the site tree.
///
/// The regexes are `semanage fcontext` syntax, not shell globs.
pub const SITE_FCONTEXTS: &[(&str, &str)] = &[
    (
        r"/home/[^/]+/[^/]+/public_html(/.*)?",
        "httpd_sys_content_t",
    ),
    (
        r"/home/[^/]+/[^/]+/public_html/wp-content/uploads(/.*)?",
        "httpd_sys_rw_content_t",
    ),
];

/// Booleans that must be on for a normal WordPress site to work.
pub const REQUIRED_BOOLEANS: &[(&str, &str)] = &[
    ("httpd_can_network_connect_db", "PHP connects to MariaDB"),
    (
        "httpd_can_network_connect",
        "site calls external APIs, WP updates",
    ),
    (
        "httpd_execmem",
        "some PHP extensions need executable memory",
    ),
    ("httpd_enable_homedirs", "sites live under /home"),
    (
        "httpd_read_user_content",
        "nginx reads files owned by the panel user",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelinuxMode {
    Enforcing,
    Permissive,
    Disabled,
}

impl SelinuxMode {
    /// Parse the output of `getenforce`.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enforcing" => Self::Enforcing,
            "permissive" => Self::Permissive,
            _ => Self::Disabled,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Enforcing | Self::Permissive)
    }
}

/// What a platform needs done about SELinux.
pub trait SelinuxPolicy: Send + Sync {
    fn applies(&self) -> bool;
    /// argv for labelling one site directory after it is created or moved.
    fn restorecon_argv(&self, path: &Path) -> Vec<String>;
    /// argv for registering the panel's non-standard port.
    fn port_argv(&self, port: u16) -> Vec<String>;
    fn fcontext_argv(&self) -> Vec<Vec<String>>;
    fn boolean_argv(&self) -> Vec<Vec<String>>;
}

/// The Debian family: nothing to do.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSelinux;

impl SelinuxPolicy for NoSelinux {
    fn applies(&self) -> bool {
        false
    }
    fn restorecon_argv(&self, _path: &Path) -> Vec<String> {
        Vec::new()
    }
    fn port_argv(&self, _port: u16) -> Vec<String> {
        Vec::new()
    }
    fn fcontext_argv(&self) -> Vec<Vec<String>> {
        Vec::new()
    }
    fn boolean_argv(&self) -> Vec<Vec<String>> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RhelSelinux;

impl SelinuxPolicy for RhelSelinux {
    fn applies(&self) -> bool {
        true
    }

    fn restorecon_argv(&self, path: &Path) -> Vec<String> {
        vec![
            "restorecon".into(),
            "-R".into(),
            path.to_string_lossy().into_owned(),
        ]
    }

    fn port_argv(&self, port: u16) -> Vec<String> {
        vec![
            "semanage".into(),
            "port".into(),
            "-a".into(),
            "-t".into(),
            "http_port_t".into(),
            "-p".into(),
            "tcp".into(),
            port.to_string(),
        ]
    }

    fn fcontext_argv(&self) -> Vec<Vec<String>> {
        SITE_FCONTEXTS
            .iter()
            .map(|(pattern, ty)| {
                vec![
                    "semanage".into(),
                    "fcontext".into(),
                    "-a".into(),
                    "-t".into(),
                    (*ty).into(),
                    (*pattern).into(),
                ]
            })
            .collect()
    }

    fn boolean_argv(&self) -> Vec<Vec<String>> {
        REQUIRED_BOOLEANS
            .iter()
            .map(|(name, _why)| vec!["setsebool".into(), "-P".into(), (*name).into(), "on".into()])
            .collect()
    }
}

/// Pick the policy for a platform.
pub fn policy_for(platform: &dyn Platform) -> Box<dyn SelinuxPolicy> {
    match platform.family() {
        Family::Rhel => Box::new(RhelSelinux),
        Family::Debian => Box::new(NoSelinux),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debian::Ubuntu2404;
    use crate::rhel::AlmaLinux10;

    #[test]
    fn the_debian_family_does_nothing() {
        let p = policy_for(&Ubuntu2404);
        assert!(!p.applies());
        assert!(p.fcontext_argv().is_empty());
        assert!(p.boolean_argv().is_empty());
        assert!(p.restorecon_argv(Path::new("/home/u/d")).is_empty());
    }

    #[test]
    fn alma_labels_the_site_tree() {
        let p = policy_for(&AlmaLinux10);
        assert!(p.applies());
        let argv = p.restorecon_argv(Path::new("/home/bp_site/example.com"));
        assert_eq!(argv, vec!["restorecon", "-R", "/home/bp_site/example.com"]);
    }

    #[test]
    fn the_panel_port_is_registered_for_http() {
        let argv = RhelSelinux.port_argv(2222);
        assert_eq!(argv.last().unwrap(), "2222");
        assert!(argv.contains(&"http_port_t".to_string()));
    }

    #[test]
    fn uploads_get_a_writable_context_and_the_rest_do_not() {
        let contexts: Vec<_> = SITE_FCONTEXTS.iter().collect();
        let uploads = contexts
            .iter()
            .find(|(p, _)| p.contains("uploads"))
            .expect("wp-content/uploads must be writable");
        assert_eq!(uploads.1, "httpd_sys_rw_content_t");
        let public = contexts
            .iter()
            .find(|(p, _)| !p.contains("uploads"))
            .expect("public_html must be readable");
        assert_eq!(public.1, "httpd_sys_content_t");
    }

    #[test]
    fn every_boolean_is_set_persistently() {
        // Without -P the setting is lost on reboot, which turns into a site
        // that works until the box restarts.
        for argv in RhelSelinux.boolean_argv() {
            assert_eq!(argv[0], "setsebool");
            assert_eq!(argv[1], "-P");
            assert_eq!(argv.last().unwrap(), "on");
        }
    }

    #[test]
    fn database_connectivity_is_among_the_booleans() {
        let names: Vec<&str> = REQUIRED_BOOLEANS.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"httpd_can_network_connect_db"));
        assert!(names.contains(&"httpd_enable_homedirs"));
    }

    #[test]
    fn getenforce_output_parses() {
        assert_eq!(SelinuxMode::parse("Enforcing\n"), SelinuxMode::Enforcing);
        assert_eq!(SelinuxMode::parse("Permissive"), SelinuxMode::Permissive);
        assert_eq!(SelinuxMode::parse("Disabled"), SelinuxMode::Disabled);
        assert!(SelinuxMode::parse("Enforcing").is_active());
        assert!(!SelinuxMode::parse("Disabled").is_active());
    }
}
