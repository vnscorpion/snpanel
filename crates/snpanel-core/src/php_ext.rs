//! The PHP extensions the panel installs and removes, one PHP version at a
//! time.
//!
//! Not in the Python. A catalogue rather than a free package name: the
//! helper installs as root, and "the extension called `x`" must never be a
//! way to name any package at all. Each entry says what `php -m` calls it
//! and what it is packaged as on each family - Sury and ondrej build
//! `php8.3-redis`, Remi builds `php83-php-pecl-redis6`: the names are not
//! one scheme with another prefix.
//!
//! The first twelve are what the panel installs with every PHP version (the
//! helper's `PHP_EXTENSIONS` and `REMI_PHP_PACKAGES`); the application
//! templates count on them, so they are installed again when missing but
//! never removed from here.

use crate::types::PhpVersion;

/// One extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhpExtension {
    /// Its name in the panel - in a helper verb, on the page: the module's
    /// own where there is one.
    pub key: &'static str,
    /// What `php -m` lists for it, lowercase. One package can bring several.
    pub modules: &'static [&'static str],
    /// `php{v}-{this}` on Debian and Ubuntu.
    pub debian: &'static str,
    /// `php{XY}-php-{this}` on EL (Remi); `None` where Remi builds it into
    /// `php-common`, which comes with every version and is never removed.
    pub remi: Option<&'static str>,
    /// Installed with every PHP version, and not removed by the panel.
    pub base: bool,
}

const fn ext(
    key: &'static str,
    modules: &'static [&'static str],
    debian: &'static str,
    remi: Option<&'static str>,
    base: bool,
) -> PhpExtension {
    PhpExtension {
        key,
        modules,
        debian,
        remi,
        base,
    }
}

/// Every extension the panel offers, the base set first.
pub const PHP_EXTENSIONS: &[PhpExtension] = &[
    ext(
        "mysql",
        &["mysqli", "pdo_mysql"],
        "mysql",
        Some("mysqlnd"),
        true,
    ),
    ext(
        "sqlite3",
        &["sqlite3", "pdo_sqlite"],
        "sqlite3",
        Some("pdo"),
        true,
    ),
    ext("curl", &["curl"], "curl", None, true),
    ext("gd", &["gd"], "gd", Some("gd"), true),
    ext(
        "mbstring",
        &["mbstring"],
        "mbstring",
        Some("mbstring"),
        true,
    ),
    ext(
        "xml",
        &["dom", "simplexml", "xml", "xmlreader", "xmlwriter", "xsl"],
        "xml",
        Some("xml"),
        true,
    ),
    ext("zip", &["zip"], "zip", Some("pecl-zip"), true),
    ext(
        "opcache",
        &["zend opcache"],
        "opcache",
        Some("opcache"),
        true,
    ),
    ext("intl", &["intl"], "intl", Some("intl"), true),
    ext("bcmath", &["bcmath"], "bcmath", Some("bcmath"), true),
    ext("redis", &["redis"], "redis", Some("pecl-redis6"), true),
    ext(
        "imagick",
        &["imagick"],
        "imagick",
        Some("pecl-imagick-im7"),
        true,
    ),
    // What a customer's application may ask for.
    ext("soap", &["soap"], "soap", Some("soap"), false),
    ext(
        "memcached",
        &["memcached"],
        "memcached",
        Some("pecl-memcached"),
        false,
    ),
    ext("apcu", &["apcu"], "apcu", Some("pecl-apcu"), false),
    ext(
        "mongodb",
        &["mongodb"],
        "mongodb",
        Some("pecl-mongodb"),
        false,
    ),
    ext(
        "igbinary",
        &["igbinary"],
        "igbinary",
        Some("pecl-igbinary"),
        false,
    ),
    ext(
        "msgpack",
        &["msgpack"],
        "msgpack",
        Some("pecl-msgpack"),
        false,
    ),
    ext("xdebug", &["xdebug"], "xdebug", Some("pecl-xdebug3"), false),
    ext("gmp", &["gmp"], "gmp", Some("gmp"), false),
    ext("ldap", &["ldap"], "ldap", Some("ldap"), false),
    ext("imap", &["imap"], "imap", Some("imap"), false),
    ext(
        "pgsql",
        &["pgsql", "pdo_pgsql"],
        "pgsql",
        Some("pgsql"),
        false,
    ),
    ext("tidy", &["tidy"], "tidy", Some("tidy"), false),
    ext("bz2", &["bz2"], "bz2", None, false),
    ext("yaml", &["yaml"], "yaml", Some("pecl-yaml"), false),
    ext("ssh2", &["ssh2"], "ssh2", Some("pecl-ssh2"), false),
    ext(
        "mailparse",
        &["mailparse"],
        "mailparse",
        Some("pecl-mailparse"),
        false,
    ),
    ext(
        "uploadprogress",
        &["uploadprogress"],
        "uploadprogress",
        Some("pecl-uploadprogress"),
        false,
    ),
];

/// The extension called `key`, if the panel offers one.
pub fn find(key: &str) -> Option<&'static PhpExtension> {
    PHP_EXTENSIONS.iter().find(|e| e.key == key)
}

impl PhpExtension {
    /// The Debian and Ubuntu package for `version`.
    pub fn debian_package(&self, version: PhpVersion) -> String {
        format!("php{}-{}", version.dotted(), self.debian)
    }

    /// The Remi package for `version`, or `None` where it is part of
    /// `php-common`.
    pub fn remi_package(&self, version: PhpVersion) -> Option<String> {
        let name = self.remi?;
        // IMAP left PHP's own tree in 8.4; Remi builds it from PECL since.
        let name = if self.key == "imap" && version.at_least(8, 4) {
            "pecl-imap"
        } else {
            name
        };
        Some(format!("php{}-php-{name}", version.compact()))
    }

    /// Whether `loaded` - what `php -m` listed - has every module of this
    /// extension.
    pub fn loaded_in(&self, loaded: &[String]) -> bool {
        self.modules.iter().all(|m| loaded.iter().any(|l| l == m))
    }
}

/// What `php -m` prints, as lowercase module names: the lines under
/// `[PHP Modules]` and `[Zend Modules]`, headings and blank lines left out.
/// Zend OPcache is listed in both when it is loaded; it is here once.
pub fn parse_modules(output: &str) -> Vec<String> {
    let mut modules: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('['))
        .map(str::to_ascii_lowercase)
        .collect();
    modules.sort();
    modules.dedup();
    modules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_one_word_and_unique() {
        let mut keys: Vec<&str> = PHP_EXTENSIONS.iter().map(|e| e.key).collect();
        for key in &keys {
            assert!(
                !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{key}"
            );
        }
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), PHP_EXTENSIONS.len());
        assert!(find("redis").is_some());
        assert!(find("../../etc").is_none());
        assert!(find("redis; rm -rf /").is_none());
    }

    #[test]
    fn the_packages_are_each_familys_own_names() {
        let v83 = PhpVersion::parse("8.3").unwrap();
        let v84 = PhpVersion::parse("8.4").unwrap();
        let redis = find("redis").unwrap();
        assert_eq!(redis.debian_package(v83), "php8.3-redis");
        assert_eq!(
            redis.remi_package(v83).as_deref(),
            Some("php83-php-pecl-redis6")
        );
        let imap = find("imap").unwrap();
        assert_eq!(imap.remi_package(v83).as_deref(), Some("php83-php-imap"));
        assert_eq!(
            imap.remi_package(v84).as_deref(),
            Some("php84-php-pecl-imap")
        );
        assert_eq!(find("curl").unwrap().remi_package(v83), None);
        assert_eq!(find("mysql").unwrap().debian_package(v84), "php8.4-mysql");
    }

    #[test]
    fn the_base_set_is_what_every_php_version_is_installed_with() {
        let base: Vec<&str> = PHP_EXTENSIONS
            .iter()
            .filter(|e| e.base)
            .map(|e| e.debian)
            .collect();
        assert_eq!(
            base,
            [
                "mysql", "sqlite3", "curl", "gd", "mbstring", "xml", "zip", "opcache", "intl",
                "bcmath", "redis", "imagick"
            ]
        );
        // And nothing base comes after the first that is not.
        let first_optional = PHP_EXTENSIONS.iter().position(|e| !e.base).unwrap();
        assert!(PHP_EXTENSIONS[first_optional..].iter().all(|e| !e.base));
    }

    #[test]
    fn php_m_is_read_as_lowercase_modules() {
        let out = "[PHP Modules]\nbcmath\nCore\nmysqli\nPDO\npdo_mysql\nZend OPcache\n\n[Zend Modules]\nZend OPcache\n\n";
        let loaded = parse_modules(out);
        assert_eq!(
            loaded,
            [
                "bcmath",
                "core",
                "mysqli",
                "pdo",
                "pdo_mysql",
                "zend opcache"
            ]
        );
        assert!(find("mysql").unwrap().loaded_in(&loaded));
        assert!(find("opcache").unwrap().loaded_in(&loaded));
        assert!(!find("redis").unwrap().loaded_in(&loaded));
    }
}
