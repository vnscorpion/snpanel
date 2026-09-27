//! PHP: which packages to ask for, and the `php.ini` the panel needs.
//!
//! Source: `install_php` and the `php_ext_packages` table behind it.
//!
//! The packages come from [`snpanel_osabi::Platform`], which has its own test
//! against the shell's list. What lives here is the rest: the check that the
//! default version is one of the installed ones, which packages to skip when
//! a repository does not carry them, and the seven `php.ini` settings the
//! panel raises.

use snpanel_core::PhpVersion;
use snpanel_osabi::Platform;

/// The packages to install for one PHP version, in the shell's order.
pub fn packages_for(platform: &dyn Platform, version: PhpVersion) -> Vec<String> {
    platform
        .php_extensions()
        .iter()
        .map(|ext| platform.php_package(version, ext))
        .collect()
}

/// What to do with the packages a repository does not carry.
///
/// Source: the `available_packages` / `missing_packages` split. A repository
/// that is missing one extension is normal — Sury and Remi do not carry the
/// same set for every version — and skipping it is right. A version where
/// **nothing** is available is not: that is a version the machine cannot
/// provide, and installing zero packages for it would leave the panel
/// offering a PHP that does not exist.
pub enum Availability {
    /// Install these, having skipped the ones listed.
    Install {
        available: Vec<String>,
        skipped: Vec<String>,
    },
    /// Stop: no package for this version at all.
    None(String),
}

pub fn split_available(
    version: PhpVersion,
    packages: &[String],
    exists: &dyn Fn(&str) -> bool,
) -> Availability {
    let mut available = Vec::new();
    let mut skipped = Vec::new();
    for package in packages {
        if exists(package) {
            available.push(package.clone());
        } else {
            skipped.push(package.clone());
        }
    }
    if available.is_empty() {
        return Availability::None(format!(
            "No package found for PHP {}. Remove {} from PHP_VERSIONS.",
            version.dotted(),
            version.dotted()
        ));
    }
    Availability::Install { available, skipped }
}

/// Source: `if [[ ! " ${PHP_VERSIONS} " =~ " ${PHP_DEFAULT} " ]]`.
///
/// A default that is not among the versions being installed is a panel whose
/// every unversioned site points at a PHP the machine does not have — and it
/// is caught before any package is fetched, because by then the mistake costs
/// an uninstall.
pub fn default_is_installed(versions: &[&str], default: &str) -> Result<(), String> {
    if versions.contains(&default) {
        return Ok(());
    }
    Err(format!(
        "PHP_DEFAULT={default} must be included in PHP_VERSIONS='{}'",
        versions.join(" ")
    ))
}

/// The seven settings the panel raises from their distribution defaults.
///
/// A customer uploading a 200 MB backup through the file manager reaches
/// `upload_max_filesize` first, and the message PHP gives for it is one the
/// panel cannot improve on — so the limits go up here rather than being
/// explained later.
/// `packages.sury.org`, which is where Debian's PHP comes from.
///
/// Source: `add_sury_repo`. Ubuntu uses Ondrej's PPA and EL uses Remi; this
/// is the third, and the only one the installer configures by hand, because
/// there is no `add-apt-repository` on Debian and the package that provides
/// it is not in the archive.
pub mod sury {
    /// The signing key, kept out of the trusted-keys directory so it signs
    /// this one repository and nothing else. A key in `trusted.gpg.d` would
    /// be accepted for every suite on the machine.
    pub const KEYRING: &str = "/usr/share/keyrings/sury-php.gpg";
    pub const KEYRING_MODE: u32 = 0o644;
    pub const KEY_URL: &str = "https://packages.sury.org/php/apt.gpg";

    pub const LIST: &str = "/etc/apt/sources.list.d/sury-php.list";
    pub const LIST_MODE: u32 = 0o644;

    /// The one line written into the sources list.
    ///
    /// `signed-by=` is what ties the key to this repository. Without it the
    /// key would have to go somewhere apt trusts globally, and a
    /// compromised mirror of any other suite could then be signed with it.
    pub fn sources_line(codename: &str) -> String {
        format!("deb [signed-by={KEYRING}] https://packages.sury.org/php/ {codename} main\n")
    }

    /// What to do about a repository that turned out to have no suite for
    /// this release.
    ///
    /// The rule, learnt the hard way: **leave nothing behind**. A sources
    /// list pointing at a suite that does not exist makes every later
    /// `apt-get update` on that machine fail — including the ones the panel
    /// runs to install a customer's PHP extension months afterwards. So the
    /// list is removed, the index is refreshed again so apt's own cache
    /// stops carrying the error, and only then does the installer stop.
    ///
    /// The second refresh is best-effort: if it fails too, the machine is no
    /// worse off than before the repository was added, and the message that
    /// matters is the one about the missing suite.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Rollback {
        pub remove: &'static str,
        pub refresh_again: bool,
        pub message: String,
    }

    pub fn rollback(codename: &str) -> Rollback {
        Rollback {
            remove: LIST,
            refresh_again: true,
            message: format!(
                "packages.sury.org has no suite for {codename}; \
                 the panel will use the PHP the distribution carries"
            ),
        }
    }

    /// `VERSION_CODENAME` out of `/etc/os-release`.
    ///
    /// An empty one is fatal rather than guessed at: a sources list with an
    /// empty suite is the exact state [`rollback`] exists to clean up, and
    /// writing one deliberately would be perverse.
    pub const NO_CODENAME: &str = "cannot determine the Debian codename for the PHP repository";

    pub fn codename_or_fail(os_release: &str) -> Result<&str, &'static str> {
        for line in os_release.lines() {
            if let Some(value) = line.trim().strip_prefix("VERSION_CODENAME=") {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                if !value.is_empty() {
                    return Ok(value);
                }
            }
        }
        Err(NO_CODENAME)
    }
}

pub const INI_SETTINGS: &[(&str, &str)] = &[
    ("upload_max_filesize", "1024M"),
    ("post_max_size", "1024M"),
    ("memory_limit", "1024M"),
    ("max_execution_time", "300"),
    ("max_input_time", "600"),
    ("max_input_vars", "10000"),
    ("max_file_uploads", "100"),
];

/// Rewrite a `php.ini`, setting each of [`INI_SETTINGS`].
///
/// Source: the seven `sed` expressions, whose pattern is
/// `^\s*;\?\s*<key>\s*=.*`. Two things about it are load-bearing:
///
/// * a **commented** default is rewritten into a live setting, so a
///   distribution that ships `;upload_max_filesize = 2M` ends up with the
///   panel's value rather than PHP's compiled-in one;
/// * whitespace is allowed **before** the semicolon as well as after, unlike
///   the pool rewrite next door — a distribution that indents its commented
///   defaults still gets them set.
pub fn php_ini(existing: &str) -> String {
    let mut out = String::with_capacity(existing.len());
    for line in existing.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        match INI_SETTINGS
            .iter()
            .find(|(key, _)| ini_setting_is(bare, key))
        {
            Some((key, value)) => {
                out.push_str(&format!("{key} = {value}"));
                if line.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

/// `^\s*;\?\s*<key>\s*=`.
fn ini_setting_is(line: &str, key: &str) -> bool {
    let rest = line.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix(';').unwrap_or(rest);
    let rest = rest.trim_start_matches([' ', '\t']);
    let Some(rest) = rest.strip_prefix(key) else {
        return false;
    };
    rest.trim_start_matches([' ', '\t']).starts_with('=')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/installer")
            .join(format!("{name}.expected"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the fixture {}: {e}", path.display()))
    }

    fn version() -> PhpVersion {
        PhpVersion::parse("8.4").expect("a version")
    }

    #[test]
    fn the_package_names_come_from_the_platform() {
        let debian: &dyn Platform = &snpanel_osabi::debian::Debian13;
        let packages = packages_for(debian, version());
        assert_eq!(packages.first().map(String::as_str), Some("php8.4-fpm"));
        assert!(packages.iter().any(|p| p == "php8.4-mysql"));

        let rhel: &dyn Platform = &snpanel_osabi::rhel::AlmaLinux10;
        let packages = packages_for(rhel, version());
        assert_eq!(packages.first().map(String::as_str), Some("php84-php-fpm"));
        // EL has `mysqlnd` and `pdo` where Debian has one `mysql`.
        assert!(packages.iter().any(|p| p == "php84-php-mysqlnd"));
        assert!(!packages.iter().any(|p| p == "php84-php-mysql"));
    }

    /// A repository missing one extension is normal. A version with **no**
    /// packages at all is not — that would install nothing and leave the
    /// panel offering a PHP the machine does not have.
    #[test]
    fn a_missing_extension_is_skipped_and_a_missing_version_stops() {
        let packages: Vec<String> = ["php8.4-fpm", "php8.4-imagick"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let Availability::Install { available, skipped } =
            split_available(version(), &packages, &|name| name != "php8.4-imagick")
        else {
            panic!("one package available should still install");
        };
        assert_eq!(available, ["php8.4-fpm"]);
        assert_eq!(skipped, ["php8.4-imagick"]);

        let Availability::None(why) = split_available(version(), &packages, &|_| false) else {
            panic!("no packages at all must not install nothing quietly");
        };
        assert!(why.contains("Remove 8.4 from PHP_VERSIONS"));
    }

    #[test]
    fn a_default_outside_the_installed_versions_is_refused() {
        assert!(default_is_installed(&["8.3", "8.4"], "8.4").is_ok());
        let Err(why) = default_is_installed(&["8.2", "8.3"], "8.4") else {
            panic!("a default nobody installs must be refused");
        };
        assert_eq!(
            why,
            "PHP_DEFAULT=8.4 must be included in PHP_VERSIONS='8.2 8.3'"
        );
    }

    /// Every platform's own default has to be one of its own versions, or
    /// the check above would fire on a stock install.
    #[test]
    fn every_platform_installs_the_version_it_defaults_to() {
        let platforms: [&dyn Platform; 4] = [
            &snpanel_osabi::debian::Ubuntu2404,
            &snpanel_osabi::debian::Debian13,
            &snpanel_osabi::debian::Debian12,
            &snpanel_osabi::rhel::AlmaLinux10,
        ];
        for platform in platforms {
            assert!(
                default_is_installed(platform.php_versions(), platform.php_default()).is_ok(),
                "{:?} defaults to a PHP it does not install",
                platform.distro()
            );
        }
    }

    #[test]
    fn the_ini_is_what_the_shell_writes() {
        let before = "[PHP]\n\
             engine = On\n\
             ;upload_max_filesize = 2M\n\
             post_max_size = 8M\n\
             \x20 ; memory_limit = 128M\n\
             max_execution_time = 30\n\
             ;   max_input_time = 60\n\
             ; max_input_vars = 1000\n\
             max_file_uploads = 20\n\
             date.timezone = UTC\n";
        assert_eq!(php_ini(before), fixture("php.ini"));
    }

    /// A commented default becomes a live setting. Leaving it commented
    /// would give PHP's compiled-in value, not the distribution's — which is
    /// smaller still.
    #[test]
    fn a_commented_default_is_turned_into_a_live_setting() {
        assert_eq!(
            php_ini(";upload_max_filesize = 2M\n"),
            "upload_max_filesize = 1024M\n"
        );
        // Space before the semicolon too, unlike the pool rewrite.
        assert_eq!(
            php_ini("  ; memory_limit = 128M\n"),
            "memory_limit = 1024M\n"
        );
    }

    #[test]
    fn what_the_panel_does_not_set_is_left_alone() {
        let before = "date.timezone = UTC\n;opcache.enable = 1\nengine = On\n";
        assert_eq!(php_ini(before), before);
    }

    /// The key has to match whole, or `post_max_size` would be claimed by
    /// something that merely starts with it.
    #[test]
    fn an_ini_key_does_not_claim_the_ones_it_prefixes() {
        assert!(ini_setting_is("memory_limit = 128M", "memory_limit"));
        assert!(!ini_setting_is("memory_limit_extra = 1", "memory_limit"));
        assert!(!ini_setting_is(
            "max_input_vars_extra = 1",
            "max_input_vars"
        ));
        // `max_input_time` and `max_input_vars` share a prefix and must not
        // be confused for one another.
        assert!(!ini_setting_is("max_input_vars = 1000", "max_input_time"));
        assert!(ini_setting_is("max_input_vars = 1000", "max_input_vars"));
    }

    /// The key signs this one repository and nothing else. In
    /// `trusted.gpg.d` it would be accepted for every suite on the machine.
    #[test]
    fn the_sury_key_is_tied_to_the_repository_that_uses_it() {
        assert!(sury::KEYRING.starts_with("/usr/share/keyrings/"));
        let line = sury::sources_line("trixie");
        assert!(line.contains(&format!("[signed-by={}]", sury::KEYRING)));
        assert_eq!(
            line,
            "deb [signed-by=/usr/share/keyrings/sury-php.gpg] \
             https://packages.sury.org/php/ trixie main\n"
        );
    }

    #[test]
    fn the_sources_line_carries_the_codename_it_was_given() {
        assert!(sury::sources_line("bookworm").contains(" bookworm main"));
        assert!(sury::sources_line("trixie").contains(" trixie main"));
    }

    /// A sources list pointing at a suite that does not exist makes every
    /// later `apt-get update` fail — including the ones the panel runs to
    /// install a customer's PHP extension months afterwards. Adding the
    /// repository is only safe because failing to use it cleans up.
    #[test]
    fn a_repository_with_no_suite_leaves_nothing_behind() {
        let rollback = sury::rollback("resolute");
        assert_eq!(rollback.remove, sury::LIST);
        assert!(
            rollback.refresh_again,
            "apt's cache still carries the error"
        );
        // Character for character the shell's, extracted from `install.sh`:
        // an operator who has seen this once should be able to search for
        // it.
        assert_eq!(
            rollback.message,
            "packages.sury.org has no suite for resolute; \
             the panel will use the PHP the distribution carries"
        );
    }

    /// Guessing a codename would write the exact sources list the rollback
    /// exists to clean up.
    #[test]
    fn a_missing_codename_stops_rather_than_being_guessed() {
        let real = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n\
                    ID=debian\n\
                    VERSION_CODENAME=trixie\n";
        assert_eq!(sury::codename_or_fail(real), Ok("trixie"));
        // Quoted, which some releases do.
        assert_eq!(
            sury::codename_or_fail("VERSION_CODENAME=\"bookworm\"\n"),
            Ok("bookworm")
        );
        // Absent, empty, and empty-quoted all stop.
        assert_eq!(
            sury::codename_or_fail("ID=debian\n"),
            Err(sury::NO_CODENAME)
        );
        assert_eq!(
            sury::codename_or_fail("VERSION_CODENAME=\n"),
            Err(sury::NO_CODENAME)
        );
        assert_eq!(
            sury::codename_or_fail("VERSION_CODENAME=\"\"\n"),
            Err(sury::NO_CODENAME)
        );
        // And a line that merely ends with the name is not the assignment.
        assert_eq!(
            sury::codename_or_fail("UBUNTU_CODENAME=noble\n"),
            Err(sury::NO_CODENAME)
        );
    }

    #[test]
    fn neither_the_key_nor_the_list_is_writable_by_anyone_else() {
        for mode in [sury::KEYRING_MODE, sury::LIST_MODE] {
            assert_eq!(mode & 0o022, 0, "{mode:o}");
        }
    }
}
