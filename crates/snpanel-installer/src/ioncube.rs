//! The ionCube Loader.
//!
//! Source: `install_ioncube_loader`.
//!
//! This phase is unusual in the installer, and the shape is the point: it is
//! the only one where **almost every failure is a skip**. ionCube decodes
//! commercially encoded PHP; nothing in the panel needs it, and a customer
//! who does not run encoded code will never notice it is absent. By the time
//! this phase runs, nginx, PHP and the database are already configured — so
//! ending the install over a 29 MB download from a third-party CDN would
//! throw away work that succeeded, to punish the absence of something
//! optional.
//!
//! There is exactly one fatal, and it is not an acquisition problem: the
//! loader was installed, `zend_extension=` lines were written, and PHP then
//! refused to load it. That state is worse than not having ionCube, because
//! **every** PHP invocation on the box prints a startup error afterwards —
//! including the panel's own probes. So the ini files are removed first and
//! the install stops with the reason, rather than leaving a PHP that
//! complains on every run.

use std::path::{Path, PathBuf};

/// Where the loader is installed, and the mode of the directory.
pub const TARGET_DIR: &str = "/usr/local/ioncube";
pub const TARGET_DIR_MODE: u32 = 0o755;
/// The loader itself. Read by PHP, so world-readable; it is vendor code and
/// holds no secret.
pub const LOADER_MODE: u32 = 0o644;

/// The drop-in written into each of the platform's PHP conf directories.
///
/// The `00-` prefix is load order: the loader is a `zend_extension` and has
/// to be in place before anything that might be encoded.
pub const INI_NAME: &str = "00-ioncube.ini";
pub const INI_MODE: u32 = 0o644;

/// Three attempts, and the curl budget for each.
///
/// `--speed-limit`/`--speed-time` abort a transfer that has stalled rather
/// than spending the whole budget on a connection delivering a few KB/s.
/// Without them, three attempts at 300s each is fifteen minutes of an
/// install stopped on a component that is optional.
pub const ATTEMPTS: u32 = 3;
pub const CONNECT_TIMEOUT_SECONDS: u32 = 10;
pub const MAX_TIME_SECONDS: u32 = 300;
pub const SPEED_LIMIT_BYTES: u32 = 10240;
pub const SPEED_TIME_SECONDS: u32 = 30;
/// Between attempts.
pub const RETRY_PAUSE_SECONDS: u32 = 5;

const X86_64_ARCHIVE: &str =
    "https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz";

/// The archive for one architecture, or `None` where ionCube publishes no
/// loader.
///
/// Both spellings are matched because the installer reads the architecture
/// from `dpkg --print-architecture` where there is a dpkg and from `uname
/// -m` where there is not, and those two disagree about the name of the same
/// machine.
pub fn archive_url(arch: &str) -> Option<&'static str> {
    match arch {
        "amd64" | "x86_64" => Some(X86_64_ARCHIVE),
        _ => None,
    }
}

/// The loader for one PHP version, as named inside the archive.
pub fn loader_file_name(version: &str) -> String {
    format!("ioncube_loader_lin_{version}.so")
}

/// Where that loader ends up.
pub fn installed_loader(version: &str) -> PathBuf {
    Path::new(TARGET_DIR).join(loader_file_name(version))
}

/// The whole contents of the drop-in.
pub fn ini_contents(loader: &Path) -> String {
    format!("zend_extension={}\n", loader.display())
}

/// Why the loader was not installed. Every one of these is survivable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// ionCube publishes loaders for x86-64 only.
    UnsupportedArchitecture(String),
    /// The CDN did not deliver, after [`ATTEMPTS`] tries.
    DownloadFailed(u32),
    /// Something arrived, but it was not a tarball.
    ArchiveUnreadable,
    /// The archive has no loader built for this PHP.
    NoLoaderForVersion(String),
}

impl Skip {
    /// The line the shell prints. Kept word for word: these are what an
    /// operator grepping an install log has seen before.
    pub fn message(&self) -> String {
        match self {
            Self::UnsupportedArchitecture(arch) => {
                format!("Skipping ionCube Loader: unsupported architecture {arch}")
            }
            Self::DownloadFailed(attempts) => {
                format!("Skipping ionCube Loader: download failed after {attempts} attempts")
            }
            Self::ArchiveUnreadable => {
                "Skipping ionCube Loader: the downloaded archive could not be unpacked".to_string()
            }
            Self::NoLoaderForVersion(version) => {
                format!("Skipping ionCube Loader: no loader found for PHP {version}")
            }
        }
    }
}

/// How the phase ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The loader is installed and PHP loaded it.
    Enabled(String),
    /// Optional support is absent and the install carries on.
    Skipped(Skip),
    /// The loader installed and PHP would not load it.
    ///
    /// The only fatal outcome, and the caller has to have removed the ini
    /// files before constructing it — see [`Outcome::is_fatal`].
    WouldNotLoad(String),
}

impl Outcome {
    /// Whether the install stops here.
    ///
    /// One variant out of the six reasons this phase can end early. That
    /// ratio is the design, not an oversight: acquiring optional vendor code
    /// is allowed to fail, and leaving PHP in a state where it errors on
    /// every startup is not.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::WouldNotLoad(_))
    }

    pub fn message(&self) -> String {
        match self {
            Self::Enabled(version) => format!("ionCube Loader enabled for PHP {version}"),
            Self::Skipped(skip) => skip.message(),
            Self::WouldNotLoad(version) => {
                format!("ionCube Loader failed to load for PHP {version}")
            }
        }
    }
}

/// Whether `php -v` says the loader is in.
///
/// Case-insensitive, matching the shell's `grep -qi`: the banner spells it
/// `ionCube` and a future version spelling it differently should still
/// count as loaded rather than tear a working install down.
pub fn banner_shows_loader(php_v: &str) -> bool {
    let needle = "ioncube";
    php_v
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// The curl invocation for one attempt, as argv. Never a shell string.
pub fn curl_argv(url: &str, archive: &Path) -> Vec<String> {
    [
        "curl",
        "-fsSL",
        "--connect-timeout",
        &CONNECT_TIMEOUT_SECONDS.to_string(),
        "--max-time",
        &MAX_TIME_SECONDS.to_string(),
        "--speed-limit",
        &SPEED_LIMIT_BYTES.to_string(),
        "--speed-time",
        &SPEED_TIME_SECONDS.to_string(),
        url,
        "-o",
        &archive.to_string_lossy(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_spellings_of_the_one_supported_architecture_resolve() {
        // `dpkg --print-architecture` and `uname -m` name the same machine
        // differently, and the installer reads whichever is available.
        assert_eq!(archive_url("amd64"), archive_url("x86_64"));
        assert!(archive_url("amd64").unwrap().ends_with("_x86-64.tar.gz"));
    }

    #[test]
    fn every_other_architecture_has_no_loader() {
        for arch in ["arm64", "aarch64", "armhf", "riscv64", "i386", "s390x", ""] {
            assert_eq!(archive_url(arch), None, "{arch}");
        }
    }

    #[test]
    fn the_loader_is_named_for_the_php_it_belongs_to() {
        assert_eq!(loader_file_name("8.4"), "ioncube_loader_lin_8.4.so");
        assert_eq!(
            installed_loader("8.3").to_string_lossy(),
            "/usr/local/ioncube/ioncube_loader_lin_8.3.so"
        );
    }

    /// The drop-in points at the file that was actually installed, not at
    /// the one inside the archive — which is in a temporary directory that
    /// is removed before PHP ever starts.
    #[test]
    fn the_ini_points_at_the_installed_path() {
        let loader = installed_loader("8.4");
        assert_eq!(
            ini_contents(&loader),
            "zend_extension=/usr/local/ioncube/ioncube_loader_lin_8.4.so\n"
        );
        assert!(ini_contents(&loader).starts_with("zend_extension="));
        assert!(ini_contents(&loader).ends_with('\n'));
    }

    /// The shape of this phase: acquiring optional vendor code may fail, and
    /// only a PHP left erroring on every startup stops the install.
    #[test]
    fn every_acquisition_failure_is_survivable_and_only_a_broken_php_is_not() {
        let survivable = [
            Skip::UnsupportedArchitecture("aarch64".into()),
            Skip::DownloadFailed(ATTEMPTS),
            Skip::ArchiveUnreadable,
            Skip::NoLoaderForVersion("8.4".into()),
        ];
        for skip in survivable {
            let outcome = Outcome::Skipped(skip);
            assert!(!outcome.is_fatal(), "{outcome:?}");
            assert!(outcome.message().starts_with("Skipping ionCube Loader: "));
        }
        assert!(!Outcome::Enabled("8.4".into()).is_fatal());
        assert!(Outcome::WouldNotLoad("8.4".into()).is_fatal());
    }

    #[test]
    fn the_messages_are_the_shells() {
        assert_eq!(
            Skip::UnsupportedArchitecture("aarch64".into()).message(),
            "Skipping ionCube Loader: unsupported architecture aarch64"
        );
        assert_eq!(
            Skip::DownloadFailed(3).message(),
            "Skipping ionCube Loader: download failed after 3 attempts"
        );
        assert_eq!(
            Skip::ArchiveUnreadable.message(),
            "Skipping ionCube Loader: the downloaded archive could not be unpacked"
        );
        assert_eq!(
            Skip::NoLoaderForVersion("8.4".into()).message(),
            "Skipping ionCube Loader: no loader found for PHP 8.4"
        );
        assert_eq!(
            Outcome::Enabled("8.4".into()).message(),
            "ionCube Loader enabled for PHP 8.4"
        );
        assert_eq!(
            Outcome::WouldNotLoad("8.4".into()).message(),
            "ionCube Loader failed to load for PHP 8.4"
        );
    }

    /// `grep -qi`: the banner's own spelling is `ionCube`, and a version
    /// that spelt it differently should still count as loaded rather than
    /// tear down an install that is working.
    #[test]
    fn the_banner_check_ignores_case_and_needs_the_whole_word() {
        let real = "PHP 8.4.1 (cli) (built: Dec 17 2024)\n\
                        with the ionCube PHP Loader (enabled) + ionCube24,\n\
                    Zend Engine v4.4.1";
        assert!(banner_shows_loader(real));
        assert!(banner_shows_loader("IONCUBE"));
        assert!(banner_shows_loader("ioncube"));
        // Without the loader, the same banner says nothing of the sort.
        assert!(!banner_shows_loader(
            "PHP 8.4.1 (cli)\nwith Zend OPcache v8.4.1"
        ));
        assert!(!banner_shows_loader("ioncub"));
        assert!(!banner_shows_loader(""));
    }

    /// The two flags that stop a stalled CDN from costing the whole budget.
    /// Losing them is not a test failure anywhere else — the download still
    /// works — so it is asserted here.
    #[test]
    fn a_stalled_transfer_is_abandoned_rather_than_waited_out() {
        let argv = curl_argv(archive_url("amd64").unwrap(), Path::new("/tmp/x.tar.gz"));
        for flag in [
            "--speed-limit",
            "--speed-time",
            "--connect-timeout",
            "--max-time",
        ] {
            assert!(
                argv.iter().any(|a| a == flag),
                "{flag} missing from {argv:?}"
            );
        }
        // A stalled attempt ends well inside the ceiling, so three of them
        // cannot add up to a quarter of an hour.
        const { assert!(SPEED_TIME_SECONDS < MAX_TIME_SECONDS) };
        const { assert!(ATTEMPTS * (SPEED_TIME_SECONDS + RETRY_PAUSE_SECONDS) < MAX_TIME_SECONDS) };
        // And nothing is passed through a shell.
        assert_eq!(argv[0], "curl");
        assert!(argv.iter().all(|a| !a.contains(' ')));
    }
}
