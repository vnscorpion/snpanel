//! `php-ext-install <version> <extension>` and `php-ext-remove <version>
//! <extension>` - one extension of the panel's catalogue for one PHP
//! version.
//!
//! Not in the Python. The extension is a key of `snpanel_core::php_ext`,
//! checked again here whatever the argv parser did: over the socket a
//! request is JSON, and the package installed as root is always the
//! catalogue's name for this machine's family, never the caller's.
//!
//! Installing checks the package is in the machine's sources first, so a
//! version the repository does not build it for is a sentence rather than
//! apt's error; then installs it, restarts that version's FPM and asks PHP -
//! with FPM's own ini files - whether the module loads. If FPM will not start
//! with it, the package goes again and FPM is started without it: a
//! half-working extension is not worth every site on that PHP being down.
//!
//! Removing is refused for the base set, and whenever the package manager
//! would take another package with it - `igbinary` is what `redis` is
//! built on - which is found by asking it to pretend first.

use snpanel_core::php_ext::{self, PhpExtension};
use snpanel_core::PhpVersion;
use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::Family;

use super::packages::{apt_installable, dpkg_installed, family, install_packages, update_index};
use crate::exec;

fn refuse(message: impl Into<String>) -> HelperResponse {
    HelperResponse::failed(HelperErrorKind::BadRequest, message)
}

fn broke(message: impl Into<String>) -> HelperResponse {
    HelperResponse::failed(HelperErrorKind::CommandFailed, message)
}

/// The last lines of what a command said, for a message.
fn tail(output: &exec::Output) -> String {
    let text = format!("{}\n{}", output.stdout, output.stderr);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(6)..].join("\n")
}

fn platform() -> Option<Box<dyn snpanel_osabi::Platform>> {
    snpanel_osabi::detect().ok()
}

fn service(version: PhpVersion) -> String {
    platform()
        .map(|p| p.php_service(version))
        .unwrap_or_else(|| format!("php{}-fpm", version.dotted()))
}

/// Whether the version is installed: its FPM configuration is there - the
/// same test `list_installed_php` makes, through the Remi shim on EL.
fn php_installed(version: PhpVersion) -> bool {
    std::path::Path::new(&format!("/etc/php/{}/fpm/php-fpm.conf", version.dotted())).exists()
}

/// What PHP loads with FPM's own ini files, as `php -m` lists it.
pub fn loaded_modules(version: PhpVersion) -> Vec<String> {
    let Some(platform) = platform() else {
        return Vec::new();
    };
    let binary = platform.php_binary(version);
    let ini = platform.php_ini_path(version);
    let Some(conf_d) = ini.parent().map(|d| d.join("conf.d")) else {
        return Vec::new();
    };
    let (Some(binary), Some(ini), Some(conf_d)) = (binary.to_str(), ini.to_str(), conf_d.to_str())
    else {
        return Vec::new();
    };
    match exec::run_with_env(&[binary, "-c", ini, "-m"], &[("PHP_INI_SCAN_DIR", conf_d)]) {
        Ok(o) if o.ok() => php_ext::parse_modules(&o.stdout),
        _ => Vec::new(),
    }
}

/// The package that is this extension on this machine, or `None` where it
/// comes with PHP itself (Remi's `php-common`).
fn package(ext: &PhpExtension, version: PhpVersion) -> Option<String> {
    match family() {
        Family::Rhel => ext.remi_package(version),
        _ => Some(ext.debian_package(version)),
    }
}

fn installed(name: &str) -> bool {
    match family() {
        Family::Rhel => matches!(exec::run(&["rpm", "-q", "--quiet", name]), Ok(o) if o.ok()),
        _ => dpkg_installed(&[name]),
    }
}

fn remove_package(name: &str) -> std::io::Result<exec::Output> {
    match family() {
        Family::Rhel => exec::run(&["dnf", "-y", "remove", name]),
        _ => exec::run_with_env(
            &["apt-get", "remove", "-y", name],
            &[("DEBIAN_FRONTEND", "noninteractive")],
        ),
    }
}

/// The packages removing `name` would take with it, the package manager
/// pretending. `Err` when it cannot say.
fn removed_with(name: &str) -> Result<Vec<String>, String> {
    match family() {
        Family::Rhel => {
            let o = exec::run(&["rpm", "-e", "--test", name]).map_err(|e| e.to_string())?;
            if o.ok() {
                return Ok(Vec::new());
            }
            Ok(rpm_dependents(&o.stderr))
        }
        _ => {
            let o = exec::run(&["apt-get", "-s", "remove", name]).map_err(|e| e.to_string())?;
            if !o.ok() {
                return Err(tail(&o));
            }
            Ok(apt_removals(&o.stdout)
                .into_iter()
                .filter(|p| p != name)
                .collect())
        }
    }
}

/// `apt-get -s remove`'s `Remv <package> [<version>]` lines, by package.
pub fn apt_removals(simulation: &str) -> Vec<String> {
    simulation
        .lines()
        .filter_map(|l| l.strip_prefix("Remv "))
        .filter_map(|l| l.split_whitespace().next())
        .map(|p| p.split(':').next().unwrap_or(p).to_string())
        .collect()
}

/// `rpm -e --test`'s `\t<capability> is needed by (installed) <package>`
/// lines, by package.
pub fn rpm_dependents(stderr: &str) -> Vec<String> {
    let mut out: Vec<String> = stderr
        .lines()
        // `<capability> is needed by (installed) <package>`: what follows the
        // marker.
        .filter_map(|l| l.split("(installed)").nth(1))
        .filter_map(|p| p.split_whitespace().next())
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

fn restart(version: PhpVersion) -> Result<(), String> {
    let unit = service(version);
    match exec::run(&["systemctl", "restart", &unit]) {
        Ok(o) if o.ok() => Ok(()),
        Ok(o) => Err(format!("{unit} did not restart: {}", tail(&o))),
        Err(e) => Err(format!("{unit} did not restart: {e}")),
    }
}

/// `php-ext-install`.
pub fn install(version: PhpVersion, key: &str) -> HelperResponse {
    let Some(ext) = php_ext::find(key) else {
        return refuse(format!("{key} is not a PHP extension the panel offers"));
    };
    if !php_installed(version) {
        return refuse(format!("PHP {version} is not installed"));
    }
    let Some(name) = package(ext, version) else {
        return HelperResponse::with_stdout(format!(
            "{key} comes with PHP {version} on this server\n"
        ));
    };
    let mut out = String::new();
    let fresh = !installed(&name);
    if fresh {
        if family() != Family::Rhel && !apt_installable(&name) {
            // The lists may predate the package: once more after a refresh.
            let _ = update_index();
            if !apt_installable(&name) {
                return refuse(format!(
                    "{name} is not in this server's package sources, so {key} cannot be installed for PHP {version}"
                ));
            }
        }
        match install_packages(&[&name]) {
            Ok(o) if o.ok() => out.push_str(&format!("installed {name}\n")),
            Ok(o) => return broke(format!("{name} could not be installed:\n{}", tail(&o))),
            Err(e) => return broke(format!("{name} could not be installed: {e}")),
        }
    } else {
        out.push_str(&format!("{name} was installed already\n"));
        // Asked for now, so wanted: were it there as another extension's
        // dependency, removing that one must not take this with it.
        if family() != Family::Rhel {
            let _ = exec::run(&["apt-mark", "manual", &name]);
        }
    }

    // Debian enables a module for every SAPI as it installs; one an
    // administrator switched off by hand is switched on again.
    if family() != Family::Rhel && !ext.loaded_in(&loaded_modules(version)) {
        let inis: Vec<&str> = ext
            .modules
            .iter()
            .map(|m| if *m == "zend opcache" { "opcache" } else { m })
            .collect();
        let dotted = version.dotted();
        let mut argv = vec!["phpenmod", "-v", dotted.as_str()];
        argv.extend(inis);
        let _ = exec::run(&argv);
    }

    if let Err(why) = restart(version) {
        if fresh {
            // Not left half-working: every site on this PHP would be down.
            let _ = remove_package(&name);
            let _ = restart(version);
            return broke(format!(
                "PHP-FPM {version} would not start with {key}, so it was removed again: {why}"
            ));
        }
        return broke(why);
    }
    if !ext.loaded_in(&loaded_modules(version)) {
        return broke(format!(
            "{name} is installed, but PHP {version} does not load {key}"
        ));
    }
    out.push_str(&format!("PHP {version} loads {key}\n"));
    HelperResponse::with_stdout(out)
}

/// `php-ext-remove`.
pub fn remove(version: PhpVersion, key: &str) -> HelperResponse {
    let Some(ext) = php_ext::find(key) else {
        return refuse(format!("{key} is not a PHP extension the panel offers"));
    };
    if ext.base {
        return refuse(format!(
            "{key} comes with every PHP version the panel installs, and the panel does not remove it"
        ));
    }
    if !php_installed(version) {
        return refuse(format!("PHP {version} is not installed"));
    }
    let Some(name) = package(ext, version) else {
        return refuse(format!(
            "{key} is part of PHP {version} itself on this server, and is not removed"
        ));
    };
    if !installed(&name) {
        return HelperResponse::with_stdout(format!("{name} is not installed\n"));
    }
    match removed_with(&name) {
        Ok(others) if others.is_empty() => {}
        Ok(others) => {
            return refuse(format!(
                "Removing {key} would also remove {}, so nothing was removed",
                others.join(", ")
            ))
        }
        Err(why) => {
            return broke(format!(
                "Cannot tell what removing {name} would take: {why}"
            ))
        }
    }
    match remove_package(&name) {
        Ok(o) if o.ok() => {}
        Ok(o) => return broke(format!("{name} could not be removed:\n{}", tail(&o))),
        Err(e) => return broke(format!("{name} could not be removed: {e}")),
    }
    let mut out = format!("removed {name}\n");
    // What came in with it and nothing needs now: memcached brings msgpack.
    // dnf takes those itself; apt leaves them, so the ones that are this
    // PHP version's are taken here - and nothing else apt would autoremove.
    if family() != Family::Rhel {
        if let Ok(o) = exec::run(&["apt-get", "-s", "autoremove"]) {
            let orphans = orphans_of(&apt_removals(&o.stdout), version);
            if !orphans.is_empty() {
                let mut argv = vec!["apt-get", "remove", "-y"];
                argv.extend(orphans.iter().map(String::as_str));
                if matches!(exec::run_with_env(&argv, &[("DEBIAN_FRONTEND", "noninteractive")]), Ok(o) if o.ok())
                {
                    out.push_str(&format!(
                        "removed {}, installed with it\n",
                        orphans.join(", ")
                    ));
                }
            }
        }
    }
    if let Err(why) = restart(version) {
        return broke(why);
    }
    out.push_str(&format!("PHP-FPM {version} restarted\n"));
    HelperResponse::with_stdout(out)
}

/// Of what apt would autoremove, this PHP version's extensions from the
/// catalogue, outside the base set - never PHP itself, whatever apt says.
pub fn orphans_of(autoremove: &[String], version: PhpVersion) -> Vec<String> {
    autoremove
        .iter()
        .filter(|p| {
            php_ext::PHP_EXTENSIONS
                .iter()
                .any(|e| !e.base && e.debian_package(version) == **p)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_says_what_a_removal_would_take() {
        let simulation = "NOTE: This is only a simulation!\n\
            Reading package lists...\n\
            The following packages will be REMOVED:\n  php8.3-igbinary php8.3-redis\n\
            Remv php8.3-redis [6.1.0-1+0~20241003.36+debian13~1.gbp6b2dd4]\n\
            Remv php8.3-igbinary:amd64 [3.2.16-1+0~20240922.45+debian13~1.gbpb3e6f3]\n";
        assert_eq!(
            apt_removals(simulation),
            ["php8.3-redis", "php8.3-igbinary"]
        );
        assert!(apt_removals("0 upgraded, 0 newly installed, 0 to remove").is_empty());
    }

    #[test]
    fn only_this_versions_leftovers_go_with_an_extension() {
        let autoremove = apt_removals(
            "Remv php8.3-msgpack [1:3.0.0-2]\nRemv php8.4-msgpack [1:3.0.0-2]\nRemv libmemcached11t64 [1.1.4-1]\nRemv php8.3-common [8.3.12-1]\n",
        );
        let v = PhpVersion::parse("8.3").unwrap();
        // Not php8.3-common, whatever apt says: PHP itself is never taken.
        assert_eq!(orphans_of(&autoremove, v), ["php8.3-msgpack"]);
        assert!(orphans_of(&autoremove, PhpVersion::parse("8.2").unwrap()).is_empty());
    }

    #[test]
    fn rpm_says_who_needs_a_package() {
        let stderr = "error: Failed dependencies:\n\
            \tphp83-php-pecl-igbinary(x86-64) = 3.2.16-1.el10.remi is needed by (installed) php83-php-pecl-redis6-6.1.0-1.el10.remi.x86_64\n\
            \tphp83-php-pecl-igbinary is needed by (installed) php83-php-pecl-redis6-6.1.0-1.el10.remi.x86_64\n";
        assert_eq!(
            rpm_dependents(stderr),
            ["php83-php-pecl-redis6-6.1.0-1.el10.remi.x86_64"]
        );
    }

    #[test]
    fn nothing_outside_the_catalogue_is_installed_or_removed() {
        let v = PhpVersion::parse("8.3").unwrap();
        for key in ["../../../bin/sh", "php8.3-fpm", "", "redis ; reboot"] {
            let answer = install(v, key);
            assert!(!answer.ok, "{key:?}");
            let answer = remove(v, key);
            assert!(!answer.ok, "{key:?}");
        }
    }

    #[test]
    fn the_base_set_is_never_removed() {
        let v = PhpVersion::parse("8.3").unwrap();
        for ext in php_ext::PHP_EXTENSIONS.iter().filter(|e| e.base) {
            let answer = remove(v, ext.key);
            assert!(!answer.ok, "{}", ext.key);
            let said = answer.error.map(|e| e.message).unwrap_or_default();
            assert!(said.contains("does not remove it"), "{said}");
        }
    }
}
