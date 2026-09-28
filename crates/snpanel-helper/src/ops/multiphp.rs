//! `ops::multiphp` - a website's own PHP version on the Hosting Edition,
//! the way cPanel's MultiPHP does it, for both web servers at once.
//!
//! - LiteSpeed Enterprise: a handler in the site's `.htaccess`, inside
//!   `<IfModule LiteSpeed>` so Apache never reads it. LiteSpeed runs it
//!   with suEXEC, as the site's owner, in the owner's CageFS and LVE. (The
//!   same handler in the *vhost* runs as the web server's user, outside
//!   CageFS, and is never written there.)
//! - Apache: a CloudLinux website isolate for the domain, with the PHP
//!   Selector's per-domain version. Apache's vhost keeps
//!   `SetHandler application/x-httpd-lsphp`, which takes precedence over the
//!   `.htaccess` handler, so Apache never meets a handler it cannot map.
//!
//! "inherit" undoes both: the site follows its owner's PHP Selector version.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use snpanel_core::{Domain, PanelUsername, PhpVersion, SitePath};
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

const BEGIN: &str = "# BEGIN SNPanel MultiPHP - managed by the panel, do not edit";
const END: &str = "# END SNPanel MultiPHP";
/// `.htaccess` files bigger than this are not the panel's to rewrite.
const MAX_HTACCESS: u64 = 1024 * 1024;

/// The block for a version, or nothing for "inherit".
fn block(version: Option<PhpVersion>) -> Option<String> {
    version.map(|v| {
        format!(
            "{BEGIN}\n<IfModule LiteSpeed>\nAddHandler application/x-httpd-alt-php{}___lsphp .php .phtml\n</IfModule>\n{END}\n",
            v.compact()
        )
    })
}

/// `.htaccess` with the panel's block replaced (or removed), everything
/// else as it was. The block goes first: a later `AddHandler` of the
/// customer's own still wins, which is their choice to make.
pub fn rewrite_htaccess(existing: &str, version: Option<PhpVersion>) -> String {
    let mut rest = String::new();
    let mut inside = false;
    for line in existing.split_inclusive('\n') {
        let trimmed = line.trim_end();
        if trimmed == BEGIN {
            inside = true;
            continue;
        }
        if inside {
            if trimmed == END {
                inside = false;
            }
            continue;
        }
        rest.push_str(line);
    }
    match block(version) {
        Some(b) if rest.trim().is_empty() => b,
        Some(b) => format!("{b}{rest}"),
        None => rest,
    }
}

/// The PHP Selector's default modules for a version (`[php8.3] modules = ...`
/// in `/etc/cl.selector/defaults.cfg`).
pub fn selector_default_modules(defaults_cfg: &str, version: PhpVersion) -> Vec<String> {
    let section = format!("[php{}]", version.dotted());
    let mut inside = false;
    for line in defaults_cfg.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t == section;
            continue;
        }
        if inside {
            if let Some(("modules", list)) = t.split_once('=').map(|(k, v)| (k.trim(), v)) {
                return list
                    .split(',')
                    .map(|m| m.trim().to_string())
                    .filter(|m| {
                        !m.is_empty() && m.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

/// One ini with the modules' own ini files from `php.d.all`, in order, each
/// `extension=`/`zend_extension=` kept the first time only: the files load
/// their dependencies first (nd_mysqli.ini loads mysqlnd.so, then itself),
/// and a module loaded twice is a warning on every request.
pub fn build_multiphp_ini(modules: &[String], read: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::from(
        "; SNPANEL MANAGED - the PHP Selector's default modules, for websites that run\n\
         ; this version through MultiPHP (.htaccess) rather than as their account's version.\n",
    );
    let mut loaded: Vec<String> = Vec::new();
    for module in modules {
        let Some(text) = read(module) else { continue };
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!(";---{module}---\n"));
        for line in text.lines() {
            let t = line.trim();
            let is_load = t.starts_with("extension=") || t.starts_with("zend_extension=");
            if is_load {
                let key = t.replace(' ', "");
                if loaded.contains(&key) {
                    continue;
                }
                loaded.push(key);
            }
            if t.is_empty() || t.starts_with(';') {
                continue;
            }
            out.push_str(t);
            out.push('\n');
        }
    }
    out
}

/// Make sure a version run through MultiPHP has the Selector's default
/// modules. CageFS points `/opt/alt/phpXX/link/conf` at the account's own
/// list only for the account's Selector version; any other version reads
/// the system's `php.d`, which has almost nothing (no mysqli: WordPress
/// answers "Requirements Not Met").
fn ensure_multiphp_defaults(version: PhpVersion) -> Result<(), String> {
    let cfg = std::fs::read_to_string("/etc/cl.selector/defaults.cfg").unwrap_or_default();
    let modules = selector_default_modules(&cfg, version);
    if modules.is_empty() {
        return Ok(());
    }
    let base = format!("/opt/alt/php{}/etc", version.compact());
    let ini = build_multiphp_ini(&modules, |m| {
        std::fs::read_to_string(format!("{base}/php.d.all/{m}.ini")).ok()
    });
    let path = format!("{base}/php.d/snpanel-multiphp.ini");
    if std::fs::read_to_string(&path).ok().as_deref() == Some(ini.as_str()) {
        return Ok(());
    }
    crate::ops::nginx::write_atomic(std::path::Path::new(&path), ini.as_bytes(), 0o644)
        .map_err(|e| format!("writing {path}: {e}"))
}

fn failed(kind: HelperErrorKind, message: String) -> HelperResponse {
    HelperResponse::failed(kind, message)
}

/// Read a site file without following a symlink at its last component (the
/// directories above were checked by `verify_no_symlinks`).
fn read_nofollow(path: &std::path::Path) -> std::io::Result<Option<String>> {
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => {
            let meta = f.metadata()?;
            if !meta.is_file() || meta.len() > MAX_HTACCESS {
                return Err(std::io::Error::other(
                    "not a regular .htaccess the panel can rewrite",
                ));
            }
            let mut s = String::new();
            f.take(MAX_HTACCESS).read_to_string(&mut s)?;
            Ok(Some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// `site-php-set <user> <domain> <document-root> <version|inherit>`.
pub fn site_php_set(
    user: &PanelUsername,
    domain: &Domain,
    document_root: &str,
    version: Option<PhpVersion>,
) -> HelperResponse {
    if !super::apache::active() || snpanel_osabi::hosting::cloudlinux().is_none() {
        return failed(
            HelperErrorKind::BadRequest,
            "site-php-set is for the Hosting Edition on CloudLinux".to_string(),
        );
    }
    let docroot = match snpanel_core::DocumentRoot::parse(document_root) {
        Ok(d) => d,
        Err(e) => return failed(HelperErrorKind::BadRequest, e.to_string()),
    };
    let htaccess =
        match SitePath::site_root(user, domain).join(&format!("{}/.htaccess", docroot.as_str())) {
            Ok(p) => p,
            Err(e) => return failed(HelperErrorKind::BadRequest, e.to_string()),
        };
    if htaccess.verify_no_symlinks().is_err() {
        return failed(
            HelperErrorKind::BadRequest,
            format!("refusing to act through a symlink: {htaccess}"),
        );
    }

    if let Some(v) = version {
        if let Err(e) = ensure_multiphp_defaults(v) {
            return failed(HelperErrorKind::Internal, e);
        }
    }

    // LiteSpeed: the .htaccess block.
    let existing = match read_nofollow(htaccess.as_path()) {
        Ok(e) => e,
        Err(e) => return failed(HelperErrorKind::BadRequest, format!("{htaccess}: {e}")),
    };
    let current = existing.clone().unwrap_or_default();
    let updated = rewrite_htaccess(&current, version);
    if updated != current {
        let result = if updated.trim().is_empty() && existing.is_some() {
            std::fs::remove_file(htaccess.as_path())
        } else {
            let owner = format!("{0}:{0}", user.as_str());
            super::site::write_atomic_owned(
                htaccess.as_path(),
                updated.as_bytes(),
                0o644,
                Some(&owner),
            )
        };
        if let Err(e) = result {
            return failed(
                HelperErrorKind::Internal,
                format!("writing {htaccess}: {e}"),
            );
        }
    }

    // Apache: the isolate and the Selector's per-domain version.
    let d = domain.as_str();
    match version {
        Some(v) => {
            let already = exec::run(&["cagefsctl", "--isolates-list", user.as_str()])
                .map(|o| o.stdout.lines().any(|l| l.trim() == d))
                .unwrap_or(false);
            let _ = exec::run(&["cagefsctl", "--isolates-allow", user.as_str()]);
            let enabled = exec::run(&["cagefsctl", "--isolates-enable", d]);
            let listed = exec::run(&["cagefsctl", "--isolates-list", user.as_str()])
                .map(|o| o.stdout.contains(d))
                .unwrap_or(false);
            if !listed {
                return exec::respond("cagefsctl --isolates-enable", enabled);
            }
            let set = exec::run(&[
                "runuser",
                "-u",
                user.as_str(),
                "--",
                "cloudlinux-selector",
                "set",
                "--json",
                "--interpreter",
                "php",
                "--domain",
                d,
                "--current-version",
                &v.dotted(),
            ]);
            let ok = matches!(&set, Ok(o) if o.ok() && o.stdout.contains("success"));
            if !ok {
                return exec::respond("cloudlinux-selector set --domain", set);
            }
            // A new isolate starts with whatever module list CageFS made for
            // the account, which can lack the MySQL drivers (WordPress then
            // answers 500). Give it the Selector's defaults once; later
            // changes are the customer's, and are left alone.
            if !already {
                let reset = exec::run(&[
                    "runuser",
                    "-u",
                    user.as_str(),
                    "--",
                    "cloudlinux-selector",
                    "set",
                    "--json",
                    "--interpreter",
                    "php",
                    "--reset-extensions",
                    "--version",
                    &v.dotted(),
                    "--domain",
                    d,
                ]);
                if !matches!(&reset, Ok(o) if o.ok() && o.stdout.contains("success")) {
                    return exec::respond("cloudlinux-selector --reset-extensions", reset);
                }
            }
        }
        None => {
            let listed = exec::run(&["cagefsctl", "--isolates-list", user.as_str()])
                .map(|o| o.stdout.contains(d))
                .unwrap_or(false);
            if listed {
                let off = exec::run(&["cagefsctl", "--isolates-disable", d]);
                if !matches!(&off, Ok(o) if o.ok()) {
                    return exec::respond("cagefsctl --isolates-disable", off);
                }
            }
        }
    }
    // Running PHP processes keep the version they started with.
    let _ = exec::run(&["pkill", "-u", user.as_str(), "-x", "lsphp"]);
    HelperResponse::with_stdout(format!(
        "{d}: PHP {}\n",
        version.map_or_else(|| "from the account".to_string(), |v| v.dotted())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Option<PhpVersion> {
        Some(PhpVersion::parse(s).unwrap())
    }

    #[test]
    fn the_selectors_defaults_are_read_per_version() {
        let cfg = "[php8.2]\nmodules = gd,intl\n\n[php8.3]\nmodules = bcmath,mysqlnd,nd_mysqli, pdo ,nd_pdo_mysql\nstate = enabled\n";
        let m = selector_default_modules(cfg, PhpVersion::parse("8.3").unwrap());
        assert_eq!(m, ["bcmath", "mysqlnd", "nd_mysqli", "pdo", "nd_pdo_mysql"]);
        assert!(selector_default_modules(cfg, PhpVersion::parse("7.4").unwrap()).is_empty());
    }

    #[test]
    fn each_module_is_loaded_once_and_after_its_dependencies() {
        let files = |m: &str| -> Option<String> {
            Some(match m {
                "mysqlnd" => "; Enable mysqlnd\nextension=mysqlnd.so\n".to_string(),
                "nd_mysqli" => {
                    "; Enable nd_mysqli\nextension=mysqlnd.so\nextension=nd_mysqli.so\n".to_string()
                }
                "pdo" => "extension=pdo.so\n".to_string(),
                "nd_pdo_mysql" => {
                    "extension=mysqlnd.so\nextension=pdo.so\nextension=nd_pdo_mysql.so\n"
                        .to_string()
                }
                "opcache" => "zend_extension=opcache.so\nopcache.enable=1\n".to_string(),
                _ => return None,
            })
        };
        let mods: Vec<String> = [
            "mysqlnd",
            "nd_mysqli",
            "pdo",
            "nd_pdo_mysql",
            "opcache",
            "missing",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let ini = build_multiphp_ini(&mods, files);
        let loads: Vec<&str> = ini.lines().filter(|l| l.contains("extension=")).collect();
        assert_eq!(
            loads,
            [
                "extension=mysqlnd.so",
                "extension=nd_mysqli.so",
                "extension=pdo.so",
                "extension=nd_pdo_mysql.so",
                "zend_extension=opcache.so"
            ]
        );
        assert!(ini.contains("opcache.enable=1"));
    }

    #[test]
    fn the_block_goes_first_and_keeps_the_rest() {
        let wp = "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n";
        let out = rewrite_htaccess(wp, v("8.3"));
        assert!(out.starts_with(BEGIN));
        assert!(out.contains("<IfModule LiteSpeed>\nAddHandler application/x-httpd-alt-php83___lsphp .php .phtml\n</IfModule>"));
        assert!(out.ends_with(wp));
    }

    #[test]
    fn changing_the_version_replaces_the_block_once() {
        let first = rewrite_htaccess("RewriteEngine On\n", v("8.3"));
        let second = rewrite_htaccess(&first, v("7.4"));
        assert_eq!(second.matches(BEGIN).count(), 1);
        assert!(second.contains("alt-php74___lsphp"));
        assert!(!second.contains("alt-php83"));
        assert!(second.ends_with("RewriteEngine On\n"));
    }

    #[test]
    fn inherit_takes_the_block_out_and_nothing_else() {
        let with = rewrite_htaccess("Options -Indexes\n", v("8.2"));
        assert_eq!(rewrite_htaccess(&with, None), "Options -Indexes\n");
        assert_eq!(rewrite_htaccess(&rewrite_htaccess("", v("8.2")), None), "");
        assert_eq!(rewrite_htaccess("", None), "");
    }
}
