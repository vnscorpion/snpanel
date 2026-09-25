//! The Fail2ban addon: the package, the panel's filters and jail file, the
//! reads the Fail2ban page makes, and the bans it hands out.
//!
//! The panel owns three files and nothing else under `/etc/fail2ban`: its jail
//! file and its two filters. The distribution's `jail.conf` and whatever an
//! administrator added stay as they are - the jail file is a `.local` in
//! `jail.d`, read after them, so what the panel sets wins and nothing else is
//! touched.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::json;
use snpanel_ipc::{Fail2banConfig, Fail2banJail, HelperErrorKind, HelperResponse};

use super::packages;
use super::Context;
use crate::exec;

const JAIL_FILE: &str = "/etc/fail2ban/jail.d/snpanel.local";
const LOGIN_FILTER: &str = "/etc/fail2ban/filter.d/snpanel-login.conf";
const WORDPRESS_FILTER: &str = "/etc/fail2ban/filter.d/snpanel-wordpress.conf";
const CLIENT: &str = "fail2ban-client";
/// Where `fail2ban.conf` sends the server's own log on every distribution the
/// panel supports, and the file `jail.conf`'s recidive jail reads.
const DEFAULT_OWN_LOG: &str = "/var/log/fail2ban.log";

/// Cloudflare's published ranges, as cloudflare.com/ips-v4 and /ips-v6 list
/// them (checked 2026-09).
///
/// Never banned by the web jails. A site behind Cloudflare logs Cloudflare's
/// address, not the visitor's - the panel does not set `real_ip` - so a ban
/// would shut out everyone that edge serves, and banning the visitor would
/// not help either: their requests arrive from Cloudflare.
const CLOUDFLARE: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// A failed WordPress sign-in, from a site's access log.
///
/// A sign-in that fails answers 200 with the form again; one that works
/// answers 302. The address is the first field of the line, which the client
/// does not write - everything it does write comes after it, so a crafted
/// request cannot name somebody else. `xmlrpc.php` is left out on purpose:
/// Jetpack and the mobile apps use it legitimately, all day.
const WORDPRESS_FILTER_TEXT: &str = r#"# Written by SNPanel: failed WordPress sign-ins, from every site's access log.
#
# A sign-in that fails answers 200 with the form again; one that works
# answers 302. The address is the first field of the line, which the client
# does not write.

[Definition]
failregex = ^<ADDR> \S+ \S+ \[[^\]]*\] "POST /[^" ]*wp-login\.php(?:\?[^" ]*)? HTTP/[0-9.]+" 200\s
ignoreregex =
"#;

/// The panel's own sign-in, from the journal.
///
/// The API writes one line for each failure, as `snpanel-auth`, and the match
/// is pinned to the panel's user as well. Any process on the machine can claim
/// an identifier - a customer's PHP included - but not another user's uid, and
/// a forged line would ban whichever address it named.
fn render_login_filter(panel_uid: u32) -> String {
    format!(
        "# Written by SNPanel: failed sign-ins to the panel.
#
# The API writes one line to the journal for each, as snpanel-auth. The match
# is pinned to the panel's uid too: any process can claim an identifier, but
# not another user's uid, and a forged line would ban whoever it named.

[INCLUDES]
before = common.conf

[Definition]
_daemon = snpanel-auth
failregex = ^%(__prefix_line)slogin failure from <ADDR>$
ignoreregex =

[Init]
journalmatch = SYSLOG_IDENTIFIER=snpanel-auth _UID={panel_uid}
"
    )
}

/// Where the server writes its own log - which is what the recidive jail
/// reads, for the bans the other jails hand out.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnLog {
    /// A file: `/var/log/fail2ban.log`, unless an administrator moved it.
    File(String),
    /// The journal, syslog or the service's own output, all of which the
    /// journal keeps under `fail2ban.service` - the unit the recidive filter
    /// matches on.
    Journal,
}

/// `logtarget`, as the server will read it: `fail2ban.conf`, then
/// `fail2ban.d`'s `.conf` files, `fail2ban.local`, then `fail2ban.d`'s `.local`
/// files, the last one winning - and a value in `[Definition]` over one in
/// `[DEFAULT]`, which is where the distributions put it.
fn own_log_in(dir: &Path) -> OwnLog {
    let dropins = |ext: &str| {
        let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(dir.join("fail2ban.d"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some(ext))
            .collect();
        found.sort();
        found
    };
    let mut files = vec![dir.join("fail2ban.conf")];
    files.extend(dropins("conf"));
    files.push(dir.join("fail2ban.local"));
    files.extend(dropins("local"));

    let (mut default, mut definition) = (None, None);
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.trim().to_string();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "logtarget" {
                continue;
            }
            match section.as_str() {
                "DEFAULT" => default = Some(value.trim().to_string()),
                "Definition" => definition = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    let target = definition
        .or(default)
        .unwrap_or_else(|| DEFAULT_OWN_LOG.to_string());
    // `SYSLOG[format=...]`: what follows the name is how, not where.
    let target = target.split('[').next().unwrap_or_default().trim();
    if target.starts_with('/') {
        OwnLog::File(target.to_string())
    } else {
        OwnLog::Journal
    }
}

/// The server's own log file, made if it is not there yet.
///
/// Only the server's first start makes it. Debian starts the service as the
/// package goes in; the RHEL family does not, so on a new EL machine the file
/// is missing when `fail2ban-client --test` runs, the test refuses a recidive
/// jail with no log to read - measured on AlmaLinux 10 - and the install
/// stops there. Mode 0640: it is a list of addresses and what they did.
fn ensure_own_log(own: &OwnLog) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match own {
        OwnLog::File(path) => std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o640)
            .open(path)
            .map(drop),
        OwnLog::Journal => Ok(()),
    }
}

/// The jail file, from the settings and the ports this machine listens on.
fn render_jail_file(
    config: &Fail2banConfig,
    ssh_ports: &[u16],
    panel_port: u16,
    own_log: &OwnLog,
) -> String {
    // Normalized like every entry after them, so an entry that repeats
    // loopback is recognised as a repeat.
    let mut exempt: Vec<String> = vec!["127.0.0.0/8".to_string(), "::1/128".to_string()];
    for entry in &config.ignoreip {
        let normalized = entry.normalized();
        if !exempt.contains(&normalized) {
            exempt.push(normalized);
        }
    }
    let mut web_exempt = exempt.clone();
    web_exempt.extend(CLOUDFLARE.iter().map(|range| range.to_string()));
    let ssh = if ssh_ports.is_empty() {
        "ssh".to_string()
    } else {
        ssh_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };

    let mut out = String::from(
        "# Written by SNPanel from its Fail2ban page, and rewritten whenever the page is
# saved. Put jails of your own in a file of their own.

",
    );
    let _ = writeln!(out, "[DEFAULT]");
    let _ = writeln!(out, "ignoreip = {}", exempt.join(" "));
    let _ = writeln!(out, "bantime = {}", config.bantime);
    let _ = writeln!(out, "findtime = {}", config.findtime);
    let _ = writeln!(out, "maxretry = {}", config.maxretry);
    // The panel's firewall is nftables, and so is every ban: fail2ban's own
    // table, beside the panel's, which lets allowed traffic through with a
    // `return` precisely so that these rules still see it.
    let _ = writeln!(out, "banaction = nftables");
    let _ = writeln!(out, "banaction_allports = nftables[type=allports]");

    for jail in Fail2banJail::ALL {
        let _ = writeln!(out, "\n[{}]", jail.name());
        let _ = writeln!(out, "enabled = {}", config.enables(jail));
        match jail {
            // The journal on every distribution: EL keeps no auth log file
            // unless rsyslog is installed, and a jail whose file is missing
            // stops fail2ban from starting at all.
            Fail2banJail::Sshd => {
                let _ = writeln!(out, "port = {ssh}");
                let _ = writeln!(out, "backend = systemd");
            }
            Fail2banJail::PanelLogin => {
                let _ = writeln!(out, "port = {panel_port}");
                let _ = writeln!(out, "filter = snpanel-login");
                let _ = writeln!(out, "backend = systemd");
            }
            // `*access.log` and not `*.access.log`: nginx's own access.log is
            // there on every machine with nginx, and a glob that matches
            // nothing - a server with no sites yet - stops fail2ban starting.
            Fail2banJail::Wordpress => {
                let _ = writeln!(out, "port = http,https");
                let _ = writeln!(out, "filter = snpanel-wordpress");
                let _ = writeln!(out, "logpath = /var/log/nginx/*access.log");
                let _ = writeln!(out, "ignoreip = {}", web_exempt.join(" "));
            }
            Fail2banJail::NginxHttpAuth => {
                let _ = writeln!(out, "port = http,https");
                let _ = writeln!(out, "logpath = /var/log/nginx/*error.log");
                let _ = writeln!(out, "ignoreip = {}", web_exempt.join(" "));
            }
            // fail2ban's own: a week, on every port, for an address banned
            // `maxretry` times in a day. It reads the server's log, which
            // `jail.conf` assumes is the default file.
            Fail2banJail::Recidive => match own_log {
                OwnLog::File(path) if path == DEFAULT_OWN_LOG => {}
                OwnLog::File(path) => {
                    let _ = writeln!(out, "logpath = {path}");
                }
                OwnLog::Journal => {
                    let _ = writeln!(out, "backend = systemd");
                }
            },
        }
    }
    out
}

fn installed() -> bool {
    ["/usr/bin/fail2ban-client", "/usr/local/bin/fail2ban-client"]
        .iter()
        .any(|p| Path::new(p).is_file())
}

fn not_installed() -> HelperResponse {
    HelperResponse::failed(
        HelperErrorKind::NotFound,
        "fail2ban is not installed; install the Fail2ban addon first",
    )
}

fn invalid(config: &Fail2banConfig) -> Option<HelperResponse> {
    config
        .validate()
        .err()
        .map(|message| HelperResponse::failed(HelperErrorKind::BadRequest, message))
}

/// The packages, per family. EPEL's `fail2ban` would pull in firewalld's
/// actions and sendmail; the server and the journal reader are what is used.
fn package_names() -> &'static [&'static str] {
    match packages::family() {
        snpanel_osabi::Family::Rhel => &["fail2ban-server", "python3-systemd"],
        _ => &["fail2ban"],
    }
}

/// The three files, from `config`.
fn write_files(config: &Fail2banConfig, ctx: &Context) -> Result<(), HelperResponse> {
    let panel_uid = crate::peercred::uid_of(crate::peercred::PANEL_USER).map_err(|e| {
        HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("cannot resolve the panel user: {e}"),
        )
    })?;
    let own_log = own_log_in(Path::new("/etc/fail2ban"));
    if let Err(e) = ensure_own_log(&own_log) {
        // Not fatal here: `--test` names the jail if it matters.
        eprintln!("snpanel-helper: making fail2ban's own log: {e}");
    }
    for (path, text) in [
        (LOGIN_FILTER, render_login_filter(panel_uid)),
        (WORDPRESS_FILTER, WORDPRESS_FILTER_TEXT.to_string()),
        (
            JAIL_FILE,
            render_jail_file(config, &ctx.ssh_ports, ctx.panel_port, &own_log),
        ),
    ] {
        super::nginx::write_atomic(Path::new(path), text.as_bytes(), 0o644).map_err(|e| {
            HelperResponse::failed(HelperErrorKind::Internal, format!("writing {path}: {e}"))
        })?;
    }
    Ok(())
}

fn running() -> bool {
    matches!(exec::run(&[CLIENT, "ping"]), Ok(o) if o.ok())
}

/// The server answers a ping. It reads its jails before it does, which takes
/// a few seconds.
fn wait_until_running() -> bool {
    for _ in 0..40 {
        if running() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    running()
}

/// `fail2ban-client --test`: the whole configuration read and checked, with
/// no server involved. A file that fails it is not left behind.
fn test_configuration() -> Result<(), HelperResponse> {
    match exec::run(&[CLIENT, "--test"]) {
        Ok(o) if o.ok() => Ok(()),
        other => Err(exec::respond("fail2ban-client --test", other)),
    }
}

/// `fail2ban-install`.
pub fn install(config: &Fail2banConfig, ctx: &Context) -> HelperResponse {
    if let Some(r) = invalid(config) {
        return r;
    }
    let mut out = String::new();
    if !installed() {
        if let Ok(o) = packages::update_index() {
            out.push_str(&o.stdout);
        }
        let names = package_names();
        match packages::install_packages(names) {
            Ok(o) if o.ok() => out.push_str(&o.stdout),
            other => return exec::respond(&format!("installing {}", names.join(" ")), other),
        }
    }
    if let Err(r) = write_files(config, ctx) {
        return r;
    }
    if let Err(r) = test_configuration() {
        return r;
    }
    // A restart rather than `--now`: on a machine where it already ran, the
    // new files have to be read. Bans survive it - fail2ban keeps them in its
    // database and puts them back.
    for step in [
        ["systemctl", "enable", "fail2ban"],
        ["systemctl", "restart", "fail2ban"],
    ] {
        let result = exec::run(&step);
        if !matches!(&result, Ok(o) if o.ok()) {
            return exec::respond(&step.join(" "), result);
        }
    }
    if !wait_until_running() {
        return HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "fail2ban was started but does not answer; see journalctl -u fail2ban",
        );
    }
    out.push_str("fail2ban installed and running\n");
    HelperResponse::with_stdout(out)
}

/// `fail2ban-configure`: the files rewritten, checked, and read.
///
/// A configuration fail2ban refuses puts the previous jail file back, so the
/// next restart - a reboot, say - does not find a broken one.
pub fn configure(config: &Fail2banConfig, ctx: &Context) -> HelperResponse {
    if let Some(r) = invalid(config) {
        return r;
    }
    if !installed() {
        return not_installed();
    }
    let previous = std::fs::read(JAIL_FILE).ok();
    if let Err(r) = write_files(config, ctx) {
        return r;
    }
    if let Err(r) = test_configuration() {
        let _ = match &previous {
            Some(bytes) => super::nginx::write_atomic(Path::new(JAIL_FILE), bytes, 0o644),
            None => std::fs::remove_file(JAIL_FILE),
        };
        return r;
    }
    let step: &[&str] = if running() {
        &[CLIENT, "reload"]
    } else {
        &["systemctl", "restart", "fail2ban"]
    };
    let result = exec::run(step);
    if !matches!(&result, Ok(o) if o.ok()) {
        return exec::respond(&step.join(" "), result);
    }
    if !wait_until_running() {
        return HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "fail2ban does not answer after the reload; see journalctl -u fail2ban",
        );
    }
    HelperResponse::with_stdout("fail2ban settings applied\n")
}

/// One jail's counters, as `fail2ban-client status <jail>` prints them.
#[derive(Debug, Default, PartialEq, Eq)]
struct JailStatus {
    currently_failed: u64,
    total_failed: u64,
    currently_banned: u64,
    total_banned: u64,
    banned: Vec<String>,
}

/// The value after `label:` on the first line that has it.
fn field<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (_, rest) = line.split_once(label)?;
        rest.strip_prefix(':').map(str::trim)
    })
}

fn parse_jail_list(status: &str) -> Vec<String> {
    field(status, "Jail list")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
        .map(str::to_string)
        .collect()
}

fn parse_jail_status(status: &str) -> JailStatus {
    let number = |label: &str| {
        field(status, label)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    JailStatus {
        currently_failed: number("Currently failed"),
        total_failed: number("Total failed"),
        currently_banned: number("Currently banned"),
        total_banned: number("Total banned"),
        banned: field(status, "Banned IP list")
            .unwrap_or_default()
            .split_whitespace()
            .filter(|a| a.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_string)
            .collect(),
    }
}

/// `Fail2Ban v1.1.0` -> `1.1.0`.
fn parse_version(text: &str) -> Option<String> {
    text.split_whitespace()
        .find_map(|word| word.strip_prefix('v'))
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .map(str::to_string)
}

/// `fail2ban-status`: the service and every jail it runs, on stdout.
///
/// Every jail, not only the panel's: a jail an administrator added by hand
/// holds bans too, and a page that hid them would leave an address banned with
/// no way to see why.
pub fn status() -> HelperResponse {
    let installed = installed();
    let version = installed
        .then(|| exec::run(&[CLIENT, "--version"]).ok())
        .flatten()
        .and_then(|o| parse_version(&o.stdout));
    let running = installed && running();
    let mut jails = Vec::new();
    if running {
        let names = exec::run(&[CLIENT, "status"])
            .ok()
            .filter(exec::Output::ok)
            .map(|o| parse_jail_list(&o.stdout))
            .unwrap_or_default();
        for name in names {
            let Some(out) = exec::run(&[CLIENT, "status", &name])
                .ok()
                .filter(exec::Output::ok)
            else {
                continue;
            };
            let s = parse_jail_status(&out.stdout);
            jails.push(json!({
                "name": name,
                "currently_failed": s.currently_failed,
                "total_failed": s.total_failed,
                "currently_banned": s.currently_banned,
                "total_banned": s.total_banned,
                "banned": s.banned,
            }));
        }
    }
    let body = json!({
        "installed": installed,
        "running": running,
        "version": version,
        "jails": jails,
    });
    HelperResponse::with_stdout(format!("{body}\n"))
}

fn require_running() -> Result<(), HelperResponse> {
    if !installed() {
        return Err(not_installed());
    }
    if !running() {
        return Err(HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "fail2ban is not running",
        ));
    }
    Ok(())
}

/// `fail2ban-ban <jail> <address>`.
pub fn ban(jail: Fail2banJail, address: std::net::IpAddr) -> HelperResponse {
    if let Err(r) = require_running() {
        return r;
    }
    let address = address.to_canonical().to_string();
    exec::respond(
        &format!("fail2ban-client set {} banip", jail.name()),
        exec::run(&[CLIENT, "set", jail.name(), "banip", &address]),
    )
}

/// `fail2ban-unban <address>`: out of every jail that holds it.
pub fn unban(address: std::net::IpAddr) -> HelperResponse {
    if let Err(r) = require_running() {
        return r;
    }
    let address = address.to_canonical().to_string();
    exec::respond(
        "fail2ban-client unban",
        exec::run(&[CLIENT, "unban", &address]),
    )
}

/// `fail2ban-stop`: stopped and disabled at boot, which lifts every ban.
pub fn stop() -> HelperResponse {
    if !installed() {
        return HelperResponse::with_stdout("fail2ban is not installed; nothing to stop\n");
    }
    exec::respond(
        "systemctl disable --now fail2ban",
        exec::run(&["systemctl", "disable", "--now", "fail2ban"]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use snpanel_core::IpOrCidr;

    fn config() -> Fail2banConfig {
        Fail2banConfig {
            ignoreip: vec![
                IpOrCidr::parse("203.0.113.7").unwrap(),
                IpOrCidr::parse("198.51.100.9/24").unwrap(),
                IpOrCidr::parse("127.0.0.1/8").unwrap(),
            ],
            bantime: 3600,
            findtime: 300,
            maxretry: 3,
            jails: vec![
                Fail2banJail::Sshd,
                Fail2banJail::PanelLogin,
                Fail2banJail::Wordpress,
            ],
        }
    }

    fn default_log() -> OwnLog {
        OwnLog::File(DEFAULT_OWN_LOG.to_string())
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "snpanel-f2b-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("fail2ban.d")).unwrap();
        dir
    }

    /// The part of the file under `[section]`, up to the next section.
    fn section<'a>(file: &'a str, name: &str) -> &'a str {
        let start = file
            .find(&format!("\n[{name}]\n"))
            .unwrap_or_else(|| panic!("no [{name}] in\n{file}"));
        let rest = &file[start + 1..];
        let end = rest[1..].find("\n[").map_or(rest.len(), |i| i + 2);
        &rest[..end]
    }

    #[test]
    fn the_jail_file_says_what_the_page_decided() {
        let file = render_jail_file(&config(), &[22, 2200], 2222, &default_log());
        let default = section(&file, "DEFAULT");
        // Loopback always, each entry once and masked, in the order given.
        assert!(
            default.contains("ignoreip = 127.0.0.0/8 ::1/128 203.0.113.7/32 198.51.100.0/24\n"),
            "{default}"
        );
        assert!(default.contains("bantime = 3600\n"));
        assert!(default.contains("findtime = 300\n"));
        assert!(default.contains("maxretry = 3\n"));
        assert!(default.contains("banaction = nftables\n"));

        let sshd = section(&file, "sshd");
        assert!(
            sshd.contains("enabled = true\n") && sshd.contains("port = 22,2200\n"),
            "{sshd}"
        );
        assert!(sshd.contains("backend = systemd\n"));
        let login = section(&file, "snpanel-login");
        assert!(login.contains("port = 2222\n") && login.contains("filter = snpanel-login\n"));
        // Switched off is written out: Debian switches sshd on in a file of its
        // own, and silence here would leave that in charge.
        assert!(section(&file, "nginx-http-auth").contains("enabled = false\n"));
        assert!(section(&file, "recidive").contains("enabled = false\n"));
        assert!(!render_jail_file(&config(), &[], 2222, &default_log()).contains("port = ,"));
        assert!(section(
            &render_jail_file(&config(), &[], 2222, &default_log()),
            "sshd"
        )
        .contains("port = ssh\n"));
    }

    /// What both distributions ship: `logtarget` in `[DEFAULT]`, and an
    /// empty `[Definition]` that inherits it.
    const SHIPPED: &str = "[DEFAULT]\nloglevel = INFO\nlogtarget = /var/log/fail2ban.log\n\n[Definition]\n\n[Thread]\n";

    #[test]
    fn the_servers_own_log_is_where_the_configuration_says() {
        let dir = scratch("own-log");
        assert_eq!(own_log_in(&dir), default_log(), "nothing there at all");
        std::fs::write(dir.join("fail2ban.conf"), SHIPPED).unwrap();
        assert_eq!(own_log_in(&dir), default_log(), "as shipped");

        // A drop-in beats the file it drops into, whichever section.
        std::fs::write(
            dir.join("fail2ban.d/00-journal.conf"),
            "[Definition]\nlogtarget = SYSTEMD-JOURNAL\n",
        )
        .unwrap();
        assert_eq!(own_log_in(&dir), OwnLog::Journal);
        // A `.local` beats every `.conf`, and fail2ban.d's `.local` beats it.
        std::fs::write(
            dir.join("fail2ban.local"),
            "[Definition]\nlogtarget = /var/log/f2b/server.log\n",
        )
        .unwrap();
        assert_eq!(
            own_log_in(&dir),
            OwnLog::File("/var/log/f2b/server.log".into())
        );
        std::fs::write(
            dir.join("fail2ban.d/zz.local"),
            "[Definition]\nlogtarget = SYSLOG[format=\"%(relname)s: %(message)s\"]\n",
        )
        .unwrap();
        assert_eq!(own_log_in(&dir), OwnLog::Journal, "options are not a path");

        // `[Definition]` beats `[DEFAULT]` even in an earlier file.
        let dir = scratch("own-log-sections");
        std::fs::write(
            dir.join("fail2ban.conf"),
            "[DEFAULT]\nlogtarget = /a.log\n[Definition]\nlogtarget = /b.log\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("fail2ban.local"),
            "[DEFAULT]\nlogtarget = /c.log\n",
        )
        .unwrap();
        assert_eq!(own_log_in(&dir), OwnLog::File("/b.log".into()));
        // And another section's `logtarget` is not the server's.
        std::fs::write(dir.join("fail2ban.local"), "[Thread]\nlogtarget = /d.log\n").unwrap();
        assert_eq!(own_log_in(&dir), OwnLog::File("/b.log".into()));
    }

    #[test]
    fn the_recidive_jail_reads_the_servers_own_log() {
        let mut every = config();
        every.jails.push(Fail2banJail::Recidive);
        let shipped = render_jail_file(&every, &[22], 2222, &default_log());
        let recidive = section(&shipped, "recidive");
        assert!(recidive.contains("enabled = true\n"), "{recidive}");
        // jail.conf's own logpath is right as shipped: nothing is repeated.
        assert!(
            !recidive.contains("logpath") && !recidive.contains("backend"),
            "{recidive}"
        );

        let moved = render_jail_file(&every, &[22], 2222, &OwnLog::File("/srv/f2b.log".into()));
        assert!(section(&moved, "recidive").contains("logpath = /srv/f2b.log\n"));
        let journal = render_jail_file(&every, &[22], 2222, &OwnLog::Journal);
        let recidive = section(&journal, "recidive");
        assert!(recidive.contains("backend = systemd\n") && !recidive.contains("logpath"));
    }

    #[test]
    fn the_servers_own_log_is_made_when_missing_and_left_alone_when_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("own-log-file");
        let path = dir.join("fail2ban.log");
        let own = OwnLog::File(path.to_string_lossy().into_owned());
        ensure_own_log(&own).unwrap();
        assert!(path.is_file());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::write(&path, "2026-09-25 NOTICE [sshd] Ban 203.0.113.9\n").unwrap();
        ensure_own_log(&own).unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("Ban 203.0.113.9"));
        assert!(ensure_own_log(&OwnLog::Journal).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Cloudflare is exempt where the address comes from a site's log, and
    /// only there: an SSH or panel attacker's address is their own.
    #[test]
    fn cloudflare_is_never_banned_from_a_site_log() {
        let file = render_jail_file(&config(), &[22], 2222, &default_log());
        for web in ["snpanel-wordpress", "nginx-http-auth"] {
            let jail = section(&file, web);
            for range in CLOUDFLARE {
                assert!(jail.contains(range), "{web} misses {range}");
            }
            // The jail's own list replaces the default one, so it carries it.
            assert!(jail.contains("203.0.113.7/32"), "{web}");
        }
        for other in ["DEFAULT", "sshd", "snpanel-login"] {
            assert!(!section(&file, other).contains("104.16.0.0/13"), "{other}");
        }
        assert_eq!(CLOUDFLARE.len(), 22);
        for range in CLOUDFLARE {
            assert!(IpOrCidr::parse(range).is_ok(), "{range}");
        }
    }

    /// Nothing from the settings reaches the file as text: every value is a
    /// number or a parsed address, and nothing can start a line of its own.
    #[test]
    fn a_setting_cannot_add_a_line() {
        let file = render_jail_file(&config(), &[22], 2222, &default_log());
        for line in file.lines() {
            let key = line.split(" = ").next().unwrap_or_default();
            assert!(
                line.is_empty()
                    || line.starts_with('#')
                    || line.starts_with('[')
                    || matches!(
                        key,
                        "ignoreip"
                            | "bantime"
                            | "findtime"
                            | "maxretry"
                            | "banaction"
                            | "banaction_allports"
                            | "enabled"
                            | "port"
                            | "backend"
                            | "filter"
                            | "logpath"
                    ),
                "unexpected line: {line}"
            );
        }
    }

    #[test]
    fn the_login_filter_is_pinned_to_the_panel_uid() {
        let filter = render_login_filter(997);
        assert!(filter.contains("journalmatch = SYSLOG_IDENTIFIER=snpanel-auth _UID=997\n"));
        assert!(filter.contains("failregex = ^%(__prefix_line)slogin failure from <ADDR>$\n"));
        assert!(filter.contains("_daemon = snpanel-auth\n"));
    }

    #[test]
    fn the_wordpress_filter_takes_the_address_from_the_first_field() {
        let line = WORDPRESS_FILTER_TEXT
            .lines()
            .find(|l| l.starts_with("failregex = "))
            .unwrap();
        assert!(line.starts_with("failregex = ^<ADDR> "), "{line}");
        assert!(line.contains("wp-login\\.php") && line.ends_with("\" 200\\s"));
        // A `%` would be read as ConfigParser interpolation.
        assert!(!WORDPRESS_FILTER_TEXT.contains('%'));
    }

    #[test]
    fn the_status_is_read_from_what_fail2ban_prints() {
        let list = "Status\n|- Number of jail:\t3\n`- Jail list:\trecidive, snpanel-login, sshd\n";
        assert_eq!(parse_jail_list(list), ["recidive", "snpanel-login", "sshd"]);
        assert!(parse_jail_list("Status\n|- Number of jail:\t0\n`- Jail list:\t\n").is_empty());
        // A name fail2ban would never print is not passed back to it.
        assert_eq!(parse_jail_list("`- Jail list:\tsshd, a b, $(x)"), ["sshd"]);

        let sshd = "Status for the jail: sshd
|- Filter
|  |- Currently failed:\t2
|  |- Total failed:\t17
|  `- Journal matches:\t_SYSTEMD_UNIT=ssh.service + _COMM=sshd
`- Actions
   |- Currently banned:\t2
   |- Total banned:\t5
   `- Banned IP list:\t198.51.100.7 2001:db8::5
";
        assert_eq!(
            parse_jail_status(sshd),
            JailStatus {
                currently_failed: 2,
                total_failed: 17,
                currently_banned: 2,
                total_banned: 5,
                banned: vec!["198.51.100.7".into(), "2001:db8::5".into()],
            }
        );
        assert_eq!(parse_jail_status("").banned, Vec::<String>::new());
        // Only addresses: whatever else shares the line - a hostname, were
        // fail2ban ever set to resolve them - is not handed to the page as one.
        assert_eq!(
            parse_jail_status("`- Banned IP list:\t198.51.100.7 host.example 2001:db8::5 -\n")
                .banned,
            ["198.51.100.7", "2001:db8::5"]
        );
        assert_eq!(parse_version("Fail2Ban v1.1.0\n").as_deref(), Some("1.1.0"));
        assert_eq!(parse_version("nothing here"), None);
        // A word that merely starts with a v is not a version.
        assert_eq!(parse_version("Fail2Ban version unknown"), None);
    }
}
