//! `ops::dns` - the DNS Manager addon: PowerDNS Authoritative on this server.
//!
//! PowerDNS answers port 53 from a SQLite database and is driven through its
//! HTTP API, which listens on the loopback only. The panel reads the API key
//! from a file only it and root can read; everything about zones and records
//! goes through that API, never through this helper - there is nothing root
//! about a DNS record.
//!
//! Installing it again is harmless: the database and the key are kept, the
//! configuration is rewritten (an address that has since appeared is bound).

use std::io::Read;
use std::path::Path;

use serde_json::json;
use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::Family;

use super::packages;
use super::Context;
use crate::exec;

/// Where the panel reads the API key: root:snpanel 0640.
pub const API_KEY_FILE: &str = "/etc/snpanel/pdns-api-key";
/// The API's port, on 127.0.0.1 only.
pub const API_PORT: u16 = 8081;
const MARKER: &str = "# SNPANEL MANAGED - DNS Manager addon";
/// The schema PowerDNS 4.7+ ships for gsqlite3, embedded because a
/// `tsflags=nodocs` install leaves the documentation - and the schema with
/// it - out.
const SCHEMA: &str = include_str!("pdns-schema.sqlite3.sql");

/// Paths and names, per family.
struct Layout {
    packages: &'static [&'static str],
    conf: &'static str,
    db_dir: &'static str,
    service: &'static str,
    user: &'static str,
}

fn layout() -> Layout {
    match packages::family() {
        Family::Rhel => Layout {
            packages: &["pdns", "pdns-backend-sqlite", "sqlite"],
            conf: "/etc/pdns/pdns.conf",
            db_dir: "/var/lib/pdns",
            service: "pdns",
            user: "pdns",
        },
        _ => Layout {
            packages: &["pdns-server", "pdns-backend-sqlite3", "sqlite3"],
            conf: "/etc/powerdns/pdns.conf",
            db_dir: "/var/lib/powerdns",
            service: "pdns",
            user: "pdns",
        },
    }
}

fn db_path(l: &Layout) -> String {
    format!("{}/pdns.sqlite3", l.db_dir)
}

fn installed(l: &Layout) -> bool {
    ["/usr/sbin/pdns_server", "/usr/bin/pdns_server"]
        .iter()
        .any(|p| Path::new(p).is_file())
        && Path::new(l.conf).exists()
}

fn failed(kind: HelperErrorKind, message: impl Into<String>) -> HelperResponse {
    HelperResponse::failed(kind, message)
}

fn step(argv: &[&str]) -> Result<(), HelperResponse> {
    let result = exec::run(argv);
    if matches!(&result, Ok(o) if o.ok()) {
        Ok(())
    } else {
        Err(exec::respond(&argv.join(" "), result))
    }
}

/// The key from last time, or a new one: 32 random bytes, hex.
fn api_key() -> std::io::Result<String> {
    if let Ok(existing) = std::fs::read_to_string(API_KEY_FILE) {
        let existing = existing.trim();
        if existing.len() >= 32 && existing.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(existing.to_string());
        }
    }
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether anything but PowerDNS already holds UDP port 53 -
/// systemd-resolved's stub on 127.0.0.53, typically - in which case the
/// wildcard cannot be bound and the global addresses are bound one by one.
fn port_53_taken_by_other() -> bool {
    match exec::run(&["ss", "-Hlnup", "sport = :53"]) {
        Ok(o) if o.ok() => o
            .stdout
            .lines()
            .any(|line| !line.trim().is_empty() && !line.contains("pdns")),
        _ => false,
    }
}

/// `ip -o addr show scope global`: the addresses, v4 and v6.
fn global_addresses() -> Vec<String> {
    let Ok(o) = exec::run(&["ip", "-o", "addr", "show", "scope", "global"]) else {
        return Vec::new();
    };
    parse_addresses(&o.stdout)
}

fn parse_addresses(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = parts.iter().position(|t| *t == "inet" || *t == "inet6") {
            if let Some(addr) = parts.get(i + 1).and_then(|a| a.split('/').next()) {
                if addr.parse::<std::net::IpAddr>().is_ok() && !out.iter().any(|a| a == addr) {
                    out.push(addr.to_string());
                }
            }
        }
    }
    out
}

fn ipv6_enabled() -> bool {
    std::fs::read_to_string("/proc/net/if_inet6").is_ok_and(|t| !t.trim().is_empty())
}

/// What `local-address` says.
fn local_addresses(taken: bool, ipv6: bool, globals: &[String]) -> String {
    if taken && !globals.is_empty() {
        let mut list = globals.to_vec();
        list.push("127.0.0.1".to_string());
        return list.join(", ");
    }
    if ipv6 {
        "0.0.0.0, ::".to_string()
    } else {
        "0.0.0.0".to_string()
    }
}

fn render_conf(db: &str, key: &str, local: &str) -> String {
    format!(
        "{MARKER}\n\
         # Rewritten when the addon is installed; zones live in the database.\n\
         launch=gsqlite3\n\
         gsqlite3-database={db}\n\
         gsqlite3-pragma-foreign-keys=yes\n\
         local-address={local}\n\
         local-port=53\n\
         api=yes\n\
         api-key={key}\n\
         webserver=yes\n\
         webserver-address=127.0.0.1\n\
         webserver-port={API_PORT}\n\
         webserver-allow-from=127.0.0.1,::1\n\
         default-ttl=3600\n\
         max-tcp-connections=100\n\
         version-string=anonymous\n\
         loglevel=4\n"
    )
}

/// The database, made from the schema when it is not there yet.
fn ensure_database(l: &Layout) -> Result<(), HelperResponse> {
    let db = db_path(l);
    std::fs::create_dir_all(l.db_dir).map_err(|e| {
        failed(HelperErrorKind::Internal, format!("creating {}: {e}", l.db_dir))
    })?;
    if !Path::new(&db).exists() {
        let result = exec::run_with_stdin(&["sqlite3", &db], Some(SCHEMA.as_bytes()));
        if !matches!(&result, Ok(o) if o.ok()) {
            let _ = std::fs::remove_file(&db);
            return Err(exec::respond("creating the PowerDNS database", result));
        }
    }
    // SQLite writes its journal beside the database, so the directory is
    // PowerDNS's too.
    let owner = format!("{0}:{0}", l.user);
    step(&["chown", &owner, l.db_dir, &db])?;
    step(&["chmod", "0750", l.db_dir])?;
    step(&["chmod", "0640", &db])?;
    Ok(())
}

fn write_key(key: &str) -> Result<(), HelperResponse> {
    let path = Path::new(API_KEY_FILE);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    super::nginx::write_atomic(path, format!("{key}\n").as_bytes(), 0o640)
        .map_err(|e| failed(HelperErrorKind::Internal, format!("writing {API_KEY_FILE}: {e}")))?;
    let owner = format!("root:{}", crate::peercred::PANEL_USER);
    step(&["chown", &owner, API_KEY_FILE])
}

fn write_conf(l: &Layout, key: &str) -> Result<(), HelperResponse> {
    let conf = Path::new(l.conf);
    // The distribution's file is kept once, beside ours.
    if let Ok(existing) = std::fs::read_to_string(conf) {
        let backup = format!("{}.orig", l.conf);
        if !existing.starts_with(MARKER) && !Path::new(&backup).exists() {
            let _ = std::fs::write(&backup, existing);
        }
    }
    let local = local_addresses(port_53_taken_by_other(), ipv6_enabled(), &global_addresses());
    super::nginx::write_atomic(conf, render_conf(&db_path(l), key, &local).as_bytes(), 0o640)
        .map_err(|e| failed(HelperErrorKind::Internal, format!("writing {}: {e}", l.conf)))?;
    let owner = format!("root:{}", l.user);
    step(&["chown", &owner, l.conf])
}

fn active(service: &str) -> bool {
    matches!(exec::run(&["systemctl", "is-active", "--quiet", service]), Ok(o) if o.ok())
}

fn listening(filter: &str, flag: &str) -> bool {
    matches!(exec::run(&["ss", flag, filter]), Ok(o) if o.ok() && !o.stdout.trim().is_empty())
}

fn wait_for_api() -> bool {
    let filter = format!("sport = :{API_PORT}");
    for _ in 0..30 {
        if listening(&filter, "-Hlnt") {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    false
}

/// `dns-install`.
pub fn install(ctx: &Context) -> HelperResponse {
    let l = layout();
    let mut out = String::new();
    if !installed(&l) {
        if let Ok(o) = packages::update_index() {
            out.push_str(&o.stdout);
        }
        match packages::install_packages(l.packages) {
            Ok(o) if o.ok() => out.push_str(&o.stdout),
            other => return exec::respond(&format!("installing {}", l.packages.join(" ")), other),
        }
    }
    let key = match api_key() {
        Ok(k) => k,
        Err(e) => return failed(HelperErrorKind::Internal, format!("making the API key: {e}")),
    };
    if let Err(r) = ensure_database(&l)
        .and_then(|()| write_key(&key))
        .and_then(|()| write_conf(&l, &key))
    {
        return r;
    }
    for argv in [
        ["systemctl", "enable", l.service],
        ["systemctl", "restart", l.service],
    ] {
        if let Err(r) = step(&argv) {
            return r;
        }
    }
    if !wait_for_api() {
        return failed(
            HelperErrorKind::CommandFailed,
            format!(
                "PowerDNS was started but its API does not answer; see journalctl -u {}",
                l.service
            ),
        );
    }
    for protocol in [
        snpanel_osabi::firewall::rules::Protocol::Udp,
        snpanel_osabi::firewall::rules::Protocol::Tcp,
    ] {
        let opened = super::fwrules::add_rule(
            ctx,
            snpanel_osabi::firewall::rules::Action::Allow,
            None,
            snpanel_core::Port::new(53).ok(),
            protocol,
        );
        if !opened.ok {
            return opened;
        }
    }
    out.push_str("PowerDNS installed and answering on port 53\n");
    HelperResponse::with_stdout(out)
}

/// `dns-stop`: the service stopped and off at boot; the zones stay.
pub fn stop() -> HelperResponse {
    let l = layout();
    if !installed(&l) {
        return HelperResponse::ok();
    }
    match step(&["systemctl", "disable", "--now", l.service]) {
        Ok(()) => HelperResponse::with_stdout("PowerDNS stopped; the zones are kept\n"),
        Err(r) => r,
    }
}

/// `dns-status`: read-only, JSON.
pub fn status() -> HelperResponse {
    let l = layout();
    let version = exec::run(&["pdns_server", "--version"])
        .ok()
        .map(|o| format!("{}{}", o.stdout, o.stderr))
        .and_then(|t| {
            t.lines()
                .find_map(|line| line.split("PowerDNS Authoritative Server ").nth(1))
                .map(|v| v.split_whitespace().next().unwrap_or("").to_string())
        });
    let body = json!({
        "installed": installed(&l),
        "running": active(l.service),
        "listening": listening("sport = :53", "-Hlnu"),
        "api": listening(&format!("sport = :{API_PORT}"), "-Hlnt"),
        "version": version,
        "key": Path::new(API_KEY_FILE).exists(),
    });
    HelperResponse::with_stdout(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_binds_the_api_to_the_loopback_only() {
        let text = render_conf("/var/lib/pdns/pdns.sqlite3", "ab12", "0.0.0.0, ::");
        assert!(text.starts_with(MARKER));
        assert!(text.contains("\nwebserver-address=127.0.0.1\n"));
        assert!(text.contains("\nwebserver-allow-from=127.0.0.1,::1\n"));
        assert!(text.contains("\nlaunch=gsqlite3\n"));
        assert!(text.contains("\napi-key=ab12\n"));
        assert!(text.contains("\nlocal-address=0.0.0.0, ::\n"));
    }

    #[test]
    fn a_taken_port_binds_the_global_addresses() {
        let globals = vec!["203.0.113.5".to_string(), "2001:db8::5".to_string()];
        assert_eq!(
            local_addresses(true, true, &globals),
            "203.0.113.5, 2001:db8::5, 127.0.0.1"
        );
        assert_eq!(local_addresses(false, true, &globals), "0.0.0.0, ::");
        assert_eq!(local_addresses(false, false, &globals), "0.0.0.0");
        // Nothing to bind one by one: the wildcard, and the journal says why.
        assert_eq!(local_addresses(true, false, &[]), "0.0.0.0");
    }

    #[test]
    fn addresses_are_read_from_ip_addr() {
        let text = "2: eth0    inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0\\\n\
                    2: eth0    inet6 2001:db8::5/64 scope global \\\n\
                    3: docker0    inet 172.17.0.1/16 scope global docker0\\\n";
        assert_eq!(
            parse_addresses(text),
            ["203.0.113.5", "2001:db8::5", "172.17.0.1"]
        );
    }

    #[test]
    fn the_schema_makes_the_tables_powerdns_reads() {
        for table in ["domains", "records", "domainmetadata", "cryptokeys", "comments"] {
            assert!(SCHEMA.contains(&format!("CREATE TABLE {table} (")), "{table}");
        }
    }
}
