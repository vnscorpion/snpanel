//! `ops::web` - LiteSpeed and its Apache standby (Hosting Edition).
//!
//! Both web servers run and read the same vhosts; one nftables table decides
//! which answers the public 80/443 (`snpanel-webswitch`), and a watchdog
//! (`snpanel-webwatch`) moves it to Apache when LiteSpeed stops answering or
//! its licence runs out. It never moves it back on its own: that is the
//! administrator's call, made here once LiteSpeed answers again.

use std::io::Read;
use std::path::Path;

use serde_json::{json, Value};
use snpanel_ipc::{HelperErrorKind, HelperResponse, WebServer};

use crate::exec;

const STATE: &str = "/var/lib/snpanel/webserver";
const LOG: &str = "/var/log/snpanel-webswitch.log";
const SWITCH: &str = "/usr/local/sbin/snpanel-webswitch";
const LSWS_CTRL: &str = "/usr/local/lsws/bin/lswsctrl";
const LSWS_BIN: &str = "/usr/local/lsws/bin/lshttpd";
const LSWS_VERSION: &str = "/usr/local/lsws/VERSION";
const ADMIN_PHP: &str = "/usr/local/lsws/admin/fcgi-bin/admin_php5";
const HTPASSWD_PHP: &str = "/usr/local/lsws/admin/misc/htpasswd.php";
const HTPASSWD: &str = "/usr/local/lsws/admin/conf/htpasswd";
/// LiteSpeed WebAdmin's port, as LiteSpeed installs it.
pub const ADMIN_PORT: u16 = 7080;

fn require_lsws() -> Result<(), HelperResponse> {
    if Path::new(LSWS_CTRL).exists() && Path::new(SWITCH).exists() {
        Ok(())
    } else {
        Err(HelperResponse::failed(
            HelperErrorKind::NotFound,
            "LiteSpeed Enterprise is not installed on this server".to_string(),
        ))
    }
}

/// The port each server answers on while it is the standby or the live one.
fn http_port(server: WebServer) -> u16 {
    match server {
        WebServer::Lsws => 9080,
        WebServer::Apache => 8080,
    }
}

/// Whether a server answers the watchdog's own probe (a static file, so a
/// cold PHP does not count as down).
fn answers(server: WebServer) -> bool {
    let url = format!(
        "http://127.0.0.1:{}/.well-known/acme-challenge/snpanel-health",
        http_port(server)
    );
    matches!(
        exec::run(&[
            "curl", "-s", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}",
            "-H", "Host: snpanel-default.invalid", &url,
        ]),
        Ok(o) if o.stdout.trim() == "200"
    )
}

fn unit_active(unit: &str) -> bool {
    matches!(exec::run(&["systemctl", "is-active", "--quiet", unit]), Ok(o) if o.ok())
}

/// The switch log's last failover and last switch, as `{at, text}`.
///
/// Lines look like `2026-09-28 14:02:57.891 FAILOVER to apache: <reason>`
/// and `2026-09-28 14:53:38.512 switch -> lsws (80->9080, 443->9443)`.
pub fn parse_log(log: &str) -> (Option<Value>, Option<Value>) {
    let split = |line: &str| {
        let mut parts = line.splitn(3, ' ');
        let (d, t, rest) = (parts.next()?, parts.next()?, parts.next()?);
        Some(json!({ "at": format!("{d} {t}"), "text": rest.trim() }))
    };
    let failover = log
        .lines()
        .rev()
        .find(|l| l.contains(" FAILOVER "))
        .and_then(split);
    let switch = log
        .lines()
        .rev()
        .find(|l| l.contains(" switch -> "))
        .and_then(split);
    (failover, switch)
}

/// The lines of `lshttpd -V` that are about the licence, timestamps off.
pub fn parse_licence(version_output: &str) -> Vec<String> {
    version_output
        .lines()
        .map(str::trim)
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            lower.contains("licen") || lower.contains("expire") || lower.contains("serial")
        })
        .map(|l| {
            // "2026-09-28 15:46:00.705428 [NOTICE] [T0] text" -> "text"
            l.rsplit_once("] ").map_or(l, |(_, text)| text).to_string()
        })
        .collect()
}

fn tail(path: &str, max: u64) -> String {
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len > max {
        use std::io::Seek;
        let _ = f.seek(std::io::SeekFrom::Start(len - max));
    }
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    s
}

/// `web-status`.
pub fn status() -> HelperResponse {
    if let Err(r) = require_lsws() {
        return r;
    }
    let live = std::fs::read_to_string(STATE)
        .ok()
        .and_then(|s| WebServer::parse(s.trim()).ok())
        .unwrap_or(WebServer::Apache);
    let (failover, switch) = parse_log(&tail(LOG, 64 * 1024));
    let licence = exec::run(&[LSWS_BIN, "-V"])
        .map(|o| parse_licence(&format!("{}\n{}", o.stdout, o.stderr)))
        .unwrap_or_default();
    let licence_ok = !licence.is_empty()
        && !licence.iter().any(|l| {
            let lower = l.to_ascii_lowercase();
            lower.contains("expired") || lower.contains("invalid") || lower.contains("not valid")
        });
    let admin_listening = matches!(
        exec::run(&["ss", "-Hltn", &format!("sport = :{ADMIN_PORT}")]),
        Ok(o) if o.ok() && !o.stdout.trim().is_empty()
    );
    let admin_open = matches!(
        exec::run(&["nft", "list", "set", "inet", "snpanel", "open_tcp"]),
        Ok(o) if o.ok() && set_has_port(&o.stdout, ADMIN_PORT)
    );
    HelperResponse::with_stdout(format!(
        "{}\n",
        json!({
            "live": live.as_str(),
            "lsws": {
                "active": unit_active("lshttpd"),
                "answering": answers(WebServer::Lsws),
                "version": std::fs::read_to_string(LSWS_VERSION).map(|s| s.trim().to_string()).unwrap_or_default(),
                "licence": licence,
                "licence_ok": licence_ok,
            },
            "apache": {
                "active": unit_active("httpd"),
                "answering": answers(WebServer::Apache),
            },
            "watchdog_active": unit_active("snpanel-webwatch"),
            "last_failover": failover,
            "last_switch": switch,
            "admin": {
                "port": ADMIN_PORT,
                "listening": admin_listening,
                "open": admin_open,
            },
        })
    ))
}

/// Whether an nftables `elements = { ... }` list holds a port, alone or in a
/// range.
pub fn set_has_port(nft_set: &str, port: u16) -> bool {
    let Some(start) = nft_set.find("elements = {") else {
        return false;
    };
    let body = &nft_set[start + "elements = {".len()..];
    let body = &body[..body.find('}').unwrap_or(body.len())];
    body.split(',')
        .map(str::trim)
        .any(|e| match e.split_once('-') {
            Some((a, b)) => match (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                (Ok(a), Ok(b)) => (a..=b).contains(&port),
                _ => false,
            },
            None => e.parse::<u16>() == Ok(port),
        })
}

/// `web-switch`.
pub fn switch(to: WebServer) -> HelperResponse {
    if let Err(r) = require_lsws() {
        return r;
    }
    if !answers(to) {
        let what = match to {
            WebServer::Lsws => "LiteSpeed is not answering on its port; start or restart it first",
            WebServer::Apache => "Apache is not answering on its standby port; start it first",
        };
        return HelperResponse::failed(HelperErrorKind::BadRequest, what.to_string());
    }
    let out = exec::run(&[SWITCH, to.as_str()]);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("snpanel-webswitch", out);
    }
    // The watchdog reads the state file every second; it takes it from here.
    HelperResponse::with_stdout(format!("live: {}\n", to.as_str()))
}

/// `lsws-restart`. Through systemd, so LiteSpeed stays in its own unit's
/// cgroup (see `waf_apache::apply`).
pub fn lsws_restart() -> HelperResponse {
    if let Err(r) = require_lsws() {
        return r;
    }
    exec::respond(
        "systemctl reload-or-restart lshttpd",
        exec::run(&["systemctl", "reload-or-restart", "lshttpd"]),
    )
}

/// A password from the kernel's CSPRNG: 20 characters of [A-Za-z0-9].
fn random_password() -> std::io::Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut bytes = [0u8; 64];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    // Rejection sampling keeps every character equally likely.
    let limit = 256 - (256 % ALPHABET.len());
    let out: String = bytes
        .iter()
        .filter(|b| usize::from(**b) < limit)
        .take(20)
        .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
        .collect();
    if out.len() == 20 {
        Ok(out)
    } else {
        Err(std::io::Error::other("not enough randomness"))
    }
}

/// `lsws-admin-password`. The password reaches LiteSpeed's hasher through
/// its environment, never argv; the file keeps LiteSpeed's owner and mode.
pub fn lsws_admin_password() -> HelperResponse {
    if let Err(r) = require_lsws() {
        return r;
    }
    let password = match random_password() {
        Ok(p) => p,
        Err(e) => return HelperResponse::failed(HelperErrorKind::Internal, e.to_string()),
    };
    let hashed = exec::run_with_env(
        &[ADMIN_PHP, "-q", HTPASSWD_PHP],
        &[("LSWS_ADMIN_PASS", &password)],
    );
    // One token, the crypt(3) hash; anything else is an error message.
    let hash = match &hashed {
        Ok(o) if o.ok() && o.stdout.split_whitespace().count() == 1 => o.stdout.trim().to_string(),
        _ => return exec::respond("htpasswd.php", hashed),
    };
    let line = format!("admin:{hash}\n");
    if let Err(e) = crate::ops::nginx::write_atomic(Path::new(HTPASSWD), line.as_bytes(), 0o600) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {HTPASSWD}: {e}"),
        );
    }
    let _ = exec::run(&["chown", "lsadm:lsadm", HTPASSWD]);
    HelperResponse::with_stdout(format!(
        "{}\n",
        json!({ "username": "admin", "password": password })
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_SAMPLE: &str = "2026-09-28 07:35:58.015 switch -> lsws (80->9080, 443->9443)
2026-09-28 14:02:57.888 switch -> apache (80->8080, 443->8443)
2026-09-28 14:02:57.891 FAILOVER to apache: lsws not answering (3 x, last=000)
2026-09-28 14:53:38.512 switch -> lsws (80->9080, 443->9443)
";

    #[test]
    fn the_last_failover_and_switch_are_read_from_the_log() {
        let (failover, switch) = parse_log(LOG_SAMPLE);
        let failover = failover.unwrap();
        assert_eq!(failover["at"], "2026-09-28 14:02:57.891");
        assert_eq!(
            failover["text"],
            "FAILOVER to apache: lsws not answering (3 x, last=000)"
        );
        assert_eq!(
            switch.unwrap()["text"],
            "switch -> lsws (80->9080, 443->9443)"
        );
        assert_eq!(parse_log(""), (None, None));
    }

    #[test]
    fn licence_lines_lose_their_timestamps() {
        let out = "2026-09-28 15:46:00.705428 [NOTICE] [T0] Memory size is: 6060668KB.\n[OK] Your trial license key will expire in 13 days!\n";
        assert_eq!(
            parse_licence(out),
            ["Your trial license key will expire in 13 days!"]
        );
    }

    #[test]
    fn ports_are_found_in_nft_sets_and_ranges() {
        let set = "table inet snpanel {\n set open_tcp {\n type inet_service\n flags interval\n elements = { 21, 7080, 30000-30100 }\n }\n}";
        assert!(set_has_port(set, 7080));
        assert!(set_has_port(set, 30050));
        assert!(!set_has_port(set, 708));
        assert!(!set_has_port("set open_tcp { type inet_service }", 7080));
    }

    #[test]
    fn passwords_are_twenty_unambiguous_characters() {
        let a = random_password().unwrap();
        let b = random_password().unwrap();
        assert_eq!(a.len(), 20);
        assert_ne!(a, b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !"0O1lI".contains(c)));
    }
}
