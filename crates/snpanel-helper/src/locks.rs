//! Which operations take turns.
//!
//! The helper answers requests side by side - as the Python's one `sudo`
//! process to a request always did - so a PHP install or a `docker pull`
//! no longer holds up the service-status poll, a file listing or a login.
//! What must not overlap is two changes to one shared piece of the system:
//! two vhost writes each followed by `nginx -t` and a reload, two rewrites of
//! the firewall's ruleset, two runs of the package manager, two accounts
//! added to `/etc/passwd`. Each such piece has a lock, and an operation holds
//! the lock of everything it changes. Locks are always taken in the order of
//! [`Resource`], so two operations can never each hold what the other waits
//! for. Reads, one site's files, a scan and a terminal command hold nothing.
//!
//! An operation this table does not name holds every lock: a new one is safe
//! before anyone has thought about it, and `every_operation_is_placed`
//! fails until somebody has.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// A shared piece of the system, in the order locks are taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resource {
    /// apt or dnf, and the installers that stand in for them.
    Packages,
    /// `/etc/passwd`, `/etc/shadow`, `/etc/group`.
    Accounts,
    /// Unit files, `daemon-reload`, starting and stopping services.
    Systemd,
    /// PHP's ini files and the PHP-FPM pools.
    Php,
    /// nginx's configuration, its reload, and certbot, which reloads it.
    Nginx,
    /// The nftables ruleset and fail2ban.
    Firewall,
    /// The crontabs.
    Cron,
    /// LMD's signatures and its monitor.
    Malware,
}

const ALL: &[Resource] = &[
    Resource::Packages,
    Resource::Accounts,
    Resource::Systemd,
    Resource::Php,
    Resource::Nginx,
    Resource::Firewall,
    Resource::Cron,
    Resource::Malware,
];

static LOCKS: [Mutex<()>; 8] = [const { Mutex::new(()) }; 8];

/// The resources `op` changes, or `None` for an operation nobody has placed.
pub fn placed(op: &str) -> Option<&'static [Resource]> {
    use Resource::*;
    Some(match op {
        // Reads, one site's or application's files, scans, commands: nothing
        // shared changes, and some of them take minutes.
        "site-app-volume-usage"
        | "site-app-compose-pull"
        | "site-app-compose-ps"
        | "site-app-logs"
        | "site-app-install-deps"
        | "site-app-pull"
        | "site-app-dir-ensure"
        | "site-app-import"
        | "site-app-export"
        | "site-app-rename"
        | "site-archive-extract"
        | "site-file-write"
        | "site-chmod"
        | "site-file-search"
        | "site-file-install"
        | "site-populate"
        | "site-document-root-ensure"
        | "site-log-read"
        | "site-log-clear"
        | "site-logs-delete"
        | "site-logs-read-many"
        | "mkdir-site"
        | "fix-permissions"
        | "wp"
        | "wp-site"
        | "terminal-exec"
        | "firewall-status"
        | "firewall-list"
        | "firewall-blocklist-status"
        | "service-status"
        | "updates-status"
        | "waf-status"
        | "waf-crs-status"
        | "waf-default-rules"
        | "waf-custom-rules"
        | "clamav-status"
        | "maldet-status"
        | "fail2ban-status"
        | "ipv6-status"
        | "time-status"
        | "time-sync"
        | "cron-list"
        | "ssh-ports"
        | "ssl-cert-info"
        | "panel-ssl-domains"
        | "docker-status"
        | "docker-prune"
        | "node-list"
        | "fastcgi-cache-clear"
        | "maldet-scan"
        | "malware-scan-server"
        | "selinux-restore-site"
        | "selinux-port-add" => &[],

        // The package manager, and what an install goes on to configure.
        "updates-os-run" | "node-install" | "certbot-dns-cloudflare-install" => &[Packages],
        "updates-os-auto" | "docker-install" => &[Packages, Systemd],
        "php-install" => &[Packages, Systemd, Php],
        "waf-install" => &[Packages, Nginx],
        "clamav-install" => &[Packages, Systemd, Malware],
        "maldet-install" => &[Packages, Malware],
        "fail2ban-install" => &[Packages, Systemd, Firewall],
        "updates-panel-run" => &[Packages, Systemd],

        // Accounts, and a site's runtime, which is an account and a pool.
        "panel-user-ensure" | "panel-user-delete" | "panel-user-password" => &[Accounts],
        "site-runtime-ensure" | "site-runtime-move" | "site-runtime-delete" | "rm-site" => {
            &[Accounts, Systemd, Php]
        }

        // Units and services.
        "service-control"
        | "daemon-reload"
        | "site-app-control"
        | "site-app-write"
        | "site-app-delete"
        | "certbot-auto-renew-install"
        | "mariadb-retune" => &[Systemd],
        "clamav-control" => &[Systemd, Malware],
        "firewall-blocklist-timer-install" => &[Systemd, Firewall],

        // PHP.
        "php-opcache-set" | "php-config-write" | "php-tune-write" => &[Systemd, Php],
        "php-pools-retune" => &[Systemd, Php],

        // nginx, and what reloads it.
        "nginx-write-site"
        | "nginx-test"
        | "nginx-reload"
        | "nginx-custom-write"
        | "nginx-custom-delete"
        | "nginx-upgrade-map-ensure"
        | "certbot-issue"
        | "certbot-renew"
        | "certbot-renew-soon"
        | "certbot-delete"
        | "cloudflare-ssl-issue"
        | "panel-ssl-selfsigned"
        | "panel-ssl-use-domain"
        | "panel-ssl-install"
        | "panel-sni-sync"
        | "panel-url-set"
        | "waf-site-save"
        | "waf-site-delete"
        | "waf-crs-mode"
        | "waf-custom-save"
        | "waf-update"
        | "http-flood-zones-save"
        | "ipv6-enable"
        | "ipv6-disable"
        | "ipv6-apply" => &[Nginx],

        // The firewall.
        "firewall-apply"
        | "firewall-flush"
        | "firewall-migrate-nft"
        | "firewall-migrate"
        | "firewall-allow-ip"
        | "firewall-deny-ip"
        | "firewall-allow-port"
        | "firewall-panel-allow-port"
        | "firewall-delete"
        | "firewall-enable"
        | "firewall-disable"
        | "firewall-blocklist-run"
        | "fail2ban-configure"
        | "fail2ban-ban"
        | "fail2ban-unban" => &[Firewall],
        "fail2ban-stop" => &[Systemd, Firewall],

        "cron-write" => &[Cron],
        "maldet-update-sigs" | "maldet-monitor" => &[Malware],

        _ => return None,
    })
}

/// The locks an operation holds while it runs; they are let go when this is
/// dropped, in the reverse of the order they were taken.
pub struct Held(Vec<MutexGuard<'static, ()>>);

impl Drop for Held {
    fn drop(&mut self) {
        // A `Vec` would drop them front to back.
        while let Some(guard) = self.0.pop() {
            drop(guard);
        }
    }
}

/// Take the locks of everything `op` changes, waiting for each in turn.
pub fn hold(op: &str) -> Held {
    let resources = placed(op).unwrap_or(ALL);
    let mut order: Vec<Resource> = resources.to_vec();
    order.sort();
    order.dedup();
    // A lock whose holder panicked still guards the same resource: whatever
    // that operation left half done, the next one is no safer running beside
    // it, so the poison is not a reason to stop serving.
    Held(
        order
            .into_iter()
            .map(|r| {
                LOCKS[r as usize]
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
            })
            .collect(),
    )
}

impl Held {
    /// How many locks are held - for the tests.
    #[cfg(test)]
    fn count(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every operation name the protocol has, read from `op_name` itself.
    fn operation_names() -> BTreeSet<&'static str> {
        let src = include_str!("../../snpanel-ipc/src/lib.rs");
        let start = src
            .find("pub fn op_name(&self) -> &'static str {")
            .expect("op_name");
        let body = &src[start..];
        let body = &body[..body.find("\n    }\n").expect("the end of op_name")];
        body.match_indices("=> \"")
            .map(|(i, _)| {
                let rest = &body[i + 4..];
                &rest[..rest.find('"').expect("a closing quote")]
            })
            .collect()
    }

    #[test]
    fn every_operation_is_placed() {
        let names = operation_names();
        assert!(
            names.len() > 100,
            "read {} names - the parse has broken",
            names.len()
        );
        let unplaced: Vec<_> = names.iter().filter(|n| placed(n).is_none()).collect();
        assert!(
            unplaced.is_empty(),
            "placed nowhere, so they take every lock: {unplaced:?}"
        );
    }

    #[test]
    fn nothing_is_placed_that_the_protocol_does_not_have() {
        // A name spelled wrongly here would leave the real operation unplaced
        // - caught above - but a stale one would linger unnoticed.
        let names = operation_names();
        let src = include_str!("locks.rs");
        let table =
            &src[src.find("Some(match op {").unwrap()..src.find("_ => return None").unwrap()];
        let mut extra = Vec::new();
        for (i, _) in table.match_indices('"') {
            let rest = &table[i + 1..];
            let name = &rest[..rest.find('"').unwrap_or(0)];
            if !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && name.contains('-')
                && !names.contains(name)
            {
                extra.push(name.to_string());
            }
        }
        extra.sort();
        extra.dedup();
        // `wp` has no dash; it is checked by name.
        assert!(names.contains("wp"));
        assert!(extra.is_empty(), "not operations: {extra:?}");
    }

    #[test]
    fn an_unknown_operation_takes_every_lock() {
        assert_eq!(hold("no-such-operation").count(), ALL.len());
    }

    #[test]
    fn a_read_takes_nothing_and_a_write_takes_its_own() {
        assert_eq!(hold("service-status").count(), 0);
        assert_eq!(hold("nginx-reload").count(), 1);
        assert_eq!(hold("php-install").count(), 3);
    }

    #[test]
    fn two_writes_to_one_resource_take_turns_and_a_read_does_not_wait() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let first = hold("firewall-apply");
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let second = std::thread::spawn(move || {
            let _held = hold("firewall-deny-ip");
            flag.store(true, Ordering::SeqCst);
        });
        // A read and a write elsewhere go straight through meanwhile.
        drop(hold("firewall-status"));
        drop(hold("cron-write"));
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !done.load(Ordering::SeqCst),
            "the second firewall write did not wait"
        );
        drop(first);
        second.join().unwrap();
        assert!(done.load(Ordering::SeqCst));
    }

    #[test]
    fn locks_are_taken_in_one_order() {
        // Declared out of order on purpose somewhere would still be sorted by
        // `hold`; this pins that the enum's order is the one the docs give.
        let mut sorted = ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted, ALL);
    }
}
