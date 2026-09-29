//! `ops::mail` - the Email addon: Exim, Dovecot, Rspamd and the webmail.
//!
//! Exim takes mail on 25 (and from mail clients on 465 and 587), asks Rspamd
//! about what arrives, signs what leaves with each domain's DKIM key, and
//! hands a mailbox's mail to Dovecot over LMTP. Dovecot keeps it in the
//! owning account's home - `~/mail/<domain>/<mailbox>/Maildir`, as that
//! account's UNIX user, so it counts against the account's disk - and serves
//! IMAP and POP3. The webmail (BNIX Webmail) runs on 2096 with the panel's
//! certificate and signs a mailbox in through a Dovecot master user that
//! works from the loopback only.
//!
//! What is mail and who owns it is the panel's: `mail-sync` is handed the
//! whole state and writes the lookup files Exim and Dovecot read. They read
//! them on every lookup, so nothing is reloaded for a new mailbox.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use serde_json::json;
use snpanel_ipc::{HelperErrorKind, HelperResponse, MailState};
use snpanel_osabi::Family;

use super::packages;
use super::Context;
use crate::exec;

/// Exim's lookup files, the DKIM keys and the certificate copy.
pub const DIR: &str = "/etc/snpanel-mail";
const DOVECOT_DIR: &str = "/etc/dovecot/snpanel";
const USERS: &str = "/etc/dovecot/snpanel/users";
const MASTER_USERS: &str = "/etc/dovecot/snpanel/master-users";
const SPAM_SIEVE: &str = "/etc/dovecot/snpanel/spam-to-junk.sieve";
/// The webmail's settings, secrets included: root and the webmail only.
const WEBMAIL_ENV: &str = "/etc/snpanel/webmail.env";
/// The single sign-on key, for the panel to sign with.
pub const SSO_KEY_FILE: &str = "/etc/snpanel/webmail-sso-key";
const WEBMAIL_ROOT: &str = "/opt/snpanel-webmail";
const WEBMAIL_SRC: &str = "/opt/snpanel-webmail/src";
const WEBMAIL_VENV: &str = "/opt/snpanel-webmail/venv";
const WEBMAIL_DATA: &str = "/var/lib/snpanel-webmail";
const WEBMAIL_USER: &str = "snpanel-webmail";
const WEBMAIL_UNIT: &str = "/etc/systemd/system/snpanel-webmail.service";
const WEBMAIL_REPO: &str = "https://github.com/bnixvn/webmail";
/// The release the panel was tested with; moved on deliberately.
const WEBMAIL_COMMIT: &str = "7851fc28c6971ee1ac7d101766fb3a76babf0864";
pub const WEBMAIL_PORT: u16 = 2096;
const MASTER_USER: &str = "snpanel-webmail";
const MARKER: &str = "# SNPANEL MANAGED - Email addon";
/// Every port the addon answers on.
const PORTS: &[u16] = &[25, 465, 587, 110, 995, 143, 993, WEBMAIL_PORT];

struct Layout {
    packages: &'static [&'static str],
    exim_conf: &'static str,
    exim_bin: &'static str,
    exim_service: &'static str,
    exim_user: &'static str,
    local_spool: &'static str,
    log_dir: &'static str,
    nologin: &'static str,
}

fn layout() -> Layout {
    match packages::family() {
        Family::Rhel => Layout {
            packages: &["exim", "dovecot", "dovecot-pigeonhole", "rspamd", "python3", "git", "openssl"],
            exim_conf: "/etc/exim/exim.conf",
            exim_bin: "/usr/sbin/exim",
            exim_service: "exim",
            exim_user: "exim",
            local_spool: "/var/spool/mail",
            log_dir: "/var/log/exim",
            nologin: "/sbin/nologin",
        },
        _ => Layout {
            packages: &[
                "exim4-daemon-heavy",
                "dovecot-imapd",
                "dovecot-pop3d",
                "dovecot-lmtpd",
                "dovecot-sieve",
                "rspamd",
                "python3-venv",
                "git",
                "openssl",
            ],
            exim_conf: "/etc/exim4/exim4.conf",
            exim_bin: "/usr/sbin/exim4",
            exim_service: "exim4",
            exim_user: "Debian-exim",
            local_spool: "/var/mail",
            log_dir: "/var/log/exim4",
            nologin: "/usr/sbin/nologin",
        },
    }
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

fn write(path: &str, text: &str, mode: u32, owner: &str) -> Result<(), HelperResponse> {
    if let Some(dir) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    super::nginx::write_atomic(Path::new(path), text.as_bytes(), mode)
        .map_err(|e| failed(HelperErrorKind::Internal, format!("writing {path}: {e}")))?;
    step(&["chown", owner, path])
}

fn random_hex(bytes: usize) -> Result<String, HelperResponse> {
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| failed(HelperErrorKind::Internal, format!("reading /dev/urandom: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// `openssl passwd -6`: the password on stdin, a SHA512-CRYPT hash out.
fn sha512_crypt(password: &str) -> Result<String, HelperResponse> {
    let input = format!("{password}\n");
    let result = exec::run_with_stdin(&["openssl", "passwd", "-6", "-stdin"], Some(input.as_bytes()));
    match result {
        Ok(o) if o.ok() && o.stdout.trim().starts_with("$6$") => Ok(o.stdout.trim().to_string()),
        other => Err(exec::respond("hashing a mailbox password", other)),
    }
}

fn installed() -> bool {
    Path::new(DIR).join("domains").exists() && Path::new(USERS).exists()
}

/// The panel's hostname: what mail clients connect to and the certificate
/// names.
fn hostname() -> String {
    let env = std::fs::read_to_string("/opt/snpanel/backend/.env").unwrap_or_default();
    super::panel::env_get(&env, "PANEL_DOMAIN")
        .map(|d| d.trim().trim_matches('"').to_ascii_lowercase())
        .filter(|d| snpanel_core::Domain::parse(d).is_ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| snpanel_core::Domain::parse(h).is_ok())
        })
        .unwrap_or_else(|| "localhost.localdomain".into())
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const EXIM_CONF: &str = r#"@@MARKER@@
# Rewritten when the addon is installed. The mail domains, mailboxes and
# forwarders are the lookup files in @@DIR@@, written by the panel.

primary_hostname = @@HOSTNAME@@
qualify_domain = @@HOSTNAME@@

domainlist hosted_domains = lsearch;@@DIR@@/domains
domainlist local_domains = @ : localhost : +hosted_domains
domainlist relay_to_domains =
hostlist relay_from_hosts = <; 127.0.0.1 ; ::1

acl_smtp_rcpt = acl_check_rcpt
acl_smtp_data = acl_check_data

spamd_address = 127.0.0.1 11333 variant=rspamd

daemon_smtp_ports = 25 : 465 : 587
tls_on_connect_ports = 465
tls_advertise_hosts = *
tls_certificate = @@DIR@@/tls.crt
tls_privatekey = @@DIR@@/tls.key
# Signing in needs TLS, except from this machine (the webmail).
auth_advertise_hosts = ${if or {{def:tls_in_cipher}{match_ip{$sender_host_address}{<; 127.0.0.1 ; ::1}}}{*}{}}

never_users = root
host_lookup =
prdr_enable = false
message_size_limit = 50M
smtp_accept_max = 200
smtp_accept_max_per_host = 20
ignore_bounce_errors_after = 2d
timeout_frozen_after = 7d
keep_environment =
log_file_path = @@LOGDIR@@/%slog
log_selector = +smtp_protocol_error +smtp_syntax_error +tls_certificate_verified

begin acl

acl_check_rcpt:
  accept  hosts = :
          control = dkim_disable_verify

  deny    domains = +local_domains
          local_parts = ^[.] : ^.*[@%!/|]
          message = Restricted characters in address

  deny    domains = !+local_domains
          local_parts = ^[./|] : ^.*[@%!] : ^.*/\\.\\./
          message = Restricted characters in address

  # 465 and 587 are for mail clients: signed in, always.
  deny    condition = ${if or {{eq{$received_port}{587}}{eq{$received_port}{465}}}}
          !authenticated = *
          message = Sign in to send mail through this server

  # A mailbox sends as itself, never as another address. The webmail signs
  # in as "<mailbox>*<master user>"; the mailbox is the part before the *.
  deny    authenticated = *
          condition = ${if eqi{$sender_address}{${extract{1}{*}{$authenticated_id}}}{no}{yes}}
          message = Send as your own address (${extract{1}{*}{$authenticated_id}})

  # A mailbox here that does not exist is refused now, whoever sends -
  # not accepted and bounced later.
  deny    domains = +hosted_domains
          !verify = recipient
          message = No such mailbox

  accept  authenticated = *
          control = submission/domain=
          control = dkim_disable_verify

  accept  hosts = +relay_from_hosts
          control = submission/domain=
          control = dkim_disable_verify

  require message = Relay not permitted
          domains = +local_domains : +relay_to_domains

  require verify = recipient

  accept

acl_check_data:
  accept  hosts = :
  accept  authenticated = *
  accept  hosts = +relay_from_hosts

  warn    remove_header = X-Spam : X-Spam-Score
  warn    spam = nobody:true
  defer   condition = ${if eq{$spam_action}{soft reject}}
          message = Try again later
  deny    condition = ${if eq{$spam_action}{reject}}
          message = Message rejected as spam
  warn    condition = ${if or {{eq{$spam_action}{add header}}{eq{$spam_action}{rewrite subject}}}}
          add_header = X-Spam: Yes
  warn    add_header = X-Spam-Score: $spam_score
  accept

begin routers

dnslookup:
  driver = dnslookup
  domains = ! +local_domains
  transport = remote_smtp
  ignore_target_hosts = 0.0.0.0 : 127.0.0.0/8
  no_more

snpanel_forwarders:
  driver = redirect
  domains = +hosted_domains
  data = ${lookup{${lc:$local_part}@$domain}lsearch{@@DIR@@/aliases}}
  allow_fail
  allow_defer
  forbid_file
  forbid_pipe
  forbid_filter_run
  qualify_preserve_domain

snpanel_mailboxes:
  driver = accept
  domains = +hosted_domains
  condition = ${lookup{${lc:$local_part}@$domain}lsearch{@@DIR@@/mailboxes}{yes}{no}}
  transport = dovecot_lmtp
  cannot_route_message = Unknown mailbox

system_aliases:
  driver = redirect
  domains = @ : localhost
  allow_fail
  allow_defer
  data = ${lookup{$local_part}lsearch{/etc/aliases}}
  file_transport = address_file
  pipe_transport = address_pipe

localuser:
  driver = accept
  domains = @ : localhost
  check_local_user
  transport = local_delivery
  cannot_route_message = Unknown user

begin transports

remote_smtp:
  driver = smtp
  # The From domain's key, when the panel made one (the lookup gives an
  # untainted name for the key's path).
  dkim_domain = ${lookup{${lc:${domain:$h_from:}}}lsearch{@@DIR@@/dkim_domains}}
  dkim_selector = default
  dkim_private_key = ${if eq{$dkim_domain}{}{0}{@@DIR@@/dkim/$dkim_domain.key}}
  dkim_canon = relaxed

dovecot_lmtp:
  driver = lmtp
  socket = /run/dovecot/lmtp
  batch_max = 200

local_delivery:
  driver = appendfile
  file = @@SPOOL@@/$local_part_data
  delivery_date_add
  envelope_to_add
  return_path_add
  group = mail
  mode = 0660

address_pipe:
  driver = pipe
  return_output

address_file:
  driver = appendfile
  delivery_date_add
  envelope_to_add
  return_path_add

begin retry

*   *   F,2h,15m; G,16h,1h,1.5; F,4d,6h

begin rewrite

begin authenticators

dovecot_plain:
  driver = dovecot
  public_name = PLAIN
  server_socket = /run/dovecot/auth-client
  server_set_id = $auth1

dovecot_login:
  driver = dovecot
  public_name = LOGIN
  server_socket = /run/dovecot/auth-client
  server_set_id = $auth1
"#;

const DOVECOT_CONF: &str = r#"@@MARKER@@
# Rewritten when the addon is installed. Mailboxes are in
# /etc/dovecot/snpanel/users, written by the panel.

protocols = imap pop3 lmtp
listen = @@LISTEN@@
ssl = yes
ssl_cert = <@@DIR@@/tls.crt
ssl_key = <@@DIR@@/tls.key
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
# No password in the clear, except from this machine (the webmail).
disable_plaintext_auth = yes
auth_mechanisms = plain login
auth_username_format = %Lu
auth_master_user_separator = *
first_valid_uid = 1000
mail_location = maildir:~/Maildir
mail_plugins = $mail_plugins quota
postmaster_address = postmaster@@@HOSTNAME@@
log_path = syslog

namespace inbox {
  inbox = yes
  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
  mailbox Archive {
    special_use = \Archive
  }
}

# The webmail's master user, from the loopback only (see the file).
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT @@MASTER@@
  master = yes
  pass = yes
}
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%Lu @@USERS@@
}
userdb {
  driver = passwd-file
  args = username_format=%Lu @@USERS@@
}

service auth {
  unix_listener auth-client {
    mode = 0660
    user = @@EXIM_USER@@
    group = @@EXIM_USER@@
  }
}
service lmtp {
  unix_listener lmtp {
    mode = 0660
    user = @@EXIM_USER@@
    group = @@EXIM_USER@@
  }
}
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

protocol imap {
  mail_plugins = $mail_plugins imap_quota
}
protocol lmtp {
  mail_plugins = $mail_plugins sieve
}

plugin {
  quota = maildir:Mailbox
  quota_exceeded_message = The mailbox is full.
  sieve = file:~/sieve;active=~/.dovecot.sieve
  sieve_before = @@SIEVE@@
}
"#;

const SPAM_SIEVE_TEXT: &str = r#"# SNPANEL MANAGED - what Rspamd marked as spam goes to Junk.
require ["fileinto", "mailbox"];
if header :contains "X-Spam" "Yes" {
  fileinto :create "Junk";
  stop;
}
"#;

fn fill(template: &str, l: &Layout, host: &str) -> String {
    let listen = if std::fs::read_to_string("/proc/net/if_inet6").is_ok_and(|t| !t.trim().is_empty()) {
        "*, ::"
    } else {
        "*"
    };
    template
        .replace("@@MARKER@@", MARKER)
        .replace("@@DIR@@", DIR)
        .replace("@@HOSTNAME@@", host)
        .replace("@@SPOOL@@", l.local_spool)
        .replace("@@LOGDIR@@", l.log_dir)
        .replace("@@EXIM_USER@@", l.exim_user)
        .replace("@@LISTEN@@", listen)
        .replace("@@MASTER@@", MASTER_USERS)
        .replace("@@USERS@@", USERS)
        .replace("@@SIEVE@@", SPAM_SIEVE)
}

fn render_webmail_env(auth: &str, sso: &str, master_password: &str) -> String {
    format!(
        "{MARKER}\n\
         AUTH_SECRET={auth}\n\
         SSO_SECRET={sso}\n\
         SSO_MASTER_USER={MASTER_USER}\n\
         SSO_MASTER_PASSWORD={master_password}\n\
         SSO_MASTER_SEPARATOR=*\n\
         IMAP_HOST=127.0.0.1\n\
         IMAP_PORT=143\n\
         IMAP_SECURE=false\n\
         SMTP_HOST=127.0.0.1\n\
         SMTP_PORT=587\n\
         SMTP_SECURE=false\n\
         ENABLE_CADDY_AUTOMATION=false\n\
         DATA_DIR={WEBMAIL_DATA}\n"
    )
}

fn render_webmail_unit(host: &str) -> String {
    format!(
        "{MARKER}\n\
         [Unit]\n\
         Description=SNPanel webmail (BNIX Webmail)\n\
         After=network-online.target dovecot.service\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={WEBMAIL_USER}\n\
         Group={WEBMAIL_USER}\n\
         WorkingDirectory={WEBMAIL_SRC}/backend\n\
         EnvironmentFile={WEBMAIL_ENV}\n\
         Environment=PYTHONDONTWRITEBYTECODE=1\n\
         ExecStart={WEBMAIL_VENV}/bin/uvicorn main:app --host {host} --port {WEBMAIL_PORT} \
         --ssl-certfile {WEBMAIL_DATA}/tls.crt --ssl-keyfile {WEBMAIL_DATA}/tls.key --no-server-header\n\
         Restart=always\n\
         RestartSec=5\n\
         PrivateTmp=true\n\
         ProtectSystem=full\n\
         ProtectHome=true\n\
         NoNewPrivileges=true\n\
         ReadWritePaths={WEBMAIL_DATA}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Rspamd: its scanner on the loopback for Exim, Redis when there is one
/// (Bayes and greylisting need it), and no signing - Exim signs.
fn rspamd_files() -> Vec<(&'static str, String)> {
    let mut files = vec![
        ("/etc/rspamd/local.d/worker-normal.inc", "bind_socket = \"127.0.0.1:11333\";\n".to_string()),
        ("/etc/rspamd/local.d/worker-controller.inc", "bind_socket = \"127.0.0.1:11334\";\n".to_string()),
        ("/etc/rspamd/local.d/worker-proxy.inc", "bind_socket = \"127.0.0.1:11332\";\n".to_string()),
        ("/etc/rspamd/local.d/dkim_signing.conf", "enabled = false;\n".to_string()),
    ];
    let redis = matches!(
        exec::run(&["ss", "-Hlnt", "sport = :6379"]),
        Ok(o) if o.ok() && o.stdout.contains("127.0.0.1")
    );
    if redis {
        files.push(("/etc/rspamd/local.d/redis.conf", "servers = \"127.0.0.1:6379\";\n".to_string()));
    }
    files
}

/// The master user's line: its hash, and only from the loopback.
fn master_line(hash: &str) -> String {
    format!("{MASTER_USER}:{{SHA512-CRYPT}}{hash}::::::allow_nets=127.0.0.1/32,::1/128\n")
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// The panel's certificate and key: its own (Let's Encrypt, a site's), or
/// the self-signed one it starts with.
fn panel_cert() -> Option<(String, String)> {
    let env = std::fs::read_to_string("/opt/snpanel/backend/.env").unwrap_or_default();
    let get = |k: &str| super::panel::env_get(&env, k).map(|v| v.trim().trim_matches('"').to_string());
    let pair = match (get("PANEL_SSL_CERT"), get("PANEL_SSL_KEY")) {
        (Some(c), Some(k)) if Path::new(&c).is_file() && Path::new(&k).is_file() => (c, k),
        _ => (
            "/etc/snpanel/panel-selfsigned-fullchain.pem".to_string(),
            "/etc/snpanel/panel-selfsigned-privkey.pem".to_string(),
        ),
    };
    (Path::new(&pair.0).is_file() && Path::new(&pair.1).is_file()).then_some(pair)
}

/// Exim, Dovecot and the webmail serve the panel's certificate, from copies
/// each can read. Reloaded when it changed. Best effort: called when the
/// panel's certificate changes, where the mail servers keeping the old one
/// is not a reason to fail.
pub(crate) fn sync_certs() {
    if !installed() {
        return;
    }
    let Some((cert, key)) = panel_cert() else {
        return;
    };
    let (Ok(chain), Ok(private)) = (std::fs::read(&cert), std::fs::read(&key)) else {
        return;
    };
    let current = std::fs::read(format!("{DIR}/tls.crt")).ok();
    if current.as_deref() == Some(chain.as_slice())
        && std::fs::read(format!("{WEBMAIL_DATA}/tls.crt")).ok().as_deref() == Some(chain.as_slice())
    {
        return;
    }
    let l = layout();
    let exim_owner = format!("root:{}", l.exim_user);
    let webmail_owner = format!("{WEBMAIL_USER}:{WEBMAIL_USER}");
    let wrote = super::nginx::write_atomic(Path::new(&format!("{DIR}/tls.key")), &private, 0o640)
        .and_then(|_| super::nginx::write_atomic(Path::new(&format!("{DIR}/tls.crt")), &chain, 0o644))
        .and_then(|_| super::nginx::write_atomic(Path::new(&format!("{WEBMAIL_DATA}/tls.key")), &private, 0o600))
        .and_then(|_| super::nginx::write_atomic(Path::new(&format!("{WEBMAIL_DATA}/tls.crt")), &chain, 0o644));
    if wrote.is_err() {
        return;
    }
    let _ = exec::run(&["chown", &exim_owner, &format!("{DIR}/tls.key")]);
    let _ = exec::run(&["chown", &webmail_owner, &format!("{WEBMAIL_DATA}/tls.key"), &format!("{WEBMAIL_DATA}/tls.crt")]);
    for unit in [l.exim_service, "dovecot"] {
        let _ = exec::run(&["systemctl", "try-reload-or-restart", unit]);
    }
    let _ = exec::run(&["systemctl", "try-restart", "snpanel-webmail"]);
}

/// Installed with the addon: the renewed panel certificate reaches the mail
/// servers too.
pub(crate) const MAIL_CERT_HOOK: &str = r#"#!/usr/bin/env bash
# Installed by SNPanel. Gives Exim, Dovecot and the webmail the renewed panel certificate.
set -euo pipefail
env_file="/opt/snpanel/backend/.env"
[[ -f "$env_file" && -d /etc/snpanel-mail ]] || exit 0
domain="$(sed -nE 's/^PANEL_DOMAIN=//p' "$env_file" | tail -n1 | tr -d '"')"
[[ -n "$domain" && "${RENEWED_LINEAGE:-}" == "/etc/letsencrypt/live/${domain}" ]] || exit 0
exim_group=exim; getent group Debian-exim >/dev/null && exim_group=Debian-exim
install -m 0640 -o root -g "$exim_group" "${RENEWED_LINEAGE}/privkey.pem" /etc/snpanel-mail/tls.key
install -m 0644 -o root -g root "${RENEWED_LINEAGE}/fullchain.pem" /etc/snpanel-mail/tls.crt
install -m 0600 -o snpanel-webmail -g snpanel-webmail "${RENEWED_LINEAGE}/privkey.pem" /var/lib/snpanel-webmail/tls.key
install -m 0644 -o snpanel-webmail -g snpanel-webmail "${RENEWED_LINEAGE}/fullchain.pem" /var/lib/snpanel-webmail/tls.crt
systemctl try-reload-or-restart exim exim4 dovecot 2>/dev/null || true
systemctl try-restart snpanel-webmail || true
"#;

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

fn add_rspamd_repo() -> Result<(), HelperResponse> {
    match packages::family() {
        Family::Rhel => {
            let major = std::fs::read_to_string("/etc/os-release")
                .unwrap_or_default()
                .lines()
                .find_map(|l| l.strip_prefix("VERSION_ID="))
                .map(|v| v.trim_matches('"').split('.').next().unwrap_or("").to_string())
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                .unwrap_or_else(|| "9".into());
            let repo = format!(
                "[rspamd]\nname=Rspamd stable repository\n\
                 baseurl=https://rspamd.com/rpm-stable/centos-{major}/$basearch\n\
                 enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n\
                 gpgkey=https://rspamd.com/rpm/rspamd.asc\n"
            );
            write("/etc/yum.repos.d/rspamd.repo", &repo, 0o644, "root:root")
        }
        _ => {
            let codename = std::fs::read_to_string("/etc/os-release")
                .unwrap_or_default()
                .lines()
                .find_map(|l| l.strip_prefix("VERSION_CODENAME="))
                .map(|v| v.trim_matches('"').to_string())
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_lowercase()))
                .ok_or_else(|| failed(HelperErrorKind::Internal, "cannot tell the Debian release"))?;
            let _ = std::fs::create_dir_all("/etc/apt/keyrings");
            let key = exec::run(&["curl", "-fsSL", "https://rspamd.com/apt-stable/gpg.key"]);
            let Ok(key) = key.and_then(|o| if o.ok() { Ok(o) } else { Err(std::io::Error::other(o.stderr)) }) else {
                return Err(failed(HelperErrorKind::CommandFailed, "downloading Rspamd's signing key failed"));
            };
            let armored = exec::run_with_stdin(
                &["gpg", "--dearmor", "--yes", "-o", "/etc/apt/keyrings/rspamd.gpg"],
                Some(key.stdout.as_bytes()),
            );
            if !matches!(&armored, Ok(o) if o.ok()) {
                return Err(exec::respond("gpg --dearmor", armored));
            }
            write(
                "/etc/apt/sources.list.d/rspamd.list",
                &format!("deb [signed-by=/etc/apt/keyrings/rspamd.gpg] https://rspamd.com/apt-stable/ {codename} main\n"),
                0o644,
                "root:root",
            )
        }
    }
}

fn user_exists(name: &str) -> bool {
    matches!(exec::run(&["id", "-u", name]), Ok(o) if o.ok())
}

/// The webmail: its source at the tested release, a virtualenv, its user and
/// data folder, its settings and its unit.
fn install_webmail(l: &Layout) -> Result<(), HelperResponse> {
    if !user_exists(WEBMAIL_USER) {
        step(&["useradd", "--system", "--home-dir", WEBMAIL_DATA, "--shell", l.nologin, WEBMAIL_USER])?;
    }
    std::fs::create_dir_all(WEBMAIL_ROOT)
        .map_err(|e| failed(HelperErrorKind::Internal, format!("creating {WEBMAIL_ROOT}: {e}")))?;
    std::fs::create_dir_all(WEBMAIL_DATA)
        .map_err(|e| failed(HelperErrorKind::Internal, format!("creating {WEBMAIL_DATA}: {e}")))?;
    step(&["chown", &format!("{WEBMAIL_USER}:{WEBMAIL_USER}"), WEBMAIL_DATA])?;
    step(&["chmod", "0700", WEBMAIL_DATA])?;
    if !Path::new(WEBMAIL_SRC).join(".git").is_dir() {
        let _ = std::fs::remove_dir_all(WEBMAIL_SRC);
        step(&["git", "clone", "--quiet", WEBMAIL_REPO, WEBMAIL_SRC])?;
    } else {
        step(&["git", "-C", WEBMAIL_SRC, "fetch", "--quiet", "origin"])?;
    }
    step(&["git", "-C", WEBMAIL_SRC, "checkout", "--quiet", "--force", WEBMAIL_COMMIT])?;
    if !Path::new(WEBMAIL_VENV).join("bin/python").exists() {
        step(&["python3", "-m", "venv", WEBMAIL_VENV])?;
    }
    let pip = format!("{WEBMAIL_VENV}/bin/pip");
    let requirements = format!("{WEBMAIL_SRC}/backend/requirements.txt");
    step(&[&pip, "install", "--quiet", "--disable-pip-version-check", "-r", &requirements])?;

    // The secrets stay from one install to the next: the webmail's sessions
    // and the panel's sign-on keep working.
    let existing = std::fs::read_to_string(WEBMAIL_ENV).unwrap_or_default();
    let keep = |key: &str| {
        super::panel::env_get(&existing, key)
            .filter(|v| v.len() >= 32 && v.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    let auth = match keep("AUTH_SECRET") {
        Some(v) => v,
        None => random_hex(32)?,
    };
    let sso = match keep("SSO_SECRET") {
        Some(v) => v,
        None => random_hex(32)?,
    };
    let master = match keep("SSO_MASTER_PASSWORD") {
        Some(v) => v,
        None => random_hex(24)?,
    };
    write(WEBMAIL_ENV, &render_webmail_env(&auth, &sso, &master), 0o640, &format!("root:{WEBMAIL_USER}"))?;
    write(SSO_KEY_FILE, &format!("{sso}\n"), 0o640, &format!("root:{}", crate::peercred::PANEL_USER))?;
    let hash = sha512_crypt(&master)?;
    write(MASTER_USERS, &master_line(&hash), 0o640, "root:dovecot")?;
    // IPv4: asyncio makes a "::" socket IPv6-only.
    let bind = "0.0.0.0";
    write(WEBMAIL_UNIT, &render_webmail_unit(bind), 0o644, "root:root")
}

/// The distribution's file, kept once beside ours.
fn keep_original(path: &str) {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let backup = format!("{path}.orig");
        if !existing.starts_with(MARKER) && !Path::new(&backup).exists() {
            let _ = std::fs::write(&backup, existing);
        }
    }
}

fn empty_state_files(l: &Layout) -> Result<(), HelperResponse> {
    let exim_owner = format!("root:{}", l.exim_user);
    std::fs::create_dir_all(format!("{DIR}/dkim"))
        .map_err(|e| failed(HelperErrorKind::Internal, format!("creating {DIR}: {e}")))?;
    step(&["chown", &exim_owner, DIR, &format!("{DIR}/dkim")])?;
    step(&["chmod", "0750", DIR, &format!("{DIR}/dkim")])?;
    for name in ["domains", "mailboxes", "aliases", "dkim_domains"] {
        let path = format!("{DIR}/{name}");
        if !Path::new(&path).exists() {
            write(&path, "", 0o640, &exim_owner)?;
        }
    }
    if !Path::new(USERS).exists() {
        write(USERS, "", 0o640, "root:dovecot")?;
    }
    Ok(())
}

/// `mail-install`.
pub fn install(ctx: &Context) -> HelperResponse {
    match install_inner(ctx) {
        Ok(out) => HelperResponse::with_stdout(out),
        Err(r) => r,
    }
}

fn install_inner(ctx: &Context) -> Result<String, HelperResponse> {
    let l = layout();
    let host = hostname();
    let mut out = String::new();

    add_rspamd_repo()?;
    if let Ok(o) = packages::update_index() {
        out.push_str(&o.stdout);
    }
    match packages::install_packages(l.packages) {
        Ok(o) if o.ok() => {}
        other => return Err(exec::respond(&format!("installing {}", l.packages.join(" ")), other)),
    }
    // The package's own owners on its spool and logs: on CloudLinux they
    // have been seen left to root, and Exim then cannot queue a message.
    if packages::family() == Family::Rhel {
        let _ = exec::run(&["rpm", "--setugids", "exim"]);
        let _ = exec::run(&["rpm", "--setperms", "exim"]);
    }
    // One MTA: Postfix would hold port 25.
    if matches!(exec::run(&["systemctl", "is-enabled", "--quiet", "postfix"]), Ok(o) if o.ok()) {
        let _ = exec::run(&["systemctl", "disable", "--now", "postfix"]);
    }

    empty_state_files(&l)?;
    install_webmail(&l)?;
    // A copy of the panel's certificate before anything reads one.
    let _ = std::fs::remove_file(format!("{DIR}/tls.crt"));
    sync_certs();
    if !Path::new(&format!("{DIR}/tls.crt")).exists() {
        return Err(failed(HelperErrorKind::Internal, "the panel has no certificate to give the mail servers"));
    }

    // Exim: checked before it replaces the distribution's file.
    let exim = fill(EXIM_CONF, &l, &host);
    let staged = format!("{DIR}/exim.conf.new");
    write(&staged, &exim, 0o644, "root:root")?;
    let checked = exec::run(&[l.exim_bin, "-C", &staged, "-bV"]);
    if !matches!(&checked, Ok(o) if o.ok()) {
        let _ = std::fs::remove_file(&staged);
        return Err(exec::respond("checking the Exim configuration", checked));
    }
    let _ = std::fs::remove_file(&staged);
    keep_original(l.exim_conf);
    write(l.exim_conf, &exim, 0o644, "root:root")?;

    // Dovecot, the same way.
    let dovecot = fill(DOVECOT_CONF, &l, &host);
    write(SPAM_SIEVE, SPAM_SIEVE_TEXT, 0o644, "root:root")?;
    let _ = exec::run(&["sievec", SPAM_SIEVE]);
    let staged = format!("{DOVECOT_DIR}/dovecot.conf.new");
    write(&staged, &dovecot, 0o644, "root:root")?;
    let checked = exec::run(&["doveconf", "-n", "-c", &staged]);
    let _ = std::fs::remove_file(&staged);
    if !matches!(&checked, Ok(o) if o.ok()) {
        return Err(exec::respond("checking the Dovecot configuration", checked));
    }
    keep_original("/etc/dovecot/dovecot.conf");
    write("/etc/dovecot/dovecot.conf", &dovecot, 0o644, "root:root")?;

    for (path, text) in rspamd_files() {
        write(path, &text, 0o644, "root:root")?;
    }
    super::panel::install_hook("snpanel-mail-cert", MAIL_CERT_HOOK);

    // PHP in CageFS sends through sendmail, which is Exim's.
    if Path::new("/usr/sbin/cagefsctl").exists() {
        let pkg = if packages::family() == Family::Rhel { "exim" } else { "exim4-daemon-heavy" };
        let _ = exec::run(&["cagefsctl", "--addrpm", pkg]);
        let _ = exec::run(&["cagefsctl", "--force-update"]);
    }

    // Exim writes its logs as its own user.
    let _ = std::fs::create_dir_all(l.log_dir);
    step(&["chown", &format!("{0}:{0}", l.exim_user), l.log_dir])?;
    step(&["chmod", "0750", l.log_dir])?;

    let _ = exec::run(&["systemctl", "daemon-reload"]);
    for unit in ["rspamd", "dovecot", l.exim_service, "snpanel-webmail"] {
        step(&["systemctl", "enable", unit])?;
        step(&["systemctl", "restart", unit])?;
    }
    for port in PORTS {
        let opened = super::fwrules::add_rule(
            ctx,
            snpanel_osabi::firewall::rules::Action::Allow,
            None,
            snpanel_core::Port::new(u32::from(*port)).ok(),
            snpanel_osabi::firewall::rules::Protocol::Tcp,
        );
        if !opened.ok {
            return Err(opened);
        }
    }
    out.push_str("Exim, Dovecot, Rspamd and the webmail are running\n");
    Ok(out)
}

/// `mail-stop`: every service stopped and off at boot; mail and settings kept.
pub fn stop() -> HelperResponse {
    let l = layout();
    for unit in ["snpanel-webmail", l.exim_service, "dovecot", "rspamd"] {
        let _ = exec::run(&["systemctl", "disable", "--now", unit]);
    }
    HelperResponse::with_stdout("the mail services are stopped; the mail is kept\n")
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

struct Account {
    uid: u32,
    gid: u32,
    home: String,
}

fn account(name: &str) -> Option<Account> {
    let c = CString::new(name).ok()?;
    // SAFETY: NUL-terminated name; the static result is copied out before
    // any other libc call.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: non-null, the fields are plain values and a C string.
    let (uid, gid, dir) = unsafe { ((*pw).pw_uid, (*pw).pw_gid, std::ffi::CStr::from_ptr((*pw).pw_dir)) };
    let home = dir.to_str().ok()?.to_string();
    (uid >= 1000 && home.starts_with("/home/")).then_some(Account { uid, gid, home })
}

/// `~/mail`, made by root in the root-owned home without following a link,
/// and given to the account. What is below it is the account's and is made
/// as the account.
fn ensure_mail_root(acc: &Account) -> Result<String, String> {
    let home = CString::new(acc.home.clone()).map_err(|e| e.to_string())?;
    // SAFETY: a valid path; the descriptor is owned below.
    let raw = unsafe { libc::open(home.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(format!("{}: {}", acc.home, std::io::Error::last_os_error()));
    }
    // SAFETY: just opened, owned from here.
    let home_fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let name = CString::new("mail").expect("no NUL");
    // SAFETY: valid descriptor and name.
    let made = unsafe { libc::mkdirat(home_fd.as_raw_fd(), name.as_ptr(), 0o700) };
    if made < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!("{}/mail: {e}", acc.home));
        }
    }
    // SAFETY: valid descriptor and name.
    let raw = unsafe {
        libc::openat(home_fd.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if raw < 0 {
        return Err(format!("{}/mail is not a folder", acc.home));
    }
    // SAFETY: just opened, owned from here.
    let mail_fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: valid descriptor.
    if unsafe { libc::fchown(mail_fd.as_raw_fd(), acc.uid, acc.gid) } < 0 || unsafe { libc::fchmod(mail_fd.as_raw_fd(), 0o700) } < 0 {
        return Err(format!("{}/mail: {}", acc.home, std::io::Error::last_os_error()));
    }
    Ok(format!("{}/mail", acc.home))
}

/// A command as the account: its own permissions are all it has.
fn as_account(acc: &Account, argv: &[&str]) -> std::io::Result<exec::Output> {
    let uid = acc.uid.to_string();
    let gid = acc.gid.to_string();
    let mut full: Vec<&str> = vec!["setpriv", "--reuid", &uid, "--regid", &gid, "--clear-groups", "--"];
    full.extend_from_slice(argv);
    exec::run(&full)
}

/// A domain's DKIM key, made once: the TXT record's value.
fn dkim_record(domain: &str, exim_owner: &str) -> Result<String, HelperResponse> {
    let key = format!("{DIR}/dkim/{domain}.key");
    if !Path::new(&key).exists() {
        let staged = format!("{key}.new");
        step(&["openssl", "genrsa", "-out", &staged, "2048"])?;
        step(&["chown", exim_owner, &staged])?;
        step(&["chmod", "0640", &staged])?;
        std::fs::rename(&staged, &key)
            .map_err(|e| failed(HelperErrorKind::Internal, format!("{key}: {e}")))?;
    }
    let public = exec::run(&["openssl", "rsa", "-in", &key, "-pubout", "-outform", "PEM"]);
    let Ok(public) = public.and_then(|o| if o.ok() { Ok(o) } else { Err(std::io::Error::other(o.stderr)) }) else {
        return Err(failed(HelperErrorKind::CommandFailed, format!("reading the DKIM key of {domain}")));
    };
    let body: String = public.stdout.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(format!("v=DKIM1; k=rsa; p={body}"))
}

/// The hashes on disk, by address.
fn existing_hashes() -> BTreeMap<String, String> {
    std::fs::read_to_string(USERS)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, ':');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect()
}

/// `mail-sync`.
pub fn sync(state: &MailState) -> HelperResponse {
    if !installed() {
        return failed(HelperErrorKind::NotFound, "the Email addon is not installed");
    }
    match sync_inner(state) {
        Ok(dkim) => HelperResponse::with_stdout(json!({ "dkim": dkim }).to_string()),
        Err(r) => r,
    }
}

fn sync_inner(state: &MailState) -> Result<BTreeMap<String, String>, HelperResponse> {
    let l = layout();
    let exim_owner = format!("root:{}", l.exim_user);
    let mut accounts: BTreeMap<String, Account> = BTreeMap::new();
    let mut owner_of: BTreeMap<&str, &str> = BTreeMap::new();
    for d in &state.domains {
        let owner = d.owner.as_str();
        if !accounts.contains_key(owner) {
            let acc = account(owner)
                .ok_or_else(|| failed(HelperErrorKind::NotFound, format!("no such account: {owner}")))?;
            accounts.insert(owner.to_string(), acc);
        }
        owner_of.insert(d.domain.as_str(), owner);
    }

    let hashes = existing_hashes();
    let mut users = String::new();
    let mut mailboxes = String::new();
    for b in &state.mailboxes {
        let (local, domain) = snpanel_ipc::split_address(&b.address).expect("validated");
        let owner = owner_of[domain];
        let acc = &accounts[owner];
        let hash = match &b.password {
            Some(p) => format!("{{SHA512-CRYPT}}{}", sha512_crypt(p.expose())?),
            // A mailbox with no password yet cannot sign in.
            None => hashes.get(&b.address).cloned().unwrap_or_else(|| "!".into()),
        };
        let mail_root = ensure_mail_root(acc).map_err(|e| failed(HelperErrorKind::Internal, e))?;
        let home = format!("{mail_root}/{domain}/{local}");
        let made = as_account(acc, &["mkdir", "-p", "-m", "0700", &home]);
        if !matches!(&made, Ok(o) if o.ok()) {
            return Err(exec::respond(&format!("making the folder of {}", b.address), made));
        }
        let quota = if b.quota_mb == 0 {
            String::new()
        } else {
            format!("userdb_quota_rule=*:storage={}M", b.quota_mb)
        };
        users.push_str(&format!("{}:{hash}:{}:{}::{home}::{quota}\n", b.address, acc.uid, acc.gid));
        mailboxes.push_str(&format!("{}: yes\n", b.address));
    }

    let mut aliases = String::new();
    for f in &state.forwarders {
        aliases.push_str(&format!("{}: {}\n", f.source, f.destinations.join(", ")));
    }

    let mut domains = String::new();
    let mut dkim_domains = String::new();
    let mut dkim = BTreeMap::new();
    for d in state.domains.iter().filter(|d| d.local) {
        let name = d.domain.as_str();
        domains.push_str(&format!("{name}: {}\n", d.owner.as_str()));
        dkim.insert(name.to_string(), dkim_record(name, &exim_owner)?);
        dkim_domains.push_str(&format!("{name}: {name}\n"));
    }
    // Mail from here for a domain whose mail is elsewhere is still signed.
    for d in state.domains.iter().filter(|d| !d.local) {
        let name = d.domain.as_str();
        dkim.insert(name.to_string(), dkim_record(name, &exim_owner)?);
        dkim_domains.push_str(&format!("{name}: {name}\n"));
    }

    // The mailboxes first, so a domain never lists an address Dovecot does
    // not know yet.
    write(USERS, &users, 0o640, "root:dovecot")?;
    write(&format!("{DIR}/mailboxes"), &mailboxes, 0o640, &exim_owner)?;
    write(&format!("{DIR}/aliases"), &aliases, 0o640, &exim_owner)?;
    write(&format!("{DIR}/dkim_domains"), &dkim_domains, 0o640, &exim_owner)?;
    write(&format!("{DIR}/domains"), &domains, 0o640, &exim_owner)?;

    // A removed mailbox's mail, deleted as its account.
    for address in &state.purge {
        let (local, domain) = snpanel_ipc::split_address(address).expect("validated");
        let Some(owner) = owner_of.get(domain) else { continue };
        let acc = &accounts[*owner];
        let path = format!("{}/mail/{domain}/{local}", acc.home);
        if Path::new(&path).exists() {
            let _ = as_account(acc, &["rm", "-rf", "--one-file-system", "--", &path]);
        }
    }
    Ok(dkim)
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn active(unit: &str) -> bool {
    matches!(exec::run(&["systemctl", "is-active", "--quiet", unit]), Ok(o) if o.ok())
}

/// The bytes under `dir`, links not followed.
fn size_of(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(meta) = e.metadata() else { continue };
            if meta.is_dir() {
                stack.push(e.path());
            } else if meta.is_file() {
                total += meta.len();
            }
        }
    }
    total
}

/// `mail-status`: JSON.
pub fn status() -> HelperResponse {
    let l = layout();
    let mut usage = serde_json::Map::new();
    for line in std::fs::read_to_string(USERS).unwrap_or_default().lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 {
            usage.insert(fields[0].to_string(), json!(size_of(&Path::new(fields[5]).join("Maildir"))));
        }
    }
    let services = json!({
        "exim": active(l.exim_service),
        "dovecot": active("dovecot"),
        "rspamd": active("rspamd"),
        "webmail": active("snpanel-webmail"),
    });
    let queue = exec::run(&[l.exim_bin, "-bpc"])
        .ok()
        .filter(exec::Output::ok)
        .and_then(|o| o.stdout.trim().parse::<u64>().ok());
    HelperResponse::with_stdout(
        json!({
            "installed": installed(),
            "hostname": hostname(),
            "services": services,
            "queue": queue,
            "webmail_port": WEBMAIL_PORT,
            "usage": usage,
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rhel() -> Layout {
        Layout {
            packages: &[],
            exim_conf: "/etc/exim/exim.conf",
            exim_bin: "/usr/sbin/exim",
            exim_service: "exim",
            exim_user: "exim",
            local_spool: "/var/spool/mail",
            log_dir: "/var/log/exim",
            nologin: "/sbin/nologin",
        }
    }

    #[test]
    fn every_placeholder_is_filled() {
        for template in [EXIM_CONF, DOVECOT_CONF] {
            let text = fill(template, &rhel(), "mail.example.com");
            assert!(!text.contains("@@"), "{}", text.lines().find(|l| l.contains("@@")).unwrap_or(""));
            assert!(text.starts_with(MARKER));
        }
        let dovecot = fill(DOVECOT_CONF, &rhel(), "mail.example.com");
        assert!(dovecot.contains("postmaster_address = postmaster@mail.example.com\n"));
        assert!(dovecot.contains("user = exim\n"));
    }

    #[test]
    fn exim_is_not_an_open_relay() {
        let text = fill(EXIM_CONF, &rhel(), "mail.example.com");
        let rcpt = &text[text.find("acl_check_rcpt:").unwrap()..text.find("acl_check_data:").unwrap()];
        // Relaying is for the signed-in and this machine; the rest may only
        // send to the domains here, and to addresses that exist.
        let relay = rcpt.find("require message = Relay not permitted").unwrap();
        assert!(rcpt[..relay].contains("accept  authenticated = *"));
        assert!(rcpt[..relay].contains("accept  hosts = +relay_from_hosts"));
        assert!(rcpt[relay..].contains("domains = +local_domains : +relay_to_domains"));
        assert!(rcpt[relay..].contains("require verify = recipient"));
        assert!(text.contains("hostlist relay_from_hosts = <; 127.0.0.1 ; ::1\n"));
        // Forwarders can never run a program or write a file.
        let fwd = &text[text.find("snpanel_forwarders:").unwrap()..text.find("snpanel_mailboxes:").unwrap()];
        assert!(fwd.contains("forbid_file") && fwd.contains("forbid_pipe"));
    }

    #[test]
    fn the_master_user_works_from_the_loopback_only() {
        let line = master_line("$6$salt$hash");
        assert_eq!(line, "snpanel-webmail:{SHA512-CRYPT}$6$salt$hash::::::allow_nets=127.0.0.1/32,::1/128\n");
    }

    #[test]
    fn the_webmail_talks_to_the_local_servers() {
        let env = render_webmail_env("a", "b", "c");
        for line in ["IMAP_HOST=127.0.0.1", "SMTP_HOST=127.0.0.1", "SSO_MASTER_USER=snpanel-webmail", "ENABLE_CADDY_AUTOMATION=false"] {
            assert!(env.contains(&format!("{line}\n")), "{line}");
        }
        let unit = render_webmail_unit("::");
        assert!(unit.contains("--port 2096"));
        assert!(unit.contains("User=snpanel-webmail\n"));
    }
}
