//! `ops::panel` - the panel's own URL, port and certificate.
//!
//! Source: `panel-url-set`, `panel-ssl-install`, `panel-ssl-use-domain`, and
//! the four helpers all three share.
//!
//! These change how the panel itself is reached, so every one of them can lock
//! an administrator out of the machine they are administering. Three things
//! follow from that and they shape the module:
//!
//! **The port is opened before the panel moves to it.** `allow_panel_port`
//! runs first and must never fail the caller: a firewall problem is not the
//! URL change failing, and a caller that aborted here would leave `.env`
//! written and nginx not reloaded.
//!
//! **The restart is scheduled, not immediate.** The helper is answering a
//! request from the API it is about to restart. Restarting inline kills the
//! connection carrying the reply, and the panel reports a failure for a change
//! that worked.
//!
//! **A borrowed certificate needs a renewal hook.** A certificate copied from
//! a website goes stale in two months when certbot renews the original, and
//! the panel would serve the expired copy until somebody noticed.

use std::path::Path;

use snpanel_core::{Domain, Email, Port};
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: `ENV_FILE`.
pub const ENV_FILE: &str = "/opt/snpanel/backend/.env";
const SNPANEL_DIR: &str = "/etc/snpanel";
const PANEL_CERT: &str = "/etc/snpanel/panel-fullchain.pem";
const PANEL_KEY: &str = "/etc/snpanel/panel-privkey.pem";
const LIVE_DIR: &str = "/etc/letsencrypt/live";
const ACME_WEBROOT: &str = "/var/www/snpanel-acme";
const TOOLS_CONF: &str = "/etc/nginx/conf.d/00-snpanel-tools.conf";
const HOOK_DIR: &str = "/etc/letsencrypt/renewal-hooks/deploy";
/// Source: `DEFAULT_PANEL_PORT`.
const DEFAULT_PANEL_PORT: &str = "2222";

// ---------------------------------------------------------------------------
// the .env file
// ---------------------------------------------------------------------------

/// Source: `env_get`.
///
/// `awk -F= '$1 == key { sub(/^[^=]*=/, ""); print; exit }'` - the **first**
/// match, and everything after the first `=`.
pub(crate) fn env_get(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::to_string)
}

/// Source: `env_set`.
///
/// `grep -q "^KEY="` then `sed -i "s|^KEY=.*|KEY=value|"` - no line range, so
/// **every** line with that key is rewritten. A file that ended up with the
/// key twice comes out with both copies agreeing, which matters because the
/// panel's own loader takes the last one.
pub(crate) fn env_set_in(text: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key}=");
    let replacement = format!("{key}={value}");
    let trailing_newline = text.is_empty() || text.ends_with('\n');
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut found = false;
    for line in lines.iter_mut() {
        if line.starts_with(&prefix) {
            *line = replacement.clone();
            found = true;
        }
    }
    if !found {
        lines.push(replacement);
    }
    let mut out = lines.join("\n");
    if trailing_newline || !found {
        out.push('\n');
    }
    out
}

/// Apply several `env_set`s in one read-modify-write.
///
/// The bash re-reads and rewrites the file per key. Doing it once is the same
/// result and leaves no window where the file carries half a change - and
/// this file decides how the panel is reached, so a half-written one is a
/// panel that does not come back.
fn env_set_all(pairs: &[(&str, &str)]) -> Result<(), HelperResponse> {
    let Ok(text) = std::fs::read_to_string(ENV_FILE) else {
        return Err(HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("{ENV_FILE} not found"),
        ));
    };
    let mut out = text;
    for (key, value) in pairs {
        out = env_set_in(&out, key, value);
    }
    std::fs::write(ENV_FILE, out).map_err(|e| {
        HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {ENV_FILE}: {e}"),
        )
    })
}

fn env_file() -> String {
    std::fs::read_to_string(ENV_FILE).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// the tools vhost
// ---------------------------------------------------------------------------

/// What `refresh_tools_nginx` needs to know to render.
pub(crate) struct ToolsConfig {
    pub ipv6: bool,
    pub cert: String,
    pub key: String,
    pub php_version: String,
}

impl ToolsConfig {
    /// TLS is on only when both files are named **and** both exist: a `.env`
    /// naming a certificate that is not there would render `ssl_certificate`
    /// for a missing file, and nginx then refuses to start at all.
    fn tls(&self) -> bool {
        !self.cert.is_empty()
            && !self.key.is_empty()
            && Path::new(&self.cert).is_file()
            && Path::new(&self.key).is_file()
    }
}

/// Source: the `00-snpanel-tools.conf` heredoc. C19: byte-identical.
pub(crate) fn render_tools_nginx(config: &ToolsConfig) -> String {
    // `default_server` is per address:port, so `[::]:80` carries its own.
    let v6_http = if config.ipv6 {
        "\n    listen [::]:80 default_server;"
    } else {
        ""
    };
    let mut ssl_block = String::new();
    if config.tls() {
        let v6_https = if config.ipv6 {
            "\n    listen [::]:443 ssl http2 default_server;"
        } else {
            ""
        };
        ssl_block = format!(
            "\n    listen 443 ssl http2 default_server;{v6_https}\
             \n    ssl_certificate {};\
             \n    ssl_certificate_key {};",
            config.cert, config.key
        );
    }
    let php = &config.php_version;
    format!(
        "server {{\n    \
         listen 80 default_server;{v6_http}{ssl_block}\n    \
         server_name _;\n    \
         client_max_body_size 1100M;\n\n    \
         # Panel certificates are issued through this, so the panel no longer has to\n    \
         # stop nginx to prove it owns its own hostname.\n    \
         location ^~ /.well-known/acme-challenge/ {{\n        \
         root /var/www/snpanel-acme;\n        \
         default_type text/plain;\n        \
         try_files $uri =404;\n        \
         access_log off;\n        \
         auth_basic off;\n    \
         }}\n    \
         location = /phpmyadmin {{ return 301 /phpmyadmin/; }}\n    \
         location /phpmyadmin/ {{ alias /usr/share/phpmyadmin/; index index.php; \
         try_files $uri $uri/ =404; }}\n    \
         location ~ ^/phpmyadmin/(.+\\.php)$ {{ alias /usr/share/phpmyadmin/$1; \
         include fastcgi_params; \
         fastcgi_param SCRIPT_FILENAME /usr/share/phpmyadmin/$1; \
         fastcgi_param SCRIPT_NAME /phpmyadmin/$1; \
         fastcgi_param PHP_VALUE \"error_reporting=E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED\"; \
         fastcgi_pass unix:/run/php/php{php}-fpm.sock; fastcgi_read_timeout 300; }}\n\
         }}\n"
    )
}

/// Source: `refresh_tools_nginx`.
fn refresh_tools_nginx() -> HelperResponse {
    let env = env_file();
    let port = env_get(&env, "PANEL_PORT")
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| DEFAULT_PANEL_PORT.to_string());
    let cert = env_get(&env, "PANEL_SSL_CERT").unwrap_or_default();
    let key = env_get(&env, "PANEL_SSL_KEY").unwrap_or_default();
    let domain = env_get(&env, "PANEL_DOMAIN").unwrap_or_default();
    let host = if domain.is_empty() {
        detect_ip()
    } else {
        domain
    };
    let config = ToolsConfig {
        ipv6: Path::new(crate::ops::misc::IPV6_MARKER).exists(),
        cert,
        key,
        php_version: std::env::var("PHP_DEFAULT").unwrap_or_else(|_| "8.4".to_string()),
    };
    let tls = config.tls();

    // The distribution's own default vhost also claims `default_server` on
    // :80, and two of them is a configuration nginx refuses to load.
    let _ = std::fs::remove_file("/etc/nginx/sites-enabled/default");
    let _ = std::fs::remove_file("/etc/nginx/conf.d/default.conf");
    let _ = crate::ops::nginx::ensure_flood_conf();

    if let Err(e) = std::fs::write(TOOLS_CONF, render_tools_nginx(&config)) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {TOOLS_CONF}: {e}"),
        );
    }

    let scheme = if tls { "https" } else { "http" };
    rewrite_phpmyadmin(scheme, &port, tls, &host);

    let checked = exec::run(&["nginx", "-t"]);
    if !matches!(&checked, Ok(o) if o.ok()) {
        return exec::respond("nginx -t", checked);
    }
    let _ = exec::run(&["systemctl", "reload", "nginx"]);
    HelperResponse::ok()
}

/// Source: `detect_ip` - `hostname -I | awk '{print $1}'`.
fn detect_ip() -> String {
    exec::run(&["hostname", "-I"])
        .ok()
        .and_then(|o| o.stdout.split_whitespace().next().map(str::to_string))
        .unwrap_or_default()
}

/// The three `sed -i` calls against phpMyAdmin's single-sign-on shim.
///
/// Every one of them ends `|| true` in the bash: phpMyAdmin is optional, and
/// a panel that refused to change its own URL because a database tool is not
/// installed would be the wrong trade.
fn rewrite_phpmyadmin(scheme: &str, port: &str, secure: bool, host: &str) {
    const SIGNON: &str = "/usr/share/phpmyadmin/snpanel-signon.php";
    const CONF_SIGNON: &str = "/etc/phpmyadmin/conf.d/snpanel-signon.php";

    if let Ok(text) = std::fs::read_to_string(SIGNON) {
        let rewritten = rewrite_sso_url(&text, scheme, port);
        if rewritten != text {
            let _ = std::fs::write(SIGNON, rewritten);
        }
    }
    for path in [CONF_SIGNON, SIGNON] {
        if let Ok(text) = std::fs::read_to_string(path) {
            let rewritten = rewrite_secure_flag(&text, secure);
            if rewritten != text {
                let _ = std::fs::write(path, rewritten);
            }
        }
    }
    if !host.is_empty() {
        if let Ok(text) = std::fs::read_to_string(CONF_SIGNON) {
            let rewritten = rewrite_absolute_uri(&text, scheme, host);
            if rewritten != text {
                let _ = std::fs::write(CONF_SIGNON, rewritten);
            }
        }
    }
}

/// `/api\/databases\/phpmyadmin-sso/s#'[^']+/api/databases/phpmyadmin-sso/'#...#`
///
/// Only lines that already mention the endpoint, and only the quoted URL on
/// them - the address the shim posts the single-sign-on token to has to follow
/// the panel's port, or logging into phpMyAdmin stops working the moment the
/// port changes.
pub(crate) fn rewrite_sso_url(text: &str, scheme: &str, port: &str) -> String {
    const NEEDLE: &str = "/api/databases/phpmyadmin-sso";
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if !line.contains(NEEDLE) {
            out.push_str(line);
            continue;
        }
        match replace_quoted_ending_with(line, "/api/databases/phpmyadmin-sso/") {
            Some((before, after)) => {
                out.push_str(&before);
                out.push_str(&format!(
                    "'{scheme}://127.0.0.1:{port}/api/databases/phpmyadmin-sso/'"
                ));
                out.push_str(&after);
            }
            None => out.push_str(line),
        }
    }
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// The first `'...'` on the line whose contents end with `suffix`, split into
/// what comes before and after it.
fn replace_quoted_ending_with(line: &str, suffix: &str) -> Option<(String, String)> {
    let open = line.find('\'')?;
    let rest = &line[open + 1..];
    let close = rest.find('\'')?;
    let value = &rest[..close];
    if !value.ends_with(suffix) || value.is_empty() {
        return None;
    }
    Some((
        line[..open].to_string(),
        line[open + 1 + close + 1..].to_string(),
    ))
}

/// `s#('secure' => )(true|false)#\1<secure>#`
pub(crate) fn rewrite_secure_flag(text: &str, secure: bool) -> String {
    let wanted = if secure { "true" } else { "false" };
    let mut out = text.to_string();
    for from in ["'secure' => true", "'secure' => false"] {
        out = out.replace(from, &format!("'secure' => {wanted}"));
    }
    out
}

/// `/PmaAbsoluteUri/s#'https?://[^']+/phpmyadmin/'#'<scheme>://<host>/phpmyadmin/'#`
pub(crate) fn rewrite_absolute_uri(text: &str, scheme: &str, host: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if !line.contains("PmaAbsoluteUri") {
            out.push_str(line);
            continue;
        }
        match replace_quoted_ending_with(line, "/phpmyadmin/") {
            Some((before, after)) if line.contains("'http://") || line.contains("'https://") => {
                out.push_str(&before);
                out.push_str(&format!("'{scheme}://{host}/phpmyadmin/'"));
                out.push_str(&after);
            }
            _ => out.push_str(line),
        }
    }
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// the port, the restart, the hooks
// ---------------------------------------------------------------------------

/// Source: `allow_panel_port`.
///
/// "This must never fail the caller: a firewall problem here is not the
/// SSL/URL change failing." The bash needs a subshell for that, because
/// `firewall_apply` reaches `deny`, which `exit`s the whole process before
/// `|| true` ever sees a status. Here the response is simply discarded, which
/// is the same intent without the trap.
fn allow_panel_port(ctx: &super::Context) {
    let _ = crate::ops::firewall::ensure_dir();
    let _ = crate::ops::firewall::apply(&crate::ops::firewall::load_ruleset(
        ctx.panel_port,
        &ctx.ssh_ports,
    ));
}

/// Source: `schedule_panel_restart`.
///
/// Two seconds later, through systemd, and not inline: this is answering a
/// request from the API it is restarting, and an inline restart kills the
/// connection carrying the reply. The panel would report a failure for a
/// change that worked.
fn schedule_panel_restart() {
    let _ = exec::run(&["systemctl", "daemon-reload"]);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let unit = format!("--unit=snpanel-api-delayed-restart-{stamp}");
    let _ = exec::run(&[
        "systemd-run",
        &unit,
        "--on-active=2s",
        "/bin/systemctl",
        "restart",
        "snpanel-api",
    ]);
}

/// Source: `install_sni_renewal_hook`.
pub(crate) const SNI_HOOK: &str = r#"#!/usr/bin/env bash
# Installed by SNPanel. Keeps the panel's per-hostname certificate copies fresh.
set -euo pipefail
# RENEWED_LINEAGE is set by certbot to the live directory that just changed.
[[ -n "${RENEWED_LINEAGE:-}" ]] || exit 0
domain="$(basename "$RENEWED_LINEAGE")"
[[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || exit 0
[[ -f "${RENEWED_LINEAGE}/fullchain.pem" && -f "${RENEWED_LINEAGE}/privkey.pem" ]] || exit 0
install -d -o root -g snpanel -m 0750 /etc/snpanel /etc/snpanel/sni "/etc/snpanel/sni/${domain}"
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/fullchain.pem" "/etc/snpanel/sni/${domain}/fullchain.pem"
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/privkey.pem" "/etc/snpanel/sni/${domain}/privkey.pem"
"#;

/// Source: `install_panel_cert_renewal_hook`.
pub(crate) const PANEL_CERT_HOOK: &str = r#"#!/usr/bin/env bash
# Installed by SNPanel. Refreshes the panel's copy of a website certificate.
set -euo pipefail
env_file="/opt/snpanel/backend/.env"
[[ -f "$env_file" ]] || exit 0
mode="$(sed -nE 's/^PANEL_SSL_MODE=//p' "$env_file" | tail -n1 | tr -d '"')"
domain="$(sed -nE 's/^PANEL_DOMAIN=//p' "$env_file" | tail -n1 | tr -d '"')"
[[ "$mode" == "domain" && -n "$domain" ]] || exit 0
# RENEWED_LINEAGE is set by certbot to the live directory that just changed.
[[ "${RENEWED_LINEAGE:-}" == "/etc/letsencrypt/live/${domain}" ]] || exit 0
install -d -o root -g snpanel -m 0750 /etc/snpanel
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/fullchain.pem" /etc/snpanel/panel-fullchain.pem
install -m 0640 -o root -g snpanel "${RENEWED_LINEAGE}/privkey.pem" /etc/snpanel/panel-privkey.pem
systemctl restart snpanel-api || true
"#;

fn install_hook(name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::create_dir_all(HOOK_DIR).is_err() {
        return;
    }
    let path = format!("{HOOK_DIR}/{name}");
    if std::fs::write(&path, body).is_ok() {
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
}

/// `install -d -o root -g snpanel -m 0750 /etc/snpanel`, then the certificate
/// pair at 0640.
///
/// The group is `snpanel` and the mode is 0640 because the panel process has
/// to read its own private key and nothing else on the box does.
fn install_panel_pair(from_dir: &Path) -> Result<(), HelperResponse> {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::create_dir_all(SNPANEL_DIR) {
        return Err(HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {SNPANEL_DIR}: {e}"),
        ));
    }
    let _ = std::fs::set_permissions(SNPANEL_DIR, std::fs::Permissions::from_mode(0o750));
    let _ = exec::run(&["chown", "root:snpanel", SNPANEL_DIR]);

    for (name, target) in [("fullchain.pem", PANEL_CERT), ("privkey.pem", PANEL_KEY)] {
        let source = from_dir.join(name);
        if let Err(e) = std::fs::copy(&source, target) {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("installing {target}: {e}"),
            ));
        }
        let _ = std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o640));
        let _ = exec::run(&["chown", "root:snpanel", target]);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the verbs
// ---------------------------------------------------------------------------

/// `panel-url-set <http|https> <host> <port>`.
pub fn url_set(ctx: &super::Context, https: bool, host: &str, port: Port) -> HelperResponse {
    // `require_panel_host` - a domain, an IPv4 address, or `localhost`.
    let is_domain = Domain::parse(host).is_ok();
    if !is_domain && !is_ipv4(host) && host != "localhost" {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("invalid panel host: {host}"),
        );
    }
    let scheme = if https { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}");
    let port_text = port.to_string();

    let mut pairs: Vec<(&str, &str)> = vec![
        ("PANEL_PORT", &port_text),
        ("PANEL_URL", &url),
        ("ALLOWED_ORIGINS", &url),
        // A host that is not a domain cannot carry a certificate, so the
        // panel's domain is cleared rather than left pointing at the old one.
        ("PANEL_DOMAIN", if is_domain { host } else { "" }),
    ];
    // Moving to plain http means the certificate no longer applies; leaving
    // the paths set would have `refresh_tools_nginx` render an `ssl_block`
    // for a listener that is not being asked for.
    if !https {
        pairs.push(("PANEL_SSL_CERT", ""));
        pairs.push(("PANEL_SSL_KEY", ""));
    }
    if let Err(resp) = env_set_all(&pairs) {
        return resp;
    }

    allow_panel_port(ctx);
    let refreshed = refresh_tools_nginx();
    if !refreshed.ok {
        return refreshed;
    }
    schedule_panel_restart();
    HelperResponse::with_stdout(format!("Panel URL: {url}\n"))
}

/// Source: `is_ipv4`.
fn is_ipv4(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok()
        && value.split('.').count() == 4
        && value.split('.').all(|p| !p.is_empty() && p.len() <= 3)
}

/// `panel-ssl-use-domain <domain> <port>`.
///
/// "A domain hosted here that already has a real certificate is a better
/// answer than a self-signed one, and than asking a certificate authority for
/// a second certificate covering the same name."
pub fn ssl_use_domain(ctx: &super::Context, domain: &Domain, port: Port) -> HelperResponse {
    let live = Path::new(LIVE_DIR).join(domain.as_str());
    if !live.join("fullchain.pem").is_file() || !live.join("privkey.pem").is_file() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no certificate for {domain}; issue SSL for that website first"),
        );
    }
    if let Err(resp) = install_panel_pair(&live) {
        return resp;
    }
    let url = format!("https://{domain}:{port}");
    if let Err(resp) = env_set_all(&[
        ("PANEL_DOMAIN", domain.as_str()),
        ("PANEL_SSL_CERT", PANEL_CERT),
        ("PANEL_SSL_KEY", PANEL_KEY),
        ("PANEL_SSL_MODE", "domain"),
        ("PANEL_URL", &url),
        ("ALLOWED_ORIGINS", &url),
    ]) {
        return resp;
    }

    install_hook("snpanel-panel-cert", PANEL_CERT_HOOK);
    install_hook("snpanel-sni-certs", SNI_HOOK);
    let _ = crate::ops::ssl::sync_sni();
    allow_panel_port(ctx);
    let refreshed = refresh_tools_nginx();
    if !refreshed.ok {
        return refreshed;
    }
    schedule_panel_restart();
    HelperResponse::with_stdout(format!(
        "Panel now uses the certificate of {domain}: {url}\n"
    ))
}

/// `panel-ssl-install <domain> <port> [email]`.
pub fn ssl_install(
    ctx: &super::Context,
    domain: &Domain,
    port: Port,
    email: Option<&Email>,
) -> HelperResponse {
    // "Webroot, not standalone: standalone needs port 80 to itself, which
    // meant stopping nginx - every website on the box went down for the ten
    // seconds certbot spent talking to Let's Encrypt, to issue a certificate
    // for the panel. The default vhost serves the challenge instead."
    let challenge = format!("{ACME_WEBROOT}/.well-known/acme-challenge");
    if let Err(e) = std::fs::create_dir_all(&challenge) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {challenge}: {e}"),
        );
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(ACME_WEBROOT, std::fs::Permissions::from_mode(0o755));
    }
    let _ = exec::run(&["chown", "root:snpanel", ACME_WEBROOT]);

    let deploy_hook = format!(
        "install -d -o root -g snpanel -m 0750 /etc/snpanel && \
         install -m 0640 -o root -g snpanel {LIVE_DIR}/{domain}/fullchain.pem {PANEL_CERT} && \
         install -m 0640 -o root -g snpanel {LIVE_DIR}/{domain}/privkey.pem {PANEL_KEY}"
    );
    let mut argv: Vec<String> = vec![
        "certbot".into(),
        "certonly".into(),
        "--webroot".into(),
        "-w".into(),
        ACME_WEBROOT.into(),
        "-d".into(),
        domain.to_string(),
        "--agree-tos".into(),
        "--non-interactive".into(),
        "--keep-until-expiring".into(),
        "--deploy-hook".into(),
        deploy_hook,
    ];
    match email {
        Some(email) => {
            argv.push("--email".into());
            argv.push(email.to_string());
        }
        None => argv.push("--register-unsafely-without-email".into()),
    }
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let issued = exec::run(&borrowed);

    // "certbot exits 1 for 'certificate not yet due for renewal' even with
    // --keep-until-expiring - that is certbot telling us it did nothing, not
    // that anything is wrong. [...] The only thing that actually matters is
    // whether a usable certificate exists on disk afterwards."
    let live = Path::new(LIVE_DIR).join(domain.as_str());
    if !matches!(&issued, Ok(o) if o.ok()) && !live.join("fullchain.pem").is_file() {
        return exec::respond("certbot", issued);
    }

    if let Err(resp) = install_panel_pair(&live) {
        return resp;
    }
    let url = format!("https://{domain}:{port}");
    if let Err(resp) = env_set_all(&[
        ("PANEL_DOMAIN", domain.as_str()),
        ("PANEL_PORT", &port.to_string()),
        ("PANEL_SSL_CERT", PANEL_CERT),
        ("PANEL_SSL_KEY", PANEL_KEY),
        ("PANEL_SSL_MODE", "letsencrypt"),
        ("PANEL_URL", &url),
        ("ALLOWED_ORIGINS", &url),
    ]) {
        return resp;
    }

    install_hook("snpanel-panel-cert", PANEL_CERT_HOOK);
    install_hook("snpanel-sni-certs", SNI_HOOK);
    let _ = crate::ops::ssl::sync_sni();
    allow_panel_port(ctx);
    let refreshed = refresh_tools_nginx();
    if !refreshed.ok {
        return refreshed;
    }
    schedule_panel_restart();
    HelperResponse::with_stdout(format!("Panel SSL ready: {url}\n"))
}

/// `cloudflare-ssl-issue <zone> [email]`, with the API token on stdin.
///
/// "Zone comes from argv (validated); the literal `*.` is built here, never
/// taken from the caller. The token arrives on stdin so it never lands in a
/// process list or the sudo log." That is C37, and it is why the credentials
/// file is written with `umask 077` before certbot is told where it is.
pub fn cloudflare_ssl_issue(zone: &Domain, email: Option<&Email>, token: &str) -> HelperResponse {
    if !crate::ops::runtime::have("certbot") {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "certbot is not installed".to_string(),
        );
    }
    if !crate::ops::packages::dpkg_installed(&["python3-certbot-dns-cloudflare"]) {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "certbot dns-cloudflare plugin is not installed \
             (run certbot-dns-cloudflare-install)"
                .to_string(),
        );
    }
    if !valid_cloudflare_token(token) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "cloudflare API token is missing or malformed".to_string(),
        );
    }

    let dir = format!("{SNPANEL_DIR}/cloudflare");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return HelperResponse::failed(HelperErrorKind::Internal, format!("creating {dir}: {e}"));
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(SNPANEL_DIR, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let ini = format!("{dir}/{zone}.ini");
    // `( umask 077; ... >"$ini" )` - the file must never exist world-readable,
    // not even for the instant between creation and `chmod`.
    if let Err(resp) = write_private(&ini, &format!("dns_cloudflare_api_token = {token}\n")) {
        return resp;
    }

    let wildcard = format!("*.{zone}");
    let mut argv: Vec<String> = vec![
        "certbot".into(),
        "certonly".into(),
        "--dns-cloudflare".into(),
        "--dns-cloudflare-credentials".into(),
        ini.clone(),
        "--dns-cloudflare-propagation-seconds".into(),
        "30".into(),
        "--cert-name".into(),
        zone.to_string(),
        "-d".into(),
        zone.to_string(),
        "-d".into(),
        wildcard,
        "--non-interactive".into(),
        "--agree-tos".into(),
        "--keep-until-expiring".into(),
    ];
    match email {
        Some(email) => {
            argv.push("--email".into());
            argv.push(email.to_string());
        }
        None => argv.push("--register-unsafely-without-email".into()),
    }
    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let issued = exec::run(&borrowed);
    if !matches!(&issued, Ok(o) if o.ok()) {
        return exec::respond("certbot", issued);
    }

    install_hook("snpanel-sni-certs", SNI_HOOK);
    let _ = crate::ops::ssl::sync_sni();
    HelperResponse::with_stdout(format!("Wildcard certificate ready: {zone} and *.{zone}\n"))
}

/// Source: `^[A-Za-z0-9_.~-]{20,200}$`.
///
/// Narrow on purpose: this string is written into a file certbot reads as
/// configuration, so a newline in it would add a directive.
pub(crate) fn valid_cloudflare_token(token: &str) -> bool {
    (20..=200).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'~' || b == b'-')
}

/// Create at 0600 and only then write, so the secret is never briefly
/// readable.
fn write_private(path: &str, contents: &str) -> Result<(), HelperResponse> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            HelperResponse::failed(HelperErrorKind::Internal, format!("writing {path}: {e}"))
        })?;
    file.write_all(contents.as_bytes()).map_err(|e| {
        HelperResponse::failed(HelperErrorKind::Internal, format!("writing {path}: {e}"))
    })?;
    let _ = exec::run(&["chown", "root:root", path]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C19: the tools vhost is byte-identical to the bash's heredoc.
    ///
    /// Eight renderings, one per combination the function can produce, taken
    /// from bash itself so its own escaping of `$uri` and `$1` is part of
    /// what is compared. A `$` that reached nginx escaped, or one that did
    /// not reach it at all, is a configuration nginx either rejects or
    /// silently serves wrong.
    #[test]
    fn the_tools_vhost_is_byte_identical_to_the_bash_heredoc() {
        #[derive(serde::Deserialize)]
        struct Case {
            ipv6: bool,
            tls: bool,
            php_version: String,
            cert: String,
            key: String,
            rendered: String,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/tools_nginx.json");
        let raw = std::fs::read_to_string(&path).expect("the tools_nginx fixture");
        let cases: Vec<Case> = serde_json::from_str(&raw).expect("it parses");
        assert_eq!(cases.len(), 8);

        for case in &cases {
            // `tls()` asks the filesystem, so the rendering is driven through
            // the same two fragments the bash builds rather than through it.
            let config = ToolsConfig {
                ipv6: case.ipv6,
                cert: case.cert.clone(),
                key: case.key.clone(),
                php_version: case.php_version.clone(),
            };
            let got = render_for_test(&config, case.tls);
            assert_eq!(
                got, case.rendered,
                "ipv6={} tls={} php={}",
                case.ipv6, case.tls, case.php_version
            );
        }

        // The fixture has to actually differ across the axes, or eight
        // identical strings would satisfy the loop.
        let distinct: std::collections::BTreeSet<&str> =
            cases.iter().map(|c| c.rendered.as_str()).collect();
        assert_eq!(distinct.len(), 8, "the eight renderings must differ");
    }

    /// `tls()` reads the filesystem; this is the same render with that answer
    /// supplied, so the template can be compared without planting files.
    fn render_for_test(config: &ToolsConfig, tls: bool) -> String {
        let real = ToolsConfig {
            ipv6: config.ipv6,
            cert: if tls {
                config.cert.clone()
            } else {
                String::new()
            },
            key: if tls {
                config.key.clone()
            } else {
                String::new()
            },
            php_version: config.php_version.clone(),
        };
        if tls {
            // Point at files that exist so `tls()` agrees; the paths in the
            // rendering come from the fixture either way.
            let base = std::env::temp_dir().join(format!("tools-tls-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&base);
            let cert = base.join("fullchain.pem");
            let key = base.join("privkey.pem");
            let _ = std::fs::write(&cert, "x");
            let _ = std::fs::write(&key, "x");
            let out = render_tools_nginx(&ToolsConfig {
                ipv6: real.ipv6,
                cert: cert.to_string_lossy().into_owned(),
                key: key.to_string_lossy().into_owned(),
                php_version: real.php_version.clone(),
            });
            let out = out
                .replace(&cert.to_string_lossy().to_string(), &config.cert)
                .replace(&key.to_string_lossy().to_string(), &config.key);
            let _ = std::fs::remove_dir_all(&base);
            return out;
        }
        render_tools_nginx(&real)
    }

    /// TLS is on only when both files are named **and** both exist.
    ///
    /// A `.env` naming a certificate that is not on disk would render
    /// `ssl_certificate` for a missing file, and nginx then refuses to start -
    /// taking every website on the box down, not just the panel.
    #[test]
    fn a_missing_certificate_renders_no_ssl_block_rather_than_a_broken_one() {
        let base = std::env::temp_dir().join(format!("tools-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("the dir");
        let cert = base.join("fullchain.pem");
        let key = base.join("privkey.pem");

        let config = |c: &std::path::Path, k: &std::path::Path| ToolsConfig {
            ipv6: false,
            cert: c.to_string_lossy().into_owned(),
            key: k.to_string_lossy().into_owned(),
            php_version: "8.4".into(),
        };

        // Neither file exists yet.
        assert!(!render_tools_nginx(&config(&cert, &key)).contains("ssl_certificate"));
        // Only the certificate.
        std::fs::write(&cert, "x").expect("cert");
        assert!(!render_tools_nginx(&config(&cert, &key)).contains("ssl_certificate"));
        // Both.
        std::fs::write(&key, "x").expect("key");
        let rendered = render_tools_nginx(&config(&cert, &key));
        assert!(rendered.contains("listen 443 ssl http2 default_server;"));
        assert!(rendered.contains("ssl_certificate_key"));

        // Empty paths are never TLS, whatever is on disk.
        assert!(!render_tools_nginx(&ToolsConfig {
            ipv6: false,
            cert: String::new(),
            key: String::new(),
            php_version: "8.4".into(),
        })
        .contains("ssl_certificate"));

        let _ = std::fs::remove_dir_all(&base);
    }

    /// `env_set`: `sed -i "s|^KEY=.*|KEY=value|"` has no line range.
    ///
    /// A `.env` that ended up with the key twice comes out with both copies
    /// agreeing. The panel's loader takes the last one, so rewriting only the
    /// first would leave the old value in force while reporting the change.
    #[test]
    fn setting_a_key_rewrites_every_copy_of_it() {
        let text = "PANEL_PORT=2222\nOTHER=1\nPANEL_PORT=9999\n";
        let out = env_set_in(text, "PANEL_PORT", "8443");
        assert_eq!(out, "PANEL_PORT=8443\nOTHER=1\nPANEL_PORT=8443\n");

        // A key that is not there is appended.
        let out = env_set_in("OTHER=1\n", "PANEL_URL", "https://x:2222");
        assert_eq!(out, "OTHER=1\nPANEL_URL=https://x:2222\n");

        // An empty value is a value: clearing PANEL_DOMAIN is how a move to
        // an IP address says the panel has no domain any more.
        assert_eq!(
            env_set_in("PANEL_DOMAIN=old.example.com\n", "PANEL_DOMAIN", ""),
            "PANEL_DOMAIN=\n"
        );

        // A key that is a prefix of another is not the same key.
        let out = env_set_in("PANEL_PORT_OLD=1\nPANEL_PORT=2\n", "PANEL_PORT", "3");
        assert_eq!(out, "PANEL_PORT_OLD=1\nPANEL_PORT=3\n");

        // `env_get` takes the first, which is what awk's `exit` does.
        assert_eq!(
            env_get("A=1\nA=2\n", "A").as_deref(),
            Some("1"),
            "awk exits on the first match"
        );
        assert_eq!(env_get("A=x=y\n", "A").as_deref(), Some("x=y"));
        assert_eq!(env_get("B=1\n", "A"), None);
    }

    /// The Cloudflare token is written into a file certbot reads as
    /// configuration, so the character set is the validation.
    #[test]
    fn a_cloudflare_token_may_not_carry_a_newline() {
        assert!(valid_cloudflare_token(&"a".repeat(20)));
        assert!(valid_cloudflare_token(&"a".repeat(200)));
        assert!(valid_cloudflare_token("Abc-123_xyz.TOKEN~value"));

        // Too short, too long, empty.
        assert!(!valid_cloudflare_token(&"a".repeat(19)));
        assert!(!valid_cloudflare_token(&"a".repeat(201)));
        assert!(!valid_cloudflare_token(""));

        // A newline would add a directive to the credentials file.
        let base = "a".repeat(30);
        for bad in ["\n", "\r", " ", "=", "#", "\t", "'", "\"", "\0", "/"] {
            assert!(
                !valid_cloudflare_token(&format!("{base}{bad}")),
                "{bad:?} should be refused"
            );
        }
    }

    /// The renewal hooks are the bash's, byte for byte.
    ///
    /// They run as root when certbot renews, so what they contain matters
    /// more than most of this file. Compared against the heredocs rather than
    /// summarised.
    #[test]
    fn the_renewal_hooks_match_the_bash_heredocs() {
        let helper = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../installer/files/snpanel-helper.sh"),
        )
        .expect("the bash helper");

        for (marker, ours) in [
            (
                "cat >/etc/letsencrypt/renewal-hooks/deploy/snpanel-sni-certs <<'HOOK'\n",
                SNI_HOOK,
            ),
            (
                "cat >/etc/letsencrypt/renewal-hooks/deploy/snpanel-panel-cert <<'HOOK'\n",
                PANEL_CERT_HOOK,
            ),
        ] {
            let start = helper.find(marker).expect("the heredoc") + marker.len();
            let end = helper[start..].find("\nHOOK\n").expect("its end") + start;
            let theirs = format!("{}\n", &helper[start..end]);
            assert_eq!(ours, theirs, "hook at {marker}");
        }

        // Both are scripts, and both refuse to act without RENEWED_LINEAGE -
        // certbot sets it, and a hook run by hand without it must do nothing
        // rather than copy whatever happens to be in the live directory.
        for hook in [SNI_HOOK, PANEL_CERT_HOOK] {
            assert!(hook.starts_with("#!/usr/bin/env bash\n"));
            assert!(hook.contains("RENEWED_LINEAGE"));
            assert!(hook.contains("set -euo pipefail"));
        }
    }

    /// `is_ipv4` - `require_panel_host` accepts a domain, an IPv4 address or
    /// `localhost`, and nothing else.
    #[test]
    fn a_panel_host_is_a_domain_an_ipv4_address_or_localhost() {
        for good in ["192.0.2.1", "10.0.0.1", "255.255.255.255", "0.0.0.0"] {
            assert!(is_ipv4(good), "{good}");
        }
        for bad in [
            "256.1.1.1",
            "1.2.3",
            "1.2.3.4.5",
            "",
            "::1",
            "2001:db8::1",
            "1.2.3.-4",
            "0x7f.0.0.1",
            "example.com",
            "localhost",
        ] {
            assert!(!is_ipv4(bad), "{bad}");
        }
    }
}
