//! Website vhosts for the Hosting Edition: one Apache configuration file per
//! site, read by Apache (the standby) and by LiteSpeed Enterprise in its
//! Apache-configuration mode (the live server).
//!
//! It reproduces what the nginx templates do - the same refusals, the same
//! headers, the same front controller - with PHP through mod_lsapi, which
//! runs it as the site's owner inside CageFS and the owner's LVE. The PHP
//! version is the owner's, from CloudLinux's PHP Selector.
//!
//! Two constraints come from LiteSpeed reading these files too. Ports are
//! literal (`*:8080`, `*:8443`): it expands neither `Define` nor a bare
//! `<VirtualHost *>`, which it would take for every site's default. And a
//! refusal is a `RewriteRule [F]` rather than only a `Require`, because that
//! gives the same 403 from both servers whether or not the file exists.

use std::fmt::Write as _;

/// Apache's own ports; LiteSpeed adds its offset (9080/9443), and whichever
/// is live gets the public 80/443 through an nftables redirect.
pub const HTTP_PORT: u16 = 8080;
pub const HTTPS_PORT: u16 = 8443;

const HEADERS: &str = r#"    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()"
    Header always set Content-Security-Policy "default-src 'self' https: data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; font-src 'self' data: https:; connect-src 'self' https:; frame-src 'self' https: blob:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self' https:; frame-ancestors 'self'; upgrade-insecure-requests""#;

/// The nginx templates' `location ~* \.(?:sql|bak|...)$ { deny all; }`.
const DENY_EXT: &str = r"\.(?:sql|bak|backup|old|orig|save|swp|swo|ini|log|conf|env|sh|inc)$";

const ACME_ROOT: &str = "/var/www/snpanel-acme";

/// A certificate for the site, as files Apache and LiteSpeed read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslFiles {
    /// The full chain (leaf first), or the leaf alone when `chain` is given.
    pub cert: String,
    pub key: String,
    pub chain: Option<String>,
}

/// What a site's vhost is made of.
#[derive(Debug, Clone)]
pub struct ApacheSite {
    pub domain: String,
    /// Aliases that serve the site (`alias` mode).
    pub aliases: Vec<String>,
    /// Aliases that answer with a 301 to the site (`redirect` mode).
    pub redirects: Vec<String>,
    /// `/home/<user>/<domain>`.
    pub root_path: String,
    /// Relative, as the panel stores it (`public_html`).
    pub document_root: String,
    pub rewrite_mode: String,
    pub linux_user: String,
    /// wordpress, php, static or application.
    pub app_type: String,
    /// The application's loopback port, for `application`.
    pub app_port: Option<u16>,
    pub suspended: bool,
    pub ssl: Option<SslFiles>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RenderError(pub String);

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(message: impl Into<String>) -> Result<T, RenderError> {
    Err(RenderError(message.into()))
}

/// A hostname as a vhost may name it: the panel's domains are validated long
/// before they get here, and this is the last check before they reach a
/// configuration file both web servers parse.
fn hostname_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'*'
        })
        && !name.starts_with(['.', '-'])
        && !name.contains("..")
}

fn path_ok(path: &str) -> bool {
    path.starts_with('/')
        && !path.split('/').any(|c| c == ".." || c == ".")
        && !path
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\\')
}

/// The directory the site is served from, as the nginx renderer computes it.
pub fn effective_document_root(site: &ApacheSite) -> String {
    let root = format!(
        "{}/{}",
        site.root_path.trim_end_matches('/'),
        site.document_root.trim_matches('/')
    );
    let root = root.trim_end_matches('/').to_string();
    if matches!(site.rewrite_mode.as_str(), "laravel" | "codeigniter") && !root.ends_with("/public")
    {
        format!("{root}/public")
    } else {
        root
    }
}

fn validate(site: &ApacheSite) -> Result<(), RenderError> {
    for name in std::iter::once(&site.domain)
        .chain(&site.aliases)
        .chain(&site.redirects)
    {
        if !hostname_ok(name) {
            return refuse(format!("invalid hostname {name:?}"));
        }
    }
    let home = format!("/home/{}/", site.linux_user);
    if site.linux_user.is_empty()
        || !site
            .linux_user
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return refuse("invalid site owner");
    }
    let docroot = effective_document_root(site);
    if !path_ok(&site.root_path)
        || !site.root_path.starts_with(&home)
        || !path_ok(&docroot)
        || !docroot.starts_with(&home)
    {
        return refuse("the site's root must be inside its owner's home");
    }
    if !matches!(
        site.app_type.as_str(),
        "wordpress" | "php" | "static" | "application"
    ) {
        return refuse(format!("unknown app type {:?}", site.app_type));
    }
    if site.app_type == "application" && site.app_port.is_none() && !site.suspended {
        return refuse("an application site needs its application's port");
    }
    if let Some(ssl) = &site.ssl {
        let allowed = |p: &str| {
            path_ok(p)
                && (p.starts_with("/etc/letsencrypt/live/")
                    || p.starts_with("/etc/nginx/snpanel/ssl/sites/"))
        };
        if !allowed(&ssl.cert)
            || !allowed(&ssl.key)
            || ssl.chain.as_deref().is_some_and(|c| !allowed(c))
        {
            return refuse("certificate files must be the panel's or Let's Encrypt's");
        }
    }
    Ok(())
}

/// ACME challenges are answered by every vhost, before anything else, from
/// the directory certbot writes to.
fn acme(out: &mut String) {
    let _ = writeln!(
        out,
        "    Alias /.well-known/acme-challenge/ {ACME_ROOT}/.well-known/acme-challenge/"
    );
    let _ = writeln!(
        out,
        "    <Directory {ACME_ROOT}/.well-known/acme-challenge/>"
    );
    let _ = writeln!(out, "        Options None\n        AllowOverride None\n        ForceType text/plain\n        Require all granted");
    let _ = writeln!(out, "    </Directory>");
}

fn ssl_lines(out: &mut String, ssl: &SslFiles) {
    let _ = writeln!(out, "    SSLEngine on");
    let _ = writeln!(out, "    SSLCertificateFile {}", ssl.cert);
    let _ = writeln!(out, "    SSLCertificateKeyFile {}", ssl.key);
    if let Some(chain) = &ssl.chain {
        let _ = writeln!(out, "    SSLCertificateChainFile {chain}");
    }
}

fn logs(out: &mut String, domain: &str) {
    let _ = writeln!(out, "    ErrorLog /var/log/httpd/{domain}.error.log");
    let _ = writeln!(
        out,
        "    CustomLog /var/log/httpd/{domain}.access.log combined"
    );
}

/// The body both the HTTP and the HTTPS vhost of a site serve.
fn site_body(out: &mut String, site: &ApacheSite) {
    let d = &site.domain;
    let docroot = effective_document_root(site);
    let app = site.app_type.as_str();
    let php = matches!(app, "php" | "wordpress") && !site.suspended;

    let _ = writeln!(out, "    DocumentRoot {docroot}");
    let _ = writeln!(out, "    DirectoryIndex index.php index.html");
    logs(out, d);
    let _ = writeln!(out, "    LimitRequestBody 1153433600");
    let _ = writeln!(out, "{HEADERS}");
    acme(out);

    if site.suspended {
        let _ = writeln!(out, "    ErrorDocument 503 \"This website is suspended.\"");
        let _ = writeln!(out, "    RewriteEngine On");
        let _ = writeln!(
            out,
            "    RewriteCond %{{REQUEST_URI}} !^/\\.well-known/acme-challenge/"
        );
        let _ = writeln!(out, "    RewriteRule ^ - [R=503,L]");
        let _ = writeln!(out, "    IncludeOptional /etc/httpd/snpanel/waf/{d}/*.conf");
        return;
    }

    if php {
        let _ = writeln!(out, "    SuexecUserGroup {0} {0}", site.linux_user);
    }
    let _ = writeln!(
        out,
        "    <Directory {}>",
        site.root_path.trim_end_matches('/')
    );
    let _ = writeln!(
        out,
        "        Options -Indexes -FollowSymLinks +SymLinksIfOwnerMatch"
    );
    let _ = writeln!(out, "        AllowOverride FileInfo Options=Indexes,FollowSymLinks,SymLinksIfOwnerMatch Limit Indexes");
    let _ = writeln!(out, "        Require all granted");
    let _ = writeln!(out, "    </Directory>");

    // Refusals: as Require (a second layer) and as RewriteRule [F], which is
    // what gives both servers the same 403.
    let _ = writeln!(out, "    <LocationMatch \"/\\.(?!well-known)\">\n        Require all denied\n    </LocationMatch>");
    let mut deny: Vec<&str> = vec![r"/\.(?!well-known)"];
    if app != "static" {
        let _ = writeln!(
            out,
            "    <FilesMatch \"{DENY_EXT}\">\n        Require all denied\n    </FilesMatch>"
        );
        deny.push(DENY_EXT);
    }
    if app == "wordpress" {
        let _ = writeln!(out, "    <FilesMatch \"^(?:xmlrpc\\.php|wp-config\\.php|readme\\.html|license\\.txt)$\">\n        Require all denied\n    </FilesMatch>");
        let _ = writeln!(out, "    <LocationMatch \"(?i)/(?:uploads|files)/.*\\.php$\">\n        Require all denied\n    </LocationMatch>");
        let _ = writeln!(out, "    <LocationMatch \"(?i)^/(?:wp-admin/includes|wp-includes)/.*\\.php$\">\n        Require all denied\n    </LocationMatch>");
        deny.extend([
            r"^/(?:xmlrpc\.php|wp-config\.php|readme\.html|license\.txt)$",
            r"/(?:uploads|files)/.*\.php$",
            r"^/(?:wp-admin/includes|wp-includes)/.*\.php$",
        ]);
    }
    if app == "static" {
        let _ = writeln!(out, "    <LocationMatch \"(?i)\\.(?:php[0-9]?|phtml)$\">\n        Require all denied\n    </LocationMatch>");
        deny.push(r"\.(?:php[0-9]?|phtml)$");
    }
    let _ = writeln!(out, "    RewriteEngine On");
    for pattern in deny {
        let _ = writeln!(out, "    RewriteRule \"(?i){pattern}\" - [F]");
    }

    if php {
        let _ = writeln!(out, "    <FilesMatch \"\\.(?:php|phtml)$\">\n        SetHandler application/x-httpd-lsphp\n    </FilesMatch>");
        // The front controller in the vhost, so it does not depend on the
        // customer's .htaccess (nginx: try_files $uri $uri/ /index.php).
        if app == "wordpress"
            || matches!(
                site.rewrite_mode.as_str(),
                "laravel" | "front_controller" | "codeigniter"
            )
        {
            let _ = writeln!(out, "    RewriteCond %{{REQUEST_URI}} !^/\\.well-known/");
            let _ = writeln!(
                out,
                "    RewriteCond %{{DOCUMENT_ROOT}}%{{REQUEST_URI}} !-f"
            );
            let _ = writeln!(
                out,
                "    RewriteCond %{{DOCUMENT_ROOT}}%{{REQUEST_URI}} !-d"
            );
            let _ = writeln!(out, "    RewriteRule ^ /index.php [L]");
        }
    }
    if app == "application" {
        if let Some(port) = site.app_port {
            let _ = writeln!(out, "    ProxyPreserveHost On");
            let _ = writeln!(
                out,
                "    RequestHeader set X-Forwarded-Proto expr=%{{REQUEST_SCHEME}}"
            );
            let _ = writeln!(out, "    ProxyPass /.well-known/acme-challenge/ !");
            let _ = writeln!(
                out,
                "    ProxyPass / http://127.0.0.1:{port}/ upgrade=websocket"
            );
            let _ = writeln!(out, "    ProxyPassReverse / http://127.0.0.1:{port}/");
        }
    }
    let _ = writeln!(out, "    IncludeOptional /etc/httpd/snpanel/waf/{d}/*.conf");
}

/// A redirect-mode alias: every request to the site's canonical name.
fn redirect_vhost(
    out: &mut String,
    name: &str,
    site: &ApacheSite,
    port: u16,
    ssl: Option<&SslFiles>,
) {
    let scheme = if ssl.is_some() || site.ssl.is_some() {
        "https"
    } else {
        "http"
    };
    let _ = writeln!(out, "\n<VirtualHost *:{port}>");
    let _ = writeln!(out, "    ServerName {name}");
    logs(out, &site.domain);
    acme(out);
    if let Some(ssl) = ssl {
        ssl_lines(out, ssl);
    }
    let _ = writeln!(out, "    RewriteEngine On");
    let _ = writeln!(
        out,
        "    RewriteCond %{{REQUEST_URI}} !^/\\.well-known/acme-challenge/"
    );
    let _ = writeln!(
        out,
        "    RewriteRule ^ {scheme}://{}%{{REQUEST_URI}} [R=301,L]",
        site.domain
    );
    let _ = writeln!(out, "</VirtualHost>");
}

/// The site's whole configuration file.
///
/// Without a certificate: one vhost on 8080 that serves the site. With one:
/// the site on 8443, and 8080 answering every request but ACME's with a 301
/// to https - what `certbot install --redirect` did to the nginx vhost.
pub fn render(site: &ApacheSite) -> Result<String, RenderError> {
    validate(site)?;
    let d = &site.domain;
    let mut names: Vec<String> = vec![format!("www.{d}")];
    names.extend(site.aliases.iter().cloned());
    names.dedup();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "# SNPANEL MANAGED VHOST - {d}. Written by the panel; changes here are overwritten."
    );
    let _ = writeln!(out, "<VirtualHost *:{HTTP_PORT}>");
    let _ = writeln!(out, "    ServerName {d}");
    let _ = writeln!(out, "    ServerAlias {}", names.join(" "));
    match &site.ssl {
        None => site_body(&mut out, site),
        Some(_) => {
            logs(&mut out, d);
            acme(&mut out);
            let _ = writeln!(out, "    RewriteEngine On");
            let _ = writeln!(
                out,
                "    RewriteCond %{{REQUEST_URI}} !^/\\.well-known/acme-challenge/"
            );
            let _ = writeln!(
                out,
                "    RewriteRule ^ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [R=301,L]"
            );
        }
    }
    let _ = writeln!(out, "</VirtualHost>");

    if let Some(ssl) = &site.ssl {
        let _ = writeln!(out, "\n<VirtualHost *:{HTTPS_PORT}>");
        let _ = writeln!(out, "    ServerName {d}");
        let _ = writeln!(out, "    ServerAlias {}", names.join(" "));
        ssl_lines(&mut out, ssl);
        site_body(&mut out, site);
        let _ = writeln!(out, "</VirtualHost>");
    }

    for name in &site.redirects {
        redirect_vhost(&mut out, name, site, HTTP_PORT, None);
        if let Some(ssl) = &site.ssl {
            redirect_vhost(&mut out, name, site, HTTPS_PORT, Some(ssl));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(app: &str) -> ApacheSite {
        ApacheSite {
            domain: "shop.example.com".into(),
            aliases: vec!["example.net".into()],
            redirects: vec![],
            root_path: "/home/alice/shop.example.com".into(),
            document_root: "public_html".into(),
            rewrite_mode: "none".into(),
            linux_user: "alice".into(),
            app_type: app.into(),
            app_port: None,
            suspended: false,
            ssl: None,
        }
    }

    fn le() -> SslFiles {
        SslFiles {
            cert: "/etc/letsencrypt/live/shop.example.com/fullchain.pem".into(),
            key: "/etc/letsencrypt/live/shop.example.com/privkey.pem".into(),
            chain: None,
        }
    }

    #[test]
    fn a_php_site_runs_php_as_its_owner_through_lsapi() {
        let text = render(&site("php")).unwrap();
        assert!(text.contains("<VirtualHost *:8080>"));
        assert!(!text.contains("*:8443"));
        assert!(text.contains("ServerAlias www.shop.example.com example.net"));
        assert!(text.contains("DocumentRoot /home/alice/shop.example.com/public_html\n"));
        assert!(text.contains("SuexecUserGroup alice alice"));
        assert!(text.contains("SetHandler application/x-httpd-lsphp"));
        assert!(text.contains("IncludeOptional /etc/httpd/snpanel/waf/shop.example.com/*.conf"));
        assert!(text.contains("/var/log/httpd/shop.example.com.access.log combined"));
    }

    #[test]
    fn a_static_site_refuses_php_and_runs_none() {
        let text = render(&site("static")).unwrap();
        assert!(!text.contains("SetHandler"));
        assert!(!text.contains("SuexecUserGroup"));
        assert!(text.contains(r#"RewriteRule "(?i)\.(?:php[0-9]?|phtml)$" - [F]"#));
    }

    #[test]
    fn wordpress_gets_its_refusals_and_a_front_controller() {
        let text = render(&site("wordpress")).unwrap();
        assert!(text.contains("xmlrpc"));
        assert!(text.contains("RewriteRule ^ /index.php [L]"));
    }

    #[test]
    fn laravel_is_served_from_public() {
        let mut s = site("php");
        s.rewrite_mode = "laravel".into();
        let text = render(&s).unwrap();
        assert!(text.contains("DocumentRoot /home/alice/shop.example.com/public_html/public\n"));
        assert!(text.contains("RewriteRule ^ /index.php [L]"));
    }

    #[test]
    fn with_a_certificate_http_redirects_and_https_serves() {
        let mut s = site("php");
        s.ssl = Some(le());
        let text = render(&s).unwrap();
        let (http, https) = text.split_once("<VirtualHost *:8443>").unwrap();
        assert!(http.contains("RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]"));
        assert!(
            http.contains("acme-challenge"),
            "certbot must still reach port 80"
        );
        assert!(!http.contains("SetHandler"));
        assert!(https.contains("SSLEngine on"));
        assert!(https
            .contains("SSLCertificateFile /etc/letsencrypt/live/shop.example.com/fullchain.pem"));
        assert!(https.contains("SetHandler application/x-httpd-lsphp"));
    }

    #[test]
    fn redirect_aliases_send_everything_to_the_site() {
        let mut s = site("php");
        s.redirects = vec!["old.example.org".into()];
        let text = render(&s).unwrap();
        assert!(text.contains("ServerName old.example.org"));
        assert!(text.contains("RewriteRule ^ http://shop.example.com%{REQUEST_URI} [R=301,L]"));
        s.ssl = Some(le());
        let text = render(&s).unwrap();
        assert_eq!(text.matches("ServerName old.example.org").count(), 2);
        assert!(text.contains("RewriteRule ^ https://shop.example.com%{REQUEST_URI} [R=301,L]"));
    }

    #[test]
    fn a_suspended_site_answers_503_and_runs_nothing() {
        let mut s = site("wordpress");
        s.suspended = true;
        let text = render(&s).unwrap();
        assert!(text.contains("RewriteRule ^ - [R=503,L]"));
        assert!(!text.contains("SetHandler"));
        assert!(!text.contains("SuexecUserGroup"));
    }

    #[test]
    fn an_application_is_proxied_to_its_loopback_port() {
        let mut s = site("application");
        assert!(render(&s).is_err());
        s.app_port = Some(3000);
        let text = render(&s).unwrap();
        assert!(text.contains("ProxyPass /.well-known/acme-challenge/ !"));
        assert!(text.contains("ProxyPass / http://127.0.0.1:3000/ upgrade=websocket"));
    }

    #[test]
    fn nothing_outside_the_owners_home_or_the_certificate_stores() {
        let mut s = site("php");
        s.root_path = "/home/bob/shop.example.com".into();
        assert!(render(&s).is_err());
        let mut s = site("php");
        s.document_root = "../../etc".into();
        assert!(render(&s).is_err());
        let mut s = site("php");
        s.ssl = Some(SslFiles {
            cert: "/etc/shadow".into(),
            key: "/etc/shadow".into(),
            chain: None,
        });
        assert!(render(&s).is_err());
        let mut s = site("php");
        s.aliases = vec!["evil.com\n    Include /etc/passwd".into()];
        assert!(render(&s).is_err());
    }
}
