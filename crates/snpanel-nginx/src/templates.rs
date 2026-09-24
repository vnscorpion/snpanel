//! The four vhost bodies, and the placeholder page.
//!
//! **Generated from the Jinja templates, not retyped.** They were
//! `templates/*.conf.j2`, rendered with minijinja - which is how the port
//! guaranteed C19, since the templates were the ones the Python used and the
//! fixtures were what real Jinja2 produced from them.
//!
//! The Python is gone, so the other side of that contract is now the
//! fixtures themselves, and a template engine at run time buys nothing: the
//! whole conditional surface of these four files is `ipv6`,
//! `http_flood_enabled` with `http_flood_burst > 0` inside it, `waf_enabled`,
//! and one four-way branch on `rewrite_mode` in the PHP one. Everything else
//! is literal nginx.
//!
//! So these are Rust, and `minijinja` has left the dependency tree.
//!
//! **Read these against the fixtures, not against your memory of nginx.** A
//! newline moved from one side of an `{{ "{%" }} endif {{ "%}" }}` to the
//! other is a vhost that still parses and no longer matches what the box
//! already has, which is the failure C19 exists to prevent.

/// Everything the four bodies interpolate.
///
/// One struct rather than four, because the header - the first twenty-six
/// lines, down to the end of the WAF block - was identical in all four
/// templates and still is here.
pub(crate) struct Vars<'a> {
    pub ipv6: bool,
    pub domain: &'a str,
    pub server_names: &'a [String],
    pub root_path: &'a str,
    pub document_root_path: &'a str,
    pub php_fpm_socket: &'a str,
    pub custom_include_path: &'a str,
    pub waf_enabled: bool,
    pub waf_rules_file: &'a str,
    pub http_flood_enabled: bool,
    pub http_flood_zone: &'a str,
    pub http_flood_burst: i64,
    pub http_flood_connections: i64,
    pub http_flood_challenge_block: &'a str,
    pub rewrite_mode: &'a str,
    /// Only the proxied type has one, and only that template reads it.
    pub app_port: i64,
    pub proxy_timeout: u32,
}

/// Source: `templates/wordpress.conf.j2`.
pub(crate) fn wordpress(v: &Vars<'_>) -> String {
    let mut out = String::new();
    out.push_str(
        r"server {
    listen 80;
",
    );
    if v.ipv6 {
        out.push_str(
            r"    listen [::]:80;
",
        );
    }
    out.push_str(r"    server_name ");
    out.push_str(&v.server_names.join(" "));
    out.push_str(
        r";
    root ",
    );
    out.push_str(v.document_root_path);
    out.push_str(
        r";
    index index.php index.html;

    server_tokens off;
    disable_symlinks if_not_owner from=",
    );
    out.push_str(v.root_path);
    out.push_str(
        r";

",
    );
    if v.http_flood_enabled {
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD BEGIN
    limit_req zone=",
        );
        out.push_str(v.http_flood_zone);
        if v.http_flood_burst > 0 {
            out.push_str(r" burst=");
            out.push_str(&v.http_flood_burst.to_string());
        }
        out.push_str(
            r";
    limit_conn snpanel_conn_flood ",
        );
        out.push_str(&v.http_flood_connections.to_string());
        out.push_str(
            r";
    limit_req_status 429;
    limit_conn_status 429;
",
        );
        out.push_str(v.http_flood_challenge_block);
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD END
",
        );
    }
    out.push_str(
        r"

",
    );
    if v.waf_enabled {
        out.push_str(
            r"
    # SNPANEL WAF BEGIN
    modsecurity on;
    modsecurity_rules_file ",
        );
        out.push_str(v.waf_rules_file);
        out.push_str(
            r";
    # SNPANEL WAF END
",
        );
    }
    out.push_str(
        r"

    access_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(
        r".access.log;
    error_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(r#".error.log;

    client_max_body_size 1100M;

    # SNPANEL ACME CHALLENGE
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/snpanel-acme;
        default_type text/plain;
        try_files $uri =404;
        access_log off;
        auth_basic off;
    }

    # SNPANEL FASTCGI CACHE SERVER BEGIN
    set $snpanel_skip_cache 0;
    if ($request_method = POST) { set $snpanel_skip_cache 1; }
    if ($query_string != "") { set $snpanel_skip_cache 1; }
    if ($http_cache_control ~* "no-cache|no-store|max-age=0") { set $snpanel_skip_cache 1; }
    if ($http_pragma = "no-cache") { set $snpanel_skip_cache 1; }
    if ($request_uri ~* "/wp-admin/|/wp-login.php|/xmlrpc.php|wp-.*.php|/feed/|sitemap(_index)?\.xml") { set $snpanel_skip_cache 1; }
    if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wordpress_logged_in|wp-postpass|woocommerce_items_in_cart|woocommerce_cart_hash|wp_woocommerce_session|edd_items_in_cart") { set $snpanel_skip_cache 1; }
    add_header X-FastCGI-Cache $upstream_cache_status always;
    # SNPANEL FASTCGI CACHE SERVER END

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()" always;
    add_header Content-Security-Policy "default-src 'self' https: data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; font-src 'self' data: https:; connect-src 'self' https:; frame-src 'self' https: blob:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self' https:; frame-ancestors 'self'; upgrade-insecure-requests" always;

    autoindex off;

    location = /xmlrpc.php {
        deny all;
        access_log off;
        log_not_found off;
    }

    location = /wp-config.php {
        deny all;
    }

    location = /readme.html {
        deny all;
    }

    location = /license.txt {
        deny all;
    }

    location ~* /(?:uploads|files)/.*\.php$ {
        deny all;
    }

    location ~* ^/(?:wp-admin/includes|wp-includes)/.*\.php$ {
        deny all;
    }

    location ~* \.(?:sql|bak|backup|old|orig|save|swp|swo|ini|log|conf|env|sh|inc)$ {
        deny all;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }

    location ~ \.php$ {
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTP_PROXY "";
        fastcgi_pass unix:"#);
    out.push_str(v.php_fpm_socket);
    out.push_str(
        r";
        fastcgi_read_timeout 300;
        # SNPANEL FASTCGI CACHE LOCATION BEGIN
        fastcgi_cache SNPANEL_FASTCGI;
        fastcgi_cache_methods GET HEAD;
        fastcgi_cache_valid 200 15s;
        fastcgi_cache_min_uses 2;
        fastcgi_cache_bypass $snpanel_skip_cache;
        fastcgi_no_cache $snpanel_skip_cache;
        fastcgi_no_cache $upstream_http_set_cookie;
        fastcgi_cache_lock on;
        # SNPANEL FASTCGI CACHE LOCATION END
    }

    location ~ /\.ht {
        deny all;
    }

    # SNPANEL CUSTOM INCLUDE
    include ",
    );
    out.push_str(v.custom_include_path);
    out.push_str(
        r";

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~* \.(jpg|jpeg|gif|png|css|js|ico|webp|svg|woff|woff2|ttf|eot)$ {
        expires -1;
        access_log off;
    }
}",
    );
    out
}

/// Source: `templates/php.conf.j2`.
pub(crate) fn php(v: &Vars<'_>) -> String {
    let mut out = String::new();
    out.push_str(
        r"server {
    listen 80;
",
    );
    if v.ipv6 {
        out.push_str(
            r"    listen [::]:80;
",
        );
    }
    out.push_str(r"    server_name ");
    out.push_str(&v.server_names.join(" "));
    out.push_str(
        r";
    root ",
    );
    out.push_str(v.document_root_path);
    out.push_str(
        r";
    index index.php index.html index.htm;

    server_tokens off;
    disable_symlinks if_not_owner from=",
    );
    out.push_str(v.root_path);
    out.push_str(
        r";

",
    );
    if v.http_flood_enabled {
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD BEGIN
    limit_req zone=",
        );
        out.push_str(v.http_flood_zone);
        if v.http_flood_burst > 0 {
            out.push_str(r" burst=");
            out.push_str(&v.http_flood_burst.to_string());
        }
        out.push_str(
            r";
    limit_conn snpanel_conn_flood ",
        );
        out.push_str(&v.http_flood_connections.to_string());
        out.push_str(
            r";
    limit_req_status 429;
    limit_conn_status 429;
",
        );
        out.push_str(v.http_flood_challenge_block);
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD END
",
        );
    }
    out.push_str(
        r"

",
    );
    if v.waf_enabled {
        out.push_str(
            r"
    # SNPANEL WAF BEGIN
    modsecurity on;
    modsecurity_rules_file ",
        );
        out.push_str(v.waf_rules_file);
        out.push_str(
            r";
    # SNPANEL WAF END
",
        );
    }
    out.push_str(
        r"

    access_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(
        r".access.log;
    error_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(r#".error.log;

    client_max_body_size 1100M;

    # SNPANEL ACME CHALLENGE
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/snpanel-acme;
        default_type text/plain;
        try_files $uri =404;
        access_log off;
        auth_basic off;
    }

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

    autoindex off;

    location ~* \.(?:sql|bak|backup|old|orig|save|swp|swo|ini|log|conf|env|sh|inc)$ {
        deny all;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }

    location ~ \.php$ {
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTP_PROXY "";
        fastcgi_pass unix:"#);
    out.push_str(v.php_fpm_socket);
    out.push_str(
        r";
        fastcgi_read_timeout 300;
    }

    location ~ /\.ht {
        deny all;
    }

    # SNPANEL CUSTOM INCLUDE
    include ",
    );
    out.push_str(v.custom_include_path);
    out.push_str(
        r";

",
    );
    if matches!(
        v.rewrite_mode,
        "front_controller" | "laravel" | "codeigniter"
    ) {
        out.push_str(
            r"
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
",
        );
    } else if v.rewrite_mode == "seohburl" {
        out.push_str(
            r"
    location / {
        try_files $uri $uri/ @seohburl;
    }

    location @seohburl {
        rewrite ^/(.+)$ /index.php?/$1 last;
    }
",
        );
    } else {
        out.push_str(
            r"
    location / {
        try_files $uri $uri/ =404;
    }
",
        );
    }
    out.push_str(
        r"

    location ~* \.(jpg|jpeg|gif|png|css|js|ico|webp|svg|woff|woff2|ttf|eot)$ {
        expires -1;
        access_log off;
    }
}",
    );
    out
}

/// Source: `templates/static.conf.j2`.
pub(crate) fn r#static(v: &Vars<'_>) -> String {
    let mut out = String::new();
    out.push_str(
        r"server {
    listen 80;
",
    );
    if v.ipv6 {
        out.push_str(
            r"    listen [::]:80;
",
        );
    }
    out.push_str(r"    server_name ");
    out.push_str(&v.server_names.join(" "));
    out.push_str(
        r";
    root ",
    );
    out.push_str(v.document_root_path);
    out.push_str(
        r";
    index index.html index.htm;

    server_tokens off;
    disable_symlinks if_not_owner from=",
    );
    out.push_str(v.root_path);
    out.push_str(
        r";

",
    );
    if v.http_flood_enabled {
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD BEGIN
    limit_req zone=",
        );
        out.push_str(v.http_flood_zone);
        if v.http_flood_burst > 0 {
            out.push_str(r" burst=");
            out.push_str(&v.http_flood_burst.to_string());
        }
        out.push_str(
            r";
    limit_conn snpanel_conn_flood ",
        );
        out.push_str(&v.http_flood_connections.to_string());
        out.push_str(
            r";
    limit_req_status 429;
    limit_conn_status 429;
",
        );
        out.push_str(v.http_flood_challenge_block);
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD END
",
        );
    }
    out.push_str(
        r"

",
    );
    if v.waf_enabled {
        out.push_str(
            r"
    # SNPANEL WAF BEGIN
    modsecurity on;
    modsecurity_rules_file ",
        );
        out.push_str(v.waf_rules_file);
        out.push_str(
            r";
    # SNPANEL WAF END
",
        );
    }
    out.push_str(
        r"

    access_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(
        r".access.log;
    error_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(r#".error.log;

    client_max_body_size 1100M;

    # SNPANEL ACME CHALLENGE
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/snpanel-acme;
        default_type text/plain;
        try_files $uri =404;
        access_log off;
        auth_basic off;
    }

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

    autoindex off;

    location ~* \.(?:sql|bak|backup|old|orig|save|swp|swo|ini|log|conf|env|sh|inc)$ {
        deny all;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }

    location ~ /\.ht {
        deny all;
    }

    # Static-only site: refuse to execute any PHP / CGI even if a script
    # somehow lands in the document root.
    location ~* \.(?:php|phtml|phar|php3|php4|php5|php7|php8|cgi|pl|py)$ {
        deny all;
        return 403;
    }

    # SNPANEL CUSTOM INCLUDE
    include "#);
    out.push_str(v.custom_include_path);
    out.push_str(
        r";

    location / {
        try_files $uri $uri/ =404;
    }

    location ~* \.(jpg|jpeg|gif|png|css|js|ico|webp|svg|woff|woff2|ttf|eot)$ {
        expires -1;
        access_log off;
    }
}",
    );
    out
}

/// Source: `templates/proxy.conf.j2`, the `application` type.
pub(crate) fn proxy(v: &Vars<'_>) -> String {
    let mut out = String::new();
    out.push_str(
        r"server {
    listen 80;
",
    );
    if v.ipv6 {
        out.push_str(
            r"    listen [::]:80;
",
        );
    }
    out.push_str(r"    server_name ");
    out.push_str(&v.server_names.join(" "));
    out.push_str(
        r";
    root ",
    );
    out.push_str(v.document_root_path);
    out.push_str(
        r";

    server_tokens off;
    disable_symlinks if_not_owner from=",
    );
    out.push_str(v.root_path);
    out.push_str(
        r";

",
    );
    if v.http_flood_enabled {
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD BEGIN
    limit_req zone=",
        );
        out.push_str(v.http_flood_zone);
        if v.http_flood_burst > 0 {
            out.push_str(r" burst=");
            out.push_str(&v.http_flood_burst.to_string());
        }
        out.push_str(
            r";
    limit_conn snpanel_conn_flood ",
        );
        out.push_str(&v.http_flood_connections.to_string());
        out.push_str(
            r";
    limit_req_status 429;
    limit_conn_status 429;
",
        );
        out.push_str(v.http_flood_challenge_block);
        out.push_str(
            r"
    # SNPANEL HTTP FLOOD END
",
        );
    }
    out.push_str(
        r"

",
    );
    if v.waf_enabled {
        out.push_str(
            r"
    # SNPANEL WAF BEGIN
    modsecurity on;
    modsecurity_rules_file ",
        );
        out.push_str(v.waf_rules_file);
        out.push_str(
            r";
    # SNPANEL WAF END
",
        );
    }
    out.push_str(
        r"

    access_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(
        r".access.log;
    error_log /var/log/nginx/",
    );
    out.push_str(v.domain);
    out.push_str(r#".error.log;

    client_max_body_size 1100M;

    # SNPANEL ACME CHALLENGE
    # Served from disk, ahead of the proxy, so certificate renewal never depends
    # on the application being up.
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/snpanel-acme;
        default_type text/plain;
        try_files $uri =404;
        access_log off;
        auth_basic off;
    }

    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

    autoindex off;

    location ~ /\.(?!well-known) {
        deny all;
    }

    # SNPANEL CUSTOM INCLUDE
    include "#);
    out.push_str(v.custom_include_path);
    out.push_str(
        r";

    # SNPANEL PROXY BEGIN
    location / {
        proxy_pass http://127.0.0.1:",
    );
    out.push_str(&v.app_port.to_string());
    out.push_str(
        r";
        proxy_http_version 1.1;

        # WebSocket upgrade. $connection_upgrade comes from the map in
        # /etc/nginx/conf.d/00-snpanel-upgrade-map.conf.
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        proxy_redirect off;
        # Off so server-sent events and long-polling reach the browser as they
        # happen instead of sitting in a buffer.
        proxy_buffering off;
        proxy_request_buffering off;

        proxy_connect_timeout 30s;
        proxy_send_timeout ",
    );
    out.push_str(&v.proxy_timeout.to_string());
    out.push_str(
        r"s;
        proxy_read_timeout ",
    );
    out.push_str(&v.proxy_timeout.to_string());
    out.push_str(
        r"s;
    }
    # SNPANEL PROXY END
}",
    );
    out
}

/// Source: `templates/placeholder.html.j2`, by way of `_write_placeholder_page`.
///
/// The one page that is escaped. The vhost bodies above cannot be - escaping
/// would corrupt the config - but this is HTML, and the domain is
/// interpolated into a `<title>` and a `<div>`.
///
/// Today every domain that reaches here has already been through `Domain`,
/// so `[a-z0-9-.]` is all it can hold and the escape does nothing. It is here
/// so that constraint stops being the thing keeping the page safe.
pub(crate) fn placeholder(domain: &str) -> String {
    let domain = &escape_html(domain);
    let mut out = String::new();
    out.push_str(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8" />
  <title>"#,
    );
    out.push_str(domain);
    out.push_str(r#"</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow">
  <style>
    :root {
      --bg1: #f9fafb;
      --bg2: #fefce8;
      --bg3: #e0f2fe;
      --accent-green: #22c55e;
      --accent-yellow: #eab308;
      --accent-orange: #f97316;
      --card-bg: rgba(255, 255, 255, 0.9);
      --card-border: rgba(15, 23, 42, 0.06);
      --card-shadow: 0 18px 45px rgba(15, 23, 42, 0.12);
      --text-main: #0f172a;
      --text-muted: #6b7280;
      --chip-bg: rgba(255, 255, 255, 0.9);
      --chip-border: rgba(15, 23, 42, 0.08);
      --footer-chip-bg: rgba(255, 255, 255, 0.8);
    }
    :root[data-theme="dark"] {
      --bg1: #020617;
      --bg2: #020617;
      --bg3: #020617;
      --card-bg: rgba(15, 23, 42, 0.96);
      --card-border: rgba(148, 163, 184, 0.28);
      --card-shadow: 0 26px 70px rgba(0, 0, 0, 0.9);
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --chip-bg: rgba(15, 23, 42, 0.96);
      --chip-border: rgba(148, 163, 184, 0.5);
      --footer-chip-bg: rgba(15, 23, 42, 0.96);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      text-align: center;
      color: var(--text-main);
      overflow: hidden;
      position: relative;
      background: linear-gradient(180deg, var(--bg1) 0%, var(--bg2) 45%, var(--bg3) 100%);
    }
    .spot {
      position: absolute;
      border-radius: 50%;
      filter: blur(120px);
      opacity: 0.35;
      animation: float 18s ease-in-out infinite alternate;
      pointer-events: none;
    }
    .spot.green { width: 420px; height: 420px; background: var(--accent-green); top: 5%; left: 10%; animation-delay: 0s; }
    .spot.yellow { width: 380px; height: 380px; background: var(--accent-yellow); bottom: 10%; right: 10%; animation-delay: 2s; }
    .spot.orange { width: 320px; height: 320px; background: var(--accent-orange); top: 60%; left: 50%; animation-delay: 4s; }
    @keyframes float {
      0% { transform: translateY(0) scale(1); }
      50% { transform: translateY(-30px) scale(1.03); opacity: 0.45; }
      100% { transform: translateY(20px) scale(1.08); opacity: 0.3; }
    }
    .theme-toggle {
      position: fixed;
      top: 20px;
      right: 24px;
      z-index: 10;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 8px;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.4);
      background: rgba(255, 255, 255, 0.8);
      cursor: pointer;
      user-select: none;
      transition: background 0.3s ease, border-color 0.3s ease;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
    }
    :root[data-theme="dark"] .theme-toggle { background: rgba(15, 23, 42, 0.9); border-color: rgba(148, 163, 184, 0.4); box-shadow: 0 0 18px rgba(255, 255, 255, 0.04); }
    .theme-icon { width: 18px; height: 18px; display: inline-flex; align-items: center; justify-content: center; color: var(--text-main); opacity: 0.5; transition: opacity 0.2s ease; }
    :root[data-theme="light"] .theme-icon.sun, :root[data-theme="dark"] .theme-icon.moon { opacity: 1; }
    .theme-icon svg { width: 100%; height: 100%; stroke: currentColor; fill: none; stroke-width: 1.6; }
    .card {
      position: relative;
      z-index: 1;
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      background: var(--card-bg);
      border-radius: 16px;
      box-shadow: var(--card-shadow);
      padding: 48px 38px 36px;
      max-width: 480px;
      width: 100%;
      border: 1px solid var(--card-border);
    }
    .title { font-size: 20px; font-weight: 600; margin-bottom: 10px; }
    .subtitle { font-size: 14px; color: var(--text-muted); margin-bottom: 26px; line-height: 1.6; }
    .host {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
      font-size: 13px;
      padding: 6px 10px;
      background: var(--chip-bg);
      border-radius: 999px;
      border: 1px solid var(--chip-border);
      display: inline-block;
      margin-bottom: 24px;
      color: var(--text-main);
    }
    .loader { display: flex; justify-content: center; gap: 10px; margin-bottom: 24px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; opacity: 0.4; animation: pulse 1.6s infinite; }
    .dot:nth-child(1) { background: var(--accent-yellow); }
    .dot:nth-child(2) { background: var(--accent-orange); animation-delay: 0.2s; }
    .dot:nth-child(3) { background: var(--accent-green); animation-delay: 0.4s; }
    @keyframes pulse {
      0%, 80%, 100% { opacity: 0.35; transform: scale(1); }
      40% { opacity: 1; transform: scale(1.4); }
    }
    .message { font-size: 15px; font-weight: 500; transition: opacity 0.6s ease; min-height: 24px; margin-bottom: 8px; }
    .footer { margin-top: 16px; font-size: 12px; color: var(--text-muted); }
    .footer code { background: var(--footer-chip-bg); border-radius: 4px; padding: 0 4px; font-size: 11px; }
    code { background: rgba(0,0,0,0.03); border-radius: 4px; padding: 0 4px; font-size: 12px; }
    :root[data-theme="dark"] code { background: rgba(15,23,42,0.9); }
    @media (max-width: 480px) { .card { padding: 32px 20px 24px; } .title { font-size: 19px; } }
  </style>
</head>
<body>
  <div class="spot green"></div>
  <div class="spot yellow"></div>
  <div class="spot orange"></div>

  <div class="theme-toggle" id="theme-toggle" aria-label="Toggle theme" title="Toggle light/dark theme">
    <span class="theme-icon sun">
      <svg viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="4"></circle>
        <g stroke-linecap="round">
          <line x1="12" y1="2" x2="12" y2="4"></line>
          <line x1="12" y1="20" x2="12" y2="22"></line>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
          <line x1="2" y1="12" x2="4" y2="12"></line>
          <line x1="20" y1="12" x2="22" y2="12"></line>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </g>
      </svg>
    </span>
    <span class="theme-icon moon">
      <svg viewBox="0 0 24 24">
        <path d="M20 14.5A7.5 7.5 0 0 1 10.5 5a7.5 7.5 0 1 0 9.5 9.5Z" />
      </svg>
    </span>
  </div>

  <main class="card">
    <h1 class="title">This site is waiting for content</h1>
    <p class="subtitle">Deploy your files when they're ready to shine.</p>
    <div class="host">"#);
    out.push_str(domain);
    out.push_str(r#"</div>
    <div class="loader">
      <div class="dot"></div>
      <div class="dot"></div>
      <div class="dot"></div>
    </div>
    <div class="message" id="message">Coming soon: an awesome project.</div>
    <div class="footer">If you see this page, your DNS and server setup has been completed correctly.</div>
  </main>

  <script>
    const messages = [
      "Coming soon: an awesome project.",
      "A cool project is on the way.",
      "Preparing something amazing for you...",
      "Stay tuned for updates!",
      "Building something special behind the scenes...",
      "Almost ready to launch!",
      "Magic is happening... please wait a bit!",
      "Good things take time — we're almost there.",
      "The future home of something great.",
      "Just polishing the final details...",
      "Something new is loading...",
      "We're crafting an experience you'll love.",
      "Innovation in progress...",
      "Your next favorite website is on its way.",
    ];
    let index = 0;
    const msgEl = document.getElementById("message");
    function cycle() {
      msgEl.style.opacity = 0;
      setTimeout(() => {
        index = (index + 1) % messages.length;
        msgEl.textContent = messages[index];
        msgEl.style.opacity = 1;
      }, 600);
    }
    setInterval(cycle, 4000);
    (function () {
      const root = document.documentElement;
      const toggle = document.getElementById("theme-toggle");
      function applyTheme(theme) { root.setAttribute("data-theme", theme); }
      try {
        const stored = localStorage.getItem("placeholder-theme");
        if (stored === "dark" || stored === "light") { applyTheme(stored); }
        else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) { applyTheme("dark"); }
      } catch (e) {}
      toggle.addEventListener("click", function () {
        const current = root.getAttribute("data-theme") === "dark" ? "dark" : "light";
        const next = current === "dark" ? "light" : "dark";
        applyTheme(next);
        try { localStorage.setItem("placeholder-theme", next); } catch (e) {}
      });
    })();
  </script>
</body>
</html>"#);
    out
}

/// Jinja2's `escape`, which is what the page was rendered with.
///
/// The five characters and the exact entities matter: `&#39;` and `&#34;`
/// are what Jinja2 emits, and a page that differed from the one already on
/// the box would be a change nobody asked for.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            '"' => out.push_str("&#34;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C19, against the Python itself.
    ///
    /// `tests/golden/nginx/template_renders.json` is twenty renders captured
    /// from the *real* Jinja2 by `tests/fixtures/generate.py`, each with the
    /// context Python computed for it - the flood zone name, the challenge
    /// block, the resolved FPM socket, values no amount of reading the
    /// template would reveal. This drives these functions from those contexts
    /// and compares the bytes.
    ///
    /// It replaces `cargo xtask golden-nginx`, which did the same comparison
    /// with minijinja standing in the middle. There is no middle any more.
    ///
    /// **What these twenty do not cover**, and the branch fixtures do:
    /// `ipv6` is false in all of them and `http_flood_burst` is above zero in
    /// all of them, so the other side of each was never captured from Python.
    /// Those two branches are one line each and were carried across by
    /// generation rather than by hand, which is the most that can honestly be
    /// claimed for them.
    #[test]
    fn every_captured_python_render_matches() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/nginx/template_renders.json");
        let captured: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("captured renders"))
                .expect("the captures parse");
        assert_eq!(captured.len(), 20, "the capture file lost entries");

        let mut failures = Vec::new();
        for (i, entry) in captured.iter().enumerate() {
            let template = entry["template"].as_str().expect("template");
            let c = &entry["context"];
            let expected = entry["output"].as_str().expect("output");

            let names: Vec<String> = c["server_names"]
                .as_array()
                .expect("server_names")
                .iter()
                .map(|v| v.as_str().expect("a name").to_string())
                .collect();
            let v = Vars {
                ipv6: c["ipv6"].as_bool().expect("ipv6"),
                domain: c["domain"].as_str().expect("domain"),
                server_names: &names,
                root_path: c["root_path"].as_str().expect("root_path"),
                document_root_path: c["document_root_path"]
                    .as_str()
                    .expect("document_root_path"),
                php_fpm_socket: c["php_fpm_socket"].as_str().unwrap_or(""),
                custom_include_path: c["custom_include_path"]
                    .as_str()
                    .expect("custom_include_path"),
                waf_enabled: c["waf_enabled"].as_bool().expect("waf_enabled"),
                waf_rules_file: c["waf_rules_file"].as_str().unwrap_or(""),
                http_flood_enabled: c["http_flood_enabled"]
                    .as_bool()
                    .expect("http_flood_enabled"),
                http_flood_zone: c["http_flood_zone"].as_str().unwrap_or(""),
                http_flood_burst: c["http_flood_burst"].as_i64().unwrap_or(0),
                http_flood_connections: c["http_flood_connections"].as_i64().unwrap_or(0),
                http_flood_challenge_block: c["http_flood_challenge_block"].as_str().unwrap_or(""),
                rewrite_mode: c["rewrite_mode"].as_str().unwrap_or("none"),
                app_port: c["app_port"].as_i64().unwrap_or(0),
                proxy_timeout: c["proxy_timeout"].as_u64().unwrap_or(300) as u32,
            };

            let rendered = match template {
                "wordpress.conf.j2" => wordpress(&v),
                "php.conf.j2" => php(&v),
                "static.conf.j2" => r#static(&v),
                "proxy.conf.j2" => proxy(&v),
                other => panic!("unknown template {other}"),
            };
            if rendered != expected {
                let at = rendered
                    .lines()
                    .zip(expected.lines())
                    .position(|(a, b)| a != b);
                failures.push(format!("#{i} {template}: first differing line {at:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The thirty recorded branch fixtures, byte for byte.
    ///
    /// They cover what the twenty captured vhosts do not: those came off a
    /// running panel, so they carry the settings that panel had - IPv6 off,
    /// the WAF on, flood off almost everywhere - and the other side of each
    /// of those conditionals went unread. `static` had one fixture and four
    /// of them.
    ///
    /// The fixtures were written by this module and then checked, while the
    /// Jinja templates and minijinja were still in the tree, against what the
    /// templates themselves rendered. That check was the handover; this is
    /// what it handed over to.
    #[test]
    fn every_branch_fixture_still_renders() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/nginx/branches");
        let mut checked = 0;
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{dir:?}: {e}"))
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".conf"))
            .collect();
        entries.sort();

        for file in &entries {
            let name = file.trim_end_matches(".conf");
            let f: fn(&Vars<'_>) -> String = match name.split('.').next().expect("a label") {
                "wordpress" => wordpress,
                "php" => php,
                "static" => r#static,
                "proxy" => proxy,
                other => panic!("unknown label {other}"),
            };
            let recorded = std::fs::read_to_string(dir.join(file)).expect("fixture");
            let rendered = f(&vars_for(name));
            if rendered != recorded {
                let at = rendered
                    .lines()
                    .zip(recorded.lines())
                    .position(|(a, b)| a != b);
                panic!("{name}: first differing line {at:?}");
            }
            checked += 1;
        }
        // Exact, not a floor: a fixture directory that lost files would
        // otherwise pass while checking fewer branches than it names.
        assert_eq!(checked, 30, "found {entries:?}");
    }

    /// The `Vars` a recorded fixture's name stands for.
    fn vars_for<'a>(name: &'a str) -> Vars<'a> {
        static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        let names =
            NAMES.get_or_init(|| vec!["example.com".to_string(), "www.example.com".to_string()]);
        let parts: Vec<&str> = name.split('.').collect();
        let (ipv6, waf, flood, burst) = match parts[1] {
            "ipv6" => (true, false, false, 0_i64),
            "waf" => (false, true, false, 0),
            "flood-burst" => (false, false, true, 25),
            "flood-no-burst" => (false, false, true, 0),
            "all" => (true, true, true, 25),
            other => panic!("unknown shape {other}"),
        };
        Vars {
            ipv6,
            domain: "example.com",
            server_names: names,
            root_path: "/home/u1/example.com",
            document_root_path: "/home/u1/example.com/public_html",
            php_fpm_socket: "/run/php/php8.4-fpm.sock",
            custom_include_path: "/etc/nginx/snpanel/custom/example.com.conf",
            waf_enabled: waf,
            waf_rules_file: "/etc/nginx/modsec/sites/example.com.conf",
            http_flood_enabled: flood,
            http_flood_zone: "snpanel_flood_example_com",
            http_flood_burst: burst,
            http_flood_connections: 60,
            http_flood_challenge_block: "    # challenge\n    set $x 1;",
            rewrite_mode: if parts.len() > 2 { parts[2] } else { "none" },
            app_port: 8080,
            proxy_timeout: 300,
        }
    }

    /// The escape is Python Jinja2's, which is not minijinja's.
    ///
    /// Measured before minijinja was removed. It escapes three characters
    /// differently:
    ///
    /// | character | Jinja2 | minijinja |
    /// | --- | --- | --- |
    /// | `'` | `&#39;` | `&#x27;` |
    /// | `"` | `&#34;` | `&quot;` |
    /// | `/` | *unescaped* | `&#x2f;` |
    ///
    /// The placeholder pages sitting on a box were written by the Python, so
    /// Jinja2's table is the one this reproduces. Nothing on a box changes
    /// either way: `Domain` holds `[a-z0-9-.]`, so no value that reaches here
    /// can contain any of them - which is also why the difference went
    /// unnoticed for the whole of the port.
    #[test]
    fn the_escape_is_jinja2s() {
        for (input, expected) in [
            ("&", "&amp;"),
            ("<", "&lt;"),
            (">", "&gt;"),
            ("'", "&#39;"),
            ("\"", "&#34;"),
            ("/", "/"),
            ("a", "a"),
            ("example.com", "example.com"),
        ] {
            assert_eq!(escape_html(input), expected, "escaping {input:?}");
        }
    }

    /// The page carries the domain in both places the template did.
    #[test]
    fn the_placeholder_names_the_domain_twice() {
        let page = placeholder("example.com");
        assert_eq!(page.matches("example.com").count(), 2);
        assert!(page.contains("<title>example.com</title>"));
        assert!(page.contains(r#"<div class="host">example.com</div>"#));
    }
}
