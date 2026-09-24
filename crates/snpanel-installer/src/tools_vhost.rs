//! The panel's own nginx server block, and the distribution default it has
//! to displace.
//!
//! Source: `write_tools_nginx_config` and `neutralise_distro_default_site`.
//!
//! This is the `default_server` — the block that answers a request for a name
//! nginx has no vhost for. It carries three things: the ACME challenge
//! directory the panel's own certificates are issued through, phpMyAdmin, and
//! nothing else. **Two `default_server` blocks make nginx refuse to start**,
//! which is what the second function here is for.

/// Where the panel's server block lives. The `00-` prefix puts it ahead of
/// every customer vhost, as with the other shared files.
pub const TOOLS_CONF_PATH: &str = "/etc/nginx/conf.d/00-snpanel-tools.conf";

/// What the panel's block is built from.
pub struct ToolsVhost<'a> {
    /// Where the distribution put phpMyAdmin. Debian lowercases it,
    /// EPEL keeps the project's own capitalisation — which is why this comes
    /// from the platform table rather than being a constant.
    pub phpmyadmin_root: &'a str,
    /// The PHP the panel's own tools run under.
    pub php_default: &'a str,
    /// The panel's certificate, when it has one. Both have to be set **and
    /// present on disk** before the block listens on 443: a `ssl_certificate`
    /// pointing at a file that is not there stops nginx from starting at all.
    pub ssl: Option<ToolsTls<'a>>,
}

pub struct ToolsTls<'a> {
    pub cert_path: &'a str,
    pub key_path: &'a str,
}

pub fn tools_vhost(config: &ToolsVhost<'_>) -> String {
    let ssl_block = match &config.ssl {
        Some(tls) => format!(
            "\n    listen 443 ssl http2 default_server;\n    \
             ssl_certificate {};\n    ssl_certificate_key {};",
            tls.cert_path, tls.key_path
        ),
        None => String::new(),
    };
    let root = config.phpmyadmin_root;
    let php = config.php_default;
    format!(
        r#"server {{
    listen 80 default_server;{ssl_block}
    server_name _;
    client_max_body_size 1100M;

    # Panel certificates are issued through this, so the panel no longer has to
    # stop nginx to prove it owns its own hostname.
    location ^~ /.well-known/acme-challenge/ {{
        root /var/www/snpanel-acme;
        default_type text/plain;
        try_files $uri =404;
        access_log off;
        auth_basic off;
    }}

    location = /phpmyadmin {{
        return 301 /phpmyadmin/;
    }}

    location /phpmyadmin/ {{
        alias {root}/;
        index index.php;
        try_files $uri $uri/ =404;
    }}

    location ~ ^/phpmyadmin/(.+\.php)$ {{
        alias {root}/$1;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME {root}/$1;
        fastcgi_param SCRIPT_NAME /phpmyadmin/$1;
        # Twig raises its deprecations as E_USER_DEPRECATED, which php.ini's
        # E_ALL & ~E_DEPRECATED does not exclude, so Debian's pairing of
        # phpMyAdmin 5.2 with Twig 3.21 shows the administrator a wall of
        # notices about a library they cannot change. Silenced here and only
        # here: a customer's own site may well want its deprecations.
        fastcgi_param PHP_VALUE "error_reporting=E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED";
        fastcgi_pass unix:/run/php/php{php}-fpm.sock;
        fastcgi_read_timeout 300;
    }}
}}
"#
    )
}

/// The marker that says this file has already been through here.
pub const NEUTRALISED_MARKER: &str = "SNPanel: distribution default server disabled";

/// Comment out the first `server { ... }` block in an EL `nginx.conf`.
///
/// RHEL ships its default site inside `nginx.conf` itself rather than in a
/// file that can simply be deleted, and two `default_server` blocks make
/// nginx refuse to start. Debian puts its in `sites-enabled/default`, which
/// the phase removes instead — so this runs on the RHEL family only.
///
/// Brace-counted rather than matched to the next `}`: the block contains
/// nested `location` blocks, and stopping at the first closing brace would
/// leave half a server block commented and the rest live.
pub fn neutralise_default_site(existing: &str) -> String {
    let mut out = String::with_capacity(existing.len() + 256);
    let mut state = 0;
    let mut depth = 0i64;
    for line in existing.split('\n') {
        match state {
            0 if is_server_open(line) => {
                out.push_str(
                    "    # SNPanel: distribution default server disabled. The panel serves\n\
                     \x20   # the default vhost from conf.d/00-snpanel-tools.conf, and two\n\
                     \x20   # default_server blocks make nginx refuse to start.\n",
                );
                state = 1;
            }
            _ => {}
        }
        if state == 1 {
            depth += count(line, '{') - count(line, '}');
            out.push('#');
            out.push_str(line);
            out.push('\n');
            if depth <= 0 {
                state = 2;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    // `split` on a trailing newline leaves an empty last piece, which the
    // loop turned back into a newline. awk's output has one fewer.
    if out.ends_with("\n\n") && existing.ends_with('\n') {
        out.pop();
    }
    out
}

/// `/^[[:space:]]*server[[:space:]]*\{/`.
fn is_server_open(line: &str) -> bool {
    let rest = line.trim_start_matches([' ', '\t']);
    let Some(rest) = rest.strip_prefix("server") else {
        return false;
    };
    rest.trim_start_matches([' ', '\t']).starts_with('{')
}

fn count(line: &str, ch: char) -> i64 {
    line.chars().filter(|c| *c == ch).count() as i64
}

/// Has this file already been through [`neutralise_default_site`]?
///
/// The phase checks before acting, so an update does not comment out a second
/// block — the one it commented out last time is still there, and its first
/// live `server {` would now be something else entirely.
pub fn already_neutralised(existing: &str) -> bool {
    existing.contains(NEUTRALISED_MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/installer")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the fixture {}: {e}", path.display()))
    }

    fn debian_tools(ssl: Option<ToolsTls<'static>>) -> ToolsVhost<'static> {
        ToolsVhost {
            phpmyadmin_root: "/usr/share/phpmyadmin",
            php_default: "8.4",
            ssl,
        }
    }

    #[test]
    fn the_plain_block_is_what_the_shell_writes() {
        assert_eq!(
            tools_vhost(&debian_tools(None)),
            fixture("00-snpanel-tools.plain.conf.expected")
        );
    }

    #[test]
    fn the_block_with_a_certificate_is_what_the_shell_writes() {
        let tls = ToolsTls {
            cert_path: "/root/toolsfix/tls/panel.crt",
            key_path: "/root/toolsfix/tls/panel.key",
        };
        assert_eq!(
            tools_vhost(&debian_tools(Some(tls))),
            fixture("00-snpanel-tools.tls.conf.expected")
        );
    }

    /// The two differ by exactly the three TLS lines, and nothing else. A
    /// block that gained or lost anything else between the two states would
    /// be a panel that behaves differently once it has a certificate.
    #[test]
    fn a_certificate_adds_three_lines_and_changes_nothing_else() {
        let plain = tools_vhost(&debian_tools(None));
        let with_tls = tools_vhost(&debian_tools(Some(ToolsTls {
            cert_path: "/etc/ssl/panel.crt",
            key_path: "/etc/ssl/panel.key",
        })));
        let added: Vec<&str> = with_tls
            .lines()
            .filter(|line| !plain.lines().any(|other| other == *line))
            .collect();
        assert_eq!(
            added,
            [
                "    listen 443 ssl http2 default_server;",
                "    ssl_certificate /etc/ssl/panel.crt;",
                "    ssl_certificate_key /etc/ssl/panel.key;",
            ]
        );
    }

    /// phpMyAdmin's path comes from the platform table: Debian lowercases the
    /// directory and EPEL keeps the project's own capitalisation, and a block
    /// pointing at the wrong one serves a 404 where the tool should be.
    /// **Everything that writes this file silences Twig's deprecations.**
    ///
    /// Four things rewrite `00-snpanel-tools.conf`: `install.sh`,
    /// `update.sh`, `snpanelctl`'s `refresh_tools_nginx` and the helper's
    /// `panel` op. Whichever ran last decides, and two of them were missing
    /// the line — so pointing the panel at a new domain, which runs
    /// `set-panel-url` and `install-panel-ssl`, put a wall of notices back
    /// in front of the administrator.
    ///
    /// The tests above compare this module against a recorded fixture,
    /// which cannot see that. This reads the writers.
    ///
    /// Twig raises its deprecations as `E_USER_DEPRECATED`, which php.ini's
    /// `E_ALL & ~E_DEPRECATED` does not exclude. It is scoped to phpMyAdmin
    /// rather than set globally on purpose: a customer's own site may well
    /// want its deprecations.
    #[test]
    fn every_writer_of_the_tools_vhost_silences_twig() {
        const NEEDLE: &str = "~E_USER_DEPRECATED";
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0;
        for name in [
            "installer/install.sh",
            "installer/update.sh",
            "installer/files/snpanelctl",
            "installer/files/snpanel-helper.sh",
            "crates/snpanel-helper/src/ops/panel.rs",
        ] {
            let Ok(text) = std::fs::read_to_string(root.join(name)) else {
                eprintln!("skipped: {name} is not there");
                continue;
            };
            // Only the files that actually write the block have to carry it.
            if !text.contains("^/phpmyadmin/(.+") {
                continue;
            }
            assert!(
                text.contains(NEEDLE),
                "{name} writes the phpMyAdmin location without {NEEDLE}, so running \
                 it puts Twig's deprecations back in front of the administrator"
            );
            checked += 1;
        }
        assert!(checked >= 4, "only {checked} writers were checked");
        assert!(
            tools_vhost(&debian_tools(None)).contains(NEEDLE),
            "and this module has to agree with them"
        );
    }

    #[test]
    fn the_phpmyadmin_path_is_the_platforms() {
        let el = tools_vhost(&ToolsVhost {
            phpmyadmin_root: "/usr/share/phpMyAdmin",
            php_default: "8.4",
            ssl: None,
        });
        assert!(el.contains("alias /usr/share/phpMyAdmin/;"));
        assert!(!el.contains("/usr/share/phpmyadmin"));
    }

    /// Brace-counted, because the block contains nested `location` blocks:
    /// stopping at the first `}` would leave half a server block commented
    /// and the rest live, which is a config nginx cannot parse.
    #[test]
    fn the_el_default_site_is_commented_out_whole() {
        let stock = fixture("nginx.conf.el-stock.input");
        assert_eq!(
            neutralise_default_site(&stock),
            fixture("nginx.conf.el-neutralised.expected")
        );
    }

    #[test]
    fn what_is_outside_the_block_is_left_alone() {
        let stock = fixture("nginx.conf.el-stock.input");
        let done = neutralise_default_site(&stock);
        assert!(done.contains("worker_processes auto;"));
        assert!(done.contains("    include /etc/nginx/conf.d/*.conf;"));
        // The nested `location` is inside the block and therefore commented.
        assert!(done.contains("#        location = /404.html {"));
        // And the `http {` that opened before it is not.
        assert!(done.contains("\nhttp {"));
    }

    /// The phase asks before acting. Without the marker an update would
    /// comment out whatever the *next* live `server {` happened to be — by
    /// then, quite possibly a customer's.
    #[test]
    fn a_file_that_has_been_through_once_is_recognised() {
        let stock = fixture("nginx.conf.el-stock.input");
        assert!(!already_neutralised(&stock));
        assert!(already_neutralised(&neutralise_default_site(&stock)));
    }

    #[test]
    fn only_a_server_block_opens_the_rewrite() {
        assert!(is_server_open("server {"));
        assert!(is_server_open("    server{"));
        assert!(is_server_open("\tserver   {"));
        // A name that merely starts the same way is not one.
        assert!(!is_server_open("server_name _;"));
        assert!(!is_server_open("    server_tokens off;"));
        assert!(!is_server_open("upstream server {"));
    }
}
