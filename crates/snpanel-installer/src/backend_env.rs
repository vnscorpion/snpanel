//! The four text files the middle of an install produces.
//!
//! The panel's `.env`, the SFTP block in `sshd_config`, the tmpfiles rule for
//! `/run/php`, and the rewrite of the distribution's PHP-FPM pool. Source:
//! `setup_backend`, `setup_sftp_access` and `configure_php_fpm_pool`.
//!
//! Two of these are **transforms** rather than renders — they take a file
//! that is already on the machine and change part of it — and those are the
//! ones worth having a test for: an sshd block that appends instead of
//! replacing grows a copy per update until sshd refuses to start, and a pool
//! rewrite that misses a line leaves PHP listening where no vhost looks.

/// Every value the panel's `.env` is built from.
///
/// Contract C18: **every name here stays exactly as it is.** The file is
/// written by the installer, rewritten by every update, and read by both
/// implementations while they run side by side — a rename strands existing
/// boxes.
pub struct BackendEnv<'a> {
    pub app_dir: &'a str,
    /// Hex, thirty-two bytes. What makes a session minted by either side
    /// valid on the other.
    pub secret_key: &'a str,
    pub panel_url: &'a str,
    pub panel_domain: &'a str,
    pub panel_port: u16,
    pub backup_root: &'a str,
    pub ssl_email: &'a str,
    /// Which PHP version the panel acts on when a site does not name one.
    /// Written here because this is the only place that knows what was
    /// actually installed.
    pub default_php_version: &'a str,
}

/// `0640`, because the file holds `SECRET_KEY`.
pub const ENV_MODE: u32 = 0o640;

pub fn backend_env(env: &BackendEnv<'_>) -> String {
    let BackendEnv {
        app_dir,
        secret_key,
        panel_url,
        panel_domain,
        panel_port,
        backup_root,
        ssl_email,
        default_php_version,
    } = env;
    format!(
        "APP_ENV=production
SECRET_KEY={secret_key}
COMMAND_DRY_RUN=false
DATABASE_URL=sqlite:///{app_dir}/backend/snpanel.db
REDIS_URL=redis://localhost:6379/0
RATE_LIMIT_BACKEND=redis
ALLOWED_ORIGINS={panel_url}
BACKUP_ROOT={backup_root}
SSL_EMAIL={ssl_email}
PANEL_URL={panel_url}
PANEL_DOMAIN={panel_domain}
PANEL_PORT={panel_port}
PANEL_SSL_CERT=
PANEL_SSL_KEY=
FRONTEND_DIST={app_dir}/frontend/dist
# Which PHP version the panel acts on when a site does not name one. Written
# here because this is the only place that knows what was installed: Ubuntu
# 24.04 gets 8.3 and 8.4, 26.04 carries 8.5 alone, and EL gets 8.3 and 8.4 from
# Remi. Without it the panel fell back to a constant and asked the helper about
# a version the machine did not have.
DEFAULT_PHP_VERSION={default_php_version}
"
    )
}

// --- the SFTP block --------------------------------------------------------

pub const SFTP_BEGIN: &str = "# BEGIN SNPANEL SFTP USERS";
pub const SFTP_END: &str = "# END SNPANEL SFTP USERS";

/// The block itself.
///
/// `ChrootDirectory /home/%u` is the guardrail, and it is why the home has to
/// be root-owned: sshd refuses to chroot into a directory the user can write.
/// `ForceCommand internal-sftp` means there is no shell at the other end of a
/// successful login.
pub fn sftp_block() -> String {
    format!(
        "{SFTP_BEGIN}
# Allow SNPanel Linux users to log in with SFTP using their panel password.
# SSH shells are intentionally disabled; /home/%u is a root-owned chroot.
Match Group snpanel-sftp
    PasswordAuthentication yes
    ChrootDirectory /home/%u
    ForceCommand internal-sftp -d /
    PermitTTY no
    X11Forwarding no
    AllowTcpForwarding no
    PermitTunnel no
{SFTP_END}
"
    )
}

/// The existing `sshd_config` with our block removed and then re-added.
///
/// Source: the `sed -i '/BEGIN/,/END/d'` followed by the append. **Removing
/// first is the whole point**: this runs on every install and every update,
/// and appending without removing would leave sshd with a second `Match
/// Group` block — which it reads as a duplicate and refuses to start on.
pub fn sshd_config_with_sftp(existing: &str) -> String {
    let mut out = String::with_capacity(existing.len() + 512);
    let mut inside = false;
    for line in existing.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        if bare == SFTP_BEGIN {
            inside = true;
            continue;
        }
        if bare == SFTP_END {
            inside = false;
            continue;
        }
        if !inside {
            out.push_str(line);
        }
    }
    // `cat >>` appends, and a file whose last line has no newline would
    // otherwise get the marker glued to it.
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&sftp_block());
    out
}

// --- PHP-FPM ---------------------------------------------------------------

pub const TMPFILES_PATH: &str = "/etc/tmpfiles.d/snpanel-php.conf";

/// `/run` is a tmpfs, so the socket directory has to be recreated on every
/// boot. Without this the first PHP request after a reboot reaches a pool
/// that could not bind.
pub fn php_run_tmpfiles() -> String {
    "d /run/php 0755 root root -\n".to_string()
}

/// Move the distribution's default pool onto the panel's socket and user.
///
/// Remi's default pool runs as `apache` and listens on a Remi-specific
/// socket path; Debian's runs as `www-data` on a Debian one. The panel's
/// generated vhosts point at `/run/php/php<version>-fpm.sock` and its
/// validation insists on that shape, so the pool is moved to match rather
/// than the other way round.
///
/// Seven settings, and each is rewritten **whether or not it is commented
/// out** — `;listen.owner` in a stock file has to become a live
/// `listen.owner`, not stay a comment. That is the `^;?[[:space:]]*` in each
/// of the shell's expressions.
pub fn php_fpm_pool(existing: &str, web_user: &str, web_group: &str, socket: &str) -> String {
    let replacements: [(&str, String); 7] = [
        ("user", format!("user = {web_user}")),
        ("group", format!("group = {web_group}")),
        ("listen", format!("listen = {socket}")),
        ("listen.owner", format!("listen.owner = {web_user}")),
        ("listen.group", format!("listen.group = {web_group}")),
        ("listen.mode", "listen.mode = 0660".to_string()),
        ("listen.acl_users", format!("listen.acl_users = {web_user}")),
    ];
    let mut out = String::with_capacity(existing.len() + 64);
    for line in existing.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        match replacements.iter().find(|(key, _)| setting_is(bare, key)) {
            Some((_, value)) => {
                out.push_str(value);
                if line.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => out.push_str(line),
        }
    }
    out
}

/// `^;?[[:space:]]*<key>[[:space:]]*=` — the setting, live or commented out.
///
/// The key has to match **whole**: `listen` must not claim `listen.owner`,
/// or six of the seven rewrites would be overwritten by the first.
fn setting_is(line: &str, key: &str) -> bool {
    let rest = line.strip_prefix(';').unwrap_or(line);
    let rest = rest.trim_start_matches([' ', '\t']);
    let Some(rest) = rest.strip_prefix(key) else {
        return false;
    };
    rest.trim_start_matches([' ', '\t']).starts_with('=')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/installer")
            .join(format!("{name}.expected"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the fixture {}: {e}", path.display()))
    }

    /// The values the fixture was recorded with. `openssl` was stubbed so
    /// the committed file shows where the secret goes without carrying one.
    fn recorded_env() -> BackendEnv<'static> {
        BackendEnv {
            app_dir: "/root/cfgfix/app",
            secret_key: "FIXTURE_SECRET_KEY_NOT_A_REAL_KEY",
            panel_url: "https://fixtures.invalid:2222",
            panel_domain: "fixtures.invalid",
            panel_port: 2222,
            backup_root: "/var/backups/snpanel",
            ssl_email: "admin@fixtures.invalid",
            default_php_version: "8.4",
        }
    }

    #[test]
    fn the_env_file_is_what_the_shell_writes() {
        assert_eq!(backend_env(&recorded_env()), fixture("backend.env"));
    }

    /// Contract C18. The names are read by both implementations while they
    /// run side by side, and by an installer that rewrites this file on
    /// every update — a rename strands every existing box.
    #[test]
    fn every_name_the_env_file_carries_is_the_one_both_sides_read() {
        let rendered = backend_env(&recorded_env());
        let names: Vec<&str> = rendered
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split('=').next())
            .collect();
        assert_eq!(
            names,
            [
                "APP_ENV",
                "SECRET_KEY",
                "COMMAND_DRY_RUN",
                "DATABASE_URL",
                "REDIS_URL",
                "RATE_LIMIT_BACKEND",
                "ALLOWED_ORIGINS",
                "BACKUP_ROOT",
                "SSL_EMAIL",
                "PANEL_URL",
                "PANEL_DOMAIN",
                "PANEL_PORT",
                "PANEL_SSL_CERT",
                "PANEL_SSL_KEY",
                "FRONTEND_DIST",
                "DEFAULT_PHP_VERSION",
            ]
        );
    }

    /// `sqlite:///` plus an absolute path is **four** slashes in the URL, and
    /// three would point at a relative file the service cannot reach.
    #[test]
    fn the_database_url_keeps_its_fourth_slash() {
        let rendered = backend_env(&recorded_env());
        assert!(rendered.contains("DATABASE_URL=sqlite:////root/cfgfix/app/backend/snpanel.db"));
    }

    #[test]
    fn the_sshd_block_is_what_the_shell_appends() {
        let before = "# A stock sshd_config, cut down to the lines that matter here.\n\
             Port 22\n\
             PermitRootLogin prohibit-password\n\
             Subsystem sftp /usr/lib/openssh/sftp-server\n";
        assert_eq!(
            sshd_config_with_sftp(before),
            fixture("sshd_config.first-run")
        );
    }

    /// The phase runs on every install **and every update**. Appending
    /// without removing would leave sshd with a second `Match Group` block,
    /// which it reads as a duplicate and refuses to start on — so the second
    /// run has to produce the same file as the first.
    #[test]
    fn running_it_twice_does_not_grow_a_second_block() {
        let before = "Port 22\n";
        let once = sshd_config_with_sftp(before);
        let twice = sshd_config_with_sftp(&once);
        assert_eq!(once, twice);
        assert_eq!(twice.matches(SFTP_BEGIN).count(), 1);
        assert_eq!(
            fixture("sshd_config.first-run"),
            fixture("sshd_config.second-run"),
            "the shell is idempotent here and the fixture proves it"
        );
    }

    /// A file that does not end in a newline would otherwise get the marker
    /// glued onto its last line, and sshd would read neither.
    #[test]
    fn a_file_with_no_trailing_newline_still_gets_a_readable_block() {
        let rendered = sshd_config_with_sftp("Port 22");
        assert!(rendered.contains("Port 22\n# BEGIN"));
    }

    #[test]
    fn the_pool_is_moved_onto_the_panels_socket() {
        let before = "[www]\n\
             user = apache\n\
             group = apache\n\
             listen = /run/php-fpm/www.sock\n\
             ;listen.owner = nobody\n\
             ;listen.group = nobody\n\
             ;listen.mode = 0660\n\
             listen.acl_users = apache,nginx\n\
             pm = dynamic\n\
             pm.max_children = 50\n\
             php_admin_value[error_log] = /var/log/php-fpm/www-error.log\n";
        assert_eq!(
            php_fpm_pool(before, "www-data", "www-data", "/run/php/php8.4-fpm.sock"),
            fixture("php-fpm-www.conf")
        );
    }

    /// The key has to match whole. `listen` claiming `listen.owner` would
    /// collapse six settings into one and leave the pool unreachable.
    #[test]
    fn a_setting_name_does_not_claim_the_ones_it_prefixes() {
        assert!(setting_is("listen = /x", "listen"));
        assert!(!setting_is("listen.owner = nobody", "listen"));
        assert!(setting_is("listen.owner = nobody", "listen.owner"));
        // Commented out, with any amount of space, is still the setting.
        assert!(setting_is(";listen.mode = 0660", "listen.mode"));
        assert!(setting_is(";  listen.mode   = 0660", "listen.mode"));
        // And something that merely starts the same way is not.
        assert!(!setting_is("username = x", "user"));
        assert!(!setting_is("listen_backlog = 511", "listen"));
    }

    #[test]
    fn the_tmpfiles_rule_recreates_the_socket_directory() {
        assert_eq!(php_run_tmpfiles(), fixture("snpanel-php.conf"));
    }

    /// The `.env` is `0640`: it holds `SECRET_KEY`, which is what signs
    /// every session on the machine.
    #[test]
    fn the_env_file_is_not_world_readable() {
        assert_eq!(ENV_MODE & 0o007, 0);
    }
}
