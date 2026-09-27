//! phpMyAdmin, and the single sign-on that gets a customer into it.
//!
//! Source: `setup_phpmyadmin_sso`.
//!
//! The panel never hands a customer their database password to type. It mints
//! a one-use token, redirects the browser to an endpoint on the phpMyAdmin
//! host, and that endpoint asks the panel — **over loopback** — what the
//! token is worth. phpMyAdmin's `signon` auth type then takes the credentials
//! out of a PHP session rather than a login form.
//!
//! Two files, and both have to agree about the cookie: a `secure` cookie on a
//! panel served over HTTP is a sign-on that never arrives, and a cookie
//! without `secure` on one served over HTTPS is a credential that can be
//! stripped onto plain HTTP.

/// Where the two files go. Debian lowercases the directory and EPEL keeps
/// the project's own capitalisation, so both come from the platform table.
pub struct PhpMyAdminPaths<'a> {
    pub conf_dir: &'a str,
    pub root: &'a str,
}

impl PhpMyAdminPaths<'_> {
    pub fn config_file(&self) -> String {
        format!("{}/conf.d/snpanel-signon.php", self.conf_dir)
    }

    pub fn signon_file(&self) -> String {
        format!("{}/snpanel-signon.php", self.root)
    }
}

/// `0640`, root and the web group. It holds the blowfish secret.
pub const CONFIG_MODE: u32 = 0o640;
/// `0644`. It is served, so the web server has to read it — and it holds no
/// secret of its own.
pub const SIGNON_MODE: u32 = 0o644;

/// Where both files keep the sign-on session: `SessionSavePath` in the one,
/// `session_save_path()` in the other.
///
/// Debian's `php-common` ships it, and nothing on EL does. There the first
/// site's session directory brought it into being as a plain `0755` parent,
/// the web user could not create a session file in it, and every phpMyAdmin
/// sign-on on AlmaLinux answered "Cannot start signon session".
pub const SESSION_DIR: &str = "/var/lib/php/sessions";
/// `1733`, root - Debian's own: anyone may create a session file, nobody may
/// list the directory, and the sticky bit keeps each file its creator's. PHP
/// refuses to read a session file another uid made, so a file planted under a
/// guessed name is not a session.
pub const SESSION_DIR_MODE: u32 = 0o1733;

/// The phpMyAdmin configuration that turns on sign-on auth.
///
/// `AllowNoPassword` is `false` and stays that way: with `signon` auth an
/// empty password would let a token that resolved to nothing log in as
/// whatever user it named.
pub fn config_php(blowfish_secret: &str, host: &str, secure: bool) -> String {
    let scheme = if secure { "https" } else { "http" };
    let secure = if secure { "true" } else { "false" };
    format!(
        r#"<?php
$cfg['blowfish_secret'] = '{blowfish_secret}';
$i = 1;
$cfg['Servers'][$i]['auth_type'] = 'signon';
$cfg['Servers'][$i]['SignonSession'] = 'SNPanelPmaSignon';
$cfg['Servers'][$i]['SignonCookieParams'] = [
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => {secure},
    'httponly' => true,
    'samesite' => 'Lax',
];
$cfg['Servers'][$i]['SignonURL'] = '/phpmyadmin/snpanel-signon.php';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['only_db'] = '';
$cfg['SessionSavePath'] = '/var/lib/php/sessions';
$cfg['PmaAbsoluteUri'] = '{scheme}://{host}/phpmyadmin/';
"#
    )
}

/// The endpoint the panel redirects a browser to.
///
/// Three things in it are the security boundary rather than plumbing:
///
/// * the token pattern, `^[A-Za-z0-9_-]{{20,}}$`, which runs **before** the
///   token reaches a URL;
/// * `session_regenerate_id(true)` and the `$_SESSION = []` after it, so a
///   session an attacker had already fixed cannot be the one the credentials
///   land in;
/// * the API base, which is `127.0.0.1` — the endpoint asks the panel on
///   loopback, so a token is only ever redeemed by something already on the
///   machine.
///
/// `CURLOPT_SSL_VERIFYPEER => false` is deliberate and is not a weakening:
/// the request is to `127.0.0.1`, and the certificate there is the panel's
/// own — frequently self-signed, and issued for the panel's hostname rather
/// than for the loopback address it is being reached on.
pub fn signon_php(api_base: &str, cookie_secure: bool) -> String {
    let secure = if cookie_secure { "true" } else { "false" };
    format!(
        r#"<?php
declare(strict_types=1);

session_save_path('/var/lib/php/sessions');
ini_set('session.use_cookies', 'true');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => {secure},
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_name('SNPanelPmaSignon');
if (!session_start()) {{
    http_response_code(500);
    exit('Cannot start signon session');
}}

$token = $_GET['snpanel_sso'] ?? '';
if (!preg_match('/^[A-Za-z0-9_-]{{20,}}$/', $token)) {{
    http_response_code(403);
    exit('Invalid token');
}}

$apiUrl = '{api_base}' . rawurlencode($token);
$ch = curl_init($apiUrl);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_HTTPHEADER => ['Accept: application/json'],
]);
$response = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($status !== 200 || !$response) {{
    http_response_code(403);
    exit('Expired token');
}}

$data = json_decode($response, true);
if (!is_array($data) || empty($data['db_user']) || empty($data['db_password'])) {{
    http_response_code(403);
    exit('Invalid signon data');
}}

session_regenerate_id(true);
$_SESSION = [];
$_SESSION['PMA_single_signon_user'] = $data['db_user'];
$_SESSION['PMA_single_signon_password'] = $data['db_password'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
$_SESSION['PMA_single_signon_port'] = '';
$_SESSION['PMA_single_signon_cfgupdate'] = [
    'only_db' => $data['db_name'] ?? '',
];
$_SESSION['PMA_single_signon_HMAC_secret'] = bin2hex(random_bytes(16));
session_write_close();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Location: /phpmyadmin/index.php?server=1');
exit;
"#
    )
}

/// EPEL's phpMyAdmin, and the three differences from Debian's package that
/// are load-bearing rather than cosmetic.
///
/// Source: `prepare_phpmyadmin_platform`, whose whole body is EL-only.
pub mod el {
    /// nginx cannot read EPEL's `/etc/phpMyAdmin` — it is `root:apache`,
    /// mode `0750` — and the panel would answer a blank 500 with nothing in
    /// phpMyAdmin's own log to say why. The directory is regrouped to the
    /// web group and the mode kept.
    pub const CONF_DIR_MODE: u32 = 0o750;

    /// An Apache drop-in that nginx also reads.
    ///
    /// It contains `fastcgi_pass php-fpm;`, naming an upstream nothing
    /// defines, so `nginx -t` fails outright — and if it did parse it would
    /// publish phpMyAdmin on every vhost, outside the panel's control.
    /// Removed, not edited.
    pub const APACHE_DROPIN: &str = "/etc/nginx/default.d/phpMyAdmin.conf";

    /// The marker the phase greps for before appending.
    pub const INCLUDE_MARKER: &str = "SNPanel conf.d include";

    /// Appended to `config.inc.php` so EPEL's package reads a `conf.d`.
    ///
    /// Debian's phpMyAdmin reads one, and the panel delivers its sign-on
    /// configuration as a file there; EPEL's has no such directory. It goes
    /// **last** in the file, so the panel's settings override the defaults
    /// above it.
    ///
    /// The `${PHPMYADMIN_CONF_DIR}` in the first comment line is literal:
    /// the shell writes this out of a quoted heredoc, so the name is never
    /// expanded. Reproduced as-is rather than tidied — the point of this
    /// side is to write the same bytes, and a comment that differs is a
    /// diff an operator has to stop and think about.
    pub const CONF_D_INCLUDE: &str = r"
// SNPanel conf.d include. Debian's phpMyAdmin reads ${PHPMYADMIN_CONF_DIR}/conf.d and
// the panel delivers its single-sign-on configuration as a file there; EPEL's
// package has no such directory, so this reproduces it. Last in the file, so
// the panel's settings override the defaults above.
foreach (glob(__DIR__ . '/conf.d/*.php') ?: [] as $snpanel_conf) {
    include $snpanel_conf;
}
";

    /// Whether `config.inc.php` already carries the include.
    ///
    /// Re-running the installer after a failure is a normal thing to do, and
    /// a second copy of the block would include every `conf.d` file twice —
    /// which for the sign-on configuration means the `$i` counter advances
    /// and phpMyAdmin offers a second, identical server.
    pub fn already_included(config: &str) -> bool {
        config.contains(INCLUDE_MARKER)
    }

    /// `config.inc.php` after the phase has run against `current`.
    pub fn with_include(current: &str) -> String {
        if already_included(current) {
            return current.to_string();
        }
        format!("{current}{CONF_D_INCLUDE}")
    }
}

/// Where the endpoint asks the panel what a token is worth.
///
/// Always `127.0.0.1`: the token is redeemed from the machine itself, so a
/// token leaked to somebody outside is a token they cannot spend.
pub fn api_base(secure: bool, panel_port: u16) -> String {
    let scheme = if secure { "https" } else { "http" };
    format!("{scheme}://127.0.0.1:{panel_port}/api/databases/phpmyadmin-sso/")
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

    /// The stub the fixture generator put in place of `openssl rand -hex 32`,
    /// so a live secret never reaches the repository.
    const SECRET: &str = "FIXTURE_SECRET_KEY_NOT_A_REAL_KEY";

    #[test]
    fn the_config_is_what_the_shell_writes() {
        assert_eq!(
            config_php(SECRET, "fixtures.invalid", false),
            fixture("pma-config.plain.php")
        );
        assert_eq!(
            config_php(SECRET, "fixtures.invalid", true),
            fixture("pma-config.tls.php")
        );
    }

    #[test]
    fn the_signon_endpoint_is_what_the_shell_writes() {
        assert_eq!(
            signon_php(&api_base(false, 2222), false),
            fixture("pma-signon.plain.php")
        );
        assert_eq!(
            signon_php(&api_base(true, 2222), true),
            fixture("pma-signon.tls.php")
        );
    }

    /// A `secure` cookie on a panel served over HTTP is a sign-on that never
    /// arrives; one without `secure` on HTTPS is a credential that can be
    /// stripped onto plain HTTP. The two files have to agree, and both
    /// follow the same flag.
    #[test]
    fn both_files_agree_about_the_cookie() {
        for secure in [true, false] {
            let flag = if secure {
                "'secure' => true,"
            } else {
                "'secure' => false,"
            };
            assert!(config_php(SECRET, "h", secure).contains(flag));
            assert!(signon_php(&api_base(secure, 2222), secure).contains(flag));
        }
    }

    /// The token reaches a URL, so its shape is checked first — and the
    /// pattern is anchored at both ends, which is what stops a token with a
    /// slash or a `..` in it from addressing something else.
    #[test]
    fn the_token_pattern_is_anchored_and_allows_no_path_characters() {
        let php = signon_php(&api_base(false, 2222), false);
        assert!(php.contains(r"preg_match('/^[A-Za-z0-9_-]{20,}$/', $token)"));
        // And it is checked before the token is used for anything.
        let check = php.find("preg_match").expect("the check");
        let use_ = php.find("rawurlencode($token)").expect("the use");
        assert!(check < use_, "the token is used before it is checked");
    }

    /// A session an attacker had already fixed must not be the one the
    /// credentials land in.
    #[test]
    fn the_session_is_regenerated_and_emptied_before_the_credentials_go_in() {
        let php = signon_php(&api_base(false, 2222), false);
        let regenerate = php
            .find("session_regenerate_id(true);")
            .expect("regenerate");
        let empty = php.find("$_SESSION = [];").expect("empty");
        let credentials = php
            .find("$_SESSION['PMA_single_signon_user']")
            .expect("the credentials");
        assert!(
            regenerate < empty,
            "the session is emptied before it is regenerated"
        );
        assert!(
            empty < credentials,
            "the credentials go in before the reset"
        );
    }

    /// The token is redeemed from the machine itself, so one leaked to
    /// somebody outside is one they cannot spend.
    #[test]
    fn a_token_is_only_ever_redeemed_over_loopback() {
        for secure in [true, false] {
            let base = api_base(secure, 2222);
            assert!(base.contains("//127.0.0.1:2222/"), "{base}");
            let php = signon_php(&base, secure);
            assert!(php.contains("curl_init($apiUrl)"));
            // Nothing else in the file names a host to reach.
            assert_eq!(php.matches("curl_init").count(), 1);
        }
    }

    /// With `signon` auth an empty password would let a token that resolved
    /// to nothing log in as whatever user it named.
    #[test]
    fn an_empty_password_is_never_accepted() {
        let config = config_php(SECRET, "h", true);
        assert!(config.contains("['AllowNoPassword'] = false;"));
        let php = signon_php(&api_base(true, 2222), true);
        assert!(php.contains("empty($data['db_password'])"));
    }

    #[test]
    fn both_files_keep_the_session_where_the_directory_is_made() {
        let config = config_php("s", "h", true);
        let signon = signon_php("https://127.0.0.1:2222", true);
        assert!(config.contains(&format!("$cfg['SessionSavePath'] = '{SESSION_DIR}';")));
        assert!(signon.contains(&format!("session_save_path('{SESSION_DIR}');")));
        // What `php-common` gives it on Debian and Ubuntu.
        assert_eq!(SESSION_DIR_MODE, 0o1733);
    }

    #[test]
    fn the_config_holding_the_secret_is_not_world_readable() {
        assert_eq!(CONFIG_MODE & 0o007, 0);
        // The endpoint is served, so the web server reads it — and it holds
        // no secret of its own.
        assert_eq!(SIGNON_MODE, 0o644);
    }

    #[test]
    fn the_el_include_is_what_the_shell_appends() {
        let stock = concat!(
            "<?php\n",
            "/* A stock EPEL config.inc.php, cut to the shape that matters here. */\n",
            "$cfg['blowfish_secret'] = '';\n",
            "$i = 0;\n",
            "$i++;\n",
            "$cfg['Servers'][$i]['auth_type'] = 'cookie';\n",
        );
        let first = el::with_include(stock);
        assert_eq!(first, fixture("pma-config.inc.el.first-run.php"));
        // The whole point of it: the sign-on file the panel writes lives in
        // that directory, and without this line EPEL's package never reads
        // it.
        assert!(first.contains("glob(__DIR__ . '/conf.d/*.php')"));
        // Last in the file, so the panel's settings win over the defaults.
        assert!(first.starts_with(stock));
    }

    /// Re-running the installer after a failure is a normal thing to do. A
    /// second copy of the block would include every `conf.d` file twice,
    /// which for the sign-on configuration advances `$i` and leaves
    /// phpMyAdmin offering a second, identical server.
    #[test]
    fn appending_the_el_include_twice_changes_nothing() {
        let first = fixture("pma-config.inc.el.first-run.php");
        assert!(el::already_included(&first));
        assert_eq!(el::with_include(&first), first);
        assert_eq!(first, fixture("pma-config.inc.el.second-run.php"));
    }

    /// `fastcgi_pass php-fpm;` names an upstream nothing defines, so
    /// `nginx -t` fails outright — and a version of it that did parse would
    /// publish phpMyAdmin on every vhost, outside the panel's control.
    #[test]
    fn the_apache_drop_in_is_removed_rather_than_edited() {
        assert_eq!(
            fixture("pma-default-d.state").trim(),
            "removed",
            "the shell left the Apache drop-in in place"
        );
        assert!(el::APACHE_DROPIN.starts_with("/etc/nginx/default.d/"));
    }

    /// nginx has to be able to read the directory, and nothing else should.
    #[test]
    fn the_el_conf_dir_is_readable_by_the_web_group_and_no_one_else() {
        assert_eq!(el::CONF_DIR_MODE & 0o007, 0);
        assert_eq!(el::CONF_DIR_MODE & 0o050, 0o050);
    }

    #[test]
    fn the_paths_follow_the_platforms_capitalisation() {
        let debian = PhpMyAdminPaths {
            conf_dir: "/etc/phpmyadmin",
            root: "/usr/share/phpmyadmin",
        };
        assert_eq!(
            debian.config_file(),
            "/etc/phpmyadmin/conf.d/snpanel-signon.php"
        );
        assert_eq!(
            debian.signon_file(),
            "/usr/share/phpmyadmin/snpanel-signon.php"
        );

        let el = PhpMyAdminPaths {
            conf_dir: "/etc/phpMyAdmin",
            root: "/usr/share/phpMyAdmin",
        };
        assert_eq!(el.signon_file(), "/usr/share/phpMyAdmin/snpanel-signon.php");
    }
}
