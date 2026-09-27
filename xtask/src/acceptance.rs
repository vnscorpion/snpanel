//! `cargo xtask acceptance` - did this installation come out right?
//!
//! Source: `installer/files/platform-check.sh`, which was 12 KB of bash that
//! nothing installed and no workflow ran. It is run by hand, as root, on a
//! server that has just been installed.
//!
//! It checks the things that differ between the distributions, and the things
//! that have to be identical on both, by **asking the machine rather than
//! assuming a distribution**:
//!
//!   * the web server's account comes from `nginx.conf`, not from a table;
//!   * the Redis-compatible unit is whichever of `redis-server`/`valkey` exists;
//!   * phpMyAdmin's paths are found, not guessed - EL capitalises them.
//!
//! Everything else is the same question on both: does the API answer, can a
//! website be created, does PHP run through nginx, and does the panel report
//! its own WAF honestly.
//!
//! **It creates one throwaway website and removes it again.** That is why it
//! lives here and not in `snpanel doctor`: a diagnostic command should not
//! write to a customer's box, and this one does.
//!
//! The reading is split from the doing. Everything that decides - which PHP
//! version is the default, which socket a vhost names, whether the panel's
//! WAF answer matches the machine - is a function below with tests. What is
//! left is `Command` and `std::fs`, which no test can pin without a server.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Result};

/// `PASS` / `FAIL` / `SKIP`, in the shell's own format.
///
/// Counted rather than collected: the script prints as it goes, because the
/// website check takes the best part of a minute and an operator watching it
/// should see progress.
#[derive(Default)]
pub struct Report {
    pass: u32,
    fail: u32,
    skip: u32,
}

impl Report {
    fn ok(&mut self, what: &str) {
        println!("  PASS  {what}");
        self.pass += 1;
    }

    fn bad(&mut self, what: &str, why: &str) {
        println!("  FAIL  {what}  -- {why}");
        self.fail += 1;
    }

    fn skip(&mut self, what: &str, why: &str) {
        println!("  SKIP  {what}  -- {why}");
        self.skip += 1;
    }

    /// Two labels, because the shell has two.
    ///
    /// `ok "login returns 200"` and `bad "login" "HTTP $code"` are not the
    /// same string, and the short one is the better failure line: "FAIL login
    /// returns 200" reads like a denial of the thing it is reporting.
    fn check(&mut self, condition: bool, passed: &str, failed: &str, why: &str) {
        if condition {
            self.ok(passed);
        } else {
            self.bad(failed, why);
        }
    }
}

// ---------------------------------------------------------------------------
// the half that decides
// ---------------------------------------------------------------------------

/// Source: `awk '$1=="user"{gsub(/;/,"",$2); print $2; exit}' /etc/nginx/nginx.conf`.
///
/// The account nginx actually runs as, which is `www-data` on the Debian
/// family and `nginx` on EL - and is whatever an administrator put there,
/// which is the reason for reading it rather than looking it up.
pub fn web_user_from_nginx_conf(text: &str) -> Option<&str> {
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("user") {
            continue;
        }
        let value = words.next()?.trim_end_matches(';');
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

/// Source: `PHP_DEFAULT="${PHP_PRESENT[${#PHP_PRESENT[@]}-1]:-}"`.
///
/// The newest version present, because that is the one the installer makes
/// the default. Hard-coding 8.4 here would report a correctly installed
/// Ubuntu 26.04 as missing its PHP.
///
/// "Newest" is the order of the candidate list, not a string comparison:
/// `"8.10" < "8.9"` lexically, and there will be an 8.10.
pub fn newest_present<'a>(candidates: &[&'a str], present: &[String]) -> Option<&'a str> {
    candidates
        .iter()
        .rev()
        .find(|c| present.iter().any(|p| p == *c))
        .copied()
}

/// Source: `sed -n 's/^Password: //p' /root/login.txt`.
///
/// C17 fixes this file at three lines - Panel URL, User, Password - so the
/// prefix is the whole parser.
pub fn password_from_login_file(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("Password: "))
}

/// Source: `awk '/snpanel_csrf/{print $NF}'` over curl's cookie jar.
///
/// The jar is tab-separated and the value is the last field. A `#HttpOnly_`
/// prefix on the domain does not change that.
pub fn csrf_from_cookie_jar(jar: &str) -> Option<&str> {
    jar.lines()
        .filter(|l| l.contains("snpanel_csrf"))
        .filter_map(|l| l.split_whitespace().next_back())
        .next_back()
}

/// Source: `sed -n 's/.*fastcgi_pass unix:\\([^;]*\\);.*/\\1/p' | head -1`.
pub fn fastcgi_socket(vhost: &str) -> Option<&str> {
    vhost
        .lines()
        .find_map(|l| l.split_once("fastcgi_pass unix:"))
        .and_then(|(_, rest)| rest.split_once(';'))
        .map(|(socket, _)| socket)
}

/// Source: `sed -n 's/^[[:space:]]*root[[:space:]]*\\(.*\\);/\\1/p' | head -1`.
///
/// The first `root` directive at the start of a line. A `root` inside the
/// ACME location block is indented too, so "first" is what the shell took and
/// what this takes.
pub fn document_root(vhost: &str) -> Option<&str> {
    for line in vhost.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("root") else {
            continue;
        };
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(value) = rest.trim_start().strip_suffix(';') {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Source: `sed -n 's/.*"id":[[:space:]]*\\([0-9]*\\).*/\\1/p' | head -1`.
///
/// Deliberately the same shape as the shell's: the first `"id":` in the
/// response body, not a parsed document. The response is the panel's own and
/// its first id is the site's.
pub fn first_id(json: &str) -> Option<i64> {
    let (_, rest) = json.split_once("\"id\":")?;
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// What `snpanel-helper waf-status` says about the engine.
///
/// **A deliberate divergence, and a bug fix.** The shell took
/// `sed -n '2s/^ *//p'` - the second line, stripped - which was right when the
/// verb printed a sentence. It prints JSON now, and the second line is
/// `"crs_installed": false,`: whether the OWASP Core Rule Set is installed,
/// not whether ModSecurity is. So on a correct box with the engine loaded and
/// no rule set, the check reported the helper and itself as disagreeing when
/// they did not.
///
/// The script's own comment warned about exactly this - "an earlier version
/// of this check was a third independent copy of the question that went
/// stale" - which it then became again.
///
/// Matched on the whole key. `"crs_installed"` ends with `installed`, so a
/// substring search finds the wrong field first.
pub fn helper_engine_installed(json: &str) -> Option<bool> {
    for line in json.lines() {
        let Some(rest) = line.trim_start().strip_prefix("\"installed\"") else {
            continue;
        };
        let value = rest.trim_start().strip_prefix(':')?.trim();
        let value = value.trim_end_matches(',').trim();
        return match value {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
    }
    None
}

/// Whether the panel's WAF answer matches the machine, and what to say.
///
/// Not "is the WAF on". An earlier version of this check was a third
/// independent copy of the question and went stale: it knew about a packaged
/// module and a compiled-in one, but not one built from source and loaded
/// with `load_module`, so it called the panel a liar when the panel was
/// right.
pub fn waf_agreement(helper_says: Option<bool>, engine_present: bool) -> Result<String, String> {
    let Some(says) = helper_says else {
        return Err(format!(
            "the helper's waf-status has no \"installed\" field; this check says '{}'",
            if engine_present { "yes" } else { "no" }
        ));
    };
    let word = if says { "installed" } else { "not installed" };
    if says == engine_present {
        Ok(format!("the helper agrees with this check ({word})"))
    } else {
        Err(format!(
            "helper says '{word}', this check says '{}'",
            if engine_present { "yes" } else { "no" }
        ))
    }
}

/// What the panel's `/api/waf/status` body has to say, given the machine.
pub fn waf_status_verdict(body: &str, engine_present: bool) -> Result<&'static str, &'static str> {
    // The body is the helper's command result, and its stdout is the helper's
    // JSON now - `"installed": false`, not the words the shell printed. Read
    // only for the words, a machine without the module was called a liar for
    // saying so correctly.
    let from_json = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("stdout").and_then(|s| s.as_str()).map(str::to_string))
        .and_then(|stdout| helper_engine_installed(&stdout));
    let claims_absent = match from_json {
        Some(installed) => !installed,
        None => body.to_ascii_lowercase().contains("not installed"),
    };
    match (engine_present, claims_absent) {
        (false, true) => Ok("the panel reports it as not installed, which is true"),
        (false, false) => Err("the panel claims an engine this machine does not have"),
        (true, true) => Err("the panel reports no engine, but nginx has one"),
        (true, false) => Ok("the panel reports the engine, which is true"),
    }
}

/// Whether any of the three places a ModSecurity module can be named says it
/// is there.
///
/// Source: the `nginx -V`, the `modules-enabled` file and the `load_module`
/// grep, which the shell ORs together.
pub fn engine_present(nginx_v: &str, modules_enabled: bool, load_module_files: &[String]) -> bool {
    if nginx_v.to_ascii_lowercase().contains("modsecurity") {
        return true;
    }
    if modules_enabled {
        return true;
    }
    load_module_files.iter().any(|text| {
        text.lines().any(|l| {
            let t = l.trim_start();
            t.starts_with("load_module") && t.to_ascii_lowercase().contains("modsecurity")
        })
    })
}

// ---------------------------------------------------------------------------
// the half that does
// ---------------------------------------------------------------------------

const PHP_CANDIDATES: &[&str] = &["8.1", "8.2", "8.3", "8.4", "8.5"];
const REDIS_CANDIDATES: &[&str] = &["redis-server", "valkey", "redis"];
const PMA_ROOTS: &[&str] = &["/usr/share/phpMyAdmin", "/usr/share/phpmyadmin"];
const PMA_CONFS: &[&str] = &["/etc/phpMyAdmin", "/etc/phpmyadmin"];

struct Machine {
    web_user: String,
    web_group: String,
    redis_service: Option<String>,
    pma_root: Option<PathBuf>,
    pma_conf: Option<PathBuf>,
    php_present: Vec<String>,
    php_default: Option<String>,
}

fn read(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn run(argv: &[&str]) -> (bool, String) {
    match Command::new(argv[0]).args(&argv[1..]).output() {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.success(), text.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

fn is_active(unit: &str) -> bool {
    run(&["systemctl", "is-active", "--quiet", unit]).0
}

fn detect() -> Machine {
    let web_user = web_user_from_nginx_conf(&read("/etc/nginx/nginx.conf"))
        .unwrap_or("www-data")
        .to_string();
    let web_group = {
        let (ok, out) = run(&["id", "-gn", &web_user]);
        if ok && !out.is_empty() {
            out
        } else {
            web_user.clone()
        }
    };
    let redis_service = REDIS_CANDIDATES
        .iter()
        .find(|u| run(&["systemctl", "cat", u]).0)
        .map(|u| u.to_string());
    let php_present: Vec<String> = PHP_CANDIDATES
        .iter()
        .filter(|v| Path::new(&format!("/etc/php/{v}/fpm")).is_dir())
        .map(|v| v.to_string())
        .collect();
    let php_default = std::env::var("PHP_DEFAULT")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| newest_present(PHP_CANDIDATES, &php_present).map(str::to_string));

    Machine {
        web_user,
        web_group,
        redis_service,
        pma_root: PMA_ROOTS.iter().map(PathBuf::from).find(|p| p.is_dir()),
        pma_conf: PMA_CONFS.iter().map(PathBuf::from).find(|p| p.is_dir()),
        php_present,
        php_default,
    }
}

pub fn run_task(_args: &[String]) -> Result<()> {
    if !run(&["id", "-u"]).1.starts_with('0') {
        bail!("run this as root");
    }

    let panel_port = std::env::var("PANEL_PORT").unwrap_or_else(|_| "2222".to_string());
    let base = format!("https://127.0.0.1:{panel_port}");
    let login_file = std::env::var("LOGIN_FILE").unwrap_or_else(|_| "/root/login.txt".to_string());

    let m = detect();
    let mut r = Report::default();

    println!("=== this machine ===");
    println!("  os:          {}", pretty_name());
    println!("  web user:    {}:{}", m.web_user, m.web_group);
    println!(
        "  redis unit:  {}",
        m.redis_service.as_deref().unwrap_or("none found")
    );
    println!(
        "  phpMyAdmin:  {}  (config {})",
        m.pma_root
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not installed".into()),
        m.pma_conf
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "none".into())
    );
    println!(
        "  php:         {}  (default {})",
        if m.php_present.is_empty() {
            "none found".to_string()
        } else {
            m.php_present.join(" ")
        },
        m.php_default.as_deref().unwrap_or("none")
    );

    services(&m, &mut r);
    permissions(&m, &mut r);
    let session = api(&base, &login_file, &m, &mut r);
    website(&base, &m, session.as_ref(), &mut r);
    phpmyadmin(&m, &mut r);
    waf(&base, session.as_ref(), &mut r);

    println!();
    println!("================================================");
    println!(
        "  passed: {}   failed: {}   skipped: {}",
        r.pass, r.fail, r.skip
    );
    if r.fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn pretty_name() -> String {
    read("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn services(m: &Machine, r: &mut Report) {
    println!();
    println!("=== services ===");
    // The panel is served one of two ways. Before the Rust cutover
    // `snpanel-api` holds the port; after it `snpanel-rust` does and
    // `snpanel-upstream` runs behind it, with `snpanel-api` stopped on
    // purpose. Insisting on the first arrangement would report a correctly
    // cut-over server as broken.
    if is_active("snpanel-rust") {
        r.ok("snpanel-rust is running (Rust front door)");
        let up = is_active("snpanel-upstream");
        r.check(
            up,
            "snpanel-upstream is running (Python behind it)",
            "snpanel-upstream",
            &run(&["systemctl", "is-active", "snpanel-upstream"]).1,
        );
    } else if is_active("snpanel-api") {
        r.ok("snpanel-api is running");
    } else {
        r.bad(
            "the panel service",
            "neither snpanel-rust nor snpanel-api is active",
        );
    }

    let mut units = vec!["nginx".to_string(), "mariadb".to_string()];
    units.extend(m.redis_service.clone());
    for unit in &units {
        let active = is_active(unit);
        r.check(
            active,
            &format!("{unit} is running"),
            unit,
            &run(&["systemctl", "is-active", unit]).1,
        );
    }

    if m.php_present.is_empty() {
        r.bad("php", "no /etc/php/<version>/fpm directory exists at all");
    }
    // PHP-FPM is `php<v>-fpm` on Debian and `php<vv>-php-fpm` on Remi; the
    // installer's compatibility shim makes the Debian name reach both, so ask
    // for that name.
    for v in &m.php_present {
        let unit = format!("php{v}-fpm");
        if run(&["systemctl", "cat", &unit]).0 {
            let active = is_active(&unit);
            r.check(
                active,
                &format!("{unit} is running"),
                &unit,
                &run(&["systemctl", "is-active", &unit]).1,
            );
        } else {
            r.skip(&unit, "not installed on this server");
        }
    }
}

fn permissions(m: &Machine, r: &mut Report) {
    println!();
    println!("=== the web server can reach what the panel writes ===");
    let groups = run(&["id", "-nG", &m.web_user]).1;
    r.check(
        groups.split_whitespace().any(|g| g == "snpanel-sites"),
        &format!("{} is in snpanel-sites", m.web_user),
        "group",
        &groups,
    );
    let groups = run(&["id", "-nG", "snpanel"]).1;
    r.check(
        groups.split_whitespace().any(|g| g == m.web_group),
        &format!("snpanel is in {}", m.web_group),
        "group",
        &groups,
    );
}

/// A logged-in session: the cookie jar curl wrote, and the CSRF token in it.
struct Session {
    jar: PathBuf,
    csrf: String,
}

fn curl(args: &[&str]) -> (String, String) {
    let mut argv: Vec<&str> = vec!["curl", "-sk", "-w", "%{http_code}"];
    argv.extend_from_slice(args);
    let (_, out) = run(&argv);
    // The status code is the last three characters; everything before it is
    // whatever the body was, when the body was not sent to a file.
    let split = out.len().saturating_sub(3);
    (out[split..].to_string(), out[..split].to_string())
}

fn api(base: &str, login_file: &str, m: &Machine, r: &mut Report) -> Option<Session> {
    println!();
    println!("=== the API ===");
    let health = format!("{base}/api/health");
    let (code, _) = curl(&["-o", "/dev/null", "--max-time", "15", &health]);
    r.check(
        code == "200",
        "/api/health returns 200",
        "health",
        &format!("HTTP {code}"),
    );

    let Some(password) = password_from_login_file(&read(login_file)).map(str::to_string) else {
        r.skip("login", &format!("no password in {login_file}"));
        return None;
    };

    let jar = std::env::temp_dir().join("snpanel-acceptance.jar");
    let _ = std::fs::remove_file(&jar);
    let jar_str = jar.to_string_lossy().into_owned();
    let url = format!("{base}/api/auth/login");
    let (code, _) = curl(&[
        "-c",
        &jar_str,
        "-o",
        "/dev/null",
        "--max-time",
        "20",
        "-X",
        "POST",
        &url,
        "--data-urlencode",
        "username=admin",
        "--data-urlencode",
        &format!("password={password}"),
    ]);
    r.check(
        code == "200",
        "login returns 200",
        "login",
        &format!("HTTP {code}"),
    );

    let jar_text = read(&jar);
    r.check(
        jar_text.contains("snpanel_session"),
        "a session cookie was set",
        "cookie",
        "none",
    );
    r.check(
        jar_text
            .lines()
            .any(|l| l.starts_with("#HttpOnly_") && l.contains("snpanel_session")),
        "and it is HttpOnly",
        "httponly",
        "",
    );

    let services = format!("{base}/api/services/list");
    let body_path = std::env::temp_dir().join("snpanel-acceptance-services.json");
    let body_str = body_path.to_string_lossy().into_owned();
    let (code, _) = curl(&[
        "-b",
        &jar_str,
        "-o",
        &body_str,
        "--max-time",
        "20",
        &services,
    ]);
    r.check(
        code == "200",
        "/api/services/list returns 200",
        "services",
        &format!("HTTP {code}"),
    );
    if let Some(redis) = &m.redis_service {
        let body = read(&body_path);
        r.check(
            body.contains(&format!("\"{redis}\"")),
            &format!("and names this machine's Redis unit ({redis})"),
            "services body",
            &format!("no mention of {redis}"),
        );
    }

    csrf_from_cookie_jar(&jar_text).map(|csrf| Session {
        jar: jar.clone(),
        csrf: csrf.to_string(),
    })
}

fn website(base: &str, m: &Machine, session: Option<&Session>, r: &mut Report) {
    println!();
    println!("=== a website, end to end ===");
    let Some(session) = session else {
        r.skip("website", "not logged in");
        return;
    };
    let jar = session.jar.to_string_lossy().into_owned();
    let csrf = format!("X-CSRF-Token: {}", session.csrf);
    let domain = format!("acceptance{}.example.com", std::process::id());
    let php = m.php_default.clone().unwrap_or_default();

    let body_path = std::env::temp_dir().join("snpanel-acceptance-site.json");
    let body_str = body_path.to_string_lossy().into_owned();
    let url = format!("{base}/api/websites");
    let payload = format!(
        "{{\"domain\":\"{domain}\",\"php_version\":\"{php}\",\"app_type\":\"php\",\"install_wordpress\":false}}"
    );
    let (code, _) = curl(&[
        "-b",
        &jar,
        "-H",
        &csrf,
        "-H",
        "Content-Type: application/json",
        "-o",
        &body_str,
        "--max-time",
        "90",
        "-X",
        "POST",
        &url,
        "-d",
        &payload,
    ]);
    if code == "200" || code == "201" {
        r.ok("created through the API");
    } else {
        let body = read(&body_path);
        r.bad(
            "create",
            &format!("HTTP {code} {}", &body[..body.len().min(200)]),
        );
    }

    let vhost_path = PathBuf::from(format!("/etc/nginx/conf.d/{domain}.conf"));
    r.check(
        vhost_path.is_file(),
        "vhost written",
        "vhost",
        &format!("{} missing", vhost_path.display()),
    );
    let vhost = read(&vhost_path);

    // Each site gets its own FPM pool, so the socket name is per-site. What
    // matters is that it is under /run/php and that the pool is listening.
    let socket = fastcgi_socket(&vhost).map(str::to_string);
    match socket.as_deref() {
        Some(s) if s.starts_with("/run/php/") && s.ends_with(".sock") => {
            r.ok("its FPM socket is under /run/php")
        }
        other => r.bad("fastcgi_pass", other.unwrap_or("none")),
    }

    match socket.as_deref() {
        Some(s) => {
            // php-fpm is reloaded asynchronously after the pool file is
            // written, so the socket appears a second or two later. Testing
            // for it immediately is a race: it passed on three platforms and
            // failed on the fourth, which is what races do rather than
            // evidence about the platform.
            if wait_for(Duration::from_secs(1), 15, || is_socket(s)) {
                r.ok(&format!("the pool is listening ({})", stat_owner_mode(s)));
            } else {
                r.bad("pool socket", &format!("{s} did not appear within 15s"));
            }
        }
        // **A deliberate divergence.** The shell ran its wait loop whatever
        // `sed` had found, so a vhost that was never written - the case
        // directly above this one - meant fifteen `sleep 1`s against the
        // empty string and then "` did not appear within 15s`", with nothing
        // before the space. Same number of checks here, no wait, and a reason
        // that is true.
        None => r.bad("pool socket", "the vhost names no socket"),
    }

    let (nginx_ok, nginx_out) = run(&["nginx", "-t"]);
    r.check(
        nginx_ok,
        "nginx accepts its configuration",
        "nginx -t",
        nginx_out.lines().next_back().unwrap_or(""),
    );

    match document_root(&vhost) {
        Some(root) if Path::new(root).is_dir() => {
            php_through_nginx(root, &domain, &m.web_user, r);
        }
        other => r.bad("document root", other.unwrap_or("not found in vhost")),
    }

    if let Some(id) = first_id(&read(&body_path)) {
        let url = format!("{base}/api/websites/{id}");
        let _ = curl(&[
            "-b",
            &jar,
            "-H",
            &csrf,
            "-o",
            "/dev/null",
            "--max-time",
            "60",
            "-X",
            "DELETE",
            &url,
        ]);
    }
    let _ = std::fs::remove_file(&vhost_path);
    if run(&["nginx", "-t"]).0 {
        let _ = run(&["systemctl", "reload", "nginx"]);
    }
}

fn php_through_nginx(root: &str, domain: &str, web_user: &str, r: &mut Report) {
    // Not a dotfile: the generated vhost denies those, correctly, and a 403
    // from that rule looks exactly like a broken PHP handler.
    let probe = Path::new(root).join("snpanel-platform-check.php");
    if std::fs::write(&probe, "<?php echo \"php-ok-\".PHP_VERSION;").is_err() {
        r.bad("document root", "could not write the probe");
        return;
    }
    let _ = set_mode(&probe, 0o644);

    let probe_str = probe.to_string_lossy().into_owned();
    let readable = run(&["runuser", "-u", web_user, "--", "test", "-r", &probe_str]).0;
    r.check(
        readable,
        &format!("{web_user} can read a file the panel created"),
        "readability",
        &format!("{web_user} cannot read it"),
    );

    // nginx is reloaded asynchronously after a site is created, so a request
    // sent immediately can still be answered by the previous configuration.
    let host = format!("Host: {domain}");
    let mut body = String::new();
    wait_for(Duration::from_secs(2), 10, || {
        let (_, out) = curl(&[
            "--max-time",
            "20",
            "-H",
            &host,
            "http://127.0.0.1/snpanel-platform-check.php",
        ]);
        body = out;
        body.starts_with("php-ok-")
    });
    if body.starts_with("php-ok-") {
        r.ok(&format!("PHP runs through nginx: {body}"));
    } else {
        r.bad("php", &body[..body.len().min(120)]);
    }
    let _ = std::fs::remove_file(&probe);
}

fn phpmyadmin(m: &Machine, r: &mut Report) {
    println!();
    println!("=== phpMyAdmin ===");
    let (Some(root), Some(conf)) = (&m.pma_root, &m.pma_conf) else {
        r.skip("phpMyAdmin", "not installed");
        return;
    };
    r.check(
        root.join("snpanel-signon.php").is_file(),
        "the signon script is in place",
        "signon",
        &format!("missing from {}", root.display()),
    );
    r.check(
        conf.join("conf.d/snpanel-signon.php").is_file(),
        "the SSO config is in conf.d",
        "sso config",
        &format!("missing from {}/conf.d", conf.display()),
    );
    let config = conf.join("config.inc.php");
    let config_str = config.to_string_lossy().into_owned();
    r.check(
        run(&[
            "runuser",
            "-u",
            &m.web_user,
            "--",
            "test",
            "-r",
            &config_str,
        ])
        .0,
        &format!("{} can read the phpMyAdmin config", m.web_user),
        "pma readable",
        &format!("{} cannot read {}", m.web_user, config.display()),
    );
    let (code, _) = curl(&[
        "-o",
        "/dev/null",
        "--max-time",
        "20",
        "http://127.0.0.1/phpmyadmin/",
    ]);
    r.check(
        code == "200" || code == "302",
        &format!("/phpmyadmin/ answers HTTP {code}"),
        "phpmyadmin",
        &format!("HTTP {code}"),
    );
}

fn waf(base: &str, session: Option<&Session>, r: &mut Report) {
    println!();
    println!("=== the WAF reports what is actually there ===");
    let load_module_sources: Vec<String> = ["/etc/nginx/nginx.conf"]
        .iter()
        .map(read)
        .chain(
            read_dir_texts("/etc/nginx/modules-enabled")
                .into_iter()
                .chain(read_dir_texts("/usr/share/nginx/modules")),
        )
        .collect();
    let present = engine_present(
        &run(&["nginx", "-V"]).1,
        Path::new("/etc/nginx/modules-enabled/50-mod-http-modsecurity.conf").exists(),
        &load_module_sources,
    );
    println!(
        "  ModSecurity module present: {}",
        if present { "yes" } else { "no" }
    );

    if Path::new("/usr/local/sbin/snpanel-helper").exists() && run(&["id", "-u", "snpanel"]).0 {
        let (_, out) = run(&[
            "sudo",
            "-u",
            "snpanel",
            "env",
            "HOME=/opt/snpanel",
            "sudo",
            "-n",
            "/usr/local/sbin/snpanel-helper",
            "waf-status",
        ]);
        match waf_agreement(helper_engine_installed(&out), present) {
            Ok(message) => r.ok(&message),
            Err(why) => r.bad("helper disagrees", &why),
        }
    }

    if let Some(session) = session {
        let jar = session.jar.to_string_lossy().into_owned();
        let body_path = std::env::temp_dir().join("snpanel-acceptance-waf.json");
        let body_str = body_path.to_string_lossy().into_owned();
        let url = format!("{base}/api/waf/status");
        let _ = curl(&["-b", &jar, "-o", &body_str, "--max-time", "20", &url]);
        match waf_status_verdict(&read(&body_path), present) {
            Ok(message) => r.ok(message),
            Err(why) => r.bad("waf status", why),
        }
    }

    r.check(
        Path::new("/etc/nginx/conf.d/00-snpanel-http-flood.conf").is_file(),
        "HTTP flood protection is configured (it needs no ModSecurity)",
        "flood conf",
        "missing",
    );
}

fn read_dir_texts(dir: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| read(e.path()))
        .collect()
}

fn wait_for(pause: Duration, attempts: u32, mut ready: impl FnMut() -> bool) -> bool {
    for i in 0..attempts {
        if ready() {
            return true;
        }
        if i + 1 < attempts {
            std::thread::sleep(pause);
        }
    }
    ready()
}

fn is_socket(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

fn stat_owner_mode(path: &str) -> String {
    run(&["stat", "-c", "%U:%G %a", path]).1
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The account nginx runs as, read the way the shell read it.
    #[test]
    fn the_web_user_comes_from_nginx_conf() {
        let debian = "user www-data;\nworker_processes auto;\n";
        assert_eq!(web_user_from_nginx_conf(debian), Some("www-data"));
        let el = "\nuser nginx;\npid /run/nginx.pid;\n";
        assert_eq!(web_user_from_nginx_conf(el), Some("nginx"));
    }

    /// `user` has to be the directive, not a word inside one - there is a
    /// `fastcgi_param REMOTE_USER` in every generated vhost.
    #[test]
    fn a_word_that_merely_contains_user_is_not_the_directive() {
        let text = "  fastcgi_param REMOTE_USER $remote_user;\nuser nginx;\n";
        assert_eq!(web_user_from_nginx_conf(text), Some("nginx"));
        assert_eq!(web_user_from_nginx_conf("# user www-data;\n"), None);
    }

    /// The newest present, in the candidate list's order rather than
    /// alphabetically - `"8.10" < "8.9"` as strings, and there will be an
    /// 8.10.
    #[test]
    fn the_default_php_is_the_newest_present() {
        let candidates = ["8.1", "8.2", "8.3", "8.4", "8.5"];
        let present = vec!["8.2".to_string(), "8.4".to_string()];
        assert_eq!(newest_present(&candidates, &present), Some("8.4"));
        assert_eq!(newest_present(&candidates, &[]), None);
        assert_eq!(
            newest_present(&candidates, &["8.1".to_string()]),
            Some("8.1")
        );
    }

    /// C17 fixes the file at three lines, so the prefix is the parser.
    #[test]
    fn the_password_comes_off_the_third_line() {
        let file = "Panel URL: https://198.51.100.7:2222\nUser: admin\nPassword: hunter2\n";
        assert_eq!(password_from_login_file(file), Some("hunter2"));
        assert_eq!(password_from_login_file("User: admin\n"), None);
        // A password with spaces survives - `sed s/^Password: //` takes the
        // rest of the line, and so does this.
        assert_eq!(password_from_login_file("Password: a b c\n"), Some("a b c"));
    }

    #[test]
    fn the_csrf_token_is_the_last_field_of_its_cookie_line() {
        let jar = "# Netscape HTTP Cookie File\n\
                   #HttpOnly_127.0.0.1\tFALSE\t/\tTRUE\t0\tsnpanel_session\tabc\n\
                   127.0.0.1\tFALSE\t/\tTRUE\t0\tsnpanel_csrf\tdeadbeef\n";
        assert_eq!(csrf_from_cookie_jar(jar), Some("deadbeef"));
        assert_eq!(csrf_from_cookie_jar("nothing here\n"), None);
    }

    #[test]
    fn the_socket_and_the_root_come_out_of_the_vhost() {
        let vhost = "server {\n    root /home/u1/site/public_html;\n\
                     location ^~ /.well-known/acme-challenge/ {\n        root /var/www/snpanel-acme;\n    }\n\
                     location ~ \\.php$ {\n        fastcgi_pass unix:/run/php/snpanel-site.sock;\n    }\n}\n";
        assert_eq!(fastcgi_socket(vhost), Some("/run/php/snpanel-site.sock"));
        // The first `root`, which is the site's - the ACME one is below it.
        assert_eq!(document_root(vhost), Some("/home/u1/site/public_html"));
        assert_eq!(fastcgi_socket("server {}\n"), None);
        assert_eq!(document_root("server {}\n"), None);
    }

    #[test]
    fn the_site_id_is_the_first_one_in_the_body() {
        assert_eq!(first_id(r#"{"id": 42, "domain": "a"}"#), Some(42));
        assert_eq!(first_id(r#"{"domain":"a","id":7}"#), Some(7));
        assert_eq!(first_id(r#"{"domain":"a"}"#), None);
    }

    /// The panel's answer against the machine, both ways round.
    #[test]
    fn the_waf_answer_has_to_match_the_machine() {
        assert!(waf_status_verdict("{\"engine\":\"not installed\"}", false).is_ok());
        assert!(waf_status_verdict("{\"engine\":\"ModSecurity 3\"}", true).is_ok());
        assert!(waf_status_verdict("{\"engine\":\"ModSecurity 3\"}", false).is_err());
        assert!(waf_status_verdict("{\"engine\":\"not installed\"}", true).is_err());
        // The command result the API returns now, with the helper's JSON in it.
        let absent = r#"{"command":"waf-status","returncode":0,"stdout":"{\n  \"installed\": false,\n  \"crs_mode\": \"off\"\n}\n","stderr":""}"#;
        let present = r#"{"command":"waf-status","returncode":0,"stdout":"{\n  \"installed\": true\n}\n","stderr":""}"#;
        assert!(waf_status_verdict(absent, false).is_ok());
        assert!(waf_status_verdict(absent, true).is_err());
        assert!(waf_status_verdict(present, true).is_ok());
        assert!(waf_status_verdict(present, false).is_err());
    }

    #[test]
    fn the_helper_and_this_check_have_to_agree() {
        assert!(waf_agreement(Some(true), true).is_ok());
        assert!(waf_agreement(Some(false), false).is_ok());
        assert!(waf_agreement(Some(true), false).is_err());
        assert!(waf_agreement(Some(false), true).is_err());
        assert!(waf_agreement(None, true).is_err());
    }

    /// The field the helper's JSON actually carries - and not the one whose
    /// name ends with it.
    ///
    /// This is the bug the port fixed: the shell read the second line, which
    /// is `"crs_installed"`, so a box with ModSecurity loaded and no rule set
    /// was reported as the helper disagreeing with the check.
    #[test]
    fn the_helper_answer_is_installed_and_not_crs_installed() {
        let json = "{\n  \"crs_installed\": false,\n  \"crs_mode\": \"off\",\n  \
                    \"installed\": true,\n  \"sites_with_rules\": 9\n}\n";
        assert_eq!(helper_engine_installed(json), Some(true));

        let absent = "{\n  \"crs_installed\": false,\n  \"installed\": false\n}\n";
        assert_eq!(helper_engine_installed(absent), Some(false));

        // The old reading, for the record: the second line is the wrong one.
        assert_eq!(
            json.lines().nth(1).unwrap().trim(),
            "\"crs_installed\": false,"
        );

        assert_eq!(helper_engine_installed("{}"), None);
        assert_eq!(helper_engine_installed(""), None);
    }

    /// A module built from source and loaded with `load_module` counts.
    ///
    /// This is the case the old bash missed, which had it calling the panel a
    /// liar when the panel was right.
    #[test]
    fn a_load_module_line_counts_as_the_engine_being_there() {
        let conf = "load_module modules/ngx_http_modsecurity_module.so;\n".to_string();
        assert!(engine_present("nginx version: 1.26", false, &[conf]));
        assert!(engine_present("built with modsecurity", false, &[]));
        assert!(engine_present("nginx version: 1.26", true, &[]));
        assert!(!engine_present("nginx version: 1.26", false, &[]));
    }

    /// A commented-out `load_module` is not a loaded module.
    #[test]
    fn a_commented_load_module_does_not_count() {
        let conf = "# load_module modules/ngx_http_modsecurity_module.so;\n".to_string();
        assert!(!engine_present("nginx version: 1.26", false, &[conf]));
    }
}
