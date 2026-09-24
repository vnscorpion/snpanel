//! Moving the panel's address, and giving it a certificate.
//!
//! Source: `set_panel_url` and `install_panel_ssl` in `snpanelctl`, with the
//! decisions taken from [`snpanel_installer::ctl::panel_url`], where they
//! already had golden fixtures.
//!
//! Both of these change how the panel is reached, so both can lock an
//! administrator out of the machine they are administering. The writing half
//! is deliberately *not* here: `panel-url-set` and `panel-ssl-install` are
//! helper verbs, already ported and already what the panel's own settings
//! page calls. Having one implementation rather than two is the point - the
//! last time this box had two, the rescue menu and the panel disagreed about
//! whether phpMyAdmin was being served over TLS.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use snpanel_installer::ctl::panel_url as rules;

use crate::passwords::write_login_info;
use crate::ENV_PATH;

const HELPER: &str = "/usr/local/sbin/snpanel-helper";
/// Source: `DEFAULT_PANEL_PORT`.
const DEFAULT_PANEL_PORT: u16 = 2222;

/// `snpanel set-panel-url`.
///
/// Source: `set_panel_url`.
pub fn set_panel_url(env_path: Option<&Path>) -> Result<()> {
    let env = require_env(env_path)?;

    let current_port = env_value(env, "PANEL_PORT")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PANEL_PORT);
    let current_domain = env_value(env, "PANEL_DOMAIN").unwrap_or_default();

    let typed_domain = ask("Panel domain (blank for server IP): ")?;
    let typed_port = ask(&format!("Panel port [{current_port}]: "))?;
    let port = if typed_port.is_empty() {
        current_port
    } else {
        parse_port(&typed_port)?
    };

    let domain = normalize_domain(&typed_domain);
    let host = if domain.is_empty() {
        // No domain means the panel answers on the address the box has, and
        // a box that cannot say what that is has nothing to move to.
        detect_ip().filter(|h| !h.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("Cannot detect server IP. Enter a panel domain instead.")
        })?
    } else {
        if !valid_domain(&domain) {
            anyhow::bail!("Invalid domain: {domain}");
        }
        domain.clone()
    };

    let cert = env_value(env, "PANEL_SSL_CERT").unwrap_or_default();
    let key = env_value(env, "PANEL_SSL_KEY").unwrap_or_default();
    let https = rules::keeps_https(
        &domain,
        &current_domain,
        &cert,
        &key,
        Path::new(&cert).is_file(),
        Path::new(&key).is_file(),
    );
    let scheme = if https { "https" } else { "http" };

    // One writer. `panel-url-set` writes every `.env` key, opens the new
    // port, re-renders the tools vhost and phpMyAdmin's sign-on file, and
    // schedules the restart - scheduled rather than immediate, because it is
    // answering a request from the process it is about to restart.
    helper(&["panel-url-set", scheme, &host, &port.to_string()])
        .context("Could not move the panel")?;

    // Not part of the verb, and deliberately after it: the old port stays
    // open until the panel is answering on the new one.
    close_old_port(current_port, port);

    // The URL line in /root/login.txt, with the password left as it was.
    let _ = write_login_info(None, env);
    println!("Panel URL: {scheme}://{host}:{port}");
    Ok(())
}

/// `snpanel install-panel-ssl`.
///
/// Source: `install_panel_ssl`.
///
/// **A divergence, and it is the good kind.** The bash issues with
/// `certbot --standalone`, which needs port 80 to itself and so stops nginx -
/// taking every website on the box down for the ten seconds certbot spends
/// talking to Let's Encrypt. `panel-ssl-install` uses `--webroot`: the
/// default vhost serves the challenge and nothing goes offline. That choice
/// was made when the verb was ported and is what the panel's own settings
/// page has been doing since; this only stops the rescue menu being the one
/// caller that still takes the sites down.
pub fn install_panel_ssl(env_path: Option<&Path>) -> Result<()> {
    let env = require_env(env_path)?;

    let mut domain = env_value(env, "PANEL_DOMAIN").unwrap_or_default();
    if domain.is_empty() {
        domain = normalize_domain(&ask("Panel domain: ")?);
    }
    if !valid_domain(&domain) {
        anyhow::bail!("Invalid domain: {domain}");
    }

    let mut email = env_value(env, "SSL_EMAIL").unwrap_or_default();
    if email.is_empty() {
        email = ask("Let's Encrypt email: ")?;
    }
    if !valid_email(&email) {
        anyhow::bail!("Invalid email");
    }

    let port = env_value(env, "PANEL_PORT")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PANEL_PORT);

    println!("Issuing certificate for {domain}.");
    helper(&["panel-ssl-install", &domain, &port.to_string(), &email])
        .context("Could not install the panel certificate")?;

    let _ = write_login_info(None, env);
    println!("Panel SSL enabled: https://{domain}:{port}");
    Ok(())
}

// ---------------------------------------------------------------------------
// the pieces
// ---------------------------------------------------------------------------

/// Source: `close_old_panel_port`.
///
/// Best effort throughout. The panel has already moved by the time this runs,
/// and a rule that could not be removed is an open port - untidy, and not a
/// reason to report the move as failed.
fn close_old_port(old: u16, new: u16) {
    if !rules::may_close_old_port(Some(old), new) {
        return;
    }
    let Ok(listing) = helper_output(&["firewall-list"]) else {
        return;
    };
    let parsed: Vec<rules::Rule> = match serde_json::from_str::<serde_json::Value>(&listing) {
        Ok(v) => v
            .get("rules")
            .and_then(|r| r.as_array())
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(rules::Rule {
                            id: row.get("id")?.to_string().trim_matches('"').to_string(),
                            port: row.get("port")?.as_u64()? as u16,
                            protected: row
                                .get("protected")
                                .and_then(|p| p.as_bool())
                                .unwrap_or(false),
                            ip: row
                                .get("ip")
                                .and_then(|i| i.as_str())
                                .filter(|i| !i.is_empty())
                                .map(str::to_string),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        Err(_) => return,
    };
    if let Some(rule) = rules::rule_to_delete(&parsed, old) {
        let _ = helper(&["firewall-delete", &rule.id]);
    }
}

fn require_env(env_path: Option<&Path>) -> Result<&Path> {
    match env_path {
        Some(p) => Ok(p),
        None => anyhow::bail!("{ENV_PATH} not found. Run the installer first."),
    }
}

/// Source: `normalize_domain` - strip the scheme, then everything from the
/// first `/`, then everything from the first `:`.
pub(crate) fn normalize_domain(value: &str) -> String {
    let v = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .unwrap_or(value);
    let v = v.split('/').next().unwrap_or(v);
    v.split(':').next().unwrap_or(v).to_string()
}

/// Source: `validate_domain`'s anchored pattern. Lowercase only, labels of
/// 1-63 characters that neither start nor end with a hyphen, and at least
/// two labels.
pub(crate) fn valid_domain(value: &str) -> bool {
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// Source: the email pattern in `install_panel_ssl`. Deliberately the same
/// shape and no stricter: a rule that refuses an address Let's Encrypt would
/// have accepted is a rescue menu that will not issue a certificate.
pub(crate) fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
    {
        return false;
    }
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Source: `validate_port`.
fn parse_port(value: &str) -> Result<u16> {
    if value.is_empty() || value.len() > 5 || !value.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("Invalid port: {value}");
    }
    match value.parse::<u32>() {
        Ok(p) if (1..=65535).contains(&p) => Ok(p as u16),
        _ => anyhow::bail!("Port out of range: {value}"),
    }
}

fn detect_ip() -> Option<String> {
    let out = Command::new("hostname").arg("-I").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
}

fn env_value(path: &Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::to_string)
        .filter(|v| !v.is_empty())
}

fn ask(prompt: &str) -> Result<String> {
    // Not a secret, but the same read: one line, nothing trimmed but the
    // newline, and EOF is an empty answer rather than a hang.
    crate::secret::read_visible(prompt)
}

fn helper(args: &[&str]) -> Result<()> {
    if !Path::new(HELPER).exists() {
        anyhow::bail!("{HELPER} is not installed");
    }
    let status = Command::new(HELPER)
        .args(args)
        .env("SUDO_USER", "snpanel")
        .status()
        .with_context(|| format!("running {HELPER} {}", args[0]))?;
    if !status.success() {
        anyhow::bail!("{HELPER} {} exited {:?}", args[0], status.code());
    }
    Ok(())
}

fn helper_output(args: &[&str]) -> Result<String> {
    let out = Command::new(HELPER)
        .args(args)
        .env("SUDO_USER", "snpanel")
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("running {HELPER} {}", args[0]))?;
    if !out.status.success() {
        anyhow::bail!("{HELPER} {} exited {:?}", args[0], out.status.code());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_is_stripped_of_everything_that_is_not_one() {
        // Operators paste the address bar. `normalize_domain` is what makes
        // that work.
        for (raw, want) in [
            ("https://panel.example.com/settings", "panel.example.com"),
            ("http://panel.example.com:2222", "panel.example.com"),
            ("panel.example.com:2222/x", "panel.example.com"),
            ("panel.example.com", "panel.example.com"),
            ("", ""),
        ] {
            assert_eq!(normalize_domain(raw), want, "{raw}");
        }
    }

    #[test]
    fn a_domain_needs_two_labels_and_no_stray_characters() {
        for good in ["a.b", "panel.example.com", "x-1.example.co.uk"] {
            assert!(valid_domain(good), "{good} should be accepted");
        }
        for bad in [
            "localhost",          // one label
            "Panel.Example.com",  // uppercase: the bash pattern is lowercase
            "-lead.example.com",  // label starts with a hyphen
            "trail-.example.com", // label ends with one
            "a..b",               // empty label
            "example.com/",       // normalize_domain's job, refused if it slips
            "",
        ] {
            assert!(!valid_domain(bad), "{bad} should be refused");
        }
    }

    #[test]
    fn an_email_has_to_look_like_one() {
        for good in ["a@b.co", "first.last+tag@sub.example.com", "x_y%z@e-x.io"] {
            assert!(valid_email(good), "{good} should be accepted");
        }
        for bad in ["", "nobody", "a@b", "a@.com", "@example.com", "a@b.c"] {
            assert!(!valid_email(bad), "{bad} should be refused");
        }
    }

    #[test]
    fn a_port_is_one_to_65535() {
        assert_eq!(parse_port("2222").unwrap(), 2222);
        assert_eq!(parse_port("1").unwrap(), 1);
        assert_eq!(parse_port("65535").unwrap(), 65535);
        for bad in ["0", "65536", "99999", "", "22a", "-1", " 22"] {
            assert!(parse_port(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn https_survives_only_a_move_that_keeps_the_name() {
        // A certificate is bound to a name. Serving the old one for a new
        // domain teaches the operator to click through warnings on the one
        // page where that habit costs most.
        assert!(rules::keeps_https(
            "panel.example.com",
            "panel.example.com",
            "/c",
            "/k",
            true,
            true
        ));
        assert!(!rules::keeps_https(
            "new.example.com",
            "panel.example.com",
            "/c",
            "/k",
            true,
            true
        ));
        // Moving to a bare IP drops it too: there is no name to match.
        assert!(!rules::keeps_https(
            "",
            "panel.example.com",
            "/c",
            "/k",
            true,
            true
        ));
        // And a certificate whose files have gone is not one.
        assert!(!rules::keeps_https(
            "panel.example.com",
            "panel.example.com",
            "/c",
            "/k",
            false,
            true
        ));
    }

    #[test]
    fn the_ports_an_operator_is_sitting_on_are_never_closed() {
        // 22 is the one that matters: this runs over SSH.
        for protected in [22, 80, 443, 465, 587] {
            assert!(
                !rules::may_close_old_port(Some(protected), 2222),
                "{protected} must not be closed"
            );
        }
        assert!(rules::may_close_old_port(Some(8443), 2222));
        // Moving to the port it is already on closes nothing.
        assert!(!rules::may_close_old_port(Some(2222), 2222));
    }

    #[test]
    fn neither_command_runs_without_an_env_file() {
        for err in [
            set_panel_url(None).unwrap_err().to_string(),
            install_panel_ssl(None).unwrap_err().to_string(),
        ] {
            assert!(err.contains(ENV_PATH), "{err}");
        }
    }
}
