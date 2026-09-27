//! One-shot login tokens - `services/sso_tokens.py`.
//!
//! A token is a JSON file under `/tmp/snpanel-phpmyadmin-sso`, and it is
//! **deleted as it is read**. That is what makes the link in a provisioning
//! response safe to put in a redirect: by the time it reaches a log, a proxy,
//! or somebody's browser history, it has already been spent.
//!
//! Two guards that look paranoid and are not:
//!
//! - the token name is checked before it is turned into a path, so
//!   `../../etc/passwd` cannot address a file outside the directory;
//! - the file is removed even when its contents turn out to be unreadable, so
//!   a corrupt token cannot be retried forever.

use std::path::PathBuf;

/// Source: `TOKEN_DIR`.
pub const TOKEN_DIR: &str = "/tmp/snpanel-phpmyadmin-sso";

/// Source: `_token_path` - the token must be alphanumeric once `-` and `_`
/// are removed, which is exactly the alphabet `secrets.token_urlsafe` emits.
fn token_path(token: &str) -> Option<PathBuf> {
    let stripped: String = token.chars().filter(|c| *c != '-' && *c != '_').collect();
    if stripped.is_empty() || !stripped.chars().all(|c| c.is_alphanumeric()) {
        return None;
    }
    Some(PathBuf::from(TOKEN_DIR).join(format!("{token}.json")))
}

/// Source: `TOKEN_TTL_SECONDS` - one minute for a phpMyAdmin hand-off, which
/// is a link that is followed immediately or not at all.
const PHPMYADMIN_TTL_SECONDS: i64 = 60;

/// Source: `PANEL_LOGIN_TTL_SECONDS` - five minutes.
///
/// Longer than the phpMyAdmin hand-off because a billing system puts this
/// in a link a human then clicks, rather than following it itself.
const PANEL_LOGIN_TTL_SECONDS: i64 = 300;

/// Consume a phpMyAdmin token. Source: `consume_phpmyadmin_token`.
///
/// Note the default in `data.get("kind", "phpmyadmin")`: a token written
/// before the `kind` field existed still counts as a phpMyAdmin one. The panel
/// login check has no such default, so a phpMyAdmin token can never be used to
/// log into the panel - only the other way round, and only for old files.
pub fn consume_phpmyadmin_token(token: &str) -> Option<serde_json::Value> {
    let data = consume(token)?;
    let kind = data
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("phpmyadmin");
    (kind == "phpmyadmin").then_some(data)
}

/// Mint a phpMyAdmin token. Source: `create_phpmyadmin_token`.
///
/// The file is created with `O_EXCL` and mode 0600 from the start, never
/// created and then chmod'd: between those two steps the credentials would be
/// world-readable, and `/tmp` is where every user on the machine can look.
/// `O_NOFOLLOW` is what stops a symlink planted at the path from redirecting
/// the write somewhere else.
pub fn create_phpmyadmin_token(
    db_user: &str,
    db_password: &str,
    db_name: &str,
) -> std::io::Result<String> {
    use std::os::unix::fs::OpenOptionsExt;

    cleanup_expired_tokens();

    let token = snpanel_core::crypto::token::generate_jti();
    let dir = PathBuf::from(TOKEN_DIR);
    std::fs::create_dir_all(&dir)?;
    // 0700: only the panel user may list what is in here.
    let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));

    let expires = chrono::Utc::now() + chrono::Duration::seconds(PHPMYADMIN_TTL_SECONDS);
    let payload = serde_json::json!({
        "kind": "phpmyadmin",
        "db_user": db_user,
        "db_password": db_password,
        "db_name": db_name,
        "expires_at": expires.to_rfc3339(),
    });

    let path = dir.join(format!("{token}.json"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&path)?;
    use std::io::Write;
    if let Err(e) = file.write_all(payload.to_string().as_bytes()) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(token)
}

/// Source: `create_panel_login_token`.
///
/// A one-use ticket that logs a billing system's customer into the panel
/// without the billing system ever holding their password. Five minutes,
/// written `O_EXCL` with mode 0600 like every other token here — the
/// exclusive create is what stops a symlink already sitting at the path
/// from redirecting the write.
pub fn create_panel_login_token(username: &str) -> std::io::Result<String> {
    use std::os::unix::fs::OpenOptionsExt;

    cleanup_expired_tokens();

    let token = snpanel_core::crypto::token::generate_jti();
    let dir = PathBuf::from(TOKEN_DIR);
    std::fs::create_dir_all(&dir)?;
    let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));

    let expires = chrono::Utc::now() + chrono::Duration::seconds(PANEL_LOGIN_TTL_SECONDS);
    let payload = serde_json::json!({
        "kind": "panel_login",
        "username": username,
        "expires_at": expires.to_rfc3339(),
    });

    let path = dir.join(format!("{token}.json"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&path)?;
    use std::io::Write;
    if let Err(e) = file.write_all(payload.to_string().as_bytes()) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(token)
}

/// Source: `cleanup_expired_tokens` - every sweep removes what has expired and
/// anything unreadable, so a directory of stale credentials cannot build up.
pub fn cleanup_expired_tokens() {
    let Ok(entries) = std::fs::read_dir(TOKEN_DIR) else {
        return;
    };
    let now = chrono::Utc::now();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let expired = match std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| {
                v.get("expires_at")
                    .and_then(|e| e.as_str())
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            }) {
            Some(expires) => expires < now,
            // Unreadable or unparsable: removed, as the Python does.
            None => true,
        };
        if expired {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Consume a panel-login token and return the username it names.
///
/// Source: `consume_panel_login_token`.
pub fn consume_panel_login_token(token: &str) -> Option<String> {
    let data = consume(token)?;
    if data.get("kind").and_then(|v| v.as_str()) != Some("panel_login") {
        return None;
    }
    data.get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn consume(token: &str) -> Option<serde_json::Value> {
    let path = token_path(token)?;
    let contents = std::fs::read_to_string(&path).ok();
    // Removed whether or not it parsed: a token that cannot be read must not
    // stay on disk to be retried.
    let _ = std::fs::remove_file(&path);

    let value: serde_json::Value = serde_json::from_str(&contents?).ok()?;
    if !value.is_object() {
        return None;
    }

    let expires_at = value.get("expires_at").and_then(|v| v.as_str())?;
    let expires = chrono::DateTime::parse_from_rfc3339(expires_at).ok()?;
    if expires < chrono::Utc::now() {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_traversing_token_never_becomes_a_path() {
        // The name goes straight into a filename, so this is the check that
        // keeps it inside the directory.
        for bad in [
            "../../etc/passwd",
            "a/b",
            "a.b",
            "",
            "..",
            "tok en",
            "tok;rm",
        ] {
            assert!(token_path(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_urlsafe_token_is_accepted() {
        // The alphabet secrets.token_urlsafe(32) produces.
        let token = "abcXYZ012-_deadbeef";
        let path = token_path(token).expect("valid");
        assert_eq!(
            path,
            PathBuf::from("/tmp/snpanel-phpmyadmin-sso/abcXYZ012-_deadbeef.json")
        );
    }

    fn write_token(name: &str, body: &str) -> PathBuf {
        let dir = PathBuf::from(TOKEN_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn a_valid_token_resolves_once_and_then_is_gone() {
        let name = format!("valid{}", std::process::id());
        let future = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        let path = write_token(
            &name,
            &format!(r#"{{"kind":"panel_login","username":"admin","expires_at":"{future}"}}"#),
        );

        assert_eq!(
            consume_panel_login_token(&name).as_deref(),
            Some("admin"),
            "the first read must work"
        );
        assert!(!path.exists(), "the file must be deleted as it is read");
        assert_eq!(
            consume_panel_login_token(&name),
            None,
            "a spent token must not work twice"
        );
    }

    #[test]
    fn an_expired_token_is_refused_and_removed() {
        let name = format!("expired{}", std::process::id());
        let past = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let path = write_token(
            &name,
            &format!(r#"{{"kind":"panel_login","username":"admin","expires_at":"{past}"}}"#),
        );
        assert_eq!(consume_panel_login_token(&name), None);
        assert!(!path.exists());
    }

    #[test]
    fn a_token_of_the_wrong_kind_does_not_log_anybody_in() {
        // A phpMyAdmin token must not be usable as a panel login.
        let name = format!("wrongkind{}", std::process::id());
        let future = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        write_token(
            &name,
            &format!(
                r#"{{"kind":"phpmyadmin","db_user":"x","username":"admin","expires_at":"{future}"}}"#
            ),
        );
        assert_eq!(consume_panel_login_token(&name), None);
    }

    #[test]
    fn a_corrupt_token_is_removed_rather_than_retried() {
        let name = format!("corrupt{}", std::process::id());
        let path = write_token(&name, "not json at all");
        assert_eq!(consume_panel_login_token(&name), None);
        assert!(!path.exists());
    }

    #[test]
    fn a_missing_token_is_none() {
        assert_eq!(consume_panel_login_token("doesnotexistatall123"), None);
    }
}
