//! `ops::siteapp` - site applications, the thin half.
//!
//! Source: the `site-app-*` arms of the bash helper. Five of them are
//! wrappers around systemctl, journalctl or docker with a narrow guard in
//! front; the rest - writing units, compose files and the import/export
//! paths - are a larger piece and stay in the bash for now.
//!
//! The naming functions are contracts. Units and containers with these names
//! already exist on installed servers, so a different spelling does not
//! rename anything - it fails to find everything, and `site-app-control stop`
//! reports "unit not found" for an application that is plainly running.

use snpanel_core::{AppName, PanelUsername};
use snpanel_ipc::{AppAction, HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: `app_unit_name`.
fn unit_name(user: &PanelUsername, app: &AppName) -> String {
    format!("snpanel-app-{}-{}", user.as_str(), app.as_str())
}

/// Source: `app_container_name`. Also the Docker Compose project name.
fn container_name(user: &PanelUsername, app: &AppName) -> String {
    format!("snpanel-{}-{}", user.as_str(), app.as_str())
}

/// Source: `app_directory`. Applications live under the owner's home, one
/// directory each, so a customer's chrooted SFTP can reach them without the
/// application being tied to any website.
fn app_directory(user: &PanelUsername, app: &AppName) -> String {
    format!("/home/{}/apps/{}", user.as_str(), app.as_str())
}

/// Source: `app_compose_file`.
fn compose_file(user: &PanelUsername, app: &AppName) -> String {
    format!(
        "/var/lib/snpanel/apps/{}-{}.compose.yml",
        user.as_str(),
        app.as_str()
    )
}

fn docker_present() -> bool {
    [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]
    .iter()
    .any(|d| std::path::Path::new(d).join("docker").is_file())
}

/// `site-app-control`.
pub fn control(user: &PanelUsername, app: &AppName, action: AppAction) -> HelperResponse {
    let unit = unit_name(user, app);
    let path = format!("/etc/systemd/system/{unit}.service");
    if !std::path::Path::new(&path).is_file() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("application unit not found: {unit}"),
        );
    }
    let service = format!("{unit}.service");
    exec::respond(
        &format!("systemctl {} {service}", action.as_str()),
        exec::run(&["systemctl", action.as_str(), &service, "--no-pager"]),
    )
}

/// `site-app-logs`.
pub fn logs(user: &PanelUsername, app: &AppName, lines: u32) -> HelperResponse {
    // Source: `^[0-9]{1,4}$`, so at most four digits.
    let n = lines.clamp(1, 9999).to_string();
    let service = format!("{}.service", unit_name(user, app));
    exec::respond(
        "journalctl",
        exec::run(&[
            "journalctl",
            "-u",
            &service,
            "-n",
            &n,
            "--no-pager",
            "--output",
            "short-iso",
        ]),
    )
}

/// `site-app-compose-ps`.
///
/// The inspect format includes the restart count on purpose: Docker restarts
/// a container that keeps dying, so at any instant it reads as running, and
/// only the count tells the panel it is looping.
pub fn compose_ps(user: &PanelUsername, app: &AppName) -> HelperResponse {
    if !docker_present() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "Docker is not installed; run docker-install first".to_string(),
        );
    }
    let file = compose_file(user, app);
    if !std::path::Path::new(&file).is_file() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no compose file for {app}; deploy it once first"),
        );
    }
    let dir = app_directory(user, app);
    let project = container_name(user, app);

    let listed = exec::run(&[
        "timeout",
        "60",
        "docker",
        "compose",
        "-f",
        &file,
        "--project-directory",
        &dir,
        "-p",
        &project,
        "ps",
        "--all",
        "--quiet",
    ]);
    let ids: Vec<String> = match &listed {
        Ok(o) => o
            .stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        // A compose project with nothing in it is not an error; the bash
        // exits 0 with no output.
        Err(_) => return HelperResponse::with_stdout(String::new()),
    };
    if ids.is_empty() {
        return HelperResponse::with_stdout(String::new());
    }

    const FORMAT: &str = concat!(
        r#"{"service":"{{index .Config.Labels "com.docker.compose.service"}}","#,
        r#""state":"{{.State.Status}}","restarts":{{.RestartCount}},"#,
        r#""exit":{{.State.ExitCode}},"oom":{{.State.OOMKilled}},"#,
        r#""started":"{{.State.StartedAt}}"}"#
    );
    let mut argv: Vec<&str> = vec!["timeout", "60", "docker", "inspect", "--format", FORMAT];
    argv.extend(ids.iter().map(String::as_str));
    exec::respond("docker inspect", exec::run(&argv))
}

/// `site-app-compose-pull`.
pub fn compose_pull(user: &PanelUsername, app: &AppName) -> HelperResponse {
    if !docker_present() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "Docker is not installed; run docker-install first".to_string(),
        );
    }
    let file = compose_file(user, app);
    if !std::path::Path::new(&file).is_file() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no compose file for {app}; deploy it once first"),
        );
    }
    let dir = app_directory(user, app);
    let project = container_name(user, app);
    exec::respond(
        "docker compose pull",
        exec::run(&[
            "timeout",
            "1800",
            "docker",
            "compose",
            "-f",
            &file,
            "--project-directory",
            &dir,
            "-p",
            &project,
            "pull",
        ]),
    )
}

/// `site-app-volume-usage`: bytes in a user's Docker named volumes.
///
/// Zero rather than an error when Docker is absent, as the bash does: a
/// machine with no Docker has no volumes, and a quota calculation should not
/// fail because of it.
pub fn volume_usage(user: &PanelUsername) -> HelperResponse {
    if !docker_present() {
        return HelperResponse::with_stdout("0\n".to_string());
    }
    let prefix = format!("snpanel-{}-", user.as_str());
    let listed = exec::run(&["docker", "volume", "ls", "--format", "{{.Name}}"]);
    let names: Vec<String> = match &listed {
        Ok(o) => o
            .stdout
            .lines()
            .map(str::trim)
            .filter(|n| n.starts_with(&prefix))
            .map(str::to_string)
            .collect(),
        Err(_) => return HelperResponse::with_stdout("0\n".to_string()),
    };

    let mut total: u64 = 0;
    for name in names {
        let path = format!("/var/lib/docker/volumes/{name}/_data");
        if !std::path::Path::new(&path).is_dir() {
            continue;
        }
        // `--one-file-system`, as the bash has it: a bind mount inside a
        // volume belongs to whatever it points at, not to this customer.
        if let Ok(out) = exec::run(&["du", "-sb", "--one-file-system", &path]) {
            if let Some(size) = out
                .stdout
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
            {
                total += size;
            }
        }
    }
    HelperResponse::with_stdout(format!("{total}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> PanelUsername {
        PanelUsername::parse("bp_site").unwrap()
    }

    fn app() -> AppName {
        AppName::parse("my-app").unwrap()
    }

    /// The four names, exactly as the bash spells them.
    #[test]
    fn the_names_match_what_is_already_on_disk() {
        let (u, a) = (user(), app());
        assert_eq!(unit_name(&u, &a), "snpanel-app-bp_site-my-app");
        assert_eq!(container_name(&u, &a), "snpanel-bp_site-my-app");
        assert_eq!(app_directory(&u, &a), "/home/bp_site/apps/my-app");
        assert_eq!(
            compose_file(&u, &a),
            "/var/lib/snpanel/apps/bp_site-my-app.compose.yml"
        );
    }

    /// An application name becomes a unit name, a Docker project name and a
    /// path, so the things it must not contain are the things those three
    /// would misread.
    #[test]
    fn an_app_name_is_narrow_on_purpose() {
        for good in [
            "a",
            "app",
            "my-app",
            "my_app_2",
            "a0",
            "x".repeat(32).as_str(),
        ] {
            assert!(AppName::parse(good).is_ok(), "{good:?} should be accepted");
        }
        for (bad, why) in [
            ("", "empty"),
            ("-app", "systemctl would read a leading dash as an option"),
            ("app-", "trailing separator"),
            ("_app", "leading separator"),
            ("My-App", "Docker refuses uppercase in a project name"),
            ("my app", "a space"),
            ("my/app", "a path separator"),
            ("../etc", "traversal"),
            ("my.app", "a dot is not in the set"),
            ("app;rm -rf /", "a semicolon"),
        ] {
            assert!(
                AppName::parse(bad).is_err(),
                "{bad:?} must be refused ({why})"
            );
        }
        assert!(
            AppName::parse(&"x".repeat(33)).is_err(),
            "33 characters is one too many"
        );
    }

    /// `control` refuses an application that has no unit rather than asking
    /// systemd about a name that does not exist.
    #[test]
    fn controlling_an_unknown_application_is_a_not_found() {
        let missing = AppName::parse("definitely-not-installed").unwrap();
        let resp = control(&user(), &missing, AppAction::Start);
        assert!(!resp.ok);
        let err = resp.error.expect("a reason");
        assert_eq!(err.kind, HelperErrorKind::NotFound);
        assert!(
            err.message
                .contains("snpanel-app-bp_site-definitely-not-installed"),
            "the message should name the unit: {}",
            err.message
        );
    }

    /// Every allowlisted action maps to the systemctl verb the bash uses, and
    /// there is no way to express one that is not on the list.
    #[test]
    fn the_eight_actions_are_the_only_ones_there_are() {
        use AppAction::*;
        assert_eq!(
            [Start, Stop, Restart, Status, IsActive, IsEnabled, Enable, Disable]
                .map(|a| a.as_str()),
            [
                "start",
                "stop",
                "restart",
                "status",
                "is-active",
                "is-enabled",
                "enable",
                "disable"
            ]
        );
    }
}
