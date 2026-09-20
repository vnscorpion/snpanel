//! `ops::packages` - installing the things SNPanel offers on demand.
//!
//! Source: the `pkg_*` layer and the `*-install` arms of the bash helper.
//!
//! Everything here is off until an administrator asks for it. A server that
//! hosts WordPress has no reason to carry ClamAV, a container runtime or a
//! certbot DNS plugin, so "not installed" is the normal state and every
//! install is a deliberate act with a visible result.
//!
//! The package manager is chosen from the platform, not guessed from what is
//! on `PATH`: a Debian box with `dnf` installed by accident must still use
//! apt, and a distribution that packages none of this should say so rather
//! than hand its package manager a name it will reject.

use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::Family;

use crate::exec;

/// The platform's family, or Debian when `/etc/os-release` cannot be read.
///
/// Defaulting matters less than not panicking: this runs as root on a box
/// whose identity is already established by the installer.
fn family() -> Family {
    snpanel_osabi::detect()
        .map(|p| p.family())
        .unwrap_or(Family::Debian)
}

/// Source: `pkg_update_index`.
fn update_index() -> std::io::Result<exec::Output> {
    match family() {
        Family::Rhel => exec::run(&["dnf", "-y", "makecache"]),
        _ => exec::run_with_env(
            &["apt-get", "update", "--allow-releaseinfo-change"],
            &[("DEBIAN_FRONTEND", "noninteractive")],
        ),
    }
}

/// Source: `pkg_install`.
fn install_packages(names: &[&str]) -> std::io::Result<exec::Output> {
    let mut argv: Vec<&str> = match family() {
        Family::Rhel => vec!["dnf", "-y", "install"],
        _ => vec!["apt-get", "install", "-y"],
    };
    argv.extend_from_slice(names);
    match family() {
        Family::Rhel => exec::run(&argv),
        _ => exec::run_with_env(&argv, &[("DEBIAN_FRONTEND", "noninteractive")]),
    }
}

/// Source: `dpkg -s <pkg> >/dev/null 2>&1`.
///
/// Only meaningful on Debian; on EL the caller asks dnf, which is idempotent
/// anyway. A missing `dpkg` answers "not installed" rather than failing, which
/// is what the bash's `2>&1` does with it.
fn dpkg_installed(names: &[&str]) -> bool {
    let mut argv: Vec<&str> = vec!["dpkg", "-s"];
    argv.extend_from_slice(names);
    matches!(exec::run(&argv), Ok(o) if o.ok())
}

/// Source: `deny_debian_only`.
///
/// "Refusing with the reason beats reaching apt-get and reporting 'command not
/// found', which reads like a broken PATH rather than a settled fact about the
/// distribution."
fn debian_only(what: &str) -> Option<HelperResponse> {
    if family() == Family::Debian {
        return None;
    }
    Some(HelperResponse::failed(
        HelperErrorKind::BadRequest,
        format!("{what} is only available on Debian and Ubuntu; this system is rhel"),
    ))
}

/// `certbot-dns-cloudflare-install`.
pub fn certbot_dns_cloudflare_install() -> HelperResponse {
    if dpkg_installed(&["python3-certbot-dns-cloudflare"]) {
        return HelperResponse::with_stdout(
            "certbot dns-cloudflare plugin already installed\n".to_string(),
        );
    }
    let mut out = String::new();
    if let Ok(o) = update_index() {
        out.push_str(&o.stdout);
    }
    match install_packages(&["python3-certbot-dns-cloudflare"]) {
        Ok(o) if o.ok() => {
            out.push_str(&o.stdout);
            out.push_str("certbot dns-cloudflare plugin installed\n");
            HelperResponse::with_stdout(out)
        }
        other => exec::respond("apt-get install python3-certbot-dns-cloudflare", other),
    }
}

/// `clamav-install`.
///
/// The `freshclam` run is deliberately fire-and-forget: it downloads a
/// signature database that takes minutes, and holding the request open for it
/// would time out the panel while the install itself succeeded.
pub fn clamav_install() -> HelperResponse {
    let mut out = String::new();
    if let Ok(o) = update_index() {
        out.push_str(&o.stdout);
    }
    if !dpkg_installed(&["clamav", "clamav-daemon"]) {
        match install_packages(&["clamav", "clamav-daemon"]) {
            Ok(o) if o.ok() => out.push_str(&o.stdout),
            other => return exec::respond("apt-get install clamav clamav-daemon", other),
        }
    }
    // `|| true` in the bash: the directory may already be there with the right
    // owner, and on a box where the package created it this is a no-op.
    let _ = std::fs::create_dir_all("/run/clamav");
    let enabled = exec::run(&["systemctl", "enable", "--now", "clamav-daemon"]);
    if !matches!(&enabled, Ok(o) if o.ok()) {
        return exec::respond("systemctl enable --now clamav-daemon", enabled);
    }
    let _ = exec::run(&["freshclam"]);
    out.push_str("ClamAV installed and clamav-daemon enabled.\n");
    HelperResponse::with_stdout(out)
}

/// `maldet-update-sigs`.
pub fn maldet_update_sigs(maldet_bin: &str) -> HelperResponse {
    if !is_executable(maldet_bin) {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "maldet is not installed".to_string(),
        );
    }
    // Both `|| true` in the bash: a signature refresh that fails is not a
    // failure of the request, and the panel reports what it could do.
    let mut out = String::new();
    if let Ok(o) = exec::run(&[maldet_bin, "-u", "--force"]) {
        out.push_str(&o.stdout);
        out.push_str(&o.stderr);
    }
    let _ = exec::run(&["freshclam"]);
    out.push_str("signatures updated\n");
    HelperResponse::with_stdout(out)
}

fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// `nginx-upgrade-map-ensure`.
///
/// "`map` only works at http level, so a proxied vhost needs this file to
/// exist before nginx will even load. The installer writes it too, but the
/// panel must not depend on the installer having run since the feature
/// shipped: without it the first proxy vhost fails `nginx -t` and gets rolled
/// back."
pub fn upgrade_map_ensure() -> HelperResponse {
    const TARGET: &str = "/etc/nginx/conf.d/00-snpanel-upgrade-map.conf";
    const BODY: &str = "map $http_upgrade $connection_upgrade {\n\
        \x20   default upgrade;\n\
        \x20   ''      close;\n\
        }\n";

    // `[[ -s "$target" ]] && return 0` - a *non-empty* file is left alone. An
    // empty one is rewritten, which is what recovers from a truncated write.
    let present = std::fs::metadata(TARGET)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if !present {
        if let Err(e) = std::fs::write(TARGET, BODY) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("writing {TARGET}: {e}"),
            );
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(TARGET, std::fs::Permissions::from_mode(0o644));
    }
    HelperResponse::with_stdout("websocket upgrade map present\n".to_string())
}

/// `updates-panel-run`.
///
/// The update is started as a **transient unit** and the request returns at
/// once. It replaces the panel's own code while the panel is serving, so a
/// request that waited for it would be killed by the restart it triggered and
/// the operator would see a failure where an update succeeded.
pub fn panel_update_run(update_script: &str) -> HelperResponse {
    const UNIT: &str = "snpanel-panel-update";
    if !std::path::Path::new(update_script).exists() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("missing {update_script}"),
        );
    }
    let active = exec::run(&[
        "systemctl",
        "is-active",
        "--quiet",
        &format!("{UNIT}.service"),
    ]);
    if matches!(&active, Ok(o) if o.ok()) {
        return HelperResponse::with_stdout(format!(
            "Panel update is already running: {UNIT}.service\n"
        ));
    }

    let env_of = |key: &str, default: &str| -> String {
        let value = std::env::var(key).unwrap_or_default();
        let value = if value.is_empty() { default } else { &value };
        format!("--property=Environment={key}={value}")
    };
    let source_dir = std::env::var("SOURCE_DIR").unwrap_or_else(|_| "/opt/snpanel-src".into());
    let app_dir = std::env::var("APP_DIR").unwrap_or_else(|_| "/opt/snpanel".into());
    let properties = vec![
        format!("--property=Environment=SOURCE_DIR={source_dir}"),
        format!("--property=Environment=APP_DIR={app_dir}"),
        env_of("REPO_URL", "https://github.com/vnscorpion/snpanel.git"),
        env_of("GIT_REMOTE", "origin"),
        env_of("UPDATE_CHANNEL", "release"),
        env_of("BRANCH", "main"),
        env_of("RELEASE_TAG", ""),
        env_of("RELEASE_PATTERN", "v[0-9]*.[0-9]*.[0-9]*"),
        env_of("SKIP_PULL", "false"),
    ];
    let unit_flag = format!("--unit={UNIT}");
    let mut argv: Vec<&str> = vec![
        "systemd-run",
        &unit_flag,
        "--collect",
        "--description=Update SNPanel from GitHub",
    ];
    argv.extend(properties.iter().map(String::as_str));
    argv.push("/bin/bash");
    argv.push(update_script);

    let started = exec::run(&argv);
    if !matches!(&started, Ok(o) if o.ok()) {
        return exec::respond("systemd-run snpanel-panel-update", started);
    }
    HelperResponse::with_stdout(format!(
        "Panel update started: {UNIT}.service\nCheck progress: journalctl -u {UNIT}.service -f\n"
    ))
}

/// Source: `require_node_major` - `^[1-9][0-9]$`, so exactly two digits and
/// not starting with zero.
///
/// It is a directory name under `/opt/snpanel/node` and half of a URL, which
/// is why it is checked rather than escaped.
fn valid_node_major(major: &str) -> bool {
    let b = major.as_bytes();
    b.len() == 2 && (b'1'..=b'9').contains(&b[0]) && b[1].is_ascii_digit()
}

/// `node-install`.
///
/// The Node tarball is unpacked beside the target and then moved into place,
/// so a download that dies half way leaves the previous version working. The
/// bash does the same with `<major>.tmp`, and the reason is worth keeping: an
/// application whose runtime disappeared mid-upgrade does not restart.
pub fn node_install(major: &str) -> HelperResponse {
    if !valid_node_major(major) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("invalid node major version: {major}"),
        );
    }
    if let Some(refusal) = debian_only("Node install") {
        return refusal;
    }
    let root = format!("/opt/snpanel/node/{major}");
    if is_executable(&format!("{root}/bin/node")) {
        return HelperResponse::with_stdout(format!("Node {major} is already installed\n"));
    }

    let arch = match exec::run(&["dpkg", "--print-architecture"]) {
        Ok(o) if o.ok() => match o.stdout.trim() {
            "amd64" => "x64",
            "arm64" => "arm64",
            _ => {
                return HelperResponse::failed(
                    HelperErrorKind::BadRequest,
                    "unsupported architecture for Node install".to_string(),
                )
            }
        },
        other => return exec::respond("dpkg --print-architecture", other),
    };

    // The bash pipes the release index through `python3`. Parsing it here is
    // what takes Python off the helper's dependency list.
    let index = match exec::run(&["curl", "-fsSL", "https://nodejs.org/dist/index.json"]) {
        Ok(o) if o.ok() => o.stdout,
        // `|| true` in the bash: a fetch that fails falls through to the
        // version check below, which is where the refusal is worded.
        _ => String::new(),
    };
    let latest = newest_release(&index, major).unwrap_or_default();
    if !looks_like_version(&latest) {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no Node {major} release found upstream"),
        );
    }

    let url = format!("https://nodejs.org/dist/{latest}/node-{latest}-linux-{arch}.tar.xz");
    let temp_dir = format!("/tmp/snpanel-node-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&temp_dir);
    if let Err(e) = std::fs::create_dir_all(&temp_dir) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {temp_dir}: {e}"),
        );
    }
    let tarball = format!("{temp_dir}/node.tar.xz");
    let fetched = exec::run(&["curl", "-fsSL", &url, "-o", &tarball]);
    if !matches!(&fetched, Ok(o) if o.ok()) {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            format!("cannot download {url}"),
        );
    }

    let staging = format!("/opt/snpanel/node/{major}.tmp");
    let _ = std::fs::create_dir_all("/opt/snpanel/node");
    let _ = std::fs::remove_dir_all(&staging);
    if let Err(e) = std::fs::create_dir_all(&staging) {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {staging}: {e}"),
        );
    }
    let untarred = exec::run(&[
        "tar",
        "-xJf",
        &tarball,
        "-C",
        &staging,
        "--strip-components=1",
    ]);
    let _ = std::fs::remove_dir_all(&temp_dir);
    if !matches!(&untarred, Ok(o) if o.ok()) {
        let _ = std::fs::remove_dir_all(&staging);
        return exec::respond("tar -xJf node.tar.xz", untarred);
    }

    let _ = std::fs::remove_dir_all(&root);
    if let Err(e) = std::fs::rename(&staging, &root) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("moving {staging} to {root}: {e}"),
        );
    }
    // `chown -R root:root` - the tarball carries whatever uid it was built
    // with, and a runtime a customer can rewrite is a runtime they can
    // backdoor.
    let _ = exec::run(&["chown", "-R", "root:root", &root]);

    HelperResponse::with_stdout(format!("Node {latest} installed to {root}\n"))
}

/// The first entry in `https://nodejs.org/dist/index.json` whose version
/// starts with `v<major>.`
///
/// Source: the inline `python3` the bash pipes the index through. The index is
/// newest-first, so "first match" is "newest of that line".
fn newest_release(index_json: &str, major: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(index_json).ok()?;
    let prefix = format!("v{major}.");
    parsed
        .as_array()?
        .iter()
        .filter_map(|item| item.get("version")?.as_str())
        .find(|version| version.starts_with(&prefix))
        .map(str::to_string)
}

/// `^v[0-9]+\.[0-9]+\.[0-9]+$`.
fn looks_like_version(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Node major is a directory name and half a URL, so it is checked
    /// rather than escaped.
    #[test]
    fn a_node_major_is_exactly_two_digits() {
        for good in ["10", "18", "20", "22", "99"] {
            assert!(valid_node_major(good), "{good}");
        }
        for bad in ["", "8", "080", "1", "100", "2.0", "v20", "20 ", "-1", "0a"] {
            assert!(!valid_node_major(bad), "{bad:?} should be refused");
        }
    }

    /// Picking a release out of the index, the way the bash's inline `python3`
    /// does: the first entry whose version starts with `v<major>.`.
    ///
    /// The index is newest-first, so "first match" is "newest of that line" -
    /// and matching on the dot is what stops `v2.x` from being offered for
    /// major 20.
    #[test]
    fn the_newest_release_of_a_line_is_chosen_and_the_dot_matters() {
        let index = r#"[
            {"version":"v23.1.0"},
            {"version":"v22.9.0"},
            {"version":"v22.8.0"},
            {"version":"v2.5.0"},
            {"version":"v20.18.0"}
        ]"#;
        assert_eq!(newest_release(index, "22").as_deref(), Some("v22.9.0"));
        assert_eq!(newest_release(index, "20").as_deref(), Some("v20.18.0"));
        assert_eq!(newest_release(index, "23").as_deref(), Some("v23.1.0"));
        // `v2.5.0` must not answer for major 25, nor `v23.1.0` for major 2.
        assert_eq!(newest_release(index, "25"), None);
        assert_eq!(newest_release(index, "21"), None);

        // A fetch that failed is an empty string, and that has to be a miss
        // rather than a panic - the bash's `|| true` leaves it empty too.
        assert_eq!(newest_release("", "22"), None);
        assert_eq!(newest_release("not json", "22"), None);
        assert_eq!(newest_release("{}", "22"), None);
    }

    /// `^v[0-9]+\.[0-9]+\.[0-9]+$` - the shape the bash insists on before it
    /// builds a download URL out of it.
    #[test]
    fn a_release_name_has_to_be_three_numbers() {
        for good in ["v1.2.3", "v22.9.0", "v20.18.100"] {
            assert!(looks_like_version(good), "{good}");
        }
        for bad in [
            "",
            "1.2.3",
            "v1.2",
            "v1.2.3.4",
            "v1.2.x",
            "vx.y.z",
            "v1..3",
            "v1.2.3-rc1",
        ] {
            assert!(!looks_like_version(bad), "{bad:?} should be refused");
        }
    }

    /// The upgrade map's body is what nginx needs before any proxied vhost
    /// will load, so it is compared against the bash's heredoc rather than
    /// described.
    #[test]
    fn the_upgrade_map_is_the_bash_helpers() {
        const BASH: &str = include_str!("../../../../installer/files/snpanel-helper.sh");
        let open = "<<'NGINX'\n";
        let start = BASH.find(open).expect("the heredoc opener") + open.len();
        let end = BASH[start..].find("NGINX\n").expect("the closer") + start;
        let want = &BASH[start..end];
        const BODY: &str = "map $http_upgrade $connection_upgrade {\n\
            \x20   default upgrade;\n\
            \x20   ''      close;\n\
            }\n";
        assert_eq!(BODY, want);
    }

    /// A non-empty file is left alone; an empty one is not.
    ///
    /// `[[ -s ]]` is the size test, not `-f`. Treating a truncated file as
    /// present would leave nginx refusing to load with a map it cannot parse.
    #[test]
    fn an_empty_upgrade_map_counts_as_absent() {
        let dir = std::env::temp_dir().join(format!("upmap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let f = dir.join("m.conf");

        let present =
            |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false);
        assert!(!present(&f), "missing is absent");
        std::fs::write(&f, "").expect("empty");
        assert!(!present(&f), "empty is absent");
        std::fs::write(&f, "map {}\n").expect("content");
        assert!(present(&f), "non-empty is present");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
