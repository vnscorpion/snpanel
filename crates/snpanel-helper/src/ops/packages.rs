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

use std::path::Path;

use snpanel_core::PhpVersion;
use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::Family;

use super::runtime::have;
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
pub(crate) fn update_index() -> std::io::Result<exec::Output> {
    match family() {
        Family::Rhel => exec::run(&["dnf", "-y", "makecache"]),
        _ => exec::run_with_env(
            &["apt-get", "update", "--allow-releaseinfo-change"],
            &[("DEBIAN_FRONTEND", "noninteractive")],
        ),
    }
}

/// Source: `pkg_install`.
pub(crate) fn install_packages(names: &[&str]) -> std::io::Result<exec::Output> {
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
pub(crate) fn dpkg_installed(names: &[&str]) -> bool {
    let mut argv: Vec<&str> = vec!["dpkg", "-s"];
    argv.extend_from_slice(names);
    matches!(exec::run(&argv), Ok(o) if o.ok())
}

/// Source: `deny_debian_only`.
///
/// "Refusing with the reason beats reaching apt-get and reporting 'command not
/// found', which reads like a broken PATH rather than a settled fact about the
/// distribution."
pub(crate) fn debian_only(what: &str) -> Option<HelperResponse> {
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

/// Source: `UPDATE_SCRIPT` in the bash helper.
///
/// Not the installer's `update.sh` in the source tree - the helper runs the
/// copy the installer put on `PATH`. Pinned by a test, because a constant
/// that looks right on its own and does not match what the rest of the system
/// uses fails as "missing ..." and never says why.
pub const UPDATE_SCRIPT: &str = "/usr/local/sbin/snpanel-update";

/// Source: `SOURCE_DIR` in the bash helper.
pub const SOURCE_DIR: &str = "/opt/snpanel-source";

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
    let source_dir = std::env::var("SOURCE_DIR").unwrap_or_else(|_| SOURCE_DIR.into());
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

// ---------------------------------------------------------------------------
// the malware scanners
// ---------------------------------------------------------------------------

/// Source: `MALDET_BIN`, `MALDET_HOME`, `MALWARE_JOBS_DIR`.
pub const MALDET_BIN: &str = "/usr/local/sbin/maldet";
pub const MALDET_HOME: &str = "/usr/local/maldetect";
pub const MALWARE_JOBS_DIR: &str = "/var/lib/snpanel/malware-scan-jobs";

/// Source: `MALWARE_SCAN_PRUNE`.
///
/// "Left out of a whole-server scan: kernel filesystems that are not files at
/// all, read-only squashfs images, package caches that are re-downloadable,
/// and the signature database itself. Scanning them costs hours and finds
/// nothing."
pub const SCAN_PRUNE: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    "/var/lib/lxcfs",
    "/var/lib/clamav",
    "/var/cache/apt/archives",
];

/// Source: `[[ "$job" =~ ^[0-9a-f]{8,64}$ ]]`.
///
/// The job id becomes a filename under a directory the panel reads, so it is
/// checked rather than escaped - and lowercase hex only, which cannot contain
/// a separator or a dot.
fn valid_job_id(job: &str) -> bool {
    (8..=64).contains(&job.len())
        && job
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Source: the `case "$resolved"` in `run_maldet_scan`.
///
/// A scan target is `/` or something under `/home`, and **nothing else**. The
/// path is resolved first, so a symlink cannot smuggle `/etc` in as
/// `/home/alice/link`.
fn scan_target(raw: &str) -> Result<Option<String>, String> {
    let resolved = readlink_m(std::path::Path::new(raw));
    let text = resolved.to_string_lossy().into_owned();
    if text == "/" {
        return Ok(Some(text));
    }
    if text == "/home" || text.starts_with("/home/") {
        // `[[ -d "$resolved" ]] && targets+=(...)` - a path under /home that
        // is not a directory is skipped, not refused. A customer removed
        // between the panel listing them and the scan starting is not an
        // error.
        return Ok(resolved.is_dir().then_some(text));
    }
    Err(format!("scan path must be / or under /home: {text}"))
}

/// `maldet-scan <job-id> <all|recent> <days> <path>...`
///
/// Foreground on purpose: `-b` daemonises and the helper would return before
/// the report exists. The panel already runs this call in a background job.
pub fn maldet_scan(job: &str, mode: &str, days: &str, paths: &[String]) -> HelperResponse {
    if !valid_job_id(job) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "invalid scan job id".to_string(),
        );
    }
    if mode != "all" && mode != "recent" {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "scan mode must be all|recent".to_string(),
        );
    }
    if days.is_empty() || days.len() > 4 || !days.bytes().all(|b| b.is_ascii_digit()) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "scan days must be an integer".to_string(),
        );
    }
    if !is_executable(MALDET_BIN) {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "maldet is not installed".to_string(),
        );
    }

    let mut targets: Vec<String> = Vec::new();
    for raw in paths {
        match scan_target(raw) {
            Ok(Some(target)) => targets.push(target),
            Ok(None) => {}
            Err(message) => return HelperResponse::failed(HelperErrorKind::BadRequest, message),
        }
    }
    if targets.is_empty() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "no valid scan path".to_string(),
        );
    }

    if let Err(e) = std::fs::create_dir_all(MALWARE_JOBS_DIR) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {MALWARE_JOBS_DIR}: {e}"),
        );
    }
    let out_path = format!("{MALWARE_JOBS_DIR}/{job}.maldet.out");
    let report_path = format!("{MALWARE_JOBS_DIR}/{job}.maldet.report");
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&report_path);

    // "A whole-machine scan skips the kernel/pkg-cache noise; a /home scan
    // does not need it. maldet takes one -co per override."
    let ignore = format!("scan_ignore={}", SCAN_PRUNE.join(","));
    let whole_machine = targets.iter().any(|t| t == "/");

    let mut argv: Vec<&str> = vec!["nice", "-n", "19", "ionice", "-c3", MALDET_BIN];
    if whole_machine {
        argv.push("-co");
        argv.push(&ignore);
    }
    if mode == "recent" {
        argv.push("-r");
        argv.push(&targets[0]);
        argv.push(days);
    } else {
        argv.push("-a");
        argv.extend(targets.iter().map(String::as_str));
    }

    let run = exec::run(&argv);
    let (stdout, code) = match run {
        Ok(o) => (format!("{}{}", o.stdout, o.stderr), o.status.unwrap_or(-1)),
        Err(e) => (format!("cannot run maldet: {e}\n"), -1),
    };
    let _ = std::fs::write(&out_path, &stdout);

    // `grep -oE '[0-9]{6}-[0-9]{4}\.[0-9]+' | head -n1`, then the session file
    // maldet left behind - the report body is that file, not `maldet -e`.
    let scanid = find_scan_id(&stdout).or_else(|| {
        std::fs::read_to_string(format!("{MALDET_HOME}/sess/session.last"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    });
    let mut report = String::new();
    if let Some(id) = &scanid {
        if let Ok(body) = std::fs::read_to_string(format!("{MALDET_HOME}/sess/session.{id}")) {
            report = body;
        }
    }
    let _ = std::fs::write(&report_path, &report);
    set_job_file_mode(&out_path);
    set_job_file_mode(&report_path);

    HelperResponse::with_stdout(format!(
        "scanid={}\nexit={code}\n",
        scanid.as_deref().unwrap_or("none")
    ))
}

/// `[0-9]{6}-[0-9]{4}\.[0-9]+`, first match.
fn find_scan_id(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let digits = |from: usize, n: usize| -> bool {
        from + n <= bytes.len() && bytes[from..from + n].iter().all(u8::is_ascii_digit)
    };
    for start in 0..bytes.len() {
        if !digits(start, 6) || bytes.get(start + 6) != Some(&b'-') || !digits(start + 7, 4) {
            continue;
        }
        if bytes.get(start + 11) != Some(&b'.') {
            continue;
        }
        let mut end = start + 12;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end == start + 12 {
            continue; // `[0-9]+` needs at least one.
        }
        return Some(text[start..end].to_string());
    }
    None
}

/// `chown snpanel:snpanel` and `chmod 0640` - the panel reads these while the
/// scan runs, and nobody else should.
fn set_job_file_mode(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
    let _ = exec::run(&["chown", "snpanel:snpanel", path]);
}

/// `malware-scan-server <job-id>` - the whole machine, through clamd.
pub fn malware_scan_server(job: &str) -> HelperResponse {
    if !valid_job_id(job) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "invalid scan job id".to_string(),
        );
    }
    if !have("clamdscan") {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "clamdscan is not installed".to_string(),
        );
    }
    let active = exec::run(&["systemctl", "is-active", "--quiet", "clamav-daemon"]);
    if !matches!(&active, Ok(o) if o.ok()) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "clamav-daemon is not running".to_string(),
        );
    }
    if let Err(e) = std::fs::create_dir_all(MALWARE_JOBS_DIR) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {MALWARE_JOBS_DIR}: {e}"),
        );
    }
    let list = format!("{MALWARE_JOBS_DIR}/{job}.files");
    let log = format!("{MALWARE_JOBS_DIR}/{job}.scan.log");
    let _ = std::fs::remove_file(&list);
    let _ = std::fs::remove_file(&log);

    // "One find over the machine, with the noise pruned. Ten seconds on a
    // normal VPS, and it buys an exact total so the panel can show real
    // progress."
    let mut find_argv: Vec<&str> = vec!["find", "/"];
    for path in SCAN_PRUNE {
        find_argv.push("-path");
        find_argv.push(path);
        find_argv.push("-prune");
        find_argv.push("-o");
    }
    find_argv.push("-type");
    find_argv.push("f");
    find_argv.push("-print");
    let files = match exec::run(&find_argv) {
        // `2>/dev/null` and no status check: `find` exits non-zero for a
        // directory it could not read, and that is not a failure of the scan.
        Ok(o) => o.stdout,
        Err(e) => {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("cannot list files to scan: {e}"),
            )
        }
    };
    let total = files.lines().count();
    if let Err(e) = std::fs::write(&list, &files) {
        return HelperResponse::failed(HelperErrorKind::Internal, format!("writing {list}: {e}"));
    }
    // "The panel reads its progress out of this file while the scan runs, so
    // the total has to be in there rather than only in the exit output."
    let _ = std::fs::write(&log, format!("total={total}\n"));
    set_job_file_mode(&list);
    set_job_file_mode(&log);

    // `--fdpass` hands clamd an open descriptor, which is the only way it
    // reads files its own user cannot. Niced hard: a scan must never be the
    // reason a website goes slow.
    let file_list = format!("--file-list={list}");
    let scanned = exec::run(&[
        "nice",
        "-n",
        "19",
        "ionice",
        "-c3",
        "clamdscan",
        "--fdpass",
        "--stdout",
        "--no-summary",
        &file_list,
    ]);
    let code = match &scanned {
        Ok(o) => {
            // `>>"$log"` - appended after the total line.
            let mut body = std::fs::read_to_string(&log).unwrap_or_default();
            body.push_str(&o.stdout);
            body.push_str(&o.stderr);
            let _ = std::fs::write(&log, body);
            o.status.unwrap_or(-1)
        }
        Err(_) => -1,
    };
    let _ = std::fs::remove_file(&list);

    HelperResponse::with_stdout(format!("total={total}\nexit={code}\n"))
}

/// `readlink -m` - resolve what exists, normalise the rest, never fail.
///
/// The `-m` is what makes it safe to use on a path that may not be there: the
/// check that follows is about where the path *points*, and a target that
/// does not exist yet still has a location.
fn readlink_m(path: &std::path::Path) -> std::path::PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    // Walk up to the deepest ancestor that does exist, resolve that, and
    // re-apply the rest lexically - dropping `.` and popping on `..`.
    let mut prefix = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !prefix.as_os_str().is_empty() {
        if let Ok(real) = std::fs::canonicalize(&prefix) {
            let mut out = real;
            for part in tail.iter().rev() {
                if part == ".." {
                    out.pop();
                } else if part != "." {
                    out.push(part);
                }
            }
            return out;
        }
        match prefix.file_name() {
            Some(name) => tail.push(name.to_os_string()),
            None => break,
        }
        if !prefix.pop() {
            break;
        }
    }
    // Nothing on the way up exists: normalise what we were given.
    let mut out = std::path::PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Source: `write_docker_daemon_config`.
///
/// "Log rotation is not optional on a shared host: an unbounded container log
/// fills the disk and takes every other site down with it." The other three
/// settings are the same kind of decision - `no-new-privileges` on by default,
/// and an address pool that does not collide with the ranges a customer's own
/// network is likely to use.
const DOCKER_DAEMON_JSON: &str = "{\n\
    \x20 \"log-driver\": \"json-file\",\n\
    \x20 \"log-opts\": { \"max-size\": \"10m\", \"max-file\": \"3\" },\n\
    \x20 \"live-restore\": true,\n\
    \x20 \"no-new-privileges\": true,\n\
    \x20 \"default-address-pool\": [ { \"base\": \"172.31.0.0/16\", \"size\": 24 } ]\n\
    }\n";

fn write_docker_daemon_config() -> std::io::Result<()> {
    std::fs::create_dir_all("/etc/docker")?;
    std::fs::write("/etc/docker/daemon.json", DOCKER_DAEMON_JSON)
}

/// Source: `install_docker_firewall_guard`.
///
/// "Docker publishes ports by DNAT in PREROUTING and allows them through its
/// own FORWARD chain, so a published port never passes through SNPANEL-INPUT.
/// Panel apps only ever publish on loopback, but a container started by hand
/// could publish on 0.0.0.0 and be reachable while the firewall looks
/// enabled. DOCKER-USER is the one chain Docker leaves to the operator."
///
/// Every step is best effort and the function returns quietly when iptables or
/// docker is absent - the guard is protection, and failing the install because
/// it could not be applied would leave the operator with neither.
///
/// The two inserts are in reverse order on purpose: each goes in at position
/// 1, so the *last* one inserted ends up first. The conntrack RETURN has to be
/// evaluated before the DROP or every established connection dies.
fn install_docker_firewall_guard() {
    if !have("iptables") || !have("docker") {
        return;
    }
    let Some(iface) = default_interface() else {
        return;
    };

    let _ = exec::run(&["iptables", "-w", "-N", "DOCKER-USER"]);
    // Remove any copy this run is about to replace, so re-running does not
    // stack duplicates.
    let _ = exec::run(&[
        "iptables",
        "-w",
        "-D",
        "DOCKER-USER",
        "-i",
        &iface,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "RETURN",
    ]);
    let _ = exec::run(&[
        "iptables",
        "-w",
        "-D",
        "DOCKER-USER",
        "-i",
        &iface,
        "-j",
        "DROP",
    ]);
    let _ = exec::run(&[
        "iptables",
        "-w",
        "-I",
        "DOCKER-USER",
        "1",
        "-i",
        &iface,
        "-j",
        "DROP",
    ]);
    let _ = exec::run(&[
        "iptables",
        "-w",
        "-I",
        "DOCKER-USER",
        "1",
        "-i",
        &iface,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "RETURN",
    ]);
}

/// `ip route show default | awk '/^default/{print $5; exit}'` - the fifth
/// field of the first default route, which is the interface name.
fn default_interface() -> Option<String> {
    let out = exec::run(&["ip", "route", "show", "default"]).ok()?;
    out.stdout
        .lines()
        .find(|line| line.starts_with("default"))
        .and_then(|line| line.split_whitespace().nth(4))
        .map(str::to_string)
}

/// `docker-install`.
pub fn docker_install() -> HelperResponse {
    if have("docker") {
        if let Err(e) = write_docker_daemon_config() {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("writing /etc/docker/daemon.json: {e}"),
            );
        }
        let _ = exec::run(&["systemctl", "restart", "docker"]);
        install_docker_firewall_guard();
        return HelperResponse::with_stdout("Docker is already installed\n".to_string());
    }
    if let Some(refusal) = debian_only("Docker install") {
        return refusal;
    }

    // `. /etc/os-release` in the bash. `OsRelease` keeps only the fields the
    // platform table needs, and the codename is not one of them, so this
    // reads the file for both rather than taking `ID` from one place and the
    // codename from another.
    let os = os_release_fields();
    let distro = match os_field(&os, "ID").as_str() {
        "ubuntu" => "ubuntu",
        "debian" => "debian",
        other => {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!(
                    "unsupported distribution for Docker install: {}",
                    if other.is_empty() { "unknown" } else { other }
                ),
            )
        }
    };
    let codename = os_field(&os, "VERSION_CODENAME");
    if codename.is_empty() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "cannot determine distribution codename".to_string(),
        );
    }
    let arch = match exec::run(&["dpkg", "--print-architecture"]) {
        Ok(o) if o.ok() => o.stdout.trim().to_string(),
        other => return exec::respond("dpkg --print-architecture", other),
    };

    let mut out = String::new();
    if let Ok(o) = update_index() {
        out.push_str(&o.stdout);
    }
    match install_packages(&["ca-certificates", "curl", "gnupg"]) {
        Ok(o) if o.ok() => out.push_str(&o.stdout),
        other => return exec::respond("apt-get install ca-certificates curl gnupg", other),
    }

    let _ = std::fs::create_dir_all("/etc/apt/keyrings");
    let key_url = format!("https://download.docker.com/linux/{distro}/gpg");
    let fetched = exec::run(&[
        "curl",
        "-fsSL",
        &key_url,
        "-o",
        "/etc/apt/keyrings/docker.asc",
    ]);
    if !matches!(&fetched, Ok(o) if o.ok()) {
        return exec::respond("curl docker gpg key", fetched);
    }
    // `chmod a+r` - apt runs the fetch as root and reads it as _apt.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(
        "/etc/apt/keyrings/docker.asc",
        std::fs::Permissions::from_mode(0o644),
    );

    let source = format!(
        "deb [arch={arch} signed-by=/etc/apt/keyrings/docker.asc] \
         https://download.docker.com/linux/{distro} {codename} stable\n"
    );
    if let Err(e) = std::fs::write("/etc/apt/sources.list.d/docker.list", source) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing /etc/apt/sources.list.d/docker.list: {e}"),
        );
    }
    if let Ok(o) = update_index() {
        out.push_str(&o.stdout);
    }
    match install_packages(&[
        "docker-ce",
        "docker-ce-cli",
        "containerd.io",
        "docker-buildx-plugin",
        "docker-compose-plugin",
    ]) {
        Ok(o) if o.ok() => out.push_str(&o.stdout),
        other => return exec::respond("apt-get install docker-ce", other),
    }

    if let Err(e) = write_docker_daemon_config() {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing /etc/docker/daemon.json: {e}"),
        );
    }
    let enabled = exec::run(&["systemctl", "enable", "--now", "docker"]);
    if !matches!(&enabled, Ok(o) if o.ok()) {
        return exec::respond("systemctl enable --now docker", enabled);
    }
    install_docker_firewall_guard();
    out.push_str("Docker installed\n");
    HelperResponse::with_stdout(out)
}

/// `/etc/os-release` as `KEY=value` pairs, quotes stripped.
///
/// Source: `. /etc/os-release`, which the bash sources for `ID` and
/// `VERSION_CODENAME`.
fn os_release_fields() -> Vec<(String, String)> {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_string(),
                value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            ))
        })
        .collect()
}

fn os_field(fields: &[(String, String)], key: &str) -> String {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// installing the scanner, and the real-time monitor
// ---------------------------------------------------------------------------

/// Source: `MALDET_CONF`, `MALDET_TARBALL_URL`.
const MALDET_CONF: &str = "/usr/local/maldetect/conf.maldet";
const MALDET_TARBALL_URL: &str = "https://www.rfxn.com/downloads/maldetect-current.tar.gz";
const MONITOR_PID_FILE: &str = "/usr/local/maldetect/tmp/inotifywait.pid";

/// Source: the `kv` list in `maldet_write_conf`.
///
/// "Panel-owned settings on top of whatever the rfxn installer shipped. The
/// panel drives scheduling and never auto-quarantines, so its cron is off."
///
/// The three `quarantine_*` zeros are the ones worth reading twice. A scanner
/// that moves a customer's file out from under their running site, on a match
/// it decided by itself, breaks the site; one that reports and waits does not.
const MALDET_SETTINGS: &[(&str, &str)] = &[
    ("quarantine_hits", "0"),
    ("quarantine_clean", "0"),
    ("quarantine_suspend_user", "0"),
    ("scan_clamscan", "1"),
    ("scan_ignore_root", "0"),
    ("scan_find_h10k_alert", "0"),
    ("autoupdate_signatures", "1"),
    ("autoupdate_version", "1"),
    ("cron_daily_scan", "0"),
    ("email_alert", "0"),
    ("default_monitor_mode", "users"),
];

/// Source: `maldet_write_conf`.
///
/// `sed -i -E "s#^${key}=.*#${key}=\"${val}\"#"` has no line range, so it
/// rewrites **every** matching line, not just the first - a config that ended
/// up with the same key twice comes out with both copies agreeing.
pub(crate) fn maldet_write_conf(conf: &std::path::Path, cron_daily: &std::path::Path) {
    // `[[ -f "$MALDET_CONF" ]] || return 0` - nothing to tune before the rfxn
    // installer has written its own config.
    let Ok(text) = std::fs::read_to_string(conf) else {
        return;
    };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    for (key, value) in MALDET_SETTINGS {
        let prefix = format!("{key}=");
        let replacement = format!("{key}=\"{value}\"");
        let mut found = false;
        for line in lines.iter_mut() {
            if line.starts_with(&prefix) {
                *line = replacement.clone();
                found = true;
            }
        }
        if !found {
            lines.push(replacement);
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    let _ = std::fs::write(conf, out);

    // `[[ -f ... ]] && chmod a-x` - the panel owns the schedule, so the
    // installer's daily cron is disarmed rather than deleted: an admin who
    // looks for it still finds it, and it cannot fire.
    if cron_daily.is_file() {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(cron_daily) {
            let mode = meta.permissions().mode() & !0o111;
            let _ = std::fs::set_permissions(cron_daily, std::fs::Permissions::from_mode(mode));
        }
    }
}

/// `maldet-install`.
///
/// "clamscan is the scan engine; the resident daemon is deliberately not
/// enabled - maldet runs clamscan one-shot so the ~1.3GB of signatures are
/// only resident during a scan."
///
/// The bash runs under `set -euo pipefail`, so the package steps that are not
/// written `|| true` are failures, not warnings. They are failures here too.
pub fn maldet_install() -> HelperResponse {
    let mut out = String::new();

    if !have("clamscan") {
        match update_index() {
            Ok(o) if o.ok() => out.push_str(&o.stdout),
            other => return install_step_failed("refreshing the package index", other),
        }
        match install_packages(&["clamav"]) {
            Ok(o) if o.ok() => out.push_str(&o.stdout),
            _ => {
                return HelperResponse::failed(
                    HelperErrorKind::CommandFailed,
                    "could not install the clamav package (scan engine)".to_string(),
                )
            }
        }
    }
    // `freshclam >/dev/null 2>&1 || true` - an initial signature refresh; a
    // box behind a proxy that cannot reach the mirrors still gets a working
    // install, and the panel has an update button for later.
    let _ = exec::run(&["freshclam"]);

    if !have("wget") && !have("curl") {
        match install_packages(&["wget"]) {
            Ok(o) if o.ok() => out.push_str(&o.stdout),
            other => return install_step_failed("installing wget", other),
        }
    }
    // "inotifywait is what maldet's Level 2 monitor runs; Debian does not ship
    // it." `|| true`: the monitor is optional, so its absence is not a reason
    // to fail the install.
    if !have("inotifywait") {
        let _ = install_packages(&["inotify-tools"]);
    }

    if !is_executable(MALDET_BIN) {
        if let Err(response) = fetch_and_run_lmd_installer(&mut out) {
            return response;
        }
    }
    if !is_executable(MALDET_BIN) {
        return HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "maldet is still not present after install".to_string(),
        );
    }

    maldet_write_conf(
        std::path::Path::new(MALDET_CONF),
        std::path::Path::new("/etc/cron.daily/maldet"),
    );
    // "The rfxn installer enables maldet.service (the inotify monitor).
    // SNPanel owns Level 2: keep it off until the admin turns it on."
    let _ = exec::run(&["systemctl", "disable", "--now", "maldet"]);
    let _ = exec::run(&[MALDET_BIN, "-u", "--force"]);

    out.push_str(&format!(
        "LMD installed at {MALDET_HOME}; ClamAV engine present (daemon not enabled).\n"
    ));
    HelperResponse::with_stdout(out)
}

/// The message `set -e` never gets to print.
///
/// When one of these steps fails the bash simply dies, so all the caller sees
/// is apt's stderr on the helper's own stderr and a non-zero status. Carrying
/// that text into the refusal keeps the reason visible in the panel instead of
/// in a journal the administrator cannot read from a web page.
fn install_step_failed(what: &str, result: std::io::Result<exec::Output>) -> HelperResponse {
    let detail = match result {
        Ok(o) => {
            let text = if o.stderr.trim().is_empty() {
                o.stdout
            } else {
                o.stderr
            };
            text.trim().to_string()
        }
        Err(e) => e.to_string(),
    };
    HelperResponse::failed(
        HelperErrorKind::CommandFailed,
        if detail.is_empty() {
            format!("{what} failed")
        } else {
            format!("{what} failed: {detail}")
        },
    )
}

/// Download the LMD tarball, check it, unpack it, run the installer inside it.
///
/// Every failure removes the temporary directory first - the bash writes
/// `{ rm -rf "$tmp"; deny ...; }` on each one, and a half-unpacked archive
/// left behind would be read by the next attempt as a good one.
fn fetch_and_run_lmd_installer(out: &mut String) -> Result<(), HelperResponse> {
    // `mktemp -d /tmp/snpanel-maldet.XXXXXX`, and asked of mktemp rather than
    // built from a pid: a name an attacker can predict is a name they can
    // pre-create as a symlink into a directory this then unpacks a
    // root-executed installer into.
    let temp = match exec::run(&["mktemp", "-d", "/tmp/snpanel-maldet.XXXXXX"]) {
        Ok(o) if o.ok() && !o.stdout.trim().is_empty() => o.stdout.trim().to_string(),
        _ => {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                "could not create a temporary directory".to_string(),
            ))
        }
    };
    let cleanup = |response: HelperResponse| -> Result<(), HelperResponse> {
        let _ = std::fs::remove_dir_all(&temp);
        Err(response)
    };
    let tarball = format!("{temp}/maldetect.tar.gz");

    let fetched = if have("wget") {
        exec::run(&[
            "wget",
            "-q",
            "--timeout=30",
            "-O",
            &tarball,
            MALDET_TARBALL_URL,
        ])
    } else {
        exec::run(&[
            "curl",
            "-fsSL",
            "--connect-timeout",
            "15",
            "--max-time",
            "120",
            MALDET_TARBALL_URL,
            "-o",
            &tarball,
        ])
    };
    if !matches!(&fetched, Ok(o) if o.ok()) {
        return cleanup(HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "could not download LMD from rfxn.com (offline? use the panel button later)"
                .to_string(),
        ));
    }

    // "Asked of gzip, not of `file`: Debian's minimal install ships no `file`,
    // and an absent command reads exactly like a corrupt download. gzip is
    // already a hard requirement here - `tar -xzf` on the next line needs it -
    // and `gzip -t` checks the whole archive's CRC, not just two magic bytes."
    if !matches!(exec::run(&["gzip", "-t", &tarball]), Ok(o) if o.ok()) {
        let bytes = std::fs::metadata(&tarball).map(|m| m.len()).unwrap_or(0);
        return cleanup(HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            format!(
                "the LMD download is not a valid gzip archive (rfxn.com returned {bytes} bytes)"
            ),
        ));
    }
    if !matches!(exec::run(&["tar", "-xzf", &tarball, "-C", &temp]), Ok(o) if o.ok()) {
        return cleanup(HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "could not unpack the LMD archive".to_string(),
        ));
    }

    // `find "$tmp" -maxdepth 1 -type d -name 'maldetect-*' | head -n1`, then
    // `[[ -n "$srcdir" && -x "$srcdir/install.sh" ]]`.
    let Some(srcdir) = lmd_source_dir(std::path::Path::new(&temp)) else {
        return cleanup(HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "LMD archive layout not recognised".to_string(),
        ));
    };

    // `( cd "$srcdir" && ./install.sh )`. The installer reads its own files by
    // relative path, so it has to run from inside its directory.
    match exec::run_in_dir(&["./install.sh"], &srcdir) {
        Ok(o) if o.ok() => out.push_str(&o.stdout),
        _ => {
            return cleanup(HelperResponse::failed(
                HelperErrorKind::CommandFailed,
                "the LMD installer failed".to_string(),
            ))
        }
    }

    let _ = std::fs::remove_dir_all(&temp);
    Ok(())
}

/// The unpacked `maldetect-*` directory, if it is there and carries an
/// executable installer.
///
/// `find | head -n1` takes whatever the filesystem hands back first; sorting
/// makes the choice the same on every run. The archive contains exactly one
/// such directory, so the two agree in practice - this only decides which one
/// wins in a temporary directory that somehow held two.
fn lmd_source_dir(temp: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(temp)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("maldetect-"))
                    .unwrap_or(false)
        })
        .collect();
    candidates.sort();
    candidates
        .into_iter()
        .find(|dir| is_executable(&dir.join("install.sh").to_string_lossy()))
}

/// Source: `maldet_monitor_running`.
///
/// The pid file first, then `pgrep` - and the pid file alone is not enough,
/// because a killed monitor leaves it behind and it would then read as
/// running for as long as nobody cleaned up.
pub(crate) fn maldet_monitor_running() -> bool {
    if let Ok(text) = std::fs::read_to_string(MONITOR_PID_FILE) {
        let pid = text.trim();
        // `[[ -n "$pid" ]] && kill -0 "$pid"` - a signal of 0 asks whether the
        // process exists and is ours to signal, and sends nothing.
        if let Ok(pid) = pid.parse::<i32>() {
            if pid > 0 && unsafe { libc::kill(pid, 0) } == 0 {
                return true;
            }
        }
    }
    // "Fallback: any inotifywait watching /home is maldet's monitor."
    matches!(
        exec::run(&["pgrep", "-f", "inotifywait.*(/home|maldet)"]),
        Ok(o) if o.ok()
    )
}

/// Source: `write_inotify_sysctl`.
///
/// The kernel default of 8192 watches runs out part-way through a box with a
/// few hundred sites, and the monitor then watches a prefix of the filesystem
/// while still reporting that it started - which is worse than not running.
const INOTIFY_SYSCTL: &str = "/etc/sysctl.d/60-snpanel-inotify.conf";
const INOTIFY_SYSCTL_BODY: &str = "\
# Raised by SNPanel so the LMD real-time monitor can watch every site file.
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 1024
";

fn write_inotify_sysctl() {
    let _ = std::fs::write(INOTIFY_SYSCTL, INOTIFY_SYSCTL_BODY);
    let _ = exec::run(&["sysctl", "--system"]);
}

/// The two commands LMD's monitor mode shells out to.
///
/// "It exits 0 when one is missing, so systemd reports a bare protocol failure
/// and the real reason never surfaces - hence installing them here rather than
/// letting the start fail and guessing afterwards. `ed` is absent from a
/// minimal Debian."
const MONITOR_DEPS: &[(&str, &str)] = &[("inotifywait", "inotify-tools"), ("ed", "ed")];

/// `maldet-monitor <start|stop|status>`.
pub fn maldet_monitor(action: &str) -> HelperResponse {
    if !is_executable(MALDET_BIN) {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "maldet is not installed".to_string(),
        );
    }
    match action {
        "start" => monitor_start(),
        "stop" => monitor_stop(),
        "status" => HelperResponse::with_stdout(format!(
            "running={}\nwatches={}\n",
            u8::from(maldet_monitor_running()),
            max_user_watches()
        )),
        _ => HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "usage: maldet-monitor <start|stop|status>".to_string(),
        ),
    }
}

/// `cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo 0`.
fn max_user_watches() -> String {
    std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
        .map(|t| t.trim().to_string())
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "0".to_string())
}

fn monitor_start() -> HelperResponse {
    for (command, package) in MONITOR_DEPS {
        if have(command) {
            continue;
        }
        let _ = install_packages(&[package]);
        if !have(command) {
            return HelperResponse::failed(
                HelperErrorKind::CommandFailed,
                format!(
                    "real-time protection needs {command} (package {package}), \
                     which could not be installed"
                ),
            );
        }
    }
    write_inotify_sysctl();
    // `grep -qE '^default_monitor_mode=' || printf ... >>` - the monitor has
    // nothing to watch without it and exits straight away.
    if let Ok(text) = std::fs::read_to_string(MALDET_CONF) {
        if !text.lines().any(|l| l.starts_with("default_monitor_mode=")) {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(MALDET_CONF) {
                let _ = f.write_all(b"default_monitor_mode=\"users\"\n");
            }
        }
    }

    // "Run the monitor through maldet.service: its children stay in the unit's
    // cgroup, so `systemctl stop` cleans them all up. A bare `maldet -b -m`
    // daemonises outside systemd and orphans its inotifywait."
    let _ = exec::run(&["systemctl", "enable", "maldet"]);
    let _ = exec::run(&["systemctl", "restart", "maldet"]);
    // `for _ in 1..10; do maldet_monitor_running && break; sleep 1; done` -
    // ten checks with a sleep between all but the first.
    for attempt in 0..10 {
        if maldet_monitor_running() {
            return HelperResponse::with_stdout("monitor started\n".to_string());
        }
        let _ = attempt;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if maldet_monitor_running() {
        return HelperResponse::with_stdout("monitor started\n".to_string());
    }
    // "Carry maldet's own sentence out to the panel. 'monitor did not start'
    // on its own sent this into a journal-reading session that the
    // administrator cannot perform from the web interface."
    let why = exec::run(&["journalctl", "-u", "maldet", "--no-pager", "-n", "20"])
        .ok()
        .map(|o| last_mon_message(&o.stdout))
        .unwrap_or_default();
    HelperResponse::failed(
        HelperErrorKind::CommandFailed,
        if why.is_empty() {
            "monitor did not start".to_string()
        } else {
            format!("monitor did not start: {why}")
        },
    )
}

/// `sed -n 's/.*{mon} //p' | tail -n 1`.
///
/// `.*` is greedy, so a line carrying the marker twice keeps what follows the
/// **last** one; `tail -n 1` then keeps the newest line that had it at all.
fn last_mon_message(journal: &str) -> String {
    journal
        .lines()
        .filter_map(|line| {
            line.rfind("{mon} ")
                .map(|i| line[i + "{mon} ".len()..].to_string())
        })
        .next_back()
        .unwrap_or_default()
}

fn monitor_stop() -> HelperResponse {
    let _ = exec::run(&["systemctl", "disable", "--now", "maldet"]);
    let _ = exec::run(&["systemctl", "reset-failed", "maldet"]);
    let _ = exec::run(&[MALDET_BIN, "--kill-monitor"]);
    // "Kill the supervisor first (it respawns inotifywait), then the watcher."
    let _ = exec::run(&["pkill", "-f", "maldet .*--monitor"]);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let _ = exec::run(&["pkill", "-f", "inotifywait .*maldetect/sess/inotify"]);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let _ = exec::run(&["pkill", "-9", "-f", "inotifywait .*maldetect/sess/inotify"]);
    let _ = std::fs::remove_file(MONITOR_PID_FILE);
    if maldet_monitor_running() {
        return HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "monitor still running after stop".to_string(),
        );
    }
    HelperResponse::with_stdout("monitor stopped\n".to_string())
}

/// `maldet-status`.
///
/// Four `key=value` lines, because that is what reads them: `_KV_RE` in
/// `backend/app/services/maldet.py` is `^([a-z_]+)=(.*)$`, applied line by
/// line. Anything else - including well-formed JSON - matches nothing, and
/// `status()` then reports a scanner that is installed, with a monitor that is
/// running, as neither.
pub fn maldet_status() -> HelperResponse {
    let sig_file = format!("{MALDET_HOME}/sigs/maldet.sigs.ver");
    HelperResponse::with_stdout(status_lines(
        is_executable(MALDET_BIN),
        maldet_monitor_running(),
        std::path::Path::new(&sig_file),
    ))
}

/// The four lines, split out from the two probes so a test can drive it.
fn status_lines(installed: bool, monitor: bool, sig_path: &std::path::Path) -> String {
    let mut out = String::new();
    out.push_str(&format!("installed={}\n", u8::from(installed)));
    out.push_str(&format!("monitor={}\n", u8::from(monitor)));

    if sig_path.is_file() {
        // `$(cat ...)` strips trailing newlines; `|| echo unknown` covers a
        // file that exists but cannot be read.
        let version = std::fs::read_to_string(sig_path)
            .map(|t| t.trim_end_matches('\n').to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        out.push_str(&format!("sig_version={version}\n"));
        let updated = std::fs::metadata(sig_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| format_utc(d.as_secs() as i64))
            .unwrap_or_default();
        out.push_str(&format!("sig_updated={updated}\n"));
    } else {
        out.push_str("sig_version=unknown\n");
        out.push_str("sig_updated=\n");
    }
    out
}

/// `date -u -r <file> +%Y-%m-%dT%H:%M:%SZ`, without the fork.
///
/// Civil date from a day count, by Howard Hinnant's algorithm: shifting the
/// year to start in March puts the leap day at the end of a 400-year era, so
/// every month length collapses into one formula and there is no table to get
/// wrong. The test compares it against GNU `date` over a corpus that includes
/// both sides of every century boundary and each leap-year rule.
pub(crate) fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// ---------------------------------------------------------------------------
// installing a PHP version
// ---------------------------------------------------------------------------

/// Source: `php_versions_installable` - the versions the panel offers.
const OFFERED_PHP_VERSIONS: &[&str] = &["5.6", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"];

/// Source: the `packages` array in `install_php_version`.
///
/// `-fpm` and `-cli` are the version; the rest are the extension set the
/// panel's application templates assume. Each is checked separately below,
/// because one name missing from a repository must skip that extension rather
/// than fail the whole transaction.
const PHP_EXTENSIONS: &[&str] = &[
    "fpm", "cli", "mysql", "sqlite3", "curl", "gd", "mbstring", "xml", "zip", "opcache", "intl",
    "bcmath", "redis", "imagick",
];

/// Source: `apt_installable`.
///
/// "Not `apt-cache show`: that succeeds for a name the archive merely
/// references. On Ubuntu 26.04 it says yes to php7.4-fpm, which has no
/// installable version - so a refusal built on it told the user 7.4 was
/// available on a release that has no such package."
fn apt_installable(package: &str) -> bool {
    let Ok(o) = exec::run(&["apt-cache", "policy", package]) else {
        return false;
    };
    candidate_version(&o.stdout).is_some()
}

/// `sed -n 's/^  Candidate: //p'`, then `-n "$c" && "$c" != "(none)"`.
///
/// Two leading spaces exactly: `apt-cache policy` indents the candidate line
/// that much, and a looser match would also take the `Candidate:` inside a
/// version table where it means something else.
pub(crate) fn candidate_version(policy: &str) -> Option<&str> {
    policy
        .lines()
        .find_map(|l| l.strip_prefix("  Candidate: "))
        .filter(|c| !c.is_empty() && *c != "(none)")
}

/// Source: `php_versions_installable` - "used to make a refusal useful rather
/// than just a refusal."
fn installable_versions() -> String {
    let mut out = Vec::new();
    for v in OFFERED_PHP_VERSIONS {
        if apt_installable(&format!("php{v}-fpm")) {
            out.push(*v);
        }
    }
    out.join(" ")
}

/// Source: `ondrej_ppa_publishes_this_release`.
///
/// Asked before the repository is added, not after. A PPA that publishes
/// nothing for this release still adds cleanly and still fails `apt-get
/// update` afterwards - at which point the box is left carrying a broken
/// source list because of a version the panel could never have installed.
fn ondrej_publishes_this_release() -> bool {
    let Some(codename) = os_release_field("VERSION_CODENAME") else {
        return false;
    };
    if codename.is_empty() {
        return false;
    }
    let url =
        format!("https://ppa.launchpadcontent.net/ondrej/php/ubuntu/dists/{codename}/Release");
    matches!(
        exec::run(&["curl", "-fsI", "--max-time", "20", &url]),
        Ok(o) if o.ok()
    )
}

/// `. /etc/os-release && printf '%s' "${FIELD:-}"`.
pub(crate) fn os_release_field(key: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    parse_os_release_field(&text, key)
}

/// The value for `key`, with one layer of quotes removed.
pub(crate) fn parse_os_release_field(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let raw = text.lines().rev().find_map(|l| l.strip_prefix(&prefix))?;
    let raw = raw.trim();
    let unquoted = if (raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2)
        || (raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2)
    {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    Some(unquoted.to_string())
}

/// Is the ondrej PPA already configured here?
///
/// "`.sources` as well as `.list`: add-apt-repository writes deb822 on
/// current Ubuntu, so a check that reads only `*.list` never sees its own
/// work and adds the repository again on every attempt."
fn ondrej_ppa_configured() -> bool {
    if std::fs::read_to_string("/etc/apt/sources.list")
        .map(|t| t.contains("ondrej/php"))
        .unwrap_or(false)
    {
        return true;
    }
    let Ok(entries) = std::fs::read_dir("/etc/apt/sources.list.d") else {
        return false;
    };
    entries.flatten().any(|e| {
        std::fs::read_to_string(e.path())
            .map(|t| t.contains("ondrej/php"))
            .unwrap_or(false)
    })
}

/// `php-install <version>`.
pub fn php_install(version: PhpVersion) -> HelperResponse {
    let v = version.dotted();

    // "Adding a version here would need both [the Remi package names and the
    // layout shim], and doing only the first is worse than refusing: the
    // packages would install, the panel would list the version, and every
    // tuning action against it would fail on a path that does not exist."
    if family() == Family::Rhel {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "installing additional PHP versions from the panel is not supported on rhel yet; \
             PHP 8.3 and 8.4 are set up by the installer"
                .to_string(),
        );
    }

    let mut out = String::new();
    if Path::new(&format!("/etc/php/{v}/fpm/php-fpm.conf")).is_file() {
        out.push_str(&format!(
            "PHP {v} is already installed; ensuring SNPanel extension set...\n"
        ));
    }

    let fpm = format!("php{v}-fpm");
    if !apt_installable(&fpm) {
        if !ondrej_ppa_configured() {
            if !ondrej_publishes_this_release() {
                return HelperResponse::failed(
                    HelperErrorKind::BadRequest,
                    format!(
                        "PHP {v} is not available on this system. Ondrej's PPA does not publish \
                         packages for this Ubuntu release, so only the versions the distribution \
                         carries can be installed: {}. Nothing was changed.",
                        installable_versions()
                    ),
                );
            }
            out.push_str(&format!("Adding ondrej/php PPA for PHP {v}...\n"));
            if let Ok(o) = update_index() {
                out.push_str(&o.stdout);
            }
            let _ = install_packages(&["software-properties-common"]);
            let _ = exec::run(&["add-apt-repository", "-y", "ppa:ondrej/php"]);
        }
        if let Ok(o) = update_index() {
            out.push_str(&o.stdout);
        }
        if !apt_installable(&fpm) {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!(
                    "PHP {v} is still not available after refreshing the package lists. \
                     Installable versions here: {}",
                    installable_versions()
                ),
            );
        }
    }

    out.push_str(&format!("Installing PHP {v}...\n"));
    let wanted: Vec<String> = PHP_EXTENSIONS
        .iter()
        .map(|ext| format!("php{v}-{ext}"))
        .collect();
    let mut available: Vec<&str> = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    for package in &wanted {
        if apt_installable(package) {
            available.push(package);
        } else {
            missing.push(package);
        }
    }
    if !missing.is_empty() {
        out.push_str(&format!(
            "Skipping PHP packages not available in repo: {}\n",
            missing.join(" ")
        ));
    }
    if available.is_empty() {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("No package found for PHP {v}"),
        );
    }
    match install_packages(&available) {
        Ok(o) if o.ok() => out.push_str(&o.stdout),
        _ => {
            out.push_str(&format!("Failed to install PHP {v}\n"));
            return HelperResponse::failed(HelperErrorKind::CommandFailed, out);
        }
    }

    match install_ioncube_loader(version) {
        Ok(text) => out.push_str(&text),
        Err(resp) => return resp,
    }

    let _ = exec::run(&["systemctl", "enable", &fpm]);
    let _ = exec::run(&["systemctl", "start", &fpm]);

    out.push_str(&format!("PHP {v} installed successfully\n"));
    HelperResponse::with_stdout(out)
}

/// Source: `install_ioncube_loader`.
///
/// This puts a third-party binary into every PHP process on the box as a
/// `zend_extension`, so the last step is not optional: PHP is asked whether it
/// actually loaded, and if it did not, both ini files are removed again. A
/// loader that is configured but not loading leaves every site running with a
/// startup error in its log and no way to see why from the panel.
fn install_ioncube_loader(version: PhpVersion) -> Result<String, HelperResponse> {
    let v = version.dotted();

    let arch = exec::run(&["dpkg", "--print-architecture"])
        .ok()
        .filter(exec::Output::ok)
        .map(|o| o.stdout.trim().to_string())
        .filter(|a| !a.is_empty())
        .or_else(|| {
            exec::run(&["uname", "-m"])
                .ok()
                .map(|o| o.stdout.trim().to_string())
        })
        .unwrap_or_default();
    if arch != "amd64" && arch != "x86_64" {
        return Ok(format!(
            "Skipping ionCube Loader: unsupported architecture {arch}\n"
        ));
    }

    let _ = install_packages(&["ca-certificates", "curl", "tar"]);

    // `mktemp -d`, not a name built from the pid: this unpacks an archive and
    // then installs a file out of it as root.
    let temp = match exec::run(&["mktemp", "-d"]) {
        Ok(o) if o.ok() && !o.stdout.trim().is_empty() => o.stdout.trim().to_string(),
        _ => {
            return Err(HelperResponse::failed(
                HelperErrorKind::Internal,
                "cannot create ionCube temporary directory".to_string(),
            ))
        }
    };
    let cleanup = |resp: HelperResponse| -> HelperResponse {
        let _ = std::fs::remove_dir_all(&temp);
        resp
    };
    let archive = format!("{temp}/ioncube_loaders.tar.gz");

    const URL: &str =
        "https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz";
    if !matches!(
        exec::run(&["curl", "-fsSL", "--connect-timeout", "10", "--max-time", "300", URL, "-o", &archive]),
        Ok(o) if o.ok()
    ) {
        return Err(cleanup(HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "failed to download ionCube Loader".to_string(),
        )));
    }
    if !matches!(exec::run(&["tar", "-xzf", &archive, "-C", &temp]), Ok(o) if o.ok()) {
        return Err(cleanup(HelperResponse::failed(
            HelperErrorKind::CommandFailed,
            "failed to unpack ionCube Loader".to_string(),
        )));
    }

    let loader = format!("{temp}/ioncube/ioncube_loader_lin_{v}.so");
    if !Path::new(&loader).is_file() {
        // Not a failure: ionCube ships loaders for the versions it supports,
        // and a PHP newer than the bundle is a normal state.
        let _ = std::fs::remove_dir_all(&temp);
        return Ok(format!(
            "Skipping ionCube Loader: no loader found for PHP {v}\n"
        ));
    }

    const TARGET_DIR: &str = "/usr/local/ioncube";
    let target = format!("{TARGET_DIR}/ioncube_loader_lin_{v}.so");
    if let Err(e) = std::fs::create_dir_all(TARGET_DIR) {
        return Err(cleanup(HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("creating {TARGET_DIR}: {e}"),
        )));
    }
    if let Err(e) = std::fs::copy(&loader, &target) {
        return Err(cleanup(HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("installing {target}: {e}"),
        )));
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(TARGET_DIR, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644));
    }
    let _ = std::fs::remove_dir_all(&temp);

    let inis = [
        format!("/etc/php/{v}/cli/conf.d/00-ioncube.ini"),
        format!("/etc/php/{v}/fpm/conf.d/00-ioncube.ini"),
    ];
    for ini in &inis {
        let dir = Path::new(ini).parent().expect("the conf.d directory");
        if !dir.is_dir() {
            continue;
        }
        if std::fs::write(ini, format!("zend_extension={target}\n")).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(ini, std::fs::Permissions::from_mode(0o644));
            let _ = exec::run(&["chown", "root:root", ini]);
        }
    }

    // The check that makes the whole thing safe to have done.
    let php = format!("php{v}");
    if have(&php) {
        let reported = exec::run(&[&php, "-v"])
            .map(|o| format!("{}{}", o.stdout, o.stderr))
            .unwrap_or_default();
        if !reported.to_lowercase().contains("ioncube") {
            for ini in &inis {
                let _ = std::fs::remove_file(ini);
            }
            return Err(HelperResponse::failed(
                HelperErrorKind::CommandFailed,
                format!("ionCube Loader failed to load for PHP {v}"),
            ));
        }
    }

    Ok(format!("ionCube Loader enabled for PHP {v}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon config, against the bash's heredoc.
    ///
    /// The log rotation is the line that matters on a shared host: "an
    /// unbounded container log fills the disk and takes every other site down
    /// with it."
    #[test]
    fn the_docker_daemon_config_is_the_bash_helpers() {
        const BASH: &str = include_str!("../../../../installer/files/snpanel-helper.sh");
        let open = "<<'JSON'\n";
        let start = BASH.find(open).expect("the heredoc opener") + open.len();
        let end = BASH[start..].find("JSON\n").expect("the closer") + start;
        assert_eq!(DOCKER_DAEMON_JSON, &BASH[start..end]);

        // And it is JSON, which a heredoc cannot promise.
        let parsed: serde_json::Value =
            serde_json::from_str(DOCKER_DAEMON_JSON).expect("daemon.json parses");
        assert_eq!(parsed["log-opts"]["max-size"], "10m");
        assert_eq!(parsed["no-new-privileges"], true);
    }

    /// `/etc/os-release` parsing, including the quoting the file uses.
    #[test]
    fn os_release_values_lose_their_quotes() {
        let fields = |text: &str| -> Vec<(String, String)> {
            text.lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return None;
                    }
                    let (k, v) = line.split_once('=')?;
                    Some((
                        k.trim().to_string(),
                        v.trim().trim_matches('"').trim_matches('\'').to_string(),
                    ))
                })
                .collect()
        };
        let sample = "# a comment\nID=debian\nVERSION_CODENAME=trixie\nPRETTY_NAME=\"Debian GNU/Linux 13\"\n\nID_LIKE='debian'\n";
        let got = fields(sample);
        assert_eq!(os_field(&got, "ID"), "debian");
        assert_eq!(os_field(&got, "VERSION_CODENAME"), "trixie");
        assert_eq!(os_field(&got, "PRETTY_NAME"), "Debian GNU/Linux 13");
        assert_eq!(os_field(&got, "ID_LIKE"), "debian");
        assert_eq!(os_field(&got, "NOT_THERE"), "");
    }

    /// The interface name is the **fifth** field of the default route.
    ///
    /// `ip route show default` prints `default via <gw> dev <iface> ...`, so
    /// counting from the wrong end puts an IP address where the DOCKER-USER
    /// rule expects a device - and the guard then silently protects nothing.
    #[test]
    fn the_default_interface_is_the_fifth_field() {
        let pick = |text: &str| -> Option<String> {
            text.lines()
                .find(|l| l.starts_with("default"))
                .and_then(|l| l.split_whitespace().nth(4))
                .map(str::to_string)
        };
        assert_eq!(
            pick("default via 10.0.0.1 dev eth0 proto dhcp metric 100").as_deref(),
            Some("eth0")
        );
        assert_eq!(
            pick("10.0.0.0/24 dev eth0 scope link\ndefault via 192.168.1.1 dev ens3").as_deref(),
            Some("ens3")
        );
        assert_eq!(pick(""), None);
        // A default route with no `dev` has nothing to guard.
        assert_eq!(pick("default via 10.0.0.1"), None);
    }

    /// A scan job id becomes a filename under a directory the panel reads, so
    /// it is checked rather than escaped: lowercase hex only, which cannot
    /// carry a separator, a dot or a traversal.
    #[test]
    fn a_scan_job_id_is_lowercase_hex_of_a_bounded_length() {
        assert!(valid_job_id("0123abcd"));
        assert!(valid_job_id(&"a".repeat(64)));
        for bad in [
            "",
            "0123abc",
            &"a".repeat(65),
            "0123ABCD",
            "0123abc-",
            "../etc",
            "0123 abcd",
            "0123abcg",
            "0123.abc",
        ] {
            assert!(!valid_job_id(bad), "{bad:?} should be refused");
        }
    }

    /// A scan target is `/` or under `/home`, decided **after** resolving.
    ///
    /// That order is the point: `/home/alice/link` pointing at `/etc` resolves
    /// to `/etc` and is refused, where checking the text first would have
    /// accepted it and handed the scanner the whole of `/etc`.
    #[test]
    fn a_scan_target_is_judged_after_it_is_resolved() {
        assert_eq!(scan_target("/").unwrap().as_deref(), Some("/"));
        assert!(scan_target("/etc").is_err());
        assert!(scan_target("/var/www").is_err());
        // `/home/../etc` normalises to `/etc` before the check.
        assert!(scan_target("/home/../etc").is_err());

        // A real symlink out of /home resolves out of /home.
        let dir = std::env::temp_dir().join(format!("scanlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let link = dir.join("escape");
        let _ = std::os::unix::fs::symlink("/etc", &link);
        if link.exists() {
            let resolved = readlink_m(&link);
            assert_eq!(resolved.to_string_lossy(), "/etc");
        }
        let _ = std::fs::remove_dir_all(&dir);

        // Under /home but not a directory: skipped, not refused. A customer
        // removed between the panel listing them and the scan starting is not
        // an error.
        assert_eq!(scan_target("/home/definitely-not-there").unwrap(), None);
    }

    /// `readlink -m` never fails, and normalises what it cannot resolve.
    #[test]
    fn the_resolver_normalises_a_path_that_is_not_there() {
        assert_eq!(readlink_m(std::path::Path::new("/")).to_string_lossy(), "/");
        assert_eq!(
            readlink_m(std::path::Path::new("/nope/../also-nope")).to_string_lossy(),
            "/also-nope"
        );
        assert_eq!(
            readlink_m(std::path::Path::new("/home/./x/../y")).to_string_lossy(),
            "/home/y"
        );
    }

    /// The scan id maldet prints, found the way the bash greps for it.
    ///
    /// `[0-9]{6}-[0-9]{4}\.[0-9]+`, first match. Getting it wrong means the
    /// report body is empty and the panel shows a scan that found nothing.
    #[test]
    fn the_scan_id_is_found_the_way_the_bash_greps_for_it() {
        assert_eq!(
            find_scan_id("maldet(1234): {scan} 250920-1431.4321 started").as_deref(),
            Some("250920-1431.4321")
        );
        // First match wins.
        assert_eq!(
            find_scan_id("111111-2222.3 then 444444-5555.6").as_deref(),
            Some("111111-2222.3")
        );
        // Near misses: wrong digit counts, and no digits after the dot.
        assert_eq!(find_scan_id("12345-1234.1"), None);
        assert_eq!(find_scan_id("123456-123.1"), None);
        assert_eq!(find_scan_id("123456-1234."), None);
        assert_eq!(find_scan_id("123456-1234"), None);
        assert_eq!(find_scan_id(""), None);
    }

    /// The prune list is the bash's, read from the bash.
    ///
    /// It is the difference between a scan that takes ten minutes and one that
    /// takes hours reading `/proc` and a package cache.
    #[test]
    fn the_scan_prune_list_is_the_bash_helpers() {
        const BASH: &str = include_str!("../../../../installer/files/snpanel-helper.sh");
        let line = BASH
            .lines()
            .find(|l| l.starts_with("MALWARE_SCAN_PRUNE="))
            .expect("MALWARE_SCAN_PRUNE is not in the bash helper");
        let inside = line
            .trim_start_matches("MALWARE_SCAN_PRUNE=(")
            .trim_end_matches(')');
        let want: Vec<&str> = inside.split_whitespace().collect();
        assert_eq!(SCAN_PRUNE, want.as_slice());
    }

    /// Both update paths, read out of the bash helper rather than asserted.
    ///
    /// I had written `/opt/snpanel-src/...` - this session's tooling path -
    /// where the helper ships `/usr/local/sbin/snpanel-update`. The verb would
    /// have refused with "missing ..." on every box and never said why.
    #[test]
    fn the_update_paths_are_the_bash_helpers() {
        const BASH: &str = include_str!("../../../../installer/files/snpanel-helper.sh");
        let value_of = |key: &str| -> String {
            BASH.lines()
                .find_map(|l| l.strip_prefix(key))
                .unwrap_or_else(|| panic!("{key} is not in the bash helper"))
                .trim()
                .trim_matches('"')
                .to_string()
        };
        assert_eq!(UPDATE_SCRIPT, value_of("UPDATE_SCRIPT="));
        assert_eq!(SOURCE_DIR, value_of("SOURCE_DIR="));
    }

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

    /// The bug this test exists for.
    ///
    /// `maldet-status` used to answer with `HelperResponse::with_data`, which
    /// the helper prints as pretty JSON. The only reader is `status()` in
    /// `backend/app/services/maldet.py`, and it parses stdout line by line with
    /// `_KV_RE = ^([a-z_]+)=(.*)$`. No JSON line can match that, so every key
    /// came back missing and the panel reported an installed scanner with a
    /// running monitor as neither installed nor running - silently, because
    /// the call is made with `check=False`.
    ///
    /// The assertion is the Python regex, applied to every line.
    #[test]
    fn every_status_line_is_one_python_s_kv_regex_can_read() {
        fn python_kv(line: &str) -> Option<(&str, &str)> {
            // ^([a-z_]+)=(.*)$
            let (key, value) = line.split_once('=')?;
            if key.is_empty() || !key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                return None;
            }
            Some((key, value))
        }

        let dir = std::env::temp_dir().join(format!("maldet-status-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let sig = dir.join("maldet.sigs.ver");

        // Without a signature file: the two placeholder lines.
        let text = status_lines(true, true, &sig);
        let parsed: Vec<(&str, &str)> = text.lines().filter_map(python_kv).collect();
        assert_eq!(
            parsed,
            vec![
                ("installed", "1"),
                ("monitor", "1"),
                ("sig_version", "unknown"),
                ("sig_updated", ""),
            ]
        );

        // With one: a version, and a timestamp Python hands to the panel as-is.
        std::fs::write(&sig, "2025091801\n").expect("the sig file");
        let text = status_lines(false, false, &sig);
        let parsed: std::collections::HashMap<&str, &str> =
            text.lines().filter_map(python_kv).collect();
        assert_eq!(parsed.len(), 4, "all four lines parse: {text:?}");
        assert_eq!(parsed["installed"], "0");
        assert_eq!(parsed["monitor"], "0");
        assert_eq!(parsed["sig_version"], "2025091801");
        let updated = parsed["sig_updated"];
        assert!(
            updated.len() == 20 && updated.ends_with('Z') && updated.as_bytes()[10] == b'T',
            "an RFC 3339 instant, not {updated:?}"
        );

        // And the shape the bug had: pretty JSON yields nothing at all.
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "installed": true, "signatures": false,
        }))
        .expect("json");
        assert!(
            json.lines().filter_map(python_kv).next().is_none(),
            "JSON must be unreadable to the caller - that was the bug"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `format_utc` against GNU `date -u -d @N`, which is what the bash runs.
    ///
    /// 1,266 instants, weighted towards the days a hand-written civil-date
    /// conversion gets wrong: 1900 (divisible by 100, not a leap year), 2000
    /// (divisible by 400, a leap year), 2100, the first and last second of a
    /// day, and both sides of the 32-bit signed epoch.
    #[test]
    fn utc_timestamps_match_gnu_date_over_the_whole_corpus() {
        #[derive(serde::Deserialize)]
        struct Case {
            secs: i64,
            utc: String,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/format_utc.json");
        let raw = std::fs::read_to_string(&path).expect("the format_utc corpus");
        let cases: Vec<Case> = serde_json::from_str(&raw).expect("the corpus parses");
        assert!(cases.len() > 1_000, "the corpus is {} cases", cases.len());
        for case in &cases {
            assert_eq!(
                format_utc(case.secs),
                case.utc,
                "at {} seconds from the epoch",
                case.secs
            );
        }
    }

    /// `sed -i -E "s#^key=.*#key=\"val\"#"` has no line range.
    ///
    /// A config that somehow ended up with `quarantine_hits` twice comes out
    /// with **both** copies set - which is the only safe answer, since the
    /// last assignment is the one the shell that sources it would keep. A
    /// first-match-only rewrite would leave a stale `quarantine_hits=1` below
    /// the corrected one and the scanner would quarantine after all.
    #[test]
    fn every_copy_of_a_key_is_rewritten_not_just_the_first() {
        let dir = std::env::temp_dir().join(format!("maldet-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");
        let conf = dir.join("conf.maldet");
        let cron = dir.join("cron.daily.maldet");

        std::fs::write(
            &conf,
            "# rfxn's own config\n\
             quarantine_hits=1\n\
             email_alert=1\n\
             quarantine_hits=1\n\
             something_else=\"keep me\"\n",
        )
        .expect("the conf");
        std::fs::write(&cron, "#!/bin/sh\n").expect("the cron");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cron, std::fs::Permissions::from_mode(0o755))
                .expect("executable to begin with");
        }

        maldet_write_conf(&conf, &cron);
        let text = std::fs::read_to_string(&conf).expect("read back");

        assert_eq!(
            text.matches("quarantine_hits=\"0\"").count(),
            2,
            "both copies: {text}"
        );
        assert!(!text.contains("quarantine_hits=1"), "{text}");
        assert!(text.contains("something_else=\"keep me\""), "{text}");
        assert!(text.contains("# rfxn's own config"), "the comment survives");
        // A key that was not there is appended, quoted.
        assert!(text.contains("default_monitor_mode=\"users\""), "{text}");
        assert!(text.ends_with('\n'));

        // `chmod a-x`: disarmed, not deleted, so an admin still finds it.
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cron)
                .expect("still there")
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0, "no execute bit left: {mode:o}");
        }

        // And a box where rfxn's installer has not run yet is left alone
        // rather than having a config invented for it.
        let absent = dir.join("not-there");
        maldet_write_conf(&absent, &cron);
        assert!(!absent.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `journalctl ... | sed -n 's/.*{mon} //p' | tail -n 1`.
    ///
    /// Greedy `.*` keeps what follows the **last** marker on a line, and
    /// `tail -n 1` keeps the newest line that carried one at all - so what
    /// reaches the panel is maldet's most recent complaint, not its first.
    #[test]
    fn the_monitor_failure_reason_is_the_last_marked_line() {
        let journal = "\
Sep 21 10:00:01 host maldet[1]: starting
Sep 21 10:00:02 host maldet[1]: {mon} inotify watch limit reached
Sep 21 10:00:03 host maldet[1]: unrelated chatter
Sep 21 10:00:04 host maldet[1]: {mon} no such user in {mon} default_monitor_mode
";
        assert_eq!(last_mon_message(journal), "default_monitor_mode");

        // Nothing marked at all: the caller falls back to its own sentence.
        assert_eq!(
            last_mon_message("Sep 21 10:00:01 host maldet[1]: quiet\n"),
            ""
        );
        assert_eq!(last_mon_message(""), "");
    }

    /// The action word is closed, and an uninstalled scanner refuses first.
    #[test]
    fn the_monitor_verb_takes_exactly_three_actions() {
        // `[[ -x "$MALDET_BIN" ]] || deny` comes before the `case`, so on a box
        // without maldet even a valid action refuses - and says which fact is
        // missing rather than reporting the monitor as stopped.
        if !is_executable(MALDET_BIN) {
            for action in ["start", "stop", "status", "restart", ""] {
                let response = maldet_monitor(action);
                assert!(!response.ok, "{action:?}");
                let message = response
                    .error
                    .as_ref()
                    .map(|e| e.message.clone())
                    .unwrap_or_default();
                assert_eq!(message, "maldet is not installed", "{action:?}");
            }
        }
    }

    /// `find -maxdepth 1 -type d -name 'maldetect-*'`, plus `-x install.sh`.
    ///
    /// The `-x` half is the one that matters: an archive that unpacked into a
    /// directory of the right name but without a runnable installer has to
    /// refuse, not `cd` into it and run nothing.
    #[test]
    fn the_unpacked_directory_is_found_only_with_a_runnable_installer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("maldet-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the dir");

        assert_eq!(lmd_source_dir(&dir), None, "an empty directory");

        // A file, not a directory: `-type d` skips it.
        std::fs::write(dir.join("maldetect-1.6.5"), "").expect("a decoy file");
        assert_eq!(lmd_source_dir(&dir), None, "a file of the right name");
        std::fs::remove_file(dir.join("maldetect-1.6.5")).expect("remove the decoy");

        // The right name, but no installer.
        let src = dir.join("maldetect-1.6.5");
        std::fs::create_dir_all(&src).expect("the source dir");
        assert_eq!(lmd_source_dir(&dir), None, "no install.sh");

        // Present but not executable - which is what a tarball unpacked with a
        // umask that stripped the bit looks like.
        let script = src.join("install.sh");
        std::fs::write(&script, "#!/bin/sh\n").expect("the script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644))
            .expect("not executable");
        assert_eq!(lmd_source_dir(&dir), None, "install.sh is not executable");

        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        assert_eq!(lmd_source_dir(&dir), Some(src));

        // A directory of some other name is not a candidate.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("maldet-1.6.5")).expect("wrong prefix");
        assert_eq!(lmd_source_dir(&dir), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `apt-cache policy <pkg> | sed -n 's/^  Candidate: //p'`.
    ///
    /// The bash comment records the bug this replaced: `apt-cache show`
    /// succeeds for a name the archive merely references, so on Ubuntu 26.04
    /// it said yes to `php7.4-fpm` and the panel told the user 7.4 was
    /// available on a release that has no such package. The candidate line is
    /// the one that distinguishes them, and `(none)` is how it says no.
    #[test]
    fn a_package_is_installable_only_when_apt_names_a_candidate() {
        // Real `apt-cache policy` output.
        let installable = "php8.4-fpm:\n  \
                           Installed: (none)\n  \
                           Candidate: 8.4.3-1+ubuntu24.04.1+deb.sury.org+1\n  \
                           Version table:\n     \
                           8.4.3-1+ubuntu24.04.1+deb.sury.org+1 500\n";
        assert_eq!(
            candidate_version(installable),
            Some("8.4.3-1+ubuntu24.04.1+deb.sury.org+1")
        );

        // Referenced but not installable - the case that caused the bug.
        let referenced = "php7.4-fpm:\n  Installed: (none)\n  \
                          Candidate: (none)\n  Version table:\n";
        assert_eq!(candidate_version(referenced), None);

        // A name apt does not know at all prints nothing useful.
        assert_eq!(
            candidate_version("N: Unable to locate package nope\n"),
            None
        );
        assert_eq!(candidate_version(""), None);

        // Exactly two leading spaces: `Candidate:` also appears inside a
        // version table's pinning block, indented further, where it means
        // something else.
        assert_eq!(candidate_version("Candidate: 1.0\n"), None);
        assert_eq!(candidate_version("      Candidate: 1.0\n"), None);
        assert_eq!(candidate_version("  Candidate: 1.0\n"), Some("1.0"));
        assert_eq!(candidate_version("  Candidate: \n"), None);
    }

    /// `. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}"`.
    ///
    /// Sourcing the file gives shell unquoting for free; reading it does not,
    /// and a codename carrying its quotes would build a URL that 404s - which
    /// this reads as "the PPA does not publish for this release" and refuses
    /// an install that would have worked.
    #[test]
    fn the_os_release_codename_arrives_unquoted() {
        let sample = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n\
                      NAME=\"Ubuntu\"\n\
                      VERSION_ID=\"24.04\"\n\
                      VERSION_CODENAME=noble\n\
                      ID=ubuntu\n";
        assert_eq!(
            parse_os_release_field(sample, "VERSION_CODENAME").as_deref(),
            Some("noble")
        );
        assert_eq!(
            parse_os_release_field(sample, "ID").as_deref(),
            Some("ubuntu")
        );
        assert_eq!(
            parse_os_release_field(sample, "VERSION_ID").as_deref(),
            Some("24.04")
        );
        assert_eq!(
            parse_os_release_field(sample, "NAME").as_deref(),
            Some("Ubuntu")
        );

        // Debian quotes the codename; Ubuntu does not. Both have to work.
        assert_eq!(
            parse_os_release_field("VERSION_CODENAME=\"trixie\"\n", "VERSION_CODENAME").as_deref(),
            Some("trixie")
        );
        assert_eq!(
            parse_os_release_field("VERSION_CODENAME='trixie'\n", "VERSION_CODENAME").as_deref(),
            Some("trixie")
        );

        // Absent is absent, not empty - the caller refuses on it.
        assert_eq!(parse_os_release_field(sample, "VERSION_CODENAMEX"), None);
        assert_eq!(parse_os_release_field("", "VERSION_CODENAME"), None);

        // A prefix of another key must not match: `ID` and `VERSION_ID` are
        // different fields and the file lists both.
        let ordered = "ID=debian\nVERSION_ID=\"13\"\n";
        assert_eq!(
            parse_os_release_field(ordered, "ID").as_deref(),
            Some("debian")
        );

        // Sourcing means the last assignment wins.
        assert_eq!(
            parse_os_release_field("ID=first\nID=second\n", "ID").as_deref(),
            Some("second")
        );
    }

    /// The extension set, and the two packages that are not optional.
    ///
    /// Every name is checked against the repository on its own before the
    /// install, because one missing extension must skip that extension rather
    /// than fail the whole `apt-get install` and leave the version uninstalled.
    #[test]
    fn the_php_package_set_is_the_bash_helpers() {
        assert_eq!(PHP_EXTENSIONS.len(), 14);
        assert_eq!(PHP_EXTENSIONS[0], "fpm");
        assert_eq!(PHP_EXTENSIONS[1], "cli");
        for required in ["fpm", "cli", "mysql", "opcache", "mbstring", "curl", "gd"] {
            assert!(PHP_EXTENSIONS.contains(&required), "{required} is missing");
        }
        // Names are suffixes, joined as `php<version>-<ext>`.
        let names: Vec<String> = PHP_EXTENSIONS
            .iter()
            .map(|e| format!("php8.4-{e}"))
            .collect();
        assert_eq!(names[0], "php8.4-fpm");
        assert!(names.iter().all(|n| n.starts_with("php8.4-")));

        // The versions the panel offers are the ones `PhpVersion` accepts.
        for v in OFFERED_PHP_VERSIONS {
            assert!(
                snpanel_core::PhpVersion::parse(v).is_ok(),
                "{v} is offered but not a valid PhpVersion"
            );
        }
        for bad in ["8.6", "9.0", "7.3", "5.5"] {
            assert!(!OFFERED_PHP_VERSIONS.contains(&bad), "{bad}");
        }
    }
}
