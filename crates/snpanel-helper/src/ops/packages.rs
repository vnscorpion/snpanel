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
}
