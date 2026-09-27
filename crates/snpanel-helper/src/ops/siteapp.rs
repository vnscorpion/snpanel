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

/// Source: `app_env_file`.
///
/// Deliberately outside the customer's home. Inside it, the file was
/// reachable through the file manager, went into every site backup, and the
/// permission pass in update.sh handed ownership back to the site user on the
/// next update. Nothing but root needs to read it: systemd loads
/// `EnvironmentFile` before dropping privileges.
fn env_file(user: &PanelUsername, app: &AppName) -> String {
    format!(
        "/var/lib/snpanel/apps/{}-{}.env",
        user.as_str(),
        app.as_str()
    )
}

/// `site-app-dir-ensure`: the application's directory, hardened.
///
/// Source: `ensure_app_directory`. The home has to exist first - creating an
/// apps directory under a home that is not there would make one owned by
/// nobody, in a place the customer's SFTP cannot reach.
pub fn dir_ensure(user: &PanelUsername, app: &AppName) -> HelperResponse {
    let home = format!("/home/{}", user.as_str());
    if !std::path::Path::new(&home).is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("home directory missing for {user}"),
        );
    }
    let apps_root = format!("{home}/apps");
    let target = app_directory(user, app);

    for dir in [&apps_root, &target] {
        let out = exec::run(&["install", "-d", "-m", "0750", dir]);
        if !matches!(&out, Ok(o) if o.ok()) {
            return exec::respond("install -d", out);
        }
        let owner = format!("{}:{}", user.as_str(), super::user::SITES_GROUP);
        let _ = exec::run(&["chown", &owner, dir]);
        let _ = exec::run(&["chmod", "0750", dir]);
        for flag in ["a-s", "-t"] {
            let _ = exec::run(&["chmod", flag, dir]);
        }
    }
    HelperResponse::with_stdout(format!("{target}\n"))
}

/// `site-app-delete`: remove the runtime, keep the code.
///
/// Source: the `site-app-delete` arm, including its closing comment. The
/// application directory is deliberately left alone - removing a runtime is
/// not a request to delete somebody's work, and a customer who redeploys
/// expects their files to still be there.
pub fn delete(user: &PanelUsername, app: &AppName) -> HelperResponse {
    let unit = unit_name(user, app);
    let service = format!("{unit}.service");

    let _ = exec::run(&["systemctl", "disable", "--now", &service]);
    let _ = std::fs::remove_file(format!("/etc/systemd/system/{service}"));
    let _ = exec::run(&["systemctl", "daemon-reload"]);

    if docker_present() {
        let file = compose_file(user, app);
        if std::path::Path::new(&file).is_file() {
            let dir = app_directory(user, app);
            let project = container_name(user, app);
            let _ = exec::run(&[
                "docker",
                "compose",
                "-f",
                &file,
                "--project-directory",
                &dir,
                "-p",
                &project,
                "down",
                "--volumes",
            ]);
        }
        let _ = exec::run(&["docker", "rm", "-f", &container_name(user, app)]);
    }

    let _ = std::fs::remove_file(env_file(user, app));
    let _ = std::fs::remove_file(compose_file(user, app));

    HelperResponse::with_stdout(format!("removed {unit}\n"))
}

/// `site-app-pull`: fetch a container image.
///
/// The reference is a `DockerImage`, so it cannot begin with a dash or
/// contain a `..` component - `docker pull` would read the first as a flag.
pub fn pull(image: &snpanel_core::DockerImage) -> HelperResponse {
    if !docker_present() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            "Docker is not installed; run docker-install first".to_string(),
        );
    }
    exec::respond(
        &format!("docker pull {image}"),
        exec::run(&["timeout", "900", "docker", "pull", "--", image.as_str()]),
    )
}

/// Where a given Node major version lives.
///
/// Source: `resolve_node_bin_dir`. The panel's own copy first, then the
/// system one - but only if it is actually that major version, because
/// running an application's install with the wrong Node is how a native
/// module gets built against the wrong ABI.
fn node_bin_dir(major: u8) -> Option<String> {
    let own = format!("/opt/snpanel/node/{major}/bin");
    if std::path::Path::new(&format!("{own}/node")).is_file() {
        return Some(own);
    }
    if std::path::Path::new("/usr/bin/node").is_file() {
        if let Ok(out) = exec::run(&[
            "/usr/bin/node",
            "-p",
            "process.versions.node.split(\".\")[0]",
        ]) {
            if out.stdout.trim() == major.to_string() {
                return Some("/usr/bin".to_string());
            }
        }
    }
    None
}

/// `site-app-install-deps`: `npm install` for a node application.
///
/// Two things are load-bearing. It runs as the application's owner, not root.
/// And it runs with `env -i`: a postinstall script is a customer's code, and
/// the helper's environment is not something to hand it. The timeout is there
/// because a runaway postinstall would otherwise hold a worker forever.
pub fn install_deps(user: &PanelUsername, app: &AppName, node_major: u8) -> HelperResponse {
    if !(10..=99).contains(&node_major) {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            format!("invalid node major version: {node_major}"),
        );
    }
    let ensured = dir_ensure(user, app);
    if !ensured.ok {
        return ensured;
    }
    let dir = app_directory(user, app);
    if !std::path::Path::new(&format!("{dir}/package.json")).is_file() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("no package.json in {app}"),
        );
    }
    let Some(bin) = node_bin_dir(node_major) else {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("Node {node_major} is not installed; run node-install {node_major} first"),
        );
    };

    let home = format!("HOME=/home/{}", user.as_str());
    let path = format!("PATH={bin}:/usr/local/bin:/usr/bin:/bin");
    let npm = format!("{bin}/npm");
    exec::respond(
        "npm install",
        exec::run(&[
            "timeout",
            "900",
            "runuser",
            "-u",
            user.as_str(),
            "--",
            "env",
            "-i",
            &home,
            &path,
            "NODE_ENV=production",
            &npm,
            "install",
            "--omit=dev",
            "--no-audit",
            "--no-fund",
            "--prefix",
            &dir,
        ]),
    )
}

/// Where the panel keeps backups. Source: `BACKUP_ROOT`.
const BACKUP_ROOT: &str = "/var/backups/snpanel";

/// A path the helper will read or write as root on the panel's behalf.
///
/// Source: `require_backup_path`. Three checks, and the third is the one that
/// is easy to leave out: the parent is *resolved* and re-checked, because a
/// symlinked directory inside the backup tree points wherever it likes and
/// the prefix test on the unresolved path would pass.
fn check_backup_path(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("empty backup path".to_string());
    }
    if target.contains('\n') || target.contains('\0') {
        return Err(format!("invalid backup path: {target}"));
    }
    if target.contains("..") {
        return Err("backup path may not contain ..".to_string());
    }
    if !target.starts_with(&format!("{BACKUP_ROOT}/")) {
        return Err(format!("backup path must be under {BACKUP_ROOT}"));
    }
    let _ = exec::run(&[
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "root",
        "-g",
        "snpanel",
        BACKUP_ROOT,
    ]);
    let parent = std::path::Path::new(target)
        .parent()
        .ok_or_else(|| format!("backup path has no directory: {target}"))?;
    if !parent.is_dir() {
        return Err(format!(
            "backup directory does not exist: {}",
            parent.display()
        ));
    }
    let real = std::fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve {}: {e}", parent.display()))?;
    let real_str = real.to_string_lossy();
    if real_str != BACKUP_ROOT && !real_str.starts_with(&format!("{BACKUP_ROOT}/")) {
        return Err(format!("backup directory escapes {BACKUP_ROOT}"));
    }
    Ok(())
}

/// `site-app-rename`.
///
/// The directory moves with the name. An application's directory is derived
/// from its name, so renaming without moving would orphan the customer's
/// files at a path nothing refers to any more.
pub fn rename(user: &PanelUsername, from: &AppName, to: &AppName) -> HelperResponse {
    if from == to {
        return HelperResponse::ok();
    }
    let old_dir = app_directory(user, from);
    let new_dir = app_directory(user, to);

    if std::path::Path::new(&old_dir).is_dir() {
        if std::path::Path::new(&new_dir).exists() {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("a directory already exists at {new_dir}"),
            );
        }
        if let Some(parent) = std::path::Path::new(&new_dir).parent() {
            let _ = exec::run(&["install", "-d", "-m", "0750", &parent.to_string_lossy()]);
        }
        if let Err(e) = std::fs::rename(&old_dir, &new_dir) {
            return HelperResponse::failed(
                HelperErrorKind::Internal,
                format!("moving {old_dir} to {new_dir}: {e}"),
            );
        }
    }
    let ensured = dir_ensure(user, to);
    if !ensured.ok {
        return ensured;
    }
    for (old, new) in [
        (env_file(user, from), env_file(user, to)),
        (compose_file(user, from), compose_file(user, to)),
    ] {
        if std::path::Path::new(&old).is_file() {
            let _ = std::fs::rename(&old, &new);
        }
    }
    HelperResponse::with_stdout(format!("{new_dir}\n"))
}

/// `site-app-export`: the directory and every named volume, in one tar.
///
/// Volumes are exported with numeric owners on purpose: a database image
/// expects its own uid inside the volume, and that uid belongs to the image
/// rather than to this machine.
pub fn export(user: &PanelUsername, app: &AppName, dest: &str) -> HelperResponse {
    if let Err(message) = check_backup_path(dest) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, message);
    }
    let dir = app_directory(user, app);
    if !std::path::Path::new(&dir).is_dir() {
        return HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("application directory not found: {dir}"),
        );
    }
    let stage = format!("{BACKUP_ROOT}/.app-export-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&stage);
    if let Err(e) = std::fs::create_dir_all(format!("{stage}/volumes")) {
        return HelperResponse::failed(HelperErrorKind::Internal, format!("creating {stage}: {e}"));
    }

    let files_tar = format!("{stage}/files.tar");
    let out = exec::run(&["tar", "-C", &dir, "-cf", &files_tar, "."]);
    if !matches!(&out, Ok(o) if o.ok()) {
        let _ = std::fs::remove_dir_all(&stage);
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            "could not read the application directory".to_string(),
        );
    }

    if docker_present() {
        let prefix = format!("{}_", container_name(user, app));
        if let Ok(list) = exec::run(&["docker", "volume", "ls", "--format", "{{.Name}}"]) {
            for name in list.stdout.lines().map(str::trim) {
                if name.is_empty() || !name.starts_with(&prefix) {
                    continue;
                }
                let path = format!("/var/lib/docker/volumes/{name}/_data");
                if !std::path::Path::new(&path).is_dir() {
                    continue;
                }
                let out_tar = format!("{stage}/volumes/{name}.tar");
                let _ = exec::run(&["tar", "-C", &path, "--numeric-owner", "-cf", &out_tar, "."]);
            }
        }
    }

    let out = exec::run(&[
        "tar",
        "-C",
        &stage,
        "--numeric-owner",
        "-cf",
        dest,
        "files.tar",
        "volumes",
    ]);
    let _ = std::fs::remove_dir_all(&stage);
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond("tar (export)", out);
    }
    let _ = exec::run(&["chown", "snpanel:snpanel", dest]);
    let _ = exec::run(&["chmod", "0600", dest]);

    let size = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    HelperResponse::with_stdout(format!("{size}\n"))
}

/// `site-app-import`: restore from an export.
///
/// The volume check is the one that matters. An export is a file and a file
/// can be edited; without it, a doctored archive would have the helper write
/// into another customer's volume.
pub fn import(user: &PanelUsername, app: &AppName, source: &str) -> HelperResponse {
    if let Err(message) = check_backup_path(source) {
        return HelperResponse::failed(HelperErrorKind::BadRequest, message);
    }
    match std::fs::symlink_metadata(source) {
        Ok(m) if m.file_type().is_symlink() => {
            return HelperResponse::failed(
                HelperErrorKind::BadRequest,
                format!("no such export file: {source}"),
            )
        }
        Ok(m) if m.is_file() => {}
        _ => {
            return HelperResponse::failed(
                HelperErrorKind::NotFound,
                format!("no such export file: {source}"),
            )
        }
    }

    let ensured = dir_ensure(user, app);
    if !ensured.ok {
        return ensured;
    }
    let dir = app_directory(user, app);
    let stage = format!("{BACKUP_ROOT}/.app-import-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&stage);
    if let Err(e) = std::fs::create_dir_all(&stage) {
        return HelperResponse::failed(HelperErrorKind::Internal, format!("creating {stage}: {e}"));
    }

    let out = exec::run(&["tar", "-C", &stage, "-xf", source, "--no-same-owner"]);
    if !matches!(&out, Ok(o) if o.ok()) {
        let _ = std::fs::remove_dir_all(&stage);
        return exec::respond("tar (import)", out);
    }
    let files_tar = format!("{stage}/files.tar");
    if !std::path::Path::new(&files_tar).is_file() {
        let _ = std::fs::remove_dir_all(&stage);
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "export file has no application directory".to_string(),
        );
    }

    // `--no-same-owner` then chown: the uid in the archive may belong to a
    // different account here, and a site tree is always owned by its own user.
    let out = exec::run(&["tar", "-C", &dir, "-xf", &files_tar, "--no-same-owner"]);
    if !matches!(&out, Ok(o) if o.ok()) {
        let _ = std::fs::remove_dir_all(&stage);
        return exec::respond("tar (files)", out);
    }
    let owner = format!("{}:{}", user.as_str(), super::user::SITES_GROUP);
    let _ = exec::run(&["chown", "-R", &owner, &dir]);
    let _ = exec::run(&["chmod", "0750", &dir]);

    let mut restored = 0usize;
    if docker_present() {
        let prefix = format!("{}_", container_name(user, app));
        if let Ok(entries) = std::fs::read_dir(format!("{stage}/volumes")) {
            for entry in entries.flatten() {
                let file = entry.path();
                if file.extension().and_then(|e| e.to_str()) != Some("tar") {
                    continue;
                }
                let name = file
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !name.starts_with(&prefix) {
                    let _ = std::fs::remove_dir_all(&stage);
                    return HelperResponse::failed(
                        HelperErrorKind::BadRequest,
                        format!("export contains a volume for another application: {name}"),
                    );
                }
                let _ = exec::run(&["docker", "volume", "create", &name]);
                let path = format!("/var/lib/docker/volumes/{name}/_data");
                if !std::path::Path::new(&path).is_dir() {
                    continue;
                }
                let _ = exec::run(&[
                    "tar",
                    "-C",
                    &path,
                    "-xf",
                    &file.to_string_lossy(),
                    "--numeric-owner",
                    "-p",
                ]);
                restored += 1;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&stage);
    HelperResponse::with_stdout(format!(
        "restored {app}: directory + {restored} volume(s)\n"
    ))
}

/// The node application unit.
///
/// Built as a string so a test can read it. Every hardening directive here is
/// load-bearing: `ProtectSystem=strict` with one `ReadWritePaths` is what
/// keeps an application inside its own directory, and `HOST=127.0.0.1` is
/// what stops one that binds whatever it likes from reaching a public
/// interface. The firewall is the second layer, not the only one.
#[allow(clippy::too_many_arguments)]
pub fn node_unit_body(
    app: &AppName,
    user: &PanelUsername,
    app_dir: &str,
    env_file: &str,
    port: u16,
    memory_mb: u32,
    bin_dir: &str,
    exec_start: &str,
    identifier: &str,
) -> String {
    format!(
        "[Unit]\n\
         Description=SNPanel application {app} ({user})\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Group={user}\n\
         WorkingDirectory={app_dir}\n\
         EnvironmentFile=-{env_file}\n\
         # HOST is forced so a misconfigured app cannot bind a public interface. The\n\
         # firewall is the second layer here, not the only one.\n\
         Environment=HOST=127.0.0.1\n\
         Environment=NODE_ENV=production\n\
         Environment=PORT={port}\n\
         Environment=HOME=/home/{user}\n\
         Environment=PATH={bin_dir}:/usr/local/bin:/usr/bin:/bin\n\
         ExecStart={exec_start}\n\
         Restart=always\n\
         RestartSec=5\n\
         MemoryAccounting=yes\n\
         MemoryMax={memory_mb}M\n\
         TasksMax=256\n\
         LimitNOFILE=8192\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         PrivateDevices=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=read-only\n\
         ReadWritePaths={app_dir}\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         ProtectClock=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictRealtime=yes\n\
         RestrictNamespaces=yes\n\
         LockPersonality=yes\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={identifier}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// The container application unit.
///
/// The unit runs as root because it talks to the Docker socket. The
/// *container* is the site's uid, drops every capability, cannot gain
/// privileges and publishes on loopback only. A customer never gets socket
/// access - that is equivalent to handing out root.
#[allow(clippy::too_many_arguments)]
pub fn docker_unit_body(
    app: &AppName,
    user: &PanelUsername,
    container: &str,
    app_dir: &str,
    env_file: &str,
    port: u16,
    memory_mb: u32,
    image: &str,
    container_port: u16,
    cpus: &str,
    uid: u32,
    gid: u32,
    identifier: &str,
) -> String {
    format!(
        "[Unit]\n\
         Description=SNPanel container {app} ({user})\n\
         After=network-online.target docker.service\n\
         Requires=docker.service\n\
         \n\
         [Service]\n\
         Type=exec\n\
         ExecStartPre=-/usr/bin/docker rm -f {container}\n\
         ExecStart=/usr/bin/docker run --rm --name {container} \\\n\
         \x20 --user {uid}:{gid} \\\n\
         \x20 --publish 127.0.0.1:{port}:{container_port} \\\n\
         \x20 --env-file {env_file} \\\n\
         \x20 --env PORT={container_port} \\\n\
         \x20 --env HOST=0.0.0.0 \\\n\
         \x20 --volume {app_dir}:/app \\\n\
         \x20 --workdir /app \\\n\
         \x20 --memory {memory_mb}m \\\n\
         \x20 --memory-swap {memory_mb}m \\\n\
         \x20 --cpus {cpus} \\\n\
         \x20 --pids-limit 256 \\\n\
         \x20 --cap-drop ALL \\\n\
         \x20 --security-opt no-new-privileges \\\n\
         \x20 --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \\\n\
         \x20 {image}\n\
         ExecStop=/usr/bin/docker stop --time 20 {container}\n\
         Restart=always\n\
         RestartSec=5\n\
         TimeoutStartSec=300\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={identifier}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Source: the `case` on `$app_exec` in `write_node_app_unit`.
fn node_exec_start(
    exec: snpanel_ipc::NodeExec,
    bin_dir: &str,
    arg: &str,
) -> Result<String, String> {
    use snpanel_ipc::NodeExec::*;
    Ok(match exec {
        Node => format!("{bin_dir}/node {arg}"),
        Npm => format!("{bin_dir}/npm run --silent {arg}"),
        Npx => format!("{bin_dir}/npx --yes {arg}"),
        Yarn => {
            if std::path::Path::new(&format!("{bin_dir}/yarn")).is_file() {
                format!("{bin_dir}/yarn {arg}")
            } else if std::path::Path::new("/usr/local/bin/yarn").is_file() {
                format!("/usr/local/bin/yarn {arg}")
            } else {
                return Err("yarn is not installed; use npm instead".to_string());
            }
        }
    })
}

/// Source: `^[A-Za-z0-9._@/-]{1,120}$`.
fn check_start_arg(arg: &str) -> Result<(), String> {
    if arg.is_empty()
        || arg.len() > 120
        || !arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'/' | b'-'))
    {
        return Err(format!("invalid start argument: {arg}"));
    }
    Ok(())
}

/// `site-app-write`, for the node and docker runtimes.
pub fn write(
    user: &PanelUsername,
    app: &AppName,
    runtime: &snpanel_ipc::AppRuntime,
    port: u16,
    memory_mb: u32,
) -> HelperResponse {
    let ensured = dir_ensure(user, app);
    if !ensured.ok {
        return ensured;
    }
    let app_dir = app_directory(user, app);
    let env = env_file(user, app);
    let unit = unit_name(user, app);
    let unit_path = format!("/etc/systemd/system/{unit}.service");

    // The env file the unit loads. `EnvironmentFile=-` so a missing one is
    // not a startup failure.
    if let Some(parent) = std::path::Path::new(&env).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if !std::path::Path::new(&env).exists() {
        let _ = std::fs::write(&env, "");
    }
    let _ = exec::run(&["chown", "root:root", &env]);
    let _ = exec::run(&["chmod", "0600", &env]);

    let body = match runtime {
        snpanel_ipc::AppRuntime::Node {
            node_major,
            exec: start,
            arg,
        } => {
            if let Err(message) = check_start_arg(arg) {
                return HelperResponse::failed(HelperErrorKind::BadRequest, message);
            }
            let Some(bin) = node_bin_dir(*node_major) else {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    format!(
                        "Node {node_major} is not installed; run node-install {node_major} first"
                    ),
                );
            };
            let exec_start = match node_exec_start(*start, &bin, arg) {
                Ok(s) => s,
                Err(message) => return HelperResponse::failed(HelperErrorKind::NotFound, message),
            };
            node_unit_body(
                app,
                user,
                &app_dir,
                &env,
                port,
                memory_mb,
                &bin,
                &exec_start,
                &unit,
            )
        }
        snpanel_ipc::AppRuntime::Docker {
            image,
            container_port,
            cpus_centi,
        } => {
            if !docker_present() {
                return HelperResponse::failed(
                    HelperErrorKind::NotFound,
                    "Docker is not installed; run docker-install first".to_string(),
                );
            }
            let (uid, gid) = match uid_gid_of(user) {
                Some(pair) => pair,
                None => {
                    return HelperResponse::failed(
                        HelperErrorKind::NotFound,
                        format!("cannot resolve uid for {user}"),
                    )
                }
            };
            // Rendered from hundredths so the unit never carries a float that
            // was produced by rounding somewhere else.
            let cpus = format!("{}.{:02}", cpus_centi / 100, cpus_centi % 100);
            docker_unit_body(
                app,
                user,
                &container_name(user, app),
                &app_dir,
                &env,
                port,
                memory_mb,
                image.as_str(),
                container_port.get(),
                &cpus,
                uid,
                gid,
                &unit,
            )
        }
    };

    if let Err(e) = std::fs::write(&unit_path, body) {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            format!("writing {unit_path}: {e}"),
        );
    }
    let _ = exec::run(&["chown", "root:root", &unit_path]);
    let _ = exec::run(&["chmod", "0644", &unit_path]);
    let _ = exec::run(&["systemctl", "daemon-reload"]);
    HelperResponse::with_stdout(format!("{unit}\n"))
}

/// Source: `id -u` and `id -g`.
fn uid_gid_of(user: &PanelUsername) -> Option<(u32, u32)> {
    let out = exec::run(&["getent", "passwd", user.as_str()]).ok()?;
    let line = out.stdout.lines().next()?;
    let mut parts = line.split(':');
    let uid = parts.nth(2)?.parse().ok()?;
    let gid = parts.next()?.parse().ok()?;
    Some((uid, gid))
}

#[cfg(test)]
mod tests {
    /// The hardening directives the shell's unit template carried.
    ///
    /// Extracted from the `write_node_app_unit` heredoc - every line that was
    /// a directive with no interpolation in it - and frozen here when that
    /// script was deleted. The test compared against the script so a
    /// directive added there and forgotten here would fail rather than
    /// silently weaken one of the two units; with one writer left, the list
    /// is what keeps a directive from being dropped by accident.
    ///
    /// These are a sandbox. `ProtectSystem=strict` and `ProtectHome` are what
    /// stop a tenant's Node process reading another tenant's site.
    const SHELL_HARDENING: &str = include_str!("node-unit-directives.txt");

    #[test]
    fn the_node_unit_keeps_every_hardening_directive() {
        let body = node_unit_body(
            &AppName::parse("my-app").unwrap(),
            &PanelUsername::parse("bp_site").unwrap(),
            "/home/bp_site/apps/my-app",
            "/var/lib/snpanel/apps/bp_site-my-app.env",
            3000,
            512,
            "/opt/snpanel/node/22/bin",
            "/opt/snpanel/node/22/bin/node server.js",
            "snpanel-app-bp_site-my-app",
        );

        let mut checked = 0;
        for line in SHELL_HARDENING.lines().map(str::trim) {
            if line.is_empty() {
                continue;
            }
            assert!(
                body.contains(line),
                "the generated unit is missing `{line}`"
            );
            checked += 1;
        }
        // A fixture that stopped loading would make this pass by comparing
        // nothing at all.
        assert_eq!(checked, 27, "the fixture lost directives");
    }

    /// The node application cannot be handed a public interface.
    #[test]
    fn the_node_unit_forces_loopback_and_its_own_directory() {
        let body = node_unit_body(
            &AppName::parse("my-app").unwrap(),
            &PanelUsername::parse("bp_site").unwrap(),
            "/home/bp_site/apps/my-app",
            "/var/lib/snpanel/apps/bp_site-my-app.env",
            3000,
            512,
            "/usr/bin",
            "/usr/bin/node server.js",
            "snpanel-app-bp_site-my-app",
        );
        assert!(body.contains("Environment=HOST=127.0.0.1"), "{body}");
        assert!(body.contains("ProtectSystem=strict"), "{body}");
        assert!(
            body.contains("ReadWritePaths=/home/bp_site/apps/my-app"),
            "exactly one writable path, and it is the app's own: {body}"
        );
        assert!(body.contains("User=bp_site") && body.contains("Group=bp_site"));
        assert!(body.contains("MemoryMax=512M"));
    }

    /// The container's confinement, flag by flag.
    #[test]
    fn the_docker_unit_confines_the_container() {
        let body = docker_unit_body(
            &AppName::parse("my-app").unwrap(),
            &PanelUsername::parse("bp_site").unwrap(),
            "snpanel-bp_site-my-app",
            "/home/bp_site/apps/my-app",
            "/var/lib/snpanel/apps/bp_site-my-app.env",
            3000,
            512,
            "nginx:alpine",
            8080,
            "1.00",
            1001,
            1001,
            "snpanel-app-bp_site-my-app",
        );

        for required in [
            "--user 1001:1001",
            "--publish 127.0.0.1:3000:8080",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 256",
            "--memory 512m",
            "--memory-swap 512m",
        ] {
            assert!(body.contains(required), "missing `{required}`: {body}");
        }
        assert!(
            !body.contains("/var/run/docker.sock") && !body.contains("--privileged"),
            "the container must never reach the Docker socket: {body}"
        );
    }

    /// A start argument is narrow, because it lands in an ExecStart line.
    #[test]
    fn a_start_argument_cannot_carry_a_shell_fragment() {
        for good in [
            "server.js",
            "start",
            "@scope/pkg",
            "dist/main.js",
            "build.prod",
        ] {
            assert!(check_start_arg(good).is_ok(), "{good:?}");
        }
        for bad in ["", "a b", "a;b", "a$(id)", "a\nb", "a|b", &"x".repeat(121)] {
            assert!(check_start_arg(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// A path that leaves the backup tree is refused, however it leaves.
    #[test]
    fn a_backup_path_may_not_leave_the_backup_tree() {
        for (bad, why) in [
            ("", "empty"),
            ("/etc/passwd", "not under the root at all"),
            ("/var/backups/snpanel/../../etc/shadow", "traversal"),
            ("/var/backups/snpanel/a\nb", "a newline"),
            (
                "/var/backups/snpanelevil/x.tar",
                "a prefix that only looks right",
            ),
        ] {
            assert!(
                check_backup_path(bad).is_err(),
                "{bad:?} must be refused ({why})"
            );
        }
    }

    /// ...including through a symlinked directory inside it.
    ///
    /// This is the one a prefix check alone would let through: the path as
    /// written starts with the backup root, and only resolving the parent
    /// shows where it actually leads. The helper writes there as root.
    #[test]
    fn a_symlinked_backup_directory_is_refused() {
        let root = std::path::Path::new(BACKUP_ROOT);
        if std::fs::create_dir_all(root).is_err() {
            eprintln!("skipped: cannot create {BACKUP_ROOT}");
            return;
        }
        let elsewhere = std::env::temp_dir().join(format!("snpanel-escape-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&elsewhere);
        let link = root.join(format!("escape-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        if std::os::unix::fs::symlink(&elsewhere, &link).is_err() {
            eprintln!("skipped: cannot create the symlink");
            return;
        }

        let target = format!("{}/payload.tar", link.display());
        let verdict = check_backup_path(&target);

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&elsewhere);

        let err = verdict.expect_err("a symlinked parent must be refused");
        assert!(err.contains("escapes"), "{err}");
    }

    /// A real path inside the tree is accepted, so the guard is not simply
    /// refusing everything.
    #[test]
    fn a_path_inside_the_backup_tree_is_accepted() {
        let root = std::path::Path::new(BACKUP_ROOT);
        if std::fs::create_dir_all(root).is_err() {
            eprintln!("skipped: cannot create {BACKUP_ROOT}");
            return;
        }
        let target = format!("{BACKUP_ROOT}/app-{}.tar", std::process::id());
        assert!(
            check_backup_path(&target).is_ok(),
            "an ordinary backup path must be allowed"
        );
    }

    /// A volume in an export must belong to the application being restored.
    ///
    /// The names come out of an archive, which is a file somebody can edit.
    /// The prefix is what keeps one customer's import from writing into
    /// another customer's volume.
    #[test]
    fn a_volume_from_another_application_is_recognisable() {
        let user = PanelUsername::parse("bp_site").unwrap();
        let mine = AppName::parse("my-app").unwrap();
        let prefix = format!("{}_", container_name(&user, &mine));

        assert!(format!("{prefix}data").starts_with(&prefix));
        // Another user, and another application of the same user.
        let other_user = PanelUsername::parse("bp_other").unwrap();
        assert!(!"snpanel-bp_other-my-app_data".starts_with(&prefix));
        assert!(!"snpanel-bp_site-other-app_data".starts_with(&prefix));
        let _ = other_user;
    }

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
