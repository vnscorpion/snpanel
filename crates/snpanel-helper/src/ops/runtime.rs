//! `ops::runtime` - the container and Node runtimes the Application addon
//! installs on demand.
//!
//! Source: the `docker-*` and `node-*` arms of the bash helper.
//!
//! Every one of these has to answer on a box where nothing is installed. The
//! Application addon is off by default and installed only where it is wanted -
//! a server that hosts WordPress has no reason to carry a container runtime -
//! so "not installed" is a normal answer here and not a failure.

use std::path::Path;

use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

/// Source: the Node installation root the bash uses.
const NODE_ROOT: &str = "/opt/snpanel/node";

/// `node-list` - the Node majors installed under `/opt/snpanel/node`.
///
/// A directory only counts when `bin/node` is **executable**. A half-finished
/// download leaves the directory behind, and reporting it would offer a
/// customer a runtime that cannot start their application.
pub fn node_list() -> HelperResponse {
    let Ok(entries) = std::fs::read_dir(NODE_ROOT) else {
        // `[[ -d ... ]] || return 0` - no directory is an empty list, not an
        // error.
        return HelperResponse::with_stdout(String::new());
    };
    let mut majors: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let node = entry.path().join("bin/node");
        if !is_executable(&node) {
            continue;
        }
        majors.push(entry.file_name().to_string_lossy().into_owned());
    }
    // The bash iterates `"$dir"/*`, which the shell expands in sorted order.
    majors.sort();
    let mut out = majors.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    HelperResponse::with_stdout(out)
}

pub(crate) fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Is a command on the helper's `PATH`?
///
/// Source: `command -v <name> >/dev/null 2>&1`.
pub(crate) fn have(command: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    path.split(':')
        .filter(|dir| !dir.is_empty())
        .any(|dir| is_executable(&Path::new(dir).join(command)))
}

/// `docker-status`.
///
/// Answers `installed=no` and stops when Docker is absent - and exits **0**
/// doing so, because "is Docker here" is a question, not an operation that
/// failed.
pub fn docker_status() -> HelperResponse {
    if !have("docker") {
        return HelperResponse::with_stdout("installed=no\n".to_string());
    }
    let mut out = String::from("installed=yes\n");

    // `docker --version | head -n1`, and a failure is an empty value rather
    // than an error: the bash uses `$(... 2>/dev/null)` throughout here.
    let version = exec::run(&["docker", "--version"])
        .ok()
        .map(|o| o.stdout.lines().next().unwrap_or("").to_string())
        .unwrap_or_default();
    out.push_str(&format!("version={version}\n"));

    let active = exec::run(&["systemctl", "is-active", "docker"])
        .ok()
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
    out.push_str(&format!("active={active}\n"));

    // "Images are shared by every tenant on the box, so they cannot be billed
    // to one customer's quota; an administrator still has to see what they
    // cost."
    if let Ok(df) = exec::run(&[
        "docker",
        "system",
        "df",
        "--format",
        "{{.Type}}|{{.Size}}|{{.Reclaimable}}",
    ]) {
        for line in df.stdout.lines() {
            if !line.is_empty() {
                out.push_str(&format!("df={line}\n"));
            }
        }
    }
    HelperResponse::with_stdout(out)
}

/// `docker-prune`.
///
/// "Dangling layers and build cache only: nothing that a tagged image, a
/// volume or a container still refers to is touched." That restraint is the
/// whole point - a prune that took volumes would delete a customer's database.
pub fn docker_prune() -> HelperResponse {
    if !have("docker") {
        return HelperResponse::failed(
            HelperErrorKind::BadRequest,
            "Docker is not installed".to_string(),
        );
    }
    let mut out = String::new();
    // `|| true` on both: a prune that finds nothing to remove exits non-zero
    // on some versions, and that is not a failure of the request.
    for argv in [
        ["docker", "image", "prune", "-f"],
        ["docker", "builder", "prune", "-f"],
    ] {
        if let Ok(o) = exec::run(&argv) {
            out.push_str(&o.stdout);
            out.push_str(&o.stderr);
        }
    }
    out.push_str("--- remaining ---\n");
    if let Ok(df) = exec::run(&[
        "docker",
        "system",
        "df",
        "--format",
        "{{.Type}}|{{.Size}}|{{.Reclaimable}}",
    ]) {
        out.push_str(&df.stdout);
    }
    HelperResponse::with_stdout(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A box with no Node directory answers an empty list, not an error.
    ///
    /// The Application addon is off by default, so this is the common case and
    /// not an edge one.
    #[test]
    fn no_node_directory_is_an_empty_list() {
        // `/opt/snpanel/node` does not exist in the test environment.
        if Path::new(NODE_ROOT).exists() {
            return;
        }
        let resp = node_list();
        assert!(resp.ok);
        assert_eq!(resp.stdout, "");
    }

    /// `have` has to agree with `command -v`, including that a directory named
    /// like the command does not count.
    #[test]
    fn a_command_is_found_only_when_it_is_an_executable_file() {
        assert!(have("sh"), "sh should be on PATH");
        assert!(!have("definitely-not-a-real-command-xyzzy"));
        // A directory on PATH with the right name is not a command.
        assert!(!is_executable(Path::new("/usr")));
    }
}
