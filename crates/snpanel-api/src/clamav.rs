//! Optional malware scanning, through ClamAV.
//!
//! Source: `app/services/malware_scan.py`.
//!
//! **Optional on purpose.** The panel never depends on ClamAV being there:
//! when scanning is switched off, or the packages are absent, every call
//! here answers `disabled` and the upload proceeds. A port that turned a
//! missing scanner into an error would break every file upload on a machine
//! that never asked for scanning.
//!
//! The two answers that matter are read by two different parsers — one line
//! from a socket, or an exit code plus output from a binary — and both
//! decide whether a customer's upload is installed or thrown away. Getting
//! either wrong in the lenient direction means a real detection is reported
//! as an error and the file lands anyway.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Source: `ScanResult`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScanResult {
    Clean,
    Infected,
    Disabled,
    Error,
}

impl ScanResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Infected => "infected",
            Self::Disabled => "disabled",
            Self::Error => "error",
        }
    }
}

/// Source: `DEFAULT_SOCKET_PATHS`.
pub const DEFAULT_SOCKET_PATHS: &[&str] = &[
    "/run/clamav/clamd.sock",
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.sock",
    "/var/run/clamav/clamd.ctl",
];

/// Source: `_parse_scan_response`.
///
/// **The strip happens first**, and it changes the answer: `" FOUND"`
/// becomes `"FOUND"`, which no longer ends with `" FOUND"` and is therefore
/// an error rather than a detection with no signature. Same for `" OK"`.
/// A line with only the word is not a verdict about anything.
///
/// The signature is everything after the **last** `": "`, so a signature
/// that itself contains a colon keeps only its tail — which is what the
/// Python does and what the page displays.
pub fn parse_scan_response(response: &str) -> (ScanResult, String) {
    let response = response.trim();
    if response.ends_with(" OK") {
        return (ScanResult::Clean, "no threats found".to_string());
    }
    if response.ends_with(" FOUND") {
        let tail = response.rsplit(": ").next().unwrap_or(response);
        let signature = tail.strip_suffix(" FOUND").unwrap_or(tail).trim();
        let signature = if signature.is_empty() {
            "unknown"
        } else {
            signature
        };
        return (ScanResult::Infected, signature.to_string());
    }
    if response.contains(" ERROR") || response.ends_with("ERROR") {
        let detail = if response.is_empty() {
            "clamd scan failed"
        } else {
            response
        };
        return (ScanResult::Error, detail.to_string());
    }
    if response.is_empty() {
        return (
            ScanResult::Error,
            "clamd returned an empty response".to_string(),
        );
    }
    (ScanResult::Error, response.to_string())
}

/// What `_scan_file_clamscan` reports about one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClamscanReport {
    pub status: ScanResult,
    pub path: String,
    pub signature: String,
    pub detail: String,
}

/// Source: `_scan_file_clamscan`, given what the binary said.
///
/// `clamscan` uses its **exit code** as the verdict: 0 clean, 1 infected,
/// anything else an error. The output is only searched for the signature
/// name, and an exit code of 1 with nothing parsable is still infected —
/// "unknown" is the right answer there, because trusting the output over
/// the exit code would turn a detection into a clean file.
pub fn parse_clamscan(returncode: i32, stdout: &str, stderr: &str, path: &str) -> ClamscanReport {
    // `"\n".join(part for part in (stdout, stderr) if part).strip()`.
    let parts: Vec<&str> = [stdout, stderr]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect();
    let output = parts.join("\n").trim().to_string();

    if returncode == 0 {
        return ClamscanReport {
            status: ScanResult::Clean,
            path: path.to_string(),
            signature: String::new(),
            detail: output,
        };
    }
    if returncode == 1 {
        let mut signature = "unknown".to_string();
        for line in output.lines() {
            let line = line.trim();
            if line.contains(": ") && line.ends_with(" FOUND") {
                let tail = line.rsplit(": ").next().unwrap_or(line);
                // `.replace(" FOUND", "")` — every occurrence, not just the
                // suffix, which is what the Python asks for.
                let candidate = tail.replace(" FOUND", "");
                let candidate = candidate.trim();
                if !candidate.is_empty() {
                    signature = candidate.to_string();
                }
                break;
            }
        }
        return ClamscanReport {
            status: ScanResult::Infected,
            path: path.to_string(),
            signature,
            detail: output,
        };
    }
    let detail = if output.is_empty() {
        "clamscan failed".to_string()
    } else {
        output
    };
    ClamscanReport {
        status: ScanResult::Error,
        path: path.to_string(),
        signature: String::new(),
        detail,
    }
}

/// Source: `_scan_path_oneshot` — what the caller makes of a report.
pub fn oneshot_verdict(report: &ClamscanReport) -> (ScanResult, String) {
    match report.status {
        ScanResult::Clean => (ScanResult::Clean, "no threats found".to_string()),
        ScanResult::Infected => (ScanResult::Infected, report.signature.clone()),
        _ => {
            let detail = if report.detail.is_empty() {
                "clamscan failed".to_string()
            } else {
                report.detail.clone()
            };
            (ScanResult::Error, detail)
        }
    }
}

/// Source: `_read_clamd_response`.
///
/// clamd terminates its answer with a NUL (the `z` command prefix asks for
/// that) or a newline, and the reader stops at whichever arrives — it does
/// **not** read to end of stream, because the daemon keeps the connection
/// open for the next command.
fn read_clamd_response(stream: &mut UnixStream) -> String {
    let mut collected: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                collected.extend_from_slice(&buf[..n]);
                if matches!(buf[n - 1], b'\0' | b'\n') {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    while matches!(collected.last(), Some(b'\0' | b'\r' | b'\n')) {
        collected.pop();
    }
    String::from_utf8_lossy(&collected).into_owned()
}

/// Source: `_ping_socket` — `zPING` answered with `PONG`.
pub fn ping_socket(path: &str) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else {
        return false;
    };
    let timeout = Some(Duration::from_secs(2));
    if stream.set_read_timeout(timeout).is_err() || stream.set_write_timeout(timeout).is_err() {
        return false;
    }
    if stream.write_all(b"zPING\0").is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    let mut response = &buf[..n];
    while matches!(response.last(), Some(b'\0' | b'\r' | b'\n')) {
        response = &response[..response.len() - 1];
    }
    response == b"PONG"
}

/// Source: `_socket_candidates` — the configured path first, then the ones
/// the distributions use, with duplicates dropped in order.
pub fn socket_candidates(configured: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for candidate in std::iter::once(configured).chain(DEFAULT_SOCKET_PATHS.iter().copied()) {
        if candidate.is_empty() || seen.iter().any(|s| s == candidate) {
            continue;
        }
        seen.push(candidate.to_string());
    }
    seen
}

/// Source: `_responsive_socket_path` — the first one that answers `PONG`.
pub fn responsive_socket_path(configured: &str) -> Option<String> {
    socket_candidates(configured)
        .into_iter()
        .find(|path| Path::new(path).exists() && ping_socket(path))
}

/// Source: `clamav_installed`.
pub fn clamav_installed() -> bool {
    which("clamd").is_some() || which("clamscan").is_some()
}

/// `shutil.which`, for a bare command name.
fn which(command: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    path.split(':')
        .map(|dir| Path::new(dir).join(command))
        .find(|candidate| candidate.is_file())
}

/// Source: `engine_available` — something that can actually run a scan.
///
/// The resident daemon is **not** required: LMD drives one-shot `clamscan`,
/// so a box with the binary and no daemon still scans. Requiring the daemon
/// would silently stop scanning uploads on every machine that installed
/// maldet and nothing else.
pub fn engine_available(configured_socket: &str) -> bool {
    crate::malware::maldet_installed()
        || clamav_installed()
        || responsive_socket_path(configured_socket).is_some()
}

/// Whether the resident daemon is installed - `clamd`, which is what
/// `clamav-daemon` adds to the `clamscan` the scanner install brings.
pub fn clamd_installed() -> bool {
    which("clamd").is_some()
}

/// Source: `is_available` — enabled in the settings **and** able to scan.
///
/// Not in the Python: **and upload scanning switched on.** Everything that
/// asks this is the File Manager's upload path; the scheduled and real-time
/// scans have their own switches and do not come here.
pub fn is_available(env_default: bool, configured_socket: &str) -> bool {
    crate::malware::persisted_enabled(env_default)
        && crate::malware::persisted_upload_scan()
        && engine_available(configured_socket)
}

/// Source: `scan_stream` — scan bytes, however the machine can.
///
/// `pyclamd` is an optional dependency and is **not** installed in the
/// panel's virtualenv, so the Python always takes the hand-written
/// `_scan_stream_clamd` path. This is that path; the `pyclamd` branch
/// beside it in the Python is unreachable on a real installation.
pub fn scan_bytes(env_default: bool, configured_socket: &str, data: &[u8]) -> (ScanResult, String) {
    if !is_available(env_default, configured_socket) {
        return (
            ScanResult::Disabled,
            "malware scanning is disabled".to_string(),
        );
    }
    match responsive_socket_path(configured_socket) {
        Some(path) => scan_stream_clamd(&path, data),
        // No resident daemon, which is the default now.
        None => scan_bytes_oneshot(data),
    }
}

/// Source: `_scan_bytes_oneshot` — write the bytes out and run `clamscan`.
fn scan_bytes_oneshot(data: &[u8]) -> (ScanResult, String) {
    let path = std::env::temp_dir().join(format!(
        "snpanel-scan-{}-{}",
        std::process::id(),
        crate::file_jobs::new_job_id()
    ));
    if std::fs::write(&path, data).is_err() {
        return (ScanResult::Error, "clamscan failed".to_string());
    }
    let report = run_clamscan(&path.to_string_lossy());
    let _ = std::fs::remove_file(&path);
    oneshot_verdict(&report)
}

/// Source: `_scan_file_clamscan` — the subprocess half.
fn run_clamscan(path: &str) -> ClamscanReport {
    let output = std::process::Command::new("clamscan")
        .args(["--infected", "--no-summary", path])
        .output();
    match output {
        Ok(output) => parse_clamscan(
            output.status.code().unwrap_or(-1),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
            path,
        ),
        Err(_) => ClamscanReport {
            status: ScanResult::Error,
            path: path.to_string(),
            signature: String::new(),
            detail: "clamscan is not installed".to_string(),
        },
    }
}

/// Source: `_scan_before_install`.
///
/// **A scan that cannot run is not a refusal.** Only `infected` stops the
/// upload; `disabled` is the normal state of a machine that never asked for
/// scanning, and `error` is logged and passed — which is the Python's
/// choice and the right one, because a broken scanner must not become a
/// broken file manager.
pub fn scan_before_install(
    env_default: bool,
    configured_socket: &str,
    data: &[u8],
    filename: &str,
) -> Result<(), String> {
    if !is_available(env_default, configured_socket) {
        return Ok(());
    }
    let (result, detail) = scan_bytes(env_default, configured_socket, data);
    match result {
        ScanResult::Infected => Err(format!("Malware detected ({detail}). File rejected.")),
        other => {
            // `logging.warning("Malware scan error for %s: %s", ...)`, with
            // the verdict named: "disabled" and "error" both end here and
            // an operator reading the log needs to know which.
            if other == ScanResult::Error {
                tracing::warn!("malware scan {} for {filename}: {detail}", other.as_str());
            }
            Ok(())
        }
    }
}

/// Source: `_scan_stream_clamd` — `zINSTREAM`, then length-prefixed chunks,
/// then a zero length.
///
/// The length is **four bytes, big-endian**, and the terminating zero is
/// what tells clamd the file is complete; without it the daemon waits for
/// its timeout and the upload hangs rather than failing.
pub fn scan_stream_clamd(socket_path: &str, data: &[u8]) -> (ScanResult, String) {
    let Ok(mut stream) = UnixStream::connect(socket_path) else {
        return (ScanResult::Error, "clamd scan failed".to_string());
    };
    let timeout = Some(Duration::from_secs(120));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);
    let mut send = || -> std::io::Result<()> {
        stream.write_all(b"zINSTREAM\0")?;
        for chunk in data.chunks(1024 * 1024) {
            stream.write_all(&(chunk.len() as u32).to_be_bytes())?;
            stream.write_all(chunk)?;
        }
        stream.write_all(&0u32.to_be_bytes())?;
        Ok(())
    };
    if let Err(e) = send() {
        return (ScanResult::Error, format!("clamd scan failed: {e}"));
    }
    parse_scan_response(&read_clamd_response(&mut stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn corpus() -> Value {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/clamav.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the clamav corpus"))
            .expect("the corpus parses")
    }

    /// Every line clamd might answer with, and what the panel makes of it.
    ///
    /// The one that catches a careless port is `" FOUND"`. The response is
    /// **stripped first**, so it becomes `"FOUND"`, which no longer ends
    /// with `" FOUND"` — an error, not a detection with no name. A port
    /// that tested the suffix before stripping would call it infected, and
    /// one that stripped only the right-hand side would too.
    #[test]
    fn a_clamd_answer_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let cases = corpus["parse_scan_response"].as_array().expect("the cases");
        assert_eq!(cases.len(), 24, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for case in cases {
            let response = case["response"].as_str().unwrap_or("");
            let want_result = case["result"].as_str().unwrap_or("");
            let want_detail = case["detail"].as_str().unwrap_or("");
            let (result, detail) = parse_scan_response(response);
            seen.insert(want_result.to_string());
            if result.as_str() != want_result || detail != want_detail {
                failures.push(format!(
                    "{response:?}\n  python {want_result} {want_detail:?}\n  rust   {} {detail:?}",
                    result.as_str()
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        // Clean, infected and error are all represented; a corpus of one
        // verdict would agree with a parser that only ever gave it.
        assert!(seen.contains("clean") && seen.contains("infected") && seen.contains("error"));

        // The three that a reading of the code gets wrong.
        assert_eq!(parse_scan_response(" FOUND").0, ScanResult::Error);
        assert_eq!(parse_scan_response(" OK").0, ScanResult::Error);
        assert_eq!(
            parse_scan_response("stream: Foo: Bar FOUND").1,
            "Bar",
            "the signature is everything after the *last* `: `"
        );
    }

    /// The binary's exit code is the verdict; its output is only the name.
    ///
    /// An exit code of 1 with nothing parsable is still **infected**, and
    /// the signature is "unknown". Trusting the output over the exit code
    /// would turn a detection into a clean file, which is the one direction
    /// this must never fail in.
    #[test]
    fn a_clamscan_run_is_read_the_way_python_reads_it() {
        let corpus = corpus();
        let cases = corpus["clamscan"].as_array().expect("the cases");
        assert_eq!(cases.len(), 14, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut infected = 0usize;
        for case in cases {
            let label = case["label"].as_str().unwrap_or("");
            let code = case["returncode"].as_i64().unwrap_or(0) as i32;
            let stdout = case["stdout"].as_str().unwrap_or("");
            let stderr = case["stderr"].as_str().unwrap_or("");
            let got = parse_clamscan(code, stdout, stderr, "/tmp/x");
            let want = &case["result"];
            if got.status.as_str() != want["status"].as_str().unwrap_or("")
                || got.signature != want["signature"].as_str().unwrap_or("")
                || got.detail != want["detail"].as_str().unwrap_or("")
                || got.path != want["path"].as_str().unwrap_or("")
            {
                failures.push(format!("{label}\n  python {want}\n  rust   {got:?}"));
            }
            if got.status == ScanResult::Infected {
                infected += 1;
            }

            let (result, detail) = oneshot_verdict(&got);
            let want_oneshot = &case["oneshot"];
            if result.as_str() != want_oneshot["result"].as_str().unwrap_or("")
                || detail != want_oneshot["detail"].as_str().unwrap_or("")
            {
                failures.push(format!(
                    "{label} /oneshot\n  python {want_oneshot}\n  rust   {} {detail:?}",
                    result.as_str()
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(infected >= 5, "only {infected} infected cases");

        // Exit code 1 and nothing to read: still infected.
        let blind = parse_clamscan(1, "", "", "/tmp/x");
        assert_eq!(blind.status, ScanResult::Infected);
        assert_eq!(blind.signature, "unknown");
        // And an exit code nobody documents is an error, not a clean file.
        assert_eq!(
            parse_clamscan(42, "", "", "/tmp/x").status,
            ScanResult::Error
        );
    }

    /// What `clamscan` not running at all looks like.
    #[test]
    fn a_missing_binary_is_an_error_and_not_a_clean_file() {
        let corpus = corpus();
        for case in corpus["oneshot"].as_array().expect("the cases") {
            let want = &case["result"];
            assert_eq!(want["status"].as_str(), Some("error"), "{}", case["label"]);
            assert_eq!(want["signature"].as_str(), Some(""));
        }
        // The port reaches the same place: a report it could not run.
        let report = ClamscanReport {
            status: ScanResult::Error,
            path: "/tmp/x".to_string(),
            signature: String::new(),
            detail: "clamscan is not installed".to_string(),
        };
        assert_eq!(
            oneshot_verdict(&report),
            (ScanResult::Error, "clamscan is not installed".to_string())
        );
        // An error with nothing to say still says something.
        let bare = ClamscanReport {
            status: ScanResult::Error,
            path: "/tmp/x".to_string(),
            signature: String::new(),
            detail: String::new(),
        };
        assert_eq!(
            oneshot_verdict(&bare),
            (ScanResult::Error, "clamscan failed".to_string())
        );
    }

    /// Which sockets are tried, in which order.
    #[test]
    fn the_configured_socket_is_tried_before_the_distribution_ones() {
        let corpus = corpus();
        let defaults: Vec<&str> = corpus["socket_candidates_default"]
            .as_array()
            .expect("the defaults")
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect();
        assert_eq!(defaults, DEFAULT_SOCKET_PATHS.to_vec());

        let configured = socket_candidates("/custom/clamd.sock");
        assert_eq!(configured[0], "/custom/clamd.sock");
        assert_eq!(configured.len(), DEFAULT_SOCKET_PATHS.len() + 1);

        // An empty setting is not a candidate.
        assert_eq!(socket_candidates("").len(), DEFAULT_SOCKET_PATHS.len());
        // And a setting that repeats a default does not appear twice: the
        // order matters, so a duplicate would make the same dead socket be
        // probed twice before the live one is reached.
        let duplicate = socket_candidates("/run/clamav/clamd.sock");
        assert_eq!(duplicate.len(), DEFAULT_SOCKET_PATHS.len());
        assert_eq!(duplicate[0], "/run/clamav/clamd.sock");
    }
}
