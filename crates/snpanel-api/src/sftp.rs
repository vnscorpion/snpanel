//! Pushing a backup to a customer's own SFTP host.
//!
//! The only operation in the panel that carries a customer's data off this
//! machine, which is why the host key handling is the part written out at
//! length rather than the transfer.
//!
//! Two modes, and the difference matters:
//!
//! * **Pinned.** A fingerprint has been stored for this target. The key the
//!   server presents is compared against it and the connection is dropped on
//!   a mismatch. The pin is the whole protection here — nothing else tells
//!   the panel it is talking to the host the operator meant.
//! * **Bootstrap (TOFU).** No fingerprint yet. The key is accepted and handed
//!   back for the caller to store, so the *next* upload is pinned. This is a
//!   real window and it is the Python's: the first connection to a target is
//!   trusted, every one after it is checked.
//!
//! The panel deliberately does **not** read the system's `known_hosts`: the
//! daemon runs as a service account with no interactive history, and trusting
//! whatever is in its file would defeat the pinning.
//!
//! Source: `backup.upload_to_sftp` and the two helpers beside it.

use std::path::Path;
use std::sync::Arc;

use russh::keys::{HashAlg, PublicKeyOrCertificate};

/// Source: `paramiko`'s `timeout`, `banner_timeout` and `auth_timeout`, all
/// twenty seconds.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[derive(Debug)]
pub enum SftpError {
    /// The local file is not there. `FileNotFoundError` in the Python.
    LocalMissing,
    /// Neither a password nor a key was configured.
    NoCredentials,
    /// The server presented a key that is not the pinned one. Its own error
    /// class in the Python, because the caller reports it differently: this
    /// is not a failed upload, it is a host that is not who it claims.
    HostKeyMismatch(String),
    Failed(String),
}

impl std::fmt::Display for SftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalMissing => write!(f, "Local backup file not found"),
            Self::NoCredentials => write!(f, "SFTP password or private key is required"),
            Self::HostKeyMismatch(message) => write!(f, "{message}"),
            Self::Failed(message) => write!(f, "{message}"),
        }
    }
}

/// Where the archive is going, and what the panel already knows about it.
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub remote_path: &'a str,
    pub password: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub expected_host_key_type: Option<&'a str>,
    pub expected_host_key_fingerprint: Option<&'a str>,
}

/// The host key a connection ends with, for the caller to pin when the
/// target had none.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostKey {
    pub host_key_type: String,
    pub host_key_fingerprint: String,
}

/// What the upload learned, which the caller has to persist for the pin to
/// mean anything next time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub remote_file: String,
    pub host_key_type: String,
    pub host_key_fingerprint: String,
}

/// The handler that decides whether to go on talking to this server.
struct Pinned {
    expected: Option<String>,
    /// Filled in by `check_server_key`, read by the caller afterwards.
    seen: Arc<std::sync::Mutex<Option<(String, String)>>>,
}

impl russh::client::Handler for Pinned {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            // A host certificate is something the panel has no way to pin,
            // so it is refused rather than accepted unverified.
            return Ok(false);
        };
        let kind = key.algorithm().to_string();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some((kind, fingerprint.clone()));
        }
        // On the pinned path the comparison happens here, **before** any
        // authentication bytes are sent — a mismatch must not be a host that
        // got to see the password first.
        Ok(match &self.expected {
            Some(pinned) => constant_time_eq(pinned.as_bytes(), fingerprint.as_bytes()),
            None => true,
        })
    }
}

/// The fingerprint comparison, in constant time.
///
/// It is public data on both sides, so this is not strictly necessary — but
/// it costs nothing and the habit is worth more than the argument.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).into()
}

/// `posixpath.normpath(path.strip() or ".")`.
pub fn normalise_remote_dir(remote_path: &str) -> String {
    let text = remote_path.trim();
    if text.is_empty() {
        return ".".to_string();
    }
    // `initial_slashes`: POSIX leaves a path beginning with **exactly two**
    // slashes implementation-defined, and `normpath` keeps both. Three or
    // more collapse to one. Found by the corpus, not by reading.
    let leading = if !text.starts_with('/') {
        0
    } else if text.starts_with("///") {
        1
    } else if text.starts_with("//") {
        2
    } else {
        1
    };
    let absolute = leading > 0;
    let mut parts: Vec<&str> = Vec::new();
    for piece in text.split('/') {
        match piece {
            "" | "." => {}
            ".." => {
                // `normpath` cancels `..` against the part before it, but a
                // leading one on a relative path survives — there is nothing
                // above it to cancel.
                match parts.last() {
                    Some(&last) if last != ".." => {
                        parts.pop();
                    }
                    _ if absolute => {}
                    _ => parts.push(".."),
                }
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return if absolute {
            "/".repeat(leading)
        } else {
            ".".to_string()
        };
    }
    let body = parts.join("/");
    if absolute {
        format!("{}{body}", "/".repeat(leading))
    } else {
        body
    }
}

/// `posixpath.join(remote_dir, name)`.
pub fn remote_file_path(remote_dir: &str, name: &str) -> String {
    if remote_dir == "/" {
        format!("/{name}")
    } else if remote_dir == "." {
        // `posixpath.join(".", "x")` is `./x`.
        format!("./{name}")
    } else {
        format!("{remote_dir}/{name}")
    }
}

/// The directories `_ensure_remote_dir` walks down, in order.
///
/// `.` and `/` are not made: one is where we already are and the other is
/// somebody else's problem.
pub fn remote_dir_chain(remote_dir: &str) -> Vec<String> {
    let remote_dir = normalise_remote_dir(remote_dir);
    if remote_dir == "." || remote_dir == "/" {
        return Vec::new();
    }
    // An absolute path starts from the empty string and picks up its leading
    // slash from the first join; a relative one starts from `.`, which is
    // what `posixpath.join(".", part)` gives back.
    let mut current = if remote_dir.starts_with('/') {
        String::new()
    } else {
        ".".to_string()
    };
    let mut chain = Vec::new();
    for part in remote_dir.split('/').filter(|part| !part.is_empty()) {
        current = format!("{current}/{part}");
        chain.push(current.clone());
    }
    chain
}

/// An open SFTP session, with what the handshake learned about the host.
///
/// The SSH handle is kept beside the session: dropping it closes the
/// connection underneath the session.
struct Open {
    _ssh: russh::client::Handle<Pinned>,
    sftp: russh_sftp::client::SftpSession,
    seen: Arc<std::sync::Mutex<Option<(String, String)>>>,
}

/// Connect, check the host key, sign in and start SFTP.
async fn open(target: &Target<'_>) -> Result<Open, SftpError> {
    let has_password = target.password.is_some_and(|text| !text.is_empty());
    let has_key = target.private_key.is_some_and(|text| !text.is_empty());
    if !has_password && !has_key {
        return Err(SftpError::NoCredentials);
    }

    // `_load_private_key`: the passphrase is the configured password, which
    // is why a target may carry both.
    let key = match target.private_key.filter(|text| !text.is_empty()) {
        Some(text) => Some(
            russh::keys::decode_secret_key(text, target.password.filter(|p| !p.is_empty()))
                .map_err(|e| SftpError::Failed(format!("Cannot load SFTP private key: {e}")))?,
        ),
        None => None,
    };

    let seen = Arc::new(std::sync::Mutex::new(None));
    let handler = Pinned {
        expected: target
            .expected_host_key_fingerprint
            .filter(|text| !text.is_empty())
            .map(str::to_string),
        seen: seen.clone(),
    };
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(TIMEOUT),
        ..russh::client::Config::default()
    });

    let connect = russh::client::connect(config, (target.host, target.port), handler);
    let mut session = match tokio::time::timeout(TIMEOUT, connect).await {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => return Err(host_key_or_failure(target, &seen, e)),
        Err(_) => {
            return Err(SftpError::Failed(format!(
                "SFTP connection to {}:{} timed out",
                target.host, target.port
            )))
        }
    };

    // `pkey` wins when there is one: the Python passes `password=None` in
    // that case, so a target with both does not fall back to the password.
    let authenticated = match key {
        Some(key) => {
            let with_hash = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
            session
                .authenticate_publickey(target.username, with_hash)
                .await
        }
        None => {
            session
                .authenticate_password(target.username, target.password.unwrap_or_default())
                .await
        }
    };
    match authenticated {
        Ok(result) if result.success() => {}
        Ok(_) => {
            return Err(SftpError::Failed(format!(
                "SFTP authentication failed for {}@{}",
                target.username, target.host
            )))
        }
        Err(e) => {
            return Err(SftpError::Failed(format!(
                "SFTP authentication failed: {e}"
            )))
        }
    }

    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| SftpError::Failed(format!("Cannot open the SFTP channel: {e}")))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| SftpError::Failed(format!("The server refused the SFTP subsystem: {e}")))?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| SftpError::Failed(format!("Cannot start the SFTP session: {e}")))?;
    Ok(Open {
        _ssh: session,
        sftp,
        seen,
    })
}

/// The host key the caller persists. A pinned target keeps the pin it had -
/// the key matched, so re-recording it would only be a chance to record it
/// wrong; one that had none gets the key this connection saw.
fn host_key_to_keep(
    target: &Target<'_>,
    seen: &Arc<std::sync::Mutex<Option<(String, String)>>>,
) -> HostKey {
    let (seen_type, seen_fingerprint) = seen
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .unwrap_or_default();
    match target
        .expected_host_key_fingerprint
        .filter(|f| !f.is_empty())
    {
        Some(pinned) => HostKey {
            host_key_type: target
                .expected_host_key_type
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .unwrap_or(seen_type),
            host_key_fingerprint: pinned.to_string(),
        },
        None => HostKey {
            host_key_type: seen_type,
            host_key_fingerprint: seen_fingerprint,
        },
    }
}

/// Upload `local_file` to the target, and report the key that was seen.
pub async fn upload(local_file: &str, target: &Target<'_>) -> Result<Uploaded, SftpError> {
    let local_path = crate::files::resolve(Path::new(local_file));
    if !local_path.is_file() {
        return Err(SftpError::LocalMissing);
    }
    let name = local_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let remote_dir = normalise_remote_dir(target.remote_path);
    let remote_file = remote_file_path(&remote_dir, &name);

    let open = open(target).await?;
    let sftp = &open.sftp;
    for directory in remote_dir_chain(&remote_dir) {
        // `except IOError: pass` — a directory that is already there is the
        // normal case, not a failure.
        let _ = sftp.create_dir(directory).await;
    }

    // Streamed, not read whole first: an archive is the size of a customer's
    // sites and databases, and the scheduler sends one for every user.
    let local = tokio::fs::File::open(&local_path)
        .await
        .map_err(|e| SftpError::Failed(format!("Cannot read the backup file: {e}")))?;
    let mut remote = sftp
        .create(remote_file.clone())
        .await
        .map_err(|e| SftpError::Failed(format!("Cannot create {remote_file}: {e}")))?;
    {
        use tokio::io::AsyncWriteExt;
        let mut local = tokio::io::BufReader::with_capacity(256 * 1024, local);
        tokio::io::copy_buf(&mut local, &mut remote)
            .await
            .map_err(|e| SftpError::Failed(format!("Cannot write {remote_file}: {e}")))?;
        remote
            .shutdown()
            .await
            .map_err(|e| SftpError::Failed(format!("Cannot finish {remote_file}: {e}")))?;
    }

    let key = host_key_to_keep(target, &open.seen);
    Ok(Uploaded {
        remote_file,
        host_key_type: key.host_key_type,
        host_key_fingerprint: key.host_key_fingerprint,
    })
}

/// The file the destination test writes and removes again.
pub const CHECK_FILE: &str = ".snpanel-write-test";

/// Whether the destination takes a backup: signed in, the folder made if it
/// is missing, one small file written and removed. `removed` is false when
/// the account may write but not delete.
pub async fn check(target: &Target<'_>) -> Result<(bool, HostKey), SftpError> {
    let remote_dir = normalise_remote_dir(target.remote_path);
    let open = open(target).await?;
    let sftp = &open.sftp;
    for directory in remote_dir_chain(&remote_dir) {
        let _ = sftp.create_dir(directory).await;
    }
    let probe = remote_file_path(&remote_dir, CHECK_FILE);
    {
        use tokio::io::AsyncWriteExt;
        let mut file = sftp
            .create(probe.clone())
            .await
            .map_err(|e| SftpError::Failed(format!("Cannot write in {remote_dir}: {e}")))?;
        file.write_all(b"SNPanel can write backups here.\n")
            .await
            .map_err(|e| SftpError::Failed(format!("Cannot write in {remote_dir}: {e}")))?;
        file.shutdown()
            .await
            .map_err(|e| SftpError::Failed(format!("Cannot write in {remote_dir}: {e}")))?;
    }
    let removed = sftp.remove_file(probe).await.is_ok();
    Ok((removed, host_key_to_keep(target, &open.seen)))
}

/// One archive in the destination's folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteArchive {
    pub name: String,
    pub size: u64,
    /// Seconds since the epoch, when the server says.
    pub modified: Option<u32>,
}

/// The `.tar.gz` files directly in the destination's folder - not in folders
/// under it, and not links, which could point anywhere on that server.
pub async fn list(target: &Target<'_>) -> Result<(Vec<RemoteArchive>, HostKey), SftpError> {
    let remote_dir = normalise_remote_dir(target.remote_path);
    let open = open(target).await?;
    let entries = open
        .sftp
        .read_dir(remote_dir.clone())
        .await
        .map_err(|e| SftpError::Failed(format!("Cannot list {remote_dir}: {e}")))?;
    let mut found: Vec<RemoteArchive> = entries
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            let metadata = entry.metadata();
            RemoteArchive {
                name: entry.file_name(),
                size: metadata.size.unwrap_or(0),
                modified: metadata.mtime,
            }
        })
        .filter(|archive| archive_name_ok(&archive.name))
        .collect();
    found.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok((found, host_key_to_keep(target, &open.seen)))
}

/// A name the restore may fetch: one file in the folder, an archive, and
/// nothing that could step out of it.
pub fn archive_name_ok(name: &str) -> bool {
    name.ends_with(".tar.gz")
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// One archive from the destination's folder into `dest`, streamed. `dest`
/// must not exist yet; it is removed again if the transfer fails, or if the
/// server sends more than `max_bytes`.
pub async fn download(
    target: &Target<'_>,
    name: &str,
    dest: &Path,
    max_bytes: u64,
) -> Result<(u64, HostKey), SftpError> {
    if !archive_name_ok(name) {
        return Err(SftpError::Failed(format!("Not a backup archive: {name}")));
    }
    let remote_dir = normalise_remote_dir(target.remote_path);
    let remote_file = remote_file_path(&remote_dir, name);
    let open = open(target).await?;
    let remote = open
        .sftp
        .open(remote_file.clone())
        .await
        .map_err(|e| SftpError::Failed(format!("Cannot read {remote_file}: {e}")))?;
    let local = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .await
        .map_err(|e| SftpError::Failed(format!("Cannot write {}: {e}", dest.display())))?;
    let copied = async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // One byte past the limit is enough to know the server sent too much.
        let mut limited =
            tokio::io::BufReader::with_capacity(256 * 1024, remote).take(max_bytes + 1);
        let mut local = tokio::io::BufWriter::with_capacity(256 * 1024, local);
        let written = tokio::io::copy_buf(&mut limited, &mut local)
            .await
            .map_err(|e| SftpError::Failed(format!("Cannot read {remote_file}: {e}")))?;
        if written > max_bytes {
            return Err(SftpError::Failed(format!(
                "{name} is larger than {max_bytes} bytes"
            )));
        }
        local
            .flush()
            .await
            .map_err(|e| SftpError::Failed(format!("Cannot write {}: {e}", dest.display())))?;
        Ok(written)
    }
    .await;
    match copied {
        Ok(written) => Ok((written, host_key_to_keep(target, &open.seen))),
        Err(e) => {
            let _ = tokio::fs::remove_file(dest).await;
            Err(e)
        }
    }
}

/// A connection that failed after the key was seen and rejected is a pin
/// mismatch, and says so; anything else is an ordinary failure.
fn host_key_or_failure(
    target: &Target<'_>,
    seen: &Arc<std::sync::Mutex<Option<(String, String)>>>,
    error: russh::Error,
) -> SftpError {
    let Some(expected) = target
        .expected_host_key_fingerprint
        .filter(|text| !text.is_empty())
    else {
        return SftpError::Failed(format!("SFTP connection failed: {error}"));
    };
    let Some((kind, fingerprint)) = seen.lock().ok().and_then(|slot| slot.clone()) else {
        return SftpError::Failed(format!("SFTP connection failed: {error}"));
    };
    if fingerprint == expected {
        return SftpError::Failed(format!("SFTP connection failed: {error}"));
    }
    SftpError::HostKeyMismatch(format!(
        "SFTP host key mismatch for {}: expected {} {expected}, got {kind} {fingerprint}",
        target.host,
        target.expected_host_key_type.unwrap_or("?"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/sftp.json"
        ))
        .expect("the corpus");
        serde_json::from_str(&text).expect("the corpus parses")
    }

    #[test]
    fn only_a_plain_archive_name_is_fetched() {
        for good in [
            "user-alice-20260925020000.tar.gz",
            "alice.tar.gz",
            "alice-monday.tar.gz",
        ] {
            assert!(archive_name_ok(good), "{good}");
        }
        for bad in [
            "../alice.tar.gz",
            "dir/alice.tar.gz",
            ".hidden.tar.gz",
            "alice.zip",
            "alice.tar.gz\0x",
            "a\\b.tar.gz",
            "",
        ] {
            assert!(!archive_name_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_remote_path_is_normalised_the_way_python_normalises_it() {
        let corpus = corpus();
        let cases = corpus["normpath"].as_array().expect("the cases");
        assert_eq!(cases.len(), 22, "the corpus changed size");
        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().expect("the text");
            let got = normalise_remote_dir(raw);
            let want = case["value"].as_str().expect("the value");
            if got != want {
                failures.push(format!("{raw:?}: want {want:?}, got {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_remote_file_is_joined_the_way_python_joins_it() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["join"].as_array().expect("the cases") {
            let directory = case["dir"].as_str().expect("the directory");
            let name = case["name"].as_str().expect("the name");
            let got = remote_file_path(directory, name);
            let want = case["value"].as_str().expect("the value");
            if got != want {
                failures.push(format!(
                    "{directory:?} + {name:?}: want {want:?}, got {got:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn the_directories_made_are_the_ones_python_makes() {
        let corpus = corpus();
        let mut failures = Vec::new();
        for case in corpus["chain"].as_array().expect("the cases") {
            let raw = case["raw"].as_str().expect("the text");
            let got = remote_dir_chain(raw);
            let want: Vec<String> = case["value"]
                .as_array()
                .expect("the value")
                .iter()
                .map(|item| item.as_str().expect("a string").to_string())
                .collect();
            if got != want {
                failures.push(format!("{raw:?}: want {want:?}, got {got:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The pin itself, end to end: a real host key, parsed here, has to give
    /// the same string paramiko gives it. That value is what an operator
    /// reads off `ssh-keygen -lf` and types into the target, and it is the
    /// whole protection on this path — if the two ever disagreed, every
    /// pinned target would start refusing the host it was pinned to.
    #[test]
    fn a_host_key_fingerprints_the_way_paramiko_fingerprints_it() {
        let corpus = corpus();
        let cases = corpus["fingerprint"].as_array().expect("the cases");
        assert!(cases.len() >= 2, "only {} keys in the corpus", cases.len());
        let mut failures = Vec::new();
        for case in cases {
            let name = case["name"].as_str().expect("the name");
            let openssh = case["openssh"].as_str().expect("the key");
            let key: russh::keys::PublicKey = match openssh.parse() {
                Ok(key) => key,
                Err(why) => {
                    failures.push(format!("{name}: cannot read the key: {why}"));
                    continue;
                }
            };
            let got = key.fingerprint(HashAlg::Sha256).to_string();
            let want = case["value"].as_str().expect("the value");
            if got != want {
                failures.push(format!("{name}: want {want}, got {got}"));
            }
            // And the algorithm name, which is reported beside it and is what
            // a mismatch message prints.
            let kind = key.algorithm().to_string();
            let want_kind = case["key_type"].as_str().expect("the type");
            if kind != want_kind {
                failures.push(format!("{name}: type want {want_kind}, got {kind}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_missing_file_and_no_credentials_are_refused_before_anything_connects() {
        let target = Target {
            host: "203.0.113.1",
            port: 22,
            username: "backup",
            remote_path: "/backups",
            password: None,
            private_key: None,
            expected_host_key_type: None,
            expected_host_key_fingerprint: None,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        // No such file: refused without a socket being opened.
        let outcome = runtime.block_on(upload("/nonexistent/backup.tar.gz", &target));
        assert!(matches!(outcome, Err(SftpError::LocalMissing)));

        // A file that exists, but nothing to authenticate with.
        let path = std::env::temp_dir().join(format!("sftp-test-{}.tar.gz", std::process::id()));
        std::fs::write(&path, b"x").expect("the file");
        let outcome = runtime.block_on(upload(&path.to_string_lossy(), &target));
        let _ = std::fs::remove_file(&path);
        assert!(matches!(outcome, Err(SftpError::NoCredentials)));
    }

    /// The message an operator reads when a host stops being the host they
    /// pinned. It names both fingerprints, because "mismatch" on its own
    /// leaves them with nothing to compare.
    #[test]
    fn a_mismatch_names_both_keys() {
        let target = Target {
            host: "backup.example.test",
            port: 22,
            username: "backup",
            remote_path: "/backups",
            password: Some("x"),
            private_key: None,
            expected_host_key_type: Some("ssh-ed25519"),
            expected_host_key_fingerprint: Some("SHA256:AAAA"),
        };
        let seen = Arc::new(std::sync::Mutex::new(Some((
            "ssh-rsa".to_string(),
            "SHA256:BBBB".to_string(),
        ))));
        let error = host_key_or_failure(&target, &seen, russh::Error::Disconnect);
        let SftpError::HostKeyMismatch(message) = error else {
            panic!("expected a mismatch, got {error:?}");
        };
        assert_eq!(
            message,
            "SFTP host key mismatch for backup.example.test: \
             expected ssh-ed25519 SHA256:AAAA, got ssh-rsa SHA256:BBBB"
        );
    }

    /// A connection that dropped for some other reason, with the **right**
    /// key seen, is not reported as a mismatch.
    #[test]
    fn a_matching_key_that_still_failed_is_not_a_mismatch() {
        let target = Target {
            host: "backup.example.test",
            port: 22,
            username: "backup",
            remote_path: "/backups",
            password: Some("x"),
            private_key: None,
            expected_host_key_type: Some("ssh-ed25519"),
            expected_host_key_fingerprint: Some("SHA256:AAAA"),
        };
        let seen = Arc::new(std::sync::Mutex::new(Some((
            "ssh-ed25519".to_string(),
            "SHA256:AAAA".to_string(),
        ))));
        let error = host_key_or_failure(&target, &seen, russh::Error::Disconnect);
        assert!(matches!(error, SftpError::Failed(_)));
    }
}
