//! Files a malware scan found, set aside where nothing serves or runs them,
//! and put back when an administrator says they are fine.
//!
//! Every path this module is handed was found by a scan of folders whose
//! owners - the hosting customers - can rename, replace and link anything in
//! them at any moment, including between the scan and this. So no path is
//! resolved the ordinary way: each folder from `/` down is opened with
//! `O_NOFOLLOW | O_DIRECTORY` relative to the one before, and the file is
//! moved with `renameat()` between those descriptors. A folder swapped for a
//! link after the scan is refused, not followed - the worst a customer can
//! do is keep their own file from moving, never make root move someone
//! else's.
//!
//! What may be set aside is a regular file under `/home`, `/tmp`,
//! `/var/tmp` or `/dev/shm`: where customers' files, and attackers', are. A
//! hit anywhere else - a whole-server scan reads `/usr` and `/etc` too - is
//! `left` where it is for an administrator to judge: isolating a system
//! binary on a signature match is how a false positive takes a server down.
//! Such a hit can still be whitelisted, which moves nothing.
//!
//! The store is root's alone (0700):
//!
//! ```text
//! /var/lib/snpanel-quarantine/items/<id>/file        the file, 0600, root's
//! /var/lib/snpanel-quarantine/items/<id>/meta.json   where it was, whose, its
//!                                                    mode, size, SHA-256,
//!                                                    signature and scan
//! /var/lib/snpanel-quarantine/whitelist.json         [{path, sha256, added_at}]
//! ```
//!
//! The whitelist is by path **and** content: a file changed after it was
//! judged fine is judged again.

use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use snpanel_ipc::{HelperErrorKind, HelperResponse};

/// Where the store is on a server.
pub const STORE: &str = "/var/lib/snpanel-quarantine";

/// The folders a file may be isolated from.
pub const ROOTS: &[&str] = &["/home/", "/tmp/", "/var/tmp/", "/dev/shm/"];

const RENAME_NOREPLACE: libc::c_uint = 1;

/// The store's place and the folders files may leave - constants on a
/// server, scratch folders in a test.
pub struct Store {
    root: PathBuf,
    roots: Vec<String>,
}

impl Store {
    pub fn system() -> Self {
        Self {
            root: PathBuf::from(STORE),
            roots: ROOTS.iter().map(|r| r.to_string()).collect(),
        }
    }

    #[cfg(test)]
    fn at(root: &Path, roots: &[&Path]) -> Self {
        Self {
            root: root.to_path_buf(),
            roots: roots.iter().map(|r| format!("{}/", r.display())).collect(),
        }
    }

    /// Whether a file at `path` may be moved out.
    fn movable(&self, path: &str) -> bool {
        self.roots
            .iter()
            .any(|root| path.starts_with(root.as_str()))
    }

    fn items(&self) -> PathBuf {
        self.root.join("items")
    }

    fn whitelist_file(&self) -> PathBuf {
        self.root.join("whitelist.json")
    }

    /// The store and its items folder, made root's and closed when they
    /// are not: a store others could write to would let them choose what
    /// a restore puts back.
    fn ensure(&self) -> Result<PathBuf, String> {
        for dir in [self.root.clone(), self.items()] {
            match std::fs::symlink_metadata(&dir) {
                Ok(meta) if meta.file_type().is_dir() => {}
                Ok(_) => return Err(format!("{} is not a folder", dir.display())),
                Err(_) => {
                    use std::os::unix::fs::DirBuilderExt;
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&dir)
                        .map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
                }
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("Cannot close {}: {e}", dir.display()))?;
        }
        Ok(self.items())
    }
}

fn refused(message: impl Into<String>) -> HelperResponse {
    HelperResponse::failed(HelperErrorKind::BadRequest, message)
}

fn broke(message: impl Into<String>) -> HelperResponse {
    HelperResponse::failed(HelperErrorKind::Internal, message)
}

fn answer(value: Value) -> HelperResponse {
    HelperResponse::with_stdout(value.to_string())
}

/// A reported path as the folders from `/` down and the file's own name -
/// or why it is not a plain absolute path.
pub fn parts(path: &str) -> Result<(Vec<&str>, &str), String> {
    if !path.starts_with('/') || path.len() > 4096 || path.contains('\0') {
        return Err("Not a path the panel isolates".to_string());
    }
    let mut pieces: Vec<&str> = path[1..].split('/').collect();
    let name = pieces.pop().unwrap_or("");
    let plain =
        |piece: &str| !piece.is_empty() && piece != "." && piece != ".." && piece.len() <= 255;
    if !plain(name) || !pieces.iter().all(|piece| plain(piece)) {
        return Err(format!("{path} is not a plain path"));
    }
    Ok((pieces, name))
}

fn c_name(text: &str) -> Result<CString, String> {
    CString::new(text).map_err(|_| "A name with a NUL in it".to_string())
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// `openat()` - a descriptor, or the error.
fn open_at(
    dir: libc::c_int,
    name: &CString,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<OwnedFd> {
    // SAFETY: `name` is a NUL-terminated string that outlives the call, and
    // a non-negative result is a descriptor this function alone now owns.
    let raw = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            libc::c_uint::from(mode),
        )
    };
    if raw < 0 {
        return Err(last_error());
    }
    // SAFETY: see above.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The folder a file is in, opened from `/` one step at a time, with every
/// link on the way refused.
fn open_parent(dirs: &[&str]) -> Result<OwnedFd, String> {
    let root = c_name("/")?;
    let mut fd = open_at(libc::AT_FDCWD, &root, libc::O_RDONLY | libc::O_DIRECTORY, 0)
        .map_err(|e| format!("Cannot open /: {e}"))?;
    let mut walked = String::new();
    for dir in dirs {
        walked.push('/');
        walked.push_str(dir);
        let name = c_name(dir)?;
        fd = match open_at(
            fd.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(next) => next,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                return Err(format!("{walked} is a link or not a folder"))
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                return Err(format!("{walked} is gone"))
            }
            Err(e) => return Err(format!("Cannot open {walked}: {e}")),
        };
    }
    Ok(fd)
}

fn stat_at(dir: &OwnedFd, name: &CString) -> std::io::Result<libc::stat> {
    // SAFETY: a zeroed stat is a valid out-parameter and is only read when
    // the call says it filled it.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        ) != 0
        {
            return Err(last_error());
        }
        Ok(st)
    }
}

fn stat_of(fd: &impl AsRawFd) -> std::io::Result<libc::stat> {
    // SAFETY: as in `stat_at`.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
            return Err(last_error());
        }
        Ok(st)
    }
}

fn is_regular(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

fn same_file(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

/// A regular file in `dir`, opened without following a link.
fn open_regular(dir: &OwnedFd, name: &CString) -> Result<(std::fs::File, libc::stat), String> {
    let fd = open_at(
        dir.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
    .map_err(|e| match e.raw_os_error() {
        Some(libc::ELOOP) => "It is a link".to_string(),
        Some(libc::ENOENT) => "It is gone".to_string(),
        _ => e.to_string(),
    })?;
    let st = stat_of(&fd).map_err(|e| e.to_string())?;
    if !is_regular(&st) {
        return Err("It is not a regular file".to_string());
    }
    Ok((std::fs::File::from(fd), st))
}

fn sha256_of(file: &mut std::fs::File) -> Result<String, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    snpanel_core::types::sha256_reader(file).map_err(|e| format!("Cannot read it: {e}"))
}

fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("No randomness: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn id_ok(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `file` in `to`, as a copy of `from` - for a move across filesystems.
fn copy_into(
    from: &mut std::fs::File,
    to: &OwnedFd,
    name: &CString,
) -> Result<std::fs::File, String> {
    let fd = open_at(
        to.as_raw_fd(),
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|e| format!("Cannot write the copy: {e}"))?;
    let mut copy = std::fs::File::from(fd);
    from.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    std::io::copy(from, &mut copy).map_err(|e| format!("Cannot copy it: {e}"))?;
    copy.sync_all()
        .map_err(|e| format!("Cannot copy it: {e}"))?;
    Ok(copy)
}

fn unlink_at(dir: &OwnedFd, name: &CString) -> std::io::Result<()> {
    // SAFETY: `name` outlives the call.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(last_error());
    }
    Ok(())
}

fn chown_mod(file: &std::fs::File, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    // SAFETY: plain calls on a descriptor this function borrows.
    unsafe {
        // Only root may give a file away; a test run as someone else keeps
        // its own files as they are.
        if libc::geteuid() == 0 && libc::fchown(file.as_raw_fd(), uid, gid) != 0 {
            return Err(format!(
                "Cannot give it back to its owner: {}",
                last_error()
            ));
        }
        if libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) != 0 {
            return Err(format!("Cannot set its mode: {}", last_error()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// the whitelist
// ---------------------------------------------------------------------------

fn read_whitelist(store: &Store) -> Vec<Value> {
    std::fs::read_to_string(store.whitelist_file())
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<Value>>(&text).ok())
        .unwrap_or_default()
}

fn write_whitelist(store: &Store, entries: &[Value]) -> Result<(), String> {
    store.ensure()?;
    let target = store.whitelist_file();
    let temp = store.root.join(".whitelist.json.new");
    let text = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|e| format!("Cannot write the whitelist: {e}"))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("Cannot write the whitelist: {e}"))?;
    }
    std::fs::rename(&temp, &target).map_err(|e| format!("Cannot write the whitelist: {e}"))
}

fn whitelisted(store: &Store, path: &str, sha256: &str) -> bool {
    read_whitelist(store).iter().any(|entry| {
        entry["path"].as_str() == Some(path) && entry["sha256"].as_str() == Some(sha256)
    })
}

// ---------------------------------------------------------------------------
// the operations
// ---------------------------------------------------------------------------

/// `malware-quarantine <path> [signature] [job]` - the file set aside, or
/// `whitelisted` when an administrator already judged this content at this
/// path fine, or `missing` when it is gone already.
pub fn quarantine(store: &Store, path: &str, signature: &str, job: &str) -> HelperResponse {
    let (dirs, name) = match parts(path) {
        Ok(parts) => parts,
        Err(message) => return refused(message),
    };
    let parent = match open_parent(&dirs) {
        Ok(fd) => fd,
        Err(message) if message.ends_with("is gone") => {
            return answer(json!({ "status": "missing", "path": path }))
        }
        Err(message) => return refused(format!("{path}: {message}")),
    };
    let c_file = match c_name(name) {
        Ok(c) => c,
        Err(message) => return refused(message),
    };
    let listed = match stat_at(&parent, &c_file) {
        Ok(st) => st,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            return answer(json!({ "status": "missing", "path": path }))
        }
        Err(e) => return refused(format!("{path}: {e}")),
    };
    if !is_regular(&listed) {
        return refused(format!("{path} is a link or not a regular file"));
    }
    let (mut file, st) = match open_regular(&parent, &c_file) {
        Ok(opened) => opened,
        Err(message) => return refused(format!("{path}: {message}")),
    };
    if !same_file(&listed, &st) {
        return refused(format!("{path} changed while it was being read"));
    }
    let mut sha256 = match sha256_of(&mut file) {
        Ok(sum) => sum,
        Err(message) => return refused(format!("{path}: {message}")),
    };
    if whitelisted(store, path, &sha256) {
        return answer(json!({ "status": "whitelisted", "path": path, "sha256": sha256 }));
    }
    if !store.movable(path) {
        return answer(json!({ "status": "left", "path": path, "sha256": sha256 }));
    }

    let items = match store.ensure() {
        Ok(items) => items,
        Err(message) => return broke(message),
    };
    let id = match random_id() {
        Ok(id) => id,
        Err(message) => return broke(message),
    };
    let item_dir = items.join(&id);
    {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&item_dir) {
            return broke(format!("Cannot create {}: {e}", item_dir.display()));
        }
    }
    let item = match c_name(&item_dir.to_string_lossy()).and_then(|c| {
        open_at(
            libc::AT_FDCWD,
            &c,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|e| e.to_string())
    }) {
        Ok(fd) => fd,
        Err(message) => return broke(message),
    };
    let c_stored = c_name("file").expect("a plain name");
    let give_up = |message: String| {
        let _ = std::fs::remove_dir_all(&item_dir);
        broke(message)
    };

    // SAFETY: both names outlive the call; the descriptors are held.
    let moved = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            c_file.as_ptr(),
            item.as_raw_fd(),
            c_stored.as_ptr(),
        )
    } == 0;
    let mut stored_st = st;
    if !moved {
        let error = last_error();
        if error.raw_os_error() != Some(libc::EXDEV) {
            return give_up(format!("Cannot move {path}: {error}"));
        }
        // Another filesystem: a copy, then the original goes - if it is
        // still the file that was copied.
        if let Err(message) = copy_into(&mut file, &item, &c_stored) {
            return give_up(message);
        }
        match stat_at(&parent, &c_file) {
            Ok(now_there) if same_file(&now_there, &st) => {
                if let Err(e) = unlink_at(&parent, &c_file) {
                    return give_up(format!("Cannot remove {path}: {e}"));
                }
            }
            _ => return give_up(format!("{path} changed while it was being moved")),
        }
    }
    let (mut stored, now_st) = match open_regular(&item, &c_stored) {
        Ok(opened) => opened,
        Err(message) => return give_up(message),
    };
    // What was moved is what is described: a file swapped in at the last
    // moment is hashed again.
    if moved && !same_file(&now_st, &st) {
        stored_st = now_st;
        sha256 = match sha256_of(&mut stored) {
            Ok(sum) => sum,
            Err(message) => return broke(message),
        };
    }
    if let Err(message) = chown_mod(&stored, 0, 0, 0o600) {
        return broke(message);
    }
    let meta = json!({
        "id": id,
        "path": path,
        "uid": stored_st.st_uid,
        "gid": stored_st.st_gid,
        "mode": stored_st.st_mode & 0o7777,
        "size": stored_st.st_size,
        "sha256": sha256,
        "signature": signature,
        "job": job,
        "quarantined_at": now(),
    });
    if let Err(e) = write_private(&item_dir.join("meta.json"), &meta.to_string()) {
        return broke(format!("Cannot record it: {e}"));
    }
    let mut out = meta;
    out["status"] = json!("quarantined");
    answer(out)
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

fn read_meta(store: &Store, id: &str) -> Result<Value, String> {
    if !id_ok(id) {
        return Err("Not a quarantine id".to_string());
    }
    let text = std::fs::read_to_string(store.items().join(id).join("meta.json"))
        .map_err(|_| "Not in quarantine".to_string())?;
    serde_json::from_str(&text).map_err(|_| "Its record is unreadable".to_string())
}

/// `malware-quarantine-restore <id>` - back where it was, its owner's and
/// in its mode, less setuid, setgid and sticky. Refused when a file is at
/// that path again, or the folder it was in is gone or is now a link.
pub fn restore(store: &Store, id: &str) -> HelperResponse {
    let meta = match read_meta(store, id) {
        Ok(meta) => meta,
        Err(message) => return refused(message),
    };
    let path = meta["path"].as_str().unwrap_or_default().to_string();
    let (dirs, name) = match parts(&path) {
        Ok(parts) => parts,
        Err(message) => return refused(message),
    };
    if !store.movable(&path) {
        return refused(format!(
            "{path} is outside the folders files are put back into"
        ));
    }
    let parent = match open_parent(&dirs) {
        Ok(fd) => fd,
        Err(message) => return refused(format!("Cannot put {path} back: {message}")),
    };
    let c_file = match c_name(name) {
        Ok(c) => c,
        Err(message) => return refused(message),
    };
    if stat_at(&parent, &c_file).is_ok() {
        return refused(format!("A file is at {path} again; move it away first"));
    }
    let item_dir = store.items().join(id);
    let item = match c_name(&item_dir.to_string_lossy()).and_then(|c| {
        open_at(
            libc::AT_FDCWD,
            &c,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|e| e.to_string())
    }) {
        Ok(fd) => fd,
        Err(message) => return broke(message),
    };
    let c_stored = c_name("file").expect("a plain name");
    // SAFETY: both names outlive the call; the descriptors are held.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            item.as_raw_fd(),
            c_stored.as_ptr(),
            parent.as_raw_fd(),
            c_file.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        let error = last_error();
        match error.raw_os_error() {
            Some(libc::EXDEV) => {
                let (mut stored, _) = match open_regular(&item, &c_stored) {
                    Ok(opened) => opened,
                    Err(message) => return broke(message),
                };
                if let Err(message) = copy_into(&mut stored, &parent, &c_file) {
                    return refused(format!("Cannot put {path} back: {message}"));
                }
                let _ = unlink_at(&item, &c_stored);
            }
            Some(libc::EEXIST) => {
                return refused(format!("A file is at {path} again; move it away first"))
            }
            _ => return broke(format!("Cannot put {path} back: {error}")),
        }
    }
    let uid = meta["uid"].as_u64().unwrap_or(0) as u32;
    let gid = meta["gid"].as_u64().unwrap_or(0) as u32;
    let mode = (meta["mode"].as_u64().unwrap_or(0o644) as u32) & 0o777;
    let restored = match open_regular(&parent, &c_file) {
        Ok((file, _)) => file,
        Err(message) => return broke(format!("{path}: {message}")),
    };
    if let Err(message) = chown_mod(&restored, uid, gid, mode) {
        return broke(format!("{path}: {message}"));
    }
    let _ = std::fs::remove_file(item_dir.join("meta.json"));
    let _ = std::fs::remove_dir(&item_dir);
    answer(json!({ "status": "restored", "id": id, "path": path }))
}

/// `malware-quarantine-delete <id>` - gone for good.
pub fn delete(store: &Store, id: &str) -> HelperResponse {
    let meta = match read_meta(store, id) {
        Ok(meta) => meta,
        Err(message) => return refused(message),
    };
    let item_dir = store.items().join(id);
    for name in ["file", "meta.json"] {
        let target = item_dir.join(name);
        if let Err(e) = std::fs::remove_file(&target) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return broke(format!("Cannot remove {}: {e}", target.display()));
            }
        }
    }
    let _ = std::fs::remove_dir(&item_dir);
    answer(json!({ "status": "deleted", "id": id, "path": meta["path"] }))
}

/// `malware-quarantine-list` - every file set aside, the newest first.
pub fn list(store: &Store) -> HelperResponse {
    let mut items: Vec<Value> = std::fs::read_dir(store.items())
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| {
                    let id = entry.file_name().to_string_lossy().into_owned();
                    read_meta(store, &id).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    items.sort_by(|a, b| {
        b["quarantined_at"]
            .as_u64()
            .cmp(&a["quarantined_at"].as_u64())
            .then_with(|| a["path"].as_str().cmp(&b["path"].as_str()))
    });
    answer(Value::Array(items))
}

/// `malware-whitelist-add <path>` - this content at this path is fine: a
/// scan that finds it again leaves it where it is.
pub fn whitelist_add(store: &Store, path: &str) -> HelperResponse {
    let (dirs, name) = match parts(path) {
        Ok(parts) => parts,
        Err(message) => return refused(message),
    };
    let parent = match open_parent(&dirs) {
        Ok(fd) => fd,
        Err(message) => return refused(format!("{path}: {message}")),
    };
    let c_file = match c_name(name) {
        Ok(c) => c,
        Err(message) => return refused(message),
    };
    let (mut file, _) = match open_regular(&parent, &c_file) {
        Ok(opened) => opened,
        Err(message) => return refused(format!("{path}: {message}")),
    };
    let sha256 = match sha256_of(&mut file) {
        Ok(sum) => sum,
        Err(message) => return refused(format!("{path}: {message}")),
    };
    let entry = json!({ "path": path, "sha256": sha256, "added_at": now() });
    let mut entries: Vec<Value> = read_whitelist(store)
        .into_iter()
        .filter(|e| e["path"].as_str() != Some(path))
        .collect();
    entries.push(entry.clone());
    if let Err(message) = write_whitelist(store, &entries) {
        return broke(message);
    }
    answer(entry)
}

/// `malware-whitelist-remove <path>`.
pub fn whitelist_remove(store: &Store, path: &str) -> HelperResponse {
    let entries = read_whitelist(store);
    let kept: Vec<Value> = entries
        .iter()
        .filter(|e| e["path"].as_str() != Some(path))
        .cloned()
        .collect();
    let removed = entries.len() - kept.len();
    if removed > 0 {
        if let Err(message) = write_whitelist(store, &kept) {
            return broke(message);
        }
    }
    answer(json!({ "removed": removed }))
}

/// `malware-whitelist-list`.
pub fn whitelist_list(store: &Store) -> HelperResponse {
    answer(Value::Array(read_whitelist(store)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("snpanel-quarantine-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("site/uploads")).unwrap();
        dir
    }

    fn out(response: &HelperResponse) -> Value {
        assert!(response.ok, "{response:?}");
        serde_json::from_str(&response.stdout).expect("JSON")
    }

    #[test]
    fn only_a_plain_absolute_path_is_taken() {
        assert!(parts("/home/alice/site/evil.php").is_ok());
        assert!(parts("/tmp/x").is_ok());
        assert!(parts("/usr/bin/php").is_ok());
        for bad in [
            "/home/../etc/passwd",
            "/home/alice/../../etc/passwd",
            "/home/alice//evil.php",
            "/home/alice/./evil.php",
            "/home/alice/",
            "home/alice/evil.php",
            "/home/alice/a\0b",
            "/",
        ] {
            assert!(parts(bad).is_err(), "{bad:?}");
        }
        let system = Store::system();
        assert!(system.movable("/home/alice/site/evil.php"));
        assert!(system.movable("/dev/shm/.x"));
        assert!(!system.movable("/usr/bin/php"));
        assert!(!system.movable("/homeless/evil.php"));
        assert!(!system.movable("/etc/passwd"));
    }

    #[test]
    fn a_hit_outside_the_customer_folders_is_left_where_it_is() {
        let dir = scratch("left");
        let store = Store::at(&dir.join("store"), &[&dir.join("site")]);
        std::fs::create_dir_all(dir.join("system")).unwrap();
        let binary = dir.join("system/tool");
        std::fs::write(&binary, b"ELF").unwrap();
        let path = binary.to_string_lossy().into_owned();
        assert_eq!(out(&quarantine(&store, &path, "", ""))["status"], "left");
        assert!(binary.exists());
        // Judged fine, it is said to be.
        assert!(whitelist_add(&store, &path).ok);
        assert_eq!(
            out(&quarantine(&store, &path, "", ""))["status"],
            "whitelisted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_is_set_aside_and_put_back_as_it_was() {
        let dir = scratch("roundtrip");
        let store = Store::at(&dir.join("store"), &[&dir.join("site")]);
        let file = dir.join("site/uploads/evil.php");
        std::fs::write(&file, b"<?php eval($_POST['x']);").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o6755)).unwrap();
        let path = file.to_string_lossy().into_owned();

        let set_aside = out(&quarantine(&store, &path, "{HEX}php.cmdshell", "job1"));
        assert_eq!(set_aside["status"], "quarantined");
        assert!(!file.exists(), "the file is still where it was");
        let id = set_aside["id"].as_str().unwrap().to_string();
        let stored = dir.join("store/items").join(&id).join("file");
        assert_eq!(std::fs::read(&stored).unwrap(), b"<?php eval($_POST['x']);");
        assert_eq!(
            std::fs::metadata(&stored).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(set_aside["mode"], 0o6755);
        assert_eq!(set_aside["signature"], "{HEX}php.cmdshell");
        let listed = out(&list(&store));
        assert_eq!(listed[0]["id"], id.as_str());

        // Something at the path again: the restore will not replace it.
        std::fs::write(&file, b"new").unwrap();
        assert!(!restore(&store, &id).ok);
        std::fs::remove_file(&file).unwrap();

        let back = out(&restore(&store, &id));
        assert_eq!(back["status"], "restored");
        assert_eq!(std::fs::read(&file).unwrap(), b"<?php eval($_POST['x']);");
        // Its mode, less setuid and setgid.
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert!(!dir.join("store/items").join(&id).exists());
        assert_eq!(out(&list(&store)), json!([]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_on_the_way_is_refused_not_followed() {
        let dir = scratch("links");
        let store = Store::at(&dir.join("store"), &[&dir.join("site")]);
        std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
        std::fs::write(dir.join("elsewhere/passwd"), b"root:x:0:0").unwrap();
        // A folder swapped for a link to somewhere else.
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join("site/swapped")).unwrap();
        let through = dir
            .join("site/swapped/passwd")
            .to_string_lossy()
            .into_owned();
        let answer = quarantine(&store, &through, "", "");
        assert!(!answer.ok, "{answer:?}");
        assert!(
            dir.join("elsewhere/passwd").exists(),
            "a file behind a link was moved"
        );
        // The file itself a link.
        std::os::unix::fs::symlink(dir.join("elsewhere/passwd"), dir.join("site/evil.php"))
            .unwrap();
        let link = dir.join("site/evil.php").to_string_lossy().into_owned();
        assert!(!quarantine(&store, &link, "", "").ok);
        assert!(dir.join("elsewhere/passwd").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_gone_is_said_to_be_missing() {
        let dir = scratch("missing");
        let store = Store::at(&dir.join("store"), &[&dir.join("site")]);
        let gone = dir.join("site/nothing.php").to_string_lossy().into_owned();
        assert_eq!(out(&quarantine(&store, &gone, "", ""))["status"], "missing");
        let gone_dir = dir
            .join("site/nofolder/x.php")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            out(&quarantine(&store, &gone_dir, "", ""))["status"],
            "missing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_whitelisted_file_stays_until_its_content_changes() {
        let dir = scratch("whitelist");
        let store = Store::at(&dir.join("store"), &[&dir.join("site")]);
        let file = dir.join("site/uploads/tool.php");
        std::fs::write(&file, b"<?php // a known false positive").unwrap();
        let path = file.to_string_lossy().into_owned();

        let added = out(&whitelist_add(&store, &path));
        assert_eq!(added["path"], path.as_str());
        assert_eq!(out(&whitelist_list(&store)).as_array().unwrap().len(), 1);
        assert_eq!(
            out(&quarantine(&store, &path, "", ""))["status"],
            "whitelisted"
        );
        assert!(file.exists());

        std::fs::write(&file, b"<?php eval($_GET[1]);").unwrap();
        assert_eq!(
            out(&quarantine(&store, &path, "", ""))["status"],
            "quarantined"
        );
        assert!(!file.exists());

        assert_eq!(out(&whitelist_remove(&store, &path))["removed"], 1);
        assert_eq!(out(&whitelist_list(&store)), json!([]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_deleted_file_is_gone_from_the_store() {
        let dir = scratch("delete");
        let store = Store::at(&dir.join("store"), &[&dir.join("site")]);
        let file = dir.join("site/evil.php");
        std::fs::write(&file, b"x").unwrap();
        let id = out(&quarantine(&store, &file.to_string_lossy(), "", ""))["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(out(&delete(&store, &id))["status"], "deleted");
        assert!(!dir.join("store/items").join(&id).exists());
        assert!(!restore(&store, &id).ok);
        assert!(!delete(&store, "../../etc").ok);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
