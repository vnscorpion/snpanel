//! SFTP accounts of a customer's own: extra logins, each shut into one
//! folder of the customer's home - DirectAdmin's FTP accounts, over SFTP.
//!
//! An account is a Linux account named `<owner>_<name>` with the owner's
//! UID and GID - so what it uploads is the owner's, and the site's PHP can
//! change it as it can the owner's own files - and the group
//! `snpanel-sftp-sub`, which sshd matches:
//!
//! ```text
//! Match Group snpanel-sftp-sub
//!     ChrootDirectory /srv/sftp/%u
//!     ForceCommand internal-sftp -d %d
//! ```
//!
//! A chroot has to be root's all the way down to it, and a customer's
//! folders are the customer's, so the folder is not the chroot:
//! `/srv/sftp/<account>` is - root's, 0755, holding one empty folder - and
//! the customer's folder is bind-mounted onto that one. The account's home
//! is the mount as seen from inside (`/public_html`), which is where
//! `internal-sftp -d %d` starts it.
//!
//! **The mount is made from a descriptor, never a path.** The customer
//! owns every folder below their home and could swap one for a link - to
//! another customer's site, say - between a check and a `mount --bind`,
//! which follows links. So the folder is opened one step at a time with
//! `O_NOFOLLOW`, checked to be the owner's, and mounted as
//! `/proc/self/fd/<n>`: that descriptor, whatever the path says by then.
//!
//! **The mount is made by systemd, not by whoever asked.** The helper's
//! own service has a private mount namespace (`PrivateTmp`), and a mount
//! made in it is one sshd never sees. So each account has a unit,
//! `snpanel-sftp-<account>.service`, whose `ExecStart` is this module's
//! `sftp-sub-mount` - run by PID 1, in the namespace sshd is in, and again
//! at every boot.
//!
//! **Nothing here removes a jail recursively.** While the mount is up the
//! jail's folder *is* the customer's folder, and `rm -rf` on it would
//! delete their site. A jail is unmounted, checked to be unmounted, and
//! emptied with `rmdir`, which refuses anything with a file in it.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::json;
use snpanel_core::{PanelUsername, SecretString};
use snpanel_ipc::{HelperErrorKind, HelperResponse};

use crate::exec;

pub const JAIL_ROOT: &str = "/srv/sftp";
pub const SUB_GROUP: &str = "snpanel-sftp-sub";
const UNIT_DIR: &str = "/etc/systemd/system";
const HELPER_BIN: &str = "/usr/local/sbin/snpanel-helper";

fn refused(message: impl Into<String>) -> HelperResponse {
    HelperResponse::failed(HelperErrorKind::BadRequest, message)
}

fn broke(message: impl Into<String>) -> HelperResponse {
    HelperResponse::failed(HelperErrorKind::Internal, message)
}

/// `<owner>_<name>`, the name 1-16 lowercase letters and digits.
pub fn account_of(owner: &PanelUsername, account: &PanelUsername) -> Result<(), String> {
    let Some(name) = account
        .as_str()
        .strip_prefix(&format!("{}_", owner.as_str()))
    else {
        return Err(format!(
            "An SFTP account of {owner} is named {owner}_<name>"
        ));
    };
    if name.is_empty()
        || name.len() > 16
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(
            "The name after the underscore is 1-16 lowercase letters and digits".to_string(),
        );
    }
    Ok(())
}

/// A folder of the owner's home as the folders below it; `.` is all of it.
/// Plain names only: letters, digits, `.`, `_` and `-`.
pub fn directory_parts(directory: &str) -> Result<Vec<&str>, String> {
    if directory == "." {
        return Ok(Vec::new());
    }
    let bad = || format!("{directory} is not a folder name the panel accepts");
    if directory.is_empty()
        || directory.len() > 1024
        || directory.starts_with('/')
        || directory.ends_with('/')
    {
        return Err(bad());
    }
    let parts: Vec<&str> = directory.split('/').collect();
    for part in &parts {
        let plain = !part.is_empty()
            && *part != "."
            && *part != ".."
            && part.len() <= 255
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !plain {
            return Err(bad());
        }
    }
    Ok(parts)
}

/// What the folder is called inside the jail: its own name, or the owner's
/// for the whole home.
pub fn mount_name(owner: &PanelUsername, parts: &[&str]) -> String {
    parts
        .last()
        .map(|name| name.to_string())
        .unwrap_or_else(|| owner.as_str().to_string())
}

pub fn unit_name(account: &PanelUsername) -> String {
    format!("snpanel-sftp-{}.service", account.as_str())
}

/// The unit that mounts an account's folder, at once and at every boot.
pub fn unit_text(owner: &PanelUsername, account: &PanelUsername, directory: &str) -> String {
    format!(
        "# Written by snpanel-helper: the SFTP folder of {account}, an account of {owner}'s.\n\
         [Unit]\n\
         Description=SNPanel SFTP folder of {account}\n\
         After=local-fs.target\n\
         Before=ssh.service sshd.service\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         ExecStart={HELPER_BIN} sftp-sub-mount {owner} {account} {directory}\n\
         ExecStop={HELPER_BIN} sftp-sub-umount {owner} {account}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

fn passwd_ids(name: &str) -> Option<(u32, u32)> {
    let out = exec::run(&["getent", "passwd", name]).ok()?;
    if !out.ok() {
        return None;
    }
    let fields: Vec<&str> = out.stdout.trim().split(':').collect();
    Some((fields.get(2)?.parse().ok()?, fields.get(3)?.parse().ok()?))
}

fn in_group(name: &str, group: &str) -> bool {
    exec::run(&["id", "-nG", name])
        .map(|out| out.ok() && out.stdout.split_whitespace().any(|g| g == group))
        .unwrap_or(false)
}

/// The owner, and their IDs - a panel user, not any account at all.
fn owner_ids(owner: &PanelUsername) -> Result<(u32, u32), String> {
    let ids = passwd_ids(owner.as_str()).ok_or_else(|| format!("No panel user {owner}"))?;
    if ids.0 == 0 || !in_group(owner.as_str(), crate::ops::user::SFTP_GROUP) {
        return Err(format!("{owner} is not a panel user"));
    }
    Ok(ids)
}

/// The account, when it is one of this owner's: same UID, in the group.
/// `None` when there is no such account; an error when it is someone else's.
fn account_ids(owner_uid: u32, account: &PanelUsername) -> Result<Option<(u32, u32)>, String> {
    let Some(ids) = passwd_ids(account.as_str()) else {
        return Ok(None);
    };
    if ids.0 != owner_uid || !in_group(account.as_str(), SUB_GROUP) {
        return Err(format!("{account} is not an SFTP account of this user"));
    }
    Ok(Some(ids))
}

fn c_path(text: &str) -> Result<CString, String> {
    CString::new(text).map_err(|_| "A name with a NUL in it".to_string())
}

fn open_dir(dir: libc::c_int, name: &CString, follow: bool) -> std::io::Result<OwnedFd> {
    let flags = libc::O_RDONLY
        | libc::O_DIRECTORY
        | libc::O_CLOEXEC
        | if follow { 0 } else { libc::O_NOFOLLOW };
    // SAFETY: `name` is NUL-terminated and outlives the call; a non-negative
    // result is a descriptor this function alone owns.
    let raw = unsafe { libc::openat(dir, name.as_ptr(), flags) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: see above.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn stat_of(fd: &OwnedFd) -> std::io::Result<libc::stat> {
    // SAFETY: a zeroed stat is a valid out-parameter, read only on success.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(st)
    }
}

/// The folder, opened: the home (root's, the owner's group - a root-owned
/// path above it, so a link there is the administrator's and is followed),
/// then every folder below it without following a link, and checked to be
/// the owner's.
fn open_folder(
    owner: &PanelUsername,
    uid: u32,
    gid: u32,
    parts: &[&str],
) -> Result<OwnedFd, String> {
    let home = format!("{}/{}", crate::ops::user::HOME_ROOT, owner.as_str());
    let mut fd = open_dir(libc::AT_FDCWD, &c_path(&home)?, true)
        .map_err(|e| format!("Cannot open {home}: {e}"))?;
    let st = stat_of(&fd).map_err(|e| e.to_string())?;
    if st.st_uid != 0 || st.st_gid != gid {
        return Err(format!("{home} is not the panel's home for {owner}"));
    }
    let mut walked = home.clone();
    for part in parts {
        walked.push('/');
        walked.push_str(part);
        fd = match open_dir(fd.as_raw_fd(), &c_path(part)?, false) {
            Ok(next) => next,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                return Err(format!("{walked} is a link or not a folder"))
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                return Err(format!("{walked} does not exist"))
            }
            Err(e) => return Err(format!("Cannot open {walked}: {e}")),
        };
    }
    if !parts.is_empty() {
        let st = stat_of(&fd).map_err(|e| e.to_string())?;
        if st.st_uid != uid {
            return Err(format!("{walked} is not {owner}'s"));
        }
    }
    Ok(fd)
}

/// A folder of root's, 0755 - made when missing, refused when it is a link
/// or someone else's.
fn root_dir(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() && meta.uid() == 0 => {}
        Ok(_) => return Err(format!("{} is not a folder of root's", path.display())),
        Err(_) => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o755)
                .create(path)
                .map_err(|e| format!("Cannot create {}: {e}", path.display()))?;
        }
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("Cannot set {}: {e}", path.display()))
}

fn jail_of(account: &PanelUsername) -> PathBuf {
    Path::new(JAIL_ROOT).join(account.as_str())
}

/// `/srv/sftp`, the account's jail and the folder the mount goes on.
fn jail_dirs(account: &PanelUsername, name: &str) -> Result<PathBuf, String> {
    root_dir(Path::new(JAIL_ROOT))?;
    let jail = jail_of(account);
    root_dir(&jail)?;
    let point = jail.join(name);
    root_dir(&point)?;
    Ok(point)
}

/// Whether something is mounted on `path`, from this process's view.
fn is_mounted(path: &Path) -> bool {
    let target = path.to_string_lossy();
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|text| {
            text.lines()
                .filter_map(|line| line.split(' ').nth(4))
                .any(|point| point == target)
        })
        .unwrap_or(false)
}

fn unmount(path: &Path) -> Result<(), String> {
    let c = c_path(&path.to_string_lossy())?;
    // SAFETY: `c` outlives both calls.
    unsafe {
        if libc::umount2(c.as_ptr(), 0) != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBUSY) {
                // In use by an open session: detached now, gone when it closes.
                if libc::umount2(c.as_ptr(), libc::MNT_DETACH) != 0 {
                    return Err(format!(
                        "Cannot unmount {}: {}",
                        path.display(),
                        std::io::Error::last_os_error()
                    ));
                }
            } else if error.raw_os_error() != Some(libc::EINVAL) {
                // EINVAL: nothing mounted there.
                return Err(format!("Cannot unmount {}: {error}", path.display()));
            }
        }
    }
    Ok(())
}

/// Everything mounted in an account's jail, unmounted - and checked to be.
fn unmount_jail(account: &PanelUsername) -> Result<(), String> {
    let jail = jail_of(account);
    let Ok(entries) = std::fs::read_dir(&jail) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let point = entry.path();
        while is_mounted(&point) {
            unmount(&point)?;
            if is_mounted(&point) {
                return Err(format!("{} is still mounted", point.display()));
            }
        }
    }
    Ok(())
}

/// The jail's folders gone - with `rmdir`, which stops at anything with a
/// file in it, and only once nothing is mounted there.
fn remove_jail(account: &PanelUsername) -> Result<(), String> {
    unmount_jail(account)?;
    let jail = jail_of(account);
    if let Ok(entries) = std::fs::read_dir(&jail) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_dir(entry.path());
        }
    }
    match std::fs::remove_dir(&jail) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "{} is not empty; left as it is: {e}",
            jail.display()
        )),
    }
}

fn password_ok(password: &SecretString) -> Result<(), String> {
    let len = password.expose().len();
    let (lo, hi) = (
        crate::ops::user::MIN_PASSWORD_LEN,
        crate::ops::user::MAX_PASSWORD_LEN,
    );
    if !(lo..=hi).contains(&len) {
        return Err(format!("password must be {lo}-{hi} characters"));
    }
    if !password.valid_as_linux_password() {
        return Err("password cannot contain ':', carriage returns or newlines".to_string());
    }
    Ok(())
}

fn chpasswd(account: &PanelUsername, password: &SecretString) -> HelperResponse {
    let line = format!("{}:{}\n", account.as_str(), password.expose());
    let out = exec::run_with_stdin(&["chpasswd"], Some(line.as_bytes()));
    let resp = exec::respond("chpasswd", out);
    if resp.ok {
        let _ = exec::run(&["passwd", "-u", account.as_str()]);
    }
    resp
}

fn systemctl(args: &[&str]) -> bool {
    let mut argv = vec!["systemctl"];
    argv.extend_from_slice(args);
    exec::run(&argv).map(|out| out.ok()).unwrap_or(false)
}

fn remove_unit(account: &PanelUsername) {
    let unit = unit_name(account);
    let _ = systemctl(&["disable", "--now", &unit]);
    let _ = std::fs::remove_file(Path::new(UNIT_DIR).join(&unit));
    let _ = systemctl(&["daemon-reload"]);
}

/// `sftp-sub-create <owner> <account> <directory>`, the password on stdin.
pub fn create(
    owner: &PanelUsername,
    account: &PanelUsername,
    directory: &str,
    password: &SecretString,
) -> HelperResponse {
    if let Err(message) = account_of(owner, account) {
        return refused(message);
    }
    let parts = match directory_parts(directory) {
        Ok(parts) => parts,
        Err(message) => return refused(message),
    };
    if let Err(message) = password_ok(password) {
        return refused(message);
    }
    let (uid, gid) = match owner_ids(owner) {
        Ok(ids) => ids,
        Err(message) => return refused(message),
    };
    if passwd_ids(account.as_str()).is_some() {
        return refused(format!("An account named {account} exists already"));
    }
    // The folder is there and the owner's - checked again at every mount.
    if let Err(message) = open_folder(owner, uid, gid, &parts) {
        return refused(message);
    }

    if !exec::run(&["getent", "group", SUB_GROUP])
        .map(|o| o.ok())
        .unwrap_or(false)
    {
        let _ = exec::run(&["groupadd", "--system", SUB_GROUP]);
    }
    let name = mount_name(owner, &parts);
    let home = format!("/{name}");
    let shell = snpanel_osabi::detect()
        .map(|p| p.nologin_shell().to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/usr/sbin/nologin".to_string());
    let (uid_text, gid_text) = (uid.to_string(), gid.to_string());
    let added = exec::run(&[
        "useradd",
        "--non-unique",
        "--uid",
        &uid_text,
        "--gid",
        &gid_text,
        "--groups",
        SUB_GROUP,
        "--no-create-home",
        "--home-dir",
        &home,
        "--shell",
        &shell,
        account.as_str(),
    ]);
    if !matches!(&added, Ok(out) if out.ok()) {
        return exec::respond("useradd", added);
    }
    // Everything after the account exists undoes it on the way out.
    let undo = |message: String| {
        remove_unit(account);
        let _ = remove_jail(account);
        let _ = exec::run(&["userdel", "--force", account.as_str()]);
        broke(message)
    };
    let set = chpasswd(account, password);
    if !set.ok {
        let _ = exec::run(&["userdel", "--force", account.as_str()]);
        return set;
    }
    if let Err(message) = jail_dirs(account, &name) {
        return undo(message);
    }
    let unit = unit_name(account);
    if let Err(e) = std::fs::write(
        Path::new(UNIT_DIR).join(&unit),
        unit_text(owner, account, directory),
    ) {
        return undo(format!("Cannot write {unit}: {e}"));
    }
    if !systemctl(&["daemon-reload"]) || !systemctl(&["enable", "--now", &unit]) {
        return undo(format!("{unit} did not start; see journalctl -u {unit}"));
    }
    HelperResponse::with_stdout(
        json!({ "account": account.as_str(), "directory": directory, "home": home }).to_string(),
    )
}

/// `sftp-sub-password <owner> <account>`, the password on stdin.
pub fn set_password(
    owner: &PanelUsername,
    account: &PanelUsername,
    password: &SecretString,
) -> HelperResponse {
    if let Err(message) = account_of(owner, account) {
        return refused(message);
    }
    if let Err(message) = password_ok(password) {
        return refused(message);
    }
    let (uid, _) = match owner_ids(owner) {
        Ok(ids) => ids,
        Err(message) => return refused(message),
    };
    match account_ids(uid, account) {
        Ok(Some(_)) => chpasswd(account, password),
        Ok(None) => HelperResponse::failed(
            HelperErrorKind::NotFound,
            format!("No SFTP account {account}"),
        ),
        Err(message) => refused(message),
    }
}

/// `sftp-sub-delete <owner> <account>` - the unit stopped (which unmounts),
/// the mount checked gone, the account removed, the jail's empty folders
/// removed. A jail something is still mounted in is left alone.
pub fn delete(owner: &PanelUsername, account: &PanelUsername) -> HelperResponse {
    if let Err(message) = account_of(owner, account) {
        return refused(message);
    }
    let owner_uid = passwd_ids(owner.as_str()).map(|ids| ids.0);
    let exists = match owner_uid {
        Some(uid) => match account_ids(uid, account) {
            Ok(found) => found.is_some(),
            Err(message) => return refused(message),
        },
        // The owner is gone already: the name alone says whose it was, and
        // the group says it is a sub-account.
        None => passwd_ids(account.as_str()).is_some() && in_group(account.as_str(), SUB_GROUP),
    };
    remove_unit(account);
    if let Err(message) = remove_jail(account) {
        return broke(message);
    }
    if exists {
        // --force: the account shares its UID with the owner's PHP workers,
        // which userdel would otherwise take for the account's own processes.
        let out = exec::run(&["userdel", "--force", account.as_str()]);
        if !matches!(&out, Ok(o) if o.ok()) {
            return exec::respond("userdel", out);
        }
    }
    HelperResponse::with_stdout(json!({ "deleted": account.as_str() }).to_string())
}

/// Every SFTP account of `owner`, deleted - before the owner is.
pub fn delete_all(owner: &PanelUsername) {
    let prefix = format!("{}_", owner.as_str());
    let members = exec::run(&["getent", "group", SUB_GROUP])
        .ok()
        .filter(|out| out.ok())
        .map(|out| out.stdout)
        .unwrap_or_default();
    let names: Vec<String> = members
        .trim()
        .rsplit(':')
        .next()
        .unwrap_or("")
        .split(',')
        .filter(|name| name.starts_with(&prefix))
        .map(str::to_string)
        .collect();
    for name in names {
        if let Ok(account) = PanelUsername::parse(&name) {
            let _ = delete(owner, &account);
        }
    }
}

/// `sftp-sub-mount <owner> <account> <directory>` - what the account's unit
/// runs. The folder is opened step by step and mounted by its descriptor.
pub fn mount(owner: &PanelUsername, account: &PanelUsername, directory: &str) -> HelperResponse {
    if let Err(message) = account_of(owner, account) {
        return refused(message);
    }
    let parts = match directory_parts(directory) {
        Ok(parts) => parts,
        Err(message) => return refused(message),
    };
    let (uid, gid) = match owner_ids(owner) {
        Ok(ids) => ids,
        Err(message) => return refused(message),
    };
    match account_ids(uid, account) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HelperResponse::failed(
                HelperErrorKind::NotFound,
                format!("No SFTP account {account}"),
            )
        }
        Err(message) => return refused(message),
    }
    let point = match jail_dirs(account, &mount_name(owner, &parts)) {
        Ok(point) => point,
        Err(message) => return broke(message),
    };
    if is_mounted(&point) {
        return HelperResponse::with_stdout(format!("{} is mounted already\n", point.display()));
    }
    let folder = match open_folder(owner, uid, gid, &parts) {
        Ok(fd) => fd,
        Err(message) => return refused(message),
    };
    let source = format!("/proc/self/fd/{}", folder.as_raw_fd());
    let (c_source, c_point) = match (c_path(&source), c_path(&point.to_string_lossy())) {
        (Ok(s), Ok(p)) => (s, p),
        _ => return broke("A path with a NUL in it"),
    };
    // SAFETY: both strings outlive the calls; the descriptor is held open
    // until after the mount, so /proc/self/fd/<n> names it throughout.
    unsafe {
        if libc::mount(
            c_source.as_ptr(),
            c_point.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        ) != 0
        {
            return broke(format!(
                "Cannot mount {}: {}",
                point.display(),
                std::io::Error::last_os_error()
            ));
        }
        // No set-user-ID programs and no device files through the jail.
        let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV;
        if libc::mount(
            std::ptr::null(),
            c_point.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        ) != 0
        {
            let error = std::io::Error::last_os_error();
            let _ = libc::umount2(c_point.as_ptr(), libc::MNT_DETACH);
            return broke(format!("Cannot restrict {}: {error}", point.display()));
        }
    }
    drop(folder);
    HelperResponse::with_stdout(format!("{} mounted\n", point.display()))
}

/// `sftp-sub-umount <owner> <account>` - the unit's stop.
pub fn umount(owner: &PanelUsername, account: &PanelUsername) -> HelperResponse {
    if let Err(message) = account_of(owner, account) {
        return refused(message);
    }
    match unmount_jail(account) {
        Ok(()) => HelperResponse::ok(),
        Err(message) => broke(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> PanelUsername {
        PanelUsername::parse(name).unwrap()
    }

    #[test]
    fn an_account_is_its_owners_name_and_a_short_one() {
        let alice = user("alice");
        assert!(account_of(&alice, &user("alice_dev")).is_ok());
        assert!(account_of(&alice, &user("alice_2")).is_ok());
        for bad in [
            "alice",
            "alice_",
            "bob_dev",
            "alicex_dev",
            "alice_dev-1",
            "alice_Dev",
            "alice_abcdefghijklmnopq",
        ] {
            if let Ok(account) = PanelUsername::parse(bad) {
                assert!(account_of(&alice, &account).is_err(), "{bad}");
            }
        }
    }

    #[test]
    fn a_folder_is_plain_names_below_the_home() {
        assert_eq!(directory_parts(".").unwrap(), Vec::<&str>::new());
        assert_eq!(
            directory_parts("example.com/public_html").unwrap(),
            ["example.com", "public_html"]
        );
        for bad in [
            "",
            "/example.com",
            "example.com/",
            "../bob",
            "example.com/../..",
            "a//b",
            "a b",
            "a;b",
            "./x",
        ] {
            assert!(directory_parts(bad).is_err(), "{bad:?}");
        }
        let alice = user("alice");
        assert_eq!(
            mount_name(&alice, &["example.com", "public_html"]),
            "public_html"
        );
        assert_eq!(mount_name(&alice, &[]), "alice");
    }

    #[test]
    fn the_unit_mounts_by_the_helper_and_unmounts_by_it() {
        let text = unit_text(
            &user("alice"),
            &user("alice_dev"),
            "example.com/public_html",
        );
        assert!(text.contains("ExecStart=/usr/local/sbin/snpanel-helper sftp-sub-mount alice alice_dev example.com/public_html\n"));
        assert!(text
            .contains("ExecStop=/usr/local/sbin/snpanel-helper sftp-sub-umount alice alice_dev\n"));
        assert!(text.contains("RemainAfterExit=yes"));
        assert!(text.contains("WantedBy=multi-user.target"));
        assert_eq!(
            unit_name(&user("alice_dev")),
            "snpanel-sftp-alice_dev.service"
        );
    }

    #[test]
    fn nothing_mounted_on_a_folder_that_is_not_a_mount_point() {
        assert!(!is_mounted(Path::new("/nonexistent/snpanel/jail")));
        assert!(is_mounted(Path::new("/")));
    }
}
