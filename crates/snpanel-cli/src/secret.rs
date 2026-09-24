//! Reading a secret from the terminal.
//!
//! Source: `read -rsp "..."` in `snpanelctl`, which is bash's own no-echo
//! read. There is no equivalent in the standard library, so this is the
//! `termios` dance written out.
//!
//! The part worth being careful about is not turning the echo off. It is
//! turning it back on. A process that exits between `tcsetattr(ECHO off)` and
//! restoring it leaves the operator's shell silently swallowing every
//! keystroke, on a machine they are probably already having a bad day with -
//! so the restore is a `Drop`, which runs on the error paths and on a panic,
//! not a line at the end of the happy path.

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::{Context, Result};

/// Restores the terminal's original settings when it goes out of scope.
struct EchoOff {
    fd: i32,
    original: libc::termios,
}

impl EchoOff {
    /// Returns `None` when stdin is not a terminal, which is not an error:
    /// `read -rs` from a pipe reads the line, and so does this.
    fn new(fd: i32) -> Option<Self> {
        // SAFETY: `termios` is plain data; `tcgetattr` fills it or fails.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }
        let mut quiet = original;
        quiet.c_lflag &= !libc::ECHO;
        // ECHONL keeps the newline visible when the user presses return, so
        // the cursor moves to the next line the way it does with `read -rs`
        // followed by the bash's explicit `echo`.
        quiet.c_lflag |= libc::ECHONL;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
            return None;
        }
        Some(Self { fd, original })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // Nothing useful to do if this fails, and it must not panic in a
        // destructor.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

/// Prompt, then read one line without echoing it.
///
/// The value is returned with the trailing newline removed and **nothing
/// else trimmed**: a password may legitimately begin or end with a space, and
/// `read -r` does not strip one either.
pub fn read_secret(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    let stdin = io::stdin();
    let _echo_off = stdin
        .is_terminal()
        .then(|| EchoOff::new(libc::STDIN_FILENO));

    let mut line = String::new();
    let read = stdin
        .lock()
        .read_line(&mut line)
        .context("reading from the terminal")?;
    if read == 0 {
        // EOF. The caller decides what an empty answer means; for a
        // confirmation it is "no".
        println!();
        return Ok(String::new());
    }
    if !stdin.is_terminal() {
        // ECHONL printed it on a terminal; a pipe needs the newline here so
        // the next prompt starts on its own line.
        println!();
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// The same read with the echo left on, for an answer that is not a secret.
///
/// Source: `read -rp`. Shares the EOF handling with [`read_secret`], which is
/// the part worth sharing: a prompt that blocks forever on a closed stdin
/// turns a scripted run into a hang.
pub fn read_visible(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        return Ok(String::new());
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turning_the_echo_off_is_skipped_without_a_terminal() {
        // Do not call `read_secret` here. `cargo test` inherits a stdin that
        // nobody is writing to, so a test that reads it blocks the whole
        // suite until the runner is killed - which is what the first version
        // of this test did.
        //
        // What is checkable without reading: `EchoOff::new` on a descriptor
        // that is not a terminal returns `None` rather than failing, which is
        // why `read_secret` can be used in a pipeline at all.
        let dev_null = std::fs::File::open("/dev/null").expect("/dev/null");
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&dev_null);
        assert!(EchoOff::new(fd).is_none(), "/dev/null is not a terminal");
    }

    #[test]
    fn a_secret_keeps_its_spaces() {
        // `read -r` strips nothing but the newline. A password that ends in a
        // space is a password an operator can type and the panel will store,
        // and silently trimming it here would make the account unreachable
        // through the panel's own form.
        let mut line = "  pass word  \n".to_string();
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        assert_eq!(line, "  pass word  ");
    }
}
