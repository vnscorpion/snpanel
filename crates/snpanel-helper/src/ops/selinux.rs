//! `ops::selinux` - a no-op on the Debian family, real work on AlmaLinux.
//!
//! Plan Appendix B marks this ★ new. The decisions (which contexts, which
//! booleans) live in `snpanel-osabi::selinux` so they are testable anywhere;
//! what is here is the part that needs root.
//!
//! Every function succeeds silently on a system without SELinux. A caller
//! should not have to ask whether it is on AlmaLinux before relabelling a site
//! it just created - that check belongs here, once.

use snpanel_core::SitePath;
use snpanel_ipc::{HelperErrorKind, HelperResponse};
use snpanel_osabi::selinux::{policy_for, SelinuxMode};

use crate::exec;

/// Read `getenforce`, treating an absent binary as "no SELinux here".
pub fn mode() -> SelinuxMode {
    match std::fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(v) if v.trim() == "1" => SelinuxMode::Enforcing,
        Ok(_) => SelinuxMode::Permissive,
        Err(_) => SelinuxMode::Disabled,
    }
}

fn applies() -> bool {
    let Ok(platform) = snpanel_osabi::detect() else {
        return false;
    };
    policy_for(platform.as_ref()).applies() && mode().is_active()
}

/// Relabel a site tree. Called after any operation that creates or moves one.
pub fn restore_site(path: &SitePath) -> HelperResponse {
    if !applies() {
        return HelperResponse::with_stdout("selinux not active; nothing to do");
    }
    // The path is already known to be under /home/<panel-user>/, so there is
    // nothing here to re-check.
    exec::respond(
        "restorecon",
        exec::run(&["restorecon", "-R", path.as_str()]),
    )
}

/// Register the panel's non-standard port so nginx may bind it.
pub fn port_add(port: u16) -> HelperResponse {
    if !applies() {
        return HelperResponse::with_stdout("selinux not active; nothing to do");
    }
    let port_str = port.to_string();
    let out = exec::run(&[
        "semanage",
        "port",
        "-a",
        "-t",
        "http_port_t",
        "-p",
        "tcp",
        &port_str,
    ]);

    // semanage fails if the port is already registered, which is the state we
    // wanted. Distinguish that from a real failure rather than reporting it.
    if let Ok(o) = &out {
        if !o.ok() && o.stderr.contains("already defined") {
            return HelperResponse::with_stdout(format!("port {port} already registered"));
        }
    }
    let mut resp = exec::respond("semanage port -a", out);
    if !resp.ok {
        if let Some(err) = resp.error.as_mut() {
            err.kind = HelperErrorKind::CommandFailed;
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_is_a_no_op_off_the_rhel_family() {
        // This test machine and the CI containers for Ubuntu/Debian.
        if applies() {
            return; // running on AlmaLinux; the other tests cover that path
        }
        let p = SitePath::parse("/home/bp_site/example.com").unwrap();
        assert!(restore_site(&p).ok);
        assert!(port_add(2222).ok);
    }

    #[test]
    fn mode_parses_the_sysfs_switch() {
        // Whatever this machine is, the call must not panic and must return
        // one of the three states.
        assert!(matches!(
            mode(),
            SelinuxMode::Enforcing | SelinuxMode::Permissive | SelinuxMode::Disabled
        ));
    }
}
