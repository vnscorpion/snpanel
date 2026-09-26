//! `snpanel` - the control and rescue CLI.
//!
//! Phase 1 of `RUST_MIGRATION_PLAN.md`. Chosen as the first thing to port
//! because it is independent of the backend and can ship on its own: if
//! something here is wrong, an admin runs the old command instead.
//!
//! Commands that need root go through the helper. During Phase 1 the helper is
//! still the bash one, so those commands shell out to it by name rather than
//! reimplementing privileged work - that is deliberate, and it is what lets
//! this ship before Phase 2 exists.

mod change_ip;
mod cli;
mod doctor;
mod menu;
mod ops;
mod panel_address;
mod passwords;
mod permissions;
mod secret;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command, FirewallCommand};

/// Where the installer puts the panel's environment file.
/// Where the panel is installed.
///
/// `install.sh` takes `APP_DIR` from the environment and defaults it to
/// `/opt/snpanel`. The bash rescue menu learned the value at install time,
/// by `sed`: the installer rewrote the script's own `APP_DIR=` line. A
/// binary cannot be rewritten that way, so the same override arrives the
/// other way round - from the environment, at run time, with the same
/// default. A box that never set it sees no difference.
pub(crate) fn app_dir() -> String {
    std::env::var("APP_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/opt/snpanel".to_string())
}

/// The panel's `.env`, under whichever `APP_DIR` this box uses.
pub(crate) fn env_path_string() -> String {
    format!("{}/backend/.env", app_dir())
}

/// Restore the default SIGPIPE disposition.
///
/// Rust sets SIGPIPE to `SIG_IGN` at startup, which turns `snpanel status |
/// head -3` - an entirely ordinary thing for an admin to type - into a panic
/// with a backtrace instead of a clean exit. Every other command-line tool on
/// the box dies quietly there, and so should this one.
fn restore_default_sigpipe() {
    // SAFETY: called once, before any thread is spawned, and only resets a
    // signal to the disposition every non-Rust program on the system uses.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() -> ExitCode {
    restore_default_sigpipe();
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("snpanel: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let env_path = PathBuf::from(env_path_string());
    let env_path = env_path.exists().then_some(env_path);

    match cli.command.unwrap_or(Command::Menu) {
        Command::Menu => {
            menu::run()?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor { json } => {
            let report = doctor::run(env_path.as_deref());
            if json {
                println!("{}", serde_json::to_string_pretty(&report.to_json())?);
            } else {
                report.print();
            }
            Ok(ExitCode::from(report.exit_code() as u8))
        }
        Command::Status => {
            ops::status(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Login => {
            ops::show_login_info()?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Logs { follow, lines } => {
            ops::logs(follow, lines)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Restart => {
            ops::restart()?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Firewall { action } => match action {
            FirewallCommand::Status => {
                ops::firewall_status()?;
                Ok(ExitCode::SUCCESS)
            }
            FirewallCommand::MigrateNft { dry_run } => {
                ops::firewall_migrate_nft(dry_run, env_path.as_deref())?;
                Ok(ExitCode::SUCCESS)
            }
            FirewallCommand::Reopen => {
                ops::repair_firewall(env_path.as_deref())?;
                Ok(ExitCode::SUCCESS)
            }
            FirewallCommand::Rescue => ops::delegate_to_helper(&["firewall-flush"]),
        },

        // Phase 1 ships these by delegating to the existing helper, which is
        // still the bash one until Phase 2 lands. The command surface is what
        // moves now; the privileged implementation moves next.
        Command::RepairFirewall => {
            ops::repair_firewall(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Update {
            release,
            tag,
            branch,
        } => {
            // `--release` is also the default: the bash only ever did that.
            let _ = release;
            let target = match (tag, branch) {
                (Some(t), _) => ops::UpdateTarget::Tag(t),
                (_, Some(b)) => ops::UpdateTarget::Branch(b),
                _ => ops::UpdateTarget::Release,
            };
            ops::run_update(target)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::ChangeIp { addresses } => {
            ops::change_ip(&addresses)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::SetPanelUrl => {
            panel_address::set_panel_url(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::InstallPanelSsl => {
            panel_address::install_panel_ssl(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::FixPermissions => {
            permissions::fix_permissions(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::ChangeAdminPassword => {
            passwords::change_admin_password(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::SyncAdminRootPassword => {
            passwords::sync_admin_root_password(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::ResetAdmin2fa => {
            passwords::reset_admin_two_factor(env_path.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The override the installer's `sed` used to bake into the bash.
    ///
    /// `install.sh` takes `APP_DIR` from the environment, and the bash
    /// rescue menu learned it at install time because the installer rewrote
    /// the script's own `APP_DIR=` line. A binary cannot be rewritten that
    /// way, so the value arrives from the environment instead - and a box
    /// that never set one must see exactly what it saw before.
    #[test]
    fn the_app_dir_defaults_to_the_one_every_box_has() {
        // Not set, or set to nothing, is the default. An empty `APP_DIR=`
        // exported by a wrapper script would otherwise make every path start
        // with `/backend/...`.
        std::env::remove_var("APP_DIR");
        assert_eq!(app_dir(), "/opt/snpanel");
        assert_eq!(env_path_string(), "/opt/snpanel/backend/.env");

        std::env::set_var("APP_DIR", "");
        assert_eq!(app_dir(), "/opt/snpanel");

        std::env::set_var("APP_DIR", "/srv/panel");
        assert_eq!(app_dir(), "/srv/panel");
        assert_eq!(env_path_string(), "/srv/panel/backend/.env");

        std::env::remove_var("APP_DIR");
    }
}
