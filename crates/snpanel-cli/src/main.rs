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

mod cli;
mod doctor;
mod menu;
mod ops;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command, FirewallCommand};

/// Where the installer puts the panel's environment file.
pub(crate) const ENV_PATH: &str = "/opt/snpanel/backend/.env";

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
    let env_path = PathBuf::from(ENV_PATH);
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
        Command::SetPanelUrl => ops::delegate_to_snpanelctl(&["set-panel-url"]),
        Command::InstallPanelSsl => ops::delegate_to_snpanelctl(&["install-panel-ssl"]),
        Command::FixPermissions => ops::delegate_to_snpanelctl(&["fix-permissions"]),
        Command::ChangeAdminPassword => ops::delegate_to_snpanelctl(&["change-admin-password"]),
        Command::SyncAdminRootPassword => {
            ops::delegate_to_snpanelctl(&["sync-admin-root-password"])
        }
    }
}
