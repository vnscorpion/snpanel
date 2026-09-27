//! The SSH rescue menu.
//!
//! Plan Phase 1 requires the same 12 entries, in the same order, with the same
//! labels as the bash `menu()` in `installer/files/snpanelctl`. They are
//! reproduced verbatim below - an admin working from a runbook that says
//! "press 5" must still get the firewall repair.
//!
//! The plan suggests `ratatui` for this. It is rendered as plain text instead,
//! deliberately: the bash menu is plain text, this is the screen an operator
//! reaches when the box is already broken, and a full-screen TUI needs a
//! terminal that a serial console or a degraded SSH session may not provide.
//! A `ratatui` front end can be added later over this same dispatch table
//! without changing behaviour. Recorded in IMPROVEMENTS.md per NT1.

use std::io::{self, IsTerminal, Write};

use anyhow::Result;

use crate::ops;

/// The menu, in the bash's order. The index is what the operator types.
const ENTRIES: &[(&str, &str)] = &[
    ("1", "Show login info"),
    ("2", "Show rescue status"),
    ("3", "View recent logs"),
    ("4", "Restart panel services"),
    ("5", "Repair firewall ports"),
    ("6", "Set/reset panel URL / port"),
    ("7", "Install/repair panel SSL"),
    ("8", "Fix permissions/runtime"),
    ("9", "Change admin password"),
    ("10", "Update panel from release"),
    ("11", "Change server IP"),
    ("12", "Sync admin password from root"),
    ("0", "Exit"),
];

pub fn run() -> Result<()> {
    if !io::stdin().is_terminal() {
        // Printing the menu to a pipe and then blocking on a read that never
        // comes is the worst of both worlds.
        print_menu();
        println!("\n(no terminal attached; run `snpanel <command>` directly)");
        return Ok(());
    }

    loop {
        print_menu();
        print!("Choose: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        if io::stdin().read_line(&mut choice)? == 0 {
            return Ok(()); // EOF
        }

        match choose(choice.trim()) {
            Choice::Exit => return Ok(()),
            Choice::Unknown => println!("Invalid choice"),
            Choice::Run(action) => {
                if let Err(e) = perform(action) {
                    eprintln!("snpanel: {e:#}");
                }
            }
        }
    }
}

fn print_menu() {
    println!();
    println!("SNPanel SSH Rescue Menu");
    for (key, label) in ENTRIES {
        println!("{key}) {label}");
    }
}

/// What an entry does - named, so that choosing an entry and doing it are
/// two steps, and the first can be tested without the second restarting
/// services or changing the server's IP on the machine running the tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    ShowLoginInfo,
    Status,
    Logs,
    Restart,
    RepairFirewall,
    SetPanelUrl,
    InstallPanelSsl,
    FixPermissions,
    ChangeAdminPassword,
    UpdateFromRelease,
    ChangeIp,
    SyncAdminPassword,
}

enum Choice {
    Run(Action),
    Exit,
    Unknown,
}

fn choose(choice: &str) -> Choice {
    // The mapping is the bash `case` statement, one for one.
    Choice::Run(match choice {
        "1" => Action::ShowLoginInfo,
        "2" => Action::Status,
        "3" => Action::Logs,
        "4" => Action::Restart,
        "5" => Action::RepairFirewall,
        "6" => Action::SetPanelUrl,
        "7" => Action::InstallPanelSsl,
        "8" => Action::FixPermissions,
        "9" => Action::ChangeAdminPassword,
        "10" => Action::UpdateFromRelease,
        "11" => Action::ChangeIp,
        "12" => Action::SyncAdminPassword,
        "0" => return Choice::Exit,
        _ => return Choice::Unknown,
    })
}

fn perform(action: Action) -> Result<()> {
    let env = env_path();
    let env = env.as_deref();
    match action {
        Action::ShowLoginInfo => ops::show_login_info(),
        Action::Status => ops::status(env),
        Action::Logs => ops::logs(false, 200),
        Action::Restart => ops::restart(),
        Action::RepairFirewall => ops::repair_firewall(env),
        Action::SetPanelUrl => crate::panel_address::set_panel_url(env),
        Action::InstallPanelSsl => crate::panel_address::install_panel_ssl(env),
        Action::FixPermissions => crate::permissions::fix_permissions(env),
        Action::ChangeAdminPassword => crate::passwords::change_admin_password(env),
        // The menu has never offered a tag or a branch, and the entry says
        // "from release".
        Action::UpdateFromRelease => ops::run_update(ops::UpdateTarget::Release),
        Action::ChangeIp => ops::change_ip(&[]),
        Action::SyncAdminPassword => crate::passwords::sync_admin_root_password(env),
    }
}

fn env_path() -> Option<std::path::PathBuf> {
    let p = std::path::PathBuf::from("/opt/snpanel/backend/.env");
    p.exists().then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_menu_matches_the_bash_one_exactly() {
        // Taken from installer/files/snpanelctl::menu(). Order and wording are
        // part of the contract: runbooks say "press 5".
        let expected = [
            ("1", "Show login info"),
            ("2", "Show rescue status"),
            ("3", "View recent logs"),
            ("4", "Restart panel services"),
            ("5", "Repair firewall ports"),
            ("6", "Set/reset panel URL / port"),
            ("7", "Install/repair panel SSL"),
            ("8", "Fix permissions/runtime"),
            ("9", "Change admin password"),
            ("10", "Update panel from release"),
            ("11", "Change server IP"),
            ("12", "Sync admin password from root"),
            ("0", "Exit"),
        ];
        assert_eq!(ENTRIES, expected);
    }

    #[test]
    fn there_are_twelve_actions_plus_exit() {
        assert_eq!(ENTRIES.len(), 13);
    }

    #[test]
    fn zero_exits_and_nonsense_does_not() {
        assert!(matches!(choose("0"), Choice::Exit));
        for bad in ["", "13", "x", "-1", "1 "] {
            assert!(matches!(choose(bad), Choice::Unknown), "{bad:?}");
        }
    }

    #[test]
    fn every_numbered_entry_has_an_action_of_its_own() {
        // Only chooses: `perform` is never called here, so nothing is
        // restarted, repaired or updated on the machine running the tests.
        let mut seen = Vec::new();
        for (key, label) in ENTRIES {
            if *key == "0" {
                continue;
            }
            match choose(key) {
                Choice::Run(action) => {
                    assert!(
                        !seen.contains(&action),
                        "entry {key} ({label}) repeats {action:?}"
                    );
                    seen.push(action);
                }
                _ => panic!("menu entry {key} ({label}) has no action"),
            }
        }
        assert_eq!(seen.len(), 12);
    }
}
