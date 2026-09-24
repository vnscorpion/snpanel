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

        match dispatch(choice.trim()) {
            Dispatch::Exit => return Ok(()),
            Dispatch::Unknown => println!("Invalid choice"),
            Dispatch::Ran(result) => {
                if let Err(e) = result {
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

enum Dispatch {
    Ran(Result<()>),
    Exit,
    Unknown,
}

fn dispatch(choice: &str) -> Dispatch {
    // The mapping is the bash `case` statement, one for one.
    match choice {
        "1" => Dispatch::Ran(ops::show_login_info()),
        "2" => Dispatch::Ran(ops::status(env_path().as_deref())),
        "3" => Dispatch::Ran(ops::logs(false, 200)),
        "4" => Dispatch::Ran(ops::restart()),
        "5" => Dispatch::Ran(ops::repair_firewall(env_path().as_deref())),
        "6" => Dispatch::Ran(crate::panel_address::set_panel_url(env_path().as_deref())),
        "7" => Dispatch::Ran(crate::panel_address::install_panel_ssl(
            env_path().as_deref(),
        )),
        "8" => Dispatch::Ran(crate::permissions::fix_permissions(env_path().as_deref())),
        "9" => Dispatch::Ran(crate::passwords::change_admin_password(
            env_path().as_deref(),
        )),
        // The menu has never offered a tag or a branch, and the entry says
        // "from release".
        "10" => Dispatch::Ran(ops::run_update(ops::UpdateTarget::Release)),
        "11" => Dispatch::Ran(ops::change_ip(&[])),
        "12" => Dispatch::Ran(crate::passwords::sync_admin_root_password(
            env_path().as_deref(),
        )),
        "0" => Dispatch::Exit,
        _ => Dispatch::Unknown,
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
        assert!(matches!(dispatch("0"), Dispatch::Exit));
        for bad in ["", "13", "x", "-1", "1 "] {
            assert!(matches!(dispatch(bad), Dispatch::Unknown), "{bad:?}");
        }
    }

    #[test]
    fn every_numbered_entry_dispatches_somewhere() {
        for (key, label) in ENTRIES {
            if *key == "0" {
                continue;
            }
            assert!(
                !matches!(dispatch(key), Dispatch::Unknown),
                "menu entry {key} ({label}) has no action"
            );
        }
    }
}
