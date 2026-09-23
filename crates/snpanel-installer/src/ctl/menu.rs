//! The menu itself, and the small helpers around it.
//!
//! Source: `menu`, `change_panel_ip`, `ensure_env_file`, `restart_panel`,
//! `run_firewall_helper`, `allow_panel_app`.

/// One entry in the rescue menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// What the operator types. A string rather than a number because `0`
    /// and `10` both exist and both are typed, and comparing text is what
    /// the shell's `case` does.
    pub key: &'static str,
    pub label: &'static str,
    /// The action, by the name of the shell function it runs.
    pub action: &'static str,
}

/// The menu, in the order it is printed.
///
/// The order is not arbitrary: the first four are the things somebody does
/// when they do not yet know what is wrong — look at the login details, the
/// status, the logs, then try a restart. Everything that *changes* something
/// comes after them.
pub const ENTRIES: &[Entry] = &[
    Entry {
        key: "1",
        label: "Show login info",
        action: "show_login_info",
    },
    Entry {
        key: "2",
        label: "Show rescue status",
        action: "show_status",
    },
    Entry {
        key: "3",
        label: "View recent logs",
        action: "show_logs",
    },
    Entry {
        key: "4",
        label: "Restart panel services",
        action: "restart_panel_command",
    },
    Entry {
        key: "5",
        label: "Repair firewall ports",
        action: "repair_firewall",
    },
    Entry {
        key: "6",
        label: "Set/reset panel URL / port",
        action: "set_panel_url",
    },
    Entry {
        key: "7",
        label: "Install/repair panel SSL",
        action: "install_panel_ssl",
    },
    Entry {
        key: "8",
        label: "Fix permissions/runtime",
        action: "fix_permissions",
    },
    Entry {
        key: "9",
        label: "Change admin password",
        action: "change_admin_password",
    },
    Entry {
        key: "10",
        label: "Update panel from release",
        action: "run_panel_update",
    },
    Entry {
        key: "11",
        label: "Change server IP",
        action: "change_panel_ip",
    },
    Entry {
        key: "12",
        label: "Sync admin password from root",
        action: "sync_admin_root_password",
    },
];

/// `0`, which is the only key that leaves.
pub const EXIT_KEY: &str = "0";

/// What an unrecognised choice does.
///
/// It says so and **loops** rather than exiting. Somebody who mistyped at a
/// rescue prompt should not have to start the tool again, and an exit on a
/// bad key would be indistinguishable from the tool crashing.
pub const INVALID_CHOICE: &str = "Invalid choice";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Run(&'static str),
    Exit,
    Invalid,
}

pub fn choose(input: &str) -> Choice {
    if input == EXIT_KEY {
        return Choice::Exit;
    }
    match ENTRIES.iter().find(|e| e.key == input) {
        Some(entry) => Choice::Run(entry.action),
        None => Choice::Invalid,
    }
}

/// `snpanel change-ip` takes two addresses, or asks for them.
///
/// The prompt offers the *current* address as the default for the new one,
/// which is the common case: the provider changed it, the machine already
/// knows, and the operator only has to remember the old one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeIp {
    /// Both given on the command line.
    Given { old: String, new: String },
    /// Neither given: ask, defaulting the new address to the detected one.
    Prompt { default_new: Option<String> },
    /// One argument, which is neither.
    Usage,
}

pub fn change_ip(args: &[&str], detected: Option<&str>) -> ChangeIp {
    match args.len() {
        2 => ChangeIp::Given {
            old: args[0].to_string(),
            new: args[1].to_string(),
        },
        0 => ChangeIp::Prompt {
            default_new: detected.filter(|d| !d.is_empty()).map(str::to_string),
        },
        _ => ChangeIp::Usage,
    }
}

pub const CHANGE_IP_USAGE: &str = "usage: snpanel change-ip <old-ip> <new-ip>";
pub const CHANGE_IP_SCRIPT: &str = "/usr/local/sbin/snpanel-change-ip";
pub const CHANGE_IP_MISSING: &str =
    "/usr/local/sbin/snpanel-change-ip not found. Reinstall/update SNPanel or copy change_IP.sh to that path.";

/// The `.env` has to be there before anything reads it.
///
/// The message names the fix rather than only the problem: somebody running
/// the rescue menu on a box where the installer never finished needs to know
/// that, not that a file is missing.
pub const NO_ENV_FILE: &str = "not found. Run installer first.";

/// How the menu reaches the helper.
///
/// `SUDO_USER=snpanel`, because the helper authorises by the account that
/// invoked it and the menu runs as root. Failures are swallowed: a firewall
/// query that cannot answer should leave the menu usable, not kill it.
pub const HELPER: &str = "/usr/local/sbin/snpanel-helper";
pub const HELPER_AS: &str = "snpanel";
pub const HELPER_FAILURE_IS_FATAL: bool = false;

#[cfg(test)]
mod tests {
    use super::*;

    /// The first four are what somebody does before they know what is wrong;
    /// everything that changes something comes after them.
    #[test]
    fn the_read_only_entries_come_first() {
        let read_only = ["show_login_info", "show_status", "show_logs"];
        for (at, entry) in ENTRIES.iter().enumerate() {
            if read_only.contains(&entry.action) {
                assert!(at < 3, "{} is not in the first three", entry.action);
            }
        }
        assert_eq!(ENTRIES[3].action, "restart_panel_command");
    }

    /// Every key is distinct, or two entries answer to the same keystroke
    /// and one of them is unreachable.
    #[test]
    fn no_two_entries_share_a_key() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in ENTRIES {
            assert!(seen.insert(entry.key), "{} is used twice", entry.key);
            assert_ne!(entry.key, EXIT_KEY, "an entry shadows the exit key");
        }
    }

    /// `0` and `10` are both typed, so the comparison is textual — a numeric
    /// parse that treated `0` as a prefix or `010` as `10` would run the
    /// wrong entry at a rescue prompt.
    #[test]
    fn the_choice_is_matched_as_text() {
        assert_eq!(choose("0"), Choice::Exit);
        assert_eq!(choose("10"), Choice::Run("run_panel_update"));
        assert_eq!(choose("1"), Choice::Run("show_login_info"));
        assert_eq!(choose("01"), Choice::Invalid);
        assert_eq!(choose(" 1"), Choice::Invalid);
        assert_eq!(choose(""), Choice::Invalid);
        assert_eq!(choose("13"), Choice::Invalid);
    }

    /// Somebody who mistyped at a rescue prompt should not have to start the
    /// tool again, and an exit on a bad key would be indistinguishable from
    /// the tool crashing.
    #[test]
    fn a_mistyped_choice_does_not_leave_the_menu() {
        assert_eq!(choose("x"), Choice::Invalid);
        assert_ne!(choose("x"), Choice::Exit);
        assert_eq!(INVALID_CHOICE, "Invalid choice");
    }

    /// Every entry runs something, and every action is named once.
    #[test]
    fn every_entry_has_a_distinct_action() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in ENTRIES {
            assert!(!entry.label.is_empty(), "{}", entry.key);
            assert!(seen.insert(entry.action), "{} runs twice", entry.action);
        }
        assert_eq!(ENTRIES.len(), 12);
    }

    /// The provider changed the address, the machine already knows it, and
    /// the operator only has to remember the old one.
    #[test]
    fn the_new_address_defaults_to_the_detected_one() {
        assert_eq!(
            change_ip(&[], Some("203.0.113.10")),
            ChangeIp::Prompt {
                default_new: Some("203.0.113.10".into())
            }
        );
        // A box that cannot detect its own address asks for both.
        assert_eq!(change_ip(&[], None), ChangeIp::Prompt { default_new: None });
        assert_eq!(
            change_ip(&[], Some("")),
            ChangeIp::Prompt { default_new: None }
        );
    }

    /// Two arguments are taken as given; one is a mistake, and saying so
    /// beats treating it as the old address and prompting for the new — the
    /// operator would not notice which half it had taken.
    #[test]
    fn one_argument_is_a_usage_error_rather_than_half_an_answer() {
        assert_eq!(
            change_ip(&["203.0.113.1", "203.0.113.2"], None),
            ChangeIp::Given {
                old: "203.0.113.1".into(),
                new: "203.0.113.2".into()
            }
        );
        assert_eq!(change_ip(&["203.0.113.1"], None), ChangeIp::Usage);
        assert_eq!(change_ip(&["a", "b", "c"], None), ChangeIp::Usage);
        assert!(CHANGE_IP_USAGE.contains("<old-ip> <new-ip>"));
    }

    /// The messages name the fix rather than only the problem: somebody on a
    /// box where the installer never finished needs to know that, not that a
    /// file is missing.
    #[test]
    fn the_messages_say_what_to_do_about_it() {
        assert!(NO_ENV_FILE.contains("Run installer first"));
        assert!(CHANGE_IP_MISSING.contains("Reinstall/update SNPanel"));
        assert!(CHANGE_IP_MISSING.contains(CHANGE_IP_SCRIPT));
    }

    /// The helper authorises by the account that invoked it, and the menu
    /// runs as root — so it says which account it is acting for. A firewall
    /// query that cannot answer leaves the menu usable rather than killing
    /// it.
    #[test]
    fn the_helper_is_invoked_as_the_panels_account() {
        assert_eq!(HELPER_AS, "snpanel");
        assert!(HELPER.starts_with("/usr/local/sbin/"));
        const { assert!(!HELPER_FAILURE_IS_FATAL) };
    }
}
