//! The command surface.
//!
//! Plan Phase 1 requires 100% backward compatibility with the bash `snpanelctl`,
//! which accepts every subcommand both bare and `--`-prefixed
//! (`snpanel logs` and `snpanel --logs`), plus several aliases. Admins have these
//! in runbooks and muscle memory, so all of them keep working.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "snpanel",
    about = "SNPanel control and SSH rescue",
    version,
    // Running `snpanel` bare opens the menu, as the bash does.
    arg_required_else_help = false,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Open the rescue menu (the default when run with no arguments).
    #[command(alias = "--menu")]
    Menu,

    /// Show the panel URL, admin username and password.
    #[command(visible_aliases = ["--login", "show-login", "--show-login"])]
    Login,

    /// Show service, port, certificate and firewall status.
    #[command(alias = "--status")]
    Status,

    /// Show recent panel logs.
    #[command(alias = "--logs")]
    Logs {
        /// Follow the log rather than printing the tail.
        #[arg(short, long)]
        follow: bool,
        /// How many lines of history to print.
        #[arg(short = 'n', long, default_value_t = 200)]
        lines: u32,
    },

    /// Restart the panel services.
    #[command(alias = "--restart")]
    Restart,

    /// Reopen the panel and SSH ports in the firewall.
    #[command(visible_aliases = ["--repair-firewall"])]
    RepairFirewall,

    /// Update the panel.
    #[command(alias = "--update")]
    Update {
        /// Update to the latest tagged release (the default).
        #[arg(long, conflicts_with_all = ["tag", "branch"])]
        release: bool,
        /// Update to a specific tag.
        #[arg(long, conflicts_with_all = ["release", "branch"])]
        tag: Option<String>,
        /// Update to the head of a branch.
        #[arg(long, conflicts_with_all = ["release", "tag"])]
        branch: Option<String>,
    },

    /// Change the server's IP address in every config that records it.
    #[command(alias = "--change-ip")]
    ChangeIp {
        /// Old and new address. Prompted for when omitted.
        #[arg(num_args = 0..=2, value_names = ["OLD_IP", "NEW_IP"])]
        addresses: Vec<String>,
    },

    /// Set or reset the panel URL and port.
    #[command(visible_aliases = ["--set-panel-url"])]
    SetPanelUrl,

    /// Install or repair the panel's own TLS certificate.
    #[command(visible_aliases = ["--install-panel-ssl"])]
    InstallPanelSsl,

    /// Repair ownership and permissions across the site tree.
    #[command(visible_aliases = ["--fix-permissions"])]
    FixPermissions,

    /// Change the admin account password.
    #[command(visible_aliases = ["--change-admin-password"])]
    ChangeAdminPassword,

    /// Set the admin password to the root account's password.
    #[command(visible_aliases = [
        "--sync-admin-root-password",
        "admin-use-root-password",
        "--admin-use-root-password"
    ])]
    SyncAdminRootPassword,

    /// Turn off the admin's two-step sign-in - the authenticator app and
    /// every passkey - after a lost device. New in the Rust port.
    #[command(name = "reset-admin-2fa")]
    ResetAdmin2fa,

    /// Firewall maintenance.
    Firewall {
        #[command(subcommand)]
        action: FirewallCommand,
    },

    /// Diagnose this machine. New in the Rust port.
    Doctor {
        /// Print the findings as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum FirewallCommand {
    /// Show the current firewall state and rules.
    Status,
    /// Reopen the panel and SSH ports.
    Reopen,
    /// Drop all SNPanel rules, for a box that has locked itself out.
    Rescue,
    /// Move from the iptables/ipset backend to nftables.
    ///
    /// Rebuilds from rules.tsv, never from `iptables-save`, so no rule is lost.
    MigrateNft {
        /// Render the ruleset and print it without loading it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_invocation_means_the_menu() {
        let cli = Cli::try_parse_from(["snpanel"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn every_bash_subcommand_still_parses() {
        // The exact list from the `case` statement in installer/files/snpanelctl.
        let bare = [
            "menu",
            "login",
            "status",
            "logs",
            "restart",
            "repair-firewall",
            "set-panel-url",
            "install-panel-ssl",
            "fix-permissions",
            "change-admin-password",
            "sync-admin-root-password",
            "update",
            "change-ip",
        ];
        for cmd in bare {
            assert!(
                Cli::try_parse_from(["snpanel", cmd]).is_ok(),
                "`snpanel {cmd}` must keep working"
            );
        }
    }

    #[test]
    fn the_dash_dash_forms_still_parse() {
        let dashed = [
            "--login",
            "--status",
            "--logs",
            "--restart",
            "--repair-firewall",
            "--set-panel-url",
            "--install-panel-ssl",
            "--fix-permissions",
            "--change-admin-password",
            "--sync-admin-root-password",
            "--update",
        ];
        for cmd in dashed {
            assert!(
                Cli::try_parse_from(["snpanel", cmd]).is_ok(),
                "`snpanel {cmd}` must keep working"
            );
        }
    }

    #[test]
    fn the_admin_password_aliases_all_resolve() {
        for alias in [
            "sync-admin-root-password",
            "--sync-admin-root-password",
            "admin-use-root-password",
            "--admin-use-root-password",
        ] {
            let cli = Cli::try_parse_from(["snpanel", alias]).unwrap();
            assert!(matches!(cli.command, Some(Command::SyncAdminRootPassword)));
        }
    }

    #[test]
    fn change_ip_takes_two_addresses_or_none() {
        let cli = Cli::try_parse_from(["snpanel", "change-ip"]).unwrap();
        match cli.command {
            Some(Command::ChangeIp { addresses }) => assert!(addresses.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
        let cli = Cli::try_parse_from(["snpanel", "change-ip", "1.2.3.4", "5.6.7.8"]).unwrap();
        match cli.command {
            Some(Command::ChangeIp { addresses }) => {
                assert_eq!(addresses, vec!["1.2.3.4", "5.6.7.8"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn update_channels_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["snpanel", "update", "--release"]).is_ok());
        assert!(Cli::try_parse_from(["snpanel", "update", "--tag", "v1.0.134"]).is_ok());
        assert!(Cli::try_parse_from(["snpanel", "update", "--branch", "main"]).is_ok());
        assert!(
            Cli::try_parse_from(["snpanel", "update", "--release", "--branch", "main"]).is_err(),
            "picking two channels at once is a mistake worth catching"
        );
    }

    #[test]
    fn the_new_subcommands_parse() {
        assert!(Cli::try_parse_from(["snpanel", "doctor"]).is_ok());
        assert!(Cli::try_parse_from(["snpanel", "doctor", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["snpanel", "firewall", "migrate-nft"]).is_ok());
        assert!(Cli::try_parse_from(["snpanel", "firewall", "migrate-nft", "--dry-run"]).is_ok());
        assert!(Cli::try_parse_from(["snpanel", "firewall", "rescue"]).is_ok());
    }

    #[test]
    fn an_unknown_subcommand_is_an_error() {
        assert!(Cli::try_parse_from(["snpanel", "definitely-not-a-command"]).is_err());
    }
}
