use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum TeamAction {
    /// List teams after an exact trusted-terminal challenge authorizes provider access
    List,
    /// Create a team after an exact trusted-terminal challenge
    Create {
        /// Team name
        name: String,
    },
    /// List members after an exact trusted-terminal challenge authorizes provider access
    Members {
        /// Team ID
        team_id: String,
    },
    /// Invite a member after an exact trusted-terminal challenge
    Invite {
        /// Team ID
        team_id: String,
        /// GitHub username to invite
        github_login: String,
        /// Role to assign (member or admin; ownership transfer is not exposed)
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Register your team-vault public key after an exact trusted-terminal challenge.
    /// Run this once per team before pushing or pulling vaults.
    KeyPublish {
        /// Team ID
        team_id: String,
    },
    /// After an exact trusted-terminal challenge, push the current project's vault to a team (E2E encrypted to every
    /// member that has a registered public key).
    VaultPush {
        /// Team ID
        team_id: String,
    },
    /// Pull the current project's team vault after an exact trusted-terminal challenge.
    VaultPull {
        /// Team ID
        team_id: String,
    },
    /// Reserved team offboarding command; currently fails closed.
    #[command(hide = true)]
    Revoke {
        /// Team ID
        team_id: String,
        /// GitHub username to revoke
        github_login: String,
        /// Legacy flag; retained only for command compatibility
        #[arg(long, short = 'y', hide = true)]
        yes: bool,
    },
    /// After an exact trusted-terminal challenge, rotate the team vault key.
    ///
    /// Re-encrypts the vault with a fresh symmetric key and re-wraps it for
    /// all members that have a registered public key. Use this for scheduled
    /// key rotation or after a suspected credential exposure.
    RotateVault {
        /// Team ID
        team_id: String,
    },
}
