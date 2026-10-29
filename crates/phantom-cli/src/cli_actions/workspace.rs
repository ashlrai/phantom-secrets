use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum WorkspaceCliAction {
    /// Create a value-free exact setup plan and pending request
    Plan {
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Claim and apply an exact pending request from a trusted terminal
    Apply {
        /// Pending workspace request identifier
        #[arg(long, value_name = "ID")]
        request: String,
    },
    /// Show authenticated, value-free request status
    Status {
        /// Workspace request identifier
        #[arg(long, value_name = "ID")]
        request: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}
