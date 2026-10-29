use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum CloudAction {
    /// Push after an exact trusted-terminal challenge; partial success must be reconciled
    Push,
    /// Pull after an exact trusted-terminal challenge; partial merges block later push
    Pull {
        /// Declare overwrites; never bypass the trusted-terminal ceremony
        #[arg(long)]
        force: bool,
    },
    /// Read cloud status after an exact trusted-terminal challenge authorizes provider access
    Status,
}
