use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum VaultAction {
    /// Copy this Linux project's volatile keyutils vault into Secret Service
    #[command(name = "migrate-linux")]
    MigrateLinux,
}
