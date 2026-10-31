use crate::commands;
use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum CryptoAction {
    /// List every algorithm and format tag Phantom names, with role, status
    /// and quantum class. Reads no vault, key, or config.
    Inventory {
        /// Output format. The global --json is the same as --format json.
        #[arg(long, value_enum, default_value_t = commands::crypto::InventoryFormat::Text)]
        format: commands::crypto::InventoryFormat,
    },
}
