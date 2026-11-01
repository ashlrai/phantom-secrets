use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum LeaksAction {
    /// Show what automated leak response would do. Read-only: no writes, no
    /// network, no secret values printed.
    Plan {
        /// Only plan for incidents with confidence at or above this value
        #[arg(long, default_value_t = 0.5)]
        min_confidence: f64,
        /// Emit JSON instead of human-readable output
        #[arg(long)]
        json: bool,
    },
}
