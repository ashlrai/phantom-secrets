use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum ExpiryAction {
    /// Mark a secret as expiring in N days from now.
    /// Stores `expires_at` Unix timestamp and `rotation_window` in .phantom.toml.
    Set {
        /// Secret name (e.g., STRIPE_KEY)
        key: String,
        /// Number of days until the secret expires
        days: u64,
    },
    /// Exit 1 if any secret has an expired TTL (for CI / pre-commit hooks).
    ///
    /// With --fail-closed, also exit 1 if any secret has no expiry policy set.
    Enforce {
        /// Also fail if any secret has no expiry policy (treat missing TTL as expired)
        #[arg(long)]
        fail_closed: bool,
        /// Emit JSON output instead of human-readable messages
        #[arg(long)]
        json: bool,
    },
    /// Deprecated compatibility command: remap the local phm_ token only.
    /// Provider credentials and expiry metadata remain unchanged.
    Rotate {
        /// Secret name to rotate
        key: String,
    },
}
