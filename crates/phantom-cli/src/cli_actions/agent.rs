use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Emit the read-only readiness report
    Report {
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Human-readable view of the readiness report (--json: value-free preflight)
    Doctor {
        /// Emit the value-free preflight JSON (no vault access unless --vault)
        #[arg(long)]
        json: bool,
        /// With --json: also probe the vault and the cloud login (keychain access)
        #[arg(long)]
        vault: bool,
        /// With --json: exit 0 when ready, exit 2 when degraded, blocked, or
        /// unknown. Exit 1 stays a command error. Omit it to keep exit 0.
        #[arg(long)]
        strict: bool,
    },
    /// Read-only, value-free view of MCP approval state (use --json for JSON)
    Status {
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Initialize safe defaults for AI-agent use
    Setup {
        /// Show planned actions without changing files
        #[arg(long, conflicts_with = "apply")]
        dry_run: bool,
        /// Apply setup actions
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
    },
}
