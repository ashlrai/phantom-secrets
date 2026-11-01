use clap::Subcommand;

// The `Add` variant carries many optional per-provider flags (client id/secret
// env, scopes, team, account, org, …); boxing a clap-derived variant complicates
// the derive for no runtime benefit here, so the size skew is accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub(crate) enum GrantAction {
    /// Compatibility command. This release returns before project, vault,
    /// environment, browser, loopback, or network access. No enrollment occurs.
    Add {
        /// Provider identifier retained for source compatibility; never contacted.
        provider: String,
        /// Org selector: for github-app, create the App under this org instead
        /// of your account; for supabase, pre-select this `organization_slug` on
        /// the OAuth consent page.
        #[arg(long)]
        org: Option<String>,
        /// GitHub App only: the App name (must be globally unique on GitHub).
        #[arg(long)]
        name: Option<String>,
        /// Reserved destination name; no credential is minted or stored.
        #[arg(long)]
        rotate_secret: Option<String>,
        /// Consent flow for a generic OAuth provider: pkce (loopback) or device.
        #[arg(long, value_name = "FLOW")]
        flow: Option<String>,
        /// The OAuth app's client id (required for --flow pkce|device).
        #[arg(long)]
        client_id: Option<String>,
        /// Reserved env-var name. Its value is not read in this release.
        #[arg(long, value_name = "ENV")]
        client_secret_env: Option<String>,
        /// Comma-separated OAuth scopes to request.
        #[arg(long)]
        scope: Option<String>,
        /// Vercel Integration only: scope the grant to this team id (the
        /// `teamId` applied to every subsequent REST call). Omit for a
        /// personal-account install.
        #[arg(long)]
        team: Option<String>,
        /// Stripe only: target Stripe account id hint (`acct_…`). Advisory — the
        /// authoritative account comes back in the token exchange.
        #[arg(long)]
        account: Option<String>,
        /// Compatibility flag. No browser is opened in this release.
        #[arg(long)]
        no_browser: bool,
        /// Emit the value-free denial as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List configured grants: provider, state, next renewal. Never values.
    List {
        /// Emit JSON instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Show grant chain health (metadata only; MCP-safe).
    Status {
        /// Limit to one provider.
        provider: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Revoke a grant remotely, then remove local material; currently fails
    /// closed before local mutation because remote revocation is not wired.
    Revoke {
        /// Provider identity to revoke (e.g. `github-app`, `supabase`).
        provider: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}
