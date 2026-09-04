mod commands;
mod util;

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use phantom_core::PROCESS_ENV_LOCK as ENV_LOCK;

    pub(crate) fn canonical_tempdir_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path()
            .canonicalize()
            .expect("temporary directory should canonicalize")
    }
}

use clap::{Parser, Subcommand};
use commands::audit::AuditAction;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "phantom",
    about = "Reduce API-key exposure in supported AI-agent workflows",
    long_about = "Phantom replaces managed dotenv secrets with non-provider phantom placeholders.\n\
                  Its authenticated local proxy matches exact routes and injects only route-owned authentication into each route's fixed header; client headers and bodies never resolve placeholders.\n\
                  Agents confined to value-blind tools and supported proxy routes do not receive stored values.\n\
                  Unmanaged files, same-user processes, arbitrary tools, and unsupported protocols remain outside this boundary.\n\n\
                  Commands are grouped (in display order):\n  \
                    Setup        init · agent · setup · doctor · completion · mcp\n  \
                    Daily use    exec · start · status · check · list · add · remove · reveal · copy · env · why\n  \
                    Sync & teams login · logout · cloud · team · sync · pull · export · import · wrap · unwrap\n  \
                    Maintenance  upgrade · watch · rotate · open · audit",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose/debug logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Output in JSON format (for scripting)
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    // ───────────────────────────── Setup ─────────────────────────────
    /// Import .env secrets into the vault and rewrite with phantom tokens
    #[command(next_help_heading = "Setup")]
    Init {
        /// Path to .env file. Auto-detects .env, .env.local, .env.development and searches subdirectories
        #[arg(short, long, default_value = ".env")]
        from: String,
        /// Protect every git repo with a .env under <DIR> in one go.
        /// Skips repos that already have .phantom.toml.
        #[arg(long, value_name = "DIR")]
        all: Option<std::path::PathBuf>,
        /// With --all: scan and report what would change without modifying anything.
        #[arg(long, requires = "all")]
        dry_run: bool,
        /// With --all: number of repos to initialise concurrently.
        /// Defaults to PHANTOM_INIT_JOBS env var, then 4.
        #[arg(long, short = 'j', value_name = "N", requires = "all")]
        jobs: Option<usize>,
        /// Create a valid .phantom.toml and empty vault without requiring a .env file.
        /// Use this to bootstrap a brand-new project before any secrets exist.
        #[arg(long, conflicts_with_all = ["all", "dry_run"])]
        empty: bool,
    },

    /// Wire Phantom into an AI client (Claude Code, Cursor, Windsurf, Codex)
    #[command(next_help_heading = "Setup")]
    Setup {
        /// AI client to configure. Defaults to Claude Code if omitted.
        #[arg(value_enum, long, short = 'c')]
        client: Option<commands::setup::Client>,
        /// Print the config snippet to stdout instead of writing files
        #[arg(long)]
        print: bool,
        /// Configure audit encryption: none/local; cloud-signed is reserved and refused
        #[arg(long, value_enum, value_name = "MODE")]
        audit_mode: Option<commands::setup::AuditMode>,
    },

    /// Agent readiness report, doctor, and setup workflows
    #[command(next_help_heading = "Setup")]
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Check configuration and vault health
    #[command(next_help_heading = "Setup")]
    Doctor {
        /// Auto-fix safe issues (install hooks, generate .env.example, etc.)
        #[arg(long)]
        fix: bool,
        /// Also check secret TTL/expiry status and warn about expired or
        /// soon-to-expire secrets
        #[arg(long)]
        expiry: bool,
    },

    /// Print a shell-completion script to stdout.
    ///
    /// Source the output from your shell rc, e.g.
    ///   bash:       phantom completion bash > ~/.local/share/bash-completion/completions/phantom
    ///   zsh:        phantom completion zsh > "${fpath[1]}/_phantom"
    ///   fish:       phantom completion fish > ~/.config/fish/completions/phantom.fish
    ///   powershell: phantom completion powershell | Out-String | Invoke-Expression
    #[command(next_help_heading = "Setup")]
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// MCP server commands (Model Context Protocol)
    #[command(next_help_heading = "Setup")]
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },

    /// Approve a pending MCP nonce for a mutating vault operation.
    ///
    /// Run this in a trusted terminal after the MCP server prints a nonce to
    /// stderr. The returned approval_token must be passed as `approval_token`
    /// in the subsequent MCP tool call.
    ///
    /// Example:
    ///   phantom mcp-approve d3a9f2...
    #[command(name = "mcp-approve", next_help_heading = "Setup")]
    McpApprove {
        /// The nonce printed by the MCP server to stderr
        nonce: String,
    },

    /// Plan, approve, apply, and inspect exact workspace setup transactions
    #[command(next_help_heading = "Setup")]
    Workspace {
        #[command(subcommand)]
        action: WorkspaceCliAction,
    },

    /// Manage the local credential backend from a trusted terminal
    #[command(next_help_heading = "Setup")]
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },

    // ─────────────────────────── Daily use ───────────────────────────
    /// Start the proxy and run a command
    #[command(next_help_heading = "Daily use")]
    Exec {
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// Start a foreground proxy owned by this terminal
    #[command(next_help_heading = "Daily use")]
    Start {
        /// Reserved compatibility flag; detached mode is hard denied
        #[arg(short, long)]
        daemon: bool,
    },

    /// TTY-only diagnostic and manual migration guidance for legacy v0.7.3 state
    #[command(next_help_heading = "Daily use")]
    Stop,

    /// Show proxy status and mapped secrets
    #[command(next_help_heading = "Daily use")]
    Status {
        /// Compact one-line output for shell prompts
        #[arg(long)]
        oneline: bool,
    },

    /// Check for unprotected secrets (pre-commit hook)
    #[command(next_help_heading = "Daily use")]
    Check {
        /// Only scan git-staged files (skip .env scanning, faster for pre-commit hooks)
        #[arg(long)]
        staged: bool,
        /// Check if phantom tokens are in environment without proxy running
        #[arg(long)]
        runtime: bool,
    },

    /// List stored secret names (never shows values)
    #[command(next_help_heading = "Daily use")]
    List {
        /// Emit JSON instead of the human-readable table
        #[arg(long)]
        json: bool,
        /// Show TTL/expiry countdown for each secret
        #[arg(long)]
        show_expiry: bool,
        /// Only show secrets whose anomaly score is >= this value (0=all, 1=caution+, 2=alert only).
        /// Reads per-secret rate-limit stats from the audit log.
        #[arg(long, value_name = "SCORE")]
        min_anomaly_score: Option<u8>,
    },

    /// Create a new secret name transactionally; existing names are never replaced
    #[command(next_help_heading = "Daily use")]
    Add {
        /// Secret name (e.g., OPENAI_API_KEY)
        name: String,
        /// Legacy positional secret value; rejected because argv is observable
        #[arg(hide = true)]
        value: Option<String>,
        /// Read one new-name value from stdin; existing names are denied before the read
        #[arg(long)]
        stdin: bool,
    },

    /// Remove a secret transactionally after an exact trusted-terminal challenge
    #[command(next_help_heading = "Daily use")]
    Remove {
        /// Secret name to remove
        name: String,
    },

    /// Reveal a secret value (print to stdout or copy to clipboard)
    #[command(next_help_heading = "Daily use")]
    Reveal {
        /// Secret name to reveal
        name: String,
        /// Copy to clipboard instead of printing (auto-clears after 30s)
        #[arg(short, long)]
        clipboard: bool,
        /// Legacy flag; secret reveal now always requires a trusted terminal
        #[arg(short, long, hide = true)]
        yes: bool,
    },

    /// Copy a secret to an initialized target; existing target ownership is never overwritten
    #[command(next_help_heading = "Daily use")]
    Copy {
        /// Secret name in this project
        name: String,
        /// Target project directory
        #[arg(long)]
        to: std::path::PathBuf,
        /// Rename the secret in the target project
        #[arg(long, alias = "as")]
        rename: Option<String>,
    },

    /// Generate .env.example for team onboarding
    #[command(next_help_heading = "Daily use")]
    Env {
        /// Output file name (defaults to .env.example)
        #[arg(short, long, default_value = ".env.example")]
        output: String,
    },

    /// Explain why a key is or isn't protected
    #[command(next_help_heading = "Daily use")]
    Why {
        /// Environment variable name to explain
        key: String,
    },

    // ───────────────────────── Sync & teams ──────────────────────────
    /// Log in only after two exact trusted-terminal challenges
    #[command(next_help_heading = "Sync & teams")]
    Login,

    /// Log out only after an exact trusted-terminal challenge
    #[command(next_help_heading = "Sync & teams")]
    Logout,

    /// Cloud status plus trusted-terminal push/pull commands
    #[command(next_help_heading = "Sync & teams")]
    Cloud {
        #[command(subcommand)]
        action: CloudAction,
    },

    /// Authenticated team reads and trusted-terminal team mutations
    #[command(next_help_heading = "Sync & teams")]
    Team {
        #[command(subcommand)]
        action: TeamAction,
    },

    /// Sync secrets to deployment platforms (Vercel, Railway)
    #[command(next_help_heading = "Sync & teams")]
    Sync {
        /// Platform to sync to (vercel, railway). Syncs all configured targets if omitted.
        #[arg(short, long)]
        platform: Option<String>,
        /// Override project ID for this sync
        #[arg(long)]
        project: Option<String>,
        /// Preview targets, filters, and selected secret names without decrypting values or calling platform APIs
        #[arg(long)]
        dry_run: bool,
        /// Only push secrets whose names match this glob pattern (e.g. STRIPE_*).
        /// Repeatable: multiple --only flags are OR-ed together.
        /// Also honoured via `only = [...]` in each [[sync]] block in .phantom.toml.
        #[arg(long, value_name = "PATTERN")]
        only: Vec<String>,
    },

    /// Pull secrets from a deployment platform into the vault
    #[command(next_help_heading = "Sync & teams")]
    Pull {
        /// Platform to pull from (vercel, railway)
        #[arg(long)]
        from: String,
        /// Project ID on the platform
        #[arg(long)]
        project: String,
        /// Environment (Railway only, defaults to "production")
        #[arg(long)]
        environment: Option<String>,
        /// Service ID (Railway only)
        #[arg(long)]
        service: Option<String>,
        /// Overwrite existing local secrets
        #[arg(long)]
        force: bool,
    },

    /// Export to a new encrypted backup after an exact trusted-terminal challenge
    #[command(next_help_heading = "Sync & teams")]
    Export {
        /// New encrypted backup path (must not already exist)
        #[arg(short, long)]
        output: Option<String>,
        /// Deprecated and rejected: argv can expose the passphrase
        #[arg(short, long, hide = true)]
        passphrase: Option<String>,
        /// Deprecated and rejected for export: enter a dedicated passphrase at the trusted-terminal prompt
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
        /// Legacy plaintext mode; retained only to fail closed
        #[arg(long, hide = true)]
        json: bool,
        /// Legacy acknowledgement flag; retained only to fail closed
        #[arg(long, hide = true)]
        allow_plaintext: bool,
    },

    /// Import only after an exact trusted-terminal challenge; --force never bypasses it
    ///
    /// Phantom encrypted backup:
    ///   phantom import <FILE>
    ///   phantom import <FILE> --passphrase-file <PRIVATE_FILE>  # non-Windows only
    ///
    /// Competitor migration (--from):
    ///   phantom import --from doppler    --file dump.json
    ///   phantom import --from infisical  --file export.env
    ///   phantom import --from dotenvx   --file .env
    ///   phantom import --from 1password  --file 1p-export.json
    ///   phantom import --from env        --file .env
    ///
    /// Note: dotenvx encrypted .env.vault files are not supported — run
    ///   `dotenvx decrypt --stdout > .env` first, then import the plain .env.
    #[command(next_help_heading = "Sync & teams")]
    Import {
        /// Path to the encrypted Phantom backup
        #[arg(required_unless_present = "from")]
        file: Option<String>,
        /// Deprecated and rejected: argv can expose the passphrase
        #[arg(short, long, hide = true)]
        passphrase: Option<String>,
        /// Read from a private regular file on non-Windows platforms (maximum 4096 bytes)
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
        /// Import source: doppler | infisical | dotenvx | 1password | env
        #[arg(long, value_name = "SOURCE")]
        from: Option<String>,
        /// Path to the export file (required with --from)
        #[arg(long = "file", alias = "file-path", value_name = "FILE", required_if_eq_all([("from", "doppler"), ("from", "infisical"), ("from", "dotenvx"), ("from", "1password"), ("from", "env")]))]
        file_path: Option<String>,
        /// Select overwrite policy for existing secrets; never bypasses the exact trusted-terminal ceremony
        #[arg(long)]
        force: bool,
    },

    /// Wrap package.json scripts with `phantom exec` (no more manual prefix)
    #[command(next_help_heading = "Sync & teams")]
    Wrap {
        /// Only wrap specific scripts (by name)
        #[arg(long)]
        only: Option<Vec<String>>,
        /// Skip specific scripts (by name)
        #[arg(long)]
        skip: Option<Vec<String>>,
    },

    /// Unwrap package.json scripts (restore originals from :raw variants)
    #[command(next_help_heading = "Sync & teams")]
    Unwrap,

    // ───────────────────────── Maintenance ───────────────────────────
    /// Check for updates; standalone installs may self-replace, while managed installs route to their owner.
    #[command(next_help_heading = "Maintenance")]
    Upgrade {
        /// Deprecated and rejected: cannot bypass the standalone replacement ceremonies
        #[arg(long)]
        force: bool,
        /// Print available version without modifying the binary
        #[arg(long)]
        check_only: bool,
    },

    /// Watch .env files and auto-detect new unprotected secrets
    #[command(next_help_heading = "Maintenance")]
    Watch {
        /// Deprecated and disabled before mutation: use watch for detection,
        /// then run `phantom init` for transactional protection.
        #[arg(long)]
        auto: bool,
        /// Deprecated and disabled: the legacy watcher remapped local phm_
        /// placeholders but did not rotate provider credentials.
        #[arg(long, hide = true)]
        auto_rotate: bool,
    },

    /// Regenerate all phantom tokens after an exact attached-terminal challenge
    #[command(next_help_heading = "Maintenance")]
    Rotate {
        /// Sync a newly provider-rotated credential. Rejected for a local-only
        /// Phantom token remap because the provider credential is unchanged.
        #[arg(long)]
        sync: bool,
        /// Deprecated and disabled for local token remaps: remapping a phm_
        /// placeholder cannot renew a provider credential's TTL.
        #[arg(long, value_name = "DAYS", hide = true)]
        with_expiry: Option<u64>,
        /// Deprecated and disabled: legacy shadow mode generated only a local
        /// phm_cand_ placeholder, not a provider-issued credential.
        #[arg(long, hide = true)]
        shadow: bool,
        /// Secret name for the reserved provider-rotation surface. In this release,
        /// every live provider path is denied before credential or network access.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Deprecated and disabled: the legacy schedule only remapped local
        /// Phantom placeholders and did not rotate provider credentials.
        #[arg(long, value_name = "STRATEGY", conflicts_with = "name", hide = true)]
        schedule_strategy: Option<String>,
        /// Reserved vendor-specific rotation selector. All providers are hard
        /// denied before bootstrap credential access and network I/O in this release.
        #[arg(long, value_name = "PROVIDER", conflicts_with_all = ["shadow", "schedule_strategy", "with_expiry", "batch"])]
        provider: Option<String>,

        /// Metadata-only discovery/manual guidance. Vendor execution is hard
        /// denied before credential or network access in this release.
        #[arg(long, conflicts_with_all = ["shadow", "schedule_strategy", "provider"])]
        batch: bool,

        /// With --batch: consider secrets expiring within this many days as due
        /// for rotation (default: 30).
        #[arg(long, value_name = "DAYS", default_value_t = 30, requires = "batch")]
        rotation_window_days: u64,
    },

    /// Inspect configured grant metadata. Enrollment and remote revocation are
    /// hard-denied in this release; obtain credentials at the provider and
    /// store them with trusted-terminal `phantom add`.
    ///
    /// Subcommands: `add`, `list`, `status`, `revoke`.
    #[command(next_help_heading = "Maintenance")]
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },

    /// Validate stored secrets; live provider checks require exact trusted-terminal consent.
    ///
    /// Sub-commands: `schedule`, `history`
    #[command(next_help_heading = "Maintenance")]
    Validate {
        #[command(subcommand)]
        action: Option<ValidateAction>,
        /// Validate all secrets in the vault (top-level shortcut)
        #[arg(long)]
        check_all: bool,
        /// Number of concurrent validation jobs (default: 4)
        #[arg(long, short = 'j', value_name = "N")]
        jobs: Option<usize>,
        /// Deprecated and disabled: legacy candidates were local placeholders,
        /// not provider-issued credentials, and cannot be promoted.
        #[arg(long, value_name = "NAME", conflicts_with = "check_all", hide = true)]
        promote: Option<String>,
        /// Run as a background daemon, polling per-secret schedules and writing
        /// results to ~/.phantom/validation-report.json for MCP tools to consume.
        /// Respects per-secret [phantom.secrets.{name}.validation] config from
        /// .phantom.toml (schedule: daily|weekly|never, timeout_secs).
        #[arg(long, conflicts_with_all = ["check_all", "promote"])]
        watch: bool,
    },

    /// View the opt-in audit log (requires PHANTOM_AUDIT=1 to start logging)
    #[command(next_help_heading = "Maintenance")]
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Open a closed-catalog Phantom page after an exact trusted-terminal challenge.
    /// Aliases: dashboard, billing, team, docs, pricing, github, issues, site.
    /// Other words and arbitrary URLs are rejected before browser access.
    #[command(next_help_heading = "Maintenance")]
    Open {
        /// What to open. Defaults to the dashboard if omitted.
        #[arg(default_value = "")]
        target: String,
    },

    /// List expired/expiring secrets; optionally remap their local Phantom tokens
    #[command(next_help_heading = "Maintenance")]
    SecretsExpiringSoon {
        /// Warn about secrets expiring within this many days (default: 7)
        #[arg(long, default_value_t = 7)]
        days: u64,
        /// Deprecated name: remap local phm_ placeholders only. Provider
        /// credentials and expiry metadata remain unchanged.
        #[arg(long)]
        auto_rotate: bool,
        /// Deprecated and rejected: token remapping creates no credential to sync
        #[arg(long, requires = "auto_rotate")]
        sync: bool,
        /// Emit JSON instead of human-readable output
        #[arg(long)]
        json: bool,
    },

    /// TTL metadata: exact-terminal set, read-only enforce, and deprecated local remap
    ///
    /// Subcommands:
    ///   phantom expiry set <KEY> <DAYS>      — mark a secret expiring in N days
    ///   phantom expiry enforce [--fail-closed] — exit 1 if any secret has expired
    ///   phantom expiry rotate <KEY>          — deprecated local phm_ token remap only
    #[command(next_help_heading = "Maintenance")]
    Expiry {
        #[command(subcommand)]
        action: ExpiryAction,
    },

    /// Internal: clear the system clipboard after N seconds. Spawned by
    /// `phantom reveal --copy` so the parent CLI can exit immediately while a
    /// detached child waits, then clears. Hidden from `--help`.
    #[command(name = "__clear-clipboard-after", hide = true)]
    ClearClipboardAfter {
        /// Seconds to wait before clearing
        #[arg(long, default_value_t = 30)]
        secs: u64,
    },
}

#[derive(Subcommand)]
enum ExpiryAction {
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

#[derive(Subcommand)]
enum ValidateAction {
    /// Show or configure validation scheduling; writes require exact terminal consent.
    ///
    /// Examples:
    ///   phantom validate schedule hourly
    ///   phantom validate schedule 6h
    ///   phantom validate schedule daily@2am
    ///   phantom validate schedule weekly
    ///   phantom validate schedule --disable
    ///   phantom validate schedule --status
    Schedule {
        /// Schedule interval: hourly, 6h, daily, daily@2am, weekly, disabled
        #[arg(value_name = "INTERVAL")]
        interval: Option<String>,
        /// Show current schedule and staleness without changing anything
        #[arg(long, conflicts_with = "interval")]
        status: bool,
        /// Disable the scheduler
        #[arg(long, conflicts_with = "interval")]
        disable: bool,
    },
    /// Show past validation run history.
    History {
        /// Number of most-recent runs to show (default: 20)
        #[arg(long, short = 'n', value_name = "N")]
        last: Option<usize>,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Run the MCP stdio server in-process (used by AI clients like Claude Code)
    Serve,
}

#[derive(Subcommand)]
enum WorkspaceCliAction {
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

// The `Add` variant carries many optional per-provider flags (client id/secret
// env, scopes, team, account, org, …); boxing a clap-derived variant complicates
// the derive for no runtime benefit here, so the size skew is accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum GrantAction {
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

#[derive(Subcommand)]
enum AgentAction {
    /// Emit the read-only readiness report
    Report {
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Human-readable view of the readiness report
    Doctor,
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

#[derive(Subcommand)]
enum VaultAction {
    /// Copy this Linux project's volatile keyutils vault into Secret Service
    #[command(name = "migrate-linux")]
    MigrateLinux,
}

#[derive(Subcommand)]
enum TeamAction {
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

#[derive(Subcommand)]
enum CloudAction {
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

/// Stack size for the real main thread.
///
/// Windows gives the process main thread a 1 MiB stack (unix platforms give
/// 8 MiB). Debug builds of this CLI need more than 1 MiB — the clap-derive
/// parser for our large `Commands` enum alone overflows 1 MiB before any
/// subcommand output (STATUS_STACK_OVERFLOW / 0xC00000FD on windows-latest
/// CI, reproducible on unix with `ulimit -s 1024`). Run the real main on a
/// spawned thread with an explicit, platform-independent stack size instead
/// of relying on the OS default.
const MAIN_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    let handle = std::thread::Builder::new()
        .name("phantom-main".into())
        .stack_size(MAIN_STACK_SIZE)
        .spawn(run)?;
    match handle.join() {
        Ok(result) => result,
        // Propagate a panic on the worker thread as if it happened here so
        // the process still dies with the standard panic exit status.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let global_json = cli.json;

    // Initialize logging — only show tracing output in verbose mode
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        // Suppress all tracing output by default — our CLI uses println for user-facing output
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();

    match cli.command {
        Commands::Init {
            from,
            all,
            dry_run,
            jobs,
            empty,
        } => {
            if empty {
                commands::init::run_empty()
            } else {
                match all {
                    Some(root) => {
                        let j = jobs
                            .or_else(commands::init::multi::jobs_from_env)
                            .unwrap_or(commands::init::multi::DEFAULT_JOBS);
                        commands::init::multi::run(root, dry_run, j)
                    }
                    None => commands::init::run(&from),
                }
            }
        }
        Commands::List {
            json,
            show_expiry,
            min_anomaly_score,
        } => commands::list::run_with_expiry(json, show_expiry, min_anomaly_score),
        Commands::Add { name, value, stdin } => commands::add::run(&name, value, stdin),
        Commands::Remove { name } => commands::remove::run(&name),
        Commands::Reveal {
            name,
            clipboard,
            yes,
        } => commands::reveal::run(&name, clipboard, yes),
        Commands::Status { oneline } => commands::status::run(oneline),
        Commands::Rotate {
            sync,
            with_expiry,
            shadow,
            name,
            schedule_strategy,
            provider,
            batch,
            rotation_window_days,
        } => {
            if batch {
                commands::rotate::run_batch(rotation_window_days, sync, cli.json)
            } else if shadow {
                let secret_name =
                    name.ok_or_else(|| anyhow::anyhow!("--shadow requires --name <NAME>"))?;
                commands::rotate::run_shadow(&secret_name).map(|_| ())
            } else if provider.is_some() || name.is_some() {
                let secret_name =
                    name.ok_or_else(|| anyhow::anyhow!("--provider requires --name <NAME>"))?;
                commands::rotate::run_with_provider(
                    provider.as_deref(),
                    &secret_name,
                    sync,
                    cli.json,
                )
            } else if let Some(ref strategy_str) = schedule_strategy {
                commands::rotate::run_with_schedule_strategy(strategy_str, sync, with_expiry)
            } else {
                commands::rotate::run_with_expiry(sync, with_expiry)
            }
        }
        Commands::Validate {
            action,
            check_all,
            jobs,
            promote,
            watch,
        } => match action {
            Some(ValidateAction::Schedule {
                interval,
                status,
                disable,
            }) => commands::validation_scheduler::run_schedule(
                interval.as_deref(),
                status,
                disable,
                cli.json,
            ),
            Some(ValidateAction::History { last }) => {
                commands::validation_scheduler::run_history(last, cli.json)
            }
            None => {
                if watch {
                    commands::validate::run_watch(jobs, cli.json)
                } else if let Some(secret_name) = promote {
                    commands::rotate::run_validate_promote(&secret_name, true)
                } else {
                    commands::validate::run(check_all, jobs, cli.json)
                }
            }
        },
        Commands::Doctor { fix, expiry } => commands::doctor::run_doctor(fix, expiry),
        Commands::Agent { action } => match action {
            AgentAction::Report { json } => commands::agent::report(json || global_json),
            AgentAction::Doctor => commands::agent::doctor(),
            AgentAction::Setup { dry_run, apply } => commands::agent::setup(dry_run, apply),
        },
        Commands::Exec { cmd } => commands::exec::run(&cmd, None),
        Commands::Start { daemon } => commands::start::run(daemon),
        Commands::Stop => commands::stop::run(),
        Commands::Check { staged, runtime } => commands::check::run(staged, runtime),
        Commands::Pull {
            from,
            project,
            environment,
            service,
            force,
        } => commands::pull::run(&from, &project, environment, service, force),
        Commands::Setup {
            client,
            print,
            audit_mode,
        } => commands::setup::run(client, print, audit_mode),
        Commands::Sync {
            platform,
            project,
            dry_run,
            only,
        } => commands::sync::run(platform, project, only, dry_run, cli.json),
        Commands::Env { output } => commands::env::run(&output),
        Commands::Export {
            output,
            passphrase,
            passphrase_file,
            json,
            allow_plaintext,
        } => commands::export_cmd::run(
            output.as_deref(),
            passphrase,
            passphrase_file.as_deref(),
            json,
            allow_plaintext,
        ),
        Commands::Import {
            file,
            passphrase,
            passphrase_file,
            from,
            file_path,
            force,
        } => {
            if let Some(source) = from {
                commands::export_cmd::reject_legacy_passphrase(passphrase)?;
                if passphrase_file.is_some() {
                    anyhow::bail!("--passphrase-file is only valid for encrypted Phantom backups");
                }
                let fp = file_path.as_deref().unwrap_or("");
                commands::import_cmd::run_from(&source, fp, force)
            } else {
                commands::import_cmd::run(
                    file.as_deref().unwrap_or(""),
                    passphrase,
                    passphrase_file.as_deref(),
                    force,
                )
            }
        }
        Commands::Login => commands::login::run(),
        Commands::Logout => commands::logout::run(),
        Commands::Cloud { action } => match action {
            CloudAction::Push => commands::cloud::run_push(),
            CloudAction::Pull { force } => commands::cloud::run_pull(force),
            CloudAction::Status => commands::cloud::run_status(),
        },
        Commands::Watch { auto, auto_rotate } => {
            commands::watch::run_with_rotate(auto, auto_rotate)
        }
        Commands::Why { key } => commands::why::run(&key),
        Commands::Wrap { only, skip } => commands::wrap::run(&only, &skip),
        Commands::Unwrap => commands::unwrap::run(),
        Commands::Copy { name, to, rename } => commands::copy::run(&name, &to, &rename),
        Commands::Audit { action } => match action {
            AuditAction::Show {
                last,
                op,
                name,
                json,
                leaked_secrets,
            } => commands::audit::run_show(
                last,
                op.as_deref(),
                name.as_deref(),
                json,
                leaked_secrets,
            ),
            AuditAction::Tail { op, name } => {
                commands::audit::run_tail(op.as_deref(), name.as_deref())
            }
            AuditAction::Path => commands::audit::run_path(),
            AuditAction::Verify { with_context } => commands::audit::run_verify(with_context),
            AuditAction::Stats {
                json,
                top,
                analytics,
                min_anomaly_score,
            } => commands::audit::run_stats(json, top, analytics, min_anomaly_score),
            AuditAction::Export {
                format,
                period,
                min_anomaly_score,
            } => commands::audit::run_export(&format, &period, min_anomaly_score),
            AuditAction::Analytics {
                window,
                min_anomaly_score,
                format,
                export,
                auto_alert_on_anomaly,
            } => commands::audit::run_analytics(
                window,
                min_anomaly_score,
                &format,
                export.as_deref(),
                auto_alert_on_anomaly,
            ),
            AuditAction::Anomalies {
                realtime,
                threshold,
                name,
                max_accesses_per_hour,
                max_quiet_days,
                json,
            } => commands::audit::run_anomalies(
                realtime,
                threshold,
                name.as_deref(),
                max_accesses_per_hour,
                max_quiet_days,
                json,
            ),
            AuditAction::Incidents {
                min_confidence,
                json,
                auto_rotate_on_high,
            } => commands::audit::run_incidents(min_confidence, json, auto_rotate_on_high),
            AuditAction::Alerts {
                last,
                backfill,
                json,
            } => commands::audit::run_alerts(last, backfill, json),
            AuditAction::ExportRange {
                format,
                from,
                to,
                name,
                op,
                pid,
            } => commands::audit::run_export_range(
                &format,
                &from,
                &to,
                name.as_deref(),
                op.as_deref(),
                pid,
            ),
            AuditAction::Report {
                r#type,
                from,
                to,
                save,
                compact,
            } => commands::audit::run_report(&r#type, &from, &to, save, compact),
        },
        Commands::Open { target } => commands::open::run(&target),
        Commands::Upgrade { force, check_only } => commands::upgrade::run(force, check_only),
        Commands::Completion { shell } => commands::completion::run(shell),
        Commands::Mcp { action } => match action {
            McpAction::Serve => commands::mcp::run_serve(),
        },
        Commands::McpApprove { nonce } => commands::mcp_approve::run(&nonce),
        Commands::Workspace { action } => match action {
            WorkspaceCliAction::Plan { json } => commands::workspace::run_plan(json),
            WorkspaceCliAction::Apply { request } => commands::workspace::run_apply(&request),
            WorkspaceCliAction::Status { request, json } => {
                commands::workspace::run_status(&request, json)
            }
        },
        Commands::Vault { action } => match action {
            VaultAction::MigrateLinux => commands::vault::run_migrate_linux(cli.json),
        },
        Commands::SecretsExpiringSoon {
            days,
            auto_rotate,
            sync,
            json,
        } => commands::expiry::run(days, auto_rotate, sync, json),
        Commands::Expiry { action } => match action {
            ExpiryAction::Set { key, days } => commands::expiry::run_set(&key, days),
            ExpiryAction::Enforce { fail_closed, json } => {
                commands::expiry::run_enforce(fail_closed, json)
            }
            ExpiryAction::Rotate { key } => commands::expiry::run_rotate(&key),
        },
        Commands::ClearClipboardAfter { secs } => commands::reveal::run_clear_after(secs),
        Commands::Team { action } => match action {
            TeamAction::List => commands::team::run_list(),
            TeamAction::Create { name } => commands::team::run_create(&name),
            TeamAction::Members { team_id } => commands::team::run_members(&team_id),
            TeamAction::Invite {
                team_id,
                github_login,
                role,
            } => commands::team::run_invite(&team_id, &github_login, &role),
            TeamAction::KeyPublish { team_id } => commands::team::run_key_publish(&team_id),
            TeamAction::VaultPush { team_id } => commands::team::run_vault_push(&team_id),
            TeamAction::VaultPull { team_id } => commands::team::run_vault_pull(&team_id),
            TeamAction::Revoke {
                team_id,
                github_login,
                yes,
            } => commands::team::run_revoke(&team_id, &github_login, yes),
            TeamAction::RotateVault { team_id } => commands::team::run_rotate_vault(&team_id),
        },
        Commands::Grant { action } => match action {
            GrantAction::Add {
                provider,
                org,
                name,
                rotate_secret,
                flow,
                client_id,
                client_secret_env,
                scope,
                team,
                account,
                no_browser,
                json,
            } => commands::grant::add::run_add(
                &provider,
                org,
                name,
                rotate_secret,
                no_browser,
                flow.as_deref(),
                client_id,
                client_secret_env,
                scope,
                team,
                account,
                json || global_json,
            ),
            GrantAction::List { json } => commands::grant::list::run_list(json || global_json),
            GrantAction::Status { provider, json } => {
                commands::grant::status::run_status(provider.as_deref(), json || global_json)
            }
            GrantAction::Revoke { provider, json } => {
                commands::grant::revoke::run_revoke(&provider, json || global_json)
            }
        },
    }
}
