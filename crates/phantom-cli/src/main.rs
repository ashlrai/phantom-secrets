mod broken_pipe;
mod cli_actions;
mod cli_json;
mod commands;
mod dispatch;
#[cfg(test)]
mod doc_facts;
mod report_file;
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
use cli_actions::{
    AgentAction, CloudAction, CryptoAction, ExpiryAction, GrantAction, LeaksAction, McpAction,
    TeamAction, ValidateAction, VaultAction, WorkspaceCliAction,
};
use commands::audit::AuditAction;

#[derive(Parser)]
#[command(
    name = "phantom",
    about = "Reduce API-key exposure in supported AI-agent workflows",
    long_about = "Phantom replaces managed dotenv secrets with non-provider phantom placeholders.\n\
                  Its authenticated local proxy matches exact routes and injects only route-owned authentication into each route's fixed header; client headers and bodies never resolve placeholders.\n\
                  Agents confined to value-blind tools and supported proxy routes do not receive stored values.\n\
                  Unmanaged files, same-user processes, arbitrary tools, and unsupported protocols remain outside this boundary.\n\n\
                  Quick start (from the project root):\n  \
                    phantom init                  protect .env secrets and rewrite them as phm_ tokens\n  \
                    phantom agent doctor          check the repo is ready for AI agents\n  \
                    phantom setup --client codex  wire MCP into claude, cursor, windsurf, or codex\n  \
                    phantom exec -- <command>     run your app or agent through the local proxy\n\n\
                  Commands by task:\n  \
                    Setup         init · agent · setup · doctor · workspace · vault · completion · mcp · mcp-approve\n  \
                    Daily use     exec · start · stop · status · check · redact · list · add · remove · reveal · copy · env · why · git-credential\n  \
                    Sync & teams  login · logout · cloud · team · sync · pull · export · import · wrap · unwrap\n  \
                    Maintenance   upgrade · watch · rotate · grant · validate · expiry · secrets-expiring-soon · open · audit · leaks · crypto",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose/debug logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress progress output from exec, wrap, and unwrap (errors and warnings still print; other commands ignore it)
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
        /// Report the keys and files this init would write, without changing anything.
        /// With --all, scan and report what would change without modifying anything.
        #[arg(long)]
        dry_run: bool,
        /// With --all: number of repos to initialise concurrently.
        /// Defaults to PHANTOM_INIT_JOBS env var, then 4.
        #[arg(long, short = 'j', value_name = "N", requires = "all")]
        jobs: Option<usize>,
        /// Create a valid .phantom.toml and empty vault without requiring a .env file.
        /// Use this to bootstrap a brand-new project before any secrets exist.
        #[arg(long, conflicts_with = "all")]
        empty: bool,
    },

    /// Wire Phantom into an AI client (Claude Code, Cursor, Windsurf, Codex, Gemini CLI)
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
        /// Read-only: list which clients (Claude Code, Cursor, Windsurf, Codex,
        /// Gemini CLI) have Phantom wired. Use the global --json for JSON.
        #[arg(long, conflicts_with_all = ["client", "print", "audit_mode"])]
        status: bool,
        /// Show what setup would change for Cursor, Windsurf, Gemini CLI or
        /// Codex, as a diff, without writing anything
        #[arg(long, conflicts_with_all = ["print", "audit_mode", "status"])]
        dry_run: bool,
        /// Overwrite an existing, differing `phantom` entry in the client config.
        /// Without it, setup refuses and names the entry. A backup and a
        /// manifest are written first.
        #[arg(long, conflicts_with_all = ["print", "audit_mode", "status", "dry_run"])]
        replace: bool,
        /// Reverse the changes recorded in ~/.phantom/setup-manifest.json.
        /// Shows what would be restored or removed; add --apply to do it.
        #[arg(long, conflicts_with_all = ["client", "print", "audit_mode", "status", "dry_run", "replace"])]
        undo: bool,
        /// With --undo: perform the undo instead of only showing it
        #[arg(long, requires = "undo")]
        apply: bool,
        /// With --undo --apply: also undo files that changed after setup wrote them
        #[arg(long, requires = "apply")]
        force_undo: bool,
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
        /// Emit one JSON report on stdout instead of the human checklist
        #[arg(long)]
        json: bool,
        /// Exit 2 when the report has any issue. Warnings count the same as
        /// failures. Omit it to keep the current exit status. Exit 1 stays a
        /// command error. Does not apply to --pq or --all.
        #[arg(long, conflicts_with_all = ["pq", "all"])]
        strict: bool,
        /// Print a read-only, value-free post-quantum readiness report
        /// (algorithms in use, which are quantum-vulnerable) instead of the
        /// health checks. Combine with --json for machine-readable output.
        #[arg(long)]
        pq: bool,
        /// One read-only, value-free report that combines the health checks,
        /// the post-quantum report, agent readiness, MCP approval status and
        /// the gateway base-URL environment. Fixes nothing. Combine with
        /// --json for machine-readable output.
        #[arg(long, conflicts_with_all = ["fix", "pq", "expiry"])]
        all: bool,
        /// Write the full report to this new file (never overwritten) and
        /// print only a short summary. Text by default, JSON with --json.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["pq", "all"])]
        output: Option<std::path::PathBuf>,
    },

    /// Print a shell-completion script to stdout
    ///
    /// Source the output from your shell rc, e.g.
    ///   bash:       phantom completion bash > ~/.local/share/bash-completion/completions/phantom
    ///   zsh:        phantom completion zsh > "${fpath[1]}/_phantom"
    ///   fish:       phantom completion fish > ~/.config/fish/completions/phantom.fish
    ///   powershell: phantom completion powershell | Out-String | Invoke-Expression
    #[command(next_help_heading = "Setup", verbatim_doc_comment)]
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

    /// Approve a pending MCP nonce for a mutating vault operation
    ///
    /// Run this in a trusted terminal after the MCP server prints a nonce to
    /// stderr. The returned approval_token must be passed as `approval_token`
    /// in the subsequent MCP tool call.
    ///
    /// Example:
    ///   phantom mcp-approve d3a9f2...
    #[command(
        name = "mcp-approve",
        next_help_heading = "Setup",
        verbatim_doc_comment
    )]
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
    /// Supply a GitHub credential to Git through a pipe (never a terminal or file).
    #[command(next_help_heading = "Daily use")]
    GitCredential {
        /// Git credential protocol operation; store and erase are effect-free.
        #[arg(value_enum)]
        operation: commands::git_credential::Operation,
        /// Exact project vault entry to use.
        #[arg(long, default_value = "GITHUB_TOKEN")]
        secret: String,
    },

    /// Start the proxy and run a command
    #[command(next_help_heading = "Daily use")]
    Exec {
        /// Opt-in: use the custody namespace of this source checkout. Accepted
        /// only when the current directory is a linked git worktree of it
        /// (same git common dir) with a byte-identical `.phantom.toml`.
        #[arg(long, value_name = "SOURCE_CHECKOUT")]
        bind_source: Option<std::path::PathBuf>,
        /// Scrub managed values and recognized credential formats from piped stdout/stderr.
        /// Opt-in piping changes terminal detection and may affect child buffering.
        #[arg(long)]
        scrub_output: bool,
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

    /// Show project status (--json uses value-free metadata inspection)
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
        /// Scan every environment variable for phantom tokens a live proxy session does not own
        #[arg(long)]
        runtime: bool,
        /// Emit a names-only JSON report on stdout (exit status unchanged)
        #[arg(long)]
        json: bool,
    },

    /// Scrub known credential shapes from stdin to stdout (no vault access)
    #[command(next_help_heading = "Daily use")]
    Redact {
        /// Flush each sanitized line; reject lines over 1 MiB. Does not detect arbitrary or encoded secrets
        #[arg(long, required = true)]
        stream: bool,
    },

    /// List stored secret names (never shows values)
    #[command(next_help_heading = "Daily use")]
    List {
        /// Only list this environment (for example dev, staging, prod, or default).
        /// Omit to list all environments. Never changes the active environment.
        #[arg(long, value_name = "ENV")]
        scope: Option<String>,
        /// Emit JSON instead of the human-readable table
        #[arg(long)]
        json: bool,
        /// Show TTL/expiry countdown for each secret
        #[arg(long)]
        show_expiry: bool,
        /// Only show secrets whose anomaly score is >= this value (0=all, 1=caution+, 2=alert only).
        /// Reads per-secret retrieval counts from the audit log; an unreadable or
        /// tampered log is an error, not an all-normal answer.
        #[arg(long, value_name = "SCORE", value_parser = clap::value_parser!(u8).range(0..=2))]
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
        /// Read one new-name value from a pipe up to EOF (64 KiB cap); input with more than one line needs --multiline or --first-line; existing names are denied before the read
        #[arg(long)]
        stdin: bool,
        /// With --stdin: store every line of multi-line input (PEM keys, JSON documents)
        #[arg(long, requires = "stdin", conflicts_with = "first_line")]
        multiline: bool,
        /// With --stdin: store only the first line (pass/gopass put metadata after it)
        #[arg(long, requires = "stdin")]
        first_line: bool,
        /// Generate a 256-bit random secret locally; print only name and SHA-256 fingerprint
        #[arg(long, conflicts_with_all = ["stdin", "value", "multiline", "first_line", "dry_run"])]
        generate: bool,
        /// Report the key and files this add would write, without reading a value or changing anything
        #[arg(long, conflicts_with_all = ["stdin", "multiline", "first_line"])]
        dry_run: bool,
    },

    /// Remove a secret transactionally after an exact trusted-terminal challenge
    #[command(next_help_heading = "Daily use")]
    Remove {
        /// Secret name to remove
        name: String,
        /// Report the key and files this removal would write, without deleting anything
        #[arg(long)]
        dry_run: bool,
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
        /// Allow copying between projects whose `owner` labels differ
        #[arg(long)]
        allow_cross_owner: bool,
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
        /// Exit 2 when the key is not protected. A JSON report for a missing
        /// key also exits 2. The human view of a missing key is still a
        /// command error (exit 1). Omit it to keep the current exit status.
        #[arg(long)]
        strict: bool,
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
    /// Expected --file format per source (UTF-8 text; one leading UTF-8 BOM is
    /// ignored; UTF-16/UTF-32 files are refused with a re-save hint):
    ///   doppler    JSON object: {"KEY": "value"} or {"KEY": {"computed": "value"}}
    ///   infisical  .env KEY=value lines, or JSON array [{"key": "KEY", "value": "value"}]
    ///   dotenvx    plaintext .env, or flat JSON object {"KEY": "value"}
    ///   1password  flat JSON object you assemble: {"KEY": "value"}
    ///   env        plaintext .env KEY=value lines
    ///
    /// 1Password: Phantom never runs `op`. The file must be ONE flat JSON object
    /// whose names are environment variable names ([A-Za-z_][A-Za-z0-9_]*) and
    /// whose values are strings, numbers or booleans; empty and null values are
    /// skipped. Raw `op item get --format json` output is refused; flatten it:
    ///   {"STRIPE_SECRET_KEY": "value", "DATABASE_URL": "value"}
    ///   op item get "My App Secrets" --vault Dev --format json \
    ///     | jq '[.fields[] | select(.value != null and .value != "")]
    ///           | if (map(.label) | unique | length) != length
    ///             then error("duplicate field labels") else map({(.label): .value}) | add end' \
    ///     > 1p-export.json
    ///
    /// In every JSON format a nested object or array value, a repeated name, or
    /// a name that is not an environment variable name refuses the whole file.
    ///
    /// Note: dotenvx encrypted .env.vault files are not supported — run
    ///   `dotenvx decrypt --stdout > .env` first, then import the plain .env.
    #[command(next_help_heading = "Sync & teams", verbatim_doc_comment)]
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

    /// Leak response tools (read-only preview)
    #[command(next_help_heading = "Maintenance")]
    Leaks {
        #[command(subcommand)]
        action: LeaksAction,
    },

    /// View the opt-in audit log (requires PHANTOM_AUDIT=1 to start logging)
    #[command(next_help_heading = "Maintenance")]
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Cryptography inventory: algorithms and format tags Phantom uses
    #[command(next_help_heading = "Maintenance")]
    Crypto {
        #[command(subcommand)]
        action: CryptoAction,
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
    #[command(next_help_heading = "Maintenance", verbatim_doc_comment)]
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

fn main() -> std::process::ExitCode {
    broken_pipe::install_panic_hook();
    let handle = match std::thread::Builder::new()
        .name("phantom-main".into())
        .stack_size(MAIN_STACK_SIZE)
        .spawn(dispatch::run)
    {
        Ok(handle) => handle,
        Err(error) => return report_error(&anyhow::Error::from(error)),
    };
    match handle.join() {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        // The reader of stdout went away (`phantom list | head`): a normal
        // end for a CLI, reported the way a shell reports SIGPIPE, with no
        // panic text or error line. The worker has already unwound.
        Ok(Err(error)) if broken_pipe::is_stdout_broken_pipe_error(&error) => {
            std::process::exit(broken_pipe::BROKEN_PIPE_EXIT)
        }
        Err(panic) if broken_pipe::is_stdout_broken_pipe_panic(&*panic) => {
            std::process::exit(broken_pipe::BROKEN_PIPE_EXIT)
        }
        Ok(Err(error)) if error.downcast_ref::<UsageError>().is_some() => {
            report_error(&error);
            std::process::ExitCode::from(2)
        }
        Ok(Err(error)) => report_error(&error),
        // Propagate a panic on the worker thread as if it happened here so
        // the process still dies with the standard panic exit status.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Print a command failure to stderr and return exit code 1.
///
/// Returning `anyhow::Result` from `main` prints the error with `{:?}`, which
/// appends a full stack backtrace whenever `RUST_BACKTRACE` or
/// `RUST_LIB_BACKTRACE` is set. Agent and CI shells commonly export
/// `RUST_BACKTRACE=1`, which buried actionable messages such as the non-TTY
/// `phantom add` refusal under dozens of frames. Keep the same
/// `Error:`/`Caused by:` layout without the backtrace.
fn report_error(error: &anyhow::Error) -> std::process::ExitCode {
    eprintln!("{}", format_error(error));
    std::process::ExitCode::FAILURE
}

fn format_error(error: &anyhow::Error) -> String {
    let mut message = format!("Error: {error}");
    let mut causes = error.chain().skip(1).peekable();
    if causes.peek().is_some() {
        message.push_str("\n\nCaused by:");
        for cause in causes {
            message.push_str(&format!("\n    {cause}"));
        }
    }
    message
}

/// A command-line usage error found after clap parsing. `main` reports it
/// like any error but exits 2, the status clap uses for usage errors.
#[derive(Debug)]
struct UsageError(String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

#[cfg(test)]
mod cli_tests;
