mod commands;
mod util;

use clap::{Parser, Subcommand};
use commands::audit::AuditAction;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "phantom",
    about = "Prevent AI coding agents from leaking your API keys",
    long_about = "Phantom replaces real secrets in your .env with worthless phantom tokens.\n\
                  A local proxy intercepts API calls, swaps in real credentials at the network layer.\n\
                  The AI agent never sees a real secret.\n\n\
                  Commands are grouped (in display order):\n  \
                    Setup        init · agent · setup · doctor · completion · mcp\n  \
                    Daily use    exec · start · stop · status · check · list · add · remove · reveal · copy · env · why\n  \
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
        #[arg(long)]
        dry_run: bool,
        /// With --all: number of repos to initialise concurrently.
        /// Defaults to PHANTOM_INIT_JOBS env var, then 4.
        #[arg(long, short = 'j', value_name = "N")]
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

    // ─────────────────────────── Daily use ───────────────────────────
    /// Start the proxy and run a command
    #[command(next_help_heading = "Daily use")]
    Exec {
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// Start the proxy server
    #[command(next_help_heading = "Daily use")]
    Start {
        /// Run in background (daemon mode)
        #[arg(short, long)]
        daemon: bool,
    },

    /// Stop the background proxy server
    #[command(next_help_heading = "Daily use")]
    Stop,

    /// Show proxy status and mapped secrets
    #[command(next_help_heading = "Daily use")]
    Status {
        /// Compact one-line output for shell prompts (e.g., "3 secrets · proxy off")
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
    },

    /// Add a secret to the vault
    #[command(next_help_heading = "Daily use")]
    Add {
        /// Secret name (e.g., OPENAI_API_KEY)
        name: String,
        /// Secret value. If omitted, phantom prompts silently on the terminal.
        /// Use --stdin to read from a pipe instead.
        value: Option<String>,
        /// Read the secret value from stdin (for piped use: echo "$VAL" | phantom add KEY --stdin)
        #[arg(long)]
        stdin: bool,
    },

    /// Remove a secret from the vault
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
        /// Skip confirmation (required for non-interactive use)
        #[arg(short, long)]
        yes: bool,
    },

    /// Copy a secret from this project's vault to another project
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
    /// Log in to Phantom Cloud
    #[command(next_help_heading = "Sync & teams")]
    Login,

    /// Log out of Phantom Cloud
    #[command(next_help_heading = "Sync & teams")]
    Logout,

    /// Cloud vault sync commands
    #[command(next_help_heading = "Sync & teams")]
    Cloud {
        #[command(subcommand)]
        action: CloudAction,
    },

    /// Team vault management
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

    /// Export secrets to an encrypted backup file or as plaintext JSON to stdout
    #[command(next_help_heading = "Sync & teams")]
    Export {
        /// Output file path (encrypted mode)
        #[arg(short, long)]
        output: Option<String>,
        /// Encryption passphrase (encrypted mode)
        #[arg(short, long)]
        passphrase: Option<String>,
        /// Emit secrets as a plaintext JSON object to stdout instead of an encrypted file
        #[arg(long)]
        json: bool,
        /// Required with --json: acknowledge that secrets will be emitted in plaintext
        #[arg(long)]
        allow_plaintext: bool,
    },

    /// Import secrets from an encrypted backup or a competitor export
    ///
    /// Legacy (phantom encrypted backup):
    ///   phantom import <FILE> --passphrase <PASS>
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
        /// Path to the encrypted backup file (legacy mode)
        #[arg(required_unless_present = "from")]
        file: Option<String>,
        /// Decryption passphrase (legacy mode, required without --from)
        #[arg(short, long, required_unless_present = "from")]
        passphrase: Option<String>,
        /// Import source: doppler | infisical | dotenvx | 1password | env
        #[arg(long, value_name = "SOURCE")]
        from: Option<String>,
        /// Path to the export file (required with --from)
        #[arg(long, value_name = "FILE", required_if_eq_all([("from", "doppler"), ("from", "infisical"), ("from", "dotenvx"), ("from", "1password"), ("from", "env")]))]
        file_path: Option<String>,
        /// Overwrite existing secrets without prompting
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
    /// Self-replace this binary with the latest GitHub release.
    #[command(next_help_heading = "Maintenance")]
    Upgrade {
        /// Skip confirmation prompt and upgrade immediately
        #[arg(long)]
        force: bool,
        /// Print available version without modifying the binary
        #[arg(long)]
        check_only: bool,
    },

    /// Watch .env files and auto-detect new unprotected secrets
    #[command(next_help_heading = "Maintenance")]
    Watch {
        /// Auto-protect new secrets without prompting
        #[arg(long)]
        auto: bool,
    },

    /// Regenerate phantom tokens (invalidates old ones)
    #[command(next_help_heading = "Maintenance")]
    Rotate {
        /// Also sync secrets to all configured deployment platforms after rotation
        #[arg(long)]
        sync: bool,
        /// Set a TTL (in days) on every secret after rotation. Sets expires_at and
        /// rotation_policy on each vault entry. Use `phantom list --show-expiry`
        /// and `phantom doctor --expiry` to monitor status.
        #[arg(long, value_name = "DAYS")]
        with_expiry: Option<u64>,
    },

    /// View the opt-in audit log (requires PHANTOM_AUDIT=1 to start logging)
    #[command(next_help_heading = "Maintenance")]
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Open a Phantom page in the browser. Defaults to the dashboard.
    /// Aliases: dashboard, billing, team, docs, pricing, github, issues, site.
    /// Any other word becomes https://phm.dev/<word>; full URLs pass through.
    #[command(next_help_heading = "Maintenance")]
    Open {
        /// What to open. Defaults to the dashboard if omitted.
        #[arg(default_value = "")]
        target: String,
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
enum McpAction {
    /// Run the MCP stdio server in-process (used by AI clients like Claude Code)
    Serve,
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
enum TeamAction {
    /// List your teams
    List,
    /// Create a new team
    Create {
        /// Team name
        name: String,
    },
    /// List team members
    Members {
        /// Team ID
        team_id: String,
    },
    /// Invite a member to a team
    Invite {
        /// Team ID
        team_id: String,
        /// GitHub username to invite
        github_login: String,
        /// Role to assign (member, admin, owner)
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Register your team-vault public key on a team you belong to.
    /// Run this once per team before pushing or pulling vaults.
    KeyPublish {
        /// Team ID
        team_id: String,
    },
    /// Push the current project's vault to a team (E2E encrypted to every
    /// member that has a registered public key).
    VaultPush {
        /// Team ID
        team_id: String,
    },
    /// Pull the current project's team vault into your local vault.
    VaultPull {
        /// Team ID
        team_id: String,
    },
}

#[derive(Subcommand)]
enum CloudAction {
    /// Push local secrets to Phantom Cloud
    Push,
    /// Pull secrets from Phantom Cloud to local vault
    Pull {
        /// Overwrite existing local secrets
        #[arg(long)]
        force: bool,
    },
    /// Show cloud sync status
    Status,
}

fn main() -> anyhow::Result<()> {
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
        Commands::List { json, show_expiry } => commands::list::run_with_expiry(json, show_expiry),
        Commands::Add { name, value, stdin } => commands::add::run(&name, value.as_deref(), stdin),
        Commands::Remove { name } => commands::remove::run(&name),
        Commands::Reveal {
            name,
            clipboard,
            yes,
        } => commands::reveal::run(&name, clipboard, yes),
        Commands::Status { oneline } => commands::status::run(oneline),
        Commands::Rotate { sync, with_expiry } => {
            commands::rotate::run_with_expiry(sync, with_expiry)
        }
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
        Commands::Setup { client, print } => commands::setup::run(client, print),
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
            json,
            allow_plaintext,
        } => commands::export_cmd::run(
            output.as_deref(),
            passphrase.as_deref(),
            json,
            allow_plaintext,
        ),
        Commands::Import {
            file,
            passphrase,
            from,
            file_path,
            force,
        } => {
            if let Some(source) = from {
                let fp = file_path.as_deref().unwrap_or("");
                commands::import_cmd::run_from(&source, fp, force)
            } else {
                // Legacy encrypted-backup path
                commands::import_cmd::run(
                    file.as_deref().unwrap_or(""),
                    passphrase.as_deref().unwrap_or(""),
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
        Commands::Watch { auto } => commands::watch::run(auto),
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
            } => commands::audit::run_show(last, op.as_deref(), name.as_deref(), json),
            AuditAction::Tail { op, name } => {
                commands::audit::run_tail(op.as_deref(), name.as_deref())
            }
            AuditAction::Path => commands::audit::run_path(),
            AuditAction::Verify => commands::audit::run_verify(),
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
        },
        Commands::Open { target } => commands::open::run(&target),
        Commands::Upgrade { force, check_only } => commands::upgrade::run(force, check_only),
        Commands::Completion { shell } => commands::completion::run(shell),
        Commands::Mcp { action } => match action {
            McpAction::Serve => commands::mcp::run_serve(),
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
        },
    }
}
