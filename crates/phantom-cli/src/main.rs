mod commands;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "phantom",
    about = "Prevent AI coding agents from leaking your API keys",
    long_about = "Phantom replaces real secrets in your .env with worthless phantom tokens.\n\
                  A local proxy intercepts API calls, swaps in real credentials at the network layer.\n\
                  The AI agent never sees a real secret.",
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
    /// Import .env secrets into the vault and rewrite with phantom tokens
    Init {
        /// Path to .env file. Auto-detects .env, .env.local, .env.development and searches subdirectories
        #[arg(short, long, default_value = ".env")]
        from: String,
    },

    /// List stored secret names (never shows values)
    List {
        /// Emit JSON instead of the human-readable table
        #[arg(long)]
        json: bool,
    },

    /// Add a secret to the vault
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
    Remove {
        /// Secret name to remove
        name: String,
    },

    /// Reveal a secret value (print to stdout or copy to clipboard)
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

    /// Show proxy status and mapped secrets
    Status {
        /// Compact one-line output for shell prompts (e.g., "3 secrets · proxy off")
        #[arg(long)]
        oneline: bool,
    },

    /// Regenerate phantom tokens (invalidates old ones)
    Rotate {
        /// Also sync secrets to all configured deployment platforms after rotation
        #[arg(long)]
        sync: bool,
    },

    /// Check configuration and vault health
    Doctor {
        /// Auto-fix safe issues (install hooks, generate .env.example, etc.)
        #[arg(long)]
        fix: bool,
    },

    /// Start the proxy and run a command
    Exec {
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// Start the proxy server
    Start {
        /// Run in background (daemon mode)
        #[arg(short, long)]
        daemon: bool,
    },

    /// Stop the background proxy server
    Stop,

    /// Check for unprotected secrets (pre-commit hook)
    Check {
        /// Only scan git-staged files (skip .env scanning, faster for pre-commit hooks)
        #[arg(long)]
        staged: bool,
        /// Check if phantom tokens are in environment without proxy running
        #[arg(long)]
        runtime: bool,
    },

    /// Sync secrets to deployment platforms (Vercel, Railway)
    Sync {
        /// Platform to sync to (vercel, railway). Syncs all configured targets if omitted.
        #[arg(short, long)]
        platform: Option<String>,
        /// Override project ID for this sync
        #[arg(long)]
        project: Option<String>,
        /// Only push secrets whose names match this glob pattern (e.g. STRIPE_*).
        /// Repeatable: multiple --only flags are OR-ed together.
        /// Also honoured via `only = [...]` in each [[sync]] block in .phantom.toml.
        #[arg(long, value_name = "PATTERN")]
        only: Vec<String>,
    },

    /// Pull secrets from a deployment platform into the vault
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

    /// Set up Phantom auto-mode for Claude Code (MCP server + hooks)
    Setup,

    /// Generate .env.example for team onboarding
    Env {
        /// Output file name (defaults to .env.example)
        #[arg(short, long, default_value = ".env.example")]
        output: String,
    },

    /// Export secrets to an encrypted backup file
    Export {
        /// Output file path
        #[arg(short, long, default_value = "phantom-export.enc")]
        output: String,
        /// Encryption passphrase
        #[arg(short, long)]
        passphrase: String,
    },

    /// Import secrets from an encrypted backup file
    Import {
        /// Path to the encrypted backup file
        file: String,
        /// Decryption passphrase
        #[arg(short, long)]
        passphrase: String,
        /// Overwrite existing secrets
        #[arg(long)]
        force: bool,
    },

    /// Log in to Phantom Cloud
    Login,

    /// Log out of Phantom Cloud
    Logout,

    /// Cloud vault sync commands
    Cloud {
        #[command(subcommand)]
        action: CloudAction,
    },

    /// Team vault management
    Team {
        #[command(subcommand)]
        action: TeamAction,
    },

    /// Wrap package.json scripts with `phantom exec` (no more manual prefix)
    Wrap {
        /// Only wrap specific scripts (by name)
        #[arg(long)]
        only: Option<Vec<String>>,
        /// Skip specific scripts (by name)
        #[arg(long)]
        skip: Option<Vec<String>>,
    },

    /// Unwrap package.json scripts (restore originals from :raw variants)
    Unwrap,

    /// Watch .env files and auto-detect new unprotected secrets
    Watch {
        /// Auto-protect new secrets without prompting
        #[arg(long)]
        auto: bool,
    },

    /// Explain why a key is or isn't protected
    Why {
        /// Environment variable name to explain
        key: String,
    },

    /// Copy a secret from this project's vault to another project
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

    /// Open a Phantom page in the browser. Defaults to the dashboard.
    /// Aliases: dashboard, billing, team, docs, pricing, github, issues, site.
    /// Any other word becomes https://phm.dev/<word>; full URLs pass through.
    Open {
        /// What to open. Defaults to the dashboard if omitted.
        #[arg(default_value = "")]
        target: String,
    },

    /// Self-replace this binary with the latest GitHub release.
    Upgrade {
        /// Skip confirmation prompt and upgrade immediately
        #[arg(long)]
        force: bool,
        /// Print available version without modifying the binary
        #[arg(long)]
        check_only: bool,
    },

    /// Print a shell-completion script to stdout.
    ///
    /// Source the output from your shell rc, e.g.
    ///   bash:       phantom completion bash > ~/.local/share/bash-completion/completions/phantom
    ///   zsh:        phantom completion zsh > "${fpath[1]}/_phantom"
    ///   fish:       phantom completion fish > ~/.config/fish/completions/phantom.fish
    ///   powershell: phantom completion powershell | Out-String | Invoke-Expression
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
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
        Commands::Init { from } => commands::init::run(&from),
        Commands::List { json } => commands::list::run(json),
        Commands::Add { name, value, stdin } => {
            commands::add::run(&name, value.as_deref(), stdin)
        }
        Commands::Remove { name } => commands::remove::run(&name),
        Commands::Reveal {
            name,
            clipboard,
            yes,
        } => commands::reveal::run(&name, clipboard, yes),
        Commands::Status { oneline } => commands::status::run(oneline),
        Commands::Rotate { sync } => commands::rotate::run(sync),
        Commands::Doctor { fix } => commands::doctor::run(fix),
        Commands::Exec { cmd } => commands::exec::run(&cmd),
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
        Commands::Setup => commands::setup::run(),
        Commands::Sync {
            platform,
            project,
            only,
        } => commands::sync::run(platform, project, only),
        Commands::Env { output } => commands::env::run(&output),
        Commands::Export { output, passphrase } => commands::export_cmd::run(&output, &passphrase),
        Commands::Import {
            file,
            passphrase,
            force,
        } => commands::import_cmd::run(&file, &passphrase, force),
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
        Commands::Open { target } => commands::open::run(&target),
        Commands::Upgrade { force, check_only } => commands::upgrade::run(force, check_only),
        Commands::Completion { shell } => commands::completion::run(shell),
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
