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
        /// Path to .env file (defaults to .env in current directory)
        #[arg(short, long, default_value = ".env")]
        from: String,
    },

    /// List stored secret names (never shows values)
    List,

    /// Add a secret to the vault
    Add {
        /// Secret name (e.g., OPENAI_API_KEY)
        name: String,
        /// Secret value
        value: String,
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
    Status,

    /// Regenerate phantom tokens (invalidates old ones)
    Rotate,

    /// Check configuration and vault health
    Doctor,

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
    Check,

    /// Sync secrets to deployment platforms (Vercel, Railway)
    Sync {
        /// Platform to sync to (vercel, railway). Syncs all configured targets if omitted.
        #[arg(short, long)]
        platform: Option<String>,
        /// Override project ID for this sync
        #[arg(long)]
        project: Option<String>,
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

    /// Log in to Phantom Cloud
    Login,

    /// Log out of Phantom Cloud
    Logout,

    /// Cloud vault sync commands
    Cloud {
        #[command(subcommand)]
        action: CloudAction,
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
        Commands::List => commands::list::run(),
        Commands::Add { name, value } => commands::add::run(&name, &value),
        Commands::Remove { name } => commands::remove::run(&name),
        Commands::Reveal {
            name,
            clipboard,
            yes,
        } => commands::reveal::run(&name, clipboard, yes),
        Commands::Status => commands::status::run(),
        Commands::Rotate => commands::rotate::run(),
        Commands::Doctor => commands::doctor::run(),
        Commands::Exec { cmd } => commands::exec::run(&cmd),
        Commands::Start { daemon } => commands::start::run(daemon),
        Commands::Stop => commands::stop::run(),
        Commands::Check => commands::check::run(),
        Commands::Pull {
            from,
            project,
            environment,
            service,
            force,
        } => commands::pull::run(&from, &project, environment, service, force),
        Commands::Setup => commands::setup::run(),
        Commands::Sync { platform, project } => commands::sync::run(platform, project),
        Commands::Env { output } => commands::env::run(&output),
        Commands::Login => commands::login::run(),
        Commands::Logout => commands::logout::run(),
        Commands::Cloud { action } => match action {
            CloudAction::Push => commands::cloud::run_push(),
            CloudAction::Pull { force } => commands::cloud::run_pull(force),
            CloudAction::Status => commands::cloud::run_status(),
        },
    }
}
