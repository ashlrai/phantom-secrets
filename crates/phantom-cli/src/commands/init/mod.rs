mod config;
mod docs;
pub(crate) mod env;
mod hooks;
pub mod multi;
mod prompts;
mod vault;

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::dotenv::{DotenvFile, SecretClassification};
use std::path::Path;

/// `phantom init --empty`
///
/// Creates a valid `.phantom.toml` and an empty vault in the current directory
/// without requiring a `.env` file. Use this to bootstrap a brand-new project
/// before any secrets exist — then add secrets one at a time with `phantom add`.
pub fn run_empty() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let config_path = cwd.join(".phantom.toml");

    if config_path.exists() {
        println!(
            "{} .phantom.toml already exists — nothing to do.",
            "!".yellow().bold()
        );
        return Ok(());
    }

    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(&cwd);
    let phantom_config = phantom_core::config::PhantomConfig::new_with_defaults(project_id.clone());

    // Touch the vault so it exists (create_vault is idempotent / lazy, but calling
    // list() forces any on-disk initialisation that the backend needs).
    let vault = phantom_vault::create_vault(&project_id);
    let _ = vault.list(); // ignore empty-vault errors

    phantom_config.save(&config_path)?;
    println!("{} Created .phantom.toml", "ok".green().bold());

    env::ensure_gitignore(&cwd)?;

    println!(
        "\n{} Empty vault initialised. Add secrets with:\n     {}",
        "done".green().bold(),
        "phantom add <NAME>".cyan().bold()
    );

    Ok(())
}

pub fn run(env_path_arg: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;

    // Auto-detect .env file if the default wasn't found
    let env_path = if Path::new(env_path_arg).exists() {
        std::path::PathBuf::from(env_path_arg)
    } else {
        env::find_env_file(&cwd, env_path_arg).ok_or_else(|| {
            anyhow::anyhow!(
                "No .env file found.\n\
                 Checked: .env, .env.local, .env.development, .env.development.local\n\
                 (also searched immediate subdirectories)\n\n\
                 Create a .env file with your secrets, or specify one:\n\
                 {}",
                "phantom init --from .env.local".cyan().bold()
            )
        })?
    };

    // Config and project dir are based on where the .env file lives (not cwd)
    // Canonicalize for stable project IDs regardless of which directory user runs from
    let project_dir = env_path.parent().unwrap_or(&cwd).to_path_buf();
    let project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| cwd.join(&project_dir));
    let config_path = project_dir.join(".phantom.toml");

    // Parse .env file
    println!("{} Reading {}...", "->".blue().bold(), env_path.display());
    let dotenv = DotenvFile::parse_file(&env_path).context("Failed to read .env file")?;

    // Classify all entries
    let classified = dotenv.classified_entries();
    let real_entries: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::Secret)
        .map(|(e, _)| *e)
        .collect();
    let public_entries: Vec<_> = classified
        .iter()
        .filter(|(_, c)| *c == SecretClassification::PublicKey)
        .map(|(e, _)| *e)
        .collect();

    let existing_protected_setup =
        config_path.exists() || dotenv.entries().iter().any(|e| e.is_phantom);
    // Preflight migration of any project-local Claude settings before touching
    // either a new secret or an already-protected project. This keeps reruns
    // useful for removing legacy network-capable MCP entries.
    let claude_setup = if !real_entries.is_empty() || existing_protected_setup {
        prompts::prepare_auto_setup_claude_code(&project_dir, &cwd)?
    } else {
        None
    };

    if real_entries.is_empty() {
        println!(
            "{} No real secrets found in {} (all values are already phantom tokens, public keys, or config)",
            "!".yellow().bold(),
            env_path.display()
        );
        if !public_entries.is_empty() {
            println!(
                "\n{} {} public key(s) detected (safe for browser bundles, not protected):",
                "->".blue().bold(),
                public_entries.len()
            );
            for entry in &public_entries {
                println!("   {} {}", "·".dimmed(), entry.key);
            }
        }

        if existing_protected_setup {
            if config_path.exists() {
                env::ensure_gitignore(&project_dir)?;
            }
            hooks::install_precommit_hook(&project_dir);
            if let Some(prepared) = claude_setup {
                prompts::apply_auto_setup_claude_code(prepared)?;
            }
            docs::auto_add_claude_md(&project_dir, &cwd);
            docs::auto_add_readme(&project_dir, &cwd);
            prompts::detect_platforms(&project_dir, &cwd);
            if config_path.exists() {
                print_next_steps(&config_path);
            }
            println!(
                "{} Existing Phantom setup checked and local integrations refreshed without rotating tokens.",
                "ok".green().bold()
            );
        }
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) to protect:",
        "->".blue().bold(),
        real_entries.len()
    );
    for entry in &real_entries {
        println!("   {} {}", "+".cyan().bold(), entry.key.bold());
    }

    if !public_entries.is_empty() {
        println!(
            "\n{} Skipping {} public key(s) (safe for browser bundles):",
            "->".blue().bold(),
            public_entries.len()
        );
        for entry in &public_entries {
            println!("   {} {}", "·".dimmed(), entry.key);
        }
        println!("   Override with: {}", "phantom add <KEY>".dimmed());
    }

    // Load or create config, then auto-detect services
    let mut phantom_config = config::load_or_create(&project_dir, &config_path)?;
    config::apply_detected_services(&mut phantom_config, &real_entries);

    // Set up vault, store secrets, backup and rewrite .env
    vault::setup_and_store(
        &real_entries,
        phantom_config.local_project_id(),
        &env_path,
        &dotenv,
    )?;

    // Persist public key classifications
    if !public_entries.is_empty() {
        phantom_config.public_keys = public_entries.iter().map(|e| e.key.clone()).collect();
    }

    // Save config
    phantom_config.save(&config_path)?;
    println!("{} Saved .phantom.toml", "ok".green().bold());

    // Add .phantom.toml to .gitignore if needed
    env::ensure_gitignore(&project_dir)?;

    // Generate .env.example for team onboarding
    let example_path = project_dir.join(".env.example");
    let example_content = dotenv.generate_example_content(Some(&phantom_config));
    std::fs::write(&example_path, &example_content)?;
    println!(
        "{} Generated {} (commit this for team onboarding)",
        "ok".green().bold(),
        ".env.example".cyan()
    );

    // Install pre-commit hook if in a git repo
    hooks::install_precommit_hook(&project_dir);

    println!(
        "\n{} {} secret(s) are now protected!",
        "done".green().bold(),
        real_entries.len()
    );

    // Commit the already validated Claude update. Check project_dir first,
    // falling back to cwd (repo root) for monorepos.
    if let Some(prepared) = claude_setup {
        prompts::apply_auto_setup_claude_code(prepared)?;
    }

    // Add Phantom instructions to CLAUDE.md so Claude knows how to use it
    docs::auto_add_claude_md(&project_dir, &cwd);

    // Add development setup section to README.md
    docs::auto_add_readme(&project_dir, &cwd);

    // Detect deployment platforms and suggest sync setup
    prompts::detect_platforms(&project_dir, &cwd);

    print_next_steps(&config_path);

    Ok(())
}

/// Print a contextual "what's next?" block. Items are conditional on
/// state — e.g., we don't suggest `phantom login` if the user is already
/// authenticated, and we promote `phantom cloud push` instead if they
/// have credentials but no cloud version yet.
fn print_next_steps(config_path: &Path) {
    use phantom_core::auth;
    use phantom_core::config::PhantomConfig;

    let logged_in = auth::load_token().is_some();
    let has_cloud_version = PhantomConfig::load(config_path)
        .ok()
        .and_then(|c| c.cloud)
        .is_some();

    println!("\n{}", "What's next?".bold());

    let mut step = 1;
    let mut item = |label: &str, command: &str| {
        println!(
            "  {}. {}\n     {}",
            step.to_string().bold(),
            label,
            command.cyan().bold()
        );
        step += 1;
    };

    item(
        "Run code with secret injection:",
        "phantom exec -- <your-command>",
    );
    item("Verify everything looks healthy:", "phantom doctor");

    if !logged_in {
        item(
            "Sign in to Phantom Cloud (optional, for E2E-encrypted backups):",
            "phantom login",
        );
    } else if !has_cloud_version {
        item("Back up this vault to Phantom Cloud:", "phantom cloud push");
    }

    item("Open your dashboard:", "phantom open");
    item(
        "Block raw-secret commits (recommended for teams):",
        "pre-commit install   # uses .pre-commit-hooks.yaml shipped with phantom",
    );
    item(
        "Other AI tools (Cursor, Windsurf, Codex):",
        "phantom setup --client cursor|windsurf|codex|claude   # --print to stdout",
    );

    println!();
}
