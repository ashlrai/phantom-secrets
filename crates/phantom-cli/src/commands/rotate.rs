use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::TokenMap;
/// Rotate all phantom tokens and optionally set a TTL (expiry) on every secret.
///
/// When `expiry_days` is `Some(n)` each secret gets a rotation policy of
/// `n` days and its `expires_at` is set to `now + n * 86400`.
pub fn run_with_expiry(sync_after: bool, expiry_days: Option<u64>) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let names = vault.list().context("Failed to list secrets")?;

    if names.is_empty() {
        println!("{} No secrets to rotate.", "!".yellow().bold());
        return Ok(());
    }

    // Generate new phantom tokens for all secrets
    let mut token_map = TokenMap::new();
    for name in &names {
        token_map.insert(name.clone());
    }

    // Rewrite .env if it exists
    if env_path.exists() {
        let dotenv = DotenvFile::parse_file(&env_path)?;
        dotenv.write_phantomized(&token_map, &env_path)?;
        println!(
            "{} Rotated {} phantom token(s) in .env",
            "ok".green().bold(),
            names.len()
        );
    } else {
        println!(
            "{} No .env file found — tokens rotated in memory only",
            "!".yellow().bold()
        );
    }

    for name in &names {
        if let Some(days) = expiry_days {
            vault
                .set_rotation_policy(name, days)
                .with_context(|| format!("Failed to set rotation policy for {name}"))?;
            println!(
                "   {} {} -> new token, expires in {} day(s)",
                "+".green(),
                name.bold(),
                days
            );
        } else {
            println!("   {} {} -> new token", "+".green(), name.bold());
        }
    }

    if expiry_days.is_some() {
        println!(
            "\n{} TTL metadata updated. Use {} to see expiry status.",
            "ok".green().bold(),
            "phantom list --show-expiry".cyan()
        );
    }

    // Sync to all deployment platforms if --sync flag is set
    if sync_after {
        println!(
            "\n{} Syncing to deployment platforms...",
            "->".blue().bold()
        );
        crate::commands::sync::run(None, None, vec![], false, false)?;
    }

    Ok(())
}
