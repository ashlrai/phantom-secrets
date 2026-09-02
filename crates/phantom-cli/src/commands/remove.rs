use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use std::io::{IsTerminal, Write};

pub fn run(name: &str) -> Result<()> {
    super::add::validate_secret_name(name)?;
    let project_dir = std::env::current_dir()?
        .canonicalize()
        .context("Failed to resolve project directory")?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)?
        .context("Project is not initialized. Run `phantom init --empty` first.")?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to load exact .phantom.toml snapshot")?;
    super::add::validate_managed_dotenv_preflight(&project_dir, &config)?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let plan = phantom_vault::ManagedRemovePlan::prepare(
        &project_dir,
        config_before,
        vault.as_ref(),
        name,
    )
    .context("Removal preflight failed; no secret value was read and no state changed")?;
    require_trusted_terminal_remove(&plan)?;
    let env_path = plan.dotenv_path().to_path_buf();
    plan.commit(vault.as_ref()).context(
        "Remove transaction failed; exact transaction-owned state was rolled back where verifiable. Inspect the vault and managed dotenv before retrying.",
    )?;
    println!(
        "{} Removed {} from vault, lifecycle config, and {} in one transaction",
        "ok".green().bold(),
        name.bold(),
        env_path
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("managed dotenv")
            .cyan()
    );

    Ok(())
}

fn require_trusted_terminal_remove(plan: &phantom_vault::ManagedRemovePlan) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "`phantom remove` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No secret value was read and no state changed. Use the approved MCP remove flow when the calling agent cannot be excluded from terminal authority."
        );
    }
    let challenge = format!(
        "REMOVE {} FROM {} ID {} DIGEST {}",
        plan.name(),
        plan.project_dir().display(),
        plan.local_project_id(),
        plan.before_digest()
    );
    eprintln!(
        "Secret removal permanently deletes local credential material unless a verified backup exists.\nProject: {}\nSecret: {}\nManaged dotenv: {}\nType this exact challenge to continue:\n{}",
        plan.project_dir().display(),
        plan.name(),
        plan.dotenv_path().display(),
        challenge
    );
    eprint!("> ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin()
        .read_line(&mut response)
        .context("Failed to read trusted-terminal removal confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!(
            "Removal confirmation did not match exactly. No secret value was read and no state changed."
        );
    }
    Ok(())
}
