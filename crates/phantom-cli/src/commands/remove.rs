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
    let plan = prepare_remove(
        &project_dir,
        config_before,
        config.local_project_id(),
        vault.as_ref(),
        name,
    )?;
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

/// Plan the removal from value-free state. A name the opened vault does not
/// list is refused before planning; beside an encrypted-file vault this
/// process cannot open, that refusal names the locked vault and the unlock
/// step instead of reporting the secret as not found.
fn prepare_remove(
    project_dir: &std::path::Path,
    config_before: Vec<u8>,
    project_id: &str,
    vault: &dyn phantom_vault::VaultBackend,
    name: &str,
) -> Result<phantom_vault::ManagedRemovePlan> {
    const PREFLIGHT_FAILED: &str =
        "Removal preflight failed; no secret value was read and no state changed";
    crate::util::require_listed_secret(vault, project_id, name, || {
        format!("Secret '{name}' not found in vault")
    })
    .context(PREFLIGHT_FAILED)?;
    phantom_vault::ManagedRemovePlan::prepare(project_dir, config_before, vault, name)
        .context(PREFLIGHT_FAILED)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::util::test_seam::{empty_keychain, LockedProject};

    /// Beside an encrypted-file vault this process cannot open, the vault is
    /// the OS keychain, which lacks the name: remove reported "not found".
    #[test]
    fn remove_beside_a_locked_file_vault_names_the_lock_not_a_missing_secret() {
        let project = LockedProject::new(empty_keychain);
        let config_path = project.dir.join(".phantom.toml");
        let config_before = std::fs::read(&config_path).unwrap();
        let vault = crate::util::open_vault(&project.project_id).unwrap();

        let outcome = prepare_remove(
            &project.dir,
            config_before.clone(),
            &project.project_id,
            vault.as_ref(),
            "OPENAI_API_KEY",
        );

        assert!(outcome.is_err(), "a locked vault must refuse the removal");
        let chain = format!("{:#}", outcome.err().unwrap());
        assert!(chain.contains("Vault locked:"));
        assert!(chain.contains("PHANTOM_VAULT_PASSPHRASE"));
        assert!(!chain.contains("not found"));
        assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
    }
}
