use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use std::io::{IsTerminal, Write};

pub fn run(name: &str, dry_run: bool) -> Result<()> {
    super::add::validate_secret_name(name)?;
    let project_dir = crate::util::project_dir()?
        .canonicalize()
        .context("Failed to resolve project directory")?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)?
        .context("Project is not initialized. Run `phantom init --empty` first.")?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to load exact .phantom.toml snapshot")?;
    super::add::validate_managed_dotenv_preflight(&project_dir, &config)?;
    if dry_run {
        return dry_run_remove(&project_dir, &config_path, &config, name);
    }
    // Refuse headless invocation before opening the vault: opening it takes
    // project locks and creates app-data directories, and a run without all
    // three terminals could never finish the confirmation ceremony anyway.
    ensure_attached_terminals()?;
    let vault = crate::util::open_vault(config.local_project_id())?;
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

/// Plan a removal from the config and dotenv only. Vault membership is not
/// listed: opening the vault can take the project lock and create app-data
/// directories.
fn dry_run_remove(
    project_dir: &std::path::Path,
    config_path: &std::path::Path,
    config: &PhantomConfig,
    name: &str,
) -> Result<()> {
    if name.len() > 128 {
        anyhow::bail!("invalid managed secret name; expected a bounded environment variable name");
    }
    let resolved = phantom_core::managed_dotenv::resolve_dotenv(project_dir, config, &[])
        .context("Failed to resolve the managed dotenv")?;
    let Some(file) = resolved.file.as_ref() else {
        anyhow::bail!("Managed dotenv does not exist: {}", resolved.path.display());
    };
    // Same dotenv key rules as a real remove. The rewritten text is discarded
    // and nothing is written. Vault membership still cannot be checked here.
    file.remove_phantom_mapping(name, true)
        .map_err(anyhow::Error::from)
        .context("Removal preflight failed; no secret value was read and no state changed")?;
    crate::commands::plan_print::print_plan(
        "remove",
        &[name.to_string()],
        &[],
        &[config_path.to_path_buf(), resolved.path],
        project_dir,
        false,
        &[],
        true,
        !config.phantom.secrets.contains_key(name),
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

/// Refuse a `phantom remove` that cannot run its trusted-terminal ceremony,
/// before the vault is opened: opening it takes project locks and creates
/// app-data directories, so the headless rejection must not leave profile
/// files behind.
fn ensure_attached_terminals() -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "`phantom remove` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No secret value was read and no state changed. Use the approved MCP remove flow when the calling agent cannot be excluded from terminal authority."
        );
    }
    Ok(())
}

fn require_trusted_terminal_remove(plan: &phantom_vault::ManagedRemovePlan) -> Result<()> {
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

#[cfg(test)]
mod source_tests {
    #[test]
    fn dry_run_returns_before_any_vault_open() {
        let source = include_str!("remove.rs");
        let run_body = source
            .split("pub fn run(")
            .nth(1)
            .unwrap()
            .split("fn dry_run_remove(")
            .next()
            .unwrap();
        let dry = run_body.find("if dry_run {").unwrap();
        let vault = run_body.find("crate::util::open_vault").unwrap();
        assert!(
            dry < vault,
            "dry-run must return before the vault is opened"
        );
        let terminals = run_body.find("ensure_attached_terminals()?").unwrap();
        assert!(
            dry < terminals && terminals < vault,
            "the headless refusal must run after dry-run and before the vault is opened"
        );
        let dry_fn = source
            .split("fn dry_run_remove(")
            .nth(1)
            .unwrap()
            .split("fn prepare_remove(")
            .next()
            .unwrap();
        assert!(!dry_fn.contains("try_create_vault"));
        assert!(!dry_fn.contains("open_vault"));
        assert!(!dry_fn.contains("acquire_project_lock"));
        assert!(!dry_fn.contains("get_or_create_passphrase"));
        assert!(!dry_fn.contains("prepare_remove"));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::util::test_seam::{
        empty_keychain, tree_snapshot, EnvRestore, LockedProject, TestProject,
    };

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

    #[test]
    fn dry_run_remove_does_not_reach_the_keychain_or_create_app_data() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let home = tempfile::tempdir().unwrap();
        let project = home.path().canonicalize().unwrap();
        let _restore = EnvRestore::apply(&project);
        std::fs::create_dir(project.join("empty-meta")).unwrap();
        std::fs::write(project.join(".hidden-lock"), b"lock").unwrap();
        std::fs::write(project.join("project.lock"), b"lock").unwrap();
        phantom_core::config::PhantomConfig::new_with_defaults(
            phantom_core::config::PhantomConfig::project_id_from_path(&project),
        )
        .save(&project.join(".phantom.toml"))
        .unwrap();
        std::fs::write(
            project.join(".env"),
            format!("OPENAI_API_KEY=phm_{}\nPORT=3000\n", "a".repeat(64)),
        )
        .unwrap();
        let _seam =
            TestProject::install(project.clone(), crate::util::test_seam::untouched_keychain);
        let before = tree_snapshot(&project);
        assert!(before.contains_key("empty-meta/"));
        assert!(before.contains_key(".hidden-lock"));
        assert!(before.contains_key("project.lock"));

        let outcome = run("OPENAI_API_KEY", true);
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(before, tree_snapshot(&project));

        let missing = run("MISSING_KEY", true);
        assert!(
            missing.is_err(),
            "a name with no phantom mapping must be refused"
        );
        let message = format!("{:#}", missing.err().unwrap());
        assert!(message.contains("expected exactly one managed mapping"));
        assert!(!message.contains("phm_"));
        assert_eq!(before, tree_snapshot(&project));
        assert!(!project.join("xdg-data").exists());
        assert!(!project.join(".local").exists());
        drop(_seam);
    }
}
