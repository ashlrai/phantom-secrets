//! Single-project `phantom init --dry-run`.
//!
//! This plans the same files `run` would hand to the init transaction and
//! prints names only. It does not open a vault, take a project transaction
//! lock, or repair directory permissions. Only read-only planners are used.

use anyhow::{Context, Result};
use phantom_core::dotenv::SecretClassification;
use phantom_core::precommit_hook::{self, HookChange};
use std::path::{Path, PathBuf};

pub fn run(env_path_arg: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let env_path = locate_env(&cwd, env_path_arg)?;
    let project_dir = env_path
        .parent()
        .unwrap_or(&cwd)
        .to_path_buf()
        .canonicalize()
        .context("Failed to resolve the initialization project root")?;
    let env_name = env_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Dotenv path has no reviewed direct-child name"))?;
    phantom_core::managed_dotenv::validate_dotenv_basename(env_name)
        .with_context(|| format!("Refusing dotenv name {env_name}"))?;

    let dotenv = phantom_core::managed_dotenv::parse_regular_dotenv(&project_dir, env_name)?
        .ok_or_else(|| anyhow::anyhow!("Dotenv disappeared during preflight"))?;
    dotenv
        .validate_for_mutation()
        .context("Managed dotenv is malformed; initialization made no changes")?;
    if let Some(entry) = dotenv.dotenvx_encrypted_entry() {
        anyhow::bail!(phantom_core::dotenv::dotenvx_ciphertext_refusal(entry));
    }

    let classified = dotenv.classified_entries();
    let keys: Vec<String> = classified
        .iter()
        .filter(|(_, class)| *class == SecretClassification::Secret)
        .map(|(entry, _)| entry.key.clone())
        .collect();
    let skipped_public: Vec<String> = classified
        .iter()
        .filter(|(_, class)| *class == SecretClassification::PublicKey)
        .map(|(entry, _)| entry.key.clone())
        .collect();
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)
        .with_context(|| format!("Failed to safely inspect {}", config_path.display()))?;
    if let Some(before) = &config_before {
        phantom_core::config::PhantomConfig::load_from_bytes(&config_path, before)
            .context("Failed to load existing .phantom.toml")?;
    }
    let config_exists = config_before.is_some();
    let existing_protected_setup =
        config_exists || dotenv.entries().iter().any(|entry| entry.is_phantom);
    let env_transaction_path = project_dir.join(env_name);
    let (mut files, may_update) = if keys.is_empty() && !existing_protected_setup {
        (Vec::new(), Vec::new())
    } else {
        planned_files(
            &project_dir,
            &env_transaction_path,
            &config_path,
            !keys.is_empty(),
        )?
    };
    if !keys.is_empty() {
        files.push(planned_vault_path(&project_dir)?);
    }
    crate::commands::plan_print::print_plan(
        "add",
        &keys,
        &skipped_public,
        &files,
        &project_dir,
        false,
        &may_update,
        false,
        false,
    );
    super::print_commented_entry_notes(&super::commented_entry_notes(&dotenv, env_name));
    Ok(())
}

pub fn run_empty() -> Result<()> {
    let cwd = std::env::current_dir()?.canonicalize()?;
    let config_path = cwd.join(".phantom.toml");
    match phantom_core::fs::read_regular_file(&config_path)
        .with_context(|| format!("Failed to safely inspect {}", config_path.display()))?
    {
        Some(_) => {
            println!(".phantom.toml already exists. Nothing to do.");
            println!("Dry run only. Nothing was written.");
            Ok(())
        }
        None => {
            let mut files = vec![config_path];
            if let Some(file) = super::env::prepare_gitignore(&cwd)? {
                files.push(file.path().to_path_buf());
            }
            files.push(planned_vault_path(&cwd)?);
            crate::commands::plan_print::print_plan(
                "add",
                &[],
                &[],
                &files,
                &cwd,
                true,
                &[],
                false,
                false,
            );
            Ok(())
        }
    }
}

fn locate_env(cwd: &Path, env_path_arg: &str) -> Result<PathBuf> {
    let env_path = if Path::new(env_path_arg).exists() {
        PathBuf::from(env_path_arg)
    } else {
        super::env::find_env_file(cwd, env_path_arg).ok_or_else(|| {
            anyhow::anyhow!(
                "No .env file found.\n\
                 Checked: .env, .env.local, .env.development, .env.development.local\n\
                 (also searched immediate subdirectories)\n\n\
                 Create a .env file with your secrets, or specify one:\n\
                 phantom init --from .env.local"
            )
        })?
    };
    Ok(if env_path.is_absolute() {
        env_path
    } else {
        cwd.join(env_path)
    })
}

fn planned_files(
    project_dir: &Path,
    env_path: &Path,
    config_path: &Path,
    rewrite_dotenv: bool,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut files = vec![config_path.to_path_buf()];
    if rewrite_dotenv {
        files.push(env_path.to_path_buf());
        let example_path = project_dir.join(".env.example");
        if phantom_core::fs::read_regular_file(&example_path)
            .with_context(|| format!("Failed to safely inspect {}", example_path.display()))?
            .is_none()
        {
            files.push(example_path);
        }
    }
    if let Some(file) = super::env::prepare_gitignore(project_dir)? {
        files.push(file.path().to_path_buf());
    }
    let claude = planned_claude_files(project_dir)?;
    files.extend(claude.create);
    let mut guidance = super::docs::prepare_guidance(project_dir, None)?;
    files.extend(
        guidance
            .take_files()
            .iter()
            .map(|file| file.path().to_path_buf()),
    );
    if let Some(path) = planned_hook(project_dir)? {
        files.push(path);
    }
    Ok((files, claude.may_update))
}

/// Encrypted-file vault location for this checkout. Path math only: the
/// directory is not created and the keychain is not opened.
fn planned_vault_path(project_dir: &Path) -> Result<PathBuf> {
    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(project_dir);
    phantom_vault::encrypted_file_vault_path(&project_id)
        .context("Failed to locate the encrypted-file vault path")
}

struct ClaudePlan {
    create: Vec<PathBuf>,
    may_update: Vec<PathBuf>,
}

/// Claude files a real init would create or merge. Existing settings are not
/// diffed: that planner takes the project transaction lock, which creates
/// directories. A dry run reports `may update` and does not lock.
fn planned_claude_files(project_dir: &Path) -> Result<ClaudePlan> {
    let claude_dir = project_dir.join(".claude");
    match std::fs::symlink_metadata(&claude_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Refusing to inspect a symlinked .claude directory");
        }
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Ok(ClaudePlan {
                create: Vec::new(),
                may_update: Vec::new(),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ClaudePlan {
                create: Vec::new(),
                may_update: Vec::new(),
            });
        }
        Err(error) => return Err(error).context("Failed to inspect .claude"),
    }
    let mut create = Vec::new();
    let mut may_update = Vec::new();
    for path in [
        claude_dir.join("settings.local.json"),
        project_dir.join(".mcp.json"),
    ] {
        match phantom_core::fs::read_regular_file(&path)
            .with_context(|| format!("Failed to safely inspect {}", path.display()))?
        {
            Some(_) => may_update.push(path),
            None => create.push(path),
        }
    }
    Ok(ClaudePlan { create, may_update })
}

fn planned_hook(project_dir: &Path) -> Result<Option<PathBuf>> {
    let plan = precommit_hook::prepare_install_plan(project_dir)
        .map_err(|error| anyhow::anyhow!("Pre-commit hook setup failed: {error}"))?;
    Ok(plan.and_then(|plan| {
        (plan.change() != HookChange::Unchanged).then(|| plan.path().to_path_buf())
    }))
}
