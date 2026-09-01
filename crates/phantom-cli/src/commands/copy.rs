use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_vault::{InitFile, InitSecret};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use super::add::{
    load_config_exact, rewrite_dotenv, snapshot_regular_file, snapshot_secret, validate_secret_name,
};

struct CopyTargetPlan {
    mutation: InitSecret,
    files: Vec<InitFile>,
    env_path: PathBuf,
}

/// Copy the source value observed during preflight into a distinct target
/// project. Only the target is mutated, so only its canonical project lock is
/// acquired; avoiding simultaneous source/target locks removes reverse-copy
/// deadlock risk. The source snapshot remains zeroizing through target commit.
pub fn run(name: &str, target_dir: &Path, rename: &Option<String>) -> Result<()> {
    validate_secret_name(name)?;
    let target_name = rename.as_deref().unwrap_or(name);
    validate_secret_name(target_name)?;

    let source_dir = std::env::current_dir()?
        .canonicalize()
        .context("Failed to resolve source project directory")?;
    let target_dir = resolve_target(&source_dir, target_dir)?;
    if source_dir == target_dir {
        anyhow::bail!(
            "Source and target resolve to the same project. Refusing an ambiguous self-copy; use `phantom add` for an intentional replacement."
        );
    }
    let source_config_path = source_dir.join(".phantom.toml");
    let target_config_path = target_dir.join(".phantom.toml");
    let (source_config, _) = load_config_exact(&source_config_path).with_context(|| {
        format!(
            "Source project is not safely initialized at {}. Run `phantom init --empty` there first.",
            source_dir.display()
        )
    })?;
    let (target_config, target_config_before) = load_config_exact(&target_config_path)
        .with_context(|| {
            format!(
                "Target project is not safely initialized at {}. Run `phantom init --empty` there first.",
                target_dir.display()
            )
        })?;

    let target_vault = phantom_vault::try_create_vault(target_config.local_project_id())?;

    // Complete every target collision and filesystem check before retrieving
    // the source plaintext. Copy has no overwrite flag, so any existing target
    // ownership is an explicit hard refusal rather than a silent clobber.
    let target_vault_names = target_vault
        .list()
        .context("Failed to list target vault entries")?;
    if snapshot_secret(target_vault.as_ref(), target_name)?.is_some() {
        anyhow::bail!(
            "Target secret '{target_name}' already exists. Copy refuses ambiguous overwrite; remove it explicitly or choose --rename."
        );
    }
    if target_config.phantom.secrets.contains_key(target_name) {
        anyhow::bail!(
            "Target config already owns metadata for '{target_name}'. Copy refuses to create a value with ambiguous lifecycle policy; choose --rename or reconcile the target first."
        );
    }
    let resolved = phantom_core::managed_dotenv::resolve_dotenv(
        &target_dir,
        &target_config,
        &target_vault_names,
    )?;
    let target_env_path = resolved.path;
    let env_before = snapshot_regular_file(&target_env_path)?;
    if dotenv_has_key(env_before.as_deref(), target_name)? {
        anyhow::bail!(
            "Target managed dotenv already contains '{target_name}'. Copy refuses to overwrite an existing mapping; remove it explicitly or choose --rename."
        );
    }

    // Consent is bound to the exact canonical path, names, and machine-local
    // vault identity observed during target preflight. The config exact-before
    // file guard below prevents that approved identity from drifting at commit.
    require_trusted_terminal_copy(
        name,
        target_name,
        &target_dir,
        target_config.local_project_id(),
    )?;

    let source_vault = phantom_vault::try_create_vault(source_config.local_project_id())?;
    let secret_value = source_vault
        .retrieve(name)
        .with_context(|| format!("Secret '{name}' not found in source vault"))?;
    let plan = prepare_target_plan(
        &target_dir,
        &target_config_path,
        target_config,
        target_config_before,
        target_vault_names,
        target_env_path,
        env_before,
        target_name,
        secret_value.as_str(),
    )?;

    phantom_vault::commit_init(
        &target_dir,
        target_vault.as_ref(),
        vec![plan.mutation],
        plan.files,
    )
    .context(
        "Copy transaction failed; exact transaction-owned target state was rolled back where verifiable. Inspect the target vault and managed dotenv before retrying.",
    )?;

    println!(
        "{} Copied {} as {} into {} and updated {} (value never printed)",
        "ok".green().bold(),
        name.bold(),
        target_name.bold(),
        target_dir.display(),
        plan.env_path
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("managed dotenv")
            .cyan()
    );
    Ok(())
}

fn require_trusted_terminal_copy(
    name: &str,
    target_name: &str,
    target_dir: &Path,
    target_local_project_id: &str,
) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "`phantom copy` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No source secret was read and no target state changed. Use the approved MCP copy flow when the calling agent cannot be excluded from terminal authority."
        );
    }
    let challenge = format!(
        "COPY {name} AS {target_name} TO {} ID {target_local_project_id}",
        target_dir.display()
    );
    eprintln!(
        "Secret copy is an exfiltration-capable operation.\nTarget: {}\nTarget vault fingerprint: {}\nSource name: {}\nTarget name: {}\nType this exact challenge to continue:\n{}",
        target_dir.display(),
        target_local_project_id,
        name,
        target_name,
        challenge
    );
    eprint!("> ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin()
        .read_line(&mut response)
        .context("Failed to read trusted-terminal copy confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!("Copy confirmation did not match exactly. No source secret was read and no target state changed.");
    }
    Ok(())
}

fn resolve_target(source_dir: &Path, target: &Path) -> Result<PathBuf> {
    let candidate = if target.is_relative() {
        source_dir.join(target)
    } else {
        target.to_path_buf()
    };
    candidate
        .canonicalize()
        .context("Target directory does not exist or cannot be safely resolved")
}

#[allow(clippy::too_many_arguments)]
fn prepare_target_plan(
    target_dir: &Path,
    config_path: &Path,
    mut config: PhantomConfig,
    config_before: Vec<u8>,
    target_vault_names: Vec<String>,
    env_path: PathBuf,
    env_before: Option<Vec<u8>>,
    target_name: &str,
    value: &str,
) -> Result<CopyTargetPlan> {
    let env_after = rewrite_dotenv(env_before.as_deref(), target_name)?;
    let mutation = InitSecret::replace_if_unchanged(target_name, None::<String>, value);
    let config_after = if config.phantom.dotenv_path.is_none() && target_vault_names.is_empty() {
        config.phantom.dotenv_path = Some(
            phantom_core::managed_dotenv::dotenv_basename(target_dir, &env_path)
                .context("Failed to persist target managed dotenv mapping")?,
        );
        toml::to_string_pretty(&config)
            .context("Failed to serialize target managed dotenv configuration")?
            .into_bytes()
    } else {
        config_before.clone()
    };
    let mut files = vec![InitFile::replace_if_unchanged(
        config_path,
        Some(config_before),
        config_after,
    )];
    files.push(InitFile::replace_if_unchanged(&env_path, env_before, env_after).commit_last());
    Ok(CopyTargetPlan {
        mutation,
        files,
        env_path,
    })
}

fn dotenv_has_key(before: Option<&[u8]>, name: &str) -> Result<bool> {
    let Some(bytes) = before else {
        return Ok(false);
    };
    let content = std::str::from_utf8(bytes)
        .context("Target managed dotenv is not valid UTF-8; refusing to inspect or rewrite it")?;
    Ok(DotenvFile::parse_str(content)
        .entries()
        .iter()
        .any(|entry| entry.key == name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::PhantomError;
    use phantom_vault::file::FileVault;
    use phantom_vault::VaultBackend;

    #[test]
    fn target_key_detection_is_exact() {
        assert!(dotenv_has_key(Some(b"API_KEY=phm_test\n"), "API_KEY").unwrap());
        assert!(!dotenv_has_key(Some(b"OTHER_API_KEY=phm_test\n"), "API_KEY").unwrap());
    }

    #[test]
    fn same_project_identity_is_rejected_by_canonical_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        assert_eq!(
            resolve_target(&canonical, Path::new(".")).unwrap(),
            canonical
        );
    }

    #[test]
    fn target_config_drift_aborts_before_vault_or_dotenv_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().canonicalize().unwrap();
        let config_path = target.join(".phantom.toml");
        PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&target))
            .save(&config_path)
            .unwrap();
        let (config, config_before) = load_config_exact(&config_path).unwrap();
        let vault =
            FileVault::new(dir.path(), "copy-target-test", "passphrase".to_string()).unwrap();
        let env_path = target.join(".env");
        let plan = prepare_target_plan(
            &target,
            &config_path,
            config,
            config_before,
            Vec::new(),
            env_path.clone(),
            None,
            "COPIED_KEY",
            "secret-value",
        )
        .unwrap();
        let mut concurrent_config = std::fs::read(&config_path).unwrap();
        concurrent_config.extend_from_slice(b"\n# concurrent owner\n");
        std::fs::write(&config_path, &concurrent_config).unwrap();

        assert!(
            phantom_vault::commit_init(&target, &vault, vec![plan.mutation], plan.files).is_err()
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent_config);
        assert!(!env_path.exists());
        assert!(matches!(
            vault.retrieve("COPIED_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }
}
