#![allow(dead_code)]
/// `phantom env` subcommands for environment scoping.
///
/// This module handles `use`, `list`, `new`, and `copy` — the environment
/// selector commands. The legacy `phantom env` (generate .env.example) is
/// still available as `phantom env example` (see `commands/env.rs`).
use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::env_scope::{
    known_envs_from_keys, namespaced_key, resolve_env, split_key, validate_env_name,
    write_active_env, DEFAULT_ENV,
};
use phantom_vault::{InitFile, InitSecret, VaultBackend};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

#[derive(Debug)]
struct EnvironmentCopyPlan {
    mutations: Vec<InitSecret>,
    copied_names: Vec<String>,
}

/// `phantom env use <name>` — set the active environment.
pub fn run_use(name: &str) -> Result<()> {
    validate_env_name(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let project_dir = std::env::current_dir()?;
    write_active_env(&project_dir, name).context("Failed to write active environment")?;

    println!(
        "{} Active environment set to {}",
        "ok".green().bold(),
        name.cyan().bold()
    );
    println!(
        "{} New secrets will be stored under the {} namespace.",
        "->".blue().bold(),
        name.cyan()
    );
    Ok(())
}

/// `phantom env list` — list known environments extracted from vault keys.
pub fn run_list() -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let all_keys = vault.list().context("Failed to list vault keys")?;

    let current = phantom_core::env_scope::read_active_env(&project_dir);
    let envs = known_envs_from_keys(&all_keys, &current);

    println!("{} Known environments:\n", "->".blue().bold());
    for env in &envs {
        if env == &current {
            println!(
                "   {} {} {}",
                "*".green().bold(),
                env.bold(),
                "(active)".dimmed()
            );
        } else {
            println!("   {} {}", "-".dimmed(), env);
        }
    }

    if envs.len() == 1 {
        println!(
            "\n{} Only the default environment exists. Use {} to create more.",
            "->".blue().bold(),
            "phantom env new <name>".cyan()
        );
    }

    Ok(())
}

/// `phantom env new <name>` — declare a new environment (no-op if it already exists).
/// Secrets are added per-key via `phantom add --env <name>`.
pub fn run_new(name: &str) -> Result<()> {
    validate_env_name(name).map_err(|e| anyhow::anyhow!("{e}"))?;

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    // Check if env already has any keys in vault
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let all_keys = vault.list().context("Failed to list vault keys")?;
    let prefix = format!("{name}/");
    let existing_count = all_keys.iter().filter(|k| k.starts_with(&prefix)).count();

    if existing_count > 0 {
        println!(
            "{} Environment {} already exists ({} secret(s)).",
            "!".yellow().bold(),
            name.cyan().bold(),
            existing_count
        );
    } else {
        println!(
            "{} Environment {} declared.",
            "ok".green().bold(),
            name.cyan().bold()
        );
    }

    println!(
        "{} Add secrets with: {}",
        "->".blue().bold(),
        format!("phantom add --env {name} KEY").cyan()
    );
    println!(
        "{} Switch to it with: {}",
        "->".blue().bold(),
        format!("phantom env use {name}").cyan()
    );

    Ok(())
}

/// `phantom env copy --from <src> --to <dst>` — copy all secrets from one env to another.
pub fn run_copy(from: &str, to: &str) -> Result<()> {
    validate_env_name(from).map_err(|e| anyhow::anyhow!("{e}"))?;
    validate_env_name(to).map_err(|e| anyhow::anyhow!("{e}"))?;

    if from == to {
        anyhow::bail!("--from and --to must be different environments.");
    }

    let project_dir = std::env::current_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)
        .context("Failed to safely snapshot .phantom.toml")?
        .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run phantom init first."))?;
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    if phantom_core::fs::read_regular_file(&config_path)?.as_deref()
        != Some(config_before.as_slice())
    {
        anyhow::bail!(".phantom.toml changed during environment-copy preflight");
    }
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let all_keys = vault.list().context("Failed to list vault keys")?;
    let plan = prepare_environment_copy(vault.as_ref(), &all_keys, from, to)?;
    let copied = plan.copied_names.len();
    let config_guard =
        InitFile::replace_if_unchanged(&config_path, Some(config_before.clone()), config_before);
    phantom_vault::commit_init(
        &project_dir,
        vault.as_ref(),
        plan.mutations,
        vec![config_guard],
    )
    .context(
        "Environment copy transaction failed; exact transaction-owned writes were rolled back where verifiable. Inspect both environments before retrying.",
    )?;

    for name in &plan.copied_names {
        println!(
            "   {} {} -> {}/{}",
            "+".green().bold(),
            name.bold(),
            to.cyan(),
            name
        );
    }

    println!(
        "\n{} Copied {} secret(s) to environment '{}'.",
        "ok".green().bold(),
        copied,
        to.cyan().bold()
    );
    println!(
        "{} Switch to it with: {}",
        "->".blue().bold(),
        format!("phantom env use {to}").cyan()
    );

    Ok(())
}

fn prepare_environment_copy(
    vault: &dyn VaultBackend,
    all_keys: &[String],
    from: &str,
    to: &str,
) -> Result<EnvironmentCopyPlan> {
    let mut sources = BTreeMap::<String, String>::new();
    for key in all_keys {
        let logical = match split_key(key) {
            Some((environment, name)) if environment == from => Some(name.to_string()),
            None if from == DEFAULT_ENV => Some(key.clone()),
            _ => None,
        };
        if let Some(name) = logical {
            if sources.insert(name.clone(), key.clone()).is_some() {
                anyhow::bail!(
                    "Environment '{from}' has ambiguous duplicate ownership for '{name}'; reconcile bare and namespaced entries before copying"
                );
            }
        }
    }
    if sources.is_empty() {
        anyhow::bail!(
            "No secrets found in environment '{}'. Add some with: {}",
            from,
            format!("phantom add --env {from} KEY").cyan()
        );
    }

    let existing: BTreeSet<&str> = all_keys.iter().map(String::as_str).collect();
    let collisions = sources
        .keys()
        .filter(|name| {
            existing.contains(namespaced_key(to, name).as_str())
                || (to == DEFAULT_ENV && existing.contains(name.as_str()))
        })
        .cloned()
        .collect::<Vec<_>>();
    if !collisions.is_empty() {
        anyhow::bail!(
            "Destination environment '{to}' already owns {} secret(s); copy refuses overwrite. Reconcile or remove the destination entries explicitly.",
            collisions.len()
        );
    }

    // Keep every provider value in zeroizing owners from retrieval until it
    // moves into InitSecret's zeroizing transaction fields.
    let mut values = Vec::<(String, String, Zeroizing<String>)>::with_capacity(sources.len());
    for (name, source_key) in sources {
        let value = vault
            .retrieve(&source_key)
            .with_context(|| format!("Failed to retrieve source secret '{source_key}'"))?;
        values.push((name, source_key, value));
    }

    let mut mutations = Vec::with_capacity(values.len() * 2);
    let mut copied_names = Vec::with_capacity(values.len());
    for (name, source_key, value) in values {
        // A no-op exact-CAS source guard makes the snapshot part of the same
        // locked transaction; all guards are preflighted before any write.
        mutations.push(InitSecret::replace_if_unchanged(
            source_key,
            Some(value.as_str().to_string()),
            value.as_str().to_string(),
        ));
        mutations.push(InitSecret::replace_if_unchanged(
            namespaced_key(to, &name),
            None::<String>,
            value.as_str().to_string(),
        ));
        copied_names.push(name);
    }
    Ok(EnvironmentCopyPlan {
        mutations,
        copied_names,
    })
}

/// `phantom env` with no subcommand — show help hint.
pub fn run_default(current: &str) -> Result<()> {
    println!(
        "{} Active environment: {}",
        "->".blue().bold(),
        current.cyan().bold()
    );
    println!(
        "{}",
        "Use a subcommand: use <name> | list | new <name> | copy --from <src> --to <dst>".dimmed()
    );
    println!(
        "  {} — generate .env.example for team onboarding",
        "phantom env example".cyan()
    );
    Ok(())
}

/// Resolve env from flag or persisted file, used by vault call sites.
pub fn effective_env(project_dir: &std::path::Path, flag: Option<&str>) -> String {
    resolve_env(project_dir, flag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_vault::file::FileVault;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FailingCasVault {
        inner: FileVault,
        cas_calls: AtomicUsize,
        retrieve_calls: AtomicUsize,
        fail_at: Option<usize>,
    }

    impl VaultBackend for FailingCasVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            self.inner.store(name, value)
        }

        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.retrieve_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve(name)
        }

        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.inner.delete(name)
        }

        fn compare_and_swap(
            &self,
            name: &str,
            expected: Option<&str>,
            replacement: Option<&str>,
        ) -> PhantomResult<bool> {
            let call = self.cas_calls.fetch_add(1, Ordering::SeqCst);
            let result = self.inner.compare_and_swap(name, expected, replacement)?;
            if self.fail_at == Some(call) {
                return Err(PhantomError::VaultError(
                    "injected ambiguous environment-copy CAS failure".to_string(),
                ));
            }
            Ok(result)
        }

        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }

        fn backend_name(&self) -> &str {
            "failing-env-copy"
        }
    }

    fn vault(fail_at: Option<usize>) -> (tempfile::TempDir, FailingCasVault) {
        let dir = tempfile::tempdir().unwrap();
        let inner = FileVault::new(dir.path(), "env-copy", "passphrase".to_string()).unwrap();
        (
            dir,
            FailingCasVault {
                inner,
                cas_calls: AtomicUsize::new(0),
                retrieve_calls: AtomicUsize::new(0),
                fail_at,
            },
        )
    }

    #[test]
    fn destination_collision_refuses_before_source_retrieval() {
        let (_dir, vault) = vault(None);
        vault.store("dev/API_KEY", "source-value").unwrap();
        vault.store("prod/API_KEY", "destination-owner").unwrap();
        let keys = vault.list().unwrap();
        let error = prepare_environment_copy(&vault, &keys, "dev", "prod").unwrap_err();

        assert!(error.to_string().contains("refuses overwrite"));
        assert_eq!(vault.retrieve_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            vault.retrieve("prod/API_KEY").unwrap().as_str(),
            "destination-owner"
        );
    }

    #[test]
    fn nth_ambiguous_cas_rolls_back_every_destination() {
        let (dir, vault) = vault(Some(3));
        vault.store("dev/A", "source-a").unwrap();
        vault.store("dev/B", "source-b").unwrap();
        let keys = vault.list().unwrap();
        let plan = prepare_environment_copy(&vault, &keys, "dev", "prod").unwrap();

        assert!(
            phantom_vault::commit_init(dir.path(), &vault, plan.mutations, Vec::new()).is_err()
        );
        assert_eq!(vault.retrieve("dev/A").unwrap().as_str(), "source-a");
        assert_eq!(vault.retrieve("dev/B").unwrap().as_str(), "source-b");
        assert!(matches!(
            vault.retrieve("prod/A"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert!(matches!(
            vault.retrieve("prod/B"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn destination_race_is_detected_without_overwrite() {
        let (dir, vault) = vault(None);
        vault.store("dev/API_KEY", "source-value").unwrap();
        let keys = vault.list().unwrap();
        let plan = prepare_environment_copy(&vault, &keys, "dev", "prod").unwrap();
        vault.store("prod/API_KEY", "concurrent-owner").unwrap();

        assert!(
            phantom_vault::commit_init(dir.path(), &vault, plan.mutations, Vec::new()).is_err()
        );
        assert_eq!(
            vault.retrieve("prod/API_KEY").unwrap().as_str(),
            "concurrent-owner"
        );
    }

    #[test]
    fn source_drift_aborts_before_any_target_write() {
        let (dir, vault) = vault(None);
        vault.store("dev/A", "source-a").unwrap();
        vault.store("dev/B", "source-b").unwrap();
        let keys = vault.list().unwrap();
        let plan = prepare_environment_copy(&vault, &keys, "dev", "prod").unwrap();
        vault.store("dev/B", "concurrent-source-owner").unwrap();

        assert!(
            phantom_vault::commit_init(dir.path(), &vault, plan.mutations, Vec::new()).is_err()
        );
        assert!(matches!(
            vault.retrieve("prod/A"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert!(matches!(
            vault.retrieve("prod/B"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert_eq!(
            vault.retrieve("dev/B").unwrap().as_str(),
            "concurrent-source-owner"
        );
    }

    #[test]
    fn default_source_duplicate_ownership_is_ambiguous() {
        let (_dir, vault) = vault(None);
        vault.store("API_KEY", "legacy").unwrap();
        vault.store("default/API_KEY", "namespaced").unwrap();
        let keys = vault.list().unwrap();

        let error = prepare_environment_copy(&vault, &keys, "default", "prod").unwrap_err();
        assert!(error.to_string().contains("ambiguous duplicate ownership"));
        assert_eq!(vault.retrieve_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn copying_to_default_uses_canonical_namespaced_representation() {
        let (dir, vault) = vault(None);
        vault.store("dev/API_KEY", "source-value").unwrap();
        let keys = vault.list().unwrap();
        let plan = prepare_environment_copy(&vault, &keys, "dev", "default").unwrap();
        phantom_vault::commit_init(dir.path(), &vault, plan.mutations, Vec::new()).unwrap();

        assert_eq!(
            vault.retrieve("default/API_KEY").unwrap().as_str(),
            "source-value"
        );
        assert!(matches!(
            vault.retrieve("API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }

    #[test]
    fn copying_to_default_refuses_legacy_bare_destination_owner() {
        let (_dir, vault) = vault(None);
        vault.store("dev/API_KEY", "source-value").unwrap();
        vault.store("API_KEY", "legacy-owner").unwrap();
        let keys = vault.list().unwrap();

        let error = prepare_environment_copy(&vault, &keys, "dev", "default").unwrap_err();
        assert!(error.to_string().contains("refuses overwrite"));
        assert_eq!(vault.retrieve("API_KEY").unwrap().as_str(), "legacy-owner");
    }
}
