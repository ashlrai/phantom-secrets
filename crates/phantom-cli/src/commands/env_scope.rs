#![allow(dead_code)]
/// `phantom env` subcommands for environment scoping.
///
/// This module handles `use`, `list`, `new`, and `copy` — the environment
/// selector commands. The legacy `phantom env` (generate .env.example) is
/// still available as `phantom env example` (see `commands/env.rs`).
use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
#[cfg(test)]
use phantom_core::env_scope::write_active_env_if_unchanged;
use phantom_core::env_scope::{
    known_envs_from_keys, namespaced_key, resolve_env, split_key, validate_env_name, DEFAULT_ENV,
};
use phantom_core::fs::{AnchoredRead, TrustedAnchor};
use phantom_vault::{
    InitFile, InitSecret, ProjectDirectoryPreparation, ProjectTransactionLock, VaultBackend,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug)]
struct EnvironmentCopyPlan {
    mutations: Vec<InitSecret>,
    copied_names: Vec<String>,
}

#[derive(Debug)]
struct EnvironmentCopyReview {
    project_dir: PathBuf,
    project_anchor: TrustedAnchor,
    config_path: PathBuf,
    config_before: AnchoredRead,
    selector_path: PathBuf,
    selector_before: Option<AnchoredRead>,
    vault_id: String,
    from: String,
    to: String,
    effect: String,
    challenge: String,
}

#[derive(Debug)]
struct EnvironmentUsePlan {
    project_dir: PathBuf,
    project_anchor: TrustedAnchor,
    config_path: PathBuf,
    config_before: AnchoredRead,
    env_before: Option<AnchoredRead>,
    name: String,
    effect: String,
    challenge: String,
}

fn read_project_regular(
    project: &TrustedAnchor,
    relative: &Path,
    label: &str,
) -> Result<Option<AnchoredRead>> {
    let target = match project.target(relative) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to retain {label} target"))
        }
    };
    target
        .read_regular()
        .with_context(|| format!("Failed to safely snapshot {label}"))
}

/// `phantom env use <name>` — set the active environment.
pub fn run_use(name: &str) -> Result<()> {
    let plan = prepare_environment_use(&std::env::current_dir()?, name)?;
    let attached = std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal();
    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let mut output = std::io::stderr().lock();
    apply_environment_use(&plan, attached, &mut input, &mut output)?;

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

fn prepare_environment_use(
    project_dir: &std::path::Path,
    name: &str,
) -> Result<EnvironmentUsePlan> {
    validate_env_name(name).map_err(|error| anyhow::anyhow!("{error}"))?;
    let project_dir = project_dir
        .canonicalize()
        .context("Failed to resolve the canonical project directory")?;
    let project_anchor = TrustedAnchor::open(&project_dir)
        .context("Failed to retain the project root for environment selection review")?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before =
        read_project_regular(&project_anchor, Path::new(".phantom.toml"), ".phantom.toml")?
            .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run phantom init first."))?;
    let config = PhantomConfig::load_from_bytes(&config_path, config_before.bytes())
        .context("Failed to load the exact .phantom.toml snapshot")?;
    let env_before = read_project_regular(
        &project_anchor,
        Path::new(".phantom/env"),
        "active environment selector",
    )?;
    let project_digest = super::export_cmd::digest_path(&project_dir);
    let config_digest = super::export_cmd::digest_bytes(config_before.bytes());
    let before_digest = env_before
        .as_ref()
        .map(AnchoredRead::bytes)
        .map(super::export_cmd::digest_bytes)
        .unwrap_or_else(|| "absent".to_string());
    let effect = format!(
        "Set active Phantom environment to '{name}' for project SHA-256 {project_digest} and local vault {} (config SHA-256 {config_digest}; selector before {before_digest})",
        config.local_project_id()
    );
    let challenge = format!(
        "USE PHANTOM ENV {name} PROJECT {project_digest} VAULT {} CONFIG {config_digest} BEFORE {before_digest}",
        config.local_project_id()
    );
    Ok(EnvironmentUsePlan {
        project_dir,
        project_anchor,
        config_path,
        config_before,
        env_before,
        name: name.to_string(),
        effect,
        challenge,
    })
}

fn apply_environment_use(
    plan: &EnvironmentUsePlan,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    apply_environment_use_with(plan, attached, reader, writer, || {})
}

fn apply_environment_use_with(
    plan: &EnvironmentUsePlan,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    before_project_lock: impl FnOnce(),
) -> Result<()> {
    if !attached {
        anyhow::bail!(
            "`phantom env use` requires attached stdin, stdout, and stderr terminals; the active environment was not changed"
        );
    }
    writeln!(writer, "Persistent environment selection: {}", plan.effect)?;
    writeln!(writer, "Approve only if this terminal is outside the requesting agent's authority; a same-user shell or agent-controlled PTY can automate this ceremony.")?;
    write!(writer, "Type `{}` to continue: ", plan.challenge)?;
    writer.flush()?;
    let mut response = String::new();
    (&mut *reader)
        .take((plan.challenge.len() + 2) as u64)
        .read_line(&mut response)
        .context("Failed to read the environment selection confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != plan.challenge {
        anyhow::bail!(
            "Environment selection confirmation did not match exactly; the active environment was not changed"
        );
    }

    before_project_lock();
    let lock = phantom_vault::acquire_project_transaction_lock(&plan.project_dir)
        .context("Failed to acquire the project transaction lock")?;
    if lock.project_identity_at_acquisition() != plan.project_anchor.identity() {
        anyhow::bail!(
            "The project root was replaced after environment selection was reviewed; the active environment was not changed"
        );
    }
    let current_config = lock
        .target(&plan.config_path)?
        .read_regular()
        .context("Failed to verify the .phantom.toml before-image")?;
    if current_config.as_ref() != Some(&plan.config_before) {
        anyhow::bail!(
            ".phantom.toml changed after environment selection was reviewed; the active environment was not changed"
        );
    }
    replace_active_environment(&lock, plan.env_before.as_ref(), &plan.name)
        .context("Failed to atomically update the active environment")?;
    Ok(())
}

fn replace_active_environment(
    lock: &ProjectTransactionLock,
    expected_before: Option<&AnchoredRead>,
    name: &str,
) -> Result<()> {
    let preparation = match lock.prepare_private_child(".phantom")? {
        ProjectDirectoryPreparation::CreatedVerifiedButDurabilityUncertain(receipt) => {
            eprintln!(
                "warning: active-environment directory creation committed and was verified, but directory crash durability is not provable on this platform"
            );
            ProjectDirectoryPreparation::Created(receipt)
        }
        ProjectDirectoryPreparation::CommittedButUncertain { receipt, error } => {
            let cleanup = receipt.map(|receipt| receipt.remove_if_empty_exact());
            return match cleanup {
                Some(Ok(
                    phantom_core::fs::AnchoredEffect::Durable(())
                    | phantom_core::fs::AnchoredEffect::
                        CommittedVerifiedButDurabilityUncertain { value: () },
                )) => {
                    eprintln!(
                        "warning: active-environment directory rollback committed and was verified, but directory crash durability is not provable on this platform"
                    );
                    Err(error).context("Active-environment directory creation was rolled back")
                }
                _ => anyhow::bail!(
                    "Active-environment directory creation may have committed and exact cleanup could not be verified: {error}"
                ),
            };
        }
        preparation => preparation,
    };

    let target = preparation
        .anchor()
        .expect("known directory preparation retains its anchor")
        .target("env")?;
    let reviewed = target.read_regular()?;
    if reviewed.as_ref() != expected_before {
        drop(target);
        cleanup_created_directory(preparation)?;
        anyhow::bail!("active environment selector changed after it was reviewed");
    }
    let permissions = reviewed
        .as_ref()
        .map(phantom_core::fs::AnchoredRead::permissions)
        .unwrap_or_else(phantom_core::fs::AnchoredFilePermissions::private);
    let effect = target.replace_if_exact_with_permissions(
        reviewed.as_ref(),
        format!("{name}\n").as_bytes(),
        permissions,
    );
    drop(target);
    match effect {
        Ok(phantom_core::fs::AnchoredEffect::Durable(_)) => Ok(()),
        Ok(phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain {
            ..
        }) => {
            eprintln!(
                "warning: active environment selection committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(())
        }
        Ok(phantom_core::fs::AnchoredEffect::CommittedButUncertain { error, .. }) => {
            anyhow::bail!(
                "active environment selector was replaced, but durability could not be verified: {error}"
            )
        }
        Err(error) => {
            cleanup_created_directory(preparation)?;
            Err(error.into())
        }
    }
}

fn cleanup_created_directory(preparation: ProjectDirectoryPreparation) -> Result<()> {
    let receipt = match preparation {
        ProjectDirectoryPreparation::Created(receipt) => receipt,
        ProjectDirectoryPreparation::CreatedVerifiedButDurabilityUncertain(receipt) => {
            eprintln!(
                "warning: active-environment directory creation was verified, but directory crash durability is not provable on this platform"
            );
            receipt
        }
        ProjectDirectoryPreparation::Existing(_)
        | ProjectDirectoryPreparation::CommittedButUncertain { .. } => return Ok(()),
    };
    match receipt.remove_if_empty_exact()? {
        phantom_core::fs::AnchoredEffect::Durable(()) => Ok(()),
        phantom_core::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain {
            value: (),
        } => {
            eprintln!(
                "warning: active-environment directory cleanup committed and was verified, but directory crash durability is not provable on this platform"
            );
            Ok(())
        }
        phantom_core::fs::AnchoredEffect::CommittedButUncertain { error, .. } => anyhow::bail!(
            "active-environment directory was removed, but cleanup durability could not be verified: {error}"
        ),
    }
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
    let review = prepare_environment_copy_review(&std::env::current_dir()?, from, to)?;
    let attached = std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal();
    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let mut output = std::io::stderr().lock();
    confirm_environment_copy(&review, attached, &mut input, &mut output)?;

    // Vault creation, listing, and especially value retrieval are deliberately
    // after the fresh trusted-terminal ceremony and exact local-state recheck.
    let vault = phantom_vault::try_create_vault(&review.vault_id)?;
    let all_keys = vault.list().context("Failed to list vault keys")?;
    let plan = prepare_environment_copy(
        vault.as_ref(),
        &all_keys,
        review.from.as_str(),
        review.to.as_str(),
    )?;
    validate_environment_copy_review(&review).context(
        "Environment copy authority changed after source values were prepared; no destination was written",
    )?;
    let copied = plan.copied_names.len();
    let file_guards = environment_copy_file_guards(&review);
    phantom_vault::commit_init_if_project_identity(
        &review.project_dir,
        review.project_anchor.identity(),
        vault.as_ref(),
        plan.mutations,
        file_guards,
    )
    .context(
        "Environment copy transaction failed; exact transaction-owned writes were rolled back where verifiable. Inspect both environments before retrying.",
    )?;

    for name in &plan.copied_names {
        println!(
            "   {} {} -> {}/{}",
            "+".green().bold(),
            name.bold(),
            review.to.as_str().cyan(),
            name
        );
    }

    println!(
        "\n{} Copied {} secret(s) to environment '{}'.",
        "ok".green().bold(),
        copied,
        review.to.as_str().cyan().bold()
    );
    println!(
        "{} Switch to it with: {}",
        "->".blue().bold(),
        format!("phantom env use {}", review.to).cyan()
    );

    Ok(())
}

fn environment_copy_file_guards(review: &EnvironmentCopyReview) -> Vec<InitFile> {
    let mut guards = vec![InitFile::replace_if_exact_snapshot(
        &review.config_path,
        Some(&review.config_before),
        review.config_before.bytes().to_vec(),
    )];
    if let Some(selector_before) = &review.selector_before {
        guards.push(InitFile::replace_if_exact_snapshot(
            &review.selector_path,
            Some(selector_before),
            selector_before.bytes().to_vec(),
        ));
    }
    guards
}

fn prepare_environment_copy_review(
    project_dir: &std::path::Path,
    from: &str,
    to: &str,
) -> Result<EnvironmentCopyReview> {
    validate_env_name(from).map_err(|error| anyhow::anyhow!("{error}"))?;
    validate_env_name(to).map_err(|error| anyhow::anyhow!("{error}"))?;
    if from == to {
        anyhow::bail!("--from and --to must be different environments.");
    }

    let project_dir = project_dir
        .canonicalize()
        .context("Failed to resolve the canonical project directory")?;
    let project_anchor = TrustedAnchor::open(&project_dir)
        .context("Failed to retain the project root for environment copy review")?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before =
        read_project_regular(&project_anchor, Path::new(".phantom.toml"), ".phantom.toml")?
            .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run phantom init first."))?;
    let config = PhantomConfig::load_from_bytes(&config_path, config_before.bytes())
        .context("Failed to load the exact .phantom.toml snapshot")?;
    let selector_path = project_dir.join(".phantom").join("env");
    let selector_before = read_project_regular(
        &project_anchor,
        Path::new(".phantom/env"),
        "active environment selector",
    )?;
    let project_digest = super::export_cmd::digest_path(&project_dir);
    let config_digest = super::export_cmd::digest_bytes(config_before.bytes());
    let selector_digest = selector_before
        .as_ref()
        .map(AnchoredRead::bytes)
        .map(super::export_cmd::digest_bytes)
        .unwrap_or_else(|| "absent".to_string());
    let effect = format!(
        "Copy every non-colliding secret owned by Phantom environment '{from}' into '{to}' for project SHA-256 {project_digest} and local vault {} (config SHA-256 {config_digest}; active-selector {selector_digest}); source values remain unchanged and existing destinations are never overwritten",
        config.local_project_id()
    );
    let challenge = format!(
        "COPY PHANTOM ENV {from} TO {to} PROJECT {project_digest} VAULT {} CONFIG {config_digest} SELECTOR {selector_digest}",
        config.local_project_id()
    );
    Ok(EnvironmentCopyReview {
        project_dir,
        project_anchor,
        config_path,
        config_before,
        selector_path,
        selector_before,
        vault_id: config.local_project_id().to_string(),
        from: from.to_string(),
        to: to.to_string(),
        effect,
        challenge,
    })
}

fn confirm_environment_copy(
    review: &EnvironmentCopyReview,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    confirm_environment_copy_with(review, attached, reader, writer, || {})
}

fn confirm_environment_copy_with(
    review: &EnvironmentCopyReview,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    before_revalidation: impl FnOnce(),
) -> Result<()> {
    if !attached {
        anyhow::bail!(
            "`phantom env copy` requires attached stdin, stdout, and stderr terminals; no vault values were retrieved and no destination was written"
        );
    }
    writeln!(writer, "Secret-bearing environment copy: {}", review.effect)?;
    writeln!(writer, "Approve only if this terminal is outside the requesting agent's authority; a same-user shell or agent-controlled PTY can automate this ceremony.")?;
    write!(writer, "Type `{}` to continue: ", review.challenge)?;
    writer.flush()?;
    let mut response = String::new();
    (&mut *reader)
        .take((review.challenge.len() + 2) as u64)
        .read_line(&mut response)
        .context("Failed to read the environment copy confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != review.challenge {
        anyhow::bail!(
            "Environment copy confirmation did not match exactly; no vault values were retrieved and no destination was written"
        );
    }

    before_revalidation();
    validate_environment_copy_review(review)
}

fn validate_environment_copy_review(review: &EnvironmentCopyReview) -> Result<()> {
    let current_project = TrustedAnchor::open(&review.project_dir)
        .context("Failed to retain the current project root before environment copy")?;
    if current_project.identity() != review.project_anchor.identity() {
        anyhow::bail!(
            "The project root was replaced after environment review; no vault values were retrieved and no destination was written"
        );
    }
    let current_config = read_project_regular(
        &current_project,
        Path::new(".phantom.toml"),
        ".phantom.toml",
    )?;
    if current_config.as_ref() != Some(&review.config_before) {
        anyhow::bail!(
            ".phantom.toml changed after environment copy was reviewed; no vault values were retrieved and no destination was written"
        );
    }
    let current_selector = read_project_regular(
        &current_project,
        Path::new(".phantom/env"),
        "active environment selector",
    )?;
    if current_selector.as_ref() != review.selector_before.as_ref() {
        anyhow::bail!(
            "The active environment selector changed after environment copy was reviewed; no vault values were retrieved and no destination was written"
        );
    }
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

    fn environment_use_plan(name: &str) -> (tempfile::TempDir, EnvironmentUsePlan) {
        let dir = tempfile::tempdir().unwrap();
        PhantomConfig::new_with_defaults("portable-env-use".to_string())
            .save(&dir.path().join(".phantom.toml"))
            .unwrap();
        let plan = prepare_environment_use(dir.path(), name).unwrap();
        (dir, plan)
    }

    fn environment_copy_review() -> (tempfile::TempDir, EnvironmentCopyReview) {
        let dir = tempfile::tempdir().unwrap();
        PhantomConfig::new_with_defaults("portable-env-copy".to_string())
            .save(&dir.path().join(".phantom.toml"))
            .unwrap();
        let review = prepare_environment_copy_review(dir.path(), "dev", "prod").unwrap();
        (dir, review)
    }

    #[test]
    fn environment_copy_headless_denial_precedes_vault_access() {
        let (_dir, review) = environment_copy_review();
        let error = confirm_environment_copy(
            &review,
            false,
            &mut std::io::Cursor::new(Vec::<u8>::new()),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("no vault values were retrieved"));
    }

    #[test]
    fn environment_copy_mismatched_challenge_precedes_vault_access() {
        let (_dir, review) = environment_copy_review();
        let error = confirm_environment_copy(
            &review,
            true,
            &mut std::io::Cursor::new(b"COPY SOMETHING ELSE\n"),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("did not match exactly"));
        assert!(error.to_string().contains("no vault values were retrieved"));
    }

    #[test]
    fn environment_copy_oversized_challenge_response_is_bounded() {
        let (_dir, review) = environment_copy_review();
        let payload = format!("{}{}\n", review.challenge, "X".repeat(64 * 1024)).into_bytes();
        let mut input = std::io::Cursor::new(payload);
        let error =
            confirm_environment_copy(&review, true, &mut input, &mut Vec::new()).unwrap_err();

        assert!(error.to_string().contains("did not match exactly"));
        assert!(input.position() <= (review.challenge.len() + 2) as u64);
    }

    #[test]
    fn environment_copy_challenge_binds_project_vault_config_and_selector() {
        let (_dir, review) = environment_copy_review();
        assert!(review
            .challenge
            .starts_with("COPY PHANTOM ENV dev TO prod PROJECT "));
        assert!(!review.vault_id.is_empty());
        assert!(review
            .challenge
            .contains(&format!(" VAULT {} ", review.vault_id)));
        assert!(review.challenge.contains(" CONFIG "));
        assert!(review.challenge.ends_with(" SELECTOR absent"));
        assert!(!review.challenge.contains("source-value"));
    }

    #[test]
    fn environment_copy_rejects_config_drift_after_confirmation() {
        let (dir, review) = environment_copy_review();
        std::fs::write(
            dir.path().join(".phantom.toml"),
            b"[phantom]\nversion = \"1\"\nproject_id = \"changed\"\n",
        )
        .unwrap();
        let response = format!("{}\n", review.challenge);
        let error = confirm_environment_copy(
            &review,
            true,
            &mut std::io::Cursor::new(response.as_bytes()),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed after"));
        assert!(error.to_string().contains("no vault values were retrieved"));
    }

    #[cfg(unix)]
    #[test]
    fn environment_copy_rejects_byte_identical_config_decoy_before_vault_access() {
        let (dir, review) = environment_copy_review();
        let config = dir.path().join(".phantom.toml");
        let moved = dir.path().join(".phantom.toml.reviewed");
        std::fs::rename(&config, &moved).unwrap();
        std::fs::write(&config, review.config_before.bytes()).unwrap();
        let response = format!("{}\n", review.challenge);
        let error = confirm_environment_copy(
            &review,
            true,
            &mut std::io::Cursor::new(response),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed after"));
        assert!(error.to_string().contains("no vault values were retrieved"));
        assert_eq!(std::fs::read(moved).unwrap(), review.config_before.bytes());
    }

    #[cfg(unix)]
    #[test]
    fn environment_copy_transaction_rejects_byte_identical_config_decoy() {
        let (project, review) = environment_copy_review();
        let guards = environment_copy_file_guards(&review);
        let config = project.path().join(".phantom.toml");
        let moved = project.path().join(".phantom.toml.reviewed");
        let config_bytes = review.config_before.bytes().to_vec();
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(&vault_dir),
            "env-copy-file-identity",
            "passphrase".to_string(),
        )
        .unwrap();

        std::fs::rename(&config, &moved).unwrap();
        std::fs::write(&config, &config_bytes).unwrap();

        let error = phantom_vault::commit_init_if_project_identity(
            project.path(),
            review.project_anchor.identity(),
            &vault,
            vec![InitSecret::replace_if_unchanged(
                "prod/API_KEY",
                None::<String>,
                "source-value",
            )],
            guards,
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed concurrently"));
        assert!(matches!(
            vault.retrieve("prod/API_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert_eq!(std::fs::read(&config).unwrap(), config_bytes);
        assert_eq!(std::fs::read(&moved).unwrap(), config_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn environment_copy_rejects_byte_identical_root_decoy_before_vault_access() {
        let container = tempfile::tempdir().unwrap();
        let project = container.path().join("project");
        let moved = container.path().join("reviewed-project");
        std::fs::create_dir(&project).unwrap();
        PhantomConfig::new_with_defaults("portable-env-copy-root".to_string())
            .save(&project.join(".phantom.toml"))
            .unwrap();
        let review = prepare_environment_copy_review(&project, "dev", "prod").unwrap();
        let config_before = review.config_before.bytes().to_vec();
        let response = format!("{}\n", review.challenge);
        let error = confirm_environment_copy_with(
            &review,
            true,
            &mut std::io::Cursor::new(response),
            &mut Vec::new(),
            || {
                std::fs::rename(&project, &moved).unwrap();
                std::fs::create_dir(&project).unwrap();
                std::fs::write(project.join(".phantom.toml"), &config_before).unwrap();
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("project root was replaced"));
        assert!(error.to_string().contains("no vault values were retrieved"));
        assert_eq!(
            std::fs::read(moved.join(".phantom.toml")).unwrap(),
            config_before
        );
    }

    #[test]
    fn environment_copy_rejects_selector_drift_after_confirmation() {
        let (dir, review) = environment_copy_review();
        write_active_env_if_unchanged(dir.path(), None, "concurrent").unwrap();
        let response = format!("{}\n", review.challenge);
        let error = confirm_environment_copy(
            &review,
            true,
            &mut std::io::Cursor::new(response.as_bytes()),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("selector changed"));
        assert!(error.to_string().contains("no vault values were retrieved"));
    }

    #[test]
    fn environment_use_headless_denial_makes_no_write() {
        let (dir, plan) = environment_use_plan("prod");
        let error = apply_environment_use(
            &plan,
            false,
            &mut std::io::Cursor::new(Vec::<u8>::new()),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("requires attached"));
        assert!(!dir.path().join(".phantom/env").exists());
    }

    #[test]
    fn environment_use_mismatched_challenge_makes_no_write() {
        let (dir, plan) = environment_use_plan("prod");
        let error = apply_environment_use(
            &plan,
            true,
            &mut std::io::Cursor::new(b"USE SOMETHING ELSE\n"),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("did not match exactly"));
        assert!(!dir.path().join(".phantom/env").exists());
    }

    #[test]
    fn environment_use_oversized_challenge_response_is_bounded() {
        let (dir, plan) = environment_use_plan("prod");
        let payload = format!("{}{}\n", plan.challenge, "X".repeat(64 * 1024)).into_bytes();
        let mut input = std::io::Cursor::new(payload);
        let error = apply_environment_use(&plan, true, &mut input, &mut Vec::new()).unwrap_err();

        assert!(error.to_string().contains("did not match exactly"));
        assert!(input.position() <= (plan.challenge.len() + 2) as u64);
        assert!(!dir.path().join(".phantom/env").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_environment_use_accepts_verified_namespace_commit() {
        let (dir, plan) = environment_use_plan("prod");
        let response = format!("{}\n", plan.challenge);

        apply_environment_use(
            &plan,
            true,
            &mut std::io::Cursor::new(response),
            &mut Vec::new(),
        )
        .unwrap();

        assert_eq!(phantom_core::env_scope::read_active_env(dir.path()), "prod");
    }

    #[test]
    fn environment_use_rejects_selector_drift_after_confirmation() {
        let (dir, plan) = environment_use_plan("prod");
        write_active_env_if_unchanged(dir.path(), None, "concurrent").unwrap();
        let response = format!("{}\n", plan.challenge);
        let error = apply_environment_use(
            &plan,
            true,
            &mut std::io::Cursor::new(response.as_bytes()),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("atomically update"));
        assert_eq!(
            phantom_core::env_scope::read_active_env(dir.path()),
            "concurrent"
        );
    }

    #[test]
    fn environment_use_rejects_config_drift_after_confirmation() {
        let (dir, plan) = environment_use_plan("prod");
        std::fs::write(
            dir.path().join(".phantom.toml"),
            b"[phantom]\nversion = \"1\"\nproject_id = \"changed\"\n",
        )
        .unwrap();
        let response = format!("{}\n", plan.challenge);
        let error = apply_environment_use(
            &plan,
            true,
            &mut std::io::Cursor::new(response.as_bytes()),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed after"));
        assert!(!dir.path().join(".phantom/env").exists());
    }

    #[cfg(unix)]
    #[test]
    fn environment_use_rejects_byte_identical_config_decoy() {
        let (dir, plan) = environment_use_plan("prod");
        let config = dir.path().join(".phantom.toml");
        let moved = dir.path().join(".phantom.toml.reviewed");
        std::fs::rename(&config, &moved).unwrap();
        std::fs::write(&config, plan.config_before.bytes()).unwrap();
        let response = format!("{}\n", plan.challenge);
        let error = apply_environment_use(
            &plan,
            true,
            &mut std::io::Cursor::new(response),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed after"));
        assert!(!dir.path().join(".phantom/env").exists());
        assert_eq!(std::fs::read(moved).unwrap(), plan.config_before.bytes());
    }

    #[cfg(unix)]
    #[test]
    fn environment_use_rejects_byte_identical_selector_decoy() {
        let dir = tempfile::tempdir().unwrap();
        PhantomConfig::new_with_defaults("portable-env-use-selector".to_string())
            .save(&dir.path().join(".phantom.toml"))
            .unwrap();
        std::fs::create_dir(dir.path().join(".phantom")).unwrap();
        std::fs::write(dir.path().join(".phantom/env"), b"dev\n").unwrap();
        let plan = prepare_environment_use(dir.path(), "prod").unwrap();
        let selector = dir.path().join(".phantom/env");
        let moved = dir.path().join(".phantom/env.reviewed");
        std::fs::rename(&selector, &moved).unwrap();
        std::fs::write(&selector, b"dev\n").unwrap();
        let response = format!("{}\n", plan.challenge);
        let error = apply_environment_use(
            &plan,
            true,
            &mut std::io::Cursor::new(response),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("atomically update"));
        assert_eq!(std::fs::read_to_string(selector).unwrap(), "dev\n");
        assert_eq!(std::fs::read_to_string(moved).unwrap(), "dev\n");
    }

    #[cfg(unix)]
    #[test]
    fn environment_use_rejects_byte_identical_root_decoy() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("project");
        let moved = dir.path().join("reviewed-project");
        std::fs::create_dir(&original).unwrap();
        PhantomConfig::new_with_defaults("portable-env-use-root".to_string())
            .save(&original.join(".phantom.toml"))
            .unwrap();
        let plan = prepare_environment_use(&original, "prod").unwrap();
        let config_before = plan.config_before.bytes().to_vec();
        let response = format!("{}\n", plan.challenge);

        let error = apply_environment_use_with(
            &plan,
            true,
            &mut std::io::Cursor::new(response),
            &mut Vec::new(),
            || {
                std::fs::rename(&original, &moved).unwrap();
                std::fs::create_dir(&original).unwrap();
                std::fs::write(original.join(".phantom.toml"), &config_before).unwrap();
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("project root was replaced"));
        assert!(!moved.join(".phantom/env").exists());
        assert!(!original.join(".phantom/env").exists());
        assert_eq!(
            std::fs::read(original.join(".phantom.toml")).unwrap(),
            config_before
        );
    }

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
        let inner = FileVault::new(
            &crate::test_support::canonical_tempdir_path(&dir),
            "env-copy",
            "passphrase".to_string(),
        )
        .unwrap();
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
