use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::error::PhantomError;
use phantom_core::sync::{self, Platform};
use phantom_core::token::TokenMap;
use phantom_vault::{InitFile, InitSecret, VaultBackend};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize)]
struct PullPlan {
    platform: String,
    provider_project: String,
    environment: Option<String>,
    service: Option<String>,
    force: bool,
    local_project: String,
    local_vault_id: String,
    config_sha256: String,
    managed_dotenv: String,
    managed_dotenv_sha256: String,
    token_env: String,
}

#[derive(Debug, Serialize)]
struct PullStageReceipt<'a> {
    mode: &'static str,
    plan_digest: &'a str,
    plan: &'a PullPlan,
    provider_fetch: &'static str,
    local_apply: &'static str,
    new_names: &'a [String],
    updated_names: &'a [String],
    skipped_names: &'a [String],
    fully_succeeded: bool,
}

pub fn run(
    from: &str,
    project: &str,
    environment: Option<String>,
    service: Option<String>,
    force: bool,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(from, project, environment, service, force))
}

async fn run_async(
    from: &str,
    project: &str,
    environment: Option<String>,
    service: Option<String>,
    force: bool,
) -> Result<()> {
    let project_dir = std::env::current_dir()?
        .canonicalize()
        .context("Failed to resolve the local project directory")?;
    let config_path = project_dir.join(".phantom.toml");

    let platform: Platform = from.parse().context("Invalid platform")?;
    let token_env = match platform {
        Platform::Vercel => "VERCEL_TOKEN",
        Platform::Railway => "RAILWAY_TOKEN",
    };

    let config_before = snapshot_regular_file(&config_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "No safe .phantom.toml found. Run `phantom init --empty` before provider pull."
        )
    })?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to parse the exact .phantom.toml snapshot")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let vault_names = vault.list().context("Failed to list local vault names")?;
    let env_path =
        phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)
            .context("Failed to resolve the managed dotenv for platform pull")?
            .path;
    let env_before = snapshot_regular_file(&env_path)?;
    let plan = PullPlan {
        platform: platform.to_string(),
        provider_project: project.to_string(),
        environment: environment.clone(),
        service: service.clone(),
        force,
        local_project: project_dir.display().to_string(),
        local_vault_id: config.local_project_id().to_string(),
        config_sha256: sha256_bytes(&config_before),
        managed_dotenv: phantom_core::managed_dotenv::dotenv_basename(&project_dir, &env_path)?,
        managed_dotenv_sha256: env_before
            .as_deref()
            .map(sha256_bytes)
            .unwrap_or_else(|| "absent".to_string()),
        token_env: token_env.to_string(),
    };
    let plan_digest = pull_plan_digest(&plan)?;
    require_trusted_terminal_pull(&plan)?;

    let token = Zeroizing::new(std::env::var(token_env).context(format!(
        "{token_env} not set. Export your {platform} API token."
    ))?);

    println!(
        "{} Pulling secrets from {} (project: {})...",
        "->".blue().bold(),
        platform.to_string().cyan().bold(),
        project.dimmed()
    );

    // Pull secrets from platform
    let pulled = match platform {
        Platform::Vercel => sync::pull_from_vercel(token.as_str(), project).await,
        Platform::Railway => {
            let env_id = environment.as_deref().unwrap_or("production");
            sync::pull_from_railway(token.as_str(), project, env_id, service.as_deref()).await
        }
    };
    let pulled = match pulled {
        Ok(pulled) => pulled,
        Err(error) => {
            let receipt = PullStageReceipt {
                mode: "live-pull",
                plan_digest: &plan_digest,
                plan: &plan,
                provider_fetch: "failed",
                local_apply: "not_started",
                new_names: &[],
                updated_names: &[],
                skipped_names: &[],
                fully_succeeded: false,
            };
            eprintln!("stage_receipt: {}", serde_json::to_string(&receipt)?);
            anyhow::bail!("Provider pull failed without local mutation: {error}");
        }
    };

    if pulled.is_empty() {
        let receipt = PullStageReceipt {
            mode: "live-pull",
            plan_digest: &plan_digest,
            plan: &plan,
            provider_fetch: "empty",
            local_apply: "not_started",
            new_names: &[],
            updated_names: &[],
            skipped_names: &[],
            fully_succeeded: false,
        };
        eprintln!("stage_receipt: {}", serde_json::to_string(&receipt)?);
        anyhow::bail!("Provider pull returned no secrets; no local mutation occurred.");
    }

    println!(
        "{} Found {} secret(s) on {}",
        "ok".green().bold(),
        pulled.len(),
        platform
    );

    let counts = match apply_platform_pull_transaction(
        &project_dir,
        &config_path,
        &env_path,
        vault.as_ref(),
        config_before,
        env_before,
        &pulled,
        force,
    ) {
        Ok(counts) => counts,
        Err(error) => {
            let receipt = PullStageReceipt {
                mode: "live-pull",
                plan_digest: &plan_digest,
                plan: &plan,
                provider_fetch: "succeeded",
                local_apply: "failed_rolled_back_where_verifiable",
                new_names: &[],
                updated_names: &[],
                skipped_names: &[],
                fully_succeeded: false,
            };
            eprintln!("stage_receipt: {}", serde_json::to_string(&receipt)?);
            return Err(error.context(
                "Provider plaintext was fetched, but the local transaction did not commit",
            ));
        }
    };

    for key in &counts.skipped_names {
        println!(
            "   {} {} (exists, use --force to overwrite)",
            "-".dimmed(),
            key
        );
    }
    for key in &counts.updated_names {
        println!("   {} {} (overwritten)", "~".blue(), key.bold());
    }
    for key in &counts.new_names {
        println!("   {} {} (new)", "+".green().bold(), key.bold());
    }

    let new_count = counts.new_names.len();
    let updated_count = counts.updated_names.len();
    let skipped_count = counts.skipped_names.len();

    let fully_succeeded = skipped_count == 0;
    let receipt = PullStageReceipt {
        mode: "live-pull",
        plan_digest: &plan_digest,
        plan: &plan,
        provider_fetch: "succeeded",
        local_apply: if fully_succeeded {
            "committed"
        } else {
            "committed_with_skips"
        },
        new_names: &counts.new_names,
        updated_names: &counts.updated_names,
        skipped_names: &counts.skipped_names,
        fully_succeeded,
    };
    eprintln!("stage_receipt: {}", serde_json::to_string(&receipt)?);

    if new_count > 0 || updated_count > 0 {
        println!(
            "{} {} updated with phantom tokens. Real values in vault.",
            "ok".green().bold(),
            env_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("managed dotenv")
        );
    }

    if !fully_succeeded {
        anyhow::bail!(
            "Provider pull only partially applied because existing local secrets were skipped. Successful local effects are recorded in the stage receipt; review before retrying with --force."
        );
    }
    println!();
    println!(
        "{} Pull complete: {} new, {} updated, 0 skipped",
        "ok".green().bold(),
        new_count,
        updated_count
    );
    Ok(())
}

fn pull_plan_digest(plan: &PullPlan) -> Result<String> {
    let canonical = serde_json::to_vec(plan).context("Could not serialize pull plan")?;
    let mut digest = Sha256::new();
    digest.update(b"phantom.live-pull.v1\0");
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn require_trusted_terminal_pull(plan: &PullPlan) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "Live `phantom pull` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. Only value-blind local destination state was inspected; no provider credential, provider plaintext, local mutation, or network endpoint was accessed."
        );
    }
    let mut nonce_bytes = [0_u8; 4];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let mut diagnostic = std::io::stderr();
    run_pull_confirmation(plan, &nonce, &mut input, &mut diagnostic)
}

fn run_pull_confirmation(
    plan: &PullPlan,
    nonce: &str,
    input: &mut impl BufRead,
    diagnostic: &mut impl Write,
) -> Result<()> {
    let digest = pull_plan_digest(plan)?;
    let expected = format!("PULL {digest} {nonce}");
    writeln!(diagnostic, "Phantom live provider pull")?;
    writeln!(
        diagnostic,
        "Exact value-blind plan:\n{}",
        serde_json::to_string_pretty(plan)?
    )?;
    writeln!(
        diagnostic,
        "This fetches provider plaintext and may create or overwrite local vault and managed-dotenv entries. Approve only from a terminal outside the requesting agent's authority."
    )?;
    writeln!(
        diagnostic,
        "Type this exact challenge to continue:\n{expected}"
    )?;
    write!(diagnostic, "> ")?;
    diagnostic.flush()?;
    let mut response = String::new();
    input
        .read_line(&mut response)
        .context("Failed to read trusted-terminal pull confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!(
            "Live pull confirmation did not match exactly. No provider credential, plaintext, or network endpoint was accessed."
        );
    }
    Ok(())
}

#[derive(Debug, Default)]
struct PullCounts {
    new_names: Vec<String>,
    updated_names: Vec<String>,
    skipped_names: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn apply_platform_pull_transaction(
    project_dir: &Path,
    config_path: &Path,
    env_path: &Path,
    vault: &dyn VaultBackend,
    config_before: Vec<u8>,
    env_before: Option<Vec<u8>>,
    pulled: &BTreeMap<String, Zeroizing<String>>,
    force: bool,
) -> Result<PullCounts> {
    let mut counts = PullCounts::default();
    let mut token_map = TokenMap::new();
    let mut mutations = Vec::new();

    for (key, value) in pulled {
        let before = snapshot_secret(vault, key)?;
        if before.is_some() && !force {
            counts.skipped_names.push(key.clone());
            continue;
        }
        mutations.push(InitSecret::replace_if_unchanged(
            key,
            before.as_ref().map(|value| value.as_str().to_string()),
            value.as_str(),
        ));
        token_map.insert(key.clone());
        if before.is_some() {
            counts.updated_names.push(key.clone());
        } else {
            counts.new_names.push(key.clone());
        }
    }

    let mut files = Vec::new();
    if !mutations.is_empty() {
        let mut env_content = match env_before.as_ref() {
            Some(bytes) => String::from_utf8(bytes.clone())
                .context("Existing .env is not valid UTF-8; refusing to rewrite it")?,
            None => String::new(),
        };

        for key in counts.new_names.iter().chain(counts.updated_names.iter()) {
            if let Some(token) = token_map.get_token(key) {
                let key_prefix = format!("{key}=");
                if env_content.lines().any(|l| l.starts_with(&key_prefix)) {
                    env_content = env_content
                        .lines()
                        .map(|line| {
                            if line.starts_with(&key_prefix) {
                                format!("{key}={token}")
                            } else {
                                line.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n";
                } else {
                    // Append new entry
                    if !env_content.is_empty() && !env_content.ends_with('\n') {
                        env_content.push('\n');
                    }
                    env_content.push_str(&format!("{key}={token}\n"));
                }
            }
        }
        files.push(
            InitFile::replace_if_unchanged(env_path, env_before, env_content.into_bytes())
                .commit_last(),
        );
    }

    if !mutations.is_empty() {
        let config_after = config_before.clone();
        files.push(InitFile::replace_if_unchanged(
            config_path,
            Some(config_before),
            config_after,
        ));
    }

    phantom_vault::commit_init(project_dir, vault, mutations, files)
        .context("Platform pull transaction failed")?;
    Ok(counts)
}

fn snapshot_secret(vault: &dyn VaultBackend, name: &str) -> Result<Option<Zeroizing<String>>> {
    match vault.retrieve(name) {
        Ok(value) => Ok(Some(value)),
        Err(PhantomError::SecretNotFound(_)) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "Failed to inspect destination secret '{name}' before platform pull: {error}"
        )),
    }
}

fn snapshot_regular_file(path: &Path) -> Result<Option<Vec<u8>>> {
    phantom_core::fs::read_regular_file(path)
        .with_context(|| format!("Failed to safely snapshot {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use std::io::Cursor;
    use zeroize::Zeroizing;

    fn plan() -> PullPlan {
        PullPlan {
            platform: "vercel".into(),
            provider_project: "provider-project".into(),
            environment: Some("production".into()),
            service: Some("api".into()),
            force: false,
            local_project: "/canonical/project".into(),
            local_vault_id: "local-vault".into(),
            config_sha256: "config-digest".into(),
            managed_dotenv: ".env".into(),
            managed_dotenv_sha256: "dotenv-digest".into(),
            token_env: "VERCEL_TOKEN".into(),
        }
    }

    #[test]
    fn pull_digest_binds_provider_and_local_effect_scope() {
        let original = plan();
        let digest = pull_plan_digest(&original).unwrap();
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.platform = "railway".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.provider_project = "other".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.environment = Some("preview".into());
        variants.push(changed);
        let mut changed = original.clone();
        changed.service = Some("worker".into());
        variants.push(changed);
        let mut changed = original.clone();
        changed.force = true;
        variants.push(changed);
        let mut changed = original.clone();
        changed.local_project = "/other/project".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.local_vault_id = "other-vault".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.config_sha256 = "other-config".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.managed_dotenv = ".env.local".into();
        variants.push(changed);
        let mut changed = original;
        changed.managed_dotenv_sha256 = "other-dotenv".into();
        variants.push(changed);
        for variant in variants {
            assert_ne!(digest, pull_plan_digest(&variant).unwrap());
        }
    }

    #[test]
    fn pull_requires_exact_digest_and_nonce() {
        let plan = plan();
        let digest = pull_plan_digest(&plan).unwrap();
        run_pull_confirmation(
            &plan,
            "fresh",
            &mut Cursor::new(format!("PULL {digest} fresh\n")),
            &mut Vec::new(),
        )
        .unwrap();
        let error = run_pull_confirmation(
            &plan,
            "fresh",
            &mut Cursor::new(format!("PULL {digest} stale\n")),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("did not match exactly"));
    }

    #[test]
    fn pull_confirmation_precedes_credential_and_provider_access() {
        let source = include_str!("pull.rs");
        let confirmation = source
            .find("require_trusted_terminal_pull(&plan)?")
            .unwrap();
        let credential = source.find("std::env::var(token_env)").unwrap();
        let provider = source.find("sync::pull_from_vercel(").unwrap();
        assert!(confirmation < credential);
        assert!(credential < provider);
    }

    #[test]
    fn noninteractive_pull_denies_before_effects() {
        if !std::io::stdin().is_terminal()
            || !std::io::stdout().is_terminal()
            || !std::io::stderr().is_terminal()
        {
            let error = require_trusted_terminal_pull(&plan()).unwrap_err();
            assert!(error.to_string().contains("cannot run headlessly"));
        }
    }

    struct ReadFailingVault;

    impl phantom_vault::VaultBackend for ReadFailingVault {
        fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
            panic!("store must not run after destination listing fails")
        }

        fn retrieve(&self, _name: &str) -> PhantomResult<Zeroizing<String>> {
            Err(PhantomError::VaultError(
                "injected platform-pull read failure".to_string(),
            ))
        }

        fn delete(&self, _name: &str) -> PhantomResult<()> {
            Ok(())
        }

        fn list(&self) -> PhantomResult<Vec<String>> {
            Ok(Vec::new())
        }

        fn backend_name(&self) -> &str {
            "read-failing"
        }
    }

    #[test]
    fn platform_pull_propagates_destination_read_errors() {
        let error = snapshot_secret(&ReadFailingVault, "TARGET")
            .expect_err("backend failure must not be interpreted as an absent secret");
        assert!(error
            .to_string()
            .contains("Failed to inspect destination secret 'TARGET'"));
        assert!(error
            .to_string()
            .contains("injected platform-pull read failure"));
    }

    #[cfg(unix)]
    #[test]
    fn platform_pull_rejects_dotenv_symlink_before_vault_mutation() {
        use phantom_vault::file::FileVault;
        use std::os::unix::fs::symlink;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let outside = dir.path().join("outside.env");
        std::fs::write(&outside, b"OWNER=unchanged\n").unwrap();
        let env_path = dir.path().join(".env");
        symlink(&outside, &env_path).unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = PhantomConfig::new_with_defaults("pull-symlink-test".to_string());
        let vault =
            FileVault::new(dir.path(), "pull-symlink-test", "passphrase".to_string()).unwrap();
        let pulled = BTreeMap::from([(
            "NEW_SECRET".to_string(),
            Zeroizing::new("provider-value".to_string()),
        )]);

        let error = apply_platform_pull_transaction(
            dir.path(),
            &config_path,
            &env_path,
            &vault,
            toml::to_string_pretty(&config).unwrap().into_bytes(),
            None,
            &pulled,
            false,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("Platform pull transaction failed"));
        assert!(!vault.exists("NEW_SECRET").unwrap());
        assert_eq!(std::fs::read(&outside).unwrap(), b"OWNER=unchanged\n");
    }

    #[test]
    fn platform_pull_rejects_config_drift_without_local_commit() {
        use phantom_vault::file::FileVault;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = PhantomConfig::new_with_defaults("pull-config-drift".to_string());
        let config_before = toml::to_string_pretty(&config).unwrap().into_bytes();
        std::fs::write(&config_path, &config_before).unwrap();
        std::fs::write(&config_path, b"[phantom]\nproject_id = \"changed\"\n").unwrap();
        let env_path = dir.path().join(".env");
        let vault =
            FileVault::new(dir.path(), "pull-config-drift", "passphrase".to_string()).unwrap();
        let pulled = BTreeMap::from([(
            "NEW_SECRET".to_string(),
            Zeroizing::new("provider-value".to_string()),
        )]);

        let error = apply_platform_pull_transaction(
            dir.path(),
            &config_path,
            &env_path,
            &vault,
            config_before,
            None,
            &pulled,
            false,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("Platform pull transaction failed"));
        assert!(!vault.exists("NEW_SECRET").unwrap());
        assert!(!env_path.exists());
    }

    #[test]
    fn platform_pull_rejects_dotenv_drift_without_local_commit() {
        use phantom_vault::file::FileVault;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = PhantomConfig::new_with_defaults("pull-env-drift".to_string());
        let config_before = toml::to_string_pretty(&config).unwrap().into_bytes();
        std::fs::write(&config_path, &config_before).unwrap();
        let env_path = dir.path().join(".env");
        let env_before = b"OWNER=before\n".to_vec();
        std::fs::write(&env_path, &env_before).unwrap();
        std::fs::write(&env_path, b"OWNER=concurrent\n").unwrap();
        let vault = FileVault::new(dir.path(), "pull-env-drift", "passphrase".to_string()).unwrap();
        let pulled = BTreeMap::from([(
            "NEW_SECRET".to_string(),
            Zeroizing::new("provider-value".to_string()),
        )]);

        let error = apply_platform_pull_transaction(
            dir.path(),
            &config_path,
            &env_path,
            &vault,
            config_before,
            Some(env_before),
            &pulled,
            false,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("Platform pull transaction failed"));
        assert!(!vault.exists("NEW_SECRET").unwrap());
        assert_eq!(std::fs::read(&env_path).unwrap(), b"OWNER=concurrent\n");
    }
}
