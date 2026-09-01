use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::error::PhantomError;
use phantom_core::sync::{self, Platform};
use phantom_core::token::TokenMap;
use phantom_vault::{InitFile, InitSecret, VaultBackend};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroizing;

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
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let env_path = project_dir.join(".env");

    let platform: Platform = from.parse().context("Invalid platform")?;

    // Determine API token
    let token_env = match platform {
        Platform::Vercel => "VERCEL_TOKEN",
        Platform::Railway => "RAILWAY_TOKEN",
    };
    let token = std::env::var(token_env).context(format!(
        "{token_env} not set. Export your {platform} API token."
    ))?;

    println!(
        "{} Pulling secrets from {} (project: {})...",
        "->".blue().bold(),
        platform.to_string().cyan().bold(),
        project.dimmed()
    );

    // Pull secrets from platform
    let pulled = match platform {
        Platform::Vercel => sync::pull_from_vercel(&token, project)
            .await
            .map_err(|e| anyhow::anyhow!("Vercel pull failed: {e}"))?,
        Platform::Railway => {
            let env_id = environment.as_deref().unwrap_or("production");
            sync::pull_from_railway(&token, project, env_id, service.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("Railway pull failed: {e}"))?
        }
    };

    if pulled.is_empty() {
        println!("{} No secrets found on {}.", "!".yellow().bold(), platform);
        return Ok(());
    }

    println!(
        "{} Found {} secret(s) on {}",
        "ok".green().bold(),
        pulled.len(),
        platform
    );

    // Load or create config
    let project_id = PhantomConfig::project_id_from_path(&project_dir);
    let config = if config_path.exists() {
        PhantomConfig::load(&config_path)?
    } else {
        PhantomConfig::new_with_defaults(project_id.clone())
    };

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let counts = apply_platform_pull_transaction(
        &project_dir,
        &config_path,
        &env_path,
        vault.as_ref(),
        &config,
        &pulled,
        force,
    )?;

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

    println!();
    println!(
        "{} Pull complete: {} new, {} updated, {} skipped",
        "ok".green().bold(),
        new_count,
        updated_count,
        skipped_count
    );

    if new_count > 0 || updated_count > 0 {
        println!(
            "{} .env updated with phantom tokens. Real values in vault.",
            "ok".green().bold()
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
    config: &PhantomConfig,
    pulled: &BTreeMap<String, String>,
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
            value,
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
        let env_before = snapshot_regular_file(env_path)?;
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
        let config_before = snapshot_regular_file(config_path)?;
        let config_after = match config_before.as_ref() {
            Some(bytes) => bytes.clone(),
            None => toml::to_string_pretty(config)
                .context("Failed to serialize .phantom.toml")?
                .into_bytes(),
        };
        files.push(InitFile::replace_if_unchanged(
            config_path,
            config_before,
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
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            anyhow::bail!(
                "Refusing to rewrite {}: target must be a regular file or absent",
                path.display()
            )
        }
        Ok(_) => Ok(Some(std::fs::read(path).with_context(|| {
            format!("Failed to snapshot {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use zeroize::Zeroizing;

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
        let pulled = BTreeMap::from([("NEW_SECRET".to_string(), "provider-value".to_string())]);

        let error = apply_platform_pull_transaction(
            dir.path(),
            &config_path,
            &env_path,
            &vault,
            &config,
            &pulled,
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("target must be a regular file"));
        assert!(!vault.exists("NEW_SECRET").unwrap());
        assert_eq!(std::fs::read(&outside).unwrap(), b"OWNER=unchanged\n");
    }
}
