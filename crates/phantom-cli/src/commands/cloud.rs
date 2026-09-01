use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use colored::Colorize;
use phantom_core::{auth, cloud, config::PhantomConfig};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

pub fn run_push() -> Result<()> {
    let config = PhantomConfig::load(std::path::Path::new(".phantom.toml"))
        .context("No .phantom.toml found. Run `phantom init` first.")?;
    ensure_cloud_push_allowed(&config)?;
    // Refuse an unreconciled push before reading cloud credentials.
    let api_base = auth::api_base_url()?;
    let token = auth::require_token()?;

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let secret_names = vault.list()?;

    if secret_names.is_empty() {
        println!("{}  No secrets to push", "warn".yellow().bold());
        return Ok(());
    }

    phantom_core::audit::log_result("cloud.push", None)
        .context("Failed to write audit event for cloud push")?;

    // Collect all secrets into a BTreeMap (sorted for deterministic encryption)
    let mut secrets = BTreeMap::new();
    for name in &secret_names {
        let value = vault.retrieve(name)?;
        secrets.insert(name.clone(), String::from(value.as_str()));
    }

    let serialize_result = serde_json::to_string(&secrets);
    for value in secrets.values_mut() {
        value.zeroize();
    }
    let plaintext = Zeroizing::new(serialize_result.context("Failed to serialize secrets")?);

    // Encrypt with cloud passphrase (stored in keychain, never transmitted)
    let passphrase =
        auth::get_or_create_cloud_passphrase().context("Failed to access cloud encryption key")?;
    let encrypted = phantom_vault::crypto::encrypt(plaintext.as_bytes(), &passphrase)?;
    let blob_b64 = BASE64.encode(&encrypted);

    let expected_version = config.cloud.as_ref().map(|c| c.version).unwrap_or(0);

    println!(
        "{}  Encrypting {} secret(s) client-side...",
        "->".blue().bold(),
        secret_names.len()
    );

    let rt = tokio::runtime::Runtime::new()?;
    let new_version = rt.block_on(cloud::push(
        &api_base,
        &token,
        config.portable_project_id(),
        &blob_b64,
        expected_version,
    ))?;

    // Update local version in config
    let mut config = config;
    record_cloud_push_success(&mut config, new_version);
    config
        .save(std::path::Path::new(".phantom.toml"))
        .with_context(|| {
            format!(
                "Cloud push succeeded remotely at version {new_version}, but local sync metadata could not be saved. Do not retry automatically: reconcile the remote version and local .phantom.toml first"
            )
        })?;

    println!(
        "{}  {} secret(s) synced to cloud (v{})",
        "ok".green().bold(),
        secret_names.len(),
        new_version
    );

    Ok(())
}

pub fn run_pull(force: bool) -> Result<()> {
    let api_base = auth::api_base_url()?;
    let token = auth::require_token()?;

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = std::fs::read(&config_path)
        .context("Failed to snapshot .phantom.toml before cloud pull")?;
    let config = PhantomConfig::load(&config_path)
        .context("No .phantom.toml found. Run `phantom init` first.")?;

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;

    println!("{}  Pulling from Phantom Cloud...", "->".blue().bold());

    phantom_core::audit::log_result("cloud.pull", None)
        .context("Failed to write audit event for cloud pull")?;

    let rt = tokio::runtime::Runtime::new()?;
    let pull_result = rt.block_on(cloud::pull(&api_base, &token, config.portable_project_id()))?;

    let pull_data = match pull_result {
        Some(data) => data,
        None => {
            println!(
                "{}  No cloud vault found for this project. Run `phantom cloud push` first.",
                "warn".yellow().bold()
            );
            return Ok(());
        }
    };

    // Decrypt the blob
    let passphrase =
        auth::get_or_create_cloud_passphrase().context("Failed to access cloud encryption key")?;
    let encrypted = BASE64
        .decode(&pull_data.encrypted_blob)
        .context("Invalid cloud vault data")?;
    let plaintext = Zeroizing::new(phantom_vault::crypto::decrypt(&encrypted, &passphrase)?);
    let secrets = SensitiveCloudSecrets::parse_json(&plaintext)
        .context("Failed to parse cloud vault data")?;

    let (added, skipped) = apply_cloud_pull_transaction(
        &project_dir,
        &config_path,
        config,
        config_before,
        vault.as_ref(),
        &secrets,
        force,
        pull_data.version,
    )?;

    if skipped > 0 {
        println!(
            "{}  Partial reconciliation: {} secret(s) restored, {} skipped. The prior cloud merge base was retained and push is blocked until `phantom cloud pull --force` fully reconciles remote version {}.",
            "warn".yellow().bold(),
            added,
            skipped,
            pull_data.version
        );
    } else {
        println!(
            "{}  {} secret(s) restored from cloud (v{})",
            "ok".green().bold(),
            added,
            pull_data.version
        );
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct ParsedCloudSecret(String);

impl ParsedCloudSecret {
    fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl Drop for ParsedCloudSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct SensitiveCloudSecrets(BTreeMap<String, Zeroizing<String>>);

impl SensitiveCloudSecrets {
    fn parse_json(bytes: &[u8]) -> serde_json::Result<Self> {
        let parsed: BTreeMap<String, ParsedCloudSecret> = serde_json::from_slice(bytes)?;
        Ok(Self(
            parsed
                .into_iter()
                .map(|(name, value)| (name, value.into_zeroizing()))
                .collect(),
        ))
    }
}

impl Drop for SensitiveCloudSecrets {
    fn drop(&mut self) {
        self.0.clear();
    }
}

fn ensure_cloud_push_allowed(config: &PhantomConfig) -> Result<()> {
    if config
        .cloud
        .as_ref()
        .is_some_and(|cloud| cloud.reconciliation_required)
    {
        anyhow::bail!(
            "Cloud push is blocked because the last pull was only partially reconciled. Run `phantom cloud pull --force` (or otherwise fully reconcile every remote secret) before pushing. Do not retry push automatically."
        );
    }
    Ok(())
}

fn record_cloud_push_success(config: &mut PhantomConfig, version: u64) {
    let cloud = config.cloud.get_or_insert_default();
    cloud.version = version;
    cloud.reconciliation_required = false;
    cloud.reconciliation_remote_version = None;
}

#[allow(clippy::too_many_arguments)]
fn apply_cloud_pull_transaction(
    project_dir: &std::path::Path,
    config_path: &std::path::Path,
    mut config: PhantomConfig,
    config_before: Vec<u8>,
    vault: &dyn phantom_vault::VaultBackend,
    secrets: &SensitiveCloudSecrets,
    force: bool,
    remote_version: u64,
) -> Result<(usize, usize)> {
    let mut mutations = Vec::new();
    let mut skipped = 0usize;
    for (name, value) in &secrets.0 {
        let before = match vault.retrieve(name) {
            Ok(value) => Some(value),
            Err(phantom_core::error::PhantomError::SecretNotFound(_)) => None,
            Err(error) => {
                anyhow::bail!("Failed to inspect local cloud-pull destination '{name}': {error}")
            }
        };
        if before.is_some() && !force {
            skipped += 1;
            continue;
        }
        mutations.push(phantom_vault::InitSecret::replace_if_unchanged(
            name,
            before.as_ref().map(|value| value.as_str().to_string()),
            value.as_str(),
        ));
    }

    update_cloud_reconciliation(&mut config, remote_version, skipped);
    let config_after = toml::to_string_pretty(&config)
        .context("Failed to serialize cloud reconciliation state")?
        .into_bytes();
    let added = mutations.len();
    phantom_vault::commit_init(
        project_dir,
        vault,
        mutations,
        vec![phantom_vault::InitFile::replace_if_unchanged(
            config_path,
            Some(config_before),
            config_after,
        )],
    )
    .context("Cloud pull transaction failed")?;
    Ok((added, skipped))
}

fn update_cloud_reconciliation(config: &mut PhantomConfig, remote_version: u64, skipped: usize) {
    let cloud = config.cloud.get_or_insert_default();
    if skipped == 0 {
        cloud.version = remote_version;
        cloud.reconciliation_required = false;
        cloud.reconciliation_remote_version = None;
    } else {
        // Keep the prior merge base. Advancing it after a partial apply would
        // permit a later push to destructively omit the skipped remote values.
        cloud.reconciliation_required = true;
        cloud.reconciliation_remote_version = Some(remote_version);
    }
}

pub fn run_status() -> Result<()> {
    let api_base = auth::api_base_url()?;

    match auth::load_token() {
        Some(token) => {
            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(auth::get_user_info(&api_base, &token)) {
                Ok(user) => {
                    println!(
                        "{}  Cloud: logged in as @{} ({})",
                        "ok".green().bold(),
                        user.github_login,
                        user.plan
                    );
                    if let Some(count) = user.vaults_count {
                        println!("   Vaults: {count}");
                    }
                }
                Err(_) => {
                    println!(
                        "{}  Cloud: token expired — run `phantom login`",
                        "warn".yellow().bold()
                    );
                }
            }
        }
        None => {
            println!(
                "{}  Cloud: not logged in — run `phantom login`",
                "->".blue().bold()
            );
        }
    }

    // Show local cloud config if it exists
    if let Ok(config) = PhantomConfig::load(std::path::Path::new(".phantom.toml")) {
        if let Some(cloud) = &config.cloud {
            println!("   Last synced version: {}", cloud.version);
            if cloud.reconciliation_required {
                let remote = cloud
                    .reconciliation_remote_version
                    .map_or_else(|| "unknown".to_string(), |version| version.to_string());
                println!(
                    "{}  Partial reconciliation with remote version {remote}; cloud push is blocked until every remote secret is reconciled.",
                    "warn".yellow().bold()
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_vault::VaultBackend;
    use tempfile::TempDir;

    fn cloud_test_config(version: u64) -> PhantomConfig {
        let mut config = PhantomConfig::new_with_defaults("cloud-test-project".to_string());
        config.cloud.get_or_insert_default().version = version;
        config
    }

    fn write_config(path: &std::path::Path, config: &PhantomConfig) -> Vec<u8> {
        let bytes = toml::to_string_pretty(config).unwrap().into_bytes();
        std::fs::write(path, &bytes).unwrap();
        bytes
    }

    fn sensitive(entries: &[(&str, &str)]) -> SensitiveCloudSecrets {
        SensitiveCloudSecrets(
            entries
                .iter()
                .map(|(name, value)| ((*name).to_string(), Zeroizing::new((*value).to_string())))
                .collect(),
        )
    }

    fn file_vault(dir: &TempDir, project: &str) -> phantom_vault::file::FileVault {
        phantom_vault::file::FileVault::new(dir.path(), project, "passphrase".to_string()).unwrap()
    }

    #[test]
    fn mixed_pull_preserves_base_and_blocks_push() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = cloud_test_config(3);
        let before = write_config(&config_path, &config);
        let vault = file_vault(&dir, "cli-cloud-mixed");
        vault.store("EXISTING", "local-owner").unwrap();

        assert_eq!(
            apply_cloud_pull_transaction(
                dir.path(),
                &config_path,
                config,
                before,
                &vault,
                &sensitive(&[("EXISTING", "remote"), ("NEW", "new")]),
                false,
                9,
            )
            .unwrap(),
            (1, 1)
        );
        assert_eq!(vault.retrieve("EXISTING").unwrap().as_str(), "local-owner");
        assert_eq!(vault.retrieve("NEW").unwrap().as_str(), "new");
        let persisted = PhantomConfig::load(&config_path).unwrap();
        let cloud = persisted.cloud.as_ref().unwrap();
        assert_eq!(cloud.version, 3);
        assert!(cloud.reconciliation_required);
        assert_eq!(cloud.reconciliation_remote_version, Some(9));
        assert!(ensure_cloud_push_allowed(&persisted).is_err());
    }

    #[test]
    fn all_skipped_pull_preserves_base_and_blocks_push() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = cloud_test_config(4);
        let before = write_config(&config_path, &config);
        let vault = file_vault(&dir, "cli-cloud-skipped");
        vault.store("EXISTING", "local-owner").unwrap();

        assert_eq!(
            apply_cloud_pull_transaction(
                dir.path(),
                &config_path,
                config,
                before,
                &vault,
                &sensitive(&[("EXISTING", "remote")]),
                false,
                10,
            )
            .unwrap(),
            (0, 1)
        );
        let persisted = PhantomConfig::load(&config_path).unwrap();
        let cloud = persisted.cloud.as_ref().unwrap();
        assert_eq!(cloud.version, 4);
        assert!(cloud.reconciliation_required);
        assert_eq!(cloud.reconciliation_remote_version, Some(10));
        assert!(ensure_cloud_push_allowed(&persisted).is_err());
    }

    #[test]
    fn complete_pull_advances_base_and_unblocks_push() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let mut config = cloud_test_config(4);
        let cloud = config.cloud.get_or_insert_default();
        cloud.reconciliation_required = true;
        cloud.reconciliation_remote_version = Some(8);
        let before = write_config(&config_path, &config);
        let vault = file_vault(&dir, "cli-cloud-complete");

        assert_eq!(
            apply_cloud_pull_transaction(
                dir.path(),
                &config_path,
                config,
                before,
                &vault,
                &sensitive(&[("NEW", "new")]),
                true,
                11,
            )
            .unwrap(),
            (1, 0)
        );
        let persisted = PhantomConfig::load(&config_path).unwrap();
        let cloud = persisted.cloud.as_ref().unwrap();
        assert_eq!(cloud.version, 11);
        assert!(!cloud.reconciliation_required);
        assert_eq!(cloud.reconciliation_remote_version, None);
        ensure_cloud_push_allowed(&persisted).unwrap();
    }

    #[test]
    fn successful_push_clears_stale_reconciliation_marker() {
        let mut config = cloud_test_config(4);
        let cloud = config.cloud.get_or_insert_default();
        cloud.reconciliation_required = true;
        cloud.reconciliation_remote_version = Some(8);

        record_cloud_push_success(&mut config, 12);

        let cloud = config.cloud.as_ref().unwrap();
        assert_eq!(cloud.version, 12);
        assert!(!cloud.reconciliation_required);
        assert_eq!(cloud.reconciliation_remote_version, None);
    }
}
