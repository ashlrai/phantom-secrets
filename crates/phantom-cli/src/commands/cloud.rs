use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use colored::Colorize;
use phantom_core::{auth, cloud, config::PhantomConfig};
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub fn run_push() -> Result<()> {
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let (config_path, config_before, config) = load_cloud_config_exact(&project_dir)?;
    ensure_cloud_push_allowed(&config)?;
    require_trusted_terminal_cloud(&cloud_consent_plan("push", &project_dir, &config, false)?)?;
    // Refuse an unreconciled push and require terminal consent before reading
    // cloud credentials or any vault value.
    let api_base = auth::api_base_url()?;
    let token = Zeroizing::new(auth::require_token()?);

    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let mut secret_names = vault.list()?;
    secret_names.sort();

    if secret_names.is_empty() {
        println!("{}  No secrets to push", "warn".yellow().bold());
        return Ok(());
    }

    phantom_core::audit::log_result("cloud.push", None)
        .context("Failed to write audit event for cloud push")?;

    // Collect all secrets into a BTreeMap (sorted for deterministic encryption)
    let mut secrets = BTreeMap::new();
    let mut guards = Vec::with_capacity(secret_names.len());
    for name in &secret_names {
        let value = vault.retrieve(name)?;
        guards.push(phantom_vault::InitSecret::replace_if_unchanged(
            name,
            Some(value.as_str().to_string()),
            value.as_str(),
        ));
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
    let new_version = rt
        .block_on(cloud::push(
            &api_base,
            &token,
            config.portable_project_id(),
            &blob_b64,
            expected_version,
        ))
        .context(
            "Cloud push did not return a success receipt; the remote outcome is unknown. Do not retry automatically until remote state is inspected",
        )?;

    // Update local version only if the exact config and every exported vault
    // value are still owned by this transaction. The remote write cannot be
    // rolled back, so any local reconciliation failure is explicit partial
    // success and must never be retried automatically.
    let mut current_names = vault.list().with_context(|| {
        format!(
            "Cloud push succeeded remotely at version {new_version}, but the local vault name set could not be verified. Do not retry automatically; reconcile remote and local state first"
        )
    })?;
    current_names.sort();
    if current_names != secret_names {
        anyhow::bail!(
            "Cloud push succeeded remotely at version {new_version}, but the local vault name set changed before reconciliation. Do not retry automatically; reconcile the remote version and local vault first"
        );
    }
    let mut config = config;
    record_cloud_push_success(&mut config, new_version);
    let config_after = toml::to_string_pretty(&config)
        .with_context(|| {
            format!(
                "Cloud push succeeded remotely at version {new_version}, but local reconciliation metadata could not be serialized. Do not retry automatically"
            )
        })?
        .into_bytes();
    phantom_vault::commit_init(
        &project_dir,
        vault.as_ref(),
        guards,
        vec![phantom_vault::InitFile::replace_if_unchanged(
            &config_path,
            Some(config_before),
            config_after,
        )],
    )
    .with_context(|| {
        format!(
            "Cloud push succeeded remotely at version {new_version}, but exact local reconciliation failed. Do not retry automatically: reconcile the remote version, local vault, and .phantom.toml first"
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
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let (config_path, config_before, config) = load_cloud_config_exact(&project_dir)?;
    require_trusted_terminal_cloud(&cloud_consent_plan("pull", &project_dir, &config, force)?)?;
    let api_base = auth::api_base_url()?;
    let token = Zeroizing::new(auth::require_token()?);

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

#[derive(Debug, PartialEq, Eq)]
struct CloudConsentPlan {
    effect: String,
    challenge: String,
}

fn cloud_consent_plan(
    action: &str,
    project_dir: &Path,
    config: &PhantomConfig,
    force: bool,
) -> Result<CloudConsentPlan> {
    let project = config.portable_project_id();
    if project.is_empty() || project.len() > 256 || project.chars().any(char::is_control) {
        anyhow::bail!(
            "Cloud project identifiers must be non-empty, bounded, and contain no control characters"
        );
    }
    let reviewed_project =
        serde_json::to_string(project).context("Failed to encode the cloud consent challenge")?;
    let path = project_dir.to_string_lossy();
    if path.is_empty() || path.len() > 1024 || path.chars().any(char::is_control) {
        anyhow::bail!(
            "Cloud project paths must be non-empty, bounded, and contain no control characters"
        );
    }
    let reviewed_path =
        serde_json::to_string(path.as_ref()).context("Failed to encode cloud project path")?;
    Ok(match action {
        "push" => CloudConsentPlan {
            effect: format!(
                "encrypt every local vault value from {reviewed_path} and overwrite the authenticated cloud vault for project {reviewed_project}"
            ),
            challenge: format!("cloud push {reviewed_project} from {reviewed_path}"),
        },
        "pull" => CloudConsentPlan {
            effect: format!(
                "download, decrypt, and transactionally write the cloud vault for project {reviewed_project} into {reviewed_path}; force={force}"
            ),
            challenge: format!("cloud pull {reviewed_project} into {reviewed_path} force={force}"),
        },
        _ => unreachable!("closed cloud action"),
    })
}

fn require_trusted_terminal_cloud(plan: &CloudConsentPlan) -> Result<()> {
    let attached = std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal();
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    confirm_cloud_effect(plan, attached, &mut stdin.lock(), &mut stderr.lock())
}

fn confirm_cloud_effect(
    plan: &CloudConsentPlan,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    if !attached {
        anyhow::bail!(
            "Cloud vault effects require stdin, stdout, and stderr attached to a trusted terminal before credential, vault-value, or network access"
        );
    }
    writeln!(writer, "Cloud effect: {}", plan.effect)?;
    writeln!(
        writer,
        "Approve only if this terminal is outside the requesting agent's authority; a same-user shell or agent-controlled PTY can automate this ceremony."
    )?;
    write!(writer, "Type `{}` to continue: ", plan.challenge)?;
    writer.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim() != plan.challenge {
        anyhow::bail!("Cloud effect cancelled: typed confirmation did not match");
    }
    Ok(())
}

fn load_cloud_config_exact(project_dir: &Path) -> Result<(PathBuf, Vec<u8>, PhantomConfig)> {
    let path = project_dir.join(".phantom.toml");
    let before = phantom_core::fs::read_regular_file(&path)
        .context("Failed to safely read .phantom.toml")?
        .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run `phantom init` first."))?;
    let config = PhantomConfig::load(&path).context("Failed to load .phantom.toml")?;
    if phantom_core::fs::read_regular_file(&path)
        .context("Failed to recheck .phantom.toml")?
        .as_deref()
        != Some(before.as_slice())
    {
        anyhow::bail!(
            ".phantom.toml changed during cloud preflight; no cloud effect was attempted"
        );
    }
    Ok((path, before, config))
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
    fn config_drift_blocks_cloud_pull_before_any_vault_write() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".phantom.toml");
        let config = cloud_test_config(4);
        let before = write_config(&config_path, &config);
        let concurrent = [before.as_slice(), b"\n# concurrent owner\n"].concat();
        std::fs::write(&config_path, &concurrent).unwrap();
        let vault = file_vault(&dir, "cli-cloud-config-drift");

        assert!(apply_cloud_pull_transaction(
            dir.path(),
            &config_path,
            config,
            before,
            &vault,
            &sensitive(&[("NEW", "new")]),
            true,
            11,
        )
        .is_err());
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent);
        assert!(matches!(
            vault.retrieve("NEW"),
            Err(phantom_core::error::PhantomError::SecretNotFound(_))
        ));
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

    #[test]
    fn cloud_consent_binds_project_action_and_force_policy() {
        let config = cloud_test_config(0);
        let path = Path::new("/reviewed/project");
        let push = cloud_consent_plan("push", path, &config, false).unwrap();
        let pull = cloud_consent_plan("pull", path, &config, true).unwrap();

        assert_eq!(
            push.challenge,
            "cloud push \"cloud-test-project\" from \"/reviewed/project\""
        );
        assert_eq!(
            pull.challenge,
            "cloud pull \"cloud-test-project\" into \"/reviewed/project\" force=true"
        );
        assert!(push.effect.contains("overwrite"));
        assert!(pull.effect.contains("transactionally write"));
    }

    #[test]
    fn headless_cloud_consent_fails_before_reading_confirmation() {
        let config = cloud_test_config(0);
        let plan =
            cloud_consent_plan("push", Path::new("/reviewed/project"), &config, false).unwrap();
        let mut reader = std::io::Cursor::new(plan.challenge.as_bytes());
        let mut output = Vec::new();

        let error = confirm_cloud_effect(&plan, false, &mut reader, &mut output).unwrap_err();
        assert!(error.to_string().contains("trusted terminal"));
        assert_eq!(reader.position(), 0);
        assert!(output.is_empty());
    }
}
