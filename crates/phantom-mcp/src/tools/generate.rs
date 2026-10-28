use anyhow::{Context, Result};
use phantom_core::{config::PhantomConfig, dotenv::DotenvFile, token::TokenMap};
use phantom_vault::{InitFile, InitSecret, VaultBackend};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// The only public output of secret generation. Never includes a value or mapping.
#[derive(serde::Serialize)]
pub struct GenerationReceipt {
    pub name: String,
    pub fingerprint: String,
}

/// Create only, using exact-before config, dotenv and vault CAS in one transaction.
/// Callers enforce their CLI inventory / MCP effect and approval boundaries first.
pub fn generate_secret(
    project: &Path,
    vault: &dyn VaultBackend,
    config_before: &[u8],
    name: &str,
) -> Result<GenerationReceipt> {
    let mut chars = name.bytes();
    anyhow::ensure!(
        matches!(chars.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_'),
        "Invalid secret name"
    );
    let config_path = project.join(".phantom.toml");
    let mut config = PhantomConfig::load_from_bytes(&config_path, config_before)?;
    let names = vault.list()?;
    anyhow::ensure!(
        !names.iter().any(|held| held == name),
        "Secret name already protected; refusing replacement"
    );
    let resolved = phantom_core::managed_dotenv::resolve_dotenv(project, &config, &names)?;
    let before = phantom_core::fs::read_regular_file(&resolved.path)?;
    let source = Zeroizing::new(
        String::from_utf8(before.clone().unwrap_or_default())
            .context("Managed dotenv is not UTF-8")?,
    );
    let dotenv = DotenvFile::parse_str(&source);
    dotenv.validate_for_mutation()?;
    // Refuse unmanaged ownership as well; generation must never overwrite it.
    anyhow::ensure!(
        !dotenv.entries().iter().any(|entry| entry.key == name),
        "Secret name already present in managed dotenv; refusing replacement"
    );
    // A pending value-free request reserves the placeholder this fulfillment
    // installs, exactly as `phantom add` does for prompted values.
    let request_placeholder = config
        .requests
        .get(name)
        .map(|request| request.placeholder.clone());
    let mut mappings = TokenMap::new();
    if let Some(placeholder) = request_placeholder {
        anyhow::ensure!(
            placeholder.len() == 68
                && placeholder.starts_with("phm_")
                && placeholder[4..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "Invalid request placeholder; refusing fulfillment"
        );
        let token = phantom_core::token::PhantomToken::parse(&placeholder)
            .context("Invalid request placeholder; refusing fulfillment")?;
        mappings.insert_with_token(name.to_owned(), token);
    } else {
        mappings.insert(name.to_owned());
    }
    let (after, mut originals) = dotenv.upsert_with_phantoms(&mappings)?;
    for value in originals.values_mut() {
        value.zeroize();
    }
    anyhow::ensure!(
        !config.phantom.secrets.contains_key(name),
        "Secret name already has lifecycle ownership; refusing replacement"
    );
    let fulfilled_request = if let Some(request) = config.requests.get_mut(name) {
        request.status = phantom_core::config::RequestStatus::Fulfilled;
        true
    } else {
        false
    };
    let config_after =
        if fulfilled_request || (config.phantom.dotenv_path.is_none() && names.is_empty()) {
            config.phantom.dotenv_path = Some(phantom_core::managed_dotenv::dotenv_basename(
                project,
                &resolved.path,
            )?);
            toml::to_string_pretty(&config)?.into_bytes()
        } else {
            config_before.to_vec()
        };
    let mut entropy = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(entropy.as_mut())
        .map_err(|_| anyhow::anyhow!("OS random source unavailable; nothing stored"))?;
    let value = Zeroizing::new(hex::encode(entropy.as_ref()));
    let fingerprint = format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())));
    phantom_vault::commit_init(
        project,
        vault,
        vec![InitSecret::replace_if_unchanged(
            name,
            None::<String>,
            value.as_str(),
        )],
        vec![
            InitFile::replace_if_unchanged(
                &config_path,
                Some(config_before.to_vec()),
                config_after,
            ),
            InitFile::replace_if_unchanged(&resolved.path, before, after.into_bytes())
                .commit_last(),
        ],
    )?;
    Ok(GenerationReceipt {
        name: name.to_owned(),
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use phantom_vault::file::FileVault;

    #[test]
    fn receipt_has_no_value_and_matches_stored_random_secret() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().canonicalize().unwrap();
        let path = project.join(".phantom.toml");
        PhantomConfig::new_with_defaults("generation-test".to_owned())
            .save(&path)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let vault = FileVault::new(
            &project,
            "generation-test",
            "test-only-passphrase".to_owned(),
        )
        .unwrap();
        let first = generate_secret(&project, &vault, &before, "GENERATED_KEY").unwrap();
        let value = vault.retrieve("GENERATED_KEY").unwrap();
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let output = serde_json::to_string(&first).unwrap();
        assert!(
            !output.contains(value.as_str()),
            "receipt leaked generated value"
        );
        assert!(!output.contains("phm_"), "receipt leaked mapping");
        assert_eq!(
            first.fingerprint,
            format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
        );
        let after = std::fs::read(&path).unwrap();
        assert!(generate_secret(&project, &vault, &after, "GENERATED_KEY").is_err());
        assert!(vault.retrieve("GENERATED_KEY").unwrap().as_str() == value.as_str());
        let second = generate_secret(&project, &vault, &after, "SECOND_KEY").unwrap();
        assert_ne!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn generation_fulfills_pending_request_with_its_reserved_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().canonicalize().unwrap();
        let path = project.join(".phantom.toml");
        let mut config = PhantomConfig::new_with_defaults("generation-test".to_owned());
        let placeholder = phantom_core::token::PhantomToken::generate()
            .as_str()
            .to_owned();
        config.requests.insert(
            "REQUESTED_KEY".to_owned(),
            phantom_core::config::SecretRequest {
                purpose: "test-only request".to_owned(),
                route: None,
                placeholder: placeholder.clone(),
                status: phantom_core::config::RequestStatus::Pending,
            },
        );
        config.save(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let vault = FileVault::new(
            &project,
            "generation-test",
            "test-only-passphrase".to_owned(),
        )
        .unwrap();
        let receipt = generate_secret(&project, &vault, &before, "REQUESTED_KEY").unwrap();
        assert!(vault.retrieve("REQUESTED_KEY").is_ok());
        assert!(!serde_json::to_string(&receipt)
            .unwrap()
            .contains(&placeholder));
        let dotenv = std::fs::read_to_string(project.join(".env")).unwrap();
        assert!(dotenv.contains(&placeholder));
        let persisted = PhantomConfig::load(&path).unwrap();
        assert_eq!(
            persisted.requests["REQUESTED_KEY"].status,
            phantom_core::config::RequestStatus::Fulfilled
        );
    }

    #[test]
    fn rejects_invalid_dotenv_ownership_and_config_drift_without_storing() {
        for content in ["BROKEN\n", "NEW_KEY=owned\n", ""] {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().canonicalize().unwrap();
            let path = project.join(".phantom.toml");
            PhantomConfig::new_with_defaults("generation-test".to_owned())
                .save(&path)
                .unwrap();
            let before = std::fs::read(&path).unwrap();
            let vault = FileVault::new(
                &project,
                "generation-test",
                "test-only-passphrase".to_owned(),
            )
            .unwrap();
            std::fs::write(project.join(".env"), content).unwrap();
            if content.is_empty() {
                std::fs::write(&path, b"# drift\n").unwrap();
            }
            assert!(generate_secret(&project, &vault, &before, "NEW_KEY").is_err());
            assert!(vault.list().unwrap().is_empty());
            assert_eq!(
                std::fs::read_to_string(project.join(".env")).unwrap(),
                content
            );
        }
    }
}
