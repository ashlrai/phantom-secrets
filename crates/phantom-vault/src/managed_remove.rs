//! Exact-before removal of one vault entry and its project-owned mappings.

use crate::{commit_init, InitFile, InitReceipt, InitSecret, InitTransactionError, VaultBackend};
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::error::{PhantomError, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct ManagedRemovePlan {
    project_dir: PathBuf,
    name: String,
    config_path: PathBuf,
    config_before: Zeroizing<Vec<u8>>,
    config_after: Zeroizing<Vec<u8>>,
    dotenv_path: PathBuf,
    dotenv_before: Zeroizing<Vec<u8>>,
    dotenv_after: Zeroizing<Vec<u8>>,
    local_project_id: String,
}

impl ManagedRemovePlan {
    /// Prepare only from value-free project state and vault names. Plaintext
    /// retrieval is deliberately deferred until after terminal/MCP approval.
    pub fn prepare(
        project_dir: &Path,
        config_before: Vec<u8>,
        vault: &dyn VaultBackend,
        name: &str,
    ) -> Result<Self> {
        validate_managed_name(name)?;
        let project_dir = project_dir.canonicalize()?;
        let config_path = project_dir.join(".phantom.toml");
        if phantom_core::fs::read_regular_file(&config_path)?.as_deref()
            != Some(config_before.as_slice())
        {
            return Err(PhantomError::Other(
                ".phantom.toml changed before removal planning; no secret value was read"
                    .to_string(),
            ));
        }
        let mut config = PhantomConfig::load_from_bytes(&config_path, &config_before)?;
        let vault_names = vault.list()?;
        if !vault_names.iter().any(|candidate| candidate == name) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }

        let resolved =
            phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &vault_names)
                .map_err(|error| PhantomError::Other(error.to_string()))?;
        let dotenv_before = phantom_core::fs::read_regular_file(&resolved.path)?
            .ok_or_else(|| PhantomError::DotenvNotFound(resolved.path.display().to_string()))?;
        let dotenv_text = Zeroizing::new(
            std::str::from_utf8(&dotenv_before)
                .map_err(|error| PhantomError::DotenvParseError(error.to_string()))?
                .to_string(),
        );
        let dotenv = DotenvFile::parse_str(&dotenv_text);
        let dotenv_after = dotenv.remove_phantom_mapping(name, dotenv_text.ends_with('\n'))?;

        config.phantom.secrets.remove(name);
        let config_after = toml::to_string_pretty(&config)
            .map_err(|error| PhantomError::ConfigParseError(error.to_string()))?
            .into_bytes();
        let local_project_id = config.local_project_id().to_string();
        Ok(Self {
            project_dir,
            name: name.to_string(),
            config_path,
            config_before: Zeroizing::new(config_before),
            config_after: Zeroizing::new(config_after),
            dotenv_path: resolved.path,
            dotenv_before: Zeroizing::new(dotenv_before),
            dotenv_after: Zeroizing::new(dotenv_after.into_bytes()),
            local_project_id,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    pub fn dotenv_path(&self) -> &Path {
        &self.dotenv_path
    }

    pub fn local_project_id(&self) -> &str {
        &self.local_project_id
    }

    /// Value-free digest binding config and managed-dotenv exact before-images.
    pub fn before_digest(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"phantom-managed-remove-v1\0");
        digest.update(self.project_dir.as_os_str().as_encoded_bytes());
        digest.update(b"\0");
        digest.update(self.name.as_bytes());
        digest.update(b"\0");
        digest.update(&*self.config_before);
        digest.update(b"\0");
        digest.update(&*self.dotenv_before);
        hex::encode(digest.finalize())
    }

    /// Retrieve the value only after authority is established, then delete it
    /// with its exact mappings through one recoverable project transaction.
    pub fn commit(
        self,
        vault: &dyn VaultBackend,
    ) -> std::result::Result<InitReceipt, InitTransactionError> {
        let before = vault
            .retrieve(&self.name)
            .map_err(|_| InitTransactionError::Preflight {
                target: self.name.clone(),
                reason: "vault snapshot failed".to_string(),
            })?;
        let secret = InitSecret::delete_if_unchanged(&self.name, before.as_str());
        let files = vec![
            InitFile::replace_if_unchanged(
                self.config_path,
                Some(self.config_before.to_vec()),
                self.config_after.to_vec(),
            ),
            InitFile::replace_if_unchanged(
                self.dotenv_path,
                Some(self.dotenv_before.to_vec()),
                self.dotenv_after.to_vec(),
            )
            .commit_last(),
        ];
        commit_init(&self.project_dir, vault, vec![secret], files)
    }
}

fn validate_managed_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    if name.len() > 128
        || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(PhantomError::Other(
            "invalid managed secret name; expected a bounded environment variable name".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileVault;
    use phantom_core::token::PhantomToken;

    fn fixture() -> (tempfile::TempDir, FileVault, String) {
        let dir = tempfile::tempdir().unwrap();
        let project_id = PhantomConfig::project_id_from_path(dir.path());
        let mut config = PhantomConfig::new_with_defaults(project_id);
        config.phantom.dotenv_path = Some(".env".to_string());
        config
            .phantom
            .secrets
            .insert("API_KEY".to_string(), Default::default());
        phantom_core::fs::atomic_write(
            &dir.path().join(".phantom.toml"),
            toml::to_string_pretty(&config).unwrap().as_bytes(),
        )
        .unwrap();
        phantom_core::fs::atomic_write(
            &dir.path().join(".env"),
            format!("PUBLIC=yes\nAPI_KEY={}\n", PhantomToken::generate()).as_bytes(),
        )
        .unwrap();
        let vault = FileVault::new(dir.path(), "remove-test", "passphrase".into()).unwrap();
        vault.store("API_KEY", "secret-value").unwrap();
        (dir, vault, "API_KEY".to_string())
    }

    #[test]
    fn removes_only_exact_managed_ownership() {
        let (dir, vault, name) = fixture();
        let before = std::fs::read(dir.path().join(".phantom.toml")).unwrap();
        let plan = ManagedRemovePlan::prepare(dir.path(), before, &vault, &name).unwrap();
        plan.commit(&vault).unwrap();
        assert!(!vault.exists(&name).unwrap());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".env")).unwrap(),
            "PUBLIC=yes\n"
        );
        let config = PhantomConfig::load(&dir.path().join(".phantom.toml")).unwrap();
        assert!(!config.phantom.secrets.contains_key(&name));
    }

    #[test]
    fn concurrent_dotenv_change_aborts_before_vault_delete() {
        let (dir, vault, name) = fixture();
        let before = std::fs::read(dir.path().join(".phantom.toml")).unwrap();
        let plan = ManagedRemovePlan::prepare(dir.path(), before, &vault, &name).unwrap();
        phantom_core::fs::atomic_write(
            &dir.path().join(".env"),
            format!("PUBLIC=changed\nAPI_KEY={}\n", PhantomToken::generate()).as_bytes(),
        )
        .unwrap();
        assert!(plan.commit(&vault).is_err());
        assert!(vault.exists(&name).unwrap());
        assert!(std::fs::read_to_string(dir.path().join(".env"))
            .unwrap()
            .contains("PUBLIC=changed"));
    }

    #[test]
    fn plaintext_or_duplicate_mapping_is_never_removed() {
        let (dir, vault, name) = fixture();
        phantom_core::fs::atomic_write(&dir.path().join(".env"), b"API_KEY=plaintext\n").unwrap();
        let before = std::fs::read(dir.path().join(".phantom.toml")).unwrap();
        assert!(ManagedRemovePlan::prepare(dir.path(), before, &vault, &name).is_err());
        assert!(vault.exists(&name).unwrap());
    }

    #[test]
    fn config_swap_before_plan_never_reads_or_deletes_vault_entry() {
        let (dir, vault, name) = fixture();
        let before = std::fs::read(dir.path().join(".phantom.toml")).unwrap();
        let mut changed = PhantomConfig::load(&dir.path().join(".phantom.toml")).unwrap();
        changed.phantom.dotenv_path = Some("custom.env".to_string());
        phantom_core::fs::atomic_write(
            &dir.path().join(".phantom.toml"),
            toml::to_string_pretty(&changed).unwrap().as_bytes(),
        )
        .unwrap();
        assert!(ManagedRemovePlan::prepare(dir.path(), before, &vault, &name).is_err());
        assert_eq!(vault.retrieve(&name).unwrap().as_str(), "secret-value");
    }
}
