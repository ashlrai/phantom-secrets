pub mod crypto;
pub mod file;
pub mod init_transaction;
pub mod keychain;
pub mod managed_remove;
pub mod metadata;
pub mod shadowing;
pub mod traits;
pub mod transaction_lock;

pub use init_transaction::{commit_init, InitFile, InitReceipt, InitSecret, InitTransactionError};
pub use managed_remove::ManagedRemovePlan;
pub use metadata::{RotationPolicy, SecretMetadata};
pub use traits::{MetadataCas, ValidationMetadataCas, VaultBackend};
pub use transaction_lock::{acquire_project_transaction_lock, ProjectTransactionLock};

use phantom_core::error::{PhantomError, Result};

const PASSPHRASE_SERVICE: &str = "phantom-secrets-vault";

/// Create the appropriate vault backend for the current platform.
/// Tries the OS keychain first and falls back to an encrypted file only when
/// its passphrase already exists or can be durably persisted and verified.
///
/// When the keychain is unavailable we fall back to an on-disk encrypted
/// vault. That fallback changes the security posture — encrypted-file secrets
/// are recoverable by anyone with the passphrase and the disk, whereas
/// keychain secrets live behind the OS's per-user unlock. We surface that
/// demotion loudly (audit F14) and let the caller opt into a hard-fail via
/// `PHANTOM_REQUIRE_KEYCHAIN=1` instead of silently downgrading.
///
/// Setting `PHANTOM_VAULT_PASSPHRASE` (CI/Docker/test mode) selects the
/// encrypted-file vault directly, skipping the OS keychain entirely. This is
/// an explicit opt-in with a caller-supplied key, not a silent demotion.
/// Without it, Linux CI runners would route every test's secrets through the
/// kernel keyring (keyutils), whose small per-user quota (~200 keys/20 KB)
/// is exhausted partway through a large test run (`QuotaExceeded`).
/// `PHANTOM_REQUIRE_KEYCHAIN=1` wins over the passphrase: it is the
/// security-strict flag and keeps its hard-fail contract.
pub fn create_vault(project_id: &str) -> Result<Box<dyn VaultBackend>> {
    try_create_vault(project_id)
}

/// Fallible vault construction for workflows such as `phantom init` that must
/// surface provisioning failures before preparing or committing project files.
pub fn try_create_vault(project_id: &str) -> Result<Box<dyn VaultBackend>> {
    let require_keychain = std::env::var("PHANTOM_REQUIRE_KEYCHAIN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !require_keychain {
        if let Ok(passphrase) = std::env::var("PHANTOM_VAULT_PASSPHRASE") {
            if !passphrase.is_empty() {
                let vault_dir = file_vault_dir();
                return Ok(Box::new(file::FileVault::new(
                    &vault_dir, project_id, passphrase,
                )?));
            }
        }
    }

    match keychain::KeychainVault::new(project_id) {
        Ok(vault) => Ok(Box::new(vault)),
        Err(keychain_err) => {
            if require_keychain {
                return Err(PhantomError::VaultError(format!(
                    "OS keychain unavailable while PHANTOM_REQUIRE_KEYCHAIN is set: {keychain_err}. Unlock/configure the OS keychain, or unset PHANTOM_REQUIRE_KEYCHAIN and set PHANTOM_VAULT_PASSPHRASE for an explicit encrypted-file vault"
                )));
            }

            let vault_dir = file_vault_dir();
            // Serialize fallback-key resolution with every other per-project
            // keychain/index operation. Otherwise two processes can each
            // persist and verify a different generated passphrase.
            let _fallback_lock = keychain::acquire_project_lock(project_id)?;
            let encrypted_vault_exists = file::encrypted_vault_exists(&vault_dir, project_id)?;
            let passphrase =
                get_or_create_passphrase(project_id, !encrypted_vault_exists).map_err(|error| {
                PhantomError::VaultError(format!(
                    "OS keychain vault unavailable ({keychain_err}); encrypted-file fallback was not created because its passphrase could not be durably persisted: {error}. Set PHANTOM_VAULT_PASSPHRASE and retry"
                ))
            })?;

            eprintln!(
                "phantom: WARNING — OS keychain unavailable; using encrypted file vault at {} with a passphrase verified in durable secure storage.\n  Reason: {keychain_err}\n  To hard-fail instead of falling back, set PHANTOM_REQUIRE_KEYCHAIN=1.",
                vault_dir.display()
            );
            Ok(Box::new(file::FileVault::new(
                &vault_dir, project_id, passphrase,
            )?))
        }
    }
}

/// Directory holding encrypted file vaults.
fn file_vault_dir() -> std::path::PathBuf {
    directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(dirs_fallback)
}

trait PassphraseStore {
    fn get(&self) -> std::result::Result<Option<String>, String>;
    fn set(&self, passphrase: &str) -> std::result::Result<(), String>;
}

struct KeyringPassphraseStore {
    entry: keyring::Entry,
}

impl PassphraseStore for KeyringPassphraseStore {
    fn get(&self) -> std::result::Result<Option<String>, String> {
        match self.entry.get_password() {
            Ok(passphrase) => Ok(Some(passphrase)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn set(&self, passphrase: &str) -> std::result::Result<(), String> {
        self.entry
            .set_password(passphrase)
            .map_err(|error| error.to_string())
    }
}

/// Resolve the encrypted-file passphrase. A generated value is returned only
/// after a read-after-write proves that secure storage persisted the exact
/// bytes. Any ambiguous backend failure aborts vault creation.
fn resolve_persisted_passphrase(
    store: &dyn PassphraseStore,
    allow_generation: bool,
    generate: impl FnOnce() -> String,
) -> Result<String> {
    match store.get() {
        Ok(Some(passphrase)) if !passphrase.is_empty() => return Ok(passphrase),
        Ok(Some(_)) => {
            return Err(PhantomError::VaultError(
                "secure passphrase entry was empty".to_string(),
            ));
        }
        Ok(None) if allow_generation => {}
        Ok(None) => {
            return Err(PhantomError::VaultError(
                "secure passphrase entry is missing for an existing encrypted vault; refusing to generate a replacement key"
                    .to_string(),
            ));
        }
        Err(error) => {
            return Err(PhantomError::VaultError(format!(
                "could not read the secure passphrase entry: {error}"
            )));
        }
    }

    let passphrase = generate();
    store.set(&passphrase).map_err(|error| {
        PhantomError::VaultError(format!(
            "could not persist the generated fallback passphrase: {error}"
        ))
    })?;
    let verified = store.get().map_err(|error| {
        PhantomError::VaultError(format!(
            "could not verify the persisted fallback passphrase: {error}"
        ))
    })?;
    if verified.as_deref() != Some(passphrase.as_str()) {
        return Err(PhantomError::VaultError(
            "secure storage did not return the generated fallback passphrase after writing it"
                .to_string(),
        ));
    }
    Ok(passphrase)
}

fn get_or_create_passphrase(project_id: &str, allow_generation: bool) -> Result<String> {
    if let Ok(passphrase) = std::env::var("PHANTOM_VAULT_PASSPHRASE") {
        if !passphrase.is_empty() {
            return Ok(passphrase);
        }
    }

    let keychain_key = format!("{PASSPHRASE_SERVICE}:{project_id}");
    let entry = keyring::Entry::new(PASSPHRASE_SERVICE, &keychain_key).map_err(|error| {
        PhantomError::VaultError(format!(
            "could not create the secure passphrase entry: {error}"
        ))
    })?;
    resolve_persisted_passphrase(
        &KeyringPassphraseStore { entry },
        allow_generation,
        generate_passphrase,
    )
}

fn generate_passphrase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn dirs_fallback() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_else(std::env::temp_dir);
    home.join(".phantom")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[test]
    fn public_vault_constructor_is_fallible() {
        let _constructor: fn(&str) -> Result<Box<dyn VaultBackend>> = create_vault;
    }

    struct ScriptedPassphraseStore {
        gets: Mutex<VecDeque<std::result::Result<Option<String>, String>>>,
        set_result: std::result::Result<(), String>,
        set_calls: Mutex<Vec<String>>,
    }

    impl ScriptedPassphraseStore {
        fn new(
            gets: impl IntoIterator<Item = std::result::Result<Option<String>, String>>,
            set_result: std::result::Result<(), String>,
        ) -> Self {
            Self {
                gets: Mutex::new(gets.into_iter().collect()),
                set_result,
                set_calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl PassphraseStore for ScriptedPassphraseStore {
        fn get(&self) -> std::result::Result<Option<String>, String> {
            self.gets
                .lock()
                .unwrap()
                .pop_front()
                .expect("test must script every secure-store read")
        }

        fn set(&self, passphrase: &str) -> std::result::Result<(), String> {
            self.set_calls.lock().unwrap().push(passphrase.to_string());
            self.set_result.clone()
        }
    }

    #[test]
    fn entry_creation_success_with_backend_read_failure_never_generates_a_key() {
        let store =
            ScriptedPassphraseStore::new([Err("credential store locked".to_string())], Ok(()));

        let error = resolve_persisted_passphrase(&store, true, || {
            panic!("generation must not run after an ambiguous backend read failure")
        })
        .unwrap_err();

        assert!(error.to_string().contains("could not read"));
        assert!(store.set_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn backend_set_failure_is_repeatable_and_cannot_strand_an_existing_vault() {
        let directory = tempdir().unwrap();
        let vault =
            file::FileVault::new(directory.path(), "project", "durable-key".to_string()).unwrap();
        vault.store("API_KEY", "existing-value").unwrap();
        let vault_path = directory.path().join("vaults/project.vault");
        let before = std::fs::read(&vault_path).unwrap();

        for _process_equivalent_creation in 0..2 {
            let store = ScriptedPassphraseStore::new(
                [Ok(None)],
                Err("secure storage rejected write".to_string()),
            );
            let error = resolve_persisted_passphrase(&store, true, || "new-random-key".to_string())
                .unwrap_err();
            assert!(error.to_string().contains("could not persist"));
            assert_eq!(
                store.set_calls.lock().unwrap().as_slice(),
                ["new-random-key"]
            );
            assert_eq!(std::fs::read(&vault_path).unwrap(), before);
            assert_eq!(
                vault.retrieve("API_KEY").unwrap().as_str(),
                "existing-value"
            );
        }
    }

    #[test]
    fn missing_passphrase_for_existing_vault_never_generates_a_replacement() {
        let directory = tempdir().unwrap();
        let vault =
            file::FileVault::new(directory.path(), "project", "durable-key".to_string()).unwrap();
        vault.store("API_KEY", "existing-value").unwrap();
        let vault_path = directory.path().join("vaults/project.vault");
        let before = std::fs::read(&vault_path).unwrap();
        assert!(file::encrypted_vault_exists(directory.path(), "project").unwrap());
        let store = ScriptedPassphraseStore::new([Ok(None)], Ok(()));

        let error = resolve_persisted_passphrase(&store, false, || {
            panic!("an existing encrypted vault must never get a replacement key")
        })
        .unwrap_err();

        assert!(error.to_string().contains("existing encrypted vault"));
        assert!(store.set_calls.lock().unwrap().is_empty());
        assert_eq!(std::fs::read(&vault_path).unwrap(), before);
        assert_eq!(
            vault.retrieve("API_KEY").unwrap().as_str(),
            "existing-value"
        );
    }

    #[test]
    fn generated_passphrase_requires_exact_read_after_write_verification() {
        let unverifiable = ScriptedPassphraseStore::new(
            [Ok(None), Err("verification read failed".to_string())],
            Ok(()),
        );
        assert!(
            resolve_persisted_passphrase(&unverifiable, true, || "candidate".to_string())
                .unwrap_err()
                .to_string()
                .contains("could not verify")
        );

        let mismatched = ScriptedPassphraseStore::new(
            [Ok(None), Ok(Some("different-value".to_string()))],
            Ok(()),
        );
        assert!(
            resolve_persisted_passphrase(&mismatched, true, || "candidate".to_string())
                .unwrap_err()
                .to_string()
                .contains("did not return the generated fallback passphrase")
        );

        let durable =
            ScriptedPassphraseStore::new([Ok(None), Ok(Some("candidate".to_string()))], Ok(()));
        assert_eq!(
            resolve_persisted_passphrase(&durable, true, || "candidate".to_string()).unwrap(),
            "candidate"
        );
    }
}
