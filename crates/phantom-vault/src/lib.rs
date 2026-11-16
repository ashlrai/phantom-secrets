pub mod crypto;
pub mod file;
pub mod init_transaction;
pub mod keychain;
pub mod lease_key;
pub mod managed_remove;
pub mod metadata;
pub mod rotation_gate;
pub mod shadowing;
pub mod traits;
pub mod transaction_lock;

pub use init_transaction::{
    commit_init, commit_init_if_project_identity, commit_init_with_source_vault, InitFile,
    InitReceipt, InitSecret, InitTransactionError,
};
pub use managed_remove::ManagedRemovePlan;
pub use metadata::{RotationPolicy, SecretMetadata};
pub use traits::{MetadataCas, ValidationMetadataCas, VaultBackend};
pub use transaction_lock::{
    acquire_project_transaction_lock, acquire_project_transaction_locks,
    ProjectDirectoryPreparation, ProjectTransactionLock, ProjectTransactionLockPair,
};

use phantom_core::error::{PhantomError, Result};
use zeroize::Zeroizing;

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
    let require_keychain = require_keychain_set();

    if !require_keychain {
        if let Ok(passphrase) = std::env::var("PHANTOM_VAULT_PASSPHRASE") {
            let mut passphrase = Zeroizing::new(passphrase);
            if !passphrase.is_empty() {
                let vault_dir = file_vault_dir();
                return Ok(Box::new(file::FileVault::new(
                    &vault_dir,
                    project_id,
                    take_passphrase(&mut passphrase),
                )?));
            }
        }
    }

    // Retain one project lock across backend selection, its availability
    // probe, and any implicit encrypted-file fallback setup. Migration cannot
    // publish a one-sided or committed marker state between those decisions.
    let selection_lock = keychain::acquire_project_lock(project_id)?;
    match keychain::KeychainVault::new_with_project_lock(project_id, &selection_lock) {
        Ok(vault) => {
            drop(selection_lock);
            Ok(Box::new(vault))
        }
        Err(keychain::KeychainOpenError::Authoritative(error)) => Err(error),
        Err(keychain::KeychainOpenError::Unavailable(keychain_err)) => {
            if require_keychain {
                return Err(PhantomError::VaultError(format!(
                    "OS keychain unavailable while PHANTOM_REQUIRE_KEYCHAIN is set: {keychain_err}. Unlock/configure the OS keychain, or unset PHANTOM_REQUIRE_KEYCHAIN and set PHANTOM_VAULT_PASSPHRASE for an explicit encrypted-file vault"
                )));
            }

            let vault_dir = file_vault_dir();
            let encrypted_vault_exists = file::encrypted_vault_exists(&vault_dir, project_id)?;
            let mut passphrase =
                get_or_create_passphrase(project_id, !encrypted_vault_exists).map_err(|error| {
                PhantomError::VaultError(format!(
                    "OS keychain vault unavailable ({keychain_err}); encrypted-file fallback was not created because its passphrase could not be durably persisted: {error}. Set PHANTOM_VAULT_PASSPHRASE and retry"
                ))
            })?;

            eprintln!(
                "phantom: WARNING — OS keychain unavailable; using encrypted file vault at {} with a passphrase verified in durable secure storage.\n  Reason: {keychain_err}\n  To hard-fail instead of falling back, set PHANTOM_REQUIRE_KEYCHAIN=1.",
                vault_dir.display()
            );
            let vault =
                file::FileVault::new(&vault_dir, project_id, take_passphrase(&mut passphrase))?;
            drop(selection_lock);
            Ok(Box::new(vault))
        }
    }
}

/// Read-only probe for the encrypted-file vault split.
///
/// A project initialized with `PHANTOM_VAULT_PASSPHRASE` keeps its secrets in
/// the encrypted-file vault. A later process without that variable (for
/// example an MCP server launched by a GUI client) selects the OS keychain
/// instead and would otherwise report an empty vault. This returns a
/// value-blind notice when this process has no passphrase in its environment
/// but an encrypted-file vault for `project_id` exists on disk. It never
/// opens, decrypts, locks, or creates anything and never reads a passphrase.
///
/// `PHANTOM_REQUIRE_KEYCHAIN` wins over the passphrase in [`try_create_vault`],
/// so with it set the file vault is never opened and the notice is returned
/// whether or not a passphrase is set.
pub fn locked_file_vault_notice(project_id: &str) -> Option<String> {
    let passphrase_set =
        std::env::var_os("PHANTOM_VAULT_PASSPHRASE").is_some_and(|v| !v.is_empty());
    locked_file_vault_notice_in(
        &file_vault_dir(),
        project_id,
        passphrase_set,
        require_keychain_set(),
    )
}

/// `PHANTOM_REQUIRE_KEYCHAIN` as [`try_create_vault`] reads it.
fn require_keychain_set() -> bool {
    std::env::var("PHANTOM_REQUIRE_KEYCHAIN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn locked_file_vault_notice_in(
    vault_dir: &std::path::Path,
    project_id: &str,
    passphrase_set: bool,
    require_keychain: bool,
) -> Option<String> {
    // The passphrase selects the file vault only when the keychain is not
    // required; under PHANTOM_REQUIRE_KEYCHAIN the file is never opened.
    if (passphrase_set && !require_keychain)
        || project_id.is_empty()
        || !project_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let path = vault_dir.join("vaults").join(format!("{project_id}.vault"));
    let is_file = std::fs::symlink_metadata(&path)
        .map(|meta| meta.file_type().is_file())
        .unwrap_or(false);
    if !is_file {
        return None;
    }
    let path = path.display();
    let stale = format!(
        "If this project's secrets now live in the OS keychain instead, that file may be stale: back it up or move it aside (do not delete it until you have confirmed nothing in it is still needed): {path}."
    );
    if require_keychain {
        let env_override_note = if passphrase_set {
            "; PHANTOM_VAULT_PASSPHRASE is set but does not override it"
        } else {
            ""
        };
        return Some(format!(
            "An encrypted-file vault for this project exists at {path} but is not opened in this process: PHANTOM_REQUIRE_KEYCHAIN is set, so Phantom uses only the OS keychain{env_override_note}. To read that file, run without PHANTOM_REQUIRE_KEYCHAIN and with PHANTOM_VAULT_PASSPHRASE set to its passphrase, then store its secrets in the OS keychain if the keychain-only policy should hold. {stale}"
        ));
    }
    // The file cannot say which way it was created, so both are described.
    // An automatic-fallback vault's passphrase was generated by Phantom and
    // kept in the OS credential store; nobody chose it, so "set the
    // passphrase you used" alone cannot be followed for it.
    Some(format!(
        "An encrypted-file vault for this project exists at {path} but is locked in this process: PHANTOM_VAULT_PASSPHRASE is not set here, so Phantom cannot open it and selects the OS keychain instead. If its secrets were stored with PHANTOM_VAULT_PASSPHRASE set, set it to that passphrase (for an MCP client, in the server's env config) and retry. If Phantom created the file itself because the OS keychain was unavailable at the time, no passphrase was ever chosen: Phantom generated one and keeps it in the OS credential store (service \"{PASSPHRASE_SERVICE}\", entry \"{PASSPHRASE_SERVICE}:{project_id}\"), and Phantom opens such a file on its own only while the OS keychain is unavailable. No Phantom command opens it while the keychain works; to read it, supply that stored passphrase as PHANTOM_VAULT_PASSPHRASE for one run, and if the entry no longer exists the file cannot be decrypted. {stale}"
    ))
}

/// Path of the encrypted-file vault for `project_id`.
///
/// Computes the location only. It does not create directories, take a lock,
/// open the keychain, or read a passphrase.
pub fn encrypted_file_vault_path(project_id: &str) -> Result<std::path::PathBuf> {
    file::validate_project_id(project_id)?;
    Ok(file_vault_dir()
        .join("vaults")
        .join(format!("{project_id}.vault")))
}

/// Directory holding encrypted file vaults.
fn file_vault_dir() -> std::path::PathBuf {
    directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(dirs_fallback)
}

/// The directory [`file_vault_dir`] falls back to when the platform project
/// dirs cannot be resolved — `<home>/.phantom` (or `<temp>/.phantom` when no
/// home exists), exactly as `dirs_fallback` computes it.
///
/// `ProjectDirs` resolves against this process's environment, and on Windows
/// the Known-Folder lookup expands `%USERPROFILE%` and verifies the folder
/// exists. A child spawned with a redirected profile (for example a test
/// `USERPROFILE` pointing at an empty directory) can therefore land in the
/// fallback while this process resolves the platform data dir, or the
/// reverse. Callers that must find a vault produced by a differently
/// configured process — diagnostics and test scaffolding — should check
/// both [`encrypted_file_vault_path`] and this directory.
pub fn file_vault_fallback_dir() -> std::path::PathBuf {
    dirs_fallback()
}

/// Move a passphrase out of its scrubbing wrapper into the `String` that
/// [`file::FileVault::new`] takes. The heap buffer is moved, not copied, so
/// no unscrubbed duplicate is left behind; the wrapper keeps an empty string.
fn take_passphrase(passphrase: &mut Zeroizing<String>) -> String {
    std::mem::take(&mut **passphrase)
}

/// Durable storage for the generated encrypted-file fallback passphrase.
/// Every value read from it is returned in a buffer scrubbed on drop.
trait PassphraseStore {
    fn get(&self) -> std::result::Result<Option<Zeroizing<String>>, String>;
    fn set(&self, passphrase: &str) -> std::result::Result<(), String>;
}

struct KeyringPassphraseStore {
    entry: keyring::Entry,
}

impl PassphraseStore for KeyringPassphraseStore {
    fn get(&self) -> std::result::Result<Option<Zeroizing<String>>, String> {
        match self.entry.get_password() {
            Ok(passphrase) => Ok(Some(Zeroizing::new(passphrase))),
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
    generate: impl FnOnce() -> Zeroizing<String>,
) -> Result<Zeroizing<String>> {
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
    if verified.as_ref().map(|value| value.as_str()) != Some(passphrase.as_str()) {
        return Err(PhantomError::VaultError(
            "secure storage did not return the generated fallback passphrase after writing it"
                .to_string(),
        ));
    }
    Ok(passphrase)
}

fn get_or_create_passphrase(project_id: &str, allow_generation: bool) -> Result<Zeroizing<String>> {
    if let Ok(passphrase) = std::env::var("PHANTOM_VAULT_PASSPHRASE") {
        let passphrase = Zeroizing::new(passphrase);
        if !passphrase.is_empty() {
            return Ok(passphrase);
        }
    }

    let keychain_key = format!("{PASSPHRASE_SERVICE}:{project_id}");
    let entry =
        keychain::unmigrated_os_entry(PASSPHRASE_SERVICE, &keychain_key).map_err(|error| {
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

fn generate_passphrase() -> Zeroizing<String> {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(bytes.as_mut());
    Zeroizing::new(hex::encode(bytes.as_ref()))
}

fn dirs_fallback() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_else(std::env::temp_dir);
    home.join(".phantom")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[test]
    fn encrypted_file_vault_path_names_a_vault_file_and_rejects_path_ids() {
        let path = encrypted_file_vault_path("abc123").unwrap();
        assert!(path.ends_with("vaults/abc123.vault") || path.ends_with("vaults\\abc123.vault"));
        assert!(encrypted_file_vault_path("").is_err());
        assert!(encrypted_file_vault_path("../abc").is_err());
        assert!(encrypted_file_vault_path("abc/def").is_err());
    }

    #[test]
    fn file_vault_fallback_dir_is_the_home_scoped_phantom_directory() {
        let fallback = file_vault_fallback_dir();
        assert_eq!(fallback, dirs_fallback());
        assert!(fallback.is_absolute());
        assert_eq!(fallback.file_name().unwrap(), ".phantom");
        // `encrypted_file_vault_path` layers `vaults/<id>.vault` onto either
        // this fallback or the platform project-data dir.
        let expected = fallback.join("vaults").join("abc123.vault");
        if file_vault_dir() == fallback {
            assert_eq!(encrypted_file_vault_path("abc123").unwrap(), expected);
        }
    }

    #[test]
    fn locked_file_vault_notice_reports_only_unopened_file_vaults() {
        let dir = tempdir().unwrap();
        let id = "abc123";
        assert!(locked_file_vault_notice_in(dir.path(), id, false, false).is_none());

        std::fs::create_dir_all(dir.path().join("vaults")).unwrap();
        std::fs::write(
            dir.path().join("vaults").join("abc123.vault"),
            b"ciphertext",
        )
        .unwrap();
        let notice = locked_file_vault_notice_in(dir.path(), id, false, false).unwrap();
        assert!(notice.contains("PHANTOM_VAULT_PASSPHRASE"));
        assert!(notice.contains("abc123.vault"));
        assert!(!notice.contains("ciphertext"));

        assert!(locked_file_vault_notice_in(dir.path(), id, true, false).is_none());
        assert!(
            locked_file_vault_notice_in(dir.path(), "../vaults/abc123", false, false).is_none()
        );
    }

    /// A `.vault` made by the automatic fallback has a generated passphrase
    /// kept in the OS credential store, so "set PHANTOM_VAULT_PASSPHRASE to
    /// the passphrase used" could not be followed. The notice names where
    /// that passphrase lives and says plainly that no command opens the file
    /// while the keychain works.
    #[test]
    fn locked_notice_is_honest_about_an_automatic_fallback_vault() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("vaults")).unwrap();
        std::fs::write(dir.path().join("vaults").join("abc123.vault"), b"x").unwrap();

        let notice = locked_file_vault_notice_in(dir.path(), "abc123", false, false).unwrap();
        assert!(notice.contains("no passphrase was ever chosen"), "{notice}");
        assert!(
            notice.contains(&format!("{PASSPHRASE_SERVICE}:abc123")),
            "{notice}"
        );
        assert!(notice.contains("No Phantom command opens it while the keychain works"));
    }

    /// `PHANTOM_REQUIRE_KEYCHAIN` wins over `PHANTOM_VAULT_PASSPHRASE` in
    /// `try_create_vault`, so the file vault is not opened even with a
    /// passphrase set. The notice used to return None there, and an empty
    /// keychain listing read as "no secrets".
    #[test]
    fn locked_notice_covers_a_required_keychain_with_a_passphrase_set() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("vaults")).unwrap();
        std::fs::write(dir.path().join("vaults").join("abc123.vault"), b"x").unwrap();

        for passphrase_set in [true, false] {
            let notice =
                locked_file_vault_notice_in(dir.path(), "abc123", passphrase_set, true).unwrap();
            assert!(
                notice.contains("PHANTOM_REQUIRE_KEYCHAIN is set"),
                "{notice}"
            );
            assert!(notice.contains("abc123.vault"), "{notice}");
            assert_eq!(
                notice.contains("does not override it"),
                passphrase_set,
                "{notice}"
            );
        }
    }

    /// The fallback vault passphrase is a key: every path that reads,
    /// generates, verifies, or hands it on must keep it in a buffer that is
    /// scrubbed on drop, never a plain `String` left behind in freed memory.
    #[test]
    fn fallback_passphrase_paths_hold_zeroizing_buffers() {
        type Scrubbed = Zeroizing<String>;
        type StoreRead = std::result::Result<Option<Scrubbed>, String>;
        type Generator = fn() -> Scrubbed;
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Scrubbed>();

        let _store_get: fn(&KeyringPassphraseStore) -> StoreRead =
            <KeyringPassphraseStore as PassphraseStore>::get;
        let _resolve: fn(&dyn PassphraseStore, bool, Generator) -> Result<Scrubbed> =
            resolve_persisted_passphrase;
        let _get_or_create: fn(&str, bool) -> Result<Scrubbed> = get_or_create_passphrase;
        let _generate: Generator = generate_passphrase;
    }

    #[test]
    fn generated_fallback_passphrase_is_256_bits_of_hex() {
        let generated = generate_passphrase();
        assert_eq!(generated.len(), 64);
        assert!(generated.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(generated.as_str(), generate_passphrase().as_str());
    }

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
        fn get(&self) -> std::result::Result<Option<Zeroizing<String>>, String> {
            self.gets
                .lock()
                .unwrap()
                .pop_front()
                .expect("test must script every secure-store read")
                .map(|value| value.map(Zeroizing::new))
        }

        fn set(&self, passphrase: &str) -> std::result::Result<(), String> {
            self.set_calls.lock().unwrap().push(passphrase.to_string());
            self.set_result.clone()
        }
    }

    #[derive(Clone)]
    struct RestartablePassphraseStore {
        persisted: Arc<Mutex<Option<String>>>,
        reject_writes: bool,
    }

    impl RestartablePassphraseStore {
        fn new(reject_writes: bool) -> Self {
            Self {
                persisted: Arc::new(Mutex::new(None)),
                reject_writes,
            }
        }

        fn restart(&self) -> Self {
            Self {
                persisted: Arc::clone(&self.persisted),
                reject_writes: self.reject_writes,
            }
        }
    }

    impl PassphraseStore for RestartablePassphraseStore {
        fn get(&self) -> std::result::Result<Option<Zeroizing<String>>, String> {
            Ok(self.persisted.lock().unwrap().clone().map(Zeroizing::new))
        }

        fn set(&self, passphrase: &str) -> std::result::Result<(), String> {
            if self.reject_writes {
                return Err("mock secure storage rejected write".to_string());
            }
            *self.persisted.lock().unwrap() = Some(passphrase.to_string());
            Ok(())
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
        let root = directory.path().canonicalize().unwrap();
        let vault = file::FileVault::new(&root, "project", "durable-key".to_string()).unwrap();
        vault.store("API_KEY", "existing-value").unwrap();
        let vault_path = directory.path().join("vaults/project.vault");
        let before = std::fs::read(&vault_path).unwrap();

        for _process_equivalent_creation in 0..2 {
            let store = ScriptedPassphraseStore::new(
                [Ok(None)],
                Err("secure storage rejected write".to_string()),
            );
            let error = resolve_persisted_passphrase(&store, true, || {
                Zeroizing::new("new-random-key".to_string())
            })
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
        let root = directory.path().canonicalize().unwrap();
        let vault = file::FileVault::new(&root, "project", "durable-key".to_string()).unwrap();
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
            resolve_persisted_passphrase(&unverifiable, true, || Zeroizing::new(
                "candidate".to_string()
            ))
            .unwrap_err()
            .to_string()
            .contains("could not verify")
        );

        let mismatched = ScriptedPassphraseStore::new(
            [Ok(None), Ok(Some("different-value".to_string()))],
            Ok(()),
        );
        assert!(
            resolve_persisted_passphrase(&mismatched, true, || Zeroizing::new(
                "candidate".to_string()
            ))
            .unwrap_err()
            .to_string()
            .contains("did not return the generated fallback passphrase")
        );

        let durable =
            ScriptedPassphraseStore::new([Ok(None), Ok(Some("candidate".to_string()))], Ok(()));
        assert_eq!(
            resolve_persisted_passphrase(&durable, true, || Zeroizing::new(
                "candidate".to_string()
            ))
            .unwrap()
            .as_str(),
            "candidate"
        );
    }

    #[test]
    fn persisted_passphrase_reopens_file_vault_after_mocked_process_restart() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let first_process = RestartablePassphraseStore::new(false);
        let passphrase = resolve_persisted_passphrase(&first_process, true, || {
            Zeroizing::new("durable-key".to_string())
        })
        .unwrap();
        let vault = file::FileVault::new(&root, "restart-project", passphrase.to_string()).unwrap();
        vault.store("API_KEY", "existing-value").unwrap();
        drop(vault);

        let restarted_process = first_process.restart();
        let recovered = resolve_persisted_passphrase(&restarted_process, false, || {
            panic!("restart must reuse the verified secure-store passphrase")
        })
        .unwrap();
        let reopened =
            file::FileVault::new(&root, "restart-project", recovered.to_string()).unwrap();

        assert_eq!(
            reopened.retrieve("API_KEY").unwrap().as_str(),
            "existing-value"
        );
    }

    #[test]
    fn rejected_passphrase_persistence_never_creates_a_file_vault_across_restarts() {
        let directory = tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let first_process = RestartablePassphraseStore::new(true);

        for process in [first_process.clone(), first_process.restart()] {
            let error = resolve_persisted_passphrase(&process, true, || {
                Zeroizing::new("ephemeral-key".to_string())
            })
            .unwrap_err();
            assert!(error.to_string().contains("could not persist"));
            assert!(process.persisted.lock().unwrap().is_none());
            assert!(!file::encrypted_vault_exists(&root, "failed-project").unwrap());
        }
    }
}
