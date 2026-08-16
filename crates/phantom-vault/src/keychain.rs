use crate::metadata::SecretMetadata;
use crate::traits::VaultBackend;
use phantom_core::error::{PhantomError, Result};
use phantom_core::validator::ValidationMetadata;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SERVICE_PREFIX: &str = "phantom-secrets";

/// 16-hex-char (64-bit) SHA-256 digest of `{project_id}:{name}`. Used as the
/// keychain entry's service and account metadata so the plaintext secret
/// name is never visible to unrelated processes that enumerate keychain
/// entries (audit F13). 64 bits is ample collision resistance for a
/// per-project keyspace while keeping the metadata string short.
fn hash_secret_name(project_id: &str, name: &str) -> String {
    let mut h = Sha256::new();
    h.update(project_id.as_bytes());
    h.update(b":");
    h.update(name.as_bytes());
    let out = h.finalize();
    hex::encode(&out[..8])
}

/// Vault backend that uses the OS keychain (macOS Keychain, Linux Secret Service).
pub struct KeychainVault {
    project_id: String,
    /// We track stored keys in a special keychain entry since keychain APIs
    /// don't support listing by prefix on all platforms.
    index_key: String,
}

// ── Metadata sidecar helpers ─────────────────────────────────────────────────
//
// The OS keychain stores opaque password strings — there is no structured
// per-entry metadata slot. We persist TTL/expiry metadata in a small JSON
// sidecar file alongside the keychain index. The file contains only
// timestamps and policy config — no secret values — so it is safe to store
// as plaintext on disk (it is no more sensitive than a .phantom.toml).

fn metadata_dir() -> PathBuf {
    directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
        .map(|d| d.data_dir().join("metadata"))
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join(".phantom")
                .join("metadata")
        })
}

fn metadata_path(project_id: &str) -> PathBuf {
    // Sanitise project_id so it is safe as a filename component.
    let safe: String = project_id
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    metadata_dir().join(format!("{safe}.meta.json"))
}

/// Load the full per-project metadata map from the sidecar file.
fn load_meta_map(project_id: &str) -> BTreeMap<String, SecretMetadata> {
    let path = metadata_path(project_id);
    if !path.exists() {
        return BTreeMap::new();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist the full per-project metadata map to the sidecar file.
fn save_meta_map(project_id: &str, map: &BTreeMap<String, SecretMetadata>) -> Result<()> {
    let path = metadata_path(project_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(map)
        .map_err(|e| PhantomError::VaultError(format!("Metadata serialize error: {e}")))?;
    // Atomic write via temp file.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

// ── Validation metadata sidecar ──────────────────────────────────────────────
//
// Mirrors the TTL metadata sidecar: a separate JSON file stores per-secret
// validation state (last_check_ts, is_valid, failure_reason). No secret
// values are ever written here.

fn validation_meta_path(project_id: &str) -> std::path::PathBuf {
    let safe: String = project_id
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    metadata_dir().join(format!("{safe}.validation.json"))
}

fn load_validation_meta_map(project_id: &str) -> BTreeMap<String, ValidationMetadata> {
    let path = validation_meta_path(project_id);
    if !path.exists() {
        return BTreeMap::new();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_validation_meta_map(
    project_id: &str,
    map: &BTreeMap<String, ValidationMetadata>,
) -> Result<()> {
    let path = validation_meta_path(project_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(map).map_err(|e| {
        PhantomError::VaultError(format!("Validation metadata serialize error: {e}"))
    })?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

impl KeychainVault {
    /// Create a new keychain vault for a project.
    /// Returns an error if the keychain is not available.
    pub fn new(project_id: &str) -> Result<Self> {
        // Test that keychain is accessible by trying a no-op
        let test_entry = keyring::Entry::new(SERVICE_PREFIX, "__phantom_test__")
            .map_err(|e| PhantomError::VaultError(format!("Keychain not available: {e}")))?;

        // Try to access it (will fail with NotFound, which is fine)
        match test_entry.get_password() {
            Ok(_) | Err(keyring::Error::NoEntry) => {}
            Err(e) => {
                return Err(PhantomError::VaultError(format!(
                    "Keychain not accessible: {e}"
                )));
            }
        }

        Ok(Self {
            index_key: format!("{SERVICE_PREFIX}:{project_id}:__index__"),
            project_id: project_id.to_string(),
        })
    }

    fn hash_name(&self, name: &str) -> String {
        hash_secret_name(&self.project_id, name)
    }

    /// F13 entry key: opaque hash of the secret name. The `h-` prefix
    /// distinguishes post-F13 entries from legacy plaintext-named entries
    /// for migration.
    fn entry_key(&self, name: &str) -> String {
        format!(
            "{SERVICE_PREFIX}:{}:h-{}",
            self.project_id,
            self.hash_name(name)
        )
    }

    /// Pre-F13 entry key used by older phantom versions. Kept for read-time
    /// migration so existing users don't lose access to their stored secrets.
    fn legacy_entry_key(&self, name: &str) -> String {
        format!("{SERVICE_PREFIX}:{}:{}", self.project_id, name)
    }

    fn entry_for(&self, name: &str) -> Result<keyring::Entry> {
        // Use the hashed name for the account field too — `keyring::Entry`
        // uses (service, account) as the lookup key on most backends, and we
        // want neither to leak the plaintext name.
        let account = self.hash_name(name);
        keyring::Entry::new(&self.entry_key(name), &account)
            .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))
    }

    fn legacy_entry_for(&self, name: &str) -> Option<keyring::Entry> {
        keyring::Entry::new(&self.legacy_entry_key(name), name).ok()
    }

    /// Best-effort deletion of the legacy plaintext-named entry for `name`.
    /// Used during F13 migration — failures are swallowed because the new
    /// entry already holds the authoritative value.
    fn delete_legacy(&self, name: &str) {
        if let Some(legacy) = self.legacy_entry_for(name) {
            let _ = legacy.delete_credential();
        }
    }

    /// Load the index of stored secret names.
    fn load_index(&self) -> Result<Vec<String>> {
        let entry = keyring::Entry::new(
            &format!("{SERVICE_PREFIX}:{}", self.project_id),
            &self.index_key,
        )
        .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))?;

        match entry.get_password() {
            Ok(data) => serde_json::from_str(&data).map_err(|e| {
                PhantomError::VaultError(format!(
                    "Corrupt keychain index (try `phantom init` to rebuild): {e}"
                ))
            }),
            Err(keyring::Error::NoEntry) => Ok(Vec::new()),
            Err(e) => Err(PhantomError::VaultError(format!(
                "Failed to read index: {e}"
            ))),
        }
    }

    /// Save the index of stored secret names.
    fn save_index(&self, names: &[String]) -> Result<()> {
        let entry = keyring::Entry::new(
            &format!("{SERVICE_PREFIX}:{}", self.project_id),
            &self.index_key,
        )
        .map_err(|e| PhantomError::VaultError(format!("Keychain error: {e}")))?;
        let data = serde_json::to_string(names)
            .map_err(|e| PhantomError::VaultError(format!("Serialize error: {e}")))?;
        entry
            .set_password(&data)
            .map_err(|e| PhantomError::VaultError(format!("Failed to save index: {e}")))?;
        Ok(())
    }
}

impl VaultBackend for KeychainVault {
    fn store(&self, name: &str, value: &str) -> Result<()> {
        let entry = self.entry_for(name)?;
        entry
            .set_password(value)
            .map_err(|e| PhantomError::VaultError(format!("Failed to store secret: {e}")))?;

        // F13 migration: once the hashed entry is written, best-effort delete
        // any pre-F13 plaintext entry left over from an older phantom version.
        self.delete_legacy(name);

        // Update index
        let mut index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            index.push(name.to_string());
            index.sort();
            self.save_index(&index)?;
        }
        phantom_core::audit::log("vault.store", Some(name));
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<zeroize::Zeroizing<String>> {
        let entry = self.entry_for(name)?;
        match entry.get_password() {
            Ok(value) => {
                phantom_core::audit::log("vault.retrieve", Some(name));
                Ok(zeroize::Zeroizing::new(value))
            }
            Err(keyring::Error::NoEntry) => {
                // F13 migration: older phantom versions stored entries under
                // the plaintext name. If we find one, return its value and
                // silently re-store at the hashed location so future reads
                // hit the new path.
                if let Some(legacy) = self.legacy_entry_for(name) {
                    match legacy.get_password() {
                        Ok(value) => {
                            if let Ok(new_entry) = self.entry_for(name) {
                                let _ = new_entry.set_password(&value);
                            }
                            let _ = legacy.delete_credential();
                            phantom_core::audit::log("vault.retrieve", Some(name));
                            Ok(zeroize::Zeroizing::new(value))
                        }
                        Err(keyring::Error::NoEntry) => {
                            Err(PhantomError::SecretNotFound(name.to_string()))
                        }
                        Err(e) => Err(PhantomError::VaultError(format!(
                            "Failed to retrieve secret: {e}"
                        ))),
                    }
                } else {
                    Err(PhantomError::SecretNotFound(name.to_string()))
                }
            }
            Err(e) => Err(PhantomError::VaultError(format!(
                "Failed to retrieve secret: {e}"
            ))),
        }
    }

    fn delete(&self, name: &str) -> Result<()> {
        let entry = self.entry_for(name)?;
        let new_result = entry.delete_credential();

        // Always best-effort delete the legacy entry regardless of whether
        // the new-style delete succeeded — the two are independent and
        // leaving a legacy copy behind defeats F13.
        self.delete_legacy(name);

        match new_result {
            Ok(()) => {}
            Err(keyring::Error::NoEntry) => {
                // If neither form existed, surface SecretNotFound. If the
                // legacy form existed and we deleted it, that's also a
                // successful delete.
                //
                // We can't easily distinguish the two here without another
                // lookup, so fall through and rebuild the index — if the
                // name isn't in the index either, callers get the not-found
                // signal from the next `list()`.
            }
            Err(e) => {
                return Err(PhantomError::VaultError(format!(
                    "Failed to delete secret: {e}"
                )));
            }
        }

        // Update index
        let mut index = self.load_index()?;
        let was_in_index = index.contains(&name.to_string());
        index.retain(|n| n != name);
        if was_in_index {
            self.save_index(&index)?;
            // Best-effort cleanup of sidecar metadata.
            let mut map = load_meta_map(&self.project_id);
            if map.remove(name).is_some() {
                let _ = save_meta_map(&self.project_id, &map);
            }
            let mut vmap = load_validation_meta_map(&self.project_id);
            if vmap.remove(name).is_some() {
                let _ = save_validation_meta_map(&self.project_id, &vmap);
            }
            phantom_core::audit::log("vault.delete", Some(name));
            Ok(())
        } else if matches!(new_result, Err(keyring::Error::NoEntry)) {
            Err(PhantomError::SecretNotFound(name.to_string()))
        } else {
            self.save_index(&index)?;
            // Best-effort cleanup of sidecar metadata.
            let mut map = load_meta_map(&self.project_id);
            if map.remove(name).is_some() {
                let _ = save_meta_map(&self.project_id, &map);
            }
            let mut vmap = load_validation_meta_map(&self.project_id);
            if vmap.remove(name).is_some() {
                let _ = save_validation_meta_map(&self.project_id, &vmap);
            }
            phantom_core::audit::log("vault.delete", Some(name));
            Ok(())
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        self.load_index()
    }

    fn backend_name(&self) -> &str {
        "os-keychain"
    }

    fn get_metadata(&self, name: &str) -> Result<Option<SecretMetadata>> {
        let map = load_meta_map(&self.project_id);
        Ok(map.get(name).cloned())
    }

    fn set_metadata(&self, name: &str, meta: SecretMetadata) -> Result<()> {
        // Only allow metadata on keys that actually exist in the vault index.
        let index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        let mut map = load_meta_map(&self.project_id);
        map.insert(name.to_string(), meta);
        save_meta_map(&self.project_id, &map)
    }

    fn get_validation_metadata(&self, name: &str) -> Result<ValidationMetadata> {
        let map = load_validation_meta_map(&self.project_id);
        Ok(map.get(name).cloned().unwrap_or_default())
    }

    fn set_validation_metadata(&self, name: &str, meta: ValidationMetadata) -> Result<()> {
        let index = self.load_index()?;
        if !index.contains(&name.to_string()) {
            return Err(PhantomError::SecretNotFound(name.to_string()));
        }
        let mut map = load_validation_meta_map(&self.project_id);
        map.insert(name.to_string(), meta);
        save_validation_meta_map(&self.project_id, &map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_secret_name_is_deterministic() {
        let a = hash_secret_name("proj-abc", "OPENAI_API_KEY");
        let b = hash_secret_name("proj-abc", "OPENAI_API_KEY");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_secret_name_differs_by_project() {
        // Same secret name under different projects must map to different
        // hashes — otherwise two projects on the same keychain would collide.
        let a = hash_secret_name("proj-a", "OPENAI_API_KEY");
        let b = hash_secret_name("proj-b", "OPENAI_API_KEY");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_secret_name_differs_by_name() {
        let a = hash_secret_name("proj", "OPENAI_API_KEY");
        let b = hash_secret_name("proj", "ANTHROPIC_API_KEY");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_secret_name_does_not_contain_plaintext() {
        // F13 core property: the hashed metadata string must not contain the
        // plaintext secret name as a substring.
        let name = "OPENAI_API_KEY";
        let hashed = hash_secret_name("proj", name);
        assert!(!hashed.contains(name));
        assert!(!hashed.contains(&name.to_ascii_lowercase()));
    }

    #[test]
    fn hash_secret_name_format() {
        let h = hash_secret_name("proj", "OPENAI_API_KEY");
        assert_eq!(h.len(), 16, "expected 16 hex chars (64 bits)");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "expected lowercase hex: {h}"
        );
    }

    /// End-to-end round-trip against the real OS keychain. Ignored by
    /// default because it touches the user's actual keychain (and CI
    /// may not have one without `keyring`'s mock backend). Run with
    /// `cargo test -p phantom-secrets-vault -- --ignored` on each
    /// platform (macOS Keychain, Linux Secret Service, Windows
    /// Credential Manager) to confirm the backend is wired up.
    #[test]
    #[ignore = "touches OS keychain — run with --ignored on each platform"]
    fn os_keychain_roundtrip() {
        use crate::traits::VaultBackend;

        // Per-run unique project_id so a previous failed run can't
        // pollute this one's state.
        let project_id = format!("phantom-test-{}", std::process::id());
        let vault = KeychainVault::new(&project_id).expect("keychain backend should initialize");

        let name = "ROUNDTRIP_TEST_KEY";
        let value = "sk-test-value-do-not-use-12345";
        vault.store(name, value).expect("store");

        let got = vault.retrieve(name).expect("retrieve");
        assert_eq!(got.as_str(), value);

        let listed = vault.list().expect("list");
        assert!(listed.iter().any(|n| n == name));

        vault.delete(name).expect("delete");
        assert!(vault.retrieve(name).is_err());
    }
}
