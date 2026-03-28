pub mod file;
pub mod keychain;
pub mod traits;

pub use traits::VaultBackend;

const PASSPHRASE_SERVICE: &str = "phantom-secrets-vault";

/// Create the appropriate vault backend for the current platform.
/// Tries OS keychain first, falls back to encrypted file.
pub fn create_vault(project_id: &str) -> Box<dyn VaultBackend> {
    match keychain::KeychainVault::new(project_id) {
        Ok(vault) => Box::new(vault),
        Err(_) => {
            let vault_dir = directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
                .map(|dirs| dirs.data_dir().to_path_buf())
                .unwrap_or_else(dirs_fallback);

            // Get or generate passphrase for encrypted file vault
            let passphrase = get_or_create_passphrase(project_id);

            Box::new(
                file::FileVault::new(&vault_dir, project_id, passphrase)
                    .expect("Failed to create file vault"),
            )
        }
    }
}

/// Get passphrase for file vault encryption.
/// Priority: 1) PHANTOM_VAULT_PASSPHRASE env var (CI/Docker)
///           2) OS keychain (stores auto-generated passphrase)
///           3) Auto-generate and store in keychain
fn get_or_create_passphrase(project_id: &str) -> String {
    // 1. Check env var (CI/Docker mode)
    if let Ok(passphrase) = std::env::var("PHANTOM_VAULT_PASSPHRASE") {
        return passphrase;
    }

    let keychain_key = format!("{PASSPHRASE_SERVICE}:{project_id}");

    // 2. Try to read existing passphrase from keychain
    if let Ok(entry) = keyring::Entry::new(PASSPHRASE_SERVICE, &keychain_key) {
        if let Ok(passphrase) = entry.get_password() {
            return passphrase;
        }

        // 3. Generate new passphrase and store in keychain
        let passphrase = generate_passphrase();
        let _ = entry.set_password(&passphrase);
        return passphrase;
    }

    // 4. Keychain not available at all — generate deterministic passphrase from project_id
    // This is less secure but ensures the vault works without any setup
    format!("phantom-fallback-{project_id}")
}

fn generate_passphrase() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn dirs_fallback() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".phantom")
}
