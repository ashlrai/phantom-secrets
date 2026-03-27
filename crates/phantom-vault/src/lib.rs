pub mod file;
pub mod keychain;
pub mod traits;

pub use traits::VaultBackend;

/// Create the appropriate vault backend for the current platform.
/// Tries OS keychain first, falls back to encrypted file.
pub fn create_vault(project_id: &str) -> Box<dyn VaultBackend> {
    match keychain::KeychainVault::new(project_id) {
        Ok(vault) => Box::new(vault),
        Err(_) => {
            let vault_dir = directories::ProjectDirs::from("ai", "phantom", "phantom-secrets")
                .map(|dirs| dirs.data_dir().to_path_buf())
                .unwrap_or_else(dirs_fallback);
            Box::new(
                file::FileVault::new(&vault_dir, project_id).expect("Failed to create file vault"),
            )
        }
    }
}

fn dirs_fallback() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".phantom")
}
