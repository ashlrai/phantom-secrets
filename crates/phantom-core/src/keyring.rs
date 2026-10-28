//! Explicit native stores for the keyring 4 ecosystem.
//!
//! Never install a process-global default: enabling Secret Service for an
//! explicitly migrated vault must not redirect cloud keys or unmigrated vaults.

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use keyring_core::api::CredentialStoreApi;
use keyring_core::{Entry, Result};

/// Value-free error category suitable for CLI/MCP diagnostics.
/// Never format a backend error: even its Display implementation can expose
/// nested credential data, platform strings, or ambiguous entry metadata.
pub fn error_kind(error: &keyring_core::Error) -> &'static str {
    use keyring_core::Error;
    match error {
        Error::PlatformFailure(_) => "platform failure",
        Error::NoStorageAccess(_) => "credential store is locked or unavailable",
        Error::NoEntry => "no entry",
        Error::BadEncoding(_) => "bad encoding",
        Error::BadDataFormat(_, _) => "malformed credential data",
        Error::BadStoreFormat(_) => "malformed credential store",
        Error::TooLong(_, _) => "attribute too long",
        Error::Invalid(_, _) => "invalid attribute",
        Error::Ambiguous(_) => "ambiguous entry",
        Error::NoDefaultStore => "no default credential store",
        Error::NotSupportedByStore(_) => "unsupported credential store operation",
        _ => "unknown credential store error",
    }
}

/// Construct an entry in the native store used by Phantom before keyring 4.
/// Construction never reads or writes a credential's value.
pub fn native_entry(service: &str, account: &str) -> Result<Entry> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()?;
    #[cfg(target_os = "linux")]
    let store = linux_keyutils_store()?;

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        store.build(service, account, None)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (service, account);
        Err(keyring_core::Error::NotSupportedByStore(
            "no native credential store is configured on this platform".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_keyutils_store() -> Result<std::sync::Arc<linux_keyutils_keyring_store::Store>> {
    // The new store defaults to `keyring:`, whereas keyring 3 used
    // `keyring-rs:`. Changing this would hide existing keys and could cause
    // replacement encryption keys to be generated for existing vaults.
    linux_keyutils_keyring_store::Store::new_with_configuration(&std::collections::HashMap::from([
        ("prefix", "keyring-rs:"),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn keyutils_preserves_keyring3_address_configuration() {
        // Store construction does not require an available kernel keyring.
        let store = linux_keyutils_store().unwrap();
        assert_eq!(store.delimiters, ["keyring-rs:", "@", ""]);
        assert!(!store.service_no_divider);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_preserves_keyring3_user_keychain_address() {
        use apple_native_keyring_store::keychain::{Cred, MacKeychainDomain};
        let entry = native_entry("phantom-test-address", "test-account").unwrap();
        let credential = entry.as_any().downcast_ref::<Cred>().unwrap();
        assert_eq!(credential.domain, MacKeychainDomain::User);
        assert_eq!(credential.service, "phantom-test-address");
        assert_eq!(credential.account, "test-account");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_preserves_keyring3_address_configuration() {
        let store = windows_native_keyring_store::Store::new().unwrap();
        assert_eq!(store.delimiters, ["", ".", ""]);
        assert!(!store.service_no_divider);
        let entry = native_entry("phantom-test-address", "test-account").unwrap();
        assert_eq!(
            entry.get_specifiers(),
            Some(("phantom-test-address".into(), "test-account".into()))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_entry_rejects_empty_identifiers() {
        for (service, account) in [("", "test-account"), ("phantom-test-address", "")] {
            assert!(matches!(
                native_entry(service, account),
                Err(keyring_core::Error::Invalid(_, _))
            ));
        }
    }
}
