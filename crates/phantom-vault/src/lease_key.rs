//! Lease store key provisioning (design: `docs/design/lease-store-key-provisioning.md`, PR #230).
//!
//! The broker's `DurableReplayStore` authenticates its snapshot with a
//! caller-supplied 32-byte key. This module is the only place that key is
//! created or loaded. It is a library surface with no callers yet: nothing in
//! Phantom issues, revokes, or rotates leases through it.
//!
//! Decisions applied here (section 11 of the design note):
//!
//! - The key lives only in a durable OS credential store (macOS Keychain,
//!   Windows Credential Manager). There is no file fallback and no derivation
//!   from a vault passphrase.
//! - Linux fails closed until lease-key provisioning explicitly supports a
//!   durable Secret Service store, because kernel keyutils does not survive a
//!   reboot.
//! - Provisioning is an explicit call. It never overwrites an existing entry,
//!   and loading never provisions.
//! - The key is exactly 32 bytes from the OS CSPRNG, is never accepted from a
//!   caller, environment variable or argv, is zeroized on drop, and is never
//!   printed: `Debug` is redacted and no error message carries key material.

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use zeroize::Zeroizing;

/// Length of a lease store key in bytes.
pub const LEASE_STORE_KEY_LEN: usize = 32;

/// Credential-store service name for lease store keys. Distinct from the
/// vault's own service names so a lease key is never mistaken for a secret.
pub const LEASE_KEY_SERVICE: &str = "phantom-secrets-lease-store";

/// File name of the non-secret descriptor written beside a replay store.
pub const LEASE_KEY_DESCRIPTOR_FILE: &str = "lease-key-backend.json";

const LEASE_KEY_ACCOUNT_DOMAIN: &[u8] = b"phantom.lease-store-key.account.v1\0";
const DESCRIPTOR_VERSION: u8 = 1;
const MAX_LABEL_LEN: usize = 128;
const MAX_DESCRIPTOR_BYTES: u64 = 4096;

/// A loaded lease store key. The bytes are zeroized on drop and never
/// formatted.
pub struct LeaseStoreKey(Zeroizing<[u8; LEASE_STORE_KEY_LEN]>);

impl LeaseStoreKey {
    /// Copy the key bytes for `DurableReplayStore::bootstrap` or
    /// `open_existing`, which take the key by value and zeroize their copy.
    pub fn to_bytes(&self) -> [u8; LEASE_STORE_KEY_LEN] {
        *self.0
    }
}

impl fmt::Debug for LeaseStoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeaseStoreKey(<redacted>)")
    }
}

/// Result of an explicit provisioning call. Neither variant carries key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// A new key was generated, stored, and read back intact.
    Provisioned,
    /// A valid key already existed and was left untouched.
    AlreadyProvisioned,
}

/// Errors from provisioning or loading. Messages are value-free.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseKeyError {
    #[error("invalid lease store label: use 1 to 128 ASCII letters, digits, '.', '_' or '-'")]
    InvalidLabel,
    #[error(
        "no durable credential store is available for lease store keys on this platform ({0}); refusing (fail closed)"
    )]
    NoDurableStore(&'static str),
    #[error(
        "lease store key is not provisioned; run the explicit provisioning step first (loading never creates a key)"
    )]
    NotProvisioned,
    #[error(
        "stored lease store key is malformed (wrong length or encoding); refusing to use or overwrite it"
    )]
    Malformed,
    #[error("generated lease store key was rejected (all zero); refusing")]
    WeakKey,
    #[error(
        "lease store key read back after provisioning does not match; another writer may have raced, refusing"
    )]
    ReadBackMismatch,
    #[error("credential store failure during {operation}: {kind}")]
    CredentialStore {
        operation: &'static str,
        kind: &'static str,
    },
    #[error("lease key descriptor problem: {0}")]
    Descriptor(&'static str),
}

/// A place a lease store key can be kept. Implementations store the key as
/// lowercase hex and must never log it.
pub trait LeaseKeyBackend {
    /// Stable, non-secret backend name recorded in the descriptor.
    fn backend_name(&self) -> &'static str;
    /// Whether the store survives a reboot. Non-durable backends are refused.
    fn is_durable(&self) -> bool;
    /// Read the stored entry, if any.
    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, LeaseKeyError>;
    /// Create the entry. Callers have already checked that none exists.
    fn create(&self, account: &str, encoded: &str) -> Result<(), LeaseKeyError>;
}

/// The platform credential store, through the vault's `credential_entry`
/// helper so native store selection remains shared with the vault.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsLeaseKeyBackend;

impl LeaseKeyBackend for OsLeaseKeyBackend {
    fn backend_name(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "macos-keychain"
        }
        #[cfg(target_os = "windows")]
        {
            "windows-credential-manager"
        }
        #[cfg(target_os = "linux")]
        {
            "linux-unsupported"
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            "unsupported"
        }
    }

    fn is_durable(&self) -> bool {
        cfg!(any(target_os = "macos", target_os = "windows"))
    }

    fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, LeaseKeyError> {
        let entry = os_entry(account, "read")?;
        match entry.get_password() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(credential_error("read", &error)),
        }
    }

    fn create(&self, account: &str, encoded: &str) -> Result<(), LeaseKeyError> {
        let entry = os_entry(account, "create")?;
        entry
            .set_password(encoded)
            .map_err(|error| credential_error("create", &error))
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn os_entry(account: &str, operation: &'static str) -> Result<keyring_core::Entry, LeaseKeyError> {
    crate::keychain::os_keychain_entry(LEASE_KEY_SERVICE, account)
        .map_err(|error| credential_error(operation, &error))
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn os_entry(account: &str, operation: &'static str) -> Result<keyring_core::Entry, LeaseKeyError> {
    let _ = (account, operation);
    Err(LeaseKeyError::NoDurableStore(
        "no durable lease-key store is wired here; Linux keyutils is not reboot-durable and Secret Service lease-key provisioning is not enabled",
    ))
}

/// Map a keyring error to a fixed, value-free category. The inner error is
/// never formatted because some variants carry raw credential bytes.
fn credential_error(operation: &'static str, error: &keyring_core::Error) -> LeaseKeyError {
    let kind = phantom_core::keyring::error_kind(error);
    LeaseKeyError::CredentialStore { operation, kind }
}

/// Validate a caller-chosen store label (for example a store id).
pub fn validate_label(label: &str) -> Result<(), LeaseKeyError> {
    if label.is_empty()
        || label.len() > MAX_LABEL_LEN
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(LeaseKeyError::InvalidLabel);
    }
    Ok(())
}

/// Credential-store account for a label: a 16-hex digest, so the label is not
/// visible to processes that enumerate credential entries.
pub fn lease_key_account(label: &str) -> Result<String, LeaseKeyError> {
    validate_label(label)?;
    let mut hasher = Sha256::new();
    hasher.update(LEASE_KEY_ACCOUNT_DOMAIN);
    hasher.update(label.as_bytes());
    Ok(format!("lease-{}", hex::encode(&hasher.finalize()[..8])))
}

/// Explicitly provision a lease store key for `label`.
///
/// Refuses non-durable backends. If a valid key exists it is left untouched
/// (idempotent). If a malformed entry exists it is refused, never overwritten.
/// Otherwise a fresh 32-byte key from the OS CSPRNG is stored and read back.
pub fn provision_lease_store_key(
    backend: &dyn LeaseKeyBackend,
    label: &str,
) -> Result<ProvisionOutcome, LeaseKeyError> {
    let account = lease_key_account(label)?;
    require_durable(backend)?;
    if let Some(existing) = backend.read(&account)? {
        decode_key(&existing)?;
        return Ok(ProvisionOutcome::AlreadyProvisioned);
    }

    let mut key = Zeroizing::new([0_u8; LEASE_STORE_KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    if key.iter().all(|byte| *byte == 0) {
        return Err(LeaseKeyError::WeakKey);
    }
    let encoded = Zeroizing::new(hex::encode(key.as_ref()));
    backend.create(&account, &encoded)?;

    let stored = backend
        .read(&account)?
        .ok_or(LeaseKeyError::ReadBackMismatch)?;
    let decoded = decode_key(&stored).map_err(|_| LeaseKeyError::ReadBackMismatch)?;
    if *decoded.0 != *key {
        return Err(LeaseKeyError::ReadBackMismatch);
    }
    Ok(ProvisionOutcome::Provisioned)
}

/// Load an existing lease store key. Never provisions: a missing key is
/// `NotProvisioned`, and a malformed one is `Malformed`.
pub fn load_lease_store_key(
    backend: &dyn LeaseKeyBackend,
    label: &str,
) -> Result<LeaseStoreKey, LeaseKeyError> {
    let account = lease_key_account(label)?;
    require_durable(backend)?;
    let stored = backend
        .read(&account)?
        .ok_or(LeaseKeyError::NotProvisioned)?;
    decode_key(&stored)
}

fn require_durable(backend: &dyn LeaseKeyBackend) -> Result<(), LeaseKeyError> {
    if backend.is_durable() {
        Ok(())
    } else {
        Err(LeaseKeyError::NoDurableStore(backend.backend_name()))
    }
}

fn decode_key(encoded: &str) -> Result<LeaseStoreKey, LeaseKeyError> {
    if encoded.len() != LEASE_STORE_KEY_LEN * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LeaseKeyError::Malformed);
    }
    let mut key = Zeroizing::new([0_u8; LEASE_STORE_KEY_LEN]);
    hex::decode_to_slice(encoded, key.as_mut()).map_err(|_| LeaseKeyError::Malformed)?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(LeaseKeyError::Malformed);
    }
    Ok(LeaseStoreKey(key))
}

/// Non-secret record of which backend holds a store's key (decision D4). It
/// holds a format version and the backend name only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseKeyDescriptor {
    pub version: u8,
    pub backend: String,
}

/// Write the descriptor into `dir` with mode 0600 (Unix), refusing to follow
/// a symlink. An identical existing descriptor is accepted; a different one
/// is refused and left in place.
pub fn record_lease_key_descriptor(
    dir: &Path,
    backend: &dyn LeaseKeyBackend,
) -> Result<LeaseKeyDescriptor, LeaseKeyError> {
    let descriptor = LeaseKeyDescriptor {
        version: DESCRIPTOR_VERSION,
        backend: backend.backend_name().to_string(),
    };
    let path = dir.join(LEASE_KEY_DESCRIPTOR_FILE);
    match read_lease_key_descriptor(dir) {
        Ok(Some(existing)) if existing == descriptor => return Ok(existing),
        Ok(Some(_)) => {
            return Err(LeaseKeyError::Descriptor(
                "an existing descriptor names a different backend; refusing to overwrite",
            ))
        }
        Ok(None) => {}
        Err(error) => return Err(error),
    }
    let bytes = serde_json::to_vec(&descriptor)
        .map_err(|_| LeaseKeyError::Descriptor("could not encode descriptor"))?;

    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| LeaseKeyError::Descriptor("could not create descriptor file"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| LeaseKeyError::Descriptor("could not write descriptor file"))?;
    Ok(descriptor)
}

/// Read the descriptor from `dir`, if present. Refuses symlinks and
/// oversized or malformed files.
pub fn read_lease_key_descriptor(dir: &Path) -> Result<Option<LeaseKeyDescriptor>, LeaseKeyError> {
    let path = dir.join(LEASE_KEY_DESCRIPTOR_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(LeaseKeyError::Descriptor(
                "could not inspect descriptor file",
            ))
        }
    };
    if !metadata.file_type().is_file() {
        return Err(LeaseKeyError::Descriptor(
            "descriptor path is not a regular file",
        ));
    }
    if metadata.len() > MAX_DESCRIPTOR_BYTES {
        return Err(LeaseKeyError::Descriptor("descriptor file is too large"));
    }
    let bytes = std::fs::read(&path)
        .map_err(|_| LeaseKeyError::Descriptor("could not read descriptor file"))?;
    let descriptor: LeaseKeyDescriptor = serde_json::from_slice(&bytes)
        .map_err(|_| LeaseKeyError::Descriptor("descriptor file is malformed"))?;
    if descriptor.version != DESCRIPTOR_VERSION {
        return Err(LeaseKeyError::Descriptor(
            "descriptor has an unsupported version",
        ));
    }
    Ok(Some(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryBackend {
        durable: bool,
        entries: RefCell<BTreeMap<String, String>>,
        creates: RefCell<u32>,
        /// When set, `create` stores this instead of what it was given.
        tamper_on_create: Option<String>,
    }

    impl MemoryBackend {
        fn durable() -> Self {
            Self {
                durable: true,
                ..Self::default()
            }
        }
    }

    impl LeaseKeyBackend for MemoryBackend {
        fn backend_name(&self) -> &'static str {
            "test-memory"
        }
        fn is_durable(&self) -> bool {
            self.durable
        }
        fn read(&self, account: &str) -> Result<Option<Zeroizing<String>>, LeaseKeyError> {
            Ok(self
                .entries
                .borrow()
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }
        fn create(&self, account: &str, encoded: &str) -> Result<(), LeaseKeyError> {
            *self.creates.borrow_mut() += 1;
            let value = self
                .tamper_on_create
                .clone()
                .unwrap_or_else(|| encoded.to_string());
            self.entries.borrow_mut().insert(account.to_string(), value);
            Ok(())
        }
    }

    fn stored(backend: &MemoryBackend, label: &str) -> String {
        backend
            .entries
            .borrow()
            .get(&lease_key_account(label).unwrap())
            .cloned()
            .unwrap()
    }

    #[test]
    fn provisioning_creates_a_32_byte_key_once_and_is_idempotent() {
        let backend = MemoryBackend::durable();
        assert_eq!(
            provision_lease_store_key(&backend, "store-a").unwrap(),
            ProvisionOutcome::Provisioned
        );
        let first = stored(&backend, "store-a");
        assert_eq!(first.len(), LEASE_STORE_KEY_LEN * 2);
        assert_eq!(hex::decode(&first).unwrap().len(), 32);

        assert_eq!(
            provision_lease_store_key(&backend, "store-a").unwrap(),
            ProvisionOutcome::AlreadyProvisioned
        );
        assert_eq!(stored(&backend, "store-a"), first, "key must not change");
        assert_eq!(*backend.creates.borrow(), 1, "second call must not write");

        let key = load_lease_store_key(&backend, "store-a").unwrap();
        assert_eq!(key.to_bytes().len(), LEASE_STORE_KEY_LEN);
        assert_eq!(hex::encode(key.to_bytes()), first);
    }

    #[test]
    fn distinct_labels_get_distinct_keys_and_accounts() {
        let backend = MemoryBackend::durable();
        provision_lease_store_key(&backend, "store-a").unwrap();
        provision_lease_store_key(&backend, "store-b").unwrap();
        assert_ne!(
            lease_key_account("store-a").unwrap(),
            lease_key_account("store-b").unwrap()
        );
        assert_ne!(stored(&backend, "store-a"), stored(&backend, "store-b"));
        assert!(!lease_key_account("store-a").unwrap().contains("store-a"));
    }

    #[test]
    fn provisioning_refuses_to_overwrite_a_malformed_entry() {
        let backend = MemoryBackend::durable();
        let account = lease_key_account("store-a").unwrap();
        for bad in [
            "abcd",
            &"ab".repeat(31),
            &"ab".repeat(33),
            &"zz".repeat(32),
            &"AB".repeat(32),
            &"00".repeat(32),
        ] {
            backend
                .entries
                .borrow_mut()
                .insert(account.clone(), bad.to_string());
            assert_eq!(
                provision_lease_store_key(&backend, "store-a"),
                Err(LeaseKeyError::Malformed)
            );
            assert_eq!(stored(&backend, "store-a"), bad, "entry must be left alone");
            assert_eq!(
                load_lease_store_key(&backend, "store-a").unwrap_err(),
                LeaseKeyError::Malformed
            );
        }
        assert_eq!(*backend.creates.borrow(), 0);
    }

    #[test]
    fn loading_fails_closed_and_never_provisions() {
        let backend = MemoryBackend::durable();
        assert_eq!(
            load_lease_store_key(&backend, "store-a").unwrap_err(),
            LeaseKeyError::NotProvisioned
        );
        assert!(backend.entries.borrow().is_empty());
        assert_eq!(*backend.creates.borrow(), 0);
    }

    #[test]
    fn non_durable_backends_are_refused_for_both_operations() {
        let backend = MemoryBackend::default();
        assert!(matches!(
            provision_lease_store_key(&backend, "store-a"),
            Err(LeaseKeyError::NoDurableStore(_))
        ));
        assert!(matches!(
            load_lease_store_key(&backend, "store-a"),
            Err(LeaseKeyError::NoDurableStore(_))
        ));
        assert_eq!(*backend.creates.borrow(), 0);
    }

    #[test]
    fn read_back_mismatch_is_refused() {
        let backend = MemoryBackend {
            durable: true,
            tamper_on_create: Some("cd".repeat(32)),
            ..MemoryBackend::default()
        };
        assert_eq!(
            provision_lease_store_key(&backend, "store-a"),
            Err(LeaseKeyError::ReadBackMismatch)
        );
    }

    #[test]
    fn labels_are_validated() {
        let backend = MemoryBackend::durable();
        for bad in ["", "a b", "a/b", "../x", &"a".repeat(129), "caf\u{e9}"] {
            assert_eq!(
                provision_lease_store_key(&backend, bad),
                Err(LeaseKeyError::InvalidLabel)
            );
        }
        assert!(validate_label(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn key_material_never_appears_in_debug_or_errors() {
        let backend = MemoryBackend::durable();
        provision_lease_store_key(&backend, "store-a").unwrap();
        let hex_key = stored(&backend, "store-a");
        let key = load_lease_store_key(&backend, "store-a").unwrap();
        let debug = format!("{key:?}");
        assert_eq!(debug, "LeaseStoreKey(<redacted>)");
        assert!(!debug.contains(&hex_key));

        let errors = [
            LeaseKeyError::InvalidLabel,
            LeaseKeyError::NoDurableStore("x"),
            LeaseKeyError::NotProvisioned,
            LeaseKeyError::Malformed,
            LeaseKeyError::WeakKey,
            LeaseKeyError::ReadBackMismatch,
            credential_error(
                "read",
                &keyring_core::Error::BadEncoding(hex_key.clone().into_bytes()),
            ),
            LeaseKeyError::Descriptor("x"),
        ];
        for error in errors {
            let text = format!("{error} {error:?}");
            assert!(!text.contains(&hex_key), "error leaked key: {text}");
        }
    }

    #[test]
    fn keyring_store_errors_are_categorized_without_rendering_inner_data() {
        const SENTINEL: &str = "credential-payload-must-stay-private";
        let errors = [
            (
                keyring_core::Error::BadDataFormat(
                    SENTINEL.as_bytes().to_vec(),
                    std::io::Error::other(SENTINEL).into(),
                ),
                "malformed credential data",
            ),
            (
                keyring_core::Error::BadStoreFormat(SENTINEL.to_string()),
                "malformed credential store",
            ),
            (
                keyring_core::Error::NoDefaultStore,
                "no default credential store",
            ),
            (
                keyring_core::Error::NotSupportedByStore(SENTINEL.to_string()),
                "unsupported credential store operation",
            ),
        ];
        for (source, kind) in errors {
            let error = credential_error("read", &source);
            assert_eq!(
                error,
                LeaseKeyError::CredentialStore {
                    operation: "read",
                    kind,
                }
            );
            let display = error.to_string();
            let debug = format!("{error:?}");
            let raw_bytes = format!("{:?}", SENTINEL.as_bytes());
            for rendered in [display, debug] {
                assert!(!rendered.contains(SENTINEL));
                assert!(!rendered.contains(&raw_bytes));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn os_backend_fails_closed_on_linux() {
        let backend = OsLeaseKeyBackend;
        assert!(!backend.is_durable());
        assert!(matches!(
            provision_lease_store_key(&backend, "store-a"),
            Err(LeaseKeyError::NoDurableStore(_))
        ));
        assert!(matches!(
            load_lease_store_key(&backend, "store-a"),
            Err(LeaseKeyError::NoDurableStore(_))
        ));
        assert!(matches!(
            backend.read("lease-0000"),
            Err(LeaseKeyError::NoDurableStore(_))
        ));
    }

    #[test]
    fn os_backend_reports_durability_by_platform() {
        let backend = OsLeaseKeyBackend;
        assert_eq!(
            backend.is_durable(),
            cfg!(any(target_os = "macos", target_os = "windows"))
        );
    }

    #[test]
    fn descriptor_is_value_free_private_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let backend = MemoryBackend::durable();
        assert_eq!(read_lease_key_descriptor(dir.path()).unwrap(), None);
        let written = record_lease_key_descriptor(dir.path(), &backend).unwrap();
        assert_eq!(written.backend, "test-memory");
        let path = dir.path().join(LEASE_KEY_DESCRIPTOR_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, r#"{"version":1,"backend":"test-memory"}"#);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Identical record is accepted; a different backend is refused.
        record_lease_key_descriptor(dir.path(), &backend).unwrap();
        assert!(matches!(
            record_lease_key_descriptor(dir.path(), &OsLeaseKeyBackend),
            Err(LeaseKeyError::Descriptor(_))
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_refuses_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(LEASE_KEY_DESCRIPTOR_FILE)).unwrap();
        assert!(matches!(
            read_lease_key_descriptor(dir.path()),
            Err(LeaseKeyError::Descriptor(_))
        ));
        assert!(matches!(
            record_lease_key_descriptor(dir.path(), &MemoryBackend::durable()),
            Err(LeaseKeyError::Descriptor(_))
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"{}");
    }
}
