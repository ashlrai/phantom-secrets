//! Provider connector packs — signed, declarative provider extensions.
//!
//! Hard-coded provider behavior (validators in [`crate::validator`], sync
//! targets in [`crate::sync`], importers in [`crate::importers`]) cannot cover
//! every provider, and every provider path touches credentials — so packs are
//! deliberately *declarative*: a pack is a signed JSON manifest describing
//! constrained operations the CLI already knows how to sandbox. Packs never
//! execute third-party code in the credential path.
//!
//! # Trust model
//!
//! - A pack is installed explicitly by the operator in a trusted terminal
//!   (`phantom connector add <dir>`). There is no auto-discovery and no
//!   auto-update.
//! - The manifest is Ed25519-signed. The signature is verified against trust
//!   anchors the operator manages under `~/.phantom/connectors/anchors/`
//!   (trust-on-first-use: the first anchor the operator adds becomes the root
//!   they vouch for). Installation refuses unsigned or badly-signed packs.
//! - Installed packs are pinned by the SHA-256 of their manifest; `installed.json`
//!   records the pin so tampering with an installed pack is detectable.
//! - Capabilities are constrained: `validate` packs may only perform HTTPS
//!   checks with the secret value substituted into declared header values;
//!   `sync-target` packs may only push to their declared HTTPS endpoint;
//!   `import-source` packs only describe how to parse a file the operator
//!   hands to `phantom import`. The MCP surface stays value-blind: packs can
//!   never add new ways to exfiltrate values.
//!
//! # Capabilities
//!
//! - `validate`: live credential checks, wired into `phantom validate` as
//!   additional [`crate::validator::SecretValidator`] implementations.
//! - `sync-target`: deployment push targets, addressable as
//!   `phantom sync --platform <pack-name>`.
//! - `import-source`: secret importers, addressable as
//!   `phantom import --from <pack-name>`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Re-exported so CLI commands can name the signing-key type without adding
/// their own ed25519 dependency.
pub use ed25519_dalek::SigningKey as ConnectorSigningKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::PhantomError;
use crate::validator::{SecretValidator, ValidationResult};

/// Current connector manifest schema version. Packs declaring any other
/// version are rejected so future schema changes fail closed.
pub const CONNECTOR_SCHEMA_VERSION: u8 = 1;

/// Placeholder substituted with the live secret value inside declared header
/// values only. It is never valid in URLs, header names, or bodies.
pub const VALUE_PLACEHOLDER: &str = "{value}";

/// Maximum manifest file size accepted (64 KiB — manifests are declarative).
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// Maximum number of secrets pushed to a pack sync target in one call.
const MAX_SYNC_SECRETS: usize = 10_000;

// ── Manifest schema ──────────────────────────────────────────────────────────

/// A connector pack manifest (`connector.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    /// Must equal [`CONNECTOR_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Pack name: lowercase letters, digits, `-`, `_`; 2–64 chars.
    pub name: String,
    /// Pack version (free-form, no path separators).
    pub version: String,
    /// Human-readable description shown by `phantom connector list`.
    pub description: String,
    /// Constrained capabilities this pack declares.
    pub capabilities: Vec<Capability>,
}

/// One constrained capability declared by a pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Capability {
    /// Live credential validators (HTTP checks against provider APIs).
    Validate { validators: Vec<HttpValidatorSpec> },
    /// Deployment sync targets (HTTPS push of vault secrets).
    SyncTarget { targets: Vec<SyncTargetSpec> },
    /// Secret importers (file-format parsers for `phantom import`).
    ImportSource { sources: Vec<ImportSourceSpec> },
}

/// HTTP methods a pack validator or sync target may use.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
}

/// A declarative live-credential check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpValidatorSpec {
    /// Validator name shown in validation reports (e.g. `"stripe-pack"`).
    pub name: String,
    /// Secret-name prefixes this validator handles (case-insensitive).
    /// A secret is checked when its name starts with any of these.
    pub key_prefixes: Vec<String>,
    /// HTTP method for the check.
    pub method: HttpMethod,
    /// HTTPS URL of the provider check endpoint. Must not contain `{value}`:
    /// values travel in headers only, never in URLs that could land in logs.
    pub url: String,
    /// Extra headers. Values may contain `{value}`, substituted with the
    /// live secret at check time. Header *names* must not contain it.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// HTTP statuses that mean "credential valid". Defaults to `[200]`.
    #[serde(default = "default_expect_status")]
    pub expect_status: Vec<u16>,
}

fn default_expect_status() -> Vec<u16> {
    vec![200]
}

/// A declarative deployment sync target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SyncTargetSpec {
    /// Target name used as `phantom sync --platform <name>`.
    pub name: String,
    /// HTTP method for the push (POST or PUT).
    pub method: HttpMethod,
    /// HTTPS endpoint receiving the secret map.
    pub url: String,
    /// Header carrying the pack credential (e.g. `"Authorization"`).
    pub auth_header: String,
    /// Scheme prepended to the credential (e.g. `"Bearer"`; empty = none).
    #[serde(default)]
    pub auth_scheme: String,
    /// Vault secret name holding this target's API credential. The operator
    /// stores it with `phantom add`; the pack never ships a credential.
    pub credential_name: String,
}

/// A declarative secret-import source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ImportSourceSpec {
    /// Source name used as `phantom import --from <name>`.
    pub name: String,
    /// File format the source parses.
    pub format: ImportFormat,
    /// For `json-map`: JSON pointer (RFC 6901) to the object holding the
    /// name→value map, e.g. `"/secrets"`. Empty means the document root.
    #[serde(default)]
    pub pointer: String,
}

/// File formats a pack import source can parse.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ImportFormat {
    /// Classic `KEY=value` dotenv files.
    Dotenv,
    /// A JSON document (or sub-object at `pointer`) mapping names to values.
    JsonMap,
}

// ── Manifest validation ──────────────────────────────────────────────────────

fn valid_pack_name(name: &str) -> bool {
    let len = name.len();
    (2..=64).contains(&len)
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && !version.contains(['/', '\\', '\0'])
        && version.chars().all(|c| !c.is_control())
}

fn valid_https_url(url: &str) -> bool {
    url.starts_with("https://") && url.len() > "https://".len() && !url.contains(VALUE_PLACEHOLDER)
}

fn validate_manifest(m: &ConnectorManifest) -> Result<(), PhantomError> {
    let bad =
        |msg: String| PhantomError::ConfigParseError(format!("invalid connector manifest: {msg}"));
    if m.schema_version != CONNECTOR_SCHEMA_VERSION {
        return Err(bad(format!(
            "unsupported schema_version {} (expected {})",
            m.schema_version, CONNECTOR_SCHEMA_VERSION
        )));
    }
    if !valid_pack_name(&m.name) {
        return Err(bad(format!(
            "bad pack name {:?}: use 2-64 chars of lowercase letters, digits, '-', '_'",
            m.name
        )));
    }
    if !valid_version(&m.version) {
        return Err(bad(format!("bad pack version {:?}", m.version)));
    }
    if m.description.trim().is_empty() || m.description.len() > 500 {
        return Err(bad("description must be 1-500 chars".to_string()));
    }
    if m.capabilities.is_empty() {
        return Err(bad("pack declares no capabilities".to_string()));
    }
    for cap in &m.capabilities {
        match cap {
            Capability::Validate { validators } => {
                if validators.is_empty() {
                    return Err(bad("validate capability declares no validators".to_string()));
                }
                for v in validators {
                    if v.name.trim().is_empty() {
                        return Err(bad("validator name must not be empty".to_string()));
                    }
                    if v.key_prefixes.is_empty()
                        || v.key_prefixes.iter().any(|p| p.trim().is_empty())
                    {
                        return Err(bad(format!(
                            "validator {:?} needs at least one non-empty key prefix",
                            v.name
                        )));
                    }
                    if !valid_https_url(&v.url) {
                        return Err(bad(format!(
                            "validator {:?}: url must be https:// and must not contain {{value}}",
                            v.name
                        )));
                    }
                    for (k, val) in &v.headers {
                        if k.trim().is_empty() || k.contains(VALUE_PLACEHOLDER) {
                            return Err(bad(format!(
                                "validator {:?}: header names must not be empty or contain {{value}}",
                                v.name
                            )));
                        }
                        let _ = val;
                    }
                    if v.expect_status.is_empty() {
                        return Err(bad(format!(
                            "validator {:?}: expect_status must not be empty",
                            v.name
                        )));
                    }
                }
            }
            Capability::SyncTarget { targets } => {
                if targets.is_empty() {
                    return Err(bad("sync-target capability declares no targets".to_string()));
                }
                for t in targets {
                    if t.name.trim().is_empty() || !valid_pack_name(&t.name) {
                        return Err(bad(format!("bad sync target name {:?}", t.name)));
                    }
                    if !matches!(t.method, HttpMethod::Post | HttpMethod::Put) {
                        return Err(bad(format!(
                            "sync target {:?}: method must be POST or PUT",
                            t.name
                        )));
                    }
                    if !valid_https_url(&t.url) {
                        return Err(bad(format!(
                            "sync target {:?}: url must be https:// and must not contain {{value}}",
                            t.name
                        )));
                    }
                    if t.auth_header.trim().is_empty() {
                        return Err(bad(format!(
                            "sync target {:?}: auth_header must not be empty",
                            t.name
                        )));
                    }
                    if t.credential_name.trim().is_empty() {
                        return Err(bad(format!(
                            "sync target {:?}: credential_name must not be empty",
                            t.name
                        )));
                    }
                }
            }
            Capability::ImportSource { sources } => {
                if sources.is_empty() {
                    return Err(bad(
                        "import-source capability declares no sources".to_string()
                    ));
                }
                for s in sources {
                    if s.name.trim().is_empty() || !valid_pack_name(&s.name) {
                        return Err(bad(format!("bad import source name {:?}", s.name)));
                    }
                    if !s.pointer.is_empty() && !s.pointer.starts_with('/') {
                        return Err(bad(format!(
                            "import source {:?}: pointer must be empty or start with '/'",
                            s.name
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

// ── Paths ────────────────────────────────────────────────────────────────────

/// `~/.phantom/connectors` — root of the local connector-pack store.
pub fn connectors_dir() -> Result<PathBuf, PhantomError> {
    let home = crate::home::home_dir()
        .map_err(|e| PhantomError::Other(format!("cannot resolve home directory: {e}")))?;
    Ok(home.join(".phantom").join("connectors"))
}

fn anchors_dir() -> Result<PathBuf, PhantomError> {
    Ok(connectors_dir()?.join("anchors"))
}

fn packs_dir() -> Result<PathBuf, PhantomError> {
    Ok(connectors_dir()?.join("packs"))
}

fn installed_index_path() -> Result<PathBuf, PhantomError> {
    Ok(connectors_dir()?.join("installed.json"))
}

// ── Trust anchors ────────────────────────────────────────────────────────────

/// Key id = first 8 hex chars of SHA-256(pubkey bytes).
fn key_id_for_pubkey(pubkey: &VerifyingKey) -> String {
    let digest = Sha256::digest(pubkey.as_bytes());
    hex::encode(digest)[..8].to_string()
}

/// Register a trust anchor (hex-encoded 32-byte Ed25519 public key).
/// The first anchor added is the trust-on-first-use root the operator vouches
/// for; every pack signature must verify against a registered anchor.
pub fn add_anchor(pubkey_hex: &str) -> Result<String, PhantomError> {
    let bytes = hex::decode(pubkey_hex.trim()).map_err(|_| {
        PhantomError::ConfigParseError("anchor key must be hex-encoded".to_string())
    })?;
    let key = VerifyingKey::try_from(bytes.as_slice()).map_err(|_| {
        PhantomError::ConfigParseError(
            "anchor key must be a 32-byte Ed25519 public key".to_string(),
        )
    })?;
    let dir = anchors_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| PhantomError::Other(format!("cannot create anchors dir: {e}")))?;
    let key_id = key_id_for_pubkey(&key);
    let path = dir.join(format!("{key_id}.pub"));
    // Anchor files are public keys — world-readable is fine, but refuse to
    // silently overwrite a different key under an existing id.
    if path.exists() {
        let existing = std::fs::read_to_string(&path)
            .map_err(|e| PhantomError::Other(format!("cannot read anchor: {e}")))?;
        if existing.trim().to_lowercase() != pubkey_hex.trim().to_lowercase() {
            return Err(PhantomError::ConfigParseError(format!(
                "anchor id {key_id} already registered with a different key; remove it first"
            )));
        }
        return Ok(key_id);
    }
    std::fs::write(&path, pubkey_hex.trim().to_lowercase())
        .map_err(|e| PhantomError::Other(format!("cannot write anchor: {e}")))?;
    Ok(key_id)
}

/// List registered trust-anchor key ids.
pub fn list_anchors() -> Result<Vec<String>, PhantomError> {
    let dir = anchors_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| PhantomError::Other(format!("cannot list anchors: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| PhantomError::Other(format!("cannot list anchors: {e}")))?;
        if entry.path().extension().and_then(|e| e.to_str()) == Some("pub") {
            if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                ids.push(stem.to_string());
            }
        }
    }
    ids.sort();
    Ok(ids)
}

/// Remove a trust anchor by key id. Installed packs stay installed; they are
/// re-verified against remaining anchors on next use.
pub fn remove_anchor(key_id: &str) -> Result<(), PhantomError> {
    let path = anchors_dir()?.join(format!("{key_id}.pub"));
    if !path.exists() {
        return Err(PhantomError::ConfigParseError(format!(
            "no trust anchor with id {key_id:?}; see `phantom connector anchor list`"
        )));
    }
    std::fs::remove_file(&path)
        .map_err(|e| PhantomError::Other(format!("cannot remove anchor: {e}")))?;
    Ok(())
}

fn load_anchors() -> Result<Vec<(String, VerifyingKey)>, PhantomError> {
    let dir = anchors_dir()?;
    let mut anchors = Vec::new();
    if !dir.exists() {
        return Ok(anchors);
    }
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| PhantomError::Other(format!("cannot list anchors: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| PhantomError::Other(format!("cannot list anchors: {e}")))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        let hex_key = std::fs::read_to_string(&path)
            .map_err(|e| PhantomError::Other(format!("cannot read anchor: {e}")))?;
        let bytes = hex::decode(hex_key.trim()).map_err(|_| {
            PhantomError::ConfigParseError(format!("anchor file {} is not hex", path.display()))
        })?;
        let key = VerifyingKey::try_from(bytes.as_slice()).map_err(|_| {
            PhantomError::ConfigParseError(format!(
                "anchor file {} is not a 32-byte key",
                path.display()
            ))
        })?;
        let key_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        anchors.push((key_id, key));
    }
    Ok(anchors)
}

// ── Signing & verification ───────────────────────────────────────────────────

/// Canonical manifest bytes: `serde_json::to_vec` over the struct emits fields
/// in declaration order and `BTreeMap` headers sorted — deterministic.
pub fn canonical_manifest_bytes(manifest: &ConnectorManifest) -> Result<Vec<u8>, PhantomError> {
    serde_json::to_vec(manifest)
        .map_err(|e| PhantomError::ConfigParseError(format!("cannot serialize manifest: {e}")))
}

/// Parse a 64-hex-char Ed25519 seed into a signing key.
/// The seed is secret material: callers must source it from an env var or a
/// 0600 file, never from argv (argv is observable) and never from the repo.
pub fn signing_key_from_hex(hex_seed: &str) -> Result<SigningKey, PhantomError> {
    let bytes = hex::decode(hex_seed.trim())
        .map_err(|_| PhantomError::ConfigParseError("signing key is not valid hex".to_string()))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        PhantomError::ConfigParseError(
            "signing key must be 32 bytes (64 hex chars), an Ed25519 seed".to_string(),
        )
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Sign a manifest. Returns the detached signature envelope
/// `<key-id>:<hex-signature>` written to `connector.sig`.
pub fn sign_manifest(
    manifest: &ConnectorManifest,
    signing_key: &SigningKey,
) -> Result<String, PhantomError> {
    validate_manifest(manifest)?;
    let bytes = canonical_manifest_bytes(manifest)?;
    let sig: Signature = signing_key.sign(&bytes);
    let key_id = key_id_for_pubkey(&signing_key.verifying_key());
    Ok(format!("{key_id}:{}", hex::encode(sig.to_bytes())))
}

/// Read `connector.json` + `connector.sig` from `dir`, verify the signature
/// against registered trust anchors, and validate manifest semantics.
/// Returns the manifest on success.
pub fn verify_pack_dir(dir: &Path) -> Result<ConnectorManifest, PhantomError> {
    let manifest_path = dir.join("connector.json");
    let sig_path = dir.join("connector.sig");
    let meta = std::fs::metadata(&manifest_path).map_err(|_| {
        PhantomError::ConfigParseError(format!(
            "pack dir {} has no connector.json; run `phantom connector pack init` to scaffold one",
            dir.display()
        ))
    })?;
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(PhantomError::ConfigParseError(format!(
            "connector.json exceeds {} bytes — refusing",
            MAX_MANIFEST_BYTES
        )));
    }
    let raw = std::fs::read(&manifest_path)
        .map_err(|e| PhantomError::Other(format!("cannot read connector.json: {e}")))?;
    let manifest: ConnectorManifest = serde_json::from_slice(&raw).map_err(|e| {
        PhantomError::ConfigParseError(format!("connector.json is not a valid manifest: {e}"))
    })?;
    validate_manifest(&manifest)?;

    let envelope = std::fs::read_to_string(&sig_path).map_err(|_| {
        PhantomError::ConfigParseError(format!(
            "pack dir {} has no connector.sig; sign it with `phantom connector pack sign`",
            dir.display()
        ))
    })?;
    let (key_id, sig_hex) = envelope.trim().split_once(':').ok_or_else(|| {
        PhantomError::ConfigParseError(
            "connector.sig must look like <key-id>:<hex-signature>".to_string(),
        )
    })?;
    let sig_bytes = hex::decode(sig_hex.trim()).map_err(|_| {
        PhantomError::ConfigParseError("connector.sig signature is not hex".to_string())
    })?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| {
        PhantomError::ConfigParseError(
            "connector.sig signature is not a valid Ed25519 signature".to_string(),
        )
    })?;

    let anchors = load_anchors()?;
    if anchors.is_empty() {
        return Err(PhantomError::ConfigParseError(
            "no connector trust anchors registered; add one with `phantom connector anchor add --key <hex>` before installing packs".to_string(),
        ));
    }
    let anchor = anchors.iter().find(|(id, _)| id == key_id).ok_or_else(|| {
        PhantomError::ConfigParseError(format!(
            "pack signature key id {key_id:?} matches no registered trust anchor; see `phantom connector anchor list`"
        ))
    })?;
    // Verify against the canonical bytes of the *parsed* manifest so that
    // formatting differences cannot smuggle unsigned content past the check.
    let canonical = canonical_manifest_bytes(&manifest)?;
    anchor.1.verify(&canonical, &sig).map_err(|_| {
        PhantomError::ConfigParseError(
            "pack signature verification FAILED — refusing to install".to_string(),
        )
    })?;
    Ok(manifest)
}

// ── Installed-pack store ─────────────────────────────────────────────────────

/// Metadata recorded for an installed pack (hash-pinned).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstalledPack {
    pub name: String,
    pub version: String,
    pub description: String,
    /// SHA-256 of the installed `connector.json` — tampering is detectable.
    pub sha256_pin: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InstalledIndex {
    #[serde(default)]
    packs: BTreeMap<String, InstalledPack>,
}

fn read_index() -> Result<InstalledIndex, PhantomError> {
    let path = installed_index_path()?;
    if !path.exists() {
        return Ok(InstalledIndex::default());
    }
    let raw = std::fs::read(&path)
        .map_err(|e| PhantomError::Other(format!("cannot read installed.json: {e}")))?;
    serde_json::from_slice(&raw).map_err(|e| {
        PhantomError::ConfigParseError(format!(
            "installed.json is corrupt: {e}; back it up and remove it to reset"
        ))
    })
}

fn write_index(index: &InstalledIndex) -> Result<(), PhantomError> {
    let dir = connectors_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| PhantomError::Other(format!("cannot create connectors dir: {e}")))?;
    let path = installed_index_path()?;
    let raw = serde_json::to_vec_pretty(index)
        .map_err(|e| PhantomError::ConfigParseError(format!("cannot serialize index: {e}")))?;
    std::fs::write(&path, raw)
        .map_err(|e| PhantomError::Other(format!("cannot write installed.json: {e}")))?;
    Ok(())
}

fn capability_names(manifest: &ConnectorManifest) -> Vec<String> {
    manifest
        .capabilities
        .iter()
        .map(|c| match c {
            Capability::Validate { .. } => "validate".to_string(),
            Capability::SyncTarget { .. } => "sync-target".to_string(),
            Capability::ImportSource { .. } => "import-source".to_string(),
        })
        .collect()
}

/// Verify and install a pack from `source_dir` (containing `connector.json` +
/// `connector.sig`). Fails closed on any signature or schema problem.
pub fn install_pack(source_dir: &Path) -> Result<InstalledPack, PhantomError> {
    let manifest = verify_pack_dir(source_dir)?;
    let raw = std::fs::read(source_dir.join("connector.json"))
        .map_err(|e| PhantomError::Other(format!("cannot re-read connector.json: {e}")))?;
    let pin = hex::encode(Sha256::digest(&raw));

    let dest = packs_dir()?.join(&manifest.name).join(&manifest.version);
    std::fs::create_dir_all(&dest)
        .map_err(|e| PhantomError::Other(format!("cannot create pack dir: {e}")))?;
    std::fs::write(dest.join("connector.json"), &raw)
        .map_err(|e| PhantomError::Other(format!("cannot install connector.json: {e}")))?;
    let sig = std::fs::read(source_dir.join("connector.sig"))
        .map_err(|e| PhantomError::Other(format!("cannot re-read connector.sig: {e}")))?;
    std::fs::write(dest.join("connector.sig"), sig)
        .map_err(|e| PhantomError::Other(format!("cannot install connector.sig: {e}")))?;

    let installed = InstalledPack {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        description: manifest.description.clone(),
        sha256_pin: pin,
        capabilities: capability_names(&manifest),
    };
    let mut index = read_index()?;
    index.packs.insert(manifest.name.clone(), installed.clone());
    write_index(&index)?;
    Ok(installed)
}

/// List installed packs (index order = alphabetical by name).
pub fn list_packs() -> Result<Vec<InstalledPack>, PhantomError> {
    Ok(read_index()?.packs.into_values().collect())
}

/// Remove an installed pack. The trust anchor is untouched.
pub fn remove_pack(name: &str) -> Result<(), PhantomError> {
    let mut index = read_index()?;
    let removed = index.packs.remove(name);
    if removed.is_none() {
        return Err(PhantomError::ConfigParseError(format!(
            "no installed pack named {name:?}; see `phantom connector list`"
        )));
    }
    write_index(&index)?;
    let dir = packs_dir()?.join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| PhantomError::Other(format!("cannot remove pack dir: {e}")))?;
    }
    Ok(())
}

/// Load an installed pack's manifest, re-verifying its hash pin so on-disk
/// tampering after install is detected.
pub fn load_pack_manifest(name: &str) -> Result<ConnectorManifest, PhantomError> {
    let index = read_index()?;
    let installed = index.packs.get(name).ok_or_else(|| {
        PhantomError::ConfigParseError(format!("no installed pack named {name:?}"))
    })?;
    let path = packs_dir()?
        .join(&installed.name)
        .join(&installed.version)
        .join("connector.json");
    let raw = std::fs::read(&path)
        .map_err(|e| PhantomError::Other(format!("cannot read installed manifest: {e}")))?;
    let pin = hex::encode(Sha256::digest(&raw));
    if pin != installed.sha256_pin {
        return Err(PhantomError::ConfigParseError(format!(
            "installed pack {name:?} FAILED its hash-pin check — the manifest changed after install; remove and reinstall it"
        )));
    }
    let manifest: ConnectorManifest = serde_json::from_slice(&raw).map_err(|e| {
        PhantomError::ConfigParseError(format!("installed manifest is corrupt: {e}"))
    })?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

// ── Pack validators (wired into `phantom validate`) ──────────────────────────

/// A [`SecretValidator`] built from a pack's `validate` capability.
pub struct PackValidator {
    pack_name: String,
    spec: HttpValidatorSpec,
}

impl PackValidator {
    fn new(pack_name: String, spec: HttpValidatorSpec) -> Self {
        Self { pack_name, spec }
    }

    /// Validator display name: `<pack>/<validator>`.
    pub fn display_name(&self) -> String {
        format!("{}/{}", self.pack_name, self.spec.name)
    }
}

impl SecretValidator for PackValidator {
    fn name(&self) -> &str {
        &self.spec.name
    }

    fn matches(&self, key: &str) -> bool {
        let upper = key.to_uppercase();
        self.spec
            .key_prefixes
            .iter()
            .any(|p| upper.starts_with(&p.to_uppercase()))
    }

    fn validate(
        &self,
        key: &str,
        secret_value: &Zeroizing<String>,
        timeout: Duration,
    ) -> ValidationResult {
        if !self.matches(key) {
            return ValidationResult::NotApplicable;
        }
        let client = match crate::provider_http::blocking_client(timeout) {
            Ok(c) => c,
            Err(e) => {
                return ValidationResult::Unreachable {
                    reason: format!("pack {}/{}: {e}", self.pack_name, self.spec.name),
                }
            }
        };
        let mut req = match self.spec.method {
            HttpMethod::Get => client.get(&self.spec.url),
            HttpMethod::Head => client.head(&self.spec.url),
            HttpMethod::Post => client.post(&self.spec.url),
            HttpMethod::Put => client.put(&self.spec.url),
        };
        // Substitute the live value into declared header values only.
        // Header names and the URL were validated at pack-install time.
        for (name, template) in &self.spec.headers {
            let value = template.replace(VALUE_PLACEHOLDER, secret_value.as_str());
            req = req.header(name.as_str(), value);
        }
        let response = match req.send() {
            Ok(r) => r,
            Err(e) => {
                return ValidationResult::Unreachable {
                    reason: format!(
                        "pack {}/{}: request failed: {}",
                        self.pack_name,
                        self.spec.name,
                        sanitize_reqwest_error(&e)
                    ),
                }
            }
        };
        let status = response.status().as_u16();
        if self.spec.expect_status.contains(&status) {
            ValidationResult::Valid
        } else if status == 401 || status == 403 {
            ValidationResult::Invalid {
                reason: format!(
                    "pack {}/{}: provider rejected the credential (HTTP {status})",
                    self.pack_name, self.spec.name
                ),
            }
        } else {
            ValidationResult::Unreachable {
                reason: format!(
                    "pack {}/{}: unexpected HTTP {status}",
                    self.pack_name, self.spec.name
                ),
            }
        }
    }
}

/// Strip potentially value-bearing detail from transport errors.
fn sanitize_reqwest_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".to_string()
    } else if e.is_connect() {
        "connection failed".to_string()
    } else {
        "request error".to_string()
    }
}

/// Build one boxed validator per `validate` spec in every installed pack.
/// Pack validators are appended after the built-in ones by `phantom validate`.
pub fn pack_validators() -> Vec<Box<dyn SecretValidator>> {
    let mut out: Vec<Box<dyn SecretValidator>> = Vec::new();
    let packs = match list_packs() {
        Ok(p) => p,
        Err(_) => return out,
    };
    for installed in packs {
        let manifest = match load_pack_manifest(&installed.name) {
            Ok(m) => m,
            Err(_) => continue, // fail-closed per pack: skip, never half-load
        };
        for cap in &manifest.capabilities {
            if let Capability::Validate { validators } = cap {
                for spec in validators {
                    out.push(Box::new(PackValidator::new(
                        installed.name.clone(),
                        spec.clone(),
                    )));
                }
            }
        }
    }
    out
}

// ── Import sources ───────────────────────────────────────────────────────────

/// Find an installed pack's import source by name.
pub fn find_import_source(name: &str) -> Result<Option<(String, ImportSourceSpec)>, PhantomError> {
    for installed in list_packs()? {
        let manifest = load_pack_manifest(&installed.name)?;
        for cap in &manifest.capabilities {
            if let Capability::ImportSource { sources } = cap {
                for source in sources {
                    if source.name == name {
                        return Ok(Some((installed.name.clone(), source.clone())));
                    }
                }
            }
        }
    }
    Ok(None)
}

fn valid_secret_name(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

/// Parse an import file with a pack's import-source spec.
/// Returns name→value pairs; values are the operator's own file content.
pub fn parse_import_source(
    spec: &ImportSourceSpec,
    bytes: &[u8],
) -> Result<BTreeMap<String, String>, PhantomError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        PhantomError::ConfigParseError("import file is not valid UTF-8".to_string())
    })?;
    let mut map = BTreeMap::new();
    match spec.format {
        ImportFormat::Dotenv => {
            for (lineno, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Strip optional `export ` prefix.
                let line = line.strip_prefix("export ").unwrap_or(line);
                let (k, v) = line.split_once('=').ok_or_else(|| {
                    PhantomError::ConfigParseError(format!(
                        "import source {:?}: line {} is not KEY=value",
                        spec.name,
                        lineno + 1
                    ))
                })?;
                let key = k.trim();
                if !valid_secret_name(key) {
                    return Err(PhantomError::ConfigParseError(format!(
                        "import source {:?}: invalid secret name {key:?} on line {}",
                        spec.name,
                        lineno + 1
                    )));
                }
                map.insert(key.to_string(), unquote(v.trim()));
            }
        }
        ImportFormat::JsonMap => {
            let doc: serde_json::Value = serde_json::from_str(text).map_err(|e| {
                PhantomError::ConfigParseError(format!(
                    "import source {:?}: invalid JSON: {e}",
                    spec.name
                ))
            })?;
            let target = if spec.pointer.is_empty() {
                &doc
            } else {
                doc.pointer(&spec.pointer).ok_or_else(|| {
                    PhantomError::ConfigParseError(format!(
                        "import source {:?}: pointer {:?} not found in document",
                        spec.name, spec.pointer
                    ))
                })?
            };
            let obj = target.as_object().ok_or_else(|| {
                PhantomError::ConfigParseError(format!(
                    "import source {:?}: pointer {:?} does not select an object",
                    spec.name, spec.pointer
                ))
            })?;
            for (k, v) in obj {
                if !valid_secret_name(k) {
                    return Err(PhantomError::ConfigParseError(format!(
                        "import source {:?}: invalid secret name {k:?}",
                        spec.name
                    )));
                }
                let value = v.as_str().ok_or_else(|| {
                    PhantomError::ConfigParseError(format!(
                        "import source {:?}: value for {k:?} is not a string",
                        spec.name
                    ))
                })?;
                map.insert(k.clone(), value.to_string());
            }
        }
    }
    Ok(map)
}

fn unquote(s: &str) -> String {
    // Strip a trailing inline comment first so it cannot break quote pairing.
    let s = s.split(" #").next().unwrap_or(s).trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

// ── Sync targets ─────────────────────────────────────────────────────────────

/// Find an installed pack's sync target by name.
pub fn find_sync_target(name: &str) -> Result<Option<(String, SyncTargetSpec)>, PhantomError> {
    for installed in list_packs()? {
        let manifest = load_pack_manifest(&installed.name)?;
        for cap in &manifest.capabilities {
            if let Capability::SyncTarget { targets } = cap {
                for target in targets {
                    if target.name == name {
                        return Ok(Some((installed.name.clone(), target.clone())));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Report for a pack sync-target push.
#[derive(Debug, Clone, Serialize)]
pub struct SyncPushReport {
    pub pack: String,
    pub target: String,
    pub pushed: usize,
    pub skipped_empty: usize,
}

/// Push secrets to a pack's sync target.
///
/// `credential` is the target's API credential (from the vault, via
/// `credential_name`); `secrets` are the vault secrets to push. Values are
/// zeroized after use and never logged.
pub fn push_sync_target(
    pack_name: &str,
    spec: &SyncTargetSpec,
    credential: &Zeroizing<String>,
    secrets: &[(String, Zeroizing<String>)],
) -> Result<SyncPushReport, PhantomError> {
    if secrets.len() > MAX_SYNC_SECRETS {
        return Err(PhantomError::ConfigParseError(format!(
            "sync target {:?}: refusing to push {} secrets (limit {})",
            spec.name,
            secrets.len(),
            MAX_SYNC_SECRETS
        )));
    }
    let timeout = Duration::from_secs(30);
    let client =
        crate::provider_http::blocking_client(timeout).map_err(PhantomError::ConfigParseError)?;
    let mut body = BTreeMap::new();
    let mut skipped_empty = 0;
    for (name, value) in secrets {
        if value.as_str().is_empty() {
            skipped_empty += 1;
            continue;
        }
        body.insert(name.clone(), value.as_str().to_string());
    }
    let auth_value = if spec.auth_scheme.trim().is_empty() {
        credential.as_str().to_string()
    } else {
        format!("{} {}", spec.auth_scheme.trim(), credential.as_str())
    };
    let mut req = match spec.method {
        HttpMethod::Post => client.post(&spec.url),
        HttpMethod::Put => client.put(&spec.url),
        _ => {
            return Err(PhantomError::ConfigParseError(format!(
                "sync target {:?}: unsupported method for sync",
                spec.name
            )))
        }
    };
    req = req.header(spec.auth_header.as_str(), auth_value);
    let response = req.json(&body).send().map_err(|e| {
        PhantomError::ConfigParseError(format!(
            "sync target {:?}: push failed: {}",
            spec.name,
            sanitize_reqwest_error(&e)
        ))
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PhantomError::ConfigParseError(format!(
            "sync target {:?}: provider returned HTTP {}",
            spec.name,
            status.as_u16()
        )));
    }
    Ok(SyncPushReport {
        pack: pack_name.to_string(),
        target: spec.name.clone(),
        pushed: body.len(),
        skipped_empty,
    })
}

// ── Pack scaffolding ─────────────────────────────────────────────────────────

/// Scaffold a new pack directory with a template `connector.json`.
/// The manifest is unsigned — sign it with [`sign_manifest`] before install.
pub fn scaffold_pack(dir: &Path, name: &str) -> Result<PathBuf, PhantomError> {
    if !valid_pack_name(name) {
        return Err(PhantomError::ConfigParseError(format!(
            "bad pack name {name:?}: use 2-64 chars of lowercase letters, digits, '-', '_'"
        )));
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| PhantomError::Other(format!("cannot create pack dir: {e}")))?;
    let manifest = ConnectorManifest {
        schema_version: CONNECTOR_SCHEMA_VERSION,
        name: name.to_string(),
        version: "0.1.0".to_string(),
        description: format!("Connector pack {name} — edit this description"),
        capabilities: vec![Capability::Validate {
            validators: vec![HttpValidatorSpec {
                name: "example".to_string(),
                key_prefixes: vec!["EXAMPLE_".to_string()],
                method: HttpMethod::Get,
                url: "https://api.example.com/v1/check".to_string(),
                headers: BTreeMap::from([(
                    "Authorization".to_string(),
                    "Bearer {value}".to_string(),
                )]),
                expect_status: vec![200],
            }],
        }],
    };
    let path = dir.join("connector.json");
    let raw = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| PhantomError::ConfigParseError(format!("cannot serialize template: {e}")))?;
    std::fs::write(&path, raw)
        .map_err(|e| PhantomError::Other(format!("cannot write template: {e}")))?;
    Ok(path)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> SigningKey {
        // Deterministic test key — never a real anchor.
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sample_manifest() -> ConnectorManifest {
        ConnectorManifest {
            schema_version: CONNECTOR_SCHEMA_VERSION,
            name: "acme".to_string(),
            version: "1.2.3".to_string(),
            description: "Acme provider pack".to_string(),
            capabilities: vec![
                Capability::Validate {
                    validators: vec![HttpValidatorSpec {
                        name: "acme-check".to_string(),
                        key_prefixes: vec!["ACME_".to_string()],
                        method: HttpMethod::Get,
                        url: "https://api.acme.test/v1/whoami".to_string(),
                        headers: BTreeMap::from([(
                            "Authorization".to_string(),
                            "Bearer {value}".to_string(),
                        )]),
                        expect_status: vec![200],
                    }],
                },
                Capability::SyncTarget {
                    targets: vec![SyncTargetSpec {
                        name: "acme-deploy".to_string(),
                        method: HttpMethod::Put,
                        url: "https://api.acme.test/v1/env".to_string(),
                        auth_header: "Authorization".to_string(),
                        auth_scheme: "Bearer".to_string(),
                        credential_name: "ACME_API_TOKEN".to_string(),
                    }],
                },
                Capability::ImportSource {
                    sources: vec![ImportSourceSpec {
                        name: "acme-export".to_string(),
                        format: ImportFormat::JsonMap,
                        pointer: "/secrets".to_string(),
                    }],
                },
            ],
        }
    }

    #[test]
    fn manifest_validation_accepts_sample() {
        assert!(validate_manifest(&sample_manifest()).is_ok());
    }

    #[test]
    fn manifest_validation_rejects_bad_schema_version() {
        let mut m = sample_manifest();
        m.schema_version = 99;
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn manifest_validation_rejects_bad_names() {
        let mut m = sample_manifest();
        for bad in ["A", "has space", "UPPER", "a/b", "x"] {
            m.name = bad.to_string();
            assert!(validate_manifest(&m).is_err(), "name {bad:?} accepted");
        }
    }

    #[test]
    fn manifest_validation_rejects_http_url_and_value_in_url() {
        let mut m = sample_manifest();
        if let Capability::Validate { validators } = &mut m.capabilities[0] {
            validators[0].url = "http://api.acme.test/v1/whoami".to_string();
        }
        assert!(validate_manifest(&m).is_err());

        let mut m = sample_manifest();
        if let Capability::Validate { validators } = &mut m.capabilities[0] {
            validators[0].url = "https://api.acme.test/v1/{value}".to_string();
        }
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn manifest_validation_rejects_value_in_header_name() {
        let mut m = sample_manifest();
        if let Capability::Validate { validators } = &mut m.capabilities[0] {
            validators[0].headers = BTreeMap::from([("{value}".to_string(), "x".to_string())]);
        }
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = test_keypair();
        let manifest = sample_manifest();
        let envelope = sign_manifest(&manifest, &key).expect("sign");
        let (key_id, sig_hex) = envelope.split_once(':').unwrap();
        assert_eq!(key_id.len(), 8);
        let sig = Signature::try_from(hex::decode(sig_hex).unwrap().as_slice()).unwrap();
        key.verifying_key()
            .verify(&canonical_manifest_bytes(&manifest).unwrap(), &sig)
            .expect("verify");
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let key = test_keypair();
        let manifest = sample_manifest();
        let envelope = sign_manifest(&manifest, &key).expect("sign");
        let (_, sig_hex) = envelope.split_once(':').unwrap();
        let sig = Signature::try_from(hex::decode(sig_hex).unwrap().as_slice()).unwrap();
        let mut tampered = manifest.clone();
        tampered.description = "evil".to_string();
        assert!(key
            .verifying_key()
            .verify(&canonical_manifest_bytes(&tampered).unwrap(), &sig)
            .is_err());
    }

    #[test]
    fn parse_import_source_dotenv() {
        let spec = ImportSourceSpec {
            name: "t".to_string(),
            format: ImportFormat::Dotenv,
            pointer: String::new(),
        };
        let bytes = b"# comment\nexport FOO=bar\nBAZ=\"quoted value\" # trailing\nEMPTY=\n";
        let map = parse_import_source(&spec, bytes).expect("parse");
        assert_eq!(map.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(map.get("BAZ").map(String::as_str), Some("quoted value"));
        assert_eq!(map.get("EMPTY").map(String::as_str), Some(""));
    }

    #[test]
    fn parse_import_source_dotenv_rejects_bad_names() {
        let spec = ImportSourceSpec {
            name: "t".to_string(),
            format: ImportFormat::Dotenv,
            pointer: String::new(),
        };
        assert!(parse_import_source(&spec, b"lowercase=x\n").is_err());
        assert!(parse_import_source(&spec, b"NOEQUALS\n").is_err());
    }

    #[test]
    fn parse_import_source_json_map() {
        let spec = ImportSourceSpec {
            name: "t".to_string(),
            format: ImportFormat::JsonMap,
            pointer: "/secrets".to_string(),
        };
        let bytes = br#"{"meta": 1, "secrets": {"AAA": "1", "BBB": "2"}}"#;
        let map = parse_import_source(&spec, bytes).expect("parse");
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("AAA").map(String::as_str), Some("1"));

        // Root pointer.
        let spec_root = ImportSourceSpec {
            name: "t".to_string(),
            format: ImportFormat::JsonMap,
            pointer: String::new(),
        };
        let bytes = br#"{"AAA": "1"}"#;
        let map = parse_import_source(&spec_root, bytes).expect("parse");
        assert_eq!(map.len(), 1);

        // Missing pointer fails closed.
        assert!(parse_import_source(&spec, br#"{"nope": {}}"#).is_err());
        // Non-string values fail closed.
        assert!(parse_import_source(&spec_root, br#"{"AAA": 1}"#).is_err());
    }

    #[test]
    fn pack_validator_matches_prefixes_case_insensitively() {
        let spec = HttpValidatorSpec {
            name: "v".to_string(),
            key_prefixes: vec!["ACME_".to_string()],
            method: HttpMethod::Get,
            url: "https://api.acme.test/v1/whoami".to_string(),
            headers: BTreeMap::new(),
            expect_status: vec![200],
        };
        let v = PackValidator::new("acme".to_string(), spec);
        assert!(v.matches("ACME_API_KEY"));
        assert!(v.matches("acme_api_key"));
        assert!(!v.matches("OTHER_KEY"));
        // Non-matching keys are NotApplicable without any network access.
        let result = v.validate(
            "OTHER_KEY",
            &Zeroizing::new("x".to_string()),
            Duration::from_secs(1),
        );
        assert_eq!(result, ValidationResult::NotApplicable);
    }

    #[test]
    fn scaffold_pack_writes_template() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = scaffold_pack(&dir.path().join("mypack"), "mypack").expect("scaffold");
        let raw = std::fs::read(&path).expect("read");
        let manifest: ConnectorManifest = serde_json::from_slice(&raw).expect("parse");
        assert!(validate_manifest(&manifest).is_ok());
        assert!(sign_manifest(&manifest, &test_keypair()).is_ok());
    }

    /// Isolate the connector store in a temp HOME for store tests.
    struct TempHome {
        _guard: crate::ProcessEnvGuard,
        _dir: tempfile::TempDir,
        prev: Option<String>,
    }

    impl TempHome {
        fn new() -> Self {
            let guard = crate::PROCESS_ENV_LOCK.lock().expect("env lock");
            let dir = tempfile::tempdir().expect("tempdir");
            let prev = std::env::var("HOME").ok();
            unsafe { std::env::set_var("HOME", dir.path()) };
            Self {
                _guard: guard,
                _dir: dir,
                prev,
            }
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    fn write_signed_pack(dir: &Path, key: &SigningKey, name: &str) {
        let mut manifest = sample_manifest();
        manifest.name = name.to_string();
        let raw = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(dir.join("connector.json"), raw).unwrap();
        let envelope = sign_manifest(&manifest, key).unwrap();
        std::fs::write(dir.join("connector.sig"), format!("{envelope}\n")).unwrap();
    }

    #[test]
    fn anchor_lifecycle() {
        let _home = TempHome::new();
        assert!(list_anchors().unwrap().is_empty());

        let key = test_keypair();
        let pub_hex = hex::encode(key.verifying_key().as_bytes());
        let key_id = add_anchor(&pub_hex).expect("add anchor");
        assert_eq!(key_id.len(), 8);

        let ids = list_anchors().unwrap();
        assert_eq!(ids, vec![key_id.clone()]);

        // Re-adding the same key is idempotent.
        assert_eq!(add_anchor(&pub_hex).unwrap(), key_id);

        // Bad keys fail closed with guidance.
        assert!(add_anchor("not-hex").is_err());
        assert!(add_anchor(&"ab".repeat(16)).is_err()); // 16 bytes, not 32

        remove_anchor(&key_id).expect("remove");
        assert!(list_anchors().unwrap().is_empty());
        assert!(remove_anchor(&key_id).is_err());
    }

    #[test]
    fn install_verify_list_remove_pack() {
        let _home = TempHome::new();
        let key = test_keypair();
        let pub_hex = hex::encode(key.verifying_key().as_bytes());
        add_anchor(&pub_hex).expect("anchor");

        let src = tempfile::tempdir().expect("tempdir");
        write_signed_pack(src.path(), &key, "acme");

        // Unsigned dir is refused with sign guidance.
        let unsigned = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            unsigned.path().join("connector.json"),
            serde_json::to_vec(&sample_manifest()).unwrap(),
        )
        .unwrap();
        let err = install_pack(unsigned.path()).unwrap_err().to_string();
        assert!(err.contains("sign"), "unexpected: {err}");

        let installed = install_pack(src.path()).expect("install");
        assert_eq!(installed.name, "acme");
        assert_eq!(installed.sha256_pin.len(), 64);
        assert!(installed.capabilities.contains(&"validate".to_string()));

        let packs = list_packs().unwrap();
        assert_eq!(packs.len(), 1);

        // Loaded manifest re-verifies the hash pin.
        let loaded = load_pack_manifest("acme").expect("load");
        assert_eq!(loaded.name, "acme");

        // Tampering with the installed manifest fails the pin check.
        let manifest_path = packs_dir()
            .unwrap()
            .join("acme")
            .join("1.2.3")
            .join("connector.json");
        let mut raw = std::fs::read(&manifest_path).unwrap();
        raw.extend_from_slice(b" ");
        std::fs::write(&manifest_path, raw).unwrap();
        let err = load_pack_manifest("acme").unwrap_err().to_string();
        assert!(err.contains("hash-pin"), "unexpected: {err}");

        remove_pack("acme").expect("remove");
        assert!(list_packs().unwrap().is_empty());
        assert!(remove_pack("acme").is_err());
    }

    #[test]
    fn install_refuses_wrong_signer() {
        let _home = TempHome::new();
        // Anchor for key A, pack signed by key B.
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        add_anchor(&hex::encode(key_a.verifying_key().as_bytes())).expect("anchor");
        let key_b = SigningKey::from_bytes(&[2u8; 32]);
        let src = tempfile::tempdir().expect("tempdir");
        write_signed_pack(src.path(), &key_b, "acme");
        let err = install_pack(src.path()).unwrap_err().to_string();
        assert!(
            err.contains("no registered trust anchor") || err.contains("verification FAILED"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn find_capabilities_across_packs() {
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).expect("anchor");
        let src = tempfile::tempdir().expect("tempdir");
        write_signed_pack(src.path(), &key, "acme");
        install_pack(src.path()).expect("install");

        let (pack, spec) = find_import_source("acme-export")
            .expect("lookup")
            .expect("found");
        assert_eq!(pack, "acme");
        assert_eq!(spec.format, ImportFormat::JsonMap);

        let (pack, target) = find_sync_target("acme-deploy")
            .expect("lookup")
            .expect("found");
        assert_eq!(pack, "acme");
        assert_eq!(target.credential_name, "ACME_API_TOKEN");

        assert!(find_import_source("nope").expect("lookup").is_none());

        // Pack validators surface for the validate pipeline.
        let validators = pack_validators();
        assert_eq!(validators.len(), 1);
        assert!(validators[0].matches("ACME_API_KEY"));
    }
}
