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
//!   route approved values to explicitly displayed, operator-trusted destinations.
//!   A valid pack signature does not establish provider endpoint authenticity.
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
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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
        && !matches!(version, "." | "..")
        && version.len() <= 64
        && version
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b'+'))
}

fn valid_https_url(url: &str) -> bool {
    url.len() <= 2048
        && !url.contains(VALUE_PLACEHOLDER)
        && reqwest::Url::parse(url).is_ok_and(|u| {
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.fragment().is_none()
        })
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
    if key.is_weak() {
        return Err(PhantomError::ConfigParseError(
            "weak trust anchor key is forbidden".into(),
        ));
    }
    let dir = anchors_dir()?;
    let key_id = key_id_for_pubkey(&key);
    let path = dir.join(format!("{key_id}.pub"));
    let target = store_target(&path, true)
        .map_err(|e| PhantomError::Other(format!("unsafe anchor destination: {e}")))?;
    let before = target
        .read_regular()
        .map_err(|e| PhantomError::Other(format!("unsafe anchor destination: {e}")))?;
    // Compare and publish using the same retained before-image, including absence.
    if let Some(raw) = before.as_ref().map(|raw| raw.bytes()) {
        if raw.len() > 128 {
            return Err(PhantomError::ConfigParseError(
                "anchor exceeds size bound".into(),
            ));
        }
        let existing = std::str::from_utf8(raw)
            .map_err(|_| PhantomError::ConfigParseError("anchor is not UTF-8".into()))?;
        if existing.trim().to_lowercase() != pubkey_hex.trim().to_lowercase() {
            return Err(PhantomError::ConfigParseError(format!(
                "anchor id {key_id} already registered with a different key; remove it first"
            )));
        }
        return Ok(key_id);
    }
    accept_store_effect(
        target
            .replace_if_exact(before.as_ref(), pubkey_hex.trim().to_lowercase().as_bytes())
            .map_err(|e| PhantomError::Other(format!("cannot register anchor: {e}")))?,
    )?;
    Ok(key_id)
}

/// List registered trust-anchor key ids.
pub fn list_anchors() -> Result<Vec<String>, PhantomError> {
    let dir = anchors_dir()?;
    if !store_directory_exists(&dir)? {
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
    if key_id.len() != 8 || !key_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PhantomError::ConfigParseError(
            "invalid trust anchor id".to_string(),
        ));
    }
    let path = anchors_dir()?.join(format!("{key_id}.pub"));
    let target = store_target(&path, false)
        .map_err(|e| PhantomError::Other(format!("unsafe anchor path: {e}")))?;
    let before = target
        .read_regular()
        .map_err(|e| PhantomError::Other(format!("unsafe anchor file: {e}")))?
        .ok_or_else(|| {
            PhantomError::ConfigParseError(format!("no trust anchor with id {key_id:?}"))
        })?;
    accept_store_effect(
        target
            .unlink_if_exact(&before)
            .map_err(|e| PhantomError::Other(format!("cannot remove anchor: {e}")))?,
    )?;
    Ok(())
}

fn load_anchors() -> Result<Vec<(String, VerifyingKey)>, PhantomError> {
    let dir = anchors_dir()?;
    let mut anchors = Vec::new();
    if !store_directory_exists(&dir)? {
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
        let raw = read_pack_file(&path, 128)?;
        let hex_key = std::str::from_utf8(&raw)
            .map_err(|_| PhantomError::ConfigParseError("anchor is not UTF-8".to_string()))?;
        let bytes = hex::decode(hex_key.trim()).map_err(|_| {
            PhantomError::ConfigParseError(format!("anchor file {} is not hex", path.display()))
        })?;
        let key = VerifyingKey::try_from(bytes.as_slice()).map_err(|_| {
            PhantomError::ConfigParseError(format!(
                "anchor file {} is not a 32-byte key",
                path.display()
            ))
        })?;
        if key.is_weak() {
            return Err(PhantomError::ConfigParseError(
                "weak stored trust anchor key is forbidden".into(),
            ));
        }
        let key_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        if key_id != key_id_for_pubkey(&key) {
            return Err(PhantomError::ConfigParseError(
                "anchor id does not match its public key".to_string(),
            ));
        }
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
    let bytes =
        Zeroizing::new(hex::decode(hex_seed.trim()).map_err(|_| {
            PhantomError::ConfigParseError("signing key is not valid hex".to_string())
        })?);
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        PhantomError::ConfigParseError(
            "signing key must be 32 bytes (64 hex chars), an Ed25519 seed".to_string(),
        )
    })?;
    let arr = Zeroizing::new(arr);
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
    Ok(verify_pack_snapshot(dir)?.manifest)
}

fn read_pack_file(path: &Path, limit: u64) -> Result<Vec<u8>, PhantomError> {
    if path.starts_with(connectors_dir()?) {
        return read_store_file(path, limit)?.ok_or_else(|| {
            PhantomError::ConfigParseError("connector store file is missing".into())
        });
    }
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        PhantomError::ConfigParseError(format!("cannot read {}: {e}; packs require connector.json and connector.sig (sign the manifest first)", path.display()))
    })?;
    if meta.len() > limit {
        return Err(PhantomError::ConfigParseError(
            "connector file exceeds its size bound".to_string(),
        ));
    }
    let raw = crate::fs::read_regular_file(path)
        .map_err(|e| PhantomError::ConfigParseError(format!("unsafe connector file: {e}")))?
        .ok_or_else(|| PhantomError::ConfigParseError("connector file disappeared".to_string()))?;
    if raw.len() as u64 > limit {
        return Err(PhantomError::ConfigParseError(
            "connector file exceeds its size bound".to_string(),
        ));
    }
    Ok(raw)
}

// Resolve every store component beneath the trusted home through retained
// no-follow handles. Ambient create_dir_all must never precede this boundary.
fn store_target(path: &Path, create: bool) -> std::io::Result<crate::fs::AnchoredTarget> {
    let home = crate::home::home_dir()?;
    let relative = path.strip_prefix(&home).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "connector path outside home",
        )
    })?;
    let anchor = crate::fs::TrustedAnchor::open(&home)?;
    if create {
        anchor.target_with_private_parents(relative)
    } else {
        anchor.target(relative)
    }
}

fn read_store_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, PhantomError> {
    let target = match store_target(path, false) {
        Ok(target) => target,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(PhantomError::ConfigParseError(format!(
                "unsafe connector store: {e}"
            )));
        }
    };
    let raw = target
        .read_regular()
        .map_err(|e| PhantomError::ConfigParseError(format!("unsafe connector store file: {e}")))?;
    raw.map(|raw| {
        if raw.bytes().len() as u64 > limit {
            return Err(PhantomError::ConfigParseError(
                "connector file exceeds its size bound".into(),
            ));
        }
        Ok(raw.bytes().to_vec())
    })
    .transpose()
}

fn store_directory_exists(path: &Path) -> Result<bool, PhantomError> {
    // A synthetic absent leaf walks and retains all directory ancestors.
    match store_target(&path.join(".directory-probe"), false) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(PhantomError::ConfigParseError(format!(
            "unsafe connector directory: {e}"
        ))),
    }
}

fn accept_store_effect<T>(effect: crate::fs::AnchoredEffect<T>) -> Result<(), PhantomError> {
    match effect {
        crate::fs::AnchoredEffect::Durable(_) => Ok(()),
        crate::fs::AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => {
            eprintln!(
                "warning: connector store change committed and verified; platform cannot prove directory crash durability"
            );
            Ok(())
        }
        crate::fs::AnchoredEffect::CommittedButUncertain { error, .. } => {
            Err(PhantomError::Other(format!(
                "connector store change committed but verification/durability is uncertain; stop and inspect before retrying: {error}"
            )))
        }
    }
}

fn write_pack_file(path: &Path, contents: &[u8]) -> Result<(), PhantomError> {
    let target = store_target(path, true)
        .map_err(|e| PhantomError::Other(format!("unsafe connector destination: {e}")))?;
    let before = target
        .read_regular()
        .map_err(|e| PhantomError::Other(format!("unsafe connector destination: {e}")))?;
    let effect = target
        .replace_if_exact(before.as_ref(), contents)
        .map_err(|e| PhantomError::Other(format!("cannot write connector file: {e}")))?;
    accept_store_effect(effect)
}

/// Exact verified bytes, retained through consent and installation. Fields are
/// private so callers cannot substitute an unverified manifest or signature.
pub struct VerifiedPack {
    manifest: ConnectorManifest,
    raw: Vec<u8>,
    signature: Vec<u8>,
    signer: String,
}

impl VerifiedPack {
    pub fn manifest(&self) -> &ConnectorManifest {
        &self.manifest
    }
    pub fn sha256_pin(&self) -> String {
        hex::encode(Sha256::digest(&self.raw))
    }
    pub fn signer(&self) -> &str {
        &self.signer
    }
}

pub fn verify_pack_snapshot(dir: &Path) -> Result<VerifiedPack, PhantomError> {
    let raw = read_pack_file(&dir.join("connector.json"), MAX_MANIFEST_BYTES)?;
    let signature = read_pack_file(&dir.join("connector.sig"), 256)?;
    verify_pack_bytes(raw, signature)
}

fn verify_pack_bytes(raw: Vec<u8>, signature: Vec<u8>) -> Result<VerifiedPack, PhantomError> {
    let manifest: ConnectorManifest = serde_json::from_slice(&raw).map_err(|e| {
        PhantomError::ConfigParseError(format!("connector.json is not a valid manifest: {e}"))
    })?;
    validate_manifest(&manifest)?;

    let envelope = std::str::from_utf8(&signature)
        .map_err(|_| PhantomError::ConfigParseError("connector.sig is not UTF-8".to_string()))?;
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
    anchor.1.verify_strict(&canonical, &sig).map_err(|_| {
        PhantomError::ConfigParseError(
            "pack signature verification FAILED — refusing to install".to_string(),
        )
    })?;
    let signer = key_id.to_string();
    Ok(VerifiedPack {
        manifest,
        raw,
        signature,
        signer,
    })
}

// ── Installed-pack store ─────────────────────────────────────────────────────

/// Metadata recorded for an installed pack (hash-pinned).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstalledPack {
    pub name: String,
    pub version: String,
    pub description: String,
    /// SHA-256 of the installed `connector.json` — tampering is detectable.
    pub sha256_pin: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct InstalledIndex {
    #[serde(default)]
    packs: BTreeMap<String, InstalledPack>,
}

fn read_index() -> Result<InstalledIndex, PhantomError> {
    let path = installed_index_path()?;
    let Some(raw) = read_store_file(&path, 1024 * 1024)? else {
        return Ok(InstalledIndex::default());
    };
    serde_json::from_slice(&raw).map_err(|e| {
        PhantomError::ConfigParseError(format!(
            "installed.json is corrupt: {e}; back it up and remove it to reset"
        ))
    })
}

fn index_for_mutation() -> Result<
    (
        InstalledIndex,
        crate::fs::AnchoredTarget,
        Option<crate::fs::AnchoredRead>,
    ),
    PhantomError,
> {
    let target = store_target(&installed_index_path()?, true)
        .map_err(|e| PhantomError::Other(format!("unsafe connector index: {e}")))?;
    let before = target
        .read_regular()
        .map_err(|e| PhantomError::Other(format!("unsafe connector index: {e}")))?;
    let index = match &before {
        None => InstalledIndex::default(),
        Some(raw) if raw.bytes().len() <= 1024 * 1024 => serde_json::from_slice(raw.bytes())
            .map_err(|e| {
                PhantomError::ConfigParseError(format!("installed.json is corrupt: {e}"))
            })?,
        Some(_) => {
            return Err(PhantomError::ConfigParseError(
                "connector index exceeds size bound".into(),
            ));
        }
    };
    Ok((index, target, before))
}

fn write_index_snapshot(
    index: &InstalledIndex,
    target: &crate::fs::AnchoredTarget,
    before: Option<&crate::fs::AnchoredRead>,
) -> Result<(), PhantomError> {
    let raw = serde_json::to_vec_pretty(index)
        .map_err(|e| PhantomError::ConfigParseError(format!("cannot serialize index: {e}")))?;
    accept_store_effect(target.replace_if_exact(before, &raw).map_err(|e| {
        PhantomError::Other(format!(
            "connector index changed; this registry update was refused: {e}"
        ))
    })?)
}

#[cfg(test)]
fn write_index(index: &InstalledIndex) -> Result<(), PhantomError> {
    let (_, target, before) = index_for_mutation()?;
    write_index_snapshot(index, &target, before.as_ref())
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
    install_verified_pack(verify_pack_snapshot(source_dir)?)
}

/// Install only the verified immutable snapshot; source paths are never reread.
/// Recheck current anchors after any caller's consent ceremony.
pub fn install_verified_pack(snapshot: VerifiedPack) -> Result<InstalledPack, PhantomError> {
    let snapshot = verify_pack_bytes(snapshot.raw, snapshot.signature)?;
    let pin = snapshot.sha256_pin();
    let VerifiedPack {
        manifest,
        raw,
        signature,
        ..
    } = snapshot;

    let (mut index, index_target, index_before) = index_for_mutation()?;
    let dest = packs_dir()?.join(&manifest.name).join(&manifest.version);
    write_pack_file(&dest.join("connector.json"), &raw)?;
    write_pack_file(&dest.join("connector.sig"), &signature)?;

    let installed = InstalledPack {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        description: manifest.description.clone(),
        sha256_pin: pin,
        capabilities: capability_names(&manifest),
    };
    index.packs.insert(manifest.name.clone(), installed.clone());
    write_index_snapshot(&index, &index_target, index_before.as_ref())?;
    Ok(installed)
}

/// List installed packs (index order = alphabetical by name).
pub fn list_packs() -> Result<Vec<InstalledPack>, PhantomError> {
    Ok(read_index()?.packs.into_values().collect())
}

/// Remove an installed pack. The trust anchor is untouched.
pub fn remove_pack(name: &str) -> Result<(), PhantomError> {
    if !valid_pack_name(name) {
        return Err(PhantomError::ConfigParseError(
            "invalid pack name".to_string(),
        ));
    }
    // Refuse an unsafe cache namespace before changing registry ownership.
    store_directory_exists(&packs_dir()?.join(name))?;
    let (mut index, index_target, index_before) = index_for_mutation()?;
    let removed = index.packs.remove(name);
    if removed.is_none() {
        return Err(PhantomError::ConfigParseError(format!(
            "no installed pack named {name:?}; see `phantom connector list`"
        )));
    }
    write_index_snapshot(&index, &index_target, index_before.as_ref())?;
    // Registry removal disables every capability. Retain inert signed cache
    // files: recursively deleting an ambient pathname would introduce a
    // symlink/ancestor-swap deletion boundary unrelated to revocation.
    Ok(())
}

/// Load an installed pack's manifest, re-verifying its hash pin so on-disk
/// tampering after install is detected.
pub fn load_pack_manifest(name: &str) -> Result<ConnectorManifest, PhantomError> {
    Ok(load_verified_pack(name)?.manifest)
}

pub fn load_verified_pack(name: &str) -> Result<VerifiedPack, PhantomError> {
    let index = read_index()?;
    let installed = index.packs.get(name).ok_or_else(|| {
        PhantomError::ConfigParseError(format!("no installed pack named {name:?}"))
    })?;
    if !valid_pack_name(name) || installed.name != name || !valid_version(&installed.version) {
        return Err(PhantomError::ConfigParseError(
            "invalid indexed pack identity".to_string(),
        ));
    }
    let dir = packs_dir()?.join(&installed.name).join(&installed.version);
    let raw = read_pack_file(&dir.join("connector.json"), MAX_MANIFEST_BYTES)?;
    let pin = hex::encode(Sha256::digest(&raw));
    if pin != installed.sha256_pin {
        return Err(PhantomError::ConfigParseError(format!(
            "installed pack {name:?} FAILED its hash-pin check — the manifest changed after install; remove and reinstall it"
        )));
    }
    let signature = read_pack_file(&dir.join("connector.sig"), 256)?;
    let snapshot = verify_pack_bytes(raw, signature)?;
    if snapshot.manifest.name != installed.name || snapshot.manifest.version != installed.version {
        return Err(PhantomError::ConfigParseError(
            "signed manifest does not match indexed pack identity".to_string(),
        ));
    }
    Ok(snapshot)
}

// ── Pack validators (wired into `phantom validate`) ──────────────────────────

/// A [`SecretValidator`] built from a pack's `validate` capability.
pub struct PackValidator {
    pack_name: String,
    spec: HttpValidatorSpec,
    expected: Option<PackValidationPlan>,
}

impl PackValidator {
    #[cfg(test)]
    fn new(pack_name: String, spec: HttpValidatorSpec) -> Self {
        Self {
            pack_name,
            spec,
            expected: None,
        }
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
        if let Some(expected) = &self.expected {
            let current = pack_validation_plan();
            if !current.as_ref().is_ok_and(|plans| plans.contains(expected)) {
                return ValidationResult::Unreachable {
                    reason: "connector trust or destination changed; reauthorize".into(),
                };
            }
        }
        let client = match crate::provider_http::blocking_client(timeout) {
            Ok(c) => c,
            Err(e) => {
                return ValidationResult::Unreachable {
                    reason: format!("pack {}/{}: {e}", self.pack_name, self.spec.name),
                };
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
                };
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackValidationPlan {
    pub pack: String,
    pub signer: String,
    pub sha256_pin: String,
    pub validator: HttpValidatorSpec,
}

/// Freeze every installed validator's destination and signed provenance before
/// consent. Corrupt or revoked packs are errors, never silently omitted.
pub fn pack_validation_plan() -> Result<Vec<PackValidationPlan>, PhantomError> {
    let mut out = Vec::new();
    for installed in list_packs()? {
        let snapshot = load_verified_pack(&installed.name)?;
        for cap in &snapshot.manifest.capabilities {
            if let Capability::Validate { validators } = cap {
                for spec in validators {
                    out.push(PackValidationPlan {
                        pack: installed.name.clone(),
                        signer: snapshot.signer.clone(),
                        sha256_pin: snapshot.sha256_pin(),
                        validator: spec.clone(),
                    });
                }
            }
        }
    }
    Ok(out)
}

pub fn verify_validation_plan(expected: &[PackValidationPlan]) -> Result<(), PhantomError> {
    if pack_validation_plan()? != expected {
        return Err(PhantomError::ConfigParseError(
            "connector validation plan changed; reauthorize before credential access".into(),
        ));
    }
    Ok(())
}

pub fn validators_for_plan(plans: &[PackValidationPlan]) -> Vec<Box<dyn SecretValidator>> {
    plans
        .iter()
        .map(|p| {
            Box::new(PackValidator {
                pack_name: p.pack.clone(),
                spec: p.validator.clone(),
                expected: Some(p.clone()),
            }) as Box<dyn SecretValidator>
        })
        .collect()
}

pub fn pack_validators() -> Result<Vec<Box<dyn SecretValidator>>, PhantomError> {
    Ok(validators_for_plan(&pack_validation_plan()?))
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
            let document = crate::dotenv::DotenvFile::parse_str(text);
            document.validate_for_mutation()?;
            for entry in document.entries() {
                if !valid_secret_name(&entry.key) {
                    return Err(PhantomError::ConfigParseError(
                        "invalid connector import secret name".into(),
                    ));
                }
                map.insert(entry.key.clone(), entry.value.clone());
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

#[derive(Serialize)]
#[serde(transparent)]
struct SyncBody(BTreeMap<String, String>);

impl Drop for SyncBody {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

/// Push secrets to a pack's sync target.
///
/// `credential` is the target's API credential (from the vault, via
/// `credential_name`); `secrets` are the vault secrets to push. Values are
/// zeroized after use and never logged.
pub fn push_sync_target(
    approved: &VerifiedPack,
    spec: &SyncTargetSpec,
    credential: &Zeroizing<String>,
    secrets: &[(String, Zeroizing<String>)],
) -> Result<SyncPushReport, PhantomError> {
    let pack_name = approved.manifest().name.as_str();
    let current = load_verified_pack(pack_name)?;
    if current.sha256_pin() != approved.sha256_pin()
        || current.signer() != approved.signer()
        || !approved.manifest().capabilities.iter().any(|cap| {
            matches!(cap,
            Capability::SyncTarget { targets } if targets.contains(spec))
        })
    {
        return Err(PhantomError::ConfigParseError(
            "connector trust or approved sync destination changed; reauthorize".into(),
        ));
    }
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
    let mut body = SyncBody(BTreeMap::new());
    let mut skipped_empty = 0;
    for (name, value) in secrets {
        if value.as_str().is_empty() {
            skipped_empty += 1;
            continue;
        }
        body.0.insert(name.clone(), value.as_str().to_string());
    }
    let auth_value = Zeroizing::new(if spec.auth_scheme.trim().is_empty() {
        credential.as_str().to_string()
    } else {
        format!("{} {}", spec.auth_scheme.trim(), credential.as_str())
    });
    let mut req = match spec.method {
        HttpMethod::Post => client.post(&spec.url),
        HttpMethod::Put => client.put(&spec.url),
        _ => {
            return Err(PhantomError::ConfigParseError(format!(
                "sync target {:?}: unsupported method for sync",
                spec.name
            )));
        }
    };
    req = req.header(spec.auth_header.as_str(), auth_value.as_str());
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
        pushed: body.0.len(),
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
            .verify_strict(&canonical_manifest_bytes(&manifest).unwrap(), &sig)
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
        assert!(
            key.verifying_key()
                .verify_strict(&canonical_manifest_bytes(&tampered).unwrap(), &sig)
                .is_err()
        );
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
    fn dotenv_import_preserves_quoted_hash_and_escapes_and_rejects_ambiguity() {
        let spec = ImportSourceSpec {
            name: "fixture".into(),
            format: ImportFormat::Dotenv,
            pointer: String::new(),
        };
        let raw = b"KEY=\"abc #def\" # comment\nOTHER='keep # this'\nESCAPED=\"quote\\\"value\"\n";
        let map = parse_import_source(&spec, raw).unwrap();
        assert_eq!(map["KEY"], "abc #def");
        assert_eq!(map["OTHER"], "keep # this");
        assert_eq!(map["ESCAPED"], "quote\"value");
        assert!(parse_import_source(&spec, b"KEY=first\nKEY=second\n").is_err());
        assert!(parse_import_source(&spec, b"KEY=\"unterminated\n").is_err());
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
    fn removed_anchor_revokes_installed_capabilities() {
        let _home = TempHome::new();
        let key = test_keypair();
        let id = add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        remove_anchor(&id).unwrap();
        assert!(load_pack_manifest("acme").is_err());
        assert!(find_sync_target("acme-deploy").is_err());
        assert!(find_import_source("acme-export").is_err());
        assert!(pack_validators().is_err());
    }

    #[test]
    fn changed_manifest_and_mutable_pin_still_require_signature() {
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        let path = packs_dir().unwrap().join("acme/1.2.3/connector.json");
        let mut manifest = sample_manifest();
        manifest.description = "unsigned replacement".into();
        let raw = serde_json::to_vec(&manifest).unwrap();
        std::fs::write(path, &raw).unwrap();
        let mut index = read_index().unwrap();
        index.packs.get_mut("acme").unwrap().sha256_pin = hex::encode(Sha256::digest(raw));
        write_index(&index).unwrap();
        assert!(
            load_pack_manifest("acme")
                .unwrap_err()
                .to_string()
                .contains("signature")
        );
    }

    #[test]
    fn changed_signature_is_rejected_with_unchanged_manifest_pin() {
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        std::fs::write(packs_dir().unwrap().join("acme/1.2.3/connector.sig"), "bad").unwrap();
        assert!(load_pack_manifest("acme").is_err());
    }

    #[test]
    fn frozen_validator_plan_rejects_signed_destination_drift_before_transport() {
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        let plan = pack_validation_plan().unwrap();
        verify_validation_plan(&plan).unwrap();
        let validators = validators_for_plan(&plan);
        let mut changed = sample_manifest();
        if let Capability::Validate { validators } = &mut changed.capabilities[0] {
            validators[0].url = "https://api.acme.test/different-path?changed=1".into();
        }
        std::fs::write(
            source.path().join("connector.json"),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            source.path().join("connector.sig"),
            sign_manifest(&changed, &key).unwrap(),
        )
        .unwrap();
        install_pack(source.path()).unwrap();
        assert!(verify_validation_plan(&plan).is_err());
        let result = validators[0].validate(
            "ACME_API_KEY",
            &Zeroizing::new("synthetic".into()),
            Duration::from_secs(1),
        );
        assert!(
            matches!(result, ValidationResult::Unreachable { reason } if reason.contains("changed"))
        );
    }

    #[test]
    fn revoked_sync_snapshot_fails_before_any_credential_transport() {
        let _home = TempHome::new();
        let key = test_keypair();
        let id = add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        let snapshot = load_verified_pack("acme").unwrap();
        let Capability::SyncTarget { targets } = &snapshot.manifest().capabilities[1] else {
            panic!("fixture");
        };
        remove_anchor(&id).unwrap();
        assert!(
            push_sync_target(
                &snapshot,
                &targets[0],
                &Zeroizing::new("synthetic".into()),
                &[]
            )
            .is_err()
        );
        assert!(install_verified_pack(snapshot).is_err());
    }

    #[test]
    fn installation_uses_verified_snapshot_after_source_replacement() {
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        let snapshot = verify_pack_snapshot(source.path()).unwrap();
        let original = snapshot.raw.clone();
        let pin = snapshot.sha256_pin();
        std::fs::write(source.path().join("connector.json"), b"replacement").unwrap();
        std::fs::write(source.path().join("connector.sig"), b"replacement").unwrap();
        let installed = install_verified_pack(snapshot).unwrap();
        assert_eq!(installed.sha256_pin, pin);
        assert_eq!(
            std::fs::read(packs_dir().unwrap().join("acme/1.2.3/connector.json")).unwrap(),
            original
        );
        assert_eq!(load_pack_manifest("acme").unwrap(), sample_manifest());
    }

    #[test]
    fn unsafe_versions_and_index_paths_fail_before_store_access() {
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        for version in [".", "..", "../escape", "C:foo", "version:stream", "1 2"] {
            let mut manifest = sample_manifest();
            manifest.version = version.into();
            assert!(sign_manifest(&manifest, &key).is_err());
        }
        assert!(!packs_dir().unwrap().exists());
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        let mut index = read_index().unwrap();
        index.packs.get_mut("acme").unwrap().version = "..".into();
        write_index(&index).unwrap();
        assert!(
            load_pack_manifest("acme")
                .unwrap_err()
                .to_string()
                .contains("indexed pack identity")
        );
        assert!(remove_anchor("../../escape").is_err());
    }

    #[test]
    fn stale_registry_snapshot_cannot_overwrite_concurrent_install() {
        let _home = TempHome::new();
        let (stale, target, before) = index_for_mutation().unwrap();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        let committed = std::fs::read(installed_index_path().unwrap()).unwrap();
        assert!(write_index_snapshot(&stale, &target, before.as_ref()).is_err());
        assert_eq!(
            std::fs::read(installed_index_path().unwrap()).unwrap(),
            committed
        );
        assert_eq!(load_pack_manifest("acme").unwrap().name, "acme");
    }

    #[test]
    fn weak_public_keys_are_rejected_when_added_and_loaded() {
        let _home = TempHome::new();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let key = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(key.is_weak());
        assert!(add_anchor(&hex::encode(identity)).is_err());
        assert!(!anchors_dir().unwrap().exists());
        let path = anchors_dir()
            .unwrap()
            .join(format!("{}.pub", key_id_for_pubkey(&key)));
        write_pack_file(&path, hex::encode(identity).as_bytes()).unwrap();
        assert!(
            load_anchors()
                .unwrap_err()
                .to_string()
                .contains("weak stored")
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_symlinks_never_redirect_anchor_or_pack_writes() {
        use std::os::unix::fs::symlink;
        let _home = TempHome::new();
        let key = test_keypair();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("sentinel"), b"unchanged").unwrap();
        let root = connectors_dir().unwrap();
        std::fs::create_dir_all(&root).unwrap();
        symlink(outside.path(), anchors_dir().unwrap()).unwrap();
        assert!(add_anchor(&hex::encode(key.verifying_key().as_bytes())).is_err());
        assert!(list_anchors().is_err());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
        std::fs::remove_file(anchors_dir().unwrap()).unwrap();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        std::fs::create_dir_all(packs_dir().unwrap()).unwrap();
        symlink(outside.path(), packs_dir().unwrap().join("acme")).unwrap();
        assert!(install_pack(source.path()).is_err());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
        assert!(!installed_index_path().unwrap().exists());
        assert_eq!(
            std::fs::read(outside.path().join("sentinel")).unwrap(),
            b"unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pack_removal_refuses_symlinked_parent_and_retains_registry() {
        use std::os::unix::fs::symlink;
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        install_pack(source.path()).unwrap();
        let original_index = std::fs::read(installed_index_path().unwrap()).unwrap();
        let original_packs = packs_dir().unwrap().with_file_name("original-packs");
        std::fs::rename(packs_dir().unwrap(), &original_packs).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("acme")).unwrap();
        std::fs::write(outside.path().join("acme/sentinel"), b"unchanged").unwrap();
        symlink(outside.path(), packs_dir().unwrap()).unwrap();
        assert!(remove_pack("acme").is_err());
        assert_eq!(
            std::fs::read(installed_index_path().unwrap()).unwrap(),
            original_index
        );
        assert_eq!(
            std::fs::read(outside.path().join("acme/sentinel")).unwrap(),
            b"unchanged"
        );
        std::fs::remove_file(packs_dir().unwrap()).unwrap();
        std::fs::rename(original_packs, packs_dir().unwrap()).unwrap();
        remove_pack("acme").unwrap();
        assert!(list_packs().unwrap().is_empty());
        assert!(load_pack_manifest("acme").is_err());
        assert!(
            packs_dir()
                .unwrap()
                .join("acme/1.2.3/connector.json")
                .is_file()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_index_is_rejected_before_install_writes() {
        use std::os::unix::fs::symlink;
        let _home = TempHome::new();
        let key = test_keypair();
        add_anchor(&hex::encode(key.verifying_key().as_bytes())).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("index.json");
        std::fs::write(&victim, b"{}").unwrap();
        symlink(&victim, installed_index_path().unwrap()).unwrap();
        let source = tempfile::tempdir().unwrap();
        write_signed_pack(source.path(), &key, "acme");
        assert!(install_pack(source.path()).is_err());
        assert!(list_packs().is_err());
        assert!(!packs_dir().unwrap().exists());
        assert_eq!(std::fs::read(&victim).unwrap(), b"{}");
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
        let validators = pack_validators().unwrap();
        assert_eq!(validators.len(), 1);
        assert!(validators[0].matches("ACME_API_KEY"));
    }
}
