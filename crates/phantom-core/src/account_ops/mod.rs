//! Provider-neutral account and credential operations (create, rotate,
//! revoke, status) that never return secret values.
//!
//! This is the value-free control layer that the hard-deny notes in
//! [`crate::rotation_provider`] and [`crate::issuance`] name as missing: a
//! durable, value-free recovery handle recorded *before* any provider call,
//! and a verified compensating revoke when local persistence fails.
//!
//! # Contract
//!
//! - Every operation returns an [`OpOutcome`]: an opaque [`OpHandle`] plus
//!   value-free metadata. No public type in this module can carry a secret
//!   value out of [`AccountOps::run`].
//! - A newly issued value travels provider -> [`ValueSink`] (the vault writer)
//!   inside [`Zeroizing`] and is dropped there. It is never formatted.
//! - `~/.ashlr/KILL` is checked first and again immediately before the
//!   provider call. If it exists, or its state cannot be determined, the
//!   operation is refused before any provider call (fail closed).
//! - [`ExecMode::DryRun`] is the default. A dry run plans and audits but never
//!   calls a provider.
//! - Every attempt is recorded in an append-only, hash-chained JSONL ledger
//!   ([`OpsLedger`]): actor, operation, provider, target, secret name, handle,
//!   time and result. Names and handles only, never values. If the intent
//!   entry cannot be written, the operation is refused before the provider
//!   call.
//! - Request fields are validated against strict, value-free character sets so
//!   a caller cannot smuggle a credential into the ledger through a name.
//!
//! No CLI or MCP command reaches this module yet; wiring it is a separate,
//! reviewed change.

pub mod github_app;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Maximum length accepted for any value-free request field.
const MAX_FIELD_LEN: usize = 128;

// ── Operation vocabulary ────────────────────────────────────────────────────

/// The four account operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountOp {
    /// Issue a new credential where none is stored yet.
    Create,
    /// Issue a successor credential for an existing one.
    Rotate,
    /// Invalidate a stored credential at the provider.
    Revoke,
    /// Read value-free provider metadata.
    Status,
}

impl AccountOp {
    /// Stable lowercase label for the ledger and `--json`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
            Self::Status => "status",
        }
    }

    /// True when a successful run yields a new value for the sink.
    pub fn issues_value(self) -> bool {
        matches!(self, Self::Create | Self::Rotate)
    }
}

/// Whether the engine may call the provider. Dry run is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecMode {
    /// Plan and audit only. No provider call.
    #[default]
    DryRun,
    /// Call the provider.
    Execute,
}

/// A value-free operation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpRequest {
    /// Who asked (agent or lane id, never a credential).
    pub actor: String,
    /// What to do.
    pub op: AccountOp,
    /// Registered provider name, e.g. `"github-app"`.
    pub provider: String,
    /// Provider resource id, e.g. `"installation:12345"`.
    pub target: String,
    /// Vault name the credential is stored under, e.g. `"GITHUB_INSTALL_TOKEN"`.
    pub secret_name: String,
}

/// Opaque, value-free handle minted locally before any provider call. It is
/// random, so it cannot encode or be derived from a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpHandle(String);

impl OpHandle {
    fn mint() -> Self {
        let bytes: [u8; 16] = rand::random();
        Self(format!("aop_{}", hex::encode(bytes)))
    }

    /// The handle string, e.g. `aop_0123...`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Final state of one operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum OpResult {
    /// Dry run: planned and audited, provider not called.
    DryRun,
    /// Provider call and (for create/rotate) vault store succeeded.
    Succeeded,
    /// Refused before any provider call.
    Refused { reason: String },
    /// The provider call failed. Nothing was issued, or nothing was stored.
    Failed { reason: String },
    /// A value was issued but could not be stored, and the provider confirmed
    /// the compensating revoke.
    Compensated { reason: String },
    /// A value was issued, could not be stored, and the compensating revoke
    /// also failed. The handle identifies the orphan for follow-up.
    CompensationFailed { reason: String },
}

impl OpResult {
    /// Stable label for the ledger.
    pub fn label(&self) -> &'static str {
        match self {
            Self::DryRun => "dry-run",
            Self::Succeeded => "succeeded",
            Self::Refused { .. } => "refused",
            Self::Failed { .. } => "failed",
            Self::Compensated { .. } => "compensated",
            Self::CompensationFailed { .. } => "compensation-failed",
        }
    }
}

/// What a caller gets back. Value-free by construction: every field is a
/// name, a handle, a label or provider metadata the adapter chose to expose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpOutcome {
    pub handle: OpHandle,
    pub op: AccountOp,
    pub provider: String,
    pub target: String,
    pub secret_name: String,
    pub mode: ExecMode,
    pub result: OpResult,
    /// Value-free provider metadata (expiry, scope labels, status).
    pub metadata: BTreeMap<String, String>,
    /// False when the final ledger entry could not be written.
    pub audited: bool,
}

/// Value-free error from an adapter, sink or credential source. Reasons are
/// fixed strings or HTTP status summaries, never response bodies or values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError {
    pub reason: String,
}

impl OpError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for OpError {}

// ── Provider-facing traits ──────────────────────────────────────────────────

/// A newly issued value plus value-free metadata. `Debug` never renders the
/// value.
pub struct Issued {
    pub value: Zeroizing<String>,
    pub metadata: BTreeMap<String, String>,
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued")
            .field("value", &"[redacted]")
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// What a provider call produced.
#[derive(Debug)]
pub enum ProviderReply {
    /// Create or rotate: a new value for the sink.
    Issued(Issued),
    /// Revoke or status: metadata only.
    Done(BTreeMap<String, String>),
}

/// Reads bootstrap or stored credentials by vault name (for example the App
/// PEM, or the token being revoked). Implementations read from the vault and
/// must not log.
pub trait CredentialSource {
    fn read(&self, name: &str) -> Result<Zeroizing<String>, OpError>;
}

/// Stores a newly issued value under a vault name. This is the only place an
/// issued value goes.
pub trait ValueSink {
    fn store(&mut self, name: &str, value: Zeroizing<String>) -> Result<(), OpError>;
}

/// A provider adapter. Adapters must keep values inside [`Zeroizing`], must
/// not log, and must return value-free [`OpError`] reasons.
pub trait AccountProvider {
    /// Registered name, e.g. `"github-app"`.
    fn name(&self) -> &str;

    /// Whether this adapter implements `op`.
    fn supports(&self, op: AccountOp) -> bool;

    /// Validate the request and describe the call without network I/O.
    fn plan(&self, req: &OpRequest) -> Result<BTreeMap<String, String>, OpError>;

    /// Perform the provider call.
    fn execute(
        &self,
        req: &OpRequest,
        creds: &dyn CredentialSource,
    ) -> Result<ProviderReply, OpError>;

    /// Invalidate a value this adapter just issued, after the sink refused it.
    fn compensate(&self, req: &OpRequest, issued: &Zeroizing<String>) -> Result<(), OpError>;
}

// ── KILL switch ─────────────────────────────────────────────────────────────

/// Default fleet stop file: `~/.ashlr/KILL`.
pub fn default_kill_path() -> std::io::Result<PathBuf> {
    Ok(crate::home::home_dir()?.join(".ashlr").join("KILL"))
}

/// Fail-closed KILL check. Any entry at `path` (file, directory or symlink,
/// even a dangling one) stops the operation, and so does any error other than
/// "not found".
pub fn check_kill(path: &Path) -> Result<(), OpError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(OpError::new(
            "KILL is set; refusing before any provider call",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(OpError::new(
            "KILL state could not be determined; refusing before any provider call",
        )),
    }
}

// ── Append-only ledger ──────────────────────────────────────────────────────

/// One ledger line. Value-free: names, labels, handle and hashes only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub seq: u64,
    pub ts: u64,
    /// `"intent"` (written before the provider call) or `"result"`.
    pub phase: String,
    pub actor: String,
    pub op: AccountOp,
    pub provider: String,
    pub target: String,
    pub secret_name: String,
    pub handle: String,
    pub mode: ExecMode,
    pub result: String,
    pub reason: Option<String>,
    pub prev_sha256: String,
    pub sha256: String,
}

/// Default ledger path: `~/.phantom/account-ops.jsonl`.
pub fn default_ledger_path() -> std::io::Result<PathBuf> {
    Ok(crate::home::home_dir()?
        .join(".phantom")
        .join("account-ops.jsonl"))
}

/// Append-only, SHA-256 chained JSONL ledger. Each line's `sha256` covers the
/// line with `sha256` empty, including `prev_sha256`, so edits, deletions and
/// reorders are detectable by [`OpsLedger::verify`].
#[derive(Debug, Clone)]
pub struct OpsLedger {
    path: PathBuf,
}

impl OpsLedger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_append(&self) -> std::io::Result<std::fs::File> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&self.path)
    }

    fn entry_hash(entry: &LedgerEntry) -> String {
        let mut unsigned = entry.clone();
        unsigned.sha256 = String::new();
        let bytes = serde_json::to_vec(&unsigned).unwrap_or_default();
        hex::encode(Sha256::digest(&bytes))
    }

    fn read_entries(file: &mut std::fs::File) -> std::io::Result<Vec<LedgerEntry>> {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0))?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str::<LedgerEntry>(l).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed ledger line")
                })
            })
            .collect()
    }

    /// Append one entry under an exclusive lock, chaining it to the last line.
    fn append(&self, mut entry: LedgerEntry) -> std::io::Result<LedgerEntry> {
        use fs2::FileExt;
        let mut file = self.open_append()?;
        file.lock_exclusive()?;
        let result = (|| {
            let existing = Self::read_entries(&mut file)?;
            let (seq, prev) = match existing.last() {
                Some(last) => (last.seq + 1, last.sha256.clone()),
                None => (1, "GENESIS".to_string()),
            };
            entry.seq = seq;
            entry.prev_sha256 = prev;
            entry.sha256 = Self::entry_hash(&entry);
            let mut line = serde_json::to_vec(&entry)
                .map_err(|_| std::io::Error::other("ledger entry could not be encoded"))?;
            line.push(b'\n');
            file.write_all(&line)?;
            file.sync_data()?;
            Ok(entry)
        })();
        let _ = FileExt::unlock(&file);
        result
    }

    /// Verify the hash chain. Returns the number of entries.
    pub fn verify(&self) -> Result<usize, OpError> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(_) => return Err(OpError::new("ledger could not be opened")),
        };
        let entries =
            Self::read_entries(&mut file).map_err(|_| OpError::new("ledger is malformed"))?;
        let mut prev = "GENESIS".to_string();
        for (i, e) in entries.iter().enumerate() {
            if e.seq != i as u64 + 1 || e.prev_sha256 != prev || Self::entry_hash(e) != e.sha256 {
                return Err(OpError::new(format!(
                    "ledger chain broken at seq {}",
                    i + 1
                )));
            }
            prev = e.sha256.clone();
        }
        Ok(entries.len())
    }
}

// ── Engine ──────────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Replace an adapter or sink reason with a fixed string if it would echo the
/// issued value. Defense in depth; adapters must already be value-free.
fn scrub_reason(reason: String, value: &Zeroizing<String>) -> String {
    if !value.is_empty() && reason.contains(value.as_str()) {
        "[reason withheld: it echoed the issued value]".to_string()
    } else {
        reason
    }
}

/// Keep provider metadata short and structural (timestamps, labels, ids).
/// Anything else is replaced, so a provider cannot echo a value into output.
pub(crate) fn meta_value(raw: &str) -> String {
    let ok = raw.len() <= 64
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_:.+=,TZ".contains(c));
    if ok {
        raw.to_string()
    } else {
        "[withheld]".to_string()
    }
}

fn valid_field(s: &str, extra: &[char]) -> bool {
    !s.is_empty()
        && s.len() <= MAX_FIELD_LEN
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || extra.contains(&c))
}

/// Reject anything that is not a short, value-free identifier. Secret names
/// follow vault naming (`A-Z`, `0-9`, `_`); targets allow `:` `.` `/`.
pub fn validate_request(req: &OpRequest) -> Result<(), OpError> {
    if !valid_field(&req.actor, &['.', ':']) {
        return Err(OpError::new("actor must be a short identifier"));
    }
    if !valid_field(&req.provider, &[]) {
        return Err(OpError::new("provider must be a short identifier"));
    }
    if !valid_field(&req.target, &[':', '.', '/']) {
        return Err(OpError::new("target must be a short resource identifier"));
    }
    let name_ok = !req.secret_name.is_empty()
        && req.secret_name.len() <= MAX_FIELD_LEN
        && req
            .secret_name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !name_ok {
        return Err(OpError::new("secret_name must match [A-Z0-9_]+"));
    }
    Ok(())
}

/// Runs account operations against registered adapters.
pub struct AccountOps {
    kill_path: PathBuf,
    ledger: OpsLedger,
    providers: Vec<Box<dyn AccountProvider>>,
}

impl AccountOps {
    /// Build an engine with explicit KILL and ledger paths.
    pub fn new(kill_path: impl Into<PathBuf>, ledger: OpsLedger) -> Self {
        Self {
            kill_path: kill_path.into(),
            ledger,
            providers: Vec::new(),
        }
    }

    /// Build an engine on `~/.ashlr/KILL` and `~/.phantom/account-ops.jsonl`.
    pub fn with_default_paths() -> std::io::Result<Self> {
        Ok(Self::new(
            default_kill_path()?,
            OpsLedger::new(default_ledger_path()?),
        ))
    }

    /// Register an adapter.
    pub fn register(&mut self, provider: Box<dyn AccountProvider>) {
        self.providers.push(provider);
    }

    pub fn ledger(&self) -> &OpsLedger {
        &self.ledger
    }

    fn record(
        &self,
        phase: &str,
        req: &OpRequest,
        handle: &OpHandle,
        mode: ExecMode,
        result: &OpResult,
    ) -> bool {
        let reason = match result {
            OpResult::Refused { reason }
            | OpResult::Failed { reason }
            | OpResult::Compensated { reason }
            | OpResult::CompensationFailed { reason } => Some(reason.clone()),
            OpResult::DryRun | OpResult::Succeeded => None,
        };
        let label = if phase == "intent" {
            "pending"
        } else {
            result.label()
        };
        let entry = LedgerEntry {
            seq: 0,
            ts: now_unix(),
            phase: phase.to_string(),
            actor: req.actor.clone(),
            op: req.op,
            provider: req.provider.clone(),
            target: req.target.clone(),
            secret_name: req.secret_name.clone(),
            handle: handle.as_str().to_string(),
            mode,
            result: label.to_string(),
            reason: if phase == "intent" { None } else { reason },
            prev_sha256: String::new(),
            sha256: String::new(),
        };
        let ok = self.ledger.append(entry).is_ok();
        if ok && phase == "result" {
            // Mirror into the existing opt-in audit log (names only).
            crate::audit::log(
                &format!("account_ops.{}.{}", req.op.label(), label),
                Some(&req.secret_name),
            );
        }
        ok
    }

    fn finish(
        &self,
        req: &OpRequest,
        handle: OpHandle,
        mode: ExecMode,
        result: OpResult,
        metadata: BTreeMap<String, String>,
    ) -> OpOutcome {
        let audited = self.record("result", req, &handle, mode, &result);
        OpOutcome {
            handle,
            op: req.op,
            provider: req.provider.clone(),
            target: req.target.clone(),
            secret_name: req.secret_name.clone(),
            mode,
            result,
            metadata,
            audited,
        }
    }

    /// Run one operation. Never returns or logs a secret value.
    pub fn run(
        &self,
        req: &OpRequest,
        mode: ExecMode,
        creds: &dyn CredentialSource,
        sink: &mut dyn ValueSink,
    ) -> OpOutcome {
        let handle = OpHandle::mint();
        let refuse = |reason: String| OpResult::Refused { reason };

        if let Err(e) = validate_request(req) {
            // Fields failed validation, so do not write them to the ledger.
            return OpOutcome {
                handle,
                op: req.op,
                provider: "[invalid]".to_string(),
                target: "[invalid]".to_string(),
                secret_name: "[invalid]".to_string(),
                mode,
                result: refuse(e.reason),
                metadata: BTreeMap::new(),
                audited: false,
            };
        }
        if let Err(e) = check_kill(&self.kill_path) {
            return self.finish(req, handle, mode, refuse(e.reason), BTreeMap::new());
        }
        let Some(provider) = self.providers.iter().find(|p| p.name() == req.provider) else {
            return self.finish(
                req,
                handle,
                mode,
                refuse("provider is not registered".to_string()),
                BTreeMap::new(),
            );
        };
        if !provider.supports(req.op) {
            return self.finish(
                req,
                handle,
                mode,
                refuse(format!("provider does not support {}", req.op.label())),
                BTreeMap::new(),
            );
        }
        let plan = match provider.plan(req) {
            Ok(p) => p,
            Err(e) => return self.finish(req, handle, mode, refuse(e.reason), BTreeMap::new()),
        };
        // Durable, value-free intent before any provider call.
        if !self.record("intent", req, &handle, mode, &OpResult::DryRun) {
            return OpOutcome {
                handle,
                op: req.op,
                provider: req.provider.clone(),
                target: req.target.clone(),
                secret_name: req.secret_name.clone(),
                mode,
                result: refuse("audit ledger unavailable; refusing before provider call".into()),
                metadata: plan,
                audited: false,
            };
        }
        if mode == ExecMode::DryRun {
            return self.finish(req, handle, mode, OpResult::DryRun, plan);
        }
        // Re-check right before the call to narrow the race with a new KILL.
        if let Err(e) = check_kill(&self.kill_path) {
            return self.finish(req, handle, mode, refuse(e.reason), plan);
        }
        match provider.execute(req, creds) {
            Err(e) => self.finish(
                req,
                handle,
                mode,
                OpResult::Failed { reason: e.reason },
                plan,
            ),
            Ok(ProviderReply::Done(meta)) => {
                if req.op.issues_value() {
                    return self.finish(
                        req,
                        handle,
                        mode,
                        OpResult::Failed {
                            reason: "provider returned no value for an issuing operation".into(),
                        },
                        meta,
                    );
                }
                self.finish(req, handle, mode, OpResult::Succeeded, meta)
            }
            Ok(ProviderReply::Issued(issued)) => {
                let Issued { value, metadata } = issued;
                if !req.op.issues_value() {
                    let result = match provider.compensate(req, &value) {
                        Ok(()) => OpResult::Compensated {
                            reason: "unexpected value for a non-issuing operation".into(),
                        },
                        Err(e) => OpResult::CompensationFailed {
                            reason: format!(
                                "unexpected value for a non-issuing operation; revoke failed: {}",
                                scrub_reason(e.reason, &value)
                            ),
                        },
                    };
                    return self.finish(req, handle, mode, result, metadata);
                }
                // Keep a zeroizing copy only for the compensating revoke.
                let backup = Zeroizing::new(value.as_str().to_string());
                match sink.store(&req.secret_name, value) {
                    Ok(()) => {
                        drop(backup);
                        self.finish(req, handle, mode, OpResult::Succeeded, metadata)
                    }
                    Err(store_err) => {
                        let store_reason = scrub_reason(store_err.reason, &backup);
                        let result = match provider.compensate(req, &backup) {
                            Ok(()) => OpResult::Compensated {
                                reason: format!("vault store failed: {store_reason}"),
                            },
                            Err(e) => OpResult::CompensationFailed {
                                reason: format!(
                                    "vault store failed: {store_reason}; revoke failed: {}",
                                    scrub_reason(e.reason, &backup)
                                ),
                            },
                        };
                        drop(backup);
                        self.finish(req, handle, mode, result, metadata)
                    }
                }
            }
        }
    }
}
