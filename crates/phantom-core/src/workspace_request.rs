//! Bearerless, out-of-repository setup-request state machine.
//!
//! MCP creates a value-free request and receives only its random `request_id`.
//! A trusted CLI claims that request by independently presenting the canonical
//! workspace, plan digest, and pre-state digest. No bearer, credential locator,
//! environment bytes, target path, or secret value is persisted or returned.

use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const REQUEST_TTL_SECS: u64 = 600;
const CLAIM_EXECUTION_TTL_SECS: u64 = 1_800;
const MAX_PENDING_PER_WORKSPACE: usize = 16;
const RECORD_DOMAIN: &[u8] = b"phantom.workspace-request.record.v1\0";
const REQUEST_DIR: &str = "workspace-requests";
const REQUEST_KEY_FILE: &str = "workspace-request-hmac-key";
const REQUEST_LOCK_FILE: &str = "workspace-requests.lock";
const PLAN_KEY_FILE: &str = "workspace-plan-seal-key";
const PLAN_KEY_DOMAIN: &[u8] = b"phantom.workspace-plan-seal-key.v1\0";
const JOURNAL_DIR: &str = "workspace-journals";
const JOURNAL_KEY_FILE: &str = "workspace-journal-root-key";
const JOURNAL_KEY_DOMAIN: &[u8] = b"phantom.workspace-journal-key.v1\0";

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceRequestError {
    #[error("workspace request I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("workspace request was not found")]
    NotFound,
    #[error("workspace request record failed authentication")]
    Tampered,
    #[error("workspace request has expired")]
    Expired,
    #[error("workspace request is in state {actual:?}, expected {expected:?}")]
    StateConflict {
        expected: WorkspaceRequestState,
        actual: WorkspaceRequestState,
    },
    #[error("workspace scope does not match this request")]
    WorkspaceMismatch,
    #[error("plan identifier does not match this request")]
    PlanMismatch,
    #[error("pre-state identifier does not match this request")]
    PreStateMismatch,
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidDigest(&'static str),
    #[error("request identifier is invalid")]
    InvalidRequestId,
    #[error("workspace path must resolve to a directory")]
    InvalidWorkspace,
    #[error("workspace request serialization failed")]
    Serialization,
    #[error("workspace has too many pending setup requests")]
    PendingLimit,
}

pub type Result<T> = std::result::Result<T, WorkspaceRequestError>;

/// Load the machine-local key used to seal workspace setup plans.
///
/// The persisted 32-byte root is separate from the request-record HMAC key.
/// The returned key is HMAC-derived under a plan-only domain and zeroized on
/// drop. Callers should immediately wrap it in `phantom_workspace::PlanSealKey`.
pub fn load_or_create_workspace_plan_key() -> Result<Zeroizing<[u8; 32]>> {
    load_or_create_workspace_plan_key_with_status().map(|(key, _created)| key)
}

/// Load the plan-seal key and report whether this call provisioned persistent
/// host state. Callers can use the status to avoid describing proposal as
/// entirely read-only on first use.
pub fn load_or_create_workspace_plan_key_with_status() -> Result<(Zeroizing<[u8; 32]>, bool)> {
    let _lock = acquire_lock()?;
    let path = phantom_home()?.join(PLAN_KEY_FILE);
    let (root, created) = if path.exists() {
        (read_fixed_key(&path)?, false)
    } else {
        let mut root = Zeroizing::new([0_u8; 32]);
        rand::thread_rng().fill_bytes(root.as_mut());
        let encoded = Zeroizing::new(hex::encode(root.as_ref()));
        crate::fs::atomic_write(&path, encoded.as_bytes())?;
        (root, true)
    };
    let mut mac = HmacSha256::new_from_slice(root.as_ref()).expect("HMAC accepts any key size");
    mac.update(PLAN_KEY_DOMAIN);
    let derived: [u8; 32] = mac.finalize().into_bytes().into();
    Ok((Zeroizing::new(derived), created))
}

/// Load an already-provisioned plan-seal key without creating host state.
pub fn load_existing_workspace_plan_key() -> Result<Zeroizing<[u8; 32]>> {
    let root = read_fixed_key(&phantom_home()?.join(PLAN_KEY_FILE))?;
    let mut mac = HmacSha256::new_from_slice(root.as_ref()).expect("HMAC accepts any key size");
    mac.update(PLAN_KEY_DOMAIN);
    let derived: [u8; 32] = mac.finalize().into_bytes().into();
    Ok(Zeroizing::new(derived))
}

/// Return an out-of-workspace journal path and a journal-only derived key.
/// The path is request-id scoped and the key is never accepted from MCP, argv,
/// or the environment.
pub fn load_or_create_workspace_journal(
    request_id: &str,
) -> Result<(PathBuf, Zeroizing<[u8; 32]>)> {
    validate_request_id(request_id)?;
    let _lock = acquire_lock()?;
    let directory = phantom_home()?.join(JOURNAL_DIR);
    ensure_private_dir(&directory)?;
    let path = phantom_home()?.join(JOURNAL_KEY_FILE);
    let root = if path.exists() {
        read_fixed_key(&path)?
    } else {
        let mut root = Zeroizing::new([0_u8; 32]);
        rand::thread_rng().fill_bytes(root.as_mut());
        let encoded = Zeroizing::new(hex::encode(root.as_ref()));
        crate::fs::atomic_write(&path, encoded.as_bytes())?;
        root
    };
    let mut mac = HmacSha256::new_from_slice(root.as_ref()).expect("HMAC accepts any key size");
    mac.update(JOURNAL_KEY_DOMAIN);
    mac.update(request_id.as_bytes());
    let derived: [u8; 32] = mac.finalize().into_bytes().into();
    Ok((
        directory.join(format!("{request_id}.journal")),
        Zeroizing::new(derived),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceActionKind {
    InitializeWorkspace,
    ProtectEnvironment,
    UpdateIgnoreRules,
    GenerateEnvironmentExample,
    InstallPreCommitCheck,
    ConfigureClient,
    ReviewPlaceBinding,
}

/// A structurally value-free description of the requested setup work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SanitizedActionSummary {
    pub action_count: u32,
    pub kinds: Vec<WorkspaceActionKind>,
}

impl SanitizedActionSummary {
    pub fn new(actions: impl IntoIterator<Item = WorkspaceActionKind>) -> Self {
        let actions: Vec<_> = actions.into_iter().collect();
        let action_count = u32::try_from(actions.len()).unwrap_or(u32::MAX);
        let mut kinds = actions;
        kinds.sort_unstable();
        kinds.dedup();
        Self {
            action_count,
            kinds,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRequestState {
    Pending,
    Claimed,
    Applied,
    RolledBack,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceExecutionOutcome {
    InProgress,
    RecoveryRequired,
}

/// Value-free status returned to MCP or CLI callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRequestStatus {
    pub request_id: String,
    pub workspace_scope_hash: String,
    pub plan_id: String,
    pub pre_state_id: String,
    pub action_summary: SanitizedActionSummary,
    pub state: WorkspaceRequestState,
    pub created_at: u64,
    pub expires_at: u64,
    /// Deadline after which a claimed operation must be recovered or resolved.
    /// A claim is never silently converted to `Expired` because it may already
    /// have produced durable effects.
    pub execution_deadline: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_outcome: Option<WorkspaceExecutionOutcome>,
    pub updated_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<WorkspaceApplyReceipt>,
}

/// Value-free evidence persisted with an applied request. File contents,
/// secret names, paths, and vault locators are intentionally excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceApplyReceipt {
    pub receipt_digest: String,
    pub file_change_count: u32,
    pub fully_applied: bool,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedRecord {
    request_id: String,
    workspace_scope_hash: String,
    plan_id: String,
    pre_state_id: String,
    action_summary: SanitizedActionSummary,
    state: WorkspaceRequestState,
    created_at: u64,
    expires_at: u64,
    execution_deadline: Option<u64>,
    execution_outcome: Option<WorkspaceExecutionOutcome>,
    updated_at: u64,
    receipt: Option<WorkspaceApplyReceipt>,
    authentication: String,
}

#[derive(Serialize)]
struct RecordBasis<'a> {
    request_id: &'a str,
    workspace_scope_hash: &'a str,
    plan_id: &'a str,
    pre_state_id: &'a str,
    action_summary: &'a SanitizedActionSummary,
    state: WorkspaceRequestState,
    created_at: u64,
    expires_at: u64,
    execution_deadline: Option<u64>,
    execution_outcome: Option<WorkspaceExecutionOutcome>,
    updated_at: u64,
    receipt: &'a Option<WorkspaceApplyReceipt>,
}

impl AuthenticatedRecord {
    fn status(&self) -> WorkspaceRequestStatus {
        WorkspaceRequestStatus {
            request_id: self.request_id.clone(),
            workspace_scope_hash: self.workspace_scope_hash.clone(),
            plan_id: self.plan_id.clone(),
            pre_state_id: self.pre_state_id.clone(),
            action_summary: self.action_summary.clone(),
            state: self.state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            execution_deadline: self.execution_deadline,
            execution_outcome: self.execution_outcome,
            updated_at: self.updated_at,
            receipt: self.receipt.clone(),
        }
    }

    fn is_expired_at(&self, now: u64) -> bool {
        self.state == WorkspaceRequestState::Pending && now >= self.expires_at
    }

    fn basis(&self) -> RecordBasis<'_> {
        RecordBasis {
            request_id: &self.request_id,
            workspace_scope_hash: &self.workspace_scope_hash,
            plan_id: &self.plan_id,
            pre_state_id: &self.pre_state_id,
            action_summary: &self.action_summary,
            state: self.state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            execution_deadline: self.execution_deadline,
            execution_outcome: self.execution_outcome,
            updated_at: self.updated_at,
            receipt: &self.receipt,
        }
    }

    fn authenticate(&mut self, key: &[u8]) -> Result<()> {
        self.authentication = record_authentication(&self.basis(), key)?;
        Ok(())
    }

    fn verify(&self, key: &[u8]) -> Result<()> {
        let provided =
            hex::decode(&self.authentication).map_err(|_| WorkspaceRequestError::Tampered)?;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(RECORD_DOMAIN);
        let basis =
            serde_json::to_vec(&self.basis()).map_err(|_| WorkspaceRequestError::Serialization)?;
        mac.update(&basis);
        mac.verify_slice(&provided)
            .map_err(|_| WorkspaceRequestError::Tampered)?;
        Ok(())
    }
}

/// Create a pending request. The only returned authority surface is its random
/// identifier; no bearer or derived token is created.
pub fn create_request(
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
    action_summary: SanitizedActionSummary,
) -> Result<String> {
    create_request_at(workspace, plan_id, pre_state_id, action_summary, now_unix())
}

fn create_request_at(
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
    action_summary: SanitizedActionSummary,
    created_at: u64,
) -> Result<String> {
    validate_digest(plan_id, "plan_id")?;
    validate_digest(pre_state_id, "pre_state_id")?;
    let workspace_scope_hash = workspace_scope_hash(workspace)?;
    let _lock = acquire_lock()?;
    let key = load_or_create_request_key_locked()?;
    let pending = cleanup_and_collect_pending_locked(&key, created_at)?;
    if let Some(existing) = pending.iter().find(|record| {
        record.workspace_scope_hash == workspace_scope_hash
            && record.plan_id == plan_id
            && record.pre_state_id == pre_state_id
            && record.action_summary == action_summary
    }) {
        return Ok(existing.request_id.clone());
    }
    if pending
        .iter()
        .filter(|record| record.workspace_scope_hash == workspace_scope_hash)
        .count()
        >= MAX_PENDING_PER_WORKSPACE
    {
        return Err(WorkspaceRequestError::PendingLimit);
    }
    let request_id = random_hex_32();
    let mut record = AuthenticatedRecord {
        request_id: request_id.clone(),
        workspace_scope_hash,
        plan_id: plan_id.to_string(),
        pre_state_id: pre_state_id.to_string(),
        action_summary,
        state: WorkspaceRequestState::Pending,
        created_at,
        expires_at: created_at.saturating_add(REQUEST_TTL_SECS),
        execution_deadline: None,
        execution_outcome: None,
        updated_at: created_at,
        receipt: None,
        authentication: String::new(),
    };
    record.authenticate(&key)?;
    write_record(&record)?;
    Ok(request_id)
}

/// Read authenticated, value-free status. Only Pending requests expire;
/// overdue Claimed requests remain recoverable and report `RecoveryRequired`.
pub fn get_status(request_id: &str) -> Result<WorkspaceRequestStatus> {
    validate_request_id(request_id)?;
    let _lock = acquire_lock()?;
    let key = load_existing_request_key_locked()?;
    let mut record = load_record(request_id, &key)?;
    expire_if_needed(&mut record, &key, now_unix())?;
    Ok(record.status())
}

/// Atomically claim a request exactly once after independently re-binding its
/// workspace, plan, and pre-state. Returns value-free status, never a bearer.
pub fn claim_exact(
    request_id: &str,
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
) -> Result<WorkspaceRequestStatus> {
    transition_with_receipt(
        request_id,
        workspace,
        plan_id,
        pre_state_id,
        WorkspaceRequestState::Pending,
        WorkspaceRequestState::Claimed,
        None,
    )
}

pub fn complete_request(
    request_id: &str,
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
) -> Result<WorkspaceRequestStatus> {
    transition_with_receipt(
        request_id,
        workspace,
        plan_id,
        pre_state_id,
        WorkspaceRequestState::Claimed,
        WorkspaceRequestState::Applied,
        None,
    )
}

/// Mark a known-applied request terminal and persist value-free evidence in the
/// same authenticated state transition. Callers must only invoke this after
/// the durable transaction journal records an applied outcome.
pub fn complete_request_with_receipt(
    request_id: &str,
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
    receipt: WorkspaceApplyReceipt,
) -> Result<WorkspaceRequestStatus> {
    validate_digest(&receipt.receipt_digest, "receipt_digest")?;
    transition_with_receipt(
        request_id,
        workspace,
        plan_id,
        pre_state_id,
        WorkspaceRequestState::Claimed,
        WorkspaceRequestState::Applied,
        Some(receipt),
    )
}

pub fn fail_request(
    request_id: &str,
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
) -> Result<WorkspaceRequestStatus> {
    transition_with_receipt(
        request_id,
        workspace,
        plan_id,
        pre_state_id,
        WorkspaceRequestState::Claimed,
        WorkspaceRequestState::Failed,
        None,
    )
}

pub fn rollback_request(
    request_id: &str,
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
) -> Result<WorkspaceRequestStatus> {
    transition_with_receipt(
        request_id,
        workspace,
        plan_id,
        pre_state_id,
        WorkspaceRequestState::Claimed,
        WorkspaceRequestState::RolledBack,
        None,
    )
}

fn transition_with_receipt(
    request_id: &str,
    workspace: &Path,
    plan_id: &str,
    pre_state_id: &str,
    expected_state: WorkspaceRequestState,
    next_state: WorkspaceRequestState,
    receipt: Option<WorkspaceApplyReceipt>,
) -> Result<WorkspaceRequestStatus> {
    validate_request_id(request_id)?;
    validate_digest(plan_id, "plan_id")?;
    validate_digest(pre_state_id, "pre_state_id")?;
    let workspace_scope_hash = workspace_scope_hash(workspace)?;
    let _lock = acquire_lock()?;
    let key = load_existing_request_key_locked()?;
    let mut record = load_record(request_id, &key)?;
    let now = now_unix();
    if expire_if_needed(&mut record, &key, now)? {
        return Err(WorkspaceRequestError::Expired);
    }
    if record.workspace_scope_hash != workspace_scope_hash {
        return Err(WorkspaceRequestError::WorkspaceMismatch);
    }
    if record.plan_id != plan_id {
        return Err(WorkspaceRequestError::PlanMismatch);
    }
    if record.pre_state_id != pre_state_id {
        return Err(WorkspaceRequestError::PreStateMismatch);
    }
    if record.state != expected_state {
        return Err(WorkspaceRequestError::StateConflict {
            expected: expected_state,
            actual: record.state,
        });
    }
    record.state = next_state;
    record.execution_deadline = if next_state == WorkspaceRequestState::Claimed {
        Some(now.saturating_add(CLAIM_EXECUTION_TTL_SECS))
    } else {
        None
    };
    record.execution_outcome = if next_state == WorkspaceRequestState::Claimed {
        Some(WorkspaceExecutionOutcome::InProgress)
    } else {
        None
    };
    record.receipt = receipt;
    record.updated_at = now;
    record.authenticate(&key)?;
    write_record(&record)?;
    Ok(record.status())
}

fn expire_if_needed(record: &mut AuthenticatedRecord, key: &[u8], now: u64) -> Result<bool> {
    if record.state == WorkspaceRequestState::Claimed
        && record
            .execution_deadline
            .is_some_and(|deadline| now >= deadline)
        && record.execution_outcome != Some(WorkspaceExecutionOutcome::RecoveryRequired)
    {
        record.execution_outcome = Some(WorkspaceExecutionOutcome::RecoveryRequired);
        record.updated_at = now;
        record.authenticate(key)?;
        write_record(record)?;
        return Ok(false);
    }
    if !record.is_expired_at(now) {
        return Ok(false);
    }
    record.state = WorkspaceRequestState::Expired;
    record.updated_at = now;
    record.authenticate(key)?;
    write_record(record)?;
    Ok(true)
}

/// Remove authenticated expired Pending records and return the live Pending
/// set while the global request lock is held. Claimed records are retained
/// regardless of age because their effects may be partially or fully durable.
fn cleanup_and_collect_pending_locked(key: &[u8], now: u64) -> Result<Vec<AuthenticatedRecord>> {
    let dir = requests_dir()?;
    ensure_private_dir(&dir)?;
    let mut pending = Vec::new();
    let mut removed = false;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(request_id) = name.strip_suffix(".json") else {
            continue;
        };
        if validate_request_id(request_id).is_err() {
            continue;
        }
        let record = load_record(request_id, key)?;
        if record.state == WorkspaceRequestState::Pending && record.is_expired_at(now) {
            std::fs::remove_file(path)?;
            removed = true;
        } else if record.state == WorkspaceRequestState::Pending {
            pending.push(record);
        }
    }
    if removed {
        crate::fs::sync_parent_dir(&dir)?;
    }
    Ok(pending)
}

/// Hash a canonical workspace path under a dedicated domain without exposing
/// the raw path. Used by status callers to enforce workspace-local visibility.
pub fn workspace_scope_hash(workspace: &Path) -> Result<String> {
    let canonical = workspace
        .canonicalize()
        .map_err(|_| WorkspaceRequestError::InvalidWorkspace)?;
    if !canonical.is_dir() {
        return Err(WorkspaceRequestError::InvalidWorkspace);
    }
    let mut digest = Sha256::new();
    digest.update(b"phantom.workspace-scope.v1\0");
    digest.update(canonical.to_string_lossy().as_bytes());
    Ok(hex::encode(digest.finalize()))
}

fn validate_digest(value: &str, field: &'static str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(WorkspaceRequestError::InvalidDigest(field))
    }
}

fn validate_request_id(request_id: &str) -> Result<()> {
    if request_id.len() == 64
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(WorkspaceRequestError::InvalidRequestId)
    }
}

fn phantom_home() -> std::io::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "HOME directory not found")
    })?;
    Ok(home.join(".phantom"))
}

fn requests_dir() -> std::io::Result<PathBuf> {
    Ok(phantom_home()?.join(REQUEST_DIR))
}

fn request_key_path() -> std::io::Result<PathBuf> {
    Ok(phantom_home()?.join(REQUEST_KEY_FILE))
}

fn request_path(request_id: &str) -> std::io::Result<PathBuf> {
    Ok(requests_dir()?.join(format!("{request_id}.json")))
}

fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace request storage directory is not a real directory",
            ));
        }
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn acquire_lock() -> std::io::Result<File> {
    let home = phantom_home()?;
    ensure_private_dir(&home)?;
    let lock_path = home.join(REQUEST_LOCK_FILE);
    if let Ok(metadata) = std::fs::symlink_metadata(&lock_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace request lock is not a regular file",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(lock_path)?;
    FileExt::lock_exclusive(&lock)?;
    Ok(lock)
}

fn load_or_create_request_key_locked() -> Result<Zeroizing<Vec<u8>>> {
    let path = request_key_path()?;
    if path.exists() {
        return read_request_key(&path);
    }
    let mut key = Zeroizing::new(vec![0_u8; 32]);
    rand::thread_rng().fill_bytes(&mut key);
    let encoded = Zeroizing::new(hex::encode(&*key));
    crate::fs::atomic_write(&path, encoded.as_bytes())?;
    Ok(key)
}

fn load_existing_request_key_locked() -> Result<Zeroizing<Vec<u8>>> {
    let path = request_key_path()?;
    if !path.exists() {
        return Err(WorkspaceRequestError::NotFound);
    }
    read_request_key(&path)
}

fn read_request_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let encoded = Zeroizing::new(
        String::from_utf8(read_regular_file(path)?).map_err(|_| WorkspaceRequestError::Tampered)?,
    );
    let key = hex::decode(encoded.trim()).map_err(|_| WorkspaceRequestError::Tampered)?;
    if key.len() != 32 {
        return Err(WorkspaceRequestError::Tampered);
    }
    Ok(Zeroizing::new(key))
}

fn read_fixed_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = Zeroizing::new(
        String::from_utf8(read_regular_file(path)?).map_err(|_| WorkspaceRequestError::Tampered)?,
    );
    let decoded =
        Zeroizing::new(hex::decode(encoded.trim()).map_err(|_| WorkspaceRequestError::Tampered)?);
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| WorkspaceRequestError::Tampered)?;
    Ok(Zeroizing::new(key))
}

fn load_record(request_id: &str, key: &[u8]) -> Result<AuthenticatedRecord> {
    let path = request_path(request_id)?;
    if !path.exists() {
        return Err(WorkspaceRequestError::NotFound);
    }
    let bytes = read_regular_file(&path).map_err(|_| WorkspaceRequestError::Tampered)?;
    let record: AuthenticatedRecord =
        serde_json::from_slice(&bytes).map_err(|_| WorkspaceRequestError::Tampered)?;
    if record.request_id != request_id {
        return Err(WorkspaceRequestError::Tampered);
    }
    record.verify(key)?;
    Ok(record)
}

fn read_regular_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "workspace request storage file is not a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "workspace request storage file is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_record(record: &AuthenticatedRecord) -> Result<()> {
    validate_request_id(&record.request_id)?;
    let dir = requests_dir()?;
    ensure_private_dir(&dir)?;
    let bytes = serde_json::to_vec(record).map_err(|_| WorkspaceRequestError::Serialization)?;
    crate::fs::atomic_write(&request_path(&record.request_id)?, &bytes)?;
    Ok(())
}

fn record_authentication(basis: &RecordBasis<'_>, key: &[u8]) -> Result<String> {
    Ok(hex::encode(record_authentication_bytes(basis, key)?))
}

fn record_authentication_bytes(basis: &RecordBasis<'_>, key: &[u8]) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(basis).map_err(|_| WorkspaceRequestError::Serialization)?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(RECORD_DOMAIN);
    mac.update(&bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn random_hex_32() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::{Builder, TempDir};

    fn digest(label: &str) -> String {
        hex::encode(Sha256::digest(label.as_bytes()))
    }

    fn summary() -> SanitizedActionSummary {
        SanitizedActionSummary::new([
            WorkspaceActionKind::InitializeWorkspace,
            WorkspaceActionKind::ProtectEnvironment,
            WorkspaceActionKind::ProtectEnvironment,
        ])
    }

    fn with_temp_home<F, T>(test: F) -> T
    where
        F: FnOnce(&TempDir) -> T,
    {
        let home = TempDir::new().unwrap();
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());
        let result = test(&home);
        match previous {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        result
    }

    #[test]
    fn create_returns_only_id_and_status_is_value_free() {
        with_temp_home(|home| {
            let workspace = TempDir::new().unwrap();
            let request_id =
                create_request(workspace.path(), &digest("plan"), &digest("pre"), summary())
                    .unwrap();
            assert_eq!(request_id.len(), 64);
            let status = get_status(&request_id).unwrap();
            assert_eq!(status.state, WorkspaceRequestState::Pending);
            assert_eq!(status.action_summary.action_count, 3);
            assert_eq!(status.action_summary.kinds.len(), 2);
            assert!(home.path().join(".phantom").join(REQUEST_DIR).exists());
            assert!(!workspace.path().join(".phantom").exists());
        });
    }

    #[test]
    fn sequential_claim_and_terminal_replay_are_rejected() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let plan = digest("plan");
            let pre = digest("pre");
            let request_id = create_request(workspace.path(), &plan, &pre, summary()).unwrap();
            assert_eq!(
                claim_exact(&request_id, workspace.path(), &plan, &pre)
                    .unwrap()
                    .state,
                WorkspaceRequestState::Claimed
            );
            let claimed = get_status(&request_id).unwrap();
            assert!(claimed.execution_deadline.is_some());
            assert!(matches!(
                claim_exact(&request_id, workspace.path(), &plan, &pre),
                Err(WorkspaceRequestError::StateConflict { .. })
            ));
            assert_eq!(
                complete_request(&request_id, workspace.path(), &plan, &pre)
                    .unwrap()
                    .state,
                WorkspaceRequestState::Applied
            );
            assert!(matches!(
                complete_request(&request_id, workspace.path(), &plan, &pre),
                Err(WorkspaceRequestError::StateConflict { .. })
            ));
        });
    }

    #[test]
    fn identical_pending_request_is_reused_and_workspace_pending_is_capped() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let pre = digest("pre");
            let first = create_request(workspace.path(), &digest("same"), &pre, summary()).unwrap();
            let reused =
                create_request(workspace.path(), &digest("same"), &pre, summary()).unwrap();
            assert_eq!(first, reused);
            for index in 1..MAX_PENDING_PER_WORKSPACE {
                create_request(
                    workspace.path(),
                    &digest(&format!("plan-{index}")),
                    &pre,
                    summary(),
                )
                .unwrap();
            }
            assert!(matches!(
                create_request(workspace.path(), &digest("over-limit"), &pre, summary()),
                Err(WorkspaceRequestError::PendingLimit)
            ));
        });
    }

    #[test]
    fn claimed_requests_do_not_expire_and_applied_receipt_persists() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let plan = digest("receipt-plan");
            let pre = digest("receipt-pre");
            let request_id = create_request(workspace.path(), &plan, &pre, summary()).unwrap();
            claim_exact(&request_id, workspace.path(), &plan, &pre).unwrap();

            let key = load_existing_request_key_locked().unwrap();
            let mut record = load_record(&request_id, &key).unwrap();
            record.expires_at = 0;
            record.execution_deadline = Some(0);
            record.authenticate(&key).unwrap();
            write_record(&record).unwrap();
            let overdue = get_status(&request_id).unwrap();
            assert_eq!(overdue.state, WorkspaceRequestState::Claimed);
            assert_eq!(
                overdue.execution_outcome,
                Some(WorkspaceExecutionOutcome::RecoveryRequired)
            );

            let receipt = WorkspaceApplyReceipt {
                receipt_digest: digest("receipt"),
                file_change_count: 3,
                fully_applied: true,
                recorded_at: 42,
            };
            let status = complete_request_with_receipt(
                &request_id,
                workspace.path(),
                &plan,
                &pre,
                receipt.clone(),
            )
            .unwrap();
            assert_eq!(status.state, WorkspaceRequestState::Applied);
            assert_eq!(status.execution_deadline, None);
            assert_eq!(status.receipt, Some(receipt));
            assert_eq!(get_status(&request_id).unwrap().receipt, status.receipt);
        });
    }

    #[test]
    fn creating_a_request_prunes_expired_pending_records() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let expired = create_request_at(
                workspace.path(),
                &digest("old"),
                &digest("old-pre"),
                summary(),
                0,
            )
            .unwrap();
            assert!(request_path(&expired).unwrap().exists());
            create_request(
                workspace.path(),
                &digest("new"),
                &digest("new-pre"),
                summary(),
            )
            .unwrap();
            assert!(!request_path(&expired).unwrap().exists());
        });
    }

    #[test]
    fn concurrent_claim_is_exactly_once() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let plan = digest("plan");
            let pre = digest("pre");
            let request_id = create_request(workspace.path(), &plan, &pre, summary()).unwrap();
            let barrier = Arc::new(Barrier::new(3));
            let mut workers = Vec::new();
            for _ in 0..2 {
                let barrier = Arc::clone(&barrier);
                let workspace = workspace.path().to_path_buf();
                let plan = plan.clone();
                let pre = pre.clone();
                let request_id = request_id.clone();
                workers.push(std::thread::spawn(move || {
                    barrier.wait();
                    claim_exact(&request_id, &workspace, &plan, &pre)
                }));
            }
            barrier.wait();
            let results: Vec<_> = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect();
            assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
            assert_eq!(
                results
                    .iter()
                    .filter(|result| matches!(
                        result,
                        Err(WorkspaceRequestError::StateConflict { .. })
                    ))
                    .count(),
                1
            );
        });
    }

    #[test]
    fn exact_binding_rejects_workspace_plan_and_pre_state_mismatch() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let other_workspace = TempDir::new().unwrap();
            let plan = digest("plan");
            let pre = digest("pre");
            let request_id = create_request(workspace.path(), &plan, &pre, summary()).unwrap();
            assert!(matches!(
                claim_exact(&request_id, other_workspace.path(), &plan, &pre),
                Err(WorkspaceRequestError::WorkspaceMismatch)
            ));
            assert!(matches!(
                claim_exact(&request_id, workspace.path(), &digest("other-plan"), &pre),
                Err(WorkspaceRequestError::PlanMismatch)
            ));
            assert!(matches!(
                claim_exact(&request_id, workspace.path(), &plan, &digest("other-pre")),
                Err(WorkspaceRequestError::PreStateMismatch)
            ));
            assert!(claim_exact(&request_id, workspace.path(), &plan, &pre).is_ok());
        });
    }

    #[test]
    fn tampering_is_rejected_before_transition() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let plan = digest("plan");
            let pre = digest("pre");
            let request_id = create_request(workspace.path(), &plan, &pre, summary()).unwrap();
            let path = request_path(&request_id).unwrap();
            let mut json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            json["plan_id"] = serde_json::Value::String(digest("tampered-plan"));
            crate::fs::atomic_write(&path, &serde_json::to_vec(&json).unwrap()).unwrap();
            assert!(matches!(
                get_status(&request_id),
                Err(WorkspaceRequestError::Tampered)
            ));
        });
    }

    #[test]
    fn expiry_uses_greater_than_or_equal_and_persists_terminal_state() {
        with_temp_home(|_| {
            let basis = RecordBasis {
                request_id: &"a".repeat(64),
                workspace_scope_hash: &digest("workspace"),
                plan_id: &digest("plan"),
                pre_state_id: &digest("pre"),
                action_summary: &summary(),
                state: WorkspaceRequestState::Pending,
                created_at: 10,
                expires_at: 20,
                execution_deadline: None,
                execution_outcome: None,
                updated_at: 10,
                receipt: &None,
            };
            let record = AuthenticatedRecord {
                request_id: basis.request_id.to_string(),
                workspace_scope_hash: basis.workspace_scope_hash.to_string(),
                plan_id: basis.plan_id.to_string(),
                pre_state_id: basis.pre_state_id.to_string(),
                action_summary: basis.action_summary.clone(),
                state: basis.state,
                created_at: basis.created_at,
                expires_at: basis.expires_at,
                execution_deadline: basis.execution_deadline,
                execution_outcome: basis.execution_outcome,
                updated_at: basis.updated_at,
                receipt: None,
                authentication: String::new(),
            };
            assert!(!record.is_expired_at(19));
            assert!(record.is_expired_at(20));

            let workspace = TempDir::new().unwrap();
            let request_id = create_request_at(
                workspace.path(),
                &digest("expired-plan"),
                &digest("expired-pre"),
                summary(),
                0,
            )
            .unwrap();
            assert_eq!(
                get_status(&request_id).unwrap().state,
                WorkspaceRequestState::Expired
            );
            assert_eq!(
                get_status(&request_id).unwrap().state,
                WorkspaceRequestState::Expired
            );
        });
    }

    #[test]
    fn all_terminal_transitions_are_supported() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let plan = digest("plan");
            let pre = digest("pre");
            let failed = create_request(workspace.path(), &plan, &pre, summary()).unwrap();
            claim_exact(&failed, workspace.path(), &plan, &pre).unwrap();
            assert_eq!(
                fail_request(&failed, workspace.path(), &plan, &pre)
                    .unwrap()
                    .state,
                WorkspaceRequestState::Failed
            );

            let rolled_back = create_request(workspace.path(), &plan, &pre, summary()).unwrap();
            claim_exact(&rolled_back, workspace.path(), &plan, &pre).unwrap();
            assert_eq!(
                rollback_request(&rolled_back, workspace.path(), &plan, &pre)
                    .unwrap()
                    .state,
                WorkspaceRequestState::RolledBack
            );
        });
    }

    #[test]
    fn sentinel_values_and_raw_workspace_path_never_reach_storage() {
        with_temp_home(|home| {
            let sentinel = "sk_live_SENTINEL_NEVER_STORE_9x7";
            let workspace = Builder::new().prefix(sentinel).tempdir().unwrap();
            std::fs::write(
                workspace.path().join(".env"),
                format!("API_KEY={sentinel}\n"),
            )
            .unwrap();
            create_request(workspace.path(), &digest("plan"), &digest("pre"), summary()).unwrap();
            let phantom_dir = home.path().join(".phantom");
            for entry in std::fs::read_dir(&phantom_dir).unwrap() {
                let entry = entry.unwrap();
                if entry.path().is_dir() {
                    for record in std::fs::read_dir(entry.path()).unwrap() {
                        let bytes = std::fs::read(record.unwrap().path()).unwrap();
                        let text = String::from_utf8_lossy(&bytes);
                        assert!(!text.contains(sentinel));
                        assert!(!text.contains(&workspace.path().to_string_lossy().to_string()));
                        assert!(!text.contains("API_KEY"));
                    }
                }
            }
        });
    }

    #[test]
    fn arbitrary_or_secret_shaped_identifiers_are_rejected() {
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            assert!(matches!(
                create_request(
                    workspace.path(),
                    "sk_live_secret",
                    &digest("pre"),
                    summary()
                ),
                Err(WorkspaceRequestError::InvalidDigest("plan_id"))
            ));
        });
    }

    #[cfg(unix)]
    #[test]
    fn key_records_and_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;
        with_temp_home(|_| {
            let workspace = TempDir::new().unwrap();
            let request_id =
                create_request(workspace.path(), &digest("plan"), &digest("pre"), summary())
                    .unwrap();
            for path in [
                request_key_path().unwrap(),
                request_path(&request_id).unwrap(),
            ] {
                let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
            let mode = std::fs::metadata(requests_dir().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        });
    }

    #[test]
    fn plan_seal_key_is_stable_separate_and_domain_derived() {
        with_temp_home(|_| {
            let (first, first_created) = load_or_create_workspace_plan_key_with_status().unwrap();
            let (second, second_created) = load_or_create_workspace_plan_key_with_status().unwrap();
            assert!(first_created);
            assert!(!second_created);
            assert_eq!(first.as_ref(), second.as_ref());
            assert_eq!(
                load_existing_workspace_plan_key().unwrap().as_ref(),
                first.as_ref()
            );

            let stored = read_fixed_key(&phantom_home().unwrap().join(PLAN_KEY_FILE)).unwrap();
            assert_ne!(first.as_ref(), stored.as_ref());
            assert_ne!(
                phantom_home().unwrap().join(PLAN_KEY_FILE),
                request_key_path().unwrap()
            );

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(phantom_home().unwrap().join(PLAN_KEY_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600);
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_request_directory_is_rejected() {
        use std::os::unix::fs::symlink;
        with_temp_home(|home| {
            let workspace = TempDir::new().unwrap();
            let phantom_dir = home.path().join(".phantom");
            std::fs::create_dir(&phantom_dir).unwrap();
            symlink(workspace.path(), phantom_dir.join(REQUEST_DIR)).unwrap();

            assert!(matches!(
                create_request(workspace.path(), &digest("plan"), &digest("pre"), summary(),),
                Err(WorkspaceRequestError::Io(_))
            ));
            assert!(std::fs::read_dir(workspace.path())
                .unwrap()
                .next()
                .is_none());
        });
    }
}
