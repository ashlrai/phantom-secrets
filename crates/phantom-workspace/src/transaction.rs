use crate::discovery::{digest_hex, WorkspaceInspection};
use crate::plan::{build_setup_plan, plan_has_valid_id};
use crate::{inspect_workspace, Result, SetupAction, SetupActionKind, SetupPlan, WorkspaceError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use phantom_core::config::PhantomConfig;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

const TRANSACTION_SCHEMA_VERSION: u8 = 1;
const JOURNAL_SCHEMA_VERSION: u8 = 1;
const JOURNAL_AAD_DOMAIN: &[u8] = b"phantom.workspace-transaction-journal.v1\0";
const ENV_IGNORE_PATTERNS: &[&str] = &[".env", ".env.local", ".env.*.local", ".env.backup"];
const HOOK_MARKER: &str = "# Phantom Secrets pre-commit hook";
const HOOK_COMMAND: &str = "npx phantom-secrets check --staged";
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
static PROCESS_TRANSACTION_LOCK: Mutex<()> = Mutex::new(());

struct WorkspaceLock {
    _process: MutexGuard<'static, ()>,
    _file: File,
}

/// Process-local key used to seal an executable plan to exact pre-state bytes.
///
/// The key has no `Debug`, `Clone`, or serialization implementation and is
/// overwritten on drop. Production callers should load it from a trusted local
/// key store, never from MCP arguments, argv, or an agent-readable environment.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlanSealKey([u8; 32]);

impl PlanSealKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// An inspect plan bound to the exact bytes/absence of every planned file and
/// every discovered dotenv file using HMAC-SHA256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSetupPlan {
    pub plan: SetupPlan,
    pub pre_state_id: String,
}

/// A safe, non-secret participant failure code.
///
/// The code is static by design so an adapter cannot accidentally propagate a
/// provider or vault error containing credential material into a receipt/log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParticipantError {
    code: &'static str,
}

impl ParticipantError {
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

/// An opaque, redacted filesystem mutation staged by a future vault adapter.
///
/// This type intentionally implements neither `Serialize` nor content-bearing
/// `Debug`. A vault participant may use it to return a tokenized dotenv file
/// without making the bytes available to plans or receipts.
pub struct ParticipantFileMutation {
    target: String,
    content: Vec<u8>,
    executable: bool,
}

impl ParticipantFileMutation {
    pub fn replace(target: impl Into<String>, content: Vec<u8>) -> Self {
        Self {
            target: target.into(),
            content,
            executable: false,
        }
    }

    pub fn executable(mut self, executable: bool) -> Self {
        self.executable = executable;
        self
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

impl fmt::Debug for ParticipantFileMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParticipantFileMutation")
            .field("target", &self.target)
            .field("content", &"[REDACTED]")
            .field("executable", &self.executable)
            .finish()
    }
}

/// Value-free result of staging an external transaction participant.
#[derive(Default)]
pub struct ParticipantPreparation {
    completed_action_ids: BTreeSet<String>,
    file_mutations: Vec<ParticipantFileMutation>,
}

impl ParticipantPreparation {
    pub fn new(
        completed_action_ids: impl IntoIterator<Item = String>,
        file_mutations: Vec<ParticipantFileMutation>,
    ) -> Self {
        Self {
            completed_action_ids: completed_action_ids.into_iter().collect(),
            file_mutations,
        }
    }
}

impl fmt::Debug for ParticipantPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParticipantPreparation")
            .field("completed_action_ids", &self.completed_action_ids)
            .field("file_mutation_count", &self.file_mutations.len())
            .finish()
    }
}

/// Transaction seam for vault- or authority-dependent setup work.
///
/// `prepare` receives only a value-free plan. An implementation may privately
/// read exact approved dotenv targets, stage vault state, and return tokenized
/// file replacements. It must retain enough private state for `rollback`.
pub trait SetupTransactionParticipant {
    fn prepare(
        &mut self,
        plan: &SetupPlan,
        external_actions: &[SetupAction],
    ) -> std::result::Result<ParticipantPreparation, ParticipantError>;

    fn commit(&mut self) -> std::result::Result<(), ParticipantError>;

    fn rollback(&mut self) -> std::result::Result<(), ParticipantError>;

    /// Return the participant's encrypted-journal recovery material after
    /// `prepare`. The transaction engine encrypts this opaque payload before
    /// the first filesystem or participant mutation.
    fn recovery_payload(&self) -> std::result::Result<Vec<u8>, ParticipantError> {
        Ok(Vec::new())
    }

    /// Restore participant recovery state from a previously encrypted journal.
    fn restore_recovery_payload(
        &mut self,
        payload: &[u8],
    ) -> std::result::Result<(), ParticipantError> {
        if payload.is_empty() {
            Ok(())
        } else {
            Err(ParticipantError::new("unsupported_recovery_payload"))
        }
    }
}

/// Trusted local configuration for an encrypted transaction journal. The key
/// intentionally has no serialization or `Debug` implementation.
pub struct DurableJournalConfig {
    request_id: String,
    path: PathBuf,
    key: [u8; 32],
}

impl Drop for DurableJournalConfig {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl DurableJournalConfig {
    pub fn new(request_id: impl Into<String>, path: PathBuf, key: [u8; 32]) -> Self {
        Self {
            request_id: request_id.into(),
            path,
            key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecovery {
    Absent,
    RolledBack,
    Applied(SetupTransactionReceipt),
}

/// Participant used until the real vault transaction adapter is wired.
/// Secret protection and place binding remain explicitly deferred.
#[derive(Debug, Default)]
pub struct NoopSetupParticipant;

impl SetupTransactionParticipant for NoopSetupParticipant {
    fn prepare(
        &mut self,
        _plan: &SetupPlan,
        _external_actions: &[SetupAction],
    ) -> std::result::Result<ParticipantPreparation, ParticipantError> {
        Ok(ParticipantPreparation::default())
    }

    fn commit(&mut self) -> std::result::Result<(), ParticipantError> {
        Ok(())
    }

    fn rollback(&mut self) -> std::result::Result<(), ParticipantError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcomeState {
    Applied,
    AlreadySatisfied,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub action_id: String,
    pub kind: SetupActionKind,
    pub target: String,
    pub state: ActionOutcomeState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChangeReceipt {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_state_id: Option<String>,
    pub after_state_id: String,
}

/// Safe-to-serialize transaction evidence. It contains hashes, never bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupTransactionReceipt {
    pub schema_version: u8,
    pub plan_id: String,
    pub workspace_fingerprint: String,
    pub replayed_plan: bool,
    pub actions: Vec<ActionOutcome>,
    pub file_changes: Vec<FileChangeReceipt>,
    pub fully_applied: bool,
}

impl SetupTransactionReceipt {
    /// Stable SHA-256 digest of the value-free serialized receipt.
    pub fn digest_hex(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

/// A recoverable filesystem snapshot. Contents are private and redacted.
///
/// Snapshots are intentionally not serializable because they can contain prior
/// local file bytes. The current filesystem-only engine does not mutate dotenv
/// files unless an explicit participant supplies a tokenized replacement.
/// Durable crash journals are deliberately deferred: persisting these bytes is
/// unsafe until an out-of-repository encrypted journal and caller-held journal
/// key are implemented and independently reviewed.
pub struct WorkspaceSnapshot {
    workspace_root: PathBuf,
    #[cfg(unix)]
    root_directory: File,
    files: Vec<FileSnapshot>,
    created_directories: Vec<PathBuf>,
    finalized: bool,
}

impl fmt::Debug for WorkspaceSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceSnapshot")
            .field("workspace_root", &self.workspace_root)
            .field("file_count", &self.files.len())
            .field("created_directory_count", &self.created_directories.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

pub struct SetupTransaction {
    pub receipt: SetupTransactionReceipt,
    pub snapshot: WorkspaceSnapshot,
}

impl fmt::Debug for SetupTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SetupTransaction")
            .field("receipt", &self.receipt)
            .field("snapshot", &self.snapshot)
            .finish()
    }
}

struct FileMutation {
    target: String,
    content: Vec<u8>,
    executable: bool,
    action_id: String,
}

enum FileState {
    Missing,
    Present {
        content: Vec<u8>,
        permissions: Permissions,
    },
}

struct FileSnapshot {
    target: String,
    path: PathBuf,
    before: FileState,
    after: Option<Vec<u8>>,
    #[cfg(unix)]
    parent: Option<SecureParent>,
}

#[cfg(unix)]
struct SecureParent {
    directory: File,
    name: CString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    FilesApplied,
    ParticipantCommitStarted,
    Applied,
    RolledBack,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    target: String,
    before: Option<Vec<u8>>,
    #[cfg(unix)]
    before_mode: Option<u32>,
    after: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    schema_version: u8,
    request_id: String,
    plan_id: String,
    pre_state_id: String,
    phase: JournalPhase,
    files: Vec<JournalFile>,
    participant_payload: Vec<u8>,
    receipt: Option<SetupTransactionReceipt>,
}

struct DurableJournal {
    request_id: String,
    path: PathBuf,
    key: [u8; 32],
    record: JournalRecord,
}

impl Drop for DurableJournal {
    fn drop(&mut self) {
        self.key.zeroize();
        self.record.participant_payload.zeroize();
        for file in &mut self.record.files {
            if let Some(before) = file.before.as_mut() {
                before.zeroize();
            }
            file.after.zeroize();
        }
    }
}

/// Build the only executable setup-plan form under the same cross-process lock
/// used by apply. The inspect-only `SetupPlan` cannot be passed to apply.
pub fn build_sealed_setup_plan(
    root: impl AsRef<Path>,
    seal_key: &PlanSealKey,
) -> Result<SealedSetupPlan> {
    let requested_root = root.as_ref();
    let canonical_root = requested_root
        .canonicalize()
        .map_err(|source| WorkspaceError::Io {
            path: requested_root.to_path_buf(),
            source,
        })?;
    let _lock = acquire_workspace_lock(&canonical_root)?;
    let inspection = inspect_workspace(&canonical_root)?;
    let plan = build_setup_plan(&inspection)?;
    let pre_state_id = calculate_pre_state_id(&plan, &inspection, &canonical_root, seal_key)?;
    Ok(SealedSetupPlan { plan, pre_state_id })
}

/// Apply the exact approved plan after recomputing the workspace plan under a
/// cross-process lock.
///
/// Idempotent callers build a fresh sealed plan after a successful application;
/// the desired filesystem merge then produces no duplicate content. A stale
/// seal is always rejected, including when only a dotenv value changed.
pub fn apply_setup_plan<P: SetupTransactionParticipant>(
    sealed_plan: &SealedSetupPlan,
    seal_key: &PlanSealKey,
    participant: &mut P,
) -> Result<SetupTransaction> {
    apply_setup_plan_inner(sealed_plan, seal_key, participant, None)
}

/// Apply with an encrypted out-of-workspace write-ahead journal. `prepare`
/// must be read-only: the journal is durably written after preparation and
/// snapshot capture, before any filesystem write or participant `commit`.
///
/// Durability scope: Unix implementations pin validated parent directories and
/// use descriptor-relative no-follow operations plus file/directory fsync. A
/// namespace rename can relocate the already-validated directory inode, but it
/// cannot redirect the mutation into a replacement path. Non-Unix mutation and
/// incomplete recovery fail closed because equivalent guarantees are unproven.
pub fn apply_setup_plan_durable<P: SetupTransactionParticipant>(
    sealed_plan: &SealedSetupPlan,
    seal_key: &PlanSealKey,
    participant: &mut P,
    journal: &DurableJournalConfig,
) -> Result<SetupTransaction> {
    apply_setup_plan_inner(sealed_plan, seal_key, participant, Some(journal))
}

fn apply_setup_plan_inner<P: SetupTransactionParticipant>(
    sealed_plan: &SealedSetupPlan,
    seal_key: &PlanSealKey,
    participant: &mut P,
    journal_config: Option<&DurableJournalConfig>,
) -> Result<SetupTransaction> {
    #[cfg(not(unix))]
    {
        let _ = (sealed_plan, seal_key, participant, journal_config);
        return Err(WorkspaceError::SafeMutationUnsupported);
    }

    let approved_plan = &sealed_plan.plan;
    if !plan_has_valid_id(approved_plan)? {
        return Err(WorkspaceError::InvalidPlan);
    }

    let requested_root = PathBuf::from(&approved_plan.workspace_root);
    let canonical_root = requested_root
        .canonicalize()
        .map_err(|source| WorkspaceError::Io {
            path: requested_root.clone(),
            source,
        })?;
    if canonical_root.to_string_lossy() != approved_plan.workspace_root {
        return Err(WorkspaceError::InvalidPlan);
    }

    let _lock = acquire_workspace_lock(&canonical_root)?;
    #[cfg(unix)]
    let root_directory = open_root_directory(&canonical_root)?;
    #[cfg(not(unix))]
    let root_directory = File::open(&canonical_root).map_err(|source| WorkspaceError::Io {
        path: canonical_root.clone(),
        source,
    })?;
    let inspection = inspect_workspace(&canonical_root)?;
    let current_plan = build_setup_plan(&inspection)?;
    validate_sealed_state(
        sealed_plan,
        &current_plan,
        &inspection,
        &canonical_root,
        seal_key,
    )?;

    let external_actions = approved_plan
        .actions
        .iter()
        .filter(|action| {
            matches!(
                action.kind,
                SetupActionKind::ProtectEnvFile | SetupActionKind::ReviewPlaceBinding
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let preparation = match participant.prepare(approved_plan, &external_actions) {
        Ok(preparation) => preparation,
        Err(error) => {
            return Err(abort_participant(
                participant,
                WorkspaceError::Participant {
                    stage: "prepare",
                    code: error.code,
                },
            ));
        }
    };
    if let Err(error) = validate_preparation(&preparation, &external_actions) {
        return Err(abort_participant(participant, error));
    }

    let ParticipantPreparation {
        completed_action_ids,
        file_mutations,
    } = preparation;
    let mutations_result = (|| -> Result<Vec<FileMutation>> {
        let mut mutations = build_filesystem_mutations(
            approved_plan,
            &inspection,
            &canonical_root,
            &root_directory,
        )?;
        for mutation in file_mutations {
            let action = external_actions
                .iter()
                .find(|action| {
                    action.id == mutation_action_id(&mutation, &external_actions).as_str()
                })
                .ok_or(WorkspaceError::InvalidPlan)?;
            mutations.push(FileMutation {
                target: mutation.target,
                content: mutation.content,
                executable: mutation.executable,
                action_id: action.id.clone(),
            });
        }
        ensure_unique_targets(&mut mutations)?;
        Ok(mutations)
    })();
    let mutations = match mutations_result {
        Ok(mutations) => mutations,
        Err(error) => return Err(abort_participant(participant, error)),
    };

    // `prepare` is staging-only. Recompute the keyed precondition immediately
    // before snapshot/write so an adapter or non-cooperating process cannot
    // silently alter a planned file during staging.
    let post_prepare_validation = (|| -> Result<()> {
        let post_prepare_inspection = inspect_workspace(&canonical_root)?;
        let post_prepare_plan = build_setup_plan(&post_prepare_inspection)?;
        validate_sealed_state(
            sealed_plan,
            &post_prepare_plan,
            &post_prepare_inspection,
            &canonical_root,
            seal_key,
        )
    })();
    if let Err(error) = post_prepare_validation {
        return Err(abort_participant(participant, error));
    }
    #[cfg(unix)]
    verify_root_identity(&canonical_root, &root_directory)?;

    let mut snapshot = match capture_snapshot(&canonical_root, &root_directory, &mutations) {
        Ok(snapshot) => snapshot,
        Err(error) => return Err(abort_participant(participant, error)),
    };
    let mut journal = if let Some(config) = journal_config {
        let payload = participant.recovery_payload().map_err(|error| {
            abort_participant(
                participant,
                WorkspaceError::Participant {
                    stage: "recovery_payload",
                    code: error.code,
                },
            )
        })?;
        Some(DurableJournal::create(
            config,
            sealed_plan,
            &snapshot,
            &mutations,
            payload,
        )?)
    } else {
        None
    };
    let write_result = apply_mutations(&canonical_root, &mutations, &mut snapshot);
    if let Err(error) = write_result {
        let filesystem_rolled_back = restore_snapshot_unchecked(&snapshot).is_ok();
        let participant_rolled_back = participant.rollback().is_ok();
        if filesystem_rolled_back && participant_rolled_back {
            if let Some(journal) = journal.as_mut() {
                let _ = journal.set_phase(JournalPhase::RolledBack, None);
            }
        }
        return if filesystem_rolled_back && participant_rolled_back {
            Err(error)
        } else {
            Err(WorkspaceError::RollbackIncomplete)
        };
    }

    if let Err(error) = finalize_snapshot(&mut snapshot) {
        let filesystem_rolled_back = restore_snapshot_unchecked(&snapshot).is_ok();
        let participant_rolled_back = participant.rollback().is_ok();
        return if filesystem_rolled_back && participant_rolled_back {
            Err(error)
        } else {
            Err(WorkspaceError::RollbackIncomplete)
        };
    }
    if let Some(journal) = journal.as_mut() {
        journal.set_phase(JournalPhase::FilesApplied, None)?;
        journal.set_phase(JournalPhase::ParticipantCommitStarted, None)?;
    }
    if let Err(error) = participant.commit() {
        let filesystem_rolled_back = restore_snapshot_unchecked(&snapshot).is_ok();
        let participant_rolled_back = participant.rollback().is_ok();
        return if filesystem_rolled_back && participant_rolled_back {
            Err(WorkspaceError::Participant {
                stage: "commit",
                code: error.code,
            })
        } else {
            Err(WorkspaceError::RollbackIncomplete)
        };
    }

    let receipt = build_receipt(
        approved_plan,
        false,
        &mutations,
        &snapshot,
        &completed_action_ids,
        seal_key,
    );
    if let Some(journal) = journal.as_mut() {
        journal.set_phase(JournalPhase::Applied, Some(receipt.clone()))?;
    }
    Ok(SetupTransaction { receipt, snapshot })
}

fn abort_participant<P: SetupTransactionParticipant>(
    participant: &mut P,
    error: WorkspaceError,
) -> WorkspaceError {
    if participant.rollback().is_ok() {
        error
    } else {
        WorkspaceError::RollbackIncomplete
    }
}

impl DurableJournal {
    fn create(
        config: &DurableJournalConfig,
        sealed: &SealedSetupPlan,
        snapshot: &WorkspaceSnapshot,
        mutations: &[FileMutation],
        participant_payload: Vec<u8>,
    ) -> Result<Self> {
        let files = snapshot
            .files
            .iter()
            .map(|file| {
                let mutation = mutations
                    .iter()
                    .find(|mutation| mutation.target == file.target)
                    .ok_or(WorkspaceError::InvalidPlan)?;
                let (before, before_mode) = match &file.before {
                    FileState::Missing => (None, None),
                    FileState::Present {
                        content,
                        permissions,
                    } => {
                        #[cfg(unix)]
                        let mode = {
                            use std::os::unix::fs::PermissionsExt;
                            Some(permissions.mode())
                        };
                        #[cfg(not(unix))]
                        let mode = None;
                        (Some(content.clone()), mode)
                    }
                };
                Ok(JournalFile {
                    target: file.target.clone(),
                    before,
                    #[cfg(unix)]
                    before_mode,
                    after: mutation.content.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut journal = Self {
            request_id: config.request_id.clone(),
            path: config.path.clone(),
            key: config.key,
            record: JournalRecord {
                schema_version: JOURNAL_SCHEMA_VERSION,
                request_id: config.request_id.clone(),
                plan_id: sealed.plan.plan_id.clone(),
                pre_state_id: sealed.pre_state_id.clone(),
                phase: JournalPhase::Prepared,
                files,
                participant_payload,
                receipt: None,
            },
        };
        journal.persist()?;
        Ok(journal)
    }

    fn load(config: &DurableJournalConfig) -> Result<Option<Self>> {
        match std::fs::symlink_metadata(&config.path) {
            Ok(metadata) => validate_target_metadata(&config.path, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(WorkspaceError::Io {
                    path: config.path.clone(),
                    source,
                })
            }
        }
        let bytes = std::fs::read(&config.path).map_err(|source| WorkspaceError::Io {
            path: config.path.clone(),
            source,
        })?;
        if bytes.len() < 16 || &bytes[..4] != b"PHJ1" {
            return Err(WorkspaceError::InvalidJournal);
        }
        let cipher = ChaCha20Poly1305::new((&config.key).into());
        let aad = journal_aad(&config.request_id);
        let plaintext = zeroize::Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&bytes[4..16]),
                    Payload {
                        msg: &bytes[16..],
                        aad: &aad,
                    },
                )
                .map_err(|_| WorkspaceError::InvalidJournal)?,
        );
        let record: JournalRecord =
            serde_json::from_slice(&plaintext).map_err(|_| WorkspaceError::InvalidJournal)?;
        if record.schema_version != JOURNAL_SCHEMA_VERSION || record.request_id != config.request_id
        {
            return Err(WorkspaceError::InvalidJournal);
        }
        Ok(Some(Self {
            request_id: config.request_id.clone(),
            path: config.path.clone(),
            key: config.key,
            record,
        }))
    }

    fn set_phase(
        &mut self,
        phase: JournalPhase,
        receipt: Option<SetupTransactionReceipt>,
    ) -> Result<()> {
        self.record.phase = phase;
        if receipt.is_some() {
            self.record.receipt = receipt;
        }
        self.persist()
    }

    fn persist(&mut self) -> Result<()> {
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&self.record)?);
        let mut nonce = [0_u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let aad = journal_aad(&self.request_id);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| WorkspaceError::InvalidJournal)?;
        let mut encoded = Vec::with_capacity(16 + ciphertext.len());
        encoded.extend_from_slice(b"PHJ1");
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        phantom_core::fs::atomic_write(&self.path, &encoded).map_err(|source| WorkspaceError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

fn journal_aad(request_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(JOURNAL_AAD_DOMAIN.len() + request_id.len());
    aad.extend_from_slice(JOURNAL_AAD_DOMAIN);
    aad.extend_from_slice(request_id.as_bytes());
    aad
}

/// Recover a request-scoped journal before rebuilding or applying a plan.
/// Incomplete phases are rolled back only when every current file is either the
/// recorded before-image or the exact intended after-image. An applied journal
/// returns its persisted receipt so the caller can repair request state without
/// re-running mutations.
pub fn recover_setup_plan_journal<P: SetupTransactionParticipant>(
    workspace_root: &Path,
    plan_id: &str,
    pre_state_id: &str,
    participant: &mut P,
    config: &DurableJournalConfig,
) -> Result<JournalRecovery> {
    let Some(mut journal) = DurableJournal::load(config)? else {
        return Ok(JournalRecovery::Absent);
    };
    if journal.record.plan_id != plan_id || journal.record.pre_state_id != pre_state_id {
        return Err(WorkspaceError::JournalMismatch);
    }
    match journal.record.phase {
        JournalPhase::Applied => {
            let receipt = journal
                .record
                .receipt
                .clone()
                .ok_or(WorkspaceError::InvalidJournal)?;
            return Ok(JournalRecovery::Applied(receipt));
        }
        JournalPhase::RolledBack => return Ok(JournalRecovery::RolledBack),
        JournalPhase::Prepared
        | JournalPhase::FilesApplied
        | JournalPhase::ParticipantCommitStarted => {}
    }

    let root = workspace_root
        .canonicalize()
        .map_err(|source| WorkspaceError::Io {
            path: workspace_root.to_path_buf(),
            source,
        })?;
    let _lock = acquire_workspace_lock(&root)?;
    #[cfg(unix)]
    let root_directory = open_root_directory(&root)?;
    #[cfg(not(unix))]
    let root_directory = File::open(&root).map_err(|source| WorkspaceError::Io {
        path: root.clone(),
        source,
    })?;
    #[cfg(not(unix))]
    return Err(WorkspaceError::SafeMutationUnsupported);

    #[cfg(unix)]
    let mut parents = Vec::with_capacity(journal.record.files.len());
    #[cfg(unix)]
    for file in &journal.record.files {
        let path = root.join(&file.target);
        let mut no_created = Vec::new();
        let parent = secure_parent(&root, &root_directory, &file.target, false, &mut no_created)?
            .ok_or_else(|| WorkspaceError::RollbackDrift(path.clone()))?;
        let current = read_at(&parent, &path)?.map(|(content, _)| content);
        if current.as_ref() != file.before.as_ref() && current.as_ref() != Some(&file.after) {
            return Err(WorkspaceError::RollbackDrift(path));
        }
        parents.push(parent);
    }
    participant
        .restore_recovery_payload(&journal.record.participant_payload)
        .map_err(|error| WorkspaceError::Participant {
            stage: "restore_recovery_payload",
            code: error.code,
        })?;
    let participant_ok = participant.rollback().is_ok();
    let mut filesystem_ok = true;
    #[cfg(unix)]
    for (file, parent) in journal.record.files.iter().zip(parents.iter()).rev() {
        let path = root.join(&file.target);
        let restored = match &file.before {
            Some(content) => {
                let permissions = file.before_mode.map(|mode| {
                    use std::os::unix::fs::PermissionsExt;
                    Permissions::from_mode(mode)
                });
                write_at(parent, &path, content, permissions, false)
            }
            None => unlink_at(parent, &path, 0),
        };
        if restored.is_err() {
            filesystem_ok = false;
        }
    }
    if !participant_ok || !filesystem_ok {
        return Err(WorkspaceError::RollbackIncomplete);
    }
    journal.set_phase(JournalPhase::RolledBack, None)?;
    Ok(JournalRecovery::RolledBack)
}

/// Delete an already-terminal encrypted journal after its value-free receipt
/// has been persisted in the authenticated request record.
pub fn clear_setup_plan_journal(config: &DurableJournalConfig) -> Result<()> {
    match std::fs::remove_file(&config.path) {
        Ok(()) => {
            if let Some(parent) = config.path.parent() {
                phantom_core::fs::sync_parent_dir(parent).map_err(|source| WorkspaceError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(WorkspaceError::Io {
            path: config.path.clone(),
            source,
        }),
    }
}

/// Restore a completed transaction's filesystem snapshot without overwriting
/// later user changes. External participant state is not included.
pub fn rollback_workspace(snapshot: WorkspaceSnapshot) -> Result<()> {
    if !snapshot.finalized {
        return Err(WorkspaceError::InvalidPlan);
    }
    let _lock = acquire_workspace_lock(&snapshot.workspace_root)?;
    for file in &snapshot.files {
        #[cfg(unix)]
        let current = read_at(
            file.parent.as_ref().ok_or(WorkspaceError::InvalidPlan)?,
            &file.path,
        )?
        .map(|(content, _)| content);
        #[cfg(not(unix))]
        let current = read_optional(&file.path)?;
        if current != file.after {
            return Err(WorkspaceError::RollbackDrift(file.path.clone()));
        }
    }
    restore_snapshot_unchecked(&snapshot)
}

fn validate_preparation(
    preparation: &ParticipantPreparation,
    external_actions: &[SetupAction],
) -> Result<()> {
    let external_ids = external_actions
        .iter()
        .map(|action| action.id.as_str())
        .collect::<BTreeSet<_>>();
    if preparation
        .completed_action_ids
        .iter()
        .any(|id| !external_ids.contains(id.as_str()))
    {
        return Err(WorkspaceError::InvalidPlan);
    }
    for mutation in &preparation.file_mutations {
        let Some(action) = external_actions.iter().find(|action| {
            action.kind == SetupActionKind::ProtectEnvFile && action.target == mutation.target
        }) else {
            return Err(WorkspaceError::UnsafeTarget(PathBuf::from(
                &mutation.target,
            )));
        };
        if !preparation.completed_action_ids.contains(&action.id) {
            return Err(WorkspaceError::InvalidPlan);
        }
    }
    Ok(())
}

fn validate_sealed_state(
    sealed_plan: &SealedSetupPlan,
    current_plan: &SetupPlan,
    inspection: &WorkspaceInspection,
    root: &Path,
    seal_key: &PlanSealKey,
) -> Result<()> {
    let current_pre_state = calculate_pre_state_id(current_plan, inspection, root, seal_key)?;
    if *current_plan == sealed_plan.plan
        && constant_time_eq(
            current_pre_state.as_bytes(),
            sealed_plan.pre_state_id.as_bytes(),
        )
    {
        return Ok(());
    }
    Err(WorkspaceError::PlanDrift {
        approved_plan_id: sealed_plan.plan.plan_id.clone(),
        current_plan_id: current_plan.plan_id.clone(),
    })
}

fn mutation_action_id(mutation: &ParticipantFileMutation, actions: &[SetupAction]) -> String {
    actions
        .iter()
        .find(|action| {
            action.kind == SetupActionKind::ProtectEnvFile && action.target == mutation.target
        })
        .map(|action| action.id.clone())
        .unwrap_or_default()
}

fn build_filesystem_mutations(
    plan: &SetupPlan,
    inspection: &WorkspaceInspection,
    root: &Path,
    root_directory: &File,
) -> Result<Vec<FileMutation>> {
    let mut mutations = Vec::new();
    for action in &plan.actions {
        let desired = match action.kind {
            SetupActionKind::InitializeWorkspace => Some(initial_config(root)?),
            SetupActionKind::EnsureEnvIgnoreRules => Some(ensure_ignore_rules(
                secure_read_target(root, root_directory, &action.target)?.unwrap_or_default(),
                root.join(&action.target),
            )?),
            SetupActionKind::GenerateEnvExample => Some(value_free_example(inspection)),
            SetupActionKind::InstallPreCommitCheck if root.join(".git").is_dir() => {
                Some(ensure_pre_commit_hook(
                    secure_read_target(root, root_directory, &action.target)?.unwrap_or_default(),
                ))
            }
            _ => None,
        };
        let Some(content) = desired else {
            continue;
        };
        if secure_read_target(root, root_directory, &action.target)?.as_deref()
            == Some(content.as_slice())
        {
            continue;
        }
        mutations.push(FileMutation {
            target: action.target.clone(),
            content,
            executable: action.kind == SetupActionKind::InstallPreCommitCheck,
            action_id: action.id.clone(),
        });
    }
    Ok(mutations)
}

fn secure_read_target(root: &Path, root_directory: &File, target: &str) -> Result<Option<Vec<u8>>> {
    #[cfg(unix)]
    {
        let mut no_created = Vec::new();
        let Some(parent) = secure_parent(root, root_directory, target, false, &mut no_created)?
        else {
            return Ok(None);
        };
        read_at(&parent, &root.join(target)).map(|value| value.map(|(content, _)| content))
    }
    #[cfg(not(unix))]
    {
        let _ = (root, root_directory, target);
        Err(WorkspaceError::SafeMutationUnsupported)
    }
}

fn initial_config(root: &Path) -> Result<Vec<u8>> {
    let project_id = PhantomConfig::project_id_from_path(root);
    let config = PhantomConfig::new_with_defaults(project_id);
    let content = toml::to_string_pretty(&config).map_err(|error| {
        WorkspaceError::Serialization(serde_json::Error::io(std::io::Error::other(error)))
    })?;
    Ok(content.into_bytes())
}

fn ensure_ignore_rules(existing: Vec<u8>, path: PathBuf) -> Result<Vec<u8>> {
    let mut content = String::from_utf8(existing).map_err(|error| WorkspaceError::Io {
        path,
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
    })?;
    for pattern in ENV_IGNORE_PATTERNS {
        if content.lines().any(|line| line.trim() == *pattern) {
            continue;
        }
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(pattern);
        content.push('\n');
    }
    Ok(content.into_bytes())
}

fn value_free_example(inspection: &WorkspaceInspection) -> Vec<u8> {
    let names = inspection
        .env_files
        .iter()
        .flat_map(|env| env.entry_names.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut content = String::from(
        "# Environment variable names discovered by Phantom.\n# Values are intentionally omitted.\n",
    );
    for name in &names {
        content.push_str(name);
        content.push_str("=\n");
    }
    content.into_bytes()
}

fn ensure_pre_commit_hook(existing: Vec<u8>) -> Vec<u8> {
    if existing
        .windows(HOOK_COMMAND.len())
        .any(|window| window == HOOK_COMMAND.as_bytes())
    {
        return existing;
    }
    let mut content = existing;
    if content.is_empty() {
        content.extend_from_slice(b"#!/bin/sh\n");
    } else if !content.ends_with(b"\n") {
        content.push(b'\n');
    }
    content.extend_from_slice(format!("\n{HOOK_MARKER}\n{HOOK_COMMAND}\n").as_bytes());
    content
}

fn ensure_unique_targets(mutations: &mut [FileMutation]) -> Result<()> {
    mutations.sort_by(|left, right| left.target.cmp(&right.target));
    for pair in mutations.windows(2) {
        if pair[0].target == pair[1].target {
            return Err(WorkspaceError::UnsafeTarget(PathBuf::from(&pair[0].target)));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn c_component(component: &std::ffi::OsStr, path: &Path) -> Result<CString> {
    CString::new(component.as_bytes()).map_err(|_| WorkspaceError::UnsafeTarget(path.to_path_buf()))
}

#[cfg(unix)]
fn open_root_directory(root: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|source| WorkspaceError::Io {
            path: root.to_path_buf(),
            source,
        })
}

#[cfg(unix)]
fn verify_root_identity(root: &Path, directory: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let path_metadata = std::fs::metadata(root).map_err(|source| WorkspaceError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let descriptor_metadata = directory.metadata().map_err(|source| WorkspaceError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if path_metadata.dev() != descriptor_metadata.dev()
        || path_metadata.ino() != descriptor_metadata.ino()
    {
        return Err(WorkspaceError::UnsafeTarget(root.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &CStr, path: &Path) -> Result<File> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(WorkspaceError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: openat returned a new owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn secure_parent(
    root: &Path,
    root_directory: &File,
    target: &str,
    create: bool,
    created: &mut Vec<PathBuf>,
) -> Result<Option<SecureParent>> {
    let relative = Path::new(target);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WorkspaceError::UnsafeTarget(relative.to_path_buf()));
    }
    let mut components = relative.components().peekable();
    let mut directory = root_directory
        .try_clone()
        .map_err(|source| WorkspaceError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    let mut display = root.to_path_buf();
    while let Some(component) = components.next() {
        let Component::Normal(part) = component else {
            return Err(WorkspaceError::UnsafeTarget(relative.to_path_buf()));
        };
        let name = c_component(part, relative)?;
        if components.peek().is_none() {
            return Ok(Some(SecureParent { directory, name }));
        }
        display.push(part);
        match open_directory_at(&directory, &name, &display) {
            Ok(next) => directory = next,
            Err(WorkspaceError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound && create =>
            {
                let created_result =
                    unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) };
                if created_result != 0 {
                    return Err(WorkspaceError::Io {
                        path: display.clone(),
                        source: std::io::Error::last_os_error(),
                    });
                }
                directory.sync_all().map_err(|source| WorkspaceError::Io {
                    path: display.parent().unwrap_or(root).to_path_buf(),
                    source,
                })?;
                created.push(display.clone());
                directory = open_directory_at(&directory, &name, &display)?;
            }
            Err(WorkspaceError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        }
    }
    Err(WorkspaceError::UnsafeTarget(relative.to_path_buf()))
}

#[cfg(unix)]
fn stat_at(parent: &SecureParent) -> std::io::Result<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.directory.as_raw_fd(),
            parent.name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: fstatat initialized stat on success.
        return Ok(Some(unsafe { stat.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn validate_regular_stat(stat: &libc::stat, path: &Path) -> Result<()> {
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG || stat.st_nlink > 1 {
        Err(WorkspaceError::UnsafeTarget(path.to_path_buf()))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn read_at(parent: &SecureParent, path: &Path) -> Result<Option<(Vec<u8>, Permissions)>> {
    let Some(stat) = stat_at(parent).map_err(|source| WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    })?
    else {
        return Ok(None);
    };
    validate_regular_stat(&stat, path)?;
    let descriptor = unsafe {
        libc::openat(
            parent.directory.as_raw_fd(),
            parent.name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(WorkspaceError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: openat returned a new owned descriptor on success.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata().map_err(|source| WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_target_metadata(path, &metadata)?;
    let mut content = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut content).map_err(|source| WorkspaceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some((content, metadata.permissions())))
}

#[cfg(unix)]
fn write_at(
    parent: &SecureParent,
    path: &Path,
    content: &[u8],
    previous_permissions: Option<Permissions>,
    executable: bool,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_name = CString::new(format!(".phantom-tmp-{}-{sequence}", std::process::id()))
        .expect("generated temp name has no NUL");
    let descriptor = unsafe {
        libc::openat(
            parent.directory.as_raw_fd(),
            temp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(WorkspaceError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: openat returned a new owned descriptor on success.
    let mut temp = unsafe { File::from_raw_fd(descriptor) };
    let result = (|| -> Result<()> {
        temp.write_all(content)
            .and_then(|_| temp.sync_all())
            .map_err(|source| WorkspaceError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let mut mode = previous_permissions
            .map(|permissions| permissions.mode())
            .unwrap_or(if executable { 0o755 } else { 0o644 });
        if executable {
            mode |= 0o111;
        }
        if unsafe { libc::fchmod(temp.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(WorkspaceError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
        if let Some(stat) = stat_at(parent).map_err(|source| WorkspaceError::Io {
            path: path.to_path_buf(),
            source,
        })? {
            validate_regular_stat(&stat, path)?;
        }
        if unsafe {
            libc::renameat(
                parent.directory.as_raw_fd(),
                temp_name.as_ptr(),
                parent.directory.as_raw_fd(),
                parent.name.as_ptr(),
            )
        } != 0
        {
            return Err(WorkspaceError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
        parent
            .directory
            .sync_all()
            .map_err(|source| WorkspaceError::Io {
                path: path.parent().unwrap_or(path).to_path_buf(),
                source,
            })?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(parent.directory.as_raw_fd(), temp_name.as_ptr(), 0);
        }
    }
    result
}

#[cfg(unix)]
fn unlink_at(parent: &SecureParent, path: &Path, flags: libc::c_int) -> Result<()> {
    if unsafe { libc::unlinkat(parent.directory.as_raw_fd(), parent.name.as_ptr(), flags) } == 0 {
        parent
            .directory
            .sync_all()
            .map_err(|source| WorkspaceError::Io {
                path: path.parent().unwrap_or(path).to_path_buf(),
                source,
            })?;
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(WorkspaceError::Io {
            path: path.to_path_buf(),
            source: error,
        })
    }
}

fn capture_snapshot(
    root: &Path,
    root_directory: &File,
    mutations: &[FileMutation],
) -> Result<WorkspaceSnapshot> {
    #[cfg(unix)]
    {
        let mut files = Vec::with_capacity(mutations.len());
        for mutation in mutations {
            let path = root.join(&mutation.target);
            let mut no_created = Vec::new();
            let parent = secure_parent(
                root,
                root_directory,
                &mutation.target,
                false,
                &mut no_created,
            )?;
            let before = match parent.as_ref() {
                Some(parent) => match read_at(parent, &path)? {
                    Some((content, permissions)) => FileState::Present {
                        content,
                        permissions,
                    },
                    None => FileState::Missing,
                },
                None => FileState::Missing,
            };
            files.push(FileSnapshot {
                target: mutation.target.clone(),
                path,
                before,
                after: None,
                parent,
            });
        }
        Ok(WorkspaceSnapshot {
            workspace_root: root.to_path_buf(),
            root_directory: root_directory
                .try_clone()
                .map_err(|source| WorkspaceError::Io {
                    path: root.to_path_buf(),
                    source,
                })?,
            files,
            created_directories: Vec::new(),
            finalized: false,
        })
    }

    #[cfg(not(unix))]
    {
        let _ = root_directory;
        let mut files = Vec::with_capacity(mutations.len());
        for mutation in mutations {
            let path = resolve_target(root, &mutation.target)?;
            let before = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    validate_target_metadata(&path, &metadata)?;
                    FileState::Present {
                        content: std::fs::read(&path).map_err(|source| WorkspaceError::Io {
                            path: path.clone(),
                            source,
                        })?,
                        permissions: metadata.permissions(),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => FileState::Missing,
                Err(source) => {
                    return Err(WorkspaceError::Io {
                        path: path.clone(),
                        source,
                    })
                }
            };
            files.push(FileSnapshot {
                target: mutation.target.clone(),
                path,
                before,
                after: None,
            });
        }
        Ok(WorkspaceSnapshot {
            workspace_root: root.to_path_buf(),
            files,
            created_directories: Vec::new(),
            finalized: false,
        })
    }
}

fn apply_mutations(
    root: &Path,
    mutations: &[FileMutation],
    snapshot: &mut WorkspaceSnapshot,
) -> Result<()> {
    #[cfg(unix)]
    {
        for mutation in mutations {
            let file = snapshot
                .files
                .iter_mut()
                .find(|file| file.target == mutation.target)
                .ok_or(WorkspaceError::InvalidPlan)?;
            if file.parent.is_none() {
                file.parent = secure_parent(
                    root,
                    &snapshot.root_directory,
                    &mutation.target,
                    true,
                    &mut snapshot.created_directories,
                )?;
            }
            let parent = file
                .parent
                .as_ref()
                .ok_or_else(|| WorkspaceError::UnsafeTarget(PathBuf::from(&mutation.target)))?;
            let previous_permissions = match &file.before {
                FileState::Present { permissions, .. } => Some(permissions.clone()),
                FileState::Missing => None,
            };
            write_at(
                parent,
                &file.path,
                &mutation.content,
                previous_permissions,
                mutation.executable,
            )?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        for mutation in mutations {
            let path = resolve_target(root, &mutation.target)?;
            create_parent_directories(root, &path, &mut snapshot.created_directories)?;
            let previous_permissions = snapshot
                .files
                .iter()
                .find(|file| file.target == mutation.target)
                .and_then(|file| match &file.before {
                    FileState::Present { permissions, .. } => Some(permissions.clone()),
                    FileState::Missing => None,
                });
            atomic_write(
                &path,
                &mutation.content,
                previous_permissions,
                mutation.executable,
            )?;
        }
        Ok(())
    }
}

fn finalize_snapshot(snapshot: &mut WorkspaceSnapshot) -> Result<()> {
    for file in &mut snapshot.files {
        #[cfg(unix)]
        let content = read_at(
            file.parent.as_ref().ok_or(WorkspaceError::InvalidPlan)?,
            &file.path,
        )?
        .map(|(content, _)| content)
        .ok_or(WorkspaceError::InvalidPlan)?;
        #[cfg(not(unix))]
        let content = std::fs::read(&file.path).map_err(|source| WorkspaceError::Io {
            path: file.path.clone(),
            source,
        })?;
        file.after = Some(content);
    }
    snapshot.finalized = true;
    Ok(())
}

fn restore_snapshot_unchecked(snapshot: &WorkspaceSnapshot) -> Result<()> {
    let mut first_error = None;
    for file in snapshot.files.iter().rev() {
        #[cfg(unix)]
        let restored = {
            let parent = file.parent.as_ref().ok_or(WorkspaceError::InvalidPlan)?;
            match &file.before {
                FileState::Missing => unlink_at(parent, &file.path, 0),
                FileState::Present {
                    content,
                    permissions,
                } => write_at(
                    parent,
                    &file.path,
                    content,
                    Some(permissions.clone()),
                    false,
                ),
            }
        };
        #[cfg(not(unix))]
        let restored = match &file.before {
            FileState::Missing => match std::fs::remove_file(&file.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(WorkspaceError::Io {
                    path: file.path.clone(),
                    source,
                }),
            },
            FileState::Present {
                content,
                permissions,
            } => atomic_write(&file.path, content, Some(permissions.clone()), false),
        };
        if restored.is_err() && first_error.is_none() {
            first_error = restored.err();
        }
    }
    #[cfg(unix)]
    for directory in snapshot.created_directories.iter().rev() {
        let Ok(relative) = directory.strip_prefix(&snapshot.workspace_root) else {
            continue;
        };
        let Some(target) = relative.to_str() else {
            continue;
        };
        let mut unused = Vec::new();
        if let Ok(Some(parent)) = secure_parent(
            &snapshot.workspace_root,
            &snapshot.root_directory,
            target,
            false,
            &mut unused,
        ) {
            let _ = unlink_at(&parent, directory, libc::AT_REMOVEDIR);
        }
    }
    #[cfg(not(unix))]
    for directory in snapshot.created_directories.iter().rev() {
        match std::fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(source) if first_error.is_none() => {
                first_error = Some(WorkspaceError::Io {
                    path: directory.clone(),
                    source,
                });
            }
            Err(_) => {}
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn build_receipt(
    plan: &SetupPlan,
    replayed_plan: bool,
    mutations: &[FileMutation],
    snapshot: &WorkspaceSnapshot,
    participant_completed: &BTreeSet<String>,
    seal_key: &PlanSealKey,
) -> SetupTransactionReceipt {
    let changed_ids = mutations
        .iter()
        .map(|mutation| mutation.action_id.as_str())
        .collect::<BTreeSet<_>>();
    let actions = plan
        .actions
        .iter()
        .map(|action| {
            let state = if participant_completed.contains(&action.id)
                || changed_ids.contains(action.id.as_str())
            {
                ActionOutcomeState::Applied
            } else if matches!(
                action.kind,
                SetupActionKind::ProtectEnvFile | SetupActionKind::ReviewPlaceBinding
            ) || (action.kind == SetupActionKind::InstallPreCommitCheck
                && !Path::new(&plan.workspace_root).join(".git").is_dir())
            {
                ActionOutcomeState::Deferred
            } else {
                ActionOutcomeState::AlreadySatisfied
            };
            ActionOutcome {
                action_id: action.id.clone(),
                kind: action.kind,
                target: action.target.clone(),
                state,
            }
        })
        .collect::<Vec<_>>();
    let file_changes = snapshot
        .files
        .iter()
        .map(|file| FileChangeReceipt {
            target: file.target.clone(),
            before_state_id: match &file.before {
                FileState::Missing => None,
                FileState::Present { content, .. } => {
                    Some(keyed_file_state_id(seal_key, &file.target, content))
                }
            },
            after_state_id: keyed_file_state_id(
                seal_key,
                &file.target,
                file.after
                    .as_deref()
                    .expect("completed transaction snapshots are finalized"),
            ),
        })
        .collect::<Vec<_>>();
    let fully_applied = actions
        .iter()
        .all(|outcome| outcome.state != ActionOutcomeState::Deferred);
    SetupTransactionReceipt {
        schema_version: TRANSACTION_SCHEMA_VERSION,
        plan_id: plan.plan_id.clone(),
        workspace_fingerprint: plan.workspace_fingerprint.clone(),
        replayed_plan,
        actions,
        file_changes,
        fully_applied,
    }
}

fn calculate_pre_state_id(
    plan: &SetupPlan,
    inspection: &WorkspaceInspection,
    root: &Path,
    seal_key: &PlanSealKey,
) -> Result<String> {
    if !plan_has_valid_id(plan)? {
        return Err(WorkspaceError::InvalidPlan);
    }

    let mut targets = plan
        .actions
        .iter()
        .filter(|action| action.kind != SetupActionKind::ReviewPlaceBinding)
        .map(|action| action.target.clone())
        .collect::<BTreeSet<_>>();
    // An existing config selects the vault namespace used by the transaction
    // participant even though InitializeWorkspace is no longer a planned
    // action. Bind its exact bytes so an approved request cannot be redirected
    // to a different vault between proposal and claim.
    targets.insert(".phantom.toml".to_string());
    targets.extend(inspection.env_files.iter().map(|env| env.path.clone()));

    let mut inner = hmac_inner(seal_key, b"phantom.workspace.pre-state.v1");
    let plan_basis = serde_json::to_vec(plan)?;
    hmac_field(&mut inner, b"plan", &plan_basis);
    for target in targets {
        let path = resolve_target(root, &target)?;
        hmac_field(&mut inner, b"path", target.as_bytes());
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_target_metadata(&path, &metadata)?;
                let content = std::fs::read(&path).map_err(|source| WorkspaceError::Io {
                    path: path.clone(),
                    source,
                })?;
                hmac_field(&mut inner, b"present", &content);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                hmac_field(&mut inner, b"absent", &[]);
            }
            Err(source) => {
                return Err(WorkspaceError::Io {
                    path: path.clone(),
                    source,
                })
            }
        }
    }
    Ok(hex::encode(hmac_finish(seal_key, inner)))
}

fn keyed_file_state_id(seal_key: &PlanSealKey, target: &str, content: &[u8]) -> String {
    let mut inner = hmac_inner(seal_key, b"phantom.workspace.file-state.v1");
    hmac_field(&mut inner, b"path", target.as_bytes());
    hmac_field(&mut inner, b"content", content);
    hex::encode(hmac_finish(seal_key, inner))
}

fn hmac_inner(seal_key: &PlanSealKey, domain: &[u8]) -> Sha256 {
    let mut pad = [0x36_u8; 64];
    for (index, byte) in seal_key.0.iter().enumerate() {
        pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(pad);
    hmac_field(&mut inner, b"domain", domain);
    pad.zeroize();
    inner
}

fn hmac_finish(seal_key: &PlanSealKey, inner: Sha256) -> [u8; 32] {
    let mut inner_digest = inner.finalize();
    let mut pad = [0x5c_u8; 64];
    for (index, byte) in seal_key.0.iter().enumerate() {
        pad[index] ^= byte;
    }
    let mut outer = Sha256::new();
    outer.update(pad);
    outer.update(inner_digest);
    let result: [u8; 32] = outer.finalize().into();
    pad.zeroize();
    inner_digest.as_mut_slice().zeroize();
    result
}

fn hmac_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn resolve_target(root: &Path, target: &str) -> Result<PathBuf> {
    let relative = Path::new(target);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(WorkspaceError::UnsafeTarget(relative.to_path_buf()));
    }
    let path = root.join(relative);
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(part) = component {
            current.push(part);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(WorkspaceError::UnsafeTarget(path));
                }
                Ok(metadata) => {
                    if metadata.is_dir() && std::fs::symlink_metadata(current.join(".git")).is_ok()
                    {
                        return Err(WorkspaceError::UnsafeTarget(path));
                    }
                    if current == path && metadata.is_file() {
                        validate_target_metadata(&current, &metadata)?;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(source) => {
                    return Err(WorkspaceError::Io {
                        path: current,
                        source,
                    })
                }
            }
        }
    }
    Ok(path)
}

fn validate_target_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WorkspaceError::UnsafeTarget(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            return Err(WorkspaceError::UnsafeTarget(path.to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_parent_directories(root: &Path, path: &Path, created: &mut Vec<PathBuf>) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| WorkspaceError::UnsafeTarget(path.to_path_buf()))?;
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| WorkspaceError::UnsafeTarget(path.to_path_buf()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(WorkspaceError::UnsafeTarget(path.to_path_buf()));
        };
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(WorkspaceError::UnsafeTarget(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|source| WorkspaceError::Io {
                    path: current.clone(),
                    source,
                })?;
                created.push(current.clone());
            }
            Err(source) => {
                return Err(WorkspaceError::Io {
                    path: current,
                    source,
                })
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn atomic_write(
    path: &Path,
    content: &[u8],
    previous_permissions: Option<Permissions>,
    executable: bool,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| WorkspaceError::UnsafeTarget(path.to_path_buf()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| WorkspaceError::UnsafeTarget(path.to_path_buf()))?;
    let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = parent.join(format!(
        ".{file_name}.phantom-tmp-{}-{sequence}",
        std::process::id()
    ));
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|source| WorkspaceError::Io {
                path: temp_path.clone(),
                source,
            })?;
        file.write_all(content)
            .and_then(|_| file.sync_all())
            .map_err(|source| WorkspaceError::Io {
                path: temp_path.clone(),
                source,
            })?;
        if let Some(permissions) = previous_permissions {
            let permissions = ensure_executable_permission(permissions, executable);
            std::fs::set_permissions(&temp_path, permissions).map_err(|source| {
                WorkspaceError::Io {
                    path: temp_path.clone(),
                    source,
                }
            })?;
        } else {
            set_new_file_permissions(&temp_path, executable)?;
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => validate_target_metadata(path, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(WorkspaceError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        }
        std::fs::rename(&temp_path, path).map_err(|source| WorkspaceError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| WorkspaceError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

#[cfg(not(unix))]
fn ensure_executable_permission(permissions: Permissions, _executable: bool) -> Permissions {
    permissions
}

#[cfg(not(unix))]
fn set_new_file_permissions(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(WorkspaceError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn acquire_workspace_lock(root: &Path) -> Result<WorkspaceLock> {
    let process = PROCESS_TRANSACTION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let lock_directory = std::env::temp_dir().join("phantom-workspace-locks");
    std::fs::create_dir_all(&lock_directory).map_err(|source| WorkspaceError::Io {
        path: lock_directory.clone(),
        source,
    })?;
    let lock_path = lock_directory.join(format!(
        "{}.lock",
        digest_hex(root.to_string_lossy().as_bytes())
    ));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| WorkspaceError::Io {
            path: lock_path.clone(),
            source,
        })?;
    fs2::FileExt::lock_exclusive(&lock).map_err(|source| WorkspaceError::Io {
        path: lock_path,
        source,
    })?;
    Ok(WorkspaceLock {
        _process: process,
        _file: lock,
    })
}

#[cfg(all(test, unix))]
mod descriptor_tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    struct ParentSwapParticipant {
        root: PathBuf,
        outside: PathBuf,
        swapped: Cell<bool>,
        fail_commit: bool,
    }

    impl SetupTransactionParticipant for ParentSwapParticipant {
        fn prepare(
            &mut self,
            _plan: &SetupPlan,
            external_actions: &[SetupAction],
        ) -> std::result::Result<ParticipantPreparation, ParticipantError> {
            let action = external_actions
                .iter()
                .find(|action| action.target == "apps/web/.env")
                .ok_or(ParticipantError::new("missing_nested_env_action"))?;
            Ok(ParticipantPreparation::new(
                [action.id.clone()],
                vec![ParticipantFileMutation::replace(
                    action.target.clone(),
                    b"API_KEY=phm_descriptor_safe\n".to_vec(),
                )],
            ))
        }

        fn commit(&mut self) -> std::result::Result<(), ParticipantError> {
            if self.fail_commit {
                Err(ParticipantError::new("injected_commit_failure"))
            } else {
                Ok(())
            }
        }

        fn rollback(&mut self) -> std::result::Result<(), ParticipantError> {
            Ok(())
        }

        fn recovery_payload(&self) -> std::result::Result<Vec<u8>, ParticipantError> {
            if !self.swapped.replace(true) {
                std::fs::rename(self.root.join("apps/web"), self.root.join("apps/web-moved"))
                    .map_err(|_| ParticipantError::new("parent_swap_rename_failed"))?;
                symlink(&self.outside, self.root.join("apps/web"))
                    .map_err(|_| ParticipantError::new("parent_swap_symlink_failed"))?;
            }
            Ok(Vec::new())
        }
    }

    fn fixture(
        fail_commit: bool,
    ) -> (
        TempDir,
        TempDir,
        TempDir,
        PlanSealKey,
        SealedSetupPlan,
        ParentSwapParticipant,
        DurableJournalConfig,
    ) {
        let workspace = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let journals = TempDir::new().unwrap();
        std::fs::create_dir_all(workspace.path().join("apps/web")).unwrap();
        std::fs::write(
            workspace.path().join("apps/web/.env"),
            b"API_KEY=sk-original-descriptor-value\n",
        )
        .unwrap();
        std::fs::write(outside.path().join(".env"), b"OUTSIDE=unchanged\n").unwrap();
        let key = PlanSealKey::from_bytes([0x91; 32]);
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let participant = ParentSwapParticipant {
            root: workspace.path().to_path_buf(),
            outside: outside.path().to_path_buf(),
            swapped: Cell::new(false),
            fail_commit,
        };
        let journal = DurableJournalConfig::new(
            "d".repeat(64),
            journals.path().join("swap.journal"),
            [0x92; 32],
        );
        (
            workspace,
            outside,
            journals,
            key,
            sealed,
            participant,
            journal,
        )
    }

    #[test]
    fn apply_uses_validated_parent_descriptor_after_path_swap() {
        let (workspace, outside, _journals, key, sealed, mut participant, journal) = fixture(false);
        apply_setup_plan_durable(&sealed, &key, &mut participant, &journal).unwrap();

        assert_eq!(
            std::fs::read(workspace.path().join("apps/web-moved/.env")).unwrap(),
            b"API_KEY=phm_descriptor_safe\n"
        );
        assert_eq!(
            std::fs::read(outside.path().join(".env")).unwrap(),
            b"OUTSIDE=unchanged\n"
        );
    }

    #[test]
    fn recovery_fails_closed_when_parent_path_was_replaced() {
        let (workspace, outside, _journals, key, sealed, mut participant, journal) = fixture(true);
        assert!(apply_setup_plan_durable(&sealed, &key, &mut participant, &journal).is_err());
        let mut recovery = NoopSetupParticipant;
        assert!(matches!(
            recover_setup_plan_journal(
                workspace.path(),
                &sealed.plan.plan_id,
                &sealed.pre_state_id,
                &mut recovery,
                &journal,
            ),
            Err(WorkspaceError::Io { .. }) | Err(WorkspaceError::UnsafeTarget(_))
        ));
        assert_eq!(
            std::fs::read(outside.path().join(".env")).unwrap(),
            b"OUTSIDE=unchanged\n"
        );
        assert_eq!(
            std::fs::read(workspace.path().join("apps/web-moved/.env")).unwrap(),
            b"API_KEY=sk-original-descriptor-value\n"
        );
    }
}
