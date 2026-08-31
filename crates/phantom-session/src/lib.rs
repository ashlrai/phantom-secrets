#![cfg_attr(not(test), allow(dead_code))]

//! Inactive, value-free session coordination journal foundation.
//!
//! This crate does not execute, authorize, lease, proxy, roll back, or sign.
//! Its only production factory denies construction. Local HMAC integrity is
//! not external trust and does not defend against a compromised same-user key.
//! Durable execution descriptors and host rollback anchors do not exist yet;
//! no runtime consumer is wired to this inactive journal.

use fs2::FileExt;
use hmac::{Hmac, Mac};
use phantom_authority::{canonical_json_v1, SessionId, Sha256Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const VERSION: u8 = 3;
const MAX_STATE: u64 = 256 * 1024;
const MAX_COMPLETED_TRANSITIONS: usize = 16;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Created,
    AuthorityEvaluated,
    AuthorityDenied,
    LeaseReserved,
    PermitActive,
    WorkerObserved,
    PermitTerminal,
    RollbackResolved,
    EvidenceFinalized,
    ReceiptPersisted,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemStep {
    RecordAuthority,
    ReserveLease,
    ActivatePermit,
    RecordWorker,
    TerminalizePermit,
    ResolveRollback,
    FinalizeEvidence,
    PersistReceipt,
    MarkComplete,
}

/// A closed, value-free pre-effect description of the subsystem operation.
///
/// Every variant carries exactly one opaque digest identifying the intended
/// operation or subject. It does not claim that an effect occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StepIntent {
    AuthorityDecision { decision_digest: Sha256Digest },
    LeaseReservation { reservation_digest: Sha256Digest },
    PermitActivation { activation_digest: Sha256Digest },
    WorkerProxyObservation { observation_digest: Sha256Digest },
    PermitTerminalState { terminal_digest: Sha256Digest },
    RollbackDisposition { disposition_digest: Sha256Digest },
    FinalizedEvidence { evidence_digest: Sha256Digest },
    PersistedReceipt { receipt_digest: Sha256Digest },
    Completion { completion_digest: Sha256Digest },
}

impl StepIntent {
    pub fn step(&self) -> SubsystemStep {
        match self {
            Self::AuthorityDecision { .. } => SubsystemStep::RecordAuthority,
            Self::LeaseReservation { .. } => SubsystemStep::ReserveLease,
            Self::PermitActivation { .. } => SubsystemStep::ActivatePermit,
            Self::WorkerProxyObservation { .. } => SubsystemStep::RecordWorker,
            Self::PermitTerminalState { .. } => SubsystemStep::TerminalizePermit,
            Self::RollbackDisposition { .. } => SubsystemStep::ResolveRollback,
            Self::FinalizedEvidence { .. } => SubsystemStep::FinalizeEvidence,
            Self::PersistedReceipt { .. } => SubsystemStep::PersistReceipt,
            Self::Completion { .. } => SubsystemStep::MarkComplete,
        }
    }
}

/// A closed, value-free observation recorded only after the intended subsystem
/// effect returns. Each variant carries exactly one observed-result digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StepCompletion {
    AuthorityDecision { result_digest: Sha256Digest },
    LeaseReservation { result_digest: Sha256Digest },
    PermitActivation { result_digest: Sha256Digest },
    WorkerProxyObservation { result_digest: Sha256Digest },
    PermitTerminalState { result_digest: Sha256Digest },
    RollbackDisposition { result_digest: Sha256Digest },
    FinalizedEvidence { result_digest: Sha256Digest },
    PersistedReceipt { result_digest: Sha256Digest },
    Completion { result_digest: Sha256Digest },
}

impl StepCompletion {
    pub fn step(&self) -> SubsystemStep {
        match self {
            Self::AuthorityDecision { .. } => SubsystemStep::RecordAuthority,
            Self::LeaseReservation { .. } => SubsystemStep::ReserveLease,
            Self::PermitActivation { .. } => SubsystemStep::ActivatePermit,
            Self::WorkerProxyObservation { .. } => SubsystemStep::RecordWorker,
            Self::PermitTerminalState { .. } => SubsystemStep::TerminalizePermit,
            Self::RollbackDisposition { .. } => SubsystemStep::ResolveRollback,
            Self::FinalizedEvidence { .. } => SubsystemStep::FinalizeEvidence,
            Self::PersistedReceipt { .. } => SubsystemStep::PersistReceipt,
            Self::Completion { .. } => SubsystemStep::MarkComplete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub from: SessionPhase,
    pub to: SessionPhase,
    pub intent: StepIntent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Clean {
        phase: SessionPhase,
        generation: u64,
    },
    Pending {
        transition: Transition,
        transition_id: Sha256Digest,
        generation: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionResult {
    New {
        transition_id: Sha256Digest,
        generation: u64,
    },
    Existing {
        transition_id: Sha256Digest,
        generation: u64,
    },
}

#[derive(Debug, Default)]
pub struct DenyAllSessionFactory;

impl DenyAllSessionFactory {
    pub fn open(&self) -> Result<(), SessionError> {
        Err(SessionError::Unavailable)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    transition_id: Sha256Digest,
    transition: Transition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    transition_id: Sha256Digest,
    completion: StepCompletion,
    completion_id: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenesisBinding {
    session_id: SessionId,
    workspace_identity_digest: Sha256Digest,
    action_intent_root_digest: Sha256Digest,
    store_id: Sha256Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateBody {
    version: u8,
    genesis: GenesisBinding,
    generation: u64,
    phase: SessionPhase,
    pending: Option<Pending>,
    completed: Vec<Completed>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    body: StateBody,
    mac: Sha256Digest,
}

struct Journal {
    dir: PathBuf,
    state: PathBuf,
    lock: PathBuf,
    genesis: GenesisBinding,
    key: Zeroizing<[u8; 32]>,
}

impl Journal {
    #[cfg(test)]
    fn bootstrap(
        root: &Path,
        workspace: &Path,
        session_id: SessionId,
        workspace_identity_digest: Sha256Digest,
        action_intent_root_digest: Sha256Digest,
        key: [u8; 32],
    ) -> Result<Self, SessionError> {
        let mut store_id_bytes = [0_u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut store_id_bytes);
        if store_id_bytes.iter().all(|byte| *byte == 0) {
            return Err(SessionError::InvalidStoreId);
        }
        let store_id = hex::encode(store_id_bytes)
            .parse()
            .map_err(|_| SessionError::Tampered)?;
        let genesis = GenesisBinding {
            session_id,
            workspace_identity_digest,
            action_intent_root_digest,
            store_id,
        };
        let journal = Self::prepare(root, workspace, genesis, key)?;
        let lock = journal.lock()?;
        match std::fs::symlink_metadata(&journal.state) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(SessionError::UnsafeStorage);
            }
            Ok(_) => return Err(SessionError::StateAlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        journal.write(&StateBody {
            version: VERSION,
            genesis: journal.genesis.clone(),
            generation: 0,
            phase: SessionPhase::Created,
            pending: None,
            completed: Vec::new(),
        })?;
        journal.load()?;
        drop(lock);
        Ok(journal)
    }

    #[cfg(test)]
    fn open_existing(
        root: &Path,
        workspace: &Path,
        genesis: GenesisBinding,
        key: [u8; 32],
    ) -> Result<Self, SessionError> {
        let journal = Self::prepare(root, workspace, genesis, key)?;
        let lock = journal.lock()?;
        match std::fs::symlink_metadata(&journal.state) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(SessionError::UnsafeStorage);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(SessionError::MissingState);
            }
            Err(error) => return Err(error.into()),
        }
        journal.load()?;
        drop(lock);
        Ok(journal)
    }

    #[cfg(test)]
    fn genesis(&self) -> GenesisBinding {
        self.genesis.clone()
    }

    fn prepare(
        root: &Path,
        workspace: &Path,
        genesis: GenesisBinding,
        key: [u8; 32],
    ) -> Result<Self, SessionError> {
        if key.iter().all(|b| *b == 0) {
            return Err(SessionError::InvalidKey);
        }
        ensure_real_dir(root)?;
        let root = root
            .canonicalize()
            .map_err(|_| SessionError::UnsafeStorage)?;
        let workspace = workspace
            .canonicalize()
            .map_err(|_| SessionError::UnsafeStorage)?;
        if root.starts_with(&workspace) || workspace.starts_with(&root) {
            return Err(SessionError::StorageOverlap);
        }
        let dir = root.join("sessions");
        ensure_private_dir(&dir)?;
        Ok(Self {
            state: dir.join(format!("{}.json", genesis.session_id.as_str())),
            lock: dir.join(format!("{}.lock", genesis.session_id.as_str())),
            dir,
            genesis,
            key: Zeroizing::new(key),
        })
    }

    fn intend(
        &self,
        expected: u64,
        transition: Transition,
    ) -> Result<TransitionResult, SessionError> {
        let transition_id = transition_digest(&self.genesis, &transition)?;
        let lock = self.lock()?;
        let mut s = self.load()?;
        if let Some(p) = &s.pending {
            if p.transition_id == transition_id && p.transition == transition {
                let r = TransitionResult::Existing {
                    transition_id,
                    generation: s.generation,
                };
                drop(lock);
                return Ok(r);
            }
            return Err(SessionError::Conflict);
        }
        if s.completed
            .iter()
            .any(|completed| completed.transition_id == transition_id)
        {
            return Ok(TransitionResult::Existing {
                transition_id,
                generation: s.generation,
            });
        }
        if s.generation != expected {
            return Err(SessionError::GenerationMismatch);
        }
        validate(&transition, s.phase)?;
        s.pending = Some(Pending {
            transition_id: transition_id.clone(),
            transition,
        });
        s.generation = s
            .generation
            .checked_add(1)
            .ok_or(SessionError::GenerationExhausted)?;
        self.write(&s)?;
        drop(lock);
        Ok(TransitionResult::New {
            transition_id,
            generation: s.generation,
        })
    }

    fn complete(
        &self,
        expected: u64,
        transition_id: &Sha256Digest,
        completion: StepCompletion,
    ) -> Result<TransitionResult, SessionError> {
        let lock = self.lock()?;
        let mut s = self.load()?;
        if let Some(existing) = s
            .completed
            .iter()
            .find(|completed| &completed.transition_id == transition_id)
        {
            if existing.completion == completion {
                return Ok(TransitionResult::Existing {
                    transition_id: transition_id.clone(),
                    generation: s.generation,
                });
            }
            return Err(SessionError::Conflict);
        }
        if s.generation != expected {
            return Err(SessionError::GenerationMismatch);
        }
        let p = s.pending.take().ok_or(SessionError::NoPending)?;
        if &p.transition_id != transition_id {
            return Err(SessionError::Conflict);
        }
        if p.transition.intent.step() != completion.step() {
            return Err(SessionError::CompletionMismatch);
        }
        if s.completed.len() >= MAX_COMPLETED_TRANSITIONS {
            return Err(SessionError::TransitionLimit);
        }
        let completion_id = completion_digest(&self.genesis, transition_id, &completion)?;
        s.phase = p.transition.to;
        s.completed.push(Completed {
            transition_id: p.transition_id.clone(),
            completion,
            completion_id,
        });
        s.generation = s
            .generation
            .checked_add(1)
            .ok_or(SessionError::GenerationExhausted)?;
        self.write(&s)?;
        drop(lock);
        Ok(TransitionResult::New {
            transition_id: p.transition_id,
            generation: s.generation,
        })
    }

    fn recover(&self) -> Result<RecoveryOutcome, SessionError> {
        let lock = self.lock()?;
        let s = self.load()?;
        let r = match s.pending {
            Some(p) => RecoveryOutcome::Pending {
                transition: p.transition,
                transition_id: p.transition_id,
                generation: s.generation,
            },
            None => RecoveryOutcome::Clean {
                phase: s.phase,
                generation: s.generation,
            },
        };
        drop(lock);
        Ok(r)
    }
    fn lock(&self) -> Result<File, SessionError> {
        let f = open_file(&self.lock, true, true)?;
        f.lock_exclusive()?;
        Ok(f)
    }
    fn load(&self) -> Result<StateBody, SessionError> {
        let f = open_file(&self.state, true, false)?;
        if f.metadata()?.len() > MAX_STATE {
            return Err(SessionError::Oversized);
        }
        let mut b = Vec::new();
        f.take(MAX_STATE + 1).read_to_end(&mut b)?;
        if b.len() as u64 > MAX_STATE {
            return Err(SessionError::Oversized);
        }
        let sf: StateFile = serde_json::from_slice(&b).map_err(|error| {
            if error.is_eof() {
                SessionError::Truncated
            } else {
                SessionError::Tampered
            }
        })?;
        if canonical_json_v1(&sf)? != b {
            return Err(SessionError::NonCanonical);
        };
        let expected = mac(&self.key, &sf.body)?;
        if expected != sf.mac {
            return Err(SessionError::Tampered);
        };
        if sf.body.version != VERSION || sf.body.genesis != self.genesis {
            return Err(SessionError::GenesisMismatch);
        }
        if sf.body.completed.len() > MAX_COMPLETED_TRANSITIONS {
            return Err(SessionError::Oversized);
        }
        validate_state_bindings(&sf.body)?;
        Ok(sf.body)
    }
    fn write(&self, body: &StateBody) -> Result<(), SessionError> {
        let sf = StateFile {
            body: StateBody {
                version: body.version,
                genesis: body.genesis.clone(),
                generation: body.generation,
                phase: body.phase,
                pending: body.pending.as_ref().map(|p| Pending {
                    transition_id: p.transition_id.clone(),
                    transition: p.transition.clone(),
                }),
                completed: body.completed.clone(),
            },
            mac: mac(&self.key, body)?,
        };
        let b = canonical_json_v1(&sf)?;
        if b.len() as u64 > MAX_STATE {
            return Err(SessionError::Oversized);
        }
        atomic_write(&self.dir, &self.state, &b)
    }
}

fn validate(t: &Transition, current: SessionPhase) -> Result<(), SessionError> {
    if t.from != current {
        return Err(SessionError::IllegalTransition);
    };
    let ok = matches!(
        (t.from, t.to, &t.intent),
        (
            SessionPhase::Created,
            SessionPhase::AuthorityEvaluated,
            StepIntent::AuthorityDecision { .. }
        ) | (
            SessionPhase::Created,
            SessionPhase::AuthorityDenied,
            StepIntent::AuthorityDecision { .. }
        ) | (
            SessionPhase::AuthorityEvaluated,
            SessionPhase::LeaseReserved,
            StepIntent::LeaseReservation { .. }
        ) | (
            SessionPhase::LeaseReserved,
            SessionPhase::PermitActive,
            StepIntent::PermitActivation { .. }
        ) | (
            SessionPhase::PermitActive,
            SessionPhase::WorkerObserved,
            StepIntent::WorkerProxyObservation { .. }
        ) | (
            SessionPhase::WorkerObserved,
            SessionPhase::PermitTerminal,
            StepIntent::PermitTerminalState { .. }
        ) | (
            SessionPhase::PermitTerminal,
            SessionPhase::RollbackResolved,
            StepIntent::RollbackDisposition { .. }
        ) | (
            SessionPhase::AuthorityDenied,
            SessionPhase::EvidenceFinalized,
            StepIntent::FinalizedEvidence { .. }
        ) | (
            SessionPhase::RollbackResolved,
            SessionPhase::EvidenceFinalized,
            StepIntent::FinalizedEvidence { .. }
        ) | (
            SessionPhase::EvidenceFinalized,
            SessionPhase::ReceiptPersisted,
            StepIntent::PersistedReceipt { .. }
        ) | (
            SessionPhase::ReceiptPersisted,
            SessionPhase::Complete,
            StepIntent::Completion { .. }
        )
    );
    if ok {
        Ok(())
    } else {
        Err(SessionError::IllegalTransition)
    }
}
fn mac(key: &[u8; 32], body: &StateBody) -> Result<Sha256Digest, SessionError> {
    let mut m = HmacSha256::new_from_slice(key).map_err(|_| SessionError::InvalidKey)?;
    m.update(b"phantom.session.state.v3\0");
    m.update(&canonical_json_v1(body)?);
    hex::encode(m.finalize().into_bytes())
        .parse()
        .map_err(|_| SessionError::Tampered)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionIdentity<'a> {
    genesis: &'a GenesisBinding,
    transition: &'a Transition,
}

fn transition_digest(
    genesis: &GenesisBinding,
    transition: &Transition,
) -> Result<Sha256Digest, SessionError> {
    let mut hasher = Sha256::new();
    hasher.update(b"phantom.session.transition.v3\0");
    hasher.update(canonical_json_v1(&TransitionIdentity {
        genesis,
        transition,
    })?);
    hex::encode(hasher.finalize())
        .parse()
        .map_err(|_| SessionError::Tampered)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionIdentity<'a> {
    genesis: &'a GenesisBinding,
    transition_id: &'a Sha256Digest,
    completion: &'a StepCompletion,
}

fn completion_digest(
    genesis: &GenesisBinding,
    transition_id: &Sha256Digest,
    completion: &StepCompletion,
) -> Result<Sha256Digest, SessionError> {
    let mut hasher = Sha256::new();
    hasher.update(b"phantom.session.completion.v1\0");
    hasher.update(canonical_json_v1(&CompletionIdentity {
        genesis,
        transition_id,
        completion,
    })?);
    hex::encode(hasher.finalize())
        .parse()
        .map_err(|_| SessionError::Tampered)
}

fn validate_state_bindings(body: &StateBody) -> Result<(), SessionError> {
    if let Some(pending) = &body.pending {
        if transition_digest(&body.genesis, &pending.transition)? != pending.transition_id
            || pending.transition.from != body.phase
        {
            return Err(SessionError::Tampered);
        }
        validate(&pending.transition, body.phase)?;
    }
    for completed in &body.completed {
        if completion_digest(
            &body.genesis,
            &completed.transition_id,
            &completed.completion,
        )? != completed.completion_id
        {
            return Err(SessionError::Tampered);
        }
    }
    Ok(())
}
fn ensure_real_dir(p: &Path) -> Result<(), SessionError> {
    let m = std::fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        Err(SessionError::UnsafeStorage)
    } else {
        Ok(())
    }
}
fn ensure_private_dir(p: &Path) -> Result<(), SessionError> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        Ok(_) => return Err(SessionError::UnsafeStorage),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(p)?,
        Err(e) => return Err(e.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn open_file(p: &Path, read: bool, append: bool) -> Result<File, SessionError> {
    if let Ok(m) = std::fs::symlink_metadata(p) {
        if m.file_type().is_symlink() || !m.is_file() {
            return Err(SessionError::UnsafeStorage);
        }
    }
    let mut o = OpenOptions::new();
    o.read(read).write(append).append(append).create(append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = o.open(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}
fn atomic_write(dir: &Path, path: &Path, b: &[u8]) -> Result<(), SessionError> {
    let tmp = dir.join(format!(".session-{:016x}.tmp", rand::random::<u64>()));
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = (|| {
        let mut f = o.open(&tmp)?;
        f.write_all(b)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session execution is unavailable")]
    Unavailable,
    #[error("unsafe session storage")]
    UnsafeStorage,
    #[error("session storage overlaps workspace")]
    StorageOverlap,
    #[error("invalid session key")]
    InvalidKey,
    #[error("invalid session store id")]
    InvalidStoreId,
    #[error("session state tampered")]
    Tampered,
    #[error("session state truncated")]
    Truncated,
    #[error("session state non-canonical")]
    NonCanonical,
    #[error("session state oversized")]
    Oversized,
    #[error("session state is missing")]
    MissingState,
    #[error("session state already exists")]
    StateAlreadyExists,
    #[error("session genesis binding does not match")]
    GenesisMismatch,
    #[error("session generation mismatch")]
    GenerationMismatch,
    #[error("session generation exhausted")]
    GenerationExhausted,
    #[error("session transition limit reached")]
    TransitionLimit,
    #[error("session transition conflict")]
    Conflict,
    #[error("session completion does not match the pending subsystem step")]
    CompletionMismatch,
    #[error("no pending transition")]
    NoPending,
    #[error("illegal session transition")]
    IllegalTransition,
    #[error(transparent)]
    Canonical(#[from] phantom_authority::CanonicalJsonError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::TempDir;

    const KEY: [u8; 32] = [0x5a; 32];

    struct Fixture {
        _temp: TempDir,
        root: PathBuf,
        workspace: PathBuf,
        session_id: SessionId,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("private-state");
            let workspace = temp.path().join("workspace");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(&workspace).unwrap();
            Self {
                _temp: temp,
                root,
                workspace,
                session_id: format!("ses_{}", "12".repeat(16)).parse().unwrap(),
            }
        }

        fn bootstrap(&self) -> Result<Journal, SessionError> {
            self.bootstrap_for(self.session_id.clone())
        }

        fn bootstrap_for(&self, session_id: SessionId) -> Result<Journal, SessionError> {
            Journal::bootstrap(
                &self.root,
                &self.workspace,
                session_id,
                digest(0x70),
                digest(0x71),
                KEY,
            )
        }

        fn open_existing(&self, genesis: GenesisBinding) -> Result<Journal, SessionError> {
            Journal::open_existing(&self.root, &self.workspace, genesis, KEY)
        }

        fn state_path(&self) -> PathBuf {
            self.root
                .join("sessions")
                .join(format!("{}.json", self.session_id.as_str()))
        }

        fn lock_path(&self) -> PathBuf {
            self.root
                .join("sessions")
                .join(format!("{}.lock", self.session_id.as_str()))
        }
    }

    fn authority_allowed() -> Transition {
        Transition {
            from: SessionPhase::Created,
            to: SessionPhase::AuthorityEvaluated,
            intent: StepIntent::AuthorityDecision {
                decision_digest: digest(1),
            },
        }
    }

    fn authority_denied() -> Transition {
        Transition {
            from: SessionPhase::Created,
            to: SessionPhase::AuthorityDenied,
            intent: StepIntent::AuthorityDecision {
                decision_digest: digest(2),
            },
        }
    }

    fn authority_completion(byte: u8) -> StepCompletion {
        StepCompletion::AuthorityDecision {
            result_digest: digest(byte),
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        format!("{byte:02x}").repeat(32).parse().unwrap()
    }

    fn result_parts(result: TransitionResult) -> (bool, Sha256Digest, u64) {
        match result {
            TransitionResult::New {
                transition_id,
                generation,
            } => (true, transition_id, generation),
            TransitionResult::Existing {
                transition_id,
                generation,
            } => (false, transition_id, generation),
        }
    }

    #[test]
    fn production_factory_is_unconditionally_deny_all() {
        assert!(matches!(
            DenyAllSessionFactory.open(),
            Err(SessionError::Unavailable)
        ));
    }

    #[test]
    fn crash_boundary_is_explicit_and_exact_retry_is_idempotent() {
        let fixture = Fixture::new();
        let journal = fixture.bootstrap().unwrap();
        let transition = authority_allowed();

        let (is_new, transition_id, generation) =
            result_parts(journal.intend(0, transition.clone()).unwrap());
        assert!(is_new);
        assert_eq!(generation, 1);
        assert_eq!(
            journal.recover().unwrap(),
            RecoveryOutcome::Pending {
                transition: transition.clone(),
                transition_id: transition_id.clone(),
                generation: 1,
            }
        );

        let (is_new, retry_id, retry_generation) =
            result_parts(journal.intend(0, transition).unwrap());
        assert!(!is_new);
        assert_eq!(retry_id, transition_id);
        assert_eq!(retry_generation, 1);
        assert!(matches!(
            journal.recover().unwrap(),
            RecoveryOutcome::Pending { generation: 1, .. }
        ));

        let completion = authority_completion(0x80);
        let (is_new, completed_id, generation) = result_parts(
            journal
                .complete(1, &transition_id, completion.clone())
                .unwrap(),
        );
        assert!(is_new);
        assert_eq!(completed_id, transition_id);
        assert_eq!(generation, 2);
        assert_eq!(
            journal.recover().unwrap(),
            RecoveryOutcome::Clean {
                phase: SessionPhase::AuthorityEvaluated,
                generation: 2,
            }
        );

        let (is_new, _, generation) = result_parts(
            journal
                .complete(1, &transition_id, completion.clone())
                .unwrap(),
        );
        assert!(!is_new);
        assert_eq!(generation, 2);
        assert!(matches!(
            journal.complete(1, &transition_id, authority_completion(0x81)),
            Err(SessionError::Conflict)
        ));
    }

    #[test]
    fn restart_preserves_pending_step_without_inferring_success() {
        let fixture = Fixture::new();
        let (transition_id, genesis) = {
            let journal = fixture.bootstrap().unwrap();
            let (_, transition_id, _) =
                result_parts(journal.intend(0, authority_denied()).unwrap());
            (transition_id, journal.genesis())
        };

        let restarted = fixture.open_existing(genesis).unwrap();
        assert_eq!(
            restarted.recover().unwrap(),
            RecoveryOutcome::Pending {
                transition: authority_denied(),
                transition_id,
                generation: 1,
            }
        );
    }

    #[test]
    fn expected_generation_and_conflicting_retry_fail_closed() {
        let fixture = Fixture::new();
        let journal = fixture.bootstrap().unwrap();
        assert!(matches!(
            journal.intend(7, authority_allowed()),
            Err(SessionError::GenerationMismatch)
        ));
        journal.intend(0, authority_allowed()).unwrap();
        assert!(matches!(
            journal.intend(0, authority_denied()),
            Err(SessionError::Conflict)
        ));
    }

    #[test]
    fn transition_id_binds_full_intent_payload_and_variant() {
        let fixture = Fixture::new();
        let first = authority_allowed();
        let second = Transition {
            from: SessionPhase::Created,
            to: SessionPhase::AuthorityEvaluated,
            intent: StepIntent::AuthorityDecision {
                decision_digest: digest(9),
            },
        };
        let wrong_variant = Transition {
            from: SessionPhase::Created,
            to: SessionPhase::AuthorityEvaluated,
            intent: StepIntent::LeaseReservation {
                reservation_digest: digest(1),
            },
        };

        let genesis = fixture.bootstrap().unwrap().genesis();
        let first_id = transition_digest(&genesis, &first).unwrap();
        assert_ne!(first_id, transition_digest(&genesis, &second).unwrap());
        assert_ne!(
            first_id,
            transition_digest(&genesis, &wrong_variant).unwrap()
        );
    }

    #[test]
    fn identical_intents_are_domain_separated_by_session() {
        let fixture = Fixture::new();
        let other_session: SessionId = format!("ses_{}", "34".repeat(16)).parse().unwrap();
        let transition = authority_allowed();
        let first = fixture.bootstrap().unwrap();
        let second = fixture.bootstrap_for(other_session).unwrap();
        assert_ne!(
            transition_digest(&first.genesis, &transition).unwrap(),
            transition_digest(&second.genesis, &transition).unwrap()
        );
        let (_, first_id, _) = result_parts(first.intend(0, transition.clone()).unwrap());
        let (_, second_id, _) = result_parts(second.intend(0, transition).unwrap());
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn every_intent_maps_to_one_closed_subsystem_step() {
        let cases = [
            (
                StepIntent::AuthorityDecision {
                    decision_digest: digest(1),
                },
                SubsystemStep::RecordAuthority,
            ),
            (
                StepIntent::LeaseReservation {
                    reservation_digest: digest(2),
                },
                SubsystemStep::ReserveLease,
            ),
            (
                StepIntent::PermitActivation {
                    activation_digest: digest(3),
                },
                SubsystemStep::ActivatePermit,
            ),
            (
                StepIntent::WorkerProxyObservation {
                    observation_digest: digest(4),
                },
                SubsystemStep::RecordWorker,
            ),
            (
                StepIntent::PermitTerminalState {
                    terminal_digest: digest(5),
                },
                SubsystemStep::TerminalizePermit,
            ),
            (
                StepIntent::RollbackDisposition {
                    disposition_digest: digest(6),
                },
                SubsystemStep::ResolveRollback,
            ),
            (
                StepIntent::FinalizedEvidence {
                    evidence_digest: digest(7),
                },
                SubsystemStep::FinalizeEvidence,
            ),
            (
                StepIntent::PersistedReceipt {
                    receipt_digest: digest(8),
                },
                SubsystemStep::PersistReceipt,
            ),
            (
                StepIntent::Completion {
                    completion_digest: digest(9),
                },
                SubsystemStep::MarkComplete,
            ),
        ];
        for (intent, expected) in cases {
            assert_eq!(intent.step(), expected);
        }
    }

    #[test]
    fn intent_wire_shape_rejects_extra_payload_fields() {
        let encoded = format!(
            r#"{{"authority_decision":{{"decision_digest":"{}","unexpected":"{}"}}}}"#,
            digest(1),
            digest(2)
        );
        assert!(serde_json::from_str::<StepIntent>(&encoded).is_err());
    }

    #[test]
    fn wrong_phase_and_step_payload_pairing_is_rejected_before_persistence() {
        let fixture = Fixture::new();
        let journal = fixture.bootstrap().unwrap();
        let illegal = Transition {
            from: SessionPhase::Created,
            to: SessionPhase::AuthorityEvaluated,
            intent: StepIntent::LeaseReservation {
                reservation_digest: digest(3),
            },
        };
        assert!(matches!(
            journal.intend(0, illegal),
            Err(SessionError::IllegalTransition)
        ));
        assert_eq!(
            journal.recover().unwrap(),
            RecoveryOutcome::Clean {
                phase: SessionPhase::Created,
                generation: 0,
            }
        );
    }

    #[test]
    fn concurrent_exact_intents_create_one_record() {
        let fixture = Fixture::new();
        let journal = Arc::new(fixture.bootstrap().unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let journal = Arc::clone(&journal);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    journal.intend(0, authority_allowed()).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| result_parts(handle.join().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|(is_new, _, _)| *is_new).count(), 1);
        assert!(results.iter().all(|(_, _, generation)| *generation == 1));
        assert!(results.windows(2).all(|pair| pair[0].1 == pair[1].1));
    }

    #[test]
    fn completion_is_step_matched_persisted_and_domain_bound() {
        let fixture = Fixture::new();
        let journal = fixture.bootstrap().unwrap();
        let transition = authority_allowed();
        let (_, transition_id, _) = result_parts(journal.intend(0, transition.clone()).unwrap());
        assert!(matches!(
            journal.complete(
                1,
                &transition_id,
                StepCompletion::LeaseReservation {
                    result_digest: digest(0x80)
                }
            ),
            Err(SessionError::CompletionMismatch)
        ));
        assert_eq!(
            journal.recover().unwrap(),
            RecoveryOutcome::Pending {
                transition,
                transition_id: transition_id.clone(),
                generation: 1,
            }
        );

        let completion = authority_completion(0x81);
        journal
            .complete(1, &transition_id, completion.clone())
            .unwrap();
        let state = journal.load().unwrap();
        assert_eq!(state.completed.len(), 1);
        assert_eq!(state.completed[0].completion, completion);
        assert_eq!(
            state.completed[0].completion_id,
            completion_digest(&journal.genesis, &transition_id, &completion).unwrap()
        );
    }

    #[test]
    fn open_existing_never_initializes_missing_state() {
        let fixture = Fixture::new();
        let genesis = GenesisBinding {
            session_id: fixture.session_id.clone(),
            workspace_identity_digest: digest(0x70),
            action_intent_root_digest: digest(0x71),
            store_id: digest(0x72),
        };
        assert!(matches!(
            fixture.open_existing(genesis),
            Err(SessionError::MissingState)
        ));
        assert!(!fixture.state_path().exists());
    }

    #[test]
    fn copied_state_and_wrong_genesis_are_rejected() {
        let source = Fixture::new();
        let source_journal = source.bootstrap().unwrap();
        let source_genesis = source_journal.genesis();
        let source_bytes = std::fs::read(source.state_path()).unwrap();

        let mut wrong_genesis = source_genesis.clone();
        wrong_genesis.workspace_identity_digest = digest(0x73);
        assert!(matches!(
            source.open_existing(wrong_genesis),
            Err(SessionError::GenesisMismatch)
        ));

        let destination = Fixture::new();
        let destination_journal = destination.bootstrap().unwrap();
        let destination_genesis = destination_journal.genesis();
        assert_ne!(source_genesis.store_id, destination_genesis.store_id);
        drop(destination_journal);
        std::fs::write(destination.state_path(), source_bytes).unwrap();
        assert!(matches!(
            destination.open_existing(destination_genesis),
            Err(SessionError::GenesisMismatch)
        ));
    }

    #[test]
    fn tamper_and_truncation_fail_closed_across_restart() {
        let fixture = Fixture::new();
        let genesis = fixture.bootstrap().unwrap().genesis();
        let path = fixture.state_path();
        let original = std::fs::read(&path).unwrap();
        let mut tampered = original.clone();
        let index = tampered.iter().position(|byte| *byte == b'0').unwrap();
        tampered[index] = b'1';
        std::fs::write(&path, &tampered).unwrap();
        assert!(matches!(
            fixture.open_existing(genesis.clone()),
            Err(SessionError::Tampered)
        ));

        std::fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            fixture.open_existing(genesis),
            Err(SessionError::Truncated)
        ));
    }

    #[test]
    fn oversized_state_fails_before_allocation() {
        let fixture = Fixture::new();
        let genesis = fixture.bootstrap().unwrap().genesis();
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(fixture.state_path())
            .unwrap();
        file.set_len(MAX_STATE + 1).unwrap();
        assert!(matches!(
            fixture.open_existing(genesis),
            Err(SessionError::Oversized)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_storage_components_and_state_are_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let outside = fixture._temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, fixture.root.join("sessions")).unwrap();
        assert!(matches!(
            fixture.bootstrap(),
            Err(SessionError::UnsafeStorage)
        ));

        std::fs::remove_file(fixture.root.join("sessions")).unwrap();
        std::fs::create_dir(fixture.root.join("sessions")).unwrap();
        let target = outside.join("state");
        std::fs::write(&target, b"sentinel").unwrap();
        symlink(&target, fixture.state_path()).unwrap();
        assert!(matches!(
            fixture.bootstrap(),
            Err(SessionError::UnsafeStorage)
        ));
        assert_eq!(std::fs::read(target).unwrap(), b"sentinel");
    }

    #[cfg(unix)]
    #[test]
    fn persisted_storage_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        fixture.bootstrap().unwrap();
        assert_eq!(
            std::fs::metadata(fixture.root.join("sessions"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in [fixture.state_path(), fixture.lock_path()] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn journal_is_value_free_and_outside_workspace() {
        let fixture = Fixture::new();
        let journal = fixture.bootstrap().unwrap();
        journal.intend(0, authority_allowed()).unwrap();
        let persisted = std::fs::read(fixture.state_path()).unwrap();
        for forbidden in [
            fixture.root.to_string_lossy().as_bytes(),
            fixture.workspace.to_string_lossy().as_bytes(),
            b"SENTINEL_SECRET_VALUE".as_slice(),
            b"https://example.invalid/private".as_slice(),
            b"--raw-argv".as_slice(),
            b"Authorization: Bearer".as_slice(),
        ] {
            assert!(!persisted
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
        assert!(!fixture.state_path().starts_with(&fixture.workspace));
    }

    #[test]
    fn zero_key_and_overlapping_storage_are_rejected() {
        let fixture = Fixture::new();
        assert!(matches!(
            Journal::bootstrap(
                &fixture.root,
                &fixture.workspace,
                fixture.session_id.clone(),
                digest(0x70),
                digest(0x71),
                [0; 32]
            ),
            Err(SessionError::InvalidKey)
        ));
        assert!(matches!(
            Journal::bootstrap(
                &fixture.workspace,
                &fixture.workspace,
                fixture.session_id,
                digest(0x70),
                digest(0x71),
                KEY
            ),
            Err(SessionError::StorageOverlap)
        ));
    }
}
