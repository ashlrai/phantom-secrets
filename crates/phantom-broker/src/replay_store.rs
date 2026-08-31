//! Crash-durable, authenticated replay and lease-use accounting.
//!
//! The store contains only opaque identifiers, digests, counters, and
//! value-free constraints. It never persists grants, signatures, credential
//! locators, proxy credentials, request bodies, or secret values. A broker
//! must call [`DurableReplayStore::start_epoch`] before creating leases; doing
//! so revokes every lease from a previous process lifetime.
//!
//! # Inactive security boundary
//!
//! This authenticated snapshot detects modification but cannot, by itself,
//! detect replacement with an older valid snapshot. It is therefore not an
//! activation authority until a host-protected monotonic rollback anchor is
//! added. The Unix storage backend retains its root descriptor and performs
//! flat-file operations relative to it; unsupported platforms fail closed.
//! Phantom's production authority transport and execution confinement remain
//! unavailable.

use crate::lease::{LeaseBinding, LeaseBindingError};
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use crate::replay_storage::ReplaceFault;
use crate::replay_storage::{InstanceLock, ReplayStorage, ReplayStorageError};
use hmac::{Hmac, Mac};
use phantom_authority::{
    canonical_json_v1, ActionId, AuthorityConstraints, CanonicalJsonError, GrantId, LeaseId,
    Operation, Sha256Digest, UseCapacity, WorkspaceId,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Mutex,
};
use zeroize::Zeroizing;

const STORE_FORMAT_VERSION: u16 = 2;
const STATE_FILE_NAME: &str = "replay-state.v2.json";
const LEGACY_STATE_FILE_NAME: &str = "replay-state.v1.json";
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
const STORE_ID_BYTES: usize = 32;
const INACTIVE: u8 = 0;
const ACTIVATING: u8 = 1;
const ACTIVE: u8 = 2;
const POISONED: u8 = 3;

type HmacSha256 = Hmac<Sha256>;

/// Result of atomically reserving a verified grant binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayReservation {
    New(LeaseId),
    Existing(LeaseId),
}

/// Durable status returned for a retry. No existing status is execution
/// authority; only `ReplayUseReservation::New` carries a permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayUseState {
    InProgress,
    Completing,
    Finished,
    Abandoned,
}

/// Exact terminal disposition bound before a use can become terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalDisposition {
    Finished,
    Abandoned,
}

/// Result of starting the durable completion phase. A matching retry while
/// completion is pending receives a fresh non-cloneable witness; a terminal
/// retry reports the already committed state without minting authority.
#[derive(Debug)]
pub enum ReplayCompletionReservation {
    New(Box<CompletionWitness>),
    Resumed(Box<CompletionWitness>),
    Existing(ReplayUseState),
}

/// Non-cloneable proof that this store atomically reserved one new operation.
/// It is not serializable and its fields are private, so callers cannot mint a
/// permit from an existing/replayed operation.
#[must_use = "an execution permit must be finished or abandoned durably"]
pub struct ExecutionPermit {
    lease_id: LeaseId,
    broker_generation: u64,
    action_id: ActionId,
    operation: Operation,
    canonical_args_sha256: Sha256Digest,
    workspace_id: WorkspaceId,
    workspace_manifest_sha256: Sha256Digest,
    policy_sha256: Sha256Digest,
    constraints: AuthorityConstraints,
    operation_sha256: String,
    store_binding: String,
}

/// Non-cloneable witness for one exact pending terminal transition.
#[must_use = "a completion witness must be committed durably"]
pub struct CompletionWitness {
    lease_id: LeaseId,
    broker_generation: u64,
    operation_sha256: String,
    terminal_record_sha256: Sha256Digest,
    disposition: TerminalDisposition,
    store_binding: String,
}

impl CompletionWitness {
    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }
    pub fn terminal_record_sha256(&self) -> &Sha256Digest {
        &self.terminal_record_sha256
    }
    pub fn disposition(&self) -> TerminalDisposition {
        self.disposition
    }
}

impl std::fmt::Debug for CompletionWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletionWitness")
            .field("lease_id", &self.lease_id)
            .field("broker_generation", &self.broker_generation)
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

impl ExecutionPermit {
    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    pub fn broker_generation(&self) -> u64 {
        self.broker_generation
    }

    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn canonical_args_sha256(&self) -> &Sha256Digest {
        &self.canonical_args_sha256
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn workspace_manifest_sha256(&self) -> &Sha256Digest {
        &self.workspace_manifest_sha256
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn constraints(&self) -> &AuthorityConstraints {
        &self.constraints
    }
}

impl std::fmt::Debug for ExecutionPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionPermit")
            .field("lease_id", &self.lease_id)
            .field("broker_generation", &self.broker_generation)
            .finish_non_exhaustive()
    }
}

/// Result of atomically starting an opaque execution operation.
#[derive(Debug)]
pub enum ReplayUseReservation {
    New(Box<ExecutionPermit>),
    Existing(ReplayUseState),
}

/// A local durable ledger. The authentication key must come from a protected
/// host facility; it is never written to disk and is zeroized on drop.
pub struct DurableReplayStore {
    storage: ReplayStorage,
    store_id: String,
    key: Zeroizing<[u8; 32]>,
    process_lock: Mutex<()>,
    instance_lock: Mutex<Option<InstanceLock>>,
    activation: AtomicU8,
}

impl DurableReplayStore {
    /// Explicitly create a new private replay store. This refuses to overwrite
    /// an existing state file. Normal broker startup must use `open_existing`.
    pub fn bootstrap(
        root: impl AsRef<Path>,
        workspace_root: impl AsRef<Path>,
        key: [u8; 32],
    ) -> Result<Self, ReplayStoreError> {
        validate_key(&key)?;
        let storage = ReplayStorage::bootstrap(root.as_ref(), workspace_root.as_ref())?;
        let _lock = storage.lock_transaction()?;
        if storage.exists(STATE_FILE_NAME)? || storage.exists(LEGACY_STATE_FILE_NAME)? {
            return Err(ReplayStoreError::AlreadyInitialized);
        }
        let mut random = [0_u8; STORE_ID_BYTES];
        OsRng.fill_bytes(&mut random);
        let state = PersistedState {
            store_id: hex::encode(random),
            ..PersistedState::default()
        };
        write_authenticated_state(&storage, &state, &key)?;
        Ok(Self::from_parts(storage, state.store_id, key))
    }

    /// Open a previously bootstrapped store. Missing state is a hard error and
    /// can never silently reset nonce, lease, or use history.
    pub fn open_existing(
        root: impl AsRef<Path>,
        workspace_root: impl AsRef<Path>,
        key: [u8; 32],
    ) -> Result<Self, ReplayStoreError> {
        validate_key(&key)?;
        let storage = ReplayStorage::open_existing(root.as_ref())?;
        if storage.overlaps_directory(workspace_root.as_ref())? {
            return Err(ReplayStoreError::StorageOverlapsWorkspace);
        }
        let _lock = storage.lock_transaction()?;
        if !storage.exists(STATE_FILE_NAME)? {
            if storage.exists(LEGACY_STATE_FILE_NAME)? {
                return Err(ReplayStoreError::UnsupportedFormat);
            }
            return Err(ReplayStoreError::MissingState);
        }
        let state = read_authenticated_state(&storage, &key)?;
        validate_store_id(&state.store_id)?;
        Ok(Self::from_parts(storage, state.store_id, key))
    }

    fn from_parts(storage: ReplayStorage, store_id: String, key: [u8; 32]) -> Self {
        Self {
            storage,
            store_id,
            key: Zeroizing::new(key),
            process_lock: Mutex::new(()),
            instance_lock: Mutex::new(None),
            activation: AtomicU8::new(INACTIVE),
        }
    }

    /// Start exactly one broker lifetime and retain an exclusive instance lock
    /// until this store is dropped. A second activation attempt fails closed.
    pub fn start_epoch(&self) -> Result<u64, ReplayStoreError> {
        let activation = self
            .activation
            .compare_exchange(INACTIVE, ACTIVATING, Ordering::AcqRel, Ordering::Acquire)
            .err();
        if let Some(activation) = activation {
            return if activation == POISONED {
                Err(ReplayStoreError::ActivationPoisoned)
            } else {
                Err(ReplayStoreError::AlreadyActive)
            };
        }
        let instance = match self.storage.try_lock_instance() {
            Ok(instance) => instance,
            Err(ReplayStorageError::InstanceAlreadyActive) => {
                self.activation.store(INACTIVE, Ordering::Release);
                return Err(ReplayStoreError::InstanceAlreadyActive);
            }
            Err(error) => {
                self.activation.store(POISONED, Ordering::Release);
                return Err(error.into());
            }
        };
        // From this point forward a failed write may already have committed a
        // new generation. This object is permanently non-retryable even when
        // the storage layer reports an error.
        self.activation.store(POISONED, Ordering::Release);
        let result = self.with_locked_state_unchecked(|state| {
            state.broker_generation = state
                .broker_generation
                .checked_add(1)
                .ok_or(ReplayStoreError::GenerationExhausted)?;
            if state.broker_generation == 0 {
                return Err(ReplayStoreError::GenerationExhausted);
            }
            for (lease_id, lease) in &mut state.leases {
                lease.revoked = true;
                for (operation_sha256, use_state) in &mut lease.uses {
                    if matches!(use_state, PersistedUseState::Active) {
                        *use_state = PersistedUseState::Abandoned {
                            terminal_record_sha256: recovery_terminal_digest(
                                &self.store_id,
                                &format!("{lease_id}:{operation_sha256}"),
                                "broker_restart",
                            )?,
                        };
                    }
                }
            }
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or(ReplayStoreError::SequenceExhausted)?;
            Ok((state.broker_generation, true))
        });
        let generation = result?;
        *self
            .instance_lock
            .lock()
            .map_err(|_| ReplayStoreError::LockPoisoned)? = Some(instance);
        self.activation.store(ACTIVE, Ordering::Release);
        Ok(generation)
    }

    pub fn current_generation(&self) -> Result<u64, ReplayStoreError> {
        self.ensure_active()?;
        self.with_locked_state_unchecked(|state| Ok((state.broker_generation, false)))
    }

    /// Atomically consume a grant nonce digest and reserve one value-free
    /// lease. Exact idempotent retries return the original lease identifier.
    pub fn reserve(
        &self,
        grant_nonce_sha256: &Sha256Digest,
        idempotency_key: &str,
        binding: &LeaseBinding,
    ) -> Result<ReplayReservation, ReplayStoreError> {
        binding.validate()?;
        validate_idempotency_key(idempotency_key)?;

        let nonce = grant_nonce_sha256.to_string();
        let idempotency_digest = sha256_hex(idempotency_key.as_bytes());
        let request_fingerprint = sha256_hex(&canonical_json_v1(binding)?);
        let lease_id = binding.lease_id().to_string();

        self.with_locked_state(|state| {
            if state.broker_generation == 0
                || binding.broker_generation() != state.broker_generation
            {
                return Err(ReplayStoreError::StaleBrokerGeneration);
            }
            if let Some(existing) = state.idempotency.get(&idempotency_digest) {
                if existing.request_fingerprint_sha256 == request_fingerprint {
                    return Ok((
                        ReplayReservation::Existing(
                            existing
                                .lease_id
                                .parse()
                                .map_err(|_| ReplayStoreError::InvalidState)?,
                        ),
                        false,
                    ));
                }
                return Err(ReplayStoreError::IdempotencyCollision);
            }
            if state.seen_nonce_digests.contains(&nonce) {
                return Err(ReplayStoreError::Replay);
            }
            if state.leases.contains_key(&lease_id) {
                return Err(ReplayStoreError::LeaseIdCollision);
            }

            let (max_uses, _) = binding.constraints().uses.capacity.limits().ok_or(
                ReplayStoreError::InvalidBinding(LeaseBindingError::NoUsableCapacity),
            )?;
            state.seen_nonce_digests.insert(nonce);
            state.idempotency.insert(
                idempotency_digest,
                PersistedIdempotency {
                    request_fingerprint_sha256: request_fingerprint,
                    lease_id: lease_id.clone(),
                },
            );
            state.leases.insert(
                lease_id.clone(),
                PersistedLease {
                    grant_id: binding.grant_id.clone(),
                    action_id: binding.action_id.clone(),
                    operation: binding.operation,
                    canonical_args_sha256: binding.canonical_args_sha256.clone(),
                    workspace_id: binding.expected_authority.workspace_id.clone(),
                    workspace_manifest_sha256: binding
                        .expected_authority
                        .workspace_manifest_sha256
                        .clone(),
                    policy_sha256: binding.expected_authority.policy_sha256.clone(),
                    broker_generation: binding.broker_generation(),
                    constraints: binding.constraints().clone(),
                    remaining_uses: max_uses,
                    uses: BTreeMap::new(),
                    revoked: false,
                },
            );
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or(ReplayStoreError::SequenceExhausted)?;
            Ok((ReplayReservation::New(binding.lease_id().clone()), true))
        })
    }

    /// Consume one use before any upstream connection can be opened.
    pub fn begin_use(
        &self,
        lease_id: &LeaseId,
        operation_id: &str,
        now_unix: u64,
    ) -> Result<ReplayUseReservation, ReplayStoreError> {
        validate_operation_id(operation_id)?;
        let lease_id = lease_id.to_string();
        let operation_digest = sha256_hex(operation_id.as_bytes());
        let store_binding = self.store_binding()?;
        self.with_locked_state(|state| {
            let generation = state.broker_generation;
            let lease = state
                .leases
                .get_mut(&lease_id)
                .ok_or(ReplayStoreError::UnknownLease)?;
            if lease.revoked || lease.broker_generation != generation {
                return Err(ReplayStoreError::Revoked);
            }
            if now_unix < lease.constraints.time.not_before
                || now_unix >= lease.constraints.time.expires_at
            {
                return Err(ReplayStoreError::Expired);
            }
            if let Some(existing) = lease.uses.get(&operation_digest) {
                return Ok((ReplayUseReservation::Existing(existing.into()), false));
            }
            let max_concurrent = match lease.constraints.uses.capacity {
                UseCapacity::Bounded {
                    max_concurrent_uses,
                    ..
                } => max_concurrent_uses,
                UseCapacity::Denied => return Err(ReplayStoreError::CapacityExhausted),
            };
            let active_uses = lease
                .uses
                .values()
                .filter(|state| {
                    matches!(
                        state,
                        PersistedUseState::Active | PersistedUseState::Completing { .. }
                    )
                })
                .count();
            if lease.remaining_uses == 0 || active_uses >= usize::from(max_concurrent) {
                return Err(ReplayStoreError::CapacityExhausted);
            }
            lease.remaining_uses -= 1;
            lease
                .uses
                .insert(operation_digest.clone(), PersistedUseState::Active);
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or(ReplayStoreError::SequenceExhausted)?;
            Ok((
                ReplayUseReservation::New(Box::new(ExecutionPermit {
                    lease_id: lease_id
                        .parse()
                        .map_err(|_| ReplayStoreError::InvalidState)?,
                    broker_generation: generation,
                    action_id: lease.action_id.clone(),
                    operation: lease.operation,
                    canonical_args_sha256: lease.canonical_args_sha256.clone(),
                    workspace_id: lease.workspace_id.clone(),
                    workspace_manifest_sha256: lease.workspace_manifest_sha256.clone(),
                    policy_sha256: lease.policy_sha256.clone(),
                    constraints: lease.constraints.clone(),
                    operation_sha256: operation_digest,
                    store_binding,
                })),
                true,
            ))
        })
    }

    /// Enter the exact durable terminal-completion phase. A matching retry is
    /// resumable; a different digest or disposition is rejected.
    pub fn begin_completion(
        &self,
        permit: &ExecutionPermit,
        terminal_record_sha256: &Sha256Digest,
        disposition: TerminalDisposition,
    ) -> Result<ReplayCompletionReservation, ReplayStoreError> {
        self.validate_permit(permit)?;
        let lease_id = permit.lease_id.to_string();
        let operation_digest = permit.operation_sha256.clone();
        let binding = permit.store_binding.clone();
        let terminal_digest = terminal_record_sha256.clone();
        self.with_locked_state(|state| {
            if permit.broker_generation != state.broker_generation {
                return Err(ReplayStoreError::Revoked);
            }
            let lease = state
                .leases
                .get_mut(&lease_id)
                .ok_or(ReplayStoreError::UnknownLease)?;
            if lease.revoked || lease.broker_generation != permit.broker_generation {
                return Err(ReplayStoreError::Revoked);
            }
            let use_state = lease
                .uses
                .get_mut(&operation_digest)
                .ok_or(ReplayStoreError::UnknownUse)?;
            let witness = || {
                Box::new(CompletionWitness {
                    lease_id: permit.lease_id.clone(),
                    broker_generation: permit.broker_generation,
                    operation_sha256: operation_digest.clone(),
                    terminal_record_sha256: terminal_digest.clone(),
                    disposition,
                    store_binding: binding.clone(),
                })
            };
            match use_state {
                PersistedUseState::Active => {
                    *use_state = PersistedUseState::Completing {
                        terminal_record_sha256: terminal_digest.clone(),
                        disposition,
                    };
                    state.sequence = state
                        .sequence
                        .checked_add(1)
                        .ok_or(ReplayStoreError::SequenceExhausted)?;
                    Ok((ReplayCompletionReservation::New(witness()), true))
                }
                PersistedUseState::Completing {
                    terminal_record_sha256: existing,
                    disposition: existing_disposition,
                } if existing == &terminal_digest && *existing_disposition == disposition => {
                    Ok((ReplayCompletionReservation::Resumed(witness()), false))
                }
                PersistedUseState::Finished {
                    terminal_record_sha256: existing,
                } if existing == &terminal_digest
                    && disposition == TerminalDisposition::Finished =>
                {
                    Ok((
                        ReplayCompletionReservation::Existing(ReplayUseState::Finished),
                        false,
                    ))
                }
                PersistedUseState::Abandoned {
                    terminal_record_sha256: existing,
                } if existing == &terminal_digest
                    && disposition == TerminalDisposition::Abandoned =>
                {
                    Ok((
                        ReplayCompletionReservation::Existing(ReplayUseState::Abandoned),
                        false,
                    ))
                }
                PersistedUseState::Completing { .. }
                | PersistedUseState::Finished { .. }
                | PersistedUseState::Abandoned { .. } => Err(ReplayStoreError::CompletionConflict),
            }
        })
    }

    /// Resume an already-persisted completion after a broker crash. This can
    /// never create a completion from an active use and therefore conveys no
    /// execution authority. The exact operation, digest, and disposition must
    /// match the durable pending record.
    pub fn resume_completion(
        &self,
        lease_id: &LeaseId,
        operation_id: &str,
        terminal_record_sha256: &Sha256Digest,
        disposition: TerminalDisposition,
    ) -> Result<ReplayCompletionReservation, ReplayStoreError> {
        validate_operation_id(operation_id)?;
        let lease_key = lease_id.to_string();
        let operation_sha256 = sha256_hex(operation_id.as_bytes());
        let store_binding = self.store_binding()?;
        self.with_locked_state(|state| {
            let lease = state
                .leases
                .get(&lease_key)
                .ok_or(ReplayStoreError::UnknownLease)?;
            let use_state = lease
                .uses
                .get(&operation_sha256)
                .ok_or(ReplayStoreError::UnknownUse)?;
            let witness = || {
                Box::new(CompletionWitness {
                    lease_id: lease_id.clone(),
                    broker_generation: lease.broker_generation,
                    operation_sha256: operation_sha256.clone(),
                    terminal_record_sha256: terminal_record_sha256.clone(),
                    disposition,
                    store_binding: store_binding.clone(),
                })
            };
            match use_state {
                PersistedUseState::Completing {
                    terminal_record_sha256: existing,
                    disposition: existing_disposition,
                } if existing == terminal_record_sha256 && *existing_disposition == disposition => {
                    Ok((ReplayCompletionReservation::Resumed(witness()), false))
                }
                PersistedUseState::Finished {
                    terminal_record_sha256: existing,
                } if existing == terminal_record_sha256
                    && disposition == TerminalDisposition::Finished =>
                {
                    Ok((
                        ReplayCompletionReservation::Existing(ReplayUseState::Finished),
                        false,
                    ))
                }
                PersistedUseState::Abandoned {
                    terminal_record_sha256: existing,
                } if existing == terminal_record_sha256
                    && disposition == TerminalDisposition::Abandoned =>
                {
                    Ok((
                        ReplayCompletionReservation::Existing(ReplayUseState::Abandoned),
                        false,
                    ))
                }
                PersistedUseState::Active => Err(ReplayStoreError::CompletionNotStarted),
                PersistedUseState::Completing { .. }
                | PersistedUseState::Finished { .. }
                | PersistedUseState::Abandoned { .. } => Err(ReplayStoreError::CompletionConflict),
            }
        })
    }

    /// Commit one exact completion witness to its terminal state.
    pub fn commit_completion(&self, witness: &CompletionWitness) -> Result<(), ReplayStoreError> {
        if witness.store_binding != self.store_binding()? {
            return Err(ReplayStoreError::ForeignCompletionWitness);
        }
        let lease_id = witness.lease_id.to_string();
        let operation_digest = witness.operation_sha256.clone();
        self.with_locked_state(|state| {
            let lease = state
                .leases
                .get_mut(&lease_id)
                .ok_or(ReplayStoreError::UnknownLease)?;
            if witness.broker_generation != lease.broker_generation {
                return Err(ReplayStoreError::ForeignCompletionWitness);
            }
            let use_state = lease
                .uses
                .get_mut(&operation_digest)
                .ok_or(ReplayStoreError::UnknownUse)?;
            match use_state {
                PersistedUseState::Completing {
                    terminal_record_sha256,
                    disposition,
                } if terminal_record_sha256 == &witness.terminal_record_sha256
                    && *disposition == witness.disposition =>
                {
                    *use_state = match witness.disposition {
                        TerminalDisposition::Finished => PersistedUseState::Finished {
                            terminal_record_sha256: witness.terminal_record_sha256.clone(),
                        },
                        TerminalDisposition::Abandoned => PersistedUseState::Abandoned {
                            terminal_record_sha256: witness.terminal_record_sha256.clone(),
                        },
                    };
                    state.sequence = state
                        .sequence
                        .checked_add(1)
                        .ok_or(ReplayStoreError::SequenceExhausted)?;
                    Ok(((), true))
                }
                PersistedUseState::Finished {
                    terminal_record_sha256,
                } if terminal_record_sha256 == &witness.terminal_record_sha256
                    && witness.disposition == TerminalDisposition::Finished =>
                {
                    Ok(((), false))
                }
                PersistedUseState::Abandoned {
                    terminal_record_sha256,
                } if terminal_record_sha256 == &witness.terminal_record_sha256
                    && witness.disposition == TerminalDisposition::Abandoned =>
                {
                    Ok(((), false))
                }
                PersistedUseState::Active => Err(ReplayStoreError::CompletionNotStarted),
                PersistedUseState::Completing { .. }
                | PersistedUseState::Finished { .. }
                | PersistedUseState::Abandoned { .. } => Err(ReplayStoreError::CompletionConflict),
            }
        })
    }

    /// Compatibility terminalization for the current inactive runtime. The
    /// digest is deterministic and value-free, but is not trusted worker or
    /// evidence attestation.
    pub fn finish_use(&self, permit: &ExecutionPermit) -> Result<(), ReplayStoreError> {
        self.legacy_terminalize(permit, TerminalDisposition::Finished)
    }

    /// Mark a permitted operation abandoned without restoring consumed use
    /// capacity. Retrying with the same permit is idempotent.
    pub fn abandon_use(&self, permit: &ExecutionPermit) -> Result<(), ReplayStoreError> {
        self.legacy_terminalize(permit, TerminalDisposition::Abandoned)
    }

    fn legacy_terminalize(
        &self,
        permit: &ExecutionPermit,
        disposition: TerminalDisposition,
    ) -> Result<(), ReplayStoreError> {
        #[derive(Serialize)]
        struct LegacyTerminal<'a> {
            version: u16,
            store_id: &'a str,
            lease_id: &'a LeaseId,
            operation_sha256: &'a str,
            disposition: TerminalDisposition,
        }
        let digest = hex::encode(Sha256::digest(canonical_json_v1(&LegacyTerminal {
            version: 1,
            store_id: &self.store_id,
            lease_id: &permit.lease_id,
            operation_sha256: &permit.operation_sha256,
            disposition,
        })?))
        .parse()
        .map_err(|_| ReplayStoreError::InvalidState)?;
        let reservation = match self.begin_completion(permit, &digest, disposition) {
            Err(ReplayStoreError::CompletionConflict) => {
                return Err(ReplayStoreError::OperationAlreadyTerminal)
            }
            result => result?,
        };
        match reservation {
            ReplayCompletionReservation::New(witness)
            | ReplayCompletionReservation::Resumed(witness) => self.commit_completion(&witness),
            ReplayCompletionReservation::Existing(_) => Ok(()),
        }
    }

    fn validate_permit(&self, permit: &ExecutionPermit) -> Result<(), ReplayStoreError> {
        if permit.store_binding != self.store_binding()? {
            return Err(ReplayStoreError::ForeignPermit);
        }
        Ok(())
    }

    fn store_binding(&self) -> Result<String, ReplayStoreError> {
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref())
            .map_err(|_| ReplayStoreError::InvalidKey)?;
        mac.update(b"phantom.broker.replay-store-binding.v2\0");
        mac.update(self.store_id.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    pub fn revoke(&self, lease_id: &LeaseId) -> Result<(), ReplayStoreError> {
        let lease_id = lease_id.to_string();
        self.with_locked_state(|state| {
            let lease = state
                .leases
                .get_mut(&lease_id)
                .ok_or(ReplayStoreError::UnknownLease)?;
            if lease.revoked {
                return Ok(((), false));
            }
            lease.revoked = true;
            for use_state in lease.uses.values_mut() {
                if matches!(use_state, PersistedUseState::Active) {
                    *use_state = PersistedUseState::Abandoned {
                        terminal_record_sha256: recovery_terminal_digest(
                            &self.store_id,
                            &lease_id,
                            "revoked_before_completion",
                        )?,
                    };
                }
            }
            state.sequence = state
                .sequence
                .checked_add(1)
                .ok_or(ReplayStoreError::SequenceExhausted)?;
            Ok(((), true))
        })
    }

    fn ensure_active(&self) -> Result<(), ReplayStoreError> {
        if self.activation.load(Ordering::Acquire) != ACTIVE {
            return Err(ReplayStoreError::NotActive);
        }
        Ok(())
    }

    fn with_locked_state<T>(
        &self,
        operation: impl FnOnce(&mut PersistedState) -> Result<(T, bool), ReplayStoreError>,
    ) -> Result<T, ReplayStoreError> {
        self.ensure_active()?;
        self.with_locked_state_unchecked(operation)
    }

    fn with_locked_state_unchecked<T>(
        &self,
        operation: impl FnOnce(&mut PersistedState) -> Result<(T, bool), ReplayStoreError>,
    ) -> Result<T, ReplayStoreError> {
        let _process_guard = self
            .process_lock
            .lock()
            .map_err(|_| ReplayStoreError::LockPoisoned)?;
        let _file_guard = self.storage.lock_transaction()?;
        if !self.storage.exists(STATE_FILE_NAME)? {
            return Err(ReplayStoreError::MissingState);
        }
        let mut state = read_authenticated_state(&self.storage, &self.key)?;
        if state.store_id != self.store_id {
            return Err(ReplayStoreError::StoreIdentityMismatch);
        }
        let (result, changed) = operation(&mut state)?;
        if changed {
            write_authenticated_state(&self.storage, &state, &self.key)?;
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    store_id: String,
    broker_generation: u64,
    sequence: u64,
    seen_nonce_digests: BTreeSet<String>,
    idempotency: BTreeMap<String, PersistedIdempotency>,
    leases: BTreeMap<String, PersistedLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedIdempotency {
    request_fingerprint_sha256: String,
    lease_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedLease {
    grant_id: GrantId,
    action_id: ActionId,
    operation: Operation,
    canonical_args_sha256: Sha256Digest,
    workspace_id: WorkspaceId,
    workspace_manifest_sha256: Sha256Digest,
    policy_sha256: Sha256Digest,
    broker_generation: u64,
    constraints: AuthorityConstraints,
    remaining_uses: u32,
    uses: BTreeMap<String, PersistedUseState>,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum PersistedUseState {
    Active,
    Completing {
        terminal_record_sha256: Sha256Digest,
        disposition: TerminalDisposition,
    },
    Finished {
        terminal_record_sha256: Sha256Digest,
    },
    Abandoned {
        terminal_record_sha256: Sha256Digest,
    },
}

impl From<&PersistedUseState> for ReplayUseState {
    fn from(value: &PersistedUseState) -> Self {
        match value {
            PersistedUseState::Active => Self::InProgress,
            PersistedUseState::Completing { .. } => Self::Completing,
            PersistedUseState::Finished { .. } => Self::Finished,
            PersistedUseState::Abandoned { .. } => Self::Abandoned,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedState {
    format_version: u16,
    payload: PersistedState,
    hmac_sha256: String,
}

#[derive(Serialize)]
struct MacInput<'a> {
    format_version: u16,
    payload: &'a PersistedState,
}

fn read_authenticated_state(
    storage: &ReplayStorage,
    key: &[u8; 32],
) -> Result<PersistedState, ReplayStoreError> {
    let bytes = storage.read(STATE_FILE_NAME, MAX_STATE_BYTES)?;
    let signed: SignedState =
        serde_json::from_slice(&bytes).map_err(|_| ReplayStoreError::InvalidState)?;
    if signed.format_version != STORE_FORMAT_VERSION {
        return Err(ReplayStoreError::UnsupportedFormat);
    }
    let expected = hex::decode(&signed.hmac_sha256).map_err(|_| ReplayStoreError::InvalidState)?;
    let input = canonical_json_v1(&MacInput {
        format_version: signed.format_version,
        payload: &signed.payload,
    })?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ReplayStoreError::InvalidKey)?;
    mac.update(b"phantom.broker.replay-state.v2\0");
    mac.update(&input);
    mac.verify_slice(&expected)
        .map_err(|_| ReplayStoreError::AuthenticationFailed)?;
    authenticated_state_bytes_with_limit(&signed.payload, key, MAX_STATE_BYTES)?;
    Ok(signed.payload)
}

fn write_authenticated_state(
    storage: &ReplayStorage,
    state: &PersistedState,
    key: &[u8; 32],
) -> Result<(), ReplayStoreError> {
    let bytes = authenticated_state_bytes_with_limit(state, key, MAX_STATE_BYTES)?;
    storage.replace(STATE_FILE_NAME, &bytes)?;
    Ok(())
}

fn authenticated_state_bytes_with_limit(
    state: &PersistedState,
    key: &[u8; 32],
    max_state_bytes: u64,
) -> Result<Vec<u8>, ReplayStoreError> {
    let bytes = authenticated_state_bytes(state, key)?;
    let recovery_bytes = authenticated_state_bytes(&recovery_sized_state(state)?, key)?;
    if bytes.len() as u64 > max_state_bytes || recovery_bytes.len() as u64 > max_state_bytes {
        return Err(ReplayStoreError::StateTooLarge);
    }
    Ok(bytes)
}

fn authenticated_state_bytes(
    state: &PersistedState,
    key: &[u8; 32],
) -> Result<Vec<u8>, ReplayStoreError> {
    validate_store_id(&state.store_id)?;
    let input = canonical_json_v1(&MacInput {
        format_version: STORE_FORMAT_VERSION,
        payload: state,
    })?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ReplayStoreError::InvalidKey)?;
    mac.update(b"phantom.broker.replay-state.v2\0");
    mac.update(&input);
    let signed = SignedState {
        format_version: STORE_FORMAT_VERSION,
        payload: serde_json::from_slice(&serde_json::to_vec(state)?)?,
        hmac_sha256: hex::encode(mac.finalize().into_bytes()),
    };
    Ok(serde_json::to_vec(&signed)?)
}

/// Construct the largest state that a mandatory restart/revocation transition
/// can produce from `state`. Persisting only states whose recovery form fits
/// ensures the size limit can never strand an active use.
fn recovery_sized_state(state: &PersistedState) -> Result<PersistedState, ReplayStoreError> {
    let mut recovery = state.clone();
    recovery.broker_generation = u64::MAX;
    recovery.sequence = u64::MAX;
    let terminal_record_sha256: Sha256Digest = "ff"
        .repeat(32)
        .parse()
        .map_err(|_| ReplayStoreError::InvalidState)?;
    for lease in recovery.leases.values_mut() {
        for use_state in lease.uses.values_mut() {
            if matches!(use_state, PersistedUseState::Active) {
                *use_state = PersistedUseState::Abandoned {
                    terminal_record_sha256: terminal_record_sha256.clone(),
                };
            }
        }
    }
    Ok(recovery)
}

fn validate_key(key: &[u8; 32]) -> Result<(), ReplayStoreError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(ReplayStoreError::InvalidKey);
    }
    Ok(())
}

fn validate_store_id(value: &str) -> Result<(), ReplayStoreError> {
    if value.len() != STORE_ID_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReplayStoreError::InvalidState);
    }
    Ok(())
}

fn recovery_terminal_digest(
    store_id: &str,
    subject: &str,
    reason: &str,
) -> Result<Sha256Digest, ReplayStoreError> {
    #[derive(Serialize)]
    struct RecoveryTerminal<'a> {
        version: u16,
        store_id: &'a str,
        subject: &'a str,
        reason: &'a str,
    }
    hex::encode(Sha256::digest(canonical_json_v1(&RecoveryTerminal {
        version: 1,
        store_id,
        subject,
        reason,
    })?))
    .parse()
    .map_err(|_| ReplayStoreError::InvalidState)
}

fn validate_idempotency_key(value: &str) -> Result<(), ReplayStoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ReplayStoreError::InvalidReservationKey);
    }
    Ok(())
}

fn validate_operation_id(value: &str) -> Result<(), ReplayStoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ReplayStoreError::InvalidOperationId);
    }
    Ok(())
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayStoreError {
    #[error("invalid idempotency reservation key")]
    InvalidReservationKey,
    #[error("invalid execution operation identifier")]
    InvalidOperationId,
    #[error("grant nonce replayed")]
    Replay,
    #[error("idempotency key reused for a different request")]
    IdempotencyCollision,
    #[error("lease identifier collision")]
    LeaseIdCollision,
    #[error("broker generation is not active or is stale")]
    StaleBrokerGeneration,
    #[error("unknown lease")]
    UnknownLease,
    #[error("lease revoked")]
    Revoked,
    #[error("lease expired")]
    Expired,
    #[error("lease use or concurrency capacity exhausted")]
    CapacityExhausted,
    #[error("unknown lease-use operation")]
    UnknownUse,
    #[error("execution permit belongs to a different replay store")]
    ForeignPermit,
    #[error("completion witness belongs to a different replay store")]
    ForeignCompletionWitness,
    #[error("terminal completion has not been started")]
    CompletionNotStarted,
    #[error("terminal completion digest or disposition conflicts with durable state")]
    CompletionConflict,
    #[error("lease-use operation is already in a different terminal state")]
    OperationAlreadyTerminal,
    #[error("broker generation exhausted")]
    GenerationExhausted,
    #[error("replay-store sequence exhausted")]
    SequenceExhausted,
    #[error("replay-store lock poisoned")]
    LockPoisoned,
    #[error("replay-store lock unavailable")]
    LockUnavailable,
    #[error("replay store is already active")]
    AlreadyActive,
    #[error("replay store activation is poisoned and cannot be retried")]
    ActivationPoisoned,
    #[error("another replay broker instance is active")]
    InstanceAlreadyActive,
    #[error("replay store has not been activated")]
    NotActive,
    #[error("replay store is already initialized")]
    AlreadyInitialized,
    #[error("replay-store state is missing")]
    MissingState,
    #[error("replay-store identity does not match the opened store")]
    StoreIdentityMismatch,
    #[error("replay-store root is invalid")]
    InvalidRoot,
    #[error("workspace root is invalid")]
    InvalidWorkspace,
    #[error("replay-store storage must not overlap the workspace")]
    StorageOverlapsWorkspace,
    #[error("replay-store symlink rejected")]
    SymlinkRejected,
    #[error("replay-store state exceeds its size limit")]
    StateTooLarge,
    #[error("replay-store format is unsupported")]
    UnsupportedFormat,
    #[error("replay-store authentication failed")]
    AuthenticationFailed,
    #[error("replay-store state is invalid")]
    InvalidState,
    #[error("replay-store key is invalid")]
    InvalidKey,
    #[error("replay-store I/O failed")]
    Io,
    #[error("replay storage is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("replay storage ownership, permissions, or file identity are unsafe")]
    UnsafeStorage,
    #[error(transparent)]
    InvalidBinding(#[from] LeaseBindingError),
    #[error(transparent)]
    Canonical(#[from] CanonicalJsonError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<ReplayStorageError> for ReplayStoreError {
    fn from(value: ReplayStorageError) -> Self {
        match value {
            ReplayStorageError::UnsupportedPlatform => Self::UnsupportedPlatform,
            ReplayStorageError::InvalidRoot => Self::InvalidRoot,
            ReplayStorageError::InvalidWorkspace => Self::InvalidWorkspace,
            ReplayStorageError::StorageOverlapsWorkspace => Self::StorageOverlapsWorkspace,
            ReplayStorageError::Missing => Self::MissingState,
            ReplayStorageError::SymlinkRejected => Self::SymlinkRejected,
            ReplayStorageError::TooLarge => Self::StateTooLarge,
            ReplayStorageError::LockUnavailable => Self::LockUnavailable,
            ReplayStorageError::InstanceAlreadyActive => Self::InstanceAlreadyActive,
            ReplayStorageError::InvalidFile
            | ReplayStorageError::UnsafePermissions
            | ReplayStorageError::IdentityChanged
            | ReplayStorageError::InvalidName => Self::UnsafeStorage,
            ReplayStorageError::Io => Self::Io,
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::lease::test_support::binding;
    use std::fs;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::thread;
    use tempfile::TempDir;

    fn bootstrap_store(
        root: impl AsRef<Path>,
        key: [u8; 32],
    ) -> Result<DurableReplayStore, ReplayStoreError> {
        let root = root.as_ref();
        let workspace = root
            .parent()
            .expect("test replay root has a parent")
            .join("workspace-boundary");
        fs::create_dir_all(&workspace).unwrap();
        DurableReplayStore::bootstrap(root, workspace, key)
    }

    fn reopen_store(
        root: impl AsRef<Path>,
        key: [u8; 32],
    ) -> Result<DurableReplayStore, ReplayStoreError> {
        let root = root.as_ref();
        let workspace = root
            .parent()
            .expect("test replay root has a parent")
            .join("workspace-boundary");
        DurableReplayStore::open_existing(root, workspace, key)
    }

    fn store() -> (TempDir, DurableReplayStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = bootstrap_store(temp.path().join("broker"), [7_u8; 32]).unwrap();
        assert_eq!(store.start_epoch().unwrap(), 1);
        (temp, store)
    }

    #[test]
    fn near_limit_state_reserves_worst_case_recovery_headroom() {
        let lease = binding();
        let (max_uses, _) = lease.constraints().uses.capacity.limits().unwrap();
        let mut uses = BTreeMap::new();
        for index in 0_u64..86_000 {
            uses.insert(format!("{index:064x}"), PersistedUseState::Active);
        }
        let mut state = PersistedState {
            store_id: "ab".repeat(STORE_ID_BYTES),
            broker_generation: 1,
            sequence: 1,
            ..PersistedState::default()
        };
        state.leases.insert(
            lease.lease_id().to_string(),
            PersistedLease {
                grant_id: lease.grant_id.clone(),
                action_id: lease.action_id.clone(),
                operation: lease.operation,
                canonical_args_sha256: lease.canonical_args_sha256.clone(),
                workspace_id: lease.expected_authority.workspace_id.clone(),
                workspace_manifest_sha256: lease
                    .expected_authority
                    .workspace_manifest_sha256
                    .clone(),
                policy_sha256: lease.expected_authority.policy_sha256.clone(),
                broker_generation: lease.broker_generation(),
                constraints: lease.constraints().clone(),
                remaining_uses: max_uses,
                uses,
                revoked: false,
            },
        );

        let key = [42_u8; 32];
        let current_len = authenticated_state_bytes(&state, &key).unwrap().len() as u64;
        let recovery_len = authenticated_state_bytes(&recovery_sized_state(&state).unwrap(), &key)
            .unwrap()
            .len() as u64;
        assert!(current_len < recovery_len);

        assert!(current_len <= MAX_STATE_BYTES);
        assert!(
            current_len > MAX_STATE_BYTES - (1024 * 1024),
            "current={current_len} recovery={recovery_len}"
        );
        assert!(recovery_len > MAX_STATE_BYTES);
        assert!(matches!(
            authenticated_state_bytes_with_limit(&state, &key, MAX_STATE_BYTES),
            Err(ReplayStoreError::StateTooLarge)
        ));
    }

    #[test]
    fn rejects_an_unprovisioned_zero_key() {
        let temp = tempfile::tempdir().unwrap();
        assert!(matches!(
            bootstrap_store(temp.path().join("broker"), [0_u8; 32]),
            Err(ReplayStoreError::InvalidKey)
        ));
    }

    #[test]
    fn replay_storage_and_workspace_must_not_overlap() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o755)).unwrap();
        let nested_root = workspace.join(".phantom-replay");
        assert!(matches!(
            DurableReplayStore::bootstrap(&nested_root, &workspace, [7_u8; 32]),
            Err(ReplayStoreError::StorageOverlapsWorkspace)
        ));
        assert!(
            !nested_root.exists(),
            "overlap rejection must not create the root"
        );

        assert!(matches!(
            DurableReplayStore::bootstrap(&workspace, &workspace, [7_u8; 32]),
            Err(ReplayStoreError::StorageOverlapsWorkspace)
        ));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(
            fs::metadata(&workspace).unwrap().permissions().mode() & 0o777,
            0o755,
            "equal-root rejection must not harden workspace permissions"
        );
        assert!(!workspace.join(STATE_FILE_NAME).exists());
        assert!(!workspace.join("replay-state.v2.lock").exists());

        let root = temp.path().join("broker");
        let nested_workspace = root.join("workspace");
        fs::create_dir_all(&nested_workspace).unwrap();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            DurableReplayStore::bootstrap(&root, &nested_workspace, [7_u8; 32]),
            Err(ReplayStoreError::StorageOverlapsWorkspace)
        ));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755,
            "nested-workspace rejection must not chmod the existing root"
        );
        assert!(!root.join(STATE_FILE_NAME).exists());
        assert!(!root.join("replay-state.v2.lock").exists());
    }

    fn nonce(byte: &str) -> Sha256Digest {
        byte.repeat(64).parse().unwrap()
    }

    #[test]
    fn exact_retry_is_idempotent_and_nonce_replay_is_rejected() {
        let (_temp, store) = store();
        let lease = binding();
        assert!(matches!(
            store.reserve(&nonce("a"), "request-1", &lease).unwrap(),
            ReplayReservation::New(_)
        ));
        assert!(matches!(
            store.reserve(&nonce("a"), "request-1", &lease).unwrap(),
            ReplayReservation::Existing(_)
        ));
        assert!(matches!(
            store.reserve(&nonce("a"), "request-2", &lease),
            Err(ReplayStoreError::Replay)
        ));
    }

    #[test]
    fn capacity_and_restart_revocation_are_durable() {
        let (temp, store) = store();
        let lease = binding();
        let lease_id = lease.lease_id().clone();
        store.reserve(&nonce("b"), "request-1", &lease).unwrap();
        let _permit = match store.begin_use(&lease_id, "operation-1", 10).unwrap() {
            ReplayUseReservation::New(permit) => permit,
            ReplayUseReservation::Existing(_) => panic!("first use must mint a permit"),
        };
        assert!(matches!(
            store.begin_use(&lease_id, "operation-1", 10).unwrap(),
            ReplayUseReservation::Existing(ReplayUseState::InProgress)
        ));
        assert!(matches!(
            store.begin_use(&lease_id, "operation-2", 10),
            Err(ReplayStoreError::CapacityExhausted)
        ));
        drop(store);

        let reopened = reopen_store(temp.path().join("broker"), [7_u8; 32]).unwrap();
        assert_eq!(reopened.start_epoch().unwrap(), 2);
        assert!(matches!(
            reopened.begin_use(&lease_id, "operation-2", 10),
            Err(ReplayStoreError::Revoked)
        ));
    }

    #[test]
    fn use_start_and_finish_retries_are_exactly_once() {
        let (_temp, store) = store();
        let mut lease = binding();
        lease.constraints.uses.capacity = UseCapacity::Bounded {
            max_uses: 2,
            max_concurrent_uses: 1,
        };
        let lease_id = lease.lease_id().clone();
        store.reserve(&nonce("d"), "request-1", &lease).unwrap();

        let permit1 = match store.begin_use(&lease_id, "operation-1", 10).unwrap() {
            ReplayUseReservation::New(permit) => permit,
            ReplayUseReservation::Existing(_) => panic!("first use must mint a permit"),
        };
        assert_eq!(permit1.lease_id(), &lease_id);
        assert_eq!(permit1.broker_generation(), 1);
        assert_eq!(permit1.action_id(), lease.action_id());
        assert_eq!(permit1.operation(), lease.operation());
        assert_eq!(
            permit1.canonical_args_sha256(),
            lease.canonical_args_sha256()
        );
        assert_eq!(permit1.workspace_id(), lease.workspace_id());
        assert_eq!(
            permit1.workspace_manifest_sha256(),
            lease.workspace_manifest_sha256()
        );
        assert_eq!(permit1.policy_sha256(), lease.policy_sha256());
        assert_eq!(permit1.constraints(), lease.constraints());
        assert!(matches!(
            store.begin_use(&lease_id, "operation-1", 10).unwrap(),
            ReplayUseReservation::Existing(ReplayUseState::InProgress)
        ));
        assert!(matches!(
            store.begin_use(&lease_id, "operation-2", 10),
            Err(ReplayStoreError::CapacityExhausted)
        ));
        assert!(matches!(
            store.begin_use(&lease_id, "operation-1", 10).unwrap(),
            ReplayUseReservation::Existing(ReplayUseState::InProgress)
        ));
        store.finish_use(&permit1).unwrap();
        store.finish_use(&permit1).unwrap();
        assert!(matches!(
            store.abandon_use(&permit1),
            Err(ReplayStoreError::OperationAlreadyTerminal)
        ));
        assert!(matches!(
            store.begin_use(&lease_id, "operation-1", 10).unwrap(),
            ReplayUseReservation::Existing(ReplayUseState::Finished)
        ));
        let permit2 = match store.begin_use(&lease_id, "operation-2", 10).unwrap() {
            ReplayUseReservation::New(permit) => permit,
            ReplayUseReservation::Existing(_) => panic!("second new use must mint a permit"),
        };
        store.abandon_use(&permit2).unwrap();
        store.abandon_use(&permit2).unwrap();
        assert!(matches!(
            store.begin_use(&lease_id, "operation-2", 10).unwrap(),
            ReplayUseReservation::Existing(ReplayUseState::Abandoned)
        ));

        let persisted =
            fs::read_to_string(_temp.path().join("broker").join(STATE_FILE_NAME)).unwrap();
        assert!(!persisted.contains("request-1"));
        assert!(!persisted.contains("operation-1"));
        assert!(!persisted.contains("operation-2"));
    }

    #[test]
    fn execution_permits_are_bound_to_one_store() {
        let first_root = tempfile::tempdir().unwrap();
        let second_root = tempfile::tempdir().unwrap();
        // Reusing a host key must not make two independent stores equivalent.
        let first = bootstrap_store(first_root.path().join("broker"), [1_u8; 32]).unwrap();
        let second = bootstrap_store(second_root.path().join("broker"), [1_u8; 32]).unwrap();
        first.start_epoch().unwrap();
        second.start_epoch().unwrap();
        let lease = binding();
        first.reserve(&nonce("1"), "request-1", &lease).unwrap();
        second.reserve(&nonce("2"), "request-2", &lease).unwrap();
        let permit = match first
            .begin_use(lease.lease_id(), "operation-1", 10)
            .unwrap()
        {
            ReplayUseReservation::New(permit) => permit,
            ReplayUseReservation::Existing(_) => panic!("first use must mint a permit"),
        };
        assert!(matches!(
            second.finish_use(&permit),
            Err(ReplayStoreError::ForeignPermit)
        ));
        first.finish_use(&permit).unwrap();
    }

    #[test]
    fn missing_state_never_bootstraps_implicitly() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("broker");
        let store = bootstrap_store(&root, [3_u8; 32]).unwrap();
        drop(store);
        fs::remove_file(root.join(STATE_FILE_NAME)).unwrap();

        assert!(matches!(
            reopen_store(&root, [3_u8; 32]),
            Err(ReplayStoreError::MissingState)
        ));
        // Explicit operator bootstrap is the only reset path.
        assert!(bootstrap_store(&root, [3_u8; 32]).is_ok());
    }

    #[test]
    fn activation_is_single_use_and_holds_a_process_lifetime_lock() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("broker");
        let first = bootstrap_store(&root, [4_u8; 32]).unwrap();
        let second = reopen_store(&root, [4_u8; 32]).unwrap();

        assert_eq!(first.start_epoch().unwrap(), 1);
        assert!(matches!(
            first.start_epoch(),
            Err(ReplayStoreError::AlreadyActive)
        ));
        assert!(matches!(
            second.start_epoch(),
            Err(ReplayStoreError::InstanceAlreadyActive)
        ));
        drop(first);
        assert_eq!(second.start_epoch().unwrap(), 2);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn ambiguous_activation_replace_failures_poison_without_retrying_generation() {
        for fault in [
            ReplaceFault::AfterRenameBeforeDirectorySync,
            ReplaceFault::AfterDirectorySync,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("broker");
            let store = bootstrap_store(&root, [4_u8; 32]).unwrap();
            store.storage.inject_replace_fault(fault);

            assert!(matches!(store.start_epoch(), Err(ReplayStoreError::Io)));
            let committed = read_authenticated_state(&store.storage, &store.key).unwrap();
            assert_eq!(committed.broker_generation, 1);
            assert!(matches!(
                store.start_epoch(),
                Err(ReplayStoreError::ActivationPoisoned)
            ));
            let after_retry = read_authenticated_state(&store.storage, &store.key).unwrap();
            assert_eq!(after_retry.broker_generation, 1);

            drop(store);
            let reopened = reopen_store(&root, [4_u8; 32]).unwrap();
            assert_eq!(reopened.start_epoch().unwrap(), 2);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn instance_lock_storage_and_transaction_errors_poison_activation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("instance-storage");
        let store = bootstrap_store(&root, [4_u8; 32]).unwrap();
        fs::write(root.join("replay-instance.v2.lock"), []).unwrap();
        fs::set_permissions(
            root.join("replay-instance.v2.lock"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            store.start_epoch(),
            Err(ReplayStoreError::UnsafeStorage)
        ));
        fs::set_permissions(
            root.join("replay-instance.v2.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            store.start_epoch(),
            Err(ReplayStoreError::ActivationPoisoned)
        ));
        assert_eq!(
            read_authenticated_state(&store.storage, &store.key)
                .unwrap()
                .broker_generation,
            0
        );

        let transaction_root = temp.path().join("transaction-storage");
        let transaction_store = bootstrap_store(&transaction_root, [4_u8; 32]).unwrap();
        fs::set_permissions(
            transaction_root.join("replay-state.v2.lock"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            transaction_store.start_epoch(),
            Err(ReplayStoreError::UnsafeStorage)
        ));
        fs::set_permissions(
            transaction_root.join("replay-state.v2.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            transaction_store.start_epoch(),
            Err(ReplayStoreError::ActivationPoisoned)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn retained_root_descriptor_survives_ancestor_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("broker");
        let moved = temp.path().join("broker-original");
        let store = bootstrap_store(&root, [5_u8; 32]).unwrap();
        store.start_epoch().unwrap();

        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        store
            .reserve(&nonce("5"), "request-after-swap", &binding())
            .unwrap();

        assert!(moved.join(STATE_FILE_NAME).is_file());
        assert!(!root.join(STATE_FILE_NAME).exists());
        let persisted = fs::read_to_string(moved.join(STATE_FILE_NAME)).unwrap();
        assert!(!persisted.contains("request-after-swap"));
    }

    fn permit_for(
        store: &DurableReplayStore,
        lease: &LeaseBinding,
        operation: &str,
    ) -> Box<ExecutionPermit> {
        match store.begin_use(lease.lease_id(), operation, 10).unwrap() {
            ReplayUseReservation::New(permit) => permit,
            ReplayUseReservation::Existing(_) => panic!("expected a new use"),
        }
    }

    #[test]
    fn two_phase_completion_is_exact_resumable_and_conflict_safe() {
        let (_temp, store) = store();
        let mut lease = binding();
        lease.constraints.uses.capacity = UseCapacity::Bounded {
            max_uses: 2,
            max_concurrent_uses: 2,
        };
        store
            .reserve(&nonce("6"), "request-terminal", &lease)
            .unwrap();
        let permit = permit_for(&store, &lease, "operation-terminal");
        let digest: Sha256Digest = "61".repeat(32).parse().unwrap();
        let other: Sha256Digest = "62".repeat(32).parse().unwrap();

        let first = match store
            .begin_completion(&permit, &digest, TerminalDisposition::Finished)
            .unwrap()
        {
            ReplayCompletionReservation::New(witness) => witness,
            _ => panic!("first completion must be new"),
        };
        assert!(matches!(
            store
                .begin_use(lease.lease_id(), "operation-terminal", 10)
                .unwrap(),
            ReplayUseReservation::Existing(ReplayUseState::Completing)
        ));
        // Simulate losing the first response/witness before terminal commit.
        drop(first);
        let resumed = match store
            .begin_completion(&permit, &digest, TerminalDisposition::Finished)
            .unwrap()
        {
            ReplayCompletionReservation::Resumed(witness) => witness,
            _ => panic!("an exact pending retry must resume"),
        };
        assert!(matches!(
            store.begin_completion(&permit, &other, TerminalDisposition::Finished),
            Err(ReplayStoreError::CompletionConflict)
        ));
        assert!(matches!(
            store.begin_completion(&permit, &digest, TerminalDisposition::Abandoned),
            Err(ReplayStoreError::CompletionConflict)
        ));
        store.commit_completion(&resumed).unwrap();
        store.commit_completion(&resumed).unwrap();
        assert!(matches!(
            store
                .begin_completion(&permit, &digest, TerminalDisposition::Finished)
                .unwrap(),
            ReplayCompletionReservation::Existing(ReplayUseState::Finished)
        ));
        assert!(matches!(
            store.begin_completion(&permit, &digest, TerminalDisposition::Abandoned),
            Err(ReplayStoreError::CompletionConflict)
        ));

        let abandoned = permit_for(&store, &lease, "operation-abandoned");
        let abandoned_digest: Sha256Digest = "63".repeat(32).parse().unwrap();
        let witness = match store
            .begin_completion(
                &abandoned,
                &abandoned_digest,
                TerminalDisposition::Abandoned,
            )
            .unwrap()
        {
            ReplayCompletionReservation::New(witness) => witness,
            _ => panic!("abandonment completion must be new"),
        };
        store.commit_completion(&witness).unwrap();
        assert!(matches!(
            store
                .begin_use(lease.lease_id(), "operation-abandoned", 10)
                .unwrap(),
            ReplayUseReservation::Existing(ReplayUseState::Abandoned)
        ));
    }

    #[test]
    fn pending_completion_survives_restart_and_can_only_resume_exactly() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("broker");
        let store = bootstrap_store(&root, [9_u8; 32]).unwrap();
        store.start_epoch().unwrap();
        let lease = binding();
        store.reserve(&nonce("9"), "request-crash", &lease).unwrap();
        let permit = permit_for(&store, &lease, "operation-crash");
        let digest: Sha256Digest = "91".repeat(32).parse().unwrap();
        let wrong: Sha256Digest = "92".repeat(32).parse().unwrap();
        let witness = match store
            .begin_completion(&permit, &digest, TerminalDisposition::Finished)
            .unwrap()
        {
            ReplayCompletionReservation::New(witness) => witness,
            _ => panic!("completion must start"),
        };
        drop(witness);
        drop(permit);
        drop(store);

        let reopened = reopen_store(&root, [9_u8; 32]).unwrap();
        assert_eq!(reopened.start_epoch().unwrap(), 2);
        assert!(matches!(
            reopened.resume_completion(
                lease.lease_id(),
                "operation-crash",
                &wrong,
                TerminalDisposition::Finished,
            ),
            Err(ReplayStoreError::CompletionConflict)
        ));
        let resumed = match reopened
            .resume_completion(
                lease.lease_id(),
                "operation-crash",
                &digest,
                TerminalDisposition::Finished,
            )
            .unwrap()
        {
            ReplayCompletionReservation::Resumed(witness) => witness,
            _ => panic!("exact crash recovery must resume"),
        };
        reopened.commit_completion(&resumed).unwrap();
        assert!(matches!(
            reopened
                .resume_completion(
                    lease.lease_id(),
                    "operation-crash",
                    &digest,
                    TerminalDisposition::Finished,
                )
                .unwrap(),
            ReplayCompletionReservation::Existing(ReplayUseState::Finished)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn unsafe_state_and_lock_files_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("broker");
        let store = bootstrap_store(&root, [6_u8; 32]).unwrap();
        drop(store);

        fs::set_permissions(
            root.join(STATE_FILE_NAME),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            reopen_store(&root, [6_u8; 32]),
            Err(ReplayStoreError::UnsafeStorage)
        ));
        fs::set_permissions(
            root.join(STATE_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        fs::set_permissions(
            root.join("replay-state.v2.lock"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(matches!(
            reopen_store(&root, [6_u8; 32]),
            Err(ReplayStoreError::UnsafeStorage)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn hardlinked_state_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("broker");
        let store = bootstrap_store(&root, [8_u8; 32]).unwrap();
        drop(store);
        fs::hard_link(
            root.join(STATE_FILE_NAME),
            temp.path().join("state-hardlink"),
        )
        .unwrap();
        assert!(matches!(
            reopen_store(&root, [8_u8; 32]),
            Err(ReplayStoreError::UnsafeStorage)
        ));
    }

    #[test]
    fn concurrent_nonce_consumption_creates_one_lease() {
        let (_temp, store) = store();
        let store = Arc::new(store);
        let handles = (0..24)
            .map(|index| {
                let store = Arc::clone(&store);
                let mut lease = binding();
                lease.lease_id = format!("lea_{index:032x}").parse().unwrap();
                thread::spawn(move || {
                    store.reserve(&nonce("c"), &format!("request-{index}"), &lease)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(ReplayReservation::New(_))))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ReplayStoreError::Replay)))
                .count(),
            23
        );
    }

    #[test]
    fn tamper_truncation_wrong_key_and_symlink_fail_closed() {
        let (temp, store) = store();
        drop(store);
        let root = temp.path().join("broker");
        let path = root.join(STATE_FILE_NAME);
        let mut bytes = fs::read(&path).unwrap();
        let midpoint = bytes.len() / 2;
        bytes[midpoint] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            reopen_store(&root, [7_u8; 32]),
            Err(ReplayStoreError::InvalidState | ReplayStoreError::AuthenticationFailed)
        ));

        fs::write(&path, b"{").unwrap();
        assert!(matches!(
            reopen_store(&root, [7_u8; 32]),
            Err(ReplayStoreError::InvalidState)
        ));

        let clean_root = temp.path().join("clean");
        bootstrap_store(&clean_root, [8_u8; 32]).unwrap();
        assert!(matches!(
            reopen_store(&clean_root, [9_u8; 32]),
            Err(ReplayStoreError::AuthenticationFailed)
        ));

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let link = temp.path().join("linked");
            std::os::unix::fs::symlink(&clean_root, &link).unwrap();
            assert!(matches!(
                reopen_store(link, [8_u8; 32]),
                Err(ReplayStoreError::SymlinkRejected)
            ));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn state_directory_and_files_are_private() {
        let (temp, store) = store();
        drop(store);
        let root = temp.path().join("broker");
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join(STATE_FILE_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join("replay-state.v2.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "macos"))))]
mod unsupported_platform_tests {
    use super::*;

    #[test]
    fn durable_replay_storage_fails_closed_on_unsupported_platforms() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        assert!(matches!(
            DurableReplayStore::bootstrap(temp.path().join("broker"), workspace, [7_u8; 32]),
            Err(ReplayStoreError::UnsupportedPlatform)
        ));
    }
}
