//! Correlated, value-free execution evidence for Phantom.
//!
//! This crate is intentionally disconnected from execution. It cannot grant
//! authority, activate a lease, inject a credential, or run a worker. It only
//! records closed metadata supplied by those future boundaries. The default
//! signing boundary is [`SigningBoundary::NoVerifiedSigner`], so locally
//! HMAC-protected receipts remain explicitly unsigned and untrusted.
//! Canonical bytes use Phantom's local `canonical_json_v1` format; they are not
//! an RFC 8785/JCS or cross-repository Phantom-Locus signature contract.
//!
//! # Security boundary and current limits
//!
//! The private local HMAC chain detects corruption and modification by actors
//! that do not possess the per-user integrity key. It is not a signature and
//! cannot establish trust against a fully compromised same-user account. A
//! truncated crash tail fails closed and requires operator recovery; this crate
//! does not guess whether a partial event took effect. No execution component
//! is wired to this store yet, no accepting signer ships in production, and no
//! durable execution descriptor or host rollback anchor is persisted here.

use fs2::FileExt;
use hmac::{Hmac, Mac};
use phantom_authority::{
    canonical_json_v1, ActionId, GrantId, InstallationId, LeaseId, SessionId, Sha256Digest,
    WorkspaceId,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

const SCHEMA_VERSION: u8 = 1;
const EVIDENCE_DIR: &str = "evidence";
const LOCK_FILE: &str = "evidence.lock";
const KEY_FILE: &str = "evidence-integrity.key";
const GENESIS_MAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RECORD_MAC_DOMAIN: &[u8] = b"phantom.execution-evidence.record.v1\0";
const RECEIPT_MAC_DOMAIN: &[u8] = b"phantom.execution-evidence.receipt.v1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"phantom.execution-evidence.payload-digest.v1\0";
const SIGNING_ASSERTION_DOMAIN: &[u8] = b"phantom.execution-evidence.signing-assertion.v1\0";
const EVENT_DIGEST_DOMAIN: &[u8] = b"phantom.execution-evidence.event.v1\0";
const APPEND_WITNESS_DOMAIN: &[u8] = b"phantom.execution-evidence.append-witness.v1\0";
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
const MAX_KEY_BYTES: u64 = 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOnceResult {
    New {
        sequence: u64,
        event_digest: Sha256Digest,
        /// Binds the session, sequence, and authenticated durable record MAC.
        record_witness: Sha256Digest,
    },
    Existing {
        sequence: u64,
        event_digest: Sha256Digest,
        /// Binds the session, sequence, and authenticated durable record MAC.
        record_witness: Sha256Digest,
    },
}

/// A closed, value-free execution event. No variant accepts arbitrary text,
/// request bodies, argv, environment values, URLs, or secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceEvent {
    SessionStarted {
        workspace_id: WorkspaceId,
        action_id: ActionId,
        intent_digest: Sha256Digest,
    },
    AuthorityDecision {
        decision: AuthorityDecision,
    },
    LeaseBound {
        grant_id: GrantId,
        grant_digest: Sha256Digest,
        lease_id: LeaseId,
        lease_digest: Sha256Digest,
    },
    ProxyUseAggregate {
        lease_id: LeaseId,
        attempted_requests: u64,
        forwarded_requests: u64,
        denied_requests: u64,
        request_bytes: u64,
        response_bytes: u64,
    },
    WorkerCompleted {
        result: WorkerResult,
        result_digest: Option<Sha256Digest>,
    },
    RollbackCompleted {
        result: RollbackResult,
        rollback_digest: Option<Sha256Digest>,
    },
    FinalOutcome {
        outcome: FinalOutcome,
        outcome_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityDecision {
    Denied {
        authority_digest: Sha256Digest,
        reason: AuthorityDenial,
    },
    Granted {
        authority_digest: Sha256Digest,
        grant_id: GrantId,
        grant_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityDenial {
    NoVerifier,
    InvalidIntent,
    InsufficientAuthority,
    Expired,
    Revoked,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerResult {
    Succeeded,
    Failed,
    TimedOut,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackResult {
    Applied,
    Failed,
    NotRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalOutcome {
    Succeeded,
    Denied,
    Failed,
    TimedOut,
    Revoked,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPayload {
    pub schema_version: u8,
    pub session_id: SessionId,
    pub event_count: u64,
    pub chain_head: Sha256Digest,
    pub summary: EvidenceSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSummary {
    pub workspace_id: Option<WorkspaceId>,
    pub action_id: Option<ActionId>,
    pub intent_digest: Option<Sha256Digest>,
    pub authority_digest: Option<Sha256Digest>,
    pub authority_denial: Option<AuthorityDenial>,
    pub grant_id: Option<GrantId>,
    pub grant_digest: Option<Sha256Digest>,
    pub lease_id: Option<LeaseId>,
    pub lease_digest: Option<Sha256Digest>,
    pub proxy_use: ProxyUseTotals,
    pub worker_result: Option<WorkerResult>,
    pub worker_result_digest: Option<Sha256Digest>,
    pub rollback_result: Option<RollbackResult>,
    pub rollback_digest: Option<Sha256Digest>,
    pub final_outcome: Option<FinalOutcome>,
    pub final_outcome_digest: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyUseTotals {
    pub aggregates: u64,
    pub attempted_requests: u64,
    pub forwarded_requests: u64,
    pub denied_requests: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
}

/// Explicit trust state. Local integrity does not imply external trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptTrustState {
    UnsignedUntrusted,
    /// A caller-supplied signer signed and self-checked the digest. Phantom has
    /// not anchored the signer to a trusted registry or external authority.
    CallerAsserted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ReceiptTrust {
    UnsignedUntrusted,
    CallerAsserted {
        signer_id: InstallationId,
        algorithm: CallerAssertedSignatureAlgorithm,
        signature_hex: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CallerAssertedSignatureAlgorithm {
    DigestSignature64V1,
}

const CALLER_ASSERTED_ALGORITHM: CallerAssertedSignatureAlgorithm =
    CallerAssertedSignatureAlgorithm::DigestSignature64V1;

/// A reconstructed canonical session receipt. This type is intentionally not
/// deserializable: a caller cannot turn untrusted JSON into a caller assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionReceipt {
    pub payload: ReceiptPayload,
    pub payload_digest: Sha256Digest,
    pub local_integrity_mac: Sha256Digest,
    trust: ReceiptTrust,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSessionReceipt {
    payload: ReceiptPayload,
    payload_digest: Sha256Digest,
    local_integrity_mac: Sha256Digest,
    trust: ReceiptTrust,
}

impl From<StoredSessionReceipt> for SessionReceipt {
    fn from(stored: StoredSessionReceipt) -> Self {
        Self {
            payload: stored.payload,
            payload_digest: stored.payload_digest,
            local_integrity_mac: stored.local_integrity_mac,
            trust: stored.trust,
        }
    }
}

impl SessionReceipt {
    pub fn trust_state(&self) -> ReceiptTrustState {
        match self.trust {
            ReceiptTrust::UnsignedUntrusted => ReceiptTrustState::UnsignedUntrusted,
            ReceiptTrust::CallerAsserted { .. } => ReceiptTrustState::CallerAsserted,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EvidenceError> {
        Ok(canonical_json_v1(self)?)
    }
}

/// A signer is supplied by the caller and is not a Phantom trust root. This
/// crate ships no accepting production implementation. The same implementation
/// self-checks the exact digest it signed, which detects signer malfunction but
/// does not establish external trust.
pub trait EvidenceSigner: Send + Sync {
    fn signer_id(&self) -> InstallationId;
    fn sign(&self, digest: &Sha256Digest) -> Result<[u8; 64], SignerError>;
    fn verify(&self, digest: &Sha256Digest, signature: &[u8; 64]) -> bool;
}

#[derive(Clone, Copy, Default)]
pub enum SigningBoundary<'a> {
    #[default]
    NoVerifiedSigner,
    CallerAsserted(&'a dyn EvidenceSigner),
}

/// Production-safe placeholder that never signs or verifies evidence.
#[derive(Debug, Default)]
pub struct DenyAllEvidenceSigner;

impl EvidenceSigner for DenyAllEvidenceSigner {
    fn signer_id(&self) -> InstallationId {
        "ins_00000000000000000000000000000000"
            .parse()
            .expect("static signer id is valid")
    }

    fn sign(&self, _digest: &Sha256Digest) -> Result<[u8; 64], SignerError> {
        Err(SignerError::Denied)
    }

    fn verify(&self, _digest: &Sha256Digest, _signature: &[u8; 64]) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    #[error("evidence signing denied")]
    Denied,
    #[error("evidence signer unavailable")]
    Unavailable,
}

/// Private, crash-durable store rooted under `<home>/.phantom/evidence`.
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    phantom_home: PathBuf,
    evidence_dir: PathBuf,
    lock_path: PathBuf,
    key_path: PathBuf,
    log_path: PathBuf,
    session_id: SessionId,
}

impl EvidenceStore {
    /// Provision or harden local evidence storage and open it for normal use.
    ///
    /// This is intentionally not a read-only verification entrypoint: it may
    /// create private directories, the lock, or the integrity key and may
    /// tighten their modes. Once a store is open, `verify_local_receipt` uses a
    /// separate existing-files-only path that performs no such mutation.
    pub fn open(
        home_dir: &Path,
        workspace_root: &Path,
        session_id: SessionId,
    ) -> Result<Self, EvidenceError> {
        ensure_existing_private_root(home_dir)?;
        let workspace = workspace_root
            .canonicalize()
            .map_err(|_| EvidenceError::InvalidStorageBoundary)?;
        let phantom_home = ensure_child_private_dir(home_dir, ".phantom")?;
        let evidence_dir = ensure_child_private_dir(&phantom_home, EVIDENCE_DIR)?;
        let evidence_canonical = evidence_dir
            .canonicalize()
            .map_err(|_| EvidenceError::InvalidStorageBoundary)?;
        if evidence_canonical.starts_with(&workspace) || workspace.starts_with(&evidence_canonical)
        {
            return Err(EvidenceError::StorageInsideWorkspace);
        }

        let store = Self {
            lock_path: phantom_home.join(LOCK_FILE),
            key_path: phantom_home.join(KEY_FILE),
            log_path: evidence_dir.join(format!("{}.jsonl", session_id.as_str())),
            phantom_home,
            evidence_dir,
            session_id,
        };
        let lock = store.acquire_lock()?;
        let _key = store.load_or_create_key_locked()?;
        drop(lock);
        Ok(store)
    }

    pub fn append(&self, event: EvidenceEvent) -> Result<u64, EvidenceError> {
        self.append_internal(event, None)
    }

    /// Append exactly one event at `expected_sequence`.
    ///
    /// The idempotency binding is the internally recomputed, domain-separated
    /// canonical event digest. Retrying the same event at the same sequence
    /// returns `Existing`; reusing the sequence for different evidence fails.
    pub fn append_once(
        &self,
        expected_sequence: u64,
        event: EvidenceEvent,
    ) -> Result<AppendOnceResult, EvidenceError> {
        let lock = self.acquire_lock()?;
        let key = self.load_existing_key_locked()?;
        let records = self.load_records_locked(&key)?;
        let index =
            usize::try_from(expected_sequence).map_err(|_| EvidenceError::UnexpectedSequence)?;
        let requested_digest = event_digest(&event)?;
        if index < records.len() {
            let existing_digest = event_digest(&records[index].event)?;
            if existing_digest != requested_digest || records[index].event != event {
                return Err(EvidenceError::IdempotencyConflict);
            }
            drop(lock);
            return Ok(AppendOnceResult::Existing {
                sequence: expected_sequence,
                event_digest: requested_digest,
                record_witness: append_witness(
                    &self.session_id,
                    expected_sequence,
                    &records[index].mac,
                )?,
            });
        }
        if index != records.len() {
            return Err(EvidenceError::UnexpectedSequence);
        }
        let observed_at_unix_ms = unix_millis()?;
        let (sequence, appended_digest, record_witness) =
            self.append_new_locked(&key, &records, event, observed_at_unix_ms)?;
        drop(lock);
        Ok(AppendOnceResult::New {
            sequence,
            event_digest: appended_digest,
            record_witness,
        })
    }

    pub fn event_count(&self) -> Result<u64, EvidenceError> {
        let lock = self.acquire_lock()?;
        let key = self.load_existing_key_locked()?;
        let records = self.load_records_locked(&key)?;
        drop(lock);
        u64::try_from(records.len()).map_err(|_| EvidenceError::SequenceExhausted)
    }

    pub fn receipt(&self, boundary: SigningBoundary<'_>) -> Result<SessionReceipt, EvidenceError> {
        let lock = self.acquire_lock()?;
        let key = self.load_existing_key_locked()?;
        let records = self.load_records_locked(&key)?;
        let mut receipt = self.rebuild_unsigned_receipt_locked(&key, &records)?;
        if let SigningBoundary::CallerAsserted(signer) = boundary {
            let signer_id = signer.signer_id();
            if let Some(existing) =
                self.load_existing_asserted_receipt_locked(&receipt, &signer_id, signer)?
            {
                drop(lock);
                return Ok(existing);
            }
            let signing_digest = signing_assertion_digest(&receipt.payload_digest, &signer_id)?;
            let mut signature = signer.sign(&signing_digest)?;
            if !signer.verify(&signing_digest, &signature) {
                signature.zeroize();
                return Err(EvidenceError::UnverifiedSignature);
            }
            let signature_hex = hex::encode(signature);
            signature.zeroize();
            receipt.trust = ReceiptTrust::CallerAsserted {
                signer_id,
                algorithm: CALLER_ASSERTED_ALGORITHM,
                signature_hex,
            };
        }
        self.persist_receipt_locked(&receipt)?;
        drop(lock);
        Ok(receipt)
    }

    fn rebuild_unsigned_receipt_locked(
        &self,
        key: &IntegrityKey,
        records: &[LogRecord],
    ) -> Result<SessionReceipt, EvidenceError> {
        let state = replay(&self.session_id, records)?;
        if !state.finalized {
            return Err(EvidenceError::SessionNotFinalized);
        }
        let event_count =
            u64::try_from(records.len()).map_err(|_| EvidenceError::SequenceExhausted)?;
        let chain_head = records
            .last()
            .map(|record| record.mac.clone())
            .ok_or(EvidenceError::SessionNotStarted)?;
        let payload = ReceiptPayload {
            schema_version: SCHEMA_VERSION,
            session_id: self.session_id.clone(),
            event_count,
            chain_head,
            summary: state.summary,
        };
        let payload_bytes = canonical_json_v1(&payload)?;
        let payload_digest = sha256_domain_digest(RECEIPT_DIGEST_DOMAIN, &payload_bytes);
        let local_integrity_mac = compute_mac(key, RECEIPT_MAC_DOMAIN, &payload_bytes)?;
        Ok(SessionReceipt {
            payload,
            payload_digest,
            local_integrity_mac,
            trust: ReceiptTrust::UnsignedUntrusted,
        })
    }

    pub fn verify_local_receipt(&self, receipt: &SessionReceipt) -> Result<(), EvidenceError> {
        let lock = self.acquire_existing_read_lock()?;
        let key = self.load_existing_key_readonly()?;
        let records = self.load_records_readonly(&key)?;
        let rebuilt = self.rebuild_unsigned_receipt_locked(&key, &records)?;
        if receipt.payload != rebuilt.payload
            || receipt.payload_digest != rebuilt.payload_digest
            || receipt.local_integrity_mac != rebuilt.local_integrity_mac
        {
            return Err(EvidenceError::Tampered);
        }
        drop(lock);
        Ok(())
    }

    #[cfg(test)]
    fn append_at(
        &self,
        event: EvidenceEvent,
        observed_at_unix_ms: u64,
    ) -> Result<u64, EvidenceError> {
        self.append_internal(event, Some(observed_at_unix_ms))
    }

    fn append_internal(
        &self,
        event: EvidenceEvent,
        observed_at_unix_ms: Option<u64>,
    ) -> Result<u64, EvidenceError> {
        let lock = self.acquire_lock()?;
        let observed_at_unix_ms = observed_at_unix_ms.map_or_else(unix_millis, Ok)?;
        let key = self.load_existing_key_locked()?;
        let records = self.load_records_locked(&key)?;
        let (sequence, _, _) =
            self.append_new_locked(&key, &records, event, observed_at_unix_ms)?;
        drop(lock);
        Ok(sequence)
    }

    fn append_new_locked(
        &self,
        key: &IntegrityKey,
        records: &[LogRecord],
        event: EvidenceEvent,
        observed_at_unix_ms: u64,
    ) -> Result<(u64, Sha256Digest, Sha256Digest), EvidenceError> {
        let state = replay(&self.session_id, records)?;
        state.validate_next(&event, observed_at_unix_ms)?;
        ensure_record_capacity(records.len())?;
        let event_digest = event_digest(&event)?;
        let sequence =
            u64::try_from(records.len()).map_err(|_| EvidenceError::SequenceExhausted)?;
        let previous_mac = records
            .last()
            .map(|record| record.mac.clone())
            .unwrap_or_else(|| GENESIS_MAC.parse().expect("genesis digest is valid"));
        let unsigned = UnsignedRecord {
            schema_version: SCHEMA_VERSION,
            session_id: &self.session_id,
            sequence,
            observed_at_unix_ms,
            event: &event,
            previous_mac: &previous_mac,
        };
        let unsigned_bytes = canonical_json_v1(&unsigned)?;
        let mac = compute_mac(key, RECORD_MAC_DOMAIN, &unsigned_bytes)?;
        let record_witness = append_witness(&self.session_id, sequence, &mac)?;
        let record = LogRecord {
            schema_version: SCHEMA_VERSION,
            session_id: self.session_id.clone(),
            sequence,
            observed_at_unix_ms,
            event,
            previous_mac,
            mac,
        };
        let mut line = canonical_json_v1(&record)?;
        line.push(b'\n');
        self.append_line_locked(&line)?;
        Ok((sequence, event_digest, record_witness))
    }

    fn acquire_lock(&self) -> Result<File, EvidenceError> {
        let lock = open_private_file(&self.lock_path, true, true, false)?;
        lock.lock_exclusive()?;
        Ok(lock)
    }

    fn acquire_existing_read_lock(&self) -> Result<File, EvidenceError> {
        let lock = open_existing_private_readonly(&self.lock_path)?;
        FileExt::lock_shared(&lock)?;
        Ok(lock)
    }

    fn load_or_create_key_locked(&self) -> Result<IntegrityKey, EvidenceError> {
        match read_private_file_bounded(&self.key_path, MAX_KEY_BYTES) {
            Ok(bytes) => parse_key(bytes),
            Err(EvidenceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut raw = Zeroizing::new([0_u8; 32]);
                rand::thread_rng().fill_bytes(raw.as_mut());
                let key = validated_integrity_key(*raw)?;
                let encoded = Zeroizing::new(hex::encode(key.0.as_ref()));
                let mut file = open_private_file(&self.key_path, true, false, true)?;
                file.write_all(encoded.as_bytes())?;
                file.sync_all()?;
                sync_dir(&self.phantom_home)?;
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }

    fn load_existing_key_locked(&self) -> Result<IntegrityKey, EvidenceError> {
        parse_key(read_private_file_bounded(&self.key_path, MAX_KEY_BYTES)?)
    }

    fn load_existing_key_readonly(&self) -> Result<IntegrityKey, EvidenceError> {
        parse_key(read_existing_private_file_bounded(
            &self.key_path,
            MAX_KEY_BYTES,
        )?)
    }

    fn load_records_locked(&self, key: &IntegrityKey) -> Result<Vec<LogRecord>, EvidenceError> {
        let bytes = match read_private_file_bounded(&self.log_path, MAX_LOG_BYTES) {
            Ok(bytes) => bytes,
            Err(EvidenceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new())
            }
            Err(error) => return Err(error),
        };
        self.decode_records(key, &bytes)
    }

    fn load_records_readonly(&self, key: &IntegrityKey) -> Result<Vec<LogRecord>, EvidenceError> {
        let bytes = read_existing_private_file_bounded(&self.log_path, MAX_LOG_BYTES)?;
        self.decode_records(key, &bytes)
    }

    fn decode_records(
        &self,
        key: &IntegrityKey,
        bytes: &[u8],
    ) -> Result<Vec<LogRecord>, EvidenceError> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        if bytes.last() != Some(&b'\n') {
            return Err(EvidenceError::Truncated);
        }

        let mut records = Vec::new();
        let mut expected_previous: Sha256Digest = GENESIS_MAC.parse().expect("valid genesis");
        for (index, line) in bytes[..bytes.len() - 1]
            .split(|byte| *byte == b'\n')
            .enumerate()
        {
            if index >= MAX_RECORDS {
                return Err(EvidenceError::RecordLimitExceeded);
            }
            if line.is_empty() {
                return Err(EvidenceError::Truncated);
            }
            let record: LogRecord =
                serde_json::from_slice(line).map_err(|_| EvidenceError::Tampered)?;
            if canonical_json_v1(&record)? != line {
                return Err(EvidenceError::NonCanonical);
            }
            let expected_sequence =
                u64::try_from(index).map_err(|_| EvidenceError::SequenceExhausted)?;
            if record.schema_version != SCHEMA_VERSION
                || record.session_id != self.session_id
                || record.sequence != expected_sequence
                || record.previous_mac != expected_previous
            {
                return Err(EvidenceError::ReplayOrSequence);
            }
            let unsigned = UnsignedRecord {
                schema_version: record.schema_version,
                session_id: &record.session_id,
                sequence: record.sequence,
                observed_at_unix_ms: record.observed_at_unix_ms,
                event: &record.event,
                previous_mac: &record.previous_mac,
            };
            let unsigned_bytes = canonical_json_v1(&unsigned)?;
            verify_mac(key, RECORD_MAC_DOMAIN, &unsigned_bytes, &record.mac)?;
            expected_previous = record.mac.clone();
            records.push(record);
        }
        replay(&self.session_id, &records)?;
        Ok(records)
    }

    fn append_line_locked(&self, line: &[u8]) -> Result<(), EvidenceError> {
        let created = std::fs::symlink_metadata(&self.log_path).is_err();
        let mut file = open_private_file(&self.log_path, true, true, false)?;
        if !file.metadata()?.is_file() {
            return Err(EvidenceError::UnsafeStorage);
        }
        let new_len = file
            .metadata()?
            .len()
            .checked_add(u64::try_from(line.len()).map_err(|_| EvidenceError::LogTooLarge)?)
            .ok_or(EvidenceError::LogTooLarge)?;
        if new_len > MAX_LOG_BYTES {
            return Err(EvidenceError::LogTooLarge);
        }
        file.write_all(line)?;
        file.sync_all()?;
        if created {
            sync_dir(&self.evidence_dir)?;
        }
        Ok(())
    }

    fn caller_asserted_receipt_path(&self, signer_id: &InstallationId) -> PathBuf {
        self.evidence_dir.join(format!(
            "{}.receipt.{}.json",
            self.session_id.as_str(),
            signer_id.as_str()
        ))
    }

    fn load_existing_asserted_receipt_locked(
        &self,
        expected: &SessionReceipt,
        signer_id: &InstallationId,
        signer: &dyn EvidenceSigner,
    ) -> Result<Option<SessionReceipt>, EvidenceError> {
        let path = self.caller_asserted_receipt_path(signer_id);
        let bytes = match read_private_file_bounded(&path, MAX_LOG_BYTES) {
            Ok(bytes) => bytes,
            Err(EvidenceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let stored: StoredSessionReceipt =
            serde_json::from_slice(&bytes).map_err(|_| EvidenceError::Tampered)?;
        if canonical_json_v1(&stored)? != bytes {
            return Err(EvidenceError::NonCanonical);
        }
        let receipt = SessionReceipt::from(stored);
        if receipt.payload != expected.payload
            || receipt.payload_digest != expected.payload_digest
            || receipt.local_integrity_mac != expected.local_integrity_mac
        {
            return Err(EvidenceError::ReceiptConflict);
        }
        let signature_hex = match &receipt.trust {
            ReceiptTrust::CallerAsserted {
                signer_id: stored_signer_id,
                algorithm,
                signature_hex,
            } if stored_signer_id == signer_id && *algorithm == CALLER_ASSERTED_ALGORITHM => {
                signature_hex
            }
            _ => return Err(EvidenceError::ReceiptConflict),
        };
        let signature_bytes = hex::decode(signature_hex).map_err(|_| EvidenceError::Tampered)?;
        let signature: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| EvidenceError::Tampered)?;
        let signing_digest = signing_assertion_digest(&receipt.payload_digest, signer_id)?;
        if !signer.verify(&signing_digest, &signature) {
            return Err(EvidenceError::ReceiptConflict);
        }
        Ok(Some(receipt))
    }

    fn persist_receipt_locked(&self, receipt: &SessionReceipt) -> Result<(), EvidenceError> {
        let suffix = match &receipt.trust {
            ReceiptTrust::UnsignedUntrusted => "unsigned".to_owned(),
            ReceiptTrust::CallerAsserted { signer_id, .. } => signer_id.as_str().to_owned(),
        };
        let path = self.evidence_dir.join(format!(
            "{}.receipt.{suffix}.json",
            self.session_id.as_str()
        ));
        let bytes = receipt.canonical_bytes()?;
        if matches!(&receipt.trust, ReceiptTrust::CallerAsserted { .. }) {
            match read_private_file_bounded(&path, MAX_LOG_BYTES) {
                Ok(existing) if existing == bytes => return Ok(()),
                Ok(_) => return Err(EvidenceError::ReceiptConflict),
                Err(EvidenceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        atomic_private_write(&path, &bytes)?;
        sync_dir(&self.evidence_dir)
    }
}

struct IntegrityKey(Zeroizing<[u8; 32]>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogRecord {
    schema_version: u8,
    session_id: SessionId,
    sequence: u64,
    observed_at_unix_ms: u64,
    event: EvidenceEvent,
    previous_mac: Sha256Digest,
    mac: Sha256Digest,
}

#[derive(Serialize)]
struct UnsignedRecord<'a> {
    schema_version: u8,
    session_id: &'a SessionId,
    sequence: u64,
    observed_at_unix_ms: u64,
    event: &'a EvidenceEvent,
    previous_mac: &'a Sha256Digest,
}

#[derive(Default)]
struct ReplayState {
    summary: EvidenceSummary,
    last_timestamp: Option<u64>,
    started: bool,
    authority_decided: bool,
    authority_granted: bool,
    lease_bound: bool,
    worker_completed: bool,
    rollback_completed: bool,
    finalized: bool,
}

impl ReplayState {
    fn validate_next(&self, event: &EvidenceEvent, timestamp: u64) -> Result<(), EvidenceError> {
        if self.finalized {
            return Err(EvidenceError::SessionFinalized);
        }
        if self.last_timestamp.is_some_and(|last| timestamp < last) {
            return Err(EvidenceError::TimestampRegression);
        }
        match event {
            EvidenceEvent::SessionStarted { .. } if !self.started => Ok(()),
            EvidenceEvent::AuthorityDecision { .. } if self.started && !self.authority_decided => {
                Ok(())
            }
            EvidenceEvent::LeaseBound {
                grant_id,
                grant_digest,
                ..
            } if self.authority_granted
                && !self.lease_bound
                && self.summary.grant_id.as_ref() == Some(grant_id)
                && self.summary.grant_digest.as_ref() == Some(grant_digest) =>
            {
                Ok(())
            }
            EvidenceEvent::ProxyUseAggregate {
                lease_id,
                attempted_requests,
                forwarded_requests,
                denied_requests,
                ..
            } if self.lease_bound
                && !self.worker_completed
                && self.summary.lease_id.as_ref() == Some(lease_id)
                && forwarded_requests
                    .checked_add(*denied_requests)
                    .is_some_and(|total| total <= *attempted_requests) =>
            {
                Ok(())
            }
            EvidenceEvent::WorkerCompleted { result_digest, .. }
                if self.lease_bound && !self.worker_completed && result_digest.is_some() =>
            {
                Ok(())
            }
            EvidenceEvent::RollbackCompleted {
                result,
                rollback_digest,
            } if self.worker_completed
                && !self.rollback_completed
                && match result {
                    RollbackResult::Applied | RollbackResult::Failed => rollback_digest.is_some(),
                    RollbackResult::NotRequired => rollback_digest.is_none(),
                } =>
            {
                Ok(())
            }
            EvidenceEvent::FinalOutcome { outcome, .. } if self.can_finalize(*outcome) => Ok(()),
            _ => Err(EvidenceError::InvalidLifecycle),
        }
    }

    fn can_finalize(&self, outcome: FinalOutcome) -> bool {
        if !self.authority_decided {
            return false;
        }
        match outcome {
            FinalOutcome::Denied => !self.authority_granted,
            FinalOutcome::Succeeded => {
                self.rollback_completed
                    && self.summary.worker_result == Some(WorkerResult::Succeeded)
                    && self.summary.rollback_result == Some(RollbackResult::NotRequired)
            }
            FinalOutcome::TimedOut => {
                self.rollback_completed
                    && self.summary.worker_result == Some(WorkerResult::TimedOut)
            }
            FinalOutcome::Revoked => {
                self.rollback_completed && self.summary.worker_result == Some(WorkerResult::Revoked)
            }
            FinalOutcome::RolledBack => {
                self.summary.rollback_result == Some(RollbackResult::Applied)
            }
            FinalOutcome::Failed => {
                self.rollback_completed
                    && (self.summary.worker_result == Some(WorkerResult::Failed)
                        || self.summary.rollback_result == Some(RollbackResult::Failed))
            }
        }
    }

    fn apply(&mut self, event: &EvidenceEvent, timestamp: u64) -> Result<(), EvidenceError> {
        self.validate_next(event, timestamp)?;
        self.last_timestamp = Some(timestamp);
        match event {
            EvidenceEvent::SessionStarted {
                workspace_id,
                action_id,
                intent_digest,
            } => {
                self.started = true;
                self.summary.workspace_id = Some(workspace_id.clone());
                self.summary.action_id = Some(action_id.clone());
                self.summary.intent_digest = Some(intent_digest.clone());
            }
            EvidenceEvent::AuthorityDecision { decision } => {
                self.authority_decided = true;
                match decision {
                    AuthorityDecision::Denied {
                        authority_digest,
                        reason,
                    } => {
                        self.summary.authority_digest = Some(authority_digest.clone());
                        self.summary.authority_denial = Some(*reason);
                    }
                    AuthorityDecision::Granted {
                        authority_digest,
                        grant_id,
                        grant_digest,
                    } => {
                        self.authority_granted = true;
                        self.summary.authority_digest = Some(authority_digest.clone());
                        self.summary.grant_id = Some(grant_id.clone());
                        self.summary.grant_digest = Some(grant_digest.clone());
                    }
                }
            }
            EvidenceEvent::LeaseBound {
                lease_id,
                lease_digest,
                ..
            } => {
                self.lease_bound = true;
                self.summary.lease_id = Some(lease_id.clone());
                self.summary.lease_digest = Some(lease_digest.clone());
            }
            EvidenceEvent::ProxyUseAggregate {
                attempted_requests,
                forwarded_requests,
                denied_requests,
                request_bytes,
                response_bytes,
                ..
            } => {
                let totals = &mut self.summary.proxy_use;
                totals.aggregates = checked_add(totals.aggregates, 1)?;
                totals.attempted_requests =
                    checked_add(totals.attempted_requests, *attempted_requests)?;
                totals.forwarded_requests =
                    checked_add(totals.forwarded_requests, *forwarded_requests)?;
                totals.denied_requests = checked_add(totals.denied_requests, *denied_requests)?;
                totals.request_bytes = checked_add(totals.request_bytes, *request_bytes)?;
                totals.response_bytes = checked_add(totals.response_bytes, *response_bytes)?;
            }
            EvidenceEvent::WorkerCompleted {
                result,
                result_digest,
            } => {
                self.worker_completed = true;
                self.summary.worker_result = Some(*result);
                self.summary.worker_result_digest = result_digest.clone();
            }
            EvidenceEvent::RollbackCompleted {
                result,
                rollback_digest,
            } => {
                self.rollback_completed = true;
                self.summary.rollback_result = Some(*result);
                self.summary.rollback_digest = rollback_digest.clone();
            }
            EvidenceEvent::FinalOutcome {
                outcome,
                outcome_digest,
            } => {
                self.finalized = true;
                self.summary.final_outcome = Some(*outcome);
                self.summary.final_outcome_digest = Some(outcome_digest.clone());
            }
        }
        Ok(())
    }
}

fn replay(session_id: &SessionId, records: &[LogRecord]) -> Result<ReplayState, EvidenceError> {
    let mut state = ReplayState::default();
    for (index, record) in records.iter().enumerate() {
        if &record.session_id != session_id
            || record.sequence
                != u64::try_from(index).map_err(|_| EvidenceError::SequenceExhausted)?
        {
            return Err(EvidenceError::ReplayOrSequence);
        }
        state.apply(&record.event, record.observed_at_unix_ms)?;
    }
    Ok(state)
}

fn checked_add(left: u64, right: u64) -> Result<u64, EvidenceError> {
    left.checked_add(right)
        .ok_or(EvidenceError::AggregateOverflow)
}

fn compute_mac(
    key: &IntegrityKey,
    domain: &[u8],
    payload: &[u8],
) -> Result<Sha256Digest, EvidenceError> {
    let mut mac =
        HmacSha256::new_from_slice(key.0.as_ref()).map_err(|_| EvidenceError::InvalidKey)?;
    mac.update(domain);
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
        .parse()
        .map_err(|_| EvidenceError::InvalidDigest)
}

fn verify_mac(
    key: &IntegrityKey,
    domain: &[u8],
    payload: &[u8],
    expected: &Sha256Digest,
) -> Result<(), EvidenceError> {
    let expected = hex::decode(expected.as_str()).map_err(|_| EvidenceError::Tampered)?;
    let mut mac =
        HmacSha256::new_from_slice(key.0.as_ref()).map_err(|_| EvidenceError::InvalidKey)?;
    mac.update(domain);
    mac.update(payload);
    mac.verify_slice(&expected)
        .map_err(|_| EvidenceError::Tampered)
}

fn sha256_domain_digest(domain: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
        .parse()
        .expect("SHA-256 output always has a valid digest shape")
}

fn event_digest(event: &EvidenceEvent) -> Result<Sha256Digest, EvidenceError> {
    Ok(sha256_domain_digest(
        EVENT_DIGEST_DOMAIN,
        &canonical_json_v1(event)?,
    ))
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SigningAssertionIdentity<'a> {
    schema_version: u8,
    payload_digest: &'a Sha256Digest,
    signer_id: &'a InstallationId,
    algorithm: CallerAssertedSignatureAlgorithm,
}

fn signing_assertion_digest(
    payload_digest: &Sha256Digest,
    signer_id: &InstallationId,
) -> Result<Sha256Digest, EvidenceError> {
    signing_assertion_digest_for_schema(SCHEMA_VERSION, payload_digest, signer_id)
}

fn signing_assertion_digest_for_schema(
    schema_version: u8,
    payload_digest: &Sha256Digest,
    signer_id: &InstallationId,
) -> Result<Sha256Digest, EvidenceError> {
    Ok(sha256_domain_digest(
        SIGNING_ASSERTION_DOMAIN,
        &canonical_json_v1(&SigningAssertionIdentity {
            schema_version,
            payload_digest,
            signer_id,
            algorithm: CALLER_ASSERTED_ALGORITHM,
        })?,
    ))
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AppendWitnessIdentity<'a> {
    session_id: &'a SessionId,
    sequence: u64,
    record_mac: &'a Sha256Digest,
}

fn append_witness(
    session_id: &SessionId,
    sequence: u64,
    record_mac: &Sha256Digest,
) -> Result<Sha256Digest, EvidenceError> {
    Ok(sha256_domain_digest(
        APPEND_WITNESS_DOMAIN,
        &canonical_json_v1(&AppendWitnessIdentity {
            session_id,
            sequence,
            record_mac,
        })?,
    ))
}

fn parse_key(bytes: Vec<u8>) -> Result<IntegrityKey, EvidenceError> {
    let encoded = Zeroizing::new(String::from_utf8(bytes).map_err(|_| EvidenceError::InvalidKey)?);
    let decoded =
        Zeroizing::new(hex::decode(encoded.trim()).map_err(|_| EvidenceError::InvalidKey)?);
    let raw: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| EvidenceError::InvalidKey)?;
    validated_integrity_key(raw)
}

fn validated_integrity_key(raw: [u8; 32]) -> Result<IntegrityKey, EvidenceError> {
    if raw.iter().all(|byte| *byte == 0) {
        return Err(EvidenceError::InvalidKey);
    }
    Ok(IntegrityKey(Zeroizing::new(raw)))
}

fn ensure_existing_private_root(path: &Path) -> Result<(), EvidenceError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| EvidenceError::InvalidStorageBoundary)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EvidenceError::InvalidStorageBoundary);
    }
    Ok(())
}

fn ensure_child_private_dir(parent: &Path, name: &str) -> Result<PathBuf, EvidenceError> {
    let path = parent.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(EvidenceError::UnsafeStorage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&path)?;
            sync_dir(parent)?;
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(path)
}

fn open_private_file(
    path: &Path,
    read: bool,
    append: bool,
    create_new: bool,
) -> Result<File, EvidenceError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(EvidenceError::UnsafeStorage);
        }
    }
    let mut options = OpenOptions::new();
    options
        .read(read)
        .write(append || create_new)
        .append(append)
        .create(append && !create_new)
        .create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(EvidenceError::UnsafeStorage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn open_existing_private_readonly(path: &Path) -> Result<File, EvidenceError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(EvidenceError::UnsafeStorage);
        }
        Ok(_) => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    validate_existing_private_readonly(&file)?;
    Ok(file)
}

fn validate_existing_private_readonly(file: &File) -> Result<(), EvidenceError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(EvidenceError::UnsafeStorage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(EvidenceError::UnsafeStorage);
        }
    }
    Ok(())
}

fn read_existing_private_file_bounded(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, EvidenceError> {
    let mut file = open_existing_private_readonly(path)?;
    if file.metadata()?.len() > max_bytes {
        return Err(EvidenceError::LogTooLarge);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| EvidenceError::LogTooLarge)? > max_bytes {
        return Err(EvidenceError::LogTooLarge);
    }
    Ok(bytes)
}

fn read_private_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, EvidenceError> {
    let mut file = open_private_file(path, true, false, false)?;
    if file.metadata()?.len() > max_bytes {
        return Err(EvidenceError::LogTooLarge);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| EvidenceError::LogTooLarge)? > max_bytes {
        return Err(EvidenceError::LogTooLarge);
    }
    Ok(bytes)
}

fn ensure_record_capacity(count: usize) -> Result<(), EvidenceError> {
    if count >= MAX_RECORDS {
        return Err(EvidenceError::RecordLimitExceeded);
    }
    Ok(())
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(EvidenceError::UnsafeStorage);
        }
    }
    let parent = path.parent().ok_or(EvidenceError::UnsafeStorage)?;
    for _ in 0..32 {
        let temp = parent.join(format!(
            ".evidence-receipt-{:016x}.tmp",
            rand::random::<u64>()
        ));
        let mut file = match open_private_file(&temp, true, false, true) {
            Ok(file) => file,
            Err(EvidenceError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(error) => return Err(error),
        };
        let result = (|| -> Result<(), EvidenceError> {
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, path)?;
            sync_dir(parent)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        return result;
    }
    Err(EvidenceError::TemporaryFileExhausted)
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), EvidenceError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<(), EvidenceError> {
    Ok(())
}

fn unix_millis() -> Result<u64, EvidenceError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EvidenceError::ClockBeforeEpoch)?
        .as_millis();
    u64::try_from(millis).map_err(|_| EvidenceError::ClockOverflow)
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence storage must be outside the workspace")]
    StorageInsideWorkspace,
    #[error("invalid evidence storage boundary")]
    InvalidStorageBoundary,
    #[error("unsafe evidence storage entry")]
    UnsafeStorage,
    #[error("evidence log is truncated")]
    Truncated,
    #[error("evidence log is non-canonical")]
    NonCanonical,
    #[error("evidence log integrity check failed")]
    Tampered,
    #[error("evidence sequence or replay check failed")]
    ReplayOrSequence,
    #[error("evidence expected sequence does not match durable state")]
    UnexpectedSequence,
    #[error("evidence sequence was reused for a different event")]
    IdempotencyConflict,
    #[error("invalid evidence lifecycle transition")]
    InvalidLifecycle,
    #[error("evidence session already finalized")]
    SessionFinalized,
    #[error("evidence session has not started")]
    SessionNotStarted,
    #[error("evidence session is not finalized")]
    SessionNotFinalized,
    #[error("evidence timestamp regressed")]
    TimestampRegression,
    #[error("evidence aggregate overflow")]
    AggregateOverflow,
    #[error("evidence sequence exhausted")]
    SequenceExhausted,
    #[error("evidence log exceeds the private storage byte limit")]
    LogTooLarge,
    #[error("evidence log exceeds the record limit")]
    RecordLimitExceeded,
    #[error("could not allocate a private evidence temporary file")]
    TemporaryFileExhausted,
    #[error("invalid evidence integrity key")]
    InvalidKey,
    #[error("invalid evidence digest")]
    InvalidDigest,
    #[error("evidence signer did not verify its signature")]
    UnverifiedSignature,
    #[error("caller-asserted receipt snapshot already exists with different bytes")]
    ReceiptConflict,
    #[error("system clock is before Unix epoch")]
    ClockBeforeEpoch,
    #[error("system clock value overflow")]
    ClockOverflow,
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error(transparent)]
    Canonical(#[from] phantom_authority::CanonicalJsonError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::thread;
    use tempfile::TempDir;

    fn session() -> SessionId {
        "ses_11111111111111111111111111111111".parse().unwrap()
    }

    fn workspace_id() -> WorkspaceId {
        "wrk_22222222222222222222222222222222".parse().unwrap()
    }

    fn action_id() -> ActionId {
        "act_33333333333333333333333333333333".parse().unwrap()
    }

    fn grant_id() -> GrantId {
        "grt_44444444444444444444444444444444".parse().unwrap()
    }

    fn lease_id() -> LeaseId {
        "lea_55555555555555555555555555555555".parse().unwrap()
    }

    fn digest(byte: char) -> Sha256Digest {
        byte.to_string().repeat(64).parse().unwrap()
    }

    struct Fixture {
        _home: TempDir,
        _workspace: TempDir,
        store: EvidenceStore,
    }

    impl Fixture {
        fn new() -> Self {
            let home = TempDir::new().unwrap();
            let workspace = TempDir::new().unwrap();
            let store = EvidenceStore::open(home.path(), workspace.path(), session()).unwrap();
            Self {
                _home: home,
                _workspace: workspace,
                store,
            }
        }
    }

    fn start(store: &EvidenceStore) {
        store.append_at(start_event(), 1).unwrap();
    }

    fn start_event() -> EvidenceEvent {
        EvidenceEvent::SessionStarted {
            workspace_id: workspace_id(),
            action_id: action_id(),
            intent_digest: digest('a'),
        }
    }

    fn grant(store: &EvidenceStore) {
        store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Granted {
                        authority_digest: digest('b'),
                        grant_id: grant_id(),
                        grant_digest: digest('c'),
                    },
                },
                2,
            )
            .unwrap();
        store
            .append_at(
                EvidenceEvent::LeaseBound {
                    grant_id: grant_id(),
                    grant_digest: digest('c'),
                    lease_id: lease_id(),
                    lease_digest: digest('d'),
                },
                3,
            )
            .unwrap();
    }

    fn complete_success(store: &EvidenceStore, timestamp: u64) {
        store
            .append_at(
                EvidenceEvent::WorkerCompleted {
                    result: WorkerResult::Succeeded,
                    result_digest: Some(digest('e')),
                },
                timestamp,
            )
            .unwrap();
        store
            .append_at(
                EvidenceEvent::RollbackCompleted {
                    result: RollbackResult::NotRequired,
                    rollback_digest: None,
                },
                timestamp + 1,
            )
            .unwrap();
        store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Succeeded,
                    outcome_digest: digest('f'),
                },
                timestamp + 2,
            )
            .unwrap();
    }

    fn finalized_denied_receipt(store: &EvidenceStore) -> SessionReceipt {
        start(store);
        store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::NoVerifier,
                    },
                },
                2,
            )
            .unwrap();
        store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();
        store.receipt(SigningBoundary::NoVerifiedSigner).unwrap()
    }

    #[test]
    fn correlated_receipt_is_canonical_value_free_and_unsigned_by_default() {
        let fixture = Fixture::new();
        start(&fixture.store);
        grant(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::ProxyUseAggregate {
                    lease_id: lease_id(),
                    attempted_requests: 3,
                    forwarded_requests: 2,
                    denied_requests: 1,
                    request_bytes: 100,
                    response_bytes: 200,
                },
                4,
            )
            .unwrap();
        complete_success(&fixture.store, 5);

        let receipt = fixture
            .store
            .receipt(SigningBoundary::NoVerifiedSigner)
            .unwrap();
        assert_eq!(receipt.trust_state(), ReceiptTrustState::UnsignedUntrusted);
        assert_eq!(receipt.payload.event_count, 7);
        assert_eq!(receipt.payload.summary.grant_id, Some(grant_id()));
        assert_eq!(receipt.payload.summary.lease_id, Some(lease_id()));
        assert_eq!(receipt.payload.summary.proxy_use.attempted_requests, 3);
        assert_eq!(
            receipt.payload.summary.final_outcome,
            Some(FinalOutcome::Succeeded)
        );
        let canonical = receipt.canonical_bytes().unwrap();
        assert_eq!(canonical, canonical_json_v1(&receipt).unwrap());
        let persisted_receipt = fixture.store.evidence_dir.join(format!(
            "{}.receipt.unsigned.json",
            fixture.store.session_id.as_str()
        ));
        assert_eq!(std::fs::read(persisted_receipt).unwrap(), canonical);
        fixture.store.verify_local_receipt(&receipt).unwrap();

        let mut altered = receipt.clone();
        altered.payload.event_count += 1;
        assert!(matches!(
            fixture.store.verify_local_receipt(&altered),
            Err(EvidenceError::Tampered)
        ));
    }

    #[test]
    fn local_receipt_verification_is_read_only() {
        let fixture = Fixture::new();
        let receipt = finalized_denied_receipt(&fixture.store);
        let receipt_path = fixture.store.evidence_dir.join(format!(
            "{}.receipt.unsigned.json",
            fixture.store.session_id.as_str()
        ));
        std::fs::remove_file(&receipt_path).unwrap();

        fixture.store.verify_local_receipt(&receipt).unwrap();
        assert!(!receipt_path.exists());
    }

    #[test]
    fn verification_never_recreates_missing_lock_key_or_log() {
        for missing in ["lock", "key", "log"] {
            let fixture = Fixture::new();
            let receipt = finalized_denied_receipt(&fixture.store);
            let path = match missing {
                "lock" => &fixture.store.lock_path,
                "key" => &fixture.store.key_path,
                "log" => &fixture.store.log_path,
                _ => unreachable!(),
            };
            std::fs::remove_file(path).unwrap();
            assert!(matches!(
                fixture.store.verify_local_receipt(&receipt),
                Err(EvidenceError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound
            ));
            assert!(
                !path.exists(),
                "verification recreated the removed {missing}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn verification_preserves_file_modes_and_mtimes() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let receipt = finalized_denied_receipt(&fixture.store);
        let paths = [
            fixture.store.phantom_home.clone(),
            fixture.store.evidence_dir.clone(),
            fixture.store.lock_path.clone(),
            fixture.store.key_path.clone(),
            fixture.store.log_path.clone(),
        ];
        let before = paths
            .iter()
            .map(|path| {
                let metadata = std::fs::metadata(path).unwrap();
                (metadata.permissions().mode(), metadata.modified().unwrap())
            })
            .collect::<Vec<_>>();

        fixture.store.verify_local_receipt(&receipt).unwrap();

        let after = paths
            .iter()
            .map(|path| {
                let metadata = std::fs::metadata(path).unwrap();
                (metadata.permissions().mode(), metadata.modified().unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(after, before);
    }

    #[cfg(unix)]
    #[test]
    fn verification_rejects_unsafe_modes_without_hardening_them() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let receipt = finalized_denied_receipt(&fixture.store);
        for path in [
            &fixture.store.lock_path,
            &fixture.store.key_path,
            &fixture.store.log_path,
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                fixture.store.verify_local_receipt(&receipt),
                Err(EvidenceError::UnsafeStorage)
            ));
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                0o644
            );
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn verification_works_with_read_only_storage_directories() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let receipt = finalized_denied_receipt(&fixture.store);
        std::fs::set_permissions(
            &fixture.store.evidence_dir,
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        std::fs::set_permissions(
            &fixture.store.phantom_home,
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();

        let result = fixture.store.verify_local_receipt(&receipt);

        std::fs::set_permissions(
            &fixture.store.phantom_home,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            &fixture.store.evidence_dir,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        result.unwrap();
    }

    #[test]
    fn concurrent_appenders_receive_one_contiguous_sequence() {
        let fixture = Fixture::new();
        start(&fixture.store);
        grant(&fixture.store);
        let store = Arc::new(fixture.store.clone());
        let threads = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    store
                        .append(EvidenceEvent::ProxyUseAggregate {
                            lease_id: lease_id(),
                            attempted_requests: 1,
                            forwarded_requests: 1,
                            denied_requests: 0,
                            request_bytes: 10,
                            response_bytes: 20,
                        })
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let mut sequences = threads
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        assert_eq!(sequences, (3_u64..19).collect::<Vec<_>>());
        assert_eq!(store.event_count().unwrap(), 19);
    }

    #[test]
    fn append_once_is_exactly_idempotent_across_restart() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let first = EvidenceStore::open(home.path(), workspace.path(), session()).unwrap();
        let new = first.append_once(0, start_event()).unwrap();
        let (new_digest, new_witness) = match new {
            AppendOnceResult::New {
                sequence,
                event_digest,
                record_witness,
            } => {
                assert_eq!(sequence, 0);
                (event_digest, record_witness)
            }
            AppendOnceResult::Existing { .. } => panic!("first append must be new"),
        };
        drop(first);

        let reopened = EvidenceStore::open(home.path(), workspace.path(), session()).unwrap();
        assert_eq!(
            reopened.append_once(0, start_event()).unwrap(),
            AppendOnceResult::Existing {
                sequence: 0,
                event_digest: new_digest,
                record_witness: new_witness,
            }
        );
        assert_eq!(reopened.event_count().unwrap(), 1);
    }

    #[test]
    fn append_witness_binds_session_sequence_and_record_mac() {
        let fixture = Fixture::new();
        let result = fixture.store.append_once(0, start_event()).unwrap();
        let witness = match result {
            AppendOnceResult::New { record_witness, .. } => record_witness,
            AppendOnceResult::Existing { .. } => panic!("first append must be new"),
        };
        let lock = fixture.store.acquire_lock().unwrap();
        let key = fixture.store.load_existing_key_locked().unwrap();
        let records = fixture.store.load_records_locked(&key).unwrap();
        drop(lock);
        assert_eq!(
            witness,
            append_witness(&fixture.store.session_id, 0, &records[0].mac).unwrap()
        );
        let other_session: SessionId = "ses_99999999999999999999999999999999".parse().unwrap();
        assert_ne!(
            witness,
            append_witness(&other_session, 0, &records[0].mac).unwrap()
        );
        assert_ne!(
            witness,
            append_witness(&fixture.store.session_id, 1, &records[0].mac).unwrap()
        );
    }

    #[test]
    fn append_once_conflict_future_sequence_and_tamper_fail_closed() {
        let fixture = Fixture::new();
        fixture.store.append_once(0, start_event()).unwrap();
        let conflicting = EvidenceEvent::SessionStarted {
            workspace_id: workspace_id(),
            action_id: action_id(),
            intent_digest: digest('b'),
        };
        assert!(matches!(
            fixture.store.append_once(0, conflicting),
            Err(EvidenceError::IdempotencyConflict)
        ));
        assert!(matches!(
            fixture.store.append_once(2, start_event()),
            Err(EvidenceError::UnexpectedSequence)
        ));

        let bytes = std::fs::read(&fixture.store.log_path).unwrap();
        let text = String::from_utf8(bytes)
            .unwrap()
            .replace(&"a".repeat(64), &"b".repeat(64));
        std::fs::write(&fixture.store.log_path, text).unwrap();
        assert!(matches!(
            fixture.store.append_once(0, start_event()),
            Err(EvidenceError::Tampered)
        ));
    }

    #[test]
    fn concurrent_exact_retries_create_only_one_record() {
        let fixture = Fixture::new();
        let store = Arc::new(fixture.store.clone());
        let results = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                thread::spawn(move || store.append_once(0, start_event()).unwrap())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, AppendOnceResult::New { .. }))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, AppendOnceResult::Existing { .. }))
                .count(),
            15
        );
        assert_eq!(store.event_count().unwrap(), 1);
    }

    #[test]
    fn tamper_is_detected_before_replay() {
        let fixture = Fixture::new();
        start(&fixture.store);
        grant(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::ProxyUseAggregate {
                    lease_id: lease_id(),
                    attempted_requests: 1,
                    forwarded_requests: 1,
                    denied_requests: 0,
                    request_bytes: 10,
                    response_bytes: 20,
                },
                4,
            )
            .unwrap();
        let bytes = std::fs::read(&fixture.store.log_path).unwrap();
        let text = String::from_utf8(bytes)
            .unwrap()
            .replace("\"request_bytes\":10", "\"request_bytes\":11");
        std::fs::write(&fixture.store.log_path, text).unwrap();
        assert!(matches!(
            fixture.store.event_count(),
            Err(EvidenceError::Tampered)
        ));
    }

    #[test]
    fn truncated_tail_fails_closed() {
        let fixture = Fixture::new();
        start(&fixture.store);
        let mut bytes = std::fs::read(&fixture.store.log_path).unwrap();
        bytes.pop();
        std::fs::write(&fixture.store.log_path, bytes).unwrap();
        assert!(matches!(
            fixture.store.event_count(),
            Err(EvidenceError::Truncated)
        ));
    }

    #[test]
    fn restart_reloads_chain_and_continues_sequence() {
        let home = TempDir::new().unwrap();
        let workspace = TempDir::new().unwrap();
        let first = EvidenceStore::open(home.path(), workspace.path(), session()).unwrap();
        start(&first);
        drop(first);

        let second = EvidenceStore::open(home.path(), workspace.path(), session()).unwrap();
        assert_eq!(
            second
                .append_at(
                    EvidenceEvent::AuthorityDecision {
                        decision: AuthorityDecision::Denied {
                            authority_digest: digest('b'),
                            reason: AuthorityDenial::NoVerifier,
                        },
                    },
                    2,
                )
                .unwrap(),
            1
        );
        second
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();
        assert_eq!(second.event_count().unwrap(), 3);
    }

    #[test]
    fn duplicate_sequence_is_rejected_even_when_record_itself_is_valid() {
        let fixture = Fixture::new();
        start(&fixture.store);
        let first = std::fs::read(&fixture.store.log_path).unwrap();
        let mut duplicated = first.clone();
        duplicated.extend_from_slice(&first);
        std::fs::write(&fixture.store.log_path, duplicated).unwrap();
        assert!(matches!(
            fixture.store.event_count(),
            Err(EvidenceError::ReplayOrSequence)
        ));
    }

    #[test]
    fn workspace_path_and_process_sentinels_never_enter_evidence() {
        const SENTINEL: &str = "sk-secret-raw-argv-env-url-body-SENTINEL";
        let home = TempDir::new().unwrap();
        let workspace_parent = TempDir::new().unwrap();
        let workspace = workspace_parent.path().join(SENTINEL);
        std::fs::create_dir(&workspace).unwrap();
        let store = EvidenceStore::open(home.path(), &workspace, session()).unwrap();
        start(&store);
        store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::InsufficientAuthority,
                    },
                },
                2,
            )
            .unwrap();
        store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();
        let receipt = store.receipt(SigningBoundary::NoVerifiedSigner).unwrap();
        let mut persisted = std::fs::read(&store.log_path).unwrap();
        for entry in std::fs::read_dir(&store.evidence_dir).unwrap() {
            let path = entry.unwrap().path();
            if path != store.log_path {
                persisted.extend_from_slice(&std::fs::read(path).unwrap());
            }
        }
        persisted.extend_from_slice(&receipt.canonical_bytes().unwrap());
        let rendered = String::from_utf8(persisted).unwrap();
        for forbidden in [
            SENTINEL,
            "secret_value",
            "request_body",
            "raw_argv",
            "environment",
            "http://",
            "https://",
        ] {
            assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        }
    }

    struct TestSigner;

    impl EvidenceSigner for TestSigner {
        fn signer_id(&self) -> InstallationId {
            "ins_99999999999999999999999999999999".parse().unwrap()
        }

        fn sign(&self, digest: &Sha256Digest) -> Result<[u8; 64], SignerError> {
            let bytes = hex::decode(digest.as_str()).unwrap();
            let mut signature = [0_u8; 64];
            signature[..32].copy_from_slice(&bytes);
            signature[32..].copy_from_slice(&bytes);
            Ok(signature)
        }

        fn verify(&self, digest: &Sha256Digest, signature: &[u8; 64]) -> bool {
            self.sign(digest)
                .is_ok_and(|expected| expected == *signature)
        }
    }

    struct AlternateSigner;

    impl EvidenceSigner for AlternateSigner {
        fn signer_id(&self) -> InstallationId {
            TestSigner.signer_id()
        }

        fn sign(&self, digest: &Sha256Digest) -> Result<[u8; 64], SignerError> {
            let mut signature = TestSigner.sign(digest)?;
            signature[0] ^= 0xff;
            Ok(signature)
        }

        fn verify(&self, digest: &Sha256Digest, signature: &[u8; 64]) -> bool {
            self.sign(digest)
                .is_ok_and(|expected| expected == *signature)
        }
    }

    #[derive(Default)]
    struct RandomizedValidSigner {
        sign_calls: AtomicUsize,
    }

    impl EvidenceSigner for RandomizedValidSigner {
        fn signer_id(&self) -> InstallationId {
            "ins_88888888888888888888888888888888".parse().unwrap()
        }

        fn sign(&self, digest: &Sha256Digest) -> Result<[u8; 64], SignerError> {
            self.sign_calls.fetch_add(1, Ordering::SeqCst);
            let mut signature = [0_u8; 64];
            rand::thread_rng().fill_bytes(&mut signature[..32]);
            signature[32..].copy_from_slice(&hex::decode(digest.as_str()).unwrap());
            Ok(signature)
        }

        fn verify(&self, digest: &Sha256Digest, signature: &[u8; 64]) -> bool {
            signature[32..] == hex::decode(digest.as_str()).unwrap()
        }
    }

    #[test]
    fn caller_asserted_state_requires_an_accepting_signer() {
        let fixture = Fixture::new();
        start(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::NoVerifier,
                    },
                },
                2,
            )
            .unwrap();
        fixture
            .store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();

        let unsigned = fixture
            .store
            .receipt(SigningBoundary::NoVerifiedSigner)
            .unwrap();
        assert_eq!(unsigned.trust_state(), ReceiptTrustState::UnsignedUntrusted);
        let caller_asserted = fixture
            .store
            .receipt(SigningBoundary::CallerAsserted(&TestSigner))
            .unwrap();
        assert_eq!(
            caller_asserted.trust_state(),
            ReceiptTrustState::CallerAsserted
        );
        assert!(matches!(
            fixture
                .store
                .receipt(SigningBoundary::CallerAsserted(&DenyAllEvidenceSigner)),
            Err(EvidenceError::Signer(SignerError::Denied))
        ));
    }

    #[test]
    fn signing_assertion_binds_schema_payload_signer_and_fixed_algorithm() {
        let fixture = Fixture::new();
        start(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::NoVerifier,
                    },
                },
                2,
            )
            .unwrap();
        fixture
            .store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();

        let receipt = fixture
            .store
            .receipt(SigningBoundary::CallerAsserted(&TestSigner))
            .unwrap();
        let signer_id = TestSigner.signer_id();
        let expected = signing_assertion_digest(&receipt.payload_digest, &signer_id).unwrap();
        assert_ne!(expected, receipt.payload_digest);
        let (algorithm, signature_hex) = match &receipt.trust {
            ReceiptTrust::CallerAsserted {
                algorithm,
                signature_hex,
                ..
            } => (*algorithm, signature_hex),
            ReceiptTrust::UnsignedUntrusted => panic!("expected asserted receipt"),
        };
        assert_eq!(algorithm, CALLER_ASSERTED_ALGORITHM);
        assert_eq!(&signature_hex[..64], expected.as_str());
        let other_signer: InstallationId = "ins_77777777777777777777777777777777".parse().unwrap();
        assert_ne!(
            expected,
            signing_assertion_digest(&receipt.payload_digest, &other_signer).unwrap()
        );
        assert_ne!(
            expected,
            signing_assertion_digest_for_schema(
                SCHEMA_VERSION + 1,
                &receipt.payload_digest,
                &signer_id
            )
            .unwrap()
        );
        let serialized = String::from_utf8(receipt.canonical_bytes().unwrap()).unwrap();
        assert!(serialized.contains("digest_signature64_v1"));
        assert!(serialized.contains(&format!("\"schema_version\":{}", SCHEMA_VERSION)));
    }

    #[test]
    fn randomized_signer_exact_retry_returns_existing_assertion() {
        let fixture = Fixture::new();
        start(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::NoVerifier,
                    },
                },
                2,
            )
            .unwrap();
        fixture
            .store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();
        let signer = RandomizedValidSigner::default();
        let first = fixture
            .store
            .receipt(SigningBoundary::CallerAsserted(&signer))
            .unwrap();
        let second = fixture
            .store
            .receipt(SigningBoundary::CallerAsserted(&signer))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(signer.sign_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.trust_state(), ReceiptTrustState::CallerAsserted);
    }

    #[test]
    fn caller_asserted_snapshot_cannot_be_overwritten_or_downgraded() {
        let fixture = Fixture::new();
        start(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::NoVerifier,
                    },
                },
                2,
            )
            .unwrap();
        fixture
            .store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();
        let asserted = fixture
            .store
            .receipt(SigningBoundary::CallerAsserted(&TestSigner))
            .unwrap();
        let asserted_path = fixture.store.evidence_dir.join(format!(
            "{}.receipt.{}.json",
            fixture.store.session_id.as_str(),
            TestSigner.signer_id().as_str()
        ));
        let original = std::fs::read(&asserted_path).unwrap();

        assert!(matches!(
            fixture
                .store
                .receipt(SigningBoundary::CallerAsserted(&AlternateSigner)),
            Err(EvidenceError::ReceiptConflict)
        ));
        assert!(matches!(
            fixture
                .store
                .append_once(
                    asserted.payload.event_count - 1,
                    EvidenceEvent::FinalOutcome {
                        outcome: FinalOutcome::Denied,
                        outcome_digest: digest('c'),
                    }
                )
                .unwrap(),
            AppendOnceResult::Existing { .. }
        ));
        fixture
            .store
            .receipt(SigningBoundary::NoVerifiedSigner)
            .unwrap();
        assert_eq!(std::fs::read(asserted_path).unwrap(), original);
    }

    #[test]
    fn invalid_lifecycle_and_post_final_append_are_denied() {
        let fixture = Fixture::new();
        assert!(matches!(
            fixture.store.append_at(
                EvidenceEvent::WorkerCompleted {
                    result: WorkerResult::Succeeded,
                    result_digest: None,
                },
                1
            ),
            Err(EvidenceError::InvalidLifecycle)
        ));
        start(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::NoVerifier,
                    },
                },
                2,
            )
            .unwrap();
        fixture
            .store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();
        assert!(matches!(
            fixture.store.append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('d'),
                },
                4
            ),
            Err(EvidenceError::SessionFinalized)
        ));
    }

    #[test]
    fn worker_digests_and_explicit_rollback_disposition_are_required() {
        let fixture = Fixture::new();
        start(&fixture.store);
        grant(&fixture.store);
        assert!(matches!(
            fixture.store.append_at(
                EvidenceEvent::WorkerCompleted {
                    result: WorkerResult::Succeeded,
                    result_digest: None,
                },
                4
            ),
            Err(EvidenceError::InvalidLifecycle)
        ));
        fixture
            .store
            .append_at(
                EvidenceEvent::WorkerCompleted {
                    result: WorkerResult::Succeeded,
                    result_digest: Some(digest('e')),
                },
                4,
            )
            .unwrap();
        assert!(matches!(
            fixture.store.append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Succeeded,
                    outcome_digest: digest('f'),
                },
                5
            ),
            Err(EvidenceError::InvalidLifecycle)
        ));
        assert!(matches!(
            fixture.store.append_at(
                EvidenceEvent::RollbackCompleted {
                    result: RollbackResult::NotRequired,
                    rollback_digest: Some(digest('f')),
                },
                5
            ),
            Err(EvidenceError::InvalidLifecycle)
        ));
    }

    #[test]
    fn timeout_revocation_and_rollback_outcomes_are_correlated() {
        for (worker, rollback, outcome) in [
            (WorkerResult::TimedOut, None, FinalOutcome::TimedOut),
            (WorkerResult::Revoked, None, FinalOutcome::Revoked),
            (
                WorkerResult::Failed,
                Some(RollbackResult::Applied),
                FinalOutcome::RolledBack,
            ),
        ] {
            let fixture = Fixture::new();
            start(&fixture.store);
            grant(&fixture.store);
            fixture
                .store
                .append_at(
                    EvidenceEvent::WorkerCompleted {
                        result: worker,
                        result_digest: Some(digest('e')),
                    },
                    4,
                )
                .unwrap();
            let rollback = rollback.unwrap_or(RollbackResult::NotRequired);
            fixture
                .store
                .append_at(
                    EvidenceEvent::RollbackCompleted {
                        result: rollback,
                        rollback_digest: (rollback != RollbackResult::NotRequired)
                            .then(|| digest('f')),
                    },
                    5,
                )
                .unwrap();
            fixture
                .store
                .append_at(
                    EvidenceEvent::FinalOutcome {
                        outcome,
                        outcome_digest: digest('9'),
                    },
                    6,
                )
                .unwrap();
            let receipt = fixture
                .store
                .receipt(SigningBoundary::NoVerifiedSigner)
                .unwrap();
            assert_eq!(receipt.payload.summary.worker_result, Some(worker));
            assert_eq!(receipt.payload.summary.rollback_result, Some(rollback));
            assert_eq!(receipt.payload.summary.final_outcome, Some(outcome));
        }
    }

    #[test]
    fn storage_inside_workspace_and_symlinked_storage_are_rejected() {
        let workspace = TempDir::new().unwrap();
        let nested_home = workspace.path().join("home");
        std::fs::create_dir(&nested_home).unwrap();
        assert!(matches!(
            EvidenceStore::open(&nested_home, workspace.path(), session()),
            Err(EvidenceError::StorageInsideWorkspace)
        ));

        let home = TempDir::new().unwrap();
        let evidence_dir = home.path().join(".phantom/evidence");
        std::fs::create_dir_all(&evidence_dir).unwrap();
        let nested_workspace = evidence_dir.join("workspace");
        std::fs::create_dir(&nested_workspace).unwrap();
        assert!(matches!(
            EvidenceStore::open(home.path(), &nested_workspace, session()),
            Err(EvidenceError::StorageInsideWorkspace)
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let home = TempDir::new().unwrap();
            let outside = TempDir::new().unwrap();
            std::fs::create_dir(home.path().join(".phantom")).unwrap();
            symlink(outside.path(), home.path().join(".phantom/evidence")).unwrap();
            assert!(matches!(
                EvidenceStore::open(home.path(), workspace.path(), session()),
                Err(EvidenceError::UnsafeStorage)
            ));
        }
    }

    #[test]
    fn oversized_logs_and_exhausted_record_capacity_fail_closed() {
        let fixture = Fixture::new();
        start(&fixture.store);
        OpenOptions::new()
            .write(true)
            .open(&fixture.store.log_path)
            .unwrap()
            .set_len(MAX_LOG_BYTES + 1)
            .unwrap();
        assert!(matches!(
            fixture.store.event_count(),
            Err(EvidenceError::LogTooLarge)
        ));
        assert!(matches!(
            ensure_record_capacity(MAX_RECORDS),
            Err(EvidenceError::RecordLimitExceeded)
        ));
    }

    #[test]
    fn all_zero_existing_and_candidate_generated_keys_are_rejected() {
        assert!(matches!(
            validated_integrity_key([0_u8; 32]),
            Err(EvidenceError::InvalidKey)
        ));

        let fixture = Fixture::new();
        std::fs::write(&fixture.store.key_path, "00".repeat(32)).unwrap();
        assert!(matches!(
            EvidenceStore::open(fixture._home.path(), fixture._workspace.path(), session()),
            Err(EvidenceError::InvalidKey)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn persisted_directories_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        start(&fixture.store);
        fixture
            .store
            .append_at(
                EvidenceEvent::AuthorityDecision {
                    decision: AuthorityDecision::Denied {
                        authority_digest: digest('b'),
                        reason: AuthorityDenial::NoVerifier,
                    },
                },
                2,
            )
            .unwrap();
        fixture
            .store
            .append_at(
                EvidenceEvent::FinalOutcome {
                    outcome: FinalOutcome::Denied,
                    outcome_digest: digest('c'),
                },
                3,
            )
            .unwrap();
        fixture
            .store
            .receipt(SigningBoundary::NoVerifiedSigner)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&fixture.store.evidence_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in [
            &fixture.store.key_path,
            &fixture.store.lock_path,
            &fixture.store.log_path,
        ] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let receipt_path = fixture.store.evidence_dir.join(format!(
            "{}.receipt.unsigned.json",
            fixture.store.session_id.as_str()
        ));
        assert_eq!(
            std::fs::metadata(receipt_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
