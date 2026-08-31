//! Conversation-native workspace inspection primitives for Phantom.
//!
//! Workspace discovery remains value-blind: public plans and receipts contain
//! only paths, key names, classifications, hashes, and normalized identity
//! hints. The transaction engine can atomically apply the value-free filesystem
//! portion of an exactly re-inspected plan. Vault-dependent actions are handled
//! only through an explicit transaction participant and are otherwise reported
//! as deferred.

mod capability;
mod discovery;
mod plan;
mod transaction;

pub use capability::{
    build_capability_card, AuthorityState, CapabilityCard, CapabilityScope,
    CompatibilityCatalogNotice, HardNo,
};
pub use discovery::{
    inspect_workspace, EnvFileObservation, GitIdentity, GitRemoteIdentity, PlaceHint,
    PlaceHintConfidence, WorkspaceInspection,
};
pub use plan::{build_setup_plan, SetupAction, SetupActionKind, SetupPlan};
pub use transaction::{
    apply_setup_plan, apply_setup_plan_durable, build_sealed_setup_plan, clear_setup_plan_journal,
    recover_setup_plan_journal, rollback_workspace, ActionOutcome, ActionOutcomeState,
    DurableJournalConfig, FileChangeReceipt, JournalRecovery, NoopSetupParticipant,
    ParticipantError, ParticipantFileMutation, ParticipantPreparation, PlanSealKey,
    SealedSetupPlan, SetupTransaction, SetupTransactionParticipant, SetupTransactionReceipt,
    WorkspaceSnapshot,
};

use std::path::PathBuf;

/// Errors produced while inspecting or planning a workspace.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("failed to inspect {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize value-blind workspace state: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("approved setup plan is internally inconsistent")]
    InvalidPlan,
    #[error("workspace changed after setup approval (approved {approved_plan_id}, current {current_plan_id})")]
    PlanDrift {
        approved_plan_id: String,
        current_plan_id: String,
    },
    #[error("unsafe transaction target: {0}")]
    UnsafeTarget(PathBuf),
    #[error("setup participant failed during {stage}: {code}")]
    Participant {
        stage: &'static str,
        code: &'static str,
    },
    #[error("setup failed and rollback was incomplete")]
    RollbackIncomplete,
    #[error("cannot roll back {0} because it changed after setup")]
    RollbackDrift(PathBuf),
    #[error("workspace transaction journal failed authentication or is invalid")]
    InvalidJournal,
    #[error("workspace transaction journal belongs to a different request or plan")]
    JournalMismatch,
    #[error("safe descriptor-relative workspace mutation is unsupported on this platform")]
    SafeMutationUnsupported,
}

pub type Result<T> = std::result::Result<T, WorkspaceError>;
