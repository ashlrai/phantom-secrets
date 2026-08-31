//! Staged secret rotation — shadow (candidate) credential tracking.
//!
//! ## Overview
//!
//! A [`ShadowedSecret`] records the *primary* (live) credential alongside a
//! *candidate* (new) credential that has been generated but not yet promoted.
//! The workflow is:
//!
//! 1. `phantom rotate <name> --shadow`  → creates a candidate; stores it via
//!    [`ShadowedSecret::new`].
//! 2. During proxy sessions `PHANTOM_CANDIDATE_MODE=1` causes the proxy to
//!    inject the candidate instead of the primary so it can be validated
//!    against real APIs without touching production traffic.
//! 3. `phantom validate <name> --promote` runs the validator and, on success,
//!    atomically swaps primary ↔ candidate via [`ShadowedSecret::promote`].
//! 4. If validation fails the candidate is marked [`PromotionStatus::Failed`]
//!    and can be abandoned via [`ShadowedSecret::abandon`].
//!
//! ## Persistence
//!
//! Shadow state is serialised as JSON and stored in a per-project directory
//! returned by [`shadow_dir`].  The file is named `<name>.shadow.json`.
//! Loading/saving is done through [`ShadowStore`].
//!
//! ## Security
//!
//! - Secret *values* are stored in the vault backend (OS keychain / encrypted
//!   file).  Only the *names* and status metadata live in the shadow file.
//! - The shadow file is written with mode 0600 on Unix.
//! - `ShadowedSecret` implements `zeroize::ZeroizeOnDrop` so in-memory
//!   candidate/primary strings are scrubbed when dropped.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Unix-epoch seconds.
pub type Timestamp = u64;

/// Returns current Unix-epoch seconds.
pub fn now_secs() -> Timestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── PromotionStatus ───────────────────────────────────────────────────────────

/// Life-cycle state of a shadow (candidate) credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStatus {
    /// Candidate created; validation not yet attempted.
    Pending,
    /// Validation passed; ready to promote (or already promoted).
    Validated,
    /// Validation was attempted and failed.
    Failed,
    /// Candidate was promoted — it is now the primary.  The old primary was
    /// discarded.
    Promoted,
    /// Candidate was explicitly abandoned without being promoted.
    Abandoned,
}

impl std::fmt::Display for PromotionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromotionStatus::Pending => write!(f, "pending"),
            PromotionStatus::Validated => write!(f, "validated"),
            PromotionStatus::Failed => write!(f, "failed"),
            PromotionStatus::Promoted => write!(f, "promoted"),
            PromotionStatus::Abandoned => write!(f, "abandoned"),
        }
    }
}

// ── ShadowAuditEntry ─────────────────────────────────────────────────────────

/// A single audit record written whenever shadow state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAuditEntry {
    /// Unix-epoch seconds when this event occurred.
    pub ts: Timestamp,
    /// What happened.
    pub event: ShadowEvent,
    /// The secret name (key name, never the value).
    pub secret_name: String,
    /// Optional free-form context string (e.g. validator name, failure reason).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// The kind of shadow audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowEvent {
    /// A candidate was created and queued for validation.
    CandidateCreated,
    /// A validation attempt succeeded.
    ValidationPassed,
    /// A validation attempt failed.
    ValidationFailed,
    /// The candidate was atomically promoted to primary.
    Promoted,
    /// The candidate was abandoned (discarded without promotion).
    Abandoned,
    /// Stale/expired candidates were garbage-collected.
    GarbageCollected,
}

// ── ShadowedSecret ───────────────────────────────────────────────────────────

/// In-memory representation of a shadowed secret.
///
/// The struct owns the *value strings* for the primary and candidate credentials.
/// [`Drop`] implementation zeroizes the secret strings so they are scrubbed when
/// the value is dropped.
///
/// **Important:** never log or serialize the `primary` or `candidate` fields.
pub struct ShadowedSecret {
    /// Secret name (e.g. `OPENAI_API_KEY`).  Not secret — safe to log.
    pub name: String,
    /// The currently live credential value.  Secret — never log or serialize.
    pub primary: String,
    /// The candidate (new) credential value.  Secret — never log or serialize.
    pub candidate: String,
    /// When the candidate was created.
    pub candidate_added_at: Timestamp,
    /// Unique identifier for this shadow operation.
    pub shadow_id: String,
    /// Current life-cycle status.
    pub promotion_status: PromotionStatus,
    /// Optional TTL in seconds after which the candidate auto-expires.
    /// `None` means no automatic expiry.
    pub auto_promote_ttl_secs: Option<u64>,
    /// Audit trail — one entry per state transition.
    pub audit_trail: Vec<ShadowAuditEntry>,
}

impl Drop for ShadowedSecret {
    fn drop(&mut self) {
        self.primary.zeroize();
        self.candidate.zeroize();
    }
}

impl std::fmt::Debug for ShadowedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowedSecret")
            .field("name", &self.name)
            .field("primary", &"[REDACTED]")
            .field("candidate", &"[REDACTED]")
            .field("candidate_added_at", &self.candidate_added_at)
            .field("shadow_id", &self.shadow_id)
            .field("promotion_status", &self.promotion_status)
            .field("auto_promote_ttl_secs", &self.auto_promote_ttl_secs)
            .field("audit_trail", &self.audit_trail)
            .finish()
    }
}

impl Clone for ShadowedSecret {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            primary: self.primary.clone(),
            candidate: self.candidate.clone(),
            candidate_added_at: self.candidate_added_at,
            shadow_id: self.shadow_id.clone(),
            promotion_status: self.promotion_status.clone(),
            auto_promote_ttl_secs: self.auto_promote_ttl_secs,
            audit_trail: self.audit_trail.clone(),
        }
    }
}

impl ShadowedSecret {
    /// Create a new shadow record.
    ///
    /// - `name`: secret key name (e.g. `OPENAI_API_KEY`).
    /// - `primary`: current live value.
    /// - `candidate`: newly generated value awaiting validation.
    /// - `auto_promote_ttl_secs`: optional TTL for automatic promotion/expiry.
    pub fn new(
        name: impl Into<String>,
        primary: impl Into<String>,
        candidate: impl Into<String>,
        auto_promote_ttl_secs: Option<u64>,
    ) -> Self {
        let name = name.into();
        let now = now_secs();
        let shadow_id = generate_shadow_id();
        let audit_entry = ShadowAuditEntry {
            ts: now,
            event: ShadowEvent::CandidateCreated,
            secret_name: name.clone(),
            context: None,
        };
        Self {
            name,
            primary: primary.into(),
            candidate: candidate.into(),
            candidate_added_at: now,
            shadow_id,
            promotion_status: PromotionStatus::Pending,
            auto_promote_ttl_secs,
            audit_trail: vec![audit_entry],
        }
    }

    /// Reconstruct a `ShadowedSecret` from persisted metadata plus the vault values.
    ///
    /// This is the canonical way to rebuild a `ShadowedSecret` after loading
    /// [`ShadowMeta`] from the store.  Secret values are obtained from the vault
    /// backend and passed in directly.
    pub fn from_meta(
        meta: ShadowMeta,
        primary: impl Into<String>,
        candidate: impl Into<String>,
    ) -> Self {
        Self {
            name: meta.name,
            primary: primary.into(),
            candidate: candidate.into(),
            candidate_added_at: meta.candidate_added_at,
            shadow_id: meta.shadow_id,
            promotion_status: meta.promotion_status,
            auto_promote_ttl_secs: meta.auto_promote_ttl_secs,
            audit_trail: meta.audit_trail,
        }
    }

    // ── State transitions ────────────────────────────────────────────────────

    /// Record a successful validation result.
    ///
    /// Advances status to [`PromotionStatus::Validated`] if currently `Pending`.
    /// Returns `Err` if the transition is not allowed.
    pub fn record_validation_success(
        &mut self,
        context: Option<String>,
    ) -> Result<(), ShadowError> {
        match self.promotion_status {
            PromotionStatus::Pending | PromotionStatus::Failed => {
                self.promotion_status = PromotionStatus::Validated;
                self.audit_trail.push(ShadowAuditEntry {
                    ts: now_secs(),
                    event: ShadowEvent::ValidationPassed,
                    secret_name: self.name.clone(),
                    context,
                });
                Ok(())
            }
            ref s => Err(ShadowError::InvalidTransition {
                from: s.clone(),
                to: PromotionStatus::Validated,
            }),
        }
    }

    /// Record a failed validation attempt.
    ///
    /// Advances status to [`PromotionStatus::Failed`].  Returns `Err` if
    /// the transition is not allowed.
    pub fn record_validation_failure(
        &mut self,
        context: Option<String>,
    ) -> Result<(), ShadowError> {
        match self.promotion_status {
            PromotionStatus::Pending | PromotionStatus::Validated | PromotionStatus::Failed => {
                self.promotion_status = PromotionStatus::Failed;
                self.audit_trail.push(ShadowAuditEntry {
                    ts: now_secs(),
                    event: ShadowEvent::ValidationFailed,
                    secret_name: self.name.clone(),
                    context,
                });
                Ok(())
            }
            ref s => Err(ShadowError::InvalidTransition {
                from: s.clone(),
                to: PromotionStatus::Failed,
            }),
        }
    }

    /// Atomically promote: swap candidate → primary, clearing the candidate.
    ///
    /// Only allowed when status is [`PromotionStatus::Validated`].  After this
    /// call `self.primary` holds the former candidate value, and `self.candidate`
    /// is zeroized and set to an empty string.
    pub fn promote(&mut self, context: Option<String>) -> Result<(), ShadowError> {
        if self.promotion_status != PromotionStatus::Validated {
            return Err(ShadowError::InvalidTransition {
                from: self.promotion_status.clone(),
                to: PromotionStatus::Promoted,
            });
        }
        // Swap: primary ← candidate, candidate ← ""
        let mut old_candidate = std::mem::take(&mut self.candidate);
        self.primary.zeroize();
        self.primary = old_candidate.clone();
        old_candidate.zeroize();
        self.candidate = String::new();
        self.promotion_status = PromotionStatus::Promoted;
        self.audit_trail.push(ShadowAuditEntry {
            ts: now_secs(),
            event: ShadowEvent::Promoted,
            secret_name: self.name.clone(),
            context,
        });
        Ok(())
    }

    /// Abandon the candidate without promoting it.
    ///
    /// Zeroizes the candidate value and marks status as
    /// [`PromotionStatus::Abandoned`].  Can be called from any non-terminal
    /// state.
    pub fn abandon(&mut self, context: Option<String>) -> Result<(), ShadowError> {
        match self.promotion_status {
            PromotionStatus::Promoted | PromotionStatus::Abandoned => {
                return Err(ShadowError::InvalidTransition {
                    from: self.promotion_status.clone(),
                    to: PromotionStatus::Abandoned,
                });
            }
            _ => {}
        }
        self.candidate.zeroize();
        self.candidate = String::new();
        self.promotion_status = PromotionStatus::Abandoned;
        self.audit_trail.push(ShadowAuditEntry {
            ts: now_secs(),
            event: ShadowEvent::Abandoned,
            secret_name: self.name.clone(),
            context,
        });
        Ok(())
    }

    // ── Query helpers ────────────────────────────────────────────────────────

    /// Returns `true` if the candidate has expired based on the TTL.
    pub fn is_candidate_expired(&self) -> bool {
        match self.auto_promote_ttl_secs {
            Some(ttl) => now_secs() >= self.candidate_added_at + ttl,
            None => false,
        }
    }

    /// Seconds remaining until the candidate TTL expires, or `None` if no TTL
    /// is set.  Returns `0` when already expired.
    pub fn ttl_remaining_secs(&self) -> Option<u64> {
        self.auto_promote_ttl_secs.map(|ttl| {
            let expires_at = self.candidate_added_at + ttl;
            let now = now_secs();
            expires_at.saturating_sub(now)
        })
    }

    /// Returns `true` if this shadow is in a terminal state (promoted or
    /// abandoned) and safe to garbage-collect.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.promotion_status,
            PromotionStatus::Promoted | PromotionStatus::Abandoned
        )
    }

    /// Return the value to inject into the environment.
    ///
    /// When `PHANTOM_CANDIDATE_MODE=1` is set *and* the candidate is non-empty,
    /// returns the candidate; otherwise returns the primary.
    pub fn active_value(&self) -> &str {
        if std::env::var("PHANTOM_CANDIDATE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
            && !self.candidate.is_empty()
        {
            &self.candidate
        } else {
            &self.primary
        }
    }
}

// ── ShadowMeta ────────────────────────────────────────────────────────────────

/// Serialisable metadata for a shadow — does **not** contain secret values.
///
/// This is what we write to disk.  Values are loaded separately from the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowMeta {
    pub name: String,
    pub shadow_id: String,
    pub candidate_added_at: Timestamp,
    pub promotion_status: PromotionStatus,
    pub auto_promote_ttl_secs: Option<u64>,
    pub audit_trail: Vec<ShadowAuditEntry>,
}

impl ShadowMeta {
    fn from_secret(s: &ShadowedSecret) -> Self {
        Self {
            name: s.name.clone(),
            shadow_id: s.shadow_id.clone(),
            candidate_added_at: s.candidate_added_at,
            promotion_status: s.promotion_status.clone(),
            auto_promote_ttl_secs: s.auto_promote_ttl_secs,
            audit_trail: s.audit_trail.clone(),
        }
    }
}

// ── ShadowStore ───────────────────────────────────────────────────────────────

/// File-backed persistence layer for shadow metadata.
///
/// Values are **not** stored here — they live in the vault backend.
pub struct ShadowStore {
    dir: PathBuf,
}

impl ShadowStore {
    /// Create a new store backed by `dir`.  The directory is created if absent.
    pub fn new(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn meta_path(&self, name: &str) -> PathBuf {
        self.dir
            .join(format!("{}.shadow.json", sanitise_name(name)))
    }

    /// Persist shadow metadata for `secret`.
    pub fn save(&self, secret: &ShadowedSecret) -> std::io::Result<()> {
        let meta = ShadowMeta::from_secret(secret);
        let bytes = serde_json::to_vec_pretty(&meta)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_secret_file(&self.meta_path(&secret.name), &bytes)
    }

    /// Load shadow metadata for the named secret.  Returns `None` if no shadow
    /// exists.
    pub fn load_meta(&self, name: &str) -> std::io::Result<Option<ShadowMeta>> {
        let path = self.meta_path(name);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let meta: ShadowMeta = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(meta))
    }

    /// List all shadow metadata records stored in this directory.
    pub fn list_all(&self) -> std::io::Result<Vec<ShadowMeta>> {
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in rd {
            let entry = entry?;
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            if !fname_str.ends_with(".shadow.json") {
                continue;
            }
            let bytes = std::fs::read(entry.path())?;
            if let Ok(meta) = serde_json::from_slice::<ShadowMeta>(&bytes) {
                out.push(meta);
            }
        }
        Ok(out)
    }

    /// Delete the shadow metadata file for `name`.
    pub fn delete(&self, name: &str) -> std::io::Result<()> {
        let path = self.meta_path(name);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Garbage-collect terminal (promoted or abandoned) shadow records that are
    /// older than `max_age_secs`.
    ///
    /// Returns the names of the records that were removed.
    pub fn gc_stale(&self, max_age_secs: u64) -> std::io::Result<Vec<String>> {
        let now = now_secs();
        let all = self.list_all()?;
        let mut removed = Vec::new();
        for meta in all {
            let is_terminal = matches!(
                meta.promotion_status,
                PromotionStatus::Promoted | PromotionStatus::Abandoned
            );
            let age = now.saturating_sub(meta.candidate_added_at);
            if is_terminal && age > max_age_secs {
                self.delete(&meta.name)?;
                removed.push(meta.name);
            }
        }
        Ok(removed)
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by shadow operations.
#[derive(Debug, thiserror::Error)]
pub enum ShadowError {
    #[error("invalid state transition from '{from}' to '{to}'")]
    InvalidTransition {
        from: PromotionStatus,
        to: PromotionStatus,
    },

    #[error("no shadow exists for secret '{name}'")]
    NotFound { name: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("shadow is in terminal state '{status}' and cannot be modified")]
    Terminal { status: PromotionStatus },
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn generate_shadow_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Replace characters that are unsafe in file names.
fn sanitise_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Write `bytes` to `path` with mode 0600 on Unix, creating or truncating.
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        use std::io::Write;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        use std::io::Write;
        f.write_all(bytes)
    }
}

// ── Default shadow directory ──────────────────────────────────────────────────

/// Returns the default directory for shadow metadata for a given project.
///
/// Path: `~/.phantom/shadows/<project_id>/`
pub fn shadow_dir(project_id: &str) -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    home.join(".phantom")
        .join("shadows")
        .join(sanitise_name(project_id))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // Environment mutation is process-global. Keep candidate-mode cases from
    // racing under Rust's parallel test runner.
    static CANDIDATE_MODE_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn make_shadow() -> ShadowedSecret {
        ShadowedSecret::new("MY_KEY", "old_value", "new_value", None)
    }

    // ── ShadowedSecret lifecycle ──────────────────────────────────────────────

    #[test]
    fn test_new_shadow_has_pending_status() {
        let s = make_shadow();
        assert_eq!(s.promotion_status, PromotionStatus::Pending);
        assert_eq!(s.name, "MY_KEY");
        assert!(!s.shadow_id.is_empty());
        assert_eq!(s.audit_trail.len(), 1);
        assert_eq!(s.audit_trail[0].event, ShadowEvent::CandidateCreated);
    }

    #[test]
    fn test_record_validation_success_advances_status() {
        let mut s = make_shadow();
        s.record_validation_success(Some("validator=openai".to_string()))
            .unwrap();
        assert_eq!(s.promotion_status, PromotionStatus::Validated);
        assert_eq!(s.audit_trail.len(), 2);
        assert_eq!(s.audit_trail[1].event, ShadowEvent::ValidationPassed);
        assert_eq!(
            s.audit_trail[1].context.as_deref(),
            Some("validator=openai")
        );
    }

    #[test]
    fn test_record_validation_failure_sets_failed() {
        let mut s = make_shadow();
        s.record_validation_failure(Some("http 401".to_string()))
            .unwrap();
        assert_eq!(s.promotion_status, PromotionStatus::Failed);
        assert_eq!(
            s.audit_trail.last().unwrap().event,
            ShadowEvent::ValidationFailed
        );
    }

    #[test]
    fn test_promote_swaps_primary_and_candidate() {
        let mut s = make_shadow();
        s.record_validation_success(None).unwrap();
        s.promote(None).unwrap();
        assert_eq!(s.promotion_status, PromotionStatus::Promoted);
        assert_eq!(
            s.primary, "new_value",
            "primary should be the former candidate"
        );
        assert!(
            s.candidate.is_empty(),
            "candidate should be cleared after promotion"
        );
    }

    #[test]
    fn test_promote_requires_validated_status() {
        let mut s = make_shadow();
        let err = s.promote(None).unwrap_err();
        assert!(matches!(err, ShadowError::InvalidTransition { .. }));
    }

    #[test]
    fn test_failed_then_re_validate_then_promote() {
        let mut s = make_shadow();
        s.record_validation_failure(None).unwrap();
        // Can re-validate after failure
        s.record_validation_success(None).unwrap();
        s.promote(None).unwrap();
        assert_eq!(s.promotion_status, PromotionStatus::Promoted);
    }

    #[test]
    fn test_abandon_clears_candidate() {
        let mut s = make_shadow();
        s.abandon(Some("no longer needed".to_string())).unwrap();
        assert_eq!(s.promotion_status, PromotionStatus::Abandoned);
        assert!(s.candidate.is_empty());
        assert_eq!(s.audit_trail.last().unwrap().event, ShadowEvent::Abandoned);
    }

    #[test]
    fn test_cannot_abandon_already_promoted() {
        let mut s = make_shadow();
        s.record_validation_success(None).unwrap();
        s.promote(None).unwrap();
        let err = s.abandon(None).unwrap_err();
        assert!(matches!(err, ShadowError::InvalidTransition { .. }));
    }

    #[test]
    fn test_cannot_abandon_already_abandoned() {
        let mut s = make_shadow();
        s.abandon(None).unwrap();
        let err = s.abandon(None).unwrap_err();
        assert!(matches!(err, ShadowError::InvalidTransition { .. }));
    }

    #[test]
    fn test_is_terminal_pending_is_false() {
        let s = make_shadow();
        assert!(!s.is_terminal());
    }

    #[test]
    fn test_is_terminal_promoted_is_true() {
        let mut s = make_shadow();
        s.record_validation_success(None).unwrap();
        s.promote(None).unwrap();
        assert!(s.is_terminal());
    }

    #[test]
    fn test_is_terminal_abandoned_is_true() {
        let mut s = make_shadow();
        s.abandon(None).unwrap();
        assert!(s.is_terminal());
    }

    // ── TTL / expiry ──────────────────────────────────────────────────────────

    #[test]
    fn test_no_ttl_never_expired() {
        let s = ShadowedSecret::new("K", "p", "c", None);
        assert!(!s.is_candidate_expired());
        assert_eq!(s.ttl_remaining_secs(), None);
    }

    #[test]
    fn test_ttl_future_not_expired() {
        let s = ShadowedSecret::new("K", "p", "c", Some(3600));
        assert!(!s.is_candidate_expired());
        let remaining = s.ttl_remaining_secs().unwrap();
        assert!(remaining > 0 && remaining <= 3600);
    }

    #[test]
    fn test_ttl_past_is_expired() {
        let mut s = ShadowedSecret::new("K", "p", "c", Some(0));
        // Force candidate_added_at to the past
        s.candidate_added_at = now_secs().saturating_sub(10);
        assert!(s.is_candidate_expired());
        assert_eq!(s.ttl_remaining_secs(), Some(0));
    }

    // ── active_value ──────────────────────────────────────────────────────────

    #[test]
    fn test_active_value_returns_primary_by_default() {
        let _guard = CANDIDATE_MODE_ENV_LOCK.lock().unwrap();
        // Ensure PHANTOM_CANDIDATE_MODE is not set
        unsafe { std::env::remove_var("PHANTOM_CANDIDATE_MODE") };
        let s = make_shadow();
        assert_eq!(s.active_value(), "old_value");
    }

    #[test]
    fn test_active_value_returns_candidate_when_mode_set() {
        let _guard = CANDIDATE_MODE_ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("PHANTOM_CANDIDATE_MODE", "1") };
        let s = make_shadow();
        assert_eq!(s.active_value(), "new_value");
        unsafe { std::env::remove_var("PHANTOM_CANDIDATE_MODE") };
    }

    #[test]
    fn test_active_value_returns_primary_when_candidate_empty() {
        let _guard = CANDIDATE_MODE_ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("PHANTOM_CANDIDATE_MODE", "1") };
        let mut s = make_shadow();
        s.candidate = String::new();
        assert_eq!(s.active_value(), "old_value");
        unsafe { std::env::remove_var("PHANTOM_CANDIDATE_MODE") };
    }

    // ── ShadowStore ───────────────────────────────────────────────────────────

    #[test]
    fn test_store_save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = ShadowStore::new(dir.path()).unwrap();
        let s = make_shadow();
        store.save(&s).unwrap();
        let meta = store.load_meta("MY_KEY").unwrap().unwrap();
        assert_eq!(meta.name, "MY_KEY");
        assert_eq!(meta.shadow_id, s.shadow_id);
        assert_eq!(meta.promotion_status, PromotionStatus::Pending);
        assert_eq!(meta.candidate_added_at, s.candidate_added_at);
        assert_eq!(meta.audit_trail.len(), 1);
    }

    #[test]
    fn test_store_load_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = ShadowStore::new(dir.path()).unwrap();
        let meta = store.load_meta("MISSING").unwrap();
        assert!(meta.is_none());
    }

    #[test]
    fn test_store_save_updates_status() {
        let dir = TempDir::new().unwrap();
        let store = ShadowStore::new(dir.path()).unwrap();
        let mut s = make_shadow();
        store.save(&s).unwrap();

        s.record_validation_success(None).unwrap();
        s.promote(None).unwrap();
        store.save(&s).unwrap();

        let meta = store.load_meta("MY_KEY").unwrap().unwrap();
        assert_eq!(meta.promotion_status, PromotionStatus::Promoted);
        assert_eq!(meta.audit_trail.len(), 3); // created + validated + promoted
    }

    #[test]
    fn test_store_list_all_returns_all_records() {
        let dir = TempDir::new().unwrap();
        let store = ShadowStore::new(dir.path()).unwrap();

        let s1 = ShadowedSecret::new("KEY_A", "p1", "c1", None);
        let s2 = ShadowedSecret::new("KEY_B", "p2", "c2", None);
        store.save(&s1).unwrap();
        store.save(&s2).unwrap();

        let all = store.list_all().unwrap();
        assert_eq!(all.len(), 2);
        let names: Vec<&str> = all.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"KEY_A"));
        assert!(names.contains(&"KEY_B"));
    }

    #[test]
    fn test_store_delete_removes_record() {
        let dir = TempDir::new().unwrap();
        let store = ShadowStore::new(dir.path()).unwrap();
        let s = make_shadow();
        store.save(&s).unwrap();
        store.delete("MY_KEY").unwrap();
        assert!(store.load_meta("MY_KEY").unwrap().is_none());
    }

    #[test]
    fn test_store_gc_stale_removes_terminal_old_records() {
        let dir = TempDir::new().unwrap();
        let store = ShadowStore::new(dir.path()).unwrap();

        // Create a promoted record that is "old" by manipulating candidate_added_at
        let mut s = ShadowedSecret::new("OLD_KEY", "p", "c", None);
        s.candidate_added_at = now_secs().saturating_sub(100_000);
        s.record_validation_success(None).unwrap();
        s.promote(None).unwrap();
        store.save(&s).unwrap();

        // Create a pending record that should NOT be removed
        let s2 = ShadowedSecret::new("NEW_KEY", "p2", "c2", None);
        store.save(&s2).unwrap();

        let removed = store.gc_stale(86_400).unwrap();
        assert_eq!(removed, vec!["OLD_KEY".to_string()]);
        assert!(store.load_meta("OLD_KEY").unwrap().is_none());
        assert!(store.load_meta("NEW_KEY").unwrap().is_some());
    }

    #[test]
    fn test_store_gc_stale_keeps_recent_terminal_records() {
        let dir = TempDir::new().unwrap();
        let store = ShadowStore::new(dir.path()).unwrap();
        let mut s = make_shadow();
        s.record_validation_success(None).unwrap();
        s.promote(None).unwrap();
        store.save(&s).unwrap();

        // GC with a 1-day window — the record was just created so it's recent
        let removed = store.gc_stale(86_400).unwrap();
        assert!(removed.is_empty());
    }

    // ── Audit trail completeness ──────────────────────────────────────────────

    #[test]
    fn test_full_lifecycle_audit_trail() {
        let mut s = make_shadow();
        s.record_validation_failure(Some("timeout".to_string()))
            .unwrap();
        s.record_validation_success(Some("retry ok".to_string()))
            .unwrap();
        s.promote(Some("agent confirmed".to_string())).unwrap();

        assert_eq!(s.audit_trail.len(), 4);
        assert_eq!(s.audit_trail[0].event, ShadowEvent::CandidateCreated);
        assert_eq!(s.audit_trail[1].event, ShadowEvent::ValidationFailed);
        assert_eq!(s.audit_trail[2].event, ShadowEvent::ValidationPassed);
        assert_eq!(s.audit_trail[3].event, ShadowEvent::Promoted);
        assert_eq!(s.audit_trail[3].context.as_deref(), Some("agent confirmed"));
    }

    #[test]
    fn test_audit_trail_timestamps_are_monotonic() {
        let mut s = make_shadow();
        let t0 = s.audit_trail[0].ts;
        s.record_validation_success(None).unwrap();
        let t1 = s.audit_trail[1].ts;
        s.promote(None).unwrap();
        let t2 = s.audit_trail[2].ts;
        assert!(t0 <= t1, "timestamps must be non-decreasing");
        assert!(t1 <= t2);
    }

    #[test]
    fn test_audit_entry_never_contains_secret_value() {
        let mut s = make_shadow();
        s.record_validation_success(Some("context with no secrets".to_string()))
            .unwrap();
        s.promote(None).unwrap();
        for entry in &s.audit_trail {
            let serialised = serde_json::to_string(entry).unwrap();
            assert!(
                !serialised.contains("old_value"),
                "audit entry must not contain primary value"
            );
            assert!(
                !serialised.contains("new_value"),
                "audit entry must not contain candidate value"
            );
        }
    }

    #[test]
    fn test_shadow_meta_does_not_contain_secret_values() {
        let s = make_shadow();
        let meta = ShadowMeta::from_secret(&s);
        let serialised = serde_json::to_string(&meta).unwrap();
        assert!(!serialised.contains("old_value"));
        assert!(!serialised.contains("new_value"));
    }

    // ── generate_shadow_id uniqueness ─────────────────────────────────────────

    #[test]
    fn test_shadow_id_is_unique() {
        let ids: Vec<String> = (0..20).map(|_| generate_shadow_id()).collect();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), 20, "shadow IDs must be unique");
    }

    // ── sanitise_name ─────────────────────────────────────────────────────────

    #[test]
    fn test_sanitise_name_replaces_special_chars() {
        assert_eq!(sanitise_name("MY_KEY"), "MY_KEY");
        assert_eq!(sanitise_name("my-key"), "my-key");
        assert_eq!(sanitise_name("my.key/bad"), "my_key_bad");
    }

    // ── PromotionStatus display ───────────────────────────────────────────────

    #[test]
    fn test_promotion_status_display() {
        assert_eq!(PromotionStatus::Pending.to_string(), "pending");
        assert_eq!(PromotionStatus::Validated.to_string(), "validated");
        assert_eq!(PromotionStatus::Failed.to_string(), "failed");
        assert_eq!(PromotionStatus::Promoted.to_string(), "promoted");
        assert_eq!(PromotionStatus::Abandoned.to_string(), "abandoned");
    }
}
