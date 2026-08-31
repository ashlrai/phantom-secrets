//! MCP Nonce Approval — out-of-band authorization for mutating MCP tools.
//!
//! ## Problem
//!
//! MCP mutating tools (`phantom_add_secret`, `phantom_rotate`, etc.) previously
//! only checked a simple `confirm: true` boolean flag. A prompt-injected agent
//! can silently set that flag; there is no audit trail tying an approval to a
//! specific CLI invocation, and replay attacks are trivially possible.
//!
//! ## Solution — 3-tier approval flow
//!
//! 1. **Generate** — When a mutating MCP tool is called, the server generates a
//!    32-byte random nonce and a canonical arg-hash = HMAC-SHA256(sorted_json(params)).
//!    A pending approval record is written to `~/.phantom/mcp-approvals.jsonl`.
//!    The nonce is printed to stderr so the human user can see it.
//!
//! 2. **Approve** — The user runs `phantom mcp-approve <NONCE>` in a trusted
//!    terminal.  The CLI verifies the nonce exists, has not expired, and computes
//!    an approval token = HMAC-SHA256(nonce_hex || ":" || arg_hash_hex, approval_key).
//!    The approval event is written to the audit log.  The pending record is
//!    atomically marked approved with a fresh, short use window.
//!
//! 3. **Enforce** — The MCP tool handler requires
//!    `approval_token: "<nonce_hex>:<token_hex>"` in the request. The server
//!    validates the token against the stored nonce + arg-hash before allowing the
//!    mutation. Expired and already-used nonces are both rejected
//!    (replay-resistance).
//!
//! ## Storage
//!
//! Pending approvals: `~/.phantom/mcp-approvals.jsonl` (one JSON object per line)
//! Approval key:      `~/.phantom/mcp-approval-key`   (32 random bytes, hex, mode 0600)
//!
//! The approval key is machine-local and is generated on first use.

use hmac::{Hmac, Mac};
use lazy_static::lazy_static;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

// ── TTL ────────────────────────────────────────────────────────────────────────

/// Pending approvals expire after 5 minutes.
pub const APPROVAL_TTL_SECS: u64 = 300;

/// Approved tokens must be consumed within 5 minutes of terminal approval.
pub const APPROVED_USE_TTL_SECS: u64 = 300;

const APPROVAL_LOCK_FILE: &str = "mcp-approvals.lock";

lazy_static! {
    /// `flock`/Windows file locks provide the cross-process boundary. This
    /// mutex also makes ownership explicit between threads in this process,
    /// independent of platform-specific same-process file-lock semantics.
    static ref APPROVAL_PROCESS_LOCK: Mutex<()> = Mutex::new(());
}

// ── Paths ──────────────────────────────────────────────────────────────────────

/// Resolve the home directory from `HOME` / `USERPROFILE`.
///
/// Same idiom as `leak_correlation::home_dir` / `audit::dirs_home_dir`:
/// `dirs::home_dir()` ignores the `HOME` env var on Windows (it goes through
/// the Known Folder API), which breaks the tests' `with_temp_home` isolation
/// there — parallel tests would all share the real `~/.phantom` and bleed
/// records into each other. Honoring the env vars keeps test isolation
/// cross-platform while matching production behavior on every login shell.
fn home_dir() -> std::io::Result<PathBuf> {
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "HOME directory not found",
    ))
}

/// Returns `~/.phantom/mcp-approvals.jsonl`.
pub fn approvals_path() -> std::io::Result<PathBuf> {
    Ok(home_dir()?.join(".phantom").join("mcp-approvals.jsonl"))
}

/// Returns `~/.phantom/mcp-approval-key`.
pub fn approval_key_path() -> std::io::Result<PathBuf> {
    Ok(home_dir()?.join(".phantom").join("mcp-approval-key"))
}

fn approval_home() -> std::io::Result<PathBuf> {
    Ok(home_dir()?.join(".phantom"))
}

fn ensure_private_approval_home(path: &Path) -> std::io::Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "MCP approval storage directory is not a real directory",
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

fn require_regular_file_if_present(path: &Path, label: &str) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{label} is not a regular file"),
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn acquire_storage_lock() -> std::io::Result<ApprovalStorageLock> {
    let process_guard = APPROVAL_PROCESS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let home = approval_home()?;
    ensure_private_approval_home(&home)?;
    let lock_path = home.join(APPROVAL_LOCK_FILE);
    require_regular_file_if_present(&lock_path, "MCP approval lock")?;

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(lock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    fs2::FileExt::lock_exclusive(&file)?;
    Ok(ApprovalStorageLock {
        file,
        _process_guard: process_guard,
    })
}

// ── Data types ─────────────────────────────────────────────────────────────────

/// A pending (or approved) MCP approval record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Hex-encoded 32-byte nonce.
    pub nonce: String,
    /// MCP tool name that requested approval.
    pub tool_name: String,
    /// Hex-encoded HMAC-SHA256 over the sorted JSON of tool params.
    pub arg_hash: String,
    /// Project identifier (current directory path).
    pub project_id: String,
    /// Unix timestamp when this record was created.
    pub created_at: u64,
    /// Unix timestamp when this record expires. Pending records use the
    /// creation TTL; approved records get a fresh, bounded use window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Whether the nonce has been approved by the user.
    #[serde(default)]
    pub approved: bool,
    /// Unix timestamp of approval (absent until approved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<u64>,
}

impl ApprovalRecord {
    /// True if the record is no longer usable. Missing expiry metadata fails
    /// closed, including legacy approved records that previously lived forever.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(now_unix())
    }

    fn is_expired_at(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|expires_at| now >= expires_at)
    }
}

struct ApprovalStorageLock {
    file: File,
    _process_guard: MutexGuard<'static, ()>,
}

impl Drop for ApprovalStorageLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

// ── Approval key management ────────────────────────────────────────────────────

/// Load the approval HMAC key, generating + persisting it on first call.
pub fn load_or_create_approval_key() -> std::io::Result<Vec<u8>> {
    let _lock = acquire_storage_lock()?;
    load_or_create_approval_key_locked()
}

fn load_or_create_approval_key_locked() -> std::io::Result<Vec<u8>> {
    let key_path = approval_key_path()?;
    require_regular_file_if_present(&key_path, "MCP approval key")?;
    if key_path.exists() {
        return read_key(&key_path);
    }
    let key = generate_32_bytes();
    write_key_0600(&key_path, &key)?;
    Ok(key)
}

fn read_key(path: &Path) -> std::io::Result<Vec<u8>> {
    let hex_str = std::fs::read_to_string(path)?;
    hex::decode(hex_str.trim()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid approval key: {e}"),
        )
    })
}

fn write_key_0600(path: &Path, key: &[u8]) -> std::io::Result<()> {
    let hex_key = hex::encode(key);
    crate::fs::atomic_write(path, hex_key.as_bytes())
}

// ── Canonical arg-hash ─────────────────────────────────────────────────────────

/// Compute `HMAC-SHA256(key, canonical_json(params))` where `canonical_json`
/// serialises the params `BTreeMap` (keys sorted) as compact JSON.
///
/// The key used here is the approval key so the hash is keyed — an attacker
/// who can read the approvals file but not the key cannot forge an arg-hash.
///
/// Approval transport fields are intentionally excluded. The first MCP call
/// usually has `approval_token: null`, while the approved retry has the actual
/// token; hashing that field would make a legitimate retry look tampered.
pub fn compute_arg_hash(params_json: &str, key: &[u8]) -> String {
    // Parse to a BTreeMap so keys are sorted deterministically regardless of
    // how the caller serialised the original params object.
    let mut sorted: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(params_json).unwrap_or_default();
    sorted.remove("approval_token");
    sorted.remove("approval_nonce");
    let canonical = serde_json::to_string(&sorted).unwrap_or_else(|_| params_json.to_string());
    hmac_sha256_hex(key, canonical.as_bytes())
}

// ── Nonce generation ───────────────────────────────────────────────────────────

/// Generate a pending approval record, persist it, and return the nonce hex
/// string.  The caller (MCP server) should print the nonce to stderr.
///
/// `params_json` is the raw JSON of the tool's parameters (used for arg-hash).
pub fn generate_pending_approval(
    tool_name: &str,
    params_json: &str,
    project_id: &str,
) -> std::io::Result<String> {
    let _lock = acquire_storage_lock()?;
    let key = load_or_create_approval_key_locked()?;
    let path = approvals_path()?;
    let mut records = load_records_if_present(&path)?;
    records.retain(|record| !record.is_expired());

    let nonce = loop {
        let candidate = hex::encode(generate_32_bytes());
        if records.iter().all(|record| record.nonce != candidate) {
            break candidate;
        }
    };
    let arg_hash = compute_arg_hash(params_json, &key);
    let now = now_unix();

    let record = ApprovalRecord {
        nonce: nonce.clone(),
        tool_name: tool_name.to_string(),
        arg_hash,
        project_id: project_id.to_string(),
        created_at: now,
        expires_at: Some(now + APPROVAL_TTL_SECS),
        approved: false,
        approved_at: None,
    };

    records.push(record);
    rewrite_records(&path, &records)?;
    Ok(nonce)
}

// ── Approval token computation ─────────────────────────────────────────────────

/// Compute the approval token: `HMAC-SHA256(key, nonce_hex || ":" || arg_hash_hex)`.
///
/// This ties the token to both the specific nonce and the exact params that were
/// approved, preventing token reuse across different operations.
pub fn compute_approval_token(nonce: &str, arg_hash: &str, key: &[u8]) -> String {
    let message = format!("{nonce}:{arg_hash}");
    hmac_sha256_hex(key, message.as_bytes())
}

// ── CLI: approve a nonce ───────────────────────────────────────────────────────

/// Outcome returned by [`approve_nonce`].
#[derive(Debug)]
pub struct ApprovalOutcome {
    /// The computed approval token to present back to the MCP tool.
    pub approval_token: String,
    /// Tool name that was approved.
    pub tool_name: String,
    /// Arg-hash that was approved.
    pub arg_hash: String,
}

/// Called by `phantom mcp-approve <NONCE>`.
///
/// Verifies the nonce exists, has not expired, marks it approved, logs the
/// event, and returns the approval token.
pub fn approve_nonce(nonce_hex: &str) -> std::io::Result<ApprovalOutcome> {
    let _lock = acquire_storage_lock()?;
    let key = load_or_create_approval_key_locked()?;
    let path = approvals_path()?;

    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No pending approvals found. Generate one by calling the MCP tool first.".to_string(),
        ));
    }

    // Load all records, find and validate target.
    let mut records = load_all_records(&path)?;
    let idx = records.iter().position(|r| r.nonce == nonce_hex);

    let idx = idx.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Nonce '{nonce_hex}' not found. It may have expired or already been used."),
        )
    })?;

    {
        let rec = &records[idx];
        if rec.is_expired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "Nonce '{nonce_hex}' has expired (TTL {}s). \
                     Call the MCP tool again to generate a fresh nonce.",
                    APPROVAL_TTL_SECS
                ),
            ));
        }
        if rec.approved {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Nonce '{nonce_hex}' has already been approved."),
            ));
        }
    }

    // Mark approved.
    let now = now_unix();
    records[idx].approved = true;
    records[idx].approved_at = Some(now);
    records[idx].expires_at = Some(now.saturating_add(APPROVED_USE_TTL_SECS));

    let tool_name = records[idx].tool_name.clone();
    let arg_hash = records[idx].arg_hash.clone();

    // Rewrite the file atomically.
    rewrite_records(&path, &records)?;

    // Log to audit trail.
    crate::audit::log(
        "mcp.approval.granted",
        Some(&format!("{tool_name}:{nonce_hex}")),
    );

    let approval_token = compute_approval_token(nonce_hex, &arg_hash, &key);

    Ok(ApprovalOutcome {
        approval_token,
        tool_name,
        arg_hash,
    })
}

// ── MCP server: validate approval token ───────────────────────────────────────

/// Validate an approval token presented in an MCP tool call.
///
/// Returns `Ok(())` if valid, `Err(message)` otherwise.
///
/// The function:
/// 1. Loads the nonce record from storage.
/// 2. Checks the record is marked approved and not expired.
/// 3. Re-computes the expected arg-hash from the current `params_json`.
/// 4. Re-computes the expected approval token.
/// 5. Constant-time-compares with the presented token.
///
/// On success the nonce is consumed (deleted) to prevent replay.
pub fn validate_and_consume_approval(
    nonce_hex: &str,
    approval_token: &str,
    tool_name: &str,
    params_json: &str,
    project_id: &str,
) -> Result<(), String> {
    let _lock =
        acquire_storage_lock().map_err(|e| format!("Failed to lock approval storage: {e}"))?;
    let key = load_or_create_approval_key_locked()
        .map_err(|e| format!("Failed to load approval key: {e}"))?;

    let path = approvals_path().map_err(|e| format!("Failed to resolve approvals path: {e}"))?;

    if !path.exists() {
        return Err(
            "No pending approvals found. Run `phantom mcp-approve <NONCE>` first.".to_string(),
        );
    }

    let mut records =
        load_all_records(&path).map_err(|e| format!("Failed to load approvals: {e}"))?;

    let idx = records
        .iter()
        .position(|r| r.nonce == nonce_hex)
        .ok_or_else(|| {
            format!(
                "Nonce '{nonce_hex}' not found. It may have expired or been consumed. \
                 Call the tool again to generate a fresh nonce."
            )
        })?;

    {
        let rec = &records[idx];

        if rec.tool_name != tool_name {
            return Err(format!(
                "Approval nonce was issued for tool '{}', not '{tool_name}'.",
                rec.tool_name
            ));
        }

        if rec.project_id != project_id {
            return Err(format!(
                "Approval nonce was issued for project '{}', not '{project_id}'.",
                rec.project_id
            ));
        }

        if !rec.approved {
            return Err(format!(
                "Nonce '{nonce_hex}' has not been approved yet. \
                 Run `phantom mcp-approve {nonce_hex}` in a trusted terminal."
            ));
        }

        if rec.is_expired() {
            return Err(format!(
                "Approval token for nonce '{nonce_hex}' has expired. Call the tool again to generate a fresh nonce."
            ));
        }

        // Re-compute arg-hash from current params to detect param-substitution.
        let expected_arg_hash = compute_arg_hash(params_json, &key);
        if expected_arg_hash != rec.arg_hash {
            crate::audit::log(
                "mcp.approval.param_mismatch",
                Some(&format!("{tool_name}:{nonce_hex}")),
            );
            return Err(format!(
                "Approval token parameter mismatch for tool '{tool_name}'. \
                 The tool parameters have changed since the nonce was approved. \
                 This may indicate a replay or substitution attack."
            ));
        }

        // Verify the approval token.
        let expected_token = compute_approval_token(nonce_hex, &rec.arg_hash, &key);
        if !constant_time_eq(approval_token.as_bytes(), expected_token.as_bytes()) {
            crate::audit::log(
                "mcp.approval.invalid_token",
                Some(&format!("{tool_name}:{nonce_hex}")),
            );
            return Err(format!(
                "Invalid approval token for nonce '{nonce_hex}'. \
                 Possible replay attack or tampered token."
            ));
        }
    }

    // Consume the nonce (remove from storage) to prevent replay.
    records.remove(idx);
    rewrite_records(&path, &records).map_err(|e| format!("Failed to consume nonce: {e}"))?;

    crate::audit::log(
        "mcp.approval.consumed",
        Some(&format!("{tool_name}:{nonce_hex}")),
    );

    Ok(())
}

// ── Storage helpers ────────────────────────────────────────────────────────────

#[cfg(test)]
fn append_record(record: &ApprovalRecord) -> std::io::Result<()> {
    let _lock = acquire_storage_lock()?;
    let path = approvals_path()?;
    let mut records = load_records_if_present(&path)?;
    records.push(record.clone());
    rewrite_records(&path, &records)
}

fn load_records_if_present(path: &Path) -> std::io::Result<Vec<ApprovalRecord>> {
    require_regular_file_if_present(path, "MCP approval records")?;
    if path.exists() {
        load_all_records(path)
    } else {
        Ok(Vec::new())
    }
}

fn load_all_records(path: &Path) -> std::io::Result<Vec<ApprovalRecord>> {
    require_regular_file_if_present(path, "MCP approval records")?;
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut records = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record = serde_json::from_str::<ApprovalRecord>(trimmed).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid MCP approval record on line {}: {error}", index + 1),
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

fn rewrite_records(path: &Path, records: &[ApprovalRecord]) -> std::io::Result<()> {
    require_regular_file_if_present(path, "MCP approval records")?;
    let mut contents = Vec::new();
    for record in records {
        serde_json::to_writer(&mut contents, record)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        contents.push(b'\n');
    }
    crate::fs::atomic_write(path, &contents)
}

// ── Crypto helpers ─────────────────────────────────────────────────────────────

fn generate_32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time byte slice comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Public query helpers ───────────────────────────────────────────────────────

/// Return all non-expired pending approval records (for status display).
pub fn list_pending_approvals() -> std::io::Result<Vec<ApprovalRecord>> {
    let _lock = acquire_storage_lock()?;
    let path = approvals_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let records = load_all_records(&path)?;
    Ok(records
        .into_iter()
        .filter(|r| !r.approved && !r.is_expired())
        .collect())
}

/// Prune expired and consumed records from the approvals file.
pub fn prune_stale_approvals() -> std::io::Result<usize> {
    let _lock = acquire_storage_lock()?;
    let path = approvals_path()?;
    if !path.exists() {
        return Ok(0);
    }
    let records = load_all_records(&path)?;
    let kept: Vec<ApprovalRecord> = records
        .iter()
        .filter(|r| !r.is_expired())
        .cloned()
        .collect();
    let pruned = records.len() - kept.len();
    if pruned > 0 {
        rewrite_records(&path, &kept)?;
    }
    Ok(pruned)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn with_temp_home<F: FnOnce()>(f: F) {
        // Each test gets its own HOME so approval files don't bleed.
        // Use the shared ENV_LOCK from test_support so HOME mutations
        // in mcp_approval tests don't race with audit tests.
        let dir = TempDir::new().unwrap();
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var("HOME").ok();
        std::env::set_var("HOME", dir.path());
        f();
        match prev {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn test_nonce_generation() {
        with_temp_home(|| {
            let nonce = generate_pending_approval(
                "phantom_add_secret",
                r#"{"name":"API_KEY","confirm":true}"#,
                "proj-1",
            )
            .unwrap();
            assert_eq!(nonce.len(), 64, "nonce should be 32 bytes = 64 hex chars");
            // Should be parseable as hex.
            hex::decode(&nonce).unwrap();
        });
    }

    #[test]
    fn test_approval_roundtrip() {
        with_temp_home(|| {
            let nonce =
                generate_pending_approval("phantom_rotate", r#"{"confirm":true}"#, "proj-rotate")
                    .unwrap();

            // Approve it.
            let outcome = approve_nonce(&nonce).unwrap();
            assert_eq!(outcome.tool_name, "phantom_rotate");
            assert!(!outcome.approval_token.is_empty());

            // Validate and consume.
            validate_and_consume_approval(
                &nonce,
                &outcome.approval_token,
                "phantom_rotate",
                r#"{"confirm":true}"#,
                "proj-rotate",
            )
            .unwrap();
        });
    }

    #[test]
    fn approved_token_gets_fresh_bounded_use_window_and_expires() {
        with_temp_home(|| {
            let params = r#"{"confirm":true}"#;
            let nonce = generate_pending_approval("phantom_rotate", params, "proj-expiry").unwrap();
            let outcome = approve_nonce(&nonce).unwrap();
            let path = approvals_path().unwrap();
            let mut records = load_all_records(&path).unwrap();
            let record = records
                .iter_mut()
                .find(|record| record.nonce == nonce)
                .expect("approved record exists");
            let approved_at = record.approved_at.expect("approval timestamp");
            assert_eq!(
                record.expires_at,
                Some(approved_at.saturating_add(APPROVED_USE_TTL_SECS))
            );

            record.expires_at = Some(1);
            rewrite_records(&path, &records).unwrap();
            let error = validate_and_consume_approval(
                &nonce,
                &outcome.approval_token,
                "phantom_rotate",
                params,
                "proj-expiry",
            )
            .unwrap_err();
            assert!(error.contains("expired"), "unexpected error: {error}");
        });
    }

    #[test]
    fn test_ttl_expiration() {
        // Build a record that expired 1 second ago.
        let expired = ApprovalRecord {
            nonce: "deadbeef".to_string(),
            tool_name: "test_tool".to_string(),
            arg_hash: "aabbcc".to_string(),
            project_id: "test-project".to_string(),
            created_at: 0,
            expires_at: Some(1), // UNIX epoch + 1 second — long expired
            approved: false,
            approved_at: None,
        };
        assert!(expired.is_expired());

        // A non-expired unapproved record.
        let future_exp = now_unix() + 9999;
        let fresh = ApprovalRecord {
            expires_at: Some(future_exp),
            ..expired.clone()
        };
        assert!(!fresh.is_expired());

        // Approved records remain bounded by their use-window expiry.
        let approved_fresh = ApprovalRecord {
            approved: true,
            expires_at: Some(future_exp),
            ..expired.clone()
        };
        assert!(!approved_fresh.is_expired());

        let approved_expired = ApprovalRecord {
            approved: true,
            expires_at: Some(1),
            ..expired.clone()
        };
        assert!(approved_expired.is_expired());

        let legacy_unbounded = ApprovalRecord {
            approved: true,
            expires_at: None,
            ..expired
        };
        assert!(legacy_unbounded.is_expired());
    }

    #[test]
    fn test_arg_hash_deterministic() {
        with_temp_home(|| {
            let key = load_or_create_approval_key().unwrap();
            // Different key ordering should produce same hash (BTreeMap sorts).
            let h1 = compute_arg_hash(r#"{"b":2,"a":1}"#, &key);
            let h2 = compute_arg_hash(r#"{"a":1,"b":2}"#, &key);
            assert_eq!(h1, h2);

            // Different params should produce different hash.
            let h3 = compute_arg_hash(r#"{"a":1,"b":3}"#, &key);
            assert_ne!(h1, h3);
        });
    }

    #[test]
    fn test_arg_hash_ignores_approval_transport_fields() {
        with_temp_home(|| {
            let key = load_or_create_approval_key().unwrap();
            let base = compute_arg_hash(r#"{"name":"API_KEY","confirm":true}"#, &key);
            let with_null = compute_arg_hash(
                r#"{"name":"API_KEY","confirm":true,"approval_token":null}"#,
                &key,
            );
            let with_token = compute_arg_hash(
                r#"{"approval_nonce":"abc","approval_token":"abc:def","name":"API_KEY","confirm":true}"#,
                &key,
            );

            assert_eq!(base, with_null);
            assert_eq!(base, with_token);

            let changed = compute_arg_hash(
                r#"{"name":"OTHER_KEY","confirm":true,"approval_token":"abc:def"}"#,
                &key,
            );
            assert_ne!(base, changed);
        });
    }

    #[test]
    fn test_approved_retry_can_include_approval_token_field() {
        with_temp_home(|| {
            let nonce = generate_pending_approval(
                "phantom_add_secret",
                r#"{"name":"SAFE_KEY","confirm":true,"approval_token":null}"#,
                "proj-retry",
            )
            .unwrap();
            let outcome = approve_nonce(&nonce).unwrap();
            let combined = format!("{}:{}", nonce, outcome.approval_token);

            validate_and_consume_approval(
                &nonce,
                &outcome.approval_token,
                "phantom_add_secret",
                &format!(
                    r#"{{"name":"SAFE_KEY","confirm":true,"approval_token":"{}"}}"#,
                    combined
                ),
                "proj-retry",
            )
            .unwrap();
        });
    }

    #[test]
    fn test_approve_expired_nonce_rejected() {
        with_temp_home(|| {
            // Write an expired record directly.
            let path = approvals_path().unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let record = ApprovalRecord {
                nonce: "expirednonce1234".to_string(),
                tool_name: "phantom_rotate".to_string(),
                arg_hash: "aabbcc".to_string(),
                project_id: "proj".to_string(),
                created_at: 0,
                expires_at: Some(1),
                approved: false,
                approved_at: None,
            };
            append_record(&record).unwrap();

            let result = approve_nonce("expirednonce1234");
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("expired"), "expected expiry error, got: {msg}");
        });
    }

    #[test]
    fn test_replay_attack_rejected() {
        with_temp_home(|| {
            let nonce = generate_pending_approval(
                "phantom_remove_secret",
                r#"{"name":"KEY","confirm":true}"#,
                "proj-replay",
            )
            .unwrap();

            let outcome = approve_nonce(&nonce).unwrap();

            // First use: succeeds and consumes the nonce.
            validate_and_consume_approval(
                &nonce,
                &outcome.approval_token,
                "phantom_remove_secret",
                r#"{"name":"KEY","confirm":true}"#,
                "proj-replay",
            )
            .unwrap();

            // Second use with same token: must fail (nonce consumed).
            let result = validate_and_consume_approval(
                &nonce,
                &outcome.approval_token,
                "phantom_remove_secret",
                r#"{"name":"KEY","confirm":true}"#,
                "proj-replay",
            );
            assert!(result.is_err(), "replay should be rejected");
        });
    }

    #[test]
    fn concurrent_identical_consumption_allows_exactly_one_success() {
        with_temp_home(|| {
            use std::sync::{Arc, Barrier};

            const CALLERS: usize = 12;
            let params = r#"{"name":"KEY","confirm":true}"#;
            let project = "proj-concurrent-replay";
            let tool = "phantom_remove_secret";
            let nonce = generate_pending_approval(tool, params, project).unwrap();
            let outcome = approve_nonce(&nonce).unwrap();
            let barrier = Arc::new(Barrier::new(CALLERS));

            let handles = (0..CALLERS)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let nonce = nonce.clone();
                    let token = outcome.approval_token.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        validate_and_consume_approval(&nonce, &token, tool, params, project)
                    })
                })
                .collect::<Vec<_>>();

            let results = handles
                .into_iter()
                .map(|handle| handle.join().expect("consumer thread panicked"))
                .collect::<Vec<_>>();
            assert_eq!(
                results.iter().filter(|result| result.is_ok()).count(),
                1,
                "exactly one concurrent caller may consume an approval: {results:?}"
            );
            assert_eq!(
                results.iter().filter(|result| result.is_err()).count(),
                CALLERS - 1
            );
            assert!(load_all_records(&approvals_path().unwrap())
                .unwrap()
                .is_empty());
        });
    }

    #[test]
    fn test_stale_token_rejected() {
        with_temp_home(|| {
            let nonce = generate_pending_approval(
                "phantom_add_secret",
                r#"{"name":"MYKEY","confirm":true}"#,
                "proj-stale",
            )
            .unwrap();

            let outcome = approve_nonce(&nonce).unwrap();

            // Tamper with the token.
            let tampered = format!("{}ff", &outcome.approval_token[..62]);

            let result = validate_and_consume_approval(
                &nonce,
                &tampered,
                "phantom_add_secret",
                r#"{"name":"MYKEY","confirm":true}"#,
                "proj-stale",
            );
            assert!(result.is_err());
            let msg = result.unwrap_err();
            assert!(
                msg.contains("Invalid approval token"),
                "expected invalid-token error, got: {msg}"
            );
        });
    }

    #[test]
    fn test_param_substitution_rejected() {
        with_temp_home(|| {
            // Approve params for one secret name.
            let nonce = generate_pending_approval(
                "phantom_add_secret",
                r#"{"name":"SAFE_KEY","confirm":true}"#,
                "proj-subst",
            )
            .unwrap();
            let outcome = approve_nonce(&nonce).unwrap();

            // Try to use the token with different params (substitution attack).
            let result = validate_and_consume_approval(
                &nonce,
                &outcome.approval_token,
                "phantom_add_secret",
                r#"{"name":"EVIL_KEY","confirm":true}"#, // different params!
                "proj-subst",
            );
            assert!(result.is_err());
            let msg = result.unwrap_err();
            assert!(
                msg.contains("parameter mismatch") || msg.contains("mismatch"),
                "expected param-mismatch error, got: {msg}"
            );
        });
    }

    #[test]
    fn test_wrong_tool_rejected() {
        with_temp_home(|| {
            let nonce =
                generate_pending_approval("phantom_rotate", r#"{"confirm":true}"#, "proj-tool")
                    .unwrap();
            let outcome = approve_nonce(&nonce).unwrap();

            // Try to use approval for a different tool.
            let result = validate_and_consume_approval(
                &nonce,
                &outcome.approval_token,
                "phantom_remove_secret", // wrong tool
                r#"{"confirm":true}"#,
                "proj-tool",
            );
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_prune_stale_approvals() {
        with_temp_home(|| {
            // Write one expired + one valid pending record.
            let path = approvals_path().unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();

            let expired = ApprovalRecord {
                nonce: "oldnonce".to_string(),
                tool_name: "t".to_string(),
                arg_hash: "h".to_string(),
                project_id: "p".to_string(),
                created_at: 0,
                expires_at: Some(1),
                approved: false,
                approved_at: None,
            };
            let future_ts = now_unix() + 9999;
            let valid = ApprovalRecord {
                nonce: "freshnoce".to_string(),
                expires_at: Some(future_ts),
                created_at: now_unix(),
                ..expired.clone()
            };

            append_record(&expired).unwrap();
            append_record(&valid).unwrap();

            let pruned = prune_stale_approvals().unwrap();
            assert_eq!(pruned, 1);

            let remaining = load_all_records(&path).unwrap();
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].nonce, "freshnoce");
        });
    }
}
