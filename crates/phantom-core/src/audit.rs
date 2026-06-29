//! Opt-in audit log for vault and sync operations.
//!
//! Writes one JSON object per line to `~/.phantom/audit.log`. Disabled by
//! default; turn on by exporting `PHANTOM_AUDIT=1`. The log records the
//! **name** of secrets accessed (for forensics) but never the **value** —
//! values must never appear in the log under any circumstance.
//!
//! ## Schema (per line)
//! ```json
//! {"seq": 1, "ts": 1714794600, "op": "vault.store", "name": "OPENAI_API_KEY",
//!  "pid": 12345, "prev_hmac": "<64-hex>", "process": "phantom",
//!  "encrypted_context": "<base64-aes-gcm>",
//!  "hmac": "<64-hex>"}
//! ```
//!
//! `ts` is seconds since the UNIX epoch. `name` is omitted for ops that
//! don't operate on a single named secret (e.g. `cloud.push`).
//!
//! ## HMAC chain
//!
//! Each line's `hmac` = HMAC-SHA256(canonical_json_minus_hmac, key) where
//! `canonical_json_minus_hmac` is the JSON with keys in sorted order
//! (BTreeMap serialisation), `prev_hmac` included. The key is a per-machine
//! 32-byte random secret stored at `~/.phantom/audit-hmac-key` with mode
//! 0600 on Unix. The first line uses `prev_hmac = "GENESIS"`.
//!
//! **Security note:** an attacker with the same UID can read both the log
//! and the key. The integrity property defends against an attacker who only
//! obtained a copy of the log file (e.g. via a backup exfil).
//!
//! ## Backward compatibility
//!
//! Old lines without `hmac` are reported as "legacy (unsigned)" by
//! `verify_log()`. A marker line `{"hmac_chain_started_at": <ts>,
//! "key_id": "<hex-prefix>"}` is written once when the key is first
//! generated.
//!
//! ## Audit Event Encryption
//!
//! Sensitive metadata (process name, hostname, parent PID) is encrypted and
//! stored in the `encrypted_context` field. Three modes are supported:
//!
//! - `Disabled`: no encryption, no `encrypted_context` field (default).
//! - `LocalOnly`: AES-256-GCM with the file-vault HMAC key as the encryption key.
//! - `CloudSigned`: ED25519-signed events are buffered and pushed asynchronously
//!   to phm.dev for compliance-grade tamper-proof audit delivery.
//!
//! Set `PHANTOM_AUDIT_ENCRYPTION=local` or `PHANTOM_AUDIT_ENCRYPTION=cloud-signed`
//! to activate. Use `phantom audit verify --with-context` to decrypt and display
//! the stored context metadata.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

// ──────────────────────────────────────────────────────────────────────────────
// Encryption types
// ──────────────────────────────────────────────────────────────────────────────

/// Controls how sensitive audit event metadata is encrypted.
///
/// Set via `PHANTOM_AUDIT_ENCRYPTION` environment variable:
/// - unset / `none`: `Disabled` (default)
/// - `local`:  `LocalOnly` — AES-256-GCM keyed from the HMAC key
/// - `cloud-signed`: `CloudSigned` — ED25519-signed + async cloud upload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventEncryption {
    /// No encryption. `encrypted_context` field is omitted. (default)
    Disabled,
    /// Encrypt context with the per-machine HMAC key (AES-256-GCM).
    /// Context is decryptable locally via `phantom audit verify --with-context`.
    LocalOnly,
    /// Sign events with an ED25519 keypair stored in the OS keychain and
    /// upload them asynchronously to phm.dev for compliance-grade delivery.
    CloudSigned,
}

impl AuditEventEncryption {
    /// Parse from `PHANTOM_AUDIT_ENCRYPTION` env var.
    pub fn from_env() -> Self {
        match std::env::var("PHANTOM_AUDIT_ENCRYPTION")
            .ok()
            .as_deref()
        {
            Some("local" | "LOCAL" | "local-only" | "LOCAL-ONLY") => Self::LocalOnly,
            Some("cloud-signed" | "CLOUD-SIGNED" | "cloud_signed") => Self::CloudSigned,
            _ => Self::Disabled,
        }
    }

    /// Return true if any encryption is active.
    pub fn is_active(self) -> bool {
        self != Self::Disabled
    }
}

/// Sensitive metadata serialized into `encrypted_context`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditContext {
    /// Process name (argv[0] basename).
    pub process_name: String,
    /// Hostname of the machine.
    pub hostname: String,
    /// Parent process ID (0 if unavailable).
    pub ppid: u32,
    /// Current working directory (empty if unavailable).
    pub cwd: String,
}

impl AuditContext {
    pub fn collect() -> Self {
        Self {
            process_name: process_name(),
            hostname: hostname(),
            ppid: parent_pid(),
            cwd: std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }
    }
}

/// Status of the async sidecar upload queue (for compliance dashboards).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditSidecarStatus {
    /// Number of events currently buffered locally, not yet uploaded.
    pub pending: usize,
    /// Number of events successfully uploaded in this session.
    pub uploaded: usize,
    /// Number of upload failures in this session.
    pub failures: usize,
    /// Unix timestamp of the last successful upload (0 if none).
    pub last_uploaded_ts: u64,
    /// Unix timestamp of the last failure (0 if none).
    pub last_failure_ts: u64,
    /// Whether the sidecar uploader is currently running.
    pub running: bool,
}

/// An event buffered for cloud-signed sidecar upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Unix timestamp (seconds).
    pub ts: u64,
    /// Operation name.
    pub op: String,
    /// Secret name (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Base64-encoded encrypted context blob.
    pub encrypted_context: String,
    /// Hex-encoded ED25519 signature over the canonical JSON of this event.
    pub signature: String,
    /// Hex-encoded public key (for auditor verification).
    pub pubkey: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Global sidecar upload queue (fire-and-forget, no blocking)
// ──────────────────────────────────────────────────────────────────────────────

lazy_static::lazy_static! {
    static ref SIDECAR_QUEUE: Arc<Mutex<SidecarQueue>> =
        Arc::new(Mutex::new(SidecarQueue::new()));
}

struct SidecarQueue {
    events: std::collections::VecDeque<SidecarEvent>,
    status: AuditSidecarStatus,
}

impl SidecarQueue {
    fn new() -> Self {
        Self {
            events: std::collections::VecDeque::new(),
            status: AuditSidecarStatus::default(),
        }
    }

    fn push(&mut self, event: SidecarEvent) {
        self.events.push_back(event);
        self.status.pending += 1;
        self.status.running = true;
    }

    fn drain(&mut self) -> Vec<SidecarEvent> {
        let drained: Vec<_> = self.events.drain(..).collect();
        self.status.pending = self.status.pending.saturating_sub(drained.len());
        drained
    }

    fn record_upload_success(&mut self, count: usize) {
        self.status.uploaded += count;
        self.status.last_uploaded_ts = now_unix();
        if self.status.pending == 0 {
            self.status.running = false;
        }
    }

    fn record_failure(&mut self, count: usize) {
        self.status.failures += count;
        self.status.last_failure_ts = now_unix();
        self.status.running = false;
    }
}

/// Enqueue a `SidecarEvent` for async cloud upload (fire-and-forget).
/// This function returns immediately; upload is attempted in a background thread.
pub fn enqueue_sidecar_event(event: SidecarEvent) {
    if let Ok(mut q) = SIDECAR_QUEUE.lock() {
        q.push(event);
    }
    // Spawn a best-effort background flush.
    std::thread::spawn(flush_sidecar_queue);
}

/// Return the current sidecar upload queue status snapshot.
pub fn sidecar_status() -> AuditSidecarStatus {
    SIDECAR_QUEUE
        .lock()
        .map(|q| q.status.clone())
        .unwrap_or_default()
}

/// Flush the sidecar queue by attempting HTTP POST to phm.dev.
/// Best-effort: failures are recorded but never propagated.
fn flush_sidecar_queue() {
    let events = {
        let Ok(mut q) = SIDECAR_QUEUE.lock() else {
            return;
        };
        q.drain()
    };
    if events.is_empty() {
        return;
    }
    // Fire-and-forget HTTP POST (non-blocking Tokio handle not available here;
    // we use reqwest's blocking client so this background thread handles it).
    let count = events.len();
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        let body = serde_json::to_vec(&events)?;
        let resp = client
            .post("https://phm.dev/api/audit/ingest")
            .header("Content-Type", "application/json")
            .header("X-Phantom-Version", env!("CARGO_PKG_VERSION"))
            .body(body)
            .send()?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", resp.status()).into())
        }
    })();
    if let Ok(mut q) = SIDECAR_QUEUE.lock() {
        match result {
            Ok(()) => q.record_upload_success(count),
            Err(_) => q.record_failure(count),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditMode {
    Disabled,
    BestEffort,
    Required,
}

/// Return the current audit mode from `PHANTOM_AUDIT`.
///
/// Supported values:
/// - unset/anything else: disabled
/// - `1`, `true`: best-effort logging
/// - `required`, `fail-closed`: propagate audit write failures
pub fn mode() -> AuditMode {
    match std::env::var("PHANTOM_AUDIT").ok().as_deref() {
        Some("1" | "true" | "TRUE" | "True") => AuditMode::BestEffort,
        Some("required" | "REQUIRED" | "fail-closed" | "FAIL-CLOSED") => AuditMode::Required,
        _ => AuditMode::Disabled,
    }
}

/// Returns true if audit logging is currently enabled.
pub fn enabled() -> bool {
    mode() != AuditMode::Disabled
}

/// Log an audit event. Best-effort: errors are swallowed so audit failures
/// can never break a vault op. No-op when [`enabled`] is false.
///
/// # Important
/// `name` MUST be a secret name (e.g. `OPENAI_API_KEY`), never a secret
/// value. Callers in security-sensitive code paths must not pass values.
pub fn log(op: &str, name: Option<&str>) {
    let _ = log_result(op, name);
}

/// Log an audit event and propagate failures when `PHANTOM_AUDIT=required`.
///
/// Most legacy call sites should continue using [`log`]. Security-sensitive
/// operations that must fail closed can call this function directly.
pub fn log_result(op: &str, name: Option<&str>) -> std::io::Result<()> {
    match mode() {
        AuditMode::Disabled => Ok(()),
        AuditMode::BestEffort => {
            let _ = write_event(op, name, false);
            Ok(())
        }
        AuditMode::Required => write_event(op, name, true),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Rate-limit anomaly classification
// ──────────────────────────────────────────────────────────────────────────────

/// Anomaly classification emitted alongside each proxy rate-limit audit event.
///
/// The same enum lives in `phantom_proxy::rate_limiter` — this copy in
/// `phantom_core` lets the CLI and MCP server reference it without depending
/// on the proxy crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnomalyClass {
    /// Request is within normal access patterns.
    Normal,
    /// Request is elevated; may warrant monitoring.
    Caution,
    /// Burst threshold exceeded; request was rate-limited.
    Alert,
}

impl AnomalyClass {
    /// Numeric score (0 / 1 / 2) for `--min-anomaly-score` CLI filtering.
    pub fn score(self) -> u8 {
        match self {
            AnomalyClass::Normal => 0,
            AnomalyClass::Caution => 1,
            AnomalyClass::Alert => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AnomalyClass::Normal => "normal",
            AnomalyClass::Caution => "caution",
            AnomalyClass::Alert => "alert",
        }
    }

    /// Parse from a string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "normal" => Some(Self::Normal),
            "caution" => Some(Self::Caution),
            "alert" => Some(Self::Alert),
            _ => None,
        }
    }
}

/// A rate-limit event record — emitted when the proxy records an access and
/// detects an anomaly.  Written to the audit log as op `proxy.rate_event`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitEvent {
    /// Secret key name (never its value).
    pub secret_key: String,
    /// Requests for this secret in the last 10 seconds.
    pub per_secret_10s: u64,
    /// Total requests across all secrets in the last 10 seconds.
    pub total_10s: u64,
    /// Requests for this secret in the last 60 seconds.
    pub per_secret_60s: u64,
    /// Computed anomaly score 0–100.
    pub anomaly_score: u8,
    /// Anomaly classification.
    pub anomaly_class: AnomalyClass,
    /// Unix timestamp (seconds).
    pub ts: u64,
}

impl RateLimitEvent {
    /// Write this event to the audit log (best-effort; never panics).
    pub fn emit(&self) {
        if !enabled() {
            return;
        }
        // Only log caution/alert events to avoid flooding the audit log with
        // normal traffic.
        if self.anomaly_class == AnomalyClass::Normal {
            return;
        }
        log(
            "proxy.rate_event",
            Some(self.secret_key.as_str()),
        );
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Response leak events
// ──────────────────────────────────────────────────────────────────────────────

/// Severity level for a secret-leak event detected in an upstream API response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakSeverity {
    /// A vault secret value was found in the response body / header — confirmed
    /// exfiltration of a live credential.
    High,
    /// A response field matches a known secret format (e.g. `sk_*`, `ghp_*`)
    /// but does not correspond to a value in the active vault injection map.
    /// May indicate a hard-coded secret surfaced by the API.
    Medium,
}

impl LeakSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            LeakSeverity::High => "high",
            LeakSeverity::Medium => "medium",
        }
    }
}

/// The part of the HTTP response where the leak was detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakLocation {
    /// Leak found inside the response body.
    Body,
    /// Leak found inside a response header. Contains the header name.
    Header(String),
    /// Leak found in the HTTP status line (unusual, but possible in forwarded errors).
    StatusLine,
}

impl LeakLocation {
    pub fn as_label(&self) -> String {
        match self {
            LeakLocation::Body => "body".to_string(),
            LeakLocation::Header(name) => format!("header:{}", name),
            LeakLocation::StatusLine => "status-line".to_string(),
        }
    }
}

/// A high-severity audit event emitted when a real secret is detected leaking
/// back through an upstream API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakEvent {
    /// Unix timestamp (seconds).
    pub ts: u64,
    /// Where in the response the leak was detected.
    pub location: LeakLocation,
    /// Severity of the detected leak.
    pub severity: LeakSeverity,
    /// The secret name (key name, e.g. `OPENAI_API_KEY`) if the leaked value
    /// matched an active vault entry. `None` for format-only matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// The matched secret format pattern (e.g. `sk_live_*`, `ghp_*`).
    pub pattern: String,
    /// Number of times this pattern was found in the response (for deduplication).
    pub match_count: usize,
}

impl LeakEvent {
    /// Emit this leak event to the audit log (best-effort; never panics).
    ///
    /// Writes op `proxy.response_leak` with the secret name if known.
    pub fn emit(&self) {
        if !enabled() {
            return;
        }
        log("proxy.response_leak", self.secret_name.as_deref());
    }
}

/// Result of a log verification walk.
#[derive(Debug, Default)]
pub struct VerifyReport {
    pub verified: usize,
    pub tampered: usize,
    pub legacy: usize,
    pub malformed: usize,
    pub sequence_errors: usize,
    pub head_missing: bool,
    pub head_mismatch: bool,
    /// 1-based line numbers of lines that failed HMAC validation.
    pub tampered_lines: Vec<usize>,
    /// 1-based line numbers of malformed JSON lines.
    pub malformed_lines: Vec<usize>,
    /// 1-based line numbers of signed events with a non-monotonic `seq`.
    pub sequence_error_lines: Vec<usize>,
}

impl VerifyReport {
    /// True if no lines were found to be tampered, malformed, or out of sequence.
    pub fn is_clean(&self) -> bool {
        self.tampered == 0
            && self.malformed == 0
            && self.sequence_errors == 0
            && !self.head_missing
            && !self.head_mismatch
    }
}

/// Walk `~/.phantom/audit.log` and verify the HMAC chain.
///
/// - Lines with no `hmac` field are counted as **legacy**.
/// - The marker line (`hmac_chain_started_at`) is skipped silently.
/// - Malformed JSON lines are counted as **malformed** and fail verification.
/// - Lines with a bad `hmac` are counted as **tampered** and their
///   1-based line number is recorded in `tampered_lines`.
/// - New signed lines include a monotonic `seq`; sequence gaps or rewinds fail
///   verification. Older signed lines without `seq` are still accepted.
/// - New signed lines also update `audit-head.json`; verification fails if
///   the walked log does not match that signed head checkpoint.
///
/// **Deletion note:** deleting both the log and its head checkpoint cannot be
/// detected without an external checkpoint or backup.
pub fn verify_log() -> std::io::Result<VerifyReport> {
    let path = log_path()?;
    if !path.exists() {
        return Ok(VerifyReport::default());
    }

    let _lock = acquire_log_lock_shared(&path)?;
    let key = load_or_skip_hmac_key(&path)?;
    let content = std::fs::read_to_string(&path)?;
    verify_log_content(&content, key.as_deref(), &path)
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal — writing
// ──────────────────────────────────────────────────────────────────────────────

fn write_event(op: &str, name: Option<&str>, required: bool) -> std::io::Result<()> {
    let path = log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let lock_file = acquire_log_lock(&path)?;

    // Load (or generate) the HMAC key. If anything fails we fall back to
    // writing unsigned lines unless the caller explicitly requires audit.
    let key = if required {
        Some(load_or_create_hmac_key(&path)?)
    } else {
        load_or_create_hmac_key(&path).ok()
    };

    // Read the last line of the log to get the previous HMAC.
    let prev_hmac = if key.is_some() {
        read_last_hmac(&path).unwrap_or_else(|| "GENESIS".to_string())
    } else {
        "GENESIS".to_string()
    };
    let seq = if key.is_some() {
        read_last_seq(&path).saturating_add(1)
    } else {
        1
    };

    let enc_mode = AuditEventEncryption::from_env();
    let encrypted_context = if enc_mode.is_active() {
        key.as_ref()
            .and_then(|k| encrypt_context(k, enc_mode).ok())
    } else {
        None
    };

    let event = AuditEvent {
        seq,
        ts: now_unix(),
        op: op.to_string(),
        name: name.map(|s| s.to_string()),
        pid: std::process::id(),
        prev_hmac: key.as_ref().map(|_| prev_hmac.clone()),
        process: process_name(),
        encrypted_context: encrypted_context.clone(),
        hmac: None, // filled in below
    };

    let hmac_val = key.as_ref().map(|k| compute_hmac_for_event(&event, k));

    let event = AuditEvent {
        hmac: hmac_val.clone(),
        ..event
    };

    // Enqueue for cloud sidecar if CloudSigned mode is active.
    if enc_mode == AuditEventEncryption::CloudSigned {
        if let Some(ec) = &encrypted_context {
            if let Ok(sidecar) = build_sidecar_event(&event, ec) {
                enqueue_sidecar_event(sidecar);
            }
        }
    }

    let mut line = serde_json::to_vec(&event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');

    // OpenOptions::append on Linux/macOS gives O_APPEND atomicity for
    // writes <= PIPE_BUF (~4096 bytes) which our JSONL lines easily fit
    // under, so we don't take an explicit lock. Windows append semantics
    // are similar with FILE_APPEND_DATA.
    let mut f = OpenOptions::new().append(true).create(true).open(&path)?;
    f.write_all(&line)?;
    if let (Some(key), Some(hmac)) = (key.as_deref(), hmac_val.as_deref()) {
        write_head(&path, seq, hmac, key)?;
    }
    drop(lock_file);
    Ok(())
}

fn lock_path(log_path: &Path) -> PathBuf {
    log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("audit.lock")
}

fn acquire_log_lock(log_path: &Path) -> std::io::Result<File> {
    let lock_path = lock_path(log_path);
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock_file.lock_exclusive()?;
    Ok(lock_file)
}

fn acquire_log_lock_shared(log_path: &Path) -> std::io::Result<File> {
    let lock_path = lock_path(log_path);
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock_file.lock_shared()?;
    Ok(lock_file)
}

/// Scan from the end of the log file to find the last `hmac` value.
/// Returns `None` (i.e. "GENESIS") if the file is empty or has no signed lines.
fn read_last_hmac(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for raw in content.lines().rev() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(trimmed).ok()?;
        if let Some(h) = v.get("hmac").and_then(|h| h.as_str()) {
            return Some(h.to_string());
        }
    }
    None
}

/// Scan from the end of the log file to find the last signed event sequence.
/// Older signed lines did not carry `seq`; those are ignored so the first new
/// sequenced event starts at 1 while preserving HMAC-chain compatibility.
fn read_last_seq(path: &Path) -> u64 {
    let Some(content) = std::fs::read_to_string(path).ok() else {
        return 0;
    };
    for raw in content.lines().rev() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(v) = serde_json::from_str::<serde_json::Value>(trimmed).ok() else {
            continue;
        };
        if v.get("hmac").is_none() {
            continue;
        }
        if let Some(seq) = v.get("seq").and_then(|s| s.as_u64()) {
            return seq;
        }
    }
    0
}

// ──────────────────────────────────────────────────────────────────────────────
// HMAC key management — file-based, mode 0600
// ──────────────────────────────────────────────────────────────────────────────

fn hmac_key_path(log_path: &Path) -> PathBuf {
    log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("audit-hmac-key")
}

fn head_path(log_path: &Path) -> PathBuf {
    log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("audit-head.json")
}

/// Load existing key or generate + persist a new one.
/// On first generation, write the chain-started marker to the log.
fn load_or_create_hmac_key(log_path: &Path) -> std::io::Result<Vec<u8>> {
    let key_path = hmac_key_path(log_path);
    if key_path.exists() {
        return read_hmac_key(&key_path);
    }

    // Generate a new 32-byte key.
    let key = generate_key();
    write_hmac_key(&key_path, &key)?;

    // Write the chain-started marker into the log so `verify` knows
    // where the signed portion begins.
    write_chain_marker(log_path, &key)?;

    Ok(key)
}

/// Load the key for verification; returns `None` if the file doesn't exist.
fn load_or_skip_hmac_key(log_path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let key_path = hmac_key_path(log_path);
    if !key_path.exists() {
        return Ok(None);
    }
    read_hmac_key(&key_path).map(Some)
}

fn generate_key() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn write_hmac_key(key_path: &Path, key: &[u8]) -> std::io::Result<()> {
    let hex_key = hex::encode(key);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(key_path)?;
        f.write_all(hex_key.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(key_path)?;
        f.write_all(hex_key.as_bytes())?;
    }

    Ok(())
}

fn read_hmac_key(key_path: &Path) -> std::io::Result<Vec<u8>> {
    let hex_str = std::fs::read_to_string(key_path)?;
    hex::decode(hex_str.trim()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid audit HMAC key: {e}"),
        )
    })
}

fn write_chain_marker(log_path: &Path, key: &[u8]) -> std::io::Result<()> {
    // key_id is the first 8 hex chars of the key — just for human identification.
    let key_id = hex::encode(&key[..4]);
    let marker = serde_json::json!({
        "hmac_chain_started_at": now_unix(),
        "key_id": key_id,
    });
    let mut line = serde_json::to_vec(&marker)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)?;
    f.write_all(&line)
}

// ──────────────────────────────────────────────────────────────────────────────
// HMAC computation
// ──────────────────────────────────────────────────────────────────────────────

/// Compute HMAC for a fully-populated `AuditEvent` (hmac field must be None).
fn compute_hmac_for_event(event: &AuditEvent, key: &[u8]) -> String {
    let mut map: BTreeMap<&str, String> = BTreeMap::new();
    map.insert("seq", event.seq.to_string());
    map.insert("op", event.op.clone());
    map.insert("pid", event.pid.to_string());
    map.insert(
        "prev_hmac",
        event
            .prev_hmac
            .clone()
            .unwrap_or_else(|| "GENESIS".to_string()),
    );
    map.insert("process", event.process.clone());
    map.insert("ts", event.ts.to_string());
    if let Some(ref n) = event.name {
        map.insert("name", n.clone());
    }
    if let Some(ref ec) = event.encrypted_context {
        map.insert("encrypted_context", ec.clone());
    }

    let canonical = serde_json::to_string(&map).expect("BTreeMap serialization is infallible");
    hmac_sha256(key, canonical.as_bytes())
}

/// Compute HMAC from a `serde_json::Value` (the recorded line, `hmac` field
/// excluded). Used during verification.
fn compute_hmac_for_line(v: &serde_json::Value, key: &[u8]) -> String {
    let mut map: BTreeMap<&str, String> = BTreeMap::new();
    for field in &[
        "seq",
        "op",
        "pid",
        "prev_hmac",
        "process",
        "ts",
        "name",
        "encrypted_context",
    ] {
        if let Some(val) = v.get(field) {
            let s = match val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => val.to_string(),
            };
            map.insert(field, s);
        }
    }
    // prev_hmac defaults to GENESIS when absent (shouldn't happen for signed lines).
    map.entry("prev_hmac")
        .or_insert_with(|| "GENESIS".to_string());

    let canonical = serde_json::to_string(&map).expect("BTreeMap serialization is infallible");
    hmac_sha256(key, canonical.as_bytes())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

fn compute_hmac_for_head(version: u8, last_seq: u64, last_hmac: &str, key: &[u8]) -> String {
    let mut map: BTreeMap<&str, String> = BTreeMap::new();
    map.insert("last_hmac", last_hmac.to_string());
    map.insert("last_seq", last_seq.to_string());
    map.insert("version", version.to_string());
    let canonical = serde_json::to_string(&map).expect("BTreeMap serialization is infallible");
    hmac_sha256(key, canonical.as_bytes())
}

fn write_head(log_path: &Path, last_seq: u64, last_hmac: &str, key: &[u8]) -> std::io::Result<()> {
    let version = 1;
    let head = AuditHead {
        version,
        last_seq,
        last_hmac: last_hmac.to_string(),
        hmac: compute_hmac_for_head(version, last_seq, last_hmac, key),
    };
    let mut bytes = serde_json::to_vec(&head)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    crate::fs::atomic_write(&head_path(log_path), &bytes)
}

fn read_head(log_path: &Path, key: &[u8]) -> std::io::Result<Option<AuditHead>> {
    let path = head_path(log_path);
    if !path.exists() {
        return Ok(None);
    }
    let head: AuditHead = serde_json::from_slice(&std::fs::read(&path)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let expected = compute_hmac_for_head(head.version, head.last_seq, &head.last_hmac, key);
    if expected == head.hmac {
        Ok(Some(head))
    } else {
        Ok(Some(AuditHead {
            hmac: String::new(),
            last_seq: 0,
            last_hmac: String::new(),
            ..head
        }))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AuditEvent {
    seq: u64,
    ts: u64,
    op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hmac: Option<String>,
    process: String,
    /// Base64-encoded AES-256-GCM or ED25519-signed blob containing
    /// sensitive metadata (process name, hostname, parent PID, cwd).
    /// Absent when `AuditEventEncryption::Disabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditHead {
    version: u8,
    last_seq: u64,
    last_hmac: String,
    hmac: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Audit statistics
// ──────────────────────────────────────────────────────────────────────────────

/// Per-secret access statistics derived from the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretStats {
    /// Secret name (key name, e.g. `OPENAI_API_KEY`).
    pub name: String,
    /// Total number of logged operations for this secret.
    pub total: u64,
    /// Number of `vault.store` events (initial store or rotation).
    pub stores: u64,
    /// Number of `vault.retrieve` events.
    pub retrieves: u64,
    /// Number of `vault.delete` events.
    pub deletes: u64,
    /// Unix timestamp of the most recent event for this secret.
    pub last_seen_ts: u64,
    /// Unix timestamp of the first recorded event for this secret.
    pub first_seen_ts: u64,
}

/// Overall audit log statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total events in the log (excluding marker lines).
    pub total_events: u64,
    /// Total events that name a specific secret.
    pub secret_events: u64,
    /// Per-secret breakdown, sorted by total descending.
    pub secrets: Vec<SecretStats>,
    /// Unix timestamp of the earliest event in the log.
    pub first_event_ts: Option<u64>,
    /// Unix timestamp of the most recent event in the log.
    pub last_event_ts: Option<u64>,
}

/// Read `~/.phantom/audit.log` and compute aggregate statistics.
///
/// Returns `Ok(AuditStats)` even if the log file doesn't exist (all counts
/// will be zero). Returns `Err` only on I/O failures.
pub fn audit_stats() -> std::io::Result<AuditStats> {
    let path = log_path()?;

    if !path.exists() {
        return Ok(AuditStats {
            total_events: 0,
            secret_events: 0,
            secrets: vec![],
            first_event_ts: None,
            last_event_ts: None,
        });
    }

    let _lock = acquire_log_lock_shared(&path)?;
    let content = std::fs::read_to_string(&path)?;

    // name → mutable stats accumulator
    let mut by_name: std::collections::BTreeMap<String, SecretStats> =
        std::collections::BTreeMap::new();
    let mut total_events: u64 = 0;
    let mut secret_events: u64 = 0;
    let mut first_event_ts: Option<u64> = None;
    let mut last_event_ts: Option<u64> = None;

    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Skip the chain-started marker line.
        if v.get("hmac_chain_started_at").is_some() {
            continue;
        }
        // Must have "op" to count as an event.
        let op = match v.get("op").and_then(|o| o.as_str()) {
            Some(op) => op.to_string(),
            None => continue,
        };

        total_events += 1;

        let ts = v.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
        if ts > 0 {
            first_event_ts = Some(match first_event_ts {
                Some(prev) => prev.min(ts),
                None => ts,
            });
            last_event_ts = Some(match last_event_ts {
                Some(prev) => prev.max(ts),
                None => ts,
            });
        }

        if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
            secret_events += 1;
            let entry = by_name.entry(name.to_string()).or_insert_with(|| SecretStats {
                name: name.to_string(),
                total: 0,
                stores: 0,
                retrieves: 0,
                deletes: 0,
                last_seen_ts: 0,
                first_seen_ts: u64::MAX,
            });
            entry.total += 1;
            match op.as_str() {
                "vault.store" => entry.stores += 1,
                "vault.retrieve" => entry.retrieves += 1,
                "vault.delete" => entry.deletes += 1,
                _ => {}
            }
            if ts > 0 {
                if ts > entry.last_seen_ts {
                    entry.last_seen_ts = ts;
                }
                if ts < entry.first_seen_ts {
                    entry.first_seen_ts = ts;
                }
            }
        }
    }

    // Fix up first_seen_ts for entries that never saw a valid ts (leave as 0).
    for s in by_name.values_mut() {
        if s.first_seen_ts == u64::MAX {
            s.first_seen_ts = 0;
        }
    }

    // Sort by total descending, then alphabetically.
    let mut secrets: Vec<SecretStats> = by_name.into_values().collect();
    secrets.sort_by(|a, b| b.total.cmp(&a.total).then(a.name.cmp(&b.name)));

    Ok(AuditStats {
        total_events,
        secret_events,
        secrets,
        first_event_ts,
        last_event_ts,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Context encryption / decryption  (AES-256-GCM)
// ──────────────────────────────────────────────────────────────────────────────

/// Encrypt sensitive metadata into a base64 blob.
///
/// Layout: `nonce(12) || ciphertext+tag`
/// Key derivation: SHA-256("phantom-audit-context" || hmac_key) → 32 bytes.
fn encrypt_context(hmac_key: &[u8], _mode: AuditEventEncryption) -> std::io::Result<String> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let ctx = AuditContext::collect();
    let plaintext = serde_json::to_vec(&ctx)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Derive a 32-byte encryption key from the HMAC key.
    let enc_key = derive_encryption_key(hmac_key);

    let cipher = Aes256Gcm::new_from_slice(&enc_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    // Random 96-bit nonce.
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&blob))
}

/// Public wrapper around `encrypt_context` for integration tests.
///
/// Using a named export avoids leaking the private `encrypt_context` function
/// while still allowing test crates to exercise the encryption path directly.
pub fn encrypt_context_for_test(
    hmac_key: &[u8],
    mode: AuditEventEncryption,
) -> std::io::Result<String> {
    encrypt_context(hmac_key, mode)
}

/// Decrypt an `encrypted_context` base64 blob back to `AuditContext`.
pub fn decrypt_context(encrypted_b64: &str, hmac_key: &[u8]) -> std::io::Result<AuditContext> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let blob = BASE64
        .decode(encrypted_b64)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    if blob.len() < 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted_context blob too short",
        ));
    }

    let enc_key = derive_encryption_key(hmac_key);
    let cipher = Aes256Gcm::new_from_slice(&enc_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let nonce = Nonce::from_slice(&blob[..12]);
    let plaintext = cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Derive a 32-byte AES key from the HMAC key via SHA-256 with a domain label.
fn derive_encryption_key(hmac_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"phantom-audit-context\x00");
    hasher.update(hmac_key);
    hasher.finalize().into()
}

// ──────────────────────────────────────────────────────────────────────────────
// ED25519 key management + cloud-signed sidecar event builder
// ──────────────────────────────────────────────────────────────────────────────

/// Path to the ED25519 public key file used for cloud-signed audit events.
pub fn ed25519_pubkey_path(log_path: &Path) -> PathBuf {
    log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("audit-ed25519.pub")
}

fn ed25519_privkey_keychain_service() -> &'static str {
    "phantom-audit-ed25519-privkey"
}

/// Generate an ED25519 keypair, store the private key in the OS keychain,
/// write the public key to `~/.phantom/audit-ed25519.pub`, and return the
/// public key bytes and a hex-encoded SHA-256 hash of the public key (for
/// compliance auditor registration).
///
/// Returns `(pubkey_bytes, pubkey_hash_hex)`.
pub fn setup_ed25519_keypair() -> std::io::Result<([u8; 32], String)> {
    use ed25519_dalek::SigningKey;

    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();

    // Store private key in OS keychain.
    let privkey_hex = hex::encode(signing_key.to_bytes());
    let kr = keyring::Entry::new(
        ed25519_privkey_keychain_service(),
        &whoami_username(),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    kr.set_password(&privkey_hex)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Write public key to disk.
    let log_p = log_path()?;
    if let Some(parent) = log_p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let pubkey_b64 = BASE64.encode(pubkey_bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(ed25519_pubkey_path(&log_p))?;
        f.write_all(pubkey_b64.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(ed25519_pubkey_path(&log_p))?;
        f.write_all(pubkey_b64.as_bytes())?;
    }

    // Compute SHA-256 hash of the public key for auditor registration.
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    let hash = hex::encode(hasher.finalize());

    Ok((pubkey_bytes, hash))
}

/// Load the ED25519 signing key from the OS keychain, if present.
fn load_signing_key() -> Option<ed25519_dalek::SigningKey> {
    let kr = keyring::Entry::new(
        ed25519_privkey_keychain_service(),
        &whoami_username(),
    )
    .ok()?;
    let privkey_hex = kr.get_password().ok()?;
    let privkey_bytes = hex::decode(privkey_hex.trim()).ok()?;
    let bytes: [u8; 32] = privkey_bytes.try_into().ok()?;
    Some(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

/// Load the ED25519 public key bytes from `~/.phantom/audit-ed25519.pub`.
pub fn load_ed25519_pubkey() -> std::io::Result<Option<[u8; 32]>> {
    let log_p = log_path()?;
    let path = ed25519_pubkey_path(&log_p);
    if !path.exists() {
        return Ok(None);
    }
    let b64 = std::fs::read_to_string(&path)?;
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "bad ED25519 pubkey length")
    })?;
    Ok(Some(arr))
}

/// Build a `SidecarEvent` from an `AuditEvent` + encrypted context, signing it
/// with the ED25519 key from the OS keychain.
fn build_sidecar_event(
    event: &AuditEvent,
    encrypted_context: &str,
) -> std::io::Result<SidecarEvent> {
    use ed25519_dalek::Signer;

    let signing_key = load_signing_key().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ED25519 signing key not found in keychain; run `phantom setup --audit-mode cloud-signed`",
        )
    })?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    // Canonical payload to sign: BTreeMap JSON of event fields + encrypted_context.
    let mut canonical_map: BTreeMap<&str, String> = BTreeMap::new();
    canonical_map.insert("seq", event.seq.to_string());
    canonical_map.insert("ts", event.ts.to_string());
    canonical_map.insert("op", event.op.clone());
    canonical_map.insert("encrypted_context", encrypted_context.to_string());
    canonical_map.insert("pubkey", pubkey_hex.clone());
    if let Some(ref n) = event.name {
        canonical_map.insert("name", n.clone());
    }
    let payload =
        serde_json::to_vec(&canonical_map).expect("BTreeMap serialization is infallible");
    let signature = signing_key.sign(&payload);
    let sig_hex = hex::encode(signature.to_bytes());

    Ok(SidecarEvent {
        seq: event.seq,
        ts: event.ts,
        op: event.op.clone(),
        name: event.name.clone(),
        encrypted_context: encrypted_context.to_string(),
        signature: sig_hex,
        pubkey: pubkey_hex,
    })
}

/// Verify an ED25519 signature on a `SidecarEvent`.
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_sidecar_event(event: &SidecarEvent) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_bytes = match hex::decode(&event.pubkey) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pubkey_arr: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig_bytes = match hex::decode(&event.signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);

    let mut canonical_map: BTreeMap<&str, String> = BTreeMap::new();
    canonical_map.insert("seq", event.seq.to_string());
    canonical_map.insert("ts", event.ts.to_string());
    canonical_map.insert("op", event.op.clone());
    canonical_map.insert("encrypted_context", event.encrypted_context.clone());
    canonical_map.insert("pubkey", event.pubkey.clone());
    if let Some(ref n) = event.name {
        canonical_map.insert("name", n.clone());
    }
    let payload =
        serde_json::to_vec(&canonical_map).expect("BTreeMap serialization is infallible");

    verifying_key.verify(&payload, &signature).is_ok()
}

// ──────────────────────────────────────────────────────────────────────────────
// verify_log_with_context  (decrypts encrypted_context for forensics)
// ──────────────────────────────────────────────────────────────────────────────

/// A single log line with its decrypted context, returned by
/// `verify_log_with_context`.
#[derive(Debug)]
pub struct VerifiedEventWithContext {
    /// 1-based line number.
    pub line_no: usize,
    /// The raw JSONL line.
    pub raw: String,
    /// Decrypted context metadata (None if no `encrypted_context` field or
    /// decryption failed).
    pub context: Option<AuditContext>,
    /// Decryption error message, if decryption was attempted but failed.
    pub context_error: Option<String>,
}

/// Walk the audit log and decrypt `encrypted_context` fields for forensics.
///
/// Returns one `VerifiedEventWithContext` per non-marker event line.
/// Also performs full HMAC-chain verification; returns both the events and
/// the `VerifyReport`.
/// Internal: run the HMAC-chain verification over already-loaded content.
/// Called by both `verify_log` (after acquiring lock) and `verify_log_with_context`
/// (which holds its own lock for the full duration).
fn verify_log_content(
    content: &str,
    key: Option<&[u8]>,
    log_path: &Path,
) -> std::io::Result<VerifyReport> {
    let mut report = VerifyReport::default();
    let mut prev_hmac = "GENESIS".to_string();
    let mut chain_started = false;
    let mut expected_seq = 1_u64;
    let mut final_seq = None;
    let mut final_hmac = None;

    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                report.malformed += 1;
                report.malformed_lines.push(line_no);
                continue;
            }
        };
        if v.get("hmac_chain_started_at").is_some() {
            continue;
        }
        let hmac_field = v
            .get("hmac")
            .and_then(|h| h.as_str())
            .map(|s| s.to_string());

        match hmac_field {
            None => {
                report.legacy += 1;
            }
            Some(recorded_hmac) => {
                let key_bytes = match key {
                    Some(k) => k,
                    None => {
                        report.legacy += 1;
                        continue;
                    }
                };
                let line_prev = v
                    .get("prev_hmac")
                    .and_then(|h| h.as_str())
                    .unwrap_or("GENESIS");
                if !chain_started {
                    prev_hmac = line_prev.to_string();
                    chain_started = true;
                }
                let expected = compute_hmac_for_line(&v, key_bytes);
                if expected == recorded_hmac && line_prev == prev_hmac {
                    report.verified += 1;
                    if let Some(seq) = v.get("seq").and_then(|s| s.as_u64()) {
                        if seq != expected_seq {
                            report.sequence_errors += 1;
                            report.sequence_error_lines.push(line_no);
                        }
                        expected_seq = seq.saturating_add(1);
                        final_seq = Some(seq);
                        final_hmac = Some(recorded_hmac.clone());
                    }
                    prev_hmac = recorded_hmac;
                } else {
                    report.tampered += 1;
                    report.tampered_lines.push(line_no);
                    prev_hmac = recorded_hmac;
                }
            }
        }
    }

    if let (Some(seq), Some(hmac), Some(key_bytes)) =
        (final_seq, final_hmac.as_deref(), key)
    {
        match read_head(log_path, key_bytes)? {
            Some(head) if head.last_seq == seq && head.last_hmac == hmac => {}
            Some(_) => report.head_mismatch = true,
            None => report.head_missing = true,
        }
    }

    Ok(report)
}

pub fn verify_log_with_context()
-> std::io::Result<(VerifyReport, Vec<VerifiedEventWithContext>)> {
    let path = log_path()?;
    if !path.exists() {
        return Ok((VerifyReport::default(), vec![]));
    }

    // Take a single shared lock for the entire operation to avoid the
    // double-lock pattern that caused hangs on macOS.
    let _lock = acquire_log_lock_shared(&path)?;
    let key = load_or_skip_hmac_key(&path)?;
    let content = std::fs::read_to_string(&path)?;

    // Run the HMAC-chain verification inline (same logic as verify_log but
    // without re-acquiring the lock).
    let report = verify_log_content(&content, key.as_deref(), &path)?;

    // Build the per-event context list.
    let mut events = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("hmac_chain_started_at").is_some() {
            continue;
        }
        if v.get("op").is_none() {
            continue;
        }

        let (context, context_error) =
            if let Some(ec) = v.get("encrypted_context").and_then(|e| e.as_str()) {
                match key.as_deref() {
                    Some(k) => match decrypt_context(ec, k) {
                        Ok(ctx) => (Some(ctx), None),
                        Err(e) => (None, Some(e.to_string())),
                    },
                    None => (None, Some("HMAC key unavailable".to_string())),
                }
            } else {
                (None, None)
            };

        events.push(VerifiedEventWithContext {
            line_no,
            raw: trimmed.to_string(),
            context,
            context_error,
        });
    }

    Ok((report, events))
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────────────────────

pub fn log_path() -> std::io::Result<PathBuf> {
    if let Some(home) = dirs_home_dir() {
        Ok(home.join(".phantom").join("audit.log"))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not resolve home directory",
        ))
    }
}

fn dirs_home_dir() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    None
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "phantom".to_string())
}

fn hostname() -> String {
    // Try env var first (works in containers / CI without libc).
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    // Fall back to gethostname via std::process on Unix.
    #[cfg(unix)]
    {
        let mut buf = vec![0u8; 256];
        unsafe {
            if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                    return s.to_string();
                }
            }
        }
    }
    // Windows / fallback: read COMPUTERNAME.
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

fn parent_pid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: getppid() has no preconditions and always succeeds on POSIX.
        (unsafe { libc::getppid() }) as u32
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn whoami_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "phantom".to_string())
}

// ──────────────────────────────────────────────────────────────────────────────
// Team member lifecycle audit events
// ──────────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Batch rotation audit events
// ──────────────────────────────────────────────────────────────────────────────

/// Emit `vault.batch_rotation.started` — composite event logged once per batch.
///
/// Encodes the `batch_id` and `total_count` into the `name` field so it
/// passes through the existing single-name audit pipeline.
/// Best-effort — never panics or propagates errors.
pub fn log_batch_rotation_started(batch_id: &str, total_count: usize) {
    if !enabled() {
        return;
    }
    let name = format!("batch_id={batch_id} total={total_count}");
    log("vault.batch_rotation.started", Some(&name));
}

/// Emit `vault.batch_rotation.item.succeeded` for a single successfully rotated secret.
///
/// Best-effort — never panics or propagates errors.
pub fn log_batch_item_succeeded(batch_id: &str, secret_name: &str, provider: &str) {
    if !enabled() {
        return;
    }
    let name = format!("batch_id={batch_id} secret={secret_name} provider={provider}");
    log("vault.batch_rotation.item.succeeded", Some(&name));
}

/// Emit `vault.batch_rotation.item.failed` for a secret that failed rotation.
///
/// The `reason` field is a short human-readable error description; it MUST NOT
/// contain secret values.
/// Best-effort — never panics or propagates errors.
pub fn log_batch_item_failed(batch_id: &str, secret_name: &str, reason: &str) {
    if !enabled() {
        return;
    }
    // Truncate reason to 120 chars to avoid bloating the audit log.
    let safe_reason = if reason.len() > 120 { &reason[..120] } else { reason };
    let name = format!("batch_id={batch_id} secret={secret_name} reason={safe_reason}");
    log("vault.batch_rotation.item.failed", Some(&name));
}

/// Emit `vault.batch_rotation.completed` — composite summary event.
///
/// Best-effort — never panics or propagates errors.
pub fn log_batch_rotation_completed(
    batch_id: &str,
    total: usize,
    succeeded: usize,
    failed: usize,
) {
    if !enabled() {
        return;
    }
    let name = format!(
        "batch_id={batch_id} total={total} succeeded={succeeded} failed={failed}"
    );
    log("vault.batch_rotation.completed", Some(&name));
}

/// Emit a tamper-proof audit event when a member is revoked from a team vault.
///
/// Records:
/// - `op`: `team.member.revoked`
/// - `name`: the revoked member's GitHub login
/// - Extra fields are embedded in the `name` field as structured data so
///   they pass through the existing single-name audit pipeline. A richer
///   structured-event system can be layered on top later.
///
/// Best-effort — never panics or propagates errors.
pub fn log_team_member_revoked(
    team_id: &str,
    revoked_login: &str,
    remaining_logins: &[String],
    new_version: u64,
) {
    if !enabled() {
        return;
    }
    // Encode structured context into the `name` field:
    // "<team_id>/<revoked_login> remaining=N v=<version>"
    let name = format!(
        "{team_id}/{revoked_login} remaining={} v={new_version}",
        remaining_logins.len()
    );
    log("team.member.revoked", Some(&name));
}

/// Emit a tamper-proof audit event when the vault symmetric key is rotated.
///
/// Records `op`: `team.vault.key_rotated`.
/// Best-effort — never panics or propagates errors.
pub fn log_vault_key_rotated(team_id: &str, project_id: &str, new_version: u64) {
    if !enabled() {
        return;
    }
    let name = format!("{team_id}/{project_id} v={new_version}");
    log("team.vault.key_rotated", Some(&name));
}

/// Emit a tamper-proof audit event recording which members were re-wrapped
/// after a proactive vault rotation (no revocation).
///
/// Records `op`: `team.vault.rotation_members`.
/// Best-effort — never panics or propagates errors.
pub fn log_team_vault_rotation_members(
    team_id: &str,
    member_logins: &[String],
    new_version: u64,
) {
    if !enabled() {
        return;
    }
    let name = format!(
        "{team_id} members={} v={new_version}",
        member_logins.len()
    );
    log("team.vault.rotation_members", Some(&name));
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ENV_LOCK;
    use serde_json::Value;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn with_temp_home<F: FnOnce()>(env: &str, val: &str, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(env).ok();
        // SAFETY: env mutation is serialized via ENV_LOCK above.
        unsafe {
            std::env::set_var(env, val);
        }
        f();
        unsafe {
            match prev {
                Some(p) => std::env::set_var(env, p),
                None => std::env::remove_var(env),
            }
        }
    }

    // Helper: run a closure with HOME=tmp_dir and PHANTOM_AUDIT=1, then restore.
    fn with_audit_env<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("PHANTOM_AUDIT", "1");
        }
        f(tmp.path());
        unsafe {
            match prev_home {
                Some(p) => std::env::set_var("HOME", p),
                None => std::env::remove_var("HOME"),
            }
            match prev_audit {
                Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
                None => std::env::remove_var("PHANTOM_AUDIT"),
            }
        }
    }

    // ── existing tests (must still pass) ────────────────────────────────────

    #[test]
    fn disabled_by_default() {
        with_temp_home("PHANTOM_AUDIT", "", || {
            assert!(!enabled());
        });
    }

    #[test]
    fn enabled_when_env_set_to_one() {
        with_temp_home("PHANTOM_AUDIT", "1", || {
            assert!(enabled());
        });
    }

    #[test]
    fn required_mode_enabled() {
        with_temp_home("PHANTOM_AUDIT", "required", || {
            assert_eq!(mode(), AuditMode::Required);
            assert!(enabled());
        });
    }

    #[test]
    fn log_result_required_errors_when_home_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var("HOME").ok();
        let prev_userprofile = std::env::var("USERPROFILE").ok();
        let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("USERPROFILE");
            std::env::set_var("PHANTOM_AUDIT", "required");
        }

        let err = log_result("vault.store", Some("KEY")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);

        unsafe {
            match prev_home {
                Some(p) => std::env::set_var("HOME", p),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(p) => std::env::set_var("USERPROFILE", p),
                None => std::env::remove_var("USERPROFILE"),
            }
            match prev_audit {
                Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
                None => std::env::remove_var("PHANTOM_AUDIT"),
            }
        }
    }

    #[test]
    fn writes_jsonl_line_when_enabled() {
        with_audit_env(|tmp| {
            log("vault.store", Some("OPENAI_API_KEY"));
            log("cloud.push", None);

            let path = tmp.join(".phantom").join("audit.log");
            let content = std::fs::read_to_string(&path).expect("audit.log should exist");
            // 3 lines: marker + 2 events
            let lines: Vec<&str> = content.lines().collect();
            assert!(lines.len() >= 2, "expected at least 2 lines");

            // Find the event lines (skip the marker)
            let event_lines: Vec<Value> = lines
                .iter()
                .filter_map(|l| serde_json::from_str(l).ok())
                .filter(|v: &Value| v.get("hmac_chain_started_at").is_none())
                .collect();

            assert_eq!(event_lines.len(), 2);
            assert_eq!(event_lines[0]["op"], "vault.store");
            assert_eq!(event_lines[0]["name"], "OPENAI_API_KEY");
            assert!(event_lines[0]["pid"].is_number());
            assert!(event_lines[0]["ts"].is_number());

            assert_eq!(event_lines[1]["op"], "cloud.push");
            assert!(
                event_lines[1].get("name").is_none(),
                "name should be omitted for None"
            );
        });
    }

    #[test]
    fn no_file_written_when_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::remove_var("PHANTOM_AUDIT");
        }

        log("vault.store", Some("X"));
        let path = tmp.path().join(".phantom").join("audit.log");
        assert!(!path.exists(), "should not write when disabled");

        unsafe {
            match prev_home {
                Some(p) => std::env::set_var("HOME", p),
                None => std::env::remove_var("HOME"),
            }
            match prev_audit {
                Some(p) => std::env::set_var("PHANTOM_AUDIT", p),
                None => std::env::remove_var("PHANTOM_AUDIT"),
            }
        }
    }

    /// Defensive sanity: log() should NEVER write the value. We don't have
    /// a typed "value" parameter to begin with, but assert the schema's
    /// serialized form has no `value` key.
    #[test]
    fn schema_has_no_value_field() {
        let event = AuditEvent {
            seq: 1,
            ts: 0,
            op: "vault.store".to_string(),
            name: Some("KEY".to_string()),
            process: "phantom".to_string(),
            pid: 1,
            prev_hmac: None,
            encrypted_context: None,
            hmac: None,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.get("value").is_none());
    }

    // ── new HMAC chain tests ─────────────────────────────────────────────────

    /// Round-trip: write 3 events, verify all OK.
    #[test]
    fn hmac_chain_round_trip() {
        with_audit_env(|_tmp| {
            log("vault.store", Some("KEY_A"));
            log("vault.retrieve", Some("KEY_A"));
            log("cloud.push", None);

            let report = verify_log().expect("verify_log should not error");
            assert_eq!(report.tampered, 0, "no tampered lines expected");
            assert_eq!(report.verified, 3, "3 events should be verified");
            assert_eq!(report.malformed, 0);
            assert_eq!(report.sequence_errors, 0);
            assert!(report.is_clean());
        });
    }

    #[test]
    fn hmac_chain_writes_monotonic_sequence_numbers() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY_A"));
            log("vault.retrieve", Some("KEY_A"));

            let log_p = tmp.join(".phantom").join("audit.log");
            let content = std::fs::read_to_string(&log_p).unwrap();
            let seqs: Vec<u64> = content
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|v| v.get("hmac_chain_started_at").is_none())
                .map(|v| v.get("seq").and_then(|s| s.as_u64()).unwrap())
                .collect();
            assert_eq!(seqs, vec![1, 2]);
        });
    }

    #[test]
    fn hmac_chain_concurrent_writes_verify_clean() {
        with_audit_env(|tmp| {
            let workers = 32;
            let barrier = Arc::new(Barrier::new(workers));
            let mut handles = Vec::new();

            for i in 0..workers {
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    log("vault.retrieve", Some(&format!("KEY_{i}")));
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let report = verify_log().expect("verify_log should not error");
            assert!(report.is_clean(), "report should be clean: {report:?}");
            assert_eq!(report.verified, workers);

            let log_p = tmp.join(".phantom").join("audit.log");
            let content = std::fs::read_to_string(&log_p).unwrap();
            let mut seqs: Vec<u64> = content
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|v| v.get("hmac_chain_started_at").is_none())
                .map(|v| v.get("seq").and_then(|s| s.as_u64()).unwrap())
                .collect();
            seqs.sort_unstable();
            assert_eq!(seqs, (1..=workers as u64).collect::<Vec<_>>());
        });
    }

    /// Tamper: write 3 events, hand-edit line 2's op, verify reports TAMPERED.
    #[test]
    fn hmac_chain_detects_tamper() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY_A"));
            log("vault.retrieve", Some("KEY_A"));
            log("cloud.push", None);

            let log_p = tmp.join(".phantom").join("audit.log");
            let content = std::fs::read_to_string(&log_p).unwrap();
            let lines: Vec<&str> = content.lines().collect();

            // Find the first event line (skip marker) and tamper its op.
            let mut new_lines: Vec<String> = Vec::new();
            let mut tampered = false;
            for line in &lines {
                let v: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => {
                        new_lines.push(line.to_string());
                        continue;
                    }
                };
                if !tampered
                    && v.get("hmac_chain_started_at").is_none()
                    && v.get("op").and_then(|o| o.as_str()) == Some("vault.store")
                {
                    let mut obj = v.as_object().unwrap().clone();
                    obj.insert("op".to_string(), serde_json::json!("TAMPERED"));
                    new_lines.push(serde_json::to_string(&obj).unwrap());
                    tampered = true;
                } else {
                    new_lines.push(line.to_string());
                }
            }
            assert!(tampered, "should have found a line to tamper");
            std::fs::write(&log_p, new_lines.join("\n") + "\n").unwrap();

            let report = verify_log().expect("verify_log should not error");
            assert!(
                report.tampered >= 1,
                "should detect at least one tampered line"
            );
        });
    }

    #[test]
    fn hmac_chain_detects_malformed_line() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY_A"));

            let log_p = tmp.join(".phantom").join("audit.log");
            let mut content = std::fs::read_to_string(&log_p).unwrap();
            content.push_str("{not json}\n");
            std::fs::write(&log_p, content).unwrap();

            let report = verify_log().expect("verify_log should not error");
            assert_eq!(report.malformed, 1);
            assert_eq!(report.malformed_lines, vec![3]);
            assert!(!report.is_clean());
        });
    }

    #[test]
    fn hmac_chain_detects_sequence_gap() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY_A"));
            log("vault.retrieve", Some("KEY_A"));

            let log_p = tmp.join(".phantom").join("audit.log");
            let content = std::fs::read_to_string(&log_p).unwrap();
            let key = read_hmac_key(&hmac_key_path(&log_p)).unwrap();
            let mut changed = false;
            let mut new_lines = Vec::new();

            for line in content.lines() {
                let Ok(mut v) = serde_json::from_str::<Value>(line) else {
                    new_lines.push(line.to_string());
                    continue;
                };
                if !changed
                    && v.get("hmac_chain_started_at").is_none()
                    && v.get("seq").and_then(|s| s.as_u64()) == Some(2)
                {
                    v.as_object_mut()
                        .unwrap()
                        .insert("seq".to_string(), serde_json::json!(4));
                    let new_hmac = compute_hmac_for_line(&v, &key);
                    v.as_object_mut()
                        .unwrap()
                        .insert("hmac".to_string(), serde_json::json!(new_hmac));
                    changed = true;
                }
                new_lines.push(serde_json::to_string(&v).unwrap());
            }

            assert!(changed, "expected to rewrite the second event");
            std::fs::write(&log_p, new_lines.join("\n") + "\n").unwrap();

            let report = verify_log().expect("verify_log should not error");
            assert_eq!(report.tampered, 0);
            assert_eq!(report.sequence_errors, 1);
            assert_eq!(report.sequence_error_lines, vec![3]);
            assert!(!report.is_clean());
        });
    }

    /// Truncation: remove the last event line. The remaining HMAC chain is
    /// valid, but the signed head checkpoint should catch the missing tail.
    #[test]
    fn hmac_chain_detects_tail_truncation_with_head_checkpoint() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY_A"));
            log("vault.retrieve", Some("KEY_B"));
            log("cloud.push", None);

            let log_p = tmp.join(".phantom").join("audit.log");
            let content = std::fs::read_to_string(&log_p).unwrap();
            let mut lines: Vec<&str> = content.lines().collect();
            while lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
                lines.pop();
            }
            lines.pop(); // remove last event
            std::fs::write(&log_p, lines.join("\n") + "\n").unwrap();

            let report = verify_log().expect("verify_log should not error");
            assert_eq!(report.tampered, 0);
            assert!(report.verified >= 1);
            assert!(report.head_mismatch);
            assert!(!report.is_clean());
        });
    }

    #[test]
    fn hmac_chain_requires_head_checkpoint_for_sequenced_events() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY_A"));

            let log_p = tmp.join(".phantom").join("audit.log");
            std::fs::remove_file(head_path(&log_p)).unwrap();

            let report = verify_log().expect("verify_log should not error");
            assert!(report.head_missing);
            assert!(!report.is_clean());
        });
    }

    #[test]
    fn hmac_chain_detects_tampered_head_checkpoint() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY_A"));

            let log_p = tmp.join(".phantom").join("audit.log");
            let head_p = head_path(&log_p);
            let mut head: Value = serde_json::from_slice(&std::fs::read(&head_p).unwrap()).unwrap();
            head.as_object_mut()
                .unwrap()
                .insert("last_seq".to_string(), serde_json::json!(42));
            std::fs::write(&head_p, serde_json::to_vec(&head).unwrap()).unwrap();

            let report = verify_log().expect("verify_log should not error");
            assert!(report.head_mismatch);
            assert!(!report.is_clean());
        });
    }

    // ── audit_stats tests ────────────────────────────────────────────────────

    #[test]
    fn stats_empty_when_no_log() {
        with_audit_env(|tmp| {
            // Don't write any events — just check stats on a fresh dir.
            let log_p = tmp.join(".phantom").join("audit.log");
            // File doesn't exist yet.
            assert!(!log_p.exists());
            let stats = audit_stats().expect("audit_stats should not error");
            assert_eq!(stats.total_events, 0);
            assert_eq!(stats.secret_events, 0);
            assert!(stats.secrets.is_empty());
            assert!(stats.first_event_ts.is_none());
            assert!(stats.last_event_ts.is_none());
        });
    }

    #[test]
    fn stats_counts_ops_correctly() {
        with_audit_env(|_tmp| {
            log("vault.store", Some("OPENAI_API_KEY"));
            log("vault.retrieve", Some("OPENAI_API_KEY"));
            log("vault.retrieve", Some("OPENAI_API_KEY"));
            log("vault.store", Some("STRIPE_KEY"));
            log("cloud.push", None); // no name — counts as total but not secret_events

            let stats = audit_stats().expect("audit_stats should not error");
            assert_eq!(stats.total_events, 5);
            assert_eq!(stats.secret_events, 4);

            // Sorted by total desc: OPENAI_API_KEY (3) before STRIPE_KEY (1).
            assert_eq!(stats.secrets.len(), 2);
            let openai = &stats.secrets[0];
            assert_eq!(openai.name, "OPENAI_API_KEY");
            assert_eq!(openai.total, 3);
            assert_eq!(openai.stores, 1);
            assert_eq!(openai.retrieves, 2);
            assert_eq!(openai.deletes, 0);

            let stripe = &stats.secrets[1];
            assert_eq!(stripe.name, "STRIPE_KEY");
            assert_eq!(stripe.total, 1);
            assert_eq!(stripe.stores, 1);
        });
    }

    #[test]
    fn stats_delete_counted() {
        with_audit_env(|_tmp| {
            log("vault.store", Some("MY_KEY"));
            log("vault.delete", Some("MY_KEY"));

            let stats = audit_stats().expect("audit_stats should not error");
            let s = &stats.secrets[0];
            assert_eq!(s.deletes, 1);
            assert_eq!(s.total, 2);
        });
    }

    #[test]
    fn stats_timestamps_tracked() {
        with_audit_env(|_tmp| {
            log("vault.store", Some("K"));
            log("vault.retrieve", Some("K"));

            let stats = audit_stats().expect("audit_stats should not error");
            assert!(stats.first_event_ts.is_some());
            assert!(stats.last_event_ts.is_some());
            // last >= first
            assert!(stats.last_event_ts.unwrap() >= stats.first_event_ts.unwrap());

            let s = &stats.secrets[0];
            assert!(s.last_seen_ts >= s.first_seen_ts);
        });
    }

    #[test]
    fn stats_sorted_by_total_desc_then_alpha() {
        with_audit_env(|_tmp| {
            log("vault.retrieve", Some("Z_KEY"));
            log("vault.retrieve", Some("A_KEY"));
            log("vault.retrieve", Some("A_KEY"));

            let stats = audit_stats().expect("audit_stats should not error");
            assert_eq!(stats.secrets[0].name, "A_KEY");  // 2 total
            assert_eq!(stats.secrets[1].name, "Z_KEY");  // 1 total
        });
    }

    #[test]
    fn stats_skips_marker_and_malformed_lines() {
        with_audit_env(|tmp| {
            log("vault.store", Some("KEY"));

            // Manually append a malformed line.
            let log_p = tmp.join(".phantom").join("audit.log");
            let mut f = std::fs::OpenOptions::new().append(true).open(&log_p).unwrap();
            use std::io::Write;
            writeln!(f, "{{not json}}").unwrap();

            let stats = audit_stats().expect("audit_stats should not error");
            // Malformed line is skipped — only the 1 real event counted.
            assert_eq!(stats.total_events, 1);
        });
    }

    /// Legacy: pre-write unsigned lines, then enable chain; verify reports legacy + verified.
    #[test]
    fn hmac_chain_legacy_lines_reported() {
        with_audit_env(|tmp| {
            let log_p = tmp.join(".phantom").join("audit.log");
            std::fs::create_dir_all(log_p.parent().unwrap()).unwrap();

            let legacy1 = r#"{"ts":1700000000,"op":"vault.store","name":"OLD_KEY","process":"phantom","pid":1}"#;
            let legacy2 = r#"{"ts":1700000060,"op":"cloud.push","process":"phantom","pid":2}"#;
            std::fs::write(&log_p, format!("{}\n{}\n", legacy1, legacy2)).unwrap();

            // Now log new events — key is generated, chain starts.
            log("vault.store", Some("NEW_KEY"));
            log("cloud.push", None);

            let report = verify_log().expect("verify_log should not error");
            assert_eq!(report.legacy, 2, "two legacy lines expected");
            assert_eq!(report.verified, 2, "two signed lines expected");
            assert_eq!(report.tampered, 0);
        });
    }
}
