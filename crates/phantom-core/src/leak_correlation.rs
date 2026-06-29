//! Leak Incident Correlation Engine
//!
//! Reads `proxy.response_leak` audit events, groups related leaks by
//! `(secret_name, location)` within time windows, computes incident
//! confidence scores, persists incident summaries to
//! `~/.phantom/leak-incidents.jsonl` with deduplication, and emits
//! warnings to stderr for high-confidence incidents.
//!
//! ## Confidence model
//!
//! | Condition                              | Confidence |
//! |----------------------------------------|------------|
//! | Single `proxy.response_leak` event     | 0.5        |
//! | >3 events for same secret within 1h   | 0.95       |
//! | 2–3 events (linear interpolation)     | 0.5–0.95   |
//!
//! ## Persistence
//!
//! Incidents are appended to `~/.phantom/leak-incidents.jsonl` (one JSON
//! object per line). Deduplication is based on `incident_id`, which is a
//! SHA-256 hash of `(secret_name, location_label, first_seen_ts / 3600)`
//! — so a new incident is created at most once per hour per
//! `(secret, location)` pair.
//!
//! Incidents with `first_seen_ts` older than 24 h are excluded from
//! `LeakCorrelationEngine::active_incidents()`.
//!
//! ## Rotation clearing
//!
//! When a secret is rotated (a `vault.store` event is appended after a
//! prior leak incident for the same name), subsequent calls to
//! `active_incidents()` exclude incidents whose `secret_name` has a
//! `vault.store` event newer than the incident's `last_seen_ts`.
//!
//! ## Contextual Leak Profiles (Adaptive Scrubbing)
//!
//! [`ContextualLeakProfileStore`] tracks `(secret_name, json_path,
//! content_type, status_code)` tuples observed across real leak events.
//! When a combination is seen ≥ `PROFILE_CONFIDENCE_THRESHOLD` times its
//! confidence reaches 1.0 and the response scrubber uses it for
//! **aggressive path-targeted redaction** — catching secrets even when
//! the exact vault value isn't present (e.g. rotated keys that share
//! the same structural location).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────────────────────────────────────
// Contextual Leak Profiles — Adaptive Scrubbing Intelligence
// ──────────────────────────────────────────────────────────────────────────────

/// Minimum observation count before a (secret, path) combination is considered
/// a high-confidence leak profile and triggers aggressive path-targeted scrubbing.
pub const PROFILE_CONFIDENCE_THRESHOLD: u32 = 3;

/// HTTP request metadata captured alongside each proxy response for enriching
/// leak profiles.  This is passed by the proxy on every response scrub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RequestContext {
    /// HTTP method of the originating request (e.g. "POST", "GET").
    pub method: String,
    /// URL path of the originating request (e.g. "/v1/chat/completions").
    pub url_path: String,
    /// Value of the Content-Type response header (e.g. "application/json").
    pub content_type: String,
    /// HTTP response status code (e.g. 200, 401, 500).
    pub status_code: u16,
}

impl RequestContext {
    pub fn new(method: &str, url_path: &str, content_type: &str, status_code: u16) -> Self {
        Self {
            method: method.to_uppercase(),
            url_path: url_path.to_string(),
            content_type: content_type.to_string(),
            status_code,
        }
    }
}

/// A single observation that a secret leaked at a specific JSON path inside a
/// response from a specific endpoint.
///
/// JSON paths use a simplified dot-notation: `.data.live_key`, `.error.message`,
/// `.[]` for array elements, etc.  The path is extracted by the adaptive
/// scrubber when it detects a vault value inside a parsed JSON tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeakPathObservation {
    /// The secret name (e.g. `STRIPE_KEY`). Never the value.
    pub secret_name: String,
    /// Dot-notation JSON path where the leak was observed (e.g. `.data.live_key`).
    pub json_path: String,
    /// Content-Type of the response at the time of observation.
    pub content_type: String,
    /// HTTP status code of the response at the time of observation.
    pub status_code: u16,
    /// Number of times this exact `(secret_name, json_path, content_type, status_code)`
    /// combination has been observed.
    pub observation_count: u32,
    /// Confidence score in [0.0, 1.0] — rises to 1.0 at `PROFILE_CONFIDENCE_THRESHOLD` observations.
    pub confidence: f64,
    /// Unix timestamp of the first observation.
    pub first_seen_ts: u64,
    /// Unix timestamp of the most recent observation.
    pub last_seen_ts: u64,
}

impl LeakPathObservation {
    fn new(
        secret_name: String,
        json_path: String,
        content_type: String,
        status_code: u16,
        ts: u64,
    ) -> Self {
        Self {
            secret_name,
            json_path,
            content_type,
            status_code,
            observation_count: 1,
            confidence: confidence_from_count(1),
            first_seen_ts: ts,
            last_seen_ts: ts,
        }
    }

    fn record_observation(&mut self, ts: u64) {
        self.observation_count += 1;
        self.confidence = confidence_from_count(self.observation_count);
        self.last_seen_ts = ts;
    }

    /// Returns true when confidence is high enough for aggressive redaction.
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.95
    }
}

/// Confidence from observation count:
/// - 1 observation  → 0.40
/// - 2 observations → 0.70
/// - ≥3 observations → 0.95+ (capped at 1.0)
fn confidence_from_count(count: u32) -> f64 {
    match count {
        0 => 0.0,
        1 => 0.40,
        2 => 0.70,
        c => {
            let extra = (c - 2) as f64 * 0.10;
            (0.90 + extra).min(1.0)
        }
    }
}

/// In-memory + file-backed store of contextual leak path observations.
///
/// The store is keyed by `(secret_name, json_path, content_type, status_code)`.
/// Observations are persisted to `~/.phantom/leak-profiles.jsonl` so they
/// survive across proxy restarts.
///
/// ## Usage by the adaptive scrubber
///
/// After each scrub the scrubber calls [`record_leak`] with the secret name,
/// observed JSON path, and request context.  On subsequent responses the
/// scrubber calls [`high_confidence_paths_for`] to obtain paths known to
/// leak a given secret, then applies aggressive redaction to any value at
/// those paths regardless of exact token match.
pub struct ContextualLeakProfileStore {
    profiles_path: PathBuf,
    /// In-memory observations. Key: (secret_name, json_path, content_type, status_code).
    observations: HashMap<(String, String, String, u16), LeakPathObservation>,
}

impl ContextualLeakProfileStore {
    /// Create using default path derived from `HOME`.
    pub fn new() -> std::io::Result<Self> {
        let home = home_dir()?;
        Ok(Self::with_path(
            home.join(".phantom").join("leak-profiles.jsonl"),
        ))
    }

    /// Create with a custom path (used in tests).
    pub fn with_path(profiles_path: PathBuf) -> Self {
        Self {
            profiles_path,
            observations: HashMap::new(),
        }
    }

    /// Load persisted profiles from disk into memory.
    pub fn load(&mut self) -> std::io::Result<()> {
        if !self.profiles_path.exists() {
            return Ok(());
        }
        let file = std::fs::File::open(&self.profiles_path)?;
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(obs) = serde_json::from_str::<LeakPathObservation>(trimmed) {
                let key = (
                    obs.secret_name.clone(),
                    obs.json_path.clone(),
                    obs.content_type.clone(),
                    obs.status_code,
                );
                self.observations.insert(key, obs);
            }
        }
        Ok(())
    }

    /// Record a new observation of `secret_name` leaking at `json_path` in a
    /// response with the given `ctx`.  Persists the updated observation to disk.
    pub fn record_leak(
        &mut self,
        secret_name: &str,
        json_path: &str,
        ctx: &RequestContext,
    ) -> std::io::Result<()> {
        let ts = now_unix();
        let key = (
            secret_name.to_string(),
            json_path.to_string(),
            ctx.content_type.clone(),
            ctx.status_code,
        );
        let is_new = !self.observations.contains_key(&key);
        let obs = self.observations.entry(key).or_insert_with(|| {
            LeakPathObservation::new(
                secret_name.to_string(),
                json_path.to_string(),
                ctx.content_type.clone(),
                ctx.status_code,
                ts,
            )
        });
        // Only call record_observation for subsequent hits (first hit was
        // constructed with count=1 above via or_insert_with).
        if !is_new {
            obs.record_observation(ts);
        }
        // Clone to avoid borrow-checker conflict with &self in persist_observation.
        let obs_clone = obs.clone();
        self.persist_observation_cloned(&obs_clone)
    }

    /// Return all high-confidence path observations for a given secret name.
    /// The caller uses these to perform aggressive path-targeted redaction.
    pub fn high_confidence_paths_for(&self, secret_name: &str) -> Vec<&LeakPathObservation> {
        self.observations
            .values()
            .filter(|obs| obs.secret_name == secret_name && obs.is_high_confidence())
            .collect()
    }

    /// Return ALL observations for a given secret name (any confidence).
    pub fn all_paths_for(&self, secret_name: &str) -> Vec<&LeakPathObservation> {
        self.observations
            .values()
            .filter(|obs| obs.secret_name == secret_name)
            .collect()
    }

    /// Return all observations in the store (used by `phantom doctor`).
    pub fn all_observations(&self) -> Vec<&LeakPathObservation> {
        let mut obs: Vec<_> = self.observations.values().collect();
        obs.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.secret_name.cmp(&b.secret_name))
                .then(a.json_path.cmp(&b.json_path))
        });
        obs
    }

    /// Return the number of distinct observations in the store.
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// True if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn persist_observation_cloned(&self, _obs: &LeakPathObservation) -> std::io::Result<()> {
        if let Some(parent) = self.profiles_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Skip persistence for /dev/null paths (ephemeral stores used in tests).
        if self.profiles_path == std::path::Path::new("/dev/null") {
            return Ok(());
        }
        // Rewrite the entire file with merged observations.
        // For typical deployment (tens to low hundreds of profiles) this is
        // acceptable; a future optimisation could use a keyed update.
        let mut lines: Vec<Vec<u8>> = Vec::new();
        for existing in self.observations.values() {
            let mut line = serde_json::to_vec(existing)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            line.push(b'\n');
            lines.push(line);
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.profiles_path)?;
        for line in lines {
            file.write_all(&line)?;
        }
        Ok(())
    }
}

/// Extract a simplified dot-notation JSON path for the position of `needle`
/// within `json_value`.
///
/// Traverses the JSON tree depth-first and returns the first path at which
/// `needle` appears as a string value. Returns `None` if not found.
///
/// Examples:
/// - `{"data": {"live_key": "sk_live_xxx"}}` with needle `"sk_live_xxx"` → `.data.live_key`
/// - `{"keys": ["sk_live_xxx"]}` with needle `"sk_live_xxx"` → `.keys[0]`
pub fn extract_json_path(json_value: &serde_json::Value, needle: &str) -> Option<String> {
    extract_json_path_inner(json_value, needle, "")
}

fn extract_json_path_inner(
    value: &serde_json::Value,
    needle: &str,
    current_path: &str,
) -> Option<String> {
    match value {
        serde_json::Value::String(s) => {
            if s.contains(needle) {
                Some(current_path.to_string())
            } else {
                None
            }
        }
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{}.{}", current_path, key);
                if let Some(found) = extract_json_path_inner(child, needle, &child_path) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for (idx, child) in arr.iter().enumerate() {
                let child_path = format!("{}[{}]", current_path, idx);
                if let Some(found) = extract_json_path_inner(child, needle, &child_path) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

/// For a high-confidence profile, extract the string value at the given
/// dot-notation JSON path from `json_value`.  Returns `None` if the path
/// does not exist or the value is not a string.
pub fn value_at_json_path<'a>(
    json_value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a str> {
    // Walk the path segments.  We handle `.key`, `[idx]`, and combinations.
    let mut current = json_value;
    let mut remaining = path;

    loop {
        if remaining.is_empty() {
            return current.as_str();
        }
        if remaining.starts_with('.') {
            remaining = &remaining[1..];
            // Find the next `.` or `[` to get the key name.
            let end = remaining
                .find(|c| c == '.' || c == '[')
                .unwrap_or(remaining.len());
            let key = &remaining[..end];
            remaining = &remaining[end..];
            current = current.get(key)?;
        } else if remaining.starts_with('[') {
            // Array index.
            let close = remaining.find(']')?;
            let idx_str = &remaining[1..close];
            remaining = &remaining[close + 1..];
            let idx: usize = idx_str.parse().ok()?;
            current = current.get(idx)?;
        } else {
            return None;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// A correlated leak incident derived from one or more `proxy.response_leak`
/// audit events.
///
/// Secret *values* are never stored here — only the secret *name*.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeakIncident {
    /// Stable deduplication identifier: SHA-256 hex of
    /// `"{secret_name}\0{location_label}\0{hour_bucket}"`.
    pub incident_id: String,
    /// Secret key name (e.g. `OPENAI_API_KEY`). Never the value.
    pub secret_name: String,
    /// Human-readable location label (e.g. `body`, `header:Authorization`).
    pub location_label: String,
    /// Unix timestamp of the earliest contributing event.
    pub first_seen_ts: u64,
    /// Unix timestamp of the most recent contributing event.
    pub last_seen_ts: u64,
    /// Total number of `proxy.response_leak` events contributing to this
    /// incident.
    pub event_count: usize,
    /// Confidence score in [0.0, 1.0].
    /// Single leak = 0.5; >3 same secret within 1h = 0.95.
    pub confidence: f64,
    /// Human-readable remediation advice.
    pub remediation: String,
}

impl LeakIncident {
    /// Return true if this incident was first seen within the last `window_secs`
    /// seconds.
    pub fn is_within_window(&self, now_ts: u64, window_secs: u64) -> bool {
        now_ts.saturating_sub(self.first_seen_ts) < window_secs
    }
}

/// A raw `proxy.response_leak` event read from the audit log.
#[derive(Debug, Clone)]
struct RawLeakEvent {
    ts: u64,
    secret_name: Option<String>,
    location_label: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Engine
// ──────────────────────────────────────────────────────────────────────────────

/// Correlates `proxy.response_leak` audit events into incidents.
pub struct LeakCorrelationEngine {
    audit_log_path: PathBuf,
    incidents_path: PathBuf,
}

impl LeakCorrelationEngine {
    /// Create a new engine using paths derived from the current `HOME`.
    pub fn new() -> std::io::Result<Self> {
        let home = home_dir()?;
        Ok(Self {
            audit_log_path: home.join(".phantom").join("audit.log"),
            incidents_path: home.join(".phantom").join("leak-incidents.jsonl"),
        })
    }

    /// Create an engine pointing at custom paths (used in tests).
    pub fn with_paths(audit_log_path: PathBuf, incidents_path: PathBuf) -> Self {
        Self {
            audit_log_path,
            incidents_path,
        }
    }

    /// Read `proxy.response_leak` events from the audit log within the last
    /// `window_secs` seconds, correlate them into incidents, persist new
    /// incidents, and return all incidents produced in this run.
    ///
    /// For each high-confidence incident (confidence ≥ 0.7) a warning line is
    /// written to stderr.
    pub fn run(&self) -> std::io::Result<Vec<LeakIncident>> {
        let now = now_unix();
        let window_secs = 24 * 3600_u64; // 24 h look-back

        // 1. Read events from the audit log.
        let events = self.read_leak_events(now, window_secs)?;

        // 2. Group by (secret_name, location_label, 1-hour bucket).
        let incidents = correlate(events, now);

        // 3. Load existing incidents for deduplication.
        let existing_ids = self.load_existing_incident_ids()?;

        // 4. Persist new incidents; emit warnings for high-confidence ones.
        let mut new_incidents = Vec::new();
        for inc in incidents {
            if existing_ids.contains(&inc.incident_id) {
                continue; // already persisted
            }
            if inc.confidence >= 0.7 {
                eprintln!(
                    "phantom WARNING: high-confidence leak incident — secret='{}' \
                     location='{}' confidence={:.2} events={} \
                     hint: {}",
                    inc.secret_name,
                    inc.location_label,
                    inc.confidence,
                    inc.event_count,
                    inc.remediation,
                );
            }
            self.append_incident(&inc)?;
            new_incidents.push(inc);
        }

        Ok(new_incidents)
    }

    /// Return all incidents stored in `~/.phantom/leak-incidents.jsonl` whose
    /// `first_seen_ts` is within the last 24 h and whose secret has not been
    /// rotated (no `vault.store` event newer than the incident's `last_seen_ts`
    /// exists in the audit log).
    pub fn active_incidents(&self, min_confidence: f64) -> std::io::Result<Vec<LeakIncident>> {
        let now = now_unix();
        let window_secs = 24 * 3600_u64;

        // Load rotation timestamps for cleared secrets.
        let rotation_ts = self.load_rotation_timestamps()?;

        let incidents = self.load_all_incidents()?;
        let active: Vec<LeakIncident> = incidents
            .into_iter()
            .filter(|inc| {
                // Must be within 24 h.
                if !inc.is_within_window(now, window_secs) {
                    return false;
                }
                // Must meet minimum confidence.
                if inc.confidence < min_confidence {
                    return false;
                }
                // Cleared if there is a vault.store event newer than the incident.
                if let Some(&rotated_at) = rotation_ts.get(&inc.secret_name) {
                    if rotated_at > inc.last_seen_ts {
                        return false; // secret has been rotated
                    }
                }
                true
            })
            .collect();

        Ok(active)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn read_leak_events(
        &self,
        now: u64,
        window_secs: u64,
    ) -> std::io::Result<Vec<RawLeakEvent>> {
        if !self.audit_log_path.exists() {
            return Ok(vec![]);
        }

        let file = std::fs::File::open(&self.audit_log_path)?;
        let reader = std::io::BufReader::new(file);
        let cutoff = now.saturating_sub(window_secs);

        let mut events = Vec::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("op").and_then(|o| o.as_str()) != Some("proxy.response_leak") {
                continue;
            }
            let ts = v.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
            if ts < cutoff {
                continue;
            }
            let secret_name = v.get("name").and_then(|n| n.as_str()).map(String::from);
            // Derive a stable location label: use the `location` field if
            // present (written by the response scrubber as a LeakEvent embedded
            // in the JSONL context); fall back to "body".
            let location_label = v
                .get("location")
                .and_then(|l| l.as_str())
                .unwrap_or("body")
                .to_string();

            events.push(RawLeakEvent {
                ts,
                secret_name,
                location_label,
            });
        }

        Ok(events)
    }

    fn load_existing_incident_ids(&self) -> std::io::Result<std::collections::HashSet<String>> {
        let mut ids = std::collections::HashSet::new();
        if !self.incidents_path.exists() {
            return Ok(ids);
        }
        let file = std::fs::File::open(&self.incidents_path)?;
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let v: serde_json::Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(id) = v.get("incident_id").and_then(|i| i.as_str()) {
                ids.insert(id.to_string());
            }
        }
        Ok(ids)
    }

    fn load_all_incidents(&self) -> std::io::Result<Vec<LeakIncident>> {
        if !self.incidents_path.exists() {
            return Ok(vec![]);
        }
        let file = std::fs::File::open(&self.incidents_path)?;
        let reader = std::io::BufReader::new(file);
        let mut incidents = Vec::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<LeakIncident>(trimmed) {
                Ok(inc) => incidents.push(inc),
                Err(_) => continue,
            }
        }
        Ok(incidents)
    }

    fn append_incident(&self, incident: &LeakIncident) -> std::io::Result<()> {
        if let Some(parent) = self.incidents_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.incidents_path)?;
        let mut line = serde_json::to_vec(incident)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        file.write_all(&line)
    }

    /// Load the most-recent `vault.store` timestamp for each secret name that
    /// has at least one such event in the audit log.
    fn load_rotation_timestamps(&self) -> std::io::Result<HashMap<String, u64>> {
        let mut map: HashMap<String, u64> = HashMap::new();
        if !self.audit_log_path.exists() {
            return Ok(map);
        }
        let file = std::fs::File::open(&self.audit_log_path)?;
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("op").and_then(|o| o.as_str()) != Some("vault.store") {
                continue;
            }
            if let (Some(name), Some(ts)) = (
                v.get("name").and_then(|n| n.as_str()),
                v.get("ts").and_then(|t| t.as_u64()),
            ) {
                let entry = map.entry(name.to_string()).or_insert(0);
                if ts > *entry {
                    *entry = ts;
                }
            }
        }
        Ok(map)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Correlation logic
// ──────────────────────────────────────────────────────────────────────────────

/// Group raw events into incidents.
///
/// Grouping key: `(secret_name_or_unknown, location_label, hour_bucket)`.
/// Confidence:
/// - 1 event  → 0.50
/// - 2 events → 0.65  (linear between 1 and 4)
/// - 3 events → 0.80
/// - ≥4 events in <1 h → 0.95
fn correlate(events: Vec<RawLeakEvent>, _now: u64) -> Vec<LeakIncident> {
    // Group events by (secret_name, location_label, hour_bucket).
    // hour_bucket = ts / 3600 — keeps events within the same calendar hour
    // together while naturally splitting across-hour bursts into separate
    // incidents.
    let mut groups: HashMap<(String, String, u64), Vec<RawLeakEvent>> = HashMap::new();

    for ev in events {
        let name = ev
            .secret_name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        let hour = ev.ts / 3600;
        groups
            .entry((name, ev.location_label.clone(), hour))
            .or_default()
            .push(ev);
    }

    let mut incidents = Vec::new();
    for ((secret_name, location_label, hour), evs) in groups {
        let count = evs.len();
        let first_seen_ts = evs.iter().map(|e| e.ts).min().unwrap_or(0);
        let last_seen_ts = evs.iter().map(|e| e.ts).max().unwrap_or(0);

        // Determine whether all events fall within a 1-hour window.
        let within_one_hour = (last_seen_ts - first_seen_ts) < 3600;

        let confidence = if count >= 4 && within_one_hour {
            0.95
        } else if count == 1 {
            0.50
        } else {
            // Linear interpolation between 0.50 (1 event) and 0.95 (4+ events).
            // For count = 2: 0.65; count = 3: 0.80.
            0.50 + (count as f64 - 1.0) * (0.45 / 3.0)
        };

        let incident_id = compute_incident_id(&secret_name, &location_label, hour);

        let remediation = build_remediation(&secret_name);

        incidents.push(LeakIncident {
            incident_id,
            secret_name,
            location_label,
            first_seen_ts,
            last_seen_ts,
            event_count: count,
            confidence,
            remediation,
        });
    }

    // Sort for determinism in tests.
    incidents.sort_by(|a, b| {
        a.first_seen_ts
            .cmp(&b.first_seen_ts)
            .then(a.secret_name.cmp(&b.secret_name))
    });

    incidents
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn compute_incident_id(secret_name: &str, location_label: &str, hour_bucket: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(secret_name.as_bytes());
    hasher.update(b"\x00");
    hasher.update(location_label.as_bytes());
    hasher.update(b"\x00");
    hasher.update(hour_bucket.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn build_remediation(secret_name: &str) -> String {
    if secret_name == "<unknown>" {
        "Rotate any recently used secrets and audit upstream API responses for credential leakage.".to_string()
    } else {
        format!(
            "Rotate '{}' immediately: `phantom rotate`. \
             Then check for account compromise on the associated service.",
            secret_name
        )
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn home_dir() -> std::io::Result<PathBuf> {
    // Respect HOME / USERPROFILE overrides (used in tests).
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
        "cannot resolve home directory",
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::tempdir;

    // Mutex so concurrent test threads don't step on each other's HOME env var.
    use crate::test_support::ENV_LOCK;

    /// Write a fake audit.log with the given (ts, op, name_opt) entries.
    fn write_audit_log(path: &std::path::Path, entries: &[(u64, &str, Option<&str>)]) {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).unwrap();
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .unwrap();
        for (ts, op, name_opt) in entries {
            let line = if let Some(n) = name_opt {
                format!(
                    r#"{{"ts":{ts},"op":"{op}","name":"{n}","pid":1,"process":"phantom"}}"#
                )
            } else {
                format!(r#"{{"ts":{ts},"op":"{op}","pid":1,"process":"phantom"}}"#)
            };
            writeln!(f, "{}", line).unwrap();
        }
    }

    fn make_engine(tmp: &std::path::Path) -> LeakCorrelationEngine {
        let audit = tmp.join(".phantom").join("audit.log");
        let incidents = tmp.join(".phantom").join("leak-incidents.jsonl");
        LeakCorrelationEngine::with_paths(audit, incidents)
    }

    // ── Test 1: single leak detected and stored ───────────────────────────────

    #[test]
    fn single_leak_detected_and_stored() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();

        let engine = make_engine(tmp.path());
        write_audit_log(
            &engine.audit_log_path,
            &[(now - 10, "proxy.response_leak", Some("OPENAI_API_KEY"))],
        );

        let produced = engine.run().unwrap();
        assert_eq!(produced.len(), 1, "should produce one incident");
        let inc = &produced[0];
        assert_eq!(inc.secret_name, "OPENAI_API_KEY");
        assert_eq!(inc.event_count, 1);
        assert!(
            (inc.confidence - 0.5).abs() < 1e-9,
            "single event → confidence 0.5"
        );

        // Incident file must have been written.
        assert!(engine.incidents_path.exists(), "incidents file should exist");

        // active_incidents should return it.
        let active = engine.active_incidents(0.0).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].secret_name, "OPENAI_API_KEY");
    }

    // ── Test 2: >3 same-secret leaks in <1h → 0.95 confidence ────────────────

    #[test]
    fn multiple_same_secret_leaks_cluster_to_high_confidence() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();
        // 4 events within the same hour for the same secret.
        let base = (now / 3600) * 3600; // start of current hour
        let engine = make_engine(tmp.path());
        write_audit_log(
            &engine.audit_log_path,
            &[
                (base + 10, "proxy.response_leak", Some("STRIPE_KEY")),
                (base + 20, "proxy.response_leak", Some("STRIPE_KEY")),
                (base + 30, "proxy.response_leak", Some("STRIPE_KEY")),
                (base + 40, "proxy.response_leak", Some("STRIPE_KEY")),
            ],
        );

        let produced = engine.run().unwrap();
        assert_eq!(produced.len(), 1, "4 events → one incident");
        let inc = &produced[0];
        assert_eq!(inc.secret_name, "STRIPE_KEY");
        assert_eq!(inc.event_count, 4);
        assert!(
            (inc.confidence - 0.95).abs() < 1e-9,
            ">3 events in <1h → confidence 0.95, got {}",
            inc.confidence
        );
    }

    // ── Test 3: different secrets at different times not clustered ────────────

    #[test]
    fn different_secrets_not_clustered() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();
        let engine = make_engine(tmp.path());
        write_audit_log(
            &engine.audit_log_path,
            &[
                (now - 100, "proxy.response_leak", Some("KEY_A")),
                (now - 50, "proxy.response_leak", Some("KEY_B")),
            ],
        );

        let produced = engine.run().unwrap();
        // If the two events happen to land in the same hour bucket they still
        // differ by secret_name, so they must form separate incidents.
        assert_eq!(produced.len(), 2, "two different secrets → two incidents");
        let names: std::collections::HashSet<_> =
            produced.iter().map(|i| i.secret_name.as_str()).collect();
        assert!(names.contains("KEY_A"));
        assert!(names.contains("KEY_B"));
    }

    // ── Test 4: incidents older than 24 h not reported ────────────────────────

    #[test]
    fn old_incidents_not_reported_by_active_incidents() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();
        let engine = make_engine(tmp.path());

        // Write an incident that is 25 h old directly to the incidents file.
        let old_inc = LeakIncident {
            incident_id: "old_id".to_string(),
            secret_name: "OLD_KEY".to_string(),
            location_label: "body".to_string(),
            first_seen_ts: now - 25 * 3600,
            last_seen_ts: now - 25 * 3600,
            event_count: 1,
            confidence: 0.5,
            remediation: "rotate".to_string(),
        };
        engine.append_incident(&old_inc).unwrap();

        // Also write a recent incident.
        let recent_inc = LeakIncident {
            incident_id: "recent_id".to_string(),
            secret_name: "RECENT_KEY".to_string(),
            location_label: "body".to_string(),
            first_seen_ts: now - 3600,
            last_seen_ts: now - 3600,
            event_count: 1,
            confidence: 0.5,
            remediation: "rotate".to_string(),
        };
        engine.append_incident(&recent_inc).unwrap();

        let active = engine.active_incidents(0.0).unwrap();
        assert_eq!(active.len(), 1, "only the recent incident should be active");
        assert_eq!(active[0].secret_name, "RECENT_KEY");
    }

    // ── Test 5: rotation of leaked secret clears related incidents ─────────────

    #[test]
    fn rotation_clears_related_incidents() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();
        let engine = make_engine(tmp.path());

        // Write a recent leak incident for SECRET_KEY.
        let inc = LeakIncident {
            incident_id: "leak_id".to_string(),
            secret_name: "SECRET_KEY".to_string(),
            location_label: "body".to_string(),
            first_seen_ts: now - 3600,
            last_seen_ts: now - 3600,
            event_count: 1,
            confidence: 0.5,
            remediation: "rotate".to_string(),
        };
        engine.append_incident(&inc).unwrap();

        // Write a vault.store event AFTER the incident (rotation happened).
        write_audit_log(
            &engine.audit_log_path,
            &[(now - 100, "vault.store", Some("SECRET_KEY"))],
        );

        let active = engine.active_incidents(0.0).unwrap();
        assert!(
            active.is_empty(),
            "after rotation, incident should be cleared"
        );
    }

    // ── Deduplication: re-running does not create duplicate incidents ──────────

    #[test]
    fn deduplication_prevents_duplicate_incidents() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();
        let engine = make_engine(tmp.path());
        write_audit_log(
            &engine.audit_log_path,
            &[(now - 10, "proxy.response_leak", Some("DUP_KEY"))],
        );

        let first_run = engine.run().unwrap();
        assert_eq!(first_run.len(), 1);

        // Second run with the same audit log should not produce a new incident.
        let second_run = engine.run().unwrap();
        assert_eq!(second_run.len(), 0, "second run should deduplicate");

        // There should still be exactly one line in the incidents file.
        let incidents = engine.load_all_incidents().unwrap();
        assert_eq!(incidents.len(), 1);
    }

    // ── min_confidence filter works ───────────────────────────────────────────

    #[test]
    fn active_incidents_min_confidence_filter() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();
        let engine = make_engine(tmp.path());

        engine
            .append_incident(&LeakIncident {
                incident_id: "low_id".to_string(),
                secret_name: "LOW_KEY".to_string(),
                location_label: "body".to_string(),
                first_seen_ts: now - 100,
                last_seen_ts: now - 100,
                event_count: 1,
                confidence: 0.5,
                remediation: String::new(),
            })
            .unwrap();
        engine
            .append_incident(&LeakIncident {
                incident_id: "high_id".to_string(),
                secret_name: "HIGH_KEY".to_string(),
                location_label: "body".to_string(),
                first_seen_ts: now - 100,
                last_seen_ts: now - 100,
                event_count: 4,
                confidence: 0.95,
                remediation: String::new(),
            })
            .unwrap();

        let filtered = engine.active_incidents(0.7).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].secret_name, "HIGH_KEY");
    }
}
