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

// reqwest is a workspace dependency available in phantom-core
#[allow(unused_imports)]
use reqwest;

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
pub fn value_at_json_path<'a>(json_value: &'a serde_json::Value, path: &str) -> Option<&'a str> {
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
            let end = remaining.find(['.', '[']).unwrap_or(remaining.len());
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

    fn read_leak_events(&self, now: u64, window_secs: u64) -> std::io::Result<Vec<RawLeakEvent>> {
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
        "Rotate any recently used secrets and audit upstream API responses for credential leakage."
            .to_string()
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
// Alert backends + Incident Alerter
// ──────────────────────────────────────────────────────────────────────────────

/// A single alert record persisted to `~/.phantom/leak-alerts.jsonl`.
///
/// One alert is emitted at most once per `(incident_id)` per 1-hour window,
/// preventing alert storms from repeated correlation runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeakAlert {
    /// The incident this alert is for (same deduplication key as `LeakIncident`).
    pub incident_id: String,
    /// Secret name that leaked. Never the value.
    pub secret_name: String,
    /// Location label (e.g. `body`, `header:Authorization`).
    pub location_label: String,
    /// Confidence score at alert time.
    pub confidence: f64,
    /// Number of contributing events.
    pub event_count: usize,
    /// Unix timestamp when this alert was emitted.
    pub alerted_at: u64,
    /// Which backends were notified (e.g. `["webhook", "slack"]`).
    pub backends_notified: Vec<String>,
    /// Human-readable remediation advice.
    pub remediation: String,
}

/// Configuration for a single alert backend, loaded from `.phantom.toml`
/// under `[[alerting.backends]]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AlertBackendConfig {
    /// HTTP POST to a custom webhook URL.
    Webhook {
        /// The URL to POST to.
        url: String,
    },
    /// Slack incoming webhook.
    Slack {
        /// Slack webhook URL (from https://api.slack.com/apps).
        url: String,
    },
    /// PagerDuty Events API v2.
    PagerDuty {
        /// PagerDuty integration key (routing key).
        integration_key: String,
    },
}

/// `[alerting]` section of `.phantom.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertingConfig {
    /// Whether alerting is enabled. Default: `false`.
    pub enabled: bool,
    /// Minimum confidence score to trigger an alert. Default: 0.7.
    #[serde(default = "default_min_alert_confidence")]
    pub min_confidence: f64,
    /// Alert backends to notify.
    #[serde(default)]
    pub backends: Vec<AlertBackendConfig>,
}

fn default_min_alert_confidence() -> f64 {
    0.7
}

/// Explicit `Default` impl so that `AlertingConfig::default().min_confidence == 0.7`.
/// `#[derive(Default)]` would use `f64::default() == 0.0`, which disagrees with the
/// serde default used during deserialization.
impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_confidence: default_min_alert_confidence(),
            backends: Vec::new(),
        }
    }
}

/// Trait for alert dispatch — one method per backend type.
/// Implementations perform the HTTP call (or mock in tests).
pub trait AlertDispatch: Send + Sync {
    /// Send a webhook (generic HTTP POST).
    fn send_webhook(&self, url: &str, payload: &serde_json::Value) -> std::io::Result<()>;
    /// Send a Slack incoming webhook message.
    fn send_slack(&self, url: &str, payload: &serde_json::Value) -> std::io::Result<()>;
    /// Send a PagerDuty Events API v2 alert.
    fn send_pagerduty(
        &self,
        integration_key: &str,
        payload: &serde_json::Value,
    ) -> std::io::Result<()>;
}

/// Default dispatcher that performs real HTTP POSTs using `reqwest` blocking.
pub struct HttpAlertDispatch;

impl AlertDispatch for HttpAlertDispatch {
    fn send_webhook(&self, url: &str, payload: &serde_json::Value) -> std::io::Result<()> {
        send_http_post(url, payload)
    }

    fn send_slack(&self, url: &str, payload: &serde_json::Value) -> std::io::Result<()> {
        send_http_post(url, payload)
    }

    fn send_pagerduty(
        &self,
        integration_key: &str,
        payload: &serde_json::Value,
    ) -> std::io::Result<()> {
        let url = "https://events.pagerduty.com/v2/enqueue";
        let _ = integration_key; // already embedded in payload
        send_http_post(url, payload)
    }
}

fn send_http_post(url: &str, payload: &serde_json::Value) -> std::io::Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(payload)
        .send()
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(std::io::Error::other(format!("HTTP {status} from {url}")));
    }
    Ok(())
}

/// Build a Slack `blocks` payload from a `LeakIncident`.
fn slack_payload(incident: &LeakIncident) -> serde_json::Value {
    let confidence_pct = (incident.confidence * 100.0).round() as u64;
    serde_json::json!({
        "text": format!(
            "[phantom] HIGH-CONFIDENCE LEAK: secret='{}' confidence={}% events={}",
            incident.secret_name, confidence_pct, incident.event_count
        ),
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":rotating_light: Phantom Secret Leak Detected"
                }
            },
            {
                "type": "section",
                "fields": [
                    { "type": "mrkdwn", "text": format!("*Secret:*\n`{}`", incident.secret_name) },
                    { "type": "mrkdwn", "text": format!("*Confidence:*\n{}%", confidence_pct) },
                    { "type": "mrkdwn", "text": format!("*Location:*\n{}", incident.location_label) },
                    { "type": "mrkdwn", "text": format!("*Events:*\n{}", incident.event_count) }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(":warning: *Remediation:* {}", incident.remediation)
                }
            }
        ]
    })
}

/// Build a PagerDuty Events API v2 `trigger` payload from a `LeakIncident`.
fn pagerduty_payload(incident: &LeakIncident, integration_key: &str) -> serde_json::Value {
    serde_json::json!({
        "routing_key": integration_key,
        "event_action": "trigger",
        "dedup_key": incident.incident_id,
        "payload": {
            "summary": format!(
                "phantom: secret '{}' leaked at '{}' (confidence={:.2})",
                incident.secret_name, incident.location_label, incident.confidence
            ),
            "severity": if incident.confidence >= 0.9 { "critical" } else { "error" },
            "source": "phantom-secrets",
            "timestamp": chrono_like_iso(incident.first_seen_ts),
            "custom_details": {
                "secret_name": incident.secret_name,
                "location_label": incident.location_label,
                "confidence": incident.confidence,
                "event_count": incident.event_count,
                "incident_id": incident.incident_id,
                "remediation": incident.remediation
            }
        }
    })
}

/// Build a generic webhook payload from a `LeakIncident`.
fn webhook_payload(incident: &LeakIncident) -> serde_json::Value {
    serde_json::json!({
        "event": "phantom.leak_incident",
        "incident_id": incident.incident_id,
        "secret_name": incident.secret_name,
        "location_label": incident.location_label,
        "confidence": incident.confidence,
        "event_count": incident.event_count,
        "first_seen_ts": incident.first_seen_ts,
        "last_seen_ts": incident.last_seen_ts,
        "remediation": incident.remediation,
        "alerted_at": now_unix()
    })
}

/// Minimal ISO-8601 timestamp from a Unix epoch (no external crates).
fn chrono_like_iso(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

/// Listens to leak incidents and emits alerts to configured backends,
/// persisting alerts to `~/.phantom/leak-alerts.jsonl` with per-hour
/// deduplication so a single incident triggers at most one alert per hour.
///
/// ## Usage
///
/// ```no_run
/// use phantom_core::leak_correlation::{AlertingConfig, LeakIncidentAlerter, HttpAlertDispatch};
/// let config = AlertingConfig::default();
/// let alerter = LeakIncidentAlerter::new(config, Box::new(HttpAlertDispatch)).unwrap();
/// // alerter.process_incidents(&incidents).unwrap();
/// ```
pub struct LeakIncidentAlerter {
    config: AlertingConfig,
    alerts_path: PathBuf,
    dispatch: Box<dyn AlertDispatch>,
}

impl LeakIncidentAlerter {
    /// Create an alerter using the default `~/.phantom/leak-alerts.jsonl` path.
    pub fn new(config: AlertingConfig, dispatch: Box<dyn AlertDispatch>) -> std::io::Result<Self> {
        let home = home_dir()?;
        Ok(Self {
            config,
            alerts_path: home.join(".phantom").join("leak-alerts.jsonl"),
            dispatch,
        })
    }

    /// Create an alerter with a custom alerts path (used in tests).
    pub fn with_path(
        config: AlertingConfig,
        alerts_path: PathBuf,
        dispatch: Box<dyn AlertDispatch>,
    ) -> Self {
        Self {
            config,
            alerts_path,
            dispatch,
        }
    }

    /// Process a list of incidents: for each incident that meets the configured
    /// `min_confidence` and has not already been alerted in this hour window,
    /// send to all backends and persist the alert.
    ///
    /// Returns the list of newly emitted alerts.
    pub fn process_incidents(&self, incidents: &[LeakIncident]) -> std::io::Result<Vec<LeakAlert>> {
        if !self.config.enabled || self.config.backends.is_empty() {
            return Ok(vec![]);
        }

        let alerted_ids = self.load_alerted_incident_ids()?;
        let mut new_alerts = Vec::new();

        for incident in incidents {
            if incident.confidence < self.config.min_confidence {
                continue;
            }
            // Dedup: one alert per incident_id per hour window.
            // The incident_id already encodes the hour bucket, so a single
            // check is sufficient.
            if alerted_ids.contains(&incident.incident_id) {
                continue;
            }

            let mut backends_notified = Vec::new();

            for backend in &self.config.backends {
                let result = match backend {
                    AlertBackendConfig::Webhook { url } => {
                        let payload = webhook_payload(incident);
                        let r = self.dispatch.send_webhook(url, &payload);
                        if r.is_ok() {
                            backends_notified.push("webhook".to_string());
                        }
                        r
                    }
                    AlertBackendConfig::Slack { url } => {
                        let payload = slack_payload(incident);
                        let r = self.dispatch.send_slack(url, &payload);
                        if r.is_ok() {
                            backends_notified.push("slack".to_string());
                        }
                        r
                    }
                    AlertBackendConfig::PagerDuty { integration_key } => {
                        let payload = pagerduty_payload(incident, integration_key);
                        let r = self.dispatch.send_pagerduty(integration_key, &payload);
                        if r.is_ok() {
                            backends_notified.push("pagerduty".to_string());
                        }
                        r
                    }
                };
                // Log backend errors to stderr but don't abort — other backends
                // should still be notified.
                if let Err(ref e) = result {
                    eprintln!(
                        "phantom WARNING: alert dispatch failed for backend {:?}: {e}",
                        backend
                    );
                }
            }

            let alert = LeakAlert {
                incident_id: incident.incident_id.clone(),
                secret_name: incident.secret_name.clone(),
                location_label: incident.location_label.clone(),
                confidence: incident.confidence,
                event_count: incident.event_count,
                alerted_at: now_unix(),
                backends_notified,
                remediation: incident.remediation.clone(),
            };

            self.append_alert(&alert)?;
            new_alerts.push(alert);
        }

        Ok(new_alerts)
    }

    /// Load all alerts persisted in `~/.phantom/leak-alerts.jsonl`.
    pub fn load_all_alerts(&self) -> std::io::Result<Vec<LeakAlert>> {
        if !self.alerts_path.exists() {
            return Ok(vec![]);
        }
        let file = std::fs::File::open(&self.alerts_path)?;
        let reader = std::io::BufReader::new(file);
        let mut alerts = Vec::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(alert) = serde_json::from_str::<LeakAlert>(trimmed) {
                alerts.push(alert);
            }
        }
        Ok(alerts)
    }

    /// Load all alerts, returning at most `last` most-recent ones (by `alerted_at`).
    pub fn load_recent_alerts(&self, last: usize) -> std::io::Result<Vec<LeakAlert>> {
        let mut alerts = self.load_all_alerts()?;
        alerts.sort_by_key(|alert| std::cmp::Reverse(alert.alerted_at));
        alerts.truncate(last);
        // Restore chronological order for display.
        alerts.reverse();
        Ok(alerts)
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn load_alerted_incident_ids(&self) -> std::io::Result<std::collections::HashSet<String>> {
        let mut ids = std::collections::HashSet::new();
        if !self.alerts_path.exists() {
            return Ok(ids);
        }
        let file = std::fs::File::open(&self.alerts_path)?;
        let reader = std::io::BufReader::new(file);
        let now = now_unix();
        let hour_start = (now / 3600) * 3600;

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(alert) = serde_json::from_str::<LeakAlert>(trimmed) {
                // Only deduplicate within the current 1-hour window.
                if alert.alerted_at >= hour_start {
                    ids.insert(alert.incident_id);
                }
            }
        }
        Ok(ids)
    }

    fn append_alert(&self, alert: &LeakAlert) -> std::io::Result<()> {
        if let Some(parent) = self.alerts_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.alerts_path)?;
        let mut line = serde_json::to_vec(alert)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        file.write_all(&line)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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
                format!(r#"{{"ts":{ts},"op":"{op}","name":"{n}","pid":1,"process":"phantom"}}"#)
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
        assert!(
            engine.incidents_path.exists(),
            "incidents file should exist"
        );

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

    // ── LeakIncidentAlerter tests ─────────────────────────────────────────────

    use std::sync::{Arc, Mutex};

    /// Spy dispatcher — records calls instead of making real HTTP requests.
    #[derive(Default, Clone)]
    struct SpyDispatch {
        webhook_calls: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
        slack_calls: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
        pagerduty_calls: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    }

    impl AlertDispatch for SpyDispatch {
        fn send_webhook(&self, url: &str, payload: &serde_json::Value) -> std::io::Result<()> {
            self.webhook_calls
                .lock()
                .unwrap()
                .push((url.to_string(), payload.clone()));
            Ok(())
        }
        fn send_slack(&self, url: &str, payload: &serde_json::Value) -> std::io::Result<()> {
            self.slack_calls
                .lock()
                .unwrap()
                .push((url.to_string(), payload.clone()));
            Ok(())
        }
        fn send_pagerduty(
            &self,
            integration_key: &str,
            payload: &serde_json::Value,
        ) -> std::io::Result<()> {
            self.pagerduty_calls
                .lock()
                .unwrap()
                .push((integration_key.to_string(), payload.clone()));
            Ok(())
        }
    }

    fn make_incident(secret: &str, confidence: f64, event_count: usize) -> LeakIncident {
        let now = now_unix();
        let hour = now / 3600;
        LeakIncident {
            incident_id: compute_incident_id(secret, "body", hour),
            secret_name: secret.to_string(),
            location_label: "body".to_string(),
            first_seen_ts: now - 60,
            last_seen_ts: now,
            event_count,
            confidence,
            remediation: format!("Rotate '{secret}' immediately."),
        }
    }

    fn make_alerter_with_spy(
        tmp: &std::path::Path,
        config: AlertingConfig,
        spy: SpyDispatch,
    ) -> LeakIncidentAlerter {
        LeakIncidentAlerter::with_path(config, tmp.join("leak-alerts.jsonl"), Box::new(spy))
    }

    // Test 1: alerter disabled → no calls emitted
    #[test]
    fn alerter_disabled_emits_no_calls() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: false,
            min_confidence: 0.7,
            backends: vec![AlertBackendConfig::Webhook {
                url: "https://example.com/hook".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let inc = make_incident("STRIPE_KEY", 0.95, 4);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert!(alerts.is_empty());
        assert!(spy.webhook_calls.lock().unwrap().is_empty());
    }

    // Test 2: single high-confidence incident → webhook called once
    #[test]
    fn alerter_calls_webhook_for_high_confidence_incident() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![AlertBackendConfig::Webhook {
                url: "https://hooks.example.com/test".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let inc = make_incident("OPENAI_API_KEY", 0.95, 4);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert_eq!(alerts.len(), 1);
        let calls = spy.webhook_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "https://hooks.example.com/test");
        // Payload should contain the secret name and event type
        let payload = &calls[0].1;
        assert_eq!(payload["event"].as_str().unwrap(), "phantom.leak_incident");
        assert_eq!(payload["secret_name"].as_str().unwrap(), "OPENAI_API_KEY");
    }

    // Test 3: confidence below min_confidence → not alerted
    #[test]
    fn alerter_skips_low_confidence_incidents() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.9,
            backends: vec![AlertBackendConfig::Webhook {
                url: "https://example.com/hook".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let inc = make_incident("LOW_KEY", 0.5, 1);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert!(alerts.is_empty());
        assert!(spy.webhook_calls.lock().unwrap().is_empty());
    }

    // Test 4: Slack backend calls send_slack with correct payload structure
    #[test]
    fn alerter_calls_slack_backend() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![AlertBackendConfig::Slack {
                url: "https://hooks.slack.com/services/TEST".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let inc = make_incident("STRIPE_KEY", 0.95, 4);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert_eq!(alerts.len(), 1);
        let calls = spy.slack_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        // Slack payload should have "blocks" field
        assert!(calls[0].1.get("blocks").is_some());
        // text field should mention the secret
        let text = calls[0].1["text"].as_str().unwrap_or("");
        assert!(text.contains("STRIPE_KEY"));
    }

    // Test 5: PagerDuty backend calls send_pagerduty with correct payload
    #[test]
    fn alerter_calls_pagerduty_backend() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![AlertBackendConfig::PagerDuty {
                integration_key: "test_routing_key_abc123".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let inc = make_incident("OPENAI_API_KEY", 0.95, 4);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert_eq!(alerts.len(), 1);
        let calls = spy.pagerduty_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "test_routing_key_abc123");
        // PD payload should have routing_key, event_action, dedup_key
        let payload = &calls[0].1;
        assert_eq!(payload["event_action"].as_str().unwrap(), "trigger");
        assert!(payload.get("dedup_key").is_some());
        assert_eq!(
            payload["routing_key"].as_str().unwrap(),
            "test_routing_key_abc123"
        );
    }

    // Test 6: alert deduplication — same incident processed twice in same hour → only one alert
    #[test]
    fn alerter_deduplicates_same_incident_same_hour() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![AlertBackendConfig::Webhook {
                url: "https://example.com/hook".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let inc = make_incident("DUP_KEY", 0.95, 4);

        let first = alerter
            .process_incidents(std::slice::from_ref(&inc))
            .unwrap();
        assert_eq!(first.len(), 1, "first call should produce one alert");

        let second = alerter.process_incidents(&[inc]).unwrap();
        assert_eq!(second.len(), 0, "second call should be deduplicated");

        // Webhook called only once total
        assert_eq!(spy.webhook_calls.lock().unwrap().len(), 1);
    }

    // Test 7: alert persisted to disk
    #[test]
    fn alerter_persists_alert_to_disk() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![AlertBackendConfig::Webhook {
                url: "https://example.com/hook".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy);
        let inc = make_incident("PERSIST_KEY", 0.95, 4);
        alerter.process_incidents(&[inc]).unwrap();

        let alerts_path = tmp.path().join("leak-alerts.jsonl");
        assert!(alerts_path.exists(), "alert file should be created");
        let content = std::fs::read_to_string(&alerts_path).unwrap();
        assert!(content.contains("PERSIST_KEY"));
        assert!(content.contains("webhook"));
    }

    // Test 8: load_all_alerts returns persisted alerts
    #[test]
    fn alerter_load_all_alerts_round_trip() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.5,
            backends: vec![AlertBackendConfig::Slack {
                url: "https://hooks.slack.com/test".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy);
        let inc1 = make_incident("KEY_A", 0.95, 4);
        let inc2 = make_incident("KEY_B", 0.65, 2);
        alerter.process_incidents(&[inc1, inc2]).unwrap();
        let all = alerter.load_all_alerts().unwrap();
        assert_eq!(all.len(), 2);
        let names: Vec<&str> = all.iter().map(|a| a.secret_name.as_str()).collect();
        assert!(names.contains(&"KEY_A"));
        assert!(names.contains(&"KEY_B"));
    }

    // Test 9: load_recent_alerts returns last N in chronological order
    #[test]
    fn alerter_load_recent_alerts_limit() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.5,
            backends: vec![AlertBackendConfig::Webhook {
                url: "https://example.com/hook".to_string(),
            }],
        };
        // Write 5 alerts directly
        let alerter = make_alerter_with_spy(tmp.path(), config, SpyDispatch::default());
        let now = now_unix();
        for i in 0..5u64 {
            let alert = LeakAlert {
                incident_id: format!("inc_{i}"),
                secret_name: format!("KEY_{i}"),
                location_label: "body".to_string(),
                confidence: 0.95,
                event_count: 4,
                alerted_at: now - (4 - i) * 60, // 4..0 minutes ago
                backends_notified: vec!["webhook".to_string()],
                remediation: String::new(),
            };
            alerter.append_alert(&alert).unwrap();
        }

        let recent = alerter.load_recent_alerts(3).unwrap();
        assert_eq!(recent.len(), 3);
        // Should be the 3 most recent (alerted_at values), in chronological order.
        assert!(recent[0].alerted_at <= recent[1].alerted_at);
        assert!(recent[1].alerted_at <= recent[2].alerted_at);
    }

    // Test 10: multiple backends called for same incident
    #[test]
    fn alerter_notifies_all_backends() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![
                AlertBackendConfig::Webhook {
                    url: "https://example.com/hook".to_string(),
                },
                AlertBackendConfig::Slack {
                    url: "https://hooks.slack.com/services/X".to_string(),
                },
                AlertBackendConfig::PagerDuty {
                    integration_key: "pd_key_xyz".to_string(),
                },
            ],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let inc = make_incident("MULTI_KEY", 0.95, 4);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].backends_notified.len(), 3);
        assert!(alerts[0].backends_notified.contains(&"webhook".to_string()));
        assert!(alerts[0].backends_notified.contains(&"slack".to_string()));
        assert!(alerts[0]
            .backends_notified
            .contains(&"pagerduty".to_string()));
        assert_eq!(spy.webhook_calls.lock().unwrap().len(), 1);
        assert_eq!(spy.slack_calls.lock().unwrap().len(), 1);
        assert_eq!(spy.pagerduty_calls.lock().unwrap().len(), 1);
    }

    // Test 11: integration test — 4 proxy leaks → correlate → alert → slack called once with 0.95
    #[test]
    fn integration_four_leaks_trigger_one_slack_alert_at_0_95() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let now = now_unix();
        let base = (now / 3600) * 3600;

        // Write 4 proxy leak events to audit log
        let engine = make_engine(tmp.path());
        write_audit_log(
            &engine.audit_log_path,
            &[
                (base + 5, "proxy.response_leak", Some("INTEGRATION_KEY")),
                (base + 10, "proxy.response_leak", Some("INTEGRATION_KEY")),
                (base + 15, "proxy.response_leak", Some("INTEGRATION_KEY")),
                (base + 20, "proxy.response_leak", Some("INTEGRATION_KEY")),
            ],
        );

        // Correlate incidents
        let incidents = engine.run().unwrap();
        assert_eq!(incidents.len(), 1);
        assert!(
            (incidents[0].confidence - 0.95).abs() < 1e-9,
            "4 events in <1h → confidence 0.95, got {}",
            incidents[0].confidence
        );

        // Alert via Slack
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![AlertBackendConfig::Slack {
                url: "https://hooks.slack.com/services/INTEGRATION".to_string(),
            }],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy.clone());
        let alerts = alerter.process_incidents(&incidents).unwrap();
        assert_eq!(alerts.len(), 1, "should emit exactly one alert");

        let slack_calls = spy.slack_calls.lock().unwrap();
        assert_eq!(slack_calls.len(), 1, "Slack called exactly once");
        let text = slack_calls[0].1["text"].as_str().unwrap_or("");
        assert!(
            text.contains("INTEGRATION_KEY"),
            "Slack message should mention the secret"
        );
        assert!(
            text.contains("95"),
            "Slack message should mention 95% confidence"
        );

        // Verify alert persisted
        let all_alerts = alerter.load_all_alerts().unwrap();
        assert_eq!(all_alerts.len(), 1);
        assert_eq!(all_alerts[0].secret_name, "INTEGRATION_KEY");
        assert!((all_alerts[0].confidence - 0.95).abs() < 1e-9);
    }

    // Test 12: webhook payload structure
    #[test]
    fn webhook_payload_has_required_fields() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let inc = make_incident("WH_KEY", 0.95, 4);
        let payload = webhook_payload(&inc);
        assert_eq!(payload["event"].as_str().unwrap(), "phantom.leak_incident");
        assert_eq!(payload["secret_name"].as_str().unwrap(), "WH_KEY");
        assert!(payload.get("incident_id").is_some());
        assert!(payload.get("confidence").is_some());
        assert!(payload.get("event_count").is_some());
        assert!(payload.get("alerted_at").is_some());
    }

    // Test 13: Slack payload has blocks + text fields
    #[test]
    fn slack_payload_has_blocks_and_text() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let inc = make_incident("SLACK_KEY", 0.95, 4);
        let payload = slack_payload(&inc);
        assert!(payload.get("text").is_some());
        assert!(payload.get("blocks").is_some());
        let text = payload["text"].as_str().unwrap();
        assert!(text.contains("SLACK_KEY"));
    }

    // Test 14: PagerDuty payload severity critical for confidence >= 0.9
    #[test]
    fn pagerduty_payload_critical_severity_high_confidence() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let inc = make_incident("PD_KEY", 0.95, 4);
        let payload = pagerduty_payload(&inc, "key123");
        let severity = payload["payload"]["severity"].as_str().unwrap();
        assert_eq!(severity, "critical");
    }

    // Test 15: PagerDuty payload severity error for confidence < 0.9
    #[test]
    fn pagerduty_payload_error_severity_moderate_confidence() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let inc = make_incident("PD_KEY2", 0.75, 2);
        let payload = pagerduty_payload(&inc, "key456");
        let severity = payload["payload"]["severity"].as_str().unwrap();
        assert_eq!(severity, "error");
    }

    // Test 16: AlertingConfig default is disabled + 0.7 min_confidence
    #[test]
    fn alerting_config_default_is_disabled() {
        let config = AlertingConfig::default();
        assert!(!config.enabled);
        assert!((config.min_confidence - 0.7).abs() < 1e-9);
        assert!(config.backends.is_empty());
    }

    // Test 17: process_incidents with no backends → no alerts even if enabled
    #[test]
    fn alerter_no_backends_emits_no_alerts() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, SpyDispatch::default());
        let inc = make_incident("NO_BACKEND_KEY", 0.95, 4);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert!(alerts.is_empty());
    }

    // Test 18: chrono_like_iso produces valid ISO-8601 format
    #[test]
    fn chrono_like_iso_format() {
        let s = chrono_like_iso(1_705_314_645); // 2024-01-15T10:30:45Z
        assert_eq!(s, "2024-01-15T10:30:45Z");
    }

    // Test 19: load_all_alerts on missing file returns empty
    #[test]
    fn load_all_alerts_missing_file_returns_empty() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let config = AlertingConfig::default();
        let alerter = make_alerter_with_spy(tmp.path(), config, SpyDispatch::default());
        let alerts = alerter.load_all_alerts().unwrap();
        assert!(alerts.is_empty());
    }

    // Test 20: backends_notified reflects which backends succeeded
    #[test]
    fn alert_records_notified_backends() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().unwrap();
        let spy = SpyDispatch::default();
        let config = AlertingConfig {
            enabled: true,
            min_confidence: 0.7,
            backends: vec![
                AlertBackendConfig::Webhook {
                    url: "https://example.com/wh".to_string(),
                },
                AlertBackendConfig::Slack {
                    url: "https://hooks.slack.com/X".to_string(),
                },
            ],
        };
        let alerter = make_alerter_with_spy(tmp.path(), config, spy);
        let inc = make_incident("BN_KEY", 0.95, 4);
        let alerts = alerter.process_incidents(&[inc]).unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].backends_notified.contains(&"webhook".to_string()));
        assert!(alerts[0].backends_notified.contains(&"slack".to_string()));
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
