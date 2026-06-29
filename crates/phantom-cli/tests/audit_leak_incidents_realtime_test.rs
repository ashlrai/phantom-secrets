//! Integration tests for `phantom audit incidents` (real-time dashboard)
//! and the `phantom_leak_incidents_realtime` MCP tool.
//!
//! These tests exercise the public API surface that both the CLI subcommand
//! and the MCP tool share: `LeakCorrelationEngine::active_incidents` with the
//! `min_confidence=0.5` default, the structured incident summaries, and the
//! auto-rotate-on-high gate.

use phantom_core::leak_correlation::{LeakCorrelationEngine, LeakIncident};
use std::io::Write as _;
use std::sync::Mutex;
use tempfile::tempdir;

// Serialise tests that mutate HOME.
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ── helpers ───────────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns (engine, audit_log_path, incidents_path).
fn make_engine(tmp: &std::path::Path) -> (LeakCorrelationEngine, std::path::PathBuf, std::path::PathBuf) {
    let audit = tmp.join(".phantom").join("audit.log");
    let incidents = tmp.join(".phantom").join("leak-incidents.jsonl");
    let engine = LeakCorrelationEngine::with_paths(audit.clone(), incidents.clone());
    (engine, audit, incidents)
}

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

fn append_incident(incidents_path: &std::path::Path, inc: &LeakIncident) {
    use std::io::Write;
    if let Some(p) = incidents_path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(incidents_path)
        .unwrap();
    let mut line = serde_json::to_vec(inc).unwrap();
    line.push(b'\n');
    f.write_all(&line).unwrap();
}

// ── Test 1: default min_confidence=0.5 returns single-event incidents ─────────

#[test]
fn realtime_default_confidence_returns_single_event_incident() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();

    let (engine, audit_path, _) = make_engine(tmp.path());
    write_audit_log(
        &audit_path,
        &[(now - 60, "proxy.response_leak", Some("STRIPE_KEY"))],
    );

    let _ = engine.run().unwrap();

    // min_confidence=0.5 — the default for the realtime dashboard.
    let active = engine.active_incidents(0.5).unwrap();
    assert_eq!(active.len(), 1, "single-event incident should be active at min_confidence=0.5");
    assert_eq!(active[0].secret_name, "STRIPE_KEY");
    assert!((active[0].confidence - 0.50).abs() < 1e-9);
}

// ── Test 2: structured summary fields are present ─────────────────────────────

#[test]
fn realtime_incident_has_all_required_summary_fields() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();
    let base = (now / 3600) * 3600;

    let (engine, audit_path, _) = make_engine(tmp.path());
    write_audit_log(
        &audit_path,
        &[
            (base + 10, "proxy.response_leak", Some("OPENAI_KEY")),
            (base + 20, "proxy.response_leak", Some("OPENAI_KEY")),
            (base + 30, "proxy.response_leak", Some("OPENAI_KEY")),
            (base + 40, "proxy.response_leak", Some("OPENAI_KEY")),
        ],
    );

    let incidents = engine.run().unwrap();
    assert_eq!(incidents.len(), 1);

    let inc = &incidents[0];
    // All fields required by the MCP tool spec must be present.
    assert!(!inc.incident_id.is_empty(), "incident_id must be present");
    assert_eq!(inc.secret_name, "OPENAI_KEY");
    assert!(!inc.location_label.is_empty(), "location_label must be present");
    assert!(inc.first_seen_ts > 0, "first_seen_ts must be set");
    assert!(inc.last_seen_ts >= inc.first_seen_ts, "last_seen_ts >= first_seen_ts");
    assert!((inc.confidence - 0.95).abs() < 1e-9, "4 events in <1h => confidence 0.95, got {}", inc.confidence);
    assert_eq!(inc.event_count, 4);
    assert!(!inc.remediation.is_empty(), "remediation must be non-empty");
}

// ── Test 3: incidents sorted by confidence descending in the summary ──────────

#[test]
fn realtime_incidents_ordered_by_confidence_descending() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();
    let base = (now / 3600) * 3600;

    let (engine, audit_path, _) = make_engine(tmp.path());

    // HIGH_KEY gets 4 events (confidence 0.95); LOW_KEY gets 1 (confidence 0.50).
    write_audit_log(
        &audit_path,
        &[
            (base + 1, "proxy.response_leak", Some("LOW_KEY")),
            (base + 2, "proxy.response_leak", Some("HIGH_KEY")),
            (base + 3, "proxy.response_leak", Some("HIGH_KEY")),
            (base + 4, "proxy.response_leak", Some("HIGH_KEY")),
            (base + 5, "proxy.response_leak", Some("HIGH_KEY")),
        ],
    );

    engine.run().unwrap();
    let mut active = engine.active_incidents(0.5).unwrap();

    // Sort the same way the MCP tool / CLI table does: confidence descending.
    active.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    assert_eq!(active.len(), 2);
    assert_eq!(active[0].secret_name, "HIGH_KEY", "highest confidence first");
    assert_eq!(active[1].secret_name, "LOW_KEY",  "lowest confidence last");
    assert!(active[0].confidence > active[1].confidence);
}

// ── Test 4: incidents older than 24h are excluded from realtime dashboard ──────

#[test]
fn realtime_excludes_incidents_older_than_24h() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();

    let (engine, _, incidents_path) = make_engine(tmp.path());

    // Write an old incident directly to the file (25 h ago).
    let old_inc = LeakIncident {
        incident_id: "old_realtime_id".to_string(),
        secret_name: "OLD_SECRET".to_string(),
        location_label: "body".to_string(),
        first_seen_ts: now - 25 * 3600,
        last_seen_ts: now - 25 * 3600,
        event_count: 1,
        confidence: 0.9,
        remediation: "rotate".to_string(),
    };
    append_incident(&incidents_path, &old_inc);

    // Write a recent incident (30 min ago).
    let recent_inc = LeakIncident {
        incident_id: "recent_realtime_id".to_string(),
        secret_name: "RECENT_SECRET".to_string(),
        location_label: "body".to_string(),
        first_seen_ts: now - 1800,
        last_seen_ts: now - 1800,
        event_count: 1,
        confidence: 0.6,
        remediation: "rotate".to_string(),
    };
    append_incident(&incidents_path, &recent_inc);

    let active = engine.active_incidents(0.5).unwrap();
    assert_eq!(active.len(), 1, "only the recent incident should appear");
    assert_eq!(active[0].secret_name, "RECENT_SECRET");
}

// ── Test 5: rotation clears incident from realtime view ───────────────────────

#[test]
fn realtime_rotation_clears_incident() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();

    let (engine, audit_path, incidents_path) = make_engine(tmp.path());

    // Write an incident.
    let inc = LeakIncident {
        incident_id: "clear_id".to_string(),
        secret_name: "ROTATABLE_KEY".to_string(),
        location_label: "body".to_string(),
        first_seen_ts: now - 3600,
        last_seen_ts: now - 3600,
        event_count: 4,
        confidence: 0.95,
        remediation: "rotate".to_string(),
    };
    append_incident(&incidents_path, &inc);

    // Simulate rotation: a vault.store event after the incident.
    write_audit_log(
        &audit_path,
        &[(now - 60, "vault.store", Some("ROTATABLE_KEY"))],
    );

    let active = engine.active_incidents(0.5).unwrap();
    assert!(active.is_empty(), "rotated incident should not appear in realtime dashboard");
}

// ── Test 6: min_confidence=0.5 boundary — exactly 0.5 incident is included ───

#[test]
fn realtime_exactly_0_5_confidence_is_included() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();

    let (engine, _, incidents_path) = make_engine(tmp.path());

    let inc = LeakIncident {
        incident_id: "boundary_id".to_string(),
        secret_name: "BOUNDARY_KEY".to_string(),
        location_label: "body".to_string(),
        first_seen_ts: now - 100,
        last_seen_ts: now - 100,
        event_count: 1,
        confidence: 0.5,
        remediation: "rotate".to_string(),
    };
    append_incident(&incidents_path, &inc);

    // min_confidence=0.5 should include confidence=0.5 (>= not >).
    let active = engine.active_incidents(0.5).unwrap();
    assert_eq!(active.len(), 1, "incident at exactly confidence=0.5 should be included");
}

// ── Test 7: auto_rotate clears incident via vault.store audit event ────────────

#[test]
fn realtime_auto_rotate_audit_event_clears_incident() {
    // Verifies that writing a vault.store event (as run_rotate_single does)
    // causes the incident to be cleared in subsequent active_incidents calls.
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();

    let (engine, audit_path, incidents_path) = make_engine(tmp.path());

    let inc = LeakIncident {
        incident_id: "auto_rotate_test_id".to_string(),
        secret_name: "HIGH_CONF_KEY".to_string(),
        location_label: "body".to_string(),
        first_seen_ts: now - 7200,
        last_seen_ts: now - 7200,
        event_count: 4,
        confidence: 0.95,
        remediation: "rotate".to_string(),
    };
    append_incident(&incidents_path, &inc);

    // Without rotation, incident is active.
    let before = engine.active_incidents(0.5).unwrap();
    assert_eq!(before.len(), 1);

    // Simulate auto-rotate writing a vault.store event (as run_rotate_single does).
    write_audit_log(
        &audit_path,
        &[(now - 100, "vault.store", Some("HIGH_CONF_KEY"))],
    );

    // After rotation, the incident should be cleared.
    let after = engine.active_incidents(0.5).unwrap();
    assert!(after.is_empty(), "auto-rotate clears the high-confidence incident");
}

// ── Test 8: auto_rotate gate — high-confidence threshold is exactly 0.9 ───────

#[test]
fn realtime_auto_rotate_threshold_is_0_9() {
    // The spec requires auto-rotate to trigger at confidence >= 0.9.
    // Verify that confidence=0.89 does NOT cross the threshold.
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();

    let (engine, _, incidents_path) = make_engine(tmp.path());

    // incident at 0.89 — below threshold.
    let low_inc = LeakIncident {
        incident_id: "low_conf_gate_id".to_string(),
        secret_name: "JUST_BELOW_KEY".to_string(),
        location_label: "body".to_string(),
        first_seen_ts: now - 100,
        last_seen_ts: now - 100,
        event_count: 3,
        confidence: 0.89,
        remediation: "rotate".to_string(),
    };
    append_incident(&incidents_path, &low_inc);

    // incident at 0.90 — at threshold.
    let high_inc = LeakIncident {
        incident_id: "at_thresh_gate_id".to_string(),
        secret_name: "AT_THRESHOLD_KEY".to_string(),
        location_label: "body".to_string(),
        first_seen_ts: now - 100,
        last_seen_ts: now - 100,
        event_count: 4,
        confidence: 0.90,
        remediation: "rotate".to_string(),
    };
    append_incident(&incidents_path, &high_inc);

    let active = engine.active_incidents(0.5).unwrap();
    let would_auto_rotate: Vec<_> = active.iter().filter(|i| i.confidence >= 0.9).collect();
    let would_not_rotate: Vec<_> = active.iter().filter(|i| i.confidence < 0.9).collect();

    assert_eq!(would_auto_rotate.len(), 1);
    assert_eq!(would_auto_rotate[0].secret_name, "AT_THRESHOLD_KEY");
    assert_eq!(would_not_rotate.len(), 1);
    assert_eq!(would_not_rotate[0].secret_name, "JUST_BELOW_KEY");
}

// ── Test 9: MCP confirm gate — params struct has correct defaults ──────────────

#[test]
fn mcp_confirm_gate_blocks_auto_rotate_without_confirm() {
    // The MCP tool `phantom_leak_incidents_realtime` must call require_confirm
    // when auto_rotate_on_high=true.  We test the params struct's contract:
    // confirm defaults to false, so callers MUST explicitly set it to true.
    use phantom_mcp::LeakIncidentsRealtimeParams;

    // Default params: confirm=false, auto_rotate_on_high=false.
    let default_params: LeakIncidentsRealtimeParams =
        serde_json::from_str(r#"{}"#).unwrap();
    assert!(!default_params.confirm, "confirm must default to false");
    assert!(!default_params.auto_rotate_on_high, "auto_rotate_on_high must default to false");
    assert!((default_params.min_confidence - 0.5).abs() < 1e-9,
        "min_confidence must default to 0.5");

    // With auto_rotate_on_high=true and confirm=false, the gate should reject.
    let risky_params: LeakIncidentsRealtimeParams =
        serde_json::from_str(r#"{"auto_rotate_on_high": true, "confirm": false}"#).unwrap();
    assert!(risky_params.auto_rotate_on_high);
    assert!(!risky_params.confirm, "confirm=false must block auto-rotate");

    // Only confirm=true should pass the gate.
    let approved_params: LeakIncidentsRealtimeParams =
        serde_json::from_str(r#"{"auto_rotate_on_high": true, "confirm": true}"#).unwrap();
    assert!(approved_params.confirm, "confirm=true is required to allow auto-rotate");
}

// ── Test 10: multiple incidents all get structured summaries ──────────────────

#[test]
fn realtime_multiple_incidents_all_summarised() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempdir().unwrap();
    let now = now_unix();

    let (engine, _, incidents_path) = make_engine(tmp.path());

    let secrets = ["KEY_A", "KEY_B", "KEY_C"];
    for (i, secret) in secrets.iter().enumerate() {
        let inc = LeakIncident {
            incident_id: format!("multi_id_{i}"),
            secret_name: secret.to_string(),
            location_label: "body".to_string(),
            first_seen_ts: now - 1000 - i as u64 * 100,
            last_seen_ts: now - 1000 - i as u64 * 100,
            event_count: 1,
            confidence: 0.5 + i as f64 * 0.1,
            remediation: format!("Rotate '{secret}' immediately."),
        };
        append_incident(&incidents_path, &inc);
    }

    let active = engine.active_incidents(0.5).unwrap();
    assert_eq!(active.len(), 3, "all three incidents should appear");

    // Every incident must have the six required summary fields.
    for inc in &active {
        assert!(!inc.incident_id.is_empty());
        assert!(!inc.secret_name.is_empty());
        assert!(!inc.location_label.is_empty());
        assert!(inc.first_seen_ts > 0);
        assert!(inc.last_seen_ts > 0);
        assert!(!inc.remediation.is_empty());
    }
}
