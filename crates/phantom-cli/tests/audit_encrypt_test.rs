//! Compliance-grade audit encryption tests.
//!
//! Covers:
//! - `AuditEventEncryption` enum parsing from env
//! - `AuditContext` collection
//! - `encrypt_context` / `decrypt_context` round-trip
//! - Concurrent writes with encryption enabled
//! - ED25519 signing and verification
//! - `verify_log_with_context` with encrypted events
//! - Error handling for invalid ciphertext
//! - HMAC chain still valid with `encrypted_context` field
//! - `phantom audit verify --with-context` integration

mod common;

use phantom_core::audit::{
    decrypt_context, encrypt_context_for_test, log, log_result, verify_log,
    verify_log_with_context, verify_sidecar_event, AuditContext, AuditEventEncryption,
    SidecarEvent,
};
use std::sync::{Arc, Barrier, Mutex};

// ─────────────────────────────────────────────────────────────────────────────
// Shared test infrastructure
// ─────────────────────────────────────────────────────────────────────────────

/// A single process-wide lock so tests that mutate env vars don't race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` with `HOME=tmp_dir`, `PHANTOM_AUDIT=1`, and the given encryption mode.
fn with_encrypt_env<F: FnOnce(&std::path::Path)>(enc: &str, f: F) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = common::canonical_tempdir();
    let prev_home = std::env::var("HOME").ok();
    let prev_audit = std::env::var("PHANTOM_AUDIT").ok();
    let prev_enc = std::env::var("PHANTOM_AUDIT_ENCRYPTION").ok();
    unsafe {
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("PHANTOM_AUDIT", "1");
        if enc.is_empty() {
            std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION");
        } else {
            std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", enc);
        }
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
        match prev_enc {
            Some(p) => std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", p),
            None => std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION"),
        }
    }
}

fn with_audit_env<F: FnOnce(&std::path::Path)>(f: F) {
    with_encrypt_env("", f);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. AuditEventEncryption enum parsing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn encryption_disabled_by_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("PHANTOM_AUDIT_ENCRYPTION").ok();
    unsafe { std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION") };
    assert_eq!(
        AuditEventEncryption::from_env(),
        AuditEventEncryption::Disabled
    );
    unsafe {
        match prev {
            Some(p) => std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", p),
            None => std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION"),
        }
    }
}

#[test]
fn encryption_local_from_env() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("PHANTOM_AUDIT_ENCRYPTION").ok();
    for val in &["local", "LOCAL", "local-only", "LOCAL-ONLY"] {
        unsafe { std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", val) };
        assert_eq!(
            AuditEventEncryption::from_env(),
            AuditEventEncryption::LocalOnly,
            "expected LocalOnly for '{val}'"
        );
    }
    unsafe {
        match prev {
            Some(p) => std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", p),
            None => std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION"),
        }
    }
}

#[test]
fn encryption_cloud_signed_from_env() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("PHANTOM_AUDIT_ENCRYPTION").ok();
    for val in &["cloud-signed", "CLOUD-SIGNED", "cloud_signed"] {
        unsafe { std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", val) };
        assert_eq!(
            AuditEventEncryption::from_env(),
            AuditEventEncryption::CloudSigned,
            "expected CloudSigned for '{val}'"
        );
    }
    unsafe {
        match prev {
            Some(p) => std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", p),
            None => std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION"),
        }
    }
}

#[test]
fn encryption_unknown_value_gives_disabled() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = std::env::var("PHANTOM_AUDIT_ENCRYPTION").ok();
    unsafe { std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", "foobar") };
    assert_eq!(
        AuditEventEncryption::from_env(),
        AuditEventEncryption::Disabled
    );
    unsafe {
        match prev {
            Some(p) => std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", p),
            None => std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION"),
        }
    }
}

#[test]
fn encryption_is_active_for_non_disabled() {
    assert!(!AuditEventEncryption::Disabled.is_active());
    assert!(AuditEventEncryption::LocalOnly.is_active());
    assert!(AuditEventEncryption::CloudSigned.is_active());
}

#[test]
fn cloud_signed_setup_is_a_non_mutating_hard_denial() {
    use assert_cmd::Command;

    let tmp = common::canonical_tempdir();
    let output = Command::cargo_bin("phantom")
        .expect("binary not found")
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .args(["setup", "--audit-mode", "cloud-signed"])
        .assert()
        .failure()
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cloud-signed audit delivery is not commissioned")
            && stderr.contains("no key, file, or network state was changed"),
        "unexpected denial: {stderr}"
    );
    assert!(
        !tmp.path().join(".phantom/audit-ed25519.pub").exists(),
        "reserved setup must not create public-key state"
    );
}

#[test]
fn legacy_cloud_signed_request_retains_encrypted_event_locally() {
    with_encrypt_env("cloud-signed", |tmp| {
        log_result("vault.store", Some("LEGACY_CLOUD_KEY"))
            .expect("legacy cloud-signed request should retain the event locally");

        let report = verify_log().expect("local HMAC chain should verify");
        assert_eq!(report.verified, 1);
        assert!(report.is_clean());

        let (_, events) = verify_log_with_context().expect("local context should decrypt");
        assert_eq!(events.len(), 1);
        assert!(events[0].context.is_some());

        let content = std::fs::read_to_string(tmp.join(".phantom/audit.log")).unwrap();
        let event = content
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|value| value.get("op").is_some())
            .expect("audit event should follow the signed-era marker");
        assert_eq!(event["op"], "vault.store");
        assert_eq!(event["name"], "LEGACY_CLOUD_KEY");
        assert!(event.get("encrypted_context").is_some());
        assert!(event.get("signature").is_none());
        assert!(event.get("pubkey").is_none());
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. encrypt_context / decrypt_context round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn encryption_round_trip_local_only() {
    let key = b"test-hmac-key-32-bytes-long-xxxx";
    let encrypted = encrypt_context_for_test(key, AuditEventEncryption::LocalOnly)
        .expect("encrypt should succeed");
    assert!(!encrypted.is_empty());

    let ctx = decrypt_context(&encrypted, key).expect("decrypt should succeed");
    // process_name and hostname should be non-empty strings
    assert!(!ctx.process_name.is_empty());
    // hostname is best-effort; just check it's a String
    let _ = ctx.hostname;
}

#[test]
fn encryption_round_trip_different_keys_fail() {
    let key1 = b"key-one-32-bytes-long-padding-xx";
    let key2 = b"key-two-32-bytes-long-padding-xx";
    let encrypted = encrypt_context_for_test(key1, AuditEventEncryption::LocalOnly)
        .expect("encrypt should succeed");

    let result = decrypt_context(&encrypted, key2);
    assert!(result.is_err(), "decryption with wrong key should fail");
}

#[test]
fn encryption_round_trip_truncated_ciphertext_fails() {
    let key = b"test-hmac-key-32-bytes-long-xxxx";
    let encrypted = encrypt_context_for_test(key, AuditEventEncryption::LocalOnly)
        .expect("encrypt should succeed");

    // Truncate to 5 bytes (less than 12-byte nonce) via base64 manipulation
    let result = decrypt_context("AAAA", key);
    assert!(result.is_err(), "too-short ciphertext should fail");
    let _ = encrypted;
}

#[test]
fn encryption_round_trip_invalid_base64_fails() {
    let key = b"test-hmac-key-32-bytes-long-xxxx";
    let result = decrypt_context("not-valid-base64!!!", key);
    assert!(result.is_err(), "invalid base64 should fail");
}

#[test]
fn encryption_context_contains_expected_fields() {
    let key = b"test-hmac-key-32-bytes-long-xxxx";
    let encrypted = encrypt_context_for_test(key, AuditEventEncryption::LocalOnly)
        .expect("encrypt should succeed");
    let ctx = decrypt_context(&encrypted, key).expect("decrypt should succeed");

    // process_name should be a reasonable string (not empty, not binary)
    assert!(!ctx.process_name.is_empty());
    // ppid is a u32 (can be 0 on non-Unix)
    let _ = ctx.ppid;
    // cwd is a string
    let _ = ctx.cwd;
}

#[test]
fn encryption_produces_different_ciphertext_each_time() {
    let key = b"test-hmac-key-32-bytes-long-xxxx";
    let enc1 = encrypt_context_for_test(key, AuditEventEncryption::LocalOnly).unwrap();
    let enc2 = encrypt_context_for_test(key, AuditEventEncryption::LocalOnly).unwrap();
    // Nonces are random so ciphertexts must differ
    assert_ne!(enc1, enc2, "random nonces ensure different ciphertexts");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Audit log writes encrypted_context field when LocalOnly enabled
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn local_encryption_writes_encrypted_context_field() {
    with_encrypt_env("local", |tmp| {
        log("vault.store", Some("MY_KEY"));

        let log_p = tmp.join(".phantom").join("audit.log");
        let content = std::fs::read_to_string(&log_p).expect("log should exist");

        let event_lines: Vec<serde_json::Value> = content
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .filter(|v: &serde_json::Value| v.get("hmac_chain_started_at").is_none())
            .collect();

        assert!(!event_lines.is_empty(), "should have at least one event");
        let event = &event_lines[0];
        assert!(
            event.get("encrypted_context").is_some(),
            "encrypted_context field should be present when LocalOnly"
        );
        let ec = event["encrypted_context"].as_str().unwrap();
        assert!(!ec.is_empty(), "encrypted_context should not be empty");
    });
}

#[test]
fn disabled_encryption_omits_encrypted_context_field() {
    with_audit_env(|tmp| {
        log("vault.store", Some("MY_KEY"));

        let log_p = tmp.join(".phantom").join("audit.log");
        let content = std::fs::read_to_string(&log_p).expect("log should exist");

        let event_lines: Vec<serde_json::Value> = content
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .filter(|v: &serde_json::Value| v.get("hmac_chain_started_at").is_none())
            .collect();

        assert!(!event_lines.is_empty());
        let event = &event_lines[0];
        assert!(
            event.get("encrypted_context").is_none(),
            "encrypted_context should be absent when Disabled"
        );
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. HMAC chain still valid with encrypted_context field
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hmac_chain_valid_with_local_encryption() {
    with_encrypt_env("local", |_tmp| {
        log("vault.store", Some("KEY_A"));
        log("vault.retrieve", Some("KEY_A"));
        log("cloud.push", None);

        let report = verify_log().expect("verify_log should not error");
        assert_eq!(report.tampered, 0, "no tampered lines with encryption");
        assert_eq!(report.verified, 3, "3 events verified");
        assert!(report.is_clean(), "report should be clean");
    });
}

#[test]
fn hmac_chain_detects_tampered_encrypted_context() {
    with_encrypt_env("local", |tmp| {
        log("vault.store", Some("KEY_A"));

        let log_p = tmp.join(".phantom").join("audit.log");
        let content = std::fs::read_to_string(&log_p).unwrap();

        // Tamper the encrypted_context field in the event line
        let new_content: String = content
            .lines()
            .map(|line| {
                let Ok(mut v) = serde_json::from_str::<serde_json::Value>(line) else {
                    return line.to_string();
                };
                if v.get("hmac_chain_started_at").is_some() {
                    return line.to_string();
                }
                if v.get("encrypted_context").is_some() {
                    v.as_object_mut().unwrap().insert(
                        "encrypted_context".to_string(),
                        serde_json::json!("TAMPERED=="),
                    );
                }
                serde_json::to_string(&v).unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";

        std::fs::write(&log_p, new_content).unwrap();

        let report = verify_log().expect("verify_log should not error");
        assert!(
            report.tampered >= 1,
            "tampered encrypted_context should be detected by HMAC"
        );
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Concurrent writes with encryption
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_writes_with_local_encryption_verify_clean() {
    with_encrypt_env("local", |tmp| {
        let workers = 16_usize;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::new();

        for i in 0..workers {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                log("vault.retrieve", Some(&format!("ENC_KEY_{i}")));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let report = verify_log().expect("verify_log should not error");
        assert!(
            report.is_clean(),
            "concurrent encrypted log should be clean: {report:?}"
        );
        assert_eq!(report.verified, workers, "all events verified");

        // All event lines should have encrypted_context
        let log_p = tmp.join(".phantom").join("audit.log");
        let content = std::fs::read_to_string(&log_p).unwrap();
        let events_without_ec: Vec<_> = content
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v.get("hmac_chain_started_at").is_none())
            .filter(|v| v.get("encrypted_context").is_none())
            .collect();
        assert!(
            events_without_ec.is_empty(),
            "all events should have encrypted_context in LocalOnly mode"
        );
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. verify_log_with_context decrypts context
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn verify_with_context_decrypts_events() {
    with_encrypt_env("local", |_tmp| {
        log("vault.store", Some("KEY_A"));
        log("vault.retrieve", Some("KEY_B"));

        let (report, events) = verify_log_with_context().expect("verify_with_context should work");
        assert!(report.is_clean(), "report should be clean");
        assert_eq!(events.len(), 2, "two events returned");

        for ev in &events {
            assert!(
                ev.context.is_some(),
                "each event should have decrypted context: {:?}",
                ev.context_error
            );
            let ctx = ev.context.as_ref().unwrap();
            assert!(!ctx.process_name.is_empty(), "process_name should be set");
        }
    });
}

#[test]
fn verify_with_context_no_encrypted_context_returns_none() {
    with_audit_env(|_tmp| {
        // Write without encryption
        log("vault.store", Some("KEY_A"));

        let (report, events) = verify_log_with_context().expect("verify_with_context should work");
        assert!(report.is_clean());
        assert_eq!(events.len(), 1);
        // No encrypted_context → context is None, no error
        assert!(events[0].context.is_none());
        assert!(events[0].context_error.is_none());
    });
}

#[test]
fn verify_with_context_returns_correct_line_numbers() {
    with_encrypt_env("local", |_tmp| {
        log("vault.store", Some("K1"));
        log("vault.retrieve", Some("K2"));
        log("cloud.push", None);

        let (_, events) = verify_log_with_context().expect("should not error");
        // Events should be in order (line_no ascending)
        for w in events.windows(2) {
            assert!(w[0].line_no < w[1].line_no, "events must be in line order");
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. ED25519 signing and verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sidecar_event_ed25519_sign_verify_roundtrip() {
    // Build a sidecar event manually to test sign/verify without keychain.
    // Keep the protocol fixture pure: production binaries do not provision a
    // signing key or commission a delivery transport.
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;

    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    let encrypted_context = "dGVzdA=="; // base64("test")
    let mut canonical_map: BTreeMap<&str, String> = BTreeMap::new();
    canonical_map.insert("seq", "1".to_string());
    canonical_map.insert("ts", "1700000000".to_string());
    canonical_map.insert("op", "vault.store".to_string());
    canonical_map.insert("encrypted_context", encrypted_context.to_string());
    canonical_map.insert("pubkey", pubkey_hex.clone());
    canonical_map.insert("name", "TEST_KEY".to_string());
    let payload = serde_json::to_vec(&canonical_map).unwrap();
    let signature = signing_key.sign(&payload);
    let sig_hex = hex::encode(signature.to_bytes());

    let event = SidecarEvent {
        seq: 1,
        ts: 1_700_000_000,
        op: "vault.store".to_string(),
        name: Some("TEST_KEY".to_string()),
        encrypted_context: encrypted_context.to_string(),
        signature: sig_hex,
        pubkey: pubkey_hex,
    };

    assert!(
        verify_sidecar_event(&event),
        "valid signature should verify"
    );
}

#[test]
fn sidecar_event_invalid_signature_rejected() {
    use ed25519_dalek::{Signer, SigningKey};

    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let other_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    // Sign with `other_key` but include `signing_key`'s pubkey → mismatch
    use std::collections::BTreeMap;
    let mut canonical_map: BTreeMap<&str, String> = BTreeMap::new();
    canonical_map.insert("seq", "1".to_string());
    canonical_map.insert("ts", "1700000000".to_string());
    canonical_map.insert("op", "vault.store".to_string());
    canonical_map.insert("encrypted_context", "dGVzdA==".to_string());
    canonical_map.insert("pubkey", pubkey_hex.clone());
    let payload = serde_json::to_vec(&canonical_map).unwrap();
    let bad_signature = other_key.sign(&payload);

    let event = SidecarEvent {
        seq: 1,
        ts: 1_700_000_000,
        op: "vault.store".to_string(),
        name: None,
        encrypted_context: "dGVzdA==".to_string(),
        signature: hex::encode(bad_signature.to_bytes()),
        pubkey: pubkey_hex,
    };

    assert!(
        !verify_sidecar_event(&event),
        "bad signature should be rejected"
    );
}

#[test]
fn sidecar_event_tampered_payload_rejected() {
    use ed25519_dalek::{Signer, SigningKey};

    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    use std::collections::BTreeMap;
    let mut canonical_map: BTreeMap<&str, String> = BTreeMap::new();
    canonical_map.insert("seq", "1".to_string());
    canonical_map.insert("ts", "1700000000".to_string());
    canonical_map.insert("op", "vault.store".to_string());
    canonical_map.insert("encrypted_context", "dGVzdA==".to_string());
    canonical_map.insert("pubkey", pubkey_hex.clone());
    let payload = serde_json::to_vec(&canonical_map).unwrap();
    let signature = signing_key.sign(&payload);

    // Create event with tampered `op`
    let event = SidecarEvent {
        seq: 1,
        ts: 1_700_000_000,
        op: "TAMPERED".to_string(), // <-- changed
        name: None,
        encrypted_context: "dGVzdA==".to_string(),
        signature: hex::encode(signature.to_bytes()),
        pubkey: pubkey_hex,
    };

    assert!(
        !verify_sidecar_event(&event),
        "tampered op field should invalidate signature"
    );
}

#[test]
fn sidecar_event_bad_pubkey_hex_rejected() {
    let event = SidecarEvent {
        seq: 1,
        ts: 0,
        op: "test".to_string(),
        name: None,
        encrypted_context: "abc".to_string(),
        signature: "abc".to_string(),
        pubkey: "not-valid-hex!!".to_string(),
    };
    assert!(!verify_sidecar_event(&event));
}

#[test]
fn sidecar_event_bad_signature_hex_rejected() {
    let event = SidecarEvent {
        seq: 1,
        ts: 0,
        op: "test".to_string(),
        name: None,
        encrypted_context: "abc".to_string(),
        signature: "not-valid-hex!!".to_string(),
        pubkey: "a".repeat(64), // 32 zero bytes in hex
    };
    assert!(!verify_sidecar_event(&event));
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. AuditContext collection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn audit_context_collect_has_process_name() {
    let ctx = AuditContext::collect();
    assert!(
        !ctx.process_name.is_empty(),
        "process_name should not be empty"
    );
}

#[test]
fn audit_context_collect_has_hostname() {
    let ctx = AuditContext::collect();
    // hostname is best-effort; at minimum it should be a string
    assert!(
        ctx.hostname.len() < 1024,
        "hostname should be a reasonable string"
    );
}

#[test]
fn audit_context_serde_roundtrip() {
    let ctx = AuditContext {
        process_name: "phantom-test".to_string(),
        hostname: "test-host".to_string(),
        ppid: 42,
        cwd: "/tmp/test".to_string(),
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let back: AuditContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back.process_name, "phantom-test");
    assert_eq!(back.hostname, "test-host");
    assert_eq!(back.ppid, 42);
    assert_eq!(back.cwd, "/tmp/test");
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Encryption integration: write + verify_log full flow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn write_with_encryption_verify_and_decrypt_full_flow() {
    with_encrypt_env("local", |tmp| {
        // Write several events
        log("vault.store", Some("API_KEY_1"));
        log("vault.retrieve", Some("API_KEY_1"));
        log("vault.delete", Some("API_KEY_1"));

        // Verify HMAC chain
        let report = verify_log().expect("verify_log should not error");
        assert_eq!(report.verified, 3, "3 events verified");
        assert!(report.is_clean());

        // Verify + decrypt context
        let (report2, events) = verify_log_with_context().expect("should not error");
        assert!(report2.is_clean());
        assert_eq!(events.len(), 3);

        for (i, ev) in events.iter().enumerate() {
            assert!(
                ev.context.is_some(),
                "event {i} should have decrypted context"
            );
            assert!(ev.context_error.is_none());
        }

        // Log still contains encrypted_context fields
        let log_p = tmp.join(".phantom").join("audit.log");
        let content = std::fs::read_to_string(&log_p).unwrap();
        let ec_count = content
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v.get("encrypted_context").is_some())
            .count();
        assert_eq!(ec_count, 3, "all 3 events should have encrypted_context");
    });
}

#[test]
fn log_result_required_with_encryption() {
    with_encrypt_env("local", |_tmp| {
        let result = log_result("vault.store", Some("REQUIRED_KEY"));
        assert!(result.is_ok(), "log_result should succeed with encryption");
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Mixed: some events encrypted, some not (backward compat)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mixed_encrypted_and_plain_events_verify_clean() {
    // Write 3 events: plain, encrypted, plain — verify HMAC chain stays clean.
    // We do this in two separate env setups since ENV_LOCK is not re-entrant.
    let tmp = common::canonical_tempdir();

    // Step 1: Write one plain event (no encryption)
    {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("PHANTOM_AUDIT", "1");
            std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION");
        }
        log("vault.store", Some("PLAIN_KEY"));
        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("PHANTOM_AUDIT");
        }
    }

    // Step 2: Write one encrypted event
    {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("PHANTOM_AUDIT", "1");
            std::env::set_var("PHANTOM_AUDIT_ENCRYPTION", "local");
        }
        log("vault.retrieve", Some("PLAIN_KEY"));
        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("PHANTOM_AUDIT");
            std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION");
        }
    }

    // Step 3: Write another plain event
    {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("PHANTOM_AUDIT", "1");
            std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION");
        }
        log("cloud.push", None);

        let report = verify_log().expect("verify_log should not error");
        assert_eq!(report.verified, 3, "all 3 events verified");
        assert!(report.is_clean(), "mixed events should still be clean");

        // Verify+decrypt: first and last events have no context, second does
        let (_, events) = verify_log_with_context().unwrap();
        assert_eq!(events.len(), 3);
        assert!(events[0].context.is_none());
        assert!(events[1].context.is_some()); // encrypted
        assert!(events[2].context.is_none());

        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("PHANTOM_AUDIT");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Sidecar event serialisation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sidecar_event_serializes_correctly() {
    let event = SidecarEvent {
        seq: 42,
        ts: 1_700_000_000,
        op: "vault.store".to_string(),
        name: Some("MY_KEY".to_string()),
        encrypted_context: "dGVzdA==".to_string(),
        signature: "aabbcc".to_string(),
        pubkey: "ddeeff".to_string(),
    };
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["seq"], 42);
    assert_eq!(json["op"], "vault.store");
    assert_eq!(json["name"], "MY_KEY");
    assert_eq!(json["encrypted_context"], "dGVzdA==");
    assert!(json.get("signature").is_some());
}

#[test]
fn sidecar_event_omits_name_when_none() {
    let event = SidecarEvent {
        seq: 1,
        ts: 0,
        op: "cloud.push".to_string(),
        name: None,
        encrypted_context: "abc".to_string(),
        signature: "def".to_string(),
        pubkey: "ghi".to_string(),
    };
    let json = serde_json::to_value(&event).unwrap();
    assert!(
        json.get("name").is_none(),
        "name should be omitted when None"
    );
}

#[test]
fn sidecar_event_roundtrip_serde() {
    let event = SidecarEvent {
        seq: 7,
        ts: 1_234_567_890,
        op: "vault.delete".to_string(),
        name: Some("TOKEN".to_string()),
        encrypted_context: "Y2lwaGVydGV4dA==".to_string(),
        signature: "s".repeat(128),
        pubkey: "p".repeat(64),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SidecarEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.seq, 7);
    assert_eq!(back.op, "vault.delete");
    assert_eq!(back.name.as_deref(), Some("TOKEN"));
}
