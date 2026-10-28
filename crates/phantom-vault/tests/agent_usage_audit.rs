//! Generated-input regression using only a temporary vault and synthetic data.
use phantom_vault::{file::FileVault, VaultBackend};
use rand::RngCore;

#[test]
fn fuzz_agent_operations_are_value_blind_and_unknown_engines_are_refused() {
    let home = tempfile::tempdir().unwrap();
    // SAFETY: this integration binary has one test and no concurrent env users.
    unsafe {
        std::env::set_var("HOME", home.path());
        std::env::set_var("PHANTOM_ENGINE_ID", "codex");
        std::env::remove_var("PHANTOM_AUDIT");
        std::env::remove_var("PHANTOM_AUDIT_ENCRYPTION");
    }
    let root = home.path().join("test-vault");
    std::fs::create_dir(&root).unwrap();
    let vault = FileVault::new(&root, "audit-test", "synthetic-test-passphrase".into()).unwrap();
    let log = home.path().join(".phantom/audit.log");
    let mut forbidden = Vec::new();
    for index in 0..32 {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let random: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let secret = format!("synthetic-{index}-{random}\"\\\n\r\tπ-phm_");
        let replacement = format!("replacement-{random}");
        forbidden.push(secret.clone());
        forbidden.push(replacement.clone());
        vault.store("AUDIT_TEST_KEY", &secret).unwrap();
        // Never assert_eq! values: even a failing test must stay value-blind.
        assert!(vault.retrieve("AUDIT_TEST_KEY").unwrap().as_str() == secret);
        assert!(
            vault
                .retrieve_for_injection("AUDIT_TEST_KEY")
                .unwrap()
                .as_str()
                == secret
        );
        assert!(vault
            .compare_and_swap("AUDIT_TEST_KEY", Some(&secret), Some(&replacement))
            .unwrap());
        phantom_core::audit::log_route_use("AUDIT_TEST_KEY", "openai", "api.openai.com").unwrap();
        phantom_core::audit::operation_batch(
            "secret.token_remapped",
            &["AUDIT_TEST_KEY"],
            || Ok::<_, std::io::Error>(()),
            |e| e,
        )
        .unwrap();
    }
    assert!(vault.retrieve("MISSING_TEST_KEY").is_err());
    let content = std::fs::read_to_string(&log).unwrap();
    for value in &forbidden {
        assert!(!content.contains(value), "raw credential reached audit log");
        let escaped = serde_json::to_string(value).unwrap();
        assert!(
            !content.contains(&escaped[1..escaped.len() - 1]),
            "escaped credential reached audit log"
        );
    }
    let events: Vec<serde_json::Value> = content
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for op in [
        "vault.store",
        "vault.retrieve",
        "vault.retrieve_for_injection",
        "vault.compare_and_swap",
        "proxy.use",
        "secret.token_remapped",
    ] {
        assert!(events
            .iter()
            .any(|v| v["op"] == op && (v["outcome"] == "success" || v["outcome"] == "admitted")));
    }
    assert!(events
        .iter()
        .any(|v| v["name"] == "MISSING_TEST_KEY" && v["outcome"] == "failure"));
    assert!(events
        .iter()
        .filter(|v| v.get("op").is_some())
        .all(|v| v["actor"] == "codex"
            && v["ts"].is_u64()
            && v["route"].is_string()
            && v["host"].is_string()));
    assert!(phantom_core::audit::verify_log().unwrap().is_clean());

    let vault_file = root.join("vaults/audit-test.vault");
    let before = std::fs::read(&vault_file).unwrap();
    let unknown = &forbidden[0];
    unsafe {
        std::env::set_var("PHANTOM_ENGINE_ID", unknown);
    }
    assert!(vault
        .store("REFUSED_TEST_KEY", "synthetic-refused-value")
        .is_err());
    assert!(vault.retrieve("AUDIT_TEST_KEY").is_err());
    assert!(vault.retrieve_for_injection("AUDIT_TEST_KEY").is_err());
    assert!(vault
        .compare_and_swap("AUDIT_TEST_KEY", None, None)
        .is_err());
    assert!(
        phantom_core::audit::log_route_use("AUDIT_TEST_KEY", "openai", "api.openai.com").is_err()
    );
    assert!(before == std::fs::read(&vault_file).unwrap());
    let content = std::fs::read_to_string(&log).unwrap();
    assert!(!content.contains(unknown));
    let refused: Vec<serde_json::Value> = content
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v["op"] == "engine.refused")
        .collect();
    assert_eq!(refused.len(), 5);
    assert!(refused.iter().all(|v| v["outcome"] == "refused"
        && v["actor"].as_str().unwrap().starts_with("unknown:sha256:")));
    assert!(phantom_core::audit::verify_log().unwrap().is_clean());

    // Mandatory admission append failure precedes any vault mutation.
    unsafe {
        std::env::set_var("PHANTOM_ENGINE_ID", "codex");
    }
    std::fs::rename(&log, log.with_extension("saved")).unwrap();
    std::fs::create_dir(&log).unwrap();
    assert!(vault
        .store("REFUSED_TEST_KEY", "synthetic-refused-value")
        .is_err());
    assert!(before == std::fs::read(&vault_file).unwrap());
}
