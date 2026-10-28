use super::*;
use serde_json::Value;
use tempfile::tempdir;

fn fake_mcp() -> McpCommand {
    McpCommand::for_test("/usr/local/bin/phantom-mcp", &[])
}

#[test]
fn claude_writer_migrates_stale_registry_entry_and_preserves_settings() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join(".claude/settings.local.json");
    std::fs::create_dir(tmp.path().join(".claude")).unwrap();
    std::fs::write(
        &path,
        r#"{
                "mcpServers": {
                    "phantom": {"command": "npx", "args": ["-y", "phantom-secrets-mcp"]},
                    "other": {"command": "other-server"}
                },
                "theme": "dark"
            }"#,
    )
    .unwrap();

    let mcp = McpCommand {
        command: "/opt/phantom/bin/phantom".to_string(),
        args: vec!["mcp".to_string(), "serve".to_string()],
    };
    let plan = prepare_claude_settings(&path, &mcp).unwrap();
    assert!(apply_claude_settings(&plan).unwrap());

    let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let registration: Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.path().join(".mcp.json")).unwrap())
            .unwrap();
    assert_eq!(
        registration["mcpServers"]["phantom"],
        serde_json::json!({
            "command": "/opt/phantom/bin/phantom",
            "args": ["mcp", "serve"]
        })
    );
    assert_eq!(value["mcpServers"]["other"]["command"], "other-server");
    assert_eq!(value["theme"], "dark");
    assert!(value["mcpServers"].get("phantom").is_none());
    assert!(!value.to_string().contains("npx"));
    let repeated = prepare_claude_settings(&path, &mcp).unwrap();
    assert!(!apply_claude_settings(&repeated).unwrap());
}

#[test]
fn claude_writer_rejects_concurrent_edit() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join(".claude/settings.local.json");
    std::fs::create_dir(tmp.path().join(".claude")).unwrap();
    std::fs::write(&path, r#"{"theme":"before"}"#).unwrap();
    let plan = prepare_claude_settings(&path, &fake_mcp()).unwrap();
    let concurrent = br#"{"theme":"concurrent-owner"}"#;
    std::fs::write(&path, concurrent).unwrap();

    let error = apply_claude_settings(&plan).unwrap_err();
    assert!(error.to_string().contains("changed after setup read it"));
    assert_eq!(std::fs::read(&path).unwrap(), concurrent);
    assert!(!tmp.path().join(".mcp.json").exists());
}

#[cfg(unix)]
#[test]
fn claude_setup_uses_retained_project_after_rename() {
    let container = tempdir().unwrap();
    let project = container.path().join("project");
    let moved = container.path().join("moved");
    std::fs::create_dir(&project).unwrap();

    setup_claude_code_in(&project, &fake_mcp(), || {
        std::fs::rename(&project, &moved).unwrap();
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("owner"), b"decoy").unwrap();
    })
    .unwrap();

    assert!(moved.join(".claude/settings.local.json").exists());
    assert!(moved.join(".mcp.json").exists());
    assert!(!project.join(".claude/settings.local.json").exists());
    assert!(!project.join(".mcp.json").exists());
    assert_eq!(std::fs::read(project.join("owner")).unwrap(), b"decoy");
}

#[test]
fn claude_writer_rolls_back_registration_after_settings_drift() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join(".claude/settings.local.json");
    std::fs::create_dir(tmp.path().join(".claude")).unwrap();
    std::fs::write(&path, r#"{"permissions":{"allow":["Read(./.env)"]}}"#).unwrap();
    let plan = prepare_claude_settings(&path, &fake_mcp()).unwrap();
    let lock = phantom_vault::acquire_project_transaction_lock(tmp.path()).unwrap();
    let concurrent = br#"{"theme":"concurrent-owner"}"#;
    let error = apply_claude_targets_with(
        &plan,
        &lock.target(&path).unwrap(),
        &lock.target(&plan.mcp_path).unwrap(),
        || {
            std::fs::write(&path, concurrent).unwrap();
        },
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("previous configuration changes were restored"));
    assert_eq!(std::fs::read(&path).unwrap(), concurrent);
    assert!(!plan.mcp_path.exists());
}

#[test]
fn claude_writer_preserves_existing_project_servers() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join(".claude/settings.local.json");
    std::fs::create_dir(tmp.path().join(".claude")).unwrap();
    std::fs::write(&path, "{}").unwrap();
    let mcp_path = tmp.path().join(".mcp.json");
    std::fs::write(
        &mcp_path,
        r#"{"mcpServers":{"other":{"command":"other","env":{"MODE":"test"}}},"owner":"team"}"#,
    )
    .unwrap();
    let plan = prepare_claude_settings(&path, &fake_mcp()).unwrap();
    apply_claude_settings(&plan).unwrap();
    let value: Value = serde_json::from_slice(&std::fs::read(&mcp_path).unwrap()).unwrap();
    assert_eq!(value["mcpServers"]["other"]["env"]["MODE"], "test");
    assert_eq!(value["owner"], "team");
    assert!(value["mcpServers"].get("phantom").is_some());
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
}

#[test]
fn legacy_dotenv_grant_removal_is_exact_and_preserves_denies() {
    let mut permissions = serde_json::json!({
        "allow": [
            "Read(./.env)",
            "Read(./.env.*)",
            "Read(./.env.example)",
            "Bash(cargo test:*)"
        ],
        "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./secrets/**)"]
    });
    let expected_denies = permissions["deny"].clone();
    let permissions = permissions.as_object_mut().unwrap();

    assert!(remove_legacy_dotenv_read_grants(permissions));
    assert_eq!(
        permissions["allow"],
        serde_json::json!(["Read(./.env.example)", "Bash(cargo test:*)"])
    );
    assert_eq!(permissions["deny"], expected_denies);
    assert!(!remove_legacy_dotenv_read_grants(permissions));
}
