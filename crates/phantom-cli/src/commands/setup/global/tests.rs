use super::*;
use serde_json::Value;
use tempfile::tempdir;

fn fake_mcp() -> McpCommand {
    McpCommand::for_test("/usr/local/bin/phantom-mcp", &[])
}

#[test]
fn cursor_writer_creates_config_when_missing() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mcp.json");
    upsert_mcp_servers_json(&path, &fake_mcp()).unwrap();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        v["mcpServers"]["phantom"]["command"],
        "/usr/local/bin/phantom-mcp"
    );
    assert_eq!(
        v["mcpServers"]["phantom"]["args"].as_array().unwrap().len(),
        0
    );
}

#[test]
fn cursor_writer_preserves_other_settings() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mcp.json");
    std::fs::write(
        &path,
        r#"{"mcpServers": {"other": {"command": "x"}}, "extra": 42}"#,
    )
    .unwrap();
    upsert_mcp_servers_json(&path, &fake_mcp()).unwrap();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["mcpServers"]["other"]["command"], "x");
    assert_eq!(
        v["mcpServers"]["phantom"]["command"],
        "/usr/local/bin/phantom-mcp"
    );
    assert_eq!(v["extra"], 42);
}

#[test]
fn cursor_writer_refuses_a_differing_entry_and_leaves_the_file_untouched() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mcp.json");
    let original =
            br#"{"mcpServers": {"phantom": {"command": "/old/path", "args": ["x"], "env": {"K": "never-print"}}}}"#;
    std::fs::write(&path, original).unwrap();
    let error = upsert_mcp_servers_json(&path, &fake_mcp()).unwrap_err();
    let text = format!("{error:#}");
    assert!(text.contains("mcpServers.phantom"), "{text}");
    assert!(text.contains("--replace"), "{text}");
    assert!(!text.contains("never-print"), "{text}");
    assert_eq!(std::fs::read(&path).unwrap(), original);
    // No backup or manifest appears for a refusal.
    assert!(!setup_backup::manifest_path(tmp.path()).exists());
    let backups = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".phantom-bak-")
        })
        .count();
    assert_eq!(backups, 0);
}

#[test]
fn cursor_writer_replaces_a_differing_entry_with_replace_after_a_backup() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mcp.json");
    let original = br#"{"mcpServers": {"phantom": {"command": "/old/path", "args": ["x"]}}}"#;
    std::fs::write(&path, original).unwrap();
    upsert_mcp_servers_json_with(&path, &fake_mcp(), true).unwrap();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        v["mcpServers"]["phantom"]["command"],
        "/usr/local/bin/phantom-mcp"
    );
    assert_eq!(
        v["mcpServers"]["phantom"]["args"].as_array().unwrap().len(),
        0
    );
    let backups: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().contains(".phantom-bak-"))
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read(&backups[0]).unwrap(), original);
    let manifest = setup_backup::load(tmp.path()).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    let entry = &manifest.entries[0];
    assert_eq!(entry.action, "replace");
    assert_eq!(entry.backup.as_deref(), Some(backups[0].as_path()));
    assert_eq!(
        entry.sha256_before.as_deref(),
        Some(setup_backup::sha256_hex(original).as_str())
    );
    assert_eq!(
        entry.sha256_after,
        setup_backup::sha256_hex(&std::fs::read(&path).unwrap())
    );
}

#[test]
fn identical_entry_writes_nothing_and_records_nothing() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mcp.json");
    upsert_mcp_servers_json(&path, &fake_mcp()).unwrap();
    let first = std::fs::read(&path).unwrap();
    let manifest_before = setup_backup::load(tmp.path()).unwrap().entries.len();
    upsert_mcp_servers_json(&path, &fake_mcp()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), first);
    assert_eq!(
        setup_backup::load(tmp.path()).unwrap().entries.len(),
        manifest_before
    );
}

#[test]
fn adding_to_an_existing_file_backs_it_up_and_creating_records_no_backup() {
    let tmp = tempdir().unwrap();
    let existing = tmp.path().join("existing.json");
    let original = br#"{"theme":"dark"}"#;
    std::fs::write(&existing, original).unwrap();
    upsert_mcp_servers_json(&existing, &fake_mcp()).unwrap();
    let created = tmp.path().join("created.json");
    upsert_mcp_servers_json(&created, &fake_mcp()).unwrap();
    let m = setup_backup::load(tmp.path()).unwrap();
    assert_eq!(m.entries.len(), 2);
    assert_eq!(m.entries[0].action, "add");
    assert!(m.entries[0].backup.is_some());
    assert_eq!(
        std::fs::read(m.entries[0].backup.as_ref().unwrap()).unwrap(),
        original
    );
    assert!(m.entries[1].backup.is_none());
    assert!(m.entries[1].sha256_before.is_none());
}

#[test]
fn codex_refuses_a_differing_entry_and_replaces_with_replace() {
    let home = tempdir().unwrap();
    let rel = Path::new(".codex/config.toml");
    let path = home.path().join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = "model = \"x\"\n[mcp_servers.phantom]\ncommand = \"/old\"\nargs = []\n";
    std::fs::write(&path, original).unwrap();
    let error = setup_codex_at(home.path(), rel, &fake_mcp(), false, || {}).unwrap_err();
    assert!(format!("{error:#}").contains("mcp_servers.phantom"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    setup_codex_at(home.path(), rel, &fake_mcp(), true, || {}).unwrap();
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("/usr/local/bin/phantom-mcp"));
    let m = setup_backup::load(home.path()).unwrap();
    assert_eq!(m.entries.len(), 1);
    assert_eq!(
        std::fs::read_to_string(m.entries[0].backup.as_ref().unwrap()).unwrap(),
        original
    );
}

#[cfg(unix)]
#[test]
fn global_json_setup_uses_retained_config_root_after_rename() {
    let home = tempdir().unwrap();
    let cursor = home.path().join(".cursor");
    let moved = home.path().join("cursor-moved");
    std::fs::create_dir(&cursor).unwrap();
    std::fs::write(cursor.join("mcp.json"), br#"{"owner":"original"}"#).unwrap();

    upsert_global_mcp_servers_json(
        home.path(),
        Path::new(".cursor/mcp.json"),
        &fake_mcp(),
        false,
        || {
            std::fs::rename(&cursor, &moved).unwrap();
            std::fs::create_dir(&cursor).unwrap();
            std::fs::write(cursor.join("mcp.json"), br#"{"owner":"decoy"}"#).unwrap();
        },
    )
    .unwrap();

    let actual: Value =
        serde_json::from_slice(&std::fs::read(moved.join("mcp.json")).unwrap()).unwrap();
    assert_eq!(actual["owner"], "original");
    assert_eq!(
        actual["mcpServers"]["phantom"]["command"],
        fake_mcp().command
    );
    assert_eq!(
        std::fs::read(cursor.join("mcp.json")).unwrap(),
        br#"{"owner":"decoy"}"#
    );
}

#[test]
fn global_nested_root_is_created_capability_relatively() {
    let home = tempdir().unwrap();
    upsert_global_mcp_servers_json(
        home.path(),
        Path::new(".codeium/windsurf/mcp_config.json"),
        &fake_mcp(),
        false,
        || {},
    )
    .unwrap();

    assert!(home
        .path()
        .join(".codeium/windsurf/mcp_config.json")
        .is_file());
    assert!(!home.path().join(".phantom-client-setup.lock").exists());
    assert!(home.path().join(".phantom/client-setup.lock").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(home.path().join(".codeium/windsurf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(home.path().join(".codeium/windsurf/mcp_config.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn codex_global_config_preserves_existing_tables() {
    let home = tempdir().unwrap();
    std::fs::create_dir(home.path().join(".codex")).unwrap();
    std::fs::write(
        home.path().join(".codex/config.toml"),
        "[features]\nreview = true\n",
    )
    .unwrap();

    setup_codex_at(
        home.path(),
        Path::new(".codex/config.toml"),
        &fake_mcp(),
        false,
        || {},
    )
    .unwrap();

    let doc: toml::Table =
        toml::from_str(&std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap())
            .unwrap();
    assert_eq!(doc["features"]["review"].as_bool(), Some(true));
    assert_eq!(
        doc["mcp_servers"]["phantom"]["command"].as_str(),
        Some("/usr/local/bin/phantom-mcp")
    );
}

#[test]
fn global_config_refuses_paths_outside_authorized_root() {
    let container = tempdir().unwrap();
    let home = container.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let outside = container.path().join("outside.json");

    for path in [
        "../outside.json",
        "/tmp/outside.json",
        r"C:\outside.json",
        r"\\server\share\outside.json",
    ] {
        assert!(
            upsert_global_mcp_servers_json(&home, Path::new(path), &fake_mcp(), false, || {})
                .is_err()
        );
    }
    assert!(!outside.exists());
}

#[test]
fn unresolved_global_directory_effect_never_claims_exact_rollback() {
    let source = include_str!("../global.rs");
    assert!(source.contains("receipt: None"));
    assert!(source.contains("may have committed without an exact receipt"));
    assert!(source.contains("attempted directory cannot be cleaned up safely"));
}

#[cfg(unix)]
#[test]
fn global_config_refuses_symlinked_parent_component() {
    use std::os::unix::fs::symlink;

    let container = tempdir().unwrap();
    let home = container.path().join("home");
    let outside = container.path().join("outside");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, home.join(".cursor")).unwrap();

    assert!(upsert_global_mcp_servers_json(
        &home,
        Path::new(".cursor/mcp.json"),
        &fake_mcp(),
        false,
        || {},
    )
    .is_err());
    assert!(!outside.join("mcp.json").exists());
}

#[cfg(unix)]
#[test]
fn cursor_writer_rejects_symlink_target() {
    use std::os::unix::fs::symlink;

    let tmp = tempdir().unwrap();
    let owner = tmp.path().join("owner.json");
    let path = tmp.path().join("mcp.json");
    std::fs::write(&owner, br#"{"owner":true}"#).unwrap();
    symlink(&owner, &path).unwrap();

    let error = upsert_mcp_servers_json(&path, &fake_mcp()).unwrap_err();
    assert!(error.to_string().contains("safely read"));
    assert_eq!(std::fs::read(&owner).unwrap(), br#"{"owner":true}"#);
}

#[test]
fn invalid_existing_json_is_preserved_byte_for_byte() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mcp.json");
    let original = b"{ invalid json\n";
    std::fs::write(&path, original).unwrap();

    let error = upsert_mcp_servers_json(&path, &fake_mcp())
        .unwrap_err()
        .to_string();

    assert!(error.contains("Failed to parse"));
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn empty_existing_json_is_invalid_and_preserved() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mcp.json");
    std::fs::write(&path, b"").unwrap();

    assert!(upsert_mcp_servers_json(&path, &fake_mcp()).is_err());
    assert!(std::fs::read(&path).unwrap().is_empty());
}

#[test]
fn codex_global_config_round_trips_bundled_command_with_escaped_path() {
    let home = tempdir().unwrap();
    let mcp = McpCommand::for_test(
        r#"C:\Program Files\Phantom\a "quoted" path\phantom.exe"#,
        &["mcp", "serve"],
    );
    setup_codex_at(
        home.path(),
        Path::new(".codex/config.toml"),
        &mcp,
        false,
        || {},
    )
    .unwrap();
    let doc: toml::Table =
        toml::from_str(&std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap())
            .unwrap();
    let server = &doc["mcp_servers"]["phantom"];
    assert_eq!(server["command"].as_str(), Some(mcp.command.as_str()));
    assert_eq!(
        server["args"].as_array().unwrap(),
        &vec![
            toml::Value::String("mcp".into()),
            toml::Value::String("serve".into())
        ]
    );
}
