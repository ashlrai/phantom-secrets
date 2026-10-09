//! Actual CLI observers and refusal paths, with isolated homes and no keychain.
mod common;

#[cfg(unix)]
use phantom_core::config::PhantomConfig;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::SystemTime;

fn onboard(project: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_phantom"))
        .env_clear()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env("PHANTOM_VAULT_PASSPHRASE", "synthetic-onboard-test-only")
        .env("PATH", "")
        .env("NO_COLOR", "1")
        .current_dir(project)
        .args(args)
        .output()
        .unwrap()
}

#[derive(Debug, PartialEq)]
struct Entry {
    bytes: Option<Vec<u8>>,
    len: u64,
    modified: SystemTime,
    readonly: bool,
    #[cfg(unix)]
    mode: u32,
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn walk(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        let meta = fs::symlink_metadata(path).unwrap();
        let bytes = if meta.is_file() {
            Some(fs::read(path).unwrap())
        } else {
            None
        };
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        entries.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            Entry {
                bytes,
                len: meta.len(),
                modified: meta.modified().unwrap(),
                readonly: meta.permissions().readonly(),
                #[cfg(unix)]
                mode: meta.permissions().mode(),
            },
        );
        if meta.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    walk(root, root, &mut entries);
    entries
}

#[cfg(unix)]
fn configure(project: &Path) -> String {
    let id = PhantomConfig::project_id_from_path(project);
    PhantomConfig::new_with_defaults(id.clone())
        .save(&project.join(".phantom.toml"))
        .unwrap();
    id
}

#[cfg(unix)]
fn legacy_storage(home: &Path, project_id: &str) {
    // Platform-specific data directories are all inside this synthetic home.
    // A constructor regression is allowed to operate only on fake test values.
    for base in [
        home.join("data/phantom-secrets"),
        home.join("Library/Application Support/ai.phantom.phantom-secrets"),
        home.join("localappdata/phantom/phantom-secrets/data"),
    ] {
        fs::create_dir_all(base.join("vaults")).unwrap();
        fs::write(
            base.join("vaults").join(format!("{project_id}.json")),
            br#"{"secrets":{"SYNTHETIC_KEY":"never-a-real-credential"}}"#,
        )
        .unwrap();
        fs::create_dir_all(base.join("metadata")).unwrap();
        fs::write(
            base.join("metadata")
                .join(format!("{project_id}.meta.json")),
            br#"{"SYNTHETIC_KEY":{"synthetic":"legacy-sidecar"}}"#,
        )
        .unwrap();
        fs::write(
            base.join("metadata")
                .join(format!("{project_id}.validation.json")),
            b"{}",
        )
        .unwrap();
    }
}

fn receipt(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "one JSON receipt required: {error}; stdout={:?}; stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

// Windows ProjectDirs uses OS KnownFolders rather than environment overrides;
// do not let a constructor regression touch the host's real vault directory.
#[cfg(unix)]
#[test]
fn plan_preserves_legacy_vault_and_sidecars_bytes_and_metadata() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let id = configure(project.path());
    legacy_storage(home.path(), &id);
    fs::write(project.path().join(".env"), b"SYNTHETIC_KEY=phm_fixture\n").unwrap();
    let before_home = snapshot(home.path());
    let before_project = snapshot(project.path());
    for args in [
        &["--json", "onboard", "--plan"] as &[&str],
        &["onboard", "--plan"],
    ] {
        let output = onboard(project.path(), home.path(), args);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(snapshot(home.path()), before_home);
        assert_eq!(snapshot(project.path()), before_project);
        if args[0] == "--json" {
            let report = receipt(&output);
            assert_eq!(report["outcome"], "planned");
            assert_eq!(report["done"], false);
            assert!(report["phases"][0]["detail"]
                .as_str()
                .unwrap()
                .contains("vault not inspected"));
            assert!(!report.to_string().contains("never-a-real-credential"));
        }
    }
}

#[test]
fn fresh_plan_does_not_create_backend_or_configuration_directories() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let output = onboard(
        project.path(),
        home.path(),
        &["--json", "onboard", "--plan", "--yes"],
    );
    assert!(output.status.success());
    let report = receipt(&output);
    assert_eq!(report["phases"].as_array().unwrap().len(), 4);
    assert_eq!(report["outcome"], "planned");
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(project.path()).unwrap().count(), 0);
}

#[test]
fn headless_protection_refusal_still_emits_one_complete_json_receipt() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join(".env"),
        b"SYNTHETIC_KEY=never-a-real-credential\n",
    )
    .unwrap();
    let before = snapshot(project.path());
    let output = onboard(project.path(), home.path(), &["--json", "onboard", "--yes"]);
    assert!(!output.status.success());
    let report = receipt(&output);
    assert_eq!(report["outcome"], "failed");
    assert_eq!(report["done"], false);
    assert_eq!(report["phases"][1]["status"], "failed");
    assert_eq!(report["phases"][2]["status"], "skipped");
    assert!(report["phases"][1]["detail"]
        .as_str()
        .unwrap()
        .contains("trusted terminal"));
    assert_eq!(snapshot(project.path()), before);
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn skip_connect_cannot_trigger_unapproved_diagnostic_vault_migration() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let id = configure(project.path());
    legacy_storage(home.path(), &id);
    let before_home = snapshot(home.path());
    let before_project = snapshot(project.path());
    let output = onboard(
        project.path(),
        home.path(),
        &["--json", "onboard", "--skip-connect", "--yes"],
    );
    assert!(!output.status.success());
    let report = receipt(&output);
    assert_eq!(report["phases"][3]["status"], "failed");
    assert_eq!(report["done"], false);
    assert_eq!(snapshot(home.path()), before_home);
    assert_eq!(snapshot(project.path()), before_project);
}

#[test]
fn profile_detection_parses_managed_entries_instead_of_searching_prose() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join(".mcp.json"),
        br#"{"notes":"phantom", "mcpServers":{"phantom":{"command":"npx","args":["phantom"]}}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.path().join(".cursor")).unwrap();
    fs::write(
        home.path().join(".cursor/mcp.json"),
        br#"{"mcpServers":{"phantom":{"command":"phantom","args":["mcp"]}}}"#,
    )
    .unwrap();
    fs::create_dir_all(home.path().join(".codex")).unwrap();
    fs::write(
        home.path().join(".codex/config.toml"),
        "[mcp_servers.phantom]\ncommand = 'phantom-mcp'\n",
    )
    .unwrap();
    let output = onboard(
        project.path(),
        home.path(),
        &["--json", "onboard", "--plan"],
    );
    assert!(output.status.success());
    let report = receipt(&output);
    let detail = report["phases"][0]["detail"].as_str().unwrap();
    assert!(detail.contains("claude:false"));
    assert!(detail.contains("cursor:true"));
    assert!(detail.contains("codex:true"));
}

#[cfg(unix)]
#[test]
fn profile_symlink_is_not_followed_during_plan() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let target = home.path().join("private-fixture");
    fs::write(
        &target,
        br#"{"mcpServers":{"phantom":{"command":"phantom-mcp"}}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, project.path().join(".mcp.json")).unwrap();
    let before = snapshot(home.path());
    let output = onboard(
        project.path(),
        home.path(),
        &["--json", "onboard", "--plan"],
    );
    assert!(output.status.success());
    assert_eq!(snapshot(home.path()), before);
    assert!(receipt(&output)["phases"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("claude:false"));
}
