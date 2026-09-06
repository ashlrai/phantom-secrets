//! The Hub status contract observes local configuration without touching the
//! vault, managed dotenv, authentication, or legacy proxy listener.
mod common;

use phantom_core::config::PhantomConfig;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::Command;

fn status(project: &Path, home: &Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .args(args)
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("APPDATA", home.join("appdata"))
        .env("LOCALAPPDATA", home.join("localappdata"))
        .env_remove("PHANTOM_VAULT_PASSPHRASE")
        .output()
        .unwrap();
    assert!(output.status.success(), "status failed: {output:?}");
    assert!(output.stderr.is_empty(), "unexpected stderr: {output:?}");
    serde_json::from_slice(&output.stdout).expect("one complete JSON document")
}

fn configure(project: &Path) {
    let config = PhantomConfig::new_with_defaults("status-fixture-project".into());
    config.save(&project.join(".phantom.toml")).unwrap();
}

#[test]
fn missing_configuration_emits_a_versioned_uninitialized_contract_without_writes() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let report = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(
        report,
        json!({
            "schema_version": 1,
            "initialized": false,
            "inspection": "metadata-only",
            "managed_dotenv": { "inspected": false },
            "vault": { "inspected": false },
            "proxy": { "lifecycle_lock": "not-inspected", "listener_authenticated": false },
            "issues": ["config-missing"]
        })
    );
    assert_eq!(fs::read_dir(project.path()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn configured_status_does_not_read_dotenv_or_create_runtime_storage() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    configure(project.path());
    // A directory cannot be parsed as dotenv: successful status proves that
    // this observer does not depend on opening the managed secret file.
    fs::create_dir(project.path().join(".env")).unwrap();
    let config_before = fs::read(project.path().join(".phantom.toml")).unwrap();
    let report = status(project.path(), home.path(), &["--json", "status"]);
    assert_eq!(report["initialized"], true);
    assert_eq!(report["proxy"]["lifecycle_lock"], "missing");
    assert_eq!(report["proxy"]["listener_authenticated"], false);
    assert_eq!(report["managed_dotenv"]["inspected"], false);
    assert_eq!(report["vault"]["inspected"], false);
    assert_eq!(report["issues"], json!([]));
    assert!(!report.to_string().contains("status-fixture-project"));
    assert!(!report
        .to_string()
        .contains(&project.path().to_string_lossy().to_string()));
    assert_eq!(
        fs::read(project.path().join(".phantom.toml")).unwrap(),
        config_before
    );
    assert_eq!(fs::read_dir(project.path()).unwrap().count(), 2);
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn malformed_configuration_returns_only_a_fixed_issue_code() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let malformed = b"[phantom]\nproject_id = 'parser-canary-secret'\nnot toml\n";
    fs::write(project.path().join(".phantom.toml"), malformed).unwrap();
    let report = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(report["initialized"], false);
    assert_eq!(report["issues"], json!(["config-invalid"]));
    assert_eq!(report["proxy"]["lifecycle_lock"], "not-inspected");
    assert!(!report.to_string().contains("parser-canary-secret"));
    assert_eq!(
        fs::read(project.path().join(".phantom.toml")).unwrap(),
        malformed
    );
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn config_directory_is_unreadable_not_initialized() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::create_dir(project.path().join(".phantom.toml")).unwrap();
    let report = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(report["initialized"], false);
    assert_eq!(report["issues"], json!(["config-unreadable"]));
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn json_takes_precedence_over_oneline() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let report = status(
        project.path(),
        home.path(),
        &["status", "--oneline", "--json"],
    );
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["initialized"], false);
}

#[test]
fn legacy_proxy_bearer_is_neither_read_nor_sent() {
    use std::net::TcpListener;
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    configure(project.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let bearer = "a".repeat(64);
    let legacy = format!(
        "{}:{}:{bearer}",
        std::process::id(),
        listener.local_addr().unwrap().port()
    );
    fs::write(project.path().join(".phantom.pid"), &legacy).unwrap();
    let report = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(report["initialized"], true);
    assert_eq!(report["proxy"]["listener_authenticated"], false);
    assert!(!report.to_string().contains(&bearer));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fs::read_to_string(project.path().join(".phantom.pid")).unwrap(),
        legacy
    );
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn configuration_symlink_cannot_select_another_project() {
    use std::os::unix::fs::symlink;
    let project = common::canonical_tempdir();
    let other = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    configure(other.path());
    symlink(
        other.path().join(".phantom.toml"),
        project.path().join(".phantom.toml"),
    )
    .unwrap();
    let report = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(report["initialized"], false);
    assert_eq!(report["issues"], json!(["config-unreadable"]));
    assert_eq!(report["proxy"]["lifecycle_lock"], "not-inspected");
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(unix)]
fn isolated_lock_path(project: &Path, home: &Path) -> std::path::PathBuf {
    let config = PhantomConfig::load(&project.join(".phantom.toml")).unwrap();
    // Match directories 5's Unix platform mapping using the isolated child
    // environment above, without changing process-global environment in tests.
    #[cfg(target_os = "macos")]
    let data = home.join("Library/Application Support/ai.phantom.phantom-secrets");
    #[cfg(not(target_os = "macos"))]
    let data = home.join("data/phantom-secrets");
    data.join("proxy-locks")
        .join(format!("{}.lock", config.local_project_id()))
}

#[cfg(unix)]
#[test]
fn lifecycle_lock_observation_never_claims_listener_authentication() {
    use fs2::FileExt;
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    configure(project.path());
    let path = isolated_lock_path(project.path(), home.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"lock-fixture-content").unwrap();
    let available = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(available["proxy"]["lifecycle_lock"], "available");
    assert_eq!(available["proxy"]["listener_authenticated"], false);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    lock.try_lock_exclusive().unwrap();
    let held = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(held["proxy"]["lifecycle_lock"], "held");
    assert_eq!(held["proxy"]["listener_authenticated"], false);
    assert_eq!(held["issues"], json!([]));
    assert_eq!(fs::read(&path).unwrap(), b"lock-fixture-content");
}

#[cfg(unix)]
#[test]
fn unsafe_lifecycle_metadata_remains_unknown_and_unmodified() {
    use std::os::unix::fs::symlink;
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    configure(project.path());
    let path = isolated_lock_path(project.path(), home.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let owner = home.path().join("private-owner-file");
    fs::write(&owner, b"private-owner-canary").unwrap();
    symlink(&owner, &path).unwrap();
    let report = status(project.path(), home.path(), &["status", "--json"]);
    assert_eq!(report["initialized"], true);
    assert_eq!(report["proxy"]["lifecycle_lock"], "unknown");
    assert_eq!(report["proxy"]["listener_authenticated"], false);
    assert_eq!(report["issues"], json!(["proxy-lock-unavailable"]));
    assert!(!report.to_string().contains("private-owner"));
    assert_eq!(fs::read(&owner).unwrap(), b"private-owner-canary");
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
}
