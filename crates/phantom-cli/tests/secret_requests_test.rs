mod common;

use phantom_core::config::PhantomConfig;
use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

fn project() -> TempDir {
    let dir = common::canonical_tempdir();
    PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(dir.path()))
        .save(&dir.path().join(".phantom.toml"))
        .unwrap();
    dir
}

fn command(dir: &TempDir, args: &[&str]) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("phantom"));
    cmd.current_dir(dir.path())
        .args(args)
        .env("HOME", dir.path())
        .env_remove("PHANTOM_VAULT_PASSPHRASE")
        .env_remove("PHANTOM_REQUIRE_KEYCHAIN")
        .env("PHANTOM_AUDIT", "1");
    cmd
}

fn ok(output: &Output) {
    assert!(output.status.success(), "command failed (output withheld)");
}

fn listing(dir: &TempDir) -> serde_json::Value {
    let output = command(dir, &["requests", "--json"]).output().unwrap();
    ok(&output);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn value_blind_request_is_idempotent_and_fulfilled_by_sanctioned_stdin_flow() {
    let dir = project();
    let args = [
        "request",
        "OPENAI_API_KEY",
        "--purpose",
        "FAKE integration testing",
        "--route",
        "openai",
    ];
    let first = command(&dir, &args).output().unwrap();
    ok(&first);
    let second = command(&dir, &args).output().unwrap();
    ok(&second);
    assert!(first.stdout == second.stdout, "placeholder changed");
    fn no_vault_files(path: &std::path::Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                no_vault_files(&entry.path());
            } else {
                assert!(
                    entry.path().extension().is_none_or(|ext| ext != "vault"),
                    "request created a vault"
                );
            }
        }
    }
    no_vault_files(dir.path());
    let pending = listing(&dir);
    assert_eq!(pending["schema"], "phantom.requests.v1");
    assert_eq!(pending["requests"]["OPENAI_API_KEY"]["status"], "pending");
    let placeholder = pending["requests"]["OPENAI_API_KEY"]["placeholder"]
        .as_str()
        .unwrap();
    assert!(placeholder.starts_with("phm_"));

    // FAKE: construct credential-shaped input only at runtime. This represents
    // a sanctioned producer outside the requesting agent, never an argv value.
    let fake = format!(
        "{}{}{}",
        ['s', 'k', '-'].iter().collect::<String>(),
        "FAKE_",
        rand::random::<u128>()
    );
    let mut child = command(&dir, &["add", "OPENAI_API_KEY", "--stdin"])
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "FAKE request test vault passphrase",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(fake.as_bytes())
        .unwrap();
    let added = child.wait_with_output().unwrap();
    ok(&added);
    let fulfilled = command(&dir, &["requests", "--json"]).output().unwrap();
    ok(&fulfilled);
    for output in [&first, &second, &added, &fulfilled] {
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !bytes
                    .windows(fake.len())
                    .any(|part| part == fake.as_bytes()),
                "FAKE value leaked to command output"
            );
        }
    }
    let status: serde_json::Value = serde_json::from_slice(&fulfilled.stdout).unwrap();
    assert_eq!(status["requests"]["OPENAI_API_KEY"]["status"], "fulfilled");
    assert!(
        status["requests"]["OPENAI_API_KEY"]["placeholder"].as_str() == Some(placeholder),
        "fulfillment changed placeholder"
    );
    let dotenv = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(
        dotenv.contains(placeholder),
        "reserved mapping was not installed"
    );
    for path in [".env", ".phantom.toml", ".phantom/audit.log"] {
        if let Ok(bytes) = fs::read(dir.path().join(path)) {
            assert!(
                !bytes
                    .windows(fake.len())
                    .any(|part| part == fake.as_bytes()),
                "FAKE value leaked to metadata/log"
            );
        }
    }
    // Existing-name denial cannot change the fulfillment receipt or mapping.
    let before = fs::read(dir.path().join(".phantom.toml")).unwrap();
    let denied = command(&dir, &["add", "OPENAI_API_KEY", "--stdin"])
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "FAKE request test vault passphrase",
        )
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(before == fs::read(dir.path().join(".phantom.toml")).unwrap());
}

#[test]
fn requests_reject_invalid_metadata_and_conflicts_without_mutating_config() {
    let dir = project();
    for args in [
        vec!["request", "BAD-NAME", "--purpose", "FAKE test"],
        vec!["request", "KEY", "--purpose", " "],
        vec!["request", "KEY", "--purpose", "FAKE\ntest"],
        vec![
            "request",
            "OPENAI_API_KEY",
            "--purpose",
            "FAKE test",
            "--route",
            "anthropic",
        ],
        vec![
            "request",
            "OPENAI_API_KEY",
            "--purpose",
            "FAKE test",
            "--route",
            "https://example.invalid",
        ],
    ] {
        let before = fs::read(dir.path().join(".phantom.toml")).unwrap();
        assert!(!command(&dir, &args).output().unwrap().status.success());
        assert!(before == fs::read(dir.path().join(".phantom.toml")).unwrap());
    }
    fs::write(dir.path().join(".env"), "EXISTING=phm_FAKE\n").unwrap();
    assert!(
        !command(&dir, &["request", "EXISTING", "--purpose", "FAKE test"])
            .output()
            .unwrap()
            .status
            .success()
    );
    ok(
        &command(&dir, &["request", "NEW_KEY", "--purpose", "FAKE test"])
            .output()
            .unwrap(),
    );
    assert!(
        !command(&dir, &["request", "NEW_KEY", "--purpose", "different"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(listing(&dir)["requests"].as_object().unwrap().len(), 1);
}

#[test]
fn empty_listing_and_global_json_are_supported() {
    let dir = project();
    let output = command(&dir, &["--json", "requests"]).output().unwrap();
    ok(&output);
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema"], "phantom.requests.v1");
    assert!(json["requests"].as_object().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn request_refuses_symlinked_config() {
    let dir = project();
    let config = dir.path().join(".phantom.toml");
    let outside = dir.path().join("outside.toml");
    fs::rename(&config, &outside).unwrap();
    std::os::unix::fs::symlink(&outside, &config).unwrap();
    let before = fs::read(&outside).unwrap();
    assert!(
        !command(&dir, &["request", "KEY", "--purpose", "FAKE test"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(before == fs::read(&outside).unwrap());
}

#[test]
fn malformed_request_metadata_is_rejected_without_echoing_credential_shaped_input() {
    use phantom_core::config::{RequestStatus, SecretRequest};
    let dir = project();
    let path = dir.path().join(".phantom.toml");
    let mut config = PhantomConfig::load(&path).unwrap();
    // FAKE: simulate an invalid, externally edited placeholder at runtime.
    let fake = format!(
        "{}FAKE_{}",
        ['s', 'k', '-'].iter().collect::<String>(),
        rand::random::<u128>()
    );
    config.requests.insert(
        "KEY".to_owned(),
        SecretRequest {
            purpose: "FAKE malformed metadata test".to_owned(),
            route: None,
            placeholder: fake.clone(),
            status: RequestStatus::Pending,
        },
    );
    config.save(&path).unwrap();
    for args in [
        vec!["requests", "--json"],
        vec!["request", "KEY", "--purpose", "FAKE test"],
    ] {
        let output = command(&dir, &args).output().unwrap();
        assert!(!output.status.success());
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !bytes
                    .windows(fake.len())
                    .any(|part| part == fake.as_bytes()),
                "FAKE input leaked in refusal"
            );
        }
    }
}
