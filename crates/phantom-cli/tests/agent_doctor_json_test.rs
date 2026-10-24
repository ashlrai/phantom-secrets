//! Contract for `phantom agent doctor --json` (docs/agent-preflight-contract.md):
//! a value-free preflight that never touches the vault or the keychain unless
//! `--vault` is passed, exits 0 by default, and maps verdicts to exit codes
//! under `--strict`.

mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const SECRET_NAME: &str = "PREFLIGHT_CANARY_KEY";

fn fake_value() -> String {
    // Obvious fake, derived at runtime.
    format!("sk-test-preflight-{}", std::process::id())
}

fn phantom(dir: &TempDir, passphrase: &str) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", passphrase)
        .env("PHANTOM_AUDIT", "1");
    cmd
}

fn run(dir: &TempDir, passphrase: &str, args: &[&str]) -> (Value, i32, String) {
    let out = phantom(dir, passphrase).args(args).output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let value: Value = serde_json::from_str(&stdout).expect("preflight json");
    (value, out.status.code().unwrap(), stdout)
}

fn initialized(passphrase: &str) -> (TempDir, String) {
    let dir = common::canonical_tempdir();
    let value = fake_value();
    fs::write(dir.path().join(".env"), format!("{SECRET_NAME}={value}\n")).unwrap();
    phantom(&dir, passphrase).arg("init").assert().success();
    (dir, value)
}

fn tree(root: &Path) -> BTreeMap<String, (u64, Option<std::time::SystemTime>)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                out.insert(
                    entry.path().display().to_string(),
                    (meta.len(), meta.modified().ok()),
                );
            }
        }
    }
    out
}

fn ids(value: &Value) -> Vec<String> {
    value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn preflight_schema_v1_keys_and_vocabulary() {
    let (dir, _) = initialized("preflight-pass");
    let (value, code, _) = run(&dir, "preflight-pass", &["agent", "doctor", "--json"]);
    assert_eq!(code, 0);
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    let mut expected = vec![
        "schema_version",
        "kind",
        "verdict",
        "readiness",
        "risk_level",
        "vault_probed",
        "checks",
        "wrap",
    ];
    expected.sort();
    let mut got = keys.clone();
    got.sort();
    assert_eq!(got, expected);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "phantom.agent.preflight");
    assert!(["ready", "degraded", "blocked"].contains(&value["verdict"].as_str().unwrap()));
    assert!([
        "unsafe",
        "protected",
        "verified",
        "team-ready",
        "compliance-ready"
    ]
    .contains(&value["readiness"].as_str().unwrap()));
    assert!(["critical", "high", "medium", "low", "none"]
        .contains(&value["risk_level"].as_str().unwrap()));
    assert_eq!(value["vault_probed"], false);
    for check in value["checks"].as_array().unwrap() {
        let mut k: Vec<&str> = check
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        k.sort();
        assert_eq!(k, vec!["id", "requires_approval", "severity"]);
        let id = check["id"].as_str().unwrap();
        assert!(id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        assert!(["critical", "warning", "info"].contains(&check["severity"].as_str().unwrap()));
        assert!(check["requires_approval"].is_boolean());
    }
    let mut wk: Vec<&str> = value["wrap"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    wk.sort();
    assert_eq!(wk, vec!["blocked_by", "exec_ready"]);
    assert!(ids(&value).contains(&"vault-not-probed".to_string()));
}

#[test]
fn preflight_without_vault_flag_never_opens_vault_or_writes() {
    let (dir, _) = initialized("preflight-pass");
    let before = tree(dir.path());
    // A wrong passphrase would make any vault open fail; without --vault the
    // preflight must not notice, and must not touch HOME or the audit log.
    let (value, code, _) = run(
        &dir,
        "wrong-preflight-pass",
        &["agent", "doctor", "--json", "--strict"],
    );
    assert_eq!(
        tree(dir.path()),
        before,
        "preflight wrote to HOME or the project"
    );
    assert_eq!(value["vault_probed"], false);
    assert!(!ids(&value).contains(&"vault-not-accessible".to_string()));
    assert_ne!(value["verdict"], "blocked");
    assert_ne!(code, 1);

    // Positive control: --vault does open the vault and reports the failure.
    let (probed, code, _) = run(
        &dir,
        "wrong-preflight-pass",
        &["agent", "doctor", "--json", "--vault", "--strict"],
    );
    assert_eq!(probed["vault_probed"], true);
    assert_eq!(probed["verdict"], "blocked");
    assert_eq!(probed["wrap"]["exec_ready"], false);
    assert!(probed["wrap"]["blocked_by"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id == "vault-not-accessible"));
    assert_eq!(code, 1);
}

#[test]
fn preflight_exit_codes_default_zero_and_strict_mapping() {
    // Blocked: uninitialized repo with a plaintext secret.
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("{SECRET_NAME}={}\n", fake_value()),
    )
    .unwrap();
    let (value, code, _) = run(&dir, "preflight-pass", &["agent", "doctor", "--json"]);
    assert_eq!(value["verdict"], "blocked");
    assert_eq!(code, 0, "default exit stays 0");
    let (_, code, _) = run(
        &dir,
        "preflight-pass",
        &["agent", "doctor", "--json", "--strict"],
    );
    assert_eq!(code, 1);

    // Degraded: initialized but no MCP wiring (warning).
    let (dir, _) = initialized("preflight-pass");
    let (value, code, _) = run(
        &dir,
        "preflight-pass",
        &["agent", "doctor", "--json", "--strict"],
    );
    assert_eq!(value["verdict"], "degraded");
    assert_eq!(code, 2);
    // The global --json flag works too.
    let (value, code, _) = run(&dir, "preflight-pass", &["--json", "agent", "doctor"]);
    assert_eq!(value["kind"], "phantom.agent.preflight");
    assert_eq!(code, 0);
}

#[test]
fn preflight_never_leaks_names_values_paths_or_project_id() {
    let (dir, value) = initialized("preflight-pass");
    fs::write(
        dir.path().join(".env.local"),
        format!("OTHER_PREFLIGHT_CANARY={value}\n"),
    )
    .unwrap();
    let config = fs::read_to_string(dir.path().join(".phantom.toml")).unwrap();
    let project_id = config
        .lines()
        .find_map(|l| l.strip_prefix("project_id = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("project_id in config");
    for args in [
        &["agent", "doctor", "--json"][..],
        &["agent", "doctor", "--json", "--vault"][..],
    ] {
        let (_, _, stdout) = run(&dir, "preflight-pass", args);
        for canary in [
            SECRET_NAME,
            "OTHER_PREFLIGHT_CANARY",
            value.as_str(),
            project_id.as_str(),
            dir.path().to_str().unwrap(),
            ".phantom.toml",
            ".env",
            "phm_",
            "phantom ",
        ] {
            assert!(!stdout.contains(canary), "{canary:?} leaked in {args:?}");
        }
    }
}

#[test]
fn vault_and_strict_require_json() {
    let (dir, _) = initialized("preflight-pass");
    phantom(&dir, "preflight-pass")
        .args(["agent", "doctor", "--strict"])
        .assert()
        .failure();
}
