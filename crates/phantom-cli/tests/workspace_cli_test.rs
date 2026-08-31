use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn phantom(workspace: &TempDir, home: &TempDir) -> Command {
    let mut command = Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(workspace.path())
        .env("HOME", home.path());
    command
}

#[test]
fn workspace_plan_and_request_records_are_value_free() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let sentinel = "sk-workspace-plan-output-sentinel";
    fs::write(
        workspace.path().join(".env"),
        format!("OPENAI_API_KEY={sentinel}\nPRIVATE_LABEL=internal-value\n"),
    )
    .unwrap();

    let assertion = phantom(&workspace, &home)
        .args(["workspace", "plan", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assertion.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(sentinel));
    assert!(!stdout.contains("internal-value"));
    let plan: Value = serde_json::from_str(&stdout).unwrap();
    let request_id = plan["request_id"].as_str().unwrap();
    assert_eq!(request_id.len(), 64);
    assert_eq!(plan["plan_id"].as_str().unwrap().len(), 64);
    assert_eq!(plan["pre_state_id"].as_str().unwrap().len(), 64);
    assert!(stdout.contains("OPENAI_API_KEY"));

    let request_path = home
        .path()
        .join(".phantom/workspace-requests")
        .join(format!("{request_id}.json"));
    let request_record = fs::read_to_string(request_path).unwrap();
    assert!(!request_record.contains(sentinel));
    assert!(!request_record.contains("internal-value"));

    let status = phantom(&workspace, &home)
        .args(["workspace", "status", "--request", request_id, "--json"])
        .assert()
        .success();
    let status_stdout = String::from_utf8(status.get_output().stdout.clone()).unwrap();
    assert!(!status_stdout.contains(sentinel));
    assert_eq!(
        serde_json::from_str::<Value>(&status_stdout).unwrap()["state"],
        "pending"
    );
}

#[test]
fn workspace_apply_refuses_non_terminal_invocation_before_request_access() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    let assertion = phantom(&workspace, &home)
        .args(["workspace", "apply", "--request", &"0".repeat(64)])
        .assert()
        .failure();
    let stderr = String::from_utf8(assertion.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("requires both stdin and stderr"));
    assert!(!home.path().join(".phantom").exists());
}
