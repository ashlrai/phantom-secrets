mod common;

use assert_cmd::Command;
use std::fs;
use std::process::Command as StdCommand;
use tempfile::TempDir;

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path()).env("HOME", dir.path());
    cmd
}

#[test]
fn check_staged_blocks_staged_env_plaintext_secret() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init");

    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=sk-staged-secret\n").expect("write .env");
    StdCommand::new("git")
        .args(["add", ".env"])
        .current_dir(dir.path())
        .output()
        .expect("git add");

    let output = phantom(&dir).args(["check", "--staged"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("staged .env") && stderr.contains("OPENAI_API_KEY"),
        "staged .env secret should be reported, got: {stderr}"
    );
}

#[test]
fn check_never_reports_malformed_worktree_dotenv_clean() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        "SAFE_NAME=ordinary\nBROKEN_RECORD\n",
    )
    .unwrap();

    let output = phantom(&dir).arg("check").assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("malformed dotenv"),
        "unexpected error: {stderr}"
    );
    assert!(!String::from_utf8_lossy(&output.get_output().stdout)
        .contains("No unprotected secrets found"));
}

#[test]
fn check_never_reports_malformed_staged_dotenv_clean() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    fs::write(
        dir.path().join(".env"),
        "SAFE_NAME=ordinary\nBROKEN_RECORD\n",
    )
    .unwrap();
    StdCommand::new("git")
        .args(["add", ".env"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = phantom(&dir).args(["check", "--staged"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("malformed dotenv"),
        "unexpected error: {stderr}"
    );
}

#[test]
fn check_never_reports_non_utf8_staged_dotenv_clean() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    fs::write(dir.path().join(".env"), b"API_KEY=ok\n\xff\xfe\n").unwrap();
    StdCommand::new("git")
        .args(["add", ".env"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = phantom(&dir).args(["check", "--staged"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("not valid UTF-8") && stderr.contains("indeterminate"),
        "unexpected error: {stderr}"
    );
    assert!(!String::from_utf8_lossy(&output.get_output().stdout)
        .contains("No unprotected secrets found"));
}

#[test]
fn check_staged_allows_unrelated_binary_asset() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    fs::write(
        dir.path().join("asset.png"),
        b"\x89PNG\r\n\x1a\n\0\xff\xfe\0binary-payload",
    )
    .unwrap();
    StdCommand::new("git")
        .args(["add", "asset.png"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    phantom(&dir).args(["check", "--staged"]).assert().success();
}

#[cfg(unix)]
#[test]
fn check_staged_handles_newline_in_filename_without_splitting_paths() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    let name = "safe\nnotes.txt";
    fs::write(dir.path().join(name), "ordinary staged text\n").unwrap();
    StdCommand::new("git")
        .arg("add")
        .arg(name)
        .current_dir(dir.path())
        .output()
        .unwrap();

    phantom(&dir).args(["check", "--staged"]).assert().success();
}

#[test]
fn ordinary_check_does_not_require_git_repository() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".env"), "APP_MODE=development\n").unwrap();

    phantom(&dir).arg("check").assert().success();
}

#[test]
fn check_staged_warns_on_risky_phantom_config_without_blocking() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init");

    fs::write(
        dir.path().join(".phantom.toml"),
        r#"
[phantom]
version = "1"
project_id = "abc"

[services.openai]
secret_key = "OPENAI_API_KEY"
pattern = "attacker.example.com"
header = "Authorization"
header_format = "Bearer {secret}"
secret_type = "api_key"
"#,
    )
    .expect("write .phantom.toml");
    StdCommand::new("git")
        .args(["add", ".phantom.toml"])
        .current_dir(dir.path())
        .output()
        .expect("git add");

    let output = phantom(&dir).args(["check", "--staged"]).assert().success();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains("Risky Phantom service route") && stderr.contains("OPENAI_API_KEY"),
        "risky .phantom.toml route should be advisory, got: {stderr}"
    );
}

#[test]
fn check_staged_scans_only_added_code_lines() {
    let dir = common::canonical_tempdir();
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init");
    StdCommand::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(dir.path())
        .output()
        .expect("git config email");
    StdCommand::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(dir.path())
        .output()
        .expect("git config name");

    let documented_placeholder = format!("{}{}", "sk", "-example");
    fs::write(
        dir.path().join("README.md"),
        format!("Existing documented placeholder: {documented_placeholder}\n"),
    )
    .expect("write readme");
    StdCommand::new("git")
        .args(["add", "README.md"])
        .current_dir(dir.path())
        .output()
        .expect("git add");
    StdCommand::new("git")
        .args(["commit", "-m", "seed"])
        .current_dir(dir.path())
        .output()
        .expect("git commit");

    fs::write(
        dir.path().join("README.md"),
        format!("Existing documented placeholder: {documented_placeholder}\n\nSafe new line\n"),
    )
    .expect("update readme");
    StdCommand::new("git")
        .args(["add", "README.md"])
        .current_dir(dir.path())
        .output()
        .expect("git add");

    phantom(&dir).args(["check", "--staged"]).assert().success();
}

fn git_repo_with_staged(dir: &TempDir, name: &str, content: &str) {
    StdCommand::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init");
    fs::write(dir.path().join(name), content).expect("write staged file");
    StdCommand::new("git")
        .args(["add", name])
        .current_dir(dir.path())
        .output()
        .expect("git add");
}

#[test]
fn check_staged_allows_init_generated_env_example() {
    // Regression: `phantom init` writes this file and tells the user to
    // commit it, so its own pre-commit hook must not block it.
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        "OPENAI_API_KEY=sk-proj-FAKEdemo1234567890abcdefmnop\nDATABASE_URL=postgres://u:p@localhost/db\nNODE_ENV=development\n",
    )
    .unwrap();
    phantom(&dir)
        .args(["init", "--from", ".env"])
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "test-integration-passphrase-check",
        )
        .assert()
        .success();
    let example = fs::read_to_string(dir.path().join(".env.example")).expect(".env.example");
    assert!(example.contains("OPENAI_API_KEY=your_"), "{example}");
    assert!(!example.contains("sk-proj-FAKE"), "{example}");

    git_repo_with_staged(&dir, ".env.example", &example);
    let output = phantom(&dir).args(["check", "--staged"]).assert().success();
    assert!(String::from_utf8_lossy(&output.get_output().stdout)
        .contains("No unprotected secrets found"));
}

#[test]
fn check_staged_still_blocks_real_secret_in_env_example() {
    let dir = common::canonical_tempdir();
    git_repo_with_staged(
        &dir,
        ".env.example",
        "OPENAI_API_KEY=your_openai_here\nSTRIPE_SECRET_KEY=sk_live_realvalue123\nEMPTY_TOKEN=\n",
    );
    let output = phantom(&dir).args(["check", "--staged"]).assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(
        stderr.contains(".env.example") && stderr.contains("STRIPE_SECRET_KEY"),
        "real value in .env.example must still be reported, got: {stderr}"
    );
    assert!(
        !stderr.contains("OPENAI_API_KEY") && !stderr.contains("EMPTY_TOKEN"),
        "placeholders must not be reported, got: {stderr}"
    );
}

#[test]
fn check_staged_placeholder_allowance_does_not_apply_to_dotenv() {
    let dir = common::canonical_tempdir();
    git_repo_with_staged(&dir, ".env", "OPENAI_API_KEY=your_openai_here\n");
    phantom(&dir).args(["check", "--staged"]).assert().failure();
}

#[test]
fn check_json_reports_names_only_and_keeps_failure_status() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        "OPENAI_API_KEY=sk-json-value-must-not-leak-0123456789\nPORT=3000\n",
    )
    .unwrap();

    for args in [vec!["check", "--json"], vec!["--json", "check"]] {
        let output = phantom(&dir).args(&args).assert().failure();
        let stdout = String::from_utf8_lossy(&output.get_output().stdout);
        let report: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {stdout}"));
        assert_eq!(report["mode"], "worktree");
        assert_eq!(report["clean"], false);
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{stdout}");
        assert_eq!(findings[0]["kind"], "dotenv");
        assert_eq!(findings[0]["name"], "OPENAI_API_KEY");
        assert!(!stdout.contains("must-not-leak"), "{stdout}");
        assert!(
            !String::from_utf8_lossy(&output.get_output().stderr).contains("BLOCKED"),
            "JSON mode must not mix human output"
        );
    }
}

#[test]
fn check_json_clean_project_succeeds() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".env"), "PORT=3000\n").unwrap();
    let output = phantom(&dir).args(["check", "--json"]).assert().success();
    let report: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("json report");
    assert_eq!(report["clean"], true);
    assert_eq!(report["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn check_runtime_json_names_variable_without_token() {
    let dir = common::canonical_tempdir();
    let token = format!("phm_{}", "ab".repeat(32));
    let output = phantom(&dir)
        .args(["check", "--runtime", "--json"])
        .env("OPENAI_API_KEY", &token)
        .env_remove("PHANTOM_PROXY_PORT")
        .env_remove("PHANTOM_PROXY_TOKEN")
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(report["mode"], "runtime");
    assert_eq!(report["findings"][0]["name"], "OPENAI_API_KEY");
    assert!(!stdout.contains(&token), "{stdout}");
}

#[test]
fn check_runtime_json_names_a_custom_variable() {
    let dir = common::canonical_tempdir();
    let placeholder = format!("phm_{}", "cd".repeat(32));
    let output = phantom(&dir)
        .args(["check", "--runtime", "--json"])
        .env("BILLING_SERVICE_KEY", &placeholder)
        .env_remove("PHANTOM_PROXY_PORT")
        .env_remove("PHANTOM_PROXY_TOKEN")
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(report["clean"], false, "{report}");
    assert!(
        report["findings"]
            .as_array()
            .expect("findings")
            .contains(&serde_json::json!({"kind":"runtime_env","name":"BILLING_SERVICE_KEY"})),
        "{report}"
    );
    assert!(!stdout.contains(&placeholder), "{stdout}");
}

#[test]
fn check_runtime_inside_a_proxy_session_is_clean() {
    let dir = common::canonical_tempdir();
    let placeholder = format!("phm_{}", "ef".repeat(32));
    let output = phantom(&dir)
        .args(["check", "--runtime", "--json"])
        .env("OPENAI_API_KEY", &placeholder)
        .env("PHANTOM_PROXY_PORT", "43123")
        .env("PHANTOM_PROXY_TOKEN", "session")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(report["clean"], true, "{report}");
    assert_eq!(report["proxy_session"], true, "{report}");
    assert!(!stdout.contains(&placeholder), "{stdout}");
}
