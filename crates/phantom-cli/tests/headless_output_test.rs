/// Integration tests for headless (no TTY, piped) CLI behavior.
///
/// Agents and CI shells read Phantom's stderr and exit code, and parse stdout
/// in `--json` modes. These tests pin that a failure is reported once, that
/// exit codes match the outcome, and that `--json` output stays JSON on the
/// empty paths too.
mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "placeholder-headless-output-passphrase";

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_AUDIT")
        .env_remove("RUST_BACKTRACE")
        .env_remove("RUST_LIB_BACKTRACE");
    cmd
}

fn init_project(dir: &TempDir) {
    fs::write(
        dir.path().join(".env"),
        "OPENAI_API_KEY=placeholder-value-for-tests\nNODE_ENV=development\n",
    )
    .expect("write seed .env");
    phantom(dir)
        .args(["init", "--from", ".env"])
        .assert()
        .success();
}

#[test]
fn sync_without_targets_reports_the_failure_once() {
    let dir = common::canonical_tempdir();
    init_project(&dir);

    let output = phantom(&dir).arg("sync").assert().failure();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr);

    assert_eq!(
        stderr.matches("No sync targets configured").count(),
        1,
        "the failure should be stated once, got:\n{stderr}"
    );
    assert!(stderr.starts_with("Error: No sync targets configured."));
    assert!(stderr.contains("[[sync]]"), "guidance missing:\n{stderr}");
    assert!(stderr.contains("phantom sync --platform vercel"));
}

#[test]
fn sync_dry_run_json_without_targets_emits_a_report() {
    let dir = common::canonical_tempdir();
    init_project(&dir);

    let output = phantom(&dir)
        .args(["sync", "--dry-run", "--json"])
        .assert()
        .failure();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON: {e}\n{stdout}"));
    assert_eq!(report["mode"], "dry-run");
    assert_eq!(report["target_count"], 0);
    assert_eq!(report["exit_code"], 1);
    assert_eq!(report["would_call_platform_api"], false);
}

#[test]
fn audit_json_modes_stay_parseable_without_a_log() {
    let dir = common::canonical_tempdir();

    // `audit show --json` is JSON Lines: no events means empty stdout.
    let output = phantom(&dir)
        .args(["audit", "show", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.trim().is_empty(), "expected no JSONL rows: {stdout}");

    let output = phantom(&dir)
        .args(["audit", "stats", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let stats: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stats stdout is not JSON: {e}\n{stdout}"));
    assert_eq!(stats["total_events"], 0);
    assert_eq!(stats["secrets"], serde_json::json!([]));

    let output = phantom(&dir)
        .args(["audit", "stats", "--json", "--analytics"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let analytics: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("analytics stdout is not JSON: {e}\n{stdout}"));
    assert_eq!(analytics["secrets"], serde_json::json!([]));
}

#[test]
fn audit_incidents_json_keeps_its_object_shape_when_empty() {
    let dir = common::canonical_tempdir();

    let output = phantom(&dir)
        .args(["audit", "incidents", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("incidents stdout is not JSON: {e}\n{stdout}"));
    assert_eq!(report["incidents"], serde_json::json!([]));
    assert_eq!(
        report["provider_credentials_rotated"],
        serde_json::json!([])
    );
}

#[test]
fn unknown_platform_flag_is_not_reported_as_a_config_parse_error() {
    let dir = common::canonical_tempdir();
    init_project(&dir);

    for (args, flag) in [
        (
            vec!["sync", "--platform", "nope", "--project", "x"],
            "--platform",
        ),
        (vec!["pull", "--from", "nope", "--project", "x"], "--from"),
    ] {
        let output = phantom(&dir).args(&args).assert().failure();
        let stderr = String::from_utf8_lossy(&output.get_output().stderr);
        assert!(
            stderr.contains(&format!(
                "Unknown {flag} 'nope'. Supported: vercel, railway"
            )),
            "{args:?}: {stderr}"
        );
        assert!(
            !stderr.contains("Failed to parse config"),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn json_on_a_command_without_json_output_is_a_usage_error() {
    let dir = common::canonical_tempdir();
    init_project(&dir);

    for args in [
        // `why` and `audit verify` gained JSON output on main; these did not.
        vec!["audit", "path", "--json"],
        vec!["--json", "audit", "path"],
        vec!["logout", "--json"],
    ] {
        let output = phantom(&dir).args(&args).assert().code(2);
        let out = output.get_output();
        assert!(out.stdout.is_empty(), "{args:?}: no human text on stdout");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(stderr.matches("Error:").count(), 1, "{args:?}: {stderr}");
        assert!(
            stderr.contains("has no --json output"),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn json_before_the_subcommand_reaches_its_own_json_flag() {
    let dir = common::canonical_tempdir();
    init_project(&dir);

    let output = phantom(&dir).args(["--json", "list"]).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    let names: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("`phantom --json list` is not JSON: {e}\n{stdout}"));
    assert_eq!(names[0]["name"], "OPENAI_API_KEY");
}

#[test]
fn quiet_wrap_and_unwrap_print_only_warnings() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join("package.json"),
        "{\"name\":\"demo\",\"scripts\":{\"dev\":\"node index.js\"}}\n",
    )
    .expect("write package.json");

    let output = phantom(&dir).args(["-q", "wrap"]).assert().success();
    assert!(output.get_output().stdout.is_empty(), "wrap -q printed");
    let pkg = fs::read_to_string(dir.path().join("package.json")).unwrap();
    assert!(pkg.contains("phantom exec -- node index.js"), "{pkg}");

    // Nothing left to wrap: the warning still prints under --quiet.
    let output = phantom(&dir).args(["wrap", "--quiet"]).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("No scripts to wrap"), "{stdout}");

    let output = phantom(&dir).args(["-q", "unwrap"]).assert().success();
    assert!(output.get_output().stdout.is_empty(), "unwrap -q printed");
    let pkg = fs::read_to_string(dir.path().join("package.json")).unwrap();
    assert!(!pkg.contains("phantom exec"), "{pkg}");
}

/// `cloud status --json` and `team list --json` have JSON output, so headless
/// they fail at the same trusted-terminal gate as their text form (exit 1),
/// not with the exit-2 "no --json output" usage error. Nothing is printed on
/// stdout and no credential or network access happens.
#[test]
fn cloud_and_team_json_keep_the_trusted_terminal_gate() {
    let dir = common::canonical_tempdir();

    for args in [
        vec!["cloud", "status", "--json"],
        vec!["--json", "team", "list"],
    ] {
        let output = phantom(&dir).args(&args).assert().code(1);
        let out = output.get_output();
        assert!(out.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("trusted terminal"), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("has no --json output"),
            "{args:?}: {stderr}"
        );
    }
}
