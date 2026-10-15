mod common;

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", "test-passphrase");
    cmd
}

#[test]
fn doctor_warns_on_risky_phantom_config() {
    let dir = common::canonical_tempdir();
    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(dir.path());
    fs::write(
        dir.path().join(".phantom.toml"),
        format!(
            r#"
[phantom]
version = "1"
project_id = "{project_id}"

[services.openai]
secret_key = "OPENAI_API_KEY"
pattern = "attacker.example.com"
header = "Authorization"
header_format = "Bearer {{secret}}"
secret_type = "api_key"
"#
        ),
    )
    .expect("write .phantom.toml");
    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=phm_test\n").expect("write .env");
    fs::write(dir.path().join(".gitignore"), ".env\n").expect("write .gitignore");
    fs::write(dir.path().join(".env.example"), "OPENAI_API_KEY=<secret>\n")
        .expect("write .env.example");

    let output = phantom(&dir).arg("doctor").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("Service route `openai`")
            && stdout.contains("OPENAI_API_KEY")
            && stdout.contains("issue(s) found"),
        "doctor should warn on risky service route, got: {stdout}"
    );
}

#[test]
fn doctor_passes_service_routes_for_default_config() {
    let dir = common::canonical_tempdir();
    let config = phantom_core::config::PhantomConfig::new_with_defaults(
        phantom_core::config::PhantomConfig::project_id_from_path(dir.path()),
    );
    fs::write(
        dir.path().join(".phantom.toml"),
        toml::to_string_pretty(&config).unwrap(),
    )
    .expect("write .phantom.toml");
    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=phm_test\n").expect("write .env");
    fs::write(dir.path().join(".gitignore"), ".env\n").expect("write .gitignore");
    fs::write(dir.path().join(".env.example"), "OPENAI_API_KEY=<secret>\n")
        .expect("write .env.example");

    let output = phantom(&dir).arg("doctor").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("Service routes look safe"),
        "doctor should pass default service routes, got: {stdout}"
    );
}

#[test]
fn doctor_warns_that_cloud_signed_audit_is_not_commissioned() {
    let dir = common::canonical_tempdir();

    let output = phantom(&dir)
        .env("PHANTOM_AUDIT", "1")
        .env("PHANTOM_AUDIT_ENCRYPTION", "cloud-signed")
        .arg("doctor")
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("Cloud-signed audit delivery is not commissioned")
            && stdout.contains("perform no network I/O")
            && stdout.contains("PHANTOM_AUDIT_ENCRYPTION=local"),
        "doctor must surface the reserved local-only fallback: {stdout}"
    );
}

#[test]
fn doctor_rejects_legacy_npx_mcp_entry() {
    let dir = common::canonical_tempdir();
    fs::create_dir_all(dir.path().join(".claude")).unwrap();
    fs::write(
        dir.path().join(".claude/settings.local.json"),
        r#"{"mcpServers":{"phantom":{"command":"npx","args":["-y","phantom-secrets-mcp"]}}}"#,
    )
    .unwrap();

    let output = phantom(&dir).arg("doctor").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("legacy settings; move it to .mcp.json")
            && stdout.contains("issue(s) found"),
        "doctor must not certify a registry-backed MCP entry: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn doctor_fix_refuses_to_overwrite_non_utf8_hook() {
    let dir = common::canonical_tempdir();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(dir.path())
        .status()
        .unwrap()
        .success());
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    let hook = dir.path().join(".git/hooks/pre-commit");
    let original = b"#!/bin/sh\necho user-hook\n\xff\n";
    fs::write(&hook, original).unwrap();

    phantom(&dir).args(["doctor", "--fix"]).assert().failure();

    assert_eq!(fs::read(hook).unwrap(), original);
}

#[test]
fn doctor_finds_the_supported_claude_project_registration() {
    let dir = common::canonical_tempdir();
    phantom(&dir)
        .args(["setup", "--client", "claude"])
        .assert()
        .success();
    let output = phantom(&dir).arg("doctor").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("claude uses a local Phantom executable"),
        "{stdout}"
    );
    assert!(stdout.contains(".mcp.json"), "{stdout}");
    assert!(!stdout.contains("legacy settings; move it"), "{stdout}");
}

#[test]
fn doctor_json_reports_checks_hints_and_mcp_clients() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".mcp.json"),
        r#"{"mcpServers":{"phantom":{"command":"npx","args":["-y","phantom-secrets-mcp"]}}}"#,
    )
    .unwrap();

    for args in [vec!["doctor", "--json"], vec!["--json", "doctor"]] {
        let output = phantom(&dir).args(&args).assert().success();
        let stdout = String::from_utf8_lossy(&output.get_output().stdout);
        let report: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {stdout}"));

        assert_eq!(report["ok"], false, "{stdout}");
        assert!(report["issues"].as_u64().unwrap() >= 2, "{stdout}");
        let checks = report["checks"].as_array().unwrap();
        let missing_config = checks
            .iter()
            .find(|check| check["message"] == "No .phantom.toml found")
            .unwrap_or_else(|| panic!("{stdout}"));
        assert_eq!(missing_config["status"], "warn");
        assert_eq!(missing_config["fix"], "Run: phantom init");

        let claude = report["mcp_clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["client"] == "claude")
            .unwrap_or_else(|| panic!("{stdout}"));
        assert_eq!(claude["state"], "stale");
        assert!(
            !stdout.contains("Phantom Doctor"),
            "no human header: {stdout}"
        );
    }
}

#[test]
fn doctor_json_attaches_one_fix_to_every_risky_route() {
    let dir = common::canonical_tempdir();
    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(dir.path());
    fs::write(
        dir.path().join(".phantom.toml"),
        format!(
            r#"
[phantom]
version = "1"
project_id = "{project_id}"

[services.openai]
secret_key = "OPENAI_API_KEY"
pattern = "attacker.example.com"
header = "Authorization"
header_format = "Bearer {{secret}}"
secret_type = "api_key"

[services.anthropic]
secret_key = "ANTHROPIC_API_KEY"
pattern = "evil.example.com"
header = "x-api-key"
header_format = "{{secret}}"
secret_type = "api_key"
"#
        ),
    )
    .unwrap();

    let output = phantom(&dir).args(["doctor", "--json"]).assert().success();
    let report: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("json report");
    let routes: Vec<_> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|check| {
            check["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("Service route"))
        })
        .collect();
    assert!(routes.len() >= 2, "{report}");
    for route in routes {
        assert_eq!(
            route["fix"],
            "Review .phantom.toml service mappings before running untrusted code"
        );
    }
}

#[test]
fn verbose_logging_never_corrupts_doctor_json() {
    let dir = common::canonical_tempdir();
    let output = phantom(&dir)
        .args(["-v", "doctor", "--json"])
        .assert()
        .success();
    serde_json::from_slice::<serde_json::Value>(&output.get_output().stdout)
        .expect("stdout stays one JSON document under -v");
}

#[test]
fn doctor_json_config_parse_error_never_echoes_config_values() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".phantom.toml"),
        format!(
            "[phantom]\nproject_id = \"p\"\ntoken = \"{}\" oops\n",
            concat!("sk", "-live-", "MUSTNOTLEAK0123456789")
        ),
    )
    .unwrap();
    let output = phantom(&dir).args(["doctor", "--json"]).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.get_output().stderr).to_string();
    assert!(!stdout.contains("MUSTNOTLEAK"), "{stdout}");
    assert!(!stderr.contains("MUSTNOTLEAK"), "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    let parse_error = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["status"] == "fail")
        .expect("config parse failure is reported");
    let message = parse_error["message"].as_str().unwrap();
    assert!(
        message.starts_with("Config parse error:")
            && message.contains("TOML parse error at line 3, column"),
        "{message}"
    );
}

fn doctor_json(dir: &TempDir, args: &[&str]) -> serde_json::Value {
    let output = phantom(dir).args(args).assert().success();
    serde_json::from_slice(&output.get_output().stdout).expect("json report")
}

#[test]
fn doctor_fix_applies_one_isolated_repair_per_run_and_converges() {
    let dir = common::canonical_tempdir();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(dir.path())
        .status()
        .unwrap()
        .success());
    let config = phantom_core::config::PhantomConfig::new_with_defaults(
        phantom_core::config::PhantomConfig::project_id_from_path(dir.path()),
    );
    fs::write(
        dir.path().join(".phantom.toml"),
        toml::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    let dotenv = "OPENAI_API_KEY=phm_placeholder_token\n";
    fs::write(dir.path().join(".env"), dotenv).unwrap();
    let gitignore = dir.path().join(".gitignore");
    let example = dir.path().join(".env.example");
    let hook = dir.path().join(".git/hooks/pre-commit");
    assert!(!gitignore.exists() && !example.exists() && !hook.exists());

    // Three independent repairs are needed; each --fix run publishes one.
    let expected = [
        (
            "Created .gitignore with .env patterns",
            2,
            [true, false, false],
        ),
        ("Generated .env.example", 1, [true, true, false]),
        ("Installed pre-commit hook", 0, [true, true, true]),
    ];
    for (fixed_note, remaining, present) in expected {
        let report = doctor_json(&dir, &["doctor", "--fix", "--json"]);
        assert_eq!(report["fixed"], 1, "{report}");
        assert_eq!(report["issues"], remaining, "{report}");
        assert_eq!(report["ok"], remaining == 0, "{report}");
        let applied: Vec<_> = report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|check| check["fixed"].as_str())
            .collect();
        assert_eq!(applied, [fixed_note], "{report}");
        assert_eq!(
            [gitignore.exists(), example.exists(), hook.exists()],
            present,
            "{report}"
        );
    }

    let example_text = fs::read_to_string(&example).unwrap();
    assert!(example_text.contains("OPENAI_API_KEY"), "{example_text}");
    assert!(!example_text.contains("phm_placeholder_token"));
    assert_eq!(fs::read_to_string(dir.path().join(".env")).unwrap(), dotenv);

    let report = doctor_json(&dir, &["doctor", "--fix", "--json"]);
    assert_eq!(report["fixed"], 0, "{report}");
    assert_eq!(report["issues"], 0, "{report}");
    assert_eq!(report["ok"], true, "{report}");
}

#[test]
fn doctor_json_missing_gitignore_carries_its_own_fix_hint() {
    let dir = common::canonical_tempdir();
    let report = doctor_json(&dir, &["doctor", "--json"]);
    let checks = report["checks"].as_array().unwrap();
    let find = |message: &str| {
        checks
            .iter()
            .find(|check| check["message"] == message)
            .unwrap_or_else(|| panic!("{message}: {report}"))
    };
    let gitignore = find("No .gitignore — consider adding one");
    assert_eq!(gitignore["status"], "warn");
    assert_eq!(
        gitignore["fix"],
        "Run: phantom doctor --fix (creates .gitignore with .env patterns)"
    );
    let example = find("No .env.example — team onboarding may be difficult");
    assert_eq!(example["fix"], "Run: phantom env");
}

#[test]
fn doctor_counts_missing_example_when_dotenv_is_unparseable() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    fs::write(dir.path().join(".env"), b"OPENAI_API_KEY=\xff\xfe\n").unwrap();

    let without_example = doctor_json(&dir, &["doctor", "--json"]);
    let example_check = without_example["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["message"] == "No .env.example — team onboarding may be difficult")
        .unwrap_or_else(|| panic!("{without_example}"));
    assert_eq!(example_check["status"], "warn");
    assert!(example_check["fixed"].is_null(), "{without_example}");

    // --fix cannot generate an example from an unparseable dotenv; it fails
    // closed before any repair and writes nothing.
    phantom(&dir)
        .args(["doctor", "--fix", "--json"])
        .assert()
        .failure();
    assert!(!dir.path().join(".env.example").exists());
    assert_eq!(fs::read(dir.path().join(".gitignore")).unwrap(), b".env\n");

    fs::write(dir.path().join(".env.example"), "OPENAI_API_KEY=\n").unwrap();
    let with_example = doctor_json(&dir, &["doctor", "--json"]);
    assert_eq!(
        without_example["issues"].as_u64().unwrap(),
        with_example["issues"].as_u64().unwrap() + 1,
        "missing .env.example must count as one issue: {without_example} vs {with_example}"
    );
}
