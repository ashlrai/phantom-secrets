//! Agent-visible env generation must not disclose vault values or mappings.
mod common;

use assert_cmd::Command;
use std::fs;

#[test]
fn env_after_init_keeps_managed_placeholders_and_masks_the_example() {
    let project = common::canonical_tempdir();
    // Synthetic fixture only; never use a developer's dotenv or vault.
    let fixture = ["sk-", "synthetic-env-scope-fixture"].concat();
    fs::write(
        project.path().join(".env"),
        format!("OPENAI_API_KEY={fixture}\nAPP_MODE=development\n"),
    )
    .unwrap();
    for args in [vec!["init", "--from", ".env"], vec!["env"]] {
        let generating_example = args == ["env"];
        if generating_example {
            // Init creates its own example; env deliberately refuses overwrite.
            fs::remove_file(project.path().join(".env.example")).unwrap();
        }
        let output = Command::cargo_bin("phantom")
            .unwrap()
            .args(args)
            .current_dir(project.path())
            .env("HOME", project.path())
            .env("PHANTOM_VAULT_PASSPHRASE", "synthetic-test-passphrase")
            .output()
            .unwrap();
        assert!(output.status.success(), "command failed (output withheld)");
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            assert!(
                !text.contains(&fixture),
                "fixture escaped to command output"
            );
            if generating_example {
                assert!(!text.contains("phm_"), "mapping escaped to command output");
            }
        }
    }
    let managed = fs::read_to_string(project.path().join(".env")).unwrap();
    let value = managed
        .lines()
        .find_map(|line| line.strip_prefix("OPENAI_API_KEY="))
        .unwrap();
    assert!(
        value.starts_with("phm_"),
        "managed secret must be a placeholder"
    );
    assert!(
        !managed.contains(&fixture),
        "fixture remained in managed dotenv"
    );
    let example = fs::read_to_string(project.path().join(".env.example")).unwrap();
    assert!(!example.contains(&fixture), "fixture escaped to example");
    assert!(
        !example.contains(value),
        "persistent mapping escaped to example"
    );
    assert!(example.contains("OPENAI_API_KEY=your_"));
    assert!(example.contains("APP_MODE=development"));
}
