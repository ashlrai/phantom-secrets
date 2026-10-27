//! Agent-safe get must never turn into a reveal, even with a locked vault.
mod common;
use phantom_core::config::PhantomConfig;
use std::process::Command;

#[test]
fn get_is_metadata_only_with_and_without_global_json() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let config = PhantomConfig::new_with_defaults("get-test".into());
    config.save(&project.path().join(".phantom.toml")).unwrap();
    let mapping = phantom_core::token::PhantomToken::generate();
    std::fs::write(
        project.path().join(".env"),
        format!("OPENAI_API_KEY={}\n", mapping.as_str()),
    )
    .unwrap();
    for args in [
        vec!["get", "OPENAI_API_KEY"],
        vec!["--json", "get", "OPENAI_API_KEY"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
            .args(args)
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env_remove("PHANTOM_VAULT_PASSPHRASE")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["exists"], true);
        assert_eq!(report["delivery_mode"], "proxied");
        assert_eq!(report["vault_inspected"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(mapping.as_str()));
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .args(["reveal", "OPENAI_API_KEY"])
        .current_dir(project.path())
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("attached stdin and stderr terminals"));
}

#[test]
fn get_errors_do_not_echo_parser_input() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let marker = "private-fixture-never-echo";
    for malformed_config in [false, true] {
        if malformed_config {
            std::fs::write(
                project.path().join(".phantom.toml"),
                format!("invalid = {marker}"),
            )
            .unwrap();
        } else {
            let config = PhantomConfig::new_with_defaults("get-test".into());
            config.save(&project.path().join(".phantom.toml")).unwrap();
            std::fs::write(
                project.path().join(".env"),
                format!("KEY={marker}\nKEY=duplicate\n"),
            )
            .unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
            .args(["get", "KEY"])
            .current_dir(project.path())
            .env("HOME", home.path())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
    }
}
