//! Shipped binary/argument parsing and init -> why -> exec smoke. The private
//! exec unit fixture separately proves the complete lifecycle against loopback;
//! the production binary intentionally cannot redirect a built-in upstream.
#![cfg(unix)]
mod common;
use std::fs;
use std::process::Command;

#[test]
fn github_binary_exec_uses_session_credentials_and_removes_stale_overrides() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let fake = "github-disposable-binary-fixture-not-a-provider-credential";
    fs::write(
        project.path().join(".env"),
        format!("GITHUB_TOKEN={fake}\n"),
    )
    .unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_phantom"));
        command
            .env_clear()
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("XDG_DATA_HOME", home.path().join("data"))
            .env("NO_COLOR", "1")
            .env(
                "PHANTOM_VAULT_PASSPHRASE",
                "github-binary-disposable-passphrase",
            )
            .env("PHANTOM_PROXY_HEADER_AUTH_ONLY", "1")
            .env("GITHUB_TOKEN", fake)
            .env("GITHUB_TOKEN_BASE_URL", "https://stale.example.invalid");
        command
    };
    let check = |output: std::process::Output| {
        for bytes in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(bytes).contains(fake));
        }
        assert!(output.status.success(), "GitHub binary fixture failed");
        output
    };
    check(command().args(["init", "--from", ".env"]).output().unwrap());
    let config_path = project.path().join(".phantom.toml");
    let mut config = phantom_core::config::PhantomConfig::load(&config_path).unwrap();
    assert!(config.services.contains_key("github_api"));
    config.validate_agentic_proxy_routes().unwrap();
    let output = check(
        command()
            .args(["why", "GITHUB_TOKEN", "--json"])
            .output()
            .unwrap(),
    );
    let why: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(why["exec"]["delivery"], "proxied");
    let persistent = fs::read_to_string(project.path().join(".env")).unwrap();
    assert!(!persistent.contains(fake));
    // Check only names and shapes; never dump the child's environment.
    check(command().args(["exec", "--", "/bin/sh", "-c",
        "case $GITHUB_TOKEN in phm_*) ;; *) exit 11 ;; esac; case $GITHUB_TOKEN_BASE_URL in http://127.0.0.1:*/github_api) ;; *) exit 12 ;; esac; test -n \"$PHANTOM_PROXY_TOKEN\" || exit 13; test -z \"${PHANTOM_VAULT_PASSPHRASE-}\" || exit 14"
    ]).output().unwrap());
    assert!(fs::read_to_string(project.path().join(".env")).unwrap() == persistent);
    config.services.remove("github_api");
    config.save(&config_path).unwrap();
    check(
        command()
            .args([
                "exec",
                "--",
                "/bin/sh",
                "-c",
                "test -z \"${GITHUB_TOKEN_BASE_URL-}\"",
            ])
            .output()
            .unwrap(),
    );
}
