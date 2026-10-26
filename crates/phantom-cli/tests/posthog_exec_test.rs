//! Exercise the actual binary's init -> why -> exec path with a disposable
//! encrypted vault. Upstream injection/200 is covered by posthog_capture_test.
#![cfg(unix)]
mod common;
use std::fs;
use std::process::Command;

#[test]
fn posthog_exec_exports_only_session_credentials_and_scrubs_stale_routes() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let fake_key = format!(
        "phc_FAKE_posthog_exec_{}",
        phantom_core::token::PhantomToken::generate().as_str()
    );
    fs::write(
        project.path().join(".env"),
        format!("POSTHOG_API_KEY={fake_key}\n"),
    )
    .unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_phantom"));
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(project.path())
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("NO_COLOR", "1")
            .env(
                "PHANTOM_VAULT_PASSPHRASE",
                "posthog-disposable-test-passphrase",
            )
            .env("POSTHOG_BASE_URL", "https://stale.example.invalid")
            .env("POSTHOG_API_KEY", &fake_key)
            .env_remove("PHANTOM_PROXY_HEADER_AUTH_ONLY");
        command
    };
    let output = command().args(["init", "--from", ".env"]).output().unwrap();
    assert!(output.status.success(), "init failed");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&fake_key));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&fake_key));
    let config_path = project.path().join(".phantom.toml");
    let mut config = phantom_core::config::PhantomConfig::load(&config_path).unwrap();
    assert!(config.services.contains_key("posthog_fleet"));
    config.validate_agentic_proxy_routes().unwrap();
    assert!(!fs::read_to_string(project.path().join(".env"))
        .unwrap()
        .contains(&fake_key));
    let output = command()
        .args(["why", "POSTHOG_API_KEY", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "why failed");
    assert!(String::from_utf8_lossy(&output.stdout).contains("proxied"));
    let output = command().args(["exec", "--", "sh", "-c",
        "case $POSTHOG_API_KEY in phm_*) ;; *) exit 11 ;; esac; case $POSTHOG_BASE_URL in http://127.0.0.1:*/posthog_fleet/_phantom/*/) ;; *) exit 12 ;; esac; test -n \"$PHANTOM_PROXY_TOKEN\" || exit 13; test -z \"${PHANTOM_VAULT_PASSPHRASE-}\" || exit 14; env"
    ]).output().unwrap();
    assert!(
        output.status.success(),
        "exec failed: {:?}",
        output.status.code()
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(&fake_key));
    }
    // No configured route means the inherited base URL must disappear too.
    config.services.remove("posthog_fleet");
    config.save(&config_path).unwrap();
    let output = command()
        .args(["exec", "--", "sh", "-c", "test -z \"${POSTHOG_BASE_URL-}\""])
        .output()
        .unwrap();
    assert!(output.status.success(), "stale override survived");
}
