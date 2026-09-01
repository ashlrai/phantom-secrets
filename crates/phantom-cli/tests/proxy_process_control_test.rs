mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const VAULT_PASS: &str = "proxy-process-control-integration-passphrase";
const PROBE_PATH_ENV: &str = "PHANTOM_TEST_CHILD_ENV_PROBE";
const EXPECT_PROTECTED_ENV: &str = "PHANTOM_TEST_EXPECT_PROTECTED_TOKEN";

fn phantom_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_phantom"))
}

fn phantom_command(project: &Path, home: &Path) -> Command {
    let mut command = Command::new(phantom_binary());
    command
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS);
    command
}

fn assert_success(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn initialize(project: &Path, home: &Path) {
    fs::write(
        project.join(".env"),
        "OPENAI_API_KEY=sk-proxy-process-control-test-value\n",
    )
    .unwrap();
    let output = phantom_command(project, home)
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert_success(&output, "phantom init");
}

fn append_sync_config(project: &Path) {
    let path = project.join(".phantom.toml");
    let config = fs::read_to_string(&path).unwrap();
    assert!(config.contains("sync = []"));
    fs::write(
        path,
        config.replace(
            "sync = []",
            "[[sync]]\nplatform = \"vercel\"\ntoken_env = \"DEPLOY_TOKEN\"\nproject_id = \"project\"",
        ),
    )
    .unwrap();
}

#[test]
fn detached_start_and_headless_legacy_stop_fail_closed_without_touching_state() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    initialize(project.path(), home.path());

    let daemon = phantom_command(project.path(), home.path())
        .args(["start", "--daemon"])
        .output()
        .unwrap();
    assert!(!daemon.status.success());
    assert!(String::from_utf8_lossy(&daemon.stderr).contains("Detached proxy mode is disabled"));
    assert!(!project.path().join(".phantom.pid").exists());

    let legacy_pid = project.path().join(".phantom.pid");
    fs::write(&legacy_pid, b"legacy-state-must-not-be-unlinked").unwrap();
    let stop = phantom_command(project.path(), home.path())
        .arg("stop")
        .output()
        .unwrap();
    assert!(!stop.status.success());
    assert!(String::from_utf8_lossy(&stop.stderr).contains("trusted-terminal diagnostic"));
    assert_eq!(
        fs::read(&legacy_pid).unwrap(),
        b"legacy-state-must-not-be-unlinked"
    );
}

#[test]
fn foreground_start_denies_headless_invocation_before_sensitive_work() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    initialize(project.path(), home.path());

    let start = phantom_command(project.path(), home.path())
        .arg("start")
        .output()
        .unwrap();
    assert!(!start.status.success());
    let stderr = String::from_utf8_lossy(&start.stderr);
    assert!(stderr.contains("stdin, stdout, and stderr"));
    assert!(stderr.contains("denied before vault access or bearer generation"));
    assert!(!stderr.contains("decrypt"));
    assert!(
        !project.path().join(".phantom.pid").exists(),
        "foreground lifecycle must never persist a PID or bearer"
    );
}

#[test]
fn exec_child_does_not_receive_vault_passphrase_or_ambient_protected_value() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    initialize(project.path(), home.path());
    append_sync_config(project.path());
    use std::io::Write;
    let mut config = fs::OpenOptions::new()
        .append(true)
        .open(project.path().join(".phantom.toml"))
        .unwrap();
    writeln!(
        config,
        "\n[phantom.secrets.OPENAI_API_KEY.rotation_provider]\nprovider = \"stripe\"\napi_key_env = \"ROTATION_ADMIN_TOKEN\""
    )
    .unwrap();
    let probe = project.path().join("probe-complete");

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe", "--nocapture"])
        .env("OPENAI_API_KEY", "ambient-real-value-must-not-reach-child")
        .env("PHANTOM_PROXY_TOKEN", "stale-bearer")
        .env("PHANTOM_PROXY_PORT", "65535")
        .env("ANTHROPIC_BASE_URL", "http://attacker.invalid")
        .env("DEPLOY_TOKEN", "ambient-deploy-token")
        .env("ROTATION_ADMIN_TOKEN", "ambient-rotation-token")
        .env(PROBE_PATH_ENV, &probe)
        .env(EXPECT_PROTECTED_ENV, "1")
        .output()
        .unwrap();
    assert_success(&output, "phantom exec protected child probe");
    assert!(probe.exists(), "child probe did not run");
}

#[test]
fn direct_child_does_not_receive_vault_passphrase() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--empty"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init --empty");
    append_sync_config(project.path());
    let probe = project.path().join("direct-probe-complete");

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe", "--nocapture"])
        .env(PROBE_PATH_ENV, &probe)
        .env("OPENAI_API_KEY", "ambient-unconfigured-real-value")
        .env("PHANTOM_PROXY_TOKEN", "stale-bearer")
        .env("PHANTOM_PROXY_PORT", "65535")
        .env("OPENAI_BASE_URL", "http://attacker.invalid")
        .env("DEPLOY_TOKEN", "ambient-deploy-token")
        .output()
        .unwrap();
    assert_success(&output, "phantom exec direct child probe");
    assert!(probe.exists(), "direct child probe did not run");
}

#[test]
fn status_is_truthful_read_only_and_surfaces_unsafe_legacy_state() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--empty"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init --empty");
    let legacy = project.path().join(".phantom.pid");
    fs::write(&legacy, b"malformed-do-not-delete").unwrap();

    let oneline = phantom_command(project.path(), home.path())
        .args(["status", "--oneline"])
        .output()
        .unwrap();
    assert_success(&oneline, "phantom status --oneline");
    assert!(String::from_utf8_lossy(&oneline.stdout).contains("unsafe legacy v0.7.3 state"));
    assert!(String::from_utf8_lossy(&oneline.stdout).contains("no lifecycle lock held"));
    assert_eq!(fs::read(&legacy).unwrap(), b"malformed-do-not-delete");

    let verbose = phantom_command(project.path(), home.path())
        .arg("status")
        .output()
        .unwrap();
    assert_success(&verbose, "phantom status");
    let stdout = String::from_utf8_lossy(&verbose.stdout);
    assert!(
        stdout.contains("lifecycle lock"),
        "unexpected status output: {stdout}"
    );
    assert!(!stdout.contains("foreground session active"));
    assert!(stdout.contains("protocol-aware broker required"));
    assert!(!stdout.contains("env var injection"));
    assert_eq!(fs::read(&legacy).unwrap(), b"malformed-do-not-delete");
}

#[test]
fn status_does_not_provision_machine_local_vault_or_lock_state() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let config = phantom_core::config::PhantomConfig::new_with_defaults("portable".to_string());
    fs::write(
        project.path().join(".phantom.toml"),
        toml::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);

    let status = phantom_command(project.path(), home.path())
        .args(["status", "--oneline"])
        .output()
        .unwrap();
    assert_success(&status, "read-only phantom status");
    assert!(String::from_utf8_lossy(&status.stdout).contains("0 managed placeholders"));
    assert_eq!(
        fs::read_dir(home.path()).unwrap().count(),
        0,
        "status created machine-local state"
    );
    let project_files: Vec<_> = fs::read_dir(project.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        project_files,
        vec![std::ffi::OsString::from(".phantom.toml")]
    );
}

#[test]
fn init_env_local_is_used_by_exec() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join(".env.local"),
        "OPENAI_API_KEY=sk-env-local-test-value\n",
    )
    .unwrap();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--from", ".env.local"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init .env.local");
    let config = fs::read_to_string(project.path().join(".phantom.toml")).unwrap();
    assert!(config.contains("dotenv_path = \".env.local\""));
    let probe = project.path().join("env-local-probe");
    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe", "--nocapture"])
        .env(PROBE_PATH_ENV, &probe)
        .env(EXPECT_PROTECTED_ENV, "1")
        .output()
        .unwrap();
    assert_success(&output, "phantom exec .env.local");
    assert!(probe.exists());
}

#[test]
fn init_custom_dotenv_basename_is_used_by_exec() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join("custom.env"),
        "OPENAI_API_KEY=sk-custom-env-test-value\n",
    )
    .unwrap();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--from", "custom.env"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init custom.env");
    let config = fs::read_to_string(project.path().join(".phantom.toml")).unwrap();
    assert!(config.contains("dotenv_path = \"custom.env\""));
    let mut add = phantom_command(project.path(), home.path())
        .args(["add", "SECOND_API_KEY", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    add.stdin
        .take()
        .unwrap()
        .write_all(b"second-secret-value\n")
        .unwrap();
    let add = add.wait_with_output().unwrap();
    assert_success(&add, "phantom add custom.env");
    let managed = fs::read_to_string(project.path().join("custom.env")).unwrap();
    assert!(managed.contains("SECOND_API_KEY=phm_"));
    assert!(!project.path().join(".env").exists());
    let probe = project.path().join("custom-env-probe");
    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe", "--nocapture"])
        .env(PROBE_PATH_ENV, &probe)
        .env(EXPECT_PROTECTED_ENV, "1")
        .output()
        .unwrap();
    assert_success(&output, "phantom exec custom.env");
    assert!(probe.exists());
}

#[test]
fn protected_connection_string_is_denied_before_vault_decryption() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join(".env"),
        "DATABASE_URL=postgresql://example.invalid/app\n",
    )
    .unwrap();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init connection string");

    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe"])
        // If exec tried to open the file vault before applying the configured
        // connection-string denial, this deliberately wrong key would produce
        // a decryption error instead of the required policy error.
        .env("PHANTOM_VAULT_PASSPHRASE", "deliberately-wrong-passphrase")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Refusing to expose connection-string secret(s)"));
    assert!(!stderr.contains("decrypt"));
}

#[test]
fn ambient_connection_string_is_denied_in_direct_mode() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let init = phantom_command(project.path(), home.path())
        .args(["init", "--empty"])
        .output()
        .unwrap();
    assert_success(&init, "phantom init --empty");
    let marker = project.path().join("must-not-run");
    let output = phantom_command(project.path(), home.path())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "child_environment_probe"])
        .env("DATABASE_URL", "postgresql://ambient.invalid/db")
        .env(PROBE_PATH_ENV, &marker)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Refusing to expose connection-string secret(s)"));
    assert!(!marker.exists());
}

#[test]
fn child_environment_probe() {
    let Ok(path) = std::env::var(PROBE_PATH_ENV) else {
        return;
    };
    assert!(
        std::env::var_os("PHANTOM_VAULT_PASSPHRASE").is_none(),
        "vault passphrase reached delegated child"
    );
    if std::env::var_os(EXPECT_PROTECTED_ENV).is_some() {
        let value = std::env::var("OPENAI_API_KEY").expect("protected key session token");
        assert!(value.starts_with("phm_"), "protected key was not tokenized");
        assert_ne!(value, "ambient-real-value-must-not-reach-child");
        let bearer = std::env::var("PHANTOM_PROXY_TOKEN").expect("fresh proxy bearer");
        assert_eq!(bearer.len(), 64);
        assert_ne!(bearer, "stale-bearer");
        let port = std::env::var("PHANTOM_PROXY_PORT").expect("fresh proxy port");
        assert_ne!(port, "65535");
        for name in ["OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"] {
            let value = std::env::var(name).expect("fresh proxy override");
            assert!(value.starts_with("http://127.0.0.1:"));
            assert_ne!(value, "http://attacker.invalid");
        }
    } else {
        for name in [
            "PHANTOM_PROXY_TOKEN",
            "PHANTOM_PROXY_PORT",
            "OPENAI_BASE_URL",
            "ANTHROPIC_BASE_URL",
        ] {
            assert!(
                std::env::var_os(name).is_none(),
                "{name} reached direct delegated child"
            );
        }
    }
    for name in ["DEPLOY_TOKEN", "ROTATION_ADMIN_TOKEN"] {
        assert!(
            std::env::var_os(name).is_none(),
            "{name} reached delegated child"
        );
    }
    fs::write(path, b"ok").unwrap();
}
