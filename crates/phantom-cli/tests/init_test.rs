/// Integration tests for `phantom init`.
///
/// These tests run against the real binary compiled from the workspace. Each
/// test creates an isolated TempDir so that:
///   - The `.phantom.toml` project_id is unique per test (derived from the
///     canonicalised directory path), preventing keychain collisions.
///   - Files written by `init` (`.env`, `.env.backup`, `.phantom.toml`,
///     `.env.example`) are cleaned up automatically when the TempDir drops.
///
/// PHANTOM_VAULT_PASSPHRASE is set so that if the OS keychain is unavailable
/// (CI, sandboxed environments) the encrypted-file vault backend is used with
/// a deterministic passphrase instead of panicking.
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

/// Passphrase that forces the encrypted-file vault when the keychain is down.
const VAULT_PASS: &str = "test-integration-passphrase-init";

/// Write a sample `.env` and run `phantom init --from .env` in that directory.
fn run_init(dir: &TempDir) -> assert_cmd::assert::Assert {
    let env_path = dir.path().join(".env");
    fs::write(
        &env_path,
        "OPENAI_API_KEY=sk-real-test\nSTRIPE_SECRET=sk_live-real-test\nNODE_ENV=development\n",
    )
    .expect("write .env");

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .arg("init")
        .arg("--from")
        .arg(".env")
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        // Prevent init from walking up and finding the real repo's .git / CLAUDE.md
        .env("HOME", dir.path())
        .assert()
}

#[test]
fn init_creates_phantom_toml() {
    let dir = TempDir::new().unwrap();
    run_init(&dir).success();
    assert!(
        dir.path().join(".phantom.toml").exists(),
        ".phantom.toml should exist after init"
    );
}

#[test]
fn init_rewrites_env_with_phantom_tokens() {
    let dir = TempDir::new().unwrap();
    run_init(&dir).success();

    let env_content = fs::read_to_string(dir.path().join(".env")).expect("read .env");

    // Secrets must be replaced with phantom tokens
    assert!(
        env_content.contains("OPENAI_API_KEY=phm_"),
        "OPENAI_API_KEY should be a phantom token, got: {env_content}"
    );
    assert!(
        env_content.contains("STRIPE_SECRET=phm_"),
        "STRIPE_SECRET should be a phantom token, got: {env_content}"
    );

    // Real values must be gone
    assert!(
        !env_content.contains("sk-real-test"),
        "real OPENAI key should not remain in .env"
    );
    assert!(
        !env_content.contains("sk_live-real-test"),
        "real Stripe key should not remain in .env"
    );
}

#[test]
fn init_leaves_non_secret_vars_untouched() {
    let dir = TempDir::new().unwrap();
    run_init(&dir).success();

    let env_content = fs::read_to_string(dir.path().join(".env")).expect("read .env");

    // NODE_ENV is config, not a secret — must remain unchanged
    assert!(
        env_content.contains("NODE_ENV=development"),
        "NODE_ENV should be left as-is, got: {env_content}"
    );
}

#[test]
fn init_creates_env_backup() {
    let dir = TempDir::new().unwrap();
    run_init(&dir).success();

    let backup = dir.path().join(".env.backup");
    assert!(backup.exists(), ".env.backup should exist after init");

    let backup_content = fs::read_to_string(&backup).expect("read .env.backup");
    // Backup must contain the original real values
    assert!(
        backup_content.contains("sk-real-test"),
        "backup should contain original secret value"
    );
}

#[test]
fn init_no_env_file_fails_gracefully() {
    let dir = TempDir::new().unwrap();
    // No .env written — init should fail with a clear error message
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .arg("init")
        .arg("--from")
        .arg(".env")
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .failure();
}

/// `phantom init --empty` creates .phantom.toml in a fresh dir without a .env,
/// and `phantom add FOO --stdin` then succeeds (auto-init path also covered).
#[test]
fn init_empty_creates_config_and_add_works() {
    let dir = TempDir::new().unwrap();

    // Step 1: phantom init --empty — must succeed and produce .phantom.toml
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--empty"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    assert!(
        dir.path().join(".phantom.toml").exists(),
        ".phantom.toml should exist after init --empty"
    );

    // Step 2: phantom add FOO --stdin — must succeed in the bootstrapped dir
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["add", "FOO", "--stdin"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .write_stdin("supersecretvalue\n")
        .assert()
        .success();
}

/// `phantom add BAR --stdin` in a brand-new directory (no .phantom.toml at all)
/// must auto-create .phantom.toml and succeed — the auto-init-on-first-add path.
#[test]
fn add_auto_inits_when_no_config() {
    let dir = TempDir::new().unwrap();

    // No init step — go straight to add
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["add", "BAR", "--stdin"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .write_stdin("anothersecret\n")
        .assert()
        .success();

    assert!(
        dir.path().join(".phantom.toml").exists(),
        ".phantom.toml should be auto-created by phantom add"
    );
}
