/// Integration tests for `phantom init`.
///
/// These tests run against the real binary compiled from the workspace. Each
/// test creates an isolated TempDir so that:
///   - The `.phantom.toml` project_id is unique per test (derived from the
///     canonicalised directory path), preventing keychain collisions.
///   - Files written by `init` (`.env`, `.phantom.toml`,
///     `.env.example`) are cleaned up automatically when the TempDir drops.
///
/// PHANTOM_VAULT_PASSPHRASE is set so that if the OS keychain is unavailable
/// (CI, sandboxed environments) the encrypted-file vault backend is used with
/// a deterministic passphrase instead of panicking.
mod common;

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
fn init_rejects_single_project_dry_run_without_mutating() {
    let dir = common::canonical_tempdir();
    let env_path = dir.path().join(".env");
    let original = "OPENAI_API_KEY=sk-real-test\n";
    fs::write(&env_path, original).expect("write .env");

    let output = Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--dry-run"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .output()
        .expect("run phantom init --dry-run");

    assert!(
        !output.status.success(),
        "unsupported flag combination must fail"
    );
    assert_eq!(
        fs::read_to_string(&env_path).expect("read .env"),
        original,
        "rejected preview must not rewrite .env"
    );
    assert!(!dir.path().join(".phantom.toml").exists());
    assert!(!dir.path().join(".env.example").exists());
}

#[test]
fn init_creates_phantom_toml() {
    let dir = common::canonical_tempdir();
    run_init(&dir).success();
    assert!(
        dir.path().join(".phantom.toml").exists(),
        ".phantom.toml should exist after init"
    );
}

#[test]
fn init_excludes_the_bearerless_lifecycle_lock_from_git() {
    let dir = common::canonical_tempdir();
    run_init(&dir).success();

    let gitignore = fs::read_to_string(dir.path().join(".gitignore")).expect("read .gitignore");
    assert!(
        gitignore
            .lines()
            .any(|line| line.trim() == ".phantom.proxy.lock"),
        "the bearerless foreground lifecycle lock must be ignored"
    );
    assert!(gitignore.lines().any(|line| line.trim() == ".phantom.pid"));
    assert!(gitignore
        .lines()
        .any(|line| line.trim() == ".phantom.start.lock"));
    assert!(
        !gitignore.lines().any(|line| line.trim() == ".phantom.toml"),
        "shareable value-free project configuration must remain trackable"
    );
}

#[test]
fn init_rewrites_env_with_phantom_tokens() {
    let dir = common::canonical_tempdir();
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
    let dir = common::canonical_tempdir();
    run_init(&dir).success();

    let env_content = fs::read_to_string(dir.path().join(".env")).expect("read .env");

    // NODE_ENV is config, not a secret — must remain unchanged
    assert!(
        env_content.contains("NODE_ENV=development"),
        "NODE_ENV should be left as-is, got: {env_content}"
    );
}

#[test]
fn init_never_leaves_a_plaintext_env_backup() {
    let dir = common::canonical_tempdir();
    run_init(&dir).success();

    let backup = dir.path().join(".env.backup");
    assert!(!backup.exists(), ".env.backup must not exist after init");
}

#[test]
fn init_no_env_file_fails_gracefully() {
    let dir = common::canonical_tempdir();
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
/// and `phantom add FOO --stdin` then succeeds through the required explicit
/// initialization path.
#[test]
fn init_empty_creates_config_and_add_works() {
    let dir = common::canonical_tempdir();

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

/// `phantom add BAR --stdin` in a brand-new directory must fail before creating
/// project state and direct the user to the explicit transactional init path.
#[test]
fn add_requires_explicit_init_when_no_config() {
    let dir = common::canonical_tempdir();

    // No init step — go straight to add
    let output = Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["add", "BAR", "--stdin"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .write_stdin("anothersecret\n")
        .assert()
        .failure();
    assert!(String::from_utf8_lossy(&output.get_output().stderr).contains("phantom init --empty"));

    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// `phantom init` must leave NEXT_PUBLIC_*, VITE_*, REACT_APP_*, EXPO_PUBLIC_*,
/// NUXT_PUBLIC_*, and GATSBY_* keys unchanged in the .env file — they are
/// browser-safe public keys and must never be wrapped in phantom tokens.
#[test]
fn init_skips_public_framework_keys() {
    let dir = common::canonical_tempdir();
    let env_path = dir.path().join(".env");
    fs::write(
        &env_path,
        concat!(
            "OPENAI_API_KEY=sk-real-secret\n",
            "NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co\n",
            "VITE_API_URL=https://api.example.com\n",
            "REACT_APP_BACKEND_URL=https://backend.example.com\n",
            "EXPO_PUBLIC_POSTHOG_KEY=phk_public_key_value\n",
            "NUXT_PUBLIC_API_BASE=https://api.example.com/v2\n",
            "GATSBY_API_URL=https://gatsby.example.com\n",
            "NODE_ENV=development\n",
        ),
    )
    .expect("write .env");

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .arg("init")
        .arg("--from")
        .arg(".env")
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    let env_content = fs::read_to_string(dir.path().join(".env")).expect("read .env");

    // The real secret must be phantomized.
    assert!(
        env_content.contains("OPENAI_API_KEY=phm_"),
        "OPENAI_API_KEY should be a phantom token, got: {env_content}"
    );

    // All framework public keys must remain as plain values — no phantom wrapping.
    assert!(
        env_content.contains("NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co"),
        "NEXT_PUBLIC_ key must not be wrapped, got: {env_content}"
    );
    assert!(
        env_content.contains("VITE_API_URL=https://api.example.com"),
        "VITE_ key must not be wrapped, got: {env_content}"
    );
    assert!(
        env_content.contains("REACT_APP_BACKEND_URL=https://backend.example.com"),
        "REACT_APP_ key must not be wrapped, got: {env_content}"
    );
    assert!(
        env_content.contains("EXPO_PUBLIC_POSTHOG_KEY=phk_public_key_value"),
        "EXPO_PUBLIC_ key must not be wrapped, got: {env_content}"
    );
    assert!(
        env_content.contains("NUXT_PUBLIC_API_BASE=https://api.example.com/v2"),
        "NUXT_PUBLIC_ key must not be wrapped, got: {env_content}"
    );
    assert!(
        env_content.contains("GATSBY_API_URL=https://gatsby.example.com"),
        "GATSBY_ key must not be wrapped, got: {env_content}"
    );
}

/// Public key keys detected during `phantom init` must be persisted in the
/// `[phantom.public_keys]` array in `.phantom.toml` so that subsequent tooling
/// (e.g., `phantom check`, `phantom add`) can respect the skip decision.
#[test]
fn init_persists_public_keys_in_toml() {
    let dir = common::canonical_tempdir();
    let env_path = dir.path().join(".env");
    fs::write(
        &env_path,
        concat!(
            "STRIPE_SECRET_KEY=sk_test_realvalue\n",
            "NEXT_PUBLIC_SUPABASE_URL=https://proj.supabase.co\n",
            "VITE_ANALYTICS_ID=G-XXXXXXXXXX\n",
        ),
    )
    .expect("write .env");

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .arg("init")
        .arg("--from")
        .arg(".env")
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    let toml_content =
        fs::read_to_string(dir.path().join(".phantom.toml")).expect("read .phantom.toml");

    // Both public keys must appear in the persisted TOML under public_keys.
    assert!(
        toml_content.contains("NEXT_PUBLIC_SUPABASE_URL"),
        ".phantom.toml must record NEXT_PUBLIC_ key, got: {toml_content}"
    );
    assert!(
        toml_content.contains("VITE_ANALYTICS_ID"),
        ".phantom.toml must record VITE_ key, got: {toml_content}"
    );

    // The real secret must NOT appear in the public_keys array.
    // Extract only the array value: everything between `public_keys = [` and the
    // closing `]`, then assert STRIPE_SECRET_KEY is absent from that slice.
    let array_content = toml_content
        .split("public_keys = [")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .unwrap_or("");
    assert!(
        !array_content.contains("STRIPE_SECRET_KEY"),
        "STRIPE_SECRET_KEY must not appear in public_keys array, got: {array_content}"
    );
}

/// When a .env contains ONLY public keys and no real secrets, `phantom init`
/// must exit successfully and report that there is nothing to protect — it must
/// not fail or attempt to create an empty vault with phantom tokens.
#[test]
fn init_handles_all_public_keys_no_secrets() {
    let dir = common::canonical_tempdir();
    let env_path = dir.path().join(".env");
    fs::write(
        &env_path,
        concat!(
            "NEXT_PUBLIC_API_URL=https://api.example.com\n",
            "VITE_FEATURE_FLAG=true\n",
            "REACT_APP_VERSION=1.0.0\n",
            "NODE_ENV=production\n",
        ),
    )
    .expect("write .env");

    // init must succeed (exit 0) even when there are no secrets to protect.
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .arg("init")
        .arg("--from")
        .arg(".env")
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();

    // The .env file must be completely unchanged — no phantom tokens inserted.
    let env_content = fs::read_to_string(&env_path).expect("read .env");
    assert!(
        !env_content.contains("phm_"),
        ".env must have no phantom tokens when all vars are public/config, got: {env_content}"
    );
    assert!(
        env_content.contains("NEXT_PUBLIC_API_URL=https://api.example.com"),
        "NEXT_PUBLIC_ value must be preserved"
    );
    assert!(
        env_content.contains("VITE_FEATURE_FLAG=true"),
        "VITE_ value must be preserved"
    );
}
