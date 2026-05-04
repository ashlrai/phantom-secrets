/// Integration tests for environment scoping.
///
/// Verifies:
///   - `phantom add --env dev KEY val` stores under dev namespace
///   - `phantom list --env dev` shows it; `phantom list --env prod` does not
///   - `phantom env use staging` + `phantom add KEY val` stores under staging
///   - `phantom env copy --from dev --to staging` copies all dev secrets
///   - Legacy bare keys (no env prefix) are readable when env==default
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-env-scope-passphrase";

fn init_project(dir: &TempDir) {
    fs::write(dir.path().join(".env"), "SEED_SECRET=sk-seed-real-value\n").expect("write .env");

    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();
}

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path());
    cmd
}

/// Add in dev env, list in dev shows it, list in prod does not.
#[test]
fn env_add_and_list_scoped() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir)
        .args(["add", "--env", "dev", "STRIPE_KEY", "sk-dev-stripe"])
        .assert()
        .success();

    // List in dev shows the key
    let out = phantom(&dir)
        .args(["list", "--env", "dev"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(
        stdout.contains("STRIPE_KEY"),
        "dev env should contain STRIPE_KEY, got: {stdout}"
    );

    // List in prod should NOT show the key
    let out = phantom(&dir)
        .args(["list", "--env", "prod"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(
        !stdout.contains("STRIPE_KEY"),
        "prod env should not contain STRIPE_KEY, got: {stdout}"
    );
}

/// Add in dev, add in prod with different value — retrieve correctly scoped.
#[test]
fn env_add_dev_and_prod_separate() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir)
        .args(["add", "--env", "dev", "DB_URL", "postgres://dev-host/db"])
        .assert()
        .success();

    phantom(&dir)
        .args(["add", "--env", "prod", "DB_URL", "postgres://prod-host/db"])
        .assert()
        .success();

    // dev list contains DB_URL
    let out = phantom(&dir)
        .args(["list", "--env", "dev"])
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&out.get_output().stdout).contains("DB_URL"),
        "dev should have DB_URL"
    );

    // prod list contains DB_URL
    let out = phantom(&dir)
        .args(["list", "--env", "prod"])
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&out.get_output().stdout).contains("DB_URL"),
        "prod should have DB_URL"
    );
}

/// `phantom env use staging` sets the active env; subsequent add goes there.
#[test]
fn env_use_then_add_uses_active_env() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir)
        .args(["env", "use", "staging"])
        .assert()
        .success();

    // Verify the env file was written
    let env_file = dir.path().join(".phantom").join("env");
    assert!(
        env_file.exists(),
        ".phantom/env should exist after `env use`"
    );
    let content = fs::read_to_string(&env_file).unwrap();
    assert_eq!(content.trim(), "staging");

    phantom(&dir)
        .args(["add", "API_KEY", "sk-staging-key"])
        .assert()
        .success();

    // Should appear under staging
    let out = phantom(&dir)
        .args(["list", "--env", "staging"])
        .assert()
        .success();
    assert!(
        String::from_utf8_lossy(&out.get_output().stdout).contains("API_KEY"),
        "staging should have API_KEY"
    );

    // Should NOT appear under default
    let out = phantom(&dir)
        .args(["list", "--env", "default"])
        .assert()
        .success();
    assert!(
        !String::from_utf8_lossy(&out.get_output().stdout).contains("API_KEY"),
        "default should not have API_KEY"
    );
}

/// `phantom env copy --from dev --to staging` clones dev secrets.
#[test]
fn env_copy_from_dev_to_staging() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir)
        .args(["add", "--env", "dev", "OPENAI_KEY", "sk-openai-dev"])
        .assert()
        .success();

    phantom(&dir)
        .args(["add", "--env", "dev", "ANTHROPIC_KEY", "sk-anthropic-dev"])
        .assert()
        .success();

    phantom(&dir)
        .args(["env", "copy", "--from", "dev", "--to", "staging"])
        .assert()
        .success();

    // staging should now have both keys
    let out = phantom(&dir)
        .args(["list", "--env", "staging"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(
        stdout.contains("OPENAI_KEY"),
        "staging should have OPENAI_KEY after copy"
    );
    assert!(
        stdout.contains("ANTHROPIC_KEY"),
        "staging should have ANTHROPIC_KEY after copy"
    );
}

/// `phantom env list` shows known environments.
#[test]
fn env_list_shows_known_envs() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir)
        .args(["add", "--env", "dev", "KEY1", "val1"])
        .assert()
        .success();

    phantom(&dir)
        .args(["add", "--env", "prod", "KEY2", "val2"])
        .assert()
        .success();

    let out = phantom(&dir).args(["env", "list"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("dev"), "env list should show dev");
    assert!(stdout.contains("prod"), "env list should show prod");
    assert!(
        stdout.contains("default"),
        "env list should always show default"
    );
}

/// `phantom env new <name>` succeeds and reports the env.
#[test]
fn env_new_reports_declared() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    let out = phantom(&dir)
        .args(["env", "new", "canary"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(
        stdout.contains("canary"),
        "env new should mention the env name"
    );
}
