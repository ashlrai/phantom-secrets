//! `enforce_rotation_on_access = true` must refuse `phantom exec` when the
//! secret's vault entry is older than its rotation schedule allows.

#![cfg(target_os = "linux")]

mod common;

use phantom_vault::VaultBackend;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VAULT_PASS: &str = "rotation-enforcement-integration-passphrase";
const FIXTURE_VALUE: &str = "rotation-enforcement-fixture-value-0123456789";
const DAY: u64 = 86_400;

fn phantom_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_phantom"))
}

fn data_home(home: &Path) -> PathBuf {
    home.join("xdg-data")
}

fn phantom_command(project: &Path, home: &Path) -> Command {
    let mut command = Command::new(phantom_binary());
    command
        .current_dir(project)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_DATA_HOME", data_home(home))
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_REQUIRE_KEYCHAIN")
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS);
    command
}

fn exec_version(project: &Path, home: &Path) -> Output {
    phantom_command(project, home)
        .args(["exec", "--"])
        .arg(phantom_binary())
        .arg("--version")
        .output()
        .unwrap()
}

fn enforced_project(rotate_every: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    fs::write(
        project.path().join(".env"),
        format!("OPENAI_API_KEY={FIXTURE_VALUE}\n"),
    )
    .unwrap();
    let output = phantom_command(project.path(), home.path())
        .args(["init", "--from", ".env"])
        .output()
        .unwrap();
    assert!(output.status.success(), "phantom init failed");

    let config_path = project.path().join(".phantom.toml");
    let mut config = fs::read_to_string(&config_path).unwrap();
    config.push_str(&format!(
        "\n[phantom.secrets.OPENAI_API_KEY]\nrotate_every = \"{rotate_every}\"\nenforce_rotation_on_access = true\n"
    ));
    fs::write(&config_path, config).unwrap();
    (project, home)
}

/// Move the vault entry's `created_at` back by `days`, as if it had been
/// stored that long ago.
fn backdate_entry(project: &Path, home: &Path, days: u64) {
    let config = phantom_core::config::PhantomConfig::load(&project.join(".phantom.toml")).unwrap();
    let vault = phantom_vault::file::FileVault::new(
        &data_home(home).join("phantom-secrets"),
        config.local_project_id(),
        VAULT_PASS.to_string(),
    )
    .unwrap();
    let names = vault.list().unwrap();
    let entry = names
        .iter()
        .find(|name| name.ends_with("OPENAI_API_KEY"))
        .expect("init vaulted OPENAI_API_KEY");
    let mut metadata = vault.get_metadata(entry).unwrap().unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    metadata.created_at = Some(now - days * DAY);
    metadata.rotated_at = None;
    vault.set_metadata(entry, metadata).unwrap();
}

fn child_ran(output: &Output) -> bool {
    String::from_utf8_lossy(&output.stdout)
        .contains(&format!("phantom {}", env!("CARGO_PKG_VERSION")))
}

#[test]
fn exec_refuses_an_overdue_secret_under_rotation_enforcement() {
    let (project, home) = enforced_project("30d");

    // Freshly stored: inside the 30-day window.
    let fresh = exec_version(project.path(), home.path());
    assert!(fresh.status.success(), "fresh secret was refused");
    assert!(child_ran(&fresh));

    backdate_entry(project.path(), home.path(), 45);
    let overdue = exec_version(project.path(), home.path());
    assert!(!overdue.status.success(), "overdue secret was not refused");
    assert!(!child_ran(&overdue), "child ran despite the refusal");
    let stderr = String::from_utf8_lossy(&overdue.stderr);
    assert!(
        stderr.contains("'OPENAI_API_KEY'"),
        "refusal does not name the secret"
    );
    assert!(
        stderr.contains("45 days ago"),
        "refusal does not state the age"
    );
    assert!(
        stderr.contains("phantom remove OPENAI_API_KEY"),
        "refusal does not name the fix"
    );
    let leaked = String::from_utf8_lossy(&overdue.stdout).contains(FIXTURE_VALUE)
        || stderr.contains(FIXTURE_VALUE);
    assert!(!leaked, "refusal printed the secret value");
}

#[test]
fn exec_allows_an_enforced_secret_inside_its_window() {
    let (project, home) = enforced_project("90d");
    backdate_entry(project.path(), home.path(), 45);
    let output = exec_version(project.path(), home.path());
    assert!(
        output.status.success(),
        "secret inside its window was refused"
    );
    assert!(child_ran(&output));
}
