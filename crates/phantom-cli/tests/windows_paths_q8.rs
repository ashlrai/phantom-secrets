//! Path regressions shared by Windows and Unix; fixtures contain no credentials.
mod common;

use phantom_core::config::PhantomConfig;

#[test]
fn empty_init_and_parent_fixture_resolve_the_same_vault() {
    let root = common::canonical_tempdir();
    let dir = tempfile::Builder::new()
        .prefix("project with spaces-ü-")
        .tempdir_in(root.path())
        .unwrap();
    common::phantom(&dir, "windows-path-fixture-passphrase")
        .args(["init", "--empty"])
        .assert()
        .success();
    let config = PhantomConfig::load(&dir.path().join(".phantom.toml")).unwrap();
    let encrypted = common::encrypted_file(&dir, config.local_project_id());
    assert!(encrypted.parent().unwrap().is_dir());
    assert!(encrypted.with_extension("lock").is_file());
    assert_eq!(
        config.local_project_id(),
        PhantomConfig::project_id_from_path(dir.path())
    );
    assert_eq!(
        config.local_project_id(),
        PhantomConfig::project_id_from_path(&dir.path().canonicalize().unwrap())
    );
    assert_eq!(
        config.local_project_id(),
        PhantomConfig::project_id_from_path(&dir.path().join("."))
    );
    common::phantom(&dir, "windows-path-fixture-passphrase")
        .args(["fleet-status", "--json", "--strict"])
        .assert()
        .success();
}

#[test]
fn help_uses_the_product_name_when_executable_path_contains_spaces() {
    let dir = common::canonical_tempdir();
    let bin_dir = dir.path().join("directory with spaces");
    std::fs::create_dir(&bin_dir).unwrap();
    let executable = bin_dir.join("renamed-phantom.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_phantom"), &executable).unwrap();
    let mut command = std::process::Command::new(&executable);
    command
        .env_clear()
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .env("NO_COLOR", "1");
    let output = command
        .current_dir(dir.path())
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout)
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        help,
        include_str!("snapshots/top_level_help.txt").replace("\r\n", "\n")
    );
    assert!(!dir.path().join(".phantom.toml").exists());
}
