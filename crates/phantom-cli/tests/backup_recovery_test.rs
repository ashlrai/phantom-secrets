mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

const VAULT_PASS: &str = "backup-recovery-vault-test-passphrase";
const BACKUP_PASS: &str = "backup-recovery-archive-test-passphrase";
const SECRET_VALUE: &str = "backup-recovery-plaintext-must-not-escape";

fn command(dir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env_remove("PHANTOM_TOKEN")
        .env_remove("PHANTOM_AUDIT");
    command
}

fn setup_secret() -> TempDir {
    let dir = common::canonical_tempdir();
    command(&dir).args(["init", "--empty"]).assert().success();
    command(&dir)
        .args(["add", "RECOVERY_TEST_SECRET", "--stdin"])
        .write_stdin(format!("{SECRET_VALUE}\n"))
        .assert()
        .success();
    dir
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn snapshot_regular_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                visit(root, &path, snapshot);
            } else if metadata.is_file() {
                snapshot.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

#[test]
fn backup_commands_hide_argv_passphrases_and_describe_current_policy() {
    let dir = common::canonical_tempdir();

    let export_help = command(&dir).args(["export", "--help"]).output().unwrap();
    assert!(export_help.status.success());
    let export_help = String::from_utf8_lossy(&export_help.stdout);
    assert!(export_help.contains("--passphrase-file"));
    assert!(export_help.contains("rejected for export"));
    assert!(export_help.contains("trusted-terminal"));
    assert!(!export_help.contains("--passphrase "));

    let import_help = command(&dir).args(["import", "--help"]).output().unwrap();
    assert!(import_help.status.success());
    let import_help = String::from_utf8_lossy(&import_help.stdout);
    assert!(import_help.contains("--passphrase-file"));
    assert!(import_help.contains("non-Windows"));
    assert!(import_help.contains("never bypasses the exact trusted-terminal ceremony"));
    assert!(!import_help.contains("--passphrase "));

    for subcommand in ["export", "import"] {
        let mut args = vec![subcommand];
        if subcommand == "import" {
            args.push("missing.enc");
        }
        args.extend(["--passphrase", BACKUP_PASS]);
        let output = command(&dir).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(combined_output(&output).contains("no longer supported"));
        assert!(!combined_output(&output).contains(BACKUP_PASS));
    }
}

#[test]
fn export_passphrase_file_is_denied_before_path_access() {
    let dir = common::canonical_tempdir();
    let missing = dir.path().join("missing-passphrase");
    let output = command(&dir)
        .args(["export", "--passphrase-file"])
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = combined_output(&output);
    assert!(message.contains("--passphrase-file is disabled for export"));
    assert!(message.contains("agent-decryptable"));
    assert!(!message.contains(BACKUP_PASS));
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn headless_export_fails_before_backup_or_vault_mutation() {
    let source = setup_secret();
    let before = snapshot_regular_files(source.path());

    let output = command(&source)
        .args(["export", "--output", "backup.enc"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = combined_output(&output);
    assert!(message.contains("stdin, stdout, and stderr attached to a trusted terminal"));
    assert!(!message.contains(SECRET_VALUE));
    assert!(!source.path().join("backup.enc").exists());
    assert_eq!(snapshot_regular_files(source.path()), before);
}

#[test]
fn headless_import_fails_before_source_read_or_vault_mutation() {
    let target = setup_secret();
    let source_path = target.path().join("unreadable.enc");
    fs::write(&source_path, b"not actually encrypted").unwrap();
    let before = snapshot_regular_files(target.path());

    let output = command(&target)
        .arg("import")
        .arg(&source_path)
        .arg("--force")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = combined_output(&output);
    assert!(message.contains("stdin, stdout, and stderr attached to a trusted terminal"));
    assert!(!message.contains(SECRET_VALUE));
    assert!(!message.contains("wrong passphrase"));
    assert_eq!(snapshot_regular_files(target.path()), before);
}
