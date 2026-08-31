use std::fs;

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
    let dir = TempDir::new().unwrap();
    command(&dir).args(["init", "--empty"]).assert().success();
    command(&dir)
        .args(["add", "RECOVERY_TEST_SECRET", "--stdin"])
        .write_stdin(format!("{SECRET_VALUE}\n"))
        .assert()
        .success();
    dir
}

fn write_private_passphrase(dir: &TempDir, name: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, format!("{BACKUP_PASS}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn combined_output(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_no_staging_files(dir: &TempDir) {
    let entries = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        entries
            .iter()
            .all(|name| !name.starts_with(".phantom-backup-")),
        "backup staging file was not cleaned up: {entries:?}"
    );
}

#[test]
fn backup_commands_hide_and_reject_legacy_argv_passphrases() {
    let dir = TempDir::new().unwrap();

    for subcommand in ["export", "import"] {
        let help = command(&dir).args([subcommand, "--help"]).output().unwrap();
        assert!(help.status.success());
        let stdout = String::from_utf8_lossy(&help.stdout);
        assert!(stdout.contains("--passphrase-file"));
        assert!(stdout.contains("non-Windows"));
        assert!(!stdout.contains("--passphrase "));
    }

    let export = command(&dir)
        .args(["export", "--passphrase", BACKUP_PASS])
        .output()
        .unwrap();
    assert!(!export.status.success());
    assert!(combined_output(&export).contains("no longer supported"));
    assert!(!combined_output(&export).contains(BACKUP_PASS));

    let import = command(&dir)
        .args(["import", "missing.enc", "--passphrase", BACKUP_PASS])
        .output()
        .unwrap();
    assert!(!import.status.success());
    assert!(combined_output(&import).contains("no longer supported"));
    assert!(!combined_output(&import).contains(BACKUP_PASS));
}

#[test]
fn backup_commands_fail_closed_without_an_attached_terminal() {
    let dir = TempDir::new().unwrap();

    let export = command(&dir).arg("export").output().unwrap();
    assert!(!export.status.success());
    assert!(combined_output(&export).contains("attached stdin and stderr terminals"));

    let import = command(&dir)
        .args(["import", "missing.enc"])
        .output()
        .unwrap();
    assert!(!import.status.success());
    assert!(combined_output(&import).contains("attached stdin and stderr terminals"));
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[cfg(windows)]
#[test]
fn windows_passphrase_file_fails_closed_without_reading_the_path() {
    let dir = TempDir::new().unwrap();
    let passphrase_file = dir.path().join("passphrase.txt");
    let missing_file = dir.path().join("missing.txt");
    fs::write(&passphrase_file, BACKUP_PASS).unwrap();

    for path in [&passphrase_file, &missing_file] {
        let output = command(&dir)
            .args(["export", "--passphrase-file"])
            .arg(path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let message = combined_output(&output);
        assert!(message.contains("--passphrase-file is disabled on Windows"));
        assert!(message.contains("hidden terminal prompt"));
        assert!(!message.contains(BACKUP_PASS));
    }
}

#[cfg(unix)]
#[test]
fn passphrase_file_must_be_private_regular_and_not_a_symlink() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = TempDir::new().unwrap();
    let exposed = dir.path().join("exposed-passphrase");
    fs::write(&exposed, BACKUP_PASS).unwrap();
    fs::set_permissions(&exposed, fs::Permissions::from_mode(0o644)).unwrap();

    let output = command(&dir)
        .args(["export", "--passphrase-file"])
        .arg(&exposed)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(combined_output(&output).contains("expected 0600 or stricter"));
    assert!(!combined_output(&output).contains(BACKUP_PASS));

    fs::set_permissions(&exposed, fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("passphrase-link");
    symlink(&exposed, &link).unwrap();
    let output = command(&dir)
        .args(["export", "--passphrase-file"])
        .arg(&link)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(combined_output(&output).contains("must not be a symlink"));
    assert!(!combined_output(&output).contains(BACKUP_PASS));
}

#[cfg(unix)]
#[test]
fn encrypted_backup_is_private_atomic_no_overwrite_and_recoverable() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let source = setup_secret();
    let passphrase_file = write_private_passphrase(&source, "backup.pass");
    let backup = source.path().join("backup.enc");

    let export = command(&source)
        .args(["export", "--output"])
        .arg(&backup)
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .output()
        .unwrap();
    assert!(export.status.success(), "{}", combined_output(&export));
    assert!(!combined_output(&export).contains(SECRET_VALUE));
    assert!(!combined_output(&export).contains(BACKUP_PASS));
    let encrypted = fs::read(&backup).unwrap();
    assert!(!encrypted
        .windows(SECRET_VALUE.len())
        .any(|window| window == SECRET_VALUE.as_bytes()));
    assert!(!encrypted
        .windows(BACKUP_PASS.len())
        .any(|window| window == BACKUP_PASS.as_bytes()));
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_no_staging_files(&source);

    let original = encrypted.clone();
    let overwrite = command(&source)
        .args(["export", "--output"])
        .arg(&backup)
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .output()
        .unwrap();
    assert!(!overwrite.status.success());
    assert!(combined_output(&overwrite).contains("refusing to overwrite"));
    assert_eq!(fs::read(&backup).unwrap(), original);
    assert_no_staging_files(&source);

    let blocked_audit_path = source.path().join(".phantom/audit.log");
    fs::create_dir_all(&blocked_audit_path).unwrap();
    let audit_failure_backup = source.path().join("audit-failure.enc");
    let audit_failure = command(&source)
        .env("PHANTOM_AUDIT", "required")
        .args(["export", "--output"])
        .arg(&audit_failure_backup)
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .output()
        .unwrap();
    assert!(!audit_failure.status.success());
    assert!(combined_output(&audit_failure).contains("Backup exists at"));
    assert!(audit_failure_backup.is_file());
    assert!(!combined_output(&audit_failure).contains(SECRET_VALUE));
    assert!(!combined_output(&audit_failure).contains(BACKUP_PASS));
    assert_no_staging_files(&source);

    let victim = source.path().join("victim");
    let backup_link = source.path().join("backup-link.enc");
    fs::write(&victim, b"untouched").unwrap();
    symlink(&victim, &backup_link).unwrap();
    let symlink_export = command(&source)
        .args(["export", "--output"])
        .arg(&backup_link)
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .output()
        .unwrap();
    assert!(!symlink_export.status.success());
    assert!(combined_output(&symlink_export).contains("symlink"));
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert_no_staging_files(&source);

    let recovery = TempDir::new().unwrap();
    command(&recovery)
        .args(["init", "--empty"])
        .assert()
        .success();
    let recovery_passphrase = write_private_passphrase(&recovery, "recovery.pass");
    let import = command(&recovery)
        .arg("import")
        .arg(&backup)
        .arg("--passphrase-file")
        .arg(&recovery_passphrase)
        .output()
        .unwrap();
    assert!(import.status.success(), "{}", combined_output(&import));
    assert!(!combined_output(&import).contains(SECRET_VALUE));
    assert!(!combined_output(&import).contains(BACKUP_PASS));

    let list = command(&recovery).arg("list").output().unwrap();
    assert!(list.status.success());
    assert!(String::from_utf8_lossy(&list.stdout).contains("RECOVERY_TEST_SECRET"));
    assert!(!combined_output(&list).contains(SECRET_VALUE));

    let backup_symlink = recovery.path().join("backup-symlink.enc");
    symlink(&backup, &backup_symlink).unwrap();
    let symlink_import = command(&recovery)
        .arg("import")
        .arg(&backup_symlink)
        .arg("--passphrase-file")
        .arg(&recovery_passphrase)
        .output()
        .unwrap();
    assert!(!symlink_import.status.success());
    assert!(combined_output(&symlink_import).contains("must not be a symlink"));
    assert!(!combined_output(&symlink_import).contains(SECRET_VALUE));
    assert!(!combined_output(&symlink_import).contains(BACKUP_PASS));
}
