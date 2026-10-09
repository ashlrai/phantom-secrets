mod common;

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use std::fs;
use tempfile::TempDir;

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path());
    cmd
}

/// Deterministic fake signing seed for tests (never a real key).
fn test_seed_hex() -> String {
    "ab".repeat(32)
}

fn test_pubkey_hex() -> String {
    let seed: [u8; 32] = [0xab; 32];
    let key = SigningKey::from_bytes(&seed);
    hex::encode(key.verifying_key().as_bytes())
}

fn scaffold_pack(dir: &TempDir, name: &str) -> std::path::PathBuf {
    let pack_dir = dir.path().join(format!("{name}-pack"));
    phantom(dir)
        .args(["connector", "pack", "init"])
        .arg(&pack_dir)
        .args(["--name", name])
        .assert()
        .success();
    assert!(pack_dir.join("connector.json").exists());
    pack_dir
}

fn sign_pack(dir: &TempDir, pack_dir: &std::path::Path) {
    phantom(dir)
        .args(["connector", "pack", "sign"])
        .arg(pack_dir)
        .env("PHANTOM_CONNECTOR_SIGNING_KEY", test_seed_hex())
        .assert()
        .success();
    assert!(pack_dir.join("connector.sig").exists());
}

#[test]
fn connector_list_empty_gives_guidance() {
    let dir = common::canonical_tempdir();
    let out = phantom(&dir).args(["connector", "list"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(
        stdout.contains("No connector packs installed"),
        "got: {stdout}"
    );

    let out = phantom(&dir)
        .args(["connector", "list", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert_eq!(stdout.trim(), "[]");
}

#[test]
fn connector_anchor_list_empty_gives_guidance() {
    let dir = common::canonical_tempdir();
    let out = phantom(&dir)
        .args(["connector", "anchor", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(
        stdout.contains("No connector trust anchors"),
        "got: {stdout}"
    );
}

#[test]
fn connector_add_requires_trusted_terminal() {
    // No TTY in tests: the trusted-terminal gate must fail closed with
    // actionable guidance, before any signature or install work.
    let dir = common::canonical_tempdir();
    let pack_dir = scaffold_pack(&dir, "demo");
    sign_pack(&dir, &pack_dir);
    let out = phantom(&dir)
        .args(["connector", "add"])
        .arg(&pack_dir)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("trusted terminal"),
        "should demand a trusted terminal, got: {stderr}"
    );
}

#[test]
fn connector_anchor_add_requires_trusted_terminal() {
    let dir = common::canonical_tempdir();
    let out = phantom(&dir)
        .args(["connector", "anchor", "add", "--key", &test_pubkey_hex()])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("trusted terminal"),
        "should demand a trusted terminal, got: {stderr}"
    );
}

#[test]
fn connector_anchor_add_rejects_bad_key_even_before_tty() {
    // Malformed keys are rejected by argument validation... but the TTY gate
    // runs first, so this asserts the TTY gate fires (fail-closed ordering).
    let dir = common::canonical_tempdir();
    let out = phantom(&dir)
        .args(["connector", "anchor", "add", "--key", "not-hex"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("trusted terminal"),
        "TTY gate must fire before key parsing, got: {stderr}"
    );
}

#[test]
fn pack_sign_needs_a_key_and_says_so() {
    let dir = common::canonical_tempdir();
    let pack_dir = scaffold_pack(&dir, "demo");
    let out = phantom(&dir)
        .args(["connector", "pack", "sign"])
        .arg(&pack_dir)
        .env_remove("PHANTOM_CONNECTOR_SIGNING_KEY")
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("PHANTOM_CONNECTOR_SIGNING_KEY") && stderr.contains("--key-file"),
        "error must name both key sources, got: {stderr}"
    );
    // The signature envelope names the anchor id for `anchor add`.
    sign_pack(&dir, &pack_dir);
    let sig = fs::read_to_string(pack_dir.join("connector.sig")).unwrap();
    let (key_id, sig_hex) = sig.trim().split_once(':').expect("envelope");
    assert_eq!(key_id.len(), 8);
    assert_eq!(sig_hex.len(), 128);
}

#[cfg(unix)]
#[test]
fn pack_sign_refuses_open_key_file_perms() {
    let dir = common::canonical_tempdir();
    let pack_dir = scaffold_pack(&dir, "demo");
    let key_file = dir.path().join("seed.hex");
    fs::write(&key_file, test_seed_hex()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let out = phantom(&dir)
        .args(["connector", "pack", "sign"])
        .arg(&pack_dir)
        .args(["--key-file"])
        .arg(&key_file)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    #[cfg(unix)]
    assert!(
        stderr.contains("0600"),
        "must refuse open key-file permissions, got: {stderr}"
    );
}

#[test]
fn pack_init_rejects_bad_name() {
    let dir = common::canonical_tempdir();
    let out = phantom(&dir)
        .args(["connector", "pack", "init"])
        .arg(dir.path().join("x"))
        .args(["--name", "BAD NAME"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("pack name"),
        "must explain the name rules, got: {stderr}"
    );
}

#[test]
fn pack_sign_accepts_valid_private_key_file() {
    let dir = common::canonical_tempdir();
    let pack_dir = scaffold_pack(&dir, "demo");
    let key_file = dir.path().join("private-seed.hex");
    fs::write(&key_file, test_seed_hex()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    phantom(&dir)
        .args(["connector", "pack", "sign"])
        .arg(&pack_dir)
        .arg("--key-file")
        .arg(key_file)
        .assert()
        .success();
    assert!(pack_dir.join("connector.sig").is_file());
}

#[test]
fn connector_inspect_missing_pack_points_at_list() {
    let dir = common::canonical_tempdir();
    let out = phantom(&dir)
        .args(["connector", "inspect", "nope"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(
        stderr.contains("no installed pack"),
        "must name the problem, got: {stderr}"
    );
}

#[test]
fn onboard_plan_is_read_only_and_json_receipt_parses() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".env"), "FOO=bar\n").unwrap();

    // Human plan: exit 0, no mutation.
    let out = phantom(&dir).args(["onboard", "--plan"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(stdout.contains("Detect"), "got: {stdout}");
    assert!(stdout.contains("Protect"), "got: {stdout}");
    assert!(!dir.path().join(".phantom.toml").exists());

    // JSON receipt: machine-readable, phases present.
    let out = phantom(&dir)
        .args(["--json", "onboard", "--plan"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    let receipt: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("receipt must be JSON");
    assert_eq!(receipt["version"], 1);
    assert_eq!(receipt["done"], false);
    let phases = receipt["phases"].as_array().expect("phases array");
    let names: Vec<&str> = phases
        .iter()
        .map(|p| p["phase"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["detect", "protect", "connect", "verify"]);
    assert_eq!(phases[0]["status"], "ok");
    assert_eq!(phases[1]["status"], "skipped");
}

#[test]
fn onboard_plan_observes_config_presence_without_vault_access() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".phantom.toml"), "# stub\n").unwrap();
    let out = phantom(&dir).args(["onboard", "--plan"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    assert!(
        stdout.contains("config_present=true") && stdout.contains("vault not inspected"),
        "plan must report config presence without claiming vault protection, got: {stdout}"
    );
}

// Windows KnownFolders ignores environment directory overrides; a constructor
// regression must never touch the host's actual vault directory.
#[cfg(unix)]
#[test]
fn headless_validation_once_and_watch_leave_legacy_storage_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let dir = common::canonical_tempdir();
    let config = phantom_core::config::PhantomConfig::new_with_defaults("headless-fixture".into());
    config.save(&dir.path().join(".phantom.toml")).unwrap();
    let mut before = Vec::new();
    for base in [
        dir.path().join("data/phantom-secrets"),
        dir.path()
            .join("Library/Application Support/ai.phantom.phantom-secrets"),
        dir.path().join("localappdata/phantom/phantom-secrets/data"),
    ] {
        let path = base.join("vaults/headless-fixture.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            br#"{"secrets":{"SYNTHETIC_KEY":"never-a-real-credential"}}"#,
        )
        .unwrap();
        let metadata = fs::metadata(&path).unwrap();
        before.push((
            path.clone(),
            fs::read(&path).unwrap(),
            metadata.modified().unwrap(),
            metadata.permissions().mode(),
        ));
    }
    for args in [
        ["validate", "--check-all", "--json"],
        ["validate", "--watch", "--json"],
    ] {
        let out = phantom(&dir)
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("APPDATA", dir.path().join("appdata"))
            .env("LOCALAPPDATA", dir.path().join("localappdata"))
            .env("PHANTOM_VAULT_PASSPHRASE", "synthetic-test-only")
            .args(args)
            .assert()
            .failure();
        assert!(
            String::from_utf8_lossy(&out.get_output().stderr)
                .contains("no credential was retrieved")
        );
        for (path, bytes, modified, mode) in &before {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(&fs::read(path).unwrap(), bytes);
            assert_eq!(&metadata.modified().unwrap(), modified);
            assert_eq!(&metadata.permissions().mode(), mode);
            assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        }
    }
    assert!(!dir.path().join(".phantom").exists());
}
