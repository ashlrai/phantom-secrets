//! `--dry-run` for init, add, and remove must print a plan and leave the
//! project tree, including the encrypted-file vault under HOME, unchanged.
mod common;

use assert_cmd::Command;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Output;

const PASS: &str = "test-passphrase-dry-run";
const CANARY: &str = "sk-dry-run-canary-7f3a9c1e5b";
const PUBLIC_VALUE: &str = "browser-label-not-secret";

fn phantom(dir: &Path) -> Command {
    let mut command = Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(dir)
        .env("HOME", dir)
        .env("PHANTOM_VAULT_PASSPHRASE", PASS)
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_AUDIT")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    command
}

fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("directory entry"))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .expect("child path")
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()));
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(&path).expect("read link");
            files.insert(relative, target.to_string_lossy().into_owned().into_bytes());
        } else if file_type.is_dir() {
            files.insert(format!("{relative}/"), Vec::new());
            walk(root, &path, files);
        } else {
            let bytes =
                fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            files.insert(relative, bytes);
        }
    }
}

fn assert_unchanged(before: &BTreeMap<String, Vec<u8>>, after: &BTreeMap<String, Vec<u8>>) {
    let mut changes = Vec::new();
    for (path, bytes) in before {
        match after.get(path) {
            Some(now) if now == bytes => {}
            Some(_) => changes.push(format!("changed {path}")),
            None => changes.push(format!("removed {path}")),
        }
    }
    for path in after.keys() {
        if !before.contains_key(path) {
            changes.push(format!("added {path}"));
        }
    }
    assert!(
        changes.is_empty(),
        "dry run changed the project or vault tree: {changes:?}"
    );
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn assert_values_absent(stdout: &str, stderr: &str) {
    for secret in [CANARY, PUBLIC_VALUE] {
        assert!(
            !stdout.contains(secret),
            "stdout contained a planted secret value"
        );
        assert!(
            !stderr.contains(secret),
            "stderr contained a planted secret value"
        );
    }
    assert!(!stdout.contains("phm_"), "stdout contained a phantom token");
    assert!(!stderr.contains("phm_"), "stderr contained a phantom token");
}

fn phantom_unset(dir: &Path) -> Command {
    let mut command = Command::cargo_bin("phantom").expect("binary not found");
    command
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_DATA_HOME", dir.join("xdg-data"))
        .env("XDG_CONFIG_HOME", dir.join("xdg-config"))
        .env("XDG_STATE_HOME", dir.join("xdg-state"))
        .env("XDG_CACHE_HOME", dir.join("xdg-cache"))
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_VAULT_PASSPHRASE")
        .env_remove("PHANTOM_REQUIRE_KEYCHAIN")
        .env_remove("PHANTOM_AUDIT")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    command
}

/// Project files from a dry-run plan, with the encrypted-file vault path
/// checked and removed. The vault lives under the temp HOME, so its prefix
/// follows the platform data dir.
fn project_files_without_vault(dir: &Path, stdout: &str) -> Vec<String> {
    let id = phantom_core::config::PhantomConfig::project_id_from_path(dir);
    let mut files = planned_files(stdout);
    let vault_at = files
        .iter()
        .position(|path| path.ends_with(".vault"))
        .expect("dry run should list the vault path");
    let vault = files.remove(vault_at);
    assert!(
        vault.ends_with(&format!("vaults/{id}.vault")),
        "vault path {vault}"
    );
    files
}

fn planned_files(stdout: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut in_files = false;
    for line in stdout.lines() {
        if line.starts_with("Would write ") {
            in_files = true;
            continue;
        }
        if !in_files {
            continue;
        }
        if let Some(path) = line.strip_prefix("  ") {
            if path.is_empty() || path.starts_with('+') || path.starts_with('-') {
                break;
            }
            files.push(path.to_string());
        } else {
            break;
        }
    }
    files
}

#[test]
fn init_dry_run_lists_files_and_keys_without_writing_or_printing_values() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={CANARY}\nNEXT_PUBLIC_APP_NAME={PUBLIC_VALUE}\nPORT=3000\n"),
    )
    .unwrap();
    let before = snapshot(dir.path());

    let output = phantom(dir.path())
        .args(["init", "--dry-run", "--from", ".env"])
        .output()
        .expect("run init --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "init dry run failed: {stderr}");
    assert!(stdout.contains("Would add 1 key(s):"));
    assert!(stdout.contains("  + OPENAI_API_KEY"));
    assert!(stdout.contains("Skipping 1 public key(s)"));
    assert!(stdout.contains("NEXT_PUBLIC_APP_NAME"));
    assert_eq!(
        project_files_without_vault(dir.path(), &stdout),
        vec![
            ".env".to_string(),
            ".env.example".to_string(),
            ".gitignore".to_string(),
            ".phantom.toml".to_string(),
            "CLAUDE.md".to_string(),
        ]
    );
    assert!(stdout.contains("Dry run only. Nothing was written."));
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
    assert!(!dir.path().join(".local").exists());
}

#[test]
fn init_empty_dry_run_plans_config_and_creates_nothing() {
    let dir = common::canonical_tempdir();
    let before = snapshot(dir.path());
    let output = phantom(dir.path())
        .args(["init", "--empty", "--dry-run"])
        .output()
        .expect("run init --empty --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "empty dry run failed: {stderr}");
    assert!(stdout.contains("Would create an empty vault."));
    assert_eq!(
        project_files_without_vault(dir.path(), &stdout),
        vec![".gitignore".to_string(), ".phantom.toml".to_string()]
    );
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
}

#[test]
fn init_empty_dry_run_leaves_an_existing_config_alone() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".phantom.toml"), "existing = true\n").unwrap();
    let before = snapshot(dir.path());
    let output = phantom(dir.path())
        .args(["init", "--empty", "--dry-run"])
        .output()
        .expect("run init --empty --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "empty dry run failed: {stderr}");
    assert!(stdout.contains(".phantom.toml already exists. Nothing to do."));
    assert!(!stdout.contains('\u{2014}'));
    assert!(!stderr.contains('\u{2014}'));
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
}

#[test]
fn init_all_dry_run_still_writes_nothing() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={CANARY}\n"),
    )
    .unwrap();
    let before = snapshot(dir.path());
    let output = phantom(dir.path())
        .args(["init", "--all", dir.path().to_str().unwrap(), "--dry-run"])
        .output()
        .expect("run init --all --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "multi dry run failed: {stderr}");
    assert!(stdout.contains("No candidate repos found."));
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
}

#[test]
fn init_dry_run_of_a_malformed_dotenv_writes_nothing_and_hides_the_value() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={CANARY}\nBROKEN_RECORD\n"),
    )
    .unwrap();
    let before = snapshot(dir.path());
    let output = phantom(dir.path())
        .args(["init", "--dry-run"])
        .output()
        .expect("run init --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(!output.status.success(), "malformed dotenv must fail");
    assert!(stderr.contains("malformed"), "{stderr}");
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
}

#[test]
fn add_dry_run_after_init_does_not_read_or_print_a_value_or_mutate() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={CANARY}\nPORT=3000\n"),
    )
    .unwrap();
    let init = phantom(dir.path())
        .args(["init", "--from", ".env"])
        .output()
        .expect("run init");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let before = snapshot(dir.path());

    let output = phantom(dir.path())
        .args(["add", "NEW_SERVICE_TOKEN", "--dry-run"])
        .output()
        .expect("run add --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "add dry run failed: {stderr}");
    assert!(stdout.contains("Would add 1 key(s):"));
    assert!(stdout.contains("  + NEW_SERVICE_TOKEN"));
    assert!(stdout.contains("would add NEW_SERVICE_TOKEN (vault state not checked in dry run)"));
    assert_eq!(
        planned_files(&stdout),
        vec![".env".to_string(), ".phantom.toml".to_string()]
    );
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
}

#[test]
fn add_dry_run_refuses_a_positional_value_without_printing_it_or_writing() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("PORT=3000\nOPENAI_API_KEY={CANARY}\n"),
    )
    .unwrap();
    let before = snapshot(dir.path());
    let output = phantom(dir.path())
        .args(["add", "OPENAI_API_KEY", CANARY, "--dry-run"])
        .output()
        .expect("run add --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(!output.status.success(), "positional value must be refused");
    assert!(stderr.contains("Positional secret values are disabled"));
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
    assert!(!dir.path().join(".phantom.toml").exists());
}

#[test]
fn add_dry_run_on_an_uninitialized_project_writes_nothing() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={CANARY}\n"),
    )
    .unwrap();
    let before = snapshot(dir.path());
    let output = phantom(dir.path())
        .args(["add", "OPENAI_API_KEY", "--dry-run"])
        .output()
        .expect("run add --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(!output.status.success(), "uninitialized add must fail");
    assert!(stderr.contains("not initialized"));
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
}

#[test]
fn remove_dry_run_after_init_leaves_the_vault_and_dotenv_in_place() {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={CANARY}\nPORT=3000\n"),
    )
    .unwrap();
    let init = phantom(dir.path())
        .args(["init", "--from", ".env"])
        .output()
        .expect("run init");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let before = snapshot(dir.path());
    let vault_before: Vec<_> = before
        .keys()
        .filter(|path| path.ends_with(".vault"))
        .cloned()
        .collect();
    assert!(!vault_before.is_empty(), "init should create a vault file");

    let output = phantom(dir.path())
        .args(["remove", "OPENAI_API_KEY", "--dry-run"])
        .output()
        .expect("run remove --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "remove dry run failed: {stderr}");
    assert!(stdout.contains("Would remove 1 key(s):"));
    assert!(stdout.contains("  - OPENAI_API_KEY"));
    assert!(stdout.contains("would remove OPENAI_API_KEY (vault state not checked in dry run)"));
    assert_eq!(
        planned_files(&stdout),
        vec![".env".to_string(), ".phantom.toml".to_string()]
    );
    assert!(!stdout.contains("DIGEST"));
    assert_values_absent(&stdout, &stderr);
    let after = snapshot(dir.path());
    assert_unchanged(&before, &after);
    for path in vault_before {
        assert_eq!(before.get(&path), after.get(&path), "vault bytes changed");
    }
}

#[test]
fn snapshot_records_empty_directories_lock_files_and_dotfiles() {
    let dir = common::canonical_tempdir();
    fs::create_dir(dir.path().join("empty-meta")).unwrap();
    fs::write(dir.path().join(".hidden-lock"), b"dot").unwrap();
    fs::write(dir.path().join("project.lock"), b"lock").unwrap();
    let shot = snapshot(dir.path());
    assert!(
        shot.contains_key("empty-meta/"),
        "empty directories must be recorded"
    );
    assert_eq!(
        shot.get(".hidden-lock").map(Vec::as_slice),
        Some(b"dot".as_slice())
    );
    assert_eq!(
        shot.get("project.lock").map(Vec::as_slice),
        Some(b"lock".as_slice())
    );
    assert!(shot.get("empty-meta/").unwrap().is_empty());
}

#[test]
fn add_and_remove_dry_run_with_passphrase_unset_create_no_app_data() {
    let dir = common::canonical_tempdir();
    fs::create_dir(dir.path().join("empty-meta")).unwrap();
    fs::write(dir.path().join(".hidden-lock"), b"dot").unwrap();
    fs::write(dir.path().join("project.lock"), b"lock").unwrap();
    fs::write(dir.path().join(".env"), "PORT=3000\n").unwrap();
    phantom_core::config::PhantomConfig::new_with_defaults(
        phantom_core::config::PhantomConfig::project_id_from_path(dir.path()),
    )
    .save(&dir.path().join(".phantom.toml"))
    .unwrap();
    let before = snapshot(dir.path());
    assert!(before.contains_key("empty-meta/"));
    assert!(before.contains_key(".hidden-lock"));
    assert!(before.contains_key("project.lock"));

    for (verb, name) in [("add", "NEW_SERVICE_TOKEN"), ("remove", "OPENAI_API_KEY")] {
        let output = phantom_unset(dir.path())
            .args([verb, name, "--dry-run"])
            .output()
            .expect("run dry-run");
        let (stdout, stderr) = text(&output);
        assert!(output.status.success(), "{verb} dry run failed: {stderr}");
        assert!(stdout.contains(&format!(
            "would {verb} {name} (vault state not checked in dry run)"
        )));
        assert!(!stderr.contains("OS keychain"), "{stderr}");
        assert!(!stderr.contains("passphrase"), "{stderr}");
        assert_values_absent(&stdout, &stderr);
        assert_unchanged(&before, &snapshot(dir.path()));
        assert!(!dir.path().join("xdg-data").exists());
        assert!(!dir.path().join("xdg-config").exists());
        assert!(!dir.path().join("xdg-state").exists());
        assert!(!dir.path().join("xdg-cache").exists());
    }
}

#[test]
fn init_dry_run_reports_existing_claude_files_as_may_update() {
    let dir = common::canonical_tempdir();
    fs::create_dir(dir.path().join(".claude")).unwrap();
    fs::write(
        dir.path().join(".claude/settings.local.json"),
        "{\"theme\":\"dark\"}\n",
    )
    .unwrap();
    fs::write(dir.path().join(".mcp.json"), "{}\n").unwrap();
    fs::write(
        dir.path().join(".env"),
        format!("OPENAI_API_KEY={CANARY}\n"),
    )
    .unwrap();
    let before = snapshot(dir.path());
    let output = phantom(dir.path())
        .args(["init", "--dry-run"])
        .output()
        .expect("run init --dry-run");
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "init dry run failed: {stderr}");
    assert!(stdout.contains("may update .claude/settings.local.json"));
    assert!(stdout.contains("may update .mcp.json"));
    let files = planned_files(&stdout);
    assert!(
        !files
            .iter()
            .any(|path| path.contains("settings.local.json")),
        "{files:?}"
    );
    assert!(
        !files.iter().any(|path| path.ends_with(".mcp.json")),
        "{files:?}"
    );
    assert!(files.iter().any(|path| path.ends_with(".vault")));
    assert_values_absent(&stdout, &stderr);
    assert_unchanged(&before, &snapshot(dir.path()));
}
