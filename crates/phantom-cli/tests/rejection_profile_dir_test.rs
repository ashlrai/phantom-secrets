//! Argument- and context-level rejections (`phantom add`, `phantom remove`)
//! must leave the project tree and the machine profile untouched: a refused
//! invocation creates no `.phantom.toml`, `.env`, vault, lock, or app-data
//! files. The profile is isolated to a second temporary directory — the
//! Windows Known-Folder resolver requires its AppData folders to exist, so
//! under an unisolated profile they would land inside the project tree.
mod common;

use assert_cmd::Command;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-rejection-profile";

fn phantom(project: &TempDir, home: &TempDir) -> Command {
    common::phantom_with_home(project, home, VAULT_PASS)
}

fn init_project(project: &TempDir, home: &TempDir) {
    fs::write(project.path().join(".env"), "SEED_SECRET=sk-seed-value\n").expect("write seed .env");
    phantom(project, home)
        .args(["init", "--from", ".env"])
        .assert()
        .success();
}

/// Recursive content snapshot of a directory tree: relative path (a trailing
/// `/` marks directories; a symlink maps to its target text) to file bytes.
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
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
            let file_type = fs::symlink_metadata(&path)
                .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
                .file_type();
            if file_type.is_symlink() {
                let target = fs::read_link(&path).expect("read link");
                files.insert(relative, target.to_string_lossy().into_owned().into_bytes());
            } else if file_type.is_dir() {
                files.insert(format!("{relative}/"), Vec::new());
                walk(root, &path, files);
            } else {
                let bytes = fs::read(&path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
                files.insert(relative, bytes);
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
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
        "rejected invocation changed the project or profile tree: {changes:?}"
    );
}

/// Run an invocation expected to fail and assert the profile tree it saw is
/// unchanged. The baseline snapshot is taken after command construction,
/// which is when the Windows AppData folders are prepared.
fn run_rejected(
    project: &TempDir,
    home: &TempDir,
    args: &[&str],
    stdin: &str,
) -> std::process::Output {
    let mut command = phantom(project, home);
    let home_before = snapshot(home.path());
    let output = command
        .args(args)
        .write_stdin(stdin.to_string())
        .output()
        .expect("run phantom");
    assert!(!output.status.success(), "expected a rejection: {output:?}");
    assert_unchanged(&home_before, &snapshot(home.path()));
    output
}

#[test]
fn positional_value_rejection_leaves_project_and_profile_dirs_untouched() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();

    let output = run_rejected(
        &project,
        &home,
        &["add", "UNSAFE_KEY", "secret-in-argv"],
        "",
    );

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Positional secret values are disabled")
    );
    assert!(snapshot(project.path()).is_empty());
}

#[test]
fn invalid_name_rejection_leaves_project_and_profile_dirs_untouched() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();

    let output = run_rejected(
        &project,
        &home,
        &["add", "BAD-NAME", "--stdin"],
        "some-value\n",
    );

    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid secret name"));
    assert!(snapshot(project.path()).is_empty());
}

#[test]
fn uninitialized_add_rejection_leaves_project_and_profile_dirs_untouched() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();

    let output = run_rejected(
        &project,
        &home,
        &["add", "SOME_KEY", "--stdin"],
        "some-value\n",
    );

    assert!(String::from_utf8_lossy(&output.stderr).contains("phantom init --empty"));
    assert!(snapshot(project.path()).is_empty());
}

#[test]
fn flag_conflict_rejection_leaves_project_and_profile_dirs_untouched() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();

    for args in [
        ["add", "KEY", "--generate", "--stdin"].as_slice(),
        ["add"].as_slice(),
    ] {
        run_rejected(&project, &home, args, "");
    }

    assert!(snapshot(project.path()).is_empty());
}

/// A piped `phantom add KEY` (no `--stdin`) is refused before the vault is
/// opened: opening it takes project locks and creates app-data directories,
/// so the non-terminal refusal must not leave profile files behind.
#[test]
fn non_tty_add_rejection_creates_no_profile_files() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    init_project(&project, &home);
    let project_before = snapshot(project.path());

    let output = run_rejected(&project, &home, &["add", "SOME_KEY"], "ignored\n");

    assert!(String::from_utf8_lossy(&output.stderr).contains("stdin is not a terminal"));
    assert_unchanged(&project_before, &snapshot(project.path()));
}

/// A headless `phantom remove` is refused before the vault is opened for the
/// same reason: the confirmation ceremony needs all three terminals, so the
/// refusal happens before vault state is touched.
#[test]
fn headless_remove_rejection_creates_no_profile_files() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    init_project(&project, &home);
    phantom(&project, &home)
        .args(["add", "MY_KEY", "--stdin"])
        .write_stdin("my-value\n")
        .assert()
        .success();
    let project_before = snapshot(project.path());

    let output = run_rejected(&project, &home, &["remove", "MY_KEY"], "");

    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("requires attached stdin, stdout, and stderr terminals"));
    assert_unchanged(&project_before, &snapshot(project.path()));
}

/// A value-content rejection (`--stdin` carrying no usable bytes) opens the
/// vault first: the existing-name check intentionally precedes the read, and
/// opening an existing vault changes nothing. The project tree must still be
/// untouched.
#[test]
fn stdin_content_rejection_writes_no_project_files() {
    let project = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    init_project(&project, &home);
    let project_before = snapshot(project.path());

    let output = run_rejected(&project, &home, &["add", "EMPTY_KEY", "--stdin"], "\n");

    assert!(String::from_utf8_lossy(&output.stderr).contains("empty value"));
    assert_unchanged(&project_before, &snapshot(project.path()));
}
