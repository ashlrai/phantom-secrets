//! `phantom exec --bind-source` lets a linked git worktree use the custody
//! namespace of its source checkout. It is opt-in and verified: no flag means
//! no binding, and an unrelated repository is refused.
#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VAULT_PASS: &str = "exec-bind-source-integration-passphrase";

fn phantom_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_phantom"))
}

fn phantom_command(dir: &Path, home: &Path) -> Command {
    let mut command = Command::new(phantom_binary());
    command
        .current_dir(dir)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("NO_COLOR", "1")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OPENAI_API_KEY")
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS);
    command
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

fn ok(output: &Output, action: &str) {
    assert!(
        output.status.success(),
        "{action} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Obviously fake key, built at runtime.
fn fake_key() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("sk-{}-{:x}", "fakebindtest", nanos)
}

struct Fixture {
    _root: tempfile::TempDir,
    home: tempfile::TempDir,
    source: PathBuf,
    worktree: PathBuf,
    key: String,
}

fn fixture() -> Fixture {
    let root = common::canonical_tempdir();
    let home = common::canonical_tempdir();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    git(&source, &["init", "-q"]);
    let key = fake_key();
    fs::write(source.join(".env"), format!("OPENAI_API_KEY={key}\n")).unwrap();
    ok(
        &phantom_command(&source, home.path())
            .args(["init", "--from", ".env"])
            .output()
            .unwrap(),
        "phantom init",
    );
    git(&source, &["add", ".phantom.toml"]);
    git(&source, &["commit", "-q", "-m", "init"]);
    let worktree = root.path().join("wt");
    git(
        &source,
        &[
            "worktree",
            "add",
            "-q",
            worktree.to_str().unwrap(),
            "-b",
            "w",
        ],
    );
    Fixture {
        _root: root,
        home,
        source,
        worktree,
        key,
    }
}

fn exec_print_base_url(f: &Fixture, dir: &Path, bind: Option<&Path>) -> Output {
    let mut command = phantom_command(dir, f.home.path());
    command.args(["--quiet", "exec"]);
    if let Some(source) = bind {
        command.arg("--bind-source").arg(source);
    }
    command
        .args([
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"${OPENAI_BASE_URL-}\" \"${OPENAI_API_KEY-}\"",
        ])
        .output()
        .unwrap()
}

#[test]
fn without_opt_in_a_worktree_gets_no_source_custody() {
    let f = fixture();
    let output = exec_print_base_url(&f, &f.worktree, None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("127.0.0.1"),
        "worktree without --bind-source must not reach the source vault: {stdout}"
    );
    assert!(!stdout.contains(&f.key));
}

#[test]
fn bound_worktree_uses_source_custody_without_the_real_value() {
    let f = fixture();
    let output = exec_print_base_url(&f, &f.worktree, Some(&f.source));
    ok(&output, "phantom exec --bind-source");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (base, token) = stdout.split_once('|').unwrap();
    assert!(
        base.contains("127.0.0.1"),
        "expected a proxy base URL: {stdout}"
    );
    assert!(
        token.starts_with("phm_"),
        "expected a phantom token: {stdout}"
    );
    assert!(!stdout.contains(&f.key), "real value reached the child");
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&f.key));
}

#[test]
fn unrelated_repository_is_refused_before_vault_access() {
    let f = fixture();
    let other = f.worktree.parent().unwrap().join("other");
    fs::create_dir(&other).unwrap();
    git(&other, &["init", "-q"]);
    fs::copy(f.source.join(".phantom.toml"), other.join(".phantom.toml")).unwrap();
    let output = exec_print_base_url(&f, &other, Some(&f.source));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("common-dir-mismatch"), "stderr:\n{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn edited_worktree_config_is_refused() {
    let f = fixture();
    let path = f.worktree.join(".phantom.toml");
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(b"\n# edited\n");
    fs::write(&path, bytes).unwrap();
    let output = exec_print_base_url(&f, &f.worktree, Some(&f.source));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("config-mismatch"));
}
