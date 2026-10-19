//! Integration tests for `phantom crypto inventory`.
//!
//! The command needs no project, vault, or config, and its JSON must parse
//! and list the registry rows.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path()).env("HOME", dir.path());
    cmd
}

fn parse(out: &[u8]) -> Value {
    serde_json::from_slice(out).expect("inventory output is JSON")
}

#[test]
fn format_json_works_outside_a_project() {
    let dir = TempDir::new().unwrap();
    let out = phantom(&dir)
        .args(["crypto", "inventory", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v = parse(&out);
    assert_eq!(v["kind"], "phantom-crypto-inventory");
    let names: Vec<&str> = v["algorithms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    for expected in ["chacha20-poly1305", "argon2id", "ed25519", "xwing"] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
    assert!(!dir.path().join(".phantom.toml").exists());
}

#[test]
fn global_json_flag_matches_format_json() {
    let dir = TempDir::new().unwrap();
    let a = phantom(&dir)
        .args(["crypto", "inventory", "--format", "json"])
        .output()
        .unwrap();
    let b = phantom(&dir)
        .args(["--json", "crypto", "inventory"])
        .output()
        .unwrap();
    assert!(a.status.success() && b.status.success());
    assert_eq!(parse(&a.stdout), parse(&b.stdout));
}

#[test]
fn default_text_output_is_a_table() {
    let dir = TempDir::new().unwrap();
    let out = phantom(&dir)
        .args(["crypto", "inventory"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("Algorithms\n"));
    assert!(text.contains("Format tags"));
    assert!(text.contains("blob-v2"));
}
