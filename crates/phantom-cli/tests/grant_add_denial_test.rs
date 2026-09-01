mod common;

use assert_cmd::Command;
use std::fs;

#[test]
fn grant_add_denies_before_project_env_or_side_effect_access() {
    let project = common::canonical_tempdir();
    let sentinel = project.path().join("sentinel.txt");
    fs::write(&sentinel, "unchanged").expect("write sentinel");

    let assertion = Command::cargo_bin("phantom")
        .expect("phantom binary")
        .current_dir(project.path())
        .env("CLIENT_SECRET_SENTINEL", "must-never-be-read")
        .args([
            "grant",
            "add",
            "vercel-integration",
            "--client-id",
            "client-id",
            "--client-secret-env",
            "CLIENT_SECRET_SENTINEL",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    assert!(stderr.contains("disabled in shipped 0.7.4"), "{stderr}");
    assert!(stderr.contains("No enrollment or local state change occurred"));
    assert!(!stderr.contains("must-never-be-read"));
    assert!(!stderr.contains("No .phantom.toml"));
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "unchanged");
    assert_eq!(fs::read_dir(project.path()).unwrap().count(), 1);
}

#[test]
fn grant_add_invalid_provider_still_hits_same_early_boundary() {
    let project = common::canonical_tempdir();
    let assertion = Command::cargo_bin("phantom")
        .expect("phantom binary")
        .current_dir(project.path())
        .args(["grant", "add", "unsupported-provider"])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    assert!(stderr.contains("disabled in shipped 0.7.4"), "{stderr}");
    assert!(!stderr.contains("unknown provider"));
    assert_eq!(fs::read_dir(project.path()).unwrap().count(), 0);
}
