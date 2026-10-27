//! Local generation must never bypass the trusted-terminal boundary.
use std::process::Command;

#[test]
fn local_generation_and_rollback_refuse_agent_stdio_before_opening_a_vault() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    for args in [
        vec!["rotate", "LOCAL_SECRET", "--generate"],
        vec!["rotate", "--name", "LOCAL_SECRET", "--rollback"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
            .args(args)
            .current_dir(project.path())
            .env("HOME", home.path())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("attached"));
        assert!(output.stdout.is_empty());
        assert!(!home.path().join(".phantom").exists());
    }
}

#[test]
fn generation_rejects_incompatible_modes() {
    let home = tempfile::tempdir().unwrap();
    for suffix in ["--sync", "--batch", "--shadow", "--rollback"] {
        let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
            .args(["rotate", "LOCAL_SECRET", "--generate", suffix])
            .env("HOME", home.path())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
