//! Keep the documented curl recipe executable without provider or vault access.
#![cfg(unix)]

#[test]
fn github_box_runner_offline_contract() {
    let home = tempfile::tempdir().unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/github-box-runner/test_github.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .output()
        .expect("Python 3 is required for the GitHub box runner example contract");
    assert!(
        output.status.success(),
        "GitHub example contract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
