use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("HOME", dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", "test-passphrase");
    cmd
}

#[test]
fn doctor_warns_on_risky_phantom_config() {
    let dir = TempDir::new().unwrap();
    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(dir.path());
    fs::write(
        dir.path().join(".phantom.toml"),
        format!(
            r#"
[phantom]
version = "1"
project_id = "{project_id}"

[services.openai]
secret_key = "OPENAI_API_KEY"
pattern = "attacker.example.com"
header = "Authorization"
header_format = "Bearer {{secret}}"
secret_type = "api_key"
"#
        ),
    )
    .expect("write .phantom.toml");
    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=phm_test\n").expect("write .env");
    fs::write(dir.path().join(".gitignore"), ".env\n").expect("write .gitignore");
    fs::write(dir.path().join(".env.example"), "OPENAI_API_KEY=<secret>\n")
        .expect("write .env.example");

    let output = phantom(&dir).arg("doctor").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("Service route `openai`")
            && stdout.contains("OPENAI_API_KEY")
            && stdout.contains("issue(s) found"),
        "doctor should warn on risky service route, got: {stdout}"
    );
}

#[test]
fn doctor_passes_service_routes_for_default_config() {
    let dir = TempDir::new().unwrap();
    let config = phantom_core::config::PhantomConfig::new_with_defaults(
        phantom_core::config::PhantomConfig::project_id_from_path(dir.path()),
    );
    fs::write(
        dir.path().join(".phantom.toml"),
        toml::to_string_pretty(&config).unwrap(),
    )
    .expect("write .phantom.toml");
    fs::write(dir.path().join(".env"), "OPENAI_API_KEY=phm_test\n").expect("write .env");
    fs::write(dir.path().join(".gitignore"), ".env\n").expect("write .gitignore");
    fs::write(dir.path().join(".env.example"), "OPENAI_API_KEY=<secret>\n")
        .expect("write .env.example");

    let output = phantom(&dir).arg("doctor").assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("Service routes look safe"),
        "doctor should pass default service routes, got: {stdout}"
    );
}
