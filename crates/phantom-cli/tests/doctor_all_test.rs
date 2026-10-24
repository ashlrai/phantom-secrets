//! `phantom doctor --all` is one read-only, value-free report.

use assert_cmd::Command;

fn run(home: &std::path::Path, cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env("OPENAI_BASE_URL", "http://user:hunter2@127.0.0.1:4000/v1")
        .env("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        .env_remove("OLLAMA_HOST")
        .current_dir(cwd)
        .args(["doctor", "--all"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn json_has_every_section_and_no_url() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let out = run(home.path(), cwd.path(), &["--json"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).expect("one JSON document");
    for key in ["health", "pq", "agent_readiness", "agent_status", "gateway"] {
        assert!(v.get(key).is_some(), "missing {key}");
    }
    let vars = v["gateway"]["vars"].as_array().unwrap();
    let class = |name: &str| {
        vars.iter().find(|x| x["name"] == name).unwrap()["class"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(class("OPENAI_BASE_URL"), "loopback");
    assert_eq!(class("ANTHROPIC_BASE_URL"), "non_loopback");
    assert_eq!(class("OLLAMA_HOST"), "unset");
    assert!(!text.contains("hunter2"));
    assert!(!text.contains("4000"));
}

#[test]
fn writes_nothing_under_home_and_human_output_works() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let out = run(home.path(), cwd.path(), &[]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Phantom doctor (combined, read-only)"));
    assert!(!text.contains("hunter2"));
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn conflicts_with_fix_and_pq() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    for flag in ["--fix", "--pq"] {
        let out = run(home.path(), cwd.path(), &[flag]);
        assert!(!out.status.success(), "{flag}");
    }
}
