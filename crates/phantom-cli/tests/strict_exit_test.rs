//! `--strict` is opt-in for `phantom doctor` and `phantom why`.
//! Without it, the pinned exit codes stay. With it, doctor exits 1 when the
//! report has any issue, and why exits 1 when the key is missing or not
//! protected. The printed report stays the same either way.
mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::process::Output;

const KEY: &str = "OPENAI_API_KEY";
const CANARY: &str = "sk-strict-exit-canary-7f3a9c1e5b";
const TOKEN: &str = "phm_strictplaceholdertokenvalue";

fn phantom(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("PHANTOM_VAULT_PASSPHRASE", "test-passphrase-strict-exit")
        .env("NO_COLOR", "1")
        .env_remove("PHANTOM_AUDIT")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .expect("run phantom")
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("process exited by signal")
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn assert_canary_absent(output: &Output) {
    let (stdout, stderr) = text(output);
    assert!(
        !stdout.contains(CANARY),
        "stdout contained the planted value"
    );
    assert!(
        !stderr.contains(CANARY),
        "stderr contained the planted value"
    );
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn unprotected_project() -> tempfile::TempDir {
    let dir = common::canonical_tempdir();
    fs::write(
        dir.path().join(".env"),
        format!("{KEY}={CANARY}\nPORT=3000\n"),
    )
    .unwrap();
    dir
}

#[test]
fn doctor_strict_exits_on_issues_for_human_and_json_and_keeps_the_report() {
    let dir = unprotected_project();
    let human = phantom(dir.path(), &["doctor"]);
    let human_strict = phantom(dir.path(), &["doctor", "--strict"]);
    let json = phantom(dir.path(), &["doctor", "--json"]);
    let json_strict = phantom(dir.path(), &["doctor", "--json", "--strict"]);
    let global_json = phantom(dir.path(), &["--json", "doctor", "--strict"]);

    assert_eq!(code(&human), 0);
    assert_eq!(code(&human_strict), 1);
    assert_eq!(code(&json), 0);
    assert_eq!(code(&json_strict), 1);
    assert_eq!(code(&global_json), 1);
    assert_eq!(text(&human).0, text(&human_strict).0);
    assert_eq!(text(&json).0, text(&json_strict).0);
    assert_eq!(text(&json_strict).0, text(&global_json).0);

    let report = json_stdout(&json_strict);
    assert_eq!(report["schema"], "phantom.doctor.v1");
    assert_eq!(report["ok"], false);
    assert!(report["issues"].as_u64().unwrap() > 0);
    for output in [&human, &human_strict, &json, &json_strict, &global_json] {
        assert_canary_absent(output);
    }
}

#[test]
fn doctor_strict_keeps_exit_zero_when_the_report_has_no_issues() {
    let dir = common::canonical_tempdir();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(dir.path())
        .status()
        .unwrap()
        .success());
    let project_id = phantom_core::config::PhantomConfig::project_id_from_path(dir.path());
    let config = phantom_core::config::PhantomConfig::new_with_defaults(project_id);
    fs::write(
        dir.path().join(".phantom.toml"),
        toml::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    fs::write(dir.path().join(".env"), format!("{KEY}={TOKEN}\n")).unwrap();

    let mut issues = 1;
    for _ in 0..5 {
        let output = phantom(dir.path(), &["doctor", "--fix", "--json"]);
        assert_eq!(code(&output), 0, "doctor --fix should keep exit 0");
        issues = json_stdout(&output)["issues"].as_u64().unwrap();
        if issues == 0 {
            break;
        }
    }
    assert_eq!(issues, 0, "doctor --fix did not reach a clean report");

    for args in [
        &["doctor"][..],
        &["doctor", "--strict"][..],
        &["doctor", "--json"][..],
        &["doctor", "--json", "--strict"][..],
    ] {
        let output = phantom(dir.path(), args);
        assert_eq!(code(&output), 0, "{args:?}");
        assert_canary_absent(&output);
    }
    let report = json_stdout(&phantom(dir.path(), &["doctor", "--json", "--strict"]));
    assert_eq!(report["ok"], true);
    assert_eq!(report["issues"], 0);
}

#[test]
fn why_strict_exits_when_the_key_is_unprotected_and_stays_quiet_about_the_value() {
    let dir = unprotected_project();
    let human = phantom(dir.path(), &["why", KEY]);
    let human_strict = phantom(dir.path(), &["why", KEY, "--strict"]);
    let json = phantom(dir.path(), &["why", KEY, "--json"]);
    let json_strict = phantom(dir.path(), &["why", "--json", KEY, "--strict"]);
    let global_json = phantom(dir.path(), &["--json", "why", KEY, "--strict"]);

    assert_eq!(code(&human), 0);
    assert_eq!(code(&human_strict), 1);
    assert_eq!(code(&json), 0);
    assert_eq!(code(&json_strict), 1);
    assert_eq!(code(&global_json), 1);
    assert_eq!(text(&human).0, text(&human_strict).0);
    assert_eq!(text(&json).0, text(&json_strict).0);
    assert_eq!(text(&json_strict).0, text(&global_json).0);

    let report = json_stdout(&json_strict);
    assert_eq!(report["schema"], "phantom.why.v1");
    assert_eq!(report["key"], KEY);
    assert_eq!(report["found"], true);
    assert_eq!(report["protected"], false);
    for output in [&human, &human_strict, &json, &json_strict, &global_json] {
        assert_canary_absent(output);
    }
}

#[test]
fn why_strict_exits_when_the_key_is_missing_without_changing_the_json_report() {
    let dir = unprotected_project();
    let human = phantom(dir.path(), &["why", "MISSING_KEY"]);
    let human_strict = phantom(dir.path(), &["why", "MISSING_KEY", "--strict"]);
    let json = phantom(dir.path(), &["why", "MISSING_KEY", "--json"]);
    let json_strict = phantom(dir.path(), &["why", "MISSING_KEY", "--json", "--strict"]);

    assert_ne!(code(&human), 0);
    assert_ne!(code(&human_strict), 0);
    assert_eq!(code(&json), 0);
    assert_eq!(code(&json_strict), 1);
    assert_eq!(text(&human).1, text(&human_strict).1);
    assert_eq!(text(&json).0, text(&json_strict).0);
    let report = json_stdout(&json_strict);
    assert_eq!(report["found"], false);
    assert_eq!(report["protected"], false);
    for output in [&human, &human_strict, &json, &json_strict] {
        assert_canary_absent(output);
    }
}

#[test]
fn why_strict_keeps_exit_zero_when_the_key_is_protected() {
    let dir = common::canonical_tempdir();
    fs::write(dir.path().join(".env"), format!("{KEY}={TOKEN}\n")).unwrap();

    for args in [
        &["why", KEY][..],
        &["why", KEY, "--strict"][..],
        &["why", KEY, "--json"][..],
        &["why", KEY, "--json", "--strict"][..],
    ] {
        let output = phantom(dir.path(), args);
        assert_eq!(code(&output), 0, "{args:?}");
        let (stdout, stderr) = text(&output);
        assert!(!stdout.contains(TOKEN), "{args:?} printed the token");
        assert!(!stderr.contains(TOKEN), "{args:?} printed the token");
    }
    let report = json_stdout(&phantom(dir.path(), &["why", KEY, "--json", "--strict"]));
    assert_eq!(report["protected"], true);
    assert_eq!(report["found"], true);
}

#[test]
fn strict_is_named_in_doctor_and_why_help() {
    let dir = common::canonical_tempdir();
    let doctor = phantom(dir.path(), &["doctor", "--help"]);
    let why = phantom(dir.path(), &["why", "--help"]);
    assert_eq!(code(&doctor), 0);
    assert_eq!(code(&why), 0);
    let doctor_help = text(&doctor).0;
    let why_help = text(&why).0;
    assert!(doctor_help.contains("--strict"));
    assert!(doctor_help.contains("any issue"));
    assert!(why_help.contains("--strict"));
    assert!(why_help.contains("not protected"));
    let rejected = phantom(dir.path(), &["doctor", "--strict", "--pq"]);
    assert_ne!(code(&rejected), 0);
}
