//! `NAME=secret://NAME` launcher references (docs/design/builtin-vault.md).
//!
//! The canary is synthetic, built at runtime, and shaped so no credential
//! detector matches it. Assertions never print captured output or the canary.
#![cfg(unix)]

mod common;

use std::path::Path;
use std::process::{Command, Output, Stdio};

const NAME: &str = "OPENAI_API_KEY";
const ANCHOR: &str = "ANCHOR_KEY";

struct Fixture {
    project: tempfile::TempDir,
    home: tempfile::TempDir,
    canary: String,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            project: common::canonical_tempdir(),
            home: common::canonical_tempdir(),
            canary: [
                "synthetic",
                "ref",
                "canary",
                &std::process::id().to_string(),
            ]
            .join("_"),
        };
        let init = fixture
            .command()
            .args(["init", "--empty"])
            .output()
            .unwrap();
        assert!(init.status.success(), "fixture init failed");
        fixture.add(NAME, &fixture.canary);
        fixture.add(ANCHOR, "synthetic_anchor_fixture");
        // `add` maps each name in the managed dotenv. Drop the referenced
        // name's mapping so the launcher reference is the only thing that
        // protects it; the anchor keeps the dotenv token-bearing.
        let dotenv = fixture.project.path().join(".env");
        let kept: String = std::fs::read_to_string(&dotenv)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with(&format!("{NAME}=")))
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&dotenv, kept).unwrap();
        fixture
    }

    fn add(&self, name: &str, value: &str) {
        use std::io::Write;
        let mut add = self
            .command()
            .args(["add", name, "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        writeln!(add.stdin.take().unwrap(), "{value}").unwrap();
        assert!(add.wait().unwrap().success(), "fixture add failed");
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_phantom"));
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env("PHANTOM_AUDIT", "required")
            .env("PHANTOM_VAULT_PASSPHRASE", "synthetic-ref-unlock-phrase")
            .current_dir(self.project.path());
        command
    }

    fn exec_env(&self, assignments: &[(&str, &str)]) -> Output {
        let mut command = self.command();
        command.args(["exec", "--", "env"]);
        for (key, value) in assignments {
            command.env(key, value);
        }
        command.output().unwrap()
    }

    fn audit_log(&self) -> Vec<u8> {
        std::fs::read(self.home.path().join(".phantom").join("audit.log")).unwrap_or_default()
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Every regular file under `root` (vault ciphertext included) is free of the canary.
fn tree_is_free_of(root: &Path, needle: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return true;
    };
    entries.flatten().all(|entry| {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => tree_is_free_of(&path, needle),
            Ok(kind) if kind.is_file() => !contains(&std::fs::read(&path).unwrap(), needle),
            _ => true,
        }
    })
}

fn assert_value_free(fixture: &Fixture, output: &Output) {
    let canary = fixture.canary.as_str();
    assert!(
        !contains(&output.stdout, canary),
        "stdout disclosed the canary"
    );
    assert!(
        !contains(&output.stderr, canary),
        "stderr disclosed the canary"
    );
    assert!(
        !contains(&fixture.audit_log(), canary),
        "audit log disclosed the canary"
    );
    assert!(
        tree_is_free_of(fixture.home.path(), canary),
        "a file under HOME disclosed the canary"
    );
    assert!(
        tree_is_free_of(fixture.project.path(), canary),
        "a project file disclosed the canary"
    );
}

#[test]
fn reference_reaches_the_child_only_as_a_session_token() {
    let fixture = Fixture::new();
    let reference = format!("secret://{NAME}");
    let output = fixture.exec_env(&[(NAME, reference.as_str())]);
    assert!(
        output.status.success(),
        "exec with a valid reference failed"
    );
    assert_value_free(&fixture, &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with(&format!("{NAME}=")))
        .expect("child did not receive the referenced variable");
    let token = &line[NAME.len() + 1..];
    assert!(
        token.starts_with("phm_"),
        "child value is not a session token"
    );
    assert!(
        !contains(&output.stdout, "secret://"),
        "reference leaked to the child"
    );

    let audit = fixture.audit_log();
    assert!(
        contains(&audit, "exec.secret_ref"),
        "no per-use audit event"
    );
    assert!(
        contains(&audit, NAME),
        "audit event does not name the secret"
    );
}

#[test]
fn refusals_name_the_variable_and_never_the_value() {
    let fixture = Fixture::new();
    let cases: &[(&str, &str, &str)] = &[
        (NAME, "secret://", "malformed"),
        (NAME, "secret://bad-name", "malformed"),
        (
            "OTHER_VAR",
            "secret://OPENAI_API_KEY",
            "different secret name",
        ),
        ("PHANTOM_X", "secret://PHANTOM_X", "reserved"),
        ("MISSING_KEY", "secret://MISSING_KEY", "MISSING_KEY"),
    ];
    for (key, value, expected) in cases {
        let output = fixture.exec_env(&[(key, value)]);
        assert!(
            !output.status.success(),
            "a refused reference launched the child"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "refusal did not explain itself");
        assert!(stderr.contains(key), "refusal did not name the variable");
        assert_value_free(&fixture, &output);
    }
}

#[test]
fn ordinary_values_pass_through_unchanged() {
    let fixture = Fixture::new();
    let output = fixture.exec_env(&[("PLAIN_SETTING", "not-a-reference")]);
    assert!(output.status.success(), "exec without references failed");
    assert!(contains(&output.stdout, "PLAIN_SETTING=not-a-reference"));
    assert_value_free(&fixture, &output);
}
