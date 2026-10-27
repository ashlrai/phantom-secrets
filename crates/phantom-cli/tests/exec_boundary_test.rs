//! Exercise both launch paths without emitting argument or environment values.
#![cfg(unix)]

mod common;

use std::process::{Command, Output};

struct Project {
    project: tempfile::TempDir,
    home: tempfile::TempDir,
}

impl Project {
    fn new(proxied: bool) -> Self {
        let fixture = Self {
            project: common::canonical_tempdir(),
            home: common::canonical_tempdir(),
        };
        if proxied {
            std::fs::write(
                fixture.project.path().join(".env"),
                "OPENAI_API_KEY=synthetic-exec-boundary-fixture\n",
            )
            .unwrap();
            let output = fixture
                .command()
                .args(["init", "--from", ".env"])
                .output()
                .unwrap();
            assert!(output.status.success(), "fixture initialization failed");
        } else {
            // A direct launch needs initialized config without protected state.
            let config = phantom_core::config::PhantomConfig::new_with_defaults(
                phantom_core::config::PhantomConfig::project_id_from_path(fixture.project.path()),
            );
            config
                .save(&fixture.project.path().join(".phantom.toml"))
                .unwrap();
            std::fs::write(fixture.project.path().join(".env"), "APP_MODE=test\n").unwrap();
        }
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_phantom"));
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env(
                "PHANTOM_VAULT_PASSPHRASE",
                "synthetic-boundary-unlock-phrase",
            )
            .current_dir(self.project.path());
        command
    }
}

fn assert_no_value(output: &Output, value: &str) {
    // Never include captured output or the canary in assertion diagnostics.
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !stream
                .windows(value.len())
                .any(|window| window == value.as_bytes()),
            "exec disclosed a synthetic canary"
        );
    }
}

#[test]
fn argv_is_preserved_without_progress_disclosing_values() {
    for proxied in [false, true] {
        let fixture = Project::new(proxied);
        // Build synthetic values at runtime; no credential or mapping is needed.
        let canary = ["sk", "synthetic boundary; $(exit 99)\nsecond line"].join("-");
        let assignment = format!("--api-key={canary}");
        let output = fixture.command()
            .args(["exec", "--", "/bin/sh", "-c"])
            .arg(r#"[ "$#" -eq 4 ] && [ "$1" = "$EXPECTED" ] && [ "$2" = "--api-key=$EXPECTED" ] && [ -z "$3" ] && [ "$4" = 'literal * space' ]"#)
            .arg("boundary-child")
            .args([canary.as_str(), assignment.as_str(), "", "literal * space"])
            .env("EXPECTED", &canary)
            .output().unwrap();
        assert_no_value(&output, &canary);
        assert!(output.status.success(), "argument boundaries changed");
    }
}

#[test]
fn child_environment_scrubs_credentials_and_preserves_ordinary_inheritance() {
    for proxied in [false, true] {
        let fixture = Project::new(proxied);
        let output = fixture.command()
            .env("APP_MODE", "inherited")
            .env("OPENAI_API_KEY", "synthetic-ambient-value")
            .env("ANTHROPIC_BASE_URL", "synthetic-stale-route")
            .env("PHANTOM_PROXY_TOKEN", "synthetic-stale-bearer")
            .env("PHANTOM_PROXY_PORT", "stale-port")
            .env("PHANTOM_SESSION_KEYS", "STALE_KEY")
            .args(["exec", "--", "/bin/sh", "-c"])
            .arg(if proxied {
                r#"[ "$APP_MODE" = inherited ] && [ -z "${PHANTOM_VAULT_PASSPHRASE+x}" ] && [ -z "${ANTHROPIC_BASE_URL+x}" ] && [ "$OPENAI_API_KEY" != synthetic-ambient-value ] && [ -n "$OPENAI_API_KEY" ] && [ "$PHANTOM_PROXY_TOKEN" != synthetic-stale-bearer ] && [ -n "$PHANTOM_PROXY_TOKEN" ] && [ "$PHANTOM_PROXY_PORT" != stale-port ] && [ "$PHANTOM_SESSION_KEYS" = OPENAI_API_KEY ]"#
            } else {
                r#"[ "$APP_MODE" = inherited ] && [ -z "${PHANTOM_VAULT_PASSPHRASE+x}" ] && [ -z "${OPENAI_API_KEY+x}" ] && [ -z "${ANTHROPIC_BASE_URL+x}" ] && [ -z "${PHANTOM_PROXY_TOKEN+x}" ] && [ -z "${PHANTOM_PROXY_PORT+x}" ] && [ -z "${PHANTOM_SESSION_KEYS+x}" ]"#
            })
            .output().unwrap();
        for canary in [
            "synthetic-ambient-value",
            "synthetic-stale-bearer",
            "synthetic-boundary-unlock-phrase",
        ] {
            assert_no_value(&output, canary);
        }
        assert!(output.status.success(), "child environment policy changed");
    }
}

#[test]
fn both_launch_paths_preserve_exit_codes_and_signal_statuses() {
    for proxied in [false, true] {
        let fixture = Project::new(proxied);
        for quiet in [false, true] {
            for (script, code) in [
                ("exit 0", 0),
                ("exit 1", 1),
                ("exit 42", 42),
                ("exit 126", 126),
                ("exit 127", 127),
                ("exit 255", 255),
                ("kill -TERM $$", 143),
                ("kill -KILL $$", 137),
            ] {
                let mut command = fixture.command();
                if quiet {
                    command.arg("--quiet");
                }
                let output = command
                    .args(["exec", "--", "/bin/sh", "-c", script])
                    .output()
                    .unwrap();
                assert_eq!(output.status.code(), Some(code), "child status changed");
                assert!(output.stdout.is_empty(), "unexpected stdout");
            }
        }
    }
}

#[test]
fn spawn_failure_does_not_disclose_executable_or_arguments() {
    for proxied in [false, true] {
        let fixture = Project::new(proxied);
        let canary = ["synthetic", "private-executable"].join("-");
        let missing = fixture.project.path().join(&canary);
        for quiet in [false, true] {
            let mut command = fixture.command();
            if quiet {
                command.arg("--quiet");
            }
            let output = command
                .args(["exec", "--"])
                .arg(&missing)
                .arg(&canary)
                .output()
                .unwrap();
            assert_no_value(&output, &canary);
            assert_eq!(output.status.code(), Some(127));
            assert!(String::from_utf8_lossy(&output.stderr).contains("Command not found"));
        }
        std::fs::write(&missing, "exit 0\n").unwrap();
        let output = fixture
            .command()
            .args(["exec", "--"])
            .arg(&missing)
            .output()
            .unwrap();
        assert_no_value(&output, &canary);
        assert_eq!(output.status.code(), Some(126));
    }
}

#[test]
fn json_spawn_failures_preserve_shell_codes_without_diagnostics() {
    for proxied in [false, true] {
        let fixture = Project::new(proxied);
        let private_name = "synthetic-private-launch-path";
        let executable = fixture.project.path().join(private_name);
        for (exists, expected_code) in [(false, 127), (true, 126)] {
            if exists {
                std::fs::write(&executable, "exit 0\n").unwrap();
            }
            for scrub in [false, true] {
                let mut command = fixture.command();
                command.args(["exec", "--json"]);
                if scrub {
                    command.arg("--scrub-output");
                }
                let output = command.args(["--"]).arg(&executable).output().unwrap();
                assert_eq!(output.status.code(), Some(expected_code));
                assert!(output.stdout.is_empty());
                assert_no_value(&output, private_name);
                let report: serde_json::Value = serde_json::from_slice(&output.stderr)
                    .expect("spawn refusal must be one JSON envelope");
                assert_eq!(report["schema"], "phantom.exec.error.v1");
                assert_eq!(report["error"]["code"], "spawn_failed");
            }
        }
    }
}
