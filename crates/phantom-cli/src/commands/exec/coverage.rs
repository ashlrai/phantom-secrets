//! Value-free compatibility checks for direct CLI invocations. This is not
//! command sandboxing: nested shells, scripts and credential helpers are not
//! inspected. A provider route alone cannot adapt an arbitrary CLI protocol.

use anyhow::Result;
use std::collections::HashSet;

const GITHUB_KEYS: &[&str] = &[
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
];

pub(super) fn validate_command(cmd: &[String], protected: &HashSet<String>) -> Result<()> {
    let Some(program) = cmd.first() else {
        return Ok(());
    };
    // Accept explicit paths and Windows launchers without inspecting files or
    // printing caller-controlled arguments (which can contain credentials).
    let basename = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = basename.to_ascii_lowercase();
    let name = [".exe", ".cmd", ".bat"]
        .iter()
        .find_map(|suffix| lower.strip_suffix(suffix))
        .unwrap_or(&lower);
    let args = &cmd[1..];
    // `vercel` with no arguments deploys; it is not a help invocation.
    if (args.is_empty() && !matches!(name, "vercel" | "vc"))
        || (args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h" | "--version" | "-v"))
        || args.first().is_some_and(|arg| arg == "help")
    {
        return Ok(());
    }

    let (keys, reason): (&[&str], &str) = match name {
        "gh" => (
            GITHUB_KEYS,
            "gh does not use GITHUB_TOKEN_BASE_URL; the github_api REST route does not adapt GitHub CLI host selection. Use an explicit curl request to the approved GitHub route for supported API work.",
        ),
        "npm" if !npm_local_script(args) => (
            &[
                "NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_AUTH_TOKEN",
                "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
            ],
            "npm registry authentication needs a registry-scoped adapter; exec has no approved npm registry route. npm run/test/start can still launch scripts that use supported SDK base URLs.",
        ),
        "vercel" | "vc" => (
            &["VERCEL_TOKEN", "VERCEL_ACCESS_TOKEN"],
            "exec has no approved Vercel CLI route or credential adapter; an API endpoint override alone does not add support.",
        ),
        "supabase" => (
            &["SUPABASE_ACCESS_TOKEN", "SUPABASE_DB_PASSWORD"],
            "Supabase CLI management tokens and database passwords are not served by the Supabase data API routes. Management needs its own adapter; database work needs a protocol-aware broker.",
        ),
        "aws" => (
            &[
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN",
            ],
            "AWS SigV4/SigV4a signing cannot use placeholders; fixed-header injection and --endpoint-url cannot repair a signature. A signing-aware broker is required.",
        ),
        "git" if !git_local_command(args) => (
            GITHUB_KEYS,
            "Git HTTPS credentials and smart HTTP are not the github_api REST route. Network commands, aliases and unknown remote transports are conservatively refused with protected GitHub credentials; local Git commands remain available.",
        ),
        _ => return Ok(()),
    };
    let blocked: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|key| protected.contains(*key))
        .collect();
    if !blocked.is_empty() {
        anyhow::bail!(
            "CLI coverage: refusing {name} with protected {}. {reason} No child was launched. See docs/exec.md; use `phantom why <KEY>` for route details. Unsupported credential work belongs in a trusted terminal outside agent authority, not in plaintext arguments or files.",
            blocked.join(", ")
        );
    }
    Ok(())
}

fn npm_local_script(args: &[String]) -> bool {
    // npm's registry operations have many aliases. Allow the known local
    // script forms instead of trying to enumerate every private-registry call.
    matches!(
        args.first().map(String::as_str),
        Some("run" | "run-script" | "test" | "t" | "tst" | "start" | "stop" | "restart")
    )
}

fn git_local_command(args: &[String]) -> bool {
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        match arg {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" => {
                if args.next().is_none() {
                    return false;
                }
            }
            "--no-pager" | "--paginate" | "--bare" | "--no-optional-locks" => {}
            option
                if option.starts_with("--git-dir=")
                    || option.starts_with("--work-tree=")
                    || option.starts_with("--namespace=") => {}
            // Do not guess what an alias, external subcommand or remote will
            // do. Even a named/SSH remote can be rewritten by Git config.
            "remote" => {
                return match args.next() {
                    None => true,
                    Some("-v" | "--verbose") => args.next().is_none(),
                    Some("remove" | "rm" | "rename" | "get-url" | "set-url") => true,
                    _ => false,
                };
            }
            command => {
                return matches!(
                    command,
                    "status"
                        | "diff"
                        | "log"
                        | "blame"
                        | "grep"
                        | "reflog"
                        | "worktree"
                        | "describe"
                        | "shortlog"
                        | "show"
                        | "rev-parse"
                        | "rev-list"
                        | "ls-files"
                        | "ls-tree"
                        | "cat-file"
                        | "branch"
                        | "tag"
                        | "add"
                        | "commit"
                        | "reset"
                        | "restore"
                        | "checkout"
                        | "switch"
                        | "stash"
                        | "merge"
                        | "rebase"
                        | "cherry-pick"
                        | "revert"
                        | "clean"
                        | "init"
                        | "config"
                );
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn credential_aliases_and_launcher_paths_are_refused_without_echoing_arguments() {
        let cases: &[(&str, &[&str])] = &[
            ("/usr/local/bin/gh", GITHUB_KEYS),
            (r"C:\tools\GH.EXE", GITHUB_KEYS),
            (
                "npm.cmd",
                &[
                    "NPM_TOKEN",
                    "NODE_AUTH_TOKEN",
                    "NPM_AUTH_TOKEN",
                    "GITHUB_TOKEN",
                    "GH_TOKEN",
                ],
            ),
            ("vc", &["VERCEL_TOKEN", "VERCEL_ACCESS_TOKEN"]),
            ("vercel", &["VERCEL_TOKEN"]),
            (
                "supabase",
                &["SUPABASE_ACCESS_TOKEN", "SUPABASE_DB_PASSWORD"],
            ),
            (
                "aws.exe",
                &[
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN",
                    "AWS_SECURITY_TOKEN",
                ],
            ),
            ("git", GITHUB_KEYS),
        ];
        for (program, keys) in cases {
            for key in *keys {
                let protected = HashSet::from([(*key).to_string()]);
                let error = validate_command(
                    &command(&[
                        program,
                        "unsupported-operation",
                        "argument-must-not-be-echoed",
                    ]),
                    &protected,
                )
                .unwrap_err()
                .to_string();
                assert!(error.contains("CLI coverage:"));
                assert!(error.contains(key));
                assert!(!error.contains("argument-must-not-be-echoed"));
            }
        }
    }

    #[test]
    fn local_forms_and_unrelated_credentials_remain_available() {
        let all_keys = GITHUB_KEYS
            .iter()
            .copied()
            .chain([
                "NPM_TOKEN",
                "VERCEL_TOKEN",
                "SUPABASE_ACCESS_TOKEN",
                "AWS_SECRET_ACCESS_KEY",
            ])
            .map(str::to_string)
            .collect();
        for args in [
            vec!["npm", "run", "build"],
            vec!["npm", "run-script", "dev"],
            vec!["npm", "test"],
            vec!["npm", "start"],
            vec!["git", "status"],
            vec!["git", "remote", "-v"],
            vec!["git", "remote", "get-url", "origin"],
            vec!["git", "-C", "/tmp/project", "--no-pager", "diff"],
            vec!["curl", "http://127.0.0.1/explicit-route"],
            vec!["sh", "-c", "npm run build"],
        ] {
            assert!(validate_command(&command(&args), &all_keys).is_ok());
        }
        for program in ["gh", "npm", "vercel", "supabase", "aws", "git"] {
            for flag in ["--help", "--version", "help"] {
                assert!(validate_command(&command(&[program, flag]), &all_keys).is_ok());
            }
            assert!(validate_command(
                &command(&[program, "operation"]),
                &HashSet::from(["OPENAI_API_KEY".to_string()]),
            )
            .is_ok());
        }
    }

    #[test]
    fn network_options_aliases_and_mixed_help_do_not_bypass_refusal() {
        let keys = ["GITHUB_TOKEN", "NODE_AUTH_TOKEN", "AWS_SECRET_ACCESS_KEY"]
            .map(str::to_string)
            .into();
        for args in [
            vec!["git", "-C", "repo", "fetch", "origin"],
            vec!["git", "-c", "alias.up=fetch", "up"],
            vec![
                "git",
                "--git-dir=.git",
                "clone",
                "https://github.com/example/repo",
            ],
            vec!["git", "remote-helper"],
            vec!["git", "remote", "update"],
            vec![
                "git",
                "remote",
                "add",
                "-f",
                "origin",
                "https://github.com/example/repo",
            ],
            vec!["npm", "--registry=http://127.0.0.1", "install"],
            vec!["npm", "publish", "--help"],
            vec![
                "aws",
                "--endpoint-url",
                "http://127.0.0.1",
                "sts",
                "get-caller-identity",
            ],
        ] {
            assert!(validate_command(&command(&args), &keys).is_err());
        }
        assert!(validate_command(
            &command(&["vercel"]),
            &HashSet::from(["VERCEL_TOKEN".to_string()]),
        )
        .is_err());
    }

    // A separate test process avoids mutating this process's HOME, cwd or
    // environment while the rest of the workspace suite runs in parallel.
    #[test]
    fn exec_refusal_child() {
        let Ok(raw) = std::env::var("PHANTOM_TEST_COVERAGE_COMMAND") else {
            return;
        };
        let cmd: Vec<String> = serde_json::from_str(&raw).unwrap();
        let result = super::super::run(&cmd, None, None, true);
        let error = result
            .expect_err("unsupported CLI must be refused")
            .to_string();
        // Do not print the invocation, fixture mappings or captured output on
        // failure. The reason must come from preflight, not a locked vault or
        // a failed child executable lookup.
        assert!(error.starts_with("CLI coverage:"), "wrong refusal stage");
        assert!(error.contains("No child was launched."));
        assert!(!std::path::Path::new(&std::env::var("HOME").unwrap())
            .join(".phantom")
            .exists());
        println!("coverage-refusal-confirmed");
    }

    #[cfg(unix)]
    #[test]
    fn network_canary_child() {
        use std::io::{Read, Write};
        let Ok(address) = std::env::var("PHANTOM_TEST_COVERAGE_UPSTREAM") else {
            return;
        };
        let mut connection = std::net::TcpStream::connect(address).unwrap();
        connection
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        connection
            .write_all(
                b"GET /child-launched HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = Vec::new();
        connection.read_to_end(&mut response).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unsupported_cli_table_stops_before_vault_child_and_loopback_upstream() {
        use std::os::unix::fs::PermissionsExt;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;
        // Positive control: prove the subprocess canary really reaches this
        // mock, so a zero-request assertion cannot hide a broken test probe.
        let canary_home = tempfile::tempdir().unwrap();
        let mut canary = tokio::process::Command::new(std::env::current_exe().unwrap());
        canary
            .env_clear()
            .env("HOME", canary_home.path())
            .env(
                "PHANTOM_TEST_COVERAGE_UPSTREAM",
                upstream.address().to_string(),
            )
            .args([
                "--exact",
                "commands::exec::coverage::tests::network_canary_child",
                "--nocapture",
            ])
            .kill_on_drop(true);
        let canary_output =
            tokio::time::timeout(std::time::Duration::from_secs(20), canary.output())
                .await
                .expect("canary timed out")
                .unwrap();
        assert!(canary_output.status.success());
        assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
        upstream.reset().await;
        let cases: &[(&str, &[&str], &str)] = &[
            ("gh", &["api", "user"], "GITHUB_TOKEN"),
            ("npm", &["install"], "NPM_TOKEN"),
            ("vercel", &[], "VERCEL_TOKEN"),
            ("supabase", &["projects", "list"], "SUPABASE_ACCESS_TOKEN"),
            (
                "aws",
                &["sts", "get-caller-identity"],
                "AWS_SECRET_ACCESS_KEY",
            ),
            (
                "git",
                &["ls-remote", "https://github.com/example/repo"],
                "GITHUB_TOKEN",
            ),
        ];
        for (cli, args, key) in cases {
            let temp_root = std::env::temp_dir().canonicalize().unwrap();
            let project = tempfile::tempdir_in(&temp_root).unwrap();
            let home = tempfile::tempdir_in(&temp_root).unwrap();
            let config =
                phantom_core::config::PhantomConfig::new_with_defaults("cli-coverage".to_string());
            std::fs::write(
                project.path().join(".phantom.toml"),
                toml::to_string(&config).unwrap(),
            )
            .unwrap();
            let mapping = phantom_core::token::PhantomToken::generate();
            std::fs::write(
                project.path().join(".env"),
                format!("{key}={}\n", mapping.as_str()),
            )
            .unwrap();
            // If the child were ever launched it would hit the mock, never an
            // installed vendor CLI or public provider. No vault is provisioned:
            // the compatibility error must win even with a locked/missing vault.
            let program = project.path().join(cli);
            std::fs::write(
                &program,
                concat!(
                    "#!/bin/sh\n",
                    "exec \"$PHANTOM_TEST_COVERAGE_BINARY\" --exact ",
                    "commands::exec::coverage::tests::network_canary_child --nocapture\n",
                ),
            )
            .unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut cmd = vec![program.to_str().unwrap().to_string()];
            cmd.extend(args.iter().map(|arg| (*arg).to_string()));
            let executable = std::env::current_exe().unwrap();
            let mut child = tokio::process::Command::new(&executable);
            child
                .env_clear()
                .current_dir(project.path())
                .env("HOME", home.path())
                .env("USERPROFILE", home.path())
                .env("NO_COLOR", "1")
                .env(
                    "PHANTOM_TEST_COVERAGE_COMMAND",
                    serde_json::to_string(&cmd).unwrap(),
                )
                .env("PHANTOM_TEST_COVERAGE_BINARY", &executable)
                .env(
                    "PHANTOM_TEST_COVERAGE_UPSTREAM",
                    upstream.address().to_string(),
                )
                .args([
                    "--exact",
                    "commands::exec::coverage::tests::exec_refusal_child",
                    "--nocapture",
                ])
                .kill_on_drop(true);
            let output = tokio::time::timeout(std::time::Duration::from_secs(20), child.output())
                .await
                .expect("coverage child timed out")
                .unwrap();
            assert!(output.status.success(), "{cli}: pre-vault refusal failed");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("coverage-refusal-confirmed"),
                "{cli}: refusal helper did not run"
            );
            for stream in [&output.stdout, &output.stderr] {
                assert!(
                    !String::from_utf8_lossy(stream).contains(mapping.as_str()),
                    "{cli}: mapping disclosed"
                );
            }
            assert!(
                upstream.received_requests().await.unwrap().is_empty(),
                "{cli}: child reached upstream"
            );
        }
    }
}
