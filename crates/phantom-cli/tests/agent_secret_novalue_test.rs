//! Black-box agent contract: only session placeholders reach the child.
//! The fixture owns synthetic credentials; the simulated agent never knows
//! them. All captured bytes are checked before any success assertion.
#[path = "../../test-utils/agent_rpc.rs"]
mod agent_rpc;
#[path = "../../test-utils/agent_secret.rs"]
mod support;

use phantom_core::dotenv::DotenvFile;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::process::{Command, Output};
use support::{assert_tree_value_free, canonical_tempdir, isolated_command, run, Canary};

struct Fixture {
    project: tempfile::TempDir,
    home: tempfile::TempDir,
    routed: Canary,
    unrouted: Canary,
    passphrase: Canary,
    ambient: Canary,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            project: canonical_tempdir(),
            home: canonical_tempdir(),
            routed: Canary::new(),
            unrouted: Canary::new(),
            passphrase: Canary::new(),
            ambient: Canary::new(),
        };
        // Provision through Phantom, not a fake vault or test-only injection.
        fs::write(
            fixture.project.path().join(".env"),
            format!(
                "OPENAI_API_KEY={}\nGROQ_API_KEY={}\nAPP_MODE=agent-test\n",
                fixture.routed.value(),
                fixture.unrouted.value()
            ),
        )
        .unwrap();
        let output = run(fixture.command().args(["init", "--from", ".env"]));
        fixture.check_output(&output);
        assert!(output.status.success(), "fixture initialization failed");
        let dotenv = DotenvFile::parse_file(&fixture.project.path().join(".env")).unwrap();
        for name in ["OPENAI_API_KEY", "GROQ_API_KEY"] {
            assert!(dotenv
                .entries()
                .iter()
                .any(|entry| { entry.key == name && entry.value.starts_with("phm_") }));
        }
        fixture
    }

    fn canaries(&self) -> [&Canary; 4] {
        [
            &self.routed,
            &self.unrouted,
            &self.passphrase,
            &self.ambient,
        ]
    }

    fn command(&self) -> Command {
        let mut command = isolated_command(
            env!("CARGO_BIN_EXE_phantom"),
            self.project.path(),
            self.home.path(),
        );
        command.env("PHANTOM_VAULT_PASSPHRASE", self.passphrase.value());
        command
    }

    fn agent_environment(&self, command: &mut Command) {
        command
            .env("NOVALUE_SIMULATED_AGENT", "1")
            .env("APP_MODE", "agent-test")
            // Ambient values must be replaced, including unrouted secrets.
            .env("OPENAI_API_KEY", self.routed.value())
            .env("GROQ_API_KEY", self.unrouted.value())
            .env("PHANTOM_PROXY_TOKEN", self.ambient.value())
            .env("OPENAI_BASE_URL", self.ambient.value());
    }

    fn check_output(&self, output: &Output) {
        for canary in self.canaries() {
            canary.assert_absent(&output.stdout, "CLI/agent stdout");
            canary.assert_absent(&output.stderr, "CLI/agent stderr and tracing");
        }
    }

    fn check_artifacts(&self) {
        assert!(assert_tree_value_free(self.project.path(), &self.canaries()) >= 3);
        assert!(assert_tree_value_free(self.home.path(), &self.canaries()) > 0);
        let audit = fs::read(self.home.path().join(".phantom/audit.log"))
            .expect("audit logging must actually run");
        assert!(!audit.is_empty(), "audit scan must not be vacuous");
        assert!(String::from_utf8_lossy(&audit).contains("vault.retrieve_for_injection"));
    }

    fn check_agent_dump(&self) -> Value {
        let bytes = fs::read(self.project.path().join("agent-env.json"))
            .expect("agent must run and persist its complete environment");
        for canary in self.canaries() {
            canary.assert_absent(&bytes, "agent environment dump");
        }
        let env: Value = serde_json::from_slice(&bytes).expect("agent env JSON");
        let dotenv = DotenvFile::parse_file(&self.project.path().join(".env")).unwrap();
        for name in ["OPENAI_API_KEY", "GROQ_API_KEY"] {
            let value = env[name].as_str().expect("managed key reaches agent");
            assert!(
                value.starts_with("phm_"),
                "child must receive a placeholder"
            );
            let persistent = dotenv
                .entries()
                .into_iter()
                .find(|entry| entry.key == name)
                .unwrap();
            assert!(
                value != persistent.value,
                "child must receive a fresh session mapping"
            );
        }
        assert!(env.get("PHANTOM_VAULT_PASSPHRASE").is_none());
        assert!(env["OPENAI_BASE_URL"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"));
        assert!(env["PHANTOM_PROXY_TOKEN"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(
            env["APP_MODE"] == "agent-test",
            "ordinary ambient variables survive"
        );
        env
    }
}

/// Subprocess entry point using the already-built test binary, with no shell,
/// Python, Node, provider access, or additional compiler dependency. In the
/// outer test runner it does nothing; only the exec child receives the marker.
#[test]
fn simulated_agent_process() {
    if std::env::var("NOVALUE_SIMULATED_AGENT").as_deref() != Ok("1") {
        return;
    }
    let env: BTreeMap<_, _> = std::env::vars_os()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    let dump = serde_json::to_vec(&env).unwrap();
    fs::write("agent-env.json", &dump).unwrap();
    // Deliberately expose every variable on both streams and in a log. The
    // parent's leak-safe assertions own these bytes; libtest never prints them.
    println!("{}", String::from_utf8_lossy(&dump));
    eprintln!("{}", String::from_utf8_lossy(&dump));
    fs::write("agent.log", &dump).unwrap();
    let dotenv = fs::read(".env").unwrap();
    println!("{}", String::from_utf8_lossy(&dotenv));
    eprintln!("{}", String::from_utf8_lossy(&dotenv));
    if std::env::var("NOVALUE_AGENT_FAIL").as_deref() == Ok("1") {
        std::process::exit(23);
    }
}

#[test]
fn exec_agent_never_observes_values_even_on_failure_and_repeated_sessions() {
    let fixture = Fixture::new();
    let mut previous: Option<Value> = None;
    for fail in [false, true] {
        let mut command = fixture.command();
        fixture.agent_environment(&mut command);
        command
            .args(["exec", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "simulated_agent_process", "--nocapture"])
            .env("NOVALUE_AGENT_FAIL", if fail { "1" } else { "0" });
        let output = run(&mut command);
        fixture.check_output(&output);
        assert_eq!(output.status.code(), Some(if fail { 23 } else { 0 }));
        let dump = fixture.check_agent_dump();
        if let Some(previous) = previous {
            for name in ["OPENAI_API_KEY", "GROQ_API_KEY", "PHANTOM_PROXY_TOKEN"] {
                assert!(
                    previous[name] != dump[name],
                    "sessions must not reuse tokens"
                );
            }
        }
        previous = Some(dump);
        fixture.check_artifacts();
    }
}

#[test]
fn wrapped_script_runs_the_agent_without_disclosing_values() {
    let fixture = Fixture::new();
    let executable = std::env::current_exe().unwrap();
    let executable = executable.to_str().unwrap();
    #[cfg(unix)]
    let quoted = format!("'{}'", executable.replace('\'', "'\\''"));
    #[cfg(windows)]
    let quoted = format!("\"{executable}\"");
    let original = format!("{quoted} --exact simulated_agent_process --nocapture");
    fs::write(
        fixture.project.path().join("package.json"),
        serde_json::to_vec(&json!({"scripts": {"dev": original}})).unwrap(),
    )
    .unwrap();
    let output = run(fixture.command().arg("wrap"));
    fixture.check_output(&output);
    assert!(output.status.success(), "wrap must succeed");
    let package: Value =
        serde_json::from_slice(&fs::read(fixture.project.path().join("package.json")).unwrap())
            .unwrap();
    let wrapped = package["scripts"]["dev"].as_str().unwrap();
    assert_eq!(wrapped, format!("phantom exec -- {original}"));
    assert_eq!(package["scripts"]["dev:raw"], original);

    // Execute the exact script produced by wrap through the platform shell,
    // as a package manager would, without downloading an npm package.
    #[cfg(unix)]
    let mut command = isolated_command("sh", fixture.project.path(), fixture.home.path());
    #[cfg(unix)]
    command.args(["-c", wrapped]);
    #[cfg(windows)]
    let mut command = isolated_command("cmd.exe", fixture.project.path(), fixture.home.path());
    #[cfg(windows)]
    command.args(["/D", "/C", wrapped]);
    let mut paths = vec![std::path::Path::new(env!("CARGO_BIN_EXE_phantom"))
        .parent()
        .unwrap()
        .to_path_buf()];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    command.env("PATH", std::env::join_paths(paths).unwrap());
    command.env("PHANTOM_VAULT_PASSPHRASE", fixture.passphrase.value());
    fixture.agent_environment(&mut command);
    let output = run(&mut command);
    fixture.check_output(&output);
    assert!(output.status.success(), "wrapped agent must run");
    fixture.check_agent_dump();
    fixture.check_artifacts();
}

#[test]
fn locked_vault_refuses_agent_launch_without_leaking_either_passphrase() {
    let fixture = Fixture::new();
    let wrong_passphrase = Canary::new();
    let mut command = fixture.command();
    fixture.agent_environment(&mut command);
    command
        .env("PHANTOM_VAULT_PASSPHRASE", wrong_passphrase.value())
        .args(["exec", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "simulated_agent_process", "--nocapture"]);
    let output = run(&mut command);
    fixture.check_output(&output);
    wrong_passphrase.assert_absent(&output.stdout, "locked-vault stdout");
    wrong_passphrase.assert_absent(&output.stderr, "locked-vault stderr");
    assert!(!output.status.success(), "locked vault must fail closed");
    assert!(!fixture.project.path().join("agent-env.json").exists());
    assert!(!output.stderr.is_empty(), "refusal must be reported");
    let mut canaries = fixture.canaries().to_vec();
    canaries.push(&wrong_passphrase);
    assert_tree_value_free(fixture.project.path(), &canaries);
    assert_tree_value_free(fixture.home.path(), &canaries);
}

#[test]
fn exec_to_mcp_keeps_reads_value_blind_and_creation_out_of_band() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    fixture.agent_environment(&mut command);
    command
        .args(["exec", "--"])
        .arg(env!("CARGO_BIN_EXE_phantom"))
        .args(["mcp", "serve"]);
    let canaries = fixture.canaries();
    let mut rpc = agent_rpc::Rpc::start(command, &canaries);
    let initialize = rpc.request(
        "initialize",
        json!({
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "simulated-exec-agent", "version": "1"}
        }),
    );
    assert!(initialize["result"]["serverInfo"].is_object());
    rpc.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    let status = rpc.call("phantom_status", json!({}));
    assert_eq!(status["result"]["structuredContent"]["initialized"], true);
    // Exec withholds the unlock passphrase (asserted by the environment-dump
    // test). Keep this nested server on its metadata-only surface so it never
    // falls back to the operator's OS keychain; the standalone MCP harness
    // exercises inventory reads with an explicitly selected encrypted vault.
    assert_eq!(
        status["result"]["structuredContent"]["vault_inspected"],
        false
    );
    let why = rpc.call("phantom_why", json!({"key": "OPENAI_API_KEY"}));
    assert_eq!(why["result"]["structuredContent"]["protected"], true);
    let create = rpc.call(
        "phantom_add_secret_interactive",
        json!({"name": "NEW_API_KEY"}),
    );
    assert!(create.get("error").is_none());
    assert!(create["result"]
        .to_string()
        .contains("phantom add NEW_API_KEY"));
    assert!(create["result"].to_string().contains("Nothing was stored"));
    rpc.finish();
    fixture.check_artifacts();
}

#[test]
fn leak_detector_rejects_raw_and_encoded_values_without_echoing_them() {
    use base64::Engine;
    let canary = Canary::new();
    for bytes in [
        canary.value().as_bytes().to_vec(),
        hex::encode(canary.value()).into_bytes(),
        base64::engine::general_purpose::STANDARD
            .encode(canary.value())
            .into_bytes(),
    ] {
        let failure = std::panic::catch_unwind(|| canary.assert_absent(&bytes, "negative control"))
            .expect_err("leak detector must reject seeded leakage");
        let message = failure
            .downcast_ref::<String>()
            .expect("safe assertion message");
        assert!(
            !message.contains(canary.value()),
            "failure diagnostic must withhold values"
        );
    }
}
