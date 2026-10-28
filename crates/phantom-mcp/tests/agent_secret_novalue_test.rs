//! Exercise the shipped stdio transport, including failure responses and logs.
//! No real credentials, approval bypass, or provider connection is used.
#[path = "../../test-utils/agent_rpc.rs"]
mod agent_rpc;
#[path = "../../test-utils/agent_secret.rs"]
mod support;

use agent_rpc::Rpc;
use phantom_core::config::PhantomConfig;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};
use support::{assert_tree_value_free, canonical_tempdir, isolated_command, Canary};

const DEADLINE: Duration = Duration::from_secs(30);

// A separate process selects the normal platform vault directory without
// changing this test process's global HOME or touching the operator's keychain.
#[test]
fn seed_agent_vault_subprocess() {
    if std::env::var_os("PHANTOM_TEST_SEED_AGENT_VAULT").is_none() {
        return;
    }
    let mut value = zeroize::Zeroizing::new(String::new());
    assert!(std::io::stdin().read_to_string(&mut value).is_ok());
    assert!(!value.is_empty(), "fixture must receive a runtime canary");
    let project = std::env::current_dir().expect("fixture project");
    let config = PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&project));
    assert!(config.save(&project.join(".phantom.toml")).is_ok());
    let vault = phantom_vault::create_vault(config.local_project_id()).expect("fixture vault");
    assert!(vault.store("OPENAI_API_KEY", &value).is_ok());
    let token = phantom_core::token::PhantomToken::generate();
    assert!(std::fs::write(project.join(".env"), format!("OPENAI_API_KEY={token}\n")).is_ok());
}

fn successful_result(response: &Value) -> &Value {
    assert!(response.get("error").is_none(), "MCP request must succeed");
    let result = response.get("result").expect("MCP result");
    assert_ne!(result["isError"], true, "MCP tool must succeed");
    assert!(result["content"]
        .as_array()
        .is_some_and(|content| !content.is_empty()));
    result
}

fn denied(response: &Value) {
    assert!(
        response.get("error").is_some() || response["result"]["isError"] == true,
        "unsafe or unavailable tool call must be refused"
    );
}

#[test]
fn agent_mcp_reads_creation_guidance_and_denials_never_disclose_vault_values() {
    let project = canonical_tempdir();
    let home = canonical_tempdir();
    let secret = Canary::new();
    let passphrase = Canary::new();
    let canaries = [&secret, &passphrase];

    let mut seed = isolated_command(
        std::env::current_exe().unwrap(),
        project.path(),
        home.path(),
    );
    seed.args(["--exact", "seed_agent_vault_subprocess", "--nocapture"])
        .env("PHANTOM_TEST_SEED_AGENT_VAULT", "1")
        .env("PHANTOM_VAULT_PASSPHRASE", passphrase.value())
        .env("PHANTOM_AUDIT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = seed.spawn().expect("fixture subprocess");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(secret.value().as_bytes())
        .expect("seed runtime canary");
    let started = Instant::now();
    while child.try_wait().expect("fixture status").is_none() {
        if started.elapsed() >= DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fixture subprocess deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("fixture output");
    for canary in &canaries {
        canary.assert_absent(&output.stdout, "fixture stdout");
        canary.assert_absent(&output.stderr, "fixture stderr");
    }
    assert!(
        output.status.success(),
        "fixture must seed the real encrypted vault"
    );

    let mut command = isolated_command(
        env!("CARGO_BIN_EXE_phantom-mcp"),
        project.path(),
        home.path(),
    );
    command
        .env("PHANTOM_VAULT_PASSPHRASE", passphrase.value())
        .env("PHANTOM_AUDIT", "1");
    let mut rpc = Rpc::start(command, &canaries);
    let initialize = rpc.request(
        "initialize",
        json!({
            "protocolVersion":"2025-06-18", "capabilities":{},
            "clientInfo":{"name":"simulated-value-blind-agent", "version":"1"}
        }),
    );
    assert!(initialize["result"]["serverInfo"].is_object());
    rpc.send(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
    let catalog = rpc.request("tools/list", json!({}));
    let tools = catalog["result"]["tools"]
        .as_array()
        .expect("runtime tool catalog");
    assert!(tools
        .iter()
        .any(|tool| tool["name"] == "phantom_list_secrets"));
    // #488/#490 get/create are not present in this checkout. Pin that fact:
    // adding them requires deliberately extending this end-to-end contract.
    for unavailable in ["phantom_get_secret", "phantom_create_secret"] {
        assert!(
            !tools.iter().any(|tool| tool["name"] == unavailable),
            "new get/create surface requires value-blind integration coverage"
        );
        denied(&rpc.call(unavailable, json!({"name":"OPENAI_API_KEY"})));
    }

    let listed = rpc.call("phantom_list_secrets", json!({}));
    let report = &successful_result(&listed)["structuredContent"];
    assert_eq!(report["count"], 1);
    assert_eq!(report["secrets"][0]["name"], "OPENAI_API_KEY");
    let status = rpc.call("phantom_status", json!({}));
    assert_eq!(
        successful_result(&status)["structuredContent"]["initialized"],
        true
    );
    let why = rpc.call("phantom_why", json!({"key":"OPENAI_API_KEY"}));
    assert_eq!(
        successful_result(&why)["structuredContent"]["protected"],
        true
    );

    let create = rpc.call(
        "phantom_add_secret_interactive",
        json!({"name":"NEW_API_KEY"}),
    );
    let guidance = successful_result(&create).to_string();
    assert!(guidance.contains("phantom add NEW_API_KEY"));
    assert!(guidance.contains("Nothing was stored"));
    denied(&rpc.call(
        "phantom_add_secret",
        json!({"name":"NEW_API_KEY", "confirm":true}),
    ));
    let response = rpc.call(
        "phantom_add_secret",
        json!({"name":"NEW_API_KEY", "value":secret.value(), "confirm":true}),
    );
    denied(&response);
    // rmcp represents parameter decoding failures as tool errors rather than
    // JSON-RPC envelope errors. Require the schema refusal, not merely any
    // denial that could have come from the later approval gate.
    assert!(
        response.to_string().contains("unknown field `value`"),
        "deprecated plaintext arguments must fail schema validation"
    );
    // The interactive helper tolerates unknown compatibility fields. Even an
    // unsolicited value must have no effect and must never enter its guidance.
    let extra_value = rpc.call(
        "phantom_add_secret_interactive",
        json!({"name":"NEW_API_KEY", "value":secret.value()}),
    );
    assert!(
        successful_result(&extra_value) == successful_result(&create),
        "ignored fields must not alter the out-of-band handoff"
    );
    // Invalid names are rejected without echoing attacker-controlled content.
    denied(&rpc.call(
        "phantom_add_secret_interactive",
        json!({"name":format!("invalid-{}", secret.value())}),
    ));
    let after = rpc.call("phantom_list_secrets", json!({}));
    assert!(
        successful_result(&after)["structuredContent"] == *report,
        "creation guidance and refused calls must not modify inventory"
    );
    rpc.finish();

    let audit = std::fs::read(home.path().join(".phantom/audit.log")).expect("real audit log");
    assert!(
        audit
            .windows(b"vault.store".len())
            .any(|window| window == b"vault.store"),
        "audit scanner must inspect an actual secret operation"
    );
    assert!(assert_tree_value_free(home.path(), &canaries) > 0);
    assert!(assert_tree_value_free(project.path(), &canaries) >= 2);
}

#[test]
fn standalone_mcp_rejects_sensitive_arguments_without_echoing_them() {
    let project = canonical_tempdir();
    let home = canonical_tempdir();
    let canary = Canary::new();
    let mut command = isolated_command(
        env!("CARGO_BIN_EXE_phantom-mcp"),
        project.path(),
        home.path(),
    );
    command.arg(canary.value());
    let output = support::run(&mut command);
    canary.assert_absent(&output.stdout, "invalid argument stdout");
    canary.assert_absent(&output.stderr, "invalid argument stderr");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"usage: phantom-mcp [--version]\n");
}
