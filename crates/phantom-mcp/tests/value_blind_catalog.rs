//! Exercise the real stdio router, including framework argument failures.
//! Canary material is generated at runtime and never printed on assertion failure.
use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::Duration;

use phantom_core::config::PhantomConfig;
use phantom_vault::{file::FileVault, VaultBackend};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn cases() -> Vec<(&'static str, Value)> {
    vec![
        (
            "phantom_do",
            json!({"action":{"action":"cargo_check","cwd":"."}}),
        ),
        ("phantom_setup_workspace", json!({})),
        ("phantom_capability", json!({})),
        ("phantom_list_secrets", json!({})),
        ("phantom_status", json!({})),
        ("phantom_init", json!({})),
        ("phantom_add_secret", json!({"name":"OPENAI_API_KEY"})),
        (
            "phantom_add_secret_interactive",
            json!({"name":"OPENAI_API_KEY"}),
        ),
        ("phantom_remove_secret", json!({"name":"OPENAI_API_KEY"})),
        ("phantom_rotate", json!({})),
        (
            "phantom_rotate_with_candidate",
            json!({"name":"OPENAI_API_KEY"}),
        ),
        ("phantom_rotate_promote", json!({"name":"OPENAI_API_KEY"})),
        ("phantom_rotate_provider", json!({"name":"OPENAI_API_KEY"})),
        ("phantom_cloud_push", json!({})),
        ("phantom_cloud_pull", json!({})),
        (
            "phantom_copy_secret",
            json!({"name":"OPENAI_API_KEY","target_dir":"target"}),
        ),
        ("phantom_doctor", json!({})),
        ("phantom_why", json!({"key":"OPENAI_API_KEY"})),
        ("phantom_wrap", json!({})),
        ("phantom_unwrap", json!({})),
        ("phantom_check", json!({"runtime":true})),
        ("phantom_env", json!({})),
        ("phantom_sync", json!({})),
        ("phantom_cloud_status", json!({})),
        ("phantom_team_list", json!({})),
        ("phantom_team_create", json!({"name":"audit-team"})),
        ("phantom_team_members", json!({"team_id":"audit-team"})),
        (
            "phantom_team_invite",
            json!({"team_id":"audit-team","github_login":"octocat"}),
        ),
        ("phantom_team_key_publish", json!({"team_id":"audit-team"})),
        ("phantom_team_vault_push", json!({"team_id":"audit-team"})),
        ("phantom_team_vault_pull", json!({"team_id":"audit-team"})),
        ("phantom_rotate_with_expiry", json!({"days_ttl":30})),
        ("phantom_list_with_expiry", json!({})),
        ("phantom_audit_stats", json!({})),
        ("phantom_audit_recent", json!({})),
        ("phantom_audit_anomalies", json!({})),
        ("phantom_audit_anomalies_realtime", json!({})),
        ("phantom_audit_hotspot_alerts", json!({})),
        ("phantom_audit_analytics", json!({})),
        ("phantom_audit_incidents", json!({})),
        ("phantom_leak_incidents_realtime", json!({})),
        ("phantom_audit_alerts", json!({})),
        ("phantom_audit_export_report", json!({})),
        ("phantom_compliance_status", json!({})),
        ("phantom_secret_rotation_due", json!({})),
        ("phantom_validate_secret", json!({"name":"OPENAI_API_KEY"})),
        ("phantom_validate_all", json!({})),
        ("phantom_validation_schedule", json!({})),
        ("phantom_validation_history", json!({})),
        ("phantom_secrets_expiry_check", json!({})),
        (
            "phantom_secrets_auto_rotate",
            json!({"name":"OPENAI_API_KEY"}),
        ),
        ("phantom_expiry_enforce", json!({})),
        (
            "phantom_rotation_schedule_next",
            json!({"name":"OPENAI_API_KEY"}),
        ),
        ("phantom_apply_expiry_policy", json!({})),
    ]
}

struct Wire {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    id: u64,
    marker: String,
}

impl Wire {
    async fn request(&mut self, method: &str, params: Value) -> Value {
        let label = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(method)
            .to_owned();
        self.id += 1;
        let id = self.id;
        let mut line =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
                .unwrap();
        line.push(b'\n');
        self.input.write_all(&line).await.unwrap();
        loop {
            let line = tokio::time::timeout(Duration::from_secs(20), self.output.next_line())
                .await
                .expect("MCP response timed out")
                .unwrap()
                .expect("MCP stdout closed");
            assert!(!line.contains(&self.marker), "canary disclosed by {label}");
            let response: Value =
                serde_json::from_str(&line).expect("MCP stdout must contain only JSON");
            if response["id"] == id {
                return response;
            }
        }
    }

    async fn call(&mut self, name: &str, arguments: Value) -> Value {
        let response = self
            .request("tools/call", json!({"name":name,"arguments":arguments}))
            .await;
        assert!(
            response.get("result").is_some() || response.get("error").is_some(),
            "missing tool response: {name}"
        );
        response
    }
}

#[tokio::test]
async fn every_registered_tool_is_value_blind_on_the_wire() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let marker = format!("MCPNOVALUE{}", hex::encode(rand::random::<[u8; 24]>()));
    let secret = format!("sk-{marker}");
    let passphrase = format!("pass-{marker}");
    let config = PhantomConfig::new_with_defaults("mcp-value-blind-audit".into());
    let config_path = project.path().join(".phantom.toml");
    config.save(&config_path).unwrap();
    let vault = FileVault::new(
        &home.path().join(".phantom"),
        config.local_project_id(),
        passphrase.clone(),
    )
    .unwrap();
    vault.store("OPENAI_API_KEY", &secret).unwrap();
    // Exercise plaintext scanning as well as metadata-only vault reads.
    std::fs::write(
        project.path().join(".env"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();
    std::fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname='audit'\nversion='0.1.0'\n",
    )
    .unwrap();
    // Unknown top-level fields are never returned; malformed known metadata
    // must not smuggle arbitrary nested JSON into an audit response either.
    let audit_rows = [
        json!({"ts":1700000000,"op":"vault.store","name":"OPENAI_API_KEY","value":secret}),
        json!({"ts":1700000001,"op":"vault.store","process":{"value":secret}}),
    ];
    std::fs::write(
        home.path().join(".phantom/audit.log"),
        audit_rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_phantom-mcp"))
        .current_dir(project.path())
        .env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("PHANTOM_VAULT_PASSPHRASE", &passphrase)
        .env("OPENAI_API_KEY", &secret)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", home.path().join("missing-gitconfig"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let stderr_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        BufReader::new(stderr)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        bytes
    });
    let mut wire = Wire {
        input: child.stdin.take().unwrap(),
        output: BufReader::new(child.stdout.take().unwrap()).lines(),
        child,
        id: 0,
        marker: marker.clone(),
    };
    wire.request("initialize", json!({"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"value-blind-audit","version":"1"}})).await;
    wire.input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();
    let listed = wire.request("tools/list", json!({})).await;
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("tools/list result");
    let table = cases();
    let expected: BTreeSet<_> = table.iter().map(|(name, _)| *name).collect();
    let actual: BTreeSet<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        expected, actual,
        "every runtime tool needs an explicit audit row"
    );
    assert_eq!(expected.len(), table.len(), "duplicate audit row");
    let mut successful_reads = 0;
    for (name, args) in &table {
        let response = wire.call(name, args.clone()).await;
        assert!(
            !response.to_string().contains("Invalid tool arguments"),
            "audit row must reach its handler: {name}"
        );
        if response.get("result").is_some() && response["result"]["isError"] != true {
            successful_reads += 1;
        }
        let mut confirmed = args.clone();
        confirmed["confirm"] = json!(true);
        wire.call(name, confirmed).await;
        let schema = tools.iter().find(|tool| tool["name"] == *name).unwrap();
        if let Some(properties) = schema["inputSchema"]["properties"].as_object() {
            for field in properties.keys() {
                let mut hostile = args.clone();
                // Wrong-type values must not escape through serde/rmcp errors.
                hostile[field] = json!({marker.clone():marker});
                wire.call(name, hostile).await;
                let mut pasted = args.clone();
                pasted[field] = json!(secret);
                let refused = wire.call(name, pasted).await;
                assert!(
                    refused.get("error").is_some(),
                    "credential-shaped input must be refused: {name}"
                );
            }
        }
        let mut unknown = args.clone();
        unknown[&marker] = json!(marker);
        wire.call(name, unknown).await;
    }
    assert!(
        successful_reads >= 20,
        "catalog test must exercise successful read paths"
    );
    for (name, args) in [
        ("phantom_doctor", json!({"fix":true,"confirm":true})),
        (
            "phantom_audit_hotspot_alerts",
            json!({"ack":true,"confirm":true}),
        ),
        (
            "phantom_audit_alerts",
            json!({"backfill":true,"confirm":true}),
        ),
        (
            "phantom_audit_export_report",
            json!({"save":true,"confirm":true}),
        ),
        (
            "phantom_validation_schedule",
            json!({"interval":"daily","confirm":true}),
        ),
    ] {
        assert!(
            wire.call(name, args).await.get("error").is_some(),
            "effect must remain denied: {name}"
        );
    }
    // A rejected enum is quoted by serde even when it is an opaque string.
    wire.call(
        "phantom_do",
        json!({"phase":marker,"action":{"action":"cargo_check","cwd":"."}}),
    )
    .await;
    // Invalid free-text selectors must never quote their rejected values.
    for (name, field) in [
        ("phantom_audit_stats", "period"),
        ("phantom_audit_anomalies", "period"),
        ("phantom_audit_analytics", "format"),
        ("phantom_audit_export_report", "format"),
        ("phantom_audit_export_report", "action"),
        ("phantom_audit_export_report", "from"),
        ("phantom_audit_export_report", "to"),
    ] {
        wire.call(name, json!({field:marker})).await;
    }
    wire.call(
        "phantom_validation_schedule",
        json!({"interval":format!("{marker}h"),"confirm":true}),
    )
    .await;
    // Corrupt persisted schedule data can quote opaque credentials in a serde
    // error. Both schedule and history expose these errors through MCP.
    let schedule_path = home
        .path()
        .join(".phantom")
        .join(config.local_project_id())
        .join("validation-state.json");
    std::fs::create_dir_all(schedule_path.parent().unwrap()).unwrap();
    std::fs::write(&schedule_path, json!({"last_run_at":marker}).to_string()).unwrap();
    wire.call("phantom_validation_schedule", json!({})).await;
    wire.call("phantom_validation_history", json!({})).await;
    std::fs::remove_file(schedule_path).unwrap();
    // The decrypted payload itself may fail serde decoding. All tools must
    // retain the value-blind boundary even when a backend returns that error.
    let vault_path = home
        .path()
        .join(".phantom/vaults")
        .join(format!("{}.vault", config.local_project_id()));
    let before = std::fs::read(&vault_path).unwrap();
    let corrupt =
        phantom_vault::crypto::encrypt(json!(marker).to_string().as_bytes(), &passphrase).unwrap();
    std::fs::write(&vault_path, corrupt).unwrap();
    for (name, args) in &table {
        wire.call(name, args.clone()).await;
    }
    std::fs::write(vault_path, before).unwrap();
    // Inspect config parse failures through every tool, not only doctor.
    std::fs::write(
        &config_path,
        format!("[phantom]\nproject_id=\"audit\"\ntoken=\"{secret}\" oops\n"),
    )
    .unwrap();
    for (name, args) in &table {
        wire.call(name, args.clone()).await;
    }
    drop(wire.input);
    let status = tokio::time::timeout(Duration::from_secs(10), wire.child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "MCP server must shut down cleanly");
    let stderr = stderr_task.await.unwrap();
    assert!(
        !String::from_utf8_lossy(&stderr).contains(&marker),
        "canary disclosed on MCP stderr"
    );
}
