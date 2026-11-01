use assert_cmd::Command;
use serde_json::{json, Value};

fn feed(input: Vec<u8>) -> Vec<Value> {
    let home = tempfile::tempdir().unwrap();
    let result = Command::new(assert_cmd::cargo::cargo_bin!("phantom"))
        .env("HOME", home.path())
        .args(["--json", "audit", "feed"])
        .write_stdin(input)
        .assert()
        .success()
        .get_output()
        .clone();
    assert!(result.stderr.is_empty());
    String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn source_strings_never_reach_output() {
    let sentinel = "synthetic-secret-phm_fixture-do-not-forward";
    let mut input = Vec::new();
    // Exercise every accepted operation plus an attacker-controlled label.
    for op in [
        "vault.store",
        "vault.retrieve",
        "vault.delete",
        "cloud.push",
        "cloud.pull",
        "proxy.response_leak",
        sentinel,
    ] {
        let event = json!({"seq": 1, "ts": 42, "op": op,
            "name": sentinel, "value": sentinel, "context": {"nested": sentinel},
            "encrypted_context": sentinel, "hmac": sentinel, "process": sentinel});
        input.extend(serde_json::to_vec(&event).unwrap());
        input.push(b'\n');
    }
    let events = feed(input);
    assert_eq!(events.len(), 7);
    for event in &events {
        assert_eq!(event.as_object().unwrap().len(), 5);
        assert_eq!(event["schema_version"], 1);
        assert_eq!(event["type"], "phantom.audit");
        assert_eq!(event["seq"], 1);
        assert_eq!(event["ts"], 42);
        assert!(!event.to_string().contains(sentinel));
    }
    assert_eq!(events[6]["operation"], "unknown");
}

#[test]
fn partial_malformed_and_oversized_records_are_discarded_and_recovery_works() {
    let valid = b"{\"seq\":2,\"ts\":3,\"op\":\"vault.store\"}\n";
    let mut input = b"not json\n{\"seq\":\"text\",\"ts\":1,\"op\":\"vault.store\"}\n".to_vec();
    input.extend(vec![b'x'; 70_000]);
    input.push(b'\n');
    input.extend_from_slice(valid);
    input.extend_from_slice(b"{\"seq\":3,");
    let events = feed(input);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["seq"], 2);
    // A complete JSON object without a newline is still an incomplete record.
    assert!(feed(valid[..valid.len() - 1].to_vec()).is_empty());
    assert!(feed(Vec::new()).is_empty());
}
