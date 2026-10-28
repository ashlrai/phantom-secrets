//! Process-boundary regression tests: the fake Locus emits value-free status
//! JSON, while Phantom retains its real configuration and approval checks.
#![cfg(unix)]

use super::*;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _guard: phantom_core::ProcessEnvGuard,
    home: tempfile::TempDir,
    previous: Vec<(OsString, Option<OsString>)>,
}

impl Fixture {
    fn new() -> Self {
        let guard = phantom_core::PROCESS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut keys = vec![
            OsString::from("HOME"),
            OsString::from("USERPROFILE"),
            OsString::from("PATH"),
            OsString::from("PHANTOM_MCP_EFFECTS"),
            OsString::from("PHANTOM_MCP_SKIP_APPROVAL"),
            OsString::from("PHANTOM_VAULT_PASSPHRASE"),
            OsString::from("PHANTOM_REQUIRE_KEYCHAIN"),
        ];
        keys.extend(
            std::env::vars_os()
                .filter_map(|(key, _)| key.to_string_lossy().starts_with("LOCUS_").then_some(key)),
        );
        let previous = keys
            .into_iter()
            .map(|key| {
                let value = std::env::var_os(&key);
                // Serialized with the same process lock as existing MCP tests.
                unsafe { std::env::remove_var(&key) };
                (key, value)
            })
            .collect();
        let bin = home.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let executable = bin.join("locus");
        std::fs::write(
            &executable,
            "#!/bin/sh\n[ \"$1\" = status ] && [ \"$2\" = --json ] && [ \"$#\" = 2 ] || exit 23\n/bin/cat \"$HOME/status.json\"\n",
        )
        .unwrap();
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("USERPROFILE", home.path());
            std::env::set_var("PATH", bin);
        }
        let fixture = Self {
            _guard: guard,
            home,
            previous,
        };
        fixture.status(pinned());
        fixture
    }

    fn status(&self, value: Value) {
        std::fs::write(
            self.home.path().join("status.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    fn project(&self, name: &str, binding: Option<(&str, &str)>) -> PhantomMcpServer {
        let dir = self.home.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        let mut config = PhantomConfig::new_with_defaults(name.to_string());
        config.phantom.locus = binding.map(|(binding, tenant)| phantom_core::locus::LocusBinding {
            binding: binding.to_string(),
            tenant: tenant.to_string(),
        });
        config.save(&dir.join(".phantom.toml")).unwrap();
        PhantomMcpServer::with_dir(dir)
    }

    fn assert_no_effects(&self) {
        assert!(
            !self.home.path().join(".phantom").exists(),
            "a refused call created approval or vault state"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

fn pinned() -> Value {
    json!({
        "pinned": true, "binding": "acme", "tenant": "acme-tenant",
        "seal_ok": true, "frozen": false, "expired": false,
        "ok": true, "authority_verified": true, "require_pin": false
    })
}

fn params<T: DeserializeOwned>(extra: Value) -> Parameters<T> {
    let mut value = json!({"confirm": true});
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    Parameters(serde_json::from_value(value).unwrap())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn assert_mismatch(result: Result<CallToolResult, McpError>) {
    let error = result.expect_err("cross-binding operation reached its existing effect path");
    assert!(
        error.message.contains("Locus binding mismatch"),
        "{}",
        error.message
    );
    assert!(!error.message.contains("out-of-band approval"));
}

#[test]
fn locus_all_provider_handlers_refuse_cross_binding_before_effects() {
    let fixture = Fixture::new();
    let server = fixture.project("other", Some(("other", "other-tenant")));
    runtime().block_on(async {
        assert_mismatch(server.phantom_cloud_push(params(json!({}))).await);
        assert_mismatch(
            server
                .phantom_cloud_pull(params(json!({"force": false})))
                .await,
        );
        assert_mismatch(server.phantom_cloud_status(params(json!({}))).await);
        assert_mismatch(server.phantom_team_list(params(json!({}))).await);
        assert_mismatch(
            server
                .phantom_team_create(params(json!({"name": "test-team"})))
                .await,
        );
        assert_mismatch(
            server
                .phantom_team_members(params(json!({"team_id": "team-test"})))
                .await,
        );
        assert_mismatch(
            server
                .phantom_team_invite(params(
                    json!({"team_id": "team-test", "github_login": "test-user"}),
                ))
                .await,
        );
        assert_mismatch(
            server
                .phantom_team_key_publish(params(json!({"team_id": "team-test"})))
                .await,
        );
        assert_mismatch(
            server
                .phantom_team_vault_push(params(json!({"team_id": "team-test"})))
                .await,
        );
        assert_mismatch(
            server
                .phantom_team_vault_pull(params(json!({"team_id": "team-test"})))
                .await,
        );
    });
    assert_mismatch(server.phantom_validate_all(params(json!({"jobs": 1}))));
    assert_mismatch(server.phantom_audit_alerts(params(json!({"backfill": true}))));
    assert_mismatch(server.phantom_copy_secret(params(
        json!({"name": "TEST_KEY", "target_dir": "does-not-exist", "rename": null}),
    )));
    fixture.assert_no_effects();
}

fn assert_ambient_refused(result: Result<CallToolResult, McpError>) {
    let error = result.expect_err("project metadata authorized an ambient provider identity");
    assert!(
        error
            .message
            .contains("ambient Cloud or notification identity"),
        "{}",
        error.message
    );
    assert!(error.message.contains("binding cannot be verified"));
    assert!(!error.message.contains("out-of-band approval"));
}

#[test]
fn locus_matching_project_cannot_authorize_ambient_credentials() {
    let fixture = Fixture::new();
    let server = fixture.project("matching", Some(("acme", "acme-tenant")));
    runtime().block_on(async {
        assert_ambient_refused(server.phantom_cloud_push(params(json!({}))).await);
        assert_ambient_refused(
            server
                .phantom_cloud_pull(params(json!({"force": false})))
                .await,
        );
        assert_ambient_refused(server.phantom_cloud_status(params(json!({}))).await);
        assert_ambient_refused(server.phantom_team_list(params(json!({}))).await);
        assert_ambient_refused(
            server
                .phantom_team_create(params(json!({"name": "test-team"})))
                .await,
        );
        assert_ambient_refused(
            server
                .phantom_team_members(params(json!({"team_id": "team-test"})))
                .await,
        );
        assert_ambient_refused(
            server
                .phantom_team_invite(params(
                    json!({"team_id": "team-test", "github_login": "test-user"}),
                ))
                .await,
        );
        assert_ambient_refused(
            server
                .phantom_team_key_publish(params(json!({"team_id": "team-test"})))
                .await,
        );
        assert_ambient_refused(
            server
                .phantom_team_vault_push(params(json!({"team_id": "team-test"})))
                .await,
        );
        assert_ambient_refused(
            server
                .phantom_team_vault_pull(params(json!({"team_id": "team-test"})))
                .await,
        );
    });
    assert_ambient_refused(server.phantom_audit_alerts(params(json!({"backfill": true}))));
    let error = runtime()
        .block_on(server.phantom_team_list(params(json!({"confirm": false}))))
        .unwrap_err();
    assert!(error.message.contains("confirm"));
    assert!(!error.message.contains("Locus"));
    fixture.assert_no_effects();
}

#[test]
fn locus_matching_project_validation_reaches_existing_approval_gate() {
    let fixture = Fixture::new();
    let server = fixture.project("matching", Some(("acme", "acme-tenant")));
    // Explicit file-backend selection: no OS keychain or real credentials are
    // accessed, and an empty vault is sufficient to reach the approval gate.
    unsafe {
        std::env::set_var("PHANTOM_VAULT_PASSPHRASE", "locus-test-only-file-vault");
    }
    let error = server
        .phantom_validate_all(params(json!({"jobs": 1})))
        .unwrap_err();
    assert!(
        error.message.contains("PHANTOM_MCP_EFFECTS"),
        "{}",
        error.message
    );
    assert!(error.message.contains("out-of-band approval"));
    assert!(!error.message.contains("Locus"));
    assert!(!fixture
        .home
        .path()
        .join(".phantom/mcp-approvals.jsonl")
        .exists());
    let error = server
        .phantom_validate_all(params(json!({"jobs": 1, "confirm": false})))
        .unwrap_err();
    assert!(error.message.contains("confirm"));
}

#[test]
fn locus_pin_requires_both_project_binding_and_tenant() {
    let fixture = Fixture::new();
    for (name, binding) in [
        ("unbound", None),
        ("wrong-binding", Some(("other", "acme-tenant"))),
        ("wrong-tenant", Some(("acme", "other-tenant"))),
    ] {
        let server = fixture.project(name, binding);
        assert_mismatch(runtime().block_on(server.phantom_team_list(params(json!({})))));
    }
    let absent = PhantomMcpServer::with_dir(fixture.home.path().join("absent"));
    assert_mismatch(runtime().block_on(absent.phantom_team_list(params(json!({})))));
    fixture.assert_no_effects();
}

#[test]
fn locus_absent_or_unpinned_preserves_existing_behavior() {
    let fixture = Fixture::new();
    let server = fixture.project("unbound", None);
    fixture.status(json!({"pinned": false, "require_pin": false}));
    assert_eq!(server.require_locus_binding().unwrap(), None);
    let unpinned = runtime()
        .block_on(server.phantom_team_list(params(json!({}))))
        .unwrap_err();
    std::fs::remove_file(fixture.home.path().join("bin/locus")).unwrap();
    assert_eq!(server.require_locus_binding().unwrap(), None);
    let absent = runtime()
        .block_on(server.phantom_team_list(params(json!({}))))
        .unwrap_err();
    assert_eq!(unpinned.message, absent.message);
    assert!(absent.message.contains("PHANTOM_MCP_EFFECTS"));
    fixture.assert_no_effects();
}

#[test]
fn locus_rechecks_pin_and_project_metadata_before_effects() {
    let fixture = Fixture::new();
    let server = fixture.project("matching", Some(("acme", "acme-tenant")));
    let expected = server.require_locus_binding().unwrap();
    fixture.status(json!({"pinned": false, "require_pin": false}));
    assert!(server
        .recheck_locus_binding(&expected)
        .unwrap_err()
        .message
        .contains("pin changed"));
    fixture.status(pinned());
    let mut config = PhantomConfig::load(&server.config_path()).unwrap();
    config.phantom.locus = None;
    config.save(&server.config_path()).unwrap();
    assert!(server
        .recheck_locus_binding(&expected)
        .unwrap_err()
        .message
        .contains("binding mismatch"));
    fixture.assert_no_effects();
}

#[test]
fn locus_unhealthy_or_malformed_status_is_refused_without_echoing_output() {
    let fixture = Fixture::new();
    let server = fixture.project("matching", Some(("acme", "acme-tenant")));
    for (field, value) in [
        ("seal_ok", false),
        ("frozen", true),
        ("expired", true),
        ("ok", false),
        ("authority_verified", false),
    ] {
        let mut status = pinned();
        status[field] = value.into();
        status["binding"] = "OUTPUT_MUST_NOT_BE_REFLECTED".into();
        fixture.status(status);
        let error = runtime()
            .block_on(server.phantom_team_list(params(json!({}))))
            .unwrap_err();
        assert!(error.message.contains("Locus"));
        assert!(!error.message.contains("OUTPUT_MUST_NOT_BE_REFLECTED"));
        assert!(!error.message.contains("PHANTOM_MCP_EFFECTS"));
    }
    std::fs::write(
        fixture.home.path().join("status.json"),
        "OUTPUT_MUST_NOT_BE_REFLECTED",
    )
    .unwrap();
    let error = server.require_locus_binding().unwrap_err();
    assert!(!error.message.contains("OUTPUT_MUST_NOT_BE_REFLECTED"));
    fixture.assert_no_effects();
}

#[test]
fn locus_copy_checks_target_binding_before_opening_either_vault() {
    let fixture = Fixture::new();
    let source = fixture.project("source", Some(("acme", "acme-tenant")));
    let target = fixture.project("target", Some(("other", "other-tenant")));
    let before = std::fs::read(target.config_path()).unwrap();
    assert_mismatch(source.phantom_copy_secret(params(json!({
        "name": "TEST_KEY", "target_dir": target.project_dir, "rename": null
    }))));
    assert_eq!(std::fs::read(target.config_path()).unwrap(), before);
    fixture.assert_no_effects();
}

#[test]
fn locus_unhealthy_pin_does_not_block_local_value_free_status() {
    let fixture = Fixture::new();
    fixture.status(json!({"pinned": true, "frozen": true}));
    let server = fixture.project("local", None);
    let result = server.phantom_status().unwrap();
    assert_ne!(result.is_error, Some(true));
    fixture.assert_no_effects();
}

#[test]
fn locus_missing_executable_cannot_bypass_a_persisted_pin() {
    let fixture = Fixture::new();
    let server = fixture.project("matching", Some(("acme", "acme-tenant")));
    std::fs::remove_file(fixture.home.path().join("bin/locus")).unwrap();
    let sessions = fixture.home.path().join(".locus/sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    // No payload is needed: Phantom must never parse the sealed session file.
    std::fs::write(sessions.join("active.json"), b"").unwrap();
    assert!(server
        .require_locus_binding()
        .unwrap_err()
        .message
        .contains("Locus status unavailable"));
    fixture.assert_no_effects();
}
