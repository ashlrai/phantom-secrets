//! Hermetic tests for the account-ops layer. No network, no real
//! credentials: a fake provider, a fake GitHub transport, and a runtime
//! generated throwaway RSA key.

use super::github_app::{GithubAppInstallationProvider, HttpReply, HttpTransport, Method};
use super::*;
use std::cell::RefCell;
use std::rc::Rc;

/// Distinctive fake values. Any appearance in output is a leak.
const CANARY: &str = "canary-fake-issued-value-5d1e9b";
const STORED_CANARY: &str = "canary-fake-stored-value-a77c40";
const GH_CANARY: &str = "canary-fake-installation-token-3f08";

// ── Fakes ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct FakeLog {
    plans: usize,
    executes: usize,
    compensated_with_issued: usize,
    compensate_calls: usize,
}

struct FakeProvider {
    log: Rc<RefCell<FakeLog>>,
    fail_execute: bool,
    fail_compensate: bool,
    /// Create the KILL file during `plan` to exercise the pre-call re-check.
    kill_on_plan: Option<PathBuf>,
    supports_revoke: bool,
}

impl FakeProvider {
    fn new(log: Rc<RefCell<FakeLog>>) -> Self {
        Self {
            log,
            fail_execute: false,
            fail_compensate: false,
            kill_on_plan: None,
            supports_revoke: true,
        }
    }
}

impl AccountProvider for FakeProvider {
    fn name(&self) -> &str {
        "fake"
    }
    fn supports(&self, op: AccountOp) -> bool {
        op != AccountOp::Revoke || self.supports_revoke
    }
    fn plan(&self, _req: &OpRequest) -> Result<BTreeMap<String, String>, OpError> {
        self.log.borrow_mut().plans += 1;
        if let Some(p) = &self.kill_on_plan {
            std::fs::write(p, b"").unwrap();
        }
        let mut m = BTreeMap::new();
        m.insert("call".into(), "fake.issue".into());
        Ok(m)
    }
    fn execute(
        &self,
        req: &OpRequest,
        creds: &dyn CredentialSource,
    ) -> Result<ProviderReply, OpError> {
        self.log.borrow_mut().executes += 1;
        if self.fail_execute {
            return Err(OpError::new("fake provider refused"));
        }
        match req.op {
            AccountOp::Create | AccountOp::Rotate => {
                let mut metadata = BTreeMap::new();
                metadata.insert("expires_at".into(), "2026-11-09T08:00:00Z".into());
                Ok(ProviderReply::Issued(Issued {
                    value: Zeroizing::new(CANARY.to_string()),
                    metadata,
                }))
            }
            AccountOp::Revoke => {
                let stored = creds.read(&req.secret_name)?;
                assert_eq!(stored.as_str(), STORED_CANARY);
                Ok(ProviderReply::Done(BTreeMap::new()))
            }
            AccountOp::Status => {
                let mut m = BTreeMap::new();
                m.insert("active".into(), "true".into());
                Ok(ProviderReply::Done(m))
            }
        }
    }
    fn compensate(&self, _req: &OpRequest, issued: &Zeroizing<String>) -> Result<(), OpError> {
        let mut log = self.log.borrow_mut();
        log.compensate_calls += 1;
        if issued.as_str() == CANARY {
            log.compensated_with_issued += 1;
        }
        if self.fail_compensate {
            Err(OpError::new("fake revoke failed"))
        } else {
            Ok(())
        }
    }
}

struct FakeCreds {
    pem: Option<Zeroizing<String>>,
}

impl CredentialSource for FakeCreds {
    fn read(&self, name: &str) -> Result<Zeroizing<String>, OpError> {
        match name {
            "GITHUB_APP_PEM" => self.pem.clone().ok_or_else(|| OpError::new("pem missing")),
            "GH_INSTALL_TOKEN" => Ok(Zeroizing::new(GH_CANARY.to_string())),
            _ => Ok(Zeroizing::new(STORED_CANARY.to_string())),
        }
    }
}

#[derive(Default)]
struct FakeSink {
    stored: Vec<(String, Zeroizing<String>)>,
    fail: bool,
    echo_value_in_error: bool,
}

impl ValueSink for FakeSink {
    fn store(&mut self, name: &str, value: Zeroizing<String>) -> Result<(), OpError> {
        if self.echo_value_in_error {
            return Err(OpError::new(format!("bad sink saw {}", value.as_str())));
        }
        if self.fail {
            return Err(OpError::new("vault is locked"));
        }
        self.stored.push((name.to_string(), value));
        Ok(())
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    kill: PathBuf,
    ledger: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let kill = dir.path().join("ashlr").join("KILL");
    std::fs::create_dir_all(kill.parent().unwrap()).unwrap();
    let ledger = dir.path().join("phantom").join("account-ops.jsonl");
    Fixture {
        _dir: dir,
        kill,
        ledger,
    }
}

fn req(op: AccountOp) -> OpRequest {
    OpRequest {
        actor: "security-lane".into(),
        op,
        provider: "fake".into(),
        target: "acct:demo".into(),
        secret_name: "DEMO_TOKEN".into(),
    }
}

fn engine(fx: &Fixture, provider: FakeProvider) -> AccountOps {
    let mut ops = AccountOps::new(&fx.kill, OpsLedger::new(&fx.ledger));
    ops.register(Box::new(provider));
    ops
}

fn creds() -> FakeCreds {
    FakeCreds { pem: None }
}

fn ledger_text(fx: &Fixture) -> String {
    std::fs::read_to_string(&fx.ledger).unwrap_or_default()
}

fn assert_no_canary(haystack: &str, what: &str) {
    for c in [CANARY, STORED_CANARY, GH_CANARY] {
        assert!(!haystack.contains(c), "{what} leaked a value");
    }
}

// ── Engine tests ────────────────────────────────────────────────────────────

#[test]
fn dry_run_is_the_default_and_never_calls_the_provider() {
    assert_eq!(ExecMode::default(), ExecMode::DryRun);
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log.clone()));
    let mut sink = FakeSink::default();
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::default(),
        &creds(),
        &mut sink,
    );
    assert_eq!(out.result, OpResult::DryRun);
    assert_eq!(log.borrow().executes, 0);
    assert!(sink.stored.is_empty());
    assert!(out.handle.as_str().starts_with("aop_"));
    assert_eq!(ops.ledger().verify().unwrap(), 2);
}

#[test]
fn kill_file_refuses_before_any_provider_call() {
    let fx = fixture();
    std::fs::write(&fx.kill, b"").unwrap();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log.clone()));
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds(),
        &mut FakeSink::default(),
    );
    assert!(matches!(out.result, OpResult::Refused { ref reason } if reason.contains("KILL")));
    assert_eq!(log.borrow().plans, 0);
    assert_eq!(log.borrow().executes, 0);
    assert!(out.audited);
    assert!(ledger_text(&fx).contains("\"refused\""));
}

#[cfg(unix)]
#[test]
fn kill_as_dangling_symlink_or_directory_still_refuses() {
    let fx = fixture();
    std::os::unix::fs::symlink(fx.kill.with_extension("missing"), &fx.kill).unwrap();
    assert!(check_kill(&fx.kill).is_err());
    std::fs::remove_file(&fx.kill).unwrap();
    std::fs::create_dir(&fx.kill).unwrap();
    assert!(check_kill(&fx.kill).is_err());
}

#[test]
fn undeterminable_kill_state_fails_closed() {
    let fx = fixture();
    // A regular file where a directory is expected gives ENOTDIR, not NotFound.
    let blocker = fx.kill.parent().unwrap().join("not-a-dir");
    std::fs::write(&blocker, b"").unwrap();
    let err = check_kill(&blocker.join("KILL")).unwrap_err();
    assert!(err.reason.contains("could not be determined"));
    assert!(check_kill(&fx.kill).is_ok());
}

#[test]
fn kill_set_after_planning_is_caught_before_the_call() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let mut p = FakeProvider::new(log.clone());
    p.kill_on_plan = Some(fx.kill.clone());
    let ops = engine(&fx, p);
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds(),
        &mut FakeSink::default(),
    );
    assert!(matches!(out.result, OpResult::Refused { .. }));
    assert_eq!(log.borrow().plans, 1);
    assert_eq!(log.borrow().executes, 0);
}

#[test]
fn unwritable_ledger_refuses_before_the_provider_call() {
    let fx = fixture();
    std::fs::create_dir_all(&fx.ledger).unwrap(); // a directory, not a file
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log.clone()));
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds(),
        &mut FakeSink::default(),
    );
    assert!(matches!(out.result, OpResult::Refused { ref reason } if reason.contains("ledger")));
    assert!(!out.audited);
    assert_eq!(log.borrow().executes, 0);
}

#[test]
fn execute_stores_value_only_in_the_sink_and_audits_intent_then_result() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log.clone()));
    let mut sink = FakeSink::default();
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds(),
        &mut sink,
    );
    assert_eq!(out.result, OpResult::Succeeded);
    assert!(out.audited);
    assert_eq!(sink.stored.len(), 1);
    assert_eq!(sink.stored[0].0, "DEMO_TOKEN");
    assert_eq!(sink.stored[0].1.as_str(), CANARY);
    assert_eq!(
        out.metadata.get("expires_at").unwrap(),
        "2026-11-09T08:00:00Z"
    );

    let text = ledger_text(&fx);
    assert_no_canary(&text, "ledger");
    assert_no_canary(&format!("{out:?}"), "outcome Debug");
    assert_no_canary(&serde_json::to_string(&out).unwrap(), "outcome JSON");
    let lines: Vec<LedgerEntry> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].phase, "intent");
    assert_eq!(lines[0].result, "pending");
    assert_eq!(lines[1].phase, "result");
    assert_eq!(lines[1].result, "succeeded");
    assert_eq!(lines[0].handle, out.handle.as_str());
    assert_eq!(lines[1].handle, out.handle.as_str());
    assert_eq!(lines[1].actor, "security-lane");
    assert_eq!(lines[1].provider, "fake");
    assert!(lines[1].ts > 0);
    assert_eq!(ops.ledger().verify().unwrap(), 2);
}

#[test]
fn store_failure_triggers_a_compensating_revoke_of_the_issued_value() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log.clone()));
    let mut sink = FakeSink {
        fail: true,
        ..Default::default()
    };
    let out = ops.run(
        &req(AccountOp::Create),
        ExecMode::Execute,
        &creds(),
        &mut sink,
    );
    assert!(
        matches!(out.result, OpResult::Compensated { ref reason } if reason.contains("vault is locked"))
    );
    assert_eq!(log.borrow().compensated_with_issued, 1);
    assert!(ledger_text(&fx).contains("\"compensated\""));
}

#[test]
fn failed_compensation_is_reported_with_the_handle() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let mut p = FakeProvider::new(log.clone());
    p.fail_compensate = true;
    let ops = engine(&fx, p);
    let mut sink = FakeSink {
        fail: true,
        ..Default::default()
    };
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds(),
        &mut sink,
    );
    assert!(matches!(out.result, OpResult::CompensationFailed { .. }));
    let text = ledger_text(&fx);
    assert!(text.contains("compensation-failed"));
    assert!(text.contains(out.handle.as_str()));
}

#[test]
fn a_reason_that_echoes_the_value_is_withheld() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log));
    let mut sink = FakeSink {
        echo_value_in_error: true,
        ..Default::default()
    };
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds(),
        &mut sink,
    );
    assert_no_canary(&format!("{out:?}"), "outcome");
    assert_no_canary(&ledger_text(&fx), "ledger");
    assert!(format!("{out:?}").contains("withheld"));
}

#[test]
fn provider_failure_is_failed_not_succeeded() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let mut p = FakeProvider::new(log.clone());
    p.fail_execute = true;
    let ops = engine(&fx, p);
    let mut sink = FakeSink::default();
    let out = ops.run(
        &req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds(),
        &mut sink,
    );
    assert!(matches!(out.result, OpResult::Failed { .. }));
    assert!(sink.stored.is_empty());
    assert_eq!(log.borrow().compensate_calls, 0);
}

#[test]
fn revoke_and_status_return_metadata_only() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log));
    let mut sink = FakeSink::default();
    let out = ops.run(
        &req(AccountOp::Revoke),
        ExecMode::Execute,
        &creds(),
        &mut sink,
    );
    assert_eq!(out.result, OpResult::Succeeded);
    let out = ops.run(
        &req(AccountOp::Status),
        ExecMode::Execute,
        &creds(),
        &mut sink,
    );
    assert_eq!(out.metadata.get("active").unwrap(), "true");
    assert!(sink.stored.is_empty());
    assert_no_canary(&ledger_text(&fx), "ledger");
}

#[test]
fn unknown_provider_and_unsupported_op_are_refused() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let mut p = FakeProvider::new(log.clone());
    p.supports_revoke = false;
    let ops = engine(&fx, p);
    let mut r = req(AccountOp::Rotate);
    r.provider = "nope".into();
    let out = ops.run(&r, ExecMode::Execute, &creds(), &mut FakeSink::default());
    assert!(matches!(out.result, OpResult::Refused { .. }));
    let out = ops.run(
        &req(AccountOp::Revoke),
        ExecMode::Execute,
        &creds(),
        &mut FakeSink::default(),
    );
    assert!(matches!(out.result, OpResult::Refused { .. }));
    assert_eq!(log.borrow().executes, 0);
}

#[test]
fn value_shaped_request_fields_are_refused_and_never_written() {
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log.clone()));
    for mutate in [
        |r: &mut OpRequest| r.secret_name = "demo token".into(),
        |r: &mut OpRequest| r.target = "acct demo=secret value".into(),
        |r: &mut OpRequest| r.actor = String::new(),
        |r: &mut OpRequest| r.target = "x".repeat(MAX_FIELD_LEN + 1),
    ] {
        let mut r = req(AccountOp::Rotate);
        mutate(&mut r);
        let out = ops.run(&r, ExecMode::Execute, &creds(), &mut FakeSink::default());
        assert!(matches!(out.result, OpResult::Refused { .. }));
        assert!(!out.audited);
    }
    assert_eq!(log.borrow().plans, 0);
    assert_eq!(ledger_text(&fx), "");
}

#[test]
fn ledger_tampering_is_detected() {
    let fx = fixture();
    let ops = engine(
        &fx,
        FakeProvider::new(Rc::new(RefCell::new(FakeLog::default()))),
    );
    for _ in 0..2 {
        ops.run(
            &req(AccountOp::Status),
            ExecMode::DryRun,
            &creds(),
            &mut FakeSink::default(),
        );
    }
    assert_eq!(ops.ledger().verify().unwrap(), 4);
    let text = ledger_text(&fx).replacen("security-lane", "someone-else", 1);
    std::fs::write(&fx.ledger, text).unwrap();
    assert!(ops.ledger().verify().is_err());
    // Deleting a line also breaks the chain.
    let fx2 = fixture();
    let ops2 = engine(
        &fx2,
        FakeProvider::new(Rc::new(RefCell::new(FakeLog::default()))),
    );
    for _ in 0..2 {
        ops2.run(
            &req(AccountOp::Status),
            ExecMode::DryRun,
            &creds(),
            &mut FakeSink::default(),
        );
    }
    let full = ledger_text(&fx2);
    let kept: Vec<&str> = full.lines().skip(1).collect();
    std::fs::write(&fx2.ledger, kept.join("\n") + "\n").unwrap();
    assert!(ops2.ledger().verify().is_err());
}

#[cfg(unix)]
#[test]
fn ledger_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let fx = fixture();
    let ops = engine(
        &fx,
        FakeProvider::new(Rc::new(RefCell::new(FakeLog::default()))),
    );
    ops.run(
        &req(AccountOp::Status),
        ExecMode::DryRun,
        &creds(),
        &mut FakeSink::default(),
    );
    let mode = std::fs::metadata(&fx.ledger).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ── GitHub App adapter with a fake transport ───────────────────────────────

#[derive(Default)]
struct WireLog {
    calls: Vec<(Method, String, String, Option<String>)>,
}

struct FakeGithub {
    log: Rc<RefCell<WireLog>>,
    mint_status: u16,
}

impl HttpTransport for FakeGithub {
    fn send(
        &self,
        method: Method,
        path: &str,
        bearer: &Zeroizing<String>,
        body: Option<&str>,
    ) -> Result<HttpReply, OpError> {
        self.log.borrow_mut().calls.push((
            method,
            path.to_string(),
            bearer.as_str().to_string(),
            body.map(str::to_string),
        ));
        let (status, json) = match (method, path) {
            (Method::Post, p) if p.ends_with("/access_tokens") => {
                if self.mint_status == 201 {
                    (
                        201,
                        format!(
                            r#"{{"token":"{GH_CANARY}","expires_at":"2026-11-09T08:00:00Z","repository_selection":"selected","permissions":{{"contents":"write","metadata":"read"}}}}"#
                        ),
                    )
                } else {
                    (
                        self.mint_status,
                        format!(
                            r#"{{"message":"Bad credentials {GH_CANARY}","status":"401"}}"#
                        ),
                    )
                }
            }
            (Method::Delete, "/installation/token") => (204, String::new()),
            (Method::Get, p) if p.starts_with("/app/installations/") => (
                200,
                r#"{"app_slug":"ashlr-release","target_type":"Organization","repository_selection":"selected","suspended_at":null}"#
                    .to_string(),
            ),
            _ => (404, "{}".to_string()),
        };
        Ok(HttpReply {
            status,
            body: Zeroizing::new(json.into_bytes()),
        })
    }
}

fn test_pem() -> Zeroizing<String> {
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    Zeroizing::new(
        PEM.get_or_init(|| {
            let mut rng = rand::thread_rng();
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
            key.to_pkcs1_pem(LineEnding::LF)
                .expect("serialize PKCS#1 PEM")
                .to_string()
        })
        .clone(),
    )
}

fn gh_engine(fx: &Fixture, mint_status: u16) -> (AccountOps, Rc<RefCell<WireLog>>) {
    let wire = Rc::new(RefCell::new(WireLog::default()));
    let mut ops = AccountOps::new(&fx.kill, OpsLedger::new(&fx.ledger));
    ops.register(Box::new(GithubAppInstallationProvider::new(
        "Iv1.testclient",
        "GITHUB_APP_PEM",
        Box::new(FakeGithub {
            log: wire.clone(),
            mint_status,
        }),
    )));
    (ops, wire)
}

fn gh_req(op: AccountOp) -> OpRequest {
    OpRequest {
        actor: "security-lane".into(),
        op,
        provider: "github-app".into(),
        target: "installation:4242".into(),
        secret_name: "GH_INSTALL_TOKEN".into(),
    }
}

#[test]
fn github_dry_run_plans_the_documented_call_without_wire_traffic() {
    let fx = fixture();
    let (ops, wire) = gh_engine(&fx, 201);
    let creds = FakeCreds { pem: None };
    let out = ops.run(
        &gh_req(AccountOp::Rotate),
        ExecMode::DryRun,
        &creds,
        &mut FakeSink::default(),
    );
    assert_eq!(out.result, OpResult::DryRun);
    assert_eq!(
        out.metadata.get("call").unwrap(),
        "POST /app/installations/4242/access_tokens"
    );
    assert_eq!(out.metadata.get("ttl_secs").unwrap(), "3600");
    assert!(wire.borrow().calls.is_empty());
}

#[test]
fn github_rotate_mints_with_an_app_jwt_and_hands_the_token_to_the_sink() {
    let fx = fixture();
    let (ops, wire) = gh_engine(&fx, 201);
    let creds = FakeCreds {
        pem: Some(test_pem()),
    };
    let mut sink = FakeSink::default();
    let out = ops.run(
        &gh_req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds,
        &mut sink,
    );
    assert_eq!(out.result, OpResult::Succeeded, "{out:?}");
    assert_eq!(sink.stored[0].1.as_str(), GH_CANARY);
    assert_eq!(
        out.metadata.get("expires_at").unwrap(),
        "2026-11-09T08:00:00Z"
    );
    assert_eq!(
        out.metadata.get("repository_selection").unwrap(),
        "selected"
    );
    assert_eq!(
        out.metadata.get("permissions").unwrap(),
        "contents=write,metadata=read"
    );
    let calls = &wire.borrow().calls;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, Method::Post);
    assert_eq!(calls[0].1, "/app/installations/4242/access_tokens");
    assert_eq!(
        calls[0].2.split('.').count(),
        3,
        "bearer must be an App JWT"
    );
    assert_no_canary(&format!("{out:?}"), "outcome");
    assert_no_canary(&ledger_text(&fx), "ledger");
}

#[test]
fn github_store_failure_revokes_the_minted_token() {
    let fx = fixture();
    let (ops, wire) = gh_engine(&fx, 201);
    let creds = FakeCreds {
        pem: Some(test_pem()),
    };
    let mut sink = FakeSink {
        fail: true,
        ..Default::default()
    };
    let out = ops.run(
        &gh_req(AccountOp::Create),
        ExecMode::Execute,
        &creds,
        &mut sink,
    );
    assert!(
        matches!(out.result, OpResult::Compensated { .. }),
        "{out:?}"
    );
    let calls = &wire.borrow().calls;
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].0, Method::Delete);
    assert_eq!(calls[1].1, "/installation/token");
    assert_eq!(calls[1].2, GH_CANARY, "revoke must use the minted token");
}

#[test]
fn github_error_reason_never_includes_the_response_message() {
    let fx = fixture();
    let (ops, _wire) = gh_engine(&fx, 401);
    let creds = FakeCreds {
        pem: Some(test_pem()),
    };
    let out = ops.run(
        &gh_req(AccountOp::Rotate),
        ExecMode::Execute,
        &creds,
        &mut FakeSink::default(),
    );
    let OpResult::Failed { reason } = &out.result else {
        panic!("expected Failed, got {out:?}");
    };
    assert!(reason.contains("HTTP 401"));
    assert!(!reason.contains("Bad credentials"));
    assert_no_canary(reason, "error reason");
}

#[test]
fn github_revoke_uses_the_stored_token_and_status_uses_the_jwt() {
    let fx = fixture();
    let (ops, wire) = gh_engine(&fx, 201);
    let creds = FakeCreds {
        pem: Some(test_pem()),
    };
    let mut sink = FakeSink::default();
    let out = ops.run(
        &gh_req(AccountOp::Revoke),
        ExecMode::Execute,
        &creds,
        &mut sink,
    );
    assert_eq!(out.result, OpResult::Succeeded);
    let out = ops.run(
        &gh_req(AccountOp::Status),
        ExecMode::Execute,
        &creds,
        &mut sink,
    );
    assert_eq!(out.metadata.get("app_slug").unwrap(), "ashlr-release");
    assert_eq!(out.metadata.get("suspended").unwrap(), "false");
    let calls = &wire.borrow().calls;
    assert_eq!(calls[0].1, "/installation/token");
    assert_eq!(calls[0].2, GH_CANARY);
    assert_eq!(calls[1].1, "/app/installations/4242");
    assert_eq!(calls[1].2.split('.').count(), 3);
    assert!(sink.stored.is_empty());
}

#[test]
fn github_target_must_be_a_numeric_installation() {
    let fx = fixture();
    let (ops, wire) = gh_engine(&fx, 201);
    let mut r = gh_req(AccountOp::Rotate);
    r.target = "installation:../../user".into();
    let out = ops.run(
        &r,
        ExecMode::Execute,
        &FakeCreds { pem: None },
        &mut FakeSink::default(),
    );
    assert!(matches!(out.result, OpResult::Refused { .. }));
    assert!(wire.borrow().calls.is_empty());
}

// ── Process-level no-leak check ─────────────────────────────────────────────

const CHILD_ENV: &str = "PHANTOM_ACCOUNT_OPS_LEAK_CHILD";

/// Child half of `no_value_reaches_stdout_stderr_logs_or_audit`. A no-op
/// unless the parent sets `CHILD_ENV`. It drives every path and prints all
/// operator-visible output to stdout and stderr.
#[test]
fn leak_child_scenarios() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let fx = fixture();
    let log = Rc::new(RefCell::new(FakeLog::default()));
    let ops = engine(&fx, FakeProvider::new(log));
    let mut outs = Vec::new();
    for (op, fail) in [
        (AccountOp::Rotate, false),
        (AccountOp::Create, true),
        (AccountOp::Revoke, false),
        (AccountOp::Status, false),
    ] {
        let mut sink = FakeSink {
            fail,
            ..Default::default()
        };
        outs.push(ops.run(&req(op), ExecMode::Execute, &creds(), &mut sink));
        let mut echo = FakeSink {
            echo_value_in_error: true,
            ..Default::default()
        };
        outs.push(ops.run(&req(op), ExecMode::Execute, &creds(), &mut echo));
    }
    let (gh, _) = gh_engine(&fx, 201);
    let gh_creds = FakeCreds {
        pem: Some(test_pem()),
    };
    outs.push(gh.run(
        &gh_req(AccountOp::Rotate),
        ExecMode::Execute,
        &gh_creds,
        &mut FakeSink::default(),
    ));
    let (gh_bad, _) = gh_engine(&fx, 401);
    outs.push(gh_bad.run(
        &gh_req(AccountOp::Rotate),
        ExecMode::Execute,
        &gh_creds,
        &mut FakeSink::default(),
    ));
    for o in &outs {
        println!("{o:?}");
        println!("{}", serde_json::to_string(o).unwrap());
        if let OpResult::Failed { reason }
        | OpResult::Refused { reason }
        | OpResult::Compensated { reason }
        | OpResult::CompensationFailed { reason } = &o.result
        {
            eprintln!("account-ops error: {reason}");
        }
    }
    let ledger = ledger_text(&fx);
    std::fs::write(
        std::env::var("PHANTOM_ACCOUNT_OPS_LEAK_LEDGER").unwrap(),
        ledger,
    )
    .unwrap();
}

#[test]
fn no_value_reaches_stdout_stderr_logs_or_audit() {
    let home = tempfile::tempdir().unwrap();
    let ledger_copy = home.path().join("ledger-copy.jsonl");
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .args([
            "account_ops::tests::leak_child_scenarios",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env("PHANTOM_ACCOUNT_OPS_LEAK_LEDGER", &ledger_copy)
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("PHANTOM_AUDIT", "1")
        .env("RUST_LOG", "trace")
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "child failed (status {:?})",
        out.status
    );
    assert!(
        stdout.contains("Succeeded") && stdout.contains("aop_"),
        "child did not run its scenarios"
    );
    assert_no_canary(&stdout, "stdout");
    assert_no_canary(&stderr, "stderr");
    let ledger = std::fs::read_to_string(&ledger_copy).unwrap();
    assert!(ledger.contains("\"result\""));
    assert_no_canary(&ledger, "ledger");
    // The mirrored entries in the existing audit log are value-free too.
    let audit = home.path().join(".phantom").join("audit.log");
    match std::fs::read_to_string(&audit) {
        Ok(text) => {
            assert!(text.contains("account_ops.rotate.succeeded"));
            assert_no_canary(&text, "audit.log");
        }
        // HOME isolation is guaranteed on Unix; other platforms may resolve
        // the profile directory elsewhere.
        Err(e) => {
            #[cfg(unix)]
            panic!("child did not write the audit log: {e}");
            #[cfg(not(unix))]
            let _ = e;
        }
    }
}

#[test]
#[should_panic(expected = "leaked a value")]
fn leak_detector_catches_a_planted_value() {
    assert_no_canary(&format!("prefix {CANARY} suffix"), "control");
}
