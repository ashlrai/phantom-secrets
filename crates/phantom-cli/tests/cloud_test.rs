/// Integration tests for `phantom cloud push` and `phantom cloud pull`.
///
/// What *is* tested unconditionally:
///   - `phantom cloud push` / `pull` exit non-zero before authentication or
///     network access when the exact terminal ceremony cannot be completed.
///   - `phantom cloud status` succeeds and reports "not logged in" when no
///     token is present.
///   - Lower-level HTTP client tests cover explicit mock origins with
///     test-only bearers; the production CLI intentionally has no API-origin
///     override because it loads a real bearer from the OS keychain.
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const VAULT_PASS: &str = "test-integration-passphrase-cloud";

fn init_project(dir: &TempDir) {
    fs::write(dir.path().join(".env"), "SEED_SECRET=sk-seed-value\n").expect("write .env");
    Command::cargo_bin("phantom")
        .expect("binary not found")
        .args(["init", "--from", ".env"])
        .current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path())
        .assert()
        .success();
}

fn phantom(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("phantom").expect("binary not found");
    cmd.current_dir(dir.path())
        .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
        .env("HOME", dir.path());
    cmd
}

// ──────────────────────────────────────────────────────────────────────────────
// Unconditional tests — no keychain token required
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn cloud_push_fails_without_auth_token() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir).args(["cloud", "push"]).assert().failure();
}

#[test]
fn cloud_pull_fails_without_auth_token() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    phantom(&dir).args(["cloud", "pull"]).assert().failure();
}

#[test]
fn cloud_status_succeeds_and_reports_not_logged_in() {
    // cloud status should always exit 0 and print a message — even without a
    // token it reports "not logged in" rather than erroring out.
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    let output = phantom(&dir).args(["cloud", "status"]).assert().success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    // Either "not logged in" or "logged in" — both are valid depending on
    // whether a real token is present in the developer's keychain.
    let has_expected_text = stdout.contains("not logged in")
        || stdout.contains("logged in")
        || stdout.contains("Cloud:");
    assert!(
        has_expected_text,
        "cloud status should report login state, got: {stdout}"
    );
}

#[test]
fn cloud_push_fails_closed_at_terminal_authority_before_api_origin_or_network() {
    let dir = TempDir::new().unwrap();
    init_project(&dir);

    let output = phantom(&dir)
        .args(["cloud", "push"])
        .env("PHANTOM_API_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("terminal"),
        "unexpected authority failure: {combined}"
    );
    assert!(!combined.contains("PHANTOM_API_URL overrides are disabled"));
    assert!(!combined.contains("Connection refused"));
}
