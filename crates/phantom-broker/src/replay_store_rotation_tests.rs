//! Test-only harness for the lease store MAC key rotation ordering.
//!
//! No rotation code exists in the library, and this module adds none: it is
//! compiled only under `cfg(test)` and drives the store's private snapshot
//! read and write helpers directly. It encodes the ordering invariants from
//! the #230 design note (`docs/design/lease-store-key-provisioning.md`):
//!
//! - Section 4: rotation replaces the MAC key, not the lease contents; it
//!   starts from an opened store with an epoch (which revokes prior leases,
//!   section 7); the snapshot is rewritten with the existing atomic replace;
//!   the format version does not change.
//! - Section 4 and section 10, risk 4: the new key must be persisted before
//!   the snapshot is rewritten, and the old key kept until the rewrite is
//!   verified by reopening. A fault-injection test must exist before any
//!   rotation code lands (section 11, R2). This is that test.
//!
//! The invariant checked at every crash point: some key still held by the
//! key source opens the snapshot, and the authenticated payload equals the
//! pre-rotation payload.

use super::*;
use crate::lease::test_support::binding;
use crate::replay_storage::ReplaceFault;
use std::fs;
use tempfile::TempDir;

const OLD_KEY: [u8; 32] = [7_u8; 32];
const NEW_KEY: [u8; 32] = [9_u8; 32];

/// One step of a candidate rotation procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Store the new key in the key source next to the old one.
    PersistNewKey,
    /// Re-MAC the snapshot with the new key via the atomic replace.
    RewriteSnapshot,
    /// Reopen the store with the new key and compare the payload.
    VerifyReopen,
    /// Remove the old key from the key source.
    DeleteOldKey,
}

/// The ordering required by section 4 and section 10, risk 4.
const SAFE_ORDER: [Step; 4] = [
    Step::PersistNewKey,
    Step::RewriteSnapshot,
    Step::VerifyReopen,
    Step::DeleteOldKey,
];

/// The ordering section 4 warns against: the key source is updated (new key
/// stored, old key removed) only after the snapshot rewrite, so a crash right
/// after the rewrite leaves a snapshot that no stored key opens.
const REWRITE_FIRST_ORDER: [Step; 4] = [
    Step::RewriteSnapshot,
    Step::DeleteOldKey,
    Step::PersistNewKey,
    Step::VerifyReopen,
];

/// Deletes the old key before the rewrite is verified by reopening.
const DELETE_BEFORE_VERIFY_ORDER: [Step; 4] = [
    Step::PersistNewKey,
    Step::DeleteOldKey,
    Step::RewriteSnapshot,
    Step::VerifyReopen,
];

/// In-memory stand-in for the OS credential store: the keys that survive a
/// crash. Process memory (the generated new key) does not.
#[derive(Debug, Default, Clone)]
struct KeySource {
    keys: Vec<[u8; 32]>,
}

struct Fixture {
    _temp: TempDir,
    root: std::path::PathBuf,
    workspace: std::path::PathBuf,
    expected_payload: serde_json::Value,
    old_snapshot: Vec<u8>,
}

fn state_path(root: &Path) -> std::path::PathBuf {
    root.join(STATE_FILE_NAME)
}

fn open(fixture: &Fixture, key: [u8; 32]) -> Result<DurableReplayStore, ReplayStoreError> {
    DurableReplayStore::open_existing(&fixture.root, &fixture.workspace, key)
}

fn payload_with(fixture: &Fixture, key: [u8; 32]) -> Result<serde_json::Value, ReplayStoreError> {
    let store = open(fixture, key)?;
    let _lock = store.storage.lock_transaction()?;
    let state = read_authenticated_state(&store.storage, &store.key)?;
    Ok(serde_json::to_value(&state).unwrap())
}

/// A store with one lease from generation 1, then activated again (section 4
/// step 1: open with the old key and start an epoch, which revokes it).
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("broker");
    let workspace = temp.path().join("workspace-boundary");
    fs::create_dir_all(&workspace).unwrap();
    {
        let store = DurableReplayStore::bootstrap(&root, &workspace, OLD_KEY).unwrap();
        assert_eq!(store.start_epoch().unwrap(), 1);
        store
            .reserve(
                &"1".repeat(64).parse::<Sha256Digest>().unwrap(),
                "request-1",
                &binding(),
            )
            .unwrap();
    }
    {
        let store = DurableReplayStore::open_existing(&root, &workspace, OLD_KEY).unwrap();
        assert_eq!(store.start_epoch().unwrap(), 2);
        let rows = store.list_leases().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].revoked,
            "the epoch before rotation revokes old leases"
        );
    }
    let old_snapshot = fs::read(state_path(&root)).unwrap();
    let mut fixture = Fixture {
        _temp: temp,
        root,
        workspace,
        expected_payload: serde_json::Value::Null,
        old_snapshot,
    };
    fixture.expected_payload = payload_with(&fixture, OLD_KEY).unwrap();
    fixture
}

/// Run `order` until `crash_after` steps have completed (or all of them), with
/// an optional storage fault injected into the snapshot rewrite. A step that
/// fails ends the run, as a crash would. Returns the key source as it would
/// be found after the crash.
fn run(
    fixture: &Fixture,
    order: &[Step],
    crash_after: usize,
    rewrite_fault: Option<ReplaceFault>,
) -> KeySource {
    let mut source = KeySource {
        keys: vec![OLD_KEY],
    };
    let new_key = NEW_KEY;
    for step in order.iter().take(crash_after) {
        let ok = match step {
            Step::PersistNewKey => {
                source.keys.push(new_key);
                true
            }
            Step::RewriteSnapshot => {
                let store = open(fixture, OLD_KEY).expect("rewrite starts from the old key");
                if let Some(fault) = rewrite_fault {
                    store.storage.inject_replace_fault(fault);
                }
                let _lock = store.storage.lock_transaction().unwrap();
                let state = read_authenticated_state(&store.storage, &store.key).unwrap();
                write_authenticated_state(&store.storage, &state, &new_key).is_ok()
            }
            Step::VerifyReopen => payload_with(fixture, new_key)
                .map(|payload| payload == fixture.expected_payload)
                .unwrap_or(false),
            Step::DeleteOldKey => {
                source.keys.retain(|key| *key != OLD_KEY);
                true
            }
        };
        if !ok {
            break;
        }
    }
    source
}

/// The invariant: some retained key opens the snapshot and yields the
/// pre-rotation payload. Returns which key did, for the caller to inspect.
fn recover(fixture: &Fixture, source: &KeySource) -> Option<[u8; 32]> {
    source.keys.iter().copied().find(|key| {
        payload_with(fixture, *key)
            .map(|payload| payload == fixture.expected_payload)
            .unwrap_or(false)
    })
}

/// A crash can also lose an un-synced rename, leaving the old snapshot bytes.
fn lose_unsynced_rename(fixture: &Fixture) {
    fs::write(state_path(&fixture.root), &fixture.old_snapshot).unwrap();
}

#[test]
fn safe_order_is_recoverable_at_every_crash_point() {
    for crash_after in 0..=SAFE_ORDER.len() {
        let fixture = fixture();
        let source = run(&fixture, &SAFE_ORDER, crash_after, None);
        assert!(
            recover(&fixture, &source).is_some(),
            "safe order lost the store after {crash_after} step(s)"
        );
    }
}

#[test]
fn safe_order_survives_injected_rewrite_faults_either_way_the_rename_lands() {
    for fault in [
        ReplaceFault::AfterRenameBeforeDirectorySync,
        ReplaceFault::AfterDirectorySync,
    ] {
        // The faulted rewrite ends the run, so the old key is never deleted.
        let fixture = fixture();
        let source = run(&fixture, &SAFE_ORDER, SAFE_ORDER.len(), Some(fault));
        assert_eq!(source.keys, vec![OLD_KEY, NEW_KEY], "{fault:?}");
        assert_eq!(
            recover(&fixture, &source),
            Some(NEW_KEY),
            "{fault:?}: rename landed"
        );
        lose_unsynced_rename(&fixture);
        assert_eq!(
            recover(&fixture, &source),
            Some(OLD_KEY),
            "{fault:?}: rename lost"
        );
    }
}

#[test]
fn completed_rotation_keeps_contents_format_and_generation_and_retires_the_old_key() {
    let fixture = fixture();
    let source = run(&fixture, &SAFE_ORDER, SAFE_ORDER.len(), None);
    assert_eq!(source.keys, vec![NEW_KEY]);
    assert_eq!(recover(&fixture, &source), Some(NEW_KEY));
    assert!(matches!(
        open(&fixture, OLD_KEY),
        Err(ReplayStoreError::AuthenticationFailed)
    ));

    let rotated: serde_json::Value =
        serde_json::from_slice(&fs::read(state_path(&fixture.root)).unwrap()).unwrap();
    assert_eq!(rotated["format_version"], u64::from(STORE_FORMAT_VERSION));
    assert_eq!(STORE_FORMAT_VERSION, 2, "section 4: no format bump");

    let store = open(&fixture, NEW_KEY).unwrap();
    assert_eq!(
        store.stored_generation().unwrap(),
        2,
        "rotation does not start an epoch"
    );
    let rows = store.list_leases().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].revoked,
        "leases revoked before rotation stay revoked"
    );
}

#[test]
fn harness_rejects_the_orderings_section_4_warns_against() {
    // Rewrite first: a crash right after the rewrite leaves only the old key,
    // which no longer opens the snapshot.
    let fixture_a = fixture();
    let source = run(&fixture_a, &REWRITE_FIRST_ORDER, 1, None);
    assert_eq!(source.keys, vec![OLD_KEY]);
    assert_eq!(recover(&fixture_a, &source), None);

    // Deleting the old key before the verified reopen: a crash after the
    // rewrite would still recover through the new key, but a rewrite whose
    // rename is lost leaves only the new key against the old snapshot.
    let fixture_b = fixture();
    let source = run(
        &fixture_b,
        &DELETE_BEFORE_VERIFY_ORDER,
        DELETE_BEFORE_VERIFY_ORDER.len(),
        Some(ReplaceFault::AfterRenameBeforeDirectorySync),
    );
    assert_eq!(source.keys, vec![NEW_KEY]);
    lose_unsynced_rename(&fixture_b);
    assert_eq!(recover(&fixture_b, &source), None);
}
