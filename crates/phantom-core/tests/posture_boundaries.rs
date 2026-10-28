//! The value-free store rejects malformed metadata and unsafe file targets.

use phantom_core::posture::{project_id, PostureCounts, PostureLedger};

fn point(ledger: &PostureLedger) -> PostureCounts {
    let key = ledger.host_key().unwrap();
    PostureCounts::from_entries(project_id(&key, "acme/widget"), &key, &[], 0)
}

fn malformed_points(valid: &PostureCounts) -> Vec<PostureCounts> {
    let mut points = Vec::new();
    for field in ["project", "key_id", "recorded_at"] {
        let mut p = valid.clone();
        match field {
            "project" => p.project = "/private/project-marker".into(),
            "key_id" => p.key_id = "arbitrary-key-marker".into(),
            "recorded_at" => p.recorded_at = "arbitrary-date-marker".into(),
            _ => unreachable!(),
        }
        points.push(p);
    }
    for schema in [0, 2] {
        let mut p = valid.clone();
        p.schema = schema;
        points.push(p);
    }
    for date in [
        "2026-02-30T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:00:00+00:00",
    ] {
        let mut p = valid.clone();
        p.recorded_at = date.into();
        points.push(p);
    }
    let mut p = valid.clone();
    p.project = "0123456789abcdeG".into();
    points.push(p);
    points
}

#[test]
fn malformed_record_metadata_is_refused_before_any_history_write() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    let valid = point(&ledger);
    for invalid in malformed_points(&valid) {
        let err = ledger.record(&invalid).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let message = err.to_string();
        for marker in ["project-marker", "key-marker", "date-marker"] {
            assert!(!message.contains(marker));
        }
        assert!(!ledger.history_path().exists());
    }
    assert!(ledger.record(&valid).unwrap());
}

#[test]
fn malformed_record_metadata_loaded_from_disk_is_corrupted() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    let valid = point(&ledger);
    for invalid in malformed_points(&valid) {
        phantom_core::fs::atomic_write(
            &ledger.history_path(),
            (serde_json::to_string(&invalid).unwrap() + "\n").as_bytes(),
        )
        .unwrap();
        let err = ledger.load().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(!err.to_string().contains("marker"));
    }
}

#[test]
fn initial_record_must_match_the_ledgers_host_key() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    ledger.host_key().unwrap();
    phantom_core::fs::atomic_write(&ledger.host_key_path(), &[0x21; 32]).unwrap();
    let other = PostureLedger::at(d.path().join("other"));
    other.host_key().unwrap();
    phantom_core::fs::atomic_write(&other.host_key_path(), &[0x42; 32]).unwrap();
    let foreign = point(&other);
    let err = ledger.record(&foreign).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!ledger.history_path().exists());
}

#[test]
fn stale_record_is_refused_after_host_key_replacement() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    ledger.host_key().unwrap();
    phantom_core::fs::atomic_write(&ledger.host_key_path(), &[0x21; 32]).unwrap();
    let original = point(&ledger);
    ledger.record(&original).unwrap();
    let before = std::fs::read(ledger.history_path()).unwrap();
    phantom_core::fs::atomic_write(&ledger.host_key_path(), &[0x42; 32]).unwrap();
    let err = ledger.record(&original).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(std::fs::read(ledger.history_path()).unwrap(), before);
}

#[test]
fn oversized_host_key_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    ledger.host_key().unwrap();
    phantom_core::fs::atomic_write(&ledger.host_key_path(), &[0x21; 4096]).unwrap();
    let err = ledger.host_key().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(!err.to_string().contains(&*d.path().to_string_lossy()));
}

#[test]
fn oversized_history_is_rejected_and_preserved_before_reset() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    let p = point(&ledger);
    let oversized = vec![b' '; 2 * 1024 * 1024 + 1];
    phantom_core::fs::atomic_write(&ledger.history_path(), &oversized).unwrap();
    assert_eq!(
        ledger.load().unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(ledger.record(&p).unwrap());
    let loaded = ledger.load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded[0].reset_after_corruption);
    let archives: Vec<_> = std::fs::read_dir(ledger.history_path().parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("history.jsonl.corrupt-")
        })
        .collect();
    assert_eq!(archives.len(), 1);
    assert_eq!(std::fs::read(&archives[0]).unwrap(), oversized);
}

#[test]
fn unknown_record_fields_are_refused_without_echoing_them() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    let p = point(&ledger);
    let mut json = serde_json::to_value(&p).unwrap();
    json["unexpected-name-marker"] = "unexpected-value-marker".into();
    let bytes = serde_json::to_vec(&json).unwrap();
    phantom_core::fs::atomic_write(&ledger.history_path(), &bytes).unwrap();
    let err = ledger.load().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(!err.to_string().contains("marker"));
    assert_eq!(std::fs::read(ledger.history_path()).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn nonprivate_history_lock_is_refused_without_changing_history() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    let p = point(&ledger);
    ledger.record(&p).unwrap();
    let before = std::fs::read(ledger.history_path()).unwrap();
    let lock = ledger.history_path().with_file_name("history.lock");
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
    let err = ledger.record(&p).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("posture_lock_insecure"));
    assert_eq!(std::fs::read(ledger.history_path()).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o666
    );
}

#[cfg(windows)]
#[test]
fn windows_symlink_host_key_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    ledger.host_key().unwrap();
    let target = d.path().join("outside");
    let marker = [0x21; 32];
    phantom_core::fs::atomic_write(&target, &marker).unwrap();
    std::fs::remove_file(ledger.host_key_path()).unwrap();
    if let Err(error) = std::os::windows::fs::symlink_file(&target, ledger.host_key_path()) {
        // Windows needs Developer Mode or the create-symlink privilege.
        if error.raw_os_error() == Some(1314) {
            eprintln!("symlink assertion unavailable: Windows create-symlink privilege missing");
            return;
        }
        panic!("could not create symlink fixture: {error}");
    }
    assert_eq!(
        ledger.host_key().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(std::fs::read(&target).unwrap(), marker);
}

#[cfg(unix)]
#[test]
fn group_or_world_readable_history_is_refused_without_changing_it() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let ledger = PostureLedger::at(d.path().join("posture"));
    let p = point(&ledger);
    ledger.record(&p).unwrap();
    let before = std::fs::read(ledger.history_path()).unwrap();
    for mode in [0o640, 0o604] {
        std::fs::set_permissions(ledger.history_path(), std::fs::Permissions::from_mode(mode))
            .unwrap();
        assert_eq!(
            ledger.load().unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            ledger.record(&p).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::read(ledger.history_path()).unwrap(), before);
    }
}

#[cfg(unix)]
#[test]
fn symlink_key_history_and_lock_are_refused_without_touching_targets() {
    use std::os::unix::fs::symlink;
    for filename in ["host.key", "history.jsonl", "history.lock"] {
        let d = tempfile::tempdir().unwrap();
        let ledger = PostureLedger::at(d.path().join("posture"));
        let p = point(&ledger);
        let target = d.path().join("outside");
        let marker = [0x21; 32];
        phantom_core::fs::atomic_write(&target, &marker).unwrap();
        let path = ledger.history_path().with_file_name(filename);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        symlink(&target, &path).unwrap();
        if filename == "host.key" {
            assert!(ledger.host_key().is_err());
        } else {
            assert!(ledger.record(&p).is_err());
            if filename == "history.jsonl" {
                assert!(ledger.load().is_err());
            }
        }
        assert_eq!(std::fs::read(&target).unwrap(), marker);
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
