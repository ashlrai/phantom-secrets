//! Integrity of the posture host key and history (Phantom Core review of #465).

use phantom_core::posture::{project_id, HistoryError, PostureCounts, PostureEntry, PostureLedger};
use std::sync::{Arc, Barrier};

fn point(ledger: &PostureLedger, n: u32) -> PostureCounts {
    let key = ledger.host_key().unwrap();
    let e: Vec<PostureEntry> = (0..n)
        .map(|_| PostureEntry {
            wrapped: true,
            expiring: false,
            unrotated: false,
        })
        .collect();
    PostureCounts::from_entries(project_id(&key, "acme/widget"), &key, &e, 0)
}

// Blocking 1
#[test]
fn concurrent_first_time_key_creators_converge_on_one_key() {
    for _ in 0..20 {
        let d = tempfile::tempdir().unwrap();
        let dir = Arc::new(d.path().join("posture"));
        let barrier = Arc::new(Barrier::new(4));
        let ids: Vec<String> = (0..4)
            .map(|_| {
                let (dir, barrier) = (Arc::clone(&dir), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    let key = PostureLedger::at((*dir).clone()).host_key().unwrap();
                    project_id(&key, "acme/widget")
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]), "{ids:?}");
    }
}

// Blocking 2
#[cfg(unix)]
#[test]
fn group_or_world_readable_key_is_refused_without_a_path() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let l = PostureLedger::at(d.path().join("posture"));
    l.host_key().unwrap();
    std::fs::set_permissions(l.host_key_path(), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = l.host_key().unwrap_err();
    assert_eq!(HistoryError::classify(&err), HistoryError::Unreadable);
    assert!(err.to_string().contains("posture_key_insecure"));
    assert!(!err.to_string().contains(&*d.path().to_string_lossy()));
}

#[test]
fn missing_key_with_existing_history_is_refused_not_regenerated() {
    let d = tempfile::tempdir().unwrap();
    let l = PostureLedger::at(d.path().join("posture"));
    l.record(&point(&l, 1)).unwrap();
    std::fs::remove_file(l.host_key_path()).unwrap();
    let err = l.host_key().unwrap_err();
    assert!(err.to_string().contains("posture_key_missing"));
    assert!(!l.host_key_path().exists());
}

#[test]
fn record_under_a_replaced_key_is_refused_and_visible() {
    let d = tempfile::tempdir().unwrap();
    let l = PostureLedger::at(d.path().join("posture"));
    let first = point(&l, 1);
    l.record(&first).unwrap();
    let mut other = first.clone();
    other.key_id = "00000000".into();
    let err = l.record(&other).unwrap_err();
    assert!(err.to_string().contains("posture_key_changed"));
    assert_eq!(l.load().unwrap().len(), 1);
}

// Blocking 3
fn hold_lock(l: &PostureLedger) -> std::fs::File {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(l.history_path().with_file_name("history.lock"))
        .unwrap();
    f.try_lock().unwrap();
    f
}

#[test]
fn busy_history_reports_locked() {
    let d = tempfile::tempdir().unwrap();
    let l = PostureLedger::at(d.path().join("posture"));
    let p = point(&l, 1);
    l.record(&p).unwrap();
    let held = hold_lock(&l);
    let err = l.record(&p).unwrap_err();
    assert_eq!(HistoryError::classify(&err), HistoryError::Locked);
    assert!(err.to_string().contains("posture_locked"));
    drop(held);
    assert!(l.record(&p).unwrap());
    assert_eq!(l.load().unwrap().len(), 2);
}

#[test]
fn sequential_writes_never_drop_points() {
    let d = tempfile::tempdir().unwrap();
    let l = PostureLedger::at(d.path().join("posture"));
    for n in 0..50 {
        l.record(&point(&l, n)).unwrap();
    }
    let r = l.load().unwrap();
    assert_eq!(r.len(), 50);
    assert!(r.iter().enumerate().all(|(i, c)| c.wrapped == i as u32));
}

#[test]
fn concurrent_writers_persist_or_report_locked_never_drop() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("posture");
    let seed = PostureLedger::at(dir.clone());
    let p = point(&seed, 1);
    let barrier = Arc::new(Barrier::new(8));
    let (ok, locked): (usize, usize) = (0..8)
        .map(|_| {
            let (dir, p, barrier) = (dir.clone(), p.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                let l = PostureLedger::at(dir);
                barrier.wait();
                let (mut ok, mut locked) = (0, 0);
                for _ in 0..50 {
                    match l.record(&p) {
                        Ok(true) => ok += 1,
                        Err(e) if e.to_string().contains("posture_locked") => locked += 1,
                        other => panic!("unexpected {other:?}"),
                    }
                }
                (ok, locked)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    assert_eq!(ok + locked, 400);
    assert!(ok > 0);
    assert_eq!(
        seed.load().unwrap().len(),
        ok,
        "silent drop: {ok} ok, {locked} locked"
    );
}
