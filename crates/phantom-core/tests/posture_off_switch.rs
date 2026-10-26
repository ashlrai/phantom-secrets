//! PHANTOM_POSTURE_HISTORY off: no reads, no writes, no file or key creation.
//! Its own test binary, because it sets a process-wide env var.

use phantom_core::posture::{PostureLedger, HISTORY_ENV};

struct EnvGuard(Option<std::ffi::OsString>);
impl EnvGuard {
    fn set(value: &str) -> Self {
        let old = std::env::var_os(HISTORY_ENV);
        std::env::set_var(HISTORY_ENV, value);
        Self(old)
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(v) => std::env::set_var(HISTORY_ENV, v),
            None => std::env::remove_var(HISTORY_ENV),
        }
    }
}

#[test]
fn off_switch_disables_reads_writes_and_creation() {
    let _lock = phantom_core::PROCESS_ENV_LOCK.lock().unwrap();
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("posture");

    // An existing, even corrupt, history is not read while off.
    let seeded = PostureLedger::at(dir.clone());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(seeded.history_path(), "{bad\n").unwrap();

    for value in ["0", "false", "OFF", "no"] {
        let _env = EnvGuard::set(value);
        let l = PostureLedger::at(d.path().join(format!("fresh-{value}")));
        assert!(!l.enabled());
        assert!(l.load().unwrap().is_empty());
        let err = l.host_key().unwrap_err();
        assert!(err.to_string().contains("posture_disabled"));
        assert!(
            !d.path().join(format!("fresh-{value}")).exists(),
            "created files for {value}"
        );
        assert!(seeded.load().unwrap().is_empty());
        assert!(!seeded.host_key_path().exists());
    }
    assert!(PostureLedger::at(dir).enabled());
}
