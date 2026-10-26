//! Secret Posture Ledger store (slice 1).
//!
//! A local, append-only history of per-project secret posture. Each record
//! holds counts and yes/no flags only: no secret names, no values, and no
//! project path (the project is a truncated SHA-256 fingerprint). The file
//! lives in a 0700 directory and is written 0600, is capped at
//! [`MAX_RECORDS`] records (oldest dropped first), and can be switched off
//! with `PHANTOM_POSTURE_HISTORY=0`. A corrupted history never breaks the
//! caller: [`PostureLedger::load`] reports it, and [`PostureLedger::record`]
//! sets the bad file aside and starts a fresh history.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// Schema version of one ledger record.
pub const SCHEMA_VERSION: u32 = 1;
/// Most records kept; older ones are dropped on write.
pub const MAX_RECORDS: usize = 2000;
/// Environment switch: `0`, `false`, or `off` disables history writes.
pub const HISTORY_ENV: &str = "PHANTOM_POSTURE_HISTORY";

/// One secret as seen by a caller. Only the booleans are kept; `name` and
/// `value` exist so callers can pass what they have without pre-filtering,
/// and are dropped by [`PostureCounts::from_entries`].
pub struct PostureEntry<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
    pub wrapped: bool,
    pub expiring: bool,
    pub unrotated: bool,
}

/// One value-free posture point for a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureCounts {
    pub schema: u32,
    pub recorded_at: u64,
    pub project: String,
    pub wrapped: u32,
    pub unwrapped: u32,
    pub expiring: u32,
    pub unrotated: u32,
    pub plaintext_env: bool,
}

/// Truncated SHA-256 fingerprint of a project root, so history can group by
/// project without storing its path.
pub fn project_fingerprint(project_root: &str) -> String {
    let digest = Sha256::digest(project_root.as_bytes());
    hex::encode(&digest[..8])
}

impl PostureCounts {
    pub fn from_entries(
        project_root: &str,
        entries: &[PostureEntry<'_>],
        plaintext_env: bool,
    ) -> Self {
        let count =
            |f: fn(&PostureEntry<'_>) -> bool| entries.iter().filter(|e| f(e)).count() as u32;
        Self {
            schema: SCHEMA_VERSION,
            recorded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            project: project_fingerprint(project_root),
            wrapped: count(|e| e.wrapped),
            unwrapped: count(|e| !e.wrapped),
            expiring: count(|e| e.expiring),
            unrotated: count(|e| e.unrotated),
            plaintext_env,
        }
    }
}

/// True unless [`HISTORY_ENV`] turns history off.
pub fn history_enabled() -> bool {
    match std::env::var(HISTORY_ENV) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

/// Handle on a posture history directory.
pub struct PostureLedger {
    dir: PathBuf,
}

impl PostureLedger {
    /// Ledger rooted at an explicit directory (tests, custom homes).
    pub fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Default ledger under `~/.phantom/posture`.
    pub fn default_location() -> io::Result<Self> {
        Ok(Self::at(
            crate::home::home_dir()?.join(".phantom").join("posture"),
        ))
    }

    pub fn history_path(&self) -> PathBuf {
        self.dir.join("history.jsonl")
    }

    /// Load every record. A missing file is an empty history; any unreadable
    /// or malformed line is an `InvalidData` error naming the remedy.
    pub fn load(&self) -> io::Result<Vec<PostureCounts>> {
        let Some(bytes) = crate::fs::read_regular_file(&self.history_path())? else {
            return Ok(Vec::new());
        };
        let text = String::from_utf8(bytes).map_err(|_| corrupted(&self.history_path()))?;
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).map_err(|_| corrupted(&self.history_path())))
            .collect()
    }

    /// Append a record. Returns `Ok(false)` when history is switched off.
    /// A corrupted history is renamed to `history.jsonl.corrupt` and a fresh
    /// one is started, so recording never fails on old bad data.
    pub fn record(&self, counts: &PostureCounts) -> io::Result<bool> {
        if !history_enabled() {
            return Ok(false);
        }
        crate::fs::ensure_private_dir(&self.dir)?;
        let mut records = match self.load() {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                std::fs::rename(self.history_path(), self.dir.join("history.jsonl.corrupt"))?;
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        records.push(counts.clone());
        if records.len() > MAX_RECORDS {
            records.drain(..records.len() - MAX_RECORDS);
        }
        let mut out = String::new();
        for r in &records {
            out.push_str(&serde_json::to_string(r).map_err(io::Error::other)?);
            out.push('\n');
        }
        crate::fs::atomic_write(&self.history_path(), out.as_bytes())?;
        Ok(true)
    }
}

fn corrupted(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "posture history at {} is corrupted; it will be set aside on the next record, or delete it",
            path.display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(n: u32) -> PostureCounts {
        PostureCounts {
            schema: 1,
            recorded_at: n as u64,
            project: "p".into(),
            wrapped: n,
            unwrapped: 0,
            expiring: 0,
            unrotated: 0,
            plaintext_env: false,
        }
    }

    #[test]
    fn size_cap_drops_oldest() {
        let d = tempfile::tempdir().unwrap();
        let l = PostureLedger::at(d.path().join("posture"));
        let seed: String = (0..MAX_RECORDS as u32)
            .map(|n| serde_json::to_string(&point(n)).unwrap() + "\n")
            .collect();
        crate::fs::ensure_private_dir(&l.dir).unwrap();
        std::fs::write(l.history_path(), seed).unwrap();
        l.record(&point(99_999)).unwrap();
        let r = l.load().unwrap();
        assert_eq!(r.len(), MAX_RECORDS);
        assert_eq!(r[0].wrapped, 1);
        assert_eq!(r.last().unwrap().wrapped, 99_999);
    }

    #[test]
    fn corrupted_history_fails_safe() {
        let d = tempfile::tempdir().unwrap();
        let l = PostureLedger::at(d.path().join("posture"));
        crate::fs::ensure_private_dir(&l.dir).unwrap();
        std::fs::write(l.history_path(), "{not json\n").unwrap();
        assert_eq!(l.load().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(l.record(&point(1)).unwrap());
        assert_eq!(l.load().unwrap(), vec![point(1)]);
        assert!(d.path().join("posture/history.jsonl.corrupt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn history_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let l = PostureLedger::at(d.path().join("posture"));
        l.record(&point(1)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&l.dir), 0o700);
        assert_eq!(mode(&l.history_path()), 0o600);
    }

    #[test]
    fn off_switch_skips_write() {
        let _g = crate::PROCESS_ENV_LOCK.lock().unwrap();
        let d = tempfile::tempdir().unwrap();
        let l = PostureLedger::at(d.path().join("posture"));
        std::env::set_var(HISTORY_ENV, "0");
        let wrote = l.record(&point(1));
        std::env::remove_var(HISTORY_ENV);
        assert!(!wrote.unwrap());
        assert!(!l.history_path().exists());
    }
}
