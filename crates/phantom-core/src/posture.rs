//! Secret Posture Ledger store (slice 1).
//!
//! A local, append-only history of per-project secret posture. Each record
//! holds counts and an RFC 3339 UTC timestamp only: no secret names, no
//! values, no project path and no remote URL. The project is a 16-hex-char
//! HMAC-SHA256 of the repo identity (`owner/name` from the origin remote, or
//! `local/<folder>`, normalized as phantom run receipts do) under a per-host
//! key stored 0600 next to the history. `wrapped`/`unwrapped` count secret
//! names, not env entries or launches, matching receipts.
//!
//! The history directory is 0700 and the file 0600, capped at
//! [`MAX_RECORDS`] records (oldest dropped first), and history can be
//! switched off with `PHANTOM_POSTURE_HISTORY=0`. A bad history never breaks
//! the caller: [`PostureLedger::load`] reports a [`HistoryError`], and
//! [`PostureLedger::record`] sets a corrupted file aside and starts fresh.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io;
use std::path::{Path, PathBuf};

/// Schema version of one ledger record.
pub const SCHEMA_VERSION: u32 = 1;
/// Most records kept; older ones are dropped on write.
pub const MAX_RECORDS: usize = 2000;
/// Environment switch: `0`, `false`, `off` or `no` disables history writes.
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
    /// RFC 3339 UTC, second precision.
    pub recorded_at: String,
    /// 16 hex chars, see [`project_id`].
    pub project: String,
    pub wrapped: u32,
    pub unwrapped: u32,
    pub expiring: u32,
    pub unrotated: u32,
    /// Number of plaintext (unwrapped) secret values found in .env files.
    pub plaintext_env: u32,
}

impl PostureCounts {
    pub fn from_entries(project: String, entries: &[PostureEntry<'_>], plaintext_env: u32) -> Self {
        let count =
            |f: fn(&PostureEntry<'_>) -> bool| entries.iter().filter(|e| f(e)).count() as u32;
        Self {
            schema: SCHEMA_VERSION,
            recorded_at: rfc3339_utc(now_secs()),
            project,
            wrapped: count(|e| e.wrapped),
            unwrapped: count(|e| !e.wrapped),
            expiring: count(|e| e.expiring),
            unrotated: count(|e| e.unrotated),
            plaintext_env,
        }
    }
}

/// Why a history could not be read. Serialized as `history.error` in the
/// `--json` envelope (`null` when there is none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryError {
    Corrupted,
    Unreadable,
    Locked,
}

impl HistoryError {
    pub fn classify(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::InvalidData => Self::Corrupted,
            io::ErrorKind::WouldBlock => Self::Locked,
            _ => Self::Unreadable,
        }
    }
}

// ---- repo identity (mirrors phantom receipt normalization, phantom #910) ----

fn valid_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// `owner/name` from a GitHub remote (https, ssh, git, scp-like). Userinfo is
/// ignored; any other host or shape returns `None`.
pub fn owner_name_from_remote(url: &str) -> Option<String> {
    let u = url.trim();
    let lower = u.to_ascii_lowercase();
    let rest = if let Some(i) = ["https://", "http://", "ssh://", "git://"]
        .iter()
        .find_map(|p| lower.starts_with(p).then_some(p.len()))
    {
        let after = &u[i..];
        let (auth, path) = after.split_once('/')?;
        let host = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
        let host_only = host.split_once(':').map_or(host, |(h, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) && !port.is_empty() {
                h
            } else {
                "invalid"
            }
        });
        if !host_only.eq_ignore_ascii_case("github.com") {
            return None;
        }
        path
    } else {
        let (auth, path) = u.split_once(':')?;
        let host = match auth.rsplit_once('@') {
            Some((user, h)) if !user.is_empty() && !user.contains(['/', ':']) => h,
            Some(_) => return None,
            None => auth,
        };
        if !host.eq_ignore_ascii_case("github.com") {
            return None;
        }
        path
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (owner, name) = rest.split_once('/')?;
    let name = name.strip_suffix(".git").unwrap_or(name);
    (valid_part(owner) && valid_part(name)).then(|| format!("{owner}/{name}"))
}

/// `local/<folder>` with the folder sanitized to receipt characters.
pub fn local_repo_name(dir: &Path) -> String {
    let folder: String = dir
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(100)
        .collect();
    if folder.is_empty() || folder.chars().all(|c| c == '.') {
        "local/repo".into()
    } else {
        format!("local/{folder}")
    }
}

/// Repo identity: origin remote `owner/name`, else `local/<folder>`.
pub fn repo_identity(origin_remote: Option<&str>, dir: &Path) -> String {
    origin_remote
        .and_then(owner_name_from_remote)
        .unwrap_or_else(|| local_repo_name(dir))
}

// ---- per-host key and project id ----

/// Per-host HMAC key. Never logged or serialized.
pub struct HostKey([u8; 32]);

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostKey(..)")
    }
}

impl HostKey {
    /// Read the key at `path`, or generate one and write it 0600.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        if let Some(bytes) = crate::fs::read_regular_file(path)? {
            let key: [u8; 32] = bytes.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "posture host key has the wrong length",
                )
            })?;
            return Ok(Self(key));
        }
        if let Some(parent) = path.parent() {
            crate::fs::ensure_private_dir(parent)?;
        }
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        crate::fs::atomic_write(path, &key)?;
        Ok(Self(key))
    }

    #[doc(hidden)]
    pub fn to_hex_for_test(&self) -> String {
        hex::encode(self.0)
    }
}

/// 16-hex-char HMAC-SHA256 of the repo identity under the host key.
pub fn project_id(key: &HostKey, identity: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).expect("hmac accepts any key length");
    mac.update(identity.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..8])
}

// ---- time ----

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format Unix seconds as RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

// ---- ledger ----

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

    /// Per-host key path, next to the history (0600).
    pub fn host_key_path(&self) -> PathBuf {
        self.dir.join("host.key")
    }

    /// Load every record. A missing file is an empty history; a malformed
    /// file is `InvalidData` (see [`HistoryError::classify`]).
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
            recorded_at: rfc3339_utc(n as u64),
            project: "0123456789abcdef".into(),
            wrapped: n,
            unwrapped: 0,
            expiring: 0,
            unrotated: 0,
            plaintext_env: 0,
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
        let err = l.load().unwrap_err();
        assert_eq!(HistoryError::classify(&err), HistoryError::Corrupted);
        assert!(l.record(&point(1)).unwrap());
        assert_eq!(l.load().unwrap(), vec![point(1)]);
        assert!(d.path().join("posture/history.jsonl.corrupt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn history_and_host_key_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let l = PostureLedger::at(d.path().join("posture"));
        l.record(&point(1)).unwrap();
        HostKey::load_or_create(&l.host_key_path()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&l.dir), 0o700);
        assert_eq!(mode(&l.history_path()), 0o600);
        assert_eq!(mode(&l.host_key_path()), 0o600);
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

    #[test]
    fn same_identity_same_id_on_one_host_and_key_is_stable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        let a = HostKey::load_or_create(&p).unwrap();
        let b = HostKey::load_or_create(&p).unwrap();
        let id = project_id(&a, "acme/widget");
        assert_eq!(id, project_id(&b, "acme/widget"));
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id, project_id(&a, "acme/other"));
        let other = HostKey::load_or_create(&d.path().join("k2")).unwrap();
        assert_ne!(id, project_id(&other, "acme/widget"));
    }

    #[test]
    fn userinfo_and_remote_shape_do_not_change_identity_or_id() {
        let d = tempfile::tempdir().unwrap();
        let key = HostKey::load_or_create(&d.path().join("k")).unwrap();
        let dir = Path::new("/home/u/checkout");
        let ids: Vec<String> = [
            "https://github.com/acme/widget.git",
            "https://x-access-token:tok123@github.com/acme/widget.git",
            "https://user@github.com/acme/widget",
            "git@github.com:acme/widget.git",
            "ssh://git@github.com:22/acme/widget.git",
        ]
        .iter()
        .map(|r| {
            let ident = repo_identity(Some(r), dir);
            assert_eq!(ident, "acme/widget", "{r}");
            project_id(&key, &ident)
        })
        .collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn local_fallback_never_contains_the_path() {
        assert_eq!(
            local_repo_name(Path::new("/home/u/work/my repo (copy)")),
            "local/my-repo--copy-"
        );
        assert_eq!(local_repo_name(Path::new("/tmp/x/")), "local/x");
        assert_eq!(local_repo_name(Path::new("/")), "local/repo");
        assert_eq!(
            repo_identity(
                Some("https://u:t@gitlab.com/a/b.git"),
                Path::new("/home/u/secret/proj")
            ),
            "local/proj"
        );
        assert_eq!(repo_identity(None, Path::new("/home/u/proj")), "local/proj");
        // The id is an HMAC: neither identity nor path appears in it.
        let d = tempfile::tempdir().unwrap();
        let key = HostKey::load_or_create(&d.path().join("k")).unwrap();
        let id = project_id(&key, "local/proj");
        assert!(!id.contains("proj") && !id.contains("home"));
    }

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_792_901_096), "2026-10-25T04:04:56Z");
    }

    #[test]
    fn history_error_classes() {
        let e = |k| io::Error::new(k, "x");
        assert_eq!(
            HistoryError::classify(&e(io::ErrorKind::InvalidData)),
            HistoryError::Corrupted
        );
        assert_eq!(
            HistoryError::classify(&e(io::ErrorKind::WouldBlock)),
            HistoryError::Locked
        );
        assert_eq!(
            HistoryError::classify(&e(io::ErrorKind::PermissionDenied)),
            HistoryError::Unreadable
        );
        assert_eq!(
            serde_json::to_string(&HistoryError::Corrupted).unwrap(),
            "\"corrupted\""
        );
    }
}
