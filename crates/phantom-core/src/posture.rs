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
use zeroize::Zeroize;

/// Schema version of one ledger record.
pub const SCHEMA_VERSION: u32 = 1;
/// Most records kept; older ones are dropped on write.
pub const MAX_RECORDS: usize = 2000;
// Bound externally modified histories before allocating or parsing their contents.
const MAX_HISTORY_BYTES: usize = MAX_RECORDS * 1024;
/// Environment switch: `0`, `false`, `off` or `no` (any case) disables history
/// reads, writes and file or key creation.
pub const HISTORY_ENV: &str = "PHANTOM_POSTURE_HISTORY";

/// One secret as seen by a caller: flags only, so this type cannot carry a
/// secret name or value.
#[derive(Debug, Clone, Copy)]
pub struct PostureEntry {
    pub wrapped: bool,
    pub expiring: bool,
    pub unrotated: bool,
}

/// One value-free posture point for a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Non-reversible fingerprint of the host key (see [`HostKey::key_id`]),
    /// so a key replacement is visible to readers.
    pub key_id: String,
    /// True on the first record after a corrupted history was set aside.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reset_after_corruption: bool,
}

impl PostureCounts {
    pub fn from_entries(
        project: String,
        key: &HostKey,
        entries: &[PostureEntry],
        plaintext_env: u32,
    ) -> Self {
        let count = |f: fn(&PostureEntry) -> bool| entries.iter().filter(|e| f(e)).count() as u32;
        Self {
            schema: SCHEMA_VERSION,
            recorded_at: rfc3339_utc(now_secs()),
            project,
            wrapped: count(|e| e.wrapped),
            unwrapped: count(|e| !e.wrapped),
            expiring: count(|e| e.expiring),
            unrotated: count(|e| e.unrotated),
            plaintext_env,
            key_id: key.key_id(),
            reset_after_corruption: false,
        }
    }
}

fn valid_counts(counts: &PostureCounts) -> bool {
    let hex = |s: &str, len| {
        s.len() == len
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    counts.schema == SCHEMA_VERSION
        && hex(&counts.project, 16)
        && hex(&counts.key_id, 8)
        && valid_timestamp(&counts.recorded_at)
}

fn valid_timestamp(s: &str) -> bool {
    if s.len() != 20 {
        return false;
    }
    let b = s.as_bytes();
    if b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, c)| ![4, 7, 10, 13, 16, 19].contains(&i) && !c.is_ascii_digit())
    {
        return false;
    }
    let number = |start: usize, end: usize| s[start..end].parse::<u32>().unwrap_or(0);
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return false,
    };
    day >= 1 && day <= days && number(11, 13) < 24 && number(14, 16) < 60 && number(17, 19) < 60
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
        let host = auth.split_once('@').map_or(auth, |(_, h)| h);
        if host.contains('@') {
            return None;
        }
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
        let host = match auth.split_once('@') {
            Some((user, h))
                if !user.is_empty()
                    && !h.contains('@')
                    && !user.contains(['/', ':'])
                    && !user.chars().any(char::is_whitespace) =>
            {
                h
            }
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
    // Per UTF-16 unit, like the JS `.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 100)`
    // in phantom #910, so a non-BMP character becomes two dashes in both.
    let name = dir
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let folder: String = name
        .encode_utf16()
        .map(|u| match u8::try_from(u) {
            Ok(b) if b.is_ascii_alphanumeric() || b"_.-".contains(&b) => b as char,
            _ => '-',
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

/// Error with a stable code and no path, so it is safe to print.
fn coded(kind: io::ErrorKind, code: &str, what: &str) -> io::Error {
    io::Error::new(kind, format!("{code}: {what}"))
}

/// Per-host HMAC key. Never logged or serialized.
pub struct HostKey([u8; 32]);

impl Drop for HostKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for HostKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostKey(..)")
    }
}

impl HostKey {
    /// Read the key at `path`, refusing one that is not a regular file owned
    /// by this user with mode 0600 (no group or other bits).
    fn read(path: &Path) -> io::Result<Option<Self>> {
        let bytes =
            zeroize::Zeroizing::new(match read_owner_only(path, 32, "posture_key_insecure")? {
                Some(b) => b,
                None => return Ok(None),
            });
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            coded(
                io::ErrorKind::InvalidData,
                "posture_key_invalid",
                "posture host key has the wrong length",
            )
        })?;
        Ok(Some(Self(key)))
    }

    /// Read the key, or create it once without ever replacing one: the new
    /// key is published with a no-replace write, and a creator that loses the
    /// race reads the winner's key.
    fn load_or_create(path: &Path) -> io::Result<Self> {
        if let Some(key) = Self::read(path)? {
            return Ok(key);
        }
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        match crate::fs::write_new_file(path, &key) {
            Ok(()) => Ok(Self(key)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Self::read(path)?.ok_or_else(|| {
                    coded(
                        io::ErrorKind::NotFound,
                        "posture_key_missing",
                        "posture host key vanished",
                    )
                })
            }
            Err(e) => Err(path_free(e)),
        }
    }

    /// First 4 bytes of HMAC(key, "phantom.posture.keyid") as hex: identifies
    /// the key without revealing it.
    pub fn key_id(&self) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("hmac accepts any key length");
        mac.update(b"phantom.posture.keyid");
        hex::encode(&mac.finalize().into_bytes()[..4])
    }
}

/// Read a regular, non-symlink file owned by the current user with no group
/// or other permission bits. Errors carry a code and no path.
fn check_owner_only(meta: &std::fs::Metadata, code: &str) -> io::Result<()> {
    let mut safe = meta.is_file() && !meta.file_type().is_symlink();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        safe &= meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0;
    }
    #[cfg(windows)]
    {
        safe &= !crate::fs::is_reparse_point(meta);
    }
    if safe {
        Ok(())
    } else {
        Err(coded(
            io::ErrorKind::PermissionDenied,
            code,
            "posture file must be regular and owner-only",
        ))
    }
}

fn read_owner_only(path: &Path, limit: usize, code: &str) -> io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let open = || {
        crate::fs::open_regular_nofollow(path).map_err(|_| {
            coded(
                io::ErrorKind::PermissionDenied,
                code,
                "posture file cannot be opened safely",
            )
        })
    };
    let Some(mut file) = open()? else {
        return Ok(None);
    };
    check_owner_only(&file.metadata().map_err(path_free)?, code)?;
    let mut out = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(path_free)?;
    if out.len() > limit {
        return Err(coded(
            io::ErrorKind::InvalidData,
            "posture_oversized",
            "posture file exceeds its size limit",
        ));
    }
    let current =
        open()?.ok_or_else(|| coded(io::ErrorKind::NotFound, code, "posture file vanished"))?;
    if crate::fs::anchored::FileIdentity::from_std_file(&file).map_err(path_free)?
        != crate::fs::anchored::FileIdentity::from_std_file(&current).map_err(path_free)?
    {
        return Err(coded(
            io::ErrorKind::PermissionDenied,
            code,
            "posture file changed while reading",
        ));
    }
    Ok(Some(out))
}

/// Drop any path from an io::Error, keeping its kind.
fn path_free(e: io::Error) -> io::Error {
    let kind = e.kind();
    io::Error::new(kind, format!("posture_io: {kind}"))
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

/// Held exclusive lock on `history.lock` (std `File::try_lock`, flock on
/// Unix, LockFileEx on Windows); released on drop.
struct HistoryLock(std::fs::File);

impl Drop for HistoryLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
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

    /// The per-host key. Created once on first use; never regenerated while
    /// a history exists (`posture_key_missing`), so project ids cannot
    /// change silently.
    ///
    /// With history off this touches nothing and returns `posture_disabled`.
    ///
    /// Windows: only a regular-file, no-reparse-point check is made on the
    /// key (no owner or ACL check), and on every platform deleting
    /// history.jsonl together with host.key starts a fresh key without
    /// `posture_key_missing`; both are owner-only actions on a 0700 dir.
    pub fn host_key(&self) -> io::Result<HostKey> {
        if !history_enabled() {
            return Err(disabled());
        }
        crate::fs::ensure_private_dir(&self.dir).map_err(path_free)?;
        if let Some(key) = HostKey::read(&self.host_key_path())? {
            return Ok(key);
        }
        if std::fs::symlink_metadata(self.history_path())
            .map(|_| true)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    Ok(false)
                } else {
                    Err(path_free(e))
                }
            })?
        {
            return Err(coded(
                io::ErrorKind::NotFound,
                "posture_key_missing",
                "posture history exists but its host key is gone; refusing to mint a new one",
            ));
        }
        HostKey::load_or_create(&self.host_key_path())
    }

    fn lock(&self) -> io::Result<HistoryLock> {
        crate::fs::ensure_private_dir(&self.dir).map_err(path_free)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(
                libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_OPEN_REPARSE_POINT: open a symlink itself, not its target.
            opts.custom_flags(0x0020_0000);
        }
        let file = opts
            .open(self.dir.join("history.lock"))
            .map_err(path_free)?;
        check_owner_only(
            &file.metadata().map_err(path_free)?,
            "posture_lock_insecure",
        )?;
        match file.try_lock() {
            Ok(()) => Ok(HistoryLock(file)),
            Err(std::fs::TryLockError::WouldBlock) => Err(coded(
                io::ErrorKind::WouldBlock,
                "posture_locked",
                "posture history is busy",
            )),
            Err(std::fs::TryLockError::Error(e)) => Err(path_free(e)),
        }
    }

    /// Whether history is on (see [`HISTORY_ENV`]); the envelope's
    /// `history.enabled`.
    pub fn enabled(&self) -> bool {
        history_enabled()
    }

    /// Load every record. A missing file is an empty history; a malformed
    /// file is `InvalidData` (see [`HistoryError::classify`]). Errors carry
    /// no path.
    ///
    /// With history off this reads and creates nothing and returns an empty
    /// history; report `history.enabled: false` from [`Self::enabled`].
    pub fn load(&self) -> io::Result<Vec<PostureCounts>> {
        if !history_enabled() {
            return Ok(Vec::new());
        }
        match std::fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(coded(
                    io::ErrorKind::PermissionDenied,
                    "posture_directory_insecure",
                    "posture directory must be a real directory",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(path_free(e)),
        }
        let Some(bytes) = read_owner_only(
            &self.history_path(),
            MAX_HISTORY_BYTES,
            "posture_history_insecure",
        )?
        else {
            return Ok(Vec::new());
        };
        let text = String::from_utf8(bytes).map_err(|_| corrupted())?;
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let counts = serde_json::from_str(l).map_err(|_| corrupted())?;
                if !valid_counts(&counts) {
                    return Err(corrupted());
                }
                Ok(counts)
            })
            .collect()
    }

    /// Append a record under an exclusive non-blocking lock (`posture_locked`,
    /// [`HistoryError::Locked`] when another writer holds it). Callers must
    /// treat `posture_locked` as a failed write (the point was not stored),
    /// not as success; retry or report it. Returns
    /// `Ok(false)` when history is switched off. A record whose `key_id`
    /// differs from the history's is refused (`posture_key_changed`). A
    /// corrupted history is renamed to `history.jsonl.corrupt-<unix secs>`
    /// (never replacing an earlier one) and the new record is marked
    /// `reset_after_corruption`.
    pub fn record(&self, counts: &PostureCounts) -> io::Result<bool> {
        if !history_enabled() {
            return Ok(false);
        }
        if !valid_counts(counts) {
            return Err(coded(
                io::ErrorKind::InvalidInput,
                "posture_record_invalid",
                "posture record has an invalid schema or field",
            ));
        }
        let _lock = self.lock()?;
        if self.host_key()?.key_id() != counts.key_id {
            return Err(coded(
                io::ErrorKind::PermissionDenied,
                "posture_key_changed",
                "record was made under a different host key than this ledger",
            ));
        }
        let mut counts = counts.clone();
        let mut records = match self.load() {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                self.set_aside_corrupt()?;
                counts.reset_after_corruption = true;
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        if records
            .last()
            .is_some_and(|last| last.key_id != counts.key_id)
        {
            return Err(coded(
                io::ErrorKind::PermissionDenied,
                "posture_key_changed",
                "record was made under a different host key than this history",
            ));
        }
        records.push(counts);
        if records.len() > MAX_RECORDS {
            records.drain(..records.len() - MAX_RECORDS);
        }
        let mut out = String::new();
        for r in &records {
            out.push_str(&serde_json::to_string(r).map_err(io::Error::other)?);
            out.push('\n');
        }
        crate::fs::atomic_write(&self.history_path(), out.as_bytes()).map_err(path_free)?;
        Ok(true)
    }

    fn set_aside_corrupt(&self) -> io::Result<()> {
        let base = format!("history.jsonl.corrupt-{}", now_secs());
        for n in 0..100u32 {
            let name = if n == 0 {
                base.clone()
            } else {
                format!("{base}-{n}")
            };
            let target = self.dir.join(name);
            // Linking is no-replace, including when the destination is a dangling
            // symlink. Remove the original only after its bytes are preserved.
            match std::fs::hard_link(self.history_path(), target) {
                Ok(()) => return std::fs::remove_file(self.history_path()).map_err(path_free),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(path_free(e)),
            }
        }
        Err(coded(
            io::ErrorKind::AlreadyExists,
            "posture_corrupt_slots_full",
            "too many set-aside histories",
        ))
    }
}

fn disabled() -> io::Error {
    coded(
        io::ErrorKind::Unsupported,
        "posture_disabled",
        "posture history is off (PHANTOM_POSTURE_HISTORY)",
    )
}

fn corrupted() -> io::Error {
    coded(
        io::ErrorKind::InvalidData,
        "posture_corrupted",
        "posture history is corrupted; it will be set aside on the next record",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(l: &PostureLedger, n: u32) -> PostureCounts {
        PostureCounts {
            schema: 1,
            recorded_at: rfc3339_utc(n as u64),
            project: "0123456789abcdef".into(),
            wrapped: n,
            unwrapped: 0,
            expiring: 0,
            unrotated: 0,
            plaintext_env: 0,
            key_id: l.host_key().unwrap().key_id(),
            reset_after_corruption: false,
        }
    }

    #[test]
    fn size_cap_drops_oldest() {
        let d = tempfile::tempdir().unwrap();
        let l = PostureLedger::at(d.path().join("posture"));
        let seed: String = (0..MAX_RECORDS as u32)
            .map(|n| serde_json::to_string(&point(&l, n)).unwrap() + "\n")
            .collect();
        crate::fs::ensure_private_dir(&l.dir).unwrap();
        crate::fs::atomic_write(&l.history_path(), seed.as_bytes()).unwrap();
        l.record(&point(&l, 99_999)).unwrap();
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
        let first = point(&l, 1);
        crate::fs::atomic_write(&l.history_path(), b"{not json\n").unwrap();
        let err = l.load().unwrap_err();
        assert_eq!(HistoryError::classify(&err), HistoryError::Corrupted);
        assert!(!format!("{err}").contains(&*d.path().to_string_lossy()));
        assert!(l.record(&first).unwrap());
        let mut marked = first;
        marked.reset_after_corruption = true;
        assert_eq!(l.load().unwrap(), vec![marked]);
        // A second corruption never replaces the first set-aside file.
        std::fs::write(l.history_path(), "{not json again\n").unwrap();
        assert!(l.record(&point(&l, 2)).unwrap());
        let set_aside = std::fs::read_dir(&l.dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("history.jsonl.corrupt-")
            })
            .count();
        assert_eq!(set_aside, 2);
    }

    #[cfg(unix)]
    #[test]
    fn history_and_host_key_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let l = PostureLedger::at(d.path().join("posture"));
        l.record(&point(&l, 1)).unwrap();
        HostKey::load_or_create(&l.host_key_path()).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&l.dir), 0o700);
        assert_eq!(mode(&l.history_path()), 0o600);
        assert_eq!(mode(&l.host_key_path()), 0o600);
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
    fn local_fallback_matches_910_utf16_units_and_truncation() {
        // One emoji is two UTF-16 units, so two dashes, as in JS.
        assert_eq!(
            local_repo_name(Path::new("/w/proj-\u{1F600}")),
            "local/proj---"
        );
        assert_eq!(local_repo_name(Path::new("/w/caf\u{e9}")), "local/caf-");
        let long = format!("/w/{}\u{1F600}x", "a".repeat(99));
        assert_eq!(
            local_repo_name(Path::new(&long)),
            format!("local/{}-", "a".repeat(99))
        );
    }

    #[test]
    fn userinfo_with_two_at_signs_is_rejected_like_910() {
        assert_eq!(owner_name_from_remote("https://a@b@github.com/o/n"), None);
        assert_eq!(owner_name_from_remote("a@b@github.com:o/n.git"), None);
        assert_eq!(
            owner_name_from_remote("https://a@github.com/o/n").as_deref(),
            Some("o/n")
        );
    }

    #[test]
    fn key_id_is_stable_short_and_not_the_key() {
        let d = tempfile::tempdir().unwrap();
        let k = HostKey::load_or_create(&d.path().join("k")).unwrap();
        let id = k.key_id();
        assert_eq!(id.len(), 8);
        assert_eq!(
            id,
            HostKey::load_or_create(&d.path().join("k"))
                .unwrap()
                .key_id()
        );
        assert!(!hex::encode(k.0).contains(&id));
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
