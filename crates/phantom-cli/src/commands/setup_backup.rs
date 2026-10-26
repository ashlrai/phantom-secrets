//! Backup and manifest for `phantom setup --client`.
//!
//! Before setup changes an existing client config it copies the file byte for
//! byte to `<config>.phantom-bak-<ms>` (mode 0600, because a client config can
//! hold secrets in other keys) and records the change in
//! `<home>/.phantom/setup-manifest.json`. The manifest is value-free: paths,
//! a timestamp, the action, and SHA-256 hashes of the file before and after.
//! A later `--undo` uses the hashes to restore only files that are still as
//! setup left them.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(crate) const MANIFEST_RELATIVE: &str = ".phantom/setup-manifest.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ManifestEntry {
    /// Config file that setup wrote.
    pub path: PathBuf,
    /// Byte-for-byte copy taken before the write. `None` when setup created the file.
    pub backup: Option<PathBuf>,
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: u128,
    /// `add` (no phantom entry before) or `replace` (a differing entry was overwritten).
    pub action: String,
    /// SHA-256 of the file before setup, `None` when the file did not exist.
    pub sha256_before: Option<String>,
    /// SHA-256 of the bytes setup wrote.
    pub sha256_after: String,
    /// Set by `setup --undo --apply` once this entry has been undone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_ms: Option<u128>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub version: u32,
    pub entries: Vec<ManifestEntry>,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn manifest_path(home: &Path) -> PathBuf {
    home.join(MANIFEST_RELATIVE)
}

pub(crate) fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Load the manifest. A missing file is an empty manifest; an unreadable or
/// invalid one is an error so setup never overwrites history it cannot parse.
pub(crate) fn load(home: &Path) -> Result<Manifest> {
    let path = manifest_path(home);
    match phantom_core::fs::read_regular_file(&path)
        .with_context(|| format!("Failed to safely read {}", path.display()))?
    {
        None => Ok(Manifest {
            version: 1,
            entries: Vec::new(),
        }),
        Some(bytes) => {
            let manifest: Manifest = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "{} is not a valid setup manifest; move it aside to continue",
                    path.display()
                )
            })?;
            if manifest.version != 1 {
                bail!(
                    "{} has unsupported version {}",
                    path.display(),
                    manifest.version
                );
            }
            Ok(manifest)
        }
    }
}

/// Append one entry and write the manifest atomically with private permissions.
pub(crate) fn record(home: &Path, entry: ManifestEntry) -> Result<()> {
    let mut manifest = load(home)?;
    manifest.entries.push(entry);
    save(home, &manifest)
}

/// Write the manifest atomically with private permissions.
pub(crate) fn save(home: &Path, manifest: &Manifest) -> Result<()> {
    let path = manifest_path(home);
    phantom_core::fs::ensure_real_parent(&path)?;
    let bytes = serde_json::to_vec_pretty(manifest).context("Failed to serialize manifest")?;
    phantom_core::fs::atomic_write(&path, &bytes)
        .with_context(|| format!("Failed to write {}", path.display()))
}

/// Write `<config>.phantom-bak-<ms>` next to the config and return its path.
/// Never overwrites an existing backup.
pub(crate) fn write_backup(config: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let name = config
        .file_name()
        .and_then(|n| n.to_str())
        .context("Config path has no UTF-8 filename")?
        .to_string();
    let mut ms = now_ms();
    loop {
        let candidate = config.with_file_name(format!("{name}.phantom-bak-{ms}"));
        // Exclusive create: an object already at the name (even one made
        // after any check we could do) is never replaced; take the next name.
        match phantom_core::fs::write_new_file(&candidate, bytes) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => ms += 1,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to write backup {}", candidate.display()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_manifest_is_empty_and_invalid_one_is_refused() {
        let home = tempdir().unwrap();
        assert!(load(home.path()).unwrap().entries.is_empty());
        std::fs::create_dir_all(home.path().join(".phantom")).unwrap();
        std::fs::write(manifest_path(home.path()), b"not json").unwrap();
        assert!(load(home.path()).is_err());
        // Never overwritten: record refuses too.
        let entry = ManifestEntry {
            path: "/x".into(),
            backup: None,
            timestamp_ms: 1,
            action: "add".into(),
            sha256_before: None,
            sha256_after: sha256_hex(b"a"),
            undone_ms: None,
        };
        assert!(record(home.path(), entry).is_err());
        assert_eq!(
            std::fs::read(manifest_path(home.path())).unwrap(),
            b"not json"
        );
    }

    #[test]
    fn record_appends_and_backup_is_exact_and_never_clobbers() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("c.json");
        let b1 = write_backup(&cfg, b"one").unwrap();
        let b2 = write_backup(&cfg, b"two").unwrap();
        assert_ne!(b1, b2);
        assert_eq!(std::fs::read(&b1).unwrap(), b"one");
        for n in 0..2u128 {
            record(
                home.path(),
                ManifestEntry {
                    path: cfg.clone(),
                    backup: Some(b1.clone()),
                    timestamp_ms: n,
                    action: "replace".into(),
                    sha256_before: Some(sha256_hex(b"one")),
                    sha256_after: sha256_hex(b"two"),
                    undone_ms: None,
                },
            )
            .unwrap();
        }
        let m = load(home.path()).unwrap();
        assert_eq!(m.entries.len(), 2);
        assert_eq!(m.version, 1);
    }

    #[test]
    fn concurrent_backups_never_replace_each_other() {
        // Many writers racing for the same millisecond name must each get
        // their own backup; none may replace another's bytes.
        for _ in 0..20 {
            let home = tempdir().unwrap();
            let cfg = home.path().join("c.json");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
            let handles: Vec<_> = (0..16u8)
                .map(|i| {
                    let cfg = cfg.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        (i, write_backup(&cfg, &[i; 8]).unwrap())
                    })
                })
                .collect();
            let results: Vec<(u8, PathBuf)> =
                handles.into_iter().map(|h| h.join().unwrap()).collect();
            let mut paths: Vec<&PathBuf> = results.iter().map(|(_, p)| p).collect();
            paths.sort();
            paths.dedup();
            assert_eq!(paths.len(), results.len());
            for (i, path) in &results {
                assert_eq!(std::fs::read(path).unwrap(), vec![*i; 8]);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_never_replaces_a_dangling_symlink_or_its_target() {
        let home = tempdir().unwrap();
        let cfg = home.path().join("c.json");
        let ms = now_ms();
        // Occupy the next names with dangling links; the backup must skip them.
        for n in 0..50u128 {
            let name = home.path().join(format!("c.json.phantom-bak-{}", ms + n));
            std::os::unix::fs::symlink(home.path().join(format!("gone-{n}")), name).unwrap();
        }
        let b = write_backup(&cfg, b"payload").unwrap();
        assert!(!std::fs::symlink_metadata(&b)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&b).unwrap(), b"payload");
        for n in 0..50u128 {
            assert!(!home.path().join(format!("gone-{n}")).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_and_manifest_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempdir().unwrap();
        let cfg = home.path().join("c.json");
        let b = write_backup(&cfg, b"secret-ish").unwrap();
        assert_eq!(
            std::fs::metadata(&b).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
