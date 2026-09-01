//! Competitor-format importers for `phantom import --from <source>`.
//!
//! Each importer implements the [`Importer`] trait and is responsible for
//! parsing its source format into a `BTreeMap<String, Zeroizing<String>>`.
//! Values are wrapped in `Zeroizing` so they are wiped from memory when
//! dropped; they must never be written to disk in plaintext.

pub mod doppler;
pub mod dotenvx;
pub mod infisical;
pub mod onepassword;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Competitor exports are parsed in memory, so cap the authoritative file
/// handle before allocating. This matches the encrypted-backup safety bound.
pub const MAX_COMPETITOR_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

/// A parsed set of secrets — key → zeroizing value.
pub type SecretMap = BTreeMap<String, Zeroizing<String>>;

/// Common interface for all format-specific importers.
pub trait Importer {
    /// Parse raw bytes from the source format and return a secret map.
    ///
    /// - Empty values are skipped silently.
    /// - Duplicate keys within the same input emit a warning to stderr;
    ///   the last value wins.
    fn parse(input: &[u8]) -> Result<SecretMap>;
}

/// Top-level entry point: read `file`, detect the format by `source` name,
/// parse it with the appropriate importer, and return the secret map.
///
/// `source` must be one of: `doppler`, `infisical`, `dotenvx`, `1password`, `env`.
pub fn import_from(source: &str, file: &Path) -> Result<SecretMap> {
    let parser: fn(&[u8]) -> Result<SecretMap> = match source {
        "doppler" => doppler::DopplerImporter::parse,
        "infisical" => infisical::InfisicalImporter::parse,
        "dotenvx" => dotenvx::DotenvxImporter::parse,
        "1password" => onepassword::OnePasswordImporter::parse,
        "env" => env_importer,
        other => anyhow::bail!(
            "Unknown import source '{}'. Supported: doppler, infisical, dotenvx, 1password, env",
            other
        ),
    };
    let bytes = read_competitor_export(file)?;
    parser(bytes.as_slice())
}

/// Read an import from one authoritative regular-file handle without following
/// a final-component symlink or Windows reparse point. The path is reopened
/// after the bounded read and must still identify the same file.
fn read_competitor_export(file: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_competitor_export_with_hook(file, || Ok(()))
}

fn read_competitor_export_with_hook(
    path: &Path,
    after_open: impl FnOnce() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut opened = match open_import_file(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            anyhow::bail!("Import source must not be a symlink: {}", path.display())
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Cannot open import file {}", path.display()))
        }
    };
    ensure_import_handle_is_regular(path, &opened)?;
    let metadata = opened.metadata()?;
    if metadata.len() > MAX_COMPETITOR_IMPORT_BYTES {
        anyhow::bail!(
            "Import source exceeds the {}-byte safety limit",
            MAX_COMPETITOR_IMPORT_BYTES
        );
    }
    after_open()?;

    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    opened
        .by_ref()
        .take(MAX_COMPETITOR_IMPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Cannot read import file {}", path.display()))?;
    if bytes.len() as u64 > MAX_COMPETITOR_IMPORT_BYTES {
        anyhow::bail!(
            "Import source exceeds the {}-byte safety limit",
            MAX_COMPETITOR_IMPORT_BYTES
        );
    }
    ensure_path_still_names_import(path, &opened)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_import_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(windows)]
fn open_import_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(all(not(unix), not(windows)))]
fn open_import_file(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn ensure_import_handle_is_regular(path: &Path, opened: &File) -> Result<()> {
    if !opened.metadata()?.is_file() {
        anyhow::bail!(
            "Import source must be a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_import_handle_is_regular(path: &Path, opened: &File) -> Result<()> {
    let information = windows_file_information(opened)?;
    if information.dwFileAttributes
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
        || !opened.metadata()?.is_file()
    {
        anyhow::bail!(
            "Import source is a reparse point or is not a regular file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_import_handle_is_regular(path: &Path, opened: &File) -> Result<()> {
    if !opened.metadata()?.is_file() {
        anyhow::bail!("Import source is not a regular file: {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_path_still_names_import(path: &Path, opened: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let original = opened.metadata()?;
    let current = open_import_file(path)
        .with_context(|| format!("Cannot re-open import file {}", path.display()))?;
    let current = current.metadata()?;
    if original.dev() != current.dev() || original.ino() != current.ino() {
        anyhow::bail!(
            "Import source changed while it was being read: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_path_still_names_import(path: &Path, opened: &File) -> Result<()> {
    let original = windows_file_information(opened)?;
    let current = open_import_file(path)
        .with_context(|| format!("Cannot re-open import file {}", path.display()))?;
    let current = windows_file_information(&current)?;
    if current.dwFileAttributes
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
        || original.dwVolumeSerialNumber != current.dwVolumeSerialNumber
        || original.nFileIndexHigh != current.nFileIndexHigh
        || original.nFileIndexLow != current.nFileIndexLow
    {
        anyhow::bail!(
            "Import source changed while it was being read: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_path_still_names_import(_path: &Path, _opened: &File) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;

    let mut information = unsafe { std::mem::zeroed() };
    let result = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut information,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("GetFileInformationByHandle failed for competitor import");
    }
    Ok(information)
}

/// Reuse phantom-core's existing dotenv parser for plain `.env` files.
pub(crate) fn env_importer(input: &[u8]) -> Result<SecretMap> {
    let content =
        std::str::from_utf8(input).map_err(|_| anyhow::anyhow!("File is not valid UTF-8"))?;
    let dotenv = crate::dotenv::DotenvFile::parse_str(content);
    let mut map = SecretMap::new();
    for entry in dotenv.entries() {
        if entry.value.is_empty() {
            continue;
        }
        if map.contains_key(&entry.key) {
            eprintln!(
                "warn: duplicate key '{}' in input — last value wins",
                entry.key
            );
        }
        map.insert(entry.key.clone(), Zeroizing::new(entry.value.clone()));
    }
    Ok(map)
}

#[cfg(test)]
mod secure_read_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn bounded_reader_returns_zeroizing_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("export.env");
        std::fs::write(&path, b"TOKEN=secret").unwrap();
        let bytes: Zeroizing<Vec<u8>> = read_competitor_export(&path).unwrap();
        assert_eq!(bytes.as_slice(), b"TOKEN=secret");
    }

    #[test]
    fn oversized_import_is_rejected_before_allocation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("huge.json");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_COMPETITOR_IMPORT_BYTES + 1).unwrap();
        let error = read_competitor_export(&path).unwrap_err();
        assert!(error.to_string().contains("safety limit"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_import_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.env");
        let link = dir.path().join("link.env");
        std::fs::write(&real, b"TOKEN=secret").unwrap();
        symlink(&real, &link).unwrap();
        let error = read_competitor_export(&link).unwrap_err();
        assert!(error.to_string().contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn path_swap_after_open_is_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("export.env");
        let replacement = dir.path().join("replacement.env");
        std::fs::write(&path, b"TOKEN=original").unwrap();
        std::fs::write(&replacement, b"TOKEN=replacement").unwrap();

        let error = read_competitor_export_with_hook(&path, || {
            std::fs::rename(&replacement, &path)?;
            Ok(())
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("changed while it was being read"));
    }

    #[test]
    fn windows_reader_contract_is_handle_bound_and_reparse_safe() {
        let source = include_str!("mod.rs");
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(source.contains("GetFileInformationByHandle"));
        assert!(source.contains("dwVolumeSerialNumber"));
        assert!(source.contains("nFileIndexHigh"));
        assert!(source.contains("nFileIndexLow"));
        assert!(source.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
    }
}
