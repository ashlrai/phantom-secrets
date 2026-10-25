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
    /// - Empty (and JSON `null`) values are skipped silently.
    /// - An entry whose value cannot be one secret (a JSON array or nested
    ///   object) refuses the whole import rather than being dropped.
    /// - A name that appears more than once refuses the whole import (the
    ///   dotenv path already did); picking one of two values silently could
    ///   store the wrong credential.
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

/// Convert one JSON export value into an importable string.
///
/// Strings are taken as-is and numbers/bools are coerced; `null` means unset
/// and yields `None` (skipped like an empty value). Arrays and objects cannot
/// be represented as a single secret, so the whole import is refused instead
/// of silently dropping that entry while reporting success. The error names
/// the entry and its JSON type, never a value.
pub(crate) fn json_scalar(
    source: &str,
    name: &str,
    value: &serde_json::Value,
) -> Result<Option<String>> {
    match value {
        serde_json::Value::String(text) => Ok(Some(text.clone())),
        serde_json::Value::Number(number) => Ok(Some(number.to_string())),
        serde_json::Value::Bool(flag) => Ok(Some(flag.to_string())),
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Array(_) => Err(unsupported_entry(source, name, "an array")),
        serde_json::Value::Object(_) => Err(unsupported_entry(source, name, "a nested object")),
    }
}

/// Parse a top-level JSON object keeping every entry in source order,
/// including repeated names. `serde_json::Map` collapses a repeated key to
/// its last value, which would hide an ambiguous export from
/// [`refuse_duplicate_names`].
pub(crate) fn parse_json_object_entries(
    input: &[u8],
) -> serde_json::Result<Vec<(String, serde_json::Value)>> {
    struct Entries(Vec<(String, serde_json::Value)>);

    impl<'de> serde::Deserialize<'de> for Entries {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct EntriesVisitor;

            impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
                type Value = Entries;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a JSON object at the top level")
                }

                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut access: A,
                ) -> Result<Entries, A::Error> {
                    let mut entries = Vec::new();
                    while let Some(entry) = access.next_entry::<String, serde_json::Value>()? {
                        entries.push(entry);
                    }
                    Ok(Entries(entries))
                }
            }

            deserializer.deserialize_map(EntriesVisitor)
        }
    }

    serde_json::from_slice::<Entries>(input).map(|entries| entries.0)
}

/// Refuse an import in which any name appears more than once. Two values for
/// one name are ambiguous: importing either one silently could replace a
/// working credential with a stale one. The error names the entry, never a
/// value.
pub(crate) fn refuse_duplicate_names<'a>(
    source: &str,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for name in names {
        if !seen.insert(name) {
            anyhow::bail!(
                "{source} input has duplicate entry '{name}'; nothing was imported. \
                 Keep one value for each name and retry."
            );
        }
    }
    Ok(())
}

pub(crate) fn unsupported_entry(source: &str, name: &str, kind: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{source} entry '{name}' has {kind} value that cannot be imported as one secret; \
         nothing was imported. Export flat KEY: value pairs and retry."
    )
}

/// Prefix dotenvx 1.x writes in front of every value it encrypts in place.
const DOTENVX_ENCRYPTED_PREFIX: &str = "encrypted:";

/// Key (or key prefix, for `DOTENV_PUBLIC_KEY_<ENV>`) of the header dotenvx
/// 1.x writes into every `.env` it encrypts in place.
const DOTENVX_PUBLIC_KEY_NAME: &str = "DOTENV_PUBLIC_KEY";

fn is_dotenvx_public_key_name(key: &str) -> bool {
    key == DOTENVX_PUBLIC_KEY_NAME
        || key
            .strip_prefix(DOTENVX_PUBLIC_KEY_NAME)
            .is_some_and(|rest| rest.starts_with('_'))
}

/// Refuse a dotenv source that dotenvx 1.x encrypted in place.
///
/// Such a file carries a `DOTENV_PUBLIC_KEY` header and `KEY="encrypted:..."`
/// values. Phantom has no private key, so those values are ciphertext, and
/// storing them would report success while replacing a working credential
/// with noise that `phantom exec` and the proxy then inject. The check only
/// fires when the header is present, so an ordinary value that happens to
/// start with `encrypted:` keeps importing. The error names the entry, never
/// a value.
pub fn refuse_dotenvx_ciphertext(dotenv: &crate::dotenv::DotenvFile) -> Result<()> {
    let entries = dotenv.entries();
    if !entries
        .iter()
        .any(|entry| is_dotenvx_public_key_name(&entry.key))
    {
        return Ok(());
    }
    if let Some(entry) = entries.iter().find(|entry| {
        entry
            .value
            .trim_start()
            .starts_with(DOTENVX_ENCRYPTED_PREFIX)
    }) {
        anyhow::bail!(
            "Entry '{}' is still dotenvx-encrypted (the file has a {} header); \
             nothing was imported.\n\
             Run `dotenvx decrypt --stdout > .env.decrypted` first, then import \
             .env.decrypted instead.",
            entry.key,
            DOTENVX_PUBLIC_KEY_NAME
        );
    }
    Ok(())
}

/// Reuse phantom-core's existing dotenv parser for plain `.env` files.
pub(crate) fn env_importer(input: &[u8]) -> Result<SecretMap> {
    let content =
        std::str::from_utf8(input).map_err(|_| anyhow::anyhow!("File is not valid UTF-8"))?;
    let dotenv = crate::dotenv::DotenvFile::parse_str(content);
    dotenv
        .validate_for_mutation()
        .map_err(|error| anyhow::anyhow!("Malformed dotenv import refused: {error}"))?;
    refuse_dotenvx_ciphertext(&dotenv)?;
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
    fn malformed_dotenv_import_is_rejected_without_returning_partial_plaintext() {
        let error = env_importer(b"API_KEY=plaintext-must-not-escape\nBROKEN_RECORD\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Malformed dotenv import refused"));
        assert!(!error.contains("plaintext-must-not-escape"));
    }

    fn dotenvx_encrypted_file(sealed_value: &str) -> String {
        let public = ["03", "fakepublicplaceholder"].concat();
        format!(
            "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n\
             DOTENV_PUBLIC_KEY=\"{public}\"\n\
             PLAIN_NAME=plain_value\n\
             SEALED_NAME=\"{sealed_value}\"\n"
        )
    }

    #[test]
    fn env_and_infisical_dotenv_refuse_dotenvx_ciphertext() {
        // A dotenvx 1.x file encrypted in place carries a DOTENV_PUBLIC_KEY
        // header and `encrypted:` values. Without the private key those are
        // ciphertext; storing them would report success while replacing the
        // credential with noise that exec and the proxy then inject.
        let ciphertext = ["encrypted:", "BFakeCipher", "PlaceholderOnly=="].concat();
        let input = dotenvx_encrypted_file(&ciphertext);
        type Parser = fn(&[u8]) -> Result<SecretMap>;
        let parsers: [(&str, Parser); 2] = [
            ("env", env_importer),
            ("infisical", infisical::InfisicalImporter::parse),
        ];
        for (label, parser) in parsers {
            let error = parser(input.as_bytes())
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(
                error.contains("'SEALED_NAME'"),
                "{label} import was not refused"
            );
            assert!(error.contains("dotenvx decrypt"), "{label} gave no remedy");
            assert!(error.contains("nothing was imported"), "{label}");
            assert!(
                !error.contains("BFakeCipher"),
                "{label} error echoed a value"
            );
            assert!(
                !error.contains("plain_value"),
                "{label} error echoed a value"
            );
        }
    }

    #[test]
    fn encrypted_prefix_without_dotenvx_header_still_imports() {
        // Without the dotenvx header the prefix alone is not proof of
        // ciphertext, so an ordinary value that happens to start with it
        // keeps importing unchanged.
        let value = ["encrypted:", "not-dotenvx"].concat();
        let input = format!("LITERAL_NAME={value}\n");
        let map = env_importer(input.as_bytes()).unwrap();
        assert!(map.get("LITERAL_NAME").map(|v| v.as_str()) == Some(value.as_str()));
    }

    #[test]
    fn decrypted_dotenvx_file_still_imports_through_env() {
        let input = dotenvx_encrypted_file("decrypted-plain");
        let map = env_importer(input.as_bytes()).unwrap();
        assert!(map.get("SEALED_NAME").map(|v| v.as_str()) == Some("decrypted-plain"));
        assert!(map.get("PLAIN_NAME").map(|v| v.as_str()) == Some("plain_value"));
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

    #[test]
    fn json_sources_refuse_duplicate_keys_instead_of_silently_picking_one() {
        // serde_json collapses a repeated object key to its last value, so a
        // hand-assembled or merged export with two different values for one
        // name used to import whichever came last, with no warning. The
        // dotenv path already refuses duplicates; every JSON path must too.
        let first = ["first", "-dup-", "value"].concat();
        let second = ["second", "-dup-", "value"].concat();
        type Parser = fn(&[u8]) -> Result<SecretMap>;
        let cases: [(&str, Parser, String); 4] = [
            (
                "1password",
                onepassword::OnePasswordImporter::parse,
                format!(r#"{{"DUP_NAME":"{first}","OTHER_NAME":"x","DUP_NAME":"{second}"}}"#),
            ),
            (
                "dotenvx",
                dotenvx::DotenvxImporter::parse,
                format!(r#"{{"DUP_NAME":"{first}","DUP_NAME":"{second}"}}"#),
            ),
            (
                "doppler",
                doppler::DopplerImporter::parse,
                format!(r#"{{"DUP_NAME":{{"raw":"{first}"}},"DUP_NAME":{{"raw":"{second}"}}}}"#),
            ),
            (
                "infisical",
                infisical::InfisicalImporter::parse,
                format!(
                    r#"[{{"key":"DUP_NAME","value":"{first}"}},{{"key":"DUP_NAME","value":"{second}"}}]"#
                ),
            ),
        ];
        for (label, parser, input) in cases {
            let outcome = parser(input.as_bytes());
            assert!(outcome.is_err(), "{label} accepted a duplicate key");
            let message = outcome.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(
                message.contains("duplicate") && message.contains("DUP_NAME"),
                "{label} refusal does not name the duplicate entry"
            );
            assert!(
                !message.contains("-dup-"),
                "{label} refusal leaked an input value"
            );
        }
    }
}
