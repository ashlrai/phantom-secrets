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
use std::path::Path;

use anyhow::Result;
use zeroize::Zeroizing;

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
    let bytes = std::fs::read(file)
        .map_err(|e| anyhow::anyhow!("Cannot read file {}: {}", file.display(), e))?;

    match source {
        "doppler" => doppler::DopplerImporter::parse(&bytes),
        "infisical" => infisical::InfisicalImporter::parse(&bytes),
        "dotenvx" => dotenvx::DotenvxImporter::parse(&bytes),
        "1password" => onepassword::OnePasswordImporter::parse(&bytes),
        "env" => env_importer(&bytes),
        other => anyhow::bail!(
            "Unknown import source '{}'. Supported: doppler, infisical, dotenvx, 1password, env",
            other
        ),
    }
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
