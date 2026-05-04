//! Infisical importer.
//!
//! Accepts two export formats produced by the Infisical CLI:
//!
//! 1. **dotenv format** (`infisical export --format dotenv`):
//!    Standard `.env` syntax — reuses phantom-core's existing dotenv parser.
//!    ```text
//!    STRIPE_SECRET_KEY=sk_live_abc123
//!    DATABASE_URL="postgres://user:pass@host/db"
//!    ```
//!
//! 2. **JSON format** (`infisical export --format json`):
//!    An array of `{key, value}` objects.
//!    ```json
//!    [
//!      {"key": "STRIPE_SECRET_KEY", "value": "sk_live_abc123"},
//!      {"key": "DATABASE_URL", "value": "postgres://user:pass@host/db"}
//!    ]
//!    ```
//!
//! Format is auto-detected: if the trimmed input starts with `[`, it's JSON;
//! otherwise it's treated as dotenv.

use anyhow::Result;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{env_importer, Importer, SecretMap};

pub struct InfisicalImporter;

#[derive(Deserialize)]
struct InfisicalEntry {
    key: String,
    value: String,
}

impl Importer for InfisicalImporter {
    fn parse(input: &[u8]) -> Result<SecretMap> {
        // Auto-detect format by checking if content looks like a JSON array
        let trimmed = input.iter().copied().find(|b| !b.is_ascii_whitespace());

        if trimmed == Some(b'[') {
            parse_json_array(input)
        } else {
            // Fall through to dotenv parser
            env_importer(input)
        }
    }
}

fn parse_json_array(input: &[u8]) -> Result<SecretMap> {
    let entries: Vec<InfisicalEntry> = serde_json::from_slice(input)
        .map_err(|e| anyhow::anyhow!("Infisical JSON parse error: {}", e))?;

    let mut map = SecretMap::new();
    for entry in entries {
        if entry.value.is_empty() {
            continue;
        }
        if map.contains_key(&entry.key) {
            eprintln!(
                "warn: duplicate key '{}' in Infisical input — last value wins",
                entry.key
            );
        }
        map.insert(entry.key, Zeroizing::new(entry.value));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_array_format() {
        let input = r#"[
            {"key": "STRIPE_SECRET_KEY", "value": "sk_live_abc123"},
            {"key": "DATABASE_URL", "value": "postgres://user:pass@host/db"},
            {"key": "NODE_ENV", "value": "production"}
        ]"#;
        let map = InfisicalImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(
            map.get("STRIPE_SECRET_KEY").map(|v| v.as_str()),
            Some("sk_live_abc123")
        );
        assert_eq!(
            map.get("DATABASE_URL").map(|v| v.as_str()),
            Some("postgres://user:pass@host/db")
        );
        assert_eq!(map.get("NODE_ENV").map(|v| v.as_str()), Some("production"));
    }

    #[test]
    fn parse_dotenv_format() {
        let input = b"STRIPE_SECRET_KEY=sk_live_abc123\nDATABASE_URL=postgres://user:pass@host/db\nNODE_ENV=production\n";
        let map = InfisicalImporter::parse(input).unwrap();
        assert_eq!(
            map.get("STRIPE_SECRET_KEY").map(|v| v.as_str()),
            Some("sk_live_abc123")
        );
        assert_eq!(
            map.get("DATABASE_URL").map(|v| v.as_str()),
            Some("postgres://user:pass@host/db")
        );
        assert_eq!(map.get("NODE_ENV").map(|v| v.as_str()), Some("production"));
    }

    #[test]
    fn parse_dotenv_with_quotes() {
        let input = b"API_KEY=\"sk-proj-with spaces\"\nOTHER='single quoted'\n";
        let map = InfisicalImporter::parse(input).unwrap();
        assert_eq!(
            map.get("API_KEY").map(|v| v.as_str()),
            Some("sk-proj-with spaces")
        );
        assert_eq!(map.get("OTHER").map(|v| v.as_str()), Some("single quoted"));
    }

    #[test]
    fn skips_empty_values_json() {
        let input = r#"[
            {"key": "EMPTY", "value": ""},
            {"key": "REAL", "value": "has_value"}
        ]"#;
        let map = InfisicalImporter::parse(input.as_bytes()).unwrap();
        assert!(!map.contains_key("EMPTY"));
        assert!(map.contains_key("REAL"));
    }

    #[test]
    fn rejects_malformed_json_array() {
        let input = b"[{\"key\": \"K\", broken}]";
        assert!(InfisicalImporter::parse(input).is_err());
    }
}
