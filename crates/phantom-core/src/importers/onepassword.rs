//! 1Password importer.
//!
//! Accepts a user-pre-collected flat JSON mapping that a 1Password user can
//! assemble from `op read` output. Phantom does **not** shell out to `op` —
//! the user collects the secrets into a JSON file and passes it here.
//!
//! **Supported format** (`--file` argument):
//! ```json
//! {
//!   "STRIPE_SECRET_KEY": "sk_live_abc123",
//!   "DATABASE_URL": "postgres://user:pass@host/db",
//!   "OPENAI_API_KEY": "sk-proj-xxx"
//! }
//! ```
//!
//! **How to create this file** (recommended workflow):
//! ```sh
//! # Read individual secrets and build the JSON manually, or use jq:
//! op item get "My App Secrets" --vault Dev --format json \
//!   | jq '{ (.fields[] | select(.value != null) | .label): .fields[] | select(.value != null) | .value }' \
//!   > 1p-export.json
//!
//! phantom import --from 1password --file 1p-export.json
//! ```
//!
//! The file is read once and never written back to disk.

use anyhow::Result;
use zeroize::Zeroizing;

use super::{json_scalar, parse_json_object_entries, refuse_duplicate_names, Importer, SecretMap};

pub struct OnePasswordImporter;

impl Importer for OnePasswordImporter {
    fn parse(input: &[u8]) -> Result<SecretMap> {
        let obj = parse_json_object_entries(input).map_err(|e| {
            anyhow::anyhow!(
                "1Password JSON parse error: {e}\n\
                Expected a flat JSON object: {{\"KEY\": \"value\", ...}}\n\
                See `phantom import --from 1password --help` for the expected format."
            )
        })?;
        refuse_duplicate_names("1Password", obj.iter().map(|(key, _)| key.as_str()))?;

        let mut map = SecretMap::new();
        for (key, val) in obj {
            let Some(value) = json_scalar("1Password", &key, &val)? else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            map.insert(key, Zeroizing::new(value));
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flat_json() {
        let input = r#"{
            "STRIPE_SECRET_KEY": "sk_live_abc123",
            "DATABASE_URL": "postgres://user:pass@host/db",
            "OPENAI_API_KEY": "sk-proj-xxx"
        }"#;
        let map = OnePasswordImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(
            map.get("STRIPE_SECRET_KEY").map(|v| v.as_str()),
            Some("sk_live_abc123")
        );
        assert_eq!(
            map.get("DATABASE_URL").map(|v| v.as_str()),
            Some("postgres://user:pass@host/db")
        );
        assert_eq!(
            map.get("OPENAI_API_KEY").map(|v| v.as_str()),
            Some("sk-proj-xxx")
        );
    }

    #[test]
    fn skips_empty_values() {
        let input = r#"{
            "EMPTY_KEY": "",
            "REAL_KEY": "has_value",
            "NULL_KEY": null
        }"#;
        let map = OnePasswordImporter::parse(input.as_bytes()).unwrap();
        assert!(!map.contains_key("EMPTY_KEY"));
        assert!(!map.contains_key("NULL_KEY"));
        assert_eq!(map.get("REAL_KEY").map(|v| v.as_str()), Some("has_value"));
    }

    #[test]
    fn refuses_nested_objects_and_arrays_instead_of_dropping_them() {
        // A nested op item or a list cannot be one secret. Dropping it while
        // the CLI reports "0 skipped, 0 failed" would lose the entry silently.
        for input in [
            r#"{"FLAT_KEY": "flat_value", "NESTED": {"username": "u", "field": "f"}}"#,
            r#"{"FLAT_KEY": "flat_value", "NESTED": ["one", "two"]}"#,
        ] {
            let error = OnePasswordImporter::parse(input.as_bytes())
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(error.contains("'NESTED'"));
            assert!(error.contains("nothing was imported"));
            assert!(!error.contains("flat_value"));
        }
    }

    #[test]
    fn rejects_non_object_input() {
        let input = r#"["not", "an", "object"]"#;
        let result = OnePasswordImporter::parse(input.as_bytes());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("flat JSON object"));
    }

    #[test]
    fn coerces_number_and_bool_values() {
        let input = r#"{
            "PORT": 3000,
            "DEBUG": false,
            "API_KEY": "sk-abc"
        }"#;
        let map = OnePasswordImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(map.get("PORT").map(|v| v.as_str()), Some("3000"));
        assert_eq!(map.get("DEBUG").map(|v| v.as_str()), Some("false"));
        assert_eq!(map.get("API_KEY").map(|v| v.as_str()), Some("sk-abc"));
    }

    #[test]
    fn rejects_malformed_json() {
        let input = b"{broken json}";
        assert!(OnePasswordImporter::parse(input).is_err());
    }
}
