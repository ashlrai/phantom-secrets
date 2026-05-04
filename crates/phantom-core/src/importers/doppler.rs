//! Doppler importer.
//!
//! Accepts two export formats produced by the Doppler CLI:
//!
//! 1. **Object format** (`doppler secrets download --no-file --format json`):
//!    ```json
//!    {
//!      "STRIPE_KEY": {"raw": "sk_live_...", "computed": "sk_live_...", "note": ""},
//!      "DATABASE_URL": {"raw": "postgres://...", "computed": "postgres://...", "note": ""}
//!    }
//!    ```
//!
//! 2. **Flat format** (also accepted — plain `{"KEY": "value"}` mapping):
//!    ```json
//!    {"STRIPE_KEY": "sk_live_...", "DATABASE_URL": "postgres://..."}
//!    ```
//!
//! Both formats are auto-detected by inspecting the first value in the object.

use anyhow::Result;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Importer, SecretMap};

pub struct DopplerImporter;

impl Importer for DopplerImporter {
    fn parse(input: &[u8]) -> Result<SecretMap> {
        let root: Value = serde_json::from_slice(input)
            .map_err(|e| anyhow::anyhow!("Doppler JSON parse error: {}", e))?;

        let obj = root
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Expected a JSON object at the top level"))?;

        let mut map = SecretMap::new();

        for (key, val) in obj.iter() {
            let raw_value: Option<String> = match val {
                // Object format: {"raw": "...", "computed": "...", ...}
                Value::Object(inner) => {
                    // Prefer "raw"; fall back to "computed" then any string field
                    let v = inner
                        .get("raw")
                        .or_else(|| inner.get("computed"))
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned);
                    v
                }
                // Flat format: "KEY": "value"
                Value::String(s) => Some(s.clone()),
                // Numbers, bools — coerce to string
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                // Null or nested objects we can't interpret
                _ => None,
            };

            let Some(value) = raw_value else {
                continue;
            };
            if value.is_empty() {
                continue;
            }

            // Doppler includes meta-keys like "DOPPLER_PROJECT", "DOPPLER_CONFIG",
            // "DOPPLER_ENVIRONMENT" — skip them.
            if key.starts_with("DOPPLER_") {
                continue;
            }

            if map.contains_key(key) {
                eprintln!("warn: duplicate key '{key}' in Doppler input — last value wins");
            }
            map.insert(key.clone(), Zeroizing::new(value));
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_object_format() {
        let input = r#"{
            "STRIPE_SECRET_KEY": {"raw": "sk_live_abc123", "computed": "sk_live_abc123", "note": ""},
            "DATABASE_URL": {"raw": "postgres://user:pass@host/db", "computed": "postgres://user:pass@host/db", "note": ""},
            "NODE_ENV": {"raw": "production", "computed": "production", "note": ""}
        }"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
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
    fn parse_flat_format() {
        let input = r#"{
            "OPENAI_API_KEY": "sk-proj-xxx",
            "STRIPE_SECRET_KEY": "sk_live_yyy",
            "PORT": "3000"
        }"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(
            map.get("OPENAI_API_KEY").map(|v| v.as_str()),
            Some("sk-proj-xxx")
        );
        assert_eq!(
            map.get("STRIPE_SECRET_KEY").map(|v| v.as_str()),
            Some("sk_live_yyy")
        );
        assert_eq!(map.get("PORT").map(|v| v.as_str()), Some("3000"));
    }

    #[test]
    fn skips_doppler_meta_keys() {
        let input = r#"{
            "DOPPLER_PROJECT": {"raw": "myproject", "computed": "myproject", "note": ""},
            "DOPPLER_CONFIG": {"raw": "prd", "computed": "prd", "note": ""},
            "DOPPLER_ENVIRONMENT": {"raw": "prd", "computed": "prd", "note": ""},
            "MY_SECRET": {"raw": "real_value", "computed": "real_value", "note": ""}
        }"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert!(!map.contains_key("DOPPLER_PROJECT"));
        assert!(!map.contains_key("DOPPLER_CONFIG"));
        assert!(!map.contains_key("DOPPLER_ENVIRONMENT"));
        assert_eq!(map.get("MY_SECRET").map(|v| v.as_str()), Some("real_value"));
    }

    #[test]
    fn skips_empty_values() {
        let input = r#"{
            "EMPTY_KEY": {"raw": "", "computed": "", "note": ""},
            "REAL_KEY": {"raw": "has_value", "computed": "has_value", "note": ""}
        }"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert!(!map.contains_key("EMPTY_KEY"));
        assert!(map.contains_key("REAL_KEY"));
    }

    #[test]
    fn rejects_non_object_input() {
        let input = r#"["not", "an", "object"]"#;
        assert!(DopplerImporter::parse(input.as_bytes()).is_err());
    }

    #[test]
    fn handles_mixed_flat_types() {
        // Doppler sometimes emits numbers/bools for non-secret config
        let input = r#"{
            "PORT": 3000,
            "DEBUG": true,
            "API_KEY": "sk-abc"
        }"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(map.get("PORT").map(|v| v.as_str()), Some("3000"));
        assert_eq!(map.get("DEBUG").map(|v| v.as_str()), Some("true"));
        assert_eq!(map.get("API_KEY").map(|v| v.as_str()), Some("sk-abc"));
    }
}
