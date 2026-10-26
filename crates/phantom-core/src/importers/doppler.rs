//! Doppler importer.
//!
//! Accepts two export formats produced by the Doppler CLI:
//!
//! 1. **Object format** (`doppler secrets --json`):
//!    ```json
//!    {
//!      "STRIPE_KEY": {"raw": "sk_live_...", "computed": "sk_live_...", "note": ""},
//!      "DATABASE_URL": {"raw": "postgres://...", "computed": "postgres://...", "note": ""}
//!    }
//!    ```
//!
//! 2. **Flat format** (`doppler secrets download --no-file --format json`, a
//!    plain `{"KEY": "value"}` mapping):
//!    ```json
//!    {"STRIPE_KEY": "sk_live_...", "DATABASE_URL": "postgres://..."}
//!    ```
//!
//! The shape is recognised per entry: an object value is the nested form,
//! a string, number or bool is the flat form.
//! In the object format the resolved `computed` value is imported; `raw` keeps
//! `${OTHER}` references unresolved and is used only when `computed` is null.

use anyhow::Result;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{
    json_scalar, parse_json_object_entries, refuse_duplicate_names, refuse_invalid_names,
    unsupported_entry, utf8_export_body, Importer, SecretMap,
};

pub struct DopplerImporter;

impl Importer for DopplerImporter {
    fn parse(input: &[u8]) -> Result<SecretMap> {
        let input = utf8_export_body("Doppler", input)?;
        let obj = parse_json_object_entries(input)
            .map_err(|e| anyhow::anyhow!("Doppler JSON parse error: {}", e))?;
        // Meta-keys are skipped below, so only secret names must be unique.
        let secret_names = || {
            obj.iter()
                .map(|(key, _)| key.as_str())
                .filter(|key| !key.starts_with("DOPPLER_"))
        };
        refuse_duplicate_names("Doppler", secret_names())?;
        refuse_invalid_names("Doppler", secret_names())?;

        let mut map = SecretMap::new();

        for (key, val) in obj.iter() {
            // Doppler includes meta-keys like "DOPPLER_PROJECT", "DOPPLER_CONFIG",
            // "DOPPLER_ENVIRONMENT" — skip them before interpreting the value.
            if key.starts_with("DOPPLER_") {
                continue;
            }

            let raw_value: Option<String> = match val {
                // Object format: {"raw": "...", "computed": "...", ...}.
                // Prefer a non-null "computed" (references like `${OTHER}`
                // resolved, the value an app receives), then "raw"; an
                // object with neither field is not a Doppler secret and is
                // refused.
                Value::Object(inner) => {
                    let mut chosen = None;
                    let mut seen = false;
                    for field in ["computed", "raw"] {
                        if let Some(candidate) = inner.get(field) {
                            seen = true;
                            chosen = json_scalar("Doppler", key, candidate)?;
                            if chosen.is_some() {
                                break;
                            }
                        }
                    }
                    if !seen {
                        return Err(unsupported_entry(
                            "Doppler",
                            key,
                            "an object without a raw or computed",
                        ));
                    }
                    chosen
                }
                // Flat format: "KEY": "value"; numbers/bools are coerced,
                // null is unset, arrays are refused.
                other => json_scalar("Doppler", key, other)?,
            };

            let Some(value) = raw_value else {
                continue;
            };
            if value.is_empty() {
                continue;
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

    #[test]
    fn imports_the_computed_value_not_the_unresolved_raw_reference() {
        // Doppler's `raw` keeps `${OTHER}` references as typed; `computed` is
        // the resolved value an app actually receives. Importing `raw` would
        // store the literal reference text and break the injected value.
        let input = r#"{
            "DB_USER": {"raw": "app", "computed": "app", "note": ""},
            "DATABASE_URL": {"raw": "postgres://${DB_USER}@host/db", "computed": "postgres://app@host/db", "note": ""}
        }"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(
            map.get("DATABASE_URL").map(|v| v.as_str()),
            Some("postgres://app@host/db")
        );
    }

    #[test]
    fn computed_null_falls_back_to_raw() {
        let input = r#"{"REAL_KEY": {"raw": "raw_value", "computed": null, "note": ""}}"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(map.get("REAL_KEY").map(|v| v.as_str()), Some("raw_value"));
    }

    #[test]
    fn raw_null_falls_back_to_computed() {
        let input = r#"{"REAL_KEY": {"raw": null, "computed": "computed_value", "note": ""}}"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(
            map.get("REAL_KEY").map(|v| v.as_str()),
            Some("computed_value")
        );
    }

    #[test]
    fn refuses_entries_it_cannot_interpret_instead_of_dropping_them() {
        // Each of these used to be dropped silently while the rest imported
        // and the CLI reported "0 skipped, 0 failed".
        for input in [
            r#"{"KEEP": "kept_value", "BAD": ["one", "two"]}"#,
            r#"{"KEEP": "kept_value", "BAD": {"value": "v", "note": ""}}"#,
            r#"{"KEEP": "kept_value", "BAD": {"raw": ["v"], "note": ""}}"#,
            r#"{"KEEP": "kept_value", "BAD": {"raw": {"nested": "v"}}}"#,
        ] {
            let error = DopplerImporter::parse(input.as_bytes())
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(error.contains("'BAD'"));
            assert!(error.contains("nothing was imported"));
            assert!(!error.contains("kept_value"));
        }
    }

    #[test]
    fn null_values_are_unset_and_meta_keys_skip_before_parsing() {
        let input = r#"{
            "NULL_FLAT": null,
            "NULL_OBJECT": {"raw": null, "computed": null},
            "DOPPLER_EXTRA": ["meta", "list"],
            "REAL_KEY": "has_value"
        }"#;
        let map = DopplerImporter::parse(input.as_bytes()).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("REAL_KEY"));
    }
}
