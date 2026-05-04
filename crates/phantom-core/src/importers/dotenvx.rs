//! dotenvx importer.
//!
//! Supports importing from dotenvx projects. **Encrypted `.env.vault` files
//! are NOT decrypted** — that requires the per-environment `DOTENV_KEY` which
//! is outside the scope of this importer. Pass a plain `.env` file instead.
//!
//! Accepted inputs:
//!
//! 1. **Plain `.env` file** — standard dotenv syntax (the most common case
//!    when migrating to Phantom from a dotenvx project):
//!    ```text
//!    STRIPE_SECRET_KEY=sk_live_abc123
//!    ```
//!
//! 2. **`dotenvx ls --format json` output** — a flat JSON object:
//!    ```json
//!    {"STRIPE_SECRET_KEY": "sk_live_abc123", "DATABASE_URL": "postgres://..."}
//!    ```
//!
//! **Note on `.env.vault`:** `.env.vault` files are AES-256-GCM encrypted per
//! environment using a `DOTENV_KEY` that Phantom does not have access to.
//! Run `dotenvx decrypt --stdout > .env` first, then import the plaintext
//! `.env` with `phantom import --from dotenvx --file .env`.
//!
//! Format is auto-detected: if the trimmed input starts with `{`, it's JSON;
//! otherwise it's treated as dotenv.

use anyhow::Result;
use zeroize::Zeroizing;

use super::{env_importer, Importer, SecretMap};

pub struct DotenvxImporter;

impl Importer for DotenvxImporter {
    fn parse(input: &[u8]) -> Result<SecretMap> {
        // Check if this looks like an encrypted .env.vault — refuse gracefully.
        if let Ok(text) = std::str::from_utf8(input) {
            let trimmed = text.trim_start();
            if trimmed.starts_with("#/-------------------[DOTENV_VAULT]")
                || trimmed.contains("DOTENV_VAULT_")
            {
                anyhow::bail!(
                    "Encrypted .env.vault files cannot be imported directly.\n\
                     Run `dotenvx decrypt --stdout > .env` first, then:\n  \
                     phantom import --from dotenvx --file .env"
                );
            }
        }

        // Auto-detect: JSON object vs dotenv
        let first_non_ws = input.iter().copied().find(|b| !b.is_ascii_whitespace());

        if first_non_ws == Some(b'{') {
            parse_flat_json(input)
        } else {
            env_importer(input)
        }
    }
}

fn parse_flat_json(input: &[u8]) -> Result<SecretMap> {
    let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(input)
        .map_err(|e| anyhow::anyhow!("dotenvx JSON parse error: {}", e))?;

    let mut map = SecretMap::new();
    for (key, val) in obj {
        let value = match &val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => continue,
        };
        if value.is_empty() {
            continue;
        }
        if map.contains_key(&key) {
            eprintln!("warn: duplicate key '{key}' in dotenvx input — last value wins");
        }
        map.insert(key, Zeroizing::new(value));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_dotenv() {
        let input = b"STRIPE_SECRET_KEY=sk_live_abc123\nDATABASE_URL=postgres://user:pass@host/db\nNODE_ENV=production\n";
        let map = DotenvxImporter::parse(input).unwrap();
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
    fn parse_json_flat_format() {
        let input = r#"{
            "OPENAI_API_KEY": "sk-proj-xxx",
            "STRIPE_SECRET_KEY": "sk_live_yyy",
            "PORT": "3000"
        }"#;
        let map = DotenvxImporter::parse(input.as_bytes()).unwrap();
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
    fn refuses_encrypted_vault_file() {
        let input = b"#/-------------------[DOTENV_VAULT]-------------------/\n\
                       #/         cloud-agnostic vaulting standard         /\n\
                       #/   [how it works](https://dotenv.org/vault)       /\n\
                       #/--------------------------------------------------/\n\
                       DOTENV_VAULT_DEVELOPMENT=\"encrypted_value_here\"";
        let result = DotenvxImporter::parse(input);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("dotenvx decrypt"));
    }

    #[test]
    fn skips_empty_values_dotenv() {
        let input = b"EMPTY_KEY=\nREAL_KEY=has_value\n";
        let map = DotenvxImporter::parse(input).unwrap();
        assert!(!map.contains_key("EMPTY_KEY"));
        assert!(map.contains_key("REAL_KEY"));
    }

    #[test]
    fn parse_dotenv_with_comments_and_export() {
        let input = b"# dotenvx managed\nexport API_KEY=sk-test-123\n# end\nPORT=8080\n";
        let map = DotenvxImporter::parse(input).unwrap();
        assert_eq!(map.get("API_KEY").map(|v| v.as_str()), Some("sk-test-123"));
        assert_eq!(map.get("PORT").map(|v| v.as_str()), Some("8080"));
    }
}
