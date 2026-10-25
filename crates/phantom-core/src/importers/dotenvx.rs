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
//! **Note on encrypted `.env` files:** dotenvx 1.x can also encrypt values in
//! place (`KEY="encrypted:..."`). Any such value refuses the whole import,
//! because importing it would store ciphertext as the secret. Decrypt with
//! `dotenvx decrypt --stdout` first.
//!
//! Format is auto-detected: if the trimmed input starts with `{`, it's JSON;
//! otherwise it's treated as dotenv.

use anyhow::Result;
use zeroize::Zeroizing;

use super::{
    env_importer, json_scalar, parse_json_object_entries, refuse_duplicate_names, Importer,
    SecretMap,
};

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

        let map = if first_non_ws == Some(b'{') {
            parse_flat_json(input)?
        } else {
            env_importer(input)?
        };
        refuse_encrypted_values(&map)?;
        Ok(map)
    }
}

/// Prefix dotenvx 1.x writes in front of every value it encrypts in place.
const DOTENVX_ENCRYPTED_PREFIX: &str = "encrypted:";

/// dotenvx 1.x encrypts values inside an ordinary `.env` file
/// (`KEY="encrypted:..."`, plus a `DOTENV_PUBLIC_KEY` header). Phantom has no
/// private key, so such a value is ciphertext. Storing it would report success
/// while replacing a working credential with noise that `phantom exec` and the
/// proxy then inject. Refuse the whole import instead; the error names the
/// entry, never a value.
fn refuse_encrypted_values(map: &SecretMap) -> Result<()> {
    if let Some(name) = map
        .iter()
        .find(|(_, value)| value.trim_start().starts_with(DOTENVX_ENCRYPTED_PREFIX))
        .map(|(name, _)| name)
    {
        anyhow::bail!(
            "dotenvx entry '{name}' is still encrypted; nothing was imported.\n\
             Run `dotenvx decrypt --stdout > .env.decrypted` first, then:\n  \
             phantom import --from dotenvx --file .env.decrypted"
        );
    }
    Ok(())
}

fn parse_flat_json(input: &[u8]) -> Result<SecretMap> {
    let obj = parse_json_object_entries(input)
        .map_err(|e| anyhow::anyhow!("dotenvx JSON parse error: {}", e))?;
    refuse_duplicate_names("dotenvx", obj.iter().map(|(key, _)| key.as_str()))?;

    let mut map = SecretMap::new();
    for (key, val) in obj {
        let Some(value) = json_scalar("dotenvx", &key, &val)? else {
            continue;
        };
        if value.is_empty() {
            continue;
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

    #[test]
    fn refuses_dotenvx_encrypted_values_instead_of_importing_ciphertext() {
        // dotenvx 1.x encrypts values in place inside a normal `.env` file.
        // Without the private key those values are ciphertext, and storing
        // them would silently replace working credentials with noise.
        let ciphertext = ["encrypted:", "BFakeCipher", "PlaceholderOnly=="].concat();
        let public = ["03", "fakepublicplaceholder"].concat();
        let dotenv = format!(
            "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/\n\
             DOTENV_PUBLIC_KEY=\"{public}\"\n\
             PLAIN_NAME=plain_value\n\
             SEALED_NAME=\"{ciphertext}\"\n"
        );
        let json = format!(r#"{{"PLAIN_NAME": "plain_value", "SEALED_NAME": "{ciphertext}"}}"#);
        for input in [dotenv, json] {
            let error = DotenvxImporter::parse(input.as_bytes())
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(error.contains("'SEALED_NAME'"), "import was not refused");
            assert!(error.contains("dotenvx decrypt"));
            assert!(error.contains("nothing was imported"));
            assert!(!error.contains("BFakeCipher"));
            assert!(!error.contains("plain_value"));
        }
    }

    #[test]
    fn decrypted_dotenvx_file_still_imports() {
        let input = b"DOTENV_PUBLIC_KEY=\"03fakepublicplaceholder\"\nPLAIN_NAME=plain_value\nNOTE=mentions encrypted: mid-value\n";
        let map = DotenvxImporter::parse(input).unwrap();
        assert_eq!(
            map.get("PLAIN_NAME").map(|v| v.as_str()),
            Some("plain_value")
        );
        assert_eq!(
            map.get("NOTE").map(|v| v.as_str()),
            Some("mentions encrypted: mid-value")
        );
    }

    #[test]
    fn json_refuses_arrays_and_objects_instead_of_dropping_them() {
        for input in [
            r#"{"KEEP": "kept_value", "BAD": ["one", "two"]}"#,
            r#"{"KEEP": "kept_value", "BAD": {"nested": "v"}}"#,
        ] {
            let error = DotenvxImporter::parse(input.as_bytes())
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default();
            assert!(error.contains("'BAD'"));
            assert!(error.contains("nothing was imported"));
            assert!(!error.contains("kept_value"));
        }
        let map = DotenvxImporter::parse(br#"{"NULL_KEY": null, "REAL_KEY": "v"}"#).unwrap();
        assert_eq!(map.len(), 1);
    }
}
