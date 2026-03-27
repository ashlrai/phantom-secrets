use crate::error::{PhantomError, Result};
use crate::token::{PhantomToken, TokenMap};
use std::collections::BTreeMap;
use std::path::Path;

/// A parsed key-value entry from a .env file.
#[derive(Debug, Clone)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
    /// Whether this value is already a phantom token.
    pub is_phantom: bool,
}

/// Represents a parsed .env file, preserving comments and blank lines for faithful rewriting.
#[derive(Debug)]
pub struct DotenvFile {
    /// All lines in order. Non-KV lines (comments, blanks) stored as-is.
    lines: Vec<DotenvLine>,
}

#[derive(Debug, Clone)]
enum DotenvLine {
    /// A key=value pair.
    Entry(EnvEntry),
    /// A comment or blank line, stored verbatim.
    Other(String),
}

impl DotenvFile {
    /// Parse a .env file from a path.
    pub fn parse_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                PhantomError::DotenvNotFound(path.display().to_string())
            } else {
                PhantomError::Io(e)
            }
        })?;
        Ok(Self::parse_str(&content))
    }

    /// Parse a .env file from a string.
    pub fn parse_str(content: &str) -> Self {
        let lines = content
            .lines()
            .map(|line| {
                let trimmed = line.trim();

                // Skip comments and blank lines
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return DotenvLine::Other(line.to_string());
                }

                // Try to parse as KEY=VALUE
                if let Some((key, value)) = parse_kv_line(trimmed) {
                    DotenvLine::Entry(EnvEntry {
                        is_phantom: PhantomToken::is_phantom_token(&value),
                        key,
                        value,
                    })
                } else {
                    DotenvLine::Other(line.to_string())
                }
            })
            .collect();

        Self { lines }
    }

    /// Get all key-value entries (excluding comments/blanks).
    pub fn entries(&self) -> Vec<&EnvEntry> {
        self.lines
            .iter()
            .filter_map(|line| match line {
                DotenvLine::Entry(entry) => Some(entry),
                _ => None,
            })
            .collect()
    }

    /// Get entries that contain real secrets (not already phantom tokens).
    /// Uses heuristics to distinguish secrets from non-secret config values.
    pub fn real_secret_entries(&self) -> Vec<&EnvEntry> {
        self.entries()
            .into_iter()
            .filter(|e| !e.is_phantom && looks_like_secret(e))
            .collect()
    }

    /// Rewrite the .env file, replacing real secret values with phantom tokens.
    /// Returns the rewritten content and a map of secret names to their original values.
    pub fn rewrite_with_phantoms(
        &self,
        token_map: &TokenMap,
    ) -> (String, BTreeMap<String, String>) {
        let mut original_values = BTreeMap::new();
        let mut output_lines = Vec::new();

        for line in &self.lines {
            match line {
                DotenvLine::Entry(entry) => {
                    if entry.is_phantom {
                        // Already a phantom token, keep as-is
                        output_lines.push(format!("{}={}", entry.key, entry.value));
                    } else if let Some(token) = token_map.get_token(&entry.key) {
                        // Replace real value with phantom token
                        original_values.insert(entry.key.clone(), entry.value.clone());
                        output_lines.push(format!("{}={}", entry.key, token));
                    } else {
                        // No mapping for this key, keep as-is (non-secret env vars)
                        output_lines.push(format!("{}={}", entry.key, entry.value));
                    }
                }
                DotenvLine::Other(text) => {
                    output_lines.push(text.clone());
                }
            }
        }

        (output_lines.join("\n"), original_values)
    }

    /// Write the rewritten content to a file.
    pub fn write_phantomized(
        &self,
        token_map: &TokenMap,
        path: &Path,
    ) -> Result<BTreeMap<String, String>> {
        let (content, originals) = self.rewrite_with_phantoms(token_map);
        std::fs::write(path, content)?;
        Ok(originals)
    }
}

/// Parse a single KEY=VALUE line, handling quotes.
fn parse_kv_line(line: &str) -> Option<(String, String)> {
    // Handle export prefix
    let line = line.strip_prefix("export ").unwrap_or(line);

    let eq_pos = line.find('=')?;
    let key = line[..eq_pos].trim().to_string();
    let raw_value = line[eq_pos + 1..].trim();

    if key.is_empty() {
        return None;
    }

    // Strip surrounding quotes (single or double)
    let value = if (raw_value.starts_with('"') && raw_value.ends_with('"'))
        || (raw_value.starts_with('\'') && raw_value.ends_with('\''))
    {
        raw_value[1..raw_value.len() - 1].to_string()
    } else {
        raw_value.to_string()
    };

    Some((key, value))
}

/// Heuristic to determine if an env entry is likely a secret.
/// Checks both the key name and value patterns.
fn looks_like_secret(entry: &EnvEntry) -> bool {
    let key = entry.key.to_uppercase();
    let value = &entry.value;

    // Key-name patterns that indicate secrets
    let secret_key_patterns = [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
        "PRIVATE",
        "API_KEY",
        "ACCESS_KEY",
        "SIGNING",
    ];

    // Key-name patterns that indicate connection strings (which contain credentials)
    let connection_patterns = [
        "DATABASE_URL",
        "REDIS_URL",
        "MONGO_URL",
        "POSTGRES_URL",
        "MYSQL_URL",
        "AMQP_URL",
        "RABBITMQ_URL",
        "ELASTICSEARCH_URL",
        "CONNECTION_STRING",
        "DSN",
    ];

    // Value patterns that indicate secrets
    let secret_value_prefixes = [
        "sk-",
        "sk_",
        "pk_",
        "rk_",
        "whsec_",
        "Bearer ",
        "ghp_",
        "gho_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "shpat_",
        "eyJ",
    ];

    // Check key name
    if secret_key_patterns.iter().any(|p| key.contains(p)) {
        return true;
    }

    // Check connection string keys
    if connection_patterns.iter().any(|p| key.contains(p)) {
        return true;
    }

    // Check value patterns
    if secret_value_prefixes.iter().any(|p| value.starts_with(p)) {
        return true;
    }

    // Connection string URLs with credentials
    if value.contains("://") && value.contains('@') {
        return true;
    }

    // High-entropy long strings are likely secrets (32+ chars of hex/base64)
    if value.len() >= 32
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '/' || c == '='
        })
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_env() {
        let content = r#"
# Database config
DATABASE_URL=postgres://localhost/mydb
OPENAI_API_KEY=sk-abc123
STRIPE_SECRET_KEY=sk_test_xyz

# App settings
NODE_ENV=production
PORT=3000
"#;
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].key, "DATABASE_URL");
        assert_eq!(entries[0].value, "postgres://localhost/mydb");
        assert_eq!(entries[1].key, "OPENAI_API_KEY");
        assert_eq!(entries[1].value, "sk-abc123");
    }

    #[test]
    fn test_parse_quoted_values() {
        let content = r#"
KEY1="value with spaces"
KEY2='single quoted'
KEY3=unquoted
"#;
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert_eq!(entries[0].value, "value with spaces");
        assert_eq!(entries[1].value, "single quoted");
        assert_eq!(entries[2].value, "unquoted");
    }

    #[test]
    fn test_parse_export_prefix() {
        let content = "export MY_KEY=my_value\n";
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert_eq!(entries[0].key, "MY_KEY");
        assert_eq!(entries[0].value, "my_value");
    }

    #[test]
    fn test_detect_phantom_tokens() {
        let content = "REAL_KEY=sk-abc123\nPHANTOM_KEY=phm_abcdef1234\n";
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert!(!entries[0].is_phantom);
        assert!(entries[1].is_phantom);
    }

    #[test]
    fn test_real_secret_entries() {
        let content = "API_KEY=sk-abc\nFAKE=phm_xyz\nDATABASE_URL=postgres://user:pass@localhost/db\nNODE_ENV=production\nPORT=3000\n";
        let dotenv = DotenvFile::parse_str(content);
        let real = dotenv.real_secret_entries();
        assert_eq!(real.len(), 2);
        assert_eq!(real[0].key, "API_KEY");
        assert_eq!(real[1].key, "DATABASE_URL");
    }

    #[test]
    fn test_looks_like_secret_heuristics() {
        // Key name patterns
        assert!(looks_like_secret(&EnvEntry {
            key: "OPENAI_API_KEY".into(),
            value: "sk-abc".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "STRIPE_SECRET_KEY".into(),
            value: "sk_test_x".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "AUTH_TOKEN".into(),
            value: "abc".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "DB_PASSWORD".into(),
            value: "mypass".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "DATABASE_URL".into(),
            value: "postgres://u:p@host/db".into(),
            is_phantom: false
        }));

        // Value patterns
        assert!(looks_like_secret(&EnvEntry {
            key: "WHATEVER".into(),
            value: "sk-proj-abc123".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "WHATEVER".into(),
            value: "ghp_xxxxxxxxxxxx".into(),
            is_phantom: false
        }));

        // Non-secrets
        assert!(!looks_like_secret(&EnvEntry {
            key: "NODE_ENV".into(),
            value: "production".into(),
            is_phantom: false
        }));
        assert!(!looks_like_secret(&EnvEntry {
            key: "PORT".into(),
            value: "3000".into(),
            is_phantom: false
        }));
        assert!(!looks_like_secret(&EnvEntry {
            key: "DEBUG".into(),
            value: "true".into(),
            is_phantom: false
        }));
        assert!(!looks_like_secret(&EnvEntry {
            key: "APP_NAME".into(),
            value: "my-app".into(),
            is_phantom: false
        }));
    }

    #[test]
    fn test_rewrite_with_phantoms() {
        let content = "# Config\nAPI_KEY=sk-real-secret\nPORT=3000\n";
        let dotenv = DotenvFile::parse_str(content);

        let mut token_map = TokenMap::new();
        token_map.insert("API_KEY".to_string());

        let (rewritten, originals) = dotenv.rewrite_with_phantoms(&token_map);

        // API_KEY should now have a phantom token
        assert!(rewritten.contains("API_KEY=phm_"));
        // PORT should be unchanged
        assert!(rewritten.contains("PORT=3000"));
        // Comment preserved
        assert!(rewritten.contains("# Config"));
        // Original value captured
        assert_eq!(originals.get("API_KEY").unwrap(), "sk-real-secret");
    }

    #[test]
    fn test_preserves_comments_and_blanks() {
        let content = "# This is a comment\n\nKEY=value\n\n# Another comment\n";
        let dotenv = DotenvFile::parse_str(content);
        let token_map = TokenMap::new();
        let (rewritten, _) = dotenv.rewrite_with_phantoms(&token_map);
        assert!(rewritten.contains("# This is a comment"));
        assert!(rewritten.contains("# Another comment"));
    }
}
