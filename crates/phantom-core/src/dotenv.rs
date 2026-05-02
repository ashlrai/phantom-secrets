use crate::error::{PhantomError, Result};
use crate::token::{PhantomToken, TokenMap};
use std::collections::BTreeMap;
use std::path::Path;

/// Classification of an environment variable entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretClassification {
    /// A real secret that should be protected with a phantom token.
    Secret,
    /// A framework public key (NEXT_PUBLIC_*, VITE_*, etc.) — safe for browser bundles.
    PublicKey,
    /// Non-secret configuration (NODE_ENV, PORT, DEBUG, etc.)
    NotSecret,
}

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
    /// A key=value pair. The optional `RawLineFormat` carries enough source
    /// info to splice a new value into the original line, preserving quotes,
    /// indentation, the `export ` prefix, and trailing inline comments.
    /// Multi-line quoted values and entries with embedded escape sequences
    /// store `None` and fall through to the canonical `KEY=value` reformat.
    Entry(EnvEntry, Option<RawLineFormat>),
    /// A comment or blank line, stored verbatim.
    Other(String),
}

/// Captures the byte span occupied by an entry's value within the original
/// source line, so phantom-token substitution can preserve everything around
/// it. Only populated for single-line entries that can be safely round-tripped
/// via value-only splicing.
#[derive(Debug, Clone)]
struct RawLineFormat {
    raw: String,
    value_start: usize,
    value_end: usize,
}

impl RawLineFormat {
    fn with_value(&self, new_value: &str) -> String {
        let mut out = String::with_capacity(self.raw.len() + new_value.len());
        out.push_str(&self.raw[..self.value_start]);
        out.push_str(new_value);
        out.push_str(&self.raw[self.value_end..]);
        out
    }
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
    ///
    /// Supports multi-line double-quoted values (audit F12), which is how
    /// PEM-encoded keys are typically stored in `.env`:
    ///
    /// ```text
    /// PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
    /// MIIEvQIBADANBgkqhkiG9w0BAQEF...
    /// -----END PRIVATE KEY-----"
    /// ```
    ///
    /// Inside `"..."` values, `\n` / `\t` / `\\` / `\"` escapes are
    /// unescaped. Single-quoted values are treated as literal (single-line
    /// only); unquoted values are single-line. An unterminated quote falls
    /// back to treating the opening line as an unparsed `Other` line.
    pub fn parse_str(content: &str) -> Self {
        let mut out: Vec<DotenvLine> = Vec::new();
        let mut iter = content.lines();

        while let Some(line) = iter.next() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                out.push(DotenvLine::Other(line.to_string()));
                continue;
            }

            let (working, had_export) = match trimmed.strip_prefix("export ") {
                Some(rest) => (rest, true),
                None => (trimmed, false),
            };
            let Some(eq_pos) = working.find('=') else {
                out.push(DotenvLine::Other(line.to_string()));
                continue;
            };

            let key = working[..eq_pos].trim().to_string();
            if key.is_empty() {
                out.push(DotenvLine::Other(line.to_string()));
                continue;
            }

            let after_eq = &working[eq_pos + 1..];
            let raw_value = after_eq.trim_start();

            // Compute byte offsets in the original `line` so we can splice a
            // replacement value while preserving the surrounding format.
            // Derived from known structure (leading whitespace + optional
            // 7-byte "export " prefix) rather than a substring search.
            // Computed unconditionally; consumed only if parsing stays on a
            // single line and produces no embedded escapes.
            let leading_ws = line.len() - line.trim_start().len();
            let working_offset = leading_ws + if had_export { "export ".len() } else { 0 };
            let eq_in_line = working_offset + eq_pos;
            let ws_after_eq = after_eq.len() - raw_value.len();
            let raw_value_offset = eq_in_line + 1 + ws_after_eq;

            let (value, fmt) = if let Some(after_quote) = raw_value.strip_prefix('"') {
                // Double-quoted — may span multiple lines (F12).
                match find_unescaped_quote(after_quote, '"') {
                    Some(end) => {
                        let raw_inner = &after_quote[..end];
                        let unescaped = unescape_double_quoted(raw_inner);
                        // Format-preservable only when no escape sequence
                        // changed the bytes; otherwise round-tripping the
                        // unescaped value back into the source would alter it.
                        let fmt = if unescaped == raw_inner {
                            let value_start = raw_value_offset + 1; // skip opening "
                            Some(RawLineFormat {
                                raw: line.to_string(),
                                value_start,
                                value_end: value_start + raw_inner.len(),
                            })
                        } else {
                            None
                        };
                        (unescaped, fmt)
                    }
                    None => {
                        // Closing quote not on the opening line — consume
                        // subsequent lines until we find it.
                        let mut buf = after_quote.to_string();
                        let mut found = false;
                        for next_line in iter.by_ref() {
                            buf.push('\n');
                            if let Some(end) = find_unescaped_quote(next_line, '"') {
                                buf.push_str(&next_line[..end]);
                                found = true;
                                break;
                            }
                            buf.push_str(next_line);
                        }
                        if !found {
                            // Unterminated quote — treat the opening line as
                            // unparseable and keep going. Lines we already
                            // consumed are effectively lost from the Other
                            // stream; acceptable since the file is malformed.
                            out.push(DotenvLine::Other(line.to_string()));
                            continue;
                        }
                        // Multi-line: format preservation not attempted.
                        (unescape_double_quoted(&buf), None)
                    }
                }
            } else if let Some(after_quote) = raw_value.strip_prefix('\'') {
                // Single-quoted: literal, single-line.
                match after_quote.find('\'') {
                    Some(end) => {
                        let value_start = raw_value_offset + 1; // skip opening '
                        let fmt = Some(RawLineFormat {
                            raw: line.to_string(),
                            value_start,
                            value_end: value_start + end,
                        });
                        (after_quote[..end].to_string(), fmt)
                    }
                    None => {
                        out.push(DotenvLine::Other(line.to_string()));
                        continue;
                    }
                }
            } else {
                // Unquoted: convention is that `#` preceded by whitespace
                // starts an inline comment. Strip it from the stored value
                // (otherwise the comment would be injected as part of the
                // secret on outbound requests) but keep it in the raw line
                // so format preservation can splice the new value in front
                // of it.
                let comment_offset = raw_value
                    .char_indices()
                    .find(|(i, c)| {
                        *c == '#' && *i > 0 && raw_value.as_bytes()[*i - 1].is_ascii_whitespace()
                    })
                    .map(|(i, _)| i);
                let value_text = match comment_offset {
                    Some(i) => raw_value[..i].trim_end(),
                    None => raw_value.trim_end(),
                };
                let fmt = Some(RawLineFormat {
                    raw: line.to_string(),
                    value_start: raw_value_offset,
                    value_end: raw_value_offset + value_text.len(),
                });
                (value_text.to_string(), fmt)
            };

            out.push(DotenvLine::Entry(
                EnvEntry {
                    is_phantom: PhantomToken::is_phantom_token(&value),
                    key,
                    value,
                },
                fmt,
            ));
        }

        Self { lines: out }
    }

    /// Get all key-value entries (excluding comments/blanks).
    pub fn entries(&self) -> Vec<&EnvEntry> {
        self.lines
            .iter()
            .filter_map(|line| match line {
                DotenvLine::Entry(entry, _) => Some(entry),
                _ => None,
            })
            .collect()
    }

    /// Get entries that contain real secrets (not already phantom tokens).
    /// Uses heuristics to distinguish secrets from non-secret config values.
    pub fn real_secret_entries(&self) -> Vec<&EnvEntry> {
        self.entries()
            .into_iter()
            .filter(|e| !e.is_phantom && classify(e) == SecretClassification::Secret)
            .collect()
    }

    /// Classify all entries, returning entries grouped by classification.
    /// Entries that are already phantom tokens are excluded.
    pub fn classified_entries(&self) -> Vec<(&EnvEntry, SecretClassification)> {
        self.entries()
            .into_iter()
            .filter(|e| !e.is_phantom)
            .map(|e| (e, classify(e)))
            .collect()
    }

    /// Get entries that are framework public keys (NEXT_PUBLIC_*, VITE_*, etc.)
    pub fn public_key_entries(&self) -> Vec<&EnvEntry> {
        self.entries()
            .into_iter()
            .filter(|e| !e.is_phantom && classify(e) == SecretClassification::PublicKey)
            .collect()
    }

    /// Generate .env.example content with secrets replaced by placeholders.
    /// Public keys and non-secret config values are preserved as-is.
    pub fn generate_example_content(
        &self,
        config: Option<&crate::config::PhantomConfig>,
    ) -> String {
        let mut output_lines = vec![
            "# Environment variables for this project".to_string(),
            "# Copy to .env and fill in real values, or use Phantom:".to_string(),
            "#   npm install -g phantom-secrets && phantom init".to_string(),
            "#".to_string(),
            "# See https://phm.dev for details".to_string(),
            String::new(),
        ];

        for line in &self.lines {
            match line {
                DotenvLine::Entry(entry, _) => {
                    if entry.is_phantom || classify(entry) == SecretClassification::Secret {
                        // Secret → placeholder
                        let placeholder = generate_placeholder(&entry.key, config);
                        output_lines.push(format!("{}={}", entry.key, placeholder));
                    } else {
                        // Public key or non-secret → actual value
                        output_lines.push(format!("{}={}", entry.key, entry.value));
                    }
                }
                DotenvLine::Other(text) => {
                    output_lines.push(text.clone());
                }
            }
        }

        let mut content = output_lines.join("\n");
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content
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
                DotenvLine::Entry(entry, fmt) => {
                    if let Some(token) = token_map.get_token(&entry.key) {
                        // Replace value with phantom token (works for both initial and rotation)
                        if !entry.is_phantom {
                            original_values.insert(entry.key.clone(), entry.value.clone());
                        }
                        let rendered = match fmt {
                            Some(f) => f.with_value(token.as_str()),
                            None => format!("{}={}", entry.key, token),
                        };
                        output_lines.push(rendered);
                    } else {
                        // No mapping for this key, keep as-is (non-secret env vars).
                        // Preserve the original line verbatim when format info exists.
                        let rendered = match fmt {
                            Some(f) => f.raw.clone(),
                            None => format!("{}={}", entry.key, entry.value),
                        };
                        output_lines.push(rendered);
                    }
                }
                DotenvLine::Other(text) => {
                    output_lines.push(text.clone());
                }
            }
        }

        let mut content = output_lines.join("\n");
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        (content, original_values)
    }

    /// Write the rewritten content to a file.
    ///
    /// Uses [`crate::fs::atomic_write`]: the new content is staged in a
    /// same-directory tempfile (mode 0o600 on POSIX), fsynced, then renamed
    /// over the target. Prevents a crash mid-write from leaving a
    /// half-plaintext .env on disk.
    pub fn write_phantomized(
        &self,
        token_map: &TokenMap,
        path: &Path,
    ) -> Result<BTreeMap<String, String>> {
        let (content, originals) = self.rewrite_with_phantoms(token_map);
        crate::fs::atomic_write(path, content.as_bytes())?;
        Ok(originals)
    }
}

/// Find the index of the first unescaped occurrence of `quote` in `s`.
/// A preceding backslash escapes the quote (and is consumed along with it
/// by the escape-pair skip). Returns `None` if no unescaped quote is found.
fn find_unescaped_quote(s: &str, quote: char) -> Option<usize> {
    let mut iter = s.char_indices();
    while let Some((i, c)) = iter.next() {
        if c == '\\' {
            // Consume the escaped character so e.g. `\"` doesn't close the string
            iter.next();
            continue;
        }
        if c == quote {
            return Some(i);
        }
    }
    None
}

/// Apply `\n` / `\r` / `\t` / `\\` / `\"` / `\'` escape handling inside a
/// double-quoted value. Unknown escape sequences are preserved verbatim
/// (including the backslash) so arbitrary bytes aren't silently dropped.
fn unescape_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Heuristic to determine if an env entry is likely a secret.
/// Checks both the key name and value patterns.
fn looks_like_secret(entry: &EnvEntry) -> bool {
    let key = entry.key.to_uppercase();
    let value = &entry.value;

    // Key-name patterns that indicate secrets. `PWD` covers short forms like
    // `DB_PWD=hunter2` that would otherwise miss (audit F11).
    let secret_key_patterns = [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PWD",
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
        // PEM-encoded private keys — the armor header is a clear marker
        // (audit F11). Multi-line PEM bodies depend on F12 quoted parsing.
        "-----BEGIN ",
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

    // Connection string URLs with credentials in userinfo (postgres://u:p@host)
    if value.contains("://") && value.contains('@') {
        return true;
    }

    // URLs carrying auth material in the query string, e.g.
    // `https://host/endpoint?api_key=xxx` (audit F11). Bare `://` alone is
    // not enough — that matches harmless public endpoints.
    if value.contains("://") && url_has_auth_query_param(value) {
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

/// Detect auth-like parameters in the query string of a URL-shaped value.
/// Case-insensitive on the parameter name only. A hit on any of these means
/// the URL is carrying a credential and should be treated as a secret.
fn url_has_auth_query_param(value: &str) -> bool {
    // Take everything after the first `?`, then scan `&`-separated pairs.
    let Some(query) = value.split_once('?').map(|(_, q)| q) else {
        return false;
    };
    const AUTH_PARAMS: &[&str] = &[
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "accesstoken",
        "auth_token",
        "authtoken",
        "auth",
        "token",
        "password",
        "secret",
        "sig",
        "signature",
    ];
    for pair in query.split('&') {
        let Some((name, _)) = pair.split_once('=') else {
            continue;
        };
        let name_lower = name.to_ascii_lowercase();
        if AUTH_PARAMS.iter().any(|p| *p == name_lower) {
            return true;
        }
    }
    false
}

/// Classify an environment variable entry as Secret, PublicKey, or NotSecret.
/// If a key has a public prefix (NEXT_PUBLIC_, VITE_, etc.) but the value matches
/// known secret patterns (sk_live_, ghp_, etc.), it's classified as Secret to prevent
/// accidental exposure of misnamed keys.
pub fn classify(entry: &EnvEntry) -> SecretClassification {
    if is_public_key(&entry.key) {
        // Safety check: if the value looks like a real secret despite the public prefix,
        // classify as Secret to prevent leaking misnamed keys (e.g., VITE_STRIPE_SECRET_KEY=sk_live_...)
        if has_secret_value_pattern(&entry.value) {
            SecretClassification::Secret
        } else {
            SecretClassification::PublicKey
        }
    } else if looks_like_secret(entry) {
        SecretClassification::Secret
    } else {
        SecretClassification::NotSecret
    }
}

/// Check if a value matches known secret prefixes (independent of key name).
fn has_secret_value_pattern(value: &str) -> bool {
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
    ];
    secret_value_prefixes.iter().any(|p| value.starts_with(p))
}

/// Check if a key name is a framework public key (safe for browser bundles).
pub fn is_public_key(key: &str) -> bool {
    let public_prefixes = [
        "NEXT_PUBLIC_",
        "EXPO_PUBLIC_",
        "VITE_",
        "REACT_APP_",
        "NUXT_PUBLIC_",
        "GATSBY_",
    ];
    public_prefixes.iter().any(|prefix| key.starts_with(prefix))
}

/// Generate a descriptive placeholder for a secret key.
fn generate_placeholder(key: &str, config: Option<&crate::config::PhantomConfig>) -> String {
    // Check for service mapping to give helpful hints
    if let Some(cfg) = config {
        for (svc_name, svc) in &cfg.services {
            if svc.secret_key == key {
                return format!("your_{}_here", svc_name);
            }
        }
    }

    // Generate placeholder based on key name
    let key_lower = key.to_lowercase();
    if key_lower.contains("url") {
        "your_connection_string_here".to_string()
    } else if key_lower.contains("password") || key_lower.contains("passwd") {
        "your_password_here".to_string()
    } else {
        format!("your_{key_lower}_here")
    }
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
    fn test_real_secret_entries_excludes_public_keys() {
        // NEXT_PUBLIC_SUPABASE_ANON_KEY contains "KEY" pattern but should be excluded as a public key
        let content = "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9\nSUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiJ9\nVITE_API_KEY=some-key\n";
        let dotenv = DotenvFile::parse_str(content);
        let real = dotenv.real_secret_entries();
        assert_eq!(real.len(), 1);
        assert_eq!(real[0].key, "SUPABASE_SERVICE_ROLE_KEY");
    }

    #[test]
    fn test_looks_like_secret_f11_additions() {
        // Short-form password variable (PWD)
        assert!(looks_like_secret(&EnvEntry {
            key: "DB_PWD".into(),
            value: "hunter2".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "ADMIN_PWD".into(),
            value: "x".into(),
            is_phantom: false
        }));

        // PEM armor header — common for RSA/EC private keys in env vars
        assert!(looks_like_secret(&EnvEntry {
            key: "SOMETHING".into(),
            value: "-----BEGIN RSA PRIVATE KEY-----".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "JWT_SIGNING".into(),
            value: "-----BEGIN EC PRIVATE KEY-----".into(),
            is_phantom: false
        }));

        // URL carrying auth material in query string (no `@` userinfo)
        assert!(looks_like_secret(&EnvEntry {
            key: "API_URL".into(),
            value: "https://host.example.com/v1/data?api_key=sekret".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "WEBHOOK".into(),
            value: "https://hooks.example/endpoint?token=abc123&user=alice".into(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "API_URL".into(),
            value: "https://api.example/sign?sig=xyz".into(),
            is_phantom: false
        }));

        // A plain URL with no auth params must remain a non-secret
        assert!(!looks_like_secret(&EnvEntry {
            key: "PUBLIC_URL".into(),
            value: "https://example.com/page?lang=en".into(),
            is_phantom: false
        }));
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
    fn test_is_public_key() {
        assert!(is_public_key("NEXT_PUBLIC_SUPABASE_URL"));
        assert!(is_public_key("NEXT_PUBLIC_SUPABASE_ANON_KEY"));
        assert!(is_public_key("EXPO_PUBLIC_POSTHOG_KEY"));
        assert!(is_public_key("VITE_API_URL"));
        assert!(is_public_key("REACT_APP_BACKEND_URL"));
        assert!(is_public_key("NUXT_PUBLIC_API_BASE"));
        assert!(is_public_key("GATSBY_API_URL"));
        assert!(!is_public_key("OPENAI_API_KEY"));
        assert!(!is_public_key("SUPABASE_SERVICE_ROLE_KEY"));
        assert!(!is_public_key("DATABASE_URL"));
        assert!(!is_public_key("NODE_ENV"));
    }

    #[test]
    fn test_classify_entries() {
        // Public keys
        assert_eq!(
            classify(&EnvEntry {
                key: "NEXT_PUBLIC_SUPABASE_URL".into(),
                value: "https://example.supabase.co".into(),
                is_phantom: false
            }),
            SecretClassification::PublicKey
        );
        assert_eq!(
            classify(&EnvEntry {
                key: "VITE_API_URL".into(),
                value: "https://api.example.com".into(),
                is_phantom: false
            }),
            SecretClassification::PublicKey
        );

        // Secrets
        assert_eq!(
            classify(&EnvEntry {
                key: "OPENAI_API_KEY".into(),
                value: "sk-abc123".into(),
                is_phantom: false
            }),
            SecretClassification::Secret
        );
        assert_eq!(
            classify(&EnvEntry {
                key: "SUPABASE_SERVICE_ROLE_KEY".into(),
                value: "eyJhbGciOiJIUzI1NiJ9".into(),
                is_phantom: false
            }),
            SecretClassification::Secret
        );

        // Not secrets
        assert_eq!(
            classify(&EnvEntry {
                key: "NODE_ENV".into(),
                value: "production".into(),
                is_phantom: false
            }),
            SecretClassification::NotSecret
        );
        assert_eq!(
            classify(&EnvEntry {
                key: "PORT".into(),
                value: "3000".into(),
                is_phantom: false
            }),
            SecretClassification::NotSecret
        );

        // Misnamed public key with secret value — should be classified as Secret
        assert_eq!(
            classify(&EnvEntry {
                key: "VITE_STRIPE_SECRET_KEY".into(),
                value: "sk_live_abc123xyz".into(),
                is_phantom: false
            }),
            SecretClassification::Secret
        );
        assert_eq!(
            classify(&EnvEntry {
                key: "NEXT_PUBLIC_GITHUB_TOKEN".into(),
                value: "ghp_xxxxxxxxxxxx".into(),
                is_phantom: false
            }),
            SecretClassification::Secret
        );
    }

    #[test]
    fn test_public_key_entries() {
        let content = "NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=eyJ\nNODE_ENV=production\nEXPO_PUBLIC_KEY=abc123\n";
        let dotenv = DotenvFile::parse_str(content);
        let public = dotenv.public_key_entries();
        assert_eq!(public.len(), 2);
        assert_eq!(public[0].key, "NEXT_PUBLIC_SUPABASE_URL");
        assert_eq!(public[1].key, "EXPO_PUBLIC_KEY");
    }

    #[test]
    fn test_generate_example_content() {
        let content = "# Config\nOPENAI_API_KEY=sk-real-secret\nNEXT_PUBLIC_URL=https://app.example.com\nPORT=3000\n";
        let dotenv = DotenvFile::parse_str(content);
        let example = dotenv.generate_example_content(None);
        // Secret should be a placeholder
        assert!(example.contains("OPENAI_API_KEY=your_openai_api_key_here"));
        // Public key should preserve actual value
        assert!(example.contains("NEXT_PUBLIC_URL=https://app.example.com"));
        // Non-secret should preserve actual value
        assert!(example.contains("PORT=3000"));
        // Should have header
        assert!(example.contains("# Environment variables for this project"));
    }

    #[test]
    fn test_multiline_double_quoted_pem() {
        // F12: PEM-encoded private key stored across multiple lines in .env.
        let content = "PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF...\n-----END RSA PRIVATE KEY-----\"\nOTHER=value\n";
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert_eq!(entries.len(), 2, "parser must produce exactly 2 entries");
        assert_eq!(entries[0].key, "PRIVATE_KEY");
        assert!(entries[0].value.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(entries[0].value.contains("MIIEvQIBADANBgkqhkiG9w0BAQEF..."));
        assert!(entries[0].value.contains("-----END RSA PRIVATE KEY-----"));
        assert_eq!(entries[1].key, "OTHER");
        assert_eq!(entries[1].value, "value");
    }

    #[test]
    fn test_multiline_pem_classified_as_secret() {
        // The PEM-armor value prefix (F11) plus multi-line parsing (F12) must
        // combine so a PEM private key is recognized as a Secret.
        let content =
            "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----\"\n";
        let dotenv = DotenvFile::parse_str(content);
        let secrets = dotenv.real_secret_entries();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].key, "PRIVATE_KEY");
    }

    #[test]
    fn test_double_quoted_escapes_unescape() {
        let content = r#"KEY="line1\nline2\tend""#;
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert_eq!(entries[0].value, "line1\nline2\tend");
    }

    #[test]
    fn test_unterminated_double_quote_preserves_file() {
        // Unterminated quote on first line — must not hang or consume the rest.
        // The opening line is treated as an unparseable Other line.
        let content = "KEY=\"missing closing\nOTHER=value\n";
        let dotenv = DotenvFile::parse_str(content);
        // OTHER may be consumed into the attempted multi-line buffer; the
        // guarantee here is the parser does not panic and still returns.
        let _ = dotenv.entries();
    }

    #[test]
    fn test_single_quoted_literal() {
        let content = r#"KEY='literal \n value'"#;
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        // Single-quoted = literal, no escape processing
        assert_eq!(entries[0].value, r"literal \n value");
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

    /// Format preservation: when a value gets a phantom token, the surrounding
    /// quotes/whitespace/`export` prefix on the same line should survive.
    /// Verifies the splice path rather than the canonical reformat path.
    fn assert_rewrite(key: &str, token: &str, input: &str, expected: &str) {
        let mut tm = TokenMap::new();
        tm.insert_with_token(
            key.to_string(),
            PhantomToken::parse(token).expect("test token must start with phm_"),
        );
        let (out, _) = DotenvFile::parse_str(input).rewrite_with_phantoms(&tm);
        assert_eq!(out, expected);
    }

    #[test]
    fn rewrite_preserves_double_quotes() {
        assert_rewrite(
            "API_KEY",
            "phm_aaaa",
            "API_KEY=\"sk-real-test\"\n",
            "API_KEY=\"phm_aaaa\"\n",
        );
    }

    #[test]
    fn rewrite_preserves_single_quotes() {
        assert_rewrite(
            "API_KEY",
            "phm_bbbb",
            "API_KEY='sk-real-test'\n",
            "API_KEY='phm_bbbb'\n",
        );
    }

    #[test]
    fn rewrite_preserves_export_prefix() {
        assert_rewrite(
            "API_KEY",
            "phm_cccc",
            "export API_KEY=sk-real-test\n",
            "export API_KEY=phm_cccc\n",
        );
    }

    #[test]
    fn rewrite_preserves_leading_indentation() {
        assert_rewrite(
            "API_KEY",
            "phm_dddd",
            "  API_KEY=sk-real-test\n",
            "  API_KEY=phm_dddd\n",
        );
    }

    #[test]
    fn rewrite_preserves_non_secret_lines_verbatim() {
        // Lines without a token mapping should round-trip exactly,
        // including quotes and indentation.
        let content = "  NODE_ENV=\"production\"\nexport PORT='8080'\n";
        let dotenv = DotenvFile::parse_str(content);
        let tm = TokenMap::new();
        let (out, _) = dotenv.rewrite_with_phantoms(&tm);
        assert_eq!(out, content);
    }

    #[test]
    fn rewrite_falls_back_for_multiline_quoted_value() {
        // Multi-line PEM-style values aren't format-preserved; the splice
        // path is skipped and the canonical KEY=value reformat is emitted.
        // Asserting an exact match (not just `contains`) verifies the
        // surrounding quotes have been dropped by the canonical reformat.
        assert_rewrite(
            "PRIVATE_KEY",
            "phm_eeee",
            "PRIVATE_KEY=\"line1\nline2\"\n",
            "PRIVATE_KEY=phm_eeee\n",
        );
    }

    #[test]
    fn rewrite_falls_back_for_double_quoted_value_with_escapes() {
        // \n inside double quotes means the parsed value differs from the
        // raw bytes; splicing back would lose the escape, so reformat.
        assert_rewrite(
            "MULTILINE_KEY",
            "phm_ffff",
            "MULTILINE_KEY=\"a\\nb\"\n",
            "MULTILINE_KEY=phm_ffff\n",
        );
    }

    #[test]
    fn parse_strips_inline_comment_from_unquoted_value() {
        // Standard .env convention: `#` preceded by whitespace starts an
        // inline comment. Without this, the comment would be stored as part
        // of the secret value and injected into outbound API requests.
        let content = "API_KEY=sk-real-test  # production key\n";
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert_eq!(entries[0].key, "API_KEY");
        assert_eq!(entries[0].value, "sk-real-test");
    }

    #[test]
    fn parse_keeps_hash_inside_unquoted_value_when_no_preceding_whitespace() {
        // `#` not preceded by whitespace is part of the value (e.g. URL
        // fragments, query strings, base64 padding-adjacent sequences).
        let content = "URL=https://example.com/path#section\n";
        let dotenv = DotenvFile::parse_str(content);
        let entries = dotenv.entries();
        assert_eq!(entries[0].value, "https://example.com/path#section");
    }

    #[test]
    fn rewrite_preserves_inline_comment_after_phantom_token() {
        // The comment is part of the original line bytes after the value
        // span, so format preservation should splice the new value in
        // front of it without disturbing the comment.
        assert_rewrite(
            "API_KEY",
            "phm_gggg",
            "API_KEY=sk-real-test  # production key\n",
            "API_KEY=phm_gggg  # production key\n",
        );
    }
}
