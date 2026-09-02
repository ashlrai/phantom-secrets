use crate::error::{PhantomError, Result};
use crate::token::{PhantomToken, TokenMap};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const UTF8_BOM: &str = "\u{feff}";

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

/// A value-free description of syntax that makes mutation unsafe.
///
/// Issues deliberately contain only a location and a fixed category. They
/// never retain source snippets or values, so diagnostics are safe to expose
/// through value-blind agent surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotenvParseIssue {
    /// One-based physical line on which the issue begins.
    pub line: usize,
    /// One-based byte column on the reported physical line.
    pub column: usize,
    /// Fixed, value-free issue category.
    pub kind: DotenvParseIssueKind,
}

/// Fixed categories for dotenv syntax that cannot be mutated safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotenvParseIssueKind {
    /// A non-comment record has no assignment delimiter.
    MissingEquals,
    /// An assignment delimiter was found without a variable name.
    EmptyKey,
    /// A variable name contains characters outside the portable dotenv set.
    InvalidKey,
    /// A UTF-8 BOM appears anywhere other than source byte offset zero.
    UnexpectedByteOrderMark,
    /// A double-quoted value reaches end of input without a closing quote.
    UnterminatedDoubleQuote,
    /// A single-quoted value reaches end of input without a closing quote.
    UnterminatedSingleQuote,
    /// Non-comment content follows the closing quote on its physical line.
    UnexpectedCharactersAfterQuotedValue,
}

impl fmt::Display for DotenvParseIssueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::MissingEquals => "missing equals sign",
            Self::EmptyKey => "empty variable name",
            Self::InvalidKey => "invalid variable name",
            Self::UnexpectedByteOrderMark => "unexpected UTF-8 byte order mark",
            Self::UnterminatedDoubleQuote => "unterminated double-quoted value",
            Self::UnterminatedSingleQuote => "unterminated single-quoted value",
            Self::UnexpectedCharactersAfterQuotedValue => {
                "unexpected characters after quoted value"
            }
        };
        f.write_str(label)
    }
}

/// A parsed dotenv document with its exact original byte representation.
pub struct DotenvFile {
    /// The complete source is retained so all bytes outside an explicitly
    /// mutated span, including CRLF endings and malformed records, survive.
    source: String,
    /// Successfully parsed assignments in source order.
    records: Vec<ParsedRecord>,
    /// Value-free syntax issues that prevent safe mutation.
    issues: Vec<DotenvParseIssue>,
}

impl fmt::Debug for DotenvFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DotenvFile")
            .field("record_count", &self.records.len())
            .field("issues", &self.issues)
            .finish_non_exhaustive()
    }
}

/// One parsed assignment and its exact source spans.
#[derive(Debug, Clone)]
struct ParsedRecord {
    /// Decoded key/value data used by read-only consumers.
    entry: EnvEntry,
    /// Full assignment span, including its physical line ending when present.
    record_span: Range<usize>,
    /// Raw inner-value span replaced during mutation.
    value_span: Range<usize>,
}

impl Drop for DotenvFile {
    fn drop(&mut self) {
        self.source.zeroize();
        for record in &mut self.records {
            record.entry.value.zeroize();
        }
    }
}

impl DotenvFile {
    /// Parse a .env file from a path.
    pub fn parse_file(path: &Path) -> Result<Self> {
        let mut content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                PhantomError::DotenvNotFound(path.display().to_string())
            } else {
                PhantomError::Io(e)
            }
        })?;
        let parsed = Self::parse_str(&content);
        content.zeroize();
        Ok(parsed)
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
    /// unescaped. Both quote styles may span physical lines. Parsing remains
    /// lenient for read-only inspection: valid entries remain available even
    /// when [`Self::issues`] is non-empty. Every mutation API validates first
    /// and fails closed without returning partially rewritten content.
    pub fn parse_str(content: &str) -> Self {
        let mut records = Vec::new();
        let mut issues = unexpected_bom_issues(content);
        let mut cursor = usize::from(content.starts_with(UTF8_BOM)) * UTF8_BOM.len();
        let mut line_number = 1;

        while cursor < content.len() {
            let record_start = cursor;
            let (line_end, next_line) = physical_line_bounds(content, cursor);
            let line = &content[cursor..line_end];
            let leading = line.len() - line.trim_start_matches([' ', '\t']).len();
            let mut working_start = cursor + leading;
            let trimmed = &content[working_start..line_end];
            if trimmed.is_empty() || trimmed.starts_with('#') {
                cursor = next_line;
                line_number += 1;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("export ") {
                working_start += trimmed.len() - rest.len();
            }
            let working = &content[working_start..line_end];
            let Some(eq_rel) = working.find('=') else {
                issues.push(DotenvParseIssue {
                    line: line_number,
                    column: leading + 1,
                    kind: DotenvParseIssueKind::MissingEquals,
                });
                cursor = next_line;
                line_number += 1;
                continue;
            };
            let key = working[..eq_rel].trim();
            if key.is_empty() {
                issues.push(DotenvParseIssue {
                    line: line_number,
                    column: working_start - cursor + 1,
                    kind: DotenvParseIssueKind::EmptyKey,
                });
                cursor = next_line;
                line_number += 1;
                continue;
            }
            if key.contains(UTF8_BOM) {
                // The pre-scan already emitted the more precise BOM issue.
                cursor = next_line;
                line_number += 1;
                continue;
            }
            if !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
            {
                issues.push(DotenvParseIssue {
                    line: line_number,
                    column: working_start - cursor + 1,
                    kind: DotenvParseIssueKind::InvalidKey,
                });
                cursor = next_line;
                line_number += 1;
                continue;
            }

            let eq = working_start + eq_rel;
            let mut value_start = eq + 1;
            while value_start < line_end && matches!(content.as_bytes()[value_start], b' ' | b'\t')
            {
                value_start += 1;
            }

            let (value_span, record_end, value, consumed_lines) =
                match content.as_bytes().get(value_start).copied() {
                    Some(quote @ (b'"' | b'\'')) => {
                        let inner_start = value_start + 1;
                        let Some(close) = find_closing_quote(content, inner_start, quote) else {
                            issues.push(DotenvParseIssue {
                                line: line_number,
                                column: value_start - cursor + 1,
                                kind: if quote == b'"' {
                                    DotenvParseIssueKind::UnterminatedDoubleQuote
                                } else {
                                    DotenvParseIssueKind::UnterminatedSingleQuote
                                },
                            });
                            break;
                        };
                        let (closing_line_end, closing_next_line) =
                            physical_line_bounds(content, close);
                        let trailing = &content[close + 1..closing_line_end];
                        let trailing_trimmed = trailing.trim_start_matches([' ', '\t']);
                        if !trailing_trimmed.is_empty() && !trailing_trimmed.starts_with('#') {
                            issues.push(DotenvParseIssue {
                                line: line_number + count_line_breaks(&content[cursor..close]),
                                column: 1,
                                kind: DotenvParseIssueKind::UnexpectedCharactersAfterQuotedValue,
                            });
                        }
                        let raw = &content[inner_start..close];
                        let parsed = if quote == b'"' {
                            let normalized = Zeroizing::new(normalize_line_endings(raw));
                            unescape_double_quoted(&normalized)
                        } else {
                            normalize_line_endings(raw)
                        };
                        (
                            inner_start..close,
                            closing_next_line,
                            parsed,
                            count_consumed_lines(&content[record_start..closing_next_line]),
                        )
                    }
                    _ => {
                        let raw = &content[value_start..line_end];
                        let comment = raw
                            .char_indices()
                            .find(|(i, c)| {
                                *c == '#'
                                    && ((*i == 0 && value_start > eq + 1)
                                        || (*i > 0 && raw.as_bytes()[*i - 1].is_ascii_whitespace()))
                            })
                            .map(|(i, _)| i);
                        let candidate = &raw[..comment.unwrap_or(raw.len())];
                        let value_len = candidate.trim_end_matches([' ', '\t']).len();
                        let end = value_start + value_len;
                        (
                            value_start..end,
                            next_line,
                            content[value_start..end].to_string(),
                            1,
                        )
                    }
                };

            records.push(ParsedRecord {
                entry: EnvEntry {
                    key: key.to_string(),
                    is_phantom: PhantomToken::is_phantom_token(&value),
                    value,
                },
                record_span: record_start..record_end,
                value_span,
            });
            cursor = record_end;
            line_number += consumed_lines;
        }

        issues.sort_by_key(|issue| (issue.line, issue.column));
        Self {
            source: content.to_string(),
            records,
            issues,
        }
    }

    /// Get all key-value entries (excluding comments/blanks).
    pub fn entries(&self) -> Vec<&EnvEntry> {
        self.records.iter().map(|record| &record.entry).collect()
    }

    /// Return value-free syntax issues discovered during lenient parsing.
    pub fn issues(&self) -> &[DotenvParseIssue] {
        &self.issues
    }

    /// Require an unambiguous, fully parsed document before producing output.
    pub fn validate_for_mutation(&self) -> Result<()> {
        if let Some(issue) = self.issues.first() {
            return Err(PhantomError::DotenvParseError(format!(
                "refusing to mutate malformed dotenv at line {}, column {}: {}",
                issue.line, issue.column, issue.kind
            )));
        }
        let mut keys = BTreeSet::new();
        for record in &self.records {
            if !keys.insert(record.entry.key.as_str()) {
                return Err(PhantomError::DotenvParseError(format!(
                    "refusing to mutate dotenv with duplicate mapping '{}'",
                    record.entry.key
                )));
            }
        }
        Ok(())
    }

    /// Remove exactly one Phantom-owned mapping while preserving every other
    /// safely round-trippable source line byte-for-byte. Plaintext entries,
    /// duplicate keys, and unrelated entries whose raw representation cannot
    /// be preserved are rejected rather than rewritten ambiguously.
    pub fn remove_phantom_mapping(
        &self,
        name: &str,
        _had_trailing_newline: bool,
    ) -> Result<String> {
        self.validate_for_mutation()?;
        let matches = self
            .records
            .iter()
            .filter(|record| record.entry.key == name)
            .count();
        if matches != 1 {
            return Err(PhantomError::DotenvParseError(format!(
                "expected exactly one managed mapping for '{name}', found {matches}"
            )));
        }
        let record = self
            .records
            .iter()
            .find(|record| record.entry.key == name)
            .ok_or_else(|| {
                PhantomError::DotenvParseError(format!(
                    "expected exactly one managed mapping for '{name}', found 0"
                ))
            })?;
        if !record.entry.is_phantom {
            return Err(PhantomError::DotenvParseError(format!(
                "refusing to remove plaintext or non-Phantom mapping '{name}'"
            )));
        }
        Ok(splice_source(
            &self.source,
            &[(record.record_span.clone(), "")],
        ))
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
    ) -> Result<String> {
        self.validate_for_mutation()?;
        let replacements = self
            .records
            .iter()
            .filter(|record| {
                record.entry.is_phantom || classify(&record.entry) == SecretClassification::Secret
            })
            .map(|record| {
                (
                    record.value_span.clone(),
                    render_replacement(
                        &self.source,
                        &record.value_span,
                        &generate_placeholder(&record.entry.key, config),
                    ),
                )
            })
            .collect::<Vec<_>>();
        let body = splice_source_owned(&self.source, &replacements);
        let (preamble, body) = body
            .strip_prefix(UTF8_BOM)
            .map_or(("", body.as_str()), |without_bom| (UTF8_BOM, without_bom));
        let eol = if self.source.contains("\r\n") {
            "\r\n"
        } else if self.source.contains('\n') {
            "\n"
        } else if self.source.contains('\r') {
            "\r"
        } else {
            "\n"
        };
        let header = [
            "# Environment variables for this project".to_string(),
            "# Copy to .env and fill in real values, or use an installed local Phantom binary:"
                .to_string(),
            "#   phantom init".to_string(),
            format!(
                "# Reviewed release: https://github.com/ashlrai/phantom-secrets/releases/tag/v{}",
                env!("CARGO_PKG_VERSION")
            ),
            "#".to_string(),
            "# See https://phm.dev for details".to_string(),
            String::new(),
        ]
        .join(eol);
        Ok(format!("{preamble}{header}{eol}{body}"))
    }

    /// Rewrite the .env file, replacing real secret values with phantom tokens.
    /// Returns the rewritten content and a map of secret names to their original values.
    pub fn rewrite_with_phantoms(
        &self,
        token_map: &TokenMap,
    ) -> Result<(String, BTreeMap<String, String>)> {
        self.validate_for_mutation()?;
        let mut original_values = BTreeMap::new();
        let mut replacements = Vec::new();
        for record in &self.records {
            if let Some(token) = token_map.get_token(&record.entry.key) {
                if !record.entry.is_phantom {
                    original_values.insert(record.entry.key.clone(), record.entry.value.clone());
                }
                replacements.push((
                    record.value_span.clone(),
                    render_replacement(&self.source, &record.value_span, token.as_str()),
                ));
            }
        }
        Ok((
            splice_source_owned(&self.source, &replacements),
            original_values,
        ))
    }

    /// Replace existing mappings and append absent mappings with Phantom
    /// tokens while preserving BOM, line-ending style, terminal-newline
    /// shape, comments, spacing, and quote syntax.
    pub fn upsert_with_phantoms(
        &self,
        token_map: &TokenMap,
    ) -> Result<(String, BTreeMap<String, String>)> {
        self.validate_for_mutation()?;
        let existing = self
            .records
            .iter()
            .map(|record| record.entry.key.as_str())
            .collect::<BTreeSet<_>>();
        let mut absent = token_map
            .secret_names()
            .into_iter()
            .filter(|name| !existing.contains(name))
            .collect::<Vec<_>>();
        absent.sort_unstable();
        if absent.iter().any(|name| !is_canonical_env_name(name)) {
            return Err(PhantomError::DotenvParseError(
                "refusing to append a mapping with an invalid variable name".to_string(),
            ));
        }
        if absent
            .iter()
            .any(|name| token_map.get_token(name).is_none())
        {
            return Err(PhantomError::DotenvParseError(
                "missing prepared Phantom token for appended mapping".to_string(),
            ));
        }
        let (mut rewritten, originals) = self.rewrite_with_phantoms(token_map)?;
        if absent.is_empty() {
            return Ok((rewritten, originals));
        }

        let eol = preferred_line_ending(&self.source);
        let had_terminal_eol = self.source.ends_with(['\r', '\n']);
        let body = self.source.strip_prefix(UTF8_BOM).unwrap_or(&self.source);
        let has_body = !body.is_empty();
        if has_body && !had_terminal_eol {
            rewritten.push_str(eol);
        }
        for (index, name) in absent.iter().enumerate() {
            let token = token_map
                .get_token(name)
                .expect("all absent mappings were resolved before plaintext rewrite");
            rewritten.push_str(name);
            rewritten.push('=');
            rewritten.push_str(token.as_str());
            if index + 1 < absent.len() || had_terminal_eol {
                rewritten.push_str(eol);
            }
        }
        Ok((rewritten, originals))
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
        let (content, originals) = self.rewrite_with_phantoms(token_map)?;
        crate::fs::atomic_write(path, content.as_bytes())?;
        Ok(originals)
    }
}

/// Canonical portable environment-variable name accepted for newly appended
/// mappings and provider-returned secret names.
pub fn is_canonical_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn preferred_line_ending(source: &str) -> &'static str {
    let bytes = source.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => return "\r\n",
            b'\r' => return "\r",
            b'\n' => return "\n",
            _ => {}
        }
    }
    "\n"
}

/// Report every BOM outside the single allowed preamble position.
fn unexpected_bom_issues(source: &str) -> Vec<DotenvParseIssue> {
    source
        .match_indices(UTF8_BOM)
        .filter(|(offset, _)| *offset != 0)
        .map(|(offset, _)| {
            let (line, column) = physical_location(source, offset);
            DotenvParseIssue {
                line,
                column,
                kind: DotenvParseIssueKind::UnexpectedByteOrderMark,
            }
        })
        .collect()
}

/// Return a one-based physical line and byte column for a source offset.
fn physical_location(source: &str, offset: usize) -> (usize, usize) {
    let bytes = source.as_bytes();
    let mut cursor = 0;
    let mut line = 1;
    let mut column = 1;
    while cursor < offset {
        match bytes[cursor] {
            b'\r' => {
                cursor += if bytes.get(cursor + 1).is_some_and(|byte| *byte == b'\n') {
                    2
                } else {
                    1
                };
                line += 1;
                column = 1;
            }
            b'\n' => {
                cursor += 1;
                line += 1;
                column = 1;
            }
            _ => {
                cursor += 1;
                column += 1;
            }
        }
    }
    (line, column)
}

/// Locate the content end and post-newline end of the physical line at `start`.
fn physical_line_bounds(source: &str, start: usize) -> (usize, usize) {
    let bytes = source.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\n' => return (cursor, cursor + 1),
            b'\r' => {
                let next = cursor
                    + if bytes.get(cursor + 1).is_some_and(|byte| *byte == b'\n') {
                        2
                    } else {
                        1
                    };
                return (cursor, next);
            }
            _ => cursor += 1,
        }
    }
    (source.len(), source.len())
}

/// Find a closing quote, respecting double-quoted backslash escape pairs.
fn find_closing_quote(source: &str, start: usize, quote: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() {
        if quote == b'"' && bytes[cursor] == b'\\' {
            cursor += 1;
            if cursor < bytes.len() {
                cursor += 1;
            }
            continue;
        }
        if bytes[cursor] == quote {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

/// Count LF, CRLF, and lone CR physical line breaks without double counting.
fn count_line_breaks(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut count = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\r' => {
                count += 1;
                cursor += if bytes.get(cursor + 1).is_some_and(|byte| *byte == b'\n') {
                    2
                } else {
                    1
                };
            }
            b'\n' => {
                count += 1;
                cursor += 1;
            }
            _ => cursor += 1,
        }
    }
    count
}

/// Count physical lines occupied by a non-empty source span.
fn count_consumed_lines(source: &str) -> usize {
    count_line_breaks(source) + usize::from(!(source.ends_with('\n') || source.ends_with('\r')))
}

/// Normalize decoded multiline values while leaving retained source untouched.
fn normalize_line_endings(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

/// Render a replacement that cannot merge with an immediately following
/// inline comment. Existing whitespace before the zero-width value remains
/// untouched; one new separator is placed between rendered value and `#`.
fn render_replacement(source: &str, span: &Range<usize>, replacement: &str) -> String {
    let needs_comment_separator = span.is_empty()
        && source
            .as_bytes()
            .get(span.end)
            .is_some_and(|byte| *byte == b'#');
    if needs_comment_separator {
        format!("{replacement} ")
    } else {
        replacement.to_string()
    }
}

/// Apply ordered, non-overlapping replacements to exact source spans.
fn splice_source(source: &str, replacements: &[(Range<usize>, &str)]) -> String {
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    for (span, replacement) in replacements {
        debug_assert!(span.start >= cursor && span.end <= source.len());
        output.push_str(&source[cursor..span.start]);
        output.push_str(replacement);
        cursor = span.end;
    }
    output.push_str(&source[cursor..]);
    output
}

/// Borrow owned replacement values before using the common source splicer.
fn splice_source_owned(source: &str, replacements: &[(Range<usize>, String)]) -> String {
    let borrowed = replacements
        .iter()
        .map(|(span, replacement)| (span.clone(), replacement.as_str()))
        .collect::<Vec<_>>();
    splice_source(source, &borrowed)
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

        let (rewritten, originals) = dotenv.rewrite_with_phantoms(&token_map).unwrap();

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
        let example = dotenv.generate_example_content(None).unwrap();
        assert!(example.contains("phantom init"));
        assert!(example.contains("/releases/tag/v"));
        assert!(!example.contains("npm install -g phantom-secrets"));
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
        let (rewritten, _) = dotenv.rewrite_with_phantoms(&token_map).unwrap();
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
        let (out, _) = DotenvFile::parse_str(input)
            .rewrite_with_phantoms(&tm)
            .unwrap();
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
        let (out, _) = dotenv.rewrite_with_phantoms(&tm).unwrap();
        assert_eq!(out, content);
    }

    #[test]
    fn rewrite_falls_back_for_multiline_quoted_value() {
        // Only the complete raw inner-value span changes. Quotes and the
        // physical newline after the record remain byte-for-byte intact.
        assert_rewrite(
            "PRIVATE_KEY",
            "phm_eeee",
            "PRIVATE_KEY=\"line1\nline2\"\n",
            "PRIVATE_KEY=\"phm_eeee\"\n",
        );
    }

    #[test]
    fn rewrite_falls_back_for_double_quoted_value_with_escapes() {
        // Parsing escapes for runtime use does not discard the raw span used
        // for mutation, so quote style still survives.
        assert_rewrite(
            "MULTILINE_KEY",
            "phm_ffff",
            "MULTILINE_KEY=\"a\\nb\"\n",
            "MULTILINE_KEY=\"phm_ffff\"\n",
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

    #[test]
    fn no_op_rewrite_preserves_every_lf_byte_without_terminal_newline() {
        let content =
            "# before\n  export ESCAPED = \"a\\n\\\"b\"  # tail\nMULTI='one\ntwo'\nPLAIN=value";
        let dotenv = DotenvFile::parse_str(content);
        assert!(dotenv.issues().is_empty());
        let (rewritten, originals) = dotenv.rewrite_with_phantoms(&TokenMap::new()).unwrap();
        assert_eq!(rewritten.as_bytes(), content.as_bytes());
        assert!(originals.is_empty());
    }

    #[test]
    fn no_op_rewrite_preserves_every_crlf_byte() {
        let content = "# before\r\n  export ESCAPED = \"a\\n\\\"b\"  # tail\r\nMULTI='one\r\ntwo'\r\nPLAIN=value\r\n";
        let dotenv = DotenvFile::parse_str(content);
        assert!(dotenv.issues().is_empty());
        assert_eq!(dotenv.entries()[1].value, "one\ntwo");
        let (rewritten, _) = dotenv.rewrite_with_phantoms(&TokenMap::new()).unwrap();
        assert_eq!(rewritten.as_bytes(), content.as_bytes());
    }

    #[test]
    fn mapped_multiline_crlf_value_changes_only_its_inner_span() {
        let content = "# keep\r\n  export PRIVATE_KEY = \"line1\r\nline2\\nline3\"  # keep too\r\nPLAIN='untouched'\r\n";
        let mut tokens = TokenMap::new();
        tokens.insert_with_token(
            "PRIVATE_KEY".to_string(),
            PhantomToken::parse("phm_crlf").unwrap(),
        );
        let (rewritten, originals) = DotenvFile::parse_str(content)
            .rewrite_with_phantoms(&tokens)
            .unwrap();
        assert_eq!(
            rewritten,
            "# keep\r\n  export PRIVATE_KEY = \"phm_crlf\"  # keep too\r\nPLAIN='untouched'\r\n"
        );
        assert_eq!(originals["PRIVATE_KEY"], "line1\nline2\nline3");
    }

    #[test]
    fn escaped_backslashes_and_quotes_do_not_close_value_early() {
        let content = r#"API_KEY="prefix\\\"middle\\\\tail" # comment
NEXT=ok
"#;
        let dotenv = DotenvFile::parse_str(content);
        assert!(dotenv.issues().is_empty());
        assert_eq!(dotenv.entries().len(), 2);
        assert_eq!(dotenv.entries()[0].value, "prefix\\\"middle\\\\tail");
        assert_eq!(dotenv.entries()[1].key, "NEXT");
    }

    #[test]
    fn malformed_input_is_readable_but_all_output_apis_fail_closed() {
        let secret = "never-echo-this-secret";
        let content = format!("GOOD=ok\nAPI_KEY=\"{secret}\nAFTER=value\n");
        let dotenv = DotenvFile::parse_str(&content);
        assert_eq!(dotenv.entries().len(), 1, "valid prefix remains readable");
        assert_eq!(dotenv.issues().len(), 1);
        assert_eq!(
            dotenv.issues()[0].kind,
            DotenvParseIssueKind::UnterminatedDoubleQuote
        );

        let mut tokens = TokenMap::new();
        tokens.insert("GOOD".to_string());
        let rewrite_error = dotenv.rewrite_with_phantoms(&tokens).unwrap_err();
        let example_error = dotenv.generate_example_content(None).unwrap_err();
        let remove_error = dotenv
            .remove_phantom_mapping("GOOD", content.ends_with('\n'))
            .unwrap_err();
        for error in [rewrite_error, example_error, remove_error] {
            let message = error.to_string();
            assert!(message.contains("unterminated double-quoted value"));
            assert!(!message.contains(secret));
        }
    }

    #[test]
    fn strict_upsert_preserves_bom_crlf_format_and_no_final_newline() {
        let source = "\u{feff}# keep\r\nexport EXISTING = \"old\"  # tail";
        let mut tokens = TokenMap::new();
        tokens.insert_with_token(
            "EXISTING".to_string(),
            PhantomToken::parse("phm_existing").unwrap(),
        );
        tokens.insert_with_token(
            "NEW_KEY".to_string(),
            PhantomToken::parse("phm_new").unwrap(),
        );

        let (rewritten, originals) = DotenvFile::parse_str(source)
            .upsert_with_phantoms(&tokens)
            .unwrap();

        assert_eq!(
            rewritten,
            "\u{feff}# keep\r\nexport EXISTING = \"phm_existing\"  # tail\r\nNEW_KEY=phm_new"
        );
        assert_eq!(originals["EXISTING"], "old");
    }

    #[test]
    fn strict_upsert_preserves_lone_cr_and_terminal_newline_shape() {
        let source = "# keep\rA=one\r";
        let mut tokens = TokenMap::new();
        tokens.insert_with_token("B".to_string(), PhantomToken::parse("phm_b").unwrap());
        let (rewritten, _) = DotenvFile::parse_str(source)
            .upsert_with_phantoms(&tokens)
            .unwrap();
        assert_eq!(rewritten, "# keep\rA=one\rB=phm_b\r");
    }

    #[test]
    fn strict_upsert_handles_empty_and_bom_only_sources_without_leading_newline() {
        let mut tokens = TokenMap::new();
        tokens.insert_with_token(
            "NEW_KEY".to_string(),
            PhantomToken::parse("phm_new").unwrap(),
        );
        let (empty, _) = DotenvFile::parse_str("")
            .upsert_with_phantoms(&tokens)
            .unwrap();
        let (bom, _) = DotenvFile::parse_str(UTF8_BOM)
            .upsert_with_phantoms(&tokens)
            .unwrap();
        assert_eq!(empty, "NEW_KEY=phm_new");
        assert_eq!(bom, "\u{feff}NEW_KEY=phm_new");
    }

    #[test]
    fn strict_upsert_rejects_malformed_duplicates_and_unsafe_new_names() {
        let mut tokens = TokenMap::new();
        tokens.insert("NEW_KEY".to_string());
        for source in ["BROKEN\n", "A=one\nA=two\n"] {
            assert!(DotenvFile::parse_str(source)
                .upsert_with_phantoms(&tokens)
                .is_err());
        }
        let mut unsafe_tokens = TokenMap::new();
        unsafe_tokens.insert("BAD-NAME".to_string());
        assert!(DotenvFile::parse_str("")
            .upsert_with_phantoms(&unsafe_tokens)
            .is_err());
    }

    #[test]
    fn all_parse_issue_diagnostics_are_value_free() {
        let cases = [
            ("not-an-assignment\n", DotenvParseIssueKind::MissingEquals),
            (" =secret-value\n", DotenvParseIssueKind::EmptyKey),
            ("BAD KEY=secret-value\n", DotenvParseIssueKind::InvalidKey),
            (
                "A='secret-value\n",
                DotenvParseIssueKind::UnterminatedSingleQuote,
            ),
            (
                "A=\"secret-value\" junk\n",
                DotenvParseIssueKind::UnexpectedCharactersAfterQuotedValue,
            ),
        ];
        for (source, expected) in cases {
            let dotenv = DotenvFile::parse_str(source);
            assert_eq!(dotenv.issues()[0].kind, expected);
            let error = dotenv.validate_for_mutation().unwrap_err().to_string();
            assert!(!error.contains("secret-value"));
        }
    }

    #[test]
    fn duplicate_keys_are_rejected_before_mutation() {
        let dotenv = DotenvFile::parse_str("API_KEY=one\nAPI_KEY=two\n");
        assert!(dotenv.issues().is_empty());
        assert!(dotenv
            .rewrite_with_phantoms(&TokenMap::new())
            .unwrap_err()
            .to_string()
            .contains("duplicate mapping 'API_KEY'"));
        assert!(dotenv.generate_example_content(None).is_err());
    }

    #[test]
    fn whitespace_before_unquoted_hash_starts_an_empty_value_comment() {
        let dotenv = DotenvFile::parse_str("EMPTY=  # explanatory comment\nHASH=#literal\n");
        assert!(dotenv.issues().is_empty());
        assert_eq!(dotenv.entries()[0].value, "");
        assert_eq!(dotenv.entries()[1].value, "#literal");
        let (rewritten, _) = dotenv.rewrite_with_phantoms(&TokenMap::new()).unwrap();
        assert_eq!(rewritten, "EMPTY=  # explanatory comment\nHASH=#literal\n");
    }

    #[test]
    fn remove_mapping_preserves_crlf_and_all_unmapped_bytes() {
        let content = "# top\r\nTOKEN = 'phm_owned' # remove\r\n  KEEP=\"a\\nb\"  # exact\r\n";
        let dotenv = DotenvFile::parse_str(content);
        let rewritten = dotenv.remove_phantom_mapping("TOKEN", true).unwrap();
        assert_eq!(rewritten, "# top\r\n  KEEP=\"a\\nb\"  # exact\r\n");
    }

    #[test]
    fn remove_last_mapping_preserves_absence_of_terminal_newline() {
        let content = "KEEP=ok\nTOKEN=phm_owned";
        let rewritten = DotenvFile::parse_str(content)
            .remove_phantom_mapping("TOKEN", false)
            .unwrap();
        assert_eq!(rewritten, "KEEP=ok\n");
    }

    #[test]
    fn example_generation_preserves_unmapped_crlf_body_spans() {
        let content = "# exact\r\nAPI_KEY = \"sk-secret\" # note\r\n  PORT='3000'\r\n";
        let example = DotenvFile::parse_str(content)
            .generate_example_content(None)
            .unwrap();
        assert!(example.contains("API_KEY = \"your_api_key_here\" # note\r\n"));
        assert!(example.contains("# exact\r\n"));
        assert!(example.ends_with("  PORT='3000'\r\n"));
    }

    #[test]
    fn lf_and_crlf_unterminated_inputs_report_same_category() {
        for content in ["A=\"one\ntwo", "A=\"one\r\ntwo"] {
            let dotenv = DotenvFile::parse_str(content);
            assert_eq!(
                dotenv.issues(),
                &[DotenvParseIssue {
                    line: 1,
                    column: 3,
                    kind: DotenvParseIssueKind::UnterminatedDoubleQuote,
                }]
            );
        }
    }

    #[test]
    fn mapped_empty_value_preserves_lf_inline_comment_boundary() {
        assert_rewrite(
            "API_KEY",
            "phm_sep",
            "API_KEY=  # explanatory comment\nNEXT=ok\n",
            "API_KEY=  phm_sep # explanatory comment\nNEXT=ok\n",
        );
    }

    #[test]
    fn mapped_empty_value_preserves_crlf_inline_comment_boundary() {
        assert_rewrite(
            "API_KEY",
            "phm_sep",
            "API_KEY=\t # explanatory comment\r\nNEXT=ok\r\n",
            "API_KEY=\t phm_sep # explanatory comment\r\nNEXT=ok\r\n",
        );
    }

    #[test]
    fn mapped_whitespace_only_value_without_comment_needs_no_separator() {
        assert_rewrite(
            "API_KEY",
            "phm_sep",
            "API_KEY=  \t\r\nNEXT=ok\r\n",
            "API_KEY=  \tphm_sep\r\nNEXT=ok\r\n",
        );
    }

    #[test]
    fn mapped_empty_quoted_value_keeps_comment_outside_quotes() {
        assert_rewrite(
            "API_KEY",
            "phm_sep",
            "API_KEY=\"\" # explanatory comment\n",
            "API_KEY=\"phm_sep\" # explanatory comment\n",
        );
        assert_rewrite(
            "API_KEY",
            "phm_sep",
            "API_KEY=''# explanatory comment\r\n",
            "API_KEY='phm_sep'# explanatory comment\r\n",
        );
    }

    #[test]
    fn mapped_empty_unquoted_value_without_comment_has_no_extra_space() {
        assert_rewrite(
            "API_KEY",
            "phm_sep",
            "API_KEY=\nNEXT=ok\n",
            "API_KEY=phm_sep\nNEXT=ok\n",
        );
    }

    #[test]
    fn example_empty_value_preserves_inline_comment_boundary_for_lf_and_crlf() {
        for (content, expected) in [
            (
                "API_KEY=  # explanatory comment\nNEXT=ok\n",
                "API_KEY=  your_api_key_here # explanatory comment\nNEXT=ok\n",
            ),
            (
                "API_KEY=\t # explanatory comment\r\nNEXT=ok\r\n",
                "API_KEY=\t your_api_key_here # explanatory comment\r\nNEXT=ok\r\n",
            ),
        ] {
            let example = DotenvFile::parse_str(content)
                .generate_example_content(None)
                .unwrap();
            assert!(example.ends_with(expected));
        }
    }

    #[test]
    fn no_op_rewrite_preserves_every_cr_only_byte() {
        let content = "# before\rA=one\rB=\"two\rthree\\nfour\" # tail\rC='x\ry'\r";
        let dotenv = DotenvFile::parse_str(content);
        assert!(dotenv.issues().is_empty());
        assert_eq!(dotenv.entries().len(), 3);
        assert_eq!(dotenv.entries()[1].value, "two\nthree\nfour");
        assert_eq!(dotenv.entries()[2].value, "x\ny");
        let (rewritten, originals) = dotenv.rewrite_with_phantoms(&TokenMap::new()).unwrap();
        assert_eq!(rewritten.as_bytes(), content.as_bytes());
        assert!(originals.is_empty());
    }

    #[test]
    fn mapped_cr_only_assignment_cannot_consume_following_record() {
        assert_rewrite("A", "phm_cr", "A=one\rB=two\r", "A=phm_cr\rB=two\r");
    }

    #[test]
    fn remove_cr_only_mapping_preserves_following_record_exactly() {
        let content = "A=phm_owned\r  B=\"two\\nthree\" # exact\r";
        let rewritten = DotenvFile::parse_str(content)
            .remove_phantom_mapping("A", false)
            .unwrap();
        assert_eq!(rewritten, "  B=\"two\\nthree\" # exact\r");
    }

    #[test]
    fn cr_only_line_accounting_reports_the_physical_issue_line() {
        let dotenv = DotenvFile::parse_str("A=one\rBROKEN\rB=two\r");
        assert_eq!(dotenv.entries().len(), 2);
        assert_eq!(dotenv.issues()[0].line, 2);
        assert_eq!(dotenv.issues()[0].kind, DotenvParseIssueKind::MissingEquals);
    }

    #[test]
    fn example_generation_uses_cr_for_a_cr_only_source() {
        let example = DotenvFile::parse_str("API_KEY=secret\rNEXT=ok\r")
            .generate_example_content(None)
            .unwrap();
        assert!(!example.contains('\n'));
        assert!(example.ends_with("API_KEY=your_api_key_here\rNEXT=ok\r"));
    }

    #[test]
    fn byte_order_mark_preamble_is_not_part_of_first_key_and_no_op_is_exact() {
        let content = "\u{feff}API_KEY=one\r\nNEXT=two\r\n";
        let dotenv = DotenvFile::parse_str(content);
        assert!(dotenv.issues().is_empty());
        assert_eq!(dotenv.entries()[0].key, "API_KEY");
        let (rewritten, originals) = dotenv.rewrite_with_phantoms(&TokenMap::new()).unwrap();
        assert_eq!(rewritten.as_bytes(), content.as_bytes());
        assert!(originals.is_empty());
    }

    #[test]
    fn mapped_first_record_preserves_byte_order_mark_preamble() {
        assert_rewrite(
            "API_KEY",
            "phm_bom",
            "\u{feff}API_KEY=one\nNEXT=two\n",
            "\u{feff}API_KEY=phm_bom\nNEXT=two\n",
        );
    }

    #[test]
    fn removing_first_record_preserves_byte_order_mark_preamble() {
        let content = "\u{feff}TOKEN=phm_owned\r\nNEXT=two\r\n";
        let rewritten = DotenvFile::parse_str(content)
            .remove_phantom_mapping("TOKEN", true)
            .unwrap();
        assert_eq!(rewritten, "\u{feff}NEXT=two\r\n");
    }

    #[test]
    fn example_keeps_one_byte_order_mark_at_output_offset_zero() {
        let example = DotenvFile::parse_str("\u{feff}API_KEY=secret\nNEXT=two\n")
            .generate_example_content(None)
            .unwrap();
        assert!(example.starts_with(UTF8_BOM));
        assert_eq!(example.match_indices(UTF8_BOM).count(), 1);
        assert!(example.ends_with("API_KEY=your_api_key_here\nNEXT=two\n"));
        assert!(DotenvFile::parse_str(&example).issues().is_empty());
    }

    #[test]
    fn byte_order_mark_anywhere_else_is_a_fail_closed_issue() {
        for content in [
            "A=one\n\u{feff}B=two\n",
            "A=one\nB=tw\u{feff}o\n",
            "A=one\r\n# comment \u{feff}\r\n",
        ] {
            let dotenv = DotenvFile::parse_str(content);
            assert!(dotenv
                .issues()
                .iter()
                .any(|issue| issue.kind == DotenvParseIssueKind::UnexpectedByteOrderMark));
            let error = dotenv
                .rewrite_with_phantoms(&TokenMap::new())
                .unwrap_err()
                .to_string();
            assert!(error.contains("unexpected UTF-8 byte order mark"));
        }
    }
}
