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
    ///
    /// The file is read only as a regular, non-symlink file (see
    /// [`crate::fs::read_regular_file`]): a `.env` symlink planted in a project
    /// may point outside it, so it is refused rather than followed, and a
    /// dangling one is refused rather than reported as missing. Nothing at
    /// `path` is [`PhantomError::DotenvNotFound`].
    pub fn parse_file(path: &Path) -> Result<Self> {
        let shown = path.display().to_string();
        let bytes = crate::fs::read_regular_file(path).map_err(|error| {
            if error.to_string().contains(&shown) {
                PhantomError::Io(error)
            } else {
                PhantomError::Io(std::io::Error::new(
                    error.kind(),
                    format!("cannot read .env file {shown}: {error}"),
                ))
            }
        })?;
        let Some(bytes) = bytes else {
            return Err(PhantomError::DotenvNotFound(shown));
        };
        let content = Zeroizing::new(String::from_utf8(bytes).map_err(|error| {
            error.into_bytes().zeroize();
            PhantomError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(".env file is not valid UTF-8: {shown}"),
            ))
        })?);
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

    /// Each entry with the quote (`'"'` or `'\''`) that delimited its value in
    /// the source, or `None` for an unquoted value, in [`Self::entries`]
    /// order. Shell-flavoured callers need it: a single-quoted `'$NAME'` is
    /// literal text, an unquoted or double-quoted `$NAME` an expansion.
    pub fn entries_with_quote(&self) -> Vec<(&EnvEntry, Option<char>)> {
        self.records
            .iter()
            .map(|record| {
                // A quoted value's inner span starts just past its opening
                // quote; an unquoted one starts after `=` or blanks.
                let quote = record
                    .value_span
                    .start
                    .checked_sub(1)
                    .and_then(|before| self.source.as_bytes().get(before))
                    .and_then(|byte| match byte {
                        b'"' => Some('"'),
                        b'\'' => Some('\''),
                        _ => None,
                    });
                (&record.entry, quote)
            })
            .collect()
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

    /// Return the key of the first value dotenvx 1.x encrypted in place.
    ///
    /// dotenvx writes a `DOTENV_PUBLIC_KEY` (or `DOTENV_PUBLIC_KEY_<ENV>`)
    /// header and `KEY="encrypted:..."` values. Phantom has no private key,
    /// so those values are ciphertext: vaulting them would replace a working
    /// encrypted file with phm_ tokens that resolve to noise at exec/proxy
    /// time. The check is header-gated, so an ordinary value that merely
    /// starts with `encrypted:` is not flagged. Only the key is returned,
    /// never a value.
    pub fn dotenvx_encrypted_entry(&self) -> Option<&str> {
        let entries = self.entries();
        if !entries
            .iter()
            .any(|entry| is_dotenvx_public_key_name(&entry.key))
        {
            return None;
        }
        entries
            .into_iter()
            .find(|entry| {
                entry
                    .value
                    .trim_start()
                    .starts_with(DOTENVX_ENCRYPTED_PREFIX)
            })
            .map(|entry| entry.key.as_str())
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
    /// Uses [`crate::fs::atomic_write_if_unchanged`]: the new content is
    /// staged in a same-directory tempfile, fsynced, then renamed over the
    /// target, so a crash mid-write cannot leave a half-plaintext .env on
    /// disk. An existing target keeps its permissions (a new one is created
    /// 0o600 on POSIX).
    ///
    /// The target must be absent or a regular file whose bytes still equal
    /// the source this value was parsed from. A symlink or other non-regular
    /// target is refused rather than replaced, and a file edited after it was
    /// parsed is refused rather than clobbered with a rewrite of the stale
    /// image.
    pub fn write_phantomized(
        &self,
        token_map: &TokenMap,
        path: &Path,
    ) -> Result<BTreeMap<String, String>> {
        let (content, originals) = self.rewrite_with_phantoms(token_map)?;
        let content = Zeroizing::new(content);
        let before = crate::fs::read_regular_file(path)?.map(Zeroizing::new);
        if let Some(before) = before.as_deref() {
            if before.as_slice() != self.source.as_bytes() {
                return Err(PhantomError::Io(std::io::Error::other(format!(
                    "{} changed after it was parsed; refusing to overwrite it",
                    path.display()
                ))));
            }
        }
        crate::fs::atomic_write_if_unchanged(
            path,
            before.as_deref().map(Vec::as_slice),
            content.as_bytes(),
        )?;
        Ok(originals)
    }
}

/// Canonical portable environment-variable name accepted for newly appended
/// mappings and provider-returned secret names.
/// Prefix dotenvx 1.x writes in front of every value it encrypts in place.
const DOTENVX_ENCRYPTED_PREFIX: &str = "encrypted:";

/// Key (or key prefix, for `DOTENV_PUBLIC_KEY_<ENV>`) of the header dotenvx
/// 1.x writes into every `.env` it encrypts in place.
pub const DOTENVX_PUBLIC_KEY_NAME: &str = "DOTENV_PUBLIC_KEY";

fn is_dotenvx_public_key_name(key: &str) -> bool {
    key == DOTENVX_PUBLIC_KEY_NAME
        || key
            .strip_prefix(DOTENVX_PUBLIC_KEY_NAME)
            .is_some_and(|rest| rest.starts_with('_'))
}

/// Value-free refusal for a dotenv that dotenvx 1.x encrypted in place.
/// Names the entry (from [`DotenvFile::dotenvx_encrypted_entry`]) and the
/// remedy; never a value.
pub fn dotenvx_ciphertext_refusal(entry: &str) -> String {
    format!(
        "Entry '{entry}' is still dotenvx-encrypted (the file has a \
         {DOTENVX_PUBLIC_KEY_NAME} header); initialization made no changes.\n\
         Run `dotenvx decrypt` first (or `dotenvx decrypt --stdout > .env.decrypted` \
         and initialize from that file), then run Phantom again."
    )
}

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

/// Key-name fragments that mark an entry as a secret. `PWD` covers short
/// forms like `DB_PWD=hunter2` that would otherwise miss (audit F11).
const NAME_RULE_FRAGMENTS: [&str; 12] = [
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

/// Key-name fragments that indicate connection strings (which contain
/// credentials).
const CONNECTION_KEY_PATTERNS: [&str; 10] = [
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

/// Value prefixes of known secret formats. These alone override a public key
/// prefix (see [`classify`]).
const KNOWN_VALUE_PREFIXES: [&str; 14] = [
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

/// Further value prefixes that mark a non-public key as a secret: JWT-style
/// base64 and a PEM armor header (audit F11; multi-line PEM bodies depend on
/// F12 quoted parsing).
const NON_PUBLIC_VALUE_PREFIXES: [&str; 2] = ["eyJ", "-----BEGIN "];

/// Framework prefixes whose keys are shipped in browser bundles.
const PUBLIC_KEY_PREFIXES: [&str; 6] = [
    "NEXT_PUBLIC_",
    "EXPO_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "NUXT_PUBLIC_",
    "GATSBY_",
];

/// The value rule that decided an entry is a secret. Holds fixed labels and
/// pattern constants only, never any part of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueRule {
    /// The value starts with this known secret prefix.
    KnownPrefix(&'static str),
    /// A PEM block whose armor header names a private key.
    PemPrivateKey,
    /// A URL carrying credentials in its userinfo (`scheme://user:pass@host`).
    UrlCredentials,
    /// A URL carrying an auth, token, key or signature parameter.
    UrlAuthParam,
    /// A long high-entropy string.
    HighEntropy,
}

impl ValueRule {
    /// A fixed, value-free sentence fragment for human output.
    pub fn describe(&self) -> String {
        match self {
            ValueRule::KnownPrefix(prefix) => {
                format!(
                    "starts with \"{}\", a known secret prefix",
                    prefix.trim_end()
                )
            }
            ValueRule::PemPrivateKey => "is a PEM private key".to_string(),
            ValueRule::UrlCredentials => "is a URL with embedded credentials".to_string(),
            ValueRule::UrlAuthParam => {
                "is a URL with an auth, token or signature parameter".to_string()
            }
            ValueRule::HighEntropy => "is a long high-entropy string".to_string(),
        }
    }
}

/// The rule [`classify`] used to reach its verdict. Explanations (`phantom
/// why`, MCP `phantom_why`) report this instead of re-deriving a reason, so
/// the reason shown is always the one that decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationReason {
    /// A framework public prefix, with no secret-shaped value.
    PublicPrefix(&'static str),
    /// A framework public prefix overridden by a secret-shaped value. Key
    /// names are never consulted for public-prefixed keys.
    PublicPrefixWithSecretValue {
        prefix: &'static str,
        rule: ValueRule,
    },
    /// The key name contains this secret fragment.
    KeyName(&'static str),
    /// The key name contains this connection-string fragment.
    ConnectionPattern(&'static str),
    /// The value alone matched this rule.
    Value(ValueRule),
    /// No rule matched.
    NoSecretPattern,
}

impl ClassificationReason {
    /// The stable label the why report uses as `reason`.
    pub fn label(&self) -> &'static str {
        match self {
            ClassificationReason::PublicPrefix(_) => "public_prefix",
            ClassificationReason::PublicPrefixWithSecretValue { .. } => {
                "public_prefix_with_secret_value"
            }
            ClassificationReason::KeyName(_) => "key_name",
            ClassificationReason::ConnectionPattern(_) => "connection_pattern",
            ClassificationReason::Value(_) => "value_pattern",
            ClassificationReason::NoSecretPattern => "no_secret_pattern",
        }
    }

    /// The matched key fragment or public prefix, if the rule matched one.
    /// Value rules report none: the report stays value-blind.
    pub fn matched_pattern(&self) -> Option<&'static str> {
        match self {
            ClassificationReason::PublicPrefix(prefix)
            | ClassificationReason::PublicPrefixWithSecretValue { prefix, .. }
            | ClassificationReason::KeyName(prefix)
            | ClassificationReason::ConnectionPattern(prefix) => Some(prefix),
            ClassificationReason::Value(_) | ClassificationReason::NoSecretPattern => None,
        }
    }
}

/// Heuristic to determine if an env entry is likely a secret.
/// Checks both the key name and value patterns.
#[cfg(test)]
fn looks_like_secret(entry: &EnvEntry) -> bool {
    deciding_rule(entry).is_some()
}

/// The rule that makes a non-public entry a secret, or `None` when it is not
/// one. Rules are tried in order and the first match decides.
fn deciding_rule(entry: &EnvEntry) -> Option<ClassificationReason> {
    let key = entry.key.to_uppercase();
    let value = &entry.value;

    // Check key name
    if let Some(pattern) = NAME_RULE_FRAGMENTS.iter().find(|p| key.contains(*p)) {
        return Some(ClassificationReason::KeyName(pattern));
    }

    // Check connection string keys
    if let Some(pattern) = CONNECTION_KEY_PATTERNS.iter().find(|p| key.contains(*p)) {
        return Some(ClassificationReason::ConnectionPattern(pattern));
    }

    // Check value patterns
    if let Some(prefix) = known_value_prefix(value).or_else(|| {
        NON_PUBLIC_VALUE_PREFIXES
            .into_iter()
            .find(|p| value.starts_with(p))
    }) {
        return Some(ClassificationReason::Value(ValueRule::KnownPrefix(prefix)));
    }

    // Connection string URLs with credentials in userinfo (postgres://u:p@host)
    if value.contains("://") && value.contains('@') {
        return Some(ClassificationReason::Value(ValueRule::UrlCredentials));
    }

    // URLs carrying auth material in the query string, e.g.
    // `https://host/endpoint?api_key=xxx` (audit F11). Bare `://` alone is
    // not enough — that matches harmless public endpoints.
    if value.contains("://") && url_has_auth_query_param(value) {
        return Some(ClassificationReason::Value(ValueRule::UrlAuthParam));
    }

    // A Twilio Account SID is a public account identifier, not a credential:
    // it appears in every REST URL path and as the Basic-auth username. If it
    // were replaced by a phantom token, `/Accounts/{sid}/...` requests through
    // the proxy could never reach the right resource. Only the exact SID shape
    // (`AC` + 32 lowercase hex) under an `*ACCOUNT_SID` key is exempt from the
    // entropy heuristic.
    if is_twilio_account_sid(&key, value) {
        return None;
    }

    // High-entropy long strings are likely secrets (32+ chars of hex/base64)
    if value.len() >= 32
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '/' || c == '='
        })
    {
        return Some(ClassificationReason::Value(ValueRule::HighEntropy));
    }

    None
}

fn is_twilio_account_sid(upper_key: &str, value: &str) -> bool {
    upper_key.ends_with("ACCOUNT_SID")
        && value.len() == 34
        && value.starts_with("AC")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Query-parameter names that carry a credential whatever their value
/// (password/secret parameters and request signatures, as in signed S3, GCS
/// or Azure SAS URLs).
const SECRET_QUERY_PARAMS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "client_secret",
    "api_secret",
    "sig",
    "signature",
    "x-amz-signature",
    "x-goog-signature",
];

/// Query-parameter names that may carry a token or key. Some services use
/// them for browser-public values (Mapbox `pk.`, Google Maps `AIza...`), so on
/// their own they only count when the value has a known secret prefix.
const TOKEN_QUERY_PARAMS: &[&str] = &[
    "token",
    "access_token",
    "auth_token",
    "api_key",
    "apikey",
    "key",
];

/// Additional auth-like names that mark a non-public URL as a secret
/// regardless of value (the long-standing audit F11 list).
const AUTH_QUERY_PARAMS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "accesstoken",
    "auth_token",
    "authtoken",
    "auth",
    "token",
];

/// One `name=value` pair from a URL, with the name percent-decoded and
/// lowercased and the value percent-decoded.
struct UrlParam {
    name: String,
    value: String,
}

/// The parameters of a URL-shaped value (`scheme://...`), split at the first
/// `#` into the query proper and the fragment. The fragment is split on both
/// `&` and `?`, so it yields the parameters of a hash-routed app
/// (`#/cb?token=...`) as well as an OAuth implicit-flow fragment
/// (`#access_token=...`). Pairs without a `=` are skipped.
struct UrlParams {
    query: Vec<UrlParam>,
    fragment: Vec<UrlParam>,
}

fn url_params(value: &str) -> Option<UrlParams> {
    let (_, rest) = value.split_once("://")?;
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((head, frag)) => (head, Some(frag)),
        None => (rest, None),
    };
    let query = before_fragment
        .split_once('?')
        .map(|(_, q)| parse_url_pairs(q))
        .unwrap_or_default();
    let fragment = fragment
        .map(|frag| parse_url_pairs_split(frag, &['&', '?']))
        .unwrap_or_default();
    Some(UrlParams { query, fragment })
}

fn parse_url_pairs(pairs: &str) -> Vec<UrlParam> {
    parse_url_pairs_split(pairs, &['&'])
}

fn parse_url_pairs_split(pairs: &str, separators: &[char]) -> Vec<UrlParam> {
    pairs
        .split(separators)
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| UrlParam {
            name: percent_decode_lossy(name).to_ascii_lowercase(),
            value: percent_decode_lossy(value),
        })
        .collect()
}

/// Decode `%XX` escapes once, as a server would. Malformed escapes are kept
/// literally and invalid UTF-8 is replaced, so this never fails.
fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A parameter that carries a credential for both the public and non-public
/// paths: a secret/signature name with a non-empty value, or a token/key name
/// whose value has a known secret prefix.
fn is_query_credential(param: &UrlParam) -> bool {
    !param.value.is_empty()
        && (SECRET_QUERY_PARAMS.contains(&param.name.as_str())
            || (TOKEN_QUERY_PARAMS.contains(&param.name.as_str())
                && has_secret_value_pattern(&param.value)))
}

/// Detect auth-like parameters in a non-public URL-shaped value: everything
/// [`url_has_query_credential`] matches, plus any auth/token/secret-style name
/// (even with an empty value), in the query or the fragment.
fn url_has_auth_query_param(value: &str) -> bool {
    let Some(params) = url_params(value) else {
        return false;
    };
    params.query.iter().chain(&params.fragment).any(|param| {
        is_query_credential(param)
            || AUTH_QUERY_PARAMS.contains(&param.name.as_str())
            || SECRET_QUERY_PARAMS.contains(&param.name.as_str())
    })
}

/// Classify an environment variable entry as Secret, PublicKey, or NotSecret.
/// If a key has a public prefix (NEXT_PUBLIC_, VITE_, etc.) but the value matches
/// known secret patterns (sk_live_, ghp_, etc.), it's classified as Secret to prevent
/// accidental exposure of misnamed keys.
pub fn classify(entry: &EnvEntry) -> SecretClassification {
    classify_with_reason(entry).0
}

/// [`classify`], with the rule that decided. This is the one decision path:
/// `classify` is this verdict, and explanations report this reason.
pub fn classify_with_reason(entry: &EnvEntry) -> (SecretClassification, ClassificationReason) {
    if let Some(prefix) = public_key_prefix(&entry.key) {
        // Safety check: if the value looks like a real secret despite the public prefix,
        // classify as Secret to prevent leaking misnamed keys (e.g., VITE_STRIPE_SECRET_KEY=sk_live_...)
        match public_value_rule(&entry.value) {
            Some(rule) => (
                SecretClassification::Secret,
                ClassificationReason::PublicPrefixWithSecretValue { prefix, rule },
            ),
            None => (
                SecretClassification::PublicKey,
                ClassificationReason::PublicPrefix(prefix),
            ),
        }
    } else if let Some(reason) = deciding_rule(entry) {
        (SecretClassification::Secret, reason)
    } else {
        (
            SecretClassification::NotSecret,
            ClassificationReason::NoSecretPattern,
        )
    }
}

/// The value rule that overrides a public key prefix, if any.
fn public_value_rule(value: &str) -> Option<ValueRule> {
    if let Some(prefix) = known_value_prefix(value) {
        Some(ValueRule::KnownPrefix(prefix))
    } else if is_pem_private_key(value) {
        Some(ValueRule::PemPrivateKey)
    } else if url_has_userinfo_password(value) {
        Some(ValueRule::UrlCredentials)
    } else if url_has_query_credential(value) {
        Some(ValueRule::UrlAuthParam)
    } else {
        None
    }
}

/// The known secret prefix `value` starts with (independent of key name).
fn known_value_prefix(value: &str) -> Option<&'static str> {
    KNOWN_VALUE_PREFIXES
        .into_iter()
        .find(|p| value.starts_with(p))
}

/// Check if a value matches known secret prefixes (independent of key name).
fn has_secret_value_pattern(value: &str) -> bool {
    known_value_prefix(value).is_some()
}

/// A PEM block whose armor header names a private key (`PRIVATE KEY`,
/// `RSA PRIVATE KEY`, `OPENSSH PRIVATE KEY`, ...). Certificates and public
/// keys are not matched.
fn is_pem_private_key(value: &str) -> bool {
    value
        .strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.lines().next())
        .is_some_and(|header| header.contains("PRIVATE KEY"))
}

/// A `scheme://user:pass@host` URL whose userinfo carries a password
/// component (`redis://:pass@host` included). A bare `user@host` is not
/// matched.
fn url_has_userinfo_password(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    authority.rsplit_once('@').is_some_and(|(userinfo, _)| {
        userinfo
            .split_once(':')
            .is_some_and(|(_, pass)| !pass.is_empty())
    })
}

/// A URL whose query string carries a credential that is never meant for a
/// browser bundle: a password/secret parameter, a request signature (signed
/// S3/GCS/Azure SAS URLs), or a token/key parameter whose value has a known
/// secret prefix. Browser-public tokens such as Mapbox `pk.` or Google Maps
/// `key=AIza...` and analytics params are not matched, nor are empty values
/// or anything in the fragment.
fn url_has_query_credential(value: &str) -> bool {
    url_params(value).is_some_and(|params| params.query.iter().any(is_query_credential))
}

/// Check if a key name is a framework public key (safe for browser bundles).
pub fn is_public_key(key: &str) -> bool {
    public_key_prefix(key).is_some()
}

/// The framework public prefix `key` starts with, if any.
pub fn public_key_prefix(key: &str) -> Option<&'static str> {
    PUBLIC_KEY_PREFIXES
        .into_iter()
        .find(|prefix| key.starts_with(prefix))
}

/// Committable dotenv template basenames (`.env.example`, `.env.sample`,
/// `.env.template`). These are meant to be committed and hold placeholders.
pub fn is_example_template_file(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    matches!(name, ".env.example" | ".env.sample" | ".env.template")
}

/// True if `value` is exactly the shape of a placeholder produced by
/// [`DotenvFile::generate_example_content`] (`your_<name>_here`, lowercase
/// ASCII letters, digits, `_` or `-`), or is empty. This is deliberately
/// strict: anything else, including real key prefixes such as `sk-`, is not a
/// placeholder.
pub fn is_example_placeholder(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > 128 {
        return false;
    }
    let Some(middle) = value
        .strip_prefix("your_")
        .and_then(|rest| rest.strip_suffix("_here"))
    else {
        return false;
    };
    !middle.is_empty()
        && middle
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
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

    fn dotenvx_source(header_key: &str, sealed_key: &str) -> String {
        let public = ["03", "fakepublicplaceholder"].concat();
        let sealed = ["encrypted:", "BFakeCipher", "PlaceholderOnly=="].concat();
        format!(
            "#/---[DOTENV_PUBLIC_KEY]---/\n\
             {header_key}=\"{public}\"\n\
             NODE_ENV=development\n\
             {sealed_key}=\"{sealed}\"\n"
        )
    }

    #[test]
    fn dotenvx_encrypted_entry_names_the_sealed_key_under_a_header() {
        for header in ["DOTENV_PUBLIC_KEY", "DOTENV_PUBLIC_KEY_PRODUCTION"] {
            let dotenv = DotenvFile::parse_str(&dotenvx_source(header, "OPENAI_API_KEY"));
            assert_eq!(
                dotenv.dotenvx_encrypted_entry(),
                Some("OPENAI_API_KEY"),
                "header {header} not recognized"
            );
        }
    }

    #[test]
    fn dotenvx_encrypted_entry_is_header_gated() {
        // Without the dotenvx header the prefix alone is not proof of
        // ciphertext, and a look-alike header name does not count.
        let sealed = ["encrypted:", "Fake", "Placeholder"].concat();
        let plain = DotenvFile::parse_str(&format!("OPENAI_API_KEY={sealed}\n"));
        assert_eq!(plain.dotenvx_encrypted_entry(), None);
        let lookalike = DotenvFile::parse_str(&dotenvx_source("DOTENV_PUBLIC_KEYS", "API_KEY"));
        assert_eq!(lookalike.dotenvx_encrypted_entry(), None);
        // A header with only decrypted values is fine.
        let decrypted = DotenvFile::parse_str("DOTENV_PUBLIC_KEY=\"03abc\"\nAPI_KEY=value\n");
        assert_eq!(decrypted.dotenvx_encrypted_entry(), None);
    }

    #[test]
    fn dotenvx_ciphertext_refusal_names_entry_and_remedy_only() {
        let message = dotenvx_ciphertext_refusal("OPENAI_API_KEY");
        assert!(message.contains("'OPENAI_API_KEY'"));
        assert!(message.contains("dotenvx decrypt"));
        assert!(message.contains("made no changes"));
        assert!(!message.contains("encrypted:"));
    }

    #[test]
    fn generated_example_placeholders_are_recognized() {
        let env = DotenvFile::parse_str(
            "OPENAI_API_KEY=sk-proj-realish-value-1234567890\nDATABASE_URL=postgres://u:p@h/db\nDB_PASSWORD=hunter2\nSTRIPE_SECRET_KEY=sk_live_abc\nNODE_ENV=development\n",
        );
        let example = env.generate_example_content(None).unwrap();
        let parsed = DotenvFile::parse_str(&example);
        let secrets = parsed.real_secret_entries();
        assert!(!secrets.is_empty());
        for entry in secrets {
            // No custom message: CodeQL treats anything derived from a
            // secret entry (even its key) as sensitive output.
            assert!(is_example_placeholder(&entry.value));
        }
    }

    #[test]
    fn example_placeholder_is_strict() {
        assert!(is_example_placeholder("your_openai_here"));
        assert!(is_example_placeholder("your_stripe_secret_key_here"));
        assert!(is_example_placeholder(""));
        for value in [
            "sk-proj-abc123",
            "your_sk-live_Abc_here",
            "your__here",
            "your_openai_here sk-abc",
            "prefix_your_openai_here",
            "YOUR_OPENAI_HERE",
            "your_openai_here\n",
            "hunter2",
        ] {
            assert!(!is_example_placeholder(value), "{value:?}");
        }
        assert!(is_example_template_file(".env.example"));
        assert!(is_example_template_file("apps/web/.env.sample"));
        assert!(!is_example_template_file(".env"));
        assert!(!is_example_template_file(".env.local"));
        assert!(!is_example_template_file("x.env.example.bak"));
    }

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
    fn twilio_account_sid_is_an_identifier_not_a_secret() {
        // Built at runtime so no identifier-shaped literal enters history.
        let sid = format!("AC{}", "0123456789abcdef".repeat(2));
        assert!(!looks_like_secret(&EnvEntry {
            key: "TWILIO_ACCOUNT_SID".into(),
            value: sid.clone(),
            is_phantom: false
        }));
        // The exemption is narrow: same shape under another key, or a
        // non-SID value under the SID key, still hits the entropy heuristic.
        assert!(looks_like_secret(&EnvEntry {
            key: "TWILIO_SOMETHING".into(),
            value: sid.clone(),
            is_phantom: false
        }));
        assert!(looks_like_secret(&EnvEntry {
            key: "TWILIO_ACCOUNT_SID".into(),
            value: format!("SK{}", &sid[2..]),
            is_phantom: false
        }));
        // Twilio SIDs are lowercase hex; an uppercase variant is not exempt.
        assert!(looks_like_secret(&EnvEntry {
            key: "TWILIO_ACCOUNT_SID".into(),
            value: sid.to_uppercase(),
            is_phantom: false
        }));
        // The auth token stays protected.
        assert!(looks_like_secret(&EnvEntry {
            key: "TWILIO_AUTH_TOKEN".into(),
            value: "0123456789abcdef".repeat(2),
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

    fn classify_kv(key: &str, value: &str) -> SecretClassification {
        classify(&EnvEntry {
            key: key.into(),
            value: value.into(),
            is_phantom: false,
        })
    }

    fn reason_kv(key: &str, value: &str) -> ClassificationReason {
        classify_with_reason(&EnvEntry {
            key: key.into(),
            value: value.into(),
            is_phantom: false,
        })
        .1
    }

    /// `classify_with_reason` names the rule that decided, in the order the
    /// classifier tries them.
    #[test]
    fn classification_reason_is_the_deciding_rule() {
        let pem = ["-----BEGIN ", "PRIVATE KEY-----\nabc"].concat();
        let userinfo = ["postgres://u:", "pw", "@db.example.com/app"].concat();
        let sid = ["AC", &"0123456789abcdef".repeat(2)].concat();
        assert_eq!(
            reason_kv("DB_PWD", "x1"),
            ClassificationReason::KeyName("PWD")
        );
        // `KEY` comes first in the key-name list, so it decides `API_KEY`.
        assert_eq!(
            reason_kv("OPENAI_API_KEY", "x"),
            ClassificationReason::KeyName("KEY")
        );
        assert_eq!(
            reason_kv("CERT", &pem),
            ClassificationReason::Value(ValueRule::KnownPrefix("-----BEGIN "))
        );
        assert_eq!(
            reason_kv("PRIMARY", &userinfo),
            ClassificationReason::Value(ValueRule::UrlCredentials)
        );
        assert_eq!(
            reason_kv("VITE_CERT", &pem),
            ClassificationReason::PublicPrefixWithSecretValue {
                prefix: "VITE_",
                rule: ValueRule::PemPrivateKey,
            }
        );
        assert_eq!(
            reason_kv("VITE_DB", &userinfo),
            ClassificationReason::PublicPrefixWithSecretValue {
                prefix: "VITE_",
                rule: ValueRule::UrlCredentials,
            }
        );
        // The Twilio SID exemption leaves no reason behind.
        assert_eq!(
            reason_kv("TWILIO_ACCOUNT_SID", &sid),
            ClassificationReason::NoSecretPattern
        );
        assert_eq!(
            classify_kv("TWILIO_ACCOUNT_SID", &sid),
            SecretClassification::NotSecret
        );
        for reason in [reason_kv("CERT", &pem), reason_kv("VITE_DB", &userinfo)] {
            assert!(!format!("{reason:?}").contains("pw@"));
            assert!(!format!("{reason:?}").contains("abc"));
        }
    }

    #[test]
    fn public_prefix_never_exempts_a_private_key_or_url_credentials() {
        let pem_header = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
        let rsa_header = ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat();
        let pem =
            format!("{pem_header}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----");
        let rsa = format!("{rsa_header}\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----");
        let pg = ["postgres://app:", "hunter2", "@db.internal:5432/app"].concat();
        let redis = ["redis://:", "s3cr3t", "@cache.internal:6379"].concat();
        for (key, value) in [
            ("NEXT_PUBLIC_SIGNER", pem.as_str()),
            ("VITE_JWT_SIGNER", rsa.as_str()),
            ("VITE_DATABASE_URL", pg.as_str()),
            ("REACT_APP_CACHE", redis.as_str()),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::Secret,
                "public-prefixed {key} must not keep credential material in plaintext"
            );
        }

        // A full rewrite replaces them, so no credential stays in the file.
        let content = format!("VITE_DATABASE_URL={pg}\nNEXT_PUBLIC_SIGNER=\"{pem}\"\n");
        let dotenv = DotenvFile::parse_str(&content);
        let names: Vec<&str> = dotenv
            .real_secret_entries()
            .iter()
            .map(|entry| entry.key.as_str())
            .collect();
        assert_eq!(names, ["VITE_DATABASE_URL", "NEXT_PUBLIC_SIGNER"]);
        assert!(dotenv.public_key_entries().is_empty());
    }

    #[test]
    fn public_prefix_never_exempts_a_url_with_a_query_credential() {
        let pw = [
            "https://api.example.com/v1?user=app&pass",
            "word=",
            "hunter2",
        ]
        .concat();
        let client = ["https://auth.example.com/cb?client_", "secret=", "abc123"].concat();
        let plain = ["https://hooks.example.com/in?sec", "ret=", "xyz789"].concat();
        let s3 = [
            "https://bucket.s3.amazonaws.com/o.pdf?X-Amz-Expires=3600&X-Amz-",
            "Signature=",
            "deadbeef",
        ]
        .concat();
        let sas = [
            "https://acct.blob.core.windows.net/c/b?sv=2022&s",
            "ig=",
            "q1w2e3",
        ]
        .concat();
        let misnamed = ["https://api.example.com/v1?api_key=", "sk_", "live_abc123"].concat();
        let gh = ["https://api.example.com/x?tok", "en=", "ghp_", "abc123"].concat();
        for (key, value) in [
            ("VITE_API_URL", pw.as_str()),
            ("NEXT_PUBLIC_OAUTH_CALLBACK", client.as_str()),
            ("REACT_APP_WEBHOOK", plain.as_str()),
            ("NEXT_PUBLIC_REPORT_URL", s3.as_str()),
            ("GATSBY_ASSET", sas.as_str()),
            ("VITE_BACKEND", misnamed.as_str()),
            ("EXPO_PUBLIC_FEED", gh.as_str()),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::Secret,
                "public-prefixed {key} carries a credential in its query string"
            );
        }
    }

    #[test]
    fn public_prefix_keeps_urls_with_public_query_params() {
        // Browser-public tokens (Mapbox `pk.`, Google Maps browser keys) and
        // analytics params stay public; so do empty placeholders.
        let mapbox = [
            "https://api.mapbox.com/styles/v1/me/s?access_",
            "token=pk.eyJ1Ijoi",
        ]
        .concat();
        let gmaps = [
            "https://maps.googleapis.com/maps/api/js?ke",
            "y=AIzaSyExample",
        ]
        .concat();
        for (key, value) in [
            ("NEXT_PUBLIC_MAP_STYLE", mapbox.as_str()),
            ("VITE_MAPS_SCRIPT", gmaps.as_str()),
            (
                "NEXT_PUBLIC_LANDING",
                "https://example.com/?utm_source=x&utm_medium=y&ref=abc&lang=en",
            ),
            ("VITE_LOGIN_URL", "https://example.com/login?password="),
            (
                "NEXT_PUBLIC_DOCS",
                "https://example.com/docs#signature=intro",
            ),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::PublicKey,
                "{key} is a public browser value"
            );
        }
    }

    #[test]
    fn public_prefix_still_keeps_genuinely_public_values() {
        let cert = [
            "-----BEGIN ",
            "CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        ]
        .concat();
        let pubkey = [
            "-----BEGIN ",
            "PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
        ]
        .concat();
        let anon_jwt = ["eyJhbGciOi", "JIUzI1NiJ9"].concat();
        for (key, value) in [
            ("NEXT_PUBLIC_SUPABASE_URL", "https://example.supabase.co"),
            ("VITE_API_URL", "https://api.example.com/v1?region=us"),
            ("VITE_CDN", "https://user@cdn.example.com/assets"),
            ("NEXT_PUBLIC_SUPABASE_ANON_KEY", anon_jwt.as_str()),
            ("VITE_ROOT_CA", cert.as_str()),
            ("NEXT_PUBLIC_VERIFY_KEY", pubkey.as_str()),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::PublicKey,
                "{key} is a public browser value"
            );
        }
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
    fn entries_with_quote_reports_each_values_delimiter() {
        let content = "A=plain\nB=\"double\"\nC='single'\nD= 'spaced'\nE=\nF=\"multi\nline\"\n";
        let dotenv = DotenvFile::parse_str(content);
        let quotes: Vec<(&str, Option<char>)> = dotenv
            .entries_with_quote()
            .into_iter()
            .map(|(entry, quote)| (entry.key.as_str(), quote))
            .collect();
        assert_eq!(
            quotes,
            [
                ("A", None),
                ("B", Some('"')),
                ("C", Some('\'')),
                ("D", Some('\'')),
                ("E", None),
                ("F", Some('"')),
            ]
        );
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

    #[test]
    fn non_public_url_query_uses_the_shared_credential_params() {
        // These query credentials were already caught for public-prefixed
        // keys; a non-public key must not be weaker.
        let client = ["https://auth.example.com/cb?client_", "secret=", "abc123"].concat();
        let s3 = [
            "https://bucket.s3.amazonaws.com/o.pdf?X-Amz-Expires=3600&X-Amz-",
            "Signature=",
            "deadbeef",
        ]
        .concat();
        let short = [
            "https://db.example.com/admin?user=app&pass",
            "wd=",
            "hunter2",
        ]
        .concat();
        let misnamed = ["https://api.example.com/v1?ke", "y=", "sk_", "live_abc123"].concat();
        for (key, value) in [
            ("CALLBACK_URL", client.as_str()),
            ("ASSET_URL", s3.as_str()),
            ("ADMIN_URL", short.as_str()),
            ("BACKEND_URL", misnamed.as_str()),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::Secret,
                "{key} carries a credential in its query string"
            );
        }
    }

    #[test]
    fn url_fragment_is_split_from_the_query() {
        // OAuth implicit-flow style: the credential follows `#`, so it is not
        // part of the last query value.
        let implicit = [
            "https://app.example.com/cb?state=xyz#access_",
            "token=",
            "abc123",
        ]
        .concat();
        // Hash-routed SPA URL: `?` appears only inside the fragment.
        let hash_route = ["https://app.example.com/#/cb?tok", "en=", "abc123"].concat();
        let trailing = ["https://app.example.com/p?a=1#x&tok", "en=", "abc123?b"].concat();
        for (key, value) in [
            ("REDIRECT_URL", implicit.as_str()),
            ("APP_LINK", hash_route.as_str()),
            ("APP_LINK", trailing.as_str()),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::Secret,
                "{key} carries a credential after its fragment marker"
            );
        }
        // A fragment never feeds the public-prefixed path, and a bare anchor
        // is not a parameter.
        for (key, value, expected) in [
            (
                "NEXT_PUBLIC_DOCS",
                "https://example.com/docs#signature=intro",
                SecretClassification::PublicKey,
            ),
            (
                "DOCS_URL",
                "https://example.com/page?lang=en#token",
                SecretClassification::NotSecret,
            ),
            (
                "DOCS_URL",
                "https://example.com/guide#section-2",
                SecretClassification::NotSecret,
            ),
        ] {
            assert_eq!(
                classify_kv(key, value),
                expected,
                "{key} is not a credential"
            );
        }
    }

    #[test]
    fn percent_encoded_query_param_names_are_decoded() {
        let pw = ["https://db.example.com/x?pass%77", "ord=", "hunter2"].concat();
        let api = ["https://api.example.com/v1?API%5F", "KEY=", "abc123"].concat();
        let tok = ["https://hooks.example.com/in?%74ok", "en=", "abc123"].concat();
        let sig = [
            "https://cdn.example.com/f?x-amz-%53ig",
            "nature=",
            "deadbeef",
        ]
        .concat();
        for (key, value) in [
            ("ADMIN_URL", pw.as_str()),
            ("SERVICE_URL", api.as_str()),
            ("WEBHOOK_URL", tok.as_str()),
            ("ASSET_URL", sig.as_str()),
            ("VITE_ADMIN_URL", pw.as_str()),
            ("NEXT_PUBLIC_ASSET", sig.as_str()),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::Secret,
                "{key} hides a credential behind a percent-encoded name"
            );
        }

        // Public-prefixed token params need a known secret prefix; that check
        // also sees through percent-encoding of the name and of the value.
        let enc_name = [
            "https://api.example.com/v1?api%5F",
            "key=",
            "sk_",
            "live_abc123",
        ]
        .concat();
        let enc_value = [
            "https://api.example.com/v1?tok",
            "en=",
            "sk%5F",
            "live_abc123",
        ]
        .concat();
        for (key, value) in [
            ("VITE_BACKEND", enc_name.as_str()),
            ("EXPO_PUBLIC_FEED", enc_value.as_str()),
        ] {
            assert_eq!(
                classify_kv(key, value),
                SecretClassification::Secret,
                "{key} hides a misnamed secret behind percent-encoding"
            );
        }
    }

    #[test]
    fn ordinary_url_params_stay_non_secret() {
        let mapbox = [
            "https://api.mapbox.com/styles/v1/me/s?access%5F",
            "token=pk.eyJ1Ijoi",
        ]
        .concat();
        let gmaps = [
            "https://maps.googleapis.com/maps/api/js?ke",
            "y=AIzaSyExample",
        ]
        .concat();
        for (key, value, expected) in [
            (
                "REPO_URL",
                "https://github.com/org/repo/archive?ref=main",
                SecretClassification::NotSecret,
            ),
            (
                "LANDING_URL",
                "https://example.com/?utm_source=x&utm_medium=y&lang=en",
                SecretClassification::NotSecret,
            ),
            (
                "MAPS_SCRIPT_URL",
                gmaps.as_str(),
                SecretClassification::NotSecret,
            ),
            (
                "BROKEN_URL",
                "https://example.com/?a%zz=1&b=%&%=c&d%2",
                SecretClassification::NotSecret,
            ),
            (
                "NEXT_PUBLIC_MAP_STYLE",
                mapbox.as_str(),
                SecretClassification::PublicKey,
            ),
            (
                "VITE_SEARCH",
                "https://example.com/s?q=100%25&ref=main",
                SecretClassification::PublicKey,
            ),
        ] {
            assert_eq!(
                classify_kv(key, value),
                expected,
                "{key} is ordinary config"
            );
        }
    }

    fn fixture_line() -> String {
        ["API_KEY=", "plain", "-fixture-value\n"].concat()
    }

    fn api_key_map() -> TokenMap {
        let mut map = TokenMap::new();
        map.insert("API_KEY".to_string());
        map
    }

    #[cfg(unix)]
    #[test]
    fn write_phantomized_refuses_a_symlinked_target_and_keeps_the_link() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = dir.path().join("outside.env");
        std::fs::write(&outside, fixture_line()).unwrap();
        let env_path = dir.path().join(".env");
        std::os::unix::fs::symlink(&outside, &env_path).unwrap();

        let dotenv = DotenvFile::parse_str(&fixture_line());
        assert!(dotenv.write_phantomized(&api_key_map(), &env_path).is_err());

        let link = std::fs::symlink_metadata(&env_path).unwrap();
        assert!(link.file_type().is_symlink(), "symlink was replaced");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), fixture_line());
    }

    #[cfg(unix)]
    #[test]
    fn write_phantomized_preserves_the_existing_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, fixture_line()).unwrap();
        std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let dotenv = DotenvFile::parse_str(&fixture_line());
        dotenv.write_phantomized(&api_key_map(), &env_path).unwrap();

        let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "rewrite reset the dotenv mode");
        assert!(std::fs::read_to_string(&env_path)
            .unwrap()
            .starts_with("API_KEY=phm_"));
    }

    #[test]
    fn write_phantomized_refuses_a_file_edited_after_it_was_parsed() {
        let dir = tempfile::TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, fixture_line()).unwrap();
        let dotenv = DotenvFile::parse_str(&fixture_line());

        let concurrent = [fixture_line(), "ADDED_LATER=kept\n".to_string()].concat();
        std::fs::write(&env_path, &concurrent).unwrap();

        assert!(dotenv.write_phantomized(&api_key_map(), &env_path).is_err());
        assert_eq!(std::fs::read_to_string(&env_path).unwrap(), concurrent);
    }

    #[test]
    fn write_phantomized_creates_an_absent_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        let dotenv = DotenvFile::parse_str(&fixture_line());
        dotenv.write_phantomized(&api_key_map(), &env_path).unwrap();
        assert!(std::fs::read_to_string(&env_path)
            .unwrap()
            .starts_with("API_KEY=phm_"));
    }

    /// A `.env` symlink planted in a project points outside it. Parsing must
    /// refuse it, naming the path, instead of reading the target. Fails on
    /// main, where `parse_file` followed the link and returned the target's
    /// entries.
    #[cfg(unix)]
    #[test]
    fn parse_file_refuses_a_symlinked_env() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("elsewhere.env");
        std::fs::write(&target, "OUTSIDE_ONLY=1\n").unwrap();
        let env_path = project.path().join(".env");
        std::os::unix::fs::symlink(&target, &env_path).unwrap();

        let outcome = DotenvFile::parse_file(&env_path);
        let Err(error) = outcome else {
            panic!("a symlinked .env was read");
        };
        let rendered = error.to_string();
        assert!(rendered.contains(&env_path.display().to_string()));
        assert!(!rendered.contains("OUTSIDE_ONLY"));
    }

    /// A dangling `.env` symlink is refused too, not reported as a missing
    /// file (which callers treat as "nothing to import").
    #[cfg(unix)]
    #[test]
    fn parse_file_refuses_a_dangling_env_symlink() {
        let project = tempfile::tempdir().unwrap();
        let env_path = project.path().join(".env");
        std::os::unix::fs::symlink(project.path().join("absent.env"), &env_path).unwrap();

        let outcome = DotenvFile::parse_file(&env_path);
        assert!(matches!(outcome, Err(PhantomError::Io(_))));
    }

    /// A directory named `.env` is refused with an error naming the path.
    #[test]
    fn parse_file_refuses_a_directory_env() {
        let project = tempfile::tempdir().unwrap();
        let env_path = project.path().join(".env");
        std::fs::create_dir(&env_path).unwrap();

        let outcome = DotenvFile::parse_file(&env_path);
        let Err(error) = outcome else {
            panic!("a directory .env was parsed");
        };
        assert!(error.to_string().contains(&env_path.display().to_string()));
    }

    /// A missing `.env` keeps its `DotenvNotFound` error, and a regular file
    /// still parses.
    #[test]
    fn parse_file_keeps_missing_and_regular_behaviour() {
        let project = tempfile::tempdir().unwrap();
        let env_path = project.path().join(".env");
        assert!(matches!(
            DotenvFile::parse_file(&env_path),
            Err(PhantomError::DotenvNotFound(_))
        ));

        std::fs::write(&env_path, "NODE_ENV=development\n").unwrap();
        let parsed = DotenvFile::parse_file(&env_path).unwrap();
        assert_eq!(parsed.entries().len(), 1);
    }
}
