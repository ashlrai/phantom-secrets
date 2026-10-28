//! Value-independent credential detection shared by checks, leak reports and log redaction.
//!
//! Matches contain offsets and static metadata only. This is shape detection,
//! not validation or a guarantee against arbitrary or encoded secrets.
//! Choose the policy appropriate to the output boundary:
//!
//! - [`staged_code_credential_matches`] preserves existing `phantom check` findings.
//! - [`code_credential_matches`] supplies the expanded LOG-REDACT code catalog.
//! - [`credential_spans`] returns sorted, coalesced ranges for arbitrary log bytes;
//!   [`redact_text`] applies those ranges to UTF-8 incident/report text.
//! - [`response`] supplies the historical response policy, including incomplete
//!   prefixes and continuation predicates for bounded incremental scrubbing.
//!
//! Code false-positive exclusions must never be used to exempt response secrets.
//! Span consumers must retain incomplete input across reads; scanning each read
//! independently can expose a credential split across two reads.
//!
//! Dotenv classification keeps historical bare-prefix rules: it protects those values
//! even when they are short or malformed. Code checks apply historical false-positive
//! filters; log redaction retains the length/boundary checks but also scrubs lowercase
//! tails because an issued credential must not be exposed merely for resembling prose.

pub mod response;

use std::ops::Range;

/// Fixed, value-free metadata for a provider credential shape.
#[derive(Debug)]
pub struct CredentialPattern {
    pub prefix: &'static str,
    pub label: &'static str,
    pub min_tail: usize,
    upper_alnum_only: bool,
}

/// Code/log policy. Specific prefixes precede their general forms.
/// The first nine entries retain the historical staged-check catalog.
pub const CREDENTIAL_PATTERNS: &[CredentialPattern] = &[
    CredentialPattern {
        prefix: "sk-",
        label: "OpenAI API key",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "sk_live_",
        label: "Stripe live key",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "sk_test_",
        label: "Stripe test key",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "ghp_",
        label: "GitHub personal token",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "github_pat_",
        label: "GitHub PAT",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "glpat-",
        label: "GitLab PAT",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "xoxb-",
        label: "Slack bot token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "xoxp-",
        label: "Slack user token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "AKIA",
        label: "AWS access key",
        min_tail: 16,
        upper_alnum_only: true,
    },
    CredentialPattern {
        prefix: "xapp-",
        label: "Slack app token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "xoxa-",
        label: "Slack app token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "xoxs-",
        label: "Slack session token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "xoxr-",
        label: "Slack refresh token",
        min_tail: 20,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "gho_",
        label: "GitHub OAuth token",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "ghu_",
        label: "GitHub user token",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "ghs_",
        label: "GitHub installation token",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "ghr_",
        label: "GitHub refresh token",
        min_tail: 30,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "ASIA",
        label: "AWS temporary access key",
        min_tail: 16,
        upper_alnum_only: true,
    },
    CredentialPattern {
        prefix: "sk_",
        label: "Secret API key",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "pk_",
        label: "Publishable API key",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "rk_",
        label: "Restricted API key",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "whsec_",
        label: "Webhook signing secret",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "shpat_",
        label: "Shopify access token",
        min_tail: 16,
        upper_alnum_only: false,
    },
    CredentialPattern {
        prefix: "Bearer ",
        label: "Bearer credential",
        min_tail: 1,
        upper_alnum_only: false,
    },
];

/// A match stores byte offsets and fixed metadata, never a copy of the credential.
#[derive(Debug)]
pub struct CredentialMatch {
    pub pattern: &'static CredentialPattern,
    pub span: Range<usize>,
}

/// Preserve dotenv's historical prefix classification independently of code/log thresholds.
pub fn known_value_prefix(value: &str) -> Option<&'static str> {
    CREDENTIAL_PATTERNS
        .iter()
        .filter(|pattern| value.starts_with(pattern.prefix))
        // Unlike the historical prefixes, the newly supported ASIA prefix is
        // also an ordinary region value. Require its AWS tail before treating
        // it as a credential; do not tighten any pre-existing value rule.
        .filter(|pattern| {
            pattern.prefix != "ASIA"
                || value.as_bytes()[pattern.prefix.len()..]
                    .iter()
                    .take_while(|byte| tail_byte(pattern, **byte))
                    .count()
                    >= pattern.min_tail
        })
        // Preserve the historical `sk_` explanation for Stripe-specific prefixes.
        .min_by_key(|pattern| pattern.prefix.len())
        .map(|pattern| pattern.prefix)
}

fn tail_byte(pattern: &CredentialPattern, byte: u8) -> bool {
    if pattern.upper_alnum_only {
        byte.is_ascii_uppercase() || byte.is_ascii_digit()
    } else {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'_' | b'-')
            || (pattern.prefix == "Bearer " && matches!(byte, b'.' | b'+' | b'/' | b'=' | b'~'))
    }
}

/// CREDENTIAL_PATTERNS grouped by first prefix byte, so a scan position only
/// tests the shapes that can begin there. Bucket contents preserve catalog order.
fn patterns_by_first_byte() -> &'static [Vec<&'static CredentialPattern>; 256] {
    static INDEX: std::sync::OnceLock<[Vec<&'static CredentialPattern>; 256]> =
        std::sync::OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index: [Vec<&'static CredentialPattern>; 256] = std::array::from_fn(|_| Vec::new());
        for pattern in CREDENTIAL_PATTERNS {
            index[pattern.prefix.as_bytes()[0] as usize].push(pattern);
        }
        index
    })
}

fn matches(input: &[u8], code: bool) -> Vec<CredentialMatch> {
    let patterns = patterns_by_first_byte();
    let mut found = Vec::new();
    let mut start = 0;
    while start < input.len() {
        if start > 0 && input[start - 1].is_ascii_alphanumeric() {
            start += 1;
            continue;
        }
        let mut next = start + 1;
        for &pattern in &patterns[input[start] as usize] {
            // Bearer is an auth wrapper, not a staged-code provider identity. Let
            // the enclosed provider token produce its existing finding/label.
            if code && pattern.prefix == "Bearer " {
                continue;
            }
            if !input[start..].starts_with(pattern.prefix.as_bytes()) {
                continue;
            }
            let tail_start = start + pattern.prefix.len();
            let mut end = tail_start;
            while end < input.len() && tail_byte(pattern, input[end]) {
                end += 1;
            }
            let tail = &input[tail_start..end];
            if tail.len() < pattern.min_tail {
                continue;
            }
            // Retain check's identifier exclusion without teaching the streaming
            // redactor that all-lowercase credentials are safe to disclose.
            if code
                && !tail
                    .iter()
                    .any(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
            {
                next = end;
                break;
            }
            found.push(CredentialMatch {
                pattern,
                span: start..end,
            });
            next = end;
            break;
        }
        start = next;
    }
    found
}

/// Nonoverlapping byte spans to scrub from logs, including non-UTF-8 logs.
pub fn credential_spans(input: &[u8]) -> Vec<Range<usize>> {
    let mut spans: Vec<_> = matches(input, false)
        .into_iter()
        .map(|found| found.span)
        .collect();
    // Logs and incident reports must also cover response-only shapes (including
    // sensitive Phantom mappings), without the code scanner's boundary filter.
    // Every byte is still tested; the index only skips shapes whose first byte
    // cannot start a match at that position.
    let specs = response::specs_by_first_byte();
    for (cursor, byte) in input.iter().enumerate() {
        for spec in &specs[*byte as usize] {
            if let Some(len) = spec.complete_prefix_len(&input[cursor..]) {
                spans.push(cursor..cursor + len);
            }
        }
    }
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for span in spans {
        if let Some(last) = merged.last_mut() {
            if span.start <= last.end {
                last.end = last.end.max(span.end);
                continue;
            }
        }
        merged.push(span);
    }
    merged
}

/// Scrub recognized shapes while borrowing unchanged text when no match exists.
/// No vault, filesystem, environment or network access is performed.
pub fn redact_text(input: &str) -> std::borrow::Cow<'_, str> {
    let spans = credential_spans(input.as_bytes());
    if spans.is_empty() {
        return std::borrow::Cow::Borrowed(input);
    }
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    for span in spans {
        // Every grammar matches ASCII bytes, so these offsets are UTF-8 boundaries.
        output.push_str(&input[copied..span.start]);
        output.push_str("[REDACTED]");
        copied = span.end;
    }
    output.push_str(&input[copied..]);
    std::borrow::Cow::Owned(output)
}

/// Nonoverlapping code-policy matches for the expanded LOG-REDACT catalog.
pub fn code_credential_matches(input: &[u8]) -> Vec<CredentialMatch> {
    matches(input, true)
}

/// The original staged-check catalog, preserving report order and coverage.
pub fn staged_code_patterns() -> &'static [CredentialPattern] {
    &CREDENTIAL_PATTERNS[..9]
}

/// Historical staged-check policy, including independent family findings.
pub fn staged_code_credential_matches(input: &[u8]) -> Vec<CredentialMatch> {
    // Scan each family independently, as staged checks historically did. A
    // permissive outer shape must not hide another family's code finding.
    let mut found = Vec::new();
    for pattern in staged_code_patterns() {
        let prefix = pattern.prefix.as_bytes();
        let mut run_end = 0;
        let mut last_key_byte = None;
        for start in 0..input.len() {
            if (start > 0 && input[start - 1].is_ascii_alphanumeric())
                || !input[start..].starts_with(prefix)
            {
                continue;
            }
            let tail_start = start + prefix.len();
            // Nested prefixes can share one long tail. Cache its endpoint and
            // last non-identifier byte instead of rescanning every suffix.
            if tail_start > run_end {
                run_end = tail_start;
                last_key_byte = None;
                while run_end < input.len() && tail_byte(pattern, input[run_end]) {
                    if input[run_end].is_ascii_digit() || input[run_end].is_ascii_uppercase() {
                        last_key_byte = Some(run_end);
                    }
                    run_end += 1;
                }
            }
            let len = run_end - tail_start;
            if len >= pattern.min_tail && last_key_byte.is_some_and(|index| index >= tail_start) {
                found.push(CredentialMatch {
                    pattern,
                    span: start..tail_start + len,
                });
            }
        }
    }
    found
}
