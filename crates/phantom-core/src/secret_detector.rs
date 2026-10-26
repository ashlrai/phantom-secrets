//! Shared provider credential shapes for dotenv classification, code checks, and log redaction.
//!
//! Dotenv classification keeps historical bare-prefix rules: it protects those values
//! even when they are short or malformed. Code checks apply historical false-positive
//! filters; log redaction retains the length/boundary checks but also scrubs lowercase
//! tails because an issued credential must not be exposed merely for resembling prose.

use std::ops::Range;

/// Fixed, value-free metadata for a provider credential shape.
#[derive(Debug)]
pub struct CredentialPattern {
    pub prefix: &'static str,
    pub label: &'static str,
    pub min_tail: usize,
    upper_alnum_only: bool,
}

/// More specific prefixes precede their general forms to avoid overlapping findings.
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

fn matches(input: &[u8], code: bool) -> Vec<CredentialMatch> {
    let mut found = Vec::new();
    let mut start = 0;
    while start < input.len() {
        if start > 0 && input[start - 1].is_ascii_alphanumeric() {
            start += 1;
            continue;
        }
        let mut next = start + 1;
        for pattern in CREDENTIAL_PATTERNS {
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
    matches(input, false)
        .into_iter()
        .map(|found| found.span)
        .collect()
}

/// Credential matches using the staged-code false-positive policy.
pub fn code_credential_matches(input: &[u8]) -> Vec<CredentialMatch> {
    matches(input, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_temporary_prefix_requires_a_key_shaped_tail_in_dotenv() {
        let positive = format!("{}{}", "ASIA", "FAKE".repeat(4));
        assert_eq!(known_value_prefix(&positive), Some("ASIA"));
        for value in ["ASIA", "ASIA-region", "ASIAEXAMPLE", "ASIAabcdefghijklmnop"] {
            assert_eq!(known_value_prefix(value), None);
        }
        // The established AWS permanent-key classifier remains conservative.
        assert_eq!(known_value_prefix("AKIA"), Some("AKIA"));
    }

    #[test]
    fn every_shape_has_positive_and_negative_fixtures() {
        for pattern in CREDENTIAL_PATTERNS {
            let tail = "FAKE0".repeat(pattern.min_tail.div_ceil(5));
            let positive = format!("credential={}{};", pattern.prefix, tail);
            let spans = credential_spans(positive.as_bytes());
            assert_eq!(spans.len(), 1, "shape {}", pattern.prefix);
            assert_eq!(spans[0], 11..positive.len() - 1, "shape {}", pattern.prefix);
            // The broad sk_ detector also counts live_/test_ toward its tail.
            // Choose a negative shorter than both accepted shapes.
            let short_tail = if matches!(pattern.prefix, "sk_live_" | "sk_test_") {
                10
            } else {
                pattern.min_tail - 1
            };
            let negative = format!("credential={}{};", pattern.prefix, "0".repeat(short_tail));
            assert!(
                credential_spans(negative.as_bytes()).is_empty(),
                "short shape {}",
                pattern.prefix
            );
            let embedded = format!("word{}{}", pattern.prefix, tail);
            assert!(
                credential_spans(embedded.as_bytes()).is_empty(),
                "embedded shape {}",
                pattern.prefix
            );
        }
    }

    #[test]
    fn redaction_is_conservative_for_lowercase_credentials() {
        let input = format!("{}{}", "ghp_", "a".repeat(36));
        let spans = credential_spans(input.as_bytes());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0], 0..input.len());
        assert!(code_credential_matches(input.as_bytes()).is_empty());
    }

    #[test]
    fn specific_shapes_do_not_produce_overlapping_matches() {
        let input = format!("{}{}", "sk_live_", "FAKE0".repeat(5));
        let found = code_credential_matches(input.as_bytes());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pattern.prefix, "sk_live_");
        assert_eq!(known_value_prefix(&input), Some("sk_"));
    }

    #[test]
    fn invalid_utf8_and_punctuation_do_not_hide_tokens() {
        let token = format!("{}{}", "xapp-", "FAKE0".repeat(5));
        let mut input = vec![0xff, b'"'];
        input.extend_from_slice(token.as_bytes());
        input.extend_from_slice(b"\", done");
        let spans = credential_spans(&input);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0], 2..2 + token.len());
    }
}
