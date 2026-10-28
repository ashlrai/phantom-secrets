use phantom_core::redact::{
    code_credential_matches, credential_spans, known_value_prefix, redact_text,
    response::FORMAT_SPECS, staged_code_credential_matches, staged_code_patterns,
    CREDENTIAL_PATTERNS,
};
use std::borrow::Cow;

#[path = "support/redact_corpus.rs"]
mod corpus;

#[test]
fn golden_corpus_covers_every_published_shape() {
    let code = corpus::code_families();
    assert_eq!(code.len(), CREDENTIAL_PATTERNS.len());
    for pattern in CREDENTIAL_PATTERNS {
        assert!(code.iter().any(|case| case.prefix == pattern.prefix));
    }
    let response = corpus::families();
    assert_eq!(response.len(), FORMAT_SPECS.len());
    for spec in FORMAT_SPECS {
        assert!(response.iter().any(|case| case.label == spec.label));
    }
}

#[test]
fn golden_code_matches_report_only_metadata_and_byte_offsets() {
    for case in corpus::code_families() {
        let input = format!("π '{}'!", case.token);
        let found = code_credential_matches(input.as_bytes());
        if case.prefix == "Bearer " {
            assert!(found.is_empty());
            continue;
        }
        assert_eq!(found.len(), 1, "{}", case.label);
        assert_eq!(found[0].pattern.prefix, case.prefix);
        assert_eq!(found[0].pattern.label, case.label);
        assert_eq!(found[0].span, 4..4 + case.token.len());
        assert!(!format!("{:?}", found[0]).contains(&case.token));
        // Assert the specific family's threshold: shorter Stripe forms can
        // intentionally match the separate generic sk_ family.
        assert!(!code_credential_matches(case.incomplete.as_bytes())
            .iter()
            .any(|found| found.pattern.prefix == case.prefix));
    }
}

#[test]
fn golden_response_grammar_preserves_complete_and_incomplete_contract() {
    for case in corpus::families() {
        let spec = FORMAT_SPECS
            .iter()
            .find(|spec| spec.label == case.label)
            .unwrap();
        assert_eq!(spec.is_unbounded(), case.unbounded);
        assert_eq!(
            spec.complete_prefix_len(case.token.as_bytes()),
            Some(case.token.len())
        );
        assert_eq!(spec.complete_prefix_len(case.incomplete.as_bytes()), None);
        assert!(spec.is_incomplete_prefix(case.incomplete.as_bytes()));
        for end in 1..spec.minimum_match_len() {
            assert!(
                spec.is_incomplete_prefix(&case.token.as_bytes()[..end]),
                "{} offset {end}",
                case.label
            );
        }
        let input = format!("x{}!{}", case.token, case.token);
        let spans = spec.match_ranges(input.as_bytes());
        assert_eq!(spans.len(), 2, "{}", case.label);
        assert_eq!(spans[0], 1..1 + case.token.len());
        assert_eq!(spans[1], 2 + case.token.len()..2 + 2 * case.token.len());
        // Log/report output must retain the response policy even when embedded.
        assert_eq!(credential_spans(input.as_bytes()), spans, "{}", case.label);
    }
}

#[test]
fn golden_log_spans_cover_every_shape_and_preserve_non_utf8_offsets() {
    for (index, token) in corpus::all_tokens().iter().enumerate() {
        let mut input = vec![0xff, b'"'];
        input.extend_from_slice(token.as_bytes());
        input.extend_from_slice(&[b'"', 0xfe]);
        let spans = credential_spans(&input);
        assert_eq!(spans.len(), 1, "case {index}");
        assert_eq!(spans[0], 2..2 + token.len(), "case {index}");
        let text = format!("π '{token}' 終");
        assert!(redact_text(&text) == "π '[REDACTED]' 終", "case {index}");
    }
}

#[test]
fn code_false_positive_rules_do_not_exempt_log_credentials() {
    let lower = format!("{}{}", "sk-", "q".repeat(30));
    assert!(code_credential_matches(lower.as_bytes()).is_empty());
    let spans = credential_spans(lower.as_bytes());
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0], 0..lower.len());
    let embedded = format!("task-{}", "Q".repeat(30));
    assert!(code_credential_matches(embedded.as_bytes()).is_empty());
    let spans = credential_spans(embedded.as_bytes());
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0], 2..embedded.len());
    for ordinary in ["task", "risk", "desk", "sk-short", "hello 世界", ""] {
        assert!(code_credential_matches(ordinary.as_bytes()).is_empty());
        assert!(credential_spans(ordinary.as_bytes()).is_empty());
        assert!(matches!(redact_text(ordinary), Cow::Borrowed(_)));
    }
}

#[test]
fn merged_spans_cover_overlapping_and_adjacent_shapes_once() {
    let token = corpus::litellm();
    let bearer = format!("Bearer {token}");
    let spans = credential_spans(bearer.as_bytes());
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0], 0..bearer.len());
    let fixed = corpus::families()
        .into_iter()
        .find(|case| case.label == "phm_*")
        .unwrap()
        .token;
    let adjacent = format!("{fixed}{fixed}");
    let spans = credential_spans(adjacent.as_bytes());
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0], 0..adjacent.len());
    let separate = format!("{token}\n{fixed}");
    assert_eq!(
        credential_spans(separate.as_bytes()),
        [0..token.len(), token.len() + 1..separate.len()]
    );
    assert!(redact_text(&separate) == "[REDACTED]\n[REDACTED]");
}

#[test]
fn charset_and_sendgrid_separator_mismatches_are_rejected() {
    for (label, bad) in [
        ("AKIA*", format!("AKIA{}", "a".repeat(16))),
        ("AC*", format!("AC{}", "G".repeat(32))),
        ("phm_*", format!("phm_{}", "G".repeat(64))),
        ("SG.*", format!("SG.{}!{}", "A".repeat(22), "B".repeat(43))),
        ("SG.*", format!("SG.{}.{}", "A".repeat(21), "B".repeat(43))),
    ] {
        let spec = FORMAT_SPECS
            .iter()
            .find(|spec| spec.label == label)
            .unwrap();
        assert!(
            spec.complete_prefix_len(bad.as_bytes()).is_none(),
            "{label}"
        );
        assert!(!spec.is_incomplete_prefix(bad.as_bytes()), "{label}");
    }
}

#[test]
fn dotenv_compatibility_keeps_existing_bare_prefixes_but_bounds_new_aws_shape() {
    assert_eq!(known_value_prefix("sk-short"), Some("sk-"));
    assert_eq!(known_value_prefix("sk_live_short"), Some("sk_"));
    for value in ["ASIA", "ASIA-region", "ASIAabcdefghijklmnop"] {
        assert_eq!(known_value_prefix(value), None);
    }
    let aws = corpus::code_families()
        .into_iter()
        .find(|case| case.prefix == "ASIA")
        .unwrap();
    assert_eq!(known_value_prefix(&aws.token), Some("ASIA"));
}

#[test]
fn log_redact_compatibility_facade_uses_the_same_detector() {
    for token in corpus::all_tokens() {
        assert_eq!(
            phantom_core::secret_detector::credential_spans(token.as_bytes()),
            credential_spans(token.as_bytes())
        );
    }
}

#[test]
fn staged_scan_preserves_independent_nested_family_findings() {
    let github = corpus::code_families()
        .into_iter()
        .find(|case| case.prefix == "ghp_")
        .unwrap();
    let outer_prefix = "glpat-";
    let input = format!("{outer_prefix}{}", github.token);
    let found = staged_code_credential_matches(input.as_bytes());
    assert_eq!(found.len(), 2);
    // Findings retain the historical family order, not byte-offset order.
    assert_eq!(found[0].pattern.prefix, "ghp_");
    assert_eq!(found[0].span, outer_prefix.len()..input.len());
    assert_eq!(found[1].pattern.prefix, outer_prefix);
    assert_eq!(found[1].span, 0..input.len());
    assert_eq!(staged_code_patterns().len(), 9);

    // LOG-REDACT's public compatibility API intentionally reports one outer
    // match. Changing staged behavior must not change that separate contract.
    let log_code = code_credential_matches(input.as_bytes());
    assert_eq!(log_code.len(), 1);
    assert_eq!(log_code[0].pattern.prefix, outer_prefix);
}

#[test]
fn staged_nested_identifier_tails_do_not_inherit_an_outer_key_byte() {
    let prefix = "glpat-";
    let first = format!("{prefix}Z0_{prefix}{}", "a".repeat(24));
    let second = format!("{prefix}{}", "a".repeat(24));
    let third = format!("{prefix}{}", "Q".repeat(20));
    let input = format!("{first}!{second}!{third}");
    let found = staged_code_credential_matches(input.as_bytes());
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|found| found.pattern.prefix == prefix));
    assert_eq!(found[0].span, 0..first.len());
    let third_start = first.len() + second.len() + 2;
    assert_eq!(found[1].span, third_start..input.len());
}

#[test]
fn staged_large_repeated_prefix_run_retains_every_nested_match() {
    // This exercises a long shared tail without a platform-dependent deadline.
    // Rescanning every suffix would do quadratic work; the detector reuses the
    // maximal tail endpoint while preserving each independent finding.
    let prefix = "glpat-";
    let repetitions = 32_768;
    let input = format!("{}{}", prefix.repeat(repetitions), "Q".repeat(20));
    let found = staged_code_credential_matches(input.as_bytes());
    assert_eq!(found.len(), repetitions);
    for (index, found) in found.iter().enumerate() {
        assert_eq!(found.pattern.prefix, prefix);
        assert_eq!(found.span, index * prefix.len()..input.len());
    }
}
