//! Independent runtime-built fake credentials. Never derive expected cases from production tables.
#![allow(dead_code)]

#[derive(Clone)]
pub struct Family {
    pub label: &'static str,
    pub token: String,
    pub incomplete: String,
    pub unbounded: bool,
}

pub fn families() -> Vec<Family> {
    vec![
        Family {
            label: "sk_*",
            token: format!("sk-{}", "A".repeat(28)),
            incomplete: format!("sk-{}", "A".repeat(19)),
            unbounded: true,
        },
        Family {
            label: "sk_live_*",
            token: format!("sk_live_{}", "B".repeat(28)),
            incomplete: format!("sk_live_{}", "B".repeat(19)),
            unbounded: true,
        },
        Family {
            label: "sk_test_*",
            token: format!("sk_test_{}", "C".repeat(28)),
            incomplete: format!("sk_test_{}", "C".repeat(19)),
            unbounded: true,
        },
        Family {
            label: "ghp_*",
            token: format!("ghp_{}", "D".repeat(44)),
            incomplete: format!("ghp_{}", "D".repeat(35)),
            unbounded: true,
        },
        Family {
            label: "github_pat_*",
            token: format!("github_pat_{}", "E".repeat(88)),
            incomplete: format!("github_pat_{}", "E".repeat(79)),
            unbounded: true,
        },
        Family {
            label: "AKIA*",
            token: format!("AKIA{}", "F".repeat(16)),
            incomplete: format!("AKIA{}", "F".repeat(15)),
            unbounded: false,
        },
        Family {
            label: "AIza*",
            token: format!("AIza{}", "G".repeat(35)),
            incomplete: format!("AIza{}", "G".repeat(34)),
            unbounded: false,
        },
        Family {
            label: "xoxb-*",
            token: format!("xoxb-{}", "H".repeat(48)),
            incomplete: format!("xoxb-{}", "H".repeat(39)),
            unbounded: true,
        },
        Family {
            label: "xoxp-*",
            token: format!("xoxp-{}", "J".repeat(48)),
            incomplete: format!("xoxp-{}", "J".repeat(39)),
            unbounded: true,
        },
        Family {
            label: "SG.*",
            token: format!("SG.{}.{}", "K".repeat(22), "L".repeat(43)),
            incomplete: format!("SG.{}.{}", "K".repeat(22), "L".repeat(42)),
            unbounded: false,
        },
        Family {
            label: "AC*",
            token: format!("AC{}", "a".repeat(32)),
            incomplete: format!("AC{}", "a".repeat(31)),
            unbounded: false,
        },
        Family {
            label: "phm_*",
            token: format!("phm_{}", "b".repeat(64)),
            incomplete: format!("phm_{}", "b".repeat(63)),
            unbounded: false,
        },
    ]
}

/// Code/log fixtures deliberately use their own thresholds, independently of
/// response thresholds. No Debug implementation can accidentally print a value.
pub struct CodeFamily {
    pub prefix: &'static str,
    pub label: &'static str,
    pub token: String,
    pub incomplete: String,
    pub staged: bool,
}

pub fn code_families() -> Vec<CodeFamily> {
    [
        ("sk-", "OpenAI API key", 20, true),
        ("sk_live_", "Stripe live key", 16, true),
        ("sk_test_", "Stripe test key", 16, true),
        ("ghp_", "GitHub personal token", 30, true),
        ("github_pat_", "GitHub PAT", 30, true),
        ("glpat-", "GitLab PAT", 20, true),
        ("xoxb-", "Slack bot token", 20, true),
        ("xoxp-", "Slack user token", 20, true),
        ("AKIA", "AWS access key", 16, true),
        ("xapp-", "Slack app token", 20, false),
        ("xoxa-", "Slack app token", 20, false),
        ("xoxs-", "Slack session token", 20, false),
        ("xoxr-", "Slack refresh token", 20, false),
        ("gho_", "GitHub OAuth token", 30, false),
        ("ghu_", "GitHub user token", 30, false),
        ("ghs_", "GitHub installation token", 30, false),
        ("ghr_", "GitHub refresh token", 30, false),
        ("ASIA", "AWS temporary access key", 16, false),
        ("sk_", "Secret API key", 16, false),
        ("pk_", "Publishable API key", 16, false),
        ("rk_", "Restricted API key", 16, false),
        ("whsec_", "Webhook signing secret", 16, false),
        ("shpat_", "Shopify access token", 16, false),
        ("Bearer ", "Bearer credential", 1, false),
    ]
    .into_iter()
    .map(|(prefix, label, length, staged)| CodeFamily {
        prefix,
        label,
        token: format!("{prefix}{}", "Z".repeat(length)),
        incomplete: format!("{prefix}{}", "Z".repeat(length - 1)),
        staged,
    })
    .collect()
}

pub fn litellm() -> String {
    format!("{}{}", "sk-", "Q7".repeat(11))
}

/// Every supported family, including the shorter code/log thresholds.
pub fn all_tokens() -> Vec<String> {
    families()
        .into_iter()
        .map(|case| case.token)
        .chain(code_families().into_iter().map(|case| case.token))
        .chain(std::iter::once(litellm()))
        .collect()
}
