use anyhow::{Context, Result};
use colored::Colorize;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, IsTerminal, Write};

/// Resolve a friendly target through the closed, reviewed browser catalog.
fn resolve_target(target: &str) -> Result<&'static str> {
    if target.chars().any(char::is_control) {
        anyhow::bail!("Browser target contains control characters");
    }
    match target {
        // Default — most common reason to run `phantom open`.
        "" | "dashboard" => Ok("https://phm.dev/dashboard"),
        "billing" => Ok("https://phm.dev/dashboard/billing"),
        "team" | "teams" => Ok("https://phm.dev/dashboard/team"),
        "docs" => Ok("https://phm.dev/docs"),
        "pricing" => Ok("https://phm.dev/pricing"),
        "github" | "repo" => Ok("https://github.com/ashlrai/phantom-secrets"),
        "issues" => Ok("https://github.com/ashlrai/phantom-secrets/issues"),
        "site" | "home" => Ok("https://phm.dev"),
        other if other.contains("://") || other.contains('@') || other.starts_with('/') => {
            anyhow::bail!(
                "Arbitrary URLs, credentials, schemes, and paths are not accepted by `phantom open`; use a reviewed alias"
            )
        }
        _ => anyhow::bail!(
            "Unknown browser alias. Use one of: dashboard, billing, team, docs, pricing, github, issues, site"
        ),
    }
}

pub fn run(target: &str) -> Result<()> {
    let url = resolve_target(target)?;
    require_open_terminals()?;
    let plan = OpenPlan {
        operation: "open-reviewed-external-browser-page",
        requested_alias: if target.is_empty() {
            "dashboard"
        } else {
            target
        },
        normalized_https_destination: url,
        ambient_auth_context_may_be_sent: true,
    };
    require_trusted_terminal_open(&plan)?;
    open::that(url).with_context(|| format!("Failed to open browser for {url}"))?;
    println!("{}  Opened {}", "ok".green().bold(), url);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct OpenPlan<'a> {
    operation: &'static str,
    requested_alias: &'a str,
    normalized_https_destination: &'static str,
    ambient_auth_context_may_be_sent: bool,
}

fn require_open_terminals() -> Result<()> {
    validate_open_terminals(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn validate_open_terminals(stdin: bool, stdout: bool, stderr: bool) -> Result<()> {
    if !stdin || !stdout || !stderr {
        anyhow::bail!(
            "`phantom open` requires attached stdin, stdout, and stderr terminals and cannot launch a browser headlessly. No browser process was started."
        );
    }
    Ok(())
}

fn require_trusted_terminal_open(plan: &OpenPlan<'_>) -> Result<()> {
    let mut nonce_bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    prompt_open(plan, &nonce, &mut reader, &mut stdout, &mut stderr)
}

fn prompt_open(
    plan: &OpenPlan<'_>,
    nonce: &str,
    reader: &mut dyn BufRead,
    prompt: &mut dyn Write,
    diagnostic: &mut dyn Write,
) -> Result<()> {
    let plan_json = serde_json::to_string_pretty(plan)?;
    let digest = hex::encode(Sha256::digest(plan_json.as_bytes()));
    let expected = format!("open {nonce} {digest}");
    writeln!(
        diagnostic,
        "Opening an external page can send ambient browser authentication to its exact HTTPS origin. Terminal attachment does not prove that an AI agent is absent; continue only from a terminal you exclusively control.\nExact browser plan:\n{plan_json}\nType this exact challenge to continue:\n{expected}"
    )?;
    write!(prompt, "> ")?;
    prompt.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!("Browser open cancelled: the fresh exact challenge did not match");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_target_defaults_to_dashboard() {
        assert_eq!(resolve_target("").unwrap(), "https://phm.dev/dashboard");
        assert_eq!(
            resolve_target("dashboard").unwrap(),
            "https://phm.dev/dashboard"
        );
    }

    #[test]
    fn known_aliases_resolve() {
        assert_eq!(
            resolve_target("billing").unwrap(),
            "https://phm.dev/dashboard/billing"
        );
        assert_eq!(
            resolve_target("team").unwrap(),
            "https://phm.dev/dashboard/team"
        );
        assert_eq!(
            resolve_target("teams").unwrap(),
            "https://phm.dev/dashboard/team"
        );
        assert_eq!(resolve_target("docs").unwrap(), "https://phm.dev/docs");
        assert_eq!(
            resolve_target("pricing").unwrap(),
            "https://phm.dev/pricing"
        );
        assert_eq!(
            resolve_target("github").unwrap(),
            "https://github.com/ashlrai/phantom-secrets"
        );
        assert_eq!(
            resolve_target("issues").unwrap(),
            "https://github.com/ashlrai/phantom-secrets/issues"
        );
        assert_eq!(resolve_target("site").unwrap(), "https://phm.dev");
    }

    #[test]
    fn arbitrary_urls_and_injection_forms_are_rejected() {
        for target in [
            "https://example.com/foo",
            "http://localhost:3000",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user@example.com",
            "/changelog",
            "docs\nhttps://evil.invalid",
            "blog",
        ] {
            assert!(resolve_target(target).is_err(), "accepted {target:?}");
        }
    }

    #[test]
    fn headless_open_is_rejected_before_browser_launch() {
        for attached in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let error = validate_open_terminals(attached.0, attached.1, attached.2).unwrap_err();
            assert!(error.to_string().contains("No browser process was started"));
        }
        let source = include_str!("open.rs");
        assert!(
            source.find("require_open_terminals()?").unwrap()
                < source.find("open::that(url)").unwrap()
        );
        assert!(
            source
                .find("require_trusted_terminal_open(&plan)?")
                .unwrap()
                < source.find("open::that(url)").unwrap()
        );
    }

    #[test]
    fn destination_change_invalidates_exact_browser_challenge() {
        let reviewed = OpenPlan {
            operation: "open-reviewed-external-browser-page",
            requested_alias: "docs",
            normalized_https_destination: "https://phm.dev/docs",
            ambient_auth_context_may_be_sent: true,
        };
        let changed = OpenPlan {
            requested_alias: "github",
            normalized_https_destination: "https://github.com/ashlrai/phantom-secrets",
            ..reviewed.clone()
        };
        let nonce = "0011223344556677";
        let reviewed_json = serde_json::to_string_pretty(&reviewed).unwrap();
        let expected = format!(
            "open {nonce} {}",
            hex::encode(Sha256::digest(reviewed_json.as_bytes()))
        );
        let mut reader = std::io::Cursor::new(format!("{expected}\n"));

        assert!(prompt_open(
            &changed,
            nonce,
            &mut reader,
            &mut Vec::new(),
            &mut Vec::new()
        )
        .is_err());
    }
}
