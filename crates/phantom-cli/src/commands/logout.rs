use anyhow::Result;
use colored::Colorize;
use phantom_core::auth;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, IsTerminal, Write};

pub fn run() -> Result<()> {
    require_logout_terminals()?;
    let plan = LogoutPlan {
        operation: "delete-persistent-phantom-cloud-auth",
        storage: "os-keychain",
        consequence: "future cloud and team operations require a new login",
    };
    require_trusted_terminal_logout(&plan)?;
    auth::clear_token()?;
    println!("{}  Logged out", "ok".green().bold());
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LogoutPlan {
    operation: &'static str,
    storage: &'static str,
    consequence: &'static str,
}

fn require_logout_terminals() -> Result<()> {
    validate_logout_terminals(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn validate_logout_terminals(stdin: bool, stdout: bool, stderr: bool) -> Result<()> {
    if !stdin || !stdout || !stderr {
        anyhow::bail!(
            "`phantom logout` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. The OS keychain was not read or changed."
        );
    }
    Ok(())
}

fn require_trusted_terminal_logout(plan: &LogoutPlan) -> Result<()> {
    let nonce = fresh_confirmation_nonce();
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    prompt_logout(plan, &nonce, &mut reader, &mut stdout, &mut stderr)
}

fn fresh_confirmation_nonce() -> String {
    let mut nonce_bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    hex::encode(nonce_bytes)
}

fn prompt_logout(
    plan: &LogoutPlan,
    nonce: &str,
    reader: &mut dyn BufRead,
    prompt: &mut dyn Write,
    diagnostic: &mut dyn Write,
) -> Result<()> {
    let plan_json = serde_json::to_string_pretty(plan)?;
    let digest = hex::encode(Sha256::digest(plan_json.as_bytes()));
    let expected = format!("logout {nonce} {digest}");
    writeln!(
        diagnostic,
        "Logging out deletes persistent Phantom cloud authorization from the OS keychain. Terminal attachment does not prove that an AI agent is absent; continue only from a terminal you exclusively control.\nExact logout plan:\n{plan_json}\nType this exact challenge to continue:\n{expected}"
    )?;
    write!(prompt, "> ")?;
    prompt.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!("Logout cancelled: the fresh exact challenge did not match");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> LogoutPlan {
        LogoutPlan {
            operation: "delete-persistent-phantom-cloud-auth",
            storage: "os-keychain",
            consequence: "future cloud and team operations require a new login",
        }
    }

    fn challenge(plan: &LogoutPlan, nonce: &str) -> String {
        let json = serde_json::to_string_pretty(plan).unwrap();
        let digest = hex::encode(Sha256::digest(json.as_bytes()));
        format!("logout {nonce} {digest}")
    }

    #[test]
    fn headless_logout_is_rejected_before_keychain_authority() {
        for attached in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let error = validate_logout_terminals(attached.0, attached.1, attached.2).unwrap_err();
            assert!(error
                .to_string()
                .contains("keychain was not read or changed"));
        }

        let source = include_str!("logout.rs");
        assert!(
            source.find("require_logout_terminals()?").unwrap()
                < source.find("auth::clear_token()?").unwrap()
        );
        assert!(
            source
                .find("require_trusted_terminal_logout(&plan)?")
                .unwrap()
                < source.find("auth::clear_token()?").unwrap()
        );
    }

    #[test]
    fn exact_logout_challenge_allows_reviewed_plan_only() {
        let plan = plan();
        let nonce = fresh_confirmation_nonce();
        let input = format!("{}\n", challenge(&plan, &nonce));
        let mut reader = std::io::Cursor::new(input);
        let mut prompt = Vec::new();
        let mut diagnostic = Vec::new();

        prompt_logout(&plan, &nonce, &mut reader, &mut prompt, &mut diagnostic).unwrap();

        let shown = String::from_utf8(diagnostic).unwrap();
        assert!(shown.contains("delete-persistent-phantom-cloud-auth"));
        assert!(shown.contains(&challenge(&plan, &nonce)));
    }

    #[test]
    fn changed_logout_plan_invalidates_challenge() {
        let reviewed = plan();
        let changed = LogoutPlan {
            consequence: "different consequence",
            ..plan()
        };
        let nonce = fresh_confirmation_nonce();
        let input = format!("{}\n", challenge(&reviewed, &nonce));
        let mut reader = std::io::Cursor::new(input);

        assert!(prompt_logout(
            &changed,
            &nonce,
            &mut reader,
            &mut Vec::new(),
            &mut Vec::new()
        )
        .is_err());
    }
}
