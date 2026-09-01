use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use phantom_core::auth;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

pub fn run() -> Result<()> {
    require_login_terminals()?;
    let api_base = auth::api_base_url()?;
    validate_api_base(&api_base)?;
    let authority_plan = LoginAuthorityPlan {
        operation: "phantom-cloud-device-login",
        canonical_api_base: &api_base,
        verification_destination_policy: "exactly https://phm.dev/device",
        browser_effect: "open one externally controlled HTTPS browser page",
        persistent_effect: "store approved bearer in the OS keychain",
        poll_policy: "server interval 1..=30s, clamped to at least 5s",
        timeout_policy: "server expiry 60..=900s; bounded attempts derived from expiry/interval",
    };
    require_trusted_terminal_login(&authority_plan, "authorize-login-network")?;

    // Check if already logged in
    if let Some(token) = auth::load_token() {
        let rt = tokio::runtime::Runtime::new()?;
        match rt.block_on(auth::get_user_info(&api_base, &token)) {
            Ok(user) => {
                println!(
                    "{}  Already logged in as @{} ({})",
                    "ok".green().bold(),
                    safe_display_field(&user.github_login),
                    safe_display_field(&user.plan)
                );
                return Ok(());
            }
            Err(_) => {
                // Token invalid, proceed with new login
            }
        }
    }

    let rt = tokio::runtime::Runtime::new()?;

    // Initiate device flow
    let flow = rt
        .block_on(auth::initiate_device_flow(&api_base))
        .map_err(|_| anyhow::anyhow!("Failed to start the Phantom login flow"))?;
    let schedule = validate_device_flow(&flow)?;
    let browser_plan = LoginBrowserPlan {
        operation: "open-device-verification-and-poll",
        canonical_api_base: &api_base,
        normalized_https_destination: &flow.verification_uri,
        ambient_auth_context_may_be_sent: true,
        poll_interval_seconds: schedule.poll_interval.as_secs(),
        maximum_poll_attempts: schedule.max_attempts,
        maximum_timeout_seconds: schedule.timeout_seconds,
        persistent_effect: "store an approved bearer in the OS keychain",
    };
    require_trusted_terminal_login(&browser_plan, "open-and-poll")?;

    // Open browser
    println!(
        "{}  Open {} and enter code:",
        "->".blue().bold(),
        flow.verification_uri.bold()
    );
    println!();
    println!("   {}", flow.user_code.bold().cyan());
    println!();

    if open::that(&flow.verification_uri).is_err() {
        println!(
            "{}  Could not open browser automatically.",
            "warn".yellow().bold()
        );
        println!(
            "   Open this URL manually: {}",
            flow.verification_uri.underline()
        );
    }

    // Poll with spinner
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    spinner.set_message("Waiting for approval...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    for _ in 0..schedule.max_attempts {
        std::thread::sleep(schedule.poll_interval);

        match rt.block_on(auth::poll_for_token(&api_base, &flow.device_code)) {
            Ok(poll) => match poll.status.as_str() {
                "approved" => {
                    spinner.finish_and_clear();

                    let token = poll.access_token.ok_or_else(|| {
                        anyhow::anyhow!(
                            "Login approval did not include a bearer; nothing was stored"
                        )
                    })?;
                    auth::store_token(&token)
                        .context("Failed to persist login authorization in the OS keychain")?;

                    let user = poll.user.unwrap_or(auth::UserInfo {
                        email: None,
                        github_login: "unknown".to_string(),
                        plan: "free".to_string(),
                        vaults_count: None,
                    });

                    println!(
                        "{}  Logged in as @{} ({})",
                        "ok".green().bold(),
                        safe_display_field(&user.github_login),
                        safe_display_field(&user.plan)
                    );
                    return Ok(());
                }
                "expired" => {
                    spinner.finish_and_clear();
                    anyhow::bail!("Login expired. Run `phantom login` to try again.");
                }
                "already_claimed" => {
                    spinner.finish_and_clear();
                    anyhow::bail!("This device code was already used. Run `phantom login` again.");
                }
                "pending" => continue,
                _ => {
                    spinner.finish_and_clear();
                    anyhow::bail!("Login provider returned an unexpected value-free status");
                }
            },
            Err(_) => {
                spinner.finish_and_clear();
                anyhow::bail!("Login polling failed; no authorization was stored");
            }
        }
    }

    spinner.finish_and_clear();
    anyhow::bail!(
        "Login timed out. Run `phantom login` to try again.\n  {}",
        crate::util::docs_url("login")
    )
}

#[derive(Debug, Serialize)]
struct LoginAuthorityPlan<'a> {
    operation: &'static str,
    canonical_api_base: &'a str,
    verification_destination_policy: &'static str,
    browser_effect: &'static str,
    persistent_effect: &'static str,
    poll_policy: &'static str,
    timeout_policy: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LoginBrowserPlan<'a> {
    operation: &'static str,
    canonical_api_base: &'a str,
    normalized_https_destination: &'a str,
    ambient_auth_context_may_be_sent: bool,
    poll_interval_seconds: u64,
    maximum_poll_attempts: usize,
    maximum_timeout_seconds: u64,
    persistent_effect: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PollSchedule {
    poll_interval: Duration,
    max_attempts: usize,
    timeout_seconds: u64,
}

fn require_login_terminals() -> Result<()> {
    validate_login_terminals(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn validate_login_terminals(stdin: bool, stdout: bool, stderr: bool) -> Result<()> {
    if !stdin || !stdout || !stderr {
        anyhow::bail!(
            "`phantom login` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No keychain token was read, no network request was sent, and no browser process was started."
        );
    }
    Ok(())
}

fn validate_api_base(api_base: &str) -> Result<()> {
    if api_base != "https://phm.dev/api/v1" {
        anyhow::bail!(
            "Refusing non-canonical Phantom Cloud API endpoint; production login is restricted to https://phm.dev"
        );
    }
    Ok(())
}

fn validate_device_flow(flow: &auth::DeviceFlowResponse) -> Result<PollSchedule> {
    if flow.verification_uri != "https://phm.dev/device" {
        anyhow::bail!(
            "Login provider returned a verification destination outside the exact https://phm.dev/device policy"
        );
    }
    if flow.interval == 0 || flow.interval > 30 {
        anyhow::bail!("Login provider returned an unsafe polling interval");
    }
    if !(60..=900).contains(&flow.expires_in) {
        anyhow::bail!("Login provider returned an unsafe device-flow expiry");
    }
    if flow.device_code.is_empty()
        || flow.device_code.len() > 128
        || !flow
            .device_code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        anyhow::bail!("Login provider returned an invalid opaque device identifier");
    }
    let user_code = flow.user_code.as_bytes();
    if user_code.len() != 9
        || user_code[4] != b'-'
        || !user_code
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        anyhow::bail!("Login provider returned an invalid one-time user code");
    }
    let interval = flow.interval.max(5);
    let max_attempts = (flow.expires_in / interval) as usize;
    if max_attempts == 0 || max_attempts > 180 {
        anyhow::bail!("Login provider returned an unsafe polling schedule");
    }
    Ok(PollSchedule {
        poll_interval: Duration::from_secs(interval),
        max_attempts,
        timeout_seconds: interval.saturating_mul(max_attempts as u64),
    })
}

fn require_trusted_terminal_login(plan: &impl Serialize, phase: &str) -> Result<()> {
    let mut nonce_bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    prompt_login(plan, phase, &nonce, &mut reader, &mut stdout, &mut stderr)
}

fn prompt_login(
    plan: &impl Serialize,
    phase: &str,
    nonce: &str,
    reader: &mut dyn BufRead,
    prompt: &mut dyn Write,
    diagnostic: &mut dyn Write,
) -> Result<()> {
    let plan_json = serde_json::to_string_pretty(plan)?;
    let digest = hex::encode(Sha256::digest(plan_json.as_bytes()));
    let expected = format!("login {phase} {nonce} {digest}");
    writeln!(
        diagnostic,
        "Phantom login opens an external verification page, polls Phantom Cloud, and can persist an approved bearer in the OS keychain. Terminal attachment does not prove that an AI agent is absent; continue only from a terminal you exclusively control.\nExact login plan:\n{plan_json}\nType this exact challenge to continue:\n{expected}"
    )?;
    write!(prompt, "> ")?;
    prompt.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim_end_matches(['\r', '\n']) != expected {
        anyhow::bail!("Login cancelled: the fresh exact challenge did not match");
    }
    Ok(())
}

fn safe_display_field(value: &str) -> &str {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        value
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(uri: &str) -> auth::DeviceFlowResponse {
        auth::DeviceFlowResponse {
            device_code: "00000000-0000-4000-8000-000000000000".to_string(),
            user_code: "ABCD-1234".to_string(),
            verification_uri: uri.to_string(),
            interval: 5,
            expires_in: 900,
        }
    }

    #[test]
    fn headless_login_is_rejected_before_keychain_network_or_browser() {
        for attached in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let error = validate_login_terminals(attached.0, attached.1, attached.2).unwrap_err();
            assert!(error.to_string().contains("No keychain token was read"));
            assert!(error.to_string().contains("no network request was sent"));
        }
        let source = include_str!("login.rs");
        let terminal = source.find("require_login_terminals()?").unwrap();
        let network_consent = source
            .find("require_trusted_terminal_login(&authority_plan")
            .unwrap();
        let browser_consent = source
            .find("require_trusted_terminal_login(&browser_plan")
            .unwrap();
        assert!(terminal < source.find("auth::load_token()").unwrap());
        assert!(terminal < source.find("auth::initiate_device_flow").unwrap());
        assert!(terminal < source.find("open::that(&flow.verification_uri)").unwrap());
        assert!(network_consent < source.find("auth::load_token()").unwrap());
        assert!(network_consent < source.find("auth::initiate_device_flow").unwrap());
        assert!(browser_consent < source.find("open::that(&flow.verification_uri)").unwrap());
        assert!(browser_consent < source.find("auth::poll_for_token").unwrap());
    }

    #[test]
    fn keychain_persistence_precedes_success_claim() {
        let source = include_str!("login.rs");
        assert!(
            source.find("auth::store_token(&token)").unwrap()
                < source.find("Logged in as @{}").unwrap()
        );
    }

    #[test]
    fn production_origins_and_poll_schedule_are_closed() {
        validate_api_base("https://phm.dev/api/v1").unwrap();
        for unsafe_base in [
            "http://phm.dev/api/v1",
            "https://evil.invalid/api/v1",
            "https://user@phm.dev/api/v1",
            "https://phm.dev/api/v1\nhttps://evil.invalid",
        ] {
            assert!(validate_api_base(unsafe_base).is_err());
        }

        let schedule = validate_device_flow(&flow("https://phm.dev/device")).unwrap();
        assert_eq!(schedule.poll_interval, Duration::from_secs(5));
        assert_eq!(schedule.max_attempts, 180);
        for unsafe_uri in [
            "http://phm.dev/device",
            "https://evil.invalid/device",
            "https://phm.dev/device?next=https://evil.invalid",
            "https://user@phm.dev/device",
        ] {
            assert!(validate_device_flow(&flow(unsafe_uri)).is_err());
        }
    }

    #[test]
    fn unsafe_provider_identifiers_and_schedules_are_rejected() {
        let mut candidate = flow("https://phm.dev/device");
        candidate.device_code = "device\ncode".to_string();
        assert!(validate_device_flow(&candidate).is_err());
        candidate = flow("https://phm.dev/device");
        candidate.user_code = "ABCD\n1234".to_string();
        assert!(validate_device_flow(&candidate).is_err());
        candidate = flow("https://phm.dev/device");
        candidate.interval = 31;
        assert!(validate_device_flow(&candidate).is_err());
        candidate = flow("https://phm.dev/device");
        candidate.expires_in = 3600;
        assert!(validate_device_flow(&candidate).is_err());
    }

    #[test]
    fn changed_login_destination_invalidates_challenge() {
        let reviewed = LoginBrowserPlan {
            operation: "open-device-verification-and-poll",
            canonical_api_base: "https://phm.dev/api/v1",
            normalized_https_destination: "https://phm.dev/device",
            ambient_auth_context_may_be_sent: true,
            poll_interval_seconds: 5,
            maximum_poll_attempts: 180,
            maximum_timeout_seconds: 900,
            persistent_effect: "store an approved bearer in the OS keychain",
        };
        let changed = LoginBrowserPlan {
            normalized_https_destination: "https://evil.invalid/device",
            ..reviewed.clone()
        };
        let nonce = "0011223344556677";
        let reviewed_json = serde_json::to_string_pretty(&reviewed).unwrap();
        let expected = format!(
            "login open-and-poll {nonce} {}",
            hex::encode(Sha256::digest(reviewed_json.as_bytes()))
        );

        assert!(prompt_login(
            &changed,
            "open-and-poll",
            nonce,
            &mut std::io::Cursor::new(format!("{expected}\n")),
            &mut Vec::new(),
            &mut Vec::new()
        )
        .is_err());
    }

    #[test]
    fn provider_display_fields_are_value_safe() {
        assert_eq!(safe_display_field("mason-wyatt"), "mason-wyatt");
        assert_eq!(safe_display_field("pro"), "pro");
        assert_eq!(safe_display_field("bad\nvalue"), "unknown");
        assert_eq!(safe_display_field(&"a".repeat(65)), "unknown");
    }
}
