use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use phantom_core::auth;
use std::time::Duration;

pub fn run() -> Result<()> {
    // Check if already logged in
    if let Some(token) = auth::load_token() {
        let rt = tokio::runtime::Runtime::new()?;
        let api_base = auth::api_base_url();
        match rt.block_on(auth::get_user_info(&api_base, &token)) {
            Ok(user) => {
                println!(
                    "{}  Already logged in as @{} ({})",
                    "ok".green().bold(),
                    user.github_login,
                    user.plan
                );
                return Ok(());
            }
            Err(_) => {
                // Token invalid, proceed with new login
            }
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    let api_base = auth::api_base_url();

    // Initiate device flow
    let flow = rt
        .block_on(auth::initiate_device_flow(&api_base))
        .context("Failed to start login flow")?;

    // Open browser
    println!(
        "{}  Open {} and enter code:",
        "->".blue().bold(),
        flow.verification_uri.bold()
    );
    println!();
    println!("   {}", flow.user_code.bold().cyan());
    println!();

    let _ = open::that(&flow.verification_uri);

    // Poll with spinner
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    spinner.set_message("Waiting for approval...");
    spinner.enable_steady_tick(Duration::from_millis(100));

    let poll_interval = Duration::from_secs(flow.interval.max(5));
    let max_attempts = (flow.expires_in / flow.interval.max(5)) as usize;

    for _ in 0..max_attempts {
        std::thread::sleep(poll_interval);

        match rt.block_on(auth::poll_for_token(&api_base, &flow.device_code)) {
            Ok(poll) => match poll.status.as_str() {
                "approved" => {
                    spinner.finish_and_clear();

                    if let Some(token) = poll.access_token {
                        auth::store_token(&token)
                            .context("Failed to store access token in keychain")?;

                        let user = poll.user.unwrap_or(auth::UserInfo {
                            email: None,
                            github_login: "unknown".to_string(),
                            plan: "free".to_string(),
                            vaults_count: None,
                        });

                        println!(
                            "{}  Logged in as @{} ({})",
                            "ok".green().bold(),
                            user.github_login,
                            user.plan
                        );
                        return Ok(());
                    }
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
                other => {
                    spinner.finish_and_clear();
                    anyhow::bail!("Unexpected status: {other}");
                }
            },
            Err(e) => {
                spinner.finish_and_clear();
                return Err(e.into());
            }
        }
    }

    spinner.finish_and_clear();
    anyhow::bail!("Login timed out. Run `phantom login` to try again.")
}
