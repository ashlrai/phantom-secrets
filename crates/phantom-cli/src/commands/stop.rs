use anyhow::Result;
use colored::Colorize;
use std::io::IsTerminal;

pub fn run() -> Result<()> {
    if !(std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal())
    {
        anyhow::bail!(
            "`phantom stop` is only a trusted-terminal migration command for authenticated v0.7.3 state; stdin, stdout, and stderr must all be terminals"
        );
    }
    let project_dir = std::env::current_dir()?;
    match super::legacy_proxy::inspect(&project_dir) {
        super::legacy_proxy::LegacyState::Missing => anyhow::bail!(
            "No legacy v0.7.3 proxy state exists. Current foreground proxies must be stopped from their owning terminal with Ctrl-C."
        ),
        super::legacy_proxy::LegacyState::Unsafe(error) => anyhow::bail!(
            "Unsafe or malformed legacy .phantom.pid state was left untouched: {error}"
        ),
        super::legacy_proxy::LegacyState::Unverified(proxy) => anyhow::bail!(
            "Refusing to stop PID {} because it did not authenticate as the recorded legacy proxy. The record was left untouched.",
            proxy.pid
        ),
        super::legacy_proxy::LegacyState::Authenticated(proxy) => {
            super::legacy_proxy::authenticated_shutdown(&proxy)?;
            super::legacy_proxy::wait_for_owner_cleanup(&project_dir)?;
            println!(
                "{} Authenticated legacy proxy shutdown completed (PID {}).",
                "ok".green().bold(),
                proxy.pid
            );
            Ok(())
        }
    }
}
