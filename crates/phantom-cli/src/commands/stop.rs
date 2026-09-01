use anyhow::Result;
use std::io::IsTerminal;

pub fn run() -> Result<()> {
    if !(std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal())
    {
        anyhow::bail!(
            "`phantom stop` is only a trusted-terminal diagnostic for legacy v0.7.3 state; stdin, stdout, and stderr must all be terminals"
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
            anyhow::bail!(
                "Authenticated legacy v0.7.3 proxy state exists for PID {}. v0.7.3 did not ship an authenticated remote-shutdown endpoint, so this binary will not kill it or delete .phantom.pid. Stop it with Ctrl-C in its owning v0.7.3 terminal; if that is unavailable, use a checksum-verified v0.7.3 binary from a trusted terminal, or independently verify that no process/listener owns the record before manually removing .phantom.pid.",
                proxy.pid
            )
        }
    }
}
