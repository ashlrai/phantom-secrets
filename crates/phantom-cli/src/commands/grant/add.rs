//! `phantom grant add` — shipped hard-denial boundary.
//!
//! ```text
//! phantom grant add github-app [--org ORG] [--name APP] [--rotate-secret KEY] [--no-browser] [--json]
//! phantom grant add <provider> --flow pkce|device --client-id ID
//!     [--client-secret-env ENV] [--scope a,b,c] [--no-browser] [--json]
//! ```
//!
//! Version 0.7.4 performs no enrollment: it returns before cwd/config/vault/env,
//! browser, loopback, network, audit, or approval effects. Protocol request
//! builders remain compiled only for hermetic unit tests.

use anyhow::{bail, Result};

#[allow(clippy::too_many_arguments)]
pub fn run_add(
    provider: &str,
    org: Option<String>,
    app_name: Option<String>,
    rotate_secret: Option<String>,
    no_browser: bool,
    flow: Option<&str>,
    client_id: Option<String>,
    client_secret_env: Option<String>,
    scope: Option<String>,
    team: Option<String>,
    account: Option<String>,
    json_output: bool,
) -> Result<()> {
    let _ = (
        provider,
        org,
        app_name,
        rotate_secret,
        no_browser,
        flow,
        client_id,
        client_secret_env,
        scope,
        team,
        account,
        json_output,
    );
    bail!(
        "`phantom grant add` is disabled in shipped 0.7.4 before project, vault, environment, browser, loopback, network, audit, or approval access. Obtain the credential directly from the provider with fresh operator consent, then store it from a trusted terminal with `phantom add <NAME>`. No enrollment or local state change occurred. Do not retry automatically."
    )
}
