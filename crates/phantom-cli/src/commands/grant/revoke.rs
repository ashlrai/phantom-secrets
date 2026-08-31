//! `phantom grant revoke <provider>` — the lifecycle bookend.
//!
//! Remote revocation must succeed before Phantom removes the local renewal
//! material or configuration. No supported provider currently has a wired,
//! authenticated revocation implementation here, so the command fails closed
//! with provider-specific operator guidance and performs no mutation.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;

use super::status::normalize_provider;

pub fn run_revoke(provider: &str, json_output: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    if !config_path.exists() {
        bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let want = normalize_provider(provider);

    // Secrets whose rotation block names this provider.
    let targets: Vec<String> = config
        .phantom
        .secrets
        .iter()
        .filter(|(_, ov)| {
            ov.rotation_provider
                .as_ref()
                .map(|rp| normalize_provider(&rp.provider) == want)
                .unwrap_or(false)
        })
        .map(|(name, _)| name.clone())
        .collect();

    if targets.is_empty() {
        bail!("No grant found for provider '{provider}'.");
    }

    let guidance = remote_revoke_guidance(&want);
    if json_output {
        let obj = serde_json::json!({
            "state": "blocked",
            "provider": provider,
            "configured_secrets": targets,
            "remote_revocation_required": true,
            "local_mutation": false,
            "guidance": guidance,
            "value_printed": false,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        bail!("remote revocation is required before local cleanup for provider '{provider}'");
    }

    bail!(
        "Remote revocation for provider '{}' is not implemented; no local vault values or \
         rotation configuration were changed. {} After the provider confirms the credential \
         is inactive, retain the local grant until Phantom supports an authenticated \
         revoke-then-cleanup transaction.",
        provider,
        guidance
    )
}

fn remote_revoke_guidance(provider: &str) -> &'static str {
    match provider {
        "github" => {
            "Revoke or uninstall the GitHub App in GitHub Settings: \
             https://github.com/settings/apps"
        }
        "vercel" | "vercel-integration" => {
            "Remove the Integration from Vercel account or team settings: \
             https://vercel.com/account/integrations"
        }
        "stripe" => "Uninstall the Stripe App from the authorized account in the Stripe Dashboard.",
        "supabase" | "supabase-management" => {
            "Revoke the OAuth app authorization from the affected Supabase organization/account."
        }
        "sentry" => "Uninstall the Integration from the affected Sentry organization settings.",
        _ => "Revoke the credential or app authorization in the provider's control plane.",
    }
}

#[cfg(test)]
mod tests {
    use super::remote_revoke_guidance;

    #[test]
    fn guidance_points_to_remote_control_plane() {
        assert!(remote_revoke_guidance("github").contains("github.com/settings/apps"));
        assert!(remote_revoke_guidance("stripe").contains("Stripe Dashboard"));
        assert!(remote_revoke_guidance("unknown").contains("provider's control plane"));
    }
}
