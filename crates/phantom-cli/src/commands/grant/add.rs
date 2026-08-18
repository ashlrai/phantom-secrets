//! `phantom grant add` — run the ONE human consent for a provider and vault the
//! durable root(s), then write the matching `rotation_provider` block.
//!
//! ```text
//! phantom grant add github-app [--org ORG] [--name APP] [--rotate-secret KEY] [--no-browser] [--json]
//! phantom grant add <provider> --flow pkce|device --client-id ID
//!     [--client-secret-env ENV] [--scope a,b,c] [--no-browser] [--json]
//! ```
//!
//! Ordering mirrors `rotate.rs` (issue → vault the root → write config → audit):
//! the ONLY place a value is written is `vault.store(...)`, and `.phantom.toml`
//! gets only the `phm:` name. Prints the ONE consent artifact (the engine emits
//! it to stderr) then non-secret metadata — never a token byte.

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::issuance::{
    default_consent_engines, Endpoints, FlowKind, GithubManifestSpec, IssuanceDeps,
    IssuanceRequest, LoopbackListener, MockLoopbackListener, NoBrowser, StdLoopbackListener,
};
use zeroize::Zeroizing;

use super::{is_headless, write_rotation_provider_block, OpenCrateBrowser};

/// Default target secret the minted GitHub installation token lands under. The
/// `rotation_provider` block is written here so `phantom rotate --name <this>`
/// mints a fresh 1-hour `ghs_` token from the vaulted PEM.
const DEFAULT_GITHUB_TOKEN_SECRET: &str = "GITHUB_TOKEN";

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
    json_output: bool,
) -> Result<()> {
    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");
    if !config_path.exists() {
        bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    // Resolve endpoints — fails CLOSED before any I/O on a bad override.
    let endpoints = Endpoints::for_provider(provider).map_err(|e| anyhow!("{e}"))?;

    // Build the request + choose the engine (by identity, never a heuristic).
    let (engine_name, request) = build_request(
        provider,
        org,
        app_name,
        no_browser,
        flow,
        client_id,
        client_secret_env.as_deref(),
        scope,
    )?;
    let engines = default_consent_engines();
    let engine = engines
        .iter()
        .find(|e| e.name() == engine_name)
        .ok_or_else(|| anyhow!("no consent engine named '{engine_name}'"))?;

    // Side-effect deps. When endpoints are overridden (the test harness), swap
    // in the deterministic mock loopback + a no-op browser so no real tab or
    // socket is involved; the engine's mock guard then fails closed unless
    // PHANTOM_ALLOW_MOCK_ISSUANCE=1.
    let http = phantom_core::issuance::build_http_client().map_err(|e| anyhow!("{e}"))?;
    let headless = no_browser || is_headless();
    let real_browser = OpenCrateBrowser;
    let no_browser_sentinel = NoBrowser;
    let browser: &dyn phantom_core::issuance::BrowserOpener = if headless || endpoints.overridden {
        &no_browser_sentinel
    } else {
        &real_browser
    };
    let std_loopback = StdLoopbackListener::new();
    let mock_loopback = MockLoopbackListener::from_env();
    let loopback: &dyn LoopbackListener = if endpoints.overridden {
        &mock_loopback
    } else {
        &std_loopback
    };

    let deps = IssuanceDeps {
        browser,
        loopback,
        http: &http,
        endpoints: &endpoints,
    };

    // Run the ONE consent. The engine prints the single consent artifact (the
    // launch URL / authorize URL / verification code) to stderr itself.
    let outcome = engine
        .issue(&request, &deps)
        .map_err(|e| anyhow!("Credential issuance failed: {e}"))?;

    // ── Vault the roots — the ONLY place values are written ──────────────────
    for material in &outcome.materials {
        vault
            .store(&material.phm_name, material.value.as_str())
            .with_context(|| format!("Failed to vault '{}'", material.phm_name))?;
    }
    phantom_core::audit::log("grant.added", Some(&outcome.provider));

    // ── Write the rotation_provider block under the target secret ────────────
    let target_secret = rotation_target(provider, &rotate_secret, &outcome);
    write_rotation_provider_block(&config_path, &target_secret, &outcome.rotation_config)
        .context("Failed to write rotation_provider block")?;

    // ── Report metadata only — never a value ─────────────────────────────────
    if json_output {
        let obj = serde_json::json!({
            "state": "active",
            "provider": outcome.provider,
            "grant_type": outcome.grant_type.label(),
            "rotation_secret": target_secret,
            "vaulted": outcome.vaulted_names(),
            "metadata": outcome.metadata,
            "value_printed": false,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!(
            "{} Grant added for {} ({}).",
            "ok".green().bold(),
            outcome.provider.cyan().bold(),
            outcome.grant_type.label()
        );
        if let Some(id) = outcome.metadata.app_id {
            println!("   App id: {id}");
        }
        if !outcome.metadata.installation_ids.is_empty() {
            println!(
                "   Installations: {}",
                outcome.metadata.installation_ids.join(", ")
            );
        }
        if !outcome.metadata.scopes.is_empty() {
            println!("   Scopes: {}", outcome.metadata.scopes.join(", "));
        }
        println!(
            "   Vaulted: {} (values were not printed)",
            outcome.vaulted_names().join(", ")
        );
        println!(
            "   Rotation configured under secret {} — run {} to mint the next credential.",
            target_secret.bold(),
            format!("phantom rotate --name {target_secret}").cyan()
        );
        for note in &outcome.metadata.notes {
            println!("   • {note}");
        }
    }

    Ok(())
}

/// Choose the secret the `rotation_provider` block attaches to.
fn rotation_target(
    provider: &str,
    rotate_secret: &Option<String>,
    outcome: &phantom_core::issuance::IssuanceOutcome,
) -> String {
    if let Some(name) = rotate_secret {
        return name.clone();
    }
    if provider == "github-app" {
        return DEFAULT_GITHUB_TOKEN_SECRET.to_string();
    }
    // OAuth-refresh: the refresh-token material name is the rotating secret.
    outcome
        .rotation_config
        .api_key_env
        .clone()
        .unwrap_or_else(|| {
            format!(
                "{}_REFRESH_TOKEN",
                provider.to_uppercase().replace('-', "_")
            )
        })
}

/// Build the engine name + [`IssuanceRequest`] for the provider/flags.
#[allow(clippy::too_many_arguments)]
fn build_request(
    provider: &str,
    org: Option<String>,
    app_name: Option<String>,
    no_browser: bool,
    flow: Option<&str>,
    client_id: Option<String>,
    client_secret_env: Option<&str>,
    scope: Option<String>,
) -> Result<(&'static str, IssuanceRequest)> {
    let scopes: Vec<String> = scope
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if provider == "github-app" {
        let name = app_name.unwrap_or_else(|| "phantom-app".to_string());
        let manifest = GithubManifestSpec::least_privilege(name, org);
        let request = IssuanceRequest {
            provider: provider.to_string(),
            client_id: None,
            client_secret: None,
            scopes,
            flow: None,
            app_manifest: Some(manifest),
        };
        return Ok(("github-app-manifest", request));
    }

    // Generic OAuth-refresh provider: pick pkce or device.
    let client_id = client_id.ok_or_else(|| {
        anyhow!("--client-id is required for provider '{provider}' (the OAuth app's client id)")
    })?;

    // --no-browser (or an auto-detected headless box) forces the device flow,
    // which needs no local browser or loopback socket.
    let flow_kind = match flow {
        Some("device") => FlowKind::Device,
        Some("pkce") => FlowKind::Pkce,
        Some(other) => bail!("unknown --flow '{other}' (expected pkce|device)"),
        None => {
            if no_browser || is_headless() {
                FlowKind::Device
            } else {
                FlowKind::Pkce
            }
        }
    };

    // Resolve the client secret from its env var — never from disk.
    let client_secret = match client_secret_env {
        Some(env_name) => match std::env::var(env_name) {
            Ok(v) => Some(Zeroizing::new(v)),
            Err(_) => bail!("--client-secret-env '{env_name}' is not set in the environment"),
        },
        None => None,
    };

    let engine_name = match flow_kind {
        FlowKind::Pkce => "loopback-pkce",
        FlowKind::Device => "device-flow",
    };
    let request = IssuanceRequest {
        provider: provider.to_string(),
        client_id: Some(client_id),
        client_secret,
        scopes,
        flow: Some(flow_kind),
        app_manifest: None,
    };
    Ok((engine_name, request))
}
