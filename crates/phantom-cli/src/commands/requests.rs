//! Value-free requests. No vault, provider, or credential input is used here.
use anyhow::{bail, Context, Result};
use phantom_core::config::{PhantomConfig, RequestStatus, SecretRequest};
use phantom_core::token::PhantomToken;

pub fn create(name: &str, purpose: &str, route: Option<&str>) -> Result<()> {
    super::add::validate_secret_name(name)?;
    if name.len() > 128
        || purpose.trim().is_empty()
        || purpose.len() > 1024
        || purpose.chars().any(char::is_control)
    {
        bail!("Request needs a name up to 128 bytes and a non-secret purpose of 1-1024 bytes without control characters");
    }
    if let Some(route) = route {
        let valid = PhantomConfig::trusted_builtin_proxy_service(route)
            .is_some_and(|service| service.secret_key == name);
        if !valid {
            bail!("Route must be a built-in proxy route belonging to the requested name");
        }
    }
    let project = crate::util::project_dir()?.canonicalize()?;
    let _lock = phantom_vault::acquire_project_transaction_lock(&project)?;
    let path = project.join(".phantom.toml");
    let (mut config, before) = super::add::load_config_exact(&path)?;
    if let Some(existing) = config.requests.get(name) {
        if existing.purpose != purpose || existing.route.as_deref() != route {
            bail!("A request already exists for this name with different metadata");
        }
        println!("{}={}", name, existing.placeholder);
        return Ok(());
    }
    // Refuse taking ownership of any existing dotenv entry, including public
    // entries and mappings. Never open the vault to create a request.
    let resolved = phantom_core::managed_dotenv::resolve_dotenv(&project, &config, &[])?;
    if let Some(dotenv) = resolved.file {
        dotenv.validate_for_mutation()?;
        if dotenv.entries().iter().any(|entry| entry.key == name) {
            bail!("Name already exists in the managed dotenv; no request created");
        }
    }
    let placeholder = PhantomToken::generate().as_str().to_owned();
    config.requests.insert(
        name.to_owned(),
        SecretRequest {
            purpose: purpose.to_owned(),
            route: route.map(str::to_owned),
            placeholder: placeholder.clone(),
            status: RequestStatus::Pending,
        },
    );
    let after = toml::to_string_pretty(&config).context("Failed to serialize request")?;
    phantom_core::fs::atomic_write_if_unchanged(&path, Some(&before), after.as_bytes())?;
    println!("{name}={placeholder}");
    eprintln!("Request pending. A human or sanctioned flow can run `phantom add {name}` outside the agent. Keep the placeholder private.");
    Ok(())
}

pub fn list(json: bool) -> Result<()> {
    let project = crate::util::project_dir()?;
    let (config, _) = super::add::load_config_exact(&project.join(".phantom.toml"))?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "schema": "phantom.requests.v1", "requests": config.requests,
            }))?
        );
    } else {
        for (name, request) in config.requests {
            let status = match request.status {
                RequestStatus::Pending => "pending",
                RequestStatus::Fulfilled => "fulfilled",
            };
            println!("{name}\t{status}");
        }
    }
    Ok(())
}
