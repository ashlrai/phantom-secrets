use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use colored::Colorize;
use phantom_core::{auth, cloud, config::PhantomConfig};
use std::collections::BTreeMap;
use zeroize::Zeroize;

pub fn run_push() -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;

    let config = PhantomConfig::load(std::path::Path::new(".phantom.toml"))
        .context("No .phantom.toml found. Run `phantom init` first.")?;

    let vault = phantom_vault::create_vault(&config.phantom.project_id);
    let secret_names = vault.list()?;

    if secret_names.is_empty() {
        println!("{}  No secrets to push", "warn".yellow().bold());
        return Ok(());
    }

    // Collect all secrets into a BTreeMap (sorted for deterministic encryption)
    let mut secrets = BTreeMap::new();
    for name in &secret_names {
        let value = vault.retrieve(name)?;
        secrets.insert(name.clone(), String::from(value.as_str()));
    }

    let mut plaintext = serde_json::to_string(&secrets).context("Failed to serialize secrets")?;

    // Encrypt with cloud passphrase (stored in keychain, never transmitted)
    let passphrase =
        auth::get_or_create_cloud_passphrase().context("Failed to access cloud encryption key")?;
    let encrypted = phantom_vault::crypto::encrypt(plaintext.as_bytes(), &passphrase)?;
    plaintext.zeroize();
    let blob_b64 = BASE64.encode(&encrypted);

    let expected_version = config.cloud.as_ref().map(|c| c.version).unwrap_or(0);

    println!(
        "{}  Encrypting {} secret(s) client-side...",
        "->".blue().bold(),
        secret_names.len()
    );

    let rt = tokio::runtime::Runtime::new()?;
    let new_version = rt.block_on(cloud::push(
        &api_base,
        &token,
        &config.phantom.project_id,
        &blob_b64,
        expected_version,
    ))?;

    // Update local version in config
    let mut config = config;
    let cloud_config = config.cloud.get_or_insert_default();
    cloud_config.version = new_version;
    config.save(std::path::Path::new(".phantom.toml"))?;

    println!(
        "{}  {} secret(s) synced to cloud (v{})",
        "ok".green().bold(),
        secret_names.len(),
        new_version
    );

    Ok(())
}

pub fn run_pull(force: bool) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;

    let config = PhantomConfig::load(std::path::Path::new(".phantom.toml"))
        .context("No .phantom.toml found. Run `phantom init` first.")?;

    let vault = phantom_vault::create_vault(&config.phantom.project_id);

    println!("{}  Pulling from Phantom Cloud...", "->".blue().bold());

    let rt = tokio::runtime::Runtime::new()?;
    let pull_result = rt.block_on(cloud::pull(&api_base, &token, &config.phantom.project_id))?;

    let pull_data = match pull_result {
        Some(data) => data,
        None => {
            println!(
                "{}  No cloud vault found for this project. Run `phantom cloud push` first.",
                "warn".yellow().bold()
            );
            return Ok(());
        }
    };

    // Decrypt the blob
    let passphrase =
        auth::get_or_create_cloud_passphrase().context("Failed to access cloud encryption key")?;
    let encrypted = BASE64
        .decode(&pull_data.encrypted_blob)
        .context("Invalid cloud vault data")?;
    let mut plaintext = phantom_vault::crypto::decrypt(&encrypted, &passphrase)?;

    let mut secrets: BTreeMap<String, String> =
        serde_json::from_slice(&plaintext).context("Failed to parse cloud vault data")?;
    // Zeroize decrypted plaintext immediately after deserialization
    zeroize::Zeroize::zeroize(&mut plaintext);

    // Store each secret in local vault
    let mut added = 0;
    let mut skipped = 0;
    for (name, value) in &secrets {
        if !force && vault.exists(name)? {
            skipped += 1;
            continue;
        }
        vault.store(name, value)?;
        added += 1;
    }
    // Zeroize secret values from memory after storing
    for value in secrets.values_mut() {
        zeroize::Zeroize::zeroize(value);
    }
    drop(secrets);

    // Update local version in config
    let mut config = config;
    let cloud_config = config.cloud.get_or_insert_default();
    cloud_config.version = pull_data.version;
    config.save(std::path::Path::new(".phantom.toml"))?;

    if skipped > 0 {
        println!(
            "{}  {} secret(s) restored, {} skipped (already exist, use --force to overwrite)",
            "ok".green().bold(),
            added,
            skipped
        );
    } else {
        println!(
            "{}  {} secret(s) restored from cloud (v{})",
            "ok".green().bold(),
            added,
            pull_data.version
        );
    }

    Ok(())
}

pub fn run_status() -> Result<()> {
    let api_base = auth::api_base_url()?;

    match auth::load_token() {
        Some(token) => {
            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(auth::get_user_info(&api_base, &token)) {
                Ok(user) => {
                    println!(
                        "{}  Cloud: logged in as @{} ({})",
                        "ok".green().bold(),
                        user.github_login,
                        user.plan
                    );
                    if let Some(count) = user.vaults_count {
                        println!("   Vaults: {count}");
                    }
                }
                Err(_) => {
                    println!(
                        "{}  Cloud: token expired — run `phantom login`",
                        "warn".yellow().bold()
                    );
                }
            }
        }
        None => {
            println!(
                "{}  Cloud: not logged in — run `phantom login`",
                "->".blue().bold()
            );
        }
    }

    // Show local cloud config if it exists
    if let Ok(config) = PhantomConfig::load(std::path::Path::new(".phantom.toml")) {
        if let Some(cloud) = &config.cloud {
            println!("   Last synced version: {}", cloud.version);
        }
    }

    Ok(())
}
