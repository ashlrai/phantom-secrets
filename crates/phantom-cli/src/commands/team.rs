use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use colored::Colorize;
use phantom_core::{auth, config::PhantomConfig, team_crypto, teams};
use rand::RngCore;
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroize;

pub fn run_list() -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;

    let rt = tokio::runtime::Runtime::new()?;
    let team_list = rt.block_on(teams::list_teams(&api_base, &token))?;

    if team_list.is_empty() {
        println!(
            "{}  No teams yet. Create one with `phantom team create <name>`",
            "->".blue().bold()
        );
        return Ok(());
    }

    println!("{}  Your teams:\n", "ok".green().bold());
    for team in &team_list {
        println!(
            "   {} {} (role: {})",
            team.id.dimmed(),
            team.name.bold(),
            team.role
        );
    }

    Ok(())
}

pub fn run_create(name: &str) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;

    println!("{}  Creating team \"{}\"...", "->".blue().bold(), name);

    let rt = tokio::runtime::Runtime::new()?;
    let team = rt.block_on(teams::create_team(&api_base, &token, name))?;

    println!(
        "{}  Team \"{}\" created (id: {})",
        "ok".green().bold(),
        team.name,
        team.id
    );

    Ok(())
}

pub fn run_members(team_id: &str) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;

    let rt = tokio::runtime::Runtime::new()?;
    let members = rt.block_on(teams::list_members(&api_base, &token, team_id))?;

    if members.is_empty() {
        println!(
            "{}  No members yet. Invite someone with `phantom team invite {} <github_login>`",
            "->".blue().bold(),
            team_id
        );
        return Ok(());
    }

    println!("{}  Team members:\n", "ok".green().bold());
    for member in &members {
        let email_str = member
            .email
            .as_deref()
            .map(|e| format!(" <{e}>"))
            .unwrap_or_default();
        println!(
            "   @{}{} ({})",
            member.github_login.bold(),
            email_str.dimmed(),
            member.role
        );
    }

    Ok(())
}

pub fn run_key_publish(team_id: &str) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;
    let pk = kp.public_b64();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(teams::register_team_key(&api_base, &token, team_id, &pk))?;
    println!(
        "{}  Public key registered on team {} ({}…)",
        "ok".green().bold(),
        team_id,
        &pk[..16.min(pk.len())]
    );
    Ok(())
}

pub fn run_vault_push(team_id: &str) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;
    let rt = tokio::runtime::Runtime::new()?;

    let config = PhantomConfig::load(std::path::Path::new(".phantom.toml"))
        .context("No .phantom.toml found. Run `phantom init` first.")?;
    let project_id = config.phantom.project_id.clone();

    // Always (re)register our key — cheap, keeps team_members.public_key
    // in sync after a key rotation.
    rt.block_on(teams::register_team_key(
        &api_base,
        &token,
        team_id,
        &kp.public_b64(),
    ))?;

    // Pull the team's member-key roster so we know who to wrap to.
    let members = rt.block_on(teams::list_team_member_keys(&api_base, &token, team_id))?;
    let recipients: Vec<&teams::TeamMemberKey> = members
        .iter()
        .filter(|m| m.public_key.is_some())
        .collect();
    if recipients.is_empty() {
        anyhow::bail!(
            "No team members have registered public keys yet. Each member should run `phantom team key publish {team_id}` first."
        );
    }
    let skipped = members.len() - recipients.len();

    // Read the local vault into a sorted plaintext map.
    let vault = phantom_vault::create_vault(&project_id);
    let secret_names = vault.list()?;
    if secret_names.is_empty() {
        println!("{}  No secrets to push", "warn".yellow().bold());
        return Ok(());
    }
    let mut secrets = BTreeMap::new();
    for name in &secret_names {
        let value = vault.retrieve(name)?;
        secrets.insert(name.clone(), String::from(value.as_str()));
    }
    let mut plaintext = serde_json::to_string(&secrets).context("Failed to serialize secrets")?;

    // Per-push 32-byte symmetric key, used once.
    let sym_key = team_crypto::generate_sym_key();

    // Encrypt the vault: ChaCha20-Poly1305 with a 12-byte random nonce.
    let cipher = ChaCha20Poly1305::new(sym_key.as_slice().into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
    plaintext.zeroize();

    // Wire format: nonce (12B) || ciphertext, base64-encoded.
    let mut framed = Vec::with_capacity(12 + ciphertext.len());
    framed.extend_from_slice(&nonce_bytes);
    framed.extend_from_slice(&ciphertext);
    let blob_b64 = BASE64.encode(&framed);

    // Wrap the symmetric key for each recipient.
    let mut shares: HashMap<String, team_crypto::KeyShare> = HashMap::new();
    for m in &recipients {
        let share = team_crypto::seal_sym_key(&sym_key, m.public_key.as_ref().unwrap())?;
        shares.insert(m.user_id.clone(), share);
    }

    let new_version = rt.block_on(teams::push_team_vault(
        &api_base,
        &token,
        team_id,
        &project_id,
        &blob_b64,
        None, // expected_version: don't gate first time; CLI doesn't track this yet
        shares,
    ))?;

    println!(
        "{}  {} secret(s) pushed to team {} (v{}, {} recipient(s){})",
        "ok".green().bold(),
        secret_names.len(),
        team_id,
        new_version,
        recipients.len(),
        if skipped > 0 {
            format!(", {skipped} member(s) skipped — no key registered yet")
        } else {
            String::new()
        }
    );
    Ok(())
}

pub fn run_vault_pull(team_id: &str) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;
    let rt = tokio::runtime::Runtime::new()?;

    let config = PhantomConfig::load(std::path::Path::new(".phantom.toml"))
        .context("No .phantom.toml found. Run `phantom init` first.")?;
    let project_id = config.phantom.project_id.clone();

    let pulled = match rt.block_on(teams::pull_team_vault(
        &api_base,
        &token,
        team_id,
        &project_id,
    ))? {
        Some(v) => v,
        None => anyhow::bail!(
            "No team vault found for project {project_id} on team {team_id}. Push from the project owner first."
        ),
    };

    // Decrypt the symmetric key from our share, then decrypt the blob.
    let sym_key = team_crypto::open_sym_key(&pulled.my_share, &kp)?;
    let framed = BASE64
        .decode(&pulled.encrypted_blob)
        .context("Bad base64 in encrypted_blob")?;
    if framed.len() < 12 + 16 {
        anyhow::bail!("Encrypted blob too short");
    }
    let (nonce_bytes, ct) = framed.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(sym_key.as_slice().into());
    let mut plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;
    let secrets: BTreeMap<String, String> =
        serde_json::from_slice(&plaintext).context("Bad vault JSON")?;
    plaintext.zeroize();

    // Write into local vault, overwriting existing values.
    let vault = phantom_vault::create_vault(&project_id);
    let mut written = 0usize;
    for (name, value) in &secrets {
        vault
            .store(name, value)
            .with_context(|| format!("Failed to store {name}"))?;
        written += 1;
    }

    println!(
        "{}  Pulled {} secret(s) from team {} (v{})",
        "ok".green().bold(),
        written,
        team_id,
        pulled.version
    );
    Ok(())
}

pub fn run_invite(team_id: &str, github_login: &str, role: &str) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url()?;

    println!(
        "{}  Inviting @{} as {} to team {}...",
        "->".blue().bold(),
        github_login,
        role,
        team_id
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(teams::invite_member(
        &api_base,
        &token,
        team_id,
        github_login,
        role,
    ))?;

    println!(
        "{}  @{} invited as {}",
        "ok".green().bold(),
        github_login,
        role
    );

    Ok(())
}
