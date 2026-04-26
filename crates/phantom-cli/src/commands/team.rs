use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::{auth, config::PhantomConfig, teams, teams_vault};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

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
    // Last 8 chars of the base64 pubkey as a stable, distinguishable
    // fingerprint for verification across rotations. Full key is on the
    // server and in the user's keychain — this is just a visual aid.
    let fp_len = 8.min(pk.len());
    let fingerprint = &pk[pk.len() - fp_len..];
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(teams::register_team_key(&api_base, &token, team_id, &pk))?;
    println!(
        "{}  Public key registered for team id {} — fingerprint …{}",
        "ok".green().bold(),
        team_id,
        fingerprint
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

    // Read the local vault into a Zeroizing-valued map so the secret
    // bytes are scrubbed when the helper drops them.
    let vault = phantom_vault::create_vault(&project_id);
    let secret_names = vault.list()?;
    if secret_names.is_empty() {
        println!("{}  No secrets to push", "warn".yellow().bold());
        return Ok(());
    }
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for name in &secret_names {
        let value = vault.retrieve(name)?; // Zeroizing<String>
        secrets.insert(name.clone(), Zeroizing::new(String::from(value.as_str())));
    }

    let outcome = rt.block_on(teams_vault::push_for_project(
        &api_base,
        &token,
        team_id,
        &project_id,
        secrets,
        &kp,
    ))?;

    let suffix = if outcome.skipped > 0 {
        format!(
            ", {} member(s) skipped — no key registered yet",
            outcome.skipped
        )
    } else {
        String::new()
    };
    println!(
        "{}  {} secret(s) pushed to team id {} (v{}, encrypted for {} member(s){suffix})",
        "ok".green().bold(),
        outcome.secret_count,
        team_id,
        outcome.new_version,
        outcome.recipients,
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

    let (secrets, version) = rt.block_on(teams_vault::pull_for_project(
        &api_base,
        &token,
        team_id,
        &project_id,
        &kp,
    ))?;

    // Write into local vault, overwriting existing values. The secrets
    // map's values are Zeroizing<String> — scrubbed on drop after this
    // loop returns.
    let vault = phantom_vault::create_vault(&project_id);
    let mut written = 0usize;
    for (name, value) in &secrets {
        vault
            .store(name, value)
            .with_context(|| format!("Failed to store {name}"))?;
        written += 1;
    }

    println!(
        "{}  Pulled {} secret(s) from team id {} (v{}). Local vault updated.",
        "ok".green().bold(),
        written,
        team_id,
        version
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
