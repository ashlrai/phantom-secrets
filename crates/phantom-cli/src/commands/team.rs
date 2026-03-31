use anyhow::Result;
use colored::Colorize;
use phantom_core::{auth, teams};

pub fn run_list() -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url();

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
    let api_base = auth::api_base_url();

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
    let api_base = auth::api_base_url();

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

pub fn run_invite(team_id: &str, github_login: &str, role: &str) -> Result<()> {
    let token = auth::require_token()?;
    let api_base = auth::api_base_url();

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
