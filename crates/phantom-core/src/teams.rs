use crate::error::{PhantomError, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct TeamMember {
    pub github_login: String,
    pub email: Option<String>,
    pub role: String,
}

/// List all teams the authenticated user belongs to.
pub async fn list_teams(api_base: &str, token: &str) -> Result<Vec<Team>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{api_base}/teams"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 => resp.json().await.map_err(|e| PhantomError::CloudError {
            status,
            message: format!("Invalid response: {e}"),
        }),
        401 => Err(PhantomError::AuthRequired),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(PhantomError::CloudError {
                status,
                message: body,
            })
        }
    }
}

/// Create a new team. Requires a Pro plan.
pub async fn create_team(api_base: &str, token: &str, name: &str) -> Result<Team> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{api_base}/teams"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 | 201 => resp.json().await.map_err(|e| PhantomError::CloudError {
            status,
            message: format!("Invalid response: {e}"),
        }),
        401 => Err(PhantomError::AuthRequired),
        402 => Err(PhantomError::PlanRequired),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(PhantomError::CloudError {
                status,
                message: body,
            })
        }
    }
}

/// List members of a team.
pub async fn list_members(api_base: &str, token: &str, team_id: &str) -> Result<Vec<TeamMember>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{api_base}/teams/{team_id}/members"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 => resp.json().await.map_err(|e| PhantomError::CloudError {
            status,
            message: format!("Invalid response: {e}"),
        }),
        401 => Err(PhantomError::AuthRequired),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(PhantomError::CloudError {
                status,
                message: body,
            })
        }
    }
}

/// Invite a member to a team by GitHub login. Requires owner or admin role.
pub async fn invite_member(
    api_base: &str,
    token: &str,
    team_id: &str,
    github_login: &str,
    role: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{api_base}/teams/{team_id}/members"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "github_login": github_login,
            "role": role,
        }))
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 | 201 => Ok(()),
        401 => Err(PhantomError::AuthRequired),
        402 => Err(PhantomError::PlanRequired),
        _ => {
            let body = resp.text().await.unwrap_or_default();
            Err(PhantomError::CloudError {
                status,
                message: body,
            })
        }
    }
}
