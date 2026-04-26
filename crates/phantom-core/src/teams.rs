use crate::error::{PhantomError, Result};
use crate::team_crypto::KeyShare;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

// ── Team-vault sharing ──────────────────────────────────────────────────

/// One member's record as needed for team-vault push: the user_id and
/// (if registered) their public key. Members without a public key are
/// returned with `public_key: None` and silently excluded from shares.
#[derive(Debug, Deserialize)]
pub struct TeamMemberKey {
    pub user_id: String,
    pub public_key: Option<String>,
}

/// Server response wrapper for GET /teams/:id/key.
#[derive(Debug, Deserialize)]
struct TeamMemberKeysResp {
    members: Vec<TeamMemberKey>,
}

/// List the team's member user_ids + public keys. Used by `team vault
/// push` to know who to encrypt the symmetric key to.
pub async fn list_team_member_keys(
    api_base: &str,
    token: &str,
    team_id: &str,
) -> Result<Vec<TeamMemberKey>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{api_base}/teams/{team_id}/key"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => resp
            .json::<TeamMemberKeysResp>()
            .await
            .map(|r| r.members)
            .map_err(|e| PhantomError::CloudError {
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

/// Register or update the caller's team-vault public key on this team.
pub async fn register_team_key(
    api_base: &str,
    token: &str,
    team_id: &str,
    public_key_b64: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{api_base}/teams/{team_id}/key"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "public_key": public_key_b64 }))
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => Ok(()),
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

/// Server response for a team-vault pull.
#[derive(Debug, Deserialize)]
pub struct PulledTeamVault {
    pub encrypted_blob: String,
    pub version: u64,
    pub my_share: KeyShare,
}

/// Pull a team vault. Server returns the encrypted blob, current
/// version, and the caller's key share. Returns `Ok(None)` if the
/// vault doesn't exist yet.
pub async fn pull_team_vault(
    api_base: &str,
    token: &str,
    team_id: &str,
    project_id: &str,
) -> Result<Option<PulledTeamVault>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{api_base}/teams/{team_id}/vaults/{project_id}"
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => {
            let v = resp
                .json::<PulledTeamVault>()
                .await
                .map_err(|e| PhantomError::CloudError {
                    status,
                    message: format!("Invalid response: {e}"),
                })?;
            Ok(Some(v))
        }
        404 => Ok(None),
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

#[derive(Debug, Serialize)]
struct PushTeamVaultBody<'a> {
    encrypted_blob: &'a str,
    expected_version: Option<u64>,
    key_shares: HashMap<String, KeyShare>,
}

/// Push a team vault. `key_shares` must cover every team member with a
/// registered public_key — the server returns 400 with a missing/extra
/// list if not. Returns the new version on success.
pub async fn push_team_vault(
    api_base: &str,
    token: &str,
    team_id: &str,
    project_id: &str,
    encrypted_blob: &str,
    expected_version: Option<u64>,
    key_shares: HashMap<String, KeyShare>,
) -> Result<u64> {
    let client = reqwest::Client::new();
    let body = PushTeamVaultBody {
        encrypted_blob,
        expected_version,
        key_shares,
    };
    let resp = client
        .post(format!(
            "{api_base}/teams/{team_id}/vaults/{project_id}"
        ))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => {
            #[derive(Deserialize)]
            struct PushResp {
                version: u64,
            }
            resp.json::<PushResp>()
                .await
                .map(|r| r.version)
                .map_err(|e| PhantomError::CloudError {
                    status,
                    message: format!("Invalid response: {e}"),
                })
        }
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

