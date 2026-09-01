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

#[derive(Debug, Deserialize)]
struct TeamsResp {
    teams: Vec<Team>,
}

#[derive(Debug, Deserialize)]
struct TeamResp {
    team: Team,
}

#[derive(Debug, Deserialize)]
struct TeamMembersResp {
    members: Vec<TeamMember>,
}

fn validate_api_id(label: &str, value: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(PhantomError::CloudError {
            status: 0,
            message: format!("Invalid {label} for Phantom Cloud request"),
        })
    }
}

async fn parse_success<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    status: u16,
    operation: &str,
) -> Result<T> {
    let bytes = crate::cloud_http::read_bounded_response(response, operation).await?;
    crate::cloud_http::parse_json(&bytes, status, operation)
}

fn rejected(status: u16, operation: &str) -> PhantomError {
    crate::cloud_http::response_error(status, operation, "Phantom Cloud rejected the request")
}

/// List all teams the authenticated user belongs to.
pub async fn list_teams(api_base: &str, token: &str) -> Result<Vec<Team>> {
    let client = crate::cloud_http::client()?;
    let resp = client
        .get(format!("{api_base}/teams"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 => parse_success::<TeamsResp>(resp, status, "Team list")
            .await
            .map(|response| response.teams),
        401 => Err(PhantomError::AuthRequired),
        _ => Err(rejected(status, "Team list")),
    }
}

/// Create a new team. Requires a Pro plan.
pub async fn create_team(api_base: &str, token: &str, name: &str) -> Result<Team> {
    let client = crate::cloud_http::client()?;
    let resp = client
        .post(format!("{api_base}/teams"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 | 201 => parse_success::<TeamResp>(resp, status, "Team creation")
            .await
            .map(|response| response.team),
        401 => Err(PhantomError::AuthRequired),
        402 => Err(PhantomError::PlanRequired),
        _ => Err(rejected(status, "Team creation")),
    }
}

/// List members of a team.
pub async fn list_members(api_base: &str, token: &str, team_id: &str) -> Result<Vec<TeamMember>> {
    validate_api_id("team ID", team_id)?;
    let client = crate::cloud_http::client()?;
    let resp = client
        .get(format!("{api_base}/teams/{team_id}/members"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 => parse_success::<TeamMembersResp>(resp, status, "Team member list")
            .await
            .map(|response| response.members),
        401 => Err(PhantomError::AuthRequired),
        _ => Err(rejected(status, "Team member list")),
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
    validate_api_id("team ID", team_id)?;
    let client = crate::cloud_http::client()?;
    let resp = client
        .post(format!("{api_base}/teams/{team_id}/members"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "github_login": github_login,
            "role": role,
        }))
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 | 201 => Ok(()),
        401 => Err(PhantomError::AuthRequired),
        402 => Err(PhantomError::PlanRequired),
        _ => Err(rejected(status, "Team member invitation")),
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
    validate_api_id("team ID", team_id)?;
    let client = crate::cloud_http::client()?;
    let resp = client
        .get(format!("{api_base}/teams/{team_id}/key"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => parse_success::<TeamMemberKeysResp>(resp, status, "Team public-key list")
            .await
            .map(|response| response.members),
        401 => Err(PhantomError::AuthRequired),
        _ => Err(rejected(status, "Team public-key list")),
    }
}

/// Register or update the caller's team-vault public key on this team.
pub async fn register_team_key(
    api_base: &str,
    token: &str,
    team_id: &str,
    public_key_b64: &str,
) -> Result<()> {
    validate_api_id("team ID", team_id)?;
    let client = crate::cloud_http::client()?;
    let resp = client
        .post(format!("{api_base}/teams/{team_id}/key"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "public_key": public_key_b64 }))
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => Ok(()),
        401 => Err(PhantomError::AuthRequired),
        _ => Err(rejected(status, "Team public-key registration")),
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
    validate_api_id("team ID", team_id)?;
    validate_api_id("project ID", project_id)?;
    let client = crate::cloud_http::client()?;
    let resp = client
        .get(format!("{api_base}/teams/{team_id}/vaults/{project_id}"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => {
            let v = parse_success::<PulledTeamVault>(resp, status, "Team vault pull").await?;
            Ok(Some(v))
        }
        404 => Ok(None),
        401 => Err(PhantomError::AuthRequired),
        _ => Err(rejected(status, "Team vault pull")),
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
    validate_api_id("team ID", team_id)?;
    validate_api_id("project ID", project_id)?;
    let client = crate::cloud_http::client()?;
    let body = PushTeamVaultBody {
        encrypted_blob,
        expected_version,
        key_shares,
    };
    let resp = client
        .post(format!("{api_base}/teams/{team_id}/vaults/{project_id}"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;
    let status = resp.status().as_u16();
    match status {
        200 => {
            #[derive(Deserialize)]
            struct PushResp {
                version: u64,
            }
            parse_success::<PushResp>(resp, status, "Team vault push")
                .await
                .map(|response| response.version)
        }
        401 => Err(PhantomError::AuthRequired),
        402 => Err(PhantomError::PlanRequired),
        409 => {
            #[derive(Deserialize)]
            struct ConflictResp {
                server_version: u64,
            }
            let conflict =
                parse_success::<ConflictResp>(resp, status, "Team vault push conflict").await?;
            Err(PhantomError::VersionConflict {
                local: expected_version.unwrap_or(0),
                remote: conflict.server_version,
            })
        }
        _ => Err(rejected(status, "Team vault push")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_teams_response_envelope() {
        let resp: TeamsResp = serde_json::from_value(serde_json::json!({
            "teams": [
                { "id": "team_1", "name": "Core", "role": "owner" }
            ]
        }))
        .unwrap();

        assert_eq!(resp.teams.len(), 1);
        assert_eq!(resp.teams[0].id, "team_1");
        assert_eq!(resp.teams[0].name, "Core");
        assert_eq!(resp.teams[0].role, "owner");
    }

    #[test]
    fn parses_create_team_response_envelope() {
        let resp: TeamResp = serde_json::from_value(serde_json::json!({
            "team": { "id": "team_2", "name": "Platform", "role": "admin" }
        }))
        .unwrap();

        assert_eq!(resp.team.id, "team_2");
        assert_eq!(resp.team.name, "Platform");
        assert_eq!(resp.team.role, "admin");
    }

    #[test]
    fn parses_list_members_response_envelope() {
        let resp: TeamMembersResp = serde_json::from_value(serde_json::json!({
            "members": [
                {
                    "github_login": "mason",
                    "email": "mason@example.com",
                    "role": "member"
                }
            ]
        }))
        .unwrap();

        assert_eq!(resp.members.len(), 1);
        assert_eq!(resp.members[0].github_login, "mason");
        assert_eq!(resp.members[0].email.as_deref(), Some("mason@example.com"));
        assert_eq!(resp.members[0].role, "member");
    }

    #[test]
    fn path_identifiers_reject_cross_route_forms() {
        for value in ["", "../vault", "team/id", "team?id", "team id"] {
            assert!(
                validate_api_id("team ID", value).is_err(),
                "accepted {value:?}"
            );
        }
        validate_api_id("team ID", "team_01-safe").unwrap();
    }
}
