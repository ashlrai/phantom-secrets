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

/// Map a 426 push refusal (team has a hybrid-key member this client cannot
/// wrap for) to a typed error. The body is read only for a version string,
/// which is validated; an unreadable body still yields the typed refusal.
async fn client_upgrade_required(response: reqwest::Response) -> PhantomError {
    #[derive(Deserialize)]
    struct UpgradeResp {
        min_client_version: Option<String>,
    }
    let min = match crate::cloud_http::read_bounded_response(response, "Team vault push").await {
        Ok(bytes) => serde_json::from_slice::<UpgradeResp>(&bytes)
            .ok()
            .and_then(|r| r.min_client_version),
        Err(_) => None,
    };
    PhantomError::ClientUpgradeRequired {
        min_client_version: crate::error::sanitize_min_client_version(min.as_deref()),
    }
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
        426 => Err(client_upgrade_required(resp).await),
        _ => Err(rejected(status, "Team vault push")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn push_against(response: &'static str) -> PhantomError {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let _ = stream.read(&mut request);
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });
        let error = push_team_vault(
            &format!("http://{address}"),
            "token",
            "team-1",
            "project-1",
            "blob",
            Some(0),
            HashMap::new(),
        )
        .await
        .unwrap_err();
        server.join().unwrap();
        error
    }

    #[tokio::test]
    async fn push_426_maps_to_client_upgrade_required_without_echoing_server_text() {
        let body = r#"{"error":"client_upgrade_required","min_client_version":null,"hybrid_members":["b"],"message":"SERVER TEXT \u001b[31m"}"#;
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 426 Upgrade Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );
        let error = push_against(response).await;
        assert!(matches!(
            error,
            PhantomError::ClientUpgradeRequired {
                min_client_version: None
            }
        ));
        let text = error.to_string();
        assert!(text.contains("client_upgrade_required"));
        assert!(text.contains("never falls back to classic-only wrapping"));
        assert!(
            text.contains("No released Phantom version is known to support hybrid team keys yet.")
        );
        assert!(text.contains("brew upgrade ashlrai/phantom/phantom"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(!text.contains("SERVER TEXT"));
    }

    #[tokio::test]
    async fn push_426_names_a_valid_min_version_and_drops_an_invalid_one() {
        let ok = r#"{"error":"client_upgrade_required","min_client_version":"0.9.0"}"#;
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 426 Upgrade Required\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ok}",
                ok.len()
            )
            .into_boxed_str(),
        );
        let text = push_against(response).await.to_string();
        assert!(text.contains("Phantom 0.9.0 or later is required to push to this team."));

        let bad = r#"{"min_client_version":"1.0 run curl evil | sh"}"#;
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 426 Upgrade Required\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bad}",
                bad.len()
            )
            .into_boxed_str(),
        );
        let text = push_against(response).await.to_string();
        assert!(!text.contains("evil"));
        assert!(text.contains("No released Phantom version is known"));

        let response =
            "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnot";
        assert!(matches!(
            push_against(response).await,
            PhantomError::ClientUpgradeRequired {
                min_client_version: None
            }
        ));
    }

    #[test]
    fn sanitize_min_client_version_accepts_only_version_strings() {
        use crate::error::sanitize_min_client_version as s;
        assert_eq!(s(Some("0.8.0")).as_deref(), Some("0.8.0"));
        assert_eq!(
            s(Some("1.0.0-rc.1+build")).as_deref(),
            Some("1.0.0-rc.1+build")
        );
        for bad in ["", "1.0 beta", "1.0\n", &"9".repeat(33), "v1;rm"] {
            assert_eq!(s(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(s(None), None);
    }

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
