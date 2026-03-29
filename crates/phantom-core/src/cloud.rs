use crate::error::{PhantomError, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PushResponse {
    pub version: u64,
}

#[derive(Debug, Deserialize)]
pub struct PullResponse {
    pub encrypted_blob: String,
    pub version: u64,
}

/// Push an encrypted vault blob to the cloud.
pub async fn push(
    api_base: &str,
    token: &str,
    project_id: &str,
    encrypted_blob: &str,
    expected_version: u64,
) -> Result<u64> {
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{api_base}/vault/push"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "project_id": project_id,
            "encrypted_blob": encrypted_blob,
            "expected_version": expected_version,
        }))
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 | 201 => {
            let push_resp: PushResponse =
                resp.json().await.map_err(|e| PhantomError::CloudError {
                    status,
                    message: format!("Invalid response: {e}"),
                })?;
            Ok(push_resp.version)
        }
        402 => Err(PhantomError::PlanRequired),
        409 => {
            let body = resp.text().await.unwrap_or_default();
            // Try to extract server version from response
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                let server_version = v["server_version"].as_u64().unwrap_or(0);
                Err(PhantomError::VersionConflict {
                    local: expected_version,
                    remote: server_version,
                })
            } else {
                Err(PhantomError::CloudError {
                    status,
                    message: body,
                })
            }
        }
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

/// Pull an encrypted vault blob from the cloud.
pub async fn pull(api_base: &str, token: &str, project_id: &str) -> Result<Option<PullResponse>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{api_base}/vault/pull"))
        .bearer_auth(token)
        .query(&[("project_id", project_id)])
        .send()
        .await
        .map_err(|e| PhantomError::CloudError {
            status: 0,
            message: format!("Failed to connect: {e}"),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 => {
            let pull_resp: PullResponse =
                resp.json().await.map_err(|e| PhantomError::CloudError {
                    status,
                    message: format!("Invalid response: {e}"),
                })?;
            Ok(Some(pull_resp))
        }
        404 => Ok(None),
        402 => Err(PhantomError::PlanRequired),
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
