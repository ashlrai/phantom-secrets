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

#[derive(Debug, Deserialize)]
struct VersionConflictResponse {
    server_version: u64,
}

/// Push an encrypted vault blob to the cloud.
pub async fn push(
    api_base: &str,
    token: &str,
    project_id: &str,
    encrypted_blob: &str,
    expected_version: u64,
) -> Result<u64> {
    let client = crate::cloud_http::client()?;
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
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 | 201 => {
            let bytes = crate::cloud_http::read_bounded_response(resp, "Cloud vault push").await?;
            let push_resp: PushResponse =
                crate::cloud_http::parse_json(&bytes, status, "Cloud vault push")?;
            Ok(push_resp.version)
        }
        402 => Err(PhantomError::PlanRequired),
        409 => {
            let bytes =
                crate::cloud_http::read_bounded_response(resp, "Cloud vault push conflict").await?;
            let conflict: VersionConflictResponse =
                crate::cloud_http::parse_json(&bytes, status, "Cloud vault push conflict")?;
            Err(PhantomError::VersionConflict {
                local: expected_version,
                remote: conflict.server_version,
            })
        }
        401 => Err(PhantomError::AuthRequired),
        _ => Err(crate::cloud_http::response_error(
            status,
            "Cloud vault push",
            "Phantom Cloud rejected the request",
        )),
    }
}

/// Pull an encrypted vault blob from the cloud.
pub async fn pull(api_base: &str, token: &str, project_id: &str) -> Result<Option<PullResponse>> {
    let client = crate::cloud_http::client()?;
    let resp = client
        .get(format!("{api_base}/vault/pull"))
        .bearer_auth(token)
        .query(&[("project_id", project_id)])
        .send()
        .await
        .map_err(|_| PhantomError::CloudError {
            status: 0,
            message: "Failed to connect to Phantom Cloud".to_string(),
        })?;

    let status = resp.status().as_u16();

    match status {
        200 => {
            let bytes = crate::cloud_http::read_bounded_response(resp, "Cloud vault pull").await?;
            let pull_resp: PullResponse =
                crate::cloud_http::parse_json(&bytes, status, "Cloud vault pull")?;
            Ok(Some(pull_resp))
        }
        404 => Ok(None),
        402 => Err(PhantomError::PlanRequired),
        401 => Err(PhantomError::AuthRequired),
        _ => Err(crate::cloud_http::response_error(
            status,
            "Cloud vault pull",
            "Phantom Cloud rejected the request",
        )),
    }
}
