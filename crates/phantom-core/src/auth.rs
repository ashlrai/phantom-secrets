use crate::error::{PhantomError, Result};
use serde::{Deserialize, Serialize};

const KEYCHAIN_SERVICE: &str = "phantom-cloud";
const TOKEN_KEY: &str = "access_token";
const CLOUD_VAULT_KEY_PREFIX: &str = "phantom-cloud:vault_key";

#[derive(Debug, Deserialize)]
pub struct DeviceFlowResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u64,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct PollResponse {
    pub status: String,
    pub access_token: Option<String>,
    pub user: Option<UserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub email: Option<String>,
    pub github_login: String,
    pub plan: String,
    pub vaults_count: Option<u64>,
}

/// Initiate the device auth flow. Returns a code the user must enter in the browser.
pub async fn initiate_device_flow(api_base: &str) -> Result<DeviceFlowResponse> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{api_base}/auth/device/initiate"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| PhantomError::AuthError(format!("Failed to connect: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(PhantomError::CloudError {
            status,
            message: body,
        });
    }

    resp.json::<DeviceFlowResponse>()
        .await
        .map_err(|e| PhantomError::AuthError(format!("Invalid response: {e}")))
}

/// Poll for device approval. Returns the access token once approved.
pub async fn poll_for_token(api_base: &str, device_code: &str) -> Result<PollResponse> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{api_base}/auth/device/poll"))
        .json(&serde_json::json!({ "device_code": device_code }))
        .send()
        .await
        .map_err(|e| PhantomError::AuthError(format!("Poll failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(PhantomError::CloudError {
            status,
            message: body,
        });
    }

    resp.json::<PollResponse>()
        .await
        .map_err(|e| PhantomError::AuthError(format!("Invalid poll response: {e}")))
}

/// Get current user info from the API.
pub async fn get_user_info(api_base: &str, token: &str) -> Result<UserInfo> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{api_base}/me"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| PhantomError::AuthError(format!("Failed to connect: {e}")))?;

    if resp.status().as_u16() == 401 {
        return Err(PhantomError::AuthRequired);
    }

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(PhantomError::CloudError {
            status,
            message: body,
        });
    }

    resp.json::<UserInfo>()
        .await
        .map_err(|e| PhantomError::AuthError(format!("Invalid response: {e}")))
}

/// Store the access token in the OS keychain.
pub fn store_token(token: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, TOKEN_KEY)
        .map_err(|e| PhantomError::AuthError(format!("Keychain error: {e}")))?;
    entry
        .set_password(token)
        .map_err(|e| PhantomError::AuthError(format!("Failed to store token: {e}")))?;
    Ok(())
}

/// Load the access token from the OS keychain.
pub fn load_token() -> Option<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, TOKEN_KEY).ok()?;
    entry.get_password().ok()
}

/// Require an access token, returning AuthRequired error if not found.
pub fn require_token() -> Result<String> {
    load_token().ok_or(PhantomError::AuthRequired)
}

/// Clear the access token from the OS keychain.
pub fn clear_token() -> Result<()> {
    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, TOKEN_KEY) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

/// Get or create a cloud vault encryption passphrase.
/// Stored in OS keychain — never transmitted to the server.
pub fn get_or_create_cloud_passphrase() -> Result<String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, CLOUD_VAULT_KEY_PREFIX)
        .map_err(|e| PhantomError::AuthError(format!("Keychain error: {e}")))?;

    // Try to load existing
    if let Ok(passphrase) = entry.get_password() {
        return Ok(passphrase);
    }

    // Generate new passphrase
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let passphrase = hex::encode(bytes);

    entry
        .set_password(&passphrase)
        .map_err(|e| PhantomError::AuthError(format!("Failed to store vault key: {e}")))?;

    Ok(passphrase)
}

/// Get the API base URL from env var or default.
pub fn api_base_url() -> String {
    std::env::var("PHANTOM_API_URL").unwrap_or_else(|_| "https://phm.dev/api/v1".to_string())
}
