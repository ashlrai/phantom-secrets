use crate::error::{PhantomError, Result};
use serde::{Deserialize, Serialize};

const KEYCHAIN_SERVICE: &str = "phantom-cloud";
const TOKEN_KEY: &str = "access_token";
const CLOUD_VAULT_KEY_PREFIX: &str = "phantom-cloud:vault_key";
const TEAM_PUBKEY: &str = "phantom-cloud:team_pubkey";
const TEAM_SECKEY: &str = "phantom-cloud:team_seckey";

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

/// Load the user's long-lived team-vault X25519 keypair, generating
/// and persisting one in the OS keychain on first call. The private key
/// never leaves the keychain.
pub fn get_or_create_team_keypair() -> Result<crate::team_crypto::MemberKeypair> {
    let pub_entry = keyring::Entry::new(KEYCHAIN_SERVICE, TEAM_PUBKEY)
        .map_err(|e| PhantomError::AuthError(format!("Keychain error: {e}")))?;
    let sec_entry = keyring::Entry::new(KEYCHAIN_SERVICE, TEAM_SECKEY)
        .map_err(|e| PhantomError::AuthError(format!("Keychain error: {e}")))?;

    if let (Ok(pub_b64), Ok(sec_b64)) = (pub_entry.get_password(), sec_entry.get_password()) {
        return crate::team_crypto::MemberKeypair::from_base64(&pub_b64, &sec_b64);
    }

    // First use — generate and persist.
    //
    // Write the private key FIRST. If we crash between the two writes,
    // the keychain ends up with a private key but no public key — the
    // next load() call sees the public-key fetch fail, falls into this
    // generate-and-persist branch, and overwrites the orphan privkey
    // with a fresh pair. Doing it the other way round (pub first) leaves
    // the keychain with a public key whose private key never existed,
    // and any vault key shares already encrypted to that pubkey become
    // permanently unrecoverable on this machine.
    let kp = crate::team_crypto::MemberKeypair::generate();
    sec_entry
        .set_password(&kp.secret_b64())
        .map_err(|e| PhantomError::AuthError(format!("Failed to store team seckey: {e}")))?;
    pub_entry
        .set_password(&kp.public_b64())
        .map_err(|e| PhantomError::AuthError(format!("Failed to store team pubkey: {e}")))?;
    Ok(kp)
}

/// Get the API base URL from env var or default.
///
/// The default is `https://phm.dev/api/v1`. Callers can override with
/// `PHANTOM_API_URL`, but only `https://…`, `http://localhost…`, or
/// `http://127.0.0.1…` are accepted — anything else is rejected with
/// [`PhantomError::AuthError`] to prevent a prompt-injected agent from
/// redirecting the OAuth bearer token or the encrypted vault blob to an
/// attacker-controlled host over cleartext.
///
/// When an override is active the resolved URL is echoed to stderr so it's
/// impossible to miss in the user's terminal.
pub fn api_base_url() -> Result<String> {
    const DEFAULT: &str = "https://phm.dev/api/v1";
    match std::env::var("PHANTOM_API_URL") {
        Err(_) => Ok(DEFAULT.to_string()),
        Ok(url) => {
            if !is_acceptable_api_url(&url) {
                return Err(PhantomError::AuthError(format!(
                    "PHANTOM_API_URL must use https:// (or http://localhost / http://127.0.0.1 for local testing). Got: {url}"
                )));
            }
            eprintln!("phantom: PHANTOM_API_URL override in effect -> {url}");
            Ok(url)
        }
    }
}

fn is_acceptable_api_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://localhost/")
        || url == "http://localhost"
        || url.starts_with("http://localhost:")
        || url.starts_with("http://127.0.0.1/")
        || url == "http://127.0.0.1"
        || url.starts_with("http://127.0.0.1:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_default_shape() {
        assert!(is_acceptable_api_url("https://phm.dev/api/v1"));
        assert!(is_acceptable_api_url("https://example.com"));
    }

    #[test]
    fn accepts_local_http_for_tests() {
        assert!(is_acceptable_api_url("http://localhost"));
        assert!(is_acceptable_api_url("http://localhost:8080/api"));
        assert!(is_acceptable_api_url("http://localhost/api"));
        assert!(is_acceptable_api_url("http://127.0.0.1"));
        assert!(is_acceptable_api_url("http://127.0.0.1:3000"));
        assert!(is_acceptable_api_url("http://127.0.0.1/api/v1"));
    }

    #[test]
    fn rejects_plain_http() {
        assert!(!is_acceptable_api_url("http://phm.dev/api/v1"));
        assert!(!is_acceptable_api_url("http://example.com"));
        assert!(!is_acceptable_api_url("http://192.0.2.5:8080/api"));
    }

    #[test]
    fn rejects_localhost_host_confusion() {
        // These look like localhost but are attacker-controlled hostnames.
        assert!(!is_acceptable_api_url("http://localhost.attacker.com/api"));
        assert!(!is_acceptable_api_url("http://127.0.0.1.attacker.com/"));
        assert!(!is_acceptable_api_url("http://localhost@attacker.com/"));
    }

    #[test]
    fn rejects_garbage_schemes() {
        assert!(!is_acceptable_api_url("ftp://phm.dev"));
        assert!(!is_acceptable_api_url("javascript:alert(1)"));
        assert!(!is_acceptable_api_url(""));
    }
}
