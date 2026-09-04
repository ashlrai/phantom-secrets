use crate::error::{PhantomError, Result};
use serde::{Deserialize, Serialize};

const KEYCHAIN_SERVICE: &str = "phantom-cloud";
const TOKEN_KEY: &str = "access_token";
const CLOUD_VAULT_KEY_PREFIX: &str = "phantom-cloud:vault_key";
const TEAM_PUBKEY: &str = "phantom-cloud:team_pubkey";
const TEAM_SECKEY: &str = "phantom-cloud:team_seckey";

fn os_keychain_entry(service: &str, account: &str) -> keyring::Result<keyring::Entry> {
    #[cfg(target_os = "linux")]
    {
        // The vault crate also compiles Secret Service support for an explicit,
        // per-project migration. Cargo feature unification must never change
        // pre-existing cloud credentials from keyutils to a different store.
        let credential =
            keyring::keyutils::KeyutilsCredential::new_with_target(None, service, account)?;
        return Ok(keyring::Entry::new_with_credential(Box::new(credential)));
    }
    #[cfg(not(target_os = "linux"))]
    {
        keyring::Entry::new(service, account)
    }
}

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
    let client = crate::cloud_http::client()?;
    let resp = client
        .post(format!("{api_base}/auth/device/initiate"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|_| PhantomError::AuthError("Failed to connect to Phantom Cloud".to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(crate::cloud_http::response_error(
            status,
            "Device authorization initiation",
            "Phantom Cloud rejected the request",
        ));
    }

    let status = resp.status().as_u16();
    let bytes =
        crate::cloud_http::read_bounded_response(resp, "Device authorization initiation").await?;
    crate::cloud_http::parse_json(&bytes, status, "Device authorization initiation")
}

/// Poll for device approval. Returns the access token once approved.
pub async fn poll_for_token(api_base: &str, device_code: &str) -> Result<PollResponse> {
    let client = crate::cloud_http::client()?;
    let resp = client
        .post(format!("{api_base}/auth/device/poll"))
        .json(&serde_json::json!({ "device_code": device_code }))
        .send()
        .await
        .map_err(|_| PhantomError::AuthError("Device authorization poll failed".to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(crate::cloud_http::response_error(
            status,
            "Device authorization poll",
            "Phantom Cloud rejected the request",
        ));
    }

    let status = resp.status().as_u16();
    let bytes = crate::cloud_http::read_bounded_response(resp, "Device authorization poll").await?;
    crate::cloud_http::parse_json(&bytes, status, "Device authorization poll")
}

/// Get current user info from the API.
pub async fn get_user_info(api_base: &str, token: &str) -> Result<UserInfo> {
    let client = crate::cloud_http::client()?;
    let resp = client
        .get(format!("{api_base}/me"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| PhantomError::AuthError("Failed to connect to Phantom Cloud".to_string()))?;

    if resp.status().as_u16() == 401 {
        return Err(PhantomError::AuthRequired);
    }

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(crate::cloud_http::response_error(
            status,
            "Phantom Cloud account lookup",
            "Phantom Cloud rejected the request",
        ));
    }

    let status = resp.status().as_u16();
    let bytes =
        crate::cloud_http::read_bounded_response(resp, "Phantom Cloud account lookup").await?;
    crate::cloud_http::parse_json(&bytes, status, "Phantom Cloud account lookup")
}

/// Store the access token in the OS keychain.
pub fn store_token(token: &str) -> Result<()> {
    let entry = os_keychain_entry(KEYCHAIN_SERVICE, TOKEN_KEY)
        .map_err(|e| PhantomError::AuthError(format!("Keychain error: {e}")))?;
    entry
        .set_password(token)
        .map_err(|e| PhantomError::AuthError(format!("Failed to store token: {e}")))?;
    Ok(())
}

/// Load the access token from the OS keychain.
pub fn load_token() -> Option<String> {
    let entry = os_keychain_entry(KEYCHAIN_SERVICE, TOKEN_KEY).ok()?;
    entry.get_password().ok()
}

/// Require an access token, returning AuthRequired error if not found.
pub fn require_token() -> Result<String> {
    load_token().ok_or(PhantomError::AuthRequired)
}

/// Clear the access token from the OS keychain.
pub fn clear_token() -> Result<()> {
    if let Ok(entry) = os_keychain_entry(KEYCHAIN_SERVICE, TOKEN_KEY) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

/// Get or create a cloud vault encryption passphrase.
/// Stored in OS keychain — never transmitted to the server.
pub fn get_or_create_cloud_passphrase() -> Result<String> {
    let entry = os_keychain_entry(KEYCHAIN_SERVICE, CLOUD_VAULT_KEY_PREFIX)
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
    let pub_entry = os_keychain_entry(KEYCHAIN_SERVICE, TEAM_PUBKEY)
        .map_err(|e| PhantomError::AuthError(format!("Keychain error: {e}")))?;
    let sec_entry = os_keychain_entry(KEYCHAIN_SERVICE, TEAM_SECKEY)
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

/// Return the only origin allowed to receive Phantom Cloud credentials.
///
/// This must not be runtime-configurable. Environment variables are inside an
/// agent's authority in common coding workflows; accepting an alternate host
/// here would let prompt-injected code redirect a keychain bearer or encrypted
/// team-vault payload away from Phantom Cloud. Network-level integration tests
/// should exercise the lower-level request helpers with an explicit URL and a
/// test-only bearer instead of changing this production credential boundary.
pub fn api_base_url() -> Result<String> {
    const DEFAULT: &str = "https://phm.dev/api/v1";
    if std::env::var_os("PHANTOM_API_URL").is_some() {
        return Err(PhantomError::AuthError(
            "PHANTOM_API_URL overrides are disabled because Phantom Cloud credentials may only be sent to https://phm.dev"
                .to_string(),
        ));
    }
    Ok(DEFAULT.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_the_canonical_phantom_cloud_origin() {
        assert_eq!(api_base_url().unwrap(), "https://phm.dev/api/v1");
    }
}
