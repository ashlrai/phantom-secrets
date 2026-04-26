//! High-level team-vault flow used by the CLI and the MCP server.
//!
//! The CLI's `phantom team vault-push` and the MCP server's
//! `phantom_team_vault_push` were near-identical 80-line duplicates of
//! the same crypto + wire-protocol logic. This module owns the flow
//! once. Each surface becomes a thin wrapper that handles output
//! formatting and the confirm gate; everything below the network is
//! tested in one place.
//!
//! Wire format on the encrypted_blob field is `nonce(12) || ciphertext`,
//! base64-encoded. Symmetric encryption is ChaCha20-Poly1305 with a
//! fresh per-push key; the symmetric key is wrapped (X25519 +
//! ChaCha20-Poly1305) for every member with a registered public key
//! via `team_crypto::seal_sym_key`. Server only ever sees ciphertext.

use crate::error::{PhantomError, Result};
use crate::team_crypto::{self, KeyShare, MemberKeypair};
use crate::teams;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use std::collections::{BTreeMap, HashMap};
use zeroize::{Zeroize, Zeroizing};

/// 12-byte ChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 12;
/// Minimum framed-blob length: nonce + Poly1305 tag (16) + at least 0
/// bytes of ciphertext. Anything shorter cannot be a valid encryption.
pub const MIN_FRAMED_LEN: usize = NONCE_LEN + 16;

/// Result of a push.
pub struct PushOutcome {
    pub new_version: u64,
    pub recipients: usize,
    /// Members of the team who don't yet have a registered public key
    /// and were therefore excluded from this push.
    pub skipped: usize,
    pub secret_count: usize,
}

/// Result of a pull.
pub struct PullOutcome {
    pub version: u64,
    pub written: usize,
}

/// Encrypt `secrets` with a fresh symmetric key, wrap that key for every
/// team member with a registered public key, and push to the team's
/// shared vault.
///
/// Takes ownership of `secrets` and zeroizes every value before return,
/// regardless of success or failure.
///
/// Always re-registers the caller's public key — cheap, keeps
/// `team_members.public_key` in sync if it has rotated since the last
/// push.
pub async fn push_for_project(
    api_base: &str,
    token: &str,
    team_id: &str,
    project_id: &str,
    mut secrets: BTreeMap<String, Zeroizing<String>>,
    kp: &MemberKeypair,
) -> Result<PushOutcome> {
    let outcome = push_inner(api_base, token, team_id, project_id, &secrets, kp).await;
    // Zeroize secret values regardless of outcome — they were copied
    // out of the source vault and should not survive on the heap.
    for v in secrets.values_mut() {
        v.zeroize();
    }
    outcome
}

async fn push_inner(
    api_base: &str,
    token: &str,
    team_id: &str,
    project_id: &str,
    secrets: &BTreeMap<String, Zeroizing<String>>,
    kp: &MemberKeypair,
) -> Result<PushOutcome> {
    if secrets.is_empty() {
        return Err(PhantomError::Other(
            "No secrets to push — the local vault is empty.".to_string(),
        ));
    }

    // Auto-register our key — keeps team_members.public_key in sync.
    teams::register_team_key(api_base, token, team_id, &kp.public_b64()).await?;

    let members = teams::list_team_member_keys(api_base, token, team_id).await?;
    let recipients: Vec<&teams::TeamMemberKey> =
        members.iter().filter(|m| m.public_key.is_some()).collect();
    if recipients.is_empty() {
        return Err(PhantomError::Other(format!(
            "No team members have registered public keys yet. \
             Each member should run `phantom team key-publish {team_id}` first."
        )));
    }
    let skipped = members.len() - recipients.len();

    // Serialise the secrets to JSON. We build the input as
    // BTreeMap<&str, &str> so we never hand serde_json an owned String
    // it might keep around — every byte stays in our control.
    let plaintext_view: BTreeMap<&str, &str> = secrets
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut plaintext = serde_json::to_string(&plaintext_view)
        .map_err(|e| PhantomError::Other(format!("Serialize failed: {e}")))?;

    // Per-push 32-byte symmetric key, never reused.
    let sym_key = team_crypto::generate_sym_key();
    let cipher = ChaCha20Poly1305::new(sym_key.as_slice().into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| PhantomError::Other(format!("Encrypt failed: {e}")))?;
    plaintext.zeroize();

    let mut framed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    framed.extend_from_slice(&nonce_bytes);
    framed.extend_from_slice(&ciphertext);
    let blob_b64 = B64.encode(&framed);

    // Wrap the symmetric key for each recipient.
    let mut shares: HashMap<String, KeyShare> = HashMap::new();
    for m in &recipients {
        let share = team_crypto::seal_sym_key(&sym_key, m.public_key.as_ref().unwrap())?;
        shares.insert(m.user_id.clone(), share);
    }

    let new_version = teams::push_team_vault(
        api_base, token, team_id, project_id, &blob_b64, None, shares,
    )
    .await?;

    Ok(PushOutcome {
        new_version,
        recipients: recipients.len(),
        skipped,
        secret_count: secrets.len(),
    })
}

/// Pull the team vault for `project_id`, decrypt the caller's key share
/// with their private key, decrypt the vault blob, and return the
/// decrypted secret map.
///
/// Caller is responsible for writing the returned secrets into a vault
/// (or whatever destination they want) and zeroizing them afterwards.
/// The returned map's values are `Zeroizing<String>` so they're scrubbed
/// when dropped.
pub async fn pull_for_project(
    api_base: &str,
    token: &str,
    team_id: &str,
    project_id: &str,
    kp: &MemberKeypair,
) -> Result<(BTreeMap<String, Zeroizing<String>>, u64)> {
    let pulled = teams::pull_team_vault(api_base, token, team_id, project_id)
        .await?
        .ok_or_else(|| {
            PhantomError::Other(format!(
                "No team vault for project {project_id} on team {team_id}. \
                 Push from a member first."
            ))
        })?;

    let sym_key = team_crypto::open_sym_key(&pulled.my_share, kp)?;
    let framed = B64
        .decode(&pulled.encrypted_blob)
        .map_err(|e| PhantomError::Other(format!("Bad ciphertext base64: {e}")))?;
    if framed.len() < MIN_FRAMED_LEN {
        return Err(PhantomError::Other(
            "Encrypted blob too short to be valid".to_string(),
        ));
    }
    let (nonce_bytes, ct) = framed.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(sym_key.as_slice().into());
    let mut plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| PhantomError::Other(format!("Decrypt failed: {e}")))?;

    let raw: BTreeMap<String, String> = serde_json::from_slice(&plaintext)
        .map_err(|e| PhantomError::Other(format!("Bad vault JSON: {e}")))?;
    plaintext.zeroize();

    // Move every value into Zeroizing so the secrets are scrubbed when
    // the caller's map is dropped.
    let secrets: BTreeMap<String, Zeroizing<String>> = raw
        .into_iter()
        .map(|(k, v)| (k, Zeroizing::new(v)))
        .collect();

    Ok((secrets, pulled.version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_framed_len_matches_chacha_poly_overhead() {
        // 12-byte nonce + 16-byte Poly1305 tag.
        assert_eq!(MIN_FRAMED_LEN, 28);
    }
}
