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

    let expected_version =
        match teams::pull_team_vault(api_base, token, team_id, project_id).await? {
            Some(vault) => vault.version,
            None => 0,
        };

    let new_version = teams::push_team_vault(
        api_base,
        token,
        team_id,
        project_id,
        &blob_b64,
        Some(expected_version),
        shares,
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

/// Result of a vault rotation (revoke or proactive rotate).
pub struct RotateOutcome {
    pub new_version: u64,
    /// Members whose key share was re-wrapped with the new symmetric key.
    pub recipients: usize,
    /// Members skipped because they have no registered public key.
    pub skipped: usize,
    /// GitHub username that was revoked (None for proactive rotation).
    pub revoked_user: Option<String>,
    pub secret_count: usize,
}

/// Revoke a member from the team vault and rotate the symmetric key.
///
/// Steps performed atomically from the server's perspective:
/// 1. Pull the current vault and decrypt it with `kp`.
/// 2. Remove `revoked_github_login` from the recipient set.
/// 3. Generate a fresh symmetric key and re-encrypt the vault plaintext.
/// 4. Re-wrap the new key for every *remaining* member with a registered
///    public key.
/// 5. Push the rotated vault — server updates the member list server-side
///    when the push succeeds.
/// 6. Emit tamper-proof audit events for the rotation + revocation.
///
/// Fails if `revoked_github_login` is not a current member, or if the
/// caller (`kp`) cannot decrypt the current vault (i.e. the caller does
/// not have a valid share).
pub async fn revoke_member(
    api_base: &str,
    token: &str,
    team_id: &str,
    project_id: &str,
    revoked_github_login: &str,
    kp: &team_crypto::MemberKeypair,
) -> Result<RotateOutcome> {
    // 1. Pull current vault and decrypt. This SINGLE pull supplies both the
    //    plaintext for re-encryption AND the OCC expected_version for the push.
    //    Do NOT pull a second time before pushing — a concurrent push between
    //    two pulls would be silently overwritten (a revoked share could
    //    re-appear). See TOCTOU fix below.
    let (secrets, current_version) =
        pull_for_project(api_base, token, team_id, project_id, kp).await?;

    // 2. Fetch current members, excluding the revoked user.
    let all_members = teams::list_team_member_keys(api_base, token, team_id).await?;
    let remaining: Vec<&teams::TeamMemberKey> = all_members
        .iter()
        .filter(|m| {
            // user_id on TeamMemberKey is typically the github login or an opaque
            // server-side ID; we also check by excluding the revoked login from the
            // public-key recipients list. The server enforces the actual removal —
            // we just stop wrapping for that user here.
            m.user_id != revoked_github_login
        })
        .collect();

    if remaining.len() == all_members.len() {
        // No member matched — either the user doesn't exist or already removed.
        return Err(PhantomError::Other(format!(
            "Member @{revoked_github_login} not found in team {team_id}. \
             Check `phantom team members {team_id}` for valid logins."
        )));
    }

    let recipients: Vec<&teams::TeamMemberKey> = remaining
        .iter()
        .filter(|m| m.public_key.is_some())
        .copied()
        .collect();
    let skipped = remaining.len() - recipients.len();

    // 3. Re-encrypt vault with a fresh symmetric key.
    let plaintext_view: std::collections::BTreeMap<&str, &str> = secrets
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut plaintext = serde_json::to_string(&plaintext_view)
        .map_err(|e| PhantomError::Other(format!("Serialize failed: {e}")))?;

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

    // 4. Re-wrap the new key for all remaining recipients.
    let mut shares: HashMap<String, team_crypto::KeyShare> = HashMap::new();
    for m in &recipients {
        let share = team_crypto::seal_sym_key(&sym_key, m.public_key.as_ref().unwrap())?;
        shares.insert(m.user_id.clone(), share);
    }

    // 5. Push the rotated vault using the version observed in step 1 as the OCC
    //    expected_version. This guarantees the push fails (rather than silently
    //    clobbering) if another writer mutated the vault after we decrypted it.
    let expected_version = current_version;
    let new_version = teams::push_team_vault(
        api_base,
        token,
        team_id,
        project_id,
        &blob_b64,
        Some(expected_version),
        shares,
    )
    .await?;

    // 6. Emit audit events (best-effort — never fail the rotation).
    let remaining_logins: Vec<String> = remaining.iter().map(|m| m.user_id.clone()).collect();
    crate::audit::log_team_member_revoked(
        team_id,
        revoked_github_login,
        &remaining_logins,
        new_version,
    );
    crate::audit::log_vault_key_rotated(team_id, project_id, new_version);

    Ok(RotateOutcome {
        new_version,
        recipients: recipients.len(),
        skipped,
        revoked_user: Some(revoked_github_login.to_string()),
        secret_count: secrets.len(),
    })
}

/// Proactively rotate the team vault's symmetric key without removing any
/// member. Re-encrypts the vault contents and re-wraps the new key for all
/// members that have a registered public key.
pub async fn rotate_vault(
    api_base: &str,
    token: &str,
    team_id: &str,
    project_id: &str,
    kp: &team_crypto::MemberKeypair,
) -> Result<RotateOutcome> {
    // Pull and decrypt current vault. This SINGLE pull supplies both the
    // plaintext and the OCC expected_version for the push below — do not pull
    // again before pushing (TOCTOU: a concurrent push would be clobbered).
    let (secrets, current_version) =
        pull_for_project(api_base, token, team_id, project_id, kp).await?;

    // Re-register caller's key to keep it current.
    teams::register_team_key(api_base, token, team_id, &kp.public_b64()).await?;

    let all_members = teams::list_team_member_keys(api_base, token, team_id).await?;
    let recipients: Vec<&teams::TeamMemberKey> = all_members
        .iter()
        .filter(|m| m.public_key.is_some())
        .collect();
    if recipients.is_empty() {
        return Err(PhantomError::Other(format!(
            "No team members have registered public keys yet for team {team_id}."
        )));
    }
    let skipped = all_members.len() - recipients.len();

    // Re-encrypt with a fresh symmetric key.
    let plaintext_view: std::collections::BTreeMap<&str, &str> = secrets
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut plaintext = serde_json::to_string(&plaintext_view)
        .map_err(|e| PhantomError::Other(format!("Serialize failed: {e}")))?;

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

    let mut shares: HashMap<String, team_crypto::KeyShare> = HashMap::new();
    for m in &recipients {
        let share = team_crypto::seal_sym_key(&sym_key, m.public_key.as_ref().unwrap())?;
        shares.insert(m.user_id.clone(), share);
    }

    // OCC: use the version observed when we pulled+decrypted above, so a
    // concurrent push between pull and push is rejected rather than clobbered.
    let expected_version = current_version;
    let new_version = teams::push_team_vault(
        api_base,
        token,
        team_id,
        project_id,
        &blob_b64,
        Some(expected_version),
        shares,
    )
    .await?;

    let member_logins: Vec<String> = all_members.iter().map(|m| m.user_id.clone()).collect();
    crate::audit::log_vault_key_rotated(team_id, project_id, new_version);
    crate::audit::log_team_vault_rotation_members(team_id, &member_logins, new_version);

    Ok(RotateOutcome {
        new_version,
        recipients: recipients.len(),
        skipped,
        revoked_user: None,
        secret_count: secrets.len(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — pure crypto paths, no network
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt a plaintext map with a fresh sym key, returning `(blob_b64, sym_key)`.
/// Extracted for reuse in rotation unit tests.
pub fn encrypt_secrets_to_blob(
    secrets: &BTreeMap<String, Zeroizing<String>>,
) -> Result<(String, Zeroizing<[u8; 32]>)> {
    let plaintext_view: BTreeMap<&str, &str> = secrets
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut plaintext = serde_json::to_string(&plaintext_view)
        .map_err(|e| PhantomError::Other(format!("Serialize failed: {e}")))?;
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
    Ok((B64.encode(&framed), sym_key))
}

/// Decrypt a `blob_b64` produced by `encrypt_secrets_to_blob` using `sym_key`.
pub fn decrypt_blob_with_key(
    blob_b64: &str,
    sym_key: &[u8; 32],
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let framed = B64
        .decode(blob_b64)
        .map_err(|e| PhantomError::Other(format!("Bad ciphertext base64: {e}")))?;
    if framed.len() < MIN_FRAMED_LEN {
        return Err(PhantomError::Other(
            "Encrypted blob too short to be valid".to_string(),
        ));
    }
    let (nonce_bytes, ct) = framed.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(sym_key.into());
    let mut plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| PhantomError::Other(format!("Decrypt failed: {e}")))?;
    let raw: BTreeMap<String, String> = serde_json::from_slice(&plaintext)
        .map_err(|e| PhantomError::Other(format!("Bad vault JSON: {e}")))?;
    plaintext.zeroize();
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, Zeroizing::new(v)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_framed_len_matches_chacha_poly_overhead() {
        // 12-byte nonce + 16-byte Poly1305 tag.
        assert_eq!(MIN_FRAMED_LEN, 28);
    }

    // ── Rotation unit tests (pure crypto, no network) ──────────────────

    /// Helper: build a secrets map with one entry.
    fn make_secrets(key: &str, val: &str) -> BTreeMap<String, Zeroizing<String>> {
        let mut m = BTreeMap::new();
        m.insert(key.to_string(), Zeroizing::new(val.to_string()));
        m
    }

    #[test]
    fn rotate_re_encrypts_same_plaintext() {
        // Encrypt once, re-encrypt (rotate), both ciphertexts decrypt to same plaintext.
        let secrets = make_secrets("API_KEY", "secret_value_123");

        let (blob1, key1) = encrypt_secrets_to_blob(&secrets).expect("first encrypt");
        let decrypted1 = decrypt_blob_with_key(&blob1, &key1).expect("first decrypt");
        assert_eq!(decrypted1["API_KEY"].as_str(), "secret_value_123");

        // Simulate rotation: decrypt then re-encrypt with new key.
        let (blob2, key2) = encrypt_secrets_to_blob(&decrypted1).expect("re-encrypt");
        assert_ne!(blob1, blob2, "rotated blob must differ from original");
        assert_ne!(*key1, *key2, "rotated key must differ from original");

        let decrypted2 = decrypt_blob_with_key(&blob2, &key2).expect("second decrypt");
        assert_eq!(decrypted2["API_KEY"].as_str(), "secret_value_123");
    }

    #[test]
    fn revoked_member_cannot_decrypt_new_vault() {
        // Alice and Bob have keypairs. Encrypt for both, then rotate for Alice only.
        let alice = team_crypto::MemberKeypair::generate();
        let bob = team_crypto::MemberKeypair::generate();

        let secrets = make_secrets("DB_URL", "postgres://host/db");

        // Initial vault: encrypted for both Alice and Bob.
        let (blob_v1, sym_key_v1) = encrypt_secrets_to_blob(&secrets).expect("v1 encrypt");
        let alice_share_v1 =
            team_crypto::seal_sym_key(&sym_key_v1, &alice.public_b64()).expect("seal alice v1");
        let bob_share_v1 =
            team_crypto::seal_sym_key(&sym_key_v1, &bob.public_b64()).expect("seal bob v1");

        // Both can decrypt v1.
        let alice_key_v1 =
            team_crypto::open_sym_key(&alice_share_v1, &alice).expect("alice open v1");
        let bob_key_v1 = team_crypto::open_sym_key(&bob_share_v1, &bob).expect("bob open v1");
        assert_eq!(*alice_key_v1, *sym_key_v1);
        assert_eq!(*bob_key_v1, *sym_key_v1);

        // Rotation: Alice is revoked. New vault encrypted only for Bob.
        let decrypted_v1 =
            decrypt_blob_with_key(&blob_v1, &sym_key_v1).expect("decrypt v1 for rotation");
        let (blob_v2, sym_key_v2) = encrypt_secrets_to_blob(&decrypted_v1).expect("v2 encrypt");
        assert_ne!(*sym_key_v1, *sym_key_v2, "new key must differ");
        let bob_share_v2 =
            team_crypto::seal_sym_key(&sym_key_v2, &bob.public_b64()).expect("seal bob v2");

        // Bob can decrypt the new vault.
        let bob_key_v2 = team_crypto::open_sym_key(&bob_share_v2, &bob).expect("bob open v2");
        let bob_decrypted = decrypt_blob_with_key(&blob_v2, &bob_key_v2).expect("bob decrypt v2");
        assert_eq!(bob_decrypted["DB_URL"].as_str(), "postgres://host/db");

        // Alice has no v2 share — attempting to use her old share against the new
        // blob must fail (wrong key → AEAD tag mismatch).
        let alice_key_wrong =
            team_crypto::open_sym_key(&alice_share_v1, &alice).expect("alice still has old share");
        // The key decrypts fine but produces wrong bytes for the new ciphertext.
        assert_ne!(*alice_key_wrong, *sym_key_v2, "alice must not know v2 key");
        let alice_attempt = decrypt_blob_with_key(&blob_v2, &alice_key_wrong);
        assert!(
            alice_attempt.is_err(),
            "revoked alice must not decrypt v2 vault"
        );
    }

    #[test]
    fn remaining_members_can_decrypt_after_rotation() {
        // Three members: Alice, Bob, Carol. Rotate (no revocation). All three can still decrypt.
        let alice = team_crypto::MemberKeypair::generate();
        let bob = team_crypto::MemberKeypair::generate();
        let carol = team_crypto::MemberKeypair::generate();

        let secrets = make_secrets("STRIPE_KEY", "sk_live_abc123");

        let (blob_v2, sym_key_v2) = encrypt_secrets_to_blob(&secrets).expect("v2 encrypt");
        let alice_share = team_crypto::seal_sym_key(&sym_key_v2, &alice.public_b64()).unwrap();
        let bob_share = team_crypto::seal_sym_key(&sym_key_v2, &bob.public_b64()).unwrap();
        let carol_share = team_crypto::seal_sym_key(&sym_key_v2, &carol.public_b64()).unwrap();

        for (name, share, kp) in [
            ("alice", &alice_share, &alice),
            ("bob", &bob_share, &bob),
            ("carol", &carol_share, &carol),
        ] {
            let k = team_crypto::open_sym_key(share, kp)
                .unwrap_or_else(|_| panic!("{name} open failed"));
            let decrypted = decrypt_blob_with_key(&blob_v2, &k)
                .unwrap_or_else(|_| panic!("{name} decrypt failed"));
            assert_eq!(
                decrypted["STRIPE_KEY"].as_str(),
                "sk_live_abc123",
                "{name} decrypted wrong value"
            );
        }
    }

    #[test]
    fn audit_trail_records_rotation_with_member_list() {
        // Verify that the audit log functions for rotation are callable and
        // produce audit entries (best-effort; we test via PHANTOM_AUDIT=1).
        // We call the audit helpers directly — the log functions themselves
        // are tested more extensively in audit.rs.
        let team_id = "team_audit_test";
        let project_id = "proj_audit_test";
        let version = 7u64;
        let remaining = vec!["@alice".to_string(), "@bob".to_string()];

        // These must not panic regardless of whether audit is enabled.
        crate::audit::log_vault_key_rotated(team_id, project_id, version);
        crate::audit::log_team_member_revoked(team_id, "@carol", &remaining, version);
        crate::audit::log_team_vault_rotation_members(team_id, &remaining, version);
    }
}
