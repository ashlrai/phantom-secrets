//! Envelope encryption for team vaults.
//!
//! Each team member has a long-lived X25519 keypair (private in OS
//! keychain, public stored on `team_members.public_key`). When a member
//! pushes a team vault:
//!
//! 1. A fresh 32-byte symmetric key is generated and used to encrypt the
//!    vault plaintext via ChaCha20-Poly1305 (already used elsewhere).
//! 2. For each team member's public key, an *ephemeral* X25519 keypair
//!    is generated and combined with the recipient's pubkey via the
//!    `crypto_box` ChaCha20-Poly1305 authenticated-DH primitive to
//!    encrypt the symmetric key. The ephemeral pubkey + nonce + the
//!    encrypted symmetric key are stored as that member's "share".
//! 3. Recipients decrypt their share with their own private key, recover
//!    the symmetric key, and decrypt the vault.
//!
//! Properties:
//! - Server only ever stores ciphertext + per-recipient ciphertext shares.
//! - Forward secrecy per push: ephemeral sender keys are not reused.
//! - Recipients can be added later by republishing (re-encrypting the
//!   sym key to the new member's pubkey). No re-keying of the team
//!   itself required.
//! - Zeroizes the symmetric key on drop.

use crate::error::{PhantomError, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto_box::{
    aead::{Aead, AeadCore},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A wire-format encrypted-key share for one recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Ephemeral sender public key (base64). Fresh per push.
    pub ephemeral_pk: String,
    /// 24-byte XChaCha20-Poly1305 nonce (base64).
    pub nonce: String,
    /// Encrypted 32-byte symmetric key (base64).
    pub ciphertext: String,
}

/// A long-lived team-member keypair. Private key stays on the member's
/// machine in the OS keychain; public key is written to the server so
/// other members can encrypt to it.
pub struct MemberKeypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl MemberKeypair {
    /// Generate a fresh keypair using the OS RNG.
    pub fn generate() -> Self {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        Self { public, secret }
    }

    /// Decode a keypair from base64-encoded private/public bytes.
    /// The decoded private-key bytes are kept inside `Zeroizing` so the
    /// stack copy is scrubbed on every exit path before returning.
    pub fn from_base64(public_b64: &str, secret_b64: &str) -> Result<Self> {
        let pub_bytes = B64
            .decode(public_b64)
            .map_err(|e| PhantomError::AuthError(format!("Bad team public key: {e}")))?;
        let sec_bytes = Zeroizing::new(
            B64.decode(secret_b64)
                .map_err(|e| PhantomError::AuthError(format!("Bad team secret key: {e}")))?,
        );
        if pub_bytes.len() != 32 || sec_bytes.len() != 32 {
            return Err(PhantomError::AuthError(
                "Team key must be 32 bytes".to_string(),
            ));
        }
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes);
        let mut sec_arr = Zeroizing::new([0u8; 32]);
        sec_arr.copy_from_slice(&sec_bytes);
        Ok(Self {
            public: PublicKey::from(pub_arr),
            secret: SecretKey::from(*sec_arr),
        })
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.public.as_bytes())
    }

    /// Base64-encode the private key. The intermediate raw byte array
    /// returned by `to_bytes()` is held in `Zeroizing` so it is scrubbed
    /// from the stack as soon as the encoded string has been produced.
    pub fn secret_b64(&self) -> String {
        let raw = Zeroizing::new(self.secret.to_bytes());
        B64.encode(*raw)
    }
}

/// Generate a fresh 32-byte symmetric key for one push.
pub fn generate_sym_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

/// Encrypt the symmetric key to one recipient's public key. The sender
/// is an ephemeral keypair fresh for this share — not reused.
pub fn seal_sym_key(sym_key: &[u8; 32], recipient_pub_b64: &str) -> Result<KeyShare> {
    let pub_bytes = B64
        .decode(recipient_pub_b64)
        .map_err(|e| PhantomError::AuthError(format!("Bad recipient pubkey: {e}")))?;
    if pub_bytes.len() != 32 {
        return Err(PhantomError::AuthError(
            "Recipient pubkey must be 32 bytes".to_string(),
        ));
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let recipient_pk = PublicKey::from(pub_arr);

    // Fresh ephemeral keypair — never reused.
    let ephemeral_sk = SecretKey::generate(&mut OsRng);
    let ephemeral_pk = ephemeral_sk.public_key();

    let cipher = ChaChaBox::new(&recipient_pk, &ephemeral_sk);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, sym_key.as_slice())
        .map_err(|e| PhantomError::AuthError(format!("Seal failed: {e}")))?;

    Ok(KeyShare {
        ephemeral_pk: B64.encode(ephemeral_pk.as_bytes()),
        nonce: B64.encode(nonce.as_slice()),
        ciphertext: B64.encode(ct),
    })
}

/// Recover the symmetric key from a share intended for `me`.
pub fn open_sym_key(share: &KeyShare, me: &MemberKeypair) -> Result<Zeroizing<[u8; 32]>> {
    let ephemeral_pub_bytes = B64
        .decode(&share.ephemeral_pk)
        .map_err(|e| PhantomError::AuthError(format!("Bad ephemeral pubkey: {e}")))?;
    if ephemeral_pub_bytes.len() != 32 {
        return Err(PhantomError::AuthError(
            "Ephemeral pubkey must be 32 bytes".to_string(),
        ));
    }
    let mut ephemeral_arr = [0u8; 32];
    ephemeral_arr.copy_from_slice(&ephemeral_pub_bytes);
    let ephemeral_pk = PublicKey::from(ephemeral_arr);

    let nonce_bytes = B64
        .decode(&share.nonce)
        .map_err(|e| PhantomError::AuthError(format!("Bad nonce: {e}")))?;
    if nonce_bytes.len() != 24 {
        return Err(PhantomError::AuthError(
            "ChaChaBox nonce must be 24 bytes".to_string(),
        ));
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = B64
        .decode(&share.ciphertext)
        .map_err(|e| PhantomError::AuthError(format!("Bad ciphertext: {e}")))?;

    let cipher = ChaChaBox::new(&ephemeral_pk, &me.secret);
    let plaintext = cipher
        .decrypt(nonce, ct.as_slice())
        .map_err(|e| PhantomError::AuthError(format!("Open failed: {e}")))?;

    if plaintext.len() != 32 {
        return Err(PhantomError::AuthError(
            "Decrypted sym key must be 32 bytes".to_string(),
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sym_key_through_envelope() {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();

        let share = seal_sym_key(&sym_key, &alice.public_b64()).expect("seal");
        let recovered = open_sym_key(&share, &alice).expect("open");

        assert_eq!(*sym_key, *recovered);
    }

    #[test]
    fn share_for_one_member_unreadable_by_another() {
        let alice = MemberKeypair::generate();
        let bob = MemberKeypair::generate();
        let sym_key = generate_sym_key();

        let share_for_bob = seal_sym_key(&sym_key, &bob.public_b64()).expect("seal");
        // Alice tries to open Bob's share with her own key — must fail.
        let result = open_sym_key(&share_for_bob, &alice);
        assert!(result.is_err());
    }

    #[test]
    fn ephemeral_keys_differ_per_push() {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();

        let s1 = seal_sym_key(&sym_key, &alice.public_b64()).expect("seal");
        let s2 = seal_sym_key(&sym_key, &alice.public_b64()).expect("seal");

        // Same plaintext, two seals — ephemeral pubkeys + nonces must differ.
        assert_ne!(s1.ephemeral_pk, s2.ephemeral_pk);
        assert_ne!(s1.nonce, s2.nonce);
    }

    #[test]
    fn keypair_base64_roundtrip() {
        let kp = MemberKeypair::generate();
        let pub_b64 = kp.public_b64();
        let sec_b64 = kp.secret_b64();
        let restored = MemberKeypair::from_base64(&pub_b64, &sec_b64).expect("restore");
        assert_eq!(restored.public.as_bytes(), kp.public.as_bytes());
        assert_eq!(restored.secret.to_bytes(), kp.secret.to_bytes());
    }
}
