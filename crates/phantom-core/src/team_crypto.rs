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
    /// Share format version. Absent on every share written before the tag
    /// existed (treated as v1) and omitted from the wire unless tagging is
    /// enabled (`PHANTOM_BLOB_FORMAT=v2`), so default output is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<u8>,
    /// Algorithm label. Readers accept it absent (every share written so far)
    /// or equal to [`CLASSIC_SHARE_ALG`], and reject any other value. Writers
    /// do not emit it yet, so the wire format is unchanged; v0.7.9 readers
    /// ignore unknown fields, so a later writer can add it compatibly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

/// Algorithm label of the classic share (X25519 + XChaCha20-Poly1305 box).
pub const CLASSIC_SHARE_ALG: &str = "x25519-xchacha20poly1305";

/// Highest share format version this build can open.
pub const SHARE_VERSION_MAX: u8 = crate::blob_format::VERSION_2;

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
    seal_sym_key_with(
        sym_key,
        recipient_pub_b64,
        crate::blob_format::WriteFormat::from_env(),
    )
}

/// Like [`seal_sym_key`] with an explicit share format.
pub fn seal_sym_key_with(
    sym_key: &[u8; 32],
    recipient_pub_b64: &str,
    format: crate::blob_format::WriteFormat,
) -> Result<KeyShare> {
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
        v: match format {
            crate::blob_format::WriteFormat::Legacy => None,
            crate::blob_format::WriteFormat::Tagged => Some(crate::blob_format::VERSION_2),
        },
        alg: None,
    })
}

/// Recover the symmetric key from a share intended for `me`.
pub fn open_sym_key(share: &KeyShare, me: &MemberKeypair) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(alg) = share.alg.as_deref() {
        if alg != CLASSIC_SHARE_ALG {
            return Err(PhantomError::AuthError(format!(
                "Unsupported key share algorithm {alg:?}; upgrade phantom"
            )));
        }
    }
    if let Some(v) = share.v {
        if v == 0 || v > SHARE_VERSION_MAX {
            return Err(PhantomError::AuthError(format!(
                "Unsupported key share version {v}; upgrade phantom"
            )));
        }
    }
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

    /// A share JSON written before the version tag existed (no `v` field).
    #[test]
    fn legacy_share_json_without_v_still_opens() {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();
        let share = seal_sym_key_with(
            &sym_key,
            &alice.public_b64(),
            crate::blob_format::WriteFormat::Legacy,
        )
        .unwrap();
        let json = serde_json::to_string(&share).unwrap();
        assert!(
            !json.contains("\"v\""),
            "legacy wire format must not change: {json}"
        );
        let parsed: KeyShare = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.v, None);
        assert_eq!(*open_sym_key(&parsed, &alice).unwrap(), *sym_key);
    }

    #[test]
    fn tagged_share_round_trips_and_carries_version() {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();
        let share = seal_sym_key_with(
            &sym_key,
            &alice.public_b64(),
            crate::blob_format::WriteFormat::Tagged,
        )
        .unwrap();
        assert_eq!(share.v, Some(2));
        let json = serde_json::to_string(&share).unwrap();
        let parsed: KeyShare = serde_json::from_str(&json).unwrap();
        assert_eq!(*open_sym_key(&parsed, &alice).unwrap(), *sym_key);
    }

    #[test]
    fn unknown_share_version_is_rejected_clearly() {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();
        let mut share = seal_sym_key_with(
            &sym_key,
            &alice.public_b64(),
            crate::blob_format::WriteFormat::Legacy,
        )
        .unwrap();
        share.v = Some(99);
        let err = open_sym_key(&share, &alice).unwrap_err().to_string();
        assert!(err.contains("Unsupported key share version 99"), "{err}");
    }

    #[test]
    fn share_version_zero_is_rejected() {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();
        let mut share = seal_sym_key_with(
            &sym_key,
            &alice.public_b64(),
            crate::blob_format::WriteFormat::Legacy,
        )
        .unwrap();
        share.v = Some(0);
        let err = open_sym_key(&share, &alice).unwrap_err().to_string();
        assert!(err.contains("Unsupported key share version 0"), "{err}");
    }

    #[test]
    fn keypair_with_one_wrong_length_half_is_rejected_without_panic() {
        let kp = MemberKeypair::generate();
        // Runtime-derived 31-byte halves (no constant key material).
        let short_secret = B64.encode(&B64.decode(kp.secret_b64()).unwrap()[..31]);
        let short_public = B64.encode(&B64.decode(kp.public_b64()).unwrap()[..31]);
        for (public, secret) in [
            (kp.public_b64(), short_secret),
            (short_public, kp.secret_b64()),
        ] {
            let err = MemberKeypair::from_base64(&public, &secret)
                .err()
                .expect("wrong-length half must be rejected")
                .to_string();
            assert!(err.contains("32 bytes"), "{err}");
        }
    }

    /// Hand-made share JSON: a real legacy share with `alg` added by hand.
    fn share_json_with_alg(alg: &str) -> (MemberKeypair, Zeroizing<[u8; 32]>, String) {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();
        let share = seal_sym_key_with(
            &sym_key,
            &alice.public_b64(),
            crate::blob_format::WriteFormat::Legacy,
        )
        .unwrap();
        let json = format!(
            r#"{{"ephemeral_pk":"{}","nonce":"{}","ciphertext":"{}","alg":"{alg}"}}"#,
            share.ephemeral_pk, share.nonce, share.ciphertext
        );
        (alice, sym_key, json)
    }

    #[test]
    fn share_with_classic_alg_label_opens() {
        let (alice, sym_key, json) = share_json_with_alg(CLASSIC_SHARE_ALG);
        let parsed: KeyShare = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.alg.as_deref(), Some(CLASSIC_SHARE_ALG));
        assert_eq!(*open_sym_key(&parsed, &alice).unwrap(), *sym_key);
    }

    #[test]
    fn share_with_unknown_or_hybrid_alg_label_is_rejected() {
        for alg in ["xwing-chacha20poly1305", "x25519-xchacha20poly1305-v9", ""] {
            let (alice, _, json) = share_json_with_alg(alg);
            let parsed: KeyShare = serde_json::from_str(&json).unwrap();
            let err = open_sym_key(&parsed, &alice).unwrap_err().to_string();
            assert!(
                err.contains("Unsupported key share algorithm"),
                "{alg}: {err}"
            );
        }
    }

    /// Writers must not change: pin the exact JSON keys and decoded sizes of
    /// both write formats (the values are random, the structure is not).
    #[test]
    fn share_writer_output_structure_is_unchanged() {
        let alice = MemberKeypair::generate();
        let sym_key = generate_sym_key();
        for (format, want_keys) in [
            (
                crate::blob_format::WriteFormat::Legacy,
                vec!["ciphertext", "ephemeral_pk", "nonce"],
            ),
            (
                crate::blob_format::WriteFormat::Tagged,
                vec!["ciphertext", "ephemeral_pk", "nonce", "v"],
            ),
        ] {
            let share = seal_sym_key_with(&sym_key, &alice.public_b64(), format).unwrap();
            let value = serde_json::to_value(&share).unwrap();
            let mut keys: Vec<&str> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, want_keys);
            let len = |k: &str| B64.decode(value[k].as_str().unwrap()).unwrap().len();
            assert_eq!(
                (len("ephemeral_pk"), len("nonce"), len("ciphertext")),
                (32, 24, 48)
            );
            if want_keys.contains(&"v") {
                assert_eq!(value["v"], 2);
            }
            // Field order on the wire is unchanged too.
            let json = serde_json::to_string(&share).unwrap();
            assert!(json.starts_with(r#"{"ephemeral_pk":""#), "{json}");
        }
    }
}
