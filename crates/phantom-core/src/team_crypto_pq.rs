//! EXPERIMENTAL hybrid post-quantum key share (feature `pq-hybrid`, off by default).
//!
//! Seals a 32-byte team symmetric key to a recipient with X-Wing (X25519 +
//! ML-KEM-768, draft-connolly-cfrg-xwing-kem-06) and wraps it with
//! ChaCha20-Poly1305 under the KEM shared secret. Confidentiality holds if
//! either X25519 or ML-KEM-768 holds.
//!
//! Draft status (checked 2026-10-19): the `x-wing` 0.1.1 crate states it
//! matches draft version 06; the current draft is version 11 (2026-09-23).
//! This build is verified against the draft 11 test vectors: all three
//! vectors in Appendix C of
//! https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.txt are
//! copied verbatim into `tests/fixtures/xwing-draft-11-vectors.json`, and the
//! tests check key generation from `seed` (`pk`), decapsulation (`ss`) and
//! deterministic encapsulation from `eseed` (`ct`, `ss`) byte for byte. CI
//! runs them with `--features pq-hybrid`. The draft 11 change log lists only
//! editorial, ASN.1, PEM and SHAKE-argument notation changes after version
//! 06. The draft is still an Internet-Draft, so re-check on each new revision.
//!
//! WARNING: the `x-wing` and `ml-kem` crates have never been independently
//! audited, and X-Wing is a pre-1.0 draft. Do not rely on this alone.
//!
//! Scope of this slice: library type and tests only. It is not wired into
//! push or pull, and it does not change the classic [`crate::team_crypto`]
//! share or the server protocol. A hybrid share is a separate type so a
//! classic reader can never mistake it for a classic share; downgrade
//! policy (rejecting classic shares) is left to the wiring slice.

use crate::error::{PhantomError, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use x_wing::{
    Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey, Kem, KeyExport,
    XWingKem, CIPHERTEXT_SIZE, ENCAPSULATION_KEY_SIZE,
};
use zeroize::Zeroizing;

/// Algorithm label bound into the AEAD as associated data.
pub const ALG: &str = "xwing-chacha20poly1305";
/// Share format version for the hybrid share.
pub const HYBRID_SHARE_VERSION: u8 = 3;
const AAD: &[u8] = b"phantom-hybrid-share-v3|xwing-chacha20poly1305";

/// Hybrid share for one recipient (wire format, all binary fields base64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKeyShare {
    pub v: u8,
    pub alg: String,
    /// X-Wing ciphertext (1120 bytes).
    pub kem_ct: String,
    /// 12-byte ChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Wrapped 32-byte symmetric key (48 bytes with tag).
    pub ciphertext: String,
}

/// Long-lived hybrid member keypair.
pub struct HybridKeypair {
    sk: DecapsulationKey,
    pk: EncapsulationKey,
}

impl HybridKeypair {
    /// Generate a keypair with the OS RNG.
    pub fn generate() -> Self {
        let (sk, pk) = XWingKem::generate_keypair();
        Self { sk, pk }
    }

    /// Base64 of the 1216-byte encapsulation (public) key.
    pub fn public_b64(&self) -> String {
        B64.encode(self.pk.to_bytes().as_slice())
    }

    /// Rebuild from a 32-byte secret seed (the X-Wing decapsulation key).
    pub fn from_secret_bytes(seed: [u8; 32]) -> Self {
        let sk = DecapsulationKey::from(seed);
        let pk = sk.encapsulation_key().clone();
        Self { sk, pk }
    }

    /// The 32-byte secret seed, zeroized on drop.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.sk.as_bytes())
    }
}

/// Seal `sym_key` to a hybrid recipient public key.
pub fn seal_sym_key_hybrid(sym_key: &[u8; 32], recipient_pub_b64: &str) -> Result<HybridKeyShare> {
    let pk_bytes = B64
        .decode(recipient_pub_b64)
        .map_err(|e| PhantomError::AuthError(format!("Bad hybrid pubkey: {e}")))?;
    if pk_bytes.len() != ENCAPSULATION_KEY_SIZE {
        return Err(PhantomError::AuthError(format!(
            "Hybrid pubkey must be {ENCAPSULATION_KEY_SIZE} bytes"
        )));
    }
    let pk = EncapsulationKey::try_from(pk_bytes.as_slice())
        .map_err(|_| PhantomError::AuthError("Invalid hybrid pubkey".to_string()))?;
    let (ct, shared) = pk.encapsulate();

    let nonce_bytes: [u8; 12] = rand::random();
    let wrapped = ChaCha20Poly1305::new(shared.as_slice().into())
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: sym_key.as_slice(),
                aad: AAD,
            },
        )
        .map_err(|e| PhantomError::AuthError(format!("Hybrid seal failed: {e}")))?;
    Ok(HybridKeyShare {
        v: HYBRID_SHARE_VERSION,
        alg: ALG.to_string(),
        kem_ct: B64.encode(ct.as_slice()),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(wrapped),
    })
}

/// Recover the symmetric key from a hybrid share.
pub fn open_sym_key_hybrid(
    share: &HybridKeyShare,
    me: &HybridKeypair,
) -> Result<Zeroizing<[u8; 32]>> {
    if share.v != HYBRID_SHARE_VERSION || share.alg != ALG {
        return Err(PhantomError::AuthError(format!(
            "Unsupported hybrid share (v{}, alg {}); upgrade phantom",
            share.v, share.alg
        )));
    }
    let ct_bytes = B64
        .decode(&share.kem_ct)
        .map_err(|e| PhantomError::AuthError(format!("Bad kem ciphertext: {e}")))?;
    if ct_bytes.len() != CIPHERTEXT_SIZE {
        return Err(PhantomError::AuthError(format!(
            "KEM ciphertext must be {CIPHERTEXT_SIZE} bytes"
        )));
    }
    let ct = x_wing::Ciphertext::try_from(ct_bytes.as_slice())
        .map_err(|_| PhantomError::AuthError("Bad kem ciphertext".to_string()))?;
    let shared = me.sk.decapsulate(&ct);

    let nonce_bytes = B64
        .decode(&share.nonce)
        .map_err(|e| PhantomError::AuthError(format!("Bad nonce: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(PhantomError::AuthError(
            "Nonce must be 12 bytes".to_string(),
        ));
    }
    let wrapped = B64
        .decode(&share.ciphertext)
        .map_err(|e| PhantomError::AuthError(format!("Bad ciphertext: {e}")))?;
    let pt = ChaCha20Poly1305::new(shared.as_slice().into())
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &wrapped,
                aad: AAD,
            },
        )
        .map_err(|e| PhantomError::AuthError(format!("Hybrid open failed: {e}")))?;
    if pt.len() != 32 {
        return Err(PhantomError::AuthError(
            "Decrypted sym key must be 32 bytes".to_string(),
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::team_crypto::{generate_sym_key, open_sym_key, seal_sym_key_with, MemberKeypair};

    #[test]
    fn round_trip() {
        let alice = HybridKeypair::generate();
        let key = generate_sym_key();
        let share = seal_sym_key_hybrid(&key, &alice.public_b64()).unwrap();
        assert_eq!(*open_sym_key_hybrid(&share, &alice).unwrap(), *key);
    }

    #[test]
    fn sizes_match_spec() {
        let alice = HybridKeypair::generate();
        assert_eq!(B64.decode(alice.public_b64()).unwrap().len(), 1216);
        let share = seal_sym_key_hybrid(&generate_sym_key(), &alice.public_b64()).unwrap();
        assert_eq!(B64.decode(&share.kem_ct).unwrap().len(), 1120);
        assert_eq!(B64.decode(&share.ciphertext).unwrap().len(), 48);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let alice = HybridKeypair::generate();
        let bob = HybridKeypair::generate();
        let share = seal_sym_key_hybrid(&generate_sym_key(), &bob.public_b64()).unwrap();
        assert!(open_sym_key_hybrid(&share, &alice).is_err());
    }

    #[test]
    fn tampering_any_field_fails() {
        let alice = HybridKeypair::generate();
        let share = seal_sym_key_hybrid(&generate_sym_key(), &alice.public_b64()).unwrap();
        for field in ["kem_ct", "nonce", "ciphertext"] {
            let mut bad = share.clone();
            let target = match field {
                "kem_ct" => &mut bad.kem_ct,
                "nonce" => &mut bad.nonce,
                _ => &mut bad.ciphertext,
            };
            let mut raw = B64.decode(&*target).unwrap();
            raw[0] ^= 1;
            *target = B64.encode(raw);
            assert!(open_sym_key_hybrid(&bad, &alice).is_err(), "{field}");
        }
    }

    #[test]
    fn label_and_version_downgrade_rejected() {
        let alice = HybridKeypair::generate();
        let share = seal_sym_key_hybrid(&generate_sym_key(), &alice.public_b64()).unwrap();
        let mut bad = share.clone();
        bad.alg = "x25519-chachabox".to_string();
        assert!(open_sym_key_hybrid(&bad, &alice).is_err());
        let mut bad = share;
        bad.v = 1;
        assert!(open_sym_key_hybrid(&bad, &alice).is_err());
    }

    #[test]
    fn secret_seed_round_trip() {
        let alice = HybridKeypair::generate();
        let key = generate_sym_key();
        let share = seal_sym_key_hybrid(&key, &alice.public_b64()).unwrap();
        let restored = HybridKeypair::from_secret_bytes(*alice.secret_bytes());
        assert_eq!(restored.public_b64(), alice.public_b64());
        assert_eq!(*open_sym_key_hybrid(&share, &restored).unwrap(), *key);
    }

    #[test]
    fn bad_public_key_length_rejected() {
        let short = B64.encode([0u8; 32]);
        assert!(seal_sym_key_hybrid(&[1u8; 32], &short).is_err());
    }

    /// Classic and hybrid shares are independent: a hybrid share does not
    /// open through the classic path and the classic path is unchanged.
    #[test]
    fn classic_path_unaffected() {
        let m = MemberKeypair::generate();
        let key = generate_sym_key();
        let classic = seal_sym_key_with(
            &key,
            &m.public_b64(),
            crate::blob_format::WriteFormat::Legacy,
        )
        .unwrap();
        assert_eq!(*open_sym_key(&classic, &m).unwrap(), *key);
        assert!(classic.v.is_none());
    }

    /// Draft 11 Appendix C known-answer vectors (same as the crate's KATs).
    /// Checks the seed-to-public-key expansion and decapsulation against the
    /// published values, so a crate bump that diverges from the draft fails.
    #[test]
    fn draft_11_vectors_match_encapsulation() {
        let raw = include_str!("../tests/fixtures/xwing-draft-11-vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 3);
        for v in vectors {
            let field = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
            // Draft 11 uses the 32-byte seed as the decapsulation key.
            assert_eq!(field("sk"), field("seed"));
            let ek = EncapsulationKey::try_from(field("pk").as_slice()).unwrap();
            let eseed = field("eseed");
            assert_eq!(eseed.len(), x_wing::ENCAPSULATION_RANDOMNESS_SIZE);
            let randomness = eseed.as_slice().try_into().unwrap();
            let (ct, ss) = ek.encapsulate_deterministic(&randomness);
            assert_eq!(ct.as_slice(), field("ct").as_slice());
            assert_eq!(ss.as_slice(), field("ss").as_slice());
        }
    }

    #[test]
    fn draft_11_vectors_match() {
        let raw = include_str!("../tests/fixtures/xwing-draft-11-vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 3);
        for v in vectors {
            let field = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
            let seed: [u8; 32] = field("seed").try_into().unwrap();
            let kp = HybridKeypair::from_secret_bytes(seed);
            assert_eq!(B64.decode(kp.public_b64()).unwrap(), field("pk"));
            let ct = x_wing::Ciphertext::try_from(field("ct").as_slice()).unwrap();
            let ss = kp.sk.decapsulate(&ct);
            assert_eq!(ss.as_slice(), field("ss").as_slice());
        }
    }
}
