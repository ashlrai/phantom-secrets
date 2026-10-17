use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use phantom_core::blob_format::{self, Tag, WriteFormat};
use phantom_core::error::{PhantomError, Result};
use zeroize::Zeroize;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Minimum size of an encrypted blob: salt + nonce + at least 1 byte of ciphertext.
pub const MIN_ENCRYPTED_LEN: usize = SALT_LEN + NONCE_LEN + 1;

/// Argon2id memory cost in KiB (64 MiB).
pub const ARGON2_M_COST_KIB: u32 = 64 * 1024;
/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism (lanes).
pub const ARGON2_P_COST: u32 = 1;

/// Hardened Argon2id parameters (OWASP "balanced" recommendation, 2024+):
/// 64 MiB memory, 3 iterations, 1 lane, 32-byte output.
fn hardened_argon2() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(KEY_LEN),
    )
    .map_err(|e| PhantomError::VaultError(format!("Argon2 params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a key using the current (hardened) Argon2id parameters. Used for
/// every new encryption.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    hardened_argon2()?
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| PhantomError::VaultError(format!("Key derivation failed: {e}")))?;
    Ok(key)
}

/// Derive a key using legacy `Argon2::default()` parameters. Tried as a
/// fallback when [`derive_key`] produces a key that doesn't decrypt — this
/// preserves compatibility with vaults encrypted under earlier phantom
/// releases (m=19MiB / t=2 / p=1, the argon2 crate's default).
fn derive_key_legacy(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| PhantomError::VaultError(format!("Legacy key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypt plaintext using ChaCha20-Poly1305 with Argon2id key derivation.
///
/// Default (untagged) output: `salt (32 bytes) || nonce (12 bytes) || ciphertext`.
/// With `PHANTOM_BLOB_FORMAT=v2` the output is prefixed by the 6-byte
/// format header (see [`phantom_core::blob_format`]).
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    encrypt_with_format(plaintext, passphrase, WriteFormat::from_env())
}

/// Encrypt with an explicit output format.
pub fn encrypt_with_format(
    plaintext: &[u8],
    passphrase: &str,
    format: WriteFormat,
) -> Result<Vec<u8>> {
    let salt: [u8; SALT_LEN] = rand::random();
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();

    let mut key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let header = blob_format::header();
    let ciphertext = match format {
        WriteFormat::Legacy => cipher.encrypt(nonce, plaintext),
        WriteFormat::Tagged => cipher.encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        ),
    }
    .map_err(|e| PhantomError::VaultError(format!("Encryption failed: {e}")))?;

    let mut output =
        Vec::with_capacity(blob_format::HEADER_LEN + SALT_LEN + NONCE_LEN + ciphertext.len());
    if format == WriteFormat::Tagged {
        output.extend_from_slice(&header);
    }
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt data produced by [`encrypt`], tagged or untagged.
///
/// Untagged input format: `salt (32 bytes) || nonce (12 bytes) || ciphertext`
pub fn decrypt(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if encrypted.len() < MIN_ENCRYPTED_LEN {
        return Err(PhantomError::VaultError(
            "Encrypted data too small — may be corrupt".to_string(),
        ));
    }

    let tag = blob_format::classify(encrypted);
    if let Tag::V2(body) = &tag {
        if body.len() >= MIN_ENCRYPTED_LEN {
            let header = &encrypted[..blob_format::HEADER_LEN];
            if let Some(pt) = decrypt_body(body, passphrase, Some(header))? {
                return Ok(pt);
            }
        }
    }
    // Untagged, or the magic collided with a legacy salt: legacy layout.
    if let Some(pt) = decrypt_body(encrypted, passphrase, None)? {
        return Ok(pt);
    }
    if let Tag::Unsupported { version, alg } = tag {
        return Err(PhantomError::VaultError(format!(
            "Unsupported vault format (version {version}, algorithm {alg}); upgrade phantom"
        )));
    }
    Err(PhantomError::VaultError(
        "Decryption failed — wrong passphrase or corrupt data".to_string(),
    ))
}

/// Decrypt a `salt || nonce || ciphertext` body. With `aad` set only the
/// hardened KDF is tried (tagged blobs never used the legacy parameters).
fn decrypt_body(body: &[u8], passphrase: &str, aad: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
    if body.len() < MIN_ENCRYPTED_LEN {
        return Ok(None);
    }
    let salt = &body[..SALT_LEN];
    let nonce = Nonce::from_slice(&body[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    // Try the hardened parameters first; if AEAD verification fails we
    // fall back to legacy `Argon2::default()` to keep older vaults
    // decryptable. Either path's key is zeroized before this fn returns.
    if let Some(plaintext) = try_decrypt_with(derive_key, passphrase, salt, nonce, ciphertext, aad)?
    {
        return Ok(Some(plaintext));
    }
    if aad.is_none() {
        return try_decrypt_with(derive_key_legacy, passphrase, salt, nonce, ciphertext, None);
    }
    Ok(None)
}

fn try_decrypt_with(
    derive: fn(&str, &[u8]) -> Result<[u8; KEY_LEN]>,
    passphrase: &str,
    salt: &[u8],
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    let mut key = derive(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
    key.zeroize();

    Ok(match aad {
        None => cipher.decrypt(nonce, ciphertext),
        Some(aad) => cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        ),
    }
    .ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello world secret data";
        let passphrase = "test-passphrase-123";

        let encrypted = encrypt(plaintext, passphrase).unwrap();
        let decrypted = decrypt(&encrypted, passphrase).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let plaintext = b"secret";
        let encrypted = encrypt(plaintext, "correct").unwrap();
        assert!(decrypt(&encrypted, "wrong").is_err());
    }

    #[test]
    fn test_too_small_input_fails() {
        assert!(decrypt(&[0u8; 10], "pass").is_err());
    }

    #[test]
    fn test_each_encryption_is_unique() {
        let plaintext = b"same data";
        let e1 = encrypt(plaintext, "pass").unwrap();
        let e2 = encrypt(plaintext, "pass").unwrap();
        // Different random salt+nonce means different ciphertext
        assert_ne!(e1, e2);
        // But both decrypt to the same thing
        assert_eq!(decrypt(&e1, "pass").unwrap(), plaintext);
        assert_eq!(decrypt(&e2, "pass").unwrap(), plaintext);
    }

    /// Encrypt with the legacy KDF, then verify the current `decrypt` path
    /// can still read it. This guarantees we never break older vaults when
    /// we tighten Argon2 parameters.
    #[test]
    fn test_legacy_vault_still_decrypts() {
        use chacha20poly1305::aead::{Aead, KeyInit};
        let plaintext = b"old-vault-data";
        let passphrase = "legacy-pass";

        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let mut key = derive_key_legacy(passphrase, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        key.zeroize();

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        // Real path — should hit the legacy fallback after the hardened
        // params produce a non-matching key.
        assert_eq!(decrypt(&blob, passphrase).unwrap(), plaintext);
    }

    #[test]
    fn test_hardened_and_legacy_keys_differ() {
        // Sanity check that the two derivations are actually different —
        // otherwise the legacy fallback would be silently dead code.
        let salt = [42u8; SALT_LEN];
        let h = derive_key("same-pass", &salt).unwrap();
        let l = derive_key_legacy("same-pass", &salt).unwrap();
        assert_ne!(h, l);
    }

    /// Fixture generated by the pre-tag writer (hardened KDF, no header).
    fn untagged_blob(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
        encrypt_with_format(plaintext, passphrase, WriteFormat::Legacy).unwrap()
    }

    #[test]
    fn legacy_format_is_the_default_layout() {
        let blob = untagged_blob(b"abc", "p");
        assert_eq!(blob.len(), SALT_LEN + NONCE_LEN + 3 + 16);
        assert_eq!(decrypt(&blob, "p").unwrap(), b"abc");
    }

    #[test]
    fn tagged_round_trip_and_header_present() {
        let blob = encrypt_with_format(b"secret", "p", WriteFormat::Tagged).unwrap();
        assert_eq!(&blob[..4], b"PHMB");
        assert_eq!(blob.len(), 6 + SALT_LEN + NONCE_LEN + 6 + 16);
        assert_eq!(decrypt(&blob, "p").unwrap(), b"secret");
        assert!(decrypt(&blob, "wrong").is_err());
    }

    #[test]
    fn tagged_header_tamper_and_strip_fail() {
        let blob = encrypt_with_format(b"secret", "p", WriteFormat::Tagged).unwrap();
        let mut bad = blob.clone();
        bad[5] ^= 1;
        assert!(decrypt(&bad, "p").is_err());
        assert!(decrypt(&blob[blob_format::HEADER_LEN..], "p").is_err());
    }

    #[test]
    fn unknown_version_is_reported() {
        let mut blob = encrypt_with_format(b"secret", "p", WriteFormat::Tagged).unwrap();
        blob[4] = 9;
        let err = decrypt(&blob, "p").unwrap_err().to_string();
        assert!(err.contains("Unsupported vault format"), "{err}");
    }

    #[test]
    fn legacy_blob_with_magic_colliding_salt_still_decrypts() {
        // Build an untagged blob whose salt starts with a valid v2 header.
        let passphrase = "collide";
        let mut salt = [5u8; SALT_LEN];
        salt[..blob_format::HEADER_LEN].copy_from_slice(&blob_format::header());
        let nonce_bytes = [6u8; NONCE_LEN];
        let mut key = derive_key(passphrase, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        key.zeroize();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), b"edge".as_ref())
            .unwrap();
        let mut blob = salt.to_vec();
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        assert!(matches!(blob_format::classify(&blob), Tag::V2(_)));
        assert_eq!(decrypt(&blob, passphrase).unwrap(), b"edge");
    }

    #[test]
    fn golden_untagged_fixture_decrypts() {
        let blob = hex_to_bytes(GOLDEN_HEX);
        assert_eq!(decrypt(&blob, "golden-pass").unwrap(), b"golden-plaintext");
    }

    fn hex_to_bytes(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    const GOLDEN_HEX: &str = "ee34d220b0bec900e8c5cd0ee92b2217a150303e7cdb62f024cf1db0ef2d4e5894398c4e170fdede11ad00a01d8846053ae505dad2e2093c0617285bf631bc5dfd77819e82020c9c6e6353bb";
}
