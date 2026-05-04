use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use phantom_core::error::{PhantomError, Result};
use rand::RngCore;
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
/// Returns: `salt (32 bytes) || nonce (12 bytes) || ciphertext`
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
    key.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PhantomError::VaultError(format!("Encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt data produced by [`encrypt`].
///
/// Input format: `salt (32 bytes) || nonce (12 bytes) || ciphertext`
pub fn decrypt(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if encrypted.len() < MIN_ENCRYPTED_LEN {
        return Err(PhantomError::VaultError(
            "Encrypted data too small — may be corrupt".to_string(),
        ));
    }

    let salt = &encrypted[..SALT_LEN];
    let nonce_bytes = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];
    let nonce = Nonce::from_slice(nonce_bytes);

    // Try the hardened parameters first; if AEAD verification fails we
    // fall back to legacy `Argon2::default()` to keep older vaults
    // decryptable. Either path's key is zeroized before this fn returns.
    if let Some(plaintext) = try_decrypt_with(derive_key, passphrase, salt, nonce, ciphertext)? {
        return Ok(plaintext);
    }
    if let Some(plaintext) =
        try_decrypt_with(derive_key_legacy, passphrase, salt, nonce, ciphertext)?
    {
        return Ok(plaintext);
    }

    Err(PhantomError::VaultError(
        "Decryption failed — wrong passphrase or corrupt data".to_string(),
    ))
}

fn try_decrypt_with(
    derive: fn(&str, &[u8]) -> Result<[u8; KEY_LEN]>,
    passphrase: &str,
    salt: &[u8],
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Option<Vec<u8>>> {
    let mut key = derive(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
    key.zeroize();

    Ok(cipher.decrypt(nonce, ciphertext).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
