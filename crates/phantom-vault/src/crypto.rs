use argon2::Argon2;
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

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| PhantomError::VaultError(format!("Key derivation failed: {e}")))?;
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

    let mut key = derive_key(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
    key.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        PhantomError::VaultError("Decryption failed — wrong passphrase or corrupt data".to_string())
    })?;

    Ok(plaintext)
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
}
