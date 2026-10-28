use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use phantom_core::blob_format::{self, Tag, WriteFormat};
use phantom_core::error::{PhantomError, Result};
use zeroize::{Zeroize, Zeroizing};

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// One authenticated unlock, owned by a single immutable-passphrase vault.
/// Never shared between vaults, persisted, or used to cache plaintext/metadata.
/// The prefix includes the exact format/KDF header, salt and nonce; every hit
/// still authenticates the current ciphertext and its associated data.
#[derive(Default)]
pub(crate) struct DecryptionCache {
    entry: Option<CachedKey>,
}

struct CachedKey {
    prefix: Vec<u8>,
    aad_len: usize,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl DecryptionCache {
    /// The caller must bind this cache to one immutable passphrase for its
    /// entire lifetime. FileVault owns both; one-shot public decrypts get a
    /// fresh cache so no passphrase can be bypassed by another caller's hit.
    pub(crate) fn decrypt(&mut self, encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>> {
        if let Some(entry) = &self.entry {
            if encrypted.starts_with(&entry.prefix) {
                let aad = (entry.aad_len != 0).then_some(&encrypted[..entry.aad_len]);
                if let Some(plaintext) =
                    decrypt_with_key(&encrypted[entry.aad_len..], &entry.key, aad)?
                {
                    return Ok(plaintext);
                }
            }
        }
        // A failed cached authentication cannot bypass the normal format and
        // legacy-collision rules. Only a successful unlock replaces the key.
        decrypt_uncached(encrypted, passphrase, self)
    }

    fn remember(&mut self, body: &[u8], aad: Option<&[u8]>, key: Zeroizing<[u8; KEY_LEN]>) {
        let mut prefix = aad.unwrap_or_default().to_vec();
        prefix.extend_from_slice(&body[..SALT_LEN + NONCE_LEN]);
        self.entry = Some(CachedKey {
            prefix,
            aad_len: aad.map_or(0, <[u8]>::len),
            key,
        });
    }
}

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
    DecryptionCache::default().decrypt(encrypted, passphrase)
}

fn decrypt_uncached(
    encrypted: &[u8],
    passphrase: &str,
    cache: &mut DecryptionCache,
) -> Result<Vec<u8>> {
    if encrypted.len() < MIN_ENCRYPTED_LEN {
        return Err(PhantomError::VaultError(
            "Encrypted data too small — may be corrupt".to_string(),
        ));
    }

    let tag = blob_format::classify(encrypted);
    if let Tag::V2(body) = &tag {
        if body.len() >= MIN_ENCRYPTED_LEN {
            let header = &encrypted[..blob_format::HEADER_LEN];
            if let Some(pt) = decrypt_body(body, passphrase, Some(header), cache)? {
                return Ok(pt);
            }
        }
    }
    // Version 3 carries its own Argon2id parameters (read-only support).
    if let Tag::Unsupported {
        version: blob_format::VERSION_3,
        ..
    } = tag
    {
        if let Some((params, header, body)) = blob_format::parse_v3_header(encrypted) {
            if let Some(pt) = decrypt_body_v3(body, passphrase, params, header, cache)? {
                return Ok(pt);
            }
        }
    }
    // Untagged, or the magic collided with a legacy salt: legacy layout.
    if let Some(pt) = decrypt_body(encrypted, passphrase, None, cache)? {
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
fn decrypt_body(
    body: &[u8],
    passphrase: &str,
    aad: Option<&[u8]>,
    cache: &mut DecryptionCache,
) -> Result<Option<Vec<u8>>> {
    if body.len() < MIN_ENCRYPTED_LEN {
        return Ok(None);
    }
    // Try the hardened parameters first; if AEAD verification fails we
    // fall back to legacy `Argon2::default()` to keep older vaults
    // decryptable. Failed keys are scrubbed immediately; a successful key is
    // retained only in the caller's zeroizing, instance-local unlock cache.
    if let Some(plaintext) = try_decrypt_with(derive_key, passphrase, body, aad, cache)? {
        return Ok(Some(plaintext));
    }
    if aad.is_none() {
        return try_decrypt_with(derive_key_legacy, passphrase, body, None, cache);
    }
    Ok(None)
}

/// Decrypt a v3 body (`salt || nonce || ciphertext`) with the header's
/// Argon2id parameters and the header as associated data.
fn decrypt_body_v3(
    body: &[u8],
    passphrase: &str,
    params: blob_format::KdfParamsV3,
    header: &[u8],
    cache: &mut DecryptionCache,
) -> Result<Option<Vec<u8>>> {
    if body.len() < MIN_ENCRYPTED_LEN {
        return Ok(None);
    }
    let argon2_params = Params::new(
        params.m_kib,
        u32::from(params.t),
        u32::from(params.p),
        Some(KEY_LEN),
    )
    .map_err(|e| PhantomError::VaultError(format!("Argon2 params: {e}")))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params)
        .hash_password_into(passphrase.as_bytes(), &body[..SALT_LEN], key.as_mut())
        .map_err(|e| PhantomError::VaultError(format!("Key derivation failed: {e}")))?;
    let plaintext = decrypt_with_key(body, &key, Some(header))?;
    if plaintext.is_some() {
        cache.remember(body, Some(header), key);
    }
    Ok(plaintext)
}

fn try_decrypt_with(
    derive: fn(&str, &[u8]) -> Result<[u8; KEY_LEN]>,
    passphrase: &str,
    body: &[u8],
    aad: Option<&[u8]>,
    cache: &mut DecryptionCache,
) -> Result<Option<Vec<u8>>> {
    let key = Zeroizing::new(derive(passphrase, &body[..SALT_LEN])?);
    let plaintext = decrypt_with_key(body, &key, aad)?;
    if plaintext.is_some() {
        cache.remember(body, aad, key);
    }
    Ok(plaintext)
}

fn decrypt_with_key(
    body: &[u8],
    key: &[u8; KEY_LEN],
    aad: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    if body.len() < MIN_ENCRYPTED_LEN {
        return Ok(None);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(&body[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

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

    /// A tagged (v2) blob was never written with the legacy Argon2 defaults,
    /// so decrypt must not fall back to them for it: that would let a
    /// rewritten blob bypass the hardened KDF and the header binding.
    #[test]
    fn tagged_blob_never_decrypts_with_the_legacy_kdf() {
        let passphrase = "obvious-fake-passphrase";
        let plaintext = b"fake-vault-contents";
        let real = encrypt_with_format(plaintext, passphrase, WriteFormat::Tagged).unwrap();
        let header_len = blob_format::HEADER_LEN;
        let salt = &real[header_len..header_len + SALT_LEN];
        let nonce_bytes = &real[header_len + SALT_LEN..header_len + SALT_LEN + NONCE_LEN];

        // Same header, salt and nonce; body sealed under the legacy KDF with
        // no associated data, as an untagged legacy blob would be.
        let mut key = derive_key_legacy(passphrase, salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        key.zeroize();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce_bytes), plaintext.as_slice())
            .unwrap();
        let mut forged = real[..header_len + SALT_LEN + NONCE_LEN].to_vec();
        forged.extend_from_slice(&ciphertext);

        assert_eq!(decrypt(&real, passphrase).unwrap(), plaintext);
        assert!(
            decrypt(&forged, passphrase).is_err(),
            "tagged blob decrypted through the legacy KDF"
        );
    }
    use rand::RngCore;

    #[test]
    fn vault_key_is_256_bits() {
        // Grover margin: the Argon2id output used as the AEAD key is 32 bytes.
        assert_eq!(KEY_LEN * 8, 256);
        let salt: [u8; SALT_LEN] = rand::random();
        assert_eq!(derive_key("pw", &salt).unwrap().len() * 8, 256);
    }

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

    /// Untagged blob whose salt starts with `PHMB` and the given version and
    /// algorithm bytes, sealed with `derive`.
    fn colliding_blob(
        derive: fn(&str, &[u8]) -> Result<[u8; KEY_LEN]>,
        passphrase: &str,
        version: u8,
        alg: u8,
    ) -> Vec<u8> {
        // Random salt and nonce; only the salt's first 6 bytes are forced.
        let mut salt: [u8; SALT_LEN] = rand::random();
        salt[..4].copy_from_slice(&blob_format::MAGIC);
        salt[4] = version;
        salt[5] = alg;
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let mut key = derive(passphrase, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        key.zeroize();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), b"edge".as_ref())
            .unwrap();
        let mut blob = salt.to_vec();
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        blob
    }

    #[test]
    fn legacy_salt_colliding_with_an_unsupported_header_still_decrypts() {
        // A salt that looks like a future header (for example version 3)
        // must fall back to the legacy layout, not fail as unsupported.
        for (version, alg) in [(3u8, 1u8), (blob_format::VERSION_2, 0xff), (0xff, 0xff)] {
            let blob = colliding_blob(derive_key, "collide", version, alg);
            assert!(matches!(
                blob_format::classify(&blob),
                Tag::Unsupported { .. }
            ));
            assert_eq!(
                decrypt(&blob, "collide").unwrap(),
                b"edge",
                "v{version} a{alg}"
            );
        }
    }

    /// Hand-made v3 fixture, generated independently with Python argon2-cffi
    /// 25.1.0 (Argon2id v0x13, m=19456 KiB, t=2, p=1) and `cryptography`
    /// ChaCha20Poly1305 with the 13-byte header as associated data.
    const V3_FIXTURE_HEX: &str = "50484d42030101004c000002013541bf7ea61ca3d2ecf4906164cb526199600097bf0f985c286af53f6b4ddc7d4cfe56d967c02079f25373aed3045a3a1e9149aed817d32c1bc9e2424c04c9a6a0a65c988c757797cb5b58dad84fcc83";

    #[test]
    fn v3_fixture_with_stored_params_decrypts() {
        let blob = hex_to_bytes(V3_FIXTURE_HEX);
        let (params, _, _) = blob_format::parse_v3_header(&blob).unwrap();
        assert_eq!(
            params,
            blob_format::KdfParamsV3 {
                m_kib: 19456,
                t: 2,
                p: 1
            }
        );
        assert_eq!(
            decrypt(&blob, "v3-fixture-pass").unwrap(),
            b"v3-fixture-plaintext"
        );
        assert!(decrypt(&blob, "wrong-pass").is_err());
    }

    /// Test-only v3 sealer (m=19456 KiB, t=2, p=1) with random salt and nonce.
    fn seal_v3_for_test(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
        let mut header = blob_format::MAGIC.to_vec();
        header.extend_from_slice(&[
            blob_format::VERSION_3,
            blob_format::ALG_CHACHA20_POLY1305,
            blob_format::KDF_ARGON2ID_V13,
        ]);
        header.extend_from_slice(&19456u32.to_le_bytes());
        header.extend_from_slice(&[2, 1]);
        let salt: [u8; SALT_LEN] = rand::random();
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let mut key: [u8; KEY_LEN] = Default::default();
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(19456, 2, 1, Some(KEY_LEN)).unwrap(),
        )
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        key.zeroize();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .unwrap();
        let mut blob = header;
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        blob
    }

    #[test]
    fn v3_header_tamper_fails() {
        // Flipping t (2 to 3) or the reserved KDF id must not decrypt.
        // Sealed at runtime with a random salt and nonce.
        let blob = seal_v3_for_test(b"v3-tamper", "v3-tamper-pass");
        assert_eq!(decrypt(&blob, "v3-tamper-pass").unwrap(), b"v3-tamper");
        // Offset 11 is t (2 becomes 3); offset 7 is the low byte of m_kib.
        for offset in [11usize, 7] {
            let mut tampered = blob.clone();
            tampered[offset] = tampered[offset].wrapping_add(1);
            let err = decrypt(&tampered, "v3-tamper-pass")
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("Unsupported vault format (version 3"),
                "{offset}: {err}"
            );
        }
    }

    #[test]
    fn legacy_params_blob_with_v2_colliding_salt_still_decrypts() {
        // Old vaults used `Argon2::default()`. The V2 attempt uses only the
        // hardened KDF, so the legacy fallback must still try both.
        let blob = colliding_blob(
            derive_key_legacy,
            "collide",
            blob_format::VERSION_2,
            blob_format::ALG_CHACHA20_POLY1305,
        );
        assert!(matches!(blob_format::classify(&blob), Tag::V2(_)));
        assert_eq!(decrypt(&blob, "collide").unwrap(), b"edge");
    }

    /// Writers must not change: `encrypt` still writes the untagged layout
    /// (or v2 only when `PHANTOM_BLOB_FORMAT=v2`), never v3.
    #[test]
    fn vault_writer_output_layout_is_unchanged() {
        let legacy = encrypt_with_format(b"pin", "pin-pass", WriteFormat::Legacy).unwrap();
        assert_eq!(legacy.len(), SALT_LEN + NONCE_LEN + 3 + 16);
        let tagged = encrypt_with_format(b"pin", "pin-pass", WriteFormat::Tagged).unwrap();
        assert_eq!(
            tagged.len(),
            blob_format::HEADER_LEN + SALT_LEN + NONCE_LEN + 3 + 16
        );
        assert_eq!(
            tagged[..blob_format::HEADER_LEN],
            [b'P', b'H', b'M', b'B', 2, 1]
        );
        let default = encrypt(b"pin", "pin-pass").unwrap();
        assert!(default.len() == legacy.len() || default[..6] == tagged[..6]);
        for blob in [&legacy, &tagged, &default] {
            assert!(blob_format::parse_v3_header(blob).is_none());
            assert_eq!(decrypt(blob, "pin-pass").unwrap(), b"pin");
        }
    }

    #[test]
    fn golden_untagged_fixture_decrypts() {
        let blob = hex_to_bytes(GOLDEN_HEX);
        assert_eq!(decrypt(&blob, "golden-pass").unwrap(), b"golden-plaintext");
    }

    #[test]
    fn unlock_cache_warm_reads_support_every_existing_format() {
        let passphrase = "synthetic-cache-format-passphrase";
        let cases = [
            (
                encrypt_with_format(b"edge", passphrase, WriteFormat::Legacy).unwrap(),
                b"edge".as_slice(),
            ),
            (
                encrypt_with_format(b"edge", passphrase, WriteFormat::Tagged).unwrap(),
                b"edge".as_slice(),
            ),
            (
                // The old KDF and a salt resembling a tagged header must
                // both retain their compatibility path on a warm unlock.
                colliding_blob(
                    derive_key_legacy,
                    passphrase,
                    blob_format::VERSION_2,
                    blob_format::ALG_CHACHA20_POLY1305,
                ),
                b"edge".as_slice(),
            ),
            (seal_v3_for_test(b"edge", passphrase), b"edge".as_slice()),
        ];
        for (blob, expected) in cases {
            let mut cache = DecryptionCache::default();
            assert_eq!(cache.decrypt(&blob, passphrase).unwrap(), expected);
            // Measure only already-authenticated reads. This generous alarm
            // catches expensive unlock regressions on ordinary runners;
            // cached AEAD authentication of tiny fixtures is much cheaper.
            let started = std::time::Instant::now();
            for _ in 0..64 {
                assert_eq!(cache.decrypt(&blob, passphrase).unwrap(), expected);
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "warm authenticated reads unexpectedly repeated expensive unlocks"
            );
        }
    }

    #[test]
    fn unlock_cache_authenticates_current_ciphertext_and_rejects_truncation() {
        let passphrase = "synthetic-cache-corruption-passphrase";
        for format in [WriteFormat::Legacy, WriteFormat::Tagged] {
            let blob = encrypt_with_format(b"current-contents", passphrase, format).unwrap();
            let mut cache = DecryptionCache::default();
            cache.decrypt(&blob, passphrase).unwrap();

            let mut corrupt = blob.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(cache.decrypt(&corrupt, passphrase).is_err());
            for end in [0, MIN_ENCRYPTED_LEN - 1, blob.len() - 1] {
                assert!(cache.decrypt(&blob[..end], passphrase).is_err());
            }
            // An unsuccessful authentication neither poisons the good
            // unlock nor substitutes previously decrypted plaintext.
            assert_eq!(
                cache.decrypt(&blob, passphrase).unwrap(),
                b"current-contents"
            );
        }
    }

    #[test]
    fn unlock_cache_does_not_bypass_header_or_stored_kdf_authentication() {
        let passphrase = "synthetic-cache-header-passphrase";
        let tagged = encrypt_with_format(b"tagged", passphrase, WriteFormat::Tagged).unwrap();
        let v3 = seal_v3_for_test(b"stored-kdf", passphrase);
        for (blob, offsets) in [
            (&tagged, [0usize, 4, 5].as_slice()),
            // KDF id, memory cost, time cost, and parallelism are all
            // authenticated header bytes and must miss the old cache key.
            (&v3, [6usize, 7, 11, 12].as_slice()),
        ] {
            let mut cache = DecryptionCache::default();
            cache.decrypt(blob, passphrase).unwrap();
            for offset in offsets {
                let mut tampered = blob.clone();
                tampered[*offset] = tampered[*offset].wrapping_add(1);
                assert!(
                    cache.decrypt(&tampered, passphrase).is_err(),
                    "warm unlock accepted a changed authenticated header"
                );
            }
            assert!(cache.decrypt(blob, passphrase).is_ok());
        }
    }

    #[test]
    fn unlock_cache_refreshes_for_replacement_and_does_not_remember_failed_keys() {
        let passphrase = "synthetic-cache-replacement-passphrase";
        let first = encrypt_with_format(b"before", passphrase, WriteFormat::Legacy).unwrap();
        let replacement = encrypt_with_format(b"after", passphrase, WriteFormat::Tagged).unwrap();
        let mut cache = DecryptionCache::default();
        assert_eq!(cache.decrypt(&first, passphrase).unwrap(), b"before");
        let original_prefix = cache.entry.as_ref().unwrap().prefix.clone();

        let mut invalid_replacement = replacement.clone();
        *invalid_replacement.last_mut().unwrap() ^= 1;
        assert!(cache.decrypt(&invalid_replacement, passphrase).is_err());
        assert_eq!(cache.entry.as_ref().unwrap().prefix, original_prefix);

        assert_eq!(cache.decrypt(&replacement, passphrase).unwrap(), b"after");
        assert_ne!(cache.entry.as_ref().unwrap().prefix, original_prefix);
        assert_eq!(cache.decrypt(&replacement, passphrase).unwrap(), b"after");
    }

    #[test]
    fn public_decrypt_never_reuses_a_vault_instances_authenticated_key() {
        let passphrase = "synthetic-cache-public-passphrase";
        let blob = encrypt_with_format(b"protected", passphrase, WriteFormat::Tagged).unwrap();
        let mut instance_cache = DecryptionCache::default();
        instance_cache.decrypt(&blob, passphrase).unwrap();

        // Public callers do not own an immutable-passphrase FileVault and
        // must perform their own unlock even after another caller succeeded.
        assert!(decrypt(&blob, "synthetic-wrong-passphrase").is_err());
        let mut other_instance = DecryptionCache::default();
        assert!(other_instance
            .decrypt(&blob, "synthetic-wrong-passphrase")
            .is_err());
        assert!(other_instance.entry.is_none());
        assert_eq!(
            instance_cache.decrypt(&blob, passphrase).unwrap(),
            b"protected"
        );
        assert_eq!(decrypt(&blob, passphrase).unwrap(), b"protected");
    }

    fn hex_to_bytes(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    const GOLDEN_HEX: &str = "ee34d220b0bec900e8c5cd0ee92b2217a150303e7cdb62f024cf1db0ef2d4e5894398c4e170fdede11ad00a01d8846053ae505dad2e2093c0617285bf631bc5dfd77819e82020c9c6e6353bb";
}
