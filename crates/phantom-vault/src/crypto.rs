use argon2::{Algorithm, Argon2, Block, Params, Version};
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

/// A derived AEAD key. Scrubbed on drop, including on every early return.
type DerivedKey = Zeroizing<[u8; KEY_LEN]>;

/// Run Argon2 into a zeroizing key buffer with zeroizing working memory.
///
/// `Argon2::hash_password_into` allocates its block memory internally and
/// frees it unscrubbed; the final memory block alone determines the derived
/// key. Supplying our own [`ScrubbedBlocks`] scrubs the whole working set
/// (up to 64 MiB) on drop, including on the error path. The output is
/// identical to `hash_password_into` with the same parameters.
fn argon2_derive(
    argon2: &Argon2<'_>,
    passphrase: &str,
    salt: &[u8],
    what: &str,
) -> Result<DerivedKey> {
    let mut key: DerivedKey = Zeroizing::new([0u8; KEY_LEN]);
    let mut blocks = ScrubbedBlocks(vec![Block::default(); argon2.params().block_count()]);
    argon2
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            salt,
            key.as_mut_slice(),
            blocks.0.as_mut_slice(),
        )
        .map_err(|e| PhantomError::VaultError(format!("{what} failed: {e}")))?;
    Ok(key)
}

/// Argon2 working memory, scrubbed on drop.
///
/// Each block is cleared as a `[u64]` slice (zeroize's volatile bulk set)
/// rather than through `Zeroizing<Vec<Block>>`, whose per-word iterator path
/// is several times slower than the derivation itself in unoptimized builds.
/// Both forms clear every word with volatile writes.
struct ScrubbedBlocks(Vec<Block>);

impl ScrubbedBlocks {
    fn scrub(&mut self) {
        for block in &mut self.0 {
            let words: &mut [u64] = block.as_mut();
            words.zeroize();
        }
    }
}

impl Drop for ScrubbedBlocks {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// Derive a key using the current (hardened) Argon2id parameters. Used for
/// every new encryption.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<DerivedKey> {
    argon2_derive(&hardened_argon2()?, passphrase, salt, "Key derivation")
}

/// Derive a key using legacy `Argon2::default()` parameters. Tried as a
/// fallback when [`derive_key`] produces a key that doesn't decrypt — this
/// preserves compatibility with vaults encrypted under earlier phantom
/// releases (m=19MiB / t=2 / p=1, the argon2 crate's default).
fn derive_key_legacy(passphrase: &str, salt: &[u8]) -> Result<DerivedKey> {
    argon2_derive(
        &Argon2::default(),
        passphrase,
        salt,
        "Legacy key derivation",
    )
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

    // The cipher is `ZeroizeOnDrop`; the derived key buffer drops (and is
    // scrubbed) at the end of this block, before the plaintext is touched.
    let cipher = {
        let key = derive_key(passphrase, &salt)?;
        ChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?
    };

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
///
/// The plaintext is returned in a [`Zeroizing`] buffer so it is scrubbed on
/// drop even when a caller forgets to wrap it. The AEAD writes the plaintext
/// in place into a buffer pre-sized for the ciphertext, so no unscrubbed
/// intermediate copy is left behind.
pub fn decrypt(encrypted: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
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
    // Version 3 carries its own Argon2id parameters (read-only support).
    if let Tag::Unsupported {
        version: blob_format::VERSION_3,
        ..
    } = tag
    {
        if let Some((params, header, body)) = blob_format::parse_v3_header(encrypted) {
            if let Some(pt) = decrypt_body_v3(body, passphrase, params, header)? {
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
fn decrypt_body(
    body: &[u8],
    passphrase: &str,
    aad: Option<&[u8]>,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
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

/// Decrypt a v3 body (`salt || nonce || ciphertext`) with the header's
/// Argon2id parameters and the header as associated data.
fn decrypt_body_v3(
    body: &[u8],
    passphrase: &str,
    params: blob_format::KdfParamsV3,
    header: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
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
    let cipher = {
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
        let key = argon2_derive(&argon2, passphrase, &body[..SALT_LEN], "Key derivation")?;
        ChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?
    };
    let nonce = Nonce::from_slice(&body[SALT_LEN..SALT_LEN + NONCE_LEN]);
    Ok(cipher
        .decrypt(
            nonce,
            Payload {
                msg: &body[SALT_LEN + NONCE_LEN..],
                aad: header,
            },
        )
        .ok()
        .map(Zeroizing::new))
}

fn try_decrypt_with(
    derive: fn(&str, &[u8]) -> Result<DerivedKey>,
    passphrase: &str,
    salt: &[u8],
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let cipher = {
        let key = derive(passphrase, salt)?;
        ChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|e| PhantomError::VaultError(format!("Cipher init failed: {e}")))?
    };

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
    .ok()
    .map(Zeroizing::new))
}

/// Serialize `value` as pretty JSON into a [`Zeroizing`] buffer.
///
/// `serde_json::to_string_pretty` grows a plain `Vec` by reallocation, and
/// every superseded allocation holding a prefix of the plaintext is freed
/// unscrubbed. [`ZeroizingWriter`] grows by copying into a fresh
/// `Zeroizing` buffer and dropping (scrubbing) the old one, so no plaintext
/// fragment outlives the call. The bytes are identical to
/// `serde_json::to_vec_pretty`.
pub fn to_json_pretty_zeroizing<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = ZeroizingWriter::default();
    serde_json::to_writer_pretty(&mut writer, value)
        .map_err(|e| PhantomError::VaultError(format!("Serialization failed: {e}")))?;
    Ok(writer.buf)
}

/// `io::Write` sink that never lets `Vec` reallocate plaintext in place.
#[derive(Default)]
struct ZeroizingWriter {
    buf: Zeroizing<Vec<u8>>,
}

impl ZeroizingWriter {
    const MIN_CAPACITY: usize = 1024;

    fn reserve_scrubbed(&mut self, additional: usize) {
        let needed = self.buf.len().saturating_add(additional);
        if needed <= self.buf.capacity() {
            return;
        }
        let capacity = needed
            .max(self.buf.capacity().saturating_mul(2))
            .max(Self::MIN_CAPACITY);
        let mut next = Zeroizing::new(Vec::with_capacity(capacity));
        next.extend_from_slice(&self.buf);
        // The previous buffer drops here and is scrubbed over its capacity.
        self.buf = next;
    }
}

impl std::io::Write for ZeroizingWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.reserve_scrubbed(data.len());
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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
        let key = derive_key_legacy(passphrase, salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).unwrap();
        drop(key);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(nonce_bytes), plaintext.as_slice())
            .unwrap();
        let mut forged = real[..header_len + SALT_LEN + NONCE_LEN].to_vec();
        forged.extend_from_slice(&ciphertext);

        assert_eq!(decrypt(&real, passphrase).unwrap().as_slice(), plaintext);
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

        assert_eq!(decrypted.as_slice(), plaintext);
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
        assert_eq!(decrypt(&e1, "pass").unwrap().as_slice(), plaintext);
        assert_eq!(decrypt(&e2, "pass").unwrap().as_slice(), plaintext);
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

        let key = derive_key_legacy(passphrase, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).unwrap();
        drop(key);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        // Real path — should hit the legacy fallback after the hardened
        // params produce a non-matching key.
        assert_eq!(decrypt(&blob, passphrase).unwrap().as_slice(), plaintext);
    }

    #[test]
    fn test_hardened_and_legacy_keys_differ() {
        // Sanity check that the two derivations are actually different —
        // otherwise the legacy fallback would be silently dead code.
        let salt = [42u8; SALT_LEN];
        let h = derive_key("same-pass", &salt).unwrap();
        let l = derive_key_legacy("same-pass", &salt).unwrap();
        // Compare without formatting key bytes into a failure message.
        assert!(*h != *l, "hardened and legacy derivations collided");
    }

    /// Fixture generated by the pre-tag writer (hardened KDF, no header).
    fn untagged_blob(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
        encrypt_with_format(plaintext, passphrase, WriteFormat::Legacy).unwrap()
    }

    #[test]
    fn legacy_format_is_the_default_layout() {
        let blob = untagged_blob(b"abc", "p");
        assert_eq!(blob.len(), SALT_LEN + NONCE_LEN + 3 + 16);
        assert_eq!(decrypt(&blob, "p").unwrap().as_slice(), b"abc");
    }

    #[test]
    fn tagged_round_trip_and_header_present() {
        let blob = encrypt_with_format(b"secret", "p", WriteFormat::Tagged).unwrap();
        assert_eq!(&blob[..4], b"PHMB");
        assert_eq!(blob.len(), 6 + SALT_LEN + NONCE_LEN + 6 + 16);
        assert_eq!(decrypt(&blob, "p").unwrap().as_slice(), b"secret");
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
        let key = derive_key(passphrase, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).unwrap();
        drop(key);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), b"edge".as_ref())
            .unwrap();
        let mut blob = salt.to_vec();
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        assert!(matches!(blob_format::classify(&blob), Tag::V2(_)));
        assert_eq!(decrypt(&blob, passphrase).unwrap().as_slice(), b"edge");
    }

    /// Untagged blob whose salt starts with `PHMB` and the given version and
    /// algorithm bytes, sealed with `derive`.
    fn colliding_blob(
        derive: fn(&str, &[u8]) -> Result<DerivedKey>,
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
        let key = derive(passphrase, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).unwrap();
        drop(key);
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
                decrypt(&blob, "collide").unwrap().as_slice(),
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
            decrypt(&blob, "v3-fixture-pass").unwrap().as_slice(),
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
        assert_eq!(
            decrypt(&blob, "v3-tamper-pass").unwrap().as_slice(),
            b"v3-tamper"
        );
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
        assert_eq!(decrypt(&blob, "collide").unwrap().as_slice(), b"edge");
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
            assert_eq!(decrypt(blob, "pin-pass").unwrap().as_slice(), b"pin");
        }
    }

    #[test]
    fn golden_untagged_fixture_decrypts() {
        let blob = hex_to_bytes(GOLDEN_HEX);
        assert_eq!(
            decrypt(&blob, "golden-pass").unwrap().as_slice(),
            b"golden-plaintext"
        );
    }

    fn hex_to_bytes(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    const GOLDEN_HEX: &str = "ee34d220b0bec900e8c5cd0ee92b2217a150303e7cdb62f024cf1db0ef2d4e5894398c4e170fdede11ad00a01d8846053ae505dad2e2093c0617285bf631bc5dfd77819e82020c9c6e6353bb";

    /// Type pins: plaintext and derived-key buffers must be `Zeroizing`.
    /// Reverting any of these to a plain `Vec<u8>` / `[u8; 32]` is a compile
    /// error, not a silent regression.
    #[test]
    fn decrypt_and_key_derivation_return_zeroizing_buffers() {
        type Plaintext = Result<Zeroizing<Vec<u8>>>;
        type Key = Result<Zeroizing<[u8; KEY_LEN]>>;
        let _decrypt: fn(&[u8], &str) -> Plaintext = decrypt;
        let _hardened: fn(&str, &[u8]) -> Key = derive_key;
        let _legacy: fn(&str, &[u8]) -> Key = derive_key_legacy;
        let _json: fn(&BTreeMap<String, String>) -> Plaintext =
            to_json_pretty_zeroizing::<BTreeMap<String, String>>;
    }

    /// Supplying zeroizing Argon2 working memory must not change the key:
    /// `argon2_derive` agrees with the crate's own `hash_password_into` for
    /// both the hardened and the legacy parameters.
    #[test]
    fn zeroizing_argon2_memory_derives_the_same_key() {
        let salt = [7u8; SALT_LEN];
        for (argon2, ours) in [
            (
                hardened_argon2().unwrap(),
                derive_key("same-input", &salt).unwrap(),
            ),
            (
                Argon2::default(),
                derive_key_legacy("same-input", &salt).unwrap(),
            ),
        ] {
            let mut reference = [0u8; KEY_LEN];
            argon2
                .hash_password_into(b"same-input", &salt, &mut reference)
                .unwrap();
            let same = *ours == reference;
            reference.zeroize();
            assert!(same, "zeroizing Argon2 memory changed the derived key");
        }
    }

    /// The Argon2 working-memory scrub clears every word of every block
    /// after a real derivation has filled them.
    #[test]
    fn argon2_working_memory_scrub_clears_every_block() {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(64, 1, 1, Some(KEY_LEN)).unwrap(),
        );
        let mut blocks = ScrubbedBlocks(vec![Block::default(); argon2.params().block_count()]);
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into_with_memory(
                b"scrub-input",
                &[3u8; SALT_LEN],
                &mut out,
                &mut blocks.0,
            )
            .unwrap();
        out.zeroize();
        let filled = blocks.0.iter().all(|b| b.as_ref().iter().any(|w| *w != 0));
        assert!(filled, "derivation did not fill the working memory");
        blocks.scrub();
        let cleared = blocks.0.iter().all(|b| b.as_ref().iter().all(|w| *w == 0));
        assert!(cleared, "working memory was not scrubbed");
    }

    /// The zeroizing serializer must emit exactly the bytes the vault wrote
    /// before (`serde_json::to_string_pretty`), so the on-disk plaintext
    /// layout under the AEAD is unchanged.
    #[test]
    fn zeroizing_json_is_byte_identical_to_serde_pretty() {
        let mut map = BTreeMap::new();
        for i in 0..200 {
            map.insert(format!("FIXTURE_NAME_{i:03}"), format!("fixture-value-{i}"));
        }
        let ours = to_json_pretty_zeroizing(&map).unwrap();
        let reference = serde_json::to_string_pretty(&map).unwrap();
        assert!(
            ours.as_slice() == reference.as_bytes(),
            "zeroizing serializer changed the JSON layout"
        );
    }

    /// Growth goes through `reserve_scrubbed`, which always moves into a new
    /// `Zeroizing` allocation (dropping the old one scrubbed) rather than
    /// letting `Vec` reallocate the plaintext prefix in place.
    #[test]
    fn zeroizing_writer_grows_into_fresh_buffers() {
        use std::io::Write;
        let mut writer = ZeroizingWriter::default();
        writer.write_all(&[b'a'; 10]).unwrap();
        assert_eq!(writer.buf.capacity(), ZeroizingWriter::MIN_CAPACITY);
        let chunk = [b'b'; ZeroizingWriter::MIN_CAPACITY];
        writer.write_all(&chunk).unwrap();
        // Policy: max(needed, 2 * old capacity, MIN_CAPACITY).
        assert_eq!(writer.buf.capacity(), 2 * ZeroizingWriter::MIN_CAPACITY);
        let big = vec![b'c'; 5 * ZeroizingWriter::MIN_CAPACITY];
        writer.write_all(&big).unwrap();
        assert_eq!(
            writer.buf.capacity(),
            10 + 6 * ZeroizingWriter::MIN_CAPACITY
        );
        assert_eq!(writer.buf.len(), 10 + 6 * ZeroizingWriter::MIN_CAPACITY);
        assert!(writer.buf[..10].iter().all(|b| *b == b'a'));
    }
}
