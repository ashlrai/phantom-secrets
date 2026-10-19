//! Self-describing format tag for encrypted blobs (crypto agility, slice 1).
//!
//! Historic blobs ("v1", also called legacy here) carry no tag at all:
//! vault files are `salt || nonce || ciphertext` and team vault blobs are
//! `nonce || ciphertext`. A tagged blob prepends a fixed 6-byte header:
//!
//! ```text
//! magic "PHMB" (4) || format version (1) || algorithm id (1) || legacy body
//! ```
//!
//! The header is bound into the AEAD as associated data, so it cannot be
//! stripped or edited without failing authentication.
//!
//! Compatibility rules:
//! - Readers accept both tagged and untagged blobs. If a blob happens to
//!   start with the magic bytes but does not authenticate as tagged, it is
//!   retried as an untagged blob, so no legacy blob can be misread.
//! - Writers keep emitting the untagged layout unless tagging is switched
//!   on with `PHANTOM_BLOB_FORMAT=v2`. This lets readers ship first. Old
//!   binaries cannot read tagged blobs, so only enable it once every
//!   reader of the data has upgraded. Unset the variable to roll back;
//!   tagged blobs already written stay readable by new binaries.

use crate::error::{PhantomError, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroizing;

/// Magic bytes that start every tagged blob.
pub const MAGIC: [u8; 4] = *b"PHMB";
/// Format version written by tagged blobs.
pub const VERSION_2: u8 = 2;
/// Algorithm id 1: ChaCha20-Poly1305 body (vault: Argon2id derived key).
pub const ALG_CHACHA20_POLY1305: u8 = 1;
/// Header length in bytes.
pub const HEADER_LEN: usize = 6;
/// Environment variable that opts writers into tagged blobs.
pub const FORMAT_ENV: &str = "PHANTOM_BLOB_FORMAT";

const NONCE_LEN: usize = 12;

/// Which layout a writer should emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFormat {
    /// Untagged historic layout (default).
    Legacy,
    /// Tagged layout with the 6-byte header.
    Tagged,
}

impl WriteFormat {
    /// Read the writer format from `PHANTOM_BLOB_FORMAT` (`v2` enables tags).
    pub fn from_env() -> Self {
        match std::env::var(FORMAT_ENV).ok().as_deref() {
            Some("v2") => Self::Tagged,
            _ => Self::Legacy,
        }
    }
}

/// The 6-byte header for a tagged blob.
pub fn header() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&MAGIC);
    h[4] = VERSION_2;
    h[5] = ALG_CHACHA20_POLY1305;
    h
}

/// Result of inspecting a blob prefix.
#[derive(Debug, PartialEq, Eq)]
pub enum Tag<'a> {
    /// No recognised header: treat the whole slice as a legacy body.
    Untagged,
    /// Recognised v2 header; the remainder is the body.
    V2(&'a [u8]),
    /// Magic present but version or algorithm not understood.
    Unsupported { version: u8, alg: u8 },
}

/// Classify a blob by its prefix.
pub fn classify(bytes: &[u8]) -> Tag<'_> {
    if bytes.len() < HEADER_LEN || bytes[..4] != MAGIC {
        return Tag::Untagged;
    }
    let (version, alg) = (bytes[4], bytes[5]);
    if version == VERSION_2 && alg == ALG_CHACHA20_POLY1305 {
        Tag::V2(&bytes[HEADER_LEN..])
    } else {
        Tag::Unsupported { version, alg }
    }
}

/// Seal `plaintext` under a 32-byte key for team vault blobs.
///
/// Legacy: `nonce || ct`. Tagged: `header || nonce || ct` with the header as AAD.
pub fn seal_team_blob(plaintext: &[u8], key: &[u8; 32], format: WriteFormat) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut out = Vec::new();
    let ct = match format {
        WriteFormat::Legacy => cipher.encrypt(nonce, plaintext),
        WriteFormat::Tagged => {
            let h = header();
            out.extend_from_slice(&h);
            cipher.encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &h,
                },
            )
        }
    }
    .map_err(|e| PhantomError::Other(format!("Encrypt failed: {e}")))?;
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_legacy(body: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if body.len() < NONCE_LEN + 16 {
        return None;
    }
    let (nonce_bytes, ct) = body.split_at(NONCE_LEN);
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .ok()
}

/// Open a team vault blob in either layout.
pub fn open_team_blob(framed: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let tag = classify(framed);
    if let Tag::V2(body) = &tag {
        if body.len() >= NONCE_LEN + 16 {
            let (nonce_bytes, ct) = body.split_at(NONCE_LEN);
            if let Ok(pt) = ChaCha20Poly1305::new(key.into()).decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ct,
                    aad: &framed[..HEADER_LEN],
                },
            ) {
                return Ok(Zeroizing::new(pt));
            }
        }
    }
    // Untagged, or magic collided with a legacy nonce: legacy layout.
    if let Some(pt) = open_legacy(framed, key) {
        return Ok(Zeroizing::new(pt));
    }
    if let Tag::Unsupported { version, alg } = tag {
        return Err(PhantomError::Other(format!(
            "Unsupported blob format (version {version}, algorithm {alg}); upgrade phantom"
        )));
    }
    Err(PhantomError::Other(
        "Decrypt failed: wrong key or corrupt data".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    /// Fixture built with the pre-tag code path: nonce || ct, key = [7; 32].
    fn legacy_fixture() -> Vec<u8> {
        let nonce = [9u8; NONCE_LEN];
        let ct = ChaCha20Poly1305::new((&KEY).into())
            .encrypt(Nonce::from_slice(&nonce), b"{\"A\":\"1\"}".as_ref())
            .unwrap();
        let mut v = nonce.to_vec();
        v.extend_from_slice(&ct);
        v
    }

    #[test]
    fn legacy_fixture_still_opens() {
        let pt = open_team_blob(&legacy_fixture(), &KEY).unwrap();
        assert_eq!(pt.as_slice(), b"{\"A\":\"1\"}");
    }

    #[test]
    fn legacy_layout_is_byte_identical_to_old_writer() {
        let blob = seal_team_blob(b"x", &KEY, WriteFormat::Legacy).unwrap();
        assert_eq!(blob.len(), NONCE_LEN + 1 + 16);
        assert_eq!(classify(&blob[..]), Tag::Untagged);
    }

    #[test]
    fn tagged_round_trip() {
        let blob = seal_team_blob(b"hello", &KEY, WriteFormat::Tagged).unwrap();
        assert_eq!(&blob[..4], b"PHMB");
        assert_eq!(blob[4], VERSION_2);
        assert_eq!(open_team_blob(&blob, &KEY).unwrap().as_slice(), b"hello");
    }

    #[test]
    fn tagged_header_tamper_fails() {
        let mut blob = seal_team_blob(b"hello", &KEY, WriteFormat::Tagged).unwrap();
        blob[5] ^= 1;
        assert!(open_team_blob(&blob, &KEY).is_err());
    }

    #[test]
    fn stripping_header_fails() {
        let blob = seal_team_blob(b"hello", &KEY, WriteFormat::Tagged).unwrap();
        assert!(open_team_blob(&blob[HEADER_LEN..], &KEY).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal_team_blob(b"hello", &KEY, WriteFormat::Tagged).unwrap();
        assert!(open_team_blob(&blob, &[8u8; 32]).is_err());
    }

    #[test]
    fn unknown_version_is_reported() {
        let mut blob = seal_team_blob(b"hello", &KEY, WriteFormat::Tagged).unwrap();
        blob[4] = 9;
        let err = open_team_blob(&blob, &KEY).unwrap_err().to_string();
        assert!(err.contains("Unsupported blob format"), "{err}");
    }

    #[test]
    fn legacy_blob_whose_nonce_collides_with_magic_still_opens() {
        let mut nonce = [3u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&MAGIC);
        nonce[4] = VERSION_2;
        nonce[5] = ALG_CHACHA20_POLY1305;
        let ct = ChaCha20Poly1305::new((&KEY).into())
            .encrypt(Nonce::from_slice(&nonce), b"edge".as_ref())
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        assert!(matches!(classify(&blob), Tag::V2(_)));
        assert_eq!(open_team_blob(&blob, &KEY).unwrap().as_slice(), b"edge");
    }

    #[test]
    fn legacy_blob_whose_nonce_collides_with_an_unsupported_header_still_opens() {
        for (version, alg) in [(3u8, 1u8), (VERSION_2, 0xff), (0xff, 0xff)] {
            let mut nonce = [4u8; NONCE_LEN];
            nonce[..4].copy_from_slice(&MAGIC);
            nonce[4] = version;
            nonce[5] = alg;
            let ct = ChaCha20Poly1305::new((&KEY).into())
                .encrypt(Nonce::from_slice(&nonce), b"edge".as_ref())
                .unwrap();
            let mut blob = nonce.to_vec();
            blob.extend_from_slice(&ct);
            assert!(matches!(classify(&blob), Tag::Unsupported { .. }));
            assert_eq!(
                open_team_blob(&blob, &KEY).unwrap().as_slice(),
                b"edge",
                "v{version} a{alg}"
            );
        }
    }

    #[test]
    fn default_env_is_legacy() {
        // Do not mutate the environment (tests run in parallel); just check
        // the parser against the current process value.
        let expected = match std::env::var(FORMAT_ENV).ok().as_deref() {
            Some("v2") => WriteFormat::Tagged,
            _ => WriteFormat::Legacy,
        };
        assert_eq!(WriteFormat::from_env(), expected);
    }
}
