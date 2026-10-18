//! Grover check: every symmetric key Phantom uses is 256 bits.
//!
//! Grover's algorithm gives a quadratic speedup against brute-force key search
//! (NIST SP 800-57 and the NIST PQC FAQ both treat 256-bit symmetric keys as the
//! comfortable margin; AES-128 is still considered acceptable by NIST, but this
//! project keeps the larger margin). This test pins that margin so a future
//! change cannot quietly introduce a smaller key.
//!
//! It checks three things:
//! 1. the key size of each AEAD cipher type the workspace depends on,
//! 2. the length of generated symmetric keys exposed by `phantom-core`,
//! 3. a source scan that fails if a 128-bit or 192-bit AES type, or a
//!    reduced-round ChaCha type, is named anywhere in the workspace crates.
//!
//! No key material is printed or compared; only lengths.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::KeySizeUser;
use chacha20poly1305::ChaCha20Poly1305;
use std::path::{Path, PathBuf};

const REQUIRED_KEY_BYTES: usize = 32;

#[test]
fn aead_cipher_types_use_256_bit_keys() {
    assert_eq!(
        <ChaCha20Poly1305 as KeySizeUser>::key_size(),
        REQUIRED_KEY_BYTES
    );
    assert_eq!(<Aes256Gcm as KeySizeUser>::key_size(), REQUIRED_KEY_BYTES);
}

#[test]
fn generated_team_symmetric_key_is_256_bits() {
    let key = phantom_core::team_crypto::generate_sym_key();
    assert_eq!(key.len() * 8, 256);
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_sub_256_bit_symmetric_cipher_is_named_in_workspace_sources() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    collect_rs(&crates_dir, &mut files);
    assert!(!files.is_empty(), "source scan found no files");

    // Built from two halves so this file does not match its own scan.
    let banned: Vec<String> = [
        ("Aes", "128Gcm"),
        ("Aes", "192Gcm"),
        ("Aes", "128Siv"),
        ("Aes", "128"),
        ("Aes", "192"),
        ("ChaCha", "8Poly1305"),
        ("ChaCha", "12Poly1305"),
    ]
    .iter()
    .map(|(a, b)| format!("{a}{b}"))
    .collect();

    let this_file = Path::new(file!()).file_name().unwrap().to_owned();
    let mut hits = Vec::new();
    for file in files {
        if file.file_name() == Some(this_file.as_os_str()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for name in &banned {
            if text.contains(name.as_str()) {
                hits.push(format!("{} names {}", file.display(), name));
            }
        }
    }
    assert!(hits.is_empty(), "sub-256-bit cipher found: {hits:?}");
}
