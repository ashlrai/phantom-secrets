### Security (Argon2 working memory and vault plaintext buffers are scrubbed)

- Encrypted-file vault key derivation now supplies its own Argon2 block
  memory and scrubs the whole working set (up to 64 MiB) on drop, including
  on error paths. `hash_password_into` freed that memory unscrubbed, and the
  final memory block alone determines the derived key. The `argon2` crate's
  `zeroize` feature is enabled so its internal hash state is cleared too.
- `phantom_vault::crypto::decrypt` (and the per-vault warm-unlock cache) now
  returns plaintext in a `Zeroizing<Vec<u8>>`, so decrypted vault JSON is
  scrubbed on drop even if a caller forgets to wrap it. Derived keys moved to
  `Zeroizing<[u8; 32]>`; manual `key.zeroize()` calls were removed.
- The vault's pretty-JSON write path serializes through a zeroizing `Write`
  sink that grows by copying into a fresh scrubbed buffer instead of letting
  `Vec` reallocate plaintext prefixes in place. Emitted bytes are identical.
