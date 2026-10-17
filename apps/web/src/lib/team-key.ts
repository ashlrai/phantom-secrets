/**
 * Team public key registration formats.
 *
 * Classic (default): X25519 public key, exactly 32 bytes, canonical padded
 * base64. Sent as `{ public_key }` with no tag, exactly as old clients do.
 *
 * Hybrid (opt in): X-Wing (X25519 + ML-KEM-768) encapsulation key, exactly
 * 1216 bytes (crates/phantom-core/src/team_crypto_pq.rs, `public_b64`). It must
 * be declared with the share format tag from the vault/share format work:
 * `{ public_key, v: 2, alg: "xwing-chacha20poly1305" }`. A key whose length
 * does not match its declared algorithm is rejected, and an untagged key is
 * always treated as classic, so an old client can never register a hybrid key
 * by accident.
 */

export const CLASSIC_ALG = "x25519";
export const XWING_ALG = "xwing-chacha20poly1305";
export const SHARE_FORMAT_VERSION = 2;

export const CLASSIC_KEY_BYTES = 32;
export const XWING_KEY_BYTES = 1216;
/** Longest accepted base64 string: ceil(1216 / 3) * 4. Hard cap before decoding. */
export const MAX_PUBLIC_KEY_CHARS = 1624;

export type TeamKeyAlg = typeof CLASSIC_ALG | typeof XWING_ALG;

export type ParsedTeamKey =
  | { ok: true; alg: TeamKeyAlg }
  | { ok: false; error: string };

function canonicalBase64Bytes(pk: string): number | null {
  if (pk.length === 0 || pk.length > MAX_PUBLIC_KEY_CHARS) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(pk) || pk.length % 4 !== 0) return null;
  let decoded: Buffer;
  try {
    decoded = Buffer.from(pk, "base64");
  } catch {
    return null;
  }
  return decoded.toString("base64") === pk ? decoded.length : null;
}

/** Algorithm implied by a stored key's decoded length, or null if neither. */
export function algForStoredKey(pk: string | null | undefined): TeamKeyAlg | null {
  if (!pk) return null;
  const n = canonicalBase64Bytes(pk);
  if (n === CLASSIC_KEY_BYTES) return CLASSIC_ALG;
  if (n === XWING_KEY_BYTES) return XWING_ALG;
  return null;
}

export function parseTeamKeyRegistration(body: {
  public_key?: unknown;
  v?: unknown;
  alg?: unknown;
}): ParsedTeamKey {
  const { public_key: pk, v, alg } = body;
  if (!pk || typeof pk !== "string") {
    return { ok: false, error: "public_key required" };
  }
  const tagged = v !== undefined || alg !== undefined;
  if (!tagged) {
    // Old clients: unchanged behavior and unchanged error text.
    return canonicalBase64Bytes(pk) === CLASSIC_KEY_BYTES
      ? { ok: true, alg: CLASSIC_ALG }
      : { ok: false, error: "public_key must be base64-encoded 32 bytes" };
  }
  if (alg === CLASSIC_ALG && (v === undefined || v === SHARE_FORMAT_VERSION)) {
    return canonicalBase64Bytes(pk) === CLASSIC_KEY_BYTES
      ? { ok: true, alg: CLASSIC_ALG }
      : { ok: false, error: "public_key must be base64-encoded 32 bytes" };
  }
  if (alg === XWING_ALG && v === SHARE_FORMAT_VERSION) {
    return canonicalBase64Bytes(pk) === XWING_KEY_BYTES
      ? { ok: true, alg: XWING_ALG }
      : { ok: false, error: "public_key must be base64-encoded 1216 bytes for alg xwing-chacha20poly1305" };
  }
  return {
    ok: false,
    error: `unsupported key format: v must be ${SHARE_FORMAT_VERSION} and alg one of ${CLASSIC_ALG}, ${XWING_ALG}`,
  };
}
