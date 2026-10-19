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

/**
 * Hybrid share wire format, `HybridKeyShare` in
 * crates/phantom-core/src/team_crypto_pq.rs (`HYBRID_SHARE_VERSION` = 3).
 */
export const HYBRID_SHARE_VERSION = 3;

export type HybridKeyShare = {
  v: number;
  alg: string;
  kem_ct: string;
  nonce: string;
  ciphertext: string;
};

export function isHybridKeyShare(value: unknown): value is HybridKeyShare {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const s = value as Partial<HybridKeyShare>;
  return (
    s.v === HYBRID_SHARE_VERSION &&
    s.alg === XWING_ALG &&
    typeof s.kem_ct === "string" &&
    typeof s.nonce === "string" &&
    typeof s.ciphertext === "string"
  );
}

/**
 * Minimum Phantom client version that can wrap a team vault key for a hybrid
 * (X-Wing) member. PLACEHOLDER: no released client does this yet, so it is
 * null. Set it to the real version string in the release that ships hybrid
 * team wrapping, and not before. While it is null, the refusal says that no
 * released version supports hybrid team keys yet instead of naming a version.
 */
export const HYBRID_TEAM_MIN_CLIENT_VERSION_SET_AT_RELEASE: string | null = null;

export const CLIENT_UPGRADE_REQUIRED = "client_upgrade_required";

export const PHANTOM_UPGRADE_HINT =
  "Upgrade Phantom: on macOS run `brew upgrade ashlrai/phantom/phantom`; on Linux or Windows download the matching asset from https://github.com/ashlrai/phantom-secrets/releases.";

export type MixedTeamRefusal = {
  status: 426;
  body: {
    error: typeof CLIENT_UPGRADE_REQUIRED;
    min_client_version: string | null;
    hybrid_members: string[];
    message: string;
  };
};

/**
 * Fail closed for teams that contain a hybrid-key member. Every member whose
 * registered key is X-Wing must receive a hybrid share in this push. A push
 * that omits such a member (an old client, which never sees hybrid keys) or
 * gives it anything but a hybrid share is refused. The server never accepts a
 * classic-only wrapping for a team with a hybrid-key member, and never drops
 * that member from the coverage check.
 */
export function refuseClassicOnlyPush(
  members: ReadonlyArray<{ user_id: string; public_key: string | null }>,
  wrappedKeys: Record<string, unknown>,
  minVersion: string | null = HYBRID_TEAM_MIN_CLIENT_VERSION_SET_AT_RELEASE
): MixedTeamRefusal | null {
  const hybrid = members
    .filter((m) => algForStoredKey(m.public_key) === XWING_ALG)
    .map((m) => m.user_id);
  const unserved = hybrid.filter(
    (u) => !Object.prototype.hasOwnProperty.call(wrappedKeys, u) || !isHybridKeyShare(wrappedKeys[u])
  );
  if (unserved.length === 0) return null;
  const need = minVersion
    ? `Pushing to it requires Phantom ${minVersion} or later.`
    : "No released Phantom version can push to it yet.";
  return {
    status: 426,
    body: {
      error: CLIENT_UPGRADE_REQUIRED,
      min_client_version: minVersion,
      hybrid_members: unserved,
      message: `This team has ${unserved.length === 1 ? "a member" : "members"} with a hybrid post-quantum team key, and this push does not include a hybrid key share for ${unserved.length === 1 ? "that member" : "them"}. Phantom never falls back to classic-only wrapping. ${need} ${PHANTOM_UPGRADE_HINT}`,
    },
  };
}
