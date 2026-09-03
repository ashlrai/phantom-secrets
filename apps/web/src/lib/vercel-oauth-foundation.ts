import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

import type { AuthUser } from "./auth";

const STATE_BYTES = 32;
const TOKEN_NONCE_BYTES = 12;
const TOKEN_TAG_BYTES = 16;
const MAX_TOKEN_BYTES = 65_536;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL_STATE = /^[A-Za-z0-9_-]{43}$/;

type QueryResult<T> = Promise<{ data: T | null; error: unknown | null }>;

interface EncryptedTokenRow {
  user_id: string;
  platform: "vercel";
  platform_account_id: string;
  access_token_ciphertext: string;
  access_token_nonce: string;
  access_token_tag: string;
  encryption_key_version: number;
  team_id: string | null;
  scope: string | null;
}

export interface OAuthStoreClient {
  from(table: "platform_tokens"): {
    upsert(
      row: EncryptedTokenRow,
      options: { onConflict: "user_id,platform" },
    ): QueryResult<unknown>;
  };
  rpc(
    functionName: "issue_vercel_oauth_state",
    args: { p_state_hash: string; p_user_id: string },
  ): QueryResult<
    Array<{
      state_id: string;
      bound_user_id: string;
      state_expires_at: string;
    }>
  >;
  rpc(
    functionName: "consume_vercel_oauth_state",
    args: { p_state_hash: string; p_user_id: string },
  ): QueryResult<
    Array<{
      state_id: string;
      bound_user_id: string;
      state_expires_at: string;
    }>
  >;
}

export interface PlatformTokenKey {
  key: Buffer;
  version: number;
}

interface PlatformTokenContext {
  userId: string;
  platformAccountId: string;
  teamId?: string | null;
}

function requireUuid(value: string, label: string): void {
  if (!UUID.test(value)) throw new Error(`${label} must be a UUID`);
}

function requireBoundedText(
  value: string,
  label: string,
  maxBytes: number,
): void {
  const length = Buffer.byteLength(value, "utf8");
  if (length === 0 || length > maxBytes) {
    throw new Error(`${label} must contain between 1 and ${maxBytes} bytes`);
  }
}

function bytea(value: Buffer): string {
  return `\\x${value.toString("hex")}`;
}

function tokenAad(
  context: PlatformTokenContext,
  keyVersion: number,
): Buffer {
  return Buffer.from(
    JSON.stringify([
      "phantom-platform-token",
      1,
      "vercel",
      context.userId,
      context.platformAccountId,
      context.teamId ?? null,
      keyVersion,
    ]),
    "utf8",
  );
}

function validateKey(key: PlatformTokenKey): void {
  if (!Buffer.isBuffer(key.key) || key.key.length !== 32) {
    throw new Error("platform token encryption key must be 32 bytes");
  }
  if (!Number.isSafeInteger(key.version) || key.version <= 0) {
    throw new Error("platform token encryption key version must be positive");
  }
}

function stateHash(state: string): Buffer {
  if (!BASE64URL_STATE.test(state)) {
    throw new Error("invalid OAuth state");
  }
  const decoded = Buffer.from(state, "base64url");
  if (decoded.length !== STATE_BYTES) throw new Error("invalid OAuth state");
  return createHash("sha256").update(decoded).digest();
}

export function platformTokenKeyFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): PlatformTokenKey {
  const encoded = env.PHANTOM_PLATFORM_TOKEN_ENCRYPTION_KEY;
  const version = Number(env.PHANTOM_PLATFORM_TOKEN_ENCRYPTION_KEY_VERSION);
  if (!encoded || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) {
    throw new Error("platform token encryption key is not configured");
  }
  const key = { key: Buffer.from(encoded, "base64url"), version };
  validateKey(key);
  return key;
}

export function encryptVercelAccessToken(
  accessToken: string,
  context: PlatformTokenContext,
  key: PlatformTokenKey,
  nonce: Buffer = randomBytes(TOKEN_NONCE_BYTES),
): {
  ciphertext: Buffer;
  nonce: Buffer;
  tag: Buffer;
  keyVersion: number;
} {
  validateKey(key);
  requireUuid(context.userId, "userId");
  requireBoundedText(context.platformAccountId, "platformAccountId", 256);
  if (context.teamId !== null && context.teamId !== undefined) {
    requireBoundedText(context.teamId, "teamId", 256);
  }
  requireBoundedText(accessToken, "accessToken", MAX_TOKEN_BYTES);
  if (!Buffer.isBuffer(nonce) || nonce.length !== TOKEN_NONCE_BYTES) {
    throw new Error("platform token nonce must be 12 bytes");
  }

  const cipher = createCipheriv("aes-256-gcm", key.key, nonce, {
    authTagLength: TOKEN_TAG_BYTES,
  });
  cipher.setAAD(tokenAad(context, key.version));
  const ciphertext = Buffer.concat([
    cipher.update(accessToken, "utf8"),
    cipher.final(),
  ]);

  return {
    ciphertext,
    nonce: Buffer.from(nonce),
    tag: cipher.getAuthTag(),
    keyVersion: key.version,
  };
}

export function decryptVercelAccessToken(
  encrypted: {
    ciphertext: Buffer;
    nonce: Buffer;
    tag: Buffer;
    keyVersion: number;
  },
  context: PlatformTokenContext,
  key: PlatformTokenKey,
): string {
  validateKey(key);
  requireUuid(context.userId, "userId");
  requireBoundedText(context.platformAccountId, "platformAccountId", 256);
  if (context.teamId !== null && context.teamId !== undefined) {
    requireBoundedText(context.teamId, "teamId", 256);
  }
  if (encrypted.keyVersion !== key.version) {
    throw new Error("platform token encryption key version is unavailable");
  }
  if (
    !Buffer.isBuffer(encrypted.ciphertext) ||
    encrypted.ciphertext.length === 0 ||
    encrypted.ciphertext.length > MAX_TOKEN_BYTES
  ) {
    throw new Error("invalid platform token ciphertext");
  }
  if (
    !Buffer.isBuffer(encrypted.nonce) ||
    encrypted.nonce.length !== TOKEN_NONCE_BYTES
  ) {
    throw new Error("invalid platform token nonce");
  }
  if (
    !Buffer.isBuffer(encrypted.tag) ||
    encrypted.tag.length !== TOKEN_TAG_BYTES
  ) {
    throw new Error("invalid platform token authentication tag");
  }

  const decipher = createDecipheriv("aes-256-gcm", key.key, encrypted.nonce, {
    authTagLength: TOKEN_TAG_BYTES,
  });
  decipher.setAAD(tokenAad(context, key.version));
  decipher.setAuthTag(encrypted.tag);
  const plaintext = Buffer.concat([
    decipher.update(encrypted.ciphertext),
    decipher.final(),
  ]);
  if (plaintext.length === 0 || plaintext.length > MAX_TOKEN_BYTES) {
    throw new Error("invalid platform token plaintext length");
  }
  return plaintext.toString("utf8");
}

export async function issueVercelOAuthState({
  client,
  actor,
  entropy = randomBytes(STATE_BYTES),
}: {
  client: OAuthStoreClient;
  actor: AuthUser;
  entropy?: Buffer;
}): Promise<string> {
  const { userId } = actor;
  requireUuid(userId, "userId");
  if (!Buffer.isBuffer(entropy) || entropy.length !== STATE_BYTES) {
    throw new Error("OAuth state entropy must be 32 bytes");
  }

  const state = entropy.toString("base64url");
  const { data, error } = await client.rpc("issue_vercel_oauth_state", {
    p_state_hash: bytea(stateHash(state)),
    p_user_id: userId,
  });
  if (
    error ||
    !data ||
    data.length !== 1 ||
    data[0].bound_user_id !== userId
  ) {
    throw new Error("failed to issue OAuth state");
  }
  return state;
}

export async function consumeVercelOAuthState({
  client,
  actor,
  state,
}: {
  client: OAuthStoreClient;
  actor: AuthUser;
  state: string;
}): Promise<{ stateId: string; userId: string; expiresAt: string } | null> {
  const { userId } = actor;
  requireUuid(userId, "userId");
  const { data, error } = await client.rpc("consume_vercel_oauth_state", {
    p_state_hash: bytea(stateHash(state)),
    p_user_id: userId,
  });
  if (error) throw new Error("failed to consume OAuth state");
  if (!data || data.length !== 1) return null;
  const consumed = data[0];
  if (consumed.bound_user_id !== userId) {
    throw new Error("OAuth state user binding mismatch");
  }
  return {
    stateId: consumed.state_id,
    userId: consumed.bound_user_id,
    expiresAt: consumed.state_expires_at,
  };
}

export async function storeEncryptedVercelAccessToken({
  client,
  actor,
  platformAccountId,
  teamId = null,
  scope = null,
  accessToken,
  key,
}: {
  client: OAuthStoreClient;
  actor: AuthUser;
  platformAccountId: string;
  teamId?: string | null;
  scope?: string | null;
  accessToken: string;
  key: PlatformTokenKey;
}): Promise<void> {
  const { userId } = actor;
  if (scope !== null) requireBoundedText(scope, "scope", 4096);
  const encrypted = encryptVercelAccessToken(
    accessToken,
    { userId, platformAccountId, teamId },
    key,
  );
  const { error } = await client.from("platform_tokens").upsert(
    {
      user_id: userId,
      platform: "vercel",
      platform_account_id: platformAccountId,
      access_token_ciphertext: bytea(encrypted.ciphertext),
      access_token_nonce: bytea(encrypted.nonce),
      access_token_tag: bytea(encrypted.tag),
      encryption_key_version: encrypted.keyVersion,
      team_id: teamId,
      scope,
    },
    { onConflict: "user_id,platform" },
  );
  if (error) throw new Error("failed to store encrypted Vercel token");
}
