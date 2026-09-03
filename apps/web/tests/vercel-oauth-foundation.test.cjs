const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const repoDir = path.resolve(__dirname, "..");
const foundationPath = path.join(
  repoDir,
  "src/lib/vercel-oauth-foundation.ts",
);
const migrationPath = path.join(
  repoDir,
  "supabase/migrations/20260903180004_vercel_oauth_security_foundation.sql",
);
const commissioningPath = path.join(
  repoDir,
  "supabase/VERCEL_OAUTH_COMMISSIONING.md",
);

const USER_A = "11111111-1111-4111-8111-111111111111";
const USER_B = "22222222-2222-4222-8222-222222222222";
const ACTOR_A = { userId: USER_A, plan: "free" };
const ACTOR_B = { userId: USER_B, plan: "free" };

function loadFoundation() {
  const source = fs.readFileSync(foundationPath, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: foundationPath,
  }).outputText;
  const module = { exports: {} };
  const fn = new Function(
    "exports",
    "require",
    "module",
    "__filename",
    "__dirname",
    output,
  );
  fn(
    module.exports,
    require,
    module,
    foundationPath,
    path.dirname(foundationPath),
  );
  return module.exports;
}

function createMemoryClient(now = new Date("2030-01-01T00:00:00.000Z")) {
  const states = new Map();
  const tokenRows = [];
  let nextId = 1;
  let currentNow = new Date(now);

  return {
    states,
    tokenRows,
    setNow(value) {
      currentNow = new Date(value);
    },
    from(table) {
      if (table === "platform_tokens") {
        return {
          async upsert(row, options) {
            tokenRows.push({ row, options });
            return { data: null, error: null };
          },
        };
      }
      throw new Error(`unexpected table: ${table}`);
    },
    async rpc(name, args) {
      if (name === "issue_vercel_oauth_state") {
        const activeStates = [...states.values()].filter(
          (state) =>
            state.user_id === args.p_user_id &&
            state.provider === "vercel" &&
            state.consumed_at === null &&
            Date.parse(state.expires_at) > currentNow.getTime(),
        );
        if (activeStates.length >= 8) {
          return { data: null, error: new Error("active state cap") };
        }
        if (states.has(args.p_state_hash)) {
          return { data: null, error: new Error("duplicate") };
        }
        const state = {
          id: `state-${nextId++}`,
          user_id: args.p_user_id,
          provider: "vercel",
          state_hash: args.p_state_hash,
          expires_at: new Date(
            currentNow.getTime() + 5 * 60 * 1000,
          ).toISOString(),
          consumed_at: null,
        };
        states.set(args.p_state_hash, state);
        return {
          data: [
            {
              state_id: state.id,
              bound_user_id: state.user_id,
              state_expires_at: state.expires_at,
            },
          ],
          error: null,
        };
      }
      assert.equal(name, "consume_vercel_oauth_state");
      const state = states.get(args.p_state_hash);
      if (
        !state ||
        state.user_id !== args.p_user_id ||
        state.provider !== "vercel" ||
        state.consumed_at !== null ||
        Date.parse(state.expires_at) <= currentNow.getTime()
      ) {
        return { data: [], error: null };
      }
      // This mutation happens before yielding, mirroring the row-locked UPDATE
      // performed by the database function.
      state.consumed_at = currentNow.toISOString();
      return {
        data: [
          {
            state_id: state.id,
            bound_user_id: state.user_id,
            state_expires_at: state.expires_at,
          },
        ],
        error: null,
      };
    },
  };
}

test("AES-256-GCM encrypts tokens and authenticates their owner context", () => {
  const {
    decryptVercelAccessToken,
    encryptVercelAccessToken,
  } = loadFoundation();
  const key = { key: Buffer.alloc(32, 7), version: 3 };
  const context = {
    userId: USER_A,
    platformAccountId: "vercel-user-123",
    teamId: "team-123",
    scope: "read-write:project",
  };
  const token = "vercel-test-token-not-a-real-secret";
  const encrypted = encryptVercelAccessToken(
    token,
    context,
    key,
    Buffer.alloc(12, 9),
  );

  assert.equal(encrypted.ciphertext.includes(Buffer.from(token)), false);
  assert.equal(encrypted.nonce.length, 12);
  assert.equal(encrypted.tag.length, 16);
  assert.equal(
    decryptVercelAccessToken(encrypted, context, key),
    token,
  );

  assert.throws(
    () =>
      decryptVercelAccessToken(
        encrypted,
        { ...context, userId: USER_B },
        key,
      ),
    /authenticate data|unable to authenticate/i,
  );
  assert.throws(
    () =>
      decryptVercelAccessToken(
        encrypted,
        { ...context, scope: "read-only:project" },
        key,
      ),
    /authenticate data|unable to authenticate/i,
  );
  assert.throws(
    () =>
      decryptVercelAccessToken(encrypted, context, {
        key: Buffer.alloc(32, 7),
        version: 4,
      }),
    /version is unavailable/,
  );

  const tampered = {
    ...encrypted,
    ciphertext: Buffer.from(encrypted.ciphertext),
  };
  tampered.ciphertext[0] ^= 1;
  assert.throws(
    () => decryptVercelAccessToken(tampered, context, key),
    /authenticate data|unable to authenticate/i,
  );
});

test("fresh nonces produce distinct ciphertext for the same token", () => {
  const { encryptVercelAccessToken } = loadFoundation();
  const key = { key: Buffer.alloc(32, 4), version: 1 };
  const context = {
    userId: USER_A,
    platformAccountId: "vercel-user-123",
  };
  const first = encryptVercelAccessToken(
    "same-test-token",
    context,
    key,
    Buffer.alloc(12, 1),
  );
  const second = encryptVercelAccessToken(
    "same-test-token",
    context,
    key,
    Buffer.alloc(12, 2),
  );

  assert.notDeepEqual(first.nonce, second.nonce);
  assert.notDeepEqual(first.ciphertext, second.ciphertext);
});

test("key versions must fit the PostgreSQL integer storage contract", () => {
  const { encryptVercelAccessToken } = loadFoundation();
  assert.throws(
    () =>
      encryptVercelAccessToken(
        "test-token",
        {
          userId: USER_A,
          platformAccountId: "vercel-user-123",
        },
        { key: Buffer.alloc(32, 3), version: 2_147_483_648 },
      ),
    /positive PostgreSQL integer/,
  );
});

test("token storage writes only authenticated ciphertext fields", async () => {
  const { storeEncryptedVercelAccessToken } = loadFoundation();
  const client = createMemoryClient();
  const plaintext = "vercel-test-token-not-a-real-secret";

  await storeEncryptedVercelAccessToken({
    client,
    actor: ACTOR_A,
    platformAccountId: "vercel-user-123",
    teamId: "team-123",
    scope: "read-write:project",
    accessToken: plaintext,
    key: { key: Buffer.alloc(32, 8), version: 2 },
  });

  assert.equal(client.tokenRows.length, 1);
  const { row, options } = client.tokenRows[0];
  assert.deepEqual(options, { onConflict: "user_id,platform" });
  assert.equal(row.user_id, USER_A);
  assert.equal(row.platform, "vercel");
  assert.equal(row.encryption_key_version, 2);
  assert.equal("access_token" in row, false);
  assert.equal(JSON.stringify(row).includes(plaintext), false);
  assert.match(row.access_token_ciphertext, /^\\x[0-9a-f]+$/);
  assert.match(row.access_token_nonce, /^\\x[0-9a-f]{24}$/);
  assert.match(row.access_token_tag, /^\\x[0-9a-f]{32}$/);
});

test("OAuth state is hashed, user-bound, one-time, and replay-safe", async () => {
  const { consumeVercelOAuthState, issueVercelOAuthState } = loadFoundation();
  const now = new Date("2030-01-01T00:00:00.000Z");
  const client = createMemoryClient(now);
  const state = await issueVercelOAuthState({
    client,
    actor: ACTOR_A,
    entropy: Buffer.alloc(32, 5),
  });

  assert.match(state, /^[A-Za-z0-9_-]{43}$/);
  const persisted = [...client.states.values()][0];
  assert.equal(JSON.stringify(persisted).includes(state), false);
  assert.match(persisted.state_hash, /^\\x[0-9a-f]{64}$/);

  assert.equal(
    await consumeVercelOAuthState({ client, actor: ACTOR_B, state }),
    null,
  );
  const accepted = await consumeVercelOAuthState({
    client,
    actor: ACTOR_A,
    state,
  });
  assert.equal(accepted.userId, USER_A);
  assert.equal(
    await consumeVercelOAuthState({ client, actor: ACTOR_A, state }),
    null,
  );
});

test("expired and malformed OAuth states are denied", async () => {
  const { consumeVercelOAuthState, issueVercelOAuthState } = loadFoundation();
  const client = createMemoryClient();
  const state = await issueVercelOAuthState({
    client,
    actor: ACTOR_A,
    entropy: Buffer.alloc(32, 6),
  });
  client.setNow(new Date("2030-01-01T00:06:00.000Z"));

  assert.equal(
    await consumeVercelOAuthState({ client, actor: ACTOR_A, state }),
    null,
  );
  await assert.rejects(
    consumeVercelOAuthState({
      client,
      actor: ACTOR_A,
      state: "attacker-controlled-state",
    }),
    /invalid OAuth state/,
  );
});

test("per-user issuance is capped before provider activation", async () => {
  const { issueVercelOAuthState } = loadFoundation();
  const client = createMemoryClient();

  for (let index = 1; index <= 8; index += 1) {
    await issueVercelOAuthState({
      client,
      actor: ACTOR_A,
      entropy: Buffer.alloc(32, index),
    });
  }

  await assert.rejects(
    issueVercelOAuthState({
      client,
      actor: ACTOR_A,
      entropy: Buffer.alloc(32, 9),
    }),
    /failed to issue OAuth state/,
  );

  await issueVercelOAuthState({
    client,
    actor: ACTOR_B,
    entropy: Buffer.alloc(32, 10),
  });
});

test("migration removes plaintext storage and atomically consumes state", () => {
  const migration = fs.readFileSync(migrationPath, "utf8");

  assert.match(migration, /IF EXISTS \(SELECT 1 FROM public\.platform_tokens\)/);
  assert.match(migration, /DROP COLUMN access_token/);
  assert.match(migration, /access_token_ciphertext bytea NOT NULL/);
  assert.match(migration, /access_token_nonce bytea NOT NULL/);
  assert.match(migration, /access_token_tag bytea NOT NULL/);
  assert.match(
    migration,
    /encryption_key_version BETWEEN 1 AND 2147483647/,
  );
  assert.match(migration, /ALTER TABLE public\.oauth_states ENABLE ROW LEVEL SECURITY/);
  assert.match(
    migration,
    /REVOKE ALL ON TABLE public\.oauth_states\s+FROM PUBLIC, anon, authenticated/,
  );
  assert.match(migration, /SECURITY INVOKER/);
  assert.match(migration, /SET search_path = pg_catalog/);
  assert.match(
    migration,
    /INSERT INTO public\.oauth_states[\s\S]*v_now \+ interval '5 minutes'/,
  );
  assert.match(migration, /pg_advisory_xact_lock/);
  assert.match(migration, /LIMIT 100[\s\S]*FOR UPDATE/);
  assert.match(migration, /v_active_states >= 8/);
  assert.match(
    migration,
    /UPDATE public\.oauth_states AS state[\s\S]*state\.user_id = p_user_id[\s\S]*state\.consumed_at IS NULL[\s\S]*state\.expires_at > v_now[\s\S]*RETURNING/,
  );
  assert.doesNotMatch(migration, /SECURITY DEFINER/);
});

test("commissioning guidance preserves rotation and retention blockers", () => {
  const guidance = fs.readFileSync(commissioningPath, "utf8");

  assert.match(guidance, /routes remain disabled and return HTTP 503/i);
  assert.match(guidance, /multi-version key provider/i);
  assert.match(guidance, /does not provide rotation by itself/i);
  assert.match(guidance, /scheduled global retention job/i);
  assert.match(guidance, /not evidence that the database migration has been applied/i);
});
