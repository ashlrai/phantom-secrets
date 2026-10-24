const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");

function load(rel, req) {
  const file = path.join(webDir, rel);
  const out = ts.transpileModule(fs.readFileSync(file, "utf8"), {
    compilerOptions: { esModuleInterop: true, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    fileName: file,
  }).outputText;
  const m = { exports: {} };
  new Function("exports", "require", "module", "__filename", "__dirname", out)(m.exports, req, m, file, path.dirname(file));
  return m.exports;
}

const lib = load("src/lib/team-key.ts", require);
const b64 = (n, fill = 7) => Buffer.alloc(n, fill).toString("base64");
const CLASSIC_PK = b64(32);
const XWING_PK = b64(1216);
const classicShare = { ephemeral_pk: b64(32, 1), nonce: b64(24, 2), ciphertext: b64(48, 3) };
const hybridShare = { v: 3, alg: "xwing-chacha20poly1305", kem_ct: b64(1120, 4), nonce: b64(12, 5), ciphertext: b64(48, 6) };

function loadVaultRoute(members, captured) {
  return load("src/app/api/v1/teams/[team_id]/vaults/[project_id]/route.ts", (s) => {
    if (s === "@/lib/commissioning") return { requireHostedService: () => null };
    if (s === "@/lib/auth") return { requireAuth: async () => ({ userId: "a" }), requirePro: () => null };
    if (s === "@/lib/team-key") return lib;
    if (s === "@/lib/http-body") {
      return {
        readBoundedJsonObject: async (req) => req.json(),
        requestBodyErrorResponse: () => Response.json({ error: "bad body" }, { status: 400 }),
      };
    }
    if (s === "@/lib/supabase-server") {
      return {
        createServiceClient: () => ({
          from: (table) => {
            const q = {
              select: () => q,
              eq: () => q,
              not: () => q,
              insert: (v) => { captured.insert = v; return q; },
              update: (v) => { captured.update = v; return q; },
              single: async () => ({ data: { version: 1 }, error: null }),
              maybeSingle: async () =>
                table === "team_members" ? { data: { public_key: CLASSIC_PK } } : { data: null },
              then: (res) => res({ data: members, error: null }),
            };
            return q;
          },
        }),
      };
    }
    return require(s);
  });
}

const ctx = { params: Promise.resolve({ team_id: "t1", project_id: "p1" }) };
async function push(members, wrappedKeys) {
  const captured = {};
  const route = loadVaultRoute(members, captured);
  const res = await route.POST(
    new Request("https://phm.dev/x", {
      method: "POST",
      body: JSON.stringify({ encrypted_blob: "blob", expected_version: 0, key_shares: wrappedKeys }),
    }),
    ctx
  );
  return { res, body: await res.json(), captured };
}

const MIXED = [
  { user_id: "a", public_key: CLASSIC_PK },
  { user_id: "b", public_key: XWING_PK },
];

test("classic-only team: an old-client push is unchanged and stored", async () => {
  const { res, body, captured } = await push([{ user_id: "a", public_key: CLASSIC_PK }], { a: classicShare });
  assert.equal(res.status, 200);
  assert.deepEqual(body, { version: 1, members_covered: 1 });
  assert.deepEqual(captured.insert.key_shares, { a: classicShare });
});

test("mixed team: an old client that omits the hybrid member is refused with 426, nothing stored", async () => {
  const { res, body, captured } = await push(MIXED, { a: classicShare });
  assert.equal(res.status, 426);
  assert.equal(body.error, "client_upgrade_required");
  assert.equal(body.min_client_version, null);
  assert.deepEqual(body.hybrid_members, ["b"]);
  assert.match(body.message, /never falls back to classic-only wrapping/);
  assert.match(body.message, /No released Phantom version can push to it yet\./);
  assert.match(body.message, /brew upgrade ashlrai\/phantom\/phantom/);
  assert.equal(captured.insert, undefined);
  assert.equal(captured.update, undefined);
});

test("mixed team: a classic share for the hybrid member is refused (no downgrade)", async () => {
  for (const share of [classicShare, "opaque-string-share"]) {
    const { res, body, captured } = await push(MIXED, { a: classicShare, b: share });
    assert.equal(res.status, 426, JSON.stringify(share));
    assert.deepEqual(body.hybrid_members, ["b"]);
    assert.equal(captured.insert, undefined);
  }
  // Wrong version or algorithm tag is not a share shape at all: refused before the gate.
  for (const share of [{ ...hybridShare, v: 2 }, { ...hybridShare, alg: "x25519" }]) {
    const { res, captured } = await push(MIXED, { a: classicShare, b: share });
    assert.equal(res.status, 400);
    assert.equal(captured.insert, undefined);
  }
});

test("mixed team: a push with a hybrid share for the hybrid member passes the gate", async () => {
  const { res, body, captured } = await push(MIXED, { a: classicShare, b: hybridShare });
  assert.equal(res.status, 200);
  assert.deepEqual(body, { version: 1, members_covered: 2 });
  assert.deepEqual(captured.insert.key_shares.b, hybridShare);
});

test("a hybrid share given to a classic-key member is refused", async () => {
  const { res, body } = await push(MIXED, { a: hybridShare, b: hybridShare });
  assert.equal(res.status, 400);
  assert.equal(body.error, "share_alg_mismatch");
  assert.deepEqual(body.members, ["a"]);
});

test("classic coverage errors are unchanged when no hybrid member is involved", async () => {
  const { res, body } = await push([{ user_id: "a", public_key: CLASSIC_PK }, { user_id: "c", public_key: CLASSIC_PK }], { a: classicShare });
  assert.equal(res.status, 400);
  assert.equal(body.error, "shares_mismatch");
  assert.deepEqual(body.missing, ["c"]);
});

test("min client version is a placeholder until release and only named when set", () => {
  assert.equal(lib.HYBRID_TEAM_MIN_CLIENT_VERSION_SET_AT_RELEASE, null);
  const r = lib.refuseClassicOnlyPush(MIXED, { a: classicShare }, "9.9.9-test");
  assert.equal(r.body.min_client_version, "9.9.9-test");
  assert.match(r.body.message, /requires Phantom 9\.9\.9-test or later/);
  assert.equal(lib.refuseClassicOnlyPush([{ user_id: "a", public_key: CLASSIC_PK }], {}), null);
});
