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
const TAG = { v: 2, alg: "xwing-chacha20poly1305" };

test("old clients: untagged 32-byte key accepted, behavior and errors unchanged", () => {
  assert.deepEqual(lib.parseTeamKeyRegistration({ public_key: b64(32) }), { ok: true, alg: "x25519" });
  for (const bad of [b64(31), b64(33), b64(1216), "not base64!", b64(32).replace("=", "")]) {
    assert.deepEqual(lib.parseTeamKeyRegistration({ public_key: bad }), {
      ok: false,
      error: "public_key must be base64-encoded 32 bytes",
    });
  }
  assert.deepEqual(lib.parseTeamKeyRegistration({}), { ok: false, error: "public_key required" });
});

test("an untagged 1216-byte key is never accepted (old client cannot register hybrid by accident)", () => {
  assert.equal(lib.parseTeamKeyRegistration({ public_key: b64(1216) }).ok, false);
});

test("tagged X-Wing key: exactly 1216 bytes accepted, other sizes rejected", () => {
  assert.deepEqual(lib.parseTeamKeyRegistration({ public_key: b64(1216), ...TAG }), {
    ok: true,
    alg: "xwing-chacha20poly1305",
  });
  for (const n of [32, 1215, 1217, 4096]) {
    assert.equal(lib.parseTeamKeyRegistration({ public_key: b64(n), ...TAG }).ok, false, `size ${n}`);
  }
});

test("explicit size cap applies before decoding", () => {
  assert.equal(lib.MAX_PUBLIC_KEY_CHARS, Math.ceil(1216 / 3) * 4);
  assert.equal(b64(1216).length, lib.MAX_PUBLIC_KEY_CHARS);
  assert.equal(lib.parseTeamKeyRegistration({ public_key: "A".repeat(lib.MAX_PUBLIC_KEY_CHARS + 4), ...TAG }).ok, false);
});

test("tagged classic is accepted; unknown or mismatched tags are rejected", () => {
  assert.equal(lib.parseTeamKeyRegistration({ public_key: b64(32), alg: "x25519" }).ok, true);
  assert.equal(lib.parseTeamKeyRegistration({ public_key: b64(1216), v: 3, alg: "xwing-chacha20poly1305" }).ok, false);
  assert.equal(lib.parseTeamKeyRegistration({ public_key: b64(1216), alg: "xwing-chacha20poly1305" }).ok, false);
  assert.equal(lib.parseTeamKeyRegistration({ public_key: b64(1216), v: 2, alg: "nope" }).ok, false);
  assert.equal(lib.parseTeamKeyRegistration({ public_key: b64(32), v: 2 }).ok, false);
});

test("stored key algorithm is derived from length", () => {
  assert.equal(lib.algForStoredKey(b64(32)), "x25519");
  assert.equal(lib.algForStoredKey(b64(1216)), "xwing-chacha20poly1305");
  assert.equal(lib.algForStoredKey(null), null);
  assert.equal(lib.algForStoredKey(b64(10)), null);
});

function loadRoute(rows, captured) {
  const teamKey = lib;
  return load("src/app/api/v1/teams/[team_id]/key/route.ts", (s) => {
    if (s === "@/lib/commissioning") return { requireHostedService: () => null };
    if (s === "@/lib/auth") return { requireAuth: async () => ({ userId: "u1" }) };
    if (s === "@/lib/team-key") return teamKey;
    if (s === "@/lib/http-body") {
      return {
        readBoundedJsonObject: async (req) => req.json(),
        requestBodyErrorResponse: () => Response.json({ error: "bad body" }, { status: 400 }),
      };
    }
    if (s === "@/lib/supabase-server") {
      return {
        createServiceClient: () => ({
          from: () => {
            const q = {
              select: () => q,
              eq: () => q,
              update: (v) => { captured.update = v; return q; },
              maybeSingle: async () => ({ data: { id: "m1" } }),
              then: (res) => res({ data: rows, error: null }),
            };
            return q;
          },
        }),
      };
    }
    return require(s);
  });
}
const ctx = { params: Promise.resolve({ team_id: "t1" }) };

test("route POST: classic default stores key; tagged X-Wing stores key; bad size is 400", async () => {
  const cap = {};
  const route = loadRoute([], cap);
  const post = (body) => route.POST(new Request("https://phm.dev/x", { method: "POST", body: JSON.stringify(body) }), ctx);
  let r = await post({ public_key: b64(32) });
  assert.equal(r.status, 200);
  assert.equal(cap.update.public_key, b64(32));
  r = await post({ public_key: b64(1216), ...TAG });
  assert.equal(r.status, 200);
  assert.equal(cap.update.public_key, b64(1216));
  r = await post({ public_key: b64(1216) });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "public_key must be base64-encoded 32 bytes");
});

test("route GET: default hides hybrid keys from old clients; ?algs=all lists them with alg", async () => {
  const rows = [
    { user_id: "a", public_key: b64(32) },
    { user_id: "b", public_key: b64(1216) },
    { user_id: "c", public_key: null },
  ];
  const route = loadRoute(rows, {});
  let j = await (await route.GET(new Request("https://phm.dev/x"), ctx)).json();
  assert.deepEqual(j.members.map((m) => m.public_key), [b64(32), null, null]);
  assert.ok(j.members.every((m) => !("alg" in m)));
  j = await (await route.GET(new Request("https://phm.dev/x?algs=all"), ctx)).json();
  assert.deepEqual(j.members.map((m) => m.alg), ["x25519", "xwing-chacha20poly1305", null]);
  assert.equal(j.members[1].public_key, b64(1216));
});
