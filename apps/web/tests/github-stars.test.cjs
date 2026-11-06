const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webRoot = path.resolve(__dirname, "..");

function load(relativePath, localRequire = require) {
  const source = fs.readFileSync(path.join(webRoot, relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true, target: ts.ScriptTarget.ES2022 },
    fileName: relativePath,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, localRequire);
  return exports;
}

test("aggregate star count sums live repository totals and refuses a partial result", () => {
  const { aggregateStarCount } = load("src/lib/github-stars.ts");
  assert.equal(aggregateStarCount([4, 6]), 10);
  assert.equal(aggregateStarCount([0, 0]), 0);
  assert.equal(aggregateStarCount([4, null]), null);
  assert.equal(aggregateStarCount([1.5, 2]), null);
  assert.equal(aggregateStarCount([-1, 2]), null);
  assert.equal(aggregateStarCount([4]), null);
});

test("the stars route returns the live sum and no invented fallback", async () => {
  const helper = load("src/lib/github-stars.ts");
  const counts = { "ashlrai/phantom": 5, "ashlrai/phantom-secrets": 7 };
  const previousFetch = global.fetch;
  global.fetch = async (url) => {
    const repo = Object.keys(counts).find((name) => String(url).endsWith(`/repos/${name}`));
    if (!repo) return { ok: false, json: async () => ({}) };
    return { ok: true, json: async () => ({ stargazers_count: counts[repo] }) };
  };
  try {
    const route = load("src/app/api/github-stars/route.ts", (name) => (
      name === "@/lib/github-stars" ? helper : require(name)
    ));
    const ok = await route.GET();
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), {
      ok: true,
      stars: 12,
      repositories: ["ashlrai/phantom", "ashlrai/phantom-secrets"],
    });

    global.fetch = async () => ({ ok: false, json: async () => ({ stargazers_count: 99 }) });
    const failed = await route.GET();
    assert.equal(failed.status, 502);
    assert.deepEqual(await failed.json(), { ok: false });
  } finally {
    global.fetch = previousFetch;
  }
});
