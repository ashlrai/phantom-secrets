const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webRoot = path.resolve(__dirname, "..");

function load(relativePath) {
  const source = fs.readFileSync(path.join(webRoot, relativePath), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true, target: ts.ScriptTarget.ES2022 },
    fileName: relativePath,
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, require);
  return { exports, source };
}

test("pageview capture uses NEXT_PUBLIC_POSTHOG_KEY, records host, and honors Do Not Track", () => {
  const posthog = load("src/lib/posthog.ts");
  const providers = fs.readFileSync(path.join(webRoot, "src/app/providers.tsx"), "utf8");

  assert.match(posthog.source, /NEXT_PUBLIC_POSTHOG_KEY/);
  assert.match(posthog.source, /\$host/);
  assert.match(posthog.source, /doNotTrack/);
  assert.match(posthog.source, /688217/);
  assert.doesNotMatch(posthog.source, /phc_[A-Za-z0-9]/);
  assert.match(posthog.source, /capture_pageview:\s*false/);
  assert.match(providers, /\$pageview/);
  assert.match(providers, /\$current_url:\s*`\$\{window\.location\.origin\}\$\{pathname\}`/);
  assert.match(providers, /\$host:\s*window\.location\.host/);

  const { trackingAllowed } = posthog.exports;
  assert.equal(trackingAllowed(undefined, null), false);
  assert.equal(trackingAllowed("", null), false);
  assert.equal(trackingAllowed("project-key", "1"), false);
  assert.equal(trackingAllowed("project-key", "yes"), false);
  assert.equal(trackingAllowed("project-key", "0"), true);
  assert.equal(trackingAllowed("project-key", null), true);
});
