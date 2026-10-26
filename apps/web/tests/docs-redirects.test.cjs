const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(webRoot, "..", "..");
const routes = JSON.parse(
  fs.readFileSync(path.join(webRoot, "docs-routes.json"), "utf8"),
);
const renderedDocs = JSON.parse(
  fs.readFileSync(path.join(webRoot, "docs-catalog.json"), "utf8"),
);

test("legacy docs redirects are closed, unique, and do not shadow rendered guides", () => {
  assert.ok(routes.length >= 8, "expected the remaining source-only guide set");

  const sources = new Set();
  for (const route of routes) {
    assert.deepEqual(Object.keys(route).sort(), ["file", "source"]);
    assert.match(route.source, /^\/docs(?:\/[a-z0-9-]+)?$/);
    assert.match(route.file, /^[a-z0-9-]+\.md$/);
    assert.equal(sources.has(route.source), false, `duplicate ${route.source}`);
    sources.add(route.source);

    const guidePath = path.join(repoRoot, "docs", route.file);
    assert.equal(
      fs.existsSync(guidePath),
      true,
      `${route.source} points to missing docs/${route.file}`,
    );
  }

  for (const required of [
    "/docs/release-readiness",
    "/docs/audit-index",
    "/docs/ci-cd",
  ]) {
    assert.equal(sources.has(required), true, `missing ${required}`);
  }

  for (const doc of renderedDocs) {
    assert.equal(
      sources.has(`/docs/${doc.slug}`),
      false,
      `/docs/${doc.slug} must resolve to the first-party renderer`,
    );
  }
  assert.equal(sources.has("/docs"), false, "the on-site docs hub must not redirect");
});

test("Next config derives temporary redirects from the reviewed manifest", () => {
  const config = fs.readFileSync(path.join(webRoot, "next.config.ts"), "utf8");
  assert.match(config, /import docsRoutes from "\.\/docs-routes\.json";/);
  assert.match(config, /docsRoutes\.map\(\(\{ source, file \}\)/);
  assert.match(
    config,
    /https:\/\/github\.com\/ashlrai\/phantom-secrets\/blob\/main\/docs\/\$\{file\}/,
  );
  assert.match(config, /permanent: false/);
  assert.doesNotMatch(config, /source: "\/install\.(?:sh|ps1)"/);
  assert.doesNotMatch(config, /destination:\s*["']https?:\/\/(?!github\.com\/ashlrai\/phantom-secrets\/blob\/main\/docs\/)/);
});
