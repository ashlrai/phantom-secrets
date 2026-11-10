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
const markdownBasename = /^[a-z0-9-]+\.md(?![\s\S])/;

test("redirect filenames are relative Markdown basenames", () => {
  for (const { source, file } of routes) {
    assert.match(file, markdownBasename, `${source} has an invalid filename`);
    assert.equal(path.posix.basename(file), file, `${source} contains a POSIX path`);
    assert.equal(path.win32.basename(file), file, `${source} contains a Windows path`);
  }

  for (const invalid of [
    "../guide.md",
    "docs/guide.md",
    "docs\\guide.md",
    "/guide.md",
    "C:\\guide.md",
    "guide.md/",
    ".md",
    "guide.txt",
    "guide.md\n",
  ]) {
    assert.doesNotMatch(invalid, markdownBasename, `${invalid} must be rejected`);
  }
});

function findShadowedGuides(redirectSources, docs) {
  const normalizedSources = new Set(redirectSources.map((source) => source.toLowerCase()));
  return docs
    .map(({ slug }) => `/docs/${slug}`)
    .filter((route) => normalizedSources.has(route.toLowerCase()));
}

function assertUniqueSourcesIgnoringCase(entries) {
  const sources = new Map();
  for (const { source } of entries) {
    const normalized = source.toLowerCase();
    assert.equal(
      sources.has(normalized),
      false,
      `duplicate redirect sources ignoring case: ${sources.get(normalized)} and ${source}`,
    );
    sources.set(normalized, source);
  }
}

test("redirect sources are unique ignoring case", () => {
  assertUniqueSourcesIgnoringCase(routes);
  assert.throws(
    () => assertUniqueSourcesIgnoringCase([
      { source: "/docs/guide" },
      { source: "/DOCS/Guide" },
    ]),
    /duplicate redirect sources ignoring case/,
  );
});

test("legacy docs redirects are closed, unique, and do not shadow rendered guides", () => {
  assert.ok(routes.length >= 8, "expected the remaining source-only guide set");

  const sources = new Set();
  for (const route of routes) {
    assert.deepEqual(Object.keys(route).sort(), ["file", "source"]);
    assert.ok(route.source.startsWith("/docs/"), `${route.source} must start with /docs/`);
    assert.ok(!route.source.endsWith("/"), `${route.source} must not end with a slash`);
    assert.match(route.source, /^\/docs(?:\/[a-z0-9-]+)?$/);
    assert.match(route.file, markdownBasename);
    assert.equal(sources.has(route.source), false, `duplicate ${route.source}`);
    sources.add(route.source);

    const guidePath = path.join(repoRoot, "docs", route.file);
    assert.equal(
      fs.existsSync(guidePath),
      true,
      `${route.source} points to missing docs/${route.file}`,
    );
    assert.equal(
      fs.statSync(guidePath).isFile(),
      true,
      `${route.source} points to a non-file docs/${route.file}`,
    );
  }

  for (const required of [
    "/docs/release-readiness",
    "/docs/audit-index",
    "/docs/ci-cd",
  ]) {
    assert.equal(sources.has(required), true, `missing ${required}`);
  }

  assert.deepEqual(
    findShadowedGuides([...sources], renderedDocs),
    [],
    "rendered guides must resolve to the first-party renderer regardless of case",
  );
  assert.equal(sources.has("/docs"), false, "the on-site docs hub must not redirect");
});

test("guide shadow detection compares both routes case-insensitively", () => {
  assert.deepEqual(
    findShadowedGuides(["/DOCS/Getting-Started"], [
      { slug: "getting-started" },
      { slug: "GETTING-STARTED" },
      { slug: "other-guide" },
    ]),
    ["/docs/getting-started", "/docs/GETTING-STARTED"],
  );
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
