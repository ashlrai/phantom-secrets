const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webRoot = path.resolve(__dirname, "..");
const read = (relativePath) =>
  fs.readFileSync(path.join(webRoot, relativePath), "utf8");

test("landing restores ecosystem proof without claiming universal proxy support", () => {
  const ecosystem = read("src/components/landing/Ecosystem.tsx");
  const page = read("src/app/page.tsx");

  assert.match(page, /<Ecosystem \/>/);
  assert.match(page, /<Transformation \/>/);
  assert.match(ecosystem, /do not imply[\s\S]*universal proxy support/i);
  assert.match(ecosystem, /exact-match proxy routes/i);
  assert.doesNotMatch(ecosystem, /every service is supported/i);
});

test("GitHub starring is a named action across the primary adoption surfaces", () => {
  for (const relativePath of [
    "src/components/landing/Hero.tsx",
    "src/components/landing/Nav.tsx",
    "src/app/docs/page.tsx",
  ]) {
    const source = read(relativePath);
    assert.match(source, /Star (?:Phantom )?(?:on|the source on) GitHub/i, relativePath);
    assert.match(source, /https:\/\/github\.com\/ashlrai\/phantom-secrets/, relativePath);
  }
});

test("on-site docs hub and machine-readable discovery are indexed", () => {
  const docs = read("src/app/docs/page.tsx");
  const layout = read("src/app/layout.tsx");
  const sitemap = read("src/app/sitemap.ts");

  assert.match(docs, /export const metadata/);
  assert.match(docs, /canonical: "\/docs"/);
  assert.match(docs, /\/llms\.txt/);
  assert.match(docs, /\/llms-full\.txt/);
  assert.doesNotMatch(docs, /cli-reference\.md/);
  assert.match(docs, /The reviewed public release is/);
  assert.match(
    read("src/components/landing/DocumentationGateway.tsx"),
    /#agent-and-editor-integrations/,
  );
  assert.match(layout, /"@type": "SoftwareSourceCode"/);
  assert.match(layout, /codeRepository: "https:\/\/github\.com\/ashlrai\/phantom-secrets"/);
  assert.match(sitemap, /path: "\/docs"/);
});

test("dotenv transformation uses only explicit synthetic examples", () => {
  const transformation = read("src/components/landing/Transformation.tsx");

  assert.match(transformation, /examples are[\s\S]*synthetic/i);
  assert.match(transformation, /example-redacted-openai-value/);
  assert.match(transformation, /GITHUB_TOKEN/);
  assert.doesNotMatch(transformation, /DATABASE_URL|MONGODB_URI/);
  assert.doesNotMatch(transformation, /sk-(?:live|proj|ant)-/i);
});
