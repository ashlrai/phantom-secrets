const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webRoot = path.resolve(__dirname, "..");
const read = (relativePath) =>
  fs.readFileSync(path.join(webRoot, relativePath), "utf8");

test("landing restores credential proof without claiming universal proxy support", () => {
  const hero = read("src/components/landing/Hero.tsx");
  const page = read("src/app/page.tsx");

  assert.match(page, /<Transformation \/>/);
  assert.match(page, /<Comparison \/>/);
  assert.match(hero, /<CredentialWall \/>/);
  assert.match(hero, /not endorsement or universal[\s\S]*proxy support/i);
  assert.match(hero, /unsupported[\s\S]*fail closed/i);
  assert.doesNotMatch(hero, /every service is supported/i);
});

test("platform chooser links every reviewed release target with bounded evidence", () => {
  const quickStart = read("src/components/landing/QuickStart.tsx");

  for (const target of [
    "phantom-aarch64-apple-darwin.tar.gz",
    "phantom-x86_64-apple-darwin.tar.gz",
    "phantom-aarch64-unknown-linux-gnu.tar.gz",
    "phantom-x86_64-unknown-linux-gnu.tar.gz",
    "phantom-aarch64-pc-windows-msvc.zip",
    "phantom-x86_64-pc-windows-msvc.zip",
  ]) {
    assert.match(quickStart, new RegExp(target.replaceAll(".", "\\.")));
  }
  assert.match(quickStart, /Credential Manager/);
  assert.match(quickStart, /session-persistent, not reboot-persistent/);
  assert.match(quickStart, /not every local shell, policy, or credential-store state/);
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
    /\/docs#connect-an-agent/,
  );
  assert.match(layout, /"@type": "SoftwareSourceCode"/);
  assert.match(layout, /codeRepository: "https:\/\/github\.com\/ashlrai\/phantom-secrets"/);
  assert.doesNotMatch(layout, /"@type": "FAQPage"|"@type": "HowTo"/);
  assert.match(read("src/components/landing/LandingStructuredData.tsx"), /QUESTIONS\.map/);
  assert.match(sitemap, /path: "\/docs"/);
});

test("landing documentation cards use the first-party rendered guides", () => {
  const gateway = read("src/components/landing/DocumentationGateway.tsx");

  assert.match(gateway, /href: "\/docs\/getting-started"/);
  assert.match(gateway, /href: "\/docs\/enterprise-adoption"/);
  assert.doesNotMatch(
    gateway,
    /github\.com\/ashlrai\/phantom-secrets\/blob\/main\/docs\/(?:getting-started|enterprise-adoption)\.md/,
  );
});

test("dotenv transformation uses only explicit synthetic examples", () => {
  const transformation = read("src/components/landing/Transformation.tsx");

  assert.match(transformation, /examples are[\s\S]*synthetic/i);
  assert.match(transformation, /example-redacted-openai-value/);
  assert.match(transformation, /GITHUB_TOKEN/);
  assert.doesNotMatch(transformation, /DATABASE_URL|MONGODB_URI/);
  assert.doesNotMatch(transformation, /sk-(?:live|proj|ant)-/i);
});
