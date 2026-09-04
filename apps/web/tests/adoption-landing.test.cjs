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
  const ecosystem = read("src/components/landing/Ecosystem.tsx");

  assert.match(page, /<Transformation \/>/);
  assert.match(page, /<Comparison \/>/);
  assert.match(page, /<Ecosystem \/>/);
  assert.match(hero, /<CredentialWall \/>/);
  assert.match(hero, /not automatic setup[\s\S]*endorsement[\s\S]*explicit configuration/i);
  assert.match(hero, /unsupported[\s\S]*fail closed/i);
  assert.match(ecosystem, /Selected editor and deployment credentials/);
  assert.match(ecosystem, /Additional vault-detection examples/);
  assert.match(ecosystem, /Logos identify products, not endorsement/);
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
  assert.match(quickStart, /Keyutils initially/);
  assert.match(quickStart, /encrypted-file[\s\S]*before <code>phantom init<\/code>/);
  assert.match(quickStart, /not every local shell, policy, or credential-store state/);
  assert.match(quickStart, /id="install"/);
  assert.match(quickStart, /Windows archives are not Authenticode-signed/);
  assert.match(quickStart, /FaApple/);
  assert.match(quickStart, /FaWindows/);
  assert.match(quickStart, /FaLinux/);
  assert.match(quickStart, /\.sha256/);
  assert.match(quickStart, /PUBLIC_RELEASE_SOURCE_COMMIT/);
  assert.match(quickStart, /PUBLIC_RELEASE_UNIX_INSTALLER_SHA256/);
  assert.match(quickStart, /PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256/);
  assert.match(quickStart, /mktemp -d/);
  assert.match(quickStart, /set -euo pipefail/);
  assert.match(quickStart, /ErrorActionPreference = 'Stop'/);
  assert.match(quickStart, /Guid\]::NewGuid/);
  assert.match(quickStart, /View exact installer source/);
  assert.doesNotMatch(quickStart, /curl[^\n]+phm\.dev\/install|irm[^\n]+phm\.dev\/install/i);
});

test("activation orders installation before client connection and previews config writes", () => {
  const page = read("src/app/page.tsx");
  const connection = read("src/components/landing/Install.tsx");

  assert.ok(page.indexOf("<QuickStart />") < page.indexOf("<Install />"));
  assert.ok(page.indexOf("<Transformation />") < page.indexOf("<QuickStart />"));
  assert.ok(page.indexOf("<Install />") < page.indexOf("<TrustBoundary />"));
  assert.match(connection, /id="connect"/);
  for (const client of ["claude", "cursor", "windsurf", "codex"]) {
    assert.match(connection, new RegExp(`phantom setup --client ${client} --print`));
  }
  assert.match(connection, /phantom agent doctor/);
  assert.match(connection, /phantom exec -- claude/);
  assert.match(connection, /phantom exec -- cursor \./);
  assert.match(connection, /phantom exec -- windsurf \./);
  assert.match(connection, /phantom exec -- codex/);
  assert.match(connection, /role="tablist"/);
  assert.match(connection, /role="tab"/);
  assert.match(connection, /role="tabpanel"/);
  assert.match(connection, /ClaudeClientLogo/);
  assert.match(connection, /CursorClientLogo/);
  assert.match(connection, /WindsurfClientLogo/);
  assert.match(connection, /CodexClientLogo/);
  assert.doesNotMatch(read("src/components/landing/QuickStart.tsx"), /phantom exec -- claude/);
});

test("logo rails expose the full catalog with motion controls and hidden duplicates", () => {
  const logos = read("src/components/landing/BrandLogos.tsx");
  const ecosystem = read("src/components/landing/Ecosystem.tsx");
  const hero = read("src/components/landing/Hero.tsx");
  const controls = read("src/components/landing/CarouselPauseButton.tsx");
  const styles = read("src/app/globals.css");

  assert.ok((logos.match(/name:\s*"/g) ?? []).length >= 37);
  assert.match(logos, /name: "Cohere"[\s\S]*COHERE_API_KEY/);
  assert.match(logos, /name: "Hugging Face"[\s\S]*HUGGINGFACE_API_KEY/);
  assert.match(logos, /CLOUDFLARE_API_TOKEN/);
  assert.match(logos, /SUPABASE_SERVICE_ROLE_KEY/);
  assert.match(ecosystem, /aria-hidden=\{index >= items\.length/);
  assert.match(hero, /aria-hidden=\{index >= items\.length/);
  assert.match(ecosystem, /CarouselPauseButton/);
  assert.match(hero, /CarouselPauseButton/);
  assert.match(controls, /aria-pressed=\{paused\}/);
  assert.match(styles, /prefers-reduced-motion[\s\S]*ecosystem-track[\s\S]*animation: none/);
  assert.match(styles, /ecosystem-track > article\[aria-hidden="true"\]/);
  assert.doesNotMatch(styles, /ecosystem-marquee \[aria-hidden="true"\]/);
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
