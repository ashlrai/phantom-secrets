const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webRoot = path.resolve(__dirname, "..");
const read = (relativePath) =>
  fs.readFileSync(path.join(webRoot, relativePath), "utf8");

test("landing restores credential proof without claiming universal proxy support", () => {
  const hero = read("src/components/landing/Hero.tsx");
  const page = read("src/app/secrets/page.tsx");
  const ecosystem = read("src/components/landing/Ecosystem.tsx");

  assert.match(page, /<Transformation \/>/);
  assert.match(page, /<Comparison \/>/);
  assert.match(page, /<Ecosystem \/>/);
  assert.match(hero, /<CredentialWall \/>/);
  assert.match(hero, /not automatic setup[\s\S]*endorsement[\s\S]*explicit configuration/i);
  assert.match(hero, /unsupported[\s\S]*fail closed/i);
  assert.match(ecosystem, /Selected editor, source-control, and deployment credentials/);
  assert.match(ecosystem, /GitHub/);
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
  const page = read("src/app/secrets/page.tsx");
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

test("GitHub is a neutral, named link across the primary adoption surfaces", () => {
  for (const relativePath of [
    "src/components/landing/Hero.tsx",
    "src/components/landing/Nav.tsx",
    "src/app/docs/page.tsx",
  ]) {
    const source = read(relativePath);
    assert.match(source, /View (?:the source )?on GitHub/i, relativePath);
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
  assert.match(read("src/components/landing/LandingStructuredData.tsx"), /"@type": "SoftwareSourceCode"/);
  assert.match(read("src/components/landing/LandingStructuredData.tsx"), /codeRepository: "https:\/\/github\.com\/ashlrai\/phantom-secrets"/);
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
  assert.match(transformation, /CodexClientLogo/);
  assert.match(transformation, /phantom setup --client codex/);
  assert.match(transformation, /phantom exec -- codex/);
  assert.match(transformation, /GitHub can receive a diff/);
  assert.match(transformation, /Unsupported routes fail closed/);
  assert.doesNotMatch(transformation, /DATABASE_URL|MONGODB_URI/);
  assert.doesNotMatch(transformation, /sk-(?:live|proj|ant)-/i);
});

test("site links to GitHub neutrally and never asks visitors to star or upvote", () => {
  const sourceFiles = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(path.join(webRoot, dir), { withFileTypes: true })) {
      const relative = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(relative);
      else if (/\.(?:tsx?|mdx?)$/.test(entry.name)) sourceFiles.push(relative);
    }
  };
  walk("src");
  assert.ok(sourceFiles.length > 20, "expected to scan the site source tree");

  for (const file of sourceFiles) {
    const source = read(file);
    assert.doesNotMatch(
      source,
      /\b(?:give\s+(?:us\s+)?a\s+)?star(?:\s+or\s+fork)?\s+(?:Phantom|us|the\s+(?:repo|repository|source|project)|on\s+GitHub)\b|\band\s+star\s+Phantom\b|\bupvote\b/i,
      file,
    );
  }

  for (const file of [
    "src/components/landing/Hero.tsx",
    "src/components/landing/Nav.tsx",
    "src/components/landing/SocialProof.tsx",
  ]) {
    assert.match(read(file), /href="https:\/\/github\.com\/ashlrai\/phantom-secrets"/, file);
    assert.match(read(file), /View (?:the source )?on GitHub/, file);
  }
});

// The replay has a real lifecycle: client navigation must leave no listener,
// observer or playback timer behind, and returning home must re-enable it.
function replayFixture() {
  const vm = require("node:vm");
  const timers = new Map();
  const observers = [];
  let sequence = 0;
  class Element {
    constructor(dataset = {}) { this.dataset = dataset; this.disabled = false; this.attributes = new Map(); this.textContent = ""; }
    closest() { return this; }
    setAttribute(name, value) { this.attributes.set(name, value); }
    removeAttribute(name) { this.attributes.delete(name); }
  }
  function events(target) {
    target.listeners = new Map();
    target.addEventListener = (name, callback, options) => {
      const set = target.listeners.get(name) ?? new Set();
      set.add(callback); target.listeners.set(name, set);
      options?.signal?.addEventListener("abort", () => set.delete(callback), { once: true });
    };
    target.fire = (name, event = {}) => target.listeners.get(name)?.forEach(callback => callback(event));
    return target;
  }
  const root = events(new Element());
  const groups = {
    "[data-resource]": ["subscription", "api", "local", "tools"].map(resource => new Element({ resource })),
    "[data-provider-kind]": ["subscription api", "api", "local", "tools"].map(providerKind => new Element({ providerKind })),
    "[data-mode]": ["with", "for"].map(mode => new Element({ mode })),
    "[data-agent]": ["scout", "builder", "reviewer"].map(agent => new Element({ agent })),
    "[data-step]": [0, 1, 2, 3, 4].map(step => new Element({ step: String(step) })),
  };
  const leaves = new Map();
  for (const action of ["play", "next", "restart"]) leaves.set(`[data-action="${action}"]`, new Element({ action }));
  root.querySelector = selector => {
    if (!leaves.has(selector)) leaves.set(selector, new Element());
    return leaves.get(selector);
  };
  const buttons = [...groups["[data-resource]"], ...groups["[data-mode]"], ...groups["[data-agent]"], ...groups["[data-step]"], ...leaves.values()];
  root.querySelectorAll = selector => selector === "button" ? buttons : groups[selector] ?? [];
  root.contains = element => buttons.includes(element);
  const classes = new Set(); root.classList = { add: value => classes.add(value), remove: value => classes.delete(value) };
  const document = events({ hidden: false });
  const window = {
    Element, AbortController,
    setTimeout(callback) { const id = ++sequence; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
    IntersectionObserver: class {
      constructor(callback) { this.callback = callback; this.disconnected = false; observers.push(this); }
      observe() {}
      disconnect() { this.disconnected = true; }
    },
  };
  const context = { window, document };
  vm.runInNewContext(read("src/components/landing/phantom-world.js").replace("export function", "function") + "\nglobalThis.initialize = initializePhantomWorld;", context);
  const click = button => root.fire("click", { target: button });
  const advance = () => { const [id, callback] = timers.entries().next().value; timers.delete(id); callback(); };
  return { root, timers, observers, document, initialize: context.initialize, click, advance, play: leaves.get('[data-action="play"]') };
}

test("illustrative replay cleans up and reinitializes after client navigation", () => {
  const fixture = replayFixture();
  const cleanup = fixture.initialize(fixture.root);
  fixture.click(fixture.play);
  assert.equal(fixture.timers.size, 1);
  cleanup();
  assert.equal(fixture.timers.size, 0);
  assert.equal(fixture.root.listeners.get("click").size, 0);
  assert.equal(fixture.document.listeners.get("visibilitychange").size, 0);
  assert.equal(fixture.observers[0].disconnected, true);
  assert.equal(fixture.root.dataset.initialized, "false");
  const nextCleanup = fixture.initialize(fixture.root);
  assert.equal(fixture.play.disabled, false);
  assert.equal(fixture.root.listeners.get("click").size, 1);
  fixture.click(fixture.play);
  assert.equal(fixture.timers.size, 1);
  nextCleanup();
  assert.equal(fixture.timers.size, 0);
  assert.equal(fixture.observers[1].disconnected, true);
});

test("illustrative replay is finite and pauses offscreen or in a background tab", () => {
  const fixture = replayFixture();
  const cleanup = fixture.initialize(fixture.root);
  fixture.click(fixture.play);
  for (let step = 0; step < 4; step += 1) fixture.advance();
  assert.equal(fixture.root.dataset.stage, "4");
  assert.equal(fixture.root.dataset.playing, "false");
  assert.equal(fixture.timers.size, 0);
  fixture.click(fixture.play);
  fixture.observers[0].callback([{ isIntersecting: false }]);
  assert.equal(fixture.timers.size, 0);
  fixture.observers[0].callback([{ isIntersecting: true }]);
  fixture.click(fixture.play);
  fixture.document.hidden = true;
  fixture.document.fire("visibilitychange");
  assert.equal(fixture.root.dataset.playing, "false");
  assert.equal(fixture.timers.size, 0);
  cleanup();
});
