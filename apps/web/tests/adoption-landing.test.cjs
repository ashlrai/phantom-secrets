const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webRoot = path.resolve(__dirname, "..");
const read = (relativePath) =>
  fs.readFileSync(path.join(webRoot, relativePath), "utf8");

test("landing primary navigation has an accessible label", () => {
  const React = require("react");
  const ts = require("typescript");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const { getByRole } = require("@testing-library/dom");
  const compiled = ts.transpileModule(read("src/components/landing/Nav.tsx"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: "Nav.tsx",
  }).outputText;

  for (const pathname of ["/", "/secrets"]) {
    for (const menuOpen of [false, true]) {
      let stateIndex = 0;
      const hooks = { ...React, useState: initial => [stateIndex++ === 1 ? menuOpen : initial, () => {}] };
      const localRequire = name => {
        if (name === "react") return hooks;
        if (name === "next/navigation") return { usePathname: () => pathname };
        if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
        if (name === "next/image") return { __esModule: true, default: ({ priority, ...props }) => React.createElement("img", props) };
        if (name === "@/lib/posthog") return { capturePostHog: async () => {} };
        if (name === "@/lib/legacy-secrets-fragment") return { legacySecretsDestination: () => null };
        if (name === "./Icons") return { Github: () => React.createElement("svg", { "aria-hidden": true }) };
        return require(name);
      };
      const exports = {};
      new Function("exports", "require", compiled)(exports, localRequire);
      const dom = new JSDOM(renderToStaticMarkup(React.createElement(exports.Nav)));
      const document = dom.window.document;
      assert.equal(
        getByRole(document.body, "navigation", { name: "Primary navigation" }),
        document.querySelector("nav"),
        `${pathname}: navigation must remain named when the menu is ${menuOpen ? "open" : "closed"}`,
      );
      dom.window.close();
    }
  }
});

test("landing controls explicitly use non-submit button types", () => {
  const ts = require("typescript");
  const { JSDOM } = require("jsdom");
  const directory = "src/components/landing";
  const controls = new Set();

  for (const file of fs.readdirSync(path.join(webRoot, directory)).filter(name => name.endsWith(".tsx"))) {
    const relativePath = `${directory}/${file}`;
    const source = ts.createSourceFile(relativePath, read(relativePath), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    function visit(node) {
      if ((ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) && node.tagName.getText(source) === "button") {
        controls.add(file);
        const attributes = node.attributes.properties;
        const typeIndex = attributes.findIndex(attribute => ts.isJsxAttribute(attribute) && attribute.name.getText(source) === "type");
        const location = `${relativePath}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`;
        assert.ok(typeIndex >= 0, `${location}: missing explicit button type`);
        const type = attributes[typeIndex];
        assert.ok(type.initializer && ts.isStringLiteral(type.initializer), `${location}: type must be a literal`);
        assert.equal(type.initializer.text, "button", location);
        assert.ok(!attributes.slice(typeIndex + 1).some(ts.isJsxSpreadAttribute), `${location}: a later spread could override type`);
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
  }
  for (const file of ["Nav.tsx", "QuickStart.tsx", "Install.tsx", "CopyButton.tsx", "CarouselPauseButton.tsx"]) {
    assert.ok(controls.has(file), `expected landing control in ${file}`);
  }

  const markup = JSON.parse(read(`${directory}/phantom-world-markup.json`));
  const document = new JSDOM(markup).window.document;
  for (const selector of ["[data-mode]", "[data-resource]", "[data-agent]", "[data-step]", "[data-action]"]) {
    assert.ok(document.querySelector(`button${selector}`), `missing demo controls: ${selector}`);
  }
  for (const button of document.querySelectorAll("button")) {
    assert.equal(button.getAttribute("type"), "button", `demo control: ${button.outerHTML}`);
  }
});

test("landing calls to action have accessible names and destinations", async () => {
  const ts = require("typescript");
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const { computeAccessibleName, isInaccessible } = require("dom-accessibility-api");
  const { pathToFileURL } = require("node:url");
  const { parseWorkbenchRelease } = await import(pathToFileURL(path.join(webRoot, "src/lib/workbench-release-contract.mjs")).href);
  const release = parseWorkbenchRelease(require("../src/lib/workbench-release.json"));

  function renderComponent(file, exportName, workbenchRelease = null) {
    const output = ts.transpileModule(read(`src/components/landing/${file}.tsx`), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    }).outputText;
    const exports = {};
    const localRequire = name => {
      if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
      if (name === "next/image") return { __esModule: true, default: () => null };
      if (name === "@/lib/workbench-release") return { WORKBENCH_RELEASE: workbenchRelease };
      if (name === "./BrandLogos") return { EXACT_ROUTE_ENTRIES: [] };
      if (name === "./CarouselPauseButton") return { CarouselPauseButton: () => null };
      if (name === "./SocialProof") return { SocialProof: () => null };
      if (name === "./Icons") return { Github: props => React.createElement("svg", props) };
      return require(name);
    };
    new Function("exports", "require", output)(exports, localRequire);
    return new JSDOM(renderToStaticMarkup(React.createElement(exports[exportName]))).window.document;
  }

  function assertActions(document, selector, expected) {
    const group = document.querySelector(selector);
    assert.ok(group, `missing action group: ${selector}`);
    const links = [...group.querySelectorAll("a")];
    assert.equal(links.length, expected.length, selector);
    for (const [index, [name, destination]] of expected.entries()) {
      const link = links[index];
      assert.equal(isInaccessible(link), false, `${selector}: action ${index + 1} must be accessible`);
      assert.equal(computeAccessibleName(link).trim(), name, `${selector}: action ${index + 1} name`);
      assert.equal(link.getAttribute("href")?.trim(), destination, `${selector}: ${name} destination`);
    }
  }

  const workbenchActions = [
    ["Choose an agent to connect", "#connect-agent"],
    ["Install and set up Phantom", "/docs/workbench-setup"],
    ["Read the documentation", "/docs/workbench"],
    ["Protect credentials with Phantom Secrets", "/secrets"],
  ];
  // Exercise both the unpublished state and the optional download action.
  for (const current of [null, release, { macDownloadUrl: "https://example.com/phantom.dmg" }]) {
    const expected = [...workbenchActions];
    if (current?.macDownloadUrl) expected.push(["Download for Mac", current.macDownloadUrl]);
    assertActions(renderComponent("WorkbenchHero", "WorkbenchHero", current), ".phantom-workbench__actions", expected);
  }
  assertActions(renderComponent("Hero", "Hero"), "#phantom-secrets .mt-8", [
    ["Install Phantom Secrets", "#install"],
    ["View Phantom Secrets source on GitHub", "https://github.com/ashlrai/phantom-secrets"],
  ]);
  assertActions(renderComponent("CTA", "CTA"), ".closing-section__actions", [
    ["Follow the install path", "#install"],
    ["View on GitHub", "https://github.com/ashlrai/phantom-secrets"],
  ]);
});

test("Secrets landing install links reach its quick-start section", () => {
  const ts = require("typescript");
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const { computeAccessibleName, isInaccessible } = require("dom-accessibility-api");

  function load(relativePath, localRequire) {
    const output = ts.transpileModule(read(relativePath), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    }).outputText;
    const exports = {};
    new Function("exports", "require", output)(exports, localRequire);
    return exports;
  }

  const release = load("src/lib/public-release.ts", require);
  const components = {};
  function localRequire(name) {
    if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
    if (name === "@/lib/public-release") return release;
    if (name === "./BrandLogos") return { EXACT_ROUTE_ENTRIES: [] };
    if (name === "./Icons") return { Github: props => React.createElement("svg", props) };
    if (["./CarouselPauseButton", "./SocialProof", "./CopyButton"].includes(name)) {
      return { [name.slice(2)]: () => null };
    }
    if (name.startsWith("@/components/landing/")) {
      const component = name.split("/").pop();
      return { [component]: components[component] || (() => null) };
    }
    return require(name);
  }
  for (const name of ["Hero", "QuickStart", "CTA"]) {
    components[name] = load(`src/components/landing/${name}.tsx`, localRequire)[name];
  }
  const { default: SecretsPage } = load("src/app/secrets/page.tsx", localRequire);
  const document = new JSDOM(renderToStaticMarkup(React.createElement(SecretsPage)), {
    url: "https://example.com/secrets",
  }).window.document;
  const sections = document.querySelectorAll('[id="install"]');
  assert.equal(sections.length, 1, "the quick-start destination must be unique");
  assert.equal(sections[0].tagName, "SECTION");
  assert.equal(isInaccessible(sections[0]), false);
  assert.match(computeAccessibleName(sections[0]), /Install on your OS/);

  for (const [selector, name] of [["#phantom-secrets", "Install Phantom Secrets"], [".closing-section", "Follow the install path"]]) {
    const link = [...document.querySelectorAll(`${selector} a`)]
      .find(element => computeAccessibleName(element).trim() === name);
    assert.ok(link, `missing ${name} link`);
    assert.equal(isInaccessible(link), false, `${name} must be accessible`);
    const destination = new URL(link.href);
    assert.equal(destination.pathname, "/secrets", `${name} must remain on the Secrets landing`);
    assert.equal(destination.hash, "#install", `${name} must point to quick start`);
    assert.equal(document.getElementById(destination.hash.slice(1)), sections[0]);
  }
});

// These images repeat adjacent text or an already named link/button. Keep the
// exceptions scoped to their source and count so new images need a review.
const decorativeImages = {
  "src/components/landing/Nav.tsx": { "/favicon.svg": 1 },
  "src/components/landing/SiteFooter.tsx": { "/favicon.svg": 1 },
  "src/components/landing/WorkbenchHero.tsx": { "/favicon.svg": 1 },
  "src/components/landing/phantom-world-markup.json": {
    "/phantom-world/provider-claude.svg": 1,
    "/phantom-world/provider-codex.svg": 1,
    "/phantom-world/provider-grok.svg": 1,
    "/phantom-world/devin-mark.svg": 1,
    "/phantom-world/provider-local.svg": 1,
    "/phantom-world/provider-vercel.svg": 1,
    "/phantom-world/provider-supabase.svg": 1,
    "/phantom-world/phantom-mark.svg": 4,
  },
};

function checkImageAlternatives(images, exceptions, location) {
  const remaining = { ...exceptions };
  for (const { src, alt } of images) {
    assert.equal(typeof alt, "string", `${location}: image ${src} needs a static alt attribute`);
    if (alt === "") {
      assert.ok(remaining[src] > 0, `${location}: review decorative image ${src}`);
      remaining[src] -= 1;
    } else {
      assert.ok(alt.trim(), `${location}: image ${src} needs nonempty alternative text`);
    }
  }
  for (const [src, count] of Object.entries(remaining)) {
    assert.equal(count, 0, `${location}: stale decorative image exception for ${src}`);
  }
}

test("landing images provide alternatives or are reviewed as decorative", () => {
  const ts = require("typescript");
  const { JSDOM } = require("jsdom");
  const landingDir = "src/components/landing";
  const files = fs.readdirSync(path.join(webRoot, landingDir))
    .filter(name => name.endsWith(".tsx"))
    .map(name => `${landingDir}/${name}`);
  files.push("src/app/page.tsx", "src/app/secrets/page.tsx");

  for (const file of files) {
    const source = ts.createSourceFile(file, read(file), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const images = [];
    function visit(node) {
      if ((ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) &&
          ["img", "Image"].includes(node.tagName.getText(source))) {
        const attributes = node.attributes.properties;
        assert.ok(attributes.every(ts.isJsxAttribute), `${file}: image attributes must be explicit`);
        const literal = name => {
          const attribute = attributes.find(item => item.name.getText(source) === name);
          return attribute && attribute.initializer && ts.isStringLiteral(attribute.initializer)
            ? attribute.initializer.text : undefined;
        };
        images.push({ src: literal("src"), alt: literal("alt") });
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
    checkImageAlternatives(images, decorativeImages[file], file);
  }

  const markupFile = `${landingDir}/phantom-world-markup.json`;
  const document = new JSDOM(JSON.parse(read(markupFile))).window.document;
  const images = [...document.querySelectorAll("img")].map(image => ({
    src: image.getAttribute("src"), alt: image.getAttribute("alt"),
  }));
  checkImageAlternatives(images, decorativeImages[markupFile], markupFile);
});

test("image alternative check rejects missing, blank and unreviewed decorative text", () => {
  for (const alt of [undefined, null, " ", "\n", ""]) {
    assert.throws(() => checkImageAlternatives([{ src: "example.png", alt }], {}, "fixture"));
  }
  assert.doesNotThrow(() => checkImageAlternatives([{ src: "example.png", alt: "A useful description" }], {}, "fixture"));
  assert.doesNotThrow(() => checkImageAlternatives([{ src: "icon.svg", alt: "" }], { "icon.svg": 1 }, "fixture"));
  assert.throws(() => checkImageAlternatives([{ src: "icon.svg", alt: "" }, { src: "icon.svg", alt: "" }], { "icon.svg": 1 }, "fixture"));
});

test("workbench introduction gives a local first step without implying fleet readiness", () => {
  const hero = read("src/components/landing/WorkbenchHero.tsx");

  assert.match(hero, /Start by installing Phantom on your machine, then connect and configure your tools/);
  assert.match(hero, /This page is an introduction; a fleet is ready only after local setup and permissions are in place/);
  assert.match(hero, /href="\/docs\/workbench-setup">\s*Install and set up Phantom/);
  assert.match(hero, /Illustrated engineering workflow, not live account status/);
});

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

test("install guidance explains the temporary installer location for each platform", () => {
  const quickStart = read("src/components/landing/QuickStart.tsx");
  const macos = quickStart.split('name: "macOS"')[1].split('name: "Windows"')[0];
  const linux = quickStart.split('name: "Linux"')[1].split("export function QuickStart")[0];

  for (const command of [macos, linux]) {
    assert.match(command, /phantom_stage=.*mktemp -d/);
    assert.match(command, /phantom_installer=.*phantom_stage\/install\.sh/);
    assert.match(command, /trap .*phantom_installer.*phantom_stage/);
  }
  assert.match(quickStart, /On macOS and Linux, a staging directory under <code>TMPDIR<\/code>\s+\(or <code>\/tmp<\/code> when unset or empty\) holds the downloaded installer\s+script/);
  assert.match(quickStart, /Once the exit trap is installed, cleanup attempts to remove the\s+script and then the empty directory on exit, including after failures;\s+cleanup is not guaranteed\. It is not the install directory/);
  assert.match(quickStart, /Windows uses a\s+temporary installer file instead/);
});

test("both Unix install snippets quote every staging directory reference", () => {
  const quickStart = read("src/components/landing/QuickStart.tsx");
  const snippets = [
    ["macOS", quickStart.split('name: "macOS"')[1]?.split('name: "Windows"')[0]],
    ["Linux", quickStart.split('name: "Linux"')[1]?.split("export function QuickStart")[0]],
  ];

  for (const [platform, snippet] of snippets) {
    assert.ok(snippet, `${platform}: install snippet exists`);
    assert.ok(snippet.includes('phantom_installer="$phantom_stage/install.sh"'), `${platform}: quote the installer path`);
    assert.ok(snippet.includes('rmdir -- "$phantom_stage"'), `${platform}: quote the cleanup path`);
    assert.equal((snippet.match(/\$phantom_stage\b/g) || []).length, 2, `${platform}: review all staging directory references`);
  }
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
  assert.match(docs, /Workbench \{WORKBENCH_RELEASE\?\.version/);
  assert.match(docs, /Phantom Secrets \{PUBLIC_RELEASE_TAG\}/);
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
    "src/components/landing/SocialProof.tsx",
  ]) {
    assert.match(read(file), /href="https:\/\/github\.com\/ashlrai\/phantom-secrets"/, file);
    assert.match(read(file), /View (?:the source )?on GitHub/, file);
  }
  // Nav chooses the product per route; landing-interactions tests its rendered
  // desktop and mobile links instead of requiring a hardcoded Secrets href.
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

test("guided agent choices render ordered next steps with native keyboard controls", () => {
  const ts = require("typescript");
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const output = ts.transpileModule(read("src/components/landing/WorkbenchIntegrations.tsx"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
  const exports = {};
  new Function("exports", "require", output)(exports, name =>
    name === "./BrandLogos" ? { KEY_ENTRIES: [] } :
      name === "next/link" ? { default: ({ children, ...props }) => React.createElement("a", props, children) } : require(name));
  const html = renderToStaticMarkup(React.createElement(exports.WorkbenchIntegrations));
  assert.match(html, /id="connect-agent"/);
  assert.match(read("src/components/landing/WorkbenchHero.tsx"), /href="#connect-agent">Choose an agent to connect/);
  const choices = [...html.matchAll(/<details\b[^>]*>([\s\S]*?)<\/details>/g)];
  assert.equal(choices.length, 4);
  for (const [index, agent] of ["Claude Code", "Codex", "Grok", "API or local model"].entries()) {
    const content = choices[index][1];
    assert.ok(content.startsWith("<summary"), "native disclosure is the first child and keyboard operable");
    assert.ok(content.includes(`${agent} — connection steps`));
    assert.ok(content.includes(`Continue with ${agent} setup`));
    const steps = [...content.matchAll(/<li>([\s\S]*?)<\/li>/g)].map(match => match[1]);
    assert.equal(steps.length, 4);
    assert.match(steps[0], index < 3 ? /sign in through its vendor CLI/ : /Configure an API engine or a local model runtime/);
    assert.match(steps[1], /phm verse/);
    assert.match(steps[2], /Resources[\s\S]*ready[\s\S]*fresh/);
    assert.match(steps[3], /Work with me[\s\S]*scratch repository[\s\S]*Review the diff and checks/);
    assert.match(content, /href="\/docs\/workbench-setup#connect-a-usable-resource"/);
  }
  assert.doesNotMatch(html, /tabindex="-1"|role="tab"|onkeydown|width:\d+px/i);
  assert.match(html, /overflow-wrap:anywhere/);
  assert.match(html, /display:grid;gap:1rem;min-width:0/);
  assert.match(read("src/app/globals.css"), /:focus-visible\s*\{[^}]*outline:/);
  assert.match(html, /does not activate unattended fleet work/);
});
