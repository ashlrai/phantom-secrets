const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { pathToFileURL } = require("node:url");

const webDir = path.resolve(__dirname, "..");

function read(relativePath) {
  return fs.readFileSync(path.join(webDir, relativePath), "utf8");
}

const nav = read("src/components/landing/Nav.tsx");
const footer = read("src/components/landing/SiteFooter.tsx");
const landingStructuredData = read("src/components/landing/LandingStructuredData.tsx");
const layout = read("src/app/layout.tsx");
const sitemap = read("src/app/sitemap.ts");
const robots = read("src/app/robots.ts");
const manifest = JSON.parse(read("public/manifest.webmanifest"));
const seoWorkflow = fs.readFileSync(
  path.resolve(webDir, "../..", ".github/workflows/seo-observe.yml"),
  "utf8",
);
const publicPages = {
  "/": read("src/app/page.tsx"),
  "/secrets": read("src/app/secrets/page.tsx"),
  "/pricing": read("src/app/pricing/page.tsx"),
  "/enterprise": read("src/app/enterprise/page.tsx"),
  "/government": read("src/app/government/page.tsx"),
  "/security": read("src/app/security/page.tsx"),
};

test("primary navigation works from the home page and nested routes", () => {
  assert.match(nav, /usePathname/);
  assert.match(
    nav,
    /pathname === "\/secrets" \? `#\$\{section\}` : `\/secrets#\$\{section\}`/,
  );
  assert.match(nav, /href: "\/pricing"/);
  assert.match(nav, /href: "\/enterprise"/);
  assert.match(nav, /href: "\/security"/);
  assert.match(nav, /aria-current=\{active \? "page" : undefined\}/);
  assert.match(nav, /aria-label="Primary navigation"/);
});

test("rendered primary navigation links are named and reach local pages and fragments", () => {
  const React = require("react");
  const ts = require("typescript");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const { getByRole, queryAllByRole } = require("@testing-library/dom");
  const catalog = JSON.parse(read("docs-catalog.json"));
  const compiled = ts.transpileModule(nav, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: "Nav.tsx",
  }).outputText;

  for (const pathname of ["/", "/secrets", "/pricing", "/docs", "/docs/workbench-setup", "/docs/getting-started"]) {
    let stateIndex = 0;
    let menuOpen = false;
    const hooks = { ...React, useState: (initial) => [stateIndex++ === 1 ? menuOpen : initial, () => {}] };
    const localRequire = (name) => {
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
    const closed = new JSDOM(renderToStaticMarkup(React.createElement(exports.Nav)));
    assert.equal(
      getByRole(closed.window.document.body, "navigation", { name: /\S/ }),
      closed.window.document.querySelector('nav[aria-label="Primary navigation"]'),
      `${pathname}: closed menu has a named navigation landmark`,
    );
    closed.window.close();
    stateIndex = 0;
    menuOpen = true;
    const document = new JSDOM(renderToStaticMarkup(React.createElement(exports.Nav))).window.document;
    const primary = document.querySelector('nav[aria-label="Primary navigation"]');
    assert.ok(primary, pathname);
    assert.equal(
      getByRole(document.body, "navigation", { name: /\S/ }),
      primary,
      `${pathname}: open menu has a named navigation landmark`,
    );
    assert.equal(primary.querySelector("#mobile-navigation").hidden, false, pathname);
    const links = [...primary.querySelectorAll("a")];
    const namedLinks = queryAllByRole(primary, "link", { name: /\S/ });
    assert.ok(links.length >= 18, `${pathname}: desktop and mobile links are present`);
    for (const link of links) {
      const href = link.getAttribute("href");
      assert.ok(namedLinks.includes(link), `${pathname}: link ${href} needs an accessible name`);
      assert.ok(href, `${pathname}: link needs a destination`);
      assert.match(href, /\S/, `${pathname}: link destination must not be whitespace`);
      if (href.startsWith("https://github.com/")) continue;
      assert.ok((href.startsWith("/") && !href.startsWith("//")) || href.startsWith("#"), `${pathname}: ${href} must be local`);
      assert.notEqual(href, "#", `${pathname}: fragment must have a target`);
      const target = new URL(href, `https://phm.dev${pathname}`);
      assert.equal(target.origin, "https://phm.dev", `${pathname}: ${href}`);
      let pageFile = `src/app${target.pathname === "/" ? "" : target.pathname}/page.tsx`;
      if (target.pathname.startsWith("/docs/")) {
        const slug = target.pathname.slice("/docs/".length);
        assert.ok(catalog.some((doc) => doc.slug === slug), `${href}: documentation slug exists`);
        pageFile = "src/app/docs/[slug]/page.tsx";
      }
      assert.ok(fs.existsSync(path.join(webDir, pageFile)), `${href}: page exists`);
      if (target.hash) {
        const page = read(pageFile);
        const components = [...page.matchAll(/@\/components\/landing\/([^\"]+)/g)]
          .map((match) => read(`src/components/landing/${match[1]}.tsx`)).join("\n");
        const id = decodeURIComponent(target.hash.slice(1));
        assert.ok((page + components).includes(`id="${id}"`), `${href}: fragment target exists`);
      }
    }
    const hrefs = links.map((link) => link.getAttribute("href"));
    assert.equal(hrefs.filter((href) => href === (pathname === "/secrets" ? "#how" : "/secrets#how")).length, 2, pathname);
    assert.ok(hrefs.includes(pathname === "/" || pathname === "/docs" || pathname.startsWith("/docs/workbench") ? "/docs/workbench-setup" : pathname === "/secrets" ? "#install" : "/secrets#install"), pathname);
  }
});

test("public footer navigation links have nonempty destinations", () => {
  const React = require("react");
  const ts = require("typescript");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const compiled = ts.transpileModule(footer, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: "SiteFooter.tsx",
  }).outputText;
  const localRequire = (name) => {
    if (name === "next/link") return { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) };
    if (name === "next/image") return { __esModule: true, default: (props) => React.createElement("img", props) };
    if (name === "@/lib/commercial-offerings") return { COMMERCIAL_CONTACT: "contact@example.com" };
    return require(name);
  };
  const exports = {};
  new Function("exports", "require", compiled)(exports, localRequire);
  const dom = new JSDOM(renderToStaticMarkup(React.createElement(exports.SiteFooter)));
  try {
    const footerElement = dom.window.document.querySelector("footer");
    assert.ok(footerElement);
    for (const label of ["Product links", "Organization links", "Open-source project links"]) {
      const group = footerElement.querySelector(`nav[aria-label="${label}"]`);
      assert.ok(group, `${label} exists`);
      assert.ok(group.querySelectorAll("a").length > 0, `${label} has links`);
    }
    for (const link of footerElement.querySelectorAll("a")) {
      assert.match(link.getAttribute("href") ?? "", /\S/, `${link.textContent.trim()}: link needs a nonempty destination`);
    }
  } finally {
    dom.window.close();
  }
});

test("mobile navigation exposes state and keyboard-close semantics", () => {
  assert.match(nav, /type="button"/);
  assert.match(nav, /aria-expanded=\{menuOpen\}/);
  assert.match(nav, /aria-controls="mobile-navigation"/);
  assert.match(nav, /id="mobile-navigation"/);
  assert.match(nav, /hidden=\{!menuOpen\}/);
  assert.match(nav, /event\.key === "Escape"/);
  assert.match(nav, /setMenuOpen\(false\)/);
  assert.match(nav, /aria-label=\{menuOpen \? "Close navigation menu" : "Open navigation menu"\}/);
});

test("public shell provides a visible-on-focus skip link with real page-main targets", () => {
  assert.match(nav, /href="#main-content"/);
  assert.match(nav, />\s*Skip to main content\s*</);
  assert.match(nav, /focus:translate-y-0/);
  assert.match(nav, /!pathname\.startsWith\("\/dashboard"\)/);
  assert.doesNotMatch(layout, /id="main-content"/);
  for (const [route, source] of Object.entries(publicPages)) {
    assert.match(
      source,
      /<main\s+id="main-content"\s+tabIndex=\{-1\}/,
      `${route} must expose the shared skip target on its main landmark`,
    );
  }
  assert.match(nav, /aria-label="Phantom home"/);
  assert.match(nav, /src="\/favicon\.svg"[\s\S]{0,100}alt=""/);
  assert.match(footer, /aria-label="Phantom home"/);
  assert.match(footer, /src="\/favicon\.svg" alt=""/);
});

test("public document declares a nonempty language", () => {
  const React = require("react");
  const ts = require("typescript");
  const { renderToStaticMarkup } = require("react-dom/server");
  const { JSDOM } = require("jsdom");
  const compiled = ts.transpileModule(layout, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
    fileName: "layout.tsx",
  }).outputText;
  const localRequire = (name) => {
    if (name.endsWith(".css")) return {};
    if (name === "./providers") return { PostHogProvider: ({ children }) => children };
    return require(name);
  };
  const exports = {};
  new Function("exports", "require", compiled)(exports, localRequire);
  const dom = new JSDOM(renderToStaticMarkup(React.createElement(exports.default, null, "Page content")));
  try {
    assert.match(dom.window.document.documentElement.getAttribute("lang") ?? "", /\S/, "document language must not be empty");
  } finally {
    dom.window.close();
  }
});

test("root metadata supplies a title template without forcing every route canonical to home", () => {
  assert.match(layout, /metadataBase: new URL\(SITE_URL\)/);
  assert.match(layout, /template: "%s — Phantom"/);
  assert.match(layout, /referrer: "origin-when-cross-origin"/);
  assert.doesNotMatch(layout, /alternates:\s*\{\s*canonical:\s*"\/"/);
  assert.doesNotMatch(layout, /openGraph:\s*\{[\s\S]{0,120}url:\s*SITE_URL/);
  assert.match(layout, /manifest: "\/manifest\.webmanifest"/);
  assert.equal(manifest.name, "Phantom");
  assert.equal(manifest.short_name, "Phantom");
  assert.match(manifest.description, /engineering workbench/);
  assert.equal(manifest.start_url, "/");
  assert.equal(manifest.scope, "/");
  assert.equal(manifest.theme_color, "#050508");
  assert.deepEqual(manifest.icons, [
    { src: "/favicon.svg", sizes: "any", type: "image/svg+xml" },
  ]);
});

test("home page exports a nonempty metadata description", () => {
  const ts = require("typescript");
  const compiled = ts.transpileModule(publicPages["/"], {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
    fileName: "page.tsx",
  }).outputText;
  const exports = {};
  const localRequire = (name) => name.startsWith("@/") ? {} : require(name);
  new Function("exports", "require", compiled)(exports, localRequire);

  assert.equal(typeof exports.metadata?.description, "string");
  assert.match(exports.metadata.description, /\S/, "home page description must not be empty");
});

test("both installable manifests and machine references identify the workbench and dedicated Secrets page", () => {
  const dynamicManifest = read("src/app/manifest.ts");
  assert.match(dynamicManifest, /name: "Phantom"/);
  assert.match(dynamicManifest, /engineering workbench/);
  assert.match(dynamicManifest, /start_url: "\/"/);
  assert.match(dynamicManifest, /scope: "\/"/);
  for (const file of ["public/llms.txt", "public/llms-full.txt"]) {
    const reference = read(file);
    assert.match(reference, /## Phantom workbench/);
    assert.match(reference, /https:\/\/github\.com\/ashlrai\/phantom\n/);
    assert.match(reference, /https:\/\/www\.npmjs\.com\/package\/@ashlr\/phantom/);
    assert.match(reference, /## Phantom Secrets/);
    assert.match(reference, /https:\/\/phm\.dev\/secrets/);
    assert.match(reference, /`v0\.7\.9` evidence below describes Phantom Secrets only/);
  }
});

test("landing JSON-LD escapes closing-script payloads before raw insertion", () => {
  assert.match(
    landingStructuredData,
    /JSON\.stringify\(value\)\.replace\(\/<\/g, "\\\\u003c"\)/,
  );
  assert.match(
    landingStructuredData,
    /serializeStructuredData\(howTo\)/,
  );
  assert.match(
    landingStructuredData,
    /serializeStructuredData\(faqPage\)/,
  );

  const payload = { text: "</script><script>alert(1)</script>" };
  const serialized = JSON.stringify(payload).replace(/</g, "\\u003c");
  assert.doesNotMatch(serialized, /<\/script>|<script>/i);
  assert.match(serialized, /\\u003c\/script>/);
});

test("root JSON-LD uses script-safe serialization at every raw insertion", () => {
  assert.match(
    layout,
    /function serializeStructuredData\(value: unknown\): string \{\s*return JSON\.stringify\(value\)\.replace\(\/<\/g, "\\\\u003c"\);\s*\}/,
  );
  assert.equal(
    (layout.match(/__html: serializeStructuredData\(\{/g) ?? []).length,
    2,
  );
  assert.doesNotMatch(layout, /__html:\s*JSON\.stringify\(/);

  const payload = { text: "</script><script>alert(1)</script>" };
  const serialized = JSON.stringify(payload).replace(/</g, "\\u003c");
  assert.doesNotMatch(serialized, /<\/script>|<script>/i);
  assert.match(serialized, /\\u003c\/script>/);
});

test("each public route owns its canonical and social metadata", () => {
  assert.match(publicPages["/"], /alternates: \{ canonical: "\/" \}/);
  assert.match(publicPages["/"], /openGraph:\s*\{[\s\S]*?url: "\/"/);
  assert.match(publicPages["/"], /images: \[\{ url: "\/workbench-og\.png"/);

  for (const route of ["/secrets", "/pricing", "/enterprise", "/government", "/security"]) {
    const source = publicPages[route];
    const escapedRoute = route.replaceAll("/", "\\/");
    assert.match(source, /title: \{ absolute: title \}/, route);
    assert.match(
      source,
      new RegExp(`alternates: \\{ canonical: "https:\\/\\/phm\\.dev${escapedRoute}" \\}`),
      route,
    );
    assert.match(
      source,
      new RegExp(`url: "https:\\/\\/phm\\.dev${escapedRoute}"`),
      route,
    );
    assert.match(source, /twitter:\s*\{[\s\S]*?card: "summary_large_image"/, route);
  }
});

test("sitemap contains only canonical same-host public surfaces", () => {
  for (const route of [
    "/",
    "/secrets",
    "/pricing",
    "/enterprise",
    "/government",
    "/security",
    "/docs",
  ]) {
    assert.match(sitemap, new RegExp(`path: "${route.replace("/", "\\/")}"`));
  }

  assert.match(sitemap, /new URL\(path, SITE_URL\)\.toString\(\)/);
  assert.match(sitemap, /lastModified: gitLastModified\(process\.cwd\(\), files\)/);
  assert.match(sitemap, /dynamic = "force-static"/);
  assert.doesNotMatch(sitemap, /path: "[^\"]*\.(?:txt|json)"/);
  assert.doesNotMatch(sitemap, /github\.com|REPO_URL/);
  assert.doesNotMatch(sitemap, /\/api\/|\/dashboard|\/device|\/integrations\//);
  assert.doesNotMatch(sitemap, /new Date\(\)/);
  assert.doesNotMatch(sitemap, /changeFrequency|priority/);
});

test("crawler policy blocks APIs while sensitive pages expose observable noindex headers", () => {
  const nextConfig = read("next.config.ts");
  assert.match(robots, /userAgent: "\*"/);
  assert.match(robots, /"\/api\/"/);
  for (const route of ["/dashboard/:path*", "/device/:path*", "/integrations/:path*"]) {
    assert.match(nextConfig, new RegExp(`source: "${route.replaceAll("/", "\\/").replaceAll("*", "\\*")}"`));
  }
  assert.match(nextConfig, /X-Robots-Tag/);
  assert.match(nextConfig, /noindex, nofollow/);
  assert.doesNotMatch(robots, /dashboard|device|integrations/);
  assert.doesNotMatch(
    robots,
    /GPTBot|ClaudeBot|Claude-Web|anthropic-ai|PerplexityBot|Google-Extended|CCBot|cohere-ai/,
  );
  assert.match(robots, /sitemap: `\$\{SITE_URL\}\/sitemap\.xml`/);
});

test("SEO observation is scheduled, read-only, credential-free, and non-publishing", async () => {
  const { assertReadOnlyWorkflowPolicy } = await import(
    pathToFileURL(
      path.resolve(webDir, "../..", "scripts/seo/workflow-policy.mjs"),
    ).href
  );
  const policy = assertReadOnlyWorkflowPolicy(seoWorkflow);
  assert.deepEqual(policy.workflowPermissions, { contents: "read" });
  assert.deepEqual(policy.jobs, {
    observe: { permissions: { contents: "read" } },
  });
  assert.match(seoWorkflow, /schedule:/);
  assert.match(seoWorkflow, /workflow_dispatch:/);
  assert.match(seoWorkflow, /scripts\/seo\/observe\.mjs/);
  assert.match(seoWorkflow, /scripts\/seo\/observe\.test\.mjs/);
  assert.match(seoWorkflow, /retention-days: 30/);
  assert.doesNotMatch(seoWorkflow, /pull_request_target/);
  assert.doesNotMatch(seoWorkflow, /gh issue|gh pr|vercel deploy|slack/i);
});

test("footer exposes product, organization, and open-source paths without live-service claims", () => {
  assert.match(footer, /aria-label="Product links"/);
  assert.match(footer, /aria-label="Organization links"/);
  assert.match(footer, /aria-label="Open-source project links"/);
  assert.match(footer, /href="https:\/\/github\.com\/ashlrai\/phantom"[\s\S]{0,100}Phantom workbench on GitHub/);
  assert.match(footer, /href="https:\/\/github\.com\/ashlrai\/phantom-secrets"[\s\S]{0,100}Phantom Secrets on GitHub/);
  assert.match(footer, /href="\/enterprise"/);
  assert.match(footer, /href="\/government"/);
  assert.match(footer, /href="\/security"/);
  assert.match(footer, /written agreement/i);
  assert.match(footer, /Hosted services and support require separate commissioning/i);
  assert.match(footer, /MIT license/);
  assert.doesNotMatch(footer, /available now|guaranteed|certified|compliant/i);
});


test("local fonts preserve licensed bytes, glyph subsets and the two Latin preloads without a network loader", () => {
  const crypto = require("node:crypto");
  const fontCss = read("src/app/local-fonts.css");
  const sources = read("public/fonts/SOURCES.md");
  assert.doesNotMatch(layout, /next\/font\/google|fonts\.googleapis\.com/);
  assert.match(layout, /import "\.\/local-fonts\.css"/);
  assert.match(fontCss, /--font-sans-stack: "Inter Tight", "Inter Tight Fallback"/);
  assert.match(fontCss, /--font-mono-stack: "JetBrains Mono", "JetBrains Mono Fallback"/);
  assert.match(fontCss, /ascent-override:100\.51%/);
  assert.match(fontCss, /ascent-override:75\.79%/);
  const faces = [...fontCss.matchAll(/@font-face\{([^}]+)\}/g)].map((match) => match[1]);
  const files = [...new Set([...fontCss.matchAll(/src:url\(\/fonts\/([^)]*)\)/g)].map((match) => match[1]))];
  assert.equal(files.length, 13);
  for (const file of files) {
    const bytes = fs.readFileSync(path.join(webDir, "public/fonts", file));
    assert.equal(bytes.subarray(0, 4).toString(), "wOF2");
    const digest = crypto.createHash("sha256").update(bytes).digest("hex");
    assert.ok(sources.includes(`| \`${file}\` |`) && sources.includes(`| \`${digest}\` |`), `manufacturer pin for ${file}`);
  }
  for (const family of ["Inter Tight", "JetBrains Mono"]) {
    const familyFaces = faces.filter((face) => face.startsWith(`font-family:${family};`));
    for (const glyphRange of ["u+00??", "u+0400-045f", "u+0370-0377", "u+0102-0103"]) {
      assert.ok(familyFaces.some((face) => face.includes(glyphRange)), `${family} preserves ${glyphRange}`);
    }
  }
  const preloads = [...layout.matchAll(/rel="preload" href="(\/fonts\/[^\"]+)"/g)].map((match) => match[1]);
  assert.equal(preloads.length, 2);
  for (const preload of preloads) {
    assert.ok(faces.some((face) => face.includes(`url(${preload})`) && face.includes("unicode-range:u+00??")));
  }
  for (const file of ["inter-tight-OFL.txt", "jetbrains-mono-OFL.txt"]) {
    assert.match(read(`public/fonts/${file}`), /SIL OPEN FONT LICENSE Version 1\.1/);
  }
});

test("only exact legacy Secrets fragments navigate from home, preserving new anchors and safe route boundaries", () => {
  const ts = require("typescript");
  const source = read("src/lib/legacy-secrets-fragment.ts");
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
  const exports = {};
  new Function("exports", compiled)(exports);
  const { legacySecretsDestination } = exports;
  const knownIds = [...source.matchAll(/^  "([^\"]+)",$/gm)].map((match) => match[1]);
  assert.equal(knownIds.length, 16);
  const secretsPage = read("src/app/secrets/page.tsx");
  const componentSources = [...secretsPage.matchAll(/@\/components\/landing\/([^\"]+)/g)].map((match) => read(`src/components/landing/${match[1]}.tsx`)).join("\n");
  for (const id of knownIds) {
    assert.ok(componentSources.includes(`id="${id}"`), `legacy destination ${id} exists`);
    assert.equal(legacySecretsDestination("/", `#${id}`), `/secrets#${id}`);
    assert.equal(legacySecretsDestination("/secrets", `#${id}`), null);
    assert.equal(legacySecretsDestination("/dashboard", `#${id}`), null);
  }
  assert.equal(legacySecretsDestination("/", "#%69nstall"), "/secrets#install");
  for (const hash of ["", "#", "install", "#phantom-world", "#main-content", "#phantom-secrets", "#workbench-title", "#unknown", "#%", "#//evil.example", "#https://evil.example", "#install?evil=true", "#install/../../dashboard"]) {
    assert.equal(legacySecretsDestination("/", hash), null, hash);
  }
  assert.match(nav, /removeEventListener\("hashchange", preserveSecretsBookmark\)/);
  assert.match(nav, /if \(destination\) window\.location\.replace\(destination\)/);
  assert.doesNotMatch(nav, /router\.replace|useRouter/);
});


test("workbench and Secrets own distinct schema and social images with script-safe metadata", async () => {
  const workbenchSchema = read("src/components/landing/WorkbenchStructuredData.tsx");
  assert.match(layout, /"@type": "WebSite"/);
  assert.match(layout, /"@type": "Organization"/);
  assert.doesNotMatch(layout, /"@type": "SoftwareApplication"|"@type": "SoftwareSourceCode"|softwareVersion|SecretsManagement/);
  assert.match(publicPages["/"], /<WorkbenchStructuredData \/>/);
  assert.match(workbenchSchema, /codeRepository: "https:\/\/github\.com\/ashlrai\/phantom"/);
  assert.doesNotMatch(workbenchSchema, /operatingSystem|SecretsManagement|phantom-secrets/);
  assert.match(workbenchSchema, /softwareVersion: WORKBENCH_RELEASE\.version/);
  assert.match(workbenchSchema, /WORKBENCH_RELEASE\?\.macDownloadUrl/);
  assert.match(publicPages["/secrets"], /<LandingStructuredData \/>/);
  assert.match(landingStructuredData, /const SITE_URL = "https:\/\/phm\.dev\/secrets"/);
  assert.match(landingStructuredData, /softwareVersion: PUBLIC_RELEASE_VERSION/);
  assert.match(landingStructuredData, /downloadUrl: PUBLIC_RELEASE_URL/);
  assert.match(landingStructuredData, /codeRepository: "https:\/\/github\.com\/ashlrai\/phantom-secrets"/);
  assert.match(workbenchSchema, /JSON\.stringify\(value\)\.replace\(\/<\/g, "\\\\u003c"\)/);
  assert.doesNotMatch(workbenchSchema, /__html:\s*JSON\.stringify\(/);
  assert.match(publicPages["/secrets"], /url: "\/og-image\.png"/);
  assert.match(layout, /url: "\/workbench-og\.png"/);
  const sharp = require("sharp");
  const metadata = await sharp(path.join(webDir, "public/workbench-og.png")).metadata();
  assert.deepEqual([metadata.format, metadata.width, metadata.height], ["png", 1200, 630]);
  const ghost = fs.readFileSync(path.join(webDir, "public/phantom-world/phantom-mark.svg"));
  assert.ok(read("public/workbench-og.svg").includes(`data:image/svg+xml;base64,${ghost.toString("base64")}`));
  assert.match(read("public/workbench-og-SOURCES.md"), /illustrated product card/);
});
