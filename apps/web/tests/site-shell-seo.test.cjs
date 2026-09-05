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
  "/pricing": read("src/app/pricing/page.tsx"),
  "/enterprise": read("src/app/enterprise/page.tsx"),
  "/government": read("src/app/government/page.tsx"),
  "/security": read("src/app/security/page.tsx"),
};

test("primary navigation works from the home page and nested routes", () => {
  assert.match(nav, /usePathname/);
  assert.match(
    nav,
    /pathname === "\/" \? `#\$\{section\}` : `\/#\$\{section\}`/,
  );
  assert.match(nav, /href: "\/pricing"/);
  assert.match(nav, /href: "\/enterprise"/);
  assert.match(nav, /href: "\/security"/);
  assert.match(nav, /aria-current=\{active \? "page" : undefined\}/);
  assert.match(nav, /aria-label="Primary navigation"/);
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

test("root metadata supplies a title template without forcing every route canonical to home", () => {
  assert.match(layout, /metadataBase: new URL\(SITE_URL\)/);
  assert.match(layout, /template: "%s — Phantom"/);
  assert.match(layout, /referrer: "origin-when-cross-origin"/);
  assert.doesNotMatch(layout, /alternates:\s*\{\s*canonical:\s*"\/"/);
  assert.doesNotMatch(layout, /openGraph:\s*\{[\s\S]{0,120}url:\s*SITE_URL/);
  assert.match(layout, /manifest: "\/manifest\.webmanifest"/);
  assert.equal(manifest.name, "Phantom Secrets");
  assert.equal(manifest.start_url, "/");
  assert.equal(manifest.scope, "/");
  assert.equal(manifest.theme_color, "#050508");
  assert.deepEqual(manifest.icons, [
    { src: "/favicon.svg", sizes: "any", type: "image/svg+xml" },
  ]);
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
    3,
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
  assert.match(publicPages["/"], /images: \[\{ url: "\/og-image\.png"/);

  for (const route of ["/pricing", "/enterprise", "/government", "/security"]) {
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
    "/pricing",
    "/enterprise",
    "/government",
    "/security",
    "/llms.txt",
    "/llms-full.txt",
  ]) {
    assert.match(sitemap, new RegExp(`path: "${route.replace("/", "\\/")}"`));
  }

  assert.match(sitemap, /new URL\(path, SITE_URL\)\.toString\(\)/);
  assert.match(sitemap, /lastModified: modified/);
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
  assert.match(footer, /href="\/enterprise"/);
  assert.match(footer, /href="\/government"/);
  assert.match(footer, /href="\/security"/);
  assert.match(footer, /written agreement/i);
  assert.match(footer, /Hosted services and support require separate commissioning/i);
  assert.match(footer, /MIT license/);
  assert.doesNotMatch(footer, /available now|guaranteed|certified|compliant/i);
});
