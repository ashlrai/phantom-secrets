const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const webRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(webRoot, "../..");
const catalog = require("../docs-catalog.json");

function load(relativePath, dependencies = {}) {
  const source = fs.readFileSync(path.join(webRoot, relativePath), "utf8");
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const module = { exports: {} };
  new Function("require", "module", "exports", compiled)(
    (name) => dependencies[name] ?? require(name), module, module.exports,
  );
  return module.exports;
}

const data = load("src/lib/secret-use-cases.ts");
const route = load("src/app/secrets/use-cases/[slug]/page.tsx", {
  "@/lib/secret-use-cases": data,
  "@/components/landing/Nav": { Nav: () => null },
  "@/components/landing/SiteFooter": { SiteFooter: () => null },
  "next/link": { __esModule: true, default: ({ children, ...props }) => React.createElement("a", props, children) },
  "next/navigation": { notFound: () => { throw new Error("NOT_FOUND"); } },
});

test("use cases cover three distinct tasks with a closed static route allowlist", () => {
  assert.equal(data.SECRET_USE_CASES.length, 3);
  assert.deepEqual(data.SECRET_USE_CASES.map(({ slug }) => slug), [
    "ai-api-development", "multi-project-setup", "debug-api-authentication",
  ]);
  assert.equal(new Set(data.SECRET_USE_CASES.map(({ title }) => title)).size, 3);
  assert.equal(route.dynamicParams, false);
  assert.deepEqual(route.generateStaticParams(), data.SECRET_USE_CASES.map(({ slug }) => ({ slug })));
});

for (const guide of data.SECRET_USE_CASES) {
  test(`${guide.slug}: every claim and command has a resolvable repository source`, () => {
    const claims = [guide.introduction, ...guide.steps, guide.limits];
    assert.equal(new Set(claims.map(({ id }) => id)).size, claims.length);
    assert.ok(guide.steps.length >= 3);
    assert.doesNotMatch(JSON.stringify(guide), /\u2014/);
    for (const claim of claims) {
      assert.ok(claim.title.trim());
      assert.ok(claim.paragraphs.length > 0);
      assert.ok(claim.paragraphs.every((paragraph) => paragraph.trim().length > 0));
      assert.ok(claim.sources.length > 0, `${claim.id} requires evidence`);
      for (const source of claim.sources) {
        assert.ok(source.label.trim());
        if (source.href.startsWith("/docs/")) {
          const slug = source.href.slice("/docs/".length);
          const doc = catalog.find((entry) => entry.slug === slug);
          assert.ok(doc, `published documentation: ${source.href}`);
          assert.ok(fs.statSync(path.join(repoRoot, "docs", doc.file)).isFile());
        } else {
          const prefix = "https://github.com/ashlrai/phantom-secrets/blob/main/";
          assert.ok(source.href.startsWith(prefix), `only first-party evidence: ${source.href}`);
          const file = source.href.slice(prefix.length);
          assert.ok(!file.includes("..") && !file.includes("?") && !file.includes("#"));
          assert.ok(fs.statSync(path.join(repoRoot, file)).isFile(), file);
        }
      }
    }
  });

  test(`${guide.slug}: rendered claim blocks carry citations, related tasks and install links`, async () => {
    const element = await route.default({ params: Promise.resolve({ slug: guide.slug }) });
    const html = renderToStaticMarkup(element);
    const claims = [guide.introduction, ...guide.steps, guide.limits];
    const blocks = [...html.matchAll(/<section\b[^>]*data-claim="([^"]+)"[^>]*>([\s\S]*?)<\/section>/g)];
    assert.equal(blocks.length, claims.length);
    for (const [index, block] of blocks.entries()) {
      assert.equal(block[1], claims[index].id);
      const sources = [...block[2].matchAll(/<a\b[^>]*data-source="true"[^>]*href="([^"]+)"/g)];
      assert.deepEqual(sources.map((match) => match[1]), claims[index].sources.map(({ href }) => href));
      assert.ok(sources.length > 0);
      assert.equal((block[2].match(/<p>/g) ?? []).length, claims[index].paragraphs.length);
      if (claims[index].command) assert.match(block[2], /<pre tabindex="0"[^>]*><code>/);
    }
    assert.equal((html.match(/<h1>/g) ?? []).length, 1);
    assert.match(html, /<main id="main-content" tabindex="-1"/);
    assert.match(html, /href="\/secrets#install"/);
    assert.match(html, /href="\/docs"/);
    assert.match(html, /href="\/docs\/getting-started"/);
    for (const related of data.SECRET_USE_CASES.filter(({ slug }) => slug !== guide.slug)) {
      assert.ok(html.includes(`href="${data.secretUseCasePath(related.slug)}"`));
    }
    const structuredData = JSON.parse(html.match(/<script type="application\/ld\+json">([^<]*)<\/script>/)[1]);
    assert.equal(structuredData.itemListElement[1].item, `https://phm.dev${data.secretUseCasePath(guide.slug)}`);
  });

  test(`${guide.slug}: metadata uses the page's absolute canonical and social identity`, async () => {
    const metadata = await route.generateMetadata({ params: Promise.resolve({ slug: guide.slug }) });
    const canonical = `https://phm.dev${data.secretUseCasePath(guide.slug)}`;
    assert.equal(metadata.alternates.canonical, canonical);
    assert.equal(metadata.openGraph.url, canonical);
    assert.equal(metadata.title.absolute, `${guide.title} | Phantom Secrets`);
    assert.equal(metadata.description, guide.description);
    assert.equal(metadata.twitter.card, "summary_large_image");
    assert.equal(metadata.twitter.title, metadata.title.absolute);
    assert.doesNotMatch(JSON.stringify(metadata), /\u2014/);
  });
}

test("unknown and traversal-shaped use cases fail closed for content and metadata", async () => {
  for (const slug of ["unknown", "", "../docs", "%2e%2e", "ai-api-development/other"]) {
    assert.equal(data.getSecretUseCase(slug), undefined);
    await assert.rejects(route.default({ params: Promise.resolve({ slug }) }), /NOT_FOUND/);
    await assert.rejects(route.generateMetadata({ params: Promise.resolve({ slug }) }), /NOT_FOUND/);
  }
});

test("authentication diagnosis uses the value-free JSON report and preserves no-route and locked-vault stops", () => {
  const guide = data.getSecretUseCase("debug-api-authentication");
  assert.match(guide.steps.find(({ id }) => id === "project").command, /phantom why OPENAI_API_KEY --json/);
  assert.match(guide.steps.find(({ id }) => id === "route").paragraphs.join(" "), /no_route/);
  assert.match(guide.steps.find(({ id }) => id === "vault").paragraphs.join(" "), /refuse an answer rather than report an empty/);
  assert.doesNotMatch(guide.steps.map(({ command }) => command ?? "").join("\n"), /phantom reveal|printenv|cat .*\.env/);
});
