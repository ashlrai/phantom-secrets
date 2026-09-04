const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(webRoot, "..", "..");
const read = (relativePath) =>
  fs.readFileSync(path.join(webRoot, relativePath), "utf8");
const catalog = JSON.parse(read("docs-catalog.json"));

const expectedSlugs = [
  "getting-started",
  "delegation-quickstart",
  "protect-api-keys-from-ai-coding-agents",
  "mcp-secrets-manager",
  "public-fact-sheet",
  "claude-code",
  "cursor",
  "windsurf",
  "codex",
  "platform-support",
  "troubleshooting",
  "architecture",
  "enterprise-adoption",
];

test("public documentation uses an exact file-backed allowlist", () => {
  assert.deepEqual(
    catalog.map(({ slug }) => slug),
    expectedSlugs,
  );

  for (const entry of catalog) {
    assert.deepEqual(
      Object.keys(entry).sort(),
      ["description", "file", "modified", "slug", "title"],
    );
    assert.match(entry.slug, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    assert.match(entry.file, /^[a-z0-9]+(?:-[a-z0-9]+)*\.md$/);
    assert.equal(entry.file, `${entry.slug}.md`);
    assert.match(entry.modified, /^\d{4}-\d{2}-\d{2}$/);
    assert.equal(
      fs.existsSync(path.join(repoRoot, "docs", entry.file)),
      true,
      `missing docs/${entry.file}`,
    );
  }
});

test("unknown and traversal-shaped slugs cannot select a documentation file", () => {
  for (const candidate of [
    "../SECURITY",
    "..%2FSECURITY",
    "%2e%2e%2fSECURITY",
    "getting-started/../../SECURITY",
    "getting-started.md",
    "",
  ]) {
    assert.equal(
      catalog.find(({ slug }) => slug === candidate),
      undefined,
      candidate,
    );
  }

  const source = read("src/lib/public-docs.ts");
  assert.match(source, /getPublicDocConfig\(slug\)/);
  assert.match(source, /if \(!entry\) return undefined/);
  assert.match(source, /readFileSync\(path\.join\(DOCS_ROOT, entry\.file\)/);
  assert.doesNotMatch(source, /readFileSync\([^\n]*slug/);

  const renderer = read("src/components/docs/MarkdownDocument.tsx");
  assert.match(renderer, /!href\.startsWith\("\/\/"\)/);
});

test("the App Router surface is static, canonical, and fails closed", () => {
  const page = read("src/app/docs/[slug]/page.tsx");

  assert.match(page, /export const dynamicParams = false/);
  assert.match(page, /generateStaticParams/);
  assert.match(page, /PUBLIC_DOCS\.map\(\(\{ slug \}\) => \(\{ slug \}\)\)/);
  assert.match(page, /generateMetadata/);
  assert.match(page, /alternates: \{ canonical \}/);
  assert.match(page, /notFound\(\)/);
  assert.match(page, /View \{doc\.file\} on GitHub/);
  assert.match(page, /"@type": "TechArticle"/);
  assert.match(page, /"@type": "BreadcrumbList"/);
  assert.match(page, /mainEntityOfPage: canonicalUrl/);
  assert.match(page, /sameAs: doc\.sourceUrl/);
  assert.match(page, /dateModified: doc\.modified/);
  assert.match(page, /JSON\.stringify\(structuredData\)\.replace/);
  assert.match(page, /dangerouslySetInnerHTML=\{\{ __html: serializedStructuredData \}\}/);

  const renderer = read("src/components/docs/MarkdownDocument.tsx");
  assert.doesNotMatch(renderer, /dangerouslySetInnerHTML/);
  assert.match(renderer, /publicDocHrefForMarkdownFile/);
  assert.match(renderer, /repositoryPath\.startsWith\("\.\.\/"\)/);
});

test("the docs hub and sitemap expose every rendered guide", () => {
  const hub = read("src/app/docs/page.tsx");
  const sitemap = read("src/app/sitemap.ts");

  for (const slug of expectedSlugs) {
    if (["getting-started", "delegation-quickstart", "protect-api-keys-from-ai-coding-agents", "mcp-secrets-manager", "public-fact-sheet", "claude-code", "cursor", "windsurf", "codex", "platform-support", "troubleshooting", "architecture", "enterprise-adoption"].includes(slug)) {
      assert.match(hub, new RegExp(`/docs/${slug}`));
    }
  }
  assert.match(sitemap, /import \{ PUBLIC_DOCS \}/);
  assert.match(sitemap, /path: `\/docs\/\$\{slug\}`/);
});
