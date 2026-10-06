const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const markdownLoader = require("../scripts/public-doc-markdown-loader.cjs");

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
  assert.match(source, /markdown: MARKDOWN_BY_FILE\[entry\.file\]/);
  assert.doesNotMatch(source, /readFileSync|process\.cwd\(|node:fs/);

  const renderer = read("src/components/docs/MarkdownDocument.tsx");
  assert.match(renderer, /!href\.startsWith\("\/\/"\)/);
});

function textModule(file, contents) {
  const dependencies = [];
  const javascript = markdownLoader.call({
    resourcePath: path.join(repoRoot, "docs", file),
    addDependency: (dependency) => dependencies.push(dependency),
  }, contents);
  assert.deepEqual(dependencies, [path.join(webRoot, "docs-catalog.json")]);
  assert.match(javascript, /^export default /);
  // Parse the actual emitted JS string literal; no source text is executed.
  return JSON.parse(javascript.slice("export default ".length, -1));
}

function loadDocs(entries = catalog) {
  const file = path.join(webRoot, "src/lib/public-docs.ts");
  const output = ts.transpileModule(fs.readFileSync(file, "utf8"), {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      resolveJsonModule: true,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: file,
  }).outputText;
  const loadedFiles = [];
  const module = { exports: {} };
  const localRequire = (specifier) => {
    if (specifier === "server-only") return {};
    if (specifier === "../../docs-catalog.json") return entries;
    if (specifier.endsWith(".md")) {
      const absolute = path.resolve(path.dirname(file), specifier);
      loadedFiles.push(absolute);
      return textModule(path.basename(absolute), fs.readFileSync(absolute, "utf8"));
    }
    throw new Error(`Runtime dependency must not be requested: ${specifier}`);
  };
  new Function("exports", "require", "module", output)(module.exports, localRequire, module);
  return { docs: module.exports, loadedFiles };
}

test("bundled documentation preserves every authoritative Markdown byte without runtime filesystem access", () => {
  const { docs, loadedFiles } = loadDocs();
  assert.deepEqual(loadedFiles.sort(), catalog.map(({ file }) => path.join(repoRoot, "docs", file)).sort());
  for (const entry of catalog) {
    const doc = docs.getPublicDoc(entry.slug);
    assert.equal(doc.markdown, fs.readFileSync(path.join(repoRoot, "docs", entry.file), "utf8"));
    assert.equal(doc.sourceUrl, `https://github.com/ashlrai/phantom-secrets/blob/main/docs/${entry.file}`);
  }
  const initialLoads = loadedFiles.length;
  for (const slug of ["", "missing", "../SECURITY", "getting-started.md", "..%2fSECURITY"]) {
    assert.equal(docs.getPublicDoc(slug), undefined);
  }
  assert.equal(loadedFiles.length, initialLoads, "unknown slugs must not request another text module");
});

test("the text loader escapes arbitrary Markdown and rejects files outside its catalog", () => {
  const source = 'quotes " backslash \\ newline\n</script> ${notCode} `code` \u2028\u2029 emoji 🧭';
  assert.equal(textModule(catalog[0].file, source), source);
  assert.equal(markdownLoader.raw, true);
  assert.equal(textModule(catalog[0].file, Buffer.from(`\ufeff${source}`, "utf8")), `\ufeff${source}`);
  for (const resourcePath of [
    path.join(repoRoot, "SECURITY.md"),
    path.join(repoRoot, "docs", "README.md"),
    path.join(webRoot, catalog[0].file),
  ]) {
    assert.throws(() => markdownLoader.call({ resourcePath, addDependency() {} }, source), /outside the public documentation catalog/);
  }
});

test("embedding fails closed when the catalog is empty, missing, duplicated or adds an unimported guide", () => {
  for (const entries of [
    [],
    catalog.slice(1),
    [...catalog, catalog[0]],
    [...catalog, { ...catalog[0], slug: "new-guide", file: "new-guide.md" }],
  ]) {
    assert.throws(() => loadDocs(entries), /catalog|documentation catalog/);
  }
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
