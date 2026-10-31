const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { JSDOM } = require("jsdom");
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
  "workbench",
  "workbench-setup",
  "workbench-agents",
  "workbench-autonomy",
  "workbench-reference",
  "workbench-troubleshooting",
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

function loadDocs(entries = catalog, revision) {
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
  new Function("exports", "require", "module", "process", output)(
    module.exports, localRequire, module, { env: { PHANTOM_BUILD_SOURCE_REVISION: revision } },
  );
  return { docs: module.exports, loadedFiles };
}

function assertPrimaryHeading(document, pagePath) {
  const heading = document.querySelector("main h1");
  assert.ok(heading, `${pagePath} must have a primary heading`);
  assert.ok(heading.textContent.trim(), `${pagePath} must have a nonempty primary heading`);
}

test("every public documentation page renders a nonempty primary heading", async () => {
  const { docs } = loadDocs();
  const empty = () => null;
  const Link = ({ href, children, ...props }) => React.createElement("a", { href, ...props }, children);
  const hub = loadComponent("src/app/docs/page.tsx", {
    "next/link": Link,
    "@/components/landing/Nav": { Nav: empty },
    "@/components/landing/SiteFooter": { SiteFooter: empty },
    "@/components/landing/CopyButton": { CopyButton: empty },
    "@/components/landing/SecretUseCases": { SecretUseCases: empty },
    "@/components/docs/AskDocumentation": { AskDocumentation: empty },
    "@/lib/workbench-release": { WORKBENCH_RELEASE: null },
    "@/lib/public-release": { PUBLIC_RELEASE_TAG: "test" },
  });
  const renderer = loadComponent("src/components/docs/MarkdownDocument.tsx", {
    "@/lib/public-docs": docs,
  });
  const page = loadComponent("src/app/docs/[slug]/page.tsx", {
    "next/link": Link,
    "next/navigation": { notFound: () => { throw new Error("Document not found"); } },
    "@/components/docs/AskDocumentation": { AskDocumentation: () => null },
    "@/components/docs/MarkdownDocument": renderer,
    "@/components/landing/Nav": { Nav: () => null },
    "@/components/landing/SiteFooter": { SiteFooter: () => null },
    "@/lib/public-docs": docs,
  });

  assertPrimaryHeading(new JSDOM(renderToStaticMarkup(React.createElement(hub.default))).window.document, "/docs");
  for (const { slug } of catalog) {
    const element = await page.default({ params: Promise.resolve({ slug }) });
    const document = new JSDOM(renderToStaticMarkup(element)).window.document;
    assertPrimaryHeading(document, `/docs/${slug}`);
  }
});

test("primary heading checks reject missing, empty, and out-of-main headings", () => {
  const document = (html) => new JSDOM(html).window.document;
  assert.doesNotThrow(() => assertPrimaryHeading(document("<main><h1>Guide</h1></main>"), "/fixture"));
  for (const html of [
    "<main></main>",
    "<main><h1>  </h1></main>",
    "<h1>Outside main</h1><main></main>",
  ]) {
    assert.throws(() => assertPrimaryHeading(document(html), "/fixture"), /\/fixture must have a (?:nonempty )?primary heading/);
  }
});

test("bundled documentation preserves every authoritative Markdown byte without runtime filesystem access", () => {
  const { docs, loadedFiles } = loadDocs();
  assert.deepEqual(loadedFiles.sort(), catalog.map(({ file }) => path.join(repoRoot, "docs", file)).sort());
  for (const entry of catalog) {
    const doc = docs.getPublicDoc(entry.slug);
    assert.equal(doc.markdown, fs.readFileSync(path.join(repoRoot, "docs", entry.file), "utf8"));
    assert.equal(doc.sourceUrl, entry.slug === "workbench" || entry.slug.startsWith("workbench-")
      ? `https://phm.dev/docs/${entry.slug}/markdown`
      : `https://github.com/ashlrai/phantom-secrets/blob/main/docs/${entry.file}`);
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

function loadComponent(relativePath, dependencies) {
  const output = ts.transpileModule(read(relativePath), {
    compilerOptions: {
      esModuleInterop: true,
      jsx: ts.JsxEmit.ReactJSX,
      module: ts.ModuleKind.CommonJS,
    },
    fileName: relativePath,
  }).outputText;
  const module = { exports: {} };
  const localRequire = (specifier) => {
    if (Object.hasOwn(dependencies, specifier)) return dependencies[specifier];
    if (specifier === "react" || specifier === "react/jsx-runtime" || specifier === "node:path") {
      return require(specifier);
    }
    throw new Error(`Unexpected component dependency: ${specifier}`);
  };
  new Function("exports", "require", "module", output)(module.exports, localRequire, module);
  return module.exports;
}

const { registerPublicDocsLinkLabelTests } = loadComponent("tests/public-docs.test.ts", {
  "node:assert/strict": assert,
  "node:test": test,
});

registerPublicDocsLinkLabelTests(async () => {
  const { pathToFileURL } = require("node:url");
  const assistant = await import(pathToFileURL(path.join(webRoot, "src/lib/documentation-assistant.mjs")).href);
  const Link = ({ href, children, ...props }) => React.createElement("a", { href, ...props }, children);
  const empty = () => null;
  const shared = {
    "next/link": Link,
    "@/components/landing/Nav": { Nav: empty },
    "@/components/landing/SiteFooter": { SiteFooter: empty },
    "@/components/docs/AskDocumentation": loadComponent("src/components/docs/AskDocumentation.tsx", {
      "@/lib/documentation-assistant.mjs": assistant,
    }),
  };
  const docs = loadDocs().docs;
  const renderer = loadComponent("src/components/docs/MarkdownDocument.tsx", { "@/lib/public-docs": docs });
  const hub = loadComponent("src/app/docs/page.tsx", {
    ...shared,
    "@/components/landing/CopyButton": { CopyButton: empty },
    "@/components/landing/SecretUseCases": loadComponent("src/components/landing/SecretUseCases.tsx", {
      "next/link": Link,
      "@/lib/secret-use-cases": loadComponent("src/lib/secret-use-cases.ts", {}),
    }),
    "@/lib/workbench-release": { WORKBENCH_RELEASE: null },
    "@/lib/public-release": { PUBLIC_RELEASE_TAG: "test" },
  });
  const page = loadComponent("src/app/docs/[slug]/page.tsx", {
    ...shared,
    "next/navigation": { notFound: () => { throw new Error("Document not found"); } },
    "@/components/docs/MarkdownDocument": renderer,
    "@/lib/public-docs": docs,
  });
  const pages = [{ path: "/docs", element: React.createElement(hub.default) }];
  for (const { slug } of catalog) {
    pages.push({ path: `/docs/${slug}`, element: await page.default({ params: Promise.resolve({ slug }) }) });
  }
  return pages.map(({ path, element }) => ({ path, document: new JSDOM(renderToStaticMarkup(element)).window.document }));
}, (html) => new JSDOM(html).window.document, require("dom-accessibility-api").computeAccessibleName);

function isLocalPage(href) {
  if (!href.startsWith("/") || href.startsWith("//")) return false;
  const pathname = new URL(href, "https://phm.dev").pathname.replace(/\/$/, "") || "/";
  const guide = /^\/docs\/([^/]+)(\/markdown)?$/.exec(pathname);
  if (guide && guide[1] !== "manifest.json") {
    return catalog.some(({ slug }) => slug === guide[1]) &&
      fs.existsSync(path.join(webRoot, "src/app/docs/[slug]", guide[2] ? "markdown/route.ts" : "page.tsx"));
  }
  const relativePath = pathname.slice(1);
  return [
    path.join(webRoot, "src/app", relativePath, "page.tsx"),
    path.join(webRoot, "src/app", relativePath, "route.ts"),
    path.join(webRoot, "public", relativePath),
  ].some((file) => fs.existsSync(file) && fs.statSync(file).isFile());
}

function localLinks(element) {
  const html = renderToStaticMarkup(element);
  return [...new JSDOM(html).window.document.querySelectorAll("a[href]")]
    .map((link) => link.getAttribute("href"))
    .filter((href) => href.startsWith("/") && !href.startsWith("//"));
}

test("rendered documentation navigation points to existing local pages", () => {
  const empty = () => null;
  const Link = ({ href, children }) => React.createElement("a", { href }, children);
  const { default: DocsPage } = loadComponent("src/app/docs/page.tsx", {
    "next/link": Link,
    "@/components/landing/Nav": { Nav: empty },
    "@/components/landing/SiteFooter": { SiteFooter: empty },
    "@/components/landing/CopyButton": { CopyButton: empty },
    "@/components/docs/AskDocumentation": { AskDocumentation: empty },
    "@/components/landing/SecretUseCases": { SecretUseCases: empty },
    "@/lib/workbench-release": { WORKBENCH_RELEASE: null },
    "@/lib/public-release": { PUBLIC_RELEASE_TAG: "test" },
  });
  const { MarkdownDocument } = loadComponent("src/components/docs/MarkdownDocument.tsx", {
    "@/lib/public-docs": loadDocs().docs,
  });
  const hubLinks = localLinks(React.createElement(DocsPage));
  assert.ok(hubLinks.length > catalog.length, "the hub must expose its guide and resource links");
  for (const href of hubLinks) assert.ok(isLocalPage(href), `docs hub links to missing ${href}`);

  for (const entry of catalog) {
    const markdown = fs.readFileSync(path.join(repoRoot, "docs", entry.file), "utf8");
    for (const href of localLinks(React.createElement(MarkdownDocument, { markdown, sourceFile: entry.file }))) {
      assert.ok(isLocalPage(href), `${entry.file} links to missing ${href}`);
    }
  }
});

test("local documentation route checks reject missing guides and accept URL fragments", () => {
  assert.equal(isLocalPage("/docs/getting-started?source=hub#install"), true);
  assert.equal(isLocalPage("/docs/getting-started/markdown"), true);
  assert.equal(isLocalPage("/docs/guide-that-does-not-exist"), false);
  assert.equal(isLocalPage("/docs/guide-that-does-not-exist/markdown"), false);
  assert.equal(isLocalPage("/docs/[slug]"), false);
  assert.equal(isLocalPage("/not-a-local-page"), false);
});

test("documented same-origin links resolve to public routes or assets", () => {
  const docs = loadDocs().docs;
  const useCases = loadComponent("src/lib/secret-use-cases.ts", {});
  const sitemap = loadComponent("src/app/sitemap.ts", {
    "@/lib/public-docs": docs,
    "@/lib/secret-use-cases": useCases,
    "@/lib/git-last-modified": { gitLastModified: () => new Date(0) },
  });
  const publicPages = new Set(sitemap.default().map(({ url }) => new URL(url).pathname));
  const appRoot = path.join(webRoot, "src/app");
  const publicRoot = path.join(webRoot, "public");
  const isFile = (file) => fs.existsSync(file) && fs.statSync(file).isFile();

  function publicDestination(href, sourcePath) {
    let url;
    try {
      url = new URL(href, `https://phm.dev${sourcePath}`);
    } catch {
      return false;
    }
    if (url.origin !== "https://phm.dev") return true;
    const pathname = url.pathname.replace(/\/$/, "") || "/";
    const doc = /^\/docs\/([^/]+)(\/markdown)?$/.exec(pathname);
    if (doc && catalog.some(({ slug }) => slug === doc[1])) {
      return (doc[2] || publicPages.has(pathname)) &&
        isFile(path.join(appRoot, "docs/[slug]", doc[2] ? "markdown/route.ts" : "page.tsx"));
    }
    const useCase = /^\/secrets\/use-cases\/([^/]+)$/.exec(pathname);
    if (useCase) {
      return publicPages.has(pathname) &&
        useCases.SECRET_USE_CASES.some(({ slug }) => slug === useCase[1]) &&
        isFile(path.join(appRoot, "secrets/use-cases/[slug]/page.tsx"));
    }
    if (publicPages.has(pathname)) return isFile(path.join(appRoot, pathname, "page.tsx"));
    if (pathname === "/docs/manifest.json") return isFile(path.join(appRoot, "docs/manifest.json/route.ts"));
    return isFile(path.join(publicRoot, pathname));
  }

  assert.ok(publicDestination("https://phm.dev/docs/getting-started?source=hub#install", "/docs"));
  assert.ok(publicDestination("getting-started", "/docs/codex"));
  assert.ok(publicDestination("#section", "/docs/codex"));
  assert.ok(publicDestination("https://example.com/missing", "/docs"));
  assert.equal(publicDestination("https://phm.dev/docs/missing", "/docs"), false);
  assert.equal(publicDestination("/docs/missing/markdown", "/docs"), false);
  assert.equal(publicDestination("/dashboard", "/docs"), false);
  assert.equal(publicDestination("/secrets/use-cases/missing", "/docs"), false);

  const empty = () => null;
  const Link = ({ href, children, ...props }) => React.createElement("a", { href, ...props }, children);
  const { default: DocsPage } = loadComponent("src/app/docs/page.tsx", {
    "next/link": Link,
    "@/components/landing/Nav": { Nav: empty },
    "@/components/landing/SiteFooter": { SiteFooter: empty },
    "@/components/landing/CopyButton": { CopyButton: empty },
    "@/components/docs/AskDocumentation": { AskDocumentation: empty },
    "@/components/landing/SecretUseCases": loadComponent("src/components/landing/SecretUseCases.tsx", {
      "next/link": Link,
      "@/lib/secret-use-cases": useCases,
    }),
    "@/lib/workbench-release": { WORKBENCH_RELEASE: null },
    "@/lib/public-release": { PUBLIC_RELEASE_TAG: "test" },
  });
  const { MarkdownDocument } = loadComponent("src/components/docs/MarkdownDocument.tsx", {
    "@/lib/public-docs": docs,
  });
  const pages = [{ source: "docs hub", path: "/docs", element: React.createElement(DocsPage) }];
  for (const { slug, file } of catalog) {
    pages.push({
      source: file,
      path: `/docs/${slug}`,
      element: React.createElement(MarkdownDocument, { markdown: docs.getPublicDoc(slug).markdown, sourceFile: file }),
    });
  }
  let checked = 0;
  for (const page of pages) {
    const document = new JSDOM(renderToStaticMarkup(page.element)).window.document;
    for (const link of document.querySelectorAll("a[href]")) {
      const href = link.getAttribute("href");
      assert.ok(publicDestination(href, page.path), `${page.source} links to missing or non-public ${href}`);
      if (new URL(href, `https://phm.dev${page.path}`).origin === "https://phm.dev") checked++;
    }
  }
  assert.ok(checked > catalog.length, "documentation must contain local links to check");
});

test("embedded Workbench guides retain build-bound source links", () => {
  const revision = "a".repeat(40);
  const { docs } = loadDocs(catalog, revision);
  for (const entry of catalog.filter(({ slug }) => slug === "workbench" || slug.startsWith("workbench-"))) {
    assert.equal(docs.getPublicDoc(entry.slug).sourceUrl, `https://github.com/ashlrai/phantom-secrets/blob/${revision}/docs/${entry.file}`);
  }
  assert.equal(loadDocs(catalog, "invalid").docs.getPublicDoc("workbench").sourceUrl, "https://phm.dev/docs/workbench/markdown");
});
