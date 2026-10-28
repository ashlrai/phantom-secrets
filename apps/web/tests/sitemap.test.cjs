const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const webDir = path.resolve(__dirname, "..");
const modules = new Map();
function load(relativePath) {
  const filename = path.resolve(webDir, relativePath);
  if (modules.has(filename)) return modules.get(filename).exports;
  const compiled = ts.transpileModule(fs.readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText;
  const module = { exports: {} };
  modules.set(filename, module);
  const originalRequire = createRequire(filename);
  const requireModule = (id) => {
    if (id === "server-only") return {};
    if (id.startsWith("@/")) return load(`src/${id.slice(2)}.ts`);
    return originalRequire(id);
  };
  new Function("require", "exports", "module", compiled)(requireModule, module.exports, module);
  return module.exports;
}

const { default: sitemap, dynamic } = load("src/app/sitemap.ts");
const { PUBLIC_DOCS } = load("src/lib/public-docs.ts");
const { SECRET_USE_CASES } = load("src/lib/secret-use-cases.ts");

function entries() {
  const previous = process.cwd();
  try {
    process.chdir(webDir);
    return sitemap();
  } finally {
    process.chdir(previous);
  }
}

test("sitemap enumerates every canonical HTML page exactly once and no private or machine resources", () => {
  const result = entries();
  const expected = ["/", "/secrets", "/docs", "/pricing", "/enterprise", "/government", "/security",
    ...PUBLIC_DOCS.map(({ slug }) => `/docs/${slug}`),
    ...SECRET_USE_CASES.map(({ slug }) => `/secrets/use-cases/${slug}`),
  ].map((pathname) => new URL(pathname, "https://phm.dev").href).sort();
  assert.deepEqual(result.map(({ url }) => url).sort(), expected);
  assert.equal(new Set(result.map(({ url }) => url)).size, result.length);
  for (const { url, lastModified } of result) {
    const parsed = new URL(url);
    assert.equal(parsed.origin, "https://phm.dev");
    assert.equal(parsed.search, "");
    assert.equal(parsed.hash, "");
    assert.doesNotMatch(parsed.pathname, /(?:^\/(?:api|dashboard|device|integrations)(?:\/|$)|\.(?:json|txt|xml)$)/);
    assert.doesNotMatch(url, /[<>&"\s]/);
    if (lastModified !== undefined) {
      assert.match(lastModified, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/);
      assert.ok(Number.isFinite(Date.parse(lastModified)));
    }
  }
  assert.equal(dynamic, "force-static", "history must be read during the build, not in serverless requests");
});

test("sitemap dates reflect page and shared content history instead of catalog review dates", () => {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
  const shared = ["src/app/layout.tsx", "src/components/landing", "src/app/globals.css"];
  const cases = [
    ["https://phm.dev/secrets", ["src/app/secrets/page.tsx", ...shared]],
    ...PUBLIC_DOCS.map(({ slug, file }) => [
      `https://phm.dev/docs/${slug}`,
      [`../../docs/${file}`, "src/app/docs/[slug]/page.tsx", "src/components/docs/MarkdownDocument.tsx", ...shared],
    ]),
  ];
  const result = new Map(entries().map((entry) => [entry.url, entry]));
  const shallow = execFileSync("git", ["rev-parse", "--is-shallow-repository"], {
    cwd: webDir, env: environment, encoding: "utf8",
  }).trim() === "true";
  for (const [url, files] of cases) {
    const expected = execFileSync("git", ["log", "-1", "--format=%cI", "--", ...files], {
      cwd: webDir, env: environment, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    assert.equal(result.get(url).lastModified, shallow ? undefined : expected || undefined, url);
  }
});

test("Next serializes a valid sitemap namespace with one absolute loc and optional ISO lastmod per URL", () => {
  const { resolveSitemap } = require("next/dist/build/webpack/loaders/metadata/resolve-route-data.js");
  const result = entries();
  const xml = resolveSitemap(result);
  const prefix = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  assert.ok(xml.startsWith(prefix));
  assert.ok(xml.endsWith("</urlset>\n"));
  const body = xml.slice(prefix.length, -"</urlset>\n".length);
  const blocks = [...body.matchAll(/<url>\n<loc>(https:\/\/phm\.dev\/[^<>\s]*)<\/loc>\n(?:<lastmod>([^<>]+)<\/lastmod>\n)?<\/url>\n/g)];
  assert.equal(blocks.map(([block]) => block).join(""), body, "no invalid, nested or unexpected XML elements");
  assert.equal(blocks.length, result.length);
  assert.deepEqual(blocks.map(([, url, lastModified]) => ({ url, lastModified })), result);
  assert.ok(Buffer.byteLength(xml) < 50 * 1024 * 1024);
  assert.ok(result.length <= 50_000);
});
