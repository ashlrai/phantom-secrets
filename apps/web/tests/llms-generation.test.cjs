const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const test = require("node:test");

const web = path.resolve(__dirname, "..");
const root = path.resolve(web, "../..");
const generator = import(pathToFileURL(path.join(web, "scripts/generate-agent-references.mjs")).href);
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("heading extraction excludes code comments and respects closing fence length", async () => {
  const { extractHeadings } = await generator;
  const input = "# Guide\n## Install `phantom`\n````sh\n# A comment\n```\n## Still code\n````\n~~~\n# Also code\n~~~\n## Install `phantom`\n";
  assert.deepEqual(extractHeadings(input), [
    { level: 1, title: "Guide", anchor: "guide" },
    { level: 2, title: "Install phantom", anchor: "install-phantom" },
    { level: 2, title: "Install phantom", anchor: "install-phantom-2" },
  ]);
  assert.equal(extractHeadings(input, true)[2].anchor, "install-phantom-1");
});

test("generated references are deterministic, current, mirrored, and free of em dashes", async () => {
  const { generateReferences } = await generator;
  const first = generateReferences();
  assert.deepEqual(first, generateReferences());
  assert.equal(first.size, 5);
  for (const [file, expected] of first) {
    assert.equal(read(file), expected, `${file}: regenerate agent references`);
    assert.doesNotMatch(expected, /\u2014/, file);
    assert.doesNotMatch(expected, /\{\{WORKSPACE_CRATE_COUNT\}\}/, file);
  }
  for (const filename of ["llms.txt", "llms-full.txt"]) {
    assert.equal(first.get(`apps/web/public/${filename}`), first.get(`docs/${filename}`));
  }
});

test("LLM references parse into one title, README source prose, and every canonical guide", async () => {
  const { extractHeadings, generateReferences } = await generator;
  const catalog = JSON.parse(read("apps/web/docs-catalog.json"));
  const readmeSummary = /^Phantom replaces project secrets[^\n]+/m.exec(read("README.md"))[0];
  for (const [file, body] of generateReferences()) {
    if (!file.endsWith(".txt")) continue;
    assert.equal(extractHeadings(body).filter(({ level }) => level === 1).length, 1, file);
    assert.ok(body.includes(readmeSummary), `${file}: README product explanation`);
    const links = [...body.matchAll(/\[[^\]\n]+\]\((https:\/\/[^)\s]+)\)/g)].map(([, href]) => new URL(href));
    assert.ok(links.length > catalog.length, `${file}: parsed section index`);
    assert.ok(links.some((url) => url.href === "https://phm.dev/secrets/capabilities"), `${file}: capabilities and installation`);
    for (const { slug, file: source } of catalog) {
      const base = `https://phm.dev/docs/${slug}`;
      assert.ok(links.some((url) => url.href === base), `${file}: canonical ${slug}`);
      for (const { level, anchor } of extractHeadings(read(`docs/${source}`))) {
        if (level > 1) assert.ok(links.some((url) => url.href === `${base}#${anchor}`), `${file}: ${slug}#${anchor}`);
      }
      assert.ok(!body.includes(`https://github.com/ashlrai/phantom-secrets/blob/main/docs/${source}`), `${file}: use the rendered guide canonical`);
    }
    assert.match(body, /2026-09-29, Homebrew published `v0\.7\.8`/);
    assert.match(body, /2026-10-06 source record below reports Homebrew `v0\.7\.9`/);
    assert.match(body, /generation does not reverify releases/);
    assert.match(body, /In the pinned `v0\.7\.9` release, Gemini CLI is status-only/);
    assert.match(body, /Newer source includes a writer/);
  }
});

test("full guidance distinguishes inspection, mutation, and unsupported custom routes", async () => {
  const { generateReferences } = await generator;
  const body = generateReferences().get("apps/web/public/llms-full.txt");
  assert.match(body, /custom-service fields below document compatibility\/design syntax only/);
  assert.match(body, /agentic `phantom exec` refuses\ncustom services before launch/);
  assert.match(body, /setup --apply: mutates local files/);
  assert.doesNotMatch(body, /Read-only readiness workflow for AI coding agents/);
  assert.match(body, /phantom_doctor\n  Run repository-local health checks without opening or provisioning a vault/);
  assert.doesNotMatch(body, /Checks: [^\n]*vault access|Health check: [^\n]*vault access/);
});

test("generated section anchors resolve in the actual public Markdown renderer", async () => {
  const { extractHeadings } = await generator;
  const ts = require("typescript");
  const React = require("react");
  const { renderToStaticMarkup } = require("react-dom/server");
  const catalog = JSON.parse(read("apps/web/docs-catalog.json"));
  const compiled = ts.transpileModule(read("apps/web/src/components/docs/MarkdownDocument.tsx"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  new Function("exports", "require", compiled)(exports, (name) => {
    if (name === "@/lib/public-docs") return {
      publicDocHrefForMarkdownFile: (file) => {
        const doc = catalog.find((entry) => entry.file === file);
        return doc ? `/docs/${doc.slug}` : undefined;
      },
    };
    return require(name);
  });
  for (const { file } of catalog) {
    const markdown = read(`docs/${file}`);
    const html = renderToStaticMarkup(React.createElement(exports.MarkdownDocument, { markdown, sourceFile: file }));
    const ids = new Set([...html.matchAll(/<h[1-6] id="([^"]+)"/g)].map(([, id]) => id));
    for (const { anchor } of extractHeadings(markdown)) assert.ok(ids.has(anchor), `${file}#${anchor}`);
  }
});
