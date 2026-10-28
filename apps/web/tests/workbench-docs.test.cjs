const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');
const ts = require('typescript');
const markdownLoader = require('../scripts/public-doc-markdown-loader.cjs');
const root = path.resolve(__dirname, '..');
const repository = path.resolve(root, '..', '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const catalog = JSON.parse(read('docs-catalog.json'));
const workbench = catalog.filter(({ slug }) => slug === 'workbench' || slug.startsWith('workbench-'));
const assistant = import(pathToFileURL(path.join(root, 'src/lib/documentation-assistant.mjs')).href);
function loadTs(file, overrides = {}) {
  const compiled = ts.transpileModule(read(file), { compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true } }).outputText;
  const exports = {};
  new Function('require', 'exports', '__dirname', compiled)((id) => {
    if (id === 'server-only') return {};
    if (Object.hasOwn(overrides, id)) return overrides[id];
    if (id === '../../docs-catalog.json') return catalog;
    if (id.endsWith('.md')) {
      const resourcePath = path.resolve(root, path.dirname(file), id);
      const javascript = markdownLoader.call({ resourcePath, addDependency() {} }, fs.readFileSync(resourcePath));
      return JSON.parse(javascript.slice('export default '.length, -1));
    }
    return require(id);
  }, exports, path.dirname(path.join(root, file)));
  return exports;
}
const docs = loadTs('src/lib/public-docs.ts');
const raw = loadTs('src/app/docs/[slug]/markdown/route.ts', { '@/lib/public-docs': docs });

test('workbench articles have immutable evidence and resolvable internal links', () => {
  assert.equal(workbench.length, 6);
  for (const { file } of workbench) {
    const body = fs.readFileSync(path.join(repository, 'docs', file), 'utf8');
    assert.match(body, /https:\/\/github.com\/ashlrai\/phantom\/blob\/37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05\//);
    for (const [, target] of body.matchAll(/\]\((workbench[^)]+\.md)\)/g)) assert.ok(catalog.some(({ file }) => file === target));
    assert.doesNotMatch(body, /phm authority resident start\s*\n|phm authority grant\s*\n/);
  }
  assert.match(fs.readFileSync(path.join(repository, 'docs/workbench-agents.md'), 'utf8'), /must not imitate Touch ID/);
});

test('every immutable upstream target belongs to the verified pinned source tree', () => {
  const evidence = JSON.parse(read('tests/fixtures/workbench-upstream-source.json'));
  assert.equal(evidence.sourceSha, '37900cb15b0b07f4f6e81b2eb7f1e99d02d13c05');
  const files = new Set(evidence.files.map(({ path, gitBlob }) => {
    assert.match(gitBlob, /^[a-f0-9]{40}$/);
    return path;
  }));
  for (const body of [
    ...workbench.map(({ file }) => fs.readFileSync(path.join(repository, 'docs', file), 'utf8')),
    read('public/workbench/llms-full.txt'),
  ]) {
    for (const [, revision, target] of body.matchAll(/https:\/\/github\.com\/ashlrai\/phantom\/blob\/([^/]+)\/([^\s)]+)/g)) {
      assert.equal(revision, evidence.sourceSha);
      assert.ok(files.has(target.split('#')[0]), `unverified upstream target: ${target}`);
    }
  }
});

test('workbench source links use the observed build instead of an unpublished main path', () => {
  const previous = process.env.PHANTOM_BUILD_SOURCE_REVISION;
  try {
    process.env.PHANTOM_BUILD_SOURCE_REVISION = 'a'.repeat(40);
    assert.equal(docs.getPublicDoc('workbench-agents').sourceUrl,
      `https://github.com/ashlrai/phantom-secrets/blob/${'a'.repeat(40)}/docs/workbench-agents.md`);
    assert.equal(docs.getPublicDoc('codex').sourceUrl,
      'https://github.com/ashlrai/phantom-secrets/blob/main/docs/codex.md');
    process.env.PHANTOM_BUILD_SOURCE_REVISION = 'unidentified';
    assert.equal(docs.getPublicDoc('workbench-agents').sourceUrl,
      'https://phm.dev/docs/workbench-agents/markdown');
  } finally {
    if (previous === undefined) delete process.env.PHANTOM_BUILD_SOURCE_REVISION;
    else process.env.PHANTOM_BUILD_SOURCE_REVISION = previous;
  }
});

test('raw handlers return exact allowed Markdown and reject arbitrary files', async () => {
  for (const { slug, file } of catalog) {
    const response = await raw.GET(new Request(`https://phm.dev/docs/${slug}/markdown`), { params: Promise.resolve({ slug }) });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Content-Type'), 'text/markdown; charset=utf-8');
    assert.equal(response.headers.get('Link'), `<https://phm.dev/docs/${slug}>; rel="canonical"`);
    assert.equal(await response.text(), fs.readFileSync(path.join(repository, 'docs', file), 'utf8'));
  }
  for (const slug of ['unknown', '../SECURITY', '%2e%2e%2fSECURITY', 'workbench/../../SECURITY']) {
    assert.equal((await raw.GET(new Request('https://phm.dev/docs/unknown/markdown'), { params: Promise.resolve({ slug }) })).status, 404);
  }
});

test('manifest preserves separate products and exact guide fetch targets', async () => {
  const release = JSON.parse(read('src/lib/workbench-release.json'));
  const manifest = loadTs('src/app/docs/manifest.json/route.ts', { '@/lib/public-docs': docs, '@/lib/workbench-release': { WORKBENCH_RELEASE: release } });
  const result = await manifest.GET().json();
  assert.equal(result.schemaVersion, 1);
  assert.deepEqual(result.publishedWorkbenchRelease, release);
  assert.equal(result.documents.length, catalog.length);
  assert.equal(result.documents.filter(({ product }) => product === 'secrets').length, 13);
  for (const doc of result.documents) {
    assert.equal(doc.url, `https://phm.dev/docs/${doc.slug}`);
    assert.equal(doc.markdownUrl, `${doc.url}/markdown`);
  }
  assert.match(result.runtimeReadiness, /does not establish live readiness/);
  for (const file of ['llms.txt', 'llms-full.txt']) {
    const body = read(`public/workbench/${file}`);
    for (const { slug } of workbench) assert.ok(body.includes(`https://phm.dev/docs/${slug}`));
  }
});

test('AI chooser shares encoded public context and rejects private or executable targets', async () => {
  const { DOCUMENTATION_ASSISTANTS, documentationAssistantLink, documentationPrompt } = await assistant;
  const hosts = new Set(['chatgpt.com', 'claude.ai', 'www.perplexity.ai', 'gemini.google.com', 'grok.com']);
  for (const { id } of DOCUMENTATION_ASSISTANTS) {
    const link = documentationAssistantLink(id, '/docs/workbench-agents');
    const url = new URL(link.href);
    assert.equal(url.protocol, 'https:');
    assert.ok(hosts.has(url.host));
    assert.match(link.prompt, /Read https:\/\/phm.dev\/docs\/workbench-agents/);
    assert.doesNotMatch(link.prompt, /token=|password=|127\.0\.0\.1|localhost/);
    assert.equal(url.searchParams.get('q'), link.attemptsPrefill ? link.prompt : null);
  }
  for (const bad of ['/dashboard', '//evil.example', '/docs?token=private', '/docs/../dashboard', 'javascript:alert(1)', 'https://evil.example/docs', '/docs/workbench#private', '/docs/workbench/markdown']) assert.throws(() => documentationPrompt(bad));
  assert.throws(() => documentationAssistantLink('foreign-provider', '/docs'));
  const component = read('src/components/docs/AskDocumentation.tsx');
  assert.match(component, /Sign-in or provider changes may require/);
  assert.match(component, /copy it manually/);
  assert.match(component, /rel="noopener noreferrer"/);
  assert.doesNotMatch(component, /fetch\(|localStorage|window.location|document.cookie/);
});
