import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createStagingFixture, installHashRecorders } from './lib/installer-staging-fixture.mjs';

const installers = {
  repository: fileURLToPath(new URL('install.sh', import.meta.url)),
  public: fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url)),
};

const LOG_FILES = ['mktemp.log', 'created.log', 'hashed-paths'];

// Builds an offline release fixture plus a mktemp shim that records its argv
// one element per line (so a word-split template shows up as extra arguments)
// and each created -d path with its mode. sha256 shims record which path the
// installer hashed, proving the staging tree was populated before it died.
// Every test stops the installer at a pre-execution seam — a checksum or
// archive-listing failure — so nothing here needs a host able to run stub
// binaries named `phantom`.
function setup(t) {
  const { root, fixture, shims, archive } = createStagingFixture(t, 'phantom-staging-spaced-home-');
  const mktempLog = join(root, 'mktemp.log');
  const createdLog = join(root, 'created.log');
  const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
{
  printf -- '--call--\\n'
  printf '%s\\n' "$@"
} >> ${JSON.stringify(mktempLog)}
created="$(${JSON.stringify(realMktemp)} "$@")" || exit $?
if [ "$1" = "-d" ]; then
  printf '%s\\n' "$created" >> ${JSON.stringify(createdLog)}
  (ls -ld "$created" | cut -c1-10) >> ${JSON.stringify(createdLog)}
fi
printf '%s\\n' "$created"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  const hashLog = installHashRecorders(root, shims);
  return { root, fixture, shims, mktempLog, createdLog, hashLog, archive };
}

// The installer runs with cwd inside the test root, so a word-split relative
// fragment would surface as a new root entry; assertNoStrays catches it.
function run({ root, fixture, shims }, installer, { home, pathPrefix, installDir } = {}) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.startsWith('PHANTOM_')) delete env[name];
  return spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    cwd: root,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      PATH: [pathPrefix, shims, env.PATH].filter(Boolean).join(':'),
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
      ...(installDir ? { PHANTOM_INSTALL_DIR: installDir } : {}),
    },
  });
}

const mktempCalls = (log) => readFileSync(log, 'utf8').split('--call--\n').slice(1)
  .map((entry) => entry.split('\n').filter(Boolean));

const stagingCalls = (log) => mktempCalls(log).filter((call) => call[0] === '-d');

// created.log pairs each staging path with the permission bits ls reported.
const createdStages = (log) => {
  const lines = readFileSync(log, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length % 2, 0, 'every created staging path must report its mode');
  const pairs = [];
  for (let i = 0; i < lines.length; i += 2) pairs.push({ path: lines[i], mode: lines[i + 1] });
  return pairs;
};

const hashedPaths = (log) => readFileSync(log, 'utf8').split('\n').filter(Boolean);

// Nothing the installer touched may appear under the test root except the
// paths the test itself created (allowed) and the shim logs.
const assertNoStrays = (root, before, allowed = []) => {
  const permitted = new Set([...LOG_FILES, ...allowed]);
  const stray = readdirSync(root).filter((name) => !before.has(name) && !permitted.has(name));
  assert.deepEqual(stray, [], 'word-splitting must not create stray paths in the root');
};

const corruptSidecar = (ctx) => writeFileSync(
  join(ctx.fixture, `${ctx.archive}.sha256`),
  `${'0'.repeat(64)}  ${ctx.archive}\n`,
);

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer stages beneath a spaced HOME parent as one path and removes the populated staging`, (t) => {
    const ctx = setup(t);
    // HOME is not governed by the install-dir override grammar, so a real
    // account directory may carry spaces into the default install parent.
    const home = join(ctx.root, 'user home');
    mkdirSync(home);
    const decoy = join(ctx.root, 'user');
    mkdirSync(decoy);
    const resolvedParent = join(realpathSync(home), '.phantom-secrets');
    // The mismatched sidecar stops the installer after it has downloaded into
    // and hashed inside the staging tree, so cleanup cannot pass vacuously.
    corruptSidecar(ctx);
    const before = new Set(readdirSync(ctx.root));

    const result = run(ctx, installer, {
      home,
      pathPrefix: join(resolvedParent, 'bin'),
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA-256 mismatch/);

    assert.deepEqual(
      stagingCalls(ctx.mktempLog),
      [['-d', join(resolvedParent, '.bin.install.XXXXXX')]],
      'the complete spaced parent template must arrive as exactly one argument',
    );
    const stages = createdStages(ctx.createdLog);
    assert.equal(stages.length, 1, 'exactly one staging directory was created');
    assert.equal(dirname(stages[0].path), resolvedParent);
    assert.equal(stages[0].mode, 'drwx------', 'staging directory is private to the owner');
    assert.deepEqual(hashedPaths(ctx.hashLog), [join(stages[0].path, 'download', ctx.archive)]);
    assert.equal(existsSync(stages[0].path), false, 'the populated staging tree was removed');
    assert.deepEqual(readdirSync(resolvedParent), [], 'no staging or lock left in the spaced parent');
    assert.deepEqual(readdirSync(home), ['.phantom-secrets'], 'HOME holds no stray files');
    assert.deepEqual(readdirSync(decoy), [], 'nothing was written at the split prefix');
    assertNoStrays(ctx.root, before);
  });

  test(`${name} installer keeps an existing install and leaves no staging beneath a spaced HOME`, (t) => {
    const ctx = setup(t);
    const home = join(ctx.root, 'fail home');
    mkdirSync(home);
    const decoy = join(ctx.root, 'fail');
    mkdirSync(decoy);
    const resolvedParent = join(realpathSync(home), '.phantom-secrets');
    const install = join(resolvedParent, 'bin');
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    corruptSidecar(ctx);
    const before = new Set(readdirSync(ctx.root));

    const result = run(ctx, installer, {
      home,
      pathPrefix: install,
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA-256 mismatch/);

    assert.deepEqual(
      stagingCalls(ctx.mktempLog),
      [['-d', join(resolvedParent, '.bin.install.XXXXXX')]],
      'the complete spaced parent template must arrive as exactly one argument',
    );
    const stages = createdStages(ctx.createdLog);
    assert.equal(stages.length, 1, 'exactly one staging directory was created');
    assert.equal(dirname(stages[0].path), resolvedParent);
    assert.equal(stages[0].mode, 'drwx------', 'staging directory is private to the owner');
    assert.deepEqual(hashedPaths(ctx.hashLog), [join(stages[0].path, 'download', ctx.archive)]);
    assert.equal(existsSync(stages[0].path), false, 'the populated staging tree was removed');
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
    assert.deepEqual(readdirSync(resolvedParent), ['bin'], 'no staging, backup, or lock left behind');
    assert.deepEqual(readdirSync(decoy), [], 'nothing was written at the split prefix');
    assertNoStrays(ctx.root, before);
  });

  test(`${name} installer removes staging beneath a spaced HOME after an unreadable archive`, (t) => {
    const ctx = setup(t);
    const home = join(ctx.root, 'garbage home');
    mkdirSync(home);
    const decoy = join(ctx.root, 'garbage');
    mkdirSync(decoy);
    const resolvedParent = join(realpathSync(home), '.phantom-secrets');
    // A self-consistent sidecar over a non-gzip archive carries the installer
    // past checksum verification, so it dies listing the archive with both
    // downloads already sitting inside the staging tree.
    const garbage = join(ctx.fixture, ctx.archive);
    writeFileSync(garbage, 'not a gzip archive');
    const digest = createHash('sha256').update(readFileSync(garbage)).digest('hex');
    writeFileSync(`${garbage}.sha256`, `${digest}  ${ctx.archive}\n`);
    const before = new Set(readdirSync(ctx.root));

    const result = run(ctx, installer, {
      home,
      pathPrefix: join(resolvedParent, 'bin'),
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /could not list release archive/);

    assert.deepEqual(
      stagingCalls(ctx.mktempLog),
      [['-d', join(resolvedParent, '.bin.install.XXXXXX')]],
      'the complete spaced parent template must arrive as exactly one argument',
    );
    const stages = createdStages(ctx.createdLog);
    assert.equal(stages.length, 1, 'exactly one staging directory was created');
    assert.equal(dirname(stages[0].path), resolvedParent);
    assert.equal(stages[0].mode, 'drwx------', 'staging directory is private to the owner');
    assert.deepEqual(hashedPaths(ctx.hashLog), [join(stages[0].path, 'download', ctx.archive)]);
    assert.equal(existsSync(stages[0].path), false, 'the populated staging tree was removed');
    assert.deepEqual(readdirSync(resolvedParent), [], 'no staging or lock left in the spaced parent');
    assert.deepEqual(readdirSync(decoy), [], 'nothing was written at the split prefix');
    assertNoStrays(ctx.root, before);
  });

  test(`${name} installer uses the complete multi-component spaced parent and removes staging`, (t) => {
    const ctx = setup(t);
    const home = join(ctx.root, 'home');
    mkdirSync(home);
    // Spaces in two parent components: a template truncated at either space
    // would land outside the real parent or split fragments under the root.
    const parent = join(ctx.root, 'suite one', 'tools two');
    const install = join(parent, 'bin');
    for (const decoy of [join(ctx.root, 'suite'), join(ctx.root, 'suite one', 'tools')]) {
      mkdirSync(decoy, { recursive: true });
    }
    corruptSidecar(ctx);
    const before = new Set(readdirSync(ctx.root));

    const result = run(ctx, installer, {
      home,
      pathPrefix: install,
      installDir: install,
    });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SHA-256 mismatch/);

    assert.deepEqual(
      stagingCalls(ctx.mktempLog),
      [['-d', join(parent, '.bin.install.XXXXXX')]],
      'the complete two-component spaced parent must be one template argument',
    );
    const stages = createdStages(ctx.createdLog);
    assert.equal(stages.length, 1, 'exactly one staging directory was created');
    assert.equal(dirname(stages[0].path), parent);
    assert.equal(stages[0].mode, 'drwx------', 'staging directory is private to the owner');
    assert.deepEqual(hashedPaths(ctx.hashLog), [join(stages[0].path, 'download', ctx.archive)]);
    assert.equal(existsSync(stages[0].path), false, 'the populated staging tree was removed');
    assert.deepEqual(readdirSync(parent), [], 'the spaced parent holds no leftovers');
    assert.deepEqual(readdirSync(join(ctx.root, 'suite')), [], 'nothing was written at the first-word split');
    assert.deepEqual(
      readdirSync(join(ctx.root, 'suite one', 'tools')),
      [],
      'nothing was written at the second-word split',
    );
    assertNoStrays(ctx.root, before, ['suite one']);
  });
}
