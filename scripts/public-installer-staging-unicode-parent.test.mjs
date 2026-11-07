import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createStagingFixture, installHashRecorders } from './lib/installer-staging-fixture.mjs';

const installer = fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url));

// Builds an offline release fixture plus a mktemp shim that records its argv,
// so a test can prove where the installer asked for its staging directory.
function setup(t) {
  const { root, fixture, shims, archive } = createStagingFixture(t, 'phantom-staging-unicode-parent-');
  const mktempLog = join(root, 'mktemp.log');
  const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(mktempLog)}
exec ${JSON.stringify(realMktemp)} "$@"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  // Recording which path the installer hashes proves the staging tree was
  // populated at failure time, so cleanup assertions cannot pass vacuously.
  const hashLog = installHashRecorders(root, shims);
  return { root, fixture, shims, mktempLog, hashLog, archive };
}

function run({ fixture, shims }, { home, pathPrefix, installDir }) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.startsWith('PHANTOM_')) delete env[name];
  return spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      // The resolved install dir is already on PATH, so no rc file is touched.
      PATH: `${pathPrefix}:${shims}:${env.PATH}`,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
      ...(installDir ? { PHANTOM_INSTALL_DIR: installDir } : {}),
    },
  });
}

const stagingTemplates = (log) => readFileSync(log, 'utf8').split('\n')
  .filter((line) => line.startsWith('-d '));

test('staging is requested under the resolved Unicode parent and removed after success', (t) => {
  const ctx = setup(t);
  const home = join(ctx.root, 'home');
  mkdirSync(home);
  // PHANTOM_INSTALL_DIR is restricted to ASCII, so the Unicode parent is
  // reached through a symlink: pwd -P resolves it to the physical parent
  // before the lock, stage, and backup paths are derived.
  const parent = join(ctx.root, 'ünïcödé påréñt');
  mkdirSync(parent);
  const resolvedParent = realpathSync(parent);
  const link = join(ctx.root, 'ascii-link');
  symlinkSync(parent, link);
  const result = run(ctx, {
    home,
    pathPrefix: join(resolvedParent, 'bin'),
    installDir: join(link, 'bin'),
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /installed to /);

  assert.deepEqual(
    stagingTemplates(ctx.mktempLog),
    [`-d ${join(resolvedParent, '.bin.install.XXXXXX')}`],
    'staging template must be one path under the resolved Unicode parent',
  );
  assert.ok(existsSync(join(resolvedParent, 'bin', 'phantom')));
  assert.ok(existsSync(join(resolvedParent, 'bin', 'phantom-mcp')));
  assert.deepEqual(readdirSync(resolvedParent), ['bin'], 'no staging, backup, or lock left behind');
});

test('the default install dir stages and cleans up under a Unicode HOME', (t) => {
  const ctx = setup(t);
  const home = join(ctx.root, 'hømê-家');
  mkdirSync(home);
  const resolvedHome = realpathSync(home);
  const resolvedParent = join(resolvedHome, '.phantom-secrets');
  const result = run(ctx, {
    home,
    pathPrefix: join(resolvedParent, 'bin'),
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /installed to /);

  assert.deepEqual(
    stagingTemplates(ctx.mktempLog),
    [`-d ${join(resolvedParent, '.bin.install.XXXXXX')}`],
    'staging template must be one path under the Unicode install parent',
  );
  assert.ok(existsSync(join(resolvedParent, 'bin', 'phantom')));
  assert.ok(existsSync(join(resolvedParent, 'bin', 'phantom-mcp')));
  assert.deepEqual(readdirSync(resolvedParent), ['bin'], 'no staging, backup, or lock left behind');
  assert.deepEqual(readdirSync(resolvedHome), ['.phantom-secrets'], 'HOME holds no stray files');
});

test('a failed install under a Unicode parent removes its staging tree', (t) => {
  const ctx = setup(t);
  const home = join(ctx.root, 'home');
  mkdirSync(home);
  const parent = join(ctx.root, 'ünïcödé-失敗');
  mkdirSync(parent);
  const resolvedParent = realpathSync(parent);
  const link = join(ctx.root, 'fail-link');
  symlinkSync(parent, link);
  mkdirSync(join(resolvedParent, 'bin'));
  writeFileSync(join(resolvedParent, 'bin', 'old-install'), 'preserve-me');
  // The mismatched sidecar stops the installer after it has downloaded into
  // and hashed inside the staging tree, but before any candidate binary is
  // executed — so this failure stays reproducible where fixture binaries
  // cannot run.
  writeFileSync(
    join(ctx.fixture, `${ctx.archive}.sha256`),
    `${'0'.repeat(64)}  ${ctx.archive}\n`,
  );

  const result = run(ctx, {
    home,
    pathPrefix: join(resolvedParent, 'bin'),
    installDir: join(link, 'bin'),
  });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHA-256 mismatch/);

  assert.deepEqual(
    stagingTemplates(ctx.mktempLog),
    [`-d ${join(resolvedParent, '.bin.install.XXXXXX')}`],
    'staging template must be one path under the resolved Unicode parent',
  );
  const hashed = readFileSync(ctx.hashLog, 'utf8').trim().split('\n');
  assert.equal(hashed.length, 1, 'the staged download is hashed exactly once');
  const [staged] = hashed;
  assert.equal(basename(staged), ctx.archive);
  assert.equal(basename(dirname(staged)), 'download');
  const stageRoot = dirname(dirname(staged));
  assert.equal(dirname(stageRoot), resolvedParent);
  assert.match(basename(stageRoot), /^\.bin\.install\.[^/]+$/);
  assert.equal(existsSync(stageRoot), false, 'staging directory must be removed');
  assert.equal(readFileSync(join(resolvedParent, 'bin', 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(resolvedParent), ['bin'], 'no staging, backup, or lock left behind');
});
