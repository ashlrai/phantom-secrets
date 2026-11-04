import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installer = fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url));

// Builds an offline release fixture plus a mktemp shim that records its argv,
// so a test can prove where the installer asked for its staging directory.
function setup(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-unicode-parent-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const shims = join(root, 'shims');
  for (const dir of [fixture, payload, shims]) mkdirSync(dir);
  for (const name of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, name), `#!/bin/sh\necho "${name} 1.2.3"\n`);
    chmodSync(join(payload, name), 0o755);
  }
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);
  const mktempLog = join(root, 'mktemp.log');
  const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
printf '%s\\n' "$*" >> ${JSON.stringify(mktempLog)}
exec ${JSON.stringify(realMktemp)} "$@"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  return { root, fixture, shims, mktempLog };
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
