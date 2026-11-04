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

const installers = {
  repository: fileURLToPath(new URL('install.sh', import.meta.url)),
  public: fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url)),
};

// Builds an offline release fixture plus a mktemp shim that records its argv,
// so a test can prove where the installer asked for its staging directory.
function setup(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-spaced-parent-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const home = join(root, 'home');
  const shims = join(root, 'shims');
  for (const dir of [fixture, payload, home, shims]) mkdirSync(dir);
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
  return { root, fixture, home, shims, mktempLog };
}

function run({ fixture, home, shims }, installer, install, extra = {}) {
  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
  return spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      // The install dir is already on PATH, so no shell rc file is touched.
      PATH: `${shims}:${install}:${env.PATH}`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
      ...extra,
    },
  });
}

const stagingTemplates = (log) => readFileSync(log, 'utf8').split('\n')
  .filter((line) => line.startsWith('-d '));

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer: staging is requested under the resolved, newly created spaced parent`, (t) => {
    const ctx = setup(t);
    // The spaced parent is reached through a symlink and does not exist yet:
    // the installer must create it and stage under its physical path.
    const real = join(ctx.root, 'real root');
    mkdirSync(real);
    const link = join(ctx.root, 'link root');
    symlinkSync(real, link);
    const install = join(link, 'new parent', 'bin');
    const result = run(ctx, installer, install);
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);

    const physicalParent = join(real, 'new parent');
    assert.deepEqual(
      stagingTemplates(ctx.mktempLog),
      [`-d ${join(physicalParent, '.bin.install.XXXXXX')}`],
      'staging template must be one path under the resolved spaced parent',
    );
    assert.ok(existsSync(join(physicalParent, 'bin', 'phantom')));
    assert.ok(existsSync(join(physicalParent, 'bin', 'phantom-mcp')));
    assert.deepEqual(readdirSync(physicalParent), ['bin'], 'no staging, backup, or lock left behind');
  });

  test(`${name} installer: a failed install in a spaced parent rolls back and removes its staging`, (t) => {
    const ctx = setup(t);
    const parent = join(ctx.root, 'parent with spaces');
    const install = join(parent, 'bin');
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
    const result = run(ctx, installer, install, { PHANTOM_TEST_FAIL_AFTER_PROMOTION: '1' });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, 'the injected post-promotion fault must fail the install');

    assert.deepEqual(
      stagingTemplates(ctx.mktempLog),
      [`-d ${join(parent, '.bin.install.XXXXXX')}`],
      'staging was created directly under the spaced parent',
    );
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
    assert.equal(existsSync(join(install, 'phantom')), false, 'the failed candidate is not live');
    assert.deepEqual(readdirSync(parent), ['bin'], 'staging, backup, and lock siblings are removed');
  });
}
