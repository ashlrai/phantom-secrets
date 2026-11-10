import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installer = fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url));
const version = '1.2.3';
const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
const archive = `phantom-${arch}-${os}.tar.gz`;

function executable(product, reported = version) {
  return `#!/bin/sh\n[ "$1" = --version ] || exit 2\necho '${product} ${reported}'\n`;
}

function makeRelease(root, options = {}) {
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  mkdirSync(fixture);
  mkdirSync(payload);
  const members = ['phantom', 'phantom-mcp'];
  if (options.linkPhantom) {
    // The symlink keeps the exact two-member name listing but fails the
    // regular-file member check.
    writeFileSync(join(payload, 'target'), executable('phantom'));
    symlinkSync('target', join(payload, 'phantom'));
  } else {
    writeFileSync(join(payload, 'phantom'), executable('phantom'));
    chmodSync(join(payload, 'phantom'), 0o755);
  }
  writeFileSync(join(payload, 'phantom-mcp'), executable('phantom-mcp'));
  chmodSync(join(payload, 'phantom-mcp'), 0o755);
  if (options.extraMember) {
    writeFileSync(join(payload, 'extra'), 'unexpected');
    members.push('extra');
  }
  const archivePath = join(fixture, archive);
  execFileSync('tar', ['-czf', archivePath, '-C', payload, ...members]);
  if (options.missingSidecar) return fixture;
  const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  writeFileSync(`${archivePath}.sha256`, options.sidecar ?? `${digest}  ${archive}\n`);
  return fixture;
}

// Run the public installer offline against a local release fixture. The
// staging directory always lands beside the install directory, so after a
// failure the parent's entry list proves every staging, backup, and lock
// sibling was removed.
function run(t, options = {}) {
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-public-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  const parent = dirname(install);
  mkdirSync(home, { recursive: true });
  mkdirSync(install, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'preserve-me');
  const fixture = options.emptyFixture ? join(root, 'fixture') : makeRelease(root, options);
  if (options.emptyFixture) mkdirSync(fixture);
  const env = { ...process.env };
  for (const name of [
    'PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS',
  ]) delete env[name];
  // A tool shim fails one exact installer call and delegates everything else
  // to the real tool, so the failure lands at the named seam only.
  if (options.failTarOp || options.failChmod) {
    const shims = join(root, 'shims');
    mkdirSync(shims);
    if (options.failTarOp) {
      const realTar = execFileSync('which', ['tar'], { encoding: 'utf8' }).trim();
      writeFileSync(join(shims, 'tar'), `#!/bin/sh
if [ "$1" = ${JSON.stringify(options.failTarOp)} ]; then
  printf 'tar: injected failure\\n' >&2
  exit 42
fi
exec ${JSON.stringify(realTar)} "$@"
`);
      chmodSync(join(shims, 'tar'), 0o755);
    }
    if (options.failChmod) {
      const realChmod = execFileSync('which', ['chmod'], { encoding: 'utf8' }).trim();
      writeFileSync(join(shims, 'chmod'), `#!/bin/sh
if [ "$1" = '755' ]; then
  printf 'chmod: injected failure\\n' >&2
  exit 42
fi
exec ${JSON.stringify(realChmod)} "$@"
`);
      chmodSync(join(shims, 'chmod'), 0o755);
    }
    env.PATH = `${shims}:${env.PATH}`;
  }
  const result = spawnSync('/bin/bash', [options.installer ?? installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: options.tag ?? `v${version}`,
    },
  });
  return { root, home, install, parent, result };
}

// Every assertion a clean failure owes: nonzero exit, the expected error, the
// previous install untouched, no staging/backup/lock siblings left beside the
// install directory, and nothing written into HOME.
function assertCleanFailure({ root, install, parent, result }, error) {
  assert.ifError(result.error);
  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, error);
  assert.deepEqual(readdirSync(install), ['old-install']);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(parent), ['bin'], 'staging and lock are removed');
  assert.deepEqual(readdirSync(join(root, 'home')), [], 'HOME must contain no temporary files');
}

// The staging directory is created before the release tag is validated, so
// even this early validation failure must still remove the empty stage.
test('public installer leaves no staging directory when the release tag is malformed', (t) => {
  assertCleanFailure(run(t, { tag: 'not a tag' }), /release tag is not strict semantic version syntax/);
});

// Each failure below happens after the staging tree exists but before any
// archive member is extracted, while the staging download directory is at
// most partly populated.
for (const { name, options, error } of [
  {
    name: 'a missing release archive',
    options: { emptyFixture: true },
    error: /offline installer fixture is missing or not a regular file/,
  },
  {
    name: 'a missing checksum sidecar',
    options: { missingSidecar: true },
    error: /offline installer fixture is missing or not a regular file/,
  },
  {
    name: 'an oversized checksum sidecar',
    options: { sidecar: `${'0'.repeat(2048)}\n` },
    error: /offline installer fixture exceeded its size limit/,
  },
  {
    name: 'a multi-line checksum sidecar',
    options: { sidecar: `${'0'.repeat(64)}  ${archive}\nextra\n` },
    error: /checksum sidecar must contain exactly one line/,
  },
  {
    name: 'a checksum sidecar with invalid syntax',
    options: { sidecar: 'not-a-checksum\n' },
    error: /checksum sidecar has invalid syntax/,
  },
  {
    name: 'a checksum sidecar naming another archive',
    options: { sidecar: `${'0'.repeat(64)}  wrong.tar.gz\n` },
    error: /checksum sidecar names an unexpected archive/,
  },
  {
    name: 'a SHA-256 mismatch',
    options: { sidecar: `${'0'.repeat(64)}  ${archive}\n` },
    error: /SHA-256 mismatch/,
  },
  {
    name: 'an extra archive member',
    options: { extraMember: true },
    error: /release archive must contain exactly phantom and phantom-mcp/,
  },
  {
    name: 'a linked archive member',
    options: { linkPhantom: true },
    error: /release archive members must be regular files/,
  },
  {
    name: 'a tar list failure',
    options: { failTarOp: '-tzf' },
    error: /could not list release archive/,
  },
  {
    name: 'a tar member-type inspection failure',
    options: { failTarOp: '-tvzf' },
    error: /could not inspect release archive member types/,
  },
]) {
  test(`public installer leaves no staging directory after ${name}`, (t) => {
    assertCleanFailure(run(t, options), error);
  });
}

// The last failure before binary verification is an implicit set -e exit
// rather than a die() message: the shimmed chmod fails only the 755 call that
// secures the extracted candidates, after both members were extracted into
// the staging candidate directory.
test('public installer removes the populated staging tree when securing candidates fails', (t) => {
  assertCleanFailure(run(t, { failChmod: true }), /chmod: injected failure/);
});

test('repository installer removes the populated staging tree when securing candidates fails', (t) => {
  const repositoryInstaller = fileURLToPath(new URL('install.sh', import.meta.url));
  assertCleanFailure(run(t, { failChmod: true, installer: repositoryInstaller }), /chmod: injected failure/);
});
