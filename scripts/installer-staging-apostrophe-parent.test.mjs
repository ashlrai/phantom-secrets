import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installers = {
  repository: fileURLToPath(new URL('install.sh', import.meta.url)),
  public: fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url)),
};

// PHANTOM_INSTALL_DIR rejects shell-significant characters, but HOME is
// unrestricted, so the default install dir can sit beneath a parent such as
// "/o'brien". Staging and cleanup must work there unchanged.
for (const [name, installer] of Object.entries(installers)) test(`${name} installer stages, installs, and cleans up beneath a parent containing an apostrophe`, (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-apostrophe-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const shims = join(root, 'shims');
  const home = join(root, "o'brien's home");
  const parent = join(home, '.phantom-secrets');
  const install = join(parent, 'bin');
  const log = join(root, 'mktemp.log');
  for (const dir of [fixture, payload, home, shims]) mkdirSync(dir, { recursive: true });
  for (const bin of ['phantom', 'phantom-mcp']) {
    writeFileSync(join(payload, bin), `#!/bin/sh\necho "${bin} 1.2.3"\n`);
    chmodSync(join(payload, bin), 0o755);
  }
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);

  // Record each staging path the real mktemp returns.
  const realMktemp = execFileSync('/usr/bin/which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
out="$("${realMktemp}" "$@")" || exit $?
for arg do
  case "$arg" in
    *.install.XXXXXX) printf '%s\\n' "$out" >> "$PHANTOM_TEST_MKTEMP_LOG" ;;
  esac
done
printf '%s\\n' "$out"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);

  const env = { ...process.env };
  for (const key of ['PHANTOM_REPO', 'PHANTOM_INSTALL_DIR', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS', 'TMPDIR']) delete env[key];
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      PATH: `${shims}:${env.PATH}`,
      PHANTOM_TEST_MKTEMP_LOG: log,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);

  const staged = readFileSync(log, 'utf8').split('\n').filter(Boolean);
  assert.equal(staged.length, 1, 'exactly one staging directory is created');
  assert.ok(staged[0].includes("'"), 'staging path contains the apostrophe');
  assert.equal(dirname(staged[0]), parent, 'staging directory is a direct child of the apostrophe parent');
  assert.match(basename(staged[0]), /^\.bin\.install\.[A-Za-z0-9]{6}$/);
  assert.equal(existsSync(staged[0]), false, 'staging directory is removed after install');
  assert.ok(existsSync(join(install, 'phantom')), 'binaries are installed beneath the apostrophe parent');
  assert.ok(existsSync(join(install, 'phantom-mcp')));
  assert.deepEqual(readdirSync(parent).filter((entry) => entry !== 'bin'), [],
    'no staging, backup, or lock leftovers remain beside the install');
});
