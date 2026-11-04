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

// With an explicit temporary install parent (one that does not exist yet and
// whose TMPDIR points elsewhere), the staging directory must be created
// beneath that selected parent, be private, and be gone after a good install.
// A mktemp shim records what the real mktemp returned and the mode it had.
test('repository installer creates its staging directory beneath the selected install parent', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-explicit-parent-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const home = join(root, 'home');
  const otherTmp = join(root, 'other-tmp');
  const shims = join(root, 'shims');
  const parent = join(root, 'chosen', 'parent');
  const install = join(parent, 'bin');
  const log = join(root, 'mktemp.log');
  for (const dir of [fixture, payload, home, otherTmp, shims]) mkdirSync(dir, { recursive: true });
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

  const realMktemp = execFileSync('/usr/bin/which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
out="$("${realMktemp}" "$@")" || exit $?
printf '%s\\n' "$out" >> "$PHANTOM_TEST_MKTEMP_LOG"
for arg do
  case "$arg" in
    *.install.XXXXXX)
      (ls -ld "$out" | cut -c1-10) >> "$PHANTOM_TEST_MKTEMP_LOG"
      ;;
  esac
done
printf '%s\\n' "$out"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);

  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS']) delete env[name];
  const result = spawnSync('/bin/bash', [fileURLToPath(new URL('install.sh', import.meta.url))], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      TMPDIR: otherTmp,
      PATH: `${shims}:${install}:${env.PATH}`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_MKTEMP_LOG: log,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);

  const lines = readFileSync(log, 'utf8').split('\n').filter(Boolean);
  const staged = lines[0];
  assert.equal(dirname(staged), parent, 'staging directory is a direct child of the selected parent');
  assert.match(basename(staged), /^\.bin\.install\.[A-Za-z0-9]{6}$/);
  assert.equal(lines[1], 'drwx------', 'staging directory is private to the owner');
  assert.ok(existsSync(join(install, 'phantom')), 'binaries are installed in the selected parent');
  assert.equal(existsSync(staged), false, 'staging directory is removed after install');
  assert.deepEqual(readdirSync(parent), ['bin'], 'only the installed bin remains in the parent');
  assert.deepEqual(readdirSync(otherTmp), [], 'TMPDIR is never used for staging');
});
