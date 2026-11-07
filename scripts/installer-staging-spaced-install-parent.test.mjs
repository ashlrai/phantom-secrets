import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installers = {
  repository: fileURLToPath(new URL('install.sh', import.meta.url)),
  public: fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url)),
};

// Builds a stubbed release fixture plus recording shims. The fixture carries a
// deliberately wrong checksum, so the installer stops right after it created
// and populated its staging directory — the deterministic seam that proves
// where staging landed on hosts that refuse to run stub binaries named
// `phantom`. The mktemp shim records every -d argv (NUL-delimited so a
// word-split template shows up as extra fields), each created staging path,
// and the mode the directory had at creation; the sha256 shims record the path
// inside the staging tree that the installer hashed before it died.
function setup(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-spaced-install-parent-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const home = join(root, 'home');
  const shims = join(root, 'shims');
  for (const dir of [fixture, payload, home, shims]) mkdirSync(dir);
  writeFileSync(join(payload, 'phantom'), 'x');
  writeFileSync(join(payload, 'phantom-mcp'), 'x');
  const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
  const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  writeFileSync(join(fixture, `${archive}.sha256`), `${'0'.repeat(64)}  ${archive}\n`);
  const mktempLog = join(root, 'mktemp.log');
  const createdLog = join(root, 'created.log');
  const hashLog = join(root, 'hashed-paths');
  const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
created="$(${JSON.stringify(realMktemp)} "$@")" || exit $?
if [ "$1" = "-d" ]; then
  printf '%s\\0' "$@" >> ${JSON.stringify(mktempLog)}
  printf '%s\\n' "$created" >> ${JSON.stringify(createdLog)}
  printf '%s\\n' "$(ls -ld "$created" | cut -c1-10)" >> ${JSON.stringify(createdLog)}
fi
printf '%s\\n' "$created"
`);
  for (const tool of ['sha256sum', 'shasum']) {
    writeFileSync(join(shims, tool), `#!/usr/bin/env node
const { createHash } = require('node:crypto');
const { appendFileSync, readFileSync } = require('node:fs');
const target = process.argv.at(-1);
appendFileSync(${JSON.stringify(hashLog)}, target + '\\n');
const digest = createHash('sha256').update(readFileSync(target)).digest('hex');
process.stdout.write(digest + '  ' + target + '\\n');
`);
  }
  for (const shim of readdirSync(shims)) chmodSync(join(shims, shim), 0o755);
  return { root, fixture, home, shims, mktempLog, createdLog, hashLog, archive };
}

function run({ fixture, home, shims }, installer, install, extra = {}) {
  const env = { ...process.env };
  for (const name of ['PHANTOM_REPO', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS', 'TMPDIR']) delete env[name];
  return spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      ...env,
      HOME: home,
      SHELL: '/bin/bash',
      PATH: `${shims}:${env.PATH}`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
      PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture,
      PHANTOM_TAG: 'v1.2.3',
      ...extra,
    },
  });
}

// NUL delimiters preserve argument boundaries even when the template has spaces.
const stagingArguments = (log) => readFileSync(log, 'utf8').split('\0').slice(0, -1);

// created.log pairs each staging path with the permission bits ls reported.
const createdStages = (log) => {
  const lines = readFileSync(log, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length % 2, 0, 'every created staging path must report its mode');
  const pairs = [];
  for (let i = 0; i < lines.length; i += 2) pairs.push({ path: lines[i], mode: lines[i + 1] });
  return pairs;
};

// The stub's wrong checksum fails the install after the download was staged
// and hashed, so reaching that error proves the staging tree existed and was
// populated under the exact parent; the exit trap must then remove it.
function assertStagedUnderExactParent({ mktempLog, createdLog, hashLog, archive }, parent) {
  assert.deepEqual(
    stagingArguments(mktempLog),
    ['-d', join(parent, '.bin.install.XXXXXX')],
    'the staging template must reach mktemp as one path under the exact spaced parent',
  );
  const created = createdStages(createdLog);
  assert.equal(created.length, 1, 'exactly one staging directory was created');
  const [stage] = created;
  assert.equal(dirname(stage.path), parent, 'staging is a direct child of the exact spaced parent');
  assert.match(basename(stage.path), /^\.bin\.install\.[^/]+$/);
  assert.equal(stage.mode, 'drwx------', 'staging is private to the owner');
  assert.equal(
    readFileSync(hashLog, 'utf8').trim(),
    join(stage.path, 'download', archive),
    'the staged download was hashed inside the staging tree under the exact parent',
  );
  assert.equal(existsSync(stage.path), false, 'the staging directory is removed before exit');
}

for (const [name, installer] of Object.entries(installers)) {
  test(`${name} installer stages and cleans beneath a spaced install parent it creates`, (t) => {
    const ctx = setup(t);
    // Neither the spaced parent nor the install dir exists yet: the installer
    // must mkdir -p the parent, resolve it with pwd -P, and stage under that
    // exact path — never under TMPDIR, which points elsewhere.
    const parent = join(ctx.root, 'chosen parent');
    const install = join(parent, 'bin');
    const otherTmp = join(ctx.root, 'other tmp');
    mkdirSync(otherTmp);
    const result = run(ctx, installer, install, { TMPDIR: otherTmp });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, 'the stub checksum must fail the install');
    assert.match(result.stderr, /SHA-256 mismatch/, 'the installer got past staging and download');

    assertStagedUnderExactParent(ctx, parent);
    assert.deepEqual(readdirSync(parent), [], 'no staging, backup, or lock left in the spaced parent');
    assert.deepEqual(readdirSync(otherTmp), [], 'TMPDIR is never used for staging');
    assert.equal(existsSync(join(ctx.root, 'chosen')), false, 'nothing was created at a word-split prefix');
    assert.deepEqual(readdirSync(ctx.home), [], 'HOME gains no files');
  });

  test(`${name} installer stages and cleans beneath an existing spaced parent, leaving the install untouched`, (t) => {
    const ctx = setup(t);
    // The spaced parent and a previous install already exist: the staged
    // failure must not disturb the install, and the parent must be left with
    // only the previous bin.
    const parent = join(ctx.root, 'existing parent');
    const install = join(parent, 'bin');
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'previous');
    const result = run(ctx, installer, install);
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, 'the stub checksum must fail the install');
    assert.match(result.stderr, /SHA-256 mismatch/, 'the installer got past staging and download');

    assertStagedUnderExactParent(ctx, parent);
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'previous');
    assert.deepEqual(readdirSync(parent), ['bin'], 'no staging, backup, or lock left in the spaced parent');
  });
}
