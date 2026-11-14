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
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installer = fileURLToPath(new URL('install.sh', import.meta.url));

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Every shim keeps a line-per-argument argv record so a word-split path shows
// up as extra lines, then delegates to the real tool. Only the staging
// template is exercised here; PATH-update mktemp calls land in the same log.
function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  const tar = execFileSync('which', ['tar'], { encoding: 'utf8' }).trim();
  const recorder = (real, log) => `#!/bin/sh
{
  printf -- '--call--\\n'
  printf '%s\\n' "$@"
} >> ${JSON.stringify(log)}
exec ${JSON.stringify(real)} "$@"
`;
  writeFileSync(join(shims, 'mktemp'), recorder(mktemp, '$PHANTOM_TEST_MKTEMP_CALLS'));
  writeFileSync(join(shims, 'tar'), recorder(tar, '$PHANTOM_TEST_TAR_CALLS'));
  writeFileSync(join(shims, 'curl'), `#!/bin/sh
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CURL_LOG"
exit 22
`);
  writeFileSync(join(shims, 'uname'), `#!/bin/sh
case "$1" in -s) printf '%s\\n' "$PHANTOM_TEST_UNAME_S" ;; -m) printf '%s\\n' "$PHANTOM_TEST_UNAME_M" ;; *) exit 2 ;; esac
`);
  for (const tool of ['sha256sum', 'shasum']) {
    writeFileSync(join(shims, tool), `#!/usr/bin/env node
const { createHash } = require('node:crypto');
const { appendFileSync, readFileSync } = require('node:fs');
const target = process.argv.at(-1);
appendFileSync(process.env.PHANTOM_TEST_HASH_LOG, target + '\\n');
const digest = createHash('sha256').update(readFileSync(target)).digest('hex');
process.stdout.write(digest + '  ' + target + '\\n');
`);
  }
  for (const name of readdirSync(shims)) chmodSync(join(shims, name), 0o755);
  return shims;
}

function callsLog(file) {
  return existsSync(file)
    ? readFileSync(file, 'utf8').split('--call--\n').slice(1)
      .map((entry) => entry.split('\n').filter(Boolean))
    : [];
}

// A successful offline install through a staging parent containing spaces:
// the private staging template must reach mktemp as exactly one argv item,
// and the exit trap must leave only the promoted install behind.
test('repository installer stages through a spaced parent as one argument and cleans up', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-spaces-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const home = join(root, 'home');
  const parent = join(root, 'install parent with spaces');
  const install = join(parent, 'bin');
  for (const dir of [fixture, payload, home, install]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(install, 'old-install'), 'preserve-me');
  const version = '1.2.3';
  const invocations = join(root, 'invocations.log');
  for (const product of ['phantom', 'phantom-mcp']) {
    const binary = join(payload, product);
    writeFileSync(binary, `#!/bin/sh
[ "$1" = --version ] || exit 2
[ -z "\${PHANTOM_TEST_RECORD_INVOCATIONS:-}" ] || printf '%s\\n' "$0" >> "$PHANTOM_TEST_RECORD_INVOCATIONS"
echo '${product} ${version}'
`);
    chmodSync(binary, 0o755);
  }
  const archive = 'phantom-x86_64-apple-darwin.tar.gz';
  const archivePath = join(fixture, archive);
  execFileSync('tar', ['-czf', archivePath, '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  writeFileSync(`${archivePath}.sha256`, `${digest}  ${archive}\n`);

  const shims = makeShims(root);
  const mktempCalls = join(root, 'mktemp-calls');
  const tarCalls = join(root, 'tar-calls');
  const curlLog = join(root, 'curl.log');
  const hashLog = join(root, 'hashed-paths');
  const env = { ...process.env };
  for (const name of [
    'PHANTOM_REPO', 'PHANTOM_TAG', 'PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES',
    'PHANTOM_TEST_LOCAL_RELEASE_DIR', 'PHANTOM_TEST_FAIL_AFTER_PROMOTION',
    'PHANTOM_INSTALL_LOCK_WAIT_SECONDS', 'PHANTOM_INSTALL_LOCK_STALE_SECONDS',
    'PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS',
  ]) delete env[name];
  const result = spawnSync('/bin/bash', [installer], {
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
      PHANTOM_TAG: `v${version}`,
      PHANTOM_TEST_MKTEMP_CALLS: mktempCalls,
      PHANTOM_TEST_TAR_CALLS: tarCalls,
      PHANTOM_TEST_CURL_LOG: curlLog,
      PHANTOM_TEST_HASH_LOG: hashLog,
      PHANTOM_TEST_RECORD_INVOCATIONS: invocations,
      PHANTOM_TEST_UNAME_S: 'Darwin',
      PHANTOM_TEST_UNAME_M: 'x86_64',
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(`installed to ${escapeRegExp(install)}`));
  assert.equal(existsSync(curlLog), false, 'the offline fixture must bypass curl entirely');

  const dirCalls = callsLog(mktempCalls).filter((call) => call[0] === '-d');
  assert.equal(dirCalls.length, 1, 'exactly one mktemp -d call creates the staging directory');
  assert.deepEqual(
    dirCalls[0],
    ['-d', join(parent, '.bin.install.XXXXXX')],
    'the spaced staging template must arrive as exactly one argument',
  );

  const staged = readFileSync(invocations, 'utf8').trim().split('\n')
    .filter((path) => path.includes('.bin.install.'));
  assert.deepEqual(staged.map((path) => basename(path)).sort(), ['phantom', 'phantom-mcp']);
  const stageRoots = new Set(staged.map((path) => dirname(dirname(path))));
  assert.equal(stageRoots.size, 1);
  const [stageRoot] = stageRoots;
  assert.equal(dirname(stageRoot), parent, 'staging lives inside the supplied spaced parent');
  assert.match(basename(stageRoot), /^\.bin\.install\.[^/]+$/);

  const hashed = readFileSync(hashLog, 'utf8').trim().split('\n');
  assert.equal(hashed.length, 1, 'the staged download is hashed exactly once');
  assert.equal(dirname(hashed[0]), join(stageRoot, 'download'));

  const extract = callsLog(tarCalls).find((call) => call.includes('-xzf'));
  assert.ok(extract, 'the release archive must be extracted once');
  assert.equal(
    extract[extract.indexOf('-C') + 1],
    join(stageRoot, 'candidate'),
    'extraction targets the spaced staging candidate as one argument',
  );

  assert.equal(existsSync(stageRoot), false, 'the staging directory must be removed');
  assert.ok(existsSync(join(install, 'phantom')));
  assert.ok(existsSync(join(install, 'phantom-mcp')));
  assert.deepEqual(
    readdirSync(parent),
    ['bin'],
    'staging, backup, and lock siblings in the spaced parent must be removed',
  );
  assert.match(
    readFileSync(join(home, '.bashrc'), 'utf8'),
    new RegExp(`export PATH="${escapeRegExp(install)}:\\$PATH"`),
  );
});
