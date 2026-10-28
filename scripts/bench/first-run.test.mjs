import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = resolve(dirname(fileURLToPath(import.meta.url)), 'first-run.sh');
const executables = new Map();
const locate = name => {
  if (executables.has(name)) return executables.get(name);
  const found = spawnSync('/bin/bash', ['-c', 'type -P "$1"', 'bash', name], { encoding: 'utf8' });
  assert.equal(found.status, 0, `missing test prerequisite: ${name}`);
  const path = found.stdout.trim();
  executables.set(name, path);
  return path;
};
const sha256 = data => createHash('sha256').update(data).digest('hex');

// Download/runtime doubles keep tests offline. Real tar, checksum utilities,
// child Python, and scorecard statistics still execute on the host platform.
function fixture(options, run) {
  const root = mkdtempSync(join(tmpdir(), 'phantom-scorecard-test-'));
  const bin = join(root, 'tools');
  const archives = join(root, 'archives');
  const temporary = join(root, 'tmp');
  const home = join(root, 'home');
  const trace = join(root, 'trace.jsonl');
  const summary = join(root, 'summary.md');
  for (const path of [bin, archives, temporary, home]) mkdirSync(path);
  function executable(name, code) {
    const path = join(bin, name);
    writeFileSync(path, `#!${process.execPath}\n${code}\n`, { mode: 0o700 });
    return path;
  }
  try {
    for (const name of ['bash', 'env', 'mkdir', 'mktemp', 'seq', 'rm', 'od', 'tr', 'cut', 'cat', 'tar', 'shasum', 'true']) {
      symlinkSync(locate(name), join(bin, name));
    }
    if (options.randomFailure) executable('head', `
if (process.argv[3] === '32') process.exit(1);
const r = require('node:child_process').spawnSync(${JSON.stringify(locate('head'))}, process.argv.slice(2), { stdio: 'inherit' });
process.exit(r.status ?? 1);`);
    else if (options.emptyPassphrase) executable('head', `
if (process.argv[3] === '32') process.exit(0);
const r = require('node:child_process').spawnSync(${JSON.stringify(locate('head'))}, process.argv.slice(2), { stdio: 'inherit' });
process.exit(r.status ?? 1);`);
    else symlinkSync(locate('head'), join(bin, 'head'));
    const ambient = join(root, 'ambient-executed');
    executable('phantom', `require('node:fs').writeFileSync(${JSON.stringify(ambient)}, 'unexpected'); process.exit(0);`);
    if (!options.bsdHash) symlinkSync(locate('sha256sum'), join(bin, 'sha256sum'));
    if (options.scanError) executable('grep', 'process.exit(2);');
    else symlinkSync(locate('grep'), join(bin, 'grep'));
    executable('uname', `console.log(process.argv[2] === '-s' ? ${JSON.stringify(options.os ?? 'Darwin')} : ${JSON.stringify(options.arch ?? 'arm64')});`);
    // Avoid inspecting the caller's git config/hooks during benchmark tests.
    executable('git', 'process.exit(process.argv.slice(2).join(" ") === "init -q" ? 0 : 1);');
    const python = locate('python3');
    const clock = join(root, 'clock');
    const samples = options.samples ?? [1];
    const times = Array.from({ length: 400 }, (_, count) => {
      const run = Math.floor(count / 4);
      return run * 100 + [0, samples[run % samples.length], 20, 20.01][count % 4];
    });
    // The timer double uses shell builtins so the harness does not launch an
    // extra Node VM for every timestamp. Child hashing and reporting still
    // exec the real Python interpreter with unchanged arguments and stdin.
    writeFileSync(join(bin, 'python3'), `#!/bin/bash
if [ "$1" = '-c' ] && [[ "$2" == *time.monotonic* ]]; then
  count=0
  if [ -f '${clock}' ]; then read -r count < '${clock}'; fi
  times=(${times.join(' ')})
  printf '%s\\n' "\${times[$count]}"
  printf '%s\\n' "$((count + 1))" > '${clock}'
else
  exec '${python}' "$@"
fi
`, { mode: 0o700 });
    const runtime = join(archives, 'phantom');
    writeFileSync(runtime, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const args = process.argv.slice(2);
const passphrase = process.env.PHANTOM_VAULT_PASSPHRASE ?? '';
const isolated = /^[0-9a-f]{64}$/.test(passphrase) && process.env.HOME.includes('/run') && !process.env.XDG_DATA_HOME && !process.env.PHANTOM_AUDIT && !process.env.OPENAI_API_KEY && !process.env.PHANTOM_REQUIRE_KEYCHAIN;
if (!isolated) { console.error('RUNTIME_DIAGNOSTIC_MUST_STAY_PRIVATE'); process.exit(4); }
fs.appendFileSync(${JSON.stringify(trace)}, JSON.stringify({ args: args.slice(0, 2), home: process.env.HOME, passphraseHash: crypto.createHash('sha256').update(passphrase).digest('hex') }) + '\\n');
const vault = path.join(process.env.HOME, 'fixture-vault');
if (args[0] === 'init') {
  if (${Boolean(options.failInit)}) { console.error('RUNTIME_DIAGNOSTIC_MUST_STAY_PRIVATE'); process.exit(5); }
} else if (args[0] === 'add') {
  if (${Boolean(options.failAdd)}) { console.error('RUNTIME_DIAGNOSTIC_MUST_STAY_PRIVATE'); process.exit(5); }
  fs.writeFileSync(vault, fs.readFileSync(0));
  if (${Boolean(options.projectLeak)}) fs.copyFileSync(vault, '.env');
} else if (args[0] === 'exec') {
  if (args[2] === 'true' && ${Boolean(options.failWarm)}) { console.error('RUNTIME_DIAGNOSTIC_MUST_STAY_PRIVATE'); process.exit(5); }
  const value = ${Boolean(options.childLeak)} ? fs.readFileSync(vault, 'utf8') : 'phm_' + crypto.randomBytes(24).toString('hex');
  const child = cp.spawnSync(args[2], args.slice(3), { env: { ...process.env, FAKE_API_KEY: value }, stdio: 'inherit' });
  if (args[2] === 'python3' && ${Boolean(options.malformed)}) fs.writeFileSync('../child.out', 'phm invalid-digest');
  process.exit(child.status ?? 1);
} else process.exit(6);
`, { mode: 0o700 });
    writeFileSync(join(archives, 'placeholder'), 'no runtime');
    const packedArchive = join(root, 'runtime.tar.gz');
    const packed = spawnSync(locate('tar'), ['-czf', packedArchive, '-C', archives, options.missingRuntime ? 'placeholder' : 'phantom']);
    assert.equal(packed.status, 0);
    for (const target of ['aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu']) {
      const asset = `phantom-${target}.tar.gz`;
      copyFileSync(packedArchive, join(archives, asset));
      writeFileSync(join(archives, `${asset}.sha256`), `${options.badChecksum ? '0'.repeat(64) : sha256(readFileSync(join(archives, asset)))}  ${asset}\n`);
    }
    executable('curl', `
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
if (${Boolean(options.downloadFailure)}) process.exit(22);
const url = args[args.length - 1];
if (!/^https:\\/\\/github\\.com\\/ashlrai\\/phantom-secrets\\/releases\\/download\\/v0\\.7\\.9\\/phantom-[a-z0-9_-]+\\.tar\\.gz(?:\\.sha256)?$/.test(url)) process.exit(7);
fs.copyFileSync(path.join(${JSON.stringify(archives)}, path.basename(url)), args[args.indexOf('-o') + 1]);
`);
    const execute = (args = ['1'], env = {}) => spawnSync(locate('bash'), [script, ...args], {
      encoding: 'utf8', timeout: 30_000,
      env: { PATH: bin, HOME: home, TMPDIR: temporary, GITHUB_STEP_SUMMARY: summary,
        XDG_DATA_HOME: '/must-not-use', PHANTOM_AUDIT: '1', OPENAI_API_KEY: 'synthetic-inherited-marker', ...env },
    });
    return run({ execute, trace, summary, temporary, root });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

for (const [os, arch, target, bsdHash] of [
  ['Darwin', 'arm64', 'aarch64-apple-darwin', true],
  ['Darwin', 'x86_64', 'x86_64-apple-darwin', true],
  ['Linux', 'x86_64', 'x86_64-unknown-linux-gnu', false],
  ['Linux', 'aarch64', 'aarch64-unknown-linux-gnu', false],
]) test(`complete offline first-run flow: ${target}`, () => fixture({ os, arch, bsdHash }, ({ execute, trace, summary, temporary }) => {
  const result = execute(['2']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(target));
  assert.match(result.stdout, /Runs: 2/);
  assert.match(result.stdout, /p95 <= 5 s: pass/);
  assert.match(result.stdout, /ephemeral encrypted-file vault/);
  assert.equal(result.stdout, readFileSync(summary, 'utf8') + '\n');
  const calls = readFileSync(trace, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length, 8);
  assert.equal(new Set(calls.slice(0, 4).map(c => c.passphraseHash)).size, 1);
  assert.notEqual(calls[0].passphraseHash, calls[4].passphraseHash);
  for (const call of calls) assert.equal(existsSync(call.home), false);
  assert.deepEqual(readdirSync(temporary), []);
}));

for (const args of [['0'], ['-1'], ['abc'], ['101'], ['1', 'extra'], ['1;echo unsafe']]) {
  test(`invalid run count rejected before execution: ${JSON.stringify(args)}`, () => fixture({}, ({ execute, trace, temporary }) => {
    const result = execute(args);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /usage:/);
    assert.equal(existsSync(trace), false);
    assert.deepEqual(readdirSync(temporary), []);
  }));
}
for (const policy of ['1', 'true', 'TrUe']) test(`keychain-only policy ${policy} is respected`, () => fixture({}, ({ execute, trace }) => {
  const result = execute(['1'], { PHANTOM_REQUIRE_KEYCHAIN: policy });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PHANTOM_REQUIRE_KEYCHAIN is set/);
  assert.equal(existsSync(trace), false);
}));

test('release tag cannot inject URLs or report text', () => fixture({}, ({ execute, trace }) => {
  const result = execute(['1'], { PHANTOM_VERSION: 'v0.7.9/../../other\nspoof' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must be a release tag/);
  assert.equal(existsSync(trace), false);
}));

test('unsupported platform fails before runtime execution', () => fixture({ os: 'Unknown' }, ({ execute, trace }) => {
  const result = execute();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unsupported platform/);
  assert.equal(existsSync(trace), false);
}));

for (const [mode, message] of [
  ['badChecksum', /download failed/], ['failInit', /init failed/],
  ['downloadFailure', /download failed/], ['missingRuntime', /init failed/],
  ['emptyPassphrase', /could not generate an ephemeral vault passphrase/],
  ['failAdd', /add failed/], ['failWarm', /warm exec failed/],
  ['childLeak', /wrapped exec check failed/], ['malformed', /wrapped exec check failed/],
  ['projectLeak', /project scan found/], ['scanError', /project scan found/],
]) test(`${mode} fails closed, cleans state, and withholds runtime evidence`, () => fixture({ [mode]: true }, ({ execute, temporary, root }) => {
  const result = execute();
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, message);
  assert.doesNotMatch(result.stdout + result.stderr, /RUNTIME_DIAGNOSTIC_MUST_STAY_PRIVATE|phm_[a-f0-9]|fake_[a-f0-9]/);
  assert.deepEqual(readdirSync(temporary), []);
  assert.equal(existsSync(join(root, 'ambient-executed')), false);
}));

test('random-source failure cannot fall back to keychain', () => fixture({ randomFailure: true }, ({ execute, trace, temporary }) => {
  const result = execute();
  assert.equal(result.status, 1);
  assert.equal(existsSync(trace), false);
  assert.deepEqual(readdirSync(temporary), []);
}));

test('p95 above five seconds remains a failing result with a summary', () => fixture({ samples: [1, 1, 6] }, ({ execute, summary }) => {
  const result = execute(['3']);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stdout, /p95 <= 5 s: FAIL/);
  assert.match(result.stdout, /\| 1\.000 s \| 6\.000 s/);
  assert.equal(result.stdout, readFileSync(summary, 'utf8') + '\n');
}));

test('p95 exactly five seconds meets the unchanged threshold', () => fixture({ samples: [5] }, ({ execute }) => {
  const result = execute();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /p95 <= 5 s: pass/);
}));
