import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const shellInstaller = join(repo, 'scripts', 'install.sh');
const psInstaller = join(repo, 'scripts', 'install.ps1');
const tag = 'v1.2.3';
const version = '1.2.3';

function executable(product, pathSensitive = false) {
  const output = pathSensitive
    ? `case "$0" in *.install.*) echo '${product} ${version}' ;; *) echo '${product} 9.9.9' ;; esac`
    : `echo '${product} ${version}'`;
  return `#!/bin/sh\n[ "$1" = --version ] || exit 2\n${output}\n`;
}

function makeArchive(root, target = 'x86_64-apple-darwin', options = {}) {
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  mkdirSync(fixture, { recursive: true });
  mkdirSync(payload, { recursive: true });
  const phantom = join(payload, 'phantom');
  const mcp = join(payload, 'phantom-mcp');
  if (options.symlink) {
    writeFileSync(join(payload, 'target'), executable('phantom'));
    symlinkSync('target', phantom);
  } else {
    writeFileSync(phantom, executable('phantom', options.pathSensitive));
    chmodSync(phantom, 0o755);
  }
  writeFileSync(mcp, executable('phantom-mcp', options.pathSensitive));
  chmodSync(mcp, 0o755);
  const members = ['phantom', 'phantom-mcp'];
  if (options.extra) {
    writeFileSync(join(payload, 'extra'), 'unexpected');
    members.push('extra');
  }
  const archiveName = `phantom-${target}.tar.gz`;
  const archive = join(fixture, archiveName);
  execFileSync('tar', ['-czf', archive, '-C', payload, ...members]);
  const digest = createHash('sha256').update(readFileSync(archive)).digest('hex');
  const sidecar = options.sidecar ?? `${digest}  ${archiveName}\n`;
  writeFileSync(`${archive}.sha256`, sidecar);
  return fixture;
}

function makeShims(root) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  const curl = join(shims, 'curl');
  writeFileSync(curl, `#!/bin/sh
if [ "$1" = --help ]; then echo ' --max-filesize '; exit 0; fi
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CURL_LOG"
out=''; url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    --write-out|--max-filesize|--max-redirs|--connect-timeout|--max-time|--proto|--proto-redir) shift 2 ;;
    --silent|--show-error|--fail|--location) shift ;;
    *) url="$1"; shift ;;
  esac
done
name="${'${url##*/}'}"
cp "$PHANTOM_TEST_FIXTURE_DIR/$name" "$out" || exit 22
printf '%s' "$url"
`);
  chmodSync(curl, 0o755);
  const uname = join(shims, 'uname');
  writeFileSync(uname, `#!/bin/sh
case "$1" in -s) printf '%s\\n' "$PHANTOM_TEST_UNAME_S" ;; -m) printf '%s\\n' "$PHANTOM_TEST_UNAME_M" ;; *) exit 2 ;; esac
`);
  chmodSync(uname, 0o755);
  return shims;
}

function runInstaller(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-test-'));
  const target = options.target ?? 'x86_64-apple-darwin';
  const fixture = makeArchive(root, target, options);
  const shims = makeShims(root);
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  mkdirSync(home);
  if (options.existing) {
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
  }
  const log = join(root, 'curl.log');
  const result = spawnSync('/bin/bash', [shellInstaller], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: home,
      SHELL: '/bin/bash',
      PATH: `${shims}:${process.env.PATH}`,
      PHANTOM_TAG: tag,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_FIXTURE_DIR: fixture,
      PHANTOM_TEST_CURL_LOG: log,
      PHANTOM_TEST_UNAME_S: options.unameS ?? 'Darwin',
      PHANTOM_TEST_UNAME_M: options.unameM ?? 'x86_64',
    },
  });
  return { root, install, log, result };
}

test('canonical installers exactly match the public mirrors', () => {
  assert.deepEqual(readFileSync(shellInstaller), readFileSync(join(repo, 'apps/web/public/install.sh')));
  assert.deepEqual(readFileSync(psInstaller), readFileSync(join(repo, 'apps/web/public/install.ps1')));
});

test('Unix installer uses bounded HTTPS downloads and promotes both exact binaries', () => {
  const { install, log, result, root } = runInstaller();
  assert.equal(result.status, 0, result.stderr);
  assert.match(readFileSync(join(install, 'phantom'), 'utf8'), /phantom 1\.2\.3/);
  assert.match(readFileSync(join(install, 'phantom-mcp'), 'utf8'), /phantom-mcp 1\.2\.3/);
  const curlLog = readFileSync(log, 'utf8');
  for (const option of ['--proto =https', '--proto-redir =https', '--max-redirs 3', '--connect-timeout 10', '--max-time 120', '--max-filesize']) {
    assert.match(curlLog, new RegExp(option.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.doesNotMatch(curlLog, /http:\/\//);
  assert.equal(readdirSync(dirname(install)).filter((name) => name.includes('.bin.install.')).length, 0);
});

test('Unix installer preserves the prior live install on malformed checksum', () => {
  const { install, result } = runInstaller({ existing: true, sidecar: `${'a'.repeat(64)}  wrong.tar.gz\nextra\n` });
  assert.notEqual(result.status, 0);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
});

test('Unix installer rejects extra and linked archive members without changing live state', () => {
  for (const options of [{ extra: true }, { symlink: true }]) {
    const { install, result } = runInstaller({ existing: true, ...options });
    assert.notEqual(result.status, 0);
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  }
});

test('Unix installer rolls back when final-path version validation fails', () => {
  const { install, result } = runInstaller({ existing: true, pathSensitive: true });
  assert.notEqual(result.status, 0);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.equal(readdirSync(install).length, 1);
});

test('Unix installer failure never creates a partial new live install', () => {
  const { install, result } = runInstaller({ sidecar: 'not-a-checksum\n' });
  assert.notEqual(result.status, 0);
  assert.throws(() => readdirSync(install));
});

test('installers retain the closed six-target mapping', () => {
  const powerShell = readFileSync(psInstaller, 'utf8');
  for (const mapping of [
    { unameS: 'Darwin', unameM: 'x86_64', target: 'x86_64-apple-darwin' },
    { unameS: 'Darwin', unameM: 'arm64', target: 'aarch64-apple-darwin' },
    { unameS: 'Linux', unameM: 'x86_64', target: 'x86_64-unknown-linux-gnu' },
    { unameS: 'Linux', unameM: 'aarch64', target: 'aarch64-unknown-linux-gnu' },
  ]) {
    const { result } = runInstaller(mapping);
    assert.equal(result.status, 0, `${mapping.target}: ${result.stderr}`);
    assert.match(result.stdout, new RegExp(`target: ${mapping.target}`));
  }
  assert.match(powerShell, /x86_64-pc-windows-msvc/);
  assert.match(powerShell, /aarch64-pc-windows-msvc/);
});

test('PowerShell installer has a strict offline-verifiable security contract', () => {
  const source = readFileSync(psInstaller, 'utf8');
  assert.doesNotMatch(source, /Unblock-File.*-ErrorAction\s+SilentlyContinue/);
  assert.match(source, /AllowAutoRedirect\s*=\s*\$false/);
  assert.match(source, /ResponseHeadersRead/);
  assert.match(source, /release archive must contain exactly phantom\.exe and phantom-mcp\.exe/);
  assert.match(source, /Assert-ExactVersion[\s\S]+phantom-mcp/);
  assert.match(source, /Move-Item[\s\S]+backupPath[\s\S]+failed-live/);
  assert.ok(source.indexOf('archive identity verified') < source.indexOf('run Unblock-File manually'));
});

test('PowerShell parses when a native PowerShell host is available', { skip: !process.env.PHANTOM_TEST_PWSH }, () => {
  execFileSync(process.env.PHANTOM_TEST_PWSH, [
    '-NoProfile', '-NonInteractive', '-Command',
    `[void][scriptblock]::Create((Get-Content -LiteralPath '${psInstaller.replaceAll("'", "''")}' -Raw))`,
  ]);
});
