import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const shellInstaller = join(repo, 'scripts', 'install.sh');
const psInstaller = join(repo, 'scripts', 'install.ps1');
const tag = 'v1.2.3';
const version = '1.2.3';

function executable(product, reportedVersion = version, pathSensitive = false) {
  const output = pathSensitive
    ? `case "$0" in *.install.*) echo '${product} ${reportedVersion}' ;; *) echo '${product} 9.9.9' ;; esac`
    : `echo '${product} ${reportedVersion}'`;
  return `#!/bin/sh\n[ "$1" = --version ] || exit 2\n${output}\n`;
}

function makeArchive(root, target = 'x86_64-apple-darwin', options = {}) {
  const reportedVersion = options.version ?? version;
  const fixtureName = options.fixtureName ?? `fixture-${reportedVersion}`;
  const fixture = join(root, fixtureName);
  const payload = join(root, `payload-${fixtureName}`);
  mkdirSync(fixture, { recursive: true });
  mkdirSync(payload, { recursive: true });
  const phantom = join(payload, 'phantom');
  const mcp = join(payload, 'phantom-mcp');
  if (options.symlink) {
    writeFileSync(join(payload, 'target'), executable('phantom', reportedVersion));
    symlinkSync('target', phantom);
  } else {
    writeFileSync(phantom, executable('phantom', reportedVersion, options.pathSensitive));
    chmodSync(phantom, 0o755);
  }
  writeFileSync(mcp, executable('phantom-mcp', reportedVersion, options.pathSensitive));
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
[ -z "$PHANTOM_TEST_CURL_DELAY_SECONDS" ] || sleep "$PHANTOM_TEST_CURL_DELAY_SECONDS"
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
  const root = options.root ?? mkdtempSync(join(tmpdir(), 'phantom-installer-test-'));
  const target = options.target ?? 'x86_64-apple-darwin';
  const fixture = makeArchive(root, target, options);
  const shims = options.shims ?? makeShims(root);
  const home = options.home ?? join(root, 'home');
  const install = options.install ?? join(root, 'live', 'bin');
  mkdirSync(home, { recursive: true });
  if (options.existing) {
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
  }
  const log = join(root, 'curl.log');
  const env = {
    ...process.env,
    HOME: home,
    SHELL: '/bin/bash',
    PATH: `${shims}:${process.env.PATH}`,
    PHANTOM_INSTALL_DIR: install,
    PHANTOM_TEST_FIXTURE_DIR: fixture,
    PHANTOM_TEST_CURL_LOG: log,
    PHANTOM_TEST_UNAME_S: options.unameS ?? 'Darwin',
    PHANTOM_TEST_UNAME_M: options.unameM ?? 'x86_64',
    PHANTOM_TEST_CURL_DELAY_SECONDS: options.curlDelaySeconds ?? '',
    PHANTOM_INSTALL_LOCK_WAIT_SECONDS: options.lockWaitSeconds ?? '30',
    PHANTOM_INSTALL_LOCK_STALE_SECONDS: options.lockStaleSeconds ?? '300',
    PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS: options.lockHeartbeatSeconds ?? '5',
  };
  delete env.PHANTOM_REPO;
  delete env.PHANTOM_TAG;
  delete env.PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES;
  if (!options.useCandidateDefaults) {
    env.PHANTOM_TAG = `v${options.version ?? version}`;
    if (options.repo) env.PHANTOM_REPO = options.repo;
    if (options.testOverrideOptIn !== false) {
      env.PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES = '1';
    }
  }
  const result = spawnSync('/bin/bash', [shellInstaller], {
    encoding: 'utf8',
    env,
  });
  return { root, install, log, result };
}

function waitForChild(child) {
  return new Promise((resolvePromise, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (status) => resolvePromise({ status, stdout, stderr }));
  });
}

async function waitForPath(path, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(path)) {
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${path}`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
  }
}

test('canonical installers exactly match the public mirrors', () => {
  assert.deepEqual(readFileSync(shellInstaller), readFileSync(join(repo, 'apps/web/public/install.sh')));
  assert.deepEqual(readFileSync(psInstaller), readFileSync(join(repo, 'apps/web/public/install.ps1')));
});

test('Unix installer guidance never emits pipe-to-shell or older-registry fallbacks', () => {
  const source = readFileSync(shellInstaller, 'utf8');
  assert.doesNotMatch(source, /curl[^\n]*https?:\/\/[^\n]*\|\s*(?:ba)?sh\b/i);
  assert.doesNotMatch(source, /cargo install|npm (?:i|install)|npx /i);
  assert.match(source, /checksum-verifiable asset from \$RELEASES_URL/);
  assert.match(source, /Do not pipe a network response directly into a shell/);
});

test('direct installers bind normal use to the canonical repository and exact candidate tag', () => {
  const shell = readFileSync(shellInstaller, 'utf8');
  const powerShell = readFileSync(psInstaller, 'utf8');
  for (const source of [shell, powerShell]) {
    assert.match(source, /ashlrai\/phantom-secrets/);
    assert.match(source, /v0\.7\.4/);
    assert.match(source, /PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES/);
    assert.doesNotMatch(source, /releases\/latest|api\.github\.com/);
  }

  const { log, result } = runInstaller({ version: '0.7.4', useCandidateDefaults: true });
  assert.equal(result.status, 0, result.stderr);
  const curlLog = readFileSync(log, 'utf8');
  assert.match(curlLog, /ashlrai\/phantom-secrets\/releases\/download\/v0\.7\.4\//);
  assert.doesNotMatch(curlLog, /releases\/latest|api\.github\.com/);
});

test('Unix installer rejects repository and tag overrides without the explicit test-only opt-in', () => {
  for (const options of [
    { version: '1.2.3', testOverrideOptIn: false },
    { version: '1.2.3', repo: 'example/decoy', testOverrideOptIn: false },
  ]) {
    const { log, result } = runInstaller(options);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /test-only overrides/);
    assert.equal(existsSync(log), false, 'override rejection must happen before download');
  }
});

test('Unix unsupported-target failures point to reviewed release assets', () => {
  for (const options of [
    { unameS: 'FreeBSD', unameM: 'x86_64' },
    { unameS: 'Darwin', unameM: 'riscv64' },
  ]) {
    const { result } = runInstaller(options);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /checksum-verifiable asset from https:\/\/github\.com\/ashlrai\/phantom-secrets\/releases/);
    assert.doesNotMatch(result.stderr, /cargo install|npm (?:i|install)|npx |curl[^\n]*\|/i);
  }
});

test('Unix installer uses bounded HTTPS downloads and promotes both exact binaries', () => {
  const { install, log, result, root } = runInstaller();
  assert.equal(result.status, 0, result.stderr);
  assert.match(readFileSync(join(install, 'phantom'), 'utf8'), /phantom 1\.2\.3/);
  assert.match(readFileSync(join(install, 'phantom-mcp'), 'utf8'), /phantom-mcp 1\.2\.3/);
  assert.deepEqual(
    JSON.parse(readFileSync(join(install, '.phantom-install-source.json'), 'utf8')),
    { schema_version: 1, source: 'direct', version: '1.2.3', target: 'x86_64-apple-darwin' },
  );
  const curlLog = readFileSync(log, 'utf8');
  for (const option of ['--proto =https', '--proto-redir =https', '--max-redirs 3', '--connect-timeout 10', '--max-time 120', '--max-filesize']) {
    assert.match(curlLog, new RegExp(option.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.doesNotMatch(curlLog, /http:\/\//);
  assert.equal(readdirSync(dirname(install)).filter((name) => name.includes('.bin.install.')).length, 0);
});

test('Unix installer rejects unsafe install-directory syntax before download', () => {
  for (const install of [
    'relative/bin',
    '/tmp/phantom"; touch injected; #',
    '/tmp/phantom\ncontrol',
  ]) {
    const { log, result } = runInstaller({ install });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /PHANTOM_INSTALL_DIR/);
    assert.equal(existsSync(log), false, 'unsafe path must fail before any download');
  }
});

test('Unix installer refuses a linked shell rc without mutating its target', () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-linked-rc-'));
  const home = join(root, 'home');
  const victim = join(root, 'victim');
  mkdirSync(home, { recursive: true });
  writeFileSync(victim, 'preserve-me\n');
  symlinkSync(victim, join(home, '.bashrc'));
  const { result } = runInstaller({ root, home, install: join(root, 'live', 'bin') });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(victim, 'utf8'), 'preserve-me\n');
  assert.match(result.stderr, /could not update your shell PATH/);
});

test('Unix installer atomically preserves an existing regular shell rc', () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-regular-rc-'));
  const home = join(root, 'home');
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, '.bashrc'), '# existing\n', { mode: 0o600 });
  const { install, result } = runInstaller({ root, home, install: join(root, 'live', 'bin') });
  assert.equal(result.status, 0, result.stderr);
  const rc = readFileSync(join(home, '.bashrc'), 'utf8');
  assert.match(rc, /^# existing\n/);
  assert.match(rc, /# phantom-secrets PATH/);
  const canonicalInstall = realpathSync(install);
  assert.match(rc, new RegExp(`export PATH="${canonicalInstall.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:\\$PATH"`));
  assert.deepEqual(
    readdirSync(home).filter((name) => name.startsWith('.phantom-path.')),
    [],
  );
});

test('Unix installer serializes concurrent versions under one owner lock', async () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-concurrent-'));
  const shims = makeShims(root);
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  const log = join(root, 'curl.log');
  mkdirSync(home, { recursive: true });
  const firstFixture = makeArchive(root, 'x86_64-apple-darwin', {
    version: '1.2.3', fixtureName: 'fixture-first',
  });
  const secondFixture = makeArchive(root, 'x86_64-apple-darwin', {
    version: '1.2.4', fixtureName: 'fixture-second',
  });
  const baseEnv = {
    ...process.env,
    HOME: home,
    SHELL: '/bin/bash',
    PATH: `${shims}:${process.env.PATH}`,
    PHANTOM_INSTALL_DIR: install,
    PHANTOM_TEST_CURL_LOG: log,
    PHANTOM_TEST_UNAME_S: 'Darwin',
    PHANTOM_TEST_UNAME_M: 'x86_64',
    PHANTOM_INSTALL_LOCK_WAIT_SECONDS: '15',
    PHANTOM_INSTALL_LOCK_STALE_SECONDS: '3',
    PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS: '1',
    PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
  };

  const first = spawn('/bin/bash', [shellInstaller], {
    env: {
      ...baseEnv,
      PHANTOM_TAG: 'v1.2.3',
      PHANTOM_TEST_FIXTURE_DIR: firstFixture,
      PHANTOM_TEST_CURL_DELAY_SECONDS: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const lockOwner = join(dirname(install), '.bin.install.lock', 'owner');
  await waitForPath(lockOwner);
  const second = spawn('/bin/bash', [shellInstaller], {
    env: {
      ...baseEnv,
      PHANTOM_TAG: 'v1.2.4',
      PHANTOM_TEST_FIXTURE_DIR: secondFixture,
      PHANTOM_TEST_CURL_DELAY_SECONDS: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const [firstResult, secondResult] = await Promise.all([
    waitForChild(first), waitForChild(second),
  ]);
  assert.equal(firstResult.status, 0, firstResult.stderr);
  assert.equal(secondResult.status, 0, secondResult.stderr);
  assert.match(readFileSync(join(install, 'phantom'), 'utf8'), /phantom 1\.2\.4/);
  assert.match(readFileSync(join(install, 'phantom-mcp'), 'utf8'), /phantom-mcp 1\.2\.4/);
  assert.equal(
    JSON.parse(readFileSync(join(install, '.phantom-install-source.json'), 'utf8')).version,
    '1.2.4',
  );
  assert.equal(existsSync(join(dirname(install), '.bin.install.lock')), false);
});

test('Unix installer recovers an abandoned stale owner lock', () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-stale-'));
  const shims = makeShims(root);
  const install = join(root, 'live', 'bin');
  const lock = join(dirname(install), '.bin.install.lock');
  mkdirSync(lock, { recursive: true, mode: 0o700 });
  const owner = join(lock, 'owner');
  writeFileSync(owner, 'abandoned-owner\n', { mode: 0o600 });
  const old = new Date(Date.now() - 10_000);
  utimesSync(owner, old, old);

  const { result } = runInstaller({
    root,
    shims,
    install,
    home: join(root, 'home'),
    fixtureName: 'fixture-recovery',
    lockWaitSeconds: '5',
    lockStaleSeconds: '2',
    lockHeartbeatSeconds: '1',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(lock), false);
  assert.match(readFileSync(join(install, 'phantom'), 'utf8'), /phantom 1\.2\.3/);
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
  assert.doesNotMatch(source, /\b(?:irm|Invoke-RestMethod)\b[^\n]*\|\s*iex\b/i);
  assert.match(source, /Get-FileHash -Algorithm SHA256/);
  assert.match(source, /Run the reviewed local file/);
  assert.doesNotMatch(source, /Unblock-File.*-ErrorAction\s+SilentlyContinue/);
  assert.match(source, /AllowAutoRedirect\s*=\s*\$false/);
  assert.match(source, /ResponseHeadersRead/);
  assert.match(source, /release archive must contain exactly phantom\.exe and phantom-mcp\.exe/);
  assert.match(source, /Assert-ExactVersion[\s\S]+phantom-mcp/);
  assert.match(source, /Move-Item[\s\S]+backupPath[\s\S]+failed-live/);
  assert.match(source, /FileMode\]::CreateNew/);
  assert.match(source, /Assert-NoReparsePathComponents/);
  assert.match(source, /MoveFileEx/);
  assert.match(source, /StructuralEqualityComparer/);
  assert.match(source, /PHANTOM_INSTALL_DIR must be a local absolute path/);
  assert.match(source, /install source receipt failed final validation/);
  assert.match(source, /\$CanonicalRepo = 'ashlrai\/phantom-secrets'/);
  assert.match(source, /\$CandidateTag = 'v0\.7\.4'/);
  assert.match(source, /PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES -ceq '1'/);
  assert.match(source, /PHANTOM_REPO and PHANTOM_TAG are test-only overrides/);
  assert.doesNotMatch(source, /releases\/latest|api\.github\.com/);
  assert.ok(source.indexOf('archive identity verified') < source.indexOf('run Unblock-File manually'));
});

test('PowerShell parses when a native PowerShell host is available', { skip: !process.env.PHANTOM_TEST_PWSH }, () => {
  execFileSync(process.env.PHANTOM_TEST_PWSH, [
    '-NoProfile', '-NonInteractive', '-Command',
    `[void][scriptblock]::Create((Get-Content -LiteralPath '${psInstaller.replaceAll("'", "''")}' -Raw))`,
  ]);
});
