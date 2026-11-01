import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
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
  return `#!/bin/sh\n[ "$1" = --version ] || exit 2\n[ -z "\${PHANTOM_TEST_RECORD_INVOCATIONS:-}" ] || printf '%s\\n' "$0" >> "$PHANTOM_TEST_RECORD_INVOCATIONS"\n${output}\n`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
  const owner = options.foreignOwner ? ['--owner=4242', '--group=4242'] : [];
  execFileSync('tar', [...owner, '-czf', archive, '-C', payload, ...members]);
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

function addGnuStatShim(shims) {
  const stat = join(shims, 'stat');
  writeFileSync(stat, `#!/usr/bin/env node
const { statSync } = require('node:fs');
const [, , flag, format, path] = process.argv;
if (flag === '-f') {
  process.stdout.write(\`  File: "\${path}"\n    ID: simulated Namelen: 255 Type: ext2/ext3\n\`);
  process.exit(0);
}
if (flag !== '-c' || !path) process.exit(2);
const value = statSync(path, { bigint: true });
switch (format) {
  case '%d:%i:%h:%f':
    process.stdout.write(\`\${value.dev}:\${value.ino}:\${value.nlink}:\${value.mode.toString(16)}\n\`);
    break;
  case '%h':
    process.stdout.write(\`\${value.nlink}\n\`);
    break;
  case '%Y':
    process.stdout.write(\`\${value.mtimeMs / 1000n}\n\`);
    break;
  default:
    process.exit(2);
}
`);
  chmodSync(stat, 0o755);
}

function runInstaller(options = {}) {
  const root = options.root ?? mkdtempSync(join(tmpdir(), 'phantom-installer-test-'));
  const target = options.target ?? 'x86_64-apple-darwin';
  const fixture = makeArchive(root, target, options);
  const shims = options.shims ?? makeShims(root);
  const home = options.home ?? join(root, 'home');
  const install = options.install ?? (options.defaultInstall
    ? join(home, '.phantom-secrets', 'bin') : join(root, 'live', 'bin'));
  mkdirSync(home, { recursive: true });
  if (options.existing) {
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
  }
  const log = join(root, 'curl.log');
  const env = {
    ...process.env,
    HOME: home,
    TMPDIR: options.tempDir ?? process.env.TMPDIR,
    SHELL: options.shell ?? '/bin/bash',
    PATH: `${shims}:${options.pathPrefix ? `${options.pathPrefix}:` : ''}${process.env.PATH}`,
    PHANTOM_INSTALL_DIR: install,
    PHANTOM_TEST_FIXTURE_DIR: fixture,
    PHANTOM_TEST_CURL_LOG: log,
    PHANTOM_TEST_UNAME_S: options.unameS ?? 'Darwin',
    PHANTOM_TEST_UNAME_M: options.unameM ?? 'x86_64',
    PHANTOM_TEST_CURL_DELAY_SECONDS: options.curlDelaySeconds ?? '',
    PHANTOM_TEST_RECORD_INVOCATIONS: options.recordInvocations ?? '',
    PHANTOM_INSTALL_LOCK_WAIT_SECONDS: options.lockWaitSeconds ?? '30',
    PHANTOM_INSTALL_LOCK_STALE_SECONDS: options.lockStaleSeconds ?? '300',
    PHANTOM_INSTALL_LOCK_HEARTBEAT_SECONDS: options.lockHeartbeatSeconds ?? '5',
  };
  if (options.defaultInstall) delete env.PHANTOM_INSTALL_DIR;
  delete env.PHANTOM_REPO;
  delete env.PHANTOM_TAG;
  delete env.PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES;
  delete env.PHANTOM_TEST_FAIL_AFTER_PROMOTION;
  if (!options.useCandidateDefaults) {
    env.PHANTOM_TAG = `v${options.version ?? version}`;
    if (options.repo) env.PHANTOM_REPO = options.repo;
    if (options.testOverrideOptIn !== false) {
      env.PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES = '1';
    }
  }
  if (options.directLocalRelease) {
    env.PHANTOM_TEST_LOCAL_RELEASE_DIR = fixture;
  }
  if (options.failAfterPromotion) {
    env.PHANTOM_TEST_FAIL_AFTER_PROMOTION = '1';
  }
  const result = spawnSync('/bin/bash', [options.installer ?? shellInstaller], {
    encoding: 'utf8',
    env,
    timeout: options.timeoutMs,
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

test('web installer mirrors remain bound to the evidenced public release', () => {
  // Release candidates can target a not-yet-published tag. The phm.dev copies
  // must not advance until public-release.ts has immutable release evidence.
  const publicShell = readFileSync(join(repo, 'apps/web/public/install.sh'), 'utf8');
  const publicPowerShell = readFileSync(join(repo, 'apps/web/public/install.ps1'), 'utf8');
  // v0.7.9 has its immutable tag-bound release receipt (workflow 34153902556).
  assert.match(publicShell, /CANDIDATE_TAG="v0\.7\.9"/);
  assert.match(publicPowerShell, /\$CandidateTag = 'v0\.7\.9'/);
  assert.doesNotMatch(publicShell, /v0\.7\.8/);
  assert.doesNotMatch(publicPowerShell, /v0\.7\.8/);
});

test('web Unix installer has valid Bash syntax', () => {
  execFileSync('/bin/bash', ['-n', join(repo, 'apps/web/public/install.sh')]);
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
    assert.match(source, /v0\.7\.9/);
    assert.match(source, /PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES/);
    assert.doesNotMatch(source, /releases\/latest|api\.github\.com/);
  }

  const { log, result } = runInstaller({ version: '0.7.9', useCandidateDefaults: true });
  assert.equal(result.status, 0, result.stderr);
  const curlLog = readFileSync(log, 'utf8');
  assert.match(curlLog, /ashlrai\/phantom-secrets\/releases\/download\/v0\.7\.9\//);
  assert.doesNotMatch(curlLog, /releases\/latest|api\.github\.com/);
});

test('Unix installer rejects repository and tag overrides without the explicit test-only opt-in', () => {
  for (const options of [
    { version: '1.2.3', testOverrideOptIn: false },
    { version: '1.2.3', repo: 'example/decoy', testOverrideOptIn: false },
  ]) {
    const { log, result } = runInstaller(options);
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /installer test overrides require PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1/,
    );
    assert.equal(existsSync(log), false, 'override rejection must happen before download');
  }
});

test('offline release fixtures require the explicit test opt-in and bypass curl only in test mode', () => {
  const denied = runInstaller({ directLocalRelease: true, testOverrideOptIn: false });
  assert.notEqual(denied.result.status, 0);
  assert.match(
    denied.result.stderr,
    /installer test overrides require PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1/,
  );
  assert.equal(existsSync(denied.log), false);

  const accepted = runInstaller({ directLocalRelease: true });
  assert.equal(accepted.result.status, 0, accepted.result.stderr);
  assert.equal(existsSync(accepted.log), false, 'offline test mode must not invoke curl');
  assert.deepEqual(
    JSON.parse(readFileSync(join(accepted.install, '.phantom-install-source.json'), 'utf8')),
    { schema_version: 1, source: 'direct', version: '1.2.3', target: 'x86_64-apple-darwin' },
  );
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
    assert.match(curlLog, new RegExp(escapeRegExp(option)));
  }
  assert.doesNotMatch(curlLog, /http:\/\//);
  assert.equal(readdirSync(dirname(install)).filter((name) => name.includes('.bin.install.')).length, 0);
});

test('Unix installer extracts without keeping the archive owner', () => {
  // Release archives carry the CI runner's uid; a root install must not hand the binaries to it.
  assert.match(readFileSync(shellInstaller, 'utf8'), /tar --no-same-owner -xzf "\$archive_path"/);
});

test('Unix installer run as root owns the installed binaries', { skip: process.getuid?.() !== 0 }, () => {
  const { install, result } = runInstaller({ foreignOwner: true });
  assert.equal(result.status, 0, result.stderr);
  for (const name of ['phantom', 'phantom-mcp']) assert.equal(lstatSync(join(install, name)).uid, 0);
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

test('Unix installer cleans its staging directory after a successful fixture upgrade', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-cleanup-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const parent = join(root, 'install-parent');
  const install = join(parent, 'bin');
  mkdirSync(parent);
  writeFileSync(join(parent, 'unrelated'), 'keep');

  const { result } = runInstaller({ root, install, existing: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(readFileSync(join(install, 'phantom'), 'utf8'), /phantom 1\.2\.3/);
  assert.match(readFileSync(join(install, 'phantom-mcp'), 'utf8'), /phantom-mcp 1\.2\.3/);
  assert.equal(existsSync(join(install, 'old-install')), false);
  assert.equal(readFileSync(join(parent, 'unrelated'), 'utf8'), 'keep');
  assert.deepEqual(readdirSync(parent).sort(), ['bin', 'unrelated']);
});

for (const installer of [shellInstaller, join(repo, 'apps/web/public/install.sh')]) {
test(`${installer} keeps downloads and extraction in private sibling staging directories`, (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-stage-review-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const shims = makeShims(root);
  const record = join(root, 'stage.json');
  const tar = execFileSync('which', ['tar'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'tar'), `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const args = process.argv.slice(2);
if (args.includes('-xzf')) {
  const candidate = args[args.indexOf('-C') + 1];
  const stage = path.dirname(candidate);
  const download = path.join(stage, 'download');
  const mode = (p) => fs.statSync(p).mode & 0o777;
  fs.writeFileSync(${JSON.stringify(record)}, JSON.stringify({
    stage, candidate, modes: [mode(stage), mode(download), mode(candidate)],
    downloads: fs.readdirSync(download).sort(), candidateFiles: fs.readdirSync(candidate),
  }));
}
const result = spawnSync(${JSON.stringify(tar)}, args, { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
`);
  chmodSync(join(shims, 'tar'), 0o755);
  const install = join(root, 'live', 'bin');
  const { result } = runInstaller({ root, shims, install, installer });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const observed = JSON.parse(readFileSync(record, 'utf8'));
  assert.match(observed.stage, new RegExp(`^${escapeRegExp(dirname(install))}/\\.bin\\.install\\.[^/]+$`));
  assert.equal(observed.candidate, join(observed.stage, 'candidate'));
  assert.deepEqual(observed.modes, [0o700, 0o700, 0o700]);
  assert.deepEqual(observed.downloads, [
    'phantom-x86_64-apple-darwin.tar.gz',
    'phantom-x86_64-apple-darwin.tar.gz.sha256',
  ]);
  assert.deepEqual(observed.candidateFiles, []);
  assert.equal(existsSync(observed.stage), false);
});

test(`${installer} stages under the physical install parent regardless of TMPDIR`, (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-stage-parent-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const parent = join(root, 'physical parent');
  const alias = join(root, 'parent alias');
  const tempDir = join(root, 'separate temp');
  mkdirSync(parent);
  mkdirSync(tempDir);
  symlinkSync(parent, alias);
  const record = join(root, 'invocations.log');
  const { result } = runInstaller({
    root, install: join(alias, 'custom-bin'), tempDir, recordInvocations: record, installer,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const staged = readFileSync(record, 'utf8').trim().split('\n')
    .filter((path) => path.includes('.custom-bin.install.'));
  assert.deepEqual(staged.map((path) => basename(path)).sort(), ['phantom', 'phantom-mcp']);
  const stageRoots = new Set(staged.map((path) => dirname(dirname(path))));
  assert.equal(stageRoots.size, 1);
  const [stage] = stageRoots;
  assert.equal(dirname(stage), parent);
  assert.match(basename(stage), /^\.custom-bin\.install\.[^/]+$/);
  assert.equal(existsSync(stage), false);
  assert.deepEqual(readdirSync(tempDir), []);
});
}

test('Unix installer passes the default destination-derived template to mktemp', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-stage-prefix-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const shims = makeShims(root);
  const record = join(root, 'mktemp-template');
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
if [ "$1" = -d ]; then printf '%s\\n' "$2" > ${JSON.stringify(record)}; fi
exec ${JSON.stringify(mktemp)} "$@"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  const invocations = join(root, 'invocations.log');
  const { install, result } = runInstaller({
    root, shims, defaultInstall: true, recordInvocations: invocations,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const parent = realpathSync(dirname(install));
  assert.equal(readFileSync(record, 'utf8').trim(), join(parent, '.bin.install.XXXXXX'));
  const staged = readFileSync(invocations, 'utf8').trim().split('\n')
    .filter((path) => path.includes('.bin.install.'));
  assert.deepEqual(staged.map((path) => basename(path)).sort(), ['phantom', 'phantom-mcp']);
  const stageRoots = new Set(staged.map((path) => dirname(dirname(path))));
  assert.equal(stageRoots.size, 1);
  const [stage] = stageRoots;
  assert.equal(dirname(stage), parent);
  assert.match(basename(stage), /^\.bin\.install\.[A-Za-z0-9]{6}$/);
  assert.equal(existsSync(stage), false);
});

test('Unix installer passes a spaced installation path to mktemp as one template argument', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-stage-argv-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const shims = makeShims(root);
  const record = join(root, 'mktemp-args.json');
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  writeFileSync(join(shims, 'mktemp'), `#!/usr/bin/env node
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const args = process.argv.slice(2);
if (args[0] === '-d') fs.writeFileSync(${JSON.stringify(record)}, JSON.stringify(args));
const result = spawnSync(${JSON.stringify(mktemp)}, args, { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  const parent = join(root, 'installation parent with spaces');
  const install = join(parent, 'phantom tools');
  const invocations = join(root, 'invocations.log');
  const { result } = runInstaller({ root, shims, install, recordInvocations: invocations });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(readFileSync(record, 'utf8')), [
    '-d', join(parent, '.phantom tools.install.XXXXXX'),
  ]);
  const staged = readFileSync(invocations, 'utf8').trim().split('\n')
    .filter((path) => path.includes('.phantom tools.install.'));
  assert.deepEqual(staged.map((path) => basename(path)).sort(), ['phantom', 'phantom-mcp']);
  const stageRoots = new Set(staged.map((path) => dirname(dirname(path))));
  assert.equal(stageRoots.size, 1);
  const [stage] = stageRoots;
  assert.equal(dirname(stage), parent);
  assert.match(basename(stage), /^\.phantom tools\.install\.[A-Za-z0-9]{6}$/);
  assert.equal(existsSync(stage), false);
  assert.ok(existsSync(join(install, 'phantom')));
  assert.ok(existsSync(join(install, 'phantom-mcp')));
});

for (const installer of [shellInstaller, join(repo, 'apps/web/public/install.sh')]) {
  const label = installer === shellInstaller ? 'candidate' : 'public-reference';
  test(`Unix ${label} installer stages inside a spaced install parent and cleans it up`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom installer stage-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const parent = join(root, 'live dir');
    const install = join(parent, 'bin');
    const record = join(root, 'invocations.log');
    const argsRecord = join(root, 'mktemp-args');
    const shims = makeShims(root);
    const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
    const shellQuote = (value) => `'${value.replace(/'/g, "'\\''")}'`;
    writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
if [ "$1" = -d ]; then printf '%s\\0' "$@" > ${shellQuote(argsRecord)}; fi
exec ${shellQuote(mktemp)} "$@"
`);
    chmodSync(join(shims, 'mktemp'), 0o755);
    const { result } = runInstaller({ root, shims, install, installer, recordInvocations: record });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readFileSync(argsRecord, 'utf8').split('\0'), [
      '-d', join(parent, '.bin.install.XXXXXX'), '',
    ], 'mktemp receives the complete staging template as one argument');

    // Every fixture --version probe logs $0: two staged runs must resolve
    // inside the spaced parent's single private staging directory.
    const staged = readFileSync(record, 'utf8').trim().split('\n')
      .filter((path) => path.includes('.bin.install.'));
    const stagedPattern = new RegExp(
      `^${escapeRegExp(parent)}/\\.bin\\.install\\.[^/]+/candidate/[^/]+$`,
    );
    assert.deepEqual(staged.map((path) => basename(path)).sort(), ['phantom', 'phantom-mcp']);
    const stageRoots = new Set(staged.map((path) => dirname(dirname(path))));
    assert.equal(stageRoots.size, 1);
    for (const path of staged) assert.match(path, stagedPattern);
    const [stageRoot] = stageRoots;
    assert.equal(existsSync(stageRoot), false, 'staging directory must be removed');
    assert.ok(existsSync(join(install, 'phantom')));
    assert.ok(existsSync(join(install, 'phantom-mcp')));
    assert.deepEqual(
      readdirSync(parent).filter((name) => name.startsWith('.bin.')),
      [],
    );
    assert.match(
      readFileSync(join(root, 'home', '.bashrc'), 'utf8'),
      new RegExp(`export PATH="${escapeRegExp(install)}:\\$PATH"`),
    );
  });
}

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

test('Unix installer atomically preserves an existing regular shell rc under GNU stat semantics', () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-installer-regular-rc-'));
  const home = join(root, 'home');
  const shims = makeShims(root);
  addGnuStatShim(shims);
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, '.bashrc'), '# existing\n', { mode: 0o600 });
  const { install, result } = runInstaller({ root, home, shims, install: join(root, 'live', 'bin') });
  assert.equal(result.status, 0, result.stderr);
  const rc = readFileSync(join(home, '.bashrc'), 'utf8');
  assert.match(rc, /^# existing\n/);
  assert.match(rc, /# phantom-secrets PATH/);
  const canonicalInstall = realpathSync(install);
  assert.match(rc, new RegExp(`export PATH="${escapeRegExp(canonicalInstall)}:\\$PATH"`));
  assert.deepEqual(
    readdirSync(home).filter((name) => name.startsWith('.phantom-path.')),
    [],
  );
});

test('Unix PATH setup removes both temporary files when the marker already exists', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-marker-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const shims = makeShims(root);
  mkdirSync(home);
  const rc = join(home, '.zshrc');
  const original = '# existing\n# phantom-secrets PATH\nexport PATH="/old/bin:$PATH"\n';
  writeFileSync(rc, original);
  const originalInode = lstatSync(rc).ino;
  const record = join(root, 'templates');
  const mktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
  const shellQuote = (value) => `'${value.replace(/'/g, "'\\''")}'`;
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh\nprintf '%s\\n' "$1" >> ${shellQuote(record)}\nexec ${shellQuote(mktemp)} "$@"\n`);
  chmodSync(join(shims, 'mktemp'), 0o755);

  const { result } = runInstaller({ root, home, shims, shell: '/bin/zsh' });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /already wired/);
  assert.equal(readFileSync(rc, 'utf8'), original);
  assert.equal(lstatSync(rc).ino, originalInode);
  const templates = readFileSync(record, 'utf8').split('\n');
  assert.ok(templates.includes(join(home, '.phantom-path.before.XXXXXX')));
  assert.ok(templates.includes(join(home, '.phantom-path.candidate.XXXXXX')));
  assert.deepEqual(readdirSync(home).filter((name) => name.startsWith('.phantom-path.')), []);
});

test('Unix PATH setup reports and cleans up failures before replacement', (t) => {
  for (const failure of ['snapshot creation', 'candidate creation', 'comparison', 'replacement']) {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-failure-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const shims = makeShims(root);
    mkdirSync(home);
    const rc = join(home, '.bashrc');
    writeFileSync(rc, '# original configuration\n');
    if (failure === 'snapshot creation' || failure === 'candidate creation') {
      const shim = join(shims, 'mktemp');
      const prefix = failure === 'snapshot creation' ? 'before' : 'candidate';
      writeFileSync(shim, `#!/bin/sh\ncase "$1" in *.phantom-path.${prefix}.*) : > "$HOME/.failure-invoked"; exit 1 ;; esac\nexec /usr/bin/mktemp "$@"\n`);
      chmodSync(shim, 0o755);
    } else if (failure === 'comparison') {
      const shim = join(shims, 'cmp');
      writeFileSync(shim, '#!/bin/sh\n: > "$HOME/.failure-invoked"\nexit 1\n');
      chmodSync(shim, 0o755);
    } else {
      const shim = join(shims, 'mv');
      writeFileSync(shim, '#!/bin/sh\ncase "$*" in *.phantom-path.candidate.*) : > "$HOME/.failure-invoked"; exit 1 ;; esac\nexec /bin/mv "$@"\n');
      chmodSync(shim, 0o755);
    }

    const { install, result } = runInstaller({ root, home, shims });
    assert.ifError(result.error);
    assert.equal(result.status, 0, `${failure}: ${result.stderr}`);
    assert.match(result.stderr, /could not update your shell PATH/);
    assert.equal(existsSync(join(home, '.failure-invoked')), true, `${failure}: failure seam reached`);
    assert.equal(readFileSync(rc, 'utf8'), '# original configuration\n');
    assert.equal(existsSync(join(install, 'phantom')), true);
    assert.equal(existsSync(join(install, 'phantom-mcp')), true);
    assert.match(result.stdout, /done\. phantom/);
    assert.deepEqual(readdirSync(home).filter((name) => name.startsWith('.phantom-path.')), []);
  }
});

test('Unix PATH setup creates an absent fish startup file and removes its temporary siblings', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-fish-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const { install, result } = runInstaller({ root, shell: '/usr/bin/fish' });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const parent = join(root, 'home', '.config', 'fish');
  const rc = join(parent, 'config.fish');
  assert.equal(readFileSync(rc, 'utf8'), `\n# phantom-secrets PATH\nset -gx PATH "${realpathSync(install)}" $PATH\n`);
  assert.equal(lstatSync(rc).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(parent), ['config.fish']);
});

test('Unix PATH final verification failure warns without restoring the previous startup file', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-final-check-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const shims = makeShims(root);
  mkdirSync(home);
  const rc = join(home, '.bashrc');
  writeFileSync(rc, '# original configuration\n');
  const shim = join(shims, 'grep');
  writeFileSync(shim, '#!/bin/sh\ncase "$*" in *"$HOME/.bashrc"*) : > "$HOME/.final-check-invoked"; exit 1 ;; esac\nexec /usr/bin/grep "$@"\n');
  chmodSync(shim, 0o755);

  const { install, result } = runInstaller({ root, home, shims });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /could not update your shell PATH/);
  assert.equal(existsSync(join(home, '.final-check-invoked')), true);
  assert.match(readFileSync(rc, 'utf8'), /^# original configuration\n\n# phantom-secrets PATH\n/);
  assert.equal(existsSync(join(install, 'phantom')), true);
  assert.deepEqual(readdirSync(home).filter((name) => name.startsWith('.phantom-path.')), []);
});

test('Unix installer leaves its existing PATH entry unchanged on a second install', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-repeat-')));
  const shims = makeShims(root);
  const options = { root, shims, install: join(root, 'live', 'bin') };
  const rcPath = join(root, 'home', '.bashrc');

  const first = runInstaller(options);
  assert.ifError(first.result.error);
  assert.equal(first.result.status, 0, first.result.stderr);
  const originalRc = readFileSync(rcPath, 'utf8');
  const entry = `export PATH="${options.install}:$PATH"`;
  assert.equal(originalRc.split('\n').filter((line) => line === entry).length, 1);

  const second = runInstaller(options);
  assert.ifError(second.result.error);
  assert.equal(second.result.status, 0, second.result.stderr);
  assert.equal(readFileSync(rcPath, 'utf8'), originalRc);
  assert.equal(execFileSync(join(options.install, 'phantom'), ['--version'], { encoding: 'utf8' }).trim(), `phantom ${version}`);
  assert.equal(execFileSync(join(options.install, 'phantom-mcp'), ['--version'], { encoding: 'utf8' }).trim(), `phantom-mcp ${version}`);
});

test('Unix installer does not alter the shell rc when the install directory is already in PATH', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-in-path-')));
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  const rcPath = join(home, '.bashrc');
  mkdirSync(home, { recursive: true });
  writeFileSync(rcPath, '# existing shell configuration\n');

  const { result } = runInstaller({ root, home, install, pathPrefix: install });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(rcPath, 'utf8'), '# existing shell configuration\n');
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

// Remove the fixture lock exactly between the installer's existence check and
// stat, reproducing an owner's normal release without relying on scheduling.
function lockStatFixture({ owner = true, remove = true, churn = false } = {}) {
  // Match the installer's canonical parent (/var -> /private/var on macOS).
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-lock-stat-')));
  const shims = makeShims(root);
  const install = join(root, 'live', 'bin');
  const lock = join(dirname(install), '.bin.install.lock');
  const marker = join(root, 'stat-interceptions');
  mkdirSync(lock, { recursive: true, mode: 0o700 });
  if (owner) writeFileSync(join(lock, 'owner'), 'existing-owner\n', { mode: 0o600 });
  const target = owner ? join(lock, 'owner') : lock;
  const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
  const stat = join(shims, 'stat');
  writeFileSync(stat, `#!/bin/sh
last=''
for arg do last="$arg"; done
if [ "$last" = ${quote(target)} ] && {
  { [ "$1" = '-c' ] && [ "$2" = '%Y' ]; } ||
  { [ "$1" = '-f' ] && [ "$2" = '%m' ]; }
}; then
  printf 'stat\\n' >> ${quote(marker)}
  if ${remove}; then /bin/rm -rf -- ${quote(lock)}; fi
  exit 1
fi
exec /usr/bin/stat "$@"
`);
  chmodSync(stat, 0o755);
  if (churn) {
    const mkdir = join(shims, 'mkdir');
    writeFileSync(mkdir, `#!/bin/sh
if [ "$1" = '-m' ] && [ "$2" = '700' ] && [ "$3" = ${quote(lock)} ]; then
  /bin/mkdir -p -m 700 -- ${quote(lock)} || exit 1
  printf 'another-owner\\n' > ${quote(join(lock, 'owner'))}
  chmod 600 ${quote(join(lock, 'owner'))}
  exit 1
fi
exec /bin/mkdir "$@"
`);
    chmodSync(mkdir, 0o755);
  }
  return { root, shims, install, lock, marker };
}

for (const installer of [shellInstaller, join(repo, 'apps/web/public/install.sh')]) {
  const label = installer === shellInstaller ? 'candidate' : 'public-reference';
  for (const owner of [true, false]) {
    const subject = owner ? 'owner' : 'ownerless directory';
    test(`Unix ${label} installer retries a disappearing lock ${subject}`, () => {
      const fixture = lockStatFixture({ owner });
      const { result, install } = runInstaller({ ...fixture, installer, timeoutMs: 60_000 });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.ok(existsSync(fixture.marker), 'stat must hit the deterministic release seam');
      assert.equal(existsSync(fixture.lock), false);
      assert.match(readFileSync(join(install, 'phantom'), 'utf8'), /phantom 1\.2\.3/);
      assert.match(readFileSync(join(install, 'phantom-mcp'), 'utf8'), /phantom-mcp 1\.2\.3/);
    });

    test(`Unix ${label} installer rejects unreadable extant lock ${subject} metadata`, () => {
      const fixture = lockStatFixture({ owner, remove: false });
      const { result, log } = runInstaller({ ...fixture, installer, timeoutMs: 60_000 });
      assert.ifError(result.error);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, owner ? /could not inspect install lock owner/ : /could not inspect install lock\s/);
      assert.equal(existsSync(log), false, 'metadata failure must precede downloads');
      assert.equal(existsSync(fixture.lock), true, 'extant lock must be preserved');
    });
  }

  test(`Unix ${label} installer bounds repeated disappearance retries`, () => {
    const fixture = lockStatFixture({ churn: true });
    const { result, log } = runInstaller({
      ...fixture, installer, lockWaitSeconds: '2', timeoutMs: 60_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /timed out waiting for another Phantom installer/);
    assert.ok(existsSync(fixture.marker), 'the disappearance retry must execute');
    assert.equal(existsSync(log), false, 'timeout must precede downloads');
  });

  test(`Unix ${label} installer rejects unsafe lock and owner types`, () => {
    for (const kind of ['lock-file', 'lock-link', 'owner-directory', 'owner-link']) {
      const root = mkdtempSync(join(tmpdir(), 'phantom-installer-lock-type-'));
      const install = join(root, 'live', 'bin');
      const lock = join(dirname(install), '.bin.install.lock');
      mkdirSync(dirname(install), { recursive: true });
      if (kind === 'lock-file') {
        writeFileSync(lock, 'not a directory');
      } else if (kind === 'lock-link') {
        symlinkSync(join(root, 'absent-target'), lock, 'dir');
      } else {
        mkdirSync(lock, { mode: 0o700 });
        if (kind === 'owner-directory') mkdirSync(join(lock, 'owner'));
        else symlinkSync(join(root, 'absent-target'), join(lock, 'owner'));
      }
      const { result, log } = runInstaller({ root, install, installer, timeoutMs: 60_000 });
      assert.ifError(result.error);
      assert.equal(result.status, 1, `${kind}: ${result.stderr}`);
      assert.match(result.stderr, kind.startsWith('owner-')
        ? /install lock owner is not a regular file/
        : /install lock is not a regular directory/);
      assert.equal(existsSync(log), false, 'unsafe locks must fail before downloads');
      assert.equal(existsSync(join(root, 'absent-target')), false);
      assert.ok(lstatSync(kind.startsWith('owner-') ? join(lock, 'owner') : lock),
        'unsafe lock paths must be preserved');
    }
  });
}

// Point-failure shims for the private staging tree. Each fails only the exact
// staging call and execs the real tool for everything else, so the installer
// reaches its staging step and must then stop with a useful error.
function addStagingFailureShim(shims, seam) {
  const scripts = {
    mktemp: `#!/bin/sh
for arg do
  case "$arg" in
    *.install.XXXXXX)
      printf 'mktemp: injected staging-directory failure\\n' >&2
      exit 1
      ;;
  esac
done
exec /usr/bin/mktemp "$@"
`,
    chmod: `#!/bin/sh
if [ "$#" -eq 2 ] && [ "$1" = '700' ]; then
  printf 'chmod: injected staging-directory failure\\n' >&2
  exit 1
fi
exec /bin/chmod "$@"
`,
    mkdir: `#!/bin/sh
for arg do
  case "$arg" in
    */download|*/candidate)
      printf 'mkdir: injected staging-directory failure\\n' >&2
      exit 1
      ;;
  esac
done
exec /bin/mkdir "$@"
`,
  };
  const shim = join(shims, seam);
  writeFileSync(shim, scripts[seam]);
  chmodSync(shim, 0o755);
}

test('Unix installer aborts before download when staging-directory creation fails', () => {
  for (const seam of ['mktemp', 'chmod', 'mkdir']) {
    const root = mkdtempSync(join(tmpdir(), `phantom-installer-stage-${seam}-`));
    const shims = makeShims(root);
    addStagingFailureShim(shims, seam);
    const install = join(root, 'live', 'bin');
    const parent = dirname(install);
    const { result, log } = runInstaller({ root, shims, install, existing: true });
    assert.ifError(result.error);
    assert.equal(result.status, 1, `${seam}: ${result.stderr}`);
    assert.match(result.stderr, /could not .*staging director/, `${seam}: must report a useful error`);
    assert.equal(existsSync(log), false, `${seam}: staging failure must precede downloads`);
    assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
    assert.equal(existsSync(join(parent, '.bin.install.lock')), false, `${seam}: lock released`);
    assert.deepEqual(
      readdirSync(parent).filter((name) => name.startsWith('.')),
      [],
      `${seam}: staging and lock leftovers must be cleaned up`,
    );
  }
});

test('Unix installer cleans staged candidates and rolls back after a controlled promotion failure', () => {
  for (const existing of [false, true]) {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom installer rollback-')));
    try {
      const install = join(root, 'live dir', 'bin');
      const record = join(root, 'invocations.log');
      const { result } = runInstaller({
        root, install, existing, recordInvocations: record, failAfterPromotion: true,
      });
      assert.ifError(result.error);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /test-only injected failure after promotion/);

      const staged = readFileSync(record, 'utf8').trim().split('\n');
      assert.deepEqual(staged.map((path) => basename(path)).sort(), ['phantom', 'phantom-mcp']);
      const stageRoots = new Set(staged.map((path) => dirname(dirname(path))));
      assert.equal(stageRoots.size, 1);
      const [stageRoot] = stageRoots;
      assert.match(stageRoot, new RegExp(`^${escapeRegExp(dirname(install))}/\\.bin\\.install\\.[^/]+$`));
      for (const path of staged) assert.equal(dirname(path), join(stageRoot, 'candidate'));
      assert.equal(existsSync(stageRoot), false, 'staging tree and candidate must be removed');
      assert.deepEqual(readdirSync(dirname(install)), existing ? ['bin'] : []);
      if (existing) {
        assert.deepEqual(readdirSync(install), ['old-install']);
        assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
      } else {
        assert.equal(existsSync(install), false);
      }
      assert.deepEqual(readdirSync(join(root, 'home')), [], 'HOME must contain no temporary files');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test('Unix installer leaves recoverable state when a rollback move fails', () => {
  for (const failedMove of ['failed-live', 'restore']) {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-rollback-move-')));
    try {
      const shims = makeShims(root);
      const shim = join(shims, 'mv');
      writeFileSync(shim, `#!/bin/sh
case "$1:$2" in
  ${failedMove === 'failed-live' ? '*:*/failed-live' : '*.backup.*:*/bin'}) exit 73 ;;
esac
exec /bin/mv "$@"
`);
      chmodSync(shim, 0o755);
      const { install, result } = runInstaller({ root, shims, existing: true, failAfterPromotion: true });
      assert.ifError(result.error);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /test-only injected failure after promotion/);
      const parent = dirname(install);
      const siblings = readdirSync(parent);
      const backups = siblings.filter((name) => name.startsWith('.bin.backup.'));
      assert.equal(backups.length, 1, 'the previous install remains in the backup');
      assert.equal(readFileSync(join(parent, backups[0], 'old-install'), 'utf8'), 'preserve-me');
      assert.equal(existsSync(join(parent, '.bin.install.lock')), false);
      assert.equal(siblings.some((name) => /^\.bin\.install\.(?!lock$)/.test(name)), false);
      if (failedMove === 'failed-live') {
        assert.equal(existsSync(join(install, 'phantom')), true, 'the promoted candidate remains live');
      } else {
        assert.equal(existsSync(install), false, 'the live destination remains absent');
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test('web Unix installer cleans staging failures and rolls back a promoted candidate', () => {
  const installer = join(repo, 'apps/web/public/install.sh');
  for (const seam of ['mktemp', 'chmod', 'mkdir']) {
    const root = mkdtempSync(join(tmpdir(), `phantom-web-stage-${seam}-`));
    try {
      const shims = makeShims(root);
      addStagingFailureShim(shims, seam);
      const { install, log, result } = runInstaller({ root, shims, installer, existing: true });
      assert.ifError(result.error);
      assert.equal(result.status, 1, `${seam}: ${result.stderr}`);
      assert.equal(existsSync(log), false, `${seam}: failure must precede downloads`);
      assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
      assert.deepEqual(readdirSync(dirname(install)), ['bin']);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  for (const existing of [false, true]) {
    const root = mkdtempSync(join(tmpdir(), 'phantom-web-rollback-'));
    try {
      const { install, result } = runInstaller({ root, installer, existing, failAfterPromotion: true });
      assert.ifError(result.error);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /test-only injected failure after promotion/);
      assert.deepEqual(readdirSync(dirname(install)), existing ? ['bin'] : []);
      if (existing) assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
      else assert.equal(existsSync(install), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
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
    { unameS: 'Darwin', unameM: 'amd64', target: 'x86_64-apple-darwin' },
    { unameS: 'Darwin', unameM: 'arm64', target: 'aarch64-apple-darwin' },
    { unameS: 'Darwin', unameM: 'aarch64', target: 'aarch64-apple-darwin' },
    { unameS: 'Linux', unameM: 'x86_64', target: 'x86_64-unknown-linux-gnu' },
    { unameS: 'Linux', unameM: 'amd64', target: 'x86_64-unknown-linux-gnu' },
    { unameS: 'Linux', unameM: 'arm64', target: 'aarch64-unknown-linux-gnu' },
    { unameS: 'Linux', unameM: 'aarch64', target: 'aarch64-unknown-linux-gnu' },
  ]) {
    const { result } = runInstaller(mapping);
    assert.equal(result.status, 0, `${mapping.target}: ${result.stderr}`);
    assert.match(result.stdout, new RegExp(`target: ${mapping.target}`));
  }
  assert.match(powerShell, /x86_64-pc-windows-msvc/);
  assert.match(powerShell, /aarch64-pc-windows-msvc/);
});

test('Unix installer rejects unsupported OS and architecture before download or installation', () => {
  for (const { unameS, unameM, error } of [
    { unameS: 'FreeBSD', unameM: 'x86_64', error: /unsupported OS: FreeBSD/ },
    { unameS: 'Windows_NT', unameM: 'x86_64', error: /unsupported OS: Windows_NT/ },
    { unameS: 'linux', unameM: 'x86_64', error: /unsupported OS: linux/ },
    { unameS: 'Linux', unameM: 'i686', error: /unsupported arch: i686/ },
    { unameS: 'Darwin', unameM: 'riscv64', error: /unsupported arch: riscv64/ },
    { unameS: 'FreeBSD', unameM: 'i686', error: /unsupported OS: FreeBSD/ },
  ]) {
    const { root, install, log, result } = runInstaller({ unameS, unameM });
    try {
      assert.equal(result.status, 1);
      assert.match(result.stderr, error);
      assert.equal(existsSync(log), false, 'must not download');
      assert.equal(existsSync(dirname(install)), false, 'must not create the install parent');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
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
  assert.match(source, /function Get-NativeUserProfilePath/);
  assert.match(source, /GetFolderPath\([\s\S]+\[System\.Environment\+SpecialFolder\]::UserProfile/);
  assert.match(source, /@\(\$env:USERPROFILE, \$platformProfile, \$env:HOME\)/);
  assert.match(source, /\^\[A-Za-z\]:\[\\\\\/\]/);
  assert.doesNotMatch(source, /\$homeDir = if \(\$env:HOME\)/);
  assert.match(source, /MoveFileEx/);
  assert.match(source, /StructuralEqualityComparer/);
  assert.match(source, /PHANTOM_INSTALL_DIR must be a local absolute path/);
  assert.match(source, /install source receipt failed final validation/);
  assert.match(source, /\$CanonicalRepo = 'ashlrai\/phantom-secrets'/);
  assert.match(source, /\$CandidateTag = 'v0\.7\.9'/);
  assert.match(source, /PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES -ceq '1'/);
  assert.match(source, /PHANTOM_TEST_LOCAL_RELEASE_DIR/);
  assert.match(source, /PHANTOM_TEST_DISABLE_PATH_PERSISTENCE/);
  assert.match(source, /installer test overrides require PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES=1/);
  assert.doesNotMatch(source, /releases\/latest|api\.github\.com/);
  assert.ok(source.indexOf('archive identity verified') < source.indexOf('run Unblock-File manually'));
});

test('PowerShell parses when a native PowerShell host is available', { skip: !process.env.PHANTOM_TEST_PWSH }, () => {
  execFileSync(process.env.PHANTOM_TEST_PWSH, [
    '-NoProfile', '-NonInteractive', '-Command',
    `[void][scriptblock]::Create((Get-Content -LiteralPath '${psInstaller.replaceAll("'", "''")}' -Raw))`,
  ]);
});
