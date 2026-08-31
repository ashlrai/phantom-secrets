import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const script = join(repo, 'scripts', 'publish-crates.sh');
const version = '0.7.3';
const sourceSha = '0123456789abcdef0123456789abcdef01234567';
const crates = [
  'phantom-secrets-authority',
  'phantom-secrets-core',
  'phantom-secrets-broker',
  'phantom-secrets-evidence',
  'phantom-secrets-locus-contract',
  'phantom-secrets-proxy',
  'phantom-secrets-session',
  'phantom-secrets-vault',
  'phantom-secrets-workspace',
  'phantom-secrets-runtime',
  'phantom-secrets-mcp',
  'phantom-secrets',
];

const dependencies = {
  'phantom-secrets-authority': [],
  'phantom-secrets-core': [],
  'phantom-secrets-broker': ['phantom-secrets-authority'],
  'phantom-secrets-evidence': ['phantom-secrets-authority'],
  'phantom-secrets-locus-contract': ['phantom-secrets-authority'],
  'phantom-secrets-proxy': ['phantom-secrets-core', 'phantom-secrets-proxy'],
  'phantom-secrets-session': ['phantom-secrets-authority'],
  'phantom-secrets-vault': ['phantom-secrets-core'],
  'phantom-secrets-workspace': ['phantom-secrets-core'],
  'phantom-secrets-runtime': ['phantom-secrets-authority', 'phantom-secrets-broker'],
  'phantom-secrets-mcp': [
    'phantom-secrets-core',
    'phantom-secrets-vault',
    'phantom-secrets-workspace',
    'phantom-secrets-runtime',
  ],
  'phantom-secrets': [
    'phantom-secrets-core',
    'phantom-secrets-vault',
    'phantom-secrets-proxy',
    'phantom-secrets-mcp',
    'phantom-secrets-workspace',
  ],
};

function executable(path, source) {
  writeFileSync(path, source);
  chmodSync(path, 0o755);
  return path;
}

function packageBytes(crate) {
  return `${crate}-${version}\n`;
}

function makeHarness(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'phantom-publish-test-'));
  const bin = join(root, 'bin');
  const state = join(root, 'state');
  mkdirSync(bin);
  mkdirSync(state);
  const cargoLog = join(root, 'cargo.log');
  const tokenLog = join(root, 'cargo-token.log');
  const curlLog = join(root, 'curl.log');
  const ghLog = join(root, 'gh.log');
  const metadataPath = join(root, 'metadata.json');
  const checksumPath = join(root, 'checksums.tsv');
  const releaseReceiptPath = join(root, 'release.json');
  const includedCrates = options.omitLast ? crates.slice(0, -1) : crates;
  const packages = includedCrates.map((name) => ({
    id: `path+file:///fixture/${name}#${version}`,
    name,
    version,
    publish: options.wrongRegistry && name === crates[0] ? ['private'] : ['crates-io'],
    dependencies: (dependencies[name] ?? []).map((dependency) => ({ name: dependency })),
  }));
  writeFileSync(metadataPath, JSON.stringify({
    packages,
    workspace_members: packages.map((entry) => entry.id),
  }));
  writeFileSync(
    checksumPath,
    crates.map((name) => {
      const checksum = createHash('sha256').update(packageBytes(name)).digest('hex');
      return `${name}\t${checksum}`;
    }).join('\n') + '\n',
  );
  const archives = [
    'phantom-aarch64-apple-darwin.tar.gz',
    'phantom-x86_64-apple-darwin.tar.gz',
    'phantom-aarch64-unknown-linux-gnu.tar.gz',
    'phantom-x86_64-unknown-linux-gnu.tar.gz',
    'phantom-aarch64-pc-windows-msvc.zip',
    'phantom-x86_64-pc-windows-msvc.zip',
  ];
  const assetNames = ['SHA256SUMS', ...archives.flatMap((archive) => [
    archive,
    `${archive}.sha256`,
    `${archive}.spdx.json`,
  ])];
  if (options.missingReleaseAsset) assetNames.pop();
  if (options.extraReleaseAsset) assetNames.push('unexpected.bin');
  writeFileSync(releaseReceiptPath, JSON.stringify({
    tagName: `v${version}`,
    isDraft: false,
    isPrerelease: false,
    url: `https://github.com/ashlrai/phantom-secrets/releases/tag/v${version}`,
    assets: assetNames.map((name) => ({ name, size: 100 })),
  }));

  const cargo = executable(join(bin, 'cargo'), `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CARGO_LOG"
command="$1"; shift
if [ -n "\${CARGO_REGISTRY_TOKEN:-}" ]; then token_state=present; else token_state=absent; fi
printf '%s\\t%s\\n' "$command" "$token_state" >> "$PHANTOM_TEST_TOKEN_LOG"
case "$command" in
  metadata) cat "$PHANTOM_TEST_METADATA" ;;
  fmt|clippy|test) exit 0 ;;
  package)
    crate=''
    while [ "$#" -gt 0 ]; do
      case "$1" in -p) crate="$2"; shift 2 ;; *) shift ;; esac
    done
    mkdir -p "$CARGO_TARGET_DIR/package"
    printf '%s-${version}\\n' "$crate" > "$CARGO_TARGET_DIR/package/$crate-${version}.crate"
    ;;
  publish)
    crate=''
    while [ "$#" -gt 0 ]; do
      case "$1" in -p) crate="$2"; shift 2 ;; *) shift ;; esac
    done
    touch "$PHANTOM_TEST_STATE/published-$crate"
    ;;
  *) exit 91 ;;
esac
`);

  const git = executable(join(bin, 'git'), `#!/bin/sh
set -eu
case "$1" in
  status) [ "\${PHANTOM_TEST_DIRTY:-0}" = 1 ] && printf ' M fixture\\n'; exit 0 ;;
  remote) printf '%s\\n' "$PHANTOM_TEST_ORIGIN_URL" ;;
  ls-remote) printf '%s\\trefs/tags/v${version}\\n' "$PHANTOM_TEST_REMOTE_SHA" ;;
  rev-parse)
    case "$*" in
      *--show-toplevel*) printf '%s\\n' "$PHANTOM_TEST_REPO" ;;
      *) printf '${sourceSha}\\n' ;;
    esac
    ;;
  *) exit 92 ;;
esac
`);

  const gh = executable(join(bin, 'gh'), `#!/bin/sh
set -eu
if [ -n "\${GH_TOKEN:-}" ]; then token_state=present; else token_state=absent; fi
printf '%s\\t%s\\n' "$*" "$token_state" >> "$PHANTOM_TEST_GH_LOG"
cat "$PHANTOM_TEST_RELEASE_RECEIPT"
`);

  const curl = executable(join(bin, 'curl'), `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CURL_LOG"
output=''; url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --write-out|--proto|--proto-redir|--max-redirs|--connect-timeout|--max-time|--max-filesize) shift 2 ;;
    --silent|--show-error|--location) shift ;;
    *) url="$1"; shift ;;
  esac
done
version="\${url##*/}"
prefix="\${url%/*}"
crate="\${prefix##*/}"
mode="\${PHANTOM_TEST_REMOTE_MODE:-missing}"
if [ "$mode" = after-publish ] && [ -f "$PHANTOM_TEST_STATE/published-$crate" ]; then mode=matching; fi
if [ "$mode" = missing ] || [ "$mode" = after-publish ]; then
  : > "$output"
  printf '404'
  exit 0
fi
checksum="$(awk -F '\\t' -v crate="$crate" '$1 == crate { print $2 }' "$PHANTOM_TEST_CHECKSUMS")"
if [ "$mode" = mismatch ]; then checksum='0000000000000000000000000000000000000000000000000000000000000000'; fi
printf '{"version":{"crate":"%s","num":"%s","checksum":"%s"}}\\n' "$crate" "$version" "$checksum" > "$output"
printf '200'
`);

  return {
    root,
    cargoLog,
    tokenLog,
    curlLog,
    ghLog,
    run(args, env = {}) {
      return spawnSync('/bin/bash', [script, ...args], {
        cwd: repo,
        encoding: 'utf8',
        env: {
          ...process.env,
          CARGO: cargo,
          CURL: curl,
          GIT: git,
          GH: gh,
          PYTHON: process.env.PYTHON ?? 'python3',
          PHANTOM_TEST_CARGO_LOG: cargoLog,
          PHANTOM_TEST_TOKEN_LOG: tokenLog,
          PHANTOM_TEST_CURL_LOG: curlLog,
          PHANTOM_TEST_GH_LOG: ghLog,
          PHANTOM_TEST_METADATA: metadataPath,
          PHANTOM_TEST_CHECKSUMS: checksumPath,
          PHANTOM_TEST_RELEASE_RECEIPT: releaseReceiptPath,
          PHANTOM_TEST_STATE: state,
          PHANTOM_TEST_REPO: repo,
          PHANTOM_TEST_REMOTE_SHA: options.remoteSha ?? sourceSha,
          PHANTOM_TEST_ORIGIN_URL: options.originUrl ?? 'https://github.com/ashlrai/phantom-secrets.git',
          PHANTOM_PUBLISH_POLL_INTERVAL_SECONDS: '1',
          PHANTOM_PUBLISH_TIMEOUT_SECONDS: '5',
          CARGO_REGISTRY_TOKEN: 'fixture-secret-never-log-this-value',
          GH_TOKEN: 'fixture-github-token-never-log-this-value',
          ...env,
        },
      });
    },
  };
}

test('no mode is inert and exits with usage', () => {
  const harness = makeHarness();
  const result = harness.run([]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Usage:/);
  assert.throws(() => readFileSync(harness.cargoLog));
});

test('verify-only packages the complete dependency-ordered set without registry access', () => {
  const harness = makeHarness();
  const result = harness.run(['--verify-only', '--version', version, '--allow-dirty']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Verified 12 local crate packages/);
  const log = readFileSync(harness.cargoLog, 'utf8');
  const packaged = [...log.matchAll(/^package .* -p ([^ ]+)/gm)].map((match) => match[1]);
  assert.deepEqual(packaged, crates);
  assert.equal(log.match(/^package --registry crates-io /gm)?.length, 12);
  assert.equal(
    log.match(/--config patch\.crates-io\.phantom-secrets-authority\.path="crates\/phantom-authority"/g)?.length,
    12,
  );
  assert.doesNotMatch(log, /^publish /m);
  assert.throws(() => readFileSync(harness.curlLog));
  assert.doesNotMatch(readFileSync(harness.tokenLog, 'utf8'), /present/);
});

test('dry-run skips byte-identical versions and never invokes cargo publish', () => {
  const harness = makeHarness();
  const result = harness.run(
    ['--dry-run', '--version', version, '--allow-dirty'],
    { PHANTOM_TEST_REMOTE_MODE: 'matching' },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /12 identical already published, 0 would publish, 0 uploaded/);
  assert.doesNotMatch(readFileSync(harness.cargoLog, 'utf8'), /^publish /m);
});

test('dry-run fails closed on an immutable version checksum collision', () => {
  const harness = makeHarness();
  const result = harness.run(
    ['--dry-run', '--version', version, '--allow-dirty'],
    { PHANTOM_TEST_REMOTE_MODE: 'mismatch' },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /immutable version collision/);
  assert.doesNotMatch(readFileSync(harness.cargoLog, 'utf8'), /^publish /m);
});

test('publish requires exact authorization and uploads every missing crate in order', () => {
  const unauthorized = makeHarness();
  const denied = unauthorized.run(['--publish', '--version', version]);
  assert.notEqual(denied.status, 0);
  assert.match(denied.stderr, /PHANTOM_PUBLISH_CONFIRM/);
  assert.doesNotMatch(readFileSync(unauthorized.cargoLog, 'utf8'), /^publish /m);

  const harness = makeHarness();
  const result = harness.run(
    ['--publish', '--version', version],
    {
      PHANTOM_PUBLISH_CONFIRM: `publish-phantom-secrets-${version}`,
      PHANTOM_TEST_REMOTE_MODE: 'after-publish',
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Publication complete: 12 published, 0 identical already present/);
  const published = readFileSync(harness.cargoLog, 'utf8')
    .split('\n')
    .filter((line) => line.startsWith('publish '))
    .map((line) => line.match(/ -p ([^ ]+)$/)?.[1]);
  assert.deepEqual(published, crates);
  assert.equal(readFileSync(harness.cargoLog, 'utf8').match(/^publish --registry crates-io /gm)?.length, 12);
  const tokenStates = readFileSync(harness.tokenLog, 'utf8').trim().split('\n');
  assert.equal(tokenStates.filter((line) => line === 'publish\tpresent').length, 12);
  assert.equal(tokenStates.filter((line) => line !== 'publish\tpresent' && line.endsWith('\tpresent')).length, 0);
  assert.match(readFileSync(harness.ghLog, 'utf8'), /release view v0\.7\.3.*\tpresent/);
});

test('publish requires remote tag parity and the exact completed GitHub release assets', () => {
  const wrongOrigin = makeHarness({ originUrl: 'https://github.com/example/fork.git' });
  const wrong = wrongOrigin.run(
    ['--publish', '--version', version],
    { PHANTOM_PUBLISH_CONFIRM: `publish-phantom-secrets-${version}` },
  );
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /origin is not the canonical/);

  const movedTag = makeHarness({ remoteSha: 'ffffffffffffffffffffffffffffffffffffffff' });
  const moved = movedTag.run(
    ['--publish', '--version', version],
    { PHANTOM_PUBLISH_CONFIRM: `publish-phantom-secrets-${version}` },
  );
  assert.notEqual(moved.status, 0);
  assert.match(moved.stderr, /origin tag .* does not resolve to local HEAD/);

  const incompleteRelease = makeHarness({ missingReleaseAsset: true });
  const incomplete = incompleteRelease.run(
    ['--publish', '--version', version],
    { PHANTOM_PUBLISH_CONFIRM: `publish-phantom-secrets-${version}` },
  );
  assert.notEqual(incomplete.status, 0);
  assert.match(incomplete.stderr, /GitHub release asset set mismatch/);
  assert.doesNotMatch(readFileSync(incompleteRelease.cargoLog, 'utf8'), /^publish /m);

  const extraRelease = makeHarness({ extraReleaseAsset: true });
  const extra = extraRelease.run(
    ['--publish', '--version', version],
    { PHANTOM_PUBLISH_CONFIRM: `publish-phantom-secrets-${version}` },
  );
  assert.notEqual(extra.status, 0);
  assert.match(extra.stderr, /GitHub release asset set mismatch/);
});

test('metadata drift aborts before source gates or packaging', () => {
  const harness = makeHarness({ omitLast: true });
  const result = harness.run(['--verify-only', '--allow-dirty']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /publication set mismatch/);
  const log = readFileSync(harness.cargoLog, 'utf8');
  assert.doesNotMatch(log, /^(fmt|clippy|test|package|publish) /m);

  const wrongRegistry = makeHarness({ wrongRegistry: true });
  const registryResult = wrongRegistry.run(['--verify-only', '--allow-dirty']);
  assert.notEqual(registryResult.status, 0);
  assert.match(registryResult.stderr, /must allow publication only to crates-io/);
});
