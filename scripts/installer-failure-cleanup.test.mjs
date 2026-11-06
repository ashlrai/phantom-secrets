import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installer = fileURLToPath(new URL('install.sh', import.meta.url));
const version = '1.2.3';
const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
const archive = `phantom-${arch}-${os}.tar.gz`;
const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
const realTar = execFileSync('which', ['tar'], { encoding: 'utf8' }).trim();
const realChmod = execFileSync('which', ['chmod'], { encoding: 'utf8' }).trim();

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
  } else if (options.brokenPhantom) {
    writeFileSync(join(payload, 'phantom'), '#!/bin/sh\nexit 2\n');
  } else {
    writeFileSync(join(payload, 'phantom'), executable('phantom', options.phantomReports ?? version));
    chmodSync(join(payload, 'phantom'), 0o755);
  }
  writeFileSync(join(payload, 'phantom-mcp'), executable('phantom-mcp'));
  chmodSync(join(payload, 'phantom-mcp'), 0o755);
  if (options.extraMember) {
    writeFileSync(join(payload, 'extra'), 'unexpected');
    members.push('extra');
  }
  const archivePath = join(fixture, archive);
  execFileSync(realTar, ['-czf', archivePath, '-C', payload, ...members]);
  if (options.missingSidecar) return fixture;
  const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  writeFileSync(`${archivePath}.sha256`, options.sidecar ?? `${digest}  ${archive}\n`);
  return fixture;
}

// The mktemp shim delegates to the real tool and records every path it
// created, so a later "no staging directory" assertion can never pass
// vacuously on a stage that never existed. With PHANTOM_TEST_FIXED_STAGE set
// it answers the .install.XXXXXX template with a deterministic name, which
// makes the installer-derived backup path predictable enough to pre-create.
// Optional tar/chmod shims fail one exact installer call or leave an extra
// extracted file behind; every other call delegates to the real tool.
function makeShims(root, options = {}) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
for arg do
  case "$arg" in
    *.install.XXXXXX)
      if [ -n "\${PHANTOM_TEST_FIXED_STAGE:-}" ]; then
        fixed="\${arg%.install.XXXXXX}.install.\${PHANTOM_TEST_FIXED_STAGE}"
        /bin/mkdir -m 700 "$fixed" || exit 1
        printf '%s\\n' "$fixed" >> "$PHANTOM_TEST_STAGE_LOG"
        printf '%s\\n' "$fixed"
        exit 0
      fi
      ;;
  esac
done
created="$(${JSON.stringify(realMktemp)} "$@")" || exit $?
printf '%s\\n' "$created" >> "$PHANTOM_TEST_STAGE_LOG"
printf '%s\\n' "$created"
`);
  const tarRules = [];
  if (options.failTarOp) {
    tarRules.push(`if [ "$1" = ${JSON.stringify(options.failTarOp)} ]; then
  printf 'tar: injected failure\\n' >&2
  exit 42
fi`);
  }
  if (options.extraExtracted) {
    tarRules.push(`if [ "$1" = "--no-same-owner" ] && [ "$2" = "-xzf" ] && [ "$4" = "-C" ]; then
  ${JSON.stringify(realTar)} "$@" || exit $?
  printf 'stowaway\\n' > "$5/extra-member"
  exit 0
fi`);
  }
  if (options.notRegular) {
    // Extract for real, then replace one member with a directory: the archive
    // still passes listing and member-type checks, and the staged candidate
    // fails its per-member regular-file check.
    tarRules.push(`if [ "$1" = "--no-same-owner" ] && [ "$2" = "-xzf" ] && [ "$4" = "-C" ]; then
  ${JSON.stringify(realTar)} "$@" || exit $?
  rm -f "$5/${options.notRegular}"
  mkdir "$5/${options.notRegular}"
  exit 0
fi`);
  }
  if (tarRules.length) {
    writeFileSync(join(shims, 'tar'), `#!/bin/sh
${tarRules.join('\n')}
exec ${JSON.stringify(realTar)} "$@"
`);
  }
  if (options.failChmod) {
    writeFileSync(join(shims, 'chmod'), `#!/bin/sh
if [ "$1" = '755' ]; then
  printf 'chmod: injected failure\\n' >&2
  exit 42
fi
exec ${JSON.stringify(realChmod)} "$@"
`);
  }
  for (const name of readdirSync(shims)) chmodSync(join(shims, name), 0o755);
  return shims;
}

// Run the repository installer offline against a local release fixture. The
// staging directory always lands beside the install directory, so after a
// failure the parent's entry list proves every staging, backup, and lock
// sibling was removed.
function run(t, options = {}) {
  assert.ok(os && arch, 'test requires a supported Unix installer target');
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-installer-failure-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  const parent = dirname(install);
  const stageLog = join(root, 'stages.log');
  mkdirSync(home, { recursive: true });
  if (options.installAsFile) {
    mkdirSync(parent, { recursive: true });
    writeFileSync(install, 'preserve-me');
  } else {
    mkdirSync(install, { recursive: true });
    writeFileSync(join(install, 'old-install'), 'preserve-me');
  }
  const fixture = options.emptyFixture ? join(root, 'fixture') : makeRelease(root, options);
  if (options.emptyFixture) mkdirSync(fixture);
  const shims = makeShims(root, options);
  // Deriving backup_path from the fixed stage name lets the test pre-create
  // the collision the installer must refuse to reuse.
  if (options.fixedStage) mkdirSync(join(parent, `.bin.backup.${options.fixedStage}`));
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.startsWith('PHANTOM_')) delete env[name];
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
      PHANTOM_TAG: options.tag ?? `v${version}`,
      PHANTOM_TEST_STAGE_LOG: stageLog,
      ...(options.fixedStage ? { PHANTOM_TEST_FIXED_STAGE: options.fixedStage } : {}),
    },
  });
  return { root, home, install, parent, stageLog, result };
}

// Every assertion a clean failure owes: nonzero exit, the expected error, and
// the single staging directory the mktemp shim recorded now removed beside
// the install directory.
function assertCleanFailure({ home, parent, stageLog, result }, error) {
  assert.ifError(result.error);
  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, error);
  const stages = readFileSync(stageLog, 'utf8').split('\n').filter(Boolean);
  assert.equal(stages.length, 1, 'exactly one staging directory was created');
  const [stage] = stages;
  assert.equal(dirname(stage), parent);
  assert.match(basename(stage), /^\.bin\.install\.[^/]+$/);
  assert.equal(existsSync(stage), false, 'staging directory must be removed');
  assert.deepEqual(readdirSync(home), [], 'HOME must contain no temporary files');
}

// The preexisting destination kept its sentinel bytes and the parent holds
// exactly the expected names — no stage or lock sibling remains.
function assertLivePreserved({ install, parent }, expectedParent = ['bin']) {
  assert.deepEqual(readdirSync(install), ['old-install']);
  assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(parent).sort(), [...expectedParent].sort());
}

// The staging directory is created before the release tag is validated, so
// even this early validation failure must still remove the empty stage.
test('repository installer leaves no staging directory when the release tag is malformed', (t) => {
  const ctx = run(t, { tag: 'not a tag' });
  assertCleanFailure(ctx, /release tag is not strict semantic version syntax/);
  assertLivePreserved(ctx);
});

// Each failure below happens after the staging tree exists but before the
// candidate is promoted, while the staging download and candidate
// directories are at most partly populated. The staged-download, staged-
// candidate, SHA-256-mismatch, post-promotion, and interrupt failure points
// are covered by the sibling staging/extraction/download/promotion tests.
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
    name: 'a tar member-type inspection failure',
    options: { failTarOp: '-tvzf' },
    error: /could not inspect release archive member types/,
  },
  {
    name: 'an unexpected file appearing in the extracted candidate',
    options: { extraExtracted: true },
    error: /candidate contains unexpected files/,
  },
  {
    name: 'an extracted phantom that is not a regular file',
    options: { notRegular: 'phantom' },
    error: /phantom is not a regular file/,
  },
  {
    name: 'an extracted phantom-mcp that is not a regular file',
    options: { notRegular: 'phantom-mcp' },
    error: /phantom-mcp is not a regular file/,
  },
  {
    name: 'a candidate binary that cannot report its version',
    options: { brokenPhantom: true },
    error: /phantom --version failed/,
  },
]) {
  test(`repository installer leaves no staging directory after ${name}`, (t) => {
    const ctx = run(t, options);
    assertCleanFailure(ctx, error);
    assertLivePreserved(ctx);
  });
}

// The last failure before binary verification is an implicit set -e exit
// rather than a die() message: the shimmed chmod fails only the 755 call that
// secures the extracted candidates, after both members were extracted into
// the staging candidate directory.
test('repository installer removes the populated staging tree when securing candidates fails', (t) => {
  const ctx = run(t, { failChmod: true });
  assertCleanFailure(ctx, /chmod: injected failure/);
  assertLivePreserved(ctx);
});

// The remaining seams sit behind the candidate --version probes, so they
// need a host that can execute the fixture stub binaries (the CI Linux leg
// does; like installer-promotion-failure-cleanup.test.mjs they cannot run
// where a name-based launch constraint keeps `phantom` binaries from exec).

// A candidate that runs but reports a different version dies at the
// verify_binary_version guard before the receipt is written or any move.
test('repository installer leaves no staging directory after a candidate binary reports the wrong version', (t) => {
  const ctx = run(t, { phantomReports: '9.9.9' });
  assertCleanFailure(ctx, /phantom reported an unexpected version/);
  assertLivePreserved(ctx);
});

// A regular file at the destination trips the late "is a directory" guard —
// after the candidate is fully validated — and must not be disturbed, just as
// no staging or lock sibling may remain.
test('repository installer leaves no staging directory when the install path is a regular file', (t) => {
  const ctx = run(t, { installAsFile: true });
  assertCleanFailure(ctx, /install path exists and is not a directory/);
  assert.equal(readFileSync(ctx.install, 'utf8'), 'preserve-me');
  assert.deepEqual(readdirSync(ctx.parent), ['bin']);
});

// The derived backup path is collision-checked before any move: a preexisting
// sibling makes the installer die with the stage populated, and cleanup must
// remove the stage and lock without touching the foreign backup directory.
test('repository installer leaves no staging directory when the private backup path already exists', (t) => {
  const ctx = run(t, { fixedStage: 'preseeded' });
  assertCleanFailure(ctx, /private backup path already exists/);
  assertLivePreserved(ctx, ['.bin.backup.preseeded', 'bin']);
  assert.deepEqual(readdirSync(join(ctx.parent, '.bin.backup.preseeded')), []);
});
