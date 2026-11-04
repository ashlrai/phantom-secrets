import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

// The source installer and its published web copy must both stage freshly.
const installers = ['../scripts/install.sh', '../apps/web/public/install.sh']
  .map((path) => fileURLToPath(new URL(path, import.meta.url)));

// Two isolated offline installs (own HOME, same install parent) must each stage
// in a fresh mktemp directory: never a shared or reused fixed path.
for (const installer of installers) {
test(`installer staging directories are distinct per invocation under one parent: ${basename(dirname(installer))}`, (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-unique-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture');
  const payload = join(root, 'payload');
  const parent = join(root, 'parent');
  const install = join(parent, 'bin');
  for (const dir of [fixture, payload, parent]) mkdirSync(dir);
  const version = '1.2.3';
  const record = join(root, 'stage-paths.log');
  for (const product of ['phantom', 'phantom-mcp']) {
    const binary = join(payload, product);
    writeFileSync(binary, `#!/bin/sh
[ "$1" = --version ] || exit 2
printf '%s\\n' "$0" >> "$PHANTOM_TEST_RECORD"
echo '${product} ${version}'
`);
    chmodSync(binary, 0o755);
  }
  const archive = 'phantom-x86_64-apple-darwin.tar.gz';
  const archivePath = join(fixture, archive);
  execFileSync('tar', ['-czf', archivePath, '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
  writeFileSync(`${archivePath}.sha256`, `${digest}  ${archive}\n`);

  const shims = join(root, 'shims');
  mkdirSync(shims);
  writeFileSync(join(shims, 'uname'), `#!/bin/sh
case "$1" in -s) echo Darwin ;; -m) echo x86_64 ;; *) exit 2 ;; esac
`);
  chmodSync(join(shims, 'uname'), 0o755);

  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.startsWith('PHANTOM_')) delete env[name];

  const run = (n) => {
    const home = join(root, `home-${n}`);
    mkdirSync(home);
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
        PHANTOM_TEST_RECORD: record,
      },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    const stages = readFileSync(record, 'utf8').trim().split('\n')
      .filter((path) => path.includes('.bin.install.'))
      .map((path) => dirname(dirname(path)));
    rmSync(record, { force: true });
    const unique = [...new Set(stages)];
    assert.equal(unique.length, 1, 'each run uses a single staging directory');
    return unique[0];
  };

  const first = run(1);
  const second = run(2);
  assert.notEqual(first, second, 'staging paths must differ between invocations');
  for (const stage of [first, second]) {
    assert.equal(dirname(stage), parent, 'staging lives under the shared parent');
    assert.match(basename(stage), /^\.bin\.install\.[A-Za-z0-9]{6,}$/);
    assert.equal(existsSync(stage), false, 'staging is cleaned up');
  }
});
}

// Executes each checked-in installer's own staging-creation lines (extracted
// from its source, so they cannot drift) twice against one parent. Needs no
// release fixture or executable payload, so it also runs where fake binaries
// cannot.
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
for (const installer of installers) {
const label = relative(repoRoot, installer);
test(`${label} staging creation yields distinct private directories`, (t) => {
  const source = readFileSync(installer, 'utf8');
  const block = source.match(/^stage_root="\$\(mktemp -d [^\n]*\n(?:  \|\| die [^\n]*\n)?chmod 700 "\$stage_root"[^\n]*\n/m);
  assert.ok(block, `staging creation block not found in ${label}`);
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-staging-block-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const script = `die() { echo "$1" >&2; exit 1; }
install_parent=${JSON.stringify(root)}
install_name=bin
${block[0]}printf '%s' "$stage_root"
`;
  const stage = () => {
    const result = spawnSync('/bin/bash', ['-c', script], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  const first = stage();
  const second = stage();
  assert.notEqual(first, second, 'two staging creations must not share a directory');
  for (const dir of [first, second]) {
    assert.equal(dirname(dir), root);
    assert.match(basename(dir), /^\.bin\.install\.[A-Za-z0-9]{6,}$/);
    assert.equal(statSync(dir).mode & 0o777, 0o700, 'staging directory is private');
  }
});
}
