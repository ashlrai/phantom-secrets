import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const installer = fileURLToPath(new URL('../apps/web/public/install.sh', import.meta.url));

// Two isolated offline installs (own HOME, same install parent) must each stage
// in a fresh mktemp directory: never a shared or reused fixed path.
test('installer staging directories are distinct per invocation under one parent', (t) => {
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
