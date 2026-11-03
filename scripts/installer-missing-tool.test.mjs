import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync,
  rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = {
  repository: join(repo, 'scripts', 'install.sh'),
  public: join(repo, 'apps', 'web', 'public', 'install.sh'),
};

// Run the installer with PATH limited to a directory holding only the stub
// commands listed in `present`, so every other download tool is missing.
function run(installer, root, present) {
  const shims = join(root, 'shims');
  mkdirSync(shims);
  for (const name of present) {
    writeFileSync(join(shims, name), '#!/bin/sh\nexit 99\n');
    chmodSync(join(shims, name), 0o755);
  }
  const home = join(root, 'home');
  const install = join(root, 'live', 'bin');
  mkdirSync(home);
  const result = spawnSync('/bin/bash', [installer], {
    encoding: 'utf8',
    timeout: 30000,
    env: { HOME: home, SHELL: '/bin/bash', PATH: shims, PHANTOM_INSTALL_DIR: install },
  });
  return { result, install };
}

const cases = [
  { missing: 'curl', present: ['tar'] },
  { missing: 'tar', present: ['curl'] },
];

for (const [name, installer] of Object.entries(installers)) {
  for (const { missing, present } of cases) {
    test(`${name} installer fails clearly and installs nothing when ${missing} is missing`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-missing-tool-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const { result, install } = run(installer, root, present);

      assert.ifError(result.error);
      assert.equal(result.status, 1);
      assert.match(result.stderr, new RegExp(`phantom: ${missing} is required to \\w+ Phantom\\. Install ${missing} with your package manager`));
      assert.match(result.stderr, /then re-run this installer/);
      assert.doesNotMatch(result.stdout, /downloading|installed/i);
      assert.equal(existsSync(join(install, 'phantom')), false, 'no phantom executable');
      assert.equal(existsSync(join(install, 'phantom-mcp')), false, 'no phantom-mcp executable');
      assert.equal(existsSync(install), false, 'install directory not created');
      assert.deepEqual(readdirSync(join(root, 'home')), [], 'home untouched');
      assert.deepEqual(readdirSync(root).sort(), ['home', 'shims']);
    });
  }
}
