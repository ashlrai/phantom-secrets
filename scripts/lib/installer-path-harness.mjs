import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import assert from 'node:assert/strict';

// Extract the shipped shell functions verbatim, including one-line helpers.
export function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  assert.ok(lineEnd > start, `${file}: locate end of ${name}`);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) {
    return source.slice(start, lineEnd + 1);
  }
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

export function pathUpdateHarness(source, file) {
  return ['set -euo pipefail', 'umask 077',
    ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
      .map((name) => extractFunction(source, name, file)),
    'add_to_user_path "$1"',
  ].join('\n');
}

// Own each synthetic startup-file fixture and exercise the shipped harness with
// the same bounded, credential-free shell invocation for every preservation case.
export function createPathUpdateFixture(t, { prefix, harness, config }) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const bin = join(root, 'live', 'bin');
  const rc = config.rc(home);
  mkdirSync(dirname(rc), { recursive: true });
  mkdirSync(bin, { recursive: true });
  const run = () => {
    const result = spawnSync('/bin/bash', ['-c', harness, 'path-test', bin], {
      encoding: 'utf8',
      timeout: 30000,
      env: { HOME: home, SHELL: config.shell, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    return result;
  };
  return { root, home, bin, rc, run };
}

// Exact startup-file locations and managed line forms shared by the full-install
// regressions. Optional preseed text belongs to each caller's fixture contract.
export function installerPathShellCases(preseed = {}) {
  const rows = [
    ['bash', '/bin/bash', (home) => join(home, '.bashrc'), (bin) => `export PATH="${bin}:$PATH"`],
    ['zsh', '/bin/zsh', (home) => join(home, '.zshrc'), (bin) => `export PATH="${bin}:$PATH"`],
    ['fish', '/usr/bin/fish', (home) => join(home, '.config', 'fish', 'config.fish'), (bin) => `set -gx PATH "${bin}" $PATH`],
  ];
  return Object.fromEntries(rows.map(([name, shell, rc, pathLine]) => [name, {
    shell, rc, pathLine,
    ...(Object.hasOwn(preseed, name) ? { preseed: preseed[name] } : {}),
  }]));
}
