import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('./affected-filterset.sh', import.meta.url));

function classify(paths, options = {}) {
  const cwd = mkdtempSync(join(tmpdir(), 'affected-filter-'));
  try {
    const commands = { git: options.gitFailure ? 'exit 1' : 'case " $* " in *" -z "*) cat diff-nul;; *) cat diff-lines;; esac',
      cargo: options.cargoFailure ? 'exit 1' : 'cat metadata.json' };
    for (const [name, command] of Object.entries(commands)) {
      writeFileSync(join(cwd, name), '#!/usr/bin/env bash\n' + command + '\n', { mode: 0o700 });
    }
    writeFileSync(join(cwd, 'diff-nul'), paths.map(path => path + '\0').join(''));
    writeFileSync(join(cwd, 'diff-lines'), paths.map(path => path + '\n').join(''));
    writeFileSync(join(cwd, 'metadata.json'), JSON.stringify({
      workspace_root: '/workspace',
      packages: [{ manifest_path: '/workspace/crates/core/Cargo.toml', name: 'workspace-core' }],
      padding: ' '.repeat(options.largeMetadata ? 2 * 1024 * 1024 : 0),
    }));
    return spawnSync('bash', [script, 'base', 'head'], {
      cwd, env: { ...process.env, PATH: cwd + delimiter + process.env.PATH }, encoding: 'utf8',
    });
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

test('classifies workspace metadata larger than an operating system argument', () => {
  const result = classify(['crates/core/src/lib.rs'], { largeMetadata: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'rdeps(=workspace-core)\n');
});

test('reads each changed path as one record and retains full-suite selection', () => {
  assert.equal(classify(['crates/core/docs/one file.md']).stdout, 'none()\n');
  assert.equal(classify(['crates/core/src/one module.rs']).stdout, 'rdeps(=workspace-core)\n');
  assert.equal(classify(['Cargo.lock']).stdout, 'all()\n');
  assert.equal(classify([]).stdout, 'none()\n');
});

test('a failed evidence read cannot report no affected tests', () => {
  for (const options of [{ gitFailure: true }, { cargoFailure: true }]) {
    const result = classify(['crates/core/src/lib.rs'], options);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
  }
});
