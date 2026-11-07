import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { pathUpdateHarness } from './lib/installer-path-harness.mjs';
import {
  assertMode600,
  assertNoPathTempFiles,
  createStartupFixture,
  managedBlock,
  marker,
  pathShellConfigs,
} from './lib/installer-path-test-fixtures.mjs';

// A startup file that exists but is zero bytes (e.g. `touch ~/.zshrc`) must get
// exactly one managed PATH block: marker and PATH line on their own lines,
// nothing else added or lost, mode preserved, and a repeat update a no-op.
// The resulting file must also be valid shell syntax: `bash -n` parses every
// leg (the bash/zsh template is POSIX; the fish template still tokenizes as a
// simple command, so a malformed write fails there too), and each leg must
// additionally parse under its own shell's no-execute check when that shell is
// installed (macOS has zsh; fish is absent from CI runners, so those checks are
// additive rather than required). The absent-startup-file shape is covered by
// installer-path-empty-config.test.mjs. The shipped add_to_user_path is
// extracted verbatim and run directly through the shared PATH-update fixture.
const installers = {
  'scripts/install.sh': new URL('install.sh', import.meta.url),
  'apps/web/public/install.sh': new URL('../apps/web/public/install.sh', import.meta.url),
};

const shells = pathShellConfigs({});

// `bash -n` parses without executing and is always available — it is the
// harness interpreter. A target shell's own no-execute parse runs only when
// that shell resolves on PATH: CI runners ship neither zsh nor fish, while
// macOS ships zsh, so the native checks are additive coverage, never a gate
// on host tooling.
const nativeParser = {
  zsh: ['zsh', '-n'],
  fish: ['fish', '--no-execute'],
};

function assertValidShellSyntax(path, shellName) {
  const bash = spawnSync('/bin/bash', ['-n', path], { encoding: 'utf8', timeout: 30000 });
  assert.ifError(bash.error);
  assert.equal(bash.status, 0, `bash -n ${path}: ${bash.stderr}`);
  const native = nativeParser[shellName];
  if (native && !spawnSync(native[0], ['--version'], { timeout: 10000 }).error) {
    const check = spawnSync(native[0], [native[1], path], { encoding: 'utf8', timeout: 30000 });
    assert.ifError(check.error);
    assert.equal(check.status, 0, `${native[0]} ${native[1]} ${path}: ${check.stderr}`);
  }
}

for (const [label, url] of Object.entries(installers)) {
  const source = readFileSync(fileURLToPath(url), 'utf8');
  const harness = pathUpdateHarness(source, label);

  for (const [shellName, config] of Object.entries(shells)) {
    test(`${label} wires an initially empty ${shellName} startup file once, leaving valid ${shellName} syntax`, (t) => {
      const fixture = createStartupFixture(t, {
        prefix: 'phantom-path-empty-', harness, config, content: '',
      });
      assert.equal(statSync(fixture.rc).size, 0);

      const first = fixture.run();
      assert.match(first.stdout, /added .* to PATH/);
      const wired = readFileSync(fixture.rc, 'utf8');
      assert.equal(wired, managedBlock(config, fixture.bin),
        'only the managed block is written, each entry on its own line');
      const lines = wired.split('\n');
      assert.equal(lines.filter((l) => l === marker).length, 1,
        'exactly one installer-managed PATH marker');
      assert.equal(lines.filter((l) => l === config.line(fixture.bin)).length, 1,
        'exactly one installer-managed PATH line');
      assertMode600(fixture.rc);

      const second = fixture.run();
      assert.match(second.stdout, /already wired into/);
      assert.equal(readFileSync(fixture.rc, 'utf8'), wired, 'repeat update leaves the file unchanged');
      assertNoPathTempFiles(fixture.rc);

      // The resulting file — which the user is told to source — must parse.
      // The repeat update left it byte-identical, so this also proves the
      // first write itself was well-formed.
      assertValidShellSyntax(fixture.rc, shellName);
    });
  }
}

// A syntax gate is only worth keeping if it fails on broken input: a startup
// file left unparseable must be rejected by every leg — the bash -n check each
// shell configuration runs, plus each native no-execute parser the host has
// installed (the helper's bash -n leg always fires first, so the native
// parsers are probed directly to keep their rejection coverage).
test('the startup-file syntax check rejects a corrupted file for every shell', (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-empty-syntax-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rc = join(root, '.bashrc');
  writeFileSync(rc, `\n${marker}\nexport PATH="unclosed\n`, { mode: 0o600 });
  for (const shellName of Object.keys(shells)) {
    assert.throws(() => assertValidShellSyntax(rc, shellName), /bash -n/,
      `${shellName} leg must reject the corrupted file`);
  }
  for (const [name, parser] of Object.entries(nativeParser)) {
    if (spawnSync(parser[0], ['--version'], { timeout: 10000 }).error) continue;
    const check = spawnSync(parser[0], [parser[1], rc], { encoding: 'utf8', timeout: 30000 });
    assert.ifError(check.error);
    assert.notEqual(check.status, 0,
      `${parser[0]} ${parser[1]} must reject the corrupted file`);
  }
});
