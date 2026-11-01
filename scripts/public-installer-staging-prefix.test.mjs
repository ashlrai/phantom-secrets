import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const read = (path) => readFileSync(join(repo, path), 'utf8');
const doc = read('docs/public-installer-staging-prefix.md');
const installer = 'apps/web/public/install.sh';

test('public staging documentation cites the implementation and its template', () => {
  const source = read(installer);
  for (const fragment of [
    'INSTALL_DIR="${PHANTOM_INSTALL_DIR:-$HOME/.phantom-secrets/bin}"',
    'install_parent="$(dirname "$INSTALL_DIR")"',
    'install_name="$(basename "$INSTALL_DIR")"',
    'install_parent="$(cd "$install_parent" && pwd -P)"',
    'stage_root="$(mktemp -d "$install_parent/.${install_name}.install.XXXXXX")"',
  ]) assert.ok(source.includes(fragment), `review documentation: installer changed ${fragment}`);
  for (const term of ['<install_parent>/.<install_name>.install.XXXXXX', 'PHANTOM_INSTALL_DIR', 'TMPDIR', 'stage_root', 'pwd -P']) {
    assert.ok(doc.includes(term), `documentation must cover ${term}`);
  }
  assert.match(read('docs/README.md'), /\]\(public-installer-staging-prefix\.md\)/);
  const links = [...doc.matchAll(/\]\(\.\.\/apps\/web\/public\/install\.sh#L(\d+)(?:-L(\d+))?\)/g)];
  assert.ok(links.length >= 5, 'expected public installer source citations');
  const lines = source.split('\n');
  for (const [, first, last = first] of links) {
    assert.ok(+first > 0 && +last >= +first && +last <= lines.length);
    assert.ok(lines.slice(+first - 1, +last).some((line) => line.trim()));
  }
});

test('public installer stages under the physical install parent and cleans up on failure', () => {
  const root = mkdtempSync(join(tmpdir(), 'phantom-public-stage-test-'));
  try {
    const home = join(root, 'home');
    const shims = join(root, 'shims');
    const temp = join(root, 'other-temp');
    const physical = join(root, 'physical parent');
    const alias = join(root, 'alias');
    for (const path of [home, shims, temp, physical]) mkdirSync(path);
    symlinkSync(physical, alias);
    const log = join(root, 'stage-log');
    const mktemp = join(shims, 'mktemp');
    writeFileSync(mktemp, '#!/bin/sh\nprintf "%s\\n" "$2" > "$STAGE_TEST_LOG"\nstage=$(/usr/bin/mktemp "$@") || exit $?\nprintf "%s\\n" "$stage" >> "$STAGE_TEST_LOG"\nprintf "%s\\n" "$stage"\n');
    chmodSync(mktemp, 0o755);
    const curl = join(shims, 'curl');
    writeFileSync(curl, '#!/bin/sh\nexit 1\n');
    chmodSync(curl, 0o755);
    for (const [override, parent, name] of [
      [undefined, join(realpathSync(home), '.phantom-secrets'), 'bin'],
      [join(alias, 'tools'), realpathSync(physical), 'tools'],
    ]) {
      const env = { HOME: home, PATH: `${shims}:/usr/bin:/bin:/usr/sbin:/sbin`, TMPDIR: temp, STAGE_TEST_LOG: log };
      if (override) env.PHANTOM_INSTALL_DIR = override;
      const result = spawnSync('/bin/bash', [join(repo, installer)], { env, encoding: 'utf8', timeout: 10000 });
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /download failed/);
      const [template, stage] = readFileSync(log, 'utf8').trim().split('\n');
      assert.equal(template, join(parent, `.${name}.install.XXXXXX`));
      assert.ok(stage.startsWith(join(parent, `.${name}.install.`)));
      assert.equal(existsSync(stage), false, 'failure should clean up the stage');
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
