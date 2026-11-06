import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  assertUnrelatedOrderKept,
  pathShellConfigs,
  unrelatedOrderLines,
} from './lib/installer-path-test-fixtures.mjs';

// The sibling installer-path-unrelated-order suite extracts add_to_user_path
// and proves order preservation at function level. This file proves the same
// property through the entire shipped installer — offline download, checksum
// verification, archive-shape validation, promotion, then the PATH update the
// script runs at the end — for both installer copies and every supported
// shell startup file. The fixtures reuse the order-sensitive line sets: ZEBRA
// precedes ALPHA so a sort visibly reorders them, two unrelated PATH prepends
// make precedence depend on position, and SHARED is assigned twice. Each
// original line is located in the result by a forward scan, so a missing or
// reordered line fails — multiple unrelated rc lines retain their original
// relative order after the update.
const shells = pathShellConfigs(unrelatedOrderLines());

// Same offline release fixture shape as installer-path-comments-integration,
// but the shim is a compiled binary rather than a `#!/bin/sh` script. Real
// release members are Mach-O/ELF too, and a script member cannot exec under
// macOS provenance rules, which would keep this test off developer laptops.
// The shim reports "<argv0 basename> 1.2.3" so one binary serves both
// release names under verify_binary_version.
function stageRelease(root, os, arch) {
  const fixture = join(root, 'release');
  const payload = join(root, 'payload');
  mkdirSync(fixture, { recursive: true });
  mkdirSync(payload, { recursive: true });
  const source = join(root, 'shim.c');
  writeFileSync(source, '#include <stdio.h>\n#include <string.h>\n'
    + 'int main(int argc, char **argv) {\n'
    + '  const char *base = argc > 0 ? strrchr(argv[0], \'/\') : 0;\n'
    + '  const char *name = base ? base + 1 : (argc > 0 ? argv[0] : "?");\n'
    + '  printf("%s 1.2.3\\n", name);\n'
    + '  return 0;\n'
    + '}\n');
  const compiler = ['cc', 'gcc', 'clang']
    .find((cc) => spawnSync(cc, ['--version'], { encoding: 'utf8' }).status === 0);
  assert.ok(compiler, 'test requires a C compiler for the release shim');
  execFileSync(compiler, [source, '-o', join(payload, 'phantom')]);
  // Self-check the shim before it goes in the archive. This also surfaces a
  // clear error on hosts where locally built binaries cannot exec (e.g.
  // macOS Gatekeeper provenance denial), instead of a downstream
  // "phantom --version failed" from inside the installer.
  const probe = spawnSync(join(payload, 'phantom'), ['--version'], { encoding: 'utf8' });
  assert.equal(probe.status, 0,
    `release shim cannot exec on this host: ${probe.stderr || probe.error || probe.status}`);
  assert.equal(probe.stdout, 'phantom 1.2.3\n', 'release shim reports an unexpected version');
  execFileSync('cp', [join(payload, 'phantom'), join(payload, 'phantom-mcp')]);
  const archive = `phantom-${arch}-${os}.tar.gz`;
  execFileSync('tar', ['-czf', join(fixture, archive), '-C', payload, 'phantom', 'phantom-mcp']);
  const digest = createHash('sha256').update(readFileSync(join(fixture, archive))).digest('hex');
  writeFileSync(join(fixture, `${archive}.sha256`), `${digest}  ${archive}\n`);
  return fixture;
}

for (const installer of ['install.sh', '../apps/web/public/install.sh']) {
  for (const [shellName, config] of Object.entries(shells)) {
    test(`${installer} keeps unrelated ${shellName} rc lines in their original order through a complete install`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-order-install-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const bin = join(root, 'live', 'bin');
      const rc = config.rc(home);
      mkdirSync(dirname(rc), { recursive: true });
      const original = `${config.unrelated.join('\n')}\n`;
      writeFileSync(rc, original, { mode: 0o600 });
      const os = { darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[process.platform];
      const arch = { x64: 'x86_64', arm64: 'aarch64' }[process.arch];
      assert.ok(os && arch, 'test requires a supported Unix installer target');
      const fixture = stageRelease(root, os, arch);
      const env = {
        HOME: home, SHELL: config.shell, PATH: '/usr/local/bin:/usr/bin:/bin',
        PHANTOM_INSTALL_DIR: bin, PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: '1',
        PHANTOM_TEST_LOCAL_RELEASE_DIR: fixture, PHANTOM_TAG: 'v1.2.3',
      };

      const result = spawnSync('/bin/bash', [fileURLToPath(new URL(installer, import.meta.url))],
        { encoding: 'utf8', timeout: 30000, env });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /added .* to PATH/);
      for (const name of ['phantom', 'phantom-mcp']) assert.ok(existsSync(join(bin, name)));

      assertUnrelatedOrderKept(rc, original, config, bin);

      if (shellName !== 'bash') return;
      // Order observed is order preserved: sourcing the updated .bashrc puts
      // the install dir first, then the two unrelated prepends in their
      // original precedence, and every unrelated setting still evaluates.
      const check = spawnSync('/bin/bash', ['--noprofile', '--norc', '-c',
        'shopt -s expand_aliases; . "$HOME/.bashrc" && '
        + '[[ "$SHARED" == final ]] && [[ "$WIDGET" == on ]] '
        + '&& alias ll >/dev/null && declare -F jump >/dev/null && '
        + `[[ "$PATH" == "${bin}:/opt/aaa-later/bin:/opt/zzz-earlier/bin:${env.PATH}" ]]`,
      ], { encoding: 'utf8', timeout: 30000, env: { HOME: home, PATH: env.PATH } });
      assert.ifError(check.error);
      assert.equal(check.status, 0, check.stderr);
    });
  }
}
