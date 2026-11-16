import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync,
  realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const repo = resolve(import.meta.dirname, '..');
const installers = [
  ['repository', join(repo, 'scripts', 'install.sh')],
  ['public', join(repo, 'apps', 'web', 'public', 'install.sh')],
];

// The staging directory is created by mktemp, secured by chmod, then split into
// download/ and candidate/ by mkdir. Each failure requires a nonzero exit, a named diagnostic,
// no download, an untouched destination, and no leftover stage sibling.
const cases = [
  {
    name: 'mktemp cannot create the staging directory',
    shim: 'mktemp',
    body: (real) => `#!/bin/sh
if [ "$1" = -d ]; then
  case "$2" in *.install.XXXXXX)
    : > "$HOME/mktemp-invoked"
    echo "mktemp: simulated failure" >&2; exit 1 ;;
  esac
fi
exec ${JSON.stringify(real)} "$@"
`,
    message: /could not create a private staging directory/,
  },
  {
    name: 'chmod cannot secure the staging directory',
    shim: 'chmod',
    // Only the call that secures the freshly created stage root (a lone 700 on a
    // ".install." path) fails; every other chmod passes through.
    body: (real) => `#!/bin/sh
if [ "$1" = 700 ] && [ "$#" = 2 ]; then
  case "$2" in *.install.*) echo "chmod: simulated failure" >&2; exit 1 ;; esac
fi
exec ${JSON.stringify(real)} "$@"
`,
    message: /could not secure the staging directory/,
  },
  {
    name: 'mkdir cannot create the staging subdirectories',
    shim: 'mkdir',
    body: (real) => `#!/bin/sh
# Only the two-directory call for download/ and candidate/ fails; the lock
# directory (also mkdir -m 700) must still be acquirable.
if [ "$1" = -m ] && [ "$2" = 700 ] && [ "$#" = 4 ]; then
  echo "mkdir: simulated failure" >&2; exit 1
fi
exec ${JSON.stringify(real)} "$@"
`,
    message: /could not create staging directories/,
  },
];

for (const [label, installer] of installers) {
  for (const c of cases) {
    test(`${label} installer exits nonzero and cleans up when ${c.name}`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), `phantom-staging-setup-${label}-`)));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const shims = join(root, 'shims');
      const parent = join(root, 'live');
      const install = join(parent, 'bin');
      const curlLog = join(root, 'curl.log');
      mkdirSync(home);
      mkdirSync(shims);
      mkdirSync(install, { recursive: true });
      writeFileSync(join(install, 'old-install'), 'preserve-me');
      const real = spawnSync('/bin/sh', ['-c', `command -v ${c.shim}`], { encoding: 'utf8' }).stdout.trim();
      assert.ok(real, `${c.shim} must exist on PATH`);
      writeFileSync(join(shims, c.shim), c.body(real));
      chmodSync(join(shims, c.shim), 0o755);
      writeFileSync(join(shims, 'curl'), `#!/bin/sh
printf '%s\\n' "$*" >> "$PHANTOM_TEST_CURL_LOG"
exit 22
`);
      chmodSync(join(shims, 'curl'), 0o755);

      const result = spawnSync('/bin/bash', [installer], {
        encoding: 'utf8',
        timeout: 30000,
        env: {
          PATH: `${shims}:${process.env.PATH}`,
          HOME: home,
          SHELL: '/bin/bash',
          PHANTOM_INSTALL_DIR: install,
          PHANTOM_TEST_CURL_LOG: curlLog,
        },
      });

      assert.ifError(result.error);
      assert.notEqual(result.status, 0, result.stderr);
      assert.match(result.stderr, c.message);
      assert.match(result.stderr, /simulated failure/, 'the underlying diagnostic stays visible');
      assert.doesNotMatch(result.stdout, /downloading|checksum|installed to/);
      assert.equal(existsSync(curlLog), false, 'staging failure must precede any download');
      assert.deepEqual(readdirSync(install), ['old-install']);
      assert.equal(readFileSync(join(install, 'old-install'), 'utf8'), 'preserve-me');
      assert.deepEqual(readdirSync(parent), ['bin'], 'no stage, lock, or backup sibling may remain');
      if (c.shim === 'mktemp') {
        assert.deepEqual(readdirSync(home), ['mktemp-invoked'], 'the staging failure was injected');
      } else {
        assert.deepEqual(readdirSync(home), [], 'HOME must contain no leftover files');
      }
    });
  }
}
