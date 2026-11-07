import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// The PATH update creates its two temporary files as private siblings of the
// shell startup file: mktemp makes `.phantom-path.before.XXXXXX` and
// `.phantom-path.candidate.XXXXXX` under the startup file's resolved parent,
// never under TMPDIR, and a successful update removes both — the candidate by
// promotion onto the startup file, the snapshot by rm. An instrumented mktemp
// records the real path each call creates, and an instrumented mv records the
// startup parent's listing at promotion, so placement is observed on disk
// rather than inferred from the template strings.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

// Same function boundary as installer-path-temp-failure.test.mjs: the
// PATH-update function ends where the installer's top-level checks begin.
function pathUpdateFunction(source, file) {
  const start = source.indexOf('add_to_user_path() {\n');
  const end = source.indexOf('\n}\n\ncommand -v curl', start);
  assert.ok(start >= 0 && end > start, `${file}: locate the installer PATH-update function`);
  return source.slice(start, end + '\n}'.length);
}

// add_to_user_path also calls the installer's say, file_identity, and
// file_link_count helpers, so the harness assembles them with the function.
// Each helper's closing brace is the first bare `}` line after its header.
function helperFunction(source, name, file) {
  const start = source.indexOf(`${name}() {\n`);
  const end = source.indexOf('\n}\n', start);
  assert.ok(start >= 0 && end > start, `${file}: locate the ${name} helper`);
  return source.slice(start, end + '\n}'.length);
}

function harness(source, file) {
  const say = source.match(/^say\(\)[^\n]*$/m);
  assert.ok(say, `${file}: locate the say helper`);
  return [
    'umask 077',
    say[0],
    helperFunction(source, 'file_identity', file),
    helperFunction(source, 'file_link_count', file),
    pathUpdateFunction(source, file),
    'add_to_user_path "$1"',
  ].join('\n');
}

const harnesses = Object.fromEntries(
  Object.entries(copies).map(([file, path]) => [file, harness(readFileSync(path, 'utf8'), file)]),
);

const realMktemp = execFileSync('which', ['mktemp'], { encoding: 'utf8' }).trim();
const realMv = execFileSync('which', ['mv'], { encoding: 'utf8' }).trim();

// Shell-selection coverage: bash and zsh use a startup file directly under
// HOME; fish uses a nested `~/.config/fish` parent the function may create.
const shells = [
  { name: 'bash', env: '/bin/bash', rcRel: '.bashrc', pathLine: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'zsh', env: '/bin/zsh', rcRel: '.zshrc', pathLine: (bin) => `export PATH="${bin}:$PATH"` },
  { name: 'fish', env: '/usr/bin/fish', rcRel: join('.config', 'fish', 'config.fish'), pathLine: (bin) => `set -gx PATH "${bin}" $PATH` },
];

function strayTemps(dir) {
  const found = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...strayTemps(path));
    else if (entry.name.startsWith('.phantom-path.')) found.push(path);
  }
  return found;
}

function runPathUpdate(t, { body, shellEnv, rcRel, rcContent, extraEnv = {}, homeName = 'home' }) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-placement-')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = join(root, homeName);
  const shims = join(root, 'shims');
  const elsewhere = join(root, 'elsewhere');
  for (const dir of [home, shims, elsewhere]) mkdirSync(dir, { recursive: true });
  const rc = join(home, rcRel);
  const rcParent = dirname(rc);
  const bin = join(root, 'live', 'bin');
  const createdLog = join(root, 'created.log');
  const premoveList = join(root, 'premove.lst');
  const record = (path) => JSON.stringify(path);
  // The mktemp shim delegates to the real mktemp, so every logged path is a
  // file the installer really created at that location.
  writeFileSync(join(shims, 'mktemp'), `#!/bin/sh
out="$(${record(realMktemp)} "$@")" || exit
case "$1" in
  *.phantom-path.*)
    [ -f "$out" ] || exit 3
    printf '%s\\n' "$out" >> ${record(createdLog)}
    ;;
esac
printf '%s\\n' "$out"
`);
  // The mv shim snapshots the destination directory's entries just before the
  // candidate replaces the startup file: both temporary files must be there.
  writeFileSync(join(shims, 'mv'), `#!/bin/sh
last=
for arg in "$@"; do last="$arg"; done
if [ "$last" = "$TEST_RC" ]; then
  ls -A "$(dirname "$last")" > ${record(premoveList)}
fi
exec ${record(realMv)} "$@"
`);
  chmodSync(join(shims, 'mktemp'), 0o755);
  chmodSync(join(shims, 'mv'), 0o755);
  if (rcContent !== undefined) {
    mkdirSync(rcParent, { recursive: true });
    writeFileSync(rc, rcContent, { mode: 0o600 });
  }
  const rcBefore = rcContent !== undefined ? lstatSync(rc) : null;
  const result = spawnSync('/bin/bash', ['-c', body, 'path-placement', bin], {
    encoding: 'utf8',
    timeout: 30000,
    env: {
      HOME: home,
      SHELL: shellEnv,
      PATH: `${shims}:/usr/bin:/bin`,
      TMPDIR: elsewhere,
      TEST_RC: rc,
      ...extraEnv,
    },
  });
  assert.ifError(result.error);
  return { root, home, rc, rcParent, bin, createdLog, premoveList, elsewhere, rcBefore, result };
}

// Exactly two created files, in creation order, each a direct child of the
// startup file's resolved parent directory.
function verifyCreatedUnderParent(run) {
  const created = readFileSync(run.createdLog, 'utf8').trim().split('\n');
  assert.equal(created.length, 2, 'exactly two PATH temporary files must be created');
  assert.match(basename(created[0]), /^\.phantom-path\.before\.[^/]+$/,
    'the first temporary file must keep the before name');
  assert.match(basename(created[1]), /^\.phantom-path\.candidate\.[^/]+$/,
    'the second temporary file must keep the candidate name');
  for (const path of created) {
    assert.equal(
      realpathSync(dirname(path)),
      realpathSync(run.rcParent),
      `${path} must be created under the shell configuration's parent`,
    );
  }
  return created;
}

function verifyRemoved(run) {
  assert.deepEqual(strayTemps(run.home), [],
    'no PATH temporary file may survive a successful update under HOME');
  assert.deepEqual(readdirSync(run.elsewhere), [],
    'no PATH temporary file may be created under TMPDIR');
}

for (const [file, body] of Object.entries(harnesses)) {
  for (const config of shells) {
    test(`${file} creates both PATH temporary files under the ${config.name} startup parent and removes them`, (t) => {
      const original = '# user shell configuration\nexport EXISTING=kept\n';
      const run = runPathUpdate(t, { body, shellEnv: config.env, rcRel: config.rcRel, rcContent: original });
      assert.equal(run.result.status, 0, run.result.stderr);
      assert.equal(run.result.stderr, '', 'a successful update reports nothing on stderr');
      assert.match(run.result.stdout, /added .* to PATH/);

      const created = verifyCreatedUnderParent(run);
      assert.ok(existsSync(run.premoveList), 'the candidate is promoted over the startup file');
      const listing = readFileSync(run.premoveList, 'utf8').trim().split('\n');
      for (const path of created) {
        assert.ok(listing.includes(basename(path)),
          `${basename(path)} must sit beside the startup file at promotion`);
      }
      verifyRemoved(run);
      assert.equal(readFileSync(run.rc, 'utf8'),
        `${original}\n# phantom-secrets PATH\n${config.pathLine(run.bin)}\n`);
      assert.equal(statSync(run.rc).mode & 0o777, 0o600, 'startup file mode is preserved');
    });
  }

  // A non-ASCII home directory (accented, CJK, emoji) must not move the
  // candidate: it is still created beside the startup file, under that parent.
  for (const config of shells) {
    test(`${file} creates both PATH temporary files under a Unicode ${config.name} startup parent`, (t) => {
      const original = '# user shell configuration\n';
      const run = runPathUpdate(t, {
        body,
        shellEnv: config.env,
        rcRel: config.rcRel,
        rcContent: original,
        homeName: 'höme-用户-🔐',
      });
      assert.equal(run.result.status, 0, run.result.stderr);
      assert.match(run.result.stdout, /added .* to PATH/);
      assert.ok(run.rcParent.includes('höme-用户-🔐'), 'the startup parent is the Unicode home');

      const created = verifyCreatedUnderParent(run);
      const listing = readFileSync(run.premoveList, 'utf8').trim().split('\n');
      for (const path of created) {
        assert.equal(dirname(path).startsWith(run.home), true,
          `${path} must be created inside the Unicode home`);
        assert.ok(listing.includes(basename(path)),
          `${basename(path)} must sit beside the startup file at promotion`);
      }
      verifyRemoved(run);
      assert.equal(readFileSync(run.rc, 'utf8'),
        `${original}\n# phantom-secrets PATH\n${config.pathLine(run.bin)}\n`);
    });
  }

  // A home directory containing spaces must not split the mktemp templates:
  // both temporary files still land beside the startup file, inside that parent.
  for (const config of shells) {
    test(`${file} creates both PATH temporary files under a space-containing ${config.name} startup parent`, (t) => {
      const original = '# user shell configuration\n';
      const run = runPathUpdate(t, {
        body,
        shellEnv: config.env,
        rcRel: config.rcRel,
        rcContent: original,
        homeName: 'home dir with spaces',
      });
      assert.equal(run.result.status, 0, run.result.stderr);
      assert.match(run.result.stdout, /added .* to PATH/);
      assert.ok(run.rcParent.includes('home dir with spaces'), 'the startup parent contains spaces');

      const created = verifyCreatedUnderParent(run);
      const listing = readFileSync(run.premoveList, 'utf8').trim().split('\n');
      for (const path of created) {
        assert.equal(dirname(path).startsWith(run.home), true,
          `${path} must be created inside the spaced home`);
        assert.ok(listing.includes(basename(path)),
          `${basename(path)} must sit beside the startup file at promotion`);
      }
      verifyRemoved(run);
      assert.equal(readFileSync(run.rc, 'utf8'),
        `${original}\n# phantom-secrets PATH\n${config.pathLine(run.bin)}\n`);
    });
  }

  test(`${file} creates and removes both PATH temporary files when the fish startup file is absent`, (t) => {
    const config = shells[2];
    const run = runPathUpdate(t, { body, shellEnv: config.env, rcRel: config.rcRel });
    assert.equal(run.result.status, 0, run.result.stderr);
    assert.match(run.result.stdout, /added .* to PATH/);

    const created = verifyCreatedUnderParent(run);
    const listing = readFileSync(run.premoveList, 'utf8').trim().split('\n');
    assert.deepEqual(listing.sort(), created.map((path) => basename(path)).sort(),
      'the function-created parent holds only the two temporary files at promotion');
    verifyRemoved(run);
    assert.equal(readFileSync(run.rc, 'utf8'),
      `\n# phantom-secrets PATH\n${config.pathLine(run.bin)}\n`);
    assert.equal(statSync(run.rc).mode & 0o777, 0o600);
  });

  test(`${file} still creates both PATH temporary files under the startup parent and removes them when the marker exists`, (t) => {
    const original = '# user shell configuration\n# phantom-secrets PATH\nexport PATH="/old/bin:$PATH"\n';
    const run = runPathUpdate(t, { body, shellEnv: '/bin/bash', rcRel: '.bashrc', rcContent: original });
    assert.equal(run.result.status, 0, run.result.stderr);
    assert.match(run.result.stdout, /already wired/);

    verifyCreatedUnderParent(run);
    assert.equal(existsSync(run.premoveList), false,
      'the already-wired path removes both temporary files without a promotion move');
    verifyRemoved(run);
    assert.equal(readFileSync(run.rc, 'utf8'), original);
    assert.equal(lstatSync(run.rc).ino, run.rcBefore.ino,
      'the startup file must not be replaced');
  });
}

test('both installer copies carry the identical PATH-update function', () => {
  assert.equal(
    pathUpdateFunction(readFileSync(copies['scripts/install.sh'], 'utf8'), 'scripts/install.sh'),
    pathUpdateFunction(readFileSync(copies['apps/web/public/install.sh'], 'utf8'), 'apps/web/public/install.sh'),
    'PATH-update temporary-file placement must match across installer copies',
  );
});

test('the placement check rejects temporary files created outside the startup parent', (t) => {
  const doctored = harnesses['scripts/install.sh']
    .replaceAll('mktemp "$rc_parent/', 'mktemp "$TEST_ROGUE_DIR/');
  assert.notEqual(doctored, harnesses['scripts/install.sh'],
    'the fixture must move the mktemp parent');
  const rogueRoot = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-rogue-')));
  t.after(() => rmSync(rogueRoot, { recursive: true, force: true }));
  const rogue = join(rogueRoot, 'rogue');
  mkdirSync(rogue);
  const run = runPathUpdate(t, {
    body: doctored,
    shellEnv: '/bin/bash',
    rcRel: '.bashrc',
    rcContent: '# user shell configuration\n',
    extraEnv: { TEST_ROGUE_DIR: rogue },
  });
  assert.equal(run.result.status, 0, run.result.stderr);
  assert.throws(() => verifyCreatedUnderParent(run), /shell configuration's parent/);
});
