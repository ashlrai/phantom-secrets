import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';

// The bash and zsh startup files live directly under HOME, so their
// configuration directory contains spaces only when HOME does — covered by
// the spaced-parent tests. The fish startup file lives at
// ~/.config/fish/config.fish: its configuration directory can contain spaces
// while HOME does not, because ~/.config — or ~/.config/fish itself — is a
// symlink into a spaced directory, the layout dotfiles managers like GNU
// stow produce. The PATH update resolves the configuration directory with
// `pwd -P`, so both temporary siblings and the final config.fish must land
// inside the spaced target, the symlink must stay a symlink, and nothing may
// be written to a path produced by splitting the spaced name.
const copies = {
  'scripts/install.sh': resolve(import.meta.dirname, 'install.sh'),
  'apps/web/public/install.sh': resolve(import.meta.dirname, '..', 'apps', 'web', 'public', 'install.sh'),
};

function extractFunction(source, name, file) {
  const start = source.indexOf(`${name}()`);
  assert.ok(start >= 0, `${file}: locate ${name}`);
  const lineEnd = source.indexOf('\n', start);
  if (source.slice(start, lineEnd).trimEnd().endsWith('}')) {
    return source.slice(start, lineEnd + 1);
  }
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `${file}: locate end of ${name}`);
  return source.slice(start, end + '\n}\n'.length);
}

const harness = (source, file) => ['set -euo pipefail', 'umask 077',
  ...['say', 'file_identity', 'file_link_count', 'add_to_user_path']
    .map((name) => extractFunction(source, name, file)),
  'add_to_user_path "$1"',
].join('\n');

const marker = '# phantom-secrets PATH';
const existingFish = 'set -gx EDITOR vim\n';
const fishLine = (bin) => `set -gx PATH "${bin}" $PATH`;
const posixLine = (bin) => `export PATH="${bin}:$PATH"`;

for (const [file, installer] of Object.entries(copies)) {
  const script = harness(readFileSync(installer, 'utf8'), file);
  const run = (home, shell, bin, cwd) => {
    const result = spawnSync('/bin/bash', ['-c', script, 'path-test', bin], {
      encoding: 'utf8',
      timeout: 30000,
      cwd,
      env: { HOME: home, SHELL: shell, PATH: '/usr/bin:/bin' },
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '', 'a successful update writes nothing to stderr');
    return result;
  };

  // ~/.config is a symlink into a spaced directory — absolute and relative
  // links — with and without an existing config.fish in the target.
  for (const [linkKind, hasRc] of [
    ['absolute', true],
    ['absolute', false],
    ['relative', true],
    ['relative', false],
  ]) {
    const article = linkKind === 'absolute' ? 'an' : 'a';
    test(`${file} updates the fish startup file under a spaced configuration directory reached through ${article} ${linkKind} .config symlink (${hasRc ? 'existing' : 'new'} config.fish)`, (t) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-spaced-config-')));
      t.after(() => rmSync(root, { recursive: true, force: true }));
      const home = join(root, 'home');
      const target = join(root, 'dot config');
      const decoys = ['dot', 'config'].map((d) => join(root, d));
      const bin = join(root, 'bin');
      for (const dir of [home, target, bin, ...decoys]) mkdirSync(dir);
      symlinkSync(linkKind === 'relative' ? '../dot config' : target,
        join(home, '.config'));
      const rc = join(target, 'fish', 'config.fish');
      if (hasRc) {
        mkdirSync(dirname(rc));
        writeFileSync(rc, existingFish, { mode: 0o600 });
      }

      const result = run(home, '/usr/bin/fish', bin, root);

      assert.match(result.stdout, /added .* to PATH/);
      assert.equal(readFileSync(rc, 'utf8'),
        `${hasRc ? existingFish : ''}\n${marker}\n${fishLine(bin)}\n`,
        'the intended startup file gained exactly the managed block');
      assert.ok(lstatSync(join(home, '.config')).isSymbolicLink(),
        '~/.config stays a symlink');
      assert.deepEqual(readdirSync(home), ['.config'],
        'nothing was written into HOME beside the symlink');
      assert.deepEqual(readdirSync(target), ['fish']);
      assert.deepEqual(readdirSync(join(target, 'fish')), ['config.fish'],
        'the spaced configuration directory holds only the startup file');
      for (const decoy of decoys) {
        assert.deepEqual(readdirSync(decoy), [], `${basename(decoy)} was never written to`);
      }
      assert.deepEqual(readdirSync(root).sort(),
        ['bin', 'config', 'dot', 'dot config', 'home'].sort(),
        'nothing else appeared under the test root');
    });
  }

  // ~/.config/fish itself is the symlink into a spaced directory. A rerun
  // must report the entry already wired and leave the file byte-identical.
  test(`${file} updates a fish configuration directory that is itself a symlink into a spaced directory`, (t) => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-spaced-config-link-')));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const home = join(root, 'home');
    const target = join(root, 'spaced fish dir');
    const decoys = ['spaced', 'fish', 'dir'].map((d) => join(root, d));
    const bin = join(root, 'bin');
    for (const dir of [join(home, '.config'), target, bin, ...decoys]) {
      mkdirSync(dir, { recursive: true });
    }
    symlinkSync(target, join(home, '.config', 'fish'));
    const rc = join(target, 'config.fish');
    writeFileSync(rc, existingFish, { mode: 0o600 });
    const expected = `${existingFish}\n${marker}\n${fishLine(bin)}\n`;

    let result = run(home, '/usr/bin/fish', bin, root);
    assert.match(result.stdout, /added .* to PATH/);
    assert.equal(readFileSync(rc, 'utf8'), expected);
    assert.ok(lstatSync(join(home, '.config', 'fish')).isSymbolicLink(),
      'the configuration directory stays a symlink');

    result = run(home, '/usr/bin/fish', bin, root);
    assert.match(result.stdout, /already wired into/);
    assert.equal(readFileSync(rc, 'utf8'), expected,
      'a rerun through the spaced symlink leaves the file byte-identical');

    assert.deepEqual(readdirSync(join(home, '.config')), ['fish'],
      'nothing was created beside the symlinked configuration directory');
    assert.deepEqual(readdirSync(target), ['config.fish'],
      'the spaced configuration directory holds only the startup file');
    for (const decoy of decoys) {
      assert.deepEqual(readdirSync(decoy), [], `${basename(decoy)} was never written to`);
    }
    assert.deepEqual(readdirSync(root).sort(),
      ['bin', 'dir', 'fish', 'home', 'spaced', 'spaced fish dir'].sort(),
      'nothing else appeared under the test root');
  });

  // For bash and zsh the configuration directory is HOME itself. Names whose
  // spaces sit at the edges — or that are nothing but spaces — split into no
  // usable words at all, so an unquoted expansion would aim at the wrong
  // parent entirely.
  const posixShells = {
    bash: { shell: '/bin/bash', rcName: '.bashrc' },
    zsh: { shell: '/bin/zsh', rcName: '.zshrc' },
  };
  for (const [name, cfg] of Object.entries(posixShells)) {
    for (const homeName of [' home', 'home ', ' ']) {
      test(`${file} updates the ${name} configuration directory ${JSON.stringify(homeName)}`, (t) => {
        const root = realpathSync(mkdtempSync(join(tmpdir(), 'phantom-path-edge-space-')));
        t.after(() => rmSync(root, { recursive: true, force: true }));
        const home = join(root, homeName);
        const bin = join(root, 'bin');
        const decoys = homeName.split(' ').filter(Boolean).map((d) => join(root, d));
        for (const dir of [home, bin, ...decoys]) mkdirSync(dir);
        const rc = join(home, cfg.rcName);
        const existing = 'export EDITOR=vim\n';
        writeFileSync(rc, existing, { mode: 0o600 });

        const result = run(home, cfg.shell, bin, root);

        assert.match(result.stdout, /added .* to PATH/);
        assert.equal(readFileSync(rc, 'utf8'),
          `${existing}\n${marker}\n${posixLine(bin)}\n`);
        assert.deepEqual(readdirSync(home), [cfg.rcName],
          'the configuration directory holds only the updated startup file');
        for (const decoy of decoys) {
          assert.deepEqual(readdirSync(decoy), [], `${basename(decoy)} was never written to`);
        }
        assert.deepEqual(readdirSync(root).sort(),
          [...decoys.map((d) => basename(d)), 'bin', homeName].sort(),
          'nothing else appeared under the test root');
      });
    }
  }
}
