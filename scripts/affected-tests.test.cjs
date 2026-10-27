'use strict';
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { affectedTests } = require('./affected-tests');

const root = path.resolve('/fixture');
const packages = [
  ['core', []], ['proxy', ['core']], ['cli', ['proxy']], ['independent', []],
].map(([name, deps]) => ({
  id: name, name, manifest_path: path.join(root, 'crates', name, 'Cargo.toml'),
  dependencies: deps.map(name => ({ name })),
}));
const metadata = { packages, workspace_members: packages.map(pkg => pkg.id) };
const fixtures = JSON.parse(readFileSync(path.join(__dirname, 'fixtures/affected-tests/diffs.json'), 'utf8'));
for (const fixture of fixtures) {
  test(fixture.name, () => assert.deepEqual(affectedTests(fixture.files, metadata, root), fixture.expected));
}


test('includes renamed, optional, dev, build and target dependencies', () => {
  const consumers = ['normal', 'dev', 'build'].map((kind, index) => ({
    id: `consumer${index}`, name: `consumer${index}`,
    manifest_path: path.join(root, `consumer${index}`, 'Cargo.toml'),
    dependencies: [{ name: 'core', rename: 'alias', kind, optional: true, target: 'cfg(windows)' }],
  }));
  assert.deepEqual(affectedTests(['crates/core/src/lib.rs'], {
    packages: [...packages, ...consumers],
    workspace_members: [...metadata.workspace_members, ...consumers.map(pkg => pkg.id)],
  }, root), ['cli', 'consumer0', 'consumer1', 'consumer2', 'core', 'proxy']);
});

test('CLI uses merge base, handles deletion and rename, and fails closed', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'affected-tests-'));
  const script = path.join(__dirname, 'affected-tests');
  const env = { ...process.env, HOME: path.join(dir, 'home'), GIT_CONFIG_NOSYSTEM: '1' };
  mkdirSync(env.HOME);
  const git = (...args) => execFileSync('git', args, { cwd: dir, env, stdio: 'pipe', encoding: 'utf8' }).trim();
  const select = base => spawnSync(process.execPath, [script, base], { cwd: dir, env, encoding: 'utf8' });
  const write = (file, text) => {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), text);
  };
  const commit = () => { git('add', '.'); git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'); };
  try {
    git('init', '-q');
    write('Cargo.toml', '[workspace]\nmembers = ["crates/core", "crates/other"]\nresolver = "2"\n');
    for (const name of ['core', 'other']) {
      write(`crates/${name}/Cargo.toml`, `[package]\nname = "${name}"\nversion = "0.1.0"\nedition = "2021"\n`);
      write(`crates/${name}/src/lib.rs`, 'pub fn example() {}\n');
    }
    write('crates/core/src/odd\n"$name.rs', '// fixture\n');
    commit();
    const base = git('rev-parse', 'HEAD');
    write('crates/core/src/lib.rs', '// uncommitted change\n');
    write('untracked-input', 'untracked change\n');
    let unchanged = select(base);
    assert.equal(unchanged.status, 0, unchanged.stderr);
    assert.equal(unchanged.stdout, '[]\n', 'uncommitted files must be excluded');
    git('add', 'crates/core/src/lib.rs');
    unchanged = select(base);
    assert.equal(unchanged.status, 0, unchanged.stderr);
    assert.equal(unchanged.stdout, '[]\n', 'staged files must be excluded');
    git('reset', '--hard', 'HEAD');
    rmSync(path.join(dir, 'untracked-input'));
    write('README.md', '# Documentation\n');
    commit();
    assert.equal(select(base).stdout, '[]\n');
    git('branch', 'topic');
    write('Cargo.lock', '# base branch only\n');
    commit();
    const divergedBase = git('rev-parse', 'HEAD');
    git('checkout', '-q', 'topic');
    assert.equal(select(divergedBase).stdout, '[]\n', 'must use merge base rather than two-dot diff');
    git('mv', 'crates/core/src/odd\n"$name.rs', 'crates/other/src/renamed.rs');
    commit();
    let result = select(base);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), ['core', 'other']);
    git('rm', 'crates/other/src/renamed.rs');
    commit();
    result = select('HEAD~1');
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), ['other']);
    write('Cargo.lock', '# changed\n');
    commit();
    assert.equal(select('HEAD~1').stdout, 'ALL\n');
    write('Cargo.toml', 'invalid manifest');
    commit();
    assert.equal(select('HEAD~1').stdout, 'ALL\n', 'config changes must not need valid metadata');
    write('crates/core/src/lib.rs', '// changed\n');
    commit();
    result = select('HEAD~1');
    assert.notEqual(result.status, 0, 'metadata errors must fail closed');
    assert.equal(result.stdout, '');
    for (const invalid of ['missing-ref', '--output=unsafe', 'HEAD...HEAD']) {
      result = select(invalid);
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
