import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, 'rust-scope.sh');
const ci = readFileSync(join(here, '..', '..', '.github', 'workflows', 'ci.yml'), 'utf8');

function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), 'rust-scope-'));
  const git = (args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' });
  git(['init', '-b', 'main']);
  git(['config', 'user.email', 'ci@example.com']);
  git(['config', 'user.name', 'ci']);
  writeFileSync(join(dir, 'base.txt'), 'base\n');
  git(['add', 'base.txt']);
  git(['commit', '-m', 'base']);
  const base = git(['rev-parse', 'HEAD']).trim();
  git(['checkout', '-b', 'head']);
  for (const [path, body] of Object.entries(files)) {
    const parent = dirname(join(dir, path));
    mkdirSync(parent, { recursive: true });
    writeFileSync(join(dir, path), body);
    git(['add', '--', path]);
  }
  git(['commit', '-m', 'head']);
  const head = git(['rev-parse', 'HEAD']).trim();
  return { dir, base, head };
}

function rust(event, files) {
  const { dir, base, head } = repo(files);
  return execFileSync('bash', [script], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, EVENT: event, BASE: base, HEAD: head },
  }).trim();
}

test('pull_request and merge_group share the three-dot file rule', () => {
  const docs = { 'docs/guide.md': 'docs\n' };
  const crate = { 'crates/phantom-vault/src/lib.rs': 'fn main() {}\n' };
  const workflow = { '.github/workflows/ci.yml': 'name: CI\n' };
  assert.equal(rust('pull_request', docs), 'rust=false');
  assert.equal(rust('merge_group', docs), 'rust=false');
  assert.equal(rust('pull_request', crate), 'rust=true');
  assert.equal(rust('merge_group', crate), 'rust=true');
  assert.equal(rust('merge_group', workflow), 'rust=true');
  assert.equal(rust('schedule', docs), 'rust=true');
  assert.equal(rust('workflow_dispatch', docs), 'rust=true');
});

test('Classify changes and Lint call rust-scope with history and merge_group shas', () => {
  const changes = ci.slice(ci.indexOf('\n  changes:\n'), ci.indexOf('\n  test:\n'));
  assert.match(changes, /fetch-depth: 0/);
  assert.match(changes, /bash scripts\/ci\/rust-scope\.sh/);
  assert.match(changes, /EVENT: \$\{\{ github\.event_name \}\}/);
  assert.match(changes, /github\.event\.pull_request\.base\.sha \|\| github\.event\.merge_group\.base_sha/);
  assert.match(changes, /github\.event\.pull_request\.head\.sha \|\| github\.event\.merge_group\.head_sha/);
  const lint = ci.slice(ci.indexOf('\n  lint:\n'), ci.indexOf('\n  dependency-policy:\n'));
  assert.doesNotMatch(lint, /\n    needs:/);
  assert.match(lint, /fetch-depth: 0/);
  assert.match(lint, /name: Select Rust scope/);
  assert.match(lint, /id: scope/);
  assert.match(lint, /EVENT: \$\{\{ github\.event_name \}\}/);
  assert.match(lint, /github\.event\.merge_group\.base_sha/);
  assert.match(lint, /github\.event\.merge_group\.head_sha/);
  assert.match(lint, /bash scripts\/ci\/rust-scope\.sh \| tee -a "\$GITHUB_OUTPUT"/);
  assert.match(ci, /const always = \['dependency-policy', 'secret-scan', 'secret-shape', 'lint'\];/);
  assert.match(ci, /const rustJobs = \['npm-wrappers'\];/);
});
