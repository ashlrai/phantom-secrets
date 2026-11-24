import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const troubleshooting = read('docs/troubleshooting.md');

test('CI guidance does not prescribe an interactive provider pull in a workflow', () => {
  const ci = troubleshooting.split('## CI/CD Usage')[1]?.split('## FAQ')[0];
  assert.ok(ci, 'missing CI/CD guidance');
  for (const [, yaml] of ci.matchAll(/```ya?ml\n([\s\S]*?)```/g)) {
    assert.doesNotMatch(yaml, /phantom pull\b/);
    assert.doesNotMatch(yaml, /\$GITHUB_ENV|\$\{\{\s*secrets\./);
  }
  assert.match(ci, /pull[\s\S]*attached[\s\S]*terminal/i);
  assert.match(ci, /already initialized/i);
});

test('Compose guidance explains both environment and loopback boundaries', () => {
  const compose = troubleshooting.split('### Does Phantom work with Docker Compose?')[1]?.split('\n### ')[0];
  assert.ok(compose, 'missing Compose guidance');
  assert.doesNotMatch(compose, /```[\s\S]*?phantom exec -- docker compose up/);
  assert.doesNotMatch(compose, /env vars are passed to containers/);
  assert.match(compose, /environment.*env_file/);
  assert.match(compose, /127\.0\.0\.1/);
  assert.match(compose, /inside.*container/);
});

test('wrapping guidance preserves the proxy boundary and shell limitations', () => {
  const guide = read('docs/llms-full.txt');
  const wrap = guide.split('\n').find(line => line.startsWith('- `phantom wrap '));
  assert.ok(wrap, 'missing wrap command entry');
  assert.doesNotMatch(wrap, /get real credentials|real secrets at runtime/);
  assert.match(wrap, /placeholders/);
  assert.match(wrap, /supported.*route/);
  assert.match(guide, /--only[\s\S]*--skip/);
  assert.match(guide, /shell command lines.*unchanged/i);
});

test('generated application secrets are not presented as delivered signing keys', () => {
  const guide = read('docs/generated-secrets.md');
  assert.match(guide, /SESSION_SECRET[\s\S]*no_route/);
  assert.match(guide, /session.signing[\s\S]*placeholder/i);
  assert.match(guide, /phantom why SESSION_SECRET --json/);
});
