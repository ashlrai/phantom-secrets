import assert from 'node:assert/strict';
import test from 'node:test';
import { extractFunction, pathUpdateHarness } from './installer-path-harness.mjs';

test('extracts exact single-line and multiline shell functions', () => {
  const source = 'say() { echo ok; }\nfile_identity() {\n  echo id\n}\nfile_link_count() { echo 1; }\nadd_to_user_path() {\n  echo "$1"\n}\n';
  assert.equal(extractFunction(source, 'say', 'fixture'), 'say() { echo ok; }\n');
  assert.equal(extractFunction(source, 'file_identity', 'fixture'), 'file_identity() {\n  echo id\n}\n');
  assert.equal(pathUpdateHarness(source, 'fixture'), `set -euo pipefail\numask 077\nsay() { echo ok; }\n\nfile_identity() {\n  echo id\n}\n\nfile_link_count() { echo 1; }\n\nadd_to_user_path() {\n  echo "$1"\n}\n\nadd_to_user_path "$1"`);
  assert.throws(() => extractFunction(source, 'missing', 'fixture'), /locate missing/);
  assert.throws(() => extractFunction('say() {', 'say', 'fixture'), /locate end of say/);
});
