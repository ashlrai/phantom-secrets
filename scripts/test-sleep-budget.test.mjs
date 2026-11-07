import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// These child processes are terminated by the code under test, not waited out.
const allow = new Map([
  ['crates/phantom-runtime/src/runtime.rs', new Set(['sleep 5', 'sleep 30'])],
  ['crates/phantom-cli/tests/exec_signal_test.rs', new Set(['sleep 30'])],
]);

function waits(source) {
  const patterns = [
    /\bsleep\s*\(\s*(?:std::time::)?Duration::from_(millis|secs)\s*\(\s*([\d_]+)\s*\)/g,
    /\bsetTimeout\s*\([^,]*,\s*([\d_]+)\s*\)/g,
    /\btime\.sleep\s*\(\s*([\d_]+)\s*\)/g,
    /\b(?:sleep|delay)\s*\(\s*([\d_]+)\s*\)/g,
    /\bsleep\s+([\d]+(?:\.[\d]+)?)/g,
  ];
  return patterns.flatMap((pattern, index) => [...source.matchAll(pattern)].flatMap((match) => {
    const value = Number(match[index === 0 ? 2 : 1].replaceAll('_', ''));
    const ms = index === 0 && match[1] === 'secs' || index === 2 || index === 4 ? value * 1000 : value;
    return ms >= 2000 ? [{ text: match[0], offset: match.index }] : [];
  }));
}

test('detects literal waits at the budget boundary', () => {
  assert.equal(waits('sleep(Duration::from_millis(1999)); setTimeout(done, 1999)').length, 0);
  assert.equal(waits('sleep(Duration::from_secs(2)); setTimeout(done, 2000); time.sleep(2); sleep 2').length, 4);
});

test('test sources avoid long literal waits', () => {
  const paths = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { encoding: 'utf8' }).split('\0');
  const violations = [];
  for (const path of paths) {
    if (!/\.(?:rs|mjs|js|py|sh)$/.test(path) || path === 'scripts/test-sleep-budget.test.mjs') continue;
    const source = readFileSync(path, 'utf8');
    const isTest = /(?:^|\/)(?:tests?\/|[^/]*[._-]tests?\.)/.test(path);
    const marker = source.search(/#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]/);
    if (!isTest && marker < 0) continue;
    const testSource = isTest ? source : source.slice(marker);
    for (const match of waits(testSource)) {
      if (allow.get(path)?.has(match.text)) continue;
      const line = testSource.slice(0, match.offset).split('\n').length + (isTest ? 0 : source.slice(0, marker).split('\n').length - 1);
      violations.push(`${path}:${line}: ${match.text}`);
    }
  }
  assert.deepEqual(violations, []);
});
