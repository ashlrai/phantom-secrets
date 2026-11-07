import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// Dependabot rates the zip crate below 9.0.5 as critical; every resolved zip
// package in Cargo.lock must stay at or above this floor.
const ZIP_FLOOR = [9, 0, 5];
const LOCKFILE = new URL('../Cargo.lock', import.meta.url);

function lockVersions(text, name) {
  const versions = [];
  for (const block of text.split('[[package]]')) {
    const nameMatch = /^name = "([^"]+)"$/m.exec(block);
    const versionMatch = /^version = "([^"]+)"$/m.exec(block);
    if (nameMatch && versionMatch && nameMatch[1] === name) {
      versions.push(versionMatch[1]);
    }
  }
  return versions;
}

function meetsFloor(version, floor) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-(.+))?(?:\+.+)?$/.exec(version.trim());
  if (!match) return false;
  const nums = match.slice(1, 4).map(Number);
  for (let index = 0; index < floor.length; index += 1) {
    if (nums[index] !== floor[index]) return nums[index] > floor[index];
  }
  return match[4] === undefined;
}

test('every zip package in Cargo.lock meets the 9.0.5 security floor', () => {
  const versions = lockVersions(readFileSync(LOCKFILE, 'utf8'), 'zip');
  assert.ok(versions.length > 0, 'Cargo.lock has no zip package to check');
  for (const version of versions) {
    assert.ok(
      meetsFloor(version, ZIP_FLOOR),
      `zip ${version} is below the ${ZIP_FLOOR.join('.')} security floor`,
    );
  }
});

test('lockVersions reads every matching package block', () => {
  const text = [
    '[[package]]\nname = "zip"\nversion = "9.0.5"\nsource = "registry+x"\n',
    '[[package]]\nname = "zed"\nversion = "1.0.0"\n',
    '[[package]]\nname = "zip"\nversion = "10.1.0"\n',
  ].join('\n');
  assert.deepEqual(lockVersions(text, 'zip'), ['9.0.5', '10.1.0']);
});

test('meetsFloor enforces the boundary', () => {
  for (const [version, expected] of [
    ['9.0.5', true],
    ['9.0.6', true],
    ['9.1.0', true],
    ['10.0.0', true],
    ['9.0.4', false],
    ['9.0.0', false],
    ['8.9.9', false],
    ['9.0.5-rc.1', false],
    ['', false],
    ['9.0', false],
    ['9.x.5', false],
  ]) {
    assert.equal(meetsFloor(version, ZIP_FLOOR), expected, version);
  }
});
