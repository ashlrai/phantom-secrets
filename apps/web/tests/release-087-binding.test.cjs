const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

// Recorded from the independently verified annotated tag and its source tree.
// The fixtures are the exact scripts from that tree, not moving web copies.
const expected = {
  version: '0.8.7',
  tagObject: '60f78437316cdfbd5c5aef43f7a1947a9e35b11f',
  source: 'a6a0413991c0bd7f3d6601f467c0b5770d0dce0c',
  unixSha256: '44ab25b1a5b99d7a1a3bb484ea17b323f89a47e43092ca4de4903a9ede6ba72e',
  unixBlob: '018ca537e0b9fe80f109f154c38456d9c71f7f95',
  windowsSha256: '7b8549e6cd0d213b7e4e12ace3513f964952d460f1717602d16022f6411b4b5e',
  windowsBlob: '6b52d955f5fa6bc33048d0ec6bdf1fb0a3cc6f59',
};
const repo = join(__dirname, '../../..');
const release = readFileSync(join(repo, 'apps/web/src/lib/public-release.ts'), 'utf8');
function exported(name) {
  const match = release.match(new RegExp(`export const ${name} =\\s*"([^"]+)"`));
  assert.ok(match, `missing ${name}`);
  return match[1];
}
const fixture = (name) => readFileSync(join(__dirname, 'fixtures/release-v0.8.7', name));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const blob = (bytes) => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
function assertBinding(binding, unix, windows) {
  assert.deepEqual(binding, expected);
  assert.equal(sha256(unix), binding.unixSha256);
  assert.equal(blob(unix), binding.unixBlob);
  assert.equal(sha256(windows), binding.windowsSha256);
  assert.equal(blob(windows), binding.windowsBlob);
}
function actualBinding() {
  return {
    version: exported('PUBLIC_RELEASE_VERSION'),
    tagObject: exported('PUBLIC_RELEASE_TAG_OBJECT'),
    source: exported('PUBLIC_RELEASE_SOURCE_COMMIT'),
    unixSha256: exported('PUBLIC_RELEASE_UNIX_INSTALLER_SHA256'),
    unixBlob: exported('PUBLIC_RELEASE_UNIX_INSTALLER_BLOB_OID'),
    windowsSha256: exported('PUBLIC_RELEASE_WINDOWS_INSTALLER_SHA256'),
    windowsBlob: exported('PUBLIC_RELEASE_WINDOWS_INSTALLER_BLOB_OID'),
  };
}

test('v0.8.7 release source, annotated tag, and installer bytes are bound', () => {
  assertBinding(actualBinding(), fixture('install.sh'), fixture('install.ps1'));
});

test('binding rejects mutations of source, tag, digests, blob ids, and either fixture', () => {
  const unix = fixture('install.sh');
  const windows = fixture('install.ps1');
  for (const key of Object.keys(expected)) {
    assert.throws(() => assertBinding({ ...expected, [key]: `${expected[key]}0` }, unix, windows), undefined, key);
  }
  assert.throws(() => assertBinding(expected, Buffer.concat([unix, Buffer.from([0])]), windows));
  assert.throws(() => assertBinding(expected, unix, Buffer.concat([windows, Buffer.from([0])])));
});
