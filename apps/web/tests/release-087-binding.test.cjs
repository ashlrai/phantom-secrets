const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

// Recorded from the independently verified annotated tag and its source tree.
// The fixtures are the exact scripts from that tree, not moving web copies.
const expected = {
  version: '0.8.11',
  tagObject: '0d913358f49e0a3edb0d01d7063cc3660223c54c',
  source: '2c93e578d8d1a8097b32c1cd89292e339681b77c',
  unixSha256: '094525f7982caaf534c1a19b2581dbee69a4b766687b593d5adda3f0ba9464a4',
  unixBlob: 'b0a39d87a1d3d84263d64c380a986e6b55434293',
  windowsSha256: 'db11ec07928802b5d951824af1c4bc9dfed8c7775b466d781f403a449152323c',
  windowsBlob: '22ac5bea9144241eadf26f585c2ebdb9f72d0904',
};
const repo = join(__dirname, '../../..');
const release = readFileSync(join(repo, 'apps/web/src/lib/public-release.ts'), 'utf8');
function exported(name) {
  const match = release.match(new RegExp(`export const ${name} =\\s*"([^"]+)"`));
  assert.ok(match, `missing ${name}`);
  return match[1];
}
const fixture = (name) => readFileSync(join(__dirname, 'fixtures/release-v0.8.11', name));
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

test('v0.8.11 release source, annotated tag, and installer bytes are bound', () => {
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
