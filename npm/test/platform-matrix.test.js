const assert = require("assert");

const {
  SUPPORTED_TARGETS,
  getPlatformTarget,
} = require("../bin/cli.js");

const expected = Object.freeze({
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "linux-x64": "x86_64-unknown-linux-gnu",
  "win32-arm64": "aarch64-pc-windows-msvc",
  "win32-x64": "x86_64-pc-windows-msvc",
});

assert.deepStrictEqual(SUPPORTED_TARGETS, expected);

for (const [platformKey, target] of Object.entries(expected)) {
  const [platform, arch] = platformKey.split("-");
  assert.strictEqual(
    getPlatformTarget({ platform, arch }),
    target,
    `phantom-secrets maps ${platformKey}`
  );
}

for (const runtime of [
  { platform: "darwin", arch: "ia32" },
  { platform: "linux", arch: "arm" },
  { platform: "freebsd", arch: "x64" },
  { platform: "win32", arch: "ia32" },
]) {
  assert.throws(() => getPlatformTarget(runtime), (error) => {
    assert.match(error.message, new RegExp(`Unsupported platform: ${runtime.platform}-${runtime.arch}`));
    assert.match(error.message, /releases\/tag\/v0\.7\.7/);
    assert.match(error.message, /checksum-verifiable/);
    assert.doesNotMatch(error.message, /cargo install|npm install|npx |curl[^\n]*\|/i);
    return true;
  });
}

const wrapperSource = require("fs").readFileSync(require("path").join(__dirname, "..", "bin", "cli.js"), "utf8");
assert.doesNotMatch(wrapperSource, /Install from source|cargo install phantom-secrets/);

console.log("npm CLI wrapper platform matrix tests passed");
