const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { chmodSync, mkdirSync, readFileSync, readdirSync, writeFileSync } = require("node:fs");
const { dirname, join, resolve } = require("node:path");
const test = require("node:test");

test("public installer downloads and extracts into a directory containing spaces offline", async (t) => {
  const { createStagingFixture } = await import("../../../scripts/lib/installer-staging-fixture.mjs");
  const { root, fixture, shims, archive } = createStagingFixture(t, "phantom-public-spaced-install-");
  const home = join(root, "home");
  const parent = join(root, "installation parent");
  const install = join(parent, "phantom bin");
  const curlLog = join(root, "curl.jsonl");
  const tarLog = join(root, "tar.args");
  mkdirSync(home);

  // Replace every curl invocation: no network is used, and JSON preserves argv
  // boundaries so a split destination cannot masquerade as the intended path.
  writeFileSync(join(shims, "curl"), `#!${process.execPath}
const { appendFileSync, copyFileSync } = require('node:fs');
const { join } = require('node:path');
const args = process.argv.slice(2);
if (args[0] === '--help') {
  process.stdout.write('--max-filesize\\n');
  process.exit(0);
}
appendFileSync(${JSON.stringify(curlLog)}, JSON.stringify(args) + '\\n');
const url = args.at(-1);
const base = 'https://github.com/ashlrai/phantom-secrets/releases/download/v1.2.3/';
const name = url.slice(base.length);
if (!url.startsWith(base) || !${JSON.stringify([archive, `${archive}.sha256`])}.includes(name)) process.exit(22);
const output = args.indexOf('--output');
if (output < 0) process.exit(2);
copyFileSync(join(${JSON.stringify(fixture)}, name), args[output + 1]);
process.stdout.write(url);
`);
  // Use real tar for archive validation and extraction, recording the exact
  // argument vector for the extraction call before delegating.
  writeFileSync(join(shims, "tar"), `#!/bin/sh
if [ "$2" = '-xzf' ]; then printf '%s\\0' "$@" > "$TEST_TAR_LOG"; fi
exec /usr/bin/tar "$@"
`);
  for (const name of ["curl", "tar"]) chmodSync(join(shims, name), 0o755);

  const result = spawnSync("/bin/bash", [resolve(__dirname, "../public/install.sh")], {
    cwd: root,
    encoding: "utf8",
    timeout: 30000,
    env: {
      HOME: home,
      SHELL: "/bin/bash",
      PATH: `${shims}:/usr/bin:/bin`,
      PHANTOM_INSTALL_DIR: install,
      PHANTOM_TEST_ALLOW_INSTALLER_OVERRIDES: "1",
      PHANTOM_TAG: "v1.2.3",
      TEST_TAR_LOG: tarLog,
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /installed to /);

  const downloads = readFileSync(curlLog, "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(downloads.length, 2, "archive and checksum both use the download stub");
  const destinations = downloads.map((args) => args[args.indexOf("--output") + 1]);
  const stage = dirname(dirname(destinations[0]));
  assert.equal(dirname(stage), parent, "staging retains the complete spaced parent");
  assert.deepEqual(destinations, [join(stage, "download", archive), join(stage, "download", `${archive}.sha256`)]);
  assert.deepEqual(readFileSync(tarLog, "utf8").split("\0").slice(0, -1), [
    "--no-same-owner", "-xzf", destinations[0], "-C", join(stage, "candidate"),
  ], "tar receives each spaced path as one argument");

  for (const name of ["phantom", "phantom-mcp"]) {
    assert.equal(readFileSync(join(install, name), "utf8"), `#!/bin/sh\necho "${name} 1.2.3"\n`);
  }
  assert.deepEqual(readdirSync(install).sort(), [".phantom-install-source.json", "phantom", "phantom-mcp"]);
  assert.deepEqual(readdirSync(parent), ["phantom bin"], "staging and lock are cleaned up");
  assert.equal(readFileSync(join(home, ".bashrc"), "utf8"), `\n# phantom-secrets PATH\nexport PATH="${install}:$PATH"\n`);
  assert.deepEqual(readdirSync(root).sort(), [
    "curl.jsonl", "fixture", "home", "installation parent", "payload", "shims", "tar.args",
  ], "no files or directories are created from split path words");
});
