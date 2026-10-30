import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { collectTargets } from "./freshness/blocks.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(import.meta.url);
const wrapper = require("../npm/bin/cli.js");
const { version } = require("../npm/package.json");
const names = ["z.md", "a.md", "B.md", "10.md", "2.md", "_x.md", "é.md", "😀.md", "\uE000.md"];
const ordered = ["10.md", "2.md", "B.md", "_x.md", "a.md", "z.md", "é.md", "😀.md", "\uE000.md"];
function fixture(t) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "phantom-sonar-q14-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("freshness paths retain UTF-16 code-unit order across directories", (t) => {
  const dir = fixture(t);
  for (const folder of ["docs", "examples"]) {
    mkdirSync(join(dir, folder));
    for (const name of names) writeFileSync(join(dir, folder, name), "");
  }
  writeFileSync(join(dir, "README.md"), "");
  assert.deepEqual(collectTargets(dir), ["README.md", ...ordered.map(n => `docs/${n}`), ...ordered.map(n => `examples/${n}`)]);
});

test("unmerged fixture paths deduplicate stages and retain code-unit order", () => {
  // Exercise the existing test helper without running its integration suite twice.
  const source = readFileSync(join(root, "scripts/resolve-merge-conflicts.test.mjs"), "utf8");
  const helper = source.slice(source.indexOf("function unmerged("), source.indexOf("function longDoc("));
  const lines = names.flatMap(name => [1, 2, 3].map(stage => `100644 abc ${stage}\t${name}`)).join("\n");
  const actual = runInNewContext(`${helper}\nunmerged('fixture')`, { git: () => lines });
  assert.deepEqual(Array.from(actual), ordered);
});

test("attestation schema accepts reordered keys and rejects unexpected keys", (t) => {
  const dir = fixture(t);
  wrapper.ensurePrivateCacheDir(dir);
  const paths = wrapper.pathSet(dir);
  wrapper.writePrivateFile(paths.binaryPath, "fixture binary", 0o700);
  const stat = lstatSync(paths.binaryPath, { bigint: true });
  const identity = Object.fromEntries(["size", "mtimeNs", "ino", "dev", "ctimeNs"].map(key => [key, String(stat[key])]));
  const changedSha = createHash("sha256").update("different binary").digest("hex");
  const record = { versionChecked: true, version, sha256: changedSha, schema: 1, identity,
    attestedAtNs: String((stat.mtimeNs > stat.ctimeNs ? stat.mtimeNs : stat.ctimeNs) + 10_000_000_000n) };
  // A valid attestation avoids hashing; a mismatched manifest makes schema
  // refusal observable because fallback hashing rejects the binary.
  wrapper.writePrivateFile(paths.manifestPath, JSON.stringify({ sha256: changedSha, version }), 0o600);
  const save = () => {
    rmSync(wrapper.attestationPath(paths.binaryPath), { force: true });
    wrapper.writePrivateFile(wrapper.attestationPath(paths.binaryPath), JSON.stringify(record), 0o600);
  };
  save();
  assert.ok(wrapper.readVerifiedManifest(paths.binaryPath, paths.manifestPath));
  record.extra = true;
  save();
  assert.equal(wrapper.readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
  delete record.extra;
  record.identity.extra = "1";
  save();
  assert.equal(wrapper.readVerifiedManifest(paths.binaryPath, paths.manifestPath), null);
});

test("affected-crates reads option-shaped metadata names literally", (t) => {
  const dir = fixture(t);
  const metadata = { workspace_root: "/repo", workspace_members: ["z", "a"], packages: ["z", "a"].map(name => ({
    id: name, name, manifest_path: `/repo/crates/${name}/Cargo.toml`, dependencies: [],
  })) };
  for (const filename of ["metadata.json", "--help", "-metadata.json"]) {
    writeFileSync(join(dir, filename), JSON.stringify(metadata));
    for (const [input, expected] of [["crates/z/src/lib.rs\0crates/a/src/lib.rs\0", "a\nz\n"], ["README.md\0", "--workspace\n"], ["", ""]]) {
      const result = spawnSync("python3", [join(root, "scripts/affected-crates.py"), filename], { cwd: dir, input, encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, expected);
    }
  }
});

test("lock regeneration keeps cwd and package-manager arguments while disabling hooks", (t) => {
  const dir = fixture(t);
  const source = readFileSync(join(root, "scripts/resolve-merge-conflicts.sh"), "utf8");
  const helper = source.slice(source.indexOf("resolve_lock()"), source.indexOf("declare -a manual="));
  mkdirSync(join(dir, "nested"));
  for (const [filename, expected] of [["bun.lock", "install --ignore-scripts"], ["bun.lockb", "install --ignore-scripts"], ["package-lock.json", "install --package-lock-only --ignore-scripts"]]) {
    const result = spawnSync("bash", ["-c", `
      set -euo pipefail
      upstream=3
      blob() { :; }
      git() { :; }
      bun() { printf '%s|%s\\n' "$PWD" "$*"; }
      npm() { printf '%s|%s\\n' "$PWD" "$*"; }
      ${helper}
      resolve_lock "$1"
    `, "fixture", `nested/${filename}`], { cwd: dir, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.split("\n")[0], `${join(dir, "nested")}|${expected}`);
  }
});
