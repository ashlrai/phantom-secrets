import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { compareReleaseArtifacts } from "./compare-release-artifacts.mjs";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-release-compare-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const trusted = path.join(root, "trusted");
  const hosted = path.join(root, "hosted");
  fs.mkdirSync(path.join(trusted, "nested"), { recursive: true });
  fs.mkdirSync(hosted);

  const archive = "trusted archive bytes\n";
  const digest = sha256(archive);
  const files = new Map([
    ["phantom-x86_64-unknown-linux-gnu.tar.gz", archive],
    ["phantom-x86_64-unknown-linux-gnu.tar.gz.sha256", `${digest}  phantom-x86_64-unknown-linux-gnu.tar.gz\n`],
    ["phantom-x86_64-unknown-linux-gnu.tar.gz.spdx.json", '{"name":"trusted SBOM"}\n'],
    ["SHA256SUMS", `${digest}  phantom-x86_64-unknown-linux-gnu.tar.gz\n`],
  ]);
  for (const [name, contents] of files) {
    fs.writeFileSync(path.join(trusted, "nested", name), contents);
    fs.writeFileSync(path.join(hosted, name), contents);
  }
  return { trusted, hosted };
}

test("accepts the same files by basename across different directory layouts", (t) => {
  const { trusted, hosted } = fixture(t);
  assert.deepEqual(compareReleaseArtifacts(trusted, hosted), { files: 4 });
});

test("rejects a self-consistent hosted archive, checksums, and SBOM replacement", (t) => {
  const { trusted, hosted } = fixture(t);
  const archiveName = "phantom-x86_64-unknown-linux-gnu.tar.gz";
  const replacement = "replacement archive bytes\n";
  const digest = sha256(replacement);
  fs.writeFileSync(path.join(hosted, archiveName), replacement);
  fs.writeFileSync(path.join(hosted, `${archiveName}.sha256`), `${digest}  ${archiveName}\n`);
  fs.writeFileSync(path.join(hosted, `${archiveName}.spdx.json`), '{"name":"replacement SBOM"}\n');
  fs.writeFileSync(path.join(hosted, "SHA256SUMS"), `${digest}  ${archiveName}\n`);

  assert.throws(
    () => compareReleaseArtifacts(trusted, hosted),
    /hosted release artifact differs from trusted build/,
  );
});

test("rejects extra, missing, and duplicate hosted basenames", async (t) => {
  await t.test("extra", () => {
    const { trusted, hosted } = fixture(t);
    fs.writeFileSync(path.join(hosted, "extra.bin"), "extra");
    assert.throws(() => compareReleaseArtifacts(trusted, hosted), /name set mismatch/);
  });

  await t.test("missing", () => {
    const { trusted, hosted } = fixture(t);
    fs.rmSync(path.join(hosted, "SHA256SUMS"));
    assert.throws(() => compareReleaseArtifacts(trusted, hosted), /name set mismatch/);
  });

  await t.test("duplicate", () => {
    const { trusted, hosted } = fixture(t);
    const duplicateDir = path.join(hosted, "duplicate");
    fs.mkdirSync(duplicateDir);
    fs.copyFileSync(path.join(hosted, "SHA256SUMS"), path.join(duplicateDir, "SHA256SUMS"));
    assert.throws(() => compareReleaseArtifacts(trusted, hosted), /duplicate basename/);
  });
});
