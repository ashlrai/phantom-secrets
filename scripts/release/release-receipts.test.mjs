import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const verifier = path.join(
  repoRoot,
  "scripts/release/verify-github-release-receipt.mjs",
);
const archives = [
  "phantom-aarch64-apple-darwin.tar.gz",
  "phantom-x86_64-apple-darwin.tar.gz",
  "phantom-aarch64-unknown-linux-gnu.tar.gz",
  "phantom-x86_64-unknown-linux-gnu.tar.gz",
  "phantom-aarch64-pc-windows-msvc.zip",
  "phantom-x86_64-pc-windows-msvc.zip",
];

function assetNames() {
  const names = ["SHA256SUMS"];
  for (const archive of archives) {
    names.push(archive, `${archive}.sha256`, `${archive}.spdx.json`);
  }
  return names;
}

function receipt(state = "draft") {
  const releasePath = state === "draft" ? "untagged-draft" : "v0.7.3";
  return {
    tagName: "v0.7.3",
    isDraft: state === "draft",
    isPrerelease: false,
    assets: assetNames().map((name) => ({
      name,
      size: 10,
      state: "uploaded",
      url: `https://github.com/ashlrai/phantom-secrets/releases/download/${releasePath}/${name}`,
    })),
  };
}

function verify(payload, state) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-release-receipt-"));
  const receiptPath = path.join(directory, "receipt.json");
  fs.writeFileSync(receiptPath, JSON.stringify(payload));
  return spawnSync(process.execPath, [verifier, receiptPath, "v0.7.3", state], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

test("accepts complete draft and published immutable release receipts", () => {
  assert.equal(verify(receipt("draft"), "draft").status, 0);
  assert.equal(verify(receipt("published"), "published").status, 0);
});

test("rejects missing, extra, empty, incomplete, or wrong-state assets", () => {
  const cases = [];

  const missing = receipt();
  missing.assets.pop();
  cases.push(missing);

  const extra = receipt();
  extra.assets.push({
    name: "unexpected.bin",
    size: 1,
    state: "uploaded",
    url: "https://github.com/ashlrai/phantom-secrets/releases/download/untagged-draft/unexpected.bin",
  });
  cases.push(extra);

  const empty = receipt();
  empty.assets[0].size = 0;
  cases.push(empty);

  const incomplete = receipt();
  incomplete.assets[0].state = "new";
  cases.push(incomplete);

  const published = receipt("published");
  cases.push(published);

  for (const payload of cases) {
    assert.notEqual(verify(payload, "draft").status, 0);
  }
});
