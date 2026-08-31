#!/usr/bin/env node

import fs from "node:fs";

const [receiptPath, expectedTag, expectedState] = process.argv.slice(2);
if (!receiptPath || !/^v\d+\.\d+\.\d+$/.test(expectedTag ?? "")) {
  console.error(
    "usage: verify-github-release-receipt.mjs RECEIPT.json vMAJOR.MINOR.PATCH draft|published",
  );
  process.exit(2);
}
if (expectedState !== "draft" && expectedState !== "published") {
  console.error("release state must be draft or published");
  process.exit(2);
}

const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
const archives = [
  "phantom-aarch64-apple-darwin.tar.gz",
  "phantom-x86_64-apple-darwin.tar.gz",
  "phantom-aarch64-unknown-linux-gnu.tar.gz",
  "phantom-x86_64-unknown-linux-gnu.tar.gz",
  "phantom-aarch64-pc-windows-msvc.zip",
  "phantom-x86_64-pc-windows-msvc.zip",
];
const expectedAssets = ["SHA256SUMS"];
for (const archive of archives) {
  expectedAssets.push(archive, `${archive}.sha256`, `${archive}.spdx.json`);
}

if (receipt.tagName !== expectedTag) {
  throw new Error(`release tag mismatch: ${receipt.tagName}`);
}
if (receipt.isPrerelease !== false) {
  throw new Error("release must not be a prerelease");
}
if (receipt.isDraft !== (expectedState === "draft")) {
  throw new Error(`release is not in expected ${expectedState} state`);
}
if (!Array.isArray(receipt.assets)) {
  throw new Error("release assets are missing");
}

const names = receipt.assets.map(({ name }) => name).sort();
const expectedNames = expectedAssets.toSorted();
if (JSON.stringify(names) !== JSON.stringify(expectedNames)) {
  const actual = new Set(names);
  const expected = new Set(expectedNames);
  const missing = expectedNames.filter((name) => !actual.has(name));
  const extra = names.filter((name) => !expected.has(name));
  throw new Error(
    `release asset set mismatch; missing=${missing.join(",")} extra=${extra.join(",")}`,
  );
}

for (const asset of receipt.assets) {
  if (asset.state !== "uploaded" || !Number.isSafeInteger(asset.size) || asset.size < 1) {
    throw new Error(`release asset is incomplete: ${asset.name}`);
  }
  const baseUrl = "https://github.com/ashlrai/phantom-secrets/releases/download/";
  const publishedPrefix = `${baseUrl}${expectedTag}/`;
  if (
    typeof asset.url !== "string" ||
    !asset.url.startsWith(expectedState === "draft" ? baseUrl : publishedPrefix) ||
    !asset.url.endsWith(`/${asset.name}`)
  ) {
    throw new Error(`release asset URL is invalid: ${asset.name}`);
  }
}

console.log(
  `Verified ${expectedState} GitHub release receipt for ${expectedTag}: ${names.length} assets`,
);
