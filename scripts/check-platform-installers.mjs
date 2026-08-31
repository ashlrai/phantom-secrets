#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const shellInstaller = readFileSync(new URL("./install.sh", import.meta.url), "utf8");
const powershellInstaller = readFileSync(
  new URL("./install.ps1", import.meta.url),
  "utf8",
);
const publicShellInstaller = readFileSync(
  new URL("../apps/web/public/install.sh", import.meta.url),
  "utf8",
);
const publicPowershellInstaller = readFileSync(
  new URL("../apps/web/public/install.ps1", import.meta.url),
  "utf8",
);

assert.equal(
  publicShellInstaller,
  shellInstaller,
  "the served Unix installer must match scripts/install.sh",
);
assert.equal(
  publicPowershellInstaller,
  powershellInstaller,
  "the served Windows installer must match scripts/install.ps1",
);

function requires(source, pattern, label) {
  assert.match(source, pattern, label);
}

for (const [pattern, label] of [
  [/Darwin\) os="apple-darwin"/, "macOS target mapping"],
  [/Linux\)\s+os="unknown-linux-gnu"/, "Linux target mapping"],
  [/x86_64\|amd64\)\s+arch="x86_64"/, "Unix x64 mapping"],
  [/arm64\|aarch64\)\s+arch="aarch64"/, "Unix ARM64 mapping"],
  [/SHA-256 mismatch/, "Unix checksum enforcement"],
  [/phantom-mcp/, "Unix two-binary installation"],
]) {
  requires(shellInstaller, pattern, label);
}

for (const [pattern, label] of [
  [/'X64'\s+\{ \$target = 'x86_64-pc-windows-msvc' \}/, "Windows x64 mapping"],
  [/'Arm64'\s+\{ \$target = 'aarch64-pc-windows-msvc' \}/, "Windows ARM64 mapping"],
  [/Get-FileHash -Algorithm SHA256/, "Windows checksum calculation"],
  [/SHA-256 mismatch/, "Windows checksum enforcement"],
  [/phantom-mcp\.exe/, "Windows two-binary installation"],
]) {
  requires(powershellInstaller, pattern, label);
}

for (const [source, label] of [
  [shellInstaller, "Unix installer"],
  [powershellInstaller, "Windows installer"],
]) {
  assert.doesNotMatch(
    source,
    /signed release binary/i,
    `${label} must not claim unsigned artifacts are signed`,
  );
}

console.log("direct installer platform contract passed");
