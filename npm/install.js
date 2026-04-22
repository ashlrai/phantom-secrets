#!/usr/bin/env node

// Pre-download the phantom binary during npm install
// so it's ready when the user first runs `phantom-secrets`

const { existsSync } = require("fs");
const { join } = require("path");

const CACHE_DIR = join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".phantom-secrets",
  "bin"
);

const binaryExt = process.platform === "win32" ? ".exe" : "";
const binaryPath = join(CACHE_DIR, `phantom${binaryExt}`);

if (existsSync(binaryPath)) {
  console.log("phantom binary already installed.");
  process.exit(0);
}

// Import and run the download from cli.js
console.log("Pre-downloading phantom binary...");
// The actual download happens on first run via cli.js
// This is a no-op placeholder — the binary downloads lazily on first use
console.log("phantom will download on first use.");
