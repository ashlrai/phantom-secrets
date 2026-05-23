#!/usr/bin/env node

// Keep installation fast and side-effect-light. The native binary downloads
// lazily on first run via bin/cli.js.

const { existsSync } = require("fs");
const { join } = require("path");

const CACHE_DIR = join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".phantom-secrets",
  "bin"
);

const binaryExt = process.platform === "win32" ? ".exe" : "";
const binaryPath = join(CACHE_DIR, `phantom-mcp${binaryExt}`);

if (existsSync(binaryPath)) {
  console.log("phantom-mcp binary already installed.");
  process.exit(0);
}

// The actual download happens on first run via cli.js
console.log("phantom-secrets-mcp will download on first use.");
