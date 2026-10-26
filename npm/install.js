#!/usr/bin/env node

// Keep installation fast and side-effect-light. The native binary downloads
// lazily on first run via bin/cli.js.

const { existsSync } = require("fs");
const { join } = require("path");
const { getCacheDir } = require("./bin/cli.js");

const CACHE_DIR = getCacheDir();

const binaryExt = process.platform === "win32" ? ".exe" : "";
const binaryPath = join(CACHE_DIR, `phantom${binaryExt}`);

if (existsSync(binaryPath)) {
  console.log("phantom binary already installed.");
  process.exit(0);
}

console.log("phantom will download on first use.");
