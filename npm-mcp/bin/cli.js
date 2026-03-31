#!/usr/bin/env node

const { execFileSync } = require("child_process");
const { existsSync, mkdirSync, unlinkSync } = require("fs");
const { join } = require("path");
const https = require("https");
const { execSync } = require("child_process");

const VERSION = "0.3.3";
const REPO = "ashlrai/phantom-secrets";
const BINARY_NAME = "phantom-mcp";
const CACHE_DIR = join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".phantom-secrets",
  "bin"
);

function getPlatformTarget() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "darwin" && arch === "arm64")
    return "aarch64-apple-darwin";
  if (platform === "darwin" && arch === "x64")
    return "x86_64-apple-darwin";
  if (platform === "linux" && arch === "x64")
    return "x86_64-unknown-linux-gnu";
  if (platform === "linux" && arch === "arm64")
    return "aarch64-unknown-linux-gnu";

  console.error(
    `Unsupported platform: ${platform}-${arch}. Install from source: cargo install phantom --git https://github.com/${REPO}`
  );
  process.exit(1);
}

function getBinaryPath() {
  return join(CACHE_DIR, BINARY_NAME);
}

function download(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

async function ensureBinary() {
  const binaryPath = getBinaryPath();

  if (existsSync(binaryPath)) {
    return binaryPath;
  }

  const target = getPlatformTarget();
  const tarball = `phantom-${target}.tar.gz`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${tarball}`;

  console.error(`Downloading phantom-mcp v${VERSION} for ${target}...`);
  mkdirSync(CACHE_DIR, { recursive: true });

  const tarPath = join(CACHE_DIR, tarball);

  try {
    const data = await download(url);
    require("fs").writeFileSync(tarPath, data);

    execSync(`tar xzf "${tarPath}" -C "${CACHE_DIR}"`, { stdio: "pipe" });
    execSync(`chmod +x "${binaryPath}"`, { stdio: "pipe" });

    unlinkSync(tarPath);

    console.error(`Installed phantom-mcp to ${binaryPath}`);
  } catch (err) {
    console.error(`Failed to download phantom-mcp: ${err.message}`);
    console.error(
      `Install from source: cargo install phantom --git https://github.com/${REPO}`
    );
    process.exit(1);
  }

  return binaryPath;
}

async function main() {
  const binary = await ensureBinary();
  const args = process.argv.slice(2);

  try {
    execFileSync(binary, args, { stdio: "inherit" });
  } catch (err) {
    process.exit(err.status || 1);
  }
}

main();
