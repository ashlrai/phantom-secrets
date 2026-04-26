#!/usr/bin/env node

const { execFileSync } = require("child_process");
const { existsSync, mkdirSync, createWriteStream, unlinkSync } = require("fs");
const { join } = require("path");
const https = require("https");
const crypto = require("crypto");
const { execSync } = require("child_process");

const VERSION = "0.5.1";
const REPO = "ashlrai/phantom-secrets";
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
  if (platform === "win32" && arch === "x64")
    return "x86_64-pc-windows-msvc";

  console.error(
    `Unsupported platform: ${platform}-${arch}. Install from source: cargo install phantom-secrets`
  );
  process.exit(1);
}

function getBinaryPath() {
  const ext = process.platform === "win32" ? ".exe" : "";
  return join(CACHE_DIR, `phantom${ext}`);
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

function parseSha256File(buf, expectedFilename) {
  // Standard `sha256sum` / `shasum -a 256` format: "<64-hex>  <filename>\n"
  const line = buf.toString("utf8").trim().split(/\r?\n/)[0] || "";
  const m = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/i);
  if (!m) return null;
  if (expectedFilename && m[2].trim() !== expectedFilename) return null;
  return m[1].toLowerCase();
}

async function ensureBinary() {
  const binaryPath = getBinaryPath();

  if (existsSync(binaryPath)) {
    return binaryPath;
  }

  const target = getPlatformTarget();
  const isWindows = process.platform === "win32";
  const archiveExt = isWindows ? "zip" : "tar.gz";
  const archiveName = `phantom-${target}.${archiveExt}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${archiveName}`;
  const sha256Url = `${url}.sha256`;

  console.error(`Downloading phantom v${VERSION} for ${target}...`);
  mkdirSync(CACHE_DIR, { recursive: true });

  const archivePath = join(CACHE_DIR, archiveName);

  try {
    // Fetch the checksum first so we fail before we've written anything to disk
    // if the release is missing its .sha256 sidecar.
    const sumBuf = await download(sha256Url);
    const expected = parseSha256File(sumBuf, archiveName);
    if (!expected) {
      throw new Error(
        `malformed or missing checksum at ${sha256Url} — refusing to install unverified binary`
      );
    }

    const data = await download(url);

    const actual = crypto.createHash("sha256").update(data).digest("hex");
    const expectedBuf = Buffer.from(expected, "hex");
    const actualBuf = Buffer.from(actual, "hex");
    if (
      expectedBuf.length !== actualBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, actualBuf)
    ) {
      throw new Error(
        `SHA-256 mismatch for ${archiveName}: expected ${expected}, got ${actual}`
      );
    }

    require("fs").writeFileSync(archivePath, data);

    // Extract
    if (isWindows) {
      // PowerShell Expand-Archive is present on Windows 10+ (PowerShell 5.0+).
      const psEscape = (s) => s.replace(/'/g, "''");
      execSync(
        `powershell -NoProfile -Command "Expand-Archive -LiteralPath '${psEscape(archivePath)}' -DestinationPath '${psEscape(CACHE_DIR)}' -Force"`,
        { stdio: "pipe" }
      );
    } else {
      execSync(`tar xzf "${archivePath}" -C "${CACHE_DIR}"`, { stdio: "pipe" });
      execSync(`chmod +x "${binaryPath}"`, { stdio: "pipe" });
    }

    // Clean up archive
    unlinkSync(archivePath);

    console.error(`Installed phantom to ${binaryPath}`);
  } catch (err) {
    console.error(`Failed to download phantom: ${err.message}`);
    console.error(
      `Install from source: cargo install phantom-secrets`
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
