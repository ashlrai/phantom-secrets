#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { lstatSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { validateNativeRuntime } from "./native-release-smoke.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(import.meta.url);
const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;
const primaryWrapper = require(resolve(repoRoot, "npm/bin/cli.js"));
const mcpWrapper = require(resolve(repoRoot, "npm-mcp/bin/cli.js"));

function stableVersion(tag) {
  if (!/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(tag ?? "")) {
    throw new Error(`npm wrapper acceptance requires a stable v<semver> tag, got ${tag}`);
  }
  return tag.slice(1);
}

async function acceptWrapper({ wrapper, binaryName, archive, archiveBytes, archiveSha, version }) {
  const cacheDir = mkdtempSync(join(tmpdir(), `phantom-${binaryName}-native-`));
  try {
    wrapper.ensurePrivateCacheDir(cacheDir);
    const binaryPath = await wrapper.ensureBinary({
      cacheDir,
      runtime: { platform: process.platform, arch: process.arch },
      downloadImpl: async (url) => {
        if (url.endsWith(".sha256")) {
          return Buffer.from(`${archiveSha}  ${basename(archive)}\n`);
        }
        if (url.endsWith(`/${basename(archive)}`)) return archiveBytes;
        throw new Error("wrapper requested an unexpected release URL");
      },
    });
    const output = execFileSync(binaryPath, ["--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
      windowsHide: true,
    });
    assert.equal(output.replace(/\r\n/g, "\n"), `${binaryName} ${version}\n`);
    assert.ok(wrapper.readVerifiedManifest(binaryPath, `${binaryPath}.manifest.json`));
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
}

export async function runNpmWrapperNativeAcceptance({
  archivePath,
  target,
  tag,
  env = process.env,
  runtime = process,
}) {
  if (!archivePath || !target || !tag) {
    throw new Error("npm wrapper acceptance requires an archive path, target, and release tag");
  }
  const contract = validateNativeRuntime(target, env, runtime);
  const version = stableVersion(tag);
  const archive = resolve(archivePath);
  const stat = lstatSync(archive);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
    throw new Error("npm wrapper acceptance archive must be one regular single-link file");
  }
  if (stat.size < 1 || stat.size > MAX_ARCHIVE_BYTES) {
    throw new Error("npm wrapper acceptance archive must be between 1 byte and 100 MiB");
  }
  if (basename(archive) !== contract.archive) {
    throw new Error(`npm wrapper acceptance expected ${contract.archive}`);
  }
  const archiveBytes = readFileSync(archive);
  const archiveSha = createHash("sha256").update(archiveBytes).digest("hex");

  await acceptWrapper({
    wrapper: mcpWrapper,
    binaryName: "phantom-mcp",
    archive,
    archiveBytes,
    archiveSha,
    version,
  });
  await acceptWrapper({
    wrapper: primaryWrapper,
    binaryName: "phantom",
    archive,
    archiveBytes,
    archiveSha,
    version,
  });

  console.log(
    `npm wrapper native acceptance passed: ${target} ${tag} archive_sha256=${archiveSha}`
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await runNpmWrapperNativeAcceptance({
    archivePath: process.env.PHANTOM_NATIVE_ARCHIVE,
    target: process.env.PHANTOM_NATIVE_TARGET,
    tag: process.env.PHANTOM_RELEASE_TAG,
  });
}
