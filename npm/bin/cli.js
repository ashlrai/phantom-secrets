#!/usr/bin/env node

const { execFileSync } = require("child_process");
const crypto = require("crypto");
const {
  chmodSync,
  closeSync,
  constants: fsConstants,
  copyFileSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} = require("fs");
const https = require("https");
const { homedir } = require("os");
const { basename, dirname, isAbsolute, join, resolve } = require("path");

const VERSION = "0.7.4";
const REPO = "ashlrai/phantom-secrets";
const BINARY_NAME = "phantom";
const REVIEWED_RELEASE_URL = `https://github.com/${REPO}/releases/tag/v${VERSION}`;
const REVIEWED_RELEASE_GUIDANCE =
  `Use the checksum-verifiable ${BINARY_NAME} assets from the reviewed release: ${REVIEWED_RELEASE_URL}`;
const MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 5;
const LOCK_WAIT_MS = 30_000;
const LOCK_STALE_MS = 2 * 60_000;
const LOCK_HEARTBEAT_MS = 10_000;
const EXEC_TIMEOUT_MS = 30_000;
const ALLOWED_DOWNLOAD_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);

// The manifest protects against accidental corruption and unverified cache
// execution. It is not a signature: a process already able to write as this
// user can replace both files. Publisher compromise likewise requires signed
// release provenance, which is intentionally outside this local wrapper.

const SUPPORTED_TARGETS = Object.freeze({
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "linux-x64": "x86_64-unknown-linux-gnu",
  "win32-arm64": "aarch64-pc-windows-msvc",
  "win32-x64": "x86_64-pc-windows-msvc",
});

function unsupportedPlatformMessage(runtime = process) {
  return `Unsupported platform: ${runtime.platform}-${runtime.arch}. ${REVIEWED_RELEASE_GUIDANCE}`;
}

function getPlatformTarget(runtime = process) {
  const target = SUPPORTED_TARGETS[`${runtime.platform}-${runtime.arch}`];
  if (!target) throw new Error(unsupportedPlatformMessage(runtime));
  return target;
}

function getBinaryFilename(platform = process.platform) {
  return platform === "win32" ? `${BINARY_NAME}.exe` : BINARY_NAME;
}

function getCacheDir({ env = process.env, homedirImpl = homedir } = {}) {
  const home = env.HOME || env.USERPROFILE || homedirImpl();
  if (!home || !isAbsolute(home)) {
    throw new Error("cannot determine an absolute private home directory for phantom cache");
  }
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- home is required to be absolute and is resolved before fixed components are appended.
  return join(resolve(home), ".phantom-secrets", "bin");
}

function pathSet(cacheDir, platform = process.platform) {
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- cacheDir is the validated private cache root and the filename is selected from a closed platform map.
  const binaryPath = join(cacheDir, getBinaryFilename(platform));
  return {
    binaryPath,
    manifestPath: `${binaryPath}.manifest.json`,
    backupBinaryPath: `${binaryPath}.previous`,
    backupManifestPath: `${binaryPath}.manifest.previous`,
    // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- fixed child of the validated private cache root.
    transactionPath: join(cacheDir, ".cli-install-transaction.json"),
    // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- fixed sibling lock derived from the validated private cache root so direct and npm installers share ownership.
    lockPath: join(dirname(cacheDir), `.${basename(cacheDir)}.install.lock`),
    // Explicitly overrides a stale direct-installer receipt in the shared root.
    sourceMarkerPath: join(cacheDir, ".phantom-install-source.npm-cli"),
  };
}

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

function validateOwnedPath(path, kind, platform = process.platform) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) throw new Error(`${path} must not be a symbolic link`);
  if (kind === "directory" && !stat.isDirectory()) throw new Error(`${path} must be a directory`);
  if (kind === "file" && (!stat.isFile() || stat.nlink !== 1)) {
    throw new Error(`${path} must be a regular single-link file`);
  }
  if (platform !== "win32") {
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      throw new Error(`${path} is not owned by the current user`);
    }
    if ((stat.mode & 0o077) !== 0) throw new Error(`${path} is not private`);
  }
  return stat;
}

function ensurePrivateCacheDir(cacheDir, platform = process.platform) {
  mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  const stat = lstatSync(cacheDir);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${cacheDir} must be a real directory`);
  }
  if (
    platform !== "win32" &&
    typeof process.getuid === "function" &&
    stat.uid !== process.getuid()
  ) {
    throw new Error(`${cacheDir} is not owned by the current user`);
  }
  if (platform !== "win32") chmodSync(cacheDir, 0o700);
  validateOwnedPath(cacheDir, "directory", platform);
}

function fsyncFile(path) {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function fsyncDirectory(path, platform = process.platform) {
  if (platform === "win32") return;
  let fd;
  try {
    fd = openSync(path, "r");
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function writePrivateFile(path, data, mode = 0o600, platform = process.platform) {
  const fd = openSync(path, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, mode);
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (platform !== "win32") chmodSync(path, mode);
  validateOwnedPath(path, "file", platform);
}

function writeAtomicPrivateFile(path, data, mode = 0o600, platform = process.platform) {
  const tempPath = `${path}.tmp-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
  try {
    writePrivateFile(tempPath, data, mode, platform);
    renameSync(tempPath, path);
    fsyncDirectory(dirname(path), platform);
  } finally {
    removeFileIfExists(tempPath);
  }
}

function removeFileIfExists(path) {
  try {
    unlinkSync(path);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function ensureNpmSourceMarker(path, platform = process.platform) {
  try {
    const contents = readFileSync(path, "utf8");
    validateOwnedPath(path, "file", platform);
    if (contents !== "npm\n") throw new Error("invalid npm install-source marker");
    return;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  writePrivateFile(path, "npm\n", 0o600, platform);
  fsyncDirectory(dirname(path), platform);
}

function sha256File(path) {
  return crypto.createHash("sha256").update(readFileSync(path)).digest("hex");
}

const SEMVER_SOURCE =
  "(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)" +
  "(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?" +
  "(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?";

function parseBinaryVersion(output) {
  const text = Buffer.isBuffer(output) ? output.toString("utf8") : String(output);
  const match = text.match(new RegExp(`^${BINARY_NAME} (${SEMVER_SOURCE})\\r?\\n?$`));
  return match ? match[1] : null;
}

function parseSha256File(buf, expectedFilename) {
  const lines = buf.toString("utf8").trim().split(/\r?\n/);
  if (lines.length !== 1) return null;
  const match = lines[0].match(/^([0-9a-f]{64})\s+\*?(.+)$/i);
  if (!match || (expectedFilename && match[2].trim() !== expectedFilename)) return null;
  return match[1].toLowerCase();
}

function readVerifiedManifest(binaryPath, manifestPath, platform = process.platform) {
  try {
    validateOwnedPath(binaryPath, "file", platform);
    const manifestStat = validateOwnedPath(manifestPath, "file", platform);
    if (manifestStat.size > 4096) return null;
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (
      !manifest ||
      Object.keys(manifest).sort().join(",") !== "sha256,version" ||
      manifest.version !== VERSION ||
      !/^[0-9a-f]{64}$/.test(manifest.sha256) ||
      sha256File(binaryPath) !== manifest.sha256
    ) return null;
    return manifest;
  } catch {
    return null;
  }
}

function runBoundedExec(
  execFileSyncImpl,
  executable,
  args,
  options,
  { timeoutMs = EXEC_TIMEOUT_MS, heartbeat = () => {} } = {}
) {
  heartbeat();
  try {
    return execFileSyncImpl(executable, args, {
      ...options,
      timeout: timeoutMs,
      killSignal: "SIGKILL",
    });
  } finally {
    heartbeat();
  }
}

function validateCachedBinary(binaryPath, manifestPath, {
  execFileSyncImpl = execFileSync,
  platform = process.platform,
  execTimeoutMs = EXEC_TIMEOUT_MS,
  heartbeat = () => {},
} = {}) {
  if (!readVerifiedManifest(binaryPath, manifestPath, platform)) return false;
  try {
    const output = runBoundedExec(
      execFileSyncImpl,
      binaryPath,
      ["--version"],
      { stdio: ["ignore", "pipe", "ignore"] },
      { timeoutMs: execTimeoutMs, heartbeat }
    );
    return parseBinaryVersion(output) === VERSION;
  } catch {
    return false;
  }
}

function isCachedBinaryStale(binaryPath, options = {}) {
  return !validateCachedBinary(binaryPath, `${binaryPath}.manifest.json`, options);
}

function allowedDownloadUrl(value, allowedHosts = ALLOWED_DOWNLOAD_HOSTS) {
  const url = value instanceof URL ? value : new URL(value);
  if (url.protocol !== "https:" || !allowedHosts.has(url.hostname)) {
    throw new Error(`refusing download from untrusted URL ${url.origin}`);
  }
  if (url.username || url.password) throw new Error("download URL must not contain credentials");
  return url;
}

function download(inputUrl, {
  httpsGet = https.get,
  maxBytes = MAX_DOWNLOAD_BYTES,
  timeoutMs = DOWNLOAD_TIMEOUT_MS,
  maxRedirects = MAX_REDIRECTS,
  allowedHosts = ALLOWED_DOWNLOAD_HOSTS,
} = {}) {
  return new Promise((resolvePromise, reject) => {
    let settled = false;
    let request;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolvePromise(value);
    };
    const timer = setTimeout(() => {
      const error = new Error(`download timed out after ${timeoutMs}ms`);
      if (request && typeof request.destroy === "function") request.destroy(error);
      finish(error);
    }, timeoutMs);

    const fetch = (value, redirects) => {
      let url;
      try {
        url = allowedDownloadUrl(value, allowedHosts);
      } catch (error) {
        finish(error);
        return;
      }
      request = httpsGet(url, (response) => {
        const status = response.statusCode || 0;
        if (status >= 300 && status < 400 && response.headers.location) {
          if (typeof response.resume === "function") response.resume();
          if (redirects >= maxRedirects) {
            finish(new Error(`too many redirects downloading ${inputUrl}`));
            return;
          }
          let next;
          try {
            next = new URL(response.headers.location, url);
          } catch (error) {
            finish(error);
            return;
          }
          fetch(next, redirects + 1);
          return;
        }
        if (status !== 200) {
          if (typeof response.resume === "function") response.resume();
          finish(new Error(`HTTP ${status}`));
          return;
        }
        const chunks = [];
        let bytes = 0;
        response.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > maxBytes) {
            if (typeof response.destroy === "function") response.destroy();
            finish(new Error(`download exceeds ${maxBytes} byte limit`));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => finish(null, Buffer.concat(chunks)));
        response.on("error", finish);
      });
      request.on("error", finish);
    };
    fetch(inputUrl, 0);
  });
}

function expectedArchiveEntries(platform = process.platform) {
  return platform === "win32" ? ["phantom-mcp.exe", "phantom.exe"] : ["phantom", "phantom-mcp"];
}

function extractBinaryFromArchive(archivePath, binaryPath, {
  cacheDir = dirname(dirname(binaryPath)),
  platform = process.platform,
  execFileSyncImpl = execFileSync,
  execTimeoutMs = EXEC_TIMEOUT_MS,
  heartbeat = () => {},
} = {}) {
  validateOwnedPath(archivePath, "file", platform);
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- mkdtemp receives a fixed prefix under the validated private cache root.
  const stagingDir = mkdtempSync(join(cacheDir, ".extract-"));
  if (platform !== "win32") chmodSync(stagingDir, 0o700);
  const binaryFilename = getBinaryFilename(platform);
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- stagingDir is freshly created and binaryFilename comes from a closed platform map.
  const extractedBinaryPath = join(stagingDir, binaryFilename);
  try {
    if (platform === "win32") {
      const script = [
        "& { param($archive, $output)",
        "Add-Type -AssemblyName System.IO.Compression.FileSystem;",
        "$zip = [IO.Compression.ZipFile]::OpenRead($archive);",
        "try {",
        "$names = @($zip.Entries | ForEach-Object { $_.FullName });",
        "$expected = @('phantom.exe','phantom-mcp.exe');",
        "if ($names.Count -ne 2 -or (@($names | Sort-Object) -join ',') -ne (@($expected | Sort-Object) -join ',')) { throw 'unexpected ZIP content' };",
        "$entry = $zip.GetEntry('phantom.exe');",
        "[IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $output, $false);",
        "} finally { $zip.Dispose() }",
        "}",
      ].join(" ");
      runBoundedExec(
        execFileSyncImpl,
        "powershell",
        ["-NoProfile", "-NonInteractive", "-Command", script, archivePath, extractedBinaryPath],
        { stdio: "pipe" },
        { timeoutMs: execTimeoutMs, heartbeat }
      );
    } else {
      const listing = runBoundedExec(
        execFileSyncImpl,
        "tar",
        ["tzf", archivePath],
        { encoding: "utf8" },
        { timeoutMs: execTimeoutMs, heartbeat }
      );
      const entries = listing.split(/\r?\n/).filter(Boolean).sort();
      const expected = expectedArchiveEntries(platform).slice().sort();
      if (JSON.stringify(entries) !== JSON.stringify(expected)) {
        throw new Error(`archive contains unexpected entries: ${entries.join(", ")}`);
      }
      runBoundedExec(
        execFileSyncImpl,
        "tar",
        ["xzf", archivePath, "-C", stagingDir, binaryFilename],
        { stdio: "pipe" },
        { timeoutMs: execTimeoutMs, heartbeat }
      );
    }
    validateOwnedPath(extractedBinaryPath, "file", platform);
    copyFileSync(extractedBinaryPath, binaryPath, fsConstants.COPYFILE_EXCL);
    if (platform !== "win32") chmodSync(binaryPath, 0o700);
    validateOwnedPath(binaryPath, "file", platform);
    fsyncFile(binaryPath);
  } finally {
    rmSync(stagingDir, { recursive: true, force: true });
  }
}

function installLockOwnerPath(lockPath) {
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- owner is a fixed child of the validated install-lock directory.
  return join(lockPath, "owner");
}

function readInstallLock(lockPath, platform = process.platform) {
  const directoryStat = validateOwnedPath(lockPath, "directory", platform);
  const ownerPath = installLockOwnerPath(lockPath);
  try {
    const ownerStat = validateOwnedPath(ownerPath, "file", platform);
    if (ownerStat.size > 128) return { token: null, mtimeMs: ownerStat.mtimeMs };
    const token = readFileSync(ownerPath, "utf8").trim();
    return {
      token: /^[0-9a-f]{64}$/.test(token) ? token : null,
      mtimeMs: ownerStat.mtimeMs,
    };
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return { token: null, mtimeMs: directoryStat.mtimeMs };
  }
}

function createOwnedInstallLock(lockPath, token, platform) {
  mkdirSync(lockPath, { mode: 0o700 });
  try {
    validateOwnedPath(lockPath, "directory", platform);
    writeAtomicPrivateFile(
      installLockOwnerPath(lockPath),
      `${token}\n`,
      0o600,
      platform
    );
    fsyncDirectory(lockPath, platform);
    fsyncDirectory(dirname(lockPath), platform);
  } catch (error) {
    rmSync(lockPath, { recursive: true, force: true });
    throw error;
  }
}

async function acquireInstallLock(lockPath, {
  waitMs = LOCK_WAIT_MS,
  staleMs = LOCK_STALE_MS,
  pollMs = 50,
  heartbeatMs = LOCK_HEARTBEAT_MS,
  platform = process.platform,
} = {}) {
  if (heartbeatMs < 1 || heartbeatMs >= staleMs) {
    throw new Error("install lock heartbeat must be positive and shorter than stale timeout");
  }
  const deadline = Date.now() + waitMs;
  const token = crypto.randomBytes(32).toString("hex");
  while (true) {
    try {
      createOwnedInstallLock(lockPath, token, platform);
      let released = false;
      let heartbeatFailure;
      const heartbeat = () => {
        if (released) throw new Error("phantom install lock is already released");
        if (heartbeatFailure) throw heartbeatFailure;
        const current = readInstallLock(lockPath, platform);
        if (current.token !== token) {
          throw new Error("phantom install lock ownership was lost");
        }
        const now = new Date();
        utimesSync(installLockOwnerPath(lockPath), now, now);
      };
      const timer = setInterval(() => {
        try {
          heartbeat();
        } catch (error) {
          heartbeatFailure = error;
          clearInterval(timer);
        }
      }, heartbeatMs);
      timer.unref();

      const release = () => {
        if (released) return false;
        released = true;
        clearInterval(timer);
        let current;
        try {
          current = readInstallLock(lockPath, platform);
        } catch (error) {
          if (error.code === "ENOENT") return false;
          throw error;
        }
        if (current.token !== token) return false;
        rmSync(lockPath, { recursive: true, force: false });
        fsyncDirectory(dirname(lockPath), platform);
        return true;
      };
      release.heartbeat = heartbeat;
      release.ownerToken = token;
      return release;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const current = readInstallLock(lockPath, platform);
      if (Date.now() - current.mtimeMs > staleMs) {
        const stalePath = `${lockPath}.stale-${crypto.randomBytes(16).toString("hex")}`;
        try {
          renameSync(lockPath, stalePath);
        } catch (renameError) {
          if (renameError.code === "ENOENT") continue;
          throw renameError;
        }
        fsyncDirectory(dirname(lockPath), platform);
        rmSync(stalePath, { recursive: true, force: true });
        fsyncDirectory(dirname(lockPath), platform);
        continue;
      }
      if (Date.now() >= deadline) throw new Error("timed out waiting for phantom install lock");
      await sleep(Math.min(pollMs, Math.max(1, deadline - Date.now())));
    }
  }
}

function recoverInterruptedInstall(paths, platform = process.platform) {
  if (readVerifiedManifest(paths.binaryPath, paths.manifestPath, platform)) {
    removeFileIfExists(paths.backupBinaryPath);
    removeFileIfExists(paths.backupManifestPath);
    removeFileIfExists(paths.transactionPath);
    fsyncDirectory(dirname(paths.binaryPath), platform);
    return "current";
  }
  if (readVerifiedManifest(paths.backupBinaryPath, paths.backupManifestPath, platform)) {
    removeFileIfExists(paths.binaryPath);
    removeFileIfExists(paths.manifestPath);
    renameSync(paths.backupBinaryPath, paths.binaryPath);
    renameSync(paths.backupManifestPath, paths.manifestPath);
    removeFileIfExists(paths.transactionPath);
    fsyncDirectory(dirname(paths.binaryPath), platform);
    return "restored-backup";
  }
  if (existsSync(paths.binaryPath) && !existsSync(paths.manifestPath) && existsSync(paths.backupManifestPath)) {
    renameSync(paths.backupManifestPath, paths.manifestPath);
    if (readVerifiedManifest(paths.binaryPath, paths.manifestPath, platform)) {
      removeFileIfExists(paths.transactionPath);
      fsyncDirectory(dirname(paths.binaryPath), platform);
      return "restored-manifest";
    }
  }
  for (const path of [
    paths.binaryPath, paths.manifestPath, paths.backupBinaryPath,
    paths.backupManifestPath, paths.transactionPath,
  ]) removeFileIfExists(path);
  fsyncDirectory(dirname(paths.binaryPath), platform);
  return "cleaned";
}

function replaceCachedBinary(candidatePath, candidateManifestPath, paths, platform = process.platform) {
  if (!readVerifiedManifest(candidatePath, candidateManifestPath, platform)) {
    throw new Error("candidate binary metadata is invalid");
  }
  const cacheDir = dirname(paths.binaryPath);
  writeAtomicPrivateFile(paths.transactionPath, JSON.stringify({ version: VERSION }) + "\n", 0o600, platform);
  const hadPrevious = Boolean(readVerifiedManifest(paths.binaryPath, paths.manifestPath, platform));
  if (hadPrevious) {
    renameSync(paths.manifestPath, paths.backupManifestPath);
    fsyncDirectory(cacheDir, platform);
    renameSync(paths.binaryPath, paths.backupBinaryPath);
    fsyncDirectory(cacheDir, platform);
  } else {
    removeFileIfExists(paths.binaryPath);
    removeFileIfExists(paths.manifestPath);
  }
  try {
    renameSync(candidatePath, paths.binaryPath);
    fsyncDirectory(cacheDir, platform);
    renameSync(candidateManifestPath, paths.manifestPath);
    fsyncDirectory(cacheDir, platform);
    if (!readVerifiedManifest(paths.binaryPath, paths.manifestPath, platform)) {
      throw new Error("installed binary failed post-replacement validation");
    }
  } catch (error) {
    recoverInterruptedInstall(paths, platform);
    throw error;
  }
  removeFileIfExists(paths.backupBinaryPath);
  removeFileIfExists(paths.backupManifestPath);
  removeFileIfExists(paths.transactionPath);
  fsyncDirectory(cacheDir, platform);
}

async function ensureBinary({
  cacheDir = getCacheDir(),
  runtime = process,
  downloadImpl = download,
  extractImpl = extractBinaryFromArchive,
  execFileSyncImpl = execFileSync,
  execTimeoutMs = EXEC_TIMEOUT_MS,
  lockOptions,
} = {}) {
  const staleMs = lockOptions?.staleMs ?? LOCK_STALE_MS;
  if (!Number.isFinite(execTimeoutMs) || execTimeoutMs < 1 || execTimeoutMs >= staleMs) {
    throw new Error("child execution timeout must be positive and shorter than lock stale timeout");
  }
  ensurePrivateCacheDir(cacheDir, runtime.platform);
  const paths = pathSet(cacheDir, runtime.platform);
  const releaseLock = await acquireInstallLock(paths.lockPath, { ...lockOptions, platform: runtime.platform });
  const heartbeat = releaseLock.heartbeat;
  try {
    ensureNpmSourceMarker(paths.sourceMarkerPath, runtime.platform);
    heartbeat();
    recoverInterruptedInstall(paths, runtime.platform);
    if (validateCachedBinary(paths.binaryPath, paths.manifestPath, {
      execFileSyncImpl,
      platform: runtime.platform,
      execTimeoutMs,
      heartbeat,
    })) return paths.binaryPath;

    const target = getPlatformTarget(runtime);
    const archiveExt = runtime.platform === "win32" ? "zip" : "tar.gz";
    const archiveName = `phantom-${target}.${archiveExt}`;
    const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${archiveName}`;
    const sha256Url = `${url}.sha256`;
    console.error(`Downloading phantom v${VERSION} for ${target}...`);

    // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- mkdtemp receives a fixed prefix under the validated private cache root.
    const installDir = mkdtempSync(join(cacheDir, ".install-"));
    if (runtime.platform !== "win32") chmodSync(installDir, 0o700);
    // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- archiveName is constructed only from the closed target and extension maps.
    const archivePath = join(installDir, archiveName);
    // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal -- filename comes from a closed platform map under a fresh install directory.
    const candidatePath = join(installDir, getBinaryFilename(runtime.platform));
    const candidateManifestPath = `${candidatePath}.manifest.json`;
    try {
      heartbeat();
      const sumBuf = await downloadImpl(sha256Url);
      heartbeat();
      const expected = parseSha256File(sumBuf, archiveName);
      if (!expected) throw new Error(`malformed or missing checksum at ${sha256Url}`);
      const data = await downloadImpl(url);
      heartbeat();
      const actual = crypto.createHash("sha256").update(data).digest("hex");
      if (!crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(actual, "hex"))) {
        throw new Error(`SHA-256 mismatch for ${archiveName}`);
      }
      writePrivateFile(archivePath, data, 0o600, runtime.platform);
      extractImpl(archivePath, candidatePath, {
        cacheDir,
        platform: runtime.platform,
        execFileSyncImpl,
        execTimeoutMs,
        heartbeat,
      });
      const candidateVersion = runBoundedExec(
        execFileSyncImpl,
        candidatePath,
        ["--version"],
        { stdio: ["ignore", "pipe", "ignore"] },
        { timeoutMs: execTimeoutMs, heartbeat }
      );
      if (parseBinaryVersion(candidateVersion) !== VERSION) {
        throw new Error(`downloaded ${BINARY_NAME} did not report exact version ${VERSION}`);
      }
      const manifest = { version: VERSION, sha256: sha256File(candidatePath) };
      writePrivateFile(candidateManifestPath, JSON.stringify(manifest) + "\n", 0o600, runtime.platform);
      replaceCachedBinary(candidatePath, candidateManifestPath, paths, runtime.platform);
      heartbeat();
      console.error(`Installed phantom to ${paths.binaryPath}`);
      return paths.binaryPath;
    } finally {
      rmSync(installDir, { recursive: true, force: true });
    }
  } finally {
    releaseLock();
  }
}

function propagateChildFailure(error, runtime = process) {
  if (error && error.signal && runtime.platform !== "win32") {
    runtime.kill(runtime.pid, error.signal);
    return;
  }
  runtime.exitCode = error && Number.isInteger(error.status) ? error.status : 1;
}

async function main() {
  try {
    const binary = await ensureBinary();
    execFileSync(binary, process.argv.slice(2), { stdio: "inherit" });
  } catch (error) {
    if (!Number.isInteger(error.status) && !error.signal) {
      console.error(`phantom wrapper failed: ${error.message}`);
      console.error(REVIEWED_RELEASE_GUIDANCE);
    }
    propagateChildFailure(error);
  }
}

if (require.main === module) main();

module.exports = {
  ALLOWED_DOWNLOAD_HOSTS,
  SUPPORTED_TARGETS,
  acquireInstallLock,
  download,
  ensureBinary,
  ensurePrivateCacheDir,
  expectedArchiveEntries,
  extractBinaryFromArchive,
  getCacheDir,
  getPlatformTarget,
  isCachedBinaryStale,
  parseBinaryVersion,
  parseSha256File,
  pathSet,
  propagateChildFailure,
  readVerifiedManifest,
  recoverInterruptedInstall,
  replaceCachedBinary,
  validateCachedBinary,
  writePrivateFile,
};
