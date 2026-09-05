const assert = require("assert");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { EventEmitter } = require("events");
const {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  utimesSync,
} = require("fs");
const { tmpdir } = require("os");
const { basename, dirname, join, posix: posixPath, win32: win32Path } = require("path");

const {
  acquireInstallLock,
  download,
  ensureBinary,
  ensurePrivateCacheDir,
  extractBinaryFromArchive,
  fsyncFile,
  getCacheDir,
  getPlatformTarget,
  pathSet,
  propagateChildFailure,
  readVerifiedManifest,
  sameWindowsFilesystemObject,
  validateWindowsPathAncestors,
  writePrivateFile,
} = require("../bin/cli.js");

function fakeHttps(sequence) {
  let index = 0;
  return (_url, callback) => {
    const request = new EventEmitter();
    request.destroy = (error) => {
      if (error) process.nextTick(() => request.emit("error", error));
    };
    const item = sequence[index++];
    process.nextTick(() => {
      if (!item) return;
      const response = new EventEmitter();
      response.statusCode = item.status;
      response.headers = item.headers || {};
      response.resume = () => {};
      response.destroy = () => {};
      callback(response);
      if (item.body !== undefined) response.emit("data", Buffer.from(item.body));
      response.emit("end");
    });
    return request;
  };
}

async function assertPreviousVersionCachePreserved(stage) {
  const cacheDir = mkdtempSync(join(tmpdir(), `phantom-mcp-previous-${stage}-`));
  try {
    ensurePrivateCacheDir(cacheDir);
    const paths = pathSet(cacheDir);
    const previousBinary = Buffer.from(`working phantom-mcp 0.7.4 cache for ${stage}`);
    const previousManifest = Buffer.from(`${JSON.stringify({
      version: "0.7.4",
      sha256: crypto.createHash("sha256").update(previousBinary).digest("hex"),
    })}\n`);
    writePrivateFile(paths.binaryPath, previousBinary, 0o700);
    writePrivateFile(paths.manifestPath, previousManifest, 0o600);

    const target = getPlatformTarget(process);
    const archiveExt = process.platform === "win32" ? "zip" : "tar.gz";
    const archiveName = `phantom-${target}.${archiveExt}`;
    const archiveUrl =
      `https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.8/${archiveName}`;
    const archiveBytes = Buffer.from(`verified archive for ${stage}`);
    const archiveSha = crypto.createHash("sha256").update(archiveBytes).digest("hex");
    const observedUrls = [];
    let versionExecutions = 0;
    const stagedFailure = Object.assign(new Error(`simulated ${stage} failure`), { code: "EIO" });

    await assert.rejects(
      ensureBinary({
        cacheDir,
        runtime: { platform: process.platform, arch: process.arch },
        downloadImpl: async (url) => {
          observedUrls.push(url);
          if (stage === "download") throw stagedFailure;
          if (url === `${archiveUrl}.sha256`) {
            return Buffer.from(`${archiveSha}  ${archiveName}\n`);
          }
          assert.strictEqual(url, archiveUrl);
          return archiveBytes;
        },
        extractImpl: (_archivePath, candidatePath) => {
          if (stage === "extract") throw stagedFailure;
          writePrivateFile(candidatePath, `candidate for ${stage}`, 0o700);
          if (stage === "flush") {
            fsyncFile(candidatePath, {
              fsyncSyncImpl: () => { throw stagedFailure; },
            });
          }
        },
        execFileSyncImpl: () => {
          versionExecutions += 1;
          return Buffer.from("phantom-mcp 0.7.4\n");
        },
      }),
      stage === "version"
        ? /did not report exact version 0\.7\.8/
        : (error) => error === stagedFailure
    );

    assert.deepStrictEqual(readFileSync(paths.binaryPath), previousBinary, `${stage} binary bytes`);
    assert.deepStrictEqual(readFileSync(paths.manifestPath), previousManifest, `${stage} manifest bytes`);
    assert.strictEqual(existsSync(paths.backupBinaryPath), false, `${stage} backup binary cleanup`);
    assert.strictEqual(existsSync(paths.backupManifestPath), false, `${stage} backup manifest cleanup`);
    assert.strictEqual(existsSync(paths.transactionPath), false, `${stage} transaction cleanup`);
    assert.strictEqual(versionExecutions, stage === "version" ? 1 : 0, `${stage} version execution`);
    assert.deepStrictEqual(
      observedUrls,
      stage === "download" ? [`${archiveUrl}.sha256`] : [`${archiveUrl}.sha256`, archiveUrl]
    );
  } finally {
    rmSync(cacheDir, { recursive: true, force: true });
  }
}

(async () => {
  assert.throws(
    () => getCacheDir({ env: {}, homedirImpl: () => "relative-home" }),
    /absolute private home/
  );
  assert.strictEqual(
    getCacheDir({
      env: { HOME: "/c/Users/msys-user", USERPROFILE: "C:\\Users\\native-user" },
      homedirImpl: () => "C:\\Users\\platform-user",
      platform: "win32",
    }),
    win32Path.join("C:\\Users\\native-user", ".phantom-secrets", "bin")
  );
  assert.strictEqual(
    getCacheDir({
      env: { USERPROFILE: "C:\\Users\\service-user" },
      homedirImpl: () => { throw new Error("OS home unavailable"); },
      platform: "win32",
    }),
    win32Path.join("C:\\Users\\service-user", ".phantom-secrets", "bin")
  );
  assert.strictEqual(
    getCacheDir({
      env: { HOME: "/c/Users/msys-user" },
      homedirImpl: () => "D:\\Users\\platform-user",
      platform: "win32",
    }),
    win32Path.join("D:\\Users\\platform-user", ".phantom-secrets", "bin")
  );
  assert.throws(
    () => getCacheDir({
      env: { HOME: "/c/Users/msys-user" },
      homedirImpl: () => "/c/Users/msys-platform-user",
      platform: "win32",
    }),
    /absolute private home/
  );
  assert.strictEqual(
    getCacheDir({
      env: { HOME: "/unix/home", USERPROFILE: "/native/windows-user" },
      homedirImpl: () => "/platform/home",
      platform: "linux",
    }),
    posixPath.join("/unix/home", ".phantom-secrets", "bin")
  );

  let fsyncOpenMode;
  let fsyncDescriptor;
  let closedDescriptor;
  fsyncFile("C:\\private\\phantom-mcp.exe", {
    openSyncImpl: (_path, mode) => {
      fsyncOpenMode = mode;
      if (mode === "r") {
        const error = new Error("simulated Windows read-only FlushFileBuffers failure");
        error.code = "EPERM";
        throw error;
      }
      return 43;
    },
    fsyncSyncImpl: (fd) => {
      fsyncDescriptor = fd;
    },
    closeSyncImpl: (fd) => {
      closedDescriptor = fd;
    },
  });
  assert.strictEqual(fsyncOpenMode, "r+");
  assert.strictEqual(fsyncDescriptor, 43);
  assert.strictEqual(closedDescriptor, 43);

  const identities = new Map([
    ["short", { dev: 7n, ino: 42n }],
    ["long", { dev: 7n, ino: 42n }],
    ["junction", { dev: 7n, ino: 43n }],
    ["unknown", { dev: 7n, ino: 0n }],
  ]);
  const fakeBigintLstat = (path, options) => {
    assert.deepStrictEqual(options, { bigint: true });
    return identities.get(path);
  };
  assert.strictEqual(
    sameWindowsFilesystemObject("short", "long", fakeBigintLstat),
    true,
    "lexical aliases with the same Windows file identity are accepted"
  );
  assert.strictEqual(
    sameWindowsFilesystemObject("junction", "long", fakeBigintLstat),
    false,
    "a reparse object and its target do not share lstat identity"
  );
  assert.strictEqual(
    sameWindowsFilesystemObject("unknown", "unknown", fakeBigintLstat),
    false,
    "an unavailable Windows file index fails closed"
  );

  const fsyncFailure = Object.assign(new Error("simulated durable write failure"), { code: "EIO" });
  let failureClosedDescriptor;
  assert.throws(
    () => fsyncFile("C:\\private\\phantom-mcp-fsync-failure.exe", {
      openSyncImpl: (_path, mode) => {
        assert.strictEqual(mode, "r+");
        return 44;
      },
      fsyncSyncImpl: (fd) => {
        assert.strictEqual(fd, 44);
        throw fsyncFailure;
      },
      closeSyncImpl: (fd) => {
        failureClosedDescriptor = fd;
      },
    }),
    (error) => error === fsyncFailure
  );
  assert.strictEqual(failureClosedDescriptor, 44);

  await assert.rejects(
    download("https://github.com/release", {
      httpsGet: fakeHttps([{ status: 302, headers: { location: "https://evil.example/payload" } }]),
      maxBytes: 10,
      timeoutMs: 100,
    }),
    /untrusted URL/
  );
  await assert.rejects(
    download("https://github.com/release", {
      httpsGet: fakeHttps([{ status: 200, body: "123456" }]),
      maxBytes: 5,
      timeoutMs: 100,
    }),
    /exceeds 5 byte limit/
  );

  for (const stage of ["download", "extract", "flush", "version"]) {
    await assertPreviousVersionCachePreserved(stage);
  }

  await assert.rejects(
    download("https://github.com/release", {
      httpsGet: fakeHttps([
        { status: 302, headers: { location: "/again" } },
        { status: 302, headers: { location: "/again" } },
      ]),
      maxRedirects: 1,
      timeoutMs: 100,
    }),
    /too many redirects/
  );

  const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-mcp-hardening-"));
  try {
    if (process.platform === "win32") {
      const nativeAlias = [fixtureDir, tmpdir(), process.env.USERPROFILE]
        .filter(Boolean)
        .find((candidate) =>
          candidate.includes("~") &&
          win32Path.normalize(realpathSync.native(candidate)).toLowerCase() !==
            win32Path.normalize(candidate).toLowerCase()
        );
      if (process.env.GITHUB_ACTIONS === "true") {
        assert.ok(nativeAlias, "GitHub Windows runners must exercise their native 8.3 alias");
      }
      if (nativeAlias) {
        assert.strictEqual(
          sameWindowsFilesystemObject(nativeAlias, realpathSync.native(nativeAlias)),
          true
        );
        assert.doesNotThrow(() => validateWindowsPathAncestors(nativeAlias, "win32"));
      }
    }

    const windowsReal = join(realpathSync(fixtureDir), "windows-real");
    const windowsLink = join(realpathSync(fixtureDir), "windows-link");
    mkdirSync(windowsReal, { mode: 0o700 });
    symlinkSync(windowsReal, windowsLink, "junction");
    assert.throws(
      () => ensurePrivateCacheDir(join(windowsLink, "bin"), "win32"),
      /Windows reparse point/
    );

    ensurePrivateCacheDir(fixtureDir);
    const paths = pathSet(fixtureDir);
    const release = await acquireInstallLock(paths.lockPath, {
      waitMs: 50,
      staleMs: 1000,
      heartbeatMs: 100,
    });
    await assert.rejects(
      acquireInstallLock(paths.lockPath, {
        waitMs: 10,
        staleMs: 1000,
        heartbeatMs: 100,
        pollMs: 2,
      }),
      /timed out/
    );
    release();

    mkdirSync(paths.lockPath, { mode: 0o700 });
    const old = new Date(Date.now() - 10_000);
    utimesSync(paths.lockPath, old, old);
    const releaseRecovered = await acquireInstallLock(paths.lockPath, {
      waitMs: 20,
      staleMs: 100,
      heartbeatMs: 10,
      pollMs: 2,
    });
    releaseRecovered();

    const heartbeatOwner = await acquireInstallLock(paths.lockPath, {
      waitMs: 20,
      staleMs: 40,
      heartbeatMs: 5,
      pollMs: 2,
    });
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 70));
    await assert.rejects(
      acquireInstallLock(paths.lockPath, {
        waitMs: 15,
        staleMs: 40,
        heartbeatMs: 5,
        pollMs: 2,
      }),
      /timed out/
    );
    assert.strictEqual(heartbeatOwner(), true);

    const staleOwner = await acquireInstallLock(paths.lockPath, {
      waitMs: 20,
      staleMs: 100,
      heartbeatMs: 99,
      pollMs: 2,
    });
    const staleOwnerPath = join(paths.lockPath, "owner");
    const staleTime = new Date(Date.now() - 10_000);
    utimesSync(staleOwnerPath, staleTime, staleTime);
    const successor = await acquireInstallLock(paths.lockPath, {
      waitMs: 20,
      staleMs: 100,
      heartbeatMs: 10,
      pollMs: 2,
    });
    assert.notStrictEqual(staleOwner.ownerToken, successor.ownerToken);
    assert.strictEqual(staleOwner(), false, "old owner must not remove successor lock");
    assert.strictEqual(existsSync(paths.lockPath), true);
    await assert.rejects(
      acquireInstallLock(paths.lockPath, {
        waitMs: 10,
        staleMs: 100,
        heartbeatMs: 10,
        pollMs: 2,
      }),
      /timed out/
    );
    assert.strictEqual(successor(), true);

    const archiveBytes = Buffer.from("verified-archive-fixture");
    const archiveSha = crypto.createHash("sha256").update(archiveBytes).digest("hex");
    let observedArchivePath;
    const installed = await ensureBinary({
      cacheDir: fixtureDir,
      runtime: { platform: process.platform, arch: process.arch },
      downloadImpl: async (url) =>
        url.endsWith(".sha256")
          ? Buffer.from(`${archiveSha}  ${basename(url.slice(0, -7))}\n`)
          : archiveBytes,
      extractImpl: (archivePath, candidatePath) => {
        observedArchivePath = archivePath;
        assert.match(basename(dirname(archivePath)), /^\.install-/);
        assert.strictEqual(lstatSync(archivePath).isSymbolicLink(), false);
        writePrivateFile(candidatePath, "verified-binary", 0o700);
      },
      execFileSyncImpl: (_path, _args, options) => {
        assert.ok(options.timeout > 0 && options.timeout < 120_000);
        return Buffer.from("phantom-mcp 0.7.8\n");
      },
    });
    assert.ok(dirname(observedArchivePath).startsWith(join(fixtureDir, ".install-")));
    assert.ok(readVerifiedManifest(installed, `${installed}.manifest.json`));

    const versionFailureCache = join(fixtureDir, "version-failure-cache");
    ensurePrivateCacheDir(versionFailureCache);
    const versionFailureBytes = Buffer.from("version-failure-archive");
    const versionFailureSha = crypto.createHash("sha256").update(versionFailureBytes).digest("hex");
    let versionFailure;
    try {
      await ensureBinary({
        cacheDir: versionFailureCache,
        runtime: { platform: process.platform, arch: process.arch },
        downloadImpl: async (url) => url.endsWith(".sha256")
          ? Buffer.from(`${versionFailureSha}  ${basename(url.slice(0, -7))}\n`)
          : versionFailureBytes,
        extractImpl: (_archivePath, candidatePath) => {
          writePrivateFile(candidatePath, "version-failure-candidate", 0o700);
        },
        execFileSyncImpl: () => {
          throw Object.assign(new Error("sensitive output /private/candidate"), { status: 23 });
        },
      });
    } catch (error) {
      versionFailure = error;
    }
    assert.strictEqual(
      versionFailure?.message,
      "downloaded phantom-mcp version check failed with exit status 23"
    );
    assert.doesNotMatch(versionFailure?.message ?? "", /sensitive|private|candidate/i);

    const runtime = { exitCode: undefined, platform: "linux", pid: 123, kill: (pid, signal) => {
      assert.strictEqual(pid, 123);
      assert.strictEqual(signal, "SIGTERM");
      runtime.killed = true;
    } };
    propagateChildFailure({ signal: "SIGTERM" }, runtime);
    assert.strictEqual(runtime.killed, true);
    propagateChildFailure({ status: 7 }, runtime);
    assert.strictEqual(runtime.exitCode, 7);

    const windowsFixtureDir = realpathSync(fixtureDir);
    const windowsArchive = join(windowsFixtureDir, "valid.zip");
    writePrivateFile(windowsArchive, "zip-fixture", 0o600);
    const windowsOutput = join(windowsFixtureDir, "phantom-mcp-windows.exe");
    extractBinaryFromArchive(windowsArchive, windowsOutput, {
      cacheDir: windowsFixtureDir,
      platform: "win32",
      execFileSyncImpl: (executable, args, options) => {
        assert.strictEqual(executable, "pwsh.exe");
        assert.ok(options.timeout > 0 && options.timeout < 120_000);
        assert.strictEqual(args[5], "-File");
        const extractionScript = readFileSync(args[6], "utf8");
        assert.match(extractionScript, /phantom\.exe','phantom-mcp\.exe/);
        assert.match(extractionScript, /GetEntry\('phantom-mcp\.exe'\)/);
        assert.match(extractionScript, /ExternalAttributes/);
        assert.match(extractionScript, /ReparsePoint/);
        assert.match(extractionScript, /non-regular entry/);
        assert.match(extractionScript, /Sort-Object -CaseSensitive/);
        assert.match(extractionScript, /-cne/);
        assert.strictEqual(args[7], windowsArchive);
        writePrivateFile(args[args.length - 1], "mcp-windows", 0o700, "win32");
      },
    });
    assert.strictEqual(readFileSync(windowsOutput, "utf8"), "mcp-windows");

    const fallbackArchive = join(windowsFixtureDir, "fallback.zip");
    writePrivateFile(fallbackArchive, "zip-fallback-fixture", 0o600);
    const fallbackOutput = join(windowsFixtureDir, "phantom-mcp-fallback.exe");
    const fallbackAttempts = [];
    const fallbackTimes = [100, 125];
    extractBinaryFromArchive(fallbackArchive, fallbackOutput, {
      cacheDir: windowsFixtureDir,
      platform: "win32",
      execTimeoutMs: 30_000,
      monotonicNow: () => fallbackTimes.shift(),
      execFileSyncImpl: (executable, args, options) => {
        fallbackAttempts.push(executable);
        if (executable === "pwsh.exe") {
          assert.strictEqual(options.timeout, 30_000);
          throw Object.assign(new Error("pwsh is unavailable"), { code: "ENOENT" });
        }
        assert.strictEqual(executable, "powershell.exe");
        assert.strictEqual(options.timeout, 29_975);
        writePrivateFile(args[args.length - 1], "mcp-fallback", 0o700, "win32");
      },
    });
    assert.deepStrictEqual(fallbackAttempts, ["pwsh.exe", "powershell.exe"]);
    assert.deepStrictEqual(fallbackTimes, []);
    assert.strictEqual(readFileSync(fallbackOutput, "utf8"), "mcp-fallback");

    const timeoutArchive = join(windowsFixtureDir, "timeout.zip");
    writePrivateFile(timeoutArchive, "zip-timeout-fixture", 0o600);
    let timeoutAttempts = 0;
    assert.throws(
      () => extractBinaryFromArchive(timeoutArchive, join(windowsFixtureDir, "timeout.exe"), {
        cacheDir: windowsFixtureDir,
        platform: "win32",
        execTimeoutMs: 7,
        execFileSyncImpl: () => {
          timeoutAttempts += 1;
          throw Object.assign(new Error("spawnSync powershell.exe ETIMEDOUT"), {
            code: "ETIMEDOUT",
            signal: "SIGTERM",
          });
        },
      }),
      /Windows ZIP extraction timed out after 7ms/
    );
    assert.strictEqual(timeoutAttempts, 1, "timeouts must not retry in another PowerShell host");

    const statusArchive = join(windowsFixtureDir, "status.zip");
    writePrivateFile(statusArchive, "zip-status-fixture", 0o600);
    let sanitizedFailure;
    let statusAttempts = 0;
    try {
      extractBinaryFromArchive(statusArchive, join(windowsFixtureDir, "status.exe"), {
        cacheDir: windowsFixtureDir,
        platform: "win32",
        execFileSyncImpl: () => {
          statusAttempts += 1;
          throw Object.assign(new Error("sensitive child output C:\\secret\\path"), { status: 17 });
        },
      });
    } catch (error) {
      sanitizedFailure = error;
    }
    assert.strictEqual(statusAttempts, 1, "nonzero exits must not retry in another PowerShell host");
    assert.strictEqual(sanitizedFailure?.message, "Windows ZIP extraction failed with exit status 17");
    assert.doesNotMatch(sanitizedFailure?.message ?? "", /sensitive|secret|path/i);

    if (process.platform === "win32") {
      const nativeZipSource = join(windowsFixtureDir, "native-zip-source");
      mkdirSync(nativeZipSource, { mode: 0o700 });
      writePrivateFile(join(nativeZipSource, "phantom.exe"), "native-cli", 0o700, "win32");
      writePrivateFile(join(nativeZipSource, "phantom-mcp.exe"), "native-mcp", 0o700, "win32");
      const nativeZip = join(windowsFixtureDir, "native-wrapper.zip");
      execFileSync("tar.exe", [
        "-a", "-cf", nativeZip, "-C", nativeZipSource, "phantom.exe", "phantom-mcp.exe",
      ]);
      const nativeOutput = join(windowsFixtureDir, "native-wrapper-phantom-mcp.exe");
      extractBinaryFromArchive(nativeZip, nativeOutput, {
        cacheDir: windowsFixtureDir,
        platform: "win32",
        execTimeoutMs: 15_000,
      });
      assert.strictEqual(readFileSync(nativeOutput, "utf8"), "native-mcp");
    }

    if (process.platform !== "win32") {
      const source = join(fixtureDir, "archive-source");
      mkdirSync(source, { mode: 0o700 });
      writePrivateFile(join(source, "phantom"), "cli", 0o700);
      writePrivateFile(join(source, "phantom-mcp"), "mcp", 0o700);
      chmodSync(join(source, "phantom"), 0o755);
      chmodSync(join(source, "phantom-mcp"), 0o755);
      const archive = join(fixtureDir, "valid.tar.gz");
      execFileSync("tar", ["czf", archive, "-C", source, "phantom", "phantom-mcp"]);
      chmodSync(archive, 0o600);
      const output = join(fixtureDir, "extracted-mcp");
      let extractionCalls = 0;
      extractBinaryFromArchive(archive, output, {
        cacheDir: fixtureDir,
        execFileSyncImpl: (executable, args, options) => {
          extractionCalls += 1;
          assert.ok(options.timeout > 0 && options.timeout < 120_000);
          return execFileSync(executable, args, options);
        },
      });
      assert.strictEqual(extractionCalls, 2);
      assert.strictEqual(readFileSync(output, "utf8"), "mcp");
      assert.strictEqual(lstatSync(output).mode & 0o777, 0o700);
      const archiveSymlink = join(fixtureDir, "archive-link.tar.gz");
      symlinkSync(archive, archiveSymlink);
      assert.throws(
        () => extractBinaryFromArchive(archiveSymlink, join(fixtureDir, "reject-archive-link"), {
          cacheDir: fixtureDir,
        }),
        /must not be a symbolic link/
      );

      writePrivateFile(join(source, "unexpected"), "extra", 0o700);
      const extraArchive = join(fixtureDir, "extra.tar.gz");
      execFileSync("tar", [
        "czf", extraArchive, "-C", source, "phantom", "phantom-mcp", "unexpected",
      ]);
      chmodSync(extraArchive, 0o600);
      assert.throws(
        () => extractBinaryFromArchive(extraArchive, join(fixtureDir, "reject-extra"), {
          cacheDir: fixtureDir,
        }),
        /unexpected entries/
      );

      const sentinelDir = mkdtempSync(join(tmpdir(), "phantom-mcp-external-sentinel-"));
      try {
        const sentinel = join(sentinelDir, "sentinel");
        writePrivateFile(sentinel, "external-sentinel", 0o700);
        const sentinelMode = lstatSync(sentinel).mode & 0o777;
        const sentinelContents = readFileSync(sentinel);
        const badSource = join(fixtureDir, "bad-source");
        mkdirSync(badSource, { mode: 0o700 });
        writePrivateFile(join(badSource, "phantom"), "cli", 0o700);
        symlinkSync(sentinel, join(badSource, "phantom-mcp"));
        const symlinkArchive = join(fixtureDir, "symlink.tar.gz");
        execFileSync("tar", ["czf", symlinkArchive, "-C", badSource, "phantom", "phantom-mcp"]);
        chmodSync(symlinkArchive, 0o600);
        assert.throws(
          () => extractBinaryFromArchive(symlinkArchive, join(fixtureDir, "must-not-install"), {
            cacheDir: fixtureDir,
          }),
          /symbolic link|regular single-link file/
        );
        assert.deepStrictEqual(readFileSync(sentinel), sentinelContents);
        assert.strictEqual(lstatSync(sentinel).mode & 0o777, sentinelMode);
      } finally {
        rmSync(sentinelDir, { recursive: true, force: true });
      }
    }
  } finally {
    rmSync(fixtureDir, { recursive: true, force: true });
  }

  console.log("npm MCP wrapper download, lock, archive, and signal hardening tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
