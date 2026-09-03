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
const { basename, dirname, join } = require("path");

const {
  acquireInstallLock,
  download,
  ensureBinary,
  ensurePrivateCacheDir,
  extractBinaryFromArchive,
  fsyncFile,
  getCacheDir,
  getPlatformTarget,
  parseSha256File,
  pathSet,
  propagateChildFailure,
  readVerifiedManifest,
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
  const cacheDir = mkdtempSync(join(tmpdir(), `phantom-cli-previous-${stage}-`));
  try {
    ensurePrivateCacheDir(cacheDir);
    const paths = pathSet(cacheDir);
    const previousBinary = Buffer.from(`working phantom 0.7.4 cache for ${stage}`);
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
      `https://github.com/ashlrai/phantom-secrets/releases/download/v0.7.5/${archiveName}`;
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
          return Buffer.from("phantom 0.7.4\n");
        },
      }),
      stage === "version"
        ? /did not report exact version 0\.7\.5/
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
    parseSha256File(Buffer.from(`${"a".repeat(64)}  phantom-linux.tar.gz\n`), "phantom-linux.tar.gz"),
    "a".repeat(64)
  );

  let fsyncOpenMode;
  let fsyncDescriptor;
  let closedDescriptor;
  fsyncFile("C:\\private\\phantom.exe", {
    openSyncImpl: (_path, mode) => {
      fsyncOpenMode = mode;
      if (mode === "r") {
        const error = new Error("simulated Windows read-only FlushFileBuffers failure");
        error.code = "EPERM";
        throw error;
      }
      return 41;
    },
    fsyncSyncImpl: (fd) => {
      fsyncDescriptor = fd;
    },
    closeSyncImpl: (fd) => {
      closedDescriptor = fd;
    },
  });
  assert.strictEqual(fsyncOpenMode, "r+");
  assert.strictEqual(fsyncDescriptor, 41);
  assert.strictEqual(closedDescriptor, 41);

  const fsyncFailure = Object.assign(new Error("simulated durable write failure"), { code: "EIO" });
  let failureClosedDescriptor;
  assert.throws(
    () => fsyncFile("C:\\private\\phantom-fsync-failure.exe", {
      openSyncImpl: (_path, mode) => {
        assert.strictEqual(mode, "r+");
        return 42;
      },
      fsyncSyncImpl: (fd) => {
        assert.strictEqual(fd, 42);
        throw fsyncFailure;
      },
      closeSyncImpl: (fd) => {
        failureClosedDescriptor = fd;
      },
    }),
    (error) => error === fsyncFailure
  );
  assert.strictEqual(failureClosedDescriptor, 42);
  for (const checksum of [
    `${"a".repeat(64)}  wrong.tar.gz\n`,
    `${"a".repeat(64)}  phantom-linux.tar.gz\nextra\n`,
    "not-a-checksum  phantom-linux.tar.gz\n",
  ]) {
    assert.strictEqual(parseSha256File(Buffer.from(checksum), "phantom-linux.tar.gz"), null);
  }

  await assert.rejects(
    download("https://github.com/release", {
      httpsGet: fakeHttps([{ status: 302, headers: { location: "https://evil.example/payload" } }]),
      maxBytes: 10,
      timeoutMs: 100,
    }),
    /untrusted URL/
  );
  await assert.rejects(
    download("https://user:password@github.com/release", {
      httpsGet: fakeHttps([]),
      timeoutMs: 100,
    }),
    /must not contain credentials/
  );
  await assert.rejects(
    download("https://github.com/release", {
      httpsGet: fakeHttps([{ status: 200, body: "123456" }]),
      maxBytes: 5,
      timeoutMs: 100,
    }),
    /exceeds 5 byte limit/
  );
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
  await assert.rejects(
    download("https://github.com/release", {
      httpsGet: fakeHttps([]),
      timeoutMs: 10,
    }),
    /timed out/
  );

  for (const stage of ["download", "extract", "flush", "version"]) {
    await assertPreviousVersionCachePreserved(stage);
  }

  const fixtureDir = mkdtempSync(join(tmpdir(), "phantom-cli-hardening-"));
  try {
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
        return Buffer.from("phantom 0.7.5\n");
      },
    });
    assert.ok(dirname(observedArchivePath).startsWith(join(fixtureDir, ".install-")));
    assert.ok(readVerifiedManifest(installed, `${installed}.manifest.json`));
    const priorBinary = readFileSync(installed);
    const priorManifest = readFileSync(`${installed}.manifest.json`);
    await assert.rejects(
      ensureBinary({
        cacheDir: fixtureDir,
        runtime: { platform: process.platform, arch: process.arch },
        execFileSyncImpl: () => Buffer.from("phantom 0.5.0\n"),
        downloadImpl: async () => {
          throw new Error("simulated verification download failure");
        },
      }),
      /simulated verification download failure/
    );
    assert.deepStrictEqual(readFileSync(installed), priorBinary);
    assert.deepStrictEqual(readFileSync(`${installed}.manifest.json`), priorManifest);
    assert.ok(readVerifiedManifest(installed, `${installed}.manifest.json`));

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
    const windowsOutput = join(windowsFixtureDir, "phantom-windows.exe");
    extractBinaryFromArchive(windowsArchive, windowsOutput, {
      cacheDir: windowsFixtureDir,
      platform: "win32",
      execFileSyncImpl: (executable, args, options) => {
        assert.strictEqual(executable, "powershell");
        assert.ok(options.timeout > 0 && options.timeout < 120_000);
        assert.match(args[3], /phantom\.exe','phantom-mcp\.exe/);
        assert.match(args[3], /GetEntry\('phantom\.exe'\)/);
        assert.match(args[3], /ExternalAttributes/);
        assert.match(args[3], /ReparsePoint/);
        assert.match(args[3], /non-regular entry/);
        writePrivateFile(args[args.length - 1], "cli-windows", 0o700, "win32");
      },
    });
    assert.strictEqual(readFileSync(windowsOutput, "utf8"), "cli-windows");

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
      const output = join(fixtureDir, "extracted-cli");
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
      assert.strictEqual(readFileSync(output, "utf8"), "cli");
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

      const sentinelDir = mkdtempSync(join(tmpdir(), "phantom-cli-external-sentinel-"));
      try {
        const sentinel = join(sentinelDir, "sentinel");
        writePrivateFile(sentinel, "external-sentinel", 0o700);
        const sentinelMode = lstatSync(sentinel).mode & 0o777;
        const sentinelContents = readFileSync(sentinel);
        const badSource = join(fixtureDir, "bad-source");
        mkdirSync(badSource, { mode: 0o700 });
        writePrivateFile(join(badSource, "phantom-mcp"), "mcp", 0o700);
        symlinkSync(sentinel, join(badSource, "phantom"));
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

  console.log("npm CLI wrapper download, lock, archive, and signal hardening tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
