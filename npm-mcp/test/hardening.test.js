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
  getCacheDir,
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

(async () => {
  assert.throws(
    () => getCacheDir({ env: {}, homedirImpl: () => "relative-home" }),
    /absolute private home/
  );

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
        return Buffer.from("phantom-mcp 0.7.4\n");
      },
    });
    assert.ok(dirname(observedArchivePath).startsWith(join(fixtureDir, ".install-")));
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
    const windowsOutput = join(windowsFixtureDir, "phantom-mcp-windows.exe");
    extractBinaryFromArchive(windowsArchive, windowsOutput, {
      cacheDir: windowsFixtureDir,
      platform: "win32",
      execFileSyncImpl: (executable, args, options) => {
        assert.strictEqual(executable, "powershell");
        assert.ok(options.timeout > 0 && options.timeout < 120_000);
        assert.match(args[3], /phantom\.exe','phantom-mcp\.exe/);
        assert.match(args[3], /GetEntry\('phantom-mcp\.exe'\)/);
        assert.match(args[3], /ExternalAttributes/);
        assert.match(args[3], /ReparsePoint/);
        assert.match(args[3], /non-regular entry/);
        writePrivateFile(args[args.length - 1], "mcp-windows", 0o700, "win32");
      },
    });
    assert.strictEqual(readFileSync(windowsOutput, "utf8"), "mcp-windows");

    if (process.platform !== "win32") {
      const source = join(fixtureDir, "archive-source");
      mkdirSync(source, { mode: 0o700 });
      writePrivateFile(join(source, "phantom"), "cli", 0o700);
      writePrivateFile(join(source, "phantom-mcp"), "mcp", 0o700);
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

      const badSource = join(fixtureDir, "bad-source");
      mkdirSync(badSource, { mode: 0o700 });
      writePrivateFile(join(badSource, "phantom"), "cli", 0o700);
      symlinkSync("phantom", join(badSource, "phantom-mcp"));
      const symlinkArchive = join(fixtureDir, "symlink.tar.gz");
      execFileSync("tar", ["czf", symlinkArchive, "-C", badSource, "phantom", "phantom-mcp"]);
      chmodSync(symlinkArchive, 0o600);
      assert.throws(
        () => extractBinaryFromArchive(symlinkArchive, join(fixtureDir, "must-not-install"), {
          cacheDir: fixtureDir,
        }),
        /symbolic link|regular single-link file/
      );
    }
  } finally {
    rmSync(fixtureDir, { recursive: true, force: true });
  }

  console.log("npm MCP wrapper download, lock, archive, and signal hardening tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
