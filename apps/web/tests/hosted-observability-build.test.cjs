const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");

const webDir = path.resolve(__dirname, "..");
const repositoryDir = path.resolve(webDir, "..", "..");
const nextCli = path.join(webDir, "node_modules/next/dist/bin/next");
const PUBLIC_CONFIGURATION = {
  NEXT_PUBLIC_SUPABASE_URL: "https://phantom-build-test.supabase.co",
  NEXT_PUBLIC_SUPABASE_ANON_KEY: `anon_${"a".repeat(32)}`,
};
const RUNTIME_CONFIGURATION = {
  VERCEL_GIT_COMMIT_SHA: "b".repeat(40),
  VERCEL_DEPLOYMENT_ID: `dpl_${"C".repeat(24)}`,
  VERCEL_ENV: "production",
  SUPABASE_SERVICE_ROLE_KEY: `service_${"d".repeat(32)}`,
};
const RELEVANT_ENV_NAMES = [
  ...Object.keys(PUBLIC_CONFIGURATION),
  ...Object.keys(RUNTIME_CONFIGURATION),
  "PHANTOM_BILLING_ENABLED",
  "PHANTOM_CLOUD_VAULTS_ENABLED",
  "PHANTOM_TEAMS_ENABLED",
  "PHANTOM_PUBLIC_AUTH_CONFIGURATION_FINGERPRINT",
];

function cleanEnvironment(values = {}) {
  const env = { ...process.env, NEXT_TELEMETRY_DISABLED: "1", ...values };
  for (const name of RELEVANT_ENV_NAMES) {
    if (!Object.hasOwn(values, name)) delete env[name];
  }
  return env;
}

function copyApplication(destination) {
  fs.cpSync(webDir, destination, {
    recursive: true,
    filter(source) {
      const relative = path.relative(webDir, source);
      const firstSegment = relative.split(path.sep)[0];
      const fileName = path.basename(relative);
      if (fileName.startsWith(".env") && fileName !== ".env.local.example") {
        return false;
      }
      return firstSegment !== ".next" && firstSegment !== "node_modules";
    },
  });
  fs.symlinkSync(
    path.join(webDir, "node_modules"),
    path.join(destination, "node_modules"),
    process.platform === "win32" ? "junction" : "dir",
  );
}

function buildApplication(directory, publicConfiguration) {
  const result = spawnSync(process.execPath, [nextCli, "build"], {
    cwd: directory,
    env: cleanEnvironment(publicConfiguration),
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  assert.equal(
    result.status,
    0,
    `production build failed:\n${result.stdout}\n${result.stderr}`,
  );
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.notEqual(address, null);
  const port = address.port;
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}

async function exitsWithin(exitPromise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      exitPromise.then(() => true),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function readProductionReadiness(directory, runtimeValues) {
  const port = await freePort();
  const child = spawn(
    process.execPath,
    [nextCli, "start", "--hostname", "127.0.0.1", "--port", String(port)],
    {
      cwd: directory,
      env: cleanEnvironment(runtimeValues),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });
  const childExited = new Promise((resolve) => child.once("exit", resolve));

  try {
    const url = `http://127.0.0.1:${port}/api/v1/ready`;
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) {
        assert.fail(`production server exited early (${child.exitCode}):\n${output}`);
      }
      try {
        const response = await fetch(url);
        return { response, body: await response.json() };
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    assert.fail(`production server did not become ready:\n${output}`);
  } finally {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      if (!(await exitsWithin(childExited, 5_000)) && child.exitCode === null) {
        child.kill("SIGKILL");
        await childExited;
      }
    }
  }
}

test(
  "production readiness uses browser configuration frozen at build time",
  { timeout: 180_000 },
  async () => {
    const temporaryRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "phantom-web-readiness-"),
    );
    const temporaryRepository = path.join(temporaryRoot, "repository");
    const withoutPublicConfig = path.join(
      temporaryRepository,
      "apps",
      "without-public",
    );
    const withPublicConfig = path.join(
      temporaryRepository,
      "apps",
      "with-public",
    );

    try {
      fs.cpSync(
        path.join(repositoryDir, "docs"),
        path.join(temporaryRepository, "docs"),
        { recursive: true },
      );
      copyApplication(withoutPublicConfig);
      buildApplication(withoutPublicConfig, {});
      const runtimeInjection = await readProductionReadiness(
        withoutPublicConfig,
        {
          ...RUNTIME_CONFIGURATION,
          ...PUBLIC_CONFIGURATION,
          PHANTOM_PUBLIC_AUTH_CONFIGURATION_FINGERPRINT: "a".repeat(64),
        },
      );
      assert.equal(runtimeInjection.response.status, 503);
      assert.equal(runtimeInjection.body.status, "not_ready");
      assert.deepEqual(runtimeInjection.body, {
        status: "not_ready",
        service: "phantom-web",
        release_version: "0.7.7",
      });

      copyApplication(withPublicConfig);
      buildApplication(withPublicConfig, PUBLIC_CONFIGURATION);
      const builtConfiguration = await readProductionReadiness(
        withPublicConfig,
        { ...RUNTIME_CONFIGURATION, ...PUBLIC_CONFIGURATION },
      );
      assert.equal(builtConfiguration.response.status, 200);
      assert.equal(builtConfiguration.body.status, "configuration_ready");
      assert.deepEqual(builtConfiguration.body, {
        status: "configuration_ready",
        service: "phantom-web",
        release_version: "0.7.7",
      });
    } finally {
      fs.rmSync(temporaryRoot, { force: true, recursive: true });
    }
  },
);
