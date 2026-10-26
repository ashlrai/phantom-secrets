const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");
const ts = require("typescript");

const sourceFixture = fs.mkdtempSync(path.join(os.tmpdir(), "phantom-source-identity-"));
fs.writeFileSync(path.join(sourceFixture, "source.txt"), "owned source fixture\n");
function fixtureGit(...args) {
  return execFileSync("git", ["-C", sourceFixture, ...args], { encoding: "utf8" }).trim();
}
fixtureGit("init", "--quiet");
fixtureGit("add", "source.txt");
fixtureGit("-c", "user.name=Phantom fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Owned fixture");
const sourceRevision = fixtureGit("rev-parse", "HEAD");
test.after(() => fs.rmSync(sourceFixture, { recursive: true, force: true }));

const webDir = path.resolve(__dirname, "..");
const repositoryDir = path.resolve(webDir, "../..");
const observabilityPath = path.join(
  webDir,
  "src/lib/hosted-observability.ts",
);
const commissioningPath = path.join(webDir, "src/lib/commissioning.ts");
const publicAuthConfigurationPath = path.join(
  webDir,
  "src/lib/public-auth-configuration.ts",
);

const OBSERVABILITY_ENVS = [
  "PHANTOM_BUILD_SOURCE_REVISION",
  "VERCEL_GIT_COMMIT_SHA",
  "VERCEL_DEPLOYMENT_ID",
  "VERCEL_ENV",
  "NEXT_PUBLIC_SUPABASE_URL",
  "NEXT_PUBLIC_SUPABASE_ANON_KEY",
  "PHANTOM_PUBLIC_AUTH_CONFIGURATION_FINGERPRINT",
  "SUPABASE_SERVICE_ROLE_KEY",
  "STRIPE_SECRET_KEY",
  "STRIPE_PRO_PRICE_ID",
  "STRIPE_WEBHOOK_SECRET",
  "PHANTOM_BILLING_ENABLED",
  "PHANTOM_CLOUD_VAULTS_ENABLED",
  "PHANTOM_TEAMS_ENABLED",
];

function compileModule(filePath, localRequire) {
  const output = ts.transpileModule(fs.readFileSync(filePath, "utf8"), {
    compilerOptions: {
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      resolveJsonModule: true,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const fn = new Function(
    "exports",
    "require",
    "module",
    "__filename",
    "__dirname",
    output,
  );
  fn(module.exports, localRequire, module, filePath, path.dirname(filePath));
  return module.exports;
}

function loadCommissioning() {
  return compileModule(commissioningPath, (specifier) => {
    if (specifier === "server-only") return {};
    return require(specifier);
  });
}

function loadObservability(packageVersion = "0.7.5", frozenSourceRevision = sourceRevision) {
  const commissioning = loadCommissioning();
  const publicAuthConfiguration = compileModule(
    publicAuthConfigurationPath,
    require,
  );
  const previousSource = process.env.PHANTOM_BUILD_SOURCE_REVISION;
  if (frozenSourceRevision === undefined || frozenSourceRevision === null) {
    delete process.env.PHANTOM_BUILD_SOURCE_REVISION;
  } else {
    process.env.PHANTOM_BUILD_SOURCE_REVISION = frozenSourceRevision;
  }
  try {
    return compileModule(observabilityPath, (specifier) => {
      if (specifier === "server-only") return {};
      if (specifier === "./commissioning") return commissioning;
      if (specifier === "./public-auth-configuration") {
        return publicAuthConfiguration;
      }
      if (specifier === "../../package.json") {
        return { name: "phantom-web", version: packageVersion };
      }
      return require(specifier);
    });
  } finally {
    if (previousSource === undefined) delete process.env.PHANTOM_BUILD_SOURCE_REVISION;
    else process.env.PHANTOM_BUILD_SOURCE_REVISION = previousSource;
  }
}

function loadRoute(relativePath, observability) {
  return compileModule(path.join(webDir, relativePath), (specifier) => {
    if (specifier === "@/lib/hosted-observability") return observability;
    return require(specifier);
  });
}

function validEnvironment() {
  const env = {
    VERCEL_GIT_COMMIT_SHA: sourceRevision,
    VERCEL_DEPLOYMENT_ID: `dpl_${"B".repeat(24)}`,
    VERCEL_ENV: "production",
    NEXT_PUBLIC_SUPABASE_URL: "https://phantom-test.supabase.co",
    NEXT_PUBLIC_SUPABASE_ANON_KEY: `anon_${"c".repeat(32)}`,
    SUPABASE_SERVICE_ROLE_KEY: `service_${"d".repeat(32)}`,
    STRIPE_SECRET_KEY: `sk_test_${"e".repeat(24)}`,
    STRIPE_PRO_PRICE_ID: `price_${"F".repeat(24)}`,
    STRIPE_WEBHOOK_SECRET: `whsec_${"g".repeat(24)}`,
  };
  env.PHANTOM_PUBLIC_AUTH_CONFIGURATION_FINGERPRINT = createHash("sha256")
    .update("phantom-public-auth-configuration-v1\0")
    .update(env.NEXT_PUBLIC_SUPABASE_URL)
    .update("\0")
    .update(env.NEXT_PUBLIC_SUPABASE_ANON_KEY)
    .digest("hex");
  return env;
}

async function withEnvironment(values, action) {
  const previous = new Map(
    OBSERVABILITY_ENVS.map((name) => [name, process.env[name]]),
  );
  for (const name of OBSERVABILITY_ENVS) delete process.env[name];
  Object.assign(process.env, values);
  try {
    return await action();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("build identity is exact, bounded, and all-or-nothing", () => {
  const observability = loadObservability();
  const valid = validEnvironment();
  assert.deepEqual(observability.readBuildIdentity(valid), {
    identified: true,
    release_version: "0.7.5",
    source_revision: valid.VERCEL_GIT_COMMIT_SHA,
    deployment_environment: "production",
    unavailable_reasons: [],
  });
  assert.equal(
    JSON.stringify(observability.readBuildIdentity(valid)).includes(
      valid.VERCEL_DEPLOYMENT_ID,
    ),
    false,
  );

  const cases = [
    [
      "short source revision",
      "VERCEL_GIT_COMMIT_SHA",
      "a".repeat(39),
      "source_revision_missing_or_invalid",
    ],
    [
      "uppercase source revision",
      "VERCEL_GIT_COMMIT_SHA",
      "A".repeat(40),
      "source_revision_missing_or_invalid",
    ],
    [
      "spaced source revision",
      "VERCEL_GIT_COMMIT_SHA",
      `${"a".repeat(40)} `,
      "source_revision_missing_or_invalid",
    ],
    [
      "wrong deployment prefix",
      "VERCEL_DEPLOYMENT_ID",
      `dep_${"B".repeat(24)}`,
      "deployment_id_missing_or_invalid",
    ],
    [
      "short deployment id",
      "VERCEL_DEPLOYMENT_ID",
      "dpl_short",
      "deployment_id_missing_or_invalid",
    ],
    [
      "unknown environment",
      "VERCEL_ENV",
      "Production",
      "deployment_environment_missing_or_invalid",
    ],
  ];

  for (const [name, field, value, reason] of cases) {
    const candidate = { ...valid };
    if (value === undefined) delete candidate[field];
    else candidate[field] = value;
    const identity = observability.readBuildIdentity(candidate);
    assert.equal(identity.identified, false, name);
    assert.equal(identity.release_version, null, name);
    assert.equal(identity.source_revision, null, name);
    assert.equal(identity.deployment_environment, null, name);
    assert.ok(identity.unavailable_reasons.includes(reason), name);
    assert.doesNotMatch(JSON.stringify(identity), /dep_|Production|A{40}/, name);
  }

  const invalidRelease = loadObservability("v0.7.5").readBuildIdentity(valid);
  assert.equal(invalidRelease.identified, false);
  assert.deepEqual(invalidRelease.unavailable_reasons, [
    "release_version_missing_or_invalid",
  ]);
});

test("clean build source identifies prebuilt deployments without a platform Git variable", () => {
  const observability = loadObservability();
  const env = validEnvironment();
  delete env.VERCEL_GIT_COMMIT_SHA;
  const identity = observability.readBuildIdentity(env);
  assert.equal(identity.identified, true);
  assert.equal(identity.source_revision, sourceRevision);
});

test("runtime source variables cannot repair missing or conflicting frozen source", () => {
  const valid = validEnvironment();
  for (const witness of [null, "unidentified", "bad"]) {
    const identity = loadObservability("0.7.5", witness).readBuildIdentity({
      ...valid,
      PHANTOM_BUILD_SOURCE_REVISION: sourceRevision,
    });
    assert.equal(identity.identified, false);
    assert.deepEqual(identity.unavailable_reasons, ["source_revision_missing_or_invalid"]);
  }
  const observability = loadObservability();
  for (const providerSource of ["", " ", "A".repeat(40), "bad", "b".repeat(40)]) {
    const identity = observability.readBuildIdentity({
      ...valid,
      VERCEL_GIT_COMMIT_SHA: providerSource,
      PHANTOM_BUILD_SOURCE_REVISION: providerSource,
    });
    assert.equal(identity.identified, false, providerSource);
    assert.equal(identity.source_revision, null);
    assert.deepEqual(identity.unavailable_reasons, ["source_revision_missing_or_invalid"]);
  }
  for (const field of ["VERCEL_DEPLOYMENT_ID", "VERCEL_ENV"]) {
    const env = { ...valid };
    delete env.VERCEL_GIT_COMMIT_SHA;
    delete env[field];
    assert.equal(observability.readBuildIdentity(env).identified, false, field);
  }
});

test("source binding diagnostics distinguish absence, invalidity, equality and conflict", () => {
  const observability = loadObservability();
  for (const [platformSource, category, identified] of [
    [undefined, "absent", true],
    ["", "invalid", false],
    ["unexpected-platform-marker", "invalid", false],
    [sourceRevision, "matching", true],
    ["f".repeat(40), "conflicting", false],
  ]) {
    const env = validEnvironment();
    if (platformSource === undefined) delete env.VERCEL_GIT_COMMIT_SHA;
    else env.VERCEL_GIT_COMMIT_SHA = platformSource;
    assert.deepEqual(observability.sourceBindingDiagnostic(env), {
      build_observation: "valid",
      platform_source: category,
    });
    assert.equal(observability.readBuildIdentity(env).identified, identified);
  }
  for (const witness of [null, "unidentified", "invalid-build-observation"]) {
    const missing = loadObservability("0.7.5", witness);
    const env = validEnvironment();
    assert.deepEqual(missing.sourceBindingDiagnostic(env), {
      build_observation: "missing_or_invalid",
      platform_source: "conflicting",
    });
    assert.equal(missing.readBuildIdentity(env).identified, false);
    delete env.VERCEL_GIT_COMMIT_SHA;
    assert.deepEqual(missing.sourceBindingDiagnostic(env), {
      build_observation: "missing_or_invalid",
      platform_source: "absent",
    });
    assert.equal(missing.readBuildIdentity(env).identified, false);
  }
});

test("held source diagnostics log only fixed categories and preserve the public response", async () => {
  const observability = loadObservability();
  const route = loadRoute("src/app/api/v1/ready/route.ts", observability);
  for (const [platformSource, category] of [
    [undefined, "absent"], ["", "invalid"],
    ["unexpected-platform-marker", "invalid"],
    [sourceRevision, "matching"], ["f".repeat(40), "conflicting"],
  ]) {
    const env = validEnvironment();
    delete env.VERCEL_DEPLOYMENT_ID; // Hold another axis to inspect every source category.
    if (platformSource === undefined) delete env.VERCEL_GIT_COMMIT_SHA;
    else env.VERCEL_GIT_COMMIT_SHA = platformSource;
    const calls = [];
    const originalWarn = console.warn;
    console.warn = (...args) => calls.push(args);
    try {
      await withEnvironment(env, async () => {
        const response = route.GET();
        assert.equal(response.status, 503);
        assert.deepEqual(await response.json(), {
          status: "not_ready", service: "phantom-web", release_version: "0.7.5",
        });
        assert.equal(calls.length, 1);
        const [marker, text] = calls[0];
        assert.equal(marker, "phantom-readiness-held");
        const diagnostic = JSON.parse(text);
        assert.deepEqual(Object.keys(diagnostic).sort(), [
          "build_identity_reasons", "checks", "hosted_services", "source_binding",
        ]);
        assert.deepEqual(diagnostic.source_binding, {
          build_observation: "valid", platform_source: category,
        });
        for (const value of [sourceRevision, "f".repeat(40), "unexpected-platform-marker",
          ...["NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY",
            "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY", "STRIPE_PRO_PRICE_ID",
            "STRIPE_WEBHOOK_SECRET"].map((name) => env[name])]) {
          assert.equal(text.includes(value), false, value);
        }
      });
    } finally {
      console.warn = originalWarn;
    }
  }
});

test("health is provider-free route/runtime liveness with no-store responses", async () => {
  const observability = loadObservability();
  const route = loadRoute("src/app/api/v1/health/route.ts", observability);
  assert.equal(route.dynamic, "force-dynamic");
  assert.equal(route.runtime, "nodejs");

  await withEnvironment({}, async () => {
    const response = route.GET();
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(await response.json(), {
      status: "alive",
      service: "phantom-web",
      release_version: "0.7.5",
    });
  });

  const source = fs.readFileSync(observabilityPath, "utf8");
  assert.doesNotMatch(source, /createServiceClient|getStripe|fetch\s*\(/);
});

test("readiness fails closed for each invalid core field and build field", async () => {
  const observability = loadObservability();
  const route = loadRoute("src/app/api/v1/ready/route.ts", observability);
  const cases = [
    ["source revision", "VERCEL_GIT_COMMIT_SHA", "bad"],
    ["deployment id", "VERCEL_DEPLOYMENT_ID", "bad"],
    ["deployment environment", "VERCEL_ENV", "staging"],
    ["missing Supabase URL", "NEXT_PUBLIC_SUPABASE_URL", undefined],
    ["Supabase URL", "NEXT_PUBLIC_SUPABASE_URL", "http://localhost:54321"],
    [
      "different valid Supabase project",
      "NEXT_PUBLIC_SUPABASE_URL",
      "https://other-project.supabase.co",
    ],
    [
      "non-Supabase HTTPS URL",
      "NEXT_PUBLIC_SUPABASE_URL",
      "https://credentials.example.com",
    ],
    [
      "Supabase URL credentials",
      "NEXT_PUBLIC_SUPABASE_URL",
      "https://user:pass@phantom-test.supabase.co",
    ],
    ["missing Supabase anon key", "NEXT_PUBLIC_SUPABASE_ANON_KEY", undefined],
    ["Supabase anon key", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "short"],
    ["missing Supabase service key", "SUPABASE_SERVICE_ROLE_KEY", undefined],
    ["Supabase service key", "SUPABASE_SERVICE_ROLE_KEY", "bad key with spaces"],
  ];

  for (const [name, field, value] of cases) {
    const env = { ...validEnvironment() };
    if (value === undefined) delete env[field];
    else env[field] = value;
    await withEnvironment(env, async () => {
      const response = route.GET();
      assert.equal(response.status, 503, name);
      assert.equal(response.headers.get("cache-control"), "no-store", name);
      assert.equal((await response.json()).status, "not_ready", name);
    });
  }
});

test("closed hosted gates do not make core configuration unready", async () => {
  const observability = loadObservability();
  const route = loadRoute("src/app/api/v1/ready/route.ts", observability);

  for (const gateValue of [undefined, "", "false", "TRUE", "1", " true "]) {
    const env = {
      ...validEnvironment(),
      ...(gateValue === undefined
        ? {}
        : {
            PHANTOM_BILLING_ENABLED: gateValue,
            PHANTOM_CLOUD_VAULTS_ENABLED: gateValue,
            PHANTOM_TEAMS_ENABLED: gateValue,
          }),
    };
    await withEnvironment(env, async () => {
      const response = route.GET();
      assert.equal(response.status, 200, String(gateValue));
      const body = await response.json();
      assert.equal(body.status, "configuration_ready");
      const internal = observability.readinessSnapshot();
      assert.deepEqual(
        internal.hosted_services,
        {
          billing: { state: "not_commissioned" },
          personal_vaults: { state: "not_commissioned" },
          teams: { state: "not_commissioned" },
        },
      );
      assert.deepEqual(internal.acceptance, {
        provider: "not_checked",
        customer: "not_established",
      });
      assert.deepEqual(body, {
        status: "configuration_ready",
        service: "phantom-web",
        release_version: "0.7.5",
      });
    });
  }
});

test("each commissioned service must have its configuration", async () => {
  const observability = loadObservability();
  const route = loadRoute("src/app/api/v1/ready/route.ts", observability);
  const cases = [
    ["billing", "PHANTOM_BILLING_ENABLED"],
    ["personal_vaults", "PHANTOM_CLOUD_VAULTS_ENABLED"],
    ["teams", "PHANTOM_TEAMS_ENABLED"],
  ];

  for (const [service, gate] of cases) {
    const configured = { ...validEnvironment(), [gate]: "true" };
    await withEnvironment(configured, async () => {
      const response = route.GET();
      assert.equal(response.status, 200, service);
      assert.equal(
        observability.readinessSnapshot().hosted_services[service].state,
        "configuration_ready",
        service,
      );
    });
  }

  for (const [name, field, value] of [
    ["missing Stripe key", "STRIPE_SECRET_KEY", undefined],
    ["malformed Stripe key", "STRIPE_SECRET_KEY", "sk_live_bad key"],
    ["missing Stripe price", "STRIPE_PRO_PRICE_ID", undefined],
    ["malformed Stripe price", "STRIPE_PRO_PRICE_ID", "prod_not-a-price"],
    ["missing webhook secret", "STRIPE_WEBHOOK_SECRET", undefined],
    ["malformed webhook secret", "STRIPE_WEBHOOK_SECRET", "whsec_bad key"],
  ]) {
    const env = {
      ...validEnvironment(),
      PHANTOM_BILLING_ENABLED: "true",
    };
    if (value === undefined) delete env[field];
    else env[field] = value;
    await withEnvironment(env, async () => {
      const response = route.GET();
      assert.equal(response.status, 503, name);
      assert.equal(
        observability.readinessSnapshot().hosted_services.billing.state,
        "configuration_incomplete",
      );
      assert.deepEqual(await response.json(), {
        status: "not_ready",
        service: "phantom-web",
        release_version: "0.7.5",
      });
    });
  }
});

test("readiness never returns credential or provider configuration values", async () => {
  const observability = loadObservability();
  const route = loadRoute("src/app/api/v1/ready/route.ts", observability);
  const env = {
    ...validEnvironment(),
    PHANTOM_BILLING_ENABLED: "true",
    PHANTOM_CLOUD_VAULTS_ENABLED: "true",
    PHANTOM_TEAMS_ENABLED: "true",
  };

  await withEnvironment(env, async () => {
    const response = route.GET();
    assert.equal(response.status, 200);
    const serialized = JSON.stringify(await response.json());
    for (const name of [
      "NEXT_PUBLIC_SUPABASE_URL",
      "NEXT_PUBLIC_SUPABASE_ANON_KEY",
      "SUPABASE_SERVICE_ROLE_KEY",
      "STRIPE_SECRET_KEY",
      "STRIPE_PRO_PRICE_ID",
      "STRIPE_WEBHOOK_SECRET",
    ]) {
      assert.equal(serialized.includes(env[name]), false, name);
    }
    for (const operationalDetail of [
      "source_revision",
      "deployment_environment",
      "unavailable_reasons",
      "hosted_services",
      "provider",
      "customer",
      env.VERCEL_GIT_COMMIT_SHA,
      env.VERCEL_DEPLOYMENT_ID,
    ]) {
      assert.equal(serialized.includes(operationalDetail), false, operationalDetail);
    }
  });
});

test("readiness binds browser auth configuration to the frozen build fingerprint", () => {
  const source = fs.readFileSync(observabilityPath, "utf8");
  assert.match(
    source,
    /process\.env\.PHANTOM_PUBLIC_AUTH_CONFIGURATION_FINGERPRINT/,
  );
  assert.doesNotMatch(source, /process\.env\.NEXT_PUBLIC_SUPABASE_/);
});

test("web release metadata matches the Rust workspace release", () => {
  const webPackage = require(path.join(webDir, "package.json"));
  const cargo = fs.readFileSync(path.join(repositoryDir, "Cargo.toml"), "utf8");
  const workspaceVersion = cargo.match(
    /\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
  )?.[1];
  assert.equal(webPackage.version, workspaceVersion);
});

test("documentation redirects are a closed canonical allowlist", async () => {
  const docsRoutes = require(path.join(webDir, "docs-routes.json"));
  const publicAuthConfiguration = compileModule(
    publicAuthConfigurationPath,
    require,
  );
  const configModule = compileModule(
    path.join(webDir, "next.config.ts"),
    (specifier) => {
      if (specifier === "./src/lib/public-auth-configuration") {
        return publicAuthConfiguration;
      }
      if (specifier === "./docs-routes.json") return docsRoutes;
      if (specifier === "./src/lib/build-source-revision") {
        return compileModule(path.join(webDir, "src/lib/build-source-revision.ts"), require);
      }
      return require(specifier);
    },
  );
  const redirects = await configModule.default.redirects();
  assert.deepEqual(
    redirects,
    docsRoutes.map(({ source, file }) => ({
      source,
      destination: `https://github.com/ashlrai/phantom-secrets/blob/main/docs/${file}`,
      permanent: false,
    })),
  );
  assert.equal(redirects.some(({ source }) => source.includes(":")), false);
});

test("retired network installer URLs return a non-executable 410 response", async () => {
  class TestNextResponse extends Response {}
  const retiredInstaller = compileModule(
    path.join(webDir, "src/middleware.ts"),
    (specifier) => {
      if (specifier === "next/server") return { NextResponse: TestNextResponse };
      return require(specifier);
    },
  );

  for (const pathName of ["/install.sh", "/install.ps1"]) {
    assert.ok(retiredInstaller.config.matcher.includes(pathName));
    const response = retiredInstaller.middleware();
    assert.equal(response.status, 410);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.match(await response.text(), /network installer endpoint is unavailable/i);
  }
});
