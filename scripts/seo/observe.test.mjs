import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertDefaultNetworkUrl,
  containsExactUrl,
  decodeEntities,
  JOB_SUMMARY_MAX_BYTES,
  observeProduction,
  requestWithinBoundary,
  renderSummary,
  structuredData,
  validateAggregateInput,
  validateExperiments,
  writePrivateReport,
} from "./observe.mjs";
import { assertReadOnlyWorkflowPolicy } from "./workflow-policy.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = path.resolve(scriptDirectory, "../..");
const publicPaths = new Set([
  "/",
  "/docs",
  "/docs/guide",
  "/security",
  "/secrets",
  "/llms.txt",
  "/llms-full.txt",
]);

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    if (!signal) return;
    const abort = () => {
      clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    };
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  });
}

function jsonLd(type, extra = {}) {
  return `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": type,
    ...extra,
  })}</script>`;
}

test("the CLI rejects a missing required output or output value", () => {
  const observer = path.join(scriptDirectory, "observe.mjs");
  for (const [args, diagnostic] of [
    [[], /--out is required/],
    [["--experiments", "missing-ledger.json"], /--out is required/],
    [["--out"], /missing value for --out/],
  ]) {
    const result = spawnSync(process.execPath, [observer, ...args], {
      cwd: repositoryDirectory,
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, diagnostic);
    assert.match(result.stderr, /Usage: node scripts\/seo\/observe\.mjs --out <report\.json>/);
  }
});

test("the documented local command writes its report and fails closed on an unreadable ledger", async () => {
  const readme = await readFile(path.join(repositoryDirectory, "apps/web/README.md"), "utf8");
  const command = readme.match(/```sh\n(node scripts\/seo\/observe\.mjs [^\n]+)\n```/);
  assert.ok(command, "README contains the local observer command");
  const [node, script, ...args] = command[1].split(/\s+/);
  assert.equal(node, "node");
  assert.deepEqual(args, ["--experiments", "seo/experiments.json", "--out", "seo/reports/observation.json"]);
  await readFile(path.join(repositoryDirectory, args[1]));

  const directory = await mkdtemp(path.join(tmpdir(), "phantom-seo-readme-"));
  try {
    // A missing ledger exercises the real CLI and report path without network access.
    args[1] = path.join(directory, "missing-ledger.json");
    args[3] = path.join(directory, "reports", "observation.json");
    const result = spawnSync(process.execPath, [script, ...args], {
      cwd: repositoryDirectory,
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    const report = JSON.parse(await readFile(args[3], "utf8"));
    assert.equal(report.verdict, "FAIL");
    assert.equal(report.findings[0].code, "observer_execution_failed");
    assert.match(result.stdout, /FAIL/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("HTML entities are decoded exactly once", () => {
  assert.equal(decodeEntities("&amp;&quot;&#39;&lt;&gt;"), "&\"'<>");
  assert.equal(decodeEntities("&amp;lt;script&amp;gt;"), "&lt;script&gt;");
});

test("JSON-LD extraction accepts HTML-compatible script endings", () => {
  const result = structuredData(
    '<script type="application/ld+json">{"@type":"SoftwareApplication"}</ScRiPt >',
  );
  assert.deepEqual(result, {
    values: [{ "@type": "SoftwareApplication" }],
    errors: [],
  });
  assert.deepEqual(structuredData('<script type="application/ld+json">{broken}</script>'), {
    values: [],
    errors: ["invalid_json_ld"],
  });
  assert.deepEqual(structuredData('<script type="application/ld+json">{"value":1}'), {
    values: [],
    errors: ["invalid_json_ld"],
  });
});

test("machine-readable links require exact canonical URLs", () => {
  const expected = "https://github.com/ashlrai/phantom-secrets";
  assert.equal(containsExactUrl(`Repository: ${expected}.`, expected), true);
  for (const candidate of [
    "https://evil.example/?next=https://github.com/ashlrai/phantom-secrets",
    "https://github.com/ashlrai/phantom-secrets.evil",
    "https://user@github.com/ashlrai/phantom-secrets",
    "https://github.com/ashlrai/phantom-secrets?token=private",
    "https://github.com/ashlrai/phantom-secrets#lookalike",
  ]) {
    assert.equal(containsExactUrl(candidate, expected), false);
  }
});

function html(origin, route, options = {}) {
  const guide = options.guideSchema ?? route === "/";
  const schema = route === "/"
    ? [
        jsonLd("SoftwareApplication", { softwareVersion: "9.8.7" }),
        jsonLd("SoftwareSourceCode"),
        jsonLd("Organization"),
        guide ? jsonLd("HowTo") : "",
        guide ? jsonLd("FAQPage") : "",
      ].join("")
    : guide
      ? `${jsonLd("HowTo")}${jsonLd("FAQPage")}`
    : route.startsWith("/docs/")
      ? `${jsonLd("TechArticle")}${jsonLd("BreadcrumbList")}`
      : "";
  const canonical = options.canonical ?? `${origin}${route}`;
  const structured = options.invalidJsonLd
    ? '<script type="application/ld+json">{not-json}</script>'
    : schema;
  return `<!doctype html><html><head><title>${route} — Phantom</title><meta name="description" content="Description for ${route}"><link rel="canonical" href="${canonical}">${structured}</head><body><h1>Page ${route}</h1></body></html>`;
}

async function withFixtureServer(action, overrides = {}) {
  const requests = [];
  const server = createServer((request, response) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    requests.push(request.url);
    const override = Object.entries(overrides).find(([route]) => route === request.url)?.[1];
    if (typeof override === "function") {
      override(response, origin);
      return;
    }
    if (request.url === "/sitemap.xml") {
      response.setHeader("content-type", "application/xml");
      response.end(
        `<?xml version="1.0"?><urlset>${[...publicPaths]
          .map((route) => `<url><loc>${origin}${route}</loc></url>`)
          .join("")}</urlset>`,
      );
      return;
    }
    if (request.url === "/robots.txt") {
      response.setHeader("content-type", "text/plain");
      response.end(`User-Agent: *\nAllow: /\nDisallow: /api/\nSitemap: ${origin}/sitemap.xml\n`);
      return;
    }
    if (request.url === "/llms.txt") {
      response.setHeader("content-type", "text/plain; charset=utf-8");
      response.end(
        `# Phantom\n\nLatest release: \`v9.8.7\`.\nhttps://phm.dev/llms-full.txt\nhttps://github.com/ashlrai/phantom-secrets\n${"boundary ".repeat(20)}`,
      );
      return;
    }
    if (request.url === "/llms-full.txt") {
      response.setHeader("content-type", "text/plain; charset=utf-8");
      response.end(`# Phantom full reference\n${"bounded evidence ".repeat(20)}`);
      return;
    }
    if (request.url === "/api/v1/health") {
      response.setHeader("content-type", "application/json");
      response.end('{"status":"ok"}');
      return;
    }
    if (request.url === "/api/v1/ready") {
      response.statusCode = 503;
      response.setHeader("content-type", "application/json");
      response.end('{"status":"not_ready"}');
      return;
    }
    if (request.url === "/github/repos/ashlrai/phantom-secrets") {
      response.setHeader("content-type", "application/json");
      response.end('{"stargazers_count":16,"forks_count":3}');
      return;
    }
    if (request.url === "/github/repos/ashlrai/phantom-secrets/releases/latest") {
      response.setHeader("content-type", "application/json");
      response.end('{"tag_name":"v9.8.7","published_at":"2026-09-05T00:00:00Z","immutable":true,"draft":false,"prerelease":false}');
      return;
    }
    if (publicPaths.has(request.url)) {
      response.setHeader("content-type", "text/html; charset=utf-8");
      if (request.url === "/") {
        for (const [name, value] of [
          ["content-security-policy", "default-src 'self'"],
          ["permissions-policy", "camera=()"],
          ["referrer-policy", "strict-origin-when-cross-origin"],
          ["strict-transport-security", "max-age=63072000"],
          ["x-content-type-options", "nosniff"],
          ["x-frame-options", "DENY"],
        ]) {
          response.setHeader(name, value);
        }
      }
      response.end(html(origin, request.url));
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    return await action({
      origin,
      requests,
      options: {
        siteOrigin: origin,
        githubRepositoryApi: `${origin}/github/repos/ashlrai/phantom-secrets`,
        networkPolicy: (url) => url.origin === origin && !url.search && !url.hash,
        now: new Date("2026-09-05T12:00:00Z"),
      },
    });
  } finally {
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

test("the default network policy is closed to phm.dev and two public GitHub records", () => {
  assert.equal(assertDefaultNetworkUrl("https://phm.dev/docs").pathname, "/docs");
  assert.equal(
    assertDefaultNetworkUrl("https://api.github.com/repos/ashlrai/phantom-secrets/releases/latest").pathname,
    "/repos/ashlrai/phantom-secrets/releases/latest",
  );
  for (const forbidden of [
    "https://example.com/",
    "http://phm.dev/",
    "https://phm.dev/docs?code=private",
    "https://phm.dev/docs?",
    "https://phm.dev/docs#",
    "https://api.github.com/user",
    "https://api.github.com/repos/another/project",
  ]) {
    assert.throws(() => assertDefaultNetworkUrl(forbidden), /not allowlisted/);
  }
});

test("an empty query is rejected before a network request", async () => {
  let requests = 0;
  await assert.rejects(
    requestWithinBoundary("https://phm.dev/docs?", {
      fetchImpl: async () => { requests += 1; },
      networkPolicy: assertDefaultNetworkUrl,
    }),
    /network destination is not allowlisted: https:\/\/phm\.dev\/docs/,
  );
  assert.equal(requests, 0);
});

test("a malformed site URL fails clearly before any network request", async () => {
  let requests = 0;
  await assert.rejects(
    observeProduction({
      siteOrigin: "https://[invalid",
      fetchImpl: async () => { requests += 1; },
    }),
    { code: "ERR_INVALID_URL", message: /Invalid URL/ },
  );
  assert.equal(requests, 0);

  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", `
    import { observeProduction } from "./scripts/seo/observe.mjs";
    await observeProduction({
      siteOrigin: "https://[invalid",
      fetchImpl: async () => { process.stdout.write("unexpected network request"); },
    });
  `], {
    cwd: repositoryDirectory,
    encoding: "utf8",
    timeout: 5_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /Invalid URL/);
  assert.match(result.stderr, /ERR_INVALID_URL/);
});

test("an empty query in a redirect is rejected before following it", async () => {
  let requests = 0;
  await assert.rejects(
    requestWithinBoundary("https://phm.dev/", {
      fetchImpl: async () => {
        requests += 1;
        return new Response(null, { status: 302, headers: { location: "/docs?" } });
      },
      networkPolicy: assertDefaultNetworkUrl,
    }),
    /network destination is not allowlisted: https:\/\/phm\.dev\/docs/,
  );
  assert.equal(requests, 1);
});

test("one monotonic request deadline covers retries and redirects", async (t) => {
  const temporary = new Response("temporary", { status: 503 });
  const redirect = new Response("", {
    status: 302,
    headers: { location: "https://phm.dev/docs" },
  });
  // Drive the monotonic clock and abort timers together so scheduler delays
  // cannot exhaust the request budget before the retry and redirect are tested.
  let now = 0;
  let nextTimer = 0;
  const timers = new Map();
  const budgets = [];
  const requests = [];
  t.mock.method(performance, "now", () => now);
  t.mock.method(globalThis, "setTimeout", (callback, milliseconds) => {
    const id = ++nextTimer;
    timers.set(id, { callback, milliseconds });
    budgets.push(milliseconds);
    return id;
  });
  t.mock.method(globalThis, "clearTimeout", (id) => timers.delete(id));
  const fetchImpl = async (url, { signal }) => {
    requests.push(url.href);
    assert.equal(signal.aborted, false);
    if (requests.length === 1) {
      now += 40;
      return temporary;
    }
    if (requests.length === 2) {
      now += 40;
      return redirect;
    }
    assert.equal(timers.size, 1);
    const timer = timers.values().next().value;
    now += timer.milliseconds;
    timer.callback();
    signal.throwIfAborted();
    assert.fail("the remaining request budget must abort the redirected request");
  };

  await assert.rejects(
    requestWithinBoundary("https://phm.dev/", {
      fetchImpl,
      networkPolicy: (url) => url.origin === "https://phm.dev",
      retries: 1,
      timeoutMs: 120,
    }),
    /request deadline exceeded/,
  );
  assert.deepEqual(requests, [
    "https://phm.dev/",
    "https://phm.dev/",
    "https://phm.dev/docs",
  ]);
  assert.deepEqual(budgets, [120, 80, 40]);
  assert.equal(now, 120);
  assert.equal(timers.size, 0);
});

test("the global observation deadline aborts concurrent initial requests", async () => {
  const fetchImpl = async (_url, { signal }) => {
    await delay(100, signal);
    return new Response("late", { status: 200 });
  };
  await assert.rejects(
    observeProduction({
      fetchImpl,
      observationBudgetMs: 25,
      requestTimeoutMs: 100,
      now: new Date("2026-09-05T12:00:00Z"),
    }),
    /request deadline exceeded/,
  );
});

test("a complete public fixture produces a deterministic, sanitized passing report", async () => {
  await withFixtureServer(async ({ options, requests }) => {
    const ledger = {
      schema_version: "phantom-seo-experiments-v1",
      default_observation_days: 28,
      experiments: [],
    };
    const first = await observeProduction({ ...options, experiments: ledger });
    const second = await observeProduction({ ...options, experiments: ledger });
    assert.deepEqual(first, second);
    assert.equal(first.verdict, "PASS");
    assert.deepEqual(first.counts, { fail: 0, warn: 0 });
    assert.equal(first.technical.sitemap.route_count, publicPaths.size);
    assert.equal(first.technical.operational.health.status, 200);
    assert.equal(first.technical.operational.ready.status, 503);
    assert.equal(first.github.stargazers, 16);
    assert.equal(first.github.latest_release, "v9.8.7");
    assert.equal(first.github.latest_release_immutable, true);
    assert.equal(JSON.stringify(first).includes("bounded evidence"), false);
    assert.equal(JSON.stringify(first).includes("json_ld"), false);
    assert.equal(JSON.stringify(first).includes("github/repos"), false);
    assert.ok(requests.length >= publicPaths.size + 6);
    assert.match(renderSummary(first), /does not edit content, publish, deploy, contact people/);
  });
});

test("a non-success public page response reports its status as a failure", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.equal(report.verdict, "FAIL");
      assert.deepEqual(report.counts, { fail: 1, warn: 0 });
      assert.equal(report.technical.public_routes.find((page) => page.route === "/docs").status, 404);
      assert.deepEqual(report.findings, [{
        severity: "fail",
        code: "public_route_status",
        message: "Public route returned HTTP 404",
        route: "/docs",
      }]);
      assert.match(renderSummary(report), /\*\*FAIL public_route_status\*\* \(\/docs\): Public route returned HTTP 404/);
    },
    {
      "/docs": (response, origin) => {
        response.statusCode = 404;
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/docs"));
      },
    },
  );
});

test("a page without a title produces a missing-title failure", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.equal(report.verdict, "FAIL");
      assert.deepEqual(report.counts, { fail: 1, warn: 0 });
      assert.equal(report.technical.public_routes.find((page) => page.route === "/docs").title, null);
      assert.deepEqual(report.findings, [{
        severity: "fail",
        code: "title_missing",
        message: "Page title is missing",
        route: "/docs",
      }]);
      assert.match(renderSummary(report), /\*\*FAIL title_missing\*\* \(\/docs\): Page title is missing/);
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/docs").replace("<title>/docs — Phantom</title>", ""));
      },
    },
  );
});

test("a page without description metadata produces a missing-description failure", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.equal(report.verdict, "FAIL");
      assert.deepEqual(report.counts, { fail: 2, warn: 0 });
      for (const route of ["/docs", "/security"]) {
        assert.equal(
          report.technical.public_routes.find((page) => page.route === route).description,
          null,
        );
      }
      assert.deepEqual(report.findings, [
        {
          severity: "fail",
          code: "description_missing",
          message: "Meta description is missing",
          route: "/docs",
        },
        {
          severity: "fail",
          code: "description_missing",
          message: "Meta description is missing",
          route: "/security",
        },
      ]);
      const summary = renderSummary(report);
      assert.match(summary, /\*\*FAIL description_missing\*\* \(\/docs\): Meta description is missing/);
      assert.match(summary, /\*\*FAIL description_missing\*\* \(\/security\): Meta description is missing/);
    },
    {
      // The description meta tag is absent entirely on /docs and present but
      // empty on /security; both must report the same missing-description result.
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(
          html(origin, "/docs").replace(
            '<meta name="description" content="Description for /docs">',
            "",
          ),
        );
      },
      "/security": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(
          html(origin, "/security").replace('content="Description for /security"', 'content=""'),
        );
      },
    },
  );
});

test("the GitHub job summary is deterministically capped with an omitted count", () => {
  const findingCount = 500;
  const report = {
    verdict: "WARN",
    captured_at: "2026-09-05T12:00:00.000Z",
    counts: { fail: 0, warn: findingCount },
    technical: { sitemap: { route_count: 250 } },
    aggregate_inputs: {
      gsc: { state: "not_supplied" },
      ga4: { state: "not_supplied" },
      ahrefs: { state: "not_supplied" },
    },
    experiments: { experiments: [] },
    findings: Array.from({ length: findingCount }, (_, index) => ({
      severity: "warn",
      code: `synthetic_${String(index).padStart(3, "0")}`,
      route: `/docs/${index}`,
      message: `Finding ${index} ${"🔐".repeat(2_000)}`,
    })),
  };

  const first = renderSummary(report);
  const second = renderSummary(report);
  assert.equal(first, second);
  assert.ok(Buffer.byteLength(first, "utf8") <= JOB_SUMMARY_MAX_BYTES);
  const omitted = first.match(/\*\*TRUNCATED:\*\* (\d+) additional findings omitted/);
  assert.ok(omitted, "summary must state how many findings were omitted");
  assert.ok(Number(omitted[1]) > 0 && Number(omitted[1]) < findingCount);
  assert.match(first, /complete sanitized report remains in the artifact/);
});

test(
  "the sanitized report is created with owner-only permissions on POSIX",
  { skip: process.platform === "win32" },
  async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "phantom-seo-report-"));
    const reportFile = path.join(directory, "nested", "observation.json");
    try {
      await writePrivateReport(reportFile, { schema_version: "test", findings: [] });
      const metadata = await stat(reportFile);
      assert.equal(metadata.mode & 0o777, 0o600);
      assert.deepEqual(JSON.parse(await readFile(reportFile, "utf8")), {
        schema_version: "test",
        findings: [],
      });
      await assert.rejects(
        writePrivateReport(reportFile, { schema_version: "overwrite" }),
        /EEXIST/,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test("canonical, structured-data, and off-origin redirect failures stay visible", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.equal(report.verdict, "FAIL");
      assert.ok(report.findings.some((finding) => finding.code === "canonical_mismatch"));
      assert.ok(report.findings.some((finding) => finding.code === "structured_data_invalid"));
      assert.ok(report.findings.some((finding) => finding.code === "public_route_unreachable"));
      assert.doesNotMatch(JSON.stringify(report), /attacker-secret/);
    },
    {
      "/security": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/security", { canonical: "https://example.com/attacker-secret" }));
      },
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/docs", { invalidJsonLd: true }));
      },
      "/docs/guide": (response) => {
        response.statusCode = 302;
        response.setHeader("location", "https://example.com/attacker-secret");
        response.end();
      },
    },
  );
});

test("duplicate sitemap URLs fail deterministically before fetching public routes", async () => {
  await withFixtureServer(
    async ({ options, requests }) => {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const start = requests.length;
        await assert.rejects(observeProduction(options), {
          message: "sitemap contains duplicate path /docs",
        });
        assert.deepEqual(requests.slice(start).sort(), ["/robots.txt", "/sitemap.xml"]);
      }
    },
    {
      "/sitemap.xml": (response, origin) => {
        response.end(`<urlset>${["/docs", "/security", "/docs"]
          .map((route) => `<url><loc>${origin}${route}</loc></url>`)
          .join("")}</urlset>`);
      },
    },
  );
});

test("sitemap URLs with an empty query are rejected before fetching the route", async () => {
  await withFixtureServer(
    async ({ options, requests }) => {
      await assert.rejects(observeProduction(options), /sitemap URL contains query or hash data: \/docs/);
      assert.ok(!requests.includes("/docs"));
    },
    {
      "/sitemap.xml": (response, origin) => {
        response.end(`<urlset><url><loc>${origin}/docs?</loc></url></urlset>`);
      },
    },
  );
});

test("sitemap URLs with a fragment are rejected before fetching the route", async () => {
  // The bare "#" delimiter matters: URL.hash is empty even when it is present.
  for (const fragment of ["#", "#section"]) {
    await withFixtureServer(
      async ({ options, requests }) => {
        await assert.rejects(
          observeProduction(options),
          /sitemap URL contains query or hash data: \/docs/,
        );
        assert.ok(!requests.includes("/docs"));
      },
      {
        "/sitemap.xml": (response, origin) => {
          response.end(
            `<urlset><url><loc>${origin}/docs${fragment}</loc></url></urlset>`,
          );
        },
      },
    );
  }
});

test("canonical URLs with an empty query are reported as mismatches", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.ok(report.findings.some(
        (finding) => finding.code === "canonical_mismatch" && finding.route === "/docs",
      ));
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/docs", { canonical: `${origin}/docs?` }));
      },
    },
  );
});

test("canonical URLs with a fragment are reported as mismatches", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.ok(report.findings.some(
        (finding) => finding.code === "canonical_mismatch" && finding.route === "/docs",
      ));
      assert.equal(
        report.technical.public_routes.find((page) => page.route === "/docs").canonical,
        null,
      );
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/docs", { canonical: `${origin}/docs#section` }));
      },
    },
  );
});

test("product guide schema may move from the umbrella homepage to /secrets", async () => {
  const serve = (route, guideSchema) => (response, origin) => {
    response.setHeader("content-type", "text/html");
    for (const [name, value] of [
      ["content-security-policy", "default-src 'self'"],
      ["permissions-policy", "camera=()"],
      ["referrer-policy", "strict-origin-when-cross-origin"],
      ["strict-transport-security", "max-age=63072000"],
      ["x-content-type-options", "nosniff"],
      ["x-frame-options", "DENY"],
    ]) {
      response.setHeader(name, value);
    }
    response.end(html(origin, route, { guideSchema }));
  };
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.ok(!report.findings.some((finding) => finding.code === "home_schema_missing"));
    },
    { "/": serve("/", false), "/secrets": serve("/secrets", true) },
  );
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      const missing = report.findings.filter((finding) => finding.code === "home_schema_missing");
      assert.equal(missing.length, 2);
      assert.equal(report.verdict, "FAIL");
    },
    { "/": serve("/", false) },
  );
});

test("Search Console input accepts finalized page aggregates and rejects raw queries", () => {
  const value = {
    schema_version: "phantom-seo-gsc-v1",
    period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
    rows: [
      {
        page_path: "/docs",
        brand_class: "nonbrand",
        clicks: 12,
        impressions: 240,
        ctr: 0.05,
        position: 8.4,
      },
    ],
  };
  assert.deepEqual(validateAggregateInput("gsc", value, publicPaths).rows[0], value.rows[0]);
  assert.throws(
    () => validateAggregateInput("gsc", { ...value, query: "api key agent" }, publicPaths),
    /forbidden field query/,
  );
  assert.throws(
    () =>
      validateAggregateInput(
        "gsc",
        { ...value, rows: [{ ...value.rows[0], page_path: "/docs?code=private" }] },
        publicPaths,
      ),
    /must not contain query or hash data/,
  );
});

test("aggregate periods reject impossible dates and days that are not yet complete", () => {
  const base = {
    schema_version: "phantom-seo-gsc-v1",
    period: { start: "2026-02-01", end: "2026-02-28", data_state: "final" },
    rows: [],
  };
  assert.throws(
    () =>
      validateAggregateInput(
        "gsc",
        { ...base, period: { ...base.period, end: "2026-02-30" } },
        publicPaths,
        new Date("2026-03-05T12:00:00Z"),
      ),
    /not a calendar date/,
  );
  assert.throws(
    () =>
      validateAggregateInput(
        "gsc",
        {
          ...base,
          period: { start: "2026-09-01", end: "2026-09-05", data_state: "final" },
        },
        publicPaths,
        new Date("2026-09-05T12:00:00Z"),
      ),
    /after the observation capture time/,
  );
});

test("GA4 input suppresses small cohorts and rejects identifying or query-bearing fields", () => {
  const row = {
    page_path: "/",
    referral_class: "chatgpt",
    sessions: 18,
    engaged_sessions: 12,
    engagement_rate: 2 / 3,
    key_events: 4,
  };
  const value = {
    schema_version: "phantom-seo-ga4-v1",
    period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
    rows: [row, { ...row, referral_class: "other", sessions: 9, engaged_sessions: 5 }],
  };
  const validated = validateAggregateInput("ga4", value, publicPaths);
  assert.equal(validated.rows.length, 1);
  assert.equal(validated.suppressed_rows, 1);
  for (const forbidden of [
    ["page_referrer", "https://private.example/person"],
    ["user_pseudo_id", "person-1"],
    ["page_path_plus_query_string", "/?code=private"],
  ]) {
    assert.throws(
      () =>
        validateAggregateInput(
          "ga4",
          { ...value, rows: [{ ...row, [forbidden[0]]: forbidden[1] }] },
          publicPaths,
        ),
      /forbidden field/,
    );
  }
});

test("Ahrefs input is URL-aggregate only and rejects keyword material", () => {
  const value = {
    schema_version: "phantom-seo-ahrefs-v1",
    period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
    rows: [{ page_path: "/security", estimated_organic_traffic: 42.5, referring_domains: 7 }],
  };
  assert.equal(validateAggregateInput("ahrefs", value, publicPaths).rows[0].referring_domains, 7);
  assert.throws(
    () => validateAggregateInput("ahrefs", { ...value, keyword: "secret manager" }, publicPaths),
    /forbidden field keyword/,
  );
});

test("experiment state advances to review without mutating the checked-in decision", () => {
  const base = {
    id: "docs-answer-test",
    hypothesis: "A direct answer improves nonbrand impressions.",
    primary_metric: "gsc_nonbrand_impressions",
    target_routes: ["/docs"],
    control_routes: ["/security"],
    status: "observing",
    baseline_start: "2026-07-01",
    baseline_end: "2026-07-28",
    implementation_sha: "a".repeat(40),
    deployment_id: `dpl_${"B".repeat(24)}`,
    implemented_at: "2026-08-01T12:00:00Z",
    not_before: "2026-08-29T12:00:00Z",
    decision_rule: "Review finalized page evidence against the control cohort.",
    lesson: null,
  };
  const ledger = {
    schema_version: "phantom-seo-experiments-v1",
    default_observation_days: 28,
    experiments: [base],
  };
  const before = structuredClone(ledger);
  const validated = validateExperiments(ledger, publicPaths, new Date("2026-09-05T00:00:00Z"));
  assert.equal(validated.experiments[0].status, "observing");
  assert.equal(validated.experiments[0].observed_status, "ready_for_review");
  assert.deepEqual(ledger, before);
  assert.throws(
    () =>
      validateExperiments(
        { ...ledger, experiments: [{ ...base, target_routes: ["/private/person"] }] },
        publicPaths,
      ),
    /not present in the observed sitemap/,
  );
  assert.throws(
    () =>
      validateExperiments(
        {
          ...ledger,
          experiments: [{ ...base, not_before: "2026-08-08T12:00:00Z" }],
        },
        publicPaths,
      ),
    /earlier than the default observation window/,
  );
  assert.throws(
    () =>
      validateExperiments(
        {
          ...ledger,
          experiments: [
            {
              ...base,
              status: "ready_for_review",
              not_before: "2026-09-29T12:00:00Z",
            },
          ],
        },
        publicPaths,
        new Date("2026-09-05T00:00:00Z"),
      ),
    /advances before not_before/,
  );
  assert.throws(
    () =>
      validateExperiments(
        {
          ...ledger,
          experiments: [{ ...base, baseline_start: "2026-02-30" }],
        },
        publicPaths,
      ),
    /not a calendar date/,
  );
  assert.throws(
    () =>
      validateExperiments(
        {
          ...ledger,
          experiments: [{ ...base, implemented_at: "2026-02-30T12:00:00Z" }],
        },
        publicPaths,
      ),
    /not a calendar-valid UTC instant/,
  );
  assert.throws(
    () =>
      validateExperiments(
        {
          ...ledger,
          experiments: [{ ...base, baseline_end: "2026-08-01" }],
        },
        publicPaths,
      ),
    /baseline_end must be strictly before implemented_at/,
  );
});

test("repository contract has no credential, mutation, messaging, or deployment authority", async () => {
  const [source, workflow, ledger, ignore] = await Promise.all([
    readFile(path.join(scriptDirectory, "observe.mjs"), "utf8"),
    readFile(path.join(repositoryDirectory, ".github/workflows/seo-observe.yml"), "utf8"),
    readFile(path.join(repositoryDirectory, "seo/experiments.json"), "utf8"),
    readFile(path.join(repositoryDirectory, ".gitignore"), "utf8"),
  ]);
  assert.doesNotMatch(source, /process\.env|authorization|bearer|cookie/i);
  assert.doesNotMatch(source, /api\.github\.com\/(?:issues|pulls)|hooks\.slack|vercel\.com\/api/i);
  const policy = assertReadOnlyWorkflowPolicy(workflow);
  assert.deepEqual(policy.workflowPermissions, { contents: "read" });
  assert.deepEqual(policy.jobs, {
    observe: { permissions: { contents: "read" } },
  });
  assert.doesNotMatch(workflow, /pull_request_target/);
  assert.doesNotMatch(workflow, /gh issue|gh pr|vercel deploy|slack/i);
  assert.deepEqual(JSON.parse(ledger), {
    schema_version: "phantom-seo-experiments-v1",
    default_observation_days: 28,
    experiments: [],
  });
  assert.match(ignore, /^seo\/private\/$/m);
  assert.match(ignore, /^seo\/reports\/$/m);
  assert.match(source, /const OBSERVATION_BUDGET_MS = 420_000/);
  assert.match(workflow, /timeout-minutes: 10/);
});

test("workflow policy rejects expanded authority and every secret context syntax", async () => {
  const workflow = await readFile(
    path.join(repositoryDirectory, ".github/workflows/seo-observe.yml"),
    "utf8",
  );
  const unsafeVariants = [
    workflow.replace(
      "permissions:\n  contents: read",
      "permissions: write-all",
    ),
    workflow.replace(
      "permissions:\n  contents: read",
      "permissions: read-all",
    ),
    workflow.replace(
      "    permissions:\n      contents: read",
      "    permissions:\n      contents: write",
    ),
    workflow.replace(
      "    permissions:\n      contents: read",
      "    permissions:\n      contents: read\n      issues: read",
    ),
    workflow.replace(
      "    permissions:\n      contents: read",
      "    permissions:\n      contents: read\n      id-token: write",
    ),
    workflow.replace("    permissions:\n      contents: read\n", ""),
    `${workflow}\n# \${{ secrets.TOKEN }}\n`,
    `${workflow}\n# \${{ secrets['TOKEN'] }}\n`,
    `${workflow}\n# \${{ secrets[\"TOKEN\"] }}\n`,
    `${workflow}\n# \${{ secrets [ 'TOKEN' ] }}\n`,
    `${workflow}\n# \${{ secrets }}\n`,
    `${workflow}\nsecrets: inherit\n`,
  ];
  for (const unsafe of unsafeVariants) {
    assert.throws(() => assertReadOnlyWorkflowPolicy(unsafe));
  }
});

test("non-HTML sitemap entries such as /docs/manifest.json are skipped, not HTML-checked", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      const manifestFindings = report.findings.filter(
        (finding) => finding.route === "/docs/manifest.json",
      );
      assert.deepEqual(manifestFindings, []);
      assert.equal(report.technical.sitemap.route_count, publicPaths.size + 1);
    },
    {
      "/sitemap.xml": (response, origin) => {
        response.setHeader("content-type", "application/xml");
        response.end(
          `<?xml version="1.0"?><urlset>${[...publicPaths, "/docs/manifest.json"]
            .map((route) => `<url><loc>${origin}${route}</loc></url>`)
            .join("")}</urlset>`,
        );
      },
      "/docs/manifest.json": (response) => {
        response.setHeader("content-type", "application/json");
        response.end('{"name":"Phantom docs"}');
      },
    },
  );
});

test("release drift compares the Phantom Secrets SoftwareApplication, not the umbrella app", async () => {
  const umbrella = (response, origin) => {
    response.setHeader("content-type", "text/html");
    response.end(
      html(origin, "/").replace(
        /"softwareVersion":"9\.8\.7"/,
        '"softwareVersion":"3.29.15","codeRepository":"https://github.com/ashlrai/phantom"',
      ),
    );
  };
  const secrets = (version) => (response, origin) => {
    response.setHeader("content-type", "text/html");
    response.end(
      html(origin, "/secrets").replace(
        "</body>",
        `${jsonLd("SoftwareApplication", {
          softwareVersion: version,
          codeRepository: "https://github.com/ashlrai/phantom-secrets",
        })}</body>`,
      ),
    );
  };
  const versionFindings = (report) =>
    report.findings.filter((finding) => finding.code.startsWith("live_release_version"));

  await withFixtureServer(
    async ({ options }) => {
      assert.deepEqual(versionFindings(await observeProduction(options)), []);
    },
    { "/": umbrella, "/secrets": secrets("9.8.7") },
  );
  await withFixtureServer(
    async ({ options }) => {
      const drift = versionFindings(await observeProduction(options));
      assert.equal(drift.length, 1);
      assert.equal(drift[0].code, "live_release_version_drift");
      assert.match(drift[0].message, /0\.0\.1/);
    },
    { "/": umbrella, "/secrets": secrets("0.0.1") },
  );
});
