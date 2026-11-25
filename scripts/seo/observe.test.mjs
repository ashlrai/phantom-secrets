import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
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
  readJson,
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

test("the CLI rejects malformed JSON inputs without creating a report or summary", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "phantom-seo-malformed-"));
  try {
    const malformed = path.join(directory, "malformed.json");
    await writeFile(malformed, '{"unfinished":');
    for (const [flag, diagnostic] of [
      ["--experiments", /experiment ledger is not valid JSON/],
      ["--gsc-file", /gsc aggregate input is not valid JSON/],
      ["--ga4-file", /ga4 aggregate input is not valid JSON/],
      ["--ahrefs-file", /ahrefs aggregate input is not valid JSON/],
    ]) {
      const report = path.join(directory, "report.json");
      const summary = path.join(directory, "summary.md");
      const result = spawnSync(process.execPath, [
        path.join(scriptDirectory, "observe.mjs"), flag, malformed,
        "--out", report, "--summary", summary,
      ], { cwd: repositoryDirectory, encoding: "utf8", timeout: 5_000 });
      assert.ifError(result.error);
      assert.equal(result.status, 1);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, diagnostic);
      await assert.rejects(stat(report), { code: "ENOENT" });
      await assert.rejects(stat(summary), { code: "ENOENT" });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
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

test("the CLI reports missing aggregate inputs without an uncaught exception", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "phantom-seo-missing-input-"));
  try {
    for (const kind of ["gsc", "ga4", "ahrefs"]) {
      const output = path.join(directory, `${kind}-report.json`);
      const missing = path.join(directory, `missing-${kind}.json`);
      const result = spawnSync(process.execPath, [
        path.join(scriptDirectory, "observe.mjs"),
        "--experiments", path.join(repositoryDirectory, "seo/experiments.json"),
        `--${kind}-file`, missing,
        "--out", output,
      ], { cwd: repositoryDirectory, encoding: "utf8", timeout: 5_000 });
      assert.ifError(result.error);
      assert.equal(result.status, 1);
      assert.equal(result.signal, null);
      assert.match(result.stderr, new RegExp(`${kind} aggregate input could not be read: ENOENT`));
      assert.ok(result.stderr.includes(missing), "error names the missing file");
      assert.match(result.stderr, /check the path or omit the flag/);
      assert.match(result.stdout, /FAIL/);
      const report = JSON.parse(await readFile(output, "utf8"));
      assert.equal(report.verdict, "FAIL");
      assert.equal(report.findings[0].code, "observer_execution_failed");
      assert.equal(
        report.findings[0].message,
        "Observer failed closed before the public-surface report completed",
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an aggregate input path containing spaces is read and its observation is reported", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "phantom seo spaced "));
  try {
    const folder = path.join(directory, "search console", "july 2026");
    await mkdir(folder, { recursive: true });
    const file = path.join(folder, "gsc final.json");
    const fixture = {
      schema_version: "phantom-seo-gsc-v1",
      period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
      rows: [
        { page_path: "/docs", brand_class: "nonbrand", clicks: 12, impressions: 240, ctr: 0.05, position: 8.4 },
      ],
    };
    await writeFile(file, JSON.stringify(fixture));
    assert.match(file, / /);

    // readJson is the CLI's reader, so this is the same path --gsc-file takes.
    const aggregate = await readJson(file, "gsc aggregate input");
    assert.deepEqual(aggregate, fixture);
    await assert.rejects(
      readJson(path.join(folder, "missing file.json"), "gsc aggregate input"),
      /gsc aggregate input could not be read: ENOENT/,
    );

    await withFixtureServer(async ({ options }) => {
      const report = await observeProduction({
        ...options,
        experiments: { schema_version: "phantom-seo-experiments-v1", default_observation_days: 28, experiments: [] },
        aggregateInputs: { gsc: aggregate },
      });
      assert.equal(report.verdict, "PASS");
      assert.notEqual(report.aggregate_inputs.gsc.state, "not_supplied");
      assert.equal(report.aggregate_inputs.ga4.state, "not_supplied");
      assert.match(renderSummary(report), /GSC: (?!not_supplied)/);
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a missing input file exits unsuccessfully and names the file to fix", async () => {
  const observer = path.join(scriptDirectory, "observe.mjs");
  const directory = await mkdtemp(path.join(tmpdir(), "phantom-seo-missing-input-"));
  try {
    const ledger = path.join(directory, "missing-ledger.json");
    const gsc = path.join(directory, "missing-gsc.json");
    for (const [flags, missing, label] of [
      [["--experiments", ledger], ledger, "experiment ledger"],
      [["--experiments", ledger, "--gsc-file", gsc], ledger, "experiment ledger"],
    ]) {
      const out = path.join(directory, "reports", `${label.replace(/\s/g, "-")}-${flags.length}.json`);
      const result = spawnSync(process.execPath, [observer, ...flags, "--out", out], {
        cwd: repositoryDirectory,
        encoding: "utf8",
        timeout: 5_000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, 1);
      assert.match(result.stderr, new RegExp(`${label} could not be read: ENOENT`));
      assert.ok(result.stderr.includes(missing), "error names the missing file");
      assert.match(result.stderr, /check the path or omit the flag/);
      const report = JSON.parse(await readFile(out, "utf8"));
      assert.equal(report.findings[0].code, "observer_execution_failed");
      assert.deepEqual(report.technical.public_routes, []);
    }

    // A present ledger with a missing aggregate input reports that input.
    const present = path.join(directory, "ledger.json");
    await writeFile(present, JSON.stringify({ schema_version: "phantom-seo-experiments-v1", experiments: [] }));
    const result = spawnSync(process.execPath, [observer, "--experiments", present, "--gsc-file", gsc, "--out", path.join(directory, "gsc.json")], {
      cwd: repositoryDirectory,
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes(gsc), "error names the missing aggregate file");
    assert.match(result.stderr, /gsc aggregate input could not be read: ENOENT/);
    const report = JSON.parse(await readFile(path.join(directory, "gsc.json"), "utf8"));
    assert.equal(report.findings[0].code, "observer_execution_failed");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the CLI reports failure when the output directory cannot be created", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "phantom-seo-output-"));
  try {
    const obstruction = path.join(directory, "not-a-directory");
    await writeFile(obstruction, "unchanged");
    const result = spawnSync(process.execPath, [
      path.join(scriptDirectory, "observe.mjs"),
      "--experiments", path.join(directory, "missing-ledger.json"),
      "--out", path.join(obstruction, "reports", "observation.json"),
      "--summary", path.join(directory, "summary.md"),
    ], { cwd: repositoryDirectory, encoding: "utf8", timeout: 5_000 });

    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /SEO observation could not write its sanitized report:/);
    assert.equal(await readFile(obstruction, "utf8"), "unchanged");
    await assert.rejects(stat(path.join(directory, "summary.md")), { code: "ENOENT" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("HTML entities are decoded exactly once", () => {
  assert.equal(decodeEntities("&amp;&quot;&#39;&lt;&gt;"), "&\"'<>");
  assert.equal(decodeEntities("&amp;lt;script&amp;gt;"), "&lt;script&gt;");
});

test("decimal HTML entities are decoded exactly once", () => {
  assert.equal(decodeEntities("&#65;"), "A");
  assert.equal(decodeEntities("&#233;&#128512;"), "é😀");
  // A decoded "&" must not start a second decode.
  assert.equal(decodeEntities("&#38;#65;"), "&#65;");
  assert.equal(decodeEntities("&#38;amp;"), "&amp;");
  // Out-of-range or surrogate references stay literal.
  assert.equal(decodeEntities("&#0;&#1114112;&#55296;"), "&#0;&#1114112;&#55296;");
});

test("adjacent named and decimal HTML entities decode independently", () => {
  assert.equal(decodeEntities("&lt;&#65;&amp;&#233;&quot;&#128512;&gt;"), '<A&é"😀>');
  assert.equal(decodeEntities("&#38;&amp;lt;&#65;&gt;"), "&&lt;A>");
  assert.equal(decodeEntities("&lt;&#0;&amp;&#55296;&gt;"), "<&#0;&&#55296;>");
});

test("empty HTML produces no structured data or errors offline", () => {
  assert.deepEqual(structuredData(""), { values: [], errors: [] });
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

test("JSON-LD extraction preserves each valid block independently", () => {
  const first = {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: "A & B < C",
    author: { name: "Zoë", sameAs: ["https://example.com/author?a=1&b=2"] },
  };
  const second = [
    { "@type": "SoftwareApplication", name: "Phantom", version: "0.8.7" },
    { "@type": "Thing", description: "Literal &amp; entity" },
  ];
  const third = { "@type": "FAQPage", accepted: true, count: 0, extra: null };
  const html = [
    `<script type="application/ld+json">${JSON.stringify(first)}</script>`,
    '<script type="application/json">{"ignored":true}</script>',
    `<script TYPE="APPLICATION/LD+JSON">${JSON.stringify(second)}</ScRiPt >`,
    `<script type='application/ld+json'>${JSON.stringify(third)}</script>`,
  ].join("\n");

  assert.deepEqual(structuredData(html), { values: [first, second, third], errors: [] });
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

test("exact URL matching rejects a longer URL with the same prefix", () => {
  const expected = "https://phm.dev/llms.txt";
  assert.equal(containsExactUrl(`See ${expected}`, expected), true);
  assert.equal(containsExactUrl(`See ${expected}/extra`, expected), false);
  assert.equal(containsExactUrl(`See ${expected}-backup`, expected), false);
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
          .filter((route) => !route.endsWith(".txt"))
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

test("local redirects are followed within the boundary and limited to two hops", async () => {
  await withFixtureServer(
    async ({ origin, options, requests }) => {
      const requestOptions = { fetchImpl: fetch, networkPolicy: options.networkPolicy, retries: 0 };
      const result = await requestWithinBoundary(`${origin}/start`, requestOptions);
      assert.equal(result.url.href, `${origin}/final`);
      assert.equal(result.status, 200);
      assert.equal(result.headers.get("content-type"), "text/plain");
      assert.equal(result.body, "redirect destination");
      assert.deepEqual(requests, ["/start", "/step", "/final"]);

      requests.length = 0;
      await assert.rejects(requestWithinBoundary(`${origin}/loop`, requestOptions), /too many redirects/);
      assert.deepEqual(requests, ["/loop", "/loop", "/loop"]);

      requests.length = 0;
      await assert.rejects(requestWithinBoundary(`${origin}/missing-location`, requestOptions), /has no location/);
      assert.deepEqual(requests, ["/missing-location"]);
    },
    {
      "/start": (response) => { response.writeHead(301, { location: "/step" }).end(); },
      "/step": (response) => { response.writeHead(302, { location: "final" }).end(); },
      "/final": (response) => { response.writeHead(200, { "content-type": "text/plain" }).end("redirect destination"); },
      "/loop": (response) => { response.writeHead(307, { location: "/loop" }).end(); },
      "/missing-location": (response) => { response.writeHead(302).end(); },
    },
  );
});

test("a local redirect outside the boundary is rejected without fetching its destination", async () => {
  await withFixtureServer(async ({ origin: destination, requests: destinationRequests }) => {
    await withFixtureServer(
      async ({ origin, options, requests }) => {
        await assert.rejects(
          requestWithinBoundary(`${origin}/start`, {
            fetchImpl: fetch,
            networkPolicy: options.networkPolicy,
            retries: 0,
          }),
          /network destination is not allowlisted/,
        );
        assert.deepEqual(requests, ["/start"]);
        assert.deepEqual(destinationRequests, []);
      },
      { "/start": (response) => { response.writeHead(302, { location: `${destination}/outside` }).end(); } },
    );
  });
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

test("unrelated observation fields do not alter the documented report or summary", async () => {
  const origin = "https://example.test";
  const options = {
    siteOrigin: origin,
    githubRepositoryApi: `${origin}/github`,
    networkPolicy: (url) => url.origin === origin,
    now: new Date("2026-09-05T12:00:00Z"),
    fetchImpl: async (url) => {
      if (url.pathname === "/sitemap.xml") {
        return new Response(`<urlset><url><loc>${origin}/docs</loc></url></urlset>`);
      }
      if (url.pathname === "/robots.txt") {
        return new Response(`User-Agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
      }
      if (url.pathname === "/docs") {
        return new Response(html(origin, "/docs"), {
          headers: { "content-type": "text/html" },
        });
      }
      return new Response("not found", { status: 404 });
    },
  };
  const expected = await observeProduction(options);
  assert.equal(expected.verdict, "FAIL");
  assert.ok(expected.counts.fail > 0);
  assert.equal(expected.technical.public_routes.find((page) => page.route === "/docs").title, "/docs — Phantom");

  const actual = await observeProduction({
    ...options,
    annotation: "Unrelated fixture metadata",
    run_number: 42,
    labels: ["regression", "extra-fields"],
    metadata: { reviewed: false, note: null },
    verdict: "PASS",
    counts: { fail: 0, warn: 0 },
    findings: [],
  });

  assert.deepEqual(actual, expected);
  assert.equal(renderSummary(actual), renderSummary(expected));
});

test("an observation preserves Unicode page text across UTF-8 chunk boundaries", async () => {
  const pagePath = "/docs/café-日本語-🔐-e\u0301";
  const encodedPath = encodeURI(pagePath);
  const title = "Café — 日本語 🔐";
  const description = "Protégez vos clés · 安全な秘密 · مرحبًا 🌍";
  const origin = "https://example.test";
  const responses = new Map([
    ["/sitemap.xml", ["application/xml", ["/", "/docs", "/security", pagePath]
      .map((route) => `<loc>${origin}${route}</loc>`).join("")]],
    ["/robots.txt", ["text/plain", `Disallow: /api/\nSitemap: ${origin}/sitemap.xml`]],
    ...["/llms.txt", "/llms-full.txt"].map((route) => [route, ["text/plain",
      `Latest release: \`v9.8.7\`\nhttps://phm.dev/llms-full.txt\nhttps://github.com/ashlrai/phantom-secrets\n${"reference ".repeat(20)}`]]),
    ["/api/v1/health", ["application/json", "{}"]],
    ["/api/v1/ready", ["application/json", "{}"]],
    ["/github", ["application/json", '{"stargazers_count":16,"forks_count":3}']],
    ["/github/releases/latest", ["application/json", '{"tag_name":"v9.8.7","immutable":true}']],
  ]);
  const report = await observeProduction({
    siteOrigin: origin,
    githubRepositoryApi: `${origin}/github`,
    networkPolicy: (url) => url.origin === origin,
    fetchImpl: async (url) => {
      if (responses.has(url.pathname)) {
        const [contentType, body] = responses.get(url.pathname);
        return new Response(body, { headers: { "content-type": contentType } });
      }
      assert.ok(["/", "/docs", "/security", encodedPath].includes(url.pathname));
      const headers = { "content-type": "text/html; charset=utf-8" };
      if (url.pathname === "/") {
        for (const name of ["content-security-policy", "permissions-policy", "referrer-policy",
          "strict-transport-security", "x-content-type-options", "x-frame-options"]) {
          headers[name] = "fixture";
        }
      }
      if (url.pathname === encodedPath) return new Response(html(origin, pagePath), { headers });
      if (url.pathname !== "/docs") return new Response(html(origin, url.pathname), { headers });
      const pageHtml = html(origin, "/docs")
        .replace("/docs — Phantom", title)
        .replace("Description for /docs", description)
        .replace("Page /docs", title);
      const bytes = new TextEncoder().encode(pageHtml);
      // Split every multibyte character to exercise the streaming decoder.
      let offset = 0;
      return new Response(new ReadableStream({
        pull(controller) {
          if (offset === bytes.length) controller.close();
          else {
            controller.enqueue(bytes.subarray(offset, offset + 1));
            offset += 1;
          }
        },
      }), { headers });
    },
  });
  const page = report.technical.public_routes.find(({ route }) => route === "/docs");
  assert.equal(report.verdict, "PASS");
  assert.equal(page.title, title);
  assert.equal(page.description, description);
  assert.equal(page.h1_count, 1);
  const unicodePage = report.technical.public_routes.find(({ route }) => route === encodedPath);
  assert.ok(unicodePage, "the non-ASCII page is retained in the observation");
  assert.equal(unicodePage.status, 200);
  assert.equal(decodeURI(unicodePage.route), pagePath);
  assert.equal(unicodePage.canonical, `${origin}${encodedPath}`);
  assert.equal(unicodePage.title, `${pagePath} — Phantom`);
  const serializedPage = JSON.parse(JSON.stringify(unicodePage));
  assert.equal(decodeURI(serializedPage.route), pagePath);
  assert.ok(!JSON.stringify(report).includes("\uFFFD"), "report has no replacement characters");
});

test("observing identical input twice renders equivalent summaries", async () => {
  const ledger = {
    schema_version: "phantom-seo-experiments-v1",
    default_observation_days: 28,
    experiments: [],
  };
  const observeTwice = async ({ options }) => {
    const first = renderSummary(await observeProduction({ ...options, experiments: ledger }));
    const second = renderSummary(await observeProduction({ ...options, experiments: ledger }));
    return { first, second };
  };
  await withFixtureServer(async (context) => {
    const { first, second } = await observeTwice(context);
    assert.ok(first.length > 0);
    assert.equal(first, second);
  });
  // Findings must also render in a stable order, not just a clean pass.
  await withFixtureServer(
    async (context) => {
      const { first, second } = await observeTwice(context);
      assert.match(first, /\*\*FAIL title_missing\*\* \(\/docs\)/);
      assert.equal(first, second);
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/docs").replace(/<title>[^<]*<\/title>/, ""));
      },
    },
  );
});

test("out-of-order route observations retain deterministic report and finding order", async () => {
  const origin = "https://example.test";
  const options = {
    siteOrigin: origin,
    githubRepositoryApi: `${origin}/github`,
    networkPolicy: (url) => url.origin === origin,
    now: new Date("2026-09-05T12:00:00Z"),
  };
  const fixtures = {
    "/sitemap.xml": [...publicPaths].filter((route) => !route.endsWith(".txt"))
      .map((route) => `<loc>${origin}${route}</loc>`).join(""),
    "/robots.txt": `User-Agent: *\nAllow: /\nDisallow: /api/\nSitemap: ${origin}/sitemap.xml\n`,
    "/llms.txt": `# Phantom\nLatest release: \`v9.8.7\`.\nhttps://phm.dev/llms-full.txt\nhttps://github.com/ashlrai/phantom-secrets\n${"boundary ".repeat(20)}`,
    "/llms-full.txt": `# Phantom full reference\n${"bounded evidence ".repeat(20)}`,
    "/api/v1/health": '{"status":"ok"}',
    "/api/v1/ready": '{"status":"ok"}',
    "/github": '{"stargazers_count":16,"forks_count":3}',
    "/github/releases/latest": '{"tag_name":"v9.8.7","published_at":"2026-09-05T00:00:00Z","immutable":true,"draft":false,"prerelease":false}',
  };
  const fixtureResponse = (route) => new Response(fixtures[route] ?? html(origin, route), {
    headers: {
      "content-type": route.endsWith(".txt") ? "text/plain" : "text/html",
      "content-security-policy": "default-src 'self'",
      "permissions-policy": "camera=()",
      "referrer-policy": "strict-origin-when-cross-origin",
      "strict-transport-security": "max-age=63072000",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
  const observeInOrder = async (arrivalOrder) => {
    const arrivals = [];
    const gates = new Map(arrivalOrder.map((route) => {
      let release;
      const promise = new Promise((resolve) => { release = resolve; });
      return [route, { promise, release }];
    }));
    gates.get(arrivalOrder[0]).release();
    const report = await observeProduction({
      ...options,
      fetchImpl: async (url) => {
        const gate = gates.get(url.pathname);
        if (!gate) return fixtureResponse(url.pathname);
        await gate.promise;
        arrivals.push(url.pathname);
        const next = arrivalOrder[arrivals.length];
        if (next) gates.get(next).release();
        // Supply identical findings in different arrival orders, without timers.
        const page = html(origin, url.pathname)
          .replace(/<title>[^<]*<\/title>/, "")
          .replace(/<meta name="description"[^>]*>/, "");
        return new Response(page, { headers: { "content-type": "text/html" } });
      },
    });
    assert.deepEqual(arrivals, arrivalOrder);
    return report;
  };

  const first = await observeInOrder(["/security", "/docs", "/secrets"]);
  const second = await observeInOrder(["/secrets", "/security", "/docs"]);
  assert.deepEqual(first, second);
  assert.deepEqual(first.technical.public_routes.map(({ route }) => route), [
    "/", "/docs", "/docs/guide", "/secrets", "/security", "/llms.txt", "/llms-full.txt",
  ]);
  // The documented finding order is severity, code, route, then message.
  assert.deepEqual(first.findings, [
    ...["/docs", "/secrets", "/security"].map((route) => ({
      severity: "fail", code: "description_missing", message: "Meta description is missing", route,
    })),
    ...["/docs", "/secrets", "/security"].map((route) => ({
      severity: "fail", code: "title_missing", message: "Page title is missing", route,
    })),
  ]);
  assert.equal(first.verdict, "FAIL");
  assert.deepEqual(first.counts, { fail: 6, warn: 0 });
  assert.equal(renderSummary(first), renderSummary(second));
});

test("experiments supplied out of chronological order retain ledger order", () => {
  const ledger = {
    schema_version: "phantom-seo-experiments-v1",
    default_observation_days: 28,
    experiments: [
      ["middle", "2026-08-01T00:00:00Z", "2026-08-29T00:00:00Z"],
      ["latest", "2026-08-20T00:00:00Z", "2026-09-17T00:00:00Z"],
      ["earliest", "2026-07-29T00:00:00Z", "2026-08-26T00:00:00Z"],
    ].map(([id, implemented_at, not_before]) => ({
      id,
      hypothesis: "A direct answer improves nonbrand impressions.",
      primary_metric: "gsc_nonbrand_impressions",
      target_routes: ["/docs"],
      control_routes: ["/security"],
      status: "observing",
      baseline_start: "2026-07-01",
      baseline_end: "2026-07-28",
      implementation_sha: "a".repeat(40),
      deployment_id: `dpl_${"B".repeat(24)}`,
      implemented_at,
      not_before,
      decision_rule: "Review finalized page evidence against the control cohort.",
      lesson: null,
    })),
  };
  const before = structuredClone(ledger);
  const validated = validateExperiments(ledger, publicPaths, new Date("2026-09-05T12:00:00Z"));
  assert.deepEqual(validated.experiments, before.experiments.map((experiment) => ({
    ...experiment,
    observed_status: experiment.id === "latest" ? "observing" : "ready_for_review",
  })));
  assert.deepEqual(ledger, before);
});

test("a multi-page sitemap produces exactly one observation per route", async () => {
  await withFixtureServer(async ({ options }) => {
    const report = await observeProduction(options);
    const pages = report.technical.public_routes;
    assert.deepEqual(pages.map((page) => page.route).sort(), [...publicPaths].sort());
    const routes = pages.map((page) => page.route);
    assert.equal(new Set(routes).size, routes.length);
    for (const route of ["/", "/docs", "/docs/guide", "/security", "/secrets"]) {
      const page = pages.find((entry) => entry.route === route);
      const expectedTitle = html(options.siteOrigin, route).match(/<title>([^<]*)<\/title>/)[1];
      assert.equal(page.status, 200);
      assert.equal(page.title, expectedTitle);
    }
  });
});

test("two distinct page observations keep their identities in saved output and summary", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "phantom-seo-page-identity-"));
  try {
    const origin = "https://example.test";
    const fixtures = {
      "/sitemap.xml": [...publicPaths].filter((route) => !route.endsWith(".txt")).map((route) => `<loc>${origin}${route}</loc>`).join(""),
      "/robots.txt": `User-Agent: *\nAllow: /\nDisallow: /api/\nSitemap: ${origin}/sitemap.xml\n`,
      "/docs": html(origin, "/docs").replace('<meta name="description" content="Description for /docs">', ""),
      "/security": html(origin, "/security").replace("<h1>Page /security</h1>", ""),
      "/llms.txt": `Latest release: \`v9.8.7\`. https://phm.dev/llms-full.txt https://github.com/ashlrai/phantom-secrets ${"boundary ".repeat(20)}`,
      "/llms-full.txt": "bounded evidence ".repeat(20),
      "/api/v1/health": '{"status":"ok"}',
      "/api/v1/ready": '{"status":"ok"}',
      "/github": '{"stargazers_count":16,"forks_count":3}',
      "/github/releases/latest": '{"tag_name":"v9.8.7","immutable":true,"draft":false,"prerelease":false}',
    };
    const report = await observeProduction({
      siteOrigin: origin,
      githubRepositoryApi: `${origin}/github`,
      networkPolicy: (url) => url.origin === origin,
      fetchImpl: async (url) => {
        assert.ok(Object.hasOwn(fixtures, url.pathname) || publicPaths.has(url.pathname));
        return new Response(fixtures[url.pathname] ?? html(origin, url.pathname), {
          headers: {
            "content-type": url.pathname.endsWith(".txt") ? "text/plain" : "text/html",
            "content-security-policy": "default-src 'self'",
            "permissions-policy": "camera=()",
            "referrer-policy": "strict-origin-when-cross-origin",
            "strict-transport-security": "max-age=63072000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
          },
        });
      },
    });
    const output = path.join(directory, "report.json");
    await writePrivateReport(output, report);
    const saved = JSON.parse(await readFile(output, "utf8"));
    assert.deepEqual(saved, report);
    assert.equal(saved.verdict, "FAIL");
    assert.deepEqual(saved.counts, { fail: 2, warn: 0 });
    assert.deepEqual(
      saved.technical.public_routes
        .filter(({ route }) => ["/docs", "/security"].includes(route))
        .map(({ route, status, title, description, canonical, h1_count }) => ({
          route, status, title, description, canonical, h1_count,
        })),
      [
        { route: "/docs", status: 200, title: "/docs — Phantom", description: null,
          canonical: `${origin}/docs`, h1_count: 1 },
        { route: "/security", status: 200, title: "/security — Phantom",
          description: "Description for /security", canonical: `${origin}/security`, h1_count: 0 },
      ],
    );
    assert.deepEqual(saved.findings, [
      { severity: "fail", code: "description_missing", message: "Meta description is missing", route: "/docs" },
      { severity: "fail", code: "h1_count", message: "Expected one h1; observed 0", route: "/security" },
    ]);
    const summary = renderSummary(saved);
    assert.match(summary, /\*\*FAIL description_missing\*\* \(\/docs\): Meta description is missing/);
    assert.match(summary, /\*\*FAIL h1_count\*\* \(\/security\): Expected one h1; observed 0/);
    assert.doesNotMatch(summary, /description_missing\*\* \(\/security\)|h1_count\*\* \(\/docs\)/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("empty aggregate observation inputs remain empty", async () => {
  const period = { start: "2026-07-01", end: "2026-07-28", data_state: "final" };
  const aggregateInputs = Object.fromEntries(
    ["gsc", "ga4", "ahrefs"].map((kind) => [kind, {
      schema_version: `phantom-seo-${kind}-v1`,
      period,
      rows: [],
    }]),
  );
  for (const [kind, input] of Object.entries(aggregateInputs)) {
    assert.deepEqual(validateAggregateInput(kind, input, publicPaths, new Date("2026-09-05T12:00:00Z")), {
      state: "supplied",
      ...input,
      ...(kind === "ga4" ? { suppressed_rows: 0 } : {}),
    });
  }

  await withFixtureServer(async ({ options }) => {
    const report = await observeProduction({ ...options, aggregateInputs });
    assert.equal(report.verdict, "PASS");
    assert.deepEqual(report.counts, { fail: 0, warn: 0 });
    assert.deepEqual(report.findings, []);
    const summary = renderSummary(report);
    for (const kind of ["gsc", "ga4", "ahrefs"]) {
      const observations = report.aggregate_inputs[kind];
      assert.equal(observations.state, "supplied");
      assert.deepEqual(observations.rows, []);
      assert.equal(observations.rows.length, 0);
      assert.match(summary, new RegExp(`- ${kind.toUpperCase()}: supplied`));
    }
    assert.equal(report.aggregate_inputs.ga4.suppressed_rows, 0);
    assert.match(summary, /Findings: 0 failures and 0 warnings\./);
  });
});

test("an observation with no experiments or aggregate inputs reports none and invents nothing", async () => {
  const emptyLedger = {
    schema_version: "phantom-seo-experiments-v1",
    default_observation_days: 28,
    experiments: [],
  };
  assert.deepEqual(
    validateExperiments(emptyLedger, publicPaths, new Date("2026-09-05T12:00:00Z")),
    emptyLedger,
  );

  await withFixtureServer(async ({ options }) => {
    // No experiments and no aggregateInputs options: every default must be empty.
    const report = await observeProduction(options);
    assert.deepEqual(report.experiments, emptyLedger);
    assert.deepEqual(report.aggregate_inputs, {
      gsc: { state: "not_supplied" },
      ga4: { state: "not_supplied" },
      ahrefs: { state: "not_supplied" },
    });
    assert.equal(report.verdict, "PASS");
    assert.deepEqual(report.findings, []);
    const summary = renderSummary(report);
    assert.match(summary, /No checked-in experiments are active\./);
    assert.match(summary, /No failures or warnings\./);
    assert.match(summary, /- GSC: not_supplied/);
  });
});

test("empty input yields the documented defaults: empty ledger, not-supplied aggregates, empty rows", async () => {
  // With no ledger or aggregate files the report carries an empty ledger and
  // not_supplied for gsc, ga4, and ahrefs.
  await withFixtureServer(async ({ options }) => {
    const report = await observeProduction(options);
    assert.deepEqual(report.experiments, {
      schema_version: "phantom-seo-experiments-v1",
      default_observation_days: 28,
      experiments: [],
    });
    assert.deepEqual(report.aggregate_inputs, {
      gsc: { state: "not_supplied" },
      ga4: { state: "not_supplied" },
      ahrefs: { state: "not_supplied" },
    });
    // Empty-but-present aggregate files are supplied, not "not_supplied".
    const emptyAggregates = await observeProduction({
      ...options,
      aggregateInputs: {
        gsc: {
          schema_version: "phantom-seo-gsc-v1",
          period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
          rows: [],
        },
      },
    });
    assert.equal(emptyAggregates.aggregate_inputs.gsc.state, "supplied");
    assert.deepEqual(emptyAggregates.aggregate_inputs.gsc.rows, []);
    assert.deepEqual(emptyAggregates.aggregate_inputs.ga4, { state: "not_supplied" });
    assert.deepEqual(emptyAggregates.aggregate_inputs.ahrefs, { state: "not_supplied" });
  });
  const ledger = validateExperiments(
    {
      schema_version: "phantom-seo-experiments-v1",
      default_observation_days: 28,
      experiments: [],
    },
    publicPaths,
  );
  assert.deepEqual(ledger.experiments, []);
  const ga4 = validateAggregateInput(
    "ga4",
    {
      schema_version: "phantom-seo-ga4-v1",
      period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
      rows: [],
    },
    publicPaths,
  );
  assert.deepEqual(ga4.rows, []);
  assert.equal(ga4.suppressed_rows, 0);
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

test("repeated identical observations produce identical report and summary output", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const outputs = [];
      for (let run = 0; run < 3; run += 1) {
        const report = await observeProduction(options);
        assert.equal(report.verdict, "FAIL");
        assert.ok(report.findings.length > 0);
        outputs.push({ report: JSON.stringify(report), summary: renderSummary(report) });
      }
      assert.deepEqual(outputs[1], outputs[0]);
      assert.deepEqual(outputs[2], outputs[0]);
    },
    { "/docs": (response) => { response.statusCode = 404; response.end("not found"); } },
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

test("a page with an empty title is observed as empty and fails as a missing title", async () => {
  for (const emptyTitle of ["<title></title>", "<title>   \n\t </title>", "<title/>"]) {
    await withFixtureServer(
      async ({ options }) => {
        const report = await observeProduction(options);
        const page = report.technical.public_routes.find((entry) => entry.route === "/docs");
        assert.equal(page.status, 200);
        assert.ok(page.title === "" || page.title === null, "title is reported as empty, not text");
        assert.ok(!page.title, "title is falsy");
        assert.equal(report.verdict, "FAIL");
        assert.deepEqual(report.counts, { fail: 1, warn: 0 });
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
          response.end(html(origin, "/docs").replace("<title>/docs — Phantom</title>", emptyTitle));
        },
      },
    );
  }
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

test("a page without any h1 produces a single h1-count failure", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      assert.equal(report.verdict, "FAIL");
      assert.equal(report.findings.length, 1);
      assert.deepEqual(report.counts, { fail: 1, warn: 0 });
      assert.equal(
        report.technical.public_routes.find((page) => page.route === "/docs").h1_count,
        0,
      );
      assert.deepEqual(report.findings, [
        {
          severity: "fail",
          code: "h1_count",
          message: "Expected one h1; observed 0",
          route: "/docs",
        },
      ]);
      const summary = renderSummary(report);
      assert.match(summary, /Findings: 1 failures and 0 warnings\./);
      assert.match(summary, /\*\*FAIL h1_count\*\* \(\/docs\): Expected one h1; observed 0/);
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html");
        response.end(html(origin, "/docs").replace("<h1>Page /docs</h1>", ""));
      },
    },
  );
});

test("the job summary handles an empty results list", () => {
  const summary = renderSummary({
    verdict: "PASS",
    captured_at: "2026-09-05T12:00:00.000Z",
    counts: { fail: 0, warn: 0 },
    technical: { sitemap: { route_count: 0 }, public_routes: [] },
    aggregate_inputs: {
      gsc: { state: "not_supplied" },
      ga4: { state: "not_supplied" },
      ahrefs: { state: "not_supplied" },
    },
    experiments: { experiments: [] },
    findings: [],
  });

  assert.match(summary, /Observed 0 canonical public routes/);
  assert.match(summary, /Findings: 0 failures and 0 warnings\./);
  assert.match(summary, /No failures or warnings\./);
  assert.doesNotMatch(summary, /TRUNCATED/);
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

test("HTML route records distinguish missing and empty metadata", async () => {
  for (const [head, expectedTitle, expectedDescription] of [
    ["", null, null],
    ['<title>  </title><meta name="description" content="  ">', "", ""],
    ['<title></title><meta name="description" content="">', "", null],
  ]) {
    await withFixtureServer(
      async ({ options }) => {
        const report = await observeProduction(options);
        const route = report.technical.public_routes.find((entry) => entry.route === "/security");
        assert.deepEqual(route, {
          route: "/security",
          status: 200,
          content_type: "text/html",
          title: expectedTitle,
          description: expectedDescription,
          canonical: null,
          h1_count: 1,
          structured_data_types: [],
        });
        assert.deepEqual(
          report.findings.filter((finding) => finding.route === "/security").map((finding) => finding.code),
          ["canonical_count", "description_missing", "title_missing"],
        );
        assert.equal(report.verdict, "FAIL");
      },
      {
        "/security": (response) => {
          response.setHeader("content-type", "text/html");
          response.end(`<!doctype html><html><head>${head}</head><body><h1>Security</h1></body></html>`);
        },
      },
    );
  }
});

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

test("a page without JSON-LD reports empty structured data, not an error", async () => {
  // The page loads other scripts (a deferred src, an inline module, and a
  // text/plain block holding JSON-lookalike content) but no ld+json, so
  // extraction returns empty arrays rather than flagging anything.
  const page = (origin) =>
    `<!doctype html><html><head><title>/about — Phantom</title>` +
    `<meta name="description" content="Description for /about">` +
    `<link rel="canonical" href="${origin}/about">` +
    `<script src="${origin}/app.js" defer></script>` +
    `<script type="module">navigator.sendBeacon("/ping")</script>` +
    `<script type="text/plain">{"not":"json-ld"}</script>` +
    `</head><body><h1>Page /about</h1></body></html>`;
  assert.deepEqual(structuredData(page("https://phm.dev")), { values: [], errors: [] });
  await withFixtureServer(
    async ({ origin, options }) => {
      const report = await observeProduction(options);
      const route = report.technical.public_routes.find((entry) => entry.route === "/about");
      assert.ok(route, "the no-JSON-LD page is observed through the sitemap");
      assert.equal(route.status, 200);
      assert.equal(route.canonical, `${origin}/about`);
      assert.deepEqual(route.structured_data_types, []);
      assert.deepEqual(
        report.findings.filter((finding) => finding.route === "/about"),
        [],
      );
      assert.equal(report.technical.sitemap.route_count, publicPaths.size + 1);
      assert.equal(report.verdict, "PASS");
    },
    {
      "/sitemap.xml": (response, origin) => {
        response.setHeader("content-type", "application/xml");
        response.end(
          `<?xml version="1.0"?><urlset>${[...publicPaths, "/about"]
            .map((route) => `<url><loc>${origin}${route}</loc></url>`)
            .join("")}</urlset>`,
        );
      },
      "/about": (response, origin) => {
        response.setHeader("content-type", "text/html; charset=utf-8");
        response.end(page(origin));
      },
    },
  );
});

test("a page with one malformed and one valid JSON-LD block keeps both", async () => {
  // The malformed block sits first so extraction must continue past its error:
  // the valid value is still returned and the bad block is still reported.
  const valid = {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: "Mixed JSON-LD blocks",
  };
  const page = (origin) =>
    `<!doctype html><html><head><title>/mixed — Phantom</title>` +
    `<meta name="description" content="Description for /mixed">` +
    `<link rel="canonical" href="${origin}/mixed">` +
    `<script type="application/ld+json">{broken</script>` +
    `<script type="application/ld+json">${JSON.stringify(valid)}</script>` +
    `</head><body><h1>Page /mixed</h1></body></html>`;
  assert.deepEqual(structuredData(page("https://phm.dev")), {
    values: [valid],
    errors: ["invalid_json_ld"],
  });
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      const route = report.technical.public_routes.find((entry) => entry.route === "/mixed");
      assert.ok(route, "the mixed-JSON-LD page is observed through the sitemap");
      assert.equal(route.status, 200);
      assert.deepEqual(route.structured_data_types, ["Article"]);
      assert.deepEqual(report.findings, [
        {
          severity: "fail",
          code: "structured_data_invalid",
          message: "Page contains invalid JSON-LD",
          route: "/mixed",
        },
      ]);
      assert.deepEqual(report.counts, { fail: 1, warn: 0 });
      assert.equal(report.verdict, "FAIL");
    },
    {
      "/sitemap.xml": (response, origin) => {
        response.setHeader("content-type", "application/xml");
        response.end(
          `<?xml version="1.0"?><urlset>${[...publicPaths, "/mixed"]
            .map((route) => `<url><loc>${origin}${route}</loc></url>`)
            .join("")}</urlset>`,
        );
      },
      "/mixed": (response, origin) => {
        response.setHeader("content-type", "text/html; charset=utf-8");
        response.end(page(origin));
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

test("a sitemapped redirect is checked against the original route's canonical", async () => {
  await withFixtureServer(
    async ({ options, requests }) => {
      const report = await observeProduction(options);
      assert.equal(report.verdict, "FAIL");
      assert.ok(requests.includes("/docs"));
      assert.ok(requests.filter((route) => route === "/docs/guide").length >= 2);
      assert.ok(report.findings.some((finding) =>
        finding.code === "canonical_mismatch" && finding.route === "/docs"));
    },
    {
      "/docs": (response) => { response.writeHead(302, { location: "/docs/guide" }).end(); },
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

test("aggregate inputs reject empty input with an actionable error", () => {
  for (const kind of ["gsc", "ga4", "ahrefs"]) {
    assert.throws(
      () => validateAggregateInput(kind, {}, publicPaths),
      { message: new RegExp(`^${kind} input is missing schema_version$`) },
    );
    for (const value of [null, undefined]) {
      assert.throws(
        () => validateAggregateInput(kind, value, publicPaths),
        { message: new RegExp(`^${kind} input must be an object$`) },
      );
    }
  }
});

test("aggregate observation arrays reject null entries without network requests", () => {
  for (const kind of ["gsc", "ga4", "ahrefs"]) {
    const value = {
      schema_version: `phantom-seo-${kind}-v1`,
      period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
      rows: [null],
    };
    assert.throws(
      () => validateAggregateInput(kind, value, publicPaths, new Date("2026-09-05T00:00:00Z")),
      { name: "Error", message: `${kind} input.rows[0] must be an object` },
    );
  }
});

test("aggregate observation arrays reject string entries without network requests", () => {
  for (const kind of ["gsc", "ga4", "ahrefs"]) {
    const value = {
      schema_version: `phantom-seo-${kind}-v1`,
      period: { start: "2026-07-01", end: "2026-07-28", data_state: "final" },
      rows: ["not an observation object"],
    };
    assert.throws(
      () => validateAggregateInput(kind, value, publicPaths, new Date("2026-09-05T00:00:00Z")),
      { name: "Error", message: `${kind} input.rows[0] must be an object` },
    );
  }
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

test("aggregate observations keep page paths containing spaces associated with their metrics", () => {
  const pagePath = "/docs/agent setup guide";
  const allowedPaths = new Set([...publicPaths, pagePath]);
  const period = { start: "2026-07-01", end: "2026-07-28", data_state: "final" };
  const now = new Date("2026-09-05T12:00:00Z");
  const cases = [
    ["gsc", { page_path: pagePath, brand_class: "nonbrand", clicks: 12, impressions: 240, ctr: 0.05, position: 8.4 }, { clicks: 2 }],
    ["ga4", { page_path: pagePath, referral_class: "other", sessions: 20, engaged_sessions: 5, engagement_rate: 0.25, key_events: 1 }, { sessions: 10, engagement_rate: 0.5 }],
    ["ahrefs", { page_path: pagePath, estimated_organic_traffic: 42, referring_domains: 7 }, { estimated_organic_traffic: 12 }],
  ];
  for (const [kind, observation, otherMetrics] of cases) {
    const otherObservation = { ...observation, ...otherMetrics, page_path: "/docs" };
    const result = validateAggregateInput(kind, {
      schema_version: `phantom-seo-${kind}-v1`,
      period,
      rows: [observation, otherObservation],
    }, allowedPaths, now);
    assert.equal(result.state, "supplied");
    assert.deepEqual(result.rows, [otherObservation, observation], `${kind} sorts whole observations without changing their paths or metrics`);
    const serialized = JSON.parse(JSON.stringify(result));
    assert.deepEqual(serialized.rows.find((row) => row.page_path === pagePath), observation, `${kind} preserves the spaced path in report JSON`);
  }
});

test("aggregate observations preserve case-distinct paths in locale comparison order without network requests", () => {
  const allowedPaths = new Set(["/docs", "/Docs"]);
  const period = { start: "2026-07-01", end: "2026-07-28", data_state: "final" };
  const now = new Date("2026-09-05T12:00:00Z");
  const cases = [
    ["gsc", { brand_class: "nonbrand", clicks: 12, impressions: 240, ctr: 0.05, position: 8.4 }, { clicks: 2 }],
    ["ga4", { referral_class: "other", sessions: 20, engaged_sessions: 5, engagement_rate: 0.25, key_events: 1 }, { sessions: 10, engagement_rate: 0.5 }],
    ["ahrefs", { estimated_organic_traffic: 42, referring_domains: 7 }, { estimated_organic_traffic: 12 }],
  ];
  for (const [kind, metrics, otherMetrics] of cases) {
    const lowercase = { page_path: "/docs", ...metrics };
    const uppercase = { page_path: "/Docs", ...metrics, ...otherMetrics };
    for (const rows of [[uppercase, lowercase], [lowercase, uppercase]]) {
      const result = validateAggregateInput(kind, {
        schema_version: `phantom-seo-${kind}-v1`,
        period,
        rows,
      }, allowedPaths, now);
      assert.equal(result.state, "supplied");
      assert.deepEqual(result.rows, [lowercase, uppercase], `${kind} compares path case and preserves each observation's metrics`);
      assert.deepEqual(JSON.parse(JSON.stringify(result)).rows, [lowercase, uppercase], `${kind} preserves both path spellings in report JSON`);
    }
  }
});

test("duplicate aggregate records are retained, with GA4 suppression applied per row", () => {
  const period = { start: "2026-07-01", end: "2026-07-28", data_state: "final" };
  const now = new Date("2026-09-05T12:00:00Z");
  const cases = [
    ["gsc", { page_path: "/docs", brand_class: "nonbrand", clicks: 2, impressions: 10, ctr: 0.2, position: 4 }],
    ["ga4", { page_path: "/docs", referral_class: "other", sessions: 10, engaged_sessions: 5, engagement_rate: 0.5, key_events: 1 }],
    ["ahrefs", { page_path: "/docs", estimated_organic_traffic: 12, referring_domains: 3 }],
  ];
  for (const [kind, row] of cases) {
    const small = kind === "ga4" ? { ...row, sessions: 9 } : null;
    const result = validateAggregateInput(kind, {
      schema_version: `phantom-seo-${kind}-v1`,
      period,
      rows: [row, { ...row }, ...(small ? [small, { ...small }] : [])],
    }, publicPaths, now);
    assert.deepEqual(result.rows, [row, row], `${kind} retains both duplicate records`);
    if (kind === "ga4") assert.equal(result.suppressed_rows, 2);
  }
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


test("observed titles preserve Unicode exactly", async () => {
  const title = "Café — 東京 🔐 e\u0301";
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      const page = report.technical.public_routes.find((entry) => entry.route === "/docs");
      assert.ok(page, "the docs route must be observed");
      assert.equal(page.title, title);
      assert.equal(report.verdict, "PASS");
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html; charset=utf-8");
        response.end(html(origin, "/docs").replace(
          "<title>/docs — Phantom</title>",
          `<title>${title}</title>`,
        ));
      },
    },
  );
});

test("observed titles preserve punctuation exactly", async () => {
  const title = "Phantom: API keys, secrets & privacy - what's next?! (v0.8.9) [guide]";
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      const page = report.technical.public_routes.find((entry) => entry.route === "/docs");
      assert.ok(page, "the docs route must be observed");
      assert.equal(page.title, title);
      assert.equal(report.verdict, "PASS");
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html; charset=utf-8");
        response.end(html(origin, "/docs").replace(
          /<title>[^<]*<\/title>/,
          `<title>${title}</title>`,
        ));
      },
    },
  );
});

test("observed titles decode supported HTML entities exactly once", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      const page = report.technical.public_routes.find((entry) => entry.route === "/docs");
      assert.ok(page, "the docs route must be observed");
      assert.equal(page.title, `Phantom & "Docs" 'Guide' <API> &lt;literal&gt;`);
    },
    {
      "/docs": (response, origin) => {
        response.setHeader("content-type", "text/html; charset=utf-8");
        response.end(html(origin, "/docs").replace(
          "<title>/docs — Phantom</title>",
          "<title>Phantom &amp; &quot;Docs&quot; &#39;Guide&#39; &lt;API&gt; &amp;lt;literal&amp;gt;</title>",
        ));
      },
    },
  );
});

const unicodeTitles = new Map([
  ["/docs", "Phantom — ドキュメント 🔐 Ünïcödé"],
  ["/security", "Sécurité ‑ مرحبا بالعالم 安全"],
]);

test("Unicode page titles are observed intact and the summary keeps them", async () => {
  await withFixtureServer(
    async ({ options }) => {
      const report = await observeProduction(options);
      for (const [route, title] of unicodeTitles) {
        assert.equal(report.technical.public_routes.find((page) => page.route === route).title, title);
      }
      assert.deepEqual(report.findings, []);

      // The summary prints titles only inside finding messages, so carry the
      // observed titles through one and check they survive byte-for-byte.
      const message = [...unicodeTitles.values()].join(" | ");
      const summary = renderSummary({
        ...report,
        verdict: "WARN",
        counts: { fail: 0, warn: 1 },
        findings: [{ severity: "warn", code: "title_check", message, route: "/docs" }],
      });
      assert.ok(summary.includes(`**WARN title_check** (/docs): ${message}`));
      assert.ok(!summary.includes("�"), "the summary must not contain replacement characters");
    },
    Object.fromEntries(
      [...unicodeTitles].map(([route, title]) => [
        route,
        (response, origin) => {
          response.setHeader("content-type", "text/html; charset=utf-8");
          response.end(html(origin, route).replace(`<title>${route} — Phantom</title>`, `<title>${title}</title>`));
        },
      ]),
    ),
  );
});

test("the summary truncates long Unicode findings on a character boundary", () => {
  const title = "安全🔐".repeat(2_000);
  const summary = renderSummary({
    verdict: "FAIL",
    captured_at: "2026-01-01T00:00:00.000Z",
    counts: { fail: 1, warn: 0 },
    technical: { sitemap: { route_count: 1 } },
    aggregate_inputs: { gsc: { state: "absent" }, ga4: { state: "absent" }, ahrefs: { state: "absent" } },
    experiments: { experiments: [] },
    findings: [{ severity: "fail", code: "title_long", message: title, route: "/docs" }],
  });
  assert.ok(!summary.includes("�"));
  assert.ok(Buffer.byteLength(summary, "utf8") <= JOB_SUMMARY_MAX_BYTES);
  assert.match(summary, /\*\*FAIL title_long\*\* \(\/docs\): (安全🔐)+…/u);
});
