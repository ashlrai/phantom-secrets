const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { pathToFileURL } = require("node:url");

const webDir = path.resolve(__dirname, "..");
const contract = import(pathToFileURL(path.join(webDir, "scripts/site-preview-contract.mjs")).href);

test("route contract mirrors the host website publisher profile", async () => {
  const { PUBLIC_ROUTE_CONTRACT } = await contract;
  assert.deepEqual(
    PUBLIC_ROUTE_CONTRACT.map(({ route, canonical, marker }) => [route, canonical, marker]),
    [
      ["/", "https://phm.dev", "Work with me"],
      ["/secrets", "https://phm.dev/secrets", "Secrets"],
    ],
  );
});

test("route contract reports each failure instead of passing partial pages", async () => {
  const { PUBLIC_ROUTE_CONTRACT, checkRouteContract } = await contract;
  const [home, secrets] = PUBLIC_ROUTE_CONTRACT;
  const good = '<link rel="canonical" href="https://phm.dev/secrets"/><h1>Phantom Secrets</h1>';
  assert.deepEqual(checkRouteContract(secrets, { status: 200, contentType: "text/html; charset=utf-8", body: good }), []);
  const problems = checkRouteContract(home, { status: 307, contentType: "text/plain", body: "moved" });
  assert.equal(problems.length, 4);
  assert.match(problems.join("\n"), /status 307/);
  assert.match(problems.join("\n"), /Work with me/);
});

test("rendered source pages keep the markers the publisher requires", () => {
  const home = fs.readFileSync(path.join(webDir, "src/components/landing/WorkbenchHero.tsx"), "utf8");
  assert.match(home, /Work with me/);
  const secrets = fs.readFileSync(path.join(webDir, "src/app/secrets/page.tsx"), "utf8");
  assert.match(secrets, /https:\/\/phm\.dev\/secrets/);
});

test("internal link extraction keeps paths and fragments and skips external and asset links", async () => {
  const { internalLinks, fragmentLinks, elementIds } = await contract;
  const html = [
    '<a href="/docs/getting-started#install">a</a>',
    '<a href="/secrets?ref=nav">b</a>',
    '<a href="https://github.com/ashlrai/phantom">c</a>',
    '<a href="//cdn.example">d</a>',
    '<link href="/_next/static/x.css">',
    '<a href="#quickstart">e</a>',
    '<section id="quickstart"></section>',
  ].join("");
  assert.deepEqual(internalLinks(html), ["/docs/getting-started#install", "/secrets"]);
  assert.deepEqual(fragmentLinks(html), ["quickstart"]);
  assert.ok(elementIds(html).has("quickstart"));
});

test("sitemap paths are limited to phm.dev", async () => {
  const { sitemapPaths } = await contract;
  const xml = "<urlset><url><loc>https://phm.dev/</loc></url><url><loc>https://phm.dev/docs/sync</loc></url><url><loc>https://example.com/x</loc></url></urlset>";
  assert.deepEqual(sitemapPaths(xml), ["/", "/docs/sync"]);
});

test("credential scan flags real key shapes and leaked private env values, not placeholders", async () => {
  const { credentialFindings, privateEnvironmentValues } = await contract;
  assert.deepEqual(credentialFindings("Use phm_... or sk-... placeholders; OPENAI_API_KEY=sk-your-key"), []);
  const stripe = ["sk", "live", "a1B2c3D4e5F6g7H8i9J0"].join("_");
  assert.deepEqual(credentialFindings(`key: ${stripe}`), ["Stripe secret or restricted key"]);
  const jwt = (role) => ["eyJhbGciOiJIUzI1NiJ9", Buffer.from(JSON.stringify({ role })).toString("base64url"), "c2lnbmF0dXJlLXNpZ25hdHVyZQ"].join(".");
  assert.deepEqual(credentialFindings(jwt("anon")), []);
  assert.deepEqual(credentialFindings(jwt("service_role")), ["JWT with role service_role"]);
  const env = { SUPABASE_SERVICE_ROLE_KEY: "server-only-value-123", NEXT_PUBLIC_SUPABASE_ANON_KEY: "public-anon-value-123", PORT: "3000" };
  const privateValues = privateEnvironmentValues(env);
  assert.deepEqual(privateValues.map(([name]) => name), ["SUPABASE_SERVICE_ROLE_KEY"]);
  assert.deepEqual(credentialFindings("x server-only-value-123 y", privateValues), ["value of SUPABASE_SERVICE_ROLE_KEY"]);
});

test("the preview build inherits no credentials", async () => {
  const { credentialFreeEnv } = await contract;
  const env = credentialFreeEnv({ PATH: "/bin", HOME: "/h", STRIPE_SECRET_KEY: "x", NEXT_PUBLIC_SUPABASE_URL: "https://x", VERCEL_TOKEN: "y" });
  assert.deepEqual(env, { NEXT_TELEMETRY_DISABLED: "1", PATH: "/bin", HOME: "/h" });
});

test("preview tooling never deploys or promotes", () => {
  const source = fs.readFileSync(path.join(webDir, "scripts/site-preview.mjs"), "utf8");
  assert.doesNotMatch(source, /\bvercel\b(?!.*publisher)|deploy\s*\(|--prod\b|promote\s*\(/i);
  assert.match(source, /-H", "127\.0\.0\.1"/);
  const pkg = JSON.parse(fs.readFileSync(path.join(webDir, "package.json"), "utf8"));
  assert.equal(pkg.scripts["preview:check"], "node scripts/site-preview.mjs check");
  assert.equal(pkg.scripts["preview:verify"], "node scripts/site-preview.mjs verify");
});
