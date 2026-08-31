const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webDir = path.resolve(__dirname, "..");

function filesUnder(relativeDirectory, acceptedExtensions) {
  const absoluteDirectory = path.join(webDir, relativeDirectory);
  return fs.readdirSync(absoluteDirectory, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) return filesUnder(relativePath, acceptedExtensions);
    return acceptedExtensions.includes(path.extname(entry.name)) ? [relativePath] : [];
  });
}

const claimPaths = [
  "src/app/layout.tsx",
  "src/app/manifest.ts",
  "src/app/pricing/page.tsx",
  "src/app/sitemap.ts",
  ...filesUnder("src/components/landing", [".tsx"]),
  ...filesUnder("public", [".json", ".txt"]),
];

function read(relativePath) {
  return fs.readFileSync(path.join(webDir, relativePath), "utf8");
}

const claims = Object.fromEntries(
  claimPaths.map((relativePath) => [relativePath, read(relativePath)]),
);
const allClaims = Object.values(claims).join("\n");

test("public surfaces reject previously audited absolute claims", () => {
  for (const forbidden of [
    /backed up automatically/i,
    /zero data sent/i,
    /zero exposure/i,
    /about 0\.5\s*ms/i,
    /not measurable in practice/i,
    /phm_ tokens are session-scoped placeholders/i,
    /blocks any commit containing an unprotected secret/i,
    /real keys never leave your machine/i,
    /no plaintext ever touches disk/i,
    /without ever seeing the values/i,
    /AI sees only the phantoms/i,
    /MCP tools \(\d+ total\)/i,
    /Tests:\s*\d+\s*\(at last count\)/i,
    /Delegate everything/i,
    /Any tool that reads \.env files works automatically/i,
    /whose API calls go through the local proxy/i,
    /Pro tier ships shared cloud vaults/i,
    /Priority support/i,
    /Configured upstreams only/i,
    /Real output\. Nothing hidden/i,
    /postgres:\/\/[\s\S]*swaps the phm_/i,
  ]) {
    assert.doesNotMatch(allClaims, forbidden);
  }
});

test("deprecated AI-plugin metadata cannot advertise a missing OpenAPI surface", () => {
  assert.equal(
    fs.existsSync(path.join(webDir, "public/.well-known/ai-plugin.json")),
    false,
  );
  assert.equal(
    fs.existsSync(path.join(webDir, "public/.well-known/openapi.yaml")),
    false,
  );
  assert.doesNotMatch(allClaims, /ai-plugin\.json|openapi\.yaml/i);
});

test("dotenv recovery copy does not confuse init, unwrap, and encrypted recovery", () => {
  const faq = claims["src/components/landing/FAQ.tsx"];
  assert.match(faq, /does not leave a plaintext/);
  assert.match(faq, /phantom unwrap/);
  assert.match(faq, /only reverses package-script[\s\S]*does not restore dotenv/);

  for (const file of ["public/llms.txt", "public/llms-full.txt"]) {
    assert.match(claims[file], /no plaintext project-local backup/i);
  }
});

test("persistent placeholders and both exec session credentials stay distinct", () => {
  for (const file of [
    "src/app/layout.tsx",
    "src/components/landing/FAQ.tsx",
    "public/llms.txt",
    "public/llms-full.txt",
  ]) {
    assert.match(claims[file], /persist\w* until/i, file);
    assert.match(claims[file], /fresh session[^\n]*phm_/i, file);
    assert.match(claims[file], /PHANTOM_PROXY_TOKEN/, file);
  }
});

test("connection strings are detection-only and absent from proxy visuals", () => {
  const proxyVisuals = [
    claims["src/components/landing/BrandLogos.tsx"],
    claims["src/components/landing/Transformation.tsx"],
  ].join("\n");
  assert.doesNotMatch(proxyVisuals, /DATABASE_URL|MONGODB_URI/);

  for (const file of ["public/llms.txt", "public/llms-full.txt"]) {
    assert.match(claims[file], /Connection strings?[\s\S]*database drivers do not use Phantom's HTTP proxy/i, file);
    assert.match(claims[file], /phantom exec[^\n]*fails closed/i, file);
  }
});

test("scanner copy names the staged and bounded behavior", () => {
  for (const file of [
    "src/components/landing/Features.tsx",
    "public/llms.txt",
    "public/llms-full.txt",
  ]) {
    assert.match(claims[file], /phantom check --staged/, file);
    assert.match(claims[file], /bounded[^\n]*(credential )?prefix/i, file);
  }
  assert.doesNotMatch(
    claims["src/components/landing/QuickStart.tsx"],
    /pre-commit hook installed/i,
  );
});

test("enterprise claims remain explicitly unavailable or contractual", () => {
  for (const [file, source] of Object.entries(claims)) {
    for (const line of source.split("\n")) {
      if (/SSO|SAML|on-prem/i.test(line)) {
        assert.match(line, /not shipped|planned/i, `${file}: ${line}`);
      }
    }
  }

  assert.doesNotMatch(allClaims, /SOC\s*2[-\s]*(certified|compliant)/i);
  assert.doesNotMatch(allClaims, /role-based access control|\bRBAC\b/i);
  assert.doesNotMatch(allClaims, /guaranteed uptime|uptime SLA/i);
  assert.match(claims["public/llms.txt"], /contractual SLA[^\n]*not shipped/i);
  assert.match(claims["public/llms.txt"], /written agreement with Ashlr AI/i);
  assert.match(allClaims, /fixed-membership pilots/i);
});

test("public guidance preserves upstream and production-authority boundaries", () => {
  assert.match(allClaims, /configured upstream/i);
  assert.match(claims["public/llms.txt"], /requests still leave the machine/i);
  assert.match(claims["public/llms-full.txt"], /requests still leave the machine/i);
  assert.match(claims["public/llms.txt"], /do not activate production execution/i);
  assert.match(claims["public/llms-full.txt"], /do not activate production execution/i);
});

test("structured metadata preserves supported-route and fail-closed boundaries", () => {
  const layout = claims["src/app/layout.tsx"];
  assert.match(layout, /supported HTTP SDK routes/);
  assert.match(layout, /configured supported HTTP routes/);
  assert.match(layout, /database connection strings fail closed/);
  assert.doesNotMatch(layout, /Any tool that reads \.env files works automatically/i);
});

test("team and support copy distinguishes source-backed pilots from hosted service", () => {
  const faq = claims["src/components/landing/FAQ.tsx"];
  assert.match(faq, /Pro-gated team-vault source/);
  assert.match(faq, /Hosted availability[\s\S]*commissioned Phantom Cloud deployment/);
  assert.doesNotMatch(claims["src/app/pricing/page.tsx"], /Priority support/i);
});

test("quickstart labels machine-dependent output as illustrative", () => {
  const quickstart = claims["src/components/landing/QuickStart.tsx"];
  assert.match(quickstart, /illustrative output/);
  assert.match(quickstart, /ephemeral-port/);
  assert.doesNotMatch(quickstart, /127\.0\.0\.1:8484/);
});

test("monorepo guidance scopes execution to one initialized subproject", () => {
  const fullReference = claims["public/llms-full.txt"];
  assert.match(fullReference, /Run `phantom exec` from the subproject/);
  assert.match(fullReference, /one session does not aggregate/);
  assert.doesNotMatch(fullReference, /A single `phantom exec` session handles all of them/i);
});

test("visible and structured FAQs retain conservative latency language", () => {
  assert.match(claims["src/components/landing/FAQ.tsx"], /Measure overhead in your own/);
  assert.match(claims["src/app/layout.tsx"], /measure overhead in your own/);
});
