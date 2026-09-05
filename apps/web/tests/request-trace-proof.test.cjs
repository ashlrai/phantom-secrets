const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const webRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(webRoot, "../..");
const read = (relativePath) =>
  fs.readFileSync(path.join(webRoot, relativePath), "utf8");
const readRepo = (relativePath) =>
  fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

const trace = read("src/components/landing/RequestTrace.tsx");
const page = read("src/app/page.tsx");
const styles = read("src/app/globals.css");

test("request proof is a secondary module in the adoption path", () => {
  assert.match(page, /import \{ RequestTrace \}/);
  assert.ok(page.indexOf("<Transformation />") < page.indexOf("<RequestTrace />"));
  assert.ok(page.indexOf("<RequestTrace />") < page.indexOf("<QuickStart />"));

  assert.match(read("src/components/landing/Hero.tsx"), /<CredentialWall \/>/);
  assert.match(read("src/components/landing/Ecosystem.tsx"), /KEY_ENTRIES/);
  assert.match(read("src/components/landing/QuickStart.tsx"), /platform-install-grid/);
});

test("request proof describes the active value-blind proxy boundary", () => {
  assert.match(trace, /Provider value absent/);
  assert.match(trace, /Fresh session placeholder/);
  assert.match(trace, /OPENAI_API_KEY=phm_a8f2…/);
  assert.match(trace, /Fresh proxy bearer authenticates this local session/);
  assert.match(trace, /Built-in service prefix selects the configured HTTPS host/);
  assert.match(trace, /Client control of the route auth header is discarded/);
  assert.match(trace, /Route-owned credential is injected only into that fixed header/);
  assert.match(trace, /Bounded, then forwarded byte-for-byte/);
  assert.match(trace, /Never resolved from client headers or body/);
  assert.match(trace, /identity bytes inspected/);
  assert.match(trace, /\[REDACTED:vault-secret\]/);
  assert.match(trace, /\["pattern", "vault-secret"\]/);
  assert.match(trace, /No credential value is shown in this synthetic trace/);
  assert.match(trace, /Leak intercepted in this example/);
  assert.match(trace, /not a live event or an externally[\s\S]*trusted attestation/);
  assert.match(trace, /Invalid bearers[\s\S]*unknown service definitions[\s\S]*missing route[\s\S]*oversized request bodies[\s\S]*encoded upstream/);
});

test("synthetic receipt stays bound to the proxy's value-independent marker", () => {
  const interceptor = readRepo("crates/phantom-proxy/src/interceptor.rs");

  assert.match(
    interceptor,
    /fn format_pattern_label\(_value: &str\) -> String \{\s*"vault-secret"\.to_string\(\)\s*\}/,
  );
  assert.match(interceptor, /format!\("\[REDACTED:\{\}\]", pattern\)/);
});

test("request proof exposes a meaningful accessible sequence", () => {
  assert.match(trace, /aria-labelledby="request-proof-title"/);
  assert.match(trace, /<h2 id="request-proof-title">/);
  assert.match(trace, /<figcaption className="sr-only">/);
  assert.match(trace, /<ol[\s\S]*aria-label="Illustrative proxy request lifecycle"/);
  assert.equal((trace.match(/className="request-trace__number"/g) ?? []).length, 3);
  assert.match(trace, /aria-label="Synthetic scrubbed response"/);
  assert.doesNotMatch(trace, /tabIndex=|-outline-none|aria-live/);
});

test("request proof collapses cleanly and suppresses decorative motion", () => {
  assert.match(
    styles,
    /@media \(max-width: 820px\)[\s\S]*\.request-trace__flow[\s\S]*grid-template-columns: minmax\(0, 1fr\)/,
  );
  assert.match(
    styles,
    /@media \(max-width: 370px\)[\s\S]*\.request-trace__facts > div,[\s\S]*\.request-trace__receipt-rows[\s\S]*grid-template-columns: minmax\(0, 1fr\)/,
  );
  assert.match(styles, /\.request-trace__request-line[\s\S]*overflow-wrap: anywhere/);
  assert.match(
    styles,
    /@keyframes routeCrossing[\s\S]*transform: translate3d\(-100%, 0, 0\)[\s\S]*transform: translate3d\(0, 0, 0\)/,
  );
  assert.doesNotMatch(
    styles.match(/@keyframes routeCrossing \{[\s\S]*?\n\}/)?.[0] ?? "",
    /\bleft:/,
  );
  assert.match(
    styles,
    /@media \(prefers-reduced-motion: reduce\)[\s\S]*\.request-trace__gate::before[\s\S]*display: none/,
  );
});
