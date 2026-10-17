// Pure checks shared by scripts/site-preview.mjs and its tests. No IO here.
//
// PUBLIC_ROUTE_CONTRACT mirrors the route contract the host-owned website
// publisher enforces before and after promotion (ashlrai/phantom
// src/core/website/host-release.ts WEBSITE_PROFILE.routes and
// host-adapter.ts routeContract). Passing it locally does not admit or
// promote anything; it only catches a change the publisher would refuse.

export const SITE_ORIGIN = "https://phm.dev";

export const PUBLIC_ROUTE_CONTRACT = Object.freeze([
  Object.freeze({ route: "/", canonical: "https://phm.dev", marker: "Work with me" }),
  Object.freeze({ route: "/secrets", canonical: "https://phm.dev/secrets", marker: "Secrets" }),
]);

export const MAX_ROUTE_BYTES = 4 * 1024 * 1024;

export const REQUIRED_SECURITY_HEADERS = Object.freeze([
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
]);

// Paths that must keep answering 410 instead of a pipe-to-shell installer.
export const RETIRED_PATHS = Object.freeze(["/install.sh", "/install.ps1"]);

/** Check one rendered public route against the publisher's contract. */
export function checkRouteContract(entry, { status, contentType, body }) {
  const problems = [];
  if (status !== 200) problems.push(`status ${status}, expected 200`);
  if (!String(contentType ?? "").includes("text/html")) problems.push(`content-type ${contentType ?? "missing"}`);
  if (Buffer.byteLength(body ?? "") > MAX_ROUTE_BYTES) problems.push("body exceeds 4 MiB");
  if (!String(body ?? "").includes(entry.canonical)) problems.push(`missing ${entry.canonical}`);
  if (!String(body ?? "").includes(entry.marker)) problems.push(`missing marker "${entry.marker}"`);
  return problems;
}

export function missingSecurityHeaders(headers) {
  return REQUIRED_SECURITY_HEADERS.filter((name) => !headers.get(name));
}

/**
 * Internal links on a rendered page: href="/..." values, without query, plus
 * the fragment when present. External, protocol-relative and asset links
 * under /_next are skipped.
 */
export function internalLinks(html) {
  const links = new Set();
  for (const match of String(html).matchAll(/\shref="([^"]*)"/g)) {
    const raw = match[1].replaceAll("&amp;", "&");
    if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/_next/")) continue;
    const [pathAndQuery, fragment = ""] = raw.split("#", 2);
    const path = pathAndQuery.split("?", 1)[0] || "/";
    links.add(fragment ? `${path}#${fragment}` : path);
  }
  return [...links].sort();
}

/** Same-document fragment targets (#id) referenced by a page. */
export function fragmentLinks(html) {
  const fragments = new Set();
  for (const match of String(html).matchAll(/\shref="#([^"]+)"/g)) fragments.add(decodeURIComponent(match[1]));
  return [...fragments].sort();
}

export function elementIds(html) {
  const ids = new Set();
  for (const match of String(html).matchAll(/\sid="([^"]+)"/g)) ids.add(match[1]);
  return ids;
}

/** Paths listed in a sitemap that belong to SITE_ORIGIN. */
export function sitemapPaths(xml) {
  const paths = [];
  for (const match of String(xml).matchAll(/<loc>([^<]+)<\/loc>/g)) {
    const url = new URL(match[1].trim());
    if (url.origin === SITE_ORIGIN) paths.push(url.pathname);
  }
  return paths;
}

// Credential shapes that must never appear in shipped output. Documentation
// placeholders such as `phm_...` or `sk-...` do not match these.
export const CREDENTIAL_PATTERNS = Object.freeze([
  ["Stripe secret or restricted key", /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/],
  ["Stripe webhook secret", /\bwhsec_[A-Za-z0-9]{24,}/],
  ["GitHub token", /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/],
  ["Private key block", /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/],
  ["Vercel token", /\bvercel_[A-Za-z0-9]{24,}/],
  ["Supabase secret key", /\bsb_secret_[A-Za-z0-9_-]{20,}/],
  ["PostHog personal API key", /\bphx_[A-Za-z0-9]{30,}/],
  ["Anthropic key", /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ["OpenAI key", /\bsk-(?:proj-)?[A-Za-z0-9]{40,}/],
]);

function jwtRole(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return typeof payload?.role === "string" ? payload.role : null;
  } catch {
    return null;
  }
}

/**
 * Find credential material in one output file. `privateValues` are values of
 * non-public environment variables present at build time; none may be copied
 * into output. Returns finding labels only, never the matched value.
 */
export function credentialFindings(text, privateValues = []) {
  const findings = [];
  for (const [label, pattern] of CREDENTIAL_PATTERNS) if (pattern.test(text)) findings.push(label);
  for (const match of text.matchAll(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g)) {
    const role = jwtRole(match[0]);
    if (role && role !== "anon") findings.push(`JWT with role ${role}`);
  }
  for (const [name, value] of privateValues) if (value.length >= 12 && text.includes(value)) findings.push(`value of ${name}`);
  return [...new Set(findings)];
}

const PUBLIC_ENV = /^(?:NEXT_PUBLIC_|npm_|NODE_|NEXT_TELEMETRY_)/;
const SENSITIVE_ENV = /(?:SECRET|TOKEN|PASSWORD|PRIVATE|_KEY$|^KEY$|CREDENTIAL|SERVICE_ROLE|DATABASE_URL|WEBHOOK)/i;

/** Non-public, credential-named environment entries to look for in output. */
export function privateEnvironmentValues(env) {
  return Object.entries(env).filter(
    ([name, value]) => typeof value === "string" && !PUBLIC_ENV.test(name) && SENSITIVE_ENV.test(name) && value.length >= 12,
  );
}

// The build runs with only these inherited variables, so a page that silently
// needs a credential to render fails here instead of in the publisher's
// credential-free builder.
export const BUILD_ENV_ALLOWLIST = Object.freeze(["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "CI", "SystemRoot", "ComSpec", "PATHEXT"]);

export function credentialFreeEnv(env) {
  const out = { NEXT_TELEMETRY_DISABLED: "1" };
  for (const name of BUILD_ENV_ALLOWLIST) if (typeof env[name] === "string") out[name] = env[name];
  return out;
}
