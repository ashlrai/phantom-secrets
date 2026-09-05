#!/usr/bin/env node

import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

export const DEFAULT_SITE_ORIGIN = "https://phm.dev";
export const DEFAULT_GITHUB_REPOSITORY_API =
  "https://api.github.com/repos/ashlrai/phantom-secrets";
export const REPORT_SCHEMA_VERSION = "phantom-seo-observation-v1";
export const JOB_SUMMARY_MAX_BYTES = 900_000;

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 45_000;
const OBSERVATION_BUDGET_MS = 420_000;
const REQUIRED_PUBLIC_PATHS = [
  "/",
  "/docs",
  "/security",
  "/llms.txt",
  "/llms-full.txt",
];
const REQUIRED_SECURITY_HEADERS = [
  "content-security-policy",
  "permissions-policy",
  "referrer-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
];
const REQUIRED_HOME_SCHEMA = [
  "FAQPage",
  "HowTo",
  "Organization",
  "SoftwareApplication",
  "SoftwareSourceCode",
];
const EXPERIMENT_STATUSES = new Set([
  "planned",
  "implemented",
  "observing",
  "ready_for_review",
  "accepted",
  "reverted",
  "inconclusive",
]);
const REFERRAL_CLASSES = new Set([
  "direct",
  "google",
  "bing",
  "github",
  "chatgpt",
  "perplexity",
  "copilot",
  "other",
]);
const BRAND_CLASSES = new Set(["all", "brand", "nonbrand"]);
const FORBIDDEN_INPUT_KEYS = new Set([
  "campaign",
  "client_id",
  "credential",
  "email",
  "full_page_url",
  "full_url",
  "ip",
  "keyword",
  "landing_page_plus_query_string",
  "medium",
  "page_path_plus_query_string",
  "page_referrer",
  "query",
  "query_string",
  "referrer",
  "secret",
  "session_id",
  "source",
  "token",
  "user_id",
  "user_pseudo_id",
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertClosedObject(value, required, optional, label) {
  invariant(isPlainObject(value), `${label} must be an object`);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    invariant(allowed.has(key), `${label} contains unexpected field ${key}`);
  }
  for (const key of required) {
    invariant(Object.hasOwn(value, key), `${label} is missing ${key}`);
  }
}

function assertFiniteNumber(value, label, { min = 0, max = Infinity } = {}) {
  invariant(Number.isFinite(value), `${label} must be a finite number`);
  invariant(value >= min && value <= max, `${label} is outside its allowed range`);
}

function assertInteger(value, label, { min = 0 } = {}) {
  invariant(Number.isInteger(value) && value >= min, `${label} must be an integer >= ${min}`);
}

function assertIsoDate(value, label) {
  invariant(/^\d{4}-\d{2}-\d{2}$/.test(value), `${label} must be YYYY-MM-DD`);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  invariant(
    !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value,
    `${label} is not a calendar date`,
  );
}

function assertIsoInstant(value, label) {
  invariant(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value), `${label} must be an ISO-8601 UTC instant`);
  const parsed = new Date(value);
  const normalized = value.endsWith("Z") && !value.includes(".")
    ? value.replace(/Z$/, ".000Z")
    : value;
  invariant(
    !Number.isNaN(parsed.getTime()) && parsed.toISOString() === normalized,
    `${label} is not a calendar-valid UTC instant`,
  );
}

function assertNoForbiddenInputKeys(value, location = "input") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoForbiddenInputKeys(entry, `${location}[${index}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, nested] of Object.entries(value)) {
    invariant(
      !FORBIDDEN_INPUT_KEYS.has(key.toLowerCase()),
      `${location} contains forbidden field ${key}`,
    );
    assertNoForbiddenInputKeys(nested, `${location}.${key}`);
  }
}

function normalizePublicPath(value, allowedPaths, label) {
  invariant(typeof value === "string" && value.startsWith("/"), `${label} must be a path`);
  invariant(!value.includes("?") && !value.includes("#"), `${label} must not contain query or hash data`);
  invariant(allowedPaths.has(value), `${label} is not present in the observed sitemap`);
  return value;
}

function validatePeriod(period, label, now) {
  assertClosedObject(period, ["start", "end", "data_state"], [], label);
  assertIsoDate(period.start, `${label}.start`);
  assertIsoDate(period.end, `${label}.end`);
  invariant(period.start <= period.end, `${label}.start must not follow end`);
  invariant(period.data_state === "final", `${label}.data_state must be final`);
  const endExclusive = Date.parse(`${period.end}T00:00:00.000Z`) + 24 * 60 * 60 * 1_000;
  invariant(endExclusive <= now.getTime(), `${label}.end is after the observation capture time`);
  return { start: period.start, end: period.end, data_state: "final" };
}

function sortRows(rows, extraKey) {
  return rows.sort((left, right) => {
    const byPath = left.page_path.localeCompare(right.page_path);
    return byPath || String(left[extraKey] ?? "").localeCompare(String(right[extraKey] ?? ""));
  });
}

export function validateAggregateInput(kind, value, allowedPaths, now = new Date()) {
  assertNoForbiddenInputKeys(value);
  assertClosedObject(value, ["schema_version", "period", "rows"], [], `${kind} input`);
  invariant(Array.isArray(value.rows), `${kind} input.rows must be an array`);
  invariant(value.rows.length <= 500, `${kind} input.rows exceeds 500 rows`);
  const period = validatePeriod(value.period, `${kind} input.period`, now);

  if (kind === "gsc") {
    invariant(value.schema_version === "phantom-seo-gsc-v1", "unexpected GSC schema_version");
    const rows = value.rows.map((row, index) => {
      const label = `gsc input.rows[${index}]`;
      assertClosedObject(
        row,
        ["page_path", "brand_class", "clicks", "impressions", "ctr", "position"],
        [],
        label,
      );
      const page_path = normalizePublicPath(row.page_path, allowedPaths, `${label}.page_path`);
      invariant(BRAND_CLASSES.has(row.brand_class), `${label}.brand_class is invalid`);
      assertFiniteNumber(row.clicks, `${label}.clicks`);
      assertFiniteNumber(row.impressions, `${label}.impressions`);
      assertFiniteNumber(row.ctr, `${label}.ctr`, { min: 0, max: 1 });
      assertFiniteNumber(row.position, `${label}.position`, { min: 0 });
      invariant(row.clicks <= row.impressions, `${label}.clicks cannot exceed impressions`);
      return {
        page_path,
        brand_class: row.brand_class,
        clicks: row.clicks,
        impressions: row.impressions,
        ctr: row.ctr,
        position: row.position,
      };
    });
    return {
      state: "supplied",
      schema_version: value.schema_version,
      period,
      rows: sortRows(rows, "brand_class"),
    };
  }

  if (kind === "ga4") {
    invariant(value.schema_version === "phantom-seo-ga4-v1", "unexpected GA4 schema_version");
    let suppressed_rows = 0;
    const rows = [];
    value.rows.forEach((row, index) => {
      const label = `ga4 input.rows[${index}]`;
      assertClosedObject(
        row,
        [
          "page_path",
          "referral_class",
          "sessions",
          "engaged_sessions",
          "engagement_rate",
          "key_events",
        ],
        [],
        label,
      );
      const page_path = normalizePublicPath(row.page_path, allowedPaths, `${label}.page_path`);
      invariant(REFERRAL_CLASSES.has(row.referral_class), `${label}.referral_class is invalid`);
      assertInteger(row.sessions, `${label}.sessions`);
      assertInteger(row.engaged_sessions, `${label}.engaged_sessions`);
      assertFiniteNumber(row.engagement_rate, `${label}.engagement_rate`, { min: 0, max: 1 });
      assertFiniteNumber(row.key_events, `${label}.key_events`);
      invariant(row.engaged_sessions <= row.sessions, `${label}.engaged_sessions exceeds sessions`);
      if (row.sessions < 10) {
        suppressed_rows += 1;
        return;
      }
      rows.push({
        page_path,
        referral_class: row.referral_class,
        sessions: row.sessions,
        engaged_sessions: row.engaged_sessions,
        engagement_rate: row.engagement_rate,
        key_events: row.key_events,
      });
    });
    return {
      state: "supplied",
      schema_version: value.schema_version,
      period,
      suppressed_rows,
      rows: sortRows(rows, "referral_class"),
    };
  }

  if (kind === "ahrefs") {
    invariant(value.schema_version === "phantom-seo-ahrefs-v1", "unexpected Ahrefs schema_version");
    const rows = value.rows.map((row, index) => {
      const label = `ahrefs input.rows[${index}]`;
      assertClosedObject(
        row,
        ["page_path", "estimated_organic_traffic", "referring_domains"],
        [],
        label,
      );
      const page_path = normalizePublicPath(row.page_path, allowedPaths, `${label}.page_path`);
      assertFiniteNumber(row.estimated_organic_traffic, `${label}.estimated_organic_traffic`);
      assertInteger(row.referring_domains, `${label}.referring_domains`);
      return {
        page_path,
        estimated_organic_traffic: row.estimated_organic_traffic,
        referring_domains: row.referring_domains,
      };
    });
    return {
      state: "supplied",
      schema_version: value.schema_version,
      period,
      rows: sortRows(rows),
    };
  }

  throw new Error(`unsupported aggregate input kind ${kind}`);
}

export function validateExperiments(value, allowedPaths, now = new Date()) {
  assertClosedObject(
    value,
    ["schema_version", "default_observation_days", "experiments"],
    [],
    "experiment ledger",
  );
  invariant(
    value.schema_version === "phantom-seo-experiments-v1",
    "unexpected experiment ledger schema_version",
  );
  assertInteger(value.default_observation_days, "default_observation_days", { min: 21 });
  invariant(Array.isArray(value.experiments), "experiments must be an array");
  invariant(value.experiments.length <= 50, "experiments exceeds 50 entries");
  const ids = new Set();

  const experiments = value.experiments.map((experiment, index) => {
    const label = `experiments[${index}]`;
    const fields = [
      "id",
      "hypothesis",
      "primary_metric",
      "target_routes",
      "control_routes",
      "status",
      "baseline_start",
      "baseline_end",
      "implementation_sha",
      "deployment_id",
      "implemented_at",
      "not_before",
      "decision_rule",
      "lesson",
    ];
    assertClosedObject(experiment, fields, [], label);
    invariant(/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(experiment.id), `${label}.id is invalid`);
    invariant(!ids.has(experiment.id), `${label}.id is duplicated`);
    ids.add(experiment.id);
    for (const field of ["hypothesis", "primary_metric", "decision_rule"]) {
      invariant(
        typeof experiment[field] === "string" &&
          experiment[field].trim().length >= 8 &&
          experiment[field].length <= 1_000,
        `${label}.${field} must contain 8 to 1000 characters`,
      );
    }
    invariant(Array.isArray(experiment.target_routes) && experiment.target_routes.length > 0, `${label}.target_routes is empty`);
    invariant(Array.isArray(experiment.control_routes), `${label}.control_routes must be an array`);
    const target_routes = experiment.target_routes.map((route) =>
      normalizePublicPath(route, allowedPaths, `${label}.target_routes`),
    );
    const control_routes = experiment.control_routes.map((route) =>
      normalizePublicPath(route, allowedPaths, `${label}.control_routes`),
    );
    invariant(new Set(target_routes).size === target_routes.length, `${label}.target_routes contains duplicates`);
    invariant(new Set(control_routes).size === control_routes.length, `${label}.control_routes contains duplicates`);
    invariant(
      target_routes.every((route) => !control_routes.includes(route)),
      `${label} target and control routes overlap`,
    );
    invariant(EXPERIMENT_STATUSES.has(experiment.status), `${label}.status is invalid`);
    assertIsoDate(experiment.baseline_start, `${label}.baseline_start`);
    assertIsoDate(experiment.baseline_end, `${label}.baseline_end`);
    invariant(experiment.baseline_start <= experiment.baseline_end, `${label} baseline is reversed`);

    const implemented = experiment.status !== "planned";
    for (const field of ["implementation_sha", "deployment_id", "implemented_at", "not_before"]) {
      invariant(
        implemented ? typeof experiment[field] === "string" : experiment[field] === null,
        `${label}.${field} does not match status`,
      );
    }
    if (implemented) {
      invariant(/^[0-9a-f]{40}$/.test(experiment.implementation_sha), `${label}.implementation_sha is invalid`);
      invariant(/^dpl_[A-Za-z0-9]{16,}$/.test(experiment.deployment_id), `${label}.deployment_id is invalid`);
      assertIsoInstant(experiment.implemented_at, `${label}.implemented_at`);
      assertIsoInstant(experiment.not_before, `${label}.not_before`);
      invariant(
        Date.parse(experiment.implemented_at) < Date.parse(experiment.not_before),
        `${label}.not_before must follow implementation`,
      );
      const baselineEndExclusive =
        Date.parse(`${experiment.baseline_end}T00:00:00.000Z`) +
        24 * 60 * 60 * 1_000;
      invariant(
        baselineEndExclusive <= Date.parse(experiment.implemented_at),
        `${label}.baseline_end must be strictly before implemented_at`,
      );
      const minimumReviewTime =
        Date.parse(experiment.implemented_at) +
        value.default_observation_days * 24 * 60 * 60 * 1_000;
      invariant(
        Date.parse(experiment.not_before) >= minimumReviewTime,
        `${label}.not_before is earlier than the default observation window`,
      );
      if (["ready_for_review", "accepted", "reverted", "inconclusive"].includes(experiment.status)) {
        invariant(
          now.getTime() >= Date.parse(experiment.not_before),
          `${label}.status advances before not_before`,
        );
      }
    }
    invariant(
      experiment.lesson === null ||
        (typeof experiment.lesson === "string" &&
          experiment.lesson.trim().length >= 8 &&
          experiment.lesson.length <= 1_000),
      `${label}.lesson is invalid`,
    );
    invariant(
      ["accepted", "reverted", "inconclusive"].includes(experiment.status)
        ? typeof experiment.lesson === "string"
        : experiment.lesson === null,
      `${label}.lesson does not match status`,
    );

    let observed_status = experiment.status;
    if (["implemented", "observing"].includes(experiment.status)) {
      observed_status = now.getTime() >= Date.parse(experiment.not_before)
        ? "ready_for_review"
        : "observing";
    }

    return {
      ...experiment,
      target_routes,
      control_routes,
      observed_status,
    };
  });

  return {
    schema_version: value.schema_version,
    default_observation_days: value.default_observation_days,
    experiments,
  };
}

function defaultNetworkPolicy(url) {
  if (url.username || url.password || url.search || url.hash) return false;
  if (url.origin === DEFAULT_SITE_ORIGIN) return true;
  if (url.origin !== "https://api.github.com") return false;
  return [
    "/repos/ashlrai/phantom-secrets",
    "/repos/ashlrai/phantom-secrets/releases/latest",
  ].includes(url.pathname);
}

export function assertDefaultNetworkUrl(input) {
  const url = new URL(input);
  invariant(defaultNetworkPolicy(url), `network destination is not allowlisted: ${url.origin}${url.pathname}`);
  return url;
}

async function readResponseBody(response, maxBytes = MAX_RESPONSE_BYTES) {
  const declared = Number(response.headers.get("content-length"));
  invariant(!Number.isFinite(declared) || declared <= maxBytes, "response exceeds byte limit");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let body = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    invariant(total <= maxBytes, "response exceeds byte limit");
    body += decoder.decode(value, { stream: true });
  }
  return body + decoder.decode();
}

export async function requestWithinBoundary(input, options) {
  const {
    fetchImpl,
    networkPolicy,
    retries = 1,
    timeoutMs = REQUEST_TIMEOUT_MS,
  } = options;
  invariant(Number.isFinite(timeoutMs) && timeoutMs > 0, "request timeout must be positive");
  invariant(
    options.deadlineMs === undefined || Number.isFinite(options.deadlineMs),
    "request deadline must be monotonic and finite",
  );
  let url = new URL(input);
  let lastError;
  const requestDeadline = Math.min(
    options.deadlineMs ?? Number.POSITIVE_INFINITY,
    performance.now() + timeoutMs,
  );

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      for (let redirect = 0; redirect <= 2; redirect += 1) {
        const remainingMs = requestDeadline - performance.now();
        invariant(remainingMs > 0, "request deadline exceeded");
        invariant(networkPolicy(url), `network destination is not allowlisted: ${url.origin}${url.pathname}`);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), Math.max(1, Math.ceil(remainingMs)));
        let response;
        try {
          response = await fetchImpl(url, {
            redirect: "manual",
            signal: controller.signal,
            headers: {
              accept: "text/html,application/json,application/xml,text/plain;q=0.9,*/*;q=0.1",
              "user-agent": "phantom-seo-observer/1",
            },
          });
          if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get("location");
            invariant(location, `redirect from ${url} has no location`);
            url = new URL(location, url);
            continue;
          }
          if (response.status >= 500 && attempt < retries) {
            throw new Error(`temporary HTTP ${response.status} from ${url}`);
          }
          return {
            url,
            status: response.status,
            headers: response.headers,
            body: await readResponseBody(response),
          };
        } finally {
          clearTimeout(timeout);
        }
      }
      throw new Error(`too many redirects from ${input}`);
    } catch (error) {
      if (error?.name === "AbortError" || performance.now() >= requestDeadline) {
        throw new Error("request deadline exceeded");
      }
      lastError = error;
      if (attempt === retries) throw error;
    }
  }
  throw lastError;
}

function decodeEntities(value) {
  return value
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">");
}

function cleanText(value) {
  return decodeEntities(value.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim())
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, 512);
}

function attributes(source) {
  const result = {};
  const pattern = /([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const match of source.matchAll(pattern)) {
    result[match[1].toLowerCase()] = decodeEntities(match[2] ?? match[3] ?? match[4] ?? "");
  }
  return result;
}

function tags(source, name) {
  return [...source.matchAll(new RegExp(`<${name}\\b([^>]*)>`, "gi"))].map((match) =>
    attributes(match[1]),
  );
}

function structuredData(source) {
  const values = [];
  const errors = [];
  for (const match of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = attributes(match[1]);
    if (attrs.type?.toLowerCase() !== "application/ld+json") continue;
    try {
      values.push(JSON.parse(match[2]));
    } catch {
      errors.push("invalid_json_ld");
    }
  }
  return { values, errors };
}

function collectTypes(value, output = new Set()) {
  if (Array.isArray(value)) {
    value.forEach((entry) => collectTypes(entry, output));
    return output;
  }
  if (!isPlainObject(value)) return output;
  if (typeof value["@type"] === "string") output.add(value["@type"]);
  if (Array.isArray(value["@type"])) {
    value["@type"].filter((entry) => typeof entry === "string").forEach((entry) => output.add(entry));
  }
  Object.values(value).forEach((entry) => collectTypes(entry, output));
  return output;
}

function inspectHtml(body) {
  const titleMatch = body.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const metaTags = tags(body, "meta");
  const linkTags = tags(body, "link");
  const description = metaTags.find((tag) => tag.name?.toLowerCase() === "description")?.content ?? null;
  const robots = metaTags.find((tag) => tag.name?.toLowerCase() === "robots")?.content ?? null;
  const canonicals = linkTags
    .filter((tag) => tag.rel?.toLowerCase().split(/\s+/).includes("canonical"))
    .map((tag) => tag.href)
    .filter(Boolean);
  const h1Count = [...body.matchAll(/<h1\b[^>]*>/gi)].length;
  const jsonLd = structuredData(body);
  return {
    title: titleMatch ? cleanText(titleMatch[1]) : null,
    description: description ? cleanText(description) : null,
    robots,
    canonicals,
    h1_count: h1Count,
    structured_data_types: [...collectTypes(jsonLd.values)].sort(),
    structured_data_errors: jsonLd.errors,
    json_ld: jsonLd.values,
  };
}

function parseSitemap(body, siteOrigin) {
  const urls = [...body.matchAll(/<loc>\s*([\s\S]*?)\s*<\/loc>/gi)].map((match) =>
    new URL(decodeEntities(match[1].trim())),
  );
  invariant(urls.length > 0, "sitemap contains no URLs");
  invariant(urls.length <= 250, "sitemap exceeds the route observation limit");
  const paths = [];
  const seen = new Set();
  for (const url of urls) {
    invariant(url.origin === siteOrigin, `sitemap contains an off-host URL: ${url.origin}`);
    invariant(!url.search && !url.hash, `sitemap URL contains query or hash data: ${url.pathname}`);
    invariant(url.pathname.length <= 512, "sitemap path exceeds the observation limit");
    invariant(!seen.has(url.pathname), `sitemap contains duplicate path ${url.pathname}`);
    seen.add(url.pathname);
    paths.push(url.pathname);
  }
  return paths.sort();
}

function addFinding(findings, severity, code, message, route = null) {
  findings.push({ severity, code, message, ...(route ? { route } : {}) });
}

function canonicalMatches(candidate, expected, siteOrigin) {
  try {
    const url = new URL(candidate, siteOrigin);
    return url.origin === siteOrigin && !url.search && !url.hash && url.pathname === expected;
  } catch {
    return false;
  }
}

function findSoftwareVersion(jsonLd) {
  const stack = [...jsonLd];
  while (stack.length) {
    const value = stack.pop();
    if (Array.isArray(value)) {
      stack.push(...value);
      continue;
    }
    if (!isPlainObject(value)) continue;
    const type = value["@type"];
    if (
      (type === "SoftwareApplication" || (Array.isArray(type) && type.includes("SoftwareApplication"))) &&
      typeof value.softwareVersion === "string"
    ) {
      return value.softwareVersion;
    }
    stack.push(...Object.values(value));
  }
  return null;
}

async function mapWithConcurrency(values, limit, mapper) {
  const results = new Array(values.length);
  let index = 0;
  async function worker() {
    while (true) {
      const current = index;
      index += 1;
      if (current >= values.length) return;
      results[current] = await mapper(values[current], current);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, () => worker()));
  return results;
}

export async function observeProduction(options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  invariant(typeof fetchImpl === "function", "fetch is unavailable");
  const now = options.now ?? new Date();
  invariant(now instanceof Date && !Number.isNaN(now.getTime()), "observation capture time is invalid");
  const siteOrigin = options.siteOrigin ?? DEFAULT_SITE_ORIGIN;
  const githubRepositoryApi = options.githubRepositoryApi ?? DEFAULT_GITHUB_REPOSITORY_API;
  const networkPolicy = options.networkPolicy ?? defaultNetworkPolicy;
  const observationBudgetMs = options.observationBudgetMs ?? OBSERVATION_BUDGET_MS;
  invariant(
    Number.isFinite(observationBudgetMs) &&
      observationBudgetMs > 0 &&
      observationBudgetMs <= OBSERVATION_BUDGET_MS,
    `observation budget must be between 1 and ${OBSERVATION_BUDGET_MS} milliseconds`,
  );
  const observationDeadline = performance.now() + observationBudgetMs;
  const requestTimeoutMs = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  invariant(
    Number.isFinite(requestTimeoutMs) &&
      requestTimeoutMs > 0 &&
      requestTimeoutMs <= OBSERVATION_BUDGET_MS,
    `request timeout must be between 1 and ${OBSERVATION_BUDGET_MS} milliseconds`,
  );
  const requestOptions = {
    fetchImpl,
    networkPolicy,
    deadlineMs: observationDeadline,
    timeoutMs: requestTimeoutMs,
  };
  const assertObservationBudget = () =>
    invariant(performance.now() < observationDeadline, "global observation deadline exceeded");
  const findings = [];

  assertObservationBudget();
  const [sitemapResponse, robotsResponse] = await Promise.all([
    requestWithinBoundary(`${siteOrigin}/sitemap.xml`, requestOptions),
    requestWithinBoundary(`${siteOrigin}/robots.txt`, requestOptions),
  ]);
  invariant(sitemapResponse.status === 200, `sitemap returned HTTP ${sitemapResponse.status}`);
  invariant(robotsResponse.status === 200, `robots.txt returned HTTP ${robotsResponse.status}`);
  const sitemapPaths = parseSitemap(sitemapResponse.body, siteOrigin);
  const allowedPaths = new Set(sitemapPaths);
  for (const required of REQUIRED_PUBLIC_PATHS) {
    if (!allowedPaths.has(required)) {
      addFinding(findings, "fail", "sitemap_required_path_missing", `Sitemap is missing ${required}`, required);
    }
  }

  const namedSitemaps = [...robotsResponse.body.matchAll(/^\s*Sitemap:\s*(\S+)\s*$/gim)].map(
    (match) => match[1],
  );
  if (!namedSitemaps.includes(`${siteOrigin}/sitemap.xml`)) {
    addFinding(findings, "fail", "robots_sitemap_missing", "robots.txt does not name the canonical sitemap");
  }
  if (!/^\s*Disallow:\s*\/api\/\s*$/im.test(robotsResponse.body)) {
    addFinding(findings, "fail", "robots_api_boundary_missing", "robots.txt does not disallow /api/");
  }
  if (/^\s*Disallow:\s*\/\s*$/im.test(robotsResponse.body)) {
    addFinding(findings, "fail", "robots_blocks_site", "robots.txt blocks the public site");
  }

  const routeResults = await mapWithConcurrency(sitemapPaths, 5, async (route) => {
    try {
      const response = await requestWithinBoundary(new URL(route, siteOrigin), requestOptions);
      const contentType = response.headers.get("content-type") ?? "";
      if (response.status !== 200) {
        addFinding(findings, "fail", "public_route_status", `Public route returned HTTP ${response.status}`, route);
      }
      if (route.endsWith(".txt")) {
        if (!contentType.toLowerCase().startsWith("text/plain")) {
          addFinding(findings, "fail", "text_route_content_type", "Machine-readable route is not text/plain", route);
        }
        return {
          route,
          status: response.status,
          content_type: contentType,
          text_length: response.body.length,
          text: response.body,
        };
      }
      if (!contentType.toLowerCase().startsWith("text/html")) {
        addFinding(findings, "fail", "html_route_content_type", "Public page is not text/html", route);
      }
      const inspected = inspectHtml(response.body);
      if (!inspected.title) addFinding(findings, "fail", "title_missing", "Page title is missing", route);
      if (!inspected.description) addFinding(findings, "fail", "description_missing", "Meta description is missing", route);
      if (inspected.h1_count !== 1) {
        addFinding(findings, "fail", "h1_count", `Expected one h1; observed ${inspected.h1_count}`, route);
      }
      if (inspected.canonicals.length !== 1) {
        addFinding(
          findings,
          "fail",
          "canonical_count",
          `Expected one canonical; observed ${inspected.canonicals.length}`,
          route,
        );
      } else if (!canonicalMatches(inspected.canonicals[0], route, siteOrigin)) {
        addFinding(findings, "fail", "canonical_mismatch", "Canonical is not the same-host route", route);
      }
      if (inspected.robots?.toLowerCase().includes("noindex")) {
        addFinding(findings, "fail", "public_route_noindex", "Sitemapped page contains noindex", route);
      }
      if ((response.headers.get("x-robots-tag") ?? "").toLowerCase().includes("noindex")) {
        addFinding(findings, "fail", "public_route_header_noindex", "Sitemapped page has an X-Robots-Tag noindex", route);
      }
      if (inspected.structured_data_errors.length) {
        addFinding(findings, "fail", "structured_data_invalid", "Page contains invalid JSON-LD", route);
      }
      if (route === "/") {
        for (const type of REQUIRED_HOME_SCHEMA) {
          if (!inspected.structured_data_types.includes(type)) {
            addFinding(findings, "fail", "home_schema_missing", `Homepage is missing ${type} JSON-LD`, route);
          }
        }
        for (const header of REQUIRED_SECURITY_HEADERS) {
          if (!response.headers.has(header)) {
            addFinding(findings, "fail", "security_header_missing", `Homepage is missing ${header}`, route);
          }
        }
      }
      if (route.startsWith("/docs/") && !inspected.structured_data_types.includes("TechArticle")) {
        addFinding(findings, "fail", "docs_article_schema_missing", "Rendered guide is missing TechArticle JSON-LD", route);
      }
      if (route.startsWith("/docs/") && !inspected.structured_data_types.includes("BreadcrumbList")) {
        addFinding(findings, "fail", "docs_breadcrumb_schema_missing", "Rendered guide is missing BreadcrumbList JSON-LD", route);
      }
      return {
        route,
        status: response.status,
        content_type: contentType,
        title: inspected.title,
        description: inspected.description,
        canonical:
          inspected.canonicals.length === 1 &&
          canonicalMatches(inspected.canonicals[0], route, siteOrigin)
            ? new URL(route, siteOrigin).toString()
            : null,
        h1_count: inspected.h1_count,
        structured_data_types: inspected.structured_data_types,
        json_ld: inspected.json_ld,
      };
    } catch (error) {
      addFinding(
        findings,
        "fail",
        "public_route_unreachable",
        "Public route could not be fetched within the allowlisted network boundary",
        route,
      );
      return { route, status: null, error: "request_failed" };
    }
  });

  const titles = new Map();
  for (const route of routeResults) {
    if (!route.title) continue;
    if (titles.has(route.title)) {
      addFinding(
        findings,
        "fail",
        "duplicate_title",
        `Title duplicates ${titles.get(route.title)}`,
        route.route,
      );
    } else {
      titles.set(route.title, route.route);
    }
  }

  const home = routeResults.find((route) => route.route === "/");
  const llms = routeResults.find((route) => route.route === "/llms.txt");
  const llmsFull = routeResults.find((route) => route.route === "/llms-full.txt");
  for (const route of [llms, llmsFull]) {
    if (route && route.text_length < 100) {
      addFinding(findings, "fail", "machine_readable_content_short", "Machine-readable content is unexpectedly short", route.route);
    }
  }
  if (llms && !llms.text.includes("https://phm.dev/llms-full.txt")) {
    addFinding(findings, "fail", "llms_full_link_missing", "llms.txt does not link llms-full.txt", "/llms.txt");
  }
  if (llms && !llms.text.includes("https://github.com/ashlrai/phantom-secrets")) {
    addFinding(findings, "fail", "llms_repository_link_missing", "llms.txt does not link the canonical repository", "/llms.txt");
  }

  const operational = {};
  for (const [name, route] of [
    ["health", "/api/v1/health"],
    ["ready", "/api/v1/ready"],
  ]) {
    try {
      const response = await requestWithinBoundary(new URL(route, siteOrigin), requestOptions);
      operational[name] = { status: response.status };
      if (name === "health" && response.status !== 200) {
        addFinding(findings, "fail", "health_status", `Health returned HTTP ${response.status}`, route);
      }
      if (name === "ready" && ![200, 503].includes(response.status)) {
        addFinding(findings, "warn", "readiness_status", `Readiness returned HTTP ${response.status}`, route);
      }
    } catch (error) {
      operational[name] = { status: null, error: "request_failed" };
      addFinding(
        findings,
        name === "health" ? "fail" : "warn",
        `${name}_unreachable`,
        "Operational endpoint could not be fetched within the allowlisted network boundary",
        route,
      );
    }
  }

  let github = { state: "unavailable" };
  try {
    const [repositoryResponse, releaseResponse] = await Promise.all([
      requestWithinBoundary(githubRepositoryApi, requestOptions),
      requestWithinBoundary(`${githubRepositoryApi}/releases/latest`, requestOptions),
    ]);
    invariant(repositoryResponse.status === 200, `GitHub repository API returned ${repositoryResponse.status}`);
    invariant(releaseResponse.status === 200, `GitHub release API returned ${releaseResponse.status}`);
    const repository = JSON.parse(repositoryResponse.body);
    const release = JSON.parse(releaseResponse.body);
    invariant(Number.isInteger(repository.stargazers_count), "GitHub stargazer count is invalid");
    invariant(Number.isInteger(repository.forks_count), "GitHub fork count is invalid");
    invariant(/^v\d+\.\d+\.\d+$/.test(release.tag_name), "GitHub release tag is invalid");
    github = {
      state: "observed",
      stargazers: repository.stargazers_count,
      forks: repository.forks_count,
      latest_release: release.tag_name,
      latest_release_immutable: release.immutable === true,
      release_published_at:
        typeof release.published_at === "string" ? release.published_at : null,
    };
    if (release.immutable !== true || release.draft === true || release.prerelease === true) {
      addFinding(
        findings,
        "warn",
        "github_latest_release_not_immutable",
        "Latest GitHub release is not an immutable final release",
      );
    }
    const liveVersion = home?.json_ld ? findSoftwareVersion(home.json_ld) : null;
    const releaseVersion = release.tag_name.slice(1);
    if (!liveVersion) {
      addFinding(findings, "warn", "live_release_version_missing", "Homepage SoftwareApplication has no softwareVersion");
    } else if (liveVersion !== releaseVersion) {
      addFinding(
        findings,
        "warn",
        "live_release_version_drift",
        `Homepage reports ${liveVersion}; latest GitHub release is ${releaseVersion}`,
        "/",
      );
    }
    if (llms && !llms.text.includes(`\`${release.tag_name}\``)) {
      addFinding(
        findings,
        "warn",
        "llms_release_version_drift",
        `llms.txt does not identify latest GitHub release ${release.tag_name}`,
        "/llms.txt",
      );
    }
  } catch (error) {
    addFinding(
      findings,
      "warn",
      "github_public_api_unavailable",
      "Public GitHub repository or release observation was unavailable",
    );
  }

  const experiments = validateExperiments(
    options.experiments ?? {
      schema_version: "phantom-seo-experiments-v1",
      default_observation_days: 28,
      experiments: [],
    },
    allowedPaths,
    now,
  );

  const aggregateInputs = {};
  assertObservationBudget();
  for (const kind of ["gsc", "ga4", "ahrefs"]) {
    aggregateInputs[kind] = options.aggregateInputs?.[kind]
      ? validateAggregateInput(kind, options.aggregateInputs[kind], allowedPaths, now)
      : { state: "not_supplied" };
  }

  findings.sort((left, right) =>
    `${left.severity}\0${left.code}\0${left.route ?? ""}\0${left.message}`.localeCompare(
      `${right.severity}\0${right.code}\0${right.route ?? ""}\0${right.message}`,
    ),
  );
  const publicRoutes = routeResults.map(({ text, json_ld, ...route }) => route);
  const counts = findings.reduce(
    (result, finding) => ({ ...result, [finding.severity]: result[finding.severity] + 1 }),
    { fail: 0, warn: 0 },
  );
  assertObservationBudget();

  return {
    schema_version: REPORT_SCHEMA_VERSION,
    captured_at: now.toISOString(),
    scope: {
      site_origin: siteOrigin,
      repository: "ashlrai/phantom-secrets",
      network_policy: options.networkPolicy
        ? "injected_test_policy"
        : "public_phm_dev_and_public_github_api_only",
    },
    verdict: counts.fail > 0 ? "FAIL" : counts.warn > 0 ? "WARN" : "PASS",
    counts,
    technical: {
      sitemap: { status: sitemapResponse.status, route_count: sitemapPaths.length },
      robots: { status: robotsResponse.status },
      public_routes: publicRoutes,
      operational,
    },
    github,
    experiments,
    aggregate_inputs: aggregateInputs,
    findings,
  };
}

export function renderSummary(report) {
  const prefix = [
    "# Phantom SEO observation",
    "",
    `**Verdict:** ${report.verdict}`,
    "",
    `Observed ${report.technical.sitemap.route_count} canonical public routes at ${report.captured_at}.`,
    `Findings: ${report.counts.fail} failures and ${report.counts.warn} warnings.`,
    "",
    "## External data",
    "",
    ...["gsc", "ga4", "ahrefs"].map(
      (kind) => `- ${kind.toUpperCase()}: ${report.aggregate_inputs[kind].state}`,
    ),
    "",
    "## Experiments",
    "",
  ];
  if (report.experiments.experiments.length === 0) {
    prefix.push("No checked-in experiments are active.");
  } else {
    for (const experiment of report.experiments.experiments) {
      prefix.push(
        `- ${truncateSummaryText(experiment.id)}: ${truncateSummaryText(experiment.observed_status)}`,
      );
    }
  }
  prefix.push("", "## Findings", "");
  const footer = [
    "",
    "This workflow observes public evidence only. It does not edit content, publish, deploy, contact people, or commission external analytics.",
    "",
  ];
  if (report.findings.length === 0) {
    return [...prefix, "No failures or warnings.", ...footer].join("\n");
  } else {
    const included = [];
    for (let index = 0; index < report.findings.length; index += 1) {
      const finding = report.findings[index];
      const route = finding.route ? ` (${finding.route})` : "";
      const line = truncateSummaryText(
        `- **${finding.severity.toUpperCase()} ${finding.code}**${route}: ${finding.message}`,
        4_096,
      );
      const candidateIncluded = [...included, line];
      const omitted = report.findings.length - candidateIncluded.length;
      const omissionLine = omitted > 0
        ? `- **TRUNCATED:** ${omitted} additional findings omitted from this job summary; the complete sanitized report remains in the artifact.`
        : null;
      const candidate = [
        ...prefix,
        ...candidateIncluded,
        ...(omissionLine ? [omissionLine] : []),
        ...footer,
      ].join("\n");
      if (Buffer.byteLength(candidate, "utf8") > JOB_SUMMARY_MAX_BYTES) break;
      included.push(line);
    }
    const omitted = report.findings.length - included.length;
    const omissionLine = omitted > 0
      ? `- **TRUNCATED:** ${omitted} additional findings omitted from this job summary; the complete sanitized report remains in the artifact.`
      : null;
    const summary = [
      ...prefix,
      ...included,
      ...(omissionLine ? [omissionLine] : []),
      ...footer,
    ].join("\n");
    invariant(
      Buffer.byteLength(summary, "utf8") <= JOB_SUMMARY_MAX_BYTES,
      "job summary fixed content exceeds its byte budget",
    );
    return summary;
  }
}

function truncateSummaryText(value, maxBytes = 2_048) {
  const normalized = String(value).replace(/\s+/g, " ").trim();
  if (Buffer.byteLength(normalized, "utf8") <= maxBytes) return normalized;
  const suffix = "…";
  const contentBudget = maxBytes - Buffer.byteLength(suffix, "utf8");
  let bytes = 0;
  let truncated = "";
  for (const character of normalized) {
    const size = Buffer.byteLength(character, "utf8");
    if (bytes + size > contentBudget) break;
    truncated += character;
    bytes += size;
  }
  return `${truncated}${suffix}`;
}

export async function writePrivateReport(file, report) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(report, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

function parseArguments(argv) {
  const result = {
    experiments: "seo/experiments.json",
    out: null,
    summary: null,
    inputs: {},
  };
  const flags = new Map([
    ["--experiments", "experiments"],
    ["--out", "out"],
    ["--summary", "summary"],
    ["--gsc-file", "gsc"],
    ["--ga4-file", "ga4"],
    ["--ahrefs-file", "ahrefs"],
  ]);
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const key = flags.get(flag);
    invariant(key, `unknown argument ${flag}`);
    invariant(index + 1 < argv.length, `missing value for ${flag}`);
    if (["gsc", "ga4", "ahrefs"].includes(key)) result.inputs[key] = argv[index + 1];
    else result[key] = argv[index + 1];
  }
  invariant(result.out, "--out is required");
  return result;
}

async function readJson(file, label) {
  let source;
  try {
    source = await readFile(file);
  } catch (error) {
    throw new Error(`${label} could not be read: ${error.code ?? "read_failed"}`);
  }
  invariant(source.byteLength <= MAX_RESPONSE_BYTES, `${label} exceeds the byte limit`);
  try {
    return JSON.parse(source.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  let report;
  try {
    const experiments = await readJson(args.experiments, "experiment ledger");
    const aggregateInputs = {};
    for (const [kind, file] of Object.entries(args.inputs)) {
      aggregateInputs[kind] = await readJson(file, `${kind} aggregate input`);
    }
    report = await observeProduction({ experiments, aggregateInputs });
  } catch {
    report = {
      schema_version: REPORT_SCHEMA_VERSION,
      captured_at: new Date().toISOString(),
      scope: {
        site_origin: DEFAULT_SITE_ORIGIN,
        repository: "ashlrai/phantom-secrets",
        network_policy: "public_phm_dev_and_public_github_api_only",
      },
      verdict: "FAIL",
      counts: { fail: 1, warn: 0 },
      technical: {
        sitemap: { status: null, route_count: 0 },
        robots: { status: null },
        public_routes: [],
        operational: {},
      },
      github: { state: "unavailable" },
      experiments: {
        schema_version: "phantom-seo-experiments-v1",
        default_observation_days: 28,
        experiments: [],
      },
      aggregate_inputs: {
        gsc: { state: "not_supplied" },
        ga4: { state: "not_supplied" },
        ahrefs: { state: "not_supplied" },
      },
      findings: [
        {
          severity: "fail",
          code: "observer_execution_failed",
          message: "Observer failed closed before the public-surface report completed",
        },
      ],
    };
  }
  await writePrivateReport(args.out, report);
  if (args.summary) await appendFile(args.summary, renderSummary(report));
  process.stdout.write(`${renderSummary(report)}\n`);
  if (report.verdict === "FAIL") process.exitCode = 1;
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`SEO observation could not write its sanitized report: ${error.message}\n`);
    process.exitCode = 1;
  });
}
