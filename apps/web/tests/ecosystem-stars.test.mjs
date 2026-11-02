import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { recordSnapshot } from "../scripts/record-star-snapshot.mjs";

const require = createRequire(import.meta.url);
const ts = require("typescript");
const {
  chartPoints,
  collectPublicStars,
  deltaFor,
  fetchOrgRepos,
  fetchPublicStars,
  formatStarCount,
  githubToken,
  isStarsResponse,
  mergeHistories,
  parseConfig,
  parseHistory,
  payloadFromHistory,
  payloadFromLive,
  upsertSnapshot,
} = require("../src/lib/stars-core.js");
const web = path.resolve(import.meta.dirname, "..");
const repo = path.resolve(web, "../..");

const config = {
  owner: "ashlrai",
  repos: ["phantom", "phantom-secrets", "homebrew-tap"],
};

function orgRepo(name, stars, extra = {}) {
  return { name, private: false, visibility: "public", stargazers_count: stars, ...extra };
}

function response(body, { status = 200, link = null } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => (name.toLowerCase() === "link" ? link : null) },
    json: async () => body,
  };
}

const older = {
  schemaVersion: 1,
  snapshots: [{
    date: "2026-10-12",
    total: 8,
    repos: { "ashlrai/phantom": 5, "ashlrai/phantom-secrets": 3, "ashlrai/homebrew-tap": 0 },
  }],
};

test("the ecosystem list is one public-repo config", () => {
  const listed = parseConfig(JSON.parse(readFileSync(path.join(web, "ecosystem-repos.json"), "utf8")));
  assert.ok(listed);
  assert.equal(listed.owner, "ashlrai");
  for (const name of ["phantom", "phantom-secrets", "ashlr-md", "ashlr-plugin", "locus", "lexicon", "ashlr-stack"]) {
    assert.ok(listed.repos.includes(name), name);
  }
  assert.equal(new Set(listed.repos).size, listed.repos.length);
  assert.equal(parseConfig({ owner: "ashlrai", repos: ["phantom", "phantom"] }), null);
  assert.equal(parseConfig({ owner: "ashlrai", repos: ["../phantom"] }), null);
  assert.equal(parseConfig({ owner: "", repos: ["phantom"] }), null);
});

test("bundled history matches the config and never stores a partial total", () => {
  const listed = parseConfig(JSON.parse(readFileSync(path.join(web, "ecosystem-repos.json"), "utf8")));
  const history = parseHistory(JSON.parse(readFileSync(path.join(web, "src/lib/star-history.json"), "utf8")));
  assert.ok(listed);
  assert.ok(history);
  const latest = history.snapshots[history.snapshots.length - 1];
  const names = Object.keys(latest.repos);
  assert.deepEqual(names.map((fullName) => fullName.split("/")[1]).sort(), [...listed.repos].sort());
  assert.equal(latest.total, names.reduce((sum, name) => sum + latest.repos[name], 0));
  assert.ok(latest.total > 0);
});

test("public stars sum only the configured public repositories", () => {
  const collected = collectPublicStars(config, [
    orgRepo("phantom", 5),
    orgRepo("phantom-secrets", 20),
    orgRepo("homebrew-tap", 0),
    orgRepo("solar", 99),
    orgRepo("phantom", 1, { private: true, visibility: "private" }),
  ]);
  assert.equal(collected.ok, true);
  if (!collected.ok) return;
  assert.equal(collected.total, 25);
  assert.deepEqual(collected.repos.map((repo) => repo.name), ["phantom-secrets", "phantom", "homebrew-tap"]);
  assert.equal(collected.repos[0].url, "https://github.com/ashlrai/phantom-secrets");
});

test("a private or missing repository keeps the count unpublished", () => {
  const missing = collectPublicStars(config, [orgRepo("phantom", 5), orgRepo("phantom-secrets", 20)]);
  assert.deepEqual(missing, { ok: false, reason: "incomplete", missing: "homebrew-tap" });
  const hidden = collectPublicStars(config, [
    orgRepo("phantom", 5),
    orgRepo("phantom-secrets", 20),
    orgRepo("homebrew-tap", 4, { private: true, visibility: "private" }),
  ]);
  assert.equal(hidden.ok, false);
  assert.equal(payloadFromLive(older, missing), null);
});

test("daily history upserts one snapshot per UTC date and reports growth", () => {
  const today = {
    date: "2026-11-02",
    total: 11,
    repos: { "ashlrai/phantom": 5, "ashlrai/phantom-secrets": 6, "ashlrai/homebrew-tap": 0 },
  };
  const first = upsertSnapshot(older, today);
  const again = upsertSnapshot(first, { ...today, total: 12, repos: { ...today.repos, "ashlrai/phantom": 6 } });
  assert.deepEqual(again.snapshots.map((snapshot) => snapshot.date), ["2026-10-12", "2026-11-02"]);
  assert.equal(again.snapshots[1].total, 12);
  assert.deepEqual(deltaFor(again.snapshots), { since: "2026-10-12", stars: 4 });
  const branch = parseHistory({
    schemaVersion: 1,
    snapshots: [{ date: "2026-10-13", total: 1, repos: { "ashlrai/phantom": 1 } }],
  });
  const merged = mergeHistories([older, branch]);
  assert.deepEqual(merged.snapshots.map((snapshot) => snapshot.date), ["2026-10-12", "2026-10-13"]);
});

test("GitHub failures and foreign pagination links do not invent a total", async () => {
  const calls = [];
  const broken = await fetchPublicStars({
    config,
    token: "",
    fetchImpl: async () => { throw new Error("offline"); },
  });
  assert.deepEqual(broken, { ok: false, reason: "network" });
  const limited = await fetchOrgRepos("ashlrai", async (url) => {
    calls.push(url);
    return response([orgRepo("phantom", 5)], { link: '<https://evil.example/repos?page=2>; rel="next"' });
  }, "test-token");
  assert.equal(limited.ok, true);
  assert.equal(calls.length, 1);
  assert.match(calls[0], /^https:\/\/api\.github\.com\/orgs\/ashlrai\/repos/);
  const paged = [];
  await fetchOrgRepos("ashlrai", async (url, init) => {
    paged.push(init.headers.Authorization);
    return response([], {
      link: paged.length === 1 ? '<https://api.github.com/orgs/ashlrai/repos?page=2>; rel="next"' : null,
    });
  }, "test-token");
  assert.deepEqual(paged, ["Bearer test-token", "Bearer test-token"]);
});

test("a failed refresh leaves the previous history untouched", async () => {
  const result = await recordSnapshot({
    config,
    histories: [older],
    token: "",
    fetchImpl: async () => response({ message: "nope" }, { status: 503 }),
  });
  assert.equal(result.ok, false);
  assert.equal(result.history, undefined);
  const live = await fetchPublicStars({
    config,
    token: "",
    now: new Date("2026-11-02T04:42:00.000Z"),
    fetchImpl: async () => response([
      orgRepo("phantom", 5),
      orgRepo("phantom-secrets", 6),
      orgRepo("homebrew-tap", 0),
    ]),
  });
  const recorded = await recordSnapshot({
    config,
    histories: [older, null],
    token: "",
    now: new Date("2026-11-02T04:42:00.000Z"),
    fetchImpl: async () => response([
      orgRepo("phantom", 5),
      orgRepo("phantom-secrets", 6),
      orgRepo("homebrew-tap", 0),
    ]),
  });
  assert.equal(live.ok, true);
  assert.equal(recorded.ok, true);
  assert.equal(recorded.history.snapshots.at(-1).date, "2026-11-02");
  assert.equal(recorded.history.snapshots.at(-1).total, 11);
  const payload = payloadFromLive(older, live);
  assert.equal(payload.stale, false);
  assert.equal(payload.source, "github");
  assert.equal(payload.delta.stars, 3);
  assert.equal(isStarsResponse(payload), true);
  assert.equal(JSON.stringify(payload).includes("test-token"), false);
  const fallback = payloadFromHistory(older, { stale: true });
  assert.equal(fallback.stale, true);
  assert.equal(fallback.source, "snapshot");
  assert.equal(fallback.total, 8);
  assert.equal(isStarsResponse({ ...fallback, total: 0 }), false);
});

test("tokens are read from the environment and absent values stay empty", () => {
  assert.equal(githubToken({ PHANTOM_STARS_GITHUB_TOKEN: "  dedicated  ", GITHUB_TOKEN: "workflow" }), "dedicated");
  assert.equal(githubToken({ GITHUB_TOKEN: "workflow" }), "workflow");
  assert.equal(githubToken({ GITHUB_TOKEN: "   " }), "");
  assert.equal(githubToken({}), "");
});

test("the growth chart uses recorded dates and the page hides a missing total", () => {
  const points = chartPoints(upsertSnapshot(older, {
    date: "2026-11-02",
    total: 11,
    repos: { "ashlrai/phantom": 5, "ashlrai/phantom-secrets": 6, "ashlrai/homebrew-tap": 0 },
  }).snapshots);
  assert.equal(points.length, 2);
  assert.ok(points[1].x > points[0].x);
  assert.ok(points[1].y < points[0].y);
  assert.equal(formatStarCount(1046), "1,046");

  const source = readFileSync(path.join(web, "src/components/landing/EcosystemStars.tsx"), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    fileName: "EcosystemStars.tsx",
  }).outputText;
  const stars = require("../src/lib/stars-core.js");
  const exports = {};
  const localRequire = (specifier) => {
    if (specifier === "react") return React;
    if (specifier === "@/lib/stars") return stars;
    if (specifier.endsWith("star-history.json")) {
      return JSON.parse(readFileSync(path.join(web, "src/lib/star-history.json"), "utf8"));
    }
    return require(specifier);
  };
  new Function("exports", "require", "module", output)(exports, localRequire, { exports });
  const payload = payloadFromHistory(upsertSnapshot(older, {
    date: "2026-11-02",
    total: 11,
    repos: { "ashlrai/phantom": 5, "ashlrai/phantom-secrets": 6, "ashlrai/homebrew-tap": 0 },
  }));
  const html = renderToStaticMarkup(React.createElement(exports.EcosystemStarsView, { data: payload }));
  assert.match(html, /Ecosystem stars/);
  assert.match(html, />11</);
  assert.match(html, /Per repository/);
  assert.match(html, /href="https:\/\/github.com\/ashlrai\/phantom-secrets"/);
  assert.match(html, /href="\/api\/stars"/);
  assert.equal(html.includes('target="_blank"'), false);
  assert.match(html, /3 more than Oct 12, 2026/);
  const unavailable = renderToStaticMarkup(React.createElement(exports.EcosystemStarsView, { data: null }));
  assert.match(unavailable, /temporarily unavailable/);
  assert.equal(unavailable.includes("ecosystem-stars__number"), false);
  const initial = renderToStaticMarkup(React.createElement(exports.EcosystemStars));
  const history = parseHistory(JSON.parse(readFileSync(path.join(web, "src/lib/star-history.json"), "utf8")));
  assert.match(initial, new RegExp(`>${formatStarCount(history.snapshots.at(-1).total)}<`));
});

test("the history workflow publishes an exact branch ref and no credential", () => {
  const workflow = readFileSync(path.join(repo, ".github/workflows/star-history.yml"), "utf8");
  assert.match(workflow, /refs\/heads\/star-history/);
  assert.doesNotMatch(workflow, /ls-remote[^\n]*--heads/);
  assert.match(workflow, /\$\{\{\s*(?:secrets\.GITHUB_TOKEN|github\.token)\s*\}\}/);
  assert.doesNotMatch(workflow, /ghp_|github_pat_|PHANTOM_STARS_GITHUB_TOKEN:\s*\S+/);
});
