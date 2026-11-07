/**
 * Public GitHub star totals for the Phantom ecosystem.
 * The repo list is apps/web/ecosystem-repos.json. Tokens come from the environment
 * at call time and are never written into history or responses.
 */

const STAR_SCHEMA_VERSION = 1;
const STAR_HISTORY_URL =
  "https://raw.githubusercontent.com/ashlrai/phantom-secrets/star-history/star-history.json";

const DATE = /^\d{4}-\d{2}-\d{2}$/;
const OWNER = /^[A-Za-z0-9-]+$/;
const REPO = /^[A-Za-z0-9._-]+$/;
const FULL_NAME = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;
const MAX_REPOS = 100;
const MAX_SNAPSHOTS = 4000;
const MAX_STARS = 10_000_000;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function utcDate(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

function formatUtcDate(value) {
  const date = String(value).slice(0, 10);
  if (!DATE.test(date)) return date;
  const [year, month, day] = date.split("-").map(Number);
  return `${MONTHS[month - 1]} ${day}, ${year}`;
}

function formatUtcTimestamp(value) {
  const iso = String(value);
  const time = /^T(\d{2}:\d{2})/.exec(iso.slice(10))?.[1];
  return time ? `${formatUtcDate(iso)}, ${time} UTC` : formatUtcDate(iso);
}

function formatStarCount(value) {
  return new Intl.NumberFormat("en-US").format(value);
}

function githubToken(env) {
  for (const key of ["PHANTOM_STARS_GITHUB_TOKEN", "GITHUB_TOKEN"]) {
    const value = env?.[key];
    if (typeof value === "string" && value.trim() !== "") return value.trim();
  }
  return "";
}

function parseConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (typeof value.owner !== "string" || !OWNER.test(value.owner)) return null;
  if (!Array.isArray(value.repos) || value.repos.length === 0 || value.repos.length > MAX_REPOS) return null;
  if (value.repos.some((name) => typeof name !== "string" || !REPO.test(name))) return null;
  if (new Set(value.repos).size !== value.repos.length) return null;
  return { owner: value.owner, repos: [...value.repos] };
}

function starCount(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_STARS;
}

function snapshotFrom(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (typeof value.date !== "string" || !DATE.test(value.date)) return null;
  if (!value.repos || typeof value.repos !== "object" || Array.isArray(value.repos)) return null;
  const repos = {};
  for (const [name, stars] of Object.entries(value.repos)) {
    if (!FULL_NAME.test(name) || !starCount(stars)) return null;
    repos[name] = stars;
  }
  const names = Object.keys(repos);
  if (names.length === 0 || names.length > MAX_REPOS) return null;
  const total = names.reduce((sum, name) => sum + repos[name], 0);
  if (!starCount(total) || value.total !== total) return null;
  return { date: value.date, total, repos };
}

function parseHistory(value) {
  if (!value || typeof value !== "object" || value.schemaVersion !== STAR_SCHEMA_VERSION) return null;
  if (!Array.isArray(value.snapshots) || value.snapshots.length === 0 || value.snapshots.length > MAX_SNAPSHOTS) return null;
  const snapshots = [];
  for (const entry of value.snapshots) {
    const snapshot = snapshotFrom(entry);
    if (!snapshot) return null;
    snapshots.push(snapshot);
  }
  for (let index = 1; index < snapshots.length; index += 1) {
    if (snapshots[index].date <= snapshots[index - 1].date) return null;
  }
  return { schemaVersion: STAR_SCHEMA_VERSION, snapshots };
}

function mergeHistories(histories) {
  const byDate = new Map();
  for (const history of histories) {
    if (!history || !Array.isArray(history.snapshots)) continue;
    for (const snapshot of history.snapshots) byDate.set(snapshot.date, snapshot);
  }
  const snapshots = [...byDate.values()].sort((left, right) => (left.date < right.date ? -1 : 1));
  if (snapshots.length > MAX_SNAPSHOTS) snapshots.splice(0, snapshots.length - MAX_SNAPSHOTS);
  return { schemaVersion: STAR_SCHEMA_VERSION, snapshots };
}

function upsertSnapshot(history, snapshot) {
  const parsed = snapshotFrom(snapshot);
  if (!parsed) return history;
  return mergeHistories([history, { schemaVersion: STAR_SCHEMA_VERSION, snapshots: [parsed] }]);
}

function deltaFor(snapshots) {
  if (!Array.isArray(snapshots) || snapshots.length < 2) return { since: null, stars: null };
  const latest = snapshots[snapshots.length - 1];
  const previous = snapshots[snapshots.length - 2];
  return { since: previous.date, stars: latest.total - previous.total };
}

function repoRecord(owner, repo) {
  const fullName = `${owner}/${repo.name}`;
  return {
    name: repo.name,
    fullName,
    url: `https://github.com/${fullName}`,
    stars: repo.stargazers_count,
  };
}

function collectPublicStars(config, orgRepos) {
  const parsed = parseConfig(config);
  if (!parsed) return { ok: false, reason: "config" };
  if (!Array.isArray(orgRepos)) return { ok: false, reason: "github-shape" };
  const byName = new Map();
  for (const repo of orgRepos) {
    if (!repo || typeof repo !== "object" || typeof repo.name !== "string") continue;
    if (repo.private !== false) continue;
    if (repo.visibility !== undefined && repo.visibility !== "public") continue;
    if (!starCount(repo.stargazers_count)) continue;
    byName.set(repo.name, repo);
  }
  const repos = [];
  for (const name of parsed.repos) {
    const repo = byName.get(name);
    if (!repo) return { ok: false, reason: "incomplete", missing: name };
    repos.push(repoRecord(parsed.owner, repo));
  }
  repos.sort((left, right) => right.stars - left.stars || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  const total = repos.reduce((sum, repo) => sum + repo.stars, 0);
  const snapshotRepos = Object.fromEntries(repos.map((repo) => [repo.fullName, repo.stars]));
  return { ok: true, total, repos, snapshotRepos };
}

function githubHeaders(token) {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "phm-dev-stars",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function nextGithubPage(link) {
  if (typeof link !== "string" || link === "") return null;
  for (const part of link.split(",")) {
    if (!part.includes('rel="next"')) continue;
    const match = part.match(/<([^>]+)>/);
    if (!match) return null;
    try {
      const url = new URL(match[1]);
      if (url.protocol !== "https:" || url.hostname !== "api.github.com") return null;
      return url.toString();
    } catch {
      return null;
    }
  }
  return null;
}

async function fetchOrgRepos(owner, fetchImpl, token) {
  if (!OWNER.test(owner)) return { ok: false, reason: "config" };
  const headers = githubHeaders(token);
  let url = `https://api.github.com/orgs/${encodeURIComponent(owner)}/repos?per_page=100&type=public`;
  const repos = [];
  const signal = typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
    ? AbortSignal.timeout(8000)
    : undefined;
  for (let page = 0; page < 5 && url; page += 1) {
    let response;
    try {
      response = await fetchImpl(url, signal ? { headers, signal, redirect: "error" } : { headers, redirect: "error" });
    } catch {
      return { ok: false, reason: "network" };
    }
    if (!response?.ok) return { ok: false, reason: `github-${response?.status ?? "error"}` };
    let body;
    try {
      body = await response.json();
    } catch {
      return { ok: false, reason: "github-shape" };
    }
    if (!Array.isArray(body)) return { ok: false, reason: "github-shape" };
    repos.push(...body);
    const link = typeof response.headers?.get === "function" ? response.headers.get("link") : null;
    url = nextGithubPage(link);
  }
  return { ok: true, repos };
}

async function fetchPublicStars({ config, fetchImpl, token, now = new Date() }) {
  const parsed = parseConfig(config);
  if (!parsed) return { ok: false, reason: "config" };
  const listed = await fetchOrgRepos(parsed.owner, fetchImpl, token);
  if (!listed.ok) return listed;
  const collected = collectPublicStars(parsed, listed.repos);
  if (!collected.ok) return collected;
  return {
    ok: true,
    fetchedAt: now.toISOString(),
    total: collected.total,
    repos: collected.repos,
    snapshot: {
      date: utcDate(now),
      total: collected.total,
      repos: collected.snapshotRepos,
    },
  };
}

function reposFromSnapshot(snapshot) {
  return Object.entries(snapshot.repos)
    .map(([fullName, stars]) => ({
      name: fullName.slice(fullName.indexOf("/") + 1),
      fullName,
      url: `https://github.com/${fullName}`,
      stars,
    }))
    .sort((left, right) => right.stars - left.stars || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
}

function payloadFromHistory(history, options = {}) {
  const parsed = parseHistory(history);
  if (!parsed) return null;
  const latest = parsed.snapshots[parsed.snapshots.length - 1];
  const repos = reposFromSnapshot(latest);
  return {
    schemaVersion: STAR_SCHEMA_VERSION,
    asOf: options.asOf ?? `${latest.date}T00:00:00.000Z`,
    source: "snapshot",
    stale: options.stale === true,
    total: latest.total,
    repoCount: repos.length,
    repos,
    history: parsed.snapshots,
    delta: deltaFor(parsed.snapshots),
  };
}

function payloadFromLive(history, live) {
  const parsed = parseHistory(history);
  if (!parsed || !live?.ok) return null;
  const next = upsertSnapshot(parsed, live.snapshot);
  const repos = live.repos;
  return {
    schemaVersion: STAR_SCHEMA_VERSION,
    asOf: live.fetchedAt,
    source: "github",
    stale: false,
    total: live.total,
    repoCount: repos.length,
    repos,
    history: next.snapshots,
    delta: deltaFor(next.snapshots),
  };
}

function isStarsResponse(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (value.schemaVersion !== STAR_SCHEMA_VERSION) return false;
  if (value.source !== "github" && value.source !== "snapshot") return false;
  if (typeof value.stale !== "boolean" || typeof value.asOf !== "string") return false;
  if (!starCount(value.total) || !starCount(value.repoCount)) return false;
  if (!Array.isArray(value.repos) || value.repos.length !== value.repoCount) return false;
  const total = value.repos.reduce((sum, repo) => {
    if (!repo || typeof repo.name !== "string" || !FULL_NAME.test(repo.fullName)) return Number.NaN;
    if (repo.url !== `https://github.com/${repo.fullName}`) return Number.NaN;
    if (!starCount(repo.stars)) return Number.NaN;
    return sum + repo.stars;
  }, 0);
  if (total !== value.total) return false;
  const history = parseHistory({ schemaVersion: STAR_SCHEMA_VERSION, snapshots: value.history });
  if (!history) return false;
  if (!value.delta || typeof value.delta !== "object") return false;
  const sinceOk = value.delta.since === null || (typeof value.delta.since === "string" && DATE.test(value.delta.since));
  const starsOk = value.delta.stars === null || Number.isSafeInteger(value.delta.stars);
  return sinceOk && starsOk;
}

function chartPoints(snapshots) {
  const parsed = Array.isArray(snapshots) ? snapshots.filter((item) => item && DATE.test(item.date) && starCount(item.total)) : [];
  if (parsed.length === 0) return [];
  const width = 320;
  const height = 72;
  const padX = 8;
  const padY = 10;
  const min = Math.min(...parsed.map((item) => item.total));
  const max = Math.max(...parsed.map((item) => item.total));
  const span = Math.max(1, max - min);
  return parsed.map((item, index) => {
    const x = parsed.length === 1 ? width / 2 : padX + (index / (parsed.length - 1)) * (width - padX * 2);
    const y = padY + (1 - (item.total - min) / span) * (height - padY * 2);
    return { date: item.date, total: item.total, x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10 };
  });
}

module.exports = {
  STAR_SCHEMA_VERSION,
  STAR_HISTORY_URL,
  utcDate,
  formatUtcDate,
  formatUtcTimestamp,
  formatStarCount,
  githubToken,
  parseConfig,
  parseHistory,
  mergeHistories,
  upsertSnapshot,
  deltaFor,
  collectPublicStars,
  fetchOrgRepos,
  fetchPublicStars,
  payloadFromHistory,
  payloadFromLive,
  isStarsResponse,
  chartPoints,
};
